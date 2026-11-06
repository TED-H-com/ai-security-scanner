# Garak

Garak 0.17.1 is published and independently verified for the 0.6.0 update. Both platform digests and signed source/SBOM evidence are verified; six controlled native TLS scenarios pass by the public amd64 digest. It contacts one explicitly approved OpenAI-compatible HTTPS chat API and model; no owner endpoint or credential was used for development QA.

| Item | Reviewed input |
| --- | --- |
| Upstream | [NVIDIA/garak](https://github.com/NVIDIA/garak), version `0.17.1`, revision `7aa740fe7412cc9bc33cdc39ca211843223cd3e1`. Rules/data identities are pinned in `engines/catalog.json`. |
| Native source archive | `sha256:34a7e31c9ca7efb00d00509f3397e8f25e87b88239c2c78d21fc9c54740b5fce` |
| Image | `ghcr.io/ted-h-com/ai-security-scanner-engine-garak:0.17.1-1`, published for linux/amd64 and linux/arm64 by [run 42186918863](https://github.com/TED-H-com/ai-security-scanner/actions/runs/42186918863) from `5ba7d2e20f6eb8913aeb3097bed43860451ee522`. Exact digests and verified attestations are in [the publication record](updates/2026-11-06-publications.json). |
| Build context | Repository root; [Dockerfile](../../engines/images/garak/Dockerfile), [complete recipe and hashes](../../engines/images/garak/plan.json) |
| Runtime | Python 3.11.16 slim at `sha256:9c900dea9e8fb7e16277c179b555cc72d29a352dbc33cff48ad5a0412fd5bfc7`; uid65532, read-only rootfs, bounded tmpfs, managed egress |
| Dependencies | 36 hash-locked binary runtime distributions; three separately hash-locked build tools excluded from runtime; unchanged langdetect 1.0.9 source built into a Python 3 wheel |
| Native modifications | None. The launcher and transport enforce capability boundaries; native prompts, probes and detectors remain unchanged |
| Output | Native `/output/report.jsonl`; execution/hashed request receipts under `/output/upstream/`, outside adapter input |
| Publication | [Dedicated workflow](../../.github/workflows/engine-image-garak.yml), immutable guard, controlled native smoke, signed provenance and four per-platform SBOMs, then promotion |

Start updates with the [all-image notebook](image-build-index.md). Reproduce with `docker buildx build --platform linux/amd64 --load -t aiss-garak-local:0.17.1-1 -f engines/images/garak/Dockerfile .`, then `python3 engines/images/garak/testdata/native_smoke.py --image aiss-garak-local:0.17.1-1 --output-dir <new-empty-task-directory>`. The helper creates its own internal-only network, TLS certificate, mock SOCKS gateway and synthetic key, then removes its own containers, network and temporary output. Cleanup uses uid0 with only DAC_OVERRIDE on the generated fixture directory; the scanner itself retains cap-drop ALL. No external model or owner credential store is used.

## Current input and execution

The app saves one canonical HTTPS chat-completions URL and model identifier as typed, non-secret coordinates. This creates an unapproved `ai_model_endpoint` asset; it does not prove ownership or contact the endpoint. Confirmation approves the exact displayed model, provider charges and fixed `garak_https_v1` profile. Public/private network selection stays explicit. A profile is selected without a separate user-editable probe allowlist; its revision is the exact native source above.

The API key stays in Zeroizing app memory for up to 30 minutes, with idle expiry cleanup, and is consumed once before dispatch. Deleting a case revokes its pending keys. Another or failed check requires a new key. No key enters case JSON, command arguments, Docker environment, report summaries or logs. The runtime writes one protected temporary credential document, mounts it read-only, and constructs a fresh child environment for the native REST generator; the runtime removes that document afterward. Cloud credential providers remain separate.

Native probes are `dan.Dan_11_0`, `dan.Dan_10_0`, `dan.Dan_9_0` and `ansiescape.AnsiEscaped`: 1 + 1 + 1 + 51 prompts, one generation each. Primary detectors are `dan.DAN` and `ansiescape.Escaped`; native configuration disables extended detectors and language providers. Request JSON contains one user message, the exact model, `stream=false` and `max_tokens=150`. No configurable provider/CLI argument, target code execution, corpus download or auxiliary hosted service is exposed.

Every request passes through the managed SOCKS gateway and project-owned transport. It requires the exact POST URL/model/header, TLS verification, no redirects, serial execution, one-second start pacing, a 20-second request timeout and a 600-second run deadline. Native backoff retries consume the 64-attempt ceiling. Requests are at most 8 KiB each and 64 KiB total; responses are at most 256 KiB; native JSONL is at most 32 MiB. The maximum **requested** output token count is 9,600; provider charges and token-limit compliance remain provider behavior. A socket audit rejects direct connections outside the numeric managed gateway.

## Current native result contract

The adapter preserves every upstream `probe/detector`, failure count, evaluated/processed count and unjudged count. Severity stays Unknown with `AdversarialProbeFailureRate`; replies are not copied into findings. Probe goal and first user prompt supply technical context. Zero-failure pairs contribute coverage without findings. OWASP LLM 2025 prefix mappings apply only to a declared AI system; native 2023 tags are not relabeled as 2025.

A complete native 0.17 report needs matching init/completion run IDs and all four approved detector pairs totaling 54 evaluated prompts without unjudged attempts. Truncation, malformed counts, missing evaluation, TLS failure, redirects, exhausted limits and cancellation stay incomplete. Completed sibling findings survive. The old 0.13 placeholder fixture remains a legacy adapter test; [the new 0.17 native fixture](../../src-tauri/tests/fixtures/adapters/garak-0.17.0-native.jsonl) is unmodified real upstream output from controlled positive TLS QA.

## Update notes — 2026-10-04

- Native REST/probe base imports require HTTPX, aiohttp, NLTK and langdetect even with no language service enabled. Optional provider/ML SDKs are outside this fixed profile. Do not claim all Garak plugins work or a full `pip check` passed.
- PyPI's langdetect 1.0.9 wheel is Python 2 only. Build the exact unchanged source archive `sha256:cbc1fef89f8d062739774bd51eda3da3274006b3661d199c2655f6b3f6d605a0` with the separate tool lock; avoid floating build/runtime dependency resolution.
- Preserve installed module mtimes at source epoch `1788977945`. Otherwise cache invalidation enumerates unused plugins whose dependencies are intentionally absent. Recheck native cache behavior and all four real constructors on every upstream update.
- Keep Rust, UI and launcher profile IDs, source revision, endpoint normalization, model identifier, grant expiry and budgets aligned. The shared grant contract forbids a profile plus a template allowlist.
- Preserve both typed identifiers (`ai-security-scanner:model-endpoint` and `ai-security-scanner:model-id`) in the private scope document. The orchestrator validates their host/port/profile against one exact grant before retaining them; a generic hostname-only filter prevents valid model dispatch. Keep the serialized-scope mismatch regression and the all-engine save/reopen/export audit in the update checks.
- Keep the run-frozen model label and asset type in reports. Its HTTPS network grant describes transport, while the report must retain the full API path and model. Framework relationships remain conditional on the declared AI context; they must not change native detector counts.
- Reserve and persist each attempt before transmission, including retries and TLS failures. Receipt counters describe attempts; fixture counters describe observed HTTP requests. Never account retries only after success.
- Keep execution receipts under `output/upstream`, raw reports private, and reject raw output containing the actual API key. Do not rewrite native fixture bytes to obtain expected verdicts.
- Repeat positive/clean/redirect/TLS/deadline/cancellation QA. Positive and refusal replies each exercise four real detector pairs; redirect cannot reach another destination, invalid TLS sends no HTTP prompt, short expiry stops backoff, and cancellation sends no later request while preserving its private partial native JSONL. The test CA is QA-only; production exposes no trust override. Local native evidence is amd64 only.

Recheck native `eval`, `attempt`, `start_run setup` and init/completion fields, prompt counts and primary detector identifiers before changing this pin. Update the Dockerfile, both locks, local hashes, plan, catalog, dedicated validator, publication verifier, workflow and this page together. Image input changes require a fresh tag. Keep historical bytes and receipts immutable. Independently verify public index/platform/layers, source/signatures/SBOMs and repeat native smoke by public digest before clearing catalog blockers.

Garak 的公開雙平台位元組、來源簽章與 SBOM 已獨立驗證；公開 amd64 digest 的六種原生 TLS 檢查亦通過，main 已接通可選派送。只測試明確核准的 HTTPS 端點與模型，金鑰不寫入案件，派送時使用一次。更新時沿用上面的來源、依賴與六種 TLS 測試紀錄；54 個提示的上游判定、失敗次數與未完成狀態必須保留。

<details>
<summary>Historical adapter research — before the authorized October 4 integration</summary>

The record below describes the earlier non-packaged adapter. It is retained as incident history; current implementation and update instructions are above.

## How it is wired

- **Release gate.** Catalog `status` `experimental`, `compatibility.runnable` false, and three blockers repeated in the plan:
  - "no packaged image: the pinned source has never been built, tested, or published for this product"
  - "no scope-grant path exists for an AI model endpoint, so no run could be authorized against one"
  - "no credential path exists for a model endpoint that requires a key"
- **Enforcement.** `validate_release_contract` in `src-tauri/src/registry.rs` requires at least one blocker and refuses `default_enabled` for a non-runnable release. `EngineManifest::release_blocker` (`src-tauri/src/domain.rs`) keeps garak out of the default plan (`default_plan_includes_manifest`), makes an explicit request record `engine_release_unavailable`, and stops `PinnedImage::from_manifest` (`src-tauri/src/container_runtime.rs`) and `src-tauri/src/orchestrator.rs` from running it.
- **Input.** An `ai_model_endpoint` asset whose grant names a hostname over `https` (`direct_network_contract`). The second blocker records that no scope-grant path exists for such an asset yet.
- **Network and resources.** Catalog `execution.network` is `managed_allowlist` to "authorized target model endpoint". The manifest is `active_external`, so `container_runtime.rs` refuses to start it without a managed network policy ([egress gateway](egress-gateway.md)). Resources: 2048 MB memory, 4096 MB disk, 2000 CPU millis, 256 pids, 3600 s.
- **Invocation.** Planned command `--engine garak --scope /run/ai-security-scanner/scope.json --output /output`; nothing implements it yet.
- **Output.** `/output/report.jsonl` (`application/x-ndjson`), garak's own run log. The generic parser reads at most 10,000 rows, skips malformed lines with a warning, and reads a one-line report as a JSON document.
- **Mapping.** Only rows with `entry_type` `eval` carry a verdict.
  - Each needs `probe`, `detector` and a non-negative integer `fails`; otherwise a warning is raised and the row skipped. A pair with `fails` 0 is coverage, not a finding.
  - Rule id `probe/detector`; title "garak probe P: detector D judged F of E attempts as failures", E being `total_evaluated`. When `total_evaluated` is below `fails`, the ratio is dropped and a warning raised.
  - Severity Unknown with basis `AdversarialProbeFailureRate`, because garak publishes none. Confidence basis `UnverifiedPatternOrDetectorMatch`, evidence kind `ExternalValidation`, family `ModelBehavior`.
  - Location `plugins.target_type:plugins.target_name` from the `start_run setup` row (the older `plugins.model_type` and `plugins.model_name` are accepted), else "model endpoint".
  - Scanner details: the counts, including `nones` (not judged) and `total_processed`, plus the probe's `goal` and its first user-role prompt (one line, at most 240 characters) from the first `attempt` rows with that `probe_classname`. Model replies are never read.
- **Failed, partial, not tested.** Any adapter warning makes the run partial. A report with no `eval` row warns "garak output contained no eval rows, so no probe result was evaluated", so zero findings means a clean result only when eval rows exist.

## Downstream changes

None. Nothing is built or patched.

## Lessons from real runs

None yet: garak has never run in this product, and 31362f4 and e79eaea record that no scan was run and no endpoint was contacted. These adapter rules came from review:

- 2026-09-12: severity stays Unknown, clean pairs stay out of the findings, and the new `ModelBehavior` family keeps a model's answers from being routed to a restrict-or-patch-the-service screen (31362f4).
- 2026-09-13: a finding named a failing probe with no context -> eval rows carry only a verdict -> the probe's goal and first prompt come from the attempt rows, never from the failing attempt or the reply (ebbef00).
- 2026-09-13: OWASP LLM 2025 references by probe namespace (9032d96); see Mapping below.
- 2026-09-13: "50 of 10" was printed as a measurement and a one-line report was rejected as malformed -> no count check, and a JSONL-only guard -> the ratio is withheld with a warning, a one-line report reads as a document, and a report without eval rows is incomplete (e79eaea).

## Updating this engine

Follow [section 4](../engine-maintenance.md#4-updating-an-engine), then:

- **Before packaging.** Clearing the blockers is owner-authorized product work: an image whose launcher enforces the recorded strategy, a scope-grant path for `ai_model_endpoint` assets, and a credential path for keyed endpoints. Emitting a Dockerfile while the plan stays `managed_artifact_not_published` sends it through `validateUnpublishedManagedBuild` in `scripts/validate-engine-catalog.mjs`, which hard-codes MCP Armor's entrypoint and requires a source patch and disabled networking, so a garak build needs its own validator branch.
- **Source.** The validator fails with "managed build source is not pinned by engines/upstreams.lock.json" unless the `NVIDIA/garak` entry in `engines/upstreams.lock.json` equals the catalog `source_revision`. The revision is also in the plan `source`, catalog `provenance`, `THIRD_PARTY.md` and `docs/engine-catalog.md`. `engines/upstream-refresh-policy.json` marks garak `experimental`, so an `npm run upstream:refresh` proposal is never PR-eligible.
- **Output shape.** Re-check the `entry_type` values, the `eval` fields (`probe`, `detector`, `fails`, `total_evaluated`, `nones`, `total_processed`), the `attempt` fields (`probe_classname`, `goal`, `prompt.turns[].role` and `content.text`) and the `start_run setup` keys. A renamed eval field raises a warning; a renamed attempt or setup key silently drops the context or the location.
- **Tests.** Fixture `src-tauri/tests/fixtures/adapters/garak.jsonl` holds marked placeholder prompts and replies and declares `garak_version` `0.13.3.pre1`, not the pinned 0.17.0; replace it with a report from the pinned revision once one exists. Tests in `src-tauri/tests/adapter_fixtures.rs`: `garak_reports_probe_failure_rates_and_keeps_clean_probes_out_of_the_findings` (six findings, all Unknown, exact counts sentences, no reply text), `garak_maps_the_probe_namespace_to_owasp_llm_only_for_a_declared_ai_system` and `garak_withholds_completion_for_counts_that_cannot_be_true`. A changed warning sentence needs its Chinese form in `src/engineWarningPresentation.ts` (`tests/frontend/warningPresentation.test.ts`).
- **Mapping.** `mappings/control-mappings.json` has 11 `prefix` entries to OWASP LLM 2025: ten whole modules (`dan.`, `encoding.`, `latentinjection.`, `sysprompt_extraction.`, `leakreplay.`, `packagehallucination.`, `snowball.`, `misleading.`, `ansiescape.`, `web_injection.`) and one class, `divergence.Repeat/`, whose slash keeps `divergence.RepeatedToken` out. They apply only when the case declares an AI system. Module-wide entries rest on each module's docstring, verified at 93aa9cd; on a new revision re-read them and confirm every module and class still exists. Do not translate garak's own `owasp:` tags, which use 2023 numbering. The garak arm of `engine_rule_identifiers_have_the_shape_their_engine_actually_emits` (`src-tauri/src/adapters/control_mapping.rs`) accepts only `module.` or `module.Class/`. A content change needs a `mapping_version` bump.
- **Hard-coded tag.** None yet; the plan keeps a null tag and digest. `support_until` is 2026-12-11.
- **Compare with raw output.** In the raw `report.jsonl`, every `eval` row with `fails` above 0 should be one `probe/detector` finding stating `fails` of `total_evaluated`, rows with `fails` 0 should produce nothing, and the location should match the `start_run setup` row's target.

</details>
