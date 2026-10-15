# Semgrep

Runs Semgrep Community Edition static analysis over a `repository` snapshot with a pinned offline rule pack. The published `1.174.0-4` image combines 1,493 legacy upstream security rules with four original product rules; see the [publication and verification record](semgrep-publication-2026-10-03.md). Both native architectures were verified before the catalog pin was updated.

| Item | Value |
| --- | --- |
| Upstream | [semgrep/semgrep](https://github.com/semgrep/semgrep) revision `a0c13f304151e531c7e7c00838076211a07a790c` (`source_ref` `develop`); the build asserts `semgrep --version` is `1.174.0`. Catalog `reported_version` is `1.174.0`; pinned commit `a0c13f3` is on `develop` beside the `v1.174.0` release commit (1 ahead, 1 behind). Rules: [semgrep/semgrep-rules](https://github.com/semgrep/semgrep-rules) `0f5a85ceab1b82b193d0eaa418784c932d237d68` plus four Apache-2.0 product rules. This is a legacy rule snapshot, not current rule knowledge. |
| Image | `ghcr.io/teddashh/ai-security-scanner-engine-semgrep:1.174.0-4` (`plan_kind: managed_build`; LGPL CE, legacy LGPL 2.1 plus Commons Clause rules, Apache-2.0 product rules; `SOURCE-OFFER.md`). The published digest is pinned in `engines/catalog.json`. |
| Build inputs | `engines/images/semgrep/`: `Dockerfile`, `submodules.lock` (36 source archives, the rules repository among them), `build_rule_pack.py`, `prepare_source_bundle.py`, `product-rules.yml`, `product-LICENSE`, Python tests, `testdata/combination-review/`, `SOURCE-OFFER.md`, `plan.json`. The archives are fetched by `node scripts/prepare-offline-engine-data.mjs semgrep` into `.engine-cache/offline/semgrep-submodules/`. The build also uses the shared launcher. |
| Launcher | [Local launcher](local-launcher.md): `verifySemgrepRulePack` and the `semgrep` branch of `planInvocation` |
| Adapter | `extract_semgrep` in `src-tauri/src/adapters/mod.rs` |
| Publish workflow | `.github/workflows/engine-images-local-k8s.yml`, explicitly new `semgrep` tag from `LOCAL_ENGINE_MATRIX`; mandatory native amd64/ARM64 verification before publication |

## Local build and update entry

Build from the repository root with [this Dockerfile](../../engines/images/semgrep/Dockerfile) and context `.`.

Prepare the host cache first: `node scripts/prepare-offline-engine-data.mjs semgrep`. This prepares the exact legacy snapshot and compiler/parser archives. Commons Clause restrictions remain applicable to the legacy rules; use the [publication record](semgrep-publication-2026-10-03.md) for the current native verification command and license status.

See the [image build index](image-build-index.md) for the repeatable local build command, shared launcher impact and update record. The sections below retain this engine’s specific patches, output fields, tests and incident history.

## How it is wired

- **What the pin runs.** `1.174.0-4` loads 1,497 unique IDs from 1,478 configurations: 1,493 selected upstream rules from the 2024-12-13 legacy snapshot and four existing product rules. The fixed launcher checks both the config manifest and original-ID provenance before execution. [Publication run 37138219098](https://github.com/teddashh/ai-security-scanner/actions/runs/37138219098) binds source `94af3e7c5f28fe5f442525a7b0d3aab88b5632ba` and both platform digests. The earlier `1.174.0-3` four-rule runtime and restricted source attachment remain documented in the [historical inspection](semgrep-combination-review.md#published-source-attachment-inspection).
- **Input.** One `repository` asset (`repository_working_tree`, no marker); the launcher refuses every other profile. Networking is disabled. Catalog resources: 2048 MB memory, 2048 MB disk, 2000 CPU millis, 3600 s.
- **Invocation.** The launcher verifies the config manifest and ID-provenance digest, then runs `semgrep scan --json --output /output/semgrep.json --config /opt/ai-security-scanner/semgrep/rules --metrics=off --disable-version-check --no-rewrite-rule-ids --oss-only --jobs 2 --max-memory 2048 --timeout 10 --timeout-threshold 3 --max-target-bytes 10000000 /workspace`, with `SEMGREP_ENABLE_VERSION_CHECK=0` and `SEMGREP_SEND_METRICS=off`. `--no-rewrite-rule-ids` preserves the prequalified upstream IDs and the four existing product IDs. Original upstream IDs remain in `RULE-PROVENANCE.json`.
- **Output.** Semgrep writes `/output/semgrep.json`; the launcher accepts exactly one JSON value.
- **Mapping.** `extract_semgrep` reads `results[]`:
  - Rule id `check_id` (required). Title `extra.message`, else `Semgrep rule <id>`.
  - Severity `extra.severity` through `parse_severity`: `ERROR` High, `WARNING` Medium, `INFO` Informational.
  - Confidence `extra.metadata.confidence`, else derived (`UnverifiedPatternOrDetectorMatch`).
  - Location `<path>:line=<n>:column=<n>` from `path`, `start.line` and `start.col`. Description `extra.metadata.description`, fix `extra.fix`, CWE `extra.metadata.cwe`, plus links through `references_from`.
- **Failed or partial.** A refused profile or rule pack, a non-zero exit or invalid JSON fails the run. These make it partial, while keeping the valid results:
  - a non-empty `errors` array (the warning is a fixed sentence; the error details stay in the raw artifact);
  - a missing `errors` or `results` array;
  - a result without `check_id`.

## Downstream changes

- **Local combination candidate (2026-10-02 onward).** The [legacy + four-rule review](semgrep-combination-review.md) records acquisition/license exceptions, collision-free IDs with original-source provenance, integrated local build and managed-launcher results, architecture evidence and observed overlap. The original experiment changed no public pin or detector body. The [published recipe](semgrep-publication-2026-10-03.md) integrates that legacy lock and pack and records the replacement image receipts.
- **ARM64 testing helper (2026-10-03).** A [local glibc helper](semgrep-combination-review.md#follow-up-local-glibc-helper) correctly preserves read-only mount flags; actual ARM64 launcher controls reject changed configs/provenance, extra rules and writable workspaces. After the initial full-upstream emulated pass exceeded its outer test deadline, one managed run using the reused ARM64 CE binary produced **22 complete results identical to amd64**, normalized to 22 findings without warnings. This does not complete a fresh ARM64 image build or native managed validation.
- **Fresh native builds (2026-10-03).** The separate publication-preparation branch completed [fresh amd64 and ARM64 image builds and native verification](semgrep-combination-review.md#fresh-native-amd64-and-arm64-builds-2026-10-03). Both returned 10/12/22/22, the full-result union, four launcher refusals and identical selected-source attachments; fresh ARM64 output normalized to 22 findings without warnings. This advances the architecture evidence beyond the earlier reused-binary experiment. That verification-mode run published no image; the later `1.174.0-4` publication and exact digest bindings are recorded separately.
- **Published source attachment correction (2026-10-02).** Inspecting the old `1.174.0-3` digest found newer upstream rules under `semgrep/tests/semgrep-rules/` in `/usr/share/source/semgrep-source.tar.gz`, despite the runtime loading only four own rules. Its attached license is Semgrep Rules License v1.0. See the [exact artifact hashes and local source-assembly fix](semgrep-combination-review.md#published-source-attachment-inspection). A runtime-only inventory does not establish the contents or distribution terms of the whole image.
- **Engine source and rule-ID changes.** Semgrep detector code is built unmodified from the pinned revision. The 35 compiler/parser archives stay upstream-owned; their size and digest are checked before extraction. The rules gitlink is overridden with the selected legacy originals, retaining its license and selection record. Only upstream config IDs are qualified with file paths; dated comments and byte-exact originals record that customization.
- **Offline security rule pack** (`build_rule_pack.py`). Engine networking is disabled, so the rules are embedded. From the rules archive the builder selects `.yaml`/`.yml` files that:
  - is not a test file;
  - lies under a `security` or `secrets` directory or under `ai/ai-best-practices/`;
  - is not under `apex/`;
  - has an allowed per-file license and is not the explicitly proprietary `java/lang/security/audit/xss/no-direct-response-writer.yaml`.

  Every selected upstream rule declares `category: security`. The pack has 1,477 upstream files/1,493 rules plus one product file/four rules: 1,478 configs and 1,497 unique IDs. Bounds remain 1 MiB per file and 16 MiB per pack. Output includes `rules/`, `RULES.sha256`, `RULE-PROVENANCE.json`, original `source/`, notices and `PACK-METADATA.json` (schema `ai-security-scanner.semgrep-rule-pack/v2`). The launcher checks config and provenance hashes; the Dockerfile labels record revision/count/manifest. Rule updates change all of these bindings.
- **`apex/` exclusion.** Semgrep CE 1.174.0 needs an unavailable proprietary parser plugin to load those rules (comment in `is_selected_rule_path`). Drop the exclusion when the pinned CE version can load them.

## Lessons from real runs

- 2026-09-05: readers saw only "Semgrep rule ai-security-scanner.python.shell-true" -> the adapter read `extra.metadata.shortlink` and never `extra.message` -> the title is now `extra.message` (a60d38a).
- 2026-09-17: the Semgrep publish job failed with "version tag is already bound to a different source commit or workflow" although its inputs had not changed -> the guard bound a tag to the commit that first published it -> reuse is now allowed when the plan's recorded SHA-256 inputs match (415ab1b).

## Updating this engine

Follow [section 4](../engine-maintenance.md#4-updating-an-engine), then:

- **Choose the final rule profile first.** `mappings/control-mappings.json` has four exact `ai-security-scanner.*` entries. The published [legacy + product recipe](semgrep-publication-2026-10-03.md) retains all four unchanged. Do not re-key existing product mappings simply because upstream rules are added. File-qualified upstream IDs need their own reviewed mappings; shared CWE/category does not establish identical detector behavior or exact mapping proof. Native `extra.metadata.cwe` can still reach standardized categories through the existing `cwe_derived_controls` fallback. If approved mapping content changes, update its version and the corresponding `control_mapping.rs` tests together. Check source bytes/IDs against the actual selected pack; catalog claims alone are insufficient.
- **Build.** New source archive and `ADD --checksum`, `SEMGREP_GIT_COMMIT`, the `--version` assertion (two places), every `submodules.lock` line, and `SOURCE_DATE_EPOCH`. `prepareSemgrepSubmodules` in `scripts/prepare-offline-engine-data.mjs` requires exactly 36 archives.
  - Alpine pins were refreshed in this recipe: `curl-dev` 8.22.0-r0, `pcre2-dev`/`pcre2-static` 10.49-r0, `python3` 3.12.15-r0, `rsync` 3.5.0-r0 and `xz-static` 5.8.4-r0. Check every pin on the pinned base before rebuilding. The separate upstream static-curl hook still selects 8.5.0; changing `curl-dev` does not update it. See the [secondary acquisitions](semgrep-combination-review.md#local-build-integration).
- **Rules.** A new rules revision changes the `tests/semgrep-rules` lock line, `EXPECTED_CONFIG_FILE_COUNT` and `EXPECTED_RULE_COUNT`, the launcher's `semgrepRuleManifestSHA256` and `semgrepRuleFileCount`, the Dockerfile labels `rules-revision`, `rules-count` and `rules-manifest-sha256`, the catalog `rule_version` and notice, and `docs/engine-catalog.md`. Update provenance hash/count, source-selection assertions and per-file license checks too. Run `python3 -m unittest discover -s engines/images/semgrep -p 'test_*.py'` after preparing the archives; both native CI jobs run these tests.
- **Output shape.** Re-check `results[].check_id`, `extra.message`, `extra.severity`, `extra.metadata.{confidence,description,cwe}`, `extra.fix`, `start.{line,col}` and the top-level `errors` array.
- **Tests.**
  - `src-tauri/tests/adapter_fixtures.rs`: `semgrep_reads_the_fixture_confidence_verbatim`, `semgrep_without_a_source_confidence_is_an_unverified_low_confidence_match`, `semgrep_lossy_rule_ids_never_gain_mapping_proof`, `semgrep_preserves_valid_findings_but_withholds_completion_for_errors_and_bad_rows`, `semgrep_findings_carry_the_engines_explanation_not_just_its_rule_id`.
  - Fixtures `semgrep.json` and `semgrep-lossy-rule-ids.json` still use the product rule ids (`semgrep-empty.json` has no results), as do `src-tauri/src/exporters/framework_report.rs`, `scripts/validate-aidefend-snapshot.mjs` and `tests/frontend/controlMappingRationalePresentation.test.ts`.
  - Launcher tests `TestSemgrepUsesThePinnedOfflineRulePackWithResourceBounds` and `TestSemgrepRulePackManifestRejectsTamperingAndUninventoriedFiles`.
  - The Dockerfile network-off smoke uses six `testdata/combination-review/` fixtures and requires 22 results with empty errors and representative qualified IDs. Both native CI jobs compare four complete result passes (10/12/22/22), validate source/notices, and exercise four actual launcher refusal controls. Publication anonymously checks each platform filesystem against those receipts before signing and promoting the version.
- **Version coupling.** The published tag is `1.174.0-4` in `LOCAL_ENGINE_MATRIX`, the Dockerfile label, admission contract, catalog, plan and artifact verifier. For an owner-approved later publication, assign a new immutable tag and update catalog/plan/evidence bindings, `scripts/release/verify-publication-artifact.mjs` and `tests/release/verifyPublicationArtifact.test.mjs` together. Use `git grep -nF '1.174.0-3'` and retain historical records. `support_until` is 2026-11-22; it is maintenance metadata and does not change what a run reports.
- **Compare with raw output.** `jq '.results | length, (.errors | length)' semgrep.json`: the finding count should equal the first number unless the same rule fired twice at one path, line and column, and the second should be 0 for a complete run. Spot-check that each `check_id` and `extra.message` reached the finding unchanged.
- **Publishing.** The guard can reuse a tag only if its historical publishing plan binds that tag and has the same recorded inputs. Changes require a new immutable tag. The current plan now records hashes for the rule builder, source assembler, product rules/license, submodule lock, verification helpers, source offer and shared launcher inputs; the two earlier uncovered Semgrep baseline exceptions have been removed. Source-input records describe the current recipe; historical publication receipts describe the image actually distributed.

## 2026-10-14 source update

The replacement recipe targets `1.181.0-1` at upstream commit `72d3525fe7e02f486428386078f192f8c4756804`. The catalog still names the previously published image until replacement publication is verified. See the [batch update record](updates/2026-10-14.md) for changed inputs, retained rules and verification.
