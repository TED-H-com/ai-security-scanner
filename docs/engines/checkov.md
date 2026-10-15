# Checkov

Runs Checkov's bundled policy checks over a `repository` or `iac_project` snapshot. Checkov picks the applicable frameworks, such as Terraform, CloudFormation and Dockerfile, from the files present. Only failed checks are reported, and no platform metadata is downloaded.

| Item | Value |
| --- | --- |
| Upstream | [bridgecrewio/checkov](https://github.com/bridgecrewio/checkov) 3.3.13 (`source_ref` `3.3.13`), revision `0604e97b0f77c89a8c6c1fe2219c3d251cbb9789`. The upstream image `bridgecrew/checkov:3.3.13` (`c5fb7154…`) was rejected: its provenance names revision `e5745d49…` (`attested_mismatch`), and it enters through `/entrypoint.sh`. |
| Image | `ghcr.io/teddashh/ai-security-scanner-engine-checkov:3.3.13-1` (`plan_kind: managed_source_image`, Apache-2.0), published from 122f3c2 (run 32754480450). The digest is pinned in `engines/catalog.json`. |
| Build inputs | `engines/images/checkov/`: `Dockerfile`, `prepare_source.py`, `.dockerignore` (lets only those two into the context) and `plan.json`. `prepare_source.py` checks the source archive and `Pipfile.lock` digests, extracts the archive with path checks, and renders the 99 `default` records into a hashed requirements lock. pip installs that lock with `--require-hashes --only-binary=:all:`, then Checkov itself with `--no-deps`; the build asserts `checkov --version` is `3.3.13`. Both stages use `python:3.11.16-slim` by digest. |
| Launcher | None: `ENTRYPOINT ["/usr/local/bin/checkov"]` receives the catalog `command`. The [local launcher](local-launcher.md) is not used. |
| Adapter | `extract_checkov` and `extract_checkov_framework` in `src-tauri/src/adapters/mod.rs` |
| Publish workflow | `.github/workflows/engine-image-checkov.yml`, triggered by the `Dockerfile`, `prepare_source.py` or `.dockerignore` |

## Local build and update entry

Build from the repository root with [this Dockerfile](../../engines/images/checkov/Dockerfile) and context `engines/images/checkov`.

No host `.engine-cache` preparation is required by this Dockerfile. Acquisition and any source preparation happen in the build; this does not imply the build is offline.

See the [image build index](image-build-index.md) for the repeatable local build command, shared launcher impact and update record. The sections below retain this engine’s specific patches, output fields, tests and incident history.

## How it is wired

- **Input.** One asset: a `repository` (`repository_working_tree`) or an `iac_project` (`iac_working_tree`). Networking is disabled. Catalog resources: 2048 MB memory, 2048 MB disk, 2000 CPU millis, 3600 s.
- **Invocation.** `checkov -d /workspace --framework all --output json --output-file-path /output/checkov.json, --skip-download --quiet --soft-fail`.
  - The trailing comma is required. With a comma, upstream `print_reports` (`checkov/common/runners/runner_registry.py`) reads the value as one file per output format; without it, the value is a directory and the file is named `results_json.json`.
  - `--skip-download` keeps platform metadata out, so severities and guidelines are mostly absent (b42ad87). `--quiet` limits the JSON to failed checks. With `--soft-fail`, failed checks do not cause a non-zero exit.
  - The image sets `BC_ENABLE_PERSIST_GRAPHS=false`, the three `CKV_*_CONFIG_FETCH_DATA=false` switches, `CKV_SKIP_PACKAGE_UPDATE_CHECK=true` and `RUN_IN_DOCKER=true`, with `HOME` and `XDG_CACHE_HOME` under `/tmp`.
  - `scripts/validate-engine-catalog.mjs` requires the graph, fetch and update-check switches, `--framework all` and `--skip-download`, and rejects `--compact`.
- **Output.** `/output/checkov.json` holds one report object for a single framework, an array of report objects for several, or only the summary when no framework applied. Without `--compact`, each failed check keeps its `code_block` (the resource's source lines) in the raw artifact; the adapter never reads it.
- **Mapping.** One record per `results.failed_checks[]` item:
  - Rule id `check_id` (exact). Title `check_name`, else `Checkov check <id>`. Description `description` or `short_description`.
  - Severity: Checkov's `severity` when present, else Unknown with basis `IacPolicyCheck`. b42ad87 found one shipped check that rates itself offline, `CKV2_AWS_34`. Confidence is derived (`DeterministicPolicyEvaluation`).
  - Location `<file_path or repo_file_path>:line=<first line>:resource=<resource or resource_address>`. Links come from `references_from` (`guideline`) plus the manifest URLs.
- **Failed or partial.** A non-zero exit fails the run. These make it partial, keeping valid rows:
  - a root that is neither an object nor an array;
  - a framework report that is not an object, or that has no `results` and is not the summary-only document;
  - `results` that is not an object, or `failed_checks` that is not an array;
  - a failed check that is not an object or has no valid `check_id`;
  - 10,000 failed checks or framework reports.

  The adapter does not read `summary`. Files Checkov could not parse (`summary.parsing_errors`) and checks skipped by `checkov:skip=` comments in the scanned files (`COMMENT_REGEX` in upstream `checkov/common/comment/enum.py`; quiet JSON keeps only `summary.skipped`) leave the run complete.

## Downstream changes

- **No source patches.** Checkov is built unmodified from the pinned source archive.
- **Source build instead of the upstream image.** The plan rejects the published image (`rejected_because_build_inputs_and_entrypoint_are_not_release_safe`). Re-inspect the upstream image at each update; return to it only if its provenance names the release revision and its entrypoint is the binary.

## Lessons from real runs

- 2026-09-05: unrated findings carried `source-severity:unknown`, a rating Checkov never gave, and sorted below Low -> `BaseCheck` sets `severity` to `None`, `--skip-download` keeps the platform ratings out, and the adapter turned a null into the literal `unknown` -> an explicit Checkov rating wins, and a missing one is derived. The derived level was Medium until 97093ae made it Unknown. The invented fixture was replaced by a real quiet-mode document (b42ad87).
- 2026-09-27: a real project report printed "Dockerfile · line 1 · /Dockerfile." -> Checkov names a Dockerfile resource after the file -> the report drops a resource label that repeats the path, and `/app/Dockerfile.EXPOSE` reads as `EXPOSE` (d53ca4e).

## Updating this engine

Follow [section 4](../engine-maintenance.md#4-updating-an-engine), then:

- **Build.** Update in step:
  - the archive URL and `ADD --checksum`;
  - `prepare_source.py`: `SOURCE_REVISION`, `SOURCE_ARCHIVE_SHA256`, `PIPFILE_LOCK_SHA256`, `EXPECTED_DEPENDENCIES` (the `default` record count), `SOURCE_DATE_EPOCH` and the header comment;
  - the Dockerfile `--version` assertion, the labels and every `SOURCE_DATE_EPOCH` value;
  - the plan `source`, `verified_upstream_artifact` (re-inspect), `build_recipe` and `dockerfile.sha256`;
  - the catalog `engine_version`, `source_revision`, `rule_version`, provenance and the notice that counts 99 records.

  Every dependency needs a wheel for amd64 and arm64. `rendered_requirements_sha256` is only format-checked; compare it with the SHA-256 of `/usr/share/licenses/checkov/runtime-requirements.lock` in the built image. `validateManagedSourceImage` in the validator checks the Dockerfile's frontend, `FROM` lines, source URL and checksum, hash-mode flags, `SOURCE_DATE_EPOCH`, preparer copy, lock digest, user, entrypoint and environment against the plan.
- **CLI and output shape.** Re-check the comma rule in `print_reports`, the four flags, and the quiet `get_dict` shape (`check_type`, `results.failed_checks`, `summary`) and summary-only document. Re-check `check_id`, `check_name`, `file_path`, `repo_file_path`, `file_line_range`, `resource`, `severity`, `guideline`, `description` and `short_description`. Re-count the checks that declare a severity locally.
- **Mapping.** `mappings/control-mappings.json` has one exact entry, `CKV_AWS_18`; confirm the id still exists. The adapter reads no CWE.
- **Tests.**
  - In `src-tauri/tests/adapter_fixtures.rs` (fixture `checkov.json`): `checkov_all_framework_output_preserves_each_finding_and_its_exact_pointer`, `checkov_all_framework_output_contains_malformed_rows_without_losing_valid_findings`, `checkov_preserves_explicit_ratings_and_keeps_missing_ones_unknown` and `source_coordinates_prevent_distinct_upstream_results_from_being_silently_merged`.
  - The fixture still nulls `code_block` as `--compact` output would, and no test covers the summary-only document.
  - The workflow never runs the image. Before pinning, scan a repository holding Terraform, CloudFormation and a Dockerfile, and check that `checkov.json` appears with rows from each framework.
- **Hard-coded values.** `3.3.13-1` appears in the workflow `concurrency.group` and `IMAGE_TAG`, catalog `image.tag` and plan `final_artifact.tag`. `3.3.13` also appears in the Dockerfile assertion and label, `prepare_source.py`, the catalog `engine_version`, provenance and notice, plan `verified_upstream_artifact.tag`, and the fixture's `checkov_version`. Find them with `grep -rn "3.3.13" --exclude-dir=node_modules --exclude-dir=target --exclude-dir=.git --exclude-dir=.upstreams --exclude-dir=.engine-cache`. `support_until` is 2026-11-22.
- **Compare with raw output.**
  - Count with `jq '[(if type=="array" then .[] else . end) | .results.failed_checks[]?] | length' checkov.json`.
  - List with `jq -r '(if type=="array" then .[] else . end) | .results.failed_checks[]? | [.check_id, .file_path, .file_line_range[0], .resource] | @tsv' checkov.json | sort | uniq -c`; identical rows merge into one finding.
  - Read `jq '(if type=="array" then .[] else . end) | (.summary // .) | {failed, skipped, parsing_errors}' checkov.json` for what the report does not show.
- **Publishing.** The plan holds two records with the same platform digests: `publication` (run 32754480450, source 122f3c2) and `publication_evidence` (run 32713536164, source 8bdeb311, which is not in this repository's history). The plan at 122f3c2 binds `3.3.13-1` with today's input digests. Its command differs (`--framework terraform` and `--compact`, changed by ef1c653 and 0e4dd55), but the command is not built into the image. Any change to a watched file needs a new tag.

## 2026-10-14 source update

The replacement recipe targets `3.3.29-1` at upstream commit `e40023ab262c7c8b7b0a8f0975072b42d1b601f9`. The catalog still names the previously published image until replacement publication is verified. See the [batch update record](updates/2026-10-14.md) for changed inputs, retained rules and verification.

## 2026-10-15 runtime dependency correction

The first 3.3.29 candidate's `pip check` found two mismatches despite a successful native scan: the upstream lock retains `bc-detect-secrets` 1.5.50 while the release declares 1.5.52, and the Python base image retains packaging 26.3 metadata over the installed 23.2 requirement. The source preparer now binds the declared secrets dependency to the verified wheel SHA-256 `772353c949a131b7b5efd2b20473e0128af9c25ea27cdb15a3a6a6727ca73c4e`; the original upstream lock remains untouched and checksum-bound. The runtime layer removes the base's wheel/packaging distributions before extracting the 99-entry locked installation, and requires `python -m pip check` to pass. No Checkov detector or finding normalization is patched.
