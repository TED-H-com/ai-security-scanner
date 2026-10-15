# TruffleHog

Runs TruffleHog's secret detectors over the files of a `repository` snapshot with credential verification switched off. Each finding is an unverified detector match. The secret value never enters a finding.

| Item | Value |
| --- | --- |
| Upstream | [trufflesecurity/trufflehog](https://github.com/trufflesecurity/trufflehog) revision `3ab759fef4bb5935d4fe9ac68b503d05346b8364` (`source_ref` `main`); the build stamps version `3.97.0` through `-X github.com/trufflesecurity/trufflehog/v3/pkg/version.BuildVersion`. Catalog `reported_version` is `3.97.0`; pinned commit `3ab759f` is 9 commits after `v3.97.0` on `main`. |
| Image | `ghcr.io/teddashh/ai-security-scanner-engine-trufflehog:3.97.0-3` (`plan_kind: managed_build`, AGPL-3.0; the image carries the source archive and `SOURCE-OFFER.md`). The published digest is pinned in `engines/catalog.json`. |
| Build inputs | `engines/images/trufflehog/`: `Dockerfile`, `SOURCE-OFFER.md`, `plan.json`, `testdata/README.md` (the smoke workspace). The source archive is `ADD --checksum`-pinned, `go.sum` is SHA-256-checked, then `go mod verify` and `go build -mod=readonly`. The runtime is `FROM scratch`. |
| Launcher | [Local launcher](local-launcher.md): the `trufflehog` branch of `planInvocation` |
| Adapter | `extract_trufflehog` in `src-tauri/src/adapters/mod.rs` |
| Publish workflow | `.github/workflows/engine-images-local-k8s.yml`, matrix entry `trufflehog` |

## Local build and update entry

Build from the repository root with [this Dockerfile](../../engines/images/trufflehog/Dockerfile) and context `.`.

No host `.engine-cache` preparation is required by this Dockerfile. Acquisition and any source preparation happen in the build; this does not imply the build is offline.

See the [image build index](image-build-index.md) for the repeatable local build command, shared launcher impact and update record. The sections below retain this engine’s specific patches, output fields, tests and incident history.

## How it is wired

- **Input.** One `repository` asset (`repository_working_tree`); the launcher refuses every other profile. The snapshot has no `.git`, so history is not scanned. Networking is disabled. Catalog resources: 1024 MB memory, 1024 MB disk, 1000 CPU millis, 3600 s.
- **Invocation.** `trufflehog filesystem /workspace --json --no-verification --no-verification-cache --no-update --concurrency 4`. With `--no-verification`, upstream `Engine.shouldVerifyChunk` returns false before any detector's verify path, so `Verified` is always false (b8b989a). The published image was built from 2641850 with this same command line.
- **Output.** The launcher sends stdout straight into `/output/trufflehog.jsonl` (created exclusively, mode 0600) and captures stderr up to 8 MiB. Every non-blank line must be a JSON object. An empty file is valid, and the adapter reads it as a finished check with no findings (`is_complete_empty_json_lines`).
- **Mapping.** `extract_trufflehog`, one finding per line:
  - Rule id `trufflehog:<DetectorName>`, or `DetectorType` when the name is absent. Title `Potential <detector> secret detected`.
  - Location: `SourceMetadata.Data.Filesystem.file` and `.line`, else the same fields under `Git`, else `repository`. `/workspace` is stripped on a path boundary (`redact_location`).
  - Severity Unknown with basis `UnverifiedCredentialDetector`, because TruffleHog emits no severity. Confidence is derived (`UnverifiedPatternOrDetectorMatch`).
  - Tags `verification:not-attempted` and `secret-value:redacted`; `merge_finding` marks the finding redacted. The manifest URLs are the only references.
  - `Verified`, `Raw`, `RawV2`, `Redacted` and `ExtraData` are never read.
- **Secret handling.** Upstream writes the secret into `Raw` and `RawV2` (`pkg/output/json.go`), and the stored raw `trufflehog.jsonl` keeps it.
  - `collect_output_artifacts` stores every `/output` file with `contains_sensitive_data: true`.
  - Exports leave raw artifacts out unless they are selected (`ExportOptions` defaults `include_raw_artifacts` to false). Even when selected, standard redaction omits sensitive ones (`prepare_artifacts` in `src-tauri/src/export.rs`).
- **Failed or partial.** These fail the run:
  - a refused profile;
  - a non-zero exit or timeout;
  - a line that is not a JSON object;
  - more than 8 MiB of stderr.

  A record without `DetectorName` or `DetectorType`, or more than 10,000 records, makes the run partial; valid sibling findings are kept.

## Downstream changes

None. TruffleHog is built unmodified from the pinned revision. The launcher fixes the command line: filesystem source only, no verification, no update check.

## Lessons from real runs

- 2026-09-05: findings named paths under `/workspace`, a directory that does not exist on the user's machine -> TruffleHog joins file names onto its scan target -> `redact_location` reports paths relative to the chosen directory, on a path boundary (a60d38a).
- 2026-09-05: one-record `.jsonl` fixtures never exercised the line loop -> a single line parses as one JSON document -> the fixture holds two records (a60d38a).
- 2026-09-05: the control mapping was keyed on `trufflehog:ExampleCredential`, which no upstream detector emits, so TruffleHog findings mapped to no control -> replaced by the `trufflehog:` prefix plus a shape guard (a5e76de).
- 2026-09-05: findings carried `source-severity:high`, and a Critical branch keyed on `Verified` that could never fire -> TruffleHog rates nothing, and `--no-verification` keeps `Verified` false -> derived severity, and `verification:not-attempted` instead of `verified:false` (b8b989a). The derived level moved from High to Unknown in 97093ae.
- 2026-09-17: the publish job failed with "version tag is already bound to a different source commit or workflow" although the inputs had not changed -> reuse is now decided by the plan's recorded SHA-256 inputs (415ab1b).

## Updating this engine

Follow [section 4](../engine-maintenance.md#4-updating-an-engine), then:

- **Build.** Update these together:
  - the archive URL and `ADD --checksum`;
  - the `go.sum` SHA-256 line;
  - the `BuildVersion` ldflag, the image labels and `SOURCE_DATE_EPOCH`;
  - the plan's `source` and `build_recipe`;
  - the catalog `engine_version`, `rule_version` and `provenance.engine`.

  The workflow `version` (`3.97.0`) must match `trufflehog --version`.
- **CLI.** Re-check that `filesystem`, `--json`, `--no-verification`, `--no-verification-cache`, `--no-update` and `--concurrency` still exist. Confirm that `--no-verification` still stops before any verify path; otherwise a scan could contact credential providers.
- **Output shape.** Re-check `DetectorName`, `DetectorType` and `SourceMetadata.Data.Filesystem.{file,line}`, that file names are still joined onto `/workspace`, and that the JSON printer still has no severity field (`pkg/output/json.go`).
- **Mapping.** `mappings/control-mappings.json` maps the `trufflehog:` prefix. `engine_rule_identifiers_have_the_shape_their_engine_actually_emits` in `src-tauri/src/adapters/control_mapping.rs` requires every TruffleHog entry to start with it.
- **Tests.**
  - In `src-tauri/tests/adapter_fixtures.rs`: `trufflehog_findings_say_verification_was_not_attempted_rather_than_failed` and `trufflehog_reports_paths_relative_to_the_directory_the_user_chose`.
  - The fixture `src-tauri/tests/fixtures/adapters/trufflehog.jsonl` must keep at least two records.
  - `secret_fields_are_never_selected_by_helpers` in `src-tauri/src/adapters/mod.rs`, and the launcher test `TestTruffleHogIsFilesystemOnlyAndCannotVerify`.
  - The workflow smoke scans `testdata/`, which holds only a README, and checks that each line parses. It proves the image runs, not that a detector fires.
- **Hard-coded values.** `3.97.0-3` appears in:
  - the workflow matrix, catalog `image.tag` and plan `final_artifact.tag`;
  - the Dockerfile version label;
  - `scripts/validate-engine-catalog.mjs`, `scripts/release/verify-publication-artifact.mjs` and `tests/release/verifyPublicationArtifact.test.mjs`.

  Find them with `grep -rn "3.97.0-3" --exclude-dir=node_modules --exclude-dir=target --exclude-dir=.git --exclude-dir=.upstreams --exclude-dir=.engine-cache`. `support_until` is 2026-11-22.
- **Compare with raw output.** Compare without printing the secret fields:
  - `jq -c '{d: .DetectorName, f: .SourceMetadata.Data.Filesystem.file, l: .SourceMetadata.Data.Filesystem.line}' trufflehog.jsonl | sort | uniq -c`.
  - Each distinct row should be one finding: lines with the same detector, file and line merge into one finding with several evidence entries.
  - Never paste `Raw`, `RawV2`, `Redacted` or `ExtraData` into an issue or a commit.
- **Publishing.** The plan at the publishing commit 2641850 binds `3.97.0-2`, and the launcher has changed since, so the next build needs a new tag.

## 2026-10-14 source update

The replacement recipe targets `3.99.2-1` at upstream commit `e76dff8a7e57d6df0c60ad8cbf5d5cba505a8fc9`. The catalog still names the previously published image until replacement publication is verified. See the [batch update record](updates/2026-10-14.md) for changed inputs, retained rules and verification.
