# Grype

Runs Grype's offline vulnerability matcher over a `repository` snapshot (`dir:`) or a single-image OCI layout (`oci-dir:`), against an embedded, checksum-pinned vulnerability database. Database updates and update checks are off, and no package filtering is added.

| Item | Value |
| --- | --- |
| Upstream | [anchore/grype](https://github.com/anchore/grype) 0.117.0 (`source_ref` `v0.117.0`), revision `b5fa92bbcbef655497e3be840a2f718380e2cdd3`. Database: Grype DB schema v6.1.9, built 2026-08-24T06:22:13Z, archive `vulnerability-db_v6.1.9_2026-08-24T00:17:18Z_1787552533.tar.zst`; digests in `engines/images/grype/DATABASE-NOTICE.md`. |
| Image | `ghcr.io/teddashh/ai-security-scanner-engine-grype:0.117.0-4` (`plan_kind: managed_build`, Apache-2.0). The digest is pinned in `engines/catalog.json`. No workflow published this tag; see **Publishing** below. |
| Build inputs | `engines/images/grype/`: `Dockerfile`, `import.json`, `DATABASE-NOTICE.md`, `plan.json`, and `testdata/package-lock.json`, which nothing uses. `node scripts/prepare-offline-engine-data.mjs grype` fetches the database archive into `.engine-cache/offline/grype/db.tar.zst` and checks its digest and size. The build pins the source with `ADD --checksum`, checks `go.sum`, runs `go mod verify`, and builds `cmd/grype` with `-mod=readonly`. The runtime is `FROM scratch`. |
| Launcher | [Local launcher](local-launcher.md): the `grype` branch of `planInvocation` and the database check in `verifyEngineInputs` |
| Adapter | `extract_grype` and `grype_weakness` in `src-tauri/src/adapters/mod.rs` |
| Publish workflow | `.github/workflows/engine-images-local-k8s.yml`, matrix entry `grype` |

## Local build and update entry

Build from the repository root with [this Dockerfile](../../engines/images/grype/Dockerfile) and context `.`.

Prepare the host cache first: `node scripts/prepare-offline-engine-data.mjs grype`. The database archive and `import.json` must describe the same pinned database.

See the [image build index](image-build-index.md) for the repeatable local build command, shared launcher impact and update record. The sections below retain this engine’s specific patches, output fields, tests and incident history.

## How it is wired

- **Input.** One asset: a `repository` (`repository_working_tree`) or a `container_image` (`container_image_oci_layout`). The launcher refuses IaC and every other profile. Networking is disabled. Catalog resources: 1024 MB memory, 3000 MB disk, 1000 CPU millis, 3600 s.
- **Database.** The build decompresses the archive into `/opt/ai-security-scanner/grype-db/6`, checks the archive and `vulnerability.db` (SHA-256 `20a73158…` and `db6f5904…`), adds `import.json` (the import metadata Grype requires), and makes the directory read-only. Before every run `verifyEngineInputs` hashes `vulnerability.db` against `grypeDBSHA256`, at most 2 GiB.
- **Invocation.** `grype dir:/workspace --output json --file /output/grype.json`, with `oci-dir:/workspace` for an OCI layout. The environment sets:
  - `GRYPE_CHECK_FOR_APP_UPDATE=false`, `GRYPE_DB_AUTO_UPDATE=false` and `GRYPE_DB_CACHE_DIR=/opt/ai-security-scanner/grype-db`;
  - `GRYPE_DB_REQUIRE_UPDATE_CHECK=false`, so the scan does not fail when it cannot check for updates;
  - `GRYPE_DB_VALIDATE_AGE=false`, so the pinned database is not refused as older than `max-allowed-built-age`;
  - `GRYPE_DB_VALIDATE_BY_HASH_ON_START=false`; the launcher's own hash check runs instead.
- **Output.** `/output/grype.json`; the launcher accepts exactly one JSON value.
- **Mapping.** `extract_grype`, one record per `matches[]` item:
  - Rule id `vulnerability.id` (exact). Title `Vulnerable package <artifact.name> (<id>)`. Severity `vulnerability.severity` through `parse_severity`: `Negligible` is Informational, a missing value Unknown.
  - Location `artifact.locations[0].path`, else the package name; `/workspace` is stripped. Tag `package:<name>`. Confidence is derived (`AdvisoryVersionMatch`).
  - Details: `vulnerability.description`, `artifact.version`, and up to 16 `vulnerability.fix.versions`. Links come from `vulnerability.dataSource` and `vulnerability.urls`.
  - `grype_weakness` keeps up to 8 entries of the direct `vulnerability.cvss[]`, each with its `source`, vector, base score and version. It reads no CWE and ignores `relatedVulnerabilities`, whose scores belong to another identifier.
  - Matches with the same id at the same location merge into one finding; each match stays a separate evidence entry with its own versions.
- **Failed or partial.** A refused profile is shown as Not tested (d8db493). A database mismatch, a non-zero exit or invalid JSON fails the run. These make it partial, keeping valid matches:
  - no `matches` array;
  - a match that is not an object, or that has no `vulnerability.id`;
  - 10,000 records.

  `{"matches":[]}` is a finished check with nothing found.

## Downstream changes

- **No source patches.** Grype is built unmodified from the pinned revision.
- **Embedded database.** The archive, the extracted database and `import.json` are fixed at build time; engine networking is disabled, so Grype cannot download one. They stay as long as scans run offline. Refresh them as described below.

## Lessons from real runs

- 2026-09-17: the Grype publish job failed with "version tag is already bound to a different source commit or workflow" although its inputs had not changed -> the guard bound a tag to the commit that first published it -> reuse now depends on the plan's recorded SHA-256 inputs (415ab1b).
- 2026-09-19: a repository scan told the user to retry Grype, and the scan sat at Need attention -> the pinned image refused the repository profile, and the host could not tell that refusal from a crash -> the refusal is shown as Not tested (d8db493).
- 2026-09-20: Grype reported 0 findings on a repository where Trivy reported 82 -> `0.117.0-3` was published from 2641850, before ef1c653 allowed repository input -> re-pinned to `0.117.0-4`, which found 81 (10 Critical, 32 High, 33 Medium, 6 Low) (3990168). Before that, d322cff pinned `0.117.0-4` and d894a6a reverted it for lack of workflow evidence.
- 2026-09-25: every dependency finding said the scanner gave no specific fix -> the report read only free-text remediation, and Grype gives `fix.versions` -> the fixed versions are shown (4ec325c).

## Updating this engine

Follow [section 4](../engine-maintenance.md#4-updating-an-engine), then:

- **Build.** Update in step: the archive URL and checksum, the `go.sum` digest, the four `main.*` ldflags (`version`, `gitCommit`, `buildDate`, `gitDescription`), the labels and `SOURCE_DATE_EPOCH`; the plan's `source` and `build_recipe`; and the catalog `engine_version`, `source_revision`, `rule_version` (the upstream revision) and `provenance.engine` and `provenance.rules`. The workflow `version` (`0.117.0`) must appear in `grype version`.
- **Database.** A refresh changes all of these together:
  - the URL, digest and size in `scripts/prepare-offline-engine-data.mjs`;
  - `import.json` (`digest`, `source`, `client_version`);
  - the archive and `vulnerability.db` checks in the Dockerfile, and the `io.ai-security-scanner.database-archive` label;
  - `grypeDBSHA256` in the launcher (a launcher change retags all six local images);
  - `DATABASE-NOTICE.md`, plan and catalog `knowledge_date`, and catalog `provenance.data` and `compatibility.knowledge_input`.
- **CLI and output shape.** Re-check the `dir:` and `oci-dir:` schemes, `--output json --file`, and the six variables (option names in upstream `cmd/grype/cli/options/database.go`). Re-check `matches[].vulnerability.{id,severity,description,fix.versions,cvss,dataSource,urls}` and `artifact.{name,version,locations}`.
- **Mapping.** `mappings/control-mappings.json` maps only the `CVE-` prefix, and `grype_weakness` reads no CWE, so a match keyed on any other advisory id reaches no control. Grouping with Trivy needs the same CVE or GHSA id, package and asset (`src-tauri/src/correlation.rs`).
- **Tests.**
  - In `src-tauri/tests/adapter_fixtures.rs` (fixture `grype.json`): `grype_preserves_valid_matches_but_withholds_completion_for_malformed_match_shapes`, `one_vulnerability_seen_by_trivy_and_grype_is_offered_as_a_single_row`, `missing_primary_result_shapes_are_incomplete_but_known_empty_shapes_are_complete` and `repo_adapters_accept_their_explicit_empty_result_shapes_without_warnings`.
  - Launcher tests: `TestGrypeRepositoryUsesTheUpstreamDirectoryCataloger`, `TestTypedContainerPlansUseOCIImageLayout` and `TestEngineProfilesRejectCrossTypeExecution`.
  - The workflow smoke scans only the OCI layout fixture: `.source.type` `image`, the fixture's `imageID`, and a `spring-core` 2.5.6.SEC03 `java-archive` match. Nothing tests repository input, so scan a real repository and compare with Trivy on the same tree, as 3990168 did.
- **Hard-coded values.** `0.117.0-4` appears in the workflow matrix, catalog `image.tag`, plan `final_artifact.tag`, the Dockerfile label, `scripts/validate-engine-catalog.mjs`, `scripts/release/verify-publication-artifact.mjs` and `tests/release/verifyPublicationArtifact.test.mjs`. User-facing text names it too: `README.md`, `README.zh-TW.md`, `docs/development-status.md`, `docs/engine-catalog.md`, both `docs/getting-started*.md` and `docs/index.html`. Find them with `grep -rn "0.117.0" --exclude-dir=node_modules --exclude-dir=target --exclude-dir=.git --exclude-dir=.upstreams --exclude-dir=.engine-cache`. `support_until` is 2026-11-22.
- **Compare with raw output.**
  - Count with `jq '.matches | length' grype.json`.
  - List with `jq -r '.matches[] | [.vulnerability.id, .artifact.name, .artifact.version, (.artifact.locations[0].path // .artifact.name)] | @tsv' grype.json | sort | uniq -c`.
  - Rows that share an id and location are one finding. Check that the severity, `fix.versions` and CVSS scores arrived unchanged.
- **Publishing.** The plan's `publication` is known to be false (3990168):
  - It names run 33196902246 and source 2641850, which published `0.117.0-3`. `0.117.0-4` was pushed by hand from a local OCI tar; it has no build attestation, and its image config says version `0.117.0-3`.
  - `scripts/validate-engine-catalog.mjs` checks only that the run id and evidence artifact agree, so its pass does not establish provenance.
  - The guard fails an existing tag without an attestation ("existing digest has no verifiable GitHub build provenance"). Give the next build a new tag. `import.json` has no plan digest (`uncovered_baseline` in `engines/image-input-hash-policy.json`).

## 2026-10-14 source update

The replacement recipe targets `0.120.1-1` at upstream commit `6f8d854af29d3a3086b11a84afa51554a2a245fe`. The catalog still names the previously published image until replacement publication is verified. See the [batch update record](updates/2026-10-14.md) for changed inputs, retained rules and verification.
