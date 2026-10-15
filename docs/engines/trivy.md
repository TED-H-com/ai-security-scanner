# Trivy

Runs Trivy's offline vulnerability scanner. Repository and IaC snapshots get two `--pkg-types library` passes: `filesystem` for lockfiles, then `rootfs` for individual package archives such as JARs. A single-image OCI layout gets one `image` pass with `--pkg-types os`. Misconfiguration, secret and license scanning are off.

| Item | Value |
| --- | --- |
| Upstream | [aquasecurity/trivy](https://github.com/aquasecurity/trivy), version `0.76.0`, source ref `v0.76.0`, revision `531360e5d2a88e732373f1614ba99a38738538b8`. Offline databases: schema 2 vulnerability DB and schema 1 Java index, both dated 2026-10-15. Exact OCI and file hashes are in `engines/images/trivy/DATABASE-NOTICE.md`. |
| Image | `ghcr.io/ted-h-com/ai-security-scanner-engine-trivy:0.76.0-1` (`plan_kind: managed_build`), published for linux/amd64 and linux/arm64 by [this run](https://github.com/TED-H-com/ai-security-scanner/actions/runs/38696246466) from `c989e75e1c3be7e7abad3395dcf5539cf2a96832`. Exact index/platform digests and verified evidence are in `engines/catalog.json` and `plan.json`. |
| Build inputs | `engines/images/trivy/`: `Dockerfile`, `DATABASE-NOTICE.md`, `plan.json`, and `testdata/` (`package.json` and `package-lock.json` for the lockfile smoke). `node scripts/prepare-offline-engine-data.mjs trivy` fetches the two database layers into `.engine-cache/offline/trivy/` (`db.tar.gz`, `java-db.tar.gz`) and checks their digest and size. The build pins the source with `ADD --checksum`, checks `go.sum`, and runs `go mod verify` with `GOEXPERIMENT=jsonv2`. |
| Launcher | [Local launcher](local-launcher.md): the `trivy` branch of `planInvocation`, the second pass in `planInvocations`, and the database checks in `verifyEngineInputs` |
| Adapter | `extract_trivy` and `trivy_weakness` in `src-tauri/src/adapters/mod.rs` |
| Publish workflow | `.github/workflows/engine-images-local-k8s.yml`, matrix entry `trivy` |

## Local build and update entry

Build from the repository root with [this Dockerfile](../../engines/images/trivy/Dockerfile) and context `.`.

Prepare the host cache first: `node scripts/prepare-offline-engine-data.mjs trivy`. Both the vulnerability DB and Java DB are required.

See the [image build index](image-build-index.md) for the repeatable local build command, shared launcher impact and update record. The sections below retain this engine’s specific patches, output fields, tests and incident history.

## How it is wired

- **Input.** One asset: a `repository` (`repository_working_tree`), an `iac_project` (`iac_working_tree`) or a `container_image` (`container_image_oci_layout`). Networking is disabled. Catalog resources: 2048 MB memory, 2000 CPU millis, and 3600 s for all passes together; 5000 MB disk, but the host clamps the `/tmp` tmpfs to 4096 MB. The catalog's `default_enabled: false` is read only by registry validation; routing alone decides when Trivy runs.
- **Databases.** Before any pass, `verifyEngineInputs` hashes `trivy-cache/db/trivy.db` and `metadata.json` against `trivyDBSHA256` and `trivyMetadataSHA256`. Working trees also check `java-db/trivy-java.db` and its `metadata.json`. Each file must be at most 2 GiB (`maxImmutableBytes`). The image makes the cache read-only (`chmod -R a-w`).
- **Invocation.** Every pass shares these flags, with `TRIVY_DISABLE_VEX_NOTICE=true`:

  `--cache-dir /opt/ai-security-scanner/trivy-cache --cache-backend memory --skip-db-update --skip-java-db-update --offline-scan --skip-version-check --disable-telemetry --skip-vex-repo-update --scanners vuln --format json`

  - Working trees: `trivy filesystem … --pkg-types library --output /output/trivy.json /workspace`, then `trivy rootfs … --pkg-types library --output /output/trivy-individual-packages.json /workspace`. `filesystem` disables individual-package analyzers such as JARs and `rootfs` disables lockfile analyzers, so the two passes do not overlap (comment in `planInvocations`).
  - OCI layout: `trivy image --input /workspace … --pkg-types os --output /output/trivy.json`. Language packages inside images are left to Grype (plan `complementary_container_engine`).
- **Output.** Each pass must leave one JSON value. Both files become raw artifacts and are adapted separately.
- **Mapping.** `extract_trivy` walks `Results[]`, using `Target` (default `container-image`) as the location base. For each `Vulnerabilities[]` item:
  - Rule id `VulnerabilityID`. Title `Title`, else `Trivy vulnerability <id>`. Severity `Severity` through `parse_severity`.
  - Location `<Target>:resource=<PkgName>@<InstalledVersion>:<PkgPath or PkgID>`, and tag `package:<PkgName>`.
  - Confidence is derived (`AdvisoryVersionMatch`).
  - Details: `Description`, `InstalledVersion` and `FixedVersion`. `trivy_weakness` keeps `CweIDs` and every vendor's CVSS v4, v3 and v2 vector and score. Links come from `PrimaryURL` and `References`.
  - The `Misconfigurations[]` and `Secrets[]` branches exist, but `--scanners vuln` never produces them.
- **Failed or partial.** A refused profile, a database mismatch or a non-zero exit from either pass fails the run. These make it partial:
  - a root that is not an object, or `Results` that is present but not an array;
  - a result, category or item of the wrong shape, or an item without an id;
  - 10,000 records.

  A document without `Results` is a finished pass with nothing found.

## Downstream changes

- **No source patches.** Trivy is built unmodified from the pinned revision.
- **Embedded databases.** The `trivy-db` and `trivy-java-db` layers are pinned by manifest and layer digest, and their files are checked at build time and on every run.
  - Why: engine networking is disabled, and identifying JAR contents needs the Java index (686e427).
  - They stay as long as scans run offline. Refresh them as described below.
- **Two-pass working-tree profile** (launcher policy). It gives lockfile and JAR coverage together, which neither upstream mode does alone. Drop the second pass if one upstream mode comes to run both analyzer families.

## Lessons from real runs

- 2026-08-28: the working-tree profile used `--pkg-types os`, so lockfile dependencies were never matched -> `--pkg-types library` (f50d967, "fix: hand off Windows QC candidate 11 repairs").
- 2026-09-05: advisory links were dropped and only `PrimaryURL` survived -> JSON Pointer is case-sensitive and `References` was not looked up -> added to `references_from` (a60d38a).
- 2026-09-09: one pass could not see both lockfile and JAR-only dependencies -> `filesystem` and `rootfs` each disable one analyzer family -> `rootfs` pass plus the embedded Java DB (686e427). Users got it only after 9ee5257 scheduled `0.74.0-4` and 85f92b1 pinned it on 2026-09-17.
- 2026-09-19: a repository scan that exited 0 and normalized all 82 records was shown as unfinished -> the second artifact had no `Results`, and the adapter warned -> absent `Results` now counts as zero (0c6fae6).
- 2026-09-25: every dependency vulnerability said the scanner gave no specific fix -> the report read only free-text remediation, while Trivy and Grype give `FixedVersion` -> the fixed version is shown; on a real scan 16 of 47 findings then named the upgrade (4ec325c).

## Updating this engine

Follow [section 4](../engine-maintenance.md#4-updating-an-engine), then:

- **Build.** Update in step: the archive and checksum, `go.sum`, the `app.ver` ldflag, labels and `SOURCE_DATE_EPOCH`; the plan's `source` and `build_recipe`; and the catalog `engine_version`, `rule_version` (the upstream revision) and `provenance.engine`.
- **Databases.** A refresh changes all of these together:
  - the manifest, layer digest and size in `scripts/prepare-offline-engine-data.mjs`;
  - the layer and file digests in the Dockerfile, and the `database-manifest` and `java-database-manifest` labels;
  - the four `trivy*SHA256` launcher constants (a launcher change retags all six local images);
  - plan `offline_data` and `DATABASE-NOTICE.md`;
  - catalog `provenance.data`, `compatibility.knowledge_input` and `knowledge_date`;
  - the Trivy entry in `scripts/validate-engine-catalog.mjs`.

  Every file must stay at or under 2 GiB. The catalog's third notice, `compatibility.wrapper.strategy`, and the Trivy row of `docs/engine-catalog.md` describe the embedded Java index. `provenance.data` and `knowledge_input` still name only the standard vulnerability database; their revision is the `trivy-db` digest, and the Java index is recorded on the plan as `offline_data.java_index_database`.
- **CLI and output shape.**
  - Re-check every shared flag, and that the `filesystem`/`rootfs` analyzer split still exists.
  - Check that an empty pass still omits `Results`.
  - Re-check `Results[].Target` and `Class`, and in `Vulnerabilities[]`: `VulnerabilityID`, `PkgName`, `PkgPath`, `PkgID`, `InstalledVersion`, `FixedVersion`, `Severity`, `Title`, `Description`, `CweIDs`, `CVSS`, `PrimaryURL` and `References`.
- **Mapping.** `mappings/control-mappings.json` maps the `CVE-` prefix. Other ids get no rule-keyed mapping, though CWE-derived OWASP categories still apply.
- **Tests.**
  - In `src-tauri/tests/adapter_fixtures.rs` (fixture `trivy.json`): `trivy_confidence_follows_each_result_kind_instead_of_one_engine_default`, `trivy_combines_lockfile_and_individual_package_artifacts`, `trivy_companion_envelope_without_results_does_not_withhold_completion`, `trivy_preserves_valid_items_but_withholds_completion_for_malformed_result_shapes`, `trivy_results_present_but_not_an_array_withholds_completion`, `kics_and_trivy_keep_distinct_upstream_resources_and_secret_coordinates` and `one_vulnerability_seen_by_trivy_and_grype_is_offered_as_a_single_row`.
  - Launcher tests: `TestTrivyFilesystemProfilesUseLibraryPackagesAndKeepTheImmutableDatabaseReadOnly`, `TestTrivyOCIProfileDoesNotAddAWorkingTreePackagePass` and `TestTypedContainerPlansUseOCIImageLayout`.
- **Workflow smoke.** It runs three scans:
  - The OCI layout fixture must give `ArtifactType` `container_image`, the fixture's `ImageID` and no `lang-pkgs` result.
  - `engines/images/trivy/testdata` must report lodash 4.17.20.
  - The decoded `local-launcher/testdata/trivy-java-db-test.jar.base64`, checked by SHA-256, must report CVE-2024-23672 in `org.apache.tomcat.embed:tomcat-embed-websocket` 9.0.65 in `trivy-individual-packages.json`.

  The evidence files are `trivy-oci.json`, `trivy-library.json`, `trivy-jar.json` and `SHA256SUMS.txt`.
- **Hard-coded values.** `0.76.0-1` appears in:
  - the workflow matrix, catalog `image.tag`, plan `final_artifact.tag` and the Dockerfile label;
  - `scripts/validate-engine-catalog.mjs`, `scripts/release/verify-publication-artifact.mjs` and `tests/release/verifyPublicationArtifact.test.mjs`.

  `0.76.0` also appears in the workflow `version`, the ldflag, and the catalog `engine_version` and `provenance.engine`. Find them with `grep -rn "0.76.0" --exclude-dir=node_modules --exclude-dir=target --exclude-dir=.git --exclude-dir=.upstreams --exclude-dir=.engine-cache`. `support_until` is 2027-01-13.
- **Compare with raw output.**
  - Count with `jq '[.Results[]?.Vulnerabilities[]?] | length' trivy.json trivy-individual-packages.json`.
  - List with `jq -r '.Results[]? | .Target as $t | .Vulnerabilities[]? | [.VulnerabilityID, $t, .PkgName, .InstalledVersion, (.PkgPath // .PkgID)] | @tsv'`.
  - Identical rows merge into one finding. Check that `Severity`, `FixedVersion` and the CVSS scores arrived unchanged.
- **Publishing.** The current `0.76.0-1` publication binds the recorded inputs at `c989e75e1c3be7e7abad3395dcf5539cf2a96832` in [this run](https://github.com/TED-H-com/ai-security-scanner/actions/runs/38696246466). Existing-tag reuse requires verified provenance and matching executable inputs. Any changed image input requires a new immutable tag.

## 2026-10-14 source update

The replacement recipe targets `0.76.0-1` at upstream commit `531360e5d2a88e732373f1614ba99a38738538b8`. The replacement is now published and pinned in the current catalog; the verified publication is recorded below. See the [batch update record](updates/2026-10-14.md) for changed inputs, retained rules and verification.

## 2026-10-15 verified publication

[Publication run](https://github.com/TED-H-com/ai-security-scanner/actions/runs/38696246466) binds both platform images to `c989e75e1c3be7e7abad3395dcf5539cf2a96832`. Five source/SBOM attestations, four SBOMs, checksums and anonymous index, version tag, platform manifest and config bytes were independently verified before catalog activation. See the [batch verification record](updates/2026-10-14.md#verified-publication-and-catalog-activation) for native execution results and the remaining scope limits.
