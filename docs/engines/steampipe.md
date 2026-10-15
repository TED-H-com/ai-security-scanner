# Steampipe

Lists the IAM users of one authorized AWS account through Steampipe's `aws_iam_user` table, under the fixed profile `aws-iam-user-inventory-us-east-1`. It produces inventory observations, not findings: whether a user is a risk belongs to a security checker, not to this query.

| Item | Value |
| --- | --- |
| Upstream | [turbot/steampipe](https://github.com/turbot/steampipe), version `2.4.7`, source ref `v2.4.7`, revision `5c62651887b3e1d127049722e7216b915d4b075d`. AWS plugin 1.34.0 at `d9a877878061013a49799c17b932616ee0ea415b`; FDW 2.2.7 at `290169e3e104eca604e9013159423027f6477d21`; embedded PostgreSQL remains 14.19.0. |
| Image | `ghcr.io/ted-h-com/ai-security-scanner-engine-steampipe:2.4.7-1` (`plan_kind: managed_source_image`), published for linux/amd64 and linux/arm64 by [this run](https://github.com/TED-H-com/ai-security-scanner/actions/runs/38689379709) from `28bd1a3e23c961ce734503a6eeb59aa7d124ea4f`. Exact index/platform digests and verified evidence are in `engines/catalog.json` and `plan.json`. |
| Build inputs | `engines/images/steampipe/`: `Dockerfile`, `Dockerfile.dockerignore`, `installprep/` (`go.mod`, `main.go`, `main_test.go`), `passwd`, `group`, `POSTGRESQL-COPYRIGHT`, `SOURCE-OFFER.md`, `plan.json` |
| Launcher | `runSteampipe`, `prepareSteampipeInstall`, `steampipeSeedDatabaseVersion` and `steampipeIAMUserInventoryQuery` in `engines/images/cloud-launcher/main.go` ([shared launcher](cloud-launcher.md)) |
| Wrapper | Build-time helper `ai-security-scanner-steampipe-installprep` (`installprep/main.go`) |
| Adapter | `extract_steampipe_inventory` in `src-tauri/src/adapters/mod.rs` |
| Publish workflow | `.github/workflows/engine-images-cloud.yml`, matrix entry `steampipe` (no image smoke step) |

## Local build and update entry

Build from the repository root with [this Dockerfile](../../engines/images/steampipe/Dockerfile) and context `.`.

No host `.engine-cache` preparation is required by this Dockerfile. Acquisition and any source preparation happen in the build; this does not imply the build is offline.

See the [image build index](image-build-index.md) for the repeatable local build command, shared launcher impact and update record. The sections below retain this engine’s specific patches, output fields, tests and incident history.

## How it is wired

- **Build.** Steampipe and the AWS plugin are compiled from checksum-pinned source archives; the FDW archive is shipped for license and source only. In the `seed` stage, running as uid 65532, `steampipe query --output json "select 1 as seed_ready"` downloads and installs the embedded database and FDW, using a build-only `config/ai-security-scanner-build.spc` with port 19193 (amd64) or 19194 (arm64) that is removed afterwards. `installprep` then requires `db/versions.json` to name `ghcr.io/turbot/steampipe/db:14.19.0` and `fdw:2.2.7` at the pinned digests and the PostgreSQL `signature` file to match them, deletes `config`, `internal`, `logs`, `plugins`, `backups` and `db/14.19.0/data`, replaces symlinks inside `db/14.19.0/postgres` with file copies, installs the plugin as `plugins/local/aws/steampipe-plugin-aws.plugin`, and writes a stable `versions.json` and `ai-security-scanner-provenance.json`. The result is the read-only seed `/opt/ai-security-scanner/steampipe-install`.
- **Input.** One `cloud_account` asset with exactly one `aws_account_id`, granted `inventory_read` (no `configuration_read` needed), and the AWS session triple expiring in 5 to 60 minutes. Provider traffic goes through the launcher's CONNECT bridge to the managed gateway, which allows `iam.amazonaws.com` and `sts.us-east-1.amazonaws.com` on port 443.
- **Runtime install.** `prepareSteampipeInstall` creates `<tmp>/steampipe-install` in the `/tmp` tmpfs: symlinks to the seed's `db/<version>/postgres` directory and plugin file, a copy of `db/versions.json` (at most 64 KiB), and exactly one database version directory in the seed or it refuses. The launcher then writes `config/aws.spc` (`plugin = "local/aws"`, `regions = ["us-east-1"]`, database `cache = false`) and points `STEAMPIPE_INSTALL_DIR` at the install. Telemetry, update checks and cache are off, `STEAMPIPE_MAX_PARALLEL=4`, `STEAMPIPE_MEMORY_MAX_MB=768`. The tmpfs size comes from the catalog `estimated_disk_mb` (1024).
- **Invocation.** `/usr/local/bin/steampipe query --output json <tmp>/iam.sql`, where the query is `select 'aws_iam_user' as resource_type, account_id, arn, user_id, name from aws_iam_user;`.
- **Output.** `runCommandToFile` writes Steampipe's stdout to `/output/steampipe.json` (exclusive create, at most 512 MiB, removed on a non-zero exit or overflow). The database cluster, logs and state stay in the tmpfs.
- **Mapping.** `extract_steampipe_inventory` needs a JSON object with a `rows` array. Per row:
  - `account_id` (or `asset_id`) is required and `resource_type` must be `aws_iam_user`. A row without `resource_type` is read as the legacy MFA shape, which needs `control_id` `steampipe:aws_iam_user_mfa` and an account-bound `resource` ARN.
  - An `arn` must be `arn:<partition>:iam::<account_id>:user/...` for the same account.
  - The observation is an `aws_iam_user` cloud resource with native id `arn` (else `user_id`) and display name `name`. Legacy `status` and `severity` columns are ignored.
  - The asset hint is `account_id` qualified by provider `aws`, so it must equal the authorized asset's `aws_account_id`.
- **Failed or partial.** A launcher refusal, a bad seed layout, or a non-zero Steampipe exit makes the container exit 126, and the run fails without normalizing. The run is partial on any row warning, a missing `rows` array, more than 10,000 rows, an artifact over 16 MiB (`MAX_ARTIFACT_BYTES`), or an unattributed account.

## Downstream changes

- No source patches. Steampipe is built with `-X main.version=2.4.5 -X main.date=2026-08-10T13:27:42Z -X main.commit=<revision> -X main.builtBy=ai-security-scanner`.
- **Preseeded install, plugin as `local/aws`.** Nothing is downloaded or installed at run time, as [section 4](../engine-maintenance.md#4-updating-an-engine) item 4 requires. Permanent while that rule stands.
- **Per-architecture build ports** 19193 and 19194 in a build-only config (1ca91b4). `validateCloudManagedImage` in `scripts/validate-engine-catalog.mjs` requires those strings and the removal line in the Dockerfile.
- **Install in `/tmp` with symlinks** (a56f0fb). Steampipe writes its cluster and state into its install directory; `/tmp` stays noexec because the links resolve to the read-only image filesystem. Needed as long as `/output` is budgeted and `/tmp` is noexec.
- **Own `passwd` and `group`.** The image ships files naming uid 1000 (`desktop`, home `/tmp/ai-security-scanner-home`) and uid 65532 (`scanner`). No reason is recorded.

## Lessons from real runs

- 2026-08-24: multi-platform seed builds needed separate database ports -> per-architecture ports in a build-only config, removed after seeding and enforced by the validator (1ca91b4).
- 2026-09-05: the report showed `severity: high` as Steampipe's rating -> it was the launcher's own SQL literal `'high' as severity` -> labelled as product-derived (df632f3).
- 2026-09-05: no Steampipe result ever resolved a control mapping -> the entry was keyed on `aws_s3_bucket_public_access_blocked`, which the fixed query never emits -> re-keyed to `steampipe:aws_iam_user_mfa` (a5e76de), then removed in 97093ae.
- 2026-09-08: Steampipe results carried a product-authored MFA control id, title and severity -> a policy decision made in the wrapper, not upstream -> the query now selects `aws_iam_user` identity columns only, rows are inventory, and the profile label changed from `aws-iam-us-east-1-mfa` to `aws-iam-user-inventory-us-east-1` (97093ae).
- 2026-10-02: on a live account the run failed -> the working install, including the embedded PostgreSQL closure and AWS plugin, was copied into `/output` and outgrew the output budget -> install in the `/tmp` tmpfs linking the image's executables; only `steampipe.json` reaches `/output` (a56f0fb, published as `2.4.5-6` in dfe8af1, pinned in bad4485).

## Updating this engine

Follow [section 4](../engine-maintenance.md#4-updating-an-engine), then:

- **Move the closure together.** Dockerfile `ARG` revisions, `ADD --checksum` values, archive names (`steampipe-v2.4.7.tar.gz`, `steampipe-plugin-aws-v1.34.0.tar.gz`, `steampipe-postgres-fdw-v2.2.7.tar.gz`), the `-X main.version` and `main.date` flags and the `database.digest` and `fdw.digest` labels; in `installprep/main.go` the `databaseVersion`, `databaseDigest`, `fdwVersion` and `fdwDigest` constants, the `InstalledFrom` strings and the three revisions in the provenance record; `plan.json` `build_recipe` (`aws_plugin`, `embedded_database`, `postgres_fdw`); `SOURCE-OFFER.md`. `validateCloudManagedImage` requires the `build_recipe` plugin, database and FDW digests and the plugin and FDW revisions to appear in the Dockerfile.
- **Layout.** Re-check that the seed still has exactly one `db/<version>/postgres`, `db/versions.json` with `struct_version` 20220411 and `plugins/local/aws/`, and that Steampipe does not write into the linked directories. Launcher tests `TestSteampipeInstallLinksTheSeedExecutablesInsteadOfCopyingThem` and `TestSteampipeInstallRefusesAnUnexpectedSeed` use `db/14.19.0`.
- **Output shape.** Re-check the `query --output json` envelope (`rows` array) and the `aws_iam_user` columns `account_id`, `arn`, `user_id` and `name`.
- **Runtime user.** On Unix the desktop runs the container as the host user's uid (`runtime_user_mapping` in `src-tauri/src/container_runtime.rs`), while the image `passwd` names only 1000 and 65532. After changes here, verify a run under a uid other than 1000.
- **Unrecorded inputs.** `installprep/main.go`, `installprep/go.mod`, `passwd`, `group`, `POSTGRESQL-COPYRIGHT`, `SOURCE-OFFER.md` and `Dockerfile.dockerignore` change the image but are not recorded by hash in `plan.json`, so the publication guard cannot see them. Change them only together with a new tag. `installprep/main_test.go` holds only `TestParsePositiveInt64`, and no CI job runs it; a successful image build is the seed's real check.
- **Tests.** `src-tauri/tests/adapter_fixtures.rs`: `steampipe_current_and_pinned_legacy_rows_are_iam_user_inventory_not_findings` (the only test of the current row shape), `steampipe_inventory_fails_closed_per_row_without_erasing_valid_siblings`, `malformed_steampipe_rows_cannot_hide_a_record_boundary_overflow`, `inventory_schema_and_asset_boundaries_fail_closed_but_known_empty_shapes_complete`, `inventory_fixtures_preserve_typed_upstream_facts_and_exact_provenance`. The shared fixture `src-tauri/tests/fixtures/adapters/steampipe.json` is still the legacy MFA shape. Launcher test `TestSteampipeQueryIsExactUpstreamIAMUserInventory` pins the query. A changed warning sentence needs its Traditional Chinese form; `tests/frontend/warningPresentation.test.ts` pins the exact Chinese form of the Steampipe warnings.
- **Hard-coded values.** Keep managed tag `2.4.7-1`, reported version `2.4.7`, full source revision, workflow selector, Dockerfile labels, catalog/plan identity and publication verifier aligned. Search current source with `rg` when updating; preserve dated records and captured fixtures. `support_until` is 2026-12-25.
- **Compare with raw output.** The number of rows in the run's raw `steampipe.json` should equal the `aws_iam_user` observations on the account, each with the row's `arn` as native id.
- **Publishing.** The next push that touches `engines/images/steampipe/` needs a new tag; see [publishing a changed image](cloud-launcher.md#publishing-a-changed-image).

## 2026-10-14 source update

The replacement recipe targets `2.4.7-1` at upstream commit `5c62651887b3e1d127049722e7216b915d4b075d`. The replacement is now published and pinned in the current catalog; the verified publication is recorded below. See the [batch update record](updates/2026-10-14.md) for changed inputs, retained rules and verification.

## 2026-10-15 verified publication

[Publication run](https://github.com/TED-H-com/ai-security-scanner/actions/runs/38689379709) binds both platform images to `28bd1a3e23c961ce734503a6eeb59aa7d124ea4f`. Five source/SBOM attestations, four SBOMs, checksums and anonymous index, version tag, platform manifest and config bytes were independently verified before catalog activation. See the [batch verification record](updates/2026-10-14.md#verified-publication-and-catalog-activation) for native execution results and the remaining scope limits.
