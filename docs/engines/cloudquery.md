# CloudQuery

Syncs seven AWS IAM tables of one authorized AWS account into per-table NDJSON under the fixed profile `aws-iam-us-east-1`, using the last fully public CloudQuery closure. Rows become inventory observations, not findings.

| Item | Value |
| --- | --- |
| Upstream | [cloudquery/cloudquery](https://github.com/cloudquery/cloudquery), version `3.5.3-aws9.2.0-file1.0.4`, revision `086baf7f70ee3c1069513d41f321720a5e7d2bb9`. Rules/data identities are pinned in `engines/catalog.json`. |
| Image | `ghcr.io/ted-h-com/ai-security-scanner-engine-cloudquery:3.5.3-aws9.2.0-file1.0.4-1`, published for linux/amd64 and linux/arm64 by [run 42186918801](https://github.com/TED-H-com/ai-security-scanner/actions/runs/42186918801) from `5ba7d2e20f6eb8913aeb3097bed43860451ee522`. Exact digests and verified attestations are in [the publication record](updates/2026-11-06-publications.json). |
| Build inputs | `engines/images/cloudquery/`: `Dockerfile`, `dependencies.lock.json`, `plugins.yml`, `SOURCE-OFFER.md`, `plan.json` (no dockerignore) |
| Launcher | `runCloudQuery` and `cloudQueryConfiguration` in `engines/images/cloud-launcher/main.go` ([shared launcher](cloud-launcher.md)) |
| Wrapper | None |
| Adapter | `read_cloudquery_rows` and `extract_cloudquery_inventory` in `src-tauri/src/adapters/mod.rs` |
| Publish workflow | `.github/workflows/engine-images-cloud.yml`, matrix entry `cloudquery` and the step "Run the anonymous CloudQuery amd64 smoke contract" |

## Local build and update entry

Build from the repository root with [this Dockerfile](../../engines/images/cloudquery/Dockerfile) and context `.`.

No host `.engine-cache` preparation is required by this Dockerfile. Acquisition and any source preparation happen in the build; this does not imply the build is offline.

See the [image build index](image-build-index.md) for the repeatable local build command, shared launcher impact and update record. The sections below retain this engine’s specific patches, output fields, tests and incident history.

## How it is wired

- **Build.** The three upstream components use release binaries; only the project-owned shared launcher is compiled. The Dockerfile adds upstream's release binaries for amd64 and arm64 (the CLI and the two plugin zips) with `ADD --checksum`, checks the SHA-256 of each plugin binary extracted from its zip, and ships the three source archives in `/usr/share/source/cloudquery/` (`cli-e27e4ab.tar.gz`, `aws-804be3a.tar.gz`, `file-600ffdd.tar.gz`) with the lock, `plugins.yml`, the Dockerfile and the launcher source. The CLI is `/app/cloudquery`; the plugins are `/usr/local/libexec/cloudquery-source-aws` and `/usr/local/libexec/cloudquery-destination-file`.
- **Input.** One `cloud_account` asset with exactly one `aws_account_id`, granted `inventory_read` (no `configuration_read` needed), and the AWS session triple expiring in 5 to 60 minutes. Provider traffic goes through the launcher's CONNECT bridge to the managed gateway, which allows `ec2.us-east-1.amazonaws.com`, `iam.amazonaws.com` and `sts.us-east-1.amazonaws.com` on port 443. The 27 AWS actions the profile requires are listed in `dependencies.lock.json` `required_aws_actions`.
- **Invocation.** The launcher writes `cloudQueryConfiguration()` to `<tmp>/cloudquery.yml` and runs `/app/cloudquery sync <tmp>/cloudquery.yml --cq-dir <tmp>/cq --no-log-file --log-console --telemetry-level none`. The configuration selects `aws_iam_accounts`, `aws_iam_credential_reports`, `aws_iam_groups`, `aws_iam_password_policies`, `aws_iam_policies`, `aws_iam_roles` and `aws_iam_users` in `us-east-1`, runs both plugins with `registry: local`, and sets the file destination to `directory: /output`, `format: json`, `no_rotate: true`, `write_mode: append`. It must equal `plugins.yml` byte for byte.
- **Output.** The file destination writes `/output/<table>.json`, one JSON row per line (`WriteTableBatch` at the pinned revision). The AWS plugin also syncs seven child tables: `aws_iam_group_policies`, `aws_iam_role_policies`, `aws_iam_ssh_public_keys`, `aws_iam_user_access_keys`, `aws_iam_user_attached_policies`, `aws_iam_user_groups` and `aws_iam_user_policies`.
- **Mapping.** `read_cloudquery_rows` streams each file (up to 512 MiB per file and in total, 64 MiB per row), keeps only each row's top-level scalar columns, and verifies length and SHA-256 over the whole file before any row is used. `extract_cloudquery_inventory` picks the table from the file name. Child tables stay raw evidence without a warning; any other unknown name warns. Each row needs `account_id`, except that `aws_iam_credential_reports` rows (which have none in plugin 9.2.0) take the account from a root or `user/` ARN. Each row becomes a cloud resource observation of its table, with the asset hint `account_id` qualified by provider `aws`:

  | Table | Native id | Display name |
  | --- | --- | --- |
  | `aws_iam_accounts`, `aws_iam_password_policies` | `account_id` | none |
  | `aws_iam_credential_reports` | `arn`, else `user_id` | `user`, else `user_name` |
  | `aws_iam_groups` | `arn`, else `group_id` | `group_name` |
  | `aws_iam_policies` | `arn`, else `policy_id` | `policy_name` |
  | `aws_iam_roles` | `arn`, else `role_id` | `role_name` |
  | `aws_iam_users` | `arn`, else `user_id` | `user_name` |

- **Failed or partial.** A launcher refusal or a non-zero `cloudquery sync` exit makes the container exit 126, and the run fails without normalizing. The run is partial on a malformed or oversized line, more than 10,000 rows in one file, a length or hash mismatch, more than 512 MiB of files, an unknown file name, a row without an account, or an account that matches no `aws_account_id` on the authorized asset.

## Downstream changes

- **Frozen plugin boundary.** `engines/upstream-refresh-policy.json` freezes automatic updates of the public AWS 9.2.0 / file 1.0.4 closure. The manually reviewed CLI replacement is 3.5.3: actual 6.49.2 execution rejects this protocol and directs users to CLI 3.0.1–3.5.3. CLI 3.5.3 negotiates both native plugins and retrieves the selected tables without registry access. The plugin knowledge date remains 2023-01-10, with support date 2023-04-10; a newer CLI does not refresh provider coverage.

## Lessons from real runs

- 2026-10-02: a live AWS run failed on its first provider call -> CloudQuery's Go 1.19 build does not accept the gateway's `socks5h://` scheme -> launcher CONNECT bridge (e4571df, published in 9f6a976, pinned in eba1c22).
- 2026-10-02: the run failed on a live account -> file destination 1.0.2 panics with "unexpected end of JSON input" when a row carries an empty JSON column -> file destination 1.0.4; its source archive, lock, source offer and smoke check moved with it (a56f0fb, published as `2.0.31-aws9.2.0-6` in dfe8af1, pinned in bad4485).
- 2026-10-02: CloudQuery exited 0 and wrote every table but read Partial -> credential report rows have no `account_id`, one `aws_iam_policies` row was 7 MB (file 11 MB) against the 1 MiB line limit, and the child tables warned -> account from the credential report ARN only, streamed reading of top-level scalars under 512 MiB bounds, child tables kept raw; adapter contract 0.2.0 -> 0.2.1. On the captured artifacts 28 resources now normalize completely, where 23 did and 5 rows were dropped before (08fd9da).

## Updating this engine

CloudQuery is frozen, so [section 4](../engine-maintenance.md#4-updating-an-engine) refreshes do not apply. When something in the closure must change anyway:

- **Move the closure together.** `dependencies.lock.json` (components, artifacts, `tables`, `network_destinations`, `required_aws_actions`, `output`); `plugins.yml` and `cloudQueryConfiguration()`, byte-equal; Dockerfile URLs, `ADD --checksum` values, per-architecture `aws_sha` and `file_sha`, and labels; `plan.json` `provider_plugins`, `component_source_archives`, `dependency_lock`, `provider_lock` and `configuration_lock`; and the hard-coded `expectedPlugins`, `expectedTables`, `expectedDestinations`, `expectedAwsActions` and `expectedComponents` in `validateCloudQueryPlan` (`scripts/validate-engine-catalog.mjs`). A new endpoint also changes the catalog network closure.
- **Output shape.** Re-check the `<table>.json` names, one row per line, the columns in the table above, the missing `account_id` in credential reports, and the child-table list in `is_cloudquery_dependent_table`. A new child table would warn as an unknown file name.
- **Media type.** Real `<table>.json` artifacts get `application/json` from `media_type_for_path` (`src-tauri/src/artifact_store.rs`), and for that type a zero-byte file warns. The empty-file case in `inventory_schema_and_asset_boundaries_fail_closed_but_known_empty_shapes_complete` uses `application/x-ndjson`.
- **Tests.** `src-tauri/tests/adapter_fixtures.rs`: `cloudquery_live_table_shapes_normalize_completely`, `cloudquery_account_fallback_is_limited_to_credential_report_arns`, `inventory_fixtures_preserve_typed_upstream_facts_and_exact_provenance` (fixture `cloudquery.json`, mounted as `aws_iam_users.json`) and the empty-shape test above; `cloudquery_rows_keep_only_top_level_scalar_columns` and `cloudquery_rows_verify_the_recorded_length_and_hash` in `src-tauri/src/adapters/mod.rs`; launcher test `TestCloudQueryConfigurationIsExactLocalSourceClosure`; the workflow smoke step. A new warning sentence needs its Traditional Chinese form in `src/engineWarningPresentation.ts`, or the census in `tests/frontend/warningPresentation.test.ts` fails (b2d0155).
- **Hard-coded values.** Keep managed tag `3.5.3-aws9.2.0-file1.0.4-1`, engine version `3.5.3-aws9.2.0-file1.0.4`, source and rule revisions, workflow checks, Dockerfile labels, catalog/plan identity and publication verifier aligned. Preserve dated records and captured fixtures. `support_until` is 2023-04-10.
- **Compare with raw output.** In the run's raw evidence, each line of the seven selected table files should be one observation of that `resource_type` on the account, with the native id from the table above; child-table files produce none. A warning naming an identifier means the asset lacks that `aws_account_id`.
- **Publishing.** The next push that touches `engines/images/cloudquery/` needs a new tag; see [publishing a changed image](cloud-launcher.md#publishing-a-changed-image).
