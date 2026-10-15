# Prowler

Runs Prowler's IAM checks against exactly one authorized AWS account, Azure subscription or GCP project under the fixed profile `aws-azure-gcp-narrow-iam`. It is the only cloud engine with Azure and GCP profiles, and both depend on six downstream patches.

| Item | Value |
| --- | --- |
| Upstream | [prowler-cloud/prowler](https://github.com/prowler-cloud/prowler), version `5.44.0`, source ref `5.44.0`, revision `499fd637f3393b485833b08cdaf4172917c5698e`. |
| Image | `ghcr.io/ted-h-com/ai-security-scanner-engine-prowler:5.44.0-1` (`plan_kind: managed_rebase`), published for linux/amd64 and linux/arm64 by [this run](https://github.com/TED-H-com/ai-security-scanner/actions/runs/38696218276) from `14fe1359a84d00a9d397e0b721e79d95929da919`. Exact index/platform digests and verified evidence are in `engines/catalog.json` and `plan.json`. |
| Build inputs | `engines/images/prowler/`: `Dockerfile`, `Dockerfile.dockerignore`, `apply-runtime-patches.py`, `patches/` (`series`, `0001` to `0006`, `verify-patches.sh`, `README.md`), `plan.json` |
| Launcher | `prowlerInvocation`, `runProwler`, `validateProwlerOutput` in `engines/images/cloud-launcher/main.go` ([shared launcher](cloud-launcher.md)) |
| Wrapper | None beyond the launcher. `scripts/prowler-catalog-contract.mjs` pins the provider contracts, patch hashes, wrapper strategy and catalog notice. |
| Adapter | `extract_prowler` in `src-tauri/src/adapters/mod.rs` |
| Publish workflow | `.github/workflows/engine-images-cloud.yml`, matrix entry `prowler` and the step "Run the anonymous Prowler amd64 patch and launcher contract" |

## Local build and update entry

Build from the repository root with [this Dockerfile](../../engines/images/prowler/Dockerfile) and context `.`.

No host `.engine-cache` preparation is required by this Dockerfile. Acquisition and any source preparation happen in the build; this does not imply the build is offline.

See the [image build index](image-build-index.md) for the repeatable local build command, shared launcher impact and update record. The sections below retain this engine’s specific patches, output fields, tests and incident history.

## How it is wired

- **Input.** One asset: `cloud_account` with `aws_account_id`, `subscription` with `azure_subscription_id`, or `project` with `gcp_project_id`, granted `inventory_read` and `configuration_read`. The credential channel holds exactly the AWS session triple, `AZURE_ACCESS_TOKEN`, or `GOOGLE_OAUTH_ACCESS_TOKEN`, each expiring in 5 to 60 minutes. Provider traffic goes through the launcher's CONNECT bridge to the managed gateway, which allows only `iam.amazonaws.com`, `sts.us-east-1.amazonaws.com`, `ec2.us-east-1.amazonaws.com`, `organizations.us-east-1.amazonaws.com`, `management.azure.com` and `cloudresourcemanager.googleapis.com` on port 443.
- **Invocation.** `/home/prowler/.venv/bin/prowler` with `--output-formats json-ocsf --output-filename prowler --output-directory /output --ignore-exit-code-3 --no-banner --no-color` and one provider profile:
  - AWS: `aws --service iam --region us-east-1`, plus `--skip-sh-update`
  - Azure: `azure --access-token-auth --access-token-expires-at <earliest credential expiry> --subscription-ids <subscription-id> --service iam`
  - GCP: `gcp --project-ids <project-id> --checks iam_audit_logs_enabled iam_no_service_roles_at_project_level iam_role_kms_enforce_separation_of_duties iam_role_sa_enforce_separation_of_duties --skip-api-check --gcp-retries-max-attempts 2`
- **Output.** Prowler writes `/output/prowler.ocsf.json` directly. `runProwler` refuses to start if the file already exists. After exit 0, `validateProwlerOutput` requires a non-empty regular file opened without following links, at most 512 MiB, holding one JSON array of objects (each at most 8 MiB, at most 1,000,000) with nothing after it.
- **Mapping.** For each array element, `extract_prowler` takes:
  - status from `status_code` (Prowler 5.39 keeps PASS/FAIL/MANUAL there; `status` holds the lifecycle value `New`). PASS and MANUAL are skipped.
  - rule id from `metadata.event_code`, then `finding_info.analytic.uid`, then `CheckID`.
  - title from the first non-empty `status_detail`, legacy `StatusExtended`, `finding_info.title` or legacy `CheckTitle`/`check_title`, then `Prowler check <id>`. The result detail names the failure; the check title usually describes the passing condition. Severity comes from Prowler's `severity` through `parse_severity`, location from the first `resources[]` entry, description from `finding_info.desc`, remediation from `remediation.desc`, tag `format:ocsf`.
  - the asset from `cloud.account.uid` qualified by `cloud.provider`. It must equal a native identifier on the authorized asset; there is no single-asset fallback. Unmatched results are dropped and named once per identifier in a warning and in `unattributed`.
- **Failed or partial.** A launcher refusal, a Prowler exit other than 0 (exit 3 for failed checks is suppressed), or an invalid OCSF file makes the container exit 126, and `src-tauri/src/orchestrator.rs` fails the run without normalizing. The run is partial when the adapter warns: a non-object record, a record with no failing status or no check id, an unattributed account, an artifact over 16 MiB (`MAX_ARTIFACT_BYTES`), or 10,000 records.

## Downstream changes

The pinned upstream image has neither git nor patch, so `apply-runtime-patches.py` applies the hunks during the build. It checks the series order, each patch's SHA-256 and file set, and the pre- and post-patch SHA-256 of the six runtime files; test hunks are not installed. Reason recorded in `patches/README.md`: upstream at this pin has no Azure `--access-token-auth`, and its GCP project selection lists every accessible project before filtering.

| Patch | Runtime files | Change |
| --- | --- | --- |
| 0001 | `azure_provider.py`, Azure `arguments.py`, `common/provider.py` | Non-refreshing Azure ARM static-token auth, exact subscription resolution, IAM service only |
| 0002 | `gcp_provider.py` | Exact requested-project lookups instead of listing every project |
| 0003 | `cloudresourcemanager_service.py` | No ambient GCP organization search |
| 0004 | `gcp_provider.py` | No parent-organization enrichment when exact project ids are given |
| 0005 | `finding.py`, `azure_provider.py` | Tenant taken from the exact subscription instead of tenant enumeration |
| 0006 | `azure_provider.py` | Rejects a subscription unless ARM reports `Enabled` (00eec6f) |

- Plan `build_recipe.patch_audit` records all six patches, 15 verified sequential source-file transitions, upstream source references, the contribution rationale, owners, fixtures and per-capability removal conditions. Reviewed 2026-10-03; review again on the next source update or by 2026-11-01. No upstream issue or submission is invented. The GCP four-check restriction and Azure non-refreshing token mode need separate upstream API decisions; they remain explicit product exceptions.
- The Dockerfile also sets `chmod 0755 /home/prowler` (4d2bca9) and points `HOME` and `XDG_CACHE_HOME` into `/tmp`.

## Lessons from real runs

- 2026-08-24: Prowler had to run as the managed non-root user -> `/home/prowler` was mode 0711 -> made 0755 (4d2bca9).
- 2026-09-05: no Prowler finding ever resolved a control mapping -> the mapping was keyed on `s3_bucket_level_public_access_block`, an S3 check the `--service iam` profile cannot emit -> re-keyed to `iam_customer_attached_policy_no_administrative_privileges`, and the fixture now uses IAM checks the profile reaches (a5e76de).
- 2026-09-05: an authorized account without its native identifier made Prowler's results all drop, and the run read as a clean scan -> provider-qualified OCSF accounts never fall back to the only asset, and nothing named the cause -> one warning per unmatched identifier with the count and the fix (165ef62).
- 2026-10-02: a live AWS run failed on its first provider call -> botocore read the gateway's `socks5h://` URL as an HTTP proxy -> launcher CONNECT bridge (e4571df, published in 9f6a976, pinned in eba1c22).
- 2026-10-02: Prowler then completed on a live AWS account (a56f0fb). Its tag still moved to `5.39.1-7` because the shared launcher changed (dfe8af1, pinned in bad4485).
- 2026-10-02: failed checks appeared to pass in the priority cards because `finding_info.title` states the passing condition -> use `status_detail` for the headline and retain `finding_info.desc` in scanner details, with adapter contract 0.2.2. Replaying the latest captured AWS output verified all 14 FAIL headlines, descriptions and stable identities; all 31 report findings remain available.

## Updating this engine

Follow [section 4](../engine-maintenance.md#4-updating-an-engine), then:

- **Rebase.** Put the new upstream digest in the Dockerfile `FROM` line and in `plan.json` `verified_upstream_artifact`; `validateCloudManagedImage` in `scripts/validate-engine-catalog.mjs` requires them to match. Regenerate each surviving patch against the new revision, update `PIN` in `patches/verify-patches.sh`, and run it with `--pytest` on a Prowler clone that contains the pin (`engines/upstreams.lock.json` records a different research revision).
- **Patch hashes** live in `apply-runtime-patches.py`, `patches/verify-patches.sh`, `plan.json` `downstream_runtime_patches` and `PROWLER_DOWNSTREAM_RUNTIME_PATCHES` in `scripts/prowler-catalog-contract.mjs`. The post-patch file hashes are also in the workflow's Prowler smoke step.
- **Output shape.** Re-check `status_code`, `status_detail`, `metadata.event_code`, `finding_info.title`, `finding_info.desc`, `severity`, `resources[]`, `cloud.account.uid`, `cloud.provider` and `remediation.desc`, and that the flags above still exist and still produce one array in `prowler.ocsf.json`. The smoke step greps `--help` for `--skip-sh-update`, `--access-token-auth` and `--project-ids`.
- **Mapping.** `iam_customer_attached_policy_no_administrative_privileges` in `mappings/control-mappings.json` must remain a check the AWS profile emits. A content change needs a `mapping_version` bump.
- **Tests.** `src-tauri/tests/adapter_fixtures.rs` with fixtures `prowler-ocsf.json` and `prowler-5.39-multi-provider.ocsf.json` (`native_fixtures_normalize_without_inventing_inventory_findings`, `prowler_5_39_ocsf_maps_provider_native_accounts_to_canonical_assets`, `prowler_native_identifier_collisions_fail_closed`, `prowler_names_the_account_it_could_not_attribute_rather_than_each_dropped_rule`); `src-tauri/tests/source_authorization.rs` (`azure_and_gcp_profiles_release_only_discovery_and_narrow_prowler`, `azure_and_gcp_ui_capability_checkout_reaches_narrow_prowler_dispatch`); `tests/engines/prowlerCatalogContract.test.mjs`; launcher tests `TestProwlerProviderInvocationsAreExactAndNarrow` and `TestProwlerOutputValidationIsBoundedAndFailClosed`.
- **Hard-coded values.** Keep managed tag `5.44.0-1`, reported version `5.44.0`, full source revision, workflow selector, Dockerfile labels, catalog/plan identity and publication verifier aligned. Search current source with `rg` when updating; preserve dated records and captured fixtures. `support_until` is 2026-12-28.
- **Compare with raw output.** In the run's raw `prowler.ocsf.json`, every element with `status_code` FAIL should appear as a finding on the asset; two FAIL elements with the same check and resource merge into one finding with two evidence items (`merge_finding`). Compare `metadata.event_code`, `severity`, `status_detail` and `resources[0].uid` with the normalized rule, severity, title and location; `finding_info.desc` and `remediation.desc` remain in scanner details. The original check title remains in raw evidence. A warning that names an identifier means the asset lacks that native identifier.
- **Publishing.** The next push that touches `engines/images/prowler/` needs a new tag; see [publishing a changed image](cloud-launcher.md#publishing-a-changed-image).

## 2026-10-14 source update

The replacement recipe targets `5.44.0-1` at upstream commit `499fd637f3393b485833b08cdaf4172917c5698e`. The replacement is now published and pinned in the current catalog; the verified publication is recorded below. See the [batch update record](updates/2026-10-14.md) for changed inputs, retained rules and verification.

## 2026-10-15 verified publication

[Publication run](https://github.com/TED-H-com/ai-security-scanner/actions/runs/38696218276) binds both platform images to `14fe1359a84d00a9d397e0b721e79d95929da919`. Five source/SBOM attestations, four SBOMs, checksums and anonymous index, version tag, platform manifest and config bytes were independently verified before catalog activation. See the [batch verification record](updates/2026-10-14.md#verified-publication-and-catalog-activation) for native execution results and the remaining scope limits.
