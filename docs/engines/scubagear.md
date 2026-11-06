# ScubaGear

Checks one approved Microsoft 365 tenant (asset kind `tenant`, provider `microsoft365`) against CISA's SCuBA baseline for Microsoft Entra ID. The fixed profile `aad-commercial-graph-token` runs the `aad` product only, in the commercial environment, with the bundled OPA, one short-lived Graph token, and `graph.microsoft.com:443` as its only destination.

| Item | Value |
| --- | --- |
| Upstream | [cisagov/ScubaGear](https://github.com/cisagov/ScubaGear), version `2.0.0`, revision `6e5a1a421b36c5a1fb3fd983b8c4bcd5b7a6c61d`. Rules/data identities are pinned in `engines/catalog.json`. |
| Image | `ghcr.io/ted-h-com/ai-security-scanner-engine-scubagear:2.0.0-1`, published for linux/amd64 and linux/arm64 by [run 42186918838](https://github.com/TED-H-com/ai-security-scanner/actions/runs/42186918838) from `5ba7d2e20f6eb8913aeb3097bed43860451ee522`. Exact digests and verified attestations are in [the publication record](updates/2026-11-06-publications.json). |
| Build inputs | `engines/images/scubagear/`: `Dockerfile`, `Dockerfile.dockerignore`, `dependencies.lock.json`, `THIRD-PARTY-NOTICES.md`; `engines/images/m365-launcher/`: `main.go`, `go.mod`, `prepare_source.py`; the pinned source archive, official PowerShell 7.6.9 archives, Microsoft.Graph.Authentication 2.25.0, powershell-yaml 0.4.12, OPA 1.19.0 static binaries (amd64, arm64), digest-pinned base images |
| Launcher | `/usr/local/bin/ai-security-scanner-m365-launcher` ([shared launcher](m365-launcher.md)) |
| Wrapper | `engines/images/scubagear/run-scubagear.ps1`, installed as `/opt/ai-security-scanner/run-scubagear.ps1` |
| Adapter | `extract_scubagear` → `extract_m365` in `src-tauri/src/adapters/mod.rs` |
| Publish workflow | `.github/workflows/engine-images-m365.yml`, matrix entry `scubagear` |

## Local build and update entry

Build from the repository root with [this Dockerfile](../../engines/images/scubagear/Dockerfile) and context `.`.

No host `.engine-cache` preparation is required by this Dockerfile. Acquisition and any source preparation happen in the build; this does not imply the build is offline.

See the [image build index](image-build-index.md) for the repeatable local build command, shared launcher impact and update record. The sections below retain this engine’s specific patches, output fields, tests and incident history.

## How it is wired

- **Launch.** `--engine scubagear --scope /run/ai-security-scanner/scope.json --output /output`. The launcher validates the scope (one `microsoft365` tenant with `inventory_read` and `configuration_read`) and the credential file `/run/ai-security-scanner/credentials.json` before PowerShell starts.
- **Token.** Exactly one `MSGRAPH_ACCESS_TOKEN`. The host stops using it at the token's expiry or one hour after sign-in, whichever comes first (`bounded_expiry` in `src-tauri/src/source_authorization/provider.rs`); the launcher refuses an `expires_at` in the past or more than 65 minutes ahead.
- **Environment.** PowerShell gets a rebuilt environment: the gateway as `socks5://<gateway-ip>:1080` in `ALL_PROXY`, `HTTP_PROXY` and `HTTPS_PROXY` (both cases), `AI_SECURITY_SCANNER_PROXY` kept as `socks5h://`, HOME and XDG directories under `/tmp`, and `SCUBAGEAR_SKIP_VERSION_CHECK=1`.
- **Sign-in.** The wrapper requires exactly one tenant GUID in the `microsoft365_tenant_id` or `microsoft_tenant_id` namespace, reads the token into a SecureString, runs `Connect-MgGraph -AccessToken $secureToken -NoWelcome` with Graph auth 2.25.0, and stops unless `Get-MgContext` reports that tenant. `Disconnect-MgGraph` runs in `finally`.
- **Invocation.** `Invoke-SCuBA -ProductNames @('aad') -M365Environment 'commercial' -OPAPath '/opt/ai-security-scanner/opa' -OutPath /output/upstream -LogIn $false -Quiet -KeepIndividualJSON -SilenceBODWarnings -SkipDoH $true -ErrorAction Stop`.
- **Upstream output.** `/output/upstream/M365BaselineConformance_<yyyy_MM_dd_HH_mm_ss>/` holds `IndividualReports/AADReport.json`, the HTML reports and `DebugLogs/`. The wrapper requires exactly one `AADReport.json`: not a link, at most 16 MiB, one top-level item (upstream writes `ConvertTo-Json @($ReportJson)`, CreateReport.psm1:427).
- **Wrapper normalization.** For each control in `Results[].Controls[]` the verdict is `Result`, or `OriginalResult` when `Result` is `Incorrect result`. `Pass` becomes `Pass`; `Fail` and `Warning` become `Failed`; any other value (`N/A`, `Error`) is dropped and left to the counters. Rows carry `PolicyId` (`Control ID`), `Requirement` (badge block cut, HTML removed), `Result`, `SourceResult`, `SourceCriticality`, `Severity`, `Service` (`Microsoft Entra ID`), `asset_id` and `HelpUrl` (the group's reference URL).
- **Severity.** `shall`, `shall/3rd party` and `shall/not-implemented` become `high`; the three `should` forms become `medium`; anything else is `unknown`. The original rating stays in `SourceCriticality`.
- **Wrapper document.** `/output/scubagear.json`, written atomically and never overwritten: `Engine: ScubaGear`, `Provenance` (version, revision, profile, `raw_report` path) and `Diagnostics` copied from upstream's `ReportSummary`: `passes`, `failures`, `warnings`, `errors`, `manual`, `omitted` (`Omits`), `disputed` (`IncorrectResults`), plus `normalized_results`, the number of rows written.
- **Adapter.** Reads `scubagear.json` only; everything under `attempt-<n>/output/upstream/` is kept as evidence and never normalized (`is_preserved_upstream_evidence_path`). Each `Failed` row becomes one finding: rule id `PolicyId`, title `Requirement`, severity `Severity`, resource `Service`, reference `HelpUrl`, tag `source-criticality:<rating>` (for example `source-criticality:should/3rd-party`), and `tenant-disputed` when `SourceResult` is `Incorrect result`. `Pass` rows produce nothing.
- **Partial** (findings kept, engine run partially completed): `errors` above 0 ("could not be evaluated"), `normalized_results` below `passes + failures + warnings`, `normalized_results` different from the `Results` length, a missing or different `Engine`, or a row without a status or rule id. `manual` ("left without an automated verdict"), `omitted` and `disputed` are disclosed without withholding completion.
- **Failed** (nothing adapted, `src-tauri/src/orchestrator.rs`): any nonzero exit, including a launcher refusal (126) and every wrapper `throw`: tenant mismatch, not exactly one bounded `AADReport.json`, an existing `/output/upstream`, an `Invoke-SCuBA` error.

## Permissions

- ScubaGear lists the least Graph permission for each cmdlet in `PowerShell/ScubaGear/schemas/ScubaGearApiCatalog.json` (in the image: `/opt/ai-security-scanner/ScubaGear/schemas/ScubaGearApiCatalog.json`). The file starts with a UTF-8 BOM, so read it as `utf-8-sig`.
- The product requests 17 read permissions, kept identical in five places:
  1. `src-tauri/src/source_authorization/provider.rs` `microsoft365_required_permissions()`: the sign-in refuses a token that lacks one.
  2. `src-tauri/src/bootstrap/executor.rs` `microsoft365_application_permissions()`: temporary-access app roles.
  3. `bootstrap/microsoft365-readonly-permissions.json` `application_permissions`.
  4. `src/cloudSetupGuide.ts` `MICROSOFT_365_READ_PERMISSIONS`: the setup guide.
  5. `cloud-setup/microsoft365-read-only.ps1` `$ReadPermissions`: the setup script. A rerun adds missing permissions and admin consent, which is what a tenant set up before e5edc84 needs.
- `tests/frontend/cloudSetupGuide.test.ts` binds 2, 3 and 4 to 1, and `tests/frontend/cloudSetupScripts.test.ts` binds 5 to 4. The fake grant `microsoft365_permissions()` in `src-tauri/tests/source_authorization.rs` must list any new name.
- Never add a write, `ReadWrite` or `AccessAsUser` permission: `validate_microsoft_read_scopes` refuses the token.
- Re-derive after an update, from the repository root with the new revision checked out under `.upstreams/`:

```sh
python3 - <<'EOF'
import json, re
catalog = json.loads(open('.upstreams/cisagov/ScubaGear/PowerShell/ScubaGear/schemas/ScubaGearApiCatalog.json', 'rb').read().decode('utf-8-sig'))
src = open('src-tauri/src/source_authorization/provider.rs').read()
body = src[src.index('fn microsoft365_required_permissions'):]
product = set(re.findall(r'"([^"]+)"', body[:body.index('\n}\n')]))
for e in catalog:
    missing = set(e['leastPermissions']) - product
    if 'aad' in e['scubaGearProduct'] and missing:
        print(e['moduleCmdlet'], sorted(missing), '->', sorted(product & set(e['higherPermissions'])) or 'NOT COVERED')
EOF
```

At 4d34e9a it prints seven lines: the product does not request `GroupMember.Read.All`, `RoleAssignmentSchedule.Read.Directory`, `RoleEligibilitySchedule.Read.Directory` or `User.Read` by name, and each line shows the broader requested permission that covers it. A `NOT COVERED` line names a permission to add in all five places.

## Downstream changes

Upstream detection is unmodified. The image carries the pinned ScubaGear source, Rego policies and report code as published; `prepare_source.py` checks the archive digest and changes only file modes and timestamps. Differences from running upstream as-is:

- **Fixed profile** (`run-scubagear.ps1`, plan `build_recipe.profile`, lock `product_profile`): AAD only, commercial, token sign-in, no DNS-over-HTTPS, no version check. Reason: Graph-only egress and one tenant asset. Remove when the product owner approves more products and their endpoints; until then `MICROSOFT_365_SCOPE_LIMIT` in `src-tauri/src/beginner_report.rs` tells the reader only Entra ID was checked.
- **Token sign-in without `-ContextScope`** (`run-scubagear.ps1`, Dockerfile build check; e4571df): Graph auth 2.25.0 rejects `-ContextScope` with `-AccessToken`. Keep while the pinned module rejects the pair.
- **Disputed results judged on `OriginalResult`** (`run-scubagear.ps1`, `tenant_disputed_controls`; cc3b455): upstream rewrites an annotated result to `Incorrect result` and counts it outside `Failures` (CreateReport.psm1:331-348), which would hide a real failure. Remove when upstream keeps the verdict and its counter.
- **Criticality to severity** (`run-scubagear.ps1`; 19a7832): upstream has no severity; only the six reviewed criticality values map, and anything else stays `unknown`. Remove if upstream publishes a severity.
- **Badge block cut** (`ConvertTo-RequirementText`; 95936ac): ScubaGear 1.8 appends `<div class='policy-indicators'>` to each requirement (CreateReport.psm1:254-255). Remove when upstream keeps indicators out of `Requirement`.
- **No exit failure for unevaluated controls** (`run-scubagear.ps1`; 7048108): a nonzero exit discards every finding, so the wrapper writes its document and leaves errors to `Diagnostics`. Permanent.
- Launcher-side changes (environment, proxy spelling, runtime directories) are in the [shared launcher page](m365-launcher.md).

## Lessons from real runs

- 2026-10-02: MS.AAD.7.4 to 7.9 were not evaluated. Graph answered 403 to ScubaGear's PIM-for-groups and role-management-policy reads, and upstream marks a control whose cmdlet failed as `Error` (CreateReport.psm1:266-267). Cause: the four permissions the API catalog names were not requested. Fix: e5edc84 added them in all five places. `DebugLogs/ScubaGear-DebugLog-ErrorReport.md` names the failing calls.
- 2026-10-02: every finding title ended in "BOD 25-01 Requirement Automated Check Configurable". Cause: removing the badge tags ran their labels into the sentence. Fix: 95936ac cuts the block before cleaning; checked against all 34 controls of the live report.
- 2026-10-02: the sign-in stopped on `-ContextScope`. Fix: e4571df; the Dockerfile now fails the build when the single `Connect-MgGraph` call uses a parameter outside `AccessTokenParameterSet`.
- 2026-10-02, after the fixes: 16 normalized findings matched upstream's 11 Fail and 5 Warning by control ID; 3 controls were manual by design (N/A, Not-Implemented) and were disclosed.
- Sign-in, discovery and gateway lessons shared with Maester are on the [shared launcher page](m365-launcher.md#lessons-from-real-runs).

## Updating this engine

After [docs/engine-maintenance.md](../engine-maintenance.md) §4:

1. Move together: plan `source` and `build_recipe` (revision, archive URL and sha256, `source_date_epoch`), the lock, `CONTRACTS["scubagear"]` in `prepare_source.py`, the Dockerfile (`ADD --checksum`, version label, `2.0.0` check), the wrapper's `Provenance.engine_version` and `source_revision`, `engines/catalog.json`, `engines/upstreams.lock.json`.
2. Pin what upstream pins: `MaximumVersion` in `PowerShell/ScubaGear/RequiredVersions.ps1` (Graph auth, powershell-yaml) and `OPAVersion` in `ScubaConfigDefaults.json`.
3. Re-read the report shape: `Results[].Controls[]` keys (`Control ID`, `Requirement`, `Result`, `OriginalResult`, `Criticality`), the verdict and criticality vocabularies, the `ReportSummary` counters, the badge markup.
4. Keep what `managedM365Contracts` and `validateManagedM365Image` in `scripts/validate-engine-catalog.mjs` require: `$control.PSObject.Properties['Criticality']` (never `$control.Criticality`); `$severity = switch ($criticality.ToLowerInvariant()) {` with exactly the six reviewed values, then `default { 'unknown' }`; `SourceCriticality = $criticality`; `$result = switch -Regex ($verdict) {` with exactly `'^Pass$'` and `'^(Fail|Warning)$'`, then `default { $null }`; `if ($null -eq $result) { continue }`; `passes`, `failures` and `warnings` as `[int]`; `normalized_results = $normalized.Count`; `-ProductNames @('aad')`, `-M365Environment 'commercial'`, `-SkipDoH $true`; `Connect-MgGraph -AccessToken $secureToken`, `Get-MgContext`, `Disconnect-MgGraph`; and none of `Invoke-WebRequest`, `Invoke-RestMethod`, `raw.githubusercontent.com`, `Resolve-DnsName`, `Test-NetConnection`, `MSGRAPH_ACCESS_TOKEN=`. A change to a verdict arm must also change `normalization_shortfall` in the adapter.
5. Rerun the permission check above and update all five places.
6. Bump the image tag, and Maester's ([publishing](m365-launcher.md#publishing)). `grep -rn "2.0.0-1" --exclude-dir=node_modules --exclude-dir=target --exclude-dir=.git --exclude-dir=.upstreams` finds the workflow matrix, the Dockerfile label, `plan.json`, `engines/catalog.json`, `scripts/validate-engine-catalog.mjs`, `scripts/release/verify-publication-artifact.mjs`, `tests/release/verifyPublicationArtifact.test.mjs`, `THIRD_PARTY.md`, `docs/engine-catalog.md` and this page.
7. After a live run, compare in the engine run's `attempt-<n>/output/` directory. An empty diff means every upstream Fail and Warning became exactly one finding:

   ```sh
   diff <(jq -r '(if type == "array" then .[0] else . end) | .Results[].Controls[]
     | select((if .Result == "Incorrect result" then .OriginalResult else .Result end) | test("^(Fail|Warning)$"))
     | ."Control ID"' upstream/M365BaselineConformance_*/IndividualReports/AADReport.json | sort) \
     <(jq -r '.Results[] | select(.Result == "Failed") | .PolicyId' scubagear.json | sort)
   ```

   Then compare `Diagnostics` in `scubagear.json` with `ReportSummary` in `AADReport.json`, and read `DebugLogs/` for 403 answers.
8. A wrapper change that alters normalized output for unchanged upstream output falls under the adapter-version rule in [docs/engine-maintenance.md](../engine-maintenance.md) §8.
