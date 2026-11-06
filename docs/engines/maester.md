# Maester

Runs Maester's Microsoft Entra ID tests against one approved Microsoft 365 tenant (asset kind `tenant`, provider `microsoft365`). The fixed profile `entra-graph-token` runs the pinned `tests/Maester/Entra` tree with one short-lived Graph token and `graph.microsoft.com:443` as its only destination. It skips upstream's long-running and preview tests and seven tests that need other hosts.

| Item | Value |
| --- | --- |
| Upstream | [maester365/maester](https://github.com/maester365/maester), version `2.3.0`, revision `7413c42d3fcc724dfea94d2726e690ddd364d914`. Rules/data identities are pinned in `engines/catalog.json`. |
| Image | `ghcr.io/ted-h-com/ai-security-scanner-engine-maester:2.3.0-1`, published for linux/amd64 and linux/arm64 by [run 42186918838](https://github.com/TED-H-com/ai-security-scanner/actions/runs/42186918838) from `5ba7d2e20f6eb8913aeb3097bed43860451ee522`. Exact digests and verified attestations are in [the publication record](updates/2026-11-06-publications.json). |
| Build inputs | `engines/images/maester/`: `Dockerfile`, `Dockerfile.dockerignore`, `dependencies.lock.json`, `THIRD-PARTY-NOTICES.md`, `run-maester.Tests.ps1`; `engines/images/m365-launcher/`: `main.go`, `go.mod`, `prepare_source.py`; the pinned source archive (`powershell/`, `tests/Maester/Entra`, `tests/maester-config.json`, `LICENSE`), exact upstream release-stamping/module-build helpers, official PowerShell 7.6.9 archives, Microsoft.Graph.Authentication 2.27.0, Pester 5.7.1, digest-pinned base images |
| Launcher | `/usr/local/bin/ai-security-scanner-m365-launcher` ([shared launcher](m365-launcher.md)) |
| Wrapper | `engines/images/maester/run-maester.ps1`, specified by `run-maester.Tests.ps1`; both installed under `/opt/ai-security-scanner/` |
| Adapter | `extract_maester` → `extract_m365` in `src-tauri/src/adapters/mod.rs` |
| Publish workflow | `.github/workflows/engine-images-m365.yml`, matrix entry `maester` |

## Local build and update entry

Build from the repository root with [this Dockerfile](../../engines/images/maester/Dockerfile) and context `.`.

No host `.engine-cache` preparation is required by this Dockerfile. Acquisition and any source preparation happen in the build; this does not imply the build is offline.

See the [image build index](image-build-index.md) for the repeatable local build command, shared launcher impact and update record. The sections below retain this engine’s specific patches, output fields, tests and incident history.

## How it is wired

- **Launch, token, environment.** As for ScubaGear, through the [shared launcher](m365-launcher.md): `--engine maester`, one `MSGRAPH_ACCESS_TOKEN` used by the host for at most one hour and refused by the launcher when expired or more than 65 minutes ahead, the gateway handed to .NET as `socks5://<gateway-ip>:1080`, HOME and XDG directories under `/tmp`.
- **Sign-in.** One tenant GUID from the scope, the token read into a SecureString, `Connect-MgGraph -AccessToken $secureToken -NoWelcome` with Graph auth 2.27.0, a `Get-MgContext` tenant match, and `Disconnect-MgGraph` in `finally`. `Invoke-ManagedMaesterRun` starts only when the script is not dot-sourced, so the specification can load its functions.
- **Invocation.** `Invoke-Maester -Path '/opt/ai-security-scanner/maester-tests/Maester/Entra' -ExcludeTag @('MT.1025','MT.1026','MT.1027','MT.1028','MT.1030','MT.1031','MT.1182') -OutputJsonFile /output/upstream/maester-raw.json -NonInteractive -NoLogo -DisableTelemetry -SkipVersionCheck -Verbosity 'None' -ErrorAction Stop`. Without `-Tag`, `-IncludeLongRunning` or `-IncludePreview`, upstream adds `LongRunning` and `Preview` to the exclusions itself (`Invoke-Maester.ps1:376-386`).
- **Configuration.** `maester-config.json` sits two levels above the test path, where `Get-MtMaesterConfig` finds it by walking up (`Invoke-Maester.ps1:480`). A severity set there overrides the test's own (`ConvertTo-MtMaesterResult.ps1:331-334`).
- **Upstream output.** Only `/output/upstream/maester-raw.json`, built by `ConvertTo-MtMaesterResult`. `Read-MaesterReport` requires it to be not a link, at most 16 MiB, and to end with `EndOfJson: 'EndOfJson'`.
- **Wrapper normalization.** For each entry in `Tests`: `Passed` becomes `Pass`, `Failed` stays `Failed`, `Investigate` stays `Investigate` with `ReviewDetail` taken from `ResultDetail.TestResult`; `Error`, `Skipped` and `NotRun` are dropped and left to the counters. Rows carry `Id`, `Title`, `Result`, `SourceResult`, `ReviewDetail`, `SourceSeverity`, `Severity`, `Service` (`Microsoft Entra ID`), `asset_id` and `HelpUrl`.
- **Severity.** `critical`, `high`, `medium` and `low` are kept, `info` becomes `informational`, anything else (including an empty value) is `unknown`. The original stays in `SourceSeverity`.
- **Wrapper document.** `/output/maester.json`, written atomically and never overwritten: `Engine: Maester`, `Provenance` (version, revision, profile, test path, excluded tags, `raw_report`) and `Diagnostics` copied from upstream's counts: `passes`, `failures`, `investigate`, `errors`, `skipped`, `not_run`, `total` (`TotalCount`), plus `normalized_results`.
- **Adapter.** Reads `maester.json` only, never `upstream/`. Each `Failed` row becomes one finding: rule id `Id`, title `Title`, severity `Severity`, resource `Service`, reference `HelpUrl`, tag `source-rating:<severity>`. Each `Investigate` row becomes a manual-review control (rule id, title, `ReviewDetail`) instead of a finding. `Pass` rows produce nothing.
- **Partial** (findings kept, engine run partially completed): `errors` above 0, `total` above the sum of the six categories ("not accounted for by any reported category"), `normalized_results` below `passes + failures + investigate`, a count or `Engine` mismatch, or a malformed row. `skipped` and `not_run` are disclosed without withholding completion.
- **Failed** (nothing adapted): any nonzero exit, including a launcher refusal (126), a tenant mismatch, an incomplete or oversized raw report, an existing `/output/upstream`, or an `Invoke-Maester` error.

## Permissions

- Maester's own list is `$scopes` in `powershell/public/Get-MtGraphScope.ps1`: 25 scopes at 6bf1d98. The product's 17-permission set includes 5 of them: `AuditLog.Read.All`, `Directory.Read.All`, `IdentityRiskEvent.Read.All`, `Policy.Read.All`, `Reports.Read.All`. The five places that hold the set are listed on the [ScubaGear page](scubagear.md#permissions).
- `Test-MtContext` (`powershell/internal/Test-MtContext.ps1`, called at `Invoke-Maester.ps1:343`) throws on missing scopes only for a `Delegated` context and otherwise warns "Continuing with missing permissions; expect failures." The 2026-10-02 run took the warning path for the 20 scopes the product does not request. Whether to request any of them is an open review item for the product owner, not a decision.
- Re-derive after an update, from the repository root. At 6bf1d98 it prints 20 names; bring any new one to the review item rather than adding it silently:

```sh
export LC_ALL=C
comm -23 \
  <(sed -n '/$scopes = @(/,/^    )/p' .upstreams/maester365/maester/powershell/public/Get-MtGraphScope.ps1 | grep -o "'[^']*'" | tr -d "'" | sort) \
  <(sed -n '/^fn microsoft365_required_permissions/,/^}/p' src-tauri/src/source_authorization/provider.rs | grep -o '"[^"]*"' | tr -d '"' | sort)
```

## Downstream changes

Upstream detection is unmodified. The module and the Entra tests are copied from the pinned archive as published; `prepare_source.py` changes only file modes and timestamps. Differences from running upstream as-is:

- **Graph-only test selection** (`run-maester.ps1`, plan `build_recipe.profile`, lock `test_profile`; 88343fa): MT.1025 to MT.1028, MT.1030 and MT.1031 (`Test-PrivilegedAssignments.Tests.ps1`) fetch a mutable role-classification file from raw.githubusercontent.com through `Test-MtPrivPermanentDirectoryRole` and `Test-MtPimAlertsExists`; MT.1182 performs a DNS DMARC lookup through `Get-MailAuthenticationRecord`. Remove a tag when its test stays inside Graph at the pinned revision.
- **Token sign-in without `-ContextScope`** (`run-maester.ps1`; e4571df): Graph auth 2.27.0 rejects `-ContextScope` with `-AccessToken`. The specification's `Graph sign-in` block binds the call to `AccessTokenParameterSet`. Keep while the pinned module rejects the pair.
- **Severity vocabulary** (`run-maester.ps1`; 19a7832): only Maester's documented ratings map; `info` becomes `informational`. Remove the `info` arm if upstream renames it to `informational`.
- **Investigate is manual review** (`run-maester.ps1`, `extract_m365`; 63097f3): a test sets it (`Add-MtTestResultDetail -Investigate`) when a person must judge the result, so it is listed for review instead of being reported as a failure or dropped. Permanent.
- **No exit failure for unevaluated tests** (`run-maester.ps1`; 7048108): a nonzero exit discards every finding, so errors go to `Diagnostics`. Permanent.
- **Uncategorized tests withhold completion** (`normalization_shortfall`; 6ba55ba, host only): a `total` the six categories do not explain is disclosed. Permanent.
- Launcher-side changes are on the [shared launcher page](m365-launcher.md).

## Lessons from real runs

- 2026-10-02: Maester exited 1 before any test ran. Cause: HOME pointed into the fresh `/tmp` tmpfs and did not exist, so .NET reported an empty user profile and the Graph SDK fell back to a relative `.mg` context path under the read-only working directory. Fix: 95936ac, the launcher creates HOME and the XDG directories (mode 0700) before PowerShell starts.
- 2026-10-02: the sign-in stopped on `-ContextScope`. Fix: e4571df.
- 2026-10-02: Maester warned that 20 of its scopes were missing and continued; see Permissions.
- Sign-in, discovery and gateway lessons shared with ScubaGear are on the [shared launcher page](m365-launcher.md#lessons-from-real-runs).

## Updating this engine

After [docs/engine-maintenance.md](../engine-maintenance.md) §4:

1. Move together: plan `source` and `build_recipe`, the lock, `CONTRACTS["maester"]` in `prepare_source.py` (selections, modules, manifest version), the Dockerfile (`ADD --checksum`, version label, `2.3.0` check), the wrapper's `Provenance`, `engines/catalog.json`, `engines/upstreams.lock.json`. Pin Graph auth to the `RequiredModules` version in `powershell/Maester.psd1`.
2. The Dockerfile requires `Test-MtDomainsDmarcRecordMaturity.Tests.ps1` in the copied Entra tree; choose another sentinel if upstream moves it. Keep `tests/maester-config.json` where `Get-MtMaesterConfig` finds it.
3. Re-trace calls that leave Graph: in the upstream checkout run `grep -rlE 'Invoke-WebRequest|Invoke-RestMethod|Resolve-Dns|raw\.githubusercontent|HttpClient' powershell --include=*.ps1`, then follow each function's callers into `tests/Maester/Entra`. Every Entra test that reaches one needs an excluded tag; `-SkipVersionCheck` and `-DisableTelemetry` cover the version and telemetry helpers. Change the list in `run-maester.ps1` (`-ExcludeTag` and `excluded_tags`), plan `exclude_tags`, lock `test_profile.exclude_tags` and `exclusions` in `scripts/validate-engine-catalog.mjs`.
4. Re-read `powershell/internal/ConvertTo-MtMaesterResult.ps1`: the verdict vocabulary, the `*Count` recount (lines 377-393), `Severity`, `ResultDetail.TestResult`, `HelpUrl` and `EndOfJson`. Update the specification's fixtures to match.
5. Keep what `scripts/validate-engine-catalog.mjs` requires: `$test.PSObject.Properties['Severity']` (never `$test.Severity`); `$severity = switch ($sourceSeverity.ToLowerInvariant()) {` with exactly `critical`, `high`, `medium`, `low`, `info`, then `default { 'unknown' }`; `SourceSeverity = $sourceSeverity`; `$result = switch ($sourceResult) {` with exactly `Passed`, `Failed`, `Investigate`, then `default { $null }`; `if ($null -eq $result) { continue }`; `passes`, `failures` and `investigate` as `[int]`; `normalized_results = $normalized.Count`; each excluded tag quoted; and the sign-in and forbidden-string rules listed on the [ScubaGear page](scubagear.md#updating-this-engine).
6. The specification runs during the image build as the image user. The build fails unless no test fails, skips or does not run and at least 40 pass. Replay it against a published image with `docker run --rm --entrypoint pwsh <image>@<digest> -NoLogo -NoProfile -NonInteractive -Command <the Dockerfile's Pester command>`. The file ships in the image, but no plan records its hash (the `.Tests.ps1` rule in `engines/image-input-hash-policy.json`); a change to it still needs a new tag.
7. Rerun the scope comparison above.
8. Bump the image tag, and ScubaGear's ([publishing](m365-launcher.md#publishing)). `grep -rn "2.3.0-1" --exclude-dir=node_modules --exclude-dir=target --exclude-dir=.git --exclude-dir=.upstreams` finds the same nine places as for ScubaGear (with Maester's own Dockerfile and `plan.json`), plus this page.
9. After a live run, compare in the engine run's `attempt-<n>/output/` directory. The diff must be empty and the two sets of counts equal:

   ```sh
   diff <(jq -r '.Tests[] | select(.Result == "Failed" or .Result == "Investigate") | "\(.Id) \(.Result)"' upstream/maester-raw.json | sort) \
        <(jq -r '.Results[] | select(.Result != "Pass") | "\(.Id) \(.SourceResult)"' maester.json | sort)
   jq '{PassedCount, FailedCount, InvestigateCount, ErrorCount, SkippedCount, NotRunCount, TotalCount}' upstream/maester-raw.json
   jq '.Diagnostics' maester.json
   ```
