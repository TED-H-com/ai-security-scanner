# Cloud launcher

The shared, shell-free entrypoint `/usr/local/bin/ai-security-scanner-cloud-launcher` of the five cloud engine images: [Prowler](prowler.md), [ScoutSuite](scoutsuite.md), [Cloudsplaining](cloudsplaining.md), [Steampipe](steampipe.md) and [CloudQuery](cloudquery.md). It validates the mounted scope and credentials, verifies the provider identity, bridges provider traffic to the managed gateway, and runs one fixed upstream command.

| Item | Value |
| --- | --- |
| Source | `engines/images/cloud-launcher/`: `main.go`, `go.mod` (`go 1.25`, standard library only), `main_test.go`, `testdata/` (`scope-<engine>.json` per engine, `credentials-aws.json`) |
| Build | Compiled inside each engine Dockerfile with `CGO_ENABLED=0`, `-trimpath`, `-buildvcs=false`, `-ldflags='-s -w -buildid='`: `golang:1.25.0-alpine3.22` for Prowler, ScoutSuite, Cloudsplaining and CloudQuery, `golang:1.26.8-alpine` (stage `project-tools`) for Steampipe |
| Recorded as | `wrapper.launcher_sha256` in all five plans: the SHA-256 of `main.go`, checked by `validateCloudManagedImage` in `scripts/validate-engine-catalog.mjs`. `go.mod` is not recorded (`engines/image-input-hash-policy.json`). |
| Tests | Job `launcher-tests` in `.github/workflows/engine-images-cloud.yml`: `gofmt -d main.go main_test.go` must be empty and `go test ./...` must pass in `golang:1.25.0-alpine3.22`. No pull-request workflow runs it. |
| Invocation | `--engine <id> --scope /run/ai-security-scanner/scope.json --output /output` (catalog `command`) |

## What it enforces for every engine

In `run` order. Any failure prints `cloud engine launcher: <reason>` to stderr and exits 126, and the desktop fails the run without normalizing.

1. **Arguments.** Exactly the three flags, an engine from `supportedEngine`, the runtime-owned scope and output paths, and a real `/output` directory.
2. **Scope** (`loadScope`). At most 4 MiB, unknown fields and trailing data rejected, `schema_version` "1", the same `engine_id`, exactly one asset with provider `aws`, `azure` or `gcp`, at most 128 identifiers, 1 to 16 grants, no control characters.
3. **Credentials** (`loadCredentials`, read-only mount `/run/ai-security-scanner/credentials.json`). At most 256 KiB, `schema_version` "1.0.0", 1 to 3 entries, keys from `allowedCredentialKey`, printable ASCII values, source `ephemeral_scan_role` or `external_read_only_grant`, each expiring in more than 5 and at most 60 minutes, no duplicate keys. The exact key set selects the provider (`providerFromCredentialKeys`): the AWS session triple, `AZURE_ACCESS_TOKEN`, or `GOOGLE_OAUTH_ACCESS_TOKEN`.
4. **Provider and grants.** Only Prowler accepts Azure or GCP (`validateProviderForEngine`), and the asset's provider must match. `inventory_read` is always required, `configuration_read` for all but CloudQuery and Steampipe; a non-null `external_scope` or an expired grant is refused (`validateScopePermissions`).
5. **Target** (`expectedProviderTarget`). Kind and namespace `cloud_account`/`aws_account_id`, `subscription`/`azure_subscription_id` or `project`/`gcp_project_id`, exactly one such identifier, and a valid 12-digit account, lowercase UUID or GCP project id.
6. **Preflight**, after re-checking the earliest credential expiry, with a 20 s timeout and redirects refused:
   - AWS: SigV4-signed `GetCallerIdentity` at `sts.us-east-1.amazonaws.com`, or `sts.amazonaws.com` for Cloudsplaining (`awsSTSEndpointForEngine`); the account must equal the target.
   - Azure: ARM `GET /subscriptions/<id>` must return the same id and state `Enabled`.
   - GCP: `testIamPermissions` must grant `resourcemanager.projects.get` and `resourcemanager.projects.getIamPolicy` and none of `resourcemanager.projects.setIamPolicy`, `resourcemanager.projects.delete`, `iam.serviceAccounts.create` or `iam.serviceAccountKeys.create`; the project must be `ACTIVE`, and `getIamPolicy` must return a `bindings` array.
   - Then `CloseIdleConnections`, so the preflight connection does not hold a gateway slot.
7. **Private state.** A 0700 directory from `MkdirTemp("/tmp", "ai-security-scanner-cloud-")`, removed on exit; `HOME`, `USER=scanner` and `XDG_CACHE_HOME` point into it.
8. **Environment** (`childEnvironment`). Only `safeEnvironmentKeys` pass through (proxy variables, `LANG`, `LC_ALL`, `PATH`, CA variables). The credentials are set only in the engine's environment. AWS adds `AWS_EC2_METADATA_DISABLED=true`, region `us-east-1`, `AWS_MAX_ATTEMPTS=2`, `AWS_RETRY_MODE=standard`, regional STS, `AWS_SDK_LOAD_CONFIG=false` and the CloudQuery and Steampipe variables; GCP passes the token as `CLOUDSDK_AUTH_ACCESS_TOKEN` with `GOOGLE_CLOUD_PROJECT` and `GOOGLE_API_USE_MTLS_ENDPOINT=never`.
9. **Provider bridge** (below), then dispatch to the engine branch.

## Provider bridge

The desktop sets `ALL_PROXY`, `HTTP_PROXY`, `HTTPS_PROXY` (both cases) and `AI_SECURITY_SCANNER_PROXY` to `socks5h://<gateway-ip>:1080` and empties `NO_PROXY` (`src-tauri/src/container_runtime.rs`). When `AI_SECURITY_SCANNER_PROXY` is set, `bridgeProviderTraffic`:

- requires `socks5h`, an IP literal, port 1080 and no user, path or query (`managedGatewayAddress`);
- listens on a random `127.0.0.1` port and points only the six proxy variables at `http://127.0.0.1:<port>`;
- accepts only `CONNECT <dns-name>:443` (`providerHostname`: two or more labels, no IP literal). Other methods get 405, other targets 403, malformed requests 400; a gateway refusal returns 403 and other gateway failures 502;
- opens each tunnel as an unauthenticated SOCKS5 CONNECT by host name, so the gateway's allowlist still decides;
- keeps at most 8 tunnels and 20 new ones a second, under the gateway's 10 and 25 per second (`from_provider_service_plan` in `src-tauri/src/managed_network.rs`, which also ends a connection after 300 s); closes a tunnel 5 s after the provider's answer or 120 s while a request awaits one; allows 60 s for the handshake and 16 KiB of request header.

## Per-engine branches

| Engine | Provider | Grants | Function | What reaches `/output` |
| --- | --- | --- | --- | --- |
| Prowler | AWS, Azure, GCP | inventory, configuration | `prowlerInvocation`, `runProwler` | `prowler.ocsf.json`, written by Prowler and checked by `validateProwlerOutput` |
| ScoutSuite | AWS | inventory, configuration | `runScoutSuite` | `scoutsuite.json`: the `.js` result without its `scoutsuite_results =` prefix |
| Cloudsplaining | AWS, global STS | inventory, configuration | `runCloudsplaining` | `cloudsplaining.json`, copied from `/tmp` |
| Steampipe | AWS | inventory | `runSteampipe`, `prepareSteampipeInstall` | `steampipe.json`, Steampipe's stdout |
| CloudQuery | AWS | inventory | `runCloudQuery` | `<table>.json`, written by the file destination |

Helpers: `runCommand` (a non-zero exit is an error), `runCommandToFile` (exclusive create, at most 512 MiB, removed on failure), `copyBoundedRegularFile` (reads the whole result, at most 512 MiB, into memory and writes it with mode 0600), `readBoundedRegularFile` (regular files only, no links).

## Lessons from real runs

- 2026-09-05: removing Steampipe's `'high' as severity` literal from the launcher was deferred -> any change under `engines/images/cloud-launcher/` republishes all five images, which needs explicit authorization -> the adapter labelled the value as product-derived (df632f3); the query became pure inventory in 97093ae.
- 2026-10-02: a live AWS run failed on its first provider call -> the gateway speaks only SOCKS5; botocore in Prowler, ScoutSuite and Cloudsplaining read `socks5h://` as an HTTP proxy and CloudQuery's Go 1.19 build rejects the scheme -> the loopback CONNECT bridge, and the idle preflight connection is closed. Checked without credentials: STS answered `MissingAuthenticationToken` through each of the five images and an out-of-policy host was still refused (e4571df, published in 9f6a976, pinned in eba1c22).
- 2026-10-02: Cloudsplaining finished but the run failed -> `os.Rename` from the `/tmp` tmpfs to the `/output` mount fails across filesystems (EXDEV) -> `copyBoundedRegularFile` (a56f0fb).
- 2026-10-02: Steampipe failed -> its install was copied into `/output/.ai-security-scanner-steampipe-runtime` and outgrew the output budget -> install in `/tmp` with symlinks to the image's executables; `/tmp` stays noexec because the links resolve to the image filesystem (a56f0fb).
- 2026-10-02: both fixes changed the launcher, so all five tags moved: published from dfe8af1 (run 37044614517), pinned in bad4485.

## Publishing a changed image

Publishing to GHCR is the product owner's decision. A push to `main` that touches `engines/images/cloud-launcher/**` or `engines/images/<engine>/**` (except `plan.json`) starts `.github/workflows/engine-images-cloud.yml`; `affectedCloudEngines` in `scripts/engine-image-evidence.mjs` selects the changed engines, and all five for a launcher change or a manual dispatch.

1. **Bump the tag** in the same push as the change: `CLOUD_ENGINE_MATRIX` in the workflow and the Dockerfile `org.opencontainers.image.version` label (dfe8af1).
2. **Pin after the run**: catalog `image.tag` and `image.digest`; plan `final_artifact`, `publication` (run, source revision, platform digests, `evidence_artifact` `<engine>-image-evidence-<run>-<attempt>`) and the recorded hashes that changed (bad4485 took each digest from the run's evidence manifest). Until then the recorded inputs no longer match and the engine admission contract fails (dfe8af1 message).
3. **Know the guard.** If the tag already exists, `publicationPreflight` reads the plan at the source revision that published it. That plan and the current one must both bind the tag in `final_artifact`, and every recorded `sha256:` value outside `final_artifact` and `publication` must be equal; then the image is reused, not rebuilt. Otherwise the job fails. Two consequences:
   - The older publishing plans at dfe8af1 bind their preceding tags (bad4485). Those records cannot authorize reuse of changed inputs. The current Steampipe and Prowler publications have separately verified plans; their source commits and digests are listed in the [current batch record](updates/2026-10-14.md#verified-publication-and-catalog-activation).
   - Files not recorded in a plan (`go.mod`, `.md` files, dockerignores, Steampipe's `installprep/`, `passwd`, `group` and `POSTGRESQL-COPYRIGHT`, ScoutSuite's `prepare_source.py`, `scout_entry.py` and `requirements.in`, Prowler's `verify-patches.sh`) are invisible to the guard. Change them only with a new tag.
4. **For a launcher change**, also record the new `main.go` SHA-256 as `wrapper.launcher_sha256` in all five plans, keep `cloudQueryConfiguration()` byte-equal to `engines/images/cloudquery/plugins.yml` (`validateCloudQueryPlan`), and run the `launcher-tests` command before pushing.

## Tests

`main_test.go` covers, by name prefix: credential closure, lifetime and value rules (`TestProviderRequiresExactCredentialClosure`, `TestCredentialLifetime...`, `TestCredentialValues...`); scope and target binding (`TestScope...`, `TestProviderTargets...`, `TestReleasedScopeFixturesMatchLauncherContract`); preflights (`TestAWS...`, `TestAzure...`, `TestGCP...`); environment (`TestChildEnvironment...`, `TestGCPChildEnvironment...`); per-engine commands and outputs (`TestProwler...`, `TestSteampipe...`, `TestCloudQueryConfigurationIsExactLocalSourceClosure`, `TestEngineResultIsCopiedIntoTheOutputMount`, `TestRunCommandToFileBoundsAndCleansOutput`); and the bridge (`TestProviderBridge...`, `TestBridgeProviderTrafficPointsOnlyTheProxyVariablesAtTheBridge`). The bridge tests run against `fakeGateway`, a local SOCKS5 stand-in; the real path was checked against the pinned gateway image in e4571df.
