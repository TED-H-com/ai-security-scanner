# Prowler downstream source patches

These patches apply only to Prowler commit
`499fd637f3393b485833b08cdaf4172917c5698e` (5.44.0).

They are ai-security-scanner downstream hardening, not native upstream Prowler
capabilities. In particular, upstream at this pin does not provide Azure
`--access-token-auth`, and its GCP project selection lists every accessible
project before filtering requested IDs.

## Patch order and contracts

1. `0001-azure-static-access-token-iam-only.patch`

   - Adds a token-only mode whose sole secret input is `AZURE_ACCESS_TOKEN`.
   - Requires launcher-provided `--access-token-expires-at <UNIX_SECONDS>`.
     The parser, provider, credential constructor, and each token request fail
     closed if expiry is malformed, expired, or more than 3600 seconds away.
   - Uses a non-refreshing `TokenCredential` restricted to the selected Azure
     cloud's single ARM scope. It never instantiates CLI, managed identity,
     service-principal environment, browser, or other default credentials.
   - Skips Microsoft Graph identity discovery.
   - Requires canonical, duplicate-free `--subscription-ids` and exactly
     `--service iam`; subscription resolution uses only individual ARM gets.

2. `0002-gcp-exact-project-lookups.patch`

   - When `project_ids` is non-empty and no organization is selected, resolves
     every requested ID with only
     `projects().get(projectId=<exact>)`.
   - Never lists projects or fabricates requested projects from an ambient
     credential/default project.
   - Treats a missing, unreadable, malformed, mismatched, or non-`ACTIVE`
     requested project as an all-or-nothing failure.

3. `0003-gcp-disable-ambient-organization-search.patch`

   - Permanently skips `organizations().search()` while constructing the
     Cloud Resource Manager client.
   - Removes the service-level organization search from the exact-project call
     graph used by the downstream GCP check allowlist:
     `iam_audit_logs_enabled`,
     `iam_no_service_roles_at_project_level`,
     `iam_role_kms_enforce_separation_of_duties`, and
     `iam_role_sa_enforce_separation_of_duties`.
   - This is intentionally incompatible with broader upstream scans whose
     services consume discovered organizations; it is safe only under the
     downstream image's narrow four-check contract.

4. `0004-gcp-disable-provider-organization-lookup.patch`

   - Skips provider-level parent organization enrichment whenever exact
     `project_ids` are present.
   - Prevents `organizations().get()` from expanding a project-scoped run into
     organization metadata while preserving legacy enrichment for ambient
     upstream discovery profiles that do not provide project IDs.

5. `0005-azure-disable-tenant-enumeration.patch`

   - Uses the pinned Resource Manager 2022-12-01 subscription client for the
     downstream static-token profile, so each exact subscription `get` returns
     its attributable tenant ID without adding another endpoint.
   - Validates each returned tenant ID as a canonical UUID, deduplicates it, and
     fails closed if the exact response omits or malforms it.
   - Skips `tenants.list()` while other upstream authentication modes retain
     their existing tenant discovery behavior.
   - Keeps credential printing and Azure Finding/OCSF conversion safe for legacy
     empty-tenant objects without fabricating an organization identifier.

`series` is the authoritative application order. Do not silently rebase these
patches to another Prowler revision; regenerate and re-run the security tests.

## Verification

From this repository:

```console
engines/images/prowler/patches/verify-patches.sh /path/to/prowler
```

The verifier creates an isolated detached worktree at the exact pin, runs
`git apply --check` before each patch, applies them in series, restricts their
changed-file set, runs `git diff --check`, and byte-compiles all touched Python
sources and tests.

To run the upstream targeted tests too, pass a Python executable whose
environment contains Prowler's pinned development dependencies:

```console
PYTHON=/path/to/prowler-venv/bin/python \
  engines/images/prowler/patches/verify-patches.sh /path/to/prowler --pytest
```

The patches add the security regression suites
`tests/providers/azure/azure_access_token_auth_test.py` and
`tests/providers/gcp/gcp_exact_projects_test.py` to the patched tree. The third
patch extends the existing Cloud Resource Manager service test to prove that
organization search is never reached. The fourth and fifth patches extend those
regressions to cover provider-level organization lookup and Azure tenant
enumeration.
