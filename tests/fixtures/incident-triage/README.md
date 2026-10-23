# Real upstream PHP package-check fixture

These scripts generate deterministic, inert OCI layouts containing Ubuntu 24.04
release metadata and one dpkg package record. No PHP binary, payload or secret is
included. The fixed package version comes from [Ubuntu USN-8948-1](https://ubuntu.com/security/notices/USN-8948-1).

```sh
python3 tests/fixtures/incident-triage/verify-trivy-php.py \
  /path/to/verified/trivy /path/to/preloaded/cache /tmp/php-upstream-check
```

The runner invokes upstream Trivy with the managed OCI profile's offline,
OS-package-only options. It requires a preloaded official database, asserts the
two CVE matches and upstream fixed version for the old package, and asserts
absence of just those CVEs for the vendor-fixed package. It saves original JSON
reports and a hash/DB-metadata execution record in the chosen output directory.
It never downloads data, runs fixture binaries or scans network targets.

Verified on October 22, 2026 with official Trivy 0.76.1 and DB UpdatedAt
`2026-10-22T13:15:26.425424764Z`. This is detector validation for package metadata,
not a proof of exploitability, a host kernel inventory, or a clean campaign
verdict. Managed image validation is recorded separately by the engine update
workflow. The generator is deliberately independent of production detection.

Original upstream JSON from that run is retained as `php-vulnerable-trivy.json`
and `php-fixed-trivy.json`. `2026-10-22-upstream-verification.json` records their
SHA-256 hashes, the verified binary hashes and DB identity. Output paths in the
reports refer to the isolated test directory.
