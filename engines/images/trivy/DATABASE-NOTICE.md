# Trivy package-vulnerability database notice

The managed image embeds Trivy DB schema 2 from the immutable OCI manifest
`ghcr.io/aquasecurity/trivy-db@sha256:fb417a88061be7d8c246c61cd56e73c91040574fb8cb7b74c48f7a2ea5c2f92f`.
Its database layer is
`sha256:c367ecccf6a0367b915ef00b90c43e5958f9ecd9ee6118d2876af6deeca8523c`
and reports `UpdatedAt` `2026-11-06T01:07:43.832840315Z`.

The image also embeds Trivy Java DB schema 1 from the immutable OCI manifest
`ghcr.io/aquasecurity/trivy-java-db@sha256:a48270d8181f59baed801e34d73e0857558570c51c9a582eaa3999e897c210e4`.
Its `application/vnd.aquasec.trivy.javadb.layer.v1.tar+gzip` layer is
`sha256:c6a199cdfd2022f0e4792f9de59b63228d63b904df5858afb1873214427d2a44`,
contains only `trivy-java.db` and `metadata.json`, and reports `UpdatedAt`
`2026-11-06T01:10:43.741478979Z`. This separate index lets upstream Trivy
resolve otherwise unidentified JAR contents; vulnerability matching still uses
the standard database above.

The project-owned launcher fixes every managed Trivy invocation to `--scanners
vuln`. Repository and IaC snapshots receive two non-overlapping upstream
profiles: Trivy `filesystem` with `--pkg-types library` for lockfiles, followed
by Trivy `rootfs` with `--pkg-types library` for individual package archives and
binaries such as JARs. Single-image OCI layout snapshots receive only
`--pkg-types os`. All profiles use an in-memory scan cache and disable
standard-database, Java-database, VEX-repository, version, and telemetry update
paths. Consequently, OCI image runs remain deliberately limited to recognized
OS packages. This image does not perform IaC misconfiguration checks. The
complementary managed Grype container profile retains offline OCI-image
language-package and JAR-archive coverage.

Trivy, trivy-db, and trivy-java-db are Apache-2.0. The vulnerability database
aggregates upstream security advisories; attribution and use conditions remain
those of the named advisory providers represented in the database. The scanner
records immutable database provenance and never updates either database in
place.
