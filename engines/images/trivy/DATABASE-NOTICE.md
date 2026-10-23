# Trivy package-vulnerability database notice

The managed image embeds Trivy DB schema 2 from the immutable OCI manifest
`ghcr.io/aquasecurity/trivy-db@sha256:4bf3ae89527fbbb3596748b1c9d294a8b240c49edc9f87e65947e42291bb0bf6`.
Its database layer is
`sha256:c6b2db527f049abfef0b2ea48e8ee38d7c5475c94612072b5eeca54c18fcb90b`
and reports `UpdatedAt` `2026-10-22T13:15:26.425424764Z`.

The image also embeds Trivy Java DB schema 1 from the immutable OCI manifest
`ghcr.io/aquasecurity/trivy-java-db@sha256:a805d22ec39082e3d0910a6c37ae4e85c666248293add991d2d2bf82237323a5`.
Its `application/vnd.aquasec.trivy.javadb.layer.v1.tar+gzip` layer is
`sha256:35c8f473bb7485db657c022eee43404fda3684fc3c0341aef3598db6016c28ca`,
contains only `trivy-java.db` and `metadata.json`, and reports `UpdatedAt`
`2026-10-22T01:08:13.998271001Z`. This separate index lets upstream Trivy
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
