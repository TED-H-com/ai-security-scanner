# Trivy package-vulnerability database notice

The managed image embeds Trivy DB schema 2 from the immutable OCI manifest
`ghcr.io/aquasecurity/trivy-db@sha256:52132f8ca6e26a5ebbc4d758a9b2f20c9537725635f185f9c19b0600f45fe3c1`.
Its database layer is
`sha256:330b31ecc8312e6f0a8eec86c328234acf84c43954846139522fb36df85b5ea6`
and reports `UpdatedAt` `2026-10-15T01:13:01.189995254Z`.

The image also embeds Trivy Java DB schema 1 from the immutable OCI manifest
`ghcr.io/aquasecurity/trivy-java-db@sha256:e578af6b1e7db314ec2d3714ba522af8e9cd59c1a4349b7d6f54d86b2b8125b0`.
Its `application/vnd.aquasec.trivy.javadb.layer.v1.tar+gzip` layer is
`sha256:33244241111425d2f4ae10daf1de961edd47673265862d7abac688a60948301c`,
contains only `trivy-java.db` and `metadata.json`, and reports `UpdatedAt`
`2026-10-15T00:58:48.745137381Z`. This separate index lets upstream Trivy
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
