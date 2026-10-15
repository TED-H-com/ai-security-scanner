# Grype vulnerability database notice

The managed image embeds Anchore Grype DB schema `v6.1.10`, built
`2026-10-14T06:30:34Z`, from the checksum-pinned archive
`vulnerability-db_v6.1.10_2026-10-14T00:28:57Z_1791959434.tar.zst`.
The archive digest is
`sha256:30d8bcd3c09e03c9f734c522e104c1387e285e3f6e33da2ee7b55f521daadb3f`
and the extracted SQLite database digest is
`sha256:8be8779b1b6fd721e6127c092bd25d5875e25cd511def5d9e7d026fb45189058`.
The required Grype import metadata records the independently calculated
`xxh64:8f0947c104495800` database digest, client schema `v6.1.10`, and fixed
archive URL; its SHA-256 is
`sha256:34f988049676aadd83f95bfe9b42f82a2a4a75cfc7c17004e079234d8aad126c`.

Grype is Apache-2.0. The database aggregates upstream advisory providers whose
attribution and use conditions remain applicable. The scanner records the
exact database digest and build time with every run and never updates it in
place.
