# Grype vulnerability database notice

The managed image embeds Anchore Grype DB schema `v6.1.10`, built
`2026-11-05T06:21:06Z`, from the checksum-pinned archive
`vulnerability-db_v6.1.10_2026-11-05T00:20:34Z_1793859666.tar.zst`.
The archive digest is
`sha256:9fbc8d8f2428cd715ffc9591cce16c4179955a7f45c76c12fbcb9cea8dc93813`
and the extracted SQLite database digest is
`sha256:420d0ac2f976acb4bf46e19bd1779f3043a868a77ca8e9debf18c3d196728344`.
The required Grype import metadata records the independently calculated
`xxh64:55547c385ac8e8bb` database digest, client schema `v6.1.10`, and fixed
archive URL; its SHA-256 is
`sha256:f60e1959e09bfba496ab6d18d4b17ef28dd88a9a6c8e82ace3c30a2b7f6673ea`.

Grype is Apache-2.0. The database aggregates upstream advisory providers whose
attribution and use conditions remain applicable. The scanner records the
exact database digest and build time with every run and never updates it in
place.
