# Semgrep source and upstream rule records

This image compiles Semgrep CE from the LGPL-2.1-or-later source at
`72d3525fe7e02f486428386078f192f8c4756804`. It verifies the one retained legacy-rule archive in
`semgrep-submodules.lock` and attaches the engine plus its upstream-vendored compiler/parser
sources before compilation. The rules gitlink is deliberately overridden:
only the selected original legacy rule files, README and license are attached.
The full rule archive is not included.

The runtime pack combines 1,493 upstream rules in 1,477 files from
`semgrep/semgrep-rules@0f5a85ceab1b82b193d0eaa418784c932d237d68` with the four
original Apache-2.0 product rules. The upstream rules retain LGPL 2.1 plus
Commons Clause; adding product rules does not remove those restrictions.
Security/secrets selection excludes tests, non-security metadata, unavailable
Apex rules, and the explicitly proprietary
`java/lang/security/audit/xss/no-direct-response-writer.yaml` from runtime AND
the attached originals. Unexpected per-file licenses fail the builder.

Only upstream IDs are qualified with their file path to avoid collisions; a
dated comment marks each changed file. Patterns, metadata, severity, messages
and fixes are unchanged. `RULE-PROVENANCE.json` maps the 1,497 unique runtime
IDs to their original IDs, paths and hashes. Original bytes, both licenses,
pack manifest, selection metadata and rebuild inputs are in the attachment's
`ai-security-scanner-build/` directory. The source tree's rules directory holds
only the 1,477 selected original files, not a complete rules checkout.

To rebuild the engine from attached source, use the pinned build prerequisites
in the attached Dockerfile, then `make opam-init OPAM_INIT_FLAGS=--disable-sandboxing`,
`make switch`, and `make install-deps` with `OPAMJOBS=4`. Compile the same upstream
targets with `DUNE_JOBS=4 SEMGREP_GIT_COMMIT=72d3525fe7e02f486428386078f192f8c4756804 opam exec --
make core`. Install the core and frozen Python CLI as
shown in the Dockerfile. Build prerequisites still require network access.

No Semgrep Pro component, registry download, token-driven installer, rule
update, or result upload is used. Runtime scans use the local pack with the OSS
engine, version checks and metrics disabled, and no autofix action.
