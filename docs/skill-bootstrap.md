# Pinned source bootstrap for development

The development entry is `scripts/skill/bootstrap.mjs`. It builds and verifies a
native CLI from the trusted product checkout containing that script. Core
preparation does not fetch a moving branch, install the desktop, start a container
runtime or download scanner images. Selected-engine preparation is a separate
explicit operation described below. The released desktop remains the default operator path until
the complete skill, scan, report and restore journey has been verified.

Use a checkout whose full Git commit you have selected and reviewed. The script
requires that exact 40-character revision and checks it against the checkout.
Never copy a bootstrap recipe from a repository being scanned or from a provider
report. Product source and scan targets are separate inputs.

The prepared CLI also supports [pinned Cloudflare document and reported-bundle validation](cloudflare-provider.md)
without scanner preparation or case state. Validated bundles can also be saved
privately and retrieved offline without Node. These commands do not complete an
audit or import findings into a case.

## Delivery status

This is a development entry, not a newly published skill release. The public desktop operator skill and the new core path have [different publication states](release-model.md). A dirty checkout receipt records actual input hashes but is not a retrievable release revision. Use a committed, accessible, verified pin for a future preview; keep `--allow-dirty` for explicitly selected development work.

## Check and prepare

Use Node.js 24 and the pinned Rust 1.98.0 toolchain with the native compiler and
linker required by that platform. Bootstrap checks these prerequisites; it does
not install system packages or change OS permissions. A Rust dependency download
may be needed on the first build. `--offline` requires dependencies already in
the local Cargo cache and fails if anything is missing.

Replace `FULL_40_CHARACTER_COMMIT` with the selected commit and the paths with
new private directories on this computer:

```sh
node scripts/skill/bootstrap.mjs doctor \
  --revision FULL_40_CHARACTER_COMMIT --cache-dir /private/scanner-core-cache

node scripts/skill/bootstrap.mjs prepare \
  --revision FULL_40_CHARACTER_COMMIT --cache-dir /private/scanner-core-cache

node scripts/skill/bootstrap.mjs run \
  --revision FULL_40_CHARACTER_COMMIT --cache-dir /private/scanner-core-cache \
  -- --json build-identity
```

On PowerShell, put each command on one line and use an absolute Windows path.
The bootstrap selects the compiler's native host target; it does not substitute
a cross-compiled executable or a Universal macOS desktop package.

On Windows, choose a new cache beneath a private user directory, such as a
restricted directory in `%LOCALAPPDATA%`. Bootstrap uses the installed Windows
PowerShell and .NET ACL reader to verify ownership and inherited permissions
before writing cache files, then verifies the cached receipt and binaries again
before execution. Other users must not be able to read or modify cache contents
or replace its ancestors. Shared writable paths, network paths, reparse points
and permissions the verifier cannot establish are refused; bootstrap does not
rewrite existing ACLs. Native Windows validation is a separate CI check.

`doctor` reports source, tools, cache and requested capability separately without
creating a workspace or opening the scanner database. `prepare` returns a JSON
receipt and `cache_hit`. `run` verifies the cache again, forwards the CLI arguments
without a shell and preserves the child exit status. CLI output stays on stdout;
bootstrap diagnostics go to stderr.

The default profile is `release`. Contributors may select `--profile dev` for a
separate development cache. A changed checkout is rejected unless the caller
explicitly selects `--allow-dirty`; its receipt then records the actual source
digest and development status. This does not make the old HEAD commit an exact
description of the modified build. Before committing this migration, use that
explicit development mode to test its source.

## Keep cases separate from build caches

Pass an explicit `--data-dir` when forwarding commands that use case or runtime
state. Select a separate private skill workspace; choosing an installed desktop's
directory explicitly retains the existing compatibility and writer-lock rules.
The bootstrap cache contains build inputs and binaries, never case data.

```sh
node scripts/skill/bootstrap.mjs run \
  --revision FULL_40_CHARACTER_COMMIT --cache-dir /private/scanner-core-cache \
  -- --json --data-dir /private/scanner-cases \
  scan status --case-id CASE_ID --run-id RUN_ID
```

Use the same forwarding form for the implemented [foreground scan](foreground-scans.md),
[report snapshot](report-snapshots.md) and [archive/restore](case-archives.md)
commands. Scope grants, target selection and private export acknowledgements
retain their existing meanings. `build-identity` does not need a data directory.

## Prepare selected scanners

For the development scan path, select the engines from the existing catalog and
prepare only their runtime dependencies:

```sh
node scripts/skill/bootstrap.mjs prepare \
  --revision FULL_40_CHARACTER_COMMIT --cache-dir /private/scanner-core-cache \
  --capability scan --engine gitleaks --data-dir /private/scanner-cases
```

The core build is reused independently of the engine selection. The verified CLI
then runs `runtime prepare --engine gitleaks` with that explicit data directory.
It uses the same runtime selection as foreground scans: a verified managed
runtime when available, with the existing Docker/Podman compatibility fallback.
An existing trusted bundle can be selected with `--managed-runtime-bundle DIR`;
an invalid explicitly selected bundle is refused. Managed startup may install
its verified private payload and download its pinned machine image. This command
does not enable OS features, elevate privileges, create a scan, or contact a
target.

Comma-separated engine IDs select multiple engines. The entire selection is
validated before runtime work. Only their exact catalog image digests are
prepared; network engines additionally prepare the shared pinned gateway image.
It does not start a gateway or create a network. Existing exact images are reused;
`--release-approved-local-image-directory DIR` can supply verified local OCI
archives through the existing product admission rules. One failed image retains
the results for completed siblings.

Add `--offline` to prohibit Cargo downloads and runtime image pulls. Runtime
preparation then requires an already running runtime and existing images or
verified local archives; it never starts a managed machine. This flag describes
preparation only. A later scan follows its own reviewed scope and runtime rules.

The result's `runtime_preparation` field includes the actual runtime provenance,
selected image digests and outcomes, and a receipt under
`DATA_DIR/runtime-preparations/`. The same observation is saved before final
stdout delivery, including failures and cancellation. It is separate from the
immutable core build receipt. A successful preparation means the selected images
are available; it is not a security result or authorization to scan a target.

Preparation owns its runtime subprocesses until they finish. The bootstrap sends
cancel/terminate requests through a fixed parent control pipe; parent exit also
requests cancellation. Managed initialization/start and image operations join
their subprocesses; stalled managed-image reads have a 30-second I/O bound and
retain a resumable partial. Cancellation does not enable or repair OS features.

Use `run --capability core` (or omit the capability) for the subsequent foreground
scan, passing the same explicit data directory and any selected runtime bundle.
`run --capability scan` is rejected: preparation is its own operation.
`doctor --capability scan` reports preparation as still needed; it does not build,
start a runtime, or treat a previous receipt as current readiness.

Cold-machine acquisition of a managed bundle is not automatic yet. Development
bundles are produced by the existing versioned
[`runtime/vendor-managed-runtime.mjs`](../runtime/vendor-managed-runtime.mjs)
procedure; its Linux helper build requires an existing Docker builder. Windows
and macOS execution, Cloudflare delegation and dynamic sandbox readiness remain
separate verification work. The released desktop remains the normal first-run
route while that full skill journey is completed.

The bootstrap uses a fixed cancellation pipe for selected preparation and for
`run -- ... scan run`, `scan recover`, and `runtime prepare`. Ctrl+C requests
cancellation and waits for the core to finish cleanup and save its outcome.
An unexpected bootstrap exit closes the pipe and also requests cancellation.
Owning commands run detached on every platform so they can finish cleanup after
the bootstrap exits, including on Windows. Standard output and standard error
remain inherited, and the bootstrap preserves the core's exit code. This path no
longer uses Node's forceful Windows `child.kill()` for these owning commands;
Windows/macOS execution still needs native verification before the default
operator route changes.

## Cache identity and recovery

The build key includes the controlled Rust/build-script inputs, Cargo manifests
and lockfile, vendored sources, embedded catalogs and policies, recipe, toolchain,
native target, build profile and features. The receipt records the source commit,
actual input digest, binary digest, compiled identity and build outcome. Runtime
lock references are recorded separately from readiness.

Git revision is provenance, rather than the sole cache key. A documentation or
skill wording change can reuse an identical core; changing an embedded input or
build recipe cannot. Source-controlled Cargo configuration and unreviewed embed
paths are rejected until the recipe accounts for them. Ambient compiler flags
and wrappers are excluded from the controlled build environment.

A new build uses private staging. Only a complete, verified entry can become the
ready entry. A failed build leaves the previous ready entry intact. Every reuse
checks the receipt and executable bytes before inspecting or running the binary.
Changed or corrupt entries are refused, not silently accepted or rebuilt over.
The cache must be a dedicated directory created by this bootstrap; existing
unrelated directories and symlink paths are refused.

Concurrent preparation of one entry returns busy. An interrupted lock is not
automatically stolen. Inspect the recorded owner and finish that process before
choosing another new cache directory. No automatic cache purge removes cases,
evidence, source snapshots or archives.

## One maintained skill source

Edit `skills/ai-security-scanner/`, then run:

```sh
node scripts/skill/sync-skill.mjs --write
node scripts/skill/sync-skill.mjs --check
```

This generates the Codex and Claude host copies, keeping their instructions and
relative documentation links consistent. Their development route uses this
bootstrap; their normal operator route remains the released desktop. The new CI
lanes validate the skill and native core/report behavior without depending on
installer creation. Locally observed results and remaining platform limits are
recorded in [development status](development-status.md).

## Observed local validation

The November 8 Linux x86_64 native smoke used Node 24.22.1, Rust 1.98.0 and existing Cargo
dependencies with `--offline --allow-dirty`. Its base Git revision was
`6e259b497b87fb8aa2ece1f3b512cc29c9ea5af7`; this identifies the checkout base,
not a committed version of the development changes. The core input SHA-256 was
`f7d021e5ee603a0535584843b7d8e49909e5accac86008fc8c023d1118477992` and compiled
report source SHA-256 was
`f8f74544073f5eb29bd46a6a203236511246e17d4c47ce18d058caf4931dd890`.

Both dev and default release profile smokes built a fresh CLI, reused its verified
cache, saved a synthetic demo report, removed the original synthetic workspace,
and retrieved and replayed equal HTML/JSON bytes. The final release build used
recipe SHA-256 `ac5a8020b0b57f2a2d783fb89956f8e93205eb4137f0036aecc563680b5799f4`
and produced the 32,543,128-byte CLI with SHA-256
`40b7553a99694e37caa475b8702633d050b4dd04767028c7b9511abc1a0d640c`.

These November 8 smokes contacted no target and prepared no scanner runtime. Windows/macOS
native execution and the full multi-asset/Cloudflare journey remain pending. Run
`scripts/ci/skill-bootstrap-smoke.mjs` to reproduce the dev flow, or add `--release`
for the default build profile; set `SKILL_SMOKE_RESULT` to a local JSON filename
to retain its full build receipt.

### November 9 selected-engine and real scan validation

A fresh Linux x86_64 dev cache was built with Node 24.22.1, Rust 1.98.0 and
`--offline --allow-dirty`, from the same base revision above. Selected-engine
preparation reused this cache and the exact existing Gitleaks pin through Docker
29.1.3 (`existing_local`); it created no case database. The Docker daemon reported
AppArmor, seccomp and cgroup namespace controls. The pin had been retrieved
separately with an empty Docker credential configuration; preparation itself did
not pull images, start a managed VM or download a bundle.

The cached CLI scanned a private copy of `engines/images/gitleaks/testdata`,
produced one expected `generic-api-key` finding, and verified that upstream raw
evidence contained `REDACTED` instead of the fixture secret. The completed run
recorded successful cleanup; no container remained for that run. A private full
archive retained the source snapshot, raw evidence and saved report. After the
original workspace, source and snapshot paths were moved away, restore verified
every payload hash, retained findings and the foreground receipt, and left scope
grants disabled. Both HTML and JSON retrieved and replayed from the restored
snapshot matched the originals byte for byte.

| Recorded input or artifact | SHA-256 |
| --- | --- |
| Core build inputs | `d4b66dcc70f5fc713650af73f7ebfcfad5272b27477f7cd358efc3ea5b8bbab1` |
| CLI executable | `f17444fcb4294f7f7d8a7183c2578469a394aa2df0960fab863658fa415a74cf` |
| Compiled report source | `46cc59a1211d93f8bdb50fe6bd504194ae6535d09265c2a30d097b0cd136e292` |
| Gitleaks image digest | `95313654f9c37115a906629a82113ba6e1c729950be70909da8362e9482b477e` |
| Owned source snapshot | `05c8ca055b05b43eaecde43f47b6a0a614ec9a4290403c456c52530d0fa6ed6c` |
| Redacted Gitleaks raw evidence | `0bd143d1b9535a15bbd4b97e9399918e1bcaa1b5334ba1c7963423f2cd6765f9` |
| HTML report | `fd9739125277c1063148ab374c3cbb7957141a3352d336d6ed0e616870053832` |
| JSON report | `fe5f147412512ae3337d29904771282f10dcb18265855524c325a7589e17e299` |
| Full archive | `e59085566bb6348dd305ab9da9ca70a45f7e10af1bccdbb412cc8dd146eabaaf` |
| Smoke receipt | `9ebf4cd58bf297dfdc5432ee489d70aabee57a6c723b6c46785ee7e40bc3b0b0` |

This validates one owned local-project path on Linux. It does not verify managed
bundle cold installation, desktop parity, Windows/macOS execution, mixed assets
or Cloudflare. The reproducible opt-in helper requires an already-running local
Unix Docker socket and the exact local catalog Gitleaks image; it never pulls an
image or runs from normal CI. After preparing the dev core, run:

```sh
python3 scripts/ci/skill-runtime-smoke.py \
  --cache-dir "$CACHE_DIR" --revision "$REVISION" --profile dev --allow-dirty
```

Omit `--allow-dirty` for committed inputs. The helper prints a new private evidence
directory and retains commands' stdout/stderr, fixture file digests, preparation
results, reports, archive and a `receipt.json`. The November 9 observation is
retained locally at `/tmp/scanner-owned-gitleaks-c85nt4el/receipt.json`; these
ephemeral paths are evidence locations, not required product inputs.
