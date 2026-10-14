# Release operations

[Documentation](README.md)

The product owner selects the version, channel, source commit, supported installer set, and publication time. Release automation builds, qualifies, freezes, verifies, attests, and publishes that exact decision.

## Current release

[v0.5.1](https://github.com/TED-H-com/ai-security-scanner/releases/tag/v0.5.1) is the current **stable/latest** desktop release for **Linux, macOS and Windows**, published on 2026-10-12. It adds Japanese UI support. [Candidate 38280286730](https://github.com/teddashh/ai-security-scanner/actions/runs/38280286730) built exact source `0405fecbf3435d16da176fc5be2ab14fcb4c962f`; [promotion 38286089269](https://github.com/teddashh/ai-security-scanner/actions/runs/38286089269) published the frozen files without rebuilding through normal `release-publication` approval. All 49 public assets matched the frozen bytes; source provenance and updater signatures were verified. See the [delivery record](release/v0.5.1.md).

GitHub records `prerelease: false`; metadata records `releaseChannel: stable` and `stableTarget: 0.5.1`. macOS and Windows NSIS have updater targets; Debian and MSI do not. Windows installers are unsigned; macOS is not notarized. Windows lifecycle/data-preservation and exact-candidate beginner human-path observations remain absent; macOS managed-runtime execution was not observed on the qualification host. AppImage and RPM are not offered.

The previous stable [v0.5.0](release/v0.5.0.md) and earlier releases retain their original files and observations.

## Release identity

Every `latest.json` payload URL must use `https://github.com/teddashh/ai-security-scanner/releases/download/v<version>/<file>` for installs <= 0.5.1; GitHub redirects this legacy path to the current repository, and `teddashh/ai-security-scanner` must never be recreated.

Use one numeric SemVer across `package.json`, `package-lock.json`, `src-tauri/tauri.conf.json`, the Rust package, and release-owned runtime manifests. Each public version uses a new immutable `vX.Y.Z` tag.

`package.json` also records:

- `release.channel`: `prerelease` or `stable`;
- `release.target`: prereleases sort below the planned stable version; a stable release uses its own version as the target.

## Prepare main

Before candidate creation:

1. Finish the release notes and current documentation.
2. Run the repository validation, frontend, component, Rust, build, release-policy, and release-evidence suites required by the changed boundaries.
3. Commit the coordinated version and channel update.
4. Push the exact candidate commit to protected `main`.

## Build and qualify without publication

For an owner-requested QC build, **Release desktop installers** uses:

- `public_release_candidate: false`, which finalizes commit-bound QC artifacts and publishes nothing;
- the optional `windows_data_preservation` input only when the owner requests the supported N-1 Windows upgrade and ambiguous-runtime recovery fixtures. The v0.3.0 record lists those observations as absent.

The workflow defines four qualification lanes. A lane can finalize as `not-offered`; use the exact run's metadata, rather than the lane list, to determine its offered installers.

| Qualification | Fresh runner | Installed artifact |
| --- | --- | --- |
| Linux x86-64 | Ubuntu 24.04 | Debian package |
| macOS Universal | macOS 15 Intel | DMG application |
| Windows x86-64 | Windows Server 2025 | MSI |
| Windows x86-64 | Windows Server 2025 | NSIS installer |

Each lane records what it actually observed: installation, application and companion layout, desktop startup, supported managed-runtime operations, runtime/container evidence, and removal of test state. Its JSON qualification record binds those observations to the version, source commit and artifact digest. A passing installer check does not imply that runtime execution or Windows lifecycle checks were observed; the current macOS and Windows limitations are listed above.

The finalized QC set records offered artifacts and their qualification evidence, checksums, runtime manifests, notices, SBOMs and limitations. The workflow summary identifies the run, artifact and source commit. Finalization does not publish anything.

## Promote a public candidate

Publication is a separate product-owner decision. When the owner authorizes it, dispatch **Release desktop installers** from `main` with `public_release_candidate: true`. **Promote frozen desktop release candidate** then consumes five values from that run's summary:

- candidate run ID;
- candidate run attempt;
- candidate artifact ID;
- candidate artifact SHA-256;
- exact source commit.

Supply the four external-evidence values together when an accepted Windows external-evidence bundle belongs to the release. Leave all four empty when the release does not use that bundle.

The promotion workflow revalidates the candidate lock and checksums, assembles the public files without rebuilding, creates build-provenance attestations, and waits for approval in the `release-publication` environment. Approval publishes the exact files under the immutable version tag. A stable channel becomes the latest release; a prerelease channel is marked as prerelease.

## Verify publication

Confirm the GitHub Release contains the intended installers, `SHA256SUMS.txt`, release index, runtime manifests, SBOMs, notices, release notes, and platform qualification records. Match the published tag and source commit to the frozen candidate summary.

Installed-product acceptance continues with the published installer and the beginner path in [Getting started](getting-started.md).
