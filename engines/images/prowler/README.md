# Managed Prowler image

This image rebases Prowler 5.47.0 on its pinned upstream OCI index. The six
downstream patches restrict Azure and GCP authentication and discovery to the
approved asset; they do not replace upstream checks.

The plan records both sequential patch transitions and the final runtime files.
Publication verifies the final `downstream_runtime_patches.runtime_files`
`post_sha256` values against the anonymous image. Comparing those patched files
to upstream `pre_sha256` values rejects a correctly built image.

The 2026-11-06 review reapplied the complete patch series in an isolated source
checkout and confirmed that all six runtime files match the built image. The
workflow regression test also binds its expected hashes to that final audit.
