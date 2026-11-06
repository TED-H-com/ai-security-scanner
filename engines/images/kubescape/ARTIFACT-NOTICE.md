# Kubescape offline policy notice

The managed image scans explicit local Kubernetes manifests only and embeds
three checksum-pinned assets from the Apache-2.0 Kubescape regolibrary `v2`
release assets updated on 2026-09-29, resolved to source commit
`3065a55568bcf3b5c3d0b19e3f3fec5b404abb4c`:

- `nsa`: `sha256:d5f079fb766304b264a5749499f1a3a466ab88bca7730dd72b48c3bd9a931432`
- `default_config_inputs`: `sha256:6e05e01793eecc8dad788ae3b0d83138ae9eddb6f5932c113ae1bd8ffc97b8c7`
- `exceptions`: `sha256:e7f1ad0e9dcae362c4b365ea1dde9f22d8663d9c9e4ca51c84a5f5c71618ec4b`

The fixed launcher verifies all three files before execution, explicitly opts
out of submission and host scanning, and supplies no network route.
