# Kubescape offline policy notice

The managed image scans explicit local Kubernetes manifests only and embeds
three checksum-pinned assets from the Apache-2.0 Kubescape regolibrary `v2`
release assets updated on 2026-09-29, resolved to source commit
`f01135a697e6f710c1797bd7cd0d2ea42ec98f9f`:

- `nsa`: `sha256:80e23ca99be3e5bb0f80d968b32ae27b7dada39f9b12b9e3abffea8680ac7737`
- `default_config_inputs`: `sha256:6b78fae941db97d00780898da40581168303985e6dae0c74799f2c0a6ff5a8b6`
- `exceptions`: `sha256:d0b662af82db3fd6b2d8a242e1c7a46f47941ac7c298c2525481f817d928ddc3`

The fixed launcher verifies all three files before execution, explicitly opts
out of submission and host scanning, and supplies no network route.
