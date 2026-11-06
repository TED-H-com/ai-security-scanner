# Naabu source record

This image is built from the upstream Naabu source at commit
`041b70fd396e95b5ed2c19f879c18247078243bc` (release `v2.7.0`).

- Repository: <https://github.com/projectdiscovery/naabu>
- Source archive: <https://github.com/projectdiscovery/naabu/archive/041b70fd396e95b5ed2c19f879c18247078243bc.tar.gz>
- Source archive SHA-256: `d31032cbd2ddb35ed547469ed9d8382203180aa1854fdeb94d022fb1f2d332bf`
- `go.sum` SHA-256: `859119b672267d1274fc4de8b8752bdcf68becc1b714f83be622279b77ff638c`
- Licenses: upstream Naabu is MIT and the project launcher is Apache-2.0; the
  image carries both license texts below `/usr/share/licenses`.

The project-owned launcher source is in `engines/images/external-launcher`.
Build from the repository root with `docker build -f engines/images/naabu/Dockerfile .`.
