# httpx source record

This image is built from the upstream httpx source at commit
`4b6a9a9d476f94a4f3a630f37051f5671ecfb1f8` (release `v1.12.0`).

- Repository: <https://github.com/projectdiscovery/httpx>
- Source archive: <https://github.com/projectdiscovery/httpx/archive/4b6a9a9d476f94a4f3a630f37051f5671ecfb1f8.tar.gz>
- Source archive SHA-256: `f018fc96c4194aa008f1e305fcdc2bb8ecd5f08d7722ab012077cd3a9ec6a84d`
- `go.sum` SHA-256: `84a4350a4313776cd832d1d052ddcfb60d132af17ce43da8f3193a99212ddf0e`
- Reviewed managed-image source helper: `patch_live_dns.go`
- `runner/runner.go` before helper SHA-256: `649a47aac12f176000b3ea26fb62e1a395e30d6009fd2bee3fb5285b9943daa2`
- `runner/runner.go` after helper SHA-256: `712382a9145071c020ee4f75ac71218e8bb9687dbab5980a813a1e59a00b6cfe`
- Licenses: upstream httpx is MIT and the project launcher is Apache-2.0; the
  image carries both license texts below `/usr/share/licenses`.

The reviewed helper removes httpx's unconditional post-request DNS enrichment.
The actual request still uses the authorized hostname through the managed
remote-name SOCKS proxy, preserving HTTP Host and TLS SNI without giving the
scanner a second live DNS path. The image build checks the exact source hash
both before and after this single replacement.

The project-owned launcher source is in `engines/images/external-launcher`.
Build from the repository root with `docker build -f engines/images/httpx/Dockerfile .`.
