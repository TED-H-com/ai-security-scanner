# Complete corresponding source and notices

The managed Steampipe image contains the exact Steampipe v2.4.9 source archive at
`/usr/share/source/steampipe/steampipe-v2.4.9.tar.gz`. That archive corresponds to
commit `4269e1dc4865647605da6af8f1828e77278106a0` and the AGPL-3.0-only executable in
the image. The public ai-security-scanner repository supplies the exact Dockerfile,
scanner-owned launcher, install preparation program, build arguments, and workflow
needed to rebuild it.

The image also carries the exact AWS plugin v1.34.1 source archive (Apache-2.0), the
Steampipe FDW v2.2.9 source archive and license (Apache-2.0), and the PostgreSQL
14.19 copyright notice. OCI content is locked to these release digests:

- embedded PostgreSQL: `sha256:84264ef41853178707bccb091f5450c22e835f8a98f9961592c75690321093d9`
- Steampipe FDW: `sha256:161e9b5e0696e66d77e94e2f9a0ee90d6e2a597b2069d1e488846e78a0b295f8`

No plugin registry, update service, or telemetry endpoint is contacted at runtime.
For the AGPL source-request path, open a public issue in
`https://github.com/TED-H-com/ai-security-scanner`; the in-image source remains the
immediate, version-matched offer.
