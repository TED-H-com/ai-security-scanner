# Complete corresponding source and notices

The managed Steampipe image contains the exact Steampipe v2.4.7 source archive at
`/usr/share/source/steampipe/steampipe-v2.4.7.tar.gz`. That archive corresponds to
commit `5c62651887b3e1d127049722e7216b915d4b075d` and the AGPL-3.0-only executable in
the image. The public ai-security-scanner repository supplies the exact Dockerfile,
scanner-owned launcher, install preparation program, build arguments, and workflow
needed to rebuild it.

The image also carries the exact AWS plugin v1.34.0 source archive (Apache-2.0), the
Steampipe FDW v2.2.7 source archive and license (Apache-2.0), and the PostgreSQL
14.19 copyright notice. OCI content is locked to these release digests:

- embedded PostgreSQL: `sha256:84264ef41853178707bccb091f5450c22e835f8a98f9961592c75690321093d9`
- Steampipe FDW: `sha256:28756ddfef21169f73e94129cabd51ef15ef81a266eaee8b302f5ec7cc1d8f4b`

No plugin registry, update service, or telemetry endpoint is contacted at runtime.
For the AGPL source-request path, open a public issue in
`https://github.com/TED-H-com/ai-security-scanner`; the in-image source remains the
immediate, version-matched offer.
