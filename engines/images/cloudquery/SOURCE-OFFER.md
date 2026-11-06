# CloudQuery corresponding source and reproducible inputs

The managed image uses CLI 3.5.3 with the last complete, anonymously available
AWS source-plugin generation in CloudQuery's public monorepo. CLI 6.50.0 removed
protocol v1/v2 support; actual 6.49.2 execution also rejects the older AWS protocol and directs this plugin to CLI 3.0.1–3.5.3. It does not use
the newer authenticated CloudQuery plugin registry.

The complete corresponding source comes from the exact public release commits
in <https://github.com/cloudquery/cloudquery>. Copies of all three commit
archives are included in the image as:

```text
/usr/share/source/cloudquery/cli-086baf7.tar.gz
/usr/share/source/cloudquery/aws-804be3a.tar.gz
/usr/share/source/cloudquery/file-600ffdd.tar.gz
```

The source associations and archive SHA-256 values are:

- CLI `v3.5.3`: commit `086baf7f70ee3c1069513d41f321720a5e7d2bb9`,
  `ae47bd08e22aac0263784c1915c60d00111ef13145550c6d177af9fb24c7eeaf`;
- AWS source plugin `v9.2.0`: commit
  `804be3a90d6f15d3e6c662c0eb7afa88a9596180`,
  `a4788989f99ab02144605539ab552e86c076405ac7516fb673e73ba6bda40c6b`;
- file destination plugin `v1.0.4`: commit
  `600ffdd2707af566e3c99469d84a34d94730aaa1`,
  `700e2008b33a31a6e396d1e348464d2e832c856fdd9b4e45362f90b84bf92a5f`.

Together the archives contain the exact component source, their Go module
locks, and the upstream MPL-2.0 license.

The runtime binaries are the upstream public release artifacts for:

- CloudQuery CLI `v3.5.3`;
- CloudQuery AWS source plugin `v9.2.0`;
- CloudQuery file destination plugin `v1.0.4`.

Both Linux architectures are selected from exact SHA-256-locked artifacts in
the adjacent Dockerfile. `dependencies.lock.json`, the fixed local-plugin
configuration, the scanner-owned launcher source, and the Dockerfile are also
copied into `/usr/share/source/cloudquery/build/`.

The AWS plugin retains its 2023 knowledge date despite the CLI update. The application must
show that age and must not imply that it is the current commercial CloudQuery
AWS plugin. The file plugin emits one newline-delimited JSON file per selected
table under `/output`. Live AWS inventory remains attributable to the case's
short-lived read-only authorization and the exact table set emitted by the
launcher.
