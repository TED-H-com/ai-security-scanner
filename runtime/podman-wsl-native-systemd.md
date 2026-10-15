# Windows Podman native systemd backport

WSL 2.9 and later changed distribution cgroup placement. Podman 5.8.2's nested
systemd startup can consequently leave rootless containers without delegated
memory controllers, making the product's bounded gateway and engine commands
fail while writing `memory.max`.

The Windows client is built from the same locked Podman 5.8.2 source revision,
with the native systemd lifecycle changes from
[upstream PR 29837](https://github.com/podman-container-tools/podman/pull/29837)
at `1795fb6ee0b45902926e95a89ddd8a47ef02c3f3` backported in
[`podman-wsl-native-systemd.patch`](podman-wsl-native-systemd.patch). That upstream
PR is still a draft. The backport enables native systemd in the private guest,
uses systemctl for state and shutdown, and restarts sshd when its port changes.
The guest also uses the systemd cgroup manager, as described in the
[upstream WSL cgroup issue](https://github.com/podman-container-tools/podman/issues/29749).
The Podman v6 module paths and new version-parsing helper from the draft are not
needed by the 5.8.2 backport; product prerequisite handling remains in place.

One additional hidden Windows WSL client keeps the exact distribution alive while
the managed machine is running: WSL does not count systemd services or an orphaned
guest process as a live Windows client. A guest-local nonblocking lock permits
only one keeper. Normal systemd poweroff followed by exact distribution
termination ends the guest command and its Windows client; no persisted host PID
or process-name termination is used. It installs no host service and does not
change global WSL idle policy.

`upstreams.lock.json` binds the source archive, local patch, Go toolchains,
offline vendored-dependency build flags, and final executable hash and size.
The build uses no downloaded Go modules. Windows builds and independent Linux
cross-builds must produce the exact same executable. Linux cross-building also
requires `git`, `tar`, and `unzip`.

The manifest identifies the component as `5.8.2+wsl-systemd.1` and includes the
source archive, patch, and complete build-input record. Podman's reported API
version remains 5.8.2. The machine OS image and upstream Windows helper binaries
retain their existing locked identities. The changed manifest selects a separate
private runtime generation through the existing ownership and collision rules.

This changes only product-managed runtime provisioning. Scanner detectors,
rootless execution, task resource limits, and the user's global WSL settings
keep their existing contracts. Formal publication still requires the normal
installed MSI and NSIS qualifications with the rebuilt desktop trust anchor.

## Verification

The source-built client was verified on Windows against the independent Linux
cross-build's executable hash in [diagnostic run 38819201843](https://github.com/TED-H-com/ai-security-scanner/actions/runs/38819201843).
Both installed MSI and NSIS CLI probes passed bounded container execution,
egress gateway readiness, 30 seconds of idle time, and a stop/start followed by
another 30 seconds of idle time. The MSI probe completed cleanup. The NSIS probe
removed its selected guest and provider home but failed the final empty-cache
check: the original installer had prepopulated its different, unpatched manifest
cache before the diagnostic override was selected. This probe does not qualify
the rebuilt installers or desktop. The normal Windows qualification now retains
the idle and restart checks and must pass against one rebuilt, anchored payload.
