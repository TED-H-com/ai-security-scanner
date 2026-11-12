# Managed local runtime

Status: current runtime architecture

Product behavior: [Product specification](product-spec.md)

The managed runtime executes containerized scanners without turning runtime administration into a user task. Its component, process, directory, ownership, and deletion boundaries isolate disposable scan infrastructure from cases, evidence, reports, and unrelated system state.

## Product-facing runtime contract

`ai-security-scanner` can run containerized engines on a clean supported Windows workstation without asking the user to install Docker, Podman, QEMU, or a system service manually. The runtime is disposable product infrastructure, not the product workspace.

- The application shell, saved projects, existing reports, and readable unsigned exports remain available while the runtime is absent, preparing, repairing, or unavailable.
- Runtime preparation begins automatically behind the selected user task. First launch is never replaced by a runtime administration screen.
- WSL, Podman, VHD, provider, machine, gateway, manifest, digest, and ownership terms remain under **Technical details**. First-layer status uses language such as “Preparing scan tools” or “This network check could not start.”
- A runtime or gateway problem affects only tasks that require it. Independent tasks continue and the run produces a partial or no-checks-completed master report with exact coverage gaps.
- Docker and user-installed Podman are explicit compatibility providers. They are never silently mixed with a managed run, and their failure does not turn managed-runtime health into a global product gate.
- Integrity failure blocks execution of the exact unverified package or helper. It does not block projects, reports, unaffected admitted engines, or unsigned readable exports.

Cases, findings, evidence, exports, settings, signing identity, and user-selected source files live outside disposable runtime generations. Rebuilding, resetting, upgrading, or removing scan tools must not migrate or delete those objects.

## Windows installation and prerequisite preparation

The official Windows install flow owns prerequisite detection and preparation:

1. The signed installer resolves the trusted `%SystemRoot%\System32\wsl.exe` boundary and runs bounded prerequisite probes.
2. If WSL installation or update is required, the installer invokes only a fixed product-defined Microsoft WSL servicing action through normal UAC. Executable, arguments, working directory, environment, and elevation behavior are compiled installer inputs; no webview or case value can select them.
3. The installer records restart-required and durable resume state before it exits. It never restarts Windows without the operating system/user decision.
4. After restart or relaunch, the application opens the main shell and resumes creation of the private runtime automatically.

Servicing failure, cancellation, or timeout marks dependent tasks unavailable and offers **Retry**. The installed application, projects, reports, and independent tasks remain available.

The installer never exposes a generic elevation helper and the desktop never asks a beginner to open Terminal, type `wsl` commands, identify a distribution, or decide which runtime object is safe to remove.

## Runtime bundle and download integrity

- A managed-runtime distribution carries or references an immutable platform-specific bundle. Every bundled file has an exact size and SHA-256 in its manifest.
- The app verifies the bundle before copying or executing it. Managed commands use absolute verified executable paths, a cleared allowlisted environment, a fixed provider working directory, and no current-directory executable lookup.
- A missing or corrupt installed component is never executed. Bounded automatic Repair restores it from the signed installer payload or another already verified product cache, then reinitializes the manager or relaunches into the same project.
- When no verified repair source is available, the exact dependent tasks become `not_tested` or `failed` after bounded reconciliation. Unaffected capabilities continue.
- VM images and other large payloads download only from manifest-approved HTTPS origins. Resumable partial files remain private and are promoted atomically only after locked size and SHA-256 verification.
- Cancellation may retain a private partial download. Resume validates its length and range response; an invalid range restarts that download safely rather than trusting mismatched bytes.

Package admission and publication evidence do not become local scan readiness. An invalid update, engine, helper, or runtime payload is not applied or executed; the current trusted installation and unrelated admitted capabilities remain usable.

## Generations and ownership

Every newly created runtime has:

- a unique generation ID and unique OS registration/machine name;
- a private product data directory;
- a durable ownership record created before mutable runtime contents;
- the exact registration identity, canonical storage path, product generation ID, and admitted manifest identity;
- one durable lifecycle operation ID and reconciliation journal.

A name match, publisher string, registry entry, prior installation record, or provider directory by itself is never ownership proof. Exact ownership proof is required before the product modifies or deletes an existing runtime. It is not required before the product creates a different isolated generation.

One durable preparation operation owns one generation identity. Retry, app relaunch, and Windows restart reuse that safe in-progress identity. Polling and focus changes must not allocate new registrations. A new generation is allocated only after reconciliation determines that the prior one is unusable, or when ownership is ambiguous and the prior object must be preserved.

### Runtime decision table

| Observed state | Required action | Preservation and user outcome |
| --- | --- | --- |
| WSL ready; no product runtime | Create and start one unique generation | Unrelated WSL state is untouched; preparation stays in the background |
| WSL absent, disabled, or outdated | Use the fixed signed-installer servicing/resume path | No Terminal; main shell and saved work remain available |
| Unrelated WSL distributions exist | Ignore them and create the product generation | Registrations and storage remain byte-for-byte unchanged |
| Verified current generation is healthy | Reuse it | Scan starts without a Repair ceremony |
| Verified older generation is healthy | Create/verify the current generation side by side | Old generation remains until the new one works |
| Verified generation is partially corrupt | Perform bounded repair or create a replacement generation | User data remains outside it; old generation remains until replacement works |
| Name resembles the product but ownership is ambiguous | Do not adopt, edit, terminate, export, import, unregister, or delete it; choose a new unique name | Preserve the ambiguous registration/storage and continue automatically |
| Ghost app registration or missing binaries/manifest/ownership proof | Repair application registration and create a new generation | Registry/name is not promoted into runtime ownership; no manual cleanup |
| Creation was interrupted or Windows restarted | Reconcile the durable journal; resume safe steps or abandon the incomplete generation and replace it | No permanent Preparing state and no deletion authority inferred from interrupted intent |
| Verified generation cannot be removed now | Mark exact cleanup pending and use another isolated generation when possible | Never claim removal; scan continues where an independent runtime/task is available |
| No supported runtime can be created after bounded attempts | Mark only dependent tasks unavailable | Keep projects/reports/export usable and save an honest report |

There is no deterministic-name reclamation flow. There is no normal recovery transaction that exports, imports, quarantines, unregisters, or deletes a legacy or ambiguous WSL distribution. Optional advanced cleanup may act only on an exact verified product-owned generation and is never required to continue scanning.

The product never runs global `wsl --shutdown`, never edits an unrelated distribution, and never invokes `wsl --unregister` without exact deletion authority for the one resolved generation.

## Reconciliation, progress, and Repair

The durable journal and current operating-system inventory are authoritative. Frontend/runtime events are delivery hints.

- Startup begins an authoritative refresh within one second of backend/UI readiness. Focus, resume, and a watchdog trigger the same refresh.
- A refresh reconciles within ten seconds or visibly becomes Retry/offline with last-known real data. It never leaves an unbounded Ready, Repairing, Running, or Preparing projection.
- Every long-running, restartable, or side-effecting non-terminal operation records its operation ID, generation ID, stage, completed work/bytes, deadline, heartbeat/stale threshold, last milestone, cancellation boundary, and deterministic timeout outcome.
- Task-specific initialization, download, start, and cleanup bounds may exceed the ten-second status refresh, but their range and last durable heartbeat remain visible. No process wait is infinite.
- A missed event, app termination, sleep, restart, or transient probe failure is recovered from authoritative state. Repeating reconciliation is idempotent.
- Cancellation stops new work immediately. Target-contacting activity stops within the displayed task bound; non-contacting cleanup may continue without hiding saved results.
- After a deadline, the product retries only a safe step, deliberately reuses or replaces the durable generation, or marks the affected capability unavailable. It does not allocate a new generation on every attempt.

**Repair** means bounded automatic reconciliation. It verifies product-owned files, resumes or restarts downloads, repairs from an admitted payload, starts or replaces a verified disposable generation, and returns to the same project/task. Technical diagnostics are optional. Repair never redirects the beginner to WSL administration or a separate setup workflow.

## Upgrade, downgrade, reset, and retention

- Runtime upgrades are side by side. A new generation becomes active only after it starts and passes a functional scan-tool probe; the old active generation remains available until then.
- Application upgrade and same-version installer Repair replace verified application binaries/resources and repair product registration without deleting runtime or user data. Missing old executables or uninstallers do not require version-specific ghost recovery.
- Retry/restart reuses its durable generation. After replacement works, automatic cleanup may remove only obsolete generations with exact product ownership.
- Retain at most the active generation, one verified rollback generation, and a generation referenced by a durable unfinished checkpoint. Ambiguous objects are outside automatic retention/garbage-collection accounting and remain untouched.
- Downgrade never rewrites newer case data. It opens compatible data read-only, uses a compatible verified backup, or refuses only the incompatible downgrade operation while the prior supported installation/data remain usable.
- **Reset scan tools** removes and rebuilds only exactly verified disposable generations, images, helpers, and caches. Ambiguous objects and all user data remain untouched.
- Data-schema migrations are versioned, transactional, restart-safe, and backed up before a potentially destructive rewrite. Runtime replacement is not a data migration mechanism.

## Uninstall contract

The Windows uninstaller offers three explicit choices:

1. **Remove the app only (default).** Remove application binaries and registration. Preserve projects, findings, evidence, exports, settings, signing identity, and managed data for reinstall.
2. **Remove the app and scan tools; keep my projects.** Remove exactly verified runtime generations, images, helpers, and disposable caches. Preserve projects, findings, evidence, exports, preferences, and signing identity.
3. **Remove the app and all ai-security-scanner data.** After explicit data-loss confirmation and a backup/export option, remove cases/evidence and only exactly verified product-owned runtime/data paths.

Before any choice completes, dispatch stops and active target-contacting workloads are stopped within a bounded operation. A workload that cannot yet be stopped blocks only completion of that uninstall action and offers Retry; it does not justify deleting its controller or unrelated state. A stopped generation that cannot be removed is retained and reported accurately.

Ambiguous and unrelated objects are preserved under every choice. Cleanup never uses a broad recursive application-data parent, name-only matching, or a global WSL operation. The uninstaller records what it removed and retained and never claims that a surviving runtime was removed.

Reinstall after app-only removal reopens and exports the same project. Reinstall after scan-tool removal rebuilds a fresh generation and can scan, reopen, and export the preserved project. The all-data path proves exact removal rather than pretending deleted projects can be reopened.

## Execution isolation

Managed engines remain rootless and least-privileged:

- read-only immutable input snapshots and a separate bounded output directory;
- no-new-privileges and dropped capabilities unless one documented engine requires a narrower reviewed exception;
- no credentials by default and only task-scoped protected credentials for an explicitly connected source;
- exact task egress grants, rate/concurrency/time bounds, and revocation on cancel;
- recorded runtime, manifest, machine-image, engine-image, command-contract, scope, and adapter identities attached to evidence;
- typed rootless/seccomp security observations for the exact runtime invocation.

Failure to establish an isolation property blocks execution of that exact engine/task. It does not invalidate already saved evidence or disable unrelated tasks, reports, or projects. The master report identifies the task as failed or not tested and states the coverage gap.

The Windows-host loopback route is explicit: a task for `127.0.0.1:9001` means the Windows host service, not loopback inside the container or WSL guest. The gateway grants only the displayed target/port. Gateway failure affects only tasks that require that gateway.

### Output exhaustion protection

Every engine plan carries a bounded aggregate output budget (512 MiB by default unless a reviewed engine contract specifies a lower bounded value):

- one exact per-file `RLIMIT_FSIZE` where the provider supports it;
- disabled container runtime logs (`--log-driver=none`) where supported;
- one in-process aggregate budget across bounded stdout, stderr, and the recursive output tree;
- file-count, depth, symlink, and special-object limits.

A breach stops only the owned container/task, preserves already committed bounded evidence, and reports incomplete coverage. The recursive monitor is not represented as an operating-system filesystem quota; the per-file kernel limit remains the hard per-file bound.

## Private namespaces and platform details

### All platforms

- Durable provider state lives beneath the private managed-runtime root, partitioned by unique generation.
- Paths are canonicalized and opened without following links before sensitive creation or deletion.
- Creation pins and rechecks the immediate final product namespace. Reparse/replacement paths and foreign write authority on that final namespace are rejected.
- Benign or unusual ancestor policy that cannot replace the final namespace is diagnostic, not a product-wide block. A hard block requires a demonstrated path to mutating the exact protected namespace.
- Cleanup is descriptor-relative and exact. Unexpected, nonempty, linked, foreign-owned, or replaced objects are retained and reported instead of recursively removed.
- Commands use fixed operation labels and never echo arguments, target names, credentials, or unbounded output in errors.

### Windows

- The runtime resolves the Windows directory through the operating-system API and uses the absolute canonical `System32\wsl.exe` with a cleared minimal environment, fixed working directory, bounded output, and strict bounded UTF-8/UTF-16LE decoding.
- The product-managed data namespace uses protected current-user access. The exact WSL distribution-storage directory may grant the narrowly required LocalSystem access for WSL servicing; that grant does not spread to identities, cases, evidence, caches, or unrelated ancestors.
- Product-created SSH identities are generated with operating-system randomness, stored in the private generation namespace, never passed through a host shell, and reused only when exact key/ownership validation succeeds. Corrupt product-owned pre-initialization keys may be regenerated; ambiguous or active mismatches cause replacement of the generation rather than silent key rotation.
- A surviving WSL distribution or interrupted journal is never, by itself, deletion authority.

### Linux

- Rootless Podman uses a private provider home and immutable `containers.conf`/`storage.conf`. Durable graph/run state remains beneath that provider home.
- A short per-generation runtime directory may be used under canonical `/tmp` for socket limits. It must be a current-user, mode-`0700`, no-follow directory whose identity is stable for the generation.
- Cleanup accepts only exact known runtime socket/pid/log objects after ownership, type, link-count, mode, identity, and bounded process-liveness checks. Anything else is retained.
- The application-data snapshot mount appears at the required canonical path inside the managed VM. Engine containers use the desktop user's non-root uid/gid and an explicit keep-id mapping so private case artifacts need not be made broadly readable.

### macOS

- A short per-generation private home may be used under canonical `/tmp` to meet socket limits. It remains stable while the machine is active and contains only exact provider-created socket/host-key scaffolding.
- Cleanup follows the same no-follow, current-user, exact-object rules and retains unexpected or nonempty content.
- Durable identities, images, configuration, and evidence remain outside the short socket namespace in the private provider/data roots appropriate to their ownership class.

## Current provider payloads

| Host | Managed provider | Managed payload | Host prerequisite |
| --- | --- | --- | --- |
| Linux x86-64 | Rootless Podman machine + QEMU | Podman, gvproxy, static x86-64 QEMU emulator, `qemu-img`, `virtiofsd`, firmware | None; KVM when available, otherwise the bounded native launcher may use QEMU TCG |
| macOS Intel/Apple silicon | Rootless Podman machine + AppleHV | Universal Podman, vfkit, gvproxy | Supported macOS with Apple virtualization support |
| Windows x86-64 | Rootless Podman machine + WSL | Podman, gvproxy, win-sshproxy | WSL 2, detected/prepared by the signed installer flow |

Provider payload availability describes implementation capability only. It does not choose platform support, packaging, or release policy.

## CLI and developer interfaces

The standalone development CLI may expose bounded lifecycle diagnostics and operations such as status, install/start/stop/update, runtime checks, and exact uninstall. These are maintainer/developer interfaces, not steps in the beginner desktop journey.

- `status` reads and reconciles authoritative state; it does not mutate unrelated objects.
- `install`, `start`, `update`, and `Repair` use the same durable operation/generation rules as the desktop.
- `stop` refuses to interrupt target-contacting containers unless the exact bounded cancellation contract is invoked.
- `uninstall` resolves exact ownership and follows the same data-preservation choices; `--force` must never widen the resolved target or turn name matching into ownership.
- An unpackaged build may take an explicit absolute bundle override. This does not alter installed-product discovery or allow a case/webview value to choose an executable.
- Runtime `qualify` is a maintainer diagnostic that executes a fixed no-network fixture through the admitted container path. It proves only that runtime execution and cleanup path; it is not a meaningful scan or a beginner-path test.

## Runtime supply-chain boundary

When runtime payload preparation is in scope, its vendor step:

- reads `runtime/upstreams.lock.json`;
- accepts only approved HTTPS origins;
- verifies every source and binary by locked size and SHA-256;
- extracts or builds without invoking untrusted archive scripts;
- validates platform, architecture, and required helper capabilities;
- atomically stages the completed directory and manifest.

Manifest schema and management-contract revisions identify how bytes are interpreted. Source and binary identities change only through the lock file, with every affected URL, size, SHA-256, source revision, helper identity, and machine image updated together. These integrity controls govern only whether the exact payload may execute; they do not create product priorities or authorize packaging or publication work.

## Verification

Verify runtime changes in proportion to the risk changed. Relevant checks include:

- durable resume and bounded recovery after interruption;
- preservation of projects, evidence, settings, and unrelated runtime objects;
- refusal to execute corrupt or ambiguously owned bytes;
- exact cleanup ownership and retention of unexpected objects;
- task-scoped degradation when a runtime, gateway, or engine is unavailable;
- real execution of the affected engine path when runtime behavior changes.

Platform qualification installs the packaged runtime on a fresh runner and records the supported lifecycle, container execution, gateway, cleanup, and application-startup outcomes.
