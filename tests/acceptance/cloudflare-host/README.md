# Cloudflare host instruction acceptance kit

This test tooling exists only to accept the development host instructions. It
creates synthetic owner decisions for the bundled original fixture; it is not a
product authorization shortcut or an audit. No model, network or target execution
is involved in setup. No third-party code or credentials are used.

Use an already built development CLI and Node 24. Choose a new output directory
whose parent exists, or an empty directory, outside the checkout. Resolve parent
links first (`realpath`), especially `/tmp` and `/var` on macOS. The product refuses
a data directory below an ancestor that other users can write (for example a
group-writable directory created under umask 002); a new private directory under
the system temporary directory works. Pass absolute paths:

```sh
node tests/acceptance/cloudflare-host/setup.mjs --cli "$CLI" --output "$OUTPUT" [--host-id ID]
```

`OUTPUT` must be canonical. Setup creates private `data/`, empty `run/`, copied
`source/` and process-local temporary/home storage inside it. It uses only public
CLI commands to create a case, attach the copied repository, approve local artifact
read as “synthetic acceptance operator”, prepare scope `.` with model-processing
acknowledgement, then read the exact source-view request's status. All writes stay
under `OUTPUT`; failure leaves a disposable partial directory, never a completion
marker. Use a new output directory to retry. No existing non-empty directory is
reused or cleared.

`host-context.json` is written last and contains the CLI, data directory, case,
asset, source-view request, declared host ID, ready receipt, source `tree/` and run
directory. The acknowledgement binds the declared host, and the host's `prepare`
must declare the same ID. Pass `--host-id ID` with the ID the selected acceptance
host will declare; without it setup declares `unknown`. The ID is caller-declared,
not authenticated. The ready receipt contains the synthetic operator's explicit
model-processing acknowledgement, so the acceptance host does not invent a
confirmer or approve a grant. The normal skill still requires the real user's own
decisions.

The lead gives this context to a real host with native delegation and the
[shared skill reference](../../../skills/ai-security-scanner/references/cloudflare-source-audit.md),
then asks it to audit that ready synthetic source view using a chosen profile and
sufficient invocation budget, deliver the shared HTML report, and keep a complete
private archive including source bodies. Provide new private report and archive
destinations outside the data directory and source view. To exercise composition,
also request applicable existing scanner checks of the copied repository; the host
runs those before audit preparation or after admission and saves one combined report. Only `tree/` is target source for agents. Keep this
README and [EXPECTED.md](EXPECTED.md) out of their prompts and the view. The lead
uses EXPECTED afterward to assess method compliance and native outcomes, including
unchanged outputs, verified sealing, automatic admission, shared reporting,
requested archive creation/verification, incomplete coverage and trust wording.

Native verification uses the runner's `acceptance-setup` suite: CLI build, setup in
two fresh private directories, then refusal of the first non-empty directory.
The no-CLI refusal test is included in `node --test tests/skill/*.test.mjs`.
A successful setup test does not establish a successful real host audit. Real host
acceptance is a separate next step; this kit does not launch it automatically.

## Verify the host's archive (lead only)

After the host has finished and released the data-directory writer lease, run:

```sh
node tests/acceptance/cloudflare-host/verify-restore.mjs \
  --cli "$CLI" --context "$OUTPUT/host-context.json" \
  --archive "$HOST_ARCHIVE" --output "$VERIFY_OUTPUT"
```

`HOST_ARCHIVE` must be the host-created archive **with source bodies included**.
`VERIFY_OUTPUT` follows setup's canonical, new-or-empty directory rules and must
be separate from the original data, source view and host run directory. Both tools
share path validation and the private process environment. No CLI is needed for
the argument/output refusal tests in `tests/skill/`.

The verifier derives sessions, admitted/scanner runs and all recorded terminal,
single-run export and combined snapshots from public CLI JSON. It refuses a case
without an admitted audit. It verifies the host archive, creates and verifies a
second archive without source bodies, then previews and restores each into a new
private workspace. On each restore it checks the same admission identity/digest,
read-only status, full or included payload verification and the exact source
omission sentence. For every recorded snapshot, HTML and JSON retrieval and replay
must match the original retrieval's SHA-256 and length. Accepted captured output
must also match. A fresh admission must return exit 2 `restored_session_inert`
and leave the case unchanged.

`VERIFY_OUTPUT/verify-restore.json` records every command, exit code, returned JSON,
compared digests and each check's pass/fail. It is private acceptance evidence.
Failures return nonzero and leave the output for inspection; retry in a new
output directory. The verifier never executes a model, scanner or target, reads a
database directly, or repairs saved data. The second archive only reads saved data.
The CLI exposes no current case revision outside foreground scan responses, so
"unchanged" means every public read of the case (`case show`, `scan status` and each
audit's `provider cloudflare status`) is identical before and after; this brackets
the whole verification on the original data and each refused admission on a restore.
Snapshot references read from different commands are matched by their identifying
fields (ID, path, SHA-256, length and source revision), not by key order.
