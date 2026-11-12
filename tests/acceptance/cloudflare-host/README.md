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
sufficient invocation budget. Only `tree/` is target source for agents. Keep this
README and [EXPECTED.md](EXPECTED.md) out of their prompts and the view. The lead
uses EXPECTED afterward to assess method compliance and native outcomes, including
unchanged outputs, sealed status, incomplete coverage and trust wording.

Native verification uses the runner's `acceptance-setup` suite: CLI build, setup in
two fresh private directories, then refusal of the first non-empty directory.
The no-CLI refusal test is included in `node --test tests/skill/*.test.mjs`.
A successful setup test does not establish a successful real host audit. Real host
acceptance is a separate next step; this kit does not launch it automatically.
