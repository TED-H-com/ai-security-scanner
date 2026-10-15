# Engine maintenance procedure

This procedure keeps each scanner close to its upstream project while preserving safe product operation and one professional report. The machine-readable catalog owns exact artifact facts, [engine-catalog.md](engine-catalog.md) owns the public capability description, and the [product specification](product-spec.md) owns product behavior.

The [engine reference](engines/README.md) has a page per engine and launcher with the wiring, the files that move together, and the lessons from real runs. The [image build and update notebook](engines/image-build-index.md) indexes every Dockerfile/context, host rule/database preparation and shared launcher impact, with a dated update-record template. Read these before changing an engine and record what the update actually tested.

## 1. Default decision: update upstream, not a private detector

For every change, classify it before implementation:

1. **Upstream artifact update:** a new upstream release, source revision, image, plugin, rule/template pack, feed, or vulnerability database. Pin and verify the new upstream closure.
2. **Thin-adapter update:** input serialization, output parsing, resource controls, or authorization/safety enforcement around unchanged upstream detection behavior.
3. **Report-layer update:** shared normalization, localization, deduplication, prioritization, or product-authored guidance after upstream results have been preserved.
4. **Detector behavior change:** a change to what the scanner detects, how it assigns its native severity, or what remediation it emits. This belongs upstream and must not be implemented casually in a wrapper.

Choose an upstream-supported CLI/API/configuration first. If it cannot express the required capability, contribute upstream or select another upstream engine. A downstream detector patch is a narrow, hash-bound exception with a defined removal condition.

## 2. Thin-adapter boundary

An engine wrapper has four responsibilities:

- **Input:** validate and serialize the already-authorized target, artifact, selected upstream profile, and credential reference.
- **Output:** retain raw upstream output and convert its structure into the common schema without changing the finding’s meaning.
- **Resources:** enforce timeout, cancellation, output-size, CPU, memory, disk, process, and cleanup limits.
- **Safety:** enforce exact targets, mounts, provider identity, outbound endpoints, redirects, rate limits, and prohibited operations.

The wrapper must not:

- add private detection rules or reproduce upstream detection logic;
- rewrite upstream severity, title, description, or remediation;
- hide, promote, or suppress findings to make the result look cleaner;
- convert an error, unknown value, inventory record, open port, or empty result into pass/fail security judgment;
- expand the target, provider, port, path, rule, template, or check set beyond the user-authorized input;
- simulate support for an upstream provider or scan mode through an open-ended patch series.

Filtering is allowed only for an explicit safety boundary or an explicitly selected upstream profile. The report must disclose the checks excluded by that boundary; the wrapper must not imply full upstream coverage.

## 3. Common professional report boundary

Wrappers emit evidence, not user-facing prose. The shared normalization/report layer may provide consistent labels and guidance, but it must preserve:

- engine name, upstream version, artifact digest, and rule/template/check identifier;
- original title, severity, message, remediation, locations, and evidence when upstream supplies them;
- whether each displayed severity or recommendation is upstream-provided, deterministically normalized, or product-authored;
- execution status, selected profile, checked scope, excluded scope, and knowledge date.

Localization and concise professional wording may sit beside the preserved upstream fields. They must not silently replace those fields. Deduplication may group equivalent observations, but every contributing engine result remains traceable.

Capability labels use the catalog definitions: connectivity, exposure, vulnerability, configuration, secrets, and inventory. An adapter or report may claim only categories produced by checks that actually completed. Zero matches never means the target is secure.

## 4. Updating an engine

1. Resolve the official upstream tag and full source revision. Update `engines/upstreams.lock.json` and the catalog entry with the exact acquisition source.
2. Record the upstream changelog items relevant to inputs, outputs, detection behavior, rules/data compatibility, resource use, and supported platforms.
3. Review the exact engine, dependencies, image, rules, templates, feed, and database licenses. Update notices, source/source-offer material, and SBOM as required.
4. Pin every build input and base image. Do not use floating tags, runtime plugin downloads, mutable rule sources, shell-expanded targets, or automatic database/feed updates.
5. Prefer an official upstream image by immutable digest. If none is suitable, build pinned upstream source with only the minimum launcher required by section 2. A scanner built from that pinned source records `engine_version` as `source@` plus the commit, and `reported_version` as the release version the built binary reports about itself, with no leading `v`. The catalog validator requires `reported_version` for that engine. When `image.tag` is a string, it must equal `reported_version` or start with `reported_version` followed by `-`.
6. Run representative bounded fixtures through the product adapter. Cover valid and malformed output, unknown fields, empty results, output limits, timeout, cancellation, cleanup, target enforcement, and managed egress where applicable.
7. Compare normalized records to the raw upstream output. Verify that rule IDs, titles, severities, messages, evidence, and remediation were preserved and that report-only additions are labeled.
8. Apply the shared adapter-contract version rule in section 8. Keep migrations capable of explaining existing cases.
9. Set `knowledge_date` to the newest date genuinely represented by the exact engine/data closure. Set `support_until` to the maintained support window; do not refresh either merely because the application was rebuilt.
10. Update the honest capability and exclusions table if, and only if, the executed upstream profile changed what the product actually checks.

If the product owner separately requests artifact distribution, use the [engine artifact trust reference](release/engine-image-supply-chain.md) to verify the exact architectures, digest, source association, entrypoint, SBOM, notices/source offer, and retrieval claim for that artifact. This is not part of ordinary scanner maintenance.

An engine failure or unavailable artifact remains an explicit per-engine `not_tested`/failed outcome. It must not be replaced by an unpinned artifact, a broader profile, or a fabricated result.

## 5. Assisted refresh proposals

Create an offline bundle with `npm run upstream:refresh -- --engine <id> [--kind revision|provenance]`, then re-validate it with `npm run upstream:propose -- --bundle <path>`. `revision` refreshes the pinned upstream revision and related adapter inputs; `provenance` records baselined build-input hashes and supports only the mechanical provider. A `revision` proposal cannot reach PR eligibility from this offline pipeline: completing one requires a re-pinned source archive with a new checksum, a Dockerfile revision update, and a rebuilt image, so `validate:engine-catalog` fails and the proposal says so. Review it as a reading of the drift, not as a shippable change.

`mechanical` is the formal default deterministic offline path. The optional AI path must be selected explicitly with `--provider cli --ai-cli <executable>`; repeat `--ai-cli-arg <arg>` when the executable needs arguments. Any model-authored files are attributed with before and after digests in `report.md` for human review.

The bundle's `generated_at` records when the proposal was produced. An offline refresh preserves the existing `knowledge_date` and `support_until`; inspecting local source or recomputing hashes does not establish newer scanner knowledge or extend support.

The proposal step records one of three PR decisions: `--open-pr` prints the local, push, and PR-creation commands; `--no-open-pr` prints only local commands; omitting both leaves the decision undecided and prints the flags for choosing later. These tools only print commands for a human to review and run; they never execute them on the client's behalf.

## 6. Downstream patch exception

Before accepting a patch to upstream scanner behavior, record all of the following beside the engine plan:

- the concrete user capability that is otherwise impossible;
- the upstream issue or contribution link, or a written reason contribution is not practical;
- the smallest patch diff and the upstream files/behavior it changes;
- pre-patch and post-patch source hashes and a dedicated behavior fixture;
- security, license, and maintenance ownership;
- the upstream version range to which it applies;
- a removal condition and review date.

Do not stack unrelated behavior into one patch series. Do not add a second downstream feature while the first lacks an upstream or removal plan. A new upstream release triggers a fresh attempt to remove every patch before rebasing it.

The current Prowler Azure static-token and GCP exact-project implementation is such an exception: six hash-bound runtime patches provide behavior that is not native to Prowler 5.39.1. It must remain labeled as the product’s narrow profile, must not be described as general Prowler Azure/GCP coverage, and must not expand without re-evaluating an upstream-supported replacement.

Project launchers that only enforce section 2 boundaries are adapters, not detector forks. Any launcher code that begins deciding whether evidence is vulnerable, changing native severity, or authoring engine-specific remediation has crossed into report or detector logic and must be moved or removed.

## 7. Dates, replacement, and history

Current recipe closure and historical publication are separate records. Each
engine plan's `build_recipe.local_inputs` records the actual SHA-256 and path of
previously uncovered context allowlists, preparers, patches, launchers, runtime
configuration and dependency definitions. The executable-input gate has no
remaining uncovered baseline. Shared support directories and documentation/test
exclusions remain explicit in `engines/image-input-hash-policy.json`; this gate
does not claim a complete transitive package closure.

These hashes describe the current source recipe. They do not establish that an
older published image contains those bytes. When a previously published tag's
historical plan differs, use a new immutable artifact revision instead of
changing the old tag or weakening the reuse guard. A reviewed replacement may
keep the old exact image runnable while its plan names the new unpublished
tag. `previous_artifact` and `previous_publication` hold only closed historical
coordinates/evidence; executable inputs cannot be stored there. Switch the
catalog only after verifying the new image and its publication evidence.

For an upstream version change, `upstream_update` holds only the closed candidate
catalog identity. The validator checks the new recipe through that identity while
keeping the old image, runtime permissions and knowledge dates in the installed
catalog. Remove this metadata only when the verified replacement is activated.
The [October 14 update record](engines/updates/2026-10-14.md) documents this flow.

`knowledge_date` describes the newest knowledge in the exact engine/rule/template/feed/database closure. `support_until` is the last date maintainers claim support for that closure and is normally no more than 90 days later. Historical cases retain their original engine identity and dates.

An artifact remains attributable whatever its age. A run records and shows the exact scanner version and its `knowledge_date` as the last-updated date. `support_until` is maintenance metadata; it never marks a run's results expired or incomplete. A replacement receives a new revision and immutable digest; it never rewrites an existing case.

Any byte-affecting launcher, Dockerfile, embedded rule/policy, feed, database, or scanner patch change creates a new engine artifact revision. A report-only normalizer change advances the adapter/report version without pretending the upstream engine changed.

If an update cannot meet its source, license, compatibility, safety, or artifact requirements, only that engine’s coverage is unavailable. Preserve completed sibling results and state the exact gap in the report.

## 8. Shared adapter contract version

`adapter_version` names the version of the shared normalization contract. It is one value, not one per engine: `ADAPTER_VERSION` in `src-tauri/src/adapters/mod.rs`, mirrored into every catalog entry. A run whose manifest version differs from the loaded adapter’s is refused.

Every stored engine run and every export carries this value, and that is what the rule protects. A stored run claims its normalized output was produced by a named contract. If normalization changes and the version does not, an old run and a new run claim the same contract while meaning different things, and a comparison between them presents our own mapping change as though the target had changed.

Bump it when the same upstream bytes would produce a different normalized result. In practice, bump it when a change alters:

- which upstream records become findings, or stop becoming findings;
- the value of any normalized field for unchanged input (severity, confidence, title, location, remediation, tags, or evidence references);
- the set of values a normalized field can take;
- the warnings or coverage attributed to an engine run.

Do not bump it for refactors, comments, or tests; for report-layer wording, which is not the adapter; or for a new upstream engine, image, or feed version, which `engine_version`, `rule_version`, and the image pin already record.

Numbering follows the contract, not the calendar:

- **Patch:** normalized values change, but every field keeps its shape and its set of possible values, so a consumer written against the old contract still parses the output.
- **Minor:** the set of possible values widens, or a field is added, so a strict consumer written against the old contract can reject output that is correct.
- **Major:** a field is removed or changes type.

The change from 0.1.4 to 0.2.0 is a minor bump. `Confidence` gained `Unknown`, and the framework report schema’s confidence enum widened from four values to five, so a validator written against the four-value enum rejects an export that is correct. It was earned in commit `4ec35b0`, where a Greenbone result with no detection quality stopped being reported as Medium confidence.

## 9. Large-report normalization

Launchers may capture reports up to 512 MiB. The shared normalizer now uses the same per-file and total serialized-byte boundary; it does not discard a whole valid report merely because it exceeds the former 16 MiB in-memory document limit. Smaller artifacts retain their existing parser. Larger JSON, JSONL and XML artifacts stream from the verified case path.

- **JSON:** `adapters/bounded_json.rs` assigns a 32 MiB materialization budget to values and keys, caps individual copied strings at 1 MiB, nested depth at 64, and each array at 100,000 entries. Normalized records still have their existing 10,000-record bound; the larger parsing bound lets engines such as Cloudsplaining prioritize retained findings before that bound. It validates skipped values with Serde `IgnoredAny`. An oversized string is omitted whole rather than becoming a truncated identifier; later values can still be read. Omission withholds complete coverage. The budget bounds the retained tree, not total process RSS: the JSON decoder may temporarily hold a serialized scalar, bounded by the 512 MiB artifact limit.
- **JSONL:** lines remain bounded at 1 MiB, with at most 10,000 retained rows and the same shared tree budget. Overlong or malformed lines make coverage incomplete while valid sibling rows remain usable. CloudQuery retains its existing specialized scalar-column reader and 64 MiB row limit.
- **XML:** the Greenbone parser streams events with its existing depth, event, record, attribute and evidence-field bounds. The raw XML stays available when these limits exclude later records or oversized fields.
- **Evidence identity:** every streamed file is read to its end even if parsing stops at a record limit. Its full length and SHA-256 must match the captured metadata before any parsed findings are accepted. A changed suffix therefore invalidates the whole parsed result.

When updating an engine, compare its actual maximum-output budget and media type with these limits. Do not shrink upstream output to 16 MiB, silently claim complete coverage after truncation, or raise the materialized-tree budget to the full on-disk maximum. Regression cases in `adapter_fixtures.rs` cover JSON/XML/JSONL above 16 MiB and a large omitted value followed by a real finding; reader tests also cover changed tails and the 512 MiB rejection boundary.
