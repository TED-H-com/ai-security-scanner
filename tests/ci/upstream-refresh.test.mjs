import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import {
  chmodSync,
  cpSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import test from "node:test";

import {
  REQUIRED_VERIFICATIONS,
  formatRefreshOutcomeLine,
  prReasons,
  refreshEngine,
  refreshEngines,
  zeroChangeOutcome,
} from "../../scripts/upstream-refresh-lib.mjs";
import { validateEngineInputHashes } from "../../scripts/validate-engine-input-hashes.mjs";
import { main as proposeMain } from "../../scripts/upstream-propose.mjs";
import { main as refreshMain, parseRefreshArguments } from "../../scripts/upstream-refresh.mjs";

const repositoryRoot = resolve(import.meta.dirname, "../..");
const fixedNow = new Date("2026-09-17T12:34:56.000Z");

function sha256(value) {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function run(command, args, options = {}) {
  const result = spawnSync(command, args, { encoding: "utf8", ...options });
  if (result.status !== 0) {
    throw new Error(result.error?.message ?? (result.stderr || `${command} exited ${result.status}`));
  }
  return result.stdout.trim();
}

function commit(repository, message) {
  run("git", ["init", "--quiet"], { cwd: repository });
  run("git", ["add", "--all"], { cwd: repository });
  run("git", [
    "-c", "user.name=Refresh Test",
    "-c", "user.email=refresh-test@invalid",
    "commit", "--quiet", "-m", message,
  ], { cwd: repository });
  return run("git", ["rev-parse", "HEAD"], { cwd: repository });
}

function passedVerification(overrides = {}) {
  return REQUIRED_VERIFICATIONS.map((name) => ({
    name,
    status: overrides[name]?.status ?? "passed",
    reason: overrides[name]?.reason ?? null,
    command: `fixture ${name}`,
    output: "fixture completed",
    output_truncated: false,
  }));
}

function createFixture({
  engineIds = ["sample"],
  absentCheckout = false,
  matchingCheckout = false,
  lockRevisionByEngine = {},
  baselineFilesByEngine = {},
} = {}) {
  const root = mkdtempSync(join(tmpdir(), "upstream-refresh-test-"));
  mkdirSync(join(root, "engines", "images"), { recursive: true });
  const repositories = [];
  const revisions = new Map();
  const uncoveredBaseline = [];
  for (const engineId of engineIds) {
    const checkoutRelative = `.upstreams/example/${engineId}`;
    const checkout = join(root, ...checkoutRelative.split("/"));
    let pinned = "1".repeat(40);
    let candidate = null;
    if (!absentCheckout) {
      mkdirSync(checkout, { recursive: true });
      writeFileSync(join(checkout, "adapter.txt"), "pinned adapter\n");
      pinned = commit(checkout, "pinned");
      if (!matchingCheckout) {
        writeFileSync(join(checkout, "adapter.txt"), "refreshed adapter\n");
        run("git", ["add", "adapter.txt"], { cwd: checkout });
        run("git", [
          "-c", "user.name=Refresh Test",
          "-c", "user.email=refresh-test@invalid",
          "commit", "--quiet", "-m", "candidate",
        ], { cwd: checkout });
        candidate = run("git", ["rev-parse", "HEAD"], { cwd: checkout });
      }
    }
    const engineDirectory = join(root, "engines", "images", engineId);
    mkdirSync(engineDirectory, { recursive: true });
    writeFileSync(join(engineDirectory, "Dockerfile"), "FROM scratch\n");
    const plan = {
      schema_version: 1,
      engine_id: engineId,
      knowledge_date: "2026-01-01",
      support_until: "2026-04-01",
      publish_state: "published_managed_artifact",
      source: {
        repository: `https://example.invalid/example/${engineId}`,
        revision: pinned,
        acquisition_source: `https://example.invalid/example/${engineId}/commit/${pinned}`,
        local_research_checkout: checkoutRelative,
      },
      final_artifact: {
        repository: `ghcr.io/example/${engineId}`,
        tag: "1.0.0",
        digest: `sha256:${"2".repeat(64)}`,
      },
      build_recipe: {
        dependency_lock: {
          path: "adapter.txt",
          sha256: sha256("pinned adapter\n"),
        },
      },
      dockerfile: {
        path: `engines/images/${engineId}/Dockerfile`,
        sha256: sha256("FROM scratch\n"),
      },
    };
    for (const file of baselineFilesByEngine[engineId] ?? []) {
      const relative = `engines/images/${engineId}/${file.path}`;
      const absolute = join(root, ...relative.split("/"));
      mkdirSync(dirname(absolute), { recursive: true });
      writeFileSync(absolute, file.content);
      uncoveredBaseline.push({ path: relative, reason: file.reason });
    }
    writeFileSync(join(engineDirectory, "plan.json"), `${JSON.stringify(plan, null, 2)}\n`);
    repositories.push({
      id: `example/${engineId}`,
      path: checkoutRelative,
      remote: plan.source.repository,
      revision: lockRevisionByEngine[engineId] ?? candidate ?? pinned,
    });
    revisions.set(engineId, { pinned, candidate });
  }
  writeFileSync(join(root, "engines", "upstreams.lock.json"), `${JSON.stringify({ repositories }, null, 2)}\n`);
  writeFileSync(join(root, "engines", "image-input-hash-policy.json"), `${JSON.stringify({
    schema_version: 1,
    exclusions: [{
      id: "provenance-record",
      match: "exact",
      value: "plan.json",
      reason: "The plan cannot record its own digest.",
    }],
    directories_without_plans: [],
    uncovered_baseline: uncoveredBaseline,
  }, null, 2)}\n`);
  return {
    root,
    revisions,
    bundleRoot: join(root, "bundles"),
    cleanup() {
      rmSync(root, { recursive: true, force: true });
    },
  };
}

function policy(entries) {
  return {
    schema_version: 1,
    engines: entries.map(([id, status, reason = `${id} fixture policy.`]) => ({ id, status, reason })),
  };
}

test("a frozen engine is refused with its stated reason and cannot become a PR", async () => {
  const frozenReason = "CloudQuery retains the public AWS 9.2.0 and file 1.0.4 plugins (knowledge_date 2023-01-10). CLI 3.5.3 is the last version supporting their protocol; newer CLIs reject this closure. Automatic refreshes remain frozen pending a manually verified public plugin and protocol replacement.";
  const result = await refreshEngine({
    root: repositoryRoot,
    engineId: "cloudquery",
    now: fixedNow,
    bundleRoot: mkdtempSync(join(tmpdir(), "upstream-refresh-frozen-")),
  });
  try {
    assert.deepEqual({
      outcome: result.proposal.outcome,
      eligible: result.proposal.pr_eligible,
      policyReason: result.proposal.policy.reason,
      patch: result.patch,
      checks: result.proposal.verification.map(({ status }) => status),
    }, {
      outcome: "frozen",
      eligible: false,
      policyReason: frozenReason,
      patch: "",
      checks: ["not_run", "not_run", "not_run"],
    });
  } finally {
    rmSync(dirname(dirname(result.bundlePath)), { recursive: true, force: true });
  }
});

test("a frozen engine remains ineligible when the early return is not what stops it", async () => {
  const frozenReason = "Deliberately pinned to a last fully public upstream.";
  const setup = createFixture({ engineIds: ["frozen-one"] });
  try {
    const proceeded = await refreshEngine({
      root: setup.root,
      engineId: "frozen-one",
      policy: policy([["frozen-one", "eligible"]]),
      now: fixedNow,
      bundleRoot: setup.bundleRoot,
      verificationRunner: () => passedVerification(),
    });
    const reasons = prReasons({
      policy: { id: "frozen-one", status: "frozen", reason: frozenReason },
      changes: new Map(proceeded.proposal.changes.files.map((file) => [file, { produced: true }])),
      verifications: proceeded.proposal.verification,
      providerError: null,
    });
    assert.deepEqual({
      proceededEligible: proceeded.proposal.pr_eligible,
      proceededChecks: proceeded.proposal.verification.map(({ status }) => status),
      produced: proceeded.proposal.changes.produced,
      frozenEligible: reasons.length === 0,
      reasons,
    }, {
      proceededEligible: true,
      proceededChecks: ["passed", "passed", "passed"],
      produced: true,
      frozenEligible: false,
      reasons: [`Policy status is frozen: ${frozenReason}`],
    });
  } finally {
    setup.cleanup();
  }
});

test("an unknown engine id is refused closed", async () => {
  const setup = createFixture({ engineIds: ["known"] });
  try {
    const result = await refreshEngine({
      root: setup.root,
      engineId: "unknown",
      policy: policy([["known", "eligible"]]),
      now: fixedNow,
      bundleRoot: setup.bundleRoot,
    });
    assert.deepEqual({
      outcome: result.proposal.outcome,
      status: result.proposal.policy.status,
      eligible: result.proposal.pr_eligible,
      reason: result.proposal.policy.reason,
    }, {
      outcome: "unsupported",
      status: "unsupported",
      eligible: false,
      reason: "No refresh-policy entry exists for engine unknown; unknown engines fail closed.",
    });
  } finally {
    setup.cleanup();
  }
});

test("an experimental failure stays experimental and does not change an eligible engine outcome", async () => {
  const setup = createFixture({ engineIds: ["experimental-one", "eligible-one"] });
  try {
    const productPolicy = JSON.parse(readFileSync(join(repositoryRoot, "engines", "upstream-refresh-policy.json")));
    const encodedProductFacts = Object.fromEntries(productPolicy.engines
      .filter(({ id }) => ["agentic-radar", "garak", "mcp-armor"].includes(id))
      .map(({ id, status, reason }) => [id, { status, cannotRelease: reason.includes("cannot reach a release") }]));
    const runResult = await refreshEngines({
      root: setup.root,
      engineIds: ["experimental-one", "eligible-one"],
      policy: policy([
        ["experimental-one", "experimental", "Its managed artifact is not published, so it cannot reach a release."],
        ["eligible-one", "eligible"],
      ]),
      now: fixedNow,
      bundleRoot: setup.bundleRoot,
      verificationRunner: ({ engineId }) => engineId === "experimental-one"
        ? passedVerification({ "validate:engine-catalog": { status: "failed", reason: "fixture failure" } })
        : passedVerification(),
    });
    assert.deepEqual({
      exitCode: runResult.exitCode,
      experimental: {
        outcome: runResult.results[0].proposal.outcome,
        eligible: runResult.results[0].proposal.pr_eligible,
        failedCheck: runResult.results[0].proposal.verification[1].status,
        releaseStatement: runResult.results[0].proposal.policy.reason,
      },
      eligible: {
        outcome: runResult.results[1].proposal.outcome,
        eligible: runResult.results[1].proposal.pr_eligible,
      },
      encodedProductFacts,
    }, {
      exitCode: 0,
      experimental: {
        outcome: "experimental",
        eligible: false,
        failedCheck: "failed",
        releaseStatement: "Its managed artifact is not published, so it cannot reach a release.",
      },
      eligible: { outcome: "ready", eligible: true },
      encodedProductFacts: {
        "agentic-radar": { status: "frozen", cannotRelease: true },
        garak: { status: "frozen", cannotRelease: true },
        "mcp-armor": { status: "frozen", cannotRelease: true },
      },
    });
  } finally {
    setup.cleanup();
  }
});

test("an experimental engine with passing verification cannot become a PR and still emits a readable proposal", async () => {
  const experimentalReason = "Its managed artifact is not published, so it cannot reach a release.";
  const setup = createFixture({ engineIds: ["experimental-one"] });
  try {
    const result = await refreshEngine({
      root: setup.root,
      engineId: "experimental-one",
      policy: policy([["experimental-one", "experimental", experimentalReason]]),
      now: fixedNow,
      bundleRoot: setup.bundleRoot,
      verificationRunner: () => passedVerification(),
    });
    const proposed = JSON.parse(readFileSync(join(result.bundlePath, "proposal.json"), "utf8"));
    const report = readFileSync(join(result.bundlePath, "report.md"), "utf8");
    assert.deepEqual({
      outcome: result.proposal.outcome,
      eligible: result.proposal.pr_eligible,
      reasons: result.proposal.pr_ineligibility_reasons,
      checks: result.proposal.verification.map(({ name, status }) => `${name}:${status}`),
      produced: result.proposal.changes.produced,
      files: result.proposal.changes.files,
      patchEmpty: result.patch.length === 0,
      bundleFiles: readdirSync(result.bundlePath).sort(),
      persistedEligible: proposed.pr_eligible,
      persistedOutcome: proposed.outcome,
      reportOutcome: report.includes("Outcome: **experimental**"),
      reportForbidsPr: report.includes("May not become a PR"),
      reportNamesExperimental: report.includes(`Policy status is experimental: ${experimentalReason}`),
    }, {
      outcome: "experimental",
      eligible: false,
      reasons: [`Policy status is experimental: ${experimentalReason}`],
      checks: [
        "validate:engine-input-hashes:passed",
        "validate:engine-catalog:passed",
        "validate:engine-line-endings:passed",
      ],
      produced: true,
      files: ["engines/images/experimental-one/plan.json"],
      patchEmpty: false,
      bundleFiles: ["changes.patch", "proposal.json", "report.md"],
      persistedEligible: false,
      persistedOutcome: "experimental",
      reportOutcome: true,
      reportForbidsPr: true,
      reportNamesExperimental: true,
    });
  } finally {
    setup.cleanup();
  }
});

test("an absent upstream checkout is unavailable rather than no drift", async () => {
  const setup = createFixture({ engineIds: ["sample"], absentCheckout: true });
  try {
    const result = await refreshEngine({
      root: setup.root,
      engineId: "sample",
      policy: policy([["sample", "eligible"]]),
      now: fixedNow,
      bundleRoot: setup.bundleRoot,
    });
    assert.deepEqual({
      checkoutStatus: result.proposal.inputs.local_research_checkout.status,
      checkoutComparison: result.proposal.inputs.local_research_checkout.comparison,
      driftStatus: result.proposal.drift.status,
      driftSummary: result.proposal.drift.summary,
      outcome: result.proposal.outcome,
      eligible: result.proposal.pr_eligible,
    }, {
      checkoutStatus: "unavailable",
      checkoutComparison: "unavailable",
      driftStatus: "unavailable",
      driftSummary: "At least one offline source was unavailable; this is not a no-drift result.",
      outcome: "drift_unavailable",
      eligible: false,
    });
    assert.notEqual(result.proposal.outcome, "no_change");
    assert.equal(
      result.proposal.pr_ineligibility_reasons[0],
      "The local research checkout is absent; upstream drift could not be inspected there; this is not a no-drift result. Restore the missing offline source or re-pin the plan manually.",
    );
  } finally {
    setup.cleanup();
  }
});

test("a zero-change refresh reports no_change only when drift is none", async () => {
  const driftedLockRevision = "a".repeat(40);
  const cases = [
    { name: "none", setup: () => createFixture({ matchingCheckout: true }) },
    {
      name: "detected",
      setup: () => createFixture({
        absentCheckout: true,
        lockRevisionByEngine: { sample: driftedLockRevision },
      }),
    },
    { name: "unavailable", setup: () => createFixture({ absentCheckout: true }) },
  ];
  const observed = [];
  try {
    for (const fixture of cases) {
      const setup = fixture.setup();
      observed.push({ setup });
      const result = await refreshEngine({
        root: setup.root,
        engineId: "sample",
        policy: policy([["sample", "eligible"]]),
        now: fixedNow,
        bundleRoot: setup.bundleRoot,
      });
      Object.assign(observed.at(-1), {
        drift: result.proposal.drift.status,
        outcome: result.proposal.outcome,
        eligible: result.proposal.pr_eligible,
        produced: result.proposal.changes.produced,
        line: `sample: ${formatRefreshOutcomeLine(result.proposal)}`,
        reason: result.proposal.pr_ineligibility_reasons[0],
        checkout: result.proposal.inputs.local_research_checkout,
        lock: result.proposal.inputs.upstream_lock,
        pin: result.proposal.drift.pinned_revision,
      });
    }
    const [none, detected, unavailable] = observed;
    const cliSource = readFileSync(join(repositoryRoot, "scripts", "upstream-refresh.mjs"), "utf8");
    assert.deepEqual({
      none: {
        drift: none.drift,
        outcome: none.outcome,
        eligible: none.eligible,
        produced: none.produced,
        line: none.line,
      },
      detected: {
        drift: detected.drift,
        outcome: detected.outcome,
        eligible: detected.eligible,
        produced: detected.produced,
        lockComparison: detected.lock.comparison,
        checkoutStatus: detected.checkout.status,
      },
      unavailable: {
        drift: unavailable.drift,
        outcome: unavailable.outcome,
        eligible: unavailable.eligible,
        produced: unavailable.produced,
        checkoutStatus: unavailable.checkout.status,
      },
      detectedIsNotNoChange: detected.outcome !== "no_change",
      unavailableIsNotNoChange: unavailable.outcome !== "no_change",
      cliPrintsFormatter: cliSource.includes("formatRefreshOutcomeLine(result.proposal)"),
    }, {
      none: {
        drift: "none",
        outcome: "no_change",
        eligible: false,
        produced: false,
        line: "sample: no_change",
      },
      detected: {
        drift: "detected",
        outcome: "drift_detected_but_no_proposal",
        eligible: false,
        produced: false,
        lockComparison: "different",
        checkoutStatus: "unavailable",
      },
      unavailable: {
        drift: "unavailable",
        outcome: "drift_unavailable",
        eligible: false,
        produced: false,
        checkoutStatus: "unavailable",
      },
      detectedIsNotNoChange: true,
      unavailableIsNotNoChange: true,
      cliPrintsFormatter: true,
    });
    assert.equal(
      detected.line,
      `sample: drift_detected_but_no_proposal — Upstream lock revision ${driftedLockRevision} differs from the plan pin ${detected.pin}; the local research checkout is absent; upstream drift could not be inspected there. Re-pin the plan after inspecting a local checkout.`,
    );
    assert.equal(
      unavailable.line,
      "sample: drift_unavailable — The local research checkout is absent; upstream drift could not be inspected there; this is not a no-drift result. Restore the missing offline source or re-pin the plan manually.",
    );
    assert.equal(detected.reason, detected.line.slice("sample: drift_detected_but_no_proposal — ".length));
    assert.equal(unavailable.reason, unavailable.line.slice("sample: drift_unavailable — ".length));
    assert.match(detected.reason, /re-pin the plan after inspecting a local checkout/i);
    assert.match(unavailable.reason, /restore the missing offline source or re-pin the plan manually/i);
  } finally {
    for (const entry of observed) entry.setup?.cleanup();
  }
});

test("zeroChangeOutcome throws on an unrecognized or missing drift status instead of reporting no_change", () => {
  for (const drift of [{ status: "surprise" }, {}, null, undefined]) {
    assert.throws(() => zeroChangeOutcome(drift));
  }
});

test("refreshEngines exits 1 when a proposal outcome is not in the known set", async () => {
  const setup = createFixture();
  // refreshEngine only emits known outcomes; rewrite the proposal during
  // JSON.stringify so the defence-in-depth exit-code guard can run.
  const stringify = JSON.stringify;
  JSON.stringify = function patchUnrecognizedOutcome(value, replacer, space) {
    if (
      value
      && typeof value === "object"
      && Object.hasOwn(value, "pr_eligible")
      && Object.hasOwn(value, "bundle_path")
      && Object.hasOwn(value, "outcome")
    ) {
      value.outcome = "surprise";
    }
    return stringify.call(this, value, replacer, space);
  };
  try {
    const run = await refreshEngines({
      root: setup.root,
      engineIds: ["sample"],
      policy: policy([["sample", "eligible"]]),
      now: fixedNow,
      bundleRoot: setup.bundleRoot,
      verificationRunner: () => passedVerification(),
    });
    assert.equal(run.results[0].error, undefined);
    assert.equal(run.results[0].proposal.policy.status, "eligible");
    assert.equal(run.results[0].proposal.outcome, "surprise");
    assert.equal(run.exitCode, 1);
  } finally {
    JSON.stringify = stringify;
    setup.cleanup();
  }
});

test("a failing verification check forces PR ineligibility and names the check", async () => {
  const setup = createFixture();
  try {
    const result = await refreshEngine({
      root: setup.root,
      engineId: "sample",
      policy: policy([["sample", "eligible"]]),
      now: fixedNow,
      bundleRoot: setup.bundleRoot,
      verificationRunner: () => passedVerification({ "validate:engine-catalog": { status: "failed", reason: "catalog mismatch" } }),
    });
    assert.deepEqual({
      eligible: result.proposal.pr_eligible,
      status: result.proposal.verification.find(({ name }) => name === "validate:engine-catalog").status,
      reasons: result.proposal.pr_ineligibility_reasons,
      reportKeepsRawEvidence: result.report.includes("fixture completed"),
      reportExplainsRequiredWork: result.report.includes("a re-pinned source archive with a new SHA-256 checksum, a Dockerfile revision update, and a rebuilt image"),
    }, {
      eligible: false,
      status: "failed",
      reasons: [
        "Verification check validate:engine-catalog failed.",
        "Completing an upstream revision refresh requires a re-pinned source archive with a new SHA-256 checksum, a Dockerfile revision update, and a rebuilt image; those network, registry, and owner-authorized publication steps are outside this offline pipeline.",
      ],
      reportKeepsRawEvidence: true,
      reportExplainsRequiredWork: true,
    });
  } finally {
    setup.cleanup();
  }
});

test("a provenance refresh with baselined gaps becomes PR-eligible and upstream:propose prints commands", async () => {
  const setup = createFixture({
    baselineFilesByEngine: {
      sample: [{
        path: "build-helper.sh",
        content: "#!/bin/sh\nexit 0\n",
        reason: "Runs a deterministic build preparation step but has no digest in the plan.",
      }],
    },
  });
  try {
    const result = await refreshEngine({
      root: setup.root,
      engineId: "sample",
      refreshKind: "provenance",
      policy: policy([["sample", "eligible"]]),
      now: fixedNow,
      bundleRoot: setup.bundleRoot,
      verificationRunner: () => passedVerification(),
    });
    let stdout = "";
    const proposeStatus = proposeMain(["--bundle", result.bundlePath, "--open-pr"], { write(value) { stdout += value; } });
    assert.deepEqual({
      kind: result.proposal.refresh_kind,
      outcome: result.proposal.outcome,
      eligible: result.proposal.pr_eligible,
      reasons: result.proposal.pr_ineligibility_reasons,
      files: result.proposal.changes.files,
      checks: result.proposal.verification.map(({ status }) => status),
      proposeStatus,
      proposeEligible: stdout.includes("PR eligible: yes\n"),
      printsPush: stdout.includes("git push -u origin"),
      printsPr: stdout.includes("gh pr create --fill --head"),
    }, {
      kind: "provenance",
      outcome: "ready",
      eligible: true,
      reasons: [],
      files: ["engines/image-input-hash-policy.json", "engines/images/sample/plan.json"],
      checks: ["passed", "passed", "passed"],
      proposeStatus: 0,
      proposeEligible: true,
      printsPush: true,
      printsPr: true,
    });
  } finally {
    setup.cleanup();
  }
});

test("a provenance refresh with passing verification remains refused for an experimental engine", async () => {
  const experimentalReason = "The adapter is experimental and cannot reach a release.";
  const setup = createFixture({
    engineIds: ["experimental-one"],
    baselineFilesByEngine: {
      "experimental-one": [{
        path: "launcher/go.mod",
        content: "module example.invalid/launcher\n",
        reason: "Defines the launcher module but has no digest in the plan.",
      }],
    },
  });
  try {
    const result = await refreshEngine({
      root: setup.root,
      engineId: "experimental-one",
      refreshKind: "provenance",
      policy: policy([["experimental-one", "experimental", experimentalReason]]),
      now: fixedNow,
      bundleRoot: setup.bundleRoot,
      verificationRunner: () => passedVerification(),
    });
    assert.deepEqual({
      outcome: result.proposal.outcome,
      eligible: result.proposal.pr_eligible,
      produced: result.proposal.changes.produced,
      checks: result.proposal.verification.map(({ status }) => status),
      reasons: result.proposal.pr_ineligibility_reasons,
      reportNamesExperimental: result.report.includes(`Policy status is experimental: ${experimentalReason}`),
    }, {
      outcome: "experimental",
      eligible: false,
      produced: true,
      checks: ["passed", "passed", "passed"],
      reasons: [`Policy status is experimental: ${experimentalReason}`],
      reportNamesExperimental: true,
    });
  } finally {
    setup.cleanup();
  }
});

test("a provenance refresh remains refused for a frozen engine and names frozen", async () => {
  const frozenReason = "Deliberately frozen at the last public upstream.";
  const setup = createFixture({ engineIds: ["frozen-one"] });
  try {
    const result = await refreshEngine({
      root: setup.root,
      engineId: "frozen-one",
      refreshKind: "provenance",
      policy: policy([["frozen-one", "frozen", frozenReason]]),
      now: fixedNow,
      bundleRoot: setup.bundleRoot,
    });
    assert.deepEqual({
      outcome: result.proposal.outcome,
      eligible: result.proposal.pr_eligible,
      reasons: result.proposal.pr_ineligibility_reasons,
      reportNamesFrozen: result.report.includes(`Policy status is frozen: ${frozenReason}`),
    }, {
      outcome: "frozen",
      eligible: false,
      reasons: [
        `Policy status is frozen: ${frozenReason}`,
        "No adapter change was produced.",
        `Verification check validate:engine-input-hashes was not run: ${frozenReason}`,
        `Verification check validate:engine-catalog was not run: ${frozenReason}`,
        `Verification check validate:engine-line-endings was not run: ${frozenReason}`,
      ],
      reportNamesFrozen: true,
    });
  } finally {
    setup.cleanup();
  }
});

test("a provenance refresh with no baselined gaps produces no change and states why", async () => {
  const setup = createFixture({ matchingCheckout: true });
  try {
    const result = await refreshEngine({
      root: setup.root,
      engineId: "sample",
      refreshKind: "provenance",
      policy: policy([["sample", "eligible"]]),
      now: fixedNow,
      bundleRoot: setup.bundleRoot,
    });
    assert.deepEqual({
      outcome: result.proposal.outcome,
      eligible: result.proposal.pr_eligible,
      produced: result.proposal.changes.produced,
      patch: result.patch,
      reason: result.proposal.pr_ineligibility_reasons[0],
    }, {
      outcome: "no_change",
      eligible: false,
      produced: false,
      patch: "",
      reason: "No baselined build-input gaps exist for engine sample; provenance is already recorded.",
    });
  } finally {
    setup.cleanup();
  }
});

test("a provenance patch changes only the selected baseline entries, applies, and reduces the passing gap count", async () => {
  const setup = createFixture({
    engineIds: ["selected", "untouched"],
    baselineFilesByEngine: {
      selected: [{
        path: "build.patch",
        content: "selected bytes\n",
        reason: "Applied during the selected image build but absent from the plan.",
      }],
      untouched: [{
        path: "build.patch",
        content: "untouched bytes\n",
        reason: "Applied during the untouched image build but absent from the plan.",
      }],
    },
  });
  const target = mkdtempSync(join(tmpdir(), "upstream-refresh-provenance-apply-"));
  try {
    const result = await refreshEngine({
      root: setup.root,
      engineId: "selected",
      refreshKind: "provenance",
      policy: policy([["selected", "eligible"], ["untouched", "eligible"]]),
      now: fixedNow,
      bundleRoot: setup.bundleRoot,
      verificationRunner: () => passedVerification(),
    });
    cpSync(join(setup.root, "engines"), join(target, "engines"), { recursive: true });
    commit(target, "target baseline");
    const trackedBefore = run("git", ["ls-files", "engines/images"], { cwd: target }).split("\n").filter(Boolean);
    const policyBefore = JSON.parse(readFileSync(join(target, "engines", "image-input-hash-policy.json"), "utf8"));
    const selectedPlanBefore = JSON.parse(readFileSync(join(target, "engines", "images", "selected", "plan.json"), "utf8"));
    const before = validateEngineInputHashes({ root: target, trackedPaths: trackedBefore, policy: policyBefore });
    const check = spawnSync("git", ["apply", "--check", join(result.bundlePath, "changes.patch")], { cwd: target, encoding: "utf8" });
    const apply = spawnSync("git", ["apply", join(result.bundlePath, "changes.patch")], { cwd: target, encoding: "utf8" });
    const policyAfter = JSON.parse(readFileSync(join(target, "engines", "image-input-hash-policy.json"), "utf8"));
    const after = validateEngineInputHashes({ root: target, trackedPaths: trackedBefore, policy: policyAfter });
    const selectedPlan = JSON.parse(readFileSync(join(target, "engines", "images", "selected", "plan.json"), "utf8"));
    const untouchedPlan = JSON.parse(readFileSync(join(target, "engines", "images", "untouched", "plan.json"), "utf8"));
    const selectedPlanWithoutBuildInputs = structuredClone(selectedPlan);
    delete selectedPlanWithoutBuildInputs.build_inputs;
    const policyBeforeWithoutBaseline = structuredClone(policyBefore);
    const policyAfterWithoutBaseline = structuredClone(policyAfter);
    delete policyBeforeWithoutBaseline.uncovered_baseline;
    delete policyAfterWithoutBaseline.uncovered_baseline;
    assert.deepEqual({
      files: result.proposal.changes.files,
      checkStatus: check.status,
      checkError: check.stderr,
      applyStatus: apply.status,
      applyError: apply.stderr,
      beforeErrors: before.errors,
      afterErrors: after.errors,
      beforeGaps: before.records.filter(({ baseline }) => baseline).length,
      afterGaps: after.records.filter(({ baseline }) => baseline).length,
      remainingBaseline: policyAfter.uncovered_baseline,
      selectedInputs: selectedPlan.build_inputs,
      untouchedInputs: untouchedPlan.build_inputs,
      selectedOtherFieldsUnchanged: selectedPlanWithoutBuildInputs,
      policyOtherFieldsUnchanged: policyAfterWithoutBaseline,
    }, {
      files: ["engines/image-input-hash-policy.json", "engines/images/selected/plan.json"],
      checkStatus: 0,
      checkError: "",
      applyStatus: 0,
      applyError: "",
      beforeErrors: [],
      afterErrors: [],
      beforeGaps: 2,
      afterGaps: 1,
      remainingBaseline: [{
        path: "engines/images/untouched/build.patch",
        reason: "Applied during the untouched image build but absent from the plan.",
      }],
      selectedInputs: [{
        path: "engines/images/selected/build.patch",
        sha256: sha256("selected bytes\n"),
        purpose: "Applied during the selected image build.",
      }],
      untouchedInputs: undefined,
      selectedOtherFieldsUnchanged: selectedPlanBefore,
      policyOtherFieldsUnchanged: policyBeforeWithoutBaseline,
    });
  } finally {
    setup.cleanup();
    rmSync(target, { recursive: true, force: true });
  }
});

test("a verification check that could not run is not passed and forces PR ineligibility", async () => {
  const setup = createFixture();
  try {
    const result = await refreshEngine({
      root: setup.root,
      engineId: "sample",
      policy: policy([["sample", "eligible"]]),
      now: fixedNow,
      bundleRoot: setup.bundleRoot,
      verificationRunner: () => passedVerification({
        "validate:engine-line-endings": { status: "not_run", reason: "validator executable unavailable" },
      }),
    });
    const check = result.proposal.verification.find(({ name }) => name === "validate:engine-line-endings");
    assert.deepEqual({
      eligible: result.proposal.pr_eligible,
      status: check.status,
      reason: check.reason,
      eligibilityReason: result.proposal.pr_ineligibility_reasons.at(-1),
    }, {
      eligible: false,
      status: "not_run",
      reason: "validator executable unavailable",
      eligibilityReason: "Verification check validate:engine-line-endings was not run: validator executable unavailable",
    });
  } finally {
    setup.cleanup();
  }
});

test("the cli provider uses an injected double and attributes model edits", async () => {
  const setup = createFixture();
  let calls = 0;
  try {
    const result = await refreshEngine({
      root: setup.root,
      engineId: "sample",
      providerId: "cli",
      policy: policy([["sample", "eligible"]]),
      now: fixedNow,
      bundleRoot: setup.bundleRoot,
      verificationRunner: () => passedVerification(),
      cliRunner: ({ command, input }) => {
        calls += 1;
        return {
          rationale: `Reviewed without spawning ${command ?? "any executable"}; request ${JSON.parse(input).engine}.`,
          edits: [{ path: "engines/images/sample/Dockerfile", content: "FROM scratch\n# model review\n", reason: "Rebased the adapter recipe." }],
        };
      },
    });
    assert.deepEqual({
      calls,
      provider: result.proposal.provider,
      files: result.proposal.changes.files,
      attributionProviders: [...new Set(result.proposal.changes.attributions.map(({ provider }) => provider))],
      reportNamesPath: result.report.includes("optional AI path; the deterministic default path is **mechanical**"),
      reportNamesModelEdits: result.report.includes("### Model-authored edits")
        && result.report.includes("A model wrote these bytes, and a human must read them before they become a PR."),
      reportRecordsDigests: result.report.includes(`before: ${sha256("FROM scratch\n")}; after: ${sha256("FROM scratch\n# model review\n")}`),
    }, {
      calls: 1,
      provider: {
        selected: "cli",
        path_class: "optional_ai",
        status: "completed",
        rationale: "Reviewed without spawning any executable; request sample.",
        model_invoked: true,
      },
      files: ["engines/images/sample/Dockerfile", "engines/images/sample/plan.json"],
      attributionProviders: ["mechanical", "cli"],
      reportNamesPath: true,
      reportNamesModelEdits: true,
      reportRecordsDigests: true,
    });
  } finally {
    setup.cleanup();
  }
});

test("the cli provider reports when it produced no model-authored edit", async () => {
  const setup = createFixture();
  try {
    const result = await refreshEngine({
      root: setup.root,
      engineId: "sample",
      providerId: "cli",
      policy: policy([["sample", "eligible"]]),
      now: fixedNow,
      bundleRoot: setup.bundleRoot,
      verificationRunner: () => passedVerification(),
      cliRunner: () => ({ rationale: "No judgment-dependent edit was needed.", edits: [] }),
    });
    assert.equal(result.report.includes("The optional AI provider produced no model-authored edit of its own."), true);
  } finally {
    setup.cleanup();
  }
});

test("a cli edit to a hash-recorded build input fails input-hash verification and cannot become a PR", async () => {
  const setup = createFixture();
  try {
    commit(setup.root, "fixture root");
    const result = await refreshEngine({
      root: setup.root,
      engineId: "sample",
      providerId: "cli",
      policy: policy([["sample", "eligible"]]),
      now: fixedNow,
      bundleRoot: setup.bundleRoot,
      cliRunner: () => ({
        rationale: "Changed a recorded build input.",
        edits: [{
          path: "engines/images/sample/Dockerfile",
          content: "FROM scratch\n# model-authored input\n",
          reason: "Changed bytes whose digest is recorded in plan.json.",
        }],
      }),
    });
    const hashCheck = result.proposal.verification.find(({ name }) => name === "validate:engine-input-hashes");
    assert.deepEqual({
      checkName: hashCheck.name,
      checkStatus: hashCheck.status,
      eligible: result.proposal.pr_eligible,
      reason: result.proposal.pr_ineligibility_reasons.includes("Verification check validate:engine-input-hashes failed."),
    }, {
      checkName: "validate:engine-input-hashes",
      checkStatus: "failed",
      eligible: false,
      reason: true,
    });
  } finally {
    setup.cleanup();
  }
});

test("a revision patch applies without advancing artifact knowledge or support dates", async () => {
  const setup = createFixture();
  const target = mkdtempSync(join(tmpdir(), "upstream-refresh-apply-"));
  try {
    const result = await refreshEngine({
      root: setup.root,
      engineId: "sample",
      policy: policy([["sample", "eligible"]]),
      now: fixedNow,
      bundleRoot: setup.bundleRoot,
      verificationRunner: () => passedVerification(),
    });
    cpSync(join(setup.root, "engines"), join(target, "engines"), { recursive: true });
    commit(target, "target baseline");
    const applyCheck = spawnSync("git", ["apply", "--check", join(result.bundlePath, "changes.patch")], {
      cwd: target,
      encoding: "utf8",
    });
    const planPath = join(target, "engines", "images", "sample", "plan.json");
    const beforePlan = JSON.parse(readFileSync(planPath, "utf8"));
    run("git", ["apply", join(result.bundlePath, "changes.patch")], { cwd: target });
    const afterPlan = JSON.parse(readFileSync(planPath, "utf8"));
    const proposedPlan = JSON.parse(readFileSync(join(result.bundlePath, "proposal.json")));
    assert.deepEqual({
      applyStatus: applyCheck.status,
      applyError: applyCheck.stderr,
      changedFiles: proposedPlan.changes.files,
      digestUpdated: proposedPlan.changes.attributions.some(({ field }) => field === "build_recipe.dependency_lock.sha256"),
      artifactCoordinate: proposedPlan.inputs.plan.final_artifact_coordinate,
      candidateRevision: afterPlan.source.revision,
      generatedAt: proposedPlan.generated_at,
      knowledgeDate: afterPlan.knowledge_date,
      supportUntil: afterPlan.support_until,
      finalArtifact: afterPlan.final_artifact,
    }, {
      applyStatus: 0,
      applyError: "",
      changedFiles: ["engines/images/sample/plan.json"],
      digestUpdated: true,
      artifactCoordinate: `ghcr.io/example/sample:1.0.0@sha256:${"2".repeat(64)}`,
      candidateRevision: setup.revisions.get("sample").candidate,
      generatedAt: fixedNow.toISOString(),
      knowledgeDate: beforePlan.knowledge_date,
      supportUntil: beforePlan.support_until,
      finalArtifact: beforePlan.final_artifact,
    });
  } finally {
    setup.cleanup();
    rmSync(target, { recursive: true, force: true });
  }
});

test("refresh rejects missing option values instead of silently using defaults", () => {
  for (const option of ["--provider", "--kind", "--engine", "--ai-cli", "--ai-cli-arg"]) {
    assert.throws(
      () => parseRefreshArguments(["--engine", "gitleaks", option]),
      { message: `Missing value for ${option}.` },
    );
    if (option === "--ai-cli-arg") continue;
    for (const next of ["", "--help", "--provider", "--unknown"]) {
      assert.throws(
        () => parseRefreshArguments(["--engine", "gitleaks", option, next]),
        { message: `Missing value for ${option}.` },
      );
    }
  }
});

test("refresh retains intentional defaults and forwards AI CLI argument values literally", () => {
  assert.deepEqual(parseRefreshArguments(["--engine", "gitleaks"]), {
    engineIds: ["gitleaks"], providerId: "mechanical", refreshKind: "revision", cliArgs: [], help: false,
  });
  assert.deepEqual(parseRefreshArguments([
    "--engine", "gitleaks", "--engine", "grype", "--kind", "revision",
    "--provider", "cli", "--ai-cli", "/a path/agent",
    "--ai-cli-arg", "--model", "--ai-cli-arg", "chosen-model",
    "--ai-cli-arg", "--help", "--ai-cli-arg", "",
  ]), {
    engineIds: ["gitleaks", "grype"], providerId: "cli", refreshKind: "revision",
    cliCommand: "/a path/agent", cliArgs: ["--model", "chosen-model", "--help", ""], help: false,
  });
});

test("both upstream refresh CLIs print help and do no work", async () => {
  let refreshOutput = "";
  let proposeOutput = "";
  const refreshStatus = await refreshMain(["--help"], { log(value) { refreshOutput += `${value}\n`; } });
  const proposeStatus = proposeMain(["-h"], { write(value) { proposeOutput += value; } });
  assert.deepEqual({
    refreshStatus,
    proposeStatus,
    refreshOptions: [
      "--engine <id>",
      "--kind {revision,provenance}",
      "--provider {mechanical,cli}",
      "--ai-cli <executable>",
      "--ai-cli-arg <arg>",
    ].every((option) => refreshOutput.includes(option)),
    refreshExplainsPaths: refreshOutput.includes("default deterministic offline path")
      && refreshOutput.includes("optional AI path"),
    proposeOptions: proposeOutput.includes("--open-pr") && proposeOutput.includes("--no-open-pr"),
  }, {
    refreshStatus: 0,
    proposeStatus: 0,
    refreshOptions: true,
    refreshExplainsPaths: true,
    proposeOptions: true,
  });
});

test("upstream:propose records explicit decisions and remains structurally unable to execute commands or use a network", () => {
  const root = mkdtempSync(join(tmpdir(), "upstream-propose-test-"));
  try {
    const makeBundle = (name, provider = { selected: "mechanical", path_class: "formal_default" }, parent = root) => {
      const bundle = join(parent, name);
      mkdirSync(bundle);
      const proposal = {
        generated_at: fixedNow.toISOString(),
        refresh_kind: "revision",
        engine: { id: "sample" },
        provider,
        policy: { status: "eligible" },
        changes: { produced: true, files: ["engines/images/sample/plan.json"] },
        verification: passedVerification(),
        artifacts: [{ path: "changes.patch", sha256: sha256("diff --git a/file b/file\n") }],
        pr_eligible: true,
      };
      writeFileSync(join(bundle, "proposal.json"), `${JSON.stringify(proposal)}\n`);
      writeFileSync(join(bundle, "changes.patch"), "diff --git a/file b/file\n");
      writeFileSync(join(bundle, "report.md"), "# Review\n");
      return bundle;
    };
    const undecidedBundle = makeBundle("undecided");
    const openBundle = makeBundle("open");
    const localBundle = makeBundle("keep-local", { selected: "cli", path_class: "optional_ai" });
    let undecidedOutput = "";
    let openOutput = "";
    let localOutput = "";
    const undecidedStatus = proposeMain(["--bundle", undecidedBundle], { write(value) { undecidedOutput += value; } });
    const openStatus = proposeMain(["--open-pr", "--bundle", openBundle], { write(value) { openOutput += value; } });
    const localStatus = proposeMain(["--bundle", localBundle, "--no-open-pr"], { write(value) { localOutput += value; } });
    const openDecision = JSON.parse(readFileSync(join(openBundle, "pr-decision.json"), "utf8"));
    const localDecision = JSON.parse(readFileSync(join(localBundle, "pr-decision.json"), "utf8"));
    const entrySource = readFileSync(join(repositoryRoot, "scripts", "upstream-propose.mjs"), "utf8");
    const librarySource = readFileSync(join(repositoryRoot, "scripts", "upstream-propose-lib.mjs"), "utf8");
    const libraryImports = [...librarySource.matchAll(/^import .* from "([^"]+)";/gm)].map((match) => match[1]);
    const commandLines = (output) => output.split("\n").filter((line) => /^(?:git|gh) /.test(line));
    const fsMutatingCalls = (source) => [...source.matchAll(/\b(?:writeFile(?:Sync)?|appendFile(?:Sync)?|rmSync|unlinkSync|renameSync|mkdirSync|cpSync|chmodSync|openSync)\s*\(/g)].map((match) => match[0]);
    const forbiddenFs = /appendFile|rmSync|unlinkSync|renameSync|mkdirSync|cpSync|chmodSync|openSync/;
    const lastCommandBlockLine = (output) => output.split("\n").reduce((index, line, current) => (
      line.startsWith("Exact commands (not executed):") || /^(?:git|gh) /.test(line) || line.startsWith("Commands: none")
        ? current
        : index
    ), -1);
    const recordLineIndex = (output) => output.split("\n").findIndex((line) => line.startsWith("PR decision record:"));
    const openRecordPath = resolve(openBundle, "pr-decision.json");
    const localRecordPath = resolve(localBundle, "pr-decision.json");
    assert.deepEqual({
      statuses: [undecidedStatus, openStatus, localStatus],
      providerFirst: undecidedOutput.startsWith("Provider: mechanical (default deterministic path)\n")
        && localOutput.startsWith("Provider: cli (optional AI path)\n"),
      decisionsNamed: undecidedOutput.includes("PR decision: undecided")
        && openOutput.includes("PR decision: open")
        && localOutput.includes("PR decision: keep-local"),
      commandCounts: [commandLines(undecidedOutput).length, commandLines(openOutput).length, commandLines(localOutput).length],
      undecidedHasNoRemoteCommands: !undecidedOutput.includes("git push") && !undecidedOutput.includes("gh pr create"),
      undecidedNamesChoices: undecidedOutput.includes("re-run with --open-pr") && undecidedOutput.includes("re-run with --no-open-pr"),
      localHasNoRemoteCommands: !localOutput.includes("git push") && !localOutput.includes("gh pr create"),
      localExplainsChoice: localOutput.includes("because the client chose to keep the change local"),
      openPrintsRemoteCommands: openOutput.includes("git push -u origin") && openOutput.includes("gh pr create --fill --head"),
      undecidedFiles: readdirSync(undecidedBundle).sort(),
      openRecord: {
        decision: openDecision.decision,
        engine: openDecision.engine,
        kind: openDecision.refresh_kind,
        provider: openDecision.provider,
        eligible: openDecision.pr_eligible,
        proposalDigest: openDecision.bundle.proposal.sha256,
        patchDigest: openDecision.bundle.patch.sha256,
        commands: openDecision.commands_printed,
      },
      localRecordCommands: localDecision.commands_printed,
      undecidedRecordLines: undecidedOutput.split("\n").filter((line) => line.startsWith("PR decision record:")),
      openRecordLine: openOutput.split("\n").filter((line) => line.startsWith("PR decision record:")),
      localRecordLine: localOutput.split("\n").filter((line) => line.startsWith("PR decision record:")),
      openRecordAfterCommands: recordLineIndex(openOutput) > lastCommandBlockLine(openOutput),
      localRecordAfterCommands: recordLineIndex(localOutput) > lastCommandBlockLine(localOutput),
      libraryImports,
      libraryMutatingCalls: fsMutatingCalls(librarySource),
      libraryWriteDestination: librarySource.match(/\bwriteFileSync\s*\(\s*(resolve\(result\.directory,\s*"pr-decision\.json"\))/)?.[1] ?? null,
      libraryForbiddenFs: forbiddenFs.test(librarySource),
      entryMutatingCalls: fsMutatingCalls(entrySource),
      entryForbiddenFs: forbiddenFs.test(entrySource),
      importsProcessOrNetwork: /node:(?:child_process|http|https|net)|\bfetch\s*\(|\bimport\s*\(/.test(`${entrySource}\n${librarySource}`),
    }, {
      statuses: [0, 0, 0],
      providerFirst: true,
      decisionsNamed: true,
      commandCounts: [5, 7, 5],
      undecidedHasNoRemoteCommands: true,
      undecidedNamesChoices: true,
      localHasNoRemoteCommands: true,
      localExplainsChoice: true,
      openPrintsRemoteCommands: true,
      undecidedFiles: ["changes.patch", "proposal.json", "report.md"],
      openRecord: {
        decision: "open",
        engine: "sample",
        kind: "revision",
        provider: { id: "mechanical", path_class: "formal_default" },
        eligible: true,
        proposalDigest: sha256(readFileSync(join(openBundle, "proposal.json"))),
        patchDigest: sha256("diff --git a/file b/file\n"),
        commands: commandLines(openOutput),
      },
      localRecordCommands: commandLines(localOutput),
      undecidedRecordLines: [],
      openRecordLine: [`PR decision record: ${openRecordPath}`],
      localRecordLine: [`PR decision record: ${localRecordPath}`],
      openRecordAfterCommands: true,
      localRecordAfterCommands: true,
      libraryImports: ["node:crypto", "node:fs", "node:path"],
      libraryMutatingCalls: ["writeFileSync("],
      libraryWriteDestination: "resolve(result.directory, \"pr-decision.json\")",
      libraryForbiddenFs: false,
      entryMutatingCalls: [],
      entryForbiddenFs: false,
      importsProcessOrNetwork: false,
    });
    const parent = join(root, "write-parent");
    mkdirSync(parent);
    const scopedBundle = makeBundle("bundle", undefined, parent);
    const parentEntries = readdirSync(parent).sort();
    const bundleEntries = readdirSync(scopedBundle).sort();
    proposeMain(["--bundle", join(scopedBundle, "proposal.json"), "--open-pr"], { write() {} });
    assert.deepEqual({
      parentEntriesAfter: readdirSync(parent).sort(),
      bundleAdded: readdirSync(scopedBundle).filter((name) => !bundleEntries.includes(name)).sort(),
      bundleRemoved: bundleEntries.filter((name) => !readdirSync(scopedBundle).includes(name)),
    }, {
      parentEntriesAfter: parentEntries,
      bundleAdded: ["pr-decision.json"],
      bundleRemoved: [],
    });
    assert.throws(
      () => proposeMain(["--no-open-pr", "--bundle", undecidedBundle, "--open-pr"], { write() {} }),
      { message: "Choose either --open-pr or --no-open-pr, not both." },
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("upstream:propose refuses drifted or unrecognized outcomes instead of treating them as no_change", () => {
  const root = mkdtempSync(join(tmpdir(), "upstream-propose-outcome-"));
  try {
    const makeBundle = (name, overrides) => {
      const bundle = join(root, name);
      mkdirSync(bundle);
      const patch = "diff --git a/file b/file\n";
      const proposal = {
        generated_at: fixedNow.toISOString(),
        refresh_kind: "revision",
        engine: { id: "sample" },
        provider: { selected: "mechanical", path_class: "formal_default" },
        policy: { status: "eligible" },
        changes: { produced: true, files: ["engines/images/sample/plan.json"] },
        verification: passedVerification(),
        artifacts: [{ path: "changes.patch", sha256: sha256(patch) }],
        pr_eligible: true,
        ...overrides,
      };
      writeFileSync(join(bundle, "proposal.json"), `${JSON.stringify(proposal)}\n`);
      writeFileSync(join(bundle, "changes.patch"), patch);
      writeFileSync(join(bundle, "report.md"), "# Review\n");
      return bundle;
    };
    const captured = [];
    for (const [name, overrides] of [
      ["no-change", { outcome: "no_change", pr_eligible: false, changes: { produced: false, files: [] } }],
      ["detected", {
        outcome: "drift_detected_but_no_proposal",
        pr_eligible: true,
        changes: { produced: false, files: [] },
      }],
      ["unavailable", {
        outcome: "drift_unavailable",
        pr_eligible: true,
        changes: { produced: false, files: [] },
      }],
      ["unrecognized", { outcome: "surprise", pr_eligible: true }],
    ]) {
      let stdout = "";
      const status = proposeMain(["--bundle", makeBundle(name, overrides), "--open-pr"], {
        write(value) { stdout += value; },
      });
      captured.push({
        name,
        status,
        eligible: stdout.includes("PR eligible: yes\n"),
        reasons: stdout.split("\n").filter((line) => line.startsWith("- ")).map((line) => line.slice(2)),
      });
    }
    assert.deepEqual(captured.map(({ name, status, eligible }) => ({ name, status, eligible })), [
      { name: "no-change", status: 1, eligible: false },
      { name: "detected", status: 1, eligible: false },
      { name: "unavailable", status: 1, eligible: false },
      { name: "unrecognized", status: 1, eligible: false },
    ]);
    assert.equal(captured[0].reasons.includes("The refresh reported no adapter change."), true);
    assert.equal(
      captured[1].reasons.includes("Upstream drift was detected but no adapter change was produced; this bundle may not become a PR."),
      true,
    );
    assert.equal(
      captured[2].reasons.includes("Offline drift could not be inspected; this bundle may not become a PR."),
      true,
    );
    assert.equal(
      captured[3].reasons.includes("Unrecognized proposal outcome surprise; refusing the PR."),
      true,
    );
    assert.equal(captured[1].reasons.includes("The refresh reported no adapter change."), false);
    assert.equal(captured[2].reasons.includes("The refresh reported no adapter change."), false);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("upstream:propose reports an unwritable decision record without changing the eligibility exit code", () => {
  const root = mkdtempSync(join(tmpdir(), "upstream-propose-read-only-"));
  const bundle = join(root, "bundle");
  try {
    mkdirSync(bundle);
    const patch = "diff --git a/file b/file\n";
    const proposal = {
      generated_at: fixedNow.toISOString(),
      refresh_kind: "revision",
      engine: { id: "sample" },
      provider: { selected: "mechanical", path_class: "formal_default" },
      policy: { status: "eligible" },
      changes: { produced: true, files: ["engines/images/sample/plan.json"] },
      verification: passedVerification(),
      artifacts: [{ path: "changes.patch", sha256: sha256(patch) }],
      pr_eligible: true,
    };
    writeFileSync(join(bundle, "proposal.json"), `${JSON.stringify(proposal)}\n`);
    writeFileSync(join(bundle, "changes.patch"), patch);
    writeFileSync(join(bundle, "report.md"), "# Review\n");
    chmodSync(bundle, 0o555);
    let stdout = "";
    const status = proposeMain(["--bundle", bundle, "--no-open-pr"], { write(value) { stdout += value; } });
    assert.deepEqual({
      status,
      reportsFailure: stdout.includes("PR decision record: not written"),
      decisionFileExists: readdirSync(bundle).includes("pr-decision.json"),
    }, {
      status: 0,
      reportsFailure: true,
      decisionFileExists: false,
    });
  } finally {
    chmodSync(bundle, 0o755);
    rmSync(root, { recursive: true, force: true });
  }
});
