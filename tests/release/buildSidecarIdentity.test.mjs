import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import { RECIPE, RUST_VERSION } from "../../scripts/skill/bootstrap-core.mjs";
import { collectInputManifest } from "../../scripts/skill/input-manifest.mjs";
import { PROJECT_ROOT } from "../../scripts/release/lib.mjs";
import {
  buildTargetsFor,
  canRunBuildTargetOnHost,
  cargoBuildEnvironment,
  expectedCliFeatures,
  resolveBootstrapIdentity,
  runnableTargetForHost,
  validateCliBuildIdentity,
  verifyBuiltCliIdentity,
} from "../../scripts/release/build-sidecar.mjs";

const SAMPLE_DIGEST = "a".repeat(64);
const OTHER_DIGEST = "b".repeat(64);

function sampleIdentity(overrides = {}) {
  return {
    schema_version: "ai-security-scanner.build-identity/v1",
    product: "ai-security-scanner",
    product_version: "0.6.2",
    target: "x86_64-unknown-linux-gnu",
    rustc_version: "rustc 1.98.0\nhost: x86_64-unknown-linux-gnu",
    features: ["cli"],
    report_source_sha256: "c".repeat(64),
    bootstrap_input_sha256: SAMPLE_DIGEST,
    bootstrap_recipe: RECIPE,
    ...overrides,
  };
}

function sampleExpected(overrides = {}) {
  return {
    target: "x86_64-unknown-linux-gnu",
    features: ["cli"],
    bootstrap_input_sha256: SAMPLE_DIGEST,
    bootstrap_recipe: RECIPE,
    ...overrides,
  };
}

test("validateCliBuildIdentity accepts matching Linux/macOS and Windows CLI identities", () => {
  const linuxIdentity = sampleIdentity();
  assert.equal(validateCliBuildIdentity(linuxIdentity, sampleExpected()), linuxIdentity);

  const windowsIdentity = sampleIdentity({
    target: "x86_64-pc-windows-msvc",
    features: ["cli", "installer-runtime-cache"],
  });
  const windowsExpected = sampleExpected({
    target: "x86_64-pc-windows-msvc",
    features: expectedCliFeatures("x86_64-pc-windows-msvc"),
  });
  assert.equal(validateCliBuildIdentity(windowsIdentity, windowsExpected), windowsIdentity);
});

test("validateCliBuildIdentity rejects each single mismatch or null field with a message naming the field", () => {
  const cases = [
    ["bootstrap_input_sha256", { bootstrap_input_sha256: OTHER_DIGEST }],
    ["bootstrap_input_sha256", { bootstrap_input_sha256: null }],
    ["bootstrap_recipe", { bootstrap_recipe: "skill-bootstrap-v0" }],
    ["bootstrap_recipe", { bootstrap_recipe: null }],
    ["target", { target: "aarch64-unknown-linux-gnu" }],
    ["target", { target: null }],
    ["features", { features: ["cli", "desktop"] }],
    ["features", { features: [] }],
    ["features", { features: null }],
    ["schema_version", { schema_version: null }],
    ["product", { product: null }],
  ];
  for (const [field, override] of cases) {
    assert.throws(
      () => validateCliBuildIdentity(sampleIdentity(override), sampleExpected()),
      (error) => {
        assert.ok(error instanceof Error);
        assert.match(error.message, new RegExp(field, "u"));
        return true;
      },
      `expected failure naming ${field}`,
    );
  }

  assert.throws(
    () =>
      validateCliBuildIdentity(
        sampleIdentity({ target: "x86_64-pc-windows-msvc", features: ["cli"] }),
        sampleExpected({
          target: "x86_64-pc-windows-msvc",
          features: expectedCliFeatures("x86_64-pc-windows-msvc"),
        }),
      ),
    /features/u,
  );
});

test("host-to-target mapping covers explicit hosts, universal macOS thin builds, and non-runnable targets", () => {
  assert.equal(runnableTargetForHost("linux", "x64"), "x86_64-unknown-linux-gnu");
  assert.equal(runnableTargetForHost("linux", "arm64"), "aarch64-unknown-linux-gnu");
  assert.equal(runnableTargetForHost("darwin", "x64"), "x86_64-apple-darwin");
  assert.equal(runnableTargetForHost("darwin", "arm64"), "aarch64-apple-darwin");
  assert.equal(runnableTargetForHost("win32", "x64"), "x86_64-pc-windows-msvc");
  assert.equal(runnableTargetForHost("freebsd", "x64"), null);

  assert.equal(canRunBuildTargetOnHost("x86_64-unknown-linux-gnu", "linux", "x64"), true);
  assert.equal(canRunBuildTargetOnHost("aarch64-unknown-linux-gnu", "linux", "x64"), false);
  assert.equal(canRunBuildTargetOnHost("x86_64-pc-windows-gnu", "win32", "x64"), false);

  assert.deepEqual(buildTargetsFor("universal-apple-darwin"), [
    "x86_64-apple-darwin",
    "aarch64-apple-darwin",
  ]);
  assert.deepEqual(buildTargetsFor("x86_64-unknown-linux-gnu"), ["x86_64-unknown-linux-gnu"]);

  for (const [hostArch, checkedTarget, skippedTarget] of [
    ["arm64", "aarch64-apple-darwin", "x86_64-apple-darwin"],
    ["x64", "x86_64-apple-darwin", "aarch64-apple-darwin"],
  ]) {
    const logs = [];
    const executed = [];
    for (const thinTarget of buildTargetsFor("universal-apple-darwin")) {
      verifyBuiltCliIdentity({
        binary: { name: "ai-security-scanner-cli", feature: "cli" },
        buildTarget: thinTarget,
        bootstrapIdentity: { inputDigest: SAMPLE_DIGEST, recipe: RECIPE },
        platform: "darwin",
        arch: hostArch,
        runIdentityCommand: (executable, args) => {
          executed.push({ executable, args });
          return JSON.stringify(sampleIdentity({ target: thinTarget, features: ["cli"] }));
        },
        log: (line) => logs.push(line),
      });
    }
    assert.equal(executed.length, 1);
    assert.deepEqual(executed[0].args, ["--json", "build-identity"]);
    assert.equal(logs.length, 2);
    assert.match(
      logs.find((line) => line.includes(`for ${skippedTarget}:`)) ?? "",
      /^Skipped CLI build-identity verification/u,
    );
    assert.match(
      logs.find((line) => line.includes(`for ${checkedTarget}:`)) ?? "",
      /^Verified CLI build identity/u,
    );
  }

  const crossLogs = [];
  let crossRan = false;
  const crossResult = verifyBuiltCliIdentity({
    binary: { name: "ai-security-scanner-cli", feature: "cli" },
    buildTarget: "aarch64-unknown-linux-gnu",
    bootstrapIdentity: { inputDigest: SAMPLE_DIGEST, recipe: RECIPE },
    platform: "linux",
    arch: "x64",
    runIdentityCommand: () => {
      crossRan = true;
      return "{}";
    },
    log: (line) => crossLogs.push(line),
  });
  assert.equal(crossRan, false);
  assert.equal(crossResult.verified, false);
  assert.equal(crossLogs.length, 1);
  assert.match(crossLogs[0], /Skipped.*aarch64-unknown-linux-gnu/u);

  assert.throws(
    () =>
      verifyBuiltCliIdentity({
        binary: { name: "ai-security-scanner-cli", feature: "cli" },
        buildTarget: "x86_64-unknown-linux-gnu",
        bootstrapIdentity: { inputDigest: SAMPLE_DIGEST, recipe: RECIPE },
        platform: "linux",
        arch: "x64",
        runIdentityCommand: () =>
          JSON.stringify(sampleIdentity({ bootstrap_input_sha256: null })),
        log: () => {},
      }),
    /bootstrap_input_sha256/u,
  );
});

test("cargoBuildEnvironment passes checkout digest and RECIPE only to the CLI build", async (t) => {
  const manifest = await collectInputManifest(PROJECT_ROOT);
  const resolved = await resolveBootstrapIdentity(PROJECT_ROOT);
  assert.deepEqual(resolved, { inputDigest: manifest.inputDigest, recipe: RECIPE });

  const baseEnv = {
    PATH: "/usr/bin",
    AI_SECURITY_SCANNER_BOOTSTRAP_INPUT_SHA256: OTHER_DIGEST,
    AI_SECURITY_SCANNER_BOOTSTRAP_RECIPE: "stale-recipe",
  };
  const cliEnv = cargoBuildEnvironment("ai-security-scanner-cli", resolved, baseEnv);
  assert.equal(cliEnv.PATH, "/usr/bin");
  assert.equal(cliEnv.AI_SECURITY_SCANNER_BOOTSTRAP_INPUT_SHA256, manifest.inputDigest);
  assert.equal(cliEnv.AI_SECURITY_SCANNER_BOOTSTRAP_RECIPE, RECIPE);

  for (const nonCliBinary of [
    "ai-security-scanner-egress-gateway",
    "ai-security-scanner-bootstrap-broker",
  ]) {
    const env = cargoBuildEnvironment(nonCliBinary, resolved, baseEnv);
    assert.equal(env.PATH, "/usr/bin");
    assert.equal("AI_SECURITY_SCANNER_BOOTSTRAP_INPUT_SHA256" in env, false);
    assert.equal("AI_SECURITY_SCANNER_BOOTSTRAP_RECIPE" in env, false);
  }

  const forbiddenRoot = await mkdtemp(path.join(tmpdir(), "sidecar-forbidden-cargo-"));
  t.after(() => rm(forbiddenRoot, { recursive: true, force: true }));
  await mkdir(path.join(forbiddenRoot, ".cargo"));
  await assert.rejects(
    () => resolveBootstrapIdentity(forbiddenRoot),
    /source-controlled Cargo configuration requires recipe review: \.cargo/u,
  );
});

test("the release workflow builds with the Rust version the skill bootstrap accepts", async () => {
  // The bootstrap accepts a prebuilt core only when its compiler line names this version, so a
  // release built with another toolchain could never be pinned.
  const workflow = await readFile(path.join(PROJECT_ROOT, ".github/workflows/release.yml"), "utf8");
  const pins = [...workflow.matchAll(/^\s*toolchain:\s*(\S+)\s*$/gmu)].map((match) => match[1]);
  assert.ok(pins.length > 0, "release.yml pins no Rust toolchain");
  assert.deepEqual([...new Set(pins)], [RUST_VERSION]);
});
