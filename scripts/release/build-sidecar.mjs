import { execFileSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { RECIPE } from "../skill/bootstrap-core.mjs";
import { collectInputManifest } from "../skill/input-manifest.mjs";
import { PROJECT_ROOT, parseArgs, requireString, runMain } from "./lib.mjs";

const CLI_BINARY = "ai-security-scanner-cli";
const BUILD_IDENTITY_SCHEMA = "ai-security-scanner.build-identity/v1";
const SHA256_RE = /^[a-f0-9]{64}$/u;
const BINARIES = Object.freeze([
  Object.freeze({ name: "ai-security-scanner-egress-gateway", feature: "egress-gateway" }),
  Object.freeze({ name: "ai-security-scanner-bootstrap-broker", feature: "broker" }),
  Object.freeze({ name: CLI_BINARY, feature: "cli" }),
]);
const SUPPORTED_TARGETS = new Set([
  "x86_64-unknown-linux-gnu",
  "aarch64-unknown-linux-gnu",
  "x86_64-apple-darwin",
  "aarch64-apple-darwin",
  "universal-apple-darwin",
  "x86_64-pc-windows-msvc",
  "x86_64-pc-windows-gnu",
]);
const RUNNABLE_HOST_TARGETS = new Map([
  ["linux:x64", "x86_64-unknown-linux-gnu"],
  ["linux:arm64", "aarch64-unknown-linux-gnu"],
  ["darwin:x64", "x86_64-apple-darwin"],
  ["darwin:arm64", "aarch64-apple-darwin"],
  ["win32:x64", "x86_64-pc-windows-msvc"],
]);

/** Return the single Rust target triple that executes natively on this host, or null. */
export function runnableTargetForHost(platform = process.platform, arch = process.arch) {
  return RUNNABLE_HOST_TARGETS.get(`${platform}:${arch}`) ?? null;
}

/** Expand universal macOS targets into the thin Rust targets Cargo builds. */
export function buildTargetsFor(target) {
  return target === "universal-apple-darwin"
    ? ["x86_64-apple-darwin", "aarch64-apple-darwin"]
    : [target];
}

/** Report whether a single Cargo build target can run directly on the given host. */
export function canRunBuildTargetOnHost(
  buildTarget,
  platform = process.platform,
  arch = process.arch,
) {
  return runnableTargetForHost(platform, arch) === buildTarget;
}

/** Return the Cargo feature list expected from `build-identity` for a CLI target. */
export function expectedCliFeatures(target) {
  if (typeof target !== "string" || target.length === 0) {
    throw new Error("target is required");
  }
  return target.includes("windows") ? ["cli", "installer-runtime-cache"] : ["cli"];
}

/** Compute the checkout bootstrap identity once using the skill input manifest and recipe. */
export async function resolveBootstrapIdentity(sourceRoot = PROJECT_ROOT) {
  const manifest = await collectInputManifest(sourceRoot);
  return { inputDigest: manifest.inputDigest, recipe: RECIPE };
}

/**
 * Build the Cargo environment for one sidecar binary.
 * Only the CLI consumes and reports the bootstrap identity; leaving the vars unset
 * for egress-gateway and bootstrap-broker avoids needless Cargo rebuilds across feature sets.
 */
export function cargoBuildEnvironment(binaryName, bootstrapIdentity, baseEnv = process.env) {
  const env = { ...baseEnv };
  if (binaryName === CLI_BINARY) {
    if (
      typeof bootstrapIdentity?.inputDigest !== "string" ||
      !SHA256_RE.test(bootstrapIdentity.inputDigest)
    ) {
      throw new Error("CLI build requires a valid 64-character SHA-256 bootstrap input digest");
    }
    if (typeof bootstrapIdentity?.recipe !== "string" || bootstrapIdentity.recipe.length === 0) {
      throw new Error("CLI build requires a non-empty bootstrap recipe");
    }
    env.AI_SECURITY_SCANNER_BOOTSTRAP_INPUT_SHA256 = bootstrapIdentity.inputDigest;
    env.AI_SECURITY_SCANNER_BOOTSTRAP_RECIPE = bootstrapIdentity.recipe;
  } else {
    delete env.AI_SECURITY_SCANNER_BOOTSTRAP_INPUT_SHA256;
    delete env.AI_SECURITY_SCANNER_BOOTSTRAP_RECIPE;
  }
  return env;
}

/** Verify that a parsed `--json build-identity` payload matches the expected CLI build. */
export function validateCliBuildIdentity(identity, expected) {
  if (!identity || typeof identity !== "object" || Array.isArray(identity)) {
    throw new Error("CLI build identity must be a JSON object");
  }
  if (identity.schema_version !== BUILD_IDENTITY_SCHEMA) {
    throw new Error(
      `CLI build identity schema_version mismatch: expected ${BUILD_IDENTITY_SCHEMA}, got ${JSON.stringify(identity.schema_version ?? null)}`,
    );
  }
  if (identity.product !== "ai-security-scanner") {
    throw new Error(
      `CLI build identity product mismatch: expected ai-security-scanner, got ${JSON.stringify(identity.product ?? null)}`,
    );
  }
  if (
    typeof expected?.bootstrap_input_sha256 !== "string" ||
    !SHA256_RE.test(expected.bootstrap_input_sha256)
  ) {
    throw new Error("expected bootstrap_input_sha256 must be a 64-character lowercase SHA-256 hex digest");
  }
  if (
    typeof identity.bootstrap_input_sha256 !== "string" ||
    identity.bootstrap_input_sha256 !== expected.bootstrap_input_sha256
  ) {
    throw new Error(
      `CLI build identity bootstrap_input_sha256 mismatch: expected ${expected.bootstrap_input_sha256}, got ${JSON.stringify(identity.bootstrap_input_sha256 ?? null)}`,
    );
  }
  if (typeof expected?.bootstrap_recipe !== "string" || expected.bootstrap_recipe.length === 0) {
    throw new Error("expected bootstrap_recipe must be a non-empty string");
  }
  if (
    typeof identity.bootstrap_recipe !== "string" ||
    identity.bootstrap_recipe !== expected.bootstrap_recipe
  ) {
    throw new Error(
      `CLI build identity bootstrap_recipe mismatch: expected ${expected.bootstrap_recipe}, got ${JSON.stringify(identity.bootstrap_recipe ?? null)}`,
    );
  }
  if (typeof expected?.target !== "string" || expected.target.length === 0) {
    throw new Error("expected target must be a non-empty string");
  }
  if (typeof identity.target !== "string" || identity.target !== expected.target) {
    throw new Error(
      `CLI build identity target mismatch: expected ${expected.target}, got ${JSON.stringify(identity.target ?? null)}`,
    );
  }
  if (!Array.isArray(expected?.features) || expected.features.length === 0) {
    throw new Error("expected features must be a non-empty array");
  }
  if (
    !Array.isArray(identity.features) ||
    identity.features.some((feature) => typeof feature !== "string" || feature.length === 0) ||
    new Set(identity.features).size !== identity.features.length
  ) {
    throw new Error(
      `CLI build identity features mismatch: expected ${JSON.stringify(expected.features)}, got ${JSON.stringify(identity.features ?? null)}`,
    );
  }
  const actualFeatures = [...identity.features].sort();
  const expectedFeatures = [...expected.features].sort();
  if (
    actualFeatures.length !== expectedFeatures.length ||
    actualFeatures.some((feature, index) => feature !== expectedFeatures[index])
  ) {
    throw new Error(
      `CLI build identity features mismatch: expected ${JSON.stringify(expectedFeatures)}, got ${JSON.stringify(actualFeatures)}`,
    );
  }
  return identity;
}

function defaultRunIdentityCommand(executable, args) {
  return execFileSync(executable, args, {
    cwd: PROJECT_ROOT,
    encoding: "utf8",
    maxBuffer: 1024 * 1024,
    timeout: 30_000,
  });
}

/** Verify a built CLI executable on runnable hosts, or log one line and skip non-runnable targets. */
export function verifyBuiltCliIdentity({
  binary,
  buildTarget,
  bootstrapIdentity,
  platform = process.platform,
  arch = process.arch,
  runIdentityCommand = defaultRunIdentityCommand,
  log = (line) => process.stdout.write(`${line}\n`),
}) {
  const runnable = runnableTargetForHost(platform, arch);
  if (runnable !== buildTarget) {
    log(
      `Skipped CLI build-identity verification for ${buildTarget}: host ${platform}/${arch} runs ${runnable ?? "none"}`,
    );
    return { verified: false, target: buildTarget };
  }
  const executable = binaryPath(binary, buildTarget);
  let stdout;
  try {
    stdout = runIdentityCommand(executable, ["--json", "build-identity"]);
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    throw new Error(`CLI build-identity execution failed for ${buildTarget}: ${detail}`);
  }
  let identity;
  try {
    identity = JSON.parse(stdout);
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    throw new Error(`CLI build-identity returned invalid JSON for ${buildTarget}: ${detail}`);
  }
  validateCliBuildIdentity(identity, {
    target: buildTarget,
    features: expectedCliFeatures(buildTarget),
    bootstrap_input_sha256: bootstrapIdentity.inputDigest,
    bootstrap_recipe: bootstrapIdentity.recipe,
  });
  log(
    `Verified CLI build identity for ${buildTarget}: recipe=${identity.bootstrap_recipe} input=${identity.bootstrap_input_sha256} features=${identity.features.join(",")}`,
  );
  return { verified: true, target: buildTarget, identity };
}

function cargoBuild(binary, target, bootstrapIdentity) {
  const cargo = process.env.CARGO || "cargo";
  const features = binary.name === "ai-security-scanner-cli" && target.includes("windows")
    ? `${binary.feature},installer-runtime-cache`
    : binary.feature;
  execFileSync(
    cargo,
    [
      "build",
      "--locked",
      "--release",
      "--package",
      "ai-security-scanner",
      "--no-default-features",
      "--features",
      features,
      "--bin",
      binary.name,
      "--target",
      target,
    ],
    {
      cwd: PROJECT_ROOT,
      env: cargoBuildEnvironment(binary.name, bootstrapIdentity, process.env),
      stdio: "inherit",
    },
  );
}

function binaryPath(binary, target) {
  const extension = target.includes("windows") ? ".exe" : "";
  return path.join(PROJECT_ROOT, "target", target, "release", `${binary.name}${extension}`);
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const target = requireString(args, "target");
  if (!SUPPORTED_TARGETS.has(target)) {
    throw new Error(`unsupported sidecar target: ${target}`);
  }
  const bootstrapIdentity = await resolveBootstrapIdentity(PROJECT_ROOT);
  const stage = path.join(PROJECT_ROOT, "scripts/release/stage-sidecar.mjs");
  for (const binary of BINARIES) {
    if (target === "universal-apple-darwin") {
      const thinTargets = buildTargetsFor(target);
      for (const thinTarget of thinTargets) {
        cargoBuild(binary, thinTarget, bootstrapIdentity);
        if (binary.name === CLI_BINARY) {
          verifyBuiltCliIdentity({ binary, buildTarget: thinTarget, bootstrapIdentity });
        }
      }
      for (const thinTarget of thinTargets) {
        execFileSync(
          process.execPath,
          [
            stage,
            "--binary",
            binary.name,
            "--target",
            thinTarget,
            "--source",
            binaryPath(binary, thinTarget),
          ],
          { cwd: PROJECT_ROOT, stdio: "inherit" },
        );
      }
      execFileSync(
        process.execPath,
        [
          stage,
          "--binary",
          binary.name,
          "--target",
          target,
          "--source-x86",
          binaryPath(binary, "x86_64-apple-darwin"),
          "--source-arm",
          binaryPath(binary, "aarch64-apple-darwin"),
        ],
        { cwd: PROJECT_ROOT, stdio: "inherit" },
      );
    } else {
      cargoBuild(binary, target, bootstrapIdentity);
      if (binary.name === CLI_BINARY) {
        verifyBuiltCliIdentity({ binary, buildTarget: target, bootstrapIdentity });
      }
      execFileSync(
        process.execPath,
        [
          stage,
          "--binary",
          binary.name,
          "--target",
          target,
          "--source",
          binaryPath(binary, target),
        ],
        { cwd: PROJECT_ROOT, stdio: "inherit" },
      );
    }
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  runMain(main);
}
