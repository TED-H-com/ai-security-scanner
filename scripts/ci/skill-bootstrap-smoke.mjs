#!/usr/bin/env node

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../../", import.meta.url));
const args = process.argv.slice(2);
assert.ok(new Set(args).size === args.length && args.every(argument => ["--allow-dirty", "--offline", "--release"].includes(argument)),
  "Usage: node scripts/ci/skill-bootstrap-smoke.mjs [--allow-dirty] [--offline] [--release]");

function invoke(program, parameters) {
  const result = spawnSync(program, parameters, {
    cwd: root, encoding: "utf8", stdio: ["ignore", "pipe", "inherit"],
    timeout: 30 * 60 * 1000, maxBuffer: 4 * 1024 * 1024,
  });
  if (result.error) throw result.error;
  assert.equal(result.status, 0, `${program} failed (${result.signal ?? result.status})`);
  return result.stdout.trim();
}

const revision = invoke("git", ["rev-parse", "HEAD"]);
assert.match(revision, /^[a-f\d]{40}$/u);
const scratch = realpathSync(mkdtempSync(join(tmpdir(), "scanner-native-bootstrap-")));
try {
  const cache = join(scratch, "cache");
  const data = join(scratch, "must-not-be-created");
  const base = [resolve(root, "scripts/skill/bootstrap.mjs")];
  const options = ["--revision", revision, "--cache-dir", cache,
    ...(args.includes("--release") ? [] : ["--profile", "dev"]),
    "--capability", "core", ...args.filter(argument => argument !== "--release")];
  const first = JSON.parse(invoke(process.execPath, [...base, "prepare", ...options]));
  const second = JSON.parse(invoke(process.execPath, [...base, "prepare", ...options]));
  assert.equal(first.schema_version, "ai-security-scanner.bootstrap-result/v1");
  assert.equal(first.cache_hit, false, "the isolated cache must start empty");
  assert.equal(second.cache_hit, true, "the second prepare must reuse the verified cache");
  assert.equal(second.cache_key, first.cache_key);
  assert.deepEqual(second.receipt.artifacts, first.receipt.artifacts);
  const identity = JSON.parse(invoke(process.execPath, [...base, "run", ...options, "--",
    "--data-dir", data, "--json", "build-identity"]));
  assert.equal(identity.schema_version, "ai-security-scanner.build-identity/v1");
  assert.ok(identity.features.includes("cli"));
  assert.ok(!identity.features.includes("desktop"));
  assert.ok(!identity.features.includes("installer-runtime-cache"));
  assert.equal(identity.target, second.receipt.build_identity.target);
  assert.equal(existsSync(data), false, "build identity must not initialize product data");
  const fixtureData = join(scratch, "synthetic-cases");
  const cli = (...parameters) => JSON.parse(invoke(process.execPath,
    [...base, "run", ...options, "--", "--data-dir", fixtureData, "--json", ...parameters]));
  // The product's explicitly labelled demo provides saved findings; it never
  // executes a security check. Scanner and complete archive evidence remain in
  // the separate native Rust integration suites.
  const demo = cli("case", "seed-demo");
  assert.equal(demo.is_demo, true);
  const run = demo.scan_runs.at(-1);
  assert.ok(run && demo.findings.length > 0);
  const snapshot = join(scratch, "synthetic.snapshot.json");
  cli("report", "snapshot", "--case-id", demo.id, "--run-id", run.id,
    "--destination", snapshot, "--acknowledge-private-context");
  // Reopen and render after removing the original synthetic workspace. No
  // scanner runtime or container images are needed by the cached core.
  rmSync(fixtureData, { recursive: true, force: true });
  const inspected = cli("report", "inspect", "--snapshot", snapshot);
  assert.equal(inspected.replay_available, true);
  const reportHashes = {};
  for (const format of ["html", "json"]) {
    const original = join(scratch, `original.${format}`);
    const replay = join(scratch, `replay.${format}`);
    cli("report", "retrieve", "--snapshot", snapshot, "--format", format, "--destination", original);
    cli("report", "replay", "--snapshot", snapshot, "--format", format, "--destination", replay);
    assert.deepEqual(readFileSync(replay), readFileSync(original));
    reportHashes[format] = createHash("sha256").update(readFileSync(replay)).digest("hex");
  }
  assert.equal(existsSync(fixtureData), false, "offline replay must not recreate the synthetic workspace");
  const summary = {
    schema_version: "ai-security-scanner.bootstrap-native-smoke/v1",
    revision, platform: process.platform, arch: process.arch,
    cache_reused: second.cache_hit, product_data_created: false,
    fixture_only: true, target_contact: false,
    synthetic_workspace_removed: true, report_replay_equal: true, report_sha256: reportHashes,
    identity, receipt: second.receipt,
  };
  const serialized = `${JSON.stringify(summary, null, 2)}\n`;
  if (process.env.SKILL_SMOKE_RESULT) writeFileSync(process.env.SKILL_SMOKE_RESULT, serialized);
  process.stdout.write(serialized);
} finally {
  rmSync(scratch, { recursive: true, force: true });
}
