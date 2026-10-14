import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { closeSync, openSync, readFileSync } from "node:fs";
import { copyFile, cp, mkdir, mkdtemp, readFile, readdir, rm } from "node:fs/promises";
import path from "node:path";
import { after, before, test } from "node:test";

import { PUBLICATION_ORIGINS, UPDATER_DOWNLOAD_REPOSITORY } from "../../scripts/publication-origins.mjs";
import { PROJECT_ROOT, readJson, writeJsonAtomic, writeTextAtomic } from "../../scripts/release/lib.mjs";
import { createPreparedReleaseMetadata } from "../../scripts/release/release-metadata.mjs";
import { finalizedUpdaterPlatforms } from "../../scripts/release/finalize-release.mjs";
import {
  createPlatformFixture,
  createQualificationFixture,
  resealFinalizedFixture,
} from "../../scripts/release/self-test.mjs";

const VERSION = (await readJson(path.join(PROJECT_ROOT, "package.json"))).version;
const TAG = `v${VERSION}`;
const COMMIT = "0123456789abcdef0123456789abcdef01234567";
const PAYLOADS = {
  "linux-x86_64": ["appimage", `ai-security-scanner_${VERSION}_amd64.AppImage`, ["linux-x86_64", "linux-x86_64-appimage"]],
  "macos-universal": ["dmg", `ai-security-scanner_${VERSION}_universal.dmg`, ["darwin-x86_64", "darwin-x86_64-app", "darwin-aarch64", "darwin-aarch64-app"]],
  "windows-x86_64": ["nsis", `ai-security-scanner_${VERSION}_x64-setup.exe`, ["windows-x86_64", "windows-x86_64-nsis"]],
};

// Independently restate the ORIGINAL <= 0.5.1 URL rule, without importing old code
// or the shared origins: changing the new policy must not change this oracle.
function originalV051Accepts(value, version, suffix) {
  if (typeof value !== "string" || value.length > 2_048) return false;
  try {
    const url = new URL(value);
    const parts = url.pathname.split("/").filter(Boolean).map(decodeURIComponent);
    const name = parts[5] ?? "";
    return url.protocol === "https:" && url.hostname === "github.com" &&
      [url.port, url.username, url.password, url.search, url.hash].every((part) => part === "") &&
      parts.length === 6 &&
      ["teddashh", "ai-security-scanner", "releases", "download"].every((part, index) => parts[index] === part) &&
      parts[4] === `v${version}` && /^[A-Za-z0-9][A-Za-z0-9._+-]{0,254}$/u.test(name) &&
      name.includes(version) && name.endsWith(suffix);
  } catch {
    return false;
  }
}

let temporary;
let output;
let config;
let packageJson;
let latest;
const collectedUpdaters = [];
let commandCount = 0;

function run(script, args) {
  const stdoutPath = path.join(temporary, `command-${++commandCount}.stdout`);
  const stderrPath = path.join(temporary, `command-${commandCount}.stderr`);
  const stdoutFd = openSync(stdoutPath, "w");
  const stderrFd = openSync(stderrPath, "w");
  let result;
  try {
    result = spawnSync(process.execPath, [path.join(PROJECT_ROOT, "scripts/release", script), ...args], {
      cwd: PROJECT_ROOT,
      stdio: ["ignore", stdoutFd, stderrFd],
    });
  } finally {
    closeSync(stdoutFd);
    closeSync(stderrFd);
  }
  if (result.error) throw result.error;
  return { status: result.status, stdout: readFileSync(stdoutPath, "utf8"), stderr: readFileSync(stderrPath, "utf8") };
}

function verificationArgs(directory) {
  return [
    "--dir", directory, "--version", VERSION, "--tag", TAG, "--commit", COMMIT,
    "--publication-mode", "commit-bound-qc", "--tauri-config", config, "--package-json", packageJson,
  ];
}

before(async () => {
  const root = path.join(PROJECT_ROOT, "target", "updater-download-tests");
  await mkdir(root, { recursive: true });
  temporary = await mkdtemp(path.join(root, "run-"));
  const key = path.join(temporary, "test.key");
  execFileSync(process.execPath, [
    path.join(PROJECT_ROOT, "node_modules", "@tauri-apps", "cli", "tauri.js"),
    "signer", "generate", "--ci", "--password", "release-self-test-only", "--write-keys", key,
  ], { cwd: PROJECT_ROOT, stdio: "ignore" });
  config = path.join(temporary, "tauri.json");
  await writeJsonAtomic(config, { plugins: { updater: { pubkey: (await readFile(`${key}.pub`, "utf8")).trim() } } });
  packageJson = path.join(temporary, "package.json");
  await writeJsonAtomic(packageJson, { release: { channel: "prerelease", target: "0.2.0" } });
  const input = path.join(temporary, "input");
  await mkdir(input);
  for (const [platform, [kind, name]] of Object.entries(PAYLOADS)) {
    const requested = platform === "linux-x86_64" ? ["deb", "rpm", "appimage"]
      : platform === "windows-x86_64" ? ["nsis", "msi"] : ["dmg"];
    const kinds = [[kind, name]];
    if (platform === "linux-x86_64") kinds.unshift(["deb", `ai-security-scanner_${VERSION}_amd64.deb`]);
    const collected = await createPlatformFixture(
      temporary, platform, kinds, key, undefined, false, requested,
    );
    const manifest = await readJson(path.join(collected, `installers-${platform}.json`));
    collectedUpdaters.push(...manifest.updaters.map((updater) => ({ updater })));
    await createQualificationFixture(collected, platform, platform === "linux-x86_64" ? "deb" : kind);
    for (const file of await readdir(collected)) {
      await copyFile(path.join(collected, file), path.join(input, file));
    }
  }
  for (const name of ["THIRD_PARTY_NOTICES.txt", "ENGINE_NOTICES.md", "LICENSE.txt"]) {
    await writeTextAtomic(path.join(input, name), "Fixture notice\n");
  }
  await writeJsonAtomic(path.join(input, "ENGINE_NOTICES.json"), { engines: [] });
  const cyclonedx = `ai-security-scanner-${VERSION}.cyclonedx.json`;
  const spdx = `ai-security-scanner-${VERSION}.spdx.json`;
  await writeJsonAtomic(path.join(input, cyclonedx), { bomFormat: "CycloneDX", specVersion: "1.6", version: 1, components: [] });
  await writeJsonAtomic(path.join(input, spdx), { spdxVersion: "SPDX-2.3", SPDXID: "SPDXRef-DOCUMENT", packages: [], relationships: [] });
  await writeJsonAtomic(path.join(input, "release-metadata.json"), createPreparedReleaseMetadata({
    version: VERSION, tag: TAG, releaseChannel: "prerelease", stableTarget: "0.2.0",
    sourceRepository: "https://github.com/TED-H-com/ai-security-scanner",
    sourceCommit: COMMIT, sourceDate: "2026-08-24T00:00:00Z", publicationMode: "commit-bound-qc",
    requestedPlatforms: Object.keys(PAYLOADS), sboms: [cyclonedx, spdx],
    inventories: { npmPackageCount: 0, cargoPackageCount: 0, engineReferenceCount: 0 },
  }));
  output = path.join(temporary, "finalized");
  const finalized = await run("finalize-release.mjs", [
    "--input", input, "--out", output, "--version", VERSION, "--tag", TAG, "--commit", COMMIT,
    "--publication-mode", "commit-bound-qc", "--tauri-config", config, "--package-json", packageJson,
  ]);
  assert.equal(finalized.status, 0, finalized.stderr);
  latest = await readJson(path.join(output, "latest.json"));
  const verified = await run("verify-finalized-release.mjs", verificationArgs(output));
  assert.equal(verified.status, 0, verified.stderr);
});

after(async () => {
  if (temporary) await rm(temporary, { recursive: true, force: true });
});

test("finalize uses the legacy updater download path for every emitted payload", () => {
  assert.equal(UPDATER_DOWNLOAD_REPOSITORY, "teddashh/ai-security-scanner");
  assert.equal(UPDATER_DOWNLOAD_REPOSITORY, PUBLICATION_ORIGINS[0].repository);
  // Current qualification offers Linux DEB only, which has no updater payload.
  const offered = Object.entries(PAYLOADS).filter(([platform]) => platform !== "linux-x86_64");
  assert.deepEqual(Object.keys(latest.platforms).sort(), offered.flatMap(([, [, , targets]]) => targets).sort());
  for (const [target, entry] of Object.entries(latest.platforms)) {
    assert.equal(entry.url, allPlatforms()[target].url);
  }
});

function allPlatforms() {
  return finalizedUpdaterPlatforms(collectedUpdaters, TAG);
}

test("finalizer manifest generation pins the legacy path for all platforms and fallbacks", () => {
  const platforms = allPlatforms();
  assert.deepEqual(Object.keys(platforms).sort(), Object.values(PAYLOADS).flatMap(([, , targets]) => targets).sort());
  for (const [platform, [, , targets]] of Object.entries(PAYLOADS)) {
    const file = platform === "macos-universal"
      ? `ai-security-scanner_${VERSION}_universal.app.tar.gz`
      : PAYLOADS[platform][1];
    for (const target of targets) {
      assert.equal(platforms[target].url,
        `https://github.com/teddashh/ai-security-scanner/releases/download/${TAG}/${encodeURIComponent(file)}`);
    }
  }
});

test("the original v0.5.1 URL rule accepts every finalized updater payload", () => {
  for (const [target, { url }] of Object.entries({ ...allPlatforms(), ...latest.platforms })) {
    const suffix = target.startsWith("darwin-") ? ".app.tar.gz" : target.startsWith("linux-") ? ".AppImage" : ".exe";
    assert.equal(originalV051Accepts(url, VERSION, suffix), true, target);
    assert.equal(originalV051Accepts(url.replace("teddashh", "TED-H-com"), VERSION, suffix), false, target);
  }
});

test("verify rejects resealed updater URLs under TED-H-com or any other owner", async () => {
  for (const owner of ["TED-H-com", "unknown"]) {
    for (const target of Object.keys(latest.platforms)) {
      const directory = path.join(temporary, `tampered-${owner}-${target}`);
      await cp(output, directory, { recursive: true });
      const tampered = structuredClone(latest);
      tampered.platforms[target].url = tampered.platforms[target].url.replace("teddashh", owner);
      await writeJsonAtomic(path.join(directory, "latest.json"), tampered);
      await resealFinalizedFixture(directory);
      const verified = await run("verify-finalized-release.mjs", verificationArgs(directory));
      assert.equal(verified.status, 1, verified.stderr);
      assert.match(verified.stderr, /latest\.json does not bind/u);
    }
  }
});

test("verify accepts only the two known source repository aliases", async () => {
  for (const source of [
    ...PUBLICATION_ORIGINS.map(({ repository }) => `https://github.com/${repository}`),
    "https://github.com/unknown/ai-security-scanner", "https://github.com/TED-H-com/other-repository",
  ]) {
    const directory = path.join(temporary, `source-${encodeURIComponent(source)}`);
    await cp(output, directory, { recursive: true });
    const metadata = await readJson(path.join(directory, "release-metadata.json"));
    metadata.sourceRepository = source;
    await writeJsonAtomic(path.join(directory, "release-metadata.json"), metadata);
    await resealFinalizedFixture(directory);
    const verified = await run("verify-finalized-release.mjs", verificationArgs(directory));
    const known = PUBLICATION_ORIGINS.some(({ repository }) => source === `https://github.com/${repository}`);
    assert.equal(verified.status, known ? 0 : 1, verified.stderr);
    if (!known) assert.match(verified.stderr, /not a known publication origin/u);
  }
});
