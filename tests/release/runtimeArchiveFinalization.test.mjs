import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { closeSync, openSync, readFileSync } from "node:fs";
import { copyFile, cp, lstat, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { after, before, test } from "node:test";

import { writeIncidentScanPack } from "../../scripts/release/incident-scan-pack.mjs";
import { PROJECT_ROOT, readJson, sha256, sha256File, writeJsonAtomic, writeTextAtomic } from "../../scripts/release/lib.mjs";
import { createPreparedReleaseMetadata } from "../../scripts/release/release-metadata.mjs";
import { packRuntimeArchive, runtimeArchiveName, verifyRuntimeArchive } from "../../scripts/release/runtime-archive.mjs";
import { createPlatformFixture, createQualificationFixture } from "../../scripts/release/self-test.mjs";

const VERSION = (await readJson(path.join(PROJECT_ROOT, "package.json"))).version;
const TAG = `v${VERSION}`;
const COMMIT = "0123456789abcdef0123456789abcdef01234567";
const ARCHIVE_NAME = runtimeArchiveName("windows-x86_64");

let temporary;
let baseInput;
let config;
let packageJson;
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
  return {
    status: result.status,
    stdout: readFileSync(stdoutPath, "utf8"),
    stderr: readFileSync(stderrPath, "utf8"),
  };
}

function finalizeArgs(input, output) {
  return [
    "--input", input,
    "--out", output,
    "--version", VERSION,
    "--tag", TAG,
    "--commit", COMMIT,
    "--publication-mode", "commit-bound-qc",
    "--tauri-config", config,
    "--package-json", packageJson,
  ];
}

function verifyArgs(directory) {
  return [
    "--dir", directory,
    "--version", VERSION,
    "--tag", TAG,
    "--commit", COMMIT,
    "--publication-mode", "commit-bound-qc",
    "--tauri-config", config,
    "--package-json", packageJson,
  ];
}

function parseChecksumFile(contents) {
  return contents
    .trimEnd()
    .split("\n")
    .filter(Boolean)
    .map((line) => {
      const separator = line.indexOf("  ");
      assert.notEqual(separator, -1, `unexpected checksum line: ${line}`);
      return {
        sha256: line.slice(0, separator),
        name: line.slice(separator + 2),
      };
    });
}

async function createAlternateRuntimeArchive(sourceManifestPath, destinationArchivePath) {
  const alternateRoot = path.join(temporary, `alternate-runtime-${++commandCount}`);
  const binaryRelative = "bin/podman.exe";
  const binaryPath = path.join(alternateRoot, "bin", "podman.exe");
  await mkdir(path.dirname(binaryPath), { recursive: true });
  const binaryBytes = Buffer.concat([Buffer.from([0x4d, 0x5a, 0, 0]), Buffer.alloc(4096, 99)]);
  await writeFile(binaryPath, binaryBytes);
  const binarySha256 = sha256(binaryBytes);

  const manifest = await readJson(sourceManifestPath);
  const alternateManifest = structuredClone(manifest);
  alternateManifest.files[0].sha256 = binarySha256;
  alternateManifest.files[0].size_bytes = binaryBytes.length;
  const bundledArtifact = alternateManifest.components[0].artifacts.find(
    (artifact) => artifact.delivery === "bundled_file" && artifact.locator === binaryRelative,
  );
  assert.ok(bundledArtifact, "fixture manifest must include bundled_file artifact for bin/podman.exe");
  bundledArtifact.sha256 = binarySha256;
  bundledArtifact.size_bytes = binaryBytes.length;

  await writeJsonAtomic(path.join(alternateRoot, "manifest.json"), alternateManifest);
  await packRuntimeArchive({ root: alternateRoot, output: destinationArchivePath });
}

function assertWindowsNotOfferedWithoutArtifacts(outputDir, metadata, outputFiles) {
  const linux = metadata.distribution.platforms.find(({ platform }) => platform === "linux-x86_64");
  const windows = metadata.distribution.platforms.find(({ platform }) => platform === "windows-x86_64");
  assert.equal(linux?.availability, "offered");
  assert.equal(windows?.availability, "not-offered");
  assert.equal(windows?.reason, "platform-shared-evidence-invalid");
  for (const installer of windows.installers) {
    assert.equal(installer.availability, "not-offered");
    assert.equal(installer.reason, "platform-shared-evidence-invalid");
  }
  assert.equal(
    outputFiles.some((name) => name.endsWith(".exe") || name.endsWith(".msi")),
    false,
    `unexpected Windows installer in ${outputDir}: ${outputFiles.join(", ")}`,
  );
  assert.equal(
    outputFiles.some((name) => name.startsWith("managed-runtime-windows-x86_64")),
    false,
    `unexpected Windows runtime file in ${outputDir}: ${outputFiles.join(", ")}`,
  );
}

before(async () => {
  temporary = await mkdtemp(path.join(os.tmpdir(), "runtime-archive-finalization-"));
  const key = path.join(temporary, "test.key");
  execFileSync(process.execPath, [
    path.join(PROJECT_ROOT, "node_modules", "@tauri-apps", "cli", "tauri.js"),
    "signer", "generate", "--ci", "--password", "release-self-test-only", "--write-keys", key,
  ], { cwd: PROJECT_ROOT, stdio: "ignore" });
  config = path.join(temporary, "tauri.json");
  await writeJsonAtomic(config, { plugins: { updater: { pubkey: (await readFile(`${key}.pub`, "utf8")).trim() } } });
  packageJson = path.join(temporary, "package.json");
  await writeJsonAtomic(packageJson, { release: { channel: "prerelease", target: "0.2.0" } });

  baseInput = path.join(temporary, "base-input");
  await mkdir(baseInput);
  await writeIncidentScanPack(baseInput, VERSION, COMMIT);

  const linuxCollected = await createPlatformFixture(
    temporary,
    "linux-x86_64",
    [
      ["deb", `ai-security-scanner_${VERSION}_amd64.deb`],
      ["appimage", `ai-security-scanner_${VERSION}_amd64.AppImage`],
    ],
    key,
    undefined,
    false,
    ["deb", "rpm", "appimage"],
  );
  await createQualificationFixture(linuxCollected, "linux-x86_64", "deb");
  for (const file of await readdir(linuxCollected)) {
    await copyFile(path.join(linuxCollected, file), path.join(baseInput, file));
  }

  const windowsCollected = await createPlatformFixture(
    temporary,
    "windows-x86_64",
    [["nsis", `ai-security-scanner_${VERSION}_x64-setup.exe`]],
    key,
    undefined,
    false,
    ["nsis", "msi"],
  );
  await createQualificationFixture(windowsCollected, "windows-x86_64", "nsis");
  for (const file of await readdir(windowsCollected)) {
    await copyFile(path.join(windowsCollected, file), path.join(baseInput, file));
  }

  for (const name of ["THIRD_PARTY_NOTICES.txt", "ENGINE_NOTICES.md", "LICENSE.txt"]) {
    await writeTextAtomic(path.join(baseInput, name), "Fixture notice\n");
  }
  await writeJsonAtomic(path.join(baseInput, "ENGINE_NOTICES.json"), { engines: [] });
  const cyclonedx = `ai-security-scanner-${VERSION}.cyclonedx.json`;
  const spdx = `ai-security-scanner-${VERSION}.spdx.json`;
  await writeJsonAtomic(path.join(baseInput, cyclonedx), {
    bomFormat: "CycloneDX",
    specVersion: "1.6",
    version: 1,
    components: [],
  });
  await writeJsonAtomic(path.join(baseInput, spdx), {
    spdxVersion: "SPDX-2.3",
    SPDXID: "SPDXRef-DOCUMENT",
    packages: [],
    relationships: [],
  });
  await writeJsonAtomic(path.join(baseInput, "release-metadata.json"), createPreparedReleaseMetadata({
    version: VERSION,
    tag: TAG,
    releaseChannel: "prerelease",
    stableTarget: "0.2.0",
    sourceRepository: "https://github.com/TED-H-com/ai-security-scanner",
    sourceCommit: COMMIT,
    sourceDate: "2026-08-24T00:00:00Z",
    publicationMode: "commit-bound-qc",
    requestedPlatforms: ["linux-x86_64", "windows-x86_64"],
    sboms: [cyclonedx, spdx],
    inventories: { npmPackageCount: 0, cargoPackageCount: 0, engineReferenceCount: 0 },
  }));
});

after(async () => {
  if (temporary) await rm(temporary, { recursive: true, force: true });
});

test("finalization publishes and verifies the Windows runtime archive alongside Linux", async () => {
  const input = path.join(temporary, "case-valid-input");
  const output = path.join(temporary, "case-valid-output");
  await cp(baseInput, input, { recursive: true });

  const finalized = run("finalize-release.mjs", finalizeArgs(input, output));
  assert.equal(finalized.status, 0, finalized.stderr);

  const inputArchive = path.join(input, ARCHIVE_NAME);
  const outputArchive = path.join(output, ARCHIVE_NAME);
  const inputBytes = await readFile(inputArchive);
  const outputBytes = await readFile(outputArchive);
  assert.equal(Buffer.compare(outputBytes, inputBytes), 0);

  const archiveSha256 = sha256(outputBytes);
  const windowsSums = parseChecksumFile(
    await readFile(path.join(output, "SHA256SUMS-windows-x86_64.txt"), "utf8"),
  );
  assert.deepEqual(
    windowsSums.find((entry) => entry.name === ARCHIVE_NAME),
    { sha256: archiveSha256, name: ARCHIVE_NAME },
  );

  const releaseSums = parseChecksumFile(
    await readFile(path.join(output, "SHA256SUMS.txt"), "utf8"),
  );
  assert.deepEqual(
    releaseSums.find((entry) => entry.name === ARCHIVE_NAME),
    { sha256: archiveSha256, name: ARCHIVE_NAME },
  );

  const releaseAssets = await readJson(path.join(output, "release-assets.json"));
  const archiveAsset = releaseAssets.files.find((entry) => entry.path === ARCHIVE_NAME);
  assert.ok(archiveAsset, "release-assets.json must list managed-runtime-windows-x86_64.tar.gz");
  assert.equal(archiveAsset.publishedName, ARCHIVE_NAME);
  assert.equal(archiveAsset.sha256, archiveSha256);
  assert.equal(archiveAsset.bytes, outputBytes.length);

  const outputManifestSha256 = await sha256File(path.join(output, "managed-runtime-windows-x86_64.manifest.json"));
  await verifyRuntimeArchive({ archive: outputArchive, manifestSha256: outputManifestSha256 });

  const verified = run("verify-finalized-release.mjs", verifyArgs(output));
  assert.equal(verified.status, 0, verified.stderr);

  await assert.rejects(
    lstat(path.join(output, "managed-runtime-linux-x86_64.tar.gz")),
    { code: "ENOENT" },
  );
  const linuxSums = parseChecksumFile(
    await readFile(path.join(output, "SHA256SUMS-linux-x86_64.txt"), "utf8"),
  );
  assert.equal(
    linuxSums.some((entry) => entry.name.startsWith("managed-runtime-") && entry.name.endsWith(".tar.gz")),
    false,
  );
});

test("finalization excludes Windows when its runtime archive is missing", async () => {
  const input = path.join(temporary, "case-missing-input");
  const output = path.join(temporary, "case-missing-output");
  await cp(baseInput, input, { recursive: true });
  await rm(path.join(input, ARCHIVE_NAME), { force: true });

  const finalized = run("finalize-release.mjs", finalizeArgs(input, output));
  assert.equal(finalized.status, 0, finalized.stderr);
  assert.match(finalized.stderr, /managed-runtime-windows-x86_64 has no runtime archive/u);

  const metadata = await readJson(path.join(output, "release-metadata.json"));
  const outputFiles = await readdir(output);
  assertWindowsNotOfferedWithoutArtifacts(output, metadata, outputFiles);

  const verified = run("verify-finalized-release.mjs", verifyArgs(output));
  assert.equal(verified.status, 0, verified.stderr);
});

test("finalization excludes Windows when its runtime archive does not match its manifest", async () => {
  const input = path.join(temporary, "case-mismatch-input");
  const output = path.join(temporary, "case-mismatch-output");
  await cp(baseInput, input, { recursive: true });
  await createAlternateRuntimeArchive(
    path.join(input, "managed-runtime-windows-x86_64.manifest.json"),
    path.join(input, ARCHIVE_NAME),
  );

  const finalized = run("finalize-release.mjs", finalizeArgs(input, output));
  assert.equal(finalized.status, 0, finalized.stderr);
  assert.match(finalized.stderr, /runtime archive does not match its manifest/u);

  const metadata = await readJson(path.join(output, "release-metadata.json"));
  const outputFiles = await readdir(output);
  assertWindowsNotOfferedWithoutArtifacts(output, metadata, outputFiles);

  const verified = run("verify-finalized-release.mjs", verifyArgs(output));
  assert.equal(verified.status, 0, verified.stderr);
});
