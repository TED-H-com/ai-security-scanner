import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  lstat,
  mkdir,
  mkdtemp,
  readdir,
  readFile,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { gunzipSync } from "node:zlib";

import {
  packRuntimeArchive,
  runtimeArchiveName,
  verifyRuntimeArchive,
} from "../../scripts/release/runtime-archive.mjs";
import {
  extractReleaseBundle,
  verifyReleaseBundle,
} from "../../scripts/skill/release-bundle.mjs";

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const EVIDENCE_SCRIPT = path.join(REPO_ROOT, "scripts/release/generate-runtime-evidence.mjs");

function sha256Hex(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function parseTarString(buffer) {
  const nul = buffer.indexOf(0);
  if (nul !== -1) {
    assert.ok(
      buffer.subarray(nul).every((byte) => byte === 0),
      "expected zero padding after NUL in tar string field",
    );
  }
  return (nul === -1 ? buffer : buffer.subarray(0, nul)).toString("utf8");
}

function parseTarOctal(buffer) {
  const text = buffer.toString("latin1");
  assert.match(text, /^ *[0-7]+[ \0]*$/u);
  return Number.parseInt(text.trim(), 8);
}

function readTarEntries(archiveBytes) {
  assert.equal(archiveBytes[0], 0x1f);
  assert.equal(archiveBytes[1], 0x8b);
  assert.equal(archiveBytes[2], 0x08);
  assert.equal(archiveBytes[3], 0x00, "gzip FLG must be 0");
  assert.deepEqual(archiveBytes.subarray(4, 8), Buffer.alloc(4, 0), "gzip MTIME must be 0");
  assert.equal(archiveBytes[9], 0xff, "gzip OS field must be 0xff");

  const tar = gunzipSync(archiveBytes);
  assert.equal(tar.length % 512, 0, "tar stream length must be a multiple of 512");

  const entries = [];
  let pos = 0;
  while (pos < tar.length) {
    const header = tar.subarray(pos, pos + 512);
    pos += 512;
    if (header.every((byte) => byte === 0)) {
      assert.ok(pos + 512 <= tar.length, "expected second all-zero end-of-archive block");
      const secondEndBlock = tar.subarray(pos, pos + 512);
      assert.ok(secondEndBlock.every((byte) => byte === 0), "second end block must be all zeros");
      pos += 512;
      assert.ok(
        tar.subarray(pos).every((byte) => byte === 0),
        "trailing tar bytes after end marker must be zero",
      );
      break;
    }

    const expectedChecksum = parseTarOctal(header.subarray(148, 156));
    let actualChecksum = 0;
    for (let i = 0; i < 512; i += 1) {
      actualChecksum += i >= 148 && i < 156 ? 32 : header[i];
    }
    assert.equal(actualChecksum, expectedChecksum, "tar header checksum must match");
    assert.equal(header.subarray(257, 263).toString("binary"), "ustar\0");
    assert.equal(header.subarray(263, 265).toString("binary"), "00");
    assert.equal(parseTarString(header.subarray(265, 297)), "", "uname must be empty");
    assert.equal(parseTarString(header.subarray(297, 329)), "", "gname must be empty");

    const rawName = parseTarString(header.subarray(0, 100));
    const rawPrefix = parseTarString(header.subarray(345, 500));
    const fullPath = rawPrefix ? `${rawPrefix}/${rawName}` : rawName;
    const typeflag = String.fromCharCode(header[156]);
    const mode = parseTarOctal(header.subarray(100, 108));
    const uid = parseTarOctal(header.subarray(108, 116));
    const gid = parseTarOctal(header.subarray(116, 124));
    const size = parseTarOctal(header.subarray(124, 136));
    const mtime = parseTarOctal(header.subarray(136, 148));
    const data = tar.subarray(pos, pos + size);
    const dataBlocks = Math.ceil(size / 512) * 512;
    assert.ok(
      tar.subarray(pos + size, pos + dataBlocks).every((byte) => byte === 0),
      "file padding bytes must be zero",
    );
    pos += dataBlocks;

    entries.push({
      path: fullPath,
      rawName,
      rawPrefix,
      typeflag,
      mode,
      uid,
      gid,
      size,
      mtime,
      data,
    });
  }
  return entries;
}

async function createTempDir(t, label) {
  const dir = await mkdtemp(path.join(tmpdir(), `runtime-archive-${label}-`));
  t.after(() => rm(dir, { recursive: true, force: true }));
  return dir;
}

async function createRuntimeFixture(root, filesSpec, { platform = "windows-x86_64" } = {}) {
  const records = [];
  const artifacts = [];
  for (const spec of filesSpec) {
    const abs = path.join(root, ...spec.path.split("/"));
    await mkdir(path.dirname(abs), { recursive: true });
    await writeFile(abs, spec.content);
    const digest = sha256Hex(spec.content);
    const record = {
      path: spec.path,
      sha256: digest,
      size_bytes: spec.content.length,
      executable: spec.executable,
    };
    records.push(record);
    artifacts.push({
      delivery: "bundled_file",
      locator: spec.path,
      sha256: digest,
      size_bytes: spec.content.length,
    });
  }

  const machineImageUrl =
    `https://github.com/podman-container-tools/podman-machine-os/releases/download/v0.0.1/${platform}.qcow2.xz`;
  const machineImageSha256 = "ab".repeat(32);
  const commit = "0123456789abcdef0123456789abcdef01234567";
  const manifestObj = {
    schema_version: "3",
    management_contract_revision: "2026-08-29.1",
    bundle_id: "podman-machine",
    runtime_version: "5.8.2",
    driver_path: records[0].path,
    files: records,
    components: [
      {
        id: "fixture-runtime-client",
        name: "Fixture runtime client",
        version: "0.0.1",
        repository_url: "https://github.com/containers/podman",
        source_revision: commit,
        license_spdx: "Apache-2.0",
        relationship: "Test stand-in for bundled managed runtime files.",
        artifacts,
      },
      {
        id: "fixture-machine-os",
        name: "Fixture machine OS",
        version: "0.0.1",
        repository_url: "https://github.com/podman-container-tools/podman-machine-os",
        source_revision: commit,
        license_spdx: "Apache-2.0",
        relationship: "Test stand-in for runtime machine image.",
        artifacts: [
          {
            delivery: "runtime_download",
            locator: machineImageUrl,
            sha256: machineImageSha256,
            size_bytes: 4096,
          },
        ],
      },
    ],
    targets: [
      {
        operating_system: platform.startsWith("linux") ? "linux" : "windows",
        architecture: "x86_64",
        provider: platform.startsWith("linux") ? "qemu" : "wsl",
        machine_image: {
          url: machineImageUrl,
          sha256: machineImageSha256,
          size_bytes: 4096,
        },
      },
    ],
    resources: { cpus: 2, memory_mb: 2048, disk_size_gb: 20 },
    source: {
      repository_url: "https://github.com/containers/podman",
      source_revision: commit,
      license_spdx: "Apache-2.0",
    },
  };

  const manifestText = `${JSON.stringify(manifestObj, null, 2)}\n`;
  const manifestPath = path.join(root, "manifest.json");
  await writeFile(manifestPath, manifestText, "utf8");
  const manifestBytes = Buffer.from(manifestText, "utf8");
  return {
    manifestPath,
    manifestBytes,
    manifestSha256: sha256Hex(manifestBytes),
    manifestObj,
  };
}

test("packRuntimeArchive creates deterministic ustar tar.gz archives matching the bootstrap reader", async (t) => {
  assert.equal(runtimeArchiveName("windows-x86_64"), "managed-runtime-windows-x86_64.tar.gz");

  const workspace = await createTempDir(t, "pack-deterministic");
  const runtimeDir = path.join(workspace, "staged");
  const outDir = path.join(workspace, "out");
  await mkdir(runtimeDir, { recursive: true });
  await mkdir(outDir, { recursive: true });

  const exeBytes = Buffer.from("MZ-fake-executable-payload\n", "utf8");
  const cfgBytes = Buffer.from('{"mode":"rootless"}\n', "utf8");
  const fixture = await createRuntimeFixture(runtimeDir, [
    { path: "bin/podman.exe", content: exeBytes, executable: true },
    { path: "share/podman/config.json", content: cfgBytes, executable: false },
  ]);

  const archiveA = path.join(outDir, "a.tar.gz");
  const archiveB = path.join(outDir, "b.tar.gz");
  const resA = await packRuntimeArchive({ root: runtimeDir, output: archiveA });
  const resB = await packRuntimeArchive({ root: runtimeDir, output: archiveB });

  const bytesA = await readFile(archiveA);
  const bytesB = await readFile(archiveB);
  assert.equal(Buffer.compare(bytesA, bytesB), 0, "two runs must emit byte-identical archives");

  const expectedEntries = [
    "managed-runtime/",
    "managed-runtime/bin/",
    "managed-runtime/bin/podman.exe",
    "managed-runtime/manifest.json",
    "managed-runtime/share/",
    "managed-runtime/share/podman/",
    "managed-runtime/share/podman/config.json",
  ];
  const expectedExtractedBytes =
    exeBytes.length + cfgBytes.length + fixture.manifestBytes.length;

  assert.equal(resA.file, archiveA);
  assert.equal(resA.bytes, bytesA.length);
  assert.equal(resA.sha256, sha256Hex(bytesA));
  assert.equal(resA.manifestSha256, fixture.manifestSha256);
  assert.equal(resA.extractedBytes, expectedExtractedBytes);
  assert.deepEqual(resA.entries, expectedEntries);

  const tarEntries = readTarEntries(bytesA);
  assert.deepEqual(
    tarEntries.map((entry) => entry.path),
    expectedEntries,
  );
  const byPath = new Map(tarEntries.map((entry) => [entry.path, entry]));
  for (const dirPath of [
    "managed-runtime/",
    "managed-runtime/bin/",
    "managed-runtime/share/",
    "managed-runtime/share/podman/",
  ]) {
    const dir = byPath.get(dirPath);
    assert.equal(dir.typeflag, "5");
    assert.equal(dir.mode, 0o755);
    assert.equal(dir.uid, 0);
    assert.equal(dir.gid, 0);
    assert.equal(dir.mtime, 0);
    assert.equal(dir.size, 0);
  }
  const exeEntry = byPath.get("managed-runtime/bin/podman.exe");
  assert.equal(exeEntry.typeflag, "0");
  assert.equal(exeEntry.mode, 0o755);
  assert.equal(exeEntry.uid, 0);
  assert.equal(exeEntry.gid, 0);
  assert.equal(exeEntry.mtime, 0);
  assert.equal(exeEntry.size, exeBytes.length);
  assert.equal(Buffer.compare(exeEntry.data, exeBytes), 0);

  const cfgEntry = byPath.get("managed-runtime/share/podman/config.json");
  assert.equal(cfgEntry.typeflag, "0");
  assert.equal(cfgEntry.mode, 0o644);
  assert.equal(cfgEntry.uid, 0);
  assert.equal(cfgEntry.gid, 0);
  assert.equal(cfgEntry.mtime, 0);
  assert.equal(cfgEntry.size, cfgBytes.length);
  assert.equal(Buffer.compare(cfgEntry.data, cfgBytes), 0);

  const manifestEntry = byPath.get("managed-runtime/manifest.json");
  assert.equal(manifestEntry.typeflag, "0");
  assert.equal(manifestEntry.mode, 0o644);
  assert.equal(manifestEntry.uid, 0);
  assert.equal(manifestEntry.gid, 0);
  assert.equal(manifestEntry.mtime, 0);
  assert.equal(manifestEntry.size, fixture.manifestBytes.length);
  assert.equal(Buffer.compare(manifestEntry.data, fixture.manifestBytes), 0);

  const extractedDir = path.join(workspace, "extracted");
  await mkdir(extractedDir, { recursive: true });
  await extractReleaseBundle(archiveA, "tar.gz", "managed-runtime", extractedDir);
  await verifyReleaseBundle(extractedDir, fixture.manifestSha256);

  if (process.platform !== "win32") {
    const exeStat = await lstat(path.join(extractedDir, "bin", "podman.exe"));
    const cfgStat = await lstat(path.join(extractedDir, "share", "podman", "config.json"));
    const manStat = await lstat(path.join(extractedDir, "manifest.json"));
    assert.equal(Boolean(exeStat.mode & 0o100), true, "executable file must keep owner-execute bit");
    assert.equal(Boolean(cfgStat.mode & 0o100), false, "non-executable file must not have execute bit");
    assert.equal(Boolean(manStat.mode & 0o100), false, "manifest.json must not have execute bit");
  }
});

test("packRuntimeArchive splits paths over 100 bytes with ustar prefix and rejects unsplittable paths", async (t) => {
  const workspace = await createTempDir(t, "long-path");
  const runtimeDir = path.join(workspace, "staged");
  await mkdir(runtimeDir, { recursive: true });

  const longDir = "share/long-segment-one-012345678901234567890123456789/long-segment-two-012345678901234567890123456789";
  const longRelPath = `${longDir}/nested-payload-file-0123456789.json`;
  assert.ok(Buffer.byteLength(`managed-runtime/${longRelPath}`, "utf8") > 100);

  const payload = Buffer.from('{"longPath":true}\n', "utf8");
  const fixture = await createRuntimeFixture(runtimeDir, [
    { path: longRelPath, content: payload, executable: false },
  ]);

  const archivePath = path.join(workspace, "long.tar.gz");
  await packRuntimeArchive({ root: runtimeDir, output: archivePath });

  const tarEntries = readTarEntries(await readFile(archivePath));
  const longEntry = tarEntries.find((entry) => entry.path === `managed-runtime/${longRelPath}`);
  assert.ok(longEntry, "long path entry must exist in tar");
  assert.ok(longEntry.rawPrefix.length > 0, "long path must use ustar prefix");
  assert.ok(Buffer.byteLength(longEntry.rawPrefix, "utf8") <= 155);
  assert.ok(Buffer.byteLength(longEntry.rawName, "utf8") <= 100);

  const extractedDir = path.join(workspace, "extracted");
  await mkdir(extractedDir, { recursive: true });
  await extractReleaseBundle(archivePath, "tar.gz", "managed-runtime", extractedDir);
  await verifyReleaseBundle(extractedDir, fixture.manifestSha256);
  await verifyRuntimeArchive({ archive: archivePath, manifestSha256: fixture.manifestSha256 });

  const unsplittableDir = path.join(workspace, "unsplittable");
  await mkdir(unsplittableDir, { recursive: true });
  const unsplittablePath = `bin/${"a".repeat(101)}`;
  await createRuntimeFixture(unsplittableDir, [
    { path: unsplittablePath, content: Buffer.from("x"), executable: true },
  ]);
  const unsplittableOut = path.join(workspace, "unsplittable.tar.gz");
  await assert.rejects(
    packRuntimeArchive({ root: unsplittableDir, output: unsplittableOut }),
    (error) => error instanceof Error && error.message.includes(unsplittablePath),
  );
  await assert.rejects(lstat(unsplittableOut));
});

test("packRuntimeArchive refuses invalid inputs cleanly and replaces existing archives atomically", async (t) => {
  const workspace = await createTempDir(t, "validation");
  const baseFiles = [
    { path: "bin/podman.exe", content: Buffer.from("exe-bytes"), executable: true },
    { path: "share/podman/config.json", content: Buffer.from("cfg-bytes"), executable: false },
  ];

  {
    const dir = path.join(workspace, "missing-file");
    const outDir = path.join(workspace, "out-missing");
    await mkdir(dir, { recursive: true });
    await mkdir(outDir, { recursive: true });
    await createRuntimeFixture(dir, baseFiles);
    await rm(path.join(dir, "bin", "podman.exe"));
    const out = path.join(outDir, "managed-runtime-windows-x86_64.tar.gz");
    await assert.rejects(
      packRuntimeArchive({ root: dir, output: out }),
      (err) => err instanceof Error && err.message.includes("bin/podman.exe"),
    );
    assert.deepEqual(await readdir(outDir), []);
  }

  {
    const dir = path.join(workspace, "extra-file");
    const outDir = path.join(workspace, "out-extra");
    await mkdir(dir, { recursive: true });
    await mkdir(outDir, { recursive: true });
    await createRuntimeFixture(dir, baseFiles);
    await writeFile(path.join(dir, "share", "stray.txt"), "extra");
    const out = path.join(outDir, "managed-runtime-windows-x86_64.tar.gz");
    const sentinel = Buffer.from("preserve-previous-archive-bytes");
    await writeFile(out, sentinel);
    await assert.rejects(
      packRuntimeArchive({ root: dir, output: out }),
      (err) => err instanceof Error && err.message.includes("share/stray.txt"),
    );
    assert.deepEqual(await readdir(outDir), ["managed-runtime-windows-x86_64.tar.gz"]);
    assert.equal(Buffer.compare(await readFile(out), sentinel), 0);
  }

  {
    const dir = path.join(workspace, "size-mismatch");
    const outDir = path.join(workspace, "out-size");
    await mkdir(dir, { recursive: true });
    await mkdir(outDir, { recursive: true });
    await createRuntimeFixture(dir, baseFiles);
    await writeFile(path.join(dir, "bin", "podman.exe"), "different-size-bytes");
    const out = path.join(outDir, "managed-runtime-windows-x86_64.tar.gz");
    await assert.rejects(
      packRuntimeArchive({ root: dir, output: out }),
      (err) => err instanceof Error && err.message.includes("bin/podman.exe"),
    );
    assert.deepEqual(await readdir(outDir), []);
  }

  {
    const dir = path.join(workspace, "digest-mismatch");
    const outDir = path.join(workspace, "out-digest");
    await mkdir(dir, { recursive: true });
    await mkdir(outDir, { recursive: true });
    await createRuntimeFixture(dir, baseFiles);
    await writeFile(path.join(dir, "share", "podman", "config.json"), "cfg-byteZ");
    const out = path.join(outDir, "managed-runtime-windows-x86_64.tar.gz");
    await assert.rejects(
      packRuntimeArchive({ root: dir, output: out }),
      (err) => err instanceof Error && err.message.includes("share/podman/config.json"),
    );
    assert.deepEqual(await readdir(outDir), []);
  }

  if (process.platform !== "win32") {
    const dir = path.join(workspace, "symlink-entry");
    const outDir = path.join(workspace, "out-symlink");
    await mkdir(dir, { recursive: true });
    await mkdir(outDir, { recursive: true });
    await createRuntimeFixture(dir, baseFiles);
    await symlink("podman.exe", path.join(dir, "bin", "link.exe"));
    const out = path.join(outDir, "managed-runtime-windows-x86_64.tar.gz");
    await assert.rejects(
      packRuntimeArchive({ root: dir, output: out }),
      (err) => err instanceof Error && err.message.includes("bin/link.exe"),
    );
    assert.deepEqual(await readdir(outDir), []);
  }

  {
    const dir = path.join(workspace, "unsafe-path");
    const outDir = path.join(workspace, "out-unsafe");
    await mkdir(dir, { recursive: true });
    await mkdir(outDir, { recursive: true });
    const fixture = await createRuntimeFixture(dir, baseFiles);
    fixture.manifestObj.files.push({
      path: "../x",
      sha256: "00".repeat(32),
      size_bytes: 1,
      executable: false,
    });
    await writeFile(fixture.manifestPath, `${JSON.stringify(fixture.manifestObj, null, 2)}\n`);
    const out = path.join(outDir, "managed-runtime-windows-x86_64.tar.gz");
    await assert.rejects(
      packRuntimeArchive({ root: dir, output: out }),
      (err) => err instanceof Error && err.message.includes("../x"),
    );
    assert.deepEqual(await readdir(outDir), []);
  }

  {
    // The manifest lists files only: a directory with no listed file below it is not packed.
    const dir = path.join(workspace, "extra-directory");
    const outDir = path.join(workspace, "out-extra-directory");
    await mkdir(dir, { recursive: true });
    await mkdir(outDir, { recursive: true });
    await createRuntimeFixture(dir, baseFiles);
    await mkdir(path.join(dir, "share", "empty"));
    const out = path.join(outDir, "managed-runtime-windows-x86_64.tar.gz");
    await assert.rejects(
      packRuntimeArchive({ root: dir, output: out }),
      (err) => err instanceof Error && err.message.includes("unexpected directory") && err.message.includes("share/empty"),
    );
    assert.deepEqual(await readdir(outDir), []);
  }

  {
    const dir = path.join(workspace, "overwrite-existing");
    const outDir = path.join(workspace, "out-overwrite");
    await mkdir(dir, { recursive: true });
    await mkdir(outDir, { recursive: true });
    const fixture = await createRuntimeFixture(dir, baseFiles);
    const out = path.join(outDir, runtimeArchiveName("windows-x86_64"));
    await packRuntimeArchive({ root: dir, output: out });
    const firstBytes = await readFile(out);
    await packRuntimeArchive({ root: dir, output: out });
    const secondBytes = await readFile(out);
    assert.equal(Buffer.compare(firstBytes, secondBytes), 0);
    assert.deepEqual(await readdir(outDir), [runtimeArchiveName("windows-x86_64")]);

    await assert.rejects(
      verifyRuntimeArchive({ archive: out, manifestSha256: "ff".repeat(32) }),
      (err) =>
        err instanceof Error &&
        /does not match its manifest/i.test(err.message) &&
        err.message.includes("bundle") &&
        err.message.includes("manifest digest mismatch"),
    );
    await verifyRuntimeArchive({ archive: out, manifestSha256: fixture.manifestSha256 });
  }
});

test("generate-runtime-evidence CLI enforces --runtime-archive preconditions and packs verified archive", async (t) => {
  const workspace = await createTempDir(t, "cli");
  const runtimeDir = path.join(workspace, "staged");
  await mkdir(runtimeDir, { recursive: true });

  const fixture = await createRuntimeFixture(runtimeDir, [
    { path: "bin/podman.exe", content: Buffer.from("cli-exe-bytes"), executable: true },
    { path: "share/podman/config.json", content: Buffer.from('{"ok":true}\n'), executable: false },
  ]);

  const badPlatformOut = path.join(workspace, "out-linux");
  const badPlatform = spawnSync(
    process.execPath,
    [
      EVIDENCE_SCRIPT,
      "--manifest",
      fixture.manifestPath,
      "--out",
      badPlatformOut,
      "--platform",
      "linux-x86_64",
      "--runtime-archive",
    ],
    { encoding: "utf8" },
  );
  assert.notEqual(badPlatform.status, 0);
  await assert.rejects(lstat(badPlatformOut));

  const badValueOut = path.join(workspace, "out-value");
  const badValue = spawnSync(
    process.execPath,
    [
      EVIDENCE_SCRIPT,
      "--manifest",
      fixture.manifestPath,
      "--out",
      badValueOut,
      "--platform",
      "windows-x86_64",
      "--runtime-archive=yes",
    ],
    { encoding: "utf8" },
  );
  assert.notEqual(badValue.status, 0);
  await assert.rejects(lstat(badValueOut));

  const withoutFlagOut = path.join(workspace, "out-no-archive");
  const withoutFlag = spawnSync(
    process.execPath,
    [
      EVIDENCE_SCRIPT,
      "--manifest",
      fixture.manifestPath,
      "--out",
      withoutFlagOut,
      "--platform",
      "windows-x86_64",
    ],
    { encoding: "utf8" },
  );
  assert.equal(withoutFlag.status, 0, withoutFlag.stderr);
  assert.deepEqual((await readdir(withoutFlagOut)).sort(), [
    "managed-runtime-windows-x86_64.NOTICES.txt",
    "managed-runtime-windows-x86_64.cyclonedx.json",
    "managed-runtime-windows-x86_64.manifest.json",
    "managed-runtime-windows-x86_64.spdx.json",
  ]);

  const withFlagOut = path.join(workspace, "out-with-archive");
  const withFlag = spawnSync(
    process.execPath,
    [
      EVIDENCE_SCRIPT,
      "--manifest",
      fixture.manifestPath,
      "--out",
      withFlagOut,
      "--platform",
      "windows-x86_64",
      "--runtime-archive",
    ],
    { encoding: "utf8" },
  );
  assert.equal(withFlag.status, 0, withFlag.stderr);
  assert.deepEqual((await readdir(withFlagOut)).sort(), [
    "managed-runtime-windows-x86_64.NOTICES.txt",
    "managed-runtime-windows-x86_64.cyclonedx.json",
    "managed-runtime-windows-x86_64.manifest.json",
    "managed-runtime-windows-x86_64.spdx.json",
    "managed-runtime-windows-x86_64.tar.gz",
  ]);

  const archiveFile = path.join(withFlagOut, "managed-runtime-windows-x86_64.tar.gz");
  const archiveBytes = await readFile(archiveFile);
  const expectedExtracted =
    Buffer.from("cli-exe-bytes").length +
    Buffer.from('{"ok":true}\n').length +
    fixture.manifestBytes.length;
  assert.match(
    withFlag.stdout,
    new RegExp(
      `Packed managed-runtime-windows-x86_64\\.tar\\.gz: bytes=${archiveBytes.length} sha256=${sha256Hex(archiveBytes)} extracted_bytes=${expectedExtracted}`,
    ),
  );
  await verifyRuntimeArchive({ archive: archiveFile, manifestSha256: fixture.manifestSha256 });
});
