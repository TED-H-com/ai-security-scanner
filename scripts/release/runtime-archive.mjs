import { randomBytes } from "node:crypto";
import { lstat, mkdir, mkdtemp, open, readdir, readFile, rename, rm, unlink } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { gzipSync } from "node:zlib";

import { extractReleaseBundle, verifyReleaseBundle } from "../skill/release-bundle.mjs";
import { sha256 } from "./lib.mjs";

const ARCHIVE_ROOT = "managed-runtime";
const MAX_MANIFEST_BYTES = 262_144;
const MAX_LISTED_FILES = 127;
const MAX_RELATIVE_PATH_BYTES = 255;
const MAX_RELATIVE_PATH_COMPONENTS = 16;
const SHA256_HEX = /^[0-9a-f]{64}$/u;
const TAR_BLOCK_BYTES = 512;
const USTAR_NAME_MAX_BYTES = 100;
const USTAR_PREFIX_MAX_BYTES = 155;

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

export function runtimeArchiveName(platform) {
  assert(
    typeof platform === "string" && platform.length > 0 && !/[\\/\0]/u.test(platform),
    `invalid runtime archive platform: ${String(platform)}`,
  );
  return `managed-runtime-${platform}.tar.gz`;
}

function validateManifestRecord(record, recordsByPath) {
  assert(
    record !== null && typeof record === "object" && !Array.isArray(record),
    "runtime manifest.files entry must be an object",
  );
  const relPath = record.path;
  assert(
    typeof relPath === "string" && relPath.length > 0,
    `invalid manifest file path: ${String(relPath)}`,
  );
  assert(
    !relPath.includes("\0") && !relPath.includes("\\") && !/^[A-Za-z]:/u.test(relPath),
    `unsafe manifest file path: ${relPath}`,
  );
  const components = relPath.split("/");
  assert(
    !components.some((part) => part === "" || part === "." || part === ".."),
    `unsafe manifest file path: ${relPath}`,
  );
  assert(
    Buffer.byteLength(relPath, "utf8") <= MAX_RELATIVE_PATH_BYTES,
    `manifest file path exceeds ${MAX_RELATIVE_PATH_BYTES} bytes: ${relPath}`,
  );
  assert(
    components.length <= MAX_RELATIVE_PATH_COMPONENTS,
    `manifest file path exceeds ${MAX_RELATIVE_PATH_COMPONENTS} components: ${relPath}`,
  );
  assert(relPath !== "manifest.json", "manifest.files must not list manifest.json");
  assert(!recordsByPath.has(relPath), `duplicate manifest file path: ${relPath}`);
  assert(
    typeof record.sha256 === "string" && SHA256_HEX.test(record.sha256),
    `invalid sha256 digest for ${relPath}`,
  );
  assert(
    Number.isSafeInteger(record.size_bytes) && record.size_bytes >= 0,
    `invalid size_bytes for ${relPath}`,
  );
  assert(
    typeof record.executable === "boolean",
    `invalid executable flag for ${relPath}`,
  );
  recordsByPath.set(relPath, record);
}

async function readAndValidateManifest(root) {
  const rootStat = await lstat(root);
  assert(
    rootStat.isDirectory() && !rootStat.isSymbolicLink(),
    `runtime root must be a directory: ${root}`,
  );

  const manifestPath = path.join(root, "manifest.json");
  let manifestStat;
  try {
    manifestStat = await lstat(manifestPath);
  } catch (error) {
    if (error?.code === "ENOENT") {
      throw new Error(`missing runtime manifest.json in ${root}`);
    }
    throw error;
  }
  assert(
    manifestStat.isFile() && !manifestStat.isSymbolicLink(),
    "runtime manifest.json must be a regular, non-symlink file",
  );
  assert(
    manifestStat.size <= MAX_MANIFEST_BYTES,
    `runtime manifest.json exceeds ${MAX_MANIFEST_BYTES} bytes`,
  );

  const manifestBytes = await readFile(manifestPath);
  assert(
    manifestBytes.length <= MAX_MANIFEST_BYTES,
    `runtime manifest.json exceeds ${MAX_MANIFEST_BYTES} bytes`,
  );

  const manifest = JSON.parse(manifestBytes.toString("utf8"));
  assert(
    manifest !== null && typeof manifest === "object" && !Array.isArray(manifest),
    "runtime manifest.json must be a JSON object",
  );
  assert(
    Array.isArray(manifest.files) &&
      manifest.files.length > 0 &&
      manifest.files.length <= MAX_LISTED_FILES,
    `runtime manifest.files must contain 1..${MAX_LISTED_FILES} entries`,
  );

  const recordsByPath = new Map();
  for (const record of manifest.files) {
    validateManifestRecord(record, recordsByPath);
  }

  return {
    manifestBytes,
    manifestSha256: sha256(manifestBytes),
    recordsByPath,
  };
}

async function collectRuntimeEntries(root, manifestBytes, recordsByPath) {
  const entries = [
    { archivePath: `${ARCHIVE_ROOT}/`, isDir: true, mode: 0o755, data: null },
  ];
  const seenFiles = new Set();
  let sawManifest = false;
  let extractedBytes = 0;
  // The manifest names files only, so a directory belongs in the archive only when a listed
  // file lies below it.
  const listedDirectories = new Set();
  for (const listedPath of recordsByPath.keys()) {
    const parts = listedPath.split("/");
    for (let depth = 1; depth < parts.length; depth += 1) {
      listedDirectories.add(parts.slice(0, depth).join("/"));
    }
  }

  async function walk(currentDirFs, relativePrefix) {
    const names = await readdir(currentDirFs);
    for (const name of names) {
      const relPath = relativePrefix ? `${relativePrefix}/${name}` : name;
      const fsPath = path.join(currentDirFs, name);
      const metadata = await lstat(fsPath);
      if (metadata.isSymbolicLink() || (!metadata.isDirectory() && !metadata.isFile())) {
        throw new Error(`unsupported non-regular entry in runtime directory: ${relPath}`);
      }
      if (metadata.isDirectory()) {
        assert(
          listedDirectories.has(relPath),
          `unexpected directory in runtime directory: ${relPath}`,
        );
        entries.push({
          archivePath: `${ARCHIVE_ROOT}/${relPath}/`,
          isDir: true,
          mode: 0o755,
          data: null,
        });
        await walk(fsPath, relPath);
        continue;
      }

      if (relPath === "manifest.json") {
        assert(!sawManifest, "duplicate manifest.json in runtime directory");
        sawManifest = true;
        const currentManifestBytes = await readFile(fsPath);
        assert(
          Buffer.compare(currentManifestBytes, manifestBytes) === 0,
          "runtime manifest.json changed during packing",
        );
        entries.push({
          archivePath: `${ARCHIVE_ROOT}/manifest.json`,
          isDir: false,
          mode: 0o644,
          data: manifestBytes,
        });
        extractedBytes += manifestBytes.length;
        continue;
      }

      const record = recordsByPath.get(relPath);
      assert(record !== undefined, `unexpected file in runtime directory: ${relPath}`);
      assert(
        metadata.size === record.size_bytes,
        `runtime file size mismatch for ${relPath}: expected ${record.size_bytes}, got ${metadata.size}`,
      );
      const data = await readFile(fsPath);
      assert(
        data.length === record.size_bytes,
        `runtime file size mismatch for ${relPath}: expected ${record.size_bytes}, got ${data.length}`,
      );
      assert(
        sha256(data) === record.sha256,
        `runtime file digest mismatch for ${relPath}`,
      );
      seenFiles.add(relPath);
      extractedBytes += data.length;
      entries.push({
        archivePath: `${ARCHIVE_ROOT}/${relPath}`,
        isDir: false,
        mode: record.executable ? 0o755 : 0o644,
        data,
      });
    }
  }

  await walk(root, "");
  assert(sawManifest, "missing manifest.json in runtime directory");
  for (const expectedPath of recordsByPath.keys()) {
    assert(seenFiles.has(expectedPath), `missing runtime file listed in manifest: ${expectedPath}`);
  }

  entries.sort((left, right) =>
    Buffer.compare(Buffer.from(left.archivePath, "utf8"), Buffer.from(right.archivePath, "utf8")),
  );
  return { entries, extractedBytes };
}

function splitUstarPath(archivePath) {
  if (Buffer.byteLength(archivePath, "utf8") <= USTAR_NAME_MAX_BYTES) {
    return { name: archivePath, prefix: "" };
  }
  for (let index = archivePath.length - 2; index > 0; index -= 1) {
    if (archivePath[index] !== "/") {
      continue;
    }
    const prefix = archivePath.slice(0, index);
    const name = archivePath.slice(index + 1);
    if (
      prefix.length > 0 &&
      name.length > 0 &&
      Buffer.byteLength(prefix, "utf8") <= USTAR_PREFIX_MAX_BYTES &&
      Buffer.byteLength(name, "utf8") <= USTAR_NAME_MAX_BYTES
    ) {
      return { name, prefix };
    }
  }
  throw new Error(`archive path cannot be split into ustar prefix and name: ${archivePath}`);
}

function writeOctalField(header, offset, length, value) {
  const octal = value.toString(8);
  assert(octal.length <= length - 1, `octal field overflow at offset ${offset}: ${value}`);
  header.write(`${octal.padStart(length - 1, "0")}\0`, offset, "ascii");
}

function buildTarHeader(entry) {
  const { name, prefix } = splitUstarPath(entry.archivePath);
  const size = entry.isDir ? 0 : entry.data.length;
  assert(
    size >= 0 && size <= 0o77777777777,
    `archive entry exceeds ustar size limit: ${entry.archivePath}`,
  );

  const header = Buffer.alloc(TAR_BLOCK_BYTES);
  Buffer.from(name, "utf8").copy(header, 0);
  writeOctalField(header, 100, 8, entry.mode);
  writeOctalField(header, 108, 8, 0);
  writeOctalField(header, 116, 8, 0);
  writeOctalField(header, 124, 12, size);
  writeOctalField(header, 136, 12, 0);
  header.fill(0x20, 148, 156);
  header[156] = entry.isDir ? 0x35 : 0x30;
  header.write("ustar\0", 257, "binary");
  header.write("00", 263, "binary");
  if (prefix) {
    Buffer.from(prefix, "utf8").copy(header, 345);
  }

  let checksum = 0;
  for (let index = 0; index < TAR_BLOCK_BYTES; index += 1) {
    checksum += header[index];
  }
  header.write(`${checksum.toString(8).padStart(6, "0")}\0 `, 148, "ascii");
  return header;
}

function buildTarBuffer(entries) {
  const chunks = [];
  for (const entry of entries) {
    chunks.push(buildTarHeader(entry));
    if (!entry.isDir && entry.data.length > 0) {
      chunks.push(entry.data);
      const remainder = entry.data.length % TAR_BLOCK_BYTES;
      if (remainder !== 0) {
        chunks.push(Buffer.alloc(TAR_BLOCK_BYTES - remainder));
      }
    }
  }
  chunks.push(Buffer.alloc(TAR_BLOCK_BYTES * 2));
  return Buffer.concat(chunks);
}

export async function verifyRuntimeArchive({ archive, manifestSha256 }) {
  const tempDir = await mkdtemp(path.join(os.tmpdir(), "runtime-archive-verify-"));
  try {
    await extractReleaseBundle(archive, "tar.gz", ARCHIVE_ROOT, tempDir);
    await verifyReleaseBundle(tempDir, manifestSha256);
  } catch (error) {
    const code = typeof error?.code === "string" && error.code.length > 0 ? error.code : "unknown";
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`runtime archive does not match its manifest (${code}: ${message})`, {
      cause: error,
    });
  } finally {
    await rm(tempDir, { recursive: true, force: true });
  }
}

export async function packRuntimeArchive({ root, output }) {
  assert(typeof root === "string" && root.length > 0, "runtime root path is required");
  assert(typeof output === "string" && output.length > 0, "runtime archive output path is required");

  const { manifestBytes, manifestSha256, recordsByPath } = await readAndValidateManifest(root);
  const { entries, extractedBytes } = await collectRuntimeEntries(
    root,
    manifestBytes,
    recordsByPath,
  );
  const tarBuffer = buildTarBuffer(entries);

  const compressed = gzipSync(tarBuffer, { level: 9 });
  assert(compressed.length >= 10, "compressed runtime archive header is incomplete");
  assert(compressed[3] === 0, `unexpected gzip header flags: ${compressed[3]}`);
  assert(
    compressed[4] === 0 &&
      compressed[5] === 0 &&
      compressed[6] === 0 &&
      compressed[7] === 0,
    "unexpected gzip header mtime",
  );
  compressed[9] = 0xff;

  const outputDir = path.dirname(output);
  await mkdir(outputDir, { recursive: true });
  const temporary = path.join(
    outputDir,
    `.${path.basename(output)}.tmp-${process.pid}-${randomBytes(6).toString("hex")}`,
  );

  const handle = await open(temporary, "wx", 0o644);
  let tempExists = true;
  try {
    try {
      await handle.writeFile(compressed);
    } finally {
      await handle.close();
    }
    await verifyRuntimeArchive({ archive: temporary, manifestSha256 });
    await rename(temporary, output);
    tempExists = false;
  } finally {
    if (tempExists) {
      await unlink(temporary).catch(() => {});
    }
  }

  return {
    file: output,
    bytes: compressed.length,
    sha256: sha256(compressed),
    manifestSha256,
    extractedBytes,
    entries: entries.map((entry) => entry.archivePath),
  };
}
