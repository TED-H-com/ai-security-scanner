import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { lstat, mkdir, open, readdir, realpath } from "node:fs/promises";
import path from "node:path";

export const INPUT_MANIFEST_SCHEMA = "ai-security-scanner.build-inputs/v1";

// Review this list whenever a production include or build-script file read is
// added. The Rust audit below refuses new embeds until they have been reviewed.
export const CORE_RESOURCE_PATHS = Object.freeze([
  "bootstrap/aws-readonly-cloudformation.yaml",
  "bootstrap/azure-readonly-arm.json",
  "bootstrap/gcp-readonly-bindings.json",
  "bootstrap/microsoft365-readonly-permissions.json",
  "docs/research/augustus-single-destination-profile.json",
  "docs/research/patches/augustus-0.14.29-machine-json.patch",
  "engines/campaigns/october-2026.json",
  "engines/catalog.json",
  "mappings/control-mappings.json",
  "providers/cloudflare/validate-document.cjs",
  "providers/cloudflare/upstream/LICENSE",
  "providers/cloudflare/upstream/skills/security-audit/report-schema.json",
  "providers/cloudflare/upstream/skills/security-audit/validate-findings.cjs",
  "providers/cloudflare/upstream/skills/security-audit/validate-coverage-ledger.cjs",
  "runtime/managed-egress-gateway.json",
]);

const CORE_FILES = ["Cargo.toml", "Cargo.lock", "src-tauri/Cargo.toml", "src-tauri/build.rs", ...CORE_RESOURCE_PATHS];
const CORE_TREES = ["src-tauri/src", "vendor/glib-0.18.5"];
// Cargo package metadata is copied, but README prose does not change the core.
const METADATA_FILES = ["README.md"];
const compare = (left, right) => left < right ? -1 : left > right ? 1 : 0;
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
const digestEntries = (files) => sha256(JSON.stringify({ schemaVersion: INPUT_MANIFEST_SCHEMA, files }));

function relativePath(value) {
  if (typeof value !== "string" || !value || value.includes("\\") || value.includes(":")) {
    throw new Error(`invalid build input path: ${value}`);
  }
  if (value.split("/").some((part) => !part || part === "." || part === ".." || /[\x00-\x1f\x7f]/.test(part))) {
    throw new Error(`invalid build input path: ${value}`);
  }
  return value;
}

async function checkedPath(root, relative) {
  relativePath(relative);
  let current = root;
  const parts = relative.split("/");
  for (const [index, part] of parts.entries()) {
    current = path.join(current, part);
    const stat = await lstat(current);
    if (stat.isSymbolicLink() || (!stat.isFile() && !stat.isDirectory())) {
      throw new Error(`build inputs cannot contain symlinks or special files: ${relative}`);
    }
    if (index < parts.length - 1 && !stat.isDirectory()) {
      throw new Error(`build input ancestor is not a directory: ${relative}`);
    }
  }
  return current;
}

async function readInput(root, relative) {
  const file = await checkedPath(root, relative);
  const handle = await open(file, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const before = await handle.stat();
    if (!before.isFile() || before.size > 64 * 1024 * 1024) {
      throw new Error(`build input must be a bounded regular file: ${relative}`);
    }
    const bytes = await handle.readFile();
    const after = await handle.stat();
    const pathname = await lstat(file);
    if (before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size
      || before.mtimeMs !== after.mtimeMs || before.ctimeMs !== after.ctimeMs
      || pathname.isSymbolicLink() || pathname.dev !== after.dev || pathname.ino !== after.ino
      || bytes.length !== after.size) {
      throw new Error(`build input changed while reading: ${relative}`);
    }
    await checkedPath(root, relative);
    return bytes;
  } finally {
    await handle.close();
  }
}

async function collectTree(root, relative, files) {
  const directory = await checkedPath(root, relative);
  if (!(await lstat(directory)).isDirectory()) throw new Error(`build source tree is not a directory: ${relative}`);
  for (const name of (await readdir(directory)).sort(compare)) {
    const child = `${relative}/${name}`;
    const file = await checkedPath(root, child);
    const stat = await lstat(file);
    if (name === ".cargo" || name === "rust-toolchain" || name === "rust-toolchain.toml") {
      throw new Error(`source-controlled Cargo configuration requires recipe review: ${child}`);
    }
    if (stat.isDirectory()) await collectTree(root, child, files);
    else files.add(child);
  }
}

async function rejectSourceConfiguration(root) {
  for (const directory of ["", "src-tauri/"]) {
    for (const name of [".cargo", "rust-toolchain", "rust-toolchain.toml"]) {
      const relative = `${directory}${name}`;
      try {
        await lstat(path.join(root, relative));
      } catch (error) {
        if (error.code === "ENOENT") continue;
        throw error;
      }
      throw new Error(`source-controlled Cargo configuration requires recipe review: ${relative}`);
    }
  }
}

// A small lexer, not a Rust parser: strings and nested comments must not create
// fake macro calls or braces. Unsupported embed expressions are rejected below.
function rustTokens(source) {
  const tokens = [];
  let offset = 0;
  while (offset < source.length) {
    const rest = source.slice(offset);
    if (/^\s/.test(rest)) { offset += 1; continue; }
    if (rest.startsWith("//")) {
      const end = source.indexOf("\n", offset);
      offset = end < 0 ? source.length : end + 1;
      continue;
    }
    if (rest.startsWith("/*")) {
      let depth = 1;
      offset += 2;
      while (depth && offset < source.length) {
        if (source.startsWith("/*", offset)) { depth += 1; offset += 2; }
        else if (source.startsWith("*/", offset)) { depth -= 1; offset += 2; }
        else offset += 1;
      }
      if (depth) throw new Error("unterminated Rust comment in build input");
      continue;
    }
    const raw = /^(?:b|c)?r(#{0,255})"/.exec(rest);
    if (raw) {
      const ending = `"${raw[1]}`;
      const end = source.indexOf(ending, offset + raw[0].length);
      if (end < 0) throw new Error("unterminated Rust raw string in build input");
      tokens.push({ value: source.slice(offset, end + ending.length), kind: "string" });
      offset = end + ending.length;
      continue;
    }
    const quoted = /^(?:b|c)?"/.exec(rest);
    if (quoted) {
      let end = offset + quoted[0].length;
      while (end < source.length && source[end] !== '"') {
        if (source[end] === "\\") end += 1;
        end += 1;
      }
      if (end === source.length) throw new Error("unterminated Rust string in build input");
      tokens.push({ value: source.slice(offset, end + 1), kind: "string" });
      offset = end + 1;
      continue;
    }
    const character = /^(?:b)?'(?:\\(?:u\{[0-9a-fA-F_]+\}|x[0-9a-fA-F]{2}|.)|[^'\\\r\n])'/u.exec(rest);
    if (character) { offset += character[0].length; continue; }
    const identifier = /^[A-Za-z_][A-Za-z_0-9]*/.exec(rest);
    if (identifier) {
      tokens.push({ value: identifier[0], kind: "identifier" });
      offset += identifier[0].length;
    } else {
      tokens.push({ value: source[offset], kind: "punctuation" });
      offset += 1;
    }
  }
  return tokens;
}

function omitTestModules(tokens) {
  const retained = [];
  const testAttribute = ["#", "[", "cfg", "(", "test", ")", "]"];
  for (let index = 0; index < tokens.length; index += 1) {
    if (testAttribute.every((value, nth) => tokens[index + nth]?.value === value)) {
      let start = index + testAttribute.length;
      if (tokens[start]?.value === "pub") {
        start += 1;
        if (tokens[start]?.value === "(") {
          while (start < tokens.length && tokens[start]?.value !== ")") start += 1;
          start += 1;
        }
      }
      if (tokens[start]?.value === "mod" && tokens[start + 1]?.kind === "identifier" && tokens[start + 2]?.value === "{") {
        let depth = 1;
        let end = start + 3;
        while (depth && end < tokens.length) {
          if (tokens[end].value === "{" && tokens[end].kind === "punctuation") depth += 1;
          if (tokens[end].value === "}" && tokens[end].kind === "punctuation") depth -= 1;
          end += 1;
        }
        if (depth) throw new Error("unterminated Rust test module in build input");
        index = end - 1;
        continue;
      }
    }
    retained.push(tokens[index]);
  }
  return retained;
}

function literalPath(token, owner) {
  if (token?.kind !== "string") throw new Error(`dynamic embedded input requires manifest review: ${owner}`);
  const raw = /^r(#{0,255})"([\s\S]*)"\1$/.exec(token.value);
  let literal;
  try { literal = raw ? raw[2] : JSON.parse(token.value); }
  catch { throw new Error(`unsupported embedded input literal: ${owner}`); }
  if (path.posix.isAbsolute(literal) || literal.includes("\\") || literal.includes(":")) {
    throw new Error(`embedded input escapes the source root: ${owner}`);
  }
  return relativePath(path.posix.normalize(path.posix.join(path.posix.dirname(owner), literal)));
}

function auditRustInputs(owner, bytes, files) {
  const tokens = omitTestModules(rustTokens(bytes.toString("utf8")));
  for (let index = 0; index < tokens.length; index += 1) {
    const token = tokens[index];
    if (["include", "include_str", "include_bytes"].includes(token.value) && tokens[index + 1]?.value === "!") {
      const opening = tokens[index + 2]?.value;
      const closing = { "(": ")", "[": "]", "{": "}" }[opening];
      const target = literalPath(tokens[index + 3], owner);
      const end = index + (tokens[index + 4]?.value === "," ? 5 : 4);
      if (!closing || tokens[end]?.value !== closing) throw new Error(`dynamic embedded input requires manifest review: ${owner}`);
      if (!files.has(target)) throw new Error(`unmanifested embedded input ${target} in ${owner}; update CORE_RESOURCE_PATHS`);
    }
    if (token.value === "#" && tokens[index + 1]?.value === "[" && tokens[index + 2]?.value === "path" && tokens[index + 3]?.value === "=") {
      const target = literalPath(tokens[index + 4], owner);
      if (!files.has(target)) throw new Error(`unmanifested Rust module path ${target} in ${owner}`);
    }
  }
}

function auditCargoPaths(owner, bytes, files) {
  const contents = bytes.toString("utf8").replace(/^\s*#.*$/gm, "");
  const fields = /(?:^|[\s,{])(?:"(path|readme|build|license-file)"|'(path|readme|build|license-file)'|(path|readme|build|license-file))\s*=\s*/g;
  for (const field of contents.matchAll(fields)) {
    const value = contents.slice(field.index + field[0].length);
    if (/^(true|false)\b/.test(value) && (field[1] ?? field[2] ?? field[3]) !== "path") continue;
    if (value.startsWith('"""') || value.startsWith("'''")) throw new Error(`multiline Cargo paths require manifest review: ${owner}`);
    const literal = /^("(?:\\.|[^"\\])*"|'[^']*')/.exec(value);
    if (!literal) throw new Error(`unsupported Cargo path requires manifest review: ${owner}`);
    let relative;
    try { relative = literal[0][0] === "'" ? literal[0].slice(1, -1) : JSON.parse(literal[0]); }
    catch { throw new Error(`unsupported Cargo path literal: ${owner}`); }
    const target = literalPath({ kind: "string", value: JSON.stringify(relative) }, owner);
    if (!files.has(target) && ![...files].some((file) => file.startsWith(`${target}/`))) {
      throw new Error(`unmanifested Cargo path ${target} in ${owner}`);
    }
  }
}

/** Return the complete, sorted native build inputs; never traverse links. */
export async function collectInputManifest(sourceRoot) {
  // A caller may select a checkout through a directory alias. Entries below its
  // resolved root must nevertheless be real files and directories.
  const root = await realpath(sourceRoot);
  if (!(await lstat(root)).isDirectory()) throw new Error("source root must be a directory");
  await rejectSourceConfiguration(root);
  const paths = new Set(CORE_FILES);
  for (const tree of CORE_TREES) await collectTree(root, tree, paths);
  const stagedPaths = new Set([...paths, ...METADATA_FILES]);
  const files = [];
  for (const relative of [...paths].sort(compare)) {
    const bytes = await readInput(root, relative);
    if (relative.endsWith(".rs")) auditRustInputs(relative, bytes, paths);
    if (path.posix.basename(relative) === "Cargo.toml") auditCargoPaths(relative, bytes, stagedPaths);
    files.push({ path: relative, sha256: sha256(bytes), size: bytes.length });
  }
  const metadataFiles = [];
  for (const relative of [...METADATA_FILES].sort(compare)) {
    const bytes = await readInput(root, relative);
    metadataFiles.push({ path: relative, sha256: sha256(bytes), size: bytes.length });
  }
  return { schemaVersion: INPUT_MANIFEST_SCHEMA, inputDigest: digestEntries(files), files, metadataDigest: digestEntries(metadataFiles), metadataFiles };
}

/** Copy exactly the reviewed manifest into a new or existing empty directory. */
export async function stageInputSnapshot(sourceRoot, destination, manifest) {
  const current = await collectInputManifest(sourceRoot);
  if (JSON.stringify(current) !== JSON.stringify(manifest)) throw new Error("build input manifest no longer matches the source");
  const root = await realpath(sourceRoot);
  try { await mkdir(destination, { mode: 0o700 }); }
  catch (error) { if (error.code !== "EEXIST") throw error; }
  const stat = await lstat(destination);
  if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error("snapshot destination must be a real directory");
  if ((await readdir(destination)).length) throw new Error("snapshot destination must be empty");
  const target = await realpath(destination);
  if (target === root || target.startsWith(`${root}${path.sep}`)) throw new Error("build snapshot must be outside its source root");
  for (const entry of [...manifest.files, ...manifest.metadataFiles]) {
    const bytes = await readInput(root, entry.path);
    if (bytes.length !== entry.size || sha256(bytes) !== entry.sha256) throw new Error(`build input changed before staging: ${entry.path}`);
    const parts = entry.path.split("/");
    parts.pop();
    let parent = target;
    for (const part of parts) {
      parent = path.join(parent, part);
      try { await mkdir(parent, { mode: 0o700 }); }
      catch (error) { if (error.code !== "EEXIST") throw error; }
      const directory = await lstat(parent);
      if (directory.isSymbolicLink() || !directory.isDirectory()) throw new Error("snapshot destination changed while staging");
    }
    const handle = await open(path.join(target, entry.path), constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW ?? 0), 0o600);
    try { await handle.writeFile(bytes); }
    finally { await handle.close(); }
  }
  if (JSON.stringify(await collectInputManifest(sourceRoot)) !== JSON.stringify(manifest)) throw new Error("build inputs changed while staging");
  return { destination: target, inputDigest: manifest.inputDigest };
}
