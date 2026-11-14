import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { classifyChangedPaths } from "../../scripts/ci/classify-changes.mjs";

const root = fileURLToPath(new URL("../../", import.meta.url));
const tracked = execFileSync("git", ["ls-files", "-z"], { cwd: root, encoding: "utf8" })
  .split("\0").filter(Boolean);
const trackedSet = new Set(tracked);
const rustFiles = execFileSync("git", ["ls-files", "-z", "src-tauri/**/*.rs"], {
  cwd: root,
  encoding: "utf8",
}).split("\0").filter(Boolean);

// These two integration targets run in skill-native, including for this file.
// Keep the exception tied to the reader: a new Rust reader still needs rust-core.
const skillNativeReaders = new Set([
  "src-tauri/tests/cli_foreground_scan.rs",
  "src-tauri/tests/cli_runtime_prepare.rs",
]);
const skillNativeInput = "scripts/skill/bootstrap-core.mjs";

// This helper returns the repository root; its callers construct the actual
// paths separately, so the manifest expression alone cannot determine a read.
// Its callers use the report-fidelity fixture directory and a fixed list of
// source hashes, all already covered by RUST_PATHS.
const unresolvedAllowlist = [
  'src-tauri/tests/report_fidelity_baseline.rs: env!("CARGO_MANIFEST_DIR")) .parent() .unwrap() .to_owned()',
];

const reads = new Map();
const unresolved = [];

function recordRead(reader, base, literal) {
  const resolved = path.relative(root, path.resolve(root, base, literal)).split(path.sep).join("/");
  // A directory read represents every tracked file below it, including files
  // selected later by a dynamic .join() or by a recursive copy.
  const files = trackedSet.has(resolved)
    ? [resolved]
    : tracked.filter((file) => file.startsWith(`${resolved}/`));
  for (const file of files) {
    if (!reads.has(file)) reads.set(file, new Set());
    reads.get(file).add(reader);
  }
}

function unresolvedSite(reader, text) {
  unresolved.push(`${reader}: ${text.replace(/\s+/gu, " ").trim()}`);
}

for (const reader of rustFiles) {
  const source = readFileSync(path.join(root, reader), "utf8");
  for (const match of source.matchAll(/include_(?:str|bytes)!\s*\(/gu)) {
    const after = source.slice(match.index + match[0].length);
    const literal = after.match(/^\s*"([^"\\]*)"\s*,?\s*\)/u);
    if (literal) recordRead(reader, path.dirname(reader), literal[1]);
    else unresolvedSite(reader, match[0] + after.slice(0, 120).split(/[;\n]/u)[0]);
  }

  for (const match of source.matchAll(/env!\s*\(\s*"CARGO_MANIFEST_DIR"\s*\)/gu)) {
    const before = source.slice(0, match.index);
    const after = source.slice(match.index + match[0].length);
    const direct = after.match(/^\s*\)\s*\.join\(\s*"([^"\\]*)"\s*\)/u);
    const parent = after.match(/^\s*\)\s*\.parent\(\)\s*\.expect\(\s*"[^"\\]*"\s*\)\s*\.join\(\s*"([^"\\]*)"\s*\)/u);
    const concat = /\bconcat!\s*\(\s*$/u.test(before)
      ? after.match(/^\s*,\s*"\/(\.\.\/[^"\\]*)"/u)
      : null;
    if (direct) recordRead(reader, "src-tauri", direct[1]);
    else if (parent) recordRead(reader, ".", parent[1]);
    else if (concat) recordRead(reader, "src-tauri", concat[1]);
    else unresolvedSite(reader, match[0] + after.split(/[;{}]/u, 1)[0]);
  }
}

test("Rust read expressions without a static path are reviewed", () => {
  assert.deepEqual(unresolved.sort(), [...unresolvedAllowlist].sort(),
    "review new or changed unresolved Rust reads and explicitly document them");
});

test("the Rust lane runs for every tracked file its tests read", () => {
  assert.ok(rustFiles.length > 50 && reads.size > 0, "Rust read discovery found suspiciously little");
  const missing = [];
  for (const [file, readers] of reads) {
    for (const reader of readers) {
      const lanes = classifyChangedPaths([file]);
      if (lanes.rust_core && !lanes.docs_only) continue;
      if (file === skillNativeInput && skillNativeReaders.has(reader) && lanes.skill_native) continue;
      missing.push(`${file} (read by ${reader})`);
    }
  }
  assert.deepEqual(missing.sort(), [], "add these Rust test inputs to RUST_PATHS");
});
