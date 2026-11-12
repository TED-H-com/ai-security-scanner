import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import test from "node:test";

test("every src/bin entry is a file declared as a Cargo binary", () => {
  const manifest = readFileSync(new URL("../../src-tauri/Cargo.toml", import.meta.url), "utf8");
  const binaries = new Set([...manifest.matchAll(/^\[\[bin\]\]\s*\n([\s\S]*?)(?=^\[|$(?![\s\S]))/gm)]
    .map(match => match[1].match(/^path\s*=\s*"([^"]+)"/m)?.[1]));
  const entries = readdirSync(new URL("../../src-tauri/src/bin/", import.meta.url), { withFileTypes: true });
  assert.ok(entries.length > 0);
  for (const entry of entries) {
    assert.ok(entry.isFile(), `${entry.name} must be a file: Tauri treats directories as binaries`);
    assert.ok(binaries.has(`src/bin/${entry.name}`), `${entry.name} must be declared in Cargo.toml`);
  }
});
