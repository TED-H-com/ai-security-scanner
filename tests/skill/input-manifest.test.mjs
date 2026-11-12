import assert from "node:assert/strict";
import { mkdtemp, mkdir, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { collectInputManifest, CORE_RESOURCE_PATHS, stageInputSnapshot } from "../../scripts/skill/input-manifest.mjs";

const repository = fileURLToPath(new URL("../..", import.meta.url));

async function put(root, name, contents = "fixture\n") {
  await mkdir(path.dirname(path.join(root, name)), { recursive: true });
  await writeFile(path.join(root, name), contents);
}

async function fixture(t) {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "scanner-build-inputs-"));
  t.after(() => rm(temporary, { recursive: true, force: true }));
  const source = path.join(temporary, "source");
  for (const name of ["Cargo.toml", "Cargo.lock", "src-tauri/Cargo.toml", "README.md", "vendor/glib-0.18.5/Cargo.toml", ...CORE_RESOURCE_PATHS]) {
    await put(source, name);
  }
  await put(source, "src-tauri/build.rs", "fn main() {}\n");
  await put(source, "src-tauri/src/lib.rs", 'const CATALOG: &str = include_str!("../../engines/catalog.json");\n');
  await put(source, "vendor/glib-0.18.5/src/lib.rs", "pub fn patched() {}\n");
  return { source, temporary };
}

test("repository manifest covers current production embeds and omits unrelated source", async () => {
  const manifest = await collectInputManifest(repository);
  const names = new Set(manifest.files.map((file) => file.path));
  for (const required of [...CORE_RESOURCE_PATHS, "src-tauri/src/publication_origins.rs", "vendor/glib-0.18.5/src/lib.rs", "vendor/glib-0.18.5/README.md"]) {
    assert.ok(names.has(required), required);
  }
  assert.ok(!names.has("README.md"));
  assert.ok(![...names].some((name) => name.startsWith("skills/") || (name.startsWith("providers/") && !CORE_RESOURCE_PATHS.includes(name)) || name.startsWith("src-tauri/tests/")));
  assert.deepEqual(manifest.files.map((file) => file.path), [...names].sort());
  assert.match(manifest.inputDigest, /^[a-f0-9]{64}$/);
  assert.ok(manifest.files.every((file) => Number.isSafeInteger(file.size) && /^[a-f0-9]{64}$/.test(file.sha256)));
});

test("every embedded resource, Rust source, new source file, lock, and vendored source invalidates the core", async (t) => {
  const { source } = await fixture(t);
  let previous = await collectInputManifest(source);
  for (const file of [...CORE_RESOURCE_PATHS, "Cargo.lock", "src-tauri/build.rs", "src-tauri/src/lib.rs", "vendor/glib-0.18.5/src/lib.rs", "src-tauri/src/new_module.rs"]) {
    await put(source, file, file.endsWith(".rs") ? "// new reviewed native input\n" : "updated input\n");
    const next = await collectInputManifest(source);
    assert.notEqual(next.inputDigest, previous.inputDigest, file);
    previous = next;
  }
});

test("skill, provider, documentation, and test-fixture prose leave the core key stable", async (t) => {
  const { source } = await fixture(t);
  const before = await collectInputManifest(source);
  for (const name of ["skills/ai-security-scanner/SKILL.md", "providers/cloudflare/prompts.md", "providers/cloudflare/upstream/skills/security-audit/HUNTING.md", "providers/cloudflare/upstream.lock.json", "docs/product-spec.md", "README.md", "src-tauri/tests/fixtures/result.json"]) {
    await put(source, name, "new non-core prose\n");
  }
  const after = await collectInputManifest(source);
  assert.equal(after.inputDigest, before.inputDigest);
  assert.notEqual(after.metadataDigest, before.metadataDigest);
  assert.deepEqual(after.files, before.files);
});

test("staging copies exactly verified inputs plus Cargo metadata into a clean destination", async (t) => {
  const { source, temporary } = await fixture(t);
  await put(source, "skills/ai-security-scanner/SKILL.md");
  await put(source, "target/not-a-build-input");
  const manifest = await collectInputManifest(source);
  const destination = path.join(temporary, "snapshot");
  await mkdir(destination);
  await stageInputSnapshot(source, destination, manifest);
  assert.deepEqual(await collectInputManifest(destination), manifest);
  assert.equal(await readFile(path.join(destination, "README.md"), "utf8"), "fixture\n");
  await assert.rejects(readFile(path.join(destination, "skills/ai-security-scanner/SKILL.md")), { code: "ENOENT" });
  await assert.rejects(readFile(path.join(destination, "target/not-a-build-input")), { code: "ENOENT" });
  await assert.rejects(stageInputSnapshot(source, destination, manifest), /must be empty/);
});

test("changed source and forged path manifests are refused before staging", async (t) => {
  const { source, temporary } = await fixture(t);
  const manifest = await collectInputManifest(source);
  const malicious = structuredClone(manifest);
  malicious.files[0].path = "../escaped";
  await assert.rejects(stageInputSnapshot(source, path.join(temporary, "bad"), malicious), /no longer matches/);
  await put(source, "engines/catalog.json", "changed\n");
  await assert.rejects(stageInputSnapshot(source, path.join(temporary, "stale"), manifest), /no longer matches/);
});

test("unreviewed and dynamic Rust embeds and escaping module paths fail closed", async (t) => {
  const { source } = await fixture(t);
  await put(source, "new-policy.json");
  for (const sourceCode of [
    'const POLICY: &str = include_str!("../../new-policy.json");',
    'const POLICY: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/policy"));',
    'include!("../../new-policy.json");',
    '#[path = "../../../escape.rs"] mod external;',
    'const POLICY: &str = include_str!("../../../escape");',
    'const POLICY: &str = include_str!("/absolute");',
  ]) {
    await put(source, "src-tauri/src/lib.rs", sourceCode);
    await assert.rejects(collectInputManifest(source), /unmanifested|dynamic embedded|invalid build input|escapes/);
  }
});

test("Cargo path dependencies must remain in the controlled snapshot", async (t) => {
  const { source } = await fixture(t);
  await put(source, "Cargo.toml", '[patch.crates-io]\nglib = { path = "vendor/glib-0.18.5" }\n');
  await put(source, "src-tauri/Cargo.toml", '[package]\nreadme = "../README.md"\n');
  await collectInputManifest(source);
  for (const value of ['"../outside"', '"new-unmanifested-vendor"', "'''../outside'''", '"/absolute"']) {
    await put(source, "Cargo.toml", `[dependencies]\nunknown = { path = ${value} }\n`);
    await assert.rejects(collectInputManifest(source), /unmanifested Cargo path|invalid build input|manifest review|escapes/);
  }
});

test("lexer ignores comments, strings and exact test modules without hiding later production embeds", async (t) => {
  const { source } = await fixture(t);
  const code = `
    /* nested /* include_str!("missing") */ comment */
    const EXAMPLE: &str = r###"include_str!("missing"); }"###;
    const BRACE: char = '}';
    #[cfg(test)]
    pub(crate) mod tests {
      const TEST: &str = include_str!("missing-fixture");
      fn test() { let x = r#"}"#; let y = '{'; }
    }
    const INCLUDED: &str = include_str!(r#"../../engines/catalog.json"#);
  `;
  await put(source, "src-tauri/src/lib.rs", code);
  await collectInputManifest(source);
  await put(source, "src-tauri/src/lib.rs", `${code}\nconst HIDDEN: &str = include_str!("missing-policy");`);
  await assert.rejects(collectInputManifest(source), /unmanifested embedded/);
});

test("file links, directory links, and special files cannot enter a native snapshot", async (t) => {
  const { source, temporary } = await fixture(t);
  await put(temporary, "outside.rs");
  const linkedFile = path.join(source, "src-tauri/src/linked.rs");
  try { await symlink(path.join(temporary, "outside.rs"), linkedFile); }
  catch (error) {
    if (process.platform === "win32" && error.code === "EPERM") { t.skip("host does not permit creating test symlinks"); return; }
    throw error;
  }
  await assert.rejects(collectInputManifest(source), /symlinks or special/);
  await rm(linkedFile);
  await symlink(temporary, path.join(source, "src-tauri/src/linked-dir"), "junction");
  await assert.rejects(collectInputManifest(source), /symlinks or special/);
  await rm(path.join(source, "src-tauri/src/linked-dir"));
  if (process.platform !== "win32") {
    const made = spawnSync("mkfifo", [path.join(source, "src-tauri/src/pipe")]);
    assert.equal(made.status, 0);
    await assert.rejects(collectInputManifest(source), /symlinks or special/);
  }
});

test("source Cargo configuration and toolchain overrides require explicit recipe review", async (t) => {
  const { source } = await fixture(t);
  for (const [name, cleanup] of [
    [".cargo/config.toml", ".cargo"],
    ["src-tauri/.cargo/config", "src-tauri/.cargo"],
    ["rust-toolchain.toml", "rust-toolchain.toml"],
    ["vendor/glib-0.18.5/.cargo/config", "vendor/glib-0.18.5/.cargo"],
  ]) {
    await put(source, name);
    await assert.rejects(collectInputManifest(source), /configuration requires recipe review/);
    await rm(path.join(source, cleanup), { recursive: true });
  }
});
