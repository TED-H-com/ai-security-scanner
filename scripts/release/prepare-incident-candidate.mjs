import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { cp, lstat, mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

// Make a reviewable local candidate without replacing the stable catalog or
// manufacturing publication/signature records. Image evidence is produced by
// actual isolated builds and fixture runs before this script may be used.
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const version = process.argv[2];
assert.match(version ?? "", /^\d+\.\d+\.\d+-incident\.\d{8}\.\d+$/, "Supply an incident prerelease version.");
const releaseRoot = path.join(root, "target/incident-release");
const inputs = path.join(releaseRoot, "candidate-inputs");
const output = path.join(releaseRoot, "source");
async function hashFile(file) {
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(file)) hash.update(chunk);
  return hash.digest("hex");
}
const catalog = JSON.parse(await readFile(path.join(inputs, "catalog.json"), "utf8"));
const evidence = JSON.parse(await readFile(path.join(inputs, "local-build-evidence.json"), "utf8"));
for (const id of ["trivy", "nuclei"]) {
  const record = evidence[id];
  const engine = catalog.find((entry) => entry.id === id);
  assert(record && engine, `Missing ${id} candidate inputs.`);
  assert.equal(record.published, false);
  assert.equal(record.signature_verified, false);
  assert.match(record.manifest_digest, /^sha256:[a-f0-9]{64}$/);
  assert.equal(engine.image.digest, record.manifest_digest);
  assert(Number.isInteger(record.verified_content_addressed_blobs) && record.verified_content_addressed_blobs > 0);
  const archive = path.resolve(root, record.archive);
  assert(archive.startsWith(releaseRoot + path.sep), "Candidate archives must remain inside their staging directory.");
  const metadata = await lstat(archive);
  assert(metadata.isFile() && !metadata.isSymbolicLink());
  assert.equal(metadata.size, record.archive_bytes);
  assert.equal(`sha256:${await hashFile(archive)}`, record.archive_sha256);
  const qualificationRoot = path.join(releaseRoot, "evidence/core-engines", id);
  const qualificationFiles = Object.entries(record.qualification_files ?? {});
  assert(qualificationFiles.length > 0, `Missing ${id} execution evidence.`);
  for (const [file, expected] of qualificationFiles) {
    const absolute = path.resolve(root, file);
    assert(absolute.startsWith(qualificationRoot + path.sep));
    const metadata = await lstat(absolute);
    assert(metadata.isFile() && !metadata.isSymbolicLink());
    assert.equal(metadata.size, expected.size_bytes);
    assert.equal(`sha256:${await hashFile(absolute)}`, expected.sha256);
  }
}
try {
  await lstat(output);
  throw new Error("Candidate source already exists; use a new staging directory before regenerating it.");
} catch (error) {
  if (error.code !== "ENOENT") throw error;
}
const includedRoots = new Set(["src", "src-tauri", "scripts", "engines", "schemas", "mappings", "vendor", "public", "tests", "docs", "runtime", "bootstrap", "cloud-setup", ".github"]);
const includedFiles = new Set(["Cargo.toml", "Cargo.lock", "package.json", "package-lock.json", "index.html", "tsconfig.json", "tsconfig.app.json", "tsconfig.node.json", "vite.config.ts", "vitest.config.ts", "LICENSE", "THIRD_PARTY.md", "AGENTS.md", "DESIGN.md", "README.md", "README.zh-TW.md", "README.ja.md"]);
const sourcePaths = execFileSync("git", ["ls-files", "-z", "--cached", "--others", "--exclude-standard"], { cwd: root, maxBuffer: 16 * 1024 * 1024 })
  .toString().split("\0").filter(Boolean)
  .filter((file) => !file.startsWith("runtime/staged/"))
  .filter((file) => includedRoots.has(file.split("/")[0]) || includedFiles.has(file));
await mkdir(output, { recursive: false });
for (const file of new Set(sourcePaths)) {
  const source = path.join(root, file);
  const metadata = await lstat(source);
  assert(metadata.isFile() && !metadata.isSymbolicLink(), `Source must be a regular file: ${file}`);
  const destination = path.join(output, file);
  await mkdir(path.dirname(destination), { recursive: true });
  await cp(source, destination, { errorOnExist: true, force: false, preserveTimestamps: true });
}
await cp(path.join(inputs, "catalog.json"), path.join(output, "engines/catalog.json"));
const oldRevision = "24858b4bfabfa86f0bcfd36aea24fb535152b012";
const plan = JSON.parse(await readFile(path.join(output, "engines/images/nuclei/plan.json"), "utf8"));
const revision = plan.build_recipe.templates.revision;
assert.match(revision ?? "", /^[a-f0-9]{40}$/);
for (const file of ["src/websiteQuickProfile.ts", "src-tauri/src/case_service.rs", "src-tauri/src/beginner_report.rs", "tests/frontend/websiteQuickProfile.test.ts", "tests/component/coverageConciseBoundaries.test.tsx"]) {
  const destination = path.join(output, file);
  const source = await readFile(destination, "utf8");
  assert(source.includes(oldRevision), `Missing the stable revision in ${file}.`);
  await writeFile(destination, source.replaceAll(oldRevision, revision));
}
for (const file of ["package.json", "package-lock.json", "src-tauri/tauri.conf.json"]) {
  const destination = path.join(output, file);
  const document = JSON.parse(await readFile(destination, "utf8"));
  document.version = version;
  if (document.packages?.[""]) document.packages[""].version = version;
  if (document.release) document.release = { channel: "prerelease", target: version };
  if (file.endsWith("tauri.conf.json")) {
    document.bundle.createUpdaterArtifacts = false;
    document.plugins.updater.endpoints = [];
  }
  await writeFile(destination, JSON.stringify(document, null, 2) + "\n");
}
for (const file of ["src-tauri/Cargo.toml", "Cargo.lock"]) {
  const destination = path.join(output, file);
  const source = await readFile(destination, "utf8");
  const updated = source.replace(/(name = "ai-security-scanner"\r?\nversion = ")[^"]+("\r?\n)/, `$1${version}$2`);
  assert.notEqual(updated, source, `Missing package version in ${file}.`);
  await writeFile(destination, updated);
}
const updaterPath = path.join(output, "src/services/appUpdater.ts");
const updaterSource = await readFile(updaterPath, "utf8");
const versionRead = "  const currentVersion = await getVersion();";
assert.equal(updaterSource.split(versionRead).length, 2);
await writeFile(updaterPath, updaterSource.replace(versionRead,
  `${versionRead}\n  // This isolated, unpublished candidate has no update channel.\n  if (currentVersion === ${JSON.stringify(version)}) return { phase: "unavailable", currentVersion };`));
await cp(path.join(root, "runtime/staged/managed-runtime"), path.join(output, "runtime/staged/managed-runtime"), { recursive: true });
await mkdir(path.join(output, "node_modules"));
const files = [];
for (const file of new Set(sourcePaths)) {
  const bytes = await readFile(path.join(output, file));
  files.push({ path: file, bytes: bytes.length, sha256: createHash("sha256").update(bytes).digest("hex") });
}
const runtimeRelative = "runtime/staged/managed-runtime";
const runtimeRoot = path.join(output, runtimeRelative);
const runtimeManifest = JSON.parse(await readFile(path.join(runtimeRoot, "manifest.json"), "utf8"));
const declaredRuntimeFiles = new Map();
for (const entry of runtimeManifest.files) {
  assert(typeof entry.path === "string" && !entry.path.includes("\\") && !entry.path.startsWith("/")
    && entry.path.split("/").every((part) => part && part !== "." && part !== ".."), "Invalid runtime payload path.");
  assert(!declaredRuntimeFiles.has(entry.path), "Duplicate runtime payload path.");
  declaredRuntimeFiles.set(entry.path, entry);
}
async function inventoryRuntime(directory, prefix = "") {
  for (const name of await readdir(directory)) {
    const relative = prefix + name;
    const absolute = path.join(directory, name);
    const metadata = await lstat(absolute);
    assert(!metadata.isSymbolicLink(), `Linked runtime payload: ${relative}`);
    if (metadata.isDirectory()) { await inventoryRuntime(absolute, relative + "/"); continue; }
    assert(metadata.isFile(), `Non-file runtime payload: ${relative}`);
    const sha256 = await hashFile(absolute);
    if (relative !== "manifest.json" && relative !== ".gitkeep") {
      const declared = declaredRuntimeFiles.get(relative);
      assert(declared, `Undeclared runtime payload: ${relative}`);
      assert.equal(metadata.size, declared.size_bytes, `Runtime size mismatch: ${relative}`);
      assert.equal(sha256, declared.sha256, `Runtime hash mismatch: ${relative}`);
      if (declared.executable) assert(metadata.mode & 0o111, `Runtime executable bit missing: ${relative}`);
      declaredRuntimeFiles.delete(relative);
    }
    files.push({ path: `${runtimeRelative}/${relative}`, bytes: metadata.size, sha256 });
  }
}
await inventoryRuntime(runtimeRoot);
assert.equal(declaredRuntimeFiles.size, 0, "Runtime payload has missing declared files.");
files.sort((a, b) => a.path.localeCompare(b.path, "en"));
const manifest = {
  schema_version: 1, version, created_at: new Date().toISOString(),
  source_base_commit: execFileSync("git", ["rev-parse", "HEAD"], { cwd: root }).toString().trim(),
  source_kind: "working_tree_snapshot", published: false, signed: false,
  runtime_manifest_sha256: createHash("sha256").update(await readFile(path.join(output, "runtime/staged/managed-runtime/manifest.json"))).digest("hex"),
  local_engine_evidence: evidence, files,
};
await writeFile(path.join(releaseRoot, "source-snapshot.json"), JSON.stringify(manifest, null, 2) + "\n");
process.stdout.write(`Prepared ${version}: ${output}\n`);
