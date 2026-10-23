import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { chmod, copyFile, cp, lstat, mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

// Assemble an unpublished, self-contained Linux candidate from a completed
// desktop package and the same verified local images used by its catalog.
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const staging = path.join(root, "target/incident-release");
const snapshot = JSON.parse(await readFile(path.join(staging, "source-snapshot.json"), "utf8"));
assert.match(snapshot.version, /^\d+\.\d+\.\d+-incident\.\d{8}\.\d+$/);
assert.equal(snapshot.published, false);
assert.equal(snapshot.signed, false);
const packageFile = path.resolve(process.argv[2] ?? "");
assert(packageFile.startsWith(path.join(root, "target") + path.sep), "Supply the locally built Debian package inside target/.");
assert(packageFile.endsWith(".deb") && (await lstat(packageFile)).isFile());
const name = `ai-security-scanner-${snapshot.version}-linux-x86_64`;
const output = path.join(staging, "dist", name);
await mkdir(path.dirname(output), { recursive: true });
await mkdir(output, { recursive: false });
const app = path.join(output, "app");
await mkdir(app);
execFileSync("dpkg-deb", ["-x", packageFile, app], { stdio: "inherit" });
const executable = path.join(app, "usr/bin/ai-security-scanner");
assert((await lstat(executable)).isFile());
const cli = path.join(app, "usr/bin/ai-security-scanner-cli");
assert(execFileSync(cli, ["--version"], { encoding: "utf8" }).includes(snapshot.version), "The bundled CLI must have the candidate version.");
const runtimeRoot = path.join(app, "usr/lib/ai-security-scanner/managed-runtime");
const runtimeManifest = await readFile(path.join(runtimeRoot, "manifest.json"));
assert.equal(createHash("sha256").update(runtimeManifest).digest("hex"), snapshot.runtime_manifest_sha256);
const localImages = path.join(output, "local-images/sha256");
await mkdir(localImages, { recursive: true });
async function hashFile(file) {
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(file)) hash.update(chunk);
  return hash.digest("hex");
}
for (const id of ["trivy", "nuclei"]) {
  const record = snapshot.local_engine_evidence[id];
  assert.equal(record.published, false);
  assert.equal(record.signature_verified, false);
  assert.match(record.manifest_digest, /^sha256:[a-f0-9]{64}$/);
  const source = path.resolve(root, record.archive);
  assert(source.startsWith(staging + path.sep));
  const metadata = await lstat(source);
  assert(metadata.isFile() && !metadata.isSymbolicLink());
  assert.equal(metadata.size, record.archive_bytes);
  assert.equal(`sha256:${await hashFile(source)}`, record.archive_sha256);
  const destination = path.join(localImages, `${record.manifest_digest.slice(7)}.tar`);
  await copyFile(source, destination);
  assert.equal(`sha256:${await hashFile(destination)}`, record.archive_sha256);
}
await mkdir(path.join(output, "evidence"));
await cp(path.join(staging, "evidence/core-engines"), path.join(output, "evidence/core-engines"), { recursive: true });
for (const id of ["trivy", "nuclei"]) {
  const prefix = `target/incident-release/evidence/core-engines/${id}/`;
  const entries = Object.entries(snapshot.local_engine_evidence[id].qualification_files ?? {});
  assert(entries.length > 0, `Missing ${id} execution evidence.`);
  for (const [file, expected] of entries) {
    assert(file.startsWith(prefix) && file.slice(prefix.length).split("/").every((part) => part && part !== "." && part !== ".."));
    const copied = path.join(output, "evidence/core-engines", id, file.slice(prefix.length));
    const metadata = await lstat(copied);
    assert(metadata.isFile() && !metadata.isSymbolicLink());
    assert.equal(metadata.size, expected.size_bytes);
    assert.equal(`sha256:${await hashFile(copied)}`, expected.sha256);
  }
}
await copyFile(path.join(staging, "source-snapshot.json"), path.join(output, "evidence/source-snapshot.json"));
for (const name of ["catalog.json", "local-build-evidence.json", "qualify-trivy.py", "qualify-nuclei.py"]) {
  await copyFile(path.join(staging, "candidate-inputs", name), path.join(output, "evidence", name));
}
await cp(path.join(staging, "source/tests/fixtures/incident-triage"), path.join(output, "evidence/incident-triage"), { recursive: true });
await copyFile(path.join(staging, "source/docs/engines/incident-triage.md"), path.join(output, "evidence/incident-triage.md"));
await writeFile(path.join(output, "launch.sh"), `#!/bin/sh
set -eu
umask 077
candidate_directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
candidate_data_base=\${XDG_DATA_HOME:-"\${HOME}/.local/share"}
export AI_SECURITY_SCANNER_DATA_DIR="$candidate_data_base/dev.teddashh.ai-security-scanner-incident/${snapshot.version}"
export AI_SECURITY_SCANNER_MANAGED_RUNTIME_BUNDLE="$candidate_directory/app/usr/lib/ai-security-scanner/managed-runtime"
export AI_SECURITY_SCANNER_RELEASE_APPROVED_LOCAL_IMAGE_DIRECTORY="$candidate_directory/local-images"
mkdir -p "$AI_SECURITY_SCANNER_DATA_DIR"
chmod 700 "$AI_SECURITY_SCANNER_DATA_DIR"
exec "$candidate_directory/app/usr/bin/ai-security-scanner" "$@"
`);
await chmod(path.join(output, "launch.sh"), 0o755);
const dependencies = execFileSync("dpkg-deb", ["-f", packageFile, "Depends"], { encoding: "utf8" }).trim();
await writeFile(path.join(output, "README.txt"), `ai-security-scanner ${snapshot.version}

Linux x86_64 local incident candidate / 本機專項候選版

Start: ./launch.sh
啟動：執行 ./launch.sh，新增 IT 環境並匯入專案或套件資料，開啟「10/21–10/22 漏洞專項」後開始掃描。
專項只執行適用的 Trivy 套件檢查；排除的資產與尚未確認的漏洞會列在結果中。
Strix 原生 JSON 可從進階匯入流程加入，再從匯出頁選取已完成的執行紀錄合併 HTML／JSON。

The launcher uses a separate, version-specific data directory and bundled local OCI images.
啟動器使用獨立資料目錄及隨附的本機 OCI 引擎，不覆寫正式版的案件資料。
This is an unpublished, unsigned review candidate. Updates are disabled in this candidate.
本候選版尚未發布或簽署，且已停用自動更新。其餘檢查仍依正式目錄提供，不代表已隨包更新。
OSS Scanner is a hosted enrollment service, not a runnable local engine.
OSS Scanner 為託管申請服務，本包沒有將其當成本機引擎執行。
Six Linux ZDI candidates remain investigation-required until verified advisory mappings exist.
六項 Linux ZDI 尚待確認公告對照，不會因無命中而列為安全。

Runtime dependencies reported by the built Debian package:
${dependencies}

Verify all bundled files: sha256sum -c SHA256SUMS
Build and engine provenance: evidence/
`);
const hashes = [];
async function inventory(directory, prefix = "") {
  for (const name of (await readdir(directory)).sort()) {
    const relative = prefix + name;
    const absolute = path.join(directory, name);
    const metadata = await lstat(absolute);
    assert(!metadata.isSymbolicLink(), `Linked bundle file: ${relative}`);
    if (metadata.isDirectory()) await inventory(absolute, relative + "/");
    else {
      assert(metadata.isFile());
      hashes.push(`${await hashFile(absolute)}  ${relative}`);
    }
  }
}
await inventory(output);
await writeFile(path.join(output, "SHA256SUMS"), hashes.join("\n") + "\n");
process.stdout.write(`${output}\n`);
