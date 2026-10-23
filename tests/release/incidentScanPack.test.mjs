import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { publishedInstallers } from "../../docs/incident-pack.js";
import { incidentScanPackForRelease } from "../../scripts/release/incident-scan-pack.mjs";

const pack = JSON.parse(readFileSync(new URL("../../docs/incident-pack.json", import.meta.url)));
const asset = (suffix, extra = {}) => ({
  name: `ai-security-scanner_${pack.app_version}_${suffix}`,
  browser_download_url: `https://github.com/${pack.repository}/releases/download/${pack.release_tag}/ai-security-scanner_${pack.app_version}_${suffix}`,
  size: 1024,
  state: "uploaded",
  ...extra,
});
const release = (assets, extra = {}) => ({
  tag_name: pack.release_tag, draft: false, published_at: "2026-10-22T19:00:00Z", assets, ...extra,
});

test("incident downloads expose only uploaded installers from the exact published release", () => {
  const valid = [asset("universal.dmg"), asset("x64-setup.exe"), asset("amd64.deb")];
  assert.deepEqual(publishedInstallers(release(valid), pack), valid);
  for (const extra of [{ draft: true }, { published_at: null }, { tag_name: "v0.5.2" }]) {
    assert.deepEqual(publishedInstallers(release(valid, extra), pack), []);
  }
  assert.deepEqual(publishedInstallers(release([
    asset("universal.dmg", { size: 0 }),
    asset("x64-setup.exe", { state: "new" }),
    asset("amd64.deb", { browser_download_url: "https://example.com/package.deb" }),
    asset("amd64.deb", { browser_download_url: "invalid" }),
    asset("amd64.deb", { browser_download_url: `https://github.com/${pack.repository}/releases/download/v0.5.2/package.deb` }),
    asset("universal.dmg", { name: "not-an-installer.dmg" }),
  ]), pack), []);
});

test("the incident pack retains its release identity and shared report contract", async () => {
  const product = JSON.parse(readFileSync(new URL("../../package.json", import.meta.url)));
  const native = JSON.parse(readFileSync(new URL("../../src-tauri/tauri.conf.json", import.meta.url)));
  assert.equal(native.version, product.version);
  assert.equal(pack.release_tag, `v${pack.app_version}`);
  const sourceCommit = "a".repeat(40);
  assert.equal((await incidentScanPackForRelease(pack.app_version, sourceCommit)).source_commit, sourceCommit);
  assert.equal(await incidentScanPackForRelease(`${pack.app_version}-other`, sourceCommit), null);
  assert.deepEqual(pack.profiles, ["standard", "october-2026"]);
  assert.equal(pack.report.model, "beginner_master_report");
  assert.deepEqual(pack.report.formats, ["html", "json"]);
  assert.equal(pack.report.certification, false);
});
