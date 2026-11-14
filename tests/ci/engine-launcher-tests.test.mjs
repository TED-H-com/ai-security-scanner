import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../../", import.meta.url));
const script = path.join(root, "scripts/ci/engine-launcher-tests.sh");
const tracked = execFileSync("git", ["ls-files", "-z"], { cwd: root, encoding: "utf8" })
  .split("\0").filter(Boolean);
const testDirectories = [...new Set(tracked
  .filter((file) => /^engines\/images\/.*(?:_test\.go|\/test_[^/]*\.py|_test\.py)$/u.test(file))
  .map((file) => path.posix.dirname(file)))].sort();
const escapeRegex = (value) => value.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");

function scriptSource() {
  assert.ok(existsSync(script), "engine launcher test script must exist");
  return readFileSync(script, "utf8");
}

test("the launcher script names every tracked launcher test directory", () => {
  const named = [...scriptSource().matchAll(/^run_launcher "([^"]+)" /gmu)]
    .map((match) => match[1]).sort();
  assert.ok(testDirectories.length > 0, "no launcher test directories found");
  assert.deepEqual(named, testDirectories);
});

test("launcher container images are pinned references already in the repository", () => {
  const references = [...scriptSource().matchAll(/\b(?:golang|python):[^\s'"\\]+/gu)]
    .map((match) => match[0]);
  assert.ok(references.length > 0, "no launcher container images found");
  const sources = tracked.filter((file) =>
    /^\.github\/workflows\/engine-image[^/]*\.yml$/u.test(file) ||
    /^engines\/images\/.*(?:^|\/)Dockerfile$/u.test(file));
  const sourceText = sources.map((file) => readFileSync(path.join(root, file), "utf8")).join("\n");
  for (const reference of references) {
    assert.match(reference, /^(?:golang|python):[\w.-]+@sha256:[a-f0-9]{64}$/u);
    assert.ok(sourceText.includes(reference), `${reference} is not in a publish workflow or Dockerfile`);
  }
});

test("launcher failures are summarized after every directory has run", () => {
  scriptSource();
  const temporary = mkdtempSync(path.join(os.tmpdir(), "launcher-tests-"));
  try {
    const calls = path.join(temporary, "calls");
    writeFileSync(path.join(temporary, "docker"),
      '#!/bin/sh\nprintf "%s\\n" "$*" >> "$LAUNCHER_CALLS"\ncase "$*" in *agentic-radar/launcher*) exit 1;; esac\n',
      { mode: 0o755 });
    writeFileSync(path.join(temporary, "node"),
      '#!/bin/sh\nprintf "node %s\\n" "$*" >> "$LAUNCHER_CALLS"\nexit 0\n',
      { mode: 0o755 });
    const result = spawnSync("bash", [script], {
      cwd: root,
      encoding: "utf8",
      env: { ...process.env, PATH: `${temporary}${path.delimiter}${process.env.PATH}`, LAUNCHER_CALLS: calls },
    });
    assert.equal(result.status, 1, result.stderr);
    const invocations = readFileSync(calls, "utf8");
    for (const directory of testDirectories) {
      assert.match(result.stdout, new RegExp(`::group::${escapeRegex(directory)}`));
      // Gitleaks needs its sibling testdata, so its publish workflow mounts
      // the parent containing both the launcher and that fixture read-only.
      const mount = directory === "engines/images/gitleaks/launcher"
        ? "engines/images/gitleaks:/gitleaks:ro"
        : `${directory}:/`;
      assert.ok(invocations.includes(mount), `${directory} was not mounted`);
      if (directory !== "engines/images/gitleaks/launcher") {
        assert.match(invocations, new RegExp(`${escapeRegex(directory)}:[^ ]+:ro`));
      }
      assert.match(result.stdout, new RegExp(`${escapeRegex(directory)}: (?:PASS|FAIL)`));
    }
    assert.match(invocations, /node scripts\/prepare-offline-engine-data\.mjs semgrep/u);
    const httpxDockerfile = readFileSync(path.join(root, "engines/images/httpx/Dockerfile"), "utf8");
    const archiveHash = httpxDockerfile.match(/ADD --checksum=sha256:([a-f0-9]{64})/u)?.[1];
    const archiveUrl = httpxDockerfile.match(/https:\/\/github\.com\/projectdiscovery\/httpx\/archive\/[^\s]+/u)?.[0];
    assert.ok(archiveHash && archiveUrl, "HTTPX pinned source was not found in its Dockerfile");
    assert.ok(invocations.includes(archiveHash) && invocations.includes(archiveUrl));
    assert.match(invocations, /HTTPX_PINNED_RUNNER=\/src\/httpx\/runner\/runner\.go go test/u);
    assert.match(result.stdout, /engines\/images\/agentic-radar\/launcher: FAIL/u);
    assert.match(result.stdout, /engines\/images\/steampipe\/installprep: PASS/u);
  } finally {
    rmSync(temporary, { recursive: true, force: true });
  }
});
