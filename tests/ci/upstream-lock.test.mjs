import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { collectUpstreams, writeLock } from "../../scripts/lock-upstreams.mjs";

const git = (path, ...args) => execFileSync("git", ["-C", path, ...args], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();

function fixture(t) {
  const root = mkdtempSync(join(tmpdir(), "upstream-lock-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  mkdirSync(join(root, ".upstreams"));
  mkdirSync(join(root, "engines"));
  git(root, "init", "--quiet");
  git(root, "remote", "add", "origin", "https://github.com/example/product.git");
  return root;
}

function checkout(root, path) {
  const directory = join(root, ".upstreams", path);
  mkdirSync(directory, { recursive: true });
  git(directory, "init", "--quiet");
  git(directory, "remote", "add", "origin", `https://github.com/example/${path.split("/").at(-1)}.git`);
  writeFileSync(join(directory, "README"), "source\n");
  git(directory, "add", "README");
  git(directory, "-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "--quiet", "-m", "source");
  return directory;
}

test("locks only checkout roots, including direct repositories, without inheriting parent Git metadata", (t) => {
  const root = fixture(t);
  checkout(root, "owner/scanner");
  const direct = checkout(root, "qemu");
  mkdirSync(join(direct, "src"));
  mkdirSync(join(direct, "docs"));
  mkdirSync(join(root, ".upstreams", "cache", "archive"), { recursive: true });
  const { repositories, outputPath } = writeLock(root);
  assert.deepEqual(repositories.map(({ id }) => id), ["owner/scanner", "qemu"]);
  assert.equal(repositories[1].revision, git(direct, "rev-parse", "HEAD"));
  assert.equal(repositories[1].remote, "https://github.com/example/qemu");
  assert.deepEqual(JSON.parse(readFileSync(outputPath, "utf8")).repositories, repositories);
});

test("retains detached linked worktrees whose .git is a file", (t) => {
  const root = fixture(t);
  const source = checkout(root, "owner/scanner");
  const linked = join(root, ".upstreams", "owner", "pinned");
  git(source, "worktree", "add", "--detach", linked, "HEAD");
  const repositories = collectUpstreams(root);
  assert.deepEqual(repositories.map(({ id }) => id), ["owner/pinned", "owner/scanner"]);
  assert.equal(repositories[0].branch, "");
  assert.equal(repositories[0].revision, repositories[1].revision);
});

test("broken checkout metadata fails before replacing an existing lock", (t) => {
  const root = fixture(t);
  const broken = join(root, ".upstreams", "owner", "broken");
  mkdirSync(broken, { recursive: true });
  writeFileSync(join(broken, ".git"), "gitdir: /nonexistent/upstream-lock-test\n");
  const output = join(root, "engines", "upstreams.lock.json");
  writeFileSync(output, "original lock\n");
  assert.throws(() => writeLock(root), /Could not inspect/);
  assert.equal(readFileSync(output, "utf8"), "original lock\n");
});
