import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, readdir, realpath, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, sep } from "node:path";
import test from "node:test";
import { parseArguments, sameSnapshotReference, verifyRestore } from "../acceptance/cloudflare-host/verify-restore.mjs";

async function fixture(t) {
  const root = await realpath(await mkdtemp(join(tmpdir(), "cf-restore-refusal-")));
  t.after(() => rm(root, { recursive: true, force: true }));
  return root;
}
function options(root, output) {
  return { cli: join(root, "missing-cli"), context: join(root, "missing-context"),
    archive: join(root, "missing-archive"), output };
}

test("restore verifier requires all four arguments and refuses unknown, duplicate and missing values", () => {
  const valid = ["--cli", "CLI", "--context", "CONTEXT", "--archive", "ARCHIVE", "--output", "OUTPUT"];
  assert.deepEqual(parseArguments(valid), { cli: "CLI", context: "CONTEXT", archive: "ARCHIVE", output: "OUTPUT" });
  for (const args of [[], valid.slice(0, -2), valid.slice(0, -1), [...valid, "--cli", "OTHER"],
    [...valid, "--unknown", "VALUE"], ["--cli", "--context", ...valid.slice(4)]]) {
    assert.throws(() => parseArguments(args), /Usage:/u);
  }
});

test("restore verifier matches snapshot references by identity, not key order", () => {
  const caseRead = { snapshot_id: "s1", source_case_revision: 13, relative_path: "c/report-snapshots/s1.json",
    sha256: "a".repeat(64), byte_length: 64632 };
  const scanRead = { byte_length: 64632, relative_path: "c/report-snapshots/s1.json", sha256: "a".repeat(64),
    snapshot_id: "s1", source_case_revision: 13 };
  assert.equal(sameSnapshotReference(caseRead, scanRead), true);
  for (const field of Object.keys(caseRead)) {
    const changed = { ...scanRead, [field]: field === "byte_length" || field === "source_case_revision" ? 1 : "other" };
    assert.equal(sameSnapshotReference(caseRead, changed), false, field);
  }
  assert.equal(sameSnapshotReference({}, {}), false);
});

test("restore verifier refuses missing options without creating output", async (t) => {
  const root = await fixture(t);
  await assert.rejects(verifyRestore({ output: join(root, "new") }), /Usage:/u);
  assert.deepEqual(await readdir(root), []);
});

test("restore verifier refuses non-empty output unchanged before opening context or CLI", async (t) => {
  const root = await fixture(t);
  const marker = join(root, "keep.txt");
  await writeFile(marker, "Keep these bytes.\n");
  await assert.rejects(verifyRestore(options(root, root)), /must not exist or must be empty/u);
  assert.deepEqual(await readdir(root), ["keep.txt"]);
  assert.equal(await readFile(marker, "utf8"), "Keep these bytes.\n");
});

test("restore verifier refuses relative, noncanonical, missing-parent and file outputs", async (t) => {
  const root = await fixture(t);
  const marker = join(root, "file");
  await writeFile(marker, "preserve");
  for (const output of ["relative", `${root}${sep}.${sep}new`, join(root, "missing", "new"), marker]) {
    await assert.rejects(verifyRestore(options(root, output)), /canonical|ENOENT/u);
  }
  assert.deepEqual(await readdir(root), ["file"]);
  assert.equal(await readFile(marker, "utf8"), "preserve");
});

test("restore verifier refuses linked output and linked parents without changing their target", async (t) => {
  const root = await fixture(t);
  const target = join(root, "target");
  await mkdir(target);
  const link = join(root, "link");
  await symlink(target, link, process.platform === "win32" ? "junction" : "dir");
  await assert.rejects(verifyRestore(options(root, link)), /canonical/u);
  await assert.rejects(verifyRestore(options(root, join(link, "new"))), /canonical/u);
  assert.deepEqual(await readdir(target), []);
});

test("restore verifier refuses output inside original data before any write or CLI resolution", async (t) => {
  const root = await fixture(t);
  const data = join(root, "data");
  await mkdir(data);
  const context = join(root, "host-context.json");
  await writeFile(context, JSON.stringify({ data_directory: data, case_id: "case-one" }));
  await assert.rejects(verifyRestore({ ...options(root, join(data, "new")), context }), /must be separate/u);
  assert.deepEqual(await readdir(data), []);
});
