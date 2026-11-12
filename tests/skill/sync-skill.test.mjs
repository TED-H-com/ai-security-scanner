import assert from "node:assert/strict";
import { mkdtemp, mkdir, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";

import { CANONICAL_SKILL, HOST_SKILLS, syncSkills } from "../../scripts/skill/sync-skill.mjs";

async function fixture(t) {
  const root = await mkdtemp(join(tmpdir(), "scanner-skill-sync-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const source = join(root, CANONICAL_SKILL);
  await mkdir(join(source, "references"), { recursive: true });
  await mkdir(join(source, "agents"));
  await writeFile(join(source, "SKILL.md"), "[Product](../../docs/product-spec.md#scope)\n[Local](references/run.md)\n");
  await writeFile(join(source, "references/run.md"), "[Guide](../../../docs/guide.md)\n");
  await writeFile(join(source, "agents/openai.yaml"), "interface:\n  display_name: Scanner\n");
  return root;
}

test("sync copies regular files, rebases repository links, and is idempotent", async (t) => {
  const root = await fixture(t);
  const first = await syncSkills({ repositoryRoot: root, check: false });
  assert.equal(first.checked_files, 6);
  assert.equal(first.differences.length, 6);
  for (const host of HOST_SKILLS) {
    assert.equal(await readFile(join(root, host, "SKILL.md"), "utf8"),
      "[Product](../../../docs/product-spec.md#scope)\n[Local](references/run.md)\n");
    assert.equal(await readFile(join(root, host, "references/run.md"), "utf8"),
      "[Guide](../../../../docs/guide.md)\n");
    assert.equal(await readFile(join(root, host, "agents/openai.yaml"), "utf8"),
      await readFile(join(root, CANONICAL_SKILL, "agents/openai.yaml"), "utf8"));
  }
  assert.deepEqual((await syncSkills({ repositoryRoot: root })).differences, []);
  assert.deepEqual((await syncSkills({ repositoryRoot: root, check: false })).differences, []);
});

test("check reports drift without changing a host copy and write repairs it", async (t) => {
  const root = await fixture(t);
  await syncSkills({ repositoryRoot: root, check: false });
  const file = join(root, HOST_SKILLS[0], "SKILL.md");
  await writeFile(file, "local drift\n");
  assert.deepEqual((await syncSkills({ repositoryRoot: root })).differences, [`${HOST_SKILLS[0]}/SKILL.md`]);
  assert.equal(await readFile(file, "utf8"), "local drift\n");
  await syncSkills({ repositoryRoot: root, check: false });
  assert.deepEqual((await syncSkills({ repositoryRoot: root })).differences, []);
});

test("sync refuses unowned extra files without removing them", async (t) => {
  const root = await fixture(t);
  await syncSkills({ repositoryRoot: root, check: false });
  const file = join(root, HOST_SKILLS[1], "notes.md");
  await writeFile(file, "retained notes\n");
  await assert.rejects(syncSkills({ repositoryRoot: root, check: false }), /Unexpected host skill files/);
  assert.equal(await readFile(file, "utf8"), "retained notes\n");
});

test("sync refuses redirected destination directories", { skip: process.platform === "win32" && "Windows symlinks require an OS privilege" }, async (t) => {
  const root = await fixture(t);
  const outside = join(root, "unowned");
  const destination = join(root, HOST_SKILLS[0]);
  await mkdir(outside);
  await mkdir(dirname(destination), { recursive: true });
  await symlink(outside, destination, "dir");
  await assert.rejects(syncSkills({ repositoryRoot: root, check: false }), /Refusing a skill symlink/);
});
