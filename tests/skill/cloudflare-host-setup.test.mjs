import assert from "node:assert/strict";
import { mkdtemp, readFile, readdir, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { setup } from "../acceptance/cloudflare-host/setup.mjs";

// No CLI is needed: rejection must precede CLI resolution or any other mutation.
test("host acceptance setup refuses a non-empty output directory unchanged", async (t) => {
  const root = await realpath(await mkdtemp(join(tmpdir(), "cloudflare-host-refusal-")));
  t.after(() => rm(root, { recursive: true, force: true }));
  const marker = join(root, "keep.txt");
  await writeFile(marker, "Keep these bytes.\n");
  await assert.rejects(setup({ cli: join(root, "missing-cli"), output: root }), /must not exist or must be empty/u);
  assert.deepEqual(await readdir(root), ["keep.txt"]);
  assert.equal(await readFile(marker, "utf8"), "Keep these bytes.\n");
});
