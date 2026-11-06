import assert from "node:assert/strict";
import { readFile, readdir } from "node:fs/promises";
import test from "node:test";
import { parse } from "yaml";

const root = new URL("../../", import.meta.url);
const readJson = async (path) => JSON.parse(await readFile(new URL(path, root), "utf8"));

test("engine workflow coordinates follow the source recipe instead of reusing a retained image tag", async () => {
  const workflows = await readdir(new URL(".github/workflows/", root));
  const checked = new Set();
  for (const file of workflows.filter((name) => /^engine-images?-.+\.yml$/u.test(name))) {
    const workflow = parse(await readFile(new URL(`.github/workflows/${file}`, root), "utf8"));
    const env = workflow.env ?? {};
    const entries = Object.entries(env)
      .filter(([key]) => key.endsWith("ENGINE_MATRIX"))
      .flatMap(([, value]) => JSON.parse(value));
    for (const job of Object.values(workflow.jobs ?? {})) {
      entries.push(...(job.strategy?.matrix?.include ?? [])
        .filter((entry) => entry.engine && entry.tag));
    }
    if (env.IMAGE_TAG) {
      entries.push({ engine: env.ENGINE ?? file.slice("engine-image-".length, -".yml".length),
        tag: env.IMAGE_TAG, epoch: env.SOURCE_DATE_EPOCH });
    }
    for (const entry of entries) {
      const plan = await readJson(`engines/images/${entry.engine}/plan.json`);
      assert.equal(entry.tag, plan.final_artifact.tag, `${file}: ${entry.engine} would build under a stale tag`);
      if (entry.epoch !== undefined) {
        assert.equal(Number(entry.epoch), plan.build_recipe.source_date_epoch,
          `${file}: SOURCE_DATE_EPOCH would override the reviewed source date`);
      }
      checked.add(entry.engine);
    }
  }
  // Every pending source update needs one explicit workflow coordinate.
  for (const engine of await readJson("engines/catalog.json")) {
    const plan = await readJson(engine.compatibility.packaging_plan);
    if (plan.upstream_update) assert.ok(checked.has(engine.id), `${engine.id}: candidate workflow is missing`);
  }
});
