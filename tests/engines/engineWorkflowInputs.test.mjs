import assert from "node:assert/strict";
import { readFile, readdir } from "node:fs/promises";
import test from "node:test";
import { parse } from "yaml";

const root = new URL("../../", import.meta.url);
const readJson = async (path) => JSON.parse(await readFile(new URL(path, root), "utf8"));

test("Prowler publication checks the patched runtime files", async () => {
  const plan = await readJson("engines/images/prowler/plan.json");
  const workflow = await readFile(new URL(".github/workflows/engine-images-cloud.yml", root), "utf8");
  const finalHashes = new Map();
  for (const patch of plan.build_recipe.patch_audit.patches) {
    for (const file of patch.files) finalHashes.set(file.path, file.after_sha256);
  }
  for (const file of plan.downstream_runtime_patches.runtime_files) {
    assert.equal(finalHashes.get(file.path), file.post_sha256, `${file.path}: sequential patch audit differs`);
    assert.ok(workflow.includes(`"${file.path}": "${file.post_sha256.slice(7)}"`),
      `${file.path}: publication would compare patched bytes to an upstream baseline`);
  }
});

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
      if (entry.expected_version !== undefined) {
        const catalog = await readJson("engines/catalog.json");
        const selected = plan.upstream_update ?? catalog.find((engine) => engine.id === entry.engine);
        assert.equal(entry.expected_version, selected.reported_version ?? selected.engine_version,
          `${file}: ${entry.engine} smoke check would require a stale native version`);
      }
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
