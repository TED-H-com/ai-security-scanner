import assert from "node:assert/strict";
import test from "node:test";
import { publishedTagFromPlan, selectLocalEnginePublication } from "../../scripts/select-local-engine-publication.mjs";

const ids = ["semgrep", "trufflehog", "trivy", "grype", "kubescape", "kube-bench"];
const matrix = ids.map((engine) => ({ engine, tag: "1.0.0-1", dockerfile: `engines/images/${engine}/Dockerfile` }));
const tags = Object.fromEntries(ids.map((engine) => [engine, "1.0.0-1"]));

test("only an explicitly new immutable tag is selected after shared input edits", () => {
  const candidate = structuredClone(matrix);
  candidate[0].tag = "1.0.0-2";
  assert.deepEqual(selectLocalEnginePublication(candidate, tags).map(({ engine }) => engine), ["semgrep"]);
});

test("a pin-only follow-up selects no publication", () => {
  assert.deepEqual(selectLocalEnginePublication(matrix, tags), []);
});

test("a pending plan selects its candidate until verified publication is activated", () => {
  const plan = {
    publish_state: "publication_in_progress",
    previous_artifact: { tag: "1.0.0-1" },
    final_artifact: { tag: "1.0.0-2", digest: null },
  };
  const candidate = structuredClone(matrix);
  candidate[0].tag = plan.final_artifact.tag;
  assert.deepEqual(selectLocalEnginePublication(candidate, { ...tags, semgrep: publishedTagFromPlan(plan) })
    .map(({ engine }) => engine), ["semgrep"]);
  plan.publish_state = "published_managed_artifact";
  assert.deepEqual(selectLocalEnginePublication(candidate, { ...tags, semgrep: publishedTagFromPlan(plan) }), []);
  assert.equal(publishedTagFromPlan({ publish_state: "publication_in_progress", final_artifact: { tag: "1.0.0-1" } }), "");
  assert.throws(() => publishedTagFromPlan({ publish_state: "unknown" }), /unsupported publication plan state/u);
});

test("a manual verification or publication selects exactly one named engine", () => {
  assert.deepEqual(selectLocalEnginePublication(matrix, tags, "grype").map(({ engine }) => engine), ["grype"]);
  assert.throws(() => selectLocalEnginePublication(matrix, tags, "all"), /one known engine/u);
});

test("missing artifact records and altered matrix membership fail closed", () => {
  assert.throws(() => selectLocalEnginePublication(matrix, {}), /missing recorded artifact tag/u);
  assert.throws(() => selectLocalEnginePublication(matrix.slice(1), tags), /unexpected local engine matrix/u);
});
