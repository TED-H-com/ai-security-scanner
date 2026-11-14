import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { parseDocument } from "yaml";

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const workflowFile = path.join(projectRoot, ".github/workflows/windows-external-evidence.yml");

async function readWorkflow() {
  const document = parseDocument(await readFile(workflowFile, "utf8"), {
    prettyErrors: true,
    strict: true,
  });
  assert.deepEqual(document.errors, []);
  return document.toJS();
}

function actionSteps(job) {
  return job.steps.filter((step) => typeof step.uses === "string");
}

test("Windows evidence importer is manual, protected, narrowly permissioned, and fully pinned", async () => {
  const workflow = await readWorkflow();
  assert.deepEqual(Object.keys(workflow.on), ["workflow_dispatch"]);
  assert.deepEqual(Object.keys(workflow.on.workflow_dispatch.inputs), [
    "candidate_run_id",
    "candidate_run_attempt",
    "candidate_artifact_id",
    "candidate_artifact_digest",
    "evidence_commit",
    "evidence_path",
  ]);
  for (const input of Object.values(workflow.on.workflow_dispatch.inputs)) {
    assert.equal(input.required, true);
    assert.equal(input.type, "string");
  }
  assert.deepEqual(workflow.permissions, { actions: "read", contents: "read" });
  assert.deepEqual(Object.keys(workflow.jobs), ["import"]);

  const job = workflow.jobs.import;
  assert.equal(job.environment, "windows-external-evidence");
  assert.equal(job["runs-on"], "ubuntu-24.04");
  assert.equal(job["timeout-minutes"], 20);
  assert.deepEqual(job.permissions, {
    actions: "read",
    attestations: "write",
    contents: "read",
    "id-token": "write",
  });

  const pins = actionSteps(job).map((step) => step.uses);
  assert.deepEqual(pins, [
    "actions/github-script@3a2844b7e9c422d3c10d287c895573f7108da1b3",
    "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
    "actions/setup-node@949feb2413d6458794dcd2491c4babbbce0c15c1",
    "actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333",
    "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
    "actions/attest-build-provenance@4d101475d8b20a2381f78447822ac1eab6504dd8",
    "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
  ]);
  for (const reference of pins) {
    assert.match(reference, /@[0-9a-f]{40}$/u);
  }
  assert.ok(!JSON.stringify(workflow).includes("secrets."));
  assert.ok(!pins.some((reference) => reference.startsWith("actions/cache@")));
});

test("Windows evidence importer binds an exact successful candidate before using inert evidence", async () => {
  const workflow = await readWorkflow();
  const job = workflow.jobs.import;
  const bind = job.steps.find((step) => step.id === "bind");
  for (const required of [
    "GET /repos/{owner}/{repo}/actions/runs/{run_id}/attempts/{attempt_number}",
    'run.event === "workflow_dispatch"',
    'run.status === "completed" && run.conclusion === "success"',
    'run.head_branch === "main"',
    'run.path === ".github/workflows/release.yml"',
    "artifact.workflow_run?.id === runId",
    "artifact.workflow_run?.head_sha === run.head_sha",
    "artifact.expired === false",
    "normalizeSha256(artifact.digest",
    'core.setOutput("candidate_artifact_digest", `sha256:${artifactDigest}`)',
    'context.ref === "refs/heads/main"',
    "windows-external-evidence.yml@refs/heads/main",
  ]) {
    assert.ok(bind.with.script.includes(required), `missing protected binding check: ${required}`);
  }

  const download = job.steps.find((step) => step.uses?.startsWith("actions/download-artifact@"));
  assert.deepEqual(download.with, {
    "artifact-ids": "${{ steps.bind.outputs.candidate_artifact_id }}",
    "github-token": "${{ github.token }}",
    repository: "${{ github.repository }}",
    "run-id": "${{ steps.bind.outputs.candidate_run_id }}",
    path: "candidate-input",
  });

  const checkouts = job.steps.filter((step) => step.uses?.startsWith("actions/checkout@"));
  assert.equal(checkouts.length, 2);
  assert.deepEqual(checkouts[0].with, {
    ref: "${{ github.workflow_sha }}",
    "persist-credentials": false,
  });
  assert.deepEqual(checkouts[1].with, {
    ref: "${{ steps.bind.outputs.evidence_commit }}",
    path: "evidence-source",
    "persist-credentials": false,
    "fetch-depth": 1,
  });
});

test("Windows evidence importer verifies the lock, calls only trusted CLI code, and seals accepted output", async () => {
  const workflow = await readWorkflow();
  const job = workflow.jobs.import;
  const shellSteps = job.steps.filter((step) => typeof step.run === "string");
  assert.ok(shellSteps.every((step) => !step.run.includes("${{ inputs.")));

  const identity = job.steps.find((step) => step.id === "candidate_identity");
  for (const required of [
    'const file = "candidate-input/release-candidate-lock.json"',
    "metadata.isSymbolicLink()",
    "metadata.size > 1024 * 1024",
    "lock.tag !== `v${lock.version}`",
    "lock.sourceCommit !== process.env.EXPECTED_CANDIDATE_COMMIT",
    'lock.publicationMode !== "public-github-release"',
  ]) {
    assert.ok(identity.run.includes(required), `missing bounded lock identity check: ${required}`);
  }

  const lockVerification = shellSteps.find((step) =>
    step.run.includes("scripts/release/release-candidate-lock.mjs verify")
  );
  for (const required of [
    "--dir candidate-input",
    "--workflow .github/workflows/release.yml",
    '--workflow-sha "${CANDIDATE_COMMIT}"',
    '--run-id "${CANDIDATE_RUN_ID}"',
    '--run-attempt "${CANDIDATE_RUN_ATTEMPT}"',
    "--job finalize-supported-artifacts",
  ]) {
    assert.ok(lockVerification.run.includes(required), `missing candidate lock binding: ${required}`);
  }

  const importStep = shellSteps.find((step) =>
    step.run.includes("scripts/release/windows-external-evidence.mjs import")
  );
  for (const required of [
    '--candidate-artifact-id "${CANDIDATE_ARTIFACT_ID}"',
    '--candidate-artifact-digest "${CANDIDATE_ARTIFACT_DIGEST}"',
    '--evidence-source-commit "${EVIDENCE_COMMIT}"',
    '--evidence-source-path "${EVIDENCE_PATH}"',
    "--importer-workflow .github/workflows/windows-external-evidence.yml",
    '--importer-workflow-sha "${GITHUB_WORKFLOW_SHA}"',
    "--importer-job import",
    "--importer-environment windows-external-evidence",
  ]) {
    assert.ok(importStep.run.includes(required), `missing accepted-evidence binding: ${required}`);
  }
  assert.ok(importStep.run.includes("git -c core.hooksPath=/dev/null -C evidence-source rev-parse"));
  assert.ok(!importStep.run.includes("npm"));

  const attestation = job.steps.find((step) => step.uses?.startsWith("actions/attest-build-provenance@"));
  assert.equal(attestation.with["subject-path"], "accepted-evidence/**/*");
  const upload = job.steps.find((step) => step.id === "upload");
  assert.equal(upload.with.name, "windows-external-evidence-${{ github.run_id }}-${{ github.run_attempt }}");
  assert.equal(upload.with.path, "accepted-evidence/");
  assert.equal(upload.with["retention-days"], 30);
  assert.equal(upload.with.overwrite, false);
  assert.equal(job.outputs.accepted_artifact_id, "${{ steps.upload.outputs.artifact-id }}");
  assert.equal(job.outputs.accepted_artifact_digest, "${{ steps.upload.outputs.artifact-digest }}");
});
