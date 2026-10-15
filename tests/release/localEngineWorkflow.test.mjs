import assert from "node:assert/strict";
import test from "node:test";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import path from "node:path";
import { parse } from "yaml";

test("a failed native Semgrep validation stops its own publication and leaves sibling jobs independent", () => {
  const workflow = parse(readFileSync(new URL("../../.github/workflows/engine-images-local-k8s.yml", import.meta.url), "utf8"));
  const publish = workflow.jobs.publish;
  assert.ok(publish.needs.includes("semgrep-native-verify"));
  assert.match(publish.if, /always\(\)/u);
  assert.doesNotMatch(publish.if, /needs\.semgrep-native-verify\.result/u);
  assert.deepEqual(publish.steps[0], {
    name: "Require both native Semgrep verifications before publication",
    if: "matrix.engine == 'semgrep'",
    env: { NATIVE_RESULT: "${{ needs.semgrep-native-verify.result }}" },
    run: 'test "${NATIVE_RESULT}" = success',
  });
  assert.equal(workflow.jobs["semgrep-native-verify"].if, "contains(fromJSON(needs.changes.outputs.engines), 'semgrep')");
});

test("manual native verification cannot publish an image, rules cache or build-record artifact", () => {
  const workflow = parse(readFileSync(new URL("../../.github/workflows/engine-images-local-k8s.yml", import.meta.url), "utf8"));
  assert.equal(workflow.on.workflow_dispatch.inputs.mode.default, "verify");
  assert.match(workflow.jobs.publish.if, /inputs\.mode != 'verify'/u);
  const native = workflow.jobs["semgrep-native-verify"];
  assert.equal(native.env.DOCKER_BUILD_RECORD_UPLOAD, "false");
  const build = native.steps.find((step) => step.uses?.startsWith("docker/build-push-action@"));
  assert.equal(build.with.push, false);
  assert.match(build.with["cache-to"], /inputs\.mode != 'verify'/u);
  const upload = native.steps.find((step) => step.uses?.startsWith("actions/upload-artifact@"));
  assert.deepEqual(upload.with.path.trim().split("\n"), [
    "package-evidence/semgrep-native-${{ matrix.arch }}/verification.json",
    "package-evidence/semgrep-native-${{ matrix.arch }}/*.log",
    "package-evidence/semgrep-native-${{ matrix.arch }}/*/semgrep.json",
  ]);
  for (const name of ["Export the exact tested native image", "Transfer the tested native image to publication"]) {
    const step = native.steps.find((candidate) => candidate.name === name);
    assert.equal(step.if, "success() && inputs.mode != 'verify'");
    assert.ok(native.steps.indexOf(step) > native.steps.findIndex((candidate) => candidate.name === "Verify complete result union, source attachment and runtime boundaries"));
  }
});

test("Semgrep publication consumes both same-attempt native image artifacts without rebuilding", () => {
  const workflow = parse(readFileSync(new URL("../../.github/workflows/engine-images-local-k8s.yml", import.meta.url), "utf8"));
  const publish = workflow.jobs.publish;
  const build = publish.steps.find((step) => step.id === "build");
  assert.match(build.if, /matrix\.engine != 'semgrep'/u);
  for (const arch of ["amd64", "arm64"]) {
    const download = publish.steps.find((step) => step.name === `Download the tested ${arch} image`);
    assert.equal(download.with.name, `semgrep-native-image-${arch}-\${{ github.run_id }}-\${{ github.run_attempt }}`);
    assert.equal(download.if, "matrix.engine == 'semgrep' && steps.guard.outputs.should_build == 'true'");
  }
  const handoff = publish.steps.find((step) => step.id === "semgrep_image");
  assert.equal(handoff.if, "matrix.engine == 'semgrep' && steps.guard.outputs.should_build == 'true'");
  assert.doesNotMatch(handoff.run, /docker (?:build|buildx build)\b/u);
  const verify = publish.steps.find((step) => step.id === "verify");
  assert.match(verify.env.DIGEST, /steps\.semgrep_image\.outputs\.digest/u);
  assert.match(verify.run, /verify_image_payload\.py/u);
  for (const step of publish.steps.filter((step) => ["./.github/actions/engine-image-evidence", "./.github/actions/engine-image-evidence/promote"].includes(step.uses))) {
    assert.match(step.with.digest, /steps\.semgrep_image\.outputs\.digest/u);
    assert.ok(publish.steps.indexOf(step) > publish.steps.indexOf(verify));
  }
});

test("native image handoff rejects corrupted bytes, wrong receipts, architectures and payloads before pushing", { skip: process.platform === "win32" }, async (t) => {
  const workflow = parse(readFileSync(new URL("../../.github/workflows/engine-images-local-k8s.yml", import.meta.url), "utf8"));
  const script = workflow.jobs.publish.steps.find((step) => step.id === "semgrep_image").run;
  for (const failure of ["none", "archive", "source", "architecture", "payload"]) {
    await t.test(failure, () => {
      const root = mkdtempSync(path.join(tmpdir(), "semgrep-image-handoff-"));
      try {
        const bin = path.join(root, "bin");
        const scratch = path.join(root, "scratch");
        mkdirSync(bin); mkdirSync(scratch);
        const source = "ab".repeat(20);
        const imageIds = { amd64: `sha256:${"11".repeat(32)}`, arm64: `sha256:${"22".repeat(32)}` };
        for (const arch of ["amd64", "arm64"]) {
          const transfer = path.join(scratch, `semgrep-native-image-${arch}`);
          const evidence = path.join(root, "package-evidence", `semgrep-native-${arch}`);
          mkdirSync(transfer); mkdirSync(evidence, { recursive: true });
          const bytes = Buffer.from(`native image ${arch}`);
          writeFileSync(path.join(transfer, "image.tar.gz"), failure === "archive" && arch === "arm64" ? "changed" : bytes);
          writeFileSync(path.join(transfer, "image.sha256"), createHash("sha256").update(bytes).digest("hex") + "\n");
          writeFileSync(path.join(transfer, "image-id.txt"), imageIds[arch] + "\n");
          writeFileSync(path.join(evidence, "verification.json"), JSON.stringify({
            source_revision: failure === "source" && arch === "arm64" ? "cd".repeat(20) : source,
            expected_version: "1.181.0-1",
            execution: { mode: "native", host_architecture: arch, image_architecture: arch },
            image_payload: { rootfs_payload_sha256: "33".repeat(32) },
          }));
        }
        const log = path.join(root, "commands.jsonl");
        const output = path.join(root, "outputs");
        writeFileSync(log, ""); writeFileSync(output, "");
        const shim = `#!/usr/bin/env node
const { appendFileSync } = require('node:fs');
const { basename } = require('node:path');
const command = basename(process.argv[1]);
const args = process.argv.slice(2);
appendFileSync(process.env.HANDOFF_LOG, JSON.stringify({ command, args }) + '\\n');
if (command === 'python3') process.exit(process.env.HANDOFF_FAILURE === 'payload' && args.includes('${imageIds.arm64}') ? 1 : 0);
if (args[0] === 'image' && args[1] === 'inspect') {
  const arm = args.includes('${imageIds.arm64}');
  process.stdout.write('linux/' + (arm && process.env.HANDOFF_FAILURE !== 'architecture' ? 'arm64' : 'amd64') + '\\n');
} else if (args.slice(0, 3).join(' ') === 'buildx imagetools inspect') {
  const prefix = args[3].endsWith('-amd64') ? '44' : args[3].endsWith('-arm64') ? '55' : '66';
  process.stdout.write(JSON.stringify('sha256:' + prefix.repeat(32)) + '\\n');
} else if (!['load', 'tag', 'push'].includes(args[0]) && args.slice(0, 3).join(' ') !== 'buildx imagetools create') process.exit(99);
`;
        for (const command of ["docker", "python3"]) {
          writeFileSync(path.join(bin, command), shim);
          chmodSync(path.join(bin, command), 0o755);
        }
        const result = spawnSync("bash", ["-c", script], {
          cwd: root, encoding: "utf8",
          env: { ...process.env, PATH: `${bin}${path.delimiter}${process.env.PATH}`, RUNNER_TEMP: scratch,
            HANDOFF_LOG: log, HANDOFF_FAILURE: failure, GITHUB_OUTPUT: output,
            REVISION: source, IMAGE_TAG: "1.181.0-1", CANDIDATE_TAG: "candidate-fixture",
            IMAGE: "ghcr.io/ted-h-com/ai-security-scanner-engine-semgrep" },
        });
        const commands = readFileSync(log, "utf8").trim().split("\n").filter(Boolean).map((line) => JSON.parse(line));
        const pushes = commands.filter((entry) => entry.command === "docker" && entry.args[0] === "push");
        if (failure === "none") {
          assert.equal(result.status, 0, result.stderr);
          assert.equal(pushes.length, 2);
          assert.equal(readFileSync(output, "utf8"), `digest=sha256:${"66".repeat(32)}\n`);
          const image = "ghcr.io/ted-h-com/ai-security-scanner-engine-semgrep";
          assert.deepEqual(commands.filter((entry) => entry.args[0] === "tag").map((entry) => entry.args), [
            ["tag", imageIds.amd64, `${image}:candidate-fixture-amd64`],
            ["tag", imageIds.arm64, `${image}:candidate-fixture-arm64`],
          ]);
          assert.deepEqual(commands.find((entry) => entry.args.slice(0, 3).join(" ") === "buildx imagetools create").args.slice(-2), [
            `${image}@sha256:${"44".repeat(32)}`, `${image}@sha256:${"55".repeat(32)}`,
          ]);
          const firstPush = commands.indexOf(pushes[0]);
          assert.equal(commands.slice(0, firstPush).filter((entry) => entry.command === "python3").length, 2);
        } else {
          assert.notEqual(result.status, 0);
          assert.equal(pushes.length, 0);
          assert.equal(readFileSync(output, "utf8"), "");
        }
      } finally {
        rmSync(root, { recursive: true, force: true });
      }
    });
  }
});
