import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import {
  chmod,
  copyFile,
  link,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  stat,
  symlink,
  writeFile,
} from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const verifier = path.join(projectRoot, "scripts/release/verify-publication-artifact.mjs");
const repository = "teddashh/ai-security-scanner";
const sourceRevision = "ab".repeat(20);
const runId = "123456789";
const attempt = "2";
const indexDigest = `sha256:${"11".repeat(32)}`;
const platformDigests = {
  "linux/amd64": `sha256:${"22".repeat(32)}`,
  "linux/arm64": `sha256:${"33".repeat(32)}`,
};
const specs = {
  steampipe: { tag: "2.4.7-1", group: "cloud", workflow: ".github/workflows/engine-images-cloud.yml" },
  prowler: { tag: "5.44.0-1", group: "cloud", workflow: ".github/workflows/engine-images-cloud.yml" },
  checkov: { tag: "3.3.29-1", group: "standalone", workflow: ".github/workflows/engine-image-checkov.yml", sourceDateEpoch: "1791891584" },
  syft: { tag: "1.54.1-1", group: "standalone", workflow: ".github/workflows/engine-image-syft.yml" },
  naabu: { tag: "2.6.1-7", group: "external" },
  httpx: { tag: "1.12.0-1", group: "external" },
  nuclei: { tag: "3.11.1-7", group: "external" },
  semgrep: { tag: "1.181.0-1", group: "local", smokeFiles: ["semgrep.json"] },
  trufflehog: { tag: "3.99.2-1", group: "local", smokeFiles: ["trufflehog.jsonl"] },
  trivy: { tag: "0.76.0-1", group: "local", smokeFiles: ["trivy-oci.json", "trivy-library.json", "trivy-jar.json"] },
  grype: { tag: "0.120.1-1", group: "local", smokeFiles: ["grype.json"] },
  kubescape: { tag: "4.0.16-1", group: "local", smokeFiles: ["kubescape.json"] },
  "kube-bench": { tag: "0.16.0-5", group: "local", smokeFiles: ["kube-bench.json"] },
  "agentic-radar": { tag: "0.14.1-1", group: "local", smokeFiles: ["agentic-radar.json"], workflow: ".github/workflows/engine-image-agentic-radar.yml" },
  garak: { tag: "0.17.0-1", group: "local", smokeFiles: ["report.jsonl", "garak-execution.json", "native-qa.json"], workflow: ".github/workflows/engine-image-garak.yml" },
  scubagear: { tag: "1.8.0-8", group: "m365" },
  maester: { tag: "2.0.0-9", group: "m365" },
  "egress-gateway": { tag: "0.3.0-1", group: "gateway" },
};
const workflows = {
  external: ".github/workflows/engine-images-external.yml",
  local: ".github/workflows/engine-images-local-k8s.yml",
  m365: ".github/workflows/engine-images-m365.yml",
  gateway: ".github/workflows/managed-egress-gateway-image.yml",
};
const platforms = ["linux/amd64", "linux/arm64"];
const sbomSpecs = [
  { format: "spdx-json", suffix: "spdx", predicateType: "https://spdx.dev/Document/v2.3" },
  { format: "cyclonedx-json", suffix: "cyclonedx", predicateType: "https://cyclonedx.org/bom" },
];
let fakeGhDirectory;
let fakeGhImplementation;

test.before(async () => {
  fakeGhDirectory = await mkdtemp(path.join(os.tmpdir(), "publication-fake-gh-"));
  fakeGhImplementation = path.join(
    fakeGhDirectory,
    process.platform === "win32" ? "attestation" : "fake-gh.cjs",
  );
  await writeFile(fakeGhImplementation, `
const { basename } = require("node:path");
if (
  process.platform !== "win32" ||
  basename(process.execPath).toLowerCase() === "gh.exe" ||
  basename(process.argv[1] ?? "").toLowerCase() === "attestation"
) {
const { readFileSync } = require("node:fs");
const args = process.argv.slice(2);
const value = (flag) => args[args.indexOf(flag) + 1];
if (process.env.FAKE_GH_ATTESTATION_FAILURE === "1") {
  process.stderr.write("fixture cryptographic failure\\n");
  process.exit(1);
}
const bundle = JSON.parse(readFileSync(value("--bundle"), "utf8"));
const statement = JSON.parse(Buffer.from(bundle.dsseEnvelope.payload, "base64").toString("utf8"));
const sourceRevision = value("--source-digest");
const sourceRef = value("--source-ref");
const signerIdentity = \`https://github.com/\${value("--signer-workflow")}@\${sourceRef}\`;
const repository = value("--repo");
const invocation = \`https://github.com/\${repository}/actions/runs/\${process.env.FAKE_GH_RUN_ID}/attempts/\${process.env.FAKE_GH_ATTEMPT}\`;
process.stdout.write(JSON.stringify([{
  attestation: { bundle },
  fixtureExtraOutput: "x".repeat(Number(process.env.FAKE_GH_EXTRA_OUTPUT_BYTES ?? 0)),
  verificationResult: {
    signature: { certificate: {
      sourceRepositoryURI: \`https://github.com/\${repository}\`,
      sourceRepositoryDigest: sourceRevision,
      sourceRepositoryRef: sourceRef,
      githubWorkflowRepository: repository,
      githubWorkflowSHA: sourceRevision,
      buildSignerURI: signerIdentity,
      buildSignerDigest: sourceRevision,
      subjectAlternativeName: signerIdentity,
      runInvocationURI: invocation,
      runnerEnvironment: "github-hosted",
      sourceRepositoryVisibilityAtSigning: "public",
    } },
    verifiedTimestamps: [{ type: "Tlog", uri: "https://rekor.sigstore.dev" }],
    statement,
  },
}]) + "\\n");
}
`);
  if (process.platform === "win32") {
    const executable = path.join(fakeGhDirectory, "gh.exe");
    try {
      await link(process.execPath, executable);
    } catch (error) {
      if (!["EXDEV", "EPERM"].includes(error?.code)) throw error;
      await copyFile(process.execPath, executable);
    }
  } else {
    const executable = path.join(fakeGhDirectory, "gh");
    await writeFile(
      executable,
      `#!/usr/bin/env node\n${await readFile(fakeGhImplementation, "utf8")}`,
    );
    await chmod(executable, 0o755);
  }
});

test.after(async () => {
  if (fakeGhDirectory) await rm(fakeGhDirectory, { recursive: true, force: true });
});

const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
const imageFor = (engine) => engine === "egress-gateway"
  ? "ghcr.io/teddashh/ai-security-scanner-egress-gateway"
  : `ghcr.io/teddashh/ai-security-scanner-engine-${engine}`;

async function writeJson(file, value) {
  await mkdir(path.dirname(file), { recursive: true });
  await writeFile(file, `${JSON.stringify(value, null, 2)}\n`);
}

async function fileRecord(file) {
  const bytes = await readFile(file);
  return { sha256: sha256(bytes), sizeBytes: bytes.length };
}

async function writeChecksums(file, directory, names, rootStyle = false) {
  const lines = [];
  for (const name of [...names].sort()) {
    const bytes = await readFile(path.join(directory, ...name.split("/")));
    lines.push(`${sha256(bytes)}  ${rootStyle ? "./" : ""}${name}`);
  }
  await writeFile(file, `${lines.join("\n")}\n`);
}

async function regularFiles(directory, prefix = "") {
  const files = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const relative = prefix ? `${prefix}/${entry.name}` : entry.name;
    if (entry.isDirectory()) files.push(...await regularFiles(path.join(directory, entry.name), relative));
    else if (entry.isFile()) files.push(relative);
  }
  return files;
}

async function sealRoot(root) {
  const names = (await regularFiles(root)).filter((name) => name !== "SHA256SUMS.txt");
  await writeChecksums(path.join(root, "SHA256SUMS.txt"), root, names, true);
}

async function sealNested(root, engine) {
  const nested = path.join(root, engine);
  const names = (await regularFiles(nested)).filter((name) => name !== "SHA256SUMS.txt");
  await writeChecksums(path.join(nested, "SHA256SUMS.txt"), nested, names);
}

function fakeSbom(engine, platform, format) {
  return format === "spdx-json"
    ? {
      spdxVersion: "SPDX-2.3",
      SPDXID: "SPDXRef-DOCUMENT",
      name: `${engine}-${platform}`,
      packages: [{ name: imageFor(engine), versionInfo: platformDigests[platform] }],
    }
    : {
      bomFormat: "CycloneDX",
      specVersion: "1.6",
      version: 1,
      metadata: { component: { type: "container", name: imageFor(engine), version: platformDigests[platform] } },
    };
}

function fakeBundle(image, digest, predicateType, predicate) {
  const statement = {
    _type: "https://in-toto.io/Statement/v1",
    subject: [{ name: image, digest: { sha256: digest.slice(7) } }],
    predicateType,
    predicate,
  };
  return {
    mediaType: "application/vnd.dev.sigstore.bundle.v0.3+json",
    verificationMaterial: { tlogEntries: [{}] },
    dsseEnvelope: {
      payloadType: "application/vnd.in-toto+json",
      payload: Buffer.from(JSON.stringify(statement)).toString("base64"),
      signatures: [{ sig: Buffer.from("fixture-signature").toString("base64") }],
    },
  };
}

async function createArtifact(testContext, engine, { largeSbom = false } = {}) {
  const spec = specs[engine];
  const workflow = spec.workflow ?? workflows[spec.group];
  const root = await mkdtemp(path.join(os.tmpdir(), `publication-${engine}-`));
  testContext.after(() => rm(root, { recursive: true, force: true }));
  const nested = path.join(root, engine);
  await mkdir(nested, { recursive: true });
  const image = imageFor(engine);
  const platformRecords = [];
  const documents = new Map();

  for (const platform of platforms) {
    const architecture = platform.split("/")[1];
    const sboms = [];
    for (const sbomSpec of sbomSpecs) {
      const file = `${engine}-linux-${architecture}.${sbomSpec.suffix}.json`;
      const document = fakeSbom(engine, platform, sbomSpec.format);
      if (largeSbom && platform === "linux/amd64" && sbomSpec.format === "spdx-json") {
        document.comment = "x".repeat(10 * 1024 * 1024);
      }
      documents.set(file, document);
      await writeJson(path.join(nested, file), document);
      const record = await fileRecord(path.join(nested, file));
      sboms.push({
        format: sbomSpec.format,
        predicateType: sbomSpec.predicateType,
        file,
        sha256: record.sha256,
        sizeBytes: record.sizeBytes,
      });
    }
    platformRecords.push({ platform, digest: platformDigests[platform], sboms });
  }

  const attestationSpecs = [
    {
      key: "provenance",
      kind: "build-provenance",
      platform: null,
      predicateType: "https://slsa.dev/provenance/v1",
      digest: indexDigest,
      predicate: {
        buildDefinition: {
          buildType: "https://actions.github.io/buildtypes/workflow/v1",
          externalParameters: {
            workflow: {
              ref: "refs/heads/main",
              repository: `https://github.com/${repository}`,
              path: workflow,
            },
          },
          resolvedDependencies: [{
            uri: `git+https://github.com/${repository}@refs/heads/main`,
            digest: { gitCommit: sourceRevision },
          }],
        },
        runDetails: {
          builder: {
            id: `https://github.com/${repository}/${workflow}@refs/heads/main`,
          },
          metadata: {
            invocationId: `https://github.com/${repository}/actions/runs/${runId}/attempts/${attempt}`,
          },
        },
      },
    },
    ...platforms.flatMap((platform) => {
      const architecture = platform.split("/")[1];
      return sbomSpecs.map((sbom) => ({
        key: `${architecture}-${sbom.suffix}`,
        kind: "sbom",
        platform,
        predicateType: sbom.predicateType,
        digest: platformDigests[platform],
        predicate: documents.get(`${engine}-linux-${architecture}.${sbom.suffix}.json`),
      }));
    }),
  ];
  const attestations = [];
  for (const [attestationIndex, attestation] of attestationSpecs.entries()) {
    const bundleFile = `${engine}-${attestation.key}.sigstore.json`;
    await writeJson(
      path.join(nested, bundleFile),
      fakeBundle(image, attestation.digest, attestation.predicateType, attestation.predicate),
    );
    const record = await fileRecord(path.join(nested, bundleFile));
    const attestationId = String(1000 + attestationIndex);
    attestations.push({
      kind: attestation.kind,
      platform: attestation.platform,
      predicateType: attestation.predicateType,
      subject: { name: image, digest: attestation.digest },
      bundleFile,
      bundleSha256: record.sha256,
      bundleSizeBytes: record.sizeBytes,
      attestationId,
      attestationUrl: `https://github.com/${repository}/attestations/${attestationId}`,
      registryPushed: true,
      githubAttestationsApi: true,
    });
  }

  const transformations = spec.group === "gateway"
    ? platforms.map((platform) => {
      const architecture = platform.split("/")[1];
      const spdx = platformRecords.find((record) => record.platform === platform).sboms[0];
      return {
        kind: "cyclonedx-first-party-scratch-application-v3",
        platform,
        platformDigest: platformDigests[platform],
        sourceRevision,
        sourceFile: `${engine}-linux-${architecture}.spdx.json`,
        outputFile: `${engine}-linux-${architecture}.cyclonedx.json`,
        componentBomRef: `urn:ai-security-scanner:egress-gateway:${platformDigests[platform].slice(7)}`,
        spdxPreserved: true,
        spdxFileCount: 2,
        spdxFileChecksumStatus: "unavailable-syft-zero-sha1-placeholder",
        spdxZeroSha1PlaceholderCount: 2,
        spdxSha256: spdx.sha256,
        tool: { name: "ai-security-scanner/scripts/engine-image-evidence.mjs", version: "3" },
      };
    })
    : [];

  const evidence = {
    schemaVersion: 1,
    engine,
    image,
    tag: spec.tag,
    indexDigest,
    sourceRevision,
    public: true,
    generator: {
      name: "anchore/syft",
      version: "1.51.0",
      image: "anchore/syft@sha256:678bfa565b60f747aac0f8e964fe5588a24445b8d0a480e91f6efd70020dfbb0",
    },
    sbomTransformations: transformations,
    imageBuild: { inlineProvenance: false, inlineSbom: false, digestMutatedByEvidence: false },
    platforms: platformRecords,
    attestations,
    verification: {
      repository,
      workflowRun: `https://github.com/${repository}/actions/runs/${runId}`,
      runAttempt: attempt,
      registryReferrers: true,
      githubAttestationApi: true,
      onlineVerificationRequiredBeforeUpload: true,
    },
    checksumsFile: "SHA256SUMS.txt",
  };
  await writeJson(path.join(nested, `${engine}-image-supply-chain.json`), evidence);
  await sealNested(root, engine);

  let smokeReceipt;
  if (spec.group === "local") {
    const smoke = path.join(root, `${engine}-managed-smoke`);
    await mkdir(smoke);
    for (const file of spec.smokeFiles) await writeFile(path.join(smoke, file), `fixture evidence for ${engine} ${file}\n`);
    if (engine === "garak") {
      const raw = await readFile(path.join(projectRoot, "src-tauri/tests/fixtures/adapters/garak-0.17.0-native.jsonl"));
      const evals = raw.toString("utf8").trim().split("\n").map((line) => JSON.parse(line)).filter((row) => row.entry_type === "eval")
        .map(({ probe, detector, fails, total_evaluated, total_processed, nones }) => ({ probe, detector, fails, total_evaluated, total_processed, nones }));
      const receipt = { schema_version: "1", profile_id: "garak_https_v1", complete: true, reason: null, max_http_attempts: 64,
        max_completion_tokens_per_request: 150, max_total_request_bytes: 65536, http_attempts: 54, total_request_bytes: 20096, scope_sha256: "ab".repeat(32) };
      const cases = [
        { case: "positive", exit_code: 0, receipt, evals, observed_http_requests: 54, raw_sha256: sha256(raw) },
        { case: "clean", exit_code: 0, receipt, evals: evals.map((row) => ({ ...row, fails: 0 })), observed_http_requests: 54 },
        ...["redirect", "bad-tls", "deadline"].map((name) => ({ case: name, exit_code: 1,
          receipt: { ...receipt, complete: false, reason: name === "redirect" ? "redirect_refused" : name === "deadline" ? "inference_deadline" : "native_execution_failed", http_attempts: 1, total_request_bytes: 156 },
          evals: [], observed_http_requests: name === "bad-tls" ? 0 : 1 })),
        { case: "cancelled", exit_code: 1, receipt: { ...receipt, complete: false, reason: "native_cancelled" }, evals: [], no_requests_after_stop: true, raw_sha256: "ab".repeat(32) },
      ];
      await writeFile(path.join(smoke, "report.jsonl"), raw);
      await writeJson(path.join(smoke, "garak-execution.json"), receipt);
      await writeJson(path.join(smoke, "native-qa.json"), { schema_version: 1, platform: "linux/amd64", image: `${image}@${indexDigest}`,
        image_id: platformDigests["linux/amd64"], native_version: "0.17.0", network_internal: true, unapproved_destinations: 0, cases });
    }
    await writeChecksums(path.join(smoke, "SHA256SUMS.txt"), smoke, spec.smokeFiles);
    smokeReceipt = `sha256:${sha256(await readFile(path.join(smoke, "SHA256SUMS.txt")))}`;
  }

  if (spec.group !== "gateway") {
    const common = {
      schemaVersion: 1,
      engine,
      image,
      tag: spec.tag,
      digest: indexDigest,
      sourceRevision,
    };
    const summary = spec.group === "local"
      ? {
        ...common,
        platformDigests,
        anonymousPullVerified: true,
        managedSmokeEvidenceSha256: smokeReceipt,
      }
      : spec.group === "m365"
        ? {
          ...common,
          platforms,
          platformDigests,
          public: true,
          anonymousPullVerified: true,
          smoke: {
            platform: "linux/amd64",
            nonRoot: true,
            fixedEntrypoint: true,
            missingOutputMountRejected: true,
            missingScopeMountRejected: true,
            missingCredentialMountRejected: true,
            moduleLockVerified: true,
            dependencyNoticesVerified: true,
          },
        }
        : { ...common, platforms, public: true };
    if (spec.group === "cloud") summary.platformDigests = platformDigests;
    if (spec.group === "standalone") delete summary.engine;
    if (spec.sourceDateEpoch) summary.sourceDateEpoch = spec.sourceDateEpoch;
    await writeJson(path.join(root, `${engine}-image-manifest.json`), summary);
  }
  if (engine === "semgrep") {
    for (const arch of ["amd64", "arm64"]) {
      const native = path.join(root, `semgrep-native-${arch}`);
      await mkdir(native);
      const product = Array.from({ length: 10 }, (_, i) => ({ check_id: `product-${i}`, path: "/workspace/synthetic.py" }));
      const upstream = Array.from({ length: 12 }, (_, i) => ({ check_id: `upstream-${i}`, path: "/workspace/synthetic.py" }));
      const passes = { product, upstream, combined: [...product, ...upstream], managed: [...product, ...upstream] };
      for (const [name, results] of Object.entries(passes)) {
        await mkdir(path.join(native, name));
        await writeJson(path.join(native, name, "semgrep.json"), { results, errors: [] });
        await writeFile(path.join(native, `${name}.log`), "synthetic scan log\n");
      }
      const rejections = { "changed-rule": 126, "changed-provenance": 126, "extra-rule": 126, "writable-workspace": 126 };
      for (const name of Object.keys(rejections)) await writeFile(path.join(native, `${name}.log`), "synthetic refusal log\n");
      const payload = { schema_version: 1, rootfs_payload_sha256: "ab".repeat(32) };
      await writeJson(path.join(native, "published-payload.json"), payload);
      await writeJson(path.join(native, "verification.json"), {
        source_revision: sourceRevision,
        expected_version: spec.tag,
        execution: { mode: "native", host_architecture: arch, image_architecture: arch },
        native_matches: { product: 10, upstream: 12, combined: 22, managed: 22 },
        exact_full_result_union: true,
        rejections_before_output: rejections,
        source_attachment: { selected_original_files: 1477, excluded_rule_absent: true, unfiltered_rules_archive_absent: true, rebuild_inputs_match: true, sha256: "cd".repeat(32) },
        image_payload: payload,
        managed_artifact_sha256: sha256(await readFile(path.join(native, "managed/semgrep.json"))),
      });
    }
  }
  if (!["cloud", "standalone"].includes(spec.group)) await sealRoot(root);
  return root;
}

function runVerifier(engine, artifact, overrides = {}) {
  const environment = { ...process.env };
  for (const key of Object.keys(environment)) {
    if (key.toLowerCase() === "path") delete environment[key];
  }
  environment.PATH = `${fakeGhDirectory}${path.delimiter}${process.env.PATH ?? ""}`;
  environment.FAKE_GH_RUN_ID = overrides.runId ?? runId;
  environment.FAKE_GH_ATTEMPT = overrides.attempt ?? attempt;
  environment.FAKE_GH_ATTESTATION_FAILURE = overrides.cryptographicFailure ? "1" : "0";
  environment.FAKE_GH_EXTRA_OUTPUT_BYTES = String(overrides.extraOutputBytes ?? 0);
  return spawnSync(process.execPath, [
    verifier,
    "--engine", engine,
    "--artifact-dir", artifact,
    "--source-revision", overrides.sourceRevision ?? sourceRevision,
    "--run-id", overrides.runId ?? runId,
    "--attempt", overrides.attempt ?? attempt,
  ], {
    cwd: process.platform === "win32" ? fakeGhDirectory : projectRoot,
    encoding: "utf8",
    maxBuffer: 8 * 1024 * 1024,
    env: environment,
  });
}

test("Garak rejects resealed incomplete native output, widened inference budgets and lost cancellation evidence", async (t) => {
  for (const mutation of ["completion", "budget", "cancellation"]) {
    const artifact = await createArtifact(t, "garak");
    const smoke = path.join(artifact, "garak-managed-smoke");
    const qa = JSON.parse(await readFile(path.join(smoke, "native-qa.json"), "utf8"));
    if (mutation === "completion") {
      const raw = await readFile(path.join(smoke, "report.jsonl"), "utf8");
      const changed = raw.trim().split("\n").filter((line) => JSON.parse(line).entry_type !== "completion").join("\n") + "\n";
      await writeFile(path.join(smoke, "report.jsonl"), changed);
      qa.cases.find((result) => result.case === "positive").raw_sha256 = sha256(Buffer.from(changed));
    } else if (mutation === "budget") qa.cases.find((result) => result.case === "clean").receipt.max_http_attempts = 65;
    else qa.cases.find((result) => result.case === "cancelled").no_requests_after_stop = false;
    await writeJson(path.join(smoke, "native-qa.json"), qa);
    await writeChecksums(path.join(smoke, "SHA256SUMS.txt"), smoke, specs.garak.smokeFiles);
    const summaryPath = path.join(artifact, "garak-image-manifest.json");
    const summary = JSON.parse(await readFile(summaryPath, "utf8"));
    summary.managedSmokeEvidenceSha256 = `sha256:${sha256(await readFile(path.join(smoke, "SHA256SUMS.txt")))}`;
    await writeJson(summaryPath, summary); await sealRoot(artifact);
    const result = runVerifier("garak", artifact);
    assert.notEqual(result.status, 0, mutation);
    assert.match(result.stderr, mutation === "completion" ? /matching terminal completion/u : mutation === "budget" ? /bounded inference contract/u : /cancellation/u);
  }
});

async function mutateNested(root, engine, mutate) {
  const manifest = path.join(root, engine, `${engine}-image-supply-chain.json`);
  const evidence = JSON.parse(await readFile(manifest, "utf8"));
  mutate(evidence);
  await writeJson(manifest, evidence);
  await sealNested(root, engine);
  await sealRoot(root);
}

async function mutateRootSummary(root, engine, mutate) {
  const summaryFile = path.join(root, `${engine}-image-manifest.json`);
  const summary = JSON.parse(await readFile(summaryFile, "utf8"));
  mutate(summary);
  await writeJson(summaryFile, summary);
  await sealRoot(root);
}

test("publication verifier accepts every fixed engine and the gateway with one normalized JSON result", async (t) => {
  for (const [engine, spec] of Object.entries(specs)) {
    const artifact = await createArtifact(t, engine);
    const result = runVerifier(engine, artifact);
    assert.equal(result.status, 0, `${engine}: ${result.stderr}`);
    assert.equal(result.stderr, "", engine);
    assert.equal(result.stdout.trim().split("\n").length, 1, `${engine} emitted more than one payload`);
    const payload = JSON.parse(result.stdout);
    assert.equal(payload.engine, engine);
    assert.equal(payload.image, imageFor(engine));
    assert.equal(payload.tag, spec.tag);
    assert.equal(payload.indexDigest, indexDigest);
    assert.deepEqual(payload.platformDigests, platformDigests);
    assert.equal(payload.sourceRevision, sourceRevision);
    assert.equal(payload.workflowRun, `https://github.com/${repository}/actions/runs/${runId}`);
    assert.equal(payload.runId, runId);
    assert.equal(payload.runAttempt, attempt);
    if (["cloud", "standalone"].includes(spec.group)) assert.equal(payload.evidence.rootChecksumReceiptSha256, null);
    else assert.match(payload.evidence.rootChecksumReceiptSha256, /^sha256:[0-9a-f]{64}$/u);
    assert.match(payload.evidence.nestedChecksumReceiptSha256, /^sha256:[0-9a-f]{64}$/u);
    assert.equal(payload.evidence.sbomCount, 4);
    assert.equal(payload.evidence.attestationCount, 5);
    if (spec.group === "local") assert.match(payload.evidence.managedSmokeEvidenceSha256, /^sha256:[0-9a-f]{64}$/u);
    if (spec.group === "gateway") assert.deepEqual(payload.evidence.sbomTransformationPlatforms, platforms);
  }
});

test("publication verifier rejects resealed Semgrep native evidence drift", async (t) => {
  const cases = [
    ["emulated architecture", (value) => { value.execution.mode = "qemu"; }, /actual native verification/u],
    ["missing refusal", (value) => { delete value.rejections_before_output["writable-workspace"]; }, /refusal controls/u],
    ["excluded source present", (value) => { value.source_attachment.excluded_rule_absent = false; }, /selected-source verification/u],
    ["wrong source commit", (value) => { value.source_revision = "ff".repeat(20); }, /native source\/version mismatch/u],
  ];
  for (const [name, mutate, error] of cases) {
    await t.test(name, async (subtest) => {
      const artifact = await createArtifact(subtest, "semgrep");
      const file = path.join(artifact, "semgrep-native-arm64/verification.json");
      const value = JSON.parse(await readFile(file, "utf8"));
      mutate(value);
      await writeJson(file, value);
      await sealRoot(artifact);
      const result = runVerifier("semgrep", artifact);
      assert.notEqual(result.status, 0);
      assert.match(result.stderr, error);
    });
  }
  await t.test("a different published filesystem", async (subtest) => {
    const artifact = await createArtifact(subtest, "semgrep");
    await writeJson(path.join(artifact, "semgrep-native-arm64/published-payload.json"), { schema_version: 1, rootfs_payload_sha256: "ff".repeat(32) });
    await sealRoot(artifact);
    const result = runVerifier("semgrep", artifact);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /published filesystem differs/u);
  });
  await t.test("changed result bytes despite matching counts and rehashed receipts", async (subtest) => {
    const artifact = await createArtifact(subtest, "semgrep");
    const managed = path.join(artifact, "semgrep-native-arm64/managed/semgrep.json");
    const value = JSON.parse(await readFile(managed, "utf8"));
    value.results[0].check_id = "different-observation";
    await writeJson(managed, value);
    const file = path.join(artifact, "semgrep-native-arm64/verification.json");
    const receipt = JSON.parse(await readFile(file, "utf8"));
    receipt.managed_artifact_sha256 = sha256(await readFile(managed));
    await writeJson(file, receipt);
    await sealRoot(artifact);
    const result = runVerifier("semgrep", artifact);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /complete native results differ/u);
  });
});

test("Microsoft 365 workflow seals the exact downloadable evidence inventory before upload", async () => {
  const workflow = await readFile(path.join(projectRoot, workflows.m365), "utf8");
  const sealStep = workflow.indexOf("- name: Seal the downloadable evidence inventory");
  const uploadStep = workflow.indexOf("- name: Upload publication and signed supply-chain evidence");

  assert.notEqual(sealStep, -1);
  assert.notEqual(uploadStep, -1);
  assert.ok(sealStep < uploadStep);
  assert.match(workflow, /find \. -type f ! -path '\.\/SHA256SUMS\.txt' -print0/u);
  assert.match(workflow, /xargs -0 sha256sum > SHA256SUMS\.txt/u);
  assert.match(workflow, /sha256sum --check SHA256SUMS\.txt/u);
});

test("publication verifier rejects resealed Microsoft 365 root-manifest drift", async (t) => {
  const cases = [
    {
      engine: "scubagear",
      mutate: (summary) => { summary.public = false; },
      error: /Microsoft 365 root summary must record public access/u,
    },
    {
      engine: "maester",
      mutate: (summary) => { summary.anonymousPullVerified = false; },
      error: /Microsoft 365 root summary must record anonymous pull verification/u,
    },
    {
      engine: "scubagear",
      mutate: (summary) => { summary.platformDigests["linux/amd64"] = `sha256:${"ff".repeat(32)}`; },
      error: /Microsoft 365 root platform digest mismatch/u,
    },
    {
      engine: "maester",
      mutate: (summary) => { summary.platforms = ["linux/amd64"]; },
      error: /Microsoft 365 root summary platform list mismatch/u,
    },
    {
      engine: "maester",
      mutate: (summary) => { summary.smoke.fixedEntrypoint = false; },
      error: /Microsoft 365 smoke summary does not match the fixed publication contract/u,
    },
    {
      engine: "scubagear",
      mutate: (summary) => { summary.smoke.unreviewedClaim = true; },
      error: /Microsoft 365 smoke summary fields are not the exact publication contract/u,
    },
  ];
  for (const fixture of cases) {
    const artifact = await createArtifact(t, fixture.engine);
    await mutateRootSummary(artifact, fixture.engine, fixture.mutate);
    const result = runVerifier(fixture.engine, artifact);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, fixture.error);
    assert.equal(result.stdout, "");
  }
});

test("publication verifier binds Microsoft 365 tags, workflow identity, and run attempt", async (t) => {
  let artifact = await createArtifact(t, "scubagear");
  await mutateNested(artifact, "scubagear", (evidence) => {
    evidence.tag = "1.8.0-1";
  });
  let result = runVerifier("scubagear", artifact);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /supply-chain image tag mismatch/u);

  artifact = await createArtifact(t, "maester");
  await mutateNested(artifact, "maester", (evidence) => {
    evidence.verification.runAttempt = 1;
  });
  result = runVerifier("maester", artifact);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /publication workflow attempt mismatch/u);

  artifact = await createArtifact(t, "scubagear");
  const bundleFile = path.join(artifact, "scubagear", "scubagear-provenance.sigstore.json");
  const bundle = JSON.parse(await readFile(bundleFile, "utf8"));
  const statement = JSON.parse(Buffer.from(bundle.dsseEnvelope.payload, "base64").toString("utf8"));
  statement.predicate.buildDefinition.externalParameters.workflow.path = ".github/workflows/engine-images-external.yml";
  bundle.dsseEnvelope.payload = Buffer.from(JSON.stringify(statement)).toString("base64");
  await writeJson(bundleFile, bundle);
  const manifestFile = path.join(artifact, "scubagear", "scubagear-image-supply-chain.json");
  const manifest = JSON.parse(await readFile(manifestFile, "utf8"));
  const record = await fileRecord(bundleFile);
  manifest.attestations[0].bundleSha256 = record.sha256;
  manifest.attestations[0].bundleSizeBytes = record.sizeBytes;
  await writeJson(manifestFile, manifest);
  await sealNested(artifact, "scubagear");
  await sealRoot(artifact);
  result = runVerifier("scubagear", artifact);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /provenance workflow path mismatch/u);
  assert.equal(result.stdout, "");
});

test("publication verifier rejects a root-seal mismatch before trusting nested evidence", async (t) => {
  const artifact = await createArtifact(t, "naabu");
  await writeFile(path.join(artifact, "naabu", "naabu-linux-amd64.spdx.json"), "tampered\n");
  const result = runVerifier("naabu", artifact);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /SHA256SUMS\.txt checksum mismatch/u);
  assert.equal(result.stdout, "");
});

test("publication verifier rejects a bad nested seal even when the root seal is current", async (t) => {
  const engine = "semgrep";
  const artifact = await createArtifact(t, engine);
  const nestedReceipt = path.join(artifact, engine, "SHA256SUMS.txt");
  const contents = await readFile(nestedReceipt, "utf8");
  await writeFile(nestedReceipt, contents.replace(/^[0-9a-f]{64}/u, "00".repeat(32)));
  await sealRoot(artifact);
  const result = runVerifier(engine, artifact);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /semgrep\/SHA256SUMS\.txt checksum mismatch/u);
});

test("publication verifier rejects resealed source/run identity drift", async (t) => {
  const sourceArtifact = await createArtifact(t, "httpx");
  await mutateNested(sourceArtifact, "httpx", (evidence) => {
    evidence.sourceRevision = "cd".repeat(20);
  });
  let result = runVerifier("httpx", sourceArtifact);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /source revision mismatch/u);

  const runArtifact = await createArtifact(t, "nuclei");
  await mutateNested(runArtifact, "nuclei", (evidence) => {
    evidence.verification.workflowRun = `https://github.com/${repository}/actions/runs/999`;
  });
  result = runVerifier("nuclei", runArtifact);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /workflow run URL mismatch/u);
});

test("publication verifier rejects provenance that is signed for another source or run", async (t) => {
  const engine = "naabu";
  const artifact = await createArtifact(t, engine);
  const bundleFile = path.join(artifact, engine, `${engine}-provenance.sigstore.json`);
  const bundle = JSON.parse(await readFile(bundleFile, "utf8"));
  const statement = JSON.parse(Buffer.from(bundle.dsseEnvelope.payload, "base64").toString("utf8"));
  statement.predicate.buildDefinition.resolvedDependencies[0].digest.gitCommit = "cd".repeat(20);
  statement.predicate.runDetails.metadata.invocationId = `https://github.com/${repository}/actions/runs/999/attempts/1`;
  bundle.dsseEnvelope.payload = Buffer.from(JSON.stringify(statement)).toString("base64");
  await writeJson(bundleFile, bundle);

  const manifestFile = path.join(artifact, engine, `${engine}-image-supply-chain.json`);
  const manifest = JSON.parse(await readFile(manifestFile, "utf8"));
  const record = await fileRecord(bundleFile);
  manifest.attestations[0].bundleSha256 = record.sha256;
  manifest.attestations[0].bundleSizeBytes = record.sizeBytes;
  await writeJson(manifestFile, manifest);
  await sealNested(artifact, engine);
  await sealRoot(artifact);

  const result = runVerifier(engine, artifact);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /provenance source revision/u);
  assert.equal(result.stdout, "");
});

test("publication verifier rejects a resealed local smoke receipt mismatch", async (t) => {
  const engine = "trivy";
  const artifact = await createArtifact(t, engine);
  const summaryFile = path.join(artifact, `${engine}-image-manifest.json`);
  const summary = JSON.parse(await readFile(summaryFile, "utf8"));
  summary.managedSmokeEvidenceSha256 = `sha256:${"ff".repeat(32)}`;
  await writeJson(summaryFile, summary);
  await sealRoot(artifact);
  const result = runVerifier(engine, artifact);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /managed smoke receipt hash/u);
});

test("publication verifier rejects missing gateway platform transformations even after resealing", async (t) => {
  const engine = "egress-gateway";
  const artifact = await createArtifact(t, engine);
  await mutateNested(artifact, engine, (evidence) => {
    evidence.sbomTransformations.pop();
  });
  const result = runVerifier(engine, artifact);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /two SBOM transformations/u);
});

test("publication verifier rejects a cryptographically invalid bundle without stdout", async (t) => {
  const artifact = await createArtifact(t, "naabu");
  const result = runVerifier("naabu", artifact, { cryptographicFailure: true });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /cryptographic verification failed/u);
  assert.equal(result.stdout, "");
});

test("publication verifier accepts a bounded SBOM whose verified CLI envelope exceeds 16 MiB", async (t) => {
  const artifact = await createArtifact(t, "prowler", { largeSbom: true });
  const bundle = JSON.parse(await readFile(path.join(artifact, "prowler/prowler-amd64-spdx.sigstore.json"), "utf8"));
  const statement = JSON.parse(Buffer.from(bundle.dsseEnvelope.payload, "base64").toString("utf8"));
  assert.ok(Buffer.byteLength(JSON.stringify({ bundle, statement })) > 16 * 1024 * 1024);
  const result = runVerifier("prowler", artifact);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(JSON.parse(result.stdout).engine, "prowler");
});

test("publication verifier rejects unbounded CLI output without a success receipt", async (t) => {
  const artifact = await createArtifact(t, "prowler");
  const result = runVerifier("prowler", artifact, { extraOutputBytes: 65 * 1024 * 1024 });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /attestation verifier could not be executed/u);
  assert.equal(result.stdout, "");
});

test("publication verifier rejects unsafe checksum paths and symlinks", async (t) => {
  const unsafeArtifact = await createArtifact(t, "httpx");
  const checksumFile = path.join(unsafeArtifact, "SHA256SUMS.txt");
  const checksums = await readFile(checksumFile, "utf8");
  await writeFile(checksumFile, checksums.replace("./httpx-image-manifest.json", "./../httpx-image-manifest.json"));
  let result = runVerifier("httpx", unsafeArtifact);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /unsafe path/u);
  assert.equal(result.stdout, "");

  const symlinkArtifact = await createArtifact(t, "nuclei");
  const unexpectedLink = path.join(symlinkArtifact, "unexpected-link");
  try {
    await symlink("nuclei-image-manifest.json", unexpectedLink);
  } catch (error) {
    if (process.platform !== "win32" || error?.code !== "EPERM") throw error;
    await symlink(path.join(symlinkArtifact, "nuclei"), unexpectedLink, "junction");
  }
  result = runVerifier("nuclei", symlinkArtifact);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /contains a symlink/u);
  assert.equal(result.stdout, "");
});

// Recreate signed fixture payloads and receipts after an origin change, so the
// refusal is attributable to publication policy rather than stale checksums.
async function changeArtifactOrigin(root, engine, namespace, sourceRepository) {
  for (const name of await regularFiles(root)) {
    if (!name.endsWith(".json")) continue;
    const file = path.join(root, name);
    let text = await readFile(file, "utf8");
    text = text.replaceAll("ghcr.io/teddashh/", `${namespace}/`)
      .replaceAll(repository, sourceRepository);
    const value = JSON.parse(text);
    if (value.dsseEnvelope) {
      const payload = Buffer.from(value.dsseEnvelope.payload, "base64").toString("utf8")
        .replaceAll("ghcr.io/teddashh/", `${namespace}/`)
        .replaceAll(repository, sourceRepository);
      value.dsseEnvelope.payload = Buffer.from(payload).toString("base64");
    }
    await writeJson(file, value);
  }
  const manifest = path.join(root, engine, `${engine}-image-supply-chain.json`);
  const evidence = JSON.parse(await readFile(manifest, "utf8"));
  for (const platform of evidence.platforms) for (const sbom of platform.sboms) {
    Object.assign(sbom, await fileRecord(path.join(root, engine, sbom.file)));
  }
  for (const record of evidence.attestations) {
    const receipt = await fileRecord(path.join(root, engine, record.bundleFile));
    record.bundleSha256 = receipt.sha256; record.bundleSizeBytes = receipt.sizeBytes;
  }
  await writeJson(manifest, evidence); await sealNested(root, engine); await sealRoot(root);
}

test("publication artifact accepts current origin and rejects both mixed pairs and unknown owner", async (t) => {
  for (const [namespace, sourceRepository, passes] of [
    ["ghcr.io/ted-h-com", "TED-H-com/ai-security-scanner", true],
    ["ghcr.io/ted-h-com", "teddashh/ai-security-scanner", false],
    ["ghcr.io/teddashh", "TED-H-com/ai-security-scanner", false],
    ["ghcr.io/unknown", "unknown/ai-security-scanner", false],
  ]) {
    const artifact = await createArtifact(t, "httpx");
    await changeArtifactOrigin(artifact, "httpx", namespace, sourceRepository);
    const result = runVerifier("httpx", artifact);
    assert.equal(result.status === 0, passes, result.stderr);
    if (!passes) assert.match(result.stderr, /publication origin/u);
  }
});


test("cloud and standalone publication summaries reject drift from signed evidence", async (t) => {
  for (const [engine, mutate, error] of [
    ["prowler", (summary) => { summary.platformDigests["linux/arm64"] = indexDigest; }, /cloud root platform digest mismatch/u],
    ["steampipe", (summary) => { summary.public = false; }, /must record public access/u],
    ["checkov", (summary) => { summary.sourceDateEpoch = "1"; }, /source epoch mismatch/u],
    ["syft", (summary) => { summary.sourceRevision = "ff".repeat(20); }, /source revision mismatch/u],
  ]) {
    const artifact = await createArtifact(t, engine);
    const file = path.join(artifact, `${engine}-image-manifest.json`);
    const summary = JSON.parse(await readFile(file, "utf8"));
    mutate(summary);
    await writeJson(file, summary);
    const result = runVerifier(engine, artifact);
    assert.notEqual(result.status, 0, engine);
    assert.match(result.stderr, error);
  }
});
