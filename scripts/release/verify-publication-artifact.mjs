#!/usr/bin/env node

import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { lstat, readdir, readFile, realpath } from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { isDeepStrictEqual } from "node:util";

import { publicationOrigin, validateRepositoryId, certificateOriginMatches, provenanceOriginMatches, validateImageSourceLabels } from "../publication-origins.mjs";
const DIGEST_PATTERN = /^sha256:[0-9a-f]{64}$/u;
const HASH_PATTERN = /^[0-9a-f]{64}$/u;
const REVISION_PATTERN = /^[0-9a-f]{40}$/u;
const POSITIVE_INTEGER_PATTERN = /^[1-9][0-9]*$/u;
const MAX_FILES = 64;
const MAX_DIRECTORIES = 16;
const MAX_TOTAL_BYTES = 512 * 1024 * 1024;
const MAX_JSON_BYTES = 64 * 1024 * 1024;
const MAX_SBOM_BYTES = 16 * 1024 * 1024;
const MAX_CHECKSUM_BYTES = 64 * 1024;

const ENGINE_SPECS = Object.freeze({
  steampipe: { tag: "2.4.7-1", group: "cloud", workflow: ".github/workflows/engine-images-cloud.yml" },
  prowler: { tag: "5.44.0-1", group: "cloud", workflow: ".github/workflows/engine-images-cloud.yml" },
  checkov: { tag: "3.3.29-1", group: "standalone", workflow: ".github/workflows/engine-image-checkov.yml", sourceDateEpoch: "1791891584" },
  syft: { tag: "1.54.1-1", group: "standalone", workflow: ".github/workflows/engine-image-syft.yml" },
  naabu: { tag: "2.6.1-7", group: "external", workflow: ".github/workflows/engine-images-external.yml" },
  httpx: { tag: "1.12.0-1", group: "external", workflow: ".github/workflows/engine-images-external.yml" },
  nuclei: { tag: "3.11.1-8", group: "external", workflow: ".github/workflows/engine-images-external.yml" },
  semgrep: { tag: "1.181.0-1", group: "local", workflow: ".github/workflows/engine-images-local-k8s.yml", smokeFiles: ["semgrep.json"] },
  trufflehog: { tag: "3.99.2-1", group: "local", workflow: ".github/workflows/engine-images-local-k8s.yml", smokeFiles: ["trufflehog.jsonl"] },
  trivy: {
    tag: "0.76.1-1",
    group: "local",
    workflow: ".github/workflows/engine-images-local-k8s.yml",
    smokeFiles: ["trivy-oci.json", "trivy-library.json", "trivy-jar.json"],
  },
  grype: { tag: "0.120.1-1", group: "local", workflow: ".github/workflows/engine-images-local-k8s.yml", smokeFiles: ["grype.json"] },
  kubescape: { tag: "4.0.16-1", group: "local", workflow: ".github/workflows/engine-images-local-k8s.yml", smokeFiles: ["kubescape.json"] },
  "kube-bench": { tag: "0.16.0-5", group: "local", workflow: ".github/workflows/engine-images-local-k8s.yml", smokeFiles: ["kube-bench.json"] },
  "mcp-armor": {
    tag: "1.0.2-config-only.1",
    group: "local",
    workflow: ".github/workflows/engine-image-mcp-armor.yml",
    smokeFiles: ["mcp-armor.json"],
  },
  "agentic-radar": {
    tag: "0.14.1-1",
    group: "local",
    workflow: ".github/workflows/engine-image-agentic-radar.yml",
    smokeFiles: ["agentic-radar.json"],
  },
  garak: {
    tag: "0.17.0-1", group: "local", workflow: ".github/workflows/engine-image-garak.yml",
    smokeFiles: ["report.jsonl", "garak-execution.json", "native-qa.json"],
  },
  scubagear: { tag: "1.8.0-8", group: "m365", workflow: ".github/workflows/engine-images-m365.yml" },
  maester: { tag: "2.0.0-9", group: "m365", workflow: ".github/workflows/engine-images-m365.yml" },
  "egress-gateway": { tag: "0.3.0-1", group: "gateway", workflow: ".github/workflows/managed-egress-gateway-image.yml" },
});

const PLATFORMS = ["linux/amd64", "linux/arm64"];
const SBOM_SPECS = [
  { format: "spdx-json", suffix: "spdx", predicateType: "https://spdx.dev/Document/v2.3" },
  { format: "cyclonedx-json", suffix: "cyclonedx", predicateType: "https://cyclonedx.org/bom" },
];
const M365_SMOKE_CONTRACT = Object.freeze({
  platform: "linux/amd64",
  nonRoot: true,
  fixedEntrypoint: true,
  missingOutputMountRejected: true,
  missingScopeMountRejected: true,
  missingCredentialMountRejected: true,
  moduleLockVerified: true,
  dependencyNoticesVerified: true,
});
const PROVENANCE_PREDICATE = "https://slsa.dev/provenance/v1";
const SEMGREP_PASSES = { product: 10, upstream: 12, combined: 22, managed: 22 };
const SEMGREP_REFUSALS = { "changed-rule": 126, "changed-provenance": 126, "extra-rule": 126, "writable-workspace": 126 };

function fail(message) {
  throw new Error(message);
}

function assert(condition, message) {
  if (!condition) fail(message);
}

function object(value, label) {
  assert(value !== null && typeof value === "object" && !Array.isArray(value), `${label} must be an object`);
  return value;
}

function exactKeys(value, expected, label) {
  object(value, label);
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  assert(isDeepStrictEqual(actual, wanted), `${label} fields are not the exact publication contract`);
}

function equalSet(actual, expected, label) {
  assert(
    isDeepStrictEqual([...actual].sort(), [...expected].sort()),
    `${label} does not exactly match the publication contract`,
  );
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function imageFor(engine, origin) {
  return engine === "egress-gateway"
    ? `${origin.namespace}/ai-security-scanner-egress-gateway`
    : `${origin.namespace}/ai-security-scanner-engine-${engine}`;
}

function parseCli(argv) {
  const allowed = new Set(["engine", "artifact-dir", "source-revision", "run-id", "attempt"]);
  const values = new Map();
  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    assert(token.startsWith("--") && !token.includes("="), `unexpected argument: ${token}`);
    const key = token.slice(2);
    assert(allowed.has(key), `unsupported argument: --${key}`);
    assert(!values.has(key), `duplicate argument: --${key}`);
    const value = argv[index + 1];
    assert(value !== undefined && !value.startsWith("--"), `--${key} requires one value`);
    values.set(key, value);
    index += 1;
  }
  for (const key of allowed) assert(values.has(key), `--${key} is required`);
  return Object.fromEntries(values);
}

function assertRelativePath(relative, label) {
  assert(
    typeof relative === "string"
      && relative.length > 0
      && relative.length <= 512
      && !path.isAbsolute(relative)
      && !relative.includes("\\")
      && !relative.includes("\0")
      && !relative.startsWith("/")
      && relative.split("/").every((component) => component.length > 0 && component !== "." && component !== ".."),
    `${label} contains an unsafe path`,
  );
}

async function inventoryDirectory(root) {
  const rootMetadata = await lstat(root);
  assert(rootMetadata.isDirectory() && !rootMetadata.isSymbolicLink(), "--artifact-dir must be a real directory");
  const canonicalRoot = await realpath(root);
  const files = new Map();
  let totalBytes = 0;
  let directoryCount = 1;

  async function walk(directory, prefix = "") {
    const initialFileCount = files.size;
    const entries = await readdir(directory, { withFileTypes: true });
    for (const entry of entries) {
      const relative = prefix ? `${prefix}/${entry.name}` : entry.name;
      assertRelativePath(relative, "artifact inventory");
      const absolute = path.join(directory, entry.name);
      const metadata = await lstat(absolute);
      assert(!metadata.isSymbolicLink(), `artifact contains a symlink: ${relative}`);
      if (metadata.isDirectory()) {
        directoryCount += 1;
        assert(directoryCount <= MAX_DIRECTORIES, `artifact contains more than ${MAX_DIRECTORIES} directories`);
        await walk(absolute, relative);
      } else {
        assert(metadata.isFile(), `artifact contains a special file: ${relative}`);
        assert(!files.has(relative), `artifact contains a duplicate file path: ${relative}`);
        files.set(relative, { absolute, bytes: metadata.size });
        totalBytes += metadata.size;
        assert(files.size <= MAX_FILES, `artifact contains more than ${MAX_FILES} files`);
        assert(totalBytes <= MAX_TOTAL_BYTES, "artifact exceeds the verification byte limit");
      }
    }
    if (prefix) assert(files.size > initialFileCount, `artifact contains an empty directory: ${prefix}`);
  }

  await walk(canonicalRoot);
  return files;
}

async function readInventoryFile(files, relative, maximum, label) {
  const record = files.get(relative);
  assert(record, `${label} is missing: ${relative}`);
  assert(record.bytes <= maximum, `${label} exceeds its byte limit: ${relative}`);
  const before = await lstat(record.absolute);
  assert(before.isFile() && !before.isSymbolicLink() && before.size === record.bytes, `${label} changed during verification: ${relative}`);
  const bytes = await readFile(record.absolute);
  const after = await lstat(record.absolute);
  assert(
    after.isFile()
      && !after.isSymbolicLink()
      && after.size === before.size
      && after.mtimeMs === before.mtimeMs,
    `${label} changed during verification: ${relative}`,
  );
  return bytes;
}

function utf8(bytes, label) {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    fail(`${label} is not valid UTF-8`);
  }
}

async function readJson(files, relative, label) {
  const bytes = await readInventoryFile(files, relative, MAX_JSON_BYTES, label);
  try {
    return JSON.parse(utf8(bytes, label));
  } catch (error) {
    fail(`${label} is not valid JSON: ${error instanceof Error ? error.message : String(error)}`);
  }
}

function parseChecksums(contents, { label, rootStyle }) {
  assert(contents.endsWith("\n") && !contents.endsWith("\n\n"), `${label} must end with exactly one newline`);
  const lines = contents.slice(0, -1).split("\n");
  assert(lines.length > 0 && lines.every(Boolean), `${label} must not contain blank lines`);
  const checksums = new Map();
  for (const line of lines) {
    const match = line.match(/^([0-9a-f]{64})  ([^\0\r\n]+)$/u);
    assert(match, `${label} contains a malformed checksum line`);
    const raw = match[2];
    assert(rootStyle ? raw.startsWith("./") : !raw.startsWith("./"), `${label} contains a non-canonical path`);
    const relative = rootStyle ? raw.slice(2) : raw;
    assertRelativePath(relative, label);
    assert(!checksums.has(relative), `${label} contains a duplicate path: ${relative}`);
    checksums.set(relative, match[1]);
  }
  return checksums;
}

async function verifyChecksums(files, checksumRelative, expectedLocalFiles, { rootStyle = false } = {}) {
  const bytes = await readInventoryFile(files, checksumRelative, MAX_CHECKSUM_BYTES, "checksum inventory");
  const checksums = parseChecksums(utf8(bytes, checksumRelative), {
    label: checksumRelative,
    rootStyle,
  });
  equalSet(checksums.keys(), expectedLocalFiles, `${checksumRelative} coverage`);
  const directory = path.posix.dirname(checksumRelative);
  for (const [local, expected] of checksums) {
    const relative = directory === "." ? local : `${directory}/${local}`;
    const actual = await readInventoryFile(files, relative, MAX_JSON_BYTES, "checksummed artifact file");
    assert(sha256(actual) === expected, `${checksumRelative} checksum mismatch: ${local}`);
  }
  return { checksums, receiptSha256: `sha256:${sha256(bytes)}` };
}

function expectedNestedFiles(engine) {
  return [
    `${engine}-image-supply-chain.json`,
    `${engine}-linux-amd64.spdx.json`,
    `${engine}-linux-amd64.cyclonedx.json`,
    `${engine}-linux-arm64.spdx.json`,
    `${engine}-linux-arm64.cyclonedx.json`,
    `${engine}-provenance.sigstore.json`,
    `${engine}-amd64-spdx.sigstore.json`,
    `${engine}-amd64-cyclonedx.sigstore.json`,
    `${engine}-arm64-spdx.sigstore.json`,
    `${engine}-arm64-cyclonedx.sigstore.json`,
  ];
}

function expectedArtifactFiles(engine, spec) {
  const nested = expectedNestedFiles(engine).map((file) => `${engine}/${file}`);
  const expected = [...(["cloud", "standalone"].includes(spec.group) ? [] : ["SHA256SUMS.txt"]), `${engine}/SHA256SUMS.txt`, ...nested];
  if (spec.group !== "gateway") expected.push(`${engine}-image-manifest.json`);
  if (spec.group === "local") {
    expected.push(`${engine}-managed-smoke/SHA256SUMS.txt`);
    expected.push(...spec.smokeFiles.map((file) => `${engine}-managed-smoke/${file}`));
  }
  if (engine === "semgrep") {
    for (const arch of ["amd64", "arm64"]) {
      const prefix = `semgrep-native-${arch}/`;
      expected.push(`${prefix}verification.json`, `${prefix}published-payload.json`);
      for (const name of Object.keys(SEMGREP_PASSES)) expected.push(`${prefix}${name}.log`, `${prefix}${name}/semgrep.json`);
      for (const name of Object.keys(SEMGREP_REFUSALS)) expected.push(`${prefix}${name}.log`);
    }
  }
  return expected;
}

async function verifySemgrepNativeEvidence(files, sourceRevision, version) {
  for (const arch of ["amd64", "arm64"]) {
    const prefix = `semgrep-native-${arch}/`;
    const receipt = await readJson(files, `${prefix}verification.json`, "Semgrep native receipt");
    assert(receipt.source_revision === sourceRevision && receipt.expected_version === version, "Semgrep native source/version mismatch");
    assert(isDeepStrictEqual(receipt.execution, { mode: "native", host_architecture: arch, image_architecture: arch }), "Semgrep requires actual native verification for each architecture");
    assert(isDeepStrictEqual(receipt.native_matches, SEMGREP_PASSES) && receipt.exact_full_result_union === true, "Semgrep native full-result union receipt is incomplete");
    assert(isDeepStrictEqual(receipt.rejections_before_output, SEMGREP_REFUSALS), "Semgrep native refusal controls are incomplete");
    const source = receipt.source_attachment;
    assert(source?.selected_original_files === 1477 && source.excluded_rule_absent === true && source.unfiltered_rules_archive_absent === true && source.rebuild_inputs_match === true, "Semgrep selected-source verification is incomplete");
    assertHash(source.sha256, "Semgrep source attachment hash");
    const published = await readJson(files, `${prefix}published-payload.json`, "Semgrep published filesystem receipt");
    assertHash(receipt.image_payload?.rootfs_payload_sha256, "Semgrep native filesystem hash");
    assert(published.schema_version === 1 && published.rootfs_payload_sha256 === receipt.image_payload.rootfs_payload_sha256, "Semgrep published filesystem differs from native verification");
    const passes = {};
    for (const [name, count] of Object.entries(SEMGREP_PASSES)) {
      const scan = await readJson(files, `${prefix}${name}/semgrep.json`, "Semgrep native scan");
      assert(Array.isArray(scan.results) && scan.results.length === count && isDeepStrictEqual(scan.errors, []), "Semgrep native scan count/errors mismatch");
      passes[name] = scan.results;
    }
    for (const name of ["combined", "managed"]) {
      const remaining = [...passes[name]];
      for (const result of [...passes.product, ...passes.upstream]) {
        const index = remaining.findIndex((row) => isDeepStrictEqual(row, result));
        assert(index >= 0, "Semgrep complete native results differ from the separate-pass union");
        remaining.splice(index, 1);
      }
      assert(remaining.length === 0, "Semgrep native output contains unexpected results");
    }
    assert(receipt.managed_artifact_sha256 === sha256(await readInventoryFile(files, `${prefix}managed/semgrep.json`, MAX_JSON_BYTES, "Semgrep managed native artifact")), "Semgrep managed native artifact hash mismatch");
  }
}

function assertDigest(value, label) {
  assert(typeof value === "string" && DIGEST_PATTERN.test(value), `${label} is not a SHA-256 OCI digest`);
}

function assertHash(value, label) {
  assert(typeof value === "string" && HASH_PATTERN.test(value), `${label} is not a SHA-256 hash`);
}

function strictBase64(value, label) {
  assert(typeof value === "string" && value.length > 0 && /^[A-Za-z0-9+/]+={0,2}$/u.test(value), `${label} is not base64`);
  const decoded = Buffer.from(value, "base64");
  assert(decoded.length > 0 && decoded.toString("base64") === value, `${label} is not canonical base64`);
  return decoded;
}

function validateGatewayTransformations(transformations, sourceRevision, platformRecords) {
  assert(Array.isArray(transformations) && transformations.length === 2, "gateway must have two SBOM transformations");
  for (let index = 0; index < PLATFORMS.length; index += 1) {
    const platform = PLATFORMS[index];
    const architecture = platform.split("/")[1];
    const record = object(transformations[index], `gateway transformation ${platform}`);
    exactKeys(record, [
      "kind", "platform", "platformDigest", "sourceRevision", "sourceFile", "outputFile",
      "componentBomRef", "spdxPreserved", "spdxFileCount", "spdxFileChecksumStatus",
      "spdxZeroSha1PlaceholderCount", "spdxSha256", "tool",
    ], `gateway transformation ${platform}`);
    assert(record.kind === "cyclonedx-first-party-scratch-application-v3", `gateway transformation kind is wrong: ${platform}`);
    assert(record.platform === platform, `gateway transformation platform order is wrong: ${platform}`);
    assert(record.platformDigest === platformRecords.get(platform).digest, `gateway transformation digest mismatch: ${platform}`);
    assert(record.sourceRevision === sourceRevision, `gateway transformation source revision mismatch: ${platform}`);
    assert(record.sourceFile === `egress-gateway-linux-${architecture}.spdx.json`, `gateway transformation SPDX file mismatch: ${platform}`);
    assert(record.outputFile === `egress-gateway-linux-${architecture}.cyclonedx.json`, `gateway transformation CycloneDX file mismatch: ${platform}`);
    assert(record.componentBomRef === `urn:ai-security-scanner:egress-gateway:${record.platformDigest.slice(7)}`, `gateway transformation component identity mismatch: ${platform}`);
    assert(record.spdxPreserved === true, `gateway transformation did not preserve SPDX: ${platform}`);
    assert(record.spdxFileCount === 2, `gateway transformation SPDX file count mismatch: ${platform}`);
    assert(record.spdxFileChecksumStatus === "unavailable-syft-zero-sha1-placeholder", `gateway transformation checksum status mismatch: ${platform}`);
    assert(record.spdxZeroSha1PlaceholderCount === 2, `gateway transformation placeholder count mismatch: ${platform}`);
    assert(record.spdxSha256 === platformRecords.get(platform).sboms.get("spdx-json").sha256, `gateway transformation SPDX hash mismatch: ${platform}`);
    exactKeys(record.tool, ["name", "version"], `gateway transformation tool ${platform}`);
    assert(record.tool.name === "ai-security-scanner/scripts/engine-image-evidence.mjs" && record.tool.version === "3", `gateway transformation tool mismatch: ${platform}`);
  }
}

export function validateProvenancePredicate(predicate, { spec, sourceRevision, runId, attempt, origin }) {
  const REPOSITORY = origin.repository;
  const RUN_URL_PREFIX = `https://github.com/${REPOSITORY}/actions/runs/`;
  validateRepositoryId(predicate);
  assert(provenanceOriginMatches(predicate, origin), "provenance repository mismatch");
  const buildDefinition = object(predicate.buildDefinition, "provenance build definition");
  assert(
    buildDefinition.buildType === "https://actions.github.io/buildtypes/workflow/v1",
    "provenance build type mismatch",
  );
  const externalParameters = object(
    buildDefinition.externalParameters,
    "provenance external parameters",
  );
  const workflow = object(externalParameters.workflow, "provenance workflow");
  assert(workflow.repository === `https://github.com/${REPOSITORY}`, "provenance repository mismatch");
  assert(workflow.ref === "refs/heads/main", "provenance workflow ref mismatch");
  assert(workflow.path === spec.workflow, "provenance workflow path mismatch");
  assert(Array.isArray(buildDefinition.resolvedDependencies), "provenance dependencies are missing");
  assert(
    buildDefinition.resolvedDependencies.some((dependency) =>
      dependency?.uri === `git+https://github.com/${REPOSITORY}@refs/heads/main`
      && dependency?.digest?.gitCommit === sourceRevision),
    "provenance source revision is not bound to the repository",
  );
  const runDetails = object(predicate.runDetails, "provenance run details");
  const builder = object(runDetails.builder, "provenance builder");
  assert(
    builder.id === `https://github.com/${REPOSITORY}/${spec.workflow}@refs/heads/main`,
    "provenance builder identity mismatch",
  );
  const metadata = object(runDetails.metadata, "provenance run metadata");
  assert(
    metadata.invocationId === `${RUN_URL_PREFIX}${runId}/attempts/${attempt}`,
    "provenance workflow run identity mismatch",
  );
}

export function validateVerifiedCertificate(certificate, { image, spec, sourceRevision, runId, attempt }) {
  const { repository: REPOSITORY } = publicationOrigin(image);
  const signerIdentity = `https://github.com/${REPOSITORY}/${spec.workflow}@refs/heads/main`;
  const invocation = `https://github.com/${REPOSITORY}/actions/runs/${runId}/attempts/${attempt}`;
  validateRepositoryId(certificate);
  assert(certificateOriginMatches(certificate, publicationOrigin(image)), "verified certificate owner mismatch");
  assert(certificate.sourceRepositoryURI === `https://github.com/${REPOSITORY}`, "verified certificate repository mismatch");
  assert(certificate.sourceRepositoryDigest === sourceRevision, "verified certificate source digest mismatch");
  assert(certificate.sourceRepositoryRef === "refs/heads/main", "verified certificate source ref mismatch");
  assert(certificate.githubWorkflowRepository === REPOSITORY, "verified certificate workflow repository mismatch");
  assert(certificate.githubWorkflowSHA === sourceRevision, "verified certificate workflow digest mismatch");
  assert(certificate.buildSignerURI === signerIdentity, "verified certificate signer identity mismatch");
  assert(certificate.buildSignerDigest === sourceRevision, "verified certificate signer digest mismatch");
  assert(certificate.subjectAlternativeName === signerIdentity, "verified certificate subject identity mismatch");
  assert(certificate.runInvocationURI === invocation, "verified certificate run identity mismatch");
  assert(certificate.runnerEnvironment === "github-hosted", "verified certificate runner is not GitHub-hosted");
  assert(certificate.sourceRepositoryVisibilityAtSigning === "public", "verified certificate did not record a public source repository");
}

function verifyBundleCryptographically({
  bundlePath,
  image,
  digest,
  predicateType,
  spec,
  sourceRevision,
  runId,
  attempt,
}) {
  const { repository: REPOSITORY } = publicationOrigin(image);
  const signerWorkflow = `${REPOSITORY}/${spec.workflow}`;
  const result = spawnSync("gh", [
    "attestation", "verify", `oci://${image}@${digest}`,
    "--bundle", bundlePath,
    "--repo", REPOSITORY,
    "--signer-workflow", signerWorkflow,
    "--signer-digest", sourceRevision,
    "--source-digest", sourceRevision,
    "--source-ref", "refs/heads/main",
    "--deny-self-hosted-runners",
    "--predicate-type", predicateType,
    "--format", "json",
  ], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
    // gh returns both the encoded bundle and its decoded statement. A valid
    // SBOM below MAX_SBOM_BYTES can therefore exceed that limit in CLI JSON.
    maxBuffer: MAX_JSON_BYTES,
    timeout: 45_000,
  });
  assert(!result.error, `GitHub attestation verifier could not be executed (${path.basename(bundlePath)}: ${result.error?.code ?? "unknown error"})`);
  assert(result.status === 0, "Sigstore bundle cryptographic verification failed");
  let records;
  try {
    records = JSON.parse(result.stdout);
  } catch {
    fail("GitHub attestation verifier returned invalid JSON");
  }
  assert(Array.isArray(records) && records.length === 1, "GitHub attestation verifier returned an unexpected record set");
  const verification = object(records[0]?.verificationResult, "cryptographic verification result");
  const certificate = object(verification.signature?.certificate, "verified signing certificate");
  validateVerifiedCertificate(certificate, { image, spec, sourceRevision, runId, attempt });
  assert(
    Array.isArray(verification.verifiedTimestamps)
      && verification.verifiedTimestamps.some((timestamp) => timestamp?.type === "Tlog"),
    "verified attestation has no transparency-log timestamp",
  );
  const statement = object(verification.statement, "cryptographically verified statement");
  assert(statement.predicateType === predicateType, "cryptographically verified predicate mismatch");
  if (predicateType === PROVENANCE_PREDICATE) validateProvenancePredicate(statement.predicate, {
    spec, sourceRevision, runId, attempt, origin: publicationOrigin(image),
  });
  const subject = Array.isArray(statement.subject)
    ? statement.subject.find((candidate) => candidate?.name === image)
    : undefined;
  assert(subject?.digest?.sha256 === digest.slice(7), "cryptographically verified subject mismatch");
}

async function verifySupplyChain({ files, engine, spec, sourceRevision, runId, attempt }) {
  const manifestRelative = `${engine}/${engine}-image-supply-chain.json`;
  const evidence = object(await readJson(files, manifestRelative, "supply-chain manifest"), "supply-chain manifest");
  exactKeys(evidence, [
    "schemaVersion", "engine", "image", "tag", "indexDigest", "sourceRevision", "public",
    "generator", "sbomTransformations", "imageBuild", "platforms", "attestations",
    "verification", "checksumsFile",
  ], "supply-chain manifest");
  const origin = publicationOrigin(evidence.image, evidence.verification?.repository);
  const REPOSITORY = origin.repository;
  const RUN_URL_PREFIX = `https://github.com/${REPOSITORY}/actions/runs/`;
  const ATTESTATION_URL_PREFIX = `https://github.com/${REPOSITORY}/attestations/`;
  const image = imageFor(engine, origin);
  assert(evidence.schemaVersion === 1, "supply-chain schemaVersion must be 1");
  assert(evidence.engine === engine, "supply-chain engine mismatch");
  assert(evidence.image === image, "supply-chain image repository mismatch");
  assert(evidence.tag === spec.tag, "supply-chain image tag mismatch");
  assertDigest(evidence.indexDigest, "supply-chain index digest");
  assert(evidence.sourceRevision === sourceRevision, "supply-chain source revision mismatch");
  assert(evidence.public === true, "supply-chain evidence must record public access");
  assert(evidence.checksumsFile === "SHA256SUMS.txt", "nested checksum filename mismatch");

  exactKeys(evidence.generator, ["name", "version", "image"], "SBOM generator");
  assert(evidence.generator.name === "anchore/syft", "unexpected SBOM generator");
  assert(evidence.generator.version === "1.51.0", "unexpected SBOM generator version");
  assert(evidence.generator.image === "anchore/syft@sha256:678bfa565b60f747aac0f8e964fe5588a24445b8d0a480e91f6efd70020dfbb0", "unexpected SBOM generator image");
  exactKeys(evidence.imageBuild, ["inlineProvenance", "inlineSbom", "digestMutatedByEvidence"], "image evidence mode");
  assert(evidence.imageBuild.inlineProvenance === false && evidence.imageBuild.inlineSbom === false && evidence.imageBuild.digestMutatedByEvidence === false, "image evidence mode can mutate the publication digest");

  exactKeys(evidence.verification, [
    "repository", "workflowRun", "runAttempt", "registryReferrers", "githubAttestationApi",
    "onlineVerificationRequiredBeforeUpload",
  ], "publication verification");
  assert(evidence.verification.repository === REPOSITORY, "publication repository mismatch");
  assert(evidence.verification.workflowRun === `${RUN_URL_PREFIX}${runId}`, "publication workflow run URL mismatch");
  assert(evidence.verification.runAttempt === attempt, "publication workflow attempt mismatch");
  assert(evidence.verification.registryReferrers === true, "registry referrer verification was not recorded");
  assert(evidence.verification.githubAttestationApi === true, "GitHub attestation verification was not recorded");
  assert(evidence.verification.onlineVerificationRequiredBeforeUpload === true, "pre-upload online verification was not recorded");

  assert(Array.isArray(evidence.platforms) && evidence.platforms.length === 2, "supply-chain evidence must contain two platforms");
  const platformRecords = new Map();
  const sbomDocuments = new Map();
  for (let index = 0; index < PLATFORMS.length; index += 1) {
    const platformName = PLATFORMS[index];
    const architecture = platformName.split("/")[1];
    const platform = object(evidence.platforms[index], `platform ${platformName}`);
    exactKeys(platform, ["platform", "digest", "sboms"], `platform ${platformName}`);
    assert(platform.platform === platformName, `platform order mismatch: ${platformName}`);
    assertDigest(platform.digest, `platform digest ${platformName}`);
    assert(Array.isArray(platform.sboms) && platform.sboms.length === 2, `platform must have two SBOMs: ${platformName}`);
    const sboms = new Map();
    for (let sbomIndex = 0; sbomIndex < SBOM_SPECS.length; sbomIndex += 1) {
      const expected = SBOM_SPECS[sbomIndex];
      const sbom = object(platform.sboms[sbomIndex], `${platformName} ${expected.format} record`);
      exactKeys(sbom, ["format", "predicateType", "file", "sha256", "sizeBytes"], `${platformName} ${expected.format} record`);
      const expectedFile = `${engine}-linux-${architecture}.${expected.suffix}.json`;
      assert(sbom.format === expected.format && sbom.predicateType === expected.predicateType, `SBOM format contract mismatch: ${platformName}`);
      assert(sbom.file === expectedFile, `SBOM filename mismatch: ${platformName} ${expected.format}`);
      assertHash(sbom.sha256, `SBOM hash ${sbom.file}`);
      assert(Number.isSafeInteger(sbom.sizeBytes) && sbom.sizeBytes > 0 && sbom.sizeBytes <= MAX_SBOM_BYTES, `SBOM size is invalid: ${sbom.file}`);
      const relative = `${engine}/${sbom.file}`;
      const bytes = await readInventoryFile(files, relative, MAX_SBOM_BYTES, "SBOM");
      assert(bytes.length === sbom.sizeBytes, `SBOM byte count mismatch: ${sbom.file}`);
      assert(sha256(bytes) === sbom.sha256, `SBOM hash mismatch: ${sbom.file}`);
      const document = await readJson(files, relative, "SBOM");
      object(document, `SBOM document ${sbom.file}`);
      validateImageSourceLabels(document.metadata, origin);
      sboms.set(expected.format, sbom);
      sbomDocuments.set(sbom.file, document);
    }
    platformRecords.set(platformName, { digest: platform.digest, sboms });
  }
  assert(platformRecords.get("linux/amd64").digest !== platformRecords.get("linux/arm64").digest, "platform digests must be distinct");

  if (spec.group === "gateway") {
    validateGatewayTransformations(evidence.sbomTransformations, sourceRevision, platformRecords);
  } else {
    assert(Array.isArray(evidence.sbomTransformations) && evidence.sbomTransformations.length === 0, "engine evidence must not contain gateway SBOM transformations");
  }

  assert(Array.isArray(evidence.attestations) && evidence.attestations.length === 5, "supply-chain evidence must contain five attestations");
  const attestationIds = new Set();
  const attestationUrls = new Set();
  const expectedAttestations = [
    { key: "provenance", kind: "build-provenance", platform: null, predicateType: PROVENANCE_PREDICATE, digest: evidence.indexDigest, predicateFile: null },
    ...PLATFORMS.flatMap((platformName) => {
      const architecture = platformName.split("/")[1];
      return SBOM_SPECS.map((sbom) => ({
        key: `${architecture}-${sbom.suffix}`,
        kind: "sbom",
        platform: platformName,
        predicateType: sbom.predicateType,
        digest: platformRecords.get(platformName).digest,
        predicateFile: `${engine}-linux-${architecture}.${sbom.suffix}.json`,
      }));
    }),
  ];
  for (let index = 0; index < expectedAttestations.length; index += 1) {
    const expected = expectedAttestations[index];
    const record = object(evidence.attestations[index], `attestation ${expected.key}`);
    exactKeys(record, [
      "kind", "platform", "predicateType", "subject", "bundleFile", "bundleSha256",
      "bundleSizeBytes", "attestationId", "attestationUrl", "registryPushed",
      "githubAttestationsApi",
    ], `attestation ${expected.key}`);
    assert(record.kind === expected.kind && record.platform === expected.platform, `attestation scope mismatch: ${expected.key}`);
    assert(record.predicateType === expected.predicateType, `attestation predicate mismatch: ${expected.key}`);
    exactKeys(record.subject, ["name", "digest"], `attestation subject ${expected.key}`);
    assert(record.subject.name === image && record.subject.digest === expected.digest, `attestation subject mismatch: ${expected.key}`);
    const expectedBundle = `${engine}-${expected.key}.sigstore.json`;
    assert(record.bundleFile === expectedBundle, `attestation bundle filename mismatch: ${expected.key}`);
    assertHash(record.bundleSha256, `attestation bundle hash ${expected.key}`);
    assert(Number.isSafeInteger(record.bundleSizeBytes) && record.bundleSizeBytes > 0, `attestation bundle size is invalid: ${expected.key}`);
    assert(typeof record.attestationId === "string" && POSITIVE_INTEGER_PATTERN.test(record.attestationId), `attestation id is invalid: ${expected.key}`);
    assert(!attestationIds.has(record.attestationId), `attestation id is duplicated: ${expected.key}`);
    attestationIds.add(record.attestationId);
    assert(record.attestationUrl === `${ATTESTATION_URL_PREFIX}${record.attestationId}`, `attestation URL does not match its id: ${expected.key}`);
    assert(!attestationUrls.has(record.attestationUrl), `attestation URL is duplicated: ${expected.key}`);
    attestationUrls.add(record.attestationUrl);
    const attestationUrl = new URL(record.attestationUrl);
    assert(attestationUrl.origin === "https://github.com" && !attestationUrl.search && !attestationUrl.hash, `attestation URL is not canonical: ${expected.key}`);
    assert(record.registryPushed === true && record.githubAttestationsApi === true, `attestation persistence was not recorded: ${expected.key}`);

    const bundleRelative = `${engine}/${record.bundleFile}`;
    const bundleBytes = await readInventoryFile(files, bundleRelative, MAX_JSON_BYTES, "attestation bundle");
    assert(bundleBytes.length === record.bundleSizeBytes, `attestation bundle byte count mismatch: ${expected.key}`);
    assert(sha256(bundleBytes) === record.bundleSha256, `attestation bundle hash mismatch: ${expected.key}`);
    const bundle = object(await readJson(files, bundleRelative, "attestation bundle"), `attestation bundle ${expected.key}`);
    assert(typeof bundle.mediaType === "string" && bundle.mediaType.includes("sigstore.bundle"), `attestation bundle media type mismatch: ${expected.key}`);
    object(bundle.verificationMaterial, `attestation verification material ${expected.key}`);
    const envelope = object(bundle.dsseEnvelope, `attestation DSSE envelope ${expected.key}`);
    assert(envelope.payloadType === "application/vnd.in-toto+json", `attestation DSSE payload type mismatch: ${expected.key}`);
    assert(Array.isArray(envelope.signatures) && envelope.signatures.length > 0, `attestation DSSE signature is missing: ${expected.key}`);
    for (const signature of envelope.signatures) strictBase64(object(signature, `attestation signature ${expected.key}`).sig, `attestation signature ${expected.key}`);
    const statementBytes = strictBase64(envelope.payload, `attestation payload ${expected.key}`);
    let statement;
    try {
      statement = object(JSON.parse(utf8(statementBytes, `attestation statement ${expected.key}`)), `attestation statement ${expected.key}`);
    } catch (error) {
      fail(`attestation statement is invalid: ${expected.key}: ${error instanceof Error ? error.message : String(error)}`);
    }
    assert(statement._type === "https://in-toto.io/Statement/v1", `attestation statement type mismatch: ${expected.key}`);
    assert(statement.predicateType === expected.predicateType, `attestation statement predicate mismatch: ${expected.key}`);
    assert(Array.isArray(statement.subject), `attestation statement subject is missing: ${expected.key}`);
    const subject = statement.subject.find((candidate) => candidate?.name === image);
    assert(subject?.digest?.sha256 === expected.digest.slice(7), `attestation statement subject mismatch: ${expected.key}`);
    object(statement.predicate, `attestation predicate ${expected.key}`);
    if (expected.key === "provenance") {
      validateProvenancePredicate(statement.predicate, {
        spec,
        origin,
        sourceRevision,
        runId,
        attempt,
      });
    } else if (expected.predicateFile) {
      assert(isDeepStrictEqual(statement.predicate, sbomDocuments.get(expected.predicateFile)), `attested SBOM differs from its file: ${expected.key}`);
    }
    verifyBundleCryptographically({
      bundlePath: files.get(bundleRelative).absolute,
      image,
      digest: expected.digest,
      predicateType: expected.predicateType,
      spec,
      sourceRevision,
      runId,
      attempt,
    });
  }

  return { evidence, platformRecords };
}

async function verifyRootSummary({ files, engine, spec, sourceRevision, evidence, platformRecords }) {
  if (spec.group === "gateway") return undefined;
  const relative = `${engine}-image-manifest.json`;
  const summary = object(await readJson(files, relative, "root image summary"), "root image summary");
  const common = ["schemaVersion", ...(spec.group === "standalone" ? [] : ["engine"]), "image", "tag", "digest", "sourceRevision"];
  exactKeys(
    summary,
    spec.group === "local"
      ? [...common, "platformDigests", "anonymousPullVerified", "managedSmokeEvidenceSha256"]
      : spec.group === "m365"
        ? [...common, "platforms", "platformDigests", "public", "anonymousPullVerified", "smoke"]
      : spec.group === "cloud"
        ? [...common, "platforms", "platformDigests", "public"]
      : spec.sourceDateEpoch
        ? [...common, "platforms", "public", "sourceDateEpoch"]
      : [...common, "platforms", "public"],
    "root image summary",
  );
  assert(summary.schemaVersion === 1 && (spec.group === "standalone" || summary.engine === engine), "root image summary identity mismatch");
  assert(summary.image === evidence.image && summary.tag === evidence.tag, "root image summary repository/tag mismatch");
  assert(summary.digest === evidence.indexDigest, "root image summary index digest mismatch");
  assert(summary.sourceRevision === sourceRevision && summary.sourceRevision === evidence.sourceRevision, "root image summary source revision mismatch");
  if (["cloud", "standalone"].includes(spec.group)) {
    assert(summary.public === true, "root summary must record public access");
    assert(isDeepStrictEqual(summary.platforms, PLATFORMS), "root summary platform list mismatch");
    if (spec.sourceDateEpoch) assert(summary.sourceDateEpoch === spec.sourceDateEpoch, "root summary source epoch mismatch");
    if (spec.group === "cloud") {
      exactKeys(summary.platformDigests, PLATFORMS, "cloud root platform digests");
      for (const platform of PLATFORMS) {
        assert(summary.platformDigests[platform] === platformRecords.get(platform).digest, `cloud root platform digest mismatch: ${platform}`);
      }
    }
    return undefined;
  }
  if (spec.group === "external") {
    assert(summary.public === true, "external root summary must record public access");
    assert(isDeepStrictEqual(summary.platforms, PLATFORMS), "external root summary platform list mismatch");
    return undefined;
  }
  if (spec.group === "m365") {
    assert(summary.public === true, "Microsoft 365 root summary must record public access");
    assert(summary.anonymousPullVerified === true, "Microsoft 365 root summary must record anonymous pull verification");
    assert(isDeepStrictEqual(summary.platforms, PLATFORMS), "Microsoft 365 root summary platform list mismatch");
    exactKeys(summary.platformDigests, PLATFORMS, "Microsoft 365 root platform digests");
    for (const platform of PLATFORMS) {
      assert(summary.platformDigests[platform] === platformRecords.get(platform).digest, `Microsoft 365 root platform digest mismatch: ${platform}`);
    }
    exactKeys(summary.smoke, Object.keys(M365_SMOKE_CONTRACT), "Microsoft 365 smoke summary");
    assert(isDeepStrictEqual(summary.smoke, M365_SMOKE_CONTRACT), "Microsoft 365 smoke summary does not match the fixed publication contract");
    return undefined;
  }
  assert(summary.anonymousPullVerified === true, "local root summary must record anonymous pull verification");
  exactKeys(summary.platformDigests, PLATFORMS, "root platform digests");
  for (const platform of PLATFORMS) {
    assert(summary.platformDigests[platform] === platformRecords.get(platform).digest, `root platform digest mismatch: ${platform}`);
  }
  assert(typeof summary.managedSmokeEvidenceSha256 === "string" && DIGEST_PATTERN.test(summary.managedSmokeEvidenceSha256), "managed smoke receipt hash is malformed");
  return summary.managedSmokeEvidenceSha256;
}

async function verifyGarakNativeEvidence(files, evidence) {
  const prefix = "garak-managed-smoke/";
  const report = await readInventoryFile(files, `${prefix}report.jsonl`, 32 * 1024 * 1024, "native Garak report");
  const rows = utf8(report, "native Garak JSONL").trim().split("\n").map((line) => JSON.parse(line));
  const expected = new Map([
    ["dan.Dan_11_0", ["dan.DAN", 1]], ["dan.Dan_10_0", ["dan.DAN", 1]],
    ["dan.Dan_9_0", ["dan.DAN", 1]], ["ansiescape.AnsiEscaped", ["ansiescape.Escaped", 51]],
  ]);
  function validateEvals(evals, positive) {
    assert(evals.length === 4, "Garak native profile must preserve all four detector pairs");
    for (const [probe, [detector, count]] of expected) {
      const matches = evals.filter((row) => row.probe === probe);
      assert(matches.length === 1 && matches[0].detector === detector && matches[0].total_evaluated === count &&
        matches[0].total_processed === count && matches[0].nones === 0 && matches[0].fails === (positive ? count : 0),
      `Garak native detector counts differ: ${probe}`);
    }
  }
  const init = rows.filter((row) => row.entry_type === "init");
  const terminal = rows.filter((row) => row.entry_type === "completion");
  assert(init.length === 1 && init[0].garak_version === "0.17.0" && typeof init[0].run === "string" && init[0].run &&
    terminal.length === 1 && terminal[0].run === init[0].run, "Garak native report lacks its matching terminal completion");
  validateEvals(rows.filter((row) => row.entry_type === "eval"), true);
  const receipt = await readJson(files, `${prefix}garak-execution.json`, "Garak native execution receipt");
  const qa = await readJson(files, `${prefix}native-qa.json`, "Garak controlled native QA");
  assert(qa.schema_version === 1 && qa.platform === "linux/amd64" && qa.native_version === "0.17.0" &&
    qa.image === `${evidence.image}@${evidence.indexDigest}` && DIGEST_PATTERN.test(qa.image_id) &&
    qa.network_internal === true && qa.unapproved_destinations === 0, "Garak native QA image or network identity differs");
  equalSet(qa.cases.map((result) => result.case), ["positive", "clean", "redirect", "bad-tls", "deadline", "cancelled"], "Garak native QA cases");
  for (const result of qa.cases) {
    if (result.case === "cancelled") {
      assert(result.exit_code !== 0 && result.no_requests_after_stop === true && result.receipt?.complete === false &&
        result.receipt?.reason === "native_cancelled" && HASH_PATTERN.test(result.raw_sha256), "Garak cancellation lost partial native output or continued model contact");
      continue;
    }
    const record = object(result.receipt, "Garak execution receipt");
    assert(record.schema_version === "1" && record.profile_id === "garak_https_v1" && HASH_PATTERN.test(record.scope_sha256) &&
      record.max_http_attempts === 64 && record.max_completion_tokens_per_request === 150 && record.max_total_request_bytes === 65536 &&
      Number.isInteger(record.http_attempts) && record.http_attempts >= 0 && record.http_attempts <= 64 &&
      Number.isInteger(record.total_request_bytes) && record.total_request_bytes >= 0 && record.total_request_bytes <= 65536,
    "Garak receipt does not preserve the bounded inference contract");
    if (["positive", "clean"].includes(result.case)) {
      assert(result.exit_code === 0 && record.complete === true && record.reason === null && record.http_attempts === 54 &&
        result.observed_http_requests === 54, "Garak completed run did not perform all native prompts");
      validateEvals(result.evals, result.case === "positive");
      if (result.case === "positive") {
        assert(result.raw_sha256 === sha256(report) && isDeepStrictEqual(record, receipt), "Garak positive raw output or receipt changed");
      }
    } else {
      assert(result.exit_code !== 0 && record.complete === false && result.evals.length === 0, "Garak interrupted native run was labeled complete");
      if (result.case === "redirect") assert(record.reason === "redirect_refused" && record.http_attempts === 1 && result.observed_http_requests === 1, "Garak redirect was followed");
      if (result.case === "bad-tls") assert(record.http_attempts === 1 && result.observed_http_requests === 0, "Garak bypassed TLS verification");
      if (result.case === "deadline") assert(record.reason === "inference_deadline" && record.http_attempts <= 6, "Garak exceeded the short native deadline");
    }
  }
}

async function verifyPublicationArtifact(args) {
  const spec = ENGINE_SPECS[args.engine];
  assert(spec, `unsupported --engine; expected one of: ${Object.keys(ENGINE_SPECS).join(", ")}`);
  assert(REVISION_PATTERN.test(args["source-revision"]), "--source-revision must be one full lowercase 40-character Git revision");
  assert(POSITIVE_INTEGER_PATTERN.test(args["run-id"]), "--run-id must be a canonical positive integer");
  assert(POSITIVE_INTEGER_PATTERN.test(args.attempt), "--attempt must be a canonical positive integer");

  const files = await inventoryDirectory(path.resolve(args["artifact-dir"]));
  const expectedFiles = expectedArtifactFiles(args.engine, spec);
  equalSet(files.keys(), expectedFiles, "artifact file inventory");
  const rootCovered = expectedFiles.filter((relative) => relative !== "SHA256SUMS.txt");
  // These established publishers seal the nested signed evidence; their root
  // summaries are cross-checked against that evidence below.
  const rootReceipt = ["cloud", "standalone"].includes(spec.group)
    ? { receiptSha256: null, checksums: new Map() }
    : await verifyChecksums(files, "SHA256SUMS.txt", rootCovered, { rootStyle: true });
  const nestedExpected = expectedNestedFiles(args.engine);
  const nestedReceipt = await verifyChecksums(
    files,
    `${args.engine}/SHA256SUMS.txt`,
    nestedExpected,
  );

  const { evidence, platformRecords } = await verifySupplyChain({
    files,
    engine: args.engine,
    spec,
    sourceRevision: args["source-revision"],
    runId: args["run-id"],
    attempt: args.attempt,
  });
  const expectedSmokeReceipt = await verifyRootSummary({
    files,
    engine: args.engine,
    spec,
    sourceRevision: args["source-revision"],
    evidence,
    platformRecords,
  });

  let managedSmokeEvidenceSha256;
  if (spec.group === "local") {
    const smoke = await verifyChecksums(
      files,
      `${args.engine}-managed-smoke/SHA256SUMS.txt`,
      spec.smokeFiles,
    );
    assert(smoke.receiptSha256 === expectedSmokeReceipt, "managed smoke receipt hash does not match the root image summary");
    managedSmokeEvidenceSha256 = smoke.receiptSha256;
  }
  if (args.engine === "semgrep") await verifySemgrepNativeEvidence(files, args["source-revision"], spec.tag);
  if (args.engine === "garak") await verifyGarakNativeEvidence(files, evidence);

  const platformDigests = Object.fromEntries(
    PLATFORMS.map((platform) => [platform, platformRecords.get(platform).digest]),
  );
  return {
    schemaVersion: 1,
    engine: args.engine,
    image: evidence.image,
    tag: evidence.tag,
    indexDigest: evidence.indexDigest,
    platformDigests,
    sourceRevision: evidence.sourceRevision,
    workflowRun: evidence.verification.workflowRun,
    runId: args["run-id"],
    runAttempt: args.attempt,
    evidence: {
      rootChecksumReceiptSha256: rootReceipt.receiptSha256,
      nestedChecksumReceiptSha256: nestedReceipt.receiptSha256,
      rootChecksumEntries: rootReceipt.checksums.size,
      nestedChecksumEntries: nestedReceipt.checksums.size,
      sbomCount: 4,
      attestationCount: 5,
      ...(managedSmokeEvidenceSha256 ? { managedSmokeEvidenceSha256 } : {}),
      ...(spec.group === "gateway" ? { sbomTransformationPlatforms: [...PLATFORMS] } : {}),
    },
  };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const args = parseCli(process.argv.slice(2));
    const payload = await verifyPublicationArtifact(args);
    process.stdout.write(`${JSON.stringify(payload)}\n`);
  } catch (error) {
    process.stderr.write(`publication artifact verification failed: ${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  }
}
