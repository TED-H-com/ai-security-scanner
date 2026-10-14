import { execFileSync } from "node:child_process";
import { isDeepStrictEqual } from "node:util";
import {
  copyFile,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { CURRENT_PUBLICATION_ORIGIN, publicationOrigin, validateRepositoryId, certificateOriginMatches, provenanceOriginMatches, validateImageSourceLabels } from "./publication-origins.mjs";
import { validateReplacementHistory } from "./engine-image-replacement.mjs";

import {
  PROJECT_ROOT,
  parseArgs,
  readJson,
  requireString,
  runMain,
  sha256,
  sha256File,
  writeJsonAtomic,
  writeTextAtomic,
} from "./release/lib.mjs";

const DIGEST_PATTERN = /^sha256:[0-9a-f]{64}$/u;
const SOURCE_REVISION_PATTERN = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/u;
const ENGINE_PATTERN = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/u;
const IMAGE_PATTERN = /^[a-z0-9.-]+\/[a-z0-9._/-]+$/u;
const TAG_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]*$/u;
const GHCR_INDEX_ACCEPT = [
  "application/vnd.oci.image.index.v1+json",
  "application/vnd.docker.distribution.manifest.list.v2+json",
].join(", ");
const MAX_ATTESTABLE_SBOM_BYTES = 16 * 1024 * 1024;
const SYFT = Object.freeze({
  name: "anchore/syft",
  version: "1.51.0",
  image: "anchore/syft@sha256:678bfa565b60f747aac0f8e964fe5588a24445b8d0a480e91f6efd70020dfbb0",
});
const PREDICATES = Object.freeze({
  provenance: "https://slsa.dev/provenance/v1",
  spdx: "https://spdx.dev/Document/v2.3",
  cyclonedx: "https://cyclonedx.org/bom",
});
const CLOUD_ENGINE_IDS = Object.freeze(["cloudquery", "prowler", "cloudsplaining", "scoutsuite", "steampipe"]);
const GATEWAY_SCRATCH_SBOM = Object.freeze({
  engine: "egress-gateway",
  image: `${CURRENT_PUBLICATION_ORIGIN.namespace}/ai-security-scanner-egress-gateway`,
  componentName: "ai-security-scanner-egress-gateway",
  source: `https://github.com/${CURRENT_PUBLICATION_ORIGIN.repository}`,
  title: "ai-security-scanner managed egress gateway",
  license: "Apache-2.0",
  fileNames: Object.freeze([
    "usr/local/bin/ai-security-scanner-egress-gateway",
    "usr/local/bin/ai-security-scanner-egress-probe",
  ]),
  normalizationProperty: "ai-security-scanner:normalization:components",
  normalizationValue: "first-party-scratch-application-from-preserved-spdx-v3",
  fileChecksumStatus: "unavailable-syft-zero-sha1-placeholder",
});
const PROJECT_SBOM_TRANSFORMER = Object.freeze({
  name: "ai-security-scanner/scripts/engine-image-evidence.mjs",
  version: "3",
});
const SYFT_UNAVAILABLE_FILE_SHA1 = "0".repeat(40);

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function staticEnvironmentEvidenceEngines(workflowSource, relative) {
  assert(typeof workflowSource === "string" && workflowSource.length > 0, `${relative}: workflow source is empty`);
  const lines = workflowSource.split(/\r?\n/u);
  const topLevelEnvIndexes = lines
    .map((line, index) => line === "env:" ? index : -1)
    .filter((index) => index >= 0);
  const topLevelEngines = [];
  for (const envIndex of topLevelEnvIndexes) {
    for (let index = envIndex + 1; index < lines.length; index += 1) {
      const line = lines[index];
      if (line.length > 0 && !/^\s/u.test(line)) break;
      const match = line.match(/^  ENGINE:\s*([a-z0-9](?:[a-z0-9-]*[a-z0-9])?)\s*$/u);
      if (match) topLevelEngines.push(match[1]);
    }
  }

  const resolved = new Set();
  for (let index = 0; index < lines.length; index += 1) {
    const uses = lines[index].match(/^(\s*)uses:\s*\.\/\.github\/actions\/engine-image-evidence\s*$/u);
    if (!uses) continue;
    const stepIndent = uses[1].length;
    let configured = null;
    for (let child = index + 1; child < lines.length; child += 1) {
      const line = lines[child];
      if (line.trim().length === 0 || line.trimStart().startsWith("#")) continue;
      const indent = line.match(/^\s*/u)[0].length;
      if (indent < stepIndent) break;
      const engine = line.match(/^\s*engine:\s*(.+?)\s*$/u);
      if (engine) {
        assert(configured === null, `${relative}: evidence step has duplicate engine inputs`);
        configured = engine[1];
      }
    }
    assert(typeof configured === "string", `${relative}: evidence step has no static engine input`);
    if (configured === "${{ env.ENGINE }}") {
      assert(topLevelEngines.length === 1, `${relative}: env.ENGINE must have one top-level literal value`);
      const engine = topLevelEngines[0];
      assert(
        ENGINE_PATTERN.test(engine),
        `${relative}: env.ENGINE must resolve to one static engine id`,
      );
      resolved.add(engine);
    } else {
      assert(
        ENGINE_PATTERN.test(configured) || configured === "${{ matrix.engine }}",
        `${relative}: evidence engine must be literal, static env.ENGINE, or matrix.engine`,
      );
    }
  }
  return resolved;
}

function digestHex(digest) {
  assert(DIGEST_PATTERN.test(digest), `invalid OCI digest: ${String(digest)}`);
  return digest.slice("sha256:".length);
}

function platformKey(platform) {
  return platform.replace("linux/", "");
}

function outputLine(key, value) {
  assert(!String(value).includes("\n"), `GitHub output ${key} contains a newline`);
  return `${key}=${value}\n`;
}

function parseIndex(rawBytes, expectedDigest) {
  const expectedHex = digestHex(expectedDigest);
  const candidates = [rawBytes];
  if (rawBytes.at(-1) === 0x0a) candidates.push(rawBytes.subarray(0, rawBytes.length - 1));
  assert(
    candidates.some((candidate) => sha256(candidate) === expectedHex),
    "registry index bytes do not match the build output digest",
  );
  const index = JSON.parse(rawBytes.toString("utf8"));
  assert(Array.isArray(index.manifests), "published image is not a multi-platform OCI/Docker index");
  assert(index.manifests.length === 2, "image index must contain exactly two platform manifests");

  const result = new Map();
  for (const descriptor of index.manifests) {
    const operatingSystem = descriptor?.platform?.os;
    const architecture = descriptor?.platform?.architecture;
    if (operatingSystem !== "linux" || !["amd64", "arm64"].includes(architecture)) continue;
    const platform = `${operatingSystem}/${architecture}`;
    assert(!result.has(platform), `image index contains duplicate ${platform} descriptors`);
    digestHex(descriptor.digest);
    result.set(platform, descriptor.digest);
  }
  assert(result.size === 2, "image index must contain linux/amd64 and linux/arm64 manifests");
  for (const platform of ["linux/amd64", "linux/arm64"]) {
    assert(result.has(platform), `image index is missing ${platform}`);
  }
  return result;
}

function registryCoordinates(image) {
  assert(IMAGE_PATTERN.test(image) && !image.includes("@") && !image.includes(":"), `image must be an untagged fully-qualified name: ${image}`);
  const prefix = "ghcr.io/";
  assert(image.startsWith(prefix), "managed publication guard supports only ghcr.io images");
  const repository = image.slice(prefix.length);
  const [owner, ...packageParts] = repository.split("/");
  assert(owner && packageParts.length > 0, `invalid GHCR repository: ${image}`);
  return { owner, repository, packageName: packageParts.join("/") };
}

async function responseJson(response, label) {
  let value;
  try {
    value = JSON.parse(await response.text());
  } catch {
    throw new Error(`${label} did not return JSON (HTTP ${response.status})`);
  }
  return value;
}

async function ghcrPullToken({ image, username, token, fetchImpl = fetch }) {
  const { repository } = registryCoordinates(image);
  assert(typeof username === "string" && username.length > 0, "GHCR username is required");
  assert(typeof token === "string" && token.length > 0, "GHCR token is required");
  const url = new URL("https://ghcr.io/token");
  url.searchParams.set("service", "ghcr.io");
  url.searchParams.set("scope", `repository:${repository}:pull`);
  const response = await fetchImpl(url, {
    headers: {
      Accept: "application/json",
      Authorization: `Basic ${Buffer.from(`${username}:${token}`).toString("base64")}`,
    },
    signal: AbortSignal.timeout(20_000),
  });
  assert(response.ok, `GHCR token request failed closed (HTTP ${response.status})`);
  const value = await responseJson(response, "GHCR token endpoint");
  const bearer = value?.token ?? value?.access_token;
  assert(typeof bearer === "string" && bearer.length > 0, "GHCR token response omitted a bearer token");
  return bearer;
}

async function inspectGhcrTag({ image, tag, username, token, fetchImpl = fetch }) {
  assert(TAG_PATTERN.test(tag), `invalid image tag: ${tag}`);
  const { repository } = registryCoordinates(image);
  const bearer = await ghcrPullToken({ image, username, token, fetchImpl });
  const response = await fetchImpl(`https://ghcr.io/v2/${repository}/manifests/${encodeURIComponent(tag)}`, {
    headers: { Accept: GHCR_INDEX_ACCEPT, Authorization: `Bearer ${bearer}` },
    signal: AbortSignal.timeout(20_000),
  });
  const raw = Buffer.from(await response.arrayBuffer());
  if (response.status === 404) {
    let body;
    try {
      body = JSON.parse(raw.toString("utf8"));
    } catch {
      throw new Error("GHCR returned a malformed 404 while checking the version tag");
    }
    assert(
      Array.isArray(body?.errors) && body.errors.some((entry) => entry?.code === "MANIFEST_UNKNOWN"),
      "GHCR returned an unrecognized 404 while checking the version tag",
    );
    return { state: "absent" };
  }
  assert(response.ok, `GHCR manifest lookup failed closed (HTTP ${response.status})`);
  const digest = response.headers.get("docker-content-digest");
  digestHex(digest);
  assert(sha256(raw) === digestHex(digest), "GHCR content digest does not match the returned index bytes");
  const platformDigests = parseIndex(raw, digest);
  return { state: "present", digest, platformDigests };
}

export function matchingVerifiedProvenance(records, { image, digest, sourceRevision, repository, workflowRef }) {
  const origin = publicationOrigin(image, repository);
  assert(workflowRef.startsWith(`${repository}/.github/workflows/`) && workflowRef.includes("@refs/heads/"), "workflow ref does not identify the publication repository");
  const expectedRepositoryUrl = `https://github.com/${repository}`;
  const expectedSigner = `https://github.com/${workflowRef}`;
  const expectedSourceRef = workflowRef.slice(workflowRef.indexOf("@") + 1);
  return records.find((record) => {
    const result = record?.verificationResult;
    const statement = result?.statement;
    const certificate = result?.signature?.certificate;
    validateRepositoryId(certificate);
    validateRepositoryId(statement?.predicate);
    if (!certificateOriginMatches(certificate, origin) || !provenanceOriginMatches(statement?.predicate, origin)) return false;
    if (certificate?.sourceRepositoryRef !== undefined && certificate.sourceRepositoryRef !== expectedSourceRef) return false;
    if (certificate?.runInvocationURI !== undefined && !certificate.runInvocationURI.startsWith(`${expectedRepositoryUrl}/actions/runs/`)) return false;
    const workflow = statement?.predicate?.buildDefinition?.externalParameters?.workflow;
    if (workflow && (workflow.repository !== expectedRepositoryUrl || `${repository}/${workflow.path}@${workflow.ref}` !== workflowRef)) return false;
    const details = statement?.predicate?.runDetails;
    if (details?.builder && details.builder.id !== expectedSigner) return false;
    if (certificate?.subjectAlternativeName !== undefined && certificate.subjectAlternativeName !== expectedSigner) return false;
    if (statement?.predicateType !== PREDICATES.provenance) return false;
    if (!statement.subject?.some((subject) =>
      subject?.name === image && subject?.digest?.sha256 === digestHex(digest))) return false;
    const dependencies = statement?.predicate?.buildDefinition?.resolvedDependencies;
    if (!Array.isArray(dependencies) || !dependencies.some((dependency) =>
      dependency?.digest?.gitCommit === sourceRevision &&
      dependency?.uri === `git+${expectedRepositoryUrl}@${expectedSourceRef}`)) return false;
    return certificate?.sourceRepositoryURI === expectedRepositoryUrl &&
      certificate?.sourceRepositoryDigest === sourceRevision &&
      certificate?.githubWorkflowRepository === repository &&
      certificate?.githubWorkflowSHA === sourceRevision &&
      certificate?.buildSignerURI === expectedSigner &&
      certificate?.buildSignerDigest === sourceRevision &&
      certificate?.runnerEnvironment === "github-hosted";
  });
}

function verifiedProvenanceSourceRevision(records, { image, digest, repository, workflowRef }) {
  for (const record of records) {
    const sourceRevision = record?.verificationResult?.signature?.certificate?.sourceRepositoryDigest;
    if (!SOURCE_REVISION_PATTERN.test(sourceRevision ?? "")) continue;
    if (matchingVerifiedProvenance([record], { image, digest, sourceRevision, repository, workflowRef })) {
      return sourceRevision;
    }
  }
  return null;
}

function verifyPublishedProvenance({ image, digest, repository, workflowRef, exec = execFileSync }) {
  publicationOrigin(image, repository);
  assert(workflowRef.startsWith(`${repository}/.github/workflows/`) && workflowRef.includes("@refs/heads/"), "workflow ref does not identify this repository's branch workflow");
  let output;
  try {
    output = exec("gh", [
      "attestation", "verify", `oci://${image}@${digest}`,
      "--repo", repository,
      "--predicate-type", PREDICATES.provenance,
      "--format", "json",
    ], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  } catch (error) {
    const detail = typeof error?.stderr === "string" ? error.stderr.trim() : "";
    throw new Error(`existing digest has no verifiable GitHub build provenance${detail ? `: ${detail}` : ""}`);
  }
  const records = JSON.parse(output);
  assert(Array.isArray(records), "GitHub attestation verification returned an invalid record set");
  const sourceRevision = verifiedProvenanceSourceRevision(records, {
    image,
    digest,
    repository,
    workflowRef,
  });
  assert(
    sourceRevision,
    "version tag is already bound to an unrecognized source repository or workflow",
  );
  return sourceRevision;
}

function verifyProvenance({ image, digest, sourceRevision, repository, workflowRef, exec = execFileSync }) {
  assert(SOURCE_REVISION_PATTERN.test(sourceRevision), `invalid source revision: ${sourceRevision}`);
  const verifiedSourceRevision = verifyPublishedProvenance({
    image,
    digest,
    repository,
    workflowRef,
    exec,
  });
  assert(
    verifiedSourceRevision === sourceRevision,
    `version tag is already bound to a different source commit or workflow (expected ${sourceRevision})`,
  );
}

function managedEngineFromImage(image) {
  const { packageName } = registryCoordinates(image);
  const prefix = "ai-security-scanner-engine-";
  if (!packageName.startsWith(prefix)) return null;
  const engine = packageName.slice(prefix.length);
  assert(ENGINE_PATTERN.test(engine), `managed engine image has an invalid engine id: ${image}`);
  return engine;
}

function validateEnginePlanBinding(plan, { engine, image, tag, label }) {
  assert(plan && typeof plan === "object" && !Array.isArray(plan), `${label} engine input plan is not an object`);
  assert(plan.engine_id === engine, `${label} engine input plan does not identify ${engine}`);
  // Plans retain published pins; a new workflow may build the same package in the current namespace.
  publicationOrigin(plan.final_artifact?.repository);
  publicationOrigin(image);
  assert(
    plan.final_artifact.repository.split("/").at(-1) === image.split("/").at(-1) && plan.final_artifact?.tag === tag,
    `${label} engine input plan does not bind ${image}:${tag}`,
  );
}

export function recordedEngineInputIdentity(plan, { engine, image, tag, label = "current" }) {
  validateEnginePlanBinding(plan, { engine, image, tag, label });
  validateReplacementHistory(plan);
  const records = [];

  function visit(value, components) {
    if (components.length === 1 && ["final_artifact", "publication", "previous_artifact", "previous_publication"].includes(components[0])) return;
    if (typeof value === "string") {
      if (value.startsWith("sha256:")) {
        assert(DIGEST_PATTERN.test(value), `${label} engine input plan has an invalid digest at ${components.join(".")}`);
        records.push([components.join("."), value]);
      }
      return;
    }
    if (Array.isArray(value)) {
      value.forEach((entry, index) => visit(entry, [...components, String(index)]));
      return;
    }
    if (value && typeof value === "object") {
      for (const key of Object.keys(value).sort()) visit(value[key], [...components, key]);
    }
  }

  visit(plan, []);
  assert(
    records.some(([field]) => field === "dockerfile.sha256"),
    `${label} engine input plan has no recorded Dockerfile digest`,
  );
  return records;
}

async function readPublishedEnginePlan({ repository, engine, sourceRevision, token, fetchImpl = fetch }) {
  const planPath = `engines/images/${engine}/plan.json`;
  const url = new URL(`https://api.github.com/repos/${repository}/contents/${planPath}`);
  url.searchParams.set("ref", sourceRevision);
  const response = await fetchImpl(url, {
    headers: {
      Accept: "application/vnd.github.raw+json",
      Authorization: `Bearer ${token}`,
      "X-GitHub-Api-Version": "2022-11-28",
    },
    signal: AbortSignal.timeout(20_000),
  });
  assert(
    response.ok,
    `published engine input plan is unavailable at ${sourceRevision} (HTTP ${response.status})`,
  );
  try {
    return JSON.parse(await response.text());
  } catch {
    throw new Error(`published engine input plan is unreadable at ${sourceRevision}`);
  }
}

async function verifyRecordedInputsUnchanged({
  engine,
  image,
  tag,
  currentSourceRevision,
  publishedSourceRevision,
  repository,
  token,
  readCurrentPlan = () => readJson(path.join(PROJECT_ROOT, "engines", "images", engine, "plan.json")),
  readPublishedPlan = (inputs) => readPublishedEnginePlan(inputs),
}) {
  let currentPlan;
  try {
    currentPlan = await readCurrentPlan();
  } catch (error) {
    throw new Error(`current engine input plan is unavailable: ${error.message}`);
  }
  let publishedPlan = currentPlan;
  if (publishedSourceRevision !== currentSourceRevision) {
    try {
      publishedPlan = await readPublishedPlan({
        repository,
        engine,
        sourceRevision: publishedSourceRevision,
        token,
      });
    } catch (error) {
      throw new Error(`published engine input plan is unavailable: ${error.message}`);
    }
  }
  const currentIdentity = recordedEngineInputIdentity(currentPlan, {
    engine,
    image,
    tag,
    label: "current",
  });
  const publishedIdentity = recordedEngineInputIdentity(publishedPlan, {
    engine,
    image,
    tag,
    label: "published",
  });
  assert(
    isDeepStrictEqual(currentIdentity, publishedIdentity),
    `version tag is already bound to different recorded build inputs (published from ${publishedSourceRevision})`,
  );
}

async function appendGithubOutputs(entries) {
  const githubOutput = process.env.GITHUB_OUTPUT;
  assert(githubOutput, "GITHUB_OUTPUT is required for publication commands");
  await writeFile(githubOutput, entries.map(([key, value]) => outputLine(key, value)).join(""), { flag: "a" });
}

function publicationInputs(args) {
  const image = requireString(args, "image");
  const tag = requireString(args, "tag");
  const sourceRevision = requireString(args, "source-revision");
  const repository = requireString(args, "repository");
  const workflowRef = requireString(args, "workflow-ref");
  const username = requireString(args, "username");
  const token = process.env.GHCR_TOKEN;
  assert(TAG_PATTERN.test(tag), `invalid image tag: ${tag}`);
  assert(SOURCE_REVISION_PATTERN.test(sourceRevision), `invalid source revision: ${sourceRevision}`);
  assert(sourceRevision === process.env.GITHUB_SHA, "source revision does not match the executing workflow commit");
  assert(typeof token === "string" && token.length > 0, "GHCR_TOKEN is required");
  const origin = publicationOrigin(image, repository);
  validateRepositoryId({ repository_id: process.env.GITHUB_REPOSITORY_ID });
  assert(origin === CURRENT_PUBLICATION_ORIGIN, "new publications require the current origin");
  assert(workflowRef.startsWith(`${repository}/.github/workflows/`) && workflowRef.includes("@refs/heads/"), "workflow ref does not identify the publication repository");
  return { image, tag, sourceRevision, repository, workflowRef, username, token };
}

export async function publicationPreflight(args, dependencies = {}) {
  const inputs = publicationInputs(args);
  const inspectTag = dependencies.inspectGhcrTag ?? inspectGhcrTag;
  const verifyExistingProvenance = dependencies.verifyPublishedProvenance ?? verifyPublishedProvenance;
  const appendOutputs = dependencies.appendGithubOutputs ?? appendGithubOutputs;
  const writeStdout = dependencies.writeStdout ?? ((message) => process.stdout.write(message));
  const existing = await inspectTag(inputs);
  const runId = process.env.GITHUB_RUN_ID;
  const runAttempt = process.env.GITHUB_RUN_ATTEMPT;
  assert(/^[1-9][0-9]*$/u.test(runId ?? "") && /^[1-9][0-9]*$/u.test(runAttempt ?? ""), "GitHub run identity is invalid");
  const candidateTag = `candidate-${inputs.sourceRevision}-${runId}-${runAttempt}`;
  assert(TAG_PATTERN.test(candidateTag) && candidateTag.length <= 128, "generated candidate tag is invalid");
  if (existing.state === "present") {
    const publishedSourceRevision = verifyExistingProvenance({
      ...inputs,
      digest: existing.digest,
      exec: dependencies.exec ?? execFileSync,
    });
    const engine = managedEngineFromImage(inputs.image);
    if (engine) {
      await verifyRecordedInputsUnchanged({
        engine,
        image: inputs.image,
        tag: inputs.tag,
        currentSourceRevision: inputs.sourceRevision,
        publishedSourceRevision,
        repository: inputs.repository,
        token: inputs.token,
        readCurrentPlan: dependencies.readCurrentPlan,
        readPublishedPlan: dependencies.readPublishedPlan,
      });
    } else {
      assert(
        publishedSourceRevision === inputs.sourceRevision,
        `version tag is already bound to a different source commit or workflow (expected ${inputs.sourceRevision})`,
      );
    }
    await appendOutputs([
      ["mode", "reuse"],
      ["should_build", "false"],
      ["digest", existing.digest],
      ["candidate_tag", candidateTag],
    ]);
    writeStdout(
      `Reusing verified immutable version ${inputs.image}:${inputs.tag}@${existing.digest}; recorded build inputs are unchanged.\n`,
    );
    return;
  }
  await appendOutputs([
    ["mode", "build"],
    ["should_build", "true"],
    ["digest", ""],
    ["candidate_tag", candidateTag],
  ]);
  writeStdout(`Version ${inputs.image}:${inputs.tag} is absent; a unique candidate may be built.\n`);
}

export async function promotePublication(args, dependencies = {}) {
  const inputs = publicationInputs(args);
  const inspectTag = dependencies.inspectGhcrTag ?? inspectGhcrTag;
  const verifyExistingProvenance = dependencies.verifyPublishedProvenance ?? verifyPublishedProvenance;
  const verifyInputsUnchanged = dependencies.verifyRecordedInputsUnchanged ?? verifyRecordedInputsUnchanged;
  const verifyCandidateProvenance = dependencies.verifyProvenance ?? verifyProvenance;
  const appendOutputs = dependencies.appendGithubOutputs ?? appendGithubOutputs;
  const dockerExec = dependencies.execFileSync ?? execFileSync;
  const writeStdout = dependencies.writeStdout ?? ((message) => process.stdout.write(message));
  const mode = requireString(args, "mode");
  assert(["build", "reuse"].includes(mode), `invalid publication mode: ${mode}`);
  const digest = requireString(args, "digest");
  digestHex(digest);
  if (mode === "reuse") {
    const existing = await inspectTag(inputs);
    assert(existing.state === "present", `reused version tag disappeared before final verification: ${inputs.image}:${inputs.tag}`);
    assert(existing.digest === digest, `reused version tag changed during verification (${existing.digest} != ${digest})`);
    const publishedSourceRevision = verifyExistingProvenance({ ...inputs, digest });
    const engine = managedEngineFromImage(inputs.image);
    if (engine) {
      await verifyInputsUnchanged({
        engine,
        image: inputs.image,
        tag: inputs.tag,
        currentSourceRevision: inputs.sourceRevision,
        publishedSourceRevision,
        repository: inputs.repository,
        token: inputs.token,
      });
    } else {
      assert(
        publishedSourceRevision === inputs.sourceRevision,
        `version tag is already bound to a different source commit or workflow (expected ${inputs.sourceRevision})`,
      );
    }
    await appendOutputs([["digest", digest], ["promoted", "false"]]);
    writeStdout(`Reverified reused immutable version ${inputs.image}:${inputs.tag}@${digest}; no registry mutation performed.\n`);
    return;
  }
  verifyCandidateProvenance({ ...inputs, digest });
  const existing = await inspectTag(inputs);
  if (existing.state === "present") {
    assert(existing.digest === digest, `refusing to overwrite ${inputs.image}:${inputs.tag} (${existing.digest} != ${digest})`);
    await appendOutputs([["digest", digest], ["promoted", "false"]]);
    writeStdout(`Verified existing immutable version ${inputs.image}:${inputs.tag}@${digest}; no registry mutation performed.\n`);
    return;
  }
  dockerExec("docker", [
    "buildx", "imagetools", "create",
    "--tag", `${inputs.image}:${inputs.tag}`,
    `${inputs.image}@${digest}`,
  ], { stdio: "inherit" });
  const promoted = await inspectTag(inputs);
  assert(promoted.state === "present" && promoted.digest === digest, "promoted version tag does not resolve to the attested candidate digest");
  await appendOutputs([["digest", digest], ["promoted", "true"]]);
  writeStdout(`Promoted immutable version ${inputs.image}:${inputs.tag}@${digest}.\n`);
}

function affectedCloudEngines(changedPaths, eventName) {
  if (eventName === "workflow_dispatch") return [...CLOUD_ENGINE_IDS];
  assert(eventName === "push", `unsupported cloud publication event: ${eventName}`);
  assert(Array.isArray(changedPaths) && changedPaths.every((entry) => typeof entry === "string" && entry.length > 0), "changed paths are invalid");
  const shared = changedPaths.some((entry) => entry.startsWith("engines/images/cloud-launcher/"));
  if (shared) return [...CLOUD_ENGINE_IDS];
  const selected = CLOUD_ENGINE_IDS.filter((engine) => changedPaths.some((entry) =>
    entry.startsWith(`engines/images/${engine}/`) && entry !== `engines/images/${engine}/plan.json`));
  assert(selected.length > 0, "cloud publication trigger did not map to an affected engine");
  return selected;
}

async function selectCloudEngines(args) {
  const eventName = requireString(args, "event-name");
  const before = requireString(args, "before");
  const after = requireString(args, "after");
  const matrix = JSON.parse(requireString(args, "matrix-json"));
  assert(Array.isArray(matrix) && matrix.length === CLOUD_ENGINE_IDS.length, "cloud matrix must be a five-entry array");
  assert(
    isDeepStrictEqual(matrix.map((entry) => entry?.engine), CLOUD_ENGINE_IDS) &&
      matrix.every((entry) => TAG_PATTERN.test(entry?.tag ?? "") && /^engines\/images\/[a-z0-9-]+\/Dockerfile$/u.test(entry?.dockerfile ?? "")),
    "cloud matrix does not match the exact managed-engine contract",
  );
  let selectedIds;
  if (eventName === "workflow_dispatch" || /^0{40}$/u.test(before)) {
    selectedIds = affectedCloudEngines([], "workflow_dispatch");
  } else {
    assert(SOURCE_REVISION_PATTERN.test(before) && SOURCE_REVISION_PATTERN.test(after), "cloud selection revisions are invalid");
    const output = execFileSync("git", ["diff", "--name-only", "--diff-filter=ACMRT", `${before}..${after}`, "--"], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    });
    selectedIds = affectedCloudEngines(output.split(/\r?\n/u).filter(Boolean), "push");
  }
  const selected = new Set(selectedIds);
  const publicationMatrix = { include: matrix.filter((entry) => selected.has(entry.engine)) };
  await appendGithubOutputs([
    ["engines", JSON.stringify(selectedIds)],
    ["matrix", JSON.stringify(publicationMatrix)],
  ]);
  process.stdout.write(`Selected cloud engine publication matrix: ${selectedIds.join(", ")}.\n`);
}

function describedSpdxPackage(document) {
  assert(document?.spdxVersion === "SPDX-2.3", "SBOM is not SPDX 2.3 JSON");
  assert(document?.SPDXID === "SPDXRef-DOCUMENT", "SPDX document identity is missing");
  assert(Array.isArray(document.packages) && document.packages.length > 0, "SPDX package inventory is empty");
  const describes = document.relationships?.find(
    (relationship) =>
      relationship?.spdxElementId === "SPDXRef-DOCUMENT" &&
      relationship?.relationshipType === "DESCRIBES",
  );
  assert(describes?.relatedSpdxElement, "SPDX document does not identify the described image");
  const root = document.packages.find((entry) => entry?.SPDXID === describes.relatedSpdxElement);
  assert(root, "SPDX described-image package is absent");
  return root;
}

function validateSpdx(document, platformDigest) {
  const root = describedSpdxPackage(document);
  const expectedHex = digestHex(platformDigest);
  assert(root.versionInfo === platformDigest, "SPDX described image version is not the platform digest");
  assert(
    root.checksums?.some(
      (checksum) => checksum?.algorithm === "SHA256" && checksum?.checksumValue === expectedHex,
    ),
    "SPDX described image checksum is not the platform digest",
  );
}

function validateCycloneDxSubject(document, platformDigest) {
  digestHex(platformDigest);
  assert(document?.bomFormat === "CycloneDX", "SBOM is not CycloneDX JSON");
  assert(/^1\.[0-9]+$/u.test(document?.specVersion ?? ""), "CycloneDX specVersion is invalid");
  assert(document?.metadata?.component?.type === "container", "CycloneDX metadata does not describe a container");
  assert(
    document.metadata.component.version === platformDigest,
    "CycloneDX described image version is not the platform digest",
  );
}

function validateCycloneDx(document, platformDigest) {
  validateCycloneDxSubject(document, platformDigest);
  assert(Array.isArray(document.components), "CycloneDX component inventory is missing");
}

function exactCycloneDxProperty(document, name, value) {
  const matches = document?.metadata?.properties?.filter(
    (property) => property?.name === name,
  );
  return Array.isArray(matches) && matches.length === 1 && matches[0]?.value === value;
}

function validateGatewayScratchSpdxInventory(document, root) {
  assert(
    document.packages.length === 1,
    "gateway scratch normalization refuses to conceal an SPDX package inventory",
  );
  const syftCreator = `Tool: syft-${SYFT.version}`;
  assert(
    Array.isArray(document?.creationInfo?.creators) &&
      document.creationInfo.creators.filter((creator) => creator === syftCreator).length === 1,
    "gateway scratch SPDX provenance does not identify the pinned Syft version",
  );
  assert(
    Array.isArray(document.files) && document.files.length === GATEWAY_SCRATCH_SBOM.fileNames.length,
    "gateway scratch SPDX file inventory does not match the image contract",
  );

  const expectedNames = new Set(GATEWAY_SCRATCH_SBOM.fileNames);
  const elementIds = new Set(["SPDXRef-DOCUMENT", root.SPDXID]);
  const seenNames = new Set();
  for (const file of document.files) {
    assert(
      typeof file?.SPDXID === "string" && /^SPDXRef-[A-Za-z0-9.-]+$/u.test(file.SPDXID) &&
        !elementIds.has(file.SPDXID),
      "gateway scratch SPDX file identity is invalid or duplicated",
    );
    elementIds.add(file.SPDXID);
    assert(
      typeof file.fileName === "string" && file.fileName.length > 0 && !file.fileName.includes("\0"),
      "gateway scratch SPDX file name is invalid",
    );
    const normalizedName = file.fileName.replace(/^\/+/, "");
    assert(
      expectedNames.has(normalizedName) && !seenNames.has(normalizedName),
      "gateway scratch SPDX file inventory contains an unexpected or duplicate path",
    );
    seenNames.add(normalizedName);
    assert(
      Array.isArray(file.checksums) && file.checksums.length === 1 &&
        file.checksums[0]?.algorithm === "SHA1" &&
        file.checksums[0]?.checksumValue === SYFT_UNAVAILABLE_FILE_SHA1,
      "gateway scratch SPDX file checksum contract changed from Syft's explicit unavailable placeholder",
    );
    assert(
      /^layerID: sha256:[0-9a-f]{64}$/u.test(file.comment ?? ""),
      "gateway scratch SPDX file is missing its Syft layer identity",
    );
  }
  assert(
    seenNames.size === expectedNames.size,
    "gateway scratch SPDX file inventory is incomplete",
  );

  assert(Array.isArray(document.relationships), "gateway scratch SPDX relationships are missing");
  const relationshipKeys = new Set();
  let describesCount = 0;
  for (const relationship of document.relationships) {
    const key = [
      relationship?.spdxElementId,
      relationship?.relationshipType,
      relationship?.relatedSpdxElement,
    ].join("\0");
    assert(!relationshipKeys.has(key), "gateway scratch SPDX relationships contain a duplicate edge");
    relationshipKeys.add(key);
    assert(
      elementIds.has(relationship?.spdxElementId) && elementIds.has(relationship?.relatedSpdxElement),
      "gateway scratch SPDX relationship references an unknown element",
    );
    if (relationship.relationshipType === "DESCRIBES") {
      describesCount += 1;
      assert(
        relationship.spdxElementId === "SPDXRef-DOCUMENT" &&
          relationship.relatedSpdxElement === root.SPDXID,
        "gateway scratch SPDX DESCRIBES relationship has the wrong subject",
      );
      continue;
    }
    assert(
      false,
      "gateway scratch SPDX loose files must not be claimed by a filesAnalyzed=false container root",
    );
  }
  assert(describesCount === 1, "gateway scratch SPDX must have exactly one DESCRIBES relationship");
  return {
    fileCount: document.files.length,
    fileChecksumStatus: GATEWAY_SCRATCH_SBOM.fileChecksumStatus,
    zeroSha1PlaceholderCount: document.files.length,
  };
}

function normalizeGatewayScratchCycloneDx({
  engine,
  image,
  tag,
  platformDigest,
  sourceRevision,
  spdxDocument,
  cycloneDxDocument,
}) {
  if (Object.hasOwn(cycloneDxDocument, "components")) return false;

  assert(
    engine === GATEWAY_SCRATCH_SBOM.engine && image === `${publicationOrigin(image).namespace}/ai-security-scanner-egress-gateway`,
    "CycloneDX component inventory is missing",
  );
  assert(TAG_PATTERN.test(tag), "gateway scratch component version tag is invalid");
  assert(SOURCE_REVISION_PATTERN.test(sourceRevision), "gateway scratch component source revision is invalid");
  validateSpdx(spdxDocument, platformDigest);
  validateCycloneDxSubject(cycloneDxDocument, platformDigest);

  const root = describedSpdxPackage(spdxDocument);
  assert(
    root.primaryPackagePurpose === "CONTAINER" &&
      typeof root.name === "string" && root.name.length > 0 &&
      root.name === cycloneDxDocument.metadata.component.name,
    "gateway scratch normalization requires matching SPDX and CycloneDX container identities",
  );
  assert(root.filesAnalyzed === false, "gateway scratch SPDX root must not claim file analysis");
  const spdxInventory = validateGatewayScratchSpdxInventory(spdxDocument, root);
  const ociPurl = root.externalRefs?.find(
    (reference) =>
      reference?.referenceCategory === "PACKAGE-MANAGER" &&
      reference?.referenceType === "purl" &&
      typeof reference?.referenceLocator === "string" &&
      reference.referenceLocator.startsWith("pkg:oci/"),
  )?.referenceLocator;
  let decodedOciPurl = "";
  try {
    decodedOciPurl = decodeURIComponent(ociPurl ?? "");
  } catch {
    // The assertion below deliberately fails closed for malformed package URLs.
  }
  assert(
    decodedOciPurl.includes(`@${platformDigest}`),
    "gateway scratch SPDX root is missing the exact OCI package digest",
  );
  assert(
    cycloneDxDocument.specVersion === "1.7" &&
      cycloneDxDocument.$schema === "http://cyclonedx.org/schema/bom-1.7.schema.json" &&
      Number.isInteger(cycloneDxDocument.version) && cycloneDxDocument.version >= 1,
    "gateway scratch normalization supports only the pinned CycloneDX 1.7 output",
  );
  assert(
    cycloneDxDocument.dependencies === undefined ||
      (Array.isArray(cycloneDxDocument.dependencies) && cycloneDxDocument.dependencies.length === 0),
    "gateway scratch normalization refuses to discard CycloneDX dependencies",
  );
  for (const [label, value] of [
    ["org.opencontainers.image.source", `https://github.com/${publicationOrigin(image).repository}`],
    ["org.opencontainers.image.title", GATEWAY_SCRATCH_SBOM.title],
    ["org.opencontainers.image.licenses", GATEWAY_SCRATCH_SBOM.license],
  ]) {
    assert(
      exactCycloneDxProperty(cycloneDxDocument, `syft:image:labels:${label}`, value),
      `gateway scratch CycloneDX metadata is missing the exact ${label} label`,
    );
  }

  const componentBomRef = `urn:ai-security-scanner:egress-gateway:${digestHex(platformDigest)}`;
  cycloneDxDocument.components = [{
    "bom-ref": componentBomRef,
    type: "application",
    name: GATEWAY_SCRATCH_SBOM.componentName,
    version: tag,
    description: "First-party policy-bound egress gateway application contained by this scratch image.",
    licenses: [{ license: { id: GATEWAY_SCRATCH_SBOM.license } }],
    externalReferences: [{
      type: "vcs",
      url: `https://github.com/${publicationOrigin(image).repository}/tree/${sourceRevision}`,
    }],
    properties: [
      { name: "ai-security-scanner:component:source-revision", value: sourceRevision },
      { name: "ai-security-scanner:component:platform-manifest-digest", value: platformDigest },
      { name: "ai-security-scanner:component:artifact-kind", value: "first-party-scratch-application-image" },
    ],
  }];
  cycloneDxDocument.version += 1;
  cycloneDxDocument.metadata.properties.push({
    name: GATEWAY_SCRATCH_SBOM.normalizationProperty,
    value: GATEWAY_SCRATCH_SBOM.normalizationValue,
  });
  return {
    componentBomRef,
    spdxFileCount: spdxInventory.fileCount,
    spdxFileChecksumStatus: spdxInventory.fileChecksumStatus,
    spdxZeroSha1PlaceholderCount: spdxInventory.zeroSha1PlaceholderCount,
  };
}

async function normalizeGatewayScratchCycloneDxFile({
  engine,
  image,
  tag,
  platform,
  platformDigest,
  sourceRevision,
  spdxFile,
  cycloneDxFile,
}) {
  const cycloneDxDocument = await readJson(cycloneDxFile);
  if (Object.hasOwn(cycloneDxDocument, "components")) return null;
  const sourceSpdxSha256 = await sha256File(spdxFile);
  const spdxDocument = await readJson(spdxFile);
  const normalization = normalizeGatewayScratchCycloneDx({
    engine,
    image,
    tag,
    platformDigest,
    sourceRevision,
    spdxDocument,
    cycloneDxDocument,
  });
  if (!normalization) return null;
  await writeJsonAtomic(cycloneDxFile, cycloneDxDocument);
  assert(
    await sha256File(spdxFile) === sourceSpdxSha256,
    "gateway scratch normalization changed the source SPDX document",
  );
  return {
    kind: "cyclonedx-first-party-scratch-application-v3",
    platform,
    platformDigest,
    sourceRevision,
    sourceFile: path.basename(spdxFile),
    outputFile: path.basename(cycloneDxFile),
    componentBomRef: normalization.componentBomRef,
    spdxPreserved: true,
    spdxFileCount: normalization.spdxFileCount,
    spdxFileChecksumStatus: normalization.spdxFileChecksumStatus,
    spdxZeroSha1PlaceholderCount: normalization.spdxZeroSha1PlaceholderCount,
    spdxSha256: sourceSpdxSha256,
    tool: PROJECT_SBOM_TRANSFORMER,
  };
}

async function sbomRecord(root, filename, format, predicateType, platformDigest) {
  const absolute = path.join(root, filename);
  const metadata = await stat(absolute);
  assert(metadata.isFile(), `SBOM is not a regular file: ${filename}`);
  assert(metadata.size > 0, `SBOM is empty: ${filename}`);
  assert(metadata.size <= MAX_ATTESTABLE_SBOM_BYTES, `SBOM exceeds the GitHub attestation limit: ${filename}`);
  const document = await readJson(absolute);
  if (format === "spdx-json") validateSpdx(document, platformDigest);
  else validateCycloneDx(document, platformDigest);
  return {
    format,
    predicateType,
    file: filename,
    sha256: await sha256File(absolute),
    sizeBytes: metadata.size,
  };
}

function runSyft(image, digest, outputRoot, prefix) {
  const user = typeof process.getuid === "function" ? `${process.getuid()}:${process.getgid()}` : "0:0";
  execFileSync(
    "docker",
    [
      "run",
      "--rm",
      "--pull",
      "always",
      "--user",
      user,
      "--env",
      "SYFT_CHECK_FOR_APP_UPDATE=false",
      "--env",
      "SYFT_CACHE_DIR=/tmp/syft-cache",
      "--env",
      "XDG_CACHE_HOME=/tmp/xdg-cache",
      "--tmpfs",
      "/tmp:rw,nosuid,nodev,mode=1777",
      "--volume",
      `${outputRoot}:/evidence`,
      SYFT.image,
      `registry:${image}@${digest}`,
      "-o",
      `spdx-json=/evidence/${prefix}.spdx.json`,
      "-o",
      `cyclonedx-json=/evidence/${prefix}.cyclonedx.json`,
    ],
    { stdio: "inherit" },
  );
}

async function createPreparedEvidence({ engine, image, tag, indexDigest, sourceRevision, outputRoot, platformDigests, runSyftScan }) {
  assert(ENGINE_PATTERN.test(engine), `invalid engine id: ${engine}`);
  assert(IMAGE_PATTERN.test(image) && !image.includes("@") && !image.includes(":"), `image must be an untagged fully-qualified name: ${image}`);
  assert(typeof tag === "string" && /^[A-Za-z0-9][A-Za-z0-9._-]*$/u.test(tag), `invalid image tag: ${tag}`);
  digestHex(indexDigest);
  assert(SOURCE_REVISION_PATTERN.test(sourceRevision), `invalid source revision: ${sourceRevision}`);
  if (process.env.GITHUB_SHA) {
    assert(sourceRevision === process.env.GITHUB_SHA, "source revision does not match the executing workflow commit");
  }
  publicationOrigin(image, process.env.GITHUB_REPOSITORY);
  validateRepositoryId({ repository_id: process.env.GITHUB_REPOSITORY_ID });
  await mkdir(outputRoot, { recursive: true });

  const platforms = [];
  const sbomTransformations = [];
  for (const platform of ["linux/amd64", "linux/arm64"]) {
    const digest = platformDigests.get(platform);
    digestHex(digest);
    const prefix = `${engine}-linux-${platformKey(platform)}`;
    if (runSyftScan) runSyftScan(image, digest, outputRoot, prefix);
    const spdxFile = path.join(outputRoot, `${prefix}.spdx.json`);
    const cycloneDxFile = path.join(outputRoot, `${prefix}.cyclonedx.json`);
    const transformation = await normalizeGatewayScratchCycloneDxFile({
      engine,
      image,
      tag,
      platform,
      platformDigest: digest,
      sourceRevision,
      spdxFile,
      cycloneDxFile,
    });
    if (transformation) sbomTransformations.push(transformation);
    const cycloneDxDocument = await readJson(cycloneDxFile);
    validateImageSourceLabels(cycloneDxDocument.metadata, publicationOrigin(image));
    const spdxRecord = await sbomRecord(
      outputRoot,
      `${prefix}.spdx.json`,
      "spdx-json",
      PREDICATES.spdx,
      digest,
    );
    const cycloneDxRecord = await sbomRecord(
      outputRoot,
      `${prefix}.cyclonedx.json`,
      "cyclonedx-json",
      PREDICATES.cyclonedx,
      digest,
    );
    if (transformation) {
      assert(
        transformation.spdxPreserved === true && transformation.spdxSha256 === spdxRecord.sha256,
        `gateway scratch SPDX preservation record diverged for ${platform}`,
      );
    }
    platforms.push({
      platform,
      digest,
      sboms: [spdxRecord, cycloneDxRecord],
    });
  }
  const transformationPlatforms = sbomTransformations.map((entry) => entry.platform);
  if (engine === GATEWAY_SCRATCH_SBOM.engine) {
    assert(
      isDeepStrictEqual(transformationPlatforms, ["linux/amd64", "linux/arm64"]),
      "gateway evidence must retain one exact SBOM transformation per supported platform",
    );
  } else {
    assert(
      transformationPlatforms.length === 0,
      "gateway scratch SBOM transformation escaped its engine contract",
    );
  }

  const evidence = {
    schemaVersion: 1,
    engine,
    image,
    tag,
    indexDigest,
    sourceRevision,
    public: true,
    generator: SYFT,
    sbomTransformations,
    imageBuild: {
      inlineProvenance: false,
      inlineSbom: false,
      digestMutatedByEvidence: false,
    },
    platforms,
    attestations: [],
    verification: {
      repository: publicationOrigin(image, process.env.GITHUB_REPOSITORY).repository,
      workflowRun:
        process.env.GITHUB_SERVER_URL && process.env.GITHUB_REPOSITORY && process.env.GITHUB_RUN_ID
          ? `${process.env.GITHUB_SERVER_URL}/${process.env.GITHUB_REPOSITORY}/actions/runs/${process.env.GITHUB_RUN_ID}`
          : null,
      runAttempt: process.env.GITHUB_RUN_ATTEMPT ?? null,
      registryReferrers: true,
      githubAttestationApi: true,
      onlineVerificationRequiredBeforeUpload: true,
    },
  };
  const manifest = path.join(outputRoot, `${engine}-image-supply-chain.json`);
  await writeJsonAtomic(manifest, evidence);
  return { evidence, manifest };
}

function decodeBundle(bundle) {
  assert(typeof bundle?.mediaType === "string" && bundle.mediaType.includes("sigstore.bundle"), "attestation is not a Sigstore bundle");
  assert(bundle?.dsseEnvelope?.payloadType === "application/vnd.in-toto+json", "attestation has the wrong DSSE payload type");
  assert(Array.isArray(bundle.dsseEnvelope.signatures) && bundle.dsseEnvelope.signatures.length > 0, "attestation has no DSSE signature");
  assert(bundle.verificationMaterial && typeof bundle.verificationMaterial === "object", "attestation verification material is absent");
  const encoded = bundle.dsseEnvelope.payload;
  assert(typeof encoded === "string" && encoded.length > 0, "attestation DSSE payload is absent");
  const decoded = Buffer.from(encoded, "base64");
  assert(decoded.length > 0, "attestation DSSE payload is invalid");
  return JSON.parse(decoded.toString("utf8"));
}

async function copyAndValidateBundle({ source, destination, image, digest, predicateType, predicate }) {
  const bundle = await readJson(source);
  const statement = decodeBundle(bundle);
  assert(statement?._type === "https://in-toto.io/Statement/v1", "attestation is not an in-toto v1 statement");
  assert(statement?.predicateType === predicateType, `unexpected attestation predicate: ${statement?.predicateType}`);
  const subject = statement?.subject?.find((candidate) => candidate?.name === image);
  assert(subject, `attestation does not name ${image}`);
  assert(subject.digest?.sha256 === digestHex(digest), "attestation subject digest is incorrect");
  if (predicateType === PREDICATES.provenance) {
    validateRepositoryId(statement.predicate);
    assert(provenanceOriginMatches(statement.predicate, publicationOrigin(image)), "provenance repository mismatch");
  }
  if (predicate) assert(isDeepStrictEqual(statement.predicate, predicate), "attested SBOM differs from the downloadable SBOM");
  await copyFile(source, destination);
  const metadata = await stat(destination);
  return { sha256: await sha256File(destination), sizeBytes: metadata.size };
}

async function finalizeEvidence(args) {
  const manifest = path.resolve(requireString(args, "manifest"));
  const root = path.dirname(manifest);
  const evidence = await readJson(manifest);
  assert(evidence?.schemaVersion === 1 && evidence.attestations?.length === 0, "prepared engine evidence is invalid or already finalized");

  publicationOrigin(evidence.image, evidence.verification?.repository);
  const specifications = [
    {
      key: "provenance",
      kind: "build-provenance",
      digest: evidence.indexDigest,
      predicateType: PREDICATES.provenance,
    },
  ];
  for (const platform of evidence.platforms) {
    const architecture = platformKey(platform.platform);
    for (const sbom of platform.sboms) {
      specifications.push({
        key: `${architecture}-${sbom.format === "spdx-json" ? "spdx" : "cyclonedx"}`,
        kind: "sbom",
        platform: platform.platform,
        digest: platform.digest,
        predicateType: sbom.predicateType,
        predicateFile: sbom.file,
      });
    }
  }

  const records = [];
  for (const specification of specifications) {
    const source = path.resolve(requireString(args, `${specification.key}-bundle`));
    const bundleFile = `${evidence.engine}-${specification.key}.sigstore.json`;
    const predicate = specification.predicateFile
      ? await readJson(path.join(root, specification.predicateFile))
      : null;
    const copied = await copyAndValidateBundle({
      source,
      destination: path.join(root, bundleFile),
      image: evidence.image,
      digest: specification.digest,
      predicateType: specification.predicateType,
      predicate,
    });
    const attestationId = requireString(args, `${specification.key}-id`);
    const attestationUrl = requireString(args, `${specification.key}-url`);
    assert(/^https:\/\/github\.com\//u.test(attestationUrl), `invalid GitHub attestation URL: ${attestationUrl}`);
    if (evidence.verification.repository) {
      assert(
        attestationUrl.startsWith(`https://github.com/${evidence.verification.repository}/attestations/`),
        `attestation URL belongs to another repository: ${attestationUrl}`,
      );
    }
    records.push({
      kind: specification.kind,
      platform: specification.platform ?? null,
      predicateType: specification.predicateType,
      subject: { name: evidence.image, digest: specification.digest },
      bundleFile,
      bundleSha256: copied.sha256,
      bundleSizeBytes: copied.sizeBytes,
      attestationId,
      attestationUrl,
      registryPushed: true,
      githubAttestationsApi: true,
    });
  }

  evidence.attestations = records;
  evidence.checksumsFile = "SHA256SUMS.txt";
  await writeJsonAtomic(manifest, evidence);
  const checksummed = [
    path.basename(manifest),
    ...evidence.platforms.flatMap((platform) => platform.sboms.map((sbom) => sbom.file)),
    ...records.map((record) => record.bundleFile),
  ].sort();
  const checksumLines = [];
  for (const file of checksummed) checksumLines.push(`${await sha256File(path.join(root, file))}  ${file}`);
  await writeTextAtomic(path.join(root, evidence.checksumsFile), `${checksumLines.join("\n")}\n`);
  process.stdout.write(`Finalized signed image evidence for ${evidence.engine}.\n`);
}

async function prepare(args) {
  const engine = requireString(args, "engine");
  const image = requireString(args, "image");
  const tag = requireString(args, "tag");
  const indexDigest = requireString(args, "digest");
  const sourceRevision = requireString(args, "source-revision");
  const outputRoot = path.resolve(requireString(args, "out"));
  const rawIndex = execFileSync("docker", ["buildx", "imagetools", "inspect", "--raw", `${image}@${indexDigest}`]);
  const platformDigests = parseIndex(rawIndex, indexDigest);
  const { manifest } = await createPreparedEvidence({
    engine,
    image,
    tag,
    indexDigest,
    sourceRevision,
    outputRoot,
    platformDigests,
    runSyftScan: runSyft,
  });
  const githubOutput = process.env.GITHUB_OUTPUT;
  if (githubOutput) {
    await writeFile(
      githubOutput,
      [
        outputLine("manifest", manifest),
        outputLine("amd64_digest", platformDigests.get("linux/amd64")),
        outputLine("arm64_digest", platformDigests.get("linux/arm64")),
        outputLine("amd64_spdx", path.join(outputRoot, `${engine}-linux-amd64.spdx.json`)),
        outputLine("amd64_cyclonedx", path.join(outputRoot, `${engine}-linux-amd64.cyclonedx.json`)),
        outputLine("arm64_spdx", path.join(outputRoot, `${engine}-linux-arm64.spdx.json`)),
        outputLine("arm64_cyclonedx", path.join(outputRoot, `${engine}-linux-arm64.cyclonedx.json`)),
      ].join(""),
      { flag: "a" },
    );
  }
  process.stdout.write(`Generated exact per-platform SBOMs for ${image}@${indexDigest}.\n`);
}

function fakeSboms(image, digest) {
  const id = `SPDXRef-DocumentRoot-Image-${digestHex(digest).slice(0, 12)}`;
  return {
    spdx: {
      spdxVersion: "SPDX-2.3",
      dataLicense: "CC0-1.0",
      SPDXID: "SPDXRef-DOCUMENT",
      name: image,
      documentNamespace: `https://example.invalid/${digestHex(digest)}`,
      creationInfo: { created: new Date(0).toISOString(), creators: ["Tool: fixture"] },
      packages: [{
        SPDXID: id,
        name: image,
        versionInfo: digest,
        checksums: [{ algorithm: "SHA256", checksumValue: digestHex(digest) }],
      }],
      relationships: [{ spdxElementId: "SPDXRef-DOCUMENT", relatedSpdxElement: id, relationshipType: "DESCRIBES" }],
    },
    cyclonedx: {
      bomFormat: "CycloneDX",
      specVersion: "1.6",
      serialNumber: "urn:uuid:00000000-0000-0000-0000-000000000000",
      version: 1,
      metadata: { component: { type: "container", name: image, version: digest } },
      components: [],
    },
  };
}

function fakeGatewayScratchSboms(digest) {
  const fixtures = fakeSboms(GATEWAY_SCRATCH_SBOM.image, digest);
  const root = fixtures.spdx.packages[0];
  root.filesAnalyzed = false;
  root.primaryPackagePurpose = "CONTAINER";
  root.externalRefs = [{
    referenceCategory: "PACKAGE-MANAGER",
    referenceType: "purl",
    referenceLocator: `pkg:oci/${GATEWAY_SCRATCH_SBOM.componentName}@${encodeURIComponent(digest)}`,
  }];
  fixtures.spdx.creationInfo.creators = ["Organization: Anchore, Inc", `Tool: syft-${SYFT.version}`];
  fixtures.spdx.files = GATEWAY_SCRATCH_SBOM.fileNames.map((fileName, index) => ({
    fileName,
    SPDXID: `SPDXRef-File-egress-gateway-${index + 1}`,
    checksums: [{ algorithm: "SHA1", checksumValue: SYFT_UNAVAILABLE_FILE_SHA1 }],
    licenseConcluded: "NOASSERTION",
    licenseInfoInFiles: ["NOASSERTION"],
    copyrightText: "NOASSERTION",
    comment: `layerID: ${digest}`,
  }));
  fixtures.cyclonedx.$schema = "http://cyclonedx.org/schema/bom-1.7.schema.json";
  fixtures.cyclonedx.specVersion = "1.7";
  fixtures.cyclonedx.metadata.properties = [
    { name: "syft:image:labels:org.opencontainers.image.licenses", value: GATEWAY_SCRATCH_SBOM.license },
    { name: "syft:image:labels:org.opencontainers.image.source", value: GATEWAY_SCRATCH_SBOM.source },
    { name: "syft:image:labels:org.opencontainers.image.title", value: GATEWAY_SCRATCH_SBOM.title },
  ];
  delete fixtures.cyclonedx.components;
  return fixtures;
}

async function fakeBundle(file, image, digest, predicateType, predicate) {
  const statement = {
    _type: "https://in-toto.io/Statement/v1",
    subject: [{ name: image, digest: { sha256: digestHex(digest) } }],
    predicateType,
    predicate,
  };
  await writeJsonAtomic(file, {
    mediaType: "application/vnd.dev.sigstore.bundle.v0.3+json",
    verificationMaterial: { tlogEntries: [{}] },
    dsseEnvelope: {
      payloadType: "application/vnd.in-toto+json",
      payload: Buffer.from(JSON.stringify(statement)).toString("base64"),
      signatures: [{ sig: Buffer.from("fixture-signature").toString("base64") }],
    },
  });
}

async function selfTest() {
  const root = await mkdtemp(path.join(os.tmpdir(), "ai-security-scanner-engine-evidence-"));
  try {
    const engine = "fixture-engine";
    const image = `${CURRENT_PUBLICATION_ORIGIN.namespace}/fixture-engine`;
    const repository = process.env.GITHUB_REPOSITORY ?? CURRENT_PUBLICATION_ORIGIN.repository;
    const indexDigest = `sha256:${"11".repeat(32)}`;
    const platformDigests = new Map([
      ["linux/amd64", `sha256:${"22".repeat(32)}`],
      ["linux/arm64", `sha256:${"33".repeat(32)}`],
    ]);
    const rawIndex = Buffer.from(JSON.stringify({
      schemaVersion: 2,
      mediaType: "application/vnd.oci.image.index.v1+json",
      manifests: [...platformDigests].map(([platform, digest]) => {
        const [operatingSystem, architecture] = platform.split("/");
        return {
          mediaType: "application/vnd.oci.image.manifest.v1+json",
          digest,
          size: 123,
          platform: { os: operatingSystem, architecture },
        };
      }),
    }));
    const parsedIndexDigest = `sha256:${sha256(rawIndex)}`;
    assert(isDeepStrictEqual(parseIndex(rawIndex, parsedIndexDigest), platformDigests), "self-test rejected an exact two-platform index");
    const scriptedFetch = (...responses) => async () => {
      assert(responses.length > 0, "self-test registry client made an unexpected request");
      return responses.shift();
    };
    const registryInputs = { image, tag: "0.3.0-1", username: "fixture", token: "fixture-token" };
    const present = await inspectGhcrTag({
      ...registryInputs,
      fetchImpl: scriptedFetch(
        new Response(JSON.stringify({ token: "fixture-bearer" }), { status: 200 }),
        new Response(rawIndex, {
          status: 200,
          headers: { "docker-content-digest": parsedIndexDigest },
        }),
      ),
    });
    assert(present.state === "present" && present.digest === parsedIndexDigest, "self-test registry lookup lost the exact index digest");
    const absent = await inspectGhcrTag({
      ...registryInputs,
      fetchImpl: scriptedFetch(
        new Response(JSON.stringify({ token: "fixture-bearer" }), { status: 200 }),
        new Response(JSON.stringify({ errors: [{ code: "MANIFEST_UNKNOWN" }] }), { status: 404 }),
      ),
    });
    assert(absent.state === "absent", "self-test did not recognize an explicit missing manifest");
    let rejected = false;
    try {
      await inspectGhcrTag({
        ...registryInputs,
        fetchImpl: scriptedFetch(new Response(JSON.stringify({ message: "forbidden" }), { status: 403 })),
      });
    } catch {
      rejected = true;
    }
    assert(rejected, "self-test treated an authorization failure as an absent tag");
    const extraIndex = JSON.parse(rawIndex.toString("utf8"));
    extraIndex.manifests.push({
      mediaType: "application/vnd.oci.image.manifest.v1+json",
      digest: `sha256:${"44".repeat(32)}`,
      size: 123,
      platform: { os: "linux", architecture: "ppc64le" },
    });
    const extraRaw = Buffer.from(JSON.stringify(extraIndex));
    rejected = false;
    try {
      parseIndex(extraRaw, `sha256:${sha256(extraRaw)}`);
    } catch {
      rejected = true;
    }
    assert(rejected, "self-test accepted an index with an undeclared third platform");

    const sourceRevision = process.env.GITHUB_SHA ?? "ab".repeat(20);
    const workflowRef = `${repository}/.github/workflows/engine-images-cloud.yml@refs/heads/main`;
    const provenanceRecords = [{
      verificationResult: {
        statement: {
          _type: "https://in-toto.io/Statement/v1",
          subject: [{ name: image, digest: { sha256: digestHex(parsedIndexDigest) } }],
          predicateType: PREDICATES.provenance,
          predicate: {
            buildDefinition: {
              resolvedDependencies: [{
                uri: `git+https://github.com/${repository}@refs/heads/main`,
                digest: { gitCommit: sourceRevision },
              }],
            },
          },
        },
        signature: {
          certificate: {
            sourceRepositoryURI: `https://github.com/${repository}`,
            sourceRepositoryDigest: sourceRevision,
            githubWorkflowRepository: repository,
            githubWorkflowSHA: sourceRevision,
            buildSignerURI: `https://github.com/${workflowRef}`,
            buildSignerDigest: sourceRevision,
            runnerEnvironment: "github-hosted",
          },
        },
      },
    }];
    assert(
      matchingVerifiedProvenance(provenanceRecords, {
        image,
        digest: parsedIndexDigest,
        sourceRevision,
        repository,
        workflowRef,
      }),
      "self-test rejected matching verified publication provenance",
    );
    assert(
      !matchingVerifiedProvenance(provenanceRecords, {
        image,
        digest: parsedIndexDigest,
        sourceRevision: "cd".repeat(20),
        repository,
        workflowRef,
      }),
      "self-test allowed a later source commit to reuse the version tag",
    );
    assert(
      isDeepStrictEqual(
        affectedCloudEngines(["engines/images/prowler/patches/0006-enabled-subscription.patch", "docs/architecture.md"], "push"),
        ["prowler"],
      ),
      "self-test did not narrow a Prowler-only cloud publication",
    );
    assert(
      isDeepStrictEqual(
        affectedCloudEngines(["engines/images/cloud-launcher/main.go"], "push"),
        CLOUD_ENGINE_IDS,
      ),
      "self-test did not expand a shared-launcher change to the full cloud matrix",
    );
    assert(
      isDeepStrictEqual(affectedCloudEngines([], "workflow_dispatch"), CLOUD_ENGINE_IDS),
      "self-test weakened full manual cloud publication",
    );

    const gatewayRoot = path.join(root, "gateway-scratch");
    await mkdir(gatewayRoot, { recursive: true });
    const gatewaySpdxBefore = new Map();
    for (const [platform, digest] of platformDigests) {
      const prefix = `${GATEWAY_SCRATCH_SBOM.engine}-linux-${platformKey(platform)}`;
      const fixtures = fakeGatewayScratchSboms(digest);
      const spdxFile = path.join(gatewayRoot, `${prefix}.spdx.json`);
      await writeJsonAtomic(spdxFile, fixtures.spdx);
      await writeJsonAtomic(path.join(gatewayRoot, `${prefix}.cyclonedx.json`), fixtures.cyclonedx);
      gatewaySpdxBefore.set(platform, {
        bytesSha256: await sha256File(spdxFile),
        files: structuredClone(fixtures.spdx.files),
      });
    }
    const gatewayPrepared = await createPreparedEvidence({
      engine: GATEWAY_SCRATCH_SBOM.engine,
      image: GATEWAY_SCRATCH_SBOM.image,
      tag: "0.3.0-1",
      indexDigest,
      sourceRevision,
      outputRoot: gatewayRoot,
      platformDigests,
      runSyftScan: null,
    });
    assert(
      gatewayPrepared.evidence.sbomTransformations.length === 2,
      "self-test did not record both project-owned gateway SBOM transformations",
    );
    for (const [platform, digest] of platformDigests) {
      const prefix = `${GATEWAY_SCRATCH_SBOM.engine}-linux-${platformKey(platform)}`;
      const transformation = gatewayPrepared.evidence.sbomTransformations.find(
        (candidate) => candidate.platform === platform,
      );
      const preservedSpdxFile = path.join(gatewayRoot, `${prefix}.spdx.json`);
      const preservedSpdx = await readJson(preservedSpdxFile);
      const normalized = await readJson(path.join(gatewayRoot, `${prefix}.cyclonedx.json`));
      const component = normalized.components?.[0];
      assert(
        transformation?.kind === "cyclonedx-first-party-scratch-application-v3" &&
          transformation?.platformDigest === digest &&
          transformation?.sourceRevision === sourceRevision &&
          transformation?.sourceFile === `${prefix}.spdx.json` &&
          transformation?.outputFile === `${prefix}.cyclonedx.json` &&
          transformation?.tool?.name === PROJECT_SBOM_TRANSFORMER.name &&
          transformation?.tool?.version === PROJECT_SBOM_TRANSFORMER.version &&
          transformation?.spdxPreserved === true &&
          transformation?.spdxFileCount === GATEWAY_SCRATCH_SBOM.fileNames.length &&
          transformation?.spdxFileChecksumStatus === GATEWAY_SCRATCH_SBOM.fileChecksumStatus &&
          transformation?.spdxZeroSha1PlaceholderCount === GATEWAY_SCRATCH_SBOM.fileNames.length &&
          transformation?.spdxSha256 === gatewaySpdxBefore.get(platform)?.bytesSha256 &&
          await sha256File(preservedSpdxFile) === gatewaySpdxBefore.get(platform)?.bytesSha256 &&
          isDeepStrictEqual(preservedSpdx.files, gatewaySpdxBefore.get(platform)?.files) &&
          normalized.version === 2 && normalized.components?.length === 1 &&
          exactCycloneDxProperty(
            normalized,
            GATEWAY_SCRATCH_SBOM.normalizationProperty,
            GATEWAY_SCRATCH_SBOM.normalizationValue,
          ) &&
          component?.type === "application" &&
          component?.name === GATEWAY_SCRATCH_SBOM.componentName &&
          component?.hashes === undefined &&
          component?.properties?.some((property) =>
            property?.name === "ai-security-scanner:component:source-revision" &&
            property?.value === sourceRevision) &&
          component?.properties?.some((property) =>
            property?.name === "ai-security-scanner:component:platform-manifest-digest" &&
            property?.value === digest),
        `self-test gateway normalization lost the first-party application identity for ${platform}`,
      );
    }

    const gatewayDigest = platformDigests.get("linux/amd64");
    const assertGatewayNormalizationRejected = (fixtures, overrides, message) => {
      let normalizationRejected = false;
      try {
        normalizeGatewayScratchCycloneDx({
          engine: GATEWAY_SCRATCH_SBOM.engine,
          image: GATEWAY_SCRATCH_SBOM.image,
          tag: "0.3.0-1",
          platformDigest: gatewayDigest,
          sourceRevision,
          spdxDocument: fixtures.spdx,
          cycloneDxDocument: fixtures.cyclonedx,
          ...overrides,
        });
      } catch {
        normalizationRejected = true;
      }
      assert(normalizationRejected, message);
    };

    assertGatewayNormalizationRejected(
      fakeGatewayScratchSboms(gatewayDigest),
      { engine: "fixture-engine" },
      "self-test allowed another engine to use the gateway scratch normalization",
    );
    assertGatewayNormalizationRejected(
      fakeGatewayScratchSboms(gatewayDigest),
      { image: "ghcr.io/teddashh/not-the-egress-gateway" },
      "self-test allowed another repository to use the gateway scratch normalization",
    );

    const hiddenPackageFixtures = fakeGatewayScratchSboms(gatewayDigest);
    hiddenPackageFixtures.spdx.packages.unshift({
      SPDXID: "SPDXRef-Package-hidden",
      name: "must-not-be-discarded",
      versionInfo: "1.0.0",
    });
    assertGatewayNormalizationRejected(
      hiddenPackageFixtures,
      {},
      "self-test allowed gateway normalization to hide an SPDX package",
    );

    const wrongLabelFixtures = fakeGatewayScratchSboms(gatewayDigest);
    wrongLabelFixtures.cyclonedx.metadata.properties.find(
      (property) => property.name.endsWith("org.opencontainers.image.source"),
    ).value = "https://github.com/example/not-this-project";
    assertGatewayNormalizationRejected(
      wrongLabelFixtures,
      {},
      "self-test allowed gateway normalization with a mismatched source label",
    );

    const wrongProvenanceFixtures = fakeGatewayScratchSboms(gatewayDigest);
    wrongProvenanceFixtures.spdx.creationInfo.creators = ["Tool: syft-1.50.0"];
    assertGatewayNormalizationRejected(
      wrongProvenanceFixtures,
      {},
      "self-test allowed gateway normalization with mismatched scanner provenance",
    );

    const danglingRelationshipFixtures = fakeGatewayScratchSboms(gatewayDigest);
    danglingRelationshipFixtures.spdx.relationships.push({
      spdxElementId: danglingRelationshipFixtures.spdx.packages[0].SPDXID,
      relationshipType: "CONTAINS",
      relatedSpdxElement: "SPDXRef-File-not-in-the-inventory",
    });
    assertGatewayNormalizationRejected(
      danglingRelationshipFixtures,
      {},
      "self-test allowed a dangling SPDX relationship",
    );

    const falseContainmentFixtures = fakeGatewayScratchSboms(gatewayDigest);
    falseContainmentFixtures.spdx.relationships.push({
      spdxElementId: falseContainmentFixtures.spdx.packages[0].SPDXID,
      relationshipType: "CONTAINS",
      relatedSpdxElement: falseContainmentFixtures.spdx.files[0].SPDXID,
    });
    assertGatewayNormalizationRejected(
      falseContainmentFixtures,
      {},
      "self-test allowed a filesAnalyzed=false gateway root to claim a loose file",
    );

    const missingFileChecksumPlaceholderFixtures = fakeGatewayScratchSboms(gatewayDigest);
    missingFileChecksumPlaceholderFixtures.spdx.files[0].checksums = [];
    assertGatewayNormalizationRejected(
      missingFileChecksumPlaceholderFixtures,
      {},
      "self-test allowed a gateway SPDX file without the pinned Syft checksum placeholder",
    );

    const fabricatedFileHashFixtures = fakeGatewayScratchSboms(gatewayDigest);
    fabricatedFileHashFixtures.spdx.files[0].checksums[0].checksumValue = "1".repeat(40);
    assertGatewayNormalizationRejected(
      fabricatedFileHashFixtures,
      {},
      "self-test treated a nonzero loose-file checksum as evidence without independently verifying it",
    );

    const addedFileHashFixtures = fakeGatewayScratchSboms(gatewayDigest);
    addedFileHashFixtures.spdx.files[0].checksums.push({
      algorithm: "SHA256",
      checksumValue: "1".repeat(64),
    });
    assertGatewayNormalizationRejected(
      addedFileHashFixtures,
      {},
      "self-test accepted an unverified checksum added to the pinned Syft placeholder contract",
    );

    assertGatewayNormalizationRejected(
      fakeGatewayScratchSboms(gatewayDigest),
      { platformDigest: platformDigests.get("linux/arm64") },
      "self-test allowed gateway normalization with a mismatched SPDX platform digest",
    );

    for (const [platform, digest] of platformDigests) {
      const prefix = `${engine}-linux-${platformKey(platform)}`;
      const fixtures = fakeSboms(image, digest);
      await writeJsonAtomic(path.join(root, `${prefix}.spdx.json`), fixtures.spdx);
      await writeJsonAtomic(path.join(root, `${prefix}.cyclonedx.json`), fixtures.cyclonedx);
    }
    const { manifest } = await createPreparedEvidence({
      engine,
      image,
      tag: "0.3.0-1",
      indexDigest,
      sourceRevision,
      outputRoot: root,
      platformDigests,
      runSyftScan: null,
    });

    const specifications = [
      ["provenance", indexDigest, PREDICATES.provenance, {}],
      ["amd64-spdx", platformDigests.get("linux/amd64"), PREDICATES.spdx, await readJson(path.join(root, `${engine}-linux-amd64.spdx.json`))],
      ["amd64-cyclonedx", platformDigests.get("linux/amd64"), PREDICATES.cyclonedx, await readJson(path.join(root, `${engine}-linux-amd64.cyclonedx.json`))],
      ["arm64-spdx", platformDigests.get("linux/arm64"), PREDICATES.spdx, await readJson(path.join(root, `${engine}-linux-arm64.spdx.json`))],
      ["arm64-cyclonedx", platformDigests.get("linux/arm64"), PREDICATES.cyclonedx, await readJson(path.join(root, `${engine}-linux-arm64.cyclonedx.json`))],
    ];
    const finalArgs = new Map([["manifest", manifest]]);
    for (const [key, digest, predicateType, predicate] of specifications) {
      const bundle = path.join(root, `${key}.input.json`);
      await fakeBundle(bundle, image, digest, predicateType, predicate);
      finalArgs.set(`${key}-bundle`, bundle);
      finalArgs.set(`${key}-id`, `fixture-${key}`);
      finalArgs.set(`${key}-url`, `https://github.com/${repository}/attestations/fixture-${key}`);
    }
    await finalizeEvidence(finalArgs);
    const finalized = await readJson(manifest);
    assert(finalized.attestations.length === 5, "self-test did not preserve all five attestations");
    assert((await readFile(path.join(root, "SHA256SUMS.txt"), "utf8")).split("\n").filter(Boolean).length === 10, "self-test checksum inventory is incomplete");

    const wrongDigestBundle = path.join(root, "wrong-digest.json");
    await fakeBundle(wrongDigestBundle, image, `sha256:${"44".repeat(32)}`, PREDICATES.spdx, {});
    rejected = false;
    try {
      await copyAndValidateBundle({
        source: wrongDigestBundle,
        destination: path.join(root, "must-not-copy.json"),
        image,
        digest: platformDigests.get("linux/amd64"),
        predicateType: PREDICATES.spdx,
        predicate: {},
      });
    } catch {
      rejected = true;
    }
    assert(rejected, "self-test accepted an attestation for the wrong image digest");

    const malformed = fakeSboms(image, platformDigests.get("linux/amd64")).spdx;
    malformed.packages[0].checksums[0].checksumValue = "00".repeat(32);
    rejected = false;
    try {
      validateSpdx(malformed, platformDigests.get("linux/amd64"));
    } catch {
      rejected = true;
    }
    assert(rejected, "self-test accepted an SPDX document for the wrong image digest");

    const workflowCoverage = new Map([
      [".github/workflows/engine-images-cloud.yml", ["cloudquery", "prowler", "cloudsplaining", "scoutsuite", "steampipe"]],
      [".github/workflows/engine-images-external.yml", ["naabu", "httpx", "nuclei"]],
      [".github/workflows/engine-images-m365.yml", ["scubagear", "maester"]],
      [".github/workflows/engine-images-local-k8s.yml", ["semgrep", "trufflehog", "trivy", "grype", "kubescape", "kube-bench"]],
      [".github/workflows/engine-image-gitleaks.yml", ["gitleaks"]],
      [".github/workflows/engine-image-greenbone.yml", ["greenbone"]],
      [".github/workflows/engine-image-checkov.yml", ["checkov"]],
      [".github/workflows/engine-image-syft.yml", ["syft"]],
    ]);
    let coveredEngines = 0;
    for (const [relative, engines] of workflowCoverage) {
      const workflow = await readFile(path.join(PROJECT_ROOT, relative), "utf8");
      const staticEnvironmentEngines = staticEnvironmentEvidenceEngines(workflow, relative);
      assert(workflow.includes("uses: ./.github/actions/engine-image-evidence"), `${relative} does not invoke signed image evidence`);
      const guardIndex = workflow.indexOf("uses: ./.github/actions/engine-image-evidence/publication-guard");
      const evidenceIndex = workflow.lastIndexOf("uses: ./.github/actions/engine-image-evidence\n");
      const promoteIndex = workflow.indexOf("uses: ./.github/actions/engine-image-evidence/promote");
      assert(guardIndex >= 0 && guardIndex < evidenceIndex, `${relative} does not guard its version before publication evidence`);
      assert(promoteIndex > evidenceIndex, `${relative} does not defer version promotion until after signed evidence`);
      assert(workflow.includes("outputs.candidate_tag"), `${relative} does not publish through a run-unique candidate tag`);
      const modeBindings = workflow.match(
        /^\s+mode: \$\{\{ (?:steps|needs)\.guard\.outputs\.mode \}\}$/gmu,
      ) ?? [];
      assert(modeBindings.length >= 2, `${relative} does not bind guard mode to evidence and promotion`);
      assert(workflow.includes("id-token: write") && workflow.includes("attestations: write"), `${relative} cannot create GitHub attestations`);
      assert(workflow.includes("provenance: false") && workflow.includes("sbom: false"), `${relative} may mutate the published index digest`);
      for (const engineId of engines) {
        assert(
          workflow.includes(`engine: ${engineId}`) || workflow.includes(`"engine":"${engineId}"`) ||
            staticEnvironmentEngines.has(engineId),
          `${relative} does not cover ${engineId}`,
        );
        coveredEngines += 1;
      }
    }
    assert(coveredEngines === 20, "self-test engine workflow coverage changed unexpectedly");
    const evidenceAction = await readFile(
      path.join(PROJECT_ROOT, ".github/actions/engine-image-evidence/action.yml"),
      "utf8",
    );
    const evidenceStepCount = evidenceAction.match(/^    - name:/gmu)?.length ?? 0;
    const buildOnlyStepCount = evidenceAction.match(/^      if: inputs\.mode == 'build'$/gmu)?.length ?? 0;
    assert(
      evidenceStepCount > 0 && buildOnlyStepCount === evidenceStepCount,
      "reuse mode can reach a signed-evidence publication step",
    );
    const promotionAction = await readFile(
      path.join(PROJECT_ROOT, ".github/actions/engine-image-evidence/promote/action.yml"),
      "utf8",
    );
    assert(
      promotionAction.includes("uses: docker/login-action@") &&
        promotionAction.includes("if: inputs.mode == 'build'") &&
        promotionAction.includes('--mode "${{ inputs.mode }}"') &&
        promotionAction.includes("password: ${{ inputs.github-token }}") &&
        promotionAction.includes("if: always()") &&
        promotionAction.includes("run: docker logout ghcr.io"),
      "promotion action is not self-contained across anonymous-smoke credential state",
    );
    process.stdout.write("Engine image evidence self-test passed (catalog-derived engine set, immutable tag provenance, non-mutating reuse, artifact-scoped attestations and SBOMs, preserved gateway SPDX inventory with explicit unavailable-checksum status, and negative scope/provenance/relationship/digest checks).\n");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

async function main() {
  const [command, ...rest] = process.argv.slice(2);
  if (command === "select-cloud-engines") return selectCloudEngines(parseArgs(rest));
  if (command === "publication-preflight") return publicationPreflight(parseArgs(rest));
  if (command === "promote-publication") return promotePublication(parseArgs(rest));
  if (command === "prepare") return prepare(parseArgs(rest));
  if (command === "finalize") return finalizeEvidence(parseArgs(rest));
  if (command === "self-test") return selfTest();
  throw new Error("expected command: select-cloud-engines, publication-preflight, promote-publication, prepare, finalize, or self-test");
}

const isMain = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
if (isMain) runMain(main);
