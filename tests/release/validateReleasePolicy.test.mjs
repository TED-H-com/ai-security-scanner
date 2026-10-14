import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { parse } from "yaml";

import {
  validateFinalizedPublicationMappingSources,
  validateGithubReleasePublisherSource,
  validateProductEngineRegistry,
  validateReleaseAssetNamingSource,
  validateReleaseWorkflow,
  validateWindowsQualificationLifecycle,
} from "../../scripts/release/validate-release.mjs";

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");

const secureCandidateWorkflow = parse(
  readFileSync(path.join(projectRoot, ".github/workflows/release.yml"), "utf8"),
);
const securePromotionWorkflow = parse(
  readFileSync(path.join(projectRoot, ".github/workflows/promote-release.yml"), "utf8"),
);
const secureWindowsQualification = readFileSync(
  path.join(projectRoot, "scripts/release/qualify-windows.ps1"),
  "utf8",
);
const secureGithubReleasePublisher = readFileSync(
  path.join(projectRoot, "scripts/release/publish-github-release.mjs"),
  "utf8",
);
const secureReleaseAssetNaming = readFileSync(
  path.join(projectRoot, "scripts/release/release-asset-name.mjs"),
  "utf8",
);
const secureReleaseFinalizer = readFileSync(
  path.join(projectRoot, "scripts/release/finalize-release.mjs"),
  "utf8",
);
const secureFinalizedReleaseVerifier = readFileSync(
  path.join(projectRoot, "scripts/release/verify-finalized-release.mjs"),
  "utf8",
);

function secureWorkflowPair() {
  return {
    candidate: structuredClone(secureCandidateWorkflow),
    promotion: structuredClone(securePromotionWorkflow),
  };
}

function validatePair({ candidate, promotion }) {
  return validateReleaseWorkflow(candidate, promotion);
}

test("ordinary Windows qualification resolves one protected isolated generation after start", () => {
  assert.doesNotThrow(() => validateWindowsQualificationLifecycle(secureWindowsQualification));
});

test("ordinary Windows qualification validates every exact generation-selection field", () => {
  for (const field of [
    "schema_version",
    "authorizes_cleanup",
    "manifest_sha256",
    "machine_image_sha256",
    "default_machine_name",
    "selected_machine_name",
    "generation_index",
    "preserved_collision_names",
  ]) {
    const mutated = secureWindowsQualification.replaceAll(`"${field}"`, `"broken_${field}"`);
    assert.throws(
      () => validateWindowsQualificationLifecycle(mutated),
      new RegExp(`exact generation-selection field twice: ${field}`, "u"),
    );
  }
});

test("ordinary Windows qualification rejects stale or weak generation routing", () => {
  for (const mutation of [
    [
      "$document = [Text.Json.JsonDocument]::Parse($text)",
      "$document = $text | ConvertFrom-Json",
    ],
    [
      "$cleanupAuthority.ValueKind -ne [Text.Json.JsonValueKind]::False",
      "$cleanupAuthority.ValueKind -ne [Text.Json.JsonValueKind]::True",
    ],
    [
      '$providerNamespace = "$($runtimeManifestSha256.Substring(0, 8))-iso-$($isolatedSuffix.Substring(0, 12))"',
      '$providerNamespace = $runtimeManifestSha256.Substring(0, 16)',
    ],
    [
      '"podman-$([string]$_.SelectedMachineName)"',
      '"podman-$defaultMachineName"',
    ],
    [
      "  $activeGenerationSelection = $orderedGenerationSelections[-1]\n",
      "  $activeGenerationSelection = $orderedGenerationSelections[0]\n",
    ],
  ]) {
    const mutated = secureWindowsQualification.replace(...mutation);
    assert.notEqual(mutated, secureWindowsQualification, `mutation source token missing: ${mutation[0]}`);
    assert.throws(
      () => validateWindowsQualificationLifecycle(mutated),
      /isolated generation|isolated-generation invariant|generation zero|unregister authority/u,
    );
  }
});

test("ordinary Windows qualification cannot precreate or override the canonical data root", () => {
  for (const injected of [
    secureWindowsQualification.replace(
      "  function Invoke-Managed(",
      "  New-Item -ItemType Directory -Path $dataDirectory -Force | Out-Null\n  function Invoke-Managed(",
    ),
    secureWindowsQualification.replace(
      "& $cli --json runtime managed @Arguments",
      "& $cli --json --data-dir $dataDirectory runtime managed @Arguments",
    ),
  ]) {
    assert.throws(
      () => validateWindowsQualificationLifecycle(injected),
      /CLI default data root|isolated-generation invariant/u,
    );
  }
});

test("ordinary Windows qualification refuses ambient path overrides and noncanonical journals", () => {
  for (const mutation of [
    ["\"AI_SECURITY_SCANNER_DATA_DIR\"", '"IGNORED_DATA_DIR"'],
    ["\"AI_SECURITY_SCANNER_MANAGED_RUNTIME_BUNDLE\"", '"IGNORED_RUNTIME_BUNDLE"'],
    [
      "$generationEntry.Name -cne $canonicalGenerationName",
      "$generationEntry.Name -ceq $canonicalGenerationName",
    ],
    [
      "$remainingWslSet.Contains([string]$expectedDistribution)",
      "$remainingWslSet.Contains([string]$managedWslDistributions[-1])",
    ],
    [
      "(-not $managedRuntimePurgeSucceeded -or -not $exactWslAbsent -or -not $providerRootEmpty)",
      "(-not $exactWslAbsent)",
    ],
    [
      "$providerRootEmpty = @(Get-ChildItem -LiteralPath $providerRoot -Force).Count -eq 0",
      "$providerRootEmpty = $true",
    ],
  ]) {
    const mutated = secureWindowsQualification.replace(...mutation);
    assert.notEqual(mutated, secureWindowsQualification, `mutation source token missing: ${mutation[0]}`);
    assert.throws(
      () => validateWindowsQualificationLifecycle(mutated),
      /isolated-generation invariant/u,
    );
  }
});

test("generation routing cannot authorize a name-only WSL unregister fallback", () => {
  const mutated = secureWindowsQualification.replace(
    "  if ($installed -and $null -ne $installerPath) {",
    '  Invoke-BoundedCleanupProcess $wsl @("--unregister", $managedWslDistributions[-1]) 90000 "unsafe"\n' +
      "  if ($installed -and $null -ne $installerPath) {",
  );
  assert.throws(
    () => validateWindowsQualificationLifecycle(mutated),
    /unregister authority/u,
  );
});

test("release policy accepts manual candidate freeze and protected exact-byte promotion", () => {
  const pair = secureWorkflowPair();
  assert.doesNotThrow(() => validatePair(pair));
  assert.deepEqual(Object.keys(pair.candidate.on), ["workflow_dispatch"]);
  assert.equal(pair.candidate.jobs.publish, undefined);
  assert.equal(pair.promotion.jobs.publish.environment, "release-publication");
});

test("candidate dispatch accepts only false-by-default public intent and fixture switches", () => {
  const pair = secureWorkflowPair();
  pair.candidate.on.workflow_dispatch.inputs.unsafe_publish_anyway = {
    description: "unsafe",
    required: false,
    type: "boolean",
    default: false,
  };
  assert.throws(
    () => validatePair(pair),
    /may accept only false-by-default public-candidate and Windows-fixture switches/u,
  );
});

test("public candidate intent must seal, verify, and freeze one exact assembled input", () => {
  const pair = secureWorkflowPair();
  const steps = pair.candidate.jobs["finalize-supported-artifacts"].steps;
  steps.splice(steps.findIndex((step) => step.run?.includes("release-candidate-lock.mjs verify")), 1);
  assert.throws(
    () => validatePair(pair),
    /consecutively lock, verify, freeze, then preview-finalize/u,
  );
});

test("candidate artifact name is attempt-scoped and non-overwriting", () => {
  const pair = secureWorkflowPair();
  const upload = pair.candidate.jobs["finalize-supported-artifacts"].steps.find(
    (step) => step.id === "upload_candidate",
  );
  upload.with.name = "release-candidate-input";
  assert.throws(
    () => validatePair(pair),
    /consecutively lock, verify, freeze, then preview-finalize/u,
  );
});

test("candidate workflow has no publication or attestation authority", () => {
  const pair = secureWorkflowPair();
  pair.candidate.jobs["finalize-supported-artifacts"].steps.push({
    uses: "softprops/action-gh-release@" + "a".repeat(40),
  });
  assert.throws(
    () => validatePair(pair),
    /must not publish a GitHub Release/u,
  );
});

test("candidate jobs cannot receive write authority", () => {
  const pair = secureWorkflowPair();
  pair.candidate.jobs["finalize-supported-artifacts"].permissions.packages = "write";
  assert.throws(
    () => validatePair(pair),
    /finalize-supported-artifacts job must not receive write permissions/u,
  );
});

test("release workflow rejects coupled installer sibling failures", () => {
  const pair = secureWorkflowPair();
  pair.candidate.jobs.build.steps.find(({ id }) => id === "bundle_msi")["continue-on-error"] = false;
  assert.throws(
    () => validatePair(pair),
    /bundle_msi must independently bundle its installer and continue after sibling failure/u,
  );
});

test("installer-only bundle formats cannot depend on updater private keys", () => {
  const pair = secureWorkflowPair();
  pair.candidate.jobs.build.steps.find(({ id }) => id === "bundle_msi").env = {
    TAURI_SIGNING_PRIVATE_KEY: "$" + "{{ secrets.TAURI_SIGNING_PRIVATE_KEY }}",
  };
  assert.throws(
    () => validatePair(pair),
    /bundle_msi must not depend on updater signing material/u,
  );
});

test("candidate assembly rejects an unprotected cross-run observation namespace", () => {
  const pair = secureWorkflowPair();
  pair.candidate.jobs["finalize-supported-artifacts"].steps.unshift({
    uses: "actions/download-artifact@" + "d".repeat(40),
    "continue-on-error": true,
    with: {
      pattern: "artifact-promotion-evidence-*",
      path: "assembled-input",
      "merge-multiple": true,
    },
  });
  assert.throws(
    () => validatePair(pair),
    /must not ingest an unprotected observation or promotion namespace/u,
  );
});

test("promotion inputs are limited to exact candidate and complete evidence selectors", () => {
  const pair = secureWorkflowPair();
  delete pair.promotion.on.workflow_dispatch.inputs.evidence_artifact_digest;
  assert.throws(
    () => validatePair(pair),
    /only exact candidate and all-or-none protected-evidence selectors/u,
  );
});

test("promotion workflow cannot make the publication token ambient", () => {
  const pair = secureWorkflowPair();
  pair.promotion.env = { GH_TOKEN: "${{ github.token }}" };
  assert.throws(
    () => validatePair(pair),
    /exact top-level topology without ambient environment or defaults/u,
  );
});

test("promotion is restricted to the workflow definition on main", () => {
  const pair = secureWorkflowPair();
  const selectors = pair.promotion.jobs.assemble.steps.find((step) => step.id === "selectors");
  selectors.run = selectors.run.replace(
    "promotion workflow ref is not the protected main-branch workflow",
    "unchecked workflow ref",
  );
  assert.throws(
    () => validatePair(pair),
    /fail closed on canonical candidate and all-or-none evidence identities/u,
  );
});

test("candidate artifact selection uses exact run, attempt, ID, and canonical digest", () => {
  const pair = secureWorkflowPair();
  const candidateProducer = pair.promotion.jobs.assemble.steps.find(
    (step) => step.run?.includes("candidate workflow run ID mismatch"),
  );
  candidateProducer.env.CANDIDATE_ARTIFACT_DIGEST =
    "$" + "{{ inputs.candidate_artifact_digest }}";
  assert.throws(
    () => validatePair(pair),
    /must use the selector's canonical artifact digest/u,
  );
});

test("promotion accepts upload-artifact SHA-256 prefixes only through canonical normalization", () => {
  const pair = secureWorkflowPair();
  const selectors = pair.promotion.jobs.assemble.steps.find((step) => step.id === "selectors");
  selectors.run = selectors.run.replace("(?:sha256:)?", "");
  assert.throws(
    () => validatePair(pair),
    /fail closed on canonical candidate and all-or-none evidence identities/u,
  );
});

test("candidate producer verification resolves the exact workflow attempt", () => {
  const pair = secureWorkflowPair();
  const candidateProducer = pair.promotion.jobs.assemble.steps.find(
    (step) => step.run?.includes("candidate workflow run ID mismatch"),
  );
  candidateProducer.run = candidateProducer.run.replace(
    "/attempts/" + "$" + "{CANDIDATE_RUN_ATTEMPT}",
    "",
  );
  assert.throws(
    () => validatePair(pair),
    /candidate producer verification is missing/u,
  );
});

test("promotion downloads candidate bytes only by exact artifact ID", () => {
  const pair = secureWorkflowPair();
  const download = pair.promotion.jobs.assemble.steps.find(
    (step) => step.with?.path === "candidate-input",
  );
  delete download.with["artifact-ids"];
  download.with.name = "release-candidate-input-*";
  assert.throws(
    () => validatePair(pair),
    /download the exact verified candidate artifact ID/u,
  );
});

test("promotion reverifies the candidate lock in public mode", () => {
  const pair = secureWorkflowPair();
  const lock = pair.promotion.jobs.assemble.steps.find((step) => step.id === "candidate_lock");
  lock.run = lock.run.replace("public-github-release", "commit-bound-qc");
  assert.throws(
    () => validatePair(pair),
    /reverify the candidate lock against every protected producer identity/u,
  );
});

test("accepted evidence is exact-ID selected after protected producer verification", () => {
  const pair = secureWorkflowPair();
  const download = pair.promotion.jobs.assemble.steps.find(
    (step) => step.with?.path === "accepted-evidence",
  );
  download.with["artifact-ids"] = "$" + "{{ inputs.candidate_artifact_id }}";
  assert.throws(
    () => validatePair(pair),
    /only the exact accepted-evidence artifact ID/u,
  );
});

test("accepted evidence is verified then materialized through the trusted CLI", () => {
  const pair = secureWorkflowPair();
  const steps = pair.promotion.jobs.assemble.steps;
  const receiptIndex = steps.findIndex((step) =>
    step.run?.includes("windows-external-evidence.mjs verify-receipt"),
  );
  [steps[receiptIndex], steps[receiptIndex + 1]] = [steps[receiptIndex + 1], steps[receiptIndex]];
  assert.throws(
    () => validatePair(pair),
    /receipt-verified then materialized without an intervening step/u,
  );
});

test("promotion forbids inline base64 evidence and release rebuilds", () => {
  for (const forbidden of ["base64 evidence.txt", "npm run tauri build"]) {
    const pair = secureWorkflowPair();
    pair.promotion.jobs.assemble.steps.unshift({ run: forbidden });
    assert.throws(
      () => validatePair(pair),
      /must not rebuild or inline external evidence/u,
    );
  }
});

test("finalization passes protected evidence provenance only through an optional argument array", () => {
  const pair = secureWorkflowPair();
  const finalize = pair.promotion.jobs.assemble.steps.find(
    (step) => step.run?.includes("scripts/release/finalize-release.mjs"),
  );
  finalize.run = finalize.run.replace("--external-evidence-job import", "");
  assert.throws(
    () => validatePair(pair),
    /public finalizer must pass the exact protected evidence identity/u,
  );
});

test("publisher crosses the release environment with only scoped write authority", () => {
  const pair = secureWorkflowPair();
  pair.promotion.jobs.publish.permissions.packages = "write";
  assert.throws(
    () => validatePair(pair),
    /must receive only release, attestation, and finalized-artifact permissions/u,
  );
  const secondPair = secureWorkflowPair();
  secondPair.promotion.jobs.publish.environment = "unprotected";
  assert.throws(
    () => validatePair(secondPair),
    /exact fail-closed protected job topology/u,
  );
});

test("publisher job cannot gain a job-level condition or ambient environment", () => {
  for (const [key, value] of [
    ["if", "always()"],
    ["env", { GH_TOKEN: "${{ github.token }}" }],
  ]) {
    const pair = secureWorkflowPair();
    pair.promotion.jobs.publish[key] = value;
    assert.throws(() => validatePair(pair), /exact fail-closed protected job topology/u);
  }
});

test("assembler derives prerelease and latest flags only from the locked release channel", () => {
  const pair = secureWorkflowPair();
  const outputs = pair.promotion.jobs.assemble.outputs;
  [outputs.prerelease, outputs.make_latest] = [outputs.make_latest, outputs.prerelease];
  assert.throws(
    () => validatePair(pair),
    /export lock-derived identity/u,
  );
});

test("assembler finalization and verification require exact candidate-lock identity inputs", () => {
  for (const command of ["finalize-release.mjs", "verify-finalized-release.mjs"]) {
    const pair = secureWorkflowPair();
    const step = pair.promotion.jobs.assemble.steps.find((candidate) =>
      candidate.run?.includes(command));
    step.env.RELEASE_TAG = "${{ inputs.expected_commit }}";
    assert.throws(
      () => validatePair(pair),
      /exactly bind the locked candidate, evidence, and public mode/u,
    );
  }
});

test("publisher downloads only the same-run finalized artifact ID", () => {
  const pair = secureWorkflowPair();
  const download = pair.promotion.jobs.publish.steps.find(
    (step) => step.uses?.includes("actions/download-artifact@"),
  );
  download.with.name = "release-finalized";
  assert.throws(
    () => validatePair(pair),
    /exact credential-free checkout, pinned tools, install, and artifact-ID download/u,
  );
});

test("publisher revalidates optional evidence provenance before attestation", () => {
  const pair = secureWorkflowPair();
  const verify = pair.promotion.jobs.publish.steps.find(
    (step) => step.run?.includes("verify-finalized-release.mjs"),
  );
  delete verify.env.EXPECTED_EVIDENCE_WORKFLOW_REF;
  assert.throws(
    () => validatePair(pair),
    /exact, terminally bounded re-verification command/u,
  );
});

test("publisher re-verification cannot mutate an asset later in the same shell step", () => {
  const pair = secureWorkflowPair();
  const verify = pair.promotion.jobs.publish.steps.find(
    (step) => step.run?.includes("verify-finalized-release.mjs"),
  );
  verify.run += "printf changed >> release-assets/RELEASE_NOTES.md\n";
  assert.throws(
    () => validatePair(pair),
    /exact, terminally bounded re-verification command/u,
  );
});

test("publisher rejects artifact mutation after final verification", () => {
  const pair = secureWorkflowPair();
  const steps = pair.promotion.jobs.publish.steps;
  const attestIndex = steps.findIndex((step) => step.uses?.includes("attest-build-provenance@"));
  steps.splice(attestIndex, 0, { run: "cp unverified release-assets/unverified" });
  assert.throws(
    () => validatePair(pair),
    /eight allowlisted steps/u,
  );
});

test("publisher cannot regress to a third-party release action", () => {
  const pair = secureWorkflowPair();
  pair.promotion.jobs.publish.steps.push({
    uses: "softprops/action-gh-release@" + "a".repeat(40),
  });
  assert.throws(
    () => validatePair(pair),
    /eight allowlisted steps/u,
  );
});

test("final publisher step cannot hide a third-party release action", () => {
  const pair = secureWorkflowPair();
  const publication = pair.promotion.jobs.publish.steps.at(-1);
  publication.uses = "softprops/action-gh-release@" + "a".repeat(40);
  assert.throws(
    () => validatePair(pair),
    /no third-party GitHub Release action/u,
  );
});

test("attestation and ID-addressed publication order cannot be swapped", () => {
  const pair = secureWorkflowPair();
  const steps = pair.promotion.jobs.publish.steps;
  [steps[6], steps[7]] = [steps[7], steps[6]];
  assert.throws(
    () => validatePair(pair),
    /consecutively download, reverify, attest, then finish/u,
  );
});

test("publisher must use exact frozen output bindings", () => {
  const pair = secureWorkflowPair();
  const publication = pair.promotion.jobs.publish.steps.find(
    (step) => step.run?.includes("publish-github-release.mjs"),
  );
  publication.env.SOURCE_COMMIT = "${{ github.sha }}";
  assert.throws(
    () => validatePair(pair),
    /exact ID-addressed checked-in publisher and frozen output bindings/u,
  );
});

test("publisher transaction cannot be conditional or followed by another step", () => {
  for (const mutation of [
    (publication) => { publication.if = "always()"; },
    (_publication, steps) => { steps.push({ run: "true" }); },
  ]) {
    const pair = secureWorkflowPair();
    const steps = pair.promotion.jobs.publish.steps;
    const publication = steps.find((step) => step.run?.includes("publish-github-release.mjs"));
    mutation(publication, steps);
    assert.throws(
      () => validatePair(pair),
      /cannot be conditionally skipped|eight allowlisted steps/u,
    );
  }
});

test("checked-in publisher preserves the private-draft publication transaction", () => {
  assert.doesNotThrow(() => validateGithubReleasePublisherSource(secureGithubReleasePublisher));
  for (const [token, replacement] of [
    ['method: "PATCH"', 'method: "POST"'],
    [
      "() => verifyDraftState(client, repository, expected, currentInventory)",
      "await verifyExactTag(client, repository, expected.tag, expected.commit);",
    ],
    ["record.digest === `sha256:${expected.sha256}`", "record.size === expected.bytes"],
    ["const suppliedRootMetadata = await lstat(directory);", "const suppliedRootMetadata = await lstat(root);"],
  ]) {
    const mutated = secureGithubReleasePublisher.replace(token, replacement);
    assert.notEqual(mutated, secureGithubReleasePublisher, `mutation source token missing: ${token}`);
    assert.throws(
      () => validateGithubReleasePublisherSource(mutated),
      /checked-in GitHub Release publisher is missing|must reverify the private draft twice|exactly one public transition/u,
    );
  }
});

test("checked-in publisher has no delete, adoption, or overwrite escape hatch", () => {
  for (const injected of [
    `${secureGithubReleasePublisher}\n// method: "DELETE"`,
    `${secureGithubReleasePublisher}\n// method: 'DELETE'`,
    `${secureGithubReleasePublisher}\n// softprops/action-gh-release`,
    `${secureGithubReleasePublisher}\n// overwrite_files`,
    `${secureGithubReleasePublisher}\n// adoptRelease`,
  ]) {
    assert.throws(
      () => validateGithubReleasePublisherSource(injected),
      /forbidden mutation authority/u,
    );
  }
});

test("checked-in publisher CLI cannot swap frozen identity, channel, or token mappings", () => {
  for (const [token, replacement] of [
    ['version: requireString(args, "version")', 'version: requireString(args, "tag")'],
    ['commit: requireString(args, "commit")', 'commit: requireString(args, "version")'],
    [
      'prerelease: exactBoolean(requireString(args, "prerelease"), "--prerelease")',
      'prerelease: exactBoolean(requireString(args, "make-latest"), "--make-latest")',
    ],
    ["token: process.env.GH_TOKEN", "token: process.env.OTHER_TOKEN"],
  ]) {
    const mutated = secureGithubReleasePublisher.replace(token, replacement);
    assert.notEqual(mutated, secureGithubReleasePublisher, `mutation source token missing: ${token}`);
    assert.throws(
      () => validateGithubReleasePublisherSource(mutated),
      /checked-in GitHub Release publisher is missing/u,
    );
  }
});

test("finalizer and verifier require legacy updater URLs independently of the source repository", () => {
  for (const repository of ["TED-H-com/ai-security-scanner", "unknown/ai-security-scanner"]) {
    assert.throws(() => validateFinalizedPublicationMappingSources(
      secureReleaseFinalizer.replace("${UPDATER_DOWNLOAD_REPOSITORY}", repository),
      secureFinalizedReleaseVerifier,
    ), /release finalizer publication mapping is missing/u);
    assert.throws(() => validateFinalizedPublicationMappingSources(
      secureReleaseFinalizer,
      secureFinalizedReleaseVerifier.replace("${UPDATER_DOWNLOAD_REPOSITORY}", repository),
    ), /finalized release verifier publication mapping is missing/u);
  }
  assert.throws(() => validateFinalizedPublicationMappingSources(
    secureReleaseFinalizer,
    secureFinalizedReleaseVerifier.replace("latestRecord.url === expectedUrl", "latestRecord.url.startsWith(expectedUrl)"),
  ), /finalized release verifier publication mapping is missing/u);
  assert.throws(() => validateFinalizedPublicationMappingSources(
    secureReleaseFinalizer,
    secureFinalizedReleaseVerifier.replace("releaseMetadata.sourceRepository ===", "releaseMetadata.sourceRepository !=="),
  ), /finalized release verifier publication mapping is missing/u);
});

test("finalizer, verifier, and publisher share one explicit nested publication-name mapping", () => {
  assert.doesNotThrow(() => validateReleaseAssetNamingSource(secureReleaseAssetNaming));
  assert.doesNotThrow(() =>
    validateFinalizedPublicationMappingSources(
      secureReleaseFinalizer,
      secureFinalizedReleaseVerifier,
    ));
  assert.throws(
    () => validateReleaseAssetNamingSource(
      secureReleaseAssetNaming.replace('"path-v1-"', '"path-v2-"'),
    ),
    /release asset naming contract is missing/u,
  );
  assert.throws(
    () => validateFinalizedPublicationMappingSources(
      secureReleaseFinalizer.replaceAll("schemaVersion: 3", "schemaVersion: 2"),
      secureFinalizedReleaseVerifier,
    ),
    /release finalizer publication mapping is missing/u,
  );
  assert.throws(
    () => validateFinalizedPublicationMappingSources(
      secureReleaseFinalizer,
      secureFinalizedReleaseVerifier.replace(
        '["path", "publishedName", "bytes", "sha256"]',
        '["path", "bytes", "sha256"]',
      ),
    ),
    /finalized release verifier publication mapping is missing/u,
  );
});

test("only the final checked-in publisher may receive the GitHub token", () => {
  const pair = secureWorkflowPair();
  pair.promotion.jobs.publish.steps[3].env = { GH_TOKEN: "${{ github.token }}" };
  assert.throws(
    () => validatePair(pair),
    /exact credential-free checkout, pinned tools, install, and artifact-ID download/u,
  );
});
test("optional unavailable engines do not become a global product release gate", () => {
  const result = validateProductEngineRegistry([
    { id: "ready-engine", status: "integrated", compatibility: { runnable: true } },
    {
      id: "optional-engine",
      status: "planned",
      compatibility: { runnable: false, blocked_by: ["artifact_not_published"] },
    },
  ]);
  assert.deepEqual(result, {
    engineCount: 2,
    unavailableEngineIds: ["optional-engine"],
    rejectedEntries: [],
  });
});

test("malformed optional engine records are isolated instead of becoming a product gate", () => {
  assert.deepEqual(
    validateProductEngineRegistry([
      { id: "ready", status: "integrated", compatibility: { runnable: true } },
      { id: "ready", status: "integrated", compatibility: { runnable: true } },
      { id: "sibling", status: "integrated", compatibility: { runnable: true } },
      { status: "planned" },
      { id: " sibling ", status: "integrated", compatibility: { runnable: true } },
    ]),
    {
      engineCount: 1,
      unavailableEngineIds: [],
      rejectedEntries: [
        { index: 0, id: "ready", code: "duplicate_engine_id" },
        { index: 1, id: "ready", code: "duplicate_engine_id" },
        { index: 3, id: null, code: "missing_engine_id" },
        { index: 4, id: " sibling ", code: "non_canonical_engine_id" },
      ],
    },
  );
  assert.deepEqual(validateProductEngineRegistry(null), {
    engineCount: 0,
    unavailableEngineIds: [],
    rejectedEntries: [{ index: null, id: null, code: "catalog_not_array" }],
  });
});

test("the generic release policy entry point succeeds without platform qualification or release builds", () => {
  const result = spawnSync(process.execPath, ["scripts/release/validate-release.mjs"], {
    cwd: projectRoot,
    encoding: "utf8",
  });
  assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
  assert.match(result.stdout, /Common release identity and publication policy are consistent/u);
});

test("product release validation does not depend on subordinate marketing prose", async () => {
  const source = await readFile(
    path.join(projectRoot, "scripts/release/validate-release.mjs"),
    "utf8",
  );
  for (const staleCoupling of [
    "repositoryReadme",
    "releaseGuide",
    "releaseLineNotes",
    "README release line is out of sync",
    "release guide does not document the strict pre-release hosted-macOS observation contract",
    "release-line notes omit the honest hosted-macOS pre-release qualification contract",
    "macos-15-intel",
    "github_hosted_macos_nested_virtualization_unsupported",
    "Installed macOS desktop exited before the 12-second observation window.",
    "PUBLIC_RELEASE_BLOCKED_AUTHENTICODE",
    "engine catalog must contain 21 records",
    "release requires every required engine",
    "scripts/validate-engine-catalog.mjs",
    "scripts/engine-image-evidence.mjs",
    "validatePlatformQualificationSources",
    "validateManagedRuntimeBuildContract",
    "validateManagedRuntimeExecutionContract",
    "assertOrderedTokens",
    "assertSourceStringArray",
    "sourceFunction",
    "managed_runtime_recovery:wsl_distribution_requires_manual_action",
  ]) {
    assert.equal(source.includes(staleCoupling), false, `stale global coupling remains: ${staleCoupling}`);
  }
  const mainSource = source.slice(source.indexOf("async function main()"));
  for (const platformCoupling of [
    "validateManagedRuntimeBuildContract(",
    "validateManagedRuntimeExecutionContract(",
    "validatePlatformQualificationSources(",
    "validate-windows-nsis-template.mjs",
    "qualify-windows-nsis-upgrade.ps1",
    "qualify-windows-nsis-ghost-recovery.ps1",
    "validateProductEngineRegistry(catalog)",
  ]) {
    assert.equal(
      mainSource.includes(platformCoupling),
      false,
      `generic release policy still invokes a platform/engine contract: ${platformCoupling}`,
    );
  }
});

test("Windows NSIS source validation is isolated to the Windows installer matrix", async () => {
  const workflow = parse(await readFile(path.join(projectRoot, ".github/workflows/release.yml"), "utf8"));
  const validationCommand = "node scripts/release/validate-windows-nsis-template.mjs";
  const commonSteps = workflow.jobs.validate.steps;
  const buildSteps = workflow.jobs.build.steps;

  assert.equal(commonSteps.some((step) => step?.run === validationCommand), false);
  const platformSteps = buildSteps.filter((step) => step?.run === validationCommand);
  assert.equal(platformSteps.length, 1);
  assert.equal(platformSteps[0].if, "matrix.platform == 'windows-x86_64'");
  assert.equal(workflow.jobs.build["continue-on-error"], true);
});
