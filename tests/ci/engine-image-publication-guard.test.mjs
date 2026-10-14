import assert from "node:assert/strict";
import test from "node:test";

import { promotePublication, publicationPreflight, recordedEngineInputIdentity } from "../../scripts/engine-image-evidence.mjs";
import { isPendingImageReplacement } from "../../scripts/engine-image-replacement.mjs";

const IMAGE = "ghcr.io/ted-h-com/ai-security-scanner-engine-scubagear";
const TAG = "1.8.0-6";
const REPOSITORY = "TED-H-com/ai-security-scanner";
const WORKFLOW_REF = `${REPOSITORY}/.github/workflows/engine-images-m365.yml@refs/heads/main`;
const CURRENT_REVISION = "cc".repeat(20);
const PUBLISHED_REVISION = "aa".repeat(20);
const INDEX_DIGEST = `sha256:${"11".repeat(32)}`;

function args() {
  return new Map([
    ["image", IMAGE],
    ["tag", TAG],
    ["source-revision", CURRENT_REVISION],
    ["repository", REPOSITORY],
    ["workflow-ref", WORKFLOW_REF],
    ["username", "fixture-user"],
  ]);
}

function recordedPlan() {
  return {
    schema_version: "1.0.0",
    engine_id: "scubagear",
    final_artifact: {
      repository: IMAGE,
      tag: TAG,
      digest: INDEX_DIGEST,
    },
    build_recipe: {
      source_archive: { sha256: `sha256:${"22".repeat(32)}` },
      base_images: [{
        repository: "mcr.microsoft.com/powershell",
        tag: "7.5.2-ubuntu-24.04",
        digest: `sha256:${"33".repeat(32)}`,
      }],
    },
    dockerfile: {
      path: "engines/images/scubagear/Dockerfile",
      sha256: `sha256:${"44".repeat(32)}`,
    },
    wrapper: { launcher_sha256: `sha256:${"55".repeat(32)}` },
    publication: {
      source_revision: PUBLISHED_REVISION,
      managed_smoke_evidence_sha256: `sha256:${"66".repeat(32)}`,
    },
  };
}

function provenanceOutput() {
  return JSON.stringify([{
    verificationResult: {
      statement: {
        subject: [{ name: IMAGE, digest: { sha256: INDEX_DIGEST.slice("sha256:".length) } }],
        predicateType: "https://slsa.dev/provenance/v1",
        predicate: {
          buildDefinition: {
            resolvedDependencies: [{
              uri: `git+https://github.com/${REPOSITORY}@refs/heads/main`,
              digest: { gitCommit: PUBLISHED_REVISION },
            }],
          },
        },
      },
      signature: {
        certificate: {
          sourceRepositoryURI: `https://github.com/${REPOSITORY}`,
          sourceRepositoryDigest: PUBLISHED_REVISION,
          githubWorkflowRepository: REPOSITORY,
          githubWorkflowSHA: PUBLISHED_REVISION,
          buildSignerURI: `https://github.com/${WORKFLOW_REF}`,
          buildSignerDigest: PUBLISHED_REVISION,
          runnerEnvironment: "github-hosted",
        },
      },
    },
  }]);
}

function replacementFixture() {
  const plan = recordedPlan();
  const previousArtifact = { ...plan.final_artifact };
  const previousPublication = {
    workflow_run: "https://github.com/TED-H-com/ai-security-scanner/actions/runs/12345",
    source_revision: PUBLISHED_REVISION,
    platforms: ["linux/amd64", "linux/arm64"],
    platform_digests: { "linux/amd64": INDEX_DIGEST, "linux/arm64": INDEX_DIGEST },
    anonymous_pull_verified: true,
    evidence_artifact: "scubagear-image-evidence-12345-1",
    managed_smoke_evidence_sha256: `sha256:${"66".repeat(32)}`,
  };
  plan.publish_state = "publication_in_progress";
  plan.previous_artifact = previousArtifact;
  plan.previous_publication = previousPublication;
  plan.final_artifact = { repository: IMAGE, tag: "1.8.0-7", digest: null };
  plan.publication = null;
  return {
    plan,
    engine: { image: previousArtifact },
    contract: { tag: "1.8.0-7", previousArtifact, previousPublicationSource: PUBLISHED_REVISION },
  };
}

test("a pending replacement keeps the old exact image separate from the unbuilt candidate", () => {
  const { plan, engine, contract } = replacementFixture();
  assert.equal(isPendingImageReplacement(plan, engine, contract), true);
  const legacy = structuredClone(plan);
  legacy.previous_artifact.repository = legacy.previous_artifact.repository.replace("ted-h-com", "teddashh");
  legacy.previous_publication.workflow_run = legacy.previous_publication.workflow_run.replace("TED-H-com", "teddashh");
  const legacyContract = { ...contract, previousArtifact: legacy.previous_artifact };
  assert.equal(isPendingImageReplacement(legacy, { ...engine, image: legacy.previous_artifact }, legacyContract), true);
  for (const mutate of [
    (p, e) => { e.image = { ...e.image, tag: contract.tag }; },
    (p) => { p.final_artifact.digest = INDEX_DIGEST; },
    (p) => { p.previous_publication.source_revision = CURRENT_REVISION; },
    (p) => { p.publication = p.previous_publication; },
    (p) => { p.previous_artifact.digest = `sha256:${"99".repeat(32)}`; },
  ]) {
    const candidate = structuredClone({ plan, engine });
    mutate(candidate.plan, candidate.engine);
    assert.equal(isPendingImageReplacement(candidate.plan, candidate.engine, contract), false);
  }
});

test("replacement history cannot hide executable inputs or alter the new build identity", () => {
  const { plan } = replacementFixture();
  const binding = { engine: "scubagear", image: IMAGE, tag: "1.8.0-7" };
  const withoutHistory = structuredClone(plan);
  delete withoutHistory.previous_artifact;
  delete withoutHistory.previous_publication;
  const identity = recordedEngineInputIdentity(plan, binding);
  assert.deepEqual(identity, recordedEngineInputIdentity(withoutHistory, binding));
  const legacyPlan = structuredClone(withoutHistory);
  legacyPlan.final_artifact.repository = legacyPlan.final_artifact.repository.replace("ted-h-com", "teddashh");
  assert.deepEqual(identity, recordedEngineInputIdentity(legacyPlan, binding));
  const changed = structuredClone(plan);
  changed.wrapper.launcher_sha256 = `sha256:${"99".repeat(32)}`;
  assert.notDeepEqual(identity, recordedEngineInputIdentity(changed, binding));
  plan.previous_publication.launcher_sha256 = `sha256:${"99".repeat(32)}`;
  assert.throws(() => recordedEngineInputIdentity(plan, binding), /only immutable artifact coordinates/u);
});

async function withPublicationEnvironment(callback) {
  const previous = new Map([
    ["GHCR_TOKEN", process.env.GHCR_TOKEN],
    ["GITHUB_SHA", process.env.GITHUB_SHA],
    ["GITHUB_RUN_ID", process.env.GITHUB_RUN_ID],
    ["GITHUB_RUN_ATTEMPT", process.env.GITHUB_RUN_ATTEMPT],
  ]);
  process.env.GHCR_TOKEN = "fixture-token";
  process.env.GITHUB_SHA = CURRENT_REVISION;
  process.env.GITHUB_RUN_ID = "12345";
  process.env.GITHUB_RUN_ATTEMPT = "2";
  try {
    return await callback();
  } finally {
    for (const [key, value] of previous) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  }
}

test("publication guard reuses an existing tag when recorded engine inputs are unchanged", async () => {
  await withPublicationEnvironment(async () => {
    const currentPlan = recordedPlan();
    const publishedPlan = structuredClone(currentPlan);
    publishedPlan.publication.source_revision = PUBLISHED_REVISION;
    const outputs = [];
    const messages = [];
    let provenanceChecks = 0;

    await publicationPreflight(args(), {
      inspectGhcrTag: async () => ({ state: "present", digest: INDEX_DIGEST }),
      exec: () => {
        provenanceChecks += 1;
        return provenanceOutput();
      },
      readCurrentPlan: async () => currentPlan,
      readPublishedPlan: async () => publishedPlan,
      appendGithubOutputs: async (entries) => outputs.push(...entries),
      writeStdout: (message) => messages.push(message),
    });

    assert.equal(provenanceChecks, 1, "reuse must verify the existing digest provenance");
    assert.deepEqual(Object.fromEntries(outputs), {
      mode: "reuse",
      should_build: "false",
      digest: INDEX_DIGEST,
      candidate_tag: `candidate-${CURRENT_REVISION}-12345-2`,
    });
    assert.match(messages.join(""), /recorded build inputs are unchanged/u);

    const promotionArgs = args();
    promotionArgs.set("mode", "reuse");
    promotionArgs.set("digest", INDEX_DIGEST);
    const promotionOutputs = [];
    let inputChecks = 0;
    await promotePublication(promotionArgs, {
      inspectGhcrTag: async () => ({ state: "present", digest: INDEX_DIGEST }),
      verifyPublishedProvenance: () => PUBLISHED_REVISION,
      verifyRecordedInputsUnchanged: async () => {
        inputChecks += 1;
      },
      appendGithubOutputs: async (entries) => promotionOutputs.push(...entries),
      execFileSync: () => assert.fail("reuse must not invoke a registry mutation command"),
      writeStdout: (message) => messages.push(message),
    });
    assert.equal(inputChecks, 1, "final reuse verification must recheck recorded inputs");
    assert.deepEqual(Object.fromEntries(promotionOutputs), {
      digest: INDEX_DIGEST,
      promoted: "false",
    });
    assert.match(messages.join(""), /no registry mutation performed/u);
  });
});

test("publication guard rejects an existing tag when a recorded Dockerfile digest changed", async () => {
  await withPublicationEnvironment(async () => {
    const currentPlan = recordedPlan();
    const publishedPlan = structuredClone(currentPlan);
    publishedPlan.dockerfile.sha256 = `sha256:${"77".repeat(32)}`;
    const outputs = [];
    let provenanceChecks = 0;

    await assert.rejects(
      publicationPreflight(args(), {
        inspectGhcrTag: async () => ({ state: "present", digest: INDEX_DIGEST }),
        exec: () => {
          provenanceChecks += 1;
          return provenanceOutput();
        },
        readCurrentPlan: async () => currentPlan,
        readPublishedPlan: async () => publishedPlan,
        appendGithubOutputs: async (entries) => outputs.push(...entries),
        writeStdout: () => {},
      }),
      /version tag is already bound to different recorded build inputs/u,
    );

    assert.equal(provenanceChecks, 1, "the existing digest must be verified before input comparison");
    assert.deepEqual(outputs, [], "changed inputs must not produce reuse or build authorization outputs");
  });
});

test("publication guard fails closed when the published input record is unavailable", async () => {
  await withPublicationEnvironment(async () => {
    const outputs = [];

    await assert.rejects(
      publicationPreflight(args(), {
        inspectGhcrTag: async () => ({ state: "present", digest: INDEX_DIGEST }),
        exec: () => provenanceOutput(),
        readCurrentPlan: async () => recordedPlan(),
        readPublishedPlan: async () => {
          throw new Error("fixture history unavailable");
        },
        appendGithubOutputs: async (entries) => outputs.push(...entries),
        writeStdout: () => {},
      }),
      /published engine input plan is unavailable: fixture history unavailable/u,
    );

    assert.deepEqual(outputs, [], "unavailable input history must not produce reuse or build authorization outputs");
  });
});

test("publication guard authorizes a build when the version tag is absent", async () => {
  await withPublicationEnvironment(async () => {
    const outputs = [];
    const messages = [];
    const unexpected = () => {
      assert.fail("an absent tag must not require provenance or historical input records");
    };

    await publicationPreflight(args(), {
      inspectGhcrTag: async () => ({ state: "absent" }),
      exec: unexpected,
      readCurrentPlan: unexpected,
      readPublishedPlan: unexpected,
      appendGithubOutputs: async (entries) => outputs.push(...entries),
      writeStdout: (message) => messages.push(message),
    });

    assert.deepEqual(Object.fromEntries(outputs), {
      mode: "build",
      should_build: "true",
      digest: "",
      candidate_tag: `candidate-${CURRENT_REVISION}-12345-2`,
    });
    assert.match(messages.join(""), /is absent; a unique candidate may be built/u);
  });
});
