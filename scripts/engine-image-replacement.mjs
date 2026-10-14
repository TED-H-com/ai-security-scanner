import { publicationOrigin, publicationRunId } from "./publication-origins.mjs";
import { isDeepStrictEqual } from "node:util";

// Historical coordinates are evidence of the retained release, never inputs to
// the replacement build. Keep this metadata closed so an executable input
// cannot be hidden in a subtree omitted from the build identity.
export function validateReplacementHistory(plan) {
  const artifact = plan.previous_artifact;
  const publication = plan.previous_publication;
  if (artifact === undefined && publication === undefined) return;
  const exactKeys = (value, keys) => value && typeof value === "object" &&
    !Array.isArray(value) && isDeepStrictEqual(Object.keys(value).sort(), keys.sort());
  const digest = /^sha256:[0-9a-f]{64}$/u;
  if (!exactKeys(artifact, ["repository", "tag", "digest"]) ||
      !digest.test(artifact.digest) || typeof artifact.repository !== "string" || typeof artifact.tag !== "string" ||
      !exactKeys(publication, ["workflow_run", "source_revision", "platforms", "platform_digests",
        "anonymous_pull_verified", "evidence_artifact", "managed_smoke_evidence_sha256"]) ||
      !publicationRunId(artifact.repository, publication.workflow_run) ||
      !/^[0-9a-f]{40}$/u.test(publication.source_revision) ||
      !isDeepStrictEqual(publication.platforms, ["linux/amd64", "linux/arm64"]) ||
      !exactKeys(publication.platform_digests, ["linux/amd64", "linux/arm64"]) ||
      !Object.values(publication.platform_digests).every((value) => digest.test(value)) ||
      publication.anonymous_pull_verified !== true ||
      !/^[a-z0-9-]+-image-evidence-[1-9][0-9]*-[1-9][0-9]*$/u.test(publication.evidence_artifact) ||
      !digest.test(publication.managed_smoke_evidence_sha256)) {
    throw new Error("replacement history must contain only immutable artifact coordinates and publication evidence");
  }
}

export function isPendingImageReplacement(plan, engine, contract) {
  if (!contract?.previousArtifact) return false;
  validateReplacementHistory(plan);
  try { publicationOrigin(plan.final_artifact?.repository); } catch { return false; }
  return plan.publish_state === "publication_in_progress" && plan.publication === null &&
    isDeepStrictEqual(plan.previous_artifact, contract.previousArtifact) &&
    plan.previous_publication?.source_revision === contract.previousPublicationSource &&
    isDeepStrictEqual(engine.image && {
      repository: engine.image.repository, tag: engine.image.tag, digest: engine.image.digest,
    }, contract.previousArtifact) &&
    plan.final_artifact.repository.split("/").at(-1) === contract.previousArtifact.repository.split("/").at(-1) &&
    plan.final_artifact?.tag === contract.tag && plan.final_artifact?.digest === null;
}
