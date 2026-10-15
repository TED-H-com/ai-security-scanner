import { publicationOrigin, publicationRunId } from "./publication-origins.mjs";
import { isDeepStrictEqual } from "node:util";

const updateFields = ["engine_version", "reported_version", "source_revision", "rule_version",
  "knowledge_date", "support_until", "engine_provenance", "rules_provenance",
  "data_provenance", "knowledge_input"];

function exactFields(value, fields) {
  return value && typeof value === "object" && !Array.isArray(value) &&
    isDeepStrictEqual(Object.keys(value).sort(), [...fields].sort());
}

export function validateUpstreamUpdateMetadata(update) {
  const flatRecord = (value, fields) => exactFields(value, fields) &&
    Object.values(value).every((item) => item === null || typeof item === "string");
  if (!exactFields(update, updateFields) ||
      !updateFields.slice(0, 6).every((field) => update[field] === null || typeof update[field] === "string") ||
      !flatRecord(update.engine_provenance, ["version", "source_repository", "source_revision", "source_ref",
        "acquisition_source", "artifact_source_revision", "source_association"]) ||
      !flatRecord(update.rules_provenance, ["mode", "identifier", "revision", "acquisition_source"]) ||
      !flatRecord(update.data_provenance, ["mode", "identifier", "revision", "acquisition_source"]) ||
      !flatRecord(update.knowledge_input, ["kind", "identifier", "version", "acquisition_source", "pin_state"])) {
    throw new Error("upstream update metadata must contain only closed catalog identity fields");
  }
}

// Historical coordinates are evidence of the retained release, never inputs to
// the replacement build. Keep this metadata closed so an executable input
// cannot be hidden in a subtree omitted from the build identity.
export function validateReplacementHistory(plan) {
  const artifact = plan.previous_artifact;
  const publication = plan.previous_publication;
  if (plan.upstream_update !== undefined) {
    validateUpstreamUpdateMetadata(plan.upstream_update);
    if (artifact === undefined || publication === undefined) {
      throw new Error("upstream update requires the retained publication history");
    }
  }
  if (artifact === undefined && publication === undefined) return;
  const exactKeys = (value, keys) => value && typeof value === "object" &&
    !Array.isArray(value) && isDeepStrictEqual(Object.keys(value).sort(), keys.sort());
  const digest = /^sha256:[0-9a-f]{64}$/u;
  if (!exactKeys(artifact, ["repository", "tag", "digest"]) ||
      !digest.test(artifact.digest) || typeof artifact.repository !== "string" || typeof artifact.tag !== "string" ||
      !exactKeys(publication, ["workflow_run", "source_revision", "platforms", "platform_digests",
        "anonymous_pull_verified", "evidence_artifact",
        ...(plan.upstream_update === undefined || Object.hasOwn(publication ?? {}, "managed_smoke_evidence_sha256")
          ? ["managed_smoke_evidence_sha256"] : [])]) ||
      !publicationRunId(artifact.repository, publication.workflow_run) ||
      !/^[0-9a-f]{40}$/u.test(publication.source_revision) ||
      !isDeepStrictEqual(publication.platforms, ["linux/amd64", "linux/arm64"]) ||
      !exactKeys(publication.platform_digests, ["linux/amd64", "linux/arm64"]) ||
      !Object.values(publication.platform_digests).every((value) => digest.test(value)) ||
      publication.anonymous_pull_verified !== true ||
      !/^[a-z0-9-]+-image-evidence-[1-9][0-9]*-[1-9][0-9]*$/u.test(publication.evidence_artifact) ||
      ((plan.upstream_update === undefined || Object.hasOwn(publication, "managed_smoke_evidence_sha256")) &&
        !digest.test(publication.managed_smoke_evidence_sha256))) {
    throw new Error("replacement history must contain only immutable artifact coordinates and publication evidence");
  }
}

// The installed catalog continues to describe the retained, published image.
// Candidate metadata is used only to check the replacement source recipe; it
// cannot change commands, permissions, targets, resource limits or image pins.
export function pendingUpstreamBuild(plan, engine) {
  if (plan.upstream_update === undefined) return null;
  validateReplacementHistory(plan);
  const update = plan.upstream_update;
  const retained = engine.image && {
    repository: engine.image.repository, tag: engine.image.tag, digest: engine.image.digest,
  };
  const candidate = plan.final_artifact;
  const validDate = (value) => typeof value === "string" && /^\d{4}-\d{2}-\d{2}$/u.test(value) &&
    Number.isFinite(Date.parse(value)) && new Date(value).toISOString().startsWith(value);
  if (plan.publish_state !== "publication_in_progress" || plan.publication !== null ||
      !isDeepStrictEqual(plan.previous_artifact, retained) || !engine.compatibility?.runnable ||
      !exactFields(candidate, ["repository", "tag", "digest"]) ||
      candidate?.digest !== null || candidate.tag === retained?.tag ||
      candidate?.repository?.split("/").at(-1) !== retained?.repository?.split("/").at(-1) ||
      !/^[0-9a-f]{40}$/u.test(update.source_revision ?? "") ||
      update.source_revision !== plan.source?.revision ||
      update.engine_provenance?.version !== update.engine_version ||
      update.engine_provenance?.source_revision !== update.source_revision ||
      update.engine_provenance?.source_repository !== plan.source?.repository ||
      update.engine_provenance?.source_repository !== engine.repository_url ||
      update.engine_provenance?.artifact_source_revision !== null ||
      update.engine_provenance?.source_association !== "source_build_required" ||
      update.rules_provenance?.revision !== update.rule_version ||
      !validDate(update.knowledge_date) || !validDate(update.support_until) ||
      Date.parse(update.support_until) < Date.parse(update.knowledge_date) ||
      Date.parse(update.support_until) - Date.parse(update.knowledge_date) > 90 * 86400_000) {
    throw new Error("upstream update must retain the published catalog and bind an unpublished source recipe");
  }
  publicationOrigin(candidate.repository);
  const sourceBuild = update.engine_version === `source@${update.source_revision}`;
  if (sourceBuild ? !/^\d+\.\d+\.\d+$/u.test(update.reported_version ?? "") : update.reported_version !== null) {
    throw new Error("upstream update must distinguish source identity from the reported version");
  }
  const version = update.reported_version ?? update.engine_version;
  if (candidate.tag !== version && !candidate.tag.startsWith(`${version}-`)) {
    throw new Error("upstream update tag must identify the candidate version");
  }
  const buildEngine = {
    ...engine,
    engine_version: update.engine_version,
    source_revision: update.source_revision,
    rule_version: update.rule_version,
    provenance: { ...engine.provenance, engine: update.engine_provenance,
      rules: update.rules_provenance, data: update.data_provenance },
    compatibility: { ...engine.compatibility, knowledge_input: update.knowledge_input },
  };
  if (sourceBuild) buildEngine.reported_version = update.reported_version;
  else delete buildEngine.reported_version;
  return buildEngine;
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
