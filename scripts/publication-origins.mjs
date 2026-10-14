// Publication coordinates are a pair: GitHub's repository move did not move GHCR packages.
export const REPOSITORY_ID = "1344650415";
export const PUBLICATION_ORIGINS = Object.freeze([
  Object.freeze({ namespace: "ghcr.io/teddashh", repository: "teddashh/ai-security-scanner" }),
  Object.freeze({ namespace: "ghcr.io/ted-h-com", repository: "TED-H-com/ai-security-scanner" }),
]);
export const CURRENT_PUBLICATION_ORIGIN = PUBLICATION_ORIGINS[1];
// Pre-move installs (<= 0.5.1) accept only this path; GitHub redirects it to the
// current repository. The name teddashh/ai-security-scanner must never be recreated.
export const UPDATER_DOWNLOAD_REPOSITORY = PUBLICATION_ORIGINS[0].repository;

export function publicationOrigin(image, repository) {
  const origin = PUBLICATION_ORIGINS.find((candidate) =>
    typeof image === "string" && image.startsWith(`${candidate.namespace}/`));
  if (!origin || !/^[a-z0-9][a-z0-9._-]*$/u.test(image.slice(origin.namespace.length + 1))
    || (repository !== undefined && repository !== origin.repository)) {
    throw new Error("unrecognized or mixed publication origin");
  }
  return origin;
}

export function validateRepositoryId(record) {
  // Older attestations do not expose this extension. Check every exposed ID.
  for (const key of ["sourceRepositoryIdentifier", "repositoryId", "repository_id"]) {
    if (record?.[key] !== undefined && String(record[key]) !== REPOSITORY_ID) {
      throw new Error("publication repository numeric id mismatch");
    }
  }
  if (record && typeof record === "object") {
    for (const value of Object.values(record)) validateRepositoryId(value);
  }
}

export function certificateOriginMatches(certificate, origin) {
  const source = `https://github.com/${origin.repository}`;
  const owner = `https://github.com/${origin.repository.split("/")[0]}`;
  return (certificate?.sourceRepositoryOwnerURI === undefined || certificate.sourceRepositoryOwnerURI === owner)
    && (certificate?.buildConfigURI === undefined || certificate.buildConfigURI.startsWith(`${source}/.github/workflows/`));
}

export function provenanceOriginMatches(predicate, origin) {
  const source = `https://github.com/${origin.repository}`;
  const workflow = predicate?.buildDefinition?.externalParameters?.workflow;
  const builder = predicate?.runDetails?.builder;
  const invocation = predicate?.runDetails?.metadata?.invocationId;
  return (!workflow || workflow.repository === source)
    && (!builder || builder.id?.startsWith(`${source}/.github/workflows/`))
    && (invocation === undefined || invocation.startsWith(`${source}/actions/runs/`))
    && (predicate?.buildDefinition?.resolvedDependencies ?? []).every((dependency) =>
      !/^(?:git\+)?https:\/\/github\.com\//u.test(dependency?.uri ?? "") || dependency.uri.startsWith(`git+${source}@`));
}

export function publicationRunId(image, url) {
  const { repository } = publicationOrigin(image);
  const prefix = `https://github.com/${repository}/actions/runs/`;
  const id = typeof url === "string" && url.startsWith(prefix) ? url.slice(prefix.length) : "";
  return /^[1-9][0-9]*$/u.test(id) ? id : null;
}

// Image labels describe the managed image, unlike upstream package source links in an SBOM.
export function validateImageSourceLabels(document, origin) {
  if (!document || typeof document !== "object") return;
  const source = `https://github.com/${origin.repository}`;
  if ((document.name === "syft:image:labels:org.opencontainers.image.source"
    || document.name === "org.opencontainers.image.source") && document.value !== source) {
    throw new Error("image source URL publication origin mismatch");
  }
  if (Object.hasOwn(document, "org.opencontainers.image.source") && document["org.opencontainers.image.source"] !== source) {
    throw new Error("image source URL publication origin mismatch");
  }
  for (const value of Object.values(document)) validateImageSourceLabels(value, origin);
}

export function publicationSourceOrigin(url) {
  const origin = PUBLICATION_ORIGINS.find(({ repository }) => url === `https://github.com/${repository}`);
  if (!origin) throw new Error("unrecognized publication source repository");
  return origin;
}
