import assert from "node:assert/strict";
import test from "node:test";
import { PUBLICATION_ORIGINS, publicationOrigin, validateImageSourceLabels } from "../../scripts/publication-origins.mjs";
import { matchingVerifiedProvenance } from "../../scripts/engine-image-evidence.mjs";
import { validateProvenancePredicate, validateVerifiedCertificate } from "../../scripts/release/verify-publication-artifact.mjs";

const spec = { workflow: ".github/workflows/engine-image-gitleaks.yml" };
const sourceRevision = "ab".repeat(20);
const digest = `sha256:${"11".repeat(32)}`;
const runId = "12345";
const attempt = "1";

function fixture(origin) {
  const image = `${origin.namespace}/ai-security-scanner-engine-gitleaks`;
  const repository = origin.repository;
  const workflowRef = `${repository}/${spec.workflow}@refs/heads/main`;
  const signer = `https://github.com/${workflowRef}`;
  const invocation = `https://github.com/${repository}/actions/runs/${runId}/attempts/${attempt}`;
  const certificate = {
    sourceRepositoryURI: `https://github.com/${repository}`,
    sourceRepositoryIdentifier: "1344650415",
    sourceRepositoryOwnerURI: `https://github.com/${repository.split("/")[0]}`,
    buildConfigURI: signer,
    sourceRepositoryDigest: sourceRevision,
    sourceRepositoryRef: "refs/heads/main",
    githubWorkflowRepository: repository,
    githubWorkflowSHA: sourceRevision,
    buildSignerURI: signer,
    buildSignerDigest: sourceRevision,
    subjectAlternativeName: signer,
    runInvocationURI: invocation,
    runnerEnvironment: "github-hosted",
    sourceRepositoryVisibilityAtSigning: "public",
  };
  const predicate = {
    buildDefinition: {
      buildType: "https://actions.github.io/buildtypes/workflow/v1",
      externalParameters: { workflow: { repository: `https://github.com/${repository}`, path: spec.workflow, ref: "refs/heads/main" } },
      resolvedDependencies: [{ uri: `git+https://github.com/${repository}@refs/heads/main`, digest: { gitCommit: sourceRevision } }],
    },
    runDetails: { builder: { id: signer }, metadata: { invocationId: invocation } },
  };
  const records = [{ verificationResult: {
    signature: { certificate },
    statement: { subject: [{ name: image, digest: { sha256: digest.slice(7) } }], predicateType: "https://slsa.dev/provenance/v1", predicate },
  } }];
  return { image, repository, workflowRef, certificate, predicate, records };
}

test("both JS verifiers accept each complete origin pair", () => {
  for (const origin of PUBLICATION_ORIGINS) {
    const f = fixture(origin);
    assert.equal(publicationOrigin(f.image, f.repository), origin);
    validateImageSourceLabels({ properties: [{ name: "org.opencontainers.image.source", value: `https://github.com/${f.repository}` }] }, origin);
    assert.ok(matchingVerifiedProvenance(f.records, { ...f, digest, sourceRevision }));
    validateVerifiedCertificate(f.certificate, { ...f, spec, sourceRevision, runId, attempt });
    validateProvenancePredicate(f.predicate, { origin, spec, sourceRevision, runId, attempt });
  }
});

test("both JS verifiers reject both mixed pairs and unknown owners", () => {
  for (const [index, origin] of PUBLICATION_ORIGINS.entries()) {
    const f = fixture(origin);
    const other = fixture(PUBLICATION_ORIGINS[1 - index]);
    assert.throws(() => publicationOrigin(f.image, other.repository), /publication origin/u);
    assert.throws(() => matchingVerifiedProvenance(other.records, { ...other, image: f.image, digest, sourceRevision }), /publication origin/u);
    assert.throws(() => validateVerifiedCertificate(other.certificate, { image: f.image, spec, sourceRevision, runId, attempt }), /(?:repository|owner) mismatch/u);
    assert.throws(() => validateProvenancePredicate(other.predicate, { origin, spec, sourceRevision, runId, attempt }), /repository mismatch/u);
    assert.throws(() => validateImageSourceLabels({ properties: [{ name: "org.opencontainers.image.source", value: `https://github.com/${other.repository}` }] }, origin), /origin mismatch/u);
    f.predicate.buildDefinition.resolvedDependencies.push(other.predicate.buildDefinition.resolvedDependencies[0]);
    assert.equal(matchingVerifiedProvenance(f.records, { ...f, digest, sourceRevision }), undefined);
    assert.throws(() => validateProvenancePredicate(f.predicate, { origin, spec, sourceRevision, runId, attempt }), /repository mismatch/u);
  }
  assert.throws(() => publicationOrigin("ghcr.io/unknown/ai-security-scanner-engine-gitleaks", "unknown/ai-security-scanner"), /publication origin/u);
});

test("verified owner fields and exposed numeric repository IDs cannot drift independently", () => {
  for (const origin of PUBLICATION_ORIGINS) {
    for (const field of ["sourceRepositoryURI", "githubWorkflowRepository", "buildSignerURI", "subjectAlternativeName", "sourceRepositoryIdentifier", "sourceRepositoryOwnerURI", "buildConfigURI"]) {
      const f = fixture(origin);
      f.certificate[field] = "unknown";
      assert.throws(() => validateVerifiedCertificate(f.certificate, { ...f, spec, sourceRevision, runId, attempt }), /mismatch/u);
      if (field === "sourceRepositoryIdentifier") {
        assert.throws(() => matchingVerifiedProvenance(f.records, { ...f, digest, sourceRevision }), /numeric id mismatch/u);
      } else assert.equal(matchingVerifiedProvenance(f.records, { ...f, digest, sourceRevision }), undefined);
    }
    const f = fixture(origin);
    f.certificate.sourceRepositoryIdentifier = 1344650415;
    validateVerifiedCertificate(f.certificate, { ...f, spec, sourceRevision, runId, attempt });
  }
});
