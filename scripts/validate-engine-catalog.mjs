#!/usr/bin/env node

import { createHash } from "node:crypto";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { basename, resolve, sep } from "node:path";
import { parse as parseYaml } from "yaml";

import { PUBLICATION_ORIGINS, publicationOrigin, publicationRunId } from "./publication-origins.mjs";
import { validateProwlerCatalogContract } from "./prowler-catalog-contract.mjs";
import { isPendingImageReplacement, pendingUpstreamBuild } from "./engine-image-replacement.mjs";
import { LOCAL_BUILD_GUARD, LOCAL_IMAGE_DIGEST, validateSemgrepNativePublication } from "./semgrep-native-publication-contract.mjs";

const root = resolve(import.meta.dirname, "..");
const catalogPath = resolve(root, "engines/catalog.json");
const schemaPath = resolve(root, "engines/compatibility.schema.json");
const upstreamLockPath = resolve(root, "engines/upstreams.lock.json");
const managedCloudIds = new Set([
  "cloudquery",
  "cloudsplaining",
  "prowler",
  "scoutsuite",
  "steampipe",
]);
const managedExternalContracts = new Map([
  ["naabu", { tag: "2.6.1-7" }],
  ["httpx", { tag: "1.12.0-1" }],
  ["nuclei", { tag: "3.11.1-8" }],
]);
const managedExternalIds = new Set(managedExternalContracts.keys());
const naabuLauncherJournalVersion = 2;
const legacyNaabuLauncherCommand = [
  "--engine", "naabu",
  "--scope", "/run/ai-security-scanner/scope.json",
  "--output", "/output",
];
const naabuLauncherJournalV2Command = [
  ...legacyNaabuLauncherCommand,
  "--journal-version", "2",
  "--journal-plan", "/run/ai-security-scanner/execution-journal-v2.json",
];
const managedM365Contracts = new Map([
  ["scubagear", {
    tag: "1.8.0-8",
    sourceRatingField: "SourceCriticality",
    sourceRatingVariable: "$criticality",
    optionalPropertySnippet: "$control.PSObject.Properties['Criticality']",
    optionalValueSnippet: "$criticalityValue = if ($null -eq $criticalityProperty) { $null } else { $criticalityProperty.Value }",
    forbiddenDirectPropertySnippet: "$control.Criticality",
    switchExpression: "$criticality.ToLowerInvariant()",
    reviewedRatings: ["shall", "shall/3rd party", "shall/not-implemented", "should", "should/3rd party", "should/not-implemented"],
    normalizationSnippets: [
      "'shall' { 'high'; break }",
      "'shall/3rd party' { 'high'; break }",
      "'shall/not-implemented' { 'high'; break }",
      "'should' { 'medium'; break }",
      "'should/3rd party' { 'medium'; break }",
      "'should/not-implemented' { 'medium'; break }",
    ],
    forbiddenNormalizationSnippets: [
      "'^Shall(?:/|$)'",
      "'^Should(?:/|$)'",
    ],
    verdictSwitchExpression: "-Regex ($verdict)",
    reviewedVerdicts: ["^Pass$", "^(Fail|Warning)$"],
    carriedVerdictCounters: ["passes", "failures", "warnings"],
  }],
  ["maester", {
    tag: "2.0.0-9",
    sourceRatingField: "SourceSeverity",
    sourceRatingVariable: "$sourceSeverity",
    optionalPropertySnippet: "$test.PSObject.Properties['Severity']",
    optionalValueSnippet: "$sourceSeverityValue = if ($null -eq $sourceSeverityProperty) { $null } else { $sourceSeverityProperty.Value }",
    forbiddenDirectPropertySnippet: "$test.Severity",
    switchExpression: "$sourceSeverity.ToLowerInvariant()",
    reviewedRatings: ["critical", "high", "medium", "low", "info"],
    normalizationSnippets: [
      "'critical' { 'critical'; break }",
      "'high' { 'high'; break }",
      "'medium' { 'medium'; break }",
      "'low' { 'low'; break }",
      "'info' { 'informational'; break }",
    ],
    forbiddenNormalizationSnippets: [
      "'informational' { 'informational'; break }",
    ],
    verdictSwitchExpression: "($sourceResult)",
    reviewedVerdicts: ["Passed", "Failed", "Investigate"],
    carriedVerdictCounters: ["passes", "failures", "investigate"],
  }],
]);
const managedM365Ids = new Set(managedM365Contracts.keys());
function managedRepository(engine, plan) {
  const image = engine?.image?.repository ?? plan?.final_artifact?.repository;
  // Upstream-only engines also visit pending-plan predicates.
  const origin = PUBLICATION_ORIGINS.find(({ namespace }) => image?.startsWith(`${namespace}/`));
  return `${(origin ?? PUBLICATION_ORIGINS[0]).namespace}/ai-security-scanner-engine-${engine?.id}`;
}
const managedLocalSmokeOutputFiles = new Map([
  ["semgrep", "semgrep.json"],
  ["trufflehog", "trufflehog.jsonl"],
  ["trivy", "trivy.json"],
  ["grype", "grype.json"],
  ["kubescape", "kubescape.json"],
  ["kube-bench", "kube-bench.json"],
]);
const managedLocalK8sContracts = new Map([
  ["agentic-radar", {
    tag: "0.14.1-1",
    planKind: "managed_build",
    license: { disposition: "allow", sourceOfferPath: null },
    entrypoint: "/usr/local/bin/ai-security-scanner-agentic-radar-entrypoint",
    launcherPath: "engines/images/agentic-radar/launcher/main.go",
    launcherDockerfileCopy: "COPY engines/images/agentic-radar/launcher/go.mod engines/images/agentic-radar/launcher/main.go engines/images/agentic-radar/launcher/main_test.go ./",
    command: ["--engine", "agentic-radar", "--workspace", "/workspace", "--output", "/output"],
    outputFormats: ["json"],
    sourceArchiveSha256: "sha256:433fe72ee2d31135730b781ef812d50c2abeaeb1ec217e90d2f6acf0d455f713",
    sourceDateEpoch: 1764257310,
    sourcePatch: {
      path: "docs/research/patches/agentic-radar-0.14.1-machine-json.patch",
      sha256: "sha256:d32c61e4c2134141686e950a3f025c1b521a1f0096e5572c6846b65d0afb9d72",
    },
    immutableLauncherInputs: [
      '"-I", "-B", "-m", "agentic_radar", "scan", framework',
      '"--export-graph-json"',
      '"PYTHON_DOTENV_DISABLED=1"',
      'command.Dir = "/tmp/ai-security-scanner-home"',
      "requireReadOnlyWorkspace(*workspace)",
      "validateTerminalEvidence(reportPath, framework)",
      'envelope.Framework != framework',
    ],
    immutableDockerfileInputs: [
      "--only-binary=:all:", "--require-hashes", "--no-build-isolation", "--no-deps",
      "tests/graph_json_export_test.py",
      "engines/images/agentic-radar/build-requirements.lock",
      "engines/images/agentic-radar/PATCHES.md",
      "git apply --check /tmp/agentic-radar-machine-json.patch",
      'io.ai-security-scanner.patch-sha256="d32c61e4c2134141686e950a3f025c1b521a1f0096e5572c6846b65d0afb9d72"',
    ],
  }],
  ["semgrep", {
    tag: "1.181.0-1",
    planKind: "managed_build",
    license: { disposition: "source_offer", sourceOfferPath: "engines/images/semgrep/SOURCE-OFFER.md" },
    immutableDockerfileInputs: [
      "COPY engines/images/semgrep/build_rule_pack.py engines/images/semgrep/product-rules.yml engines/images/semgrep/product-LICENSE /tmp/rule-builder/",
      "COPY --from=rule-pack /tmp/semgrep-rule-pack/rules /opt/ai-security-scanner/semgrep/rules",
      "COPY --from=rule-pack /tmp/semgrep-rule-pack/RULES.sha256 /opt/ai-security-scanner/semgrep/RULES.sha256",
      "COPY --from=rule-pack /tmp/semgrep-rule-pack/LICENSE /usr/share/licenses/semgrep-rules/LICENSE",
      "COPY --from=rule-pack /tmp/semgrep-rule-pack/RULE-PROVENANCE.json /opt/ai-security-scanner/semgrep/RULE-PROVENANCE.json",
      "COPY --from=source /tmp/semgrep-complete-source.tar.gz /usr/share/source/semgrep-source.tar.gz",
      "RUN --mount=type=bind,source=.engine-cache/offline/semgrep-submodules/tests__semgrep-rules.tar.gz,target=/tmp/rules.tar.gz,readonly",
      "COPY engines/images/semgrep/submodules.lock /usr/share/source/semgrep-submodules.lock",
      "COPY engines/images/semgrep/SOURCE-OFFER.md /usr/share/source/SEMGREP-SOURCE-OFFER.md",
      'SEMGREP_ENABLE_VERSION_CHECK="0"',
      'SEMGREP_SEND_METRICS="off"',
    ],
  }],
  ["gitleaks", {
    tag: "8.30.1-2",
    previousArtifact: {
      repository: "ghcr.io/teddashh/ai-security-scanner-engine-gitleaks",
      tag: "8.30.1-1",
      digest: "sha256:5b4538ca17201dba53fed7d5ea49f94cfd7815a4ce2a5b36cac408757ff349aa",
    },
    previousPublicationSource: "77233a2d08684294c7620f8da601e1e1efed6023",
    planKind: "managed_build",
    license: { disposition: "allow", sourceOfferPath: null },
    entrypoint: "/usr/local/bin/ai-security-scanner-gitleaks-entrypoint",
    launcherPath: "engines/images/gitleaks/launcher/main.go",
    launcherDockerfileCopy: "COPY engines/images/gitleaks/launcher/go.mod engines/images/gitleaks/launcher/main.go engines/images/gitleaks/launcher/main_test.go ./",
    command: ["--workspace", "/workspace", "--output", "/output"],
    outputFormats: ["json"],
    ruleVersion: "sha256:e163e53b9e7e8a8511e77271e2b323ed057759542a6d988258afe3a1fa329caf",
    sourceArchiveSha256: "sha256:6b2638a733b85619dc80bdf28e84e4fed7e526a761ab5c148fbf67695aea2115",
    sourceDateEpoch: 1773330037,
    sourceIntegrity: {
      go_sum_sha256: "sha256:3fd66952713338b561c71c7ed608c5cce41355a7594c4eb8ffb4303abae29ccd",
      default_config_sha256: "sha256:e163e53b9e7e8a8511e77271e2b323ed057759542a6d988258afe3a1fa329caf",
    },
    sourcePatch: {
      path: "engines/images/gitleaks/patches/0001-add-scanner-owned-ignore-policy.patch",
      sha256: "sha256:9e7e7443fe5b5ee52dfb5ebb458d73fa868c441729e98d98a0453e7dd8cc24a7",
    },
    immutableLauncherInputs: [
      'workspaceMountPath  = "/workspace"',
      'outputMountPath     = "/output"',
      'reportPath          = "/output/gitleaks.json"',
      'configPath          = "/opt/ai-security-scanner/gitleaks/gitleaks.toml"',
      'configSHA256        = "e163e53b9e7e8a8511e77271e2b323ed057759542a6d988258afe3a1fa329caf"',
      '"--ignore-gitleaks-allow"',
      '"--no-source-ignore"',
      '"--exit-code", "0"',
      '"--redact=100"',
      '"--max-decode-depth", "5"',
      '"--max-archive-depth", "0"',
      'secret != "REDACTED"',
      "requireReadOnlyWorkspace(*workspace)",
      "ensureAbsent(reportPath)",
      "validateRedactedEvidence(reportPath)",
    ],
    immutableDockerfileInputs: [
      "COPY engines/images/gitleaks/testdata/ /src/testdata/",
      "ADD --checksum=sha256:6b2638a733b85619dc80bdf28e84e4fed7e526a761ab5c148fbf67695aea2115",
      "https://github.com/gitleaks/gitleaks/archive/83d9cd684c87d95d656c1458ef04895a7f1cbd8e.tar.gz",
      "3fd66952713338b561c71c7ed608c5cce41355a7594c4eb8ffb4303abae29ccd  go.sum",
      "e163e53b9e7e8a8511e77271e2b323ed057759542a6d988258afe3a1fa329caf  config/gitleaks.toml",
      "COPY engines/images/gitleaks/patches/0001-add-scanner-owned-ignore-policy.patch /tmp/0001-add-scanner-owned-ignore-policy.patch",
      "9e7e7443fe5b5ee52dfb5ebb458d73fa868c441729e98d98a0453e7dd8cc24a7  /tmp/0001-add-scanner-owned-ignore-policy.patch",
      "git apply --check /tmp/0001-add-scanner-owned-ignore-policy.patch",
      "install -m 0444 config/gitleaks.toml /rootfs/opt/ai-security-scanner/gitleaks/gitleaks.toml",
      "SOURCE_DATE_EPOCH=1773330037",
      'io.ai-security-scanner.gitleaks-config-sha256="e163e53b9e7e8a8511e77271e2b323ed057759542a6d988258afe3a1fa329caf"',
      'io.ai-security-scanner.patch-sha256="9e7e7443fe5b5ee52dfb5ebb458d73fa868c441729e98d98a0453e7dd8cc24a7"',
    ],
  }],
  ["mcp-armor", {
    tag: "1.0.2-config-only.1",
    planKind: "managed_build",
    license: { disposition: "allow", sourceOfferPath: null },
    entrypoint: "/usr/local/bin/ai-security-scanner-mcp-armor-entrypoint",
    launcherPath: "engines/images/mcp-armor/launcher/main.go",
    launcherDockerfileCopy: "COPY engines/images/mcp-armor/launcher/go.mod engines/images/mcp-armor/launcher/main.go engines/images/mcp-armor/launcher/main_test.go ./",
    command: ["--engine", "mcp-armor", "--workspace", "/workspace", "--output", "/output"],
    outputFormats: ["json"],
    ruleVersion: "6af4cee4665ab6242f02a88952f9127b6a04922a",
    sourceArchiveSha256: "sha256:6bf3da5f1332748eb0dc60fb1f82f1ee43bb721f70686f99f4f262d256da45a6",
    sourceDateEpoch: 1774602347,
    sourcePatch: {
      path: "docs/research/patches/mcp-armor-1.0.2-config-only.patch",
      sha256: "sha256:ae7732b5f9c922fbf2bee54e0246cccde6e1e5af829db112eb0f948cbd424122",
    },
    immutableLauncherInputs: [
      'workspaceMountPath             = "/workspace"',
      'scopeDocumentPath              = "/run/ai-security-scanner/scope.json"',
      'reportPath                     = "/output/mcp-armor.json"',
      '"--config-only"',
      "requireReadOnlyWorkspace(*workspace)",
      "verifySelectedConfiguration(*workspace, selected)",
      "validateTerminalEvidence(reportPath)",
    ],
    immutableDockerfileInputs: [
      "ADD --checksum=sha256:6bf3da5f1332748eb0dc60fb1f82f1ee43bb721f70686f99f4f262d256da45a6",
      "https://github.com/aira-security/mcp-armor/archive/6af4cee4665ab6242f02a88952f9127b6a04922a.tar.gz",
      "COPY docs/research/patches/mcp-armor-1.0.2-config-only.patch /tmp/mcp-armor-config-only.patch",
      "ae7732b5f9c922fbf2bee54e0246cccde6e1e5af829db112eb0f948cbd424122  /tmp/mcp-armor-config-only.patch",
      "git apply --check /tmp/mcp-armor-config-only.patch",
      "86d9dfb49bdd485ebb7855fda467c2cd6ac93c2a91609c08fa9e476c6dc746f8  /tmp/requirements.lock",
      "--only-binary=:all:",
      "--require-hashes",
      "SOURCE_DATE_EPOCH=1774602347",
      'io.ai-security-scanner.patch-sha256="ae7732b5f9c922fbf2bee54e0246cccde6e1e5af829db112eb0f948cbd424122"',
      'io.ai-security-scanner.requirements-sha256="86d9dfb49bdd485ebb7855fda467c2cd6ac93c2a91609c08fa9e476c6dc746f8"',
    ],
  }],
  ["trufflehog", {
    tag: "3.99.2-1",
    planKind: "managed_build",
    license: { disposition: "source_offer", sourceOfferPath: "engines/images/trufflehog/SOURCE-OFFER.md" },
    immutableDockerfileInputs: [
      "go mod verify",
      "go build -mod=readonly",
      "COPY engines/images/trufflehog/SOURCE-OFFER.md /usr/share/source/TRUFFLEHOG-SOURCE-OFFER.md",
    ],
  }],
  ["trivy", {
    tag: "0.76.1-1",
    planKind: "managed_build",
    license: { disposition: "allow", sourceOfferPath: null },
    immutableLauncherInputs: [
      'outputPath:  "/output/trivy-individual-packages.json"',
      '"rootfs", "--cache-dir", "/opt/ai-security-scanner/trivy-cache"',
      'verifyFile("/opt/ai-security-scanner/trivy-cache/java-db/trivy-java.db", trivyJavaDBSHA256, maxImmutableBytes)',
      'trivyJavaDBSHA256           = "24d6c783ce89260282c46886b2dab64a69b7fcc31dae4447ed67194b38f77770"',
      'trivyJavaMetadataSHA256     = "1b91db7182eda1c8b74db15a4b515238617c5e179d9d1623b82ff0af4a8b4ee2"',
    ],
    immutableDockerfileInputs: [
      "go mod verify",
      "go build -mod=readonly",
      "COPY .engine-cache/offline/trivy/db.tar.gz /tmp/trivy-db.tar.gz",
      "COPY .engine-cache/offline/trivy/java-db.tar.gz /tmp/trivy-java-db.tar.gz",
      "35c8f473bb7485db657c022eee43404fda3684fc3c0341aef3598db6016c28ca  /tmp/trivy-java-db.tar.gz",
      "24d6c783ce89260282c46886b2dab64a69b7fcc31dae4447ed67194b38f77770  /rootfs/opt/ai-security-scanner/trivy-cache/java-db/trivy-java.db",
      "1b91db7182eda1c8b74db15a4b515238617c5e179d9d1623b82ff0af4a8b4ee2  /rootfs/opt/ai-security-scanner/trivy-cache/java-db/metadata.json",
      "COPY engines/images/trivy/DATABASE-NOTICE.md /usr/share/licenses/trivy/DATABASE-NOTICE.md",
      'io.ai-security-scanner.java-database-manifest="sha256:a805d22ec39082e3d0910a6c37ae4e85c666248293add991d2d2bf82237323a5"',
      'TRIVY_CACHE_DIR="/opt/ai-security-scanner/trivy-cache"',
    ],
  }],
  ["grype", {
    tag: "0.120.1-1",
    planKind: "managed_build",
    license: { disposition: "allow", sourceOfferPath: null },
    immutableDockerfileInputs: [
      "go mod verify",
      "go build -mod=readonly",
      "COPY .engine-cache/offline/grype/db.tar.zst /tmp/grype-db.tar.zst",
      "COPY engines/images/grype/import.json /tmp/grype-import.json",
      'GRYPE_CHECK_FOR_APP_UPDATE="false"',
      'GRYPE_DB_AUTO_UPDATE="false"',
    ],
  }],
  ["kubescape", {
    tag: "4.0.16-1",
    planKind: "managed_build",
    license: { disposition: "allow", sourceOfferPath: null },
    immutableDockerfileInputs: [
      "go mod verify",
      "go build -mod=readonly",
      "https://github.com/kubescape/regolibrary/releases/download/v2/nsa",
      "https://github.com/kubescape/regolibrary/releases/download/v2/default_config_inputs",
      "https://github.com/kubescape/regolibrary/releases/download/v2/exceptions",
      'KS_SUBMIT="false"',
      'OTEL_SDK_DISABLED="true"',
    ],
  }],
  ["kube-bench", {
    tag: "0.16.0-5",
    planKind: "managed_build",
    license: { disposition: "allow", sourceOfferPath: null },
    immutableDockerfileInputs: [
      "go mod verify",
      "go build -mod=readonly",
      "276ade4e21a043f508328ce5598c15fd0f421fe60a8d7e41774439cb355bf6a7  cfg/cis-1.11/node.yaml",
      "f8beefa9c5392e5c25d03e802294ad1852ac094d3bf3053903dad718f599e3b7  cfg/cis-1.11/config.yaml",
      "COPY engines/images/kube-bench/cfg/config.yaml /opt/ai-security-scanner/kube-bench/cfg/config.yaml",
      "COPY --from=build /src/kube-bench/cfg/cis-1.11/config.yaml /opt/ai-security-scanner/kube-bench/cfg/cis-1.11/config.yaml",
      "COPY --from=build /src/kube-bench/cfg/cis-1.11/node.yaml /opt/ai-security-scanner/kube-bench/cfg/cis-1.11/node.yaml",
      "COPY engines/images/kube-bench/SNAPSHOT-PROFILE.md /usr/share/doc/ai-security-scanner/kube-bench-snapshot-profile.md",
    ],
  }],
]);
const managedGreenboneContract = {
  tag: "23.50.24-feed202610010558-1",
  planKind: "multi_component_build",
  license: { disposition: "source_offer", sourceOfferPath: "engines/images/greenbone/SOURCE-OFFER.md" },
  engineVersion: "23.50.24",
  scannerRevision: "26465a11ff0e6a98d60a253265fab5974fc757b6",
  scannerArchiveUrl: "https://github.com/greenbone/openvas-scanner/archive/refs/tags/v23.50.24.tar.gz",
  scannerArchiveSha256: "sha256:af8b1e0175dfc57f38bdecc08607dbac294459e684e2f3e7d69c85101fa13517",
  feedVersion: "202610010558-community",
  feedRevision: "816c24126e0375d32c667b78d20342ce7c58ec58",
  feedImageDigest: "sha256:86a44fb7a9f9b982d521f98914aba98846f573b4f9ec9e8c1007c4866ec943af",
  notusRevision: "202610010540",
  notusImageDigest: "sha256:f53836e6ac0eb3abb7f5ab74ccf93b8317fedd2ba5cd293473cd307c148fc4c3",
  smokeOid: "1.3.6.1.4.1.25623.1.0.108252",
};
const greenbonePublicationBlocker =
  "Publish and independently verify the Greenbone 23.50.24-feed202610010558-1 image for linux/amd64 and linux/arm64, then record its immutable digest and exact publication evidence.";
const managedEvidenceWorkflows = [
  ".github/workflows/engine-image-garak.yml",
  ".github/workflows/engine-image-agentic-radar.yml",
  ".github/workflows/engine-images-cloud.yml",
  ".github/workflows/engine-images-external.yml",
  ".github/workflows/engine-images-m365.yml",
  ".github/workflows/engine-images-local-k8s.yml",
  ".github/workflows/engine-image-gitleaks.yml",
  ".github/workflows/engine-image-greenbone.yml",
  ".github/workflows/engine-image-checkov.yml",
  ".github/workflows/engine-image-syft.yml",
  ".github/workflows/engine-image-mcp-armor.yml",
];
const localK8sWorkflowRelative = ".github/workflows/engine-images-local-k8s.yml";
const managedEgressGatewayWorkflowRelative = ".github/workflows/managed-egress-gateway-image.yml";
const newlyPublishedEvidenceWorkflows = [
  ".github/workflows/engine-image-garak.yml",
  ".github/workflows/engine-image-agentic-radar.yml",
  ".github/workflows/engine-images-external.yml",
  ".github/workflows/engine-images-m365.yml",
  localK8sWorkflowRelative,
  managedEgressGatewayWorkflowRelative,
  ".github/workflows/engine-image-mcp-armor.yml",
];
const upstreamImageOnlyIds = new Set(["kics"]);
const shellNames = new Set([
  "sh", "bash", "dash", "zsh", "fish", "cmd", "cmd.exe",
  "powershell", "powershell.exe", "pwsh", "pwsh.exe",
]);
const floatingTags = new Set([
  "latest", "stable", "edge", "dev", "development", "main", "master",
  "nightly", "canary", "current", "rolling",
]);
const digestPattern = /^sha256:[0-9a-f]{64}$/;
const revisionPattern = /^[0-9a-f]{40}$/;
const isoDatePattern = /^(\d{4})-(\d{2})-(\d{2})$/;
const planKinds = new Set(["upstream_image", "managed_build", "managed_rebase", "managed_source_image", "multi_component_build"]);
const localInputProfilesByAssetKind = new Map([
  ["repository", "repository_working_tree"],
  ["iac_project", "iac_working_tree"],
  ["container_image", "container_image_oci_layout"],
  ["kubernetes_cluster", "kubernetes_manifests"],
  ["host", "kubernetes_node_snapshot"],
]);
const errors = [];

function isIsoDate(value) {
  const match = typeof value === "string" ? isoDatePattern.exec(value) : null;
  if (!match) return false;
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const leapYear = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const daysInMonth = [31, leapYear ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  return month >= 1 && month <= 12 && day >= 1 && day <= daysInMonth[month - 1];
}

function parseJson(path) {
  try {
    return JSON.parse(readFileSync(path, "utf8"));
  } catch (error) {
    errors.push(`${path}: invalid JSON (${error.message})`);
    return null;
  }
}

function sortedUnique(values) {
  return [...new Set(values)].sort();
}

function validateExactIdSet(actual, expected, label) {
  const actualIds = sortedUnique(actual);
  const expectedValues = sortedUnique(expected);
  if (deepEqual(actualIds, expectedValues)) return;
  const actualSet = new Set(actualIds);
  const expectedSet = new Set(expectedValues);
  const missing = expectedValues.filter((id) => !actualSet.has(id));
  const unexpected = actualIds.filter((id) => !expectedSet.has(id));
  errors.push(`${label}: missing [${missing.join(", ") || "none"}]; unexpected [${unexpected.join(", ") || "none"}]`);
}

function parseWorkflow(relative) {
  const absolute = resolve(root, relative);
  if (!existsSync(absolute)) {
    errors.push(`${relative}: managed image evidence workflow is missing`);
    return null;
  }
  try {
    const workflow = parseYaml(readFileSync(absolute, "utf8"));
    if (!workflow || typeof workflow !== "object" || Array.isArray(workflow)) {
      errors.push(`${relative}: workflow must be a YAML mapping`);
      return null;
    }
    return workflow;
  } catch (error) {
    errors.push(`${relative}: invalid workflow YAML (${error.message})`);
    return null;
  }
}

function resolveEvidenceStepEngines(workflow, job, step, label) {
  const configuredEngine = step?.with?.engine;
  if (typeof configuredEngine !== "string") {
    errors.push(`${label}: common evidence action requires an engine input`);
    return [];
  }
  if (/^\$\{\{\s*matrix\.engine\s*\}\}$/.test(configuredEngine)) {
    const include = job?.strategy?.matrix?.include;
    const direct = job?.strategy?.matrix?.engine;
    const matrixEngines = Array.isArray(include)
      ? include.map((entry) => entry?.engine)
      : Array.isArray(direct) ? direct : [];
    if (matrixEngines.length === 0 && typeof job?.strategy?.matrix === "string" &&
        job.strategy.matrix.includes("needs.changes.outputs.matrix")) {
      try {
        const configuredMatrix = JSON.parse(workflow?.env?.CLOUD_ENGINE_MATRIX ?? workflow?.env?.LOCAL_ENGINE_MATRIX ?? "null");
        matrixEngines.push(...(Array.isArray(configuredMatrix) ? configuredMatrix.map((entry) => entry?.engine) : []));
      } catch {
        errors.push(`${label}: declared engine matrix contract is not valid JSON`);
      }
    }
    if (matrixEngines.length === 0 || matrixEngines.some((id) => typeof id !== "string" || !/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(id))) {
      errors.push(`${label}: matrix.engine must resolve to a non-empty static engine list`);
      return [];
    }
    return matrixEngines;
  }
  if (/^\$\{\{\s*env\.ENGINE\s*\}\}$/.test(configuredEngine)) {
    const environmentEngine = workflow?.env?.ENGINE;
    if (typeof environmentEngine !== "string" || !/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(environmentEngine)) {
      errors.push(`${label}: env.ENGINE must resolve to one static engine id`);
      return [];
    }
    return [environmentEngine];
  }
  if (!/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(configuredEngine)) {
    errors.push(`${label}: evidence engine input must be a literal id, exactly \${{ matrix.engine }}, or the statically declared env.ENGINE`);
    return [];
  }
  return [configuredEngine];
}

function validateManagedImageEvidence(catalogEntries) {
  const catalogManagedIds = [];
  for (const engine of Array.isArray(catalogEntries) ? catalogEntries : []) {
    const planPath = engine?.compatibility?.packaging_plan;
    const plan = typeof planPath === "string" && existsSync(resolve(root, planPath))
      ? parseJson(resolve(root, planPath))
      : null;
    const repository = engine?.image?.repository ??
      (isPendingM365Publication(plan, engine) || isPendingManagedExternalPublication(plan, engine) ||
       isPendingMcpArmorPublication(plan, engine) || isPendingLocalK8sPublication(plan, engine)
        ? plan.final_artifact.repository
        : undefined);
    if (typeof repository !== "string" || !PUBLICATION_ORIGINS.some(({ namespace }) => repository.startsWith(`${namespace}/ai-security-scanner-engine-`))) continue;
    catalogManagedIds.push(engine.id);
    if (upstreamImageOnlyIds.has(engine.id)) {
      errors.push(`catalog:${engine.id}.image.repository: upstream-only engine must not be counted as a project-managed image`);
    }
    const expectedRepository = managedRepository(engine, plan);
    if (repository !== expectedRepository) {
      errors.push(`catalog:${engine.id}.image.repository: project-managed image must be exactly ${expectedRepository}`);
    }
  }
  const catalogManagedIdSet = new Set(catalogManagedIds);
  const guardActionPath = resolve(root, ".github/actions/engine-image-evidence/publication-guard/action.yml");
  const promotionActionPath = resolve(root, ".github/actions/engine-image-evidence/promote/action.yml");
  const guardActionText = existsSync(guardActionPath) ? readFileSync(guardActionPath, "utf8") : "";
  const promotionActionText = existsSync(promotionActionPath) ? readFileSync(promotionActionPath, "utf8") : "";
  for (const [label, text, required] of [
    ["managed image publication guard", guardActionText, [
      "publication-preflight",
      "GHCR_TOKEN: ${{ inputs.github-token }}",
      "candidate_tag",
    ]],
    ["managed image version promotion", promotionActionText, [
      "uses: docker/login-action@",
      "password: ${{ inputs.github-token }}",
      "promote-publication",
      "if: always()",
      "run: docker logout ghcr.io",
    ]],
  ]) {
    if (!text || required.some((needle) => !text.includes(needle))) {
      errors.push(`${label} action is missing or does not preserve its fail-closed authentication contract`);
    }
  }
  const localK8sWorkflowPath = resolve(root, localK8sWorkflowRelative);
  const localK8sWorkflowText = existsSync(localK8sWorkflowPath)
    ? readFileSync(localK8sWorkflowPath, "utf8")
    : "";
  const localK8sWorkflow = parseWorkflow(localK8sWorkflowRelative);
  const managedEgressGatewayWorkflow = parseWorkflow(managedEgressGatewayWorkflowRelative);
  const managedEgressGatewayTriggers = Object.keys(managedEgressGatewayWorkflow?.on ?? {}).sort();
  if (JSON.stringify(managedEgressGatewayTriggers) !== JSON.stringify(["workflow_dispatch"])) {
    errors.push(
      `${managedEgressGatewayWorkflowRelative}: immutable gateway publication must be manual-only via workflow_dispatch`,
    );
  }
  let localK8sMatrix = localK8sWorkflow?.jobs?.publish?.strategy?.matrix?.include;
  if (localK8sWorkflow?.jobs?.publish?.strategy?.matrix === "${{ fromJSON(needs.changes.outputs.matrix) }}") {
    try {
      localK8sMatrix = JSON.parse(localK8sWorkflow?.env?.LOCAL_ENGINE_MATRIX ?? "null");
    } catch {
      errors.push(`${localK8sWorkflowRelative}: declared local engine matrix is invalid JSON`);
    }
  }
  const observedSmokeOutputs = new Map(
    Array.isArray(localK8sMatrix)
      ? localK8sMatrix.map((entry) => [entry?.engine, entry?.output_file])
      : [],
  );
  for (const [engineId, contract] of managedLocalK8sContracts) {
    if (!managedLocalSmokeOutputFiles.has(engineId)) continue;
    const matrixEntry = Array.isArray(localK8sMatrix)
      ? localK8sMatrix.find((entry) => entry?.engine === engineId)
      : undefined;
    let expectedTag = contract.tag;
    const candidateEngine = catalog.find((engine) => engine.id === engineId);
    const candidatePlan = candidateEngine?.compatibility?.packaging_plan
      ? parseJson(resolve(root, candidateEngine.compatibility.packaging_plan)) : null;
    try {
      if (candidatePlan && pendingUpstreamBuild(candidatePlan, candidateEngine)) {
        expectedTag = candidatePlan.final_artifact.tag;
      }
    } catch (error) {
      errors.push(`${localK8sWorkflowRelative}: ${engineId} candidate: ${error.message}`);
    }
    if (matrixEntry?.tag !== expectedTag) {
      errors.push(`${localK8sWorkflowRelative}:jobs.publish: ${engineId} tag must match its reviewed artifact contract`);
    }
  }
  for (const [engine, outputFile] of observedSmokeOutputs) {
    const expectedOutputFile = managedLocalSmokeOutputFiles.get(engine);
    if (!expectedOutputFile) {
      errors.push(`${localK8sWorkflowRelative}:jobs.publish: ${engine} has no reviewed managed-smoke output contract`);
    } else if (outputFile !== expectedOutputFile) {
      errors.push(`${localK8sWorkflowRelative}:jobs.publish: ${engine} smoke output must be ${expectedOutputFile}`);
    }
  }
  const localPublishNeeds = Array.isArray(localK8sWorkflow?.jobs?.publish?.needs)
    ? localK8sWorkflow.jobs.publish.needs
    : [localK8sWorkflow?.jobs?.publish?.needs].filter(Boolean);
  const nativeSemgrep = localK8sWorkflow?.jobs?.["semgrep-native-verify"];
  const localPublishIf = localK8sWorkflow?.jobs?.publish?.if ?? "";
  const nativeGate = localK8sWorkflow?.jobs?.publish?.steps?.[0];
  if (!localPublishNeeds.includes("semgrep-native-verify") || nativeSemgrep?.["continue-on-error"] === true ||
      nativeSemgrep?.if !== "contains(fromJSON(needs.changes.outputs.engines), 'semgrep')" ||
      !localPublishIf.includes("always()") ||
      localPublishIf.includes("needs.semgrep-native-verify.result") ||
      nativeGate?.if !== "matrix.engine == 'semgrep'" ||
      nativeGate?.env?.NATIVE_RESULT !== "${{ needs.semgrep-native-verify.result }}" ||
      nativeGate?.run !== 'test "${NATIVE_RESULT}" = success' ||
      !localPublishIf.includes("inputs.mode != 'verify'")) {
    errors.push(`${localK8sWorkflowRelative}: Semgrep requires native verification on both architectures before publication, with sibling engines independent`);
  }
  const localPublishSteps = localK8sWorkflow?.jobs?.publish?.steps;
  errors.push(...validateSemgrepNativePublication(localK8sWorkflow));
  const localVerifyStep = Array.isArray(localPublishSteps)
    ? localPublishSteps.find((step) => step?.id === "verify")
    : undefined;
  const localManifestStep = Array.isArray(localPublishSteps)
    ? localPublishSteps.find((step) => step?.name === "Record the published index and platform digests")
    : undefined;
  if (typeof localVerifyStep?.run !== "string" ||
      !localVerifyStep.run.includes('echo "evidence_sha256=${evidence_sha256}"') ||
      localManifestStep?.env?.EVIDENCE_SHA256 !== "${{ steps.verify.outputs.evidence_sha256 }}" ||
      typeof localManifestStep?.run !== "string" ||
      !localManifestStep.run.includes('--arg evidenceSha256 "${EVIDENCE_SHA256}"') ||
      !localManifestStep.run.includes("managedSmokeEvidenceSha256: $evidenceSha256")) {
    errors.push(`${localK8sWorkflowRelative}: managed smoke receipt hash must flow unchanged from verification output into the root manifest`);
  }
  for (const required of [
    'smoke_evidence="package-evidence/${ENGINE}-managed-smoke"',
    'cp "${output}/${OUTPUT_FILE}" "${smoke_evidence}/${OUTPUT_FILE}"',
    'sha256sum "${OUTPUT_FILE}" > SHA256SUMS.txt',
    "sha256sum trivy-jar.json trivy-library.json trivy-oci.json > SHA256SUMS.txt",
    "engines/images/local-launcher/testdata/trivy-java-db-test.jar.base64",
    "a5c71902c4d26153f1256491362dc94e6598e70e3ba06f19ee02b1dfcd392470",
    '"${jar_output}/trivy-individual-packages.json"',
    'VulnerabilityID == "CVE-2024-23672"',
    'evidence_sha256="sha256:$(sha256sum "${smoke_evidence}/SHA256SUMS.txt"',
    "EVIDENCE_SHA256: ${{ steps.verify.outputs.evidence_sha256 }}",
    "managedSmokeEvidenceSha256: $evidenceSha256",
  ]) {
    if (!localK8sWorkflowText.includes(required)) {
      errors.push(`${localK8sWorkflowRelative}: managed smoke outputs and their checksum receipt must remain downloadable`);
    }
  }
  for (const relative of newlyPublishedEvidenceWorkflows) {
    const workflowPath = resolve(root, relative);
    const workflowText = existsSync(workflowPath) ? readFileSync(workflowPath, "utf8") : "";
    for (const required of [
      "Seal the downloadable evidence inventory",
      "find . -type f ! -path './SHA256SUMS.txt' -print0",
      "LC_ALL=C sort -z",
      "xargs -0 sha256sum > SHA256SUMS.txt",
      "sha256sum --check SHA256SUMS.txt",
    ]) {
      if (!workflowText.includes(required)) {
        errors.push(`${relative}: downloadable publication evidence must have one reproducible top-level checksum inventory`);
      }
    }
    const workflow = parseWorkflow(relative);
    const publicationJobs = Object.entries(workflow?.jobs ?? {}).filter(([, job]) =>
      Array.isArray(job?.steps) && job.steps.some((step) =>
        typeof step?.uses === "string" &&
        step.uses.startsWith("actions/upload-artifact@") &&
        step?.with?.path === "package-evidence"));
    if (publicationJobs.length === 0) {
      errors.push(`${relative}: publication workflow has no package-evidence upload job`);
    }
    for (const [jobId, job] of publicationJobs) {
      const uploadIndex = job.steps.findIndex((step) =>
        typeof step?.uses === "string" &&
        step.uses.startsWith("actions/upload-artifact@") &&
        step?.with?.path === "package-evidence");
      const sealIndex = job.steps.findIndex((step) =>
        step?.name === "Seal the downloadable evidence inventory");
      if (sealIndex < 0 || sealIndex >= uploadIndex) {
        errors.push(`${relative}:jobs.${jobId}: evidence inventory must be sealed before package-evidence is uploaded`);
      }
    }
  }

  const coveredIds = [];
  for (const relative of managedEvidenceWorkflows) {
    const workflow = parseWorkflow(relative);
    if (!workflow) continue;
    const paths = workflow.on?.push?.paths;
    if (!Array.isArray(paths)) {
      errors.push(`${relative}: push.paths must be a static list`);
    } else {
      for (const forbiddenPath of [
        ".github/actions/engine-image-evidence/**",
        "scripts/engine-image-evidence.mjs",
        relative,
      ]) {
        if (paths.includes(forbiddenPath)) {
          errors.push(`${relative}: evidence/workflow-only change must not auto-republish immutable version tags (${forbiddenPath})`);
        }
      }
    }

    const jobs = workflow.jobs;
    if (!jobs || typeof jobs !== "object" || Array.isArray(jobs)) {
      errors.push(`${relative}: jobs must be a YAML mapping`);
      continue;
    }
    const workflowIds = [];
    let evidenceStepCount = 0;
    for (const [jobId, job] of Object.entries(jobs)) {
      const steps = Array.isArray(job?.steps) ? job.steps : [];
      for (const [index, step] of steps.entries()) {
        if (typeof step?.run === "string" && step.run.includes("docker buildx imagetools create") &&
            step.run.includes('${IMAGE}:${IMAGE_TAG}')) {
          errors.push(`${relative}:jobs.${jobId}.steps[${index}]: workflow must not directly mutate a managed version tag`);
        }
      }
      const buildIndexes = steps
        .map((step, index) => typeof step?.uses === "string" && step.uses.startsWith("docker/build-push-action@") ? index : -1)
        .filter((index) => index >= 0);
      for (const buildIndex of buildIndexes) {
        const buildStep = steps[buildIndex];
        const label = `${relative}:jobs.${jobId}.steps[${buildIndex}]`;
        if (typeof buildStep?.with?.push !== "boolean") {
          errors.push(`${label}: docker/build-push-action push must be an explicit boolean`);
        }
        if (buildStep?.with?.provenance !== false || buildStep?.with?.sbom !== false) {
          errors.push(`${label}: docker/build-push-action must set provenance: false and sbom: false`);
        }
        if (buildStep?.with?.push === true) {
          const guardIndex = steps.findIndex((candidate, index) =>
            index < buildIndex && candidate?.uses === "./.github/actions/engine-image-evidence/publication-guard");
          const requiredGuard = relative === localK8sWorkflowRelative && jobId === "publish"
            ? LOCAL_BUILD_GUARD : "steps.guard.outputs.should_build == 'true'";
          if (guardIndex < 0 || buildStep?.if !== requiredGuard ||
              buildStep?.with?.tags !== "${{ env.IMAGE }}:${{ steps.guard.outputs.candidate_tag }}") {
            errors.push(`${label}: publishing build must be guarded and write only its run-unique candidate tag`);
          }
        }
      }
      const publishingBuildIndexes = buildIndexes.filter((index) => steps[index]?.with?.push === true);
      const evidenceIndexes = steps
        .map((step, index) => step?.uses === "./.github/actions/engine-image-evidence" ? index : -1)
        .filter((index) => index >= 0);
      if (publishingBuildIndexes.length > 0 && evidenceIndexes.length === 0) {
        errors.push(`${relative}:jobs.${jobId}: every image publication job must invoke the common evidence action`);
      }
      for (const evidenceIndex of evidenceIndexes) {
        evidenceStepCount += 1;
        const label = `${relative}:jobs.${jobId}.steps[${evidenceIndex}]`;
        const evidenceStep = steps[evidenceIndex];
        if (Object.hasOwn(evidenceStep, "if")) {
          errors.push(`${label}: common evidence action must not be conditionally skipped inside a publication job`);
        }
        for (const input of ["engine", "image", "tag", "digest", "source-revision", "github-token"]) {
          if (typeof evidenceStep?.with?.[input] !== "string" || evidenceStep.with[input].length === 0) {
            errors.push(`${label}: common evidence action requires non-empty ${input}`);
          }
        }
        const evidenceEngineIds = resolveEvidenceStepEngines(workflow, job, evidenceStep, label);
        workflowIds.push(...evidenceEngineIds);

        const permissions = job?.permissions ?? workflow.permissions;
        if (!permissions || typeof permissions !== "object" || Array.isArray(permissions) ||
            permissions["id-token"] !== "write" || permissions.attestations !== "write") {
          errors.push(`${label}: effective permissions must grant id-token: write and attestations: write`);
        }

        const precedingPublishingBuildIndexes = publishingBuildIndexes.filter((index) => index < evidenceIndex);
        if (precedingPublishingBuildIndexes.length === 0) {
          const nativePromotionIndex = steps.findIndex((candidate, index) =>
            index < evidenceIndex &&
            evidenceEngineIds.length === 1 && evidenceEngineIds[0] === "greenbone" &&
            candidate?.id === "publish" &&
            candidate?.shell === "bash" &&
            typeof candidate?.run === "string" &&
            candidate.run.includes("docker buildx imagetools create") &&
            candidate.run.includes('native-evidence/amd64/native-digest.json') &&
            candidate.run.includes('native-evidence/arm64/native-digest.json') &&
            candidate.run.includes('printf \'digest=%s\\n\' "${index_digest}" >> "${GITHUB_OUTPUT}"'));
          if (nativePromotionIndex < 0) {
            errors.push(`${label}: evidence action must follow a docker/build-push-action publication or the exact Greenbone native-manifest promotion step`);
          } else if (evidenceStep?.with?.digest !== "${{ needs.guard.outputs.digest || steps.publish.outputs.digest }}") {
            errors.push(`${label}: Greenbone evidence digest must select only a verified reuse or the candidate index output`);
          }
        } else {
          const expectedDigestInputs = precedingPublishingBuildIndexes
            .map((index) => steps[index]?.id)
            .filter((id) => typeof id === "string" && id.length > 0)
            .flatMap((id) => [
              `\${{ steps.${id}.outputs.digest }}`,
              `\${{ steps.guard.outputs.digest || steps.${id}.outputs.digest }}`,
            ]);
          if (relative === localK8sWorkflowRelative && jobId === "publish" &&
              steps.some((step, index) => index < evidenceIndex && step.id === "semgrep_image")) {
            expectedDigestInputs.push(LOCAL_IMAGE_DIGEST);
          }
          if (!expectedDigestInputs.includes(evidenceStep?.with?.digest)) {
            errors.push(`${label}: digest must reference a preceding publication step output`);
          }
        }

        const promotionIndex = steps.findIndex((candidate, index) =>
          index > evidenceIndex && candidate?.uses === "./.github/actions/engine-image-evidence/promote");
        if (promotionIndex < 0) {
          errors.push(`${label}: immutable version promotion must follow signed evidence`);
        } else {
          const promotion = steps[promotionIndex];
          if (promotion?.with?.image !== evidenceStep?.with?.image ||
              promotion?.with?.tag !== evidenceStep?.with?.tag ||
              promotion?.with?.digest !== evidenceStep?.with?.digest ||
              promotion?.with?.["source-revision"] !== evidenceStep?.with?.["source-revision"] ||
              promotion?.with?.["github-token"] !== evidenceStep?.with?.["github-token"]) {
            errors.push(`${label}: promotion must bind the same image, tag, digest, revision, and token as evidence`);
          }
          const anonymousVersionCheck = steps.slice(promotionIndex + 1).find((candidate) =>
            typeof candidate?.run === "string" && candidate.run.includes("docker logout ghcr.io") &&
            candidate.run.includes('imagetools inspect "${IMAGE}:${IMAGE_TAG}"'));
          if (!anonymousVersionCheck) {
            errors.push(`${label}: promoted version tag must be anonymously re-resolved to its exact digest`);
          }
        }

        const evidenceUpload = steps.slice(evidenceIndex + 1).find((step) =>
          typeof step?.uses === "string" && step.uses.startsWith("actions/upload-artifact@") &&
          step?.with?.path === "package-evidence" && step?.with?.["retention-days"] === 90 &&
          !Object.hasOwn(step, "if"));
        if (!evidenceUpload) {
          errors.push(`${label}: signed package-evidence must be uploaded after attestation with retention-days: 90`);
        } else {
          const matrixEngine = /^\$\{\{\s*matrix\.engine\s*\}\}$/.test(evidenceStep?.with?.engine ?? "");
          const artifactSuffix = "-image-evidence-${{ github.run_id }}-${{ github.run_attempt }}";
          const expectedArtifactName = matrixEngine
            ? "${{ matrix.engine }}" + artifactSuffix
            : `${evidenceEngineIds[0] ?? "__missing_engine__"}${artifactSuffix}`;
          if (evidenceUpload.with.name !== expectedArtifactName || evidenceUpload.with["if-no-files-found"] !== "error") {
            errors.push(`${label}: evidence upload must use ${expectedArtifactName} and fail when evidence is absent`);
          }
        }
      }
    }
    if (evidenceStepCount === 0) errors.push(`${relative}: workflow does not invoke the common evidence action`);
    if (workflowIds.length !== new Set(workflowIds).size) {
      errors.push(`${relative}: common evidence action covers an engine more than once`);
    }
    for (const engineId of workflowIds) {
      if (!catalogManagedIdSet.has(engineId)) {
        errors.push(`${relative}: ${engineId} publication has no matching project-managed catalog entry`);
      }
    }
    coveredIds.push(...workflowIds);
  }

  if (coveredIds.length !== new Set(coveredIds).size) {
    errors.push("managed image evidence workflows cover an engine more than once");
  }
  validateExactIdSet(
    catalogManagedIds,
    coveredIds,
    "catalog project-managed GHCR images differ from signed workflow coverage",
  );
  return { coveredIds, workflowCount: managedEvidenceWorkflows.length };
}

function jsonType(value) {
  if (value === null) return "null";
  if (Array.isArray(value)) return "array";
  if (Number.isInteger(value)) return "integer";
  return typeof value === "number" ? "number" : typeof value;
}

function deepEqual(left, right) {
  return JSON.stringify(left) === JSON.stringify(right);
}

function resolveReference(rootSchema, reference) {
  if (!reference.startsWith("#/")) return null;
  return reference.slice(2).split("/").reduce((value, token) => {
    const key = token.replaceAll("~1", "/").replaceAll("~0", "~");
    return value?.[key];
  }, rootSchema);
}

function validateSchemaValue(value, rule, path, rootSchema, targetErrors) {
  if (rule.$ref) {
    const resolved = resolveReference(rootSchema, rule.$ref);
    if (!resolved) {
      targetErrors.push(`${path}: schema has unresolved reference ${rule.$ref}`);
      return;
    }
    validateSchemaValue(value, resolved, path, rootSchema, targetErrors);
    return;
  }
  if (rule.anyOf) {
    const matched = rule.anyOf.some((candidate) => {
      const candidateErrors = [];
      validateSchemaValue(value, candidate, path, rootSchema, candidateErrors);
      return candidateErrors.length === 0;
    });
    if (!matched) targetErrors.push(`${path}: does not match any allowed schema`);
    return;
  }
  if (rule.const !== undefined && !deepEqual(value, rule.const)) {
    targetErrors.push(`${path}: expected constant ${JSON.stringify(rule.const)}`);
  }
  if (rule.enum && !rule.enum.some((candidate) => deepEqual(value, candidate))) {
    targetErrors.push(`${path}: value ${JSON.stringify(value)} is not in the allowed enum`);
  }
  if (rule.type) {
    const allowedTypes = Array.isArray(rule.type) ? rule.type : [rule.type];
    if (!allowedTypes.includes(jsonType(value))) {
      targetErrors.push(`${path}: expected ${allowedTypes.join(" or ")}, got ${jsonType(value)}`);
      return;
    }
  }
  if (typeof value === "string") {
    if (rule.minLength !== undefined && value.length < rule.minLength) targetErrors.push(`${path}: string is too short`);
    if (rule.maxLength !== undefined && value.length > rule.maxLength) targetErrors.push(`${path}: string is too long`);
    if (rule.pattern && !new RegExp(rule.pattern).test(value)) targetErrors.push(`${path}: does not match ${rule.pattern}`);
    if (rule.format === "date" && !isIsoDate(value)) targetErrors.push(`${path}: is not a real ISO calendar date`);
  }
  if (typeof value === "number") {
    if (rule.minimum !== undefined && value < rule.minimum) targetErrors.push(`${path}: is below minimum ${rule.minimum}`);
    if (rule.maximum !== undefined && value > rule.maximum) targetErrors.push(`${path}: exceeds maximum ${rule.maximum}`);
  }
  if (Array.isArray(value)) {
    if (rule.minItems !== undefined && value.length < rule.minItems) targetErrors.push(`${path}: has fewer than ${rule.minItems} items`);
    if (rule.maxItems !== undefined && value.length > rule.maxItems) targetErrors.push(`${path}: has more than ${rule.maxItems} items`);
    if (rule.uniqueItems) {
      const serialized = value.map((item) => JSON.stringify(item));
      if (new Set(serialized).size !== serialized.length) targetErrors.push(`${path}: contains duplicate items`);
    }
    if (rule.items) value.forEach((item, index) => validateSchemaValue(item, rule.items, `${path}[${index}]`, rootSchema, targetErrors));
  }
  if (value !== null && typeof value === "object" && !Array.isArray(value)) {
    for (const required of rule.required ?? []) {
      if (!Object.hasOwn(value, required)) targetErrors.push(`${path}: missing required property ${required}`);
    }
    if (rule.additionalProperties === false) {
      const known = new Set(Object.keys(rule.properties ?? {}));
      for (const key of Object.keys(value)) if (!known.has(key)) targetErrors.push(`${path}: unknown property ${key}`);
    }
    for (const [key, childRule] of Object.entries(rule.properties ?? {})) {
      if (Object.hasOwn(value, key)) validateSchemaValue(value[key], childRule, `${path}.${key}`, rootSchema, targetErrors);
    }
  }
}

function validateStaticArgv(command, path) {
  if (!Array.isArray(command) || command.length === 0) return;
  const program = typeof command[0] === "string" ? basename(command[0]).toLowerCase() : "";
  if (shellNames.has(program)) errors.push(`${path}: may not invoke shell ${program}`);
  for (const token of command) {
    if (typeof token !== "string") continue;
    const lower = token.toLowerCase();
    if (shellNames.has(basename(lower))) errors.push(`${path}: shell token ${token} is forbidden`);
    if (token.includes("\0") || token.includes("${") || token.includes("$(") || token.includes("{{") || token.includes("`")) {
      errors.push(`${path}: dynamic or unsafe token ${JSON.stringify(token)}`);
    }
    if ([";", "&&", "||", "|", ">", ">>", "<"].includes(token)) errors.push(`${path}: shell operator ${token} is forbidden`);
  }
}

function validateStaticCommand(engine) {
  validateStaticArgv(engine.command, `catalog:${engine.id}.command`);
  for (const [index, contract] of (engine.input_contracts ?? []).entries()) {
    if (contract?.command !== undefined) {
      validateStaticArgv(contract.command, `catalog:${engine.id}.input_contracts[${index}].command`);
    }
  }
}

function validateTag(tag, path) {
  if (typeof tag !== "string" || tag.length === 0) {
    errors.push(`${path}: exact tag is required`);
    return;
  }
  const normalized = tag.toLowerCase();
  if (floatingTags.has(normalized) || [...floatingTags].some((value) => normalized === `${value}-latest`)) {
    errors.push(`${path}: floating tag ${tag} is forbidden`);
  }
  if (/[${}]/.test(tag)) errors.push(`${path}: templated tag ${tag} is forbidden`);
  if (!/^(?:v?\d+(?:\.\d+){1,3}(?:[-.][0-9A-Za-z]+)*|[0-9a-f]{40})$/.test(tag)) {
    errors.push(`${path}: tag ${tag} is not an exact version or commit tag`);
  }
}

function validateImage(image, path, {
  allowDigestPinnedAlias = false,
  allowFloatingDigestPinnedAlias = false,
} = {}) {
  if (!image || typeof image !== "object") {
    errors.push(`${path}: image object is required`);
    return;
  }
  if (typeof image.repository !== "string" || image.repository.includes("@") || /\s/.test(image.repository)) {
    errors.push(`${path}.repository: invalid repository`);
  }
  if (image.signature_identity || image.repository?.split("/").at(-1)?.startsWith("ai-security-scanner-engine-")) {
    try {
      const origin = publicationOrigin(image.repository);
      if (image.signature_identity && !image.signature_identity.startsWith(`https://github.com/${origin.repository}/.github/workflows/`)) {
        errors.push(`${path}: mixed publication origin`);
      }
    } catch { errors.push(`${path}: unrecognized publication origin`); }
  }
  const normalizedTag = typeof image.tag === "string" ? image.tag.toLowerCase() : "";
  if (allowFloatingDigestPinnedAlias && image.tag && !/[${}]/.test(image.tag)) {
    // Greenbone's community registry keeps only rolling tags. The recorded
    // rolling tag is provenance only; the mandatory digest remains the build
    // identity and every Dockerfile FROM uses that digest directly.
  } else if (allowDigestPinnedAlias && image.tag && !floatingTags.has(normalizedTag) && !/[${}]/.test(image.tag)) {
    // A human-readable distro codename remains immutable because the digest
    // below is mandatory; latest/nightly/template aliases stay forbidden.
  } else {
    validateTag(image.tag, `${path}.tag`);
  }
  if (!digestPattern.test(image.digest ?? "")) errors.push(`${path}.digest: immutable sha256 digest is required`);
}

function walkFiles(path) {
  if (!existsSync(path)) return [];
  const files = [];
  for (const entry of readdirSync(path, { withFileTypes: true })) {
    const child = resolve(path, entry.name);
    if (entry.isDirectory()) files.push(...walkFiles(child));
    else if (entry.isFile()) files.push(child);
  }
  return files;
}

function sha256File(path) {
  return `sha256:${createHash("sha256").update(readFileSync(path)).digest("hex")}`;
}

function validatePatchAudit(plan, planRelative, engine) {
  const audited = new Set(["gitleaks", "greenbone", "prowler", "scoutsuite", "mcp-armor", "httpx"]);
  if (!audited.has(engine.id)) return;
  const audit = plan.build_recipe?.patch_audit;
  const required = ["capability", "contribution_reason", "removal_condition"];
  if (!audit || audit.applicable_source_revision !== plan.source?.revision ||
      audit.applicable_upstream_version !== engine.engine_version ||
      !/^\d{4}-\d{2}-\d{2}$/.test(audit.reviewed_on ?? "") ||
      !/^\d{4}-\d{2}-\d{2}$/.test(audit.review_due ?? "") ||
      audit.review_due <= audit.reviewed_on || audit.contribution_status !== "not_submitted" ||
      required.some((field) => typeof audit[field] !== "string" || audit[field].trim().length === 0) ||
      ["security_owner", "license_owner", "maintenance_owner"].some((field) => audit[field] !== plan.maintenance_owner) ||
      !Array.isArray(audit.dedicated_fixtures) || audit.dedicated_fixtures.length === 0 ||
      !Array.isArray(audit.patches) || audit.patches.length === 0) {
    errors.push(`${planRelative}: downstream patch audit must bind capability, pinned applicability, contribution reason, owners, fixtures and removal/review dates`);
    return;
  }
  for (const patch of audit.patches) {
    const safePath = typeof patch.path === "string" && !patch.path.startsWith("/") && !patch.path.split("/").includes("..");
    if (!safePath || !existsSync(resolve(root, patch.path)) ||
        patch.sha256 !== sha256File(resolve(root, patch.path)) ||
        !Array.isArray(patch.files) || patch.files.length === 0 ||
        patch.files.some((file) =>
          typeof file.path !== "string" || file.path.startsWith("/") || file.path.split("/").includes("..") ||
          ![file.before_sha256, file.after_sha256].every((hash) => hash === null || digestPattern.test(hash ?? "")) ||
          file.before_sha256 === null && file.after_sha256 === null)) {
      errors.push(`${planRelative}: patch audit must bind an actual patch file and its reviewed source pre/post hashes`);
    }
  }
}

function isManagedPublicationClaimed(engine, plan, expectedRepository) {
  return engine.compatibility?.runnable === true ||
    engine.status === "integrated" ||
    engine.image?.repository === expectedRepository ||
    plan.publish_state === "published_managed_artifact" ||
    plan.dockerfile?.emitted === true ||
    plan.publication !== null && plan.publication !== undefined;
}

function validatePublishedManagedEvidence(
  plan,
  planRelative,
  engine,
  { requireManagedSmoke = false } = {},
) {
  const publication = plan.publication;
  const runId = publicationRunId(plan.final_artifact?.repository, publication?.workflow_run);
  const runMatch = runId ? [publication.workflow_run, runId] : null;
  if (!runMatch) {
    errors.push(`${planRelative}: publication.workflow_run must identify one exact ai-security-scanner Actions run`);
  }
  if (!deepEqual(publication?.platforms, ["linux/amd64", "linux/arm64"]) ||
      !deepEqual(sortedUnique(Object.keys(publication?.platform_digests ?? {})), ["linux/amd64", "linux/arm64"]) ||
      !Object.values(publication?.platform_digests ?? {}).every((digest) => digestPattern.test(digest))) {
    errors.push(`${planRelative}: publication must contain the exact amd64 and arm64 platform digests`);
  }
  if (publication?.anonymous_pull_verified !== true) {
    errors.push(`${planRelative}: publication must prove anonymous access to the immutable multi-platform index`);
  }
  // The publication revision identifies the exact source tree used to build
  // the immutable engine image. The desktop adapter can advance independently
  // while continuing to consume that same pinned image, so coupling these two
  // revisions would force a false image-republication claim on every adapter
  // hardening release.
  if (!revisionPattern.test(publication?.source_revision ?? "")) {
    errors.push(`${planRelative}: publication must record an exact 40-character build source revision`);
  }
  const artifactMatch = typeof publication?.evidence_artifact === "string"
    ? new RegExp(`^${engine.id}-image-evidence-([1-9][0-9]*)-([1-9][0-9]*)$`).exec(publication.evidence_artifact)
    : null;
  if (!artifactMatch || !runMatch || artifactMatch[1] !== runMatch[1]) {
    errors.push(`${planRelative}: evidence artifact must be ${engine.id}-image-evidence-<workflow-run-id>-<positive-attempt> for the same run`);
  }
  const hasManagedSmokeEvidence = publication !== null &&
    typeof publication === "object" &&
    Object.hasOwn(publication, "managed_smoke_evidence_sha256");
  if (requireManagedSmoke && !digestPattern.test(publication?.managed_smoke_evidence_sha256 ?? "")) {
    errors.push(`${planRelative}: publication must bind the managed smoke evidence by sha256`);
  } else if (hasManagedSmokeEvidence && !digestPattern.test(publication.managed_smoke_evidence_sha256 ?? "")) {
    errors.push(`${planRelative}: publication managed smoke evidence must be sha256 when present`);
  }
}

function validatePublishedManagedDockerfile(plan, planRelative, engine, expectedTag, entrypoint) {
  const dockerfileRelative = `engines/images/${engine.id}/Dockerfile`;
  const dockerfilePath = resolve(root, dockerfileRelative);
  if (plan.dockerfile?.emitted !== true || plan.dockerfile?.path !== dockerfileRelative || plan.dockerfile?.reason !== null) {
    errors.push(`${planRelative}: published managed image must emit ${dockerfileRelative} with a null absence reason`);
    return null;
  }
  if (!existsSync(dockerfilePath)) {
    errors.push(`${planRelative}: published managed Dockerfile is missing`);
    return null;
  }
  const dockerfileText = readFileSync(dockerfilePath, "utf8");
  const actualDockerfileSha256 = sha256File(dockerfilePath);
  if (plan.dockerfile.sha256 !== actualDockerfileSha256) {
    errors.push(`${planRelative}: Dockerfile digest ${plan.dockerfile.sha256 ?? "missing"} does not match ${actualDockerfileSha256}`);
  }
  if (!/^# syntax=docker\/dockerfile:[^\s]+@sha256:[0-9a-f]{64}$/m.test(dockerfileText.split(/\r?\n/, 1)[0])) {
    errors.push(`${planRelative}: published managed Dockerfile frontend must be digest-pinned`);
  }
  if (!dockerfileText.split(/\r?\n/).some((line) => line.trim() === "USER 65532:65532")) {
    errors.push(`${planRelative}: published managed Dockerfile must select USER 65532:65532`);
  }
  if (!dockerfileText.split(/\r?\n/).some((line) => line.trim() === `ENTRYPOINT ${JSON.stringify([entrypoint])}`)) {
    errors.push(`${planRelative}: published managed Dockerfile must use the direct project-owned entrypoint`);
  }
  if (!dockerfileText.includes(`org.opencontainers.image.version="${expectedTag}"`)) {
    errors.push(`${planRelative}: Dockerfile OCI version label must equal the released tag ${expectedTag}`);
  }
  return dockerfileText;
}

function normalizedImageDigestReference(reference) {
  const digestSeparator = typeof reference === "string" ? reference.lastIndexOf("@") : -1;
  if (digestSeparator < 1) return reference;
  const nameAndTag = reference.slice(0, digestSeparator);
  const lastSlash = nameAndTag.lastIndexOf("/");
  const tagSeparator = nameAndTag.lastIndexOf(":");
  const repository = tagSeparator > lastSlash ? nameAndTag.slice(0, tagSeparator) : nameAndTag;
  return `${repository}${reference.slice(digestSeparator)}`;
}

function externalDockerfileDigestReferences(dockerfileText) {
  const stageAliases = new Set();
  const references = [];
  for (const line of dockerfileText.split(/\r?\n/)) {
    const match = line.trim().match(/^FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?$/i);
    if (!match) continue;
    const reference = match[1];
    if (reference !== "scratch" && !stageAliases.has(reference.toLowerCase())) {
      references.push(normalizedImageDigestReference(reference));
    }
    if (match[2]) stageAliases.add(match[2].toLowerCase());
  }
  return sortedUnique(references);
}

function validateExactDeclaredBaseImages(recipe, dockerfileText, planRelative, {
  allowFloatingDigestPinnedAliases = false,
} = {}) {
  if (!Array.isArray(recipe?.base_images) || recipe.base_images.length === 0) {
    errors.push(`${planRelative}: source build must enumerate every digest-pinned external base image`);
    return;
  }
  const declaredReferences = [];
  for (const [index, image] of recipe.base_images.entries()) {
    validateImage(image, `${planRelative}.build_recipe.base_images[${index}]`, {
      allowDigestPinnedAlias: true,
      allowFloatingDigestPinnedAlias: allowFloatingDigestPinnedAliases &&
        image.repository.startsWith("registry.community.greenbone.net/community/"),
    });
    const digestReference = `${image.repository}@${image.digest}`;
    declaredReferences.push(digestReference);
    if (!dockerfileText.includes(image.digest ?? "__missing_digest__")) {
      errors.push(`${planRelative}: declared base image digest ${digestReference} is unused`);
    }
  }
  const actualReferences = externalDockerfileDigestReferences(dockerfileText);
  if (!deepEqual(sortedUnique(declaredReferences), actualReferences)) {
    errors.push(`${planRelative}: declared base images must exactly equal Dockerfile external FROM digest closure`);
  }
}

function validatePublishedManagedBasics(plan, planRelative, engine, contract, command, network) {
  const expectedRepository = managedRepository(engine, plan);
  if (plan.plan_kind !== contract.planKind) {
    errors.push(`${planRelative}: published ${engine.id} plan kind must be ${contract.planKind}`);
  }
  if (plan.publish_state !== "published_managed_artifact") {
    errors.push(`${planRelative}: published ${engine.id} image must use publish_state published_managed_artifact`);
  }
  if (engine.distribution_mode !== "pull_pinned_image" ||
      engine.image?.repository !== expectedRepository ||
      engine.image?.tag !== contract.tag ||
      !digestPattern.test(engine.image?.digest ?? "")) {
    errors.push(`catalog:${engine.id}: released image must be ${expectedRepository}:${contract.tag} at an immutable digest`);
  }
  if (plan.final_artifact?.repository !== expectedRepository ||
      plan.final_artifact?.tag !== contract.tag ||
      plan.final_artifact?.digest !== engine.image?.digest) {
    errors.push(`${planRelative}: final artifact must be the exact released catalog image`);
  }
  if (engine.status !== "integrated" || engine.compatibility?.runnable !== true ||
      !deepEqual(engine.compatibility?.blocked_by, []) || !deepEqual(plan.blockers, [])) {
    errors.push(`${planRelative}: published engine must be integrated, runnable, and blocker-free in catalog and plan`);
  }
  if (engine.license?.disposition !== contract.license.disposition ||
      engine.license?.source_offer_path !== contract.license.sourceOfferPath) {
    errors.push(`catalog:${engine.id}.license: published disposition/source offer does not match the fixed release contract`);
  }
  if (contract.license.sourceOfferPath !== null && !existsSync(resolve(root, contract.license.sourceOfferPath))) {
    errors.push(`catalog:${engine.id}.license: required source offer ${contract.license.sourceOfferPath} is missing`);
  }
  if (!deepEqual(engine.command, command) || !deepEqual(plan.command, command)) {
    errors.push(`${planRelative}: published engine command must equal the fixed non-shell launcher argv`);
  }
  if (contract.outputFormats !== undefined && !deepEqual(engine.output_formats, contract.outputFormats)) {
    errors.push(`catalog:${engine.id}.output_formats: released formats do not match the fixed managed-image contract`);
  }
  if (contract.ruleVersion !== undefined &&
      (engine.rule_version !== contract.ruleVersion || engine.provenance?.rules?.revision !== contract.ruleVersion)) {
    errors.push(`catalog:${engine.id}.rule_version: embedded rules do not match the fixed managed-image contract`);
  }
  if (engine.execution?.network?.required !== network.required ||
      engine.execution?.network?.mode !== network.mode ||
      !deepEqual(engine.execution?.network?.destinations, network.destinations) ||
      !deepEqual(engine.network_destinations, network.destinations)) {
    errors.push(`catalog:${engine.id}.execution.network: released network contract is not exact`);
  }

  const entrypoint = contract.entrypoint ?? "/usr/local/bin/ai-security-scanner-engine-entrypoint";
  const runtime = plan.managed_runtime;
  if (runtime?.non_root_user !== "65532:65532" || runtime?.read_only_rootfs !== true ||
      !deepEqual(runtime?.entrypoint, [entrypoint]) || runtime?.network_mode !== network.mode ||
      !deepEqual(runtime?.network_destinations, network.destinations)) {
    errors.push(`${planRelative}: managed runtime must preserve the non-root, read-only, direct-entrypoint network contract`);
  }
  const launcherRelative = contract.launcherPath ?? (engine.id === "greenbone"
    ? "engines/images/greenbone-launcher/main.go"
    : "engines/images/local-launcher/main.go");
  const launcherPath = resolve(root, launcherRelative);
  if (engine.compatibility?.wrapper?.required !== true || engine.compatibility?.wrapper?.entrypoint !== entrypoint ||
      plan.wrapper?.required !== true || plan.wrapper?.entrypoint !== entrypoint ||
      plan.wrapper?.launcher_sha256 !== sha256File(launcherPath)) {
    errors.push(`${planRelative}: wrapper must bind the exact project-owned launcher source and entrypoint`);
  }
  if (contract.immutableLauncherInputs !== undefined) {
    const launcherText = existsSync(launcherPath) ? readFileSync(launcherPath, "utf8") : "";
    for (const required of contract.immutableLauncherInputs) {
      if (!launcherText.includes(required)) {
        errors.push(`${planRelative}: launcher lacks immutable release input ${required}`);
      }
    }
  }

  validatePublishedManagedEvidence(plan, planRelative, engine, { requireManagedSmoke: true });
  return validatePublishedManagedDockerfile(plan, planRelative, engine, contract.buildTag ?? contract.tag, entrypoint);
}

function validatePublishedLocalK8sImage(plan, planRelative, engine, contract) {
  const command = contract.command ?? ["--engine", engine.id, "--workspace", "/workspace", "--output", "/output"];
  const dockerfileText = validatePublishedManagedBasics(plan, planRelative, engine, contract, command, {
    required: false,
    mode: "disabled",
    destinations: [],
  });
  if (dockerfileText === null) return;

  const recipe = plan.build_recipe;
  if (recipe?.source_revision !== engine.source_revision ||
      !deepEqual(recipe?.target_platforms, ["linux/amd64", "linux/arm64"]) ||
      !Number.isInteger(recipe?.source_date_epoch) || recipe.source_date_epoch < 1) {
    errors.push(`${planRelative}: local/Kubernetes source build must lock its source, epoch, and publication platforms`);
  }
  const sourceArchive = recipe?.source_archive;
  const sourceArchivePosition = typeof sourceArchive?.url === "string" ? dockerfileText.indexOf(sourceArchive.url) : -1;
  const sourceArchivePrefix = sourceArchivePosition >= 0
    ? dockerfileText.slice(Math.max(0, sourceArchivePosition - 180), sourceArchivePosition)
    : "";
  if (!sourceArchive?.url?.startsWith("https://github.com/") || !sourceArchive.url.includes(engine.source_revision) ||
      !digestPattern.test(sourceArchive?.sha256 ?? "") || sourceArchivePosition < 0 ||
      !sourceArchivePrefix.includes(`ADD --checksum=${sourceArchive.sha256}`)) {
    errors.push(`${planRelative}: source archive must be an exact checksum-pinned GitHub artifact for the catalog revision`);
  }
  if (contract.sourceArchiveSha256 !== undefined && sourceArchive?.sha256 !== contract.sourceArchiveSha256) {
    errors.push(`${planRelative}: source archive digest does not match the fixed ${engine.id} release contract`);
  }
  if (contract.sourceDateEpoch !== undefined && recipe?.source_date_epoch !== contract.sourceDateEpoch) {
    errors.push(`${planRelative}: SOURCE_DATE_EPOCH does not match the fixed ${engine.id} release contract`);
  }
  if (contract.sourceIntegrity !== undefined && !deepEqual(recipe?.source_integrity, contract.sourceIntegrity)) {
    errors.push(`${planRelative}: reviewed upstream file digests do not match the fixed ${engine.id} release contract`);
  }
  if (contract.sourcePatch !== undefined) {
    const patchPath = resolve(root, contract.sourcePatch.path);
    if (!deepEqual(recipe?.source_patch, contract.sourcePatch) || !existsSync(patchPath) ||
        sha256File(patchPath) !== contract.sourcePatch.sha256) {
      errors.push(`${planRelative}: source patch path and digest do not match the reviewed ${engine.id} patch`);
    }
  }
  if (engine.id === "gitleaks") {
    for (const [field, path] of [
      ["module", "engines/images/gitleaks/launcher/go.mod"],
      ["patch_notice", "engines/images/gitleaks/PATCHES.md"],
    ]) {
      if (!deepEqual(plan.wrapper?.[field], { path, sha256: sha256File(resolve(root, path)) })) {
        errors.push(`${planRelative}: wrapper.${field} must bind the actual build input ${path}`);
      }
    }
  }
  const frontend = recipe?.dockerfile_frontend;
  validateImage(frontend, `${planRelative}.build_recipe.dockerfile_frontend`);
  if (dockerfileText.split(/\r?\n/)[0] !== `# syntax=${frontend?.repository}:${frontend?.tag}@${frontend?.digest}`) {
    errors.push(`${planRelative}: source build frontend must match the exact Dockerfile frontend`);
  }
  validateExactDeclaredBaseImages(recipe, dockerfileText, planRelative);
  const launcherDockerfileCopy = contract.launcherDockerfileCopy ??
    "COPY engines/images/local-launcher/go.mod engines/images/local-launcher/main.go engines/images/local-launcher/main_test.go ./";
  if (!dockerfileText.includes(launcherDockerfileCopy) ||
      !dockerfileText.includes("-buildvcs=false -trimpath") ||
      !dockerfileText.includes(engine.source_revision)) {
    errors.push(`${planRelative}: Dockerfile is not closed over the reviewed launcher and engine source revision`);
  }
  for (const required of contract.immutableDockerfileInputs) {
    if (!dockerfileText.includes(required)) errors.push(`${planRelative}: Dockerfile lacks immutable release input ${required}`);
  }
}

function validateGreenboneBuildClosure(plan, planRelative, dockerfileText) {
  const runtime = plan.managed_runtime;
  if (runtime?.proxy !== "AI_SECURITY_SCANNER_PROXY" || runtime?.updates !== false || runtime?.telemetry !== false ||
      runtime?.per_grant_target_execution !== true) {
    errors.push(`${planRelative}: Greenbone runtime must require the managed proxy, disable updates/telemetry, and isolate each grant`);
  }
  const recipe = plan.build_recipe;
  if (recipe?.source_revision !== managedGreenboneContract.scannerRevision ||
      !deepEqual(recipe?.target_platforms, ["linux/amd64", "linux/arm64"]) ||
      !Number.isInteger(recipe?.source_date_epoch) || recipe.source_date_epoch < 1) {
    errors.push(`${planRelative}: Greenbone build must lock the scanner revision, epoch, and publication platforms`);
  }
  const sourceArchive = recipe?.source_archive;
  if (sourceArchive?.url !== managedGreenboneContract.scannerArchiveUrl ||
      sourceArchive?.sha256 !== managedGreenboneContract.scannerArchiveSha256) {
    errors.push(`${planRelative}: Greenbone scanner source archive does not match the exact release closure`);
  }
  if (plan.source?.revision !== managedGreenboneContract.scannerRevision ||
      plan.source?.acquisition_source !== `https://github.com/greenbone/openvas-scanner/commit/${managedGreenboneContract.scannerRevision}`) {
    errors.push(`${planRelative}: Greenbone source provenance does not match the reviewed scanner revision`);
  }
  const frontend = recipe?.dockerfile_frontend;
  validateImage(frontend, `${planRelative}.build_recipe.dockerfile_frontend`);
  if (dockerfileText.split(/\r?\n/)[0] !== `# syntax=${frontend?.repository}:${frontend?.tag}@${frontend?.digest}`) {
    errors.push(`${planRelative}: Greenbone Dockerfile frontend does not match its immutable build recipe`);
  }
  validateExactDeclaredBaseImages(recipe, dockerfileText, planRelative, {
    allowFloatingDigestPinnedAliases: true,
  });
  const greenboneBaseTags = new Map((recipe?.base_images ?? []).map(({ repository, tag }) => [repository, tag]));
  for (const [repository, tag] of [
    ["registry.community.greenbone.net/community/vulnerability-tests", "community"],
    ["registry.community.greenbone.net/community/notus-data", "community"],
  ]) {
    if (greenboneBaseTags.get(repository) !== tag) {
      errors.push(`${planRelative}: Greenbone base image ${repository} must record the rolling ${tag} tag resolved for this digest`);
    }
  }
  // The community registry deletes superseded digests; Greenbone's GHCR package
  // keeps each scanner release tag at the same digest.
  if (greenboneBaseTags.get("ghcr.io/greenbone/openvas-scanner") !== managedGreenboneContract.engineVersion) {
    errors.push(`${planRelative}: Greenbone runtime base must be the ghcr.io/greenbone/openvas-scanner ${managedGreenboneContract.engineVersion} release`);
  }

  const requiredDockerfileInputs = [
    `ADD --checksum=${managedGreenboneContract.scannerArchiveSha256}`,
    managedGreenboneContract.scannerArchiveUrl,
    'org.opencontainers.image.source="https://github.com/greenbone/openvas-scanner"',
    'org.opencontainers.image.licenses="GPL-2.0-only AND ODbL-1.0 AND Apache-2.0"',
    `community/vulnerability-tests@${managedGreenboneContract.feedImageDigest}`,
    `community/notus-data@${managedGreenboneContract.notusImageDigest}`,
    `io.ai-security-scanner.openvas-revision="${managedGreenboneContract.scannerRevision}"`,
    `io.ai-security-scanner.openvas-source-sha256="${managedGreenboneContract.scannerArchiveSha256}"`,
    `io.ai-security-scanner.feed-revision="${managedGreenboneContract.feedRevision}"`,
    `io.ai-security-scanner.feed-version="${managedGreenboneContract.feedVersion}"`,
    `io.ai-security-scanner.feed-image-digest="${managedGreenboneContract.feedImageDigest}"`,
    `io.ai-security-scanner.notus-revision="${managedGreenboneContract.notusRevision}"`,
    `io.ai-security-scanner.notus-image-digest="${managedGreenboneContract.notusImageDigest}"`,
    "/var/lib/openvas/24.10/vt-data/nasl/sha256sums.asc",
    "/prepared/advisories/sha256sums.asc",
    "COPY --chmod=0444 engines/images/greenbone/SOURCE-OFFER.md /usr/share/source/greenbone/SOURCE-OFFER.md",
    "COPY --chmod=0444 engines/images/greenbone/THIRD-PARTY-NOTICES.md /usr/share/licenses/greenbone/THIRD-PARTY-NOTICES.md",
    "setcap -r /usr/bin/nmap",
    "rm -f /usr/bin/nmap /usr/local/sbin/openvas",
  ];
  for (const required of requiredDockerfileInputs) {
    if (!dockerfileText.includes(required)) errors.push(`${planRelative}: Greenbone Dockerfile lacks immutable component closure ${required}`);
  }
  for (const [name, relative] of [
    ["rustls-provider", "engines/images/greenbone/openvasd-rustls-provider.patch"],
    ["service-port", "engines/images/greenbone/openvasd-service-port.patch"],
    ["http-compat", "engines/images/greenbone/openvasd-http-compat.patch"],
    ["nasl-array-compat", "engines/images/greenbone/openvasd-nasl-array-compat.patch"],
    ["eregmatch-captures", "engines/images/greenbone/openvasd-eregmatch-captures.patch"],
    ["report-port", "engines/images/greenbone/openvasd-report-port.patch"],
    ["socket-eof", "engines/images/greenbone/openvasd-socket-eof.patch"],
  ]) {
    const patchPath = resolve(root, relative);
    const patchDigest = existsSync(patchPath) ? sha256File(patchPath).slice("sha256:".length) : null;
    if (!patchDigest || !dockerfileText.includes(`${name}:${patchDigest}`) || !dockerfileText.includes(`COPY ${relative}`)) {
      errors.push(`${planRelative}: Greenbone patch ${relative} is absent or its actual digest is not recorded in the image`);
    }
  }

  const launcherPath = resolve(root, "engines/images/greenbone-launcher/main.go");
  const launcherText = readFileSync(launcherPath, "utf8");
  for (const required of [
    `feedRevision             = "${managedGreenboneContract.feedRevision}"`,
    'managedProxy(os.Getenv("AI_SECURITY_SCANNER_PROXY"))',
    'managedGatewayPort       = "1080"',
    "byRelayPort",
    "byOriginalPort",
  ]) {
    if (!launcherText.includes(required)) errors.push(`${planRelative}: Greenbone launcher lacks proxy/feed boundary ${required}`);
  }

  const smokeRelative = "engines/images/greenbone/managed-socks-smoke.sh";
  const smokePath = resolve(root, smokeRelative);
  const smokeText = existsSync(smokePath) ? readFileSync(smokePath, "utf8") : "";
  for (const required of [
    `selected_oid="${managedGreenboneContract.smokeOid}"`,
    "internal-only bridge unexpectedly allowed direct target egress",
    "managed SOCKS gateway unexpectedly allowed an unapproved target port",
    "authorized vulnerable fixture produced no alarm",
    "actionable_alarms=",
    "CARGO_HOME=/tmp/cargo-home",
    "CARGO_TARGET_DIR=/tmp/cargo-target",
    "dst=/workspace,readonly",
  ]) {
    if (!smokeText.includes(required)) errors.push(`${planRelative}: Greenbone real-alarm smoke contract lacks ${required}`);
  }
  const workflowPath = resolve(root, ".github/workflows/engine-image-greenbone.yml");
  const workflowText = existsSync(workflowPath) ? readFileSync(workflowPath, "utf8") : "";
  for (const required of [
    "!engines/images/greenbone/plan.json",
    smokeRelative,
    "managedSmokeEvidenceSha256",
    "nativeImageIdentityMatchesFinal: $native_identity_matches",
    "reusedSignedIndex: ($native_identity_matches | not)",
    "Push the exact smoke-tested native image",
    "Assemble the exact smoke-tested native candidate index",
    "engine-image-evidence/publication-guard",
    "engine-image-evidence/promote",
    ".publishedImage.digest",
    ".publishedImage.digest == $final_digest",
    ".imageIdentity.id == $registry.config.digest",
    ".imageIdentity.rootFsDiffIds == $image.RootFS.Layers",
    "docker buildx imagetools create",
    "(.manifests | length == 2)",
    "platformDigests:",
    "greenbone-image-manifest.json",
    `selectedOid: "${managedGreenboneContract.smokeOid}"`,
    "actionableAlarms: 1",
    "adapterFindings: 1",
    "directEgressDenied: true",
    "unauthorizedPortDenied: true",
    "docker logout ghcr.io",
    `IMAGE_TAG: ${managedGreenboneContract.tag}`,
  ]) {
    if (!workflowText.includes(required)) errors.push(`${planRelative}: Greenbone workflow does not preserve ${required}`);
  }
  if ((workflowText.match(/managed-socks-smoke\.sh/g) ?? []).length < 2) {
    errors.push(`${planRelative}: Greenbone workflow must real-smoke both native inputs and the final anonymously pulled index`);
  }
}

function isPendingGreenbonePublication(plan, engine) {
  const expectedRepository = managedRepository(engine, plan);
  return engine?.id === "greenbone" && plan?.publish_state === "publication_in_progress" &&
    plan.publication === null && deepEqual(plan.blockers, [greenbonePublicationBlocker]) &&
    plan.final_artifact?.repository === expectedRepository &&
    plan.final_artifact?.tag === managedGreenboneContract.tag && plan.final_artifact?.digest === null &&
    engine.distribution_mode === "pull_pinned_image" && engine.image?.repository === expectedRepository &&
    engine.image?.tag === managedGreenboneContract.tag && digestPattern.test(engine.image?.digest ?? "") &&
    engine.engine_version === managedGreenboneContract.engineVersion &&
    engine.source_revision === managedGreenboneContract.scannerRevision &&
    engine.rule_version === managedGreenboneContract.feedRevision &&
    engine.status === "integrated" && engine.compatibility?.runnable === true &&
    deepEqual(engine.compatibility?.blocked_by, []);
}

function validatePublishedGreenboneImage(plan, planRelative, engine) {
  const command = ["--engine", "greenbone", "--scope", "/run/ai-security-scanner/scope.json", "--output", "/output"];
  const dockerfileText = validatePublishedManagedBasics(plan, planRelative, engine, managedGreenboneContract, command, {
    required: true,
    mode: "managed_allowlist",
    destinations: ["authorized target addresses"],
  });
  if (dockerfileText === null) return;

  if (engine.engine_version !== managedGreenboneContract.engineVersion ||
      engine.source_revision !== managedGreenboneContract.scannerRevision ||
      engine.provenance?.engine?.artifact_source_revision !== managedGreenboneContract.scannerRevision ||
      engine.rule_version !== managedGreenboneContract.feedRevision ||
      engine.provenance?.rules?.mode !== "embedded" ||
      engine.provenance?.rules?.revision !== managedGreenboneContract.feedRevision ||
      engine.provenance?.data?.mode !== "embedded" ||
      engine.provenance?.data?.revision !== managedGreenboneContract.feedRevision ||
      engine.compatibility?.knowledge_input?.kind !== "embedded" ||
      engine.compatibility?.knowledge_input?.version !== managedGreenboneContract.feedVersion ||
      engine.compatibility?.knowledge_input?.pin_state !== "pinned_or_not_applicable") {
    errors.push(`catalog:greenbone: scanner and Community Feed provenance must match the immutable release closure`);
  }
  validateGreenboneBuildClosure(plan, planRelative, dockerfileText);
}

function validatePendingGreenboneImage(plan, planRelative, engine) {
  if (!isPendingGreenbonePublication(plan, engine)) {
    errors.push(`${planRelative}: Greenbone refresh must retain the currently published catalog image while the exact replacement awaits publication`);
    return;
  }
  const command = ["--engine", "greenbone", "--scope", "/run/ai-security-scanner/scope.json", "--output", "/output"];
  const entrypoint = "/usr/local/bin/ai-security-scanner-engine-entrypoint";
  if (plan.plan_kind !== managedGreenboneContract.planKind || !deepEqual(plan.command, command) ||
      engine.license?.disposition !== managedGreenboneContract.license.disposition ||
      engine.license?.source_offer_path !== managedGreenboneContract.license.sourceOfferPath) {
    errors.push(`${planRelative}: pending Greenbone build does not match its reviewed plan, command, or source-offer contract`);
  }
  const dockerfileText = validatePublishedManagedDockerfile(
    plan,
    planRelative,
    engine,
    managedGreenboneContract.tag,
    entrypoint,
  );
  const launcherPath = resolve(root, "engines/images/greenbone-launcher/main.go");
  if (plan.wrapper?.required !== true || plan.wrapper?.entrypoint !== entrypoint ||
      plan.wrapper?.launcher_sha256 !== sha256File(launcherPath) ||
      engine.compatibility?.wrapper?.entrypoint !== entrypoint) {
    errors.push(`${planRelative}: pending Greenbone wrapper must bind the exact project-owned launcher source and entrypoint`);
  }
  if (dockerfileText !== null) validateGreenboneBuildClosure(plan, planRelative, dockerfileText);
}

function validateCloudManagedImage(plan, planRelative, engine) {
  if (engine.image) {
    if (plan.publish_state !== "published_managed_artifact") {
      errors.push(`${planRelative}: runnable cloud image must be marked as a published managed artifact`);
    }
    validatePublishedManagedEvidence(plan, planRelative, engine);
  } else if (plan.publication !== undefined) {
    errors.push(`${planRelative}: unpublished cloud image must not claim publication evidence`);
  }

  const expectedPath = `engines/images/${engine.id}/Dockerfile`;
  const dockerfile = plan.dockerfile;
  if (dockerfile?.emitted !== true || dockerfile?.path !== expectedPath) {
    errors.push(`${planRelative}: managed cloud image must emit ${expectedPath}`);
    return;
  }
  const dockerfilePath = resolve(root, expectedPath);
  if (!existsSync(dockerfilePath)) {
    errors.push(`${planRelative}: managed cloud Dockerfile is missing`);
    return;
  }
  const dockerfileText = readFileSync(dockerfilePath, "utf8");
  const actualDockerfileSha256 = sha256File(dockerfilePath);
  if (dockerfile.sha256 !== actualDockerfileSha256) {
    errors.push(`${planRelative}: Dockerfile digest ${dockerfile.sha256 ?? "missing"} does not match ${actualDockerfileSha256}`);
  }
  if (!/^# syntax=[^\s]+@sha256:[0-9a-f]{64}$/m.test(dockerfileText.split(/\r?\n/, 1)[0])) {
    errors.push(`${planRelative}: managed cloud Dockerfile frontend must be digest-pinned`);
  }

  const launcherPath = resolve(root, "engines/images/cloud-launcher/main.go");
  const expectedLauncherSha256 = sha256File(launcherPath);
  if (plan.wrapper?.entrypoint !== "/usr/local/bin/ai-security-scanner-cloud-launcher") {
    errors.push(`${planRelative}: managed cloud wrapper must use the scanner-owned launcher`);
  }
  if (plan.wrapper?.launcher_sha256 !== expectedLauncherSha256) {
    errors.push(`${planRelative}: launcher digest ${plan.wrapper?.launcher_sha256 ?? "missing"} does not match ${expectedLauncherSha256}`);
  }
  if (!dockerfileText.includes(`ENTRYPOINT ${JSON.stringify([plan.wrapper?.entrypoint])}`)) {
    errors.push(`${planRelative}: managed cloud Dockerfile does not set its declared direct entrypoint`);
  }

  const expectedCommand = [
    "--engine", engine.id,
    "--scope", "/run/ai-security-scanner/scope.json",
    "--output", "/output",
  ];
  if (!deepEqual(plan.command, expectedCommand)) {
    errors.push(`${planRelative}: managed cloud command must use the fixed scope and output mounts`);
  }

  const runtime = plan.managed_runtime;
  if (!runtime || typeof runtime !== "object") {
    errors.push(`${planRelative}: managed cloud image requires a runtime contract`);
    return;
  }
  if (!/^[1-9][0-9]*:[1-9][0-9]*$/.test(runtime.non_root_user ?? "")) {
    errors.push(`${planRelative}: managed cloud runtime must declare a numeric non-root uid:gid`);
  } else if (!dockerfileText.split(/\r?\n/).some((line) => line.trim() === `USER ${runtime.non_root_user}`)) {
    errors.push(`${planRelative}: managed cloud Dockerfile does not set its declared non-root user`);
  }
  if (runtime.read_only_rootfs !== true) errors.push(`${planRelative}: managed cloud runtime must require a read-only root filesystem`);
  if (runtime.network_mode !== "managed_allowlist" || engine.execution?.network?.mode !== "managed_allowlist") {
    errors.push(`${planRelative}: managed cloud runtime must use the managed network allowlist`);
  }
  if (!deepEqual(runtime.network_destinations, engine.execution?.network?.destinations)) {
    errors.push(`${planRelative}: managed cloud endpoint closure does not match the catalog`);
  }
  if (runtime.updates !== false || runtime.telemetry !== false) {
    errors.push(`${planRelative}: managed cloud runtime must disable updates and telemetry`);
  }
  for (const destination of runtime.network_destinations ?? []) {
    if (!/^[a-z0-9.-]+:443$/.test(destination)) {
      errors.push(`${planRelative}: managed cloud destination must be an exact lowercase fqdn:443 (${destination})`);
    }
  }

  if (plan.plan_kind === "managed_rebase") {
    validateImage(plan.verified_upstream_artifact, `${planRelative}.verified_upstream_artifact`);
    const expectedBase = `${plan.verified_upstream_artifact?.repository}@${plan.verified_upstream_artifact?.digest}`;
    if (!dockerfileText.split(/\r?\n/).some((line) => line.trim() === `FROM ${expectedBase}`)) {
      errors.push(`${planRelative}: managed cloud rebase does not use its verified upstream artifact`);
    }
    return;
  }

  const recipe = plan.build_recipe;
  if (!recipe || typeof recipe !== "object") {
    errors.push(`${planRelative}: managed cloud source image requires a build recipe`);
    return;
  }
  if (recipe.source_revision !== engine.source_revision) {
    errors.push(`${planRelative}: managed cloud source recipe must match the catalog source revision`);
  }
  const sourceArchive = recipe.source_archive;
  if (!sourceArchive?.url?.startsWith("https://") || !sourceArchive.url.includes(engine.source_revision) || !digestPattern.test(sourceArchive?.sha256 ?? "")) {
    errors.push(`${planRelative}: managed cloud source archive must have an immutable URL and digest`);
  } else if (!dockerfileText.includes(`ADD --checksum=${sourceArchive.sha256}`) || !dockerfileText.includes(sourceArchive.url)) {
    errors.push(`${planRelative}: managed cloud Dockerfile does not acquire its checksum-pinned source archive`);
  }
  if (!deepEqual(recipe.target_platforms, ["linux/amd64", "linux/arm64"])) {
    errors.push(`${planRelative}: managed cloud source image must target amd64 and arm64`);
  }
  if (!Number.isInteger(recipe.source_date_epoch) || recipe.source_date_epoch < 1) {
    errors.push(`${planRelative}: managed cloud source image requires a positive SOURCE_DATE_EPOCH`);
  }
  for (const [index, image] of (recipe.base_images ?? []).entries()) {
    validateImage(image, `${planRelative}.build_recipe.base_images[${index}]`, { allowDigestPinnedAlias: true });
    const reference = `${image.repository}:${image.tag}@${image.digest}`;
    if (!dockerfileText.includes(reference)) errors.push(`${planRelative}: declared cloud build image ${reference} is unused`);
  }
  if (recipe.dependency_lock && !digestPattern.test(recipe.dependency_lock.sha256 ?? "")) {
    errors.push(`${planRelative}: managed cloud dependency lock requires an immutable digest`);
  }
  if (recipe.source_patch) {
    const patchPath = resolve(root, recipe.source_patch.path ?? "__missing_patch__");
    if (!existsSync(patchPath) || sha256File(patchPath) !== recipe.source_patch.sha256) {
      errors.push(`${planRelative}: managed cloud source patch is missing or does not match its digest`);
    }
  }
  if (engine.id === "steampipe") {
    for (const required of [
      'amd64) database_port=19193',
      'arm64) database_port=19194',
      'ai-security-scanner-build.spc',
      'rm -f "${STEAMPIPE_INSTALL_DIR}/config/ai-security-scanner-build.spc"',
    ]) {
      if (!dockerfileText.includes(required)) {
        errors.push(`${planRelative}: Steampipe multi-platform seed must preserve isolated build ports and remove its build-only config`);
      }
    }
    for (const [label, value] of [
      ["AWS plugin archive", recipe.aws_plugin?.archive_sha256],
      ["embedded database OCI artifact", recipe.embedded_database?.oci_digest],
      ["PostgreSQL FDW archive", recipe.postgres_fdw?.archive_sha256],
      ["PostgreSQL FDW OCI artifact", recipe.postgres_fdw?.oci_digest],
    ]) {
      if (!digestPattern.test(value ?? "") || !dockerfileText.includes(value)) {
        errors.push(`${planRelative}: ${label} digest is missing from the build closure`);
      }
    }
    for (const revision of [recipe.aws_plugin?.revision, recipe.postgres_fdw?.revision]) {
      if (!revisionPattern.test(revision ?? "") || !dockerfileText.includes(revision)) {
        errors.push(`${planRelative}: Steampipe component revision is missing from the build closure`);
      }
    }
  }
}

function validateCloudQueryPlan(plan, planRelative, engine) {
  const expectedPlugins = [
    {
      name: "cloudquery-source-aws",
      version: "9.2.0",
      release_ref: "plugins-source-aws-v9.2.0",
      source_revision: "804be3a90d6f15d3e6c662c0eb7afa88a9596180",
      path: "/usr/local/libexec/cloudquery-source-aws",
      registry: "local",
    },
    {
      name: "cloudquery-destination-file",
      version: "1.0.4",
      release_ref: "plugins-destination-file-v1.0.4",
      source_revision: "600ffdd2707af566e3c99469d84a34d94730aaa1",
      path: "/usr/local/libexec/cloudquery-destination-file",
      registry: "local",
    },
  ];
  if (!deepEqual(plan.provider_plugins, expectedPlugins)) {
    errors.push(`${planRelative}: CloudQuery provider plugins must retain the exact local public-release closure`);
  }
  const providerLock = plan.provider_lock;
  const lockPath = resolve(root, providerLock?.path ?? "__missing_cloudquery_lock__");
  if (!existsSync(lockPath) || !digestPattern.test(providerLock?.sha256 ?? "") || sha256File(lockPath) !== providerLock.sha256) {
    errors.push(`${planRelative}: CloudQuery provider lock is missing or does not match its digest`);
    return;
  }
  if (providerLock?.install_result !== "anonymous_public_release_artifacts" || providerLock?.source_closure !== "complete" || providerLock?.registry !== "local") {
    errors.push(`${planRelative}: CloudQuery provider lock must declare the complete anonymous local closure`);
  }
  const configurationLock = plan.configuration_lock;
  const configurationPath = resolve(root, configurationLock?.path ?? "__missing_cloudquery_configuration__");
  if (!existsSync(configurationPath) || !digestPattern.test(configurationLock?.sha256 ?? "") || sha256File(configurationPath) !== configurationLock.sha256) {
    errors.push(`${planRelative}: CloudQuery fixed local-plugin configuration is missing or does not match its digest`);
    return;
  }

  const lock = parseJson(lockPath);
  if (!lock) return;
  const expectedTables = [
    "aws_iam_accounts",
    "aws_iam_credential_reports",
    "aws_iam_groups",
    "aws_iam_password_policies",
    "aws_iam_policies",
    "aws_iam_roles",
    "aws_iam_users",
  ];
  const expectedDestinations = [
    "ec2.us-east-1.amazonaws.com:443",
    "iam.amazonaws.com:443",
    "sts.us-east-1.amazonaws.com:443",
  ];
  const expectedAwsActions = [
    "ec2:DescribeRegions",
    "iam:GenerateCredentialReport",
    "iam:GetAccessKeyLastUsed",
    "iam:GetAccountAuthorizationDetails",
    "iam:GetAccountPasswordPolicy",
    "iam:GetAccountSummary",
    "iam:GetCredentialReport",
    "iam:GetGroupPolicy",
    "iam:GetRole",
    "iam:GetRolePolicy",
    "iam:GetUser",
    "iam:GetUserPolicy",
    "iam:ListAccessKeys",
    "iam:ListAccountAliases",
    "iam:ListAttachedGroupPolicies",
    "iam:ListAttachedRolePolicies",
    "iam:ListAttachedUserPolicies",
    "iam:ListGroupPolicies",
    "iam:ListGroups",
    "iam:ListGroupsForUser",
    "iam:ListPolicyTags",
    "iam:ListRolePolicies",
    "iam:ListRoles",
    "iam:ListSSHPublicKeys",
    "iam:ListUserPolicies",
    "iam:ListUsers",
    "sts:GetCallerIdentity",
  ];
  if (lock.schema_version !== "1.0.0" || lock.profile !== "aws-iam-us-east-1" || lock.knowledge_date !== "2023-01-10" ||
      lock.source_repository !== "https://github.com/cloudquery/cloudquery" ||
      !deepEqual(lock.registry, { mode: "local", authenticated: false, runtime_downloads: false })) {
    errors.push(`${providerLock.path}: CloudQuery lock identity or anonymous local registry policy changed`);
  }
  if (!deepEqual(lock.tables, expectedTables)) errors.push(`${providerLock.path}: CloudQuery table allowlist changed`);
  if (!deepEqual(lock.network_destinations, expectedDestinations) || !deepEqual(engine.network_destinations, expectedDestinations)) {
    errors.push(`${providerLock.path}: CloudQuery exact AWS endpoint closure changed`);
  }
  if (!deepEqual(lock.required_aws_actions, expectedAwsActions)) errors.push(`${providerLock.path}: CloudQuery exact AWS read action closure changed`);
  if (!deepEqual(lock.output, { directory: "/output", format: "ndjson-per-table", file_suffix: ".json" })) {
    errors.push(`${providerLock.path}: CloudQuery per-table NDJSON output contract changed`);
  }

  const expectedComponents = new Map([
    ["cloudquery-cli", { version: "2.0.31", release_ref: "cli-v2.0.31", source_revision: "e27e4ab61ad85479a5d53dae9b08440bc63e72b3" }],
    ["cloudquery-source-aws", { version: "9.2.0", release_ref: "plugins-source-aws-v9.2.0", source_revision: "804be3a90d6f15d3e6c662c0eb7afa88a9596180" }],
    ["cloudquery-destination-file", { version: "1.0.4", release_ref: "plugins-destination-file-v1.0.4", source_revision: "600ffdd2707af566e3c99469d84a34d94730aaa1" }],
  ]);
  if (!Array.isArray(lock.components) || lock.components.length !== expectedComponents.size) {
    errors.push(`${providerLock.path}: CloudQuery lock must contain exactly three components`);
  }
  const dockerfilePath = resolve(root, "engines/images/cloudquery/Dockerfile");
  const dockerfileText = existsSync(dockerfilePath) ? readFileSync(dockerfilePath, "utf8") : "";
  for (const component of lock.components ?? []) {
    const expected = expectedComponents.get(component.name);
    if (!expected || component.version !== expected.version || component.release_ref !== expected.release_ref || component.source_revision !== expected.source_revision) {
      errors.push(`${providerLock.path}: CloudQuery component identity changed (${component.name ?? "missing"})`);
      continue;
    }
    const sourceArchive = component.source_archive;
    if (!sourceArchive?.url?.includes(component.source_revision) || !digestPattern.test(sourceArchive?.sha256 ?? "") ||
        !dockerfileText.includes(sourceArchive.url) || !dockerfileText.includes(`ADD --checksum=${sourceArchive.sha256}`)) {
      errors.push(`${providerLock.path}: ${component.name} source archive is not checksum-closed by the Dockerfile`);
    }
    if (!deepEqual(Object.keys(component.artifacts ?? {}), ["linux/amd64", "linux/arm64"])) {
      errors.push(`${providerLock.path}: ${component.name} must lock amd64 and arm64 release artifacts`);
      continue;
    }
    for (const [platform, artifact] of Object.entries(component.artifacts)) {
      const checksums = [artifact.sha256, artifact.archive_sha256, artifact.binary_sha256].filter(Boolean);
      if (!artifact.url?.startsWith("https://github.com/cloudquery/cloudquery/releases/download/") ||
          checksums.length === 0 || checksums.some((digest) => !digestPattern.test(digest)) ||
          !dockerfileText.includes(artifact.url) || checksums.some((digest) => !dockerfileText.includes(digest.slice("sha256:".length)))) {
        errors.push(`${providerLock.path}: ${component.name} ${platform} artifact is not fully checksum-closed by the Dockerfile`);
      }
    }
  }

  const pluginsText = readFileSync(configurationPath, "utf8");
  const launcherPath = resolve(root, "engines/images/cloud-launcher/main.go");
  const launcherText = readFileSync(launcherPath, "utf8");
  const generatedConfiguration = launcherText.match(/func cloudQueryConfiguration\(\) \[\]byte \{\s*return \[\]byte\(`([\s\S]*?)`\)\s*\}/)?.[1];
  if (generatedConfiguration === undefined || generatedConfiguration !== pluginsText) {
    errors.push(`${planRelative}: scanner launcher and reviewed CloudQuery configuration lock differ`);
  }
  const authenticatedRegistry = /(?:hub\.cloudquery\.io|registry:\s*(?:cloudquery|grpc|github)|path:\s*cloudquery\/(?:aws|file)|"authenticated"\s*:\s*true)/i;
  for (const [path, text] of [[configurationLock.path, pluginsText], ["engines/images/cloud-launcher/main.go", launcherText], ["engines/images/cloudquery/Dockerfile", dockerfileText]]) {
    if (authenticatedRegistry.test(text)) errors.push(`${path}: authenticated or remote CloudQuery plugin registry is forbidden`);
  }
  if (!deepEqual(plan.blockers, []) || !engine.compatibility?.runnable || engine.status !== "integrated" || plan.knowledge_date !== "2023-01-10") {
    errors.push(`${planRelative}: CloudQuery must be runnable, integrated, blocker-free, and disclose its 2023-01-10 knowledge date`);
  }
}

function validateManagedRebase(plan, planRelative, engine) {
  if (plan.publish_state !== "published_managed_artifact") {
    errors.push(`${planRelative}: managed rebase must be a published managed artifact`);
  }
  validatePublishedManagedEvidence(plan, planRelative, engine);

  if (!plan.verified_upstream_artifact) {
    errors.push(`${planRelative}: managed rebase requires an immutable verified upstream artifact`);
  }
  if (plan.build_recipe !== null) {
    errors.push(`${planRelative}: managed rebase must not compile or download additional build inputs`);
  }
  const dockerfile = plan.dockerfile;
  const expectedPath = `engines/images/${engine.id}/Dockerfile`;
  if (dockerfile?.emitted !== true || dockerfile?.path !== expectedPath) {
    errors.push(`${planRelative}: managed rebase must emit ${expectedPath}`);
    return;
  }
  const dockerfilePath = resolve(root, expectedPath);
  if (!existsSync(dockerfilePath)) {
    errors.push(`${planRelative}: managed rebase Dockerfile is missing`);
    return;
  }
  const actualSha256 = sha256File(dockerfilePath);
  if (dockerfile.sha256 !== actualSha256) {
    errors.push(`${planRelative}: Dockerfile digest ${dockerfile.sha256 ?? "missing"} does not match ${actualSha256}`);
  }
  if (dockerfile.reason !== null) {
    errors.push(`${planRelative}: emitted managed Dockerfile must have a null absence reason`);
  }
  const dockerfileText = readFileSync(dockerfilePath, "utf8");
  const expectedBase = `${plan.verified_upstream_artifact?.repository}@${plan.verified_upstream_artifact?.digest}`;
  if (!dockerfileText.split(/\r?\n/).some((line) => line.trim() === `FROM ${expectedBase}`)) {
    errors.push(`${planRelative}: managed Dockerfile base does not match the verified upstream artifact`);
  }

  const runtime = plan.managed_runtime;
  if (!runtime || typeof runtime !== "object") {
    errors.push(`${planRelative}: managed rebase requires a runtime contract`);
    return;
  }
  if (!/^[1-9][0-9]*:[1-9][0-9]*$/.test(runtime.non_root_user ?? "")) {
    errors.push(`${planRelative}: managed runtime must declare a numeric non-root uid:gid`);
  } else if (!dockerfileText.split(/\r?\n/).some((line) => line.trim() === `USER ${runtime.non_root_user}`)) {
    errors.push(`${planRelative}: managed Dockerfile does not set its declared non-root user`);
  }
  if (!Array.isArray(runtime.entrypoint) || runtime.entrypoint.length !== 1 || shellNames.has(basename(runtime.entrypoint[0] ?? "").toLowerCase())) {
    errors.push(`${planRelative}: managed runtime requires one direct non-shell entrypoint`);
  } else if (!dockerfileText.split(/\r?\n/).some((line) => line.trim() === `ENTRYPOINT ${JSON.stringify(runtime.entrypoint)}`)) {
    errors.push(`${planRelative}: managed Dockerfile does not set its declared direct entrypoint`);
  }
  if (runtime.network_mode !== "disabled" || engine.execution?.network?.mode !== "disabled") {
    errors.push(`${planRelative}: managed offline runtime must disable networking`);
  }
  if (typeof runtime.cache_path !== "string" || !runtime.cache_path.startsWith("/tmp/") || runtime.cache_path.includes("..")) {
    errors.push(`${planRelative}: managed runtime cache must be bounded by the /tmp tmpfs`);
  }
  const environment = runtime.environment;
  if (!environment || Object.values(environment).some((value) => typeof value !== "string" || value.length === 0)) {
    errors.push(`${planRelative}: managed runtime environment must be a non-empty static string map`);
  } else {
    for (const [key, value] of Object.entries(environment)) {
      if (!/^[A-Z][A-Z0-9_]*$/.test(key) || !dockerfileText.includes(`${key}="${value}"`)) {
        errors.push(`${planRelative}: managed Dockerfile is missing declared environment ${key}`);
      }
    }
  }
  if (engine.id === "syft" && environment?.SYFT_CHECK_FOR_APP_UPDATE !== "false") {
    errors.push(`${planRelative}: managed Syft runtime must disable its update check`);
  }
}

function validateManagedSourceImage(plan, planRelative, engine) {
  if (plan.publish_state !== "published_managed_artifact") {
    errors.push(`${planRelative}: managed source image must be a published managed artifact`);
  }
  validatePublishedManagedEvidence(plan, planRelative, engine);

  const recipe = plan.build_recipe;
  if (!recipe || typeof recipe !== "object") {
    errors.push(`${planRelative}: managed source image requires a build recipe`);
    return;
  }
  if (recipe.source_revision !== engine.source_revision) {
    errors.push(`${planRelative}: managed source image recipe must use the catalog source revision`);
  }

  const sourceArchive = recipe.source_archive;
  if (!sourceArchive || typeof sourceArchive.url !== "string" || !sourceArchive.url.startsWith("https://") || !sourceArchive.url.includes(engine.source_revision)) {
    errors.push(`${planRelative}: managed source archive URL must embed the exact source revision`);
  }
  if (!digestPattern.test(sourceArchive?.sha256 ?? "")) {
    errors.push(`${planRelative}: managed source archive requires an immutable sha256 digest`);
  }

  const dependencyLock = recipe.dependency_lock;
  if (dependencyLock?.path !== "Pipfile.lock" || !digestPattern.test(dependencyLock?.sha256 ?? "")) {
    errors.push(`${planRelative}: managed Python source image requires the exact Pipfile.lock digest`);
  }
  if (!Number.isInteger(dependencyLock?.records) || dependencyLock.records < 1) {
    errors.push(`${planRelative}: managed Python source image must declare its runtime lock record count`);
  }
  if (!digestPattern.test(dependencyLock?.rendered_requirements_sha256 ?? "")) {
    errors.push(`${planRelative}: managed Python source image must pin its rendered requirements digest`);
  }
  if (dependencyLock?.require_hashes !== true || dependencyLock?.only_binary !== true) {
    errors.push(`${planRelative}: managed Python dependencies must require hashes and binary distributions`);
  }

  const preparer = recipe.source_preparer;
  const expectedPreparer = `engines/images/${engine.id}/prepare_source.py`;
  if (preparer?.path !== expectedPreparer || !digestPattern.test(preparer?.sha256 ?? "")) {
    errors.push(`${planRelative}: managed source image requires a pinned ${expectedPreparer}`);
  } else {
    const preparerPath = resolve(root, expectedPreparer);
    if (!existsSync(preparerPath)) {
      errors.push(`${planRelative}: managed source preparer is missing`);
    } else {
      const actualPreparerSha256 = sha256File(preparerPath);
      if (preparer.sha256 !== actualPreparerSha256) {
        errors.push(`${planRelative}: source preparer digest ${preparer.sha256} does not match ${actualPreparerSha256}`);
      }
      const preparerText = readFileSync(preparerPath, "utf8");
      for (const expected of [
        engine.source_revision,
        sourceArchive?.sha256?.slice("sha256:".length),
        dependencyLock?.sha256?.slice("sha256:".length),
        `EXPECTED_DEPENDENCIES = ${dependencyLock?.records}`,
      ]) {
        if (expected && !preparerText.includes(expected)) errors.push(`${planRelative}: source preparer is missing locked value ${expected}`);
      }
    }
  }

  if (!Number.isInteger(recipe.source_date_epoch) || recipe.source_date_epoch < 1) {
    errors.push(`${planRelative}: managed source image requires a positive SOURCE_DATE_EPOCH`);
  }
  if (!deepEqual(recipe.target_platforms, ["linux/amd64", "linux/arm64"])) {
    errors.push(`${planRelative}: managed source image must declare its exact publication platforms`);
  }
  if (!Array.isArray(recipe.base_images) || recipe.base_images.length === 0) {
    errors.push(`${planRelative}: managed source image requires at least one digest-pinned base image`);
  }
  const frontend = recipe.dockerfile_frontend;
  validateImage(frontend, `${planRelative}.build_recipe.dockerfile_frontend`);

  const expectedDockerignore = `engines/images/${engine.id}/.dockerignore`;
  const buildContext = recipe.build_context;
  if (buildContext?.dockerignore_path !== expectedDockerignore || !digestPattern.test(buildContext?.dockerignore_sha256 ?? "")) {
    errors.push(`${planRelative}: managed source image requires a pinned minimal .dockerignore`);
  } else {
    const dockerignorePath = resolve(root, expectedDockerignore);
    if (!existsSync(dockerignorePath)) {
      errors.push(`${planRelative}: managed source image .dockerignore is missing`);
    } else if (sha256File(dockerignorePath) !== buildContext.dockerignore_sha256) {
      errors.push(`${planRelative}: managed source image .dockerignore digest does not match its plan`);
    }
  }

  const dockerfile = plan.dockerfile;
  const expectedPath = `engines/images/${engine.id}/Dockerfile`;
  if (dockerfile?.emitted !== true || dockerfile?.path !== expectedPath) {
    errors.push(`${planRelative}: managed source image must emit ${expectedPath}`);
    return;
  }
  const dockerfilePath = resolve(root, expectedPath);
  if (!existsSync(dockerfilePath)) {
    errors.push(`${planRelative}: managed source Dockerfile is missing`);
    return;
  }
  const actualDockerfileSha256 = sha256File(dockerfilePath);
  if (dockerfile.sha256 !== actualDockerfileSha256) {
    errors.push(`${planRelative}: Dockerfile digest ${dockerfile.sha256 ?? "missing"} does not match ${actualDockerfileSha256}`);
  }
  if (dockerfile.reason !== null) {
    errors.push(`${planRelative}: emitted managed Dockerfile must have a null absence reason`);
  }
  const dockerfileText = readFileSync(dockerfilePath, "utf8");
  const expectedFrontend = `# syntax=${frontend?.repository}:${frontend?.tag}@${frontend?.digest}`;
  if (dockerfileText.split(/\r?\n/)[0] !== expectedFrontend) {
    errors.push(`${planRelative}: managed Dockerfile frontend is not digest-pinned to its build recipe`);
  }
  const declaredBases = new Set((recipe.base_images ?? []).map((image) => `${image.repository}:${image.tag}@${image.digest}`));
  const actualBases = [...dockerfileText.matchAll(/^\s*FROM\s+([^\s]+)(?:\s+AS\s+[^\s]+)?\s*$/gmi)].map((match) => match[1]);
  if (actualBases.length === 0 || actualBases.some((reference) => !declaredBases.has(reference))) {
    errors.push(`${planRelative}: managed Dockerfile FROM instructions must match declared base images`);
  }
  for (const reference of declaredBases) {
    if (!actualBases.includes(reference)) errors.push(`${planRelative}: declared base image ${reference} is unused`);
  }
  if (!dockerfileText.includes(`ADD --checksum=${sourceArchive?.sha256 ?? ""}`) || !dockerfileText.includes(sourceArchive?.url ?? "")) {
    errors.push(`${planRelative}: managed Dockerfile does not acquire the checksum-pinned source archive`);
  }
  if (!dockerfileText.includes("--require-hashes") || !dockerfileText.includes("--only-binary=:all:")) {
    errors.push(`${planRelative}: managed Dockerfile does not enforce the hashed binary dependency lock`);
  }
  if (!dockerfileText.includes(`ARG SOURCE_DATE_EPOCH=${recipe.source_date_epoch}`)) {
    errors.push(`${planRelative}: managed Dockerfile does not fix SOURCE_DATE_EPOCH`);
  }
  if (!dockerfileText.includes(`COPY ${expectedPreparer.split("/").at(-1)} `)) {
    errors.push(`${planRelative}: managed Dockerfile does not copy the pinned source preparer`);
  }
  if (!dockerfileText.includes(dependencyLock?.sha256?.slice("sha256:".length) ?? "__missing_lock_digest__")) {
    errors.push(`${planRelative}: managed Dockerfile does not record the dependency lock digest`);
  }

  const runtime = plan.managed_runtime;
  if (!runtime || typeof runtime !== "object") {
    errors.push(`${planRelative}: managed source image requires a runtime contract`);
    return;
  }
  if (!/^[1-9][0-9]*:[1-9][0-9]*$/.test(runtime.non_root_user ?? "")) {
    errors.push(`${planRelative}: managed runtime must declare a numeric non-root uid:gid`);
  } else if (!dockerfileText.split(/\r?\n/).some((line) => line.trim() === `USER ${runtime.non_root_user}`)) {
    errors.push(`${planRelative}: managed Dockerfile does not set its declared non-root user`);
  }
  if (!Array.isArray(runtime.entrypoint) || runtime.entrypoint.length !== 1 || shellNames.has(basename(runtime.entrypoint[0] ?? "").toLowerCase())) {
    errors.push(`${planRelative}: managed runtime requires one direct non-shell entrypoint`);
  } else if (!dockerfileText.split(/\r?\n/).some((line) => line.trim() === `ENTRYPOINT ${JSON.stringify(runtime.entrypoint)}`)) {
    errors.push(`${planRelative}: managed Dockerfile does not set its declared direct entrypoint`);
  }
  if (runtime.network_mode !== "disabled" || engine.execution?.network?.mode !== "disabled") {
    errors.push(`${planRelative}: managed offline runtime must disable networking`);
  }
  if (typeof runtime.cache_path !== "string" || !runtime.cache_path.startsWith("/tmp/") || runtime.cache_path.includes("..")) {
    errors.push(`${planRelative}: managed runtime cache must be bounded by the /tmp tmpfs`);
  }
  const environment = runtime.environment;
  if (!environment || Object.values(environment).some((value) => typeof value !== "string" || value.length === 0)) {
    errors.push(`${planRelative}: managed runtime environment must be a non-empty static string map`);
  } else {
    for (const [key, value] of Object.entries(environment)) {
      if (!/^[A-Z][A-Z0-9_]*$/.test(key) || !dockerfileText.includes(`${key}="${value}"`)) {
        errors.push(`${planRelative}: managed Dockerfile is missing declared environment ${key}`);
      }
    }
  }
  if (engine.id === "checkov") {
    const requiredEnvironment = {
      BC_ENABLE_PERSIST_GRAPHS: "false",
      CKV_BITBUCKET_CONFIG_FETCH_DATA: "false",
      CKV_GITHUB_CONFIG_FETCH_DATA: "false",
      CKV_GITLAB_CONFIG_FETCH_DATA: "false",
      CKV_SKIP_PACKAGE_UPDATE_CHECK: "true",
      XDG_CACHE_HOME: runtime.cache_path,
    };
    for (const [key, value] of Object.entries(requiredEnvironment)) {
      if (environment?.[key] !== value) errors.push(`${planRelative}: managed Checkov runtime requires ${key}=${value}`);
    }
    const frameworkIndex = engine.command.indexOf("--framework");
    if (!engine.command.includes("--skip-download") || frameworkIndex < 0 || engine.command[frameworkIndex + 1] !== "all") {
      errors.push(`${planRelative}: managed Checkov runtime must retain fixed offline upstream framework auto-detection`);
    }
    if (engine.command.includes("--compact")) {
      errors.push(`${planRelative}: managed Checkov JSON output must retain upstream evidence code blocks`);
    }
  }
}

function validateUnpublishedManagedBuild(
  plan,
  planRelative,
  engine,
  { publishState = "managed_artifact_not_published", artifactTag = null } = {},
) {
  if (plan.publish_state !== publishState || engine.compatibility?.runnable !== false) {
    errors.push(`${planRelative}: unpublished managed build must remain explicitly non-runnable`);
  }
  if (plan.final_artifact?.tag !== artifactTag || plan.final_artifact?.digest !== null) {
    errors.push(`${planRelative}: unpublished managed build must retain only its reviewed candidate tag and a null digest`);
  }
  const dockerfileRelative = `engines/images/${engine.id}/Dockerfile`;
  const dockerfilePath = resolve(root, dockerfileRelative);
  if (plan.dockerfile?.path !== dockerfileRelative || plan.dockerfile?.reason !== null || !existsSync(dockerfilePath)) {
    errors.push(`${planRelative}: locally verified build must retain its emitted Dockerfile`);
    return;
  }
  const dockerfileText = readFileSync(dockerfilePath, "utf8");
  if (plan.dockerfile.sha256 !== sha256File(dockerfilePath)) {
    errors.push(`${planRelative}: locally verified Dockerfile digest does not match`);
  }
  const recipe = plan.build_recipe;
  const frontend = recipe?.dockerfile_frontend;
  validateImage(frontend, `${planRelative}.build_recipe.dockerfile_frontend`);
  if (dockerfileText.split(/\r?\n/)[0] !== `# syntax=${frontend?.repository}:${frontend?.tag}@${frontend?.digest}`) {
    errors.push(`${planRelative}: locally verified Dockerfile frontend is not digest-pinned`);
  }
  const sourceArchive = recipe?.source_archive;
  if (recipe?.source_revision !== engine.source_revision ||
      !digestPattern.test(sourceArchive?.sha256 ?? "") ||
      !dockerfileText.includes(`ADD --checksum=${sourceArchive?.sha256 ?? ""}`) ||
      !dockerfileText.includes(sourceArchive?.url ?? "")) {
    errors.push(`${planRelative}: locally verified build does not retain its pinned source archive`);
  }
  const patch = recipe?.source_patch;
  if (!digestPattern.test(patch?.sha256 ?? "") || !existsSync(resolve(root, patch?.path ?? "")) ||
      patch.sha256 !== sha256File(resolve(root, patch.path)) ||
      !dockerfileText.includes(patch.path) || !dockerfileText.includes(patch.sha256.slice("sha256:".length))) {
    errors.push(`${planRelative}: locally verified build does not retain its exact source patch`);
  }
  const dependencyLock = recipe?.dependency_lock;
  if (!digestPattern.test(dependencyLock?.sha256 ?? "") ||
      !existsSync(resolve(root, dependencyLock?.path ?? "")) ||
      dependencyLock.sha256 !== sha256File(resolve(root, dependencyLock.path)) ||
      dependencyLock.require_hashes !== true || dependencyLock.only_binary !== true ||
      !dockerfileText.includes("--require-hashes") || !dockerfileText.includes("--only-binary=:all:") ||
      !dockerfileText.includes(dependencyLock.sha256.slice("sha256:".length))) {
    errors.push(`${planRelative}: locally verified build does not retain its hashed binary dependency lock`);
  }
  const declaredBases = new Set((recipe?.base_images ?? []).map((image) => `${image.repository}:${image.tag}@${image.digest}`));
  const actualBases = [...dockerfileText.matchAll(/^\s*FROM(?:\s+--platform=[^\s]+)?\s+([^\s]+)(?:\s+AS\s+[^\s]+)?\s*$/gmi)].map((match) => match[1]);
  for (const image of recipe?.base_images ?? []) validateImage(image, `${planRelative}.build_recipe.base_images`);
  if (actualBases.length === 0 || actualBases.some((reference) => !declaredBases.has(reference)) ||
      [...declaredBases].some((reference) => !actualBases.includes(reference))) {
    errors.push(`${planRelative}: locally verified Dockerfile base images differ from its build recipe`);
  }
  const launcher = plan.wrapper;
  const launcherPath = resolve(root, `engines/images/${engine.id}/launcher/main.go`);
  const expectedEntrypoint = managedLocalK8sContracts.get(engine.id)?.entrypoint;
  if (!existsSync(launcherPath) || !expectedEntrypoint || launcher?.entrypoint !== expectedEntrypoint ||
      launcher?.launcher_sha256 !== sha256File(launcherPath) ||
      !dockerfileText.includes(`ENTRYPOINT ${JSON.stringify([launcher.entrypoint])}`)) {
    errors.push(`${planRelative}: locally verified build does not retain its exact non-shell launcher`);
  }
  const runtime = plan.managed_runtime;
  if (runtime?.network_mode !== "disabled" || engine.execution?.network?.mode !== "disabled" ||
      runtime?.non_root_user !== "65532:65532" ||
      !dockerfileText.split(/\r?\n/).some((line) => line.trim() === `USER ${runtime?.non_root_user}`)) {
    errors.push(`${planRelative}: locally verified build must remain offline and non-root`);
  }
  const evidence = plan.local_build_evidence;
  if (evidence?.platform !== "linux/amd64" || !digestPattern.test(evidence?.local_image_id ?? "") ||
      !existsSync(resolve(root, evidence?.scope_fixture ?? "")) ||
      !existsSync(resolve(root, evidence?.input_fixture ?? ""))) {
    errors.push(`${planRelative}: locally verified build lacks bounded smoke evidence`);
  }
}

function isPendingManagedCandidate(plan, engine, contract, artifactState) {
  const expectedRepository = managedRepository(engine, plan);
  return Boolean(contract) && plan?.publish_state === "publication_in_progress" &&
    plan.publication === null && engine.distribution_mode === "pull_pinned_image" && engine.image === null &&
    engine.default_enabled === false && engine.status === "experimental" &&
    engine.compatibility?.runnable === false && engine.compatibility?.artifact_state === artifactState &&
    Array.isArray(engine.compatibility?.blocked_by) && engine.compatibility.blocked_by.length > 0 &&
    Array.isArray(plan.blockers) && plan.blockers.length > 0 &&
    plan.final_artifact?.repository === expectedRepository && plan.final_artifact?.tag === contract.tag &&
    plan.final_artifact?.digest === null && engine.provenance?.engine?.artifact_source_revision === null &&
    engine.provenance?.engine?.source_association === "source_build_required";
}

function isPendingLocalK8sPublication(plan, engine) {
  if (engine?.id === "mcp-armor") return false;
  return isPendingManagedCandidate(
    plan,
    engine,
    managedLocalK8sContracts.get(engine?.id),
    "managed_build_plan",
  );
}

function validatePendingManagedCandidate(plan, planRelative, engine, contract) {
  if (!isPendingLocalK8sPublication(plan, engine)) {
    errors.push(`${planRelative}: unpublished managed build must remain isolated with null artifact/publication claims and an explicit per-engine blocker`);
    return;
  }
  if (plan.plan_kind !== contract.planKind) {
    errors.push(`${planRelative}: pending ${engine.id} plan kind must be ${contract.planKind}`);
  }
  if (engine.license?.disposition !== contract.license.disposition ||
      engine.license?.source_offer_path !== contract.license.sourceOfferPath) {
    errors.push(`catalog:${engine.id}.license: pending disposition/source offer does not match the reviewed release contract`);
  }
  const entrypoint = contract.entrypoint ?? "/usr/local/bin/ai-security-scanner-engine-entrypoint";
  validatePublishedManagedDockerfile(plan, planRelative, engine, contract.tag, entrypoint);
  const launcherRelative = contract.launcherPath ?? "engines/images/local-launcher/main.go";
  const launcherPath = resolve(root, launcherRelative);
  if (plan.wrapper?.launcher_sha256 !== sha256File(launcherPath) ||
      plan.wrapper?.entrypoint !== entrypoint || engine.compatibility?.wrapper?.entrypoint !== entrypoint) {
    errors.push(`${planRelative}: pending wrapper must bind the exact project-owned launcher source and entrypoint`);
  }
}

function isPendingMcpArmorPublication(plan, engine) {
  const contract = managedLocalK8sContracts.get("mcp-armor");
  const expectedRepository = managedRepository(engine, plan);
  return engine?.id === "mcp-armor" && plan?.publish_state === "publication_in_progress" &&
    plan.publication === null && engine.distribution_mode === "pull_pinned_image" && engine.image === null &&
    engine.default_enabled === false && engine.status === "experimental" &&
    engine.compatibility?.runnable === false && engine.compatibility?.artifact_state === "managed_build_plan" &&
    Array.isArray(engine.compatibility?.blocked_by) && engine.compatibility.blocked_by.length === 1 &&
    Array.isArray(plan.blockers) && plan.blockers.length === 1 &&
    plan.final_artifact?.repository === expectedRepository && plan.final_artifact?.tag === contract?.tag &&
    plan.final_artifact?.digest === null && engine.provenance?.engine?.artifact_source_revision === null &&
    engine.provenance?.engine?.source_association === "source_build_required";
}

function validateMcpArmorImage(plan, planRelative, engine) {
  const contract = managedLocalK8sContracts.get("mcp-armor");
  if (plan.publish_state === "published_managed_artifact") {
    validatePublishedLocalK8sImage(plan, planRelative, engine, contract);
    return;
  }
  if (!isPendingMcpArmorPublication(plan, engine)) {
    errors.push(`${planRelative}: MCP Armor must be either an admitted immutable image or one isolated publication-in-progress candidate`);
    return;
  }
  validateUnpublishedManagedBuild(plan, planRelative, engine, {
    publishState: "publication_in_progress",
    artifactTag: contract.tag,
  });
  const workflowPath = resolve(root, ".github/workflows/engine-image-mcp-armor.yml");
  const workflowText = existsSync(workflowPath) ? readFileSync(workflowPath, "utf8") : "";
  if (!workflowText.includes(`IMAGE_TAG: ${contract.tag}`) ||
      !workflowText.includes("engines/images/mcp-armor/Dockerfile") ||
      !workflowText.includes("docs/research/patches/mcp-armor-1.0.2-config-only.patch")) {
    errors.push(`${planRelative}: MCP Armor publication workflow does not bind the reviewed tag, Dockerfile, and machine-output patch`);
  }
}

function validateAgenticRadarImage(plan, planRelative, engine) {
  const contract = managedLocalK8sContracts.get("agentic-radar");
  if (plan.publish_state === "published_managed_artifact") {
    validatePublishedLocalK8sImage(plan, planRelative, engine, contract);
  } else {
    validatePendingManagedCandidate(plan, planRelative, engine, contract);
    validateUnpublishedManagedBuild(plan, planRelative, engine, {
      publishState: "publication_in_progress",
      artifactTag: contract.tag,
    });
  }
  const buildLock = plan.build_recipe?.build_dependency_lock;
  const buildLockPath = resolve(root, "engines/images/agentic-radar/build-requirements.lock");
  if (buildLock?.path !== "engines/images/agentic-radar/build-requirements.lock" ||
      !existsSync(buildLockPath) || buildLock?.sha256 !== sha256File(buildLockPath) ||
      buildLock?.require_hashes !== true || buildLock?.only_binary !== true || buildLock?.runtime_included !== false) {
    errors.push(`${planRelative}: Agentic Radar build/test dependencies require their own hashed lock outside the runtime`);
  }
  const workflowPath = resolve(root, ".github/workflows/engine-image-agentic-radar.yml");
  const workflow = existsSync(workflowPath) ? readFileSync(workflowPath, "utf8") : "";
  if (!workflow.includes(`IMAGE_TAG: ${contract.tag}`) ||
      !workflow.includes("engines/images/agentic-radar/Dockerfile") ||
      !workflow.includes(contract.sourcePatch.path)) {
    errors.push(`${planRelative}: Agentic Radar publication must bind its reviewed tag, Dockerfile and machine-output patch`);
  }
}

function isPendingGarakPublication(plan, engine) {
  return engine?.id === "garak" && plan?.publish_state === "publication_in_progress" &&
    plan.publication === null && engine.image === null && engine.distribution_mode === "pull_pinned_image" &&
    engine.status === "experimental" && engine.default_enabled === false && engine.compatibility?.runnable === false &&
    engine.compatibility?.artifact_state === "managed_build_plan" && plan.blockers?.length === 1 &&
    plan.final_artifact?.repository === managedRepository(engine, plan) &&
    plan.final_artifact?.tag === "0.17.0-1" && plan.final_artifact?.digest === null &&
    engine.provenance?.engine?.artifact_source_revision === null &&
    engine.provenance?.engine?.source_association === "source_build_required";
}

function validateGarakImage(plan, planRelative, engine) {
  const tag = "0.17.0-1";
  const sourceRevision = "93aa9cdec309ec4170559676f1826ea2a679920c";
  const repository = managedRepository(engine, plan);
  const recipe = plan.build_recipe;
  const dockerfileRelative = "engines/images/garak/Dockerfile";
  const dockerfilePath = resolve(root, dockerfileRelative);
  const dockerfile = existsSync(dockerfilePath) ? readFileSync(dockerfilePath, "utf8") : "";
  const runtime = plan.managed_runtime;
  const entrypoint = ["/usr/local/bin/python3", "-I", "-B", "/usr/local/lib/aiss-garak/main.py"];
  const profile = {
    id: "garak_https_v1", revision: sourceRevision,
    probes: ["dan.Dan_11_0", "dan.Dan_10_0", "dan.Dan_9_0", "ansiescape.AnsiEscaped"],
    native_prompts: 54, max_http_attempts: 64, max_request_bytes: 8192, max_total_request_bytes: 65536,
    max_response_bytes: 262144, requested_completion_tokens: 150, requests_per_second: 1, concurrency: 1,
    timeout_seconds: 20, deadline_seconds: 600,
  };
  if (plan.publish_state === "published_managed_artifact") {
    if (engine.image?.repository !== repository || engine.image?.tag !== tag ||
        plan.final_artifact?.repository !== repository || plan.final_artifact?.tag !== tag ||
        plan.final_artifact?.digest !== engine.image?.digest || engine.compatibility?.runnable !== true) {
      errors.push(`${planRelative}: Garak admission must name its exact independently verified immutable image`);
    }
    validatePublishedManagedEvidence(plan, planRelative, engine, { requireManagedSmoke: true });
  } else if (!isPendingGarakPublication(plan, engine)) {
    errors.push(`${planRelative}: Garak must remain an isolated candidate until its public image evidence is admitted`);
  }
  if (engine.source_revision !== sourceRevision || recipe?.source_revision !== sourceRevision ||
      lockedRepositories.get(engine.repository_url)?.revision !== sourceRevision || plan.plan_kind !== "managed_build" ||
      recipe?.source_patch !== null || recipe?.patch_audit !== undefined) {
    errors.push(`${planRelative}: Garak requires the unchanged reviewed native source and no detector patch`);
  }
  if (plan.dockerfile?.emitted !== true || plan.dockerfile?.path !== dockerfileRelative ||
      plan.dockerfile?.reason !== null || !existsSync(dockerfilePath) || plan.dockerfile?.sha256 !== sha256File(dockerfilePath) ||
      !dockerfile.includes(`org.opencontainers.image.version="${tag}"`) ||
      !dockerfile.includes(`org.opencontainers.image.revision="${sourceRevision}"`) ||
      !deepEqual(JSON.parse(dockerfile.match(/^ENTRYPOINT (\[.*\])$/m)?.[1] ?? "null"), entrypoint) || !/^USER 65532:65532$/m.test(dockerfile)) {
    errors.push(`${planRelative}: Garak requires its exact non-root Dockerfile and direct isolated Python entrypoint`);
  }
  const archives = [recipe?.source_archive, ...(recipe?.dependency_source_archives ?? [])];
  const expectedArchives = [
    { url: `https://github.com/NVIDIA/garak/archive/${sourceRevision}.tar.gz`, sha256: "sha256:34a7e31c9ca7efb00d00509f3397e8f25e87b88239c2c78d21fc9c54740b5fce" },
    { url: "https://files.pythonhosted.org/packages/0e/72/a3add0e4eec4eb9e2569554f7c70f4a3c27712f40e3284d483e88094cc0e/langdetect-1.0.9.tar.gz", sha256: "sha256:cbc1fef89f8d062739774bd51eda3da3274006b3661d199c2655f6b3f6d605a0" },
  ];
  if (archives.length !== 2 || archives.some((archive, index) => archive?.url !== expectedArchives[index].url ||
      archive?.sha256 !== expectedArchives[index].sha256 ||
      !dockerfile.includes(`ADD --checksum=${archive?.sha256}`) || !dockerfile.includes(archive?.url ?? ""))) {
    errors.push(`${planRelative}: Garak and langdetect source archives must retain their exact reviewed hashes`);
  }
  for (const [field, filename, count] of [["dependency_lock", "requirements.lock", 36], ["build_dependency_lock", "build-requirements.lock", 3]]) {
    const lock = recipe?.[field]; const relative = `engines/images/garak/${filename}`; const absolute = resolve(root, relative);
    if (lock?.path !== relative || !existsSync(absolute) || lock?.sha256 !== sha256File(absolute) ||
        lock?.records !== count || lock?.require_hashes !== true || lock?.only_binary !== true ||
        !dockerfile.includes(lock?.sha256?.slice(7) ?? "missing") || !dockerfile.includes("--require-hashes") ||
        !dockerfile.includes("--only-binary=:all:") || field === "build_dependency_lock" && lock?.runtime_included !== false) {
      errors.push(`${planRelative}: ${field} must retain its separately hash-locked binary dependency closure`);
    }
  }
  const launcher = "engines/images/garak/launcher/main.py";
  const transport = "engines/images/garak/launcher/runner.py";
  for (const [relative, field] of [[launcher, "launcher_sha256"], [transport, "transport_sha256"]]) {
    if (!existsSync(resolve(root, relative)) || plan.wrapper?.[field] !== sha256File(resolve(root, relative)) ||
        !recipe?.local_inputs?.some((input) => input.path === relative && input.sha256 === sha256File(resolve(root, relative)))) {
      errors.push(`${planRelative}: Garak must bind its exact launcher and bounded transport sources`);
    }
  }
  const base = "python:3.11.16-slim@sha256:9c900dea9e8fb7e16277c179b555cc72d29a352dbc33cff48ad5a0412fd5bfc7";
  const actualBases = [...dockerfile.matchAll(/^FROM\s+(\S+)/gm)].map((match) => match[1]);
  if (actualBases.length !== 2 || actualBases.some((reference) => reference !== base) ||
      !deepEqual(recipe?.target_platforms, ["linux/amd64", "linux/arm64"]) || recipe?.source_date_epoch !== 1788977945 ||
      recipe?.build_context?.path !== "." || recipe?.build_context?.dockerignore_path !== ".dockerignore" ||
      recipe?.build_context?.dockerignore_sha256 !== sha256File(resolve(root, ".dockerignore"))) {
    errors.push(`${planRelative}: Garak must preserve its reviewed build context, base image, epoch and platforms`);
  }
  if (runtime?.non_root_user !== "65532:65532" || runtime?.read_only_rootfs !== true ||
      !deepEqual(runtime?.entrypoint, entrypoint) || runtime?.network_mode !== "managed_allowlist" ||
      !deepEqual(runtime?.profile, profile) || engine.execution?.network?.mode !== "managed_allowlist" ||
      engine.execution?.resources?.timeout_seconds !== 600 || engine.compatibility?.wrapper?.entrypoint !== entrypoint[0] ||
      plan.wrapper?.entrypoint !== entrypoint[0] || !deepEqual(engine.direct_network_contract, {target_kinds: ["hostname", "address"], protocols: ["https"]})) {
    errors.push(`${planRelative}: Garak must preserve its exact HTTPS endpoint, native profile, transient key and bounded resource contract`);
  }
  const workflowPath = resolve(root, ".github/workflows/engine-image-garak.yml");
  const workflow = existsSync(workflowPath) ? readFileSync(workflowPath, "utf8") : "";
  for (const required of [`IMAGE_TAG: ${tag}`, dockerfileRelative, "engines/images/garak/testdata/native_smoke.py",
    "engine-image-evidence/publication-guard", "engine-image-evidence/promote", "managedSmokeEvidenceSha256",
    "report.jsonl garak-execution.json native-qa.json", "docker logout ghcr.io"]) {
    if (!workflow.includes(required)) errors.push(`${planRelative}: Garak publication workflow lacks ${required}`);
  }
  if (plan.local_build_evidence?.platform !== "linux/amd64" || !digestPattern.test(plan.local_build_evidence?.local_image_id ?? "") ||
      plan.local_build_evidence?.smoke_runner !== "engines/images/garak/testdata/native_smoke.py") {
    errors.push(`${planRelative}: Garak must retain its controlled native smoke entry and local amd64 identity`);
  }
}

function isPendingManagedExternalPublication(plan, engine) {
  const contract = managedExternalContracts.get(engine.id);
  const expectedRepository = managedRepository(engine, plan);
  return Boolean(contract) && plan?.publish_state === "publication_in_progress" &&
    plan.publication === null && engine.distribution_mode === "pull_pinned_image" && engine.image === null &&
    engine.default_enabled === false && engine.status === "experimental" &&
    engine.compatibility?.runnable === false && engine.compatibility?.artifact_state === "managed_build_plan" &&
    Array.isArray(engine.compatibility?.blocked_by) && engine.compatibility.blocked_by.length > 0 &&
    Array.isArray(plan.blockers) && plan.blockers.length > 0 &&
    plan.final_artifact?.repository === expectedRepository && plan.final_artifact?.tag === contract.tag &&
    plan.final_artifact?.digest === null && engine.provenance?.engine?.artifact_source_revision === null &&
    engine.provenance?.engine?.source_association === "source_build_required";
}

function validateManagedExternalImage(plan, planRelative, engine, contract = managedExternalContracts.get(engine.id)) {
  const expectedRepository = managedRepository(engine, plan);
  if (!contract) {
    errors.push(`${planRelative}: managed external engine has no reviewed artifact contract`);
    return;
  }
  if (plan.publish_state === "published_managed_artifact") {
    if (engine.image?.repository !== expectedRepository || engine.image?.tag !== contract.tag ||
        plan.final_artifact?.repository !== expectedRepository || plan.final_artifact?.tag !== contract.tag ||
        plan.final_artifact?.digest !== engine.image?.digest) {
      errors.push(`${planRelative}: managed external image must match the fixed ${engine.id} repository, tag, and digest contract`);
    }
    validatePublishedManagedEvidence(plan, planRelative, engine);
  } else if (plan.publish_state === "publication_in_progress") {
    if (!isPendingManagedExternalPublication(plan, engine)) {
      errors.push(`${planRelative}: unpublished managed external build must remain isolated with null artifact/publication claims and an explicit per-engine blocker`);
    }
  } else {
    errors.push(`${planRelative}: managed external image must be published or explicitly awaiting its own publication`);
  }

  const dockerfilePath = resolve(root, `engines/images/${engine.id}/Dockerfile`);
  if (plan.dockerfile?.emitted !== true || plan.dockerfile?.path !== `engines/images/${engine.id}/Dockerfile` || !existsSync(dockerfilePath)) {
    errors.push(`${planRelative}: managed external image must emit its engine Dockerfile`);
    return;
  }
  const dockerfileText = readFileSync(dockerfilePath, "utf8");
  const buildTag = contract.buildTag ?? contract.tag;
  if (!dockerfileText.includes(`org.opencontainers.image.version="${buildTag}"`)) {
    errors.push(`${planRelative}: managed external Dockerfile OCI version label must equal ${buildTag}`);
  }
  const externalWorkflowPath = resolve(root, ".github/workflows/engine-images-external.yml");
  const externalWorkflowText = existsSync(externalWorkflowPath)
    ? readFileSync(externalWorkflowPath, "utf8")
    : "";
  const workflowIdentity = new RegExp(
    `- engine: ${engine.id}\\r?\\n\\s+tag: ${buildTag.replaceAll(".", "\\.")}`,
  );
  if (!workflowIdentity.test(externalWorkflowText)) {
    errors.push(`${planRelative}: external publication workflow tag does not match ${contract?.tag ?? "the fixed contract"}`);
  }
  if (plan.dockerfile.sha256 !== sha256File(dockerfilePath)) {
    errors.push(`${planRelative}: managed external Dockerfile digest does not match`);
  }
  const launcherPath = resolve(root, "engines/images/external-launcher/main.go");
  if (plan.wrapper?.entrypoint !== "/usr/local/bin/ai-security-scanner-engine-entrypoint" || plan.wrapper?.launcher_sha256 !== sha256File(launcherPath)) {
    errors.push(`${planRelative}: external launcher identity does not match the project-owned source`);
  }
  if (!dockerfileText.includes(`ENTRYPOINT ${JSON.stringify([plan.wrapper?.entrypoint])}`)) {
    errors.push(`${planRelative}: managed external image lacks its direct non-shell entrypoint`);
  }
  const expectedCommand = engine.id === "naabu" && engine.execution?.launcher_journal_version === naabuLauncherJournalVersion
    ? naabuLauncherJournalV2Command
    : ["--engine", engine.id, "--scope", "/run/ai-security-scanner/scope.json", "--output", "/output"];
  if (!deepEqual(plan.command, expectedCommand)) {
    errors.push(`${planRelative}: external command is not the fixed launcher contract`);
  }

  const recipe = plan.build_recipe;
  if (recipe?.source_revision !== engine.source_revision || !recipe?.source_archive?.url?.includes(engine.source_revision) || !digestPattern.test(recipe?.source_archive?.sha256 ?? "")) {
    errors.push(`${planRelative}: external source archive is not closed over the catalog commit and digest`);
  } else if (!dockerfileText.includes(`ADD --checksum=${recipe.source_archive.sha256}`) || !dockerfileText.includes(recipe.source_archive.url)) {
    errors.push(`${planRelative}: external Dockerfile does not acquire the declared exact source archive`);
  }
  if (recipe?.dependency_lock?.path !== "go.sum" || !digestPattern.test(recipe?.dependency_lock?.sha256 ?? "") || !dockerfileText.includes(recipe?.dependency_lock?.sha256?.slice("sha256:".length) ?? "__missing_lock__")) {
    errors.push(`${planRelative}: external Go dependency closure is not checksum-pinned`);
  }
  if (!Number.isInteger(recipe?.source_date_epoch) || recipe.source_date_epoch < 1 || !deepEqual(recipe?.target_platforms, ["linux/amd64", "linux/arm64"])) {
    errors.push(`${planRelative}: external source epoch or publication platforms are invalid`);
  }
  validateImage(recipe?.dockerfile_frontend, `${planRelative}.build_recipe.dockerfile_frontend`);
  const expectedFrontend = `# syntax=${recipe?.dockerfile_frontend?.repository}:${recipe?.dockerfile_frontend?.tag}@${recipe?.dockerfile_frontend?.digest}`;
  if (dockerfileText.split(/\r?\n/)[0] !== expectedFrontend) {
    errors.push(`${planRelative}: external Dockerfile frontend is not the declared immutable frontend`);
  }
  for (const [index, image] of (recipe?.base_images ?? []).entries()) {
    validateImage(image, `${planRelative}.build_recipe.base_images[${index}]`, { allowDigestPinnedAlias: true });
    if (!dockerfileText.includes(`${image.repository}:${image.tag}@${image.digest}`)) {
      errors.push(`${planRelative}: external Dockerfile does not use declared base image ${index}`);
    }
  }
  if (!dockerfileText.includes("-mod=readonly") || !dockerfileText.includes("go mod verify") || !dockerfileText.includes("CGO_ENABLED=0")) {
    errors.push(`${planRelative}: external source build does not enforce its Go module/static-build closure`);
  }

  const runtime = plan.managed_runtime;
  if (runtime?.non_root_user !== "65532:65532" || runtime?.read_only_rootfs !== true || runtime?.network_mode !== "managed_allowlist" || runtime?.proxy !== "AI_SECURITY_SCANNER_PROXY" || runtime?.per_grant_target_execution !== true || runtime?.updates !== false || runtime?.stdin !== false || runtime?.redirects !== false) {
    errors.push(`${planRelative}: external runtime contract is not fail-closed`);
  }
  if (!dockerfileText.split(/\r?\n/).some((line) => line.trim() === `USER ${runtime?.non_root_user}`)) {
    errors.push(`${planRelative}: external Dockerfile does not set its declared non-root user`);
  }
  if (engine.id === "nuclei") {
    const templates = recipe?.templates;
    if (templates?.revision !== engine.rule_version || templates?.revision !== "f938a3dd530c283e9387b518b97911152ff5846c" || !templates?.source_archive?.url?.includes(templates.revision) || !digestPattern.test(templates?.source_archive?.sha256 ?? "")) {
      errors.push(`${planRelative}: Nuclei template artifact is not the required exact revision`);
    } else if (!dockerfileText.includes(`ADD --checksum=${templates.source_archive.sha256}`) || !dockerfileText.includes(templates.source_archive.url)) {
      errors.push(`${planRelative}: Nuclei Dockerfile does not embed the declared exact template artifact`);
    }
    if (!runtime?.template_policy ||
        runtime.template_policy.revision !== `nuclei-templates@${templates?.revision}` ||
        runtime.template_policy.profile_id !== "nuclei_web_safe_v1" ||
        runtime.template_policy.derived_template_count !== 4775 ||
        runtime.template_policy.legacy_exact_allowlist_supported !== true ||
        runtime.template_policy.denied_capabilities?.some((value) => typeof value !== "string") ||
        runtime.template_policy.denied_capabilities?.length !== 6) {
      errors.push(`${planRelative}: Nuclei runtime lacks the pinned upstream automatic-profile contract`);
    }
  }
}

function isPendingM365Publication(plan, engine) {
  const contract = managedM365Contracts.get(engine.id);
  const expectedRepository = managedRepository(engine, plan);
  return Boolean(contract) && plan?.publish_state === "publication_in_progress" &&
    plan.publication === null && engine.distribution_mode === "pull_pinned_image" && engine.image === null &&
    engine.default_enabled === false && engine.status === "experimental" &&
    engine.compatibility?.runnable === false && engine.compatibility?.artifact_state === "managed_build_plan" &&
    Array.isArray(engine.compatibility?.blocked_by) &&
    engine.compatibility.blocked_by.length > 0 && Array.isArray(plan.blockers) && plan.blockers.length > 0 &&
    plan.final_artifact?.repository === expectedRepository && plan.final_artifact?.tag === contract.tag &&
    plan.final_artifact?.digest === null && engine.provenance?.engine?.artifact_source_revision === null &&
    engine.provenance?.engine?.source_association === "source_build_required";
}

function validateManagedM365Image(plan, planRelative, engine) {
  const contract = managedM365Contracts.get(engine.id);
  const expectedRepository = managedRepository(engine, plan);
  if (!contract) {
    errors.push(`${planRelative}: managed Microsoft 365 engine has no reviewed artifact contract`);
    return;
  }
  if (plan.publish_state === "published_managed_artifact") {
    if (plan.final_artifact?.repository !== expectedRepository || plan.final_artifact?.tag !== contract.tag) {
      errors.push(`${planRelative}: published Microsoft 365 artifact does not match the reviewed wrapper-hardened repository/tag`);
    }
    validatePublishedManagedEvidence(plan, planRelative, engine);
  } else if (plan.publish_state === "publication_in_progress") {
    if (!isPendingM365Publication(plan, engine)) {
      errors.push(`${planRelative}: unpublished wrapper-hardened Microsoft 365 build must remain isolated with null artifact/publication claims and an explicit per-engine blocker`);
    }
  } else {
    errors.push(`${planRelative}: managed Microsoft 365 artifact must be published or explicitly awaiting its own publication`);
  }

  const engineRoot = `engines/images/${engine.id}`;
  const dockerfileRelative = `${engineRoot}/Dockerfile`;
  const dockerfilePath = resolve(root, dockerfileRelative);
  if (plan.plan_kind !== "managed_build" || plan.dockerfile?.emitted !== true || plan.dockerfile?.path !== dockerfileRelative || !existsSync(dockerfilePath)) {
    errors.push(`${planRelative}: managed Microsoft 365 image must emit its engine Dockerfile`);
    return;
  }
  const dockerfileText = readFileSync(dockerfilePath, "utf8");
  if (plan.dockerfile.sha256 !== sha256File(dockerfilePath) || plan.dockerfile.reason !== null) {
    errors.push(`${planRelative}: managed Microsoft 365 Dockerfile identity does not match`);
  }
  const frontend = plan.build_recipe?.dockerfile_frontend;
  validateImage(frontend, `${planRelative}.build_recipe.dockerfile_frontend`);
  if (dockerfileText.split(/\r?\n/)[0] !== `# syntax=${frontend?.repository}:${frontend?.tag}@${frontend?.digest}`) {
    errors.push(`${planRelative}: Microsoft 365 Dockerfile frontend is not the declared immutable frontend`);
  }

  const recipe = plan.build_recipe;
  const sourceArchive = recipe?.source_archive;
  if (recipe?.source_revision !== engine.source_revision ||
      !sourceArchive?.url?.includes(engine.source_revision) ||
      !digestPattern.test(sourceArchive?.sha256 ?? "") ||
      !dockerfileText.includes(`ADD --checksum=${sourceArchive?.sha256}`) ||
      !dockerfileText.includes(sourceArchive?.url ?? "")) {
    errors.push(`${planRelative}: Microsoft 365 source archive is not closed over the catalog commit and digest`);
  }
  if (!Number.isInteger(recipe?.source_date_epoch) || recipe.source_date_epoch < 1 ||
      !deepEqual(recipe?.target_platforms, ["linux/amd64", "linux/arm64"])) {
    errors.push(`${planRelative}: Microsoft 365 source epoch or publication platforms are invalid`);
  }
  for (const [index, image] of (recipe?.base_images ?? []).entries()) {
    validateImage(image, `${planRelative}.build_recipe.base_images[${index}]`, { allowDigestPinnedAlias: true });
    if (!dockerfileText.includes(`${image.repository}:${image.tag}@${image.digest}`)) {
      errors.push(`${planRelative}: Microsoft 365 Dockerfile does not use declared base image ${index}`);
    }
  }

  const lockRelative = `${engineRoot}/dependencies.lock.json`;
  const lockPath = resolve(root, lockRelative);
  const lock = existsSync(lockPath) ? parseJson(lockPath) : null;
  const lockText = existsSync(lockPath) ? readFileSync(lockPath, "utf8") : "";
  if (recipe?.dependency_lock?.path !== lockRelative ||
      recipe?.dependency_lock?.sha256 !== sha256File(lockPath) ||
      lock?.engine_id !== engine.id || lock?.source?.revision !== engine.source_revision) {
    errors.push(`${planRelative}: Microsoft 365 dependency closure does not match its exact lock`);
  }
  const preparerPath = resolve(root, "engines/images/m365-launcher/prepare_source.py");
  if (recipe?.source_preparer?.path !== "engines/images/m365-launcher/prepare_source.py" ||
      recipe?.source_preparer?.sha256 !== sha256File(preparerPath) ||
      !dockerfileText.includes("COPY engines/images/m365-launcher/prepare_source.py /opt/prepare_source.py")) {
    errors.push(`${planRelative}: Microsoft 365 source preparer identity does not match`);
  }
  for (const dependency of [...(lock?.powershell_modules ?? []), ...(lock?.native_dependencies ?? [])]) {
    const locations = [dependency.package_url, dependency.license_url, ...Object.values(dependency.artifacts ?? {}).map((artifact) => artifact.url)].filter(Boolean);
    const digests = [dependency.package_sha256, dependency.license_sha256, ...Object.values(dependency.artifacts ?? {}).map((artifact) => artifact.sha256)].filter(Boolean);
    for (const location of locations) if (!dockerfileText.includes(location)) errors.push(`${planRelative}: dependency URL ${location} is absent from the Dockerfile closure`);
    for (const digest of digests) if (!digestPattern.test(digest) || !dockerfileText.includes(digest.slice("sha256:".length)) && !lockText.includes(digest)) errors.push(`${planRelative}: dependency digest ${digest} is absent from the declared build closure`);
  }

  const launcherPath = resolve(root, "engines/images/m365-launcher/main.go");
  const scriptRelative = `${engineRoot}/run-${engine.id}.ps1`;
  const scriptPath = resolve(root, scriptRelative);
  const scriptText = readFileSync(scriptPath, "utf8");
  const normalizationStartText = `$severity = switch (${contract.switchExpression}) {`;
  const normalizationStart = scriptText.indexOf(normalizationStartText);
  const normalizationDefault = normalizationStart < 0
    ? -1
    : scriptText.indexOf("default { 'unknown' }", normalizationStart + normalizationStartText.length);
  const observedRatings = normalizationStart < 0 || normalizationDefault < 0
    ? []
    : [...scriptText.slice(normalizationStart, normalizationDefault).matchAll(/^\s*'([^']+)'\s*\{/gm)]
      .map((match) => match[1]);
  if (plan.wrapper?.entrypoint !== "/usr/local/bin/ai-security-scanner-m365-launcher" ||
      plan.wrapper?.launcher_sha256 !== sha256File(launcherPath) ||
      plan.wrapper?.script?.path !== scriptRelative ||
      plan.wrapper?.script?.sha256 !== sha256File(scriptPath) ||
      plan.wrapper?.strategy !== engine.compatibility?.wrapper?.strategy ||
      !plan.wrapper?.strategy?.includes("unknown") ||
      !dockerfileText.includes(`ENTRYPOINT ${JSON.stringify([plan.wrapper?.entrypoint])}`)) {
    errors.push(`${planRelative}: Microsoft 365 launcher, wrapper contract, or fixed script identity does not match`);
  }
  if (!scriptText.includes(contract.optionalPropertySnippet) ||
      !scriptText.includes(contract.optionalValueSnippet) ||
      scriptText.includes(contract.forbiddenDirectPropertySnippet) ||
      !scriptText.includes(`${contract.sourceRatingField} = ${contract.sourceRatingVariable}`) ||
      !scriptText.includes("default { 'unknown' }") ||
      !deepEqual(observedRatings, contract.reviewedRatings) ||
      !contract.normalizationSnippets.every((snippet) => scriptText.includes(snippet)) ||
      contract.forbiddenNormalizationSnippets.some((snippet) => scriptText.includes(snippet)) ||
      scriptText.includes("else { 'low' }") ||
      scriptText.includes("{ $severity = 'medium' }")) {
    errors.push(`${planRelative}: Microsoft 365 wrapper must safely retain the optional original source rating, map only its exact reviewed values, and leave missing or unrecognized values unknown`);
  }

  // Every verdict this switch does not name falls to `default { $null }` and is
  // dropped. `Diagnostics.normalized_results` counts the list the wrapper just
  // built, so it cannot notice that: an upstream verdict rename empties the
  // audit while every counter stays self-consistent. The host catches it at
  // runtime by comparing the counters named in `carriedVerdictCounters` against
  // `normalized_results` (`adapters::normalization_shortfall`); pinning the arms
  // here catches it at review time instead. Changing an arm without changing
  // that list on the Rust side restores the silent empty audit.
  const verdictStartText = `$result = switch ${contract.verdictSwitchExpression} {`;
  const verdictStart = scriptText.indexOf(verdictStartText);
  const verdictDefault = verdictStart < 0
    ? -1
    : scriptText.indexOf("default { $null }", verdictStart + verdictStartText.length);
  const observedVerdicts = verdictStart < 0 || verdictDefault < 0
    ? []
    : [...scriptText.slice(verdictStart, verdictDefault).matchAll(/^\s*'([^']+)'\s*\{/gm)]
      .map((match) => match[1]);
  const carriedCountersDeclared = contract.carriedVerdictCounters
    .every((counter) => new RegExp(`^\\s*${counter} = \\[int\\]`, "m").test(scriptText));
  if (!deepEqual(observedVerdicts, contract.reviewedVerdicts) ||
      !scriptText.includes("if ($null -eq $result) { continue }") ||
      !carriedCountersDeclared ||
      !scriptText.includes("normalized_results = $normalized.Count")) {
    errors.push(`${planRelative}: Microsoft 365 wrapper must convert exactly the reviewed verdicts into results and publish the engine's own counts for each of them (${contract.carriedVerdictCounters.join(", ")}), so a dropped verdict cannot read as a clean tenant`);
  }
  const expectedCommand = ["--engine", engine.id, "--scope", "/run/ai-security-scanner/scope.json", "--output", "/output"];
  if (!deepEqual(plan.command, expectedCommand)) errors.push(`${planRelative}: Microsoft 365 command is not the fixed launcher contract`);
  for (const forbidden of ["Invoke-WebRequest", "Invoke-RestMethod", "raw.githubusercontent.com", "Resolve-DnsName", "Test-NetConnection", "MSGRAPH_ACCESS_TOKEN="]) {
    if (scriptText.includes(forbidden)) errors.push(`${planRelative}: fixed Microsoft 365 script contains forbidden network or credential behavior ${forbidden}`);
  }
  for (const required of ["/run/ai-security-scanner/credentials.json", "Connect-MgGraph -AccessToken $secureToken", "Get-MgContext", "Disconnect-MgGraph"]) {
    if (!scriptText.includes(required)) errors.push(`${planRelative}: fixed Microsoft 365 script lacks ${required}`);
  }

  const runtime = plan.managed_runtime;
  if (runtime?.non_root_user !== "65532:65532" || runtime?.read_only_rootfs !== true ||
      runtime?.network_mode !== "managed_allowlist" || runtime?.proxy !== "AI_SECURITY_SCANNER_PROXY" ||
      runtime?.updates !== false || runtime?.telemetry !== false || runtime?.stdin !== false ||
      runtime?.credentials_path !== "/run/ai-security-scanner/credentials.json" ||
      runtime?.credential_key !== "MSGRAPH_ACCESS_TOKEN" || runtime?.credential_max_lifetime_minutes !== 65 ||
      !deepEqual(runtime?.network_destinations, ["graph.microsoft.com:443"]) ||
      !deepEqual(runtime?.network_destinations, engine.execution?.network?.destinations) ||
      engine.execution?.network?.mode !== "managed_allowlist") {
    errors.push(`${planRelative}: Microsoft 365 managed runtime is not the exact Graph-only fail-closed contract`);
  }
  if (!dockerfileText.split(/\r?\n/).some((line) => line.trim() === `USER ${runtime?.non_root_user}`)) {
    errors.push(`${planRelative}: Microsoft 365 Dockerfile does not set its declared non-root user`);
  }

  if (engine.id === "scubagear") {
    if (!deepEqual(recipe?.profile, { products: ["aad"], environment: "commercial", login: false, skip_dns_over_https: true, version_check: false, telemetry: false }) ||
        !deepEqual(lock?.product_profile?.network_destinations, ["graph.microsoft.com:443"]) ||
        !scriptText.includes("-ProductNames @('aad')") || !scriptText.includes("-M365Environment 'commercial'") || !scriptText.includes("-SkipDoH $true")) {
      errors.push(`${planRelative}: ScubaGear must retain its exact AAD commercial Graph-only profile`);
    }
  } else {
    const exclusions = ["MT.1025", "MT.1026", "MT.1027", "MT.1028", "MT.1030", "MT.1031", "MT.1182"];
    if (recipe?.profile?.test_path !== "/opt/ai-security-scanner/maester-tests/Maester/Entra" ||
        !deepEqual(recipe?.profile?.exclude_tags, exclusions) || recipe?.profile?.include_long_running !== false ||
        recipe?.profile?.include_preview !== false || recipe?.profile?.version_check !== false || recipe?.profile?.telemetry !== false ||
        !deepEqual(lock?.test_profile?.exclude_tags, exclusions) || !deepEqual(lock?.test_profile?.network_destinations, ["graph.microsoft.com:443"]) ||
        !exclusions.every((tag) => scriptText.includes(`'${tag}'`))) {
      errors.push(`${planRelative}: Maester must retain its exact Graph-only Entra test profile`);
    }
  }
}

const schema = parseJson(schemaPath);
const catalog = parseJson(catalogPath);
const upstreamLock = parseJson(upstreamLockPath);

if (schema && catalog) validateSchemaValue(catalog, schema, "catalog", schema, errors);
if (schema?.$schema !== "https://json-schema.org/draft/2020-12/schema") errors.push("compatibility schema must use JSON Schema draft 2020-12");
if (Object.hasOwn(schema ?? {}, "minItems") || Object.hasOwn(schema ?? {}, "maxItems")) {
  errors.push("compatibility schema must not turn catalog cardinality into a product-readiness requirement");
}

const catalogIds = Array.isArray(catalog) ? catalog.map((engine) => engine.id) : [];
if (new Set(catalogIds).size !== catalogIds.length) errors.push("catalog engine ids must be unique");
const managedEvidence = validateManagedImageEvidence(catalog);

const lockedRepositories = new Map((upstreamLock?.repositories ?? []).map((entry) => [entry.remote.replace(/\.git$/, ""), entry]));
for (let engine of Array.isArray(catalog) ? catalog : []) {
  const label = `catalog:${engine.id}`;
  validateStaticCommand(engine);
  const launcherJournalVersion = engine.execution?.launcher_journal_version;
  const hasLauncherJournalFlag = (flag) => (engine.command ?? []).some(
    (token) => token === flag || token.startsWith(`${flag}=`),
  );
  const hasJournalVersionFlag = hasLauncherJournalFlag("--journal-version");
  const hasJournalPlanFlag = hasLauncherJournalFlag("--journal-plan");
  if (launcherJournalVersion !== undefined) {
    if (launcherJournalVersion !== naabuLauncherJournalVersion) {
      errors.push(`${label}: unsupported launcher journal version`);
    } else if (engine.id !== "naabu") {
      errors.push(`${label}: launcher journal version 2 is supported only by the reviewed Naabu launcher`);
    } else if (!deepEqual(engine.command, naabuLauncherJournalV2Command)) {
      errors.push(`${label}: launcher journal version 2 requires the exact reviewed Naabu launcher command`);
    }
  } else if (hasJournalVersionFlag || hasJournalPlanFlag) {
    errors.push(`${label}: launcher journal command flags require the declared version 2 execution contract`);
  }
  const knowledgeDate = engine.compatibility?.knowledge_date;
  const supportUntil = engine.compatibility?.support_until;
  const maintenanceOwner = engine.compatibility?.maintenance_owner;
  if (isIsoDate(knowledgeDate) && isIsoDate(supportUntil) && supportUntil < knowledgeDate) {
    errors.push(`${label}: support_until must be on or after knowledge_date`);
  }
  if (typeof maintenanceOwner !== "string" || maintenanceOwner !== maintenanceOwner.trim() || maintenanceOwner.length === 0 || maintenanceOwner.length > 200 || /[\u0000-\u001f\u007f]/.test(maintenanceOwner)) {
    errors.push(`${label}: maintenance_owner must be a non-empty, trimmed, printable owner of at most 200 characters`);
  }
  const updateProcedure = engine.compatibility?.update_procedure;
  if (updateProcedure !== "docs/engine-maintenance.md" || !existsSync(resolve(root, updateProcedure ?? ""))) {
    errors.push(`${label}: update_procedure must resolve to docs/engine-maintenance.md`);
  }
  const expectedProviders = engine.id === "prowler"
    ? ["aws", "azure", "gcp"]
    : managedCloudIds.has(engine.id)
      ? ["aws"]
    : managedM365Ids.has(engine.id) ? ["microsoft365"] : [];
  if (!deepEqual(engine.supported_providers, expectedProviders)) {
    errors.push(`${label}: supported_providers must disclose only providers consumed by this released image`);
  }
  const permissions = new Set(engine.required_permissions ?? []);
  const inputContracts = engine.input_contracts ?? [];
  const providerContracts = engine.provider_execution_contracts ?? [];
  const directNetworkPermission = permissions.has("low_impact_external_connection") || permissions.has("active_external_testing");
  const directNetworkContract = engine.direct_network_contract;
  if ((engine.supported_providers?.length ?? 0) > 1 && providerContracts.length === 0) {
    errors.push(`${label}: a multi-provider engine requires exact provider execution contracts`);
  }
  if ((engine.supported_providers?.length ?? 0) === 0 && providerContracts.length > 0) {
    errors.push(`${label}: a provider-agnostic engine cannot declare provider execution contracts`);
  }
  if (providerContracts.length > 0) {
    const contractProviders = providerContracts.map((contract) => contract.provider);
    const contractAssetKinds = providerContracts.map((contract) => contract.asset_kind);
    const contractProfiles = providerContracts.map((contract) => contract.profile);
    const contractDestinations = providerContracts.flatMap((contract) => contract.network_destinations ?? []);
    if (!deepEqual(sortedUnique(contractProviders), sortedUnique(engine.supported_providers ?? [])) ||
        new Set(contractProviders).size !== providerContracts.length ||
        !deepEqual(sortedUnique(contractAssetKinds), sortedUnique(engine.supported_asset_kinds ?? [])) ||
        new Set(contractAssetKinds).size !== providerContracts.length ||
        new Set(contractProfiles).size !== providerContracts.length ||
        !deepEqual(sortedUnique(contractDestinations), sortedUnique(engine.network_destinations ?? []))) {
      errors.push(`${label}: provider execution contracts must uniquely cover the provider, asset-kind, profile, and network declarations`);
    }
    for (const [index, contract] of providerContracts.entries()) {
      if (typeof contract.profile !== "string" || !/^[a-z0-9][a-z0-9_-]{2,63}$/.test(contract.profile) ||
          !Array.isArray(contract.network_destinations) || contract.network_destinations.length === 0 ||
          new Set(contract.network_destinations).size !== contract.network_destinations.length) {
        errors.push(`${label}.provider_execution_contracts[${index}]: malformed profile or destination closure`);
      }
    }
  }
  if (permissions.has("local_artifact_read")) {
    const expectedContracts = (engine.supported_asset_kinds ?? []).map((assetKind) => ({
      asset_kind: assetKind,
      input_profile: localInputProfilesByAssetKind.get(assetKind),
    }));
    if (expectedContracts.some((contract) => contract.input_profile === undefined)) {
      errors.push(`${label}: local-artifact engine declares an asset kind without a backend input profile`);
    } else if (!deepEqual(
      inputContracts.map((contract) => ({
        asset_kind: contract?.asset_kind,
        input_profile: contract?.input_profile,
      })),
      expectedContracts,
    )) {
      errors.push(`${label}: input_contracts must bind every supported asset kind to its exact backend profile`);
    }
  } else if (inputContracts.length > 0) {
    errors.push(`${label}: non-local engine cannot declare a local input contract`);
  }
  if (directNetworkPermission) {
    if (!directNetworkContract || !Array.isArray(directNetworkContract.target_kinds) || directNetworkContract.target_kinds.length === 0 ||
        new Set(directNetworkContract.target_kinds).size !== directNetworkContract.target_kinds.length ||
        !Array.isArray(directNetworkContract.protocols) || directNetworkContract.protocols.length === 0 ||
        new Set(directNetworkContract.protocols).size !== directNetworkContract.protocols.length) {
      errors.push(`${label}: a direct-network engine requires unique, non-empty target-kind and protocol contracts`);
    }
  } else if (directNetworkContract !== undefined) {
    errors.push(`${label}: non-direct-network engine cannot declare a direct-network contract`);
  }
  if (!revisionPattern.test(engine.source_revision ?? "")) errors.push(`${label}.source_revision: exact 40-character commit is required`);
  if (engine.source_revision !== engine.provenance?.engine?.source_revision) errors.push(`${label}: top-level and provenance source revisions differ`);
  if (engine.engine_version !== engine.provenance?.engine?.version) errors.push(`${label}: top-level and provenance engine versions differ`);
  const reportedVersionPattern = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.]+)?$/;
  const sourceBuiltEngine = typeof engine.engine_version === "string" && engine.engine_version.startsWith("source@");
  if (sourceBuiltEngine) {
    if (!Object.hasOwn(engine, "reported_version")) {
      errors.push(`${label}: source-built engine requires reported_version`);
    } else if (typeof engine.reported_version !== "string" || !reportedVersionPattern.test(engine.reported_version)) {
      errors.push(`${label}: reported_version must match ^\\d+\\.\\d+\\.\\d+(?:-[0-9A-Za-z.]+)?$`);
    } else if (typeof engine.image?.tag === "string" && engine.image.tag !== engine.reported_version && !engine.image.tag.startsWith(`${engine.reported_version}-`)) {
      errors.push(`${label}: image.tag must equal reported_version or start with ${engine.reported_version}-`);
    }
  } else if (Object.hasOwn(engine, "reported_version")) {
    errors.push(`${label}: reported_version is only valid when engine_version starts with source@`);
  }
  if (engine.rule_version !== engine.provenance?.rules?.revision) errors.push(`${label}: top-level and provenance rule versions differ`);
  if (engine.adapter_version !== engine.provenance?.adapter?.version) errors.push(`${label}: top-level and provenance adapter versions differ`);
  const compatibilityBlockers = Array.isArray(engine.compatibility?.blocked_by)
    ? engine.compatibility.blocked_by
    : [];
  for (const [index, blocker] of compatibilityBlockers.entries()) {
    if (typeof blocker !== "string" || blocker.length === 0 || blocker.length > 512 ||
        blocker !== blocker.trim() || /[\u0000-\u001f\u007f]/u.test(blocker)) {
      errors.push(`${label}.compatibility.blocked_by[${index}]: blocker must be 1 to 512 trimmed, printable characters`);
    }
  }
  if (engine.compatibility?.runnable && engine.status !== "integrated") errors.push(`${label}: runnable engines must be integrated`);
  if (engine.compatibility?.runnable && engine.compatibility.blocked_by?.length > 0) errors.push(`${label}: runnable engines cannot retain compatibility blockers`);
  if (!engine.compatibility?.runnable && engine.compatibility?.blocked_by?.length === 0) errors.push(`${label}: non-runnable engines must state at least one compatibility blocker`);
  if (engine.default_enabled && (!engine.compatibility?.runnable || engine.status !== "integrated")) errors.push(`${label}: only integrated runnable engines may be default-enabled`);
  if (engine.status === "integrated" && engine.provenance?.adapter?.release_state !== "released") errors.push(`${label}: integrated engine requires a released adapter`);
  if (engine.provenance?.adapter?.release_state === "released" && !revisionPattern.test(engine.provenance.adapter.source_revision ?? "")) {
    errors.push(`${label}: released adapter requires an exact source revision`);
  }
  if (["license_review", "blocked"].includes(engine.license?.disposition) && engine.compatibility?.runnable) errors.push(`${label}: unresolved license disposition cannot be runnable`);
  if (engine.license?.disposition === "source_offer") {
    const offer = engine.license.source_offer_path;
    if (!offer || !existsSync(resolve(root, offer))) errors.push(`${label}: source-offer disposition requires an existing source offer notice`);
  } else if (engine.license?.source_offer_path !== null) {
    errors.push(`${label}: source_offer_path must be null unless disposition is source_offer`);
  }
  if (engine.active_external) {
    if (!permissions.has("low_impact_external_connection") && !permissions.has("active_external_testing")) {
      errors.push(`${label}: active external engine requires an external-connection permission`);
    }
    if (engine.execution?.network?.mode !== "managed_allowlist" || !engine.execution?.network?.required) {
      errors.push(`${label}: active external engine requires a managed network allowlist`);
    }
  }
  if ((engine.network_destinations?.length > 0) !== engine.execution?.network?.required) errors.push(`${label}: network required flag disagrees with declared destinations`);
  if (!deepEqual(engine.network_destinations, engine.execution?.network?.destinations)) errors.push(`${label}: network destinations disagree between runtime and compatibility declarations`);
  if (engine.execution?.network?.mode === "disabled" && engine.network_destinations?.length > 0) errors.push(`${label}: disabled network cannot declare destinations`);
  if (engine.execution?.output && !engine.output_formats?.includes(engine.execution.output.primary_format)) errors.push(`${label}: primary output format is absent from output_formats`);
  if (engine.execution?.resources?.memory_mb !== engine.estimated_memory_mb || engine.execution?.resources?.disk_mb !== engine.estimated_disk_mb) {
    errors.push(`${label}: resource declarations disagree`);
  }
  if (engine.provenance?.data?.mode === "external_pin_required") {
    if (engine.provenance.data.revision !== null || engine.compatibility?.runnable) errors.push(`${label}: unpinned external knowledge must remain non-runnable with null revision`);
    if (engine.compatibility?.knowledge_input?.pin_state !== "awaiting_pin") errors.push(`${label}: unpinned external knowledge must be marked awaiting_pin`);
  }
  if (engine.provenance?.engine?.source_association !== "attested_match" && engine.compatibility?.runnable) {
    errors.push(`${label}: runnable image requires attested matching source provenance`);
  }
  const planRelative = engine.compatibility?.packaging_plan;
  const planPath = planRelative ? resolve(root, planRelative) : null;
  if (!planPath || !existsSync(planPath)) {
    errors.push(`${label}: packaging plan is missing`);
    continue;
  }
  const plan = parseJson(planPath);
  if (!plan) continue;
  let pendingUpstreamUpdate = false;
  try {
    const buildEngine = pendingUpstreamBuild(plan, engine);
    if (buildEngine) {
      pendingUpstreamUpdate = true;
      engine = buildEngine;
    }
  } catch (error) {
    errors.push(`${planRelative}: ${error.message}`);
    continue;
  }
  const pendingGreenbonePublication = isPendingGreenbonePublication(plan, engine);
  const replacementContract = managedLocalK8sContracts.get(engine.id);
  const pendingImageReplacement = isPendingImageReplacement(plan, engine, replacementContract);
  const expectedManagedRepository = managedRepository(engine, plan);
  if (engine.distribution_mode === "pull_pinned_image" || engine.distribution_mode === "bundled_image") {
    if (engine.image !== null) {
      validateImage(engine.image, `${label}.image`);
    } else if (!isPendingM365Publication(plan, engine) &&
        !isPendingManagedExternalPublication(plan, engine) &&
        !isPendingMcpArmorPublication(plan, engine) &&
        !isPendingLocalK8sPublication(plan, engine) && !isPendingGarakPublication(plan, engine)) {
      errors.push(`${label}.image: only an exactly isolated reviewed publication-in-progress operation may omit its immutable image`);
    }
  } else if (engine.image !== null) {
    errors.push(`${label}: non-image distribution must not expose an executable image reference`);
  }
  if (engine.id === "prowler") {
    errors.push(...validateProwlerCatalogContract({ engine, plan, projectRoot: root }));
  }
  if (!planKinds.has(plan.plan_kind)) errors.push(`${planRelative}: unsupported plan kind ${plan.plan_kind}`);
  if (plan.engine_id !== engine.id) errors.push(`${planRelative}: engine id does not match catalog`);
  for (const field of ["knowledge_date", "support_until", "maintenance_owner", "update_procedure"]) {
    if (plan[field] !== engine.compatibility[field]) errors.push(`${planRelative}: ${field} does not match catalog`);
  }
  if (Object.hasOwn(plan, "support_date")) errors.push(`${planRelative}: retired support_date field must not be present`);
  if (!pendingGreenbonePublication &&
      (plan.source?.revision !== engine.source_revision ||
       plan.build_recipe?.source_revision && plan.build_recipe.source_revision !== engine.source_revision)) {
    errors.push(`${planRelative}: source revision does not match catalog`);
  }
  if (!revisionPattern.test(plan.source?.revision ?? "")) errors.push(`${planRelative}: source must be pinned to a commit`);
  validatePatchAudit(plan, planRelative, engine);
  if (!deepEqual(plan.command, engine.command)) errors.push(`${planRelative}: command does not match catalog`);
  if (!deepEqual(plan.output, engine.execution?.output)) errors.push(`${planRelative}: output contract does not match catalog`);
  if (!deepEqual(plan.license, engine.license)) errors.push(`${planRelative}: license disposition does not match catalog`);
  if (!pendingGreenbonePublication && engine.compatibility?.runnable && plan.blockers?.length > 0) errors.push(`${planRelative}: runnable engine plan cannot retain blockers`);
  if (!pendingGreenbonePublication && !engine.compatibility?.runnable && (!Array.isArray(plan.blockers) || plan.blockers.length === 0)) errors.push(`${planRelative}: non-runnable engine plan must state blockers`);
  if (!pendingGreenbonePublication && !deepEqual(plan.blockers, engine.compatibility?.blocked_by)) {
    errors.push(`${planRelative}: plan blockers must exactly match catalog compatibility blockers`);
  }
  if (plan.verified_upstream_artifact) validateImage(plan.verified_upstream_artifact, `${planRelative}.verified_upstream_artifact`);
  for (const [index, image] of (plan.build_recipe?.base_images ?? []).entries()) {
    validateImage(image, `${planRelative}.build_recipe.base_images[${index}]`, {
      allowDigestPinnedAlias: managedCloudIds.has(engine.id),
      allowFloatingDigestPinnedAlias: engine.id === "greenbone" &&
        image.repository.startsWith("registry.community.greenbone.net/community/"),
    });
  }
  for (const [index, step] of (plan.build_recipe?.static_steps ?? []).entries()) {
    const stepPath = `${planRelative}.build_recipe.static_steps[${index}]`;
    if (!Array.isArray(step) || step.length === 0 || step.some((token) => typeof token !== "string" || token.length === 0)) {
      errors.push(`${stepPath}: must be a static argv array`);
      continue;
    }
    if (shellNames.has(basename(step[0]).toLowerCase())) errors.push(`${stepPath}: shell-based build steps are forbidden`);
    for (const token of step) {
      if (token.includes("${") || token.includes("$(") || token.includes("{{") || token.includes("`") || [";", "&&", "||", "|", ">", ">>", "<"].includes(token)) {
        errors.push(`${stepPath}: dynamic or shell-interpreted token ${JSON.stringify(token)} is forbidden`);
      }
    }
  }
  if (pendingUpstreamUpdate) {
    validateImage(plan.previous_artifact, `${planRelative}.previous_artifact`);
    validateTag(plan.final_artifact.tag, `${planRelative}.final_artifact.tag`);
  } else if (pendingGreenbonePublication) {
    const pending = plan.final_artifact;
    if (!pending || pending.repository !== expectedManagedRepository ||
        pending.tag !== managedGreenboneContract.tag || pending.digest !== null ||
        plan.publish_state !== "publication_in_progress") {
      errors.push(`${planRelative}: Greenbone publication in progress must retain its exact replacement repository/tag and null digest`);
    }
  } else if (pendingImageReplacement) {
    // The runnable catalog still names the exact previous release. The build
    // plan separately binds a fresh tag whose digest is not known yet.
    validateImage(plan.previous_artifact, `${planRelative}.previous_artifact`);
  } else if (engine.image) {
    validateImage(plan.final_artifact, `${planRelative}.final_artifact`);
    if (!deepEqual(plan.final_artifact, { repository: engine.image.repository, tag: engine.image.tag, digest: engine.image.digest })) errors.push(`${planRelative}: final artifact does not match catalog image`);
  } else if (managedCloudIds.has(engine.id) || isPendingM365Publication(plan, engine) ||
      isPendingManagedExternalPublication(plan, engine) || isPendingMcpArmorPublication(plan, engine) ||
      isPendingLocalK8sPublication(plan, engine) || isPendingGarakPublication(plan, engine)) {
    const pending = plan.final_artifact;
    if (!pending || typeof pending.repository !== "string" || typeof pending.tag !== "string" || pending.digest !== null || plan.publish_state !== "publication_in_progress") {
      errors.push(`${planRelative}: managed image publication in progress must retain its exact repository/tag and null digest`);
    } else {
      validateTag(pending.tag, `${planRelative}.final_artifact.tag`);
    }
  } else if (plan.final_artifact?.digest !== null || plan.final_artifact?.tag !== null || plan.publish_state !== "managed_artifact_not_published") {
    errors.push(`${planRelative}: unpublished managed artifact must have null tag/digest and explicit publish state`);
  }
  const localK8sContract = managedLocalK8sContracts.get(engine.id);
  if (pendingUpstreamUpdate) {
    // Publication checks refer only to the retained image. Recipe checks use
    // candidate source metadata and the new tag, without making it runnable.
    const retainedPlan = {
      ...plan, publish_state: "published_managed_artifact",
      final_artifact: plan.previous_artifact, publication: plan.previous_publication,
    };
    if (localK8sContract) {
      validatePublishedLocalK8sImage(retainedPlan, planRelative, engine, {
        ...localK8sContract, tag: plan.previous_artifact.tag, buildTag: plan.final_artifact.tag,
      });
    } else if (managedExternalIds.has(engine.id)) {
      validateManagedExternalImage(retainedPlan, planRelative, engine, {
        ...managedExternalContracts.get(engine.id), tag: plan.previous_artifact.tag,
        buildTag: plan.final_artifact.tag,
      });
    } else if (managedCloudIds.has(engine.id)) {
      validateCloudManagedImage(retainedPlan, planRelative, engine);
    } else if (plan.plan_kind === "managed_rebase") {
      validateManagedRebase(retainedPlan, planRelative, engine);
    } else if (plan.plan_kind === "managed_source_image") {
      validateManagedSourceImage(retainedPlan, planRelative, engine);
    } else {
      errors.push(`${planRelative}: unsupported upstream replacement kind`);
    }
  } else if (engine.id === "mcp-armor") {
    validateMcpArmorImage(plan, planRelative, engine);
  } else if (engine.id === "agentic-radar") {
    validateAgenticRadarImage(plan, planRelative, engine);
  } else if (engine.id === "garak") {
    validateGarakImage(plan, planRelative, engine);
  } else if (pendingImageReplacement) {
    validatePublishedLocalK8sImage({
      ...plan,
      publish_state: "published_managed_artifact",
      final_artifact: plan.previous_artifact,
      publication: plan.previous_publication,
    }, planRelative, engine, {
      ...localK8sContract,
      tag: plan.previous_artifact.tag,
      buildTag: localK8sContract.tag,
    });
  } else if (localK8sContract && isPendingLocalK8sPublication(plan, engine)) {
    validatePendingManagedCandidate(plan, planRelative, engine, localK8sContract);
  } else if (localK8sContract && isManagedPublicationClaimed(engine, plan, expectedManagedRepository)) {
    validatePublishedLocalK8sImage(plan, planRelative, engine, localK8sContract);
  } else if (engine.id === "greenbone" && pendingGreenbonePublication) {
    validatePendingGreenboneImage(plan, planRelative, engine);
  } else if (engine.id === "greenbone" && isManagedPublicationClaimed(engine, plan, expectedManagedRepository)) {
    validatePublishedGreenboneImage(plan, planRelative, engine);
  } else if (engine.id === "cloudquery") {
    validateCloudManagedImage(plan, planRelative, engine);
    validateCloudQueryPlan(plan, planRelative, engine);
  } else if (managedCloudIds.has(engine.id)) {
    validateCloudManagedImage(plan, planRelative, engine);
  } else if (managedExternalIds.has(engine.id)) {
    validateManagedExternalImage(plan, planRelative, engine);
  } else if (managedM365Ids.has(engine.id)) {
    validateManagedM365Image(plan, planRelative, engine);
  } else if (plan.plan_kind === "managed_rebase") {
    validateManagedRebase(plan, planRelative, engine);
  } else if (plan.plan_kind === "managed_source_image") {
    validateManagedSourceImage(plan, planRelative, engine);
  } else if (plan.plan_kind !== "upstream_image") {
    const lock = lockedRepositories.get(engine.repository_url);
    if (!lock || lock.revision !== engine.source_revision) errors.push(`${planRelative}: managed build source is not pinned by engines/upstreams.lock.json`);
    if (plan.dockerfile?.emitted === true && plan.publish_state === "managed_artifact_not_published") {
      validateUnpublishedManagedBuild(plan, planRelative, engine);
    } else if (plan.dockerfile?.emitted !== false || !plan.dockerfile?.reason) {
      errors.push(`${planRelative}: absent managed Dockerfile requires an explicit reason`);
    }
  }
}

const cloudWorkflowPath = resolve(root, ".github/workflows/engine-images-cloud.yml");
if (!existsSync(cloudWorkflowPath)) {
  errors.push("managed cloud publication workflow is missing");
} else {
  const workflowText = readFileSync(cloudWorkflowPath, "utf8");
  if (!/^\s*workflow_dispatch:\s*$/m.test(workflowText)) {
    errors.push("managed cloud publication workflow must retain workflow_dispatch");
  }
  if (/^\s*-\s*["']?\.github\/workflows\/engine-images-cloud\.yml["']?\s*$/m.test(workflowText) ||
      /^\s*-\s*["']?\.github\/actions\/engine-image-evidence\/\*\*["']?\s*$/m.test(workflowText) ||
      /^\s*-\s*["']?scripts\/engine-image-evidence\.mjs["']?\s*$/m.test(workflowText)) {
    errors.push("managed cloud workflow/evidence-only changes must not auto-republish immutable version tags");
  }
  for (const engineId of managedCloudIds) {
    const positive = new RegExp(`^\\s*-\\s*["']?engines/images/${engineId}/\\*\\*["']?\\s*$`, "m");
    const negative = new RegExp(`^\\s*-\\s*["']?!engines/images/${engineId}/plan\\.json["']?\\s*$`, "m");
    if (!positive.test(workflowText) || !negative.test(workflowText)) {
      errors.push(`managed cloud publication workflow must watch ${engineId} inputs while excluding digest writeback`);
    }
  }
  if (!/^\s*-\s*["']?engines\/images\/cloud-launcher\/\*\*["']?\s*$/m.test(workflowText)) {
    errors.push("managed cloud publication workflow must watch the shared launcher source");
  }
}

const m365WorkflowPath = resolve(root, ".github/workflows/engine-images-m365.yml");
if (!existsSync(m365WorkflowPath)) {
  errors.push("managed Microsoft 365 publication workflow is missing");
} else {
  const workflowText = readFileSync(m365WorkflowPath, "utf8");
  const workflow = parseWorkflow(".github/workflows/engine-images-m365.yml");
  if (!/^\s*workflow_dispatch:\s*$/m.test(workflowText) ||
      !/^\s*-\s*["']?engines\/images\/m365-launcher\/\*\*["']?\s*$/m.test(workflowText)) {
    errors.push("managed Microsoft 365 workflow must retain dispatch and shared-launcher triggers");
  }
  for (const engineId of managedM365Ids) {
    const positive = new RegExp(`^\\s*-\\s*["']?engines/images/${engineId}/\\*\\*["']?\\s*$`, "m");
    const negative = new RegExp(`^\\s*-\\s*["']?!engines/images/${engineId}/plan\\.json["']?\\s*$`, "m");
    if (!positive.test(workflowText) || !negative.test(workflowText)) {
      errors.push(`managed Microsoft 365 workflow must watch ${engineId} inputs while excluding digest writeback`);
    }
    const matrixEntry = workflow?.jobs?.publish?.strategy?.matrix?.include?.find((entry) => entry?.engine === engineId);
    if (matrixEntry?.tag !== managedM365Contracts.get(engineId)?.tag) {
      errors.push(`managed Microsoft 365 workflow tag for ${engineId} must match its wrapper-hardened artifact contract`);
    }
  }
  for (const required of [
    "platforms: linux/amd64,linux/arm64",
    "docker logout ghcr.io",
    "Verify anonymous multi-platform access",
    "Run the anonymous amd64 smoke contract",
    "Validate the shared launcher in the pinned toolchain",
    "gofmt -d main.go main_test.go",
    "go test ./...",
    "missingOutputMountRejected: true",
    "missingScopeMountRejected: true",
    "missingCredentialMountRejected: true",
  ]) {
    if (!workflowText.includes(required)) errors.push(`managed Microsoft 365 workflow lacks ${required}`);
  }
  const publishSteps = workflow?.jobs?.publish?.steps;
  const launcherTestIndex = Array.isArray(publishSteps)
    ? publishSteps.findIndex((step) => step?.name === "Validate the shared launcher in the pinned toolchain")
    : -1;
  const imageBuildIndex = Array.isArray(publishSteps)
    ? publishSteps.findIndex((step) => step?.name === "Build and publish the immutable multi-platform image")
    : -1;
  if (launcherTestIndex < 0 || imageBuildIndex < 0 || launcherTestIndex >= imageBuildIndex) {
    errors.push("managed Microsoft 365 launcher tests must complete before either image is built or published");
  }
}

for (const dockerfile of walkFiles(resolve(root, "engines/images")).filter((path) => {
  // Deliberately insecure scanner fixtures are inputs, never build recipes.
  if (path.split(sep).includes("testdata")) return false;
  const name = basename(path).toLowerCase();
  return name === "dockerfile" || name.startsWith("dockerfile.") && !name.endsWith(".dockerignore");
})) {
  const lines = readFileSync(dockerfile, "utf8").split(/\r?\n/);
  const fromLines = lines.filter((line) => /^\s*FROM\s+/i.test(line));
  if (fromLines.length === 0) errors.push(`${dockerfile}: Dockerfile has no FROM instruction`);
  const stageAliases = new Set();
  for (const line of fromLines) {
    const match = line.trim().match(/^FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?$/i);
    const reference = match?.[1];
    const dynamicStage = reference?.includes("${TARGETARCH}") && ["amd64", "arm64"].every((architecture) =>
      stageAliases.has(reference.replace("${TARGETARCH}", architecture).toLowerCase()));
    if (!reference || reference !== "scratch" && !stageAliases.has(reference.toLowerCase()) && !dynamicStage && !/@sha256:[0-9a-f]{64}$/.test(reference)) {
      errors.push(`${dockerfile}: every external base image must be pinned by digest (${line.trim()})`);
    }
    if (match?.[2]) stageAliases.add(match[2].toLowerCase());
  }
}

if (errors.length > 0) {
  for (const error of [...new Set(errors)].sort()) console.error(`ERROR ${error}`);
  process.exit(1);
}

const imagePins = catalog.filter((engine) => engine.image).length;
const candidatePins = catalog.filter((engine) => {
  const plan = parseJson(resolve(root, engine.compatibility.packaging_plan));
  return !engine.image && Boolean(plan?.verified_upstream_artifact);
}).length;
const managedPlans = catalog.filter((engine) => engine.compatibility.artifact_state === "managed_build_plan").length;
const multiComponentPlans = catalog.filter((engine) => engine.compatibility.artifact_state === "multi_component_plan").length;
const runnable = catalog.filter((engine) => engine.compatibility.runnable).map((engine) => engine.id);
const licenseReview = catalog.filter((engine) => ["license_review", "blocked"].includes(engine.license.disposition)).map((engine) => engine.id);

console.log(`Validated ${catalog.length} engine compatibility records against ${schemaPath.replace(`${root}/`, "")}.`);
console.log(`Verified final upstream image pins: ${imagePins}; verified candidate/base pins: ${candidatePins}; managed build plans: ${managedPlans}; multi-component plans: ${multiComponentPlans}.`);
console.log(`Managed-image publication workflow contract: ${managedEvidence.coveredIds.length} present or pending engine coordinates across ${managedEvidence.workflowCount} workflows.`);
console.log(`Runnable now: ${runnable.length ? runnable.join(", ") : "none"}.`);
console.log(`License review: ${licenseReview.join(", ") || "none"}.`);
