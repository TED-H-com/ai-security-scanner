import { publicationSourceOrigin } from "../publication-origins.mjs";
import { WINDOWS_INSTALLED_LIFECYCLE_RECORDS } from "./windows-installed-lifecycle-evidence.mjs";

export const RELEASE_PLATFORM_CATALOG = Object.freeze([
  Object.freeze({ platform: "linux-x86_64", installerTypes: Object.freeze(["appimage", "deb", "rpm"]) }),
  Object.freeze({ platform: "macos-universal", installerTypes: Object.freeze(["dmg"]) }),
  Object.freeze({ platform: "windows-x86_64", installerTypes: Object.freeze(["msi", "nsis"]) }),
]);

const PLATFORM_BY_ID = new Map(RELEASE_PLATFORM_CATALOG.map((record) => [record.platform, record]));
const PUBLICATION_MODES = new Set(["commit-bound-qc", "public-github-release"]);
const UPDATER_TARGETS = new Map([
  ["linux-x86_64/appimage", ["linux-x86_64", "linux-x86_64-appimage"]],
  ["macos-universal/dmg", ["darwin-x86_64", "darwin-x86_64-app", "darwin-aarch64", "darwin-aarch64-app"]],
  ["windows-x86_64/nsis", ["windows-x86_64", "windows-x86_64-nsis"]],
]);
const AUXILIARY_EXECUTABLES = Object.freeze([
  "ai-security-scanner-egress-gateway",
  "ai-security-scanner-bootstrap-broker",
  "ai-security-scanner-cli",
]);
const WINDOWS_NSIS_DATA_PRESERVATION_FILES = Object.freeze([
  ["n-minus-one-upgrade-evidence", "windows-nsis-data-preservation/n-minus-one-upgrade/evidence.json"],
  ["n-minus-one-upgrade-report", "windows-nsis-data-preservation/n-minus-one-upgrade/beginner-report.html"],
  ["ghost-repair-uninstall-evidence", "windows-nsis-data-preservation/ghost-repair-uninstall/evidence.json"],
  ["ghost-repair-uninstall-report", "windows-nsis-data-preservation/ghost-repair-uninstall/beginner-report.html"],
]);

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function exactKeys(value, expected, label) {
  assert(value && typeof value === "object" && !Array.isArray(value), `${label} must be an object`);
  assert(
    JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...expected].sort()),
    `${label} fields are not the released schema-v3 set`,
  );
}

export function parseRequestedPlatforms(value) {
  const canonical = RELEASE_PLATFORM_CATALOG.map(({ platform }) => platform);
  const requested = value === undefined
    ? canonical
    : String(value).split(",").map((platform) => platform.trim()).filter(Boolean);
  assert(requested.length > 0, "at least one release platform must be requested");
  assert(new Set(requested).size === requested.length, "requested release platforms contain duplicates");
  for (const platform of requested) assert(PLATFORM_BY_ID.has(platform), `unsupported release platform: ${platform}`);
  return canonical.filter((platform) => requested.includes(platform));
}

function pendingInstaller(installerType) {
  return { installerType, availability: "pending", reason: null, artifact: null };
}

function unavailableInstaller(installerType, reason) {
  return { installerType, availability: "not-offered", reason, artifact: null };
}

export function createPreparedReleaseMetadata({
  version,
  tag,
  releaseChannel,
  stableTarget,
  sourceRepository,
  sourceCommit,
  sourceDate,
  publicationMode,
  requestedPlatforms,
  sboms,
  inventories,
}) {
  const requested = new Set(parseRequestedPlatforms(requestedPlatforms?.join(",")));
  const metadata = {
    schemaVersion: 3,
    releaseState: "prepared",
    product: "ai-security-scanner",
    version,
    tag,
    releaseChannel,
    stableTarget,
    sourceRepository,
    sourceCommit,
    sourceDate,
    publicationMode,
    distribution: {
      platforms: RELEASE_PLATFORM_CATALOG.map(({ platform, installerTypes }) => requested.has(platform)
        ? {
            platform,
            availability: "pending",
            reason: null,
            installers: installerTypes.map(pendingInstaller),
          }
        : {
            platform,
            availability: "not-offered",
            reason: "not-requested-for-this-release",
            installers: installerTypes.map((installerType) =>
              unavailableInstaller(installerType, "platform-not-requested")),
          }),
      bundledEngines: [],
      bundledAuxiliaryExecutables: [...AUXILIARY_EXECUTABLES],
      engineDelivery: "separate-artifacts-not-bundled-in-desktop-installers",
    },
    security: {
      checksums: "SHA256SUMS.txt",
      sboms: [...sboms],
    },
    inventories: { ...inventories },
  };
  validateReleaseMetadataV3(metadata, { releaseState: "prepared" });
  return metadata;
}

function expectedProvenance(publicationMode) {
  return publicationMode === "public-github-release"
    ? { state: "required-before-publication", provider: "GitHub artifact attestations", evidenceFile: null }
    : { state: "not-created-for-commit-bound-qc", provider: null, evidenceFile: null };
}

function validateOutcome(outcome, label, allowedStates) {
  exactKeys(outcome, ["state", "evidenceFile", "reason"], label);
  assert(allowedStates.includes(outcome.state), `${label} state is invalid`);
  if (["passed", "installer-passed-runtime-not-observed", "verified"].includes(outcome.state)) {
    assert(typeof outcome.evidenceFile === "string" && outcome.evidenceFile.length > 0, `${label} evidence is missing`);
    assert(outcome.reason === null, `${label} verified state must not have an unavailable reason`);
  } else {
    assert(outcome.evidenceFile === null, `${label} unavailable state must not claim evidence`);
    assert(typeof outcome.reason === "string" && outcome.reason.length > 0, `${label} unavailable state needs a reason`);
  }
}

function validateWindowsLifecycle(outcome, platform, installerType, label) {
  exactKeys(outcome, ["state", "evidenceFiles", "reason"], `${label} Windows lifecycle`);
  assert(Array.isArray(outcome.evidenceFiles), `${label} Windows lifecycle evidenceFiles must be an array`);
  if (platform !== "windows-x86_64") {
    assert(
      outcome.state === "not-applicable" && outcome.evidenceFiles.length === 0 &&
        typeof outcome.reason === "string" && outcome.reason.length > 0,
      `${label} non-Windows artifact has a Windows lifecycle claim`,
    );
    return;
  }
  if (outcome.state === "not-observed") {
    assert(outcome.evidenceFiles.length === 0, `${label} unobserved Windows lifecycle claims evidence`);
    assert(typeof outcome.reason === "string" && outcome.reason.length > 0, `${label} unobserved Windows lifecycle needs a reason`);
    return;
  }
  assert(installerType === "nsis", `${label} has no reviewed installed-lifecycle contract for ${installerType}`);
  assert(["verified", "partial", "failed"].includes(outcome.state), `${label} Windows lifecycle state is invalid`);
  assert(outcome.evidenceFiles.length >= 2, `${label} observed Windows lifecycle has no protected receipt and row evidence`);
  const expectedPaths = new Set(
    WINDOWS_INSTALLED_LIFECYCLE_RECORDS.map(({ path: evidencePath }) =>
      `windows-installed-lifecycle/${evidencePath}`),
  );
  assert(
    outcome.evidenceFiles[0]?.path === "windows-external-evidence-import.json",
    `${label} Windows lifecycle does not begin with its protected import receipt`,
  );
  const seen = new Set();
  for (const [index, record] of outcome.evidenceFiles.entries()) {
    exactKeys(record, ["path", "bytes", "sha256"], `${label} Windows lifecycle evidence record`);
    assert(
      typeof record.path === "string" && record.path.length > 0 && !record.path.startsWith("/") &&
        !record.path.includes("\\") && !record.path.split("/").includes(".."),
      `${label} Windows lifecycle evidence path is unsafe`,
    );
    assert(!seen.has(record.path), `${label} Windows lifecycle evidence path is duplicated`);
    seen.add(record.path);
    assert(Number.isSafeInteger(record.bytes) && record.bytes > 0, `${label} Windows lifecycle evidence bytes are invalid`);
    assert(/^[0-9a-f]{64}$/u.test(record.sha256), `${label} Windows lifecycle evidence digest is invalid`);
    if (index > 0) assert(expectedPaths.has(record.path), `${label} Windows lifecycle evidence path is unsupported`);
  }
  if (outcome.state === "verified") {
    assert(
      outcome.evidenceFiles.length === WINDOWS_INSTALLED_LIFECYCLE_RECORDS.length + 1 &&
        WINDOWS_INSTALLED_LIFECYCLE_RECORDS.every(({ path: evidencePath }) =>
          seen.has(`windows-installed-lifecycle/${evidencePath}`)),
      `${label} verified Windows lifecycle is missing a required row`,
    );
    assert(outcome.reason === null, `${label} verified Windows lifecycle has an unavailable reason`);
  } else {
    assert(typeof outcome.reason === "string" && outcome.reason.length > 0, `${label} non-verified Windows lifecycle needs a reason`);
  }
}

function validateWindowsDataPreservation(outcome, platform, installerType, label) {
  exactKeys(outcome, ["state", "evidenceFiles", "reason"], `${label} Windows data preservation`);
  assert(Array.isArray(outcome.evidenceFiles), `${label} Windows data-preservation evidenceFiles must be an array`);
  if (platform !== "windows-x86_64") {
    assert(
      outcome.state === "not-applicable" && outcome.evidenceFiles.length === 0 &&
        typeof outcome.reason === "string" && outcome.reason.length > 0,
      `${label} non-Windows artifact has a Windows data-preservation claim`,
    );
    return;
  }
  if (outcome.state === "not-observed") {
    assert(outcome.evidenceFiles.length === 0, `${label} unobserved Windows data preservation claims evidence`);
    assert(typeof outcome.reason === "string" && outcome.reason.length > 0, `${label} unobserved Windows data preservation needs a reason`);
    return;
  }
  assert(
    outcome.state === "supporting-data-preservation-only" && installerType === "nsis",
    `${label} Windows data-preservation state is unsupported for this installer`,
  );
  assert(
    JSON.stringify(outcome.evidenceFiles.map(({ role, path: file }) => [role, file])) ===
      JSON.stringify(WINDOWS_NSIS_DATA_PRESERVATION_FILES),
    `${label} supporting NSIS data-preservation evidence set is incomplete or out of order`,
  );
  for (const record of outcome.evidenceFiles) {
    exactKeys(record, ["role", "path", "bytes", "sha256"], `${label} data-preservation evidence record`);
    assert(
      typeof record.path === "string" && record.path.length > 0 &&
        !record.path.startsWith("/") && !record.path.includes("\\") && !record.path.split("/").includes(".."),
      `${label} data-preservation evidence path is unsafe`,
    );
    assert(Number.isSafeInteger(record.bytes) && record.bytes > 0, `${label} data-preservation evidence bytes are invalid`);
    assert(/^[0-9a-f]{64}$/u.test(record.sha256), `${label} data-preservation evidence digest is invalid`);
  }
  assert(
    outcome.reason === "real-installed-app-localhost-lifecycle-not-observed",
    `${label} supporting-only data-preservation evidence must disclose the missing real-app journey`,
  );
}

function validateArtifact(artifact, platform, installerType, publicationMode) {
  exactKeys(
    artifact,
    [
      "file", "bytes", "sha256", "technicalQualification", "humanPath",
      "operatingSystemSigning", "notarization", "windowsLifecycle", "windowsDataPreservation",
      "updater", "provenanceAttestation",
      "knownLimitations",
    ],
    `${platform}/${installerType} artifact`,
  );
  assert(typeof artifact.file === "string" && artifact.file.length > 0, `${platform}/${installerType} artifact file is missing`);
  assert(Number.isSafeInteger(artifact.bytes) && artifact.bytes > 0, `${platform}/${artifact.file} byte count is invalid`);
  assert(/^[0-9a-f]{64}$/u.test(artifact.sha256), `${platform}/${artifact.file} digest is invalid`);
  validateOutcome(
    artifact.technicalQualification,
    `${platform}/${artifact.file} technical qualification`,
    ["passed", "installer-passed-runtime-not-observed"],
  );
  validateOutcome(artifact.humanPath, `${platform}/${artifact.file} human path`, ["verified", "not-observed"]);
  validateWindowsLifecycle(artifact.windowsLifecycle, platform, installerType, `${platform}/${artifact.file}`);
  validateWindowsDataPreservation(artifact.windowsDataPreservation, platform, installerType, `${platform}/${artifact.file}`);
  exactKeys(artifact.operatingSystemSigning, ["state", "evidenceFile", "reason"], `${platform}/${artifact.file} OS signing`);
  assert(["verified", "not-configured"].includes(artifact.operatingSystemSigning.state), `${platform}/${artifact.file} OS-signing state is invalid`);
  if (artifact.operatingSystemSigning.state === "verified") {
    assert(typeof artifact.operatingSystemSigning.evidenceFile === "string" && artifact.operatingSystemSigning.evidenceFile.length > 0, `${platform}/${artifact.file} OS-signing evidence is missing`);
    assert(artifact.operatingSystemSigning.reason === null, `${platform}/${artifact.file} verified OS signing must not have a reason`);
  } else {
    assert(artifact.operatingSystemSigning.evidenceFile === null, `${platform}/${artifact.file} unsigned artifact must not claim signing evidence`);
    assert(typeof artifact.operatingSystemSigning.reason === "string" && artifact.operatingSystemSigning.reason.length > 0, `${platform}/${artifact.file} unsigned artifact needs a reason`);
  }
  exactKeys(artifact.notarization, ["state", "evidenceFile", "reason"], `${platform}/${artifact.file} notarization`);
  const notarizationStates = platform === "macos-universal"
    ? ["verified", "not-configured"]
    : ["not-applicable"];
  assert(notarizationStates.includes(artifact.notarization.state), `${platform}/${artifact.file} notarization state is invalid`);
  if (artifact.notarization.state === "verified") {
    assert(typeof artifact.notarization.evidenceFile === "string" && artifact.notarization.evidenceFile.length > 0, `${platform}/${artifact.file} notarization evidence is missing`);
    assert(artifact.notarization.reason === null, `${platform}/${artifact.file} verified notarization must not have a reason`);
  } else {
    assert(artifact.notarization.evidenceFile === null, `${platform}/${artifact.file} notarization state fabricates evidence`);
    assert(typeof artifact.notarization.reason === "string" && artifact.notarization.reason.length > 0, `${platform}/${artifact.file} notarization state needs a reason`);
  }
  exactKeys(artifact.updater, ["state", "payloadFile", "signatureFile", "targetKeys", "reason"], `${platform}/${artifact.file} updater`);
  assert(["signed", "not-offered"].includes(artifact.updater.state), `${platform}/${artifact.file} updater state is invalid`);
  assert(Array.isArray(artifact.updater.targetKeys), `${platform}/${artifact.file} updater targets are invalid`);
  if (artifact.updater.state === "signed") {
    const expectedTargets = UPDATER_TARGETS.get(`${platform}/${installerType}`);
    assert(expectedTargets, `${platform}/${artifact.file} is not a runtime-consumable updater package`);
    assert(typeof artifact.updater.payloadFile === "string" && artifact.updater.payloadFile.length > 0, `${platform}/${artifact.file} updater payload is missing`);
    assert(typeof artifact.updater.signatureFile === "string" && artifact.updater.signatureFile.length > 0, `${platform}/${artifact.file} updater signature is missing`);
    assert(artifact.updater.targetKeys.length > 0 && artifact.updater.reason === null, `${platform}/${artifact.file} updater evidence is incomplete`);
    assert(
      JSON.stringify(artifact.updater.targetKeys) === JSON.stringify(expectedTargets),
      `${platform}/${artifact.file} updater targets do not match the runtime updater contract`,
    );
  } else {
    assert(artifact.updater.payloadFile === null && artifact.updater.signatureFile === null && artifact.updater.targetKeys.length === 0, `${platform}/${artifact.file} unavailable updater claims files`);
    assert(typeof artifact.updater.reason === "string" && artifact.updater.reason.length > 0, `${platform}/${artifact.file} unavailable updater needs a reason`);
  }
  exactKeys(artifact.provenanceAttestation, ["state", "provider", "evidenceFile"], `${platform}/${artifact.file} provenance`);
  assert(
    JSON.stringify(artifact.provenanceAttestation) === JSON.stringify(expectedProvenance(publicationMode)),
    `${platform}/${artifact.file} provenance state does not match publication mode`,
  );
  assert(Array.isArray(artifact.knownLimitations) && artifact.knownLimitations.every((item) => typeof item === "string" && item.length > 0), `${platform}/${artifact.file} known limitations are invalid`);
  assert(
    new Set(artifact.knownLimitations).size === artifact.knownLimitations.length,
    `${platform}/${artifact.file} known limitations contain duplicates`,
  );
  if (artifact.humanPath.state === "not-observed") {
    assert(
      artifact.knownLimitations.includes("beginner-human-path-not-observed"),
      `${platform}/${artifact.file} does not disclose its unobserved beginner human path`,
    );
  }
  if (artifact.operatingSystemSigning.state === "not-configured") {
    assert(
      artifact.knownLimitations.includes("operating-system-signing-not-configured"),
      `${platform}/${artifact.file} does not disclose its missing operating-system signature`,
    );
  }
  if (platform === "windows-x86_64" && artifact.windowsLifecycle.state === "not-observed") {
    assert(
      artifact.knownLimitations.includes("windows-lifecycle-not-observed"),
      `${platform}/${artifact.file} does not disclose its unobserved Windows lifecycle`,
    );
  }
  if (platform === "windows-x86_64" && artifact.windowsLifecycle.state === "partial") {
    assert(
      artifact.knownLimitations.includes("windows-lifecycle-partial"),
      `${platform}/${artifact.file} does not disclose its partial Windows lifecycle`,
    );
  }
  if (platform === "windows-x86_64" && artifact.windowsLifecycle.state === "failed") {
    assert(
      artifact.knownLimitations.includes("windows-lifecycle-failed"),
      `${platform}/${artifact.file} does not disclose its failed Windows lifecycle`,
    );
  }
  if (platform === "windows-x86_64" && artifact.windowsDataPreservation.state === "not-observed") {
    assert(
      artifact.knownLimitations.includes("windows-data-preservation-not-observed"),
      `${platform}/${artifact.file} does not disclose its unobserved Windows data preservation`,
    );
  }
  if (
    platform === "windows-x86_64" &&
    artifact.windowsDataPreservation.state === "supporting-data-preservation-only"
  ) {
    assert(
      artifact.knownLimitations.includes("windows-data-preservation-fixtures-only"),
      `${platform}/${artifact.file} overstates its supporting Windows data-preservation fixtures`,
    );
  }
}

function validatePlatform(platformRecord, releaseState, publicationMode) {
  exactKeys(platformRecord, ["platform", "availability", "reason", "installers"], `platform ${String(platformRecord?.platform)}`);
  const contract = PLATFORM_BY_ID.get(platformRecord.platform);
  assert(contract, `release metadata has an unsupported platform: ${String(platformRecord.platform)}`);
  assert(Array.isArray(platformRecord.installers), `${platformRecord.platform} installers must be an array`);
  assert(
    JSON.stringify(platformRecord.installers.map(({ installerType }) => installerType)) === JSON.stringify(contract.installerTypes),
    `${platformRecord.platform} installer support matrix is incomplete or out of order`,
  );
  const allowedAvailability = releaseState === "prepared"
    ? ["pending", "not-offered"]
    : ["offered", "not-offered"];
  assert(allowedAvailability.includes(platformRecord.availability), `${platformRecord.platform} availability is invalid for ${releaseState} metadata`);
  let offeredCount = 0;
  for (const installer of platformRecord.installers) {
    exactKeys(installer, ["installerType", "availability", "reason", "artifact"], `${platformRecord.platform}/${installer.installerType}`);
    assert(contract.installerTypes.includes(installer.installerType), `${platformRecord.platform} has an unsupported installer type`);
    assert(allowedAvailability.includes(installer.availability), `${platformRecord.platform}/${installer.installerType} availability is invalid`);
    if (installer.availability === "offered") {
      offeredCount += 1;
      assert(installer.reason === null, `${platformRecord.platform}/${installer.installerType} offered record has a reason`);
      validateArtifact(
        installer.artifact,
        platformRecord.platform,
        installer.installerType,
        publicationMode,
      );
    } else {
      assert(installer.artifact === null, `${platformRecord.platform}/${installer.installerType} unavailable record claims an artifact`);
      if (installer.availability === "pending") {
        assert(installer.reason === null, `${platformRecord.platform}/${installer.installerType} pending record has a final reason`);
      } else {
        assert(typeof installer.reason === "string" && installer.reason.length > 0, `${platformRecord.platform}/${installer.installerType} unavailable record needs a reason`);
      }
    }
  }
  if (platformRecord.availability === "offered") {
    assert(offeredCount > 0 && platformRecord.reason === null, `${platformRecord.platform} offered state is inconsistent`);
  } else if (platformRecord.availability === "pending") {
    assert(platformRecord.installers.some(({ availability }) => availability === "pending") && platformRecord.reason === null, `${platformRecord.platform} pending state is inconsistent`);
  } else {
    assert(offeredCount === 0 && typeof platformRecord.reason === "string" && platformRecord.reason.length > 0, `${platformRecord.platform} not-offered state is inconsistent`);
  }
}

export function validateReleaseMetadataV3(metadata, expected = {}) {
  exactKeys(
    metadata,
    [
      "schemaVersion", "releaseState", "product", "version", "tag", "releaseChannel",
      "stableTarget", "sourceRepository", "sourceCommit", "sourceDate", "publicationMode",
      "distribution", "security", "inventories",
    ],
    "release metadata",
  );
  assert(metadata.schemaVersion === 3, "release metadata schemaVersion must be 3");
  assert(["prepared", "finalized"].includes(metadata.releaseState), "release metadata releaseState is invalid");
  assert(metadata.product === "ai-security-scanner", "release metadata product is incorrect");
  assert(/^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/u.test(metadata.version), "release metadata version is invalid");
  assert(metadata.tag === `v${metadata.version}`, "release metadata tag/version mismatch");
  assert(["prerelease", "stable"].includes(metadata.releaseChannel), "release metadata channel is invalid");
  assert(/^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/u.test(metadata.stableTarget), "release metadata stableTarget is invalid");
  publicationSourceOrigin(metadata.sourceRepository);
  assert(/^[0-9a-f]{40}$/u.test(metadata.sourceCommit), "release metadata source commit is invalid");
  assert(typeof metadata.sourceDate === "string" && !Number.isNaN(Date.parse(metadata.sourceDate)), "release metadata source date is invalid");
  assert(PUBLICATION_MODES.has(metadata.publicationMode), "release metadata publication mode is invalid");
  for (const [field, value] of Object.entries(expected)) {
    assert(metadata[field] === value, `release metadata ${field} differs from the expected release identity`);
  }
  exactKeys(metadata.distribution, ["platforms", "bundledEngines", "bundledAuxiliaryExecutables", "engineDelivery"], "release distribution");
  assert(Array.isArray(metadata.distribution.platforms), "release metadata platforms must be an array");
  assert(
    JSON.stringify(metadata.distribution.platforms.map(({ platform }) => platform)) ===
      JSON.stringify(RELEASE_PLATFORM_CATALOG.map(({ platform }) => platform)),
    "release metadata platform support matrix is incomplete or out of order",
  );
  for (const platformRecord of metadata.distribution.platforms) {
    validatePlatform(
      platformRecord,
      metadata.releaseState,
      metadata.publicationMode,
    );
  }
  assert(Array.isArray(metadata.distribution.bundledEngines) && metadata.distribution.bundledEngines.length === 0, "release metadata must not claim bundled engines");
  assert(JSON.stringify(metadata.distribution.bundledAuxiliaryExecutables) === JSON.stringify(AUXILIARY_EXECUTABLES), "release metadata auxiliary executable inventory is invalid");
  assert(metadata.distribution.engineDelivery === "separate-artifacts-not-bundled-in-desktop-installers", "release metadata engine delivery is invalid");
  exactKeys(metadata.security, ["checksums", "sboms"], "release security evidence");
  assert(metadata.security.checksums === "SHA256SUMS.txt", "release metadata checksum file is invalid");
  assert(Array.isArray(metadata.security.sboms) && metadata.security.sboms.length === 2 && metadata.security.sboms.every((item) => typeof item === "string" && item.length > 0), "release metadata SBOM inventory is invalid");
  exactKeys(metadata.inventories, ["npmPackageCount", "cargoPackageCount", "engineReferenceCount"], "release inventories");
  for (const [name, count] of Object.entries(metadata.inventories)) {
    assert(Number.isSafeInteger(count) && count >= 0, `release metadata ${name} is invalid`);
  }
  return metadata;
}

export function provenanceForArtifact(publicationMode) {
  assert(PUBLICATION_MODES.has(publicationMode), "unsupported publication mode");
  return expectedProvenance(publicationMode);
}

export function platformContract(platform) {
  const contract = PLATFORM_BY_ID.get(platform);
  assert(contract, `unsupported release platform: ${platform}`);
  return contract;
}
