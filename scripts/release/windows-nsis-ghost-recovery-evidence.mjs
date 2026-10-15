import { lstat, readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  PROJECT_ROOT,
  isSemver,
  parseArgs,
  readJson,
  requireString,
  runMain,
  sha256File,
  writeJsonAtomic,
} from "./lib.mjs";

const SCHEMA_VERSION = 10;
const PLATFORM = "windows-x86_64";
const RUNNER = "windows-2025";
const INSTALLER_TYPE = "nsis";
const OLD_MACHINE = "assm1-win-x64-e2b6cbcadd8b";
const OLD_DISTRIBUTION = "podman-assm1-win-x64-e2b6cbcadd8b";
const CURRENT_DEFAULT_MACHINE = "assm2-win-x64-e2b6cbcadd8b";
const ISOLATED_MACHINE_PREFIX = "assm2-iso-";
const OLD_VERSION_DIRECTORY = "podman-machine-5.8.2-8b2257ace33ecb14";
const GENERATION_SELECTION_SCHEMA = "ai-security-scanner.managed-wsl-generation-selection/v1";
const CANDIDATE_RUNTIME_MANIFEST_SHA256 =
  "c30195e26367a8612d600383e181e232bd9cd87a7e36332cc288aacca6b17833";
const CANDIDATE_VERSION = "0.1.10";
const SELF_TEST_SOURCE_COMMIT = "0123456789abcdef0123456789abcdef01234567";
const SENTINEL_LIFECYCLE_SCHEMA_VERSION = 1;
const SENTINEL_PHASES = Object.freeze([
  "fixture_ready",
  "before_candidate_install",
  "after_candidate_install",
  "after_same_version_reinstall",
  "before_candidate_runtime_start",
  "after_candidate_runtime_running",
  "after_current_runtime_purge",
  "before_app_only_uninstall",
]);
const SENTINEL_CHECKPOINT_FIELDS = Object.freeze([
  "phase",
  "observedAt",
  "distributionName",
  "registrationId",
  "windowsClientPid",
  "windowsClientStartedAt",
  "linuxBootId",
  "linuxPid",
  "linuxStartTicks",
  "tokenSha256",
]);
const SENTINEL_IDENTITY_FIELDS = Object.freeze([
  "distributionName",
  "registrationId",
  "windowsClientPid",
  "windowsClientStartedAt",
  "linuxBootId",
  "linuxPid",
  "linuxStartTicks",
  "tokenSha256",
]);
const CANONICAL_UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u;
const UTC_TIMESTAMP_PATTERN =
  /^([0-9]{4})-(0[1-9]|1[0-2])-([0-2][0-9]|3[01])T([01][0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9])(?:\.([0-9]{1,9}))?(Z|\+00:00)$/u;
const MAX_U64 = 18_446_744_073_709_551_615n;

export const PRIOR_GHOST_RELEASE = Object.freeze({
  version: "0.1.7",
  tag: "v0.1.7",
  installerFile: "ai-security-scanner_0.1.7_x64-setup.exe",
  installerBytes: 38_730_365,
  installerSha256: "4d2057ca4c008b46dc0195a792075e4b4b377c1909a7795b29efc30f9ae48b1a",
  downloadUrl:
    "https://github.com/teddashh/ai-security-scanner/releases/download/v0.1.7/ai-security-scanner_0.1.7_x64-setup.exe",
  runtimeManifestSha256:
    "8b2257ace33ecb14bb0995044a4e6d2b4e71b314741601122801fbb59e7de13f",
  machineImageSha256:
    "e2b6cbcadd8b41b708fecb58a246a20d737dee0ef26872a3f75b575f77eba968",
});

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function exactKeys(value, keys, label) {
  assert(value && typeof value === "object" && !Array.isArray(value), `${label} must be an object`);
  assert(
    JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...keys].sort()),
    `${label} fields changed`,
  );
}

function sha256(value, label) {
  assert(typeof value === "string" && /^[0-9a-f]{64}$/u.test(value), `${label} is not SHA-256`);
}

function isBoundedReleaseSelfTestFixture(artifactDirectory, commit) {
  if (commit !== SELF_TEST_SOURCE_COMMIT) return false;
  const fixtureRoot = path.resolve(PROJECT_ROOT, "target", "release-self-test");
  const relative = path.relative(fixtureRoot, artifactDirectory);
  return relative !== "" && relative !== ".." && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative);
}

function yes(value, label) {
  assert(value === true, `${label} was not proven`);
}

function bounded(value, minimum, maximum, label) {
  assert(Number.isSafeInteger(value) && value >= minimum && value <= maximum, `${label} is outside its bound`);
}

function canonicalUuid(value, label) {
  assert(typeof value === "string" && CANONICAL_UUID_PATTERN.test(value), `${label} is not a canonical UUID`);
}

function utcTimestampOrderKey(value, label) {
  assert(typeof value === "string", `${label} is not a string`);
  const match = value.match(UTC_TIMESTAMP_PATTERN);
  assert(match, `${label} is not a canonical UTC timestamp`);
  const [, yearText, monthText, dayText, hourText, minuteText, secondText, fraction = ""] = match;
  const year = Number(yearText);
  const month = Number(monthText);
  const day = Number(dayText);
  const hour = Number(hourText);
  const minute = Number(minuteText);
  const second = Number(secondText);
  assert(year >= 2000, `${label} is outside the supported UTC range`);
  const epochMilliseconds = Date.UTC(year, month - 1, day, hour, minute, second);
  const instant = new Date(epochMilliseconds);
  assert(
    instant.getUTCFullYear() === year &&
      instant.getUTCMonth() === month - 1 &&
      instant.getUTCDate() === day &&
      instant.getUTCHours() === hour &&
      instant.getUTCMinutes() === minute &&
      instant.getUTCSeconds() === second,
    `${label} is not a real UTC instant`,
  );
  const nanoseconds = BigInt(fraction.padEnd(9, "0"));
  return BigInt(Math.trunc(epochMilliseconds / 1000)) * 1_000_000_000n + nanoseconds;
}

function canonicalPositiveDecimal(value, label) {
  assert(
    typeof value === "string" && /^[1-9][0-9]{0,19}$/u.test(value),
    `${label} is not a canonical positive decimal string`,
  );
  const parsed = BigInt(value);
  assert(parsed <= MAX_U64, `${label} exceeds the unsigned 64-bit bound`);
}

function validateFileProof(value, label) {
  exactKeys(value, ["length", "sha256", "volume", "fileIndex"], label);
  bounded(value.length, 1, 64 * 1024, `${label} length`);
  sha256(value.sha256, `${label} digest`);
  bounded(value.volume, 0, 0xffff_ffff, `${label} volume`);
  canonicalPositiveDecimal(value.fileIndex, `${label} file index`);
}

function validateVhdFileProof(value, label) {
  exactKeys(value, [
    "length", "sha256", "volume", "fileIndex", "numberOfLinks", "attributes",
  ], label);
  bounded(value.length, 1, 64 * 1024 * 1024 * 1024, `${label} length`);
  sha256(value.sha256, `${label} digest`);
  bounded(value.volume, 0, 0xffff_ffff, `${label} volume`);
  canonicalPositiveDecimal(value.fileIndex, `${label} file index`);
  bounded(value.numberOfLinks, 1, 1024, `${label} link count`);
  bounded(value.attributes, 0, 0xffff_ffff, `${label} attributes`);
}

function validateWindowsNsisVhdPreservation(before, after, label) {
  validateVhdFileProof(before, `${label} before app-only uninstall`);
  validateVhdFileProof(after, `${label} after app-only uninstall`);
  for (const field of [
    "length", "sha256", "volume", "fileIndex", "numberOfLinks", "attributes",
  ]) {
    assert(
      after[field] === before[field],
      `app-only uninstall changed ${label} ${field}`,
    );
  }
}

export function validateWindowsNsisUnrelatedVhdPreservation(before, after) {
  validateWindowsNsisVhdPreservation(before, after, "unrelated WSL VHD");
}

export function validateWindowsNsisGenerationSelection(selection, identity) {
  exactKeys(selection, [
    "pathBoundToCandidateManifestAndGeneration",
    "recordPresent",
    "recordProtected",
    "recordBytes",
    "recordSha256",
    "schemaVersion",
    "authorizesCleanup",
    "manifestSha256",
    "machineImageSha256",
    "defaultMachineName",
    "selectedMachineName",
    "selectedMachineDeterministic",
    "generationIndex",
    "preservedCollisionNames",
    "recordPreservedAfterCurrentRuntimePurge",
    "recordPreservedThroughAppOnlyUninstall",
  ], "isolated-generation routing record");
  for (const field of [
    "pathBoundToCandidateManifestAndGeneration",
    "recordPresent",
    "recordProtected",
    "selectedMachineDeterministic",
    "recordPreservedAfterCurrentRuntimePurge",
    "recordPreservedThroughAppOnlyUninstall",
  ]) yes(selection[field], `isolated-generation routing record ${field}`);
  assert(selection.schemaVersion === GENERATION_SELECTION_SCHEMA, "generation selection schema changed");
  assert(selection.authorizesCleanup === false, "generation selection incorrectly grants cleanup authority");
  assert(selection.manifestSha256 === identity.runtimeManifestSha256, "generation selection is not bound to the candidate manifest");
  assert(selection.machineImageSha256 === identity.machineImageSha256, "generation selection is not bound to the candidate image");
  assert(selection.defaultMachineName === CURRENT_DEFAULT_MACHINE, "generation selection default machine is not assm2");
  assert(/^assm2-iso-[0-9a-f]{20}$/u.test(selection.selectedMachineName), "generation selection did not select a canonical isolated assm2 machine");
  assert(selection.selectedMachineName !== selection.defaultMachineName, "generation selection reused the compatibility machine");
  assert(selection.generationIndex === 1, "generation selection did not use the first isolated generation");
  assert(
    Array.isArray(selection.preservedCollisionNames) && selection.preservedCollisionNames.length === 0,
    "isolated-generation routing record unexpectedly claims a preserved current-generation collision",
  );
  bounded(selection.recordBytes, 1, 64 * 1024, "generation selection bytes");
  sha256(selection.recordSha256, "generation selection digest");
}

export function validateWindowsNsisGhostFixtureScope(scope) {
  exactKeys(scope, [
    "classification", "qualifiesPublicLifecycle", "syntheticCliCaseUsed", "installedDesktopInteractionObserved",
    "localhost1270019001ReportObserved", "projectReopenedInDesktopObserved",
    "postUninstallReinstallObserved",
  ], "registered-WSL ghost fixture scope");
  assert(scope.classification === "risk_focused_automated_data_preservation", "ghost fixture classification changed");
  assert(scope.syntheticCliCaseUsed === true, "ghost data-preservation fixture must disclose its synthetic CLI case");
  for (const field of [
    "qualifiesPublicLifecycle", "installedDesktopInteractionObserved",
    "localhost1270019001ReportObserved", "projectReopenedInDesktopObserved",
    "postUninstallReinstallObserved",
  ]) assert(scope[field] === false, `ghost data-preservation fixture cannot claim ${field}`);
}

export function validateWindowsNsisGhostInstallerManifestShape(installerManifest) {
  if (installerManifest.schemaVersion === 2) {
    exactKeys(installerManifest, [
      "schemaVersion", "product", "version", "tag", "sourceCommit", "platform",
      "requestedBundleTypes", "availableBundleTypes", "updaters", "updaterFailures",
      "installers", "auxiliaryExecutables",
    ], "source Windows installer manifest");
    for (const field of [
      "requestedBundleTypes", "availableBundleTypes", "updaters", "updaterFailures",
      "installers", "auxiliaryExecutables",
    ]) assert(Array.isArray(installerManifest[field]), `source Windows installer manifest ${field} is not an array`);
  } else if (installerManifest.schemaVersion === 3) {
    exactKeys(installerManifest, [
      "schemaVersion", "product", "version", "tag", "sourceCommit", "platform",
      "artifactScoped", "sourceManifestSha256", "installers", "auxiliaryExecutables", "updaters",
    ], "finalized Windows installer manifest");
    assert(installerManifest.artifactScoped === true, "finalized Windows installer manifest is not artifact-scoped");
    sha256(installerManifest.sourceManifestSha256, "finalized Windows source-manifest digest");
    for (const field of ["installers", "auxiliaryExecutables", "updaters"]) {
      assert(Array.isArray(installerManifest[field]), `finalized Windows installer manifest ${field} is not an array`);
    }
  } else {
    throw new Error("Windows installer manifest schema is unsupported");
  }
}

function sentinelIdentity(checkpoint) {
  return SENTINEL_IDENTITY_FIELDS.map((field) => checkpoint[field]);
}

function validateSentinelCheckpoints(checkpoints, expectedDistribution, expectedRegistration, label) {
  assert(Array.isArray(checkpoints), `${label} checkpoints must be an array`);
  assert(checkpoints.length === SENTINEL_PHASES.length, `${label} checkpoints are incomplete`);
  let baselineIdentity;
  let previousObservedAt;
  for (const [index, checkpoint] of checkpoints.entries()) {
    exactKeys(checkpoint, SENTINEL_CHECKPOINT_FIELDS, `${label} checkpoint ${index + 1}`);
    assert(checkpoint.phase === SENTINEL_PHASES[index], `${label} checkpoint phases are not exact and ordered`);
    const observedAt = utcTimestampOrderKey(
      checkpoint.observedAt,
      `${label} ${checkpoint.phase} observation time`,
    );
    if (previousObservedAt !== undefined) {
      assert(observedAt >= previousObservedAt, `${label} checkpoint timestamps are not monotonic`);
    }
    previousObservedAt = observedAt;
    assert(
      checkpoint.distributionName === expectedDistribution,
      `${label} checkpoint distribution identity changed`,
    );
    assert(
      checkpoint.registrationId === expectedRegistration,
      `${label} checkpoint registration identity changed`,
    );
    canonicalUuid(checkpoint.registrationId, `${label} checkpoint registration ID`);
    bounded(checkpoint.windowsClientPid, 1, 0xffffffff, `${label} Windows client PID`);
    utcTimestampOrderKey(checkpoint.windowsClientStartedAt, `${label} Windows client start time`);
    canonicalUuid(checkpoint.linuxBootId, `${label} Linux boot ID`);
    bounded(checkpoint.linuxPid, 1, 0x7fffffff, `${label} Linux PID`);
    canonicalPositiveDecimal(checkpoint.linuxStartTicks, `${label} Linux process start ticks`);
    sha256(checkpoint.tokenSha256, `${label} token digest`);
    const identity = sentinelIdentity(checkpoint);
    if (baselineIdentity === undefined) {
      baselineIdentity = identity;
    } else {
      assert(
        JSON.stringify(identity) === JSON.stringify(baselineIdentity),
        `${label} process identity changed across checkpoints`,
      );
    }
  }
  return baselineIdentity;
}

function validateSentinelLifecycle(lifecycle, fixture, sideBySide) {
  exactKeys(
    lifecycle,
    ["schemaVersion", "requiredPhases", "legacyCheckpoints", "unrelatedCheckpoints"],
    "sentinel lifecycle",
  );
  assert(
    lifecycle.schemaVersion === SENTINEL_LIFECYCLE_SCHEMA_VERSION,
    "sentinel lifecycle schema is unsupported",
  );
  assert(
    JSON.stringify(lifecycle.requiredPhases) === JSON.stringify(SENTINEL_PHASES),
    "sentinel lifecycle required phases changed",
  );
  const legacyIdentity = validateSentinelCheckpoints(
    lifecycle.legacyCheckpoints,
    sideBySide.legacyDistributionName,
    sideBySide.legacyRegistrationIdBefore,
    "legacy WSL sentinel",
  );
  const unrelatedIdentity = validateSentinelCheckpoints(
    lifecycle.unrelatedCheckpoints,
    sideBySide.unrelatedDistributionName,
    sideBySide.unrelatedRegistrationIdBefore,
    "unrelated WSL sentinel",
  );
  assert(
    sideBySide.legacyDistributionName === fixture.distributionName &&
      sideBySide.legacyRegistrationIdBefore === fixture.registrationId,
    "legacy sentinel lifecycle is not bound to the ghost fixture",
  );
  assert(
    sideBySide.unrelatedDistributionName === fixture.unrelatedDistributionName &&
      sideBySide.unrelatedRegistrationIdBefore === fixture.unrelatedRegistrationId,
    "unrelated sentinel lifecycle is not bound to the ghost fixture",
  );
  assert(
    JSON.stringify(legacyIdentity) !== JSON.stringify(unrelatedIdentity),
    "legacy and unrelated sentinels share one complete process identity",
  );
  assert(
    lifecycle.legacyCheckpoints[0].tokenSha256 !== lifecycle.unrelatedCheckpoints[0].tokenSha256,
    "legacy and unrelated sentinels share one token identity",
  );
  assert(
    lifecycle.legacyCheckpoints[0].windowsClientPid !==
      lifecycle.unrelatedCheckpoints[0].windowsClientPid,
    "legacy and unrelated sentinels share one Windows client process",
  );
}

async function candidateIdentity(
  artifactDirectory,
  version,
  tag,
  commit,
  expectedRuntimeManifestSha256,
) {
  const installerManifest = await readJson(
    path.join(artifactDirectory, "installers-windows-x86_64.json"),
  );
  validateWindowsNsisGhostInstallerManifestShape(installerManifest);
  assert(installerManifest.product === "ai-security-scanner", "Windows installer product is incorrect");
  assert(installerManifest.platform === PLATFORM, "Windows installer platform is incorrect");
  assert(
    installerManifest.version === version && installerManifest.tag === tag && installerManifest.sourceCommit === commit,
    "Windows installer release identity differs from the candidate",
  );
  const installers = installerManifest.installers?.filter((item) => item.bundleType === INSTALLER_TYPE) ?? [];
  assert(installers.length === 1, "candidate must contain exactly one NSIS installer");
  const installer = installers[0];
  exactKeys(installer, ["bundleType", "file", "bytes", "sha256"], "candidate NSIS record");
  assert(
    path.posix.basename(installer.file) === installer.file && path.win32.basename(installer.file) === installer.file,
    "candidate NSIS path is not flat",
  );
  bounded(installer.bytes, 1, 256 * 1024 * 1024, "candidate NSIS bytes");
  sha256(installer.sha256, "candidate NSIS digest");
  const installerPath = path.join(artifactDirectory, installer.file);
  const metadata = await lstat(installerPath);
  assert(metadata.isFile() && !metadata.isSymbolicLink(), "candidate NSIS is not a regular file");
  assert(metadata.size === installer.bytes, "candidate NSIS byte length changed");
  assert((await sha256File(installerPath)) === installer.sha256, "candidate NSIS digest changed");

  const runtimeFile = path.join(artifactDirectory, "managed-runtime-windows-x86_64.manifest.json");
  const runtimeMetadata = await lstat(runtimeFile);
  assert(runtimeMetadata.isFile() && !runtimeMetadata.isSymbolicLink(), "candidate runtime manifest is not regular");
  const runtime = await readJson(runtimeFile);
  assert(runtime.schema_version === "3", "candidate runtime manifest schema is unsupported");
  assert(
    runtime.management_contract_revision === "2026-08-29.1",
    "candidate runtime management contract revision is unsupported",
  );
  assert(runtime.bundle_id === "podman-machine" && runtime.runtime_version === "5.8.2", "candidate runtime identity changed");
  const targets = runtime.targets?.filter(
    (target) => target.operating_system === "windows" && target.architecture === "x86_64" && target.provider === "wsl",
  ) ?? [];
  assert(targets.length === 1, "candidate runtime must have one Windows x86_64 WSL target");
  sha256(targets[0].machine_image?.sha256, "candidate machine-image digest");
  const runtimeManifestSha256 = await sha256File(runtimeFile);
  assert(
    runtimeManifestSha256 === expectedRuntimeManifestSha256,
    "candidate runtime manifest differs from the reviewed Windows identity",
  );
  return {
    installer,
    runtimeManifestSha256,
    machineImageSha256: targets[0].machine_image.sha256,
    providerNamespace: runtimeManifestSha256.slice(0, 16),
  };
}

function validateObservations(observations, identity, version) {
  exactKeys(
    observations,
    [
      "schemaVersion",
      "scenario",
      "platform",
      "runner",
      "priorRelease",
      "candidate",
      "fixtureScope",
      "ghostFixture",
      "candidateInstallation",
      "runtimeSideBySide",
      "dataPreservation",
      "cleanup",
    ],
    "side-by-side ghost observations",
  );
  assert(observations.schemaVersion === SCHEMA_VERSION, "side-by-side ghost schema is unsupported");
  assert(
    observations.scenario === "automated_registered_wsl_n_minus_one_ghost_isolated_generation_fixture",
    "ghost data-preservation fixture scenario is incorrect",
  );
  assert(observations.platform === PLATFORM && observations.runner === RUNNER, "ghost runner is incorrect");
  validateWindowsNsisGhostFixtureScope(observations.fixtureScope);
  exactKeys(observations.priorRelease, Object.keys(PRIOR_GHOST_RELEASE), "prior ghost release");
  assert(
    JSON.stringify(observations.priorRelease) === JSON.stringify(PRIOR_GHOST_RELEASE),
    "prior ghost release differs from the immutable v0.1.7 pin",
  );

  exactKeys(
    observations.candidate,
    ["version", "installerFile", "installerBytes", "installerSha256", "runtimeManifestSha256", "machineImageSha256"],
    "ghost candidate",
  );
  const candidate = observations.candidate;
  assert(candidate.version === version, "ghost candidate version is wrong");
  assert(candidate.installerFile === identity.installer.file, "ghost candidate filename changed");
  assert(candidate.installerBytes === identity.installer.bytes, "ghost candidate bytes changed");
  assert(candidate.installerSha256 === identity.installer.sha256, "ghost candidate installer digest changed");
  assert(candidate.runtimeManifestSha256 === identity.runtimeManifestSha256, "ghost candidate runtime digest changed");
  assert(candidate.machineImageSha256 === identity.machineImageSha256, "ghost candidate image digest changed");

  const fixture = observations.ghostFixture;
  exactKeys(
    fixture,
    [
      "defaultInstallDirectoryUsed",
      "canonicalProductDataCurrentUserOwner",
      "priorCliVersion",
      "oldRegistryIdentityExact",
      "oldRuntimeInstalled",
      "oldRuntimeStarted",
      "oldRuntimeStopped",
      "oldProviderNamespace",
      "oldProviderCryptographicIdentityPresent",
      "distributionName",
      "registrationId",
      "registeredWslStateExercised",
      "registrationBoundToOldProvider",
      "missingVersionsManifestExercised",
      "oldVersionDirectory",
      "oldVersionPayloadDigestVerifiedBeforeRemoval",
      "oldVersionPayloadDirectoryRemoved",
      "oldDesktopRemoved",
      "oldUninstallerRemoved",
      "unrelatedDistributionName",
      "unrelatedRegistrationId",
    ],
    "real ghost fixture",
  );
  yes(fixture.defaultInstallDirectoryUsed, "default NSIS install directory");
  yes(fixture.canonicalProductDataCurrentUserOwner, "canonical product data current-user owner");
  assert(fixture.priorCliVersion === PRIOR_GHOST_RELEASE.version, "ghost fixture CLI is not v0.1.7");
  for (const field of [
    "oldRegistryIdentityExact",
    "oldRuntimeInstalled",
    "oldRuntimeStarted",
    "oldRuntimeStopped",
    "oldProviderCryptographicIdentityPresent",
    "registeredWslStateExercised",
    "registrationBoundToOldProvider",
    "missingVersionsManifestExercised",
    "oldVersionPayloadDigestVerifiedBeforeRemoval",
    "oldVersionPayloadDirectoryRemoved",
    "oldDesktopRemoved",
    "oldUninstallerRemoved",
  ]) yes(fixture[field], "ghost fixture " + field);
  assert(
    fixture.oldProviderNamespace === PRIOR_GHOST_RELEASE.runtimeManifestSha256.slice(0, 16),
    "ghost fixture provider namespace is not pinned N-1",
  );
  assert(fixture.distributionName === OLD_DISTRIBUTION, "ghost fixture distribution is not deterministic N-1");
  assert(fixture.oldVersionDirectory === OLD_VERSION_DIRECTORY, "ghost fixture removed the wrong versions entry");
  assert(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u.test(fixture.registrationId), "legacy registration ID is not canonical");
  assert(/^ai-security-scanner-unrelated-[0-9a-f]{32}$/u.test(fixture.unrelatedDistributionName), "unrelated WSL fixture name is malformed");
  assert(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u.test(fixture.unrelatedRegistrationId), "unrelated registration ID is not canonical");

  const installation = observations.candidateInstallation;
  exactKeys(
    installation,
    [
      "candidateInstallerCompleted",
      "candidateCliVersion",
      "registryVersionUpdated",
      "registryIdentityExact",
      "versionNeutralInstallCompleted",
      "candidateDesktopRestored",
      "candidateUninstallerRestored",
      "candidateRuntimeResourceMatchesRelease",
      "exactPrivateDataSnapshotPreserved",
      "sameVersionSilentReinstallCompleted",
      "sameVersionReinstallRemainedVersionNeutral",
    ],
    "candidate installation",
  );
  for (const field of [
    "candidateInstallerCompleted",
    "registryVersionUpdated",
    "registryIdentityExact",
    "versionNeutralInstallCompleted",
    "candidateDesktopRestored",
    "candidateUninstallerRestored",
    "candidateRuntimeResourceMatchesRelease",
    "exactPrivateDataSnapshotPreserved",
    "sameVersionSilentReinstallCompleted",
    "sameVersionReinstallRemainedVersionNeutral",
  ]) yes(installation[field], "candidate installation " + field);
  assert(installation.candidateCliVersion === version, "version-neutral installation did not install the candidate CLI");

  const sideBySide = observations.runtimeSideBySide;
  exactKeys(
    sideBySide,
    [
      "startSucceeded",
      "noManualActionFallback",
      "runningAndAvailable",
      "legacyMachineName",
      "legacyDistributionName",
      "legacyRegistrationIdBefore",
      "legacyRegistrationIdAfter",
      "legacyRegistrationBasePathExact",
      "legacyProviderRetained",
      "legacyProviderNamespace",
      "legacyVhdIdentityPreserved",
      "legacyProviderProofFilesPreserved",
      "currentMachineName",
      "currentDistributionName",
      "currentRegistrationId",
      "currentRegistrationBasePathExact",
      "currentProviderNamespace",
      "currentProviderCreated",
      "unrelatedDistributionName",
      "unrelatedRegistrationIdBefore",
      "unrelatedRegistrationIdAfter",
      "unrelatedRegistrationBasePathExact",
      "noQuarantineDistributionCreated",
      "sentinelLifecycle",
      "generationSelection",
      "noVersionedReceipt",
      "legacyWorkspaceAfterAppOnlyUninstall",
      "unrelatedWorkspaceAfterAppOnlyUninstall",
    ],
    "managed-runtime side-by-side initialization",
  );
  for (const field of [
    "startSucceeded",
    "noManualActionFallback",
    "runningAndAvailable",
    "legacyRegistrationBasePathExact",
    "legacyProviderRetained",
    "legacyVhdIdentityPreserved",
    "legacyProviderProofFilesPreserved",
    "currentRegistrationBasePathExact",
    "currentProviderCreated",
    "unrelatedRegistrationBasePathExact",
    "noQuarantineDistributionCreated",
  ]) yes(sideBySide[field], "runtime side-by-side " + field);
  assert(sideBySide.legacyMachineName === OLD_MACHINE, "legacy machine epoch changed");
  assert(sideBySide.legacyDistributionName === OLD_DISTRIBUTION, "legacy distribution changed");
  assert(sideBySide.legacyRegistrationIdBefore === fixture.registrationId, "legacy registration does not match fixture");
  assert(sideBySide.legacyRegistrationIdAfter === sideBySide.legacyRegistrationIdBefore, "legacy registration GUID changed");
  assert(
    sideBySide.legacyProviderNamespace === PRIOR_GHOST_RELEASE.runtimeManifestSha256.slice(0, 16),
    "legacy provider namespace changed",
  );
  assert(/^assm2-iso-[0-9a-f]{20}$/u.test(sideBySide.currentMachineName), "candidate did not use a canonical isolated assm2 machine");
  assert(sideBySide.currentDistributionName === `podman-${sideBySide.currentMachineName}`, "candidate distribution is not bound to its isolated machine");
  assert(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u.test(sideBySide.currentRegistrationId), "current registration ID is not canonical");
  const isolatedSuffix = sideBySide.currentMachineName.slice(ISOLATED_MACHINE_PREFIX.length);
  assert(
    sideBySide.currentProviderNamespace ===
      `${identity.runtimeManifestSha256.slice(0, 8)}-iso-${isolatedSuffix.slice(0, 12)}`,
    "current provider namespace is not bound to the selected isolated generation",
  );
  assert(sideBySide.unrelatedDistributionName === fixture.unrelatedDistributionName, "unrelated distribution identity changed");
  assert(sideBySide.unrelatedRegistrationIdBefore === fixture.unrelatedRegistrationId, "unrelated registration does not match fixture");
  assert(sideBySide.unrelatedRegistrationIdAfter === sideBySide.unrelatedRegistrationIdBefore, "unrelated registration GUID changed");
  validateSentinelLifecycle(sideBySide.sentinelLifecycle, fixture, sideBySide);

  validateWindowsNsisGenerationSelection(sideBySide.generationSelection, identity);

  exactKeys(sideBySide.noVersionedReceipt, [
    "beforeCandidateInstall",
    "afterCandidateInstall",
    "afterSameVersionReinstall",
    "beforeRuntimeStart",
    "afterRuntimeStart",
  ], "version-neutral installation state");
  for (const [name, value] of Object.entries(sideBySide.noVersionedReceipt)) {
    yes(value, `version-neutral installation state ${name}`);
  }

  const afterUninstall = sideBySide.legacyWorkspaceAfterAppOnlyUninstall;
  exactKeys(afterUninstall, [
    "registrationIdBefore",
    "registrationIdAfter",
    "providerConfigSha256Before",
    "providerConfigSha256After",
    "sshPublicKeySha256Before",
    "sshPublicKeySha256After",
    "vhdBeforeAppOnlyUninstall",
    "vhdAfterAppOnlyUninstall",
  ], "legacy workspace after app-only uninstall");
  assert(
    afterUninstall.registrationIdBefore === fixture.registrationId &&
      afterUninstall.registrationIdAfter === afterUninstall.registrationIdBefore,
    "app-only uninstall changed the legacy registration GUID",
  );
  sha256(afterUninstall.providerConfigSha256Before, "legacy provider config digest before uninstall");
  sha256(afterUninstall.providerConfigSha256After, "legacy provider config digest after uninstall");
  sha256(afterUninstall.sshPublicKeySha256Before, "legacy SSH public-key digest before uninstall");
  sha256(afterUninstall.sshPublicKeySha256After, "legacy SSH public-key digest after uninstall");
  assert(
    afterUninstall.providerConfigSha256After === afterUninstall.providerConfigSha256Before &&
      afterUninstall.sshPublicKeySha256After === afterUninstall.sshPublicKeySha256Before,
    "app-only uninstall changed the retained provider config or machine.pub digest",
  );
  validateWindowsNsisVhdPreservation(
    afterUninstall.vhdBeforeAppOnlyUninstall,
    afterUninstall.vhdAfterAppOnlyUninstall,
    "legacy WSL VHD",
  );

  const unrelatedAfterUninstall = sideBySide.unrelatedWorkspaceAfterAppOnlyUninstall;
  exactKeys(unrelatedAfterUninstall, [
    "registrationIdBefore", "registrationIdAfter",
    "vhdBeforeAppOnlyUninstall", "vhdAfterAppOnlyUninstall",
  ], "unrelated workspace after app-only uninstall");
  assert(
    unrelatedAfterUninstall.registrationIdBefore === fixture.unrelatedRegistrationId &&
      unrelatedAfterUninstall.registrationIdAfter === unrelatedAfterUninstall.registrationIdBefore,
    "app-only uninstall changed the unrelated WSL registration GUID",
  );
  validateWindowsNsisUnrelatedVhdPreservation(
    unrelatedAfterUninstall.vhdBeforeAppOnlyUninstall,
    unrelatedAfterUninstall.vhdAfterAppOnlyUninstall,
  );

  const data = observations.dataPreservation;
  exactKeys(
    data,
    [
      "preInstallerFileCount",
      "preInstallerBytes",
      "demoCaseId",
      "demoRunId",
      "demoCasePreserved",
      "existingExportIdentity",
      "beginnerReportExport",
      "appOnlyUninstallSnapshot",
    ],
    "ghost data preservation",
  );
  bounded(data.preInstallerFileCount, 1, 4096, "ghost data file count");
  bounded(data.preInstallerBytes, 1, 512 * 1024 * 1024, "ghost data bytes");
  canonicalUuid(data.demoCaseId, "ghost demo case ID");
  canonicalUuid(data.demoRunId, "ghost demo run ID");
  yes(data.demoCasePreserved, "ghost demo case preservation");

  const exportIdentity = data.existingExportIdentity;
  exactKeys(exportIdentity, [
    "fixtureSha256", "initial", "afterUpgrade", "afterReinstall", "afterReportExport", "afterAppOnlyUninstall",
  ], "existing export identity preservation");
  assert(exportIdentity.fixtureSha256 === "630dcd2966c4336691125448bbb25b4ff412a49c732db2c8abc1b8581bd710dd", "existing export identity fixture digest changed");
  for (const field of ["initial", "afterUpgrade", "afterReinstall", "afterReportExport", "afterAppOnlyUninstall"]) {
    validateFileProof(exportIdentity[field], `existing export identity ${field}`);
    assert(JSON.stringify(exportIdentity[field]) === JSON.stringify(exportIdentity.initial), `existing export identity ${field} changed bytes or NTFS identity`);
  }
  assert(exportIdentity.initial.length === 32 && exportIdentity.initial.sha256 === exportIdentity.fixtureSha256, "existing export identity is not the exact 32-byte fixture");

  const report = data.beginnerReportExport;
  exactKeys(report, ["receipt", "independentFile"], "beginner report export evidence");
  const receipt = report.receipt;
  exactKeys(receipt, [
    "id", "case_id", "run_id", "created_at", "format", "path", "sha256",
    "coverage_manifest_path", "coverage_manifest_sha256", "signature", "public_key",
    "redaction_profile", "raw_artifacts_included", "raw_artifacts_omitted",
    "integrity_only_notice",
  ], "raw CLI CaseExport receipt");
  canonicalUuid(receipt.id, "beginner report export ID");
  canonicalUuid(receipt.case_id, "beginner report case ID");
  canonicalUuid(receipt.run_id, "beginner report run ID");
  assert(
    receipt.case_id === data.demoCaseId && receipt.run_id === data.demoRunId && receipt.format === "html",
    "beginner report receipt is for the wrong seeded case, run, or format",
  );
  assert(typeof receipt.created_at === "string" && Number.isFinite(Date.parse(receipt.created_at)), "beginner report creation time is invalid");
  assert(
    typeof receipt.path === "string" && path.win32.isAbsolute(receipt.path) &&
      path.win32.basename(receipt.path) === "beginner-report.html",
    "beginner report runner destination is not one exact absolute Windows path",
  );
  sha256(receipt.sha256, "beginner report CLI digest");
  assert(receipt.coverage_manifest_path === null && receipt.coverage_manifest_sha256 === null, "HTML export unexpectedly has a companion coverage manifest");
  assert(receipt.signature === null && receipt.public_key === null, "ordinary beginner report unexpectedly carries signing fields");
  assert(receipt.redaction_profile === "standard", "beginner report did not use standard redaction");
  assert(receipt.raw_artifacts_included === 0, "beginner report unexpectedly includes raw artifacts");
  bounded(receipt.raw_artifacts_omitted, 0, 4096, "beginner report omitted raw-artifact count");
  assert(typeof receipt.integrity_only_notice === "string" && receipt.integrity_only_notice.length > 0, "beginner report integrity notice is absent");
  exactKeys(report.independentFile, ["file", "bytes", "sha256"], "independent beginner report file proof");
  assert(report.independentFile.file === "beginner-report.html", "beginner report portable artifact filename changed");
  assert(path.win32.basename(receipt.path) === report.independentFile.file, "CLI receipt and portable report filename differ");
  bounded(report.independentFile.bytes, 1, 16 * 1024 * 1024, "beginner report bytes");
  sha256(report.independentFile.sha256, "independent beginner report digest");
  assert(receipt.sha256 === report.independentFile.sha256, "CLI and independent beginner report digests differ");

  const uninstall = data.appOnlyUninstallSnapshot;
  exactKeys(uninstall, [
    "beforeFileCount", "afterFileCount", "beforeBytes", "afterBytes", "beforeDigest", "afterDigest",
    "processLeaseBefore", "processLeaseAfter", "allNonLeaseProductDataPreserved",
  ], "app-only uninstall non-lease product-data snapshot");
  bounded(uninstall.beforeFileCount, 1, 4096, "pre-uninstall non-lease file count");
  bounded(uninstall.afterFileCount, 1, 4096, "post-uninstall non-lease file count");
  bounded(uninstall.beforeBytes, 1, 64 * 1024 * 1024 * 1024, "pre-uninstall non-lease product-data bytes");
  bounded(uninstall.afterBytes, 1, 64 * 1024 * 1024 * 1024, "post-uninstall non-lease product-data bytes");
  sha256(uninstall.beforeDigest, "pre-uninstall non-lease product-data digest");
  sha256(uninstall.afterDigest, "post-uninstall non-lease product-data digest");
  for (const field of ["processLeaseBefore", "processLeaseAfter"]) {
    const proof = uninstall[field];
    exactKeys(proof, ["length", "sha256", "volume", "fileIndex"], `app-only uninstall ${field}`);
    assert(proof.length === 0, `app-only uninstall ${field} is not empty`);
    assert(proof.sha256 === "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", `app-only uninstall ${field} has unexpected bytes`);
    bounded(proof.volume, 0, 0xffff_ffff, `app-only uninstall ${field} volume`);
    canonicalPositiveDecimal(proof.fileIndex, `app-only uninstall ${field} file index`);
  }
  assert(JSON.stringify(uninstall.processLeaseAfter) === JSON.stringify(uninstall.processLeaseBefore), "app-only uninstall replaced the root process lease");
  yes(uninstall.allNonLeaseProductDataPreserved, "app-only uninstall non-lease product-data preservation");
  assert(uninstall.beforeFileCount === uninstall.afterFileCount && uninstall.beforeBytes === uninstall.afterBytes && uninstall.beforeDigest === uninstall.afterDigest, "app-only uninstall changed non-lease product data");

  exactKeys(
    observations.cleanup,
    [
      "currentRuntimePurged",
      "currentDistributionAbsent",
      "legacyDistributionRetainedThroughRuntimePurge",
      "unrelatedDistributionRetainedThroughRuntimePurge",
      "generationSelectionPreservedThroughRuntimePurge",
      "generationSelectionPreservedThroughAppOnlyUninstall",
      "legacyDataPreservedThroughNsisUninstall",
      "uninstallerInvoked",
      "productRegistryRemovedByUninstaller",
      "fixtureTeardownRemovedLegacy",
      "fixtureTeardownRemovedUnrelated",
      "quarantineDistributionsAbsent",
      "fixtureTeardownInstallDirectoryRemoved",
      "fixtureTeardownPrivateDataRemoved",
    ],
    "ghost side-by-side fixture teardown",
  );
  for (const [name, value] of Object.entries(observations.cleanup)) yes(value, "ghost cleanup " + name);
}

async function validateBeginnerReport(file, observation) {
  const absolute = path.resolve(file);
  const { receipt, independentFile } = observation;
  assert(path.basename(absolute) === independentFile.file, "beginner report portable artifact filename changed");
  const metadata = await lstat(absolute);
  assert(metadata.isFile() && !metadata.isSymbolicLink(), "beginner report is not a regular file");
  assert(metadata.size === independentFile.bytes, "beginner report byte length differs from the independent proof");
  assert((await sha256File(absolute)) === receipt.sha256 && receipt.sha256 === independentFile.sha256, "beginner report digest differs from the CLI receipt or independent proof");
  const html = await readFile(absolute, "utf8");
  for (const marker of [
    "<!doctype html><html lang=\"en\">",
    "ai-security-scanner / local case export",
    `<p>Selected run <code>${receipt.run_id}</code></p>`,
    "<h2>What you asked to scan</h2>",
    "<h2>What was actually tested</h2>",
    "<h2>What was not tested</h2>",
    "<section><h2>What to do next</h2>",
    "<h2>Problems found</h2>",
    "Integrity: unsigned HTML with SHA-256 retained in the local case.",
  ]) assert(html.includes(marker), `beginner report is missing required structure: ${marker}`);
}

async function identityFromArgs(args) {
  const artifactDirectory = path.resolve(requireString(args, "artifact-dir"));
  const version = requireString(args, "version");
  const tag = requireString(args, "tag");
  const commit = requireString(args, "commit");
  assert(
    isSemver(version) && version === CANDIDATE_VERSION && tag === `v${version}`,
    `candidate version/tag is not the bounded ${CANDIDATE_VERSION} isolation fixture`,
  );
  assert(/^[0-9a-f]{40}$/u.test(commit), "candidate commit is not a full lowercase Git object ID");
  const testOnlyRuntimeManifestSha256 = args.get("test-only-runtime-manifest-sha256");
  let expectedRuntimeManifestSha256 = CANDIDATE_RUNTIME_MANIFEST_SHA256;
  if (testOnlyRuntimeManifestSha256 !== undefined) {
    assert(
      typeof testOnlyRuntimeManifestSha256 === "string" &&
        /^[0-9a-f]{64}$/u.test(testOnlyRuntimeManifestSha256),
      "test-only runtime manifest identity is malformed",
    );
    assert(
      isBoundedReleaseSelfTestFixture(artifactDirectory, commit),
      "test-only runtime identity is restricted to the bounded release self-test fixture",
    );
    expectedRuntimeManifestSha256 = testOnlyRuntimeManifestSha256;
  }
  return {
    artifactDirectory,
    version,
    tag,
    commit,
    candidate: await candidateIdentity(
      artifactDirectory,
      version,
      tag,
      commit,
      expectedRuntimeManifestSha256,
    ),
  };
}

async function create(args) {
  const identity = await identityFromArgs(args);
  const observationsFile = path.resolve(requireString(args, "observations"));
  const metadata = await lstat(observationsFile);
  assert(
    metadata.isFile() && !metadata.isSymbolicLink() && metadata.size > 0 && metadata.size <= 256 * 1024,
    "ghost observations are not one bounded regular file",
  );
  const observations = JSON.parse(await readFile(observationsFile, "utf8"));
  validateObservations(observations, identity.candidate, identity.version);
  await validateBeginnerReport(requireString(args, "beginner-report"), observations.dataPreservation.beginnerReportExport);
  const evidence = {
    schemaVersion: SCHEMA_VERSION,
    qualification: "windows_nsis_registered_wsl_ghost_isolated_generation_fixture",
    releaseIdentity: {
      product: "ai-security-scanner",
      version: identity.version,
      tag: identity.tag,
      sourceCommit: identity.commit,
    },
    platform: PLATFORM,
    runner: RUNNER,
    installerType: INSTALLER_TYPE,
    fixtureScope: { ...observations.fixtureScope },
    candidateInstaller: { ...identity.candidate.installer },
    candidateRuntime: {
      manifestSha256: identity.candidate.runtimeManifestSha256,
      machineImageSha256: identity.candidate.machineImageSha256,
      providerNamespace: identity.candidate.providerNamespace,
    },
    priorReleasePin: { ...PRIOR_GHOST_RELEASE },
    observations,
  };
  await writeJsonAtomic(path.resolve(requireString(args, "out")), evidence);
  process.stdout.write("Created registered-WSL ghost data-preservation fixture evidence\n");
}

async function validate(args) {
  const identity = await identityFromArgs(args);
  const file = path.resolve(requireString(args, "file"));
  const metadata = await lstat(file);
  assert(metadata.isFile() && !metadata.isSymbolicLink() && metadata.size <= 256 * 1024, "ghost evidence is not bounded");
  const evidence = JSON.parse(await readFile(file, "utf8"));
  exactKeys(
    evidence,
    [
      "schemaVersion",
      "qualification",
      "releaseIdentity",
      "platform",
      "runner",
      "installerType",
      "fixtureScope",
      "candidateInstaller",
      "candidateRuntime",
      "priorReleasePin",
      "observations",
    ],
    "ghost-isolation evidence",
  );
  assert(evidence.schemaVersion === SCHEMA_VERSION, "ghost evidence schema is unsupported");
  assert(
    evidence.qualification === "windows_nsis_registered_wsl_ghost_isolated_generation_fixture",
    "ghost data-preservation fixture evidence ID is wrong",
  );
  exactKeys(evidence.releaseIdentity, ["product", "version", "tag", "sourceCommit"], "ghost release identity");
  assert(
    JSON.stringify(evidence.releaseIdentity) === JSON.stringify({
      product: "ai-security-scanner",
      version: identity.version,
      tag: identity.tag,
      sourceCommit: identity.commit,
    }),
    "ghost evidence release identity changed",
  );
  assert(evidence.platform === PLATFORM && evidence.runner === RUNNER && evidence.installerType === INSTALLER_TYPE, "ghost evidence execution identity changed");
  validateWindowsNsisGhostFixtureScope(evidence.fixtureScope);
  assert(
    JSON.stringify(evidence.fixtureScope) === JSON.stringify(evidence.observations.fixtureScope),
    "ghost fixture scope differs between evidence and observations",
  );
  assert(JSON.stringify(evidence.candidateInstaller) === JSON.stringify(identity.candidate.installer), "ghost evidence installer binding changed");
  assert(
    JSON.stringify(evidence.candidateRuntime) === JSON.stringify({
      manifestSha256: identity.candidate.runtimeManifestSha256,
      machineImageSha256: identity.candidate.machineImageSha256,
      providerNamespace: identity.candidate.providerNamespace,
    }),
    "ghost evidence runtime binding changed",
  );
  assert(JSON.stringify(evidence.priorReleasePin) === JSON.stringify(PRIOR_GHOST_RELEASE), "ghost evidence prior pin changed");
  validateObservations(evidence.observations, identity.candidate, identity.version);
  await validateBeginnerReport(requireString(args, "beginner-report"), evidence.observations.dataPreservation.beginnerReportExport);
  process.stdout.write(`Validated registered-WSL ghost data-preservation fixture for ${identity.tag}\n`);
  return evidence;
}

export async function validateWindowsNsisGhostDataPreservationFixtureFile({
  file,
  artifactDirectory,
  version,
  tag,
  commit,
  testOnlyRuntimeManifestSha256,
  beginnerReportFile,
}) {
  const args = new Map([
    ["file", file],
    ["artifact-dir", artifactDirectory],
    ["version", version],
    ["tag", tag],
    ["commit", commit],
    ["beginner-report", beginnerReportFile],
  ]);
  if (testOnlyRuntimeManifestSha256 !== undefined) {
    args.set("test-only-runtime-manifest-sha256", testOnlyRuntimeManifestSha256);
  }
  return validate(args);
}

async function main() {
  const [command, ...rest] = process.argv.slice(2);
  const args = parseArgs(rest);
  if (command === "create") return create(args);
  if (command === "validate") return validate(args);
  throw new Error("usage: windows-nsis-ghost-recovery-evidence.mjs <create|validate> --artifact-dir <dir> --version <semver> --tag <tag> --commit <sha> --beginner-report <beginner-report.html> [--observations <json>|--file <json>] [--out <json>]");
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  runMain(main);
}
