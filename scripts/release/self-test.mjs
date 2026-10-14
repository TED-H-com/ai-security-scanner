import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import {
  copyFile,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rename,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { UPDATER_DOWNLOAD_REPOSITORY } from "../publication-origins.mjs";
import { PROJECT_ROOT, isSemver, readJson, runMain, sha256File, toPosix } from "./lib.mjs";
import { createPlatformQualification } from "./platform-qualification.mjs";
import { createReleaseCandidateLock } from "./release-candidate-lock.mjs";
import { publishedReleaseAssetName } from "./release-asset-name.mjs";
import { createPreparedReleaseMetadata } from "./release-metadata.mjs";
import { verifyUpdaterSignatures } from "./verify-updater-signatures.mjs";
import {
  WINDOWS_EXTERNAL_EVIDENCE_RECEIPT_FILE,
  WINDOWS_HUMAN_PATH_FILE,
  WINDOWS_UNSIGNED_SIGNING_OBSERVATION_FILE,
  importWindowsExternalEvidence,
  materializeWindowsExternalEvidence,
  windowsExternalEvidenceImporterIdentity,
} from "./windows-external-evidence.mjs";

const VERSION = JSON.parse(
  readFileSync(path.join(PROJECT_ROOT, "package.json"), "utf8"),
).version;
const GITLEAKS_RELEASE = JSON.parse(
  readFileSync(path.join(PROJECT_ROOT, "engines", "catalog.json"), "utf8"),
).find((engine) => engine?.id === "gitleaks");
if (!GITLEAKS_RELEASE?.image?.repository || !/^sha256:[0-9a-f]{64}$/u.test(GITLEAKS_RELEASE.image.digest ?? "")) {
  throw new Error("release self-test requires the immutable managed Gitleaks catalog image");
}
const EXPECTED_QUALIFICATION_IMAGE =
  `${GITLEAKS_RELEASE.image.repository}@${GITLEAKS_RELEASE.image.digest}`;
const GATEWAY_RELEASE_MANIFEST = JSON.parse(
  readFileSync(
    path.join(PROJECT_ROOT, "runtime", "managed-egress-gateway.json"),
    "utf8",
  ),
);
const EXPECTED_GATEWAY_IMAGE =
  `${GATEWAY_RELEASE_MANIFEST.image.repository}@${GATEWAY_RELEASE_MANIFEST.image.digest}`;
const TAG = `v${VERSION}`;
const COMMIT = "0123456789abcdef0123456789abcdef01234567";
const TEST_KEY_PASSWORD = "release-self-test-only";
const TAURI_CLI = path.join(PROJECT_ROOT, "node_modules", "@tauri-apps", "cli", "tauri.js");
let releasePolicyFixture = null;
function run(script, arguments_) {
  const policyArguments = releasePolicyFixture && [
    "finalize-release.mjs",
    "verify-finalized-release.mjs",
  ].includes(script)
    ? ["--package-json", releasePolicyFixture]
    : [];
  execFileSync(process.execPath, [
    path.join(PROJECT_ROOT, "scripts/release", script),
    ...arguments_,
    ...policyArguments,
  ], {
    cwd: PROJECT_ROOT,
    stdio: "inherit",
  });
}

function tauriSigner(arguments_) {
  execFileSync(process.execPath, [TAURI_CLI, "signer", ...arguments_], {
    cwd: PROJECT_ROOT,
    stdio: "ignore",
  });
}

function expectFailure(action, label) {
  try {
    action();
  } catch {
    return;
  }
  throw new Error(`${label} unexpectedly passed`);
}

async function createFixtureSymlink(target, link) {
  try {
    await symlink(target, link);
  } catch (error) {
    if (process.platform !== "win32" || error?.code !== "EPERM") throw error;

    // Creating file symlinks on Windows normally requires Developer Mode or an
    // elevated token. A directory junction still exercises lstat's symlink
    // boundary without making the release self-test depend on host policy.
    const junctionTarget = `${link}.junction-target`;
    await mkdir(junctionTarget, { recursive: true });
    await symlink(junctionTarget, link, "junction");
  }

  const metadata = await lstat(link);
  if (!metadata.isSymbolicLink()) {
    throw new Error(`release self-test fixture is not a symlink: ${link}`);
  }
}

export async function createPlatformFixture(
  root,
  platform,
  kinds,
  signingKey,
  macUpdaterName = "ai-security-scanner.app.tar.gz",
  replaceInstallerWithSymlink = false,
  requestedKinds = kinds.map(([kind]) => kind),
  signUpdaters = true,
) {
  const bundleRoot = path.join(root, `bundle-${platform}`);
  for (const [kind, filename] of kinds) {
    const directory = path.join(bundleRoot, kind);
    await mkdir(directory, { recursive: true });
    await writeFile(
      path.join(directory, filename),
      Buffer.concat([
        Buffer.from(`fixture:${platform}:${kind}:${VERSION}\n`),
        Buffer.alloc(2048, `${platform}:${kind}`),
      ]),
    );
  }
  let updaterPayloads;
  if (platform === "linux-x86_64") {
    const appimage = kinds.find(([candidate]) => candidate === "appimage");
    updaterPayloads = appimage ? [path.join(bundleRoot, "appimage", appimage[1])] : [];
  } else if (platform === "windows-x86_64") {
    const nsis = kinds.find(([candidate]) => candidate === "nsis");
    updaterPayloads = nsis ? [path.join(bundleRoot, "nsis", nsis[1])] : [];
  } else {
    const macos = path.join(bundleRoot, "macos");
    await mkdir(macos, { recursive: true });
    // Match Tauri's real macOS updater output: the `.app` name intentionally
    // omits the version. Collection must publish a canonical versioned asset.
    const updaterPayload = path.join(macos, macUpdaterName);
    await writeFile(updaterPayload, Buffer.alloc(4096, "macos-universal-updater"));
    updaterPayloads = [updaterPayload];
  }
  const stagingDirectory =
    platform === "linux-x86_64"
      ? path.join(bundleRoot, "appimage", "ai-security-scanner.AppDir")
      : platform === "macos-universal"
        ? path.join(bundleRoot, "macos", "ai-security-scanner.app", "Contents", "Resources")
        : null;
  if (stagingDirectory) {
    await mkdir(stagingDirectory, { recursive: true });
    await writeFile(path.join(stagingDirectory, "application-icon.png"), Buffer.alloc(2048, "icon"));
    await createFixtureSymlink("application-icon.png", path.join(stagingDirectory, ".DirIcon"));
  }
  if (signUpdaters) {
    for (const updaterPayload of updaterPayloads) {
      tauriSigner([
        "sign",
        "--private-key-path",
        signingKey,
        "--password",
        TEST_KEY_PASSWORD,
        updaterPayload,
      ]);
    }
  }
  if (replaceInstallerWithSymlink) {
    const [kind, filename] = kinds[0];
    const installer = path.join(bundleRoot, kind, filename);
    const regularTarget = `${installer}.regular`;
    await rename(installer, regularTarget);
    await createFixtureSymlink(path.basename(regularTarget), installer);
  }
  const sidecarExtension = platform === "windows-x86_64" ? ".exe" : "";
  const magic =
    platform === "windows-x86_64"
      ? Buffer.from([0x4d, 0x5a, 0, 0])
      : platform === "macos-universal"
        ? Buffer.from([0xca, 0xfe, 0xba, 0xbe])
        : Buffer.from([0x7f, 0x45, 0x4c, 0x46]);
  const egressSidecar = path.join(root, `egress-sidecar-${platform}${sidecarExtension}`);
  const bootstrapBroker = path.join(root, `bootstrap-broker-${platform}${sidecarExtension}`);
  const caseworkCli = path.join(root, `casework-cli-${platform}${sidecarExtension}`);
  await writeFile(egressSidecar, Buffer.concat([magic, Buffer.alloc(4096, platform.length)]));
  await writeFile(bootstrapBroker, Buffer.concat([magic, Buffer.alloc(4096, platform.length + 1)]));
  await writeFile(caseworkCli, Buffer.concat([magic, Buffer.alloc(4096, platform.length + 2)]));
  const output = path.join(root, `output-${platform}`);
  run("collect-bundles.mjs", [
    "--bundle-root",
    bundleRoot,
    "--out",
    output,
    "--platform",
    platform,
    "--expect",
    requestedKinds.join(","),
    "--available",
    kinds.map(([kind]) => kind).join(","),
    "--egress-sidecar",
    egressSidecar,
    "--bootstrap-broker",
    bootstrapBroker,
    "--casework-cli",
    caseworkCli,
    "--version",
    VERSION,
    "--tag",
    TAG,
    "--commit",
    COMMIT,
  ]);
  const runtimeRoot = path.join(root, `runtime-${platform}`);
  const runtimeBinaryRelative = platform === "windows-x86_64" ? "bin/podman.exe" : "bin/podman";
  const runtimeBinary = path.join(runtimeRoot, ...runtimeBinaryRelative.split("/"));
  await mkdir(path.dirname(runtimeBinary), { recursive: true });
  await writeFile(runtimeBinary, Buffer.concat([magic, Buffer.alloc(3072, platform.length + 2)]));
  const runtimeBinaryBytes = (await readFile(runtimeBinary)).length;
  const runtimeBinarySha256 = await sha256File(runtimeBinary);
  const machineImageUrl =
    `https://github.com/podman-container-tools/podman-machine-os/releases/download/v0.0.1/${platform}.qcow2.xz`;
  const machineImageSha256 = "ab".repeat(32);
  const runtimeManifest = path.join(runtimeRoot, "manifest.json");
  await writeFile(
    runtimeManifest,
    `${JSON.stringify({
      schema_version: "3",
      management_contract_revision: "2026-08-29.1",
      bundle_id: platform === "windows-x86_64" ? "podman-machine" : "release-self-test",
      runtime_version: platform === "windows-x86_64" ? "5.8.2" : VERSION,
      driver_path: runtimeBinaryRelative,
      files: [{
        path: runtimeBinaryRelative,
        sha256: runtimeBinarySha256,
        size_bytes: runtimeBinaryBytes,
        executable: true,
      }],
      components: [
        {
          id: "fixture-runtime-client",
          name: "Fixture runtime client",
          version: VERSION,
          repository_url: "https://github.com/containers/podman",
          source_revision: COMMIT,
          license_spdx: "Apache-2.0",
          relationship: "Release self-test stand-in for one exact bundled runtime executable.",
          artifacts: [{
            delivery: "bundled_file",
            locator: runtimeBinaryRelative,
            sha256: runtimeBinarySha256,
            size_bytes: runtimeBinaryBytes,
          }],
        },
        {
          id: "fixture-machine-os",
          name: "Fixture machine OS",
          version: VERSION,
          repository_url: "https://github.com/podman-container-tools/podman-machine-os",
          source_revision: COMMIT,
          license_spdx: "Apache-2.0",
          relationship: "Release self-test stand-in for one exact runtime-downloaded machine image.",
          artifacts: [{
            delivery: "runtime_download",
            locator: machineImageUrl,
            sha256: machineImageSha256,
            size_bytes: 4096,
          }],
        },
      ],
      targets: [{
        operating_system: platform.startsWith("linux") ? "linux" : platform.startsWith("macos") ? "macos" : "windows",
        architecture: "x86_64",
        provider: platform.startsWith("linux") ? "qemu" : platform.startsWith("macos") ? "applehv" : "wsl",
        machine_image: {
          url: machineImageUrl,
          sha256: machineImageSha256,
          size_bytes: 4096,
        },
      }],
      resources: { cpus: 2, memory_mb: 2048, disk_size_gb: 20 },
      source: {
        repository_url: "https://github.com/containers/podman",
        source_revision: COMMIT,
        license_spdx: "Apache-2.0",
      },
    }, null, 2)}\n`,
  );
  run("generate-runtime-evidence.mjs", [
    "--manifest",
    runtimeManifest,
    "--out",
    output,
    "--platform",
    platform,
  ]);
  return output;
}

async function mergeFlat(source, destination) {
  for (const name of await readdir(source)) {
    await copyFile(path.join(source, name), path.join(destination, name));
  }
}

async function copyTree(source, destination) {
  await mkdir(destination, { recursive: true });
  for (const entry of await readdir(source, { withFileTypes: true })) {
    const from = path.join(source, entry.name);
    const to = path.join(destination, entry.name);
    if (entry.isDirectory()) await copyTree(from, to);
    else if (entry.isFile()) await copyFile(from, to);
    else throw new Error(`release self-test refuses to copy a special entry: ${from}`);
  }
}

async function recursiveRegularFiles(root, directory = root) {
  const output = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const absolute = path.join(directory, entry.name);
    if (entry.isDirectory()) output.push(...(await recursiveRegularFiles(root, absolute)));
    else if (entry.isFile()) output.push({
      absolute,
      relative: toPosix(path.relative(root, absolute)),
      bytes: (await lstat(absolute)).size,
    });
    else throw new Error(`release self-test refuses to reseal a special entry: ${absolute}`);
  }
  return output;
}

export async function resealFinalizedFixture(directory) {
  const releaseMetadata = await readJson(path.join(directory, "release-metadata.json"));
  const platformManifests = (await readdir(directory))
    .filter((name) => /^installers-(?:linux-x86_64|macos-universal|windows-x86_64)\.json$/u.test(name));
  for (const manifestName of platformManifests) {
    const manifest = await readJson(path.join(directory, manifestName));
    const runtimeSuffixes = ["manifest.json", "cyclonedx.json", "spdx.json", "NOTICES.txt"];
    const names = [
      manifestName,
      ...manifest.installers.map(({ file }) => file),
      ...manifest.auxiliaryExecutables.map(({ releaseFile }) => releaseFile),
      ...manifest.updaters.flatMap(({ payloadFile, signatureFile }) => [payloadFile, signatureFile]),
      ...runtimeSuffixes.map((suffix) => `managed-runtime-${manifest.platform}.${suffix}`),
    ].sort();
    await writeFile(
      path.join(directory, `SHA256SUMS-${manifest.platform}.txt`),
      `${(await Promise.all(names.map(async (name) => `${await sha256File(path.join(directory, name))}  ${name}`))).join("\n")}\n`,
    );
  }
  const beforeIndex = (await recursiveRegularFiles(directory))
    .filter(({ relative }) => relative !== "SHA256SUMS.txt" && relative !== "release-assets.json")
    .sort((left, right) => left.relative.localeCompare(right.relative));
  await writeFile(
    path.join(directory, "release-assets.json"),
    `${JSON.stringify({
      schemaVersion: 3,
      product: "ai-security-scanner",
      version: VERSION,
      tag: TAG,
      sourceCommit: COMMIT,
      publicationMode: releaseMetadata.publicationMode,
      indexSelfExcluded: true,
      files: await Promise.all(beforeIndex.map(async (file) => ({
        path: file.relative,
        publishedName: publishedReleaseAssetName(file.relative),
        bytes: file.bytes,
        sha256: await sha256File(file.absolute),
      }))),
    }, null, 2)}\n`,
  );
  const finalFiles = (await recursiveRegularFiles(directory))
    .filter(({ relative }) => relative !== "SHA256SUMS.txt")
    .sort((left, right) => left.relative.localeCompare(right.relative));
  await writeFile(
    path.join(directory, "SHA256SUMS.txt"),
    `${(await Promise.all(finalFiles.map(async (file) =>
      `${await sha256File(file.absolute)}  ${publishedReleaseAssetName(file.relative)}`))).join("\n")}\n`,
  );
}

export async function createQualificationFixture(output, platform, installerType) {
  const runtimeManifestFile = path.join(output, `managed-runtime-${platform}.manifest.json`);
  const runtimeManifest = await readJson(runtimeManifestFile);
  const manifestSha256 = await sha256File(runtimeManifestFile);
  const target = runtimeManifest.targets[0];
  const status = (phase, available) => ({
    provider: "managed_local",
    phase,
    available,
    runtime_version: runtimeManifest.runtime_version,
    manifest_sha256: manifestSha256,
    machine_image_sha256: target.machine_image.sha256,
    operating_system: target.operating_system,
    architecture: target.architecture,
    machine_provider: target.provider,
    prerequisite: null,
    detail: `release self-test ${phase} status`,
  });
  const passed = (name, phase, available) => ({ name, outcome: "passed", status: status(phase, available) });
  const macosHostedLimitation = "github_hosted_macos_nested_virtualization_unsupported";
  const notObserved = (name) => ({
    name,
    outcome: "not_observed",
    reasonCode: macosHostedLimitation,
  });
  const qualificationRoot = path.join(output, `qualification-fixture-${platform}`);
  await mkdir(qualificationRoot);
  await copyFile(runtimeManifestFile, path.join(qualificationRoot, "installed-runtime-manifest.json"));
  const installedPath = platform === "windows-x86_64" ? path.win32 : path.posix;
  const prefix = platform === "windows-x86_64"
    ? installedPath.join("C:\\fixture-installed", platform, installerType)
    : installedPath.join("/fixture-installed", platform, installerType);
  const extension = platform === "windows-x86_64" ? ".exe" : "";
  const initialRuntimePhase = platform === "windows-x86_64" && installerType === "nsis"
    ? "installed"
    : "not_installed";
  const observations = {
    installedLayout: {
      pathsVerifiedAbsolute: true,
      desktop: installedPath.join(prefix, `ai-security-scanner${extension}`),
      cli: installedPath.join(prefix, `ai-security-scanner-cli${extension}`),
      companions: [
        { name: "ai-security-scanner-egress-gateway", path: installedPath.join(prefix, `ai-security-scanner-egress-gateway${extension}`) },
        { name: "ai-security-scanner-bootstrap-broker", path: installedPath.join(prefix, `ai-security-scanner-bootstrap-broker${extension}`) },
        { name: "ai-security-scanner-cli", path: installedPath.join(prefix, `ai-security-scanner-cli${extension}`) },
      ],
      runtimeManifestOriginalPath: installedPath.join(prefix, "managed-runtime", "manifest.json"),
    },
    desktopStartup: {
      outcome: "passed",
      observationSeconds: 12,
      installedExecutable: installedPath.join(prefix, `ai-security-scanner${extension}`),
    },
    privateDataDirectory: platform === "windows-x86_64"
      ? installedPath.join("C:\\fixture-private", platform, installerType)
      : installedPath.join("/fixture-private", platform, installerType),
    operations: platform === "macos-universal"
      ? [
          notObserved("initial_status"),
          notObserved("install"),
          notObserved("installed_status"),
          notObserved("start"),
          notObserved("running_status"),
          notObserved("stop"),
          notObserved("stopped_status"),
          notObserved("uninstall_purge"),
          notObserved("final_status"),
        ]
      : [
          passed("initial_status", initialRuntimePhase, false),
          passed("install", "installed", false),
          passed("installed_status", "installed", false),
          passed("start", "running", true),
          passed("running_status", "running", true),
          passed("stop", "stopped", false),
          passed("stopped_status", "stopped", false),
          passed("uninstall_purge", "not_installed", false),
          passed("final_status", "not_installed", false),
        ],
    egressGateway: platform === "macos-universal"
      ? { outcome: "not_observed", reasonCode: macosHostedLimitation }
      : {
          outcome: "passed",
          result: {
            schema_version: "1.0.0",
            status: "passed",
            qualification_kind: "managed_egress_gateway_readiness",
            product_version: VERSION,
            runtime: {
              provider: "managed_local",
              server_version: runtimeManifest.runtime_version,
              command_provenance: {
                kind: "managed_local",
                runtime_version: runtimeManifest.runtime_version,
                manifest_sha256: manifestSha256,
                machine_image_sha256: target.machine_image.sha256,
              },
            },
            gateway: {
              image: EXPECTED_GATEWAY_IMAGE,
              backend: "pinned_container",
              ready: true,
              scanner_reachable: true,
              reachability_probe: "socks5_no_connect_greeting",
              upstream_connection_attempted: false,
              container_id: "15".repeat(32),
              probe_container_id: "19".repeat(32),
              internal_network_id: "16".repeat(32),
              uplink_network_id: "17".repeat(32),
              policy_sha256: "18".repeat(32),
            },
            cleanup: {
              gateway_container_removed: true,
              probe_container_removed: true,
              internal_network_removed: true,
              uplink_network_removed: true,
              policy_file_removed: true,
              status_directory_removed: true,
              registry_record_removed: true,
            },
          },
        },
    containerExecution: platform === "macos-universal"
      ? { outcome: "not_observed", reasonCode: macosHostedLimitation }
      : {
          outcome: "passed",
          result: {
            schema_version: "1.0.0",
            status: "passed",
            qualification_kind: "managed_container_execution",
            product_version: VERSION,
            runtime: {
              provider: "managed_local",
              server_version: runtimeManifest.runtime_version,
              command_provenance: {
                kind: "managed_local",
                runtime_version: runtimeManifest.runtime_version,
                manifest_sha256: manifestSha256,
                machine_image_sha256: target.machine_image.sha256,
              },
            },
            container: {
              engine_id: "gitleaks",
              image: EXPECTED_QUALIFICATION_IMAGE,
              network: "none",
              read_only_root: true,
              capabilities: "drop_all",
              no_new_privileges: true,
              credential_count: 0,
              exit_code: 0,
              cancelled: false,
              created_object_id: "cd".repeat(32),
              cleanup_removed: true,
            },
            evidence: {
              scope_sha256: "10".repeat(32),
              report_sha256: "11".repeat(32),
              report_bytes: 2,
              finding_count: 0,
              stdout_sha256: "12".repeat(32),
              stderr_sha256: "13".repeat(32),
            },
          },
        },
    cleanup: platform === "macos-universal"
      ? {
          diskImageDetached: true,
          installedApplicationRemoved: true,
          privateDataRemoved: true,
          managedRuntimeState: "not_created",
          machineImageCacheState: "not_created",
        }
      : {
          managedRuntimePurged: true,
          machineImageCachePurged: true,
          installerRemoved: true,
          privateDataRemoved: true,
        },
    installedManifestSnapshot: "installed-runtime-manifest.json",
  };
  const observationsFile = path.join(qualificationRoot, "observations.json");
  await writeFile(observationsFile, `${JSON.stringify(observations, null, 2)}\n`);
  const runner = platform === "linux-x86_64"
    ? { label: "ubuntu-24.04", os: "Linux", image: "ubuntu24" }
    : platform === "macos-universal"
      ? { label: "macos-15-intel", os: "macOS", image: "macos15" }
      : { label: "windows-2025", os: "Windows", image: "win25" };
  await createPlatformQualification({
    artifactDirectory: output,
    observationsFile,
    outputFile: path.join(output, `platform-qualification-${platform}-${installerType}.json`),
    platform,
    installerType,
    version: VERSION,
    tag: TAG,
    commit: COMMIT,
    releaseChannel: "prerelease",
    runnerLabel: runner.label,
    environment: {
      GITHUB_ACTIONS: "true",
      RUNNER_ENVIRONMENT: "github-hosted",
      RUNNER_OS: runner.os,
      RUNNER_ARCH: "X64",
      ImageOS: runner.image,
      ImageVersion: "20260824.1",
      GITHUB_WORKFLOW: "Release self-test fixture",
      GITHUB_JOB: "qualification",
      GITHUB_RUN_ID: "123456789",
      GITHUB_RUN_ATTEMPT: "1",
      GITHUB_SHA: COMMIT,
    },
  });
  await rm(qualificationRoot, { recursive: true, force: true });
}

async function createWindowsExternalObservationFixture(directory, artifact) {
  await mkdir(directory, { recursive: true });
  await writeFile(
    path.join(directory, WINDOWS_HUMAN_PATH_FILE),
    `${JSON.stringify({
      schemaVersion: 1,
      evidenceType: "beginner-human-path",
      product: "ai-security-scanner",
      platform: "windows-x86_64",
      installerType: "nsis",
      releaseIdentity: { version: VERSION, tag: TAG, sourceCommit: COMMIT },
      artifact,
      outcome: "passed",
      observedAt: "2026-09-07T12:00:00Z",
      details: {
        participantProfile: "windows-beginner-no-security-or-linux-experience",
        participantBuiltProduct: false,
        participantContributedToProduct: false,
        participantRehearsedSetup: false,
        facilitatorTookControl: false,
        facilitatorDictatedOperationalSteps: false,
        facilitatorAdministeredWsl: false,
        terminalOpened: false,
        typedCommandCount: 0,
        windowsVersion: "Windows 11 Pro 24H2 build 26100",
        firstReportTimingBasis:
          "installer-launch-to-first-durable-report-excluding-os-shutdown-to-desktop",
        firstReportElapsedSeconds: 420,
        firstReportWallClockElapsedSeconds: 420,
        excludedOperatingSystemRestartSeconds: 0,
        totalJourneyElapsedSeconds: 900,
        userDecisions: ["install", "start-localhost-scan"],
        visibleErrors: [],
        installed: true,
        launched: true,
        minimumLocalhostScanStarted: true,
        beginnerReportViewed: true,
        projectReopened: true,
        readableReportExported: true,
        readableExport: { format: "html", outcome: "exported-and-opened-readable" },
        finalCoverage: {
          state: "complete",
          testedCount: 1,
          notTestedCount: 0,
          failedCount: 0,
          coverageGapCount: 0,
        },
        localhostReport: {
          target: "127.0.0.1:9001",
          taskExecutionState: "executed",
          outcome: "reachable",
          findingCount: 0,
          durableReportId: "11111111-2222-4333-8444-555555555555",
          durableReportState: "saved",
        },
      },
    }, null, 2)}\n`,
  );
  await writeFile(
    path.join(directory, WINDOWS_UNSIGNED_SIGNING_OBSERVATION_FILE),
    `${JSON.stringify({
      schemaVersion: 1,
      evidenceType: "operating-system-code-signing-observation",
      product: "ai-security-scanner",
      platform: "windows-x86_64",
      installerType: "nsis",
      releaseIdentity: { version: VERSION, tag: TAG, sourceCommit: COMMIT },
      artifact,
      outcome: "not-configured",
      observedAt: "2026-09-07T12:01:00Z",
      details: {
        signatureScheme: "authenticode",
        signatureStatus: "NotSigned",
        artifactSha256: artifact.sha256,
        verificationTool: "Get-AuthenticodeSignature",
      },
    }, null, 2)}\n`,
  );
}

async function main() {
  for (const version of ["0.1.2", "0.1.4", "0.2.0", "2.3.4"]) {
    if (!isSemver(version)) throw new Error(`native-compatible release version was rejected: ${version}`);
  }
  for (const version of ["01.2.0", "0.02.0", "0.2.00", "0.2.0-rc.1", "0.2.0+build"]) {
    if (isSemver(version)) throw new Error(`non-native release version was accepted: ${version}`);
  }

  const temporaryRoot = path.join(PROJECT_ROOT, "target", "release-self-test");
  await mkdir(temporaryRoot, { recursive: true });
  const temporary = await mkdtemp(path.join(temporaryRoot, "run-"));
  try {
    releasePolicyFixture = path.join(temporary, "prerelease-package.json");
    await writeFile(
      releasePolicyFixture,
      `${JSON.stringify({ version: VERSION, release: { channel: "prerelease", target: "0.2.0" } })}\n`,
    );
    const signingKey = path.join(temporary, "updater-test.key");
    tauriSigner([
      "generate",
      "--ci",
      "--password",
      TEST_KEY_PASSWORD,
      "--write-keys",
      signingKey,
    ]);
    const updaterPublicKey = (await readFile(`${signingKey}.pub`, "utf8")).trim();
    const tauriConfig = path.join(temporary, "tauri-test.conf.json");
    await writeFile(
      tauriConfig,
      `${JSON.stringify({ plugins: { updater: { pubkey: updaterPublicKey } } })}\n`,
    );

    const verificationPayload = path.join(temporary, "signature-contract.bin");
    await writeFile(verificationPayload, Buffer.from("authentic updater payload\n"));
    tauriSigner([
      "sign",
      "--private-key-path",
      signingKey,
      "--password",
      TEST_KEY_PASSWORD,
      verificationPayload,
    ]);
    verifyUpdaterSignatures(updaterPublicKey, [{
      payload: verificationPayload,
      signature: `${verificationPayload}.sig`,
    }]);
    const tamperedPayload = path.join(temporary, "tampered-updater.bin");
    await writeFile(tamperedPayload, Buffer.from("tampered updater payload\n"));
    expectFailure(
      () => verifyUpdaterSignatures(updaterPublicKey, [{
        payload: tamperedPayload,
        signature: `${verificationPayload}.sig`,
      }]),
      "tampered updater payload",
    );
    const otherKey = path.join(temporary, "other-updater-test.key");
    tauriSigner([
      "generate",
      "--ci",
      "--password",
      TEST_KEY_PASSWORD,
      "--write-keys",
      otherKey,
    ]);
    const otherPublicKey = (await readFile(`${otherKey}.pub`, "utf8")).trim();
    expectFailure(
      () => verifyUpdaterSignatures(otherPublicKey, [{
        payload: verificationPayload,
        signature: `${verificationPayload}.sig`,
      }]),
      "mismatched updater public key",
    );

    const unexpectedMacUpdater = await createPlatformFixture(
      path.join(temporary, "negative-mac-updater"),
      "macos-universal",
      [["dmg", `ai-security-scanner_${VERSION}_unexpected-name-test.dmg`]],
      signingKey,
      "unexpected-product.app.tar.gz",
    );
    const unexpectedMacUpdaterManifest = await readJson(
      path.join(unexpectedMacUpdater, "installers-macos-universal.json"),
    );
    if (
      unexpectedMacUpdaterManifest.installers.length !== 1 ||
      unexpectedMacUpdaterManifest.updaters.length !== 0 ||
      unexpectedMacUpdaterManifest.updaterFailures.length !== 1
    ) {
      throw new Error("an invalid optional macOS updater changed the valid DMG outcome");
    }

    const symlinkSiblingOutput = await createPlatformFixture(
      path.join(temporary, "negative-symlink-installer"),
      "linux-x86_64",
      [
        ["deb", `ai-security-scanner_${VERSION}_amd64.deb`],
        ["rpm", `ai-security-scanner-${VERSION}-1.x86_64.rpm`],
        ["appimage", `ai-security-scanner_${VERSION}_amd64.AppImage`],
      ],
      signingKey,
      undefined,
      true,
    );
    const symlinkSiblingManifest = await readJson(
      path.join(symlinkSiblingOutput, "installers-linux-x86_64.json"),
    );
    if (
      JSON.stringify(symlinkSiblingManifest.availableBundleTypes) !==
        JSON.stringify(["rpm", "appimage"]) ||
      symlinkSiblingManifest.installers.some(({ bundleType }) => bundleType === "deb") ||
      !symlinkSiblingManifest.installers.some(({ bundleType }) => bundleType === "rpm") ||
      !symlinkSiblingManifest.installers.some(({ bundleType }) => bundleType === "appimage")
    ) {
      throw new Error("an invalid symlink installer was accepted or discarded valid siblings");
    }

    const partialLinux = await createPlatformFixture(
      path.join(temporary, "partial-linux-siblings"),
      "linux-x86_64",
      [
        ["deb", `ai-security-scanner_${VERSION}_amd64.deb`],
        ["appimage", `ai-security-scanner_${VERSION}_amd64.AppImage`],
      ],
      signingKey,
      undefined,
      false,
      ["deb", "rpm", "appimage"],
    );
    const partialLinuxManifest = await readJson(path.join(partialLinux, "installers-linux-x86_64.json"));
    if (
      JSON.stringify(partialLinuxManifest.requestedBundleTypes) !== JSON.stringify(["deb", "rpm", "appimage"]) ||
      JSON.stringify(partialLinuxManifest.availableBundleTypes) !== JSON.stringify(["deb", "appimage"]) ||
      partialLinuxManifest.installers.some(({ bundleType }) => bundleType === "rpm") ||
      partialLinuxManifest.updaters.length !== 1 ||
      partialLinuxManifest.updaters[0].bundleType !== "appimage"
    ) {
      throw new Error("Linux partial collection did not preserve successful siblings exactly");
    }

    const partialWindows = await createPlatformFixture(
      path.join(temporary, "partial-windows-siblings"),
      "windows-x86_64",
      [["msi", `ai-security-scanner_${VERSION}_x64_en-US.msi`]],
      signingKey,
      undefined,
      false,
      ["nsis", "msi"],
    );
    const partialWindowsManifest = await readJson(path.join(partialWindows, "installers-windows-x86_64.json"));
    if (
      JSON.stringify(partialWindowsManifest.availableBundleTypes) !== JSON.stringify(["msi"]) ||
      partialWindowsManifest.installers.length !== 1 ||
      partialWindowsManifest.installers[0].bundleType !== "msi" ||
      partialWindowsManifest.updaters.length !== 0
    ) {
      throw new Error("Windows partial collection fabricated an MSI updater or lost its valid installer");
    }

    const installerOnlyAppImage = await createPlatformFixture(
      path.join(temporary, "appimage-without-updater-signature"),
      "linux-x86_64",
      [["appimage", `ai-security-scanner_${VERSION}_amd64.AppImage`]],
      signingKey,
      undefined,
      false,
      ["deb", "rpm", "appimage"],
      false,
    );
    const installerOnlyAppImageManifest = await readJson(
      path.join(installerOnlyAppImage, "installers-linux-x86_64.json"),
    );
    if (
      installerOnlyAppImageManifest.installers.length !== 1 ||
      installerOnlyAppImageManifest.updaters.length !== 0 ||
      installerOnlyAppImageManifest.updaterFailures.length !== 1 ||
      (await readdir(installerOnlyAppImage)).some((name) => name.startsWith(".updater-stage-"))
    ) {
      throw new Error("a missing optional updater signature lost the AppImage installer or left partial collection state");
    }

    const outputs = [
      await createPlatformFixture(temporary, "linux-x86_64", [
        ["deb", `ai-security-scanner_${VERSION}_amd64.deb`],
        ["rpm", `ai-security-scanner-${VERSION}-1.x86_64.rpm`],
        ["appimage", `ai-security-scanner_${VERSION}_amd64.AppImage`],
      ], signingKey),
      await createPlatformFixture(temporary, "macos-universal", [
        ["dmg", `ai-security-scanner_${VERSION}_universal.dmg`],
      ], signingKey),
      await createPlatformFixture(temporary, "windows-x86_64", [
        ["nsis", `ai-security-scanner_${VERSION}_x64-setup.exe`],
        ["msi", `ai-security-scanner_${VERSION}_x64_en-US.msi`],
      ], signingKey),
    ];
    await createQualificationFixture(outputs[0], "linux-x86_64", "deb");
    await createQualificationFixture(outputs[1], "macos-universal", "dmg");
    await createQualificationFixture(outputs[2], "windows-x86_64", "msi");
    await createQualificationFixture(outputs[2], "windows-x86_64", "nsis");
    const stableMacQualification = path.join(
      outputs[1],
      "platform-qualification-macos-universal-dmg-stable.json",
    );
    const stableMacEvidence = await readJson(
      path.join(outputs[1], "platform-qualification-macos-universal-dmg.json"),
    );
    stableMacEvidence.releaseIdentity.releaseChannel = "stable";
    await writeFile(stableMacQualification, `${JSON.stringify(stableMacEvidence, null, 2)}\n`);
    run("platform-qualification.mjs", [
      "validate",
      "--file", stableMacQualification,
      "--artifact-dir", outputs[1],
      "--platform", "macos-universal",
      "--installer-type", "dmg",
      "--version", VERSION,
      "--tag", TAG,
      "--commit", COMMIT,
      "--release-channel", "stable",
    ]);
    await rm(stableMacQualification);
    for (const [platformOutput, platform, installerType, wrongInitialPhase] of [
      [outputs[0], "linux-x86_64", "deb", "installed"],
      [outputs[2], "windows-x86_64", "msi", "installed"],
      [outputs[2], "windows-x86_64", "nsis", "not_installed"],
    ]) {
      const invalidInitialStatusFile = path.join(
        platformOutput,
        `platform-qualification-${platform}-${installerType}-wrong-initial-status.json`,
      );
      const invalidInitialStatus = await readJson(
        path.join(platformOutput, `platform-qualification-${platform}-${installerType}.json`),
      );
      invalidInitialStatus.managedRuntime.operations[0].status.phase = wrongInitialPhase;
      await writeFile(invalidInitialStatusFile, `${JSON.stringify(invalidInitialStatus, null, 2)}\n`);
      expectFailure(
        () => run("platform-qualification.mjs", [
          "validate",
          "--file", invalidInitialStatusFile,
          "--artifact-dir", platformOutput,
          "--platform", platform,
          "--installer-type", installerType,
          "--version", VERSION,
          "--tag", TAG,
          "--commit", COMMIT,
          "--release-channel", "prerelease",
        ]),
        `${platform}/${installerType} qualification with the wrong initial managed-runtime phase`,
      );
      await rm(invalidInitialStatusFile);
    }
    const wrongSourceQualification = path.join(outputs[2], "platform-qualification-wrong-source.json");
    const wrongSourceEvidence = await readJson(
      path.join(outputs[2], "platform-qualification-windows-x86_64-nsis.json"),
    );
    wrongSourceEvidence.sourceArtifact.name = "release-windows-x86_64";
    await writeFile(wrongSourceQualification, `${JSON.stringify(wrongSourceEvidence, null, 2)}\n`);
    expectFailure(
      () => run("platform-qualification.mjs", [
        "validate",
        "--file", wrongSourceQualification,
        "--artifact-dir", outputs[2],
        "--platform", "windows-x86_64",
        "--installer-type", "nsis",
        "--version", VERSION,
        "--tag", TAG,
        "--commit", COMMIT,
        "--release-channel", "prerelease",
      ]),
      "qualification whose source artifact differs from the workflow upload",
    );
    await rm(wrongSourceQualification);
    const release = path.join(temporary, "release-assets");
    await mkdir(release);
    for (const output of outputs) {
      await mergeFlat(output, release);
    }

    await writeFile(path.join(release, "THIRD_PARTY_NOTICES.txt"), "fixture dependency notice\n");
    await writeFile(path.join(release, "ENGINE_NOTICES.md"), "# Fixture engine notice\n");
    await writeFile(path.join(release, "ENGINE_NOTICES.json"), "{\"engines\":[]}\n");
    await writeFile(path.join(release, "LICENSE.txt"), "Apache-2.0 fixture\n");
    await writeFile(
      path.join(release, `ai-security-scanner-${VERSION}.cyclonedx.json`),
      `${JSON.stringify({ bomFormat: "CycloneDX", specVersion: "1.6", version: 1, components: [] })}\n`,
    );
    await writeFile(
      path.join(release, `ai-security-scanner-${VERSION}.spdx.json`),
      `${JSON.stringify({ spdxVersion: "SPDX-2.3", SPDXID: "SPDXRef-DOCUMENT", packages: [], relationships: [] })}\n`,
    );
    await writeFile(
      path.join(release, "release-metadata.json"),
      `${JSON.stringify(createPreparedReleaseMetadata({
        version: VERSION,
        tag: TAG,
        releaseChannel: "prerelease",
        stableTarget: "0.2.0",
        sourceRepository: "https://github.com/TED-H-com/ai-security-scanner",
        sourceCommit: COMMIT,
        sourceDate: "2026-08-24T00:00:00Z",
        publicationMode: "commit-bound-qc",
        requestedPlatforms: ["linux-x86_64", "macos-universal", "windows-x86_64"],
        sboms: [
          `ai-security-scanner-${VERSION}.cyclonedx.json`,
          `ai-security-scanner-${VERSION}.spdx.json`,
        ],
        inventories: { npmPackageCount: 0, cargoPackageCount: 0, engineReferenceCount: 0 },
      }))}\n`,
    );

    const scopedAllOutput = path.join(temporary, "finalized-all-qualified");
    const finalizeArguments = [
      "--input",
      release,
      "--out",
      scopedAllOutput,
      "--version",
      VERSION,
      "--tag",
      TAG,
      "--commit",
      COMMIT,
      "--publication-mode",
      "commit-bound-qc",
      "--tauri-config",
      tauriConfig,
    ];
    run("finalize-release.mjs", finalizeArguments);
    run("verify-finalized-release.mjs", [
      "--dir", scopedAllOutput,
      "--version", VERSION,
      "--tag", TAG,
      "--commit", COMMIT,
      "--publication-mode", "commit-bound-qc",
      "--tauri-config", tauriConfig,
    ]);
    const scopedAllMetadata = await readJson(path.join(scopedAllOutput, "release-metadata.json"));
    const scopedAllLatest = await readJson(path.join(scopedAllOutput, "latest.json"));
    for (const platform of scopedAllMetadata.distribution.platforms) {
      for (const { artifact } of platform.installers.filter(({ availability }) => availability === "offered")) {
        if (artifact.updater.state !== "signed") continue;
        const expectedUrl = `https://github.com/${UPDATER_DOWNLOAD_REPOSITORY}/releases/download/${TAG}/${encodeURIComponent(artifact.updater.payloadFile)}`;
        for (const target of artifact.updater.targetKeys) {
          if (scopedAllLatest.platforms[target]?.url !== expectedUrl) {
            throw new Error(`finalization changed the legacy updater download path for ${target}`);
          }
        }
      }
    }
    const scopedAllOffered = scopedAllMetadata.distribution.platforms.flatMap(({ installers }) =>
      installers.filter(({ availability }) => availability === "offered"));
    if (
      scopedAllOffered.length !== 4 ||
      scopedAllMetadata.security.operatingSystemCodeSigning !== undefined ||
      scopedAllMetadata.security.updater !== undefined ||
      scopedAllMetadata.security.provenanceAttestation !== undefined
    ) {
      throw new Error("artifact-scoped finalization retained a global security claim");
    }

    const noUpdaterKeyConfig = path.join(temporary, "tauri-without-updater-key.json");
    await writeFile(noUpdaterKeyConfig, `${JSON.stringify({ plugins: { updater: {} } })}\n`);
    const noUpdaterKeyOutput = path.join(temporary, "finalized-without-updater-key");
    run("finalize-release.mjs", [
      "--input", release,
      "--out", noUpdaterKeyOutput,
      "--version", VERSION,
      "--tag", TAG,
      "--commit", COMMIT,
      "--publication-mode", "commit-bound-qc",
      "--tauri-config", noUpdaterKeyConfig,
    ]);
    run("verify-finalized-release.mjs", [
      "--dir", noUpdaterKeyOutput,
      "--version", VERSION,
      "--tag", TAG,
      "--commit", COMMIT,
      "--publication-mode", "commit-bound-qc",
      "--tauri-config", noUpdaterKeyConfig,
    ]);
    const noUpdaterKeyMetadata = await readJson(path.join(noUpdaterKeyOutput, "release-metadata.json"));
    const noUpdaterKeyOffered = noUpdaterKeyMetadata.distribution.platforms.flatMap(({ installers }) =>
      installers.filter(({ availability }) => availability === "offered"));
    if (
      noUpdaterKeyOffered.length !== scopedAllOffered.length ||
      noUpdaterKeyOffered.some(({ artifact: offeredArtifact }) => offeredArtifact.updater.state !== "not-offered")
    ) {
      throw new Error("a missing embedded updater key changed valid installer availability");
    }

    const resealedUrlTamper = path.join(temporary, "resealed-latest-url-tamper");
    await copyTree(scopedAllOutput, resealedUrlTamper);
    const tamperedLatest = await readJson(path.join(resealedUrlTamper, "latest.json"));
    const tamperedLatestTarget = Object.keys(tamperedLatest.platforms)[0];
    tamperedLatest.platforms[tamperedLatestTarget].url =
      tamperedLatest.platforms[tamperedLatestTarget].url.replace(`/${TAG}/`, "/v9.9.9/");
    await writeFile(path.join(resealedUrlTamper, "latest.json"), `${JSON.stringify(tamperedLatest, null, 2)}\n`);
    await resealFinalizedFixture(resealedUrlTamper);
    expectFailure(
      () => run("verify-finalized-release.mjs", [
        "--dir", resealedUrlTamper,
        "--version", VERSION,
        "--tag", TAG,
        "--commit", COMMIT,
        "--publication-mode", "commit-bound-qc",
        "--tauri-config", tauriConfig,
      ]),
      "resealed latest.json URL/tag tamper",
    );

    const resealedUpdaterKeyTamper = path.join(temporary, "resealed-updater-key-tamper");
    await copyTree(scopedAllOutput, resealedUpdaterKeyTamper);
    const macManifestPath = path.join(resealedUpdaterKeyTamper, "installers-macos-universal.json");
    const macManifest = await readJson(macManifestPath);
    const macUpdater = macManifest.updaters[0];
    const macPayloadPath = path.join(resealedUpdaterKeyTamper, macUpdater.payloadFile);
    const macSignaturePath = path.join(resealedUpdaterKeyTamper, macUpdater.signatureFile);
    await writeFile(macPayloadPath, Buffer.concat([await readFile(macPayloadPath), Buffer.from("resealed attacker bytes\n")]));
    await rm(macSignaturePath);
    tauriSigner([
      "sign",
      "--private-key-path",
      otherKey,
      "--password",
      TEST_KEY_PASSWORD,
      macPayloadPath,
    ]);
    const replacementSignature = (await readFile(macSignaturePath, "utf8")).trim();
    const replacementSignatureMetadata = await lstat(macSignaturePath);
    macUpdater.payloadBytes = (await lstat(macPayloadPath)).size;
    macUpdater.payloadSha256 = await sha256File(macPayloadPath);
    macUpdater.signatureBytes = replacementSignatureMetadata.size;
    macUpdater.signatureSha256 = await sha256File(macSignaturePath);
    macUpdater.signature = replacementSignature;
    await writeFile(macManifestPath, `${JSON.stringify(macManifest, null, 2)}\n`);
    const keyTamperLatest = await readJson(path.join(resealedUpdaterKeyTamper, "latest.json"));
    for (const target of macUpdater.targetKeys) keyTamperLatest.platforms[target].signature = replacementSignature;
    await writeFile(
      path.join(resealedUpdaterKeyTamper, "latest.json"),
      `${JSON.stringify(keyTamperLatest, null, 2)}\n`,
    );
    await resealFinalizedFixture(resealedUpdaterKeyTamper);
    expectFailure(
      () => run("verify-finalized-release.mjs", [
        "--dir", resealedUpdaterKeyTamper,
        "--version", VERSION,
        "--tag", TAG,
        "--commit", COMMIT,
        "--publication-mode", "commit-bound-qc",
        "--tauri-config", tauriConfig,
      ]),
      "resealed updater payload signed by an untrusted key",
    );

    const publicWithoutPromotionInput = path.join(temporary, "public-without-windows-promotion-input");
    await mkdir(publicWithoutPromotionInput);
    await mergeFlat(release, publicWithoutPromotionInput);
    const publicWithoutPromotionMetadata = await readJson(
      path.join(publicWithoutPromotionInput, "release-metadata.json"),
    );
    publicWithoutPromotionMetadata.publicationMode = "public-github-release";
    await writeFile(
      path.join(publicWithoutPromotionInput, "release-metadata.json"),
      `${JSON.stringify(publicWithoutPromotionMetadata, null, 2)}\n`,
    );
    const publicWithoutPromotionOutput = path.join(temporary, "public-without-windows-promotion-output");
    run("finalize-release.mjs", [
      "--input", publicWithoutPromotionInput,
      "--out", publicWithoutPromotionOutput,
      "--version", VERSION,
      "--tag", TAG,
      "--commit", COMMIT,
      "--publication-mode", "public-github-release",
      "--tauri-config", tauriConfig,
      "--tauri-config", tauriConfig,
    ]);
    run("verify-finalized-release.mjs", [
      "--dir", publicWithoutPromotionOutput,
      "--version", VERSION,
      "--tag", TAG,
      "--commit", COMMIT,
      "--publication-mode", "public-github-release",
      "--tauri-config", tauriConfig,
    ]);
    const publicWithoutPromotionFinal = await readJson(
      path.join(publicWithoutPromotionOutput, "release-metadata.json"),
    );
    const publicAvailability = new Map(
      publicWithoutPromotionFinal.distribution.platforms.map(({ platform, availability }) =>
        [platform, availability]),
    );
    const publicWindowsPrerelease = publicWithoutPromotionFinal.distribution.platforms.find(
      ({ platform }) => platform === "windows-x86_64",
    );
    if (
      publicAvailability.get("linux-x86_64") !== "offered" ||
      publicAvailability.get("macos-universal") !== "offered" ||
      publicAvailability.get("windows-x86_64") !== "offered" ||
      publicWindowsPrerelease.installers.some(({ artifact, availability }) =>
        availability === "offered" && (
          artifact.humanPath.state !== "not-observed" ||
          artifact.operatingSystemSigning.state !== "not-configured" ||
          artifact.windowsLifecycle.state !== "not-observed" ||
          !artifact.knownLimitations.includes("beginner-human-path-not-observed") ||
          !artifact.knownLimitations.includes("operating-system-signing-not-configured") ||
          !artifact.knownLimitations.includes("windows-lifecycle-not-observed")
        ))
    ) {
      throw new Error("public prerelease did not retain qualified platforms with exact limitations");
    }
    const publicPrereleaseNotes = await readFile(
      path.join(publicWithoutPromotionOutput, "RELEASE_NOTES.md"),
      "utf8",
    );
    if (
      !publicPrereleaseNotes.includes("Windows package record") ||
      !publicPrereleaseNotes.includes("unsigned Windows installers for public testing") ||
      !publicPrereleaseNotes.includes("Authenticode not verified") ||
      !publicPrereleaseNotes.includes("exact-candidate beginner path not observed") ||
      !publicPrereleaseNotes.includes("installed-app lifecycle not observed") ||
      !publicPrereleaseNotes.includes("data-preservation path not observed") ||
      !publicPrereleaseNotes.includes("- MSI:") ||
      !publicPrereleaseNotes.includes("- NSIS:")
    ) {
      throw new Error("public Windows prerelease did not disclose its exact testing limitations");
    }
    if (
      publicPrereleaseNotes.indexOf("Windows package record") <
      publicPrereleaseNotes.indexOf("Artifacts offered by this finalized set")
    ) {
      throw new Error("Windows package record interrupted the release outcome");
    }

    const scopedWindowsInput = path.join(temporary, "windows-only-input");
    await mkdir(scopedWindowsInput);
    await mergeFlat(outputs[2], scopedWindowsInput);
    for (const name of [
      "THIRD_PARTY_NOTICES.txt",
      "ENGINE_NOTICES.md",
      "ENGINE_NOTICES.json",
      "LICENSE.txt",
      `ai-security-scanner-${VERSION}.cyclonedx.json`,
      `ai-security-scanner-${VERSION}.spdx.json`,
    ]) {
      await copyFile(path.join(release, name), path.join(scopedWindowsInput, name));
    }
    const preparedWindowsMetadata = (publicationMode) => createPreparedReleaseMetadata({
      version: VERSION,
      tag: TAG,
      releaseChannel: "prerelease",
      stableTarget: "0.2.0",
      sourceRepository: "https://github.com/TED-H-com/ai-security-scanner",
      sourceCommit: COMMIT,
      sourceDate: "2026-08-24T00:00:00Z",
      publicationMode,
      requestedPlatforms: ["windows-x86_64"],
      sboms: [
        `ai-security-scanner-${VERSION}.cyclonedx.json`,
        `ai-security-scanner-${VERSION}.spdx.json`,
      ],
      inventories: { npmPackageCount: 0, cargoPackageCount: 0, engineReferenceCount: 0 },
    });
    await writeFile(
      path.join(scopedWindowsInput, "release-metadata.json"),
      `${JSON.stringify(preparedWindowsMetadata("commit-bound-qc"), null, 2)}\n`,
    );
    const scopedWindowsOutput = path.join(temporary, "windows-only-output");
    run("finalize-release.mjs", [
      "--input", scopedWindowsInput,
      "--out", scopedWindowsOutput,
      "--version", VERSION,
      "--tag", TAG,
      "--commit", COMMIT,
      "--publication-mode", "commit-bound-qc",
      "--tauri-config", tauriConfig,
    ]);
    const scopedWindowsMetadata = await readJson(path.join(scopedWindowsOutput, "release-metadata.json"));
    const scopedWindowsPlatform = scopedWindowsMetadata.distribution.platforms.find(({ platform }) =>
      platform === "windows-x86_64");
    if (
      scopedWindowsPlatform.availability !== "offered" ||
      scopedWindowsPlatform.installers.some(({ availability }) => availability !== "offered") ||
      scopedWindowsMetadata.distribution.platforms
        .filter(({ platform }) => platform !== "windows-x86_64")
        .some(({ availability }) => availability !== "not-offered")
    ) {
      throw new Error("Windows-only finalization did not preserve an explicit support matrix");
    }
    const scopedWindowsLatest = await readJson(path.join(scopedWindowsOutput, "latest.json"));
    if (
      JSON.stringify(Object.keys(scopedWindowsLatest.platforms).sort()) !==
        JSON.stringify(["windows-x86_64", "windows-x86_64-nsis"])
    ) {
      throw new Error("Windows-only finalization leaked unrelated updater targets");
    }

    const scopedInvalidInput = path.join(temporary, "windows-invalid-sibling-input");
    await mkdir(scopedInvalidInput);
    await mergeFlat(scopedWindowsInput, scopedInvalidInput);
    const scopedWindowsManifest = await readJson(path.join(scopedInvalidInput, "installers-windows-x86_64.json"));
    const scopedNsis = scopedWindowsManifest.installers.find(({ bundleType }) => bundleType === "nsis");
    await writeFile(
      path.join(scopedInvalidInput, scopedNsis.file),
      Buffer.concat([await readFile(path.join(scopedInvalidInput, scopedNsis.file)), Buffer.from("tampered\n")]),
    );
    const scopedInvalidOutput = path.join(temporary, "windows-invalid-sibling-output");
    run("finalize-release.mjs", [
      "--input", scopedInvalidInput,
      "--out", scopedInvalidOutput,
      "--version", VERSION,
      "--tag", TAG,
      "--commit", COMMIT,
      "--publication-mode", "commit-bound-qc",
      "--tauri-config", tauriConfig,
    ]);
    const scopedInvalidMetadata = await readJson(path.join(scopedInvalidOutput, "release-metadata.json"));
    const scopedInvalidWindows = scopedInvalidMetadata.distribution.platforms.find(({ platform }) =>
      platform === "windows-x86_64");
    if (
      scopedInvalidWindows.installers.find(({ installerType }) => installerType === "nsis").availability !== "not-offered" ||
      scopedInvalidWindows.installers.find(({ installerType }) => installerType === "msi").availability !== "offered"
    ) {
      throw new Error("an invalid Windows artifact changed its valid sibling's outcome");
    }

    const malformedUpdaterInput = path.join(temporary, "windows-malformed-updater-input");
    await mkdir(malformedUpdaterInput);
    await mergeFlat(scopedWindowsInput, malformedUpdaterInput);
    const malformedUpdaterManifestPath = path.join(
      malformedUpdaterInput,
      "installers-windows-x86_64.json",
    );
    const malformedUpdaterManifest = await readJson(malformedUpdaterManifestPath);
    malformedUpdaterManifest.updaters = [null];
    await writeFile(malformedUpdaterManifestPath, `${JSON.stringify(malformedUpdaterManifest, null, 2)}\n`);
    const malformedUpdaterOutput = path.join(temporary, "windows-malformed-updater-output");
    run("finalize-release.mjs", [
      "--input", malformedUpdaterInput,
      "--out", malformedUpdaterOutput,
      "--version", VERSION,
      "--tag", TAG,
      "--commit", COMMIT,
      "--publication-mode", "commit-bound-qc",
      "--tauri-config", tauriConfig,
    ]);
    const malformedUpdaterMetadata = await readJson(
      path.join(malformedUpdaterOutput, "release-metadata.json"),
    );
    const malformedUpdaterWindows = malformedUpdaterMetadata.distribution.platforms.find(
      ({ platform }) => platform === "windows-x86_64",
    );
    if (
      malformedUpdaterWindows.installers.some(({ availability }) => availability !== "offered") ||
      malformedUpdaterWindows.installers.find(({ installerType }) => installerType === "nsis")
        .artifact.updater.state !== "not-offered"
    ) {
      throw new Error("a malformed optional updater changed valid Windows installer outcomes");
    }

    const malformedInstallerInput = path.join(temporary, "windows-malformed-installer-input");
    await mkdir(malformedInstallerInput);
    await mergeFlat(scopedWindowsInput, malformedInstallerInput);
    const malformedInstallerManifestPath = path.join(
      malformedInstallerInput,
      "installers-windows-x86_64.json",
    );
    const malformedInstallerManifest = await readJson(malformedInstallerManifestPath);
    const malformedNsisIndex = malformedInstallerManifest.installers.findIndex(
      ({ bundleType }) => bundleType === "nsis",
    );
    malformedInstallerManifest.installers[malformedNsisIndex] = null;
    await writeFile(
      malformedInstallerManifestPath,
      `${JSON.stringify(malformedInstallerManifest, null, 2)}\n`,
    );
    const malformedInstallerOutput = path.join(temporary, "windows-malformed-installer-output");
    run("finalize-release.mjs", [
      "--input", malformedInstallerInput,
      "--out", malformedInstallerOutput,
      "--version", VERSION,
      "--tag", TAG,
      "--commit", COMMIT,
      "--publication-mode", "commit-bound-qc",
      "--tauri-config", tauriConfig,
    ]);
    const malformedInstallerMetadata = await readJson(
      path.join(malformedInstallerOutput, "release-metadata.json"),
    );
    const malformedInstallerWindows = malformedInstallerMetadata.distribution.platforms.find(
      ({ platform }) => platform === "windows-x86_64",
    );
    if (
      malformedInstallerWindows.installers.find(({ installerType }) => installerType === "nsis")
        .availability !== "not-offered" ||
      malformedInstallerWindows.installers.find(({ installerType }) => installerType === "msi")
        .availability !== "offered"
    ) {
      throw new Error("a malformed NSIS manifest record changed its valid MSI sibling's outcome");
    }

    const scopedPublicInput = path.join(temporary, "windows-public-input");
    await mkdir(scopedPublicInput);
    await mergeFlat(scopedWindowsInput, scopedPublicInput);
    await writeFile(
      path.join(scopedPublicInput, "release-metadata.json"),
      `${JSON.stringify(preparedWindowsMetadata("public-github-release"), null, 2)}\n`,
    );
    const scopedPublicOutput = path.join(temporary, "windows-public-prerelease-output");
    run("finalize-release.mjs", [
      "--input", scopedPublicInput,
      "--out", scopedPublicOutput,
      "--version", VERSION,
      "--tag", TAG,
      "--commit", COMMIT,
      "--publication-mode", "public-github-release",
      "--tauri-config", tauriConfig,
    ]);
    run("verify-finalized-release.mjs", [
      "--dir", scopedPublicOutput,
      "--version", VERSION,
      "--tag", TAG,
      "--commit", COMMIT,
      "--publication-mode", "public-github-release",
      "--tauri-config", tauriConfig,
    ]);
    const scopedPublicWindows = (await readJson(path.join(scopedPublicOutput, "release-metadata.json")))
      .distribution.platforms.find(({ platform }) => platform === "windows-x86_64");
    if (
      scopedPublicWindows.availability !== "offered" ||
      scopedPublicWindows.installers.some(({ availability }) => availability !== "offered")
    ) {
      throw new Error("technically qualified Windows prerelease installers were not offered");
    }

    const stablePublicInput = path.join(temporary, "windows-public-stable-input");
    await mkdir(stablePublicInput);
    await mergeFlat(publicWithoutPromotionInput, stablePublicInput);
    const stablePublicPreparedMetadata = structuredClone(publicWithoutPromotionMetadata);
    stablePublicPreparedMetadata.releaseChannel = "stable";
    stablePublicPreparedMetadata.stableTarget = VERSION;
    await writeFile(
      path.join(stablePublicInput, "release-metadata.json"),
      `${JSON.stringify(stablePublicPreparedMetadata, null, 2)}\n`,
    );
    for (const [platform, installerType] of [
      ["linux-x86_64", "deb"],
      ["macos-universal", "dmg"],
      ["windows-x86_64", "msi"],
      ["windows-x86_64", "nsis"],
    ]) {
      const qualificationFile = path.join(
        stablePublicInput,
        `platform-qualification-${platform}-${installerType}.json`,
      );
      const stableQualification = await readJson(qualificationFile);
      stableQualification.releaseIdentity.releaseChannel = "stable";
      await writeFile(qualificationFile, `${JSON.stringify(stableQualification, null, 2)}\n`);
    }
    const stableReleasePolicyFixture = path.join(temporary, "stable-package.json");
    await writeFile(
      stableReleasePolicyFixture,
      `${JSON.stringify({ version: VERSION, release: { channel: "stable", target: VERSION } })}\n`,
    );
    const prereleasePolicyFixture = releasePolicyFixture;
    const stablePublicOutput = path.join(temporary, "windows-public-stable-output");
    releasePolicyFixture = stableReleasePolicyFixture;
    try {
      run("finalize-release.mjs", [
        "--input", stablePublicInput,
        "--out", stablePublicOutput,
        "--version", VERSION,
        "--tag", TAG,
        "--commit", COMMIT,
        "--publication-mode", "public-github-release",
        "--tauri-config", tauriConfig,
      ]);
      run("verify-finalized-release.mjs", [
        "--dir", stablePublicOutput,
        "--version", VERSION,
        "--tag", TAG,
        "--commit", COMMIT,
        "--publication-mode", "public-github-release",
        "--tauri-config", tauriConfig,
      ]);
    } finally {
      releasePolicyFixture = prereleasePolicyFixture;
    }
    const stablePublicMetadata = await readJson(
      path.join(stablePublicOutput, "release-metadata.json"),
    );
    const stablePublicWindows = stablePublicMetadata.distribution.platforms.find(
      ({ platform }) => platform === "windows-x86_64",
    );
    const stablePublicMac = stablePublicMetadata.distribution.platforms.find(
      ({ platform }) => platform === "macos-universal",
    );
    if (
      stablePublicMetadata.releaseChannel !== "stable" ||
      stablePublicWindows.availability !== "offered" ||
      stablePublicWindows.installers.some(({ availability, artifact }) =>
        availability !== "offered" ||
        artifact.humanPath.state !== "not-observed" ||
        artifact.operatingSystemSigning.state !== "not-configured" ||
        artifact.operatingSystemSigning.evidenceFile !== null ||
        artifact.notarization.state !== "not-applicable" ||
        artifact.windowsLifecycle.state !== "not-observed" ||
        !artifact.knownLimitations.includes("beginner-human-path-not-observed") ||
        !artifact.knownLimitations.includes("operating-system-signing-not-configured") ||
        !artifact.knownLimitations.includes("windows-lifecycle-not-observed")
      )
    ) {
      throw new Error("stable public Windows installers were blocked or overstated their evidence");
    }
    const stablePublicDmg = stablePublicMac.installers[0];
    if (
      stablePublicMac.availability !== "offered" ||
      stablePublicDmg.availability !== "offered" ||
      stablePublicDmg.artifact.technicalQualification.state !== "installer-passed-runtime-not-observed" ||
      stablePublicDmg.artifact.notarization.state !== "not-configured" ||
      !stablePublicDmg.artifact.knownLimitations.includes("managed-runtime-not-observed-on-qualification-host") ||
      !stablePublicDmg.artifact.knownLimitations.includes("apple-notarization-not-configured")
    ) {
      throw new Error("stable public macOS qualification lost or overstated its hosted-runner limitations");
    }
    const stablePublicNotes = await readFile(
      path.join(stablePublicOutput, "RELEASE_NOTES.md"),
      "utf8",
    );
    if (
      !stablePublicNotes.includes("Windows installers in this stable release are not code-signed") ||
      !stablePublicNotes.includes("Unknown publisher") ||
      !stablePublicNotes.includes("SmartScreen may warn on first run") ||
      !stablePublicNotes.includes("Authenticode not verified") ||
      stablePublicNotes.includes("unsigned Windows installers for public testing")
    ) {
      throw new Error("stable public Windows release notes did not disclose unsigned installers accurately");
    }

    const protectedCandidateInput = path.join(temporary, "windows-protected-candidate-input");
    await copyTree(scopedPublicInput, protectedCandidateInput);
    const candidateProducer = {
      version: VERSION,
      tag: TAG,
      commit: COMMIT,
      releaseChannel: "prerelease",
      publicationMode: "public-github-release",
      repository: "teddashh/ai-security-scanner",
      workflow: ".github/workflows/release.yml",
      workflowSha: COMMIT,
      runId: "123456789",
      runAttempt: "1",
      job: "finalize-supported-artifacts",
    };
    await createReleaseCandidateLock({ directory: protectedCandidateInput, ...candidateProducer });
    const protectedCandidateManifest = await readJson(
      path.join(protectedCandidateInput, "installers-windows-x86_64.json"),
    );
    const candidateNsis = protectedCandidateManifest.installers.find(({ bundleType }) => bundleType === "nsis");
    const candidateNsisArtifact = {
      file: candidateNsis.file,
      bytes: candidateNsis.bytes,
      sha256: candidateNsis.sha256,
    };
    const externalObservationInput = path.join(temporary, "windows-external-observations");
    await createWindowsExternalObservationFixture(externalObservationInput, candidateNsisArtifact);
    const protectedImporter = windowsExternalEvidenceImporterIdentity({
      repository: "teddashh/ai-security-scanner",
      workflow: ".github/workflows/windows-external-evidence.yml",
      workflowSha: "23".repeat(20),
      runId: "987654321",
      runAttempt: "2",
      job: "import",
      environment: "windows-external-evidence",
    });
    const acceptedExternalEvidence = path.join(temporary, "accepted-windows-external-evidence");
    await importWindowsExternalEvidence({
      candidateDirectory: protectedCandidateInput,
      evidenceDirectory: externalObservationInput,
      output: acceptedExternalEvidence,
      candidate: candidateProducer,
      candidateArtifactId: "11223344",
      candidateArtifactDigest: `sha256:${"ab".repeat(32)}`,
      evidenceSource: {
        repository: "teddashh/ai-security-scanner",
        commit: "34".repeat(20),
        path: `evidence/${TAG}/windows-x86_64`,
      },
      importer: protectedImporter,
      importedAt: "2026-09-07T12:05:00Z",
    });
    const materializedExternalCandidate = path.join(temporary, "windows-candidate-with-external-evidence");
    await materializeWindowsExternalEvidence({
      directory: acceptedExternalEvidence,
      candidateDirectory: protectedCandidateInput,
      output: materializedExternalCandidate,
      expectedImporter: protectedImporter,
    });
    const externalEvidenceArgs = [
      "--external-evidence-repository", protectedImporter.repository,
      "--external-evidence-workflow", protectedImporter.workflow,
      "--external-evidence-workflow-ref", protectedImporter.workflowRef,
      "--external-evidence-run-id", protectedImporter.runId,
      "--external-evidence-run-attempt", String(protectedImporter.runAttempt),
      "--external-evidence-job", protectedImporter.job,
      "--external-evidence-environment", protectedImporter.environment,
    ];
    const finalizedWithExternalEvidence = path.join(temporary, "windows-finalized-with-external-evidence");
    run("finalize-release.mjs", [
      "--input", materializedExternalCandidate,
      "--out", finalizedWithExternalEvidence,
      "--version", VERSION,
      "--tag", TAG,
      "--commit", COMMIT,
      "--publication-mode", "public-github-release",
      "--tauri-config", tauriConfig,
      ...externalEvidenceArgs,
    ]);
    const verifyExternalFinalizationArguments = [
      "--dir", finalizedWithExternalEvidence,
      "--version", VERSION,
      "--tag", TAG,
      "--commit", COMMIT,
      "--publication-mode", "public-github-release",
      "--tauri-config", tauriConfig,
      ...externalEvidenceArgs,
    ];
    run("verify-finalized-release.mjs", verifyExternalFinalizationArguments);
    expectFailure(
      () => run("verify-finalized-release.mjs", [
        "--dir", scopedPublicOutput,
        "--version", VERSION,
        "--tag", TAG,
        "--commit", COMMIT,
        "--publication-mode", "public-github-release",
        "--tauri-config", tauriConfig,
        ...externalEvidenceArgs,
      ]),
      "external-evidence importer selector without a protected receipt",
    );
    const protectedFinalMetadata = await readJson(
      path.join(finalizedWithExternalEvidence, "release-metadata.json"),
    );
    const protectedFinalNsis = protectedFinalMetadata.distribution.platforms
      .find(({ platform }) => platform === "windows-x86_64")
      .installers.find(({ installerType }) => installerType === "nsis");
    if (
      protectedFinalNsis.artifact.humanPath.state !== "verified" ||
      protectedFinalNsis.artifact.operatingSystemSigning.state !== "not-configured" ||
      protectedFinalNsis.artifact.windowsLifecycle.state !== "not-observed"
    ) {
      throw new Error("protected external evidence was not represented with exact non-promotional outcomes");
    }
    await readFile(path.join(finalizedWithExternalEvidence, WINDOWS_EXTERNAL_EVIDENCE_RECEIPT_FILE));
    await readFile(path.join(finalizedWithExternalEvidence, WINDOWS_UNSIGNED_SIGNING_OBSERVATION_FILE));

    const resealedExternalOutcomeTamper = path.join(temporary, "resealed-external-outcome-tamper");
    await copyTree(finalizedWithExternalEvidence, resealedExternalOutcomeTamper);
    const tamperedExternalMetadata = await readJson(
      path.join(resealedExternalOutcomeTamper, "release-metadata.json"),
    );
    tamperedExternalMetadata.distribution.platforms
      .find(({ platform }) => platform === "windows-x86_64")
      .installers.find(({ installerType }) => installerType === "nsis")
      .artifact.windowsLifecycle.reason = "receipt-details-were-rewritten";
    await writeFile(
      path.join(resealedExternalOutcomeTamper, "release-metadata.json"),
      `${JSON.stringify(tamperedExternalMetadata, null, 2)}\n`,
    );
    await resealFinalizedFixture(resealedExternalOutcomeTamper);
    expectFailure(
      () => run("verify-finalized-release.mjs", [
        "--dir", resealedExternalOutcomeTamper,
        "--version", VERSION,
        "--tag", TAG,
        "--commit", COMMIT,
        "--publication-mode", "public-github-release",
        "--tauri-config", tauriConfig,
        ...externalEvidenceArgs,
      ]),
      "resealed protected external-evidence metadata rewrite",
    );
    process.stdout.write(
      "Release tooling self-test passed artifact-scoped v3, optional-updater, sibling-failure, protected external-evidence, stable hosted-macOS limitations, and disclosed public-Windows prerelease/stable fixtures.\n",
    );
    return;
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
}

if (path.resolve(process.argv[1] ?? "") === path.resolve(fileURLToPath(import.meta.url))) {
  runMain(main);
}
