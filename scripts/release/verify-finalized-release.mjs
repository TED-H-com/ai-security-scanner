import { lstat, readdir, readFile } from "node:fs/promises";
import path from "node:path";
import {
  PROJECT_ROOT,
  assertSafeRelativePath,
  isSemver,
  parseArgs,
  readJson,
  requireString,
  runMain,
  sha256File,
  toPosix,
} from "./lib.mjs";
import { validateReleaseMetadataV3 } from "./release-metadata.mjs";
import { verifyBoundArtifactEvidenceFile } from "./artifact-evidence.mjs";
import { verifyPlatformQualificationFile } from "./platform-qualification.mjs";
import { verifyUpdaterSignatures } from "./verify-updater-signatures.mjs";
import { verifyWindowsNsisSupportingDataPreservationEvidence } from "./windows-data-preservation-evidence.mjs";
import {
  WINDOWS_EXTERNAL_EVIDENCE_RECEIPT_FILE,
  verifyFinalizedWindowsExternalEvidenceOutcomes,
  verifyFinalizedWindowsExternalEvidence,
  windowsExternalEvidenceImporterIdentity,
} from "./windows-external-evidence.mjs";
import { publishedReleaseAssetName } from "./release-asset-name.mjs";
import { PUBLICATION_ORIGINS, UPDATER_DOWNLOAD_REPOSITORY } from "../publication-origins.mjs";

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

function expectedExternalEvidenceImporter(args) {
  const workflowRef = requireString(args, "external-evidence-workflow-ref");
  const separator = workflowRef.lastIndexOf("@");
  assert(separator > 0, "external-evidence workflow ref must end in its full workflow SHA");
  const importer = windowsExternalEvidenceImporterIdentity({
    repository: requireString(args, "external-evidence-repository"),
    workflow: requireString(args, "external-evidence-workflow"),
    workflowSha: workflowRef.slice(separator + 1),
    runId: requireString(args, "external-evidence-run-id"),
    runAttempt: requireString(args, "external-evidence-run-attempt"),
    job: requireString(args, "external-evidence-job"),
    environment: requireString(args, "external-evidence-environment"),
  });
  assert(importer.workflowRef === workflowRef, "external-evidence workflow ref is inconsistent");
  return importer;
}

const EXTERNAL_EVIDENCE_IMPORTER_ARGUMENTS = Object.freeze([
  "external-evidence-repository",
  "external-evidence-workflow",
  "external-evidence-workflow-ref",
  "external-evidence-run-id",
  "external-evidence-run-attempt",
  "external-evidence-job",
  "external-evidence-environment",
]);

function externalEvidenceImporterForRelease(args, hasReceipt) {
  const supplied = EXTERNAL_EVIDENCE_IMPORTER_ARGUMENTS.filter((key) => args.has(key));
  assert(
    supplied.length === 0 || supplied.length === EXTERNAL_EVIDENCE_IMPORTER_ARGUMENTS.length,
    "external-evidence importer arguments must be supplied as one complete set",
  );
  assert(
    hasReceipt === (supplied.length === EXTERNAL_EVIDENCE_IMPORTER_ARGUMENTS.length),
    hasReceipt
      ? "protected external-evidence receipt requires its exact importer arguments"
      : "external-evidence importer arguments were supplied without a protected receipt",
  );
  return hasReceipt ? expectedExternalEvidenceImporter(args) : null;
}

const PUBLICATION_MODES = new Set(["commit-bound-qc", "public-github-release"]);

async function regularFiles(directory, root = directory) {
  const files = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const absolute = path.join(directory, entry.name);
    const metadata = await lstat(absolute);
    if (metadata.isSymbolicLink()) {
      throw new Error(`finalized release contains a symlink: ${absolute}`);
    }
    if (metadata.isDirectory()) {
      files.push(...(await regularFiles(absolute, root)));
    } else if (metadata.isFile()) {
      files.push({
        absolute,
        relative: toPosix(path.relative(root, absolute)),
        bytes: metadata.size,
      });
    } else {
      throw new Error(`finalized release contains a special file: ${absolute}`);
    }
  }
  return files;
}

function sorted(values) {
  return [...values].sort((left, right) => left.localeCompare(right));
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const directory = path.resolve(requireString(args, "dir"));
  const version = requireString(args, "version");
  const tag = requireString(args, "tag");
  const commit = requireString(args, "commit");
  const publicationMode = requireString(args, "publication-mode");
  if (!isSemver(version) || tag !== `v${version}` || !/^[0-9a-f]{40}$/u.test(commit)) {
    throw new Error("release identity is malformed or inconsistent");
  }
  assert(
    PUBLICATION_MODES.has(publicationMode),
    "publication mode must be commit-bound-qc or public-github-release",
  );

  const files = await regularFiles(directory);
  const actualByPath = new Map(files.map((file) => [file.relative, file]));
  const actualByPublishedName = new Map();
  const foldedPublishedNames = new Set();
  for (const file of files) {
    const publishedName = publishedReleaseAssetName(file.relative);
    const folded = publishedName.toLowerCase();
    assert(!foldedPublishedNames.has(folded), `finalized publication filename collision: ${publishedName}`);
    foldedPublishedNames.add(folded);
    actualByPublishedName.set(publishedName, file);
  }
  assert(actualByPath.has("SHA256SUMS.txt"), "finalized release has no SHA256SUMS.txt");
  assert(actualByPath.has("release-assets.json"), "finalized release has no release-assets.json");

  const checksumContents = await readFile(path.join(directory, "SHA256SUMS.txt"), "utf8");
  assert(checksumContents.endsWith("\n"), "SHA256SUMS.txt must end with one newline");
  const checksumBody = checksumContents.slice(0, -1);
  assert(checksumBody.length > 0, "SHA256SUMS.txt must not be empty");
  const checksumLines = checksumBody.split("\n");
  assert(
    checksumLines.every((line) => line.length > 0),
    "SHA256SUMS.txt must not contain blank lines",
  );
  const checksums = new Map();
  for (const line of checksumLines) {
    const match = line.match(/^([0-9a-f]{64})  ([^\0\r\n]+)$/u);
    assert(match, `malformed SHA256SUMS.txt line: ${line}`);
    const publishedName = match[2];
    assertSafeRelativePath(publishedName);
    assert(
      toPosix(publishedName) === publishedName &&
        path.posix.basename(publishedName) === publishedName &&
        path.win32.basename(publishedName) === publishedName,
      `checksum publication name is not one canonical flat filename: ${publishedName}`,
    );
    assert(publishedName !== "SHA256SUMS.txt", "SHA256SUMS.txt must not claim to cover itself");
    assert(!checksums.has(publishedName), `duplicate checksum entry: ${publishedName}`);
    checksums.set(publishedName, match[1]);
  }

  const checksumCoveredPaths = sorted(
    [...actualByPath.keys()]
      .filter((relative) => relative !== "SHA256SUMS.txt")
      .map((relative) => publishedReleaseAssetName(relative)),
  );
  assert(
    JSON.stringify(sorted(checksums.keys())) === JSON.stringify(checksumCoveredPaths),
    "SHA256SUMS.txt does not exactly cover every other finalized release file",
  );
  for (const [publishedName, expectedDigest] of checksums) {
    const actual = actualByPublishedName.get(publishedName);
    assert(actual, `checksum references a missing publication file: ${publishedName}`);
    assert((await sha256File(actual.absolute)) === expectedDigest, `checksum mismatch: ${publishedName}`);
  }
  const checksumForPath = (relative) => checksums.get(publishedReleaseAssetName(relative));

  const index = await readJson(path.join(directory, "release-assets.json"));
  assert(index.schemaVersion === 3, "release index schemaVersion must be 3");
  assert(index.product === "ai-security-scanner", "release index product is incorrect");
  assert(index.version === version && index.tag === tag, "release index version/tag mismatch");
  assert(index.sourceCommit === commit, "release index source commit mismatch");
  assert(index.publicationMode === publicationMode, "release index publication mode mismatch");
  assert(index.indexSelfExcluded === true, "release index must declare its self-exclusion");
  assert(Array.isArray(index.files), "release index has no files array");

  const indexEntries = new Map();
  const indexPublishedNames = new Set();
  for (const record of index.files) {
    assert(record && typeof record === "object", "release index contains an invalid file record");
    assert(
      JSON.stringify(Object.keys(record)) ===
        JSON.stringify(["path", "publishedName", "bytes", "sha256"]),
      "release index file record fields are not the schema-v3 set",
    );
    assertSafeRelativePath(record.path);
    assert(toPosix(record.path) === record.path, `index path is not canonical POSIX form: ${record.path}`);
    assert(
      record.path !== "SHA256SUMS.txt" && record.path !== "release-assets.json",
      `release index improperly includes a self-generated file: ${record.path}`,
    );
    assert(!indexEntries.has(record.path), `release index contains a duplicate path: ${record.path}`);
    assert(
      record.publishedName === publishedReleaseAssetName(record.path),
      `release index publication name is not derived from its logical path: ${record.path}`,
    );
    const foldedPublishedName = record.publishedName.toLowerCase();
    assert(
      !indexPublishedNames.has(foldedPublishedName),
      `release index contains a colliding publication name: ${record.publishedName}`,
    );
    indexPublishedNames.add(foldedPublishedName);
    assert(Number.isSafeInteger(record.bytes) && record.bytes >= 0, `invalid byte count: ${record.path}`);
    assert(/^[0-9a-f]{64}$/u.test(record.sha256), `invalid digest: ${record.path}`);
    indexEntries.set(record.path, record);
  }

  const indexCoveredPaths = sorted(
    [...actualByPath.keys()].filter(
      (relative) => relative !== "SHA256SUMS.txt" && relative !== "release-assets.json",
    ),
  );
  assert(
    JSON.stringify(sorted(indexEntries.keys())) === JSON.stringify(indexCoveredPaths),
    "release-assets.json does not exactly index every pre-index release file",
  );
  for (const [relative, record] of indexEntries) {
    const actual = actualByPath.get(relative);
    assert(actual, `release index references a missing file: ${relative}`);
    assert(actual.bytes === record.bytes, `release index byte count mismatch: ${relative}`);
    assert(checksumForPath(relative) === record.sha256, `release index digest mismatch: ${relative}`);
  }

  const releaseMetadata = await readJson(path.join(directory, "release-metadata.json"));
  assert(
    PUBLICATION_ORIGINS.some(({ repository }) => releaseMetadata.sourceRepository === `https://github.com/${repository}`),
    "finalized release source repository is not a known publication origin",
  );
  validateReleaseMetadataV3(releaseMetadata, {
    releaseState: "finalized",
    version,
    tag,
    sourceCommit: commit,
    publicationMode,
  });
  const packageJson = await readJson(
    path.resolve(args.get("package-json") ?? path.join(PROJECT_ROOT, "package.json")),
  );
  assert(
    releaseMetadata.releaseChannel === packageJson.release?.channel &&
      releaseMetadata.stableTarget === packageJson.release?.target,
    "finalized release channel does not match the exact source package",
  );
  const latest = await readJson(path.join(directory, "latest.json"));
  assert(
    latest.version === version && latest.tag === tag && latest.platforms &&
      typeof latest.platforms === "object" && !Array.isArray(latest.platforms),
    "finalized updater manifest identity is invalid",
  );
  const tauriConfigPath = path.resolve(args.get("tauri-config") ?? path.join(PROJECT_ROOT, "src-tauri", "tauri.conf.json"));
  const tauriConfig = await readJson(tauriConfigPath);
  const updaterPublicKey = tauriConfig.plugins?.updater?.pubkey;
  const updaterTargets = new Set();
  const updaterTargetRecords = new Map();
  const hasExternalEvidenceReceipt = actualByPath.has(WINDOWS_EXTERNAL_EVIDENCE_RECEIPT_FILE);
  const externalEvidenceImporter = externalEvidenceImporterForRelease(args, hasExternalEvidenceReceipt);
  let verifiedExternalEvidence = null;
  let offeredArtifacts = 0;
  for (const platform of releaseMetadata.distribution.platforms) {
    for (const installer of platform.installers) {
      if (installer.availability !== "offered") continue;
      offeredArtifacts += 1;
      const artifact = installer.artifact;
      const actual = actualByPath.get(artifact.file);
      assert(actual, `offered artifact is missing: ${artifact.file}`);
      assert(actual.bytes === artifact.bytes, `offered artifact byte count mismatch: ${artifact.file}`);
      assert(checksumForPath(artifact.file) === artifact.sha256, `offered artifact digest mismatch: ${artifact.file}`);
      if (
        hasExternalEvidenceReceipt &&
        platform.platform === "windows-x86_64" &&
        installer.installerType === "nsis"
      ) {
        verifiedExternalEvidence = await verifyFinalizedWindowsExternalEvidence({
          directory,
          expectedImporter: externalEvidenceImporter,
          artifact: { file: artifact.file, bytes: artifact.bytes, sha256: artifact.sha256 },
          version,
          tag,
          commit,
          releaseChannel: releaseMetadata.releaseChannel,
          publicationMode,
        });
        verifyFinalizedWindowsExternalEvidenceOutcomes({
          receipt: verifiedExternalEvidence.receipt,
          receiptFile: {
            path: WINDOWS_EXTERNAL_EVIDENCE_RECEIPT_FILE,
            bytes: actualByPath.get(WINDOWS_EXTERNAL_EVIDENCE_RECEIPT_FILE).bytes,
            sha256: checksumForPath(WINDOWS_EXTERNAL_EVIDENCE_RECEIPT_FILE),
          },
          humanPath: artifact.humanPath,
          windowsLifecycle: artifact.windowsLifecycle,
        });
      }
      const technicalEvidence = artifact.technicalQualification.evidenceFile;
      assert(actualByPath.has(technicalEvidence), `artifact-scoped evidence is missing: ${technicalEvidence}`);
      await verifyPlatformQualificationFile(path.join(directory, technicalEvidence), {
        platform: platform.platform,
        installerType: installer.installerType,
        version,
        tag,
        commit,
        releaseChannel: releaseMetadata.releaseChannel,
        releaseDirectory: directory,
      });
      for (const [outcome, evidenceType] of [
        [artifact.humanPath, "beginner-human-path"],
        [artifact.operatingSystemSigning, "operating-system-code-signing"],
        [artifact.notarization, "apple-notarization"],
      ]) {
        if (!outcome.evidenceFile) continue;
        assert(actualByPath.has(outcome.evidenceFile), `artifact-scoped evidence is missing: ${outcome.evidenceFile}`);
        await verifyBoundArtifactEvidenceFile(path.join(directory, outcome.evidenceFile), {
          platform: platform.platform,
          installerType: installer.installerType,
          version,
          tag,
          commit,
          artifact,
          evidenceType,
          label: outcome.evidenceFile,
        });
      }
      if (artifact.humanPath.state === "verified") {
        assert(
          verifiedExternalEvidence && platform.platform === "windows-x86_64" && installer.installerType === "nsis",
          "verified Windows beginner evidence has no protected external-evidence receipt",
        );
      }
      if (["verified", "partial", "failed"].includes(artifact.windowsLifecycle.state)) {
        assert(verifiedExternalEvidence, "observed Windows lifecycle has no protected external-evidence receipt");
        for (const record of artifact.windowsLifecycle.evidenceFiles) {
          const actualEvidence = actualByPath.get(record.path);
          assert(actualEvidence, `Windows lifecycle evidence is missing: ${record.path}`);
          assert(actualEvidence.bytes === record.bytes, `Windows lifecycle evidence bytes changed: ${record.path}`);
          assert(checksumForPath(record.path) === record.sha256, `Windows lifecycle evidence digest changed: ${record.path}`);
        }
      }
      if (artifact.windowsDataPreservation.state === "supporting-data-preservation-only") {
        for (const dataPreservationFile of artifact.windowsDataPreservation.evidenceFiles) {
          const dataPreservationActual = actualByPath.get(dataPreservationFile.path);
          assert(dataPreservationActual, `Windows data-preservation evidence is missing: ${dataPreservationFile.path}`);
          assert(
            dataPreservationActual.bytes === dataPreservationFile.bytes,
            `Windows data-preservation evidence bytes changed: ${dataPreservationFile.path}`,
          );
          assert(
            checksumForPath(dataPreservationFile.path) === dataPreservationFile.sha256,
            `Windows data-preservation evidence digest changed: ${dataPreservationFile.path}`,
          );
        }
        const revalidatedDataPreservation = await verifyWindowsNsisSupportingDataPreservationEvidence({
          root: directory,
          artifactDirectory: directory,
          version,
          tag,
          commit,
        });
        assert(
          JSON.stringify(revalidatedDataPreservation) === JSON.stringify(artifact.windowsDataPreservation),
          "publisher-side Windows data-preservation evidence differs from finalized metadata",
        );
      }
      if (artifact.updater.state === "signed") {
        assert(
          typeof updaterPublicKey === "string" && updaterPublicKey.length >= 64,
          `signed updater ${artifact.updater.payloadFile} has no embedded verification key`,
        );
        assert(actualByPath.has(artifact.updater.payloadFile), `updater payload is missing: ${artifact.updater.payloadFile}`);
        assert(actualByPath.has(artifact.updater.signatureFile), `updater signature is missing: ${artifact.updater.signatureFile}`);
        const platformManifest = await readJson(path.join(directory, `installers-${platform.platform}.json`));
        assert(
          platformManifest.schemaVersion === 3 && platformManifest.artifactScoped === true &&
            platformManifest.version === version && platformManifest.tag === tag &&
            platformManifest.sourceCommit === commit && platformManifest.platform === platform.platform,
          `${platform.platform} finalized installer manifest identity is invalid`,
        );
        const updaterRecords = platformManifest.updaters.filter((record) =>
          record.payloadFile === artifact.updater.payloadFile &&
          record.signatureFile === artifact.updater.signatureFile,
        );
        assert(updaterRecords.length === 1, `updater record is missing or ambiguous: ${artifact.updater.payloadFile}`);
        const updaterRecord = updaterRecords[0];
        assert(
          JSON.stringify(updaterRecord.targetKeys) === JSON.stringify(artifact.updater.targetKeys),
          `updater target keys changed: ${artifact.updater.payloadFile}`,
        );
        const payloadActual = actualByPath.get(updaterRecord.payloadFile);
        const signatureActual = actualByPath.get(updaterRecord.signatureFile);
        assert(
          payloadActual.bytes === updaterRecord.payloadBytes &&
            checksumForPath(updaterRecord.payloadFile) === updaterRecord.payloadSha256,
          `updater payload identity changed: ${updaterRecord.payloadFile}`,
        );
        assert(
          signatureActual.bytes === updaterRecord.signatureBytes &&
            checksumForPath(updaterRecord.signatureFile) === updaterRecord.signatureSha256,
          `updater signature-file identity changed: ${updaterRecord.signatureFile}`,
        );
        const inlineSignature = (await readFile(signatureActual.absolute, "utf8")).trim();
        assert(inlineSignature === updaterRecord.signature, `updater inline signature changed: ${updaterRecord.signatureFile}`);
        verifyUpdaterSignatures(updaterPublicKey, [{
          payload: payloadActual.absolute,
          signature: signatureActual.absolute,
        }]);
        const expectedUrl =
          `https://github.com/${UPDATER_DOWNLOAD_REPOSITORY}/releases/download/${tag}/${encodeURIComponent(updaterRecord.payloadFile)}`;
        for (const target of artifact.updater.targetKeys) {
          assert(!updaterTargets.has(target), `duplicate finalized updater target: ${target}`);
          updaterTargets.add(target);
          const latestRecord = latest.platforms[target];
          assert(
            latestRecord && latestRecord.url === expectedUrl && latestRecord.signature === inlineSignature,
            `latest.json does not bind ${target} to the exact ${tag} payload and inline signature`,
          );
          updaterTargetRecords.set(target, latestRecord);
        }
      }
    }
  }
  assert(offeredArtifacts > 0, "finalized release metadata has no offered artifact");
  assert(
    !hasExternalEvidenceReceipt || verifiedExternalEvidence,
    "protected external-evidence receipt is not bound to an offered Windows NSIS artifact",
  );
  assert(
    JSON.stringify(sorted(Object.keys(latest.platforms))) === JSON.stringify(sorted(updaterTargets)),
    "finalized updater manifest does not exactly match offered artifact updater targets",
  );
  assert(
    JSON.stringify(Object.fromEntries([...updaterTargetRecords].sort(([left], [right]) => left.localeCompare(right)))) ===
      JSON.stringify(Object.fromEntries(Object.entries(latest.platforms).sort(([left], [right]) => left.localeCompare(right)))),
    "latest.json contains an unverified or resealed updater target",
  );

  process.stdout.write(
    `Verified ${checksums.size} finalized files, ${indexEntries.size} indexed release inputs, and ${offeredArtifacts} independently offered artifact(s) for ${tag}.\n`,
  );
}

runMain(main);
