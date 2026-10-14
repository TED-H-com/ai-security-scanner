import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  createPreparedReleaseMetadata,
  validateReleaseMetadataV3,
} from "../../scripts/release/release-metadata.mjs";
import { WINDOWS_INSTALLED_LIFECYCLE_RECORDS } from "../../scripts/release/windows-installed-lifecycle-evidence.mjs";

const releaseSchema = JSON.parse(
  await readFile(new URL("../../docs/release/release-metadata.schema.json", import.meta.url), "utf8"),
);

const identity = {
  version: "0.1.8",
  tag: "v0.1.8",
  releaseChannel: "prerelease",
  stableTarget: "0.2.0",
  sourceRepository: "https://github.com/TED-H-com/ai-security-scanner",
  sourceCommit: "01".repeat(20),
  sourceDate: "2026-08-30T00:00:00Z",
  publicationMode: "commit-bound-qc",
  sboms: [
    "ai-security-scanner-0.1.8.cyclonedx.json",
    "ai-security-scanner-0.1.8.spdx.json",
  ],
  inventories: { npmPackageCount: 1, cargoPackageCount: 2, engineReferenceCount: 3 },
};

function windowsOnlyPrepared() {
  return createPreparedReleaseMetadata({
    ...identity,
    requestedPlatforms: ["windows-x86_64"],
  });
}

function artifact() {
  return {
    file: "ai-security-scanner_0.1.8_x64_en-US.msi",
    bytes: 1234,
    sha256: "ab".repeat(32),
    technicalQualification: {
      state: "passed",
      evidenceFile: "platform-qualification-windows-x86_64-msi.json",
      reason: null,
    },
    humanPath: {
      state: "not-observed",
      evidenceFile: null,
      reason: "exact-candidate-beginner-path-not-observed",
    },
    operatingSystemSigning: {
      state: "not-configured",
      evidenceFile: null,
      reason: "artifact-has-no-verified-operating-system-signature",
    },
    notarization: {
      state: "not-applicable",
      evidenceFile: null,
      reason: "apple-notarization-does-not-apply",
    },
    windowsLifecycle: {
      state: "not-observed",
      evidenceFiles: [],
      reason: "installer-lifecycle-not-observed",
    },
    windowsDataPreservation: {
      state: "not-observed",
      evidenceFiles: [],
      reason: "installer-data-preservation-not-observed",
    },
    updater: {
      state: "not-offered",
      payloadFile: null,
      signatureFile: null,
      targetKeys: [],
      reason: "updater-not-offered-for-this-artifact",
    },
    provenanceAttestation: {
      state: "not-created-for-commit-bound-qc",
      provider: null,
      evidenceFile: null,
    },
    knownLimitations: [
      "beginner-human-path-not-observed",
      "operating-system-signing-not-configured",
      "windows-lifecycle-not-observed",
      "windows-data-preservation-not-observed",
    ],
  };
}

function supportingNsisDataPreservation() {
  return {
    state: "supporting-data-preservation-only",
    evidenceFiles: [
      ["n-minus-one-upgrade-evidence", "windows-nsis-data-preservation/n-minus-one-upgrade/evidence.json"],
      ["n-minus-one-upgrade-report", "windows-nsis-data-preservation/n-minus-one-upgrade/beginner-report.html"],
      ["ghost-repair-uninstall-evidence", "windows-nsis-data-preservation/ghost-repair-uninstall/evidence.json"],
      ["ghost-repair-uninstall-report", "windows-nsis-data-preservation/ghost-repair-uninstall/beginner-report.html"],
    ].map(([role, file], index) => ({ role, path: file, bytes: 100 + index, sha256: `${index + 1}`.repeat(64) })),
    reason: "real-installed-app-localhost-lifecycle-not-observed",
  };
}

function verifiedWindowsLifecycle() {
  return {
    state: "verified",
    evidenceFiles: [
      { path: "windows-external-evidence-import.json", bytes: 200, sha256: "f".repeat(64) },
      ...WINDOWS_INSTALLED_LIFECYCLE_RECORDS.map(({ path: recordPath }, index) => ({
        path: `windows-installed-lifecycle/${recordPath}`,
        bytes: 300 + index,
        sha256: String((index % 9) + 1).repeat(64),
      })),
    ],
    reason: null,
  };
}

function finalizedWindowsMetadata(candidateArtifact = artifact()) {
  const metadata = windowsOnlyPrepared();
  metadata.releaseState = "finalized";
  const windows = metadata.distribution.platforms[2];
  windows.availability = "offered";
  windows.installers[0] = {
    installerType: "msi",
    availability: "offered",
    reason: null,
    artifact: candidateArtifact,
  };
  windows.installers[1] = {
    installerType: "nsis",
    availability: "not-offered",
    reason: "technical-qualification-not-observed",
    artifact: null,
  };
  return metadata;
}

test("prepared v3 metadata records a requested Windows subset without global security claims", () => {
  for (const owner of ["teddashh", "TED-H-com"]) {
    const paired = windowsOnlyPrepared();
    paired.sourceRepository = `https://github.com/${owner}/ai-security-scanner`;
    validateReleaseMetadataV3(paired);
  }
  const unknown = windowsOnlyPrepared();
  unknown.sourceRepository = "https://github.com/unknown/ai-security-scanner";
  assert.throws(() => validateReleaseMetadataV3(unknown), /publication source repository/u);
  const metadata = windowsOnlyPrepared();
  assert.equal(metadata.schemaVersion, 3);
  assert.equal(metadata.releaseState, "prepared");
  assert.deepEqual(Object.keys(metadata.security), ["checksums", "sboms"]);
  assert.deepEqual(
    metadata.distribution.platforms.map(({ platform, availability }) => [platform, availability]),
    [
      ["linux-x86_64", "not-offered"],
      ["macos-universal", "not-offered"],
      ["windows-x86_64", "pending"],
    ],
  );
  assert.doesNotThrow(() => validateReleaseMetadataV3(metadata, { releaseState: "prepared" }));
});

test("finalized v3 metadata can offer one qualified artifact while siblings stay explicit", () => {
  const metadata = windowsOnlyPrepared();
  metadata.releaseState = "finalized";
  const windows = metadata.distribution.platforms[2];
  windows.availability = "offered";
  windows.installers[0] = {
    installerType: "msi",
    availability: "offered",
    reason: null,
    artifact: artifact(),
  };
  windows.installers[1] = {
    installerType: "nsis",
    availability: "not-offered",
    reason: "technical-qualification-not-observed",
    artifact: null,
  };
  assert.doesNotThrow(() => validateReleaseMetadataV3(metadata, { releaseState: "finalized" }));

  const invalidSibling = structuredClone(metadata);
  invalidSibling.distribution.platforms[2].installers[1].availability = "offered";
  invalidSibling.distribution.platforms[2].installers[1].reason = null;
  assert.throws(
    () => validateReleaseMetadataV3(invalidSibling, { releaseState: "finalized" }),
    /artifact must be an object/u,
  );
  assert.equal(metadata.distribution.platforms[2].installers[0].availability, "offered");
});

test("unsigned artifact rejects claimed operating-system signing evidence", () => {
  const candidateArtifact = artifact();
  candidateArtifact.operatingSystemSigning.evidenceFile = "authenticode-evidence.json";
  const metadata = finalizedWindowsMetadata(candidateArtifact);

  assert.throws(
    () => validateReleaseMetadataV3(metadata, { releaseState: "finalized" }),
    {
      name: "Error",
      message: "windows-x86_64/ai-security-scanner_0.1.8_x64_en-US.msi unsigned artifact must not claim signing evidence",
    },
  );
});

test("unsigned artifact rejects a null or empty signing reason", () => {
  for (const reason of [null, ""]) {
    const candidateArtifact = artifact();
    candidateArtifact.operatingSystemSigning.reason = reason;
    const metadata = finalizedWindowsMetadata(candidateArtifact);

    assert.throws(
      () => validateReleaseMetadataV3(metadata, { releaseState: "finalized" }),
      {
        name: "Error",
        message: "windows-x86_64/ai-security-scanner_0.1.8_x64_en-US.msi unsigned artifact needs a reason",
      },
    );
  }
});

test("correctly formed unsigned artifact is accepted without signing or notarization evidence", () => {
  assert.doesNotThrow(
    () => validateReleaseMetadataV3(finalizedWindowsMetadata(), { releaseState: "finalized" }),
  );
});

test("non-verified notarization rejects claimed evidence", () => {
  const candidateArtifact = artifact();
  candidateArtifact.notarization.evidenceFile = "notarization-evidence.json";
  const metadata = finalizedWindowsMetadata(candidateArtifact);

  assert.throws(
    () => validateReleaseMetadataV3(metadata, { releaseState: "finalized" }),
    {
      name: "Error",
      message: "windows-x86_64/ai-security-scanner_0.1.8_x64_en-US.msi notarization state fabricates evidence",
    },
  );
});

test("non-verified notarization rejects a null or empty reason", () => {
  for (const reason of [null, ""]) {
    const candidateArtifact = artifact();
    candidateArtifact.notarization.reason = reason;
    const metadata = finalizedWindowsMetadata(candidateArtifact);

    assert.throws(
      () => validateReleaseMetadataV3(metadata, { releaseState: "finalized" }),
      {
        name: "Error",
        message: "windows-x86_64/ai-security-scanner_0.1.8_x64_en-US.msi notarization state needs a reason",
      },
    );
  }
});

test("public Windows releases remain offerable on prerelease and stable with exact limitations", () => {
  const metadata = windowsOnlyPrepared();
  metadata.publicationMode = "public-github-release";
  metadata.releaseState = "finalized";
  const windows = metadata.distribution.platforms[2];
  windows.availability = "offered";
  const publicArtifact = artifact();
  publicArtifact.provenanceAttestation = {
    state: "required-before-publication",
    provider: "GitHub artifact attestations",
    evidenceFile: null,
  };
  windows.installers[0] = {
    installerType: "msi",
    availability: "offered",
    reason: null,
    artifact: publicArtifact,
  };
  windows.installers[1] = {
    installerType: "nsis",
    availability: "not-offered",
    reason: "beginner-human-path-not-observed;authenticode-not-verified",
    artifact: null,
  };
  assert.doesNotThrow(
    () => validateReleaseMetadataV3(metadata, { releaseState: "finalized" }),
  );

  for (const [limitation, expectedError] of [
    ["beginner-human-path-not-observed", /does not disclose its unobserved beginner human path/u],
    ["operating-system-signing-not-configured", /does not disclose its missing operating-system signature/u],
    ["windows-lifecycle-not-observed", /does not disclose its unobserved Windows lifecycle/u],
    ["windows-data-preservation-not-observed", /does not disclose its unobserved Windows data preservation/u],
  ]) {
    const undisclosedPrerelease = structuredClone(metadata);
    const candidate = undisclosedPrerelease.distribution.platforms[2].installers[0].artifact;
    candidate.knownLimitations = candidate.knownLimitations.filter((item) => item !== limitation);
    assert.throws(
      () => validateReleaseMetadataV3(undisclosedPrerelease, { releaseState: "finalized" }),
      expectedError,
    );
  }

  const stable = structuredClone(metadata);
  stable.releaseChannel = "stable";
  stable.stableTarget = stable.version;
  assert.doesNotThrow(() => validateReleaseMetadataV3(stable, { releaseState: "finalized" }));
  const stableArtifact = stable.distribution.platforms[2].installers[0].artifact;
  assert.equal(stableArtifact.humanPath.state, "not-observed");
  assert.equal(stableArtifact.operatingSystemSigning.state, "not-configured");
  assert.equal(stableArtifact.operatingSystemSigning.evidenceFile, null);
  assert.equal(stableArtifact.windowsLifecycle.state, "not-observed");

  for (const [limitation, expectedError] of [
    ["beginner-human-path-not-observed", /does not disclose its unobserved beginner human path/u],
    ["operating-system-signing-not-configured", /does not disclose its missing operating-system signature/u],
    ["windows-lifecycle-not-observed", /does not disclose its unobserved Windows lifecycle/u],
  ]) {
    const undisclosedStable = structuredClone(stable);
    const candidate = undisclosedStable.distribution.platforms[2].installers[0].artifact;
    candidate.knownLimitations = candidate.knownLimitations.filter((item) => item !== limitation);
    assert.throws(
      () => validateReleaseMetadataV3(undisclosedStable, { releaseState: "finalized" }),
      expectedError,
    );
  }
});

test("MSI cannot claim an updater target the desktop runtime cannot consume", () => {
  const metadata = windowsOnlyPrepared();
  metadata.releaseState = "finalized";
  const windows = metadata.distribution.platforms[2];
  windows.availability = "offered";
  const invalidArtifact = artifact();
  invalidArtifact.updater = {
    state: "signed",
    payloadFile: invalidArtifact.file,
    signatureFile: `${invalidArtifact.file}.sig`,
    targetKeys: ["windows-x86_64-msi"],
    reason: null,
  };
  windows.installers[0] = {
    installerType: "msi",
    availability: "offered",
    reason: null,
    artifact: invalidArtifact,
  };
  windows.installers[1] = {
    installerType: "nsis",
    availability: "not-offered",
    reason: "technical-qualification-not-observed",
    artifact: null,
  };
  assert.throws(
    () => validateReleaseMetadataV3(metadata, { releaseState: "finalized" }),
    /not a runtime-consumable updater package/u,
  );
});

test("NSIS fixture evidence is retained only as supporting data preservation and cannot stand in for MSI", () => {
  const metadata = windowsOnlyPrepared();
  metadata.releaseState = "finalized";
  const windows = metadata.distribution.platforms[2];
  windows.availability = "offered";
  const nsisArtifact = artifact();
  nsisArtifact.file = "ai-security-scanner_0.1.8_x64-setup.exe";
  nsisArtifact.technicalQualification.evidenceFile = "platform-qualification-windows-x86_64-nsis.json";
  nsisArtifact.windowsDataPreservation = supportingNsisDataPreservation();
  nsisArtifact.knownLimitations = nsisArtifact.knownLimitations
    .filter((limitation) => limitation !== "windows-data-preservation-not-observed");
  nsisArtifact.knownLimitations.push("windows-data-preservation-fixtures-only");
  windows.installers[0] = {
    installerType: "msi",
    availability: "not-offered",
    reason: "equivalent-msi-lifecycle-not-observed",
    artifact: null,
  };
  windows.installers[1] = {
    installerType: "nsis",
    availability: "offered",
    reason: null,
    artifact: nsisArtifact,
  };
  assert.doesNotThrow(() => validateReleaseMetadataV3(metadata, { releaseState: "finalized" }));

  const mislabeledMsi = structuredClone(metadata);
  mislabeledMsi.distribution.platforms[2].installers = [
    { installerType: "msi", availability: "offered", reason: null, artifact: nsisArtifact },
    { installerType: "nsis", availability: "not-offered", reason: "not-tested", artifact: null },
  ];
  assert.throws(
    () => validateReleaseMetadataV3(mislabeledMsi, { releaseState: "finalized" }),
    /unsupported for this installer/u,
  );
});

test("protected lifecycle evidence can qualify NSIS only when every canonical row is retained", () => {
  const metadata = windowsOnlyPrepared();
  metadata.releaseState = "finalized";
  const windows = metadata.distribution.platforms[2];
  windows.availability = "offered";
  const nsisArtifact = artifact();
  nsisArtifact.file = "ai-security-scanner_0.1.8_x64-setup.exe";
  nsisArtifact.technicalQualification.evidenceFile = "platform-qualification-windows-x86_64-nsis.json";
  nsisArtifact.windowsLifecycle = verifiedWindowsLifecycle();
  nsisArtifact.knownLimitations = nsisArtifact.knownLimitations.filter(
    (limitation) => limitation !== "windows-lifecycle-not-observed",
  );
  windows.installers[0] = {
    installerType: "msi",
    availability: "not-offered",
    reason: "not-tested",
    artifact: null,
  };
  windows.installers[1] = {
    installerType: "nsis",
    availability: "offered",
    reason: null,
    artifact: nsisArtifact,
  };
  assert.doesNotThrow(() => validateReleaseMetadataV3(metadata, { releaseState: "finalized" }));

  const missingRow = structuredClone(metadata);
  missingRow.distribution.platforms[2].installers[1].artifact.windowsLifecycle.evidenceFiles.pop();
  assert.throws(
    () => validateReleaseMetadataV3(missingRow, { releaseState: "finalized" }),
    /missing a required row/u,
  );

  const partial = structuredClone(metadata);
  const partialArtifact = partial.distribution.platforms[2].installers[1].artifact;
  partialArtifact.windowsLifecycle.state = "partial";
  partialArtifact.windowsLifecycle.reason = "external-installed-app-lifecycle-partial";
  partialArtifact.windowsLifecycle.evidenceFiles.pop();
  partialArtifact.knownLimitations.push("windows-lifecycle-partial");
  assert.doesNotThrow(() => validateReleaseMetadataV3(partial, { releaseState: "finalized" }));
  partialArtifact.knownLimitations = partialArtifact.knownLimitations.filter(
    (limitation) => limitation !== "windows-lifecycle-partial",
  );
  assert.throws(
    () => validateReleaseMetadataV3(partial, { releaseState: "finalized" }),
    /does not disclose its partial Windows lifecycle/u,
  );
});

test("JSON schema fixes the same ordered platform/installer tuples and lifecycle states as the JS validator", () => {
  assert.deepEqual(
    releaseSchema.properties.distribution.properties.platforms.prefixItems.map(({ $ref }) => $ref),
    ["#/$defs/linuxPlatform", "#/$defs/macosPlatform", "#/$defs/windowsPlatform"],
  );
  assert.equal(releaseSchema.properties.distribution.properties.platforms.items, false);
  for (const [definition, platform, installers] of [
    ["linuxPlatform", "linux-x86_64", ["appimageInstaller", "debInstaller", "rpmInstaller"]],
    ["macosPlatform", "macos-universal", ["dmgInstaller"]],
    ["windowsPlatform", "windows-x86_64", ["msiInstaller", "nsisInstaller"]],
  ]) {
    const contract = releaseSchema.$defs[definition].allOf[1].properties;
    assert.equal(contract.platform.const, platform);
    assert.deepEqual(
      contract.installers.prefixItems.map(({ $ref }) => $ref.replace("#/$defs/", "")),
      installers,
    );
    assert.equal(contract.installers.items, false);
  }
  const releaseStateConditional = releaseSchema.allOf[0];
  const preparedPlatform =
    releaseStateConditional.then.properties.distribution.properties.platforms.items.properties;
  const finalizedPlatform =
    releaseStateConditional.else.properties.distribution.properties.platforms.items.properties;
  assert.deepEqual(preparedPlatform.availability.enum, ["pending", "not-offered"]);
  assert.deepEqual(preparedPlatform.installers.items.properties.availability.enum, ["pending", "not-offered"]);
  assert.deepEqual(finalizedPlatform.availability.enum, ["offered", "not-offered"]);
  assert.deepEqual(finalizedPlatform.installers.items.properties.availability.enum, ["offered", "not-offered"]);
  assert.equal(releaseSchema.$defs.windowsLifecycle.oneOf.length, 4);
  assert.equal(releaseSchema.$defs.verifiedWindowsLifecycle.properties.evidenceFiles.minItems, 16);
  assert.equal(
    releaseSchema.$defs.nsisArtifactOrNull.oneOf[1].allOf[1].properties.windowsLifecycle.$ref,
    "#/$defs/windowsLifecycle",
  );
  assert.equal(
    releaseSchema.$defs.msiArtifactOrNull.oneOf[1].allOf[1].properties.windowsDataPreservation.$ref,
    "#/$defs/notObservedWindowsDataPreservation",
  );
  assert.equal(
    releaseSchema.$defs.nsisArtifactOrNull.oneOf[1].allOf[1].properties.windowsDataPreservation.$ref,
    "#/$defs/windowsNsisDataPreservation",
  );
  assert.equal(releaseSchema.$defs.supportingWindowsNsisDataPreservation.properties.evidenceFiles.minItems, 4);
  assert.equal(releaseSchema.$defs.supportingWindowsNsisDataPreservation.properties.reason.const,
    "real-installed-app-localhost-lifecycle-not-observed");
  assert.equal(releaseSchema.allOf.length, 2);
  assert.equal(JSON.stringify(releaseSchema.allOf).includes('"releaseChannel"'), false);
});
