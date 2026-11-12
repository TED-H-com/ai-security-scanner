import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { build } from "esbuild";

import { declaredHostScanProfileByWire } from "../../src/internalHostProfile.ts";

// The report's closed vocabularies are declared twice: once as a Rust enum the
// backend serializes, once as a TypeScript union the app narrows on. A variant
// added on one side and missed on the other compiles, passes every existing
// gate, and reaches the reader as an unhandled value -- a coverage row with no
// label, or a next step the page cannot name.
//
// Nothing else catches it. `tsconfig.app.json` includes only `src`, so a bad
// literal in a test is not even a type error, and the Rust side has no reason
// to know the union exists. This test reads both declarations.

const rust = (file: string) =>
  readFileSync(new URL(`../../src-tauri/src/${file}`, import.meta.url), "utf8");

const typescriptFile = (file: string) =>
  readFileSync(new URL(`../../src/${file}`, import.meta.url), "utf8");

const beginnerReport = rust("beginner_report.rs");
const domain = rust("domain.rs");
const exportLayer = rust("export.rs");
const externalScope = rust("external_scope.rs");
const managedRuntime = rust("managed_runtime.rs");

const rustSources: Readonly<Record<string, string>> = {
  "beginner_report.rs": beginnerReport,
  "domain.rs": domain,
  "export.rs": exportLayer,
  "external_scope.rs": externalScope,
  "managed_runtime.rs": managedRuntime,
};

const rustSource = (file: string): string => {
  const source = rustSources[file];
  assert.ok(source, `Rust source ${file} was not loaded`);
  return source;
};

const typescriptSources: Readonly<Record<string, string>> = {
  "types.ts": typescriptFile("types.ts"),
  "internalDeviceProfile.ts": typescriptFile("internalDeviceProfile.ts"),
  "internalEndpointProfile.ts": typescriptFile("internalEndpointProfile.ts"),
  "internalHostProfile.ts": typescriptFile("internalHostProfile.ts"),
};

const typescriptSource = (file: string): string => {
  const source = typescriptSources[file];
  assert.ok(source, `TypeScript source ${file} was not loaded`);
  return source;
};

const typescript = typescriptSource("types.ts");

const bundledAdapter = await build({
  stdin: {
    contents: 'export { adaptDeclaredHostScanMetadata, localQuestionnaireKinds, mapDataClasses } from "./src/services/nativeAdapter.ts"; export { nativeDataClasses } from "./src/services/scanner.ts";',
    loader: "ts",
    resolveDir: process.cwd(),
    sourcefile: "report-enum-parity-adapter-entry.ts",
  },
  bundle: true,
  format: "esm",
  platform: "node",
  target: "node22",
  write: false,
});
const bundledAdapterSource = bundledAdapter.outputFiles[0]?.text;
assert.ok(bundledAdapterSource, "the declared-input adapter bundle should contain JavaScript");
const {
  adaptDeclaredHostScanMetadata,
  localQuestionnaireKinds,
  mapDataClasses,
  nativeDataClasses,
}: {
  adaptDeclaredHostScanMetadata: (metadata: Record<string, unknown> | undefined) => {
    scanProfile: string;
  } | undefined;
  localQuestionnaireKinds: ReadonlySet<string>;
  mapDataClasses: (values: string[]) => string[];
  nativeDataClasses: Readonly<Record<string, string>>;
} = await import(
  `data:text/javascript;base64,${Buffer.from(bundledAdapterSource).toString("base64")}`
);

/** Serde's `rename_all = "snake_case"`: lower-case, `_` before each capital. */
const serdeSnakeCase = (variant: string): string =>
  variant.replaceAll(/(?<!^)[A-Z]/gu, (capital) => `_${capital}`).toLowerCase();

/**
 * The variants of one snake_case wire enum, as the wire spells them, including
 * any per-variant `serde(rename)` override.
 *
 * Snake-case on the wire is required rather than assumed: an enum without
 * `rename_all = "snake_case"` serializes its variants verbatim unless every
 * variant has an explicit `serde(rename)`. Comparing PascalCase wire names
 * against a snake_case union would report drift that is not there -- or,
 * worse, miss drift that is.
 */
const rustVariants = (source: string, name: string): string[] => {
  const declaration = source.indexOf(`pub enum ${name} {`);
  assert.ok(declaration > 0, `Rust enum ${name} was not found`);
  const attributes = source.slice(Math.max(0, declaration - 400), declaration);
  const hasRenameAll = attributes.includes('#[serde(rename_all = "snake_case")]');
  const body = source.slice(declaration + `pub enum ${name} {`.length);
  const end = body.indexOf("\n}");
  assert.ok(end > 0, `Rust enum ${name} has no closing brace`);
  const matches = [...body.slice(0, end).matchAll(
    /^(?:[ \t]*#\[serde\(rename = "([^"]+)"\)\][ \t]*\r?\n)?[ \t]*([A-Z][A-Za-z0-9]*),[ \t]*$/gmu,
  )];
  assert.ok(
    hasRenameAll || (matches.length > 0 && matches.every((match) => match[1])),
    `${name} is compared as snake_case but does not declare rename_all or per-variant serde rename`,
  );
  return matches.map((match) => match[1] ?? serdeSnakeCase(match[2]!));
};

/** Variants of an internally tagged Rust enum whose members carry fields. */
const rustTaggedVariants = (source: string, name: string): string[] => {
  const declaration = source.indexOf(`pub enum ${name} {`);
  assert.ok(declaration > 0, `Rust enum ${name} was not found`);
  const attributes = source.slice(Math.max(0, declaration - 400), declaration);
  assert.ok(
    attributes.includes('#[serde(tag = "kind", rename_all = "snake_case")]'),
    `${name} is compared as a kind-tagged snake_case enum but does not declare it`,
  );
  const body = source.slice(declaration + `pub enum ${name} {`.length);
  const end = body.indexOf("\n}");
  assert.ok(end > 0, `Rust enum ${name} has no closing brace`);
  return [...body.slice(0, end).matchAll(
    /^(?:[ \t]*#\[serde\(rename = "([^"]+)"\)\][ \t]*\r?\n)?[ \t]*([A-Z][A-Za-z0-9]*)[ \t]*(?:\{(?:[^\r\n]*\}[ \t]*,?)?|,)[ \t]*$/gmu,
  )].map((match) => match[1] ?? serdeSnakeCase(match[2]!));
};

/** The string members of one exported TypeScript string-union type. */
const unionMembers = (name: string, source = typescript): string[] => {
  const declaration = source.indexOf(`export type ${name} =`);
  assert.ok(declaration >= 0, `TypeScript type ${name} was not found`);
  const body = source.slice(declaration);
  const end = body.indexOf(";");
  assert.ok(end > 0, `TypeScript type ${name} is not terminated`);
  return [...body.slice(0, end).matchAll(/"([^"]+)"/gu)].map((match) => match[1]!);
};

/** `kind` literals from one exported TypeScript discriminated union. */
const discriminatedUnionMembers = (name: string): string[] => {
  const declaration = typescript.indexOf(`export type ${name} =`);
  assert.ok(declaration > 0, `TypeScript type ${name} was not found`);
  const body = typescript.slice(declaration);
  const nextDeclaration = body.slice(1).search(/\nexport (?:interface|type) /u);
  const definition = nextDeclaration < 0 ? body : body.slice(0, nextDeclaration + 1);
  return [...definition.matchAll(/\bkind:[ \t]*"([^"]+)"/gu)].map((match) => match[1]!);
};

// Every closed vocabulary the app has to narrow on. A new one belongs here the
// day it is added, which is cheaper than the day a reader sees a blank label.
const PAIRS: ReadonlyArray<readonly [source: string, rustName: string, typescriptName: string]> = [
  ["beginner_report.rs", "CoverageGapKind", "BeginnerCoverageGapKind"],
  ["beginner_report.rs", "CoverageGapClass", "BeginnerCoverageGapClass"],
  ["beginner_report.rs", "NextActionCode", "BeginnerNextActionCode"],
  ["beginner_report.rs", "CoverageDimensionStatus", "BeginnerCoverageStatus"],
  ["beginner_report.rs", "BeginnerReportSummary", "BeginnerReportSummary"],
  ["beginner_report.rs", "ReportLifecycle", "BeginnerReportLifecycle"],
  ["beginner_report.rs", "FindingGroupPresentationScope", "BeginnerFindingGroupPresentationScope"],
  ["beginner_report.rs", "ReportScanStage", "BeginnerReportStage"],
  ["beginner_report.rs", "DataAvailability", "BeginnerReportDataAvailability"],
  ["beginner_report.rs", "CheckResultKind", "BeginnerCheckResultKindWire"],
  ["beginner_report.rs", "RequestedLimitSource", "BeginnerRequestedLimitSource"],
  ["beginner_report.rs", "FindingSnapshotSource", "BeginnerFindingSnapshotSource"],
  ["domain.rs", "AssessmentActivity", "AssessmentActivity"],
  ["domain.rs", "AssessmentIntent", "AssessmentIntent"],
  ["domain.rs", "AiGeneratedArtifactAnswer", "AiGeneratedArtifactAnswer"],
  ["domain.rs", "AssetKind", "AssetKind"],
  ["domain.rs", "AwsIamPolicySource", "AwsIamPolicySource"],
  ["domain.rs", "CaseStatus", "CaseStatusWire"],
  ["domain.rs", "Confidence", "Confidence"],
  ["domain.rs", "ConfidenceBasisCode", "ConfidenceBasisCode"],
  ["domain.rs", "ContextFactor", "ContextFactor"],
  ["domain.rs", "CoverageStatus", "CoverageStatusWire"],
  ["domain.rs", "DataClass", "DataClassWire"],
  ["domain.rs", "EvidenceKind", "EvidenceKind"],
  ["domain.rs", "EngineCategory", "EngineCategory"],
  ["domain.rs", "EngineRunStatus", "EngineRunStatusWire"],
  ["domain.rs", "UnevaluatedTargetCause", "UnevaluatedTargetCauseWire"],
  ["domain.rs", "ManifestStatus", "EngineManifestStatusWire"],
  ["domain.rs", "DistributionMode", "DistributionMode"],
  ["domain.rs", "FindingDiffReasonCode", "FindingDiffReasonCode"],
  ["domain.rs", "FindingDiffStatus", "FindingDiffStatus"],
  ["domain.rs", "FindingFamily", "FindingFamily"],
  ["domain.rs", "FindingGroupAction", "FindingGroupAction"],
  ["domain.rs", "FindingStatus", "FindingStatusWire"],
  ["domain.rs", "LocalInputProfile", "LocalInputProfile"],
  ["domain.rs", "LocalhostTcpOutcome", "LocalhostTcpOutcome"],
  ["domain.rs", "KnowledgeInputKind", "KnowledgeInputKind"],
  ["domain.rs", "KnowledgePinState", "KnowledgePinState"],
  ["domain.rs", "ScanRequestOutcomeCode", "ScanRequestOutcomeCode"],
  ["domain.rs", "ScanPermission", "ScanPermissionWire"],
  ["domain.rs", "Severity", "SeverityWire"],
  ["domain.rs", "SeverityBasisCode", "SeverityBasisCode"],
  ["domain.rs", "SourceConnectionStatus", "SourceConnectionStatus"],
  ["domain.rs", "SourceKind", "SourceKind"],
  ["export.rs", "RedactionProfile", "RedactionProfile"],
  ["export.rs", "ReportLocale", "ReportLocale"],
  ["external_scope.rs", "ExternalActivity", "ExternalActivity"],
  ["external_scope.rs", "TransportProtocol", "TransportProtocol"],
  ["external_scope.rs", "DirectNetworkTargetKind", "DirectNetworkTargetKind"],
  ["managed_runtime.rs", "ManagedRuntimeSetupPhase", "ManagedRuntimeSetupPhase"],
  ["managed_runtime.rs", "ManagedRuntimeSetupFailureReason", "ManagedRuntimeSetupFailureReason"],
  ["managed_runtime.rs", "ManagedRuntimeSetupNextAction", "ManagedRuntimeSetupNextAction"],
];

const TAGGED_PAIRS: ReadonlyArray<readonly [source: string, rustName: string, typescriptName: string]> = [
  ["beginner_report.rs", "BeginnerInventoryItemKind", "BeginnerInventoryItem"],
  ["beginner_report.rs", "TechnicalExecution", "BeginnerTechnicalExecution"],
  ["domain.rs", "CaseProductIdentity", "CaseProductIdentity"],
  ["domain.rs", "EngineTaskKind", "EngineTaskKindWire"],
];

for (const [file, rustName, typescriptName] of PAIRS) {
  test(`${rustName} and ${typescriptName} describe the same set of values`, () => {
    const fromRust = rustVariants(rustSource(file), rustName);
    const fromTypescript = unionMembers(typescriptName);

    assert.ok(fromRust.length > 0, `${rustName} extracted no variants`);
    // Sets, not sequences: the two files are free to declare in different
    // orders, and neither order reaches the reader.
    assert.deepEqual(
      [...fromRust].sort(),
      [...fromTypescript].sort(),
      `${rustName} and ${typescriptName} disagree`,
    );
  });
}

for (const [file, rustName, typescriptName] of TAGGED_PAIRS) {
  test(`${rustName} and ${typescriptName} describe the same kind tags`, () => {
    const fromRust = rustTaggedVariants(rustSource(file), rustName);
    const fromTypescript = discriminatedUnionMembers(typescriptName);

    assert.ok(fromRust.length > 0, `${rustName} extracted no tagged variants`);
    assert.deepEqual(
      [...fromRust].sort(),
      [...fromTypescript].sort(),
      `${rustName} and ${typescriptName} disagree`,
    );
  });
}

test("the extractor reads real variants, not whatever the regex allows", () => {
  // A silent extraction failure would make every assertion above pass by
  // comparing two empty sets, so the shapes it must find are named here.
  assert.deepEqual(rustVariants(beginnerReport, "CoverageGapKind"), [
    "not_tested",
    "failed",
    "timed_out",
    "cancelled",
    "excluded",
    "truncated",
    "unavailable",
    "unattributed",
    "manual_review",
  ]);
  // Digits stay attached to the word they belong to.
  assert.ok(rustVariants(domain, "FindingFamily").includes("microsoft365"));
  // Per-variant serde names win over the enum's rename_all convention.
  assert.deepEqual(rustVariants(domain, "ScanRequestOutcomeCode"), [
    "no_effective_scope_grants",
    "no_ownership_confirmed_targets",
    "no_applicable_checks",
  ]);
  assert.deepEqual(rustVariants(externalScope, "DirectNetworkTargetKind"), [
    "hostname",
    "address",
    "network",
  ]);
  // Explicit per-variant serde names, with no enum-level rename_all.
  assert.deepEqual(rustVariants(managedRuntime, "ManagedRuntimeSetupFailureReason"), [
    "packaged_runtime_missing",
    "packaged_runtime_verification_failed",
    "developer_build_without_packaged_runtime",
    "developer_build_packaged_runtime_verification_failed",
    "windows_wsl_not_installed",
    "windows_wsl_optional_feature_disabled",
    "windows_wsl_update_required",
    "windows_restart_required",
    "windows_wsl_command_failed",
  ]);
  assert.deepEqual(unionMembers("BeginnerReportLifecycle"), ["final"]);
  // Closed export vocabulary: as_str() and serde snake_case agree on these two.
  assert.deepEqual(rustVariants(exportLayer, "RedactionProfile"), [
    "none",
    "standard",
  ]);
  // A non-serde attribute before a per-variant rename must not hide it.
  assert.deepEqual(rustVariants(exportLayer, "ReportLocale"), [
    "en",
    "zh-Hant",
  ]);
  assert.deepEqual(rustTaggedVariants(beginnerReport, "TechnicalExecution"), [
    "catalog_engine",
    "built_in_localhost_tcp",
    "external_report_import",
    "invalid_built_in_task",
  ]);
  assert.throws(
    () => typescriptSource("missing.ts"),
    /TypeScript source missing\.ts was not loaded/u,
  );
  assert.deepEqual(
    unionMembers("InternalDeviceScanProfile", typescriptSource("internalDeviceProfile.ts")),
    ["internal_device_https"],
  );
});

const DECLARED_PROFILE_PAIRS: ReadonlyArray<
  readonly [rustName: string, typescriptFile: string, typescriptName: string]
> = [
  ["DeclaredWebServiceScanProfile", "internalDeviceProfile.ts", "InternalDeviceScanProfile"],
  ["DeclaredNetworkServiceScanProfile", "internalEndpointProfile.ts", "InternalEndpointScanProfile"],
];

for (const [rustName, typescriptFile, typescriptName] of DECLARED_PROFILE_PAIRS) {
  test(`${rustName} and ${typescriptName} describe the same set of values`, () => {
    const fromRust = rustVariants(rustSource("domain.rs"), rustName);
    const fromTypescript = unionMembers(typescriptName, typescriptSource(typescriptFile));

    assert.ok(fromRust.length > 0, `${rustName} extracted no variants`);
    assert.deepEqual(
      [...fromRust].sort(),
      [...fromTypescript].sort(),
      `${rustName} and ${typescriptName} disagree`,
    );
  });
}

test("DeclaredHostScanProfile maps exhaustively onto InternalHostScanProfile", () => {
  const fromRust = rustVariants(rustSource("domain.rs"), "DeclaredHostScanProfile");
  const fromTypescript = unionMembers(
    "InternalHostScanProfile",
    typescriptSource("internalHostProfile.ts"),
  );
  const mapping = declaredHostScanProfileByWire;

  assert.ok(fromRust.length > 0, "DeclaredHostScanProfile extracted no variants");
  assert.deepEqual(
    [...fromRust].sort(),
    [...Object.keys(mapping)].sort(),
    "DeclaredHostScanProfile has a variant the adapter does not translate",
  );
  assert.deepEqual(
    [...new Set(Object.values(mapping))].sort(),
    [...fromTypescript].sort(),
    "InternalHostScanProfile members must each be a mapped adapter result",
  );

  for (const [wire, ui] of Object.entries(mapping)) {
    const adapted = adaptDeclaredHostScanMetadata({
      declared_host_scan: { protocol: "tcp", ports: [22], profile: wire },
    });
    assert.equal(
      adapted?.scanProfile,
      ui,
      `adaptDeclaredHostScanMetadata did not translate ${wire} to ${ui}`,
    );
  }
});

test("DataClass round-trips through the outbound and inbound adapters", () => {
  const uiDataClasses = unionMembers("DataClass");

  assert.ok(uiDataClasses.length > 0, "DataClass extracted no members");
  for (const dataClass of uiDataClasses) {
    const wire = nativeDataClasses[dataClass];
    assert.ok(wire, `nativeDataClasses does not translate ${dataClass}`);
    assert.deepEqual(
      mapDataClasses([wire]),
      [dataClass],
      `${dataClass} did not survive the adapter round trip`,
    );
  }
});

test("localQuestionnaireKinds plus external_target matches DeclaredAssetKind", () => {
  // A new DeclaredAssetKind is not automatically a local questionnaire
  // placeholder. Classify it in localQuestionnaireKinds or leave it out
  // (like external_target). Do not derive that set from the Rust enum.
  const fromRust = rustVariants(rustSource("domain.rs"), "DeclaredAssetKind");
  assert.ok(fromRust.length > 0, "DeclaredAssetKind extracted no variants");
  assert.deepEqual(
    [...localQuestionnaireKinds, "external_target"].sort(),
    [...fromRust].sort(),
    "a new DeclaredAssetKind must be classified as a local placeholder or not",
  );
});
