import { lstat, readFile } from "node:fs/promises";
import path from "node:path";

import {
  parseArgs,
  readJson,
  requireString,
  runMain,
  sha256File,
  writeJsonAtomic,
  writeTextAtomic,
} from "./lib.mjs";

const MANAGEMENT_CONTRACT_REVISION = "2026-08-29.1";
const WINDOWS_X86_64_MANIFEST_SHA256 =
  "83a4f0106c5c1be17e515db9f86f32d9e43fc4563d85473b400e3df6efe240e3";

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const manifestPath = path.resolve(requireString(args, "manifest"));
  const bundleRoot = path.dirname(manifestPath);
  const output = path.resolve(requireString(args, "out"));
  const platform = requireString(args, "platform");
  const expectedManifestSha256 = args.get("expected-manifest-sha256");
  const manifest = await readJson(manifestPath);
  assert(manifest.schema_version === "3", "managed runtime evidence requires schema 3");
  assert(
    manifest.management_contract_revision === MANAGEMENT_CONTRACT_REVISION,
    "managed runtime evidence has the wrong management contract revision",
  );
  assert(Array.isArray(manifest.files) && manifest.files.length > 0, "runtime file inventory is empty");
  assert(Array.isArray(manifest.components) && manifest.components.length > 0, "runtime component inventory is empty");

  const files = new Map();
  for (const file of manifest.files) {
    const absolute = path.join(bundleRoot, ...file.path.split("/"));
    const metadata = await lstat(absolute);
    assert(metadata.isFile() && !metadata.isSymbolicLink(), `runtime file is not regular: ${file.path}`);
    assert(metadata.size === file.size_bytes, `runtime file size mismatch: ${file.path}`);
    assert((await sha256File(absolute)) === file.sha256, `runtime file digest mismatch: ${file.path}`);
    files.set(file.path, file);
  }

  const coveredFiles = new Set();
  const coveredDownloads = new Set();
  for (const component of manifest.components) {
    assert(component.id && component.version && component.source_revision, "runtime component identity is incomplete");
    assert(component.license_spdx && component.repository_url, "runtime component licensing is incomplete");
    assert(Array.isArray(component.artifacts) && component.artifacts.length > 0, `runtime component ${component.id} has no artifacts`);
    for (const artifact of component.artifacts) {
      if (artifact.delivery === "bundled_file") {
        const file = files.get(artifact.locator);
        assert(file && file.sha256 === artifact.sha256 && file.size_bytes === artifact.size_bytes, `component ${component.id} has an invalid bundled artifact`);
        coveredFiles.add(artifact.locator);
      } else if (artifact.delivery === "runtime_download") {
        const image = manifest.targets.find((target) => target.machine_image.url === artifact.locator)?.machine_image;
        assert(image && image.sha256 === artifact.sha256 && image.size_bytes === artifact.size_bytes, `component ${component.id} has an invalid runtime download`);
        coveredDownloads.add(artifact.locator);
      } else {
        throw new Error(`component ${component.id} has an unknown delivery mode`);
      }
    }
  }
  assert([...files.keys()].every((file) => coveredFiles.has(file)), "runtime components do not cover every bundled file");
  assert(manifest.targets.every((target) => coveredDownloads.has(target.machine_image.url)), "runtime components do not cover every machine image");

  const prefix = `managed-runtime-${platform}`;
  const manifestSha256 = await sha256File(manifestPath);
  if (expectedManifestSha256 !== undefined) {
    assert(
      typeof expectedManifestSha256 === "string" && /^[0-9a-f]{64}$/u.test(expectedManifestSha256),
      "expected managed runtime manifest identity must be a lowercase SHA-256 digest",
    );
    assert(
      manifestSha256 === expectedManifestSha256,
      "managed runtime manifest differs from its reviewed immutable identity",
    );
  }
  if (platform === "windows-x86_64" && expectedManifestSha256 !== undefined) {
    assert(
      expectedManifestSha256 === WINDOWS_X86_64_MANIFEST_SHA256,
      "Windows managed runtime evidence was not pinned to the reviewed Windows identity",
    );
  }
  const deterministicUuid = `${manifestSha256.slice(0, 8)}-${manifestSha256.slice(8, 12)}-${manifestSha256.slice(12, 16)}-${manifestSha256.slice(16, 20)}-${manifestSha256.slice(20, 32)}`;
  await writeJsonAtomic(path.join(output, `${prefix}.manifest.json`), manifest);
  await writeJsonAtomic(path.join(output, `${prefix}.cyclonedx.json`), {
    bomFormat: "CycloneDX",
    specVersion: "1.6",
    serialNumber: `urn:uuid:${deterministicUuid}`,
    version: 1,
    metadata: {
      component: { type: "application", name: `ai-security-scanner-managed-runtime-${platform}`, version: manifest.runtime_version },
      properties: [
        { name: "ai-security-scanner:manifest-sha256", value: manifestSha256 },
        {
          name: "ai-security-scanner:management-contract-revision",
          value: manifest.management_contract_revision,
        },
      ],
    },
    components: manifest.components.map((component) => ({
      type: "application",
      "bom-ref": `pkg:generic/${encodeURIComponent(component.id)}@${encodeURIComponent(component.version)}?platform=${encodeURIComponent(platform)}`,
      name: component.name,
      version: component.version,
      licenses: [{ expression: component.license_spdx }],
      externalReferences: [{ type: "vcs", url: `${component.repository_url}/tree/${component.source_revision}` }],
      properties: [
        { name: "ai-security-scanner:relationship", value: component.relationship },
        { name: "ai-security-scanner:source-revision", value: component.source_revision },
        ...component.artifacts.map((artifact) => ({
          name: `ai-security-scanner:artifact:${artifact.delivery}:${artifact.locator}`,
          value: `sha256:${artifact.sha256};bytes:${artifact.size_bytes}`,
        })),
      ],
    })),
  });
  await writeJsonAtomic(path.join(output, `${prefix}.spdx.json`), {
    spdxVersion: "SPDX-2.3",
    dataLicense: "CC0-1.0",
    SPDXID: "SPDXRef-DOCUMENT",
    name: `${prefix}-sbom`,
    documentNamespace: `https://github.com/TED-H-com/ai-security-scanner/releases/${prefix}/${manifestSha256}`,
    creationInfo: { created: new Date(0).toISOString(), creators: ["Tool: ai-security-scanner-runtime-evidence-1"] },
    packages: manifest.components.map((component) => ({
      SPDXID: `SPDXRef-${component.id.replace(/[^A-Za-z0-9.-]/gu, "-")}`,
      name: component.name,
      versionInfo: component.version,
      downloadLocation: `${component.repository_url}/tree/${component.source_revision}`,
      filesAnalyzed: false,
      licenseConcluded: component.license_spdx,
      licenseDeclared: component.license_spdx,
      copyrightText: "NOASSERTION",
      sourceInfo: component.relationship,
      comment: JSON.stringify({ artifacts: component.artifacts, sourceArchive: component.source_archive ?? null }),
    })),
  });

  const notices = [
    `ai-security-scanner managed runtime inventory: ${platform}`,
    `Manifest SHA-256: ${manifestSha256}`,
    `Management contract revision: ${manifest.management_contract_revision}`,
    "",
    ...manifest.components.flatMap((component) => [
      `${component.name} ${component.version}`,
      `  License: ${component.license_spdx}`,
      `  Source: ${component.repository_url}/tree/${component.source_revision}`,
      `  Relationship: ${component.relationship}`,
      ...(component.source_archive ? [
        `  Corresponding source archive: ${component.source_archive.url}`,
        `  Source SHA-256: ${component.source_archive.sha256}`,
        `  Source bytes: ${component.source_archive.size_bytes}`,
      ] : []),
      "",
    ]),
    "The component SPDX identifiers above identify obligations; consult each exact source revision for copyright and license text.",
  ];
  await writeTextAtomic(path.join(output, `${prefix}.NOTICES.txt`), `${notices.join("\n")}\n`);

  // Ensure the emitted evidence itself is non-empty before the caller uploads it.
  for (const suffix of ["manifest.json", "cyclonedx.json", "spdx.json", "NOTICES.txt"]) {
    const evidence = path.join(output, `${prefix}.${suffix}`);
    assert((await readFile(evidence)).length > 0, `empty runtime evidence: ${evidence}`);
  }
  process.stdout.write(`Generated exact managed runtime evidence for ${platform}.\n`);
}

runMain(main);
