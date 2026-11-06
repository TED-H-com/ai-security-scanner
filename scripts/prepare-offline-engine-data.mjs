#!/usr/bin/env node

import { createHash } from "node:crypto";
import { createWriteStream } from "node:fs";
import { mkdir, readFile, rename, rm, stat } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";

const root = resolve(import.meta.dirname, "..");
const requested = process.argv.length === 2 ? "all" : process.argv[2];
if (!new Set(["all", "semgrep", "trivy", "grype"]).has(requested) || process.argv.length > 3) {
  throw new Error("usage: prepare-offline-engine-data.mjs [all|semgrep|trivy|grype]");
}

const trivyDatabase = {
  repository: "aquasecurity/trivy-db",
  manifest: "sha256:fb417a88061be7d8c246c61cd56e73c91040574fb8cb7b74c48f7a2ea5c2f92f",
  layer: "sha256:c367ecccf6a0367b915ef00b90c43e5958f9ecd9ee6118d2876af6deeca8523c",
  size: 138781380,
  mediaType: "application/vnd.aquasec.trivy.db.layer.v1.tar+gzip",
  title: "db.tar.gz",
  output: resolve(root, ".engine-cache/offline/trivy/db.tar.gz"),
};
const trivyJavaDatabase = {
  repository: "aquasecurity/trivy-java-db",
  manifest: "sha256:a48270d8181f59baed801e34d73e0857558570c51c9a582eaa3999e897c210e4",
  layer: "sha256:c6a199cdfd2022f0e4792f9de59b63228d63b904df5858afb1873214427d2a44",
  size: 995358342,
  mediaType: "application/vnd.aquasec.trivy.javadb.layer.v1.tar+gzip",
  title: "javadb.tar.gz",
  output: resolve(root, ".engine-cache/offline/trivy/java-db.tar.gz"),
};
const grype = {
  url: "https://grype.anchore.io/databases/v6/vulnerability-db_v6.1.10_2026-11-05T00:20:34Z_1793859666.tar.zst",
  digest: "sha256:9fbc8d8f2428cd715ffc9591cce16c4179955a7f45c76c12fbcb9cea8dc93813",
  size: 198222678,
  output: resolve(root, ".engine-cache/offline/grype/db.tar.zst"),
};

async function fetchChecked(url, output, expectedDigest, expectedSize, headers = {}) {
  const response = await fetch(url, { headers, redirect: "follow", signal: AbortSignal.timeout(20 * 60 * 1000) });
  if (!response.ok || !response.body) {
    throw new Error(`immutable engine input download failed (${response.status})`);
  }
  if (response.url.startsWith("http://")) {
    throw new Error("immutable engine input followed an insecure redirect");
  }
  await mkdir(dirname(output), { recursive: true, mode: 0o700 });
  const temporary = `${output}.partial-${process.pid}`;
  await rm(temporary, { force: true });
  try {
    await pipeline(Readable.fromWeb(response.body), createWriteStream(temporary, { flags: "wx", mode: 0o600 }));
    const info = await stat(temporary);
    if (!info.isFile() || info.size !== expectedSize) {
      throw new Error(`immutable engine input size mismatch (expected ${expectedSize}, got ${info.size})`);
    }
    const digest = createHash("sha256");
    const file = await import("node:fs").then(({ createReadStream }) => createReadStream(temporary));
    for await (const chunk of file) digest.update(chunk);
    const actual = `sha256:${digest.digest("hex")}`;
    if (actual !== expectedDigest) {
      throw new Error(`immutable engine input digest mismatch (expected ${expectedDigest}, got ${actual})`);
    }
    await rename(temporary, output);
  } catch (error) {
    await rm(temporary, { force: true });
    throw error;
  }
}

async function prepareTrivyArtifact(artifact) {
  const tokenResponse = await fetch(`https://ghcr.io/token?service=ghcr.io&scope=repository%3A${encodeURIComponent(artifact.repository)}%3Apull`, {
    signal: AbortSignal.timeout(30_000),
  });
  if (!tokenResponse.ok) throw new Error("could not obtain anonymous Trivy DB pull token");
  const tokenDocument = await tokenResponse.json();
  if (typeof tokenDocument.token !== "string" || tokenDocument.token.length < 32) {
    throw new Error("anonymous Trivy DB pull token is invalid");
  }
  const headers = {
    Accept: "application/vnd.oci.image.manifest.v1+json",
    Authorization: `Bearer ${tokenDocument.token}`,
  };
  const manifestURL = `https://ghcr.io/v2/${artifact.repository}/manifests/${artifact.manifest}`;
  const manifestResponse = await fetch(manifestURL, { headers, signal: AbortSignal.timeout(30_000) });
  if (!manifestResponse.ok) throw new Error("could not read the immutable Trivy DB OCI manifest");
  const returnedDigest = manifestResponse.headers.get("docker-content-digest");
  const manifest = await manifestResponse.json();
  if (
    returnedDigest !== artifact.manifest ||
    manifest.schemaVersion !== 2 ||
    manifest.artifactType !== "application/vnd.aquasec.trivy.config.v1+json" ||
    manifest.layers?.length !== 1
  ) {
    throw new Error("Trivy DB OCI manifest does not match its release contract");
  }
  const layer = manifest.layers[0];
  if (
    layer.digest !== artifact.layer ||
    layer.size !== artifact.size ||
    layer.mediaType !== artifact.mediaType ||
    layer.annotations?.["org.opencontainers.image.title"] !== artifact.title
  ) {
    throw new Error("Trivy DB OCI layer does not match its release contract");
  }
  await fetchChecked(
    `https://ghcr.io/v2/${artifact.repository}/blobs/${artifact.layer}`,
    artifact.output,
    artifact.layer,
    artifact.size,
    { Authorization: `Bearer ${tokenDocument.token}` },
  );
}

async function prepareTrivy() {
  await prepareTrivyArtifact(trivyDatabase);
  await prepareTrivyArtifact(trivyJavaDatabase);
}

async function prepareSemgrepSubmodules() {
  const lockPath = resolve(root, "engines/images/semgrep/submodules.lock");
  const records = (await readFile(lockPath, "utf8"))
    .split(/\r?\n/u)
    .filter((line) => line !== "" && !line.startsWith("#"))
    .map((line) => {
      const [path, repository, revision, digest, sizeText, archive] = line.split("|");
      if (
        !/^[a-z0-9_./-]+$/u.test(path) || path.includes("..") ||
        !/^https:\/\/github\.com\/(?:returntocorp|semgrep)\/[a-z0-9_.-]+$/u.test(repository) ||
        !/^[0-9a-f]{40}$/u.test(revision) ||
        !/^sha256:[0-9a-f]{64}$/u.test(digest) ||
        !/^[1-9][0-9]*$/u.test(sizeText) ||
        !/^[a-z0-9_.-]+\.tar\.gz$/u.test(archive)
      ) {
        throw new Error(`invalid Semgrep submodule lock record: ${line}`);
      }
      return { repository, revision, digest, size: Number(sizeText), archive };
    });
  if (records.length !== 1 || new Set(records.map(({ archive }) => archive)).size !== records.length) {
    throw new Error("Semgrep submodule lock must contain one reviewed rules archive");
  }

  for (let offset = 0; offset < records.length; offset += 6) {
    await Promise.all(records.slice(offset, offset + 6).map((record) => fetchChecked(
      `${record.repository}/archive/${record.revision}.tar.gz`,
      resolve(root, ".engine-cache/offline/semgrep-submodules", record.archive),
      record.digest,
      record.size,
    )));
  }
}

if (requested === "all" || requested === "semgrep") await prepareSemgrepSubmodules();
if (requested === "all" || requested === "trivy") await prepareTrivy();
if (requested === "all" || requested === "grype") await fetchChecked(grype.url, grype.output, grype.digest, grype.size);

process.stdout.write(`Prepared checksum-verified offline data for ${requested}.\n`);
