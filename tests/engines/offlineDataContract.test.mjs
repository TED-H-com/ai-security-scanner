import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const root = new URL("../../", import.meta.url);
const read = (path) => readFileSync(new URL(path, root), "utf8");

test("offline launcher digests match the exact files checked during image assembly", () => {
  const launcher = read("engines/images/local-launcher/main.go");
  const files = [
    ["trivy", "trivyDBSHA256", "/rootfs/opt/ai-security-scanner/trivy-cache/db/trivy.db"],
    ["trivy", "trivyMetadataSHA256", "/rootfs/opt/ai-security-scanner/trivy-cache/db/metadata.json"],
    ["trivy", "trivyJavaDBSHA256", "/rootfs/opt/ai-security-scanner/trivy-cache/java-db/trivy-java.db"],
    ["trivy", "trivyJavaMetadataSHA256", "/rootfs/opt/ai-security-scanner/trivy-cache/java-db/metadata.json"],
    ["grype", "grypeDBSHA256", "/rootfs/opt/ai-security-scanner/grype-db/6/vulnerability.db"],
    ["kubescape", "kubescapeNSASHA256", "/rootfs/opt/ai-security-scanner/kubescape-artifacts/nsa.json"],
    ["kubescape", "kubescapeControlsSHA256", "/rootfs/opt/ai-security-scanner/kubescape-artifacts/controls-inputs.json"],
    ["kubescape", "kubescapeExceptionsSHA256", "/rootfs/opt/ai-security-scanner/kubescape-artifacts/exceptions.json"],
  ];
  for (const [engine, constant, path] of files) {
    const digest = launcher.match(new RegExp(`\\b${constant}\\s*=\\s*"([a-f0-9]{64})"`, "u"))?.[1];
    assert.ok(digest, `${constant} must name an exact immutable file`);
    const dockerfile = read(`engines/images/${engine}/Dockerfile`);
    const checksumAdd = dockerfile.replace(/\\\r?\n\s*/gu, " ").split("\n").some((line) => {
      const tokens = line.trim().split(/\s+/u);
      return tokens[0] === "ADD" && tokens[1] === `--checksum=sha256:${digest}` && tokens.at(-1) === path;
    });
    assert.ok(checksumAdd || dockerfile.includes(`${digest}  ${path}`),
      `${engine}: build-time ${path} and runtime ${constant} disagree`);
  }
});
