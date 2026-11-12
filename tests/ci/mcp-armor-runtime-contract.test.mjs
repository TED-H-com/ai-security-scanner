import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";
import assert from "node:assert/strict";

const load = (path) => readFile(new URL(`../../${path}`, import.meta.url), "utf8");
const sha256 = (value) => `sha256:${createHash("sha256").update(value).digest("hex")}`;

test("MCP Armor published runtime remains digest-pinned, offline, and non-root", async () => {
  const [catalogText, planText, statusText, thirdParty, decision, dockerfile, requirements, patch, launcher, scopeText, input, workflow, verifier] = await Promise.all([
    load("engines/catalog.json"),
    load("engines/images/mcp-armor/plan.json"),
    load("docs/development-status.md"),
    load("THIRD_PARTY.md"),
    load("docs/research/mcp-armor-evaluation.md"),
    load("engines/images/mcp-armor/Dockerfile"),
    load("engines/images/mcp-armor/requirements.lock"),
    load("docs/research/patches/mcp-armor-1.0.2-config-only.patch"),
    load("engines/images/mcp-armor/launcher/main.go"),
    load("engines/images/mcp-armor/testdata/scope.json"),
    load("engines/images/mcp-armor/testdata/workspace/mcp.json"),
    load(".github/workflows/engine-image-mcp-armor.yml"),
    load("scripts/release/verify-publication-artifact.mjs"),
  ]);
  const engine = JSON.parse(catalogText).find((entry) => entry.id === "mcp-armor");
  const plan = JSON.parse(planText);
  const statusRow = statusText.split("\n").find((line) => line.startsWith("| MCP Armor |"));
  assert.ok(statusRow, "public development status must include MCP Armor");
  assert.equal(engine.compatibility.runnable, true);
  assert.equal(engine.status, "integrated");
  assert.deepEqual(engine.image, {
    repository: "ghcr.io/teddashh/ai-security-scanner-engine-mcp-armor",
    tag: "1.0.2-config-only.1",
    digest: "sha256:f8dcf9b774e0f90cfbe32d81b1dc04c6b1d61538fa9829ca28c674d78440dfdc",
    signature_identity: null,
  });
  assert.equal(plan.publish_state, "published_managed_artifact");
  assert.deepEqual(plan.publication, {
    workflow_run: "https://github.com/teddashh/ai-security-scanner/actions/runs/34810830035",
    source_revision: "16dfb80c7e45a1ccfa7d6d7d60cc41fae45c455c",
    platforms: ["linux/amd64", "linux/arm64"],
    platform_digests: {
      "linux/amd64": "sha256:2188bc5fc4b4c1cb2e8862a32c53f0d8af24ad5967150ddc6be867e3c48118c3",
      "linux/arm64": "sha256:d203df4079916cf46337ecf7f983ac27f3eb09f34e04058bca948b8f5038eb89",
    },
    anonymous_pull_verified: true,
    evidence_artifact: "mcp-armor-image-evidence-34810830035-1",
    managed_smoke_evidence_sha256: "sha256:8d796b2eb0d1e817f36ea1bec34ace60c5c495c26d8c4e8dffbdf24f199e492f",
  });
  assert.deepEqual(plan.final_artifact, {
    repository: "ghcr.io/teddashh/ai-security-scanner-engine-mcp-armor",
    tag: "1.0.2-config-only.1",
    digest: "sha256:f8dcf9b774e0f90cfbe32d81b1dc04c6b1d61538fa9829ca28c674d78440dfdc",
  });
  assert.deepEqual(plan.blockers, []);
  assert.equal(plan.dockerfile.sha256, sha256(dockerfile));
  assert.equal(plan.build_recipe.dependency_lock.sha256, sha256(requirements));
  assert.equal(plan.build_recipe.source_patch.sha256, sha256(patch));
  assert.equal(plan.wrapper.launcher_sha256, sha256(launcher));
  const scope = JSON.parse(scopeText);
  const inputDigest = scope.assets[0].identifiers.find(({ namespace }) => (
    namespace === "ai-security-scanner:mcp-configuration-sha256"
  ));
  assert.equal(inputDigest.value, sha256(input).replace("sha256:", ""));
  const syntheticInput = JSON.parse(input);
  assert.deepEqual(syntheticInput.mcpServers["fixture-safe"].permissions, ["terminal:exec"]);
  assert.match(plan.local_build_evidence.result, /one excessive-permission finding/u);
  assert.equal(plan.managed_runtime.network_mode, "disabled");
  assert.equal(plan.managed_runtime.non_root_user, "65532:65532");
  assert.match(statusRow, /local image produced a complete two-check report/u);
  assert.match(statusRow, /networking disabled/u);
  assert.match(statusRow, /published, digest-pinned, and dispatchable/u);
  assert.equal(
    engine.notices.some((notice) => /non-dispatchable/iu.test(notice)),
    false,
    "published MCP Armor must not remain labeled non-dispatchable",
  );
  assert.match(
    engine.notices[0] ?? "",
    /dispatchable, but not default-enabled/u,
  );
  const thirdPartyRow = thirdParty.split("\n").find((line) => line.includes("[aira-security/mcp-armor]"));
  assert.ok(thirdPartyRow, "THIRD_PARTY.md must include MCP Armor");
  assert.match(thirdPartyRow, /ALLOW/u);
  assert.doesNotMatch(thirdPartyRow, /NOT_DISTRIBUTED|no image or model is built/iu);
  assert.match(decision, /`integrated` and `runnable: true`/u);
  assert.match(decision, new RegExp(engine.image.digest.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&"), "u"));
  assert.doesNotMatch(decision, /catalog stays\s+`experimental`, `runnable: false`/u);
  assert.match(decision, /published configuration-only image is `ALLOW`/u);
  assert.doesNotMatch(decision, /recorded here as `RESEARCH \/ NOT_DISTRIBUTED`/u);
  assert.match(dockerfile, /USER 65532:65532/u);
  assert.match(dockerfile, /--require-hashes/u);
  assert.match(dockerfile, /--only-binary=:all:/u);
  for (const absent of ["fastmcp==", "thefuzz==", "transformers==", "torch=="]) {
    assert.equal(requirements.toLowerCase().includes(absent), false, absent);
  }
  const guardIndex = workflow.indexOf("uses: ./.github/actions/engine-image-evidence/publication-guard");
  const buildIndex = workflow.indexOf("uses: docker/build-push-action@");
  const evidenceIndex = workflow.indexOf("uses: ./.github/actions/engine-image-evidence\n");
  const promotionIndex = workflow.indexOf("uses: ./.github/actions/engine-image-evidence/promote");
  assert.ok(guardIndex >= 0 && guardIndex < buildIndex && buildIndex < evidenceIndex && evidenceIndex < promotionIndex);
  assert.match(workflow, /^  IMAGE_TAG: 1\.0\.2-config-only\.1$/mu);
  assert.match(workflow, /platforms: linux\/amd64,linux\/arm64/u);
  assert.match(workflow, /--read-only --network none --cap-drop ALL/u);
  assert.match(workflow, /mcp-armor-managed-smoke/u);
  assert.match(workflow, /docs\/research\/patches\/mcp-armor-1\.0\.2-config-only\.patch/u);
  assert.match(verifier, /"mcp-armor": \{[\s\S]*?engine-image-mcp-armor\.yml[\s\S]*?mcp-armor\.json/u);
});

test("MCP Armor production path binds one exact snapshot file before invocation", async () => {
  const [rust, launcher, commands, coverage, service] = await Promise.all([
    load("src-tauri/src/mcp_armor_input.rs"),
    load("engines/images/mcp-armor/launcher/main.go"),
    load("src-tauri/src/commands.rs"),
    load("src/pages/CoveragePage.tsx"),
    load("src/services/scanner.ts"),
  ]);
  const pathNamespace = "ai-security-scanner:mcp-configuration-relative-path";
  const digestNamespace = "ai-security-scanner:mcp-configuration-sha256";
  for (const value of [pathNamespace, digestNamespace]) {
    assert.ok(rust.includes(value), value);
    assert.ok(launcher.includes(value), value);
  }
  assert.match(rust, /MAX_MCP_CONFIGURATION_BYTES: u64 = 10 \* 1024 \* 1024/u);
  assert.match(rust, /candidates\.len\(\) == 1/u);
  assert.match(rust, /selected MCP configuration differs from its verified snapshot evidence/u);
  assert.match(commands, /verify_mcp_configuration_selection\(asset, &resolved\.manifest\)/u);
  assert.match(launcher, /"--config-only"/u);
  assert.match(launcher, /requireReadOnlyWorkspace/u);
  assert.match(launcher, /verifySelectedConfiguration/u);
  assert.match(launcher, /validateTerminalEvidence/u);
  assert.match(coverage, /manifest\.id === "mcp-armor" && manifest\.runnable === true/u);
  assert.match(coverage, /asset\.selectedMcpConfiguration/u);
  assert.match(coverage, /mcpSelectionRequired/u);
  assert.match(coverage, /!externalScopeReady \|\| mcpSelectionRequired/u);
  assert.match(service, /selectMcpConfiguration: "select_mcp_configuration"/u);
});
