import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  ciBoundaryResultErrors,
  classifyAllBoundaries,
  classifyChangedPaths,
  githubOutputLines,
} from "../../scripts/ci/classify-changes.mjs";

function normalizeLineEndings(source) {
  return source.replace(/\r\n?/gu, "\n");
}

const ciWorkflow = normalizeLineEndings(
  readFileSync(new URL("../../.github/workflows/ci.yml", import.meta.url), "utf8"),
);

// This guard runs in the always-on classifier lane, which deliberately has no
// `npm ci`. Read the workflow as text instead of importing a YAML parser.
function ciJobSteps(jobName) {
  const jobs = ciWorkflow.slice(ciWorkflow.indexOf("\njobs:\n"));
  const headers = [...jobs.matchAll(/^ {2}([\w-]+):$/gmu)];
  const index = headers.findIndex((header) => header[1] === jobName);
  assert.notEqual(index, -1, `the ${jobName} job must exist`);
  const block = jobs.slice(
    headers[index].index,
    index + 1 < headers.length ? headers[index + 1].index : jobs.length,
  );
  return block.split(/^ {6}- /mu).slice(1);
}

function assertRequiredCheckContract(source) {
  const workflow = normalizeLineEndings(source);
  assert.match(workflow, /\n  frontend:\n    name: Frontend\n/);
  assert.match(workflow, /\n  windows-managed-runtime:\n    name: Windows managed-runtime repair\n/);
  assert.match(workflow, /\n  ci-result:\n    name: CI result\n    if: always\(\)\n/);
  for (const dependency of [
    "changes",
    "frontend",
    "engine-admission",
    "framework-contract",
    "release-contract",
    "rust-core",
    "windows-managed-runtime",
    "desktop-linux",
  ]) {
    assert.match(workflow, new RegExp(`ci-result:[\\s\\S]*?needs:[\\s\\S]*?- ${dependency.replaceAll("-", "\\-")}`));
  }
  assert.match(workflow, /ci-result:[\s\S]*?uses: actions\/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1[\s\S]*?uses: actions\/setup-node@820762786026740c76f36085b0efc47a31fe5020/);
  assert.match(workflow, /run: node scripts\/ci\/classify-changes\.mjs --verify-results/);
  for (const expected of [
    "FRONTEND_EXPECTED",
    "ENGINE_EXPECTED",
    "FRAMEWORK_EXPECTED",
    "RELEASE_EXPECTED",
    "RUST_EXPECTED",
    "WINDOWS_EXPECTED",
    "DESKTOP_EXPECTED",
  ]) {
    assert.match(workflow, new RegExp(`\\n      ${expected}: \\$\\{\\{ needs\\.changes\\.outputs\\.`));
  }
}

test("documentation-only changes do not schedule product or release lanes", () => {
  assert.deepEqual(classifyChangedPaths([
    "README.md",
    "CONTRIBUTORS.md",
    "docs/product-spec.md",
  ]), {
    changed_path_count: 3,
    docs_only: true,
    frontend: false,
    rust_core: false,
    desktop: false,
    engine: false,
    framework: false,
    release_contract: false,
    windows_runtime: false,
  });
});

test("scanner skill copies are documentation contracts, not release triggers", () => {
  const result = classifyChangedPaths([
    ".claude/skills/ai-security-scanner/SKILL.md",
    ".codex/skills/ai-security-scanner/SKILL.md",
  ]);
  assert.equal(result.docs_only, true);
  assert.equal(result.frontend, false);
  assert.equal(result.rust_core, false);
  assert.equal(result.release_contract, false);
  assert.equal(result.windows_runtime, false);
});

test("ordinary frontend changes schedule only the fast frontend lane", () => {
  assert.deepEqual(classifyChangedPaths([
    "src/pages/StartPage.tsx",
    "tests/frontend/scanPresentation.test.ts",
  ]), {
    changed_path_count: 2,
    docs_only: false,
    frontend: true,
    rust_core: false,
    desktop: false,
    engine: false,
    framework: false,
    release_contract: false,
    windows_runtime: false,
  });
});

test("component render tests and their runner config reach the frontend lane", () => {
  // These are the only tests that actually render a component, so a path that
  // failed to classify would leave the render suite permanently unscheduled
  // while the lane still reported green.
  assert.deepEqual(classifyChangedPaths([
    "tests/component/providerAuthorizationPanel.test.tsx",
    "vitest.config.ts",
  ]), {
    changed_path_count: 2,
    docs_only: false,
    frontend: true,
    rust_core: false,
    desktop: false,
    engine: false,
    framework: false,
    release_contract: false,
    windows_runtime: false,
  });
});

test("the shared external-target corpus schedules both parity-test lanes", () => {
  assert.deepEqual(classifyChangedPaths([
    "tests/fixtures/external-target-corpus.json",
  ]), {
    changed_path_count: 1,
    docs_only: false,
    frontend: true,
    rust_core: true,
    desktop: false,
    engine: false,
    framework: false,
    release_contract: false,
    windows_runtime: false,
  });
});

test("backend files a frontend test reads schedule the frontend lane too", () => {
  // `coverageDimensionPresentation.test.ts` reads the beginner report's Rust
  // source to enumerate every coverage dimension the backend can name, and
  // `exportRunSelection.test.ts` reads the native export command. Both are
  // cross-boundary contracts, so the commit most likely to break them is a
  // backend-only one -- exactly the commit that would otherwise skip the lane
  // these tests live in while CI still reported green.
  assert.deepEqual(classifyChangedPaths([
    "src-tauri/src/beginner_report.rs",
  ]), {
    changed_path_count: 1,
    docs_only: false,
    frontend: true,
    rust_core: true,
    desktop: true,
    engine: false,
    framework: false,
    release_contract: false,
    windows_runtime: false,
  });
  assert.equal(classifyChangedPaths(["src-tauri/src/commands.rs"]).frontend, true);
  // `correlationWireContract.test.ts` reads the correlation module to hold the
  // report's JSON field names identical on both sides. Renaming a Rust field
  // compiles everywhere and silently delivers `undefined` to the page.
  assert.equal(classifyChangedPaths(["src-tauri/src/correlation.rs"]).frontend, true);
  // The warning census also reads the orchestrator and adapter producer files.
  assert.equal(classifyChangedPaths(["src-tauri/src/orchestrator.rs"]).frontend, true);
  assert.equal(classifyChangedPaths(["src-tauri/src/adapters/mod.rs"]).frontend, true);
  // `cloudSetupScripts.test.ts` loads the fake Graph module by directory, which
  // the read guard skips, so pin the fake and the scripts it exercises here.
  assert.equal(classifyChangedPaths([
    "tests/fixtures/cloud-setup/modules/Microsoft.Graph.Authentication/Microsoft.Graph.Authentication.psm1",
  ]).frontend, true);
  assert.equal(classifyChangedPaths(["cloud-setup/microsoft365-read-only.ps1"]).frontend, true);
  // Unrelated backend files must not drag the frontend suite in with them.
  assert.equal(classifyChangedPaths(["src-tauri/src/bootstrap.rs"]).frontend, false);
});

test("the frontend lane actually runs the component render suite", () => {
  const frontendBlock = ciWorkflow.split("\n  engine-admission:", 1)[0].split("\n  frontend:")[1];
  assert.ok(frontendBlock, "frontend job block is missing");
  assert.match(frontendBlock, /npm run test:component/);
});

test("engine inputs schedule engine admission without release or installer work", () => {
  assert.deepEqual(classifyChangedPaths([
    "engines/images/gitleaks/Dockerfile",
    ".github/workflows/engine-image-gitleaks.yml",
    "tests/engines/prowlerCatalogContract.test.mjs",
  ]), {
    changed_path_count: 3,
    docs_only: false,
    frontend: false,
    rust_core: false,
    desktop: false,
    engine: true,
    framework: false,
    release_contract: false,
    windows_runtime: false,
  });
});

test("engine evidence and OCI fixture scripts cannot bypass engine admission", () => {
  for (const path of [
    "scripts/engine-image-evidence.mjs",
    "scripts/generate-oci-layout-fixture.mjs",
  ]) {
    const result = classifyChangedPaths([path]);
    assert.equal(result.engine, true, `${path} did not schedule engine admission`);
    assert.equal(result.release_contract, false, `${path} scheduled the release lane`);
    assert.equal(result.windows_runtime, false, `${path} scheduled the Windows installer lane`);
  }
});

test("the embedded engine catalog also exercises Rust and desktop integration", () => {
  const result = classifyChangedPaths(["engines/catalog.json"]);
  assert.equal(result.engine, true);
  assert.equal(result.rust_core, true);
  assert.equal(result.desktop, true);
  assert.equal(result.release_contract, false);
  assert.equal(result.windows_runtime, false);
});

test("the master-framework producer exercises Rust, desktop, and release contracts", () => {
  const result = classifyChangedPaths(["src-tauri/src/exporters/framework_report.rs"]);
  assert.equal(result.rust_core, true);
  assert.equal(result.desktop, true);
  assert.equal(result.framework, true);
  assert.equal(result.release_contract, true);
  assert.equal(result.engine, false);
  assert.equal(result.windows_runtime, false);
});

test("AIDEFEND inputs use the framework lane and mapping schema also exercises Rust", () => {
  assert.deepEqual(classifyChangedPaths([
    "mappings/control-mappings.schema.json",
    "mappings/vendor/aidefend/1.20260805/selected-controls.json",
    "mappings/vendor/aidefend/1.20260805/PROVENANCE.json",
    "scripts/validate-aidefend-snapshot.mjs",
  ]), {
    changed_path_count: 4,
    docs_only: false,
    frontend: false,
    rust_core: true,
    desktop: false,
    engine: false,
    framework: true,
    release_contract: false,
    windows_runtime: false,
  });

  const embeddedMapping = classifyChangedPaths(["mappings/control-mappings.json"]);
  assert.equal(embeddedMapping.frontend, true);
  assert.equal(embeddedMapping.framework, true);
  assert.equal(embeddedMapping.rust_core, true);
  assert.equal(embeddedMapping.desktop, true);
  assert.equal(embeddedMapping.release_contract, false);
});

test("platform startup, installer and managed-runtime inputs schedule their focused heavyweight lanes", () => {
  assert.deepEqual(classifyChangedPaths([
    "runtime/managed-runtime.schema.json",
    "src-tauri/src/bin/cli.rs",
    "src-tauri/src/managed_runtime.rs",
    "src-tauri/windows/nsis/installer.nsi",
  ]), {
    changed_path_count: 4,
    docs_only: false,
    frontend: false,
    rust_core: true,
    desktop: true,
    engine: false,
    framework: false,
    release_contract: true,
    windows_runtime: true,
  });
  // Startup messages select the locale through different Unix and Windows APIs.
  const result = classifyChangedPaths(["src-tauri/src/startup_failure.rs"]);
  assert.equal(result.rust_core, true);
  assert.equal(result.desktop, true);
  assert.equal(result.windows_runtime, true);
  assert.equal(result.engine, false);
  assert.equal(result.release_contract, false);

  // Shared publication origins are read by the gateway and managed network.
  assert.deepEqual(classifyChangedPaths(["src-tauri/src/publication_origins.rs"]), {
    changed_path_count: 1,
    docs_only: false,
    frontend: false,
    rust_core: true,
    desktop: true,
    engine: false,
    framework: false,
    release_contract: false,
    windows_runtime: true,
  });
});

test("the vendored Linux desktop security patch runs its provenance and build gates", () => {
  const result = classifyChangedPaths(["vendor/glib-0.18.5/src/variant_iter.rs"]);
  assert.equal(result.rust_core, true);
  assert.equal(result.desktop, true);
  assert.equal(result.release_contract, true);
  assert.equal(result.windows_runtime, false);
  assert.equal(result.engine, false);
  assert.equal(result.docs_only, false);

  assert.ok(
    ciJobSteps("rust-core").some((step) => step.includes("bash scripts/verify-vendored-glib.sh")),
    "rust-core must verify the checksum-pinned glib backport",
  );
});

test("shared Node dependencies and publication origins exercise their consumers", () => {
  const result = classifyChangedPaths(["package-lock.json"]);
  assert.equal(result.frontend, true);
  assert.equal(result.desktop, true);
  assert.equal(result.engine, true);
  assert.equal(result.framework, true);
  assert.equal(result.release_contract, true);
  assert.equal(result.windows_runtime, true);
  assert.equal(result.rust_core, false);

  for (const path of [
    "scripts/publication-origins.mjs",
    "scripts/publication-origins.d.mts",
  ]) {
    assert.deepEqual(classifyChangedPaths([path]), {
      changed_path_count: 1,
      docs_only: false,
      frontend: true,
      rust_core: false,
      desktop: false,
      engine: true,
      framework: false,
      release_contract: true,
      windows_runtime: false,
    }, path);
  }
});

test("every frozen-release workflow and release schema schedules release-contract tests", () => {
  for (const path of [
    ".github/workflows/release.yml",
    ".github/workflows/promote-release.yml",
    ".github/workflows/windows-external-evidence.yml",
    "docs/release/release-metadata.schema.json",
    "docs/release/engine-image-supply-chain.schema.json",
    "docs/release/windows-installed-lifecycle-evidence.schema.json",
    "docs/release/windows-external-evidence-receipt.schema.json",
  ]) {
    const result = classifyChangedPaths([path]);
    assert.equal(result.release_contract, true, `${path} skipped release-contract tests`);
    assert.equal(result.docs_only, false, `${path} was misclassified as documentation-only`);
  }
  assert.equal(
    classifyChangedPaths(["docs/release/windows-external-qualification-plan.md"]).release_contract,
    false,
    "release prose alone should not schedule the heavyweight release-contract lane",
  );
});

test("CI classifier changes rely on the always-run classifier test, not heavyweight lanes", () => {
  assert.deepEqual(classifyChangedPaths([
    ".github/workflows/ci.yml",
    "scripts/ci/classify-changes.mjs",
    "tests/ci/classify-changes.test.mjs",
  ]), {
    changed_path_count: 3,
    docs_only: false,
    frontend: false,
    rust_core: false,
    desktop: false,
    engine: false,
    framework: false,
    release_contract: false,
    windows_runtime: false,
  });
});

test("the Windows NSIS validator stays in the focused Windows lane", () => {
  const validationCommand = "node scripts/release/validate-windows-nsis-template.mjs";
  assert.equal(
    ciJobSteps("release-contract").some((step) => step.includes(validationCommand)),
    false,
  );
  const windowsSteps = ciJobSteps("windows-managed-runtime");
  const validatorIndexes = windowsSteps
    .map((step, index) => (step.includes(validationCommand) ? index : -1))
    .filter((index) => index >= 0);
  assert.deepEqual(validatorIndexes, [
    windowsSteps.findIndex((step) => step.includes("npm ci --ignore-scripts")) + 1,
  ]);
});

test("an unavailable push base schedules every lane instead of silently omitting work", () => {
  assert.deepEqual(classifyAllBoundaries(), {
    changed_path_count: 0,
    docs_only: false,
    frontend: true,
    rust_core: true,
    desktop: true,
    engine: true,
    framework: true,
    release_contract: true,
    windows_runtime: true,
  });

  assert.match(ciWorkflow, /if \[\[ -z "\$base_sha" \]\]; then/);
  assert.match(ciWorkflow, /classify-changes\.mjs --all/);
  assert.match(ciWorkflow, /git diff-tree --root --no-renames/);
  assert.match(ciWorkflow, /git diff --no-renames --name-only/);
  assert.match(ciWorkflow, /if git cat-file -e "\$\{base_sha\}\^\{commit\}"; then[\s\S]*Base commit is not present[\s\S]*classify-changes\.mjs --all/);
});

test("heavyweight commands stay behind their focused job conditions", () => {
  const frontendBlock = ciWorkflow.split("\n  engine-admission:", 1)[0].split("\n  frontend:")[1];
  assert.ok(frontendBlock, "frontend job block is missing");
  assert.doesNotMatch(frontendBlock, /validate:engines|validate:aidefend|release:self-test|vendor-managed-runtime|bundles nsis/);

  assert.match(ciWorkflow, /Record intentional documentation-only scope[\s\S]*?steps\.classify\.outputs\.docs_only == 'true'/);
  assert.match(ciWorkflow, /Record classifier-only scope[\s\S]*?an unclassified path; only classifier tests are scheduled/);
  assert.match(ciWorkflow, /engine-admission:[\s\S]*?if: needs\.changes\.outputs\.engine == 'true'[\s\S]*?npm run validate:engines/);
  assert.match(ciWorkflow, /engine-admission:[\s\S]*?node --check scripts\/engine-image-evidence\.mjs[\s\S]*?node --check scripts\/generate-oci-layout-fixture\.mjs/);
  assert.match(ciWorkflow, /framework-contract:[\s\S]*?if: needs\.changes\.outputs\.framework == 'true'[\s\S]*?npm run validate:aidefend/);
  assert.match(ciWorkflow, /release-contract:[\s\S]*?if: needs\.changes\.outputs\.release_contract == 'true'[\s\S]*?npm run release:self-test/);
  assert.match(
    ciWorkflow,
    /windows-managed-runtime:[\s\S]*?if: needs\.changes\.outputs\.windows_runtime == 'true'[\s\S]*?vendor-managed-runtime[\s\S]*?desktop:prepare-sidecar[\s\S]*?cli,installer-runtime-cache[\s\S]*?bundles nsis/,
  );
});

test("existing required-check names remain stable and one aggregate verifies scheduled lanes", () => {
  assertRequiredCheckContract(ciWorkflow);
});

test("required-check contract accepts both LF and CRLF workflow text", () => {
  assertRequiredCheckContract(ciWorkflow);
  assertRequiredCheckContract(ciWorkflow.replaceAll("\n", "\r\n"));
});

test("aggregate result logic accepts intentional skips and rejects every incomplete scheduled lane", () => {
  const lanes = [
    { label: "Frontend", expected: "true", result: "success" },
    { label: "Engine admission", expected: "false", result: "skipped" },
  ];
  assert.deepEqual(ciBoundaryResultErrors("success", lanes), []);
  assert.deepEqual(ciBoundaryResultErrors("failure", lanes), [
    "Changed-boundary classification did not complete successfully (failure).",
  ]);
  assert.deepEqual(ciBoundaryResultErrors("success", [
    { label: "Frontend", expected: "true", result: "skipped" },
    { label: "Engine admission", expected: "false", result: "success" },
    { label: "Framework mapping", expected: "", result: "skipped" },
  ]), [
    "Frontend was scheduled but finished as skipped.",
    "Engine admission was not scheduled but finished as success.",
    "Framework mapping has an invalid classifier output: missing.",
  ]);
  for (const result of ["failure", "cancelled", "skipped", "missing"]) {
    assert.equal(ciBoundaryResultErrors("success", [
      { label: "Scheduled lane", expected: "true", result: result === "missing" ? "" : result },
    ]).length, 1, `scheduled ${result} lane was accepted`);
  }
});

test("GitHub output is deterministic and uses workflow-compatible scalar values", () => {
  assert.deepEqual(
    githubOutputLines(classifyChangedPaths(["src/App.tsx", "./src/App.tsx"])),
    [
      "changed_path_count=1",
      "docs_only=false",
      "frontend=true",
      "rust_core=false",
      "desktop=false",
      "engine=false",
      "framework=false",
      "release_contract=false",
      "windows_runtime=false",
    ],
  );
});
