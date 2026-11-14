import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { CORE_RESOURCE_PATHS } from "../../scripts/skill/input-manifest.mjs";

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
    "engine-launchers",
    "framework-contract",
    "release-contract",
    "rust-core",
    "windows-managed-runtime",
    "desktop-linux",
    "skill-bootstrap",
    "skill-native",
  ]) {
    assert.match(workflow, new RegExp(`ci-result:[\\s\\S]*?needs:[\\s\\S]*?- ${dependency.replaceAll("-", "\\-")}`));
  }
  assert.match(workflow, /ci-result:[\s\S]*?uses: actions\/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1[\s\S]*?uses: actions\/setup-node@820762786026740c76f36085b0efc47a31fe5020/);
  assert.match(workflow, /run: node scripts\/ci\/classify-changes\.mjs --verify-results/);
  for (const expected of [
    "FRONTEND_EXPECTED",
    "ENGINE_EXPECTED",
    "ENGINE_LAUNCHERS_EXPECTED",
    "FRAMEWORK_EXPECTED",
    "RELEASE_EXPECTED",
    "RUST_EXPECTED",
    "WINDOWS_EXPECTED",
    "DESKTOP_EXPECTED",
    "SKILL_BOOTSTRAP_EXPECTED",
    "SKILL_NATIVE_EXPECTED",
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
    windows_installer: false,
    skill_bootstrap: false,
    skill_native: false,
  });
});

test("scanner skill copies run lightweight contracts without native or release builds", () => {
  const result = classifyChangedPaths([
    ".claude/skills/ai-security-scanner/SKILL.md",
    ".codex/skills/ai-security-scanner/SKILL.md",
  ]);
  assert.equal(result.docs_only, false);
  assert.equal(result.skill_bootstrap, true);
  assert.equal(result.skill_native, false);
  assert.equal(result.frontend, false);
  assert.equal(result.rust_core, false);
  assert.equal(result.release_contract, false);
  assert.equal(result.windows_runtime, false);
});

test("skill prompts, metadata, provider methods and sync changes avoid core rebuilds", () => {
  for (const path of [
    "skills/ai-security-scanner/SKILL.md",
    "skills/ai-security-scanner/agents/openai.yaml",
    ".codex/skills/ai-security-scanner/agents/openai.yaml",
    "providers/cloudflare/method.md",
    "scripts/skill/sync-skill.mjs",
    "scripts/ci/skill-runtime-smoke.py",
    "tests/skill/sync-skill.test.mjs",
    "tests/acceptance/cloudflare-host/setup.mjs",
    "tests/acceptance/cloudflare-host/fixture/vouchers.mjs",
    "docs/skill-bootstrap.md",
  ]) {
    const result = classifyChangedPaths([path]);
    assert.equal(result.skill_bootstrap, true, path);
    for (const boundary of ["skill_native", "rust_core", "desktop", "release_contract", "windows_runtime", "windows_installer", "docs_only"]) {
      assert.equal(result[boundary], false, `${path}: ${boundary}`);
    }
  }
});

test("bootstrap recipes and input changes exercise native bootstrap without installers", () => {
  for (const path of [
    "scripts/skill/bootstrap.mjs",
    "scripts/skill/bootstrap-core.mjs",
    "scripts/skill/build-inputs.mjs",
    "tests/skill/bootstrap.test.mjs",
    "scripts/ci/skill-bootstrap-smoke.mjs",
  ]) {
    const result = classifyChangedPaths([path]);
    assert.equal(result.skill_bootstrap, true, path);
    assert.equal(result.skill_native, true, path);
    for (const boundary of ["rust_core", "desktop", "release_contract", "windows_runtime", "windows_installer"]) {
      assert.equal(result[boundary], false, `${path}: ${boundary}`);
    }
  }
  assert.equal(classifyChangedPaths(["src-tauri/src/report_renderer.rs"]).skill_native, true);
  assert.equal(classifyChangedPaths(["Cargo.lock"]).skill_native, true);
  for (const path of CORE_RESOURCE_PATHS) {
    assert.equal(classifyChangedPaths([path]).skill_native, true, `${path}: embedded core resource`);
  }
});

test("Cloudflare executable inputs and fixtures run native checks; method prose stays in contracts", () => {
  for (const path of [
    "providers/cloudflare/validate-document.cjs",
    "providers/cloudflare/upstream/skills/security-audit/report-schema.json",
    "providers/cloudflare/upstream/skills/security-audit/validate-findings.cjs",
    "providers/cloudflare/upstream/skills/security-audit/validate-coverage-ledger.cjs",
    "tests/fixtures/cloudflare/findings.json",
    "src-tauri/tests/cli_cloudflare_source_view.rs",
    "src-tauri/tests/cli_cloudflare_audit/main.rs",
  ]) {
    const result = classifyChangedPaths([path]);
    assert.equal(result.rust_core, true, path);
    assert.equal(result.skill_native, true, path);
    assert.equal(result.release_contract, false, path);
    assert.equal(result.desktop, false, path);
  }
  for (const path of [
    "providers/cloudflare/upstream/skills/security-audit/HUNTING.md",
    "providers/cloudflare/upstream.lock.json",
    "providers/cloudflare/provider.json",
  ]) {
    const result = classifyChangedPaths([path]);
    assert.equal(result.skill_bootstrap, true, path);
    assert.equal(result.rust_core, false, path);
    assert.equal(result.skill_native, false, path);
  }
});

test("native skill lanes execute cache reuse, core identity, reports and archives on each OS", () => {
  const nativeSteps = ciJobSteps("skill-native");
  const native = nativeSteps.join("\n");
  assert.match(ciWorkflow, /skill-native:[\s\S]*?if: needs\.changes\.outputs\.skill_native == 'true'[\s\S]*?os: \[ubuntu-24\.04, macos-15, windows-2025\]/u);
  assert.match(native, /node scripts\/ci\/skill-bootstrap-smoke\.mjs/u);
  assert.match(native, /--no-default-features[\s\S]*?--features cli --test cli_build_identity --test cli_report_snapshot --test cli_case_archive[\s\S]*?--test cli_foreground_scan --test cli_runtime_prepare --test cli_cloudflare_provider --test report_fidelity_baseline/u);
  assert.match(native, /--test cli_cloudflare_bundle/u);
  assert.match(native, /--test cli_cloudflare_source_view --test cli_cloudflare_audit/u);
  const libraryTests = nativeSteps.findIndex((step) => step.startsWith("name: Run the library unit tests on macOS and Windows"));
  const foregroundTests = nativeSteps.findIndex((step) => step.startsWith("name: Run foreground scans, runtime preparation, reports and archives with a fixture runtime"));
  const evidence = nativeSteps.findIndex((step) => step.startsWith("name: Retain native bootstrap evidence"));
  assert.ok(foregroundTests >= 0 && libraryTests > foregroundTests && evidence > libraryTests);
  assert.match(nativeSteps[libraryTests], /^ {8}if: \$\{\{ !cancelled\(\) && runner\.os != 'Linux' && needs\.changes\.outputs\.rust_core == 'true' \}\}$/mu);
  assert.match(nativeSteps[libraryTests], /run: >-\s+cargo test --locked --no-fail-fast --package ai-security-scanner --no-default-features\s+--features cli --lib\s*$/u);
  assert.doesNotMatch(native, /installer-runtime-cache|desktop:prepare|bundles (?:nsis|msi|dmg|deb)|npm run tauri/u);
  assert.doesNotMatch(ciWorkflow, /skill-runtime-smoke\.py/u);
  const contracts = ciJobSteps("skill-bootstrap").join("\n");
  assert.match(contracts, /sync-skill\.mjs --check/u);
  assert.match(contracts, /node --test tests\/skill\/\*\.test\.mjs/u);
  assert.doesNotMatch(contracts, /cargo|npm ci|rust-toolchain|vendor-managed-runtime/u);
});

test("Windows native bootstrap initializes the runner's compiler before executing source builds", () => {
  const nativeSteps = ciJobSteps("skill-native");
  const initialization = nativeSteps.findIndex((step) => step.includes("initialize-windows-toolchain.ps1"));
  const contracts = nativeSteps.findIndex((step) => step.includes("node --test tests/skill/*.test.mjs"));
  const smoke = nativeSteps.findIndex((step) => step.includes("skill-bootstrap-smoke.mjs"));
  assert.ok(initialization >= 0 && initialization < smoke);
  assert.ok(contracts > initialization && contracts < smoke, "Windows ACL tests must run before admitting the native cache");
  assert.doesNotMatch(nativeSteps[contracts], /\bif:/u, "portable ownership tests run on every native platform");
  assert.match(nativeSteps[initialization], /if: runner\.os == 'Windows'/u);
  assert.match(nativeSteps[initialization], /shell: pwsh/u);
  const helper = readFileSync(new URL("../../scripts/ci/initialize-windows-toolchain.ps1", import.meta.url), "utf8");
  assert.match(helper, /ProgramFiles\(x86\)[\s\S]*?Microsoft Visual Studio\\Installer\\vswhere\.exe/u);
  assert.match(helper, /-requires Microsoft\.VisualStudio\.Component\.VC\.Tools\.x86\.x64/u);
  assert.match(helper, /Common7\\Tools\\VsDevCmd\.bat/u);
  assert.match(helper, /-arch=x64 -host_arch=x64/u);
  assert.match(helper, /AppendAllText\(\$env:GITHUB_ENV/u);
  assert.match(helper, /Get-Command cl\.exe/u);
  assert.match(helper, /Get-Command link\.exe/u);
  assert.doesNotMatch(helper, /Invoke-WebRequest|Start-BitsTransfer|winget|choco|curl/u);
  const result = classifyChangedPaths(["scripts/ci/initialize-windows-toolchain.ps1"]);
  assert.equal(result.skill_native, true);
  assert.equal(result.windows_installer, false);
});

test("ordinary core changes preserve Windows checks while only installer inputs build NSIS", () => {
  for (const path of [
    "src-tauri/src/bin/cli.rs",
    "src-tauri/src/managed_runtime.rs",
    "src-tauri/build.rs",
    "Cargo.lock",
    "scripts/skill/bootstrap.mjs",
    "skills/ai-security-scanner/SKILL.md",
  ]) {
    assert.equal(classifyChangedPaths([path]).windows_installer, false, path);
  }
  const cli = classifyChangedPaths(["src-tauri/src/bin/cli.rs"]);
  assert.equal(cli.windows_runtime, true);
  assert.equal(cli.desktop, true);
  for (const path of [
    "src-tauri/windows/nsis/installer.nsi",
    "src-tauri/tauri.conf.json",
    "scripts/release/build-sidecar.mjs",
    "scripts/release/stage-sidecar.mjs",
    "runtime/vendor-managed-runtime.mjs",
  ]) {
    const result = classifyChangedPaths([path]);
    assert.equal(result.windows_installer, true, path);
    assert.equal(result.windows_runtime, true, `${path}: installer implies its owning runtime job`);
  }
  const windows = ciJobSteps("windows-managed-runtime");
  const installer = windows.find((step) => step.includes("--bundles nsis"));
  assert.match(installer, /if: needs\.changes\.outputs\.windows_installer == 'true'/u);
  const desktop = windows.find((step) => step.includes("Compile Windows desktop"));
  assert.doesNotMatch(desktop, /\n\s+if:/u);
  assert.match(desktop, /cargo check[\s\S]*?--features desktop/u);
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
    windows_installer: false,
    skill_bootstrap: false,
    skill_native: false,
  });
});

test("frozen report inputs schedule Rust replay and the corpus verifier is always run", (t) => {
  for (const path of [
    "tests/fixtures/report-fidelity/all-detectors/case.json.gz",
    "tests/fixtures/report-fidelity/mixed-terminal/en-standard.html.gz",
    "tests/fixtures/report-fidelity/receipt.json",
  ]) {
    const result = classifyChangedPaths([path]);
    assert.equal(result.rust_core, true, path);
    assert.equal(result.desktop, false, path);
    assert.equal(result.release_contract, false, path);
  }
  assert.ok(ciJobSteps("changes").some((step) =>
    step.includes("run: node scripts/verify-report-fidelity-baseline.mjs") && !/\n\s+if:/.test(step)));

  const root = fileURLToPath(new URL("../../", import.meta.url));
  const directory = mkdtempSync(path.join(tmpdir(), "report-fidelity-verifier-"));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  mkdirSync(path.join(directory, "scripts"));
  cpSync(path.join(root, "scripts/verify-report-fidelity-baseline.mjs"),
    path.join(directory, "scripts/verify-report-fidelity-baseline.mjs"));
  const corpus = path.join(directory, "tests/fixtures/report-fidelity");
  cpSync(path.join(root, "tests/fixtures/report-fidelity"), corpus, { recursive: true });
  const receiptPath = path.join(corpus, "receipt.json");
  const receipt = JSON.parse(readFileSync(receiptPath, "utf8"));
  const run = () => spawnSync(process.execPath, [path.join(directory, "scripts/verify-report-fidelity-baseline.mjs")], {
    encoding: "utf8",
  });
  const replacement = () => ({
    baselineCoreRevision: "0123456789abcdef0123456789abcdef01234567",
    productVersion: "0.5.0",
    receiptSha256: "a".repeat(64),
    reason: "Reviewed report wording",
    inputs: "carried over byte-identical",
    changedDocuments: ["all-detectors/en-standard.html", "mixed-terminal/report.case.tar.gz"],
  });

  let result = run();
  assert.equal(result.status, 0, result.stderr);
  assert.doesNotMatch(result.stdout, /Replaced revision/);
  receipt.replaces = replacement();
  writeFileSync(receiptPath, JSON.stringify(receipt));
  result = run();
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /Replaced revision 0123456789abcdef0123456789abcdef01234567.*2 changed documents/);

  for (const value of [
    null,
    [],
    { ...replacement(), baselineCoreRevision: "A".repeat(40) },
    { ...replacement(), baselineCoreRevision: receipt.baselineCoreRevision },
    { ...replacement(), productVersion: "" },
    { ...replacement(), receiptSha256: "g".repeat(64) },
    { ...replacement(), receiptSha256: "a".repeat(63) },
    { ...replacement(), reason: "" },
    { ...replacement(), reason: "   " },
    { ...replacement(), inputs: "recreated" },
    { ...replacement(), changedDocuments: "all-detectors/en-standard.html" },
    { ...replacement(), changedDocuments: ["all-detectors/en-standard.html", "all-detectors/en-standard.html"] },
    { ...replacement(), changedDocuments: ["mixed-terminal/en-standard.html", "all-detectors/en-standard.html"] },
    { ...replacement(), changedDocuments: ["all-detectors/unknown.html"] },
    { ...replacement(), changedDocuments: ["all-detectors/extra/en-standard.html"] },
    { ...replacement(), changedDocuments: [42] },
  ]) {
    receipt.replaces = value;
    writeFileSync(receiptPath, JSON.stringify(receipt));
    result = run();
    assert.notEqual(result.status, 0, `accepted invalid replacement: ${JSON.stringify(value)}`);
  }
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
    windows_installer: false,
    skill_bootstrap: false,
    skill_native: false,
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
    windows_installer: false,
    skill_bootstrap: false,
    skill_native: true,
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
    windows_installer: false,
    skill_bootstrap: false,
    skill_native: true,
  });
  assert.equal(classifyChangedPaths(["src-tauri/src/commands.rs"]).frontend, true);
  // `correlationWireContract.test.ts` reads the correlation module to hold the
  // report's JSON field names identical on both sides. Renaming a Rust field
  // compiles everywhere and silently delivers `undefined` to the page.
  assert.equal(classifyChangedPaths(["src-tauri/src/correlation.rs"]).frontend, true);
  assert.equal(classifyChangedPaths(["src-tauri/src/source_audit_report.rs"]).frontend, true);
  assert.equal(classifyChangedPaths(["src-tauri/src/provider_report.rs"]).frontend, true);
  assert.equal(classifyChangedPaths(["src-tauri/src/agent_audit_admission.rs"]).frontend, true);
  assert.equal(classifyChangedPaths(["tests/support/sourceAudit.ts"]).frontend, true);
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
    windows_installer: false,
    skill_bootstrap: false,
    skill_native: false,
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
    windows_installer: false,
    skill_bootstrap: false,
    skill_native: true,
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
    windows_installer: true,
    skill_bootstrap: false,
    skill_native: true,
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
    windows_installer: false,
    skill_bootstrap: false,
    skill_native: true,
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
    windows_installer: false,
    skill_bootstrap: false,
    skill_native: false,
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

test("release and usability test inputs schedule the contracts that read them", () => {
  for (const path of [
    "docs/incident-pack.js",
    "docs/incident-pack.json",
    ".github/workflows/engine-images-local-k8s.yml",
    "scripts/semgrep-native-publication-contract.mjs",
    "tests/usability/evidenceValidator.test.mjs",
    "scripts/validate-usability-evidence.mjs",
    "docs/usability/session-evidence.schema.json",
  ]) {
    const result = classifyChangedPaths([path]);
    assert.equal(result.release_contract, true, `${path}: release_contract`);
    assert.equal(result.docs_only, false, `${path}: docs_only`);
  }
  assert.equal(classifyChangedPaths(["scripts/semgrep-native-publication-contract.mjs"]).engine, true);
  assert.ok(ciJobSteps("release-contract").some((step) => step.trim() === "run: npm run test:usability-evidence"));
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
    windows_installer: false,
    skill_bootstrap: false,
    skill_native: false,
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
    windows_installer: true,
    skill_bootstrap: true,
    skill_native: true,
  });

  assert.match(ciWorkflow, /if \[\[ -z "\$base_sha" \]\]; then/);
  assert.match(ciWorkflow, /classify-changes\.mjs --all/);
  assert.match(ciWorkflow, /git diff-tree --root --no-renames/);
  assert.match(ciWorkflow, /git diff --no-renames --name-only/);
  assert.match(ciWorkflow, /if git cat-file -e "\$\{base_sha\}\^\{commit\}"; then[\s\S]*Base commit is not present[\s\S]*classify-changes\.mjs --all/);
});

test("only pull requests cancel an in-progress run on the same ref", () => {
  assert.match(ciWorkflow, /\nconcurrency:\n  group: ci-\$\{\{ github\.ref \}\}\n  cancel-in-progress: \$\{\{ github\.event_name == 'pull_request' \}\}\n/u);
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

test("engine launcher changes schedule the dedicated job and aggregate its result", () => {
  assert.equal(classifyChangedPaths(["scripts/ci/engine-launcher-tests.sh"]).engine, true);
  const block = ciWorkflow.match(/\n  engine-launchers:\n([\s\S]*?)(?=\n  [\w-]+:\n|$)/u)?.[1];
  assert.ok(block, "engine-launchers job must exist");
  assert.match(block, /\n    needs: changes\n    if: needs\.changes\.outputs\.engine == 'true'\n    runs-on: ubuntu-24\.04\n/u);
  const steps = ciJobSteps("engine-launchers").map((step) => step.trim());
  assert.equal(steps.length, 2);
  assert.match(steps[0], /^uses: actions\/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1/u);
  assert.equal(steps[1], "run: bash scripts/ci/engine-launcher-tests.sh");
  assert.match(ciWorkflow, /ENGINE_LAUNCHERS_EXPECTED: \$\{\{ needs\.changes\.outputs\.engine \}\}/u);
  assert.match(ciWorkflow, /ENGINE_LAUNCHERS_RESULT: \$\{\{ needs\['engine-launchers'\]\.result \}\}/u);
});

test("the aggregate rejects incomplete launcher results", () => {
  const environment = { ...process.env, CHANGES_RESULT: "success" };
  for (const lane of ["FRONTEND", "ENGINE", "ENGINE_LAUNCHERS", "FRAMEWORK", "RELEASE", "RUST", "WINDOWS", "DESKTOP", "SKILL_BOOTSTRAP", "SKILL_NATIVE"]) {
    environment[`${lane}_EXPECTED`] = "true";
    environment[`${lane}_RESULT`] = "success";
  }
  const verify = () => spawnSync(process.execPath, ["scripts/ci/classify-changes.mjs", "--verify-results"], {
    cwd: new URL("../../", import.meta.url), env: environment, encoding: "utf8",
  });
  assert.equal(verify().status, 0);
  environment.ENGINE_LAUNCHERS_RESULT = "failure";
  const failed = verify();
  assert.equal(failed.status, 1);
  assert.match(failed.stderr, /Engine launcher tests was scheduled but finished as failure/u);
  environment.ENGINE_LAUNCHERS_EXPECTED = "false";
  environment.ENGINE_LAUNCHERS_RESULT = "skipped";
  assert.equal(verify().status, 0);
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
      "windows_installer=false",
      "skill_bootstrap=false",
      "skill_native=false",
    ],
  );
});
