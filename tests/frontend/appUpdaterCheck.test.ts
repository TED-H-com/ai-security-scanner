import assert from "node:assert/strict";
import test from "node:test";

import { build } from "esbuild";
import { UPDATER_DOWNLOAD_REPOSITORY } from "../../scripts/publication-origins.mjs";

const VERSION = "1.0.0";
const SIGNATURE = "A".repeat(96);
const CURRENT_VERSION = "0.1.8";

const windowsPayloads = () => {
  const entry = {
    signature: SIGNATURE,
    url: `https://github.com/${UPDATER_DOWNLOAD_REPOSITORY}/releases/download/v${VERSION}/ai-security-scanner_${VERSION}_x64-setup.exe`,
  };
  return {
    "windows-x86_64": entry,
    "windows-x86_64-nsis": { ...entry },
  };
};

interface FakeUpdate {
  currentVersion: string;
  version: string;
  date?: string;
  body?: string;
  rawJson: Record<string, unknown>;
  close: () => Promise<void>;
}

interface CheckHarness {
  currentVersion: string;
  nextCheck: () => Promise<FakeUpdate | null>;
  closes: FakeUpdate[];
}

declare global {
  // eslint-disable-next-line no-var
  var __APP_UPDATER_CHECK_TEST__: CheckHarness;
}

const bundledUpdater = await build({
  stdin: {
    contents: 'export { checkForAppUpdate } from "./src/services/appUpdater.ts";',
    loader: "ts",
    resolveDir: process.cwd(),
    sourcefile: "app-updater-check-test-entry.ts",
  },
  bundle: true,
  define: {
    "import.meta.env.TAURI_ENV_ARCH": JSON.stringify("x86_64"),
    "import.meta.env.TAURI_ENV_PLATFORM": JSON.stringify("windows"),
  },
  format: "esm",
  platform: "node",
  plugins: [{
    name: "app-updater-check-test-doubles",
    setup(context) {
      context.onResolve({ filter: /^@tauri-apps\/api\/app$/ }, () => ({
        namespace: "updater-check-test-double",
        path: "app",
      }));
      context.onResolve({ filter: /^@tauri-apps\/plugin-process$/ }, () => ({
        namespace: "updater-check-test-double",
        path: "process",
      }));
      context.onResolve({ filter: /^@tauri-apps\/plugin-updater$/ }, () => ({
        namespace: "updater-check-test-double",
        path: "updater",
      }));
      context.onLoad({ filter: /.*/, namespace: "updater-check-test-double" }, ({ path }) => {
        if (path === "app") {
          return {
            contents:
              "export const getVersion = async () => globalThis.__APP_UPDATER_CHECK_TEST__.currentVersion;",
          };
        }
        if (path === "process") {
          return { contents: "export const relaunch = async () => {};" };
        }
        return {
          contents: `export const check = () => globalThis.__APP_UPDATER_CHECK_TEST__.nextCheck();
          export class Update {}`,
        };
      });
    },
  }],
  target: "node22",
  write: false,
});
const updaterSource = bundledUpdater.outputFiles[0]?.text;
assert.ok(updaterSource, "app updater check test bundle should contain JavaScript");
const { checkForAppUpdate } = await import(
  `data:text/javascript;base64,${Buffer.from(updaterSource).toString("base64")}`
) as Pick<typeof import("../../src/services/appUpdater.ts"), "checkForAppUpdate">;

const resetHarness = (): CheckHarness => {
  const harness: CheckHarness = {
    currentVersion: CURRENT_VERSION,
    nextCheck: async () => null,
    closes: [],
  };
  globalThis.__APP_UPDATER_CHECK_TEST__ = harness;
  return harness;
};

const trackedUpdate = (rawJson: Record<string, unknown>, version = VERSION): FakeUpdate => {
  const update: FakeUpdate = {
    currentVersion: CURRENT_VERSION,
    version,
    rawJson,
    close: async () => {
      globalThis.__APP_UPDATER_CHECK_TEST__.closes.push(update);
    },
  };
  return update;
};

test("check() resolving null reports the installed app as current", async () => {
  const harness = resetHarness();
  harness.nextCheck = async () => null;

  const state = await checkForAppUpdate();

  assert.equal(state.phase, "current");
  assert.equal(state.currentVersion, CURRENT_VERSION);
  assert.equal(state.availableVersion, undefined);
  assert.equal(harness.closes.length, 0);
});

test("check() throwing is unreachable and keeps the underlying failure message", async () => {
  const harness = resetHarness();
  harness.nextCheck = async () => {
    throw new Error("update endpoint timed out");
  };

  const state = await checkForAppUpdate();

  assert.equal(state.phase, "unreachable");
  assert.equal(state.currentVersion, CURRENT_VERSION);
  assert.equal(state.message, "update endpoint timed out");
  assert.equal(harness.closes.length, 0);
});

test("a reachable service whose latest release lists no installer for this computer is not offline", async () => {
  // The published v0.2.0 manifest lists no platform, and the updater rejects
  // that before comparing versions, so every newer install saw an outage.
  const harness = resetHarness();
  const missingPlatform =
    'None of the fallback platforms `["windows-x86_64-nsis", "windows-x86_64"]` were found in the response `platforms` object';
  harness.nextCheck = async () => {
    throw missingPlatform;
  };

  const state = await checkForAppUpdate();

  assert.equal(state.phase, "unoffered");
  assert.equal(state.currentVersion, CURRENT_VERSION);
  assert.equal(state.availableVersion, undefined);
  assert.equal(state.message, missingPlatform);

  harness.nextCheck = async () => {
    throw new Error("the platform `windows-x86_64` was not found in the response `platforms` object");
  };
  assert.equal((await checkForAppUpdate()).phase, "unoffered");
});

test("an offered update that fails manifest verification is an error, not offline", async () => {
  const harness = resetHarness();
  const invalid = trackedUpdate({ version: VERSION, platforms: {} });
  harness.nextCheck = async () => invalid;

  const state = await checkForAppUpdate();

  assert.equal(state.phase, "error");
  assert.notEqual(state.phase, "unreachable");
  assert.equal(state.currentVersion, CURRENT_VERSION);
  assert.equal(state.availableVersion, undefined);
  assert.match(state.message ?? "", /missing the required windows-x86_64 payload/u);
  assert.deepEqual(harness.closes, [invalid]);

  harness.nextCheck = async () => null;
  const followUp = await checkForAppUpdate();

  assert.equal(followUp.phase, "current");
  assert.deepEqual(harness.closes, [invalid]);
});

test("a valid offered update is available and carries the offered version", async () => {
  const harness = resetHarness();
  const update = trackedUpdate({ version: VERSION, platforms: windowsPayloads() });
  harness.nextCheck = async () => update;

  const state = await checkForAppUpdate();

  assert.equal(state.phase, "available");
  assert.equal(state.currentVersion, CURRENT_VERSION);
  assert.equal(state.availableVersion, VERSION);
  assert.equal(harness.closes.length, 0);
});
