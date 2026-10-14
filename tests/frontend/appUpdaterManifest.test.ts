import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { build } from "esbuild";
import { CURRENT_PUBLICATION_ORIGIN, UPDATER_DOWNLOAD_REPOSITORY } from "../../scripts/publication-origins.mjs";

import {
  resolveAppUpdaterRuntime,
  validateAppUpdateManifest,
  type AppUpdaterRuntime,
} from "../../src/services/appUpdaterManifest.ts";

const VERSION = "0.3.0";
const SIGNATURE = "A".repeat(96);

const payload = (name: string, signature = SIGNATURE) => ({
  signature,
  url: `https://github.com/${UPDATER_DOWNLOAD_REPOSITORY}/releases/download/v${VERSION}/${name}`,
});

const windowsPayloads = () => {
  const entry = payload(`ai-security-scanner_${VERSION}_x64-setup.exe`);
  return {
    "windows-x86_64": entry,
    "windows-x86_64-nsis": { ...entry },
  };
};

const linuxPayloads = () => {
  const entry = payload(`ai-security-scanner_${VERSION}_amd64.AppImage`);
  return {
    "linux-x86_64": entry,
    "linux-x86_64-appimage": { ...entry },
  };
};

const macPayloads = () => {
  const entry = payload(`ai-security-scanner_${VERSION}_universal.app.tar.gz`);
  return {
    "darwin-x86_64": entry,
    "darwin-x86_64-app": { ...entry },
    "darwin-aarch64": { ...entry },
    "darwin-aarch64-app": { ...entry },
  };
};

const candidate = (platforms: Record<string, unknown>, version = VERSION) => ({
  version,
  rawJson: { version, platforms },
});

const validates = (platforms: Record<string, unknown>, runtime: AppUpdaterRuntime): void => {
  assert.doesNotThrow(() => validateAppUpdateManifest(candidate(platforms), runtime));
};

test("Windows accepts current and legacy signed payloads without Linux or macOS", () => {
  validates(windowsPayloads(), resolveAppUpdaterRuntime("windows", "x86_64"));
  const current = windowsPayloads();
  for (const entry of Object.values(current)) {
    entry.url = entry.url.replace(UPDATER_DOWNLOAD_REPOSITORY, CURRENT_PUBLICATION_ORIGIN.repository);
  }
  validates(current, resolveAppUpdaterRuntime("windows", "x86_64"));
  const mixed = windowsPayloads();
  mixed["windows-x86_64-nsis"].url = mixed["windows-x86_64-nsis"].url.replace(
    UPDATER_DOWNLOAD_REPOSITORY, CURRENT_PUBLICATION_ORIGIN.repository,
  );
  assert.throws(() => validateAppUpdateManifest(candidate(mixed), resolveAppUpdaterRuntime("windows", "x86_64")), /same signed payload/u);
});

test("Linux and each macOS architecture validate only the payloads that runtime can select", () => {
  validates(linuxPayloads(), resolveAppUpdaterRuntime("linux", "x86_64"));
  validates(macPayloads(), resolveAppUpdaterRuntime("macos", "x86_64"));
  validates(macPayloads(), resolveAppUpdaterRuntime("darwin", "aarch64"));
  validates(macPayloads(), resolveAppUpdaterRuntime("macos", "universal"));

  const armOnly = macPayloads();
  delete (armOnly as Partial<typeof armOnly>)["darwin-x86_64"];
  delete (armOnly as Partial<typeof armOnly>)["darwin-x86_64-app"];
  validates(armOnly, resolveAppUpdaterRuntime("macos", "aarch64"));
});

test("an unrelated platform entry cannot block a valid current-platform update", () => {
  validates({
    ...windowsPayloads(),
    "linux-x86_64": { signature: "bad", url: "http://untrusted.invalid/update" },
  }, resolveAppUpdaterRuntime("windows", "x86_64"));
});

test("updater downloads accept only the two known owner/repository pairs", () => {
  for (const repository of [
    "unknown/ai-security-scanner",
    "teddashh/other-repository",
    "TED-H-com/other-repository",
  ]) {
    const platforms = windowsPayloads();
    for (const entry of Object.values(platforms)) {
      entry.url = entry.url.replace(UPDATER_DOWNLOAD_REPOSITORY, repository);
    }
    assert.throws(
      () => validateAppUpdateManifest(candidate(platforms), resolveAppUpdaterRuntime("windows", "x86_64")),
      /untrusted download location/u,
    );
  }
});

test("a required current-platform entry or fallback must be present and bind identical bytes", () => {
  const missingFallback = windowsPayloads();
  delete (missingFallback as Partial<typeof missingFallback>)["windows-x86_64-nsis"];
  assert.throws(
    () => validateAppUpdateManifest(
      candidate(missingFallback),
      resolveAppUpdaterRuntime("windows", "x86_64"),
    ),
    /missing the required windows-x86_64-nsis payload/u,
  );

  const mismatchedFallback = windowsPayloads();
  mismatchedFallback["windows-x86_64-nsis"] = payload(
    `ai-security-scanner_${VERSION}_different-setup.exe`,
  );
  assert.throws(
    () => validateAppUpdateManifest(
      candidate(mismatchedFallback),
      resolveAppUpdaterRuntime("windows", "x86_64"),
    ),
    /fallback does not reference the same signed payload/u,
  );
});

test("the current runtime fails closed for invalid URLs, signatures, and versions", () => {
  const badUrl = windowsPayloads();
  badUrl["windows-x86_64"] = {
    ...badUrl["windows-x86_64"],
    url: `https://example.com/ai-security-scanner_${VERSION}_x64-setup.exe`,
  };
  assert.throws(
    () => validateAppUpdateManifest(candidate(badUrl), resolveAppUpdaterRuntime("windows", "x86_64")),
    /untrusted download location/u,
  );

  const badSignature = windowsPayloads();
  badSignature["windows-x86_64"] = {
    ...badSignature["windows-x86_64"],
    signature: "not a signed payload",
  };
  assert.throws(
    () => validateAppUpdateManifest(
      candidate(badSignature),
      resolveAppUpdaterRuntime("windows", "x86_64"),
    ),
    /invalid signature/u,
  );

  assert.throws(
    () => validateAppUpdateManifest(
      { version: "latest", rawJson: { version: "latest", platforms: windowsPayloads() } },
      resolveAppUpdaterRuntime("windows", "x86_64"),
    ),
    /invalid version or platform section/u,
  );
  assert.throws(
    () => validateAppUpdateManifest(
      { version: VERSION, rawJson: { version: "0.2.1", platforms: windowsPayloads() } },
      resolveAppUpdaterRuntime("windows", "x86_64"),
    ),
    /invalid version or platform section/u,
  );
});

test("unsupported operating systems and processor architectures fail closed", () => {
  assert.throws(() => resolveAppUpdaterRuntime("freebsd", "x86_64"), /not supported/u);
  assert.throws(() => resolveAppUpdaterRuntime("windows", "aarch64"), /not supported/u);
  assert.throws(() => resolveAppUpdaterRuntime("linux", undefined), /not supported/u);
});

test("the packaged frontend exposes Tauri's platform and architecture identity", () => {
  const viteConfig = readFileSync(new URL("../../vite.config.ts", import.meta.url), "utf8");
  assert.match(viteConfig, /envPrefix:\s*\["VITE_",\s*"TAURI_ENV_"\]/u);
});

interface UpdaterHarness {
  currentVersion: string;
  update: ReturnType<typeof fakeUpdate> | null;
  checks: number;
  closes: number;
  downloads: number;
  relaunches: number;
}

declare global {
  // eslint-disable-next-line no-var
  var __APP_UPDATER_TEST__: UpdaterHarness;
}

const fakeUpdate = (platforms: Record<string, unknown>) => ({
  currentVersion: "0.1.8",
  version: VERSION,
  rawJson: candidate(platforms).rawJson,
  close: async () => {
    globalThis.__APP_UPDATER_TEST__.closes += 1;
  },
  downloadAndInstall: async () => {
    globalThis.__APP_UPDATER_TEST__.downloads += 1;
  },
});

const bundledUpdater = await build({
  stdin: {
    contents: 'export { checkForAppUpdate, installAppUpdate } from "./src/services/appUpdater.ts";',
    loader: "ts",
    resolveDir: process.cwd(),
    sourcefile: "app-updater-manifest-test-entry.ts",
  },
  bundle: true,
  define: {
    "import.meta.env.TAURI_ENV_ARCH": JSON.stringify("x86_64"),
    "import.meta.env.TAURI_ENV_PLATFORM": JSON.stringify("windows"),
  },
  format: "esm",
  platform: "node",
  plugins: [{
    name: "app-updater-test-doubles",
    setup(context) {
      context.onResolve({ filter: /^@tauri-apps\/api\/app$/ }, () => ({
        namespace: "updater-test-double",
        path: "app",
      }));
      context.onResolve({ filter: /^@tauri-apps\/plugin-process$/ }, () => ({
        namespace: "updater-test-double",
        path: "process",
      }));
      context.onResolve({ filter: /^@tauri-apps\/plugin-updater$/ }, () => ({
        namespace: "updater-test-double",
        path: "updater",
      }));
      context.onLoad({ filter: /.*/, namespace: "updater-test-double" }, ({ path }) => {
        if (path === "app") {
          return { contents: "export const getVersion = async () => globalThis.__APP_UPDATER_TEST__.currentVersion;" };
        }
        if (path === "process") {
          return { contents: "export const relaunch = async () => { globalThis.__APP_UPDATER_TEST__.relaunches += 1; };" };
        }
        return {
          contents: `export const check = async () => {
            globalThis.__APP_UPDATER_TEST__.checks += 1;
            return globalThis.__APP_UPDATER_TEST__.update;
          };
          export class Update {}`,
        };
      });
    },
  }],
  target: "node22",
  write: false,
});
const updaterSource = bundledUpdater.outputFiles[0]?.text;
assert.ok(updaterSource, "app updater test bundle should contain JavaScript");
const updater = await import(
  `data:text/javascript;base64,${Buffer.from(updaterSource).toString("base64")}`
) as Pick<typeof import("../../src/services/appUpdater.ts"), "checkForAppUpdate" | "installAppUpdate">;

const setHarness = (platforms: Record<string, unknown>): UpdaterHarness => {
  const harness: UpdaterHarness = {
    currentVersion: "0.1.8",
    update: null,
    checks: 0,
    closes: 0,
    downloads: 0,
    relaunches: 0,
  };
  globalThis.__APP_UPDATER_TEST__ = harness;
  harness.update = fakeUpdate(platforms);
  return harness;
};

test("an invalid offered update stays an error state and never replaces the installed app", async () => {
  const invalid = windowsPayloads();
  delete (invalid as Partial<typeof invalid>)["windows-x86_64-nsis"];
  const harness = setHarness(invalid);

  const state = await updater.checkForAppUpdate();

  assert.equal(state.phase, "error");
  assert.equal(state.currentVersion, "0.1.8");
  assert.equal(harness.downloads, 0);
  assert.equal(harness.relaunches, 0);
  assert.equal(harness.closes, 1);

  await assert.rejects(
    () => updater.installAppUpdate(VERSION, () => undefined),
    /missing the required windows-x86_64-nsis payload/u,
  );
  assert.equal(harness.downloads, 0);
  assert.equal(harness.relaunches, 0);
});

test("the packaged Windows updater offers a valid Windows-only manifest", async () => {
  const harness = setHarness(windowsPayloads());

  const state = await updater.checkForAppUpdate();

  assert.equal(state.phase, "available");
  assert.equal(state.currentVersion, "0.1.8");
  assert.equal(state.availableVersion, VERSION);
  assert.equal(harness.checks, 1);
  assert.equal(harness.downloads, 0);
  assert.equal(harness.relaunches, 0);
});
