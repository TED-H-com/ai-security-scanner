import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, dirname, join } from 'node:path';
import { BootstrapError, RECIPE } from '../../scripts/skill/bootstrap-core.mjs';

export const digest = value => createHash('sha256').update(value).digest('hex');
export const revision = 'a'.repeat(40);
export const toolchain = {
  version: '1.98.0', rustc_version: 'rustc 1.98.0 (fixture)\nhost: fixture-native\nrelease: 1.98.0',
  cargo_version: 'cargo 1.98.0 (fixture)', target: 'fixture-native',
  compiler: { path: '/fixture/cc', sha256: 'b'.repeat(64), version: 'fixture compiler' },
};

export async function fixture(t) {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'scanner-bootstrap-test-')));
  t.after(() => rm(root, { recursive: true, force: true }));
  const source = join(root, 'source');
  await mkdir(join(source, 'scripts', 'skill'), { recursive: true });
  for (const name of ['bootstrap.mjs', 'bootstrap-core.mjs', 'input-manifest.mjs', 'managed-runtime-bundles.mjs', 'prebuilt-cores.mjs', 'release-bundle.mjs']) {
    await writeFile(join(source, 'scripts', 'skill', name), `// ${name} trusted fixture recipe\n`);
  }
  await writeFile(join(source, 'Cargo.lock'), 'version = 4\n');
  await writeFile(join(source, 'core.rs'), 'fn main() {}\n');
  const options = { revision, cacheDir: join(root, 'cache'), profile: 'dev', capability: 'core' };
  const state = { builds: 0, identities: 0, revision, dirty: false, fail: false, buildHook: undefined };
  async function collectInputManifest() {
    const files = await Promise.all(['Cargo.lock', 'core.rs'].map(async path => {
      const bytes = await readFile(join(source, path));
      return { path, size: bytes.length, sha256: digest(bytes) };
    }));
    return { schemaVersion: 'fixture/v1', inputDigest: digest(JSON.stringify(files)), files, metadataFiles: [] };
  }
  const deps = {
    sourceRoot: source,
    platform: process.platform,
    environment: { PATH: process.env.PATH, HOME: join(root, 'home'), ...(process.platform === 'win32' ? { SystemRoot: process.env.SystemRoot } : {}) },
    inspectSource: async (_path, requested) => {
      if (requested !== state.revision) throw new BootstrapError('revision_mismatch', 'The pinned source does not match.', 2);
      return { revision: state.revision, dirty: state.dirty, status_sha256: digest(state.dirty ? 'M core.rs' : '') };
    },
    inspectToolchain: async () => toolchain,
    validatePinnedInputs: async () => false,
    collectInputManifest,
    stageInputSnapshot: async (_source, destination, manifest) => {
      for (const file of manifest.files) await writeFile(join(destination, file.path), await readFile(join(source, file.path)));
    },
    build: async ({ targetDirectory, manifest, configuration, offline }) => {
      assert.match(basename(dirname(targetDirectory)), /^[a-f0-9]{12}$/);
      state.builds += 1;
      state.offline = offline;
      if (state.buildHook) await state.buildHook();
      if (state.fail) throw new BootstrapError('build_failed', 'Fixture build failed.');
      const output = join(targetDirectory, toolchain.target, configuration.profile === 'release' ? 'release' : 'debug');
      await mkdir(output, { recursive: true });
      const identity = {
        schema_version: 'ai-security-scanner.build-identity/v1', product: 'ai-security-scanner', product_version: 'fixture',
        target: toolchain.target, rustc_version: toolchain.rustc_version, features: configuration.features,
        bootstrap_input_sha256: manifest.inputDigest, bootstrap_recipe: RECIPE, report_source_sha256: 'd'.repeat(64),
      };
      const bytes = `#!/usr/bin/env node\n// IDENTITY ${JSON.stringify(identity)}\n${state.runtimeScript ?? 'process.exit(Number(process.argv.at(-1) ?? 0));'}\n`;
      await writeFile(join(output, `ai-security-scanner-cli${process.platform === 'win32' ? '.exe' : ''}`), bytes, { mode: 0o700 });
    },
    readIdentity: async executable => {
      state.identities += 1;
      const bytes = await readFile(executable, 'utf8');
      return JSON.parse(bytes.split('\n').find(line => line.startsWith('// IDENTITY ')).slice('// IDENTITY '.length));
    },
  };
  return { root, source, options, deps, state };
}
