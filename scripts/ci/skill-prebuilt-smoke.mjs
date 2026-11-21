#!/usr/bin/env node

// Exercise the public download path, without building or starting a scanner.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { delimiter, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { collectInputManifest } from '../skill/input-manifest.mjs';
import { PREBUILT_CORES } from '../skill/prebuilt-cores.mjs';
import { RECOGNIZED_MANAGED_RUNTIME_BUNDLES } from '../skill/managed-runtime-bundles.mjs';
import { downloadReleaseBundle, extractReleaseBundle, verifyReleaseBundle } from '../skill/release-bundle.mjs';

assert.equal(process.argv.length, 2, 'Usage: node scripts/ci/skill-prebuilt-smoke.mjs');
const root = fileURLToPath(new URL('../../', import.meta.url));
const scratch = realpathSync(mkdtempSync(join(tmpdir(), 'scanner-prebuilt-')));
const summary = {
  schema_version: 'ai-security-scanner.prebuilt-native-smoke/v1',
  platform: process.platform, arch: process.arch, success: false,
  fixture_only: true, target_contact: false, runtime_started: false, scanner_execution: false,
};
let phase = 'setup';
try {
  const gitName = process.platform === 'win32' ? 'git.exe' : 'git';
  const git = (process.env.PATH ?? process.env.Path ?? '').split(delimiter)
    .map(directory => join(directory, gitName)).find(file => existsSync(file));
  assert.ok(git, 'Git must be installed');
  const path = join(scratch, 'path');
  mkdirSync(path, { mode: 0o700 });
  // Windows Git needs its adjacent support files; use only its command folder.
  // Unix links keep /usr/bin (and its compilers) off the child PATH.
  const environment = { ...process.env };
  for (const key of Object.keys(environment)) if (key.toLowerCase() === 'path') delete environment[key];
  if (process.platform === 'win32') {
    environment.PATH = [dirname(process.execPath), dirname(git)].join(delimiter);
  } else {
    symlinkSync(process.execPath, join(path, 'node'));
    symlinkSync(realpathSync(git), join(path, 'git'));
    environment.PATH = path;
  }
  for (const command of ['cargo', 'rustc', 'rustup', 'cc', 'gcc', 'clang', 'cl', 'link', 'docker', 'podman']) {
    const result = spawnSync(command, ['--version'], { env: environment, timeout: 10_000, encoding: 'utf8' });
    assert.equal(result.error?.code, 'ENOENT', `${command} must be absent from the restricted PATH`);
  }
  summary.toolchain_on_path = false;
  summary.compatibility_runtime_on_path = false;
  function invoke(program, parameters) {
    const result = spawnSync(program, parameters, {
      cwd: root, env: environment, encoding: 'utf8', stdio: ['ignore', 'pipe', 'inherit'],
      timeout: 5 * 60 * 1000, maxBuffer: 4 * 1024 * 1024,
    });
    if (result.error) throw result.error;
    assert.equal(result.status, 0, `${phase}: command failed (${result.signal ?? result.status})`);
    return result.stdout.trim();
  }
  const revision = invoke('git', ['rev-parse', 'HEAD']);
  const manifest = await collectInputManifest(root);
  const pins = PREBUILT_CORES.filter(entry => entry.platform === process.platform
    && entry.targets[process.arch] && entry.input_sha256 === manifest.inputDigest);
  assert.equal(pins.length, 1, 'this clean source must have one matching public core pin');
  const pin = pins[0];
  Object.assign(summary, { revision, input_sha256: manifest.inputDigest, release_source: pin.release_source });
  const options = ['--revision', revision, '--cache-dir', join(scratch, 'cache')];
  const bootstrap = (command, ...tail) => JSON.parse(invoke(process.execPath,
    [join(root, 'scripts/skill/bootstrap.mjs'), command, ...options, ...tail]));
  phase = 'doctor';
  const doctor = bootstrap('doctor');
  assert.equal(doctor.ready, true);
  assert.deepEqual(doctor.core_sources, { prebuilt_release: 'downloadable', local_build: 'unavailable' });
  for (const name of ['rust_toolchain', 'native_compiler_and_linker']) {
    const check = doctor.checks.find(item => item.name === name);
    assert.equal(check.ready, false);
    assert.equal(check.required, false);
  }
  phase = 'download-core';
  const first = bootstrap('prepare');
  assert.equal(first.core_source, 'prebuilt_release');
  assert.equal(first.cache_hit, false);
  const reused = bootstrap('prepare');
  const offline = bootstrap('prepare', '--offline');
  for (const result of [reused, offline]) {
    assert.equal(result.core_source, 'prebuilt_release');
    assert.equal(result.cache_hit, true);
    assert.equal(result.cache_key, first.cache_key);
  }
  const data = join(scratch, 'synthetic-cases');
  const cli = (...args) => bootstrap('run', '--offline', '--', '--data-dir', data, '--json', ...args);
  const identity = cli('build-identity');
  assert.equal(existsSync(data), false);
  assert.equal(identity.product_version, pin.product_version);
  assert.equal(identity.bootstrap_input_sha256, pin.input_sha256);
  assert.equal(identity.bootstrap_recipe, pin.recipe);
  assert.equal(identity.target, pin.targets[process.arch]);
  assert.deepEqual(identity.features, pin.features);
  summary.identity = identity;
  summary.cache_reused = summary.offline_core_reused = true;
  phase = 'offline-report';
  const demo = cli('case', 'seed-demo');
  assert.equal(demo.is_demo, true);
  const snapshot = join(scratch, 'synthetic.snapshot.json');
  cli('report', 'snapshot', '--case-id', demo.id, '--run-id', demo.scan_runs.at(-1).id,
    '--destination', snapshot, '--acknowledge-private-context');
  rmSync(data, { recursive: true, force: true });
  assert.equal(cli('report', 'inspect', '--snapshot', snapshot).replay_available, true);
  summary.report_sha256 = {};
  for (const format of ['html', 'json']) {
    const original = join(scratch, `original.${format}`);
    const replay = join(scratch, `replay.${format}`);
    cli('report', 'retrieve', '--snapshot', snapshot, '--format', format, '--destination', original);
    cli('report', 'replay', '--snapshot', snapshot, '--format', format, '--destination', replay);
    assert.deepEqual(readFileSync(original), readFileSync(replay));
    summary.report_sha256[format] = createHash('sha256').update(readFileSync(replay)).digest('hex');
  }
  assert.equal(existsSync(data), false);
  summary.report_replay_equal = true;
  phase = 'download-runtime-bundle';
  const bundlePin = RECOGNIZED_MANAGED_RUNTIME_BUNDLES.find(entry => entry.platform === process.platform
    && entry.arch.includes(process.arch) && entry.release_source);
  assert.ok(bundlePin, 'this host must have a pinned runtime download');
  const archive = join(scratch, 'runtime-archive');
  const bundle = join(scratch, 'runtime-bundle');
  await downloadReleaseBundle(bundlePin.release_source, archive, { fetch: globalThis.fetch });
  mkdirSync(bundle, { mode: 0o700 });
  await extractReleaseBundle(archive, bundlePin.release_source.kind, bundlePin.release_source.inner_path, bundle);
  await verifyReleaseBundle(bundle, bundlePin.manifest_sha256);
  summary.runtime_bundle = { source: bundlePin.release_source, manifest_sha256: bundlePin.manifest_sha256, verified: true };
  summary.success = true;
} catch (error) {
  summary.failure = { phase, message: error.message };
  throw error;
} finally {
  rmSync(scratch, { recursive: true, force: true });
  summary.scratch_removed = !existsSync(scratch);
  const serialized = `${JSON.stringify(summary, null, 2)}\n`;
  if (process.env.SKILL_PREBUILT_RESULT) writeFileSync(process.env.SKILL_PREBUILT_RESULT, serialized);
  process.stdout.write(serialized);
}
