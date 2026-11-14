import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { execFileSync, spawn } from 'node:child_process';
import { chmod, link, lstat, mkdir, mkdtemp, readFile, readdir, realpath, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, dirname, join } from 'node:path';
import test from 'node:test';
import * as bootstrapCore from '../../scripts/skill/bootstrap-core.mjs';
import * as bootstrapEntry from '../../scripts/skill/bootstrap.mjs';
import {
  BootstrapError, RECIPE, controlledBuildEnvironment, doctorBootstrap,
  parseBootstrapArguments, prepareBootstrap, runPrepared,
  validateRunArguments,
  assertWindowsAclSnapshot, auditWindowsCachePaths,
  invokeRuntimePreparation, runtimePreparationArguments,
} from '../../scripts/skill/bootstrap-core.mjs';

const digest = value => createHash('sha256').update(value).digest('hex');
const revision = 'a'.repeat(40);
const toolchain = {
  version: '1.98.0', rustc_version: 'rustc 1.98.0 (fixture)\nhost: fixture-native\nrelease: 1.98.0',
  cargo_version: 'cargo 1.98.0 (fixture)', target: 'fixture-native',
  compiler: { path: '/fixture/cc', sha256: 'b'.repeat(64), version: 'fixture compiler' },
};

async function fixture(t) {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'scanner-bootstrap-test-')));
  t.after(() => rm(root, { recursive: true, force: true }));
  const source = join(root, 'source');
  await mkdir(join(source, 'scripts', 'skill'), { recursive: true });
  for (const name of ['bootstrap.mjs', 'bootstrap-core.mjs', 'input-manifest.mjs', 'managed-runtime-bundles.mjs']) {
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

test('bootstrap parser requires exact revision and separates core argv without interpreting it', () => {
  const options = parseBootstrapArguments(['run', '--revision', revision, '--cache-dir', '/cache', '--offline', '--profile', 'dev', '--', '--json', 'scan', 'status', '--case-id', '$(touch nope)']);
  assert.deepEqual(options.cliArguments, ['--json', 'scan', 'status', '--case-id', '$(touch nope)']);
  assert.equal(options.offline, true);
  assert.throws(() => parseBootstrapArguments(['prepare', '--revision', 'main', '--cache-dir', '/cache']), { code: 'invalid_revision', exitCode: 2 });
  assert.throws(() => parseBootstrapArguments(['prepare', '--revision', revision, '--cache-dir', '/cache', '--recipe', 'target-script']), { code: 'invalid_arguments' });
  assert.throws(() => parseBootstrapArguments(['prepare', '--revision', revision, '--cache-dir', '/cache', '--profile', 'dev', '--profile', 'release']), { code: 'invalid_arguments' });
  assert.throws(() => parseBootstrapArguments(['prepare', '--revision', revision, '--cache-dir', '/cache', '--', '--help']), { code: 'invalid_arguments' });
});

test('controlled build environment removes Cargo, Rust, native compiler and arbitrary overrides', () => {
  const env = controlledBuildEnvironment({ PATH: '/bin', CARGO_HOME: '/pinned/cargo', RUSTUP_HOME: '/pinned/rustup', HOME: '/home', RUSTFLAGS: '--cfg malicious', CARGO_ENCODED_RUSTFLAGS: 'bad', RUSTC_WRAPPER: '/evil', CC: '/evil', CFLAGS: 'evil', RUSTUP_TOOLCHAIN: 'nightly', TARGET: 'other', SECRET: 'never-build', AI_SECURITY_SCANNER_BOOTSTRAP_RECIPE: 'bad' });
  assert.deepEqual(env, { PATH: '/bin', CARGO_HOME: '/pinned/cargo', RUSTUP_HOME: '/pinned/rustup', HOME: '/home', RUSTUP_TOOLCHAIN: '1.98.0', RUSTUP_AUTO_INSTALL: '0', CARGO_TERM_COLOR: 'never', CARGO_INCREMENTAL: '0' });
});

test('cache publishes verified receipt and reuses core across prompt-only revisions', async t => {
  const f = await fixture(t);
  const first = await prepareBootstrap({ ...f.options, offline: true }, f.deps);
  assert.equal(first.cache_hit, false);
  assert.equal(f.state.builds, 1);
  assert.equal(f.state.offline, true);
  assert.equal(first.receipt.source.revision, revision);
  assert.equal(first.receipt.runtime.prepared, false);
  assert.equal(first.receipt.artifacts[0].sha256, digest(await readFile(first.executable)));
  await writeFile(join(f.source, 'SKILL.md'), 'A prompt-only update.\n');
  f.state.revision = 'b'.repeat(40);
  const second = await prepareBootstrap({ ...f.options, revision: f.state.revision }, f.deps);
  assert.equal(second.cache_hit, true);
  assert.equal(second.cache_key, first.cache_key);
  assert.equal(second.receipt.source.revision, revision);
  assert.equal(second.requested_source.revision, f.state.revision);
  assert.equal(f.state.builds, 1);
  assert.deepEqual(await readdir(join(f.options.cacheDir, 'locks')), []);
  assert.deepEqual(await readdir(join(f.options.cacheDir, 'staging')), []);
});

test('core source, lockfile, native toolchain, profile, and recipe each invalidate the cache', async t => {
  const f = await fixture(t);
  const keys = [(await prepareBootstrap(f.options, f.deps)).cache_key];
  await writeFile(join(f.source, 'core.rs'), 'fn main() { changed(); }\n');
  keys.push((await prepareBootstrap(f.options, f.deps)).cache_key);
  await writeFile(join(f.source, 'Cargo.lock'), 'version = 4\n# changed\n');
  keys.push((await prepareBootstrap(f.options, f.deps)).cache_key);
  const changedTools = { ...f.deps, inspectToolchain: async () => ({ ...toolchain, compiler: { ...toolchain.compiler, version: 'new native compiler' } }) };
  keys.push((await prepareBootstrap(f.options, changedTools)).cache_key);
  keys.push((await prepareBootstrap({ ...f.options, profile: 'release' }, changedTools)).cache_key);
  await writeFile(join(f.source, 'scripts', 'skill', 'bootstrap-core.mjs'), '// changed trusted recipe\n');
  keys.push((await prepareBootstrap({ ...f.options, profile: 'release' }, changedTools)).cache_key);
  await writeFile(join(f.source, 'scripts', 'skill', 'managed-runtime-bundles.mjs'), '// changed trusted runtime list\n');
  keys.push((await prepareBootstrap({ ...f.options, profile: 'release' }, changedTools)).cache_key);
  assert.equal(new Set(keys).size, 7);
  assert.equal(f.state.builds, 7);
});

test('cached artifact corruption fails before executing identity or rebuilding', async t => {
  const f = await fixture(t);
  const first = await prepareBootstrap(f.options, f.deps);
  const identities = f.state.identities;
  await writeFile(first.executable, 'tampered');
  await assert.rejects(prepareBootstrap(f.options, f.deps), { code: 'artifact_digest_mismatch' });
  assert.equal(f.state.identities, identities);
  assert.equal(f.state.builds, 1);
});

test('receipt corruption and incompatible executable identity fail closed', async t => {
  const f = await fixture(t);
  const first = await prepareBootstrap(f.options, f.deps);
  const receipt = JSON.parse(await readFile(first.receipt_path, 'utf8'));
  receipt.build_outcome = 'failed';
  await writeFile(first.receipt_path, JSON.stringify(receipt));
  await assert.rejects(prepareBootstrap(f.options, f.deps), { code: 'cache_receipt_mismatch' });
  const other = await fixture(t);
  await assert.rejects(prepareBootstrap(other.options, { ...other.deps, readIdentity: async () => ({ schema_version: 'old' }) }), { code: 'artifact_identity_mismatch' });
  assert.deepEqual(await readdir(join(other.options.cacheDir, 'entries')), []);
});

test('failed replacement build preserves prior ready pointer and artifacts', async t => {
  const f = await fixture(t);
  const first = await prepareBootstrap(f.options, f.deps);
  const readyPath = join(f.options.cacheDir, 'ready', 'core-dev-fixture-native.json');
  const before = await readFile(readyPath);
  await writeFile(join(f.source, 'core.rs'), 'changed source\n');
  f.state.fail = true;
  await assert.rejects(prepareBootstrap(f.options, f.deps), { code: 'build_failed' });
  assert.deepEqual(await readFile(readyPath), before);
  assert.equal(digest(await readFile(first.executable)), first.receipt.artifacts[0].sha256);
  assert.deepEqual(await readdir(join(f.options.cacheDir, 'staging')), []);
  assert.deepEqual(await readdir(join(f.options.cacheDir, 'locks')), []);
});

test('concurrent preparation never takes over an active key lock', async t => {
  const f = await fixture(t);
  let enter;
  const entered = new Promise(resolve => { enter = resolve; });
  let finish;
  const blocked = new Promise(resolve => { finish = resolve; });
  f.state.buildHook = async () => { enter(); await blocked; };
  const first = prepareBootstrap(f.options, f.deps);
  await entered;
  await assert.rejects(prepareBootstrap(f.options, f.deps), { code: 'cache_busy', exitCode: 3 });
  finish();
  await first;
  assert.equal(f.state.builds, 1);
});

test('dirty source needs explicit development choice and is recorded', async t => {
  const f = await fixture(t);
  f.state.dirty = true;
  await assert.rejects(prepareBootstrap(f.options, f.deps), { code: 'dirty_source', exitCode: 2 });
  await assert.rejects(readFile(join(f.options.cacheDir, '.ai-security-scanner-bootstrap.json')), { code: 'ENOENT' });
  const result = await prepareBootstrap({ ...f.options, allowDirty: true }, f.deps);
  assert.equal(result.receipt.source.dirty, true);
  assert.equal(result.receipt.source.development_dirty_allowed, true);
  assert.equal(result.receipt.source.input_sha256, result.receipt.cache_identity.input_sha256);
});

test('changes during build reject publication and preserve previous ready entry', async t => {
  const f = await fixture(t);
  const first = await prepareBootstrap(f.options, f.deps);
  await writeFile(join(f.source, 'core.rs'), 'next build');
  f.state.buildHook = async () => writeFile(join(f.source, 'core.rs'), 'changed during build');
  await assert.rejects(prepareBootstrap(f.options, f.deps), { code: 'source_changed' });
  const ready = JSON.parse(await readFile(join(f.options.cacheDir, 'ready', 'core-dev-fixture-native.json'), 'utf8'));
  assert.equal(ready.cache_key, first.cache_key);
});

test('dedicated cache refuses existing user directory and insecure permissions', async t => {
  const f = await fixture(t);
  await mkdir(f.options.cacheDir, { mode: 0o700 });
  await writeFile(join(f.options.cacheDir, 'evidence.txt'), 'preserve me');
  await assert.rejects(prepareBootstrap(f.options, f.deps), { code: 'unowned_cache_directory' });
  assert.equal(await readFile(join(f.options.cacheDir, 'evidence.txt'), 'utf8'), 'preserve me');
  if (process.platform !== 'win32') {
    await chmod(f.options.cacheDir, 0o755);
    await assert.rejects(prepareBootstrap(f.options, f.deps), { code: 'unsafe_cache_permissions' });
  }
});

test('cache refuses symbolic link traversal and artifact replacement', { skip: process.platform === 'win32' ? 'Symbolic link creation requires Windows privileges' : false }, async t => {
  const f = await fixture(t);
  const outside = join(f.root, 'outside');
  await mkdir(outside, { mode: 0o700 });
  await symlink(outside, f.options.cacheDir);
  await assert.rejects(prepareBootstrap(f.options, f.deps), { code: 'unsafe_cache_path' });
  assert.deepEqual(await readdir(outside), []);
  await rm(f.options.cacheDir);
  const first = await prepareBootstrap(f.options, f.deps);
  await rm(first.executable);
  await symlink(join(f.source, 'core.rs'), first.executable);
  await assert.rejects(prepareBootstrap(f.options, f.deps), { code: 'unsafe_cache_file' });
});

test('Cargo configuration in the cache ancestry or Cargo home is refused', async t => {
  const f = await fixture(t);
  await mkdir(join(f.root, '.cargo'));
  await writeFile(join(f.root, '.cargo', 'config.toml'), '[build]\nrustc-wrapper="evil"\n');
  await assert.rejects(prepareBootstrap(f.options, f.deps), { code: 'cargo_configuration_override', message: /Temporarily rename this file.*CARGO_HOME/ });
  assert.equal(f.state.builds, 0);
  await rm(join(f.root, '.cargo'), { recursive: true });
  await mkdir(join(f.root, 'cargo'));
  await writeFile(join(f.root, 'cargo', 'config'), '[alias]\n');
  await assert.rejects(prepareBootstrap(f.options, { ...f.deps, environment: { ...f.deps.environment, CARGO_HOME: join(f.root, 'cargo') } }), { code: 'cargo_configuration_override' });
});

test('doctor is read only and does not pretend core build provisions scan runtime', async t => {
  const f = await fixture(t);
  const result = await doctorBootstrap(f.options, f.deps);
  assert.equal(result.ready, true);
  assert.equal(result.execution.scanner_runtime, 'not prepared');
  await assert.rejects(readdir(f.options.cacheDir), { code: 'ENOENT' });
  const scanOptions = { ...f.options, capability: 'scan', engineIds: ['gitleaks'], dataDir: join(f.root, 'data') };
  const unavailable = await doctorBootstrap(scanOptions, { ...f.deps, prepareRuntime: () => assert.fail('doctor must never prepare a runtime') });
  assert.equal(unavailable.ready, false);
  assert.equal(unavailable.checks.find(check => check.name === 'requested_capability').ready, false);
  await assert.rejects(prepareBootstrap({ ...scanOptions, command: 'run' }, f.deps), { code: 'invalid_arguments' });
  assert.equal(f.state.builds, 0);
});

function runtimeResult(options, overrides = {}) {
  return {
    schema_version: 'ai-security-scanner.runtime-preparation/v1', ready: true, offline: options.offline === true,
    engines: options.engineIds, runtime: { provider: 'fixture' },
    images: options.engineIds.map(id => ({ role: 'engine', engine_ids: [id], image: `fixture/${id}@sha256:${'a'.repeat(64)}`, status: 'ready', error: null })),
    receipt_path: join(options.dataDir, 'runtime-preparations', 'fixture.json'), ...overrides,
  };
}

test('scan preparation arguments require explicit selected engines and data before any build', async t => {
  const f = await fixture(t);
  const base = ['prepare', '--revision', revision, '--cache-dir', f.options.cacheDir];
  const parsed = parseBootstrapArguments([...base, '--capability', 'scan', '--engine', 'gitleaks,semgrep', '--data-dir', join(f.root, 'data'), '--offline']);
  assert.deepEqual(parsed.engineIds, ['gitleaks', 'semgrep']);
  assert.equal(parsed.offline, true);
  for (const extra of [
    ['--capability', 'scan'],
    ['--capability', 'scan', '--engine', 'gitleaks,gitleaks', '--data-dir', join(f.root, 'data')],
    ['--capability', 'scan', '--engine', 'gitleaks,', '--data-dir', join(f.root, 'data')],
    ['--capability', 'core', '--engine', 'gitleaks'],
    ['--capability', 'scan', '--engine', 'gitleaks', '--data-dir', join(f.options.cacheDir, 'data')],
  ]) assert.throws(() => parseBootstrapArguments([...base, ...extra]), error => error instanceof BootstrapError && error.exitCode === 2);
  await assert.rejects(prepareBootstrap({ ...parsed, command: 'run' }, f.deps), { code: 'invalid_arguments' });
  assert.equal(f.state.builds, 0);
  await assert.rejects(readdir(f.options.cacheDir), { code: 'ENOENT' });
});

test('selected runtime preparation reuses the exact core entry and releases its build lock', async t => {
  const f = await fixture(t);
  const core = await prepareBootstrap(f.options, f.deps);
  const options = { ...f.options, capability: 'scan', engineIds: ['gitleaks', 'semgrep'], dataDir: join(f.root, 'data'), offline: true };
  let preparations = 0;
  const prepareRuntime = async (executable, request) => {
    preparations += 1;
    assert.equal(executable, core.executable);
    assert.deepEqual(await readdir(join(f.options.cacheDir, 'locks')), []);
    assert.deepEqual(request.engineIds, options.engineIds);
    return runtimeResult(request);
  };
  const selected = await prepareBootstrap(options, { ...f.deps, prepareRuntime });
  assert.equal(selected.cache_hit, true);
  assert.equal(selected.cache_key, core.cache_key);
  assert.equal(selected.receipt.receipt_sha256, core.receipt.receipt_sha256);
  assert.equal(selected.receipt.cache_identity.capability, 'core');
  assert.equal(selected.receipt.runtime.prepared, false);
  assert.equal(selected.requested_capability, 'scan');
  assert.equal(selected.runtime_preparation.ready, true);
  assert.equal(selected.runtime_preparation.offline, true);
  assert.equal(f.state.builds, 1);
  assert.equal(preparations, 1);
  assert.equal((await prepareBootstrap(f.options, f.deps)).cache_key, core.cache_key);
});

test('runtime preparation failure preserves core readiness and the concrete child result', async t => {
  const f = await fixture(t);
  const options = { ...f.options, capability: 'scan', engineIds: ['gitleaks'], dataDir: join(f.root, 'data') };
  const failed = runtimeResult(options, { ready: false, images: [{ role: 'engine', engine_ids: ['gitleaks'], image: 'fixture', status: 'failed', error: 'Pinned image unavailable' }] });
  await assert.rejects(prepareBootstrap(options, { ...f.deps, prepareRuntime: async () => failed }), error => {
    assert.equal(error.code, 'runtime_preparation_failed');
    assert.deepEqual(error.details, failed);
    return true;
  });
  const core = await prepareBootstrap(f.options, f.deps);
  assert.equal(core.cache_hit, true);
  assert.equal(f.state.builds, 1);
  assert.equal(core.runtime_preparation, undefined);
});

test('runtime preparation constructs only the fixed Rust command and explicit source overrides', () => {
  const options = { engineIds: ['gitleaks', 'semgrep'], dataDir: 'selected-data', managedRuntimeBundle: 'selected-bundle', localImageDirectory: 'selected-images', offline: true };
  const args = runtimePreparationArguments(options);
  assert.deepEqual(args.slice(0, 2), ['--json', '--data-dir']);
  assert.deepEqual(args.slice(-6), ['runtime', 'prepare', '--engine', 'gitleaks,semgrep', '--bootstrap-control-stdin', '--offline']);
  assert.equal(args[3], '--managed-runtime-bundle');
  assert.equal(args[5], '--release-approved-local-image-directory');
});

async function runtimeChild(t, script) {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'scanner-runtime-child-')));
  t.after(() => rm(root, { recursive: true, force: true }));
  const executable = join(root, 'fixture-core');
  await writeFile(executable, `#!${process.execPath}\n${script}\n`, { mode: 0o700 });
  return { root, executable, options: { capability: 'scan', engineIds: ['gitleaks'], dataDir: join(root, 'data'), offline: true } };
}

test('runtime child keeps fixed argv literal and removes ambient product source overrides', async t => {
  const f = await runtimeChild(t, `process.stdout.write(JSON.stringify({schema_version:'ai-security-scanner.runtime-preparation/v1',ready:true,offline:true,engines:['gitleaks'],runtime:{args:process.argv.slice(2),ambient:Object.keys(process.env).filter(key=>['AI_SECURITY_SCANNER_DATA_DIR','AI_SECURITY_SCANNER_MANAGED_RUNTIME_BUNDLE','AI_SECURITY_SCANNER_RELEASE_APPROVED_LOCAL_IMAGE_DIRECTORY'].includes(key.toUpperCase()))},images:[{role:'engine',engine_ids:['gitleaks'],image:'fixture@sha256:${'a'.repeat(64)}',status:'ready',error:null}],receipt_path:'fixture-receipt'}));`);
  const result = await invokeRuntimePreparation(process.execPath, f.options, { argvPrefix: [f.executable], environment: {
    ...process.env,
    AI_SECURITY_SCANNER_MANAGED_RUNTIME_BUNDLE: '/ambient/unselected',
    ai_security_scanner_managed_runtime_bundle: '/ambient/lowercase-bundle',
    Ai_Security_Scanner_Data_Dir: '/ambient/mixed-case-data',
    ai_SECURITY_scanner_RELEASE_APPROVED_local_IMAGE_directory: '/ambient/mixed-case-images',
  } });
  assert.deepEqual(result.runtime.args, runtimePreparationArguments(f.options));
  assert.deepEqual(result.runtime.ambient, []);
});

test('runtime child preserves failed receipts and refuses successful malformed or mismatched JSON', async t => {
  const f = await runtimeChild(t, `process.stdout.write(JSON.stringify({schema_version:'ai-security-scanner.runtime-preparation/v1',ready:false,offline:true,engines:['gitleaks'],runtime:null,images:[{status:'failed',error:'Unavailable'}],receipt_path:'preserved-receipt'}));process.exitCode=3;`);
  await assert.rejects(invokeRuntimePreparation(process.execPath, f.options, { argvPrefix: [f.executable] }), error => {
    assert.equal(error.exitCode, 3);
    assert.equal(error.details.receipt_path, 'preserved-receipt');
    assert.equal(error.details.ready, false);
    return true;
  });
  await writeFile(f.executable, `#!${process.execPath}\nprocess.stdout.write('not JSON');\n`, { mode: 0o700 });
  await assert.rejects(invokeRuntimePreparation(process.execPath, f.options, { argvPrefix: [f.executable] }), { code: 'invalid_runtime_preparation_result' });
  await writeFile(f.executable, `#!${process.execPath}\nprocess.stdout.write(JSON.stringify(${JSON.stringify(runtimeResult(f.options, { engines: ['semgrep'] }))}));\n`, { mode: 0o700 });
  await assert.rejects(invokeRuntimePreparation(process.execPath, f.options, { argvPrefix: [f.executable] }), { code: 'invalid_runtime_preparation_result' });
});

test('runtime preparation cancellation waits for the child owner to settle before returning', async t => {
  const f = await runtimeChild(t, `import fs from 'node:fs';process.stdin.on('data',bytes=>{if(bytes.toString()!=='terminate\\n')process.exit(2);setTimeout(()=>{fs.writeFileSync(process.env.SETTLED,'done');process.stdout.write(JSON.stringify({schema_version:'ai-security-scanner.runtime-preparation/v1',ready:false,offline:true,engines:['gitleaks'],runtime:null,images:[],receipt_path:'cancelled-receipt'}));process.exit(143);},80)});`);
  const settled = join(f.root, 'settled');
  const listeners = process.listenerCount('SIGTERM');
  await assert.rejects(invokeRuntimePreparation(process.execPath, f.options, { argvPrefix: [f.executable], environment: { ...process.env, SETTLED: settled }, timeoutMs: 50 }), error => {
    assert.equal(error.code, 'runtime_preparation_deadline');
    assert.equal(error.exitCode, 4);
    assert.equal(error.details.receipt_path, 'cancelled-receipt');
    return true;
  });
  assert.equal(await readFile(settled, 'utf8'), 'done');
  assert.equal(process.listenerCount('SIGTERM'), listeners);
});

test('runtime output limit cancels and joins the owner without retaining unbounded JSON', async t => {
  const f = await runtimeChild(t, `import fs from 'node:fs';process.stdin.on('data',bytes=>{if(bytes.toString()!=='terminate\\n')process.exit(2);setTimeout(()=>{fs.writeFileSync(process.env.SETTLED,'done');process.exit(143)},40)});process.stdout.write('x'.repeat(2*1024*1024));`);
  const settled = join(f.root, 'settled');
  await assert.rejects(invokeRuntimePreparation(process.execPath, f.options, { argvPrefix: [f.executable], environment: { ...process.env, SETTLED: settled } }), { code: 'runtime_preparation_output_limit' });
  assert.equal(await readFile(settled, 'utf8'), 'done');
});

test('SIGINT reaches the runtime owner through its control pipe and preserves its cancelled receipt', async t => {
  const f = await runtimeChild(t, `import fs from 'node:fs';process.stdin.on('data',bytes=>{if(bytes.toString()!=='cancel\\n')process.exit(2);setTimeout(()=>{fs.writeFileSync(process.env.SETTLED,'done');process.stdout.write(JSON.stringify({schema_version:'ai-security-scanner.runtime-preparation/v1',ready:false,offline:true,engines:['gitleaks'],runtime:null,images:[],receipt_path:'interrupted-receipt'}));process.exit(130)},40)});fs.writeFileSync(process.env.READY,'ready');`);
  const ready = join(f.root, 'ready');
  const settled = join(f.root, 'settled');
  const before = process.listenerCount('SIGINT');
  const completion = invokeRuntimePreparation(process.execPath, f.options, { argvPrefix: [f.executable], environment: { ...process.env, READY: ready, SETTLED: settled }, timeoutMs: 5000 }).then(
    () => assert.fail('interruption must not report ready'), error => error,
  );
  let announced = false;
  for (let attempt = 0; attempt < 100; attempt += 1) {
    if (await readFile(ready).then(() => true, () => false)) { announced = true; break; }
    await new Promise(resolve => setTimeout(resolve, 10));
  }
  assert.equal(announced, true);
  process.emit('SIGINT');
  const error = await completion;
  assert.equal(error.code, 'interrupted');
  assert.equal(error.exitCode, 130);
  assert.equal(error.details.receipt_path, 'interrupted-receipt');
  assert.equal(await readFile(settled, 'utf8'), 'done');
  assert.equal(process.listenerCount('SIGINT'), before);
});

test('ready runtime results must cover exactly the selected engines with pinned ready images', async t => {
  const f = await fixture(t);
  const options = { ...f.options, capability: 'scan', engineIds: ['gitleaks'], dataDir: join(f.root, 'data') };
  for (const value of [
    runtimeResult(options, { images: [] }),
    runtimeResult(options, { runtime: null }),
    runtimeResult(options, { receipt_path: null }),
    runtimeResult(options, { images: [{ role: 'engine', engine_ids: ['semgrep'], image: `fixture@sha256:${'a'.repeat(64)}`, status: 'ready' }] }),
    runtimeResult(options, { images: [{ role: 'engine', engine_ids: ['gitleaks'], image: 'fixture:latest', status: 'ready' }] }),
  ]) {
    await assert.rejects(prepareBootstrap(options, { ...f.deps, prepareRuntime: async () => value }), { code: 'invalid_runtime_preparation_result' });
  }
  assert.equal(f.state.builds, 1);
});

test('run rechecks artifacts and propagates child exit without shell evaluation', async t => {
  const f = await fixture(t);
  const result = await prepareBootstrap(f.options, f.deps);
  assert.equal(await runPrepared(result, ['--data-dir', join(f.root, 'data'), '17'], { ...f.deps, commandExecutable: process.execPath, argvPrefix: [result.executable] }), 17);
  await writeFile(result.executable, 'corrupted between prepare and run');
  await assert.rejects(runPrepared(result, ['build-identity'], f.deps), { code: 'artifact_digest_mismatch' });
});

test('run requires an explicit data namespace before ordinary commands', () => {
  for (const args of [['build-identity'], ['--json', 'build-identity'], ['--help'], ['--version'], ['--data-dir', '/selected/data', 'scan', 'status'], ['--json', '--data-dir=/selected/data', 'case', 'list']]) {
    assert.doesNotThrow(() => validateRunArguments(args));
  }
  for (const args of [[], ['case', 'list'], ['scan', 'status', '--case-id', 'build-identity'], ['report', 'inspect', '--snapshot', '--data-dir=/fake'], ['scan', 'run', '--data-dir', '/late']]) {
    assert.throws(() => validateRunArguments(args), { code: 'explicit_data_directory_required', exitCode: 2 });
  }
});

test('unsafe writable ancestors and caches inside source are refused before creating entries', { skip: process.platform === 'win32' ? 'POSIX permission modes are required' : false }, async t => {
  const f = await fixture(t);
  const writable = join(f.root, 'writable');
  await mkdir(writable);
  await chmod(writable, 0o777);
  await assert.rejects(prepareBootstrap({ ...f.options, cacheDir: join(writable, 'cache') }, f.deps), { code: 'unsafe_cache_ancestor' });
  const inside = { ...f.options, cacheDir: join(f.source, 'cache') };
  assert.equal((await doctorBootstrap(inside, f.deps)).ready, false);
  await assert.rejects(prepareBootstrap(inside, f.deps), { code: 'unsafe_cache_path' });
  await assert.rejects(readdir(inside.cacheDir), { code: 'ENOENT' });
});

test('clean pin compares raw Git blobs even when assume-unchanged hides source edits', async t => {
  const f = await fixture(t);
  const git = args => execFileSync('git', ['-C', f.source, ...args], { encoding: 'utf8' }).trim();
  git(['init', '-q']);
  git(['config', 'core.autocrlf', 'false']);
  git(['add', '.']);
  git(['-c', 'user.name=Bootstrap Fixture', '-c', 'user.email=fixture@example.invalid', '-c', 'commit.gpgsign=false', '-c', 'core.hooksPath=/dev/null', 'commit', '-qm', 'Pinned source']);
  const pinned = git(['rev-parse', 'HEAD']);
  const realSourceInspection = { ...f.deps };
  delete realSourceInspection.inspectSource;
  delete realSourceInspection.validatePinnedInputs;
  await prepareBootstrap({ ...f.options, revision: pinned }, realSourceInspection);
  git(['update-index', '--assume-unchanged', 'scripts/skill/managed-runtime-bundles.mjs']);
  await writeFile(join(f.source, 'scripts', 'skill', 'managed-runtime-bundles.mjs'), '// hidden runtime list change\n');
  assert.equal(git(['status', '--porcelain=v1']), '');
  await assert.rejects(prepareBootstrap({ ...f.options, revision: pinned }, realSourceInspection), { code: 'dirty_source' });
  await writeFile(join(f.source, 'scripts', 'skill', 'managed-runtime-bundles.mjs'), '// managed-runtime-bundles.mjs trusted fixture recipe\n');
  git(['update-index', '--no-assume-unchanged', 'scripts/skill/managed-runtime-bundles.mjs']);
  git(['update-index', '--assume-unchanged', 'core.rs']);
  await writeFile(join(f.source, 'core.rs'), 'a hidden source change');
  assert.equal(git(['status', '--porcelain=v1']), '');
  await assert.rejects(prepareBootstrap({ ...f.options, revision: pinned }, realSourceInspection), { code: 'dirty_source' });
  const development = await prepareBootstrap({ ...f.options, revision: pinned, allowDirty: true }, realSourceInspection);
  assert.equal(development.receipt.source.input_dirty, true);
  assert.equal(development.receipt.source.dirty, true);
  assert.equal(f.state.builds, 2);
});

test('native SDK selection participates in core cache identity', async t => {
  const f = await fixture(t);
  const first = await prepareBootstrap(f.options, f.deps);
  const second = await prepareBootstrap(f.options, { ...f.deps, environment: { ...f.deps.environment, INCLUDE: '/different/sdk/include', LIB: '/different/sdk/lib' } });
  assert.notEqual(first.cache_key, second.cache_key);
  assert.equal(f.state.builds, 2);
});

test('recipe edits during build reject publication while unrelated prose edits do not', async t => {
  const f = await fixture(t);
  f.state.buildHook = async () => {
    await writeFile(join(f.source, 'SKILL.md'), 'New prompt text during a core build.');
    f.state.dirty = true;
  };
  const first = await prepareBootstrap(f.options, f.deps);
  assert.equal(first.cache_hit, false);
  assert.equal(first.receipt.source.dirty, false);
  await writeFile(join(f.source, 'core.rs'), 'a new core revision');
  f.state.buildHook = async () => writeFile(join(f.source, 'scripts', 'skill', 'bootstrap-core.mjs'), '// recipe changed during build');
  await assert.rejects(prepareBootstrap({ ...f.options, allowDirty: true }, f.deps), { code: 'source_changed' });
  const ready = JSON.parse(await readFile(join(f.options.cacheDir, 'ready', 'core-dev-fixture-native.json'), 'utf8'));
  assert.equal(ready.cache_key, first.cache_key);
});

test('Cargo hardlinked outputs are copied into single-link cache artifacts', async t => {
  const f = await fixture(t);
  const build = async parameters => {
    await f.deps.build(parameters);
    const binary = join(parameters.targetDirectory, toolchain.target, 'debug', `ai-security-scanner-cli${process.platform === 'win32' ? '.exe' : ''}`);
    const dependencyDirectory = join(parameters.targetDirectory, toolchain.target, 'debug', 'deps');
    await mkdir(dependencyDirectory);
    await link(binary, join(dependencyDirectory, 'ai-security-scanner-cli-hash'));
    assert.equal((await lstat(binary)).nlink, 2);
  };
  const result = await prepareBootstrap(f.options, { ...f.deps, build });
  assert.equal((await lstat(result.executable)).nlink, 1);
  assert.equal((await prepareBootstrap(f.options, { ...f.deps, build })).cache_hit, true);
  await link(result.executable, join(f.root, 'external-cache-alias'));
  await assert.rejects(prepareBootstrap(f.options, f.deps), { code: 'unsafe_cache_file' });
  assert.equal(f.state.builds, 1);
});

const aclUser = 'S-1-5-21-100-200-300-1001';
const aclOther = 'S-1-5-21-100-200-300-1002';
const aclPath = 'C:\\Users\\fixture\\scanner-cache';
function aclFixture(aces, { owner = aclUser, hasDacl = true } = {}) {
  return {
    schema_version: 'ai-security-scanner.windows-cache-acl/v1', current_user_sid: aclUser,
    records: [{ path: aclPath, kind: 'directory', owner_sid: owner, has_dacl: hasDacl, reparse_point: false, aces }],
  };
}
const allow = (sid, rights = 0x1f01ff, flags = 0) => ({ type: 'allow', sid, rights, flags });

test('Windows private cache ACL requires trusted owners and rejects foreign access even behind deny ACEs', () => {
  const request = [{ path: aclPath, kind: 'directory', access: 'private' }];
  assert.doesNotThrow(() => assertWindowsAclSnapshot(aclFixture([
    allow(aclUser), allow('S-1-5-18'), allow('S-1-5-32-544'), allow('S-1-3-0', 0x1f01ff, 11),
  ]), request));
  for (const record of [
    aclFixture([allow(aclUser), allow(aclOther, 2)]),
    aclFixture([allow(aclUser), allow('S-1-1-0', 0x120089)]),
    aclFixture([{ type: 'deny', sid: aclOther, rights: 0x1f01ff, flags: 0 }, allow(aclOther, 2)]),
    aclFixture([allow(aclUser), allow(aclOther, 2, 11)]),
    aclFixture([allow(aclUser)], { owner: aclOther }),
    aclFixture([], { hasDacl: false }),
  ]) assert.throws(() => assertWindowsAclSnapshot(record, request), { code: 'unsafe_windows_cache_acl' });
});

test('Windows ancestor ACL allows traversal and new folders but rejects replacement and permissions rights', () => {
  const request = [{ path: aclPath, kind: 'directory', access: 'ancestor' }];
  assert.doesNotThrow(() => assertWindowsAclSnapshot(aclFixture([
    allow(aclUser), allow('S-1-5-11', 0x1200ad), // read/traverse + CreateDirectories
    allow('S-1-3-0', 0x1f01ff, 11), // inheritance-only CREATOR OWNER
  ]), request));
  for (const rights of [2, 16, 64, 256, 0x10000, 0x40000, 0x80000, 0x40000000, 0x10000000]) {
    assert.throws(() => assertWindowsAclSnapshot(aclFixture([allow(aclUser), allow(aclOther, rights)]), request), { code: 'unsafe_windows_cache_acl' });
  }
});

test('Windows ACL verification fails closed for missing paths, unknown ACEs, and reparse points', () => {
  const request = [{ path: aclPath, kind: 'directory', access: 'private' }];
  assert.throws(() => assertWindowsAclSnapshot({ ...aclFixture([]), records: [] }, request), { code: 'windows_acl_unavailable' });
  assert.throws(() => assertWindowsAclSnapshot(aclFixture([{ ...allow(aclUser), type: 'unsupported' }]), request), { code: 'unsafe_windows_cache_acl' });
  const reparse = aclFixture([allow(aclUser)]);
  reparse.records[0].reparse_point = true;
  assert.throws(() => assertWindowsAclSnapshot(reparse, request), { code: 'unsafe_windows_cache_acl' });
});

test('native Windows ACL verifier accepts private directories and rejects a broad writable ACE', { skip: process.platform !== 'win32' ? 'Windows ACL verification requires Windows' : false }, async t => {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'scanner-native-acl-test-')));
  t.after(() => rm(root, { recursive: true, force: true }));
  const powershell = join(process.env.SystemRoot || process.env.SYSTEMROOT, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
  const initialize = String.raw`
$ErrorActionPreference = 'Stop'
$path = [Environment]::GetEnvironmentVariable('SCANNER_TEST_ACL_PATH')
$user = [Security.Principal.WindowsIdentity]::GetCurrent().User
$acl = [Security.AccessControl.DirectorySecurity]::new()
$acl.SetOwner($user)
$acl.SetAccessRuleProtection($true, $false)
foreach ($sid in @($user.Value, 'S-1-5-18', 'S-1-5-32-544')) {
  $rule = [Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid), [Security.AccessControl.FileSystemRights]::FullControl, [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit', [Security.AccessControl.PropagationFlags]::None, [Security.AccessControl.AccessControlType]::Allow)
  $acl.AddAccessRule($rule)
}
[IO.Directory]::SetAccessControl($path, $acl)
`;
  const env = { ...process.env, SCANNER_TEST_ACL_PATH: root };
  execFileSync(powershell, ['-NoProfile', '-NonInteractive', '-Command', initialize], { env, timeout: 15_000 });
  const request = [{ path: root, kind: 'directory', access: 'private' }];
  await assert.doesNotReject(auditWindowsCachePaths(request));
  const broaden = String.raw`
$ErrorActionPreference = 'Stop'
$path = [Environment]::GetEnvironmentVariable('SCANNER_TEST_ACL_PATH')
$acl = [IO.Directory]::GetAccessControl($path)
$rule = [Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new('S-1-1-0'), [Security.AccessControl.FileSystemRights]::WriteData, [Security.AccessControl.AccessControlType]::Allow)
$acl.AddAccessRule($rule)
[IO.Directory]::SetAccessControl($path, $acl)
`;
  execFileSync(powershell, ['-NoProfile', '-NonInteractive', '-Command', broaden], { env, timeout: 15_000 });
  await assert.rejects(auditWindowsCachePaths(request), { code: 'unsafe_windows_cache_acl' });
  await assert.rejects(auditWindowsCachePaths([{ ...request[0], access: 'ancestor' }]), { code: 'unsafe_windows_cache_acl' });
});

test('run selects a prepared core without inspecting or building a toolchain', async t => {
  const f = await fixture(t);
  const { loadPreparedBootstrap } = await import('../../scripts/skill/bootstrap-core.mjs');
  await assert.rejects(loadPreparedBootstrap(f.options, f.deps), { code: 'core_not_prepared' });
  await prepareBootstrap(f.options, f.deps);
  const result = await loadPreparedBootstrap(f.options, { ...f.deps, inspectToolchain: () => { throw Error('toolchain'); }, build: () => { throw Error('build'); } });
  assert.equal(result.cache_hit, true);
  assert.equal(f.state.builds, 1);
  await writeFile(join(f.source, 'core.rs'), 'changed');
  await assert.rejects(loadPreparedBootstrap(f.options, f.deps), { code: 'core_not_prepared' });
});

test('archive operations that do not read data accept no data directory', () => {
  for (const action of ['verify', 'restore-preview', 'restore']) assert.deepEqual(validateRunArguments(['--json', 'archive', action, '--archive', '/x']), ['archive', action, '--archive', '/x']);
  assert.throws(() => validateRunArguments(['--json', 'archive', 'create']), { code: 'explicit_data_directory_required' });
});

test('doctor gives a Rust installation step when tools are missing', async t => {
  const f = await fixture(t);
  const deps = { ...f.deps, inspectToolchain: undefined, environment: { PATH: join(f.root, 'missing'), HOME: join(f.root, 'home') } };
  delete deps.inspectToolchain;
  const result = await doctorBootstrap(f.options, deps);
  assert.match(result.checks.find(c => c.name === 'rust_toolchain').reason, /rustup toolchain install 1\.98\.0/);
  await assert.rejects(prepareBootstrap(f.options, deps), { code: 'rust_toolchain_unavailable', exitCode: 4 });
});

test('bootstrap error schema is documented before CLI recovery', async () => {
  for (const path of ['docs/skill-bootstrap.md', 'skills/ai-security-scanner/references/cloudflare-source-audit.md']) {
    assert.match(await readFile(path, 'utf8'), /ai-security-scanner\.bootstrap-error\/v1/);
  }
  assert.match(await readFile('docs/skill-bootstrap.md', 'utf8'), /next_step/);
});


test('prepared selection refuses mismatches, tampering and ambiguous pointers', async t => {
  const f = await fixture(t);
  const { loadPreparedBootstrap } = await import('../../scripts/skill/bootstrap-core.mjs');
  const result = await prepareBootstrap(f.options, f.deps);
  await assert.rejects(loadPreparedBootstrap({ ...f.options, profile: 'release' }, f.deps), { code: 'core_not_prepared' });
  const pointer = join(f.options.cacheDir, 'ready', 'core-dev-fixture-native.json');
  const original = await readFile(pointer);
  await writeFile(join(f.options.cacheDir, 'ready', 'core-dev-another.json'), original);
  await assert.rejects(loadPreparedBootstrap(f.options, f.deps), { code: 'ambiguous_ready_pointer' });
  await rm(join(f.options.cacheDir, 'ready', 'core-dev-another.json'));
  const value = JSON.parse(original); value.receipt_sha256 = '0'.repeat(64);
  await writeFile(pointer, JSON.stringify(value));
  await assert.rejects(loadPreparedBootstrap(f.options, f.deps), { code: 'cache_receipt_mismatch' });
  await writeFile(pointer, original);
  const receipt = JSON.parse(await readFile(result.receipt_path)); receipt.build_outcome = 'failed';
  await writeFile(result.receipt_path, JSON.stringify(receipt));
  await assert.rejects(loadPreparedBootstrap(f.options, f.deps), { code: 'cache_receipt_mismatch' });
  assert.equal(f.state.builds, 1);
});

test('a later revision with identical build inputs runs the core that was already prepared', async t => {
  const f = await fixture(t);
  const { loadPreparedBootstrap } = await import('../../scripts/skill/bootstrap-core.mjs');
  const first = await prepareBootstrap(f.options, f.deps);
  f.state.revision = 'b'.repeat(40);
  const later = { ...f.options, revision: f.state.revision };
  assert.equal((await prepareBootstrap(later, f.deps)).cache_hit, true);
  const selected = await loadPreparedBootstrap(later, f.deps);
  assert.equal(selected.cache_key, first.cache_key);
  assert.equal(selected.requested_source.revision, f.state.revision);
  assert.equal(f.state.builds, 1);
});

test('looking for a prepared core does not create a cache directory', async t => {
  const f = await fixture(t);
  const { loadPreparedBootstrap } = await import('../../scripts/skill/bootstrap-core.mjs');
  await assert.rejects(loadPreparedBootstrap(f.options, f.deps), { code: 'core_not_prepared', exitCode: 2 });
  await assert.rejects(lstat(f.options.cacheDir), { code: 'ENOENT' });
});

test('an interrupted build stops the compilers it started and releases its lock', { skip: process.platform === 'win32' ? 'POSIX process groups are required for this interruption test' : false }, async t => {
  const f = await fixture(t);
  const tools = join(f.root, 'tools');
  await mkdir(tools);
  const pids = join(f.root, 'build-pids');
  // Stands in for Cargo: starts a compiler-like child, then waits for it.
  await writeFile(join(tools, 'cargo'), `#!/bin/sh\nsleep 300 &\necho "$$ $!" > ${JSON.stringify(pids)}\nwait\n`, { mode: 0o755 });
  const helper = join(f.root, 'interrupt-build.mjs');
  const moduleUrl = new URL('../../scripts/skill/bootstrap-core.mjs', import.meta.url).href;
  await writeFile(helper, `import { prepareBootstrap } from ${JSON.stringify(moduleUrl)};
const options = ${JSON.stringify(f.options)};
const deps = { sourceRoot: ${JSON.stringify(f.source)}, environment: ${JSON.stringify({ ...f.deps.environment, PATH: `${tools}:${process.env.PATH}` })},
 inspectSource: async () => ({revision: options.revision, dirty: false}), validatePinnedInputs: async () => false,
 collectInputManifest: async () => (${JSON.stringify(await f.deps.collectInputManifest())}), inspectToolchain: async () => (${JSON.stringify(toolchain)}),
 stageInputSnapshot: async () => {} };
try { await prepareBootstrap(options, deps); } catch (error) { console.error(error.code); process.exitCode = error.exitCode || 4; }
`);
  const child = spawn(process.execPath, [helper], { stdio: ['ignore', 'ignore', 'pipe'] });
  let stderr = '';
  child.stderr.on('data', bytes => { stderr += bytes; });
  // Wait for the exit itself: a compiler left running would keep the output pipe open.
  const exited = new Promise(resolve => child.once('exit', (code, signal) => resolve({ code, signal })));
  let started;
  t.after(() => { for (const pid of started ?? []) { try { process.kill(pid, 'SIGKILL'); } catch { /* already gone */ } } });
  for (let i = 0; i < 500 && !started; i += 1) {
    started = await readFile(pids, 'utf8').then(text => (/^\d+ \d+\n$/.test(text) ? text.trim().split(' ').map(Number) : undefined), () => undefined);
    if (!started) await new Promise(resolve => setTimeout(resolve, 10));
  }
  assert.ok(started, stderr);
  child.kill('SIGTERM');
  assert.deepEqual(await exited, { code: 143, signal: null }, stderr);
  assert.match(stderr, /interrupted/);
  const running = pid => { try { process.kill(pid, 0); return true; } catch { return false; } };
  for (let i = 0; i < 500 && started.some(running); i += 1) await new Promise(resolve => setTimeout(resolve, 10));
  assert.deepEqual(started.map(running), [false, false]);
  assert.deepEqual(await readdir(join(f.options.cacheDir, 'locks')), []);
  assert.deepEqual(await readdir(join(f.options.cacheDir, 'staging')), []);
});

test('interrupted preparation releases staging and its lock', { skip: process.platform === 'win32' ? 'POSIX signals are required for this interruption test' : false }, async t => {
  const f = await fixture(t);
  const helper = join(f.root, 'interrupt.mjs');
  const moduleUrl = new URL('../../scripts/skill/bootstrap-core.mjs', import.meta.url).href;
  await writeFile(helper, `import { prepareBootstrap } from ${JSON.stringify(moduleUrl)};
import { writeFile } from 'node:fs/promises';
import { spawn } from 'node:child_process';
const options = ${JSON.stringify(f.options)};
const toolchain = ${JSON.stringify(toolchain)};
const deps = { sourceRoot: ${JSON.stringify(f.source)}, environment: ${JSON.stringify(f.deps.environment)},
 inspectSource: async () => ({revision: options.revision, dirty: false}), validatePinnedInputs: async () => false,
 collectInputManifest: async () => (${JSON.stringify(await f.deps.collectInputManifest())}), inspectToolchain: async () => toolchain,
 stageInputSnapshot: async () => {}, build: async ({signal}) => {
  const child = spawn(process.execPath, ['-e', 'setInterval(()=>{},1000)']);
  signal.addEventListener('abort', () => child.kill('SIGTERM'), {once:true});
  await writeFile(${JSON.stringify(join(f.root, 'ready-signal'))}, 'ready');
  await new Promise(resolve => child.once('close', resolve));
 }};
try { await prepareBootstrap(options, deps); } catch (error) { console.error(error); process.exitCode = error.exitCode || 4; }
`);
  const child = spawn(process.execPath, [helper], { stdio: ['ignore', 'ignore', 'pipe'] });
  let stderr = '';
  child.stderr.on('data', bytes => { stderr += bytes; });
  const closed = new Promise(resolve => child.once('close', (code, signal) => resolve({ code, signal })));
  let ready = false;
  for (let i = 0; i < 300; i += 1) {
    if (await readFile(join(f.root, 'ready-signal')).then(() => true, () => false)) { ready = true; break; }
    await new Promise(resolve => setTimeout(resolve, 10));
  }
  assert.equal(ready, true, stderr);
  child.kill('SIGINT');
  assert.deepEqual(await closed, { code: 130, signal: null });
  assert.deepEqual(await readdir(join(f.options.cacheDir, 'locks')), []);
  assert.deepEqual(await readdir(join(f.options.cacheDir, 'staging')), []);
  await prepareBootstrap(f.options, f.deps);
});


test('run children cannot inherit ambient product source overrides', async t => {
  const f = await fixture(t);
  const output = join(f.root, 'environment.json');
  f.state.runtimeScript = `require('node:fs').writeFileSync(process.env.OUTPUT, JSON.stringify(Object.keys(process.env).filter(k => k.toUpperCase().startsWith('AI_SECURITY_SCANNER_'))));`;
  const result = await prepareBootstrap(f.options, f.deps);
  const environment = { ...f.deps.environment, OUTPUT: output, Ai_Security_Scanner_Data_Dir: 'ambient', AI_SECURITY_SCANNER_MANAGED_RUNTIME_BUNDLE: 'ambient', ai_security_scanner_release_approved_local_image_directory: 'ambient' };
  assert.equal(await runPrepared(result, ['--data-dir', join(f.root, 'data'), 'case', 'list'], { ...f.deps, environment, commandExecutable: process.execPath, argvPrefix: [result.executable] }), 0);
  assert.deepEqual(JSON.parse(await readFile(output)), []);
});

test('doctor requires Node.js 24', async t => {
  const f = await fixture(t);
  const result = await doctorBootstrap(f.options, { ...f.deps, nodeVersion: '22.0.0' });
  assert.match(result.checks.find(c => c.name === 'node').reason, /Node.js 24 or newer/);
});

test('doctor checks the nearest existing cache ancestor for writability', { skip: process.platform === 'win32' ? 'POSIX permission modes are required' : false }, async t => {
  const f = await fixture(t);
  const parent = join(f.root, 'no-write');
  await mkdir(parent, { mode: 0o500 });
  try {
    const result = await doctorBootstrap({ ...f.options, cacheDir: join(parent, 'missing', 'cache') }, f.deps);
    const check = result.checks.find(c => c.name === 'cache');
    assert.equal(check.ready, false);
    assert.equal(check.error, 'cache_parent_not_writable');
  } finally { await chmod(parent, 0o700); }
});

async function installedBundleFixture(t) {
  const f = await fixture(t);
  const bundle = join(f.root, 'desktop-runtime');
  const manifest = '{"fixture":"installed desktop"}\n';
  await mkdir(bundle);
  await writeFile(join(bundle, 'manifest.json'), manifest);
  // The host's own platform keeps the fixture core's file name (.exe on Windows) the one the build wrote.
  const entry = { platform: process.platform, arch: [process.arch], product_version: '0.6.2', manifest_sha256: digest(manifest), installed_paths: [bundle] };
  const deps = { ...f.deps, platform: entry.platform, arch: process.arch, recognizedManagedRuntimeBundles: [entry] };
  const options = { ...f.options, capability: 'scan', engineIds: ['gitleaks'], dataDir: join(f.root, 'data') };
  return { ...f, bundle, entry, deps, options };
}

const retryNotice = 'No Docker or Podman found. Using the scan runtime of the installed desktop app; its first start downloads a machine image and can take several minutes.\n';
const runtimeNextSteps = {
  offline: 'Offline preparation needs a runtime that is already running. Start Docker or Podman, or run prepare once without --offline.',
  unrecognized: "The installed desktop app's scan runtime is not one this source revision recognizes. Use a newer source revision, or start Docker or Podman, then run prepare again.",
  absent: 'Start Docker or Podman, or install the desktop app for this computer, then run prepare again.',
  unsupported: 'Start Docker or Podman, then run prepare again.',
  managed_runtime_unavailable: 'The managed scan runtime could not start; the image errors in detail say why. Fix that, or start Docker or Podman, then run prepare again.',
  managed_bundle_rejected: 'The selected runtime bundle was refused; the image errors in detail say why. Select the bundle that ships with the desktop app, or start Docker or Podman.',
};

test('scan preparation retries a recognized desktop bundle once and records its provenance', async t => {
  for (const firstThrows of [false, true]) {
    const f = await installedBundleFixture(t);
    const calls = [];
    let stderr = '';
    const failed = runtimeResult(f.options, { ready: false, runtime_unavailable_reason: 'no_runtime' });
    const prepareRuntime = async (_executable, request) => {
      calls.push(request);
      if (calls.length === 1) {
        if (firstThrows) throw new BootstrapError('runtime_preparation_failed', 'Core exited.', 4, failed);
        return failed;
      }
      return runtimeResult(request, { runtime_unavailable_reason: null });
    };
    const result = await prepareBootstrap(f.options, { ...f.deps, prepareRuntime, stderr: { write: value => { stderr += value; } } });
    assert.equal(calls.length, 2);
    assert.equal(calls[0].managedRuntimeBundle, undefined);
    assert.equal(calls[1].managedRuntimeBundle, f.bundle);
    assert.equal(calls[1].expectedManagedRuntimeManifestSha256, f.entry.manifest_sha256);
    assert.equal(stderr, retryNotice);
    assert.equal(result.runtime_bundle_source, 'installed_desktop');
    assert.deepEqual(result.runtime_bundle, { path: f.bundle, manifest_sha256: f.entry.manifest_sha256, product_version: '0.6.2' });
  }
});

test('scan preparation records explicit and absent bundle sources without retrying success', async t => {
  const f = await installedBundleFixture(t);
  for (const bundle of [undefined, f.bundle]) {
    let calls = 0;
    const result = await prepareBootstrap({ ...f.options, managedRuntimeBundle: bundle }, {
      ...f.deps, prepareRuntime: async (_executable, request) => { calls += 1; return runtimeResult(request); },
    });
    assert.equal(calls, 1);
    assert.equal(result.runtime_bundle_source, bundle ? 'explicit' : 'none');
    assert.equal(Object.hasOwn(result, 'runtime_bundle'), false);
  }
});

test('scan failures do not retry in excluded cases and give the matching next step', async t => {
  const f = await installedBundleFixture(t);
  const cases = [
    { name: 'explicit', reason: 'no_runtime', options: { managedRuntimeBundle: f.bundle }, entries: [], next: runtimeNextSteps.unsupported },
    { name: 'offline', reason: 'no_runtime', options: { offline: true }, next: runtimeNextSteps.offline },
    { name: 'managed unavailable', reason: 'managed_runtime_unavailable', next: runtimeNextSteps.managed_runtime_unavailable },
    { name: 'bundle rejected', reason: 'managed_bundle_rejected', next: runtimeNextSteps.managed_bundle_rejected },
    { name: 'null reason', reason: null },
    { name: 'missing reason' },
    { name: 'unrecognized', reason: 'no_runtime', entries: [{ ...f.entry, manifest_sha256: '0'.repeat(64) }], next: runtimeNextSteps.unrecognized },
    { name: 'absent', reason: 'no_runtime', entries: [{ ...f.entry, installed_paths: [join(f.root, 'missing')] }], next: runtimeNextSteps.absent },
    { name: 'unsupported', reason: 'no_runtime', entries: [], next: runtimeNextSteps.unsupported },
    { name: 'unsupported architecture', reason: 'no_runtime', entries: [{ ...f.entry, arch: ['other'] }], next: runtimeNextSteps.unsupported },
    { name: 'no installed paths', reason: 'no_runtime', entries: [{ ...f.entry, installed_paths: [] }], next: runtimeNextSteps.unsupported },
  ];
  for (const testCase of cases) {
    for (const firstThrows of [false, true]) {
      const options = { ...f.options, ...testCase.options };
      const failed = runtimeResult(options, { ready: false, ...(Object.hasOwn(testCase, 'reason') ? { runtime_unavailable_reason: testCase.reason } : {}) });
      let calls = 0;
      const prepareRuntime = async () => {
        calls += 1;
        if (firstThrows) throw new BootstrapError('runtime_preparation_failed', 'Existing core message.', 3, failed);
        return failed;
      };
      await assert.rejects(prepareBootstrap(options, { ...f.deps, recognizedManagedRuntimeBundles: testCase.entries ?? [f.entry], prepareRuntime }), error => {
        assert.equal(error.code, 'runtime_preparation_failed', testCase.name);
        assert.equal(error.nextStep, testCase.next, testCase.name);
        assert.deepEqual(error.details, failed, testCase.name);
        if (firstThrows) {
          assert.equal(error.message, 'Existing core message.');
          assert.equal(error.exitCode, 3);
        }
        return true;
      });
      assert.equal(calls, 1, testCase.name);
    }
  }
});

test('a failed desktop retry is final and an interrupted first attempt never retries', async t => {
  const f = await installedBundleFixture(t);
  const failed = runtimeResult(f.options, { ready: false, runtime_unavailable_reason: 'managed_runtime_unavailable' });
  let calls = 0;
  await assert.rejects(prepareBootstrap(f.options, { ...f.deps, stderr: { write() {} }, prepareRuntime: async () => {
    calls += 1;
    if (calls === 1) throw new BootstrapError('runtime_preparation_failed', 'First failed.', 4, runtimeResult(f.options, { ready: false, runtime_unavailable_reason: 'no_runtime' }));
    throw new BootstrapError('runtime_preparation_failed', 'Second failed.', 3, failed);
  } }), error => {
    assert.equal(error.message, 'Second failed.');
    assert.equal(error.exitCode, 3);
    assert.deepEqual(error.details, failed);
    assert.equal(error.nextStep, runtimeNextSteps.managed_runtime_unavailable);
    return true;
  });
  assert.equal(calls, 2);
  calls = 0;
  await assert.rejects(prepareBootstrap(f.options, { ...f.deps, prepareRuntime: async () => {
    calls += 1;
    throw new BootstrapError('interrupted', 'Interrupted.', 130, runtimeResult(f.options, { ready: false, runtime_unavailable_reason: 'no_runtime' }));
  } }), { code: 'interrupted', exitCode: 130 });
  assert.equal(calls, 1);
});

test('installed bundle discovery ignores relative and oversized paths and distinguishes wrong digests', async t => {
  const f = await installedBundleFixture(t);
  const oversized = join(f.root, 'oversized');
  await mkdir(oversized);
  await writeFile(join(oversized, 'manifest.json'), Buffer.alloc(262145));
  const locate = paths => bootstrapCore.locateInstalledManagedRuntimeBundle({ ...f.deps, recognizedManagedRuntimeBundles: [{ ...f.entry, installed_paths: paths }] });
  assert.deepEqual(await locate(['relative-path', oversized]), { state: 'absent' });
  assert.deepEqual(await locate([join(f.root, 'missing'), f.bundle]), { state: 'recognized', path: f.bundle, manifest_sha256: f.entry.manifest_sha256, product_version: '0.6.2' });
  await writeFile(join(f.bundle, 'manifest.json'), 'different');
  assert.deepEqual(await locate([f.bundle]), { state: 'unrecognized', path: f.bundle });
  assert.deepEqual(await bootstrapCore.locateInstalledManagedRuntimeBundle({ ...f.deps, arch: 'other' }), { state: 'unsupported' });
  const maximum = Buffer.alloc(262144, 7);
  await writeFile(join(f.bundle, 'manifest.json'), maximum);
  assert.deepEqual(await bootstrapCore.locateInstalledManagedRuntimeBundle({ ...f.deps, recognizedManagedRuntimeBundles: [{ ...f.entry, manifest_sha256: digest(maximum) }] }),
    { state: 'recognized', path: f.bundle, manifest_sha256: digest(maximum), product_version: '0.6.2' });
});

test('installed bundle discovery does not follow symbolic links', { skip: process.platform === 'win32' ? 'Symbolic link creation requires Windows privileges' : false }, async t => {
  const f = await installedBundleFixture(t);
  const directoryLink = join(f.root, 'directory-link');
  await symlink(f.bundle, directoryLink);
  const fileLinkDir = join(f.root, 'file-link');
  await mkdir(fileLinkDir);
  await symlink(join(f.bundle, 'manifest.json'), join(fileLinkDir, 'manifest.json'));
  const parentLink = join(f.root, 'parent-link');
  await symlink(f.root, parentLink);
  assert.deepEqual(await bootstrapCore.locateInstalledManagedRuntimeBundle({ ...f.deps, recognizedManagedRuntimeBundles: [{ ...f.entry,
    installed_paths: [directoryLink, fileLinkDir, join(parentLink, 'desktop-runtime')],
  }] }), { state: 'absent' });
});

test('runtime arguments bind an expected manifest digest to the selected bundle', () => {
  const options = { engineIds: ['gitleaks'], dataDir: 'data', managedRuntimeBundle: 'bundle', expectedManagedRuntimeManifestSha256: 'a'.repeat(64) };
  const args = runtimePreparationArguments(options);
  assert.deepEqual(args.slice(3, 7), ['--managed-runtime-bundle', join(process.cwd(), 'bundle'), '--expected-managed-runtime-manifest-sha256', options.expectedManagedRuntimeManifestSha256]);
  assert.throws(() => runtimePreparationArguments({ ...options, managedRuntimeBundle: undefined }), { code: 'invalid_request', exitCode: 2 });
});

test('bootstrap error printer emits next_step only when set', t => {
  const detail = { schema_version: 'ai-security-scanner.runtime-preparation/v1', ready: false, offline: false,
    engines: ['gitleaks'], runtime: null, images: [], receipt_path: null, runtime_unavailable_reason: 'no_runtime' };
  let output = '';
  const write = text => { output += text; };
  bootstrapEntry.printBootstrapError(new BootstrapError('runtime_preparation_failed', 'Selected scanner resources are not ready.', 4, detail, runtimeNextSteps.absent), write);
  assert.deepEqual(JSON.parse(output), { schema_version: 'ai-security-scanner.bootstrap-error/v1', error: 'runtime_preparation_failed', message: 'Selected scanner resources are not ready.', detail, next_step: runtimeNextSteps.absent });
  t.diagnostic(`printed error: ${output.trim()}`);
  output = '';
  bootstrapEntry.printBootstrapError(new BootstrapError('invalid_request', 'Unchanged.', 2), write);
  assert.deepEqual(JSON.parse(output), { schema_version: 'ai-security-scanner.bootstrap-error/v1', error: 'invalid_request', message: 'Unchanged.' });
});

test('scan doctor reports runtime sources without executing commands or changing readiness', async t => {
  const f = await installedBundleFixture(t);
  const bin = join(f.root, 'bin');
  await mkdir(bin);
  await writeFile(join(bin, 'docker'), 'must not execute');
  await mkdir(join(bin, 'podman'));
  const deps = { ...f.deps, environment: { ...f.deps.environment, PATH: bin } };
  const scan = await doctorBootstrap(f.options, deps);
  assert.deepEqual(scan.runtime_sources, { compatibility_commands_on_path: ['docker'], installed_desktop_bundle: 'recognized' });
  const core = await doctorBootstrap({ ...f.options, capability: 'core', engineIds: undefined, dataDir: undefined }, deps);
  assert.equal(Object.hasOwn(core, 'runtime_sources'), false);
  assert.equal(scan.ready, false);
  const emptySources = await doctorBootstrap(f.options, { ...deps, environment: { ...deps.environment, PATH: join(f.root, 'missing-bin') }, recognizedManagedRuntimeBundles: [] });
  assert.deepEqual(emptySources.runtime_sources, { compatibility_commands_on_path: [], installed_desktop_bundle: 'unsupported' });
  assert.equal(scan.ready, emptySources.ready);
  const windowsBin = join(f.root, 'windows-bin');
  await mkdir(windowsBin);
  await writeFile(join(windowsBin, 'docker.EXE'), 'must not execute');
  await writeFile(join(windowsBin, 'podman.CMD'), 'must not execute');
  const windows = await doctorBootstrap(f.options, { ...deps, platform: 'win32', recognizedManagedRuntimeBundles: [{ ...f.entry, platform: 'win32', installed_paths: [] }],
    environment: { ...deps.environment, PATH: windowsBin, PATHEXT: '.EXE;.CMD' } });
  assert.deepEqual(windows.runtime_sources, { compatibility_commands_on_path: ['docker', 'podman'], installed_desktop_bundle: 'unsupported' });
  assert.equal(windows.ready, scan.ready);
});

test('scan doctor records this host runtime sources without executing commands', async t => {
  const f = await fixture(t);
  const result = await doctorBootstrap({ ...f.options, capability: 'scan', engineIds: ['gitleaks'], dataDir: join(f.root, 'data') }, f.deps);
  assert.equal(result.ready, false);
  assert.ok(Array.isArray(result.runtime_sources.compatibility_commands_on_path));
  assert.ok(['recognized', 'unrecognized', 'absent', 'unsupported'].includes(result.runtime_sources.installed_desktop_bundle));
  t.diagnostic(`host runtime_sources: ${JSON.stringify(result.runtime_sources)}`);
});
