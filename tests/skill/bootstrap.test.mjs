import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { chmod, link, lstat, mkdir, mkdtemp, readFile, readdir, realpath, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
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
  for (const name of ['bootstrap.mjs', 'bootstrap-core.mjs', 'input-manifest.mjs']) {
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
      const bytes = `#!/usr/bin/env node\n// IDENTITY ${JSON.stringify(identity)}\nprocess.exit(Number(process.argv.at(-1) ?? 0));\n`;
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
  assert.equal(new Set(keys).size, 6);
  assert.equal(f.state.builds, 6);
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

test('cache refuses symbolic link traversal and artifact replacement', { skip: process.platform === 'win32' }, async t => {
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
  await assert.rejects(prepareBootstrap(f.options, f.deps), { code: 'cargo_configuration_override' });
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

test('runtime child keeps fixed argv literal and removes ambient product source overrides', { skip: process.platform === 'win32' }, async t => {
  const f = await runtimeChild(t, `process.stdout.write(JSON.stringify({schema_version:'ai-security-scanner.runtime-preparation/v1',ready:true,offline:true,engines:['gitleaks'],runtime:{args:process.argv.slice(2),ambient:Object.keys(process.env).filter(key=>['AI_SECURITY_SCANNER_DATA_DIR','AI_SECURITY_SCANNER_MANAGED_RUNTIME_BUNDLE','AI_SECURITY_SCANNER_RELEASE_APPROVED_LOCAL_IMAGE_DIRECTORY'].includes(key.toUpperCase()))},images:[{role:'engine',engine_ids:['gitleaks'],image:'fixture@sha256:${'a'.repeat(64)}',status:'ready',error:null}],receipt_path:'fixture-receipt'}));`);
  const result = await invokeRuntimePreparation(f.executable, f.options, { environment: {
    ...process.env,
    AI_SECURITY_SCANNER_MANAGED_RUNTIME_BUNDLE: '/ambient/unselected',
    ai_security_scanner_managed_runtime_bundle: '/ambient/lowercase-bundle',
    Ai_Security_Scanner_Data_Dir: '/ambient/mixed-case-data',
    ai_SECURITY_scanner_RELEASE_APPROVED_local_IMAGE_directory: '/ambient/mixed-case-images',
  } });
  assert.deepEqual(result.runtime.args, runtimePreparationArguments(f.options));
  assert.deepEqual(result.runtime.ambient, []);
});

test('runtime child preserves failed receipts and refuses successful malformed or mismatched JSON', { skip: process.platform === 'win32' }, async t => {
  const f = await runtimeChild(t, `process.stdout.write(JSON.stringify({schema_version:'ai-security-scanner.runtime-preparation/v1',ready:false,offline:true,engines:['gitleaks'],runtime:null,images:[{status:'failed',error:'Unavailable'}],receipt_path:'preserved-receipt'}));process.exitCode=3;`);
  await assert.rejects(invokeRuntimePreparation(f.executable, f.options), error => {
    assert.equal(error.exitCode, 3);
    assert.equal(error.details.receipt_path, 'preserved-receipt');
    assert.equal(error.details.ready, false);
    return true;
  });
  await writeFile(f.executable, `#!${process.execPath}\nprocess.stdout.write('not JSON');\n`, { mode: 0o700 });
  await assert.rejects(invokeRuntimePreparation(f.executable, f.options), { code: 'invalid_runtime_preparation_result' });
  await writeFile(f.executable, `#!${process.execPath}\nprocess.stdout.write(JSON.stringify(${JSON.stringify(runtimeResult(f.options, { engines: ['semgrep'] }))}));\n`, { mode: 0o700 });
  await assert.rejects(invokeRuntimePreparation(f.executable, f.options), { code: 'invalid_runtime_preparation_result' });
});

test('runtime preparation cancellation waits for the child owner to settle before returning', { skip: process.platform === 'win32' }, async t => {
  const f = await runtimeChild(t, `import fs from 'node:fs';process.stdin.on('data',bytes=>{if(bytes.toString()!=='terminate\\n')process.exit(2);setTimeout(()=>{fs.writeFileSync(process.env.SETTLED,'done');process.stdout.write(JSON.stringify({schema_version:'ai-security-scanner.runtime-preparation/v1',ready:false,offline:true,engines:['gitleaks'],runtime:null,images:[],receipt_path:'cancelled-receipt'}));process.exit(143);},80)});`);
  const settled = join(f.root, 'settled');
  const listeners = process.listenerCount('SIGTERM');
  await assert.rejects(invokeRuntimePreparation(f.executable, f.options, { environment: { ...process.env, SETTLED: settled }, timeoutMs: 50 }), error => {
    assert.equal(error.code, 'runtime_preparation_deadline');
    assert.equal(error.exitCode, 4);
    assert.equal(error.details.receipt_path, 'cancelled-receipt');
    return true;
  });
  assert.equal(await readFile(settled, 'utf8'), 'done');
  assert.equal(process.listenerCount('SIGTERM'), listeners);
});

test('runtime output limit cancels and joins the owner without retaining unbounded JSON', { skip: process.platform === 'win32' }, async t => {
  const f = await runtimeChild(t, `import fs from 'node:fs';process.stdin.on('data',bytes=>{if(bytes.toString()!=='terminate\\n')process.exit(2);setTimeout(()=>{fs.writeFileSync(process.env.SETTLED,'done');process.exit(143)},40)});process.stdout.write('x'.repeat(2*1024*1024));`);
  const settled = join(f.root, 'settled');
  await assert.rejects(invokeRuntimePreparation(f.executable, f.options, { environment: { ...process.env, SETTLED: settled } }), { code: 'runtime_preparation_output_limit' });
  assert.equal(await readFile(settled, 'utf8'), 'done');
});

test('SIGINT reaches the runtime owner through its control pipe and preserves its cancelled receipt', { skip: process.platform === 'win32' }, async t => {
  const f = await runtimeChild(t, `import fs from 'node:fs';process.stdin.on('data',bytes=>{if(bytes.toString()!=='cancel\\n')process.exit(2);setTimeout(()=>{fs.writeFileSync(process.env.SETTLED,'done');process.stdout.write(JSON.stringify({schema_version:'ai-security-scanner.runtime-preparation/v1',ready:false,offline:true,engines:['gitleaks'],runtime:null,images:[],receipt_path:'interrupted-receipt'}));process.exit(130)},40)});fs.writeFileSync(process.env.READY,'ready');`);
  const ready = join(f.root, 'ready');
  const settled = join(f.root, 'settled');
  const before = process.listenerCount('SIGINT');
  const completion = invokeRuntimePreparation(f.executable, f.options, { environment: { ...process.env, READY: ready, SETTLED: settled }, timeoutMs: 5000 }).then(
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

test('run rechecks artifacts and propagates child exit without shell evaluation', { skip: process.platform === 'win32' }, async t => {
  const f = await fixture(t);
  const result = await prepareBootstrap(f.options, f.deps);
  assert.equal(await runPrepared(result, ['--data-dir', join(f.root, 'data'), '17'], f.deps), 17);
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

test('unsafe writable ancestors and caches inside source are refused before creating entries', { skip: process.platform === 'win32' }, async t => {
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

test('native Windows ACL verifier accepts private directories and rejects a broad writable ACE', { skip: process.platform !== 'win32' }, async t => {
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
