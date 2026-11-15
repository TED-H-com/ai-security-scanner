import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { lstat, readFile, readdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import test from 'node:test';
import {
  BootstrapError, RECIPE, RUST_VERSION, assertValidPrebuiltCoreEntry,
  doctorBootstrap, loadPreparedBootstrap, parseBootstrapArguments, prepareBootstrap,
} from '../../scripts/skill/bootstrap-core.mjs';
import { PREBUILT_CORES } from '../../scripts/skill/prebuilt-cores.mjs';
import { digest, fixture, revision } from './bootstrap-fixture.mjs';
import { chunkedResponse } from './release-bundle-fixture.mjs';

function makeBinary(identity) {
  return Buffer.from(`#!/usr/bin/env node\n// IDENTITY ${JSON.stringify(identity)}\nprocess.stdout.write(JSON.stringify(${JSON.stringify(identity)}));\n`);
}

async function prebuiltFixture(t, {
  platform = process.platform,
  arch = process.arch,
  product_version = '0.0.0-fixture',
  targets = { [arch]: 'fixture-prebuilt-target' },
  features = ['cli'],
  identityOverrides = {},
  url = 'https://releases.example.test/v0.0.0-fixture/ai-security-scanner-cli',
} = {}) {
  const f = await fixture(t);
  const manifest = await f.deps.collectInputManifest();
  const target = targets[arch];
  const identity = {
    schema_version: 'ai-security-scanner.build-identity/v1',
    product: 'ai-security-scanner',
    product_version,
    target,
    rustc_version: `rustc ${RUST_VERSION} (prebuilt)\nhost: ${target}\nrelease: ${RUST_VERSION}`,
    features,
    bootstrap_input_sha256: manifest.inputDigest,
    bootstrap_recipe: RECIPE,
    report_source_sha256: 'e'.repeat(64),
    ...identityOverrides,
  };
  const bytes = makeBinary(identity);
  const entry = {
    product_version,
    input_sha256: manifest.inputDigest,
    platform,
    targets,
    features,
    release_source: { url, bytes: bytes.length, sha256: digest(bytes) },
  };
  const state = { fetches: 0, readIdentities: 0, stderr: '' };
  const releaseOptions = { ...f.options, profile: 'release' };
  const noToolchainDeps = {
    ...f.deps,
    platform,
    arch,
    prebuiltCores: [entry],
    inspectToolchain: () => { throw new Error('inspectToolchain must not run on the prebuilt path'); },
    build: () => { throw new Error('build must not run on the prebuilt path'); },
    fetch: async () => {
      state.fetches += 1;
      return chunkedResponse(bytes, { headers: { 'content-length': String(bytes.length) } });
    },
    readIdentity: async executable => {
      state.readIdentities += 1;
      return f.deps.readIdentity(executable);
    },
    stderr: { write: value => { state.stderr += value; } },
  };
  return { ...f, manifest, identity, bytes, entry, releaseOptions, noToolchainDeps, prebuiltState: state };
}

test('shipped PREBUILT_CORES is frozen and every entry passes strict shape validation', () => {
  assert.ok(Array.isArray(PREBUILT_CORES));
  assert.ok(Object.isFrozen(PREBUILT_CORES));
  for (const entry of PREBUILT_CORES) {
    assert.ok(Object.isFrozen(entry));
    assert.ok(Object.isFrozen(entry.targets));
    assert.ok(Object.isFrozen(entry.features));
    assert.ok(Object.isFrozen(entry.release_source));
    assertValidPrebuiltCoreEntry(entry);
  }
  const sample = {
    product_version: '0.0.0-fixture',
    input_sha256: 'a'.repeat(64),
    platform: 'linux',
    targets: { x64: 'x86_64-unknown-linux-gnu' },
    features: ['cli'],
    release_source: { url: 'https://example.test/cli', bytes: 123, sha256: 'b'.repeat(64) },
  };
  assertValidPrebuiltCoreEntry(sample);
  for (const broken of [
    null,
    { ...sample, extra: true },
    { ...sample, product_version: '' },
    { ...sample, input_sha256: 'bad' },
    { ...sample, platform: 'freebsd' },
    { ...sample, targets: {} },
    { ...sample, targets: { amd64: 'x86_64-unknown-linux-gnu' } },
    { ...sample, targets: { x64: 'bad target' } },
    { ...sample, features: [] },
    { ...sample, features: ['desktop'] },
    { ...sample, features: ['cli', 'cli'] },
    { ...sample, release_source: { ...sample.release_source, url: 'http://example.test/cli' } },
    { ...sample, release_source: { ...sample.release_source, url: 'https://user:pass@example.test/cli' } },
    { ...sample, release_source: { ...sample.release_source, bytes: 0 } },
    { ...sample, release_source: { ...sample.release_source, sha256: 'xyz' } },
  ]) {
    assert.throws(() => assertValidPrebuiltCoreEntry(broken), { code: 'invalid_prebuilt_core' });
  }
});

test('--build-from-source is accepted by doctor, prepare, and run and documented in help', () => {
  for (const command of ['doctor', 'prepare', 'run']) {
    const parsed = parseBootstrapArguments([command, '--revision', revision, '--cache-dir', '/cache', '--build-from-source']);
    assert.equal(parsed.buildFromSource, true);
    assert.throws(
      () => parseBootstrapArguments([command, '--revision', revision, '--cache-dir', '/cache', '--build-from-source', '--build-from-source']),
      { code: 'invalid_arguments', exitCode: 2 },
    );
  }
  const help = execFileSync(process.execPath, ['scripts/skill/bootstrap.mjs', '--help'], { encoding: 'utf8' });
  assert.match(help, /--build-from-source/);
});

test('prebuilt core prepares without a toolchain, hits cache on reuse, and loads for run', async t => {
  const f = await prebuiltFixture(t);
  const first = await prepareBootstrap(f.releaseOptions, f.noToolchainDeps);
  assert.equal(first.cache_hit, false);
  assert.equal(first.core_source, 'prebuilt_release');
  assert.equal(first.receipt.core_source, 'prebuilt_release');
  assert.equal(first.receipt.build_outcome, 'success');
  assert.deepEqual(first.receipt.cache_identity.toolchain, { prebuilt: true, version: RUST_VERSION, target: f.entry.targets[process.arch] });
  assert.deepEqual(first.receipt.cache_identity.native_environment, {});
  assert.deepEqual(first.receipt.cache_identity.prebuilt, {
    product_version: f.entry.product_version,
    features: f.entry.features,
    release_source: f.entry.release_source,
  });
  assert.deepEqual(first.receipt.cache_identity.features, ['cli']);
  assert.equal(f.prebuiltState.fetches, 1);
  assert.equal(f.prebuiltState.stderr.trim().split('\n').length, 1);
  assert.match(f.prebuiltState.stderr, /prebuilt scanner core.*0\.0\.0-fixture/i);
  assert.match(f.prebuiltState.stderr, new RegExp(String(f.bytes.length)));
  assert.deepEqual(await readdir(join(f.releaseOptions.cacheDir, 'staging')), []);
  assert.deepEqual(await readdir(join(f.releaseOptions.cacheDir, 'locks')), []);

  const second = await prepareBootstrap(f.releaseOptions, f.noToolchainDeps);
  assert.equal(second.cache_hit, true);
  assert.equal(second.cache_key, first.cache_key);
  assert.equal(second.core_source, 'prebuilt_release');
  assert.equal(second.receipt.core_source, 'prebuilt_release');
  assert.equal(f.prebuiltState.fetches, 1);

  const loaded = await loadPreparedBootstrap(f.releaseOptions, f.noToolchainDeps);
  assert.equal(loaded.cache_hit, true);
  assert.equal(loaded.cache_key, first.cache_key);
  assert.equal(loaded.executable, first.executable);
  assert.equal(loaded.receipt.core_source, 'prebuilt_release');

  await assert.rejects(
    loadPreparedBootstrap({ ...f.releaseOptions, buildFromSource: true }, f.noToolchainDeps),
    { code: 'core_not_prepared', exitCode: 2 },
  );
});

test('download size, digest, HTTP, and non-HTTPS failures preserve prior ready entry and never execute bytes', async t => {
  const f = await prebuiltFixture(t);
  const prior = await prepareBootstrap({ ...f.options, profile: 'release' }, { ...f.deps, prebuiltCores: [] });
  assert.equal(prior.core_source, 'local_build');
  assert.equal(Object.hasOwn(prior.receipt.cache_identity, 'prebuilt'), false);
  const readyPath = join(f.options.cacheDir, 'ready', `core-release-${prior.receipt.cache_identity.toolchain.target}.json`);
  const priorReady = await readFile(readyPath);

  await writeFile(join(f.source, 'core.rs'), 'fn main() { updated(); }\n');
  const updatedManifest = await f.deps.collectInputManifest();
  const goodBytes = makeBinary({ ...f.identity, bootstrap_input_sha256: updatedManifest.inputDigest });
  const baseEntry = {
    ...f.entry,
    input_sha256: updatedManifest.inputDigest,
    release_source: { ...f.entry.release_source, bytes: goodBytes.length, sha256: digest(goodBytes) },
  };
  let identityCalls = 0;
  const neverReadIdentity = () => { identityCalls += 1; throw new Error('must never call readIdentity'); };

  for (const scenario of [
    {
      name: 'wrong size',
      code: 'prebuilt_core_size_mismatch',
      entry: baseEntry,
      fetch: async () => chunkedResponse(goodBytes.subarray(0, goodBytes.length - 1)),
    },
    {
      name: 'wrong digest',
      code: 'prebuilt_core_digest_mismatch',
      entry: { ...baseEntry, release_source: { ...baseEntry.release_source, sha256: '0'.repeat(64) } },
      fetch: async () => chunkedResponse(goodBytes),
    },
    {
      name: 'HTTP failure',
      code: 'prebuilt_core_download_failed',
      entry: baseEntry,
      fetch: async () => new Response(null, { status: 503 }),
    },
    {
      name: 'redirect to non-HTTPS URL',
      code: 'prebuilt_core_download_failed',
      entry: baseEntry,
      fetch: async url => {
        assert.ok(String(url).startsWith('https://'));
        return new Response(null, { status: 302, headers: { location: 'http://insecure.example.test/cli' } });
      },
    },
    {
      name: 'direct non-HTTPS URL in entry',
      code: 'invalid_prebuilt_core',
      entry: { ...baseEntry, release_source: { ...baseEntry.release_source, url: 'http://insecure.example.test/cli' } },
      fetch: async () => { throw new Error('fetch must not run for non-HTTPS pin'); },
      skipBuildFromSourceMessage: true,
    },
  ]) {
    await assert.rejects(
      prepareBootstrap(f.releaseOptions, {
        ...f.noToolchainDeps,
        prebuiltCores: [scenario.entry],
        fetch: scenario.fetch,
        readIdentity: neverReadIdentity,
      }),
      error => {
        assert.equal(error.code, scenario.code, scenario.name);
        assert.equal(error.exitCode, 4, scenario.name);
        // Only a failed transfer is worth repeating; a file that differs from its pin is not.
        if (scenario.code === 'prebuilt_core_download_failed') assert.match(error.message, /run prepare again, or pass --build-from-source/, scenario.name);
        else assert.doesNotMatch(error.message, /run prepare again/, scenario.name);
        if (!scenario.skipBuildFromSourceMessage) {
          assert.match(error.message, /--build-from-source/, scenario.name);
          assert.match(error.message, new RegExp(RUST_VERSION.replaceAll('.', '\\.')), scenario.name);
          assert.match(error.message, /compiler/i, scenario.name);
        }
        return true;
      },
    );
    assert.equal(identityCalls, 0, scenario.name);
    assert.deepEqual(await readFile(readyPath), priorReady, scenario.name);
    assert.deepEqual(await readdir(join(f.options.cacheDir, 'staging')), [], scenario.name);
    assert.deepEqual(await readdir(join(f.options.cacheDir, 'locks')), [], scenario.name);
  }
});

test('identity mismatches and unstartable executables fail closed without publishing', async t => {
  const f = await prebuiltFixture(t);
  const cases = [
    ['input digest', { bootstrap_input_sha256: '0'.repeat(64) }],
    ['recipe', { bootstrap_recipe: 'wrong-recipe' }],
    ['target', { target: 'wrong-target' }],
    ['features', { features: ['cli', 'unexpected'] }],
    ['product version', { product_version: '9.9.9' }],
    ['compiler release line', { rustc_version: 'rustc 1.97.0 (bad)\nrelease: 1.97.0' }],
    ['compiler release line with a suffix', { rustc_version: `rustc ${RUST_VERSION}-nightly (bad)\nrelease: ${RUST_VERSION}-nightly` }],
  ];
  for (const [name, overrides] of cases) {
    const badBytes = makeBinary({ ...f.identity, ...overrides });
    const entry = { ...f.entry, release_source: { ...f.entry.release_source, bytes: badBytes.length, sha256: digest(badBytes) } };
    await assert.rejects(
      prepareBootstrap(f.releaseOptions, {
        ...f.noToolchainDeps,
        prebuiltCores: [entry],
        fetch: async () => chunkedResponse(badBytes),
      }),
      error => {
        assert.equal(error.code, 'artifact_identity_mismatch', name);
        assert.equal(error.exitCode, 4, name);
        assert.match(error.message, /--build-from-source/, name);
        assert.match(error.message, /1\.98\.0/, name);
        assert.match(error.message, /compiler/i, name);
        return true;
      },
    );
    assert.deepEqual(await readdir(join(f.releaseOptions.cacheDir, 'entries')), [], name);
    assert.deepEqual(await readdir(join(f.releaseOptions.cacheDir, 'ready')), [], name);
    assert.deepEqual(await readdir(join(f.releaseOptions.cacheDir, 'staging')), [], name);
  }

  const unstartable = Buffer.from('\x7fELFnot-a-runnable-executable-on-this-host');
  const unstartableEntry = {
    ...f.entry,
    release_source: { ...f.entry.release_source, bytes: unstartable.length, sha256: digest(unstartable) },
  };
  const realIdentityDeps = {
    ...f.noToolchainDeps,
    prebuiltCores: [unstartableEntry],
    fetch: async () => chunkedResponse(unstartable),
  };
  delete realIdentityDeps.readIdentity;
  await assert.rejects(
    prepareBootstrap(f.releaseOptions, realIdentityDeps),
    error => {
      assert.equal(error.code, 'artifact_identity_failed');
      assert.equal(error.exitCode, 4);
      assert.match(error.message, /--build-from-source/);
      assert.match(error.message, /1\.98\.0/);
      assert.match(error.message, /compiler/i);
      return true;
    },
  );
  assert.deepEqual(await readdir(join(f.releaseOptions.cacheDir, 'entries')), []);
  assert.deepEqual(await readdir(join(f.releaseOptions.cacheDir, 'ready')), []);
  assert.deepEqual(await readdir(join(f.releaseOptions.cacheDir, 'staging')), []);
});

test('download interruption cleans up staging and locks and preserves prior ready entry', async t => {
  for (const [signal, exitCode] of [['SIGINT', 130], ['SIGTERM', 143], ['SIGHUP', 129]]) {
    const f = await prebuiltFixture(t);
    const before = process.listenerCount(signal);
    const deps = {
      ...f.noToolchainDeps,
      fetch: async () => {
        setImmediate(() => process.emit(signal));
        return new Response(new ReadableStream({ pull() { return new Promise(() => {}); } }));
      },
    };
    await assert.rejects(prepareBootstrap(f.releaseOptions, deps), { code: 'interrupted', exitCode });
    assert.equal(process.listenerCount(signal), before, signal);
    assert.deepEqual(await readdir(join(f.releaseOptions.cacheDir, 'staging')), [], signal);
    assert.deepEqual(await readdir(join(f.releaseOptions.cacheDir, 'locks')), [], signal);
    assert.deepEqual(await readdir(join(f.releaseOptions.cacheDir, 'entries')), [], signal);
    assert.deepEqual(await readdir(join(f.releaseOptions.cacheDir, 'ready')), [], signal);
  }
});

test('--build-from-source, --profile dev, and dirty checkout with --allow-dirty build locally even when a prebuilt entry matches', async t => {
  for (const mode of ['build-from-source', 'dev', 'dirty']) {
    const f = await prebuiltFixture(t);
    if (mode === 'dirty') f.state.dirty = true;
    const options = {
      ...f.releaseOptions,
      ...(mode === 'build-from-source' ? { buildFromSource: true } : {}),
      ...(mode === 'dev' ? { profile: 'dev' } : {}),
      ...(mode === 'dirty' ? { allowDirty: true } : {}),
    };
    const result = await prepareBootstrap(options, {
      ...f.deps,
      prebuiltCores: [f.entry],
      fetch: async () => { throw new Error(`fetch must not run for ${mode}`); },
    });
    assert.equal(result.core_source, 'local_build', mode);
    assert.equal(result.receipt.core_source, 'local_build', mode);
    assert.equal(Object.hasOwn(result.receipt.cache_identity, 'prebuilt'), false, mode);
    assert.equal(f.state.builds, 1, mode);
  }
});

test('--offline uses cached prebuilt, falls back to local build when uncached, and gives prebuilt guidance if toolchain is missing', async t => {
  const f = await prebuiltFixture(t);
  await prepareBootstrap(f.releaseOptions, f.noToolchainDeps);
  const cachedOffline = await prepareBootstrap({ ...f.releaseOptions, offline: true }, {
    ...f.noToolchainDeps,
    fetch: async () => { throw new Error('offline cache hit must not fetch'); },
  });
  assert.equal(cachedOffline.cache_hit, true);
  assert.equal(cachedOffline.core_source, 'prebuilt_release');

  const g = await prebuiltFixture(t);
  const builtOffline = await prepareBootstrap({ ...g.releaseOptions, offline: true }, {
    ...g.deps,
    prebuiltCores: [g.entry],
    fetch: async () => { throw new Error('offline fallback must not fetch'); },
  });
  assert.equal(builtOffline.core_source, 'local_build');
  assert.equal(g.state.builds, 1);
  assert.equal(g.state.offline, true);

  const h = await prebuiltFixture(t);
  const missingToolchainDeps = { ...h.deps, prebuiltCores: [h.entry], environment: { PATH: join(h.root, 'missing-tools'), HOME: join(h.root, 'home') } };
  delete missingToolchainDeps.inspectToolchain;
  await assert.rejects(
    prepareBootstrap({ ...h.releaseOptions, offline: true }, missingToolchainDeps),
    error => {
      assert.equal(error.code, 'rust_toolchain_unavailable');
      // The download is the shorter way for a beginner, so it leads; the local build follows.
      assert.match(error.message, /^This checkout has a prebuilt scanner core: run prepare once without --offline to download it\. To build offline instead: .*Rust/);
      return true;
    },
  );
});

test('two matching entries or a malformed entry fail closed without building or downloading', async t => {
  const f = await prebuiltFixture(t);
  await assert.rejects(
    prepareBootstrap(f.releaseOptions, { ...f.noToolchainDeps, prebuiltCores: [f.entry, { ...f.entry, product_version: '0.0.1-fixture' }] }),
    { code: 'ambiguous_prebuilt_core', exitCode: 4 },
  );
  for (const bad of [
    'not-an-array',
    [null],
    [{ input_sha256: f.manifest.inputDigest, platform: process.platform, targets: null }],
    [{ ...f.entry, release_source: 'bad' }],
  ]) {
    await assert.rejects(
      prepareBootstrap(f.releaseOptions, { ...f.noToolchainDeps, prebuiltCores: bad }),
      { code: 'invalid_prebuilt_core', exitCode: 4 },
    );
  }
  await assert.rejects(readdir(f.releaseOptions.cacheDir), { code: 'ENOENT' });
});

test('loadPreparedBootstrap refuses removed/changed allowlist entry, dirty checkout for prebuilt, and tampered binary bytes before execution', async t => {
  const f = await prebuiltFixture(t);
  const prepared = await prepareBootstrap(f.releaseOptions, f.noToolchainDeps);

  await assert.rejects(
    loadPreparedBootstrap(f.releaseOptions, { ...f.noToolchainDeps, prebuiltCores: [] }),
    { code: 'core_not_prepared', exitCode: 2 },
  );
  await assert.rejects(
    loadPreparedBootstrap(f.releaseOptions, { ...f.noToolchainDeps, prebuiltCores: [{ ...f.entry, product_version: '0.0.1-fixture' }] }),
    { code: 'core_not_prepared', exitCode: 2 },
  );

  f.state.dirty = true;
  await assert.rejects(
    loadPreparedBootstrap({ ...f.releaseOptions, allowDirty: true }, f.noToolchainDeps),
    { code: 'core_not_prepared', exitCode: 2 },
  );
  f.state.dirty = false;

  const tampered = Buffer.alloc(f.bytes.length, 0x41);
  await writeFile(prepared.executable, tampered, { mode: 0o700 });
  const beforeCalls = f.prebuiltState.readIdentities;
  await assert.rejects(
    loadPreparedBootstrap(f.releaseOptions, f.noToolchainDeps),
    { code: 'artifact_digest_mismatch' },
  );
  assert.equal(f.prebuiltState.readIdentities, beforeCalls);

  // The receipt and ready pointer are rewritten to agree with the replaced file,
  // so only the comparison with the pin can refuse it.
  const canonical = value => Array.isArray(value) ? `[${value.map(canonical).join(',')}]`
    : value && typeof value === 'object' ? `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`
      : JSON.stringify(value);
  const forged = Buffer.concat([f.bytes, Buffer.from('// replaced after download\n')]);
  await writeFile(prepared.executable, forged, { mode: 0o700 });
  const receiptPath = join(prepared.entry_directory, 'receipt.json');
  const { receipt_sha256: recordedDigest, ...body } = JSON.parse(await readFile(receiptPath, 'utf8'));
  assert.equal(recordedDigest, digest(canonical(body)));
  body.artifacts = body.artifacts.map(record => ({ ...record, sha256: digest(forged), size: forged.length }));
  const forgedReceipt = { ...body, receipt_sha256: digest(canonical(body)) };
  await writeFile(receiptPath, `${JSON.stringify(forgedReceipt, null, 2)}\n`);
  const readyPath = join(f.releaseOptions.cacheDir, 'ready', `core-release-${f.entry.targets[process.arch]}.json`);
  const pointer = JSON.parse(await readFile(readyPath, 'utf8'));
  await writeFile(readyPath, `${JSON.stringify({ ...pointer, receipt_sha256: forgedReceipt.receipt_sha256 })}\n`);
  const fetchesBeforeForgery = f.prebuiltState.fetches;
  for (const attempt of [loadPreparedBootstrap, prepareBootstrap]) {
    await assert.rejects(
      attempt(f.releaseOptions, f.noToolchainDeps),
      error => {
        assert.equal(error.code, 'artifact_digest_mismatch', attempt.name);
        assert.match(error.message, /pinned release/, attempt.name);
        assert.match(error.message, /--cache-dir/, attempt.name);
        return true;
      },
    );
  }
  assert.equal(f.prebuiltState.readIdentities, beforeCalls);
  assert.equal(f.prebuiltState.fetches, fetchesBeforeForgery);

  const g = await fixture(t);
  await prepareBootstrap(g.options, g.deps);
  g.state.dirty = true;
  const localAllowedDirty = await loadPreparedBootstrap({ ...g.options, allowDirty: true }, {
    ...g.deps,
    inspectToolchain: () => { throw new Error('run must not inspect toolchain'); },
  });
  assert.equal(localAllowedDirty.receipt.core_source, 'local_build');
});

test('doctor reports core_sources, marks tools not required when prebuilt applies, and creates nothing', async t => {
  const f = await prebuiltFixture(t);
  const missingDeps = {
    ...f.noToolchainDeps,
    environment: { PATH: join(f.root, 'missing-tools'), HOME: join(f.root, 'home') },
  };
  delete missingDeps.inspectToolchain;

  const downloadable = await doctorBootstrap(f.releaseOptions, missingDeps);
  assert.equal(downloadable.ready, true);
  assert.deepEqual(downloadable.core_sources, { prebuilt_release: 'downloadable', local_build: 'unavailable' });
  const rustCheck = downloadable.checks.find(c => c.name === 'rust_toolchain');
  const ccCheck = downloadable.checks.find(c => c.name === 'native_compiler_and_linker');
  assert.equal(rustCheck.ready, false);
  assert.equal(rustCheck.required, false);
  assert.doesNotMatch(rustCheck.reason, /--offline/);
  assert.equal(ccCheck.ready, false);
  assert.equal(ccCheck.required, false);
  await assert.rejects(lstat(f.releaseOptions.cacheDir), { code: 'ENOENT' });

  const offlineUncached = await doctorBootstrap({ ...f.releaseOptions, offline: true }, missingDeps);
  assert.equal(offlineUncached.ready, false);
  assert.deepEqual(offlineUncached.core_sources, { prebuilt_release: 'not_selected', local_build: 'unavailable' });
  assert.match(offlineUncached.checks.find(c => c.name === 'rust_toolchain').reason, /^This checkout has a prebuilt scanner core: run prepare once without --offline to download it\./);

  const devDoctor = await doctorBootstrap({ ...f.releaseOptions, profile: 'dev' }, missingDeps);
  assert.equal(devDoctor.ready, false);
  assert.deepEqual(devDoctor.core_sources, { prebuilt_release: 'not_selected', local_build: 'unavailable' });
  assert.doesNotMatch(devDoctor.checks.find(c => c.name === 'rust_toolchain').reason, /--offline/);

  const fromSourceDoctor = await doctorBootstrap({ ...f.releaseOptions, buildFromSource: true }, missingDeps);
  assert.equal(fromSourceDoctor.ready, false);
  assert.deepEqual(fromSourceDoctor.core_sources, { prebuilt_release: 'not_selected', local_build: 'unavailable' });

  const notListed = await doctorBootstrap(f.releaseOptions, { ...missingDeps, prebuiltCores: [] });
  assert.equal(notListed.ready, false);
  assert.deepEqual(notListed.core_sources, { prebuilt_release: 'not_listed', local_build: 'unavailable' });
  assert.equal(Object.hasOwn(notListed.checks.find(c => c.name === 'rust_toolchain'), 'required'), false);

  const preparedCore = await prepareBootstrap(f.releaseOptions, f.noToolchainDeps);
  const cached = await doctorBootstrap({ ...f.releaseOptions, offline: true }, missingDeps);
  assert.equal(cached.ready, true);
  assert.deepEqual(cached.core_sources, { prebuilt_release: 'cached', local_build: 'unavailable' });
  assert.equal(cached.checks.some(c => c.name === 'prebuilt_core'), false);

  // `prepare` refuses a cached entry that fails verification and never downloads
  // over it, so the doctor must not offer it as cached or downloadable.
  const identitiesBefore = f.prebuiltState.readIdentities;
  await writeFile(preparedCore.executable, Buffer.alloc(f.bytes.length, 0x41), { mode: 0o700 });
  for (const offline of [false, true]) {
    const refused = await doctorBootstrap({ ...f.releaseOptions, offline }, missingDeps);
    assert.equal(refused.ready, false, `offline=${offline}`);
    assert.deepEqual(refused.core_sources, { prebuilt_release: 'cache_entry_refused', local_build: 'unavailable' });
    const refusal = refused.checks.find(c => c.name === 'prebuilt_core');
    assert.equal(refusal.ready, false);
    assert.equal(refusal.error, 'artifact_digest_mismatch');
    assert.match(refusal.reason, /--cache-dir/);
    assert.match(refusal.reason, /--build-from-source/);
    await assert.rejects(prepareBootstrap({ ...f.releaseOptions, offline }, f.noToolchainDeps), { code: 'artifact_digest_mismatch' });
  }
  assert.equal(f.prebuiltState.fetches, 1);
  assert.equal(f.prebuiltState.readIdentities, identitiesBefore);
});

test('supports Windows installer-runtime-cache feature list and macOS universal dual-arch targets', async t => {
  if (process.platform !== 'win32') {
    const win = await prebuiltFixture(t, {
      platform: 'win32',
      arch: 'x64',
      targets: { x64: 'x86_64-pc-windows-msvc' },
      features: ['cli', 'installer-runtime-cache'],
    });
    const prepared = await prepareBootstrap(win.releaseOptions, win.noToolchainDeps);
    assert.ok(prepared.executable.endsWith('.exe'));
    assert.deepEqual(prepared.receipt.cache_identity.features, ['cli']);
    assert.deepEqual(prepared.receipt.cache_identity.prebuilt.features, ['cli', 'installer-runtime-cache']);
    const loaded = await loadPreparedBootstrap(win.releaseOptions, win.noToolchainDeps);
    assert.equal(loaded.executable, prepared.executable);
  }

  for (const [arch, target] of [['arm64', 'aarch64-apple-darwin'], ['x64', 'x86_64-apple-darwin']]) {
    const mac = await prebuiltFixture(t, {
      platform: 'darwin',
      arch,
      targets: { arm64: 'aarch64-apple-darwin', x64: 'x86_64-apple-darwin' },
      identityOverrides: { target },
    });
    const prepared = await prepareBootstrap(mac.releaseOptions, mac.noToolchainDeps);
    assert.equal(prepared.receipt.cache_identity.toolchain.target, target);
    const loaded = await loadPreparedBootstrap(mac.releaseOptions, mac.noToolchainDeps);
    assert.equal(loaded.cache_key, prepared.cache_key);
  }
});

test('editing prebuilt-cores.mjs invalidates the recipe and fails clean pin validation when hidden', async t => {
  const f = await fixture(t);
  const first = await prepareBootstrap({ ...f.options, profile: 'release' }, f.deps);
  await writeFile(join(f.source, 'scripts', 'skill', 'prebuilt-cores.mjs'), '// modified prebuilt list\n');
  const second = await prepareBootstrap({ ...f.options, profile: 'release' }, f.deps);
  assert.notEqual(second.cache_key, first.cache_key);
});
