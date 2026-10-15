import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';

const runtime = resolve(import.meta.dirname, '../../runtime');
const locked = JSON.parse(readFileSync(join(runtime, 'upstreams.lock.json'), 'utf8'));

function verify(mutate = () => {}, mutatePatch = false) {
  const directory = mkdtempSync(join(tmpdir(), 'windows-runtime-build-test-'));
  try {
    for (const name of ['vendor-managed-runtime.mjs', 'podman-wsl-native-systemd.patch']) {
      cpSync(join(runtime, name), join(directory, name));
    }
    const lock = structuredClone(locked);
    mutate(lock);
    writeFileSync(join(directory, 'upstreams.lock.json'), JSON.stringify(lock));
    if (mutatePatch) writeFileSync(join(directory, 'podman-wsl-native-systemd.patch'), 'substituted patch\n');
    return spawnSync(process.execPath, [
      join(directory, 'vendor-managed-runtime.mjs'),
      '--target', 'x86_64-pc-windows-msvc', '--verify-lock-only',
    ], { encoding: 'utf8', timeout: 30_000 });
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

test('the reviewed Windows source build passes its offline lock check', () => {
  const result = verify();
  assert.equal(result.status, 0, result.stderr);
});

test('a source archive from a different upstream revision is rejected before downloading', () => {
  const result = verify((lock) => { lock.runtime.source_revision = '0'.repeat(40); });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /exact upstream runtime revision/);
});

test('substituting the local source patch fails its locked identity check', () => {
  const result = verify(() => {}, true);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /source patch differs from its locked size/);
});

test('a different Go version cannot reuse the locked toolchain downloads', () => {
  const result = verify((lock) => { lock.windows_podman_build.go_version = '1.27.3'; });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /exact version and build platform/);
});

test('enabling cgo or removing reproducible build flags is rejected', () => {
  for (const [name, value] of [['cgo_enabled', true], ['trimpath', false], ['buildvcs', true]]) {
    const result = verify((lock) => { lock.windows_podman_build.build_contract[name] = value; });
    assert.equal(result.status, 1, name);
    assert.match(result.stderr, /offline reproducible remote-client contract/);
  }
});
