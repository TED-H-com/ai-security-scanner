import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { isAbsolute } from 'node:path';
import test from 'node:test';
import { RECOGNIZED_MANAGED_RUNTIME_BUNDLES } from '../../scripts/skill/managed-runtime-bundles.mjs';

test('recognized desktop runtime manifests match the published installer assets', async () => {
  const publication = JSON.parse(await readFile(new URL('../../docs/release/v0.6.2-publication.json', import.meta.url), 'utf8'));
  const names = {
    linux: 'managed-runtime-linux-x86_64.manifest.json',
    darwin: 'managed-runtime-macos-universal.manifest.json',
    win32: 'managed-runtime-windows-x86_64.manifest.json',
  };
  const entries = RECOGNIZED_MANAGED_RUNTIME_BUNDLES;
  assert.ok(Object.isFrozen(entries));
  assert.deepEqual(entries.map(entry => entry.platform).sort(), Object.keys(names).sort());
  assert.equal(new Set(entries.map(entry => entry.platform)).size, entries.length);
  const installed = {
    linux: { arch: ['x64'], paths: ['/usr/lib/ai-security-scanner/managed-runtime'] },
    darwin: { arch: ['x64', 'arm64'], paths: ['/Applications/ai-security-scanner.app/Contents/Resources/managed-runtime'] },
    win32: { arch: ['x64'], paths: [] },
  };
  for (const entry of entries) {
    const matching = publication.publication.assets.filter(asset => asset.name === names[entry.platform]);
    assert.equal(matching.length, 1, entry.platform);
    assert.equal(entry.product_version, '0.6.2');
    assert.equal(entry.manifest_sha256, matching[0].sha256, entry.platform);
    assert.deepEqual(entry.arch, installed[entry.platform].arch);
    assert.deepEqual(entry.installed_paths, installed[entry.platform].paths);
    assert.ok(entry.installed_paths.every(path => isAbsolute(path)), entry.platform);
  }
});
