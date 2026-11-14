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
    linux: { arch: ['x64'], paths: ['/usr/lib/ai-security-scanner/managed-runtime'], locations: [] },
    darwin: { arch: ['x64', 'arm64'], paths: ['/Applications/ai-security-scanner.app/Contents/Resources/managed-runtime'], locations: [] },
    win32: {
      arch: ['x64'],
      paths: [],
      locations: [
        { environment: 'LOCALAPPDATA', components: ['ai-security-scanner', 'managed-runtime'] },
        { environment: 'ProgramFiles', components: ['ai-security-scanner', 'managed-runtime'] },
      ],
    },
  };
  for (const entry of entries) {
    const matching = publication.publication.assets.filter(asset => asset.name === names[entry.platform]);
    assert.equal(matching.length, 1, entry.platform);
    assert.equal(entry.product_version, '0.6.2');
    assert.equal(entry.manifest_sha256, matching[0].sha256, entry.platform);
    assert.deepEqual(entry.arch, installed[entry.platform].arch);
    assert.deepEqual(entry.installed_paths, installed[entry.platform].paths);
    assert.ok(entry.installed_paths.every(path => isAbsolute(path)), entry.platform);
    assert.deepEqual(entry.installed_locations, installed[entry.platform].locations);
    assert.ok(Object.isFrozen(entry.installed_locations), entry.platform);
    for (const location of entry.installed_locations) {
      assert.ok(Object.isFrozen(location), entry.platform);
      assert.ok(Object.isFrozen(location.components), entry.platform);
      assert.ok(location.environment === 'LOCALAPPDATA' || location.environment === 'ProgramFiles', entry.platform);
    }
  }
  const tauriConf = JSON.parse(await readFile(new URL('../../src-tauri/tauri.conf.json', import.meta.url), 'utf8'));
  const installerNsi = await readFile(new URL('../../src-tauri/windows/nsis/installer.nsi', import.meta.url), 'utf8');
  assert.ok(installerNsi.includes('StrCpy $INSTDIR "$LOCALAPPDATA\\${PRODUCTNAME}"'));
  const resourceTargets = Object.values(tauriConf.bundle.resources);
  const win32Entry = entries.find(entry => entry.platform === 'win32');
  for (const location of win32Entry.installed_locations) {
    assert.equal(tauriConf.productName, location.components[0]);
    assert.ok(resourceTargets.includes(`${location.components[1]}/`));
  }
});
