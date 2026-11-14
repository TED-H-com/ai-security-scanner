import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, readdir, rm, writeFile, chmod, symlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { gunzipSync } from 'node:zlib';
import { downloadReleaseBundle, extractReleaseBundle, verifyReleaseBundle } from '../../scripts/skill/release-bundle.mjs';
import { RECOGNIZED_MANAGED_RUNTIME_BUNDLES } from '../../scripts/skill/managed-runtime-bundles.mjs';
import { appPackageFixture, chunkedResponse, debFromTar, innerPath, macInnerPath, packageFixture, tarEntry } from './release-bundle-fixture.mjs';

async function fixture(t) {
  const root = await mkdtemp(join(tmpdir(), 'release-bundle-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  return { root, file: join(root, 'package.deb'), bundle: join(root, 'bundle') };
}
async function extract(f, bytes) {
  await writeFile(f.file, bytes);
  await mkdir(f.bundle);
  return extractReleaseBundle(f.file, 'deb', innerPath, f.bundle);
}

test('download follows HTTPS redirects without credentials, streams and verifies before extraction', async t => {
  const f = await fixture(t); const p = packageFixture(); const calls = [];
  const fetch = async (url, options) => {
    calls.push([String(url), options]);
    if (calls.length === 1) return new Response(null, { status: 302, headers: { location: 'https://cdn.example.test/package' } });
    return chunkedResponse(p.bytes, { headers: { 'content-length': String(p.bytes.length) } });
  };
  await downloadReleaseBundle(p.source, f.file, { fetch });
  assert.equal(calls.length, 2);
  assert.equal(calls[1][0], 'https://cdn.example.test/package');
  for (const [, options] of calls) { assert.equal(options.redirect, 'manual'); assert.equal(options.credentials, 'omit'); assert.equal(options.headers, undefined); }
  assert.deepEqual(await readFile(f.file), p.bytes);
  await mkdir(f.bundle);
  await extractReleaseBundle(f.file, 'deb', innerPath, f.bundle);
  await verifyReleaseBundle(f.bundle, p.manifestSha);
  assert.deepEqual((await readdir(f.bundle)).sort(), ['bin', 'manifest.json', 'notes.txt']);
});

test('macOS app archive extracts and verifies only its GNU runtime files and modes', async t => {
  const f = await fixture(t); const p = appPackageFixture();
  const tar = gunzipSync(p.bytes);
  const modes = new Map();
  for (let pos = 0; tar[pos] !== 0;) {
    const header = tar.subarray(pos, pos + 512);
    assert.equal(header.subarray(257, 265).toString('binary'), 'ustar  \0');
    assert.ok(header.subarray(345, 500).every(byte => byte === 0));
    const name = header.subarray(0, 100).toString('utf8').replace(/\0.*$/s, '');
    const size = Number.parseInt(header.subarray(124, 136).toString('ascii'), 8);
    modes.set(name, Number.parseInt(header.subarray(100, 108).toString('ascii'), 8));
    pos += 512 + Math.ceil(size / 512) * 512;
  }
  assert.equal(modes.get(`${macInnerPath}/manifest.json`), 0o100600);
  for (const file of p.files) assert.equal(modes.get(`${macInnerPath}/${file.path}`), 0o100700);
  await writeFile(f.file, p.bytes);
  await mkdir(f.bundle);
  await extractReleaseBundle(f.file, 'tar.gz', macInnerPath, f.bundle);
  await verifyReleaseBundle(f.bundle, p.manifestSha);
  assert.deepEqual((await readdir(f.bundle)).sort(), ['bin', 'manifest.json']);
  assert.deepEqual((await readdir(join(f.bundle, 'bin'))).sort(), ['gvproxy', 'podman', 'vfkit']);
  if (process.platform !== 'win32') {
    const { lstat } = await import('node:fs/promises');
    assert.equal((await lstat(join(f.bundle, 'manifest.json'))).mode & 0o777, 0o600);
    for (const file of p.files) assert.equal((await lstat(join(f.bundle, file.path))).mode & 0o777, 0o700);
  }
});

test('archive kind mismatches and unknown kinds are refused', async t => {
  for (const [pkg, kind, message] of [
    [packageFixture(), 'tar.gz', 'invalid archive'],
    [appPackageFixture(), 'deb', 'invalid package header'],
  ]) {
    const f = await fixture(t);
    await writeFile(f.file, pkg.bytes);
    await mkdir(f.bundle);
    await assert.rejects(extractReleaseBundle(f.file, kind, pkg.source.inner_path, f.bundle), { code: 'archive', message });
  }
  const missing = await fixture(t);
  await assert.rejects(extractReleaseBundle(missing.file, 'zip', innerPath, missing.bundle), { code: 'archive', message: 'unsupported package kind' });
});

test('macOS archive applies the same tar safety checks outside and inside the runtime', async t => {
  for (const [entry, message] of [
    [tarEntry('other/link', '', { format: 'gnu', type: '2' }), 'unsupported tar entry'],
    [tarEntry(`${macInnerPath}/../escape`, '', { format: 'gnu' }), 'unsafe path'],
    [tarEntry(`${macInnerPath}/bin/gvproxy`, '', { format: 'gnu' }), 'runtime entry limit or duplicate'],
  ]) {
    const f = await fixture(t); const p = appPackageFixture({ extra: [entry] });
    await writeFile(f.file, p.bytes);
    await mkdir(f.bundle);
    await assert.rejects(extractReleaseBundle(f.file, 'tar.gz', macInnerPath, f.bundle), { code: 'archive', message });
  }
});

test('download rejects size, checksum, HTTP, redirect and stalled transfers, removing partial files', async t => {
  const p = packageFixture();
  const cases = [
    { name: 'content length', fetch: async () => chunkedResponse(p.bytes, { headers: { 'content-length': '1' } }), code: 'size', message: 'content length mismatch' },
    { name: 'digest', source: { ...p.source, sha256: '0'.repeat(64) }, fetch: async () => chunkedResponse(p.bytes), code: 'digest', message: 'download checksum mismatch' },
    { name: 'oversize', source: { ...p.source, bytes: 3 }, fetch: async () => chunkedResponse(p.bytes, { chunkSize: 4 }), code: 'size', message: 'download size exceeded' },
    { name: 'http hop', fetch: async () => new Response(null, { status: 302, headers: { location: 'http://example.test' } }), code: 'network', message: 'insecure download URL' },
    { name: 'six redirects', fetch: async () => new Response(null, { status: 302, headers: { location: '/again' } }), code: 'network', message: 'too many redirects' },
    { name: '404', fetch: async () => new Response(null, { status: 404 }), code: 'network', message: 'HTTP 404' },
    { name: 'stall', fetch: async () => new Response(new ReadableStream({ pull() { return new Promise(() => {}); } })), code: 'network', message: 'download stalled', stallMs: 20 },
  ];
  for (const item of cases) {
    const f = await fixture(t); const requested = [];
    const fetch = async (...args) => { requested.push(args[0]); return item.fetch(...args); };
    await assert.rejects(downloadReleaseBundle(item.source ?? p.source, f.file, { fetch, stallMs: item.stallMs }), { code: item.code, message: item.message }, item.name);
    if (item.name === 'http hop') {
      assert.deepEqual(requested, [p.source.url]);
      assert.ok(requested.every(url => new URL(url).protocol === 'https:'));
    }
    await assert.rejects(readFile(f.file), { code: 'ENOENT' }, item.name);
  }
});

test('archive rejects unsafe paths, types and malformed tar anywhere', async t => {
  const cases = [
    ['symlink inside', tarEntry(`${innerPath}/link`, '', { type: '2' }), 'unsupported tar entry'],
    ['hard link outside', tarEntry('unrelated/link', '', { type: '1' }), 'unsupported tar entry'],
    ['parent segment', tarEntry(`${innerPath}/../escape`, ''), 'unsafe path'],
    ['absolute', tarEntry('/outside', ''), 'unsafe path'],
    ['duplicate', tarEntry(`${innerPath}/notes.txt`, ''), 'runtime entry limit or duplicate'],
    ['checksum', tarEntry('unrelated/bad', '', { corrupt: true }), 'invalid tar header'],
  ];
  for (const [name, entry, message] of cases) {
    const f = await fixture(t);
    await assert.rejects(extract(f, packageFixture({ extra: [entry] }).bytes), { code: 'archive', message }, name);
  }
  const f = await fixture(t);
  await assert.rejects(extract(f, packageFixture({ removeEnd: true }).bytes), { code: 'archive', message: 'truncated tar' });
});

test('bundle verification rejects extra files, wrong manifest, links and executable mode', async t => {
  for (const scenario of ['extra', 'manifest', 'link', 'mode']) {
    if (process.platform === 'win32' && (scenario === 'link' || scenario === 'mode')) continue;
    const f = await fixture(t); const p = packageFixture();
    await extract(f, p.bytes);
    if (scenario === 'extra') await writeFile(join(f.bundle, 'extra'), 'x');
    if (scenario === 'link') await symlink('notes.txt', join(f.bundle, 'link'));
    if (scenario === 'mode') await chmod(join(f.bundle, 'bin', 'tool'), 0o600);
    const message = { extra: 'unexpected bundle file', manifest: 'manifest digest mismatch', link: 'invalid bundle entry', mode: 'bundle file mismatch' }[scenario];
    await assert.rejects(verifyReleaseBundle(f.bundle, scenario === 'manifest' ? '0'.repeat(64) : p.manifestSha), { code: 'bundle', message }, scenario);
  }
});

test('real published release bundles download and verify', { skip: process.env.AI_SCANNER_REAL_RELEASE_BUNDLE !== '1', timeout: 900_000 }, async t => {
  for (const entry of RECOGNIZED_MANAGED_RUNTIME_BUNDLES.filter(item => item.release_source)) {
    await t.test(entry.platform, async t => {
      const f = await fixture(t);
      await downloadReleaseBundle(entry.release_source, f.file, { fetch: globalThis.fetch });
      await mkdir(f.bundle);
      await extractReleaseBundle(f.file, entry.release_source.kind, entry.release_source.inner_path, f.bundle);
      await verifyReleaseBundle(f.bundle, entry.manifest_sha256);
      const manifest = JSON.parse(await readFile(join(f.bundle, 'manifest.json'), 'utf8'));
      if (entry.platform === 'linux') assert.equal(manifest.files.length, 114);
      if (entry.platform === 'darwin') assert.equal(manifest.files.length, 3);
    });
  }
});

test('oversize body is cancelled before the remaining chunks are read', async t => {
  const f = await fixture(t); const p = packageFixture(); let pulls = 0; let cancelled = false;
  const fetch = async () => new Response(new ReadableStream({
    pull(controller) { pulls += 1; controller.enqueue(new Uint8Array([1, 2, 3, 4])); },
    cancel() { cancelled = true; },
  }));
  await assert.rejects(downloadReleaseBundle({ ...p.source, bytes: 3 }, f.file, { fetch }), { code: 'size', message: 'download size exceeded' });
  assert.ok(pulls < 5);
  assert.equal(cancelled, true);
  await assert.rejects(readFile(f.file), { code: 'ENOENT' });
});

test('archive rejects duplicate or unsupported data members and invalid debian version', async t => {
  const { arMember } = await import('./release-bundle-fixture.mjs');
  const ar = (...members) => Buffer.concat([Buffer.from('!<arch>\n'), ...members]);
  for (const [bytes, message] of [
    [ar(arMember('debian-binary', '1.0\n'), arMember('data.tar.gz', 'x')), 'invalid package version'],
    [ar(arMember('debian-binary', '2.0\n'), arMember('data.tar.xz', 'x')), 'unsupported package compression'],
    [ar(arMember('debian-binary', '2.0\n'), arMember('data.tar.zst', 'x')), 'unsupported package compression'],
    [ar(arMember('debian-binary', '2.0\n'), arMember('data.tar.gz', 'x'), arMember('data.tar.gz', 'x')), 'duplicate data member'],
    [ar(arMember('debian-binary', '2.0\n')), 'missing data member'],
  ]) {
    const f = await fixture(t);
    await assert.rejects(extract(f, bytes), { code: 'archive', message });
  }
});

test('tar rejects non-ustar headers, base-256 sizes and unsafe directory paths', async t => {
  const prefix = `${innerPath}/`;
  const entries = [
    [tarEntry(`${prefix}back\\slash`, 'x'), 'unsafe path'],
    [tarEntry('C:/absolute', 'x'), 'unsafe path'],
    [tarEntry(`${prefix}empty//segment`, 'x'), 'unsafe path'],
    [tarEntry(`${prefix}dir/../file`, 'x'), 'unsafe path'],
    [tarEntry(`${prefix}pax`, '', { type: 'x' }), 'unsupported tar entry'],
    [tarEntry('other', '', { type: 'L' }), 'unsupported tar entry'],
  ];
  const badSize = tarEntry('other', '');
  badSize[124] = 0x80;
  badSize.fill(32, 148, 156);
  badSize.write(badSize.subarray(0, 512).reduce((sum, byte) => sum + byte, 0).toString(8).padStart(7, '0') + '\0', 148, 8, 'ascii');
  entries.push([badSize, 'unsupported tar number']);
  const badMagic = tarEntry('other', '');
  badMagic.write('nontar', 257, 6, 'ascii');
  badMagic.fill(32, 148, 156);
  badMagic.write(badMagic.subarray(0, 512).reduce((sum, byte) => sum + byte, 0).toString(8).padStart(7, '0') + '\0', 148, 8, 'ascii');
  entries.push([badMagic, 'invalid tar header']);
  const badGnuVersion = tarEntry('other', '', { format: 'gnu' });
  badGnuVersion[264] = 49;
  badGnuVersion.fill(32, 148, 156);
  badGnuVersion.write(badGnuVersion.subarray(0, 512).reduce((sum, byte) => sum + byte, 0).toString(8).padStart(7, '0') + '\0', 148, 8, 'ascii');
  entries.push([badGnuVersion, 'invalid tar header']);
  for (const [entry, message] of entries) {
    const f = await fixture(t);
    await assert.rejects(extract(f, packageFixture({ extra: [entry] }).bytes), { code: 'archive', message });
  }
});

test('verification rejects missing files, invalid manifests and file content changes', async t => {
  for (const variant of ['missing', 'content', 'duplicate', 'unsafe']) {
    const f = await fixture(t);
    const badManifest = variant === 'duplicate'
      ? { files: [{ path: 'a', sha256: '0'.repeat(64), size_bytes: 1, executable: false }, { path: 'a', sha256: '0'.repeat(64), size_bytes: 1, executable: false }] }
      : variant === 'unsafe' ? { files: [{ path: '../a', sha256: '0'.repeat(64), size_bytes: 1, executable: false }] } : undefined;
    const p = packageFixture({ manifestOverride: badManifest });
    await extract(f, p.bytes);
    if (variant === 'missing') await rm(join(f.bundle, 'notes.txt'));
    if (variant === 'content') await writeFile(join(f.bundle, 'notes.txt'), 'changed!\n');
    const message = { missing: 'missing bundle file', content: 'bundle file mismatch', duplicate: 'invalid manifest entry', unsafe: 'unsafe path' }[variant];
    await assert.rejects(verifyReleaseBundle(f.bundle, p.manifestSha), { code: 'bundle', message }, variant);
  }
});

test('GNU headers ignore nonzero timestamps in the POSIX prefix region', async t => {
  const f = await fixture(t);
  const p = packageFixture({ tarOptions: { format: 'gnu', atime: 1_234_567, ctime: 7_654_321 }, entryOptions: { 'notes.txt': { type: '\0' } } });
  await extract(f, p.bytes);
  assert.deepEqual((await readdir(f.bundle)).sort(), ['bin', 'manifest.json', 'notes.txt']);
  assert.equal(await readFile(join(f.bundle, 'notes.txt'), 'utf8'), 'contents\n');
  assert.equal(await readFile(join(f.bundle, 'bin', 'tool'), 'utf8'), 'executable\n');
  await verifyReleaseBundle(f.bundle, p.manifestSha);
});

test('GNU long-name, sparse and pax entries are refused inside or outside the runtime', async t => {
  for (const type of ['L', 'K', 'S', 'x', 'g']) {
    for (const name of [`${innerPath}/unsupported`, 'outside/unsupported']) {
      const f = await fixture(t);
      const p = packageFixture({ tarOptions: { format: 'gnu' }, extra: [tarEntry(name, 'name', { format: 'gnu', type })] });
      await assert.rejects(extract(f, p.bytes), { code: 'archive', message: 'unsupported tar entry' }, `${type} ${name}`);
    }
  }
});

test('ustar prefixes work and extracted modes are private', { skip: process.platform === 'win32' }, async t => {
  const { lstat } = await import('node:fs/promises');
  const f = await fixture(t);
  const p = packageFixture({ extra: [tarEntry('nested/', '', { type: '5', mode: 0o755, prefix: innerPath }), tarEntry('nested/prefixed', 'inside', { mode: 0o755, prefix: innerPath })] });
  await extract(f, p.bytes);
  assert.equal(await readFile(join(f.bundle, 'nested', 'prefixed'), 'utf8'), 'inside');
  for (const path of [f.bundle, join(f.bundle, 'bin'), join(f.bundle, 'nested'), join(f.bundle, 'nested', 'prefixed')]) assert.equal((await lstat(path)).mode & 0o777, 0o700);
  assert.equal((await lstat(join(f.bundle, 'manifest.json'))).mode & 0o777, 0o600);
});

test('archive enforces entry, depth and declared data limits before writing beyond them', async t => {
  const extras = [
    Array.from({ length: 125 }, (_, index) => tarEntry(`${innerPath}/extra-${index}`, '')),
    [tarEntry(`${innerPath}/${Array(17).fill('a').join('/')}`, '')],
  ];
  for (const entries of extras) {
    const f = await fixture(t);
    await assert.rejects(extract(f, packageFixture({ extra: entries }).bytes), { code: 'archive', message: 'runtime entry limit or duplicate' });
  }
  const tooBig = tarEntry(`${innerPath}/huge`, '');
  tooBig.write((2 * 1024 ** 3 + 1).toString(8).padStart(11, '0') + '\0', 124, 12, 'ascii');
  tooBig.fill(32, 148, 156);
  tooBig.write(tooBig.subarray(0, 512).reduce((sum, byte) => sum + byte, 0).toString(8).padStart(7, '0') + '\0', 148, 8, 'ascii');
  const f = await fixture(t);
  await assert.rejects(extract(f, debFromTar(Buffer.concat([tooBig, Buffer.alloc(1024)]))), { code: 'archive', message: 'runtime data too large' });
  assert.deepEqual(await readdir(f.bundle), []);
});

test('five HTTPS redirects are allowed and a sixth is refused without another request', async t => {
  const p = packageFixture();
  for (const redirects of [5, 6]) {
    const f = await fixture(t); let calls = 0;
    const fetch = async () => {
      calls += 1;
      return calls <= redirects ? new Response(null, { status: 307, headers: { location: `/hop-${calls}` } }) : chunkedResponse(p.bytes);
    };
    if (redirects === 5) await downloadReleaseBundle(p.source, f.file, { fetch });
    else await assert.rejects(downloadReleaseBundle(p.source, f.file, { fetch }), { code: 'network', message: 'too many redirects' });
    assert.equal(calls, 6);
  }
});

test('extraction and verification honor cancellation', async t => {
  const f = await fixture(t); const p = packageFixture({ extra: [tarEntry('large-outside', Buffer.alloc(4 * 1024 * 1024))] });
  await writeFile(f.file, p.bytes);
  await mkdir(f.bundle);
  const extraction = new AbortController();
  setImmediate(() => extraction.abort(new Error('cancel extraction')));
  await assert.rejects(extractReleaseBundle(f.file, 'deb', innerPath, f.bundle, extraction.signal), /cancel extraction/);
  const g = await fixture(t); const normal = packageFixture();
  await extract(g, normal.bytes);
  const verification = new AbortController();
  verification.abort(new Error('cancel verification'));
  await assert.rejects(verifyReleaseBundle(g.bundle, normal.manifestSha, verification.signal), /cancel verification/);
});

test('download refuses a preexisting file and credential-bearing redirects', async t => {
  const p = packageFixture();
  const f = await fixture(t);
  await writeFile(f.file, 'keep');
  await assert.rejects(downloadReleaseBundle(p.source, f.file, { fetch: async () => chunkedResponse(p.bytes) }), { code: 'network', message: 'download failed' });
  assert.equal(await readFile(f.file, 'utf8'), 'keep');
  const g = await fixture(t); let calls = 0;
  await assert.rejects(downloadReleaseBundle(p.source, g.file, { fetch: async () => {
    calls += 1;
    return new Response(null, { status: 302, headers: { location: 'https://user:password@example.test/file' } });
  } }), { code: 'network', message: 'insecure download URL' });
  assert.equal(calls, 1);
});

test('archive rejects non-octal bytes hidden after a tar number terminator', async t => {
  const f = await fixture(t);
  const entry = tarEntry('outside/bad-number', '');
  entry.write('0000\0bad1234', 124, 12, 'ascii');
  entry.fill(32, 148, 156);
  entry.write(entry.subarray(0, 512).reduce((sum, byte) => sum + byte, 0).toString(8).padStart(7, '0') + '\0', 148, 8, 'ascii');
  await assert.rejects(extract(f, packageFixture({ extra: [entry] }).bytes), { code: 'archive', message: 'invalid tar number' });
});

test('a stalled request before headers is cancelled and leaves no partial file', async t => {
  const f = await fixture(t); const p = packageFixture(); let aborted = false;
  const fetch = async (_url, { signal }) => new Promise((_resolve, reject) => {
    signal.addEventListener('abort', () => { aborted = true; reject(new Error('cancelled')); }, { once: true });
  });
  await assert.rejects(downloadReleaseBundle(p.source, f.file, { fetch, stallMs: 20 }), { code: 'network', message: 'download stalled' });
  assert.equal(aborted, true);
  await assert.rejects(readFile(f.file), { code: 'ENOENT' });
});
