import { createHash } from 'node:crypto';
import { constants, createReadStream } from 'node:fs';
import { chmod, lstat, mkdir, open, readdir, unlink } from 'node:fs/promises';
import { join } from 'node:path';
import { createGunzip } from 'node:zlib';

const MAX_TAR_BYTES = 1024 ** 3;
const MAX_BUNDLE_BYTES = 2 * 1024 ** 3;
const MAX_ENTRIES = 128;
const SHA256 = /^[a-f0-9]{64}$/;

class ReleaseBundleError extends Error {
  constructor(code, message) { super(message); this.code = code; }
}
function reject(code, message) { throw new ReleaseBundleError(code, message); }
function checkAbort(signal) { if (signal?.aborted) throw signal.reason ?? new Error('Aborted'); }
function isDiskError(error) { return error?.code === 'ENOSPC' || error?.code === 'EDQUOT'; }

// A stalled response or body read is aborted even when a fetch implementation
// does not itself respond to cancellation.
async function waitForData(promise, signal, controller, stallMs) {
  checkAbort(signal);
  let timer;
  let onAbort;
  try {
    return await Promise.race([
      promise,
      new Promise((_, rejectPromise) => {
        timer = setTimeout(() => { controller.abort(); rejectPromise(new ReleaseBundleError('network', 'download stalled')); }, stallMs);
        onAbort = () => { controller.abort(); rejectPromise(signal.reason ?? new Error('Aborted')); };
        signal?.addEventListener('abort', onAbort, { once: true });
        if (signal?.aborted) onAbort();
      }),
    ]);
  } finally {
    clearTimeout(timer);
    signal?.removeEventListener('abort', onAbort);
  }
}

export async function downloadReleaseBundle(source, file, { fetch, signal, stallMs = 30_000 }) {
  let handle; let created = false; let reader; let response;
  const controller = new AbortController();
  try {
    if (!Number.isSafeInteger(source.bytes) || source.bytes < 0 || !SHA256.test(source.sha256) || typeof fetch !== 'function') reject('network', 'invalid download source');
    let url = new URL(source.url);
    for (let redirects = 0; ; redirects += 1) {
      if (url.protocol !== 'https:' || url.username || url.password) reject('network', 'insecure download URL');
      checkAbort(signal);
      response = await waitForData(fetch(url.href, { redirect: 'manual', credentials: 'omit', signal: controller.signal }), signal, controller, stallMs);
      if ([301, 302, 303, 307, 308].includes(response.status)) {
        response.body?.cancel().catch(() => {});
        if (redirects >= 5) reject('network', 'too many redirects');
        const location = response.headers.get('location');
        if (!location) reject('network', 'redirect without location');
        url = new URL(location, url);
        continue;
      }
      if (response.status !== 200 || !response.body) reject('network', `HTTP ${response.status}`);
      break;
    }
    const length = response.headers.get('content-length');
    if (length !== null && (!/^\d+$/.test(length) || Number(length) !== source.bytes)) reject('size', 'content length mismatch');
    handle = await open(file, 'wx', 0o600);
    created = true;
    if (process.platform !== 'win32') await handle.chmod(0o600);
    reader = response.body.getReader();
    const hasher = createHash('sha256');
    let size = 0;
    let lastData = Date.now();
    for (;;) {
      const remaining = stallMs - (Date.now() - lastData);
      if (remaining <= 0) reject('network', 'download stalled');
      checkAbort(signal);
      const { value, done } = await waitForData(reader.read(), signal, controller, remaining);
      if (done) break;
      checkAbort(signal);
      const chunk = Buffer.from(value);
      if (!chunk.length) continue;
      lastData = Date.now();
      size += chunk.length;
      if (size > source.bytes) reject('size', 'download size exceeded');
      hasher.update(chunk);
      for (let position = 0; position < chunk.length;) {
        const { bytesWritten } = await handle.write(chunk, position, chunk.length - position);
        if (!bytesWritten) throw new Error('short write');
        position += bytesWritten;
      }
    }
    if (size !== source.bytes) reject('size', 'download size mismatch');
    if (hasher.digest('hex') !== source.sha256) reject('digest', 'download checksum mismatch');
    checkAbort(signal);
    await handle.close();
    handle = undefined;
  } catch (error) {
    controller.abort();
    if (reader) reader.cancel().catch(() => {});
    else response?.body?.cancel().catch(() => {});
    if (handle) { await handle.close().catch(() => {}); handle = undefined; }
    if (created) await unlink(file).catch(() => {});
    if (signal?.aborted || isDiskError(error) || error instanceof ReleaseBundleError) throw error;
    throw new ReleaseBundleError('network', 'download failed');
  } finally { await handle?.close(); }
}

async function readAt(handle, position, size) {
  const bytes = Buffer.alloc(size);
  let count = 0;
  while (count < size) {
    const part = await handle.read(bytes, count, size - count, position + count);
    if (!part.bytesRead) reject('archive', 'truncated archive');
    count += part.bytesRead;
  }
  return bytes;
}

async function dataMember(file, signal) {
  const handle = await open(file, 'r');
  try {
    const total = (await handle.stat()).size;
    if (total < 8 || (await readAt(handle, 0, 8)).toString('ascii') !== '!<arch>\n') reject('archive', 'invalid package header');
    let pos = 8; let index = 0; let data;
    while (pos < total) {
      checkAbort(signal);
      if (total - pos < 60) reject('archive', 'truncated package header');
      const header = await readAt(handle, pos, 60);
      if (header.subarray(58, 60).toString('ascii') !== '`\n') reject('archive', 'invalid package member header');
      const name = header.subarray(0, 16).toString('ascii').trim().replace(/\/$/, '');
      const field = header.subarray(48, 58).toString('ascii').trim();
      if (!/^\d+$/.test(field)) reject('archive', 'invalid package member size');
      const size = Number(field);
      if (!Number.isSafeInteger(size) || pos + 60 + size + size % 2 > total) reject('archive', 'truncated package member');
      const start = pos + 60;
      if (index === 0 && (name !== 'debian-binary' || size !== 4 || (await readAt(handle, start, 4)).toString('ascii') !== '2.0\n')) reject('archive', 'invalid package version');
      if (name === 'data.tar.xz' || name === 'data.tar.zst') reject('archive', 'unsupported package compression');
      if (name === 'data.tar.gz') {
        if (data) reject('archive', 'duplicate data member');
        data = { start, size };
      }
      pos = start + size + size % 2;
      index += 1;
    }
    if (!data || !data.size) reject('archive', 'missing data member');
    return data;
  } finally { await handle.close(); }
}

function tarString(buffer) {
  const nul = buffer.indexOf(0);
  if (nul !== -1 && buffer.subarray(nul).some(byte => byte !== 0)) reject('archive', 'invalid tar name');
  try { return new TextDecoder('utf-8', { fatal: true }).decode(nul === -1 ? buffer : buffer.subarray(0, nul)); }
  catch { reject('archive', 'invalid tar name encoding'); }
}
function tarOctal(buffer) {
  if (buffer.some(byte => (byte & 0x80) !== 0)) reject('archive', 'unsupported tar number');
  const text = buffer.toString('latin1');
  if (!/^ *[0-7]+[ \0]*$/.test(text)) reject('archive', 'invalid tar number');
  const value = Number.parseInt(text.trim(), 8);
  if (!Number.isSafeInteger(value)) reject('archive', 'oversized tar number');
  return value;
}
function safePath(name, directory, code = 'archive') {
  if (name.includes('\0') || name.includes('\\') || name.startsWith('/') || /^[A-Za-z]:/.test(name)) reject(code, 'unsafe path');
  const path = directory && name.endsWith('/') ? name.slice(0, -1) : name;
  if (!path || path.split('/').some(part => !part || part === '.' || part === '..')) reject(code, 'unsafe path');
  return path;
}

class TarReader {
  constructor(stream, signal) { this.iterator = stream[Symbol.asyncIterator](); this.signal = signal; this.buffer = Buffer.alloc(0); this.total = 0; }
  async next() {
    checkAbort(this.signal);
    const next = await this.iterator.next();
    if (next.done) return false;
    this.total += next.value.length;
    if (this.total > MAX_TAR_BYTES) reject('archive', 'decompressed archive too large');
    this.buffer = this.buffer.length ? Buffer.concat([this.buffer, next.value]) : next.value;
    return true;
  }
  async read(size) {
    while (this.buffer.length < size) if (!(await this.next())) reject('archive', 'truncated tar');
    const result = this.buffer.subarray(0, size);
    this.buffer = this.buffer.subarray(size);
    return result;
  }
  async finish() {
    do {
      if (this.buffer.some(byte => byte !== 0)) reject('archive', 'data after tar end');
      this.buffer = Buffer.alloc(0);
    } while (await this.next());
  }
}

async function ensureParents(destination, parts) {
  let current = destination;
  for (const part of parts) {
    current = join(current, part);
    try { await mkdir(current, { mode: 0o700 }); } catch (error) { if (error.code !== 'EEXIST') throw error; }
    const item = await lstat(current);
    if (!item.isDirectory() || item.isSymbolicLink()) reject('archive', 'unsafe destination directory');
    if (process.platform !== 'win32') await chmod(current, 0o700);
  }
}

export async function extractReleaseBundle(packageFile, kind, innerPath, destination, signal) {
  let source; let gunzip;
  try {
    if (kind !== 'deb' && kind !== 'tar.gz') reject('archive', 'unsupported package kind');
    safePath(innerPath, false);
    const root = await lstat(destination);
    if (!root.isDirectory() || root.isSymbolicLink()) reject('archive', 'unsafe destination');
    if (process.platform !== 'win32') await chmod(destination, 0o700);
    if (kind === 'deb') {
      const member = await dataMember(packageFile, signal);
      source = createReadStream(packageFile, { start: member.start, end: member.start + member.size - 1 });
    } else {
      source = createReadStream(packageFile);
    }
    gunzip = createGunzip();
    source.on('error', error => gunzip.destroy(error));
    const abort = () => { source.destroy(); gunzip.destroy(signal.reason ?? new Error('Aborted')); };
    signal?.addEventListener('abort', abort, { once: true });
    try {
      checkAbort(signal);
      source.pipe(gunzip);
      const reader = new TarReader(gunzip, signal);
      const seen = new Set(); let bundleSize = 0;
      for (;;) {
        const header = await reader.read(512);
        if (header.every(byte => byte === 0)) {
          if (!(await reader.read(512)).every(byte => byte === 0)) reject('archive', 'missing tar end marker');
          await reader.finish();
          break;
        }
        const expected = tarOctal(header.subarray(148, 156));
        let sum = 0;
        for (let i = 0; i < 512; i += 1) sum += i >= 148 && i < 156 ? 32 : header[i];
        const posix = header.subarray(257, 263).toString('binary') === 'ustar\0';
        const gnu = header.subarray(257, 265).toString('binary') === 'ustar  \0';
        if (expected !== sum || (!posix && !gnu)) reject('archive', 'invalid tar header');
        const type = header[156];
        if (type !== 0 && type !== 48 && type !== 53) reject('archive', 'unsupported tar entry');
        const directory = type === 53;
        const prefix = posix ? tarString(header.subarray(345, 500)) : '';
        const name = tarString(header.subarray(0, 100));
        const path = safePath(prefix ? `${prefix}/${name}` : name, directory);
        const size = tarOctal(header.subarray(124, 136));
        const mode = tarOctal(header.subarray(100, 108));
        if (directory && size !== 0) reject('archive', 'directory has data');
        if (path === innerPath && !directory) reject('archive', 'invalid runtime directory');
        let handle;
        if (path.startsWith(`${innerPath}/`)) {
          const relative = path.slice(innerPath.length + 1);
          if (Buffer.byteLength(relative) > 255 || relative.split('/').length > 16 || seen.has(relative) || seen.size >= MAX_ENTRIES) reject('archive', 'runtime entry limit or duplicate');
          seen.add(relative);
          bundleSize += size;
          if (bundleSize > MAX_BUNDLE_BYTES) reject('archive', 'runtime data too large');
          const parts = relative.split('/');
          await ensureParents(destination, directory ? parts : parts.slice(0, -1));
          if (!directory) handle = await open(join(destination, ...parts), constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | (constants.O_NOFOLLOW ?? 0), mode & 0o111 ? 0o700 : 0o600);
        }
        try {
          let left = size;
          while (left) {
            const bytes = await reader.read(Math.min(left, 65536));
            if (handle) {
              let position = 0;
              while (position < bytes.length) {
                const { bytesWritten } = await handle.write(bytes, position, bytes.length - position);
                if (!bytesWritten) reject('archive', 'short extraction write');
                position += bytesWritten;
              }
            }
            left -= bytes.length;
          }
          if (handle && process.platform !== 'win32') await handle.chmod(mode & 0o111 ? 0o700 : 0o600);
        } finally { await handle?.close(); }
        if (size % 512) await reader.read(512 - size % 512);
      }
    } finally {
      signal?.removeEventListener('abort', abort);
      source.destroy(); gunzip.destroy();
    }
  } catch (error) {
    if (signal?.aborted || isDiskError(error) || error instanceof ReleaseBundleError) throw error;
    throw new ReleaseBundleError('archive', 'invalid archive');
  }
}

async function fileBytes(path, limit, signal) {
  checkAbort(signal);
  const before = await lstat(path);
  if (!before.isFile() || before.isSymbolicLink() || before.size > limit) reject('bundle', 'invalid bundle file');
  const handle = await open(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const opened = await handle.stat();
    if (!opened.isFile() || opened.dev !== before.dev || opened.ino !== before.ino || opened.size !== before.size) reject('bundle', 'bundle file changed');
    const hasher = createHash('sha256');
    const chunks = []; let size = 0;
    for await (const chunk of handle.createReadStream({ autoClose: false, signal })) {
      size += chunk.length;
      if (size > limit || size > opened.size) reject('bundle', 'bundle file too large');
      hasher.update(chunk);
      if (limit === 262144) chunks.push(chunk);
    }
    const after = await handle.stat();
    if (size !== opened.size || after.size !== opened.size || after.mtimeMs !== opened.mtimeMs || after.ctimeMs !== opened.ctimeMs) reject('bundle', 'bundle file changed');
    checkAbort(signal);
    return { size, sha256: hasher.digest('hex'), bytes: chunks.length ? Buffer.concat(chunks) : Buffer.alloc(0), mode: opened.mode };
  } finally { await handle.close(); }
}

export async function verifyReleaseBundle(dir, manifestSha256, signal) {
  try {
    if (!SHA256.test(manifestSha256)) reject('bundle', 'invalid manifest digest');
    const root = await lstat(dir);
    if (!root.isDirectory() || root.isSymbolicLink()) reject('bundle', 'invalid bundle directory');
    const manifestFile = await fileBytes(join(dir, 'manifest.json'), 262144, signal);
    if (manifestFile.sha256 !== manifestSha256) reject('bundle', 'manifest digest mismatch');
    const manifest = JSON.parse(manifestFile.bytes.toString('utf8'));
    if (!Array.isArray(manifest.files) || manifest.files.length > MAX_ENTRIES) reject('bundle', 'invalid manifest files');
    const expected = new Map();
    for (const item of manifest.files) {
      if (typeof item?.path !== 'string' || safePath(item.path, false, 'bundle') !== item.path || item.path === 'manifest.json'
        || Buffer.byteLength(item.path) > 255 || item.path.split('/').length > 16 || expected.has(item.path)
        || !SHA256.test(item.sha256 ?? '') || !Number.isSafeInteger(item.size_bytes) || item.size_bytes < 0 || typeof item.executable !== 'boolean') reject('bundle', 'invalid manifest entry');
      expected.set(item.path, item);
    }
    let count = 0;
    async function walk(current, prefix = '') {
      checkAbort(signal);
      for (const name of await readdir(current)) {
        const path = prefix ? `${prefix}/${name}` : name;
        safePath(path, false, 'bundle');
        const full = join(current, name);
        const item = await lstat(full);
        if (++count > MAX_ENTRIES || item.isSymbolicLink()) reject('bundle', 'invalid bundle entry');
        if (item.isDirectory()) await walk(full, path);
        else if (item.isFile()) {
          if (path === 'manifest.json') continue;
          const wanted = expected.get(path);
          if (!wanted) reject('bundle', 'unexpected bundle file');
          const actual = await fileBytes(full, wanted.size_bytes, signal);
          if (actual.size !== wanted.size_bytes || actual.sha256 !== wanted.sha256 || (process.platform !== 'win32' && Boolean(actual.mode & 0o100) !== wanted.executable)) reject('bundle', 'bundle file mismatch');
          expected.delete(path);
        } else reject('bundle', 'invalid bundle entry');
      }
    }
    await walk(dir);
    if (expected.size) reject('bundle', 'missing bundle file');
  } catch (error) {
    if (signal?.aborted || isDiskError(error) || error instanceof ReleaseBundleError) throw error;
    throw new ReleaseBundleError('bundle', 'bundle verification failed');
  }
}
