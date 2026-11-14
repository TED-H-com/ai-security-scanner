import { createHash } from 'node:crypto';
import { gzipSync } from 'node:zlib';

export const sha256 = value => createHash('sha256').update(value).digest('hex');
export const innerPath = 'usr/lib/ai-security-scanner/managed-runtime';

function octal(buffer, offset, length, number) {
  buffer.write(number.toString(8).padStart(length - 1, '0') + '\0', offset, length, 'ascii');
}
export function tarEntry(name, content = '', { type = '0', mode = 0o644, corrupt = false, prefix = '', format = 'posix', atime = 0, ctime = 0 } = {}) {
  const data = Buffer.from(content);
  const header = Buffer.alloc(512);
  header.write(name, 0, 100, 'utf8');
  octal(header, 100, 8, mode);
  octal(header, 108, 8, 0);
  octal(header, 116, 8, 0);
  octal(header, 124, 12, data.length);
  octal(header, 136, 12, 0);
  header.fill(32, 148, 156);
  header.write(type, 156, 1, 'ascii');
  if (format === 'gnu') {
    header.write('ustar  \0', 257, 8, 'ascii');
    octal(header, 345, 12, atime);
    octal(header, 357, 12, ctime);
  } else {
    header.write('ustar\0', 257, 6, 'ascii');
    header.write('00', 263, 2, 'ascii');
    header.write(prefix, 345, 155, 'utf8');
  }
  octal(header, 148, 8, header.reduce((sum, byte) => sum + byte, 0) + (corrupt ? 1 : 0));
  return Buffer.concat([header, data, Buffer.alloc((512 - data.length % 512) % 512)]);
}
export function arMember(name, content) {
  const data = Buffer.from(content);
  const header = Buffer.from(`${(name + '/').padEnd(16)}${'0'.padEnd(12)}${'0'.padEnd(6)}${'0'.padEnd(6)}${'100644'.padEnd(8)}${String(data.length).padEnd(10)}\x60\n`, 'ascii');
  return Buffer.concat([header, data, data.length % 2 ? Buffer.from('\n') : Buffer.alloc(0)]);
}
export function debFromTar(tar) {
  return Buffer.concat([Buffer.from('!<arch>\n'), arMember('debian-binary', '2.0\n'), arMember('control.tar.gz', gzipSync(Buffer.alloc(1024))), arMember('data.tar.gz', gzipSync(tar))]);
}
export function packageFixture({ extra = [], removeEnd = false, manifestOverride, entryOptions = {}, tarOptions = {} } = {}) {
  const files = [
    { path: 'bin/tool', data: Buffer.from('executable\n'), executable: true },
    { path: 'notes.txt', data: Buffer.from('contents\n'), executable: false },
  ];
  const manifest = Buffer.from(JSON.stringify(manifestOverride ?? { files: files.map(file => ({ path: file.path, sha256: sha256(file.data), size_bytes: file.data.length, executable: file.executable })) }));
  const entries = [
    tarEntry('usr/', '', { ...tarOptions, type: '5', mode: 0o755 }),
    tarEntry('usr/share/unrelated', 'ignored', tarOptions),
    tarEntry(`${innerPath}/`, '', { ...tarOptions, type: '5', mode: 0o755 }),
    tarEntry(`${innerPath}/bin/`, '', { ...tarOptions, type: '5', mode: 0o755 }),
    tarEntry(`${innerPath}/manifest.json`, manifest, tarOptions),
    ...files.map(file => tarEntry(`${innerPath}/${file.path}`, file.data, { ...tarOptions, mode: file.executable ? 0o755 : 0o644, ...entryOptions[file.path] })),
    ...extra,
  ];
  const tar = Buffer.concat([...entries, ...(removeEnd ? [] : [Buffer.alloc(1024)])]);
  const bytes = debFromTar(tar);
  return { bytes, manifest, files, manifestSha: sha256(manifest), source: { kind: 'deb', url: 'https://example.test/runtime.deb', bytes: bytes.length, sha256: sha256(bytes), inner_path: innerPath, extracted_bytes: manifest.length + files.reduce((sum, file) => sum + file.data.length, 0) } };
}
export function chunkedResponse(bytes, options = {}) {
  let offset = 0;
  return new Response(new ReadableStream({
    pull(controller) {
      if (offset >= bytes.length) return controller.close();
      const end = Math.min(offset + (options.chunkSize ?? 37), bytes.length);
      controller.enqueue(new Uint8Array(bytes.subarray(offset, end)));
      offset = end;
    },
    cancel() { options.onCancel?.(); },
  }), { status: 200, headers: options.headers });
}
