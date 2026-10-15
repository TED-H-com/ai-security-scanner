import { copyFile, cp, readFile, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { join } from 'node:path';

const [source, client, output] = process.argv.slice(2);
if (!source || !client || !output) throw new Error('source, patched client and output required');
await cp(source, output, { recursive: true, errorOnExist: true, force: false });
const bytes = await readFile(client);
const sha256 = createHash('sha256').update(bytes).digest('hex');
if (sha256 !== '7fcf04af2896503991da8ab7e926ab42d42c64565cfd8e5704937d260628cf64') {
  throw new Error('patched client differs');
}
await copyFile(client, join(output, 'bin/podman.exe'));
const manifestPath = join(output, 'manifest.json');
const manifest = JSON.parse(await readFile(manifestPath, 'utf8'));
const driver = manifest.files.find((file) => file.path === 'bin/podman.exe');
driver.sha256 = sha256;
driver.size_bytes = bytes.length;
const component = manifest.components.find((value) => value.id === 'podman');
const artifact = component.artifacts.find((value) => value.locator === 'bin/podman.exe');
artifact.sha256 = sha256;
artifact.size_bytes = bytes.length;
component.relationship = 'Diagnostic native-systemd backport of upstream Podman PR 29837; not a release artifact';
await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
