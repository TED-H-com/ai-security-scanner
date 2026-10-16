import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { parseArgs, requireString, runMain, sha256File } from './lib.mjs';

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const cli = path.resolve(requireString(args, 'cli'));
  const bundle = path.resolve(requireString(args, 'bundle'));
  const manifestPath = path.join(bundle, 'manifest.json');
  const manifest = JSON.parse(await readFile(manifestPath, 'utf8'));
  const digest = await sha256File(manifestPath);
  const operatingSystem = {win32: 'windows', linux: 'linux', darwin: 'macos'}[process.platform];
  const architecture = {x64: 'x86_64', arm64: 'aarch64'}[process.arch];
  const supported = manifest.targets.some(target =>
    target.operating_system === operatingSystem && target.architecture === architecture);
  const directory = await mkdtemp(path.join(tmpdir(), 'managed-runtime-consumer-'));
  try {
    const stdout = execFileSync(cli, [
      '--data-dir', path.join(directory, 'data'), '--managed-runtime-bundle', bundle,
      '--json', 'runtime', 'managed', 'status',
    ], {encoding: 'utf8', timeout: 45_000, maxBuffer: 1024 * 1024});
    const status = JSON.parse(stdout);
    assert.equal(status.manifest_sha256, digest, 'CLI did not admit this exact staged manifest');
    assert.equal(status.runtime_version, manifest.runtime_version);
    assert.equal(status.available, false, 'fresh consumer verification must not start a runtime');
    assert.equal(status.phase, supported ? 'not_installed' : 'unsupported');
    process.stdout.write(`Runtime consumer admitted manifest ${digest} (${status.phase}).\n`);
  } finally {
    await rm(directory, {recursive: true, force: true});
  }
}

runMain(main);
