#!/usr/bin/env node

import { createHash, randomUUID } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { constants as fsConstants } from 'node:fs';
import {
  chmod,
  copyFile,
  cp,
  mkdir,
  mkdtemp,
  open,
  readFile,
  readdir,
  rename,
  rm,
  stat,
  lstat,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { get as httpsGet } from 'node:https';
import { basename, dirname, isAbsolute, join, parse, relative, resolve, sep } from 'node:path';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import { execFile as execFileCallback } from 'node:child_process';

const execFile = promisify(execFileCallback);
const SCRIPT_DIRECTORY = dirname(fileURLToPath(import.meta.url));
const REPOSITORY_ROOT = resolve(SCRIPT_DIRECTORY, '..');
const DEFAULT_LOCK = join(SCRIPT_DIRECTORY, 'upstreams.lock.json');
const APPROVED_DOWNLOAD_HOSTS = new Set([
  'github.com',
  'objects.githubusercontent.com',
  'release-assets.githubusercontent.com',
  'codeload.github.com',
  'go.dev',
  'dl.google.com',
  'download.qemu.org',
  'gitlab.com',
]);
const MAX_DOWNLOAD_BYTES = 4 * 1024 * 1024 * 1024;
const MAX_ARCHIVE_ENTRIES = 100_000;
const MAX_STAGED_FILES = 128;
const MAX_STAGED_FILE_BYTES = 1024 * 1024 * 1024;
const MAX_STAGED_BYTES = 2 * 1024 * 1024 * 1024;

function usage() {
  return [
    'Usage:',
    '  node runtime/vendor-managed-runtime.mjs --target <rust-target> --output <managed-runtime-dir>',
    '  node runtime/vendor-managed-runtime.mjs --target <rust-target> --verify-lock-only',
    '',
    'Supported targets: x86_64-unknown-linux-gnu, universal-apple-darwin, x86_64-pc-windows-msvc',
  ].join('\n');
}

function parseArguments(argv) {
  const options = { lock: DEFAULT_LOCK, output: undefined, target: undefined, verifyLockOnly: false };
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === '--verify-lock-only') {
      options.verifyLockOnly = true;
      continue;
    }
    if (argument === '--help' || argument === '-h') {
      process.stdout.write(`${usage()}\n`);
      process.exit(0);
    }
    if (!['--lock', '--output', '--target'].includes(argument) || index + 1 >= argv.length) {
      throw new Error(`unknown or incomplete argument ${argument}\n${usage()}`);
    }
    const value = argv[index + 1];
    index += 1;
    if (argument === '--lock') options.lock = resolve(value);
    if (argument === '--output') options.output = resolve(value);
    if (argument === '--target') options.target = value;
  }
  if (!options.target) throw new Error(`--target is required\n${usage()}`);
  if (!options.verifyLockOnly && !options.output) {
    throw new Error(`--output is required unless --verify-lock-only is used\n${usage()}`);
  }
  return options;
}

function requireObject(value, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value;
}

function requireText(value, label) {
  if (typeof value !== 'string' || value.length === 0 || value.includes('\0') || value.includes('\n')) {
    throw new Error(`${label} must be bounded non-empty text`);
  }
  return value;
}

function requireSha256(value, label) {
  if (typeof value !== 'string' || !/^[0-9a-f]{64}$/.test(value)) {
    throw new Error(`${label} must be a lowercase SHA-256 digest`);
  }
  return value;
}

function requireManagementContractRevision(value) {
  const revision = requireText(value, 'managed runtime management contract revision');
  if (!/^\d{4}-\d{2}-\d{2}\.[1-9]\d{0,3}$/.test(revision)) {
    throw new Error('managed runtime management contract revision must be a dated positive revision');
  }
  const [date] = revision.split('.');
  if (new Date(`${date}T00:00:00Z`).toISOString().slice(0, 10) !== date) {
    throw new Error('managed runtime management contract revision has an invalid calendar date');
  }
  return revision;
}

function requireSize(value, label, maximum = MAX_DOWNLOAD_BYTES) {
  if (!Number.isSafeInteger(value) || value < 1 || value > maximum) {
    throw new Error(`${label} has an invalid locked size`);
  }
  return value;
}

function approvedUrl(value, label) {
  const url = new URL(requireText(value, label));
  if (
    url.protocol !== 'https:' ||
    url.username !== '' ||
    url.password !== '' ||
    url.hash !== '' ||
    !APPROVED_DOWNLOAD_HOSTS.has(url.hostname.toLowerCase())
  ) {
    throw new Error(`${label} is not an approved credential-free HTTPS URL`);
  }
  return url;
}

function assetUrl(base, assetName, label) {
  const baseUrl = approvedUrl(base, `${label} base URL`);
  const name = requireText(assetName, `${label} asset name`);
  if (!/^[A-Za-z0-9._-]+$/.test(name) || !baseUrl.pathname.endsWith('/')) {
    throw new Error(`${label} asset identity is invalid`);
  }
  return approvedUrl(new URL(name, baseUrl).href, `${label} URL`).href;
}

function normalizeRelativePath(value, label) {
  requireText(value, label);
  if (isAbsolute(value) || value.includes('\\')) throw new Error(`${label} must be a POSIX relative path`);
  const parts = value.split('/');
  if (parts.some((part) => part === '' || part === '.' || part === '..')) {
    throw new Error(`${label} contains an unsafe path component`);
  }
  return parts.join('/');
}

function excludedForeignQemuFirmware(lock) {
  const qemu = requireObject(lock.linux_qemu, 'Linux QEMU lock');
  const contract = requireObject(qemu.build_contract, 'Linux QEMU build contract');
  const explicitBuildTargets = contract.explicit_build_targets;
  const exportedExecutables = contract.exported_executables;
  const requiredOutputs = contract.required_outputs;
  if (
    contract.build_platform !== 'linux/amd64' ||
    contract.target_list !== 'x86_64-softmmu' ||
    contract.static !== true ||
    !Array.isArray(explicitBuildTargets) ||
    explicitBuildTargets.length !== 2 ||
    explicitBuildTargets[0] !== 'qemu-img' ||
    explicitBuildTargets[1] !== 'qemu-system-x86_64' ||
    !Array.isArray(exportedExecutables) ||
    exportedExecutables.length !== 3 ||
    exportedExecutables[0] !== 'bin/qemu-img' ||
    exportedExecutables[1] !== 'bin/qemu-system-x86_64' ||
    exportedExecutables[2] !== 'bin/qemu-system-x86_64.real' ||
    !Array.isArray(requiredOutputs) ||
    requiredOutputs.length !== 4 ||
    requiredOutputs[0] !== 'bin/qemu-img' ||
    requiredOutputs[1] !== 'bin/qemu-system-x86_64' ||
    requiredOutputs[2] !== 'bin/qemu-system-x86_64.real' ||
    requiredOutputs[3] !== 'share/qemu'
  ) {
    throw new Error('Linux QEMU build contract must lock the amd64 static executable exports');
  }
  const configured = contract.excluded_foreign_firmware;
  if (!Array.isArray(configured) || configured.length === 0 || configured.length > 32) {
    throw new Error('Linux QEMU excluded foreign firmware must be a bounded non-empty array');
  }
  const excluded = new Set();
  configured.forEach((value, index) => {
    const path = normalizeRelativePath(value, `excluded foreign QEMU firmware ${index}`);
    if (!path.startsWith('share/qemu/') || excluded.has(path)) {
      throw new Error('Linux QEMU excluded foreign firmware must contain unique share/qemu paths');
    }
    excluded.add(path);
  });
  return excluded;
}

function requiredQemuDeviceModels(lock) {
  const qemu = requireObject(lock.linux_qemu, 'Linux QEMU lock');
  const contract = requireObject(qemu.build_contract, 'Linux QEMU build contract');
  const configured = contract.required_device_models;
  if (
    !Array.isArray(configured) ||
    configured.length !== 1 ||
    configured[0] !== 'vhost-user-fs-pci'
  ) {
    throw new Error('Linux QEMU build contract must require the exact Podman virtio-fs PCI device');
  }
  return configured;
}

function linuxVirtiofsdBuildContract(lock) {
  const virtiofsd = requireObject(lock.linux_virtiofsd, 'Linux virtiofsd lock');
  approvedUrl(virtiofsd.repository_url, 'virtiofsd repository');
  requireText(virtiofsd.version, 'virtiofsd version');
  const sourceRevision = requireText(virtiofsd.source_revision, 'virtiofsd source revision');
  requireText(virtiofsd.license_spdx, 'virtiofsd license');
  const sourceUrl = approvedUrl(virtiofsd.source_url, 'virtiofsd source URL');
  if (!sourceUrl.pathname.includes(sourceRevision)) {
    throw new Error('Linux virtiofsd source URL does not bind its exact source revision');
  }
  const contract = requireObject(virtiofsd.build_contract, 'Linux virtiofsd build contract');
  if (
    contract.build_platform !== 'linux/amd64' ||
    contract.rust_version !== '1.91.1' ||
    contract.rust_builder_image !==
      'rust@sha256:d9f4b83fd097eaae5f9ace6d939e5a955dbbaa92804f9af4925f646cf9e46636' ||
    contract.target !== 'x86_64-unknown-linux-musl' ||
    contract.cargo_locked !== true ||
    contract.static !== true ||
    contract.exported_executable !== 'bin/virtiofsd'
  ) {
    throw new Error('Linux virtiofsd build contract must lock the static amd64 executable export');
  }
  return contract;
}

function validateLock(lock, targetName) {
  requireObject(lock, 'upstream lock');
  if (lock.schema_version !== '1') throw new Error('upstream lock schema is unsupported');
  requireManagementContractRevision(lock.management_contract_revision);
  const runtime = requireObject(lock.runtime, 'runtime lock');
  requireText(runtime.version, 'runtime version');
  approvedUrl(runtime.repository_url, 'runtime repository');
  requireText(runtime.source_revision, 'runtime source revision');
  approvedUrl(runtime.release_base_url, 'runtime release base');
  const machineOs = requireObject(lock.machine_os, 'machine OS lock');
  approvedUrl(machineOs.repository_url, 'machine OS repository');
  requireText(machineOs.version, 'machine OS version');
  requireText(machineOs.source_revision, 'machine OS source revision');
  requireText(machineOs.license_spdx, 'machine OS license');
  approvedUrl(machineOs.release_base_url, 'machine OS release base');
  const gvproxy = requireObject(lock.linux_gvproxy, 'gvisor-tap-vsock lock');
  approvedUrl(gvproxy.repository_url, 'gvisor-tap-vsock repository');
  requireText(gvproxy.version, 'gvisor-tap-vsock version');
  requireText(gvproxy.source_revision, 'gvisor-tap-vsock source revision');
  requireText(gvproxy.license_spdx, 'gvisor-tap-vsock license');
  const target = requireObject(
    requireObject(lock.release_targets, 'release targets')[targetName],
    `release target ${targetName}`,
  );
  const client = requireObject(target.client_asset, 'client asset');
  assetUrl(runtime.release_base_url, client.name, 'client');
  requireSha256(client.sha256, 'client asset SHA-256');
  requireSize(client.size_bytes, 'client asset size');
  if (targetName === 'x86_64-unknown-linux-gnu') {
    for (const [name, source] of [
      ['QEMU', requireObject(lock.linux_qemu, 'Linux QEMU lock')],
      ['DTC', requireObject(lock.linux_qemu_dtc, 'Linux QEMU DTC lock')],
      ['virtiofsd', requireObject(lock.linux_virtiofsd, 'Linux virtiofsd lock')],
    ]) {
      approvedUrl(source.source_url, `${name} source URL`);
      requireSha256(source.source_sha256, `${name} source SHA-256`);
      requireSize(source.source_size_bytes, `${name} source size`);
      requireText(source.source_revision, `${name} source revision`);
    }
    excludedForeignQemuFirmware(lock);
    requiredQemuDeviceModels(lock);
    linuxVirtiofsdBuildContract(lock);
    const gvproxyAsset = requireObject(gvproxy.asset, 'gvproxy asset');
    assetUrl(gvproxy.release_base_url, gvproxyAsset.name, 'gvproxy');
    requireSha256(gvproxyAsset.sha256, 'gvproxy asset SHA-256');
    requireSize(gvproxyAsset.size_bytes, 'gvproxy asset size');
  }
  if (targetName === 'universal-apple-darwin') {
    const vfkit = requireObject(lock.macos_vfkit, 'macOS vfkit lock');
    approvedUrl(vfkit.repository_url, 'vfkit repository');
    requireText(vfkit.version, 'vfkit version');
    requireText(vfkit.source_revision, 'vfkit source revision');
    requireText(vfkit.license_spdx, 'vfkit license');
  }
  if (targetName === 'x86_64-pc-windows-msvc') windowsPodmanBuildContract(lock);
  return { runtime, machineOs, target };
}

function windowsPodmanBuildContract(lock) {
  const build = requireObject(lock.windows_podman_build, 'Windows Podman source build');
  requireText(build.version, 'Windows Podman component version');
  if (!/^[A-Za-z0-9._-]{1,64}$/.test(build.version)) {
    throw new Error('Windows Podman component version must use the runtime manifest version vocabulary');
  }
  const source = approvedUrl(build.source_url, 'Windows Podman source URL');
  if (source.href !== `https://github.com/podman-container-tools/podman/archive/${lock.runtime.source_revision}.tar.gz`) {
    throw new Error('Windows Podman source must bind the exact upstream runtime revision');
  }
  requireSha256(build.source_sha256, 'Windows Podman source SHA-256');
  requireSize(build.source_size_bytes, 'Windows Podman source size');
  if (build.upstream_pull_request !== 'https://github.com/podman-container-tools/podman/pull/29837' ||
      !/^[0-9a-f]{40}$/.test(build.upstream_patch_revision)) {
    throw new Error('Windows Podman backport must identify its upstream change');
  }
  const patch = requireObject(build.patch, 'Windows Podman source patch');
  if (patch.path !== 'podman-wsl-native-systemd.patch') throw new Error('Windows Podman patch path is unsupported');
  requireSha256(patch.sha256, 'Windows Podman patch SHA-256');
  requireSize(patch.size_bytes, 'Windows Podman patch size', 1024 * 1024);
  if (!/^\d+\.\d+\.\d+$/.test(build.go_version)) throw new Error('Windows Podman Go version must be exact');
  for (const [platform, suffix] of [['win32', 'windows-amd64.zip'], ['linux', 'linux-amd64.tar.gz']]) {
    const toolchain = requireObject(build.go_toolchains?.[platform], `Windows Podman ${platform} build toolchain`);
    if (approvedUrl(toolchain.url, 'Go toolchain URL').href !== `https://go.dev/dl/go${build.go_version}.${suffix}`) {
      throw new Error('Go toolchain URL must bind its exact version and build platform');
    }
    requireSha256(toolchain.sha256, 'Go toolchain SHA-256');
    requireSize(toolchain.size_bytes, 'Go toolchain size');
  }
  const contract = requireObject(build.build_contract, 'Windows Podman build contract');
  if (contract.goos !== 'windows' || contract.goarch !== 'amd64' || contract.goamd64 !== 'v1' ||
      contract.cgo_enabled !== false || contract.vendor_dependencies !== true || contract.trimpath !== true ||
      contract.buildvcs !== false || contract.build_id !== '' || contract.build_info !== '0' ||
      contract.build_origin !== 'ai-security-scanner-native-wsl-systemd' ||
      JSON.stringify(contract.tags) !== JSON.stringify(['remote', 'exclude_graphdriver_btrfs', 'containers_image_openpgp'])) {
    throw new Error('Windows Podman build must use the reviewed offline reproducible remote-client contract');
  }
  return build;
}

async function sha256File(path, expectedMaximum = MAX_DOWNLOAD_BYTES) {
  const metadata = await lstat(path);
  if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.size > expectedMaximum) {
    throw new Error(`${path} is not a bounded regular file`);
  }
  const hasher = createHash('sha256');
  for await (const chunk of createReadStream(path)) hasher.update(chunk);
  return hasher.digest('hex');
}

async function verifyLockedFile(path, locked, label) {
  const size = requireSize(locked.size_bytes, `${label} size`);
  const digest = requireSha256(locked.sha256, `${label} SHA-256`);
  const metadata = await lstat(path);
  if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.size !== size) {
    throw new Error(`${label} differs from its locked size`);
  }
  const actual = await sha256File(path, size);
  if (actual !== digest) throw new Error(`${label} failed its locked SHA-256 check`);
}

function requestHttps(url, signal) {
  return new Promise((resolveResponse, rejectResponse) => {
    const request = httpsGet(
      url,
      {
        headers: {
          accept: 'application/octet-stream',
          'accept-encoding': 'identity',
          'user-agent': 'ai-security-scanner-release-vendor/1',
        },
        signal,
      },
      resolveResponse,
    );
    request.setTimeout(30_000, () => request.destroy(new Error('HTTPS response timeout')));
    request.once('error', rejectResponse);
  });
}

async function downloadLocked(urlValue, locked, destination, label) {
  const expectedSize = requireSize(locked.size_bytes, `${label} size`);
  const expectedDigest = requireSha256(locked.sha256, `${label} SHA-256`);
  let current = approvedUrl(urlValue, `${label} URL`);
  let response;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 4 * 60 * 60 * 1000);
  try {
    let redirects = 0;
    let retries = 0;
    for (;;) {
      response = await requestHttps(current, controller.signal);
      const status = response.statusCode ?? 0;
      if ([301, 302, 303, 307, 308].includes(status)) {
        const location = response.headers.location;
        if (!location || redirects === 8) throw new Error(`${label} exceeded its redirect policy`);
        response.destroy();
        current = approvedUrl(new URL(location, current).href, `${label} redirect`);
        redirects += 1;
        continue;
      }
      if (
        retries < 3 &&
        (status === 406 || status === 408 || status === 425 || status === 429 || status >= 500)
      ) {
        response.destroy();
        await new Promise((resolveDelay) => setTimeout(resolveDelay, 250 * 2 ** retries));
        retries += 1;
        continue;
      }
      break;
    }
    if (!response || response.statusCode !== 200) {
      response?.destroy();
      throw new Error(
        `${label} download failed with HTTP ${response?.statusCode ?? 'unknown'} from ${current.hostname}${current.pathname}`,
      );
    }
    const contentLength = response.headers['content-length'];
    if (contentLength !== undefined && Number(contentLength) !== expectedSize) {
      throw new Error(`${label} HTTP content length differs from the lock`);
    }
    const file = await open(destination, 'wx', 0o600);
    const hasher = createHash('sha256');
    let received = 0;
    try {
      for await (const chunk of response) {
        received += chunk.byteLength;
        if (received > expectedSize) throw new Error(`${label} exceeded its locked size`);
        hasher.update(chunk);
        await file.write(chunk);
      }
      await file.sync();
    } finally {
      await file.close();
    }
    if (received !== expectedSize || hasher.digest('hex') !== expectedDigest) {
      throw new Error(`${label} failed its locked size or SHA-256 check`);
    }
  } finally {
    clearTimeout(timer);
  }
}

async function run(program, programArguments, options = {}) {
  try {
    return await execFile(program, programArguments, {
      cwd: options.cwd,
      env: options.env ?? process.env,
      maxBuffer: options.maxBuffer ?? 16 * 1024 * 1024,
      timeout: options.timeout ?? 15 * 60 * 1000,
      windowsHide: true,
    });
  } catch (error) {
    const message = String(error.message ?? 'command failed');
    const stderr = String(error.stderr ?? '').trim();
    const combined = stderr && !message.includes(stderr) ? `${message}\nstderr:\n${stderr}` : message;
    const detail = combined.length <= 4096
      ? combined
      : `${combined.slice(0, 1536)}\n... diagnostic truncated ...\n${combined.slice(-2512)}`;
    throw new Error(`${program} failed: ${detail}`);
  }
}

function validateArchiveMember(member, label) {
  const value = member.replace(/\/$/, '');
  if (value === '') return;
  if (value.includes('\\') || value.startsWith('/') || /^[A-Za-z]:/.test(value)) {
    throw new Error(`${label} contains an absolute archive member`);
  }
  if (value.split('/').some((part) => part === '..')) {
    throw new Error(`${label} contains a traversal archive member`);
  }
}

function windowsSystemTar() {
  const systemRoot = process.env.SystemRoot;
  if (process.platform !== 'win32' || !systemRoot || !isAbsolute(systemRoot) || systemRoot.includes('\0')) {
    throw new Error('Windows system archive extractor is unavailable');
  }
  return join(systemRoot, 'System32', 'tar.exe');
}

async function extractWithTar(archive, destination, program = 'tar') {
  await mkdir(destination, { recursive: false, mode: 0o700 });
  const archiveDirectory = dirname(archive);
  const archiveArgument = normalizeRelativePath(basename(archive), 'archive filename');
  const destinationArgument = normalizeRelativePath(
    relative(archiveDirectory, destination).split(sep).join('/'),
    'archive extraction destination',
  );
  // GNU tar cannot read the official Windows client ZIP. This also permits
  // an independent Linux cross-build to verify the exact Windows bundle.
  const linuxZip = process.platform === 'linux' && archive.endsWith('.zip');
  const listing = await run(linuxZip ? 'unzip' : program, linuxZip ? ['-Z', '-1', archiveArgument] : ['-tf', archiveArgument], {
    cwd: archiveDirectory,
    maxBuffer: 64 * 1024 * 1024,
  });
  const members = listing.stdout.split(/\r?\n/).filter(Boolean);
  if (members.length === 0 || members.length > MAX_ARCHIVE_ENTRIES) {
    throw new Error('archive has an invalid entry count');
  }
  for (const member of members) validateArchiveMember(member, 'locked upstream archive');
  await run(linuxZip ? 'unzip' : program, linuxZip
    ? ['-q', archiveArgument, '-d', destinationArgument]
    : ['-xf', archiveArgument, '-C', destinationArgument], {
    cwd: archiveDirectory,
  });
}

async function singleDirectory(root, label) {
  const entries = await readdir(root, { withFileTypes: true });
  const directories = entries.filter((entry) => entry.isDirectory());
  if (directories.length !== 1 || entries.some((entry) => !entry.isDirectory())) {
    throw new Error(`${label} did not extract to one deterministic root directory`);
  }
  return join(root, directories[0].name);
}

async function walkRegularFiles(root, { rejectSymlinks = false, maximum = MAX_ARCHIVE_ENTRIES } = {}) {
  const files = [];
  const queue = [root];
  let entries = 0;
  while (queue.length > 0) {
    const directory = queue.pop();
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      entries += 1;
      if (entries > maximum) throw new Error(`filesystem tree exceeds ${maximum} entries`);
      const path = join(directory, entry.name);
      const metadata = await lstat(path);
      if (metadata.isSymbolicLink()) {
        if (rejectSymlinks) throw new Error(`staged payload contains a symlink: ${path}`);
        continue;
      }
      if (metadata.isDirectory()) queue.push(path);
      else if (metadata.isFile()) files.push({ path, size: metadata.size });
      else throw new Error(`filesystem tree contains an unsupported object: ${path}`);
    }
  }
  return files;
}

async function readElfIdentity(path) {
  const handle = await open(path, 'r');
  const header = Buffer.alloc(20);
  let bytesRead;
  try {
    ({ bytesRead } = await handle.read(header, 0, header.length, 0));
  } finally {
    await handle.close();
  }
  const hasElfMagic =
    bytesRead >= 4 && header[0] === 0x7f && header[1] === 0x45 && header[2] === 0x4c && header[3] === 0x46;
  if (!hasElfMagic) return undefined;
  if (bytesRead !== header.length || ![1, 2].includes(header[4]) || ![1, 2].includes(header[5])) {
    throw new Error(`managed QEMU output contains a malformed ELF header: ${path}`);
  }
  const machine = header[5] === 1 ? header.readUInt16LE(18) : header.readUInt16BE(18);
  return { class: header[4], data: header[5], machine };
}

async function readElfExecutableContract(path) {
  const identity = await readElfIdentity(path);
  if (!identity) throw new Error(`managed QEMU executable is not ELF: ${path}`);
  const handle = await open(path, 'r');
  const headerSize = identity.class === 1 ? 52 : 64;
  const header = Buffer.alloc(headerSize);
  let bytesRead;
  let fileSize;
  try {
    ({ bytesRead } = await handle.read(header, 0, header.length, 0));
    fileSize = (await handle.stat()).size;
  } finally {
    await handle.close();
  }
  if (bytesRead !== header.length) {
    throw new Error(`managed QEMU executable has a truncated ELF header: ${path}`);
  }
  const littleEndian = identity.data === 1;
  const read16 = (offset) => littleEndian ? header.readUInt16LE(offset) : header.readUInt16BE(offset);
  const programHeaderOffset = identity.class === 1
    ? (littleEndian ? header.readUInt32LE(28) : header.readUInt32BE(28))
    : Number(littleEndian ? header.readBigUInt64LE(32) : header.readBigUInt64BE(32));
  const programHeaderEntrySize = read16(identity.class === 1 ? 42 : 54);
  const programHeaderCount = read16(identity.class === 1 ? 44 : 56);
  const minimumEntrySize = identity.class === 1 ? 32 : 56;
  const tableBytes = programHeaderEntrySize * programHeaderCount;
  if (
    !Number.isSafeInteger(programHeaderOffset) ||
    programHeaderOffset < headerSize ||
    programHeaderCount < 1 ||
    programHeaderCount > 256 ||
    programHeaderEntrySize < minimumEntrySize ||
    tableBytes > 1024 * 1024 ||
    programHeaderOffset + tableBytes > fileSize
  ) {
    throw new Error(`managed QEMU executable has an invalid ELF program-header table: ${path}`);
  }
  const table = Buffer.alloc(tableBytes);
  const tableHandle = await open(path, 'r');
  try {
    const result = await tableHandle.read(table, 0, table.length, programHeaderOffset);
    if (result.bytesRead !== table.length) {
      throw new Error(`managed QEMU executable program headers changed while reading: ${path}`);
    }
  } finally {
    await tableHandle.close();
  }
  let hasInterpreter = false;
  for (let index = 0; index < programHeaderCount; index += 1) {
    const offset = index * programHeaderEntrySize;
    const type = littleEndian ? table.readUInt32LE(offset) : table.readUInt32BE(offset);
    if (type === 3) hasInterpreter = true;
  }
  return { ...identity, hasInterpreter };
}

function isNativeX86Elf(identity) {
  return (
    identity.data === 1 &&
    ((identity.class === 1 && identity.machine === 3) ||
      (identity.class === 2 && identity.machine === 62))
  );
}

async function copyLockedClientFiles(extractedRoot, lockedFiles, stageRoot) {
  const candidates = await walkRegularFiles(extractedRoot);
  for (const locked of lockedFiles) {
    const destinationRelative = normalizeRelativePath(locked.path, 'locked client destination');
    const size = requireSize(locked.size_bytes, `${destinationRelative} size`, MAX_STAGED_FILE_BYTES);
    const digest = requireSha256(locked.sha256, `${destinationRelative} SHA-256`);
    const matches = [];
    for (const candidate of candidates.filter((candidate) => candidate.size === size)) {
      if ((await sha256File(candidate.path, size)) === digest) matches.push(candidate.path);
    }
    if (matches.length !== 1) {
      throw new Error(`${destinationRelative} matched ${matches.length} files in the locked client archive`);
    }
    const destination = join(stageRoot, ...destinationRelative.split('/'));
    await mkdir(dirname(destination), { recursive: true, mode: 0o700 });
    await copyFile(matches[0], destination, fsConstants.COPYFILE_EXCL);
    await verifyLockedFile(destination, locked, destinationRelative);
    await chmod(destination, 0o700);
  }
}

async function copyQemuOutput(
  qemuOutput,
  stageRoot,
  expectedVersion,
  excludedFirmware,
  requiredDeviceModels,
  virtiofsd,
) {
  const sourceFiles = await walkRegularFiles(qemuOutput, {
    rejectSymlinks: true,
    maximum: MAX_STAGED_FILES,
  });
  if (sourceFiles.length === 0 || sourceFiles.length >= MAX_STAGED_FILES) {
    throw new Error('managed QEMU output has an invalid file count');
  }
  const files = sourceFiles.map((file) => ({
    ...file,
    destinationRelative: relative(qemuOutput, file.path).split(sep).join('/'),
  }));
  const sourcePaths = new Set(files.map((file) => file.destinationRelative));
  const discoveredForeignFirmware = new Set();
  for (const file of files) {
    if (!file.destinationRelative.startsWith('share/qemu/')) continue;
    const identity = await readElfIdentity(file.path);
    if (identity && !isNativeX86Elf(identity)) {
      discoveredForeignFirmware.add(file.destinationRelative);
    }
  }
  for (const path of excludedFirmware) {
    if (!sourcePaths.has(path)) {
      throw new Error(`managed QEMU output omitted contracted foreign firmware ${path}`);
    }
    if (!discoveredForeignFirmware.has(path)) {
      throw new Error(`contracted QEMU firmware is no longer a foreign ELF: ${path}`);
    }
  }
  for (const path of discoveredForeignFirmware) {
    if (!excludedFirmware.has(path)) {
      throw new Error(`managed QEMU output contains uncontracted foreign ELF firmware ${path}`);
    }
  }
  for (const file of files) {
    const { destinationRelative } = file;
    normalizeRelativePath(destinationRelative, 'managed QEMU output path');
    if (!destinationRelative.startsWith('bin/') && !destinationRelative.startsWith('share/qemu/')) {
      throw new Error(`unexpected managed QEMU output ${destinationRelative}`);
    }
    if (excludedFirmware.has(destinationRelative)) continue;
    const destination = join(stageRoot, ...destinationRelative.split('/'));
    await mkdir(dirname(destination), { recursive: true, mode: 0o700 });
    await copyFile(file.path, destination, fsConstants.COPYFILE_EXCL);
    await chmod(destination, destinationRelative.startsWith('bin/') ? 0o700 : 0o600);
  }
  for (const required of [
    'bin/qemu-img',
    'bin/qemu-system-x86_64',
    'bin/qemu-system-x86_64.real',
    'bin/virtiofsd',
  ]) {
    const metadata = await stat(join(stageRoot, ...required.split('/')));
    if (!metadata.isFile()) throw new Error(`managed QEMU omitted ${required}`);
    const executable = await readElfExecutableContract(join(stageRoot, ...required.split('/')));
    if (
      executable.class !== 2 ||
      executable.data !== 1 ||
      executable.machine !== 62 ||
      executable.hasInterpreter
    ) {
      throw new Error(`managed QEMU executable is not a static ELF64 little-endian x86-64 binary: ${required}`);
    }
  }
  const emulatorVersion = await run(join(stageRoot, 'bin', 'qemu-system-x86_64.real'), ['--version']);
  if (!emulatorVersion.stdout.includes(`QEMU emulator version ${expectedVersion}`)) {
    throw new Error('managed QEMU version does not match the upstream lock');
  }
  const deviceHelp = await run(join(stageRoot, 'bin', 'qemu-system-x86_64.real'), [
    '-device',
    'help',
  ]);
  const deviceNames = new Set(
    [...deviceHelp.stdout.matchAll(/name "([^"]+)"/gu)].map((match) => match[1]),
  );
  for (const model of requiredDeviceModels) {
    if (!deviceNames.has(model)) {
      throw new Error(`managed QEMU omitted required device model ${model}`);
    }
  }
  const imageToolVersion = await run(join(stageRoot, 'bin', 'qemu-img'), ['--version']);
  if (!imageToolVersion.stdout.includes(`qemu-img version ${expectedVersion}`)) {
    throw new Error('managed qemu-img version does not match the upstream lock');
  }
  const virtiofsdVersion = await run(join(stageRoot, 'bin', 'virtiofsd'), ['--version']);
  const expectedVirtiofsdVersion = requireText(
    requireObject(virtiofsd, 'Linux virtiofsd lock').version,
    'virtiofsd version',
  );
  if (!virtiofsdVersion.stdout.includes(`virtiofsd ${expectedVirtiofsdVersion}`)) {
    throw new Error('managed virtiofsd version does not match the upstream lock');
  }
  const imageTool = join(stageRoot, 'bin', 'qemu-img');
  const imageProbe = join(qemuOutput, `.qemu-img-probe-${randomUUID()}.qcow2`);
  try {
    await run(imageTool, ['create', '-f', 'qcow2', imageProbe, '1G']);
    await run(imageTool, ['resize', imageProbe, '40G']);
    const information = JSON.parse((await run(imageTool, ['info', '--output=json', imageProbe])).stdout);
    if (information.format !== 'qcow2' || information['virtual-size'] !== 40 * 1024 * 1024 * 1024) {
      throw new Error('managed qemu-img failed its exact create, resize, and inspect contract');
    }
  } finally {
    await rm(imageProbe, { force: true });
  }
}

async function buildLinuxQemu(lock, workRoot, stageRoot) {
  const qemu = requireObject(lock.linux_qemu, 'Linux QEMU lock');
  const dtc = requireObject(lock.linux_qemu_dtc, 'Linux QEMU DTC lock');
  const virtiofsd = requireObject(lock.linux_virtiofsd, 'Linux virtiofsd lock');
  const qemuArchive = join(workRoot, 'qemu-source.tar.xz');
  const dtcArchive = join(workRoot, 'dtc-source.tar.gz');
  const virtiofsdArchive = join(workRoot, 'virtiofsd-source.tar.gz');
  await downloadLocked(
    approvedUrl(qemu.source_url, 'QEMU source URL').href,
    { sha256: qemu.source_sha256, size_bytes: qemu.source_size_bytes },
    qemuArchive,
    'QEMU source',
  );
  await downloadLocked(
    approvedUrl(dtc.source_url, 'DTC source URL').href,
    { sha256: dtc.source_sha256, size_bytes: dtc.source_size_bytes },
    dtcArchive,
    'DTC source',
  );
  await downloadLocked(
    approvedUrl(virtiofsd.source_url, 'virtiofsd source URL').href,
    { sha256: virtiofsd.source_sha256, size_bytes: virtiofsd.source_size_bytes },
    virtiofsdArchive,
    'virtiofsd source',
  );
  const qemuExtract = join(workRoot, 'qemu-source');
  const dtcExtract = join(workRoot, 'dtc-source');
  const virtiofsdExtract = join(workRoot, 'virtiofsd-source');
  await extractWithTar(qemuArchive, qemuExtract);
  await extractWithTar(dtcArchive, dtcExtract);
  await extractWithTar(virtiofsdArchive, virtiofsdExtract);
  const qemuRoot = await singleDirectory(qemuExtract, 'QEMU source');
  const dtcRoot = await singleDirectory(dtcExtract, 'DTC source');
  const virtiofsdRoot = await singleDirectory(virtiofsdExtract, 'virtiofsd source');
  const dtcDestination = join(qemuRoot, 'subprojects', 'dtc');
  await rm(dtcDestination, { recursive: true, force: true });
  await mkdir(dirname(dtcDestination), { recursive: true, mode: 0o700 });
  await cp(dtcRoot, dtcDestination, { recursive: true, dereference: false, errorOnExist: true });

  const output = join(workRoot, 'qemu-output');
  await mkdir(output, { mode: 0o700 });
  await run(
    'docker',
    [
      'buildx',
      'build',
      '--platform',
      'linux/amd64',
      '--file',
      join(SCRIPT_DIRECTORY, 'linux-qemu.Dockerfile'),
      '--build-context',
      `launcher=${SCRIPT_DIRECTORY}`,
      '--build-context',
      `virtiofsd=${virtiofsdRoot}`,
      '--output',
      `type=local,dest=${output}`,
      qemuRoot,
    ],
    { timeout: 60 * 60 * 1000, maxBuffer: 64 * 1024 * 1024 },
  );
  await copyQemuOutput(
    output,
    stageRoot,
    requireText(qemu.version, 'QEMU version'),
    excludedForeignQemuFirmware(lock),
    requiredQemuDeviceModels(lock),
    virtiofsd,
  );
}

async function stageLinuxGvproxy(lock, workRoot, stageRoot) {
  const gvproxy = requireObject(lock.linux_gvproxy, 'Linux gvproxy lock');
  const asset = requireObject(gvproxy.asset, 'Linux gvproxy asset');
  const locked = requireObject(gvproxy.locked_file, 'Linux gvproxy locked file');
  if (asset.sha256 !== locked.sha256 || asset.size_bytes !== locked.size_bytes) {
    throw new Error('Linux gvproxy asset and staged-file identities differ');
  }
  const downloaded = join(workRoot, 'gvproxy-linux-amd64');
  await downloadLocked(
    assetUrl(gvproxy.release_base_url, asset.name, 'gvproxy'),
    asset,
    downloaded,
    'gvproxy asset',
  );
  const destinationRelative = normalizeRelativePath(locked.path, 'gvproxy destination');
  if (destinationRelative !== 'bin/gvproxy') throw new Error('Linux gvproxy destination is unsupported');
  const destination = join(stageRoot, 'bin', 'gvproxy');
  await mkdir(dirname(destination), { recursive: true, mode: 0o700 });
  await copyFile(downloaded, destination, fsConstants.COPYFILE_EXCL);
  await verifyLockedFile(destination, locked, 'gvproxy staged file');
  await chmod(destination, 0o700);
}

function lockedClientFiles(target) {
  if (target.locked_client_file) return [requireObject(target.locked_client_file, 'locked client file')];
  if (!Array.isArray(target.locked_client_files) || target.locked_client_files.length === 0) {
    throw new Error('release target has no locked client files');
  }
  return target.locked_client_files.map((entry, index) => requireObject(entry, `locked client file ${index}`));
}

function machineImage(lock, value, label) {
  const image = requireObject(value, `${label} machine image`);
  return {
    url: assetUrl(lock.machine_os.release_base_url, image.name, `${label} machine image`),
    sha256: requireSha256(image.sha256, `${label} machine image SHA-256`),
    size_bytes: requireSize(image.size_bytes, `${label} machine image size`),
  };
}

function manifestTargets(lock, targetName, target) {
  if (targetName === 'x86_64-unknown-linux-gnu') {
    if (target.provider !== 'qemu') throw new Error('Linux managed provider lock must be qemu');
    return [{
      operating_system: 'linux',
      architecture: 'x86_64',
      provider: 'qemu',
      machine_image: machineImage(lock, target.machine_image, 'Linux x86_64'),
    }];
  }
  if (targetName === 'universal-apple-darwin') {
    if (target.provider !== 'applehv') throw new Error('macOS managed provider lock must be applehv');
    const images = requireObject(target.machine_images, 'macOS machine images');
    return ['x86_64', 'aarch64'].map((architecture) => ({
      operating_system: 'macos',
      architecture,
      provider: 'applehv',
      machine_image: machineImage(lock, images[architecture], `macOS ${architecture}`),
    }));
  }
  if (targetName === 'x86_64-pc-windows-msvc') {
    if (target.provider !== 'wsl') throw new Error('Windows managed provider lock must be wsl');
    return [{
      operating_system: 'windows',
      architecture: 'x86_64',
      provider: 'wsl',
      machine_image: machineImage(lock, target.machine_image, 'Windows x86_64'),
      prerequisite: requireText(target.prerequisite, 'Windows prerequisite'),
    }];
  }
  throw new Error(`unsupported managed runtime target ${targetName}`);
}

function bundledArtifact(file) {
  return {
    delivery: 'bundled_file',
    locator: file.path,
    sha256: file.sha256,
    size_bytes: file.size_bytes,
  };
}

function downloadedArtifact(image) {
  return {
    delivery: 'runtime_download',
    locator: image.url,
    sha256: image.sha256,
    size_bytes: image.size_bytes,
  };
}

function componentRecord(source, id, relationship, artifacts, sourceArchive) {
  const version = source.version ?? `revision-${requireText(source.source_revision, `${id} revision`).slice(0, 12)}`;
  return {
    id,
    name: requireText(source.name, `${id} name`),
    version: requireText(version, `${id} version`),
    repository_url: approvedUrl(source.repository_url, `${id} repository`).href,
    source_revision: requireText(source.source_revision, `${id} source revision`),
    license_spdx: requireText(source.license_spdx, `${id} license`),
    relationship,
    artifacts,
    ...(sourceArchive ? { source_archive: sourceArchive } : {}),
  };
}

function componentInventory(lock, targetName, files, targets) {
  const byPath = new Map(files.map((file) => [file.path, file]));
  const select = (...paths) => paths.map((path) => {
    const file = byPath.get(path);
    if (!file) throw new Error(`component inventory references missing staged file ${path}`);
    return bundledArtifact(file);
  });
  const runtime = requireObject(lock.runtime, 'runtime lock');
  const machineOs = requireObject(lock.machine_os, 'machine OS lock');
  const windowsBuild = targetName === 'x86_64-pc-windows-msvc' ? windowsPodmanBuildContract(lock) : undefined;
  const components = [
    windowsBuild
      ? componentRecord(
        { ...runtime, version: windowsBuild.version },
        'podman',
        'Rootless Podman client with the upstream PR 29837 native WSL systemd lifecycle backport and systemd cgroup manager; exact build inputs and patch are bundled under share/podman',
        select('bin/podman.exe', 'share/podman/podman-wsl-native-systemd.patch', 'share/podman/windows-source-build.json'),
        { url: windowsBuild.source_url, sha256: windowsBuild.source_sha256, size_bytes: windowsBuild.source_size_bytes },
      )
      : componentRecord(runtime, 'podman', 'Bundled rootless Podman machine client', select('bin/podman')),
    componentRecord(
      machineOs,
      'podman-machine-os',
      'Pinned rootless VM image downloaded on first setup',
      targets.map((target) => downloadedArtifact(target.machine_image)),
    ),
  ];
  const gvproxy = requireObject(lock.linux_gvproxy, 'gvisor-tap-vsock lock');
  if (targetName === 'x86_64-unknown-linux-gnu') {
    components.push(componentRecord(
      gvproxy,
      'gvisor-tap-vsock',
      'Bundled rootless VM network helper',
      select('bin/gvproxy'),
    ));
    const qemuFiles = files.filter((file) => file.path.startsWith('bin/qemu-') || file.path.startsWith('share/qemu/'));
    const qemu = requireObject(lock.linux_qemu, 'Linux QEMU lock');
    components.push(componentRecord(
      qemu,
      'qemu',
      'Statically built x86_64 system emulator and image utility; foreign-architecture firmware is excluded and launcher source is runtime/qemu-launcher.c',
      qemuFiles.map(bundledArtifact),
      {
        url: approvedUrl(qemu.source_url, 'QEMU source URL').href,
        sha256: requireSha256(qemu.source_sha256, 'QEMU source SHA-256'),
        size_bytes: requireSize(qemu.source_size_bytes, 'QEMU source size'),
      },
    ));
    const dtc = requireObject(lock.linux_qemu_dtc, 'Linux QEMU DTC lock');
    components.push(componentRecord(
      dtc,
      'device-tree-compiler',
      'Source incorporated into the statically built QEMU system emulator',
      select('bin/qemu-system-x86_64.real'),
      {
        url: approvedUrl(dtc.source_url, 'DTC source URL').href,
        sha256: requireSha256(dtc.source_sha256, 'DTC source SHA-256'),
        size_bytes: requireSize(dtc.source_size_bytes, 'DTC source size'),
      },
    ));
    const virtiofsd = requireObject(lock.linux_virtiofsd, 'Linux virtiofsd lock');
    components.push(componentRecord(
      virtiofsd,
      'virtiofsd',
      'Statically built rootless VirtioFS host-filesystem helper required by Podman QEMU machine mounts',
      select('bin/virtiofsd'),
      {
        url: approvedUrl(virtiofsd.source_url, 'virtiofsd source URL').href,
        sha256: requireSha256(virtiofsd.source_sha256, 'virtiofsd source SHA-256'),
        size_bytes: requireSize(virtiofsd.source_size_bytes, 'virtiofsd source size'),
      },
    ));
  } else if (targetName === 'universal-apple-darwin') {
    components.push(componentRecord(
      gvproxy,
      'gvisor-tap-vsock',
      'Bundled rootless VM network helper',
      select('bin/gvproxy'),
    ));
    components.push(componentRecord(
      requireObject(lock.macos_vfkit, 'macOS vfkit lock'),
      'vfkit',
      'Bundled Apple Virtualization.framework machine helper',
      select('bin/vfkit'),
    ));
  } else {
    components.push(componentRecord(
      gvproxy,
      'gvisor-tap-vsock',
      'Bundled rootless WSL network and SSH proxy helpers',
      select('bin/gvproxy.exe', 'bin/win-sshproxy.exe'),
    ));
  }
  const covered = new Set(components.flatMap((component) => component.artifacts
    .filter((artifact) => artifact.delivery === 'bundled_file')
    .map((artifact) => artifact.locator)));
  const missing = files.filter((file) => !covered.has(file.path));
  if (missing.length > 0) throw new Error(`component inventory omits staged files: ${missing.map((file) => file.path).join(', ')}`);
  return components;
}

async function stageClient(lock, targetName, target, workRoot, stageRoot) {
  const client = target.client_asset;
  const extension = targetName === 'x86_64-pc-windows-msvc' ? '.zip' : targetName === 'universal-apple-darwin' ? '.pkg' : '.tar.gz';
  const archive = join(workRoot, `podman-client${extension}`);
  await downloadLocked(
    assetUrl(lock.runtime.release_base_url, client.name, 'Podman client'),
    client,
    archive,
    'Podman client asset',
  );
  const extracted = join(workRoot, 'podman-client');
  if (targetName === 'universal-apple-darwin') {
    await run('pkgutil', ['--expand-full', archive, extracted]);
  } else {
    await extractWithTar(
      archive,
      extracted,
      process.platform === 'win32' ? windowsSystemTar() : 'tar',
    );
  }
  const clientFiles = lockedClientFiles(target);
  await copyLockedClientFiles(
    extracted,
    targetName === 'x86_64-pc-windows-msvc'
      ? clientFiles.filter((file) => file.path !== 'bin/podman.exe')
      : clientFiles,
    stageRoot,
  );
  if (targetName === 'x86_64-pc-windows-msvc') {
    await buildWindowsPodman(lock, target, workRoot, stageRoot);
  }
}

async function buildWindowsPodman(lock, target, workRoot, stageRoot) {
  const build = windowsPodmanBuildContract(lock);
  if (!['win32', 'linux'].includes(process.platform) || process.arch !== 'x64') {
    throw new Error('Windows Podman source build requires a Windows or Linux x86_64 build host');
  }
  const toolchain = build.go_toolchains[process.platform];
  const sourceArchive = join(workRoot, 'podman-source.tar.gz');
  const goArchive = join(workRoot, process.platform === 'win32' ? 'go.zip' : 'go.tar.gz');
  await Promise.all([
    downloadLocked(build.source_url, {
      sha256: build.source_sha256, size_bytes: build.source_size_bytes,
    }, sourceArchive, 'Windows Podman source'),
    downloadLocked(toolchain.url, toolchain, goArchive, 'Go build toolchain'),
  ]);
  const tar = process.platform === 'win32' ? windowsSystemTar() : 'tar';
  const sourceExtract = join(workRoot, 'podman-source');
  const goExtract = join(workRoot, 'go-toolchain');
  await extractWithTar(sourceArchive, sourceExtract, tar);
  await extractWithTar(goArchive, goExtract, tar);
  const sourceRoot = await singleDirectory(sourceExtract, 'Windows Podman source');
  const goRoot = await singleDirectory(goExtract, 'Go build toolchain');
  const patch = join(SCRIPT_DIRECTORY, build.patch.path);
  await verifyLockedFile(patch, build.patch, 'Windows Podman source patch');
  await run('git', ['apply', '--check', patch], { cwd: sourceRoot });
  await run('git', ['apply', patch], { cwd: sourceRoot });
  const go = join(goRoot, 'bin', process.platform === 'win32' ? 'go.exe' : 'go');
  if (process.platform !== 'win32') await chmod(go, 0o700);
  const revision = lock.runtime.source_revision;
  const contract = build.build_contract;
  const binary = join(workRoot, 'podman.exe');
  await run(go, [
    'build', '-mod=vendor', '-trimpath', '-buildvcs=false',
    '-tags', contract.tags.join(' '),
    '-ldflags', `-s -w -buildid= -X github.com/containers/podman/v5/libpod/define.gitCommit=${revision} -X github.com/containers/podman/v5/libpod/define.buildInfo=0 -X github.com/containers/podman/v5/libpod/define.buildOrigin=${contract.build_origin}`,
    '-o', binary, './cmd/podman',
  ], {
    cwd: sourceRoot,
    env: {
      ...process.env,
      GOOS: 'windows', GOARCH: 'amd64', GOAMD64: 'v1', CGO_ENABLED: '0',
      GOTOOLCHAIN: 'local', GOWORK: 'off', GOENV: 'off', GOFLAGS: '',
      GOEXPERIMENT: '', GOFIPS140: 'off', GOPROXY: 'off', GOSUMDB: 'off',
      GOPATH: join(workRoot, 'go-path'), GOCACHE: join(workRoot, 'go-cache'), GOMAXPROCS: '4',
    },
  });
  const driver = lockedClientFiles(target).find((file) => file.path === 'bin/podman.exe');
  if (!driver) throw new Error('Windows Podman build has no locked executable identity');
  await verifyLockedFile(binary, driver, 'Source-built Windows Podman client');
  await copyFile(binary, join(stageRoot, 'bin', 'podman.exe'), fsConstants.COPYFILE_EXCL);
  const sourceInfo = join(stageRoot, 'share', 'podman');
  await mkdir(sourceInfo, { recursive: true, mode: 0o700 });
  await copyFile(patch, join(sourceInfo, build.patch.path), fsConstants.COPYFILE_EXCL);
  await writeFile(join(sourceInfo, 'windows-source-build.json'), `${JSON.stringify(build, null, 2)}\n`, {
    encoding: 'utf8', flag: 'wx', mode: 0o600,
  });
}

async function createManifest(lock, targetName, stageRoot, target) {
  const staged = await walkRegularFiles(stageRoot, { rejectSymlinks: true, maximum: MAX_STAGED_FILES });
  const files = [];
  let total = 0;
  for (const entry of staged) {
    const path = relative(stageRoot, entry.path).split(sep).join('/');
    normalizeRelativePath(path, 'staged file path');
    requireSize(entry.size, `${path} size`, MAX_STAGED_FILE_BYTES);
    total += entry.size;
    if (total > MAX_STAGED_BYTES) throw new Error('managed runtime staged bytes exceed the manifest bound');
    files.push({
      path,
      sha256: await sha256File(entry.path, MAX_STAGED_FILE_BYTES),
      size_bytes: entry.size,
      executable: path.startsWith('bin/'),
    });
  }
  files.sort((left, right) => left.path.localeCompare(right.path));
  if (files.length === 0 || files.length > MAX_STAGED_FILES) {
    throw new Error('managed runtime manifest has an invalid file count');
  }
  const driverPath = targetName === 'x86_64-pc-windows-msvc' ? 'bin/podman.exe' : 'bin/podman';
  if (!files.some((entry) => entry.path === driverPath)) throw new Error('managed runtime driver is absent');
  const targets = manifestTargets(lock, targetName, target);
  return {
    schema_version: '3',
    management_contract_revision: requireManagementContractRevision(
      lock.management_contract_revision,
    ),
    bundle_id: 'podman-machine',
    runtime_version: requireText(lock.runtime.version, 'runtime version'),
    driver_path: driverPath,
    files,
    components: componentInventory(lock, targetName, files, targets),
    targets,
    resources: { cpus: 2, memory_mb: 4096, disk_size_gb: 40 },
    source: {
      repository_url: approvedUrl(lock.runtime.repository_url, 'runtime repository').href,
      source_revision: requireText(lock.runtime.source_revision, 'runtime source revision'),
      license_spdx: requireText(lock.runtime.license_spdx, 'runtime license'),
    },
  };
}

function assertSafeOutput(output) {
  const resolved = resolve(output);
  if (resolved === parse(resolved).root || resolved === REPOSITORY_ROOT || basename(resolved) !== 'managed-runtime') {
    throw new Error('--output must name an exact managed-runtime directory, never a filesystem or repository root');
  }
  return resolved;
}

async function publish(staging, output) {
  const backup = `${output}.previous-${randomUUID()}`;
  let hadPrevious = false;
  try {
    await rename(output, backup);
    hadPrevious = true;
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
  try {
    await rename(staging, output);
  } catch (error) {
    if (hadPrevious) {
      try {
        await rename(backup, output);
      } catch {
        // Preserve the original error; the backup path remains explicit.
      }
    }
    throw error;
  }
  if (hadPrevious) await rm(backup, { recursive: true, force: false });
}

async function main() {
  const options = parseArguments(process.argv.slice(2));
  const lock = JSON.parse(await readFile(options.lock, 'utf8'));
  const { target } = validateLock(lock, options.target);
  // Validate every target-derived machine-image identity even for the cheap CI mode.
  manifestTargets(lock, options.target, target);
  lockedClientFiles(target).forEach((entry, index) => {
    normalizeRelativePath(entry.path, `locked client file ${index} path`);
    requireSha256(entry.sha256, `locked client file ${index} SHA-256`);
    requireSize(entry.size_bytes, `locked client file ${index} size`, MAX_STAGED_FILE_BYTES);
  });
  if (options.target === 'x86_64-pc-windows-msvc') {
    const build = windowsPodmanBuildContract(lock);
    await verifyLockedFile(join(SCRIPT_DIRECTORY, build.patch.path), build.patch, 'Windows Podman source patch');
  }
  if (options.verifyLockOnly) {
    process.stdout.write(`managed runtime lock verified for ${options.target}\n`);
    return;
  }

  const output = assertSafeOutput(options.output);
  await mkdir(dirname(output), { recursive: true, mode: 0o700 });
  const staging = await mkdtemp(join(dirname(output), '.managed-runtime-stage-'));
  const workRoot = await mkdtemp(join(tmpdir(), 'ai-security-scanner-managed-runtime-'));
  let published = false;
  try {
    await stageClient(lock, options.target, target, workRoot, staging);
    if (options.target === 'x86_64-unknown-linux-gnu') {
      await stageLinuxGvproxy(lock, workRoot, staging);
      await buildLinuxQemu(lock, workRoot, staging);
    }
    const manifest = await createManifest(lock, options.target, staging, target);
    await writeFile(join(staging, 'manifest.json'), `${JSON.stringify(manifest, null, 2)}\n`, {
      encoding: 'utf8',
      flag: 'wx',
      mode: 0o600,
    });
    await publish(staging, output);
    published = true;
    process.stdout.write(
      `staged ${manifest.files.length} verified managed runtime files for ${options.target} at ${output}\n`,
    );
  } finally {
    await rm(workRoot, { recursive: true, force: true });
    if (!published) await rm(staging, { recursive: true, force: true });
  }
}

main().catch((error) => {
  process.stderr.write(`managed runtime staging failed: ${error.message}\n`);
  process.exitCode = 1;
});
