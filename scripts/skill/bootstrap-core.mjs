import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { spawn } from 'node:child_process';
import { constants } from 'node:fs';
import {
  access, lstat, mkdir, open, readdir, realpath, rename, rm, rmdir, stat, unlink, writeFile,
} from 'node:fs/promises';
import { dirname, isAbsolute, join, parse, relative, resolve, sep } from 'node:path';
import { homedir, hostname } from 'node:os';
import { fileURLToPath } from 'node:url';
import { collectInputManifest, stageInputSnapshot } from './input-manifest.mjs';
import { RECOGNIZED_MANAGED_RUNTIME_BUNDLES } from './managed-runtime-bundles.mjs';

export const RECIPE = 'skill-bootstrap-v1';
export const RUST_VERSION = '1.98.0';
export const RECEIPT_SCHEMA = 'ai-security-scanner.bootstrap-receipt/v1';
const MARKER_SCHEMA = 'ai-security-scanner.bootstrap-cache/v1';
const MARKER = '.ai-security-scanner-bootstrap.json';
const RESULT_SCHEMA = 'ai-security-scanner.bootstrap-result/v1';
const ownSourceRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const SHA256 = /^[a-f0-9]{64}$/;
const REVISION = /^[a-f0-9]{40}$/;
const MAX_RECEIPT_BYTES = 1024 * 1024;
const CORE_BIN = 'ai-security-scanner-cli';
const WINDOWS_ACL_SCHEMA = 'ai-security-scanner.windows-cache-acl/v1';
const WINDOWS_ACL_SCRIPT = String.raw`
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
[Console]::InputEncoding = [Text.UTF8Encoding]::new($false)
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
$request = [Console]::In.ReadToEnd() | Microsoft.PowerShell.Utility\ConvertFrom-Json
if ($request.paths.Count -gt 128) { throw 'Too many ACL paths' }
$currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$records = @()
foreach ($path in $request.paths) {
  if ($path.Length -gt 4096) { throw 'ACL path too long' }
  $attributes = [IO.File]::GetAttributes($path)
  $directory = ($attributes -band [IO.FileAttributes]::Directory) -ne 0
  $sections = [Security.AccessControl.AccessControlSections]::Owner -bor [Security.AccessControl.AccessControlSections]::Access
  if ($directory) { $security = [IO.Directory]::GetAccessControl($path, $sections) }
  else { $security = [IO.File]::GetAccessControl($path, $sections) }
  $descriptor = [Security.AccessControl.RawSecurityDescriptor]::new($security.GetSecurityDescriptorBinaryForm(), 0)
  $present = (($descriptor.ControlFlags -band [Security.AccessControl.ControlFlags]::DiscretionaryAclPresent) -ne 0) -and ($null -ne $descriptor.DiscretionaryAcl)
  $aces = @()
  if ($present) {
    if ($descriptor.DiscretionaryAcl.Count -gt 512) { throw 'Too many ACL entries' }
    foreach ($ace in $descriptor.DiscretionaryAcl) {
      $type = 'unsupported'
      if ($ace.AceType -eq [Security.AccessControl.AceType]::AccessAllowed) { $type = 'allow' }
      if ($ace.AceType -eq [Security.AccessControl.AceType]::AccessDenied) { $type = 'deny' }
      if ($type -eq 'unsupported') { $aces += @{ type = $type; sid = ''; rights = 0; flags = [int]$ace.AceFlags } }
      else {
        $aces += @{ type = $type; sid = $ace.SecurityIdentifier.Value; rights = [Convert]::ToUInt32($ace.AccessMask.ToString('X8'), 16); flags = [int]$ace.AceFlags }
      }
    }
  }
  $owner = ''
  if ($null -ne $descriptor.Owner) { $owner = $descriptor.Owner.Value }
  $kind = 'file'
  if ($directory) { $kind = 'directory' }
  $records += @{ path = $path; kind = $kind; owner_sid = $owner; has_dacl = $present; aces = @($aces); reparse_point = (($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) }
}
$result = @{ schema_version = 'ai-security-scanner.windows-cache-acl/v1'; current_user_sid = $currentSid; records = @($records) }
[Console]::Out.Write(($result | Microsoft.PowerShell.Utility\ConvertTo-Json -Depth 8 -Compress))
`;

// Do not emulate a Windows access check. Conservatively reject a dangerous
// allow even when another ACE might deny it; unsupported/conditional ACEs and
// null DACLs are not sufficient proof of a private executable cache.
export function assertWindowsAclSnapshot(snapshot, requests) {
  const sid = /^S-1-(?:\d+-)+\d+$/;
  if (!snapshot || snapshot.schema_version !== WINDOWS_ACL_SCHEMA || !sid.test(snapshot.current_user_sid ?? '')
    || !Array.isArray(snapshot.records) || snapshot.records.length !== requests.length || requests.length > 128) {
    fail('windows_acl_unavailable', 'Windows cache ACL verification returned an invalid or incomplete result.');
  }
  const trusted = new Set([snapshot.current_user_sid, 'S-1-5-18', 'S-1-5-32-544']);
  // The Windows servicing account owns some system ancestors, never a cache.
  const trustedInstaller = 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464';
  const records = new Map(snapshot.records.map(record => [record.path, record]));
  if (records.size !== requests.length) fail('windows_acl_unavailable', 'Windows cache ACL verification returned duplicate paths.');
  for (const request of requests) {
    const record = records.get(request.path);
    if (!record || record.kind !== request.kind || record.reparse_point !== false || record.has_dacl !== true
      || !Array.isArray(record.aces) || record.aces.length > 512
      || (!trusted.has(record.owner_sid) && !(request.access === 'ancestor' && record.owner_sid === trustedInstaller))) {
      fail('unsafe_windows_cache_acl', 'The Windows cache or its ancestry has an untrusted owner, reparse point, or missing DACL.');
    }
    for (const ace of record.aces) {
      if (!['allow', 'deny'].includes(ace.type) || !sid.test(ace.sid ?? '') || !Number.isInteger(ace.rights) || ace.rights < 0 || ace.rights > 0xffffffff
        || !Number.isInteger(ace.flags) || ace.flags < 0 || ace.flags > 31) {
        fail('unsafe_windows_cache_acl', 'The Windows cache has an unsupported access-control entry.');
      }
      if (ace.type === 'deny' || ace.rights === 0) continue;
      if (trusted.has(ace.sid) || (request.access === 'ancestor' && ace.sid === trustedInstaller)) continue;
      const inheritOnly = (ace.flags & 8) !== 0;
      // CREATOR OWNER is replaced by a child's owner when inherited. In a
      // private directory, only trusted principals can create that child.
      if (ace.sid === 'S-1-3-0' && inheritOnly && (ace.flags & 3) !== 0) continue;
      if (request.access === 'ancestor') {
        if (inheritOnly) continue; // Every actual descendant is checked too.
        // Read/traverse and creating a NEW directory cannot replace an
        // already protected child. Delete-child, delete, write-data/attributes,
        // changing permissions/owner, generic-write/all and unknown bits fail.
        const allowed = (0x80000000 | 0x20000000 | 0x100000 | 0x020000 | 0x80 | 0x20 | 0x08 | 0x04 | 0x01) >>> 0;
        if (((ace.rights >>> 0) & (~allowed >>> 0)) === 0) continue;
      }
      fail('unsafe_windows_cache_acl', request.access === 'ancestor'
        ? 'Another Windows principal can modify or replace a cache ancestor.'
        : 'The Windows cache grants access to another principal; choose a private user directory with restricted inherited ACLs.');
    }
  }
}

export async function auditWindowsCachePaths(requests, environment = process.env) {
  if (!requests.length) return;
  if (requests.length > 128 || requests.some(request => !/^[A-Za-z]:\\/.test(request.path) || request.path.length > 4096)) {
    fail('unsafe_windows_cache_path', 'The Windows cache requires bounded local drive paths; network and device paths are unsupported.');
  }
  const systemRoot = environment.SystemRoot || environment.SYSTEMROOT;
  if (!systemRoot || !/^[A-Za-z]:\\[^\r\n]*$/.test(systemRoot)) fail('windows_acl_unavailable', 'Windows SystemRoot is required for local cache ACL verification.');
  const powershell = join(systemRoot, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
  const env = { ...controlledBuildEnvironment(environment), PSModulePath: join(systemRoot, 'System32', 'WindowsPowerShell', 'v1.0', 'Modules') };
  let outcome;
  try {
    outcome = await runCommand(powershell, ['-NoLogo', '-NoProfile', '-NonInteractive', '-Command', WINDOWS_ACL_SCRIPT], {
      env, input: JSON.stringify({ paths: requests.map(request => request.path) }), timeout: 15_000,
    });
  } catch { fail('windows_acl_unavailable', 'The fixed local Windows ACL verifier could not run; the cache was not trusted.'); }
  if (outcome.code !== 0) fail('windows_acl_unavailable', 'The fixed local Windows ACL verifier failed; the cache was not trusted.');
  let snapshot;
  try { snapshot = JSON.parse(outcome.stdout); } catch { fail('windows_acl_unavailable', 'The Windows ACL verifier returned invalid JSON.'); }
  assertWindowsAclSnapshot(snapshot, requests);
}

export class BootstrapError extends Error {
  constructor(code, message, exitCode = 4, details, nextStep) {
    super(message);
    this.name = 'BootstrapError';
    this.code = code;
    this.exitCode = exitCode;
    if (details !== undefined) this.details = details;
    if (nextStep !== undefined) this.nextStep = nextStep;
  }
}

function fail(code, message, exitCode) { throw new BootstrapError(code, message, exitCode); }
function hash(bytes) { return createHash('sha256').update(bytes).digest('hex'); }
function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}
function contained(parent, child) {
  const suffix = relative(parent, child);
  return suffix === '' || (!suffix.startsWith(`..${sep}`) && suffix !== '..' && !isAbsolute(suffix));
}

export function parseBootstrapArguments(argv) {
  if (argv.length === 1 && ['--help', '-h'].includes(argv[0])) return { help: true };
  const [command, ...args] = argv;
  if (!['doctor', 'prepare', 'run'].includes(command)) fail('invalid_arguments', 'Choose doctor, prepare, or run.', 2);
  const options = { command, capability: 'core', profile: 'release', allowDirty: false, offline: false, cliArguments: [] };
  const seen = new Set();
  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index];
    if (argument === '--') {
      if (command !== 'run') fail('invalid_arguments', 'Only run accepts CLI arguments after --.', 2);
      options.cliArguments = args.slice(index + 1);
      break;
    }
    if (seen.has(argument)) fail('invalid_arguments', `Duplicate option: ${argument}`, 2);
    seen.add(argument);
    if (argument === '--allow-dirty') options.allowDirty = true;
    else if (argument === '--offline') options.offline = true;
    else if (['--revision', '--cache-dir', '--capability', '--profile', '--engine', '--data-dir', '--managed-runtime-bundle', '--release-approved-local-image-directory'].includes(argument)) {
      const value = args[++index];
      if (!value || value.startsWith('--')) fail('invalid_arguments', `Missing value for ${argument}.`, 2);
      if (argument === '--engine') options.engineIds = value.split(',');
      else options[{ '--revision': 'revision', '--cache-dir': 'cacheDir', '--capability': 'capability', '--profile': 'profile', '--data-dir': 'dataDir', '--managed-runtime-bundle': 'managedRuntimeBundle', '--release-approved-local-image-directory': 'localImageDirectory' }[argument]] = value;
    } else fail('invalid_arguments', `Unknown bootstrap option: ${argument}`, 2);
  }
  validateOptions(options);
  return options;
}

function validateOptions(options) {
  if (!REVISION.test(options.revision ?? '')) fail('invalid_revision', 'An exact lowercase 40-character Git revision is required.', 2);
  if (!options.cacheDir || typeof options.cacheDir !== 'string' || options.cacheDir.includes('\0')) fail('invalid_cache_path', 'An explicit cache directory is required.', 2);
  if (!['core', 'scan'].includes(options.capability ?? 'core')) fail('invalid_capability', 'Capability must be core or scan.', 2);
  if (!['release', 'dev'].includes(options.profile ?? 'release')) fail('invalid_profile', 'Profile must be release or dev.', 2);
  if ((options.capability ?? 'core') === 'core') {
    if (['engineIds', 'dataDir', 'managedRuntimeBundle', 'localImageDirectory'].some(key => options[key] !== undefined)) {
      fail('invalid_arguments', 'Engine and runtime-source options belong to --capability scan preparation; core run passes CLI options after --.', 2);
    }
  } else {
    if (options.command === 'run') fail('invalid_arguments', 'Use prepare --capability scan to prepare selected engines, then run --capability core with explicit CLI arguments.', 2);
    if (!Array.isArray(options.engineIds) || options.engineIds.length < 1 || options.engineIds.length > 25
      || options.engineIds.some(id => typeof id !== 'string' || !/^[a-z][a-z0-9-]{0,63}$/.test(id))
      || new Set(options.engineIds).size !== options.engineIds.length) {
      fail('invalid_engine_selection', 'Scan preparation requires --engine with 1–25 distinct engine IDs separated by commas.', 2);
    }
    for (const [key, required] of [['dataDir', true], ['managedRuntimeBundle', false], ['localImageDirectory', false]]) {
      const value = options[key];
      if ((required && value === undefined) || (value !== undefined && (typeof value !== 'string' || !value || value.includes('\0')))) {
        fail('invalid_arguments', 'Scan preparation requires an explicit --data-dir and valid optional runtime source directories.', 2);
      }
    }
    const cache = resolve(options.cacheDir);
    const data = resolve(options.dataDir);
    if (contained(cache, data) || contained(data, cache)) fail('invalid_data_directory', 'Runtime data and the core build cache must use separate directory trees.', 2);
  }
}

// Exported injection seams are for tests; the command line never accepts a source,
// recipe, tool path, shell fragment, or builder supplied by a scanned project.
function dependencies(overrides) {
  return {
    sourceRoot: ownSourceRoot,
    collectInputManifest,
    stageInputSnapshot,
    inspectSource,
    validatePinnedInputs,
    inspectToolchain,
    build: buildSnapshot,
    readIdentity: readBuildIdentity,
    prepareRuntime: invokeRuntimePreparation,
    recognizedManagedRuntimeBundles: RECOGNIZED_MANAGED_RUNTIME_BUNDLES,
    stderr: process.stderr,
    platform: process.platform,
    arch: process.arch,
    environment: process.env,
    nodeVersion: process.versions.node,
    ...overrides,
  };
}

async function unlinkedDirectoryPath(path) {
  const { root } = parse(path);
  let current = root;
  for (const part of path.slice(root.length).split(sep).filter(Boolean)) {
    if (part === '.' || part === '..') return false;
    current = join(current, part);
    const entry = await lstat(current);
    if (!entry.isDirectory() || entry.isSymbolicLink()) return false;
  }
  return true;
}

export async function locateInstalledManagedRuntimeBundle(deps) {
  const entry = deps.recognizedManagedRuntimeBundles.find(item => item.platform === deps.platform && item.arch.includes(deps.arch));
  if (!entry || entry.installed_paths.length === 0) return { state: 'unsupported' };
  for (const path of entry.installed_paths) {
    if (!isAbsolute(path)) continue;
    try {
      if (!(await unlinkedDirectoryPath(path))) continue;
      const manifestPath = join(path, 'manifest.json');
      const before = await lstat(manifestPath);
      if (!before.isFile() || before.isSymbolicLink() || before.size > 262144) continue;
      const handle = await open(manifestPath, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
      let manifestSha256;
      try {
        const opened = await handle.stat();
        if (!opened.isFile() || opened.dev !== before.dev || opened.ino !== before.ino || opened.size !== before.size) continue;
        const bytes = Buffer.alloc(opened.size + 1);
        let count = 0;
        while (count < bytes.length) {
          const { bytesRead } = await handle.read(bytes, count, bytes.length - count, count);
          if (!bytesRead) break;
          count += bytesRead;
        }
        const after = await handle.stat();
        const current = await lstat(manifestPath);
        if (count !== opened.size || after.size !== opened.size || after.mtimeMs !== opened.mtimeMs || after.ctimeMs !== opened.ctimeMs
          || current.isSymbolicLink() || current.dev !== opened.dev || current.ino !== opened.ino || !(await unlinkedDirectoryPath(path))) continue;
        manifestSha256 = hash(bytes.subarray(0, count));
      } finally { await handle.close(); }
      return manifestSha256 === entry.manifest_sha256
        ? { state: 'recognized', path, manifest_sha256: manifestSha256, product_version: entry.product_version }
        : { state: 'unrecognized', path };
    } catch { /* An inaccessible, replaced or missing path is not a candidate. */ }
  }
  return { state: 'absent' };
}

async function compatibilityCommandsOnPath(deps) {
  const path = deps.environment.PATH ?? deps.environment.Path;
  if (!path) return [];
  const windows = deps.platform === 'win32';
  const directories = path.split(windows ? ';' : ':').map(directory => directory || '.');
  const extensions = windows ? ['', ...(deps.environment.PATHEXT ?? '.COM;.EXE;.BAT;.CMD').split(';').filter(Boolean)] : [''];
  const found = [];
  for (const command of ['docker', 'podman']) {
    let exists = false;
    for (const directory of directories) {
      for (const extension of extensions) {
        try { if ((await stat(join(directory, `${command}${extension}`))).isFile()) { exists = true; break; } } catch { /* Not a file on PATH. */ }
      }
      if (exists) break;
    }
    if (exists) found.push(command);
  }
  return found;
}

async function safeStat(path) {
  try { return await lstat(path); } catch (error) { if (error.code === 'ENOENT') return undefined; throw error; }
}

async function directoryChain(path, create = false) {
  const absolute = resolve(path);
  const parsed = parse(absolute);
  let current = parsed.root;
  const windowsRequests = process.platform === 'win32' ? [{ path: current, kind: 'directory', access: 'ancestor' }] : [];
  for (const part of absolute.slice(parsed.root.length).split(sep).filter(Boolean)) {
    current = join(current, part);
    let stat = await safeStat(current);
    if (!stat && create) {
      if (process.platform === 'win32') await auditWindowsCachePaths(windowsRequests);
      try { await mkdir(current, { mode: 0o700 }); } catch (error) { if (['EACCES', 'EPERM'].includes(error.code)) fail('cache_parent_not_writable', `Cannot create cache directory: ${current}`); if (error.code !== 'EEXIST') throw error; }
      stat = await lstat(current);
    }
    if (!stat) {
      if (process.platform === 'win32') await auditWindowsCachePaths(windowsRequests);
      return false;
    }
    if (!stat.isDirectory() || stat.isSymbolicLink()) fail('unsafe_cache_path', 'Cache paths must contain only real directories, without symbolic links.');
    if (process.platform !== 'win32') {
      const trustedOwner = stat.uid === 0 || (process.getuid && stat.uid === process.getuid());
      if (!trustedOwner || ((stat.mode & 0o022) !== 0 && (stat.mode & 0o1000) === 0)) {
        fail('unsafe_cache_ancestor', 'Cache ancestors must have trusted ownership and prevent other users from replacing their children.');
      }
    } else windowsRequests.push({ path: current, kind: 'directory', access: 'ancestor' });
  }
  if (process.platform === 'win32') await auditWindowsCachePaths(windowsRequests);
  return true;
}

function assertPrivate(stat, path) {
  if ((stat.mode & 0o077) !== 0 || (process.getuid && stat.uid !== process.getuid())) {
    fail('unsafe_cache_permissions', `The cache must be owned by this user with private permissions: ${path}`);
  }
}

async function privateDirectory(path, create = false) {
  if (!(await directoryChain(path, create))) return false;
  if (process.platform === 'win32') await auditWindowsCachePaths([{ path: resolve(path), kind: 'directory', access: 'private' }]);
  else assertPrivate(await lstat(path), path);
  return true;
}

async function regularBytes(path, limit = MAX_RECEIPT_BYTES, allowHardlinks = false) {
  const before = await lstat(path);
  if (!before.isFile() || before.isSymbolicLink() || (!allowHardlinks && before.nlink !== 1) || before.size > limit) {
    fail('unsafe_cache_file', `Expected a bounded regular file without links: ${path}`);
  }
  const handle = await open(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const opened = await handle.stat();
    if (!opened.isFile() || (!allowHardlinks && opened.nlink !== 1) || opened.dev !== before.dev || opened.ino !== before.ino || opened.size !== before.size) {
      fail('cache_file_changed', 'A cache file changed while it was being opened.');
    }
    const bytes = await handle.readFile();
    const after = await handle.stat();
    if (bytes.length > limit || after.size !== opened.size || after.mtimeMs !== opened.mtimeMs || after.ctimeMs !== opened.ctimeMs) {
      fail('cache_file_changed', 'A cache file changed while it was being read.');
    }
    return bytes;
  } finally { await handle.close(); }
}

async function readJson(path) {
  try { return JSON.parse((await regularBytes(path)).toString('utf8')); }
  catch (error) {
    if (error instanceof BootstrapError || error.code === 'ENOENT') throw error;
    fail('invalid_cache_metadata', `Invalid cache metadata: ${path}`);
  }
}

function validateCacheLocation(cacheDir, sourceRoot) {
  const root = resolve(cacheDir);
  if (process.platform === 'win32' && (!/^[A-Za-z]:\\/.test(root) || /[:*?"<>|]/.test(root.slice(3)))) {
    fail('unsafe_windows_cache_path', 'The Windows cache must use an ordinary local drive path.');
  }
  if (root === parse(root).root || root === resolve(homedir()) || contained(root, sourceRoot) || contained(sourceRoot, root)) {
    fail('unsafe_cache_path', 'The cache must be a dedicated child directory, separate from the source and user home.');
  }
  return root;
}

async function initializeCache(cacheDir, sourceRoot) {
  const root = validateCacheLocation(cacheDir, sourceRoot);
  const exists = await safeStat(root);
  if (exists) {
    await privateDirectory(root);
    if (!(await safeStat(join(root, MARKER)))) fail('unowned_cache_directory', 'The existing directory is not a scanner bootstrap cache; choose a new directory.');
    if (process.platform === 'win32') await auditWindowsCachePaths([{ path: join(root, MARKER), kind: 'file', access: 'private' }]);
    const marker = await readJson(join(root, MARKER));
    if (marker.schema_version !== MARKER_SCHEMA) fail('invalid_cache_metadata', 'Unsupported cache marker.');
  } else {
    await privateDirectory(root, true);
    await writeFile(join(root, MARKER), `${JSON.stringify({ schema_version: MARKER_SCHEMA })}\n`, { flag: 'wx', mode: 0o600 });
  }
  for (const name of ['entries', 'locks', 'staging', 'ready']) await privateDirectory(join(root, name), true);
  return root;
}

async function acquireLock(root, key) {
  const path = join(root, 'locks', key);
  try { await mkdir(path, { mode: 0o700 }); }
  catch (error) {
    if (error.code === 'EEXIST') {
      const owner = await readJson(join(path, 'owner.json')).catch(() => null);
      let ownerRunning = 'unknown';
      if (owner?.hostname === hostname() && Number.isInteger(owner.pid) && owner.pid > 0) {
        try { process.kill(owner.pid, 0); ownerRunning = true; } catch (err) { if (err.code === 'ESRCH') ownerRunning = false; }
      }
      throw new BootstrapError('cache_busy', `This build cache entry is locked. After confirming its owner is no longer running, remove the lock by hand: ${path}`, 3, { lock: path, owner, owner_running: ownerRunning });
    }
    throw error;
  }
  const owner = { schema_version: 'ai-security-scanner.bootstrap-lock/v1', token: randomUUID(), pid: process.pid, hostname: hostname(), created_at: new Date().toISOString() };
  await writeFile(join(path, 'owner.json'), `${JSON.stringify(owner)}\n`, { flag: 'wx', mode: 0o600 });
  return async () => {
    await privateDirectory(path);
    const current = await readJson(join(path, 'owner.json'));
    if (current.token !== owner.token) fail('cache_lock_changed', 'The cache lock changed; it was not removed.');
    await unlink(join(path, 'owner.json'));
    await rmdir(path);
  };
}

async function runCommand(program, args, { cwd, env, capture = true, timeout = 30_000, input, signal } = {}) {
  return await new Promise((resolvePromise, reject) => {
    // A command that can be interrupted leads its own process group on Unix, so
    // stopping it also stops the compilers it started.
    const grouped = Boolean(signal) && process.platform !== 'win32';
    const child = spawn(program, args, { cwd, env, shell: false, windowsHide: true, detached: grouped, stdio: capture ? [input === undefined ? 'ignore' : 'pipe', 'pipe', 'pipe'] : ['ignore', process.stderr, process.stderr] });
    const abort = () => {
      const name = signal.reason?.signal || 'SIGTERM';
      try { if (grouped && child.pid) process.kill(-child.pid, name); else child.kill(name); } catch { child.kill(name); }
    };
    if (signal?.aborted) abort(); else signal?.addEventListener('abort', abort, { once: true });
    let stdout = '';
    let stderr = '';
    let oversized = false;
    const timer = timeout ? setTimeout(() => child.kill(), timeout) : undefined;
    timer?.unref();
    if (input !== undefined) {
      child.stdin.on('error', () => {}); // Early verifier failure is reported by its exit status.
      child.stdin.end(input);
    }
    for (const [stream, append] of [[child.stdout, value => { stdout += value; }], [child.stderr, value => { stderr += value; }]]) {
      stream?.on('data', bytes => {
        append(bytes.toString('utf8'));
        if (stdout.length + stderr.length > MAX_RECEIPT_BYTES) { oversized = true; child.kill(); }
      });
    }
    child.once('error', error => { clearTimeout(timer); signal?.removeEventListener('abort', abort); reject(error.code === 'ENOENT' ? new BootstrapError('tool_unavailable', `${program} was not found on PATH.`) : error); });
    child.once('close', (code, childSignal) => {
      clearTimeout(timer);
      signal?.removeEventListener('abort', abort);
      if (oversized) reject(new BootstrapError('tool_output_limit', 'Tool output exceeded the bootstrap limit.'));
      else resolvePromise({ code, signal: childSignal, stdout: stdout.trim(), stderr: stderr.trim() });
    });
  });
}

async function inspectSource(sourceRoot, revision) {
  const gitEnvironment = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith('GIT_')));
  const prefix = ['-c', 'core.fsmonitor=false', '-c', 'core.untrackedCache=false', '-C', sourceRoot];
  let head;
  try { head = await runCommand('git', [...prefix, 'rev-parse', '--verify', 'HEAD'], { env: gitEnvironment }); } catch (error) { if (error.code === 'tool_unavailable') fail('source_unavailable', 'Install Git and run from a Git clone of the product.'); throw error; }
  if (head.code !== 0 || !REVISION.test(head.stdout)) fail('source_unavailable', 'The bootstrap must run from its fixed Git source checkout.');
  if (head.stdout !== revision) fail('revision_mismatch', 'The requested revision does not match this bootstrap checkout HEAD.', 2);
  const status = await runCommand('git', [...prefix, 'status', '--porcelain=v1', '--untracked-files=normal'], { env: gitEnvironment });
  if (status.code !== 0) fail('source_unavailable', 'Unable to inspect source checkout changes.');
  return { revision: head.stdout, dirty: status.stdout.length > 0, status_sha256: hash(status.stdout) };
}

async function validatePinnedInputs(sourceRoot, revision, manifest) {
  const files = new Map([...manifest.files, ...(manifest.metadataFiles ?? [])].map(file => [file.path, file]));
  for (const path of ['scripts/skill/bootstrap.mjs', 'scripts/skill/bootstrap-core.mjs', 'scripts/skill/input-manifest.mjs', 'scripts/skill/managed-runtime-bundles.mjs']) {
    if (!files.has(path)) files.set(path, { path });
  }
  const gitEnvironment = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith('GIT_')));
  const tree = await runCommand('git', ['-c', 'core.fsmonitor=false', '-C', sourceRoot, 'ls-tree', '-r', '-z', '--full-tree', revision, '--', ...files.keys()], { env: gitEnvironment });
  if (tree.code !== 0) fail('source_unavailable', 'Unable to verify the controlled build inputs against the pinned Git tree.');
  const entries = new Map(tree.stdout.split('\0').filter(Boolean).map(record => {
    const match = /^(\d+) (\w+) ([a-f0-9]{40})\t([\s\S]+)$/.exec(record);
    if (!match) fail('source_unavailable', 'The pinned Git tree returned an unsupported entry.');
    return [match[4], { mode: match[1], type: match[2], object: match[3] }];
  }));
  let changed = false;
  for (const [path, file] of files) {
    const bytes = await regularBytes(join(sourceRoot, path), 32 * 1024 * 1024);
    if (file.sha256 && hash(bytes) !== file.sha256) fail('source_changed', 'The controlled source changed while its Git identity was being checked.');
    const entry = entries.get(path);
    const object = createHash('sha1').update(`blob ${bytes.length}\0`).update(bytes).digest('hex');
    if (!entry || !['100644', '100755'].includes(entry.mode) || entry.type !== 'blob' || entry.object !== object) changed = true;
  }
  return changed;
}

export function controlledBuildEnvironment(environment = process.env) {
  const accepted = new Set([
    'PATH', 'Path', 'PATHEXT', 'SYSTEMROOT', 'SystemRoot', 'WINDIR', 'COMSPEC',
    'HOME', 'USERPROFILE', 'APPDATA', 'LOCALAPPDATA', 'TMP', 'TEMP', 'TMPDIR',
    'LANG', 'LC_ALL', 'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'NO_PROXY',
    'http_proxy', 'https_proxy', 'all_proxy', 'no_proxy',
    // Visual Studio's initialized native toolchain needs these search paths.
    'INCLUDE', 'LIB', 'LIBPATH', 'VCToolsInstallDir', 'VCINSTALLDIR', 'WindowsSdkDir',
    'WindowsSDKVersion', 'UniversalCRTSdkDir', 'UCRTVersion',
    'CARGO_HOME', 'RUSTUP_HOME',
  ]);
  const result = Object.fromEntries(Object.entries(environment).filter(([key]) => accepted.has(key)));
  result.RUSTUP_TOOLCHAIN = RUST_VERSION;
  result.RUSTUP_AUTO_INSTALL = '0';
  result.CARGO_TERM_COLOR = 'never';
  result.CARGO_INCREMENTAL = '0';
  return result;
}

async function auditCargoConfiguration(cwd, environment) {
  let current = resolve(cwd);
  const paths = new Set();
  while (true) {
    paths.add(join(current, '.cargo', 'config'));
    paths.add(join(current, '.cargo', 'config.toml'));
    const parent = dirname(current);
    if (parent === current) break;
    current = parent;
  }
  const cargoHome = resolve(environment.CARGO_HOME || join(environment.HOME || environment.USERPROFILE || homedir(), '.cargo'));
  paths.add(join(cargoHome, 'config'));
  paths.add(join(cargoHome, 'config.toml'));
  for (const path of paths) {
    if (await safeStat(path)) fail('cargo_configuration_override', `Uncontrolled Cargo configuration is present: ${path}. The bootstrap does not use personal Cargo settings. Temporarily rename this file, or set CARGO_HOME to a directory without config and choose a cache directory outside the file's parent tree.`);
  }
}

async function inspectToolchain({ environment, platform }) {
  const env = controlledBuildEnvironment(environment);
  const rustMessage = `Install Rust ${RUST_VERSION} with rustup (rustup toolchain install ${RUST_VERSION}), then run doctor again.`;
  let rustc, cargo;
  try {
    rustc = await runCommand('rustc', ['--version', '--verbose'], { env });
    cargo = await runCommand('cargo', ['--version'], { env });
  } catch (error) { if (error.code === 'tool_unavailable') fail('rust_toolchain_unavailable', rustMessage); throw error; }
  if (rustc.code !== 0 || !new RegExp(`^release: ${RUST_VERSION.replaceAll('.', '\\.')}\\r?$`, 'm').test(rustc.stdout)) {
    fail('rust_toolchain_unavailable', rustMessage);
  }
  if (cargo.code !== 0 || !cargo.stdout.startsWith(`cargo ${RUST_VERSION} `)) fail('rust_toolchain_unavailable', rustMessage);
  const target = /^host: (.+)$/m.exec(rustc.stdout)?.[1]?.trim();
  if (!target || !/^[a-zA-Z0-9_-]+$/.test(target)) fail('invalid_toolchain_identity', 'Rust did not report a valid native target.');
  const rustIdentity = {
    version: RUST_VERSION, rustc_version: rustc.stdout, cargo_version: cargo.stdout, target,
    rustc: await executableIdentity('rustc', env), cargo: await executableIdentity('cargo', env),
  };
  try {
  const compilerName = platform === 'win32' ? 'cl.exe' : 'cc';
  const compiler = await runCommand(compilerName, platform === 'win32' ? ['/?'] : ['--version'], { env });
  if (compiler.code !== 0) fail('native_linker_unavailable', 'A native compiler is required for the bundled SQLite dependency.');
  let linkerName = 'link.exe';
  if (platform !== 'win32') {
    const located = await runCommand(compilerName, ['-print-prog-name=ld'], { env });
    if (located.code !== 0 || !located.stdout || located.stdout.includes('\n')) fail('native_linker_unavailable', 'The native compiler did not identify its linker.');
    linkerName = located.stdout;
  }
  const linker = await runCommand(linkerName, platform === 'win32' ? ['/?'] : platform === 'darwin' ? ['-v'] : ['--version'], { env });
  if (!linker.stdout && !linker.stderr) fail('native_linker_unavailable', 'A native linker is required.');
  return {
    ...rustIdentity,
    compiler: { ...await executableIdentity(compilerName, env), version: compiler.stdout || compiler.stderr },
    linker: { ...await executableIdentity(linkerName, env), version: linker.stdout || linker.stderr },
  };
  } catch (error) {
    if (error.code === 'tool_unavailable' || error.code === 'native_linker_unavailable') error = new BootstrapError('native_compiler_unavailable', platform === 'win32' ? 'Open x64 Native Tools/Developer PowerShell for VS, then run doctor again.' : platform === 'darwin' ? 'Run xcode-select --install, then run doctor again.' : 'Install the system C compiler (cc), then run doctor again.');
    error.rustIdentity = rustIdentity;
    throw error;
  }
}

async function executableIdentity(program, environment) {
  const candidates = isAbsolute(program) ? [program] : (environment.PATH || environment.Path || '').split(process.platform === 'win32' ? ';' : ':').filter(Boolean).flatMap(directory => {
    const extensions = process.platform === 'win32' && !program.toLowerCase().endsWith('.exe') ? ['', '.exe'] : [''];
    return extensions.map(extension => join(directory, `${program}${extension}`));
  });
  for (const candidate of candidates) {
    if (!(await safeStat(candidate))) continue;
    const resolved = await realpath(candidate);
    const bytes = await regularBytes(resolved, 512 * 1024 * 1024, true);
    return { path: resolved, sha256: hash(bytes) };
  }
  fail('tool_unavailable', `The required build tool is not on PATH: ${program}`);
}

async function runtimeReferences(sourceRoot) {
  const files = ['runtime/upstreams.lock.json', 'runtime/managed-egress-gateway.json', 'engines/catalog.json', 'engines/upstreams.lock.json'];
  const references = [];
  for (const path of files) {
    if (await safeStat(join(sourceRoot, path))) references.push({ path, sha256: hash(await regularBytes(join(sourceRoot, path), 32 * 1024 * 1024)) });
  }
  return { prepared: false, lock_references: references, reason: 'Core preparation does not prepare scanner helpers, runtime images, or provider execution.' };
}

function buildConfiguration(options) {
  // Runtime preparation uses this same CLI. Selected engines and runtime
  // sources do not change a native binary or create another core cache entry.
  return { capability: 'core', profile: options.profile ?? 'release', features: ['cli'], binaries: [CORE_BIN] };
}

async function recipeDigest(sourceRoot) {
  const inputs = [];
  for (const path of ['scripts/skill/bootstrap.mjs', 'scripts/skill/bootstrap-core.mjs', 'scripts/skill/input-manifest.mjs', 'scripts/skill/managed-runtime-bundles.mjs']) {
    inputs.push({ path, sha256: hash(await regularBytes(join(sourceRoot, path), 2 * 1024 * 1024)) });
  }
  return hash(canonical({ version: RECIPE, inputs }));
}

async function buildSnapshot({ snapshot, targetDirectory, configuration, toolchain, manifest, environment, offline, signal }) {
  const env = controlledBuildEnvironment(environment);
  await auditCargoConfiguration(snapshot, env);
  env.CARGO_TARGET_DIR = targetDirectory;
  env.AI_SECURITY_SCANNER_BOOTSTRAP_INPUT_SHA256 = manifest.inputDigest;
  env.AI_SECURITY_SCANNER_BOOTSTRAP_RECIPE = RECIPE;
  const args = ['build', '--locked', '--package', 'ai-security-scanner', '--no-default-features', '--features', configuration.features.join(','), '--target', toolchain.target];
  if (configuration.profile === 'release') args.push('--release');
  if (offline) args.push('--offline');
  for (const binary of configuration.binaries) args.push('--bin', binary);
  const outcome = await runCommand('cargo', args, { cwd: snapshot, env, capture: false, timeout: 0, signal });
  if (outcome.code !== 0) fail('build_failed', `The fixed core build failed${outcome.signal ? ` (${outcome.signal})` : ` (exit ${outcome.code})`}; the prior ready entry is preserved.`);
}

async function readBuildIdentity(executable, { environment }) {
  const outcome = await runCommand(executable, ['--json', 'build-identity'], { env: environment });
  if (outcome.code !== 0) fail('artifact_identity_failed', 'The built core did not return its read-only build identity.');
  try { return JSON.parse(outcome.stdout); } catch { fail('artifact_identity_failed', 'The built core returned invalid identity JSON.'); }
}

function validateIdentity(identity, expected) {
  if (!identity || identity.schema_version !== 'ai-security-scanner.build-identity/v1' || identity.product !== 'ai-security-scanner'
    || identity.target !== expected.toolchain.target || identity.rustc_version !== expected.toolchain.rustc_version
    || canonical(identity.features) !== canonical(expected.configuration.features)
    || identity.bootstrap_input_sha256 !== expected.manifest.inputDigest || identity.bootstrap_recipe !== RECIPE
    || !SHA256.test(identity.report_source_sha256 ?? '')) {
    fail('artifact_identity_mismatch', 'The core build identity does not match the pinned input, toolchain, features, and recipe.');
  }
}

async function artifactRecord(entry, binary, platform) {
  const name = `${binary}${platform === 'win32' ? '.exe' : ''}`;
  const path = `bin/${name}`;
  const absolute = join(entry, 'bin', name);
  const bytes = await regularBytes(absolute, 1024 * 1024 * 1024);
  const stat = await lstat(absolute);
  if (bytes.length === 0 || (platform !== 'win32' && (stat.mode & 0o111) === 0)) fail('invalid_artifact', 'The core artifact is empty or is not executable.');
  return { name: binary, path, sha256: hash(bytes), size: bytes.length };
}

async function verifyEntry(entry, expected, deps) {
  await privateDirectory(entry);
  await privateDirectory(join(entry, 'bin'));
  if (process.platform === 'win32') {
    await auditWindowsCachePaths([
      { path: join(entry, 'receipt.json'), kind: 'file', access: 'private' },
      ...expected.configuration.binaries.map(binary => ({ path: join(entry, 'bin', `${binary}.exe`), kind: 'file', access: 'private' })),
    ]);
  }
  const receipt = await readJson(join(entry, 'receipt.json'));
  const { receipt_sha256: digest, ...body } = receipt;
  if (!SHA256.test(digest ?? '') || hash(canonical(body)) !== digest
    || receipt.schema_version !== RECEIPT_SCHEMA || receipt.cache_key !== expected.key
    || canonical(receipt.cache_identity) !== canonical(expected.cacheIdentity)
    || receipt.build_outcome !== 'success' || !REVISION.test(receipt.source?.revision ?? '')
    || !Array.isArray(receipt.artifacts) || receipt.artifacts.length !== expected.configuration.binaries.length) {
    fail('cache_receipt_mismatch', 'The cache receipt is incomplete, corrupted, or belongs to different build inputs.');
  }
  for (const binary of expected.configuration.binaries) {
    const artifact = await artifactRecord(entry, binary, deps.platform);
    if (canonical(receipt.artifacts.find(record => record.name === binary)) !== canonical(artifact)) fail('artifact_digest_mismatch', 'A cached binary no longer matches its receipt; it was not executed.');
  }
  const executable = join(entry, 'bin', `${CORE_BIN}${deps.platform === 'win32' ? '.exe' : ''}`);
  const identity = await deps.readIdentity(executable, { environment: deps.environment });
  validateIdentity(identity, expected);
  if (canonical(identity) !== canonical(receipt.build_identity)) fail('artifact_identity_mismatch', 'The cached binary identity changed since its receipt was recorded.');
  return { receipt, executable };
}

async function publishReady(root, expected, receipt) {
  const name = `${expected.configuration.capability}-${expected.configuration.profile}-${expected.toolchain.target}.json`;
  const destination = join(root, 'ready', name);
  const existing = await safeStat(destination);
  if (existing && (!existing.isFile() || existing.isSymbolicLink() || existing.nlink !== 1)) fail('unsafe_cache_file', 'The ready pointer is not a regular cache file.');
  const temporary = join(root, 'ready', `.${randomUUID()}.json`);
  await writeFile(temporary, `${JSON.stringify({ schema_version: 'ai-security-scanner.bootstrap-ready/v1', cache_key: expected.key, receipt_sha256: receipt.receipt_sha256 })}\n`, { flag: 'wx', mode: 0o600 });
  try { await rename(temporary, destination); } finally { await rm(temporary, { force: true }); }
}

export async function loadPreparedBootstrap(options, overrides = {}) {
  validateOptions(options);
  const deps = dependencies(overrides);
  const sourceRoot = await realpath(deps.sourceRoot);
  const configuration = buildConfiguration(options);
  const source = await deps.inspectSource(sourceRoot, options.revision);
  const manifest = await deps.collectInputManifest(sourceRoot);
  if (!SHA256.test(manifest.inputDigest ?? '')) fail('invalid_input_manifest', 'The controlled source input manifest has no valid digest.');
  source.input_dirty = await deps.validatePinnedInputs(sourceRoot, options.revision, manifest);
  source.dirty ||= source.input_dirty;
  if (source.dirty && !options.allowDirty) fail('dirty_source', 'The source checkout differs from the pinned Git tree; use a clean checkout or explicitly choose --allow-dirty for development.', 2);
  const notPrepared = () => fail('core_not_prepared', 'No prepared scanner core matches this checkout. Run prepare with the same --revision, --cache-dir and --profile first.', 2);
  // Looking for a prepared core never creates a cache.
  if (!(await safeStat(validateCacheLocation(options.cacheDir, sourceRoot)))) notPrepared();
  const root = await initializeCache(options.cacheDir, sourceRoot);
  const prefix = `${configuration.capability}-${configuration.profile}-`;
  const names = (await readdir(join(root, 'ready'))).filter(name => name.startsWith(prefix) && /^[a-zA-Z0-9_-]+\.json$/.test(name.slice(prefix.length))).sort();
  if (!names.length) notPrepared();
  if (names.length > 1) fail('ambiguous_ready_pointer', `Multiple prepared scanner cores match: ${names.join(', ')}. Keep one Rust target per cache directory: run prepare again with a new --cache-dir.`, 2);
  const pointer = await readJson(join(root, 'ready', names[0]));
  if (pointer.schema_version !== 'ai-security-scanner.bootstrap-ready/v1' || !SHA256.test(pointer.cache_key ?? '') || !SHA256.test(pointer.receipt_sha256 ?? '')) fail('invalid_cache_metadata', 'Invalid ready pointer.');
  const entry = join(root, 'entries', pointer.cache_key);
  await privateDirectory(entry);
  const receipt = await readJson(join(entry, 'receipt.json'));
  const identity = receipt.cache_identity;
  if (!identity || receipt.receipt_sha256 !== pointer.receipt_sha256) fail('cache_receipt_mismatch', 'The ready pointer does not match its receipt.');
  const requested = {
    input_sha256: manifest.inputDigest, cargo_lock_sha256: manifest.files.find(file => file.path === 'Cargo.lock')?.sha256,
    recipe: RECIPE, recipe_sha256: await recipeDigest(sourceRoot), platform: deps.platform, architecture: deps.arch, ...configuration,
  };
  // The receipt names the revision that first built these inputs. A later
  // revision with identical build inputs reuses the entry, exactly as prepare does.
  if (Object.entries(requested).some(([key, value]) => canonical(identity[key]) !== canonical(value))
    || names[0] !== `${prefix}${identity.toolchain?.target}.json`) notPrepared();
  const expected = { key: pointer.cache_key, cacheIdentity: identity, configuration, toolchain: identity.toolchain, manifest };
  const verified = await verifyEntry(entry, expected, { ...deps, environment: withoutProductSourceOverrides(deps.environment) });
  return { schema_version: RESULT_SCHEMA, cache_hit: true, cache_key: pointer.cache_key, requested_source: source,
    requested_capability: options.capability ?? 'core', entry_directory: entry, receipt_path: join(entry, 'receipt.json'),
    executable: verified.executable, receipt: verified.receipt };
}

export async function prepareBootstrap(options, overrides = {}) {
  validateOptions(options);
  const deps = dependencies(overrides);
  const sourceRoot = await realpath(deps.sourceRoot);
  const configuration = buildConfiguration(options);
  const source = await deps.inspectSource(sourceRoot, options.revision);
  const manifest = await deps.collectInputManifest(sourceRoot);
  if (!SHA256.test(manifest.inputDigest ?? '')) fail('invalid_input_manifest', 'The controlled source input manifest has no valid digest.');
  source.input_dirty = await deps.validatePinnedInputs(sourceRoot, options.revision, manifest);
  source.dirty ||= source.input_dirty;
  if (source.dirty && !options.allowDirty) fail('dirty_source', 'The source checkout differs from the pinned Git tree; use a clean checkout or explicitly choose --allow-dirty for development.', 2);
  const toolchain = await deps.inspectToolchain(deps);
  const runtime = await runtimeReferences(sourceRoot);
  const root = await initializeCache(options.cacheDir, sourceRoot);
  await auditCargoConfiguration(root, controlledBuildEnvironment(deps.environment));
  const cacheIdentity = {
    input_sha256: manifest.inputDigest,
    cargo_lock_sha256: manifest.files.find(file => file.path === 'Cargo.lock')?.sha256,
    recipe: RECIPE,
    recipe_sha256: await recipeDigest(sourceRoot),
    toolchain,
    platform: deps.platform,
    architecture: deps.arch,
    native_environment: Object.fromEntries(Object.entries(controlledBuildEnvironment(deps.environment)).filter(([key]) => ['INCLUDE', 'LIB', 'LIBPATH', 'VCToolsInstallDir', 'VCINSTALLDIR', 'WindowsSdkDir', 'WindowsSDKVersion', 'UniversalCRTSdkDir', 'UCRTVersion'].includes(key))),
    ...configuration,
  };
  if (!SHA256.test(cacheIdentity.cargo_lock_sha256 ?? '')) fail('invalid_input_manifest', 'Cargo.lock must be part of the controlled source inputs.');
  const key = hash(canonical(cacheIdentity));
  const expected = { key, cacheIdentity, configuration, toolchain, manifest };
  const verifySourceUnchanged = async () => {
    const freshManifest = await deps.collectInputManifest(sourceRoot);
    const freshSource = await deps.inspectSource(sourceRoot, options.revision);
    const inputDirty = await deps.validatePinnedInputs(sourceRoot, options.revision, freshManifest);
    if (freshManifest.inputDigest !== manifest.inputDigest || await recipeDigest(sourceRoot) !== cacheIdentity.recipe_sha256
      || freshSource.revision !== source.revision || (!options.allowDirty && inputDirty)) {
      fail('source_changed', 'The pinned build inputs or recipe changed during preparation; the result was not published.');
    }
  };
  const entry = join(root, 'entries', key);
  const release = await acquireLock(root, key);
  let staging;
  let result;
  const controller = new AbortController();
  const handlers = new Map([['SIGINT', 130], ['SIGTERM', 143], ['SIGHUP', 129]].map(([signal, exitCode]) => [signal, () => controller.abort({ signal, exitCode })]));
  for (const [signal, handler] of handlers) process.on(signal, handler);
  try {
    let verified;
    const cacheHit = Boolean(await safeStat(entry));
    if (cacheHit) {
      verified = await verifyEntry(entry, expected, deps);
      await verifySourceUnchanged();
    }
    else {
      const candidate = join(root, 'staging', randomBytes(6).toString('hex'));
      await mkdir(candidate, { mode: 0o700 });
      staging = candidate;
      await privateDirectory(staging);
      const snapshot = join(staging, 'source');
      await privateDirectory(snapshot, true);
      await deps.stageInputSnapshot(sourceRoot, snapshot, manifest);
      const targetDirectory = join(staging, 'target');
      await privateDirectory(targetDirectory, true);
      try {
        await deps.build({ snapshot, targetDirectory, configuration, toolchain, manifest, environment: deps.environment, offline: options.offline === true, signal: controller.signal });
      } catch (error) {
        if (!controller.signal.aborted) throw error;
      }
      if (controller.signal.aborted) throw new BootstrapError('interrupted', 'Core preparation was interrupted.', controller.signal.reason.exitCode);
      const complete = join(staging, 'entry');
      await privateDirectory(join(complete, 'bin'), true);
      for (const binary of configuration.binaries) {
        const name = `${binary}${deps.platform === 'win32' ? '.exe' : ''}`;
        const built = join(targetDirectory, toolchain.target, configuration.profile === 'release' ? 'release' : 'debug', name);
        // Cargo may hardlink this public output to target/.../deps. Both paths
        // belong to this controlled build; the published cache receives bytes
        // in a new, single-link file and retains strict link checks on reuse.
        const bytes = await regularBytes(built, 1024 * 1024 * 1024, true);
        await writeFile(join(complete, 'bin', name), bytes, { flag: 'wx', mode: 0o700 });
      }
      const executable = join(complete, 'bin', `${CORE_BIN}${deps.platform === 'win32' ? '.exe' : ''}`);
      const identity = await deps.readIdentity(executable, { environment: deps.environment });
      validateIdentity(identity, expected);
      const artifacts = await Promise.all(configuration.binaries.map(binary => artifactRecord(complete, binary, deps.platform)));
      await verifySourceUnchanged();
      const body = {
        schema_version: RECEIPT_SCHEMA,
        cache_key: key,
        cache_identity: cacheIdentity,
        source: { ...source, input_sha256: manifest.inputDigest, development_dirty_allowed: options.allowDirty === true },
        build_identity: identity,
        artifacts,
        build_outcome: 'success',
        completed_at: new Date().toISOString(),
        runtime,
      };
      const receipt = { ...body, receipt_sha256: hash(canonical(body)) };
      await writeFile(join(complete, 'receipt.json'), `${JSON.stringify(receipt, null, 2)}\n`, { flag: 'wx', mode: 0o600 });
      // The per-key lock gives no-replace publication among bootstrap writers.
      if (await safeStat(entry)) fail('cache_entry_changed', 'A cache entry appeared while the build was in progress.');
      await rename(complete, entry);
      verified = await verifyEntry(entry, expected, deps);
    }
    if (controller.signal.aborted) throw new BootstrapError('interrupted', 'Core preparation was interrupted.', controller.signal.reason.exitCode);
    await publishReady(root, expected, verified.receipt);
    result = {
      schema_version: RESULT_SCHEMA,
      cache_hit: cacheHit,
      cache_key: key,
      requested_source: source,
      requested_capability: options.capability ?? 'core',
      runtime,
      entry_directory: entry,
      receipt_path: join(entry, 'receipt.json'),
      executable: verified.executable,
      receipt: verified.receipt,
    };
  } finally {
    try {
      // Tools stopped by an interruption can still be closing files here.
      if (staging) await rm(staging, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 });
    } finally {
      try { await release(); } finally { for (const [signal, handler] of handlers) process.off(signal, handler); }
    }
  }
  if (options.capability === 'scan') {
    // Runtime preparation owns its own data-directory lease and receipt. It
    // must not hold the unrelated core build lock while starting or fetching.
    const verified = await verifyEntry(entry, expected, deps);
    const prepareSelectedRuntime = async request => {
      const preparation = await deps.prepareRuntime(verified.executable, request, { environment: deps.environment });
      validateRuntimePreparation(preparation, request);
      if (!preparation.ready) throw new BootstrapError('runtime_preparation_failed', 'Selected scanner resources are not ready.', 4, preparation);
      return preparation;
    };
    let failure;
    let failed = false;
    let location;
    let bundleSource = options.managedRuntimeBundle ? 'explicit' : 'none';
    try { result.runtime_preparation = await prepareSelectedRuntime(options); } catch (error) { failed = true; failure = error; }
    if (failed && !options.managedRuntimeBundle && !options.offline
      && failure instanceof BootstrapError && failure.code === 'runtime_preparation_failed'
      && failure.details?.schema_version === 'ai-security-scanner.runtime-preparation/v1'
      && failure.details.ready === false && failure.details.runtime_unavailable_reason === 'no_runtime') {
      location = await locateInstalledManagedRuntimeBundle(deps);
      if (location.state === 'recognized') {
        deps.stderr.write('No Docker or Podman found. Using the scan runtime of the installed desktop app; its first start downloads a machine image and can take several minutes.\n');
        try {
          result.runtime_preparation = await prepareSelectedRuntime({ ...options, managedRuntimeBundle: location.path, expectedManagedRuntimeManifestSha256: location.manifest_sha256 });
          bundleSource = 'installed_desktop';
          failed = false;
        } catch (error) { failure = error; }
      }
    }
    if (failed) {
      const nextStep = await runtimePreparationNextStep(failure, options, deps, location);
      if (nextStep !== undefined) failure.nextStep = nextStep;
      throw failure;
    }
    result.runtime_bundle_source = bundleSource;
    if (bundleSource === 'installed_desktop') {
      result.runtime_bundle = { path: location.path, manifest_sha256: location.manifest_sha256, product_version: location.product_version };
    }
  }
  return result;
}

export async function doctorBootstrap(options, overrides = {}) {
  validateOptions(options);
  const deps = dependencies(overrides);
  const checks = [];
  async function check(name, action) {
    try { const detail = await action(); checks.push({ name, ready: true, detail }); }
    catch (error) { checks.push({ name, ready: false, reason: error.message, ...(error instanceof BootstrapError ? { error: error.code } : {}) }); }
  }
  await check('node', async () => {
    if (Number(deps.nodeVersion.split('.')[0]) < 24) fail('node_version', 'Node.js 24 or newer is required.');
    return `v${deps.nodeVersion}`;
  });
  await check('source', async () => {
    const source = await deps.inspectSource(await realpath(deps.sourceRoot), options.revision);
    const manifest = await deps.collectInputManifest(await realpath(deps.sourceRoot));
    source.input_dirty = await deps.validatePinnedInputs(await realpath(deps.sourceRoot), options.revision, manifest);
    source.dirty ||= source.input_dirty;
    if (source.dirty && !options.allowDirty) fail('dirty_source', 'The pinned source has changes; --allow-dirty is development-only.');
    return source;
  });
  try {
    const { compiler, linker, ...rustIdentity } = await deps.inspectToolchain(deps);
    checks.push({ name: 'rust_toolchain', ready: true, detail: rustIdentity });
    checks.push({ name: 'native_compiler_and_linker', ready: true, detail: { compiler, linker } });
  } catch (error) {
    checks.push(error.rustIdentity
      ? { name: 'rust_toolchain', ready: true, detail: error.rustIdentity }
      : { name: 'rust_toolchain', ready: false, reason: error.message });
    checks.push({ name: 'native_compiler_and_linker', ready: false, reason: error.rustIdentity ? error.message : 'Rust toolchain identification must succeed first.' });
  }
  await check('cache', async () => {
    const cacheDir = validateCacheLocation(options.cacheDir, await realpath(deps.sourceRoot));
    let ancestor = dirname(cacheDir);
    while (!(await safeStat(ancestor))) ancestor = dirname(ancestor);
    await directoryChain(ancestor);
    if (process.platform !== 'win32') {
      try { await access(ancestor, constants.W_OK | constants.X_OK); } catch { fail('cache_parent_not_writable', `Cache parent is not writable: ${ancestor}`); }
    }
    await auditCargoConfiguration(cacheDir, controlledBuildEnvironment(deps.environment));
    const stat = await safeStat(cacheDir);
    if (stat) {
      await privateDirectory(cacheDir);
      if (process.platform === 'win32') await auditWindowsCachePaths([{ path: join(cacheDir, MARKER), kind: 'file', access: 'private' }]);
      if ((await readJson(join(cacheDir, MARKER))).schema_version !== MARKER_SCHEMA) fail('invalid_cache_metadata', 'The directory is not a recognized bootstrap cache.');
    } else if (process.platform === 'win32') {
      let parent = dirname(cacheDir);
      while (!(await safeStat(parent))) parent = dirname(parent);
      // Node's mode argument does not set Windows ACLs. Require a private
      // parent whose inherited permissions can safely create the new cache.
      await auditWindowsCachePaths([{ path: parent, kind: 'directory', access: 'private' }]);
    }
    return { path: cacheDir, exists: Boolean(stat), creates_data: false };
  });
  await check('requested_capability', async () => {
    if (options.capability === 'scan') fail('runtime_preparation_required', 'Selected engine readiness requires explicit prepare --capability scan; doctor does not start runtimes or retrieve images.');
    return buildConfiguration(options);
  });
  return {
    schema_version: 'ai-security-scanner.bootstrap-doctor/v1',
    ready: checks.every(item => item.ready),
    checks,
    execution: { native_core: 'build identity is verified during prepare', scanner_runtime: 'not prepared', cloudflare_delegation: 'not assessed', dynamic_sandbox: 'not assessed' },
    ...(options.capability === 'scan' ? { runtime_sources: {
      compatibility_commands_on_path: await compatibilityCommandsOnPath(deps),
      installed_desktop_bundle: (await locateInstalledManagedRuntimeBundle(deps)).state,
    } } : {}),
  };
}

async function runtimePreparationNextStep(error, options, deps, location) {
  if (!(error instanceof BootstrapError) || error.code !== 'runtime_preparation_failed'
    || error.details?.schema_version !== 'ai-security-scanner.runtime-preparation/v1' || error.details.ready !== false) return undefined;
  switch (error.details.runtime_unavailable_reason) {
    case 'no_runtime': {
      if (options.offline) return 'Offline preparation needs a runtime that is already running. Start Docker or Podman, or run prepare once without --offline.';
      const state = (location ?? await locateInstalledManagedRuntimeBundle(deps)).state;
      if (state === 'unrecognized') return "The installed desktop app's scan runtime is not one this source revision recognizes. Use a newer source revision, or start Docker or Podman, then run prepare again.";
      if (state === 'absent') return 'Start Docker or Podman, or install the desktop app for this computer, then run prepare again.';
      if (state === 'unsupported') return 'Start Docker or Podman, then run prepare again.';
      return undefined;
    }
    case 'managed_runtime_unavailable':
      return 'The managed scan runtime could not start; the image errors in detail say why. Fix that, or start Docker or Podman, then run prepare again.';
    case 'managed_bundle_rejected':
      return 'The selected runtime bundle was refused; the image errors in detail say why. Select the bundle that ships with the desktop app, or start Docker or Podman.';
    default:
      return undefined;
  }
}

function validateRuntimePreparation(value, options) {
  if (!value || value.schema_version !== 'ai-security-scanner.runtime-preparation/v1' || typeof value.ready !== 'boolean'
    || value.offline !== (options.offline === true) || !Array.isArray(value.engines)
    || canonical([...value.engines].sort()) !== canonical([...options.engineIds].sort())
    || !Array.isArray(value.images) || value.images.length > 26 || !Object.hasOwn(value, 'runtime')
    || !(typeof value.receipt_path === 'string' || value.receipt_path === null)) {
    throw new BootstrapError('invalid_runtime_preparation_result', 'The core returned an incompatible or mismatched runtime preparation result.', 4, value);
  }
  if (value.ready) {
    const covered = new Set();
    const validImages = value.images.every(image => {
      if (!image || !['engine', 'gateway'].includes(image.role) || image.status !== 'ready'
        || typeof image.image !== 'string' || !/^.+@sha256:[a-f0-9]{64}$/.test(image.image)
        || !Array.isArray(image.engine_ids) || image.engine_ids.length < 1
        || image.engine_ids.some(id => !options.engineIds.includes(id))
        || new Set(image.engine_ids).size !== image.engine_ids.length) return false;
      if (image.role === 'engine') for (const id of image.engine_ids) covered.add(id);
      return true;
    });
    if (!validImages || covered.size !== options.engineIds.length || !value.runtime
      || typeof value.receipt_path !== 'string' || !value.receipt_path) {
      throw new BootstrapError('invalid_runtime_preparation_result', 'The core did not retain ready image outcomes and a receipt for every selected engine.', 4, value);
    }
  }
}

export function runtimePreparationArguments(options) {
  const args = ['--json', '--data-dir', resolve(options.dataDir)];
  if (options.managedRuntimeBundle) args.push('--managed-runtime-bundle', resolve(options.managedRuntimeBundle));
  if (options.expectedManagedRuntimeManifestSha256 !== undefined) {
    if (!options.managedRuntimeBundle) fail('invalid_request', 'An expected managed-runtime manifest digest requires a bundle.', 2);
    args.push('--expected-managed-runtime-manifest-sha256', options.expectedManagedRuntimeManifestSha256);
  }
  if (options.localImageDirectory) args.push('--release-approved-local-image-directory', resolve(options.localImageDirectory));
  args.push('runtime', 'prepare', '--engine', options.engineIds.join(','), '--bootstrap-control-stdin');
  if (options.offline) args.push('--offline');
  return args;
}

function withoutProductSourceOverrides(environment) {
  const sourceOverrides = new Set(['AI_SECURITY_SCANNER_DATA_DIR', 'AI_SECURITY_SCANNER_MANAGED_RUNTIME_BUNDLE', 'AI_SECURITY_SCANNER_RELEASE_APPROVED_LOCAL_IMAGE_DIRECTORY']);
  return Object.fromEntries(Object.entries(environment).filter(([key]) => !sourceOverrides.has(key.toUpperCase())));
}

export async function invokeRuntimePreparation(executable, options, { environment = process.env, timeoutMs = 30 * 60 * 1000, argvPrefix = [] } = {}) {
  const args = runtimePreparationArguments(options);
  const env = withoutProductSourceOverrides(environment);
  const outcome = await new Promise((resolvePromise, reject) => {
    const child = spawn(executable, [...argvPrefix, ...args], { shell: false, stdio: ['pipe', 'pipe', process.stderr], env, windowsHide: true, detached: process.platform !== 'win32' });
    const chunks = [];
    let size = 0;
    let stop;
    const requestStop = (reason, exitCode, signal = 'SIGTERM') => {
      if (stop) return;
      stop = { reason, exitCode };
      child.stdin.write(signal === 'SIGINT' ? 'cancel\n' : 'terminate\n');
    };
    const handlers = new Map([
      ['SIGINT', () => requestStop('interrupted', 130, 'SIGINT')],
      ['SIGTERM', () => requestStop('interrupted', 143)],
    ]);
    for (const [signal, handler] of handlers) process.on(signal, handler);
    const timer = setTimeout(() => requestStop('runtime_preparation_deadline', 4), timeoutMs);
    timer.unref();
    child.stdin.on('error', () => {}); // A closed child is handled by close/error below.
    const cleanup = () => {
      clearTimeout(timer);
      for (const [signal, handler] of handlers) process.off(signal, handler);
    };
    child.stdout.on('data', bytes => {
      size += bytes.length;
      if (size > MAX_RECEIPT_BYTES) requestStop('runtime_preparation_output_limit', 4);
      else chunks.push(bytes);
    });
    child.once('error', () => {
      cleanup();
      reject(new BootstrapError('runtime_preparation_unavailable', 'The verified core could not start runtime preparation.'));
    });
    child.once('close', (code, signal) => {
      cleanup();
      resolvePromise({ code: code ?? (signal === 'SIGINT' ? 130 : signal === 'SIGTERM' ? 143 : 4), stop, output: Buffer.concat(chunks).toString('utf8'), oversized: size > MAX_RECEIPT_BYTES });
    });
    // The fixed control pipe requests cancellation on every platform. Windows
    // child.kill() is forceful, so never use it for this resource-owning child.
    // Keep stdin open until the Rust owner joins bounded runtime operations and
    // persists its receipt; parent death closes the pipe and requests cleanup.
  });
  let value;
  if (!outcome.oversized) {
    try { value = JSON.parse(outcome.output); } catch { /* handled below */ }
  }
  if (outcome.stop) {
    throw new BootstrapError(outcome.stop.reason, 'Runtime preparation stopped after the core owner settled its active operation.', outcome.stop.exitCode, value);
  }
  if (outcome.code !== 0) {
    const exitCode = [2, 3, 4, 130, 143].includes(outcome.code) ? outcome.code : 4;
    throw new BootstrapError('runtime_preparation_failed', `Runtime preparation did not complete successfully (exit ${outcome.code}).`, exitCode, value);
  }
  validateRuntimePreparation(value, options);
  if (!value.ready) throw new BootstrapError('runtime_preparation_failed', 'The selected scanner resources are not ready.', 4, value);
  return value;
}

export async function runPrepared(result, argv, overrides = {}) {
  const { args, parentControl } = preparedCommandArguments(argv);
  const deps = dependencies(overrides);
  const expected = {
    key: result.cache_key,
    cacheIdentity: result.receipt.cache_identity,
    configuration: result.receipt.cache_identity,
    toolchain: result.receipt.cache_identity.toolchain,
    manifest: { inputDigest: result.receipt.cache_identity.input_sha256 },
  };
  const verified = await verifyEntry(result.entry_directory, expected, { ...deps, environment: withoutProductSourceOverrides(deps.environment) });
  return invokeCoreCommand(overrides.commandExecutable ?? verified.executable, args, { environment: withoutProductSourceOverrides(deps.environment), parentControl, argvPrefix: overrides.argvPrefix ?? [] });
}

export function invokeCoreCommand(executable, args, { environment = process.env, parentControl = false, argvPrefix = [] } = {}) {
  // Keep output connected to the consumer, preserving the core's bounded output
  // delivery. Only stdin is private. Detach owning commands on every platform
  // so parent death closes the pipe instead of killing the child (including
  // Windows job teardown). The child stays referenced until close.
  return new Promise((resolvePromise, reject) => {
    const child = spawn(executable, [...argvPrefix, ...args], {
      shell: false, env: environment, windowsHide: true,
      stdio: parentControl ? ['pipe', 'inherit', 'inherit'] : 'inherit',
      detached: parentControl,
    });
    let requested = false;
    const requestStop = signal => {
      if (!parentControl) { child.kill(signal); return; }
      if (requested) return;
      requested = true;
      child.stdin.end(signal === 'SIGINT' ? 'cancel\n' : 'terminate\n');
    };
    child.stdin?.on('error', () => {}); // Early exit is handled by close/error.
    const handlers = new Map(['SIGINT', 'SIGTERM'].map(signal => [signal, () => requestStop(signal)]));
    for (const [signal, handler] of handlers) process.on(signal, handler);
    const clean = () => { for (const [signal, handler] of handlers) process.off(signal, handler); };
    child.once('error', error => { clean(); reject(error); });
    child.once('close', (code, signal) => { clean(); resolvePromise(code ?? (signal === 'SIGINT' ? 130 : signal === 'SIGTERM' ? 143 : 4)); });
  });
}

export function preparedCommandArguments(argv) {
  const command = validateRunArguments(argv);
  const action = command.slice(globalOptionEnd(command, 1))[0];
  const parentControl = (command[0] === 'scan' && ['run', 'recover'].includes(action))
    || (command[0] === 'runtime' && action === 'prepare');
  const flag = '--bootstrap-control-stdin';
  return { args: parentControl && !argv.includes(flag) ? [...argv, flag] : [...argv], parentControl };
}

function globalOptionEnd(argv, start = 0) {
  let index = start;
  for (; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === '--json') continue;
    if (['--data-dir', '--managed-runtime-bundle', '--release-approved-local-image-directory'].includes(argument)) { index += 1; continue; }
    if (['--data-dir=', '--managed-runtime-bundle=', '--release-approved-local-image-directory='].some(prefix => argument.startsWith(prefix))) continue;
    break;
  }
  return index;
}

export function validateRunArguments(argv) {
  if (!Array.isArray(argv) || argv.some(value => typeof value !== 'string' || value.includes('\0'))) fail('invalid_arguments', 'CLI arguments must be ordinary strings.', 2);
  const independent = [
    ['build-identity'], ['--json', 'build-identity'], ['build-identity', '--json'],
    ['--help'], ['-h'], ['--version'], ['-V'],
  ];
  if (independent.some(shape => canonical(shape) === canonical(argv))) return [];
  // Require the data choice before the subcommand, so a path/value named
  // --data-dir or build-identity cannot masquerade as a global option.
  let explicitData = false;
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === '--json') continue;
    if (argument.startsWith('--data-dir=')) {
      if (argument.slice('--data-dir='.length).length > 0) explicitData = true;
      continue;
    }
    if (['--data-dir', '--managed-runtime-bundle', '--release-approved-local-image-directory'].includes(argument)) {
      const value = argv[++index];
      if (!value || value.startsWith('--')) fail('invalid_arguments', `Missing value for ${argument}.`, 2);
      if (argument === '--data-dir') explicitData = true;
      continue;
    }
    if (argument.startsWith('--managed-runtime-bundle=') || argument.startsWith('--release-approved-local-image-directory=')) continue;
    break;
  }
  const tail = argv.slice(globalOptionEnd(argv));
  if (tail[0] === 'archive' && ['verify', 'restore-preview', 'restore'].includes(tail[1])) return tail;
  if (!explicitData) fail('explicit_data_directory_required', 'Pass --data-dir DIR before the CLI subcommand to select its data explicitly; bootstrap does not default to existing desktop data.', 2);
  return argv.slice(globalOptionEnd(argv));
}
