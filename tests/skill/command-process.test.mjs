import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { invokeCoreCommand, preparedCommandArguments } from '../../scripts/skill/bootstrap-core.mjs';

async function untilFile(path) {
  const deadline = Date.now() + 5000;
  while (Date.now() < deadline) {
    try { return await readFile(path, 'utf8'); } catch (error) { if (error.code !== 'ENOENT') throw error; }
    await new Promise(resolve => setTimeout(resolve, 10));
  }
  assert.fail(`Child never wrote ${path}`);
}

async function ownerFixture(t) {
  const root = await mkdtemp(join(tmpdir(), 'scanner-command-owner-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const script = join(root, 'owner.mjs');
  const ready = join(root, 'ready');
  const receipt = join(root, 'receipt');
  await writeFile(script, `
    import { writeFileSync } from 'node:fs';
    let control = '';
    const watchdog = setTimeout(() => process.exit(99), 10000);
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', bytes => { control += bytes; });
    process.stdin.on('end', () => {
      clearTimeout(watchdog);
      setTimeout(() => {
        writeFileSync(process.argv[3], control || 'parent exited');
        process.exit(control === 'terminate\\n' ? 143 : 130);
      }, 80);
    });
    writeFileSync(process.argv[2], String(process.pid));
  `);
  return { root, script, ready, receipt, args: [script, ready, receipt] };
}

test('only owning subcommands receive the fixed control pipe, independent of option values', () => {
  for (const tail of [
    ['scan', 'run', '--case-id', 'fixture', '--wait'],
    ['scan', 'recover', '--case-id', 'fixture', '--run-id', 'run', '--wait'],
    ['scan', '--json', 'run', '--wait'],
    ['scan', '--managed-runtime-bundle', 'status', 'recover', '--wait'],
    ['runtime', 'prepare', '--engine', 'gitleaks'],
    ['runtime', '--json', 'prepare', '--engine', 'gitleaks'],
  ]) {
    const args = ['--data-dir', 'selected data', ...tail];
    assert.deepEqual(preparedCommandArguments(args), { args: [...args, '--bootstrap-control-stdin'], parentControl: true });
    assert.deepEqual(preparedCommandArguments([...args, '--bootstrap-control-stdin']).args, [...args, '--bootstrap-control-stdin']);
  }
  for (const args of [
    ['--help'], ['--json', 'build-identity'],
    ['--data-dir', 'scan', 'case', 'list'],
    ['--data-dir', 'data', 'scan', 'status', '--case-id', 'run'],
    ['--data-dir', 'data', 'case', 'show', 'scan', 'run'],
    ['--data-dir', 'data', 'runtime', 'managed', 'status'],
    ['--data-dir', 'data', 'scan', '--unknown', 'run'],
  ]) assert.deepEqual(preparedCommandArguments(args), { args, parentControl: false });
});

for (const [signal, control, code] of [['SIGINT', 'cancel\n', 130], ['SIGTERM', 'terminate\n', 143]]) {
  test(`${signal} requests cancellation once and waits for the owned child receipt`, async t => {
    const fixture = await ownerFixture(t);
    const counts = ['SIGINT', 'SIGTERM'].map(name => process.listenerCount(name));
    const completion = invokeCoreCommand(process.execPath, fixture.args, { parentControl: true });
    await untilFile(fixture.ready);
    process.emit(signal);
    process.emit(signal === 'SIGINT' ? 'SIGTERM' : 'SIGINT');
    assert.equal(await completion, code);
    assert.equal(await readFile(fixture.receipt, 'utf8'), control);
    assert.deepEqual(['SIGINT', 'SIGTERM'].map(name => process.listenerCount(name)), counts);
  });
}

test('parent death closes the control pipe and lets the child save its outcome', async t => {
  const fixture = await ownerFixture(t);
  const module = new URL('../../scripts/skill/bootstrap-core.mjs', import.meta.url).href;
  const parent = spawn(process.execPath, ['--input-type=module', '-e', `
    import { invokeCoreCommand } from ${JSON.stringify(module)};
    process.exitCode = await invokeCoreCommand(process.execPath, process.argv.slice(1), { parentControl: true });
  `, ...fixture.args], { stdio: 'ignore' });
  const parentClosed = new Promise((resolve, reject) => { parent.once('close', resolve); parent.once('error', reject); });
  t.after(() => { if (parent.exitCode === null && parent.signalCode === null) parent.kill('SIGKILL'); });
  await untilFile(fixture.ready);
  parent.kill('SIGKILL');
  await parentClosed;
  assert.equal(await untilFile(fixture.receipt), 'parent exited');
});

test('normal completion keeps the pipe open and returns the actual child outcome', async () => {
  assert.equal(await invokeCoreCommand(process.execPath, ['-e', `
    process.stdin.on('data', () => process.exit(98));
    process.stdin.on('end', () => process.exit(99));
    setTimeout(() => process.exit(17), 50);
  `], { parentControl: true }), 17);
});

test('spawn failure removes cancellation listeners', async () => {
  const counts = ['SIGINT', 'SIGTERM'].map(name => process.listenerCount(name));
  await assert.rejects(invokeCoreCommand(join(tmpdir(), 'absent-scanner-core', 'cli'), [], { parentControl: true }), { code: 'ENOENT' });
  assert.deepEqual(['SIGINT', 'SIGTERM'].map(name => process.listenerCount(name)), counts);
});
