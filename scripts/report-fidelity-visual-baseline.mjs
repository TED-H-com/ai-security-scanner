#!/usr/bin/env node
// Capture fixed HTML outputs with a caller-selected Chromium. No package fetch,
// application server, scanner runtime, or external page request is required.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtemp, mkdir, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const args = process.argv.slice(2);
const option = (name) => {
  const index = args.indexOf(name);
  assert(index >= 0 && args[index + 1], `Missing ${name}`);
  return path.resolve(args[index + 1]);
};
const executable = option('--browser');
const reports = option('--reports');
const destination = option('--output');
await mkdir(destination, { recursive: true });
assert.equal((await readdir(destination)).length, 0, 'Visual output must be empty');
const profile = await mkdtemp(path.join(tmpdir(), 'report-fidelity-chromium-'));
const browser = spawn(executable, [
  '--headless', '--no-sandbox', '--disable-gpu', '--disable-background-networking',
  '--disable-extensions', '--disable-sync', '--no-first-run', '--no-default-browser-check',
  '--force-device-scale-factor=1', '--remote-debugging-port=0', `--user-data-dir=${profile}`,
  'about:blank',
], { stdio: ['ignore', 'ignore', 'pipe'] });
let socket;
let nextId = 0;
const pending = new Map();
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');

try {
  const websocket = await new Promise((resolve, reject) => {
    let stderr = '';
    const timeout = setTimeout(() => reject(new Error('Chromium did not become ready')), 20_000);
    browser.on('error', reject);
    browser.on('exit', (code) => reject(new Error(`Chromium exited: ${code}`)));
    browser.stderr.on('data', (chunk) => {
      stderr += chunk;
      const match = stderr.match(/DevTools listening on (ws:\/\/[^\s]+)/);
      if (match) {
        clearTimeout(timeout);
        resolve(match[1]);
      }
    });
  });
  socket = new WebSocket(websocket);
  await new Promise((resolve, reject) => {
    socket.addEventListener('open', resolve, { once: true });
    socket.addEventListener('error', reject, { once: true });
  });
  socket.addEventListener('message', ({ data }) => {
    const message = JSON.parse(data);
    const entry = pending.get(message.id);
    if (!entry) return;
    pending.delete(message.id);
    if (message.error) entry.reject(new Error(JSON.stringify(message.error)));
    else entry.resolve(message.result);
  });
  const send = (method, params = {}, sessionId) => new Promise((resolve, reject) => {
    const id = ++nextId;
    pending.set(id, { resolve, reject });
    socket.send(JSON.stringify({ id, method, params, ...(sessionId ? { sessionId } : {}) }));
  });
  const version = await send('Browser.getVersion');
  const captures = [];
  for (const scenario of ['all-detectors', 'mixed-terminal']) {
    for (const locale of ['en', 'zh-Hant']) {
      const file = path.join(reports, scenario, `${locale}-standard.html`);
      const sourceSha256 = sha256(await readFile(file));
      const { targetId } = await send('Target.createTarget', { url: 'about:blank' });
      const { sessionId } = await send('Target.attachToTarget', { targetId, flatten: true });
      const page = (method, params = {}) => send(method, params, sessionId);
      await page('Page.enable');
      await page('Network.enable');
      await page('Network.setBlockedURLs', { urls: ['http://*', 'https://*'] });
      await page('Page.navigate', { url: pathToFileURL(file).href });
      for (const width of [390, 768, 1440]) {
        await page('Emulation.setDeviceMetricsOverride', { width, height: 960, deviceScaleFactor: 1, mobile: false });
        await page('Runtime.evaluate', {
          expression: `new Promise(resolve => {
            const finish = async () => { await document.fonts.ready; window.scrollTo(0, 0); requestAnimationFrame(() => requestAnimationFrame(resolve)); };
            if (document.readyState === 'complete') finish(); else window.addEventListener('load', finish, { once: true });
          })`,
          awaitPromise: true,
        });
        const modes = width === 1440 ? ['screen', 'expanded-detail', 'print'] : ['screen'];
        for (const mode of modes) {
          await page('Emulation.setEmulatedMedia', { media: mode === 'print' ? 'print' : 'screen' });
          if (mode === 'expanded-detail') {
            await page('Runtime.evaluate', { expression: `(() => { const detail = document.querySelector('details'); if (detail) { detail.open = true; detail.scrollIntoView({ block: 'start' }); } })()` });
          } else {
            await page('Runtime.evaluate', { expression: `document.querySelectorAll('details').forEach(detail => detail.open = false); window.scrollTo(0, 0)` });
          }
          const { result } = await page('Runtime.evaluate', { returnByValue: true, expression: `({
            title: document.title, language: document.documentElement.lang,
            headingCount: document.querySelectorAll('h1,h2,h3').length,
            detailsCount: document.querySelectorAll('details').length,
            viewportWidth: innerWidth, documentWidth: document.documentElement.scrollWidth,
            horizontalOverflow: document.documentElement.scrollWidth > innerWidth + 1,
            bodyTextLength: document.body.innerText.length,
            fontsReady: document.fonts.status === 'loaded'
          })` });
          const screenshot = await page('Page.captureScreenshot', { format: 'png', captureBeyondViewport: false });
          const bytes = Buffer.from(screenshot.data, 'base64');
          const name = `${scenario}-${locale}-${width}-${mode}.png`;
          await writeFile(path.join(destination, name), bytes);
          captures.push({ file: name, source: `${scenario}/${locale}-standard.html`, sourceSha256, width, height: 960, mode, sha256: sha256(bytes), byteLength: bytes.length, ...result.value });
        }
      }
      await send('Target.closeTarget', { targetId });
    }
  }
  await writeFile(path.join(destination, 'receipt.json'), JSON.stringify({
    schemaVersion: 1, capturedAt: new Date().toISOString(), browser: version,
    method: 'Chromium DevTools Protocol; local frozen production HTML; HTTP(S) blocked',
    command: 'node scripts/report-fidelity-visual-baseline.mjs --browser <chromium> --reports <verified-output> --output <empty-directory>',
    purpose: 'Reviewable rendering reference; pixel identity across different browsers/fonts is not promised',
    captures,
  }, null, 2) + '\n');
  console.log(`Captured ${captures.length} screenshots; horizontal overflow: ${captures.filter(capture => capture.horizontalOverflow).length}`);
} finally {
  socket?.close();
  browser.kill('SIGTERM');
  await new Promise((resolve) => {
    if (browser.exitCode !== null) resolve();
    else { browser.once('exit', resolve); setTimeout(() => { browser.kill('SIGKILL'); resolve(); }, 5_000).unref(); }
  });
  await rm(profile, { recursive: true, force: true });
}
