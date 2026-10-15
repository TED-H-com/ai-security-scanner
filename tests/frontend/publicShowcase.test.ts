import assert from 'node:assert/strict';
import { readFile, stat } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { JSDOM } from 'jsdom';
import { buildOutputs, sha256, stripSampleAdditions } from '../../scripts/build-public-showcase.mjs';

const root = fileURLToPath(new URL('../../', import.meta.url));
const read = (path: string) => readFile(resolve(root, path), 'utf8');
const json = async (path: string) => JSON.parse(await read(path));
const samplePath = 'docs/samples/v0.4.0/';
const inventory = new Set(['cloudquery','steampipe','naabu','httpx','syft','agentic-radar']);

test('every frozen adapter has a real format fixture and an attributed sample result', async () => {
  const [catalog, sources, generation, content, frozenReport] = await Promise.all([
    json('engines/catalog.json'), json('docs/scanner-guide.sources.json'),
    json(samplePath+'sample-generation.json'), json('docs/scanner-guide.content.json'),
    read(samplePath+'sample-report-full-en.html'),
  ]);
  const integrated = catalog.filter((e: any) => e.status === 'integrated');
  assert.equal(integrated.length, 25);
  assert.equal(generation.liveTargetContact, false);
  assert.equal(sources.releaseSourceCommit, content.releaseSourceCommit);
  assert.equal(generation.productVersion, content.productVersion);
  for (const rows of [sources.scanners, content.scanners, generation.sources]) {
    assert.deepEqual(rows.map((s: any) => s.id ?? s.engineId).sort(), integrated.map((s: any) => s.id).sort());
  }
  for (const engine of integrated) {
    const source = sources.scanners.find((s: any) => s.id === engine.id);
    const result = generation.sources.find((s: any) => s.engineId === engine.id);
    assert.ok(result.findings + result.inventoryObservations > 0, engine.id);
    assert.equal(result.findings === 0, inventory.has(engine.id), engine.id);
    // These v0.4.0 examples retain their recorded scanner versions when the
    // runnable catalog advances. Bind them to the checksummed frozen export.
    assert.ok(frozenReport.includes(source.image.digest), engine.id);
    assert.match(source.sourceRevision, /^[0-9a-f]{40}$/u);
    assert.equal(result.engineVersion, source.engineVersion);
    assert.equal(result.adapterVersion, source.adapterVersion);
    assert.equal(sha256(await read(source.fixturePath)), source.fixtureSha256);
    assert.equal(result.fixtureSha256, source.fixtureSha256);
    assert.ok(Date.parse(source.upstreamRevisionDate) <= Date.parse(content.reviewedAt+'T23:59:59Z'));
    assert.ok(source.readmeUrl.includes(source.sourceRevision));
  }
  assert.equal(generation.sources.reduce((n: number,s: any) => n+s.findings,0), generation.findings);
  assert.equal(generation.sources.reduce((n: number,s: any) => n+s.inventoryObservations,0), generation.inventoryObservations);
});

test('public additions preserve the original product export bytes and all 25 sources', async () => {
  const manifest = await json(samplePath+'manifest.json');
  assert.equal(manifest.exports.length, 4);
  for (const entry of manifest.exports) {
    const html = await read(samplePath+entry.file);
    assert.equal(sha256(html),entry.sha256);
    assert.equal(Buffer.byteLength(html),entry.bytes);
    const original = stripSampleAdditions(html);
    assert.equal(sha256(original),entry.standardExportSha256);
    const dom = new JSDOM(html);
    assert.equal(dom.window.document.querySelectorAll('.public-sample-banner').length,1);
    assert.equal(dom.window.document.querySelectorAll('.sample-sources article').length,25);
    for (const source of manifest.sources) {
      assert.ok(dom.window.document.getElementById('sample-source-'+source.engineId));
      const identity = entry.locale === 'en' ? 'engine '+source.engineId+';' : '引擎 '+source.engineId+'；';
      assert.ok(original.includes(identity), source.engineId+' must exist in standard export provenance');
    }
    assert.equal(dom.window.document.querySelectorAll('script,iframe,form,img').length,0);
    assert.ok(dom.window.document.querySelector('meta[http-equiv="Content-Security-Policy"]'));
    dom.window.close();
  }
});

test('redaction changes identity fields without losing report facts or exposing secrets', async () => {
  for (const locale of ['en','zh-TW']) {
    const redacted = await read(samplePath+`sample-report-redacted-${locale}.html`);
    const full = await read(samplePath+`sample-report-full-${locale}.html`);
    for (const value of ['ExampleCo','123456789012','portal.example.test','passive.example.test','model.example.test']) {
      assert.ok(!redacted.includes(value), 'identity leaked: '+value);
      assert.ok(full.includes(value), 'full context absent: '+value);
    }
    for (const value of ['SECRET_SENTINEL_MUST_NEVER_LEAK','synthetic-fixture-only-no-provider-access']) {
      assert.ok(!redacted.includes(value) && !full.includes(value));
    }
    const docs = [redacted,full].map(html => new JSDOM(html));
    const facts = docs.map(dom => [...dom.window.document.querySelectorAll('.kpi__value')].map(e => e.textContent));
    assert.ok(facts[0].length > 0);
    assert.deepEqual(facts[0],facts[1]);
    for (const dom of docs) dom.window.close();
  }
});

test('the published files regenerate from their frozen inputs without changing the standard report', async () => {
  const outputs = await buildOutputs();
  for (const [path, expected] of outputs) assert.equal(await read(path), expected, path);
});

async function page(path: string) {
  const dom = new JSDOM(await read('docs/'+path), {url:'https://example.test/'+path,runScripts:'outside-only'});
  dom.window.HTMLElement.prototype.scrollIntoView = () => {};
  dom.window.requestAnimationFrame = (callback: FrameRequestCallback) => { callback(0); return 1; };
  dom.window.eval(await read('docs/project-site.js'));
  return dom;
}

test('guide search, categories, hash links and language changes work together', async () => {
  const dom = await page('scanner-guide.html');
  dom.window.eval(await read('docs/scanner-guide.js'));
  const doc = dom.window.document;
  const search = doc.querySelector<HTMLInputElement>('#scanner-search')!;
  const category = doc.querySelector<HTMLSelectElement>('#scanner-category')!;
  const visible = () => [...doc.querySelectorAll<HTMLElement>('.scanner-entry')].filter(e => !e.hidden);
  assert.equal(visible().length,25);
  category.value='ai'; category.dispatchEvent(new dom.window.Event('change'));
  assert.equal(visible().length,3);
  search.value='hardcoded_secrets'; search.dispatchEvent(new dom.window.Event('input'));
  assert.deepEqual(visible().map(e=>e.id),['mcp-armor']);
  search.value='no scanner has this phrase'; search.dispatchEvent(new dom.window.Event('input'));
  assert.equal(visible().length,0);
  assert.equal(doc.querySelector<HTMLElement>('#scanner-empty')!.hidden,false);
  dom.window.location.hash='#trivy'; dom.window.dispatchEvent(new dom.window.HashChangeEvent('hashchange'));
  assert.equal(visible().length,25);
  assert.equal(doc.querySelector<HTMLDetailsElement>('#trivy')!.open,true);
  doc.querySelector<HTMLButtonElement>('[data-language="zh-TW"]')!.click();
  assert.match(doc.title,/掃描器指南/);
  assert.equal(doc.documentElement.lang,'zh-Hant');
  assert.equal(category.options[0].textContent,'所有分類');
  assert.match(doc.querySelector('#scanner-count')!.textContent!,/25 \/ 25 個掃描器/);
  assert.equal(dom.window.location.hash,'#trivy');
  assert.ok(doc.querySelector<HTMLAnchorElement>('a[data-href-zh^="sample-reports"]')!.href.includes('?lang=zh-TW'));
  for (const entry of doc.querySelectorAll('.scanner-entry')) {
    assert.equal(entry.querySelectorAll('.swot-grid section').length,4);
    for (const section of entry.querySelectorAll('.swot-grid section')) {
      assert.ok(section.querySelector('p .lang-en')!.textContent!.length>40);
      assert.ok(section.querySelector('p .lang-zh')!.textContent!.length>20);
    }
  }
  dom.window.close();
});

test('homepage language switch points both downloads at the selected report language', async () => {
  const dom = await page('index.html');
  const doc = dom.window.document;
  const downloads = [...doc.querySelectorAll<HTMLAnchorElement>('#sample-reports a[download]')];
  assert.equal(downloads.length,2);
  assert.ok(downloads.every(a=>a.href.endsWith('-en.html')));
  doc.querySelector<HTMLButtonElement>('[data-language="zh-TW"]')!.click();
  assert.ok(downloads.every(a=>a.href.endsWith('-zh-TW.html')));
  assert.equal(doc.querySelector('#sample-reports')!.closest('.section-dark'),null);
  doc.querySelector<HTMLButtonElement>('[data-language="en"]')!.click();
  assert.ok(downloads.every(a=>a.href.endsWith('-en.html')));
  dom.window.close();
});

test('every local website/download link resolves, including alternate-language destinations', async () => {
  for (const path of ['index.html','scanner-guide.html','sample-reports.html','check-fixes-demo.html']) {
    const dom = new JSDOM(await read('docs/'+path),{url:'https://example.test/'+path});
    for (const element of dom.window.document.querySelectorAll('a[href],link[href],script[src],img[src]')) {
      for (const attr of ['href','src','data-href-en','data-href-zh']) {
        const raw = element.getAttribute(attr); if (!raw) continue;
        const url = new URL(raw,dom.window.location.href);
        if (url.origin!=='https://example.test') continue;
        const target = decodeURIComponent(url.pathname).replace(/^\//,'') || 'index.html';
        assert.ok((await stat(resolve(root,'docs',target))).isFile(), target);
        if (url.hash && target.endsWith('.html')) {
          const linked = target===path ? dom : new JSDOM(await read('docs/'+target));
          assert.ok(linked.window.document.getElementById(decodeURIComponent(url.hash.slice(1))),raw);
          if (linked!==dom) linked.window.close();
        }
      }
    }
    dom.window.close();
  }
});
