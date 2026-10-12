import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { JSDOM } from 'jsdom';
import { addJapanese } from '../../scripts/localize-public-site.mjs';

const read = (path: string) => readFile(new URL('../../docs/' + path, import.meta.url), 'utf8');
const pages = ['index', 'scanner-guide', 'sample-reports', 'check-fixes-demo'];
const [initial, runtime, guide, dictionary] = await Promise.all([
  read('site-language.js'), read('project-site.js'), read('scanner-guide.js'), read('locales/ja.json'),
]);

async function open(name: string, query = '', languages = ['ja-JP', 'en-US'], saved?: string, blocked = false) {
  const dom = new JSDOM(await read(name + '.html'), { url: 'https://example.test/' + name + '.html' + query, runScripts: 'outside-only' });
  Object.defineProperty(dom.window.navigator, 'languages', { value: languages });
  if (saved) dom.window.localStorage.setItem('ai-security-scanner.site-language', saved);
  if (blocked) Object.defineProperty(dom.window, 'localStorage', { get() { throw new Error('Storage blocked'); } });
  dom.window.eval(initial);
  dom.window.eval(runtime);
  return dom;
}

test('Japanese website URLs select translated pages, metadata and navigation with English report downloads', async () => {
  for (const name of pages) {
    const dom = await open(name, '?lang=ja#main', ['zh-TW']);
    const doc = dom.window.document;
    assert.equal(doc.documentElement.lang, 'ja');
    assert.match(doc.title, /[ぁ-んァ-ヶ]/u);
    assert.match(doc.querySelector('meta[name="description"]')!.getAttribute('content')!, /[ぁ-んァ-ヶ]/u);
    assert.equal(doc.querySelector('meta[property="og:locale"]')!.getAttribute('content'), 'ja_JP');
    assert.equal(doc.querySelector('[data-language="ja"]')!.getAttribute('aria-pressed'), 'true');
    assert.ok(doc.querySelector('link[hreflang="ja"]'));
    assert.equal(doc.querySelectorAll('.lang-ja').length, doc.querySelectorAll('.lang-en').length);
    for (const link of doc.querySelectorAll<HTMLAnchorElement>('a[data-href-en]')) {
      const url = new URL(link.href);
      if (url.origin === dom.window.location.origin && pages.some(page => url.pathname.endsWith('/' + page + '.html'))) {
        assert.equal(url.searchParams.get('lang'), 'ja', link.href);
      }
    }
    for (const link of doc.querySelectorAll<HTMLAnchorElement>('a[download][data-href-en], .lang-ja a[download]')) {
      assert.ok(link.href.endsWith('-en.html'), link.href);
    }
    doc.querySelector<HTMLButtonElement>('[data-language="en"]')!.click();
    assert.equal(doc.documentElement.lang, 'en');
    assert.equal(new URL(dom.window.location.href).searchParams.get('lang'), 'en');
    assert.equal(dom.window.location.hash, '#main');
    assert.equal(dom.window.localStorage.getItem('ai-security-scanner.site-language'), 'en');
    dom.window.eval(initial); // Reload must retain English even with a Chinese browser.
    assert.equal(doc.documentElement.lang, 'en');
    dom.window.close();
  }
});

test('website locale respects URL, saved preference, browser ordering, and blocked storage', async () => {
  for (const [query, languages, saved, blocked, expected] of [
    ['?lang=ja', ['en'], 'zh-TW', false, 'ja'],
    ['', ['ja-JP'], 'en', false, 'en'],
    ['', ['ja-JP', 'zh-TW'], undefined, false, 'ja'],
    ['', ['en-US', 'zh-TW'], undefined, false, 'en'],
    ['', ['fr-FR'], undefined, false, 'en'],
    ['?lang=ja', ['en'], undefined, true, 'ja'],
  ] as const) {
    const dom = await open('index', query, [...languages], saved, blocked);
    assert.equal(dom.window.document.documentElement.dataset.lang, expected);
    dom.window.document.querySelector<HTMLButtonElement>('[data-language="ja"]')!.click();
    assert.equal(dom.window.document.documentElement.lang, 'ja');
    dom.window.close();
  }
});

test('Japanese guide search and categories keep counts and deep links usable', async () => {
  const dom = await open('scanner-guide');
  const doc = dom.window.document;
  dom.window.HTMLElement.prototype.scrollIntoView = () => {};
  dom.window.requestAnimationFrame = callback => { callback(0); return 1; };
  dom.window.eval(guide);
  const search = doc.querySelector<HTMLInputElement>('#scanner-search')!;
  const category = doc.querySelector<HTMLSelectElement>('#scanner-category')!;
  assert.equal(category.options[0].textContent, 'すべての分類');
  category.value = 'ai';
  search.value = '過剰な権限';
  search.dispatchEvent(new dom.window.Event('input'));
  assert.deepEqual([...doc.querySelectorAll<HTMLElement>('.scanner-entry')].filter(e => !e.hidden).map(e => e.id), ['mcp-armor']);
  assert.equal(doc.querySelector('#scanner-count')!.textContent, '1 / 25 件のスキャナー');
  dom.window.location.hash = '#trivy';
  dom.window.dispatchEvent(new dom.window.HashChangeEvent('hashchange'));
  assert.equal(doc.querySelector<HTMLDetailsElement>('#trivy')!.open, true);
  assert.equal(doc.querySelector('#scanner-count')!.textContent, '25 / 25 件のスキャナー');
  dom.window.close();
});

test('all scanner prose has Japanese copy, and hand-maintained pages can regenerate without drift', async () => {
  const messages = JSON.parse(dictionary);
  const content = JSON.parse(await read('scanner-guide.content.json'));
  for (const scanner of content.scanners) {
    for (const [field, value] of Object.entries(scanner) as [string, any][]) {
      if (value?.en) assert.ok(messages[value.en], `${scanner.id}/${field} needs Japanese copy`);
    }
  }
  for (const name of ['index', 'check-fixes-demo']) {
    const html = await read(name + '.html');
    assert.equal(addJapanese(html), html, name);
  }
});
