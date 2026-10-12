// Add static Japanese markup while retaining the hand-written English/Chinese bytes.
import { readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { JSDOM } from 'jsdom';

const messages = JSON.parse(await readFile(new URL('../docs/locales/ja.json', import.meta.url), 'utf8'));
const translate = value => Object.hasOwn(messages, value.trim()) ? messages[value.trim()] : value.trim();
const sitePages = new Set(['index.html', 'scanner-guide.html', 'sample-reports.html', 'check-fixes-demo.html']);

export function addJapanese(html) {
  // Rebuild existing Japanese blocks too, so dictionary updates cannot leave stale copy.
  const previous = new JSDOM(html, { includeNodeLocations: true });
  const generated = [...previous.window.document.querySelectorAll('.lang-ja, [data-language="ja"], link[hreflang="ja"]')];
  for (const element of generated.filter(node => !node.parentElement.closest('.lang-ja'))
    .sort((a, b) => previous.nodeLocation(b).startOffset - previous.nodeLocation(a).startOffset)) {
    const { startOffset, endOffset } = previous.nodeLocation(element);
    html = html.slice(0, startOffset) + html.slice(endOffset);
  }
  previous.window.close();
  const dom = new JSDOM(html, { includeNodeLocations: true });
  const { document, NodeFilter } = dom.window;
  const edits = [];
  const replace = (element, replacement) => {
    const { startOffset, endOffset } = dom.nodeLocation(element);
    edits.push({ start: startOffset, end: endOffset, text: replacement });
  };
  for (const element of document.querySelectorAll('.lang-en')) {
    if (element.parentElement.closest('.lang-en')) continue;
    const clone = element.cloneNode(true);
    clone.classList.replace('lang-en', 'lang-ja');
    clone.lang = 'ja';
    const walker = document.createTreeWalker(clone, NodeFilter.SHOW_TEXT);
    while (walker.nextNode()) {
      const node = walker.currentNode;
      if (node.textContent.trim()) node.textContent = node.textContent.replace(/\S[\s\S]*\S|\S/, translate);
    }
    for (const node of [clone, ...clone.querySelectorAll('[alt], [aria-label]')]) {
      for (const attr of ['alt', 'aria-label']) if (node.hasAttribute(attr)) node.setAttribute(attr, translate(node.getAttribute(attr)));
    }
    if (clone.dataset.fd) {
      const flow = JSON.parse(clone.dataset.fd);
      if (flow.lanes) flow.lanes = flow.lanes.map(translate);
      clone.dataset.fd = JSON.stringify(flow);
    }
    // The original English/Chinese report files remain the downloadable evidence.
    for (const link of clone.querySelectorAll('a[href]')) {
      const url = new URL(link.getAttribute('href'), 'https://site.invalid/');
      if (url.origin === 'https://site.invalid' && sitePages.has(url.pathname.slice(1))) {
        url.searchParams.set('lang', 'ja');
        link.setAttribute('href', url.pathname.slice(1) + url.search + url.hash);
      }
    }
    const { endOffset } = dom.nodeLocation(element);
    edits.push({ start: endOffset, end: endOffset, text: clone.outerHTML });
  }
  for (const element of document.querySelectorAll('title, meta[name="description"]')) {
    element.dataset.ja = translate(element.tagName === 'TITLE' ? element.textContent : element.content);
    replace(element, element.outerHTML);
  }
  for (const element of document.querySelectorAll('[aria-label], img[alt], option[data-label-en]')) {
    if (element.closest('.lang-en, .lang-zh')) continue;
    for (const attr of ['aria-label', 'alt']) if (element.getAttribute(attr)) {
      element.setAttribute(`data-${attr}-en`, element.getAttribute(attr));
      element.setAttribute(`data-${attr}-ja`, translate(element.getAttribute(attr)));
    }
    if (element.dataset.labelEn) element.dataset.labelJa = translate(element.dataset.labelEn);
    // Replace only the opening tag: a nav or a language group contains other edits.
    const { startOffset, startTag } = dom.nodeLocation(element);
    edits.push({ start: startOffset, end: startTag.endOffset, text: element.outerHTML.slice(0, element.outerHTML.indexOf('>') + 1) });
  }
  const switcher = document.querySelector('[data-language="zh-TW"]');
  if (switcher) {
    const { endOffset } = dom.nodeLocation(switcher);
    edits.push({ start: endOffset, end: endOffset, text: '<button type="button" data-language="ja" aria-pressed="false">日本語</button>' });
  }
  const alternate = document.querySelector('link[hreflang="en"]');
  if (alternate) {
    const clone = alternate.cloneNode();
    clone.hreflang = 'ja';
    clone.href += '?lang=ja';
    const { endOffset } = dom.nodeLocation(alternate);
    edits.push({ start: endOffset, end: endOffset, text: clone.outerHTML });
  }
  for (const script of document.querySelectorAll('head script:not([src])')) replace(script, '<script src="site-language.js"></script>');
  for (const edit of edits.sort((a, b) => b.start - a.start)) html = html.slice(0, edit.start) + edit.text + html.slice(edit.end);
  dom.window.close();
  return html;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  for (const name of ['index', 'check-fixes-demo']) {
    const file = new URL(`../docs/${name}.html`, import.meta.url);
    const current = await readFile(file, 'utf8');
    const localized = addJapanese(current);
    if (process.argv.includes('--check')) {
      if (current !== localized) throw Error(`Regenerate docs/${name}.html`);
    } else await writeFile(file, localized);
  }
}
