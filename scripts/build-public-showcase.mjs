// Frozen public examples: keep the production export intact beneath the sample labels.
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { addJapanese } from './localize-public-site.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
const repo = 'https://github.com/teddashh/ai-security-scanner';
const site = 'https://teddashh.github.io/ai-security-scanner/';
const languages = ['en', 'zh-TW'];
const fields = {
  introduction: ['About this tool', '工具介紹'],
  upstream: ['What the original tool does', '原本的工具能做什麼'],
  included: ['What this app checks', '這個程式會檢查什麼'],
  notIncluded: ['What it does not check', '哪些不在檢查範圍內'],
  why: ['Why we selected it', '為什麼選用'],
  when: ['When to use it', '什麼情況下使用'],
  result: ['What you see in the report', '報告會呈現什麼'],
  strengths: ['Strengths', '優勢'], weaknesses: ['Weaknesses', '弱點'],
  opportunities: ['Opportunities', '機會'], threats: ['Threats', '威脅'],
};
const categories = {
  repository: ['Code, packages & deployment settings', '程式碼、套件與部署設定'],
  network: ['Websites & networks', '網站與網路'], cloud: ['Cloud', '雲端'],
  m365: ['Microsoft 365', 'Microsoft 365'], kubernetes: ['Kubernetes', 'Kubernetes'], ai: ['AI & MCP', 'AI 與 MCP'],
};
const pick = (pair, lang) => pair[lang === 'en' ? 0 : 1];
const escape = (value) => String(value).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const bilingual = (en, zh) => `<span class="lang-en">${escape(en)}</span><span class="lang-zh" lang="zh-Hant">${escape(zh)}</span>`;
const bi = pair => bilingual(...pair);
const text = value => bilingual(value.en, value['zh-TW']);
export const sha256 = value => createHash('sha256').update(value).digest('hex');
const readJson = async path => JSON.parse(await readFile(resolve(root, path), 'utf8'));
const link = (url, label) => `<a href="${escape(url)}">${escape(label)}</a>`;
const localizedLink = (path, label, anchor = '') => `<a href="${path}${anchor}" data-href-en="${path}${anchor}" data-href-zh="${path}?lang=zh-TW${anchor}">${bi(label)}</a>`;
const marked = (id, html) => `<!-- public-sample:${id}:start -->${html}<!-- public-sample:${id}:end -->`;
export function stripSampleAdditions(html) {
  return html.replace(/<!-- public-sample:(style|banner|sources):start -->[\s\S]*?<!-- public-sample:\1:end -->/g, '');
}
function shell(page, title, description, content) {
  return addJapanese(`<!doctype html>
<html lang="en" data-lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="theme-color" content="#102c37"><meta name="description" content="${escape(description[0])}" data-en="${escape(description[0])}" data-zh="${escape(description[1])}">
<meta property="og:type" content="website"><meta property="og:locale" content="en_US"><meta property="og:title" content="${escape(title[0])}"><meta property="og:description" content="${escape(description[0])}">
<link rel="canonical" href="${site}${page}.html"><link rel="alternate" hreflang="en" href="${site}${page}.html"><link rel="alternate" hreflang="zh-Hant" href="${site}${page}.html?lang=zh-TW">
<link rel="icon" href="project-mark.svg" type="image/svg+xml"><link rel="stylesheet" href="project-site.css"><link rel="stylesheet" href="showcase.css">
<title data-en="${escape(title[0])}" data-zh="${escape(title[1])}">${escape(title[0])}</title>
<script>(()=>{const q=new URLSearchParams(location.search).get('lang');if(q==='zh-TW'||(!q&&navigator.languages?.some(l=>l.toLowerCase().startsWith('zh')))){document.documentElement.dataset.lang='zh-TW';document.documentElement.lang='zh-Hant';}})();</script>
</head><body class="showcase-page">
<a class="skip-link" href="#main">${bi(['Skip to content','跳到主要內容'])}</a>
<header class="site-header"><div class="header-inner"><a class="brand" href="index.html" data-href-en="index.html" data-href-zh="index.html?lang=zh-TW"><img src="project-mark.svg" alt=""><span>ai-security-scanner</span></a>
<nav class="nav" aria-label="Primary navigation">${localizedLink('sample-reports.html',['Sample reports','範例報告'])}${localizedLink('scanner-guide.html',['Scanner guide','掃描器指南'])}${localizedLink('check-fixes-demo.html',['Real scan example','真實掃描案例'])}<a href="${repo}">GitHub ↗</a></nav>
<div class="language-switch" role="group" aria-label="Language"><button type="button" data-language="en" aria-pressed="true">EN</button><button type="button" data-language="zh-TW" aria-pressed="false">繁中</button></div></div></header>
<main id="main">${content}</main>
<footer class="site-footer"><div class="footer-inner"><p>ai-security-scanner · v0.4.0 · 2026-10-04</p><p>${localizedLink('index.html',['Back to the project','回到專案首頁'])} · <a href="${repo}/tree/main/docs/samples/v0.4.0">${bi(['Examples on GitHub','GitHub 範例檔案'])}</a></p></div></footer>
<script src="project-site.js" defer></script>${page === 'scanner-guide' ? '<script src="scanner-guide.js" defer></script>' : ''}
</body></html>\n`);
}
function format(source) {
  if (['scubagear', 'maester'].includes(source.id)) return ['JSON · managed envelope of native verdicts', 'JSON · 包含原生判定的受管外層格式'];
  if (source.id === 'mcp-armor') return ['JSON · configuration-only output patch', 'JSON · 僅限設定模式的輸出修改'];
  if (source.id === 'agentic-radar') return ['JSON · native parser graph via output patch', 'JSON · 透過輸出修改取得原生解析圖形'];
  if (source.id === 'cloudquery') return ['NDJSON · per-table output', 'NDJSON · 各資料表輸出'];
  return [source.outputFormats.join(' / ').toUpperCase(), source.outputFormats.join(' / ').toUpperCase()];
}
function versionRows(source, lang) {
  const t = pair => pick(pair, lang);
  const none = t(['None / runtime input', '無／執行時輸入']);
  return [
    [t(['Engine version (catalog)', '引擎版本（目錄紀錄）']), source.engineVersion],
    [t(['Image tag', '映像標籤']), source.image.tag],
    [t(['Pinned source commit date (UTC)', '固定來源提交日期（UTC）']), source.upstreamRevisionDate],
    [t(['Source revision', '原始碼版本']), source.sourceRevision],
    [t(['Rules / checks', '規則／檢查']), source.rules.identifier],
    [t(['Rules revision', '規則版本']), source.rules.revision ?? (source.rules.mode === 'embedded' ? t(['Bundled with engine source ', '隨引擎來源提供 '])+source.sourceRevision : t(['Not applicable', '不適用']))],
    [t(['Data input', '資料輸入']), source.data.identifier],
    [t(['Data revision', '資料版本']), source.data.revision ?? none],
    [t(['Catalog knowledge baseline date', '目錄知識基準日期']), source.catalogKnowledgeDate],
    [t(['Adapter version', 'Adapter 版本']), source.adapterVersion],
    [t(['Output format', '輸出格式']), t(format(source))],
  ];
}
function guideCard(entry, source, sample) {
  const normal = Object.keys(fields).slice(0,7).map(key => `<section><h3>${bi(fields[key])}</h3><p>${text(entry[key])}</p></section>`).join('\n');
  const swot = Object.keys(fields).slice(7).map(key => `<section><h4>${bi(fields[key])}</h4><p>${text(entry[key])}</p></section>`).join('\n');
  const facts = languages.map(lang => `<dl class="version-facts ${lang === 'en' ? 'lang-en' : 'lang-zh'}"${lang === 'en' ? '' : ' lang="zh-Hant"'}>${versionRows(source, lang).map(([k,v]) => `<div><dt>${escape(k)}</dt><dd>${escape(v)}</dd></div>`).join('')}</dl>`).join('');
  return `<details class="scanner-entry" id="${entry.id}" data-category="${entry.category}">
<summary><span class="scanner-entry-heading"><strong>${escape(source.displayName)}</strong><span class="scanner-purpose">${text(entry.purpose)}</span></span><span class="scanner-kind">${bi(sample.findings ? ['Security checks','安全檢查'] : ['Inventory','盤點'])}</span></summary>
<div class="scanner-detail"><p class="scanner-source-links">${link(source.repository, 'Upstream ↗')} · ${link(source.readmeUrl, 'README @ '+source.sourceRevision.slice(0,7))} · <a href="${repo}/blob/${'335d0666bdc63eb86e6c8c4cddeae110db893397'}/docs/engines/${entry.id}.md">${bi(['Integration & update notes','整合與更新筆記'])}</a> · <a href="#${entry.id}">${bi(['Link to this scanner','此掃描器連結'])}</a></p>
${normal}<h3>${bi(['SWOT · project team assessment','SWOT · 專案團隊評估'])}</h3><div class="swot-grid">${swot}</div>
<h3>${bi(['Version record · included on 2026-10-04','版本紀錄 · 2026-10-04 提供'])}</h3>${facts}<p class="version-note">${bi(['The source date is a commit date, not an upstream release date. The catalog baseline date is not the date of every embedded database or rule. Exact revisions and image digest identify the frozen inputs.','來源日期是提交日期，不是上游發布日。目錄基準日期不等於每份內附資料庫或規則的日期；確切版本與映像 digest 用來辨識固定輸入。'])}</p>
<details class="image-detail"><summary>${bi(['Image identity','映像識別'])}</summary><p><code>${escape(source.image.repository+':'+source.image.tag+'@'+source.image.digest)}</code></p></details>
<p class="sample-count">${bi([`Sample: ${sample.findings} original findings · ${sample.inventoryObservations} inventory observations.`,`範例：${sample.findings} 筆原始發現 · ${sample.inventoryObservations} 筆盤點觀察。`])} ${localizedLink('sample-reports.html',['Open the reports →','開啟報告 →'])}</p></div></details>`;
}
function downloads(prefix='samples/v0.4.0/') {
  return `<div class="sample-downloads">${['redacted','full'].map((mode,i)=>`<article class="sample-card"><p class="eyebrow">${i ? '02 / FULL' : '01 / REDACTED'}</p><h3>${bi(i ? ['Fully disclosed','完整揭露版'] : ['Redacted','遮蔽版'])}</h3><p>${bi(i ? ['Read the example with system names, addresses and account details included. All names are fictional. Passwords and keys stay hidden.','保留範例裡的系統名稱、網址與帳號資訊，看看內部報告的樣子。這些資料都是虛構的，密碼與金鑰仍會隱藏。'] : ['Read the findings and next steps with system names and other identifying details hidden. You can still see which tool found each problem.','隱藏系統名稱等識別資訊，保留問題、處理順序與下一步，也看得到是哪個工具發現的。'])}</p><div class="button-row">${languages.map(lang=>`<span class="${lang==='en'?'lang-en':'lang-zh'}"${lang==='en'?'':' lang="zh-Hant"'}><a class="button button-primary" href="${prefix}sample-report-${mode}-${lang}.html">${pick(['Read report','閱讀報告'],lang)} →</a> <a class="button button-secondary" href="${prefix}sample-report-${mode}-${lang}.html" download>${pick(['Download HTML','下載 HTML'],lang)}</a></span>`).join('')}</div></article>`).join('')}</div>`;
}
function appendix(content, sources, generation, lang) {
  const t = pair => pick(pair,lang);
  return `<section class="sample-sources" id="sample-sources"><h2>${t(['Sample sources · all 25 adapters','範例來源 · 全部 25 個 adapter'])}</h2><p>${t(['Representative upstream-format inputs were processed by the production adapters, saved as a terminal case and exported through the standard report service. Execution was simulated; no customer system or live model was contacted. The source table and sample label were added for this public edition; the standard report body is unchanged.','具代表性的上游格式輸入，經由正式 adapter 處理、儲存成結束狀態案件，再透過標準報告服務匯出。執行過程為模擬，未連接客戶系統或即時模型。此公開版加上來源表及範例標記；標準報告本文未修改。'])}</p><p>${t(['62 original findings and 42 inventory observations. Related findings can share a problem card; inventory is not counted as a vulnerability. The scenario intentionally includes incomplete coverage.','共 62 筆原始發現與 42 筆盤點觀察。相關發現可共用一張問題卡；盤點不計為漏洞。此情境刻意包含未完整涵蓋的檢查。'])}</p>
${sources.scanners.map(s=>{const entry=content.scanners.find(e=>e.id===s.id);const counts=generation.sources.find(e=>e.engineId===s.id);return `<article id="sample-source-${s.id}"><h3>${escape(s.displayName)}</h3><p>${escape(entry.purpose[lang])}</p><p><strong>${t(['Results:','結果：'])}</strong> ${counts.findings} ${t(['findings','筆發現'])} · ${counts.inventoryObservations} ${t(['inventory observations','筆盤點觀察'])} · ${escape(t(format(s)))}</p><p><strong>${t(['Included version:','提供版本：'])}</strong> ${escape(s.engineVersion)} · ${t(['Image','映像'])} ${escape(s.image.tag)} · ${t(['Source date','來源日期'])} ${s.upstreamRevisionDate.slice(0,10)} · adapter ${s.adapterVersion}</p><p>${link(`${site}scanner-guide.html${lang==='en'?'':'?lang=zh-TW'}#${s.id}`,t(['Purpose, enabled features & SWOT','用途、啟用功能與 SWOT']))} · ${link(`${repo}/blob/${content.releaseSourceCommit}/${s.fixturePath}`,t(['Input format example','輸入格式範例']))}</p></article>`;}).join('')}
<p>${link(`${repo}/tree/main/docs/samples/v0.4.0`,t(['Generation method, source manifest and file hashes','產製方式、來源清單與檔案雜湊']))}</p></section>`;
}
function decorate(original, entry, content, sources, generation) {
  const lang=entry.locale;const t=pair=>pick(pair,lang);
  const label=t(entry.redaction==='standard'?['REDACTED SAMPLE','遮蔽版範例']:['FULLY DISCLOSED SAMPLE','完整揭露版範例']);
  const style=marked('style','<style>.public-sample-banner{border-left:5px solid var(--accent);background:var(--tint);padding:1rem 1.25rem;margin-bottom:1.75rem}.public-sample-banner p{margin:.35rem 0}.public-sample-banner a,.sample-sources a{color:var(--accent)}.sample-sources{margin-top:3rem}.sample-sources p,.sample-sources code{overflow-wrap:anywhere}.sample-sources article{break-inside:avoid}@media print{.sample-sources{break-before:page}}</style>');
  const banner=marked('banner',`<aside class="public-sample-banner" aria-label="${label}"><strong>${label} · v0.4.0 · 2026-10-04</strong><p>${t(['This example uses simulated data from all 25 tools to show how the app presents results.','這份範例用 25 個工具的模擬資料，展示程式如何呈現檢查結果。'])}</p><p>${t(['The names and account details are fictional. Both versions hide passwords and keys.','名稱與帳號資料都是虛構的；兩個版本都會隱藏密碼與金鑰。'])} <a href="#sample-sources">${t(['Scanner sources and purposes ↓','掃描器來源與用途 ↓'])}</a></p></aside>`);
  return original.replace('</head>',style+'</head>').replace('<body>','<body>'+banner).replace('<footer>',marked('sources',appendix(content,sources,generation,lang))+'<footer>');
}
export async function buildOutputs(sampleDirectory) {
  const [content,sources] = await Promise.all([readJson('docs/scanner-guide.content.json'),readJson('docs/scanner-guide.sources.json')]);
  if(content.productVersion!==sources.productVersion||content.releaseSourceCommit!==sources.releaseSourceCommit) throw Error('Mismatched frozen product snapshots');
  const sampleRoot=sampleDirectory?resolve(sampleDirectory):resolve(root,'docs/samples/v'+content.productVersion);
  const generation=JSON.parse(await readFile(resolve(sampleRoot,'sample-generation.json'),'utf8'));
  const ids=sources.scanners.map(e=>e.id).sort();
  for(const collection of [content.scanners.map(e=>e.id),generation.sources.map(e=>e.engineId)]){
    if(new Set(collection).size!==25||JSON.stringify(collection.sort())!==JSON.stringify(ids)) throw Error('All 25 scanners must appear exactly once');
  }
  if(generation.productVersion!==content.productVersion||generation.liveTargetContact!==false)throw Error('Wrong sample version or live execution');
  for(const entry of content.scanners){
    if(!categories[entry.category])throw Error('Unknown category '+entry.id);
    for(const key of ['purpose',...Object.keys(fields)])for(const lang of languages)if(!entry[key]?.[lang]?.trim())throw Error(`Missing ${entry.id}/${key}/${lang}`);
    const counts=generation.sources.find(s=>s.engineId===entry.id);
    if(counts.findings+counts.inventoryObservations===0)throw Error('Missing result '+entry.id);
  }
  const outputs=new Map();
  const target='docs/samples/v'+content.productVersion;
  const manifest={...generation,reviewedAt:content.reviewedAt,releaseSourceCommit:content.releaseSourceCommit,standardReportBodyUnchanged:true,additions:['sample label','scanner source and purpose appendix'],sources:generation.sources.map(s=>({...s,fixturePath:sources.scanners.find(e=>e.id===s.engineId).fixturePath})),exports:[]};
  const expectedFiles=languages.flatMap(locale=>['redacted','full'].map(mode=>`sample-report-${mode}-${locale}.html`)).sort();
  if(JSON.stringify(generation.exports.map(e=>e.file).sort())!==JSON.stringify(expectedFiles))throw Error('Expected exactly two disclosure modes in both languages');
  for(const entry of generation.exports){
    const original=stripSampleAdditions(await readFile(resolve(sampleRoot,entry.file),'utf8'));
    if(sha256(original)!==entry.standardExportSha256)throw Error('Standard report bytes changed: '+entry.file);
    const html=decorate(original,entry,content,sources,generation);
    outputs.set(`${target}/${entry.file}`,html);
    manifest.exports.push({...entry,sha256:sha256(html),bytes:Buffer.byteLength(html)});
  }
  outputs.set(`${target}/sample-generation.json`,JSON.stringify(generation,null,2)+'\n');
  outputs.set(`${target}/manifest.json`,JSON.stringify(manifest,null,2)+'\n');
  outputs.set(`${target}/SHA256SUMS.txt`,manifest.exports.map(e=>`${e.sha256}  ${e.file}`).join('\n')+'\n');
  const cards=Object.keys(categories).map(category=>`<section class="scanner-group" data-group="${category}"><h2>${bi(categories[category])}</h2>${content.scanners.filter(e=>e.category===category).map(entry=>guideCard(entry,sources.scanners.find(s=>s.id===entry.id),generation.sources.find(s=>s.engineId===entry.id))).join('\n')}</section>`).join('\n');
  const intro= `<section class="section showcase-intro"><p class="eyebrow">v0.4.0 / 2026-10-04</p><h1>${bi(['Know every scanner.','認識每一個掃描器。'])}</h1><p class="showcase-lead">${bi(['What do these 25 tools check? Find out when each is useful, what this app uses it for and what its limits are.','這 25 個工具各自能查什麼？了解它們適合的情境、這個程式使用了哪些功能，以及有哪些限制。'])}</p><p>${bi(['This guide describes the product released on October 4, 2026. Source dates below are pinned commit dates, not claims to use the newest upstream releases. SWOT is our project assessment; opportunities describe possible value, not promised features.','本指南描述 2026 年 10 月 4 日發布的產品。以下來源日期為固定提交日期，不代表採用最新上游版本。SWOT 是本專案的評估；機會描述可能價值，不是已承諾功能。'])}</p><div class="button-row">${localizedLink('sample-reports.html',['See the actual report examples →','查看實際報告範例 →'])}<a href="${repo}/blob/${content.releaseSourceCommit}/engines/catalog.json">${bi(['Frozen v0.4.0 catalog','v0.4.0 固定目錄'])}</a></div></section>`;
  const filters=`<section class="section scanner-browser"><div class="scanner-filter" hidden><label>${bi(['Find a scanner or use case','搜尋掃描器或使用情境'])}<input type="search" id="scanner-search" autocomplete="off"></label><label>${bi(['Category','分類'])}<select id="scanner-category"><option value="all" data-label-en="All categories" data-label-zh="所有分類">All categories</option>${Object.entries(categories).map(([id,p])=>`<option value="${id}" data-label-en="${escape(p[0])}" data-label-zh="${escape(p[1])}">${escape(p[0])}</option>`).join('')}</select></label><p role="status" aria-live="polite" id="scanner-count"></p></div><p id="scanner-empty" hidden>${bi(['No matching scanners. Try another term or category.','沒有符合的掃描器，請更換搜尋字詞或分類。'])}</p>${cards}</section>`;
  outputs.set('docs/scanner-guide.html',shell('scanner-guide',['Scanner guide · ai-security-scanner','掃描器指南 · ai-security-scanner'],['A detailed bilingual guide to all 25 integrated upstream scanners: enabled features, use cases, SWOT, versions and source dates.','全部 25 個上游掃描器的詳細中英文指南：啟用功能、使用情境、SWOT、版本及來源日期。'],intro+filters));
  const rows=sources.scanners.map(s=>{const e=content.scanners.find(e=>e.id===s.id),n=generation.sources.find(n=>n.engineId===s.id);return `<tr><th scope="row">${localizedLink('scanner-guide.html',[s.displayName,s.displayName],'#'+s.id)}</th><td>${text(e.purpose)}</td><td class="numeric">${n.findings}</td><td class="numeric">${n.inventoryObservations}</td><td>${bi(format(s))}</td></tr>`;}).join('\n');
  const samples=`<section class="section showcase-intro"><p class="eyebrow">v0.4.0 / 2026-10-04</p><h1>${bi(['See the report.','直接看報告。'])}</h1><p class="showcase-lead">${bi(['See the same example with identifying details hidden or included.','同一份範例，你可以選擇隱藏或保留系統名稱等資訊。'])}</p><p>${bi(['These reports show 62 findings and 42 inventory observations from all 25 tools, using simulated data. They show how the app presents results, not the security of a real company.','範例使用模擬資料，呈現 25 個工具的 62 筆發現與 42 筆盤點紀錄。你可以看到程式怎麼整理結果；這些內容不代表真實公司的安全狀況。'])}</p>${downloads()}<p class="download-note">${bi(['Open the HTML file in a browser, save it or print it. Use the language switch for English or Traditional Chinese. Both versions show the same findings and unfinished checks; passwords, keys and raw logs are excluded. The examples add a sample label and a source appendix to the app’s report.','HTML 檔可以直接用瀏覽器閱讀、儲存或列印，也能切換中英文。兩個版本都有相同的發現與未完成項目，不顯示密碼、金鑰或原始紀錄。範例另加了標記與來源附錄。'])}</p><div class="button-row"><a href="${repo}/tree/main/docs/samples/v0.4.0">${bi(['Download from GitHub','從 GitHub 下載'])}</a><a href="samples/v0.4.0/manifest.json" download>${bi(['Source manifest (JSON)','來源清單（JSON）'])}</a><a href="samples/v0.4.0/SHA256SUMS.txt" download>SHA-256</a></div></section>
<section class="section sample-coverage"><div class="section-heading"><p class="eyebrow">25 / 25</p><h2>${bi(['Where each result comes from','每筆結果從哪裡來'])}</h2><p>${bi(['Several findings may point to the same problem. This table counts each original finding before the report groups related ones. Inventory is separate from vulnerabilities. Select a tool to read about its uses and limits.','不同工具可能發現同一個問題。這張表計算的是整理前的原始筆數；報告會把相關發現放在一起。盤點與漏洞分開計算。點選工具名稱，可以了解用途與限制。'])}</p></div><div class="table-scroll" role="region" tabindex="0" aria-label="Scanner results"><table><thead><tr>${[['Scanner','掃描器'],['Purpose','用途'],['Findings','發現'],['Inventory','盤點'],['Input format','輸入格式']].map(p=>`<th scope="col">${bi(p)}</th>`).join('')}</tr></thead><tbody>${rows}</tbody></table></div></section>`;
  outputs.set('docs/sample-reports.html',shell('sample-reports',['Sample reports · ai-security-scanner','範例報告 · ai-security-scanner'],['Download real-format sample security reports in redacted and fully disclosed editions, in English and Traditional Chinese. All 25 adapters included.','下載真實格式的安全範例報告：遮蔽版及完整揭露版，提供英文與繁體中文，涵蓋全部 25 個 adapter。'],samples));
  for(const lang of languages){
    const t=p=>pick(p,lang);
    let md=`# ${t(['Scanner guide','掃描器指南'])}\n\n${t(['Product v0.4.0 · released and reviewed 2026-10-04.','產品 v0.4.0 · 發布及檢視日期 2026-10-04。'])}\n\n[${t(['Interactive website','互動網站'])}](${site}scanner-guide.html${lang==='en'?'':'?lang=zh-TW'}) · [${t(['Sample reports','範例報告'])}](samples/v0.4.0/README${lang==='en'?'':'.zh-TW'}.md)\n\n${t(['SWOT is the project team’s assessment. Enabled features describe this product profile, not the whole upstream platform. Source dates are commit dates, not release dates. Opportunities are possible uses, not promised functionality.','SWOT 為專案團隊評估。啟用功能描述本產品設定，不代表完整上游平台。來源日期為提交日期，不是發布日。機會描述可能用途，不是承諾功能。'])}\n\n`;
    for(const e of content.scanners){const s=sources.scanners.find(s=>s.id===e.id);md+=`## ${s.displayName}\n\n${e.purpose[lang]}\n\n[Upstream](${s.repository}) · [README @ ${s.sourceRevision.slice(0,7)}](${s.readmeUrl}) · [${t(['Integration and update notes','整合與更新筆記'])}](${repo}/blob/${content.releaseSourceCommit}/docs/engines/${e.id}.md)\n\n`;for(const [key,label] of Object.entries(fields))md+=`### ${t(label)}\n\n${e[key][lang]}\n\n`;md+=`### ${t(['Version record','版本紀錄'])}\n\n| ${t(['Item','項目'])} | ${t(['Included on 2026-10-04','2026-10-04 提供'])} |\n| --- | --- |\n`+versionRows(s,lang).map(([k,v])=>`| ${k} | ${String(v).replaceAll('|','\\|')} |`).join('\n')+`\n\n${t(['Image identity','映像識別'])}: \`${s.image.repository}:${s.image.tag}@${s.image.digest}\`\n\n`;}
    outputs.set(`docs/scanner-guide${lang==='en'?'':'.zh-TW'}.md`,md.trimEnd()+'\n');
  }
  return outputs;
}
if(process.argv[1] && resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  const args=process.argv.slice(2);const i=args.indexOf('--samples');const outputs=await buildOutputs(i<0?undefined:args[i+1]);
  for(const [path,body] of outputs){
    const absolute=resolve(root,path);
    if(args.includes('--check')){if(await readFile(absolute,'utf8')!==body)throw Error('Regenerate '+path);}
    else{await mkdir(dirname(absolute),{recursive:true});await writeFile(absolute,body);}
  }
  console.log(`${args.includes('--check')?'Verified':'Built'} ${outputs.size} public showcase files.`);
}
