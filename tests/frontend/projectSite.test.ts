import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { JSDOM } from "jsdom";

type CatalogEngine = {
  id: string;
  repository_url: string;
  status: string;
};

type StarSnapshot = {
  schemaVersion: number;
  checkedAt: string;
  source: string;
  tools: Array<{ id: string; repository: string; stars: number }>;
  ruleSources: Array<{ repository: string; stars: number }>;
};

const workspaceFile = (path: string) => readFile(new URL(`../../${path}`, import.meta.url), "utf8");

const occurrences = (source: string, value: string) => source.split(value).length - 1;

test("the bilingual project site lists every integrated upstream engine exactly once", async () => {
  const [catalogSource, site, readme, readmeZh] = await Promise.all([
    workspaceFile("engines/catalog.json"),
    workspaceFile("docs/index.html"),
    workspaceFile("README.md"),
    workspaceFile("README.zh-TW.md"),
  ]);
  const catalog = JSON.parse(catalogSource) as CatalogEngine[];
  const integrated = catalog.filter((engine) => engine.status === "integrated");

  assert.equal(integrated.length, 25);
  assert.equal(occurrences(site, 'class="tool-card" data-tool='), integrated.length);
  for (const engine of integrated) {
    assert.equal(occurrences(site, `data-tool="${engine.id}"`), 1, `${engine.id} site card`);
    assert.equal(occurrences(site, `href="${engine.repository_url}"`), 1, `${engine.id} site link`);
    assert.ok(readme.includes(engine.repository_url), `${engine.id} English README link`);
    assert.ok(readmeZh.includes(engine.repository_url), `${engine.id} Chinese README link`);
  }

  assert.match(site, /Find risks\.[\s\S]*Act on them\./u);
  assert.match(site, /找出問題，[\s\S]*知道怎麼做。/u);
  assert.match(site, /completed sibling results survive/iu);
  assert.match(site, /其他已完成結果仍會保留/u);
  assert.match(readme, /docs\/engine-catalog\.md/u);
  assert.match(readmeZh, /docs\/engine-catalog\.md/u);
});

test("the displayed GitHub stars match the dated API snapshot", async () => {
  const [snapshotSource, site] = await Promise.all([
    workspaceFile("docs/tool-stars.json"),
    workspaceFile("docs/index.html"),
  ]);
  const snapshot = JSON.parse(snapshotSource) as StarSnapshot;
  // Frozen rule revisions still attribute their stars to the same repository.
  const repositoryLinks = Array.from(
    site.matchAll(/href="(https:\/\/github\.com\/[^"]+)"/gu),
    ([, href]) => href.replace(/\/tree\/[a-f0-9]{40}$/u, ""),
  );

  assert.equal(snapshot.schemaVersion, 1);
  assert.equal(snapshot.source, "GitHub REST API");
  assert.ok(Number.isFinite(Date.parse(snapshot.checkedAt)));
  assert.equal(snapshot.tools.length, 25);
  assert.equal(new Set(snapshot.tools.map((entry) => entry.id)).size, 25);

  for (const entry of [...snapshot.tools, ...snapshot.ruleSources]) {
    assert.ok(Number.isSafeInteger(entry.stars) && entry.stars >= 0, entry.repository);
    assert.equal(occurrences(site, `<data value="${entry.stars}">`), 1, `${entry.repository} star count`);
    assert.equal(
      repositoryLinks.filter((href) => href === `https://github.com/${entry.repository}`).length,
      1,
      `${entry.repository} link`,
    );
  }
});

test("the project site stays local, responsive, bilingual, and GitHub Pages ready", async () => {
  const [site, styles, script, noJekyll, packageSource] = await Promise.all([
    workspaceFile("docs/index.html"),
    workspaceFile("docs/project-site.css"),
    workspaceFile("docs/project-site.js"),
    workspaceFile("docs/.nojekyll"),
    workspaceFile("package.json"),
  ]);

  assert.equal(noJekyll, "\n");
  assert.match(site, /<html lang="en" data-lang="en">/u);
  assert.ok(occurrences(site, 'class="lang-en"') >= 50);
  assert.ok(occurrences(site, 'class="lang-zh"') >= 50);
  assert.match(site, /<link rel="stylesheet" href="project-site\.css">/u);
  assert.match(site, /<script src="project-site\.js" defer><\/script>/u);
  assert.doesNotMatch(site, /<(?:script|img)[^>]+src="https?:\/\//iu);
  assert.doesNotMatch(site, /<link[^>]+rel="stylesheet"[^>]+href="https?:\/\//iu);
  assert.match(styles, /@media \(max-width: 720px\)/u);
  assert.match(styles, /@media \(prefers-reduced-motion: reduce\)/u);
  assert.match(script, /document\.documentElement\.lang/u);
  assert.match(script, /aria-pressed/u);
  assert.doesNotMatch(script, /innerHTML|document\.write/u);

  const packageMetadata = JSON.parse(packageSource) as { homepage?: string };
  assert.equal(packageMetadata.homepage, "https://teddashh.github.io/ai-security-scanner/");
});

test("tool cards and all three READMEs use each scanner introduction", async () => {
  const [catalogSource, contentSource, site, readme, readmeZh, readmeJa, japaneseSource] = await Promise.all([
    workspaceFile("engines/catalog.json"),
    workspaceFile("docs/scanner-guide.content.json"),
    workspaceFile("docs/index.html"),
    workspaceFile("README.md"),
    workspaceFile("README.zh-TW.md"),
    workspaceFile("README.ja.md"),
    workspaceFile("docs/locales/ja.json"),
  ]);
  const catalog = JSON.parse(catalogSource) as CatalogEngine[];
  const content = JSON.parse(contentSource) as {
    scanners: Array<{ id: string; introduction: { en: string; "zh-TW": string } }>;
  };
  const integrated = catalog.filter((engine) => engine.status === "integrated");
  const dom = new JSDOM(site);
  const japanese = JSON.parse(japaneseSource) as Record<string, string>;

  assert.equal(integrated.length, 25);
  for (const engine of integrated) {
    const entry = content.scanners.find((scanner) => scanner.id === engine.id);
    assert.ok(entry?.introduction.en && entry.introduction["zh-TW"], `${engine.id} introduction`);
    const card = dom.window.document.querySelector(`[data-tool="${engine.id}"] > p:not(.tool-kind)`);
    assert.ok(card, `${engine.id} card paragraph`);
    assert.equal(card.querySelector('.lang-en')?.textContent, entry.introduction.en, `${engine.id} English card`);
    assert.equal(card.querySelector('.lang-zh')?.textContent, entry.introduction["zh-TW"], `${engine.id} Chinese card`);
    assert.ok(japanese[entry.introduction.en], `${engine.id} Japanese introduction`);
    assert.equal(card.querySelector('.lang-ja')?.textContent, japanese[entry.introduction.en], `${engine.id} Japanese card`);
    assert.ok(readme.includes(entry.introduction.en), `${engine.id} English README`);
    assert.ok(readmeZh.includes(entry.introduction["zh-TW"]), `${engine.id} Chinese README`);
    assert.ok(readmeJa.includes(japanese[entry.introduction.en]!), `${engine.id} Japanese README`);
    assert.ok(readmeJa.includes(engine.repository_url), `${engine.id} Japanese upstream link`);
  }
  dom.window.close();
});
