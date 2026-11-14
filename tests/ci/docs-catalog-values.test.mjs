import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const load = (file) => readFileSync(new URL(`../../${file}`, import.meta.url), "utf8");

function statement(source, file, phrase) {
  const line = source.split(/\r?\n/u).find((line) => line.includes(phrase));
  assert.ok(line, `${file}: missing statement containing "${phrase}"`);
  return line.slice(line.indexOf(phrase) + phrase.length);
}

function extractValue(source, file, phrase, pattern, label) {
  const match = statement(source, file, phrase).match(pattern);
  assert.ok(match, `${file}: missing ${label} in statement containing "${phrase}"`);
  return match[1];
}

function extractPin(source, file, phrase, full = false) {
  return {
    tag: extractValue(source, file, phrase, full
      ? /`[^`\s]*ai-security-scanner-engine-grype:([^`\s]+)`/u
      : /`([^`\s]+)`/u, "Grype tag"),
    digest: extractValue(source, file, phrase,
      /`(sha256:[0-9a-f]+)(?:…|\.\.\.)?`/u, "Grype digest"),
  };
}

function checkValue(file, label, found, expected) {
  assert.equal(found, expected,
    `${file}: ${label}: found "${found}", expected "${expected}"`);
}

function checkPin(source, file, phrase, expected, full = false) {
  const found = extractPin(source, file, phrase, full);
  checkValue(file, "Grype tag", found.tag, expected.tag);
  checkValue(file, "Grype digest", found.digest, expected.digest);
}

function checkCount(source, file, phrase, pattern, expected) {
  const found = extractValue(source, file, phrase, pattern, "Nuclei template count");
  checkValue(file, "Nuclei template count", found, expected);
}

const catalog = JSON.parse(load("engines/catalog.json"));
const grype = catalog.find((engine) =>
  engine.image?.repository.endsWith("/ai-security-scanner-engine-grype"));
assert.ok(grype, "engines/catalog.json: missing ai-security-scanner-engine-grype image");
assert.match(grype.image.digest, /^sha256:[0-9a-f]{64}$/u);
const shortPin = { tag: grype.image.tag, digest: grype.image.digest.slice(0, "sha256:".length + 8) };
const plan = JSON.parse(load("engines/images/nuclei/plan.json"));
const derivedTemplateCount = plan.managed_runtime?.template_policy?.derived_template_count;
assert.ok(Number.isInteger(derivedTemplateCount),
  "engines/images/nuclei/plan.json: missing integer derived_template_count");
const templateCount = derivedTemplateCount.toLocaleString("en-US");

const shortPinDocuments = [
  ["README.md", "The current catalog pins the Grype image to"],
  ["README.zh-TW.md", "目前目錄將 Grype 映像固定為"],
  ["README.ja.md", "現在のカタログでは、Grype イメージを"],
  ["docs/getting-started.md", "The current Grype image pin is"],
  ["docs/getting-started.zh-TW.md", "目前 Grype 映像固定為"],
];
for (const [file, phrase] of shortPinDocuments) {
  test(`${file}: current Grype short pin matches the catalog`, () => {
    checkPin(load(file), file, phrase, shortPin);
  });
}

test("docs/engine-catalog.md: current Grype full pin matches the catalog", () => {
  checkPin(load("docs/engine-catalog.md"), "docs/engine-catalog.md",
    "The current catalog pins", grype.image, true);
});

for (const [file, phrase, pattern] of [
  ["docs/engine-catalog.md", "Nuclei derives", /^ ([\d,]+) bounded read-only candidates/u],
  ["docs/engine-catalog.md", "| Active HTTP testing | [Nuclei]", /with a ([\d,]+)-template read-only pool/u],
  ["engines/catalog.json", "The pinned automatic profile derives", /^ ([\d,]+) eligible templates/u],
]) {
  test(`${file}: ${phrase} count matches the Nuclei plan`, () => {
    checkCount(load(file), file, phrase, pattern, templateCount);
  });
}

// Synthetic pins/counts exercise failures independently of the current catalog.
const samplePin = { tag: "2.0.0-1", digest: "sha256:1234abcd" };
const samplePhrase = "The current catalog pins the Grype image to";

test("a stale tag reports the file, found tag and expected tag", () => {
  assert.throws(() => checkPin(
    "The current catalog pins the Grype image to **`1.0.0-1`**, digest `sha256:1234abcd…`.",
    "README.md", samplePhrase, samplePin,
  ), /README\.md: Grype tag: found "1\.0\.0-1", expected "2\.0\.0-1"/u);
});

test("a stale digest prefix reports the file, found prefix and expected prefix", () => {
  assert.throws(() => checkPin(
    "The current catalog pins the Grype image to **`2.0.0-1`**, digest `sha256:deadbeef…`.",
    "README.md", samplePhrase, samplePin,
  ), /README\.md: Grype digest: found "sha256:deadbeef", expected "sha256:1234abcd"/u);
});

test("a stale full digest reports both digests", () => {
  const expectedDigest = `sha256:${"a".repeat(64)}`;
  const staleDigest = `sha256:${"b".repeat(64)}`;
  assert.throws(() => checkPin(
    `The current catalog pins \`example/ai-security-scanner-engine-grype:2.0.0-1\` to \`${staleDigest}\`.`,
    "docs/engine-catalog.md", "The current catalog pins",
    { tag: samplePin.tag, digest: expectedDigest }, true,
  ), (error) => error.message.includes(
    `docs/engine-catalog.md: Grype digest: found "${staleDigest}", expected "${expectedDigest}"`,
  ));
});

test("a stale count reports the file, found count and expected count", () => {
  assert.throws(() => checkCount(
    "Nuclei derives 1,234 bounded read-only candidates.",
    "docs/engine-catalog.md", "Nuclei derives", /^ ([\d,]+) bounded read-only candidates/u, "2,345",
  ), /docs\/engine-catalog\.md: Nuclei template count: found "1,234", expected "2,345"/u);
});

test("a missing statement reports the file and the phrase sought", () => {
  assert.throws(() => extractPin("No current pin here.", "README.md", samplePhrase),
    /README\.md: missing statement containing "The current catalog pins the Grype image to"/u);
});

test("a missing value reports the file, field and statement sought", () => {
  assert.throws(() => extractPin(
    "The current catalog pins the Grype image to `2.0.0-1`.", "README.md", samplePhrase,
  ), /README\.md: missing Grype digest in statement containing "The current catalog pins the Grype image to"/u);
});

test("historical Grype pins are never selected as the current pin", () => {
  const history = "A controlled repository scan on **2026-09-20** using the earlier image **`0.117.0-4`** recorded **81 Grype findings**.";
  const current = "The current catalog pins the Grype image to **`2.0.0-1`**, digest `sha256:1234abcd…`.";
  for (const source of [`${history}\n${current}`, `${current}\n${history}`]) {
    assert.deepEqual(extractPin(source, "README.md", samplePhrase), samplePin);
  }
  assert.throws(() => extractPin(history, "README.md", samplePhrase),
    /README\.md: missing statement containing "The current catalog pins the Grype image to"/u);
});
