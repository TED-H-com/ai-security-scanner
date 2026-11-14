#!/usr/bin/env node
// Offline integrity check for the committed RF-01 input, output and visual corpus.
// The Rust integration test separately checks the current production renderer.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { gunzipSync } from 'node:zlib';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const directory = path.join(root, 'tests/fixtures/report-fidelity');
const hash = (bytes) => createHash('sha256').update(bytes).digest('hex');
const receipt = JSON.parse(await readFile(path.join(directory, 'receipt.json'), 'utf8'));
assert.equal(receipt.schemaVersion, 1);
assert.equal(receipt.liveTargetContact, false);
assert.equal(receipt.baselineCoreRevision, 'cc2ef089584594b2908177550da65bb18ae26361');
assert.equal(receipt.scenarios.length, 2);
if (Object.hasOwn(receipt, 'replaces')) {
  const replacement = receipt.replaces;
  assert(replacement && typeof replacement === 'object' && !Array.isArray(replacement));
  const revision = /^[0-9a-f]{40}$/;
  assert.match(receipt.baselineCoreRevision, revision);
  assert.match(replacement.baselineCoreRevision, revision);
  assert.notEqual(receipt.baselineCoreRevision, replacement.baselineCoreRevision);
  assert(typeof replacement.productVersion === 'string' && replacement.productVersion.trim());
  assert.match(replacement.receiptSha256, /^[0-9a-fA-F]{64}$/);
  assert(typeof replacement.reason === 'string' && replacement.reason.trim());
  assert.equal(replacement.inputs, 'carried over byte-identical');
  assert(Array.isArray(replacement.changedDocuments));
  const documents = new Set(receipt.scenarios.flatMap((scenario) =>
    Object.keys(scenario.documents).map((document) => `${scenario.name}/${document}`)));
  for (const document of replacement.changedDocuments) {
    assert(typeof document === 'string' && /^[^/]+\/[^/]+$/.test(document) && documents.has(document));
  }
  assert.deepEqual(replacement.changedDocuments, [...new Set(replacement.changedDocuments)].sort());
}
let documentCount = 0;
for (const scenario of receipt.scenarios) {
  const input = gunzipSync(await readFile(path.join(directory, scenario.name, 'case.json.gz')));
  assert.equal(hash(input), scenario.caseSha256, `${scenario.name}/case`);
  const frozen = JSON.parse(input);
  assert.equal(frozen.id, scenario.caseId);
  assert.equal(frozen.scan_runs.at(-1).id, scenario.runId);
  assert.equal(scenario.sources.length, 25);
  for (const [file, expected] of Object.entries(scenario.documents)) {
    if (file === 'report.case.tar.gz') {
      assert.equal(expected.comparison, 'verified-signature-and-deterministic-payload-entries');
      assert.equal(Object.keys(expected.entries).length, 18);
      continue;
    }
    const bytes = gunzipSync(await readFile(path.join(directory, scenario.name, `${file}.gz`)));
    assert.equal(hash(bytes), expected.sha256, `${scenario.name}/${file}`);
    assert.equal(bytes.length, expected.byteLength, `${scenario.name}/${file} length`);
    documentCount += 1;
  }
  const semantic = JSON.parse(gunzipSync(await readFile(path.join(directory, scenario.name, 'en-standard.json.gz')))).report;
  assert.equal(semantic.state.lifecycle, 'final');
  // Every detector returning does not erase a real WARN/partial coverage gap.
  assert.equal(semantic.state.summary, 'partial');
  assert(semantic.findings.length > 0 && semantic.inventory.total > 0);
  if (scenario.name === 'mixed-terminal') {
    const statuses = new Set(semantic.actual.checks.map((check) => check.status));
    for (const status of ['failed', 'cancelled', 'timed_out', 'tested_complete', 'tested_partial']) {
      assert(statuses.has(status), `Missing mixed-terminal outcome: ${status}`);
    }
  }
}
const visual = JSON.parse(await readFile(path.join(directory, 'visual/receipt.json'), 'utf8'));
assert.equal(visual.captures.length, 20);
for (const capture of visual.captures) {
  const bytes = await readFile(path.join(directory, 'visual', capture.file));
  assert.equal(hash(bytes), capture.sha256, capture.file);
  assert.equal(bytes.length, capture.byteLength, `${capture.file} length`);
  const [scenario, file] = capture.source.split('/');
  const source = receipt.scenarios.find((candidate) => candidate.name === scenario);
  assert.equal(capture.sourceSha256, source.documents[file].sha256, `${capture.file} HTML source`);
  assert.equal(capture.horizontalOverflow, false, capture.file);
  assert.equal(capture.fontsReady, true, capture.file);
}
console.log(`Verified 2 frozen cases, ${documentCount} document snapshots, 36 signed-bundle payload hashes, and ${visual.captures.length} screenshots.`);
if (Object.hasOwn(receipt, 'replaces')) {
  console.log(`Replaced revision ${receipt.replaces.baselineCoreRevision}; ${receipt.replaces.changedDocuments.length} changed documents.`);
}
