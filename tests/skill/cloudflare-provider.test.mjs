import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile, readdir, lstat } from "node:fs/promises";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import test from "node:test";

const require = createRequire(import.meta.url);
const provider = new URL("../../providers/cloudflare/", import.meta.url);
const upstream = new URL("upstream/skills/security-audit/", provider);
const { validateBytes } = require(fileURLToPath(new URL("validate-document.cjs", provider)));
const findings = require(fileURLToPath(new URL("validate-findings.cjs", upstream)));
const ledger = require(fileURLToPath(new URL("validate-coverage-ledger.cjs", upstream)));
const schema = require(fileURLToPath(new URL("report-schema.json", upstream)));
const hash = (algorithm, bytes) => createHash(algorithm).update(bytes).digest("hex");
const fixture = async (name) => JSON.parse(await readFile(new URL(`../fixtures/cloudflare/${name}.json`, import.meta.url)));
const check = (kind, value) => validateBytes(kind, Buffer.from(JSON.stringify(value)));

test("provider capabilities and file index bind to the vendored dependency", async () => {
  const metadata = JSON.parse(await readFile(new URL("provider.json", provider)));
  const lock = JSON.parse(await readFile(new URL("upstream.lock.json", provider)));
  assert.equal(metadata.upstream.commit, lock.commit);
  assert.equal(metadata.upstream.repository, lock.repository);
  assert.equal(metadata.capabilities.single_document_validation, true);
  assert.equal(metadata.capabilities.reported_bundle_validation, true);
  assert.equal(metadata.capabilities.reported_bundle_retention, true);
  assert.equal(metadata.capabilities.offline_retained_retrieval, true);
  assert.equal(metadata.capabilities.product_source_view_preparation, true);
  assert.equal(metadata.capabilities.offline_source_view_inspection, true);
  assert.equal(metadata.capabilities.source_view_status, true);
  assert.equal(metadata.capabilities.audit_execution, false);
  assert.equal(metadata.capabilities.bundle_admission, false);
  assert.equal(metadata.capabilities.finding_import, false);
  for (const file of [metadata.upstream.license, ...Object.values(metadata.files)]) {
    assert.ok(!file.split("/").some((part) => !part || part === "." || part === ".."));
    assert.ok((await lstat(new URL(file, provider))).isFile());
    if (file.startsWith("upstream/")) assert.ok(lock.files.some((entry) => `upstream/${entry.path}` === file));
  }
});

test("the complete vendored Git blob inventory matches the pinned commit lock", async () => {
  const lock = JSON.parse(await readFile(new URL("upstream.lock.json", provider)));
  assert.equal(lock.commit, "c1c8a8c1471069fb0e188eeaff69b8e8db6564a8");
  assert.equal(lock.repository, "https://github.com/cloudflare/security-audit-skill");
  assert.equal(lock.files.length, 22);
  const actual = [];
  async function walk(relative = "") {
    for (const name of await readdir(new URL(`upstream/${relative}`, provider))) {
      const entry = relative + name;
      const stat = await lstat(new URL(`upstream/${entry}`, provider));
      assert.equal(stat.isSymbolicLink(), false, entry);
      if (stat.isDirectory()) await walk(`${entry}/`);
      else { assert.equal(stat.isFile(), true, entry); actual.push(entry); }
    }
  }
  await walk();
  assert.deepEqual(actual.sort(), lock.files.map((file) => file.path).sort());
  for (const file of lock.files) {
    const bytes = await readFile(new URL(`upstream/${file.path}`, provider));
    assert.equal(bytes.length, file.byte_length, file.path);
    assert.equal(hash("sha256", bytes), file.sha256, file.path);
    assert.equal(hash("sha1", Buffer.concat([Buffer.from(`blob ${bytes.length}\0`), bytes])), file.git_blob, file.path);
  }
});

test("findings preflight remains identical to the unexported pinned upstream function", async () => {
  const original = await readFile(new URL("validate-findings.cjs", upstream), "utf8");
  const wrapper = await readFile(new URL("validate-document.cjs", provider), "utf8");
  const preflight = original.slice(original.indexOf("function enforceJsonTextLimits(contents) {"), original.indexOf("\nfunction run(file) {"));
  assert.ok(wrapper.includes(preflight));
});

test("native verdicts and mutations produce the same upstream decisions", async () => {
  const valid = await fixture("findings");
  assert.deepEqual(valid.map((finding) => finding.verdict), ["confirmed", "needs_validation", "rejected"]);
  const cases = [valid, [], {}, [...valid, valid[0]]];
  for (const field of Object.keys(valid[0])) {
    const value = structuredClone(valid);
    delete value[0][field];
    cases.push(value);
  }
  const severity = structuredClone(valid);
  severity[1].severity = valid[0].severity;
  cases.push(severity);
  for (const value of cases) {
    const expected = findings.validateDocument(JSON.parse(JSON.stringify(value)), schema);
    const actual = check("findings", value);
    assert.equal(actual.valid, expected.length === 0);
    assert.deepEqual(actual.errors, expected);
  }
  assert.equal(check("findings", severity).valid, false);
});

test("coverage ledger identifiers, states and field mutations retain upstream semantics", async () => {
  const valid = await fixture("coverage-ledger");
  const cases = [valid, [], {}, [...valid, valid[0]]];
  for (const field of Object.keys(valid[0])) {
    const value = structuredClone(valid);
    delete value[0][field];
    cases.push(value);
  }
  for (const value of cases) {
    const expected = ledger.validateDocument(JSON.parse(JSON.stringify(value)));
    const actual = check("coverage-ledger", value);
    assert.equal(actual.valid, expected.length === 0);
    assert.deepEqual(actual.errors, expected);
  }
});

test("preflight retains byte, depth, per-array and ledger collection bounds", () => {
  for (const kind of ["findings", "coverage-ledger"]) {
    for (const bytes of [
      Buffer.alloc(5 * 1024 * 1024 + 1, 32),
      Buffer.from("[".repeat(65) + "]".repeat(65)),
      Buffer.from('[{"nested":[' + "0,".repeat(1000) + "0]}]"),
      Buffer.from([0xc3, 0x28]),
    ]) assert.equal(validateBytes(kind, bytes).valid, false, kind);
  }
  assert.equal(check("findings", Array(1001).fill({})).phase, "preflight");
  assert.equal(check("coverage-ledger", Array(10001).fill({})).phase, "preflight");
  assert.equal(check("coverage-ledger", [Object.fromEntries(Array.from({ length: 1001 }, (_, i) => [String(i), 0]))]).phase, "preflight");
});

test("duplicate decoded keys are refused without interpreting quoted payloads as keys", async () => {
  for (const kind of ["findings", "coverage-ledger"]) {
    const result = validateBytes(kind, Buffer.from('[{"verdict":"confirmed","\\u0076erdict":"rejected"}]'));
    assert.equal(result.valid, false);
    assert.match(result.errors[0], /duplicate JSON object key/);
  }
  const value = await fixture("findings");
  value[0].execution.payloads = ['{"x":1,"x":2}', '" } ] \\ " :'];
  assert.equal(check("findings", value).valid, true);
});

test("malformed JSON and hostile diagnostic values have bounded control-free output", () => {
  for (const text of ['[{"x":', '[{"x\\q":1}]', "\ufeff[]"]) {
    assert.equal(validateBytes("findings", Buffer.from(text)).valid, false);
  }
  const result = check("findings", [{ ["x".repeat(50000) + "\u202e"]: "\u001b" }]);
  assert.equal(result.valid, false);
  assert.ok(Buffer.byteLength(JSON.stringify(result)) <= 256 * 1024);
  assert.ok(result.errors.every((error) => !/[\p{Cc}\p{Cf}]/u.test(error)));
});

test("source-view policy, UTF-8 file index and content identity match independent golden vectors", async () => {
  const vectors = await fixture("source-view-policy/golden");
  const canonical = (value) => {
    if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
    if (value && typeof value === "object") return `{${Object.keys(value).sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b))).map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
    return JSON.stringify(value);
  };
  const domain = (name, value) => hash("sha256", Buffer.concat([Buffer.from(`${name}\0`), Buffer.from(canonical(value))]));
  assert.equal(domain("ai-security-scanner.ai-source-policy/v1", vectors.policy), vectors.policy_sha256);
  const u64 = (n) => { const bytes = Buffer.alloc(8); bytes.writeBigUInt64LE(BigInt(n)); return bytes; };
  assert.notDeepEqual(vectors.files.map(f => f.path).toSorted(), vectors.files.map(f => f.path));
  assert.equal(vectors.identity_payload.source_ref, `snapshot:${vectors.identity_payload.lineage.canonical_snapshot_id};git:not_recorded`);
  const chunks = [Buffer.from("ai-security-scanner.file-index/v1\0")];
  for (const file of vectors.files.toSorted((a, b) => Buffer.compare(Buffer.from(a.path), Buffer.from(b.path)))) {
    const path = Buffer.from(file.path);
    chunks.push(u64(path.length), path, Buffer.from(file.sha256, "hex"), u64(file.byte_length));
  }
  assert.equal(hash("sha256", Buffer.concat(chunks)), vectors.file_index_sha256);
  assert.equal(`ai-view-${domain("ai-security-scanner.ai-source-view-identity/v1", vectors.identity_payload)}`, vectors.view_id);
  assert.equal(vectors.identity_payload.policy_sha256, vectors.policy_sha256);
  assert.equal(vectors.identity_payload.file_index_sha256, vectors.file_index_sha256);
  assert.equal(vectors.identity_payload.lineage.capture_record.status, "not_recorded");
  for (const key of ["authorization", "host_id", "confirmed_by", "request_id", "case_revision", "timestamp"]) assert.ok(!Object.hasOwn(vectors.identity_payload, key));
});
