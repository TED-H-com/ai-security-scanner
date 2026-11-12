import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { adaptSourceAudit } from "../../src/sourceAuditTypes.ts";

const read = (path: string) => readFileSync(new URL(path, import.meta.url), "utf8");
const typescript = read("../../src/sourceAuditTypes.ts");
const block = (source: string, declaration: string) => {
  const start = source.indexOf(declaration);
  assert.ok(start >= 0, declaration);
  const end = source.indexOf("\n}", start);
  assert.ok(end > start);
  return source.slice(start + declaration.length, end);
};
for (const [file, names] of [
  ["../../src-tauri/src/source_audit_report.rs", ["SourceAuditMethod", "SourceAuditOutcome", "SourceAuditGap", "SourceAuditValidation", "SourceAuditReport", "SourceAuditTechnical"]],
  ["../../src-tauri/src/provider_report.rs", ["ProviderSourceLocation", "AgentAuditRecord"]],
  ["../../src-tauri/src/agent_audit_admission.rs", ["ProviderRecordRef"]],
] as const) {
  const rust = read(file);
  for (const name of names) test(`${name}: every serde field survives the desktop wire contract`, () => {
    const body = block(rust, `pub struct ${name} {`);
    // These DTOs serialize snake_case literally; fail if serde naming changes.
    assert.ok(!body.includes("serde(rename"));
    assert.ok(!rust.slice(Math.max(0, rust.indexOf(`pub struct ${name}`) - 120), rust.indexOf(`pub struct ${name}`)).includes("rename_all"));
    const fields = [...body.matchAll(/^    pub (\w+):/gmu)].map((m) => m[1]).sort();
    const tsFields = [...block(typescript, `export interface ${name}Wire {`).matchAll(/^  (\w+)\??:/gmu)].map((m) => m[1]).sort();
    assert.ok(fields.length >= 3);
    assert.deepEqual(tsFields, fields);
  });
}
// The adapter intentionally clones the entire typed DTO. Check the full native
// shape (including arbitrary native JSON keys) instead of maintaining a second
// whitelist of fields which could silently discard future provenance.
test("the source audit adapter keeps native records and every nested field", async () => {
  const { sourceAudit } = await import("../support/sourceAudit.ts");
  const wire = sourceAudit();
  const adapted = adaptSourceAudit(wire);
  assert.deepEqual(adapted, wire);
  assert.notEqual(adapted, wire);
  assert.notEqual(adapted.technical_detail, wire.technical_detail);
});

import { blockerWording, terminationWording, failureText, failureDescription } from "../../src/auditFailure.ts";
const failures = read("../../src/auditFailure.ts");
const snake = (word: string) => word.replace(/(?<!^)[A-Z]/gu, (c) => `_${c}`).toLowerCase();
for (const [path, name, table] of [
  ["../../src-tauri/src/cloudflare_provider/audit/mod.rs", "BlockerCode", blockerWording],
  ["../../src-tauri/src/cloudflare_provider/audit/record.rs", "TerminationReason", terminationWording],
] as const) test(`${name}: desktop accepts exactly the native failure codes`, () => {
  const codes = [...block(read(path), `pub enum ${name} {`).matchAll(/^    (\w+),$/gmu)].map((m) => snake(m[1]!));
  assert.deepEqual(Object.keys(table).sort(), codes.sort());
});
test("failure outcome fields and ending variants retain the flattened Rust DTO", () => {
  const rust = read("../../src-tauri/src/agent_audit_failure.rs");
  const fields = [...block(rust, "pub struct Outcome {").matchAll(/pub (\w+):/gu)].map((m) => m[1]).filter((v) => v !== "ending");
  const tsFields = [...block(failures, "export interface AuditFailureFields {").matchAll(/^  (\w+)\??:/gmu)].map((m) => m[1]);
  assert.deepEqual(tsFields, fields);
  assert.match(rust, /#\[serde\(flatten\)\]\s+pub ending: Ending/u);
  assert.match(failures, /AuditFailureOutcome = AuditFailureFields & AuditFailureEnding/u);
  const ending = block(rust, "pub enum Ending {");
  for (const [variant, fields] of [...ending.matchAll(/(Blocked|Terminated) \{([^}]+)\}/gu)].map((m) => [m[1]!, [...m[2]!.matchAll(/(\w+):/gu)].map((f) => f[1])])) {
    const ts = failures.match(new RegExp(`\\{ ending: "${snake(variant as string)}"; ([^}]+)\\}`))![1]!;
    assert.deepEqual([...ts.matchAll(/(\w+):/gu)].map((m) => m[1]), fields);
  }
});
test("failure technical execution and actual outcome fields equal the native report DTO", () => {
  const rust = read("../../src-tauri/src/beginner_report.rs");
  const body = block(rust, "pub enum TechnicalExecution {").match(/AgentAuditFailure \{([^}]+)\}/u)![1]!;
  const fields = [...body.matchAll(/^        (\w+):/gmu)].map((m) => m[1]);
  const tsFields = [...block(failures, "export interface AuditFailureTechnicalWire {").matchAll(/^  (\w+):/gmu)].map((m) => m[1]).filter((v) => v !== "kind");
  assert.deepEqual(tsFields, fields);
  const description = block(read("../../src-tauri/src/agent_audit_failure/wording.rs"), "pub struct Description {");
  assert.deepEqual([...description.matchAll(/pub (\w+):/gu)].map((m) => m[1]), ["summary", "reason", "next_action"]);
  assert.match(block(rust, "pub struct ActualCheck {"), /pub outcome: Option<crate::agent_audit_failure::wording::Description>/u);
  const types = read("../../src/types.ts");
  assert.match(block(types, "export interface BeginnerActualCheck {"), /outcome\?: \{ summary: string; reason: string; nextAction: string \}/u);
});
test("failure EN and zh-TW sentences and every code-to-sentence mapping equal Rust", () => {
  const rust = read("../../src-tauri/src/agent_audit_failure/wording.rs");
  const pairs = [...rust.matchAll(/^    \("(.*?)", "(.*?)"\),$/gmu)].map((m) => [m[1], m[2]]);
  assert.equal(pairs.length, 26);
  assert.deepEqual(failureText, pairs);
  for (const [prefix, table] of [["B", blockerWording], ["T", terminationWording]] as const) {
    const mapped: Record<string, number[]> = {};
    const expression = new RegExp(`((?:${prefix}::\\w+\\s*(?:\\|\\s*)?)+)=>\\s*\\{?\\s*\\((\\d+), (\\d+)\\)`, "gu");
    for (const match of rust.matchAll(expression)) {
      for (const code of match[1]!.matchAll(/::(\w+)/gu)) mapped[snake(code[1]!)] = [Number(match[2]), Number(match[3])];
    }
    assert.deepEqual(table, mapped);
    for (const code of Object.keys(table)) {
      const description = failureDescription(prefix === "B" ? { ending: "blocked", reasons: [code as keyof typeof blockerWording] }
        : { ending: "terminated", reason: code as keyof typeof terminationWording, assignment_count: 0, capture_count: 0 });
      for (const [locale, index] of [["en", 0], ["zhTW", 1]] as const) {
        assert.equal(description.summary[locale], pairs[prefix === "B" ? 0 : 1]![index]);
        assert.equal(description.gap[locale], pairs[prefix === "B" ? 2 : 3]![index]);
        assert.equal(description.reason[locale], pairs[mapped[code]![0]!]![index]);
        assert.equal(description.nextAction[locale], pairs[mapped[code]![1]!]![index]);
      }
    }
  }
});


test("technical failure outcomes and labels match the HTML renderer in both locales", () => {
  const renderer = read("../../src-tauri/src/report_renderer.rs");
  const arm = renderer.slice(renderer.indexOf("TechnicalExecution::AgentAuditFailure {"), renderer.indexOf("TechnicalExecution::AgentAudit {"));
  const details = read("../../src/components/AuditFailureDetails.tsx");
  for (const pair of [
    ["Source audit did not start", "原始碼稽核未開始"],
    ["Source audit ended before completion", "原始碼稽核未完成即結束"],
    ["reason codes", "原因代碼"], ["recorded time", "記錄時間"],
    ["preparation receipt SHA-256", "準備收據 SHA-256"],
    ["terminal record entry SHA-256", "終態紀錄項目 SHA-256"],
    ["assignment count", "派工筆數"], ["capture count", "擷取筆數"],
  ]) for (const sentence of pair) {
    assert.ok(arm.includes(`"${sentence}"`), sentence);
    assert.ok(details.includes(`"${sentence}"`), sentence);
  }
});
