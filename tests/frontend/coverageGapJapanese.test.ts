import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { parseSync } from "vite";
import { failureText } from "../../src/auditFailure.ts";
import {
  coverageGapProse,
  coverageGapProseWithoutDiagnosticCode,
  localizedControlMappingRationale,
  localizedCoverageRecordDetail,
  localizedDataQualityWarning,
  localizedRequestedLimitKind,
  testedObservationProse,
  UNEVALUATED_CONTROL_KINDS,
} from "../../src/findingNarrative.ts";
import { jaInline } from "../../src/i18n/locales/ja-inline.ts";

// Read the private table as syntax, just as the source-audit copy contract does,
// so adding a gap sentence automatically adds it to this localization contract.
const tableKeys = (name: string): string[] => {
  const path = "../../src/findingNarrative.ts";
  const parsed = parseSync(path, readFileSync(new URL(path, import.meta.url), "utf8"));
  assert.deepEqual(parsed.errors, []);
  let rows: unknown[] | undefined;
  const visit = (value: unknown): void => {
    if (Array.isArray(value)) return value.forEach(visit);
    if (!value || typeof value !== "object") return;
    const node = value as Record<string, any>;
    if (node.type === "VariableDeclarator" && node.id?.name === name) {
      assert.equal(node.init?.type, "ArrayExpression");
      rows = node.init.elements;
    }
    Object.values(value).forEach(visit);
  };
  visit(parsed.program);
  assert.ok(rows?.length, `${name} must contain entries`);
  return rows.map((row: any) => {
    assert.equal(row.type, "ArrayExpression");
    assert.equal(row.elements[0]?.type, "Literal");
    assert.equal(typeof row.elements[0]?.value, "string");
    return row.elements[0].value as string;
  });
};

const templates = [
  "{count} {kind}",
  "{sentence} Upstream detail: {detail}",
  "{sentence} Diagnostic code: {code}.",
  "{sentence} Support ended: {date}.",
  "{sentence} Refused connections: {count}.",
  "{sentence} Not evaluated: {items}.",
] as const;

test("coverage gap copy has complete Japanese translations with matching placeholders", () => {
  const sentences = tableKeys("COVERAGE_GAP_PROSE");
  const english = new Set([
    ...sentences,
    ...UNEVALUATED_CONTROL_KINDS.map(([kind]) => kind),
    ...failureText.map(([sentence]) => sentence),
    ...templates,
  ]);
  const missing = [...english].filter((entry) => !Object.hasOwn(jaInline, entry)).sort();
  assert.deepEqual(missing, [], `Missing Japanese inline entries:\n${missing.join("\n")}`);
  const invalid = [...english].filter((entry) => !jaInline[entry]?.trim() || jaInline[entry] === entry).sort();
  assert.deepEqual(invalid, [], `Empty or untranslated Japanese inline entries:\n${invalid.join("\n")}`);
  const placeholders = (value: string) => [...value.matchAll(/\{([A-Za-z][A-Za-z0-9_]*)\}/gu)]
    .map((match) => match[1]).sort();
  for (const entry of english) assert.deepEqual(placeholders(jaInline[entry]!), placeholders(entry), entry);
  for (const sentence of [...sentences, ...failureText.map(([entry]) => entry)]) {
    assert.equal(coverageGapProse("ja", sentence), jaInline[sentence], sentence);
  }
});

const cases = [
  {
    en: "This check did not start, so it is not a pass.",
    zh: "這項檢查沒有啟動，因此不代表通過。",
    ja: "この確認は開始されなかったため、合格とは見なせません。",
  },
  {
    en: "Maester evaluated this control but did not return a pass or fail verdict. Upstream detail: Confirm {code}.",
    zh: "Maester 已評估這項控制措施，但未回傳通過或失敗的判定。上游詳細資料：Confirm {code}.",
    ja: "Maester はこのコントロールを評価しましたが、合格または不合格の判定を返しませんでした。上流の詳細：Confirm {code}.",
  },
  {
    en: "This check did not start, so it is not a pass. Diagnostic code: engine_release_unavailable.",
    zh: "這項檢查沒有啟動，因此不代表通過。診斷代碼：engine_release_unavailable。",
    ja: "この確認は開始されなかったため、合格とは見なせません。診断コード：engine_release_unavailable。",
  },
  {
    en: "This check ran on detection knowledge whose declared support had already ended, so issues published after that date were not tested. Support ended: 2023-04-10.",
    zh: "這項檢查執行時所用的偵測知識，其宣告的支援期限已經結束，因此該日期之後才公布的問題並未受測。支援結束日期：2023-04-10。",
    ja: "この確認ではサポート終了済みの検出情報を使用したため、終了日以降に公開された問題はテストしていません。サポート終了日：2023-04-10。",
  },
  {
    en: "The approved rate limit refused some of this check's connections, so part of the check never reached the target. Refused connections: 0012.",
    zh: "核准的速率限制拒絕了這項檢查的部分連線，因此部分檢查未能送達目標。拒絕的連線：0012。",
    ja: "承認済みのレート制限により、この確認の一部の接続が拒否され、確認の一部が対象に届きませんでした。拒否された接続：0012。",
  },
  {
    en: "Some controls in scope were not evaluated, so their state is unknown. Not evaluated: 20 left without an automated verdict, 5 could not be evaluated, 2 future kind.",
    zh: "範圍內有部分控制項未經評估，因此狀態未知。未評估：20 未回傳自動判定、5 無法評估、2 future kind。",
    ja: "対象範囲の一部のコントロールは評価されていないため、状態は不明です。未評価：20 件（自動判定なし）、5 件（評価できなかった）、2 future kind。",
  },
  { en: "An unknown sentence.", zh: "An unknown sentence.", ja: "An unknown sentence." },
] as const;

test("coverage gap sentences and data splits preserve English and Chinese behavior and translate Japanese", () => {
  for (const { en, zh, ja } of cases) {
    assert.equal(coverageGapProse("en", en), en);
    assert.equal(coverageGapProse("zh-TW", en), zh);
    assert.equal(coverageGapProse("ja", en), ja);
    const withoutCode = en.replace(/ Diagnostic code: (.+)\.$/u, "");
    assert.equal(coverageGapProseWithoutDiagnosticCode("en", en), withoutCode);
    assert.equal(coverageGapProseWithoutDiagnosticCode("zh-TW", en), coverageGapProse("zh-TW", withoutCode));
    assert.equal(coverageGapProseWithoutDiagnosticCode("ja", en), coverageGapProse("ja", withoutCode));
  }
});

test("each recorded control kind is translated without changing its count", () => {
  const base = "Some controls in scope were not evaluated, so their state is unknown.";
  const items = UNEVALUATED_CONTROL_KINDS.map(([kind], index) => `00${index + 1} ${kind}`);
  const english = `${base} Not evaluated: ${items.join(", ")}, 4 future kind.`;
  const translated = UNEVALUATED_CONTROL_KINDS.map(([kind], index) => `00${index + 1} 件（${jaInline[kind]}）`);
  assert.equal(coverageGapProse("en", english), english);
  assert.equal(
    coverageGapProse("ja", english),
    `${jaInline[base]}未評価：${translated.join("、")}、4 future kind。`,
  );
});

test("unknown bases and malformed data use the same fallback in every locale", () => {
  for (const english of [
    "Unknown base. Diagnostic code: unrecognized.",
    "Unknown base. Support ended: 2023-04-10.",
    "Unknown base. Refused connections: 3.",
    "Unknown base. Not evaluated: 3 skipped.",
    "Maester evaluated this control but did not return a pass or fail verdict. Upstream detail: ",
    "Some controls in scope were not evaluated, so their state is unknown. Refused connections: -1.",
  ]) {
    for (const locale of ["en", "zh-TW", "ja"] as const) assert.equal(coverageGapProse(locale, english), english);
  }
});


// The same contract covers every producer-authored sentence and unit in the
// coverage details. Parsing the tables means new rows cannot silently ship in English.
const coverageDetailTemplates = [
  "{check} check", "{check}: unfinished part",
  "{check}: no verdict for {control}", "{check}: manual review for {control}",
  "{label} ({count})", "{check} {label}", "requested check {engine}",
  "Coverage detail: {dimension}",
  "one connection attempt; {timeout} ms timeout; {payload} application-payload bytes",
  "{check} on asset {asset}", "{done} of {total}",
  "{count} frozen {checks} on asset {asset}",
  "technology-aware upstream profile on exact website origin for asset {asset}",
  "applicability-driven upstream profile on asset {asset} across {ports} approved TCP ports",
  "exact {count}-check upstream Greenbone SMTP profile on asset {asset}",
  "{evidenced} of {total} selected TLS checks on asset {asset}",
  "{sentence} Explicit stale-knowledge warning: {detail}. Completion proves execution, not current knowledge.",
  "{sentence} Exact built-in localhost TCP attempt(s): {detail}. This records only those connection attempts; it does not establish that the service or computer is secure, and it does not cover other ports or hosts.",
  "{sentence} Latest provider discovery: {detail}",
  "{sentence} This state is independent of how many findings were reported.",
  "The source area is explicitly outside this case: {reason} This is a scoped applicability statement, not a successful scan result.",
  "The source is connected and the latest attributable discovery returned no assets. This is not a successful scan result; {count} prior asset observation(s) remain retained.",
  "The source is not currently connected (status: {status}). Its present coverage is unknown; {count} previously attributed asset(s) are retained but do not make the source green.",
  "The scan's frozen authorization evidence is incomplete: {detail}. Live grants are never used to reconstruct historical scan permission.",
  "All {count} compatible engine run(s) planned for this asset completed.",
  "All {count} planned task(s) for this asset completed their exact declared dimensions.",
  "The authorized scan is incomplete: {reasons}. Only completed compatible catalog-engine runs or exact completed built-in tasks can produce scanned coverage.",
  "Finding {finding} selected-run presentation snapshot: unavailable. Display wording: current canonical text.",
  "Finding {finding} presentation detail: unavailable. Retained run observation: available.",
  "Limit used in this run: {kind}", "{kind} ({holder})",
  "{value} ms", "{value} bytes", "{value} seconds",
  "{requests} per second, concurrency {concurrency}",
] as const;

test("coverage detail tables and templates have complete Japanese translations with matching placeholders", () => {
  const tables = ["TESTED_OBSERVATION_PROSE", "CONTROL_MAPPING_RATIONALE_PROSE",
    "COVERAGE_RECORD_DETAIL_PROSE", "DATA_QUALITY_WARNING_PROSE",
    "REQUESTED_LIMIT_KIND_SUFFIXES", "REQUESTED_LIMIT_VALUE_UNITS"];
  const english = new Set([...tables.flatMap(tableKeys), ...coverageDetailTemplates]);
  const missing = [...english].filter((entry) => !Object.hasOwn(jaInline, entry)).sort();
  assert.deepEqual(missing, [], `Missing Japanese inline entries:\n${missing.join("\n")}`);
  const invalid = [...english].filter((entry) => !jaInline[entry]?.trim() || jaInline[entry] === entry).sort();
  assert.deepEqual(invalid, [], `Empty or untranslated Japanese inline entries:\n${invalid.join("\n")}`);
  const placeholders = (value: string) => [...value.matchAll(/\{([A-Za-z][A-Za-z0-9_]*)\}/gu)]
    .map((match) => match[1]).sort();
  for (const entry of english) assert.deepEqual(placeholders(jaInline[entry]!), placeholders(entry), entry);
  for (const entry of tableKeys("TESTED_OBSERVATION_PROSE")) {
    assert.equal(testedObservationProse("ja", entry), jaInline[entry], entry);
  }
  for (const entry of tableKeys("CONTROL_MAPPING_RATIONALE_PROSE")) {
    assert.equal(localizedControlMappingRationale(entry, "ja"), jaInline[entry], entry);
  }
  for (const entry of tableKeys("COVERAGE_RECORD_DETAIL_PROSE")) {
    assert.equal(localizedCoverageRecordDetail(entry, "ja"), jaInline[entry], entry);
  }
  for (const entry of tableKeys("DATA_QUALITY_WARNING_PROSE")) {
    assert.equal(localizedDataQualityWarning(entry, "ja"), jaInline[entry], entry);
  }
  for (const entry of tableKeys("REQUESTED_LIMIT_KIND_SUFFIXES")) {
    assert.equal(localizedRequestedLimitKind(entry, "ja"), jaInline[entry], entry);
  }
});
