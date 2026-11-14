import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { parseSync } from "vite";
import { jaInline } from "../../src/i18n/locales/ja-inline.ts";

const sources = [
  "../../src/auditFailure.ts",
  "../../src/components/AuditFailureDetails.tsx",
  "../../src/components/SourceAuditResults.tsx",
  "../../src/components/CombinedReportExport.tsx",
];

type ParsedNode = {
  type: string;
  name?: string;
  value?: unknown;
  key?: ParsedNode;
  callee?: ParsedNode;
  arguments?: ParsedNode[];
  elements?: Array<ParsedNode | null>;
  expressions?: ParsedNode[];
  quasis?: ParsedNode[];
  consequent?: ParsedNode;
  alternate?: ParsedNode;
  expression?: ParsedNode;
};

// These components use en: fields, bilingual tuples and t(en, zhTW) calls.
// Walk their syntax instead of matching source text, so escaped and single-quoted
// literals are checked too. Runtime-generated strings are not string literals.
const englishLiterals = (path: string, source: string): Set<string> => {
  const parsed = parseSync(path, source);
  assert.deepEqual(parsed.errors, [], `${path} must parse`);
  const result = new Set<string>();
  const literal = (node: ParsedNode | null | undefined): string | undefined => {
    if (node?.type === "Literal" && typeof node.value === "string") return node.value;
    if (node?.type === "TemplateLiteral" && node.expressions?.length === 0) {
      const value = node.quasis?.[0]?.value as { cooked?: unknown } | undefined;
      if (typeof value?.cooked === "string") return value.cooked;
    }
    return undefined;
  };
  const addConditionalLiterals = (node: ParsedNode | undefined): void => {
    if (!node) return;
    const value = literal(node);
    if (value !== undefined) result.add(value);
    else if (node.type === "ConditionalExpression") {
      addConditionalLiterals(node.consequent);
      addConditionalLiterals(node.alternate);
    } else if (node.type === "ParenthesizedExpression" || node.type === "TSAsExpression") {
      addConditionalLiterals(node.expression);
    }
  };
  const visit = (value: unknown): void => {
    if (Array.isArray(value)) {
      for (const child of value) visit(child);
      return;
    }
    if (!value || typeof value !== "object") return;
    const node = value as ParsedNode;
    if (node.type === "Property" && (node.key?.name === "en" || node.key?.value === "en")) {
      addConditionalLiterals(node.value as ParsedNode | undefined);
    }
    if (node.type === "CallExpression" && node.callee?.type === "Identifier" && node.callee.name === "t") {
      addConditionalLiterals(node.arguments?.[0]);
    }
    if (node.type === "ArrayExpression" && node.elements) {
      for (let index = 1; index < node.elements.length; index += 1) {
        const english = literal(node.elements[index - 1]);
        const chinese = literal(node.elements[index]);
        if (english !== undefined && chinese !== undefined && /[\u3400-\u9fff]/u.test(chinese)) result.add(english);
      }
    }
    for (const child of Object.values(value)) visit(child);
  };
  visit(parsed.program);
  return result;
};

test("source audit copy collector handles inline translation forms", () => {
  const source = [
    'const copy = { en: "A \\"quote\\"", zhTW: "中文" };',
    "const rows = [['Second', '第二'], ['field', 'Third', '第三']];",
    "t(flag ? 'Fourth' : `Fifth`, '選項');",
  ].join("\n");
  assert.deepEqual([...englishLiterals("example.tsx", source)].sort(), [
    'A "quote"', "Fifth", "Fourth", "Second", "Third",
  ]);
});

test("source audit inline copy has complete and nonempty Japanese translations", () => {
  const english = new Set<string>();
  for (const source of sources) {
    const entries = englishLiterals(source, readFileSync(new URL(source, import.meta.url), "utf8"));
    assert.ok(entries.size > 0, `No inline copy found in ${source}`);
    for (const entry of entries) english.add(entry);
  }
  const missing = [...english].filter((entry) => !Object.hasOwn(jaInline, entry)).sort();
  assert.deepEqual(missing, [], `Missing Japanese inline entries:\n${missing.join("\n")}`);

  const productNames = new Set(["Cloudflare"]);
  const invalid = [...english].filter((entry) => {
    const translated = jaInline[entry]!;
    return translated.trim().length === 0 || (translated === entry && !productNames.has(entry));
  }).sort();
  assert.deepEqual(invalid, [], `Empty or untranslated Japanese inline entries:\n${invalid.join("\n")}`);
  const placeholders = (value: string) => [...value.matchAll(/\{([A-Za-z][A-Za-z0-9_]*)\}/gu)]
    .map((match) => match[1]).sort();
  for (const entry of english) assert.deepEqual(placeholders(jaInline[entry]!), placeholders(entry), entry);
});
