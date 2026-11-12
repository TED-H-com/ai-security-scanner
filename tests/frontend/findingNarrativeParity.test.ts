import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import test from "node:test";

import {
  PASSWORD_COMPOSITION_ORDER_REASON,
  PASSWORD_EXPIRY_ORDER_REASON,
} from "../../src/findingNarrative.ts";

// The same sentences about a finding are written twice: TypeScript composes
// them for the findings pane, Rust composes them for the shared HTML report,
// because that report is produced as a file rather than rendered. Duplication
// is the price of that split; drift is not.
//
// Two people reading the same finding -- one on screen, one in the report they
// were sent -- being told different things is the failure that matters, and
// neither side's own tests can see it. This one reads both files.

const typescript = readFileSync(new URL("../../src/findingNarrative.ts", import.meta.url), "utf8");
const rustSource = readFileSync(
  new URL("../../src-tauri/src/finding_narrative.rs", import.meta.url),
  "utf8",
);

// The Rust test module asserts on Chinese fragments of its own, which are not
// translations and have no TypeScript counterpart.
const rust = rustSource.split("#[cfg(test)]")[0] ?? "";

const HAN = /\p{Script=Han}/u;

/**
 * Every Chinese string literal in a file, with interpolation collapsed.
 *
 * `${engineName}` and `{engine}` are the same hole in the same sentence, so the
 * two frames compare equal while the words around them still have to match
 * character for character.
 */
const chineseLiterals = (source: string): Set<string> => {
  const found = new Set<string>();
  // Double-quoted (both languages) and backtick template literals (TypeScript).
  // The escape class is [\s\S] rather than `.` because Rust continues a long
  // literal with a backslash before a newline. With `.` the opening quote of
  // such a literal never closes, every quote after it pairs with the wrong
  // partner, and the extractor silently returns about half the file's strings
  // -- which is what the size guards below are for.
  for (const match of source.matchAll(/"((?:[^"\\]|\\[\s\S])*)"|`((?:[^`\\]|\\[\s\S])*)`/gu)) {
    const literal = match[1] ?? match[2] ?? "";
    if (!HAN.test(literal)) continue;
    found.add(literal.replaceAll(/\$\{[^}]*\}|\{[^}]*\}/gu, "⟦⟧").trim());
  }
  return found;
};

test("the report and the screen tell a reader the same thing", () => {
  const fromTypescript = chineseLiterals(typescript);
  const fromRust = chineseLiterals(rust);

  assert.ok(fromTypescript.size > 25, `extractor found only ${fromTypescript.size} strings`);
  assert.ok(fromRust.size > 25, `extractor found only ${fromRust.size} strings`);

  const onlyOnScreen = [...fromTypescript].filter((line) => !fromRust.has(line));
  const onlyInReport = [...fromRust].filter((line) => !fromTypescript.has(line));

  assert.deepEqual(
    onlyOnScreen,
    [],
    `wording the findings pane has and the shared report does not:\n${onlyOnScreen.join("\n")}`,
  );
  assert.deepEqual(
    onlyInReport,
    [],
    `wording the shared report has and the findings pane does not:\n${onlyInReport.join("\n")}`,
  );
});

test("the extractor can tell two translations apart", () => {
  // Guards the test above: if the normalization flattened everything, or the
  // regex matched nothing, both sets would be equal and empty and the parity
  // assertion would pass while saying nothing at all.
  const changed = typescript.replace("雲端資源或資料可能遭到未預期的存取、變更或使用", "雲端資源可能有風險");
  assert.notEqual(changed, typescript, "the sentence this guard edits has moved");
  const drifted = [...chineseLiterals(changed)].filter((line) => !chineseLiterals(rust).has(line));
  assert.ok(drifted.includes("雲端資源可能有風險"), drifted.join("\n"));
});

/**
 * The English both sides now match on, not just the Chinese both sides print.
 *
 * The priority reasons carry no per-entry code, so these English strings are
 * the matching key. If the Rust side rewords one, this side stops recognising
 * it and quietly falls back to English -- no crash, no failed assertion, just a
 * reader who is shown one Chinese bullet and two English ones. Comparing the
 * output would never see it, because both sides would still be "correct".
 */
const rustLiterals = (() => {
  // Rust continues a long literal with a backslash before the newline and
  // swallows the following indentation.
  const joined = rustSource.replaceAll(/\\\n\s*/gu, "");
  return [...joined.matchAll(/"((?:[^"\\]|\\[\s\S])*)"/gu)].map(
    (match) => match[1]?.replaceAll("\\'", "'") ?? "",
  );
})();

test("the lower-order password reasons are the sentences the report stores", () => {
  // The screen recognises these by exact text. JSON.stringify keeps the
  // surrounding quotes, so a longer sentence that merely contains one cannot pass.
  const missing = [PASSWORD_COMPOSITION_ORDER_REASON, PASSWORD_EXPIRY_ORDER_REASON]
    .filter((sentence) => !rustSource.includes(JSON.stringify(sentence)));
  assert.deepEqual(
    missing,
    [],
    `src-tauri/src/finding_narrative.rs must store:\n${missing.join("\n")}`,
  );
});

test("the English keys the screen matches on are the ones the report writes", () => {
  const matchedOnScreen = [
    ...typescript.matchAll(/^\s*(?:[a-z_]+:|export const [A-Z_]+ =)\s*\n?\s*"((?:[^"\\]|\\.)*)",?$/gmu),
  ]
    .map((match) => match[1] ?? "")
    .filter((literal) => !HAN.test(literal) && literal.length > 20);

  assert.ok(matchedOnScreen.length > 5, `extractor found only ${matchedOnScreen.length} keys`);

  const missing = matchedOnScreen.filter((literal) => !rustLiterals.includes(literal));
  assert.deepEqual(
    missing,
    [],
    `English the findings pane matches on that the report no longer writes:\n${missing.join("\n")}`,
  );
});

/**
 * Coverage names are matched on a fragment, not on the whole sentence, so the
 * Chinese comparison above cannot see a missing rule.
 *
 * Both sides can hold the label "失敗的掃描批次" and still disagree about which
 * English names reach it: one side matching on " failed scan batches" and the
 * other on " failed scan batch" produces identical literals and different
 * output. The needle is the part that has to be the same.
 */
test("both sides recognise the same English before writing the same Chinese", () => {
  // Both files pair an English key with a Chinese sentence: coverage names
  // matched on a fragment, and coverage prose matched on the whole sentence.
  // rustfmt and prettier each break a long pair across lines, so runs of
  // whitespace are flattened first and the brackets left out -- one side ends
  // the pair with a trailing comma.
  const flatten = (source: string): string => source.replaceAll(/\s+/gu, " ");
  const flatRust = flatten(rust);
  const pairs = [
    ...flatten(typescript).matchAll(/\[ ?"( ?[A-Za-z][^"]*)", ?"([^"]*)",? ?\]/gu),
  ].map((match) => ({ english: match[1] ?? "", chinese: match[2] ?? "" }));

  assert.ok(pairs.length >= 90, `extractor found only ${pairs.length} pairs`);
  assert.ok(pairs.some((pair) => pair.english === " completed-check time"));
  assert.ok(pairs.some((pair) => pair.english === "This check did not start, so it is not a pass."));

  const unmatched = pairs.filter(
    (pair) => !flatRust.includes(`"${pair.english}", "${pair.chinese}"`),
  );
  assert.deepEqual(
    unmatched,
    [],
    `pairs the screen has that the report does not, English key and Chinese together:\n${unmatched
      .map((pair) => `${pair.english} -> ${pair.chinese}`)
      .join("\n")}`,
  );

  const interruptedPreparation = pairs.find(
    (pair) => pair.english === "The app closed while preparing this check. Retry from the saved plan.",
  );
  assert.deepEqual(interruptedPreparation, {
    english: "The app closed while preparing this check. Retry from the saved plan.",
    chinese: "應用程式在準備這項檢查時關閉。請從已儲存的計畫重新執行。",
  });
});

const confidenceTable = (source: string, marker: string): Map<string, string> => {
  const start = source.indexOf(marker);
  assert.ok(start >= 0, `missing ${marker}`);
  const end = [source.indexOf("\n};", start), source.indexOf("\n}\n", start)]
    .filter((candidate) => candidate >= 0)
    .sort((left, right) => left - right)[0];
  assert.ok(end !== undefined, `unterminated ${marker}`);
  const tail = source.slice(start, end + 2).replaceAll(/\s+/gu, " ");
  const entries = new Map<string, string>();
  for (const match of tail.matchAll(
    /(?:ConfidenceBasisCode::)?([A-Za-z][A-Za-z0-9_]*)\s*(?:=>|:)\s*(?:\{\s*)?"([^"]*)"/gu,
  )) {
    const raw = match[1] ?? "";
    const key = raw.includes("_")
      ? raw
      : raw.replaceAll(/([a-z0-9])([A-Z])/gu, "$1_$2").toLowerCase();
    entries.set(key, match[2] ?? "");
  }
  return entries;
};

test("the confidence basis tables have identical code-to-prose pairs", () => {
  const tsChinese = confidenceTable(typescript, "const CONFIDENCE_BASIS:");
  const tsEnglish = confidenceTable(typescript, "const CONFIDENCE_BASIS_ENGLISH:");
  const rustEnglish = confidenceTable(rustSource, "pub fn confidence_basis_english");
  const rustChinese = confidenceTable(rustSource, "pub fn confidence_basis_zh_hant");

  assert.equal(tsChinese.size, 6);
  assert.deepEqual(tsChinese, rustChinese);
  assert.deepEqual(tsEnglish, rustEnglish);
});

/**
 * The product has one Traditional Chinese word for a scanner, 掃描工具. A
 * reader who also meets 掃描器 cannot tell whether the two name different
 * sources. This reads the interface and the report's Rust source and fails on
 * the retired word in either. A line counts as a comment only when, after
 * leading whitespace, it starts with `//`, `/*`, or `*`.
 */
const isCommentLine = (line: string): boolean => {
  const trimmed = line.replace(/^\s+/u, "");
  return trimmed.startsWith("//") || trimmed.startsWith("/*") || trimmed.startsWith("*");
};

const retiredScannerWord = "掃描器";

const findRetiredWord = (label: string, source: string, violations: string[]): void => {
  source.split("\n").forEach((line, index) => {
    if (isCommentLine(line)) return;
    if (line.includes(retiredScannerWord)) violations.push(`${label}:${index + 1}`);
  });
};

/** Everything before Rust's own test module, never the fixtures inside it. */
const beforeModTests = (source: string, label: string): string => {
  const marker = "\nmod tests {";
  const cut = source.indexOf(marker);
  assert.ok(cut > 0, `${label} no longer has a top-level \`mod tests {\` boundary`);
  return source.slice(0, cut);
};

test("the Chinese interface calls a scanner 掃描工具", () => {
  const repoRoot = new URL("../../", import.meta.url);
  const violations: string[] = [];

  const walk = (directory: string): void => {
    for (const entry of readdirSync(new URL(directory, repoRoot), { withFileTypes: true })) {
      if (entry.isDirectory()) {
        walk(`${directory}${entry.name}/`);
        continue;
      }
      if (!/\.tsx?$/u.test(entry.name)) continue;
      const relative = `${directory}${entry.name}`;
      findRetiredWord(relative, readFileSync(new URL(relative, repoRoot), "utf8"), violations);
    }
  };
  walk("src/");

  const caseServiceSource = readFileSync(
    new URL("../../src-tauri/src/case_service.rs", import.meta.url),
    "utf8",
  );
  findRetiredWord(
    "src-tauri/src/case_service.rs",
    beforeModTests(caseServiceSource, "src-tauri/src/case_service.rs"),
    violations,
  );
  findRetiredWord(
    "src-tauri/src/finding_narrative.rs",
    beforeModTests(rustSource, "src-tauri/src/finding_narrative.rs"),
    violations,
  );

  assert.deepEqual(
    violations,
    [],
    `still calls a scanner 掃描器 instead of 掃描工具:\n${violations.join("\n")}`,
  );
});
