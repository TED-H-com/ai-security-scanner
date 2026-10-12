import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  isReportLocale,
  reportLocaleForUiLocale,
} from "../../src/reportLocale.ts";

test("the UI locale maps to the closed native HTML report locale", () => {
  assert.equal(reportLocaleForUiLocale("en"), "en");
  assert.equal(reportLocaleForUiLocale("ja"), "en");
  assert.equal(reportLocaleForUiLocale("zh-TW"), "zh-Hant");
  assert.equal(isReportLocale("en"), true);
  assert.equal(isReportLocale("zh-Hant"), true);
  assert.equal(isReportLocale("zh-TW"), false);
  assert.equal(isReportLocale("fr"), false);
});

test("preview and download share the same locale coordinate", () => {
  const page = readFileSync(new URL("../../src/pages/ExportPage.tsx", import.meta.url), "utf8");
  assert.match(page, /onPreview\(\{ runId: selectedRun\.id, locale: reportLocale,/u);
  assert.match(page, /result\.locale !== reportLocale/u);
  assert.match(page, /onExport\(\{ runId: selectedRun\.id, locale: reportLocale,/u);
  assert.match(page, /preview\.locale === reportLocale/u);
  assert.match(page, /preview\.includeRawEvidence === includeRawEvidence/u);
});
