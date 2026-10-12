import assert from "node:assert/strict";
import test from "node:test";

import { build } from "esbuild";

const bundled = await build({
  stdin: {
    contents: [
      'export * from "./src/i18n/core.ts";',
      'export { formatDate, formatDateTime, phaseMeta, coverageMeta, runStatusMeta } from "./src/lib.ts";',
    ].join("\n"),
    loader: "ts",
    resolveDir: process.cwd(),
    sourcefile: "i18n-test-entry.ts",
  },
  bundle: true,
  format: "esm",
  platform: "node",
  target: "node22",
  write: false,
});

const source = bundled.outputFiles[0]?.text;
assert.ok(source, "the i18n core bundle should contain JavaScript");
const i18n = await import(`data:text/javascript;base64,${Buffer.from(source).toString("base64")}`);

const placeholders = (message: string): string[] =>
  [...message.matchAll(/\{([A-Za-z][A-Za-z0-9_]*)\}/gu)]
    .map((match) => match[1] ?? "")
    .sort();

test("English and Traditional Chinese locales cover the exact same message contract", () => {
  const englishKeys = Object.keys(i18n.localeMessages.en).sort();
  const chineseKeys = Object.keys(i18n.localeMessages["zh-TW"]).sort();

  assert.deepEqual(chineseKeys, englishKeys);
  assert.deepEqual([...i18n.messageKeys].sort(), englishKeys);
  for (const key of i18n.messageKeys) {
    assert.deepEqual(
      placeholders(i18n.localeMessages["zh-TW"][key]),
      placeholders(i18n.localeMessages.en[key]),
      `${key} should use the same interpolation parameters in both locales`,
    );
  }
});

test("typed translators interpolate central and page-local bilingual copy", () => {
  assert.equal(
    i18n.translate("en", "runtime.badge.ready"),
    "Advanced local tools ready at last check",
  );
  assert.equal(
    i18n.translate("zh-TW", "runtime.badge.ready"),
    "進階本機掃描工具上次檢查時可用",
  );

  const localCopy = {
    en: "Scan {target}",
    zhTW: "掃描 {target}",
  } as const;
  assert.equal(i18n.translateBilingualText("en", localCopy, { target: "example.com" }), "Scan example.com");
  assert.equal(i18n.translateBilingualText("zh-TW", localCopy, { target: "example.com" }), "掃描 example.com");
});

test("stored language wins, browser language is a fallback, and unsupported browsers use English", () => {
  assert.equal(i18n.resolveLocalePreference("zh-TW", ["en-US"]), "zh-TW");
  assert.equal(i18n.resolveLocalePreference("en", ["zh-Hant-TW"]), "en");
  assert.equal(i18n.resolveLocalePreference(undefined, ["zh-Hant-TW", "en"]), "zh-TW");
  assert.equal(i18n.resolveLocalePreference(undefined, ["zh-CN"]), "zh-TW");
  assert.equal(i18n.resolveLocalePreference(undefined, ["fr-FR"]), "en");
});

test("locale persistence and the document language use the stable locale contract", () => {
  const values = new Map<string, string>();
  const storage = {
    getItem: (key: string) => values.get(key) ?? null,
    setItem: (key: string, value: string) => { values.set(key, value); },
  };
  const document = { documentElement: { lang: "" } };

  assert.equal(i18n.persistLocalePreference(storage, "zh-TW"), true);
  assert.equal(values.get(i18n.localeStorageKey), "zh-TW");
  assert.equal(i18n.readLocalePreference(storage, ["en-US"]), "zh-TW");
  i18n.applyDocumentLocale(document, "en");
  assert.equal(document.documentElement.lang, "en");

  const blockedStorage = {
    getItem: () => { throw new Error("blocked"); },
    setItem: () => { throw new Error("blocked"); },
  };
  assert.equal(i18n.readLocalePreference(blockedStorage, ["zh-Hant"]), "zh-TW");
  assert.equal(i18n.persistLocalePreference(blockedStorage, "en"), false);
});

test("number and date formatting use the selected Intl locale", () => {
  const date = new Date("2026-08-25T14:30:00.000Z");
  const dateOptions = { year: "numeric", month: "long", day: "numeric", timeZone: "UTC" } as const;

  assert.equal(
    i18n.formatLocaleNumber("en", 1234567.89),
    new Intl.NumberFormat("en").format(1234567.89),
  );
  assert.equal(
    i18n.formatLocaleNumber("zh-TW", 1234567.89),
    new Intl.NumberFormat("zh-TW").format(1234567.89),
  );
  assert.equal(
    i18n.formatLocaleDate("en", date, dateOptions),
    new Intl.DateTimeFormat("en", dateOptions).format(date),
  );
  assert.equal(
    i18n.formatLocaleDate("zh-TW", date, dateOptions),
    new Intl.DateTimeFormat("zh-TW", dateOptions).format(date),
  );
});

test("shared status copy and legacy date helpers follow the active locale", () => {
  i18n.setActiveLocale("en");
  assert.equal(i18n.phaseMeta.ready.label, "Ready to scan");
  assert.equal(i18n.coverageMeta.source_unavailable_unknown.shortLabel, "Unknown");
  assert.equal(i18n.translate("en", "status.engine.pending"), "Queued");
  assert.equal(i18n.runStatusMeta.queued.label, "Queued");
  assert.equal(i18n.translate("en", "status.workflow.pendingVerification"), "Fix reported; verification pending");
  assert.equal(i18n.translate("en", "status.case.verificationDue"), "Fix verification pending");
  assert.equal(i18n.translate("en", "status.coverage.unauthorized.label"), "Authorization required");
  assert.equal(i18n.translate("en", "status.stage.failed.label"), "Stopped with an error");
  assert.equal(i18n.translate("en", "runtime.phase.start.detail"), "Starting the advanced local scan workspace.");
  assert.equal(i18n.translate("en", "runtime.phase.verify.label"), "Verifying advanced local scan tools");
  assert.equal(i18n.translate("en", "runtime.phase.failed.label"), "Advanced local scan-tool setup failed");
  assert.equal(i18n.translate("en", "status.stage.cleanupPending.description"), "Cleaning the local scan workspace.");
  assert.equal(i18n.runStatusMeta.no_checks_completed.label, "No checks completed");
  assert.equal(i18n.runStatusMeta.no_checks_completed.tone, "warning");
  assert.equal(i18n.translate("en", "status.stage.capturing.description"), "Recording scanner output.");
  assert.equal(i18n.translate("en", "shell.data.refreshErrorDetail"), "Refresh saved scans.");

  i18n.setActiveLocale("zh-TW");
  assert.equal(i18n.phaseMeta.ready.label, "可以開始掃描");
  assert.equal(i18n.coverageMeta.source_unavailable_unknown.shortLabel, "未知");
  assert.equal(i18n.translate("zh-TW", "status.engine.pending"), "已排入佇列");
  assert.equal(i18n.runStatusMeta.queued.label, "已排入佇列");
  assert.equal(i18n.translate("zh-TW", "status.workflow.pendingVerification"), "已回報修復，待驗證");
  assert.equal(i18n.translate("zh-TW", "status.case.verificationDue"), "待驗證修復");
  assert.equal(i18n.translate("zh-TW", "status.coverage.unauthorized.label"), "需要授權");
  assert.equal(i18n.translate("zh-TW", "status.stage.failed.label"), "因錯誤停止");
  assert.equal(i18n.translate("zh-TW", "runtime.phase.start.detail"), "正在啟動進階本機掃描工作區。");
  assert.equal(i18n.translate("zh-TW", "runtime.phase.verify.label"), "正在驗證進階本機掃描工具");
  assert.equal(i18n.translate("zh-TW", "runtime.phase.failed.label"), "進階本機掃描工具設定失敗");
  assert.equal(i18n.translate("zh-TW", "status.stage.cleanupPending.description"), "正在清理本機掃描工作區。");
  assert.equal(i18n.runStatusMeta.no_checks_completed.label, "沒有完成任何檢查");
  assert.equal(i18n.translate("zh-TW", "status.stage.capturing.description"), "正在記錄掃描工具輸出。");
  assert.equal(i18n.translate("zh-TW", "shell.data.refreshErrorDetail"), "請重新整理已保存的掃描。");

  const value = "2026-08-25T14:30:00.000Z";
  assert.equal(
    i18n.formatDate(value),
    new Intl.DateTimeFormat("zh-TW", { year: "numeric", month: "short", day: "numeric" })
      .format(new Date(value)),
  );
});

test("runtime failures become plain-language guidance without echoing backend output", () => {
  const raw = String.raw`runtime error: command \\?\C:\Windows\System32\wsl.exe failed with exit status 1`;
  const issue = i18n.classifyRuntimeIssue(raw);
  assert.equal(issue, "wsl");

  const guidance = i18n.translate("en", "runtime.prerequisite.localSupport");
  assert.match(guidance, /advanced local scan tool has not finished setup/u);
  assert.match(guidance, /Try setup again/u);
  assert.doesNotMatch(guidance, /localhost|TCP/u);
  assert.doesNotMatch(guidance, /exit status|System32|runtime error/u);
  assert.doesNotMatch(guidance, /WSL|Terminal|PowerShell/u);

  assert.equal(
    i18n.translate("en", "runtime.badge.needsSetup"),
    "Advanced local scans need setup",
  );
  assert.equal(
    i18n.translate("zh-TW", "runtime.badge.needsSetup"),
    "進階本機掃描需要設定",
  );
  assert.equal(
    i18n.translate("en", "runtime.nextStep"),
    "Advanced local scan tool status",
  );
  assert.equal(
    i18n.translate("zh-TW", "runtime.nextStep"),
    "進階本機掃描工具狀態",
  );

  const chineseGuidance = i18n.translate("zh-TW", "runtime.prerequisite.localSupport");
  assert.match(chineseGuidance, /進階本機掃描工具尚未完成設定/u);
  assert.match(chineseGuidance, /請再試一次/u);
  assert.doesNotMatch(chineseGuidance, /localhost|TCP/u);
});

test("every managed-runtime warning stays concise and action-led", () => {
  const warningKeys = [
    "runtime.prerequisite.localSupport",
    "runtime.prerequisite.virtualization",
    "runtime.prerequisite.permission",
    "runtime.prerequisite.network",
    "runtime.prerequisite.storage",
    "runtime.prerequisite.generic",
    "runtime.recovery.retryAutomatic",
    "runtime.recovery.windowsPending",
    "runtime.phase.idle.detail",
    "runtime.phase.failed.detail",
    "runtime.phase.failed.generic.detail",
    "runtime.phase.failed.nonRetryable.detail",
    "runtime.phase.failed.developerBuild.detail",
    "runtime.phase.failed.developerBuildUnverified.detail",
    "runtime.phase.cancelled.detail",
  ];

  for (const key of warningKeys) {
    const english = i18n.translate("en", key);
    assert.ok(english.length > 0, `${key} should have English guidance`);
    assert.doesNotMatch(english, /saved results|unaffected checks/u, `${key} should avoid defensive reassurance`);
    assert.doesNotMatch(english, /localhost|TCP/u, `${key} should not advertise an unrelated connection utility`);

    const chinese = i18n.translate("zh-TW", key);
    assert.ok(chinese.length > 0, `${key} should have Traditional Chinese guidance`);
    assert.doesNotMatch(chinese, /保存.*結果|不受影響/u, `${key} should avoid defensive reassurance`);
    assert.doesNotMatch(chinese, /localhost|TCP/u, `${key} should not advertise an unrelated connection utility`);
  }

  assert.doesNotMatch(
    i18n.translate("en", "runtime.phase.failed.developerBuild.detail"),
    /install|reinstall/iu,
  );
  assert.doesNotMatch(
    i18n.translate("zh-TW", "runtime.phase.failed.developerBuild.detail"),
    /安裝|重裝/u,
  );
  assert.doesNotMatch(
    i18n.translate("en", "runtime.phase.failed.developerBuildUnverified.detail"),
    /install|reinstall/iu,
  );
  assert.doesNotMatch(
    i18n.translate("zh-TW", "runtime.phase.failed.developerBuildUnverified.detail"),
    /安裝|重裝/u,
  );

  assert.equal(
    i18n.translate("en", "runtime.phase.cancelled.detail"),
    "Scan-tool status: not ready.",
  );
  assert.equal(
    i18n.translate("zh-TW", "runtime.phase.cancelled.detail"),
    "掃描工具狀態：尚未就緒。",
  );
});


test("Japanese has the same central keys and interpolation parameters", () => {
  assert.deepEqual(Object.keys(i18n.localeMessages.ja).sort(), Object.keys(i18n.localeMessages.en).sort());
  for (const key of i18n.messageKeys) {
    assert.deepEqual(placeholders(i18n.localeMessages.ja[key]), placeholders(i18n.localeMessages.en[key]), key);
  }
  assert.equal(i18n.translate("ja", "language.japanese"), "日本語");
});

test("Japanese preference is normalized, persisted, and used for document and Intl formatting", () => {
  assert.equal(i18n.resolveLocalePreference("ja_JP", ["en-US"]), "ja");
  assert.equal(i18n.resolveLocalePreference(null, ["ja-JP", "en-US"]), "ja");
  assert.equal(i18n.normalizeLocale(" JA-jp "), "ja");
  const values = new Map<string, string>();
  const storage = { getItem: (key: string) => values.get(key) ?? null, setItem: (key: string, value: string) => { values.set(key, value); } };
  i18n.persistLocalePreference(storage, "ja");
  assert.equal(i18n.readLocalePreference(storage, ["en"]), "ja");
  const document = { documentElement: { lang: "" } };
  i18n.applyDocumentLocale(document, "ja");
  assert.equal(document.documentElement.lang, "ja");
  assert.equal(i18n.formatLocaleNumber("ja", 1234567), new Intl.NumberFormat("ja").format(1234567));
});

test("Japanese inline copy interpolates translated messages and falls back to English safely", () => {
  assert.equal(i18n.translateBilingualText("ja", { en: "Settings", zhTW: "設定" }), "設定");
  assert.equal(i18n.translateBilingualText("ja", { en: "Working on {action}", zhTW: "正在處理 {action}" }, { action: "テスト" }), "テストを実行中");
  for (const en of ["Untranslated {target}", "constructor", "__proto__", "toString"]) {
    const copy = { en, zhTW: "中国語" };
    assert.equal(i18n.translateBilingualText("ja", copy, { target: "example.com" }), en.replace("{target}", "example.com"));
  }
  assert.deepEqual(i18n.localizeJapanese({ title: "Settings", nested: ["Untranslated", "Language"] }), { title: "設定", nested: ["Untranslated", "言語"] });
});
