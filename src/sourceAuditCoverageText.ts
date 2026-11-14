import { translateBilingualText, type Locale } from "./i18n/core.ts";

// Source-audit coverage reasons are stored in English with the count already
// filled in. Reconstruct only these product-authored templates for translation.
const sentences = [
  { suffix: " unit remains.", en: "{count} unit remains.", zhTW: "尚有 {count} 個單元未完成。" },
  { suffix: " units remain.", en: "{count} units remain.", zhTW: "尚有 {count} 個單元未完成。" },
  { suffix: " unit is outside the audit scope.", en: "{count} unit is outside the audit scope.", zhTW: "有 {count} 個單元不在稽核範圍內。" },
  { suffix: " units are outside the audit scope.", en: "{count} units are outside the audit scope.", zhTW: "有 {count} 個單元不在稽核範圍內。" },
] as const;

export const sourceAuditCoverageText = (locale: Locale, english: string): string | undefined => {
  for (const { suffix, ...copy } of sentences) {
    if (!english.endsWith(suffix)) continue;
    const count = english.slice(0, -suffix.length);
    if (/^\d+$/u.test(count)) return translateBilingualText(locale, copy, { count });
  }
  return undefined;
};
