import { ja } from "./locales/ja.ts";
import { jaInline } from "./locales/ja-inline.ts";
import { en } from "./locales/en.ts";
import { zhTW } from "./locales/zh-TW.ts";

export const supportedLocales = ["en", "zh-TW", "ja"] as const;
export type Locale = (typeof supportedLocales)[number];
export type TranslationKey = keyof typeof en;
export type InterpolationValue = string | number;

export interface BilingualText<English extends string = string, Chinese extends string = string> {
  en: English;
  zhTW: Chinese;
}

type ParameterNames<Message extends string> =
  Message extends `${string}{${infer Parameter}}${infer Rest}`
    ? Parameter | ParameterNames<Rest>
    : never;

export type InterpolationParameters<Message extends string> = {
  [Parameter in ParameterNames<Message>]: InterpolationValue;
};

type HasMatchingParameters<Copy extends BilingualText> =
  [ParameterNames<Copy["en"]>] extends [ParameterNames<Copy["zhTW"]>]
    ? [ParameterNames<Copy["zhTW"]>] extends [ParameterNames<Copy["en"]>]
      ? unknown
      : never
    : never;

export type TranslationArguments<Key extends TranslationKey> =
  [ParameterNames<(typeof en)[Key]>] extends [never]
    ? []
    : [parameters: InterpolationParameters<(typeof en)[Key]>];

export type StaticTranslationKey = {
  [Key in TranslationKey]: [ParameterNames<(typeof en)[Key]>] extends [never] ? Key : never;
}[TranslationKey];

export type BilingualTextArguments<Copy extends BilingualText> =
  [HasMatchingParameters<Copy>] extends [never]
    ? [invalidPlaceholderNames: never]
    : [ParameterNames<Copy["en"]>] extends [never]
      ? []
      : [parameters: InterpolationParameters<Copy["en"]>];

export type Translator = <Key extends TranslationKey>(
  key: Key,
  ...arguments_: TranslationArguments<Key>
) => string;

export type BilingualTextTranslator = <const Copy extends BilingualText>(
  copy: Copy,
  ...arguments_: BilingualTextArguments<Copy>
) => string;

export const localeStorageKey = "ai-security-scanner.locale";

const translations: Record<Locale, Record<TranslationKey, string>> = {
  en,
  "zh-TW": zhTW,
  ja,
};

let activeLocale: Locale = "zh-TW";

export const isLocale = (value: unknown): value is Locale =>
  typeof value === "string" && supportedLocales.includes(value as Locale);

export const normalizeLocale = (value: string | undefined | null): Locale | undefined => {
  if (!value) return undefined;
  const normalized = value.trim().replaceAll("_", "-").toLowerCase();
  if (normalized === "en" || normalized.startsWith("en-")) return "en";
  if (normalized === "ja" || normalized.startsWith("ja-")) return "ja";
  if (normalized === "zh" || normalized.startsWith("zh-")) return "zh-TW";
  return undefined;
};

export const detectPreferredLocale = (languages: readonly string[] | undefined): Locale => {
  for (const language of languages ?? []) {
    const locale = normalizeLocale(language);
    if (locale) return locale;
  }
  return "en";
};

export const resolveLocalePreference = (
  storedLocale: string | undefined | null,
  browserLanguages: readonly string[] | undefined,
): Locale => normalizeLocale(storedLocale) ?? detectPreferredLocale(browserLanguages);

export interface LocaleStorage {
  getItem: (key: string) => string | null;
  setItem: (key: string, value: string) => void;
}

export interface LocaleDocument {
  documentElement: { lang: string };
}

export const readLocalePreference = (
  storage: LocaleStorage,
  browserLanguages: readonly string[] | undefined,
): Locale => {
  try {
    return resolveLocalePreference(storage.getItem(localeStorageKey), browserLanguages);
  } catch {
    return detectPreferredLocale(browserLanguages);
  }
};

export const persistLocalePreference = (storage: LocaleStorage, locale: Locale): boolean => {
  try {
    storage.setItem(localeStorageKey, locale);
    return true;
  } catch {
    return false;
  }
};

export const applyDocumentLocale = (document: LocaleDocument, locale: Locale): void => {
  document.documentElement.lang = locale;
};

export const getActiveLocale = (): Locale => activeLocale;

export const setActiveLocale = (locale: Locale): void => {
  activeLocale = locale;
};

/** Missing Japanese UI copy falls back to English, including inherited property names. */
export const japaneseText = (english: string): string =>
  Object.hasOwn(jaInline, english) ? jaInline[english]! : english;

/** Translate nested, language-specific UI objects without changing technical keys. */
export const localizeJapanese = <T>(value: T): T => {
  if (typeof value === "string") return japaneseText(value) as T;
  if (Array.isArray(value)) return value.map(localizeJapanese) as T;
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([key, entry]) =>
      [key, localizeJapanese(entry)])) as T;
  }
  return value;
};

const interpolate = (message: string, parameters?: Record<string, InterpolationValue>): string =>
  message.replace(/\{([A-Za-z][A-Za-z0-9_]*)\}/gu, (placeholder, name: string) => {
    const value = parameters?.[name];
    return value === undefined ? placeholder : String(value);
  });

export const translate = <Key extends TranslationKey>(
  locale: Locale,
  key: Key,
  ...arguments_: TranslationArguments<Key>
): string => interpolate(translations[locale][key], arguments_[0]);

export const translateActive = <Key extends TranslationKey>(
  key: Key,
  ...arguments_: TranslationArguments<Key>
): string => translate(activeLocale, key, ...arguments_);

export const translateStatic = (locale: Locale, key: StaticTranslationKey): string =>
  translations[locale][key];

export const translateActiveStatic = (key: StaticTranslationKey): string =>
  translateStatic(activeLocale, key);

export const translateBilingualText = <const Copy extends BilingualText>(
  locale: Locale,
  copy: Copy,
  ...arguments_: BilingualTextArguments<Copy>
): string => interpolate(locale === "zh-TW" ? copy.zhTW : locale === "ja" ? japaneseText(copy.en) : copy.en, arguments_[0]);

const asDate = (value: Date | string | number): Date | undefined => {
  const date = value instanceof Date ? value : new Date(value);
  return Number.isNaN(date.getTime()) ? undefined : date;
};

export const formatLocaleNumber = (
  locale: Locale,
  value: number,
  options?: Intl.NumberFormatOptions,
): string => new Intl.NumberFormat(locale, options).format(value);

export const formatLocaleDate = (
  locale: Locale,
  value: Date | string | number,
  options?: Intl.DateTimeFormatOptions,
): string => {
  const date = asDate(value);
  if (!date) return String(value);
  return new Intl.DateTimeFormat(locale, options ?? {
    year: "numeric",
    month: "short",
    day: "numeric",
  }).format(date);
};

export const formatLocaleDateTime = (
  locale: Locale,
  value: Date | string | number,
  options?: Intl.DateTimeFormatOptions,
): string => {
  const date = asDate(value);
  if (!date) return String(value);
  return new Intl.DateTimeFormat(locale, options ?? {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  }).format(date);
};

export const messageKeys = Object.freeze(Object.keys(en) as TranslationKey[]);

export const localeMessages = translations;

export type RuntimeIssue = "wsl" | "virtualization" | "permission" | "network" | "storage" | "generic";

export const classifyRuntimeIssue = (...values: Array<string | undefined>): RuntimeIssue => {
  const value = values.filter(Boolean).join(" ").toLowerCase();
  if (/\bwsl(?:\.exe)?\b|windows subsystem for linux|linux subsystem/u.test(value)) return "wsl";
  if (/virtuali[sz]ation|virtual machine platform|hyper-v|hardware acceleration|vm support/u.test(value)) {
    return "virtualization";
  }
  if (/access denied|permission|not permitted|administrator|elevation|privilege/u.test(value)) return "permission";
  if (/network|download|timed? out|timeout|dns|certificate|\btls\b|connection/u.test(value)) return "network";
  if (/disk|no space|storage|volume.*full/u.test(value)) return "storage";
  return "generic";
};
