import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";

import {
  applyDocumentLocale,
  detectPreferredLocale,
  formatLocaleDate,
  formatLocaleDateTime,
  formatLocaleNumber,
  persistLocalePreference,
  readLocalePreference,
  setActiveLocale,
  supportedLocales,
  translate,
  translateBilingualText,
  type BilingualTextTranslator,
  type Locale,
  type Translator,
} from "./core";

export * from "./core";

export interface I18nContextValue {
  locale: Locale;
  setLocale: (locale: Locale) => void;
  toggleLocale: () => void;
  t: Translator;
  text: BilingualTextTranslator;
  formatNumber: (value: number, options?: Intl.NumberFormatOptions) => string;
  formatDate: (value: Date | string | number, options?: Intl.DateTimeFormatOptions) => string;
  formatDateTime: (value: Date | string | number, options?: Intl.DateTimeFormatOptions) => string;
}

const I18nContext = createContext<I18nContextValue | undefined>(undefined);

const readInitialLocale = (): Locale => {
  if (typeof window === "undefined") return "zh-TW";
  try {
    return readLocalePreference(window.localStorage, window.navigator.languages);
  } catch {
    // Privacy modes can disable storage. Browser language remains a safe fallback.
  }
  return detectPreferredLocale(window.navigator.languages);
};

export function I18nProvider({ children }: { children: ReactNode }) {
  const [locale, setLocaleState] = useState<Locale>(readInitialLocale);
  setActiveLocale(locale);

  const setLocale = useCallback((nextLocale: Locale) => setLocaleState(nextLocale), []);
  const toggleLocale = useCallback(
    () => setLocaleState((current) => supportedLocales[(supportedLocales.indexOf(current) + 1) % supportedLocales.length]!),
    [],
  );

  useEffect(() => {
    applyDocumentLocale(document, locale);
    document.querySelector<HTMLMetaElement>('meta[name="description"]')?.setAttribute(
      "content",
      locale === "en"
        ? "Find security issues across websites, cloud, code, and internal systems—from one simple local app."
        : locale === "ja"
          ? "シンプルなローカルアプリで、ウェブサイト、クラウド、コード、社内システムのセキュリティ問題を確認できます。"
          : "用一個簡單的本機工具，掃描網站、雲端、程式碼與內部系統的資安問題。",
    );
    persistLocalePreference(window.localStorage, locale);
  }, [locale]);

  const value = useMemo<I18nContextValue>(() => {
    const t: Translator = (key, ...arguments_) => translate(locale, key, ...arguments_);
    const text: BilingualTextTranslator = (copy, ...arguments_) =>
      translateBilingualText(locale, copy, ...arguments_);
    const formatNumber = (number: number, options?: Intl.NumberFormatOptions) =>
      formatLocaleNumber(locale, number, options);
    const formatDate = (input: Date | string | number, options?: Intl.DateTimeFormatOptions) =>
      formatLocaleDate(locale, input, options);
    const formatDateTime = (input: Date | string | number, options?: Intl.DateTimeFormatOptions) =>
      formatLocaleDateTime(locale, input, options);
    return { locale, setLocale, toggleLocale, t, text, formatNumber, formatDate, formatDateTime };
  }, [locale, setLocale, toggleLocale]);

  return <I18nContext.Provider value={value}>{children}</I18nContext.Provider>;
}

export const useI18n = (): I18nContextValue => {
  const value = useContext(I18nContext);
  if (!value) throw new Error("useI18n must be used inside I18nProvider");
  return value;
};
