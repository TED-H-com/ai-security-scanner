import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, expect, test } from "vitest";
import { I18nProvider, useI18n } from "../../src/i18n";
import { SettingsPage } from "../../src/pages/SettingsPage";
import { StartPage } from "../../src/pages/StartPage";
import { startPageCopy } from "../../src/useCases";

function SettingsHarness() {
  const { locale, setLocale } = useI18n();
  return <SettingsPage locale={locale} mode="native" runtimeAvailable onLocaleChange={setLocale}
    onOpenNewScan={() => {}} onOpenProjects={() => {}} />;
}

afterEach(() => { cleanup(); window.localStorage.clear(); });

test("Japanese is selectable alongside both original languages and persists after remount", () => {
  window.localStorage.setItem("ai-security-scanner.locale", "en");
  const view = render(<I18nProvider><SettingsHarness /></I18nProvider>);
  fireEvent.click(screen.getByRole("button", { name: "日本語" }));
  expect(screen.getByRole("button", { name: "日本語" }).getAttribute("aria-pressed")).toBe("true");
  expect(screen.getByRole("heading", { name: "言語" })).toBeTruthy();
  expect(document.documentElement.lang).toBe("ja");
  expect(window.localStorage.getItem("ai-security-scanner.locale")).toBe("ja");
  view.unmount();
  render(<I18nProvider><SettingsHarness /></I18nProvider>);
  expect(screen.getByRole("button", { name: "日本語" }).getAttribute("aria-pressed")).toBe("true");
  fireEvent.click(screen.getByRole("button", { name: "繁體中文" }));
  expect(screen.getByRole("heading", { name: "語言" })).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: "English" }));
  expect(screen.getByRole("heading", { name: "Language" })).toBeTruthy();
});

test("Japanese start page has a complete locale object without falling into Chinese copy", () => {
  const view = render(<StartPage locale="ja" copy={startPageCopy.ja} nativeMode
    onStartLocalhostQuickScan={() => {}} onChoose={() => {}} />);
  expect(screen.getByRole("heading", { name: "セキュリティチェック" })).toBeTruthy();
  expect(screen.getByRole("button", { name: "自分の環境をスキャン" })).toBeTruthy();
  expect(screen.getByRole("button", { name: "ウェブサイトをチェック" })).toBeTruthy();
  expect(screen.getByRole("button", { name: "コード・AI プロジェクトをチェック" })).toBeTruthy();
  expect(view.container.textContent).not.toContain("Security checks");
  expect(view.container.textContent).not.toContain("資安檢查");
});
