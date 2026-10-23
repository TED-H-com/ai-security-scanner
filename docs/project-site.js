const languageButtons = document.querySelectorAll("[data-language]");
const description = document.querySelector('meta[name="description"]');

const pageCopy = {
  en: {
    title: "ai-security-scanner · Find security problems. Know what to do next.",
    description: "Check your code, websites and company systems from one desktop app. Read a clear report with priorities and next steps. Available for Windows, macOS and Linux.",
  },
  "zh-TW": {
    title: "ai-security-scanner · 找出安全問題，知道下一步",
    description: "在一個桌面程式裡檢查程式碼、網站與公司系統。看一份報告，了解問題、處理順序與下一步。支援 Windows、macOS 與 Linux。",
  },
  ja: {
    title: "ai-security-scanner · セキュリティの問題と、次にすることがわかる。",
    description: "コード、ウェブサイト、社内システムを 1 つのデスクトップアプリでチェック。対応の優先順位と次の手順を、わかりやすいレポートで確認できます。Windows・macOS・Linux に対応。",
  },
};

const applyLanguage = (language, updateUrl = true) => {
  const selected = Object.hasOwn(pageCopy, language) ? language : "en";
  document.documentElement.dataset.lang = selected;
  document.documentElement.lang = selected === "zh-TW" ? "zh-Hant" : selected;
  const titleElement = document.querySelector("title");
  const key = selected === "zh-TW" ? "zh" : selected;
  const title = titleElement?.dataset[key] || pageCopy[selected].title;
  const summary = description?.dataset[key] || pageCopy[selected].description;
  document.title = title;
  description?.setAttribute("content", summary);
  document.querySelector('meta[property="og:title"]')?.setAttribute("content", title);
  document.querySelector('meta[property="og:description"]')?.setAttribute("content", summary);
  document.querySelector('meta[property="og:locale"]')?.setAttribute("content", { en: "en_US", "zh-TW": "zh_TW", ja: "ja_JP" }[selected]);
  for (const link of document.querySelectorAll("a[data-href-en][data-href-zh]")) {
    const url = new URL(selected === "zh-TW" ? link.dataset.hrefZh : link.dataset.hrefEn, window.location.href);
    const page = url.pathname.split('/').pop();
    if (url.origin === location.origin && ['index.html', 'scanner-guide.html', 'sample-reports.html', 'check-fixes-demo.html', 'incident-october-21.html'].includes(page)) {
      url.searchParams.set('lang', selected);
    }
    link.href = selected === 'ja' && link.dataset.hrefJa ? link.dataset.hrefJa : url.href;
  }
  for (const element of document.querySelectorAll('[data-aria-label-en], [data-alt-en]')) {
    for (const attribute of ['aria-label', 'alt']) {
      const value = element.getAttribute(`data-${attribute}-${key}`) || element.getAttribute(`data-${attribute}-en`);
      if (value) element.setAttribute(attribute, value);
    }
  }

  for (const button of languageButtons) {
    button.setAttribute("aria-pressed", String(button.dataset.language === selected));
  }

  document.dispatchEvent(new Event("site-language-change"));

  if (updateUrl) {
    const url = new URL(window.location.href);
    url.searchParams.set("lang", selected);
    window.history.replaceState({}, "", url);
    try { localStorage.setItem('ai-security-scanner.site-language', selected); } catch { /* Storage is optional. */ }
  }
};

for (const button of languageButtons) {
  button.addEventListener("click", () => applyLanguage(button.dataset.language));
}

applyLanguage(document.documentElement.dataset.lang, false);
