// Resolve before paint. An explicit URL wins over a saved choice and browser preferences.
(() => {
  const normalize = value => {
    const language = value?.toLowerCase().replaceAll('_', '-');
    if (/^ja(?:-|$)/.test(language)) return 'ja';
    if (/^zh(?:-|$)/.test(language)) return 'zh-TW';
    if (/^en(?:-|$)/.test(language)) return 'en';
  };
  let saved;
  try { saved = localStorage.getItem('ai-security-scanner.site-language'); } catch { /* Storage is optional. */ }
  const requested = new URLSearchParams(location.search).get('lang');
  const selected = normalize(requested) || normalize(saved)
    || navigator.languages?.map(normalize).find(Boolean) || 'en';
  document.documentElement.dataset.lang = selected;
  document.documentElement.lang = selected === 'zh-TW' ? 'zh-Hant' : selected;
})();
