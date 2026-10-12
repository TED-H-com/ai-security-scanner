const entries = [...document.querySelectorAll('.scanner-entry')];
const search = document.querySelector('#scanner-search');
const category = document.querySelector('#scanner-category');
const count = document.querySelector('#scanner-count');
const searchable = new Map(entries.map(entry => [entry, entry.textContent.toLocaleLowerCase()]));
function filterScanners() {
  const query = search.value.trim().toLocaleLowerCase();
  let visible = 0;
  for (const entry of entries) {
    entry.hidden = (category.value !== 'all' && entry.dataset.category !== category.value) || !searchable.get(entry).includes(query);
    if (!entry.hidden) visible++;
  }
  for (const group of document.querySelectorAll('[data-group]')) group.hidden = ![...group.querySelectorAll('.scanner-entry')].some(entry => !entry.hidden);
  const chinese = document.documentElement.dataset.lang === 'zh-TW';
  const japanese = document.documentElement.dataset.lang === 'ja';
  count.textContent = chinese ? `${visible} / ${entries.length} 個掃描器` : japanese ? `${visible} / ${entries.length} 件のスキャナー` : `${visible} / ${entries.length} scanners`;
  for (const option of category.options) option.textContent = chinese ? option.dataset.labelZh : japanese ? option.dataset.labelJa : option.dataset.labelEn;
  document.querySelector('#scanner-empty').hidden = visible !== 0;
}
function revealLinkedScanner() {
  let id;
  try { id = decodeURIComponent(location.hash.slice(1)); } catch { return; }
  const entry = entries.find(item => item.id === id);
  if (!entry) return;
  search.value = ''; category.value = 'all'; filterScanners();
  entry.open = true;
  requestAnimationFrame(() => entry.scrollIntoView({ block: 'start' }));
}
search.addEventListener('input', filterScanners);
category.addEventListener('change', filterScanners);
document.addEventListener('site-language-change', filterScanners);
window.addEventListener('hashchange', revealLinkedScanner);
document.querySelector('.scanner-filter').hidden = false;
filterScanners();
revealLinkedScanner();
