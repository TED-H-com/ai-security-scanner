// Download availability comes from this exact public release, never /latest.
const labels = {
  en: { loading: 'Checking published downloads…', pending: 'Downloads will appear here when this release is published.', unavailable: 'No published installer for this platform yet.', failed: 'Open the release page to check downloads.', download: 'Download', published: 'Published downloads', notes: 'Release notes and checksums' },
  'zh-TW': { loading: '正在確認已發布的下載檔案…', pending: '此版本發布後，這裡會顯示下載檔案。', unavailable: '此平台尚無已發布的安裝程式。', failed: '請開啟發布頁確認下載檔案。', download: '下載', published: '已發布的下載檔案', notes: '發布說明與校驗碼' },
  ja: { loading: '公開済みのファイルを確認中…', pending: 'リリース公開後にダウンロードが表示されます。', unavailable: 'このプラットフォームのインストーラーはまだ公開されていません。', failed: 'リリースページでダウンロードを確認してください。', download: 'ダウンロード', published: '公開済みのダウンロード', notes: 'リリースノートとチェックサム' },
};

export function publishedInstallers(release, pack) {
  if (release.tag_name !== pack.release_tag || release.draft || !release.published_at) return [];
  return (release.assets ?? []).filter(asset => {
    if (asset.state !== 'uploaded' || !(asset.size > 0)) return false;
    let url;
    try { url = new URL(asset.browser_download_url); } catch { return false; }
    const prefix = `https://github.com/${pack.repository}/releases/download/${pack.release_tag}/`;
    if (!url.href.startsWith(prefix) || url.username || url.password || url.search || url.hash) return false;
    const version = pack.app_version.replaceAll('.', '\\.');
    return new RegExp(`^ai-security-scanner_${version}_(?:universal\\.dmg|x64-setup\\.exe|x64_en-US\\.msi|amd64\\.deb|amd64\\.rpm|amd64\\.AppImage)$`).test(asset.name)
      && decodeURIComponent(url.pathname.split('/').pop()) === asset.name;
  });
}

let state = 'loading';
let installers = [];
const render = () => {
  const copy = labels[document.documentElement.dataset.lang] ?? labels.en;
  document.querySelector('[data-release-status]').textContent = copy[state];
  for (const platform of ['macos', 'windows', 'linux']) {
    const container = document.querySelector(`[data-downloads="${platform}"]`);
    container.replaceChildren();
    const assets = installers.filter(asset => platform === 'macos' ? asset.name.endsWith('.dmg')
      : platform === 'windows' ? /\.(exe|msi)$/.test(asset.name) : /\.(deb|rpm|AppImage)$/.test(asset.name));
    if (!assets.length) { container.textContent = copy.unavailable; continue; }
    for (const asset of assets) {
      const link = document.createElement('a');
      link.className = 'button button-secondary';
      link.href = asset.browser_download_url;
      link.textContent = `${copy.download} .${asset.name.split('.').pop()}`;
      container.append(link);
    }
  }
};

if (typeof document !== 'undefined') {
  document.addEventListener('site-language-change', render);
  render();
  try {
    const packResponse = await fetch('incident-pack.json');
    if (!packResponse.ok) throw new Error('Pack unavailable');
    const pack = await packResponse.json();
    const response = await fetch(`https://api.github.com/repos/${pack.repository}/releases/tags/${pack.release_tag}`, {
      headers: { Accept: 'application/vnd.github+json' }, credentials: 'omit',
    });
    if (response.status === 404) state = 'pending';
    else {
      if (!response.ok) throw new Error('Release unavailable');
      installers = publishedInstallers(await response.json(), pack);
      state = installers.length ? 'published' : 'pending';
    }
  } catch { state = 'failed'; }
  render();
}
