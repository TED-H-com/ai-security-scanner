# 標準報告範例 · v0.4.0

[English](README.md) · [在網站閱讀](https://ted-h-com.github.io/ai-security-scanner/sample-reports.html?lang=zh-TW)

公開快照：**2026 年 10 月 4 日**，產品 **v0.4.0**。提供兩種揭露程度，各有英文與繁體中文。皆為獨立 HTML，可在瀏覽器閱讀、儲存或列印。

| 版本 | 繁體中文 | English |
| --- | --- | --- |
| 遮蔽版 | [閱讀](https://ted-h-com.github.io/ai-security-scanner/samples/v0.4.0/sample-report-redacted-zh-TW.html) · [從 GitHub 下載](https://raw.githubusercontent.com/TED-H-com/ai-security-scanner/main/docs/samples/v0.4.0/sample-report-redacted-zh-TW.html) | [閱讀](https://ted-h-com.github.io/ai-security-scanner/samples/v0.4.0/sample-report-redacted-en.html) · [從 GitHub 下載](https://raw.githubusercontent.com/TED-H-com/ai-security-scanner/main/docs/samples/v0.4.0/sample-report-redacted-en.html) |
| 完整揭露版 | [閱讀](https://ted-h-com.github.io/ai-security-scanner/samples/v0.4.0/sample-report-full-zh-TW.html) · [從 GitHub 下載](https://raw.githubusercontent.com/TED-H-com/ai-security-scanner/main/docs/samples/v0.4.0/sample-report-full-zh-TW.html) | [閱讀](https://ted-h-com.github.io/ai-security-scanner/samples/v0.4.0/sample-report-full-en.html) · [從 GitHub 下載](https://raw.githubusercontent.com/TED-H-com/ai-security-scanner/main/docs/samples/v0.4.0/sample-report-full-en.html) |

全部 **25 個 adapter** 都有可見結果：**62 筆原始發現及 42 筆盤點觀察**。標準報告將相關發現整理為 56 張問題卡。CloudQuery、Steampipe、Naabu、httpx、Syft 與 Agentic Radar 僅提供盤點。範例也包含未完整完成的檢查，保留其他已完成結果，不把盤點當成漏洞，也不宣稱全部通過。

情境與身分資料均為模擬。輸入採用 adapter 實際支援的上游結構：JSON、JSONL／NDJSON 及 Greenbone XML。部分是縮減的代表性資料，部分來自受控原生執行。ScubaGear 與 Maester 使用整合層包裝的原生判定；MCP Armor 與 Agentic Radar 採用已記錄的輸出修改。這**不代表 25 個即時掃描器曾對真實組織執行**。產生報告時未使用客戶資料或憑證，也未連接即時目標。

遮蔽版使用產品的 `standard` 遮蔽設定；完整揭露版使用 `none`，保留虛構資產名稱、端點與帳號背景。兩版都保留 adapter 原有的機密值隱藏機制，不包含原始紀錄；發現、優先順序、來源與涵蓋範圍相同。完整揭露不會還原匯出前已過濾的機密資料。

## 產製方式

1. [全引擎驗證](../../../src-tauri/tests/all_engine_report_audit.rs) 透過模擬執行層提供上游格式輸入，實際使用正式 adapter、範圍規劃、協調、儲存與結束狀態報告模型。合成資產／授權 ID 及保留範例主機名稱，將輸入資料綁定到範例情境。
2. [公開範例產生器](../../../src-tauri/tests/support/public_sample_reports.rs) 將儲存案件標記為 demo、設定虛構組織，並呼叫 `CaseService.export_case` 產生兩種遮蔽設定與兩種語言。每個可派送 adapter 都必須有發現或盤點觀察，也檢查識別欄位遮蔽與機密值隱藏。
3. [網站產製程式](../../../scripts/build-public-showcase.mjs) 加入可見的範例標記及掃描器來源／用途附錄。**標準報告本文維持逐位元組相同。** `standardExportSha256` 是原始匯出雜湊，`sha256` 是下載版雜湊。移除三個 `public-sample` 註解界定的附加區塊，即可還原原始雜湊。範例專用附錄不宣稱是已安裝 v0.4.0 匯出器的功能。
4. [manifest.json](manifest.json) 記錄各掃描器結果數、輸入範例路徑與雜湊、版本及各檔案雜湊。[SHA256SUMS.txt](SHA256SUMS.txt) 用於驗證四份下載。輸入範例雜湊對應情境替換前的範本，報告內證據雜湊對應替換後的實際輸入位元組。範例中的執行時間與環境紀錄為模擬，不是即時掃描證據。

報告實作與引擎目錄來自 [v0.4.0 原始碼快照](https://github.com/TED-H-com/ai-security-scanner/tree/335d0666bdc63eb86e6c8c4cddeae110db893397)。公開產生器及呈現附加內容在本儲存庫維護。[掃描器指南](../../scanner-guide.zh-TW.md) 記錄全部工具的來源日期、啟用功能、排除項目、選用原因與 SWOT。

## 重現及更新

從儲存庫根目錄執行，選擇新的空白本機輸出目錄。不需要容器、帳號登入或網路掃描：

```bash
AI_SCANNER_PUBLIC_SAMPLE_DIR=/absolute/path/to/new-empty-directory \
  cargo test -j 4 -p ai-security-scanner --no-default-features --features cli \
  --test all_engine_report_audit public_sample_reports::generate_public_sample_reports \
  -- --ignored --exact --test-threads=4
node scripts/build-public-showcase.mjs --samples /absolute/path/to/new-empty-directory
node scripts/build-public-showcase.mjs --check
node --experimental-strip-types --test tests/frontend/publicShowcase.test.ts
```

新案件會有新的 ID 及時間，因此重新產生可重現相同語意，但不保證位元組相同。要從已提交輸入重建目前公開快照及指南，可執行不帶 `--samples` 的 `node scripts/build-public-showcase.mjs`；它會先驗證保留的標準匯出雜湊，再重新加入範例附加內容。

文字在 `docs/scanner-guide.content.json` 修改，經檢視的官方來源與目錄資料在 `docs/scanner-guide.sources.json` 修改，之後重新產生。來源提交日期來自官方儲存庫提交中繼資料，README 連結指向確切提交。不要把來源提交日稱為上游發布日，也不要把目錄基準日當成每份資料庫的日期。修改啟用功能說明前，重新核對對應 `docs/engines/<id>.md` 及實際啟動器設定，中英文一起更新。

下一個產品版本應保留這份有日期的目錄，另建版本快照，對齊目錄、輸入範例、來源日期及產生器輸入。重新檢查格式、結果類型、遮蔽或完成語意有變更的 adapter。發布前後檢查桌面與手機排版、全部下載雜湊及網站。更新公開範例不代表核准發布新引擎映像或安裝程式。
