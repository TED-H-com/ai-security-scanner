# 開發狀態

[English](development-status.md) · [文件](README.zh-TW.md)

更新：2026-10-12。[產品規格](product-spec.md)定義現行產品行為；本頁記錄工程現況與已觀察的限制。

## 現況

- [v0.5.1 日文支援](release/v0.5.1.zh-TW.md)已發布為目前 stable／latest，提供 Windows、macOS 與 Linux 安裝版。納入日文介面、README、網站與初次使用流程補譯；公開檔案、更新簽章、精確來源 CI 及 CodeQL 均驗證通過，平台觀察與限制見發布紀錄。

- 先前的 [v0.4.1 正式版](release/v0.4.1.zh-TW.md)保留原始安裝檔、更新目標與平台觀察紀錄。
- 程式包含可選的 ZAP、Agentic Radar 與 Garak；並保留 Prowler 實際失敗標題、核准的 AWS 發現合併、重新連接再掃描、受阻的繼續操作修正、Semgrep `1.174.0-4` 合併規則包，以及 kube-bench／KICS 的未完成涵蓋範圍揭露。
- 引擎目錄共 25 個紀錄，25 個均可執行；Agentic Radar 提供離線工作流程盤點，Garak 則以精確端點／模型、明確授權與一次性本機金鑰進行可選檢查。
- 主要路徑可合併專案資料夾、網站及已獲准內部系統；另有單一網站與單一專案捷徑。結果依資產整理，個別工具失敗不會抹除其他已完成發現。
- v0.4.0 的共用 HTML 匯出已將寬表格限制在自己的捲動區域，平板尺寸採單欄，長技術識別字串可換行。v0.3.1 的原始交付觀察仍保留在該版歷史紀錄中。
- v0.4.0 也已修正 Microsoft 365 身分資產的平台標記，辨識後端的 `microsoft365` 值，避免誤列為公開網站與 IP 位址；擁有者重新登入的最新實測仍未觀察。
- Microsoft 365 已更新 setup、四項 PIM 讀取權限與固定的 ScubaGear／Maester 映像檔；仍待擁有者登入後重新實測。
- MCP Armor 可執行已核准 MCP 設定快照的靜態檢查，預設不啟用；不啟動 MCP 伺服器、不載入模型。
- Augustus 仍是研究用資料契約，沒有 production 引擎、派送或授權路徑。開發期間沒有連線擁有者或 hosted 模型服務；Garak 原生 QA 使用自建 TLS fixture。

**v0.4.1 正式版**新增中英文 HTML 原始報告 ZIP 附件，改善結果說明、臨時憑證建立失敗時的清理，並提供依紀錄收尾的 AWS／Microsoft 365 存取清理輔助程式。精確交付與限制見[發布紀錄](release/v0.4.1.zh-TW.md)。

**v0.4.0 正式版**已完成擁有者選定的結果完整性、引擎建置／修補維護與可選功能整合。本版修正將 Greenbone 按確切授權分成獨立工作，保存重試所需的授權成員；Kubescape 的缺漏或未評估資料會揭露涵蓋缺口；大型報告則在 512 MiB 證據限制內串流處理。這些改動已包含於 v0.4.0。Gitleaks 新映像與所有建置／修補輸入稽核已完成。ZAP 已接通進階網站選項、確切授權派送、每秒 5 次的上游請求限速與計畫保存；Agentic Radar 已完成五種框架、空專案與 `.env` 隔離的原生靜態盤點測試；CrewAI 的五項診斷保留為未完成盤點。框架選擇、雙平台公開映像與來源簽章已驗證，並以公開 amd64 映像複驗全部七個案例；Garak 已完成精確 HTTPS／模型輸入、一次性本機金鑰、固定原生探針與六種受控 TLS 測試，公開雙平台位元組、來源簽章與 SBOM 已獨立驗證，六種 TLS 案例亦以公開 amd64 digest 複驗通過；v0.4.0 已正式發布；精確來源、凍結檔案、平台觀察與匿名下載驗證，見[本版交付紀錄](release/v0.4.0.zh-TW.md)。

## 已記錄的驗證

10 月 4 日 Garak admission 與 v0.4.0 來源檢查：2,114 項 Rust、527 項 component、91 項 CI 合約、203 項發布合約通過；以保存的測試資料稽核 25 個工具的報告路徑，精確模型資訊及原生次數可保存、重開與中英文匯出。功能來源的前端 CI 通過 806 項，沒有 skip；最後文案修正的來源 CI 亦另行通過。公開雙平台位元組、來源／SBOM 簽章、六種 amd64 原生 TLS 案例、Formatting、Clippy 與 production build 亦已驗證；安裝包交付另行記錄。

10 月 4 日 ZAP 整合：2,092 項 Rust、798 項前端（六項明確 skip）、518 項 component、Formatting、Clippy 與 production build 通過。受控的原生 amd64 掃描驗證固定主機名稱解析、來源邊界、持續連線下的請求限速與取消；報告測試保留所有原生警示實例。這是現行原始碼與受控資料的驗證，安裝包的獨立驗證見本版交付紀錄。

10 月 3 日來源準備檢查：2,072 項 Rust、798 項前端（六項明確 skip）、515 項 component、89 項 CI 合約與 202 項發布合約通過。Formatting、Clippy、production build、引擎 admission 與 release identity 亦通過。v0.3.1 準備另通過完整打包自測及三項 gateway 身分／安全測試。

以上是來源測試；安裝、實際掃描、保存與重新開啟的觀察，請見[本版交付紀錄](release/v0.4.0.zh-TW.md)。歷史測試數量保存在[英文工程紀錄](development-status.md#recorded-verification-baseline)，不會當作本版新測試宣稱。

## 維護入口

- [引擎參考](engines/README.zh-TW.md)與[全部映像檔建置更新筆記](engines/image-build-index.md)
- [發布流程](releasing.zh-TW.md)與[本版發布紀錄](release/v0.4.0.zh-TW.md)
- [現行產品檢視](product-audit.md)與[掃描範圍](scanning-scope.zh-TW.md)

掃描只使用明確授權範圍；憑證不透過聊天或指令參數傳遞。版本、發布、簽章與包裝由產品負責人決定。

CI 文件與合約測試：91 項，新增既有映像與新建置候選分開記錄，以及禁止把可執行輸入藏在發布歷史中的檢查。引擎維護已補齊原先缺漏的實際檔案雜湊、六類下游修改的例外紀錄，並驗證全新 Gitleaks amd64 建置與遮蔽秘密值的合成掃描；新版 Gitleaks `8.30.1-2` 已發布，雙架構來源／SBOM 證據與匿名下載驗證通過，catalog 已固定使用新映像。

CI 文件與合約測試：97 項，包含上游更新候選的中繼資料檢查。10 月 14 日的原始碼更新保留既有已發布 catalog，另外驗證新版建置；候選資料不能變更掃描權限或隱藏可執行的建置輸入。版本與驗證詳見[上游更新紀錄](engines/updates/2026-10-14.md)。

CI 文件與合約測試：102 項，新增拒絕被替換的 Windows 執行環境來源、修補檔、工具鏈，以及不可重現建置設定的檢查。[Windows 執行環境來源紀錄（英文）](../runtime/podman-wsl-native-systemd.md)說明原生 systemd 回移修補與固定的建置輸入。
