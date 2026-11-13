# 文件

[專案網站](https://ted-h-com.github.io/ai-security-scanner/?lang=zh-TW) · [English](README.md)

**最新發布版本仍是 Linux、macOS、Windows 的 v0.6.2 桌面版**，也是初學者的預設入口。公開的操作 skill 協助安裝應用程式、確認準備狀態、引導在視窗中掃描及保存報告。

## 使用產品

- [發布內容與新版定義](release-model.zh-TW.md)：已發布桌面版與操作 skill、尚未發布的開發功能，以及 skill 預覽／正式版建議。
- [開始使用](getting-started.zh-TW.md)：安裝 Linux、macOS 或 Windows 的 v0.6.2 桌面程式並完成第一次掃描。
- [Agent Skills](getting-started.zh-TW.md#透過-agent-skill-使用)：在同一台電腦上透過 Claude Code 或 Codex 確認能否掃描、引導在應用程式中掃描，並保存最終報告。
- [掃描範圍](scanning-scope.zh-TW.md)：精確目標界線、掃描設定與引擎行為。
- [結果與匯出](results-and-exports.zh-TW.md)：閱讀優先順序、涵蓋範圍、證據與保存報告。
- [v0.6.2 發布紀錄](release/v0.6.2.md#繁體中文)：本版更新、實際交付證據與尚未觀察的平台項目。

- [標準報告範例](samples/v0.4.0/README.zh-TW.md)：遮蔽／完整揭露版，中英皆有；25 個 adapter、真實格式、模擬資料。
- [修正後再檢查一次](demos/check-fixes/README.zh-TW.md)：一個小型示範專案修正前後的兩次真實掃描，中英皆有。
- [全部掃描器指南](scanner-guide.zh-TW.md)：詳細 SWOT、選用原因、情境、啟用功能與 2026-10-04 版本快照。

## 開發中的新功能

以下功能已在本分支原始碼實作，尚未包含於任何發布版本：

- [Skill 主流程](skill-bootstrap.md)：固定來源 bootstrap 與所選掃描引擎的準備。
- [前景掃描與復原](foreground-scans.md)：執行已核准的檢查、讀取保存狀態並復原已擷取的結果。
- [Cloudflare 原始碼稽核](cloudflare-provider.md)：由宿主執行準備、記錄派工與輸出、檢查點、驗證、定稿、案件入案及共用報告整合；不再繼續的稽核可明示終止。
- [未完成稽核檢查](results-and-exports.zh-TW.md#未開始或未完成的原始碼稽核)：準備受阻與已終止稽核，會在案件、桌面結果與共用報告中列為未開始或失敗的檢查。
- [報告保存與離線重播](report-snapshots.md)：保存報告、取回原始檔案，並使用完全相容的報告產生器重播。
- [完整私密案件封存](case-archives.md)：建立、驗證並將案件、證據、保存報告與已記錄稽核歷史還原至新工作區；還原的稽核維持唯讀。

**尚未完成**

- 完整 skill 主流程的真實宿主驗收尚未完成。
- 預設 skill 仍使用已發布桌面版，尚未切換。
- 受管理執行環境套件的自動取得與宣稱平台驗證尚未完成。macOS 與 Windows 的 CI 已涵蓋 bootstrap、Cloudflare 原始碼稽核、報告保存與案件封存；前景掃描與掃描引擎準備在這兩個平台的測試尚不完整。

## 理解產品

- [產品規格](product-spec.md)：產品行為與驗收的唯一依據。
- [Skill 主入口與 Cloudflare 遷移規格](plans/skill-first-cloudflare-migration.md)：已採納的下一階段方向、現況缺口、分批實作順序與待完成驗收。
- [報告保真與封存契約](specs/report-fidelity-and-archive.md)：報告快照、provider 資料、離線重建、可攜案件還原與可追蹤驗收。
- [目前產品檢視](product-audit.md)：已完成路徑與剩餘產品工作。
- [架構](architecture.md)：元件、信任邊界、資料模型、執行與報告流程。
- [引擎目錄](engine-catalog.md)：已整合的上游掃描器與能力用語。
- [受管理執行環境](managed-runtime.md)：生命週期、隔離、修復與清理。
- [服務商授權](provider-authorization.md)：雲端授權與隔離 bootstrap。

## 開發與維護

- [目前開發狀態](development-status.zh-TW.md)：目前實作、已記錄的驗證與剩餘工作。
- [參與開發](../CONTRIBUTING.md)：產品優先順序、實作規則與驗證方式。
- [引擎維護](engine-maintenance.md)：上游更新、adapter 邊界與 patch 例外。
- [引擎參考](engines/README.zh-TW.md)：每個引擎的執行方式、adapter 保留內容、建置更新步驟與實測注意事項。
- [引擎與報告層契約](engine-alignment-handover.zh-TW.md)：目前的引擎語意、資產路徑、報告行為與完成判準。
- [威脅模型](threat-model.md)：保護資產、威脅與必要控制。
- [安全政策](../SECURITY.md)：非公開弱點回報與操作規則。
- [第三方清單](../THIRD_PARTY.md)：授權、notice 與散布紀錄。
- [發布流程](releasing.zh-TW.md)：候選版本、平台驗證與正式發布。([English](releasing.md))

## 歷史與研究紀錄

- [發布紀錄](release/README.zh-TW.md)保存已發布版本事實與證據格式。
- [研究](research/)保存已評估的整合與產品研究。
- [易用性研究](usability/)保存研究流程與證據處理規則。

目前產品行為以產品規格為準；歷史紀錄只描述其註明的版本或 commit。
