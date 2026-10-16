# 文件

[專案網站](https://ted-h-com.github.io/ai-security-scanner/?lang=zh-TW) · [English](README.md)

依照工作選擇最短的文件路徑。

## 使用產品

- [開始使用](getting-started.zh-TW.md)：安裝 Linux、macOS 或 Windows 的 v0.5.2 桌面程式並完成第一次掃描。
- [Agent Skills](getting-started.zh-TW.md#透過-agent-skill-使用)：在同一台電腦上透過 Claude Code 或 Codex 確認能否掃描、引導在應用程式中掃描，並保存最終報告。
- [掃描範圍](scanning-scope.zh-TW.md)：精確目標界線、掃描設定與引擎行為。
- [結果與匯出](results-and-exports.zh-TW.md)：閱讀優先順序、涵蓋範圍、證據與保存報告。
- [v0.5.2 發布紀錄](release/v0.5.2.zh-TW.md)：本版更新、實際交付證據與尚未觀察的平台項目。

- [標準報告範例](samples/v0.4.0/README.zh-TW.md)：遮蔽／完整揭露版，中英皆有；25 個 adapter、真實格式、模擬資料。
- [修正後再檢查一次](demos/check-fixes/README.zh-TW.md)：一個小型示範專案修正前後的兩次真實掃描，中英皆有。
- [全部掃描器指南](scanner-guide.zh-TW.md)：詳細 SWOT、選用原因、情境、啟用功能與 2026-10-04 版本快照。

## 理解產品

- [產品規格](product-spec.md)：產品行為與驗收的唯一依據。
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
