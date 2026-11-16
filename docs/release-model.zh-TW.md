# 現在發布了什麼？如何定義新版？

[English](release-model.md) · [文件](README.zh-TW.md)

發布狀態查核日期：2026-11-16。桌面 v0.7.0 已發布，完整 skill 主入口仍在開發中。

## 目前可取得的內容

| 交付項目 | 已查證狀態 | 使用者得到什麼 |
| --- | --- | --- |
| 桌面版 | [v0.7.0 正式版](https://github.com/TED-H-com/ai-security-scanner/releases/tag/v0.7.0)，2026 年 11 月 16 日發布 | Windows、macOS、Linux 安裝檔，以及既有桌面掃描與報告流程。 |
| 儲存庫操作 skill | [指引已公開](https://github.com/TED-H-com/ai-security-scanner/blob/main/.codex/skills/ai-security-scanner/SKILL.md)，另有相同的 Claude Code 版本 | 協助安裝及操作桌面版、解讀結果、匯出報告。可以稱為「已公開的儲存庫 skill」。 |
| 新的 skill 主流程與 bootstrap | 核心已包含於 v0.7.0；完整 skill 主入口尚未發布 | 前景掃描、所選引擎準備、報告保存、案件封存還原，以及 Cloudflare 資料驗證與保存。須明確選擇開發 checkout。 |
| Plugin 目錄上架 | 儲存庫公開並不能證明已上架 | 屬於另一個分發管道；沒有實際 listing，就不能宣稱已上架或通過平台審核。 |

[v0.7.0 交付紀錄](release/v0.7.0.md#繁體中文)記錄精確來源、公開檔案與驗證。原始碼公開及核心可下載，本身不代表完整 skill 新手流程已受支援。

## 建議用「交付內容＋成熟度」命名

| 用語 | 本產品建議定義 |
| --- | --- |
| 原始碼／文件公開 | 別人能取得指定來源或頁面；本身不代表完整流程已受支援。 |
| 儲存庫 skill 已公開 | 指引與必要資源可從指定 revision 取得，並清楚說明它操作桌面版或新核心。 |
| Skill 預覽版（preview） | 固定且可取得的 skill／core revision，入口已實測，先決條件、支援範圍與缺口清楚，供明確選擇的早期使用者試用。 |
| Skill 正式版（stable） | 在宣稱支援的宿主與平台上，新手可走完準備、真正掃描、共用報告、完整封存與異地還原。 |
| 桌面發布版 | 指定版本與平台的安裝檔及更新交付已發布，可依自己的時程推出。 |
| Plugin 發布／上架 | 另外分發的套件或目錄 listing，必須在該管道查證狀態。 |

**Publish 是讓內容可取得；release 是有明確身分、成熟度與支援範圍的一次交付。** Skill 加上固定來源與 bootstrap 就能構成產品 release，不必有桌面安裝檔。GitHub Release 可用來記錄這次交付；是否附二進位檔不是正式版的定義。

OpenAI 官方文件將本機／儲存庫 skill 與透過 plugin 的廣泛分發分開說明；plugin 可以包含 skill，也可以選擇加入 connector。本產品目前採用儲存庫 skill，這份建議沒有新增 plugin 打包工作。見 [Build skills](https://learn.chatgpt.com/docs/build-skills) 與 [Plugin architecture](https://developers.openai.com/plugins/concepts/plugins)。

## 新流程現在適合怎麼發布

下一次 skill 交付可稱為 **Skill 預覽版**，記錄實測的固定入口、支援範圍及先決條件；目前尚未宣布。[Bootstrap 驗證紀錄](skill-bootstrap.md#november-9-selected-engine-and-real-scan-validation)已有 Linux 上的真正 Gitleaks 掃描、秘密值遮蔽、報告交付與封存還原，但尚不能證明全部掃描器、資產類型與平台。

目前 source 已有前景執行／復原、所選引擎映像準備、共用報告快照、合併原始附件，以及既有案件 domain 的完整封存還原。Cloudflare 原始碼稽核可由宿主從準備、定稿、案件入案一路完成並納入共用報告，已入案稽核也會保存在完整封存中。完整能力與證據見[開發狀態](development-status.zh-TW.md)。

要把完整新 skill 流程稱為正式版，還需要：

1. 在宣稱支援的宿主與平台實測文件中的首次入口，完成新手路徑承諾的 managed runtime 自動取得。
2. 完成 Cloudflare 可信來源處理、宿主協調與案件／報告整合，讓完整封存保存其證據。
3. 跑通宣稱支援的混合資產掃描、部分失敗、共用報告、離線取回與新 workspace 還原，並保留桌面資料相容性。
4. 公開實測的來源身分、入口、支援範圍及變更說明；同步 canonical skill、兩份宿主 skill、文件與網站後，再切換預設入口。

這些是既定產品成果，不是追求測試數量，也不要求較窄範圍的預覽先具備所有平台。版本範圍、號碼與日期由產品負責人決定。目前 **桌面 v0.7.0 為正式版**，**完整 skill 主入口仍在開發中**。舊版本的 tag 與 updater 檔案保留原本身分。

## 下次交付記錄什麼

一份交付說明記錄：交付類型、channel、精確來源 revision、core identity、實測宿主／平台、入口指令、變更、限制與資料相容性。README 與網站連向同一份紀錄。不可重用舊 tag，或偷偷移動已固定的來源。

版本編號仍由產品負責人決定；這份建議維持現有 package metadata 與發布自動化。[桌面發布操作](releasing.zh-TW.md)只在交付安裝檔時適用。歷史發布紀錄與凍結範例報告保留原日期、版本和證據。
