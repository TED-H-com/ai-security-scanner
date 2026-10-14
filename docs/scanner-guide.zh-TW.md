# 掃描器指南

產品 v0.4.0 · 發布及檢視日期 2026-10-04。

[互動網站](https://ted-h-com.github.io/ai-security-scanner/scanner-guide.html?lang=zh-TW) · [範例報告](samples/v0.4.0/README.zh-TW.md)

SWOT 為專案團隊評估。啟用功能描述本產品設定，不代表完整上游平台。來源日期為提交日期，不是發布日。機會描述可能用途，不是承諾功能。

## CloudQuery

整理部分 AWS 身分與權限政策，作為盤點資料，和安全問題分開列出。

[Upstream](https://github.com/cloudquery/cloudquery) · [README @ e27e4ab](https://github.com/cloudquery/cloudquery/blob/e27e4ab61ad85479a5d53dae9b08440bc63e72b3/README.md) · [整合與更新筆記](https://github.com/TED-H-com/ai-security-scanner/blob/335d0666bdc63eb86e6c8c4cddeae110db893397/docs/engines/cloudquery.md)

### 工具介紹

CloudQuery 是一款廣泛使用的開源工具，會把雲端服務商 API 提供的資料整理成結構化表格，方便你之後查詢與比對。它用來源外掛讀取雲端服務，再用目的地外掛寫下每一列資料，所以每次收集到的格式都一致。我們把它放進本程式，是因為它能幫你很快看清一個核准的 AWS 帳號裡有哪些身分與權限政策，讓安全檢查的結果更容易對照。這裡只收集一組固定的身分與存取管理（IAM）表格：帳號、使用者、群組、角色、政策、密碼政策與憑證報告。這些資料屬於盤點，只說明目前有什麼，會和安全問題分開列出，也不涵蓋所有 AWS 服務。

### 原本的工具能做什麼

CloudQuery 把 API 資料轉成可查詢、比較的結構化資料。CLI、來源 plugin 與目的地 plugin 各有版本，只記 CLI 版本不足以辨識實際收集行為。

### 這個程式會檢查什麼

內嵌 CLI 2.0.31、AWS source 9.2.0 與 file destination 1.0.4，以本機 plugin 執行。對一個核准 AWS 帳號使用固定 us-east-1 IAM profile，包含帳號、憑證報表、群組、密碼政策、政策、角色與使用者七張表；子表保留為證據。各表 NDJSON 轉成附來源的盤點觀察。

### 哪些不在檢查範圍內

這項整合不盤點全部 AWS 服務、不在掃描時下載 plugin，也不把資源列當成弱點。專案刻意固定早期公開 plugin 組合，不宣稱提供最新 CloudQuery 平台。

### 為什麼選用

選用理由是收集範圍能明確到資料表，且機器輸出可檢查。它建立 IAM 資源底冊，讓讀者在同一資產報告中對照 Prowler 或政策分析的證據。

### 什麼情況下使用

適合 AWS 管理者先清點 IAM 使用者、角色與政策，再檢查安全設定；也能協助理解其他工具提到的身分從何而來。使用時選定精確帳號與唯讀盤點權限。

### 報告會呈現什麼

範例提供雲端資源觀察，保留原生識別碼與資料表來源；它增加盤點涵蓋範圍，不增加弱點數或安全通過判定。

### 優勢

資料表與 plugin 分別固定，收集方式可重現；結構化資料列比雲端主控台截圖更容易歸屬資產並保留證據。

### 弱點

盤點描述設定，無法證明是否可被利用。固定的 2023 年 plugin，其 API 模型比現行上游版本更舊、更窄；同步完資料表也不代表整個雲端已完整受測。

### 機會

保留的底冊可用於確認身分負責人、對照政策發現及比較前後評估。未來若更換收集器，仍可沿用這套標準化盤點契約。

### 威脅

AWS API 變更、分頁失敗或唯讀權限不足都可能遺漏資源。舊依賴組合需要明確維護審查；應用程式發布新版，不會自動更新這個上游收集器。

### 版本紀錄

| 項目 | 2026-10-04 提供 |
| --- | --- |
| 引擎版本（目錄紀錄） | 2.0.31-aws9.2.0-file1.0.4 |
| 映像標籤 | 2.0.31-aws9.2.0-6 |
| 固定來源提交日期（UTC） | 2023-01-05T14:16:38Z |
| 原始碼版本 | e27e4ab61ad85479a5d53dae9b08440bc63e72b3 |
| 規則／檢查 | CloudQuery AWS source plugin v9.2.0 and fixed seven-table IAM profile |
| 規則版本 | 804be3a90d6f15d3e6c662c0eb7afa88a9596180 |
| 資料輸入 | AWS IAM inventory |
| 資料版本 | 無／執行時輸入 |
| 目錄知識基準日期 | 2023-01-10 |
| Adapter 版本 | 0.2.6 |
| 輸出格式 | NDJSON · 各資料表輸出 |

映像識別: `ghcr.io/teddashh/ai-security-scanner-engine-cloudquery:2.0.31-aws9.2.0-6@sha256:e80bc6914b9a007b2a1e8978a222ff7b0ead657d004ca22f410270d086c3be82`

## Steampipe

列出 AWS 使用者與部分帳號設定，方便了解哪些人可以存取。

[Upstream](https://github.com/turbot/steampipe) · [README @ 71fa72f](https://github.com/turbot/steampipe/blob/71fa72fc9ce33897bcb0bd0c9ebf09b867b881cf/README.md) · [整合與更新筆記](https://github.com/TED-H-com/ai-security-scanner/blob/335d0666bdc63eb86e6c8c4cddeae110db893397/docs/engines/steampipe.md)

### 工具介紹

Steampipe 由 Turbot 維護，是一款廣泛使用的開源工具，能把雲端 API 變成 SQL 資料表。SQL 是查詢資料庫的標準語言，而每個服務商外掛決定你能讀到哪些服務與欄位。我們把它放進本程式，是因為它能幫你很快列出一個核准 AWS 帳號裡的身分與存取管理（IAM）使用者，再拿這份名單對照安全檢查的結果。這裡只執行一個固定的 IAM 使用者查詢。查到的資料屬於盤點：只列出找到的使用者，不判斷哪個使用者有風險。本程式也不執行 Steampipe 現成的安全基準檢查，也不接受你自己寫的 SQL。

### 原本的工具能做什麼

Steampipe 透過 provider plugin 將 API 變成 SQL 資料表。雲端中繼資料因此能以熟悉的關聯模型查詢，實際可用服務與欄位則由 plugin 決定。

### 這個程式會檢查什麼

Steampipe 2.4.5 使用預先放入映像的 AWS plugin 1.32.0。產品透過 cloud launcher 與受控網路出口，對一個核准帳號執行固定 AWS IAM 盤點子集。JSON 資料列轉成雲端資源觀察，保留查詢與來源歸屬。

### 哪些不在檢查範圍內

此 profile 不執行使用者任意 SQL、不在執行期安裝 plugin、不涵蓋所有雲端服務，也不啟用整套 security Mod。SQL 輸出本身不是安全控制失敗。

### 為什麼選用

SQL 資料表模型提供另一種可檢查的 IAM 底冊表示方式，可與 CloudQuery 並列。專案明確保留它的盤點角色，讓讀者知道資料底冊與安全判定各自代表什麼。

### 什麼情況下使用

適合已核准的 AWS IAM 檢視，當你需要結構化資源列來說明有哪些使用者、角色或政策時使用。尤其可把安全發現中的身分，追溯回 provider 原始資料。

### 報告會呈現什麼

範例保留 IAM 資源觀察與 Steampipe 來源，報告將它們放在盤點區，不增加弱點數量。

### 優勢

SQL 讓底冊具有一致且可檢查的形狀；固定的本機 plugin 與查詢範圍，使實際收集路徑容易審閱。

### 弱點

選定查詢只涵蓋 IAM 子集，而且只能呈現 provider 實際回傳的資料；Steampipe 本身與 plugin 管理，也比一次直接 API 呼叫多出維護元件。

### 機會

可比較不同評估的資料表底冊、把身分對上政策發現，並在刻意更新 plugin 時維持穩定輸出契約。若增加 SQL 表，需另行檢視範圍與權限。

### 威脅

Provider 限流、欄位或結構變更，以及 API 權限拒絕，都可能造成部分盤點。自動換成新版 plugin 可能連帶改變查詢與權限，因此版本日期與固定輸入很重要。

### 版本紀錄

| 項目 | 2026-10-04 提供 |
| --- | --- |
| 引擎版本（目錄紀錄） | 2.4.5 |
| 映像標籤 | 2.4.5-6 |
| 固定來源提交日期（UTC） | 2026-08-10T13:27:42Z |
| 原始碼版本 | 71fa72fc9ce33897bcb0bd0c9ebf09b867b881cf |
| 規則／檢查 | Steampipe AWS plugin v1.32.0 |
| 規則版本 | 6e79b2dece502bc198310b39bd54bc95d2842c99 |
| 資料輸入 | AWS IAM inventory |
| 資料版本 | 無／執行時輸入 |
| 目錄知識基準日期 | 2026-08-24 |
| Adapter 版本 | 0.2.6 |
| 輸出格式 | JSON |

映像識別: `ghcr.io/teddashh/ai-security-scanner-engine-steampipe:2.4.5-6@sha256:cd488a85ca1ebfb4c5f17212b9b29c1309a4cf9450d8645a911ffb1bdb6b4e42`

## Prowler

檢查核准的 AWS 帳號、Azure 訂用帳戶或 GCP 專案中的部分身分與權限設定。

[Upstream](https://github.com/prowler-cloud/prowler) · [README @ 40ecbd0](https://github.com/prowler-cloud/prowler/blob/40ecbd035e5541bf099917c5033cceb8959c4737/README.md) · [整合與更新筆記](https://github.com/TED-H-com/ai-security-scanner/blob/335d0666bdc63eb86e6c8c4cddeae110db893397/docs/engines/prowler.md)

### 工具介紹

Prowler 是一款廣泛使用的開源雲端安全評估工具。它呼叫雲端服務商的 API、執行內建檢查，並記下檢查名稱、受影響的資源、哪裡不符合，以及怎麼修正。上游的 Prowler 能涵蓋許多服務與合規框架。我們把它放進本程式，是因為它能幫你很快找出需要注意的身分與權限設定。這裡每次只對一個核准資產執行範圍很窄的身分與存取管理（IAM）檢查：一個 AWS 帳號的 IAM 服務、一個 Azure 訂用帳戶的 IAM 服務，或一個 GCP 專案的四項指定 IAM 檢查。其他服務與帳號不在這次檢查範圍內，單一檢查通過也不代表取得認證。

### 原本的工具能做什麼

Prowler 是雲端安全評估專案，提供依 provider 區分的檢查與修正指引。上游完整平台的能力，比本桌面整合選用的受限 provider profile 更廣。

### 這個程式會檢查什麼

Prowler 5.39.1 針對一個精確 AWS 帳號、Azure subscription 或 GCP project，評估選定的 IAM 設定。原生 OCSF 保留 check ID、FAIL／PASS、資源、嚴重度、失敗原因與修正建議。上游標題若描述理想安全狀態，報告會優先呈現實際失敗條件。

### 哪些不在檢查範圍內

此整合不是涵蓋所有服務、所有帳號的 Prowler 部署。不宣稱執行所有上游合規套件；個別檢查通過也不代表取得認證或獲准更動雲端資源。

### 為什麼選用

選用 Prowler，是因為它能在三大雲端 provider 提供資源層級證據與可執行的修正指引。保留 check ID，讓報告層能整理相關工作，同時保有每一筆上游結果。

### 什麼情況下使用

適合 IAM 安全檢視、身分政策變更後複查，或將帳號／subscription／project 交接給其他團隊前使用。先確認精確 provider 範圍，再完成 provider 的唯讀授權。

### 報告會呈現什麼

範例包含具有萬用管理權限的 AWS managed policy，顯示失敗條件、政策 ARN、原生 check 與修正方式；同份輸入的 PASS 資料列不會被轉成問題。

### 優勢

原生資源識別碼與 OCSF 輸出支持精確證據歸屬；沿用上游 check 語意和修正指引，使發現能回到原始設定核對。

### 弱點

設定發現無法證明攻擊者實際使用過權限。選定 profile 刻意維持窄範圍，並依賴完整讀取權限；沒有發現只代表核准範圍內已評估的項目。

### 機會

可搭配 Cloudsplaining 政策細節與資源盤點，指派具體的最小權限修正；重複掃描能核對同一原生 check、同一資源是否改善。

### 威脅

雲端 API 演進、權限缺口與上游新增 check 都可能改變涵蓋範圍。讀者也可能把上游完整平台的能力當成此產品實際範圍，因此必須同時提供 profile 與版本紀錄。

### 版本紀錄

| 項目 | 2026-10-04 提供 |
| --- | --- |
| 引擎版本（目錄紀錄） | 5.39.1 |
| 映像標籤 | 5.39.1-7 |
| 固定來源提交日期（UTC） | 2026-08-18T09:32:24Z |
| 原始碼版本 | 40ecbd035e5541bf099917c5033cceb8959c4737 |
| 規則／檢查 | Prowler checks |
| 規則版本 | 40ecbd035e5541bf099917c5033cceb8959c4737 |
| 資料輸入 | Exact-scope AWS, Azure, or GCP IAM configuration |
| 資料版本 | 無／執行時輸入 |
| 目錄知識基準日期 | 2026-08-24 |
| Adapter 版本 | 0.2.6 |
| 輸出格式 | OCSF-JSON |

映像識別: `ghcr.io/teddashh/ai-security-scanner-engine-prowler:5.39.1-7@sha256:38d9593af214ce164c78b731d1ea29abd06de6babe84b230502972f67a658450`

## ScoutSuite

檢查部分 AWS 身分與存取設定。本程式使用的是 ScoutSuite 的部分功能。

[Upstream](https://github.com/nccgroup/ScoutSuite) · [README @ 7909f2f](https://github.com/nccgroup/ScoutSuite/blob/7909f2fc6186063e5c9e7ddef8c4d7d1072c8f3d/README.md) · [整合與更新筆記](https://github.com/TED-H-com/ai-security-scanner/blob/335d0666bdc63eb86e6c8c4cddeae110db893397/docs/engines/scoutsuite.md)

### 工具介紹

ScoutSuite 來自 NCC Group，是一款廣泛使用的開源工具。它透過雲端服務商的 API 讀取設定，用自己的規則標出有風險的設定，每筆結果都保留規則、受影響的項目，以及值得檢視的原因。上游的 ScoutSuite 支援多家雲端服務商，也有自己的報告。我們把它放進本程式，是因為它能幫你很快找出值得再看一眼的 AWS 身分與存取設定，也能和 Prowler 互相對照。這裡只對一個核准帳號執行 AWS 身分與存取管理（IAM）規則，其他雲端服務商與其他 AWS 服務都不在範圍內。設定要被規則標出才會成為報告裡的問題，只是收集到設定並不代表有弱點。

### 原本的工具能做什麼

ScoutSuite 透過 provider API 收集雲端設定，標出需要檢視的風險設定。上游支援更廣的多雲評估流程，也有自己的呈現介面。

### 這個程式會檢查什麼

ScoutSuite 5.14.0 對一個核准 AWS 帳號執行受限的 IAM-only profile。保留的 JSON 輸出修補提供機器可讀結果，不需依賴上游 HTML viewer；adapter 保留規則識別、受影響 IAM 項目與上游嚴重度、證據。

### 哪些不在檢查範圍內

此 profile 不包含 ScoutSuite 其他雲端 provider 或 AWS 服務類別。產品不把偵測規則搬進 wrapper，也不把每個收集到的設定項目視為弱點。

### 為什麼選用

它提供另一套上游 AWS IAM 設定檢視，可與 Prowler 互補。即使多個工具在共用報告中整理成同一個修正動作，仍能檢查每筆原生證據。

### 什麼情況下使用

適合第二套 IAM 設定檢視，或需要完整證據的帳號交接；當操作者需要知道設定哪裡有風險，而不只是有哪些資源時尤其有用。

### 報告會呈現什麼

範例包含來自原生 JSON 結構的多筆 IAM 規則發現；每筆在技術證據中保留 ScoutSuite 來源及受影響資源背景。

### 優勢

以資源為中心的設定證據容易人工核對；第二套上游規則可呈現不同的檢視角度，產品仍沿用現有偵測器。

### 弱點

固定版本較舊，整合也依賴一項窄範圍機器輸出修補；與其他 IAM 工具可能重疊，因此原始發現數不能直接視為獨立受影響資產數。

### 機會

可比較同一 IAM 資源的 ScoutSuite 與 Prowler 證據，保留差異供審閱，並在產品報告整理共通修正。較新來源可在輸出修補重新驗證後評估採用。

### 威脅

AWS 回應變化可能超出固定 parser 的理解範圍；上游報告結構改變，也可能減少細節，因此更新時需要一起核對 adapter 範例與輸出修補。

### 版本紀錄

| 項目 | 2026-10-04 提供 |
| --- | --- |
| 引擎版本（目錄紀錄） | 5.14.0 |
| 映像標籤 | 5.14.0-6 |
| 固定來源提交日期（UTC） | 2024-05-10T09:24:57Z |
| 原始碼版本 | 7909f2fc6186063e5c9e7ddef8c4d7d1072c8f3d |
| 規則／檢查 | ScoutSuite AWS IAM rules |
| 規則版本 | 7909f2fc6186063e5c9e7ddef8c4d7d1072c8f3d |
| 資料輸入 | AWS IAM configuration |
| 資料版本 | 無／執行時輸入 |
| 目錄知識基準日期 | 2026-08-24 |
| Adapter 版本 | 0.2.6 |
| 輸出格式 | JSON |

映像識別: `ghcr.io/teddashh/ai-security-scanner-engine-scoutsuite:5.14.0-6@sha256:72eea2aa430852cb92511a5234c99fe6fce6d574c36594fdc15dcf85d3a26394`

## Cloudsplaining

分析收集到的 AWS 權限政策，找出可能給得太多的權限。

[Upstream](https://github.com/salesforce/cloudsplaining) · [README @ 75a67ea](https://github.com/salesforce/cloudsplaining/blob/75a67ea9cb6d0fdf35ff185d08dad0d45587e6f7/README.md) · [整合與更新筆記](https://github.com/TED-H-com/ai-security-scanner/blob/335d0666bdc63eb86e6c8c4cddeae110db893397/docs/engines/cloudsplaining.md)

### 工具介紹

Cloudsplaining 來自 Salesforce，是一款開源工具，專門檢查 AWS 身分與存取管理（IAM）政策是否給了超過工作所需的權限，也就是有沒有違反「最小權限」原則。它讀取帳號的授權細節，找出沒有限定資源範圍的動作，再把有風險的動作分成權限提升、資料外洩、資源曝露與更動基礎設施等類別，並指出是哪一份政策、哪些動作。我們把它放進本程式，是因為它能幫你很快找出過寬的權限，看清該檢視哪些動作。這裡只分析一個核准的 AWS 帳號。被標出的動作是供你審閱的證據：它不判斷業務是否需要這項權限、不修改政策，也不能證明現在真的有人用得到。

### 原本的工具能做什麼

Cloudsplaining 專注 AWS IAM 政策分析，檢視授權資料，將高風險權限分類，例如權限提升、資料存取或更動基礎設施的能力。

### 這個程式會檢查什麼

0.9.1 會下載一個核准 AWS 帳號的授權細節，執行上游政策分析。原生 action、政策識別、排除資訊與附加資源背景會進入共用報告；相關發現可共用修正動作，每筆證據仍可查閱。

### 哪些不在檢查範圍內

它不模擬每一個實際 AWS 授權判定、不替使用者判斷業務必要性，也不修改政策。被分類為高風險的 action 是審閱證據，不能直接證明攻擊者目前可利用。

### 為什麼選用

一般 posture check 常指出較廣的 IAM 問題；Cloudsplaining 補上政策與 action 細節，協助管理者縮小萬用權限。即使其他工具指向同一政策，這項專長仍有用途。

### 什麼情況下使用

適合把角色交給應用程式前、進行最小權限檢視時，或已发现過度授權政策之後使用。判讀 action 時，仍須搭配 trust policy、組織控制與應用需求。

### 報告會呈現什麼

範例顯示附原生分類與來源的政策／action 發現。多個 action 紀錄可能屬於同一政策，報告會保留此關係，不把它們當成多個無關資產。

### 優勢

專注 IAM 的分析能指出哪些權限值得關注；保留 action 名稱，使修正討論更具體，也讓管理者能回到政策文件核對。

### 弱點

靜態政策分析不能證明實際使用狀態、可達性，或所有外部限制的完整效果；部分廣泛權限可能出於必要，需由負責團隊確認操作需求。

### 機會

可把 action 級證據與 Prowler、ScoutSuite 及盤點結合，形成聚焦的政策檢視；後續掃描可追蹤具體高風險 action 是否移除，並保留原始識別。

### 威脅

新的 AWS 服務與 action 可能比固定分析定義更新；缺少授權細節或權限不足會限制分析。若只計算原始紀錄，不看多工具重疊，也可能誇大問題數量。

### 版本紀錄

| 項目 | 2026-10-04 提供 |
| --- | --- |
| 引擎版本（目錄紀錄） | 0.9.1 |
| 映像標籤 | 0.9.1-6 |
| 固定來源提交日期（UTC） | 2026-06-14T23:46:19Z |
| 原始碼版本 | 75a67ea9cb6d0fdf35ff185d08dad0d45587e6f7 |
| 規則／檢查 | Cloudsplaining IAM analysis definitions |
| 規則版本 | 75a67ea9cb6d0fdf35ff185d08dad0d45587e6f7 |
| 資料輸入 | AWS IAM authorization details |
| 資料版本 | 無／執行時輸入 |
| 目錄知識基準日期 | 2026-08-24 |
| Adapter 版本 | 0.2.6 |
| 輸出格式 | JSON |

映像識別: `ghcr.io/teddashh/ai-security-scanner-engine-cloudsplaining:0.9.1-6@sha256:26f629d8bf65dd43aec6e217a4492e7c974ec81d0daf6b07d52efff475968997`

## ScubaGear

依照美國 CISA 的安全建議，檢查支援的 Microsoft 365 設定。

[Upstream](https://github.com/cisagov/ScubaGear) · [README @ 4d34e9a](https://github.com/cisagov/ScubaGear/blob/4d34e9a48e38ce5c2e14c0fdfbaee53e57594ae2/README.md) · [整合與更新筆記](https://github.com/TED-H-com/ai-security-scanner/blob/335d0666bdc63eb86e6c8c4cddeae110db893397/docs/engines/scubagear.md)

### 工具介紹

ScubaGear 來自美國網路安全暨基礎設施安全局（CISA），是一款開源工具，會把 Microsoft 365 租戶（也就是組織的 Microsoft 365 環境）的設定，和 CISA 的 Secure Cloud Business Applications（SCuBA）基準比較；這些基準是以書面寫下的安全設定要求。上游也涵蓋其他 Microsoft 365 產品。我們把它放進本程式，是因為它能幫你很快找出不符合這份基準的 Microsoft Entra ID 設定；Entra ID 是租戶的登入與身分目錄。這裡只為一個已授權、位於 Microsoft 商業雲端的租戶檢查 Entra ID 基準，Exchange、SharePoint 與其他工作負載不在範圍內。通過不等於合規認證，沒能評估的項目也會照樣列出，不算通過。

### 原本的工具能做什麼

CISA ScubaGear 依公開 SCuBA 安全設定基準評估 Microsoft 365 租戶設定。上游有不同產品的評估，因此每份基準結果都需要說明實際評估了哪個產品。

### 這個程式會檢查什麼

ScubaGear 1.8.0 透過 Microsoft Graph，對一個已授權租戶執行固定 AAD／Entra ID profile。受控映像包含經檢視的 PowerShell 模組與基準輸入；保留原生政策／控制識別、判定與證據，失敗項目形成發現，未評估部分仍可見。

### 哪些不在檢查範圍內

此設定不評估所有 Microsoft 365 工作負載，不執行 Exchange 或 SharePoint 評估，也不提供合規認證。這些模擬範例不代表即時租用戶評估的結果。

### 為什麼選用

CISA 公開具體基準要求，使設定檢查的依據可供查閱。ScubaGear 以基準為主軸，與 Maester 對同一核准 Entra 環境的檢查互補。

### 什麼情況下使用

適合 Entra 設定檢視、租戶交接或身分政策修改後複查。開始前完成文件列出的 Microsoft 唯讀同意，並確認精確租戶。

### 報告會呈現什麼

範例包含一筆失敗的 SCuBA 控制，保留原生識別與租戶歸屬；它以代表性輸入展示報告呈現，不代表新掃描了真實 Microsoft 租戶。

### 優勢

公開基準參照能說明政策目的；原生控制識別讓讀者回查 CISA 資料，並在後續複掃延續證據軌跡。

### 弱點

產品只啟用上游套件的 Entra 部分。授權方案、租戶設定與權限會影響可評估項目；符合基準也不等於衡量了每條攻擊路徑。

### 機會

可搭配 Maester 測試細節，再依實際需要修改的身分設定整理工作；重複授權掃描可核對同一控制是否由失敗轉為通過。

### 威脅

Microsoft Graph 變更、條件式存取限制與同意權限缺漏可能中斷收集；基準改版也可能改變要求，因此不能只因發布日期較新就默默換掉固定基準。

### 版本紀錄

| 項目 | 2026-10-04 提供 |
| --- | --- |
| 引擎版本（目錄紀錄） | 1.8.0 |
| 映像標籤 | 1.8.0-8 |
| 固定來源提交日期（UTC） | 2026-08-20T18:59:38Z |
| 原始碼版本 | 4d34e9a48e38ce5c2e14c0fdfbaee53e57594ae2 |
| 規則／檢查 | CISA ScubaGear baselines |
| 規則版本 | 4d34e9a48e38ce5c2e14c0fdfbaee53e57594ae2 |
| 資料輸入 | Microsoft Entra ID configuration |
| 資料版本 | 無／執行時輸入 |
| 目錄知識基準日期 | 2026-08-24 |
| Adapter 版本 | 0.2.6 |
| 輸出格式 | JSON · 包含原生判定的受管外層格式 |

映像識別: `ghcr.io/teddashh/ai-security-scanner-engine-scubagear:1.8.0-8@sha256:9933c263fee77b187f2b763ffc0b490a0e220effb8b011c8a204abb23d340cc7`

## Maester

檢查支援的 Microsoft 365 安全設定，列出需要注意的項目。

[Upstream](https://github.com/maester365/maester) · [README @ 6bf1d98](https://github.com/maester365/maester/blob/6bf1d98f094fc7a68e449d2f40f73ef820b72ee3/README.md) · [整合與更新筆記](https://github.com/TED-H-com/ai-security-scanner/blob/335d0666bdc63eb86e6c8c4cddeae110db893397/docs/engines/maester.md)

### 工具介紹

Maester 是一套開源的測試框架，用 PowerShell（Microsoft 的腳本語言）寫成，專門檢查 Microsoft 365 的安全設定。每一項測試都寫明安全的租戶應有的設定，並記錄你的租戶是否符合。我們把它放進本程式，是因為它能幫你很快找出不符合這些要求的 Microsoft Entra ID 設定；Entra ID 是租戶的登入與身分目錄。這裡對一個已授權的租戶執行一組固定的 Entra 測試，並略過耗時很長的測試、預覽測試，以及需要連到其他服務的測試；Exchange Online 和你自己提供的腳本都不在範圍內。被略過的測試絕不會顯示成通過，需要人來判斷的測試會列出來供你審閱。

### 原本的工具能做什麼

Maester 是以 PowerShell 為基礎的 Microsoft 365 安全設定測試框架。測試把預期設定寫成明確條件，保留判定以便長期追蹤。

### 這個程式會檢查什麼

Maester 2.0.0 對一個已授權租戶執行固定、只使用 Graph 的 Entra 測試 profile。映像固定必要模組與測試，adapter 保留原生測試識別、失敗細節及完成資訊；M365 設定文件列出必要讀取權限，包含選定的 PIM 讀取。

### 哪些不在檢查範圍內

產品不執行所有 Maester 工作負載、Exchange Online 測試或任意租用戶腳本。略過或無法使用的檢查不會轉成通過。範例展示輸出，不代表即時租用戶評估。

### 為什麼選用

以測試為中心的輸出，讓管理者有明確項目可調查、複查。與 ScubaGear 搭配可提供互補原生證據，共用報告則讓讀者集中閱讀。

### 什麼情況下使用

適合 Entra 政策變更後、租戶安全檢視時，或團隊需要可重複的設定回歸證據時使用；選定租戶與 Graph 權限須符合核准 profile。

### 報告會呈現什麼

範例包含原生失敗測試的標題與支援細節，報告標示 Maester 來源並保留測試識別。

### 優勢

明確測試與穩定識別有助重複審閱；固定的 Graph-only profile 也減少操作者需要理解的獨立連線方式。

### 弱點

測試只看得到已授權 API 暴露的設定，無法證明所有租戶攻擊路徑都已實測；需要其他授權方案或權限的測試可能仍未評估。

### 機會

可追蹤經審閱設定變更前後的原生測試結果，並將與 ScubaGear 重疊的發現整理成可執行工作；更廣的工作負載涵蓋範圍需要另行檢視 profile。

### 威脅

Graph 與 PowerShell 依賴改版可能破壞原本有效的收集路徑；即使本機工具版本不變，租戶政策或權限變動仍可能造成部分結果。

### 版本紀錄

| 項目 | 2026-10-04 提供 |
| --- | --- |
| 引擎版本（目錄紀錄） | 2.0.0 |
| 映像標籤 | 2.0.0-9 |
| 固定來源提交日期（UTC） | 2026-08-18T05:20:09Z |
| 原始碼版本 | 6bf1d98f094fc7a68e449d2f40f73ef820b72ee3 |
| 規則／檢查 | Maester Graph-only Entra test profile |
| 規則版本 | 6bf1d98f094fc7a68e449d2f40f73ef820b72ee3 |
| 資料輸入 | Microsoft Entra ID configuration |
| 資料版本 | 無／執行時輸入 |
| 目錄知識基準日期 | 2026-08-24 |
| Adapter 版本 | 0.2.6 |
| 輸出格式 | JSON · 包含原生判定的受管外層格式 |

映像識別: `ghcr.io/teddashh/ai-security-scanner-engine-maester:2.0.0-9@sha256:a41df2693dcb5923a85fb4e75f10d80dca130c6269c5621d82cd4809f176cf81`

## Naabu

查看核准的連接埠是否接受連線。連接埠開著值得了解，但不代表有漏洞。

[Upstream](https://github.com/projectdiscovery/naabu) · [README @ 5a0ca8b](https://github.com/projectdiscovery/naabu/blob/5a0ca8bde91b5bb16213e9e8b5c6871eac954bd8/README.md) · [整合與更新筆記](https://github.com/TED-H-com/ai-security-scanner/blob/335d0666bdc63eb86e6c8c4cddeae110db893397/docs/engines/naabu.md)

### 工具介紹

Naabu 是 ProjectDiscovery 維護的開源連接埠探索工具，用來找出哪些 TCP 連接埠正在接受連線。TCP 連接埠就是網路服務等候連線時使用的編號。它的連線掃描會對每個位址與連接埠嘗試一次一般的 TCP 連線，連得上就代表連接埠是開的；上游另外還有其他探索方式。我們把它放進本程式，是因為它能幫你很快看出哪些核准的服務正在等候連線，讓接下來的安全檢查有明確的對象。這裡只連你核准的位址與連接埠，不會把附近的主機加進來，也不掃描 UDP（另一種常見的服務連線方式）。開著的連接埠會記在盤點裡，本身不是漏洞。

### 原本的工具能做什麼

Naabu 是網路連接埠探索工具。上游提供多種掃描方式與探索選項；本產品將執行綁定至固定工作計畫。

### 這個程式會檢查什麼

Naabu 2.6.1 執行核准的 TCP connect 探索 profile。精確目標與連接埠形成有界工作單元及嘗試紀錄；原生 JSONL 服務觀察保留主機／IP、連接埠背景，並由紀錄判定哪些要求的單元確實完成。

### 哪些不在檢查範圍內

開放連接埠本身不是弱點，也不代表已完成安全掃描。此路徑不授權相鄰主機、擴展 CIDR、UDP 涵蓋範圍或所有上游探索模式。

### 為什麼選用

它提供明確服務底冊，可用來準備適用的安全檢查；將探索獨立呈現，讓正常監聽服務不會被誤列為可利用問題。

### 什麼情況下使用

適合管理者在選擇協定相關檢查前，確認哪些已核准 TCP 服務會回應。於主要內部系統安全路徑，探索是評估的準備工作，不能取代 Greenbone 發現。

### 報告會呈現什麼

範例顯示兩筆附 Naabu 來源的服務觀察，以及已完成工作單元的紀錄；它們出現在盤點區，不增加發現數。

### 優勢

機器可讀的服務探索可作為更廣評估的輸入；精確工作單元也讓已取消、部分完成與完整探索能明確區分。

### 弱點

TCP 連線無法充分說明服務身分、修補狀態或存取控制；防火牆與時序可能影響觀察，關閉或無回應的連接埠也不能證明主機安全。

### 機會

可把預期曝露範圍與觀察到的服務比較，再為已識別端點準備經檢視的安全 profile；重複盤點也能發現新增曝露服務以供調查。

### 威脅

網路中介設備、限流與短暫故障可能影響探索；另一項風險是把只有盤點的結果當成安全評估通過，因此報告明確標示其類型。

### 版本紀錄

| 項目 | 2026-10-04 提供 |
| --- | --- |
| 引擎版本（目錄紀錄） | 2.6.1 |
| 映像標籤 | 2.6.1-7 |
| 固定來源提交日期（UTC） | 2026-05-05T15:29:23Z |
| 原始碼版本 | 5a0ca8bde91b5bb16213e9e8b5c6871eac954bd8 |
| 規則／檢查 | TCP port discovery has no external rule pack |
| 規則版本 | 不適用 |
| 資料輸入 | authorized target reachability |
| 資料版本 | 無／執行時輸入 |
| 目錄知識基準日期 | 2026-08-24 |
| Adapter 版本 | 0.2.6 |
| 輸出格式 | JSONL |

映像識別: `ghcr.io/teddashh/ai-security-scanner-engine-naabu:2.6.1-7@sha256:e94240f4f067f39b7db9501a48c60411e6b29a215a11dda63406b9e62c061ab6`

## httpx

確認選定的網站服務是否回應，並記錄基本資訊；這不是漏洞檢查。

[Upstream](https://github.com/projectdiscovery/httpx) · [README @ 13037dd](https://github.com/projectdiscovery/httpx/blob/13037dd08b9715cfbd960a70ae1edfef6686a857/README.md) · [整合與更新筆記](https://github.com/TED-H-com/ai-security-scanner/blob/335d0666bdc63eb86e6c8c4cddeae110db893397/docs/engines/httpx.md)

### 工具介紹

httpx 是 ProjectDiscovery 維護的開源網站探測工具，和 Python 裡同名的 HTTPX 程式庫不是同一個東西。它會對一個位址送出一般的網頁（HTTP）請求，記下有沒有網站服務回應、回傳的狀態碼，以及其他基本的回應資訊；這些都是只看連接埠開不開無法得知的。我們把它放進本程式，是因為它能幫你在真正的安全檢查開始前，很快確認核准的網站服務是否有在回應。上游還能做更多種探測，這裡只詢問你核准的那一個服務，不爬網站、不登入，也不開啟所有上游探測。結果是描述這個服務的盤點資料，本身不代表有漏洞。

### 原本的工具能做什麼

ProjectDiscovery httpx 是 HTTP 探測工具，與 Python HTTPX client library 不同。它的探測協助描述會回應的網站服務；一次回應本身不構成弱點判斷。

### 這個程式會檢查什麼

httpx 1.10.0 對精確核准服務使用受限的唯讀 HTTP profile。JSONL 回應紀錄提供 URL／狀態及保留的服務中繼資料，轉成附上游與資產來源的類型化盤點；受控網路路徑限制核准目的地。

### 哪些不在檢查範圍內

此整合不因 HTTP 狀態就宣稱弱點，不爬取全部應用路由、不登入應用程式，也不啟用所有上游探測功能。

### 為什麼選用

它能在安全檢查前或同時，提供容易檢查的核准網站服務描述；與 Nuclei、ZAP 發現分開呈現，讓報告語意清楚。

### 什麼情況下使用

適合確認選定 HTTP 服務是否回應，並於曝露盤點保留基本回應背景；若要回答服務是否有安全問題，需使用安全掃描器。

### 報告會呈現什麼

範例包含帶 URL／狀態中繼資料與來源參照的 HTTP 服務觀察；即使上游紀錄有看似風險的欄位，仍依此工具的盤點角色呈現。

### 優勢

逐行 JSON 容易保存及歸屬；回應中繼資料能說明哪個服務可達，讀者不必先閱讀網路日誌。

### 弱點

中繼資料只是時間點快照，描述的可能是反向代理而非後方應用程式；可達性也不能說明受驗證隱藏路由或可利用性。

### 機會

可用底冊說明選定網站資產、比較曝露變化，並替後續 Nuclei 或 ZAP 工作提供回應背景；也有助區分不可用目標與已完成安全檢查。

### 威脅

CDN、WAF、短暫錯誤與改變的重新導向會讓不同輪觀察不同；操作者也可能把 HTTP 成功回應過度解讀為安全保證，因此盤點需獨立呈現。

### 版本紀錄

| 項目 | 2026-10-04 提供 |
| --- | --- |
| 引擎版本（目錄紀錄） | 1.10.0 |
| 映像標籤 | 1.10.0-7 |
| 固定來源提交日期（UTC） | 2026-07-09T16:11:51Z |
| 原始碼版本 | 13037dd08b9715cfbd960a70ae1edfef6686a857 |
| 規則／檢查 | HTTP metadata collection has no external rule pack |
| 規則版本 | 不適用 |
| 資料輸入 | authorized HTTP service observations |
| 資料版本 | 無／執行時輸入 |
| 目錄知識基準日期 | 2026-08-24 |
| Adapter 版本 | 0.2.6 |
| 輸出格式 | JSONL |

映像識別: `ghcr.io/teddashh/ai-security-scanner-engine-httpx:1.10.0-7@sha256:6911039efb20370ebd84ed6e57d7d793d5ae7bdff5813c007ac9b2774aaaed1e`

## Nuclei

先辨識網站使用的技術，再於核准的網址與限制內執行適用的唯讀檢查。

[Upstream](https://github.com/projectdiscovery/nuclei) · [README @ a8c88fe](https://github.com/projectdiscovery/nuclei/blob/a8c88feb4a1c8e961b7902534ce3af97e9d524a4/README.md) · [整合與更新筆記](https://github.com/TED-H-com/ai-security-scanner/blob/335d0666bdc63eb86e6c8c4cddeae110db893397/docs/engines/nuclei.md)

### 工具介紹

Nuclei 是 ProjectDiscovery 維護的開源弱點掃描工具，也是同類工具中最受歡迎且備受信任的工具之一。它的每一項檢查都是一份範本：寫好的請求，加上代表已知曝露或漏洞的回應特徵。它會先辨識網站用了哪些技術，再挑出適合的範本。我們把它放進本程式，是因為它能幫你很快找出這些已知問題；它是預設的網站檢查，使用本程式內附的範本。它只對一個核准的網站位址送出唯讀請求，不登入、不送出表單、不做模糊測試或漏洞利用、不操作瀏覽器，也不請外部伺服器回撥。你輸入的路徑不會把檢查範圍縮小到那個路徑。

### 原本的工具能做什麼

Nuclei 以上游 YAML 範本評估目標。範本 repository 提供偵測邏輯，且與引擎各自更新，因此需要同時識別引擎與範本 revision。

### 這個程式會檢查什麼

Nuclei 3.11.1 使用固定 nuclei-templates 快照及經檢視的唯讀 HTTP profile。原生 automatic scan 執行上游技術辨識，在一個核准 scheme://host:port 來源上選擇適用且符合限制的範本；保留範本識別、嚴重度、證據與修正建議。

### 哪些不在檢查範圍內

快速 profile 排除驗證登入、跨來源重新導向、表單／請求主體、帶外回呼、headless 流程、fuzzing 與利用型操作。輸入 URL 路徑不會把上游範本限制在該路徑，授權範圍是整個來源。

### 為什麼選用

上游範本生態提供依技術而異的檢查，產品不需維護自己的廠牌或 CVE 決策樹。此有界 profile 能產生真正偵測證據，因此被選為快速網站安全檢查的預設工具。

### 什麼情況下使用

適合自有網站或 API 來源、應用部署後，或檢視曝露的管理介面時使用。執行前須確認對整個顯示來源具有授權。

### 報告會呈現什麼

範例包含原生範本命中，例如由工具分類的曝露管理介面。每筆保留範本 ID 與原始嚴重度；資訊性命中不會被升級成嚴重利用弱點。

### 優勢

分別固定引擎與範本，使偵測依據可追溯；上游適用性判斷與原生證據提供具體結果，薄層 adapter 保持偵測行為可辨識。

### 弱點

涵蓋範圍依賴範本、辨識出的技術與可存取回應。零命中不代表每個符合限制的範本都執行過，也不代表每頁與受驗證流程都受測。

### 機會

可把範本發現與 ZAP 回應層觀察、儲存庫證據一起檢視，優先處理具體網站修正；刻意更新範本也能增加涵蓋範圍，而不重寫產品偵測邏輯。

### 威脅

過舊範本快照缺少較新檢查；WAF 或部署變動會改變回應與適用性。未檢視的範本更新也可能引入超出核准 profile 的行為，因此採納檢查與版本紀錄必須一起更新。

### 版本紀錄

| 項目 | 2026-10-04 提供 |
| --- | --- |
| 引擎版本（目錄紀錄） | 3.11.1 |
| 映像標籤 | 3.11.1-7 |
| 固定來源提交日期（UTC） | 2026-08-08T12:20:01Z |
| 原始碼版本 | a8c88feb4a1c8e961b7902534ce3af97e9d524a4 |
| 規則／檢查 | projectdiscovery/nuclei-templates |
| 規則版本 | 24858b4bfabfa86f0bcfd36aea24fb535152b012 |
| 資料輸入 | authorized service responses |
| 資料版本 | 無／執行時輸入 |
| 目錄知識基準日期 | 2026-08-24 |
| Adapter 版本 | 0.2.6 |
| 輸出格式 | JSONL / SARIF |

映像識別: `ghcr.io/teddashh/ai-security-scanner-engine-nuclei:3.11.1-7@sha256:c0d9709528f9d900ccf7e676de3e19456865aaa9788828adb29e19bd55204520`

## Greenbone Community Edition

辨識核准主機與連接埠上的服務，再執行適合的安全檢查。

[Upstream](https://github.com/greenbone/openvas-scanner) · [README @ 26465a1](https://github.com/greenbone/openvas-scanner/blob/26465a11ff0e6a98d60a253265fab5974fc757b6/README.md) · [整合與更新筆記](https://github.com/TED-H-com/ai-security-scanner/blob/335d0666bdc63eb86e6c8c4cddeae110db893397/docs/engines/greenbone.md)

### 工具介紹

Greenbone OpenVAS 是 Greenbone 維護的開源網路弱點掃描工具。它使用一份固定版本的 Greenbone Community Feed 來做弱點測試；Community Feed 是 Greenbone 另外維護的檢查項目庫。它會先辨識連接埠上跑的是什麼服務，再執行適用的測試。我們把它放進本程式，是因為它能幫你找出內部設備與伺服器上、光靠連線看不出來的已知安全問題。這裡只測試你核准的主機與連接埠，不登入、不進到主機內部檢查、不猜密碼、不試預設帳號，也不做可能中斷或壓垮服務的檢查。辨識不出服務時，這些測試就不會執行，報告會把該主機列為未測試。

### 原本的工具能做什麼

Greenbone OpenVAS Scanner 執行 feed 中的弱點測試，透過服務辨識與測試依賴判斷適用性。引擎與 feed 是分開的輸入；相同引擎搭配不同日期的 feed，具備的偵測知識也不同。

### 這個程式會檢查什麼

OpenVAS Scanner 23.50.24 使用以 feed202610010558 識別的固定 Community Feed 快照。remote-safe profile 納入未棄用、無需驗證的 gather_info 測試，再由上游前置條件選擇適用工作。每個工作綁定一份精確主機／連接埠授權；原始 OID、family、嚴重度、證據與解法在標準化及復原後仍保留。

### 哪些不在檢查範圍內

不啟用憑證、本機安全檢查、暴力／預設帳號檢查、破壞／阻斷服務類別或其他連接埠掃描器。排程了 feed profile 不代表每個 VT 都執行；目前上游結果 API 沒有完整逐 VT 執行帳本。

### 為什麼選用

它為內部系統提供有意義的協定、服務相關安全檢查。產品辨識與弱點邏輯由上游負責，產品無需自行維護各廠牌 wrapper 分支。

### 什麼情況下使用

適合已授權伺服器、工作站或網路設備，使用前選定精確 TCP 連接埠。新手 profile 提供常見連接埠，管理者可為同一主機檢視另一份有界清單。

### 報告會呈現什麼

範例保留原生 XML 弱點測試結果，包含 OID 與遠端證據；主機、錯誤或盤點紀錄不會自動轉成弱點。

### 優勢

Feed 與上游依賴系統支持依服務選擇適用測試；精確 OID、解法與範圍授權，讓結果可追溯到偵測器及核准端點。

### 弱點

整套服務與 feed 是較大的運作輸入。未驗證遠端證據不能取代具身分驗證的修補底冊；零發現也無法證明整台主機或整份 feed 都受測。

### 機會

可由探索觀察準備適用安全檢查，再在修正複驗時比較原生 OID。經檢視的 feed 更新能擴大涵蓋範圍，adapter 仍保持薄層。

### 威脅

Feed 時效、服務指紋變化與被過濾的網路回應都會影響適用性；其他 VT 類別可能有不同操作影響，因此更新 feed 時須維持已採納的 remote-safe profile。

### 版本紀錄

| 項目 | 2026-10-04 提供 |
| --- | --- |
| 引擎版本（目錄紀錄） | 23.50.24 |
| 映像標籤 | 23.50.24-feed202610010558-1 |
| 固定來源提交日期（UTC） | 2026-08-31T11:14:24Z |
| 原始碼版本 | 26465a11ff0e6a98d60a253265fab5974fc757b6 |
| 規則／檢查 | Greenbone Community Feed vulnerability tests |
| 規則版本 | 816c24126e0375d32c667b78d20342ce7c58ec58 |
| 資料輸入 | Greenbone Community Feed and Notus snapshot |
| 資料版本 | 816c24126e0375d32c667b78d20342ce7c58ec58 |
| 目錄知識基準日期 | 2026-08-24 |
| Adapter 版本 | 0.2.6 |
| 輸出格式 | XML |

映像識別: `ghcr.io/teddashh/ai-security-scanner-engine-greenbone:23.50.24-feed202610010558-1@sha256:d2e95d252272488891d04766e66362aacb234e1e2975dca27e834f0050a695c4`

## ZAP

瀏覽一個核准網站的頁面並檢查回應，不會送出表單或攻擊內容。

[Upstream](https://github.com/zaproxy/zaproxy) · [README @ 2665d97](https://github.com/zaproxy/zaproxy/blob/2665d972f6d587ba4773a95053ac39af3fdf8df9/README.md) · [整合與更新筆記](https://github.com/TED-H-com/ai-security-scanner/blob/335d0666bdc63eb86e6c8c4cddeae110db893397/docs/engines/zap.md)

### 工具介紹

ZAP（Zed Attack Proxy，也就是大家熟悉的 OWASP ZAP）是開源的網站應用程式安全掃描工具，也是同類工具中最受歡迎且備受信任的工具之一。上游的 ZAP 可以站在瀏覽器與網站之間、爬取頁面、檢查每一個回應，也能主動送出攻擊內容。它的被動規則只讀取回應，包括標頭與 cookie，不發動攻擊。我們把它放進本程式，是因為這些被動規則能幫你在它走得到的頁面上，找出缺少安全標頭、cookie 設定不安全這類問題，和 Nuclei 互補。在本程式裡它是選用的：只在固定限制內爬一個核准的網站，不登入、不送出表單、不送攻擊內容，也不跟著連結到其他網站。預設的網站檢查仍是 Nuclei。

### 原本的工具能做什麼

ZAP 是網站應用安全測試專案，具有代理、爬取、被動及主動測試功能。被動掃描分析觀察到的訊息，是完整上游工具中的一部分。

### 這個程式會檢查什麼

官方 2.17.0 映像提供 pscanrules 75.0.0 被動規則。可選 zap_passive_v1 automation plan 爬取一個核准來源，使用上游每秒 5 次請求節奏、5 個 spider thread、10 秒請求逾時，爬取與被動處理各有 2 分鐘上限、深度 5、每頁最多 100 個子項目；警示保留全部原生實例。

### 哪些不在檢查範圍內

此 profile 不登入、不送出表單、不傳主動攻擊內容，也不進入其他來源。它是進階選項中的明確選擇，快速預設仍為 Nuclei。限速沿用上游節奏控制，不宣稱嚴格滾動一秒視窗保證。

### 為什麼選用

ZAP 補上回應層檢查與有界連結探索，與範本驅動的 Nuclei 互補。保留警示及每個實例，讓多頁面證據可供核對，也不必重寫被動規則。

### 什麼情況下使用

當你要檢視自有單一來源內可達頁面的標頭、cookie 與其他被動回應指標時使用；尤其適合網站伺服器或回應政策變更後。

### 報告會呈現什麼

範例保留原生 ZAP 警示 ID、風險／信心值及各 URL 實例；同一警示的多個實例會保留可查閱的出現位置。

### 優勢

被動規則能提供來自回應訊息的具體證據；保留實例有助維護者找到每個觀察到的位置，而不只收到警示總數。

### 弱點

它只看到爬取限制內取得的回應；登入頁面後方內容、應用狀態與主動利用行為不在此 profile 內。爬取仍會向網站送出實際讀取請求。

### 機會

可比較標頭／cookie 修改前後的被動發現，並依資產和程式碼、Nuclei 發現一起閱讀；未來新增 profile 時，需要各自檢視行為與授權。

### 威脅

大量依賴 JavaScript 的導覽、WAF 行為及有限爬取時間可能隱藏頁面；add-on 變更會影響規則或請求處理，因此同時記錄官方映像與內附 add-on 版本。

### 版本紀錄

| 項目 | 2026-10-04 提供 |
| --- | --- |
| 引擎版本（目錄紀錄） | 2.17.0 |
| 映像標籤 | 2.17.0 |
| 固定來源提交日期（UTC） | 2026-08-06T08:30:53Z |
| 原始碼版本 | 2665d972f6d587ba4773a95053ac39af3fdf8df9 |
| 規則／檢查 | zaproxy/zap-extensions pscanrules |
| 規則版本 | pscanrules-75.0.0 |
| 資料輸入 | authorized service responses |
| 資料版本 | 無／執行時輸入 |
| 目錄知識基準日期 | 2026-08-07 |
| Adapter 版本 | 0.2.6 |
| 輸出格式 | JSON |

映像識別: `ghcr.io/zaproxy/zaproxy:2.17.0@sha256:781a2bdaea47324e7bab583e2263f21d257b0aee61ed51521a5be45f5f5081ef`

## Semgrep

依照本版提供的規則，找出程式碼中可能不安全的寫法。

[Upstream](https://github.com/semgrep/semgrep) · [README @ a0c13f3](https://github.com/semgrep/semgrep/blob/a0c13f304151e531c7e7c00838076211a07a790c/README.md) · [整合與更新筆記](https://github.com/TED-H-com/ai-security-scanner/blob/335d0666bdc63eb86e6c8c4cddeae110db893397/docs/engines/semgrep.md)

### 工具介紹

Semgrep 是一套廣泛使用的開源靜態應用程式安全測試（SAST）工具，也就是不編譯、不執行專案，直接檢查程式碼裡的安全問題。一般的文字搜尋只看字面，換行、空白不同或變數改名，都可能讓同一種寫法躲過去；Semgrep 則會把程式碼解析成語法樹（程式碼的結構），比對的是結構而不是字面。本程式使用的是社群版（Community Edition），追蹤不受信任資料流向的規則，只會在同一個函式內追蹤。我們把它放進本程式，是因為它能幫你很快找出有風險的寫法，例如不安全的指令呼叫，或直接拿使用者輸入組成的資料庫查詢；使用的是本程式內附的安全規則包，不是目前完整的規則庫。

### 原本的工具能做什麼

Semgrep 以宣告式規則分析原始碼。語言支援、規則選擇與 Community Edition 能力，決定能在不編譯、不執行目標專案的情況下觀察什麼。

### 這個程式會檢查什麼

固定 CE 來源建成 1.174.0-4，包含 1,493 個選定的早期上游安全規則與 4 個產品規則，共 1,497 個唯一 ID。規則包離線內嵌並保留來源追溯；JSON 結果保留規則 ID、檔案／行號、上游嚴重度、訊息、信心及可用修正／CWE 細節。

### 哪些不在檢查範圍內

這不是目前完整 Semgrep registry，也不是 Semgrep Pro 部署。不納入不可用或專有 parser 依賴及未選規則類別；不執行專案快照。解析錯誤或不支援檔案會形成涵蓋缺口。

### 為什麼選用

它補上相依套件與祕密掃描無法取代的程式碼層證據。規則訊息與位置能直接導向開發者的修正工作，偵測器仍由上游負責。

### 什麼情況下使用

適合儲存庫或 AI 應用程式碼快照，可於審查前或高風險實作變更後使用；尤其有助檢視不安全程序呼叫、輸入處理及固定規則包涵蓋的其他模式。

### 報告會呈現什麼

範例顯示透過 shell 呼叫子程序，附原生規則 ID、檔案位置、CWE 與工具提供的修正；資料採用 adapter 實際支援的 Semgrep JSON 形狀，原始碼背景為模擬。

### 優勢

原始碼位置與明確規則訊息有利修正；離線內嵌規則提供可重現的偵測依據，分析無需上傳儲存庫。

### 弱點

模式命中依賴支援語法與可取得背景，部分需要人工判讀。固定早期規則包有明確日期，不會自動繼承每個新上游規則或付費分析功能。

### 機會

可結合 Gitleaks／TruffleHog 祕密與套件發現來解釋應用風險；規則更新可透過精確原始來源 ID 與代表性原生輸出審阅。

### 威脅

語言變更、生成程式碼與缺少依賴可能降低背景資訊；規則散布條件及 parser 可用性也會限制更新，因此必須明確記錄規則包組成與來源。

### 版本紀錄

| 項目 | 2026-10-04 提供 |
| --- | --- |
| 引擎版本（目錄紀錄） | source@a0c13f304151e531c7e7c00838076211a07a790c |
| 映像標籤 | 1.174.0-4 |
| 固定來源提交日期（UTC） | 2026-08-20T18:29:37Z |
| 原始碼版本 | a0c13f304151e531c7e7c00838076211a07a790c |
| 規則／檢查 | semgrep/semgrep-rules legacy security selection plus four product rules |
| 規則版本 | 0f5a85ceab1b82b193d0eaa418784c932d237d68 |
| 資料輸入 | repository or filesystem snapshot |
| 資料版本 | case_artifact_sha256 |
| 目錄知識基準日期 | 2026-08-24 |
| Adapter 版本 | 0.2.6 |
| 輸出格式 | JSON / SARIF |

映像識別: `ghcr.io/teddashh/ai-security-scanner-engine-semgrep:1.174.0-4@sha256:3f1a10c7bce32eae912479c5744dbb653bdfa9a4cbd3d53afd2e0a435b10fb59`

## Gitleaks

找出專案檔案裡可能留下的密碼與金鑰，報告會隱藏它們的內容。

[Upstream](https://github.com/gitleaks/gitleaks) · [README @ 83d9cd6](https://github.com/gitleaks/gitleaks/blob/83d9cd684c87d95d656c1458ef04895a7f1cbd8e/README.md) · [整合與更新筆記](https://github.com/TED-H-com/ai-security-scanner/blob/335d0666bdc63eb86e6c8c4cddeae110db893397/docs/engines/gitleaks.md)

### 工具介紹

Gitleaks 是一套開源工具，也是最受歡迎且備受信任的密碼與金鑰掃描工具之一，用來找出寫死在專案檔案裡的密碼、API 金鑰、token 與其他憑證。它的規則認得許多已知金鑰的格式，有些規則還會參考附近的字詞，或字串看起來有多隨機。上游的 Gitleaks 也能搜尋儲存庫的 Git 歷史，就算金鑰後來刪掉了也找得到。我們把它放進本程式，是因為它能幫你很快找出你所選專案裡留下的密碼與金鑰。這裡只讀取目前檔案的唯讀副本，不搜尋已刪除的 Git 歷史，也不測試憑證是否仍然有效，報告也會遮蔽密碼與金鑰本身。

### 原本的工具能做什麼

Gitleaks 透過掃描器自有規則與模式背景偵測祕密。上游支援比此處檔案快照更廣的工作流程，因此判讀搜尋範圍時需要知道掃描模式。

### 這個程式會檢查什麼

原生 8.30.1 封裝為 8.30.1-2，使用固定預設設定掃描唯讀儲存庫快照。Adapter 保留規則、檔案、行號、fingerprint 與遮蔽證據。-2 映像修正建置流程的測試資料複製，沒有替換原生偵測邏輯。

### 哪些不在檢查範圍內

此路徑不搜尋已刪除 Git 歷史、不驗證憑證是否有效、不撤銷金鑰，也不上傳檔案。完整範例仍保留 adapter 對祕密值的隱藏；完整揭露指資產與背景欄位。

### 為什麼選用

祕密曝露是高價值的第一類檢查，而且不需執行專案程式碼。Gitleaks 提供具體檔案／行號證據，可與 TruffleHog 的偵測器類別互補。

### 什麼情況下使用

適合分享原始碼前、加入環境或設定檔後，以及 AI 專案檢視時使用。祕密模式被回報後，由負責人確認；若屬真實祕密，再依組織流程輪替。

### 報告會呈現什麼

範例使用合成 API key 樣式值；發現會顯示 Gitleaks 來源與位置，而值在兩種報告中都保持隱藏。

### 優勢

聚焦的離線掃描提供容易定位的證據，不需雲端存取權限；穩定 fingerprint 有助和後續掃描比較。

### 弱點

模式可能命中範例或測試 token，也可能漏掉未知格式或動態組合的祕密。掃描工作目錄快照無法找回已從快照移除的內容。

### 機會

可結合兩套獨立祕密偵測器，保留各自原始規則，再由共用報告整理修正；重複使用相同快照 profile 能核對原始碼曝露是否移除。

### 威脅

新憑證格式、被忽略或未納入檔案，以及混淆祕密會降低涵蓋範圍。把完整祕密印進報告會形成第二次曝露，因此隱藏值仍是產品界線。

### 版本紀錄

| 項目 | 2026-10-04 提供 |
| --- | --- |
| 引擎版本（目錄紀錄） | 8.30.1 |
| 映像標籤 | 8.30.1-2 |
| 固定來源提交日期（UTC） | 2026-03-12T15:40:37Z |
| 原始碼版本 | 83d9cd684c87d95d656c1458ef04895a7f1cbd8e |
| 規則／檢查 | scanner-owned Gitleaks default configuration |
| 規則版本 | sha256:e163e53b9e7e8a8511e77271e2b323ed057759542a6d988258afe3a1fa329caf |
| 資料輸入 | repository or filesystem snapshot |
| 資料版本 | case_artifact_sha256 |
| 目錄知識基準日期 | 2026-08-24 |
| Adapter 版本 | 0.2.6 |
| 輸出格式 | JSON |

映像識別: `ghcr.io/teddashh/ai-security-scanner-engine-gitleaks:8.30.1-2@sha256:95313654f9c37115a906629a82113ba6e1c729950be70909da8362e9482b477e`

## TruffleHog

在本機檔案裡找出可能外洩的密碼與金鑰，不會拿它們登入服務。

[Upstream](https://github.com/trufflesecurity/trufflehog) · [README @ 3ab759f](https://github.com/trufflesecurity/trufflehog/blob/3ab759fef4bb5935d4fe9ac68b503d05346b8364/README.md) · [整合與更新筆記](https://github.com/TED-H-com/ai-security-scanner/blob/335d0666bdc63eb86e6c8c4cddeae110db893397/docs/engines/trufflehog.md)

### 工具介紹

TruffleHog 是一套開源工具，也是最受歡迎且備受信任的密碼與金鑰掃描工具之一，用來找出 API 金鑰、token 這類可能外洩的憑證。它為許多種憑證各準備了專屬的偵測器。上游的 TruffleHog 還能向對應的線上服務確認找到的金鑰是否有效，也能搜尋 Git 歷史。我們把它放進本程式，是因為它能幫你很快找出目前檔案裡的密碼與金鑰，偵測器也和 Gitleaks 互補。這裡會關閉網路，只讀取這些檔案的唯讀副本，不搜尋 Git 歷史，也不拿憑證去線上服務測試。找到結果不代表金鑰仍然有效，報告也不會放上金鑰內容。

### 原本的工具能做什麼

TruffleHog 為多種憑證類型提供偵測器，並支援多種來源與驗證流程。本產品的本機掃描刻意關閉上游線上有效性驗證。

### 這個程式會檢查什麼

固定來源封裝於 3.97.0-3，在停用網路下，對一份不可變儲存庫工作目錄快照執行 filesystem profile。JSONL 發現保留偵測器識別、位置與可用驗證狀態，原始祕密不進入一般證據內容。

### 哪些不在檢查範圍內

此 profile 不進行線上金鑰驗證、provider 登入、Git 歷史遍歷、遠端來源連接或憑證修復；未驗證命中不會被改標為已確認有效憑證。

### 為什麼選用

它的偵測器集合可與 Gitleaks 互補檢視祕密曝露。明確保留驗證狀態，讓讀者取得有用證據，同時理解原生結果支持到什麼程度。

### 什麼情況下使用

適合含應用設定、整合程式碼或 AI 服務 client 的儲存庫快照；可在散布程式碼前，或檢視意外納入憑證時使用。

### 報告會呈現什麼

範例包含檔案系統背景中的偵測器命中，保留原生偵測器名稱與驗證狀態，祕密內容仍受保護。

### 優勢

類型化原生偵測器與逐行輸出提供清楚來源；離線執行讓疑似憑證不會被送到外部驗證端點。

### 弱點

停用驗證會降低對命中是否仍有效的確定性；重疊偵測器也可能回報同一曝露。不支援格式、動態值及未納入歷史仍是涵蓋限制。

### 機會

可對照 Gitleaks 證據與應用負責人，在團隊輪替真實憑證後確認原始碼曝露已移除；未來增加來源類型需獨立檢視範圍。

### 威脅

憑證格式與 provider 驗證行為會演進；未來更新須保留不做線上驗證的界線及遮蔽行為，不能默默啟用網路檢查。

### 版本紀錄

| 項目 | 2026-10-04 提供 |
| --- | --- |
| 引擎版本（目錄紀錄） | source@3ab759fef4bb5935d4fe9ac68b503d05346b8364 |
| 映像標籤 | 3.97.0-3 |
| 固定來源提交日期（UTC） | 2026-08-21T14:53:01Z |
| 原始碼版本 | 3ab759fef4bb5935d4fe9ac68b503d05346b8364 |
| 規則／檢查 | TruffleHog detectors |
| 規則版本 | 3ab759fef4bb5935d4fe9ac68b503d05346b8364 |
| 資料輸入 | repository or filesystem snapshot |
| 資料版本 | case_artifact_sha256 |
| 目錄知識基準日期 | 2026-08-24 |
| Adapter 版本 | 0.2.6 |
| 輸出格式 | JSONL |

映像識別: `ghcr.io/teddashh/ai-security-scanner-engine-trufflehog:3.97.0-3@sha256:dd0e0879bc4d3ac79194d6c734d2a2636cc83fdacb01f611b6b3284fe86dd55a`

## Checkov

檢查支援的部署與基礎設施設定檔，找出不安全的設定。

[Upstream](https://github.com/bridgecrewio/checkov) · [README @ 0604e97](https://github.com/bridgecrewio/checkov/blob/0604e97b0f77c89a8c6c1fe2219c3d251cbb9789/README.md) · [整合與更新筆記](https://github.com/TED-H-com/ai-security-scanner/blob/335d0666bdc63eb86e6c8c4cddeae110db893397/docs/engines/checkov.md)

### 工具介紹

Checkov 是一套廣泛使用的開源工具，專門檢查基礎設施即程式碼（IaC），也就是描述雲端資源與部署該怎麼設定的檔案。它把這些檔案讀成資源以及資源之間的關係，而不是一段純文字，再用一套安全政策逐一檢查。我們把它放進本程式，是因為它能幫你在真正部署之前，很快找出 Terraform、CloudFormation 與 Dockerfile 等檔案裡不安全的設定。這裡只讀取你所選專案的唯讀副本，不連接雲端帳號、不下載平台政策資料，也不套用這些檔案，所以結果描述的是檔案本身，不是線上環境實際的狀態。

### 原本的工具能做什麼

Checkov 對基礎設施即程式碼、容器設定與交付流程提供政策檢查，理解資源及其關聯，而非只把檔案當成文字。

### 這個程式會檢查什麼

唯讀掛載所選儲存庫或 IaC 工作目錄。Checkov 3.3.13 內附檢查會自動選擇適用框架，包括 Terraform、CloudFormation 與 Dockerfile。產品啟用框架辨識，取得精簡 JSON 失敗結果，並停用平台中繼資料下載。

### 哪些不在檢查範圍內

此設定不連接雲端帳號、不套用 Terraform、不下載平台政策資料，也不包含上游商業平台。離線缺少嚴重程度時保留 Unknown。解析失敗與原始碼內的略過註解需要特別留意：目前 adapter 尚未把 Checkov 摘要計數完整轉換成涵蓋範圍紀錄。

### 為什麼選用

選用原因是它能跨常見部署格式評估政策，並保留精確的上游檢查 ID 與資源位置。它補足程式碼分析及相依套件比對：套件漏洞與不安全的儲存政策是需要不同證據的問題。

### 什麼情況下使用

適合選取含基礎設施或建置設定的專案，在部署前及設定變更後執行。無法即時存取雲端環境時，仍可先檢查部署定義。

### 報告會呈現什麼

每個失敗檢查保留 check_id、名稱、檔案、起始行與資源。範例包含兩筆失敗檢查。原生程式碼區塊保存在底層證據；可讀報告呈現位置、下一步與上游連結，不補造掃描器未提供的嚴重程度。

### 優勢

支援多種基礎設施格式，並能依資源檢查，適合及早介入交付流程。穩定的檢查 ID 方便追溯上游政策，修正後再檢查同一資源。

### 弱點

靜態設定無法確認實際部署狀態；未解析變數或缺少模組會減少資訊。離線操作缺少多數平台提供的評級與指引；處理成功並不代表每個檔案或規則都已評估。

### 機會

可搭配 Prowler 或 ScoutSuite 的部署帳號觀察，並分別保留來源。KICS 也能對同一批所選檔案提供另一種政策檢查觀點。

### 威脅

基礎設施語法與雲端預設值會改變。固定政策套件可能漏掉新服務，過於寬鬆的略過註解也可能遮蔽重要檢查。更新引擎時，應包含產品實際使用格式的代表性檔案。

### 版本紀錄

| 項目 | 2026-10-04 提供 |
| --- | --- |
| 引擎版本（目錄紀錄） | 3.3.13 |
| 映像標籤 | 3.3.13-1 |
| 固定來源提交日期（UTC） | 2026-08-20T09:39:24Z |
| 原始碼版本 | 0604e97b0f77c89a8c6c1fe2219c3d251cbb9789 |
| 規則／檢查 | Checkov checks |
| 規則版本 | 0604e97b0f77c89a8c6c1fe2219c3d251cbb9789 |
| 資料輸入 | repository working-tree snapshot |
| 資料版本 | case_artifact_sha256 |
| 目錄知識基準日期 | 2026-08-24 |
| Adapter 版本 | 0.2.6 |
| 輸出格式 | JSON / SARIF / CYCLONEDX |

映像識別: `ghcr.io/teddashh/ai-security-scanner-engine-checkov:3.3.13-1@sha256:0ecc187b17faa9c538c9b1ecc08a4195283290222694d0f87d50016f2bb79b35`

## KICS

檢查用來部署系統的設定檔，找出可能造成風險的設定。

[Upstream](https://github.com/Checkmarx/kics) · [README @ e1f23ca](https://github.com/Checkmarx/kics/blob/e1f23cad9640f55b963f22a116b04906b8c16ac6/README.md) · [整合與更新筆記](https://github.com/TED-H-com/ai-security-scanner/blob/335d0666bdc63eb86e6c8c4cddeae110db893397/docs/engines/kics.md)

### 工具介紹

KICS（Keeping Infrastructure as Code Secure）來自 Checkmarx，是一套開源工具，用來找出基礎設施即程式碼（IaC）裡不安全的設定；IaC 就是描述系統要怎麼部署的檔案。它用一套安全查詢檢查 Terraform、CloudFormation、Kubernetes 設定檔與 Dockerfile 等格式，並把每筆結果對應到檔案與行號；內附的查詢也會找出檔案裡留下的密碼與金鑰。我們把它放進本程式，是因為它能幫你很快找出有風險的部署設定，查詢庫和 Checkov 各自獨立，能提供第二種觀點。這裡用工具內附的查詢掃描你所選專案的唯讀副本，不連接雲端帳號，也不另外下載查詢。

### 原本的工具能做什麼

KICS 透過安全查詢庫評估 Terraform、CloudFormation、Kubernetes、Dockerfile 等格式的基礎設施定義，將每個查詢結果連到個別檔案位置。

### 這個程式會檢查什麼

產品使用未修改、固定 digest 的 KICS 2.1.20 上游映像，掃描單一唯讀儲存庫或 IaC 快照。執行內附查詢，包括機密資料查詢，且不排除任何嚴重程度。JSON 輸出提供查詢說明與檔案層級證據。

### 哪些不在檢查範圍內

不部署雲端資源、不檢查即時帳號，也不下載外部查詢。未啟用上游可選的 BOM 查詢。停用網路，因此外部說明或版本查詢不會擴充內附資料。

### 為什麼選用

KICS 提供以查詢為基礎的基礎設施風險觀點，同時保留原生查詢 UUID、嚴重程度與原始碼位置。檔案及查詢失敗計數也協助區分已完成的檢查與未完整處理的工作。

### 什麼情況下使用

適合套用基礎設施變更前，或檢查包含部署定義的儲存庫時使用。與 Checkov 並行時，不同查詢庫可涵蓋不同設定錯誤。

### 報告會呈現什麼

範例有一筆設定發現。每筆結果保留查詢 ID、名稱、原生嚴重程度、檔案、行號、說明，以及可用的 CWE 或查詢網址。檔案或查詢失敗計數會讓工作維持未完成狀態，同時保留其他有效發現。

### 優勢

精確的檔案位置與原生說明，方便在變更審查中修正。直接執行未修改的上游映像，讓偵測器與內附查詢維持接近上游。

### 弱點

檔案層級政策結果可能缺少執行環境資訊，行內略過指令也會縮小檢查範圍。多個工具可能回報相似問題；統一呈現仍須保留不同的原生觀察。

### 機會

可對同一資產整合 KICS、即時雲端態勢及相依套件結果。查詢網址讓維護者直接理解規則，並向上游提出改善。

### 威脅

新的 IaC 功能、供應商預設值變更及查詢回歸問題，都可能影響適用性。更新固定映像時，除了可見發現，也需檢查輸出格式與失敗計數。

### 版本紀錄

| 項目 | 2026-10-04 提供 |
| --- | --- |
| 引擎版本（目錄紀錄） | 2.1.20 |
| 映像標籤 | v2.1.20 |
| 固定來源提交日期（UTC） | 2026-03-03T17:56:16Z |
| 原始碼版本 | e1f23cad9640f55b963f22a116b04906b8c16ac6 |
| 規則／檢查 | KICS queries |
| 規則版本 | e1f23cad9640f55b963f22a116b04906b8c16ac6 |
| 資料輸入 | IaC project snapshot |
| 資料版本 | case_artifact_sha256 |
| 目錄知識基準日期 | 2026-08-24 |
| Adapter 版本 | 0.2.6 |
| 輸出格式 | JSON / SARIF |

映像識別: `checkmarx/kics:v2.1.20@sha256:3e5a268eb8adda2e5a483c9359ddfc4cd520ab856a7076dc0b1d8784a37e2602`

## Trivy

用內附的漏洞資料庫，檢查支援的專案與容器套件。

[Upstream](https://github.com/aquasecurity/trivy) · [README @ e1fd17a](https://github.com/aquasecurity/trivy/blob/e1fd17a0ea4a8cf24bc4b4dd7e2cfbf4bb31b994/README.md) · [整合與更新筆記](https://github.com/TED-H-com/ai-security-scanner/blob/335d0666bdc63eb86e6c8c4cddeae110db893397/docs/engines/trivy.md)

### 工具介紹

Trivy 來自 Aqua Security，是一套開源的資安掃描工具，也是最受歡迎且備受信任的套件弱點掃描工具之一。它會讀取認得出的相依套件檔，以及 JAR 這類個別的 Java 套件檔，再把版本拿去和漏洞資料庫裡的公開公告比對；這些公告通常是 CVE，也就是已知漏洞的標準編號。上游的 Trivy 還能檢查設定與密碼金鑰。我們把它放進本程式，是因為它能幫你很快找出已知有漏洞的套件；資料庫列有修正版本時，也會一併告訴你。這裡只執行漏洞檢查，使用本程式內附的資料庫。檢查容器映像時只看作業系統套件，映像裡的應用程式函式庫交給 Grype 檢查。

### 原本的工具能做什麼

Trivy 對多種目標提供漏洞、錯誤設定、機密資料等安全檢查。本整合明確選用其中的漏洞掃描器及固定離線資料庫。

### 這個程式會檢查什麼

儲存庫及 IaC 快照執行兩個上游步驟：filesystem 分析語言套件清單與鎖定檔，再由 rootfs 分析 JAR 等獨立套件。所選 OCI 映像配置接受作業系統套件漏洞檢查。不可變更的漏洞與 Java 資料庫內附於受管映像。 漏洞資料庫更新日為 2026-08-24，獨立 Java 辨識索引為 2026-09-09。較新的 Java 索引不代表漏洞公告資料庫也較新。

### 哪些不在檢查範圍內

呼叫僅使用 --scanners vuln，未啟用 Trivy 的機密資料、設定及授權掃描。OCI 映像內的語言套件由獨立的 Grype 設定涵蓋，不屬於此 Trivy OCI 呼叫。掃描期間不更新資料庫。

### 為什麼選用

Trivy 提供公告 ID、已安裝與修正版、供應商評分及套件位置，可轉成實用升級指引。儲存庫的兩步設定使用上游分析器，不在 adapter 重新實作套件偵測。

### 什麼情況下使用

適合含相依資訊的專案、含受支援封裝函式庫的目錄，或所選容器映像。相依套件改變，或產品取得更新漏洞資料庫後，適合重新執行。

### 報告會呈現什麼

範例包含四筆發現。原生漏洞 ID、嚴重程度、受影響套件與版本、修正版、公告連結，以及可用的 CVSS/CWE 資料均保留 Trivy 來源。上游提供修正版時便呈現，缺少時不猜測升級版本。

### 優勢

套件層級修正資訊與多種生態系分析，能形成可採取行動的相依套件報告。內附資料庫讓結果可重現，無須把專案檔案送到遠端掃描服務。

### 弱點

版本比對不能確認應用程式是否會走到弱點程式碼，或是否能被利用。缺少中繼資料可能妨礙辨識，離線結果也受內附資料庫日期限制。

### 機會

可與 Grype 比較，並透過 Syft 盤點理解套件組成。程式碼檢查可補充應用脈絡；報告可呈現共通修正方向，同時保留雙方上游觀察。

### 威脅

新公告、撤回的 CVE、發行版回補修正及套件名稱歧義，都可能改變比對結果。引擎升級與資料庫更新必須分別記錄，讓讀者知道結果使用哪一份知識快照。

### 版本紀錄

| 項目 | 2026-10-04 提供 |
| --- | --- |
| 引擎版本（目錄紀錄） | 0.74.0 |
| 映像標籤 | 0.74.0-4 |
| 固定來源提交日期（UTC） | 2026-08-14T10:24:58Z |
| 原始碼版本 | e1fd17a0ea4a8cf24bc4b4dd7e2cfbf4bb31b994 |
| 規則／檢查 | Trivy OS and library package analyzers |
| 規則版本 | e1fd17a0ea4a8cf24bc4b4dd7e2cfbf4bb31b994 |
| 資料輸入 | Trivy vulnerability database snapshot |
| 資料版本 | sha256:a61aa42edc534843230ca24ef72ef322a2da18d717c3de4b6277f4aac43926a1 |
| 目錄知識基準日期 | 2026-08-24 |
| Adapter 版本 | 0.2.6 |
| 輸出格式 | JSON / SARIF / CYCLONEDX / SPDX-JSON |

映像識別: `ghcr.io/teddashh/ai-security-scanner-engine-trivy:0.74.0-4@sha256:9bfcef9a6a9d9a69eefcece06b0670eaed72541656b65155469b41acb3855dc2`

## Grype

使用內附資料庫，找出支援的專案與容器套件是否有已知漏洞。

[Upstream](https://github.com/anchore/grype) · [README @ b5fa92b](https://github.com/anchore/grype/blob/b5fa92bbcbef655497e3be840a2f718380e2cdd3/README.md) · [整合與更新筆記](https://github.com/TED-H-com/ai-security-scanner/blob/335d0666bdc63eb86e6c8c4cddeae110db893397/docs/engines/grype.md)

### 工具介紹

Grype 來自 Anchore，是一套廣泛使用的開源工具，用來把軟體套件對上已知漏洞。它拿套件名稱與版本去比對漏洞資料庫，回報對應的公告，例如 CVE（已知漏洞的標準編號）或 GitHub 安全公告；資料庫若列有修正版本，也會一併呈現。我們把它放進本程式，是因為它能幫你很快找出所選專案或容器映像裡已知有漏洞的套件；檢查映像時，應用程式函式庫和作業系統套件都包含在內。即使 Trivy 也回報同一個問題，報告仍會標明各是哪個工具找到的。這裡使用本程式內附的資料庫，不會自己從 registry 下載映像，也不會執行容器。

### 原本的工具能做什麼

Grype 將軟體元件與漏洞資料比對，回報受影響套件、公告及可用修正，支援套件目錄、檔案目錄與容器相關輸入。

### 這個程式會檢查什麼

受管設定以固定離線資料庫掃描所選儲存庫快照及單一映像 OCI 配置。OCI 設定包含作業系統與語言套件，也包含受支援的 JAR 內容，補足 Trivy 僅檢查 OCI 作業系統套件的設定。輸出採原生 Grype JSON。 內附資料庫採用 schema 6.1.9，建置日為 2026-08-24。

### 哪些不在檢查範圍內

此設定不任意拉取登錄站、不執行容器、不在執行中更新資料庫，也不證明可利用性。不會直接升級套件。取得登錄站內容及選擇已核准 OCI 快照，與漏洞比對是分開的步驟。

### 為什麼選用

Grype 提供獨立的公告比對觀點與實用的套件修正模型。與 Trivy 部分重疊是刻意安排：涵蓋範圍及公告解讀可能不同，報告說明相關結果時仍保留原始掃描器來源。

### 什麼情況下使用

適合檢查所選專案或容器映像的相依套件，尤其同時包含應用函式庫及作業系統套件的映像。升級後或取得新的內附公告快照後可重新執行。

### 報告會呈現什麼

範例包含四筆發現，保留漏洞 ID、原生嚴重程度、套件與已安裝版本、上游提供的修正版及公告證據。相似的 Trivy 比對仍可分別追溯；共通發現視圖不應把不同引擎比對誤算成額外受影響資產。

### 優勢

專注漏洞比對，提供實用的套件與修正資訊。離線呼叫讓分析可重現，OCI 語言套件涵蓋範圍則補足搭配的 Trivy 設定。

### 弱點

套件辨識與公告比對可能存在歧義，尤其遇到供應商回補修正或不完整版本資訊。比對結果代表受影響版本的關聯證據，不是對執行中應用程式成功攻擊的證明。

### 機會

可利用 Syft 盤點與 Trivy 結果，追查缺少或矛盾的比對。在統一報告中整合相關修正方向，同時保留雙方的公告細節及來源位置。

### 威脅

公告資料庫老化與套件生態系變化，可能讓新問題未被涵蓋。資料庫結構變更也可能破壞原本有效的引擎與資料組合，升級時必須一起驗證。

### 版本紀錄

| 項目 | 2026-10-04 提供 |
| --- | --- |
| 引擎版本（目錄紀錄） | 0.117.0 |
| 映像標籤 | 0.117.0-4 |
| 固定來源提交日期（UTC） | 2026-08-10T16:05:15Z |
| 原始碼版本 | b5fa92bbcbef655497e3be840a2f718380e2cdd3 |
| 規則／檢查 | Grype matchers |
| 規則版本 | b5fa92bbcbef655497e3be840a2f718380e2cdd3 |
| 資料輸入 | Grype vulnerability database snapshot |
| 資料版本 | sha256:db6f590412955f6b58cec12bfa4b712b2626eef9a030bffd8f32b9ebce074ff8 |
| 目錄知識基準日期 | 2026-08-24 |
| Adapter 版本 | 0.2.6 |
| 輸出格式 | JSON / CYCLONEDX / SARIF |

映像識別: `ghcr.io/teddashh/ai-security-scanner-engine-grype:0.117.0-4@sha256:56b0d675e3b8d539890e853699c114493a72a54cca0bbe254eceee7ec2b4c517`

## Syft

列出專案或容器裡的軟體元件，幫你掌握用了哪些東西；清單本身不是漏洞報告。

[Upstream](https://github.com/anchore/syft) · [README @ 2293641](https://github.com/anchore/syft/blob/2293641e3bd628a01bb37639318d62c0ebe89b39/README.md) · [整合與更新筆記](https://github.com/TED-H-com/ai-security-scanner/blob/335d0666bdc63eb86e6c8c4cddeae110db893397/docs/engines/syft.md)

### 工具介紹

Syft 來自 Anchore，是一套廣泛使用的開源工具，用來建立軟體物料清單（SBOM），也就是列出專案或容器映像裡有哪些軟體元件的清單，例如函式庫與作業系統套件。它會記下每個認得出的元件名稱、版本與類型。我們把它放進本程式，是因為它能幫你很快看清所選專案或映像裡有哪些軟體，也就知道漏洞檢查看的是哪些東西。這份清單只說明有什麼，不是漏洞報告。這裡只讀取唯讀副本、不連網路，也不會從 registry 下載映像；已知漏洞交給 Trivy 與 Grype 檢查。

### 原本的工具能做什麼

Syft 辨識目錄與容器映像中的套件，產生軟體物料清單。元件盤點可供漏洞工具及供應鏈工作流程使用。

### 這個程式會檢查什麼

產品以 Syft 1.51.0 離線掃描唯讀儲存庫目錄或所選單一映像 OCI 配置。adapter 從原生 syft-json 記錄元件名稱、版本、類型及套件 URL。上游執行檔未修改；受管映像設定非 root 執行與暫存快取。

### 哪些不在檢查範圍內

Syft 在本產品中不產生漏洞發現。原生授權、CPE 及位置細節保留在原始證據，不轉成授權合規判定。任意遠端登錄站與自動修正不屬於此所選快照設定。

### 為什麼選用

我們需要區分「這裡有哪些軟體」與「哪些軟體有已知漏洞」。Syft 提供獨立的上游盤點來源，避免只從漏洞發現反推元件清單。

### 什麼情況下使用

儲存庫或容器評估需要了解完整元件組成時使用，包括漏洞工具沒有比對結果的情況。搭配 Grype 或 Trivy 才能進行實際公告檢查。

### 報告會呈現什麼

範例有兩筆元件觀察，安全發現為零。元件放在盤點區，並標示 Syft 來源。元件存在或盤點完成，不會被當成漏洞，也不代表資產安全。

### 優勢

專門的套件盤點提供更清楚的相依涵蓋範圍基礎。原生套件 URL 協助一致辨識同一元件，同時避免把盤點與風險混為一談。

### 弱點

套件清單不描述執行時可達性、部署權限或可利用性。不支援的生態系與缺少中繼資料可能讓元件未被辨識；空清單不證明沒有軟體。

### 機會

盤點可支援後續比較已儲存的評估，並協助說明漏洞比對器為何有或沒有辨識套件，也為相依套件移除與升級提供背景。

### 威脅

封裝慣例會改變，無法辨識新格式的掃描器可能無聲地看到較少軟體。大型盤點也可能超過輸入上限；部分盤點必須與完整元件概況清楚區分。

### 版本紀錄

| 項目 | 2026-10-04 提供 |
| --- | --- |
| 引擎版本（目錄紀錄） | 1.51.0 |
| 映像標籤 | 1.51.0-1 |
| 固定來源提交日期（UTC） | 2026-08-10T14:26:29Z |
| 原始碼版本 | 2293641e3bd628a01bb37639318d62c0ebe89b39 |
| 規則／檢查 | Syft catalogers |
| 規則版本 | 2293641e3bd628a01bb37639318d62c0ebe89b39 |
| 資料輸入 | repository working-tree snapshot |
| 資料版本 | case_artifact_sha256 |
| 目錄知識基準日期 | 2026-08-24 |
| Adapter 版本 | 0.2.6 |
| 輸出格式 | SYFT-JSON / CYCLONEDX-JSON / SPDX-JSON |

映像識別: `ghcr.io/teddashh/ai-security-scanner-engine-syft:1.51.0-1@sha256:805c9fe522113319f994f99cd68fcb5c18e322dd933e7d89f82cd91f5a5c8501`

## Kubescape

檢查你選好的 Kubernetes 設定檔，不會連到正在運作的叢集。

[Upstream](https://github.com/kubescape/kubescape) · [README @ 469969f](https://github.com/kubescape/kubescape/blob/469969f6bebf46bef5e808b91a4bb46fb2bbf4ed/README.md) · [整合與更新筆記](https://github.com/TED-H-com/ai-security-scanner/blob/335d0666bdc63eb86e6c8c4cddeae110db893397/docs/engines/kubescape.md)

### 工具介紹

Kubescape 是一套廣泛使用的開源工具，用來檢查 Kubernetes（許多團隊用來運行容器的系統）的設定。它把 YAML 與 JSON 檔案讀成 Kubernetes 資源，再對照一份固定的強化檢查清單，也就是根據美國 NSA 與 CISA 指引整理的 NSA 框架，所以每筆結果都會指出是哪個資源、哪一項控制沒有通過。上游的 Kubescape 也能掃描運作中的叢集與容器映像。我們把它放進本程式，是因為它能幫你很快找出所選 Kubernetes 設定檔裡有風險的設定。這裡只離線檢查那份已儲存的快照，不連到運作中的叢集，無法判斷檔案是否與實際部署一致，也不掃描容器套件。

### 原本的工具能做什麼

Kubescape 提供 Kubernetes 設定評估及更廣泛叢集工作流程的安全能力。本產品選用離線資源清單評估，搭配固定的框架與政策庫。

### 這個程式會檢查什麼

以固定 NSA 框架及內附 Rego 政策資料，評估所選 Kubernetes YAML/JSON 快照。網路停用。原生 JSON 資源與控制項結果，連同上游 ID、嚴重程度及證據送入 adapter。

### 哪些不在檢查範圍內

此設定不連接即時叢集、不安裝 operator、不檢查執行時流量，也不掃描容器套件。它不能確認已儲存清單與部署狀態是否一致。容器漏洞比對由 Trivy 與 Grype 負責。

### 為什麼選用

Kubernetes 專屬的資源與控制項語意，適合交由上游專業工具處理。固定的離線框架，讓所選檢查對一組已儲存清單而言可說明、可重現。

### 什麼情況下使用

適合部署前檢查 Kubernetes 清單，或審查匯出的設定快照。若同時關心工作負載設定與節點強化，可搭配 kube-bench 節點證據。

### 報告會呈現什麼

範例包含三筆原生控制項發現。即使其他結果格式錯誤、略過或失敗，有效的失敗控制項仍會保留；不完整證據不會變成無問題評估。報告保留受影響資源及原始控制項識別。

### 優勢

理解 Kubernetes 資源的檢查，能為清單變更提供精確背景。框架及政策版本與引擎分別固定，讀者可確認評估使用的確切知識版本。

### 弱點

快照缺少准入時變更、即時權限與執行行為。框架檢查涵蓋特定強化規則，不涵蓋叢集或應用程式的所有安全性質。

### 機會

可將工作負載發現、節點強化與映像漏洞結果整合到同一份依資產組織的報告。比較已儲存評估，可看出哪些設定變更解決了上游控制項。

### 威脅

Kubernetes API 演進及政策庫變更，可能讓舊檢查不完整或不適用。尚未展開的清單範本，也可能妨礙掃描器看到最終資源。

### 版本紀錄

| 項目 | 2026-10-04 提供 |
| --- | --- |
| 引擎版本（目錄紀錄） | 4.0.12 |
| 映像標籤 | 4.0.12-3 |
| 固定來源提交日期（UTC） | 2026-08-12T08:18:39Z |
| 原始碼版本 | 469969f6bebf46bef5e808b91a4bb46fb2bbf4ed |
| 規則／檢查 | Kubescape NSA framework and control artifacts |
| 規則版本 | a12188c49147bb6ec379b42a4159d3d5852634b8 |
| 資料輸入 | Kubernetes manifest snapshot |
| 資料版本 | case_artifact_sha256 |
| 目錄知識基準日期 | 2026-08-24 |
| Adapter 版本 | 0.2.6 |
| 輸出格式 | JSON |

映像識別: `ghcr.io/teddashh/ai-security-scanner-engine-kubescape:4.0.12-3@sha256:87c8e5c29c938aa39e304355b1c037b09bda9f89e130b3ccde6df3eaf7ee537c`

## kube-bench

依照 CIS 建議檢查節點設定的副本，不會取得管理員權限來檢查運作中的主機。

[Upstream](https://github.com/aquasecurity/kube-bench) · [README @ 9f133cb](https://github.com/aquasecurity/kube-bench/blob/9f133cb7509ce1dbedfc860e94474588000e25ac/README.md) · [整合與更新筆記](https://github.com/TED-H-com/ai-security-scanner/blob/335d0666bdc63eb86e6c8c4cddeae110db893397/docs/engines/kube-bench.md)

### 工具介紹

kube-bench 是 Aqua Security 維護、廣泛使用的開源工具，依照 CIS Kubernetes Benchmark 檢查 Kubernetes 節點，也就是實際運行工作負載的機器；CIS Benchmark 是網際網路安全中心（CIS）公開的安全設定檢查清單。它拿設定檔與執行中程序的資訊逐項比對，標成通過、失敗或警告；警告代表這項檢查需要自動化無法提供的資訊或判斷。上游的 kube-bench 會在運作中的節點上執行，也能檢查控制平面。我們把它放進本程式，是因為它能幫你很快找出不符合這份清單的節點設定。這裡只使用你匯出的節點資訊與節點檢查項目，不會登入運作中的主機，也不執行控制平面檢查。

### 原本的工具能做什麼

kube-bench 依 Kubernetes 設定及程序資訊執行基準檢查。原生結果包括 PASS、FAIL 與 WARN；部分檢查需要自動化無法提供的資訊或判斷。

### 這個程式會檢查什麼

產品將明確選取的匯出節點資訊快照，提供給未修改的 CIS 1.11 節點設定。現行型別化快照包含五個必要檔案與兩筆程序資訊。受限的轉接層提供原生檢查所需的已儲存檔案中繼資料及程序資訊。

### 哪些不在檢查範圍內

不包含特權主機掛載、即時節點連線、全叢集蒐集或控制平面基準。執行檔由固定原始碼版本建置並標記 0.16.0；此標記不代表採用了上游發布封存檔。

### 為什麼選用

上游基準已定義節點檢查與判定。提供明確資訊可維持上游邏輯，並以受限快照工作流程操作，無須讓桌面掃描器取得 Kubernetes 節點特權。

### 什麼情況下使用

有已核准節點資訊匯出，且需要評估節點設定時使用。工作負載清單另用 Kubescape；兩者結果不能互相替代。

### 報告會呈現什麼

原生範例包含 26 項檢查：15 項 PASS、6 項 FAIL、5 項 WARN。六項失敗形成發現；上游未評級，因此嚴重程度維持 Unknown。五項警告保留為未完整涵蓋，不算通過。

### 優勢

可識別的基準 ID 與原生修正建議，將發現連到具體節點控制項。快照重播讓證據可檢視，並避免在產品內重寫基準判定。

### 弱點

結果取決於匯出資訊是否新鮮且完整。人工或缺少資訊的檢查仍為 WARN；所選節點設定也不評估所有叢集元件。

### 機會

可並列節點失敗、工作負載設定及映像漏洞，分別保留來源與涵蓋範圍。變更後的新快照可提供具體證據，確認同一基準檢查是否通過。

### 威脅

基準版本、Kubernetes 發行版及程序參數變更，可能使快照契約的假設失效。更新時不可把缺少的資訊默默替換成可通過的值。

### 版本紀錄

| 項目 | 2026-10-04 提供 |
| --- | --- |
| 引擎版本（目錄紀錄） | source@9f133cb7509ce1dbedfc860e94474588000e25ac |
| 映像標籤 | 0.16.0-4 |
| 固定來源提交日期（UTC） | 2026-08-18T08:46:22Z |
| 原始碼版本 | 9f133cb7509ce1dbedfc860e94474588000e25ac |
| 規則／檢查 | CIS benchmark configuration |
| 規則版本 | 9f133cb7509ce1dbedfc860e94474588000e25ac |
| 資料輸入 | Kubernetes node configuration snapshot |
| 資料版本 | case_artifact_sha256 |
| 目錄知識基準日期 | 2026-08-24 |
| Adapter 版本 | 0.2.6 |
| 輸出格式 | JSON |

映像識別: `ghcr.io/teddashh/ai-security-scanner-engine-kube-bench:0.16.0-4@sha256:77a136e48c6491528a70acabc8380e161d362a63c5bcc9d66312393c3436538c`

## garak

對一個核准的模型服務送出 54 個固定測試提示。開始前請確認請求限制與服務商費用。

[Upstream](https://github.com/NVIDIA/garak) · [README @ 93aa9cd](https://github.com/NVIDIA/garak/blob/93aa9cdec309ec4170559676f1826ea2a679920c/README.md) · [整合與更新筆記](https://github.com/TED-H-com/ai-security-scanner/blob/335d0666bdc63eb86e6c8c4cddeae110db893397/docs/engines/garak.md)

### 工具介紹

Garak 是 NVIDIA 維護、廣泛使用的開源大型語言模型（LLM）弱點掃描工具。它送出稱為「探測」的特製提示，再用偵測器判斷模型的回覆。這裡使用的探測包括「Do Anything Now」這類試圖讓模型拋開自身規則的指示，以及試圖讓模型輸出終端機跳脫碼的提示；上游的 Garak 還有更多探測。我們把它放進本程式，是因為它能幫你很快看出一個核准的模型如何回應這組固定測試。這項選用檢查要由你自己啟動，只對一個核准、相容 OpenAI 格式的 HTTPS 聊天 API 與模型送出 54 個提示。沒有發現問題，也只代表這些提示沒有引出問題。服務商可能會收費；你輸入的 API 金鑰只用於這一次檢查，不會存進掃描紀錄或報告。

### 原本的工具能做什麼

NVIDIA garak 是具備探測、生成器及偵測器外掛的 LLM 弱點掃描器。完整上游支援多種研究流程；本產品提供一組明確受限的原生探測設定。

### 這個程式會檢查什麼

Garak 0.17.0 將 dan.Dan_11_0、dan.Dan_10_0、dan.Dan_9_0 與 ansiescape.AnsiEscaped 的 54 個原生提示，送到單一已核准 HTTPS chat-completions 網址及模型。原生 DAN 與 ANSI 跳脫偵測器評估回應。請求依序執行，每秒一個，含重試最多 64 次，工作期限為 600 秒。

### 哪些不在檢查範圍內

此功能不包含整套 Garak 外掛目錄、自適應紅隊測試或本機模型執行，也不保證模型安全。沒有任意提示編輯器或輔助模型服務。供應商使用量可能收費；核准範圍僅限所選端點及模型。

### 為什麼選用

選用 Garak 是為了使用既有上游探測與偵測器，而非在包裝層自創模型風險判定。其評估計數讓報告能區分已觀察失敗、已評估提示與未判定或缺少的工作。

### 什麼情況下使用

在確認確切網址、模型及供應商費用後，可對有權評估的模型 API 使用此可選檢查。模型或防護措施變更後尤其適用。新輸入的本機 API 金鑰僅使用一次，不儲存在案件或報告中。

### 報告會呈現什麼

範例包含原生格式 JSONL 評估中的四筆探測／偵測器發現。每筆保留失敗與評估計數，以及原始配對識別。嚴重程度維持 Unknown。缺少評估、未判定嘗試或截斷工作會留下未完整涵蓋；原始模型回覆不複製到發現中。

### 優勢

原生探測及明確偵測器計數，讓範圍明確的行為測試可檢視。綁定確切端點、驗證 TLS 與固定請求預算，讓成本及執行範圍容易掌握。

### 弱點

少量提示無法描述模型所有行為。偵測器啟發式判斷及回應變異可能產生模糊結果；供應商端變更後，同一端點的行為也可能不同。

### 機會

可結合 Agentic Radar 的架構盤點與 MCP Armor 的設定檢查。分別記錄時間的重複評估，有助於追查防護變更是否影響被測行為。

### 威脅

模型供應商可能不改模型名稱就改變行為，新攻擊方式也可能不在固定探測中。速率限制、API 結構及計費政策變更，也可能中斷或影響實際測試。

### 版本紀錄

| 項目 | 2026-10-04 提供 |
| --- | --- |
| 引擎版本（目錄紀錄） | 0.17.0 |
| 映像標籤 | 0.17.0-1 |
| 固定來源提交日期（UTC） | 2026-09-09T18:19:05Z |
| 原始碼版本 | 93aa9cdec309ec4170559676f1826ea2a679920c |
| 規則／檢查 | garak packaged probes and detectors |
| 規則版本 | 隨引擎來源提供 93aa9cdec309ec4170559676f1826ea2a679920c |
| 資料輸入 | the AI model endpoint named by the case scope grant |
| 資料版本 | 無／執行時輸入 |
| 目錄知識基準日期 | 2026-09-12 |
| Adapter 版本 | 0.2.6 |
| 輸出格式 | JSONL |

映像識別: `ghcr.io/teddashh/ai-security-scanner-engine-garak:0.17.0-1@sha256:8a39b5812a4fd5aa2caecfef089ff85c39709f1bc00afa3328714346baab222f`

## Agentic Radar

整理支援的 AI 工作流程，讓你看懂有哪些代理、工具與連線，不會執行那些流程。

[Upstream](https://github.com/splx-ai/agentic-radar) · [README @ 65a7e4b](https://github.com/splx-ai/agentic-radar/blob/65a7e4bd01e2034c7cb52e9620eeed287688cc53/README.md) · [整合與更新筆記](https://github.com/TED-H-com/ai-security-scanner/blob/335d0666bdc63eb86e6c8c4cddeae110db893397/docs/engines/agentic-radar.md)

### 工具介紹

Agentic Radar 是一套開源工具，會閱讀由 AI 代理組成的專案，整理出各個部分如何相連。你先選定一個受支援的框架（LangGraph、CrewAI、n8n、OpenAI Agents 或 AutoGen），它的解析器就會列出代理、工具、MCP 伺服器，以及它們之間的連線。MCP 伺服器是透過 Model Context Protocol 接上的外部工具，這個協定讓 AI 應用程式能呼叫其他工具。上游的 Agentic Radar 還有更廣的風險分析。我們把它放進本程式，是因為它能幫你在審閱之前，很快看懂一個 AI 代理專案裡有哪些元件。這裡只盤點一份已儲存的專案副本，不執行工作流程、不連線到模型，也不會回報安全問題。

### 原本的工具能做什麼

Agentic Radar 分析代理式工作流程，提供架構及安全分析能力。本整合選用其框架解析器與圖形盤點，不包含完整上游分析流程。

### 這個程式會檢查什麼

從單一不可變更的儲存庫快照，解析明確選取的框架：LangGraph、CrewAI、n8n、OpenAI Agents 或 AutoGen。離線輸出記錄工作流程元件與邊。小範圍的機器可讀 JSON 修改提供原生解析資料；產品不執行應用程式，也不載入其 .env 檔案。

### 哪些不在檢查範圍內

不包含即時代理呼叫、提示攻擊、模型下載或網路存取。上游警告與圖形結構不會轉成自創安全發現，也不宣稱已啟用上游更廣泛的風險分析功能。

### 為什麼選用

實用的 AI 評估需要先理解所選應用的元件。原生框架解析器提供這些結構，無須另寫解析器，也不必呼叫應用程式的工具。

### 什麼情況下使用

審查受支援代理框架專案，想在深入測試前了解代理、工具及工作流程連線時使用。需明確選擇實際框架；不支援或動態建立的結構可能不在解析圖形內。

### 報告會呈現什麼

範例包含 Agentic Radar 的 33 筆盤點觀察，漏洞為零。解析診斷保留為涵蓋資訊；已知不完整的 CrewAI 解析不會顯示成完整架構。每筆觀察保留上游來源識別。

### 優勢

專門的框架知識提供比一般檔案清單更有用的結構。靜態離線分析可在授予執行權限前，揭露應用宣告的工具與連線。

### 弱點

靜態解析器無法完整解析執行時產生的代理、條件式匯入或動態選取工具。盤點描述結構，不代表代理安全，也不代表工具可被利用。

### 機會

可用圖形判斷哪些地方適合另行核准的 Garak 或 MCP 設定檢查。若上游未來提供機器可讀匯出，就有機會移除目前維護的小範圍輸出修改。

### 威脅

代理框架 API 變動迅速，固定解析器可能跟不上。看似合理的部分圖形可能誤導讀者，因此需要保留診斷及框架範圍。

### 版本紀錄

| 項目 | 2026-10-04 提供 |
| --- | --- |
| 引擎版本（目錄紀錄） | 0.14.1 |
| 映像標籤 | 0.14.1-1 |
| 固定來源提交日期（UTC） | 2025-11-27T15:28:30Z |
| 原始碼版本 | 65a7e4bd01e2034c7cb52e9620eeed287688cc53 |
| 規則／檢查 | No vulnerability rules are consumed; only the static workflow graph is normalized |
| 規則版本 | 不適用 |
| 資料輸入 | repository working-tree snapshot |
| 資料版本 | case_artifact_sha256 |
| 目錄知識基準日期 | 2026-09-13 |
| Adapter 版本 | 0.2.6 |
| 輸出格式 | JSON · 透過輸出修改取得原生解析圖形 |

映像識別: `ghcr.io/teddashh/ai-security-scanner-engine-agentic-radar:0.14.1-1@sha256:2a8d16b9ff5ac7974b0aea8e6504219e0da295b804d01f51da0b4267d7cdafae`

## MCP Armor

檢查選定的 MCP 設定是否留下金鑰，或給了工具過大的權限；不會啟動或連線 MCP 伺服器。

[Upstream](https://github.com/aira-security/mcp-armor) · [README @ 6af4cee](https://github.com/aira-security/mcp-armor/blob/6af4cee4665ab6242f02a88952f9127b6a04922a/README.md) · [整合與更新筆記](https://github.com/TED-H-com/ai-security-scanner/blob/335d0666bdc63eb86e6c8c4cddeae110db893397/docs/engines/mcp-armor.md)

### 工具介紹

MCP Armor 是一套開源工具，用來檢查 MCP 設定檔。MCP（Model Context Protocol）是 AI 應用程式連接外部工具的協定，設定檔則寫明要連哪些工具。它有兩項檢查直接讀取這個檔案：一項找出寫在檔案裡的金鑰等機密，另一項依上游規則標出範圍過大的工具指令與權限；比對到的機密內容不會寫進報告。上游的 MCP Armor 還能連上設定裡的伺服器，並執行需要模型的測試。我們把它放進本程式，是因為它能幫你很快找出你選定的那份設定裡外露的金鑰與過大的工具權限。這裡只讀取已儲存專案中的那一個檔案，不啟動也不連線任何 MCP 伺服器、不載入模型，也無法顯示運作中的伺服器實際執行的權限控管。

### 原本的工具能做什麼

MCP Armor 提供 Model Context Protocol 設定及相關工作流程的安全檢查。本產品透過僅限設定模式，使用其中兩項既有原生靜態檢查。

### 這個程式會檢查什麼

MCP Armor 1.0.2 評估唯讀儲存庫快照中，明確選取的單一 JSON/YAML 設定。原生 hardcoded_secrets 與 excessive_tool_permissions 檢查保留原本模式、嚴重程度及判定。維護中的修改新增僅限設定入口與結構化完成紀錄。

### 哪些不在檢查範圍內

不啟動或連接 MCP 伺服器、不呼叫工具、不載入提示注入模型，也不測試執行時權限。本整合不宣稱包含完整上游動態測試功能。

### 為什麼選用

這兩項原生檢查針對具體設定錯誤提供實用證據，受限的純檔案模式也適合本產品的本機專案流程。我們保留上游偵測邏輯，不用產品自行撰寫的正規表示式取代。

### 什麼情況下使用

所選儲存庫含可辨識 MCP 設定，且想在執行伺服器前檢查機密資料或工具權限時使用。沒有適用設定的專案，不會因此產生虛假的失敗檢查。

### 報告會呈現什麼

範例包含兩種原生發現。保留檢查 ID、嚴重程度、設定路徑，以及伺服器或行號位置，同時排除比對到的機密值。JSON 外層紀錄兩項檢查各自是否完成；解析或檢查失敗會保留未完整涵蓋。

### 優勢

小而明確的檢查集合容易說明及檢視。離線設定審查可在伺服器啟動前，找出暴露的憑證或過大權限。

### 弱點

靜態設定不能顯示執行中伺服器實際施行的控制。模式式機密偵測可能漏掉特殊值或標記範例；寬鬆設定也需要應用脈絡才能評估實際影響。

### 機會

可結合 Gitleaks、TruffleHog 發現與 Agentic Radar 工具盤點。若上游提供等效的僅限設定模式，可取代目前維護的入口修改，同時保留原生結果。

### 威脅

MCP 設定慣例及權限模型變化迅速。上游結構變更可能破壞嚴格結果契約；若隱藏部分檢查狀態，就會讓人誤以為兩項都已完成。

### 版本紀錄

| 項目 | 2026-10-04 提供 |
| --- | --- |
| 引擎版本（目錄紀錄） | 1.0.2 |
| 映像標籤 | 1.0.2-config-only.1 |
| 固定來源提交日期（UTC） | 2026-03-27T09:05:47Z |
| 原始碼版本 | 6af4cee4665ab6242f02a88952f9127b6a04922a |
| 規則／檢查 | MCP Armor hardcoded_secrets and excessive_tool_permissions configuration checks |
| 規則版本 | 6af4cee4665ab6242f02a88952f9127b6a04922a |
| 資料輸入 | one MCP configuration file selected from the repository snapshot |
| 資料版本 | case_artifact_sha256 |
| 目錄知識基準日期 | 2026-09-13 |
| Adapter 版本 | 0.2.6 |
| 輸出格式 | JSON · 僅限設定模式的輸出修改 |

映像識別: `ghcr.io/teddashh/ai-security-scanner-engine-mcp-armor:1.0.2-config-only.1@sha256:f8dcf9b774e0f90cfbe32d81b1dc04c6b1d61538fa9829ca28c674d78440dfdc`
