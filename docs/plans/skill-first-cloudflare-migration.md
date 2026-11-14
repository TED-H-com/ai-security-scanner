# AI Security Scanner：Skill 主入口與 Cloudflare 整合規格

版本：採納規格 1，依產品負責人提供的 2026-11-07 計畫草案 2 編修。  
日期：2026-11-10。狀態：已有報告基準、共用 renderer、terminal／單 run／combined 報告快照與原始附件、唯讀 status、既有案件完整 archive／restore、前景執行與復原、固定來源 bootstrap、指定引擎準備，以及 Cloudflare 文件／reported bundle 驗證、私密保存與離線取回；全新主機的 managed bundle 自動取得、可信 Cloudflare 稽核與案件整合、三平台完整流程仍待完成。以上新流程尚未發布，見[發布定義](../release-model.zh-TW.md)。  
產品依據：[product-spec.md](../product-spec.md)；資料驗收：[報告保真與封存契約](../specs/report-fidelity-and-archive.md)。

本文件是可分批實作的規範，沒有將規格定稿當成功能完成。§15 的「PR」是工作批次名稱，不代表已建立遠端 PR；未實作的命令及新路徑維持 planned。目前 source CLI 的可用範圍見[開發 bootstrap](../skill-bootstrap.md)、[保存報告操作](../report-snapshots.md)、[案件封存](../case-archives.md)與[前景掃描](../foreground-scans.md)。現行桌面操作說明維持可用，正式首選入口於最後一批驗收後切換。

## 0. 決策、範圍與成功定義

### 0.1 已確定的產品決策

1. 主要交付改為 agent skill、受版本控制的原始碼與固定 bootstrap。GitHub binary release、安裝器、簽章與桌面打包不再是一般功能完成或發布 skill 的前提。
2. 保留 Windows、macOS、Linux 的核心編譯與必要執行驗證；編譯成功和完整掃描能力分別呈現。
3. 沿用既有掃描器、adapter、scope、runtime、案件、證據和報告能力。對外入口改變，既有偵測能力和資料價值繼續保留。
4. 第一個新增方法僅為 Cloudflare security-audit-skill。此計畫不整合 Claude plugin、Anthropic OSS Scanner 或其他新 AI 掃描來源。
5. 正式成果維持目前的報告層次、優先排序、資產視角、原始證據、遮罩、附件、雙語可讀輸出與機器格式。
6. 新增明確的離線報告重建及完整案件封存／還原能力；既有資料中未曾保存的歷史資訊必須保留為未知。
7. 不要求 agent 自行發明 build 指令或重寫 detector。Skill 呼叫受版本控制的程序，Cloudflare 保留其方法與原生輸出。
8. 依產品規格、資料契約與相依順序增量實作。程式查核不等於執行驗收；已產生的基準及程式驗證與尚未完成的掃描／restore 證據在 §15 分開記錄。文件檢查另計，不冒充功能已通過。

### 0.2 成功的使用者旅程

使用者對 coding agent 說「掃描這個專案，包含 Cloudflare 分析，給我完整報告」。Agent 透過同一個 skill：

- 確認選定資產、方法、必要能力和已授權範圍；
- 取得或建立固定版本的核心快取；
- 保存實際受檢的 source snapshot，完成適用的既有檢查與 Cloudflare 工作流程；
- 以既有專業報告層輸出一份可讀 HTML 與相同語義的結構化資料；
- 保存上游原始輸出、驗證紀錄、來源版本與報告快照；
- 日後可在不呼叫 AI、不連回原目標的情況下查看原報告、驗證證據並重建報告；完整封存可在新 workspace 還原案件。

對外只需要一個 skill 入口。第一版不增加必須常駐的服務、不建立新雲端平台，也不要求為新增掃描方法製作桌面安裝包。

### 0.3 完成不等於哪些事情

- build 通過不代表所有掃描 runtime 或 target OS 已被驗證。
- JSON schema 通過不代表漏洞已被證實。
- 保留簽章不代表報告內容必然正確。
- 相同 source/model/prompt 不保證 AI 重跑發現完全相同。
- 舊版 case bundle 可驗完整性，不等於已存在完整的案件還原功能。

以上界線由資料欄位和驗收條件表達，不在使用者主流程堆疊免責文字。

## 1. 研究基準與既有資產

本計畫以以下不可變版本為依據；實作開始時先比較新 HEAD，若相關程式有變動，更新差異紀錄與基準測試，不重做無關研究。

| Repository | 查核版本 | 用途 |
| --- | --- | --- |
| TED-H-com/ai-security-scanner | 6e259b497b87fb8aa2ece1f3b512cc29c9ea5af7 | 既有產品、報告、runtime 與資料契約 |
| cloudflare/security-audit-skill | c1c8a8c1471069fb0e188eeaff69b8e8db6564a8 | 第一個 AI audit 方法、schema、validators 與方法文件 |

2026-11-08 再查核：產品 `origin/main` 仍為上述基準；Cloudflare 官方 `main` 與固定 revision 的 compare 為 identical。此前 issue #88 的獨立文件修正不涉及本計畫查核的 core。後續實作仍使用固定 revision，查核當天相同不代表可以執行 moving branch。

### 1.1 已確認、應直接重用的能力

| 既有位置／能力 | 現況 | 改造原則 |
| --- | --- | --- |
| docs/product-spec.md、AGENTS.md | 產品以統一、可行動、可追溯的報告為核心；目前執行入口仍指向桌面 | 更新入口與主要使用者定義，保留薄 adapter、原始證據與範圍規則 |
| src-tauri/src/case_service.rs | CaseService::export_case 共用 HTML、JSON、framework report、OCSF、OSCAL、case bundle；HTML renderer 已在 Rust | 抽出共用 renderer，禁止另寫簡化版 skill 報告 |
| src-tauri/src/beginner_report.rs | BeginnerMasterReport 目前 schema 1.1.0；terminal run 才產生正式報告 | 加法擴充 AI audit 資訊，保留既有優先順序與 coverage 語義 |
| src-tauri/src/domain.rs | FindingObservation.finding_snapshot、run 的 frozen asset/scope、evidence pointer、raw artifact hash | 歷史觀察與人工工作流獨立保存 |
| src-tauri/src/export.rs | manifest hash、Ed25519、驗證與有界 bundle；case.json 是摘要 | 沿用完整性機制，另建完整 restore schema |
| src-tauri/src/report_attachments.rs | 原始檔以每個 task 的 ZIP 保留；HTML 附件上限 64 MiB／10,000 檔 | 保留精確 bytes、目錄與來源，不把上游 HTML 當主報告執行內容 |
| src-tauri/src/external_scanner_import.rs | 目前明確支援 Strix 格式；有 preview hash、asset binding、檔案限制及原始 JSON 留存 | 重用通用 admission 元件，新增 Cloudflare 專屬 adapter |
| src-tauri/src/selected_run_report.rs | 2–16 個 terminal reports 的 HTML／JSON 合併；保留每個來源時間與限制 | 用於第一版整合成果；不把不同 run 改寫成同次掃描 |
| src-tauri/src/storage.rs | SQLite WAL、optimistic revision、transaction、損壞案件隔離 | 沿用；case_events 不是完整 event-sourcing log |
| commands.rs、state.rs、orchestrator.rs、job_manager.rs | state/commands 的生命週期接線依賴 Tauri；JobManager、Orchestrator 與 CaseService 已可在非 desktop core 使用，checkpoint 已處理 artifact 重解析與 cleanup | 抽出接線與 event sink，重用現有 runner、generation reconciliation 與 lease |
| src-tauri/src/bin/cli.rs | 已能管理、doctor 診斷與匯出；Start／Pause／Resume 目前拒絕執行；共同 initialization 會開 writable storage | 擴充既有 doctor，新增 foreground ownership 與真正唯讀 status 入口 |

來源：[R01]、[R02]、[R03]、[R04]、[R05]、[R06]、[R07]、[R08]、[R09]、[R10]、[R11]；原始證據、附件、儲存與執行鎖另見 [R19]、[R20]、[R23]、[R24]。

### 1.2 必須在計畫中承認的缺口

目前 bundle 的文件集合未完整保存 AssessmentCase 的每一個恢復必要欄位，例如 inventory_observations、exports 與部分案件脈絡。不能僅新增一個 restore 按鈕，便宣稱所有歷史資料可完整恢復。[R05][R06]

部分 legacy finding 缺少 frozen snapshot，會以目前 canonical 資料補呈現。新格式不得把這種 fallback 重新標成「掃描當時原貌」。[R05][R06]

目前 CLI 控制禁令背後有生命週期原因：JobManager 擁有程序內的 worker，CLI 一返回可能使 worker 消失。解除拒絕分支本身不能完成 headless 改造。[R10][R11]

現有範例 HTML 位於 docs/samples/v0.4.0/，可作視覺參考；正式回歸基準仍要從上述當前 commit 的 exporter 與 fixtures 生成，不能直接把舊樣本稱為 v0.6.0 的精確輸出。[R22]

## 2. 報告保真與資料不變條件

以下條件是本次改造的 acceptance contract。

| 編號 | 必須保留的行為 |
| --- | --- |
| INV-01 | 原本支援的實際安全檢查、資產綁定、scope 和 detector 語義不因入口變更而縮減或擴張 |
| INV-02 | 相同保存資料與報告設定下，既有 findings、severity、priority、coverage、workflow、grouping 與 evidence 語義一致 |
| INV-03 | 所有新 AI 結果能回到原始 provider record、source snapshot、task/attempt 與 artifact |
| INV-04 | 不把 planned、not run、blocked、failed、cancelled 或無法驗證視為 clean |
| INV-05 | 一個方法失敗不刪除其他方法已完成的資料 |
| INV-06 | 原始輸出不被正規化或翻譯覆寫；人工工作流決定不被 provider verdict 覆蓋 |
| INV-07 | 已封存報告可離線讀取及重建，不依賴重新呼叫 LLM、重新掃描或原機器的絕對路徑 |
| INV-08 | 原始 HTML／JSON／MD／證據若被納入封存，取回 bytes 與 SHA-256 必須一致 |
| INV-09 | 分享版遮罩不修改本地 canonical 資料；完整 archive 與 redacted handoff 的可還原程度明確不同 |
| INV-10 | 新核心可讀舊案件；未知舊歷史保持未知；舊 binary 能否讀新 schema 不作對稱承諾 |
| INV-11 | Formal report 僅對 terminal assessment 產生；執行中使用 progress 與 durable checkpoints |
| INV-12 | 首次 build、runtime 下載與 source audit 是不同工作；報告開啟與還原不要求掃描 runtime 可用 |

## 3. 目標架構

~~~mermaid
flowchart TD
    A["主 Skill：選擇資產與方法"] --> B["凍結範圍與 source snapshot"]
    B --> C["既有工具：共用 ScanCoordinator"]
    B --> D["Cloudflare：宿主 Agent 工作流程"]
    D --> E["固定驗證器與 Cloudflare Adapter"]
    C --> F["案件、原始證據與來源紀錄"]
    E --> F
    F --> G["共用報告模型與 Renderer"]
    G --> H["HTML 與既有機器格式"]
    G --> I["報告快照、封存與還原"]
~~~

### 3.1 各層責任

| 層 | 責任 | 不應承擔的工作 |
| --- | --- | --- |
| 主 skill | 探測能力、選擇方法、呼叫固定程序、協調宿主 agents、回傳成果 | 不自行改寫 detector，不用聊天文字作唯一保存狀態 |
| Bootstrap | 固定來源與 toolchain、建置最小 core、快取、能力診斷 | 不為每次掃描建完整桌面 app |
| ScanCoordinator | scope、admission、preflight、worker ownership、checkpoint、cleanup、reconciliation | 不依賴 Tauri AppHandle |
| Cloudflare workflow adapter | 對應宿主 delegation、階段紀錄、上游流程與原始文件 | 不假設 Rust 能直接呼叫任意宿主的 subagent API |
| Provider result adapter | 有界讀檔、驗 schema、核對來源、保存 record、轉換可呈現資料 | 不重新判斷上游 detector，不把 schema 通過稱為漏洞驗證 |
| Report layer | 同一套優先順序、可讀敘述、資產結果、證據、遮罩與輸出 | 不在每次開啟報告時重新問 LLM |
| Archive/restore | 完整案件快照、blob、manifest、驗證與原子還原 | 不恢復秘密憑證、不重新啟用歷史掃描授權 |

### 3.2 第一版採序列協調，保留各來源 run

為避免同時新增 daemon、IPC 和跨程序資料庫寫入協議，第一版主 skill 以序列方式完成：

1. 沿用既有掃描計畫與任務結果清單，記錄本次選定資產和方法；Cloudflare 與其他方法一樣有一列工作狀態。
2. 執行需要的既有工具 run；CLI 持有 worker 與資料目錄 lease，等 exact generation 的 terminal outcome 持久化與有界 reconciliation 完成後退出，未完成 cleanup 另存可恢復 obligation。
3. 在 Cloudflare staging workspace 執行其階段工作。進度與中間紀錄保存於專屬 session，不冒充正在由 Rust worker 執行的 catalog task。
4. Cloudflare finalize 完成 bounded validation 後封存保管紀錄；另由獨立接納步驟將 provider run 加入案件。中斷時也可用明確 incomplete outcome 封存已得到的資料。
5. 單一來源沿用單 run 報告，多來源沿用 selected-run composition；每項方法的結果使用既有 task/outcome 呈現。
6. 各項工作結束後產生報告。工具 run 成功但 Cloudflare 無法啟動時，保留工具結果，Cloudflare 那一列顯示「失敗」，展開後說明未執行及原因。

既有 export combine 的 2–16 個來源契約保留，不為啟動失敗增加新的 composition 範圍或獨立 assessment projection。Cloudflare 被選定時即可沿用任務紀錄；沒有執行也沒有 findings，仍可保存正常的失敗結果。內部使用既有適用的 NotExecuted／Failed 狀態，原因如「環境缺少必要的 delegation，分析未執行」。任務紀錄不代表掃描曾經執行。[R08]

使用者介面只需要方法清單中的一列失敗與可展開原因，無須為單項啟動失敗增加警告區、預期來源索引或另一套結果模型。重開報告與還原時沿用該任務紀錄即可。驗收只確認這列狀態、原因與其他方法的結果都有正常保存。

沒有建立 session 或產出 provider bundle 的啟動失敗，也必須經既有 run/task 保存路徑留下 terminal outcome；不得要求先偽造空 findings、validator receipt 或 source digest 才能記錄失敗。新增 `AgentAudit` task kind 表示實際宿主協調，沿用 `ScanRun`／`EngineRun` 狀態與結果列；手動匯入繼續使用 `ExternalReportImport`，不能冒用 catalog image identity。

prepare/checkpoint 使用 provider session 專用互斥鎖；finalize 重新取得資料目錄 writer lease，核對 case revision、frozen asset/source binding，並以 case_id、session_id、manifest_digest 的 durable receipt 保證重試冪等。同一 session 的不同 sealed manifest 不得靜默覆蓋。若桌面已持有 lease，回傳可辨識的 busy 結果。耗時驗證在短 DB transaction 前完成，commit 前重新核對已驗證 bytes 與 digests。

此設計刻意將「同一入口、同一份成果」與「所有工作同時共用一個 live worker」分開。未來需要並行時，再以同一個 owner 的正式 IPC 擴充。

## 4. Headless 核心改造

### 4.1 提取協調層

開發 source 已新增 CoreState、ScanCoordinator、ScanEventSink，桌面與前景 CLI 共用原 worker。下列提取邊界已接線；實測範圍見[開發紀錄](../development-status.zh-TW.md)，完整跨平台驗收仍依 §14.4。提取順序：

1. 先把 state.rs 中可共用的核心依賴移出 desktop feature gate。
2. 將 commands.rs 的 start_scan、start_persisted_scan_job、prepare_persisted_new_scan 與 worker 協調路徑改成接收核心參照。
3. Tauri command 保留薄轉接：取得輸入、呼叫 coordinator、將 typed events 傳到 UI。
4. CLI 以另一個 EventSink 輸出 NDJSON；診斷訊息走 stderr。
5. 保留既有 Orchestrator、adapter、runtime 與 evidence append 程序，避免複製一套新的 runner。

應保留的既有程式行為包含：durable admission、scope/run/tasks 一起保存、runtime 準備後再 preflight、duplicate job 防護、單項失敗隔離，以及根據 recorded runtime identity cleanup。[R10][R11][R12]

### 4.2 Worker ownership 與控制

開發 source 已提供 `scan run --wait` 與 `scan recover --wait`，操作及 exit codes 見[前景 CLI 文件](../foreground-scans.md)。首版 recovery 僅執行 exact cleanup 與已保存 artifacts 重解析，包括阻止 Naabu 自動續批；需要重新接觸目標的 checkpoint 明確拒絕，保留資料供 status 查閱及既有桌面 recovery 處理。未結束的舊 run 可能阻止新 scan，不能將重開新掃描視為通用復原方式。

- 程序存活期間擁有 worker，等待 exact generation 的最終資料持久化及有界 reconciliation 後才返回。只看到 in-memory terminal 不足以退出；現有 best-effort callback 失敗時由前景 owner 重試並確認 durable acknowledgement。
- Cleanup 無法在界線內完成時，保存 exact runtime identity、資源及 pending obligation，輸出明確恢復方式；不無限等待、不宣稱清理成功，也不把已完成的使用者工作永久留在 paused。
- 宿主 agent 可利用自己的長任務機制保持該程序；skill 不在 command 返回後假稱掃描仍會繼續。
- 中斷停止新工作，保留已捕捉證據，使用既有 cancellation/cleanup 契約。
- scan status 以真正 read-only storage 開啟 durable 狀態；不得建立目錄、執行 schema migration、修改權限或初始化 execution owner。現有共同 CLI initialization 的 writable `Storage::open` 必須拆開；不能因無法取得 writer lease 就把活躍工作標成已中斷。
- 同一資料根目錄仍使用 DataDirectoryExclusiveLease；桌面與 CLI 不得同時成為 execution owner。
- 所有 mutation command 盤點 writer lease，不能假設現有 `command_requires_exclusive_data_directory` 已涵蓋每種新寫入。Ctrl+C 或 NDJSON sink 中斷也須由 owner 保存 outcome／checkpoint，不能讓輸出失敗丟失 worker ownership。
- 第一版不提供假跨程序 pause/resume。若需要由第二個程序操作 live worker，必須新增正式控制 channel，且由現有 owner 執行轉換。
- Crash recovery 先 reconcile，再依 checkpoint 選擇 reparse artifacts、cleanup-only 或重新執行；不得一律重掃。
- 新增 owned foreground recovery 入口，例如 scan recover --wait：確認舊 owner 不存在並取得 lease 後，恢復既有 run；若必須重新接觸 target，先檢查目前授權仍有效。這與另一個程序操作 live worker 的 resume 是不同介面。

### 4.3 結束狀態

CLI JSON／NDJSON 必須分開表達：

- command 是否成功完成；
- assessment/run 是否完整；
- 各 task 的既有 wire status，例如 completed、partially_completed、failed、cancelled、not_executed；不得將既有 `partially_completed` 靜默改名為 partial；
- finding counts 與 coverage gaps；
- 保存的 report、archive、receipt 位置。

發現 Critical 漏洞不等於 CLI 執行失敗；沒有 findings 也不等於 run 成功。退出碼在 CLI contract 中集中定義並測試，不在 skill 中憑語句推測。

## 5. Skill、build、cache 與 runtime

### 5.1 單一 skill 來源

Canonical skill 已位於 `skills/ai-security-scanner/`；`scripts/skill/sync-skill.mjs --write` 產生 Claude/Codex discovery 目錄的可攜副本，`--check` 驗證同步與相對文件連結。不依賴 Windows 可能缺少的 symlink 權限。預設操作仍使用已發布桌面；開發者可明確選擇下列 core bootstrap。

- 主 SKILL.md 保持精簡，載明入口、必要步驟、能力限制與成果位置。
- 深入流程放 references/，固定命令放 scripts/。
- Cloudflare 上游內容放獨立 vendor 目錄，按方法啟用時載入。
- 既有 skill parity 測試改為確認 canonical source 與產生物一致，並驗證方法依賴存在。
- 更新 AGENTS.md、product spec、README、getting-started，移除與新方向衝突的「執行掃描一律安裝桌面／禁止 source build」規則。

保留既有不重複詢問相同授權的行為。Skill 安裝與一般 code audit 不得自動擴張成網路、付費目標 API 或有破壞性的檢查。

### 5.2 固定 bootstrap

已新增獨立 `scripts/skill/bootstrap.mjs`，提供 `doctor`、`prepare`、`run` 及版本化結果／收據。它要求受信產品 checkout 的完整 40 字元 revision，驗證來源與受控 build inputs，未經明確 `--allow-dirty` 不接受開發變更。不重用 `scripts/release/build-sidecar.mjs`：該路徑在 Windows 會加入 installer-runtime-cache 並 stage 桌面封裝產物。[R13]

Bootstrap 在私密 staging 中，以以下固定 core-only recipe 加上已驗證的 native `--target` 建置；操作端使用 bootstrap，不自行拼接建置指令：

~~~sh
cargo build --locked --release --package ai-security-scanner \
  --no-default-features --features cli \
  --bin ai-security-scanner-cli
~~~

預設使用 release profile，開發驗證可明確選 `--profile dev`，兩者使用不同 cache key。Linux 已實際完成離線 dev 與預設 release build、快取重用與移除原 workspace 後的 HTML／JSON 重播；各平台與 profile 的實測記於[開發紀錄](../development-status.zh-TW.md)。`prepare --capability scan --engine ID --data-dir DIR` 現在可透過同一核心準備指定引擎；核心快取與 runtime 收據分開保存，不因選擇另一引擎而重建核心。[R14]

Bootstrap 的 Node、Rust/native linker 等前置能力由 doctor 分項回報；recipe 只來自固定受信 product source，不接受受檢專案、provider artifacts 或聊天中臨時提供的 build script。既有 `src-tauri/src/bootstrap.rs` 是雲端授權 bootstrap，不是此次 source-build bootstrap。

Bootstrap receipt 至少記錄：

| 欄位 | 說明 |
| --- | --- |
| core source revision / source digest | 精確來源；開發 dirty build 另有內容 digest |
| Cargo.lock digest | 依賴版本 |
| Rust toolchain | 固定 1.98.0；保存 rustc／Cargo 身分及 native compiler／linker 雜湊與版本 |
| target triple / OS / architecture | 區分編譯目標與實際宿主 |
| features / binaries | 不同能力使用不同快取 |
| build recipe version | 固定指令與程序版本 |
| artifact digests | 建出的每個 binary |
| build outcome / time | 成功才標示 cache ready |
| runtime/provider lock references | 記錄所需能力，不將無關 provider prompt 改動混入核心 build key |

Cache key 對核心 build 只使用會改變核心產物的資訊：受控 core/build-script inputs、被編譯嵌入的 catalog/mappings、Cargo.lock、toolchain、target、features/binaries 與 recipe。完整 Git revision 留在 receipt，不可單獨作為 reuse key；只 hash `src-tauri/src` 也不完整。Cloudflare 提示修訂、翻譯或 skill 入口文字變動，如果未變更 core/runtime 契約，不應強迫重建核心。

以暫存目錄完成 build、驗產物、寫 receipt 後原子切換 ready pointer。失敗保留先前可用快取；digest 不符不能直接執行。快取清理不得刪除案件、原始證據、來源快照或封存。

### 5.3 能力分層與按需準備

| 能力 | 需要什麼 | 不應被迫準備什麼 |
| --- | --- | --- |
| 查看／重建保存報告 | core、相容 renderer、保存資料 | VM、掃描引擎、AI 連線 |
| Cloudflare source review | core、受支援宿主 delegation、固定 Node validators | 全套 25 個工具映像 |
| Cloudflare 本地動態驗證 | 上述能力加符合條件的 OS sandbox | 外部網路或環境憑證 |
| 既有工具掃描 | 該工具 profile 所需 runtime/helpers/images | 無關工具與桌面安裝器 |
| Full archive restore | core、archive 驗證器、可寫新資料根目錄 | 原始工作站或掃描 runtime |

runtime/upstreams.lock.json、映像 digest 與下載驗證繼續維持。取消安裝器不代表刪除 runtime 供應鏈；相關 engine image 的維護可獨立進行。[R15]

CLI 已支援明確 `--managed-runtime-bundle`、packaged candidates 及 verified `open_installed`。指定引擎準備重用既有 runtime resolver 與精確映像 pin；優先使用受驗證 managed runtime，否則使用已存在的相容 runtime。明確指定卻無效的 bundle 不會悄悄回退。全新主機自動取得 managed bundle 仍待實作；Linux 的現有 QEMU bundle 建置需要 Docker，不能將它當成無 runtime 主機的自動啟動解法。

`runtime prepare` 要求明確 data-dir，先驗證全部引擎，再取得 writer lease。只準備所選映像及其必要的共用 gateway 映像，不建立案件、授權或掃描工作，也不啟動 gateway 或接觸目標。每項保存 ready／failed／cancelled 與取得方式；單一失敗不抹除已完成項目。最後收據先寫入 `runtime-preparations/`，再輸出結果。SIGINT／SIGTERM 與 bootstrap 控制管道會要求取消並等待擁有的程序收尾。

`--offline` 只使用正在執行的 runtime、已存在映像或受驗證的本機 OCI archive，不啟動 managed VM、不連 registry。它只約束準備操作，後續掃描仍依各引擎及已核准範圍執行。`doctor --capability scan` 維持唯讀，回報需進一步準備；不將核心建置成功當成 scanner ready。完整命令見 [bootstrap 操作文件](../skill-bootstrap.md#prepare-selected-scanners)。

基準 runtime lock 列出的組合為 Linux x86_64/QEMU、macOS Intel 與 Apple Silicon/applehv、Windows x86_64/WSL；core 能接受其他 target 不代表 runtime 也支援。平台能力分開記錄 build、native core execution、runtime、Cloudflare delegation 與 dynamic sandbox 的證據。Windows 的 WSL2 前置條件保留，不由 skill 自行提權開啟。

doctor 輸出逐項能力與具體原因。現有 managed-runtime 支援範圍與 Rust 可編譯 targets 不相同；Linux ARM64 等未驗證組合不得只因編譯通過就標成完整支援。

## 6. Cloudflare 上游整合

### 6.1 固定版本與檔案組成

第一版固定 Cloudflare commit c1c8a8c1471069fb0e188eeaff69b8e8db6564a8。保留 MIT LICENSE、來源網址、commit，以及所有使用之 schema、validator、方法及 companion 檔案的 SHA-256。[C01]

建議位置：

| 位置 | 內容 |
| --- | --- |
| providers/cloudflare/provider.json | 方法 ID、相容契約、上游 revision、能力與檔案索引 |
| providers/cloudflare/upstream.lock.json | 上游 commit、檔案 hash、vendor 程序版本 |
| providers/cloudflare/upstream/ | 原樣保留的 LICENSE、SKILL、方法文件、schema、validators |
| providers/cloudflare/adapter/ | 自有宿主轉接與驗證 wrapper；與上游內容分開 |
| tests/fixtures/providers/cloudflare/ | 可公開的正常／異常契約 fixtures |

掃描中不下載 moving main；上游更新以獨立 dependency change 提交差異、更新 lock 並跑相容性測試。初期無須建立通用第三方 plugin marketplace。

### 6.2 宿主執行方式

Cloudflare 本身是 agent-neutral 方法。主 skill 使用宿主原生 delegation，保存角色、隔離與獨立驗證要求；不假設將 MD 放進目錄便能在任何宿主等價執行。[C02]

第一版建議預設 standard profile，按使用者選定範圍和 agent invocation budget 執行。完整流程為 reconnaissance、hunting、candidate validation、structured validation、final independent verification、reporting。細節直接引用 pinned 方法文件，不在產品重新創造另一套 Cloudflare detector。[C02][C04]

宿主能力不夠時：

- 缺少獨立 delegation：選定的 full audit 任務顯示失敗，展開說明分析未執行；可保留 guidance 作附屬資料，但不得自動降級後計為完成。
- 缺少安全動態 sandbox：保留 source review；需執行才能判定的項目記錄具體 blocker。Source-only 的有效驗證不被錯誤要求必須執行 target code。
- 預算不足：按上游語義保存未完成工作，不跳過必要驗證來達成 complete。
- 模型／宿主版本拿不到：記錄 unknown；不得依 agent 的自我介紹推定精確模型。
- 保留每次 assignment ID、角色、開始／結束、輸入 revision、輸出 hash 及結果摘要。這是執行來源紀錄，不是模型能力或正確性的證明。

產品沿用使用者目前的 agent host，不新增 scanner 專用模型帳號系統。由宿主處理的 source 可能依宿主設定送往模型服務；更新產品文件，精確區分「資料持久化在本地」和「AI 推論完全離線」。不得沿用不符合新工作流程的絕對不外傳宣稱。

Before-recon budget gate 沿用 pinned 方法，先保留必要 reconnaissance、critic 與 verifier 次數；不夠時不啟動一個注定省略驗證的 full audit。`standard` 的 candidate validation 與 final verification 分開；不能私自套用 quick profile 的合併規則。Candidate verifier 不得是原 hunter，也不得取得另一 verifier 的結論。Malformed 或 prose-wrapped verifier JSON 捨棄並交 fresh verifier，parent 不得代修成有效 verdict。強化 verdict 或重要主張變更需要新的獨立 verifier；預算不足時保留 unresolved ledger 和歷史版本。[C02][C04]

### 6.3 原始 provider bundle

保持以下上游檔名與原始 bytes：[C02]

| 檔案 | 保存目的 |
| --- | --- |
| run-metadata.json | source ref、profile、scope、budget、run outcome |
| architecture.md | 實際生成的架構與邊界敘述 |
| coverage-ledger.json | coverage units、attempts、缺口與 fingerprints |
| findings.json | 三種正式 verdict 的原生 records |
| REPORT.md | 上游摘要原文 |
| FINDINGS-DETAIL.md | 上游 confirmed medium/high/critical 的深入說明；完整 record 索引以 JSON 為準 |
| NEEDS-VALIDATION.md | 正式 needs_validation records 的說明；未驗證 candidates 仍在 ledger 與 incomplete report |
| agents/<agent-id>/artifacts/ 內獲准 retained files | 最小必要的驗證證據 |

工作 scratch 不作整包永久保存，也不遞迴複製進正式 evidence。原始文件在 finalize 後唯讀；後續修正產生新的 revision/attempt，並保留 lineage。

產品自己的 method/schema/host/model/receipt 資訊放 sidecar envelope。Cloudflare findings 是 strict top-level array，沒有 provider、model、schema_version、CWE、CVSS 欄位；不能把自有 metadata 插回原生 records。[C03]

## 7. Cloudflare 資料對映與驗證

### 7.1 狀態對映

新增獨立 AgentAuditRecord／ProviderValidationState。不要用 FindingStatus::Confirmed 代表 Cloudflare 的 confirmed；前者是既有人工工作流狀態。[R05]

| Cloudflare 原生狀態 | 保存與呈現 | Findings／風險計數 |
| --- | --- | --- |
| confirmed | 保存原 verdict、severity、confidence、root cause、trace、execution 與 remediation；產生證據綁定的 finding observation | 進入可行動發現；人工 workflow 仍使用既有初始狀態 |
| needs_validation | 保存 source-grounded hypothesis、blockers、validation_plan | 獨立待驗證區；沒有 severity，不加入 Critical/High confirmed counts |
| rejected | 保存 claim、trace、evidence 與 reason | 留在技術歷史，排除可行動漏洞數 |
| 尚未經必要驗證的 candidate | 保留 ledger 與階段紀錄，列明未完成 | 不新增 findings.json record，不冒充 needs_validation |

candidate 的特殊語義：ledger 狀態 candidate 也可能代表「已產出有正式判定的 records」。判斷未完成必須檢查 fingerprint linkage 和必要 verifier 是否完成，不能看到 candidate 就一律將整次掃描標失敗。[C02][C03][C05]

### 7.2 欄位對映

| 原生資料 | 產品資料／規則 |
| --- | --- |
| fingerprint | 保存 provider 原值；occurrence 綁定 provider、asset、source snapshot、run；跨 run 關聯另外建立 |
| title / description | 原文保留；可讀敘述在 finalized projection 中凍結 |
| trace[].file/line/kind/scope/description | 對應 source snapshot 的路徑與位置；保留 entrypoint/propagation/sink |
| evidence[].file/line/description | 原生 source references；另建自有 evidence ID、snapshot digest 與 locator check |
| root_cause / intended_behavior | 保留確認原因與預期 invariant |
| conditions | 保留 typed 條件，不把環境假設改寫成已知事實 |
| execution | 保存 observed_result、payloads、instructions；不因匯入而執行 |
| remediation | 保留 strategy 與可選 code_changes；不自動修改 target |
| severity | 保留 likelihood/impact 分數與理由、overall severity；產品 priority 另外計算 |
| confidence | 保留 low/medium/high 與 reason；不自動映射到 Confidence::Confirmed |
| blockers / validation_plan | 轉為具體待驗證原因與下一步 |
| rejected.reason | 保存否決歷史，避免日後只看到 record 消失 |

payloads、fixed_code 等有語義的字串不得 trim 或重新格式化。上游沒提供 CWE/CVSS 時保持空值，不從自然語言猜測來填 framework 關係。[C03]

Source-only local check 可有 `method = source`、`artifact = null`。原生 confirmed 所需的 execution 資料必須有可查證來源；不得為滿足 schema 補造已執行的 command、payload 或 observed_result。缺乏有效來源時依上游方法保存 blocker／未完成狀態。

先不新增 Cloudflare 與其他引擎的自動合併規則。沿用既有可證明的 grouping；缺乏共同明確識別資料的結果保留獨立 observation。相似標題、附近行數或兩個模型同意都不足以合併成同一已證實漏洞。

### 7.3 Coverage 保存

ledger 原生狀態 planned、not_applicable、out_of_scope、deferred、in_progress、blocked、covered、candidate 全部保留。保存 stable coverage_id、canonical_refs、reviewed_paths、local_checks、attempts 與 result_fingerprints。[C05][C06]

呈現規則：

- 用已檢查單元、未完成單元、排除原因及對應路徑說明覆蓋。
- 不把單元完成比例命名為「已找到全部漏洞的百分比」。
- source check 不表示 target code 曾執行；local check 必須連到合法 retained artifact。
- attempts 與 critic reopen 歷史不被最後一次結果覆寫。
- 歷史 covered 或 rejected 可以協助此次規劃，但不能讓變更過的 source 自動取得已檢查狀態。

### 7.4 三層驗證

**第一層：讀檔與結構。** 使用有界、非跟隨連結、regular-file 檢查，拒絕危險路徑、重複識別值、過深 JSON、超限內容和未知格式版本。Preview digest 綁定整組 provider manifest、各檔案 hash、asset/source binding，不只綁 findings.json。

既有 Strix 的 preview/commit、raw artifact 和 failed-task pattern 可重用，但其單檔 reader 不等於已具備整組 provider bundle 的安全入場。Retained-root traversal、hardlink、identity stability、cross-file references 與 receipts 是需新增的保護。

**第二層：上游語義。** 執行 pinned Cloudflare validators。findings 上限 5 MiB／1,000 records；ledger 上限 5 MiB／10,000 units，並保留上游 depth/collection/diagnostic bounds。既有 Strix 的 4 MiB 限制繼續適用 Strix；以 provider-specific limits 配置，不全域放寬或默默截斷。[R07][C06][C07]

**第三層：產品關聯。** 檢查 source snapshot 是否一致、位置是否存在、artifact 是否屬於正確 agent/run/task、檔案長度與 hash、ledger/finding fingerprint 是否互相對應、必要 verifier 紀錄是否存在、run outcome 與 report counts 是否一致。

第三層的機械檢查能確認資料關聯與來源，不能單靠行號存在證明語義結論正確。語義驗證仍由上游獨立工作流程提供，報告保留其方法來源。

### 7.5 跨 OS validator 方案

上游兩個 CLI reader 依賴非零 O_NOFOLLOW 與 O_NONBLOCK；不具備時會拒絕輸入。不得假設 Node CLI 在 Windows 已可用，也不得移除安全檢查以取得表面通過。[C06][C07]

優先方案：

1. Rust core 用等價安全的 handle-based reader 完成檔案型別、連結、長度、identity stability、UTF-8 與 JSON 前置界線檢查。
2. 透過有界 stdin 傳遞資料給受信任 Node wrapper。
3. Wrapper 使用上游匯出的 validateDocument；findings 同時使用 pinned schema。
4. 保留原 CLI 的 preflight limits。上游 JSON.parse 並未拒絕重複 keys；產品新增 duplicate-key 拒絕策略時，將其標為刻意加嚴的差異，不能宣稱原本就有這項保護。
5. 使用上游測試 corpus 與自有 integration cases，在 native Windows/macOS/Linux 驗證兩種入口的接受／拒絕結果；產品刻意加嚴的差異另列 corpus 與原因。
6. 任一平台無法提供等價保護，該能力明確 unavailable；既有工具結果與報告開啟仍然可用。

Node 執行目錄與模組解析固定到 vendor cache，不能從 target repo 讀取任意 loader、hook 或可替換 schema。

Findings 的 CLI `enforceJsonTextLimits` 沒有 export；ledger 的 `preflightJsonText` 有 export。只呼叫 `validateDocument` 不保留 parse 前界線，Rust／自有 wrapper 必須補齊等價 preflight 並用 corpus 對照。Pinned findings 保留 5 MiB、array 1,000、depth 64、diagnostics 100 及 canonical-key／unique-set bounds；ledger 保留 5 MiB、10,000 units、collection/object 1,000、depth 64、preflight values 500,000、diagnostics 100。Node process 另有時間與輸出界線，移除 `NODE_OPTIONS`、`NODE_PATH` 等可注入設定。

### 7.6 Orchestrated run 與外部匯入

第一版正式流程是主 skill 協調的 Cloudflare 工作。若同時提供手工匯入：

- 保存 upstream verdict，但獨立記錄 provenance 為 reported-only 或 workflow-recorded。後者只能由本產品的受信協調紀錄支持，匯入 sidecar 或自帶 receipts 不能自行授予。
- 單憑 findings.json 不能宣稱獨立 verifier、完整 coverage 或 target snapshot 已驗證。
- 匯入永遠不建立新授權、不觸發執行、不跟隨報告內的 URL 或命令。
- 缺少的執行紀錄保留為未知；不能為了符合 UI 期待自行生成假 receipts。
- reported-confirmed 與本產品完整流程確認的 findings 分開計數與標示；原生 verdict 不被改寫，但也不能因此宣稱本產品已完成獨立驗證。

## 8. Source、執行環境與階段恢復

### 8.1 Source snapshot

沿用 workspace_snapshot.rs 的有界 snapshot 機制。現有規則會保留疑似 secret/private config 供本機 detector 檢查，tracked 檔也不因 `.gitignore` 自動排除；這不是可直接提供給模型的無秘密快照。Canonical source identity 至少包含 repository identity、Git commit（若有）、dirty 狀態、實際受檢檔案集合與內容 digest。非 Git 目錄使用內容快照身分。[R16]

Cloudflare 另有 AI-readable source view manifest/digest，明確連到 canonical snapshot，依使用者選定 scope、敏感檔政策與宿主資料處理設定建立。預設不向 agent 提供已識別的憑證、私鑰與私人 runtime 設定內容，也不在 prompt 補貼；本機既有 secret scanners 仍依原契約檢查其適用資料。View policy 的排除與任何遮罩必須可追溯，保留 source path/line 對應與實際讀取 bytes 的 digest；不得把未讀或已遮罩內容計為已檢查。敏感檔政策無法成立時該方法記錄 blocker，不默認整包傳出。

Cloudflare 位置驗證與 evidence extraction 指向實際 AI-reviewed view，並保持 canonical snapshot lineage。Agent 執行期間 target working tree 改變，不改寫已凍結的 source；使用者要掃新內容就建立新 run。

Target 內的 README、AGENTS、提示文字與工具設定是受檢資料，不能覆蓋本次 skill、scope、output ownership 或授權。新增 fixture 驗證惡意指令文字不會使流程連外、擴大目標、改寫 retained files 或執行未選定工具。

Cloudflare 與既有 source scanners 若使用不同 snapshot，合併報告必須顯示各自來源，不能把差異隱藏成同一份程式碼。

### 8.2 Target code 執行

第一版預設 source inspection；必要的 target-controlled build/test 只有在完整 sandbox 能力成立時才執行：無外部網路、隔離 loopback、乾淨且允許清單化的環境、唯讀來源/工具、scratch-only writes、CPU/記憶體/process/檔案/時間限制。[C02]

Scanner 自己的 bootstrap 可以依固定 lock 準備其相依套件；這不授權 target build 連外下載相依。無法驗證執行邊界時保留 blocker 與驗證計畫，既有 source evidence 仍可保存。

動態 evidence 的保留由受信 parent 程序負責：等 sandbox 與全部子程序結束後，只提升事前允許的檔案；使用保留的 directory/file handles 與 no-follow traversal，確認 regular file、link count 1、identity/size 穩定、單檔和總容量界線，並以 exclusive destination 寫入。不同 OS 要有等價保護。任何條件不成立便不接納該檔為證據，必要時記錄明確 validation blocker。

### 8.3 Cloudflare checkpoint

新增 provider 專屬 checkpoint，不把 agent 工作硬塞進 container image identity。

| Checkpoint | 可恢復的內容 |
| --- | --- |
| prepared | source、method revision、profile、scope、budget、capabilities |
| reconnaissance_saved | 架構原文、初始有效 ledger |
| wave_saved | hunter/critic outputs、ledger attempts、分配紀錄 |
| candidate_decisions_saved | 已完成的獨立判定與剩餘 fingerprints |
| final_verification_saved | 最終 records、修訂歷史、validator receipts |
| sealed | 原始 bundle、normalized records、完整性 manifest |
| reported | frozen projection、HTML/JSON、export receipt |

每個階段以新檔／新版本寫入並原子替換 checkpoint pointer；不得只有聊天中的「做完了」作為狀態。Interrupted assignment 重新分配新的 attempt ID，保留舊產物與中斷原因。

已取得 raw artifacts 而 normalization 失敗，重試應重新解析相同 bytes；不重新詢問 LLM或接觸目標。若 final verifier 改變重要主張，依 pinned 方法補新的獨立檢查，再封存。

Ledger 建立及每次更新都先通過其 validator；structured-output 階段及 final-verification 的每次 replacement 都重新通過兩個 validators。重要 replacement 若缺少新的獨立 verifier 或預算，爭議主張留在 ledger unresolved，run 為 incomplete，不列為新的正式 confirmed record；先前版本保留為歷史。這些是 checkpoint 能否推進的條件。

## 9. 報告精緻度與統一輸出

### 9.1 保留既有閱讀順序

維持現有產品定義的第一層：哪些資產有問題、什麼最優先、影響、最小下一步、如何驗證修復、哪些工作未完成。原始技術資料、hash、模型資訊與 sandbox 細節留在展開區及報告末端。[R02]

新增 Cloudflare 時只補需要的內容：

- 可行動 findings 依既有 priority system 排序，標示方法來源。
- source trace 與 execution evidence 可展開。
- 待驗證 hypotheses 與未驗證 candidates 分開，不能借用高風險數字營造更多漏洞。
- 未完成 coverage 在對應資產旁給一個具體下一步。
- rejected claims 放技術歷史，預設不搶佔主報告。
- 原始 Cloudflare MD/JSON 作附件或可驗證的 evidence reference。

新內容不得使現有 inventory、CVE、secrets、cloud、network、incident 或框架參考區消失。

### 9.2 Renderer 與敘述快照

先將 case_service.rs 的 HTML renderer 原樣提取，固定 inputs 下輸出保持一致；接著再新增 provider 區塊。避免在同一 commit 重新設計整份 HTML。[R03]

新 ReportSnapshot 至少保存：

- report snapshot ID、case/run 或 selected source run IDs；
- frozen canonical projection 與 report schema；
- renderer 另讀取的 grouping history、framework report、verification comparison/baseline 與相關 case context；只保存 `BeginnerMasterReport` 不足以重建現有整份 HTML；
- narrative strings、翻譯結果與缺省語言來源；
- renderer/core revision、template/assets digests；
- locale、redaction、attachment selection、固定 as_of/generated_at；
- canonical data digest、原始 HTML/JSON digests；
- 既有各方法 task/outcome，包含啟動失敗的狀態及可展開原因；
- legacy fallback、omitted evidence、source completeness 標記。

需要 AI 寫摘要或翻譯時，只在建立該版報告時完成並保存；重新開啟、export replay、restore 不重問 AI。原上游文字始終保留。

已保存 ReportSnapshot 不隨後續人工 triage 漂移；案件工作流仍可正常更新。要求反映最新處理狀態時建立新的 snapshot 與 receipt，保留前一版和原始 scanner observation。今天對 legacy fallback 做的快照，只能標示今天的呈現，不能說是當年掃描當時原貌。

Renderer 的版本號與 digest 不足以提供離線重建。受信任 core 必須內建它宣稱支援的版本化 renderer／資料遷移；archive 保存重建必要的非執行模板與 assets，禁止自動執行封存內的程式。如果某舊版只能讀原 HTML 而無可用 renderer，能力標示 retrieve-only，不能宣稱 replay-ready。

所有 provider 敘述、程式片段和路徑仍走既有 escaping／安全連結處理；原生 MD/HTML 不能以未處理 markup 注入主報告。加入 script、事件屬性及危險 URL 的呈現 fixture。

### 9.3 六種既有格式

| 輸出 | 本次要求 |
| --- | --- |
| HTML | 沿用樣式、資產表、優先列表、技術展開、列印、附件 |
| Canonical JSON | 同一 frozen projection；新增資訊有明確 schema 與來源 |
| Framework report | 沿用既有 mappings；未有根據的 Cloudflare 關聯保持 unmapped |
| OCSF | 保留 findings 及 coverage companion；不得遺失未知/未完成資訊 |
| OSCAL | 同上；不將新增 AI method 包裝成合規認證 |
| Existing signed case bundle | 繼續可匯出與驗證，原契約不偷換成完整 backup |

OCSF/OSCAL 目前的 coverage companion 和原子輸出規則要繼續維持。新 AI 資料若不適合某標準主檔，必須以既有 companion 或明確 extension 保存並在 receipt 說明；不能靜默丟失。[R03][R06]

### 9.4 合併報告的附件與快照

開發版 selected-run HTML 已實作原始附件與超限私密 archive fallback，沿用明確敏感資料選擇。第一版主流程採來源合併時，保留與單 run 報告相同的可取回能力：[R08]

- 每個原始檔以 source run/task namespace 歸屬；
- 保留各自時間、source snapshot、severity 與 coverage；
- 保留單 run 原檔累計 64 MiB／10,000 檔界線；combined HTML 現有整份文件另有 64 MiB 上限，必須計入 base64、ZIP、markup 及附件索引大小，兩者不可當成同一容量；
- 超限保留一份精緻可讀 HTML，原檔改由完整 archive 承載並提供清楚位置；
- 合併 projection 與最後 HTML 自己也有 ReportSnapshot；
- 不改寫既有單 run export history，不推斷跨 run 問題已修復。

既有合併的 HTML/JSON 保持可用；六種原有格式的兼容要求以原本支援的單 run 範圍為準，不虛構已存在六種 combined export。

## 10. 四種可還原性承諾

| 層級 | 必須提供的能力 | 精確限制 |
| --- | --- | --- |
| A. 原檔取回 | 取回當時的 HTML、JSON、MD、原始 evidence | 用原始 bytes/hash 保證；被分享設定排除的內容不能還原 |
| B. 報告重建 | 由 frozen projection 與相容 renderer 離線生成報告 | 固定 inputs/版本/時間的 deterministic payload 應一致；換 renderer 產生新 receipt |
| C. 案件還原 | 封存搬到新 workspace，恢復資產、run、findings、history、evidence 及報告 | 恢復資料，不重新授權掃描，不要求原絕對路徑存在 |
| D. 重新掃描 | 依保存設定建立新 run，與舊 run 比較 | AI 非確定性；不保證相同 findings，也不因未再找到就自動 resolved |

保存原 HTML bytes 是取回同一份檔案的直接保證。報告重建測試可要求 canonical JSON 與固定 renderer 的 HTML payload 穩定；不同瀏覽器／字型的畫面使用視覺等價驗收，不混成所有封裝壓縮 bytes 必須相同。

## 11. 完整 archive 與 restore 設計

### 11.1 使用獨立新格式

建議新增 ai-security-scanner.archive/v1，例如 .scanner-archive.tar.gz。保留既有 .case.tar.gz 格式與 verifier，不對舊 bundle 加上未能履行的完整還原承諾。

Archive payload 建議如下；實際路徑與 DTO 在第一階段定版：

| 路徑／資料 | 內容 |
| --- | --- |
| archive-manifest.json | schema、producer、minimum reader、完整性、omissions、來源索引 |
| case-snapshot.json | 專用可攜 DTO，完整案件資料與 relationships |
| run-snapshots/ | immutable run/scope/asset/finding observations |
| agent-audits/ | Cloudflare raw records、coverage、attempts、verifier receipts |
| artifacts/ | 被選入的原始 evidence，依 manifest 引用 |
| report-snapshots/ | frozen projection、render settings、原 HTML/JSON |
| source-snapshots/ | 已保存且被選入的必要 source snapshots |
| histories/ | grouping、workflow、comparison、export history |
| producer-locks/ | core/skill/provider/runtime/renderer 版本與相關 digests |
| signature.json / public identity | 沿用完整性簽章機制；不包含私人金鑰 |

不要直接複製 SQLite database 或序列化帶有 live handle 的內部結構。DTO 明確轉換資料位置、credential reference 和 runtime 狀態；storage_revision 不作跨 workspace concurrency token。

封存從單一已確認的 case revision／snapshot boundary 讀取 DTO、artifact inventory、workflow、既有任務結果與 report snapshots；不能分次讀取不一致的版本。Immutable blobs 沿用同一 verified handle 讀取。若封存期間相關資料改變而無法維持一致快照，回傳 conflict/retry；不得生成缺參照但自稱完整的 archive。

完整 archival DTO 必須涵蓋 AssessmentCase 的 inventory、exports、assessment context 及新 provider 資料，並做 reference graph validation。[R05]

### 11.2 完整度宣告

Manifest 至少區分：

- report replay 是否完整；
- case data restore 是否完整；
- raw evidence 保存範圍；
- source snapshot 是否存在；
- 每項 omission 的原因；
- credentials/signing private key 已排除；
- legacy 歷史欄位是否本來就不存在。

完整案件還原不代表一定能重新掃原始遠端系統。若未含 source snapshot，仍可恢復報告與證據，但不能宣稱擁有當時完整受檢來源。

對外 redacted handoff 不應被標記成完整 archive。本地 durable data 依正常流程保留證據；完整封存建立／匯出沿用清楚的敏感原始資料選擇，不自動將 raw data 放進分享版 HTML。

### 11.3 Restore 流程

1. Verify：有界讀 archive，驗 manifest、簽章、hash、長度、entry 種類與路徑。
2. Preview：顯示案件、run、artifact 數、schema 相容性、缺漏、來源與目的地。
3. Stage：在新 workspace 的暫存區建立資料；拒絕 symlink、hardlink、device、absolute path、parent traversal、大小寫碰撞與解壓炸彈。
4. Validate：檢查 case/run/task/asset/finding/evidence/reference graph；只解決保存區位置，不改寫原 evidence 的 source identity。
5. Publish：第一版只還原到新空 workspace，因此將新 DB 與 blobs 全部建在同檔案系統的 staging directory，完成驗證、關閉／同步 DB 與必要檔案後，透過單一原子 rename 發布目錄。若平台不能提供此條件，實作 durable commit journal 與恢復狀態機，不能把 SQLite transaction 宣稱成跨檔案系統原子性。
6. Receipt：保存 archive digest、source identity、new workspace identity、mapping、warnings 與結果。
7. Reopen：離線看原 HTML、驗 raw artifacts、重繪並比對 frozen projection。

預設 restore 到空 workspace，保留 archive 內的歷史識別值。第一版不做兩個獨立案件的智慧 merge；有 ID collision 就明確拒絕或另建 workspace，不靜默重新關聯 evidence。

Restore receipt 與 publish intent 在 staging 先持久化，避免發布後尚未補寫 receipt 就失去恢復線索。驗收涵蓋 DB 已完成但尚未發布，以及已發布但最後 acknowledgement 尚未完成兩個 crash 邊界；重啟只能看見完整案件，或可重試的未發布 staging。

歷史 scope grants 只供報告說明；credentials、live runtime ownership、未完成的 target-contact 指令不復活。後續重掃重新走目前有效的 scope/auth 流程。新機器的簽章 identity 用於新輸出，舊報告的簽章與 public identity 原樣保留。

## 12. 既有資料相容與回退

### 12.1 資料目錄策略

Skill 預設使用穩定的使用者資料目錄，與程式 build cache 分開，且位於受檢 repo 外。第一版避免直接用新 schema 修改舊安裝版正在使用的資料根目錄。

資料路徑由 product workspace resolver 決定，預設使用獨立 skill workspace namespace；不得只沿用現有 CLI 的 OS default 而意外開啟舊桌面的 writable 目錄。明確 data-root 選擇仍須通過相容版本及 writer lease 檢查。

舊資料移轉採 read-only source + copy/import 到新 workspace。原資料保存，使用者可繼續用原版本讀原目錄；同一份新資料不可交由舊 binary 同時寫入。

### 12.2 Schema 演進

2026-11-12 D7 B1：Rust 已新增嚴格 `agent_audit_failure` 與 `cloudflare_audit_terminal/v1`；受阻／終止保管與單一失敗列同交易保存，重播僅修復 pending 報告快照。共用報告、匯出與 failure-only provider 封存／唯讀還原已接線；資料庫 migration 仍為 [1, 2]，D7 B2 桌面與共用報告已對齊：未開始／未完成列、原因及下一步、資產缺口、技術明細、控制排除與整合報告選取均已接線。

2026-11-12 封存 B 切片已完成入案稽核的完整清單、create／verify 與兩個必要能力欄位；
舊案固定輸入 SHA-256 保持不變。來源省略只限已索引 body，歷史定稿包與擷取原件不改寫。
C 切片已接 provider preview／restore、staged 驗證、唯讀事件邊界、contextual 省略驗證、再次封存及整合附件超限私密封存；舊案 bytes 不變，migrations 仍為 [1, 2]。比較仍拒絕。D7 A 已加入宿主明示 terminate、全寫入終態防護、狀態與未定稿封存 custody；D7 B 的案件／共用報告失敗列及桌面對齊已完成。

- 11 月 12 日封存 A 切片：新增不依賴資料庫或檔案系統的 captured-history reader，從驗證事件列出所有文件修訂、已接受輸出與僅含中繼資料的已捨棄輸出；`retrieve-captured` 以單一唯讀快照、容量界限、精確摘要及安全目的檔發布恢復遺失宿主副本，不新增授權或事件。現有 status 已有目前修訂／摘要與派工身分／角色／摘要，語義不變。完整封存建立／驗證及惰性還原分別留給 B／C 切片，入案稽核比較仍拒絕。

- 11 月 12 日第七切片：已簽署案件包加入條件式案件層 `source-audit-admissions.json` 與 schema 項目，保留 profile 投影、原件綁定與提供者來源；框架延伸直接使用同份共用報告，Standard 隱藏數量不重建。bundle 與附件先驗證 admission graph；提供者工作不列入目錄／內建檢查。只有 `none` 加原始檔案選項包含精確原件；Standard 不讀取並計入敏感省略。單輪／整合附件保留巢狀名稱、摘要與輪次／工作命名空間，預覽獨立計數稽核工作；桌面已開放。含入案稽核案件的整合超限以 `source_audit_attachment_overflow` 在發布前拒絕，提示減少輪次或匯出案件包；沒有入案稽核的 fallback 不變。完整 archive／restore 與比較仍拒絕，留待後續切片。

- 新增 optional/defaulted 欄位，保留舊 finding/run 的讀取能力。
- 已建立 `AgentAudit` task kind、不可變 admission record、純規劃函式及 `cloudflare_audit_admission/v1` format requirement；只有 confirmed records 產生 finding 與 frozen observation。Rust match 與各輸出相容性閘門已接線；共用單輪／合併 HTML、canonical JSON 與快照已接受已入案稽核，角色及狀態計數納入 admission digest。已實作 admit 命令、原件安全發布／精確重用、單一案件交易、收據重播與狀態；禁止以 AgentAudit 執行 Check fixes 或 run comparison。入案交易後保存終態快照，失敗可用同一入案要求重播；11 月 12 日框架報告已加入遮蔽後的共用 source_audits 區塊；OCSF／OSCAL 僅輸出 confirmed findings 並附提供者身分，必要配套保留完整共用稽核報告，身分不代表控制項結論；已驗證 admission／task／artifact 繫結，標準設定的 unresolved 指紋與隱藏計數已修正；案件 bundle 與單輪／整合附件已於第七切片接入；完整封存仍拒絕整個已入案案件。11 月 12 日已接線桌面 TS task／report／provider record、待驗證與未測試顯示、原生文字及匯出限制，並恢復前端 parity；其他輸出整合由後續切片完成，不變更技能入口。
- 明確保存 minimum reader / archive schema version。
- 對未知新格式先拒絕寫入，保留原 bytes；不能「盡量讀」後覆蓋資料。
- Legacy fallback 以原有標記保留，不憑現況補造歷史 model、verifier 或 source digest。
- 報告判定、人工 triage、跨 run comparison 分別保存。

### 12.3 回退

Bootstrap 可切回上一個已驗證 core cache，但只有在資料 schema 相容時使用。Schema migration 前保留可還原副本；涉及新 task kind 的資料不可直接退給舊 reader。

已驗證：不支援入案的舊版 CLI 會在案件清單略過含已入案稽核的案件，開啟、修改、比較、封存與刪除計畫皆拒絕，且不改寫其資料；同一資料目錄的其他案件照常可用。

每個 PR 盡量保持舊入口可編譯／可讀；feature switch 關閉 Cloudflare 時仍能讀已保存的原報告及 raw artifacts。不得為停用方法刪除資料。

## 13. CLI 與 Skill Contract 提案

下表分開列出已實作的 source CLI 子集與仍待實作的設計契約。現有命令須維持相容；報告快照及寫出收據已有版本化 schema。前景命令已有版本化 envelope、case-event receipt 及 exit codes；bootstrap 已有 core 能力與建置收據、指定引擎的 runtime 準備及獨立收據。全新主機 managed bundle 自動取得與 provider 介面仍待實作。

| 指令族 | 現況／變更 | 契約 |
| --- | --- | --- |
| bootstrap doctor / prepare / run | 已有開發版固定建置入口及指定引擎 prepare；產品原 doctor 保留 | 來源版本、toolchain、cache、逐項能力、缺失原因；case／runtime prepare 要求明確 data-dir |
| runtime prepare --engine | 已實作指定映像準備與 offline 模式 | 驗證全部選項、共用 runtime resolver、逐項結果、先保存收據、不建立案件或授權、不接觸目標 |
| build-identity | 已有唯讀提早分流，不開資料目錄 | 編譯 target、features、Rust 版本、report source digest 與 bootstrap input digest |
| scan run --wait | 開發 source 已實作；非已發布 skill 預設入口 | 單 owner、durable terminal outcome、NDJSON |
| scan recover --wait | 開發 source 已實作 captured-only／cleanup-only 子集 | 先取得 lease，重解析 exact artifacts 或清理 recorded runtime；不自動建立 target-facing attempt |
| scan status | 已接唯讀路徑 | 讀取已存在的相容 DB；不取得 writer lease、不 migration、不恢復或改寫 live worker 狀態 |
| provider cloudflare prepare | 開發來源已實作準備收據、產品身分、重試與描述檔恢復；不執行稽核或模型 | 綁定 ready 來源目錄、授權、profile、budget 與宿主；已支援派工、擷取、驗證與定稿；案件／報告整合待完成 |
| provider cloudflare status | 開發來源已實作唯讀查詢 | 依準備請求或稽核識別碼讀取歷史收據、驗證後的紀錄鏈、派工狀態、角色計數、預算與描述檔狀態；不取寫入鎖；定稿前可接續檢查點或驗證，定稿後回報三份提交檔案的完整性及明確驗證範圍、終態投影及無下一步操作 |
| provider cloudflare checkpoint | 開發來源已實作派工、中斷、共用文件及派工輸出擷取、最終驗證派工 | 支援七種共用文件與各角色單一輸出契約、固定版本驗證器、私有內容定址物件、文件修訂及累計容量限制；驗證者格式不合時永久捨棄，可另行派工並計入預算。最終驗證派工由產品綁定已接受發現文件的修訂與紀錄雜湊；沿用鏈首比對、重試與交易內授權核對，驗證資源改變時拒絕舊準備。定稿後所有檢查點均拒絕變更；案件／報告整合待完成 |
| provider cloudflare validate | 已實作（開發核心） | 從產品保管的位元組產生終態 manifest；完整核對來源與授權，回傳三層驗證、紀錄檢查、可定稿狀態及 digest；不寫入紀錄或定稿 |
| provider cloudflare finalize | 已實作（開發核心） | 以預期鏈首及資料包雜湊重新驗證，發布唯讀資料包並交易提交終態紀錄；獨立投影記錄工作流程來源，可重試並恢復已發布但未提交的資料包；定稿後拒絕變更，案件／報告正式接納與完整封存整合待完成 |
| provider cloudflare inspect-sealed | 已實作（開發核心） | 離線核對完整定稿資料包、產品紀錄鏈與來源收據；不取寫入鎖、不重新執行驗證器，回報資產與來源是否仍存在；不接納至案件 |
| export create / combine / verify | 保留現有命令並加法擴充 | 單 run 六格式；combined HTML/JSON；保留遮罩與完整性 |
| report snapshot / inspect / retrieve / replay | 已實作 terminal run／單 run 與 combined 匯出自動快照及手動快照；[目前用法](../report-snapshots.md) | 保存完整私密 render context 與原始 HTML/JSON；相容 core 才重建，否則可取回原檔；無 AI、無 target contact |
| archive create / archive verify | 已有開發版實作 | 明確完整度、omissions 與 archive receipt；既有 case archive 保持案件狀態操作原義 |
| archive restore-preview / restore | 已有開發版實作 | 新 workspace，驗證後原子提交；沿用 saved receipt 恢復遺失的 acknowledgement |

現有 export create 已使用 case-id、run-id、format、destination、redaction、locale；include-raw-artifacts 必須搭配明確敏感資料 acknowledgement。Skill 不得為方便而無條件代填。[R09]

本輪不要求全新 REST/MCP server。未來如增加，都應包裝相同核心 contract。

### 13.1 新介面的共同資料契約

以下固定新增介面所需語義；前景命令已提供版本化 envelope 與 receipt，其他新增介面的 Rust 型別／JSON schema 與 compatibility corpus 仍分批接入。不能將下列共同設計視為全部現有 CLI 的輸出承諾；既有命令及 task wire enum 維持相容。

| 資料群 | 必須可機械讀取的資訊 |
| --- | --- |
| Command envelope | `schema_version`、operation、request ID、command outcome、error code、可否重試；人類可讀訊息不能替代 typed result |
| Durable result | case/run/task/session IDs、case revision、已提交的 receipt ID/digest；尚未建立或未知的值明確為空，不補假 ID |
| Run summary | 既有 task statuses、各來源 completeness、confirmed findings counts、coverage gaps；不由 exit code 推定乾淨結果 |
| Capability | host OS/arch、build/core/runtime/delegation/sandbox 各項 available/unavailable/unknown、原因與實際驗證依據 |
| Artifacts | report snapshot、HTML/JSON、archive 與 receipts 的位置、長度、digest、omissions；只列實際已保存產物 |
| Recovery | durable checkpoint、exact pending cleanup、下一個受支援操作；不得回傳假背景 job 仍在執行 |

JSON 模式輸出一個 terminal envelope；NDJSON 模式先輸出 typed progress/events，再輸出一次 terminal envelope。診斷走 stderr。Consumer 使用版本及 typed fields，不解析 prose 或用 findings 數推測 command 成敗。輸出管道失敗須保留 durable receipt，下一次可用唯讀 status 取得，不能因此重做掃描。

退出碼表在 CLI parser 實作前與現有 error convention 一起固定，並納入 CLI contract corpus；最低契約是「成功提交結果」、「非法／不支援輸入」、「busy/conflict」、「操作／持久化失敗」和「中斷」可區分，發現漏洞不使成功提交變成命令錯誤。`command outcome` 與 run completeness 始終分開。目前前景命令固定為 0 成功提交、2 輸入／能力拒絕、3 busy/conflict、4 操作／持久化／輸出／待恢復、130 SIGINT、Unix 143 SIGTERM。既有命令保留原碼；詳見[目前介面](../foreground-scans.md)。

Provider envelope、ReportSnapshot、portable archive DTO 的欄位與語義以[報告保真與封存契約](../specs/report-fidelity-and-archive.md)為準。Core、provider method、report、archive schema 各自版本化；未知的新寫入格式拒絕 mutation，保留原檔。

## 14. 測試與跨 OS CI

### 14.1 CI 分層

| Lane | 觸發範圍 | 核心驗證 |
| --- | --- | --- |
| skill-contract | skill、provider、wrapper、manifest | 同步一致、檔案存在、pin、能力分支、代表性 workflow |
| core-host-matrix | core、CLI、storage、renderer | native Windows/macOS/Linux build + 核心 smoke |
| provider-contract | Cloudflare vendor/adapter/schema | 上游 corpus、mapping、壞輸入、跨檔案關聯 |
| report-parity | report/domain/export/provider | legacy/current fixtures、六種單 run 格式、combined report、遮罩及視覺 |
| archive-roundtrip | archive/storage/artifact/schema | 新 workspace 離線 restore、hash/reference、failure injection |
| runtime-contract | runtime/helpers/engine adapter | 支援組合的實際啟動、capture/cleanup、scope 與來源驗證 |

CI classifier 已新增 skill contract 與 native bootstrap 範圍；skill 文字修改會驗證同步／契約，但不因此重建 core。新增 Windows、macOS、Linux 的 native bootstrap／report／archive lanes；實際平台結果仍分別收集。Windows managed-runtime 驗證保留，NSIS step 改由 installer inputs 單獨觸發。後續 providers/ 的執行契約隨 provider 實作擴充。[R17][R18]

不建立「每次提示修改都重跑全部 VM 和所有真實遠端掃描」的門檻。既有大量 fixtures 應重用；live smoke 只針對具體變動風險或需要驗證的支援組合。Engine image 工作流獨立保留，installer/release 不再是 skill merge 的必要 gate。

### 14.2 代表性 fixture 集合

| 類型 | 最低案例 |
| --- | --- |
| 既有報告 | current/legacy、正向 finding、零發現但有實際 checks、partial、failed、cancelled、inventory-only |
| Cloudflare findings | confirmed、needs_validation、rejected、空陣列＋有效coverage、無法完成validation的candidate |
| Cloudflare coverage | covered source-only、local artifact、blocked、deferred、out_of_scope、critic reopen、candidate有final disposition |
| 整合 | 原有引擎＋Cloudflare、同一問題多來源但未自動合併、Cloudflare 無法啟動時該列失敗且可展開原因 |
| Evidence | hash mismatch、缺檔、錯 run、相對路徑越界、link、Windows reserved name/case collision |
| File limits | 4 MiB Strix policy 不變、5 MiB Cloudflare 邊界、JSON depth、record/unit count、總附件上限 |
| 恢復 | captured artifacts 重解析、階段重試不重複、archive 並行變更的一致快照、publish 前後 crash、schema 不相容、legacy fallback |
| 呈現 | EN/繁中、390/768/1440px、長路徑、長標題、code evidence、列印、附件超限與遮罩 |

不得把「同一模型重跑總是同樣找到 N 個漏洞」列為測試。Provider adapter 用固定 artifact corpus 驗證；方法品質另外用受控樣本觀察，不混同 deterministic regression。

### 14.3 視覺回歸

從 baseline core 產生代表性 HTML，固定時間／資料／locale／redaction。Renderer extraction 階段先比相同輸入的 HTML bytes，再比新擴充區塊的 DOM/語義與 screenshots。

沿用 DESIGN.md 的配色、字型 fallback、可展開技術資料、非只靠顏色的狀態，以及既有窄螢幕表現。[R21]

PDF 本輪沿用瀏覽器列印能力；不另立 PDF engine，也不將列印版聲稱為原始附件的承載格式。

### 14.4 執行與方法驗收索引

CORE-01…CORE-04 已有開發版共用 coordinator、owned worker、receipt、lease 與 captured-only recovery 接線；Linux 子程序及核心測試證據記於[開發紀錄](../development-status.zh-TW.md)。11 月 9 日已由固定 bootstrap 快取執行真正 pinned Gitleaks，自建 fixture 產生一筆預期發現，原始秘密值完整遮蔽，並完成報告及完整封存還原；精確證據見 [bootstrap 紀錄](../skill-bootstrap.md#november-9-selected-engine-and-real-scan-validation)。桌面／前景結果對照、三平台及多資產／Cloudflare 完整流程仍為 **pending**，不能將模擬 runtime 的 adapter 測試當成真上游執行證據。每筆證據保存 source revision、平台／宿主能力、fixture digest、命令、結果及產物；doc test 通過不改變此狀態。報告及 archive 的 RF-01…RF-09／AR-01…AR-06 詳見[資料驗收](../specs/report-fidelity-and-archive.md#9-可追蹤驗收與現有測試接點)。

BOOT-01 已有固定輸入、並行鎖、失敗保留、快取竄改及 prompt-only 重用的執行測試。BOOT-02 已有 Linux 實際編譯、二次快取命中，以及刪除合成案件 workspace 後 HTML／JSON 取回與重播的證據。11 月 9 日再驗證 offline 指定引擎準備重用核心與既有精確映像；真正 Gitleaks 掃描後移開原資料，完整 archive 還原仍保留發現、raw、source snapshot 及前景 receipt，HTML／JSON 取回與重播等同原始 bytes，且不恢復掃描授權。全新主機 managed bundle 自動取得、Windows／macOS native 執行及完整多資產／Cloudflare skill-to-restore 仍為 **pending**；新增 CI lanes 不等於已在該平台通過。

| ID | 最小可觀察驗收 | 實作批次 |
| --- | --- | --- |
| CORE-01 | 同一受控 scanner/fixture 經 desktop 與 foreground coordinator，scope/task routing、findings、evidence、coverage 語義一致 | PR 4 |
| CORE-02 | live owner 存在時第二 writer 回 busy；status 可讀且不建立資料、不 migration、不改 revision 或 live state | PR 4 |
| CORE-03 | 前景返回後 exact generation 的結果能重開；callback／輸出中斷、Ctrl+C 與 cleanup 失敗均有 durable outcome 或明確 recovery obligation | PR 4 |
| CORE-04 | captured artifacts recovery 只重解析；cleanup 使用原 runtime identity；需重新接觸 target 的 attempt 重新核對有效授權 | PR 4 |
| BOOT-01 | cache hit／prompt-only 變動不重建；core input 變動會失效；產物竄改拒用；失敗不覆蓋 last-known-ready | PR 5 |
| BOOT-02 | 三 OS native core/report smoke 分別有證據；report/restore/source-only 不下載無關映像；不改舊桌面資料目錄 | PR 5 |
| CF-01 | 缺 delegation／必要預算時方法列失敗且有原因，其他方法結果仍存在；guidance 不計為 full audit | PR 6–7 |
| CF-02 | upstream/wrapper corpus 接受及拒絕一致；產品加嚴另記；三 OS reader、preflight limits、Node isolation 均有證據 | PR 6 |
| CF-03 | 原 hunter 不可當獨立 verifier；壞 verifier JSON 不由 parent 修復；重要 replacement 缺 fresh verifier 時保留 unresolved 與 incomplete | PR 7 |
| CF-04 | AI view 不包含政策排除的敏感檔；working tree 變更不改已讀 bytes；target prompt injection 不改 scope、工具或 retained files | PR 7 |
| CF-05 | 無完整 sandbox 不執行 target code；有 sandbox 時驗證無外網、無 inherited credentials、唯讀輸入和資源界線 | PR 7 |
| CF-06 | 子程序未退出、link/FIFO、變動檔、超限、錯 agent/run artifact 不獲提升；raw bytes 與 admission hash 一致 | PR 6–7 |
| FLOW-01 | 一次 skill request 完成既有 scanner＋Cloudflare、共享合併報告、完整 archive、新 workspace 離線 restore；各來源與失敗列保留 | PR 8 |

## 15. 分階段 PR 計畫與相依性

### 目前實作與剩餘工作

| 工作 | 本次狀態 | 下一步 |
| --- | --- | --- |
| Owner 決策、canonical product spec、操作規則與公開文件的階段說明 | 已寫入規格 | 維持目前可用入口；完成端到端驗收後再切換 |
| 基準程式／Cloudflare 上游查核、資料欄位語義、驗收索引 | 已完成只讀查核與規格 | 在 PR 1 固定 wire schema／exit codes 與輸入 corpus |
| Baseline semantic outputs、固定 HTML bytes 與 screenshots | 已由原 core 生成並保存 [baseline corpus](../../tests/fixtures/report-fidelity/README.md) | 保持原件，使用固定 inputs 比較目前 exporter；不可更新 expected outputs 掩蓋 extraction 差異 |
| 共用 Renderer／單 run ReportSnapshot | 已實作 HTML／canonical JSON 共用 renderer、完成與單 run／combined 匯出自動快照、手動快照、inspect／retrieve／replay，完整 archive 自動保存已記錄原件 | combined 原始附件與超限 fallback 已接線；桌面選項已接線；補齊跨平台原生執行證據 |
| 唯讀 scan status | 已實作提早分流，不初始化 runtime 或 writer lease；可查已保存 command receipts | 保持與 live owner 共存 |
| Cloudflare captured history／宿主副本恢復 | 封存 A 切片已加入純事件清單與唯讀 `retrieve-captured`，涵蓋過往修訂、所有已接受輸出及已捨棄輸出的不可用標記；共用技能指引已同步 | B／C 切片已接完整封存建立／驗證、唯讀還原及繼承來源省略；比較仍拒絕；D7 B1 已加入 Rust 案件／報告失敗列，D7 B2 桌面與共用報告已對齊：未開始／未完成列、原因及下一步、資產缺口、技術明細、控制排除與整合報告選取均已接線 |
| D7 A 明示終止 | 已實作嚴格 terminate request、精確重播、滿額紀錄的單筆終態保留、所有後續寫入拒絕、狀態及帶 capability 的未定稿封存／唯讀還原；宿主技能指引已更新 | D7 B1 已加入 blocked／terminated 單一案件／報告列、快照、匯出及完整封存；D7 B2 桌面與共用報告已對齊：未開始／未完成列、原因及下一步、資產缺口、技術明細、控制排除與整合報告選取均已接線 |
| 完整案件 archive／restore | 已實作既有 domain 的 DTO／事件／raw／報告保存、選配來源與原匯出、verify／preview／原子還原 | 入案 provider 完整封存 create／verify 與 C 切片唯讀還原、繼承來源省略及再次封存已接入；三平台原生驗收仍待補齊 |
| Headless coordinator／前景 CLI | 已實作共用 worker、exact generation join／reconcile、訊號／輸出中斷與 captured-only recovery；bootstrap 已共用固定取消管道，Linux 驗證父程序結束後的清理與保存；已執行真正 pinned Gitleaks 至封存還原 | 桌面對照、Windows／macOS 前景取消的原生證據及三平台驗收 |
| 固定來源 bootstrap／canonical skill／CI 解耦 | 已實作 doctor／prepare／run、受控輸入快照、驗證快取與編譯身分、skill 同步及三 OS CI lanes；指定引擎 prepare 重用核心快取並保存逐項 runtime 收據；真實宿主已從空快取以 release 設定離線建置，並經 `run` 完成整個流程 | 自動取得 managed bundle；完成 Windows／macOS native 執行證據 |
| Cloudflare vendor／adapter／宿主流程 | 已實作固定上游驗證、來源目錄、準備、派工、文件及輸出擷取、終態驗證、定稿與完整離線核驗；定稿資料包保存原件與獨立工作流程投影，外部資料包仍僅屬回報資料；開發宿主技能在定稿核驗後自動入案並交付共用報告，可依請求整合掃描工具結果與建立、驗證完整封存；已發布桌面入口不變 | 開發技能已提供[共用宿主操作指引](../../skills/ai-security-scanner/references/cloudflare-source-audit.md)、合成來源驗收工具與公開 CLI 還原驗證工具；一個 Linux 宿主已完成快速設定、預算七次的合成來源稽核至定稿，並以單一請求完成 Gitleaks、稽核、自動入案、繁中整合報告與完整封存，lead 還原驗證 78 項全數通過；入案案件封存保存完整稽核歷史與選配來源資料，還原後為唯讀歷史；未入案的舊案封存仍明列省略稽核資料包；待完成另一宿主驗收；見[定稿指南](../cloudflare-provider.md#sealing-the-audit-record) |
| Cloudflare admission domain | 已完成型別、confirmed mapping、原件發布／中斷重用、admit 單一交易、重播與狀態；共用單輪／合併 HTML／JSON 與快照已接線，入案後保存終態快照並支援失敗重播 | 11 月 12 日已完成 TS 顯示、生命週期及匯出限制與前端 parity；框架／OCSF／OSCAL 及必要配套現已接受入案稽核，維持人工處理狀態與非控制項結論；第七切片已完成案件 bundle、單輪／整合附件與 profile 原件選取；封存 B／C 切片已接完整封存、唯讀還原與超限私密封存，比較留待後續；本切片不變更技能入口 |
| 三平台／宿主實測、完整 skill-to-restore 與首選入口切換 | Linux 自建本機專案至報告／封存還原已實測；macOS／Windows CI 已涵蓋核心、稽核、報告及封存；一個 Linux 真實宿主已完成單一請求至封存，並經 lead 還原驗證與 v0.6.2 舊版讀取拒絕確認；另一次由宿主從空快取以固定版本 bootstrap 自行建置後完成同一流程，還原驗證 78 項全數通過；以新的空快取離線重建同一固定版本（舊快取不可讀取），執行檔摘要與先前相同，建置與還原皆無網路連線嘗試，還原驗證 78 項全數通過；未開始與已停止的稽核在重新開啟及封存還原後仍保留原因與收合的技術明細，已有自動測試；報告第一層會把待驗證項目列為下一步 | 第二個宿主、完整多資產及三平台前景流程仍 pending；對照 §14／§16 保存證據，不以編譯或文件測試代替 |

PR 1 的規格與報告基準已建立；provider wire contract 已有 reported bundle v1，核心已記錄並定稿宿主協調流程，開發技能已具備操作指引及合成來源準備工具，並已以一個宿主完成從掃描、稽核、入案、整合報告到封存還原的真實執行驗收；另一宿主實測仍待接入。PR 2 已有 terminal run／單 run 與 combined 匯出自動快照及手動快照，PR 3 已有既有 domain 的完整封存／還原，PR 4 已有唯讀 status、前景 run／有限 recovery 及版本化 receipt，PR 5 已有固定來源 core bootstrap、指定引擎準備與 skill／CI 接線；這些不代表整批或整個 migration 完成。當前操作與邊界見[bootstrap 文件](../skill-bootstrap.md)、[報告快照文件](../report-snapshots.md)、[案件封存文件](../case-archives.md)與[前景掃描文件](../foreground-scans.md)，已執行驗證記於[開發狀態](../development-status.zh-TW.md)。內部 Rust 型別名稱可調整，但不能改變已固定的使用者行為與資料不變條件。

### PR 1 — 決策、契約與現況基準

目的：先固定要保留什麼，防止 coding agent 將改入口解讀成重寫整個產品。

變更：

- 更新 product-spec、AGENTS/CLAUDE、README/getting-started 的下一階段入口決策；現行使用說明保留已可執行路徑，PR 9 才切換正式首選；
- 建立本計畫與 report-fidelity acceptance 文件；
- 盤點 current fixtures、格式與 schema；
- 產生 baseline report semantic snapshots 與視覺基準；
- 定版新增 provider envelope、report snapshot、archive DTO、CLI contract 的欄位。

完成條件：基準來自指定 core commit；已確認目前與目標的差距；沒有刪掉既有 detector/資料格式；尚未實作的命令明確標為 planned，文件依實際進度列出可用子集。

### PR 2 — 共用 Renderer 與 ReportSnapshot

相依：PR 1。

變更：原樣抽取 Rust HTML renderer；保留 CaseService 轉接；加入 frozen projection、narrative、locale/redaction/as_of、renderer identity 及原始輸出收據。

完成條件：既有 fixture 六格式語義一致；renderer 抽取前後 fixed-input HTML 一致；舊報告不因新 finding/asset/triage 而漂移；legacy fallback 仍可辨識。

### PR 3 — 完整 Archive、Verify、Restore、Replay

相依：PR 1、PR 2。

變更：新增 portable archive DTO、manifest、snapshot/blob 引用、preview／verify／atomic restore，以及離線 replay。舊 case bundle 契約保留。

完成條件：全新空 workspace、無舊 build cache、無 AI／無網路還原；由宣稱相容的受信 core 取回原報告 bytes、驗 raw evidence、重建 projection；缺 renderer 明確標示；漏檔與損毀不能得到成功；不恢復 live authorization。

### PR 4 — ScanCoordinator 與真正 Headless 執行

相依：PR 1；可與 PR 2 部分並行，避免同時修改 case_service 同一區塊。

變更：提取 CoreState/EventSink/協調流程；前景 CLI 執行；lease、checkpoint、cleanup 和 status read path。

完成條件：代表性既有 scanner 從 CLI 取得與舊路徑相同的 canonical result；中斷/重解析/競態有行為證據；desktop adapter 保持可用。

### PR 5 — Skill Bootstrap 與 CI 解耦

相依：PR 4 的介面；可先實作 cache/manifest 與 classifier。

變更：獨立 bootstrap、core/toolchain cache、按需 runtime、skill canonical source、跨 OS lanes；移出 installer gate。

完成條件：有 cache 時不重建；prompt-only 變動不重建 core；cache 損壞會被辨識；native 三平台 core/report smoke；不需要生成 MSI/DMG/DEB 才能完成 skill 流程。

### PR 6 — Cloudflare Vendor、Adapter 與原始證據

相依：PR 1 的契約、PR 2 的報告模型。

變更：固定 vendor、LICENSE/lock、safe reader wrapper、上游 validators、三 verdict mapping、coverage、原始 bundle 留存、cross-file validation。

完成條件：全部受控 fixture 對映正確；needs_validation/rejected 無 severity；unvalidated candidate 留在 ledger；Windows reader 能力經實測；原始 bytes 不變。

### PR 7 — 宿主 Skill 協調與階段恢復

相依：PR 4、PR 5、PR 6。

變更：主 skill 能力檢查、Cloudflare prepare/checkpoint/finalize、標準流程角色映射、budget、source/sandbox policy；沿用既有方法清單與任務結果。

完成條件：至少各在宣稱支援的宿主實際完成受控 audit；獨立 verifier 紀錄存在；缺能力時 honest blocked/incomplete；中斷後能接續已保存資料；不透過假 async CLI 丟失 worker。

### PR 8 — 完整成果、合併附件與端到端驗收

相依：PR 2、PR 3、PR 7。

變更：一次 skill request →既有掃描＋Cloudflare→專業合併報告→完整封存→新 workspace 還原；加入 combined attachments 與其 ReportSnapshot。

完成條件：符合第 16 節所有必要 gate；上游、產品、機器格式的數字與證據互相一致；報告視覺與可讀性不退步。既有任務保存測試包含「Cloudflare 無法啟動」：重開／還原後仍是該列失敗並可展開原因；加驗舊 report snapshot 不變而新版能反映人工 triage。

### PR 9 — 文件收斂與預設入口切換

相依：PR 8。

變更：將已驗證的新 skill path 設為正式首選；安裝版下載移到歷史／次要入口；更新所有語言的入口承諾、能力矩陣與結果說明。刪除過時的 release gate 關聯，不刪歷史 release records 或可讀舊資料所需程式。

完成條件：README、AGENTS、兩個宿主 skill、product-spec、CI 與實際指令一致；沒有以 planned 介面冒充已實作功能；正常貢獻者不需要跑 installer pipeline。

### 可並行與應保持單一 ownership 的工作

- 基準與契約完成後，renderer/restore、headless/bootstrap、Cloudflare adapter 可分支並行。
- domain.rs、case_service.rs、CLI contract、report schema 的變動由一個整合負責人協調。
- Cloudflare adapter 先以 fixtures 開發，宿主協調在 contract 穩定後接入。
- 每個 PR 先通過其直接風險的驗收再往下，不把完整產品改寫塞進一個巨型 PR。

## 16. 第一版整體 Definition of Done

1. 使用者從一個 skill 入口完成受控專案的既有掃描與 Cloudflare audit，不必下載桌面安裝器。
2. 支援平台的 bootstrap 可以從固定 source build，並準確呈現 core／runtime／sandbox 各自能力。
3. 原有安全檢查、scope、inventory 與六種單 run 輸出在 regression corpus 中保持語義。
4. Cloudflare 的三種 verdict、未驗證 candidates、coverage、attempts、原始 MD/JSON 全部可追溯。
5. 同一份資料由 UI/CLI/HTML/JSON 使用同一報告契約，沒有另寫品質較低的 skill-only report。
6. 合併結果保留每個來源的 snapshot、時間、限制和證據；沒有跨 run 的假修復判斷。
7. 原 HTML 和原始 evidence 可取回且 hash 一致。
8. 沒有舊 build cache 的新 workspace 可以由相容受信 core 離線 restore 完整 archive，讀原報告並重建相同語義的 projection。
9. 報告重建不呼叫 LLM，也不依賴 target、舊機器路徑或掃描 runtime。
10. Legacy 案件可讀；缺失的歷史資訊未被補造；舊資料原件保留。
11. 中斷、壞 JSON、hash mismatch、非法路徑、缺 verifier、缺 sandbox、預算耗盡，不會產生假 complete 或 clean。
12. 跨 OS CI 驗證必要工程行為，installer/release publication 不在完成條件內。

## 17. 本輪排除與後續擴充

本輪不做 Claude/OSS Scanner 接入、通用第三方 marketplace、模型訂閱代理、專用雲端後端、完整 UI redesign、自動修補、live exploit、任意遠端掃描擴張、所有 OS/CPU 的無條件完整支援。

可在本輪成熟後評估：正式 background worker/IPC、更多 provider、標準 SARIF 匯入、跨來源的證據等價規則、受控的並行執行。這些不阻擋本輪 skill 路線和 Cloudflare 整合完成。

## 18. 給 Coding Agent 的執行要求

1. 先讀本計畫、AGENTS.md、docs/product-spec.md 及當前 HEAD 差異；以本次 owner 明確決策更新過時桌面入口條款，不反過來要求 owner 再批准相同方向。
2. 從 PR 1 開始建立基準；不要先刪 Tauri、移除 scanners 或改報告樣式。
3. 所有事實性結果由保存的 core/provider 資料產生；禁止用一段自然語言 summary 取代原始 artifacts。
4. 新增功能名稱、schema 和介面在提交中明確標示，測試要驗證使用者能觀察的行為與重要資料不變條件。
5. 不把 source build、installer packaging、runtime preparation、target build 混為一件事。
6. 對大型檔案採最小可審查的提取，避免無關重排；先保留行為再擴充。
7. 每階段回報變更、驗收證據、尚缺能力與下一階段；未執行的 build/test 不得寫成通過。
8. 以第 16 節為完成標準，避免擴張成新一輪 release qualification 工程。

## 19. 來源與查核範圍

以下為本計畫既有事實的 primary sources。計畫中的新增 API、目錄、資料結構、測試與 PR 次序是設計建議，不宣稱已存在。研究只讀取程式與文件，未執行實際建置／掃描／恢復。

- 產品與報告：[產品規格][R02]、[共用 exporter][R03]、[資料模型][R05]、[bundle 與簽章][R06]、[原始附件][R20]。
- 執行與交付：[CLI][R09]、[掃描協調][R10]、[checkpoint][R12]、[Cargo features][R14]、[CI][R17]、[path classifier][R18]。
- Cloudflare：[方法][C02]、[finding schema][C03]、[驗證與報告][C04]、[coverage][C05]、[ledger validator][C06]、[findings validator][C07]、[MIT 授權][C01]。

[R01]: https://github.com/TED-H-com/ai-security-scanner/blob/6e259b497b87fb8aa2ece1f3b512cc29c9ea5af7/AGENTS.md "Owner authority and product constraints"
[R02]: https://github.com/TED-H-com/ai-security-scanner/blob/6e259b497b87fb8aa2ece1f3b512cc29c9ea5af7/docs/product-spec.md "Canonical product behavior"
[R03]: https://github.com/TED-H-com/ai-security-scanner/blob/6e259b497b87fb8aa2ece1f3b512cc29c9ea5af7/src-tauri/src/case_service.rs "Shared exports and HTML renderer"
[R04]: https://github.com/TED-H-com/ai-security-scanner/blob/6e259b497b87fb8aa2ece1f3b512cc29c9ea5af7/src-tauri/src/beginner_report.rs "Unified report model"
[R05]: https://github.com/TED-H-com/ai-security-scanner/blob/6e259b497b87fb8aa2ece1f3b512cc29c9ea5af7/src-tauri/src/domain.rs "Cases, observations, task kinds and evidence"
[R06]: https://github.com/TED-H-com/ai-security-scanner/blob/6e259b497b87fb8aa2ece1f3b512cc29c9ea5af7/src-tauri/src/export.rs "Bundle construction and verification"
[R07]: https://github.com/TED-H-com/ai-security-scanner/blob/6e259b497b87fb8aa2ece1f3b512cc29c9ea5af7/docs/external-scanner-import.md "Existing bounded import and combined report contract"
[R08]: https://github.com/TED-H-com/ai-security-scanner/blob/6e259b497b87fb8aa2ece1f3b512cc29c9ea5af7/src-tauri/src/selected_run_report.rs "Historical source report composition"
[R09]: https://github.com/TED-H-com/ai-security-scanner/blob/6e259b497b87fb8aa2ece1f3b512cc29c9ea5af7/src-tauri/src/bin/cli.rs "Current CLI"
[R10]: https://github.com/TED-H-com/ai-security-scanner/blob/6e259b497b87fb8aa2ece1f3b512cc29c9ea5af7/src-tauri/src/commands.rs "Desktop-coupled execution coordination"
[R11]: https://github.com/TED-H-com/ai-security-scanner/blob/6e259b497b87fb8aa2ece1f3b512cc29c9ea5af7/src-tauri/src/state.rs "Core resources and runtime identity"
[R12]: https://github.com/TED-H-com/ai-security-scanner/blob/6e259b497b87fb8aa2ece1f3b512cc29c9ea5af7/src-tauri/src/orchestrator.rs "Execution checkpoints and resume actions"
[R13]: https://github.com/TED-H-com/ai-security-scanner/blob/6e259b497b87fb8aa2ece1f3b512cc29c9ea5af7/scripts/release/build-sidecar.mjs "Current packaging-oriented builder"
[R14]: https://github.com/TED-H-com/ai-security-scanner/blob/6e259b497b87fb8aa2ece1f3b512cc29c9ea5af7/src-tauri/Cargo.toml "Cargo feature boundaries"
[R15]: https://github.com/TED-H-com/ai-security-scanner/blob/6e259b497b87fb8aa2ece1f3b512cc29c9ea5af7/runtime/upstreams.lock.json "Runtime source pins"
[R16]: https://github.com/TED-H-com/ai-security-scanner/blob/6e259b497b87fb8aa2ece1f3b512cc29c9ea5af7/src-tauri/src/workspace_snapshot.rs "Bounded source snapshots"
[R17]: https://github.com/TED-H-com/ai-security-scanner/blob/6e259b497b87fb8aa2ece1f3b512cc29c9ea5af7/.github/workflows/ci.yml "Current CI lanes"
[R18]: https://github.com/TED-H-com/ai-security-scanner/blob/6e259b497b87fb8aa2ece1f3b512cc29c9ea5af7/scripts/ci/classify-changes.mjs "Path classifier"
[R19]: https://github.com/TED-H-com/ai-security-scanner/blob/6e259b497b87fb8aa2ece1f3b512cc29c9ea5af7/src-tauri/src/artifact_store.rs "Verified artifact storage"
[R20]: https://github.com/TED-H-com/ai-security-scanner/blob/6e259b497b87fb8aa2ece1f3b512cc29c9ea5af7/src-tauri/src/report_attachments.rs "Original-file HTML attachments"
[R21]: https://github.com/TED-H-com/ai-security-scanner/blob/6e259b497b87fb8aa2ece1f3b512cc29c9ea5af7/DESIGN.md "Existing visual system"
[R22]: https://github.com/TED-H-com/ai-security-scanner/tree/6e259b497b87fb8aa2ece1f3b512cc29c9ea5af7/docs/samples/v0.4.0 "Existing visual reference samples"
[R23]: https://github.com/TED-H-com/ai-security-scanner/blob/6e259b497b87fb8aa2ece1f3b512cc29c9ea5af7/src-tauri/src/storage.rs "Durable storage and optimistic revision"
[R24]: https://github.com/TED-H-com/ai-security-scanner/blob/6e259b497b87fb8aa2ece1f3b512cc29c9ea5af7/src-tauri/src/process_lease.rs "Exclusive execution ownership"
[C01]: https://github.com/cloudflare/security-audit-skill/blob/c1c8a8c1471069fb0e188eeaff69b8e8db6564a8/LICENSE "MIT license"
[C02]: https://github.com/cloudflare/security-audit-skill/blob/c1c8a8c1471069fb0e188eeaff69b8e8db6564a8/skills/security-audit/SKILL.md "Modes and workflow"
[C03]: https://github.com/cloudflare/security-audit-skill/blob/c1c8a8c1471069fb0e188eeaff69b8e8db6564a8/skills/security-audit/report-schema.json "Native finding contract"
[C04]: https://github.com/cloudflare/security-audit-skill/blob/c1c8a8c1471069fb0e188eeaff69b8e8db6564a8/skills/security-audit/VALIDATION-AND-REPORTING.md "Validation and reporting semantics"
[C05]: https://github.com/cloudflare/security-audit-skill/blob/c1c8a8c1471069fb0e188eeaff69b8e8db6564a8/skills/security-audit/RECONNAISSANCE.md "Coverage planning"
[C06]: https://github.com/cloudflare/security-audit-skill/blob/c1c8a8c1471069fb0e188eeaff69b8e8db6564a8/skills/security-audit/validate-coverage-ledger.cjs "Ledger validator"
[C07]: https://github.com/cloudflare/security-audit-skill/blob/c1c8a8c1471069fb0e188eeaff69b8e8db6564a8/skills/security-audit/validate-findings.cjs "Findings validator"
