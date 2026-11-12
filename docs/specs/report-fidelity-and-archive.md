# 報告保真、離線重建與案件封存規格

狀態：報告基準、terminal run／單 run／combined 匯出自動快照、手動快照與既有 domain 的完整封存／還原已實作；跨平台與 provider 整合待驗收。更新日期：2026-11-10。Cloudflare reported bundle 已可私密保存與離線取回，但尚未整合為案件封存；見[目前資料邊界](../cloudflare-provider.md)及[發布狀態](../release-model.zh-TW.md)。
查核基準：`6e259b497b87fb8aa2ece1f3b512cc29c9ea5af7`。
產品決策以 [product-spec.md](../product-spec.md) 為準；本文件定義下一階段的資料與驗收契約。
目前 source CLI 可保存、檢查、取回與重播單 run 與 combined 報告，使用方式與限制見[報告快照文件](../report-snapshots.md)；既有 domain 的案件保存、選配來源／原匯出與新 workspace 還原見[案件封存文件](../case-archives.md)。基準資料來自上述 core 的實際 exporter 與 adapter fixtures，沒有連線真實目標。三平台 archive／restore、原生桌面與 Cloudflare 驗收仍為 **pending**。

## 1. 已有能力與缺口

| 已查核位置 | 目前行為 | 本階段需要補上的能力 |
| --- | --- | --- |
| [beginner_report.rs](../../src-tauri/src/beginner_report.rs) | `BeginnerMasterReport` schema `1.1.0`；由 durable case 衍生，非新 lifecycle；只有 terminal run 能建立 | 保存完整報告呈現快照，加入 provider 的可追溯資料 |
| [case_service.rs](../../src-tauri/src/case_service.rs) | `export_case` 共用六種單 run 格式；HTML renderer 已在 Rust | 原樣提取 renderer，再加法擴充；不得另寫 skill 專用簡版報告 |
| [domain.rs](../../src-tauri/src/domain.rs) | run 凍結資產與 scope；finding observation 可有 `finding_snapshot`；人工 workflow 獨立保存 | 加入 provider record、session receipt 與 ReportSnapshot 關聯 |
| [export.rs](../../src-tauri/src/export.rs) | `.case.tar.gz` 有 manifest、SHA-256、Ed25519 與有界 verifier；`case.json` 是摘要 | 獨立完整 archive DTO、版本契約與 restore；保留舊 bundle |
| [report_attachments.rs](../../src-tauri/src/report_attachments.rs) | 單 run 每 task ZIP；原檔累計上限 64 MiB／10,000 檔；超限目前拒絕附檔匯出 | 合併來源 namespace、明確 omissions 與 archive 取回位置 |
| [selected_run_report.rs](../../src-tauri/src/selected_run_report.rs) | 合併 2–16 個 terminal reports，HTML 支援原始附件；JSON 保留來源及附檔計數 | 有序來源快照、附件與明確選擇的私密 archive 超限 fallback 已實作 |
| [storage.rs](../../src-tauri/src/storage.rs) | SQLite WAL、optimistic revision、transaction；壞案件與正常案件隔離 | 在現有持久化上增加必要欄位／表；不重建整個 storage |

現有 bundle 沒有完整保存 `inventory_observations`、`exports`、`assessment_intent` 和案件層的 `ai_generated_artifact` 等恢復所需資料。
`case_events.payload_json` 目前只保存案件 status，不能由它重播出完整案件。
舊 observation 缺少 frozen finding 時可使用目前 canonical wording，且有 `CurrentCanonicalLegacyFallback` 或 `ObservationOnly` 標記；這不是當時原貌。
`FindingStatus::Confirmed` 是人工工作流，不是 Cloudflare 的 provider verdict。

目前 HTML 除了 `BeginnerMasterReport`，還讀取案件 grouping/history、framework projection、verification comparison 與 baseline 資料。
只保存 `BeginnerMasterReport` 然後日後重新讀取最新 case，不能滿足本規格的完整報告保真。
現有 combined report 的 64 MiB 是**最終文件大小**限制；單 run 附件的 64 MiB 是**所選原檔總長度**限制，兩者不可混同。

## 2. 產品與資料不變條件

1. 第一層仍回答掃了什麼、發現什麼、何者最優先、影響、下一步與未完成工作；技術資料、來源與正式條款仍採既有層次。
2. scanner severity、confidence、原文、evidence、識別值與時間保留；產品 priority、grouping、人工工作流另外保存。
3. 未啟動、未完成、失敗、取消與未知 coverage 均不等於 clean；一個方法失敗不刪除其他方法的結果。
4. 正式報告僅對 terminal run 產生。進行中的 provider session 使用 progress/checkpoints，不產生 interim report。
5. Cloudflare 無法啟動時，使用既有 task/outcome 保存一列失敗與可展開原因；沒有 findings，也不假稱曾執行。
6. 不新增 assessment index、expected-source 模型或另一套成果生命週期。單來源沿用單 run，多來源沿用 selected-run composition。
7. 重開、取回、重建與還原不呼叫 AI、不接觸原目標，也不要求掃描 runtime 可用。

## 3. Provider result 契約

Cloudflare 原生 `findings.json` 是 strict top-level array。上游原始 bytes 與產品 envelope 分開保存；不能把 schema、模型或 provenance 欄位塞回原生 record。
新增型別名稱可依 repo 慣例調整，但下列資訊必須可由 durable data 找回。

| 產品 envelope／record 欄位 | 必要語義 |
| --- | --- |
| schema、provider/method ID、upstream revision、檔案 digests | 固定方法與 validator 的身分，與 core/report schema 分開 |
| case/run/task/session/attempt IDs、manifest digest | 每筆結果與唯一接納收據相連；重試不重複寫入 |
| asset IDs、canonical source snapshot 與 AI-readable view IDs/digests、frozen scope/profile | 指向實際受檢內容與排除政策；不得改指目前 working tree，或把本機 secret-scanner snapshot 當成已獲准傳給模型的 view |
| host/model identity 與 availability | 無法可靠取得的版本記為 unknown，不從 agent 自述推定 |
| assignment/verifier receipts、時間、輸入 revision、輸出 hash | 保存實際協調紀錄；不是正確性證明 |
| provenance | 區分本產品記錄的 workflow 與外部 reported-only 匯入；自帶 receipt 不授予可信身分 |
| raw record locator、fingerprint、原始 verdict | 可回到來源檔案與原值；跨 run 關聯另外保存 |
| coverage ledger、attempts、blockers、record/evidence references | 保留 covered、candidate、blocked 等原生狀態與歷史 |
| validation results 與 completeness | 分開記錄結構、上游 validators、產品 reference checks；schema 通過不等於漏洞成立 |

| Provider 狀態 | 報告位置與計數 |
| --- | --- |
| confirmed | 保留上游 severity/confidence/root cause/trace/remediation；產生 evidence-bound observation，人工 workflow 保持獨立 |
| needs_validation | 顯示待驗證假說、blockers 與 validation plan；無 severity，不加入 confirmed 風險數 |
| rejected | 保存原因與證據於技術歷史，不列為可行動漏洞 |
| 尚未完成必要驗證的 candidate | 留在 ledger 與 incomplete outcome，不偽造正式 finding 或 needs_validation record |

ledger 的 `candidate` 可能已連到正式 verdict；必須核對 fingerprint linkage 與必要 verifier，不能只看字面判定未完成。
Cloudflare 未提供的 CWE/CVSS 保持空值；confidence 不自動提升為產品 `Confirmed`；payload/code 字串不可 trim 或重新排版覆寫。
只有明確證據支持的既有 grouping 才可重用。相似標題、附近行號或多個模型同意均不構成新的跨來源合併規則。
reported-only 的 confirmed 與完整產品 workflow 的 confirmed 分開標示與計數，不能由匯入建立掃描授權或補造 coverage。

## 4. ReportSnapshot 契約

`ReportSnapshot` 保存一個已確定的呈現版本，不取代 canonical case、provider 原文或人工工作流。
建立時凍結下列輸入；重新整理最新工作流須建立新 snapshot 與 receipt，不能改寫上一版。

| 欄位群 | 必須保存的內容 |
| --- | --- |
| Identity | snapshot ID、case ID、單 run 或有序 selected run IDs、來源 case revision、建立原因與時間 |
| Projection | schema、完整 frozen report projection、provider 區塊、既有任務結果與 coverage |
| Render context | 實際使用的 grouping/history、framework projection、verification comparison/baseline 與其他 renderer inputs |
| Narrative | 已採用的敘述／翻譯、locale 與 fallback 語言來源；不得重開時重新生成 |
| Settings | locale、redaction、附件選擇、固定 `as_of`／`generated_at`、呈現版本 |
| Renderer | core/renderer revision、相容 schema、非執行 templates/assets digests |
| Artifacts | canonical data digest、原 HTML/JSON blob references/digests、附件 manifest 與每檔 hash/length |
| Completeness | legacy fallback、缺證據、omissions、來源完整度、retrieve/replay 能力與原因 |

Renderer extraction 先在固定資料、時間、locale、redaction 下保持 HTML bytes；之後再加入 provider 區塊。
六種單 run 格式仍是 HTML、canonical JSON、framework report、OCSF、OSCAL、signed case bundle。

已入案來源稽核的框架報告新增可省略的 `source_audits` 成員，型別定義見 `schemas/master-framework-report.schema.json`。它直接採用共用報告遮蔽後的身分、方法、結果、計數、待驗證、缺口及技術資料；空集合省略。稽核不計入 scanner engine counts／states，confirmed observation 使用 `source_audit_not_mapped`，不產生控制項結論。OCSF／OSCAL 的 confirmed finding 另帶提供者身分，待驗證與涵蓋資訊由既有必要配套保存。Schema version 與既有 notices 不變；沒有稽核的固定輸入輸出 bytes 不變。案件 bundle、附件、整合附件、完整封存與比較仍維持拒絕。

combined 仍只承諾 HTML／JSON，不把它描述成已支援六格式。
OCSF／OSCAL 保留 mandatory coverage companion 與雙檔輸出失敗清理；無法放進標準主檔的新資料由明確 companion/extension 承載。
Snapshot 必須保存 renderer 實際需要的完整輸入，不能靠最新 case、當前 framework catalog 或動態翻譯補回。

相容受信 core 應內建它宣稱支援的 renderer／資料遷移。只有版本字串與 digest 不足以重建；不得執行 archive 內攜帶的程式。
缺少相容 renderer 時可取回原 HTML，能力為 `retrieve-only`；不能冒稱 `replay-ready`。
換 renderer、語言、遮罩或 triage 產生新輸出時建立新 receipt，保留原 bytes。

## 5. 原始附件與遮罩

保留原始 MD/JSON/HTML 與證據的精確 bytes、相對目錄和 SHA-256。上游 HTML 作為不執行的附件，不注入主報告 DOM。
合併附件以 source run/task namespace 區分，同名檔不覆蓋；每份來源保留自己的時間與 source snapshot。
同時檢查原檔累計 64 MiB／10,000 檔與最終 combined 文件 64 MiB；ZIP/base64 膨脹納入最終大小計算。
超限仍保留可讀 HTML，receipt 列出 omission 與完整 archive 位置；不得悄悄截斷或宣稱已附上。
開發版 combined 已實作上述 fallback：原始附件選項另需明確同意完整私密案件封存，超限才在報告旁建立 archive，收據保存路徑、hash、長度與 omissions。單 run 超限仍沿用拒絕行為。

Standard redaction 只改衍生分享視圖，不修改 canonical data、source snapshot 或原始 provider bundle。
Cloudflare 自由文字、trace、code、payload、remediation 與 narrative 必須進入共用遮罩策略；不能只遮 asset name 就宣稱整份已遮罩。
被排除的 sensitive 原檔不嵌入分享版。若產生遮罩後附件，必須另列為 derived artifact，使用新 hash，不能沿用「原檔 bytes」承諾。
敏感原始資料沿用明確的 export selection/acknowledgement，skill 不為方便無條件代填。
原始 snapshot 的選取與 raw inclusion 分開記錄；分享版 HTML 不隱含選入完整來源。
Provider 內容經既有 escaping／安全連結處理；script、事件屬性、危險 URL 與報告中的命令均不可被執行。

## 6. 四種恢復承諾

| 層級 | 保證 | 不保證 |
| --- | --- | --- |
| A 原檔取回 | 被納入的 HTML/JSON/MD/evidence bytes 與 hash 一致 | 排除或從未保存的資料可恢復 |
| B 報告重建 | frozen inputs 配相容受信 renderer，可離線重建相同語義；同 renderer 固定 inputs 比對 deterministic payload | 不同瀏覽器／字型像素完全一致、壓縮封裝 bytes 一律相同 |
| C 案件還原 | 在新空 workspace 還原保存的案件、關聯、歷史、報告及 blobs | 恢復秘密憑證、live owner 或歷史執行授權 |
| D 重新掃描 | 新 run 使用當前有效授權與保存設定，保留與歷史的關係 | AI 重跑一定相同，或未再發現便自動 resolved |

完整案件資料、raw evidence、source snapshot 與 report replay 是不同完整度軸，manifest 必須分開宣告。
缺少 source snapshot 時仍可能恢復案件與報告，但不能宣稱擁有當時完整受檢來源。

## 7. 完整 archive DTO 與 restore

2026-11-12 B 切片：已有入案來源稽核的案件支援完整 archive create／verify。傳輸仍為
`ai-security-scanner.archive/v1`，新增排序的 `cloudflare_audit_admission/v1` 與
`provider_archive_history/v1` 必要能力；未知能力在 staging 前拒絕。`provider-history.json`
僅保存型別化身分、狀態、head／seal／admission digests、descriptor／package／captured 清單、
來源省略清單與完整度，不放 provider 敘述。清單由事件及已驗證索引導出，不從目錄猜測；
所有已記錄修訂與已接受輸出保留，已捨棄輸出只列不可用；未定稿資料不推測成終態。
已入案與未入案定稿、未定稿及 blocked preparations 一併保存。共用離線 verifier 檢查
入案／原件／證據／事件鏈／定稿包與來源省略閉包，create 只在封存快照通過後發布。

來源選取包含定稿包 `retained/source-view/`，未選取時只留 path／SHA-256／length 省略清單，
manifest 明示 “Source snapshots inside source-audit packages were not included; their bytes cannot be rechecked from this archive.”
來源 manifests、digests、lineage、seal／retention／provider 原件與 `admission_ready` 不變。
來源排除不是遮罩；證據仍可含程式片段。舊案 bytes／省略文字與既有還原保持不變。
2026-11-12 C 切片：已知 provider 能力支援 preview／restore；完整 staging 後再次驗證
provider graph／package，才匯入資料庫、checkpoint、寫 receipt／intent 並發布，不執行
provider、validator、model 或 admission，也不重建報告。`case.restored` 事件僅新增嚴格
`provider_history` DTO，保存 history digest 與排序的來源省略清單；資料庫 migrations 仍為 [1, 2]。
準備終態事件早於最新還原事件即為唯讀歷史；準備重播、checkpoint、validate、finalize、admit 及其
重播均以 `restored_session_inert` 拒絕，新增授權不會解除。讀取、報告、匯出及原件下載保留。
明列來源省略的還原稽核使用 contextual `included_payload`；其他還原稽核使用嚴格 `full_payload` 驗證。
還原 `status` 僅在驗證通過後標示上述範圍，否則維持 `committed_files`；驗證失敗仍以
exit 0 回報 `sealed_state: "mismatch"`、`sealed_failed_check` 檢查名稱且不提供下一步，
`inspect-sealed` 維持 exit 2 拒絕。
standalone retained 操作仍嚴格。再次封存保留每包完整來源省略集合及一次省略說明，
即使選擇包含來源；若繼承省略的工作區來源快照仍缺失，manifest 另以固定句子明列，
驗證及還原會依繼承清單與來源索引檢查，缺少、多餘或重複句子以 `archive_omission_mismatch` 拒絕。完整包 bytes 不變。Provider preview／receipt 在原五項後新增唯讀
轉換文字；舊案 bytes、payload 與欄位不變。比較與 D7 終態列維持拒絕。
穩定 error codes 及操作方式見[案件封存指南](../case-archives.md#archives-containing-admitted-source-audits)。

新增獨立 `ai-security-scanner.archive/v1` 契約；既有 `.case.tar.gz` 保留原義，不直接改稱完整 backup。
以下是必要資料群，實際檔名可在實作 PR 固定；不得用直接複製 SQLite 取代 portable DTO。

| 資料群 | 必須涵蓋的內容 |
| --- | --- |
| Manifest | archive/producer/minimum-reader schema、各 entry hash/length/type、完整度、omissions、來源索引 |
| Case identity/context | title/profile/status/times、intent、AI applicability context、requested activities、data sources、原有 IDs |
| Asset/scope | assets/relations、歷史 scope grants、run 的 frozen asset/scope；還原後不啟用授權 |
| Execution | 所有 runs/tasks/outcomes、coverage、inventory observations、必要 checkpoint 歷史；不恢復 live workers |
| Findings/history | canonical findings、frozen observations、grouping/workflow events、comparisons、export history |
| Provider | raw bundle、envelope、ledger/attempts、session admission receipts、source/evidence bindings |
| Blobs/reports | verified raw artifacts、所選 source snapshots、ReportSnapshots、原輸出、templates/assets |
| Provenance | core/skill/provider/runtime/renderer locks、公開簽章 identity 與歷史簽章；排除私人金鑰／憑證 |

`AssessmentCase` 的每個可持久化欄位須在 DTO 對照表有保存或明確 exclusion；`storage_revision` 不作跨 workspace concurrency token。

目前 `case.json` 使用 `PortableCase` 保存完整 `AssessmentCase`，另保留 `original-case.json` 的原 DB bytes；欄位對照如下。還原變更只套用於新 DB 的 operational copy，原件保持不變。

| 欄位 | 保存／還原行為 |
| --- | --- |
| `id`, `title`, `profile`, `status`, `created_at`, `updated_at`, `knowledge_cutoff`, `is_demo` | 完整保存；維持案件原 ID |
| `assessment_intent`, `ai_generated_artifact`, `requested_activities` | 完整保存，不推測 legacy 缺值 |
| `data_sources`, `assets`, `asset_relations`, `scope_grants`, `coverage` | 原件完整保存；新 DB 清除目前 grants／owner confirmations，停用來源連線與 capability metadata；歷史 frozen context 保留 |
| `scan_runs`, `findings`, `finding_observations`, `inventory_observations` | 完整保存；新 DB 移除 resume tokens，不帶回 live cleanup／worker |
| `finding_groups`, `finding_group_events`, `finding_workflow_events`, `comparisons` | 完整保存；不以還原當下的 workflow projection 覆寫原件 |
| `raw_artifacts`, `exports` | 完整 metadata，所有 raw bytes 必須存在且驗 hash；所選原匯出 bytes 還原後重綁路徑，未選 export path 清空 |
| `storage_revision` | 非 DTO 欄位；manifest 保存來源 revision，新 DB 起始 revision 1 |
| `case_events` | 獨立保存原 sequence／time／payload，還原交易附加一筆 `case.restored` 事件 |

來源檔案選取另外涵蓋 immutable workspace trees 與 connector captures，且檢查 current／frozen／已記錄歷史 reference 的閉包。缺少歷史完整 reference 時拒絕來源選取；不從現在的來源補造過去。現階段 archive 只有 SHA-256 內部完整性驗證，`authenticity` 明示 `not_authenticated`；既有 export 公開簽章歷史保留，未新增 archive 簽章或私人金鑰匯入。CLI 的實際格式與限制以[操作文件](../case-archives.md)為準。

路徑轉為 portable blob references；保留 evidence 原 source identity，不要求原機器絕對路徑存在。
Archive 讀取單一已確認 revision／snapshot boundary，artifact inventory 與關聯來自同一狀態；衝突回傳 retry，不產生假完整 archive。
簽章只證明 manifest 完整性；來源可信度與漏洞正確性另有證據，不由簽章推出。

Restore 順序：有界 verify → preview → 同檔案系統 staging → reference graph validation → atomic publish → durable receipt → offline reopen/replay。
拒絕 absolute/parent traversal、symlink/hardlink/device、Windows reserved names、大小寫／file-directory 碰撞、重複 entries、超額解壓與未知 schema。
驗證 case/run/task/asset/finding/evidence/provider/snapshot 關聯與每個 blob 的長度、hash；缺漏不回報完整成功。
第一版只還原至新空 workspace，保留原 IDs；目的地已存在或 collision 則拒絕，不做智慧 merge。
在 staging 完成 DB/blobs、同步必要檔案並寫入 publish intent/receipt，關閉 DB 後單次 rename 發布完整目錄。
若平台無法滿足該原子條件，須用 durable journal/state machine；SQLite transaction 不等於跨檔案原子性。
涵蓋「DB 完成但尚未 publish」與「已 publish 但 acknowledgement 未完成」兩個 crash 邊界，不留下半案件。

## 8. Legacy 與讀取相容性

新 core 可讀舊資料；舊 binary 不承諾可讀新 schema。未知版本拒絕寫入並保留原 bytes。
舊資料以 read-only source + copy/import 遷移至新 workspace；不讓新舊 binary 同時寫同一資料根目錄。
缺少的 source/model/verifier、frozen observation 或歷史 context 保持 unknown，不從目前值補造。
今天由 legacy fallback 建立的 snapshot 是今天的保存視圖，必須標示其來源完整度，不能回填掃描當時日期。
新增 AgentAudit task kind 時同步檢查 Rust match、TS type、terminal eligibility、origin、coverage、exporters 與 schema；不得偽造 catalog image identity。
停用 Cloudflare 或缺 runtime 不影響讀取已保存報告與 evidence；build cache 清理不得刪除案件或封存。

## 9. 可追蹤驗收與現有測試接點

每個驗收 receipt 記錄實際 core revision、fixture digest、命令、結果及產物。下表定義完整驗收目標；目前僅有以下子集，不將子項結果擴張成完整 migration 已通過：

- RF-01：已保存 [原 core 的固定輸入、26 份文件、36 筆 bundle payload 雜湊](../../tests/fixtures/report-fidelity/README.md)，由 `report_fidelity_baseline.rs` 比較共用 renderer 抽取後的六格式輸出。
- RF-02／RF-03：`report_snapshot.rs` 與 `cli_report_snapshot.rs` 覆蓋 active run 拒絕、雙語快照、案件／triage 變動，以及移除原 DB／workspace 後的獨立重播。混合 terminal outcomes 保存在 baseline；HTML／JSON 匯出已自動保存快照並綁定匯出紀錄；完整 archive 自動保留原始快照與相對參照。共用 coordinator 在結果整理與清理完成後自動保存 terminal run；重試不覆寫原件、保存失敗保留發現並可用 recovery 補存。combined snapshot 已凍結完整有序來源、生成時間與呈現版本，匯出自動保存、手動保存、離線取回／重播及完整封存還原均已接線。
- RF-07：單 run 原始 HTML 與相對目錄資源保留 bytes，Standard 排除敏感原檔；移除 artifacts 後仍能重播附檔報告。combined 的原始 ZIP 以 run/task 區分，快照重播與 archive／restore 保留 bytes；64 MiB 原檔、10,000 檔及最終 64 MiB 文件超限均有驗證，fallback 產生可驗證的完整私密案件 archive。
- RF-09：已保存 20 張中英／390、768、1440px／展開及列印媒體的 Chromium 基準截圖；它們不是完整長 trace／provider／跨瀏覽器驗收。
- AR-01／AR-02／AR-06：目前 domain 的完整 DTO、事件、inventory／triage／grouping／export history、raw、所選來源與報告已接入；CLI fixture 移走原 data root 後還原並讀取原報告，operational copy 停用歷史授權。缺失來源保持 omission，未涵蓋尚未實作的 provider domain 或三平台操作。
- AR-03／AR-04：有界 transport、完整 reference graph、原 revision 一致性、來源 hash、缺檔／未知欄位拒絕，以及 publish 前後中斷與相同 restore 重試已有測試；既有目的地及變動後的 workspace 不覆寫。
- AR-05：單 run 原件取回、exact-compatible replay、未知 renderer 或未來 domain/report shape 的 retrieve-only，以及損毀／覆寫拒絕已有測試；完整 archive 同時保存這些快照。combined snapshot 的離線取回／重播與封存還原已有整合測試；provider 相關項目仍 pending。

實際執行命令與結果記於[開發狀態](../development-status.zh-TW.md)。未執行新能力的三平台或真實目標掃描驗收。

| ID | 觀察到的行為／證據 | 可重用的既有接點 |
| --- | --- | --- |
| RF-01 | 固定 inputs 的 renderer extraction 前後 HTML bytes 一致；六種單 run 格式語義一致 | `src-tauri/tests/all_engine_report_audit.rs`、`src-tauri/tests/support/public_sample_reports.rs`、`case_service.rs` tests |
| RF-02 | active run 不產正式報告；failed/cancelled/inventory-only 不為 clean；已完成 sibling 留存 | `beginner_report.rs::tests` 的 `active_run_has_no_beginner_report` 與 coverage fixtures |
| RF-03 | 之後改 title/asset/grouping/framework/triage/comparison 不改舊 snapshot；新 snapshot 反映新狀態 | `beginner_report.rs` frozen/legacy tests；新增 snapshot mutation corpus |
| RF-04 | confirmed、needs_validation、rejected、unvalidated candidate 正確分區計數；reference/verifier mismatch 拒絕假 complete | 新增固定 Cloudflare artifact corpus；`src-tauri/tests/adapter_fixtures.rs` 提供既有 adapter 模式 |
| RF-05 | Cloudflare 未能啟動仍保存一列失敗與原因，重開／restore 後與 sibling 結果同在 | `selected_run_report.rs::tests` 與新增 provider failure fixture |
| RF-06 | combined 仍要求 2–16 個唯一 terminal sources；原始觀察不跨 run 自動合併或推斷 resolved | `selected_run_report.rs::tests::repeated_historical_observations_stay_separate_and_unselected_run_is_excluded` |
| RF-07 | 單 run／combined 附件取回 bytes/hash 相同；namespace、大小與 omissions 正確 | `src-tauri/src/case_service_attachment_tests.rs`、`tests/fixtures/external-scanners/verify-combined-report.py` |
| RF-08 | Standard 分享版無 sentinel 私密字串；canonical/raw 原件不變；惡意 markup 不執行 | `export.rs::tests`、`case_service.rs::tests::standard_redaction_pipeline_is_shared_by_all_document_formats` |
| RF-09 | EN／繁中、390/768/1440px、長 trace/code、列印與展開資訊仍可讀 | `tests/frontend/reportLocale.test.ts`、`tests/component/reportProblemGroups.test.tsx`；新增固定 rendered baseline |
| AR-01 | 空 workspace、無 AI／網路／掃描 runtime／舊 cache，可用預先可用的相容受信 core 還原並驗 blobs | 新增 archive roundtrip corpus；`storage.rs::tests::case_round_trip_and_selection` |
| AR-02 | DTO 對照完整；inventory/context/exports/provider/history/reference graph 不遺失 | `domain.rs::AssessmentCase` 欄位清單、`export.rs` bundle fixtures |
| AR-03 | 缺檔、壞 hash、未知 schema、非法路徑／link、解壓超限、碰撞均不 publish 成功案件 | `export.rs::tests` verifier/path cases；新增 restore rejection corpus |
| AR-04 | 並行 revision 變更拒絕混合快照；兩個 publish crash 邊界可恢復且冪等 | `storage.rs::tests` revision cases；新增 archive/restore failure injection |
| AR-05 | 原報告 bytes 可取回；相容 renderer 可 replay；缺 renderer 明示 retrieve-only | 新增 ReportSnapshot compatibility corpus |
| AR-06 | 舊案原件未改、未知歷史仍未知；redacted handoff 不被標為完整 archive；授權／credentials 不復活 | `export.rs` legacy fixtures、`storage.rs::tests::unreadable_cases_are_preserved_and_isolated_from_healthy_siblings` |

## 10. 實作順序

先固定 baseline inputs／輸出與 DTO 欄位對照，再原樣抽出 renderer，接著建立完整 ReportSnapshot。
其後完成 archive/verify/restore/replay；provider adapter 可依已固定資料契約另行開發。
最後加入 combined attachments、provider outcome 與端到端還原驗收。每階段保留既有入口與歷史資料可讀，不以重新設計報告或整個 storage 取代增量工作。
