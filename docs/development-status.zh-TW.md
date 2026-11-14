# 開發狀態

[English](development-status.md) · [文件](README.zh-TW.md)

更新：2026-11-14。

**最新發布版本仍是 Linux、macOS、Windows 的 v0.6.2 桌面版**，也是初學者的預設入口。公開的操作 skill 協助安裝應用程式、確認準備狀態、引導在視窗中掃描及保存報告。

## 開發中的新功能

以下功能已在本分支原始碼實作，尚未包含於任何發布版本：

- [Skill 主流程](skill-bootstrap.md)：固定來源 bootstrap 與所選掃描引擎的準備。
- [重用已安裝的桌面執行環境](skill-bootstrap.md)：在 Linux x86_64 與 macOS 重用可辨識的桌面執行環境，不需 Docker 或 Podman 即可準備掃描。
- [前景掃描與復原](foreground-scans.md)：執行已核准的檢查、讀取保存狀態並復原已擷取的結果。
- [Cloudflare 原始碼稽核](cloudflare-provider.md)：由宿主執行準備、記錄派工與輸出、檢查點、驗證、定稿、案件入案及共用報告整合；不再繼續的稽核可明示終止。
- [未完成稽核檢查](results-and-exports.zh-TW.md#未開始或未完成的原始碼稽核)：準備受阻與已終止稽核，會在案件、桌面結果與共用報告中列為未開始或失敗的檢查。
- [報告保存與離線重播](report-snapshots.md)：保存報告、取回原始檔案，並使用完全相容的報告產生器重播。
- [完整私密案件封存](case-archives.md)：建立、驗證並將案件、證據、保存報告與已記錄稽核歷史還原至新工作區；還原的稽核維持唯讀。

**尚未完成**

- 真實宿主驗收已在一個 Linux 宿主以合成專案完成，從空的固定版本 bootstrap 快取一路到還原；第二個宿主、多資產與 macOS／Windows 宿主仍待完成。
- 預設 skill 仍使用已發布桌面版，尚未切換。
- 沒有安裝桌面程式的電腦仍無法自動取得受管理執行環境套件。macOS 與 Windows 的 CI 現在也會執行程式庫測試，以及使用測試替身的前景掃描與引擎準備測試；在這兩種系統上執行實際掃描工具仍未驗證。

以下日期章節保留各階段當時的觀察。[產品規格](product-spec.md)定義產品行為；[遷移計畫](plans/skill-first-cloudflare-migration.md)與[報告及封存契約](specs/report-fidelity-and-archive.md)說明已採納的工作。可用內容請見[發布狀態](release-model.zh-TW.md)。

CI 文件與契約測試目前共 124 項。

## 11 月 14 日跨平台檢查與執行環境重用 — 30

沒有 Docker 或 Podman 時，`prepare --capability scan` 可在 Linux x86_64 與 macOS 重用已安裝桌面程式的掃描執行環境，前提是此原始碼版本認得其套件清單；Windows 尚未實作偵測。核心會再次核對清單摘要。若無法準備可用的執行環境，程序會停止並提供一則 `next_step` 供操作人員轉達；不會下載或安裝執行環境。`doctor --capability scan` 會列出可見的執行環境來源，但不會執行它們。

沒有將 Docker 或 Podman 放在 `PATH` 的 Linux 主機已完成這條準備流程的端對端驗證；該主機未安裝套件，因此重用本身目前僅由測試涵蓋。前景命令會據實回報已保存的內容；取消會停止進行中的受管理執行環境啟動，每次主控台中斷也都會在工作收束後回報結果。

原始碼稽核與整合報告會以讀者的語言說明各來源檢查了什麼。桌面程式也會以日文顯示原始碼稽核數量、涵蓋細節、問題說明與下一步。

封存會拒絕還原工作區自行管理的檔案。Cloudflare 原始碼稽核會說明拒絕原因與封存限制；列舉套件目錄時，也能察覺在同一時鐘刻度內新增或移除的項目。

CI 現在在 macOS 與 Windows 執行程式庫測試，並在 Linux、macOS 與 Windows 執行使用測試替身的前景掃描及引擎準備測試。測試讀取的每個檔案都會觸發對應的 CI 工作；macOS 與 Windows 上實際執行掃描工具仍未驗證。

## 11 月 13 日報告與封存驗收門檻 — 27

以同一固定版本與全新、空的 bootstrap 快取，在舊快取無法讀取的情況下以 `--offline` 重新建置 CLI，不到四分鐘完成，新執行檔摘要與先前建置相同。以這個核心對 26 流程的宿主封存再次執行還原驗證，78 項全數通過：兩種來源選項都還原至新的工作區，保存報告皆逐位元組取回與重播。連線追蹤顯示建置與還原期間沒有任何網路連線嘗試。Rust 相依套件已在本機，過程中未下載任何套件。

新增的自動測試涵蓋因預算過小而未開始的稽核，以及已被停止的稽核。封存前，保存的報告寫明結束方式與原因，任務技術紀錄收合在技術詳細資料中。重新開啟案件後與還原封存後的匯出都顯示相同原因與收合方式，還原後的快照位元組與原件相同。

宿主流程中的原始碼稽核無論有無 sandbox 都不得執行目標程式碼，準備收據與定稿紀錄都記載此限制。需要執行才能確認的事實保留為沒有嚴重程度的待驗證紀錄，含未驗證候選問題的稽核維持未完成。報告現在會把這些紀錄列為下一步：單輪與整合報告的第一層會說明「待驗證」中有幾個原始碼稽核項目需要驗證，沒有其他發現時排在最前，否則接在主要行動之後。已完成檢查未發現問題、但有這類紀錄的資產，下一步顯示「請先驗證列出的原始碼稽核項目」。計數、嚴重程度、狀態標籤與 JSON 輸出不變。

證據：`b27b-01` 通過失敗列測試組（11 項）；`b27e-01` 通過報告測試（11 項），`b27e-02` 通過整個 Cloudflare 稽核測試目標（157 項）。在最終版本上，`b27-lead-01` 通過程式庫、CLI 與 Cloudflare 測試目標（2,020 項），`b27-lead-02` 通過快照、封存、前景、執行環境準備與基準測試目標（56 passed、2 項 ignored），`b27-lead-03` 與 `b27-lead-04` 通過全引擎報告與案件生命週期測試目標；`b27-lead-05` 通過 repository checks（2 個凍結案件、26 份文件快照、36 個 payload hashes、20 張截圖），`b27-lead-06` 全部 114 項 CI 測試通過。

## 11 月 13 日以 bootstrap 起步的真實宿主流程 — 26

一個 Linux 宿主只取得操作 skill、固定於已提交版本的乾淨產品 checkout，以及一個空的私有快取位置。它自行執行固定版本的 bootstrap：先 `doctor`，再以預設 release 設定加 `--offline` 執行 `prepare`，以本機既有的 Rust 相依套件約三分半鐘建好 CLI，接著透過既有的 Docker 相容執行環境完成 Gitleaks 掃描準備。之後每個掃描器指令都經由 `bootstrap.mjs run` 執行。

建置收據記錄固定版本、乾淨來源且不允許以變更中的來源建置，CLI 摘要與快取中的執行檔一致；checkout 全程保持乾淨。宿主接著依 25b 的順序完成同一流程：Gitleaks 掃描未發現秘密、Cloudflare quick 原始碼稽核七次委派全數完成、定稿、自動入案、一份繁體中文整合報告，以及含原始碼快照並經宿主驗證的完整封存。七個委派輸出都與保存的成品逐位元組相同，每次委派都在核發它的 checkpoint 之後，且沒有委派讀取超出核准的原始碼檢視。核准執行器拒絕了一個漏了資料目錄的請求，宿主更正後繼續。全程約 19 分鐘。另以 bootstrap 建出的 CLI 做還原檢查，78 項全數通過。

證據：native 檢查 `b26-01` 通過（2 個凍結案件、26 份文件快照、36 個 payload hashes、20 張截圖）；CI 文件測試 `b26-02` 全部 114 項通過。

## 11 月 13 日真實宿主完整流程 — 25b

以一個請求交給一個 Linux 宿主（合成專案、quick profile、預算七次），完整走完開發技能流程：先執行 Gitleaks 秘密掃描，再進行 Cloudflare 來源稽核至定稿，以三個已核驗 digest 自動入案，將兩次執行保存為一份繁體中文整合報告，並建立含來源快照、經宿主驗證的完整私密封存。33 個核准指令全部成功、無拒絕，掃描未與稽核保管或入案交錯。七個派工皆先發出再委派，每份擷取輸出都與子代理最後訊息相同；沒有代理讀取來源目錄以外的資料或執行目標。Gitleaks 未發現秘密；稽核沒有已確認發現，保留一項無嚴重度的待驗證線索（並行兌換可能以同一點餘額取得兩張票券）。

之後 lead 的還原驗證工具以 68 個公開 CLI 指令通過 78 項檢查。宿主封存與另建的排除來源封存皆通過驗證，並分別還原至新的工作區，範圍為 `full_payload` 與 `included_payload`。三份已保存報告（掃描、已入案稽核、整合報告）從兩個還原工作區取回與重播皆逐位元組相同，整合報告也與宿主保存的 HTML 相同。擷取輸出相符，對還原稽核的新入案請求因還原稽核為唯讀而被拒絕，原始與還原案件的公開讀取結果皆未變動。驗證工具第一次執行因依鍵序比較報告快照參照而停止；現已改為比較識別欄位，並有單元測試。已發布的 v0.6.2 CLI 在還原工作區副本中不列出案件，並拒絕開啟、匯出、比較、封存或規劃刪除該案件；所有資料檔案未變動。

驗證工具修正的 Linux 原生證據：`b25b-lead-07` 通過 repository checks（2 個凍結案件、26 份文件快照、36 個 payload hashes、20 張截圖）；`b25b-lead-08` 共 75 項 skill 測試（74 passed、1 項平台限定 skipped）；`b25b-lead-09` 全部 114 項 CI 測試通過。全部回傳零，沒有暫存殘留。

## 11 月 13 日宿主完整流程 — Brief 25a

開發宿主技能現在會在定稿核驗後自動入案，解釋並保存共用報告；同時要求的掃描工具檢查不與稽核交錯執行，結果保存為整合報告，並依請求建立及驗證完整私密封存。已發布桌面版仍是預設入口。供 lead 使用的還原驗證工具僅透過公開 CLI 檢查兩種來源選項、保存 HTML／JSON 的取回與重播、已擷取輸出，以及還原稽核的唯讀拒絕。CLI 除前景掃描回應外不提供目前案件 revision，因此驗證工具以所有公開讀取結果前後完全相同，判定案件未變動。第一次真實宿主使用記於上方 25b。

審查後版本的 Linux 原生證據：`b25a-lead-01` 同步並檢查 6 個 skill 檔案；`b25a-lead-02` 通過 repository checks（2 個凍結案件、26 份文件快照、36 個 payload hashes、20 張截圖）；`b25a-lead-03` 共 74 項 skill 測試（73 passed、1 項平台限定 skipped）；`b25a-lead-04` 全部 114 項 CI 測試通過；`b25a-lead-05` 通過兩次 setup 與非空目錄拒絕。全部回傳零；最後一項留下的兩個 setup 暫存項目已由 runner 移除。這些檢查未執行新驗證工具的完整還原流程。

## 11 月 12 日 macOS 與 Windows 原生 CI

來源 bootstrap、Cloudflare 原始碼稽核、報告保存與案件封存的測試，現在除了 Linux，也在 CI 的 macOS 15 與 Windows Server 2025 原生通過。這些開發功能先前只在 Linux 執行過。前景掃描仍只在 Linux 測試，所選掃描引擎的準備則在 Linux 與 macOS 測試。

- **唯讀發布。** 來源目錄與稽核資料包先將內容設為唯讀、移到最終名稱，再將根目錄設為唯讀；macOS 不允許重新命名擁有者無法寫入的目錄。根目錄尚未受保護即中斷的發布，讀取端一律拒絕，並由下一次嘗試取代或完成。產品在 Linux 套用相同規則，順序錯誤時 Linux 測試也會失敗。
- **Windows 路徑。** 產品內部路徑維持一般的 `C:\…` 形式，內部目的地因此通過與使用者輸入相同的檢查，Node.js 驗證器也能啟動。直接呼叫 Windows 的地方，只在路徑超過舊有長度上限時改用延伸長度形式。
- **Windows 檔案規則。** 還原時先關閉暫存資料庫，再以可寫入的控制代碼寫入磁碟。含連接器來源的封存，先解析連接器根目錄再檢查範圍。
- **ZAP 報告目錄。** 改以容器內路徑的規則驗證，因此在 Windows 主機上可以規劃 ZAP 被動網站檢查。
- **Bootstrap 與打包。** Bootstrap 暫存目錄改用短名稱，Windows 建置不再超過連結器的路徑長度上限。程式來源目錄內每個項目都是已宣告的程式，桌面打包不再把模組目錄當成程式。

Linux 原生驗證通過 **2,727 項 Rust 測試**、**114 項 CI 契約測試**與 **67 項 skill 測試**；Rust 保留三項 ignored，skill 保留一項平台限定 skipped。格式、Clippy 與發布工具自我測試均通過。

## 11 月 12 日未完成稽核的桌面結果 — B2

桌面「掃描結果」現在將受阻原始碼稽核顯示為「Cloudflare 原始碼稽核未開始。」，終止稽核顯示為「Cloudflare 原始碼稽核未完成即結束。」每列在英文與繁體中文均包含與共用報告一致的原因、下一步及資產缺口。可展開的技術明細以「原始碼稽核」結果為首列，再列出代碼、時間、摘要及終止計數。僅有失敗稽核的結果不再顯示一般掃描重試提示；已入案稽核與掃描工具的相鄰結果維持原有呈現。

保留原生工作狀態，不提供恢復，也不計為掃描工具已嘗試工作或完成涵蓋。進度控制、複驗基準與確認修復均排除這些工作；匯出預覽與掃描工具工作分開計數。兩種失敗標籤均可選入整合報告，沿用既有原生命令。

合成測試涵蓋合法與不合法 wire outcome、恢復與控制排除、嘗試／完成涵蓋、複驗基準、雙語結果與技術明細順序、已入案稽核／掃描工具相鄰結果、整合選取與命令傳遞、展示預覽計數，以及 Rust／TypeScript 欄位、代碼與句子對齊。本次續作新增 **71 項前端測試及 10 項元件測試**。Production 僅修改 `AuditFailureDetails.tsx` 與 `FindingsPage.tsx`，**新增 6 行、移除 1 行**，保留先前 B2 實作。

以下最終 Linux 原生請求在最後一次編輯後依序執行，全部回傳零，暫存殘留皆為零。前端保留 33 項環境限定 skipped。未啟動桌面應用程式；macOS／Windows 原生執行仍未驗證。

| Suite | Native request | Total tests | Passed | Failed | Ignored or skipped | Temporary entries left |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| Typecheck | b2c-final-01 | — | Check passed | 0 | — | 0 |
| Node frontend | b2c-final-02 | 1066 | 1033 | 0 | 33 | 0 |
| Components | b2c-final-03 | 622 | 622 | 0 | 0 | 0 |
| Node CI | b2c-final-04 | 113 | 113 | 0 | 0 | 0 |
| Repository checks | b2c-final-05 | — | Check passed | 0 | — | 0 |
| Formatting | b2c-final-06 | — | Check passed | 0 | — | 0 |
| Clippy | b2c-final-07 | — | Check passed | 0 | — | 0 |
| Rust A | b2c-final-08 | 2009 | 2009 | 0 | 0 | 0 |

## 11 月 12 日稽核終態檢查列 — Rust B1

準備受阻現在自動新增一般的未執行原始碼稽核檢查；明示終止新增失敗檢查。不可變的型別化結果、案件列、格式需求與 outcome 事件，和保管收據／終態紀錄在同一交易提交。受阻列使用案件與收據摘要衍生的產品識別；終止列沿用預留的 provider 輪次／工作識別。完全相同的重播不新增檢查或 outcome 事件，僅重試 pending 報告快照。舊保管資料不回填，還原後維持唯讀歷史。

英文與繁體中文共用報告包含一列檢查、一項資產缺口、固定原因／下一步及型別化技術明細，不產生完成涵蓋、發現或待驗證線索。框架計數、OCSF／OSCAL 配套、案件包及整合報告保留未完成涵蓋。僅含失敗列與混合案件的完整封存，會核驗精確 outcome 清單及依內容計算的 capabilities，再執行還原。掃描派送、恢復、擷取恢復、重掃、清理、修正檢查與比較均排除這些工作。桌面 parity 留待 B2，未變更 TypeScript source。

一般案件儲存現在只核對失敗輪次是否已存在於先前的案件文件，不讀取保管事件；沒有稽核中繼資料的一般案件也不解碼先前文件。

Linux 原生最終驗證共 **2,540 項 Rust 測試執行、179 項 CI／skill Node 測試通過**；Rust 保留三項 ignored，Node 保留一項平台限定 skipped。下列最終請求全部通過，暫存殘留皆為零。凍結報告保真基準與舊封存 byte pin 不變；macOS／Windows 原生編譯及執行尚未驗證。

合成資料涵蓋所有 blocker 與終止原因、多原因順序、已移除資產、嚴格 DTO、列寫入失敗原子回滾、revision／事件保留、pending 快照修復、重播且不回填、還原唯讀、雙語 HTML／JSON 與標準遮蔽、scanner／入案／受阻／終止混合案件、原件及既有快照 bytes 不變、框架計數、零觀察匯出與配套、案件包、預覽計數、掃描拒絕、failure-only／混合封存，以及缺少／錯誤／額外 outcome 綁定、摘要與 capability 拒絕。

本切片變更 24 個 Rust production 檔案，新增 **774 行**、移除 **33 行**，另新增 **18 行 schema**；canonical skill 與兩份宿主技能已透過原生同步套件更新。資料庫 migrations 仍為 [1, 2]。核心涵蓋 outcome／domain、儲存交易、provider／CLI、共用報告與匯出、封存及掃描排除入口。

| Suite | Native request | Total tests | Passed | Failed | Ignored or skipped | Temporary entries left |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| Formatting | b1fix-final-01 | — | Check passed | 0 | — | 0 |
| Clippy | b1fix-final-02 | — | Check passed | 0 | — | 0 |
| Rust A | b1fix-final-03 | 2009 | 2009 | 0 | 0 | 0 |
| Rust B | b1fix-final-04 | 58 | 56 | 0 | 2 | 0 |
| Node CI | b1fix-final-05 | 113 | 113 | 0 | 0 | 0 |
| Node skill | b1fix-final-06 | 67 | 66 | 0 | 1 | 0 |
| Repository checks | b1fix-final-07 | — | Check passed | 0 | — | 0 |
| Skill synchronization | b1fix-final-08 | — | Check passed | 0 | — | 0 |
| TypeScript typecheck | b1fix-final-09 | — | Check passed | 0 | — | 0 |
| All-engine report audit | b1fix-final-10 | 8 | 7 | 0 | 1 | 0 |
| Local case lifecycle | b1fix-final-11 | 5 | 5 | 0 | 0 | 0 |
| Engine execution | b1fix-final-12 | 438 | 438 | 0 | 0 | 0 |
| Job manager | b1fix-final-13 | 25 | 25 | 0 | 0 | 0 |


## 11 月 12 日明示終止稽核

宿主現在可以明示結束無法定稿且不再繼續的稽核。嚴格的 `terminate` 指令在既有 custody 鏈記錄型別化原因，支援完全相同請求的重播及過期 head 衝突；不要求目前授權、validator 或仍存在的宿主目錄。不活動本身不會自動終止。即使已達一般筆數或位元組上限，仍保留一筆有界終態紀錄。

終止保存既有派工、文件修訂及擷取結果，拒絕其後所有 checkpoint、驗證、定稿及入案，包括舊請求重播。狀態顯示已記錄的結束且不提供下一個操作；目前與過往修訂仍可取回。含入案稽核的封存以未定稿 custody 保存終止，僅在需要時增加 reader capability，核驗重建完整清單；還原後維持唯讀。沒有入案的案件保留原有省略說明，舊案 byte pin 不變。案件與報告的失敗檢查列留待下一切片。

Linux 原生驗證：完整套件共 **2,070 項 Rust、179 項 CI／skill Node 測試通過**。Rust 保留三項 ignored，skill 保留一項平台限定 skipped。下列成功請求沒有失敗或取消，各請求暫存殘留皆為零；格式、Clippy、儲存庫檢查及技能同步通過。macOS／Windows 原生編譯及執行尚未驗證。

合成資料涵蓋全部原因、空白／已有資料／兩種滿額紀錄、嚴格輸入、重播與衝突、writer contention、blocked／未知準備、已定稿與再次終止拒絕、授權過期與目錄遺失、所有寫入入口、擷取取回、損壞事件鏈、持久化回滾、輸出遺失後重播、還原未終止與已終止歷史、封存往返，以及缺少或錯誤終止資料。未變更案件文件、報告、匯出、桌面或 TypeScript 行為。

| Suite | Native request | Total tests | Passed | Failed | Ignored or skipped | Temporary entries left |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| Formatting | 23xa-22 | — | Check passed | 0 | — | 0 |
| Clippy | 23xa-14 | — | Check passed | 0 | — | 0 |
| Rust A | 23xa-15 | 2002 | 2002 | 0 | 0 | 0 |
| Rust B | 23xa-16 | 58 | 56 | 0 | 2 | 0 |
| Node CI | 23xa-17 | 113 | 113 | 0 | 0 | 0 |
| Node skill | 23xa-18 | 67 | 66 | 0 | 1 | 0 |
| Repository checks | 23xa-19 | — | Check passed | 0 | — | 0 |
| Skill synchronization | 23xa-12 | — | 6 files checked | 0 | — | 0 |
| All-engine report audit | 23xa-20 | 8 | 7 | 0 | 1 | 0 |
| Local case lifecycle | 23xa-21 | 5 | 5 | 0 | 0 | 0 |


## 11 月 12 日稽核唯讀還原

含入案來源稽核的完整封存，現在可在暫存資料通過 provider 驗證後還原為新工作區。刪除原始資料與宿主副本後，發現、報告、匯出、案件包、原件下載及過往擷取修訂仍可使用。還原準備紀錄為唯讀歷史；準備重播、checkpoint、驗證、定稿及入案都在舊目錄或案件歷史變動前拒絕，新增授權亦不解除。新的準備可使用目前授權。

還原事件新增嚴格型別的來源省略資料，資料庫不新增 migration。Contextual 讀取明示來源省略，standalone retained 操作維持嚴格驗證。再次封存保存定稿 bytes 與繼承省略，即使選擇包含來源亦同。Provider 預覽與收據增加一項唯讀轉換，舊案欄位及固定封存 byte pin 不變。入案案件的整合附件超限改用私密完整封存；入案輪次比較與未定稿終態失敗列仍不提供。

Linux 原生驗證：完整套件共 **2,060 項 Rust、179 項 CI／skill Node 測試通過**。Rust 保留三項 ignored，skill 保留一項平台限定 skipped。下列成功請求沒有失敗或取消，各請求暫存殘留皆為零；格式、Clippy、儲存庫檢查及技能同步通過。還原歷史測試涵蓋驗證入口防護、正確驗證範圍、成功回報不符狀態及繼承工作區來源快照省略。

合成資料涵蓋包含／省略來源、刪除原資料後還原、精確擷取與原件下載、實際匯出、唯讀寫入／重播拒絕、新授權、邏輯資料庫不變、未列省略的缺檔失敗、繼承省略、偽造封存的固定拒絕碼、暫存 bytes 不符、發布前後恢復、預覽轉換與附件超限。macOS／Windows 原生編譯及執行仍未驗證。

| 套件 | 原生請求 | 測試總數 | 通過 | 失敗 | Ignored／skipped | 暫存殘留 |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| Formatting | b24cf-20-final | — | 檢查通過 | 0 | — | 0 |
| Clippy | b24cf-21-final | — | 檢查通過 | 0 | — | 0 |
| Rust A | b24cf-22-final | 1992 | 1992 | 0 | 0 | 0 |
| Rust B | b24cf-23-final | 58 | 56 | 0 | 2 | 0 |
| Node CI | b24cf-24-final | 113 | 113 | 0 | 0 | 0 |
| Node skill | b24cf-25-final | 67 | 66 | 0 | 1 | 0 |
| Repository checks | b24cf-26-final | — | 檢查通過 | 0 | — | 0 |
| Skill synchronization | b24cf-27-final | — | 已檢查六個檔案 | 0 | — | 0 |
| All-engine report audit | b24cf-28-final | 8 | 7 | 0 | 1 | 0 |
| Local case lifecycle | b24cf-29-final | 5 | 5 | 0 | 0 | 0 |

## 11 月 12 日入案稽核完整封存

完整案件封存已支援入案來源稽核，並保存全部已記錄準備，包括定稿、未定稿與 blocked 歷史。清單涵蓋目前與已取代文件修訂、定稿未選取的已接受輸出，以及僅列不可用的已捨棄輸出；不記錄孤立物件。來源選取包含定稿來源檔案；未選取時只留型別化路徑、摘要與長度省略清單，原始文件及 lineage 不變。來源排除不是遮罩，provider 原件仍可含來源片段。

建立及驗證共用離線入案、原件、證據、事件鏈及定稿資料包核驗。必要 reader capabilities 避免靜默丟失資料。這類封存的 restore／restore-preview 在 staging 前拒絕；入案匯入、比較及整合附件超限拒絕保持不變。舊案固定位元組摘要及既有還原行為維持不變。共用技能指引透過 native suite 同步。

Linux 原生驗證：**2,057 項 Rust 與 179 項 CI／skill Node 測試通過**。Rust 維持 3 項 ignored，skill 維持 1 項平台限定 skipped；沒有失敗或取消，各 request 的暫存殘留皆為零。格式、Clippy、儲存庫檢查及技能同步通過。舊案固定輸入摘要在 builder 變更前完成原生 pin，之後保持不變。合成測試涵蓋全部穩定拒絕碼、重新計算外層摘要的錯誤封存、schema、雙份原件一致性、來源省略、未完成歷史及拒絕發布。macOS／Windows 原生編譯與執行尚未驗證。

| Suite | Native request | Total tests | Passed | Failed | Ignored or skipped | Temporary entries left |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| Formatting | b24b-50-final | — | Check passed | 0 | — | 0 |
| Clippy | b24b-51-final | — | Check passed | 0 | — | 0 |
| Rust A | b24b-52-final | 1989 | 1989 | 0 | 0 | 0 |
| Rust B | b24b-53-final | 58 | 56 | 0 | 2 | 0 |
| Node CI | b24b-54-final | 113 | 113 | 0 | 0 | 0 |
| Node skill | b24b-55-final | 67 | 66 | 0 | 1 | 0 |
| Repository checks | b24b-56-final | — | Check passed | 0 | — | 0 |
| Skill synchronization | b24b-57-final | — | 6 files checked | 0 | — | 0 |
| All-engine report audit | b24b-58-final | 8 | 7 | 0 | 1 | 0 |
| Local case lifecycle | b24b-59-final | 5 | 5 | 0 | 0 | 0 |


## 11 月 12 日擷取歷史與宿主副本恢復

開發核心已能由驗證事件直接列出完整擷取歷史，包含已取代的文件修訂、所有已接受派工輸出，以及標記不可用的已捨棄輸出中繼資料。宿主遺失副本後可用 `retrieve-captured` 將精確位元組取回新的私密檔案；現有狀態欄位已提供目前文件修訂與摘要、已接受派工的識別碼、角色與摘要，語義不變。

恢復使用有容量界限的單一唯讀資料庫快照，不初始化、不取得寫入鎖、不改寫資料庫，也不新增授權。讀取核對物件長度與摘要，固定目的目錄並在發布前重新核對快照。呼叫端摘要不符或不安全目的地會拒絕；歷史改變或資料庫忙碌會回傳衝突，不自動重試；已提交資料遺失或損壞會回傳儲存失敗。進行中、已定稿及已放棄的稽核皆可讀取；後續紀錄仍須有效的現行授權。

合成原生測試涵蓋目前與過往文件、未選入定稿資料包的已接受輸出、已捨棄輸出拒絕、孤立物件排除、跨案件隔離、選擇器與摘要／鏈首不符、私密檔案、既有檔案／連結／特殊檔案／產品儲存目的地、父目錄替換、物件遺失／損壞／超限、已儲存長度界限、忙碌資料庫、並行歷史變更、邏輯資料庫不變及現有探索欄位。原生同步套件已由唯一技能來源重建兩份宿主副本。已入案稽核的完整封存、還原及比較仍拒絕，報告、匯出及案件包行為不變。

Linux 原生驗證：完整套件共 **2,045 個 Rust 測試及 179 個 CI／技能 Node 測試通過**。Rust 保留三個忽略測試，技能保留一個平台限定跳過。未選入資料包輸出的聚焦測試亦通過，已包含在完整 Rust 測試數中，不重複加總。沒有失敗或取消，每筆要求都沒有遺留暫存項目。格式、Clippy、儲存庫檢查及技能同步皆通過。本切片未修改 TypeScript；macOS／Windows 原生建置與執行仍未驗證。

| 套件 | 原生要求 | 測試總數 | 通過 | 失敗 | 忽略或跳過 | 遺留暫存項目 |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| 格式 | 24a-20-verify | — | 檢查通過 | 0 | — | 0 |
| Clippy | 24a-21-verify | — | 檢查通過 | 0 | — | 0 |
| Rust A | 24a-22-verify | 1982 | 1982 | 0 | 0 | 0 |
| Rust B | 24a-23-verify | 58 | 56 | 0 | 2 | 0 |
| Node CI | 24a-24-verify | 113 | 113 | 0 | 0 | 0 |
| Node 技能 | 24a-25-verify | 67 | 66 | 0 | 1 | 0 |
| 儲存庫檢查 | 24a-26-verify | — | 檢查通過 | 0 | — | 0 |
| 全引擎報告稽核 | 24a-27-verify | 8 | 7 | 0 | 1 | 0 |
| 技能同步 | 24a-13-skill-sync | — | 檢查六個檔案 | 0 | — | 0 |
| 未選入資料包的擷取輸出 | 24a-28-unselected | 1 | 1 | 0 | 0 | 0 |


## 11 月 12 日已入案稽核案件包與附件

已簽署案件包現包含案件層入案投影、原件繫結與提供者工作來源，即使報告僅選取掃描工具輪次亦同。Standard 隱藏提供者文字／程式碼並保留隱藏數量，遮蔽位置並對涵蓋單元與指紋使用假名；`none` 保留原生值。案件包框架延伸與共用報告的稽核延伸完全相同。入案與原生摘要承諾原始資料，簽署清單另行雜湊匯出文件。稽核工作不列為目錄引擎版本或產品內建檢查。

單輪與整合 HTML 附件現保留原始碼稽核原件的巢狀名稱、提供者／入案／方法來源與逐檔及 ZIP 摘要。只有 `none` 加原始檔案選項會包含提供者原件；Standard 不讀取原件並計入敏感省略。原件消失後仍可重播凍結附件。含入案稽核案件的整合超限會在檔案與歷史發布前以 `source_audit_attachment_overflow` 拒絕，提示減少輪次或匯出案件包；沒有入案稽核的案件維持私密完整封存 fallback。預覽獨立計數稽核工作，桌面已開放附件與案件包；完整稽核封存、還原及比較仍拒絕。

合成測試涵蓋兩種遮罩設定與原件選項、入案案件選取掃描工具報告、遮罩投影與原始承諾、框架／共用報告一致性、精確原件與 ZIP 摘要、原件刪除／竄改、入案繫結變造、簽署文件竄改／移除／額外加入、名稱衝突、單輪及合計限制、編碼後超限、拒絕時不發布或新增歷史、略過數量、離線重播、預覽與桌面選項。固定輸入／時間／金鑰的案件包在四種遮罩／原件組合中均與變更前位元組相同；既有封存 fallback 與凍結報告基準不變。

Linux 原生驗證：**Rust 2,035、CI／技能 Node 179、前端 957、元件 612 項通過**。保留 Rust 三項 ignored、前端 33 項與技能一項平台略過；無失敗或取消，每個要求均無暫存項目遺留。格式、Clippy、儲存庫檢查與桌面型別檢查均通過。macOS／Windows 原生執行與打包桌面程式仍未驗證。

| 套件 | 原生要求 | 測試總數 | 通過 | 失敗 | 略過 | 遺留暫存項目 |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| 格式檢查 | b23b2-final-01 | — | 檢查通過 | 0 | — | 0 |
| Clippy | b23b2-final-02 | — | 檢查通過 | 0 | — | 0 |
| Rust A | b23b2-final-03 | 1967 | 1967 | 0 | 0 | 0 |
| Rust B | b23b2-final-04 | 58 | 56 | 0 | 2 | 0 |
| Node CI | b23b2-final-05 | 113 | 113 | 0 | 0 | 0 |
| Node 技能 | b23b2-final-06 | 67 | 66 | 0 | 1 | 0 |
| 儲存庫檢查 | b23b2-final-07 | — | 檢查通過 | 0 | — | 0 |
| 全引擎報告稽核 | b23b2-final-08 | 8 | 7 | 0 | 1 | 0 |
| 本機案件生命週期 | b23b2-final-09 | 5 | 5 | 0 | 0 | 0 |
| 桌面型別檢查 | b23b2-final-10 | — | 檢查通過 | 0 | — | 0 |
| 前端 Node | b23b2-final-11 | 990 | 957 | 0 | 33 | 0 |
| 元件 | b23b2-final-12 | 612 | 612 | 0 | 0 | 0 |

## 11 月 12 日原始碼稽核結構化匯出

已入案原始碼稽核現可使用 Standard 與 `none` 兩種設定匯出框架報告、OCSF 與 OSCAL。框架報告保留共用報告遮蔽後的 `source_audits` 區塊，稽核工作不計入掃描工具數量與引擎狀態，問題標示為 `source_audit_not_mapped`。OCSF Detection Finding 與 OSCAL `EXAMINE` 觀察只包含已確認問題，另附提供者身分並維持人工處理狀態；提供者確認不是控制項或合規結論。OCSF／OSCAL 必要配套即使在零問題時仍保留線索、缺口、方法與結果，綁定主檔雜湊並維持發布失敗回復。

匯出前驗證唯一入案紀錄與案件、輪次、工作、提供者及原件繫結。標準設定統一未解決指紋假名，衍生缺口標籤不計入隱藏文字數，文字／程式碼隱藏數沿用共用報告。桌面提供三種格式，附件保留尚不可用提示。案件 bundle、單輪及整合附件、完整封存與比較仍拒絕稽核。Schema 定義為附加擴充；常數、聲明、凍結報告基準與宿主技能未變更。

最終 Linux 原生驗證：**Rust 2,021、CI／技能 Node 179、前端 956、元件 612 項通過**。保留 Rust 三項 ignored、前端 33 項及技能一項平台略過。所有檢查通過，無失敗或取消，每個要求均無暫存項目遺留。尚未驗證 macOS／Windows 原生執行與打包後桌面程式。

| 套件 | 要求 | 測試總數 | 通過 | 失敗 | 略過 | 遺留暫存項目 |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| 格式檢查 | b23b1-final-01 | — | 檢查通過 | 0 | — | 0 |
| Clippy | b23b1-final-02 | — | 檢查通過 | 0 | — | 0 |
| Rust A | b23b1-final-03 | 1958 | 1958 | 0 | 0 | 0 |
| Rust B | b23b1-final-04 | 58 | 56 | 0 | 2 | 0 |
| Node CI | b23b1-final-05 | 113 | 113 | 0 | 0 | 0 |
| Node 技能 | b23b1-final-06 | 67 | 66 | 0 | 1 | 0 |
| 儲存庫檢查 | b23b1-final-07 | — | 檢查通過 | 0 | — | 0 |
| 全引擎報告稽核 | b23b1-final-08 | 8 | 7 | 0 | 1 | 0 |
| 桌面型別檢查 | b23b1-final-09 | — | 檢查通過 | 0 | — | 0 |
| 前端 Node | b23b1-final-10 | 989 | 956 | 0 | 33 | 0 |
| 元件 | b23b1-final-11 | 612 | 612 | 0 | 0 | 0 |

## 11 月 12 日桌面版原始碼稽核顯示

已入案原始碼稽核已接入桌面掃描結果，英文與繁體中文使用共用報告的文字。已確認問題保留原生影響及修復策略；待驗證清單獨立顯示，不計入問題數。剩餘單元顯示可讀標籤、在地化狀態及繼續路徑；範圍外單元不顯示繼續路徑。方法、嘗試紀錄、來源沿革、摘要及提供者證據保留在可展開的技術詳細資料。提供者文字一律按原文顯示，包含多行程式碼與看似連結的內容。

桌面已辨識稽核工作，不提供目錄引擎執行或復原控制。只有稽核的輪次不能用於確認修復；混合輪次若含掃描工具工作，仍可作為基準。提供單輪 HTML／JSON 與整合報告，整合來源標示為「原始碼稽核」。框架報告、OCSF、OSCAL 及附件不提供給稽核；案件 bundle、完整封存及比較維持後端拒絕。Rust 正式程式碼、凍結基準與宿主技能均未變更。

最終 Linux 原生驗證已修復原先七項前端 parity 失敗：**前端 956、元件 612、CI 113、技能 66 項通過**。保留前端 33 項及技能一項平台限定略過；無失敗或取消。型別與儲存庫檢查通過，每項最終要求均無暫存項目遺留。尚未驗證打包後桌面程式、各裝置寬度的視覺呈現，以及 macOS／Windows 原生執行。

| 套件 | 要求 | 測試總數 | 通過 | 失敗 | 略過 | 遺留暫存項目 |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| 桌面型別檢查 | b23c-final-01 | — | 檢查通過 | 0 | — | 0 |
| 前端 Node | b23c-final-02 | 989 | 956 | 0 | 33 | 0 |
| 元件 | b23c-final-03 | 612 | 612 | 0 | 0 | 0 |
| Node CI | b23c-final-04 | 113 | 113 | 0 | 0 | 0 |
| Node 技能 | b23c-final-05 | 67 | 66 | 0 | 1 | 0 |
| 儲存庫檢查 | b23c-final-06 | — | 檢查通過 | 0 | — | 0 |

## 11 月 11 日已入案原始碼稽核報告

已入案稽核可出現在單輪及合併 HTML／JSON 報告與凍結快照。標準設定套用共用遮蔽政策：提供者文字與程式碼分別隱藏並計數，檔案與範圍使用位置標記，標題替換已知私密字串，提供者涵蓋識別碼與指紋使用固定的 SHA-256 假名，產品產生的識別碼、分數與摘要維持原值。已確認問題使用在地化的原始碼問題類別敘述。`none` 保留原生說明、影響與修復策略，也保留看似產品標記的提供者文字。

只有規劃中、進行中、受阻、延後，以及仍有未解決候選問題的單元計入剩餘工作並提供後續路徑。每項稽核的剩餘單元彙整為一列涵蓋缺口，不重複增加未測試計數；範圍外單元另彙整為一列排除項目。第一層使用「Cloudflare 原始碼稽核」名稱，並在地化單元狀態與驗證標籤。剩餘單元共用一項下一步：「請從列出的路徑繼續原始碼稽核。」標準遮蔽保留此產品句子；路徑留在未測試項目及技術詳細資料。範圍外單元不產生下一步。範圍外單元列出狀態而不提供繼續路徑；不適用單元只出現在計數與技術詳細資料。沒有剩餘單元的未完成稽核顯示未解決候選問題數，或簡短的未完成結果。候選指紋只列於技術詳細資料。空的待驗證與未測試區塊省略，繁體中文產品詞彙與標記已在地化，來源及驗證器事實讀取保存值。稽核報告繼續省略框架區塊，結尾也移除指向該區塊的句子。

入案交易提交後保存終態快照。待處理快照與前景命令共用函式庫中的錯誤分類，回歸測試涵蓋全部十三種錯誤。待處理快照提供實際失敗代碼及可重試性；儲存或 I/O 失敗可重試，恢復退出碼為四；報告不可用時不可重試，退出碼為二。恢復不啟動稽核工作。框架報告、OCSF、OSCAL、附件、案件 bundle 和完整封存保持既有入案限制，稽核比較仍不可用，宿主技能不變。

最終原生 Linux 驗證通過 **2,013 項 Rust、179 項 CI／技能 Node 及 584 項元件測試**。桌面型別檢查通過。前端 Node 通過 935 項、略過 33 項，保留七項已知的詞彙及前後端種類一致性失敗；稽核產品標籤與繼續句子亦待桌面翻譯。三項既有 Rust 測試維持忽略，另略過一項 Windows ACL Node 測試。格式、無警告 Clippy、diff、技能同步、網站語系與未變更的報告保真驗證均通過。以下列出最終請求的完整明細，每項請求的**暫存殘留數均為零**。macOS 與 Windows 原生執行仍未驗證。

| 原生測試組 | 請求識別碼 | 通過 | 失敗 | 忽略或略過 | 暫存殘留 |
| --- | --- | ---: | ---: | ---: | ---: |
| 格式 | 23af3-final-01 | 檢查通過 | 0 | — | 0 |
| Clippy | 23af3-final-02 | 檢查通過 | 0 | — | 0 |
| Rust A | 23af3-final-03 | 1,950 | 0 | 0 | 0 |
| Rust B | 23af3-final-04 | 56 | 0 | 2 | 0 |
| Node CI | 23af3-final-05 | 113 | 0 | 0 | 0 |
| Node 技能 | 23af3-final-06 | 66 | 0 | 1 | 0 |
| 儲存庫檢查 | 23af3-final-07 | 檢查通過 | 0 | — | 0 |
| 全引擎報告稽核 | 23af3-final-08 | 7 | 0 | 1 | 0 |
| 桌面型別檢查 | 23af3-final-09 | 檢查通過 | 0 | — | 0 |
| 前端 Node | 23af3-final-10 | 935 | 7 | 33 | 0 |
| 元件 | 23af3-final-11 | 584 | 0 | 0 | 0 |

## 11 月 11 日定稿稽核入案

開發命令已可將核驗完成的定稿稽核與原件複本以單一交易入案，支援收據重播及發布中斷恢復。該較早階段的 Check fixes 與執行比較拒絕使用已入案稽核；報告、匯出與完整封存亦拒絕相關案件，技能入口不變。原生 Linux 的兩組指定 Rust 測試共通過 1,991 項，CI 與技能 Node 測試共通過 179 項，另重跑全部 10 項入案 CLI 測試亦通過；兩項既有 Rust 測試維持忽略，另略過一項 Windows ACL 的 Node 測試。格式、無警告的 Clippy、diff、技能同步、網站語系與報告保真檢查皆通過，每項最終驗證請求的暫存殘留數皆為零。macOS 與 Windows 原生執行尚未驗證。

## 11 月 11 日測試暫存清理

建立唯讀產品資料的測試改用同一個共用暫存根目錄輔助型別；清理時恢復目錄擁有者權限且不跟隨連結，Unix 上若仍無法移除，測試即失敗。原生 Linux 通過 2,606 項 Rust 測試及 241 項 Node 測試，每項最終驗證請求的暫存殘留數皆為零；三項既有 Rust 測試維持忽略，另略過一項 Windows ACL 的 Node 測試。格式、無警告的 Clippy 與儲存庫檢查皆通過；原生 macOS 與 Windows 執行仍未驗證。

## 11 月 11 日 Cloudflare 稽核準備

定稿紀錄現在可離線對照產品自身的保管紀錄與來源收據，完整核驗資料包，無須重新執行驗證器。

開發技能現已提供[宿主操作指引](../skills/ai-security-scanner/references/cloudflare-source-audit.md)，將固定版本來源稽核方法對應到就緒檢查、使用者確認模型處理範圍、原生代理委派、輸出擷取、驗證及定稿。[合成來源驗收工具](../tests/acceptance/cloudflare-host/README.md)透過公開命令建立已就緒來源目錄；準備成功本身不代表執行過稽核。在 Linux 的真實驗收中，一個具原生子代理的開發宿主依此指引對該合成儲存庫完成快速稽核，預算七次呼叫：四個偵察代理、一個漏洞搜尋代理、一個涵蓋審查代理與一個驗證代理。每項派工都先核發再委派，每份回傳輸出逐位元組保存，七份共用文件皆獲接受，紀錄通過驗證並完成定稿。結果為一項待驗證線索（即該儲存庫的並行扣點缺陷，未標嚴重度），沒有已確認或已排除的紀錄，涵蓋範圍為部分。兩個支援的宿主中已有一個完成此驗收。已發布桌面版的操作方式維持不變。

開發核心可準備、保存並定稿稽核紀錄，綁定已就緒的產品來源目錄、產生產品識別碼並保存收據；會檢查宿主宣告、預算、當前授權與來源完整性。準備不執行稽核、不呼叫模型、不執行目標程式。宿主工作目錄必須是真實目錄，路徑各層都不能經過連結；準備不讀取目錄內容或寫入檔案。定稿前的所有檢查點操作及重試都會重新核對目錄與授權。

宿主可在委派前取得產品產生的派工與代理識別碼，並以中斷原因記錄放棄的派工。產品記錄角色、順序與時間，核對波次及預算規則，保留替代關係；核發派工不會啟動代理，也不代表代理曾經執行。每項請求以預期鏈首延伸雜湊鏈，相同請求重試取回原紀錄。

宿主現在可一次提交七種共用文件中的一至七份，整批接受或整批拒絕。產品只擷取指定檔案，核對可選的雜湊及長度宣告、文字編碼與大小限制，以固定版本驗證器檢查已擷取的涵蓋紀錄及發現文件，並比對執行中繼資料與準備內容；允許尚在進行中的狀態。文件遭拒時不保留內容或新增事件。接受的位元組先存入私有內容定址儲存區，再以一筆事件記錄各文件的修訂編號。相同內容可重用物件，但每次接受的修訂都計入每次稽核 512 MiB 的累計上限。擷取表示產品保管這些位元組，不代表對文件內容作出判斷。

宿主可為每個尚未結束的派工提交一份輸出，路徑限於該派工自己的代理目錄。偵察角色須回傳非空文字，獵手與評論者須回傳單一嚴格 JSON 物件。候選驗證者的決定須與紀錄裁定一致，且紀錄通過固定版本的發現驗證器。接受後派工結束，保存原始位元組與驗證決定資料。格式錯誤的驗證者輸出永久捨棄，只記錄雜湊、長度與型別化原因，不保存內容；重新派工會再消耗一次預算。讀取或驗證器執行環境失敗時，原派工仍保持開啟。

標準及深入模式可針對已有候選驗證輸出的合格發現核發最終驗證派工。產品從已保存的發現文件讀取紀錄，自行綁定目前修訂編號與精確紀錄雜湊。最終輸出可核對指定指紋，或提出通過格式驗證的替代紀錄；提案不會直接修改發現。修訂改變後須重新綁定新的派工。定稿前的所有檢查點動作，包括重試，都會在驗證資源與準備時不同時拒絕使用過時準備。

宿主現在可從產品已保管的位元組驗證終態稽核。產品自行產生資料包清單，選取目前適用的驗證收據，完整核對來源目錄與原始快照，並執行既有資料包驗證器；另核對涵蓋紀錄中的代理是否曾獲派工、證據擁有者是否已結束，以及完整稽核是否具備偵察與評論輸出。宿主工作目錄已移除仍可驗證。結果包含能否定稿、可重現的清單及資料包雜湊、維持僅屬回報資料的原始驗證收據，以及獨立的紀錄錯誤。驗證持有寫入鎖但不新增紀錄，結束前會移除私密暫存資料包；可以定稿不代表已經定稿。

宿主可提供驗證回傳的鏈首與資料包雜湊進行定稿。產品重新執行終態驗證，在私密暫存區建立唯讀資料包，並於交易內重新核對鏈首、案件修訂、請求身分與有效授權後提交一筆終態紀錄。資料包保存原有的僅屬回報資料原件、準備收據與依序排列的完整紀錄，以及獨立的工作流程投影；只有此投影及其終態紀錄宣告流程已記錄、來源綁定與授權已驗證。是否執行稽核只表示至少一個獵手派工已結束，不證明代理曾執行、模型獨立或發現為真；正式接納與目標執行旗標仍為否。

定稿後拒絕後續檢查點、驗證及不同的定稿請求。原定稿請求可在核對三份已記錄檔案後重播，不需要當前授權。發布後、交易前中斷時，只有檔案雜湊與預期完全相同才重用既有資料包；不同內容保留原狀並回報儲存失敗。唯讀狀態顯示資料包路徑、原生結果與計數，以及已驗證、遺失或不符的狀態，不提供下一步操作。案件封存保留終態歷史事件並明列省略資料包，因此還原後顯示資料包遺失；確認刪除案件檔案會一併移除唯讀資料包。

唯讀狀態可在另一個寫入者持有鎖定時查詢，回報鏈首、派工的開啟／結束／中斷／捨棄狀態、結束時間、輸出資料、各狀態計數、預算、文件最新修訂、接受時間、修訂次數及累計容量，不讀取物件。定稿前的檢查點重試核對授權與目錄，但不重新開啟文件。準備仍有效時可恢復遺失的描述檔，既有不同內容不會被覆寫。封存保留歷史事件，並明列省略稽核目錄與物件；還原後不能恢復執行。確認刪除案件檔案時會一併移除物件。

本輪離線核驗通過 1,967 項 Linux 原生 Rust 測試：核心與提供者群組 1,911 項，封存、前景執行與報告群組 56 項；兩項既有保真測試維持忽略。Node 通過 244 項測試，包含持續整合 113 項、技能 66 項與上游 65 項；一項既有 Windows 存取控制測試跳過。格式檢查、禁止警告的 Clippy、差異檢查、技能副本同步、網站語系與報告保真驗證均通過。每項已完成的原生請求均未留下暫存項目。macOS 與 Windows 原生執行尚未驗證。

先前保管流程的 Linux 原生驗證通過 1,957 項 Rust 測試：1,659 項函式庫單元、75 項 CLI 單元、77 項稽核 CLI、24 項來源目錄 CLI、29 項工作區快照、24 項資料包、六項提供者、六項唯讀狀態、一項建置身分、14 項案件封存、14 項前景掃描、13 項報告快照、七項執行環境準備，以及八項報告保真測試；另有兩項既有保真測試維持忽略。Node 共通過 244 項，包含 113 項持續整合、66 項技能與 65 項上游測試；一項既有 Windows 存取控制測試在 Linux 跳過。格式檢查、禁止警告的 Clippy、差異檢查、技能副本同步、網站語系與報告保真驗證均通過。原生驗收準備在兩個全新目錄均成功，並拒絕重用非空目錄。macOS 與 Windows 原生執行尚未驗證。後續仍須完成另一宿主的驗收，以及案件、報告與完整稽核資料包封存整合。操作方式見[稽核準備與狀態](cloudflare-provider.md#audit-preparation-and-status)及[定稿指南](cloudflare-provider.md#sealing-the-audit-record)。

## 11 月 11 日 Git 追蹤檔案探測強化

擷取專案快照時，開發核心會請主機上受信任的 Git 列出儲存庫追蹤的檔案。這個子程序除了既有的固定環境外，現在一律拒絕所有 Git 傳輸，也不會隨需抓取缺少的物件；受檢儲存庫自己的設定因此無法讓掃描器在擷取期間啟動程式或連線到網路。所有 Git 呼叫都由同一個共用建構函式建立。

若儲存庫的追蹤清單必須抓取物件才能讀出，沿用探測無法使用時的既有規則：擷取照常完成，該儲存庫範圍保留全部檔案。一般儲存庫與一般 partial clone 的清單及快照內容不變。

Linux 原生測試在執行期建立本機儲存庫，設定中指名一個只有抓取物件時才會啟動的標記程式；先確認測試資料確實有效，再經產品擷取，結果不得出現標記。另一項測試比對一般 partial clone 與完整 clone。Linux 原生驗證通過 1,861 項 Rust 測試，其中函式庫單元 1,642 項、工作區快照 29 項，其餘各組不變；另通過 113 項 CI 文件測試。格式檢查、禁止警告的 Clippy 與儲存庫檢查均通過。尚未驗證 macOS 原生執行；Windows 不執行這項探測。

## 11 月 10 日產品管理的來源檢視

開發核心已能從授權的儲存庫快照準備模型可讀的來源目錄、離線檢查內容，並查詢準備紀錄。每次準備請求都須明確指定範圍並同意模型處理。固定政策保留納入檔案的原始位元組與行號，排除敏感名稱與私鑰標記，並逐一交代原快照檔案的去向；不保證內容完全沒有機密，也不執行稽核或呼叫模型。

準備時會核對當前授權、快照綁定與完整性；發布前會再核對授權，交易內記錄收據前也會做最後一次核對。請求進入快照評估時才逐一檢查範圍選項；較早遇到阻擋原因時直接回傳。重試 ready 請求會重新評估授權及實際檔案；重試 blocked 請求則回傳已記錄的阻擋原因，排除原因後須使用新的請求 ID。過時紀錄僅供查閱，不回傳可用路徑。遺失的來源目錄會重建，損壞副本或阻擋目的地的檔案、符號連結會先移到保留名稱，再建立新的來源目錄；不跟隨連結或改動其目標。離線檢查會驗證檢查期間曾存在一致的目錄清單、政策、排除紀錄及內容身分，但不認證產出者。外部資料包即使引用產品實際建立的來源目錄，也維持 reported-only。

Linux 原生驗證通過 1,857 項 Rust 測試：1,641 項函式庫單元、75 項 CLI 單元、24 項來源目錄 CLI、26 項工作區快照、22 項資料包、六項 provider、六項唯讀狀態、一項建置身分、14 項案件封存、14 項前景掃描、13 項報告快照、七項執行環境準備，以及八項報告保真測試；另有兩項既有保真測試維持忽略。Node 共通過 241 項，包含 113 項 CI、63 項 skill 與 65 項上游測試；一項既有 Windows ACL 測試在 Linux 跳過。格式檢查、禁止警告的 Clippy、差異檢查、skill 副本同步、網站語系與報告保真驗證均通過。

案件封存保留歷史準備紀錄，並明列未包含來源目錄；還原不會重新授權。確認刪除案件檔案時，唯讀來源目錄與保留的損壞副本都會一併移除。Git 擷取、宿主協調、資料包正式接納及案件／報告整合仍待完成；尚未驗證 macOS 與 Windows 原生執行。操作方式見[來源目錄指南](cloudflare-provider.md#product-owned-source-views)。

## 11 月 10 日 Cloudflare 私密保存與離線取回

新增 `retain-bundle`、`inspect-retained` 與 `retrieve-retained`。保存要求先前驗證的 bundle digest，先在私密暫存目錄擷取原件與來源 view，再核對擷取內容、保存報告投影與驗證紀錄，最後一次發布完整目錄，不覆寫既有資料。Index 綁定全部列出檔案與來源；不複製未列入的 scratch。同時保存到同一路徑時只會有一份完整結果。

保存目錄搬移、原資料刪除後，仍可在沒有 Node、模型、掃描 runtime 或案件資料庫的情況下檢查完整性及逐位元組取回。讀取不重新執行 validators，也不認證外部 workflow；取回要求保存 index 的 digest，不因 producer core 不同而阻止讀取支援格式。全程不改案件或取得案件 writer lease，身分保持 reported-only。

Linux 通過 1,724 項 Rust 測試：1,616 項核心、74 項 CLI 單元、一項 build identity、21 項 bundle／保存子程序、六項單文件子程序及六項唯讀 status。覆蓋移除來源後逐檔取回、搬移、竄改、過期 digest、拒絕覆寫、排除 scratch，以及案件 writer 存在時的同時保存。另通過 240 項 Node／上游／CI 測試；一項 Windows ACL 測試在 Linux 明確跳過。CLI feature 全 workspace targets 的禁止 warning Clippy、格式與 skill 副本同步均通過。

這是 provider 原件與來源 view 的私密保存，並非完整 canonical repository 或案件備份。該保存里程碑當時，受信來源政策、宿主協調、正式案件接納與報告整合仍待完成；Windows／macOS 本批原生執行仍未驗證。用法見[保存與離線取回](cloudflare-provider.md#private-retention-and-offline-retrieval)。

## 11 月 10 日 Cloudflare 資料包驗證與報告投影

新增 `provider cloudflare validate-bundle`，核對版本化 manifest、明確選取的來源 view、上游 validators、來源行號、當前與歷史 coverage 證據、fingerprint、宣告計數及自帶 verifier 輸出。讀取器從固定根目錄逐層開啟，拒絕連結、reparse point、路徑別名及讀取期間的替換；回傳 digest 綁定 manifest、列出的全部檔案與來源雜湊，不讀取或複製未列入的 scratch。

驗證成功後回傳共用 provider 報告投影，保留原生 records、來源 hash、ledger／attempt 歷史，並分開計算 confirmed、needs_validation、rejected 與未驗證 candidate。Payload 與 proposed code 的空白完整保留；未完成 run 仍保留已完成項目，不偽造發現。Quick 合併驗證與 carried-record owner 例外沿用固定上游語義。

結果一律維持 reported-only，自帶 receipt 不會取得受信 workflow、來源授權或 canonical snapshot 證明；不建立案件、人工確認狀態、掃描、匯出或正式入場紀錄。操作與 manifest 契約見[資料包驗證](cloudflare-provider.md#reported-bundle-validation)。受信 source view、宿主協調 receipts、durable 入場與案件／報告整合仍待接續。

Linux 通過 1,716 項 Rust 測試：1,616 項核心、74 項 CLI 單元、一項 build identity、13 項資料包子程序、六項單文件子程序及六項唯讀 status。另通過 240 項 Node／上游／CI 測試；一項 Windows ACL 測試在 Linux 明確跳過。CLI feature 全 workspace targets 的禁止 warning Clippy 通過。CI 已納入三平台資料包命令，但 Windows／macOS 本批實際執行仍未驗證；預設 skill 入口不變。

## 11 月 10 日固定版本 Cloudflare 文件驗證

已依[文件中的固定上游版本](cloudflare-provider.md)原樣保存 Cloudflare 的 22 份檔案，包括 MIT 授權、方法、schema 與 validators；lock 記錄 Git blob、SHA-256 與長度。新增 `provider cloudflare validate-document`，可驗證 findings 或 coverage ledger，回傳原始輸入與內嵌驗證程式的雜湊；文件不合格以 exit 2 回傳。它不建立案件、不取得資料 writer lease、不接觸目標，也不匯入發現。

轉接器保留上游 schema／verdict 與 CLI preflight 限制，另外拒絕重複 JSON 欄位。程式由私密暫存目錄執行，輸入、輸出與執行時間均有上限，不繼承 Node preload／module／loader 環境變數。唯讀輸入拒絕實體連結、特殊檔案、無效 UTF-8、超大或讀取期間改變的檔案；完整 bundle 的根目錄、來源與證據路徑政策仍待接入。方法文件更新維持核心快取可重用，驗證程式與 schema 更新會重建核心。

Linux 通過 1,700 項 Rust 測試：1,613 項核心、74 項 CLI 單元、一項 build identity、六項 Cloudflare 子程序及六項唯讀 status；包含真正 Node 程序的停滯輸入、stdout／stderr 超限後終止與回收。另通過原樣保存的 65 項上游測試、62 項適用的 skill／bootstrap 測試與 113 項 CI 契約，共 240 項 Node 測試；一項 Windows ACL 測試在 Linux 明確跳過。CLI feature 全 workspace targets 的禁止 warning Clippy、格式與 skill 副本同步均通過。CI 已納入三平台命令測試，本批 Windows／macOS 實際執行仍未驗證。

此單文件里程碑當時，bundle 關聯驗證、報告映射與宿主協調仍待實作；後續資料包成果見上方紀錄。用法與邊界見[Cloudflare 文件驗證](cloudflare-provider.md)。

## 11 月 8 日報告保存實作

[報告基準](../tests/fixtures/report-fidelity/README.md)在 renderer 抽取前，從收據記錄的原始 core 生成：兩份固定案件使用全部 25 個 adapter fixtures，保存 26 份文件、36 筆簽章 bundle payload 雜湊及 20 張 Chromium 截圖。混合 terminal 情境仍保留完成的 sibling 結果。這是 fixture 執行，不是對真實目標的掃描。

共用 renderer 保留原 HTML／canonical JSON 實作；快照保存完整私密案件脈絡、設定、選定原始附件 ZIP 與精確 HTML／JSON。移除原 DB、workspace、runtime 後仍可取回與重播，不呼叫模型。重播要求相同編譯 renderer／來源身分且 bytes 一致；不相容時只能取回原件。這是手動單 run 報告保存，不是完整案件 archive，也不改寫匯出歷史。

本機 Linux 使用 Rust 1.98.0、`--locked --no-default-features --features cli` 驗證：1,506 項核心單元測試（含七項新增 snapshot）、70 項 CLI 單元測試、六項唯讀 status、五項 CLI snapshot 子程序測試與八項報告保真整合測試通過（共 1,595 項；兩個明確的輸出產生器 ignored）。涵蓋 live owner 的 WAL 最新提交、無 migration／建工作區、案件與 triage 變更、刪除原始資料、附件 bytes 與 Standard 選取、未來 renderer/domain/report 格式、壞 hash 和拒絕覆寫。Baseline verifier、120 項報告相關前端測試及全部 106 項 CI 契約測試通過。Formatting 與禁止 warning 的 Clippy 亦通過；CI 已接上固定報告資料變更時的 replay 測試，並每次驗證 corpus 收據。報告基準 README 保留重現命令；以上不是三平台遷移或完整 archive／restore 驗收。目前環境缺少 GTK／WebKit 開發套件，本批未宣稱桌面編譯或執行通過。

## 11 月 8 日私密案件封存實作

開發版 CLI 新增 `archive create`、`verify`、`restore-preview` 與 `restore`；既有 `case archive` 狀態指令與 signed report bundle 保持原義。新封存保存原始案件 JSON、全部目前 domain 欄位、事件順序、所有已記錄 raw evidence 及 terminal 報告快照；來源快照與舊匯出檔分別明確選取。缺少已選資料、無法追溯的歷史來源或會被反序列化丟失的欄位均拒絕。

還原在同檔案系統的私密 staging 建立新 DB，先寫 intent／receipt 再原子發布完整目錄，拒絕覆寫。原 DTO 保留歷史，新的 operational copy 停用目前 grants、owner confirmations、來源 capability 與 resume tokens。Archive 的 SHA-256 僅檢查內部完整性；未新增 archive 簽章或匯入私人簽章金鑰。[操作文件](case-archives.md)記錄限制、omissions 與重試語義。Windows／macOS 執行與完整 skill-to-restore 流程仍待驗收。

Linux／Rust 1.98.0、`--locked --no-default-features --features cli` 驗證通過：1,544 項核心單元測試、70 項 CLI 單元測試、七項 archive CLI 整合、六項 status、五項 snapshot CLI 與八項報告保真測試（共 1,640 項；兩個明確輸出產生器 ignored）。封存測試涵蓋移除原始資料、來源 writer lease 共存、完整 DTO／事件／blob、歷史來源 omissions、未知欄位、損毀檔案、目錄膨脹上限、私密 staging、不安全目的地拒絕、publish 前後中斷與原工作目錄未變時的重試。全部 106 項 CI 契約與固定 baseline verifier 通過。本批沒有修改 UI 或 scanner 執行行為；重現命令見[英文紀錄](development-status.md#november-8-private-case-archive-implementation)。

相同 Rust targets 的格式檢查與禁止 warning 的 Clippy 亦通過。

## 11 月 8 日共用前景執行

開發版 CLI 新增 `scan run --wait` 與 `scan recover --wait`，桌面與 CLI 共用 coordinator、worker 和上游 adapters。前景程序持有並等待 exact generation worker 與 runtime 準備執行緒結束，完成持久狀態核對後保存版本化 command receipt。JSON 輸出 terminal envelope，NDJSON 加上進度事件；訊號及輸出失敗／阻塞會要求取消，仍等待底層 runtime 操作收尾，不放棄執行所有權。

所有使用 writable initialization 的 CLI 路徑會取得資料目錄 writer lease；唯讀 status 可與 live owner 共存，並確認案件與 command receipts 來自同一個觀察版本。收據可重開，也隨案件封存／還原保存。若只在最後傳送結果時失敗，CLI 回傳 4，已提交的收據仍可由 status 取回。

復原只選定 exact run，修改前先核對 checkpoint 身分，只清理已記錄資源及重解析已驗證證據；保留其他已完成／失敗任務，拒絕新 target-facing attempt，也阻止 Naabu 自動續批。損壞證據保留失敗結果與 checkpoint，不再建議立即重試。指令及退出碼見[前景操作文件](foreground-scans.md)。

Linux／Rust 1.98.0、鎖定依賴驗證通過：1,597 項核心單元測試、73 項 CLI 單元測試、25 項 job-manager、九項前景子程序、七項 archive、六項 status、五項 snapshot 及八項報告保真測試（共 1,730 項；兩個明確輸出產生器 ignored）。前景測試涵蓋 SIGINT／SIGTERM、writer 互斥、stdout 中斷／停止讀取、最後傳送失敗仍保留不可變收據、同批失敗保留、無來源／runtime 的證據復原、capture 中斷及竄改證據拒絕。全部 106 項 CI 契約、固定報告基準、格式檢查與 CLI feature 全 workspace targets 的禁止 warning Clippy 通過。

獨立 egress-gateway 配置亦通過全 targets 禁止 warning 的 Clippy 與 20 項 binary 測試。

以上為 Linux 原始碼與受控 fixture 驗證。子程序使用本機受控 runtime executable，經過真正的 orchestrator 與 Gitleaks adapter，未執行固定上游 scanner image。桌面與 pinned scanner 對照、Windows／macOS 執行及完整 skill-to-restore 仍待驗收。桌面 `cargo check` 因缺少 `dbus-1` 開發檔而停在 `libdbus-sys`，本機亦缺 GTK／WebKit 開發套件，因此未宣稱桌面編譯或執行通過。重現命令見[英文紀錄](development-status.md#november-8-shared-foreground-execution)。

## 11 月 8 日固定核心 bootstrap 與 skill 入口

`scripts/skill/bootstrap.mjs` 已提供 `doctor`、`prepare` 與 `run`，要求受信產品 checkout 的完整 Git revision。建置先保存受控輸入，使用 Rust 1.98.0 與 native compiler，產生帶版本化收據的 CLI-only 快取。重用時再次驗證收據、執行檔雜湊與編譯身分；skill 文字修改可重用相同 core，嵌入資料或 recipe 變動則會重建。失敗不覆蓋原先 ready entry。開發變更須明確使用 `--allow-dirty`，並保存實際輸入 digest。新增 `build-identity` 不初始化案件或 runtime。

單一 skill 來源已移至 `skills/ai-security-scanner/`，同步腳本產生並檢查兩個宿主副本及相對文件連結。開發路徑使用 bootstrap，正常操作仍以已發布桌面為預設。轉送會使用案件狀態的 CLI 命令時，必須明確指定資料目錄。[Bootstrap 操作文件](skill-bootstrap.md)列出目前可用指令。

CI 已分開 skill 文字／契約、native core 與 installer 輸入。新增 Linux、macOS、Windows 原生 lanes，實際建置與執行 bootstrap、重用快取、重播報告及驗證 archive round trip。Windows runtime 驗證保留，NSIS 步驟僅由 installer 變更觸發；新增 lanes 本身不等於各平台已通過。

Linux x86_64 使用 Node 24.22.1、Rust 1.98.0 與既有 Cargo 依賴，以 `--offline` 分別完成全新 dev 與預設 release build、第二次快取命中，以及透過快取 CLI 保存合成示範案件報告。刪除該 workspace 後，取回與重播的 HTML／JSON bytes 完全一致，也沒有重建原 workspace。未接觸目標、未下載 scanner runtime 或映像。收據明確記錄基準 revision、dirty development 狀態及實際 input SHA-256；精確身分見 [bootstrap 驗證紀錄](skill-bootstrap.md#observed-local-validation)。

本批 Rust 驗證通過 73 項 CLI 單元、一項 build-identity 子程序、七項 archive、五項 snapshot 及八項報告保真測試，共 94 項不同測試；兩個明確輸出產生器 ignored。CLI feature 全 workspace targets 的禁止 warning Clippy 與格式檢查通過。38 項可攜 Node skill／bootstrap 測試、112 項 CI 契約、canonical skill 驗證及宿主副本同步檢查全部通過；另有一項真實 Windows ACL 測試在 Linux 明確跳過，已接入 Windows 原生 lane。Windows 快取已加入 owner／ACL 入場檢查，執行前拒絕其他使用者存取、不安全父目錄或無法確認的權限。

各引擎按需 runtime 準備、Cloudflare 協調、Windows／macOS 原生執行及完整 skill-to-restore 仍待完成；core 準備會明確回報 scan 準備尚未提供。正式首選入口尚未切換，本批不要求安裝包或新版發布。重現命令見[英文紀錄](development-status.md#november-8-pinned-core-bootstrap-and-skill-entry)。

## 11 月 9 日指定引擎的 runtime 準備

開發 bootstrap 現在接受 `prepare --capability scan --engine ID --data-dir DIR`，重用已驗證的核心快取，只準備所選 catalog pin 及必要的共用 gateway 映像。CLI 先驗證全部引擎，要求明確資料目錄並取得 writer lease，再逐項保存準備結果；最後收據先保存才輸出。準備不建立案件、授權或接觸目標的工作；個別映像失敗保留其他已完成結果。

準備流程與掃描共用 managed runtime／相容 runtime 選擇。離線模式只使用正在執行的 runtime、既有映像或受驗證的本機 archive，不啟動 VM 或連 registry。父程序透過固定管道傳遞取消，父程序結束也會觸發取消。Managed 啟動與映像操作會回收所屬程序；停滯的 managed 映像讀取有 30 秒 I/O 上限，保留可續傳資料。此路徑不進入桌面版的 Windows 自動前置條件修復流程。

Linux 驗證通過 1,611 項核心單元、74 項 CLI 單元、一項編譯身分、七項 runtime 準備、25 項 job-manager、九項前景、七項封存、六項狀態、五項報告快照與八項報告保真測試，共 1,753 項；兩個明確輸出產生器 ignored。範圍包含準備前取消、保留下載前綴、所屬程序收尾、不自動修復 Windows 前置條件、離線映像選擇及保留成功項目。48 項可攜 Node skill／bootstrap 測試通過，另有一項 Windows ACL 測試在 Linux 明確跳過。CLI feature 全 workspace targets 的禁止 warning Clippy、格式檢查、112 項 CI 契約、固定報告基準、canonical skill 驗證與副本同步均通過。

Linux x86_64 使用 Node 24.22.1／Rust 1.98.0 完成新的離線 dev bootstrap 建置，再由[可重現的 runtime smoke](../scripts/ci/skill-runtime-smoke.py) 重用快取，以 Docker 29.1.3 執行已存在的固定 Gitleaks 映像。只掃描自建合成 fixture，得到一筆預期秘密發現，原始證據中的秘密值完整遮蔽，完成後沒有遺留容器。移開原 workspace、來源與快照後，完整封存還原保留發現、全部證據、來源快照及前景收據，並停用掃描授權；所有還原檔案 hash 通過，HTML／JSON 取回與重播均和原始 bytes 一致。精確身分見 [bootstrap 驗證紀錄](skill-bootstrap.md#november-9-selected-engine-and-real-scan-validation)。此證據涵蓋 Linux 的自建本機專案流程，尚不代表多資產、Cloudflare 或三平台完整流程。

全新主機自動取得 managed bundle 仍待實作。Windows／macOS 原生執行、桌面對照與 Cloudflare 整合，仍需各自實作或驗證。一般 bootstrap 前景命令已改用下述共用取消管道，Windows 原生驗證仍待完成。現行操作預設維持已發布桌面版。重現命令見[英文紀錄](development-status.md#november-9-selected-engine-runtime-preparation)。

## 11 月 9 日 bootstrap 前景取消

Bootstrap 的 `run` 現在為 `scan run`、`scan recover` 及 `runtime prepare` 建立私有取消管道，共用指定引擎準備既有的有限長度 Rust reader。Ctrl+C／終止請求只傳遞一次，bootstrap 等待核心結束並保留退出碼；父程序意外結束也透過 EOF 取消。非法控制輸入仍會清理所屬工作，保存 `cancellation_control_failed`，不再誤報輸出失敗。正常完成不必等待管道關閉。

Linux 通過 74 項 CLI 單元、13 項前景子程序、七項 runtime 準備、六項唯讀狀態及七項封存測試，共 107 項。前景測試串接實際 Node launcher 與編譯後 CLI，驗證中斷、終止及父程序被強制結束時，精確收據仍保存、原資源完成清理、受控 runtime 程序回收且資料目錄鎖釋放；另驗證 EOF、非法／超長控制訊息及正常完成。此批使用合成 runtime fixture，未執行上游掃描。

54 項適用的 Node skill／bootstrap 測試通過，Windows ACL 測試在 Linux 明確跳過。新增六項可攜測試涵蓋命令辨識、重複取消、父程序結束、正常退出及啟動失敗；三平台 native CI 現在都執行這些 Node 測試。CLI／前景／runtime 準備的禁止 warning Clippy、格式、宿主副本同步及 112 項 CI 契約皆通過。Windows／macOS 原生執行及完整 skill-to-restore 仍待驗收；重現命令見[英文紀錄](development-status.md#november-9-bootstrap-foreground-cancellation)。

## 11 月 10 日合併原始附件與超限封存

合併 HTML 已支援依來源 run／task 區分的 ZIP 下載，重用既有原檔驗證與遮罩規則，保留相對目錄、原始 bytes、hash 及來源時間。Standard 排除敏感原檔；ZIP 隨快照凍結，移除原 workspace 後仍可重播及封存還原。單 run 附件與報告輸出維持原行為。

所選原檔跨來源合計限制為 64 MiB／10,000 檔，最後文件另有 64 MiB 上限，包含 ZIP、base64 與 markup。超過任一附檔界線時保留可讀 HTML，在旁邊產生完整私密案件 archive；收據列出 included／omitted 數量、原因、檔名、路徑、hash 與長度。完整案件封存可能包含其他輪次的敏感證據，因此附件選項明確包含此同意。Archive 保存匯出歷史提交前的案件 revision、全部已記錄證據及本次凍結報告，既有來源 omissions 仍保留，不新增掃描授權。任一發布或歷史提交失敗均回復本次新建 HTML、快照與 archive。

桌面面板沿用既有元件，HTML 才顯示原檔／私密封存選項，切換 JSON 會清除選取；成功時顯示實際封存位置，提供英、中、日文。後續完整 archive 選擇 `--include-export-files` 可保留該封存副檔，restore 驗證並重新指向還原位置；未選時清除舊絕對路徑，但原始證據與合併快照仍保存在案件封存中。[操作說明](report-snapshots.md#include-original-files)記錄 CLI 旗標及手動快照界線。

Linux 通過 2,179 項 Rust 測試：1,612 項核心單元、74 項 CLI 單元、438 項獨立 engine/domain、14 項前景、14 項封存、13 項快照、六項唯讀 status 與八項保真；兩個明確輸出產生器 ignored。涵蓋實際 65 MiB 原檔、48 MiB 難壓縮資料經 ZIP／base64 後超限、跨來源 10,002 檔、敏感檔排除、損壞原檔、失敗回復、封存還原及副檔保留。CLI feature 全 targets 禁止 warning Clippy、TypeScript 與 112 項 CI 契約通過；前端測試 942 項通過、33 項明確跳過；三項元件測試驗證選取／同意／JSON 重設與封存位置。

Chromium 使用真正元件與 CSS，在英、中、日文的 390／768／1440px 共九種版面檢查長路徑，沒有水平溢出或頁面錯誤。視覺 fixture 的匯出是受控假資料，未接觸目標；固定報告基準與宿主 skill 副本保持一致。原生桌面及 Windows／macOS 執行仍需另行驗證。

## 11 月 9 日合併報告快照

合併 HTML／JSON 匯出已透過共用桌面／CLI 服務自動保存私密快照與 `combined_exports` 歷史紀錄。沿用 2–16 個 terminal sources、明確來源順序與各來源獨立的發現及涵蓋缺口。快照凍結完整 selected-run projection、生成時間、語言、遮罩、原始文件 bytes 與案件脈絡；匯出和離線重播共用同一 renderer，重播不讀取最新案件、不啟動掃描或模型。

`report snapshot --run-id FIRST --run-id SECOND` 可手動保存多來源而不改寫案件。合併快照使用含有序 `selected_run_ids` 的 v2 envelope，單 run v1 維持可讀。renderer 不相容時仍可取回原件，包含目前 domain 無法解碼的未來 variant；來源順序或已知 report schema 不符會拒絕。此步仍不支援 combined 原始附件。

快照與分享文件完成後才提交匯出歷史；輸出或資料庫失敗時只回復本次新檔。完整 archive 自動保留已記錄的合併快照、核對各來源及參照，並可選入外部分享檔。Restore 保留快照相對路徑，清除未選外部路徑並重新指向已選且驗證的檔案；即使重算傳輸 manifest，刪掉已記錄的原件仍拒絕驗證／還原。還原案件可再次封存。

Linux 通過 2,175 項 Rust 測試：1,611 項核心單元、74 項 CLI 單元、438 項獨立 engine/domain、14 項前景子程序、11 項封存、13 項報告快照、六項唯讀 status 與八項報告保真；兩個明確輸出產生器 ignored。新增子程序測試涵蓋雙語合併匯出、反向來源順序、後續案件／triage 修改、原 workspace 不存在、手動快照、未來 domain／renderer 的 retrieve-only、失敗回復、封存缺件、選配匯出檔還原及再次封存。

CLI feature 全 workspace targets 的禁止 warning Clippy、格式、112 項 CI 契約、固定報告基準與宿主 skill 副本同步均通過，基準資料未重新生成。本批以 Linux 保存的合成案件驗證；此變更的原生桌面及 Windows／macOS 執行尚未驗證。重現命令沿用下方 terminal-run 里程碑，完整記錄見[英文紀錄](development-status.md#november-9-combined-report-snapshots)。

## 11 月 9 日掃描結束自動快照

共用服務現在會在結果整理與資源清理結束後，保存 terminal run 的私密 HTML／JSON 報告。接線涵蓋一般 worker、未執行檢查的請求、桌面取消收尾，以及前景 captured-result／cleanup-only recovery。桌面同步取消流程將報告產生交給既有追蹤中的背景收尾，不等待大型報告。仍有待整理證據或待清理資源的工作不產生 interim report。

`run_report_snapshots` 保存確切 run outcome、來源 revision 與可攜相對參照；前景收據提供 `result.report_snapshot`，唯讀 status 列出已保存紀錄。自動版本使用英文、Standard 遮罩，不含原始附件。同一結果重試、收據寫入及後續 triage 不覆寫原件；復原得到不同結果時另存新版。run 雜湊排序 JSON 物件，不依賴桌面／CLI 的 serializer feature；封存驗證使用已凍結 run，而非以目前 domain 重新序列化歷史資料。

保存失敗保留既有發現；資料庫寫入失敗時回復本次新建檔案。CLI 回報 `terminal_report_snapshot_failed`，沒有參照時提供同一 run 的 recovery 命令。重試不偵測 runtime、不啟動新掃描。已記錄但缺失或損壞的原件會被拒絕，不重新產生冒充歷史。唯讀查閱不替舊資料補存；明確 recovery 只能保存現在可用的脈絡與實際時間。Demo／已歸檔案件維持不可修改。

完整封存包含所有已記錄 terminal 原件並核對 run 關聯。即使重算傳輸 manifest，刪掉已引用快照仍會拒絕還原。移開原 workspace 後，還原快照的 HTML／JSON 取回與相容重播保持相同 bytes。分享報告不包含私密儲存參照。

Linux 通過 2,171 項 Rust 測試：1,611 項核心單元、74 項 CLI 單元、438 項獨立 engine/domain、14 項前景子程序、十項封存、十項報告快照、六項唯讀 status 及八項報告保真；兩個明確輸出產生器 ignored。覆蓋完成／失敗 sibling、取消、未執行檢查、待清理與 captured recovery、無 runtime 接觸的保存重試、triage 後不重複產生、原件損壞，以及封存缺件／還原。CLI feature 全 workspace targets 的禁止 warning Clippy、格式、112 項 CI 契約、固定 baseline 與 skill 副本同步均通過；基準原件未重新生成。

該里程碑使用 Linux 合成 fixture；當時原生桌面、Windows／macOS 執行、combined snapshot 與 Cloudflare 仍是後續工作，正式預設入口不變。重現命令見[英文紀錄](development-status.md#november-9-automatic-terminal-run-snapshots)。

## 11 月 9 日匯出報告自動快照

HTML／canonical JSON 單 run 匯出現在會在 `artifacts/CASE_ID/report-snapshots/` 自動保存私密快照。桌面與 CLI 共用的匯出層從同一份固定脈絡產生報告，分享文件使用快照內的原始 bytes；匯出歷史保存快照身分、來源 revision、相對路徑、長度與 hash。後續匯出另存新版，既有快照不改寫；沒有快照參照的歷史匯出仍保留原貌。

即使分享報告使用 Standard 遮罩，快照仍是本機私密資料。原始附件維持明確選擇與既有遮罩政策。目的檔已存在、快照保存或資料庫寫入失敗時，只移除本次新建的文件與快照；不刪除原有檔案。若程序在檔案發布後、歷史提交前中斷，可能保留未被紀錄引用的本機檔案，不據此宣稱匯出成功。

完整 archive 自動包含所有已記錄的匯出快照，不必另列 `--report-snapshot` 或選擇外部匯出檔案。驗證會核對匯出原件、case/run、遮罩、來源 revision 及精確 bytes；restore 後的相對參照可直接在新 workspace 使用。已記錄快照缺失或損壞會拒絕建立／還原封存。另存的手動快照與 archive 建立當下的新呈現版本仍保留。

新增子程序測試涵蓋雙語原始報告、案件／triage 修改後的獨立呈現脈絡、匯出失敗回復，以及免額外選取的完整封存。移開原資料與刪除分享文件後，還原的 HTML／JSON 取回與重播均等同原始 bytes，包含已選取的 HTML 附件；還原資料也可再次封存。即使重新計算傳輸 manifest，刪掉已記錄歷史快照的封存仍被拒絕。

Linux 通過 2,153 項 Rust 測試：1,611 項核心單元、74 項 CLI 單元、438 項獨立 engine/domain、九項封存、七項報告快照、六項唯讀狀態及八項報告保真測試；兩個明確的輸出產生器 ignored。CLI feature 全 workspace targets 的禁止 warning Clippy、格式、112 項 CI 契約、固定 baseline 驗證及宿主 skill 副本同步均通過；既有報告原始輸出與基準資料未改寫。

該里程碑當時的掃描完成自動快照、合併快照與 Cloudflare 尚待接線；該批未變更 scanner 行為或正式預設入口。驗證使用 Linux 合成保存案件，Windows／macOS 原生執行另待驗收。重現命令見[英文紀錄](development-status.md#november-9-automatic-export-snapshots)。

## 現況

- [v0.6.2 Windows 網站掃描修正](release/v0.6.2.md#繁體中文)為目前 stable／latest，提供 Windows、macOS 與 Linux 安裝版。修正 Windows 上無法啟動「頁面回應檢查（ZAP）」的問題，並包含 v0.6.1 安全性更新；實際驗證狀態見發布紀錄。

- [v0.6.1 安全性更新](release/v0.6.1.md#繁體中文)為前一個正式版，提供 Windows、macOS 與 Linux 安裝版。掃描不是自己建立的儲存庫之前，請先更新；變更、公告與實際驗證狀態見發布紀錄。

- [v0.6.0 上游與執行環境更新](release/v0.6.0.md#繁體中文)為較早的正式版，提供 Windows、macOS 與 Linux 安裝版。全部 25 個引擎已核對，十八個自建映像、KICS、離線資料、專用執行環境及應用依賴已更新；精確交付與平台限制見發布紀錄。

- [v0.5.3 10/21 事件掃描包](release/v0.5.3.md#繁體中文)為較早的正式版，提供 Windows、macOS 與 Linux 安裝版。一般掃描與事件專項共用 HTML／JSON 報告，附 ISO／NIST 對照；本版也更新 Trivy 資料庫、Nuclei 範本與 Vite 開發工具。公開檔案與平台觀察保存在發布紀錄。

- 較早的 [v0.5.2 上游引擎更新](release/v0.5.2.zh-TW.md)保留原始發布與平台觀察紀錄。更新十個引擎與離線資料，並修正新版 WSL 的 Windows 受限執行環境；公開檔案、更新簽章、來源證明、精確來源 CI 及 CodeQL 均驗證通過，平台觀察與限制見發布紀錄。

- 先前的 [v0.4.1 正式版](release/v0.4.1.zh-TW.md)保留原始安裝檔、更新目標與平台觀察紀錄。
- 程式包含可選的 ZAP、Agentic Radar 與 Garak；並保留 Prowler 實際失敗標題、核准的 AWS 發現合併、重新連接再掃描、受阻的繼續操作修正、Semgrep `1.184.0-1` 合併規則包，以及 kube-bench／KICS 的未完成涵蓋範圍揭露。
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
- [發布流程](releasing.zh-TW.md)與[本版發布紀錄](release/v0.6.2.md#繁體中文)
- [現行產品檢視](product-audit.md)與[掃描範圍](scanning-scope.zh-TW.md)

掃描只使用明確授權範圍；憑證不透過聊天或指令參數傳遞。版本、發布、簽章與包裝由產品負責人決定。

CI 文件與合約測試：91 項，新增既有映像與新建置候選分開記錄，以及禁止把可執行輸入藏在發布歷史中的檢查。引擎維護已補齊原先缺漏的實際檔案雜湊、六類下游修改的例外紀錄，並驗證全新 Gitleaks amd64 建置與遮蔽秘密值的合成掃描；新版 Gitleaks `8.30.1-2` 已發布，雙架構來源／SBOM 證據與匿名下載驗證通過，catalog 已固定使用新映像。

CI 文件與合約測試：97 項，包含上游更新候選的中繼資料檢查。10 月 14 日的原始碼更新保留既有已發布 catalog，另外驗證新版建置；候選資料不能變更掃描權限或隱藏可執行的建置輸入。版本與驗證詳見[上游更新紀錄](engines/updates/2026-10-14.md)。

CI 文件與合約測試：102 項，新增拒絕被替換的 Windows 執行環境來源、修補檔、工具鏈，以及不可重現建置設定的檢查。[Windows 執行環境來源紀錄（英文）](../runtime/podman-wsl-native-systemd.md)說明原生 systemd 回移修補與固定的建置輸入。
