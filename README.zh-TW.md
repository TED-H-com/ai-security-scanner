# ai-security-scanner

[專案網站](https://ted-h-com.github.io/ai-security-scanner/?lang=zh-TW) · [English](README.md) · [使用說明](docs/README.zh-TW.md) · [下載](https://github.com/TED-H-com/ai-security-scanner/releases) · [日本語](README.ja.md)

*本機優先的整合式資安評估工作台：選好要檢查的資產，就能拿到一份可追溯、能直接交付並照著處理的報告，不必自己管理整套掃描工具。*

檢查你的程式碼、網站與公司系統，把需要注意的安全問題整理成一份報告。你會知道哪裡有問題、為什麼重要，以及接下來可以怎麼做。

在桌面應用程式裡選好要檢查的項目，程式就會選用適合的安全工具，整理檢查結果。可以先從一個資料夾或網站開始，也可以一次檢查公司環境中的多個系統。

## 介面語言

v0.5.2 安裝版包含日文介面，可在 **設定 → 日本語** 選擇，重新啟動後仍會保留。未翻譯的說明會顯示英文；日文介面匯出的 HTML 報告目前使用英文。另有 [日文 README](README.ja.md) 與[日文網站](https://ted-h-com.github.io/ai-security-scanner/?lang=ja)。

## 完成第一次掃描

1. [下載 v0.5.2](https://github.com/TED-H-com/ai-security-scanner/releases/tag/v0.5.2)，依你的 Windows、macOS 或 Linux 電腦[完成安裝](docs/getting-started.zh-TW.md#安裝)。程式會準備掃描工具，不需要另外安裝 Docker。
2. 開啟程式，選擇**掃描公司環境**、**檢查網站**或**檢查程式碼或 AI 專案**，加入想檢查的資料夾、網址或內部系統。
3. 確認畫面列出的目標與檢查內容。網站及內部系統必須是你有權檢查的對象，再從應用程式視窗開始掃描。
4. 掃描結束後，打開**掃描結果**。按**保存或分享報告**，再儲存 **HTML 報告**，就能用瀏覽器閱讀。

第一次可能需要等候工具下載，之後可以重複使用。每個畫面的操作方式都在[開始使用](docs/getting-started.zh-TW.md#從開始新掃描到-html-報告)。

## v0.5.2 更新

- 更新十個掃描引擎，刷新離線弱點資料庫與 Kubernetes 政策。
- 更新 Steampipe AWS 外掛，修正 Checkov 相依套件一致性與 Grype 資料庫大小檢查。
- 修正新版 WSL 上 Windows 掃描工具的啟動與閒置穩定性，維持記憶體限制。
- 保留日文介面與既有安裝的應用程式更新相容性。

[查看 v0.5.2 更新](docs/release/v0.5.2.zh-TW.md)。

## v0.5.1 更新

- 安裝版加入日文介面，可從 **設定 → 日本語** 切換，重新啟動後仍會保留。
- 新增日文 README 與網站，涵蓋全部 25 個掃描工具介紹。
- 納入 [@kieiken](https://github.com/kieiken) 的 [#69](https://github.com/TED-H-com/ai-security-scanner/pull/69)，並補齊首頁與掃描環境準備的日文。

[查看 v0.5.1 更新](docs/release/v0.5.1.zh-TW.md)。

## v0.5.0 更新

- 相關發現合併成一張問題卡，展開細節仍可查看原始證據。
- 用**確認修復**重新選取修改後的資料夾，比對這次沒有再看到、仍然存在與新增的問題，也能看出部分修復的情況。
- 改善雲端說明、進度與工具版本資訊，補齊中英文指南及[真實修復前後範例](https://ted-h-com.github.io/ai-security-scanner/check-fixes-demo.html?lang=zh-TW)。

本版收納 v0.4.1 之後所有已完成更新，並包含 Linux 建置與依賴安全修正。[查看完整更新](docs/release/v0.5.0.zh-TW.md)。

## 可以檢查什麼？

| 你想檢查的東西 | 可以了解的問題 |
| --- | --- |
| 程式碼資料夾，包括 AI 專案 | 支援的檔案中，是否留下密碼或金鑰、使用有已知漏洞的套件，或有危險寫法與不安全設定。程式會複製檔案來檢查，不會執行或修改你的專案。 |
| 網站與 API | 核准範圍內的網站是否有已知漏洞，或暴露了不該公開的資訊。開始前會列出檢查的網址範圍與限制。 |
| 公司內部系統 | 指定主機與連接埠提供哪些服務，以及適用的安全檢查發現了什麼。連接埠開著，本身不代表有漏洞。 |
| 雲端帳號與 Microsoft 365 | 支援的帳號與權限檢查發現了什麼。目前 AWS、Azure、GCP 只檢查部分身分與權限設定，還不能代表整個雲端環境的安全狀況。 |
| 部署設定、容器與 Kubernetes | 支援的設定檔或容器內容，是否使用有已知漏洞的套件，或有不安全設定。可執行的檢查會依提供的資料而定。 |

進階 AI 選項可以整理支援的工作流程、檢查 MCP 設定，或測試一個你核准的模型服務。模型測試會送出 54 個固定提示，可能產生服務商費用；開始前會讓你確認。詳細內容見[掃描範圍](docs/scanning-scope.zh-TW.md)。

## 看完報告，知道下一步

先看需要優先處理的問題。每一項都會說明影響哪個系統或檔案、為什麼值得注意，以及可以先做什麼。負責調查或修正的人，也能展開技術細節，查看掃描工具原本的證據、評級與建議。

報告同時列出已檢查與未檢查的項目。某項檢查失敗，其他結果仍會保留。「沒有發現問題」只代表完成的檢查沒有找到問題，不代表所有風險都已排除。程式會提供修正建議，不會自行更改你的系統。

報告可以重新開啟、比較相容的前後兩次掃描，也能存成英文或繁體中文 HTML 分享。未遮蔽的匯出可在報告最後附上原始掃描報告 ZIP。詳見[閱讀與分享結果](docs/results-and-exports.zh-TW.md)。

### 先看看報告長什麼樣

[打開範例報告](https://ted-h-com.github.io/ai-security-scanner/samples/v0.4.0/sample-report-redacted-zh-TW.html)，或[選擇其他語言與顯示方式](https://ted-h-com.github.io/ai-security-scanner/sample-reports.html?lang=zh-TW)。

範例使用模擬資料，包含 25 個工具的 62 筆發現與 42 筆盤點紀錄。它用來展示報告，不代表任何真實公司的安全狀況。盤點紀錄會另外列出，不算成安全問題。[範例製作方式](docs/samples/v0.4.0/README.zh-TW.md)。

想看真實掃描，請看[修正專案後再檢查一次](https://ted-h-com.github.io/ai-security-scanner/check-fixes-demo.html?lang=zh-TW)：修正前 13 個問題、修正後 8 個，以及兩次之間的變化。

## 請 Claude Code 或 Codex 幫忙

在同一台電腦上的 AI 助手，可以協助安裝、確認設定、解讀結果與儲存報告。你負責選好目標，並在桌面應用程式裡開始、暫停或繼續掃描。

在 AI 助手中開啟這個專案，告訴它：

> 使用 ai-security-scanner skill，幫我安裝程式、引導我完成第一次掃描，並存下最後的 HTML 報告。

這裡有 [Claude Code 指引](.claude/skills/ai-security-scanner/SKILL.md)與 [Codex 指引](.codex/skills/ai-security-scanner/SKILL.md)。如果助手在另一台機器上，它可以提供操作說明與下載連結，無法直接替你的電腦安裝。[查看使用方式](docs/getting-started.zh-TW.md#透過-agent-skill-使用)。

## 資料放在哪裡？權限會留下嗎？

專案、檢查結果與證據存放在你的電腦。本機程式碼檢查不會上傳或執行專案；網站與雲端檢查會連到你核准的服務。儲存 HTML 報告只會建立本機檔案，是否分享由你決定。

雲端登入與雲端權限是兩件事。登入可能已經過期，但設定時建立的權限仍然存在。Microsoft 365 有可選用的[清理 script](cloud-setup/README.md)：等指定掃描結束、存下報告，再撤除紀錄中的設定變更。AWS 也新增了[掃描專用存取與清理](cloud-setup/README.md#aws-專用存取與清理)。執行時須保持清理視窗開啟；管理員登入過期時可能需要重新登入。這些還不是桌面程式的預設動作，也不會一併撤除缺少建立紀錄的舊 AWS 或 Azure 權限。

## 報告背後有哪些工具？

程式整合了 25 個開源工具。各工具負責原本的安全檢查，程式再整理結果、說明處理順序。想了解用途、限制與版本，可以閱讀[工具指南](https://ted-h-com.github.io/ai-security-scanner/scanner-guide.html?lang=zh-TW)。

<details>
<summary>這 25 個工具各自在做什麼</summary>

### 程式碼專案、相依套件與基礎設施即程式碼

**[Semgrep](https://github.com/semgrep/semgrep)** — Semgrep 是一套廣泛使用的開源靜態應用程式安全測試（SAST）工具，也就是不編譯、不執行專案，直接檢查程式碼裡的安全問題。一般的文字搜尋只看字面，換行、空白不同或變數改名，都可能讓同一種寫法躲過去；Semgrep 則會把程式碼解析成語法樹（程式碼的結構），比對的是結構而不是字面。本程式使用的是社群版（Community Edition），追蹤不受信任資料流向的規則，只會在同一個函式內追蹤。我們把它放進本程式，是因為它能幫你很快找出有風險的寫法，例如不安全的指令呼叫，或直接拿使用者輸入組成的資料庫查詢；使用的是本程式內附的安全規則包，不是目前完整的規則庫。

**[Gitleaks](https://github.com/gitleaks/gitleaks)** — Gitleaks 是一套開源工具，也是最受歡迎且備受信任的密碼與金鑰掃描工具之一，用來找出寫死在專案檔案裡的密碼、API 金鑰、token 與其他憑證。它的規則認得許多已知金鑰的格式，有些規則還會參考附近的字詞，或字串看起來有多隨機。上游的 Gitleaks 也能搜尋儲存庫的 Git 歷史，就算金鑰後來刪掉了也找得到。我們把它放進本程式，是因為它能幫你很快找出你所選專案裡留下的密碼與金鑰。這裡只讀取目前檔案的唯讀副本，不搜尋已刪除的 Git 歷史，也不測試憑證是否仍然有效，報告也會遮蔽密碼與金鑰本身。

**[TruffleHog](https://github.com/trufflesecurity/trufflehog)** — TruffleHog 是一套開源工具，也是最受歡迎且備受信任的密碼與金鑰掃描工具之一，用來找出 API 金鑰、token 這類可能外洩的憑證。它為許多種憑證各準備了專屬的偵測器。上游的 TruffleHog 還能向對應的線上服務確認找到的金鑰是否有效，也能搜尋 Git 歷史。我們把它放進本程式，是因為它能幫你很快找出目前檔案裡的密碼與金鑰，偵測器也和 Gitleaks 互補。這裡會關閉網路，只讀取這些檔案的唯讀副本，不搜尋 Git 歷史，也不拿憑證去線上服務測試。找到結果不代表金鑰仍然有效，報告也不會放上金鑰內容。

**[Trivy](https://github.com/aquasecurity/trivy)** — Trivy 來自 Aqua Security，是一套開源的資安掃描工具，也是最受歡迎且備受信任的套件弱點掃描工具之一。它會讀取認得出的相依套件檔，以及 JAR 這類個別的 Java 套件檔，再把版本拿去和漏洞資料庫裡的公開公告比對；這些公告通常是 CVE，也就是已知漏洞的標準編號。上游的 Trivy 還能檢查設定與密碼金鑰。我們把它放進本程式，是因為它能幫你很快找出已知有漏洞的套件；資料庫列有修正版本時，也會一併告訴你。這裡只執行漏洞檢查，使用本程式內附的資料庫。檢查容器映像時只看作業系統套件，映像裡的應用程式函式庫交給 Grype 檢查。

**[Grype](https://github.com/anchore/grype)** — Grype 來自 Anchore，是一套廣泛使用的開源工具，用來把軟體套件對上已知漏洞。它拿套件名稱與版本去比對漏洞資料庫，回報對應的公告，例如 CVE（已知漏洞的標準編號）或 GitHub 安全公告；資料庫若列有修正版本，也會一併呈現。我們把它放進本程式，是因為它能幫你很快找出所選專案或容器映像裡已知有漏洞的套件；檢查映像時，應用程式函式庫和作業系統套件都包含在內。即使 Trivy 也回報同一個問題，報告仍會標明各是哪個工具找到的。這裡使用本程式內附的資料庫，不會自己從 registry 下載映像，也不會執行容器。

**[Checkov](https://github.com/bridgecrewio/checkov)** — Checkov 是一套廣泛使用的開源工具，專門檢查基礎設施即程式碼（IaC），也就是描述雲端資源與部署該怎麼設定的檔案。它把這些檔案讀成資源以及資源之間的關係，而不是一段純文字，再用一套安全政策逐一檢查。我們把它放進本程式，是因為它能幫你在真正部署之前，很快找出 Terraform、CloudFormation 與 Dockerfile 等檔案裡不安全的設定。這裡只讀取你所選專案的唯讀副本，不連接雲端帳號、不下載平台政策資料，也不套用這些檔案，所以結果描述的是檔案本身，不是線上環境實際的狀態。

**[KICS](https://github.com/Checkmarx/kics)** — KICS（Keeping Infrastructure as Code Secure）來自 Checkmarx，是一套開源工具，用來找出基礎設施即程式碼（IaC）裡不安全的設定；IaC 就是描述系統要怎麼部署的檔案。它用一套安全查詢檢查 Terraform、CloudFormation、Kubernetes 設定檔與 Dockerfile 等格式，並把每筆結果對應到檔案與行號；內附的查詢也會找出檔案裡留下的密碼與金鑰。我們把它放進本程式，是因為它能幫你很快找出有風險的部署設定，查詢庫和 Checkov 各自獨立，能提供第二種觀點。這裡用工具內附的查詢掃描你所選專案的唯讀副本，不連接雲端帳號，也不另外下載查詢。

**[Syft](https://github.com/anchore/syft)** — Syft 來自 Anchore，是一套廣泛使用的開源工具，用來建立軟體物料清單（SBOM），也就是列出專案或容器映像裡有哪些軟體元件的清單，例如函式庫與作業系統套件。它會記下每個認得出的元件名稱、版本與類型。我們把它放進本程式，是因為它能幫你很快看清所選專案或映像裡有哪些軟體，也就知道漏洞檢查看的是哪些東西。這份清單只說明有什麼，不是漏洞報告。這裡只讀取唯讀副本、不連網路，也不會從 registry 下載映像；已知漏洞交給 Trivy 與 Grype 檢查。

本版目錄將 Grype 映像固定為 **`0.117.0-4`**，digest 為 `sha256:56b0d675…`，可檢查本機專案相依套件的已知弱點；受控專案掃描曾記錄 **81 筆 Grype 問題**。這是測試專案的實測結果，各專案筆數會不同。詳見[完整釘選與實測紀錄](docs/engine-catalog.md#grype-repository-support)。

### 網站與內部系統

**[Nuclei](https://github.com/projectdiscovery/nuclei)** · [Nuclei Templates](https://github.com/projectdiscovery/nuclei-templates) — Nuclei 是 ProjectDiscovery 維護的開源弱點掃描工具，也是同類工具中最受歡迎且備受信任的工具之一。它的每一項檢查都是一份範本：寫好的請求，加上代表已知曝露或漏洞的回應特徵。它會先辨識網站用了哪些技術，再挑出適合的範本。我們把它放進本程式，是因為它能幫你很快找出這些已知問題；它是預設的網站檢查，使用本程式內附的範本。它只對一個核准的網站位址送出唯讀請求，不登入、不送出表單、不做模糊測試或漏洞利用、不操作瀏覽器，也不請外部伺服器回撥。你輸入的路徑不會把檢查範圍縮小到那個路徑。

**[ZAP](https://github.com/zaproxy/zaproxy)** — ZAP（Zed Attack Proxy，也就是大家熟悉的 OWASP ZAP）是開源的網站應用程式安全掃描工具，也是同類工具中最受歡迎且備受信任的工具之一。上游的 ZAP 可以站在瀏覽器與網站之間、爬取頁面、檢查每一個回應，也能主動送出攻擊內容。它的被動規則只讀取回應，包括標頭與 cookie，不發動攻擊。我們把它放進本程式，是因為這些被動規則能幫你在它走得到的頁面上，找出缺少安全標頭、cookie 設定不安全這類問題，和 Nuclei 互補。在本程式裡它是選用的：只在固定限制內爬一個核准的網站，不登入、不送出表單、不送攻擊內容，也不跟著連結到其他網站。預設的網站檢查仍是 Nuclei。

**[Greenbone OpenVAS Scanner](https://github.com/greenbone/openvas-scanner)** — Greenbone OpenVAS 是 Greenbone 維護的開源網路弱點掃描工具。它使用一份固定版本的 Greenbone Community Feed 來做弱點測試；Community Feed 是 Greenbone 另外維護的檢查項目庫。它會先辨識連接埠上跑的是什麼服務，再執行適用的測試。我們把它放進本程式，是因為它能幫你找出內部設備與伺服器上、光靠連線看不出來的已知安全問題。這裡只測試你核准的主機與連接埠，不登入、不進到主機內部檢查、不猜密碼、不試預設帳號，也不做可能中斷或壓垮服務的檢查。辨識不出服務時，這些測試就不會執行，報告會把該主機列為未測試。

**[Naabu](https://github.com/projectdiscovery/naabu)** — Naabu 是 ProjectDiscovery 維護的開源連接埠探索工具，用來找出哪些 TCP 連接埠正在接受連線。TCP 連接埠就是網路服務等候連線時使用的編號。它的連線掃描會對每個位址與連接埠嘗試一次一般的 TCP 連線，連得上就代表連接埠是開的；上游另外還有其他探索方式。我們把它放進本程式，是因為它能幫你很快看出哪些核准的服務正在等候連線，讓接下來的安全檢查有明確的對象。這裡只連你核准的位址與連接埠，不會把附近的主機加進來，也不掃描 UDP（另一種常見的服務連線方式）。開著的連接埠會記在盤點裡，本身不是漏洞。

**[httpx](https://github.com/projectdiscovery/httpx)** — httpx 是 ProjectDiscovery 維護的開源網站探測工具，和 Python 裡同名的 HTTPX 程式庫不是同一個東西。它會對一個位址送出一般的網頁（HTTP）請求，記下有沒有網站服務回應、回傳的狀態碼，以及其他基本的回應資訊；這些都是只看連接埠開不開無法得知的。我們把它放進本程式，是因為它能幫你在真正的安全檢查開始前，很快確認核准的網站服務是否有在回應。上游還能做更多種探測，這裡只詢問你核准的那一個服務，不爬網站、不登入，也不開啟所有上游探測。結果是描述這個服務的盤點資料，本身不代表有漏洞。

### 雲端與 Microsoft 365

**[Prowler](https://github.com/prowler-cloud/prowler)** — Prowler 是一款廣泛使用的開源雲端安全評估工具。它呼叫雲端服務商的 API、執行內建檢查，並記下檢查名稱、受影響的資源、哪裡不符合，以及怎麼修正。上游的 Prowler 能涵蓋許多服務與合規框架。我們把它放進本程式，是因為它能幫你很快找出需要注意的身分與權限設定。這裡每次只對一個核准資產執行範圍很窄的身分與存取管理（IAM）檢查：一個 AWS 帳號的 IAM 服務、一個 Azure 訂用帳戶的 IAM 服務，或一個 GCP 專案的四項指定 IAM 檢查。其他服務與帳號不在這次檢查範圍內，單一檢查通過也不代表取得認證。

**[ScoutSuite](https://github.com/nccgroup/ScoutSuite)** — ScoutSuite 來自 NCC Group，是一款廣泛使用的開源工具。它透過雲端服務商的 API 讀取設定，用自己的規則標出有風險的設定，每筆結果都保留規則、受影響的項目，以及值得檢視的原因。上游的 ScoutSuite 支援多家雲端服務商，也有自己的報告。我們把它放進本程式，是因為它能幫你很快找出值得再看一眼的 AWS 身分與存取設定，也能和 Prowler 互相對照。這裡只對一個核准帳號執行 AWS 身分與存取管理（IAM）規則，其他雲端服務商與其他 AWS 服務都不在範圍內。設定要被規則標出才會成為報告裡的問題，只是收集到設定並不代表有弱點。

**[Cloudsplaining](https://github.com/salesforce/cloudsplaining)** — Cloudsplaining 來自 Salesforce，是一款開源工具，專門檢查 AWS 身分與存取管理（IAM）政策是否給了超過工作所需的權限，也就是有沒有違反「最小權限」原則。它讀取帳號的授權細節，找出沒有限定資源範圍的動作，再把有風險的動作分成權限提升、資料外洩、資源曝露與更動基礎設施等類別，並指出是哪一份政策、哪些動作。我們把它放進本程式，是因為它能幫你很快找出過寬的權限，看清該檢視哪些動作。這裡只分析一個核准的 AWS 帳號。被標出的動作是供你審閱的證據：它不判斷業務是否需要這項權限、不修改政策，也不能證明現在真的有人用得到。

**[CloudQuery](https://github.com/cloudquery/cloudquery)** — CloudQuery 是一款廣泛使用的開源工具，會把雲端服務商 API 提供的資料整理成結構化表格，方便你之後查詢與比對。它用來源外掛讀取雲端服務，再用目的地外掛寫下每一列資料，所以每次收集到的格式都一致。我們把它放進本程式，是因為它能幫你很快看清一個核准的 AWS 帳號裡有哪些身分與權限政策，讓安全檢查的結果更容易對照。這裡只收集一組固定的身分與存取管理（IAM）表格：帳號、使用者、群組、角色、政策、密碼政策與憑證報告。這些資料屬於盤點，只說明目前有什麼，會和安全問題分開列出，也不涵蓋所有 AWS 服務。

**[Steampipe](https://github.com/turbot/steampipe)** — Steampipe 由 Turbot 維護，是一款廣泛使用的開源工具，能把雲端 API 變成 SQL 資料表。SQL 是查詢資料庫的標準語言，而每個服務商外掛決定你能讀到哪些服務與欄位。我們把它放進本程式，是因為它能幫你很快列出一個核准 AWS 帳號裡的身分與存取管理（IAM）使用者，再拿這份名單對照安全檢查的結果。這裡只執行一個固定的 IAM 使用者查詢。查到的資料屬於盤點：只列出找到的使用者，不判斷哪個使用者有風險。本程式也不執行 Steampipe 現成的安全基準檢查，也不接受你自己寫的 SQL。

**[ScubaGear](https://github.com/cisagov/ScubaGear)** — ScubaGear 來自美國網路安全暨基礎設施安全局（CISA），是一款開源工具，會把 Microsoft 365 租戶（也就是組織的 Microsoft 365 環境）的設定，和 CISA 的 Secure Cloud Business Applications（SCuBA）基準比較；這些基準是以書面寫下的安全設定要求。上游也涵蓋其他 Microsoft 365 產品。我們把它放進本程式，是因為它能幫你很快找出不符合這份基準的 Microsoft Entra ID 設定；Entra ID 是租戶的登入與身分目錄。這裡只為一個已授權、位於 Microsoft 商業雲端的租戶檢查 Entra ID 基準，Exchange、SharePoint 與其他工作負載不在範圍內。通過不等於合規認證，沒能評估的項目也會照樣列出，不算通過。

**[Maester](https://github.com/maester365/maester)** — Maester 是一套開源的測試框架，用 PowerShell（Microsoft 的腳本語言）寫成，專門檢查 Microsoft 365 的安全設定。每一項測試都寫明安全的租戶應有的設定，並記錄你的租戶是否符合。我們把它放進本程式，是因為它能幫你很快找出不符合這些要求的 Microsoft Entra ID 設定；Entra ID 是租戶的登入與身分目錄。這裡對一個已授權的租戶執行一組固定的 Entra 測試，並略過耗時很長的測試、預覽測試，以及需要連到其他服務的測試；Exchange Online 和你自己提供的腳本都不在範圍內。被略過的測試絕不會顯示成通過，需要人來判斷的測試會列出來供你審閱。

### Kubernetes

**[Kubescape](https://github.com/kubescape/kubescape)** — Kubescape 是一套廣泛使用的開源工具，用來檢查 Kubernetes（許多團隊用來運行容器的系統）的設定。它把 YAML 與 JSON 檔案讀成 Kubernetes 資源，再對照一份固定的強化檢查清單，也就是根據美國 NSA 與 CISA 指引整理的 NSA 框架，所以每筆結果都會指出是哪個資源、哪一項控制沒有通過。上游的 Kubescape 也能掃描運作中的叢集與容器映像。我們把它放進本程式，是因為它能幫你很快找出所選 Kubernetes 設定檔裡有風險的設定。這裡只離線檢查那份已儲存的快照，不連到運作中的叢集，無法判斷檔案是否與實際部署一致，也不掃描容器套件。

**[kube-bench](https://github.com/aquasecurity/kube-bench)** — kube-bench 是 Aqua Security 維護、廣泛使用的開源工具，依照 CIS Kubernetes Benchmark 檢查 Kubernetes 節點，也就是實際運行工作負載的機器；CIS Benchmark 是網際網路安全中心（CIS）公開的安全設定檢查清單。它拿設定檔與執行中程序的資訊逐項比對，標成通過、失敗或警告；警告代表這項檢查需要自動化無法提供的資訊或判斷。上游的 kube-bench 會在運作中的節點上執行，也能檢查控制平面。我們把它放進本程式，是因為它能幫你很快找出不符合這份清單的節點設定。這裡只使用你匯出的節點資訊與節點檢查項目，不會登入運作中的主機，也不執行控制平面檢查。

### AI 工作流程與 MCP 設定

**[Agentic Radar](https://github.com/splx-ai/agentic-radar)** — Agentic Radar 是一套開源工具，會閱讀由 AI 代理組成的專案，整理出各個部分如何相連。你先選定一個受支援的框架（LangGraph、CrewAI、n8n、OpenAI Agents 或 AutoGen），它的解析器就會列出代理、工具、MCP 伺服器，以及它們之間的連線。MCP 伺服器是透過 Model Context Protocol 接上的外部工具，這個協定讓 AI 應用程式能呼叫其他工具。上游的 Agentic Radar 還有更廣的風險分析。我們把它放進本程式，是因為它能幫你在審閱之前，很快看懂一個 AI 代理專案裡有哪些元件。這裡只盤點一份已儲存的專案副本，不執行工作流程、不連線到模型，也不會回報安全問題。

**[Garak](https://github.com/NVIDIA/garak)** — Garak 是 NVIDIA 維護、廣泛使用的開源大型語言模型（LLM）弱點掃描工具。它送出稱為「探測」的特製提示，再用偵測器判斷模型的回覆。這裡使用的探測包括「Do Anything Now」這類試圖讓模型拋開自身規則的指示，以及試圖讓模型輸出終端機跳脫碼的提示；上游的 Garak 還有更多探測。我們把它放進本程式，是因為它能幫你很快看出一個核准的模型如何回應這組固定測試。這項選用檢查要由你自己啟動，只對一個核准、相容 OpenAI 格式的 HTTPS 聊天 API 與模型送出 54 個提示。沒有發現問題，也只代表這些提示沒有引出問題。服務商可能會收費；你輸入的 API 金鑰只用於這一次檢查，不會存進掃描紀錄或報告。

**[MCP Armor](https://github.com/aira-security/mcp-armor)** — MCP Armor 是一套開源工具，用來檢查 MCP 設定檔。MCP（Model Context Protocol）是 AI 應用程式連接外部工具的協定，設定檔則寫明要連哪些工具。它有兩項檢查直接讀取這個檔案：一項找出寫在檔案裡的金鑰等機密，另一項依上游規則標出範圍過大的工具指令與權限；比對到的機密內容不會寫進報告。上游的 MCP Armor 還能連上設定裡的伺服器，並執行需要模型的測試。我們把它放進本程式，是因為它能幫你很快找出你選定的那份設定裡外露的金鑰與過大的工具權限。這裡只讀取已儲存專案中的那一個檔案，不啟動也不連線任何 MCP 伺服器、不載入模型，也無法顯示運作中的伺服器實際執行的權限控管。

探索、盤點、SBOM 與 localhost TCP 連線工具會和弱點問題清楚分開。完整固定版本、授權、設定與執行界線記錄在[引擎目錄](docs/engine-catalog.md)。

完整掃描界線與設定行為請參閱[掃描範圍](docs/scanning-scope.zh-TW.md)。

仍在評估中的工具另行記錄，還不能用來掃描。


</details>

## 更多說明

- [開始使用](docs/getting-started.zh-TW.md)
- [掃描範圍](docs/scanning-scope.zh-TW.md)
- [閱讀與分享結果](docs/results-and-exports.zh-TW.md)
- [目前開發狀態](docs/development-status.zh-TW.md)
- [v0.5.2 更新](docs/release/v0.5.2.zh-TW.md) · [v0.5.1 更新](docs/release/v0.5.1.zh-TW.md) · [v0.5.0 更新](docs/release/v0.5.0.zh-TW.md) · [v0.3.1 更新](docs/release/v0.3.1.md)
- [參與開發](CONTRIBUTING.md) · [貢獻者](CONTRIBUTORS.md) · [安全政策](SECURITY.md)

## 開發

開發環境需要 Node.js 24 或更新版本、Rust 1.98，以及 Tauri 對應平台的相依套件。

```sh
npm ci
npm run typecheck
npm run test:frontend
npm run test:component
npm run build
cargo test --locked --workspace --no-default-features --features cli
npm run tauri dev
```

`npm run dev` 會開啟使用範例資料的瀏覽器預覽。桌面掃描由 Tauri 應用程式執行。

`npm run upstream:refresh -- --engine <id>` 會產生離線的 adapter 更新提案套件，再用 `npm run upstream:propose -- --bundle <path>` 重新驗證。預設走確定性的 `mechanical` 路徑；若要使用 AI，需明確指定 `--provider cli --ai-cli <executable>`。`--open-pr` 或 `--no-open-pr` 記錄變更是否應送回本儲存庫。這些指令只會印出供人執行的命令，本身不會執行。完整流程見[引擎維護](docs/engine-maintenance.md)。

## 授權

本專案自行撰寫的原始碼採用 [Apache-2.0](LICENSE) 授權。第三方引擎與資料保留各自的授權，詳見 [THIRD_PARTY.md](THIRD_PARTY.md)。
