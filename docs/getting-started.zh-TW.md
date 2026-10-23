# 開始使用

[English](getting-started.md) · [文件](README.zh-TW.md)

## 從開始新掃描到 HTML 報告

在應用程式中依以下路徑操作：

**開始新掃描 → 確認後開始 → 掃描進度 → 掃描結果 → 分享結果 → HTML 報告**

1. 在側欄選擇**開始新掃描**。依目標選擇**掃描公司環境**、**檢查網站**或**檢查程式碼或 AI 專案**。
2. 在表單加入目標，再按**檢查掃描內容**。本機專案的操作是：**選擇程式碼資料夾** → 選取資料夾 → **檢查掃描內容**。專案名稱可以留白。
3. 在**確認後開始**確認列出的目標與檢查項目，以及畫面顯示的範圍，再按**開始一次整合掃描**（單一網站或資料夾的按鈕是**確認並開始掃描**）。
4. 在**掃描進度**查看執行情況，工具準備也會顯示在這裡。等待這一輪結束或停止；即使個別檢查未完成，其他已完成結果仍會保留。
5. 在側欄選擇**掃描結果**。若有多筆已保存的掃描，先在**報告輪次**選擇要看的那一輪。查看受影響資產、優先問題與下一步，以及哪些項目未測試。
6. 按掃描結果上方的**保存或分享報告**。頂端路徑會變成**分享結果**。
7. 選擇 **HTML 報告（建議）**，保留**遮罩敏感識別資訊（建議）**的勾選，再按**儲存「HTML 報告」**。在存檔視窗選擇檔名與位置並儲存，用瀏覽器開啟保存的 `.html` 檔，即可閱讀或分享專業報告。

儲存的 HTML 使用應用程式語言：英文或繁體中文。CLI 匯出預設 `--locale en`；需要繁體中文時加上 `--locale zh-Hant`。掃描事實不變。

**確認後開始**、**掃描進度**與**分享結果**由上述操作開啟，側欄沒有獨立入口。儲存報告會產生本機檔案。

### 回到原本的掃描

從**我的掃描**選擇專案。工作仍在執行時，按**查看掃描進度**；已結束或停止時，選擇**掃描結果**，保存報告前確認**報告輪次**。若要重試未完成檢查，從掃描結果按**查看掃描工具狀態**。

若掃描進度提示計畫已保存但尚未開始檢查，選擇**繼續原本的範圍**接續執行，或按**開始新的掃描**建立新一輪。畫面提供**取消這一輪**時，可用它停止排隊中或執行中的工作。

報告內容的更多說明請見[結果與匯出](results-and-exports.zh-TW.md)。

AWS 或 Microsoft 365 的唯讀連線過期時，掃描結果會提供**重新連接後再掃描**。請在應用程式完成連接並保留核准範圍。相關 AWS 發現可能合併為同一個修正動作；展開技術細節可查看每筆原始發現。

## 安裝

從[發布頁](https://github.com/TED-H-com/ai-security-scanner/releases/tag/v0.5.3)下載適合你電腦的 **v0.5.3 正式版**：

| 電腦 | 安裝檔 | 第一次開啟前 |
| --- | --- | --- |
| macOS（Apple 晶片或 Intel） | [ai-security-scanner_0.5.3_universal.dmg](https://github.com/TED-H-com/ai-security-scanner/releases/download/v0.5.3/ai-security-scanner_0.5.3_universal.dmg) | 把應用程式拖進**應用程式**資料夾。此版本未經 Apple 公證，開啟前先在「終端機」執行一次 `xattr -dr com.apple.quarantine /Applications/ai-security-scanner.app`。 |
| Windows x86-64 | [ai-security-scanner_0.5.3_x64-setup.exe](https://github.com/TED-H-com/ai-security-scanner/releases/download/v0.5.3/ai-security-scanner_0.5.3_x64-setup.exe) 或 [MSI](https://github.com/TED-H-com/ai-security-scanner/releases/download/v0.5.3/ai-security-scanner_0.5.3_x64_en-US.msi) | 安裝檔未簽章。SmartScreen 警告時，選**其他資訊 → 仍要執行**。Windows 要求安裝或更新 WSL 時請允許。 |
| Debian 或 Ubuntu x86-64 | [ai-security-scanner_0.5.3_amd64.deb](https://github.com/TED-H-com/ai-security-scanner/releases/download/v0.5.3/ai-security-scanner_0.5.3_amd64.deb) | 以 `sudo apt install ./ai-security-scanner_0.5.3_amd64.deb` 安裝。 |

安裝完成後啟動 **ai-security-scanner**。第一次需要掃描時，應用程式會自行準備掃描環境，不需要另外安裝 Docker。

## 透過 Agent Skill 使用

掃描在你自己電腦上的桌面應用程式中執行，**開始**是應用程式視窗裡的按鈕。在同一台電腦上的 Agent 可以安裝應用程式、確認這台電腦能否掃描、引導你操作應用程式、解讀結果，並透過應用程式的 CLI 保存 HTML 報告。它安裝的是上方的發布版本，不需要建置本儲存庫。

在 **Claude Code** 或 **Codex** 開啟本儲存庫，使用其中的 `ai-security-scanner` skill：[Claude Code 指引](../.claude/skills/ai-security-scanner/SKILL.md) · [Codex 指引](../.codex/skills/ai-security-scanner/SKILL.md)。兩份內容相同。

可以這樣要求 Agent：

> 使用 ai-security-scanner skill 在這台電腦安裝應用程式、確認可以掃描、引導我完成一次掃描，並保存最終 HTML 報告。

Agent 必須和應用程式在同一台電腦上執行，並且能連網。沙箱擋住下載或應用程式時，它會請你允許那一個指令。雲端 Agent 無法在你的電腦上安裝任何東西，會直接提供安裝檔連結，不會反覆排錯。資料夾由你選定，網路目標也由你在應用程式中確認，Skill 不會代為授權。執行中的工作顯示於**掃描進度**，**掃描結果**與**分享結果**使用已結束或停止的掃描。

### 從原始碼建置

只有要修改產品時才需要建置。安裝 Node.js 24 或更新版本、Rust 1.98，以及 Tauri 的 Linux 開發相依套件後，用以下指令從本儲存庫建置並開啟應用程式：

```sh
npm ci
cargo build --locked --no-default-features --features cli --bin ai-security-scanner-cli
./target/debug/ai-security-scanner-cli doctor
npm run tauri dev
```

這些指令已在 Linux 實測。

目前 Grype 映像固定為 `0.117.0-4`（`sha256:56b0d675…`），已有本機專案弱點掃描結果。詳見[完整釘選與實測紀錄](engine-catalog.md#grype-repository-support)。

## 選擇第一次掃描

### IT 環境

需要把程式碼專案、網站與內部系統放進同一次評估時，在**開始新掃描**選擇**掃描公司環境**。

1. 加入一個或多個專案資料夾。
2. 加入完整的 `http://` 或 `https://` 網站網址。
3. 以精確主機名稱或 IP 位址加入每個已獲准的內部系統。預設檢查 22、23、25、80、443、445、3389、5900、8080 與 8443；進階設定可改為最多 64 個精確連接埠。
4. 按**檢查掃描內容**進入**確認後開始**，確認每個資產與網路界線。
5. 確認畫面列出的網路目標，選擇**開始一次整合掃描**。

每個掃描器只會收到分配給它的資產；所有已完成結果會集中在同一份報告。

### 網站

1. 選擇**檢查網站**。
2. 輸入一個完整網址，再按**檢查掃描內容**。
3. 在**確認後開始**確認精確 origin，選擇**確認並開始掃描**。

這個設定涵蓋畫面列出的 `scheme://host:port` origin。請在[掃描範圍](scanning-scope.zh-TW.md#網站或-api)查看請求行為。

### 專案資料夾

1. 在**開始新掃描**選擇**檢查程式碼或 AI 專案**。
2. 按**選擇程式碼資料夾**，選取本機資料夾。
3. 按**檢查掃描內容**。
4. 在**確認後開始**確認副本界線，選擇**確認並開始掃描**。

應用程式會掃描有界的唯讀副本，不會改動原始資料夾。

### v0.5.3 的可選檢查

本版提供以下明確選項：

- **ZAP：**在網站進階設定選擇被動網站檢查，確認精確 origin 與畫面所列限制。Nuclei 仍是快速預設。
- **Agentic Radar：**在儲存庫進階設定選擇 LangGraph、CrewAI、n8n、OpenAI Agents 或 AutoGen，離線盤點工作流程；Agent 與工具盤點會與安全問題分開呈現。
- **Garak：**在 AI 專案或 IT 環境的確認頁面，展開**可選的模型行為檢查**。填入完整的 HTTPS 聊天 API 網址與模型識別碼，再把 API 金鑰輸入專用密碼欄位。依實際情況勾選內部／本機網路，確認授權與服務商費用後按**開始模型檢查**。這會建立獨立的一輪，送出 54 個固定原生 DAN／ANSI 提示；金鑰只在本機保留最多 30 分鐘、派送時使用一次，再次嘗試需新金鑰與確認。

精確的請求與 token 限制請見[掃描範圍](scanning-scope.zh-TW.md#模型行為檢查)。模型金鑰只輸入應用程式，不放進聊天或指令參數。

### 雲端帳號

這會檢查一個 AWS 帳戶、Azure 訂用帳戶、Google Cloud 組織或 Microsoft 365 租用戶的身分與存取設定。如果你是這個帳號的擁有者或管理員，每一步都可以自己完成。

1. 在**開始新掃描**展開**更多檢查方式**，選擇**檢查雲端帳號**。
2. 選擇雲端服務，按**建立掃描專案**。
3. 在**掃描設定**按**開啟連線指南**，保留**以唯讀存取登入**。
4. 步驟 1 會列出在主控台設定一次唯讀存取的步驟，以及要選的權限集、角色或權限。帳號由別人管理時，展開**帳號由別人管理？**複製請求，再匯入對方寄回的設定檔。
5. 在步驟 2 填入步驟 1 要你複製的資料。這些都是公開識別碼；不要貼上密碼或秘密值。
6. 按**前往官方登入**，在雲端服務商自己的頁面登入；頁面要求時，輸入本程式顯示的一次性代碼。
7. 本程式顯示唯讀存取已驗證後，按**繼續：尋找雲端資產**，確認帳號，再按**掃描這個已登入帳號**。

AWS 和 Microsoft 365 可以用腳本完成步驟 1。腳本會以英文印出步驟 2 要填的資料，並存成設定檔。再執行一次只會補上缺少的部分，不會移除任何東西。

- **AWS：**在管理 IAM Identity Center 的帳號的 AWS 主控台開啟 CloudShell，執行：

  ```sh
  curl -fsSLO https://raw.githubusercontent.com/TED-H-com/ai-security-scanner/main/cloud-setup/aws-read-only.sh
  bash aws-read-only.sh
  ```

  啟用 IAM Identity Center 和新增登入用的使用者仍要在主控台完成；缺哪一步，腳本會直接說明。
- **Microsoft 365：**在 Windows 的 PowerShell 執行下列指令。打開腳本印出的 Microsoft 網頁，輸入它給的代碼，再以全域管理員身分登入。macOS 或 Linux 請改用 `pwsh`（PowerShell 7）執行腳本。

  ```powershell
  Invoke-WebRequest https://raw.githubusercontent.com/TED-H-com/ai-security-scanner/main/cloud-setup/microsoft365-read-only.ps1 -OutFile microsoft365-read-only.ps1 -UseBasicParsing
  powershell -ExecutionPolicy Bypass -File .\microsoft365-read-only.ps1
  ```

Google Cloud 需要組織（Google Workspace 或 Cloud Identity）；個人 Gmail 帳號底下的專案無法掃描。

如果雲端服務商因為存取權限可以修改帳號，或缺少某個權限而拒絕登入，面板會指出原因與修正方式。到主控台修正存取權限後再登入一次。

不想保留長期唯讀存取的管理員，可以選擇**讓本程式建立暫時存取**。本程式會建立獨立的唯讀身分，一小時內到期；掃描結束後，選擇**只移除這次設定建立的內容**。精確權限請見[雲端服務商授權](provider-authorization.md)（英文）。

開始後，依[取得 HTML 報告的步驟](#從開始新掃描到-html-報告)繼續操作。
