# 引擎參考

[先看所有掃描器的用途、SWOT 與版本](../scanner-guide.zh-TW.md) · [下載標準範例報告](../samples/v0.4.0/README.zh-TW.md)

[English](README.md) · [文件](../README.zh-TW.md)

每個掃描器與共用 launcher 都有自己的維護頁，記錄產品如何執行、adapter 保留哪些上游結果、更新步驟，以及實際掃描學到的注意事項。修改前先閱讀該頁；有新的實測經驗時，在 **Lessons from real runs** 補上日期、症狀、原因與修正 commit。

建置或更新先從[映像檔建置與更新筆記](image-build-index.md)開始。它涵蓋全部 **25 個引擎紀錄**及 gateway，列出 build context、規則與資料準備、必須同步修改的檔案、patch 與已知限制。目前目錄整合 25 個可執行引擎，包含可選的 ZAP 被動網站檢查、Agentic Radar 離線工作流程盤點與受限的 Garak 模型檢查。

[引擎維護流程](../engine-maintenance.md)是維護規則；精確版本、digest 與 provenance 以 `engines/catalog.json` 和各引擎 `plan.json` 為準。現行原始碼可能與歷史映像檔不同，不能只看 Dockerfile 就宣稱已發布內容。[目前發布紀錄](updates/2026-10-14.md#verified-publication-and-catalog-activation)保留雙架構、合併規則包與來源的實際證據。

## 各類資產

| 資產 | 引擎與執行入口 |
| --- | --- |
| AWS；Prowler 另支援 Azure 與 GCP 的固定範圍 | [Prowler](prowler.md)、[ScoutSuite](scoutsuite.md)、[Cloudsplaining](cloudsplaining.md)、[Steampipe](steampipe.md)、[CloudQuery](cloudquery.md)；[雲端 launcher](cloud-launcher.md)。後兩者提供盤點。 |
| Microsoft 365 | [ScubaGear](scubagear.md)、[Maester](maester.md)；[M365 launcher](m365-launcher.md)。 |
| 網站與內部系統 | [Nuclei](nuclei.md)、[httpx](httpx.md)、[naabu](naabu.md)；[外部 launcher](external-launcher.md)。[Greenbone](greenbone.md)使用自己的 [launcher](greenbone-launcher.md)。 |
| 專案、相依套件、IaC 與映像檔 | [Semgrep](semgrep.md)、[TruffleHog](trufflehog.md)、[Trivy](trivy.md)、[Grype](grype.md)使用[本機 launcher](local-launcher.md)；另有 [Gitleaks](gitleaks.md)、[Checkov](checkov.md)、[KICS](kics.md)、[Syft](syft.md)。 |
| Kubernetes | [Kubescape](kubescape.md)、[kube-bench](kube-bench.md)；[本機 launcher](local-launcher.md)。 |
| MCP 設定 | [MCP Armor](mcp-armor.md)，只讀取已核准設定快照，不啟動 MCP 伺服器或模型。 |
| 新增於 main | [ZAP](zap.md) 被動網站檢查、[Agentic Radar](agentic-radar.md) 離線工作流程盤點。 |
| 模型端點 | [Garak](garak.md)，以精確 HTTPS／模型、一次性本機金鑰與固定原生探針執行。 |

需要接觸網路目標或服務商的引擎，只能透過 [egress gateway](egress-gateway.md)離開容器。

## 更新時要保留的紀錄

1. 確認上游版本、revision、image tag、digest、規則或資料版本，以及真正的建置來源。
2. 依維護頁修改 launcher、wrapper、Dockerfile 或 lock。相同上游輸出若會得到不同的 normalized output，遵循[共用 adapter 版本規則](../engine-maintenance.md#8-shared-adapter-contract-version)。
3. 負責人核准發布的映像檔才配置新的 immutable tag。共用 launcher 的消費者要同步更新來源紀錄，未重建的其他映像檔保留歷史事實。
4. 核對雙架構 smoke、publication manifest、匿名拉取與供應鏈驗證，再同步 catalog、plan、來源、輸入 hash 與現行文件。不要重寫歷史紀錄。
5. 用受控 fixture 或已核准目標確認產品執行，與上游原始輸出比對識別碼、嚴重度、證據、修正建議與完成狀態。記錄實際範圍與限制。

若只是替使用者安裝或執行掃描，依 AGENTS.md 使用已發布的桌面程式與 scanner skill。維護流程不會自行擴大掃描授權。
