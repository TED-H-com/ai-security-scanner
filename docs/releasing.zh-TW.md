# 發布流程

[English](releasing.md) · [文件](README.zh-TW.md)

產品負責人選擇版本、channel、source commit、支援的安裝檔與發布時間。自動化流程會針對同一個決定完成建置、平台驗證、凍結、重新驗證、attestation 與發布。

## 目前發布版本

[v0.5.1](https://github.com/TED-H-com/ai-security-scanner/releases/tag/v0.5.1) 是目前的 **stable／latest** 桌面版本，於 2026-10-12 發布，涵蓋 **Linux、macOS、Windows**，新增日文介面。[候選 38280286730](https://github.com/teddashh/ai-security-scanner/actions/runs/38280286730) 建置精確來源 `0405fecbf3435d16da176fc5be2ab14fcb4c962f`；[發布流程 38286089269](https://github.com/teddashh/ai-security-scanner/actions/runs/38286089269) 經正常 `release-publication` 核准後直接發布凍結檔案。全部 49 個公開檔案均符合凍結檢查碼，來源證明與更新簽章也驗證通過。見[交付紀錄](release/v0.5.1.zh-TW.md)。

GitHub 記錄 `prerelease: false`；metadata 記錄 `releaseChannel: stable`、`stableTarget: 0.5.1`。macOS 與 Windows NSIS 有更新目標，Debian 與 MSI 沒有。Windows 安裝檔未簽章，macOS 未公證；Windows 生命週期／資料保留與精確候選新手真人操作仍未觀察，macOS qualification 主機也未觀察 managed runtime 執行。不提供 AppImage 與 RPM。

前一個正式版 [v0.5.0](release/v0.5.0.zh-TW.md) 與更早版本保留原始檔案及觀察。

## 版本身分

每個 `latest.json` 更新檔案 URL 都必須使用 `https://github.com/teddashh/ai-security-scanner/releases/download/v<version>/<file>`，以支援 <= 0.5.1 的既有安裝；GitHub 會將此舊路徑重新導向目前的儲存庫，且絕不可重新建立 `teddashh/ai-security-scanner`。

`package.json`、`package-lock.json`、`src-tauri/tauri.conf.json`、Rust package 與 release-owned runtime manifests 使用同一個 numeric SemVer。每個公開版本使用新的 immutable `vX.Y.Z` tag。

`package.json` 另外記錄：

- `release.channel`：`prerelease` 或 `stable`；
- `release.target`：prerelease 必須低於預定正式版本；stable 必須等於本版版本號。

## 準備 main

1. 完成 release notes 與現行文件。
2. 執行變更範圍要求的 repository validation、frontend、component、Rust、build、release-policy 與 release-evidence suites。
3. Commit 一致的版本與 channel 更新。
4. 把精確 candidate commit 推到 protected `main`。

## 建置與 platform qualification，不執行公開發布

產品負責人要求 QC 建置時，**Release desktop installers** 使用：

- `public_release_candidate: false`：只完成 commit-bound QC artifacts，不發布任何內容；
- 僅在負責人要求 Windows N-1 upgrade 與 ambiguous-runtime recovery fixtures 時使用選用的 `windows_data_preservation` 輸入。v0.3.0 紀錄仍標示未觀察這些項目。

Workflow 定義以下四條 qualification 路徑，各路徑最終可記為 `not-offered`。實際提供哪些安裝檔，應以該次 run 的 metadata 判定，不可只看路徑清單。

| Qualification | Runner | 安裝檔 |
| --- | --- | --- |
| Linux x86-64 | Ubuntu 24.04 | Debian package |
| macOS Universal | macOS 15 Intel | DMG application |
| Windows x86-64 | Windows Server 2025 | MSI |
| Windows x86-64 | Windows Server 2025 | NSIS installer |

各 lane 如實記錄觀察到的安裝、application 與 companion layout、桌面啟動、支援的 managed-runtime operations、runtime／container evidence，以及測試狀態移除。JSON qualification record 將這些觀察綁定 version、source commit 與 artifact digest。安裝檔檢查通過不代表已觀察 runtime 執行或 Windows lifecycle；本次 macOS／Windows 限制已列於上方。

Finalized QC 集合記錄所提供的 artifacts 及其 qualification evidence、checksums、runtime manifests、notices、SBOM 與限制。Workflow summary 識別 run、artifact 與 source commit；finalization 不會發布任何內容。

## 發布 public candidate

公開發布由產品負責人另外決定。負責人授權後，從 `main` 以 `public_release_candidate: true` 執行 **Release desktop installers**；**Promote frozen desktop release candidate** 再使用該 run summary 中的五個值：

- candidate run ID；
- candidate run attempt；
- candidate artifact ID；
- candidate artifact SHA-256；
- exact source commit。

使用 Windows external-evidence bundle 時，四個 evidence 欄位必須一起填寫；不使用時全部留空。

Promotion workflow 會重新驗證 candidate lock 與 checksums，在不重新建置的情況下組合公開檔案，建立 build-provenance attestations，並進入 `release-publication` environment 等待核准。核准後會把同一批檔案發布到 immutable version tag。Stable channel 會成為 latest release；prerelease channel 會標示為 prerelease。

## 確認發布內容

GitHub Release 應包含選定的安裝檔、`SHA256SUMS.txt`、release index、runtime manifests、SBOMs、notices、release notes 與 platform qualification records。Published tag 與 source commit 必須和 frozen candidate summary 完全一致。

安裝版產品驗收依[開始使用](getting-started.zh-TW.md)完成新手路徑。
