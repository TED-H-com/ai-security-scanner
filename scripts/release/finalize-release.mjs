import { copyFile, lstat, mkdir, readdir, readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  PROJECT_ROOT,
  assertSafeRelativePath,
  isSemver,
  parseArgs,
  readJson,
  requireString,
  runMain,
  sha256File,
  toPosix,
  writeJsonAtomic,
  writeTextAtomic,
} from "./lib.mjs";
import { verifyUpdaterSignatures } from "./verify-updater-signatures.mjs";
import { updaterLayoutsFor } from "./updater-layout.mjs";
import { verifyPlatformQualificationFile } from "./platform-qualification.mjs";
import { verifyBoundArtifactEvidenceFile } from "./artifact-evidence.mjs";
import { verifyWindowsNsisSupportingDataPreservationEvidence } from "./windows-data-preservation-evidence.mjs";
import { RELEASE_CANDIDATE_LOCK_FILE } from "./release-candidate-lock.mjs";
import {
  WINDOWS_EXTERNAL_EVIDENCE_RECEIPT_FILE,
  WINDOWS_UNSIGNED_SIGNING_OBSERVATION_FILE,
  verifyFinalizedWindowsExternalEvidenceOutcomes,
  verifyMaterializedWindowsExternalEvidence,
  windowsExternalEvidenceImporterIdentity,
} from "./windows-external-evidence.mjs";
import {
  platformContract,
  provenanceForArtifact,
  validateReleaseMetadataV3,
} from "./release-metadata.mjs";
import { publishedReleaseAssetName } from "./release-asset-name.mjs";
import { UPDATER_DOWNLOAD_REPOSITORY } from "../publication-origins.mjs";

const PUBLICATION_MODES = new Set(["commit-bound-qc", "public-github-release"]);

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

function expectedExternalEvidenceImporter(args) {
  const workflowRef = requireString(args, "external-evidence-workflow-ref");
  const separator = workflowRef.lastIndexOf("@");
  assert(separator > 0, "external-evidence workflow ref must end in its full workflow SHA");
  const workflowSha = workflowRef.slice(separator + 1);
  const importer = windowsExternalEvidenceImporterIdentity({
    repository: requireString(args, "external-evidence-repository"),
    workflow: requireString(args, "external-evidence-workflow"),
    workflowSha,
    runId: requireString(args, "external-evidence-run-id"),
    runAttempt: requireString(args, "external-evidence-run-attempt"),
    job: requireString(args, "external-evidence-job"),
    environment: requireString(args, "external-evidence-environment"),
  });
  assert(importer.workflowRef === workflowRef, "external-evidence workflow ref is inconsistent");
  return importer;
}

const EXTERNAL_EVIDENCE_IMPORTER_ARGUMENTS = Object.freeze([
  "external-evidence-repository",
  "external-evidence-workflow",
  "external-evidence-workflow-ref",
  "external-evidence-run-id",
  "external-evidence-run-attempt",
  "external-evidence-job",
  "external-evidence-environment",
]);

function externalEvidenceImporterForInput(args, hasReceipt) {
  const supplied = EXTERNAL_EVIDENCE_IMPORTER_ARGUMENTS.filter((key) => args.has(key));
  assert(
    supplied.length === 0 || supplied.length === EXTERNAL_EVIDENCE_IMPORTER_ARGUMENTS.length,
    "external-evidence importer arguments must be supplied as one complete set",
  );
  assert(
    hasReceipt === (supplied.length === EXTERNAL_EVIDENCE_IMPORTER_ARGUMENTS.length),
    hasReceipt
      ? "protected external-evidence receipt requires its exact importer arguments"
      : "external-evidence importer arguments were supplied without a protected receipt",
  );
  return hasReceipt ? expectedExternalEvidenceImporter(args) : null;
}

const RELEASE_COPY = new Map([
  [
    "0.1.8",
    {
      updaterNotes:
        "Keeps old or uncertain scan-tool workspaces untouched, prepares a fresh isolated workspace automatically, and gets the first useful local scan moving without a manual cleanup detour.",
      releaseNotes: [
        "> **Faster first scan, safer automatic recovery.** This build keeps internal runtime details",
        "> out of the beginner path and favors an isolated, reversible recovery when old state is unclear.",
        "",
        "On first launch, product-owned disposable state is reconciled automatically. Old state whose",
        "ownership is uncertain is left untouched while the app creates a uniquely named isolated",
        "workspace and continues. Nothing unfamiliar is deleted just to make the scanner start.",
        "",
        "The app opens the selected task immediately, keeps recovery in the background, and reports",
        "tested, not tested, failed, and incomplete coverage separately instead of turning one optional",
        "component failure into an all-or-nothing result.",
        "",
        "Existing local cases, cleanup obligations, evidence snapshots, and provenance remain intact.",
        "The app still waits for an explicit Start action before contacting a scan target.",
        "",
      ],
    },
  ],
  [
    "0.1.9",
    {
      updaterNotes:
        "Public testing update with safer runtime recovery, clearer partial-coverage reporting, bilingual finding guidance, and accessibility improvements. Existing local cases and historical provenance remain intact.",
      releaseNotes: [
        "> **A clearer, safer public testing build.** This prerelease improves automatic runtime",
        "> recovery, evidence-backed finding explanations, and honest incomplete-coverage reporting.",
        "",
        "Findings now retain the engine facts used to compose their summary, impact, priority, and",
        "next step. English and Traditional Chinese reports explain tested dimensions, limitations,",
        "warnings, control relationships, and verification outcomes without turning unknown or failed",
        "work into a clean result.",
        "",
        "Related observations from different engines are grouped reversibly, source attribution stays",
        "visible, and identifiers that could not be attributed are withheld from redacted exports.",
        "The interface also improves responsive layout, keyboard focus, readable text, and motion",
        "preferences.",
        "",
        "Verified product-owned runtime material can recover from its digest-anchored packaged cache.",
        "Ambiguous or unrelated state remains untouched, and optional engine failures remain scoped to",
        "their affected tasks. Existing projects, evidence, cleanup obligations, and signer history are",
        "preserved.",
        "",
        "For Windows installed-app testing, use the exact published installer bytes and follow the",
        "[external qualification plan](https://github.com/TED-H-com/ai-security-scanner/blob/v0.1.9/docs/release/windows-external-qualification-plan.md).",
        "",
      ],
    },
  ],
  [
    "0.1.10",
    {
      updaterNotes:
        "A focused IT-environment scan, direct progress states, terminal unified reports, and concise English and Traditional Chinese guidance.",
      releaseNotes: [
        "> **One scan. One report. Clear next actions.**",
        "",
        "ai-security-scanner 0.1.10 centers the desktop experience on three direct starting points:",
        "one IT environment, one website, or one project folder.",
        "",
        "An IT-environment scan can combine repositories, websites, and exact approved internal",
        "systems. Applicable upstream scanners receive only their assigned assets, while completed",
        "sibling outcomes stay together in one terminal report.",
        "",
        "Progress now presents current work, confirmed problem counts, completed checks, remaining",
        "checks, and attention-needed assets. Results lead with affected assets, priority, impact,",
        "next actions, verification guidance, and per-asset coverage. Technical evidence remains",
        "available on demand, and readable HTML follows the same report order.",
        "",
        "The English and Traditional Chinese documentation now follows the complete path from",
        "installation and target selection through scanning, results, export, and release operations.",
        "",
      ],
    },
  ],
  [
    "0.2.0",
    {
      updaterNotes:
        "Clearer honest reports, client-controlled upstream refresh proposals, hash-gated engine inputs, and new MCP Armor, agentic radar, and garak coverage.",
      releaseNotes: [
        "> **More honest reports, controlled refreshes, and broader evidence.**",
        "",
        "ai-security-scanner 0.2.0 rewrites the report layer for honesty and readability. Every",
        "severity stays visible, including zeros, while zero and unmeasured values remain distinct.",
        "A check without a verdict is no longer called untested, and a connection test is named as",
        "not a scan in both languages.",
        "",
        "Tables are captioned and each header says what it heads. Evidence records carry what the",
        "scanner actually reported, and the Chinese report uses complete Chinese sentences rather",
        "than translated fragments.",
        "",
        "The product can now propose upstream adapter refreshes. The client decides whether a",
        "refresh becomes a pull request back to main, and a refresh never claims more than was",
        "actually checked. Every engine build input is gated on a recorded hash.",
        "",
        "New coverage includes MCP Armor static configuration results, agentic radar workflow",
        "inventory, and garak probe results read without inventing a severity.",
        "",
      ],
    },
  ],
  [
    "0.3.0",
    {
      updaterNotes:
        "Public test build for Windows, macOS, and Linux with refreshed website and internal-system scanners. Existing local cases and historical provenance remain intact.",
      releaseNotes: [
        "> **A public test build for Windows, macOS, and Linux.**",
        "",
        "ai-security-scanner 0.3.0 is a pre-release for trying the whole path on your own computer:",
        "choose project folders, websites, and approved internal systems, start one scan, and read",
        "one report organized by asset.",
        "",
        "Website and internal-system checks run on refreshed Nuclei, httpx, and naabu images. The",
        "managed egress gateway now waits instead of refusing a connection over the rate limit,",
        "answers a denied destination instead of closing silently, and records what it refused, so",
        "the report names a check it cut short.",
        "",
        "Internal-system checks now finish: Greenbone gets the processor time its scanner needs,",
        "no longer stalls on a service that closes its connection, and reports a host where it",
        "identified no service on the approved ports as not tested, with the next step.",
        "",
        "The installers are not signed by Microsoft or Apple. On Windows, SmartScreen may warn",
        "before the installer starts. On macOS, drag the app to Applications, then run this once in",
        "Terminal before opening it; without it, macOS reports the app as damaged or from an",
        "unidentified developer:",
        "",
        "    xattr -dr com.apple.quarantine /Applications/ai-security-scanner.app",
        "",
      ],
    },
  ],
  [
    "0.3.1",
    {
      updaterNotes:
        "Clearer cloud findings, grouped actions, reconnect-and-rescan, 1,497 Semgrep rules, and explicit incomplete scan coverage. 雲端結果更清楚、相同修正合併呈現、重新連接後再掃描、1,497 條 Semgrep 規則，並標示未完成的檢查範圍。",
      releaseNotes: [
        "> **One scan, clearer findings, and practical next steps. / 一次掃描，清楚結果與下一步。**",
        "",
        "ai-security-scanner 0.3.1 is the stable-channel desktop release for Linux, macOS, and Windows.",
        "Choose approved project folders, websites, and internal systems, then read one report organized by asset.",
        "",
        "- Prowler headlines now describe the condition that actually failed. Related AWS findings share an action card while their original identifiers, evidence, severity, and remediation stay available.",
        "- An expired read-only connection leads directly to reconnecting and scanning again. Blocked continuation actions and Markdown presentation are corrected.",
        "- Semgrep uses a pinned pack of 1,493 legacy upstream rules plus four product rules. Published source, notices, image digests, and build/update notes are retained.",
        "- kube-bench manual checks and KICS scan failures now appear as incomplete coverage, while completed sibling findings remain in the report.",
        "- Microsoft 365 setup includes the four approved PIM read permissions and pinned ScubaGear/Maester images. A fresh owner-signed-in live rerun is still pending; this release does not claim that rerun passed.",
        "",
        "### 繁體中文",
        "",
        "0.3.1 為 Linux、macOS 與 Windows 的正式發布版本。選擇已授權的專案資料夾、網站與內部系統，即可閱讀依資產整理的同一份報告。",
        "",
        "- Prowler 標題改為實際失敗的原因；需要相同修正的 AWS 發現合併呈現，原始識別碼、證據、嚴重度與修正建議完整保留。",
        "- 唯讀連線過期後，可直接重新連接再掃描；受阻的繼續操作與 Markdown 顯示也已修正。",
        "- Semgrep 固定使用 1,493 條舊版上游規則加上四條產品規則，並提供來源、授權聲明、映像檔摘要與更新筆記。",
        "- kube-bench 的人工檢查與 KICS 的掃描失敗會標示檢查範圍未完成，已完成的其他發現仍保留。",
        "- Microsoft 365 已更新四項核准的 PIM 讀取權限及 ScubaGear／Maester 映像檔；仍待擁有者登入後重新實測，本版不宣稱該次複驗已通過。",
        "",
        "Windows installers are unsigned. macOS is not notarized. The artifact-specific qualification record below states what was observed and what remains unobserved.",
        "Windows 安裝檔未簽章，macOS 尚未公證；下方依安裝檔列出實際驗證與尚未觀察的項目。",
        "",
        "On macOS, drag the app to Applications, then remove quarantine from this app if macOS blocks it:",
        "macOS 請先將程式拖入 Applications；若系統阻擋開啟，再針對此程式移除隔離標記：",
        "",
        "    xattr -dr com.apple.quarantine /Applications/ai-security-scanner.app",
        "",
      ],
    },
  ],
  [
    "0.4.0",
    {
      updaterNotes:
        "Optional ZAP passive website checks, offline Agentic Radar workflow inventory, bounded Garak model checks, and more reliable reports. 新增可選的 ZAP 被動網站檢查、Agentic Radar 離線工作流程盤點、受限的 Garak 模型檢查，並改善報告完整性。",
      releaseNotes: [
        "ai-security-scanner 0.4.0 is the stable desktop release for Linux, macOS, and Windows, integrating 25 upstream projects.",
        "",
        "- ZAP: optionally crawl one approved website origin and retain upstream passive findings, evidence and remediation. No login, form submission or active attack jobs.",
        "- Agentic Radar: optionally inventory one saved repository using LangGraph, CrewAI, n8n, OpenAI Agents or AutoGen. No workflow execution or model contact; inventory is distinct from security findings.",
        "- Garak: explicitly check one approved OpenAI-compatible HTTPS chat API and model with 54 native DAN/ANSI prompts. One-shot local API keys, TLS verification, no redirects, 1 request/second, 64 attempts including retries, and 150 requested output tokens per attempt. Provider charges apply.",
        "- Reports preserve completed sibling results, identify malformed or unevaluated Kubescape output, and stream large evidence within the retained evidence budget. Greenbone tasks and resume state bind to each exact grant.",
        "- HTML reports fit desktop, tablet and mobile widths. Microsoft 365 adapter platform matching is corrected; a fresh owner-signed-in live rerun remains unobserved.",
        "- Gitleaks 8.30.1-2 and the new managed images retain immutable source/build evidence. Build and update notes cover all 25 engine records and the egress gateway.",
        "",
        "### 繁體中文",
        "",
        "0.4.0 為 Linux、macOS 與 Windows 的正式版，整合 25 個上游專案。",
        "",
        "- ZAP：可選擇爬取一個核准的網站來源，保留上游被動發現、證據與修正建議；不登入、不送出表單、不執行主動攻擊。",
        "- Agentic Radar：離線盤點保存儲存庫中的 LangGraph、CrewAI、n8n、OpenAI Agents 或 AutoGen 工作流程；不執行流程、不連線模型，盤點與安全發現分開呈現。",
        "- Garak：明確核准一個 OpenAI 相容 HTTPS 聊天 API 與模型後，送出 54 個原生 DAN／ANSI 提示。金鑰在本機短暫保留、派送時使用一次，不寫入案件；驗證 TLS、不跟隨重新導向、每秒一次、含重試最多 64 次，每次要求最多 150 個輸出 token；服務商費用適用。",
        "- 報告保留其他已完成結果；Kubescape 無效或未評估輸出會標示未完成。大型證據以串流方式處理，Greenbone 工作與復原狀態綁定精確授權。",
        "- HTML 報告改善桌面、平板與手機版面；M365 平台辨識已修正，仍待擁有者登入後的最新實測。",
        "- Gitleaks 8.30.1-2 與新增映像保留固定來源與建置證據；25 個引擎與閘道器都有建置、例外與更新筆記。",
        "",
        "Windows installers are unsigned; macOS is not notarized. / Windows 安裝檔未簽章，macOS 尚未公證。",
        "",
        "On macOS, drag the app to Applications, then remove quarantine from this app if macOS blocks it:",
        "macOS 請先將程式拖入 Applications；若系統阻擋開啟，再針對此程式移除隔離標記：",
        "",
        "    xattr -dr com.apple.quarantine /Applications/ai-security-scanner.app",
        "",
      ],
    },
  ],
  [
    "0.4.1",
    {
      updaterNotes:
        "Attach original scanner reports to English or Traditional Chinese HTML reports, with clearer results and safer temporary credential cleanup. 中英文 HTML 報告可附上原始掃描報告，並改善結果說明與臨時憑證清理。",
      releaseNotes: [
        "ai-security-scanner 0.4.1 is the stable desktop release for Linux, macOS, and Windows.",
        "",
        "- HTML exports can include original scanner reports and supporting files as downloadable ZIP attachments at the end of the document. Files retain their exact bytes and folder structure, with a SHA-256 manifest for each scanner run.",
        "- English and Traditional Chinese exports support full, unredacted reports. Attachments are optional and require unredacted export; only the selected scan is included. Embedded attachments remain in the HTML file and are not carried into printed PDFs.",
        "- Results, public sample reports and scanner guides use clearer descriptions of findings, incomplete checks and next steps.",
        "- Temporary credential files are covered by cleanup immediately after creation, including later validation failures. Existing files are preserved.",
        "- AWS and Microsoft 365 setup helpers can record temporary access and use companion cleanup scripts to wait for a selected scan, save its report, and revoke recorded access. These are explicitly started helper workflows, not automatic desktop cleanup. New full live-cloud and Windows PowerShell 5.1 flows remain unobserved.",
        "",
        "### 繁體中文",
        "",
        "0.4.1 為 Linux、macOS 與 Windows 的正式版。",
        "",
        "- HTML 報告最後可附上原始掃描報告與支援檔案，以 ZIP 下載；保留原始位元組與資料夾結構，每個掃描工具都有 SHA-256 檔案清單。",
        "- 支援英文與繁體中文的未遮蔽完整報告。附件預設關閉，僅在未遮蔽匯出時提供，且只包含選定掃描；附件保留在 HTML 中，列印成 PDF 不會攜帶附件。",
        "- 結果、公開範例報告與工具指南改用更清楚的發現、未完成檢查及下一步說明。",
        "- 臨時憑證檔建立後立即納入清理保護，後續驗證失敗也會清理；既有檔案保留。",
        "- AWS 與 Microsoft 365 設定輔助程式可記錄臨時存取，搭配清理程式等待指定掃描、保存報告與撤除記錄中的權限；需明確啟動，尚非桌面預設收尾。新版完整真實雲端流程與 Windows PowerShell 5.1 實測仍未觀察。",
        "",
        "Windows installers are unsigned; macOS is not notarized. / Windows 安裝檔未簽章，macOS 尚未公證。",
        "",
        "On macOS, drag the app to Applications, then remove quarantine from this app if macOS blocks it:",
        "macOS 請先將程式拖入 Applications；若系統阻擋開啟，再針對此程式移除隔離標記：",
        "",
        "    xattr -dr com.apple.quarantine /Applications/ai-security-scanner.app",
        "",
      ],
    },
  ],
  [
    "0.5.0",
    {
      updaterNotes:
        "Clearer problem cards, reliable Check fixes comparisons, local-folder reselection, and scanner version details. 問題卡合併、修復後重掃比對、重新選取本機資料夾與工具版本資訊全面整合。",
      releaseNotes: [
        "ai-security-scanner 0.5.0 brings together the desktop and report updates since 0.4.1 for Linux, macOS, and Windows.",
        "",
        "- Results group the same vulnerable package, exposed secret, or same-line code issue into one problem card, while retaining original findings, scanner evidence and provenance.",
        "- Check fixes compares problem cards, keeps their representative when a code line moves, and shows how many original findings remain in a partly fixed problem. The app and HTML report use the same problem order.",
        "- Reselect a local project folder before checking fixes; the scan uses a fresh read-only snapshot within the approved scope. My scans shows the latest finished scan's problem count.",
        "- Cloud configuration and identity findings have fitting labels and next steps. Reports distinguish upstream severity, benchmark classifications and the product's priority order, and explain whether grouped next steps share one fix.",
        "- Progress clearly distinguishes partial completion and failure. Scanner details show versions and update dates, and inventory checks no longer request irrelevant vulnerability-data updates.",
        "- The bilingual real scan example includes before/after reports and refreshed screenshots. Animated guides explain scans, routing, trust, rechecks, reports and model-check limits; scanner guides explain each tool's purpose and boundaries.",
        "- Security dependencies update to rustls 0.23.45 and source-map-js 1.2.2. The Linux runtime builder uses available, fixed zlib and libseccomp package revisions.",
        "",
        "### 繁體中文",
        "",
        "0.5.0 整合 v0.4.1 之後的桌面與報告更新，提供 Linux、macOS 與 Windows 安裝包。",
        "",
        "- 相同弱點套件、相同外洩秘密，以及同一行且同一 CWE 的程式碼問題合併成一張問題卡，保留原始發現、工具證據與來源。",
        "- 修復後重掃以問題卡比對，程式碼行號移動時保留代表發現；部分修復會顯示尚存的原始發現數。介面與 HTML 報告採用一致的問題排序。",
        "- 重掃前可重新選取本機專案資料夾，以核准範圍內的新唯讀快照檢查；我的掃描顯示最近完成掃描的問題數。",
        "- 雲端設定與身分發現採用合適的標籤和下一步；區分上游嚴重度、基準分類與產品處理順序，說明合併建議是否共用一項修正。",
        "- 進度清楚區分部分完成與失敗；工具詳細資訊顯示版本和更新日期，盤點工具不再要求不適用的弱點資料更新。",
        "- 中英文真實掃描範例更新前後報告與截圖；動畫圖解說明掃描、派送、信任邊界、重掃、報告與模型檢查限制，工具指南補齊各工具用途與範圍。",
        "- 安全依賴更新至 rustls 0.23.45 與 source-map-js 1.2.2；Linux runtime 建置改用可取得的固定 zlib 與 libseccomp 套件版本。",
        "",
        "Windows installers are unsigned; macOS is not notarized. / Windows 安裝檔未簽章，macOS 尚未公證。",
        "",
        "On macOS, drag the app to Applications, then remove quarantine from this app if macOS blocks it:",
        "macOS 請先將程式拖入 Applications；若系統阻擋開啟，再針對此程式移除隔離標記：",
        "",
        "    xattr -dr com.apple.quarantine /Applications/ai-security-scanner.app",
        "",
      ],
    },
  ],
  [
    "0.5.1",
    {
      updaterNotes:
        "Japanese UI is now available in Settings → 日本語, with a Japanese README and website. 日文介面、README 與網站正式推出。設定から日本語を選べるようになりました。日本語の README と Web サイトも公開しています。",
      releaseNotes: [
        "ai-security-scanner 0.5.1 adds Japanese UI support to the Linux, macOS, and Windows desktop installers.",
        "",
        "- Choose **Settings → 日本語**. The app remembers your language across restarts.",
        "- Japanese translations cover navigation, scan setup, results, settings, and the runtime setup assistant. Missing explanations fall back to English; HTML reports exported from the Japanese UI currently use English.",
        "- A Japanese README and website include all 25 scanner introductions, search, language switching, and links to existing English sample reports.",
        "- Thanks to [@kieiken](https://github.com/kieiken) for the Japanese UI contribution in [#69](https://github.com/TED-H-com/ai-security-scanner/pull/69). This release also fills gaps in onboarding and runtime setup translations.",
        "",
        "### 日本語",
        "",
        "0.5.1 では、Linux・macOS・Windows のデスクトップアプリで日本語を選べるようになりました。",
        "",
        "- **Settings → 日本語** で切り替えられます。選択した言語は再起動後も保存されます。",
        "- ナビゲーション、スキャンの設定、結果、設定画面、スキャン環境の準備を日本語で表示します。未翻訳の説明は英語で表示され、日本語 UI からエクスポートする HTML レポートも現時点では英語です。",
        "- 日本語の README と Web サイトを追加しました。全 25 スキャナーの紹介、検索、言語切り替えに対応し、既存の英語のサンプルレポートを参照できます。",
        "- [@kieiken](https://github.com/kieiken) さんの [#69](https://github.com/TED-H-com/ai-security-scanner/pull/69) の翻訳を取り込み、初期設定とスキャン環境の準備に残っていた未翻訳箇所も補いました。",
        "",
        "### 繁體中文",
        "",
        "- Windows、macOS 與 Linux 安裝版加入日文介面，可從 **設定 → 日本語** 切換，重新啟動後仍會保留。",
        "- 補齊首頁、掃描設定與 runtime 準備流程的日文，新增日文 README 與網站，涵蓋全部 25 個掃描工具介紹。",
        "- 感謝 @kieiken 的 #69 翻譯貢獻。尚未翻譯的動態說明沿用英文；日文介面匯出的 HTML 報告目前使用英文。",
        "",
        "Windows installers are unsigned; macOS is not notarized. / Windows 安裝檔未簽章，macOS 尚未公證。 / Windows インストーラーは未署名、macOS アプリは未公証です。",
        "",
        "On macOS, drag the app to Applications. If macOS blocks it, remove quarantine from this app:",
        "macOS ではアプリを Applications に移動し、起動がブロックされる場合は次のコマンドを実行してください。",
        "",
        "    xattr -dr com.apple.quarantine /Applications/ai-security-scanner.app",
        "",
      ],
    },
  ],
  [
    "0.5.2",
    {
      updaterNotes:
        "Updates ten scanning engines and offline vulnerability/policy data. Japanese UI remains available. 更新十個掃描引擎與離線弱點、政策資料，保留日文介面。10 個のスキャンエンジンとオフラインの脆弱性・ポリシーデータを更新しました。日本語 UI も引き続き利用できます。",
      releaseNotes: [
        "ai-security-scanner 0.5.2 updates the scanning tools available in the Windows, macOS and Linux desktop app.",
        "",
        "- Updates Steampipe to 2.4.7, Prowler to 5.44.0, httpx to 1.12.0, Semgrep to 1.181.0, TruffleHog to 3.99.2, Checkov to 3.3.29, Trivy to 0.76.0, Grype to 0.120.1, Syft to 1.54.1 and Kubescape to 4.0.16.",
        "- Refreshes the embedded Trivy and Grype vulnerability databases and Kubescape policies. Steampipe also updates its AWS plugin and FDW. kube-bench receives the shared launcher update.",
        "- Aligns Checkov runtime dependencies with the upstream release requirements and verifies their consistency during image builds.",
        "- Fixes the Grype database size check for the new snapshot and checks database fingerprints against the image recipe.",
        "- Preserves the reviewed Semgrep rules, scanner scope boundaries, native finding identifiers and Japanese UI support.",
        "- Installer download links use the current TED-H-com repository. Updater downloads retain the original URLs and follow GitHub's repository redirect.",
        "",
        "### 日本語",
        "",
        "- 10 個のスキャンエンジンを更新し、Trivy・Grype の脆弱性データベースと Kubescape のポリシーを刷新しました。Steampipe の AWS プラグインと FDW、および kube-bench の共通ランチャーも更新しています。",
        "- Checkov の依存パッケージを上流リリースの要件に合わせ、イメージの構築時に依存関係の整合性を確認します。",
        "- 新しい Grype データベースの容量に対応し、組み込みデータの整合性確認を修正しました。",
        "- 確認済みの Semgrep ルール、スキャン対象の制限、検出結果の識別子、日本語 UI を引き続き利用できます。",
        "- インストーラーのダウンロード先は現在の TED-H-com リポジトリです。アプリ内更新のダウンロード URL は従来のものを維持し、GitHub のリダイレクトを利用します。",
        "",
        "### 繁體中文",
        "",
        "- 更新十個掃描引擎，刷新 Trivy、Grype 離線弱點資料與 Kubescape 政策；同步更新 Steampipe AWS 外掛、FDW 與 kube-bench 共用啟動器。",
        "- 修正 Checkov 執行環境的相依套件版本，並在映像建置時確認套件相容性。",
        "- 修正新版 Grype 資料庫超出原大小限制的問題，並核對內建資料的雜湊。",
        "- 保留已驗證的 Semgrep 規則、掃描範圍限制、原始發現識別碼與日文介面。",
        "- 安裝檔下載連結使用目前的 TED-H-com 儲存庫；應用程式更新保留原有網址，透過 GitHub 儲存庫轉址下載。",
        "",
        "Windows installers are unsigned; macOS is not notarized. / Windows 安裝檔未簽章，macOS 尚未公證。 / Windows インストーラーは未署名、macOS アプリは未公証です。",
        "",
        "On macOS, drag the app to Applications. If macOS blocks it, remove quarantine from this app:",
        "macOS ではアプリを Applications に移動し、起動がブロックされる場合は次のコマンドを実行してください。",
        "",
        "    xattr -dr com.apple.quarantine /Applications/ai-security-scanner.app",
        "",
      ],
    },
  ],
  [
    "0.5.3",
    {
      updaterNotes: "October 21 incident scan pack: standard and focused package checks share one report with ISO / NIST references. 10/21 事件掃描包：一般掃描與事件套件檢查共用一份含 ISO／NIST 對照的報告。",
      releaseNotes: [
        "October 21 incident scan pack for the Windows, macOS and Linux desktop app.",
        "",
        "- Keep the standard scan, or select October 21–22 incident triage for applicable local Trivy package checks.",
        "- Both modes use the same asset-first HTML / JSON report, with evidence-bound ISO/IEC 27001:2022, NIST CSF 2.0, AIDEFEND, OWASP and CIS references.",
        "- Incident matches retain upstream findings; unverified checks, account investigations and pending advisories remain distinct.",
        "- Import supported external scanner results and combine saved results while retaining their sources and coverage.",
        "- The attached incident-scan-pack.json binds the campaign, its SHA-256 and report contract to this exact source commit.",
        "",
        "[Downloads and instructions](https://ted-h-com.github.io/ai-security-scanner/incident-october-21.html)",
        "",
        "### 繁體中文",
        "",
        "10/21 事件掃描包保留一般掃描，並加入適用本機副本的事件套件檢查。Mac、Windows、Linux 共用 HTML／JSON 報告與 ISO、NIST 等框架對照。特定漏洞未測試、需調查與公告待確認的狀態分別保留。",
        "",
        "Framework relationships support review; they are not certification or compliance determinations.",
      ],
    },
  ],
  [
    "1.0.0",
    {
      updaterNotes:
        "Windows and macOS installers are now offered alongside Linux, with each artifact's signing and testing state stated in the release record.",
      releaseNotes: [
        "> **Windows, macOS, and Linux installers, offered as what they are.**",
        "",
        "ai-security-scanner 1.0.0 offers installers for all three desktop platforms.",
        "",
        "Version 0.2.0 built Windows and macOS installers and shipped neither. The Windows",
        "installers passed qualification on a fresh runner and were then withheld, because the",
        "release tooling required signing evidence this product does not produce. The macOS",
        "qualification was refused outright, because the tooling accepted hosted-runner",
        "evidence only on a pre-release. Both rules preferred refusing to disclosing.",
        "",
        "Those refusals are gone and every honesty rule beneath them remains. An unsigned",
        "installer still cannot claim to be signed, still carries a stated reason, and still",
        "reports what was not tested. The release record states these facts instead of",
        "treating them as grounds to publish nothing.",
        "",
        "This release also reports an engine result with no detection quality as unknown",
        "confidence rather than rating it medium, refreshes Greenbone to 23.50.24 with its",
        "feed, and binds every engine's adapter contract version to one shared constant.",
      ],
    },
  ],
]);

function releaseCopyFor(version) {
  return RELEASE_COPY.get(version) ?? {
    updaterNotes:
      "Signed ai-security-scanner application update. Existing local cases and historical provenance remain intact.",
    releaseNotes: [],
  };
}

async function regularFiles(directory, root = directory) {
  const files = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const candidate = path.join(directory, entry.name);
    const metadata = await lstat(candidate);
    if (metadata.isSymbolicLink()) {
      throw new Error(`release artifacts contain a symlink: ${candidate}`);
    }
    if (metadata.isDirectory()) {
      files.push(...(await regularFiles(candidate, root)));
    } else if (metadata.isFile()) {
      files.push({
        absolute: candidate,
        relative: toPosix(path.relative(root, candidate)),
        bytes: metadata.size,
      });
    } else {
      throw new Error(`release artifacts contain a special file: ${candidate}`);
    }
  }
  return files;
}

async function verifyRuntimeEvidence(directory, platform) {
  const prefix = `managed-runtime-${platform}`;
  const manifestPath = path.join(directory, `${prefix}.manifest.json`);
  const manifest = await readJson(manifestPath);
  const manifestSha256 = await sha256File(manifestPath);
  const cyclonedx = await readJson(path.join(directory, `${prefix}.cyclonedx.json`));
  const spdx = await readJson(path.join(directory, `${prefix}.spdx.json`));
  const notices = await readFile(path.join(directory, `${prefix}.NOTICES.txt`), "utf8");
  assert(manifest.schema_version === "3", `${prefix} has an unsupported manifest schema`);
  assert(
    manifest.management_contract_revision === "2026-08-29.1",
    `${prefix} has the wrong management contract revision`,
  );
  assert(Array.isArray(manifest.files) && manifest.files.length > 0, `${prefix} has no file inventory`);
  assert(Array.isArray(manifest.targets) && manifest.targets.length > 0, `${prefix} has no target inventory`);
  assert(Array.isArray(manifest.components) && manifest.components.length > 0, `${prefix} has no components`);
  const coveredFiles = new Set();
  const coveredDownloads = new Set();
  for (const component of manifest.components) {
    assert(component.id && component.version && component.source_revision, `${prefix} component identity is incomplete`);
    assert(component.license_spdx && component.repository_url, `${prefix} component license/source is incomplete`);
    assert(notices.includes(component.name) && notices.includes(component.license_spdx), `${prefix} notices omit ${component.id}`);
    if (/GPL-/u.test(component.license_spdx)) {
      assert(
        component.source_archive?.url && component.source_archive?.sha256 && component.source_archive?.size_bytes,
        `${prefix} GPL component ${component.id} has no exact corresponding-source archive`,
      );
    }
    for (const artifact of component.artifacts ?? []) {
      if (artifact.delivery === "bundled_file") coveredFiles.add(artifact.locator);
      if (artifact.delivery === "runtime_download") coveredDownloads.add(artifact.locator);
    }
  }
  assert(manifest.files.every((file) => coveredFiles.has(file.path)), `${prefix} leaves a bundled file unattributed`);
  assert(manifest.targets.every((target) => coveredDownloads.has(target.machine_image.url)), `${prefix} leaves a runtime download unattributed`);
  assert(
    cyclonedx.bomFormat === "CycloneDX" && cyclonedx.components?.length === manifest.components.length,
    `${prefix} CycloneDX inventory does not match its manifest`,
  );
  const runtimeProperties = new Map(
    (cyclonedx.metadata?.properties ?? []).map((property) => [
      property.name,
      property.value,
    ]),
  );
  assert(
    runtimeProperties.get("ai-security-scanner:manifest-sha256") === manifestSha256 &&
      runtimeProperties.get("ai-security-scanner:management-contract-revision") ===
        manifest.management_contract_revision,
    `${prefix} CycloneDX metadata does not bind its manifest and management contract`,
  );
  assert(
    spdx.spdxVersion === "SPDX-2.3" && spdx.packages?.length === manifest.components.length,
    `${prefix} SPDX inventory does not match its manifest`,
  );
  assert(
    spdx.documentNamespace?.endsWith(`/${manifestSha256}`) &&
      notices.includes(`Manifest SHA-256: ${manifestSha256}`) &&
      notices.includes(
        `Management contract revision: ${manifest.management_contract_revision}`,
      ),
    `${prefix} release provenance does not bind its exact manifest identity`,
  );
  return manifest.components.map((component) => ({ ...component, platform }));
}

function enrichSboms(cyclonedx, spdx, sidecars, runtimeComponents, version) {
  assert(Array.isArray(cyclonedx.components), "CycloneDX SBOM has no components array");
  assert(Array.isArray(spdx.packages), "SPDX SBOM has no packages array");
  if (!Array.isArray(spdx.relationships)) {
    spdx.relationships = [];
  }
  for (const sidecar of sidecars) {
    const purl = `pkg:cargo/ai-security-scanner@${version}?binary=${sidecar.binaryName}&platform=${sidecar.platform}`;
    cyclonedx.components.push({
      type: "application",
      "bom-ref": purl,
      name: sidecar.binaryName,
      version,
      hashes: [{ alg: "SHA-256", content: sidecar.sha256 }],
      licenses: [{ license: { id: "Apache-2.0" } }],
      properties: [
        { name: "ai-security-scanner:platform", value: sidecar.platform },
        { name: "ai-security-scanner:release-file", value: sidecar.releaseFile },
        { name: "ai-security-scanner:installed-sibling-name", value: sidecar.installedSiblingName },
        { name: "ai-security-scanner:sidecar-role", value: sidecar.role },
      ],
    });
    const spdxId = `SPDXRef-Package-${sidecar.binaryName}-${sidecar.platform}`;
    spdx.packages.push({
      SPDXID: spdxId,
      name: `${sidecar.binaryName}-${sidecar.platform}`,
      versionInfo: version,
      downloadLocation: "NOASSERTION",
      filesAnalyzed: false,
      checksums: [{ algorithm: "SHA256", checksumValue: sidecar.sha256 }],
      licenseConcluded: "Apache-2.0",
      licenseDeclared: "Apache-2.0",
      copyrightText: "Copyright 2026 Ted Huang and ai-security-scanner contributors",
      primaryPackagePurpose: "APPLICATION",
      externalRefs: [
        {
          referenceCategory: "PACKAGE-MANAGER",
          referenceType: "purl",
          referenceLocator: purl,
        },
      ],
      summary: `First-party ${sidecar.role} installed beside the desktop executable for ${sidecar.platform}.`,
    });
    spdx.relationships.push({
      spdxElementId: "SPDXRef-DOCUMENT",
      relationshipType: "DESCRIBES",
      relatedSpdxElement: spdxId,
    });
  }
  for (const component of runtimeComponents) {
    const purl = `pkg:generic/${encodeURIComponent(component.id)}@${encodeURIComponent(component.version)}?platform=${encodeURIComponent(component.platform)}`;
    cyclonedx.components.push({
      type: "application",
      "bom-ref": purl,
      name: component.name,
      version: component.version,
      licenses: [{ expression: component.license_spdx }],
      externalReferences: [{ type: "vcs", url: `${component.repository_url}/tree/${component.source_revision}` }],
      properties: [
        { name: "ai-security-scanner:platform", value: component.platform },
        { name: "ai-security-scanner:relationship", value: component.relationship },
        ...component.artifacts.map((artifact) => ({
          name: `ai-security-scanner:runtime-artifact:${artifact.delivery}:${artifact.locator}`,
          value: `sha256:${artifact.sha256};bytes:${artifact.size_bytes}`,
        })),
      ],
    });
    const spdxId = `SPDXRef-Runtime-${component.id}-${component.platform}`.replace(/[^A-Za-z0-9.-]/gu, "-");
    spdx.packages.push({
      SPDXID: spdxId,
      name: `${component.name}-${component.platform}`,
      versionInfo: component.version,
      downloadLocation: `${component.repository_url}/tree/${component.source_revision}`,
      filesAnalyzed: false,
      licenseConcluded: component.license_spdx,
      licenseDeclared: component.license_spdx,
      copyrightText: "NOASSERTION",
      primaryPackagePurpose: "APPLICATION",
      externalRefs: [{
        referenceCategory: "PACKAGE-MANAGER",
        referenceType: "purl",
        referenceLocator: purl,
      }],
      summary: `${component.relationship}; exact artifacts are recorded in the platform runtime manifest.`,
    });
    spdx.relationships.push({
      spdxElementId: "SPDXRef-DOCUMENT",
      relationshipType: "DESCRIBES",
      relatedSpdxElement: spdxId,
    });
  }
}

async function regularFileIfPresent(file) {
  try {
    const metadata = await lstat(file);
    return metadata.isFile() && !metadata.isSymbolicLink() ? metadata : null;
  } catch (error) {
    if (error && typeof error === "object" && error.code === "ENOENT") return null;
    throw error;
  }
}

function isFlatReleaseName(value) {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    !/[\0\r\n]/u.test(value) &&
    value !== "." &&
    value !== ".." &&
    path.posix.basename(value) === value &&
    path.win32.basename(value) === value
  );
}

async function readCandidatePlatformManifest(input, platform, version, tag, commit) {
  const name = `installers-${platform}.json`;
  if (!(await regularFileIfPresent(path.join(input, name)))) return null;
  const manifest = await readJson(path.join(input, name));
  assert(manifest.schemaVersion === 2, `${name} has the wrong schema version`);
  assert(manifest.product === "ai-security-scanner", `${name} has the wrong product`);
  assert(manifest.version === version && manifest.tag === tag, `${name} version/tag mismatch`);
  assert(manifest.sourceCommit === commit && manifest.platform === platform, `${name} release identity mismatch`);
  assert(Array.isArray(manifest.installers), `${name} has no installer records`);
  assert(Array.isArray(manifest.auxiliaryExecutables), `${name} has no companion records`);
  assert(Array.isArray(manifest.updaters), `${name} has no updater records array`);
  assert(Array.isArray(manifest.updaterFailures), `${name} has no optional-updater failure records array`);
  const releasedInstallerTypes = platformContract(platform).installerTypes;
  assert(
    Array.isArray(manifest.requestedBundleTypes) &&
      JSON.stringify([...manifest.requestedBundleTypes].sort()) ===
        JSON.stringify([...releasedInstallerTypes].sort()),
    `${name} requested installer matrix is invalid`,
  );
  assert(
    Array.isArray(manifest.availableBundleTypes) && manifest.availableBundleTypes.length > 0 &&
      new Set(manifest.availableBundleTypes).size === manifest.availableBundleTypes.length &&
      manifest.availableBundleTypes.every((installerType) => releasedInstallerTypes.includes(installerType)),
    `${name} available installer matrix is invalid`,
  );
  return manifest;
}

async function verifyCompanionEvidence(input, platform, manifest) {
  const expected = [
    ["managed-egress-gateway", "ai-security-scanner-egress-gateway"],
    ["isolated-bootstrap-broker", "ai-security-scanner-bootstrap-broker"],
    ["local-casework-cli", "ai-security-scanner-cli"],
  ];
  assert(manifest.auxiliaryExecutables.length === expected.length, `${platform} companion evidence is incomplete`);
  for (const [index, sidecar] of manifest.auxiliaryExecutables.entries()) {
    const [role, binaryName] = expected[index];
    assert(sidecar.role === role && sidecar.binaryName === binaryName, `${platform} companion identity is invalid`);
    assert(isFlatReleaseName(sidecar.releaseFile), `${platform} companion filename is invalid`);
    const metadata = await regularFileIfPresent(path.join(input, sidecar.releaseFile));
    assert(metadata && metadata.size === sidecar.bytes, `${platform}/${sidecar.releaseFile} companion bytes are invalid`);
    assert((await sha256File(path.join(input, sidecar.releaseFile))) === sidecar.sha256, `${platform}/${sidecar.releaseFile} companion digest is invalid`);
  }
  return manifest.auxiliaryExecutables.map((sidecar) => ({ ...sidecar, platform }));
}

async function verifyUpdaterForInstaller(input, platform, installerType, manifest, updaterPublicKey) {
  try {
    const updaterType = platform === "macos-universal" && installerType === "dmg" ? "app" : installerType;
    const layout = updaterLayoutsFor(platform).find(({ bundleType }) => bundleType === updaterType);
    if (!layout) return null;
    if (typeof updaterPublicKey !== "string" || updaterPublicKey.length < 64) return null;
    const matches = manifest.updaters.filter((record) =>
      record && typeof record === "object" && !Array.isArray(record) && record.bundleType === updaterType,
    );
    if (matches.length !== 1) return null;
    const updater = matches[0];
    if (JSON.stringify(updater.targetKeys) !== JSON.stringify(layout.targetKeys)) return null;
    for (const field of ["payloadFile", "signatureFile"]) {
      if (!isFlatReleaseName(updater[field])) return null;
    }
    if (
      !Number.isSafeInteger(updater.payloadBytes) || updater.payloadBytes <= 0 ||
      !Number.isSafeInteger(updater.signatureBytes) || updater.signatureBytes <= 0 ||
      !/^[0-9a-f]{64}$/u.test(updater.payloadSha256) ||
      !/^[0-9a-f]{64}$/u.test(updater.signatureSha256) ||
      typeof updater.signature !== "string"
    ) return null;
    const payloadMetadata = await regularFileIfPresent(path.join(input, updater.payloadFile));
    const signatureMetadata = await regularFileIfPresent(path.join(input, updater.signatureFile));
    if (
      !payloadMetadata || payloadMetadata.size !== updater.payloadBytes ||
      !signatureMetadata || signatureMetadata.size !== updater.signatureBytes ||
      (await sha256File(path.join(input, updater.payloadFile))) !== updater.payloadSha256 ||
      (await sha256File(path.join(input, updater.signatureFile))) !== updater.signatureSha256
    ) return null;
    const signature = (await readFile(path.join(input, updater.signatureFile), "utf8")).trim();
    if (signature !== updater.signature) return null;
    verifyUpdaterSignatures(updaterPublicKey, [{
      payload: path.join(input, updater.payloadFile),
      signature: path.join(input, updater.signatureFile),
    }]);
    return updater;
  } catch {
    return null;
  }
}

function unavailable(installer, reason) {
  installer.availability = "not-offered";
  installer.reason = reason;
  installer.artifact = null;
}

export function finalizedUpdaterPlatforms(selections, tag) {
  const platforms = {};
  for (const { updater } of selections.filter(({ updater }) => updater)) {
    const url = `https://github.com/${UPDATER_DOWNLOAD_REPOSITORY}/releases/download/${tag}/${encodeURIComponent(updater.payloadFile)}`;
    for (const target of updater.targetKeys) {
      assert(!platforms[target], `duplicate updater target key: ${target}`);
      platforms[target] = { url, signature: updater.signature };
    }
  }
  return platforms;
}

async function scopedFinalizeMain() {
  const args = parseArgs(process.argv.slice(2));
  const input = path.resolve(requireString(args, "input"));
  const output = path.resolve(requireString(args, "out"));
  assert(input !== output, "--input and --out must be different directories");
  const version = requireString(args, "version");
  const tag = requireString(args, "tag");
  const commit = requireString(args, "commit");
  const publicationMode = requireString(args, "publication-mode");
  assert(isSemver(version) && tag === `v${version}` && /^[0-9a-f]{40}$/u.test(commit), "release identity is malformed or inconsistent");
  assert(PUBLICATION_MODES.has(publicationMode), "publication mode must be commit-bound-qc or public-github-release");
  const outputMetadata = await regularFileIfPresent(output);
  assert(!outputMetadata, "release output must be a directory, not a file");
  try {
    assert((await readdir(output)).length === 0, "release output directory must start empty");
  } catch (error) {
    if (!error || typeof error !== "object" || error.code !== "ENOENT") throw error;
  }

  const metadata = await readJson(path.join(input, "release-metadata.json"));
  validateReleaseMetadataV3(metadata, {
    releaseState: "prepared",
    version,
    tag,
    sourceCommit: commit,
    publicationMode,
  });
  const packageJson = await readJson(
    path.resolve(args.get("package-json") ?? path.join(PROJECT_ROOT, "package.json")),
  );
  assert(
    metadata.releaseChannel === packageJson.release?.channel &&
      metadata.stableTarget === packageJson.release?.target,
    "release metadata publication channel does not match the source package",
  );
  const tauriConfigPath = path.resolve(args.get("tauri-config") ?? path.join(PROJECT_ROOT, "src-tauri", "tauri.conf.json"));
  const tauriConfig = await readJson(tauriConfigPath);
  const updaterPublicKey = tauriConfig.plugins?.updater?.pubkey;

  let externalEvidence = null;
  const hasExternalEvidenceReceipt = Boolean(
    await regularFileIfPresent(path.join(input, WINDOWS_EXTERNAL_EVIDENCE_RECEIPT_FILE)),
  );
  const expectedExternalImporter = externalEvidenceImporterForInput(args, hasExternalEvidenceReceipt);
  if (hasExternalEvidenceReceipt) {
    externalEvidence = await verifyMaterializedWindowsExternalEvidence({
      directory: input,
      expectedImporter: expectedExternalImporter,
    });
    assert(
      externalEvidence.receipt.releaseIdentity.version === version &&
        externalEvidence.receipt.releaseIdentity.tag === tag &&
        externalEvidence.receipt.releaseIdentity.sourceCommit === commit &&
        externalEvidence.receipt.releaseIdentity.releaseChannel === metadata.releaseChannel &&
        externalEvidence.receipt.releaseIdentity.publicationMode === publicationMode,
      "protected external evidence belongs to a different release identity",
    );
  }

  const finalized = structuredClone(metadata);
  finalized.releaseState = "finalized";
  const selections = [];
  const rejectionMessages = [];
  for (const platformRecord of finalized.distribution.platforms) {
    if (platformRecord.availability === "not-offered") continue;
    let manifest;
    try {
      manifest = await readCandidatePlatformManifest(input, platformRecord.platform, version, tag, commit);
    } catch (error) {
      manifest = null;
      rejectionMessages.push(`${platformRecord.platform}: ${error instanceof Error ? error.message : String(error)}`);
    }
    if (!manifest) {
      platformRecord.availability = "not-offered";
      platformRecord.reason = "platform-build-unavailable-or-invalid";
      for (const installer of platformRecord.installers) unavailable(installer, "platform-build-unavailable-or-invalid");
      continue;
    }
    let shared;
    try {
      shared = {
        sidecars: await verifyCompanionEvidence(input, platformRecord.platform, manifest),
        runtimeComponents: await verifyRuntimeEvidence(input, platformRecord.platform),
      };
    } catch (error) {
      rejectionMessages.push(`${platformRecord.platform}: ${error instanceof Error ? error.message : String(error)}`);
      platformRecord.availability = "not-offered";
      platformRecord.reason = "platform-shared-evidence-invalid";
      for (const installer of platformRecord.installers) unavailable(installer, "platform-shared-evidence-invalid");
      continue;
    }
    for (const installerSupport of platformRecord.installers) {
      const qualificationName = `platform-qualification-${platformRecord.platform}-${installerSupport.installerType}.json`;
      if (!(await regularFileIfPresent(path.join(input, qualificationName)))) {
        unavailable(installerSupport, "technical-qualification-not-observed");
        continue;
      }
      const installers = manifest.installers.filter((record) =>
        record && typeof record === "object" && !Array.isArray(record) &&
          record.bundleType === installerSupport.installerType,
      );
      if (installers.length !== 1) {
        unavailable(installerSupport, "qualified-installer-artifact-missing-or-ambiguous");
        continue;
      }
      const installer = installers[0];
      if (
        !isFlatReleaseName(installer.file) ||
        !Number.isSafeInteger(installer.bytes) || installer.bytes <= 0 ||
        !/^[0-9a-f]{64}$/u.test(installer.sha256)
      ) {
        unavailable(installerSupport, "qualified-installer-filename-invalid");
        rejectionMessages.push(
          `${platformRecord.platform}/${installerSupport.installerType}: qualified installer record is invalid`,
        );
        continue;
      }
      let installerBytesValid = false;
      try {
        const installerMetadata = await regularFileIfPresent(path.join(input, installer.file));
        installerBytesValid = Boolean(
          installerMetadata && installerMetadata.size === installer.bytes &&
            (await sha256File(path.join(input, installer.file))) === installer.sha256,
        );
      } catch (error) {
        rejectionMessages.push(
          `${platformRecord.platform}/${installerSupport.installerType}: ${error instanceof Error ? error.message : String(error)}`,
        );
      }
      if (!installerBytesValid) {
        unavailable(installerSupport, "qualified-installer-bytes-invalid");
        rejectionMessages.push(
          `${platformRecord.platform}/${installerSupport.installerType}: qualified installer bytes are invalid`,
        );
        continue;
      }
      let qualification;
      try {
        qualification = await verifyPlatformQualificationFile(path.join(input, qualificationName), {
          platform: platformRecord.platform,
          installerType: installerSupport.installerType,
          version,
          tag,
          commit,
          releaseChannel: metadata.releaseChannel,
          releaseDirectory: input,
        });
      } catch (error) {
        rejectionMessages.push(`${platformRecord.platform}/${installerSupport.installerType}: ${error instanceof Error ? error.message : String(error)}`);
        unavailable(installerSupport, "technical-qualification-invalid");
        continue;
      }
      const identity = {
        platform: platformRecord.platform,
        installerType: installerSupport.installerType,
        version,
        tag,
        commit,
      };
      let dataPreservationEvidence = null;
      const acceptedExternalEvidence =
        externalEvidence &&
          platformRecord.platform === "windows-x86_64" &&
          installerSupport.installerType === "nsis" &&
          JSON.stringify(externalEvidence.receipt.artifact) === JSON.stringify({
            file: installer.file,
            bytes: installer.bytes,
            sha256: installer.sha256,
          })
          ? externalEvidence.receipt
          : null;
      const installedAppLifecycleEvidence = acceptedExternalEvidence?.windowsLifecycle ?? null;
      const acceptedExternalEvidenceReceiptFile = acceptedExternalEvidence
        ? {
            path: WINDOWS_EXTERNAL_EVIDENCE_RECEIPT_FILE,
            bytes: (await regularFileIfPresent(path.join(input, WINDOWS_EXTERNAL_EVIDENCE_RECEIPT_FILE))).size,
            sha256: await sha256File(path.join(input, WINDOWS_EXTERNAL_EVIDENCE_RECEIPT_FILE)),
          }
        : null;
      if (
        platformRecord.platform === "windows-x86_64" &&
        installerSupport.installerType === "nsis"
      ) {
        try {
          dataPreservationEvidence = await verifyWindowsNsisSupportingDataPreservationEvidence({
            root: input,
            artifactDirectory: input,
            version,
            tag,
            commit,
          });
        } catch (error) {
          rejectionMessages.push(
            `${platformRecord.platform}/${installerSupport.installerType} data preservation: ${error instanceof Error ? error.message : String(error)}`,
          );
        }
      }
      const humanName = `human-path-qualification-${platformRecord.platform}-${installerSupport.installerType}.json`;
      let humanEvidence = null;
      try {
        if (acceptedExternalEvidence?.humanPath?.path === humanName) {
          humanEvidence = await verifyBoundArtifactEvidenceFile(path.join(input, humanName), {
            ...identity,
            artifact: installer,
            evidenceType: "beginner-human-path",
            label: humanName,
          });
        } else if (await regularFileIfPresent(path.join(input, humanName))) {
          rejectionMessages.push(`${humanName}: ignored because it has no matching protected import receipt`);
        }
      } catch (error) {
        rejectionMessages.push(`${humanName}: ${error instanceof Error ? error.message : String(error)}`);
      }
      const signingName = `os-signing-${platformRecord.platform}-${installerSupport.installerType}.json`;
      // A generic external import may retain an exact NotSigned observation, but
      // only a separately reviewed protected signing producer/publisher policy
      // may create OS-signing promotion evidence. No such policy is configured.
      const signingEvidence = null;
      const notarizationName = `notarization-${platformRecord.platform}-${installerSupport.installerType}.json`;
      let notarizationEvidence = null;
      if (
        platformRecord.platform === "macos-universal" &&
        await regularFileIfPresent(path.join(input, notarizationName))
      ) {
        try {
          notarizationEvidence = await verifyBoundArtifactEvidenceFile(path.join(input, notarizationName), {
            ...identity,
            artifact: installer,
            evidenceType: "apple-notarization",
            label: notarizationName,
          });
        } catch (error) {
          rejectionMessages.push(`${notarizationName}: ${error instanceof Error ? error.message : String(error)}`);
        }
      }
      const updater = await verifyUpdaterForInstaller(
        input,
        platformRecord.platform,
        installerSupport.installerType,
        manifest,
        updaterPublicKey,
      );
      const limitations = [];
      if (!humanEvidence) limitations.push("beginner-human-path-not-observed");
      if (!signingEvidence) limitations.push("operating-system-signing-not-configured");
      if (platformRecord.platform === "windows-x86_64") {
        if (installedAppLifecycleEvidence?.summary?.state === "partial") {
          limitations.push("windows-lifecycle-partial");
        } else if (installedAppLifecycleEvidence?.summary?.state === "failed") {
          limitations.push("windows-lifecycle-failed");
        } else if (installedAppLifecycleEvidence?.summary?.state !== "verified") {
          limitations.push("windows-lifecycle-not-observed");
        }
        if (installerSupport.installerType === "nsis" && dataPreservationEvidence) {
          limitations.push("windows-data-preservation-fixtures-only");
        } else {
          limitations.push("windows-data-preservation-not-observed");
        }
      }
      if (platformRecord.platform === "macos-universal" && !notarizationEvidence) {
        limitations.push("apple-notarization-not-configured");
      }
      if (!updater) limitations.push("updater-not-offered-for-this-artifact");
      if (qualification.qualificationState === "installer_passed_runtime_not_observed") {
        limitations.push("managed-runtime-not-observed-on-qualification-host");
      }
      installerSupport.availability = "offered";
      installerSupport.reason = null;
      installerSupport.artifact = {
        file: installer.file,
        bytes: installer.bytes,
        sha256: installer.sha256,
        technicalQualification: {
          state: qualification.qualificationState === "passed"
            ? "passed"
            : "installer-passed-runtime-not-observed",
          evidenceFile: qualificationName,
          reason: null,
        },
        humanPath: humanEvidence
          ? { state: "verified", evidenceFile: humanName, reason: null }
          : { state: "not-observed", evidenceFile: null, reason: "exact-candidate-beginner-path-not-observed" },
        operatingSystemSigning: signingEvidence
          ? { state: "verified", evidenceFile: signingName, reason: null }
          : { state: "not-configured", evidenceFile: null, reason: "artifact-has-no-verified-operating-system-signature" },
        notarization: platformRecord.platform === "macos-universal"
          ? notarizationEvidence
            ? { state: "verified", evidenceFile: notarizationName, reason: null }
            : { state: "not-configured", evidenceFile: null, reason: "artifact-has-no-verified-apple-notarization" }
          : { state: "not-applicable", evidenceFile: null, reason: "apple-notarization-does-not-apply" },
        windowsLifecycle: platformRecord.platform !== "windows-x86_64"
          ? { state: "not-applicable", evidenceFiles: [], reason: "Windows lifecycle does not apply" }
          : installedAppLifecycleEvidence &&
              installedAppLifecycleEvidence.summary.state !== "not-observed" &&
              installedAppLifecycleEvidence.records.length > 0
            ? {
                state: installedAppLifecycleEvidence.summary.state,
                evidenceFiles: [
                  acceptedExternalEvidenceReceiptFile,
                  ...installedAppLifecycleEvidence.records.map(({ path: evidencePath, bytes, sha256 }) => ({
                    path: evidencePath,
                    bytes,
                    sha256,
                  })),
                ],
                reason: installedAppLifecycleEvidence.summary.state === "verified"
                  ? null
                  : `external-installed-app-lifecycle-${installedAppLifecycleEvidence.summary.state}`,
              }
            : {
              state: "not-observed",
              evidenceFiles: [],
              reason: installerSupport.installerType === "msi"
                ? "equivalent-msi-lifecycle-not-observed"
                : "real-installed-app-localhost-lifecycle-not-observed",
            },
        windowsDataPreservation: platformRecord.platform !== "windows-x86_64"
          ? { state: "not-applicable", evidenceFiles: [], reason: "Windows data preservation does not apply" }
          : installerSupport.installerType === "nsis" && dataPreservationEvidence
            ? dataPreservationEvidence
            : {
                state: "not-observed",
                evidenceFiles: [],
                reason: installerSupport.installerType === "msi"
                  ? "equivalent-msi-data-preservation-not-observed"
                  : "exact-current-candidate-nsis-data-preservation-not-observed",
              },
        updater: updater
          ? {
              state: "signed",
              payloadFile: updater.payloadFile,
              signatureFile: updater.signatureFile,
              targetKeys: [...updater.targetKeys],
              reason: null,
            }
          : {
              state: "not-offered",
              payloadFile: null,
              signatureFile: null,
              targetKeys: [],
              reason: "no-valid-artifact-scoped-updater",
            },
        provenanceAttestation: provenanceForArtifact(publicationMode),
        knownLimitations: limitations,
      };
      if (acceptedExternalEvidence) {
        verifyFinalizedWindowsExternalEvidenceOutcomes({
          receipt: acceptedExternalEvidence,
          receiptFile: acceptedExternalEvidenceReceiptFile,
          humanPath: installerSupport.artifact.humanPath,
          windowsLifecycle: installerSupport.artifact.windowsLifecycle,
        });
      }
      selections.push({
        platform: platformRecord.platform,
        installerType: installerSupport.installerType,
        installer,
        qualificationName,
        humanName: humanEvidence ? humanName : null,
        signingName: signingEvidence ? signingName : null,
        notarizationName: notarizationEvidence ? notarizationName : null,
        dataPreservationFiles: dataPreservationEvidence?.evidenceFiles ?? [],
        externalEvidenceFiles: acceptedExternalEvidence
          ? [
              RELEASE_CANDIDATE_LOCK_FILE,
              WINDOWS_EXTERNAL_EVIDENCE_RECEIPT_FILE,
              ...(acceptedExternalEvidence.unsignedSigningObservation
                ? [WINDOWS_UNSIGNED_SIGNING_OBSERVATION_FILE]
                : []),
              ...acceptedExternalEvidence.windowsLifecycle.records.map(({ path: evidencePath }) => evidencePath),
            ]
          : [],
        updater,
        manifest,
        shared,
      });
    }
    const offered = platformRecord.installers.filter(({ availability }) => availability === "offered");
    platformRecord.availability = offered.length > 0 ? "offered" : "not-offered";
    platformRecord.reason = offered.length > 0 ? null : "no-qualified-installer-artifact";
  }
  assert(selections.length > 0, `no releasable installer artifact remains (${rejectionMessages.join(" | ")})`);
  assert(
    !externalEvidence || selections.some(({ externalEvidenceFiles }) =>
      externalEvidenceFiles.includes(WINDOWS_EXTERNAL_EVIDENCE_RECEIPT_FILE)),
    "protected external evidence was not bound to an offered Windows NSIS artifact",
  );
  validateReleaseMetadataV3(finalized, { releaseState: "finalized" });

  await mkdir(output, { recursive: true });
  const copied = new Map();
  const copySelected = async (name) => {
    assert(typeof name === "string" && name === toPosix(name), `release file path is not canonical POSIX: ${String(name)}`);
    assertSafeRelativePath(name);
    const source = path.join(input, name);
    const metadata_ = await regularFileIfPresent(source);
    assert(metadata_ && metadata_.size > 0, `selected release file is missing: ${name}`);
    const digest = await sha256File(source);
    if (copied.has(name)) {
      assert(copied.get(name) === digest, `selected release filename collision: ${name}`);
      return;
    }
    const destination = path.join(output, name);
    await mkdir(path.dirname(destination), { recursive: true });
    await copyFile(source, destination);
    copied.set(name, digest);
  };
  const cyclonedxName = `ai-security-scanner-${version}.cyclonedx.json`;
  const spdxName = `ai-security-scanner-${version}.spdx.json`;
  for (const name of [
    "THIRD_PARTY_NOTICES.txt",
    "ENGINE_NOTICES.md",
    "ENGINE_NOTICES.json",
    "LICENSE.txt",
    cyclonedxName,
    spdxName,
  ]) await copySelected(name);

  if (version === "0.5.3") {
    const pack = await readJson(path.join(input, "incident-scan-pack.json"));
    assert(pack.app_version === version && pack.release_tag === tag && pack.source_commit === commit,
      "incident scan pack does not match the release source");
    const campaignBytes = await readFile(path.join(PROJECT_ROOT, pack.campaign_path));
    assert(pack.campaign_sha256 === await sha256File(path.join(PROJECT_ROOT, pack.campaign_path)),
      "incident campaign hash differs from the release source");
    assert(JSON.stringify(pack.campaign) === JSON.stringify(JSON.parse(campaignBytes)),
      "incident campaign differs from the release source");
    await copySelected("incident-scan-pack.json");
    await copySelected("INCIDENT_SCAN_PACK.md");
  }

  const includedPlatforms = new Map();
  for (const selection of selections) {
    const platform = includedPlatforms.get(selection.platform) ?? {
      installers: [], sidecars: selection.shared.sidecars, updaters: [], runtimeComponents: selection.shared.runtimeComponents,
    };
    platform.installers.push(selection.installer);
    if (selection.updater && !platform.updaters.some(({ bundleType }) => bundleType === selection.updater.bundleType)) {
      platform.updaters.push(selection.updater);
    }
    includedPlatforms.set(selection.platform, platform);
    await copySelected(selection.installer.file);
    await copySelected(selection.qualificationName);
    for (const name of [selection.humanName, selection.signingName, selection.notarizationName].filter(Boolean)) {
      await copySelected(name);
    }
    for (const name of selection.externalEvidenceFiles) await copySelected(name);
    for (const dataPreservationFile of selection.dataPreservationFiles) {
      assert(
        (await sha256File(path.join(input, dataPreservationFile.path))) === dataPreservationFile.sha256,
        `data-preservation evidence changed before copy: ${dataPreservationFile.path}`,
      );
      await copySelected(dataPreservationFile.path);
    }
    if (selection.updater) {
      await copySelected(selection.updater.payloadFile);
      await copySelected(selection.updater.signatureFile);
    }
  }
  const runtimeSuffixes = ["manifest.json", "cyclonedx.json", "spdx.json", "NOTICES.txt"];
  for (const [platform, records] of includedPlatforms) {
    for (const sidecar of records.sidecars) await copySelected(sidecar.releaseFile);
    for (const suffix of runtimeSuffixes) await copySelected(`managed-runtime-${platform}.${suffix}`);
    const sourceManifestSha256 = await sha256File(path.join(input, `installers-${platform}.json`));
    const filteredManifestName = `installers-${platform}.json`;
    await writeJsonAtomic(path.join(output, filteredManifestName), {
      schemaVersion: 3,
      product: "ai-security-scanner",
      version,
      tag,
      sourceCommit: commit,
      platform,
      artifactScoped: true,
      sourceManifestSha256,
      installers: records.installers,
      auxiliaryExecutables: records.sidecars.map(({ platform: _platform, ...sidecar }) => sidecar),
      updaters: records.updaters,
    });
    copied.set(filteredManifestName, await sha256File(path.join(output, filteredManifestName)));
    const names = [...new Set([
      filteredManifestName,
      ...records.installers.map(({ file }) => file),
      ...records.sidecars.map(({ releaseFile }) => releaseFile),
      ...records.updaters.flatMap(({ payloadFile, signatureFile }) => [payloadFile, signatureFile]),
      ...runtimeSuffixes.map((suffix) => `managed-runtime-${platform}.${suffix}`),
    ])].sort();
    const lines = [];
    for (const name of names) lines.push(`${await sha256File(path.join(output, name))}  ${name}`);
    await writeTextAtomic(path.join(output, `SHA256SUMS-${platform}.txt`), `${lines.join("\n")}\n`);
  }

  const cyclonedx = await readJson(path.join(output, cyclonedxName));
  const spdx = await readJson(path.join(output, spdxName));
  const sidecars = [...includedPlatforms.values()].flatMap(({ sidecars }) => sidecars);
  const runtimeComponents = [...includedPlatforms.values()].flatMap(({ runtimeComponents }) => runtimeComponents);
  enrichSboms(cyclonedx, spdx, sidecars, runtimeComponents, version);
  await writeJsonAtomic(path.join(output, cyclonedxName), cyclonedx);
  await writeJsonAtomic(path.join(output, spdxName), spdx);
  await writeJsonAtomic(path.join(output, "release-metadata.json"), finalized);

  await writeJsonAtomic(path.join(output, "latest.json"), {
    version,
    tag,
    notes: releaseCopyFor(version).updaterNotes,
    pub_date: metadata.sourceDate,
    platforms: finalizedUpdaterPlatforms(selections, tag),
  });

  const offeredLines = finalized.distribution.platforms.flatMap((platform) =>
    platform.installers
      .filter(({ availability }) => availability === "offered")
      .map(({ installerType, artifact }) =>
        `- ${platform.platform} / ${installerType}: ${artifact.file}; technical qualification ${artifact.technicalQualification.state}; beginner human path ${artifact.humanPath.state}.`),
  );
  const unavailableLines = finalized.distribution.platforms.flatMap((platform) =>
    platform.installers
      .filter(({ availability }) => availability === "not-offered")
      .map(({ installerType, reason }) => `- ${platform.platform} / ${installerType}: not offered (${reason}).`),
  );
  const distributionVerification = publicationMode === "public-github-release"
    ? "Verify the selected file against SHA256SUMS.txt and its artifact-specific public provenance before installing."
    : "These are commit-bound QC artifacts, not a public release; public provenance has not been created.";
  const offeredWindowsInstallers =
    publicationMode === "public-github-release" &&
    finalized.distribution.platforms
      .find(({ platform }) => platform === "windows-x86_64")
      ?.installers.filter(({ availability }) => availability === "offered");
  const windowsPackageRecord = offeredWindowsInstallers?.length > 0
    ? [
        "## Windows package record",
        "",
        metadata.releaseChannel === "prerelease"
          ? "This prerelease includes unsigned Windows installers for public testing. Windows may show an Unknown publisher warning."
          : "The Windows installers in this stable release are not code-signed. Windows may show an Unknown publisher warning, and Microsoft Defender SmartScreen may warn on first run.",
        "",
        ...offeredWindowsInstallers.map(({ installerType, artifact }) => {
          const limitations = [];
          if (artifact.operatingSystemSigning.state !== "verified") limitations.push("Authenticode not verified");
          if (artifact.humanPath.state !== "verified") limitations.push("exact-candidate beginner path not observed");
          if (artifact.windowsLifecycle.state === "partial") limitations.push("installed-app lifecycle partial");
          else if (artifact.windowsLifecycle.state === "failed") limitations.push("installed-app lifecycle failed");
          else if (artifact.windowsLifecycle.state !== "verified") limitations.push("installed-app lifecycle not observed");
          if (artifact.windowsDataPreservation.state === "not-observed") {
            limitations.push("data-preservation path not observed");
          } else if (artifact.windowsDataPreservation.state === "supporting-data-preservation-only") {
            limitations.push("data-preservation fixtures only");
          }
          return `- ${installerType.toUpperCase()}: ${limitations.join("; ")}.`;
        }),
        "",
      ]
    : [];
  await writeTextAtomic(path.join(output, "RELEASE_NOTES.md"), [
    `# ai-security-scanner ${version}`,
    "",
    `Source: \`${commit}\``,
    "",
    ...releaseCopyFor(version).releaseNotes,
    "Artifacts offered by this finalized set:",
    ...offeredLines,
    "",
    "Not offered in this finalized set:",
    ...unavailableLines,
    "",
    distributionVerification,
    "Qualification, human-path observation, OS signing, notarization, updater availability,",
    "provenance requirements, and known limitations are recorded independently for every offered artifact",
    "in release-metadata.json. An absent platform never implies that it passed.",
    "",
    ...windowsPackageRecord,
  ].join("\n"));

  const beforeIndex = (await regularFiles(output))
    .filter((file) => file.relative !== "SHA256SUMS.txt" && file.relative !== "release-assets.json")
    .sort((left, right) => left.relative.localeCompare(right.relative));
  const fileRecords = [];
  const indexedPublicationNames = new Set();
  for (const file of beforeIndex) {
    const publishedName = publishedReleaseAssetName(file.relative);
    const foldedPublishedName = publishedName.toLowerCase();
    assert(
      !indexedPublicationNames.has(foldedPublishedName),
      `release index publication filename collision: ${publishedName}`,
    );
    indexedPublicationNames.add(foldedPublishedName);
    fileRecords.push({
      path: file.relative,
      publishedName,
      bytes: file.bytes,
      sha256: await sha256File(file.absolute),
    });
  }
  await writeJsonAtomic(path.join(output, "release-assets.json"), {
    schemaVersion: 3,
    product: "ai-security-scanner",
    version,
    tag,
    sourceCommit: commit,
    publicationMode,
    indexSelfExcluded: true,
    files: fileRecords,
  });
  const finalFiles = (await regularFiles(output))
    .filter((file) => file.relative !== "SHA256SUMS.txt")
    .sort((left, right) => left.relative.localeCompare(right.relative));
  const checksums = [];
  const checksumPublicationNames = new Set();
  for (const file of finalFiles) {
    const publishedName = publishedReleaseAssetName(file.relative);
    const foldedPublishedName = publishedName.toLowerCase();
    assert(
      !checksumPublicationNames.has(foldedPublishedName),
      `release checksum publication filename collision: ${publishedName}`,
    );
    checksumPublicationNames.add(foldedPublishedName);
    checksums.push(`${await sha256File(file.absolute)}  ${publishedName}`);
  }
  await writeTextAtomic(path.join(output, "SHA256SUMS.txt"), `${checksums.join("\n")}\n`);
  for (const message of rejectionMessages) process.stderr.write(`release tooling: excluded candidate: ${message}\n`);
  process.stdout.write(
    `Finalized ${selections.length} independently qualified installer artifact(s) across ${includedPlatforms.size} platform(s); absent or unqualified siblings remain explicit in release-metadata.json.\n`,
  );
}

if (path.resolve(process.argv[1] ?? "") === path.resolve(fileURLToPath(import.meta.url))) {
  runMain(scopedFinalizeMain);
}
