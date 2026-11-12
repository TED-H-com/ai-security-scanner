import { useEffect, useState } from "react";

import { caseIdentityPresentation } from "../caseIdentityPresentation";
import { Icon } from "../components/Icon";
import { CombinedReportExport } from "../components/CombinedReportExport";
import { EmptyState, InlineNotice, PageHeader } from "../components/Shared";
import { StatusPill } from "../components/StatusPill";
import {
  exportFormatIsAvailable,
  isFindingOnlyExportFormat,
  resetUnavailableExportFormat,
  runSupportsFindingOnlyExport,
} from "../exportFormatEligibility";
import { useI18n } from "../i18n";
import { isExactBuiltInLocalhostQuickScanRun } from "../localhostQuickScan";
import { reportLocaleForUiLocale } from "../reportLocale";
import { scanRunIdentityPresentation } from "../scanRunIdentityPresentation";
import type { CaseExport, CaseWorkspace, ExportFormat, ExportPreview } from "../types";
import "./page-technical-details.css";
import { displayTechnicalDetail } from "./pageTechnicalDetails";

interface ExportPageProps {
  workspace: CaseWorkspace;
  selectedRunId?: string;
  runningScanResultsPending?: boolean;
  exports: CaseExport[];
  demoMode: boolean;
  busy?: boolean;
  onPreview: (options: {
    runId: string;
    locale: "en" | "zh-Hant";
    format: ExportFormat;
    includeRawEvidence: boolean;
    redactSensitiveValues: boolean;
  }) => Promise<ExportPreview | undefined>;
  onExport: (options: {
    runId: string;
    locale: "en" | "zh-Hant";
    format: ExportFormat;
    includeRawEvidence: boolean;
    redactSensitiveValues: boolean;
  }) => Promise<void>;
  onVerify: (path: string) => Promise<void>;
  onVerifyReceived: () => Promise<void>;
}

const copy = {
  eyebrow: { en: "EXPORT", zhTW: "匯出" },
  title: { en: "Export results", zhTW: "匯出結果" },
  description: {
    en: "Choose a format and save locally.",
    zhTW: "選擇格式並儲存到本機。",
  },
  finishedRunWhileScanning: {
    en: "Showing a finished scan; the latest results open automatically.",
    zhTW: "目前顯示已完成的掃描；最新結果將自動開啟。",
  },
  preparing: { en: "Preparing…", zhTW: "準備中…" },
  exportDemo: { en: "Download {format} demo file", zhTW: "下載「{format}」展示檔" },
  createExport: { en: "Save {format}", zhTW: "儲存「{format}」" },
  recommendedFormat: { en: "{format} (recommended)", zhTW: "{format}（建議）" },
  connectionOnlyTitle: {
    en: "Connection test only — no vulnerability scan ran",
    zhTW: "這只是連線測試，沒有執行漏洞掃描",
  },
  connectionOnlyBody: {
    en: "The exported file records only whether one local port accepted a bounded TCP connection. Choose a website, project, or applicable network scan for a security report.",
    zhTW: "匯出檔只會記錄單一本機連接埠是否接受有限制的 TCP 連線。若要取得資安報告，請選擇網站、專案或適用的網路掃描。",
  },
  demoTitle: { en: "This downloads a sample report", zhTW: "這次會下載一份範例報告" },
  demoBody: {
    en: "Browser demo export: one selected-run JSON sample.",
    zhTW: "瀏覽器展示匯出：一份所選掃描輪次的 JSON 範例。",
  },
  demoDetails: { en: "About sample reports", zhTW: "關於範例報告" },
  demoTechnical: {
    en: "Marker: DEMO_ONLY_NOT_A_SCAN. Format: JSON. Excludes source files, redaction transforms, coverage companions, and local signatures.",
    zhTW: "標記：DEMO_ONLY_NOT_A_SCAN。格式：JSON。不含來源檔案、遮罩轉換、涵蓋附檔與本機簽章。",
  },
  previewErrorTitle: { en: "The exact export preview is unavailable", zhTW: "目前無法取得精確匯出預覽" },
  previewErrorBody: {
    en: "Retry preview before exporting.",
    zhTW: "請在匯出前重新取得預覽。",
  },
  runUnavailableTitle: { en: "Choose a saved scan before exporting", zhTW: "請先選擇一筆已保存的掃描" },
  runUnavailableBody: {
    en: "No available saved scan is selected. Go to Results and choose a saved scan, or start one from New scan.",
    zhTW: "目前沒有選定可用的已保存掃描。請前往「掃描結果」選擇一筆掃描，或從「開始新掃描」開始。",
  },
  chooseRun: { en: "Choose a scan in Results", zhTW: "前往「掃描結果」選擇掃描" },
  retryPreview: { en: "Try preview again", zhTW: "重新取得預覽" },
  // One of these three replaces the single unconditional sentence that used to
  // sit here. That sentence promised "Passwords and access keys are never
  // included", which holds only under standard redaction: with redaction off,
  // `include = include_raw_artifacts && !(Standard && sensitive)` in
  // export.rs admits every artifact, and gitleaks and trufflehog ship as
  // engines whose raw output carries the values verbatim. The backend already
  // computes the contradicting sentence -- it was rendered one disclosure down
  // from the promise.
  sharingRedacted: {
    en: "Sensitive identifiers hidden; source files excluded",
    zhTW: "已遮罩敏感識別資訊；不附來源檔案",
  },
  sharingIdentifiable: {
    en: "Identifiers remain readable; source files are not attached",
    zhTW: "識別資訊仍可讀；不附來源檔案",
  },
  sharingRawSources: {
    en: "Includes unredacted scanner files that may contain secrets; share only with trusted recipients",
    zhTW: "將附上未遮罩的掃描工具原始檔，可能含機密；僅交付可信對象",
  },
  previewPending: { en: "Checking file contents…", zhTW: "正在確認檔案內容…" },
  scopeSelectedRun: { en: "Selected-run report", zhTW: "所選掃描輪次報告" },
  scopeCaseBundle: {
    en: "Case-wide records; reports use the selected run",
    zhTW: "案件全域紀錄；報告使用所選輪次",
  },
  scopeDemo: { en: "Selected-run demo sample", zhTW: "所選掃描輪次展示範例" },
  scopeUnavailable: { en: "No saved scan selected", zhTW: "尚未選擇已保存的掃描" },
  integritySignedDecision: {
    en: "Integrity: locally signed",
    zhTW: "完整性：本機簽署",
  },
  integrityUnsignedDecision: {
    en: "Integrity: SHA-256 recorded in this scan project",
    zhTW: "完整性：SHA-256 已記錄在這個掃描專案",
  },
  integrityDemoDecision: {
    en: "Demo sample: integrity record unavailable",
    zhTW: "展示範例：不提供完整性紀錄",
  },
  // Only the case bundle is signed: `export.rs` attaches an envelope, while
  // every other format takes the `case_service.rs` path that sets
  // `signature: None` and stores UNSIGNED_SCHEMA_NOTICE. This sentence headed
  // the summary for whichever format was selected, so five of the six were
  // introduced by a description of a signature they do not carry. The backend's
  // own notice says so and reaches no screen.
  signatureLimit: {
    en: "Integrity: locally signed. Detects changes after export.",
    zhTW: "完整性：本機簽署，可偵測匯出後的變更。",
  },
  signatureUnsigned: {
    en: "Integrity: SHA-256 digest recorded in this scan project.",
    zhTW: "完整性：SHA-256 摘要已記錄在這個掃描專案。",
  },
  caseBundleScopeBody: {
    en: "The bundle contains case-wide assets, grants, coverage, scan history, findings, workflow history, comparisons, and optional raw source files. Reports use observations and evidence from the selected scan run. For older observations without a frozen snapshot, fallback wording uses the current finding; workflow status and asset names come from the current case.",
    zhTW: "案件包包含整個案件的資產、授權、涵蓋、掃描歷史、問題、工作流程歷史、比較與選配的原始來源檔案。包內報告使用所選掃描輪次的觀察與證據；較舊且沒有凍結快照的觀察會以目前問題內容作為後備文字，工作流程狀態與資產名稱來自目前案件。",
  },
  technicalPreview: { en: "Technical preview details", zhTW: "預覽技術細節" },
  coverageDetails: { en: "See what was checked and what was not", zhTW: "查看哪些已檢查、哪些未完成" },
  previewFailure: { en: "Preview failure", zhTW: "預覽錯誤" },
  backendWarning: { en: "Recorded export warning", zhTW: "核心記錄的匯出警告" },
  countUnavailable: { en: "Exact count: unknown.", zhTW: "精確數量：未知。" },
  disclosureAria: { en: "Coverage and execution facts included with the export", zhTW: "匯出前的涵蓋與執行情況" },
  unknownSources: { en: "Sources with no visibility", zhTW: "看不到的資料來源" },
  unknownSourcesSome: { en: "Source visibility: none. Asset count: unknown.", zhTW: "來源視野：無。資產數量：未知。" },
  unknownSourcesNone: {
    en: "Sources marked unknown: 0. Inventory completeness: unknown.",
    zhTW: "標記為未知的來源：0。資產清單完整度：未知。",
  },
  connectedNone: { en: "Connected sources that found nothing", zhTW: "已連接但沒有找到資產的來源" },
  connectedNoneDetail: { en: "Saved source snapshot result: zero items.", zhTW: "已保存來源快照結果：零項。" },
  completedWork: { en: "Completed scanner jobs", zhTW: "已完成的掃描工作" },
  completedWorkDetail: {
    en: "Completed jobs in the selected scan. Broader coverage appears separately below.",
    zhTW: "所選掃描中已完成的工作；更廣泛的涵蓋範圍另列於下方。",
  },
  incompleteWork: { en: "Scanner work not fully completed", zhTW: "沒有完整完成的掃描工作" },
  incompleteWorkDetail: { en: "Includes partly completed, failed, or cancelled scanner jobs.", zhTW: "包含部分完成、失敗或取消的掃描工作。" },
  notRun: { en: "Scanner jobs not run", zhTW: "未執行的掃描工作" },
  notRunDetail: { en: "Exported fields: recorded reason and not-run status.", zhTW: "匯出欄位：已記錄原因與未執行狀態。" },
  formatTitle: { en: "Choose a format", zhTW: "選擇格式" },
  advancedFormats: { en: "More formats", zhTW: "更多格式" },
  advancedFormatsHint: {
    en: "For specialist or standards-based workflows.",
    zhTW: "供專家交接或標準格式工作流程使用。",
  },
  // OCSF and OSCAL need a selected run; the case-level formats stay available.
  advancedFormatsNeedRun: {
    en: "OCSF and OSCAL require a saved scan for their coverage manifest. Available now: HTML, JSON, framework report, and case bundle.",
    zhTW: "OCSF 與 OSCAL 的涵蓋說明檔需要一筆已保存掃描。目前可用：HTML、JSON、框架報告與案件包。",
  },
  includeRaw: { en: "Include original scanner files", zhTW: "附上掃描工具原始檔" },
  includeRawHtml: { en: "Attach original reports at the end", zhTW: "在報告最後附上原始報告" },
  includeRawHtmlDetail: {
    en: "Embeds downloadable ZIP attachments in the HTML, including supporting files and logs. May contain secrets. Attachments are not carried into printed PDFs.",
    zhTW: "將可下載的 ZIP 附件存入 HTML，包含配套檔案與紀錄，可能含機密。列印的 PDF 不會帶出附件。",
  },
  // Every artifact the desktop app captures is marked sensitive
  // (artifact_store.rs sets it unconditionally), and standard redaction drops
  // every sensitive artifact. So with private details hidden this option
  // attaches nothing at all -- which the old wording, promising a larger file
  // and no credentials, described as the opposite of what happens in both
  // states.
  includeRawBundle: {
    en: "May contain secrets. Share only with trusted recipients.",
    zhTW: "可能含機密；僅交付可信對象。",
  },
  includeRawNeedsUnredacted: {
    en: "Turn off masking to attach these files.",
    zhTW: "關閉遮罩後才能附上這些檔案。",
  },
  redact: { en: "Hide sensitive identifiers (recommended)", zhTW: "遮罩敏感識別資訊（建議）" },
  redactDetail: {
    en: "Replaces project, organization, and target names (targets appear as “Asset 1”, “Asset 2”, …) and masks tokens, email addresses, internal IPs, and system IDs.",
    zhTW: "以代稱取代專案、組織與目標名稱（目標會顯示為「Asset 1」、「Asset 2」…），並遮罩權杖、電子郵件、內部 IP 與系統 ID。",
  },
  includesEyebrow: { en: "FILE CONTENTS", zhTW: "檔案內容" },
  case: { en: "Case", zhTW: "案件" },
  exactType: { en: "File type", zhTW: "檔案類型" },
  selectedRun: { en: "Selected scan run", zhTW: "選定的掃描輪次" },
  calculating: { en: "Calculating", zhTW: "計算中" },
  dataSources: { en: "Data sources", zhTW: "資料來源" },
  coverageEntries: { en: "Coverage records", zhTW: "涵蓋紀錄" },
  assets: { en: "Known / candidate assets", zhTW: "全部／候選資產" },
  findings: { en: "Case / selected-run result records", zhTW: "案件全部／本輪結果紀錄" },
  evidenceIndexes: { en: "All / selected-run evidence records", zhTW: "全部／本輪證據索引" },
  runs: { en: "Scan runs / selected-run jobs", zhTW: "掃描輪次／本輪工作" },
  externalPolicies: { en: "Pinned external-scope grants", zhTW: "固定的外部範圍授權" },
  rawEvidence: { en: "Raw evidence included / omitted", zhTW: "原始證據包含／略過" },
  sensitiveOmitted: { en: "Sensitive raw evidence omitted", zhTW: "略過的敏感原始證據" },
  notRunJobs: { en: "Jobs not run", zhTW: "未執行工作" },
  unknownSourceFact: { en: "Sources with no visibility", zhTW: "看不到的資料來源" },
  contentsScope: { en: "Scope statement and coverage record", zhTW: "範圍聲明與涵蓋紀錄" },
  contentsVersions: { en: "Scanner, rule library, and result-adapter versions", zhTW: "掃描工具、規則庫與結果轉換器版本" },
  contentsHashes: { en: "Source-evidence hash for each result record", zhTW: "每筆結果紀錄的原始證據雜湊" },
  // `case.asset_relations` is serialized in exactly one place -- the bundle's
  // `assets.json`. OCSF names "asset relationships" in its own
  // `omitted_canonical_areas`, and the master JSON, HTML, OSCAL, and framework
  // report all build from the beginner report, which has no such field. The
  // bullet was rendered with a check for every format.
  contentsAssets: { en: "Asset relationships for specialist review", zhTW: "供專家查看的資產關聯資料" },
  contentsAssetsExcluded: {
    en: "Asset relationships are not carried by this format; the technical case bundle is the one that includes them",
    zhTW: "這個格式不會帶出資產關聯資料；只有技術案件包會包含",
  },
  contentsUnknown: { en: "Not-run, partial, failed, and unknown states", zhTW: "未執行、部分、失敗與未知狀態" },
  contentsLimits: { en: "Report terms at the end", zhTW: "報告末端的正式條款" },
  localOnly: { en: "Before export: local only", zhTW: "匯出前：僅限本機" },
  historyEyebrow: { en: "EXPORT HISTORY", zhTW: "匯出紀錄" },
  historyTitle: { en: "Files created on this device", zhTW: "這台電腦上的匯出紀錄" },
  historyDescription: { en: "Find every report saved on this device, or verify a package someone sent you.", zhTW: "查看這台電腦儲存過的報告，也能驗證別人傳來的案件包。" },
  fileCount: { en: "Files: {count}", zhTW: "{count} 份" },
  verifyReceived: { en: "Check a file someone sent you", zhTW: "檢查別人傳來的檔案" },
  noExportsTitle: { en: "No saved reports", zhTW: "沒有已儲存的報告" },
  noExportsDescription: { en: "Saved reports use only the selected location on this device.", zhTW: "報告只會儲存到這台電腦上選定的位置。" },
  legacyUnknownFormat: { en: "Older record: file type unknown", zhTW: "舊版紀錄：檔案類型未知" },
  savedReport: { en: "Saved security report", zhTW: "已儲存的資安報告" },
  fileDetails: { en: "File details and integrity check", zhTW: "檔案細節與完整性檢查" },
  fileName: { en: "File name", zhTW: "檔案名稱" },
  scanRunId: { en: "Immutable scan-run ID", zhTW: "不可變更的掃描輪次 ID" },
  savedRunUnavailable: { en: "Saved scan is no longer available", zhTW: "這筆已保存的掃描已無法使用" },
  fileHash: { en: "SHA-256", zhTW: "SHA-256" },
  coverageManifest: { en: "Coverage companion", zhTW: "涵蓋說明檔" },
  coverageManifestIncluded: { en: "Included next to this file", zhTW: "已存放在此檔案旁" },
  integrity: { en: "Integrity status", zhTW: "完整性狀態" },
  sourceFiles: { en: "Source-file contents", zhTW: "來源檔案內容" },
  demoFile: { en: "Demo file", zhTW: "展示檔" },
  demoSignature: { en: "Demo value, not a formal signature", zhTW: "展示值，不是正式簽章" },
  localSignature: { en: "Local integrity signature", zhTW: "本機完整性簽章" },
  unsigned: { en: "Unsigned", zhTW: "未簽章" },
  legacyRawUnknown: { en: "Older record: original evidence unknown", zhTW: "舊版紀錄：原始證據未知" },
  rawIncluded: { en: "Original evidence files included: {count}", zhTW: "包含 {count} 份原始證據" },
  some: { en: "some", zhTW: "部分" },
  indexOnly: { en: "Evidence index only", zhTW: "只含證據索引" },
  verifyHelp: { en: "Verify that the file has not changed", zhTW: "驗證檔案是否遭到修改" },
  noPathHelp: { en: "This demo record has no local file to verify", zhTW: "這筆展示紀錄沒有可驗證的本機檔案" },
  verify: { en: "Check file", zhTW: "檢查檔案" },
} as const;

const formatCopy = {
  case_bundle: {
    title: { en: "Technical case bundle", zhTW: "技術案件包" },
    detail: {
      en: "Full case records for specialist handoff.",
      zhTW: "完整案件紀錄，供資安專家接手。",
    },
    extension: ".case.tar.gz",
  },
  html: {
    title: { en: "HTML report", zhTW: "HTML 報告" },
    detail: {
      en: "For teammates; opens in a browser.",
      zhTW: "給同事閱讀；可用瀏覽器開啟。",
    },
    extension: ".html",
  },
  json: {
    title: { en: "JSON report", zhTW: "JSON 報告" },
    detail: {
      en: "Structured data for other tools.",
      zhTW: "供其他工具使用的結構化資料。",
    },
    extension: ".json",
  },
  framework_report: {
    title: { en: "Framework mappings", zhTW: "框架對照" },
    detail: {
      en: "NIST, ISO 27001, and AIDEFEND references.",
      zhTW: "NIST、ISO 27001 與 AIDEFEND 對照。",
    },
    extension: ".frameworks.json",
  },
  ocsf: {
    title: { en: "OCSF events", zhTW: "OCSF 事件資料" },
    detail: {
      en: "For OCSF-compatible security tools.",
      zhTW: "供支援 OCSF 的資安工具使用。",
    },
    extension: ".ocsf.json",
  },
  oscal: {
    title: { en: "OSCAL assessment", zhTW: "OSCAL 評估資料" },
    detail: {
      en: "For OSCAL-compatible governance tools.",
      zhTW: "供支援 OSCAL 的治理工具使用。",
    },
    extension: ".oscal.json",
  },
} as const satisfies Record<ExportFormat, {
  title: { en: string; zhTW: string };
  detail: { en: string; zhTW: string };
  extension: string;
}>;

const primaryFormats = ["html", "json"] as const satisfies readonly ExportFormat[];
const recommendedFormat = "html" as const satisfies ExportFormat;
const advancedFormats = [
  "case_bundle",
  "framework_report",
  "ocsf",
  "oscal",
] as const satisfies readonly ExportFormat[];
const findingOnlyCoverageCopy = {
  ocsf: {
    en: "OCSF finding and service-inventory events plus a coverage manifest for missing or unfinished checks.",
    zhTW: "OCSF 問題與服務盤點事件，另附涵蓋說明檔記錄未測或未完成項目。",
  },
  oscal: {
    en: "OSCAL observations plus a coverage manifest for missing or unfinished checks.",
    zhTW: "OSCAL 觀察資料，另附涵蓋說明檔記錄未測或未完成項目。",
  },
} as const;

export function ExportPage({ workspace, selectedRunId, runningScanResultsPending, exports, demoMode, busy, onPreview, onExport, onVerify, onVerifyReceived }: ExportPageProps) {
  const { locale, text, formatDateTime, formatNumber } = useI18n();
  const reportLocale = reportLocaleForUiLocale(locale);
  const selectedRun = workspace.runs.find((run) => run.id === selectedRunId);
  const selectedRunUnavailable = !selectedRun;
  const connectionOnlyRun = Boolean(selectedRun && isExactBuiltInLocalhostQuickScanRun(selectedRun));
  const activeRun = selectedRun && ["queued", "running", "paused"].includes(selectedRun.status)
    ? selectedRun
    : undefined;
  const workspaceExportRevision = `${workspace.findings.length}|${workspace.runs
    .map((run) => `${run.id}:${run.status}:${run.progress}:${run.finishedAt ?? ""}`)
    .join("|")}`;
  const [format, setFormat] = useState<ExportFormat>("html");
  const [includeRawEvidence, setIncludeRawEvidence] = useState(false);
  const [redactSensitiveValues, setRedactSensitiveValues] = useState(!demoMode);
  const [preview, setPreview] = useState<ExportPreview>();
  const [previewError, setPreviewError] = useState<string>();
  const [previewPending, setPreviewPending] = useState(true);
  const [previewRequest, setPreviewRequest] = useState(0);
  const findingOnlyFormatsAvailable = runSupportsFindingOnlyExport(selectedRun);
  const selectedFormatUnavailable = !selectedRun
    || Boolean(activeRun)
    || !exportFormatIsAvailable(format, selectedRun);

  useEffect(() => {
    if (!demoMode) return;
    setFormat("json");
    setIncludeRawEvidence(false);
    setRedactSensitiveValues(false);
  }, [demoMode]);

  useEffect(() => {
    const availableFormat = resetUnavailableExportFormat(format, selectedRun);
    if (availableFormat !== format) {
      setFormat(availableFormat);
      setIncludeRawEvidence(false);
    }
  }, [findingOnlyFormatsAvailable, format, selectedRun]);

  useEffect(() => {
    let active = true;
    setPreviewPending(true);
    setPreview(undefined);
    setPreviewError(undefined);
    if (demoMode && format !== "json") {
      return () => {
        active = false;
      };
    }
    if (activeRun) {
      setPreviewPending(false);
      return () => {
        active = false;
      };
    }
    if (!selectedRun) {
      setPreviewError("export_run_unavailable");
      setPreviewPending(false);
      return () => {
        active = false;
      };
    }
    if (selectedFormatUnavailable) {
      setPreviewPending(false);
      return () => {
        active = false;
      };
    }
    void onPreview({ runId: selectedRun.id, locale: reportLocale, format, includeRawEvidence, redactSensitiveValues })
      .then((result) => {
        if (!active) return;
        const expectedRedaction = redactSensitiveValues ? "standard" : "none";
        if (
          !result
          || result.caseId !== workspace.case.id
          || result.runId !== selectedRun.id
          || result.locale !== reportLocale
          || result.format !== format
          || result.redactionProfile !== expectedRedaction
          || result.includeRawEvidence !== includeRawEvidence
        ) {
          console.error("[ai-security-scanner] export preview did not match the requested case, run, locale, format, or redaction profile");
          setPreview(undefined);
          setPreviewError(result ? "export_preview_coordinate_mismatch" : "export_preview_unavailable");
          return;
        }
        setPreview(result);
      })
      .catch((error: unknown) => {
        if (!active) return;
        const message = displayTechnicalDetail(error) ?? "export_preview_failed";
        console.error("[ai-security-scanner] export preview failed", message);
        setPreview(undefined);
        setPreviewError(message);
      })
      .finally(() => {
        if (active) setPreviewPending(false);
      });
    return () => {
      active = false;
    };
  }, [activeRun, demoMode, format, includeRawEvidence, onPreview, previewRequest, redactSensitiveValues, reportLocale, selectedFormatUnavailable, selectedRun, workspace.case.id, workspaceExportRevision]);

  const previewMatchesSelection = Boolean(
    preview
    && selectedRun
    && preview.caseId === workspace.case.id
    && preview.runId === selectedRun.id
    && preview.locale === reportLocale
    && preview.format === format
    && preview.redactionProfile === (redactSensitiveValues ? "standard" : "none")
    && preview.includeRawEvidence === includeRawEvidence,
  );

  const unknownSourceCount = preview?.unknownSourceCount;
  const connectedNoAssetCount = preview?.connectedNoAssetCount;
  const incompleteEngineCount = preview?.incompleteEngineRunCount;
  const notExecutedCount = preview?.notExecutedEngineRunCount;
  const completedEngineCount = preview
    ? Math.max(0, preview.selectedEngineRunCount - preview.incompleteEngineRunCount - preview.notExecutedEngineRunCount)
    : undefined;
  const currentFormat = formatCopy[format];
  // Read from the controls rather than from `preview`, which lags a toggle by a
  // debounce -- the sentence below must never describe settings the user has
  // already changed. HTML and case bundles can carry original files when
  // redaction is off; see the copy note on `includeRawBundle`.
  const formatSupportsAttachments = format === "case_bundle" || format === "html";
  const rawSourcesAttached = formatSupportsAttachments && includeRawEvidence && !redactSensitiveValues;
  // Signing and case-wide asset relations remain specific to case bundles.
  // HTML attachments do not change either of those contracts.
  const formatIsSigned = !demoMode && format === "case_bundle";
  const formatCarriesAssetRelations = format === "case_bundle";
  const sharingConsequence = redactSensitiveValues
    ? copy.sharingRedacted
    : rawSourcesAttached
      ? copy.sharingRawSources
      : copy.sharingIdentifiable;
  const scopeConsequence = demoMode
    ? copy.scopeDemo
    : !selectedRun
      ? copy.scopeUnavailable
      : format === "case_bundle"
        ? copy.scopeCaseBundle
        : copy.scopeSelectedRun;
  const integrityConsequence = demoMode
    ? copy.integrityDemoDecision
    : formatIsSigned
      ? copy.integritySignedDecision
      : copy.integrityUnsignedDecision;
  const privacyTone = rawSourcesAttached ? "danger" : redactSensitiveValues ? "neutral" : "warning";
  const shownCount = (value: number | undefined): string => value === undefined ? "—" : formatNumber(value);
  const renderFormatCard = (id: ExportFormat) => {
    const item = formatCopy[id];
    const unavailableWithoutRun = isFindingOnlyExportFormat(id) && !findingOnlyFormatsAvailable;
    const unavailableInDemo = demoMode && id !== "json";
    const unavailable = unavailableWithoutRun || unavailableInDemo;
    return (
      <label
        key={id}
        className={`${format === id ? "format-card format-card--active" : "format-card"}${unavailable ? " format-card--disabled" : ""}`}
        aria-disabled={unavailable || undefined}
      >
        <input
          type="radio"
          name="export-format"
          value={id}
          checked={format === id}
          disabled={unavailable}
          onChange={() => {
            setFormat(id);
            if (id !== "case_bundle" && id !== "html") setIncludeRawEvidence(false);
          }}
        />
        <span className="format-card__icon"><Icon name={id === "case_bundle" ? "cases" : "file"} size={20} /></span>
        <span>
          <strong>{id === recommendedFormat ? text(copy.recommendedFormat, { format: text(item.title) }) : text(item.title)}</strong>
          <small>{text(isFindingOnlyExportFormat(id) ? findingOnlyCoverageCopy[id] : item.detail)}</small>
        </span>
      </label>
    );
  };

  if (activeRun) {
    return null;
  }

  return (
    <div className="page">
      <PageHeader
        eyebrow={text(copy.eyebrow)}
        title={text(copy.title)}
        description={text(copy.description)}
      />

      {locale === "ja" && (
        <InlineNotice tone="info" title="レポートは英語で保存されます" />
      )}

      {runningScanResultsPending && (
        <InlineNotice tone="info" title={text(copy.finishedRunWhileScanning)} />
      )}

      {connectionOnlyRun && !demoMode && (
        <InlineNotice tone="warning" title={text(copy.connectionOnlyTitle)}>
          <p>{text(copy.connectionOnlyBody)}</p>
        </InlineNotice>
      )}

      {demoMode && (
        <InlineNotice tone="warning" title={text(copy.demoTitle)}>
          <p>{text(copy.demoBody)}</p>
          <details className="page-technical-details">
            <summary>{text(copy.demoDetails)}</summary>
            <p>{text(copy.demoTechnical)}</p>
          </details>
        </InlineNotice>
      )}

      <div className="export-layout">
        <section className="section-block export-builder">
          <div className="section-heading">
            <h2>{text(copy.formatTitle)}</h2>
          </div>

          <fieldset className="export-format-fieldset">
            <legend className="sr-only">{text(copy.formatTitle)}</legend>
            <div className="format-grid">
              {primaryFormats.map(renderFormatCard)}
            </div>

            <details className="page-secondary-feature export-advanced-formats">
              <summary>{text(copy.advancedFormats)}</summary>
              <p className="page-secondary-feature__intro">
                {text(findingOnlyFormatsAvailable ? copy.advancedFormatsHint : copy.advancedFormatsNeedRun)}
              </p>
              <div className="format-grid">{advancedFormats.map(renderFormatCard)}</div>
            </details>
          </fieldset>

          <div className="export-options">
            <label className="toggle-row">
              <input
                type="checkbox"
                checked={redactSensitiveValues}
                disabled={demoMode}
                onChange={(event) => {
                  const nextRedaction = event.target.checked;
                  setRedactSensitiveValues(nextRedaction);
                  if (nextRedaction) setIncludeRawEvidence(false);
                }}
              />
              <span><strong>{text(copy.redact)}</strong><small>{text(copy.redactDetail)}</small></span>
            </label>
            {formatSupportsAttachments && (
              <label className="toggle-row">
                <input
                  type="checkbox"
                  checked={includeRawEvidence}
                  disabled={demoMode || redactSensitiveValues}
                  onChange={(event) => setIncludeRawEvidence(event.target.checked)}
                />
                <span>
                  <strong>{text(format === "html" ? copy.includeRawHtml : copy.includeRaw)}</strong>
                  <small>{text(redactSensitiveValues ? copy.includeRawNeedsUnredacted : format === "html" ? copy.includeRawHtmlDetail : copy.includeRawBundle)}</small>
                </span>
              </label>
            )}
          </div>

          {previewError ? (
            <InlineNotice tone="danger" title={text(selectedRunUnavailable ? copy.runUnavailableTitle : copy.previewErrorTitle)}>
              <p>{text(selectedRunUnavailable ? copy.runUnavailableBody : copy.previewErrorBody)}</p>
              {selectedRunUnavailable ? (
                <a className="button button--secondary button--small" href="#findings">
                  <Icon name="findings" size={15} /> {text(copy.chooseRun)}
                </a>
              ) : (
                <button className="button button--secondary button--small" type="button" disabled={busy || previewPending} onClick={() => setPreviewRequest((request) => request + 1)}>
                  <Icon name="refresh" size={15} /> {text(copy.retryPreview)}
                </button>
              )}
              <details className="page-technical-details">
                <summary>{text(copy.technicalPreview)}</summary>
                <dl>
                  <div><dt>{text(copy.previewFailure)}</dt><dd>{previewError}</dd></div>
                  {preview?.sensitiveDataWarning && <div><dt>{text(copy.backendWarning)}</dt><dd>{displayTechnicalDetail(preview.sensitiveDataWarning)}</dd></div>}
                </dl>
              </details>
            </InlineNotice>
          ) : preview?.sensitiveDataWarning ? (
            <details className="page-technical-details export-preview-technical">
              <summary>{text(copy.technicalPreview)}</summary>
              <dl><div><dt>{text(copy.backendWarning)}</dt><dd>{displayTechnicalDetail(preview.sensitiveDataWarning)}</dd></div></dl>
            </details>
          ) : null}

          <div
            className={`export-privacy-status export-privacy-status--${privacyTone}`}
            id="export-preview-status"
            role={rawSourcesAttached ? "alert" : "status"}
            aria-live={rawSourcesAttached ? "assertive" : "polite"}
            aria-atomic="true"
          >
            <Icon name={rawSourcesAttached || !redactSensitiveValues ? "warning" : "lock"} size={17} />
            <span className="export-decision-summary">
              <span className="export-sharing-consequence">{text(sharingConsequence)}</span>
              {" · "}{text(scopeConsequence)}{" · "}{text(integrityConsequence)}
              {previewPending ? ` · ${text(copy.previewPending)}` : ""}
            </span>
          </div>

          <div className="export-actions">
            <button
              className="button button--primary"
              type="button"
              disabled={busy || previewPending || !previewMatchesSelection}
              aria-busy={busy || previewPending}
              aria-describedby="export-preview-status"
              onClick={() => {
                if (!selectedRun || !previewMatchesSelection) return;
                void onExport({ runId: selectedRun.id, locale: reportLocale, format, includeRawEvidence, redactSensitiveValues });
              }}
            >
              <Icon name="download" size={18} />
              {busy || previewPending
                ? text(copy.preparing)
                : demoMode
                  ? text(copy.exportDemo, { format: text(currentFormat.title) })
                  : text(copy.createExport, { format: text(currentFormat.title) })}
            </button>
          </div>
        </section>

        <details className="export-summary export-summary--details">
          <summary className="export-summary__header">
            <Icon name="file" size={22} />
            <span><span className="eyebrow">{text(copy.includesEyebrow)}</span><strong>{text(currentFormat.title)}</strong></span>
          </summary>
          {formatIsSigned && <p className="export-summary__note">{text(copy.caseBundleScopeBody)}</p>}
          {!demoMode && <p className="export-summary__note">{text(formatIsSigned ? copy.signatureLimit : copy.signatureUnsigned)}</p>}
          <dl className="export-facts">
            <div><dt>{text(copy.case)}</dt><dd>{caseIdentityPresentation(workspace.case, locale).name}</dd></div>
            <div><dt>{text(copy.exactType)}</dt><dd>{text(currentFormat.title)} · <code>{currentFormat.extension}</code></dd></div>
            <div>
              <dt>{text(copy.selectedRun)}</dt>
              <dd>{selectedRun ? scanRunIdentityPresentation(selectedRun, locale) : text(copy.calculating)} · <code>{preview?.runId ?? text(copy.calculating)}</code></dd>
            </div>
            <div><dt>{text(copy.dataSources)}</dt><dd>{shownCount(preview?.dataSourceCount)}</dd></div>
            <div><dt>{text(copy.coverageEntries)}</dt><dd>{shownCount(preview?.coverageEntryCount)}</dd></div>
            <div><dt>{text(copy.assets)}</dt><dd>{preview ? `${formatNumber(preview.assetCount)} / ${formatNumber(preview.candidateAssetCount)}` : "—"}</dd></div>
            <div><dt>{text(copy.findings)}</dt><dd>{preview ? `${formatNumber(preview.canonicalFindingCount)} / ${formatNumber(preview.selectedRunFindingCount)}` : "—"}</dd></div>
            <div><dt>{text(copy.evidenceIndexes)}</dt><dd>{preview ? `${formatNumber(preview.evidenceIndexCount)} / ${formatNumber(preview.selectedRunEvidenceCount)}` : "—"}</dd></div>
            <div><dt>{text(copy.runs)}</dt><dd>{preview ? `${formatNumber(preview.scanRunCount)} / ${formatNumber(preview.selectedEngineRunCount)}` : "—"}</dd></div>
            <div><dt>{text(copy.externalPolicies)}</dt><dd>{shownCount(preview?.externalScopeGrantCount)}</dd></div>
            <div><dt>{text(copy.rawEvidence)}</dt><dd>{preview ? `${formatNumber(preview.rawArtifactsIncluded)} / ${formatNumber(preview.rawArtifactsOmitted)}` : "—"}</dd></div>
            <div><dt>{text(copy.sensitiveOmitted)}</dt><dd>{shownCount(preview?.sensitiveRawArtifactsOmitted)}</dd></div>
            <div><dt>{text(copy.notRunJobs)}</dt><dd>{shownCount(preview?.notExecutedEngineRunCount)}</dd></div>
            <div><dt>{text(copy.unknownSourceFact)}</dt><dd>{shownCount(preview?.unknownSourceCount)}</dd></div>
          </dl>
          <ul className="export-contents">
            <li><Icon name="check" size={15} /> {text(copy.contentsScope)}</li>
            <li><Icon name="check" size={15} /> {text(copy.contentsVersions)}</li>
            <li><Icon name="check" size={15} /> {text(copy.contentsHashes)}</li>
            <li className={formatCarriesAssetRelations ? undefined : "export-contents__excluded"}>
              <Icon name={formatCarriesAssetRelations ? "check" : "close"} size={15} />
              {" "}
              {text(formatCarriesAssetRelations ? copy.contentsAssets : copy.contentsAssetsExcluded)}
            </li>
            <li><Icon name="check" size={15} /> {text(copy.contentsUnknown)}</li>
            <li><Icon name="check" size={15} /> {text(copy.contentsLimits)}</li>
          </ul>
          <div className="export-summary__footer"><Icon name="lock" size={16} /><span>{text(copy.localOnly)}</span></div>
        </details>
      </div>

      <details className="page-technical-details page-technical-details--guide">
        <summary>{text(copy.coverageDetails)}</summary>
        <section className="export-disclosure-grid" aria-label={text(copy.disclosureAria)}>
          <article className={completedEngineCount === undefined ? "export-disclosure export-disclosure--unknown" : "export-disclosure"}>
            <span>{text(copy.completedWork)}</span><strong>{shownCount(completedEngineCount)}</strong><p>{completedEngineCount === undefined ? text(copy.countUnavailable) : text(copy.completedWorkDetail)}</p>
          </article>
          <article className={unknownSourceCount === undefined || unknownSourceCount > 0 ? "export-disclosure export-disclosure--unknown" : "export-disclosure"}>
            <span>{text(copy.unknownSources)}</span><strong>{shownCount(unknownSourceCount)}</strong>
            <p>{unknownSourceCount === undefined ? text(copy.countUnavailable) : unknownSourceCount > 0 ? text(copy.unknownSourcesSome) : text(copy.unknownSourcesNone)}</p>
          </article>
          <article className={connectedNoAssetCount === undefined ? "export-disclosure export-disclosure--unknown" : "export-disclosure"}>
            <span>{text(copy.connectedNone)}</span><strong>{shownCount(connectedNoAssetCount)}</strong><p>{connectedNoAssetCount === undefined ? text(copy.countUnavailable) : text(copy.connectedNoneDetail)}</p>
          </article>
          <article className={incompleteEngineCount === undefined || incompleteEngineCount > 0 ? "export-disclosure export-disclosure--warning" : "export-disclosure"}>
            <span>{text(copy.incompleteWork)}</span><strong>{shownCount(incompleteEngineCount)}</strong><p>{incompleteEngineCount === undefined ? text(copy.countUnavailable) : text(copy.incompleteWorkDetail)}</p>
          </article>
          <article className={notExecutedCount === undefined || notExecutedCount > 0 ? "export-disclosure export-disclosure--unknown" : "export-disclosure"}>
            <span>{text(copy.notRun)}</span><strong>{shownCount(notExecutedCount)}</strong><p>{notExecutedCount === undefined ? text(copy.countUnavailable) : text(copy.notRunDetail)}</p>
          </article>
        </section>
      </details>

      <CombinedReportExport key={workspace.case.id} caseId={workspace.case.id} runs={workspace.runs}
        nativeMode={!demoMode} busy={busy} />

      <details className="section-block page-secondary-feature export-history-section">
        <summary className="export-history-summary">
          <span>
            <span className="eyebrow">{text(copy.historyEyebrow)}</span>
            <strong>{text(copy.historyTitle)}</strong>
          </span>
          <span className="count-label">{text(copy.fileCount, { count: formatNumber(exports.length) })}</span>
        </summary>
        <div className="export-history-intro">
          <p>{text(copy.historyDescription)}</p>
          <button className="button button--ghost button--small" type="button" disabled={busy || demoMode} onClick={() => void onVerifyReceived()}>
            <Icon name="shield" size={16} /> {text(copy.verifyReceived)}
          </button>
        </div>

        {exports.length === 0 ? (
          <EmptyState icon="export" title={text(copy.noExportsTitle)} description={text(copy.noExportsDescription)} />
        ) : (
          <div className="export-history">
            {exports.map((item) => {
              const itemFormat = item.format ? formatCopy[item.format] : undefined;
              const historyRun = workspace.runs.find((run) => run.id === item.runId);
              const historyRunName = historyRun
                ? scanRunIdentityPresentation(historyRun, locale)
                : text(copy.savedRunUnavailable);
              return (
                <article key={item.id} className="export-row">
                  <span className="export-row__icon"><Icon name="file" size={19} /></span>
                  <div>
                    <strong>{itemFormat ? text(itemFormat.title) : text(copy.savedReport)}</strong>
                    <span>{historyRunName} · {formatDateTime(item.createdAt)}</span>
                  </div>
                  <details className="page-technical-details export-row__technical">
                    <summary>{text(copy.fileDetails)}</summary>
                    <dl>
                      <div><dt>{text(copy.fileName)}</dt><dd>{item.fileName}</dd></div>
                      <div><dt>{text(copy.exactType)}</dt><dd>{itemFormat ? `${text(itemFormat.title)} · ${itemFormat.extension}` : text(copy.legacyUnknownFormat)}</dd></div>
                      <div><dt>{text(copy.selectedRun)}</dt><dd>{historyRunName}</dd></div>
                      <div><dt>{text(copy.scanRunId)}</dt><dd><code>{item.runId}</code></dd></div>
                      <div><dt>{text(copy.fileHash)}</dt><dd><code>{item.sha256}</code></dd></div>
                      {item.coverageManifestPath && <div><dt>{text(copy.coverageManifest)}</dt><dd>
                        <StatusPill label={text(copy.coverageManifestIncluded)} tone="neutral" />
                        {item.coverageManifestSha256 && <code>{item.coverageManifestSha256}</code>}
                      </dd></div>}
                      <div><dt>{text(copy.integrity)}</dt><dd>
                        <span className="export-row__badges">
                          {item.isDemo && <StatusPill label={text(copy.demoFile)} tone="demo" />}
                          <StatusPill
                            label={item.isDemo ? text(copy.demoSignature) : item.signatureState === "local_integrity" ? text(copy.localSignature) : text(copy.unsigned)}
                            tone={!item.isDemo && item.signatureState === "local_integrity" ? "positive" : "neutral"}
                          />
                        </span>
                      </dd></div>
                      <div><dt>{text(copy.sourceFiles)}</dt><dd>
                        <StatusPill
                          label={item.includesRawEvidence === undefined
                            ? text(copy.legacyRawUnknown)
                            : item.includesRawEvidence
                              ? text(copy.rawIncluded, { count: item.rawArtifactsIncluded === undefined ? text(copy.some) : formatNumber(item.rawArtifactsIncluded) })
                              : text(copy.indexOnly)}
                          tone="neutral"
                        />
                      </dd></div>
                    </dl>
                  </details>
                  <button
                    className="button button--ghost button--small"
                    type="button"
                    disabled={!item.path || item.isDemo}
                    title={item.path ? text(copy.verifyHelp) : text(copy.noPathHelp)}
                    onClick={() => item.path && void onVerify(item.path)}
                  >
                    <Icon name="shield" size={16} /> {text(copy.verify)}
                  </button>
                </article>
              );
            })}
          </div>
        )}
      </details>
    </div>
  );
}
