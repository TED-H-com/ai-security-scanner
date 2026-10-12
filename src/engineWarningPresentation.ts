import type { Locale } from "./i18n/core";
import { UNEVALUATED_CONTROL_KINDS, unevaluatedControlItemsZhTW } from "./findingNarrative.ts";

/**
 * Product-authored engine-run warnings shown only by the Progress page.
 * Stored English remains canonical; values inside known frames stay verbatim.
 */
const FIXED_ENGINE_WARNINGS: ReadonlyArray<readonly [string, string]> = [
  ["This saved check combines several target authorizations. Start a new scan to run each authorization independently.", "這項已保存的檢查合併了多個目標授權；請開始新的掃描，分別執行每個授權。"],
  ["report data exceeded the normalization memory boundary; check results are incomplete", "報告資料超過處理記憶體限制；檢查結果不完整"],
  ["adapter input exceeded the total byte limit; remaining raw artifacts were retained but not normalized", "轉接器輸入超過總位元組限制；其餘原始成品已保留，但未正規化"],
  ["adapter extraction reached the record safety boundary; completeness cannot be established", "轉接器擷取已達記錄安全界線；無法確認完整性"],
  ["adapter record limit reached; remaining raw records were retained but not normalized", "轉接器已達記錄限制；其餘原始記錄已保留，但未正規化"],
  ["adapter artifact-count limit reached; extra raw artifacts were retained but not normalized", "轉接器已達成品數量限制；額外的原始成品已保留，但未正規化"],
  ["an artifact path escaped the case artifact root and was rejected", "成品路徑超出案件成品根目錄，因此遭到拒絕"],
  ["the case artifact root could not be opened", "無法開啟案件成品根目錄"],
  ["an artifact path did not resolve inside the case artifact root", "成品路徑無法解析至案件成品根目錄內"],
  ["an artifact exceeded the byte limit while being read", "讀取成品時超過位元組限制"],
  ["an artifact length did not match its recorded evidence metadata", "成品長度與記錄的證據中繼資料不符"],
  ["an artifact hash did not match its recorded evidence metadata", "成品雜湊與記錄的證據中繼資料不符"],
  ["JSONL record limit reached; later lines remain only as raw evidence", "JSONL 已達記錄限制；後續行只保留為原始證據"],
  ["Nuclei execution evidence named an asset outside this engine task and was not counted", "Nuclei 執行證據指向這項引擎工作以外的資產，因此未納入計算"],
  ["ZAP expected one JSON report object", "ZAP 預期收到單一 JSON 報告物件"],
  ["ZAP observed no website responses; no passive security check could be confirmed", "ZAP 未取得網站回應，無法確認被動安全檢查已執行"],
  ["ZAP output lacked its site array; the raw artifact was retained, and the scan should be retried with the pinned JSON reporter", "ZAP 輸出缺少 site 陣列；原始成品已保留，請使用固定的 JSON 報告器重試"],
  ["Greenbone XML event limit reached; later results remain only as raw evidence", "Greenbone XML 已達事件限制；後續結果只保留為原始證據"],
  ["Greenbone XML containing a DTD or custom entity reference was rejected", "含有 DTD 或自訂實體參照的 Greenbone XML 已遭拒絕"],
  ["Greenbone XML nesting limit was exceeded; no XML findings were normalized", "Greenbone XML 超過巢狀層級限制；未正規化任何 XML 問題"],
  ["nested Greenbone result elements were rejected", "巢狀 Greenbone 結果元素已遭拒絕"],
  ["Greenbone result limit reached; later results remain only as raw evidence", "Greenbone 已達結果限制；後續結果只保留為原始證據"],
  ["Greenbone result had an invalid NVT OID", "Greenbone 結果含有無效的 NVT OID"],
  ["Greenbone reported that the host did not respond, so none of its vulnerability checks ran for that target", "Greenbone 回報主機沒有回應，因此該目標的弱點檢查一項都沒有執行"],
  ["Greenbone reported scanner errors for the target, so some of its checks did not finish", "Greenbone 回報該目標發生掃描工具錯誤，因此部分檢查沒有完成"],
  ["Greenbone result carried an unsupported upstream result type and was retained only as raw evidence", "Greenbone 結果帶有不支援的上游結果類型，只保留為原始證據"],
  ["Greenbone result lacked an upstream result type and a positive severity; it was retained only as raw evidence and this run cannot be treated as a clean result", "Greenbone 結果缺少上游結果類型與正的嚴重程度；只保留為原始證據，本輪不能視為乾淨的結果"],
  ["Greenbone reported a target it could not evaluate, but the result named no authorized asset; the raw artifact was retained", "Greenbone 回報了一個無法評估的目標，但該結果沒有指名任何已授權的資產；原始成品已保留"],
  ["an oversized Greenbone XML field was ignored", "已忽略過大的 Greenbone XML 欄位"],
  ["a Greenbone XML text field could not be decoded", "無法解碼 Greenbone XML 文字欄位"],
  ["a Greenbone XML field used an unsupported entity and was ignored", "Greenbone XML 欄位使用不支援的實體，因此已忽略"],
  ["a Greenbone XML CDATA field could not be decoded", "無法解碼 Greenbone XML CDATA 欄位"],
  ["a Greenbone XML processing instruction was ignored", "已忽略 Greenbone XML 處理指令"],
  ["an incomplete Greenbone result was retained only as raw evidence", "不完整的 Greenbone 結果只保留為原始證據"],
  ["Greenbone XML contained no complete bounded result records; no findings were inferred", "Greenbone XML 沒有完整且有界的結果記錄；未推斷任何問題"],
  ["top-level JSON record limit reached; later rows remain only as raw evidence", "頂層 JSON 已達記錄限制；後續資料列只保留為原始證據"],
  ["top-level JSON scalar was ignored", "已忽略頂層 JSON 純量"],
  ["Cloudsplaining results were not a single JSON object, so no policy findings could be read.", "Cloudsplaining 結果不是單一 JSON 物件，因此無法讀取原則問題。"],
  ["Cloudsplaining output links were not an object; findings were preserved without those references", "Cloudsplaining 輸出的 links 不是物件；問題已保留，但不含那些參照"],
  ["Cloudsplaining output lacked its required links object; findings were preserved without those references", "Cloudsplaining 輸出缺少必要的 links 物件；問題已保留，但不含那些參照"],
  ["Cloudsplaining principal context exceeded the bounded report budget; later findings retain policy and action details, while their complete AttachedTo values stay in raw evidence", "Cloudsplaining 主體資訊超過報告的有界容量；後續問題仍保留政策與動作資訊，完整 AttachedTo 值則保留在原始證據中"],
  ["Greenbone expected a bounded XML report", "Greenbone 預期收到有界的 XML 報告"],
  ["Semgrep expected a JSON document", "Semgrep 預期收到 JSON 文件"],
  ["Semgrep output had no results array", "Semgrep 輸出沒有 results 陣列"],
  ["Semgrep output lacked its required errors array; valid findings were preserved, but completeness cannot be established", "Semgrep 輸出缺少必要的 errors 陣列；有效問題已保留，但無法確認完整性"],
  ["Semgrep reported one or more scanner errors; valid findings were preserved, but the error details remain only in the raw artifact and completeness cannot be established", "Semgrep 回報一項或多項掃描工具錯誤；有效問題已保留，錯誤細節只留在原始成品中，且無法確認完整性"],
  ["Checkov expected a JSON document", "Checkov 預期收到 JSON 文件"],
  ["Checkov expected a JSON object or an array of framework result objects", "Checkov 預期收到一個 JSON 物件，或由各框架結果物件組成的陣列"],
  ["Checkov framework result limit reached; later framework results remain only as raw evidence", "Checkov 已達框架結果限制；後續框架結果只保留為原始證據"],
  ["Checkov failed-check record limit reached; later rows remain only as raw evidence", "Checkov 已達失敗檢查記錄限制；後續資料列只保留為原始證據"],
  ["KICS expected a JSON document", "KICS 預期收到 JSON 文件"],
  ["KICS output lacked its queries array; the raw artifact was retained", "KICS 輸出缺少 queries 陣列；原始成品已保留"],
  ["Trivy expected a JSON document", "Trivy 預期收到 JSON 文件"],
  ["Grype expected a JSON document", "Grype 預期收到 JSON 文件"],
  ["Kubescape expected a JSON document", "Kubescape 預期收到 JSON 文件"],
  ["Kubescape summaryDetails lacked its controls object; result processing is incomplete", "Kubescape 摘要缺少 controls 物件；結果處理不完整"],
  ["Kubescape summary control was not an object; result processing is incomplete", "Kubescape 摘要中的控制項不是物件；結果處理不完整"],
  ["Kubescape summary control lacked a valid control ID; result processing is incomplete", "Kubescape 摘要中的控制項缺少有效識別碼；結果處理不完整"],
  ["Kubescape output lacked its results array; result processing is incomplete", "Kubescape 輸出缺少 results 陣列；結果處理不完整"],
  ["Kubescape reported failing summary controls without matching resource findings; result processing is incomplete", "Kubescape 摘要回報控制項失敗，但缺少對應資源的問題記錄；結果處理不完整"],
  ["Kubescape output contained no evaluated resource controls; check coverage is incomplete", "Kubescape 輸出沒有已評估的資源控制項；檢查涵蓋不完整"],
  ["kube-bench expected a JSON document", "kube-bench 預期收到 JSON 文件"],
  ["Steampipe output was not its supported JSON document; the raw artifact was retained, and the inventory query should be retried", "Steampipe 輸出不是支援的 JSON 文件；原始成品已保留，請重試盤點查詢"],
  ["Steampipe output lacked its rows array; the raw artifact was retained, and the inventory query should be retried", "Steampipe 輸出缺少 rows 陣列；原始成品已保留，請重試盤點查詢"],
  ["Steampipe rows exceeded the record safety boundary; later inventory rows remain only as raw evidence", "Steampipe 資料列超過記錄安全界線；後續盤點資料列只保留為原始證據"],
  ["Agentic Radar output was not its supported JSON document; the raw artifact was retained, and workflow inventory is incomplete", "Agentic Radar 輸出不是支援的 JSON 文件；工作流程盤點不完整"],
  ["Agentic Radar output did not match the pinned schema and scanner version; the raw artifact was retained, and workflow inventory is incomplete", "Agentic Radar 輸出不符合支援的結構描述與掃描工具版本；工作流程盤點不完整"],
  ["Agentic Radar output lacked its framework; the raw artifact was retained, and workflow inventory is incomplete", "Agentic Radar 輸出缺少框架；工作流程盤點不完整"],
  ["Agentic Radar output named an unsupported framework; the raw artifact was retained, and workflow inventory is incomplete", "Agentic Radar 輸出指名不支援的框架；工作流程盤點不完整"],
  ["Agentic Radar output lacked its status; the raw artifact was retained, and workflow inventory is incomplete", "Agentic Radar 輸出缺少狀態；工作流程盤點不完整"],
  ["Agentic Radar output named an unsupported status; the raw artifact was retained, and workflow inventory is incomplete", "Agentic Radar 輸出指名不支援的狀態；工作流程盤點不完整"],
  ["Agentic Radar completeness did not agree with its structured warnings; the partial graph was retained, but workflow inventory is incomplete", "Agentic Radar 的完整性狀態與結構化警告不一致；工作流程盤點不完整"],
  ["Agentic Radar warnings exceeded the adapter safety boundary; later diagnostics remain only in the raw artifact", "Agentic Radar 警告超過結果處理安全界線；額外診斷未納入"],
  ["Agentic Radar output lacked its graph object; the raw artifact was retained, and workflow inventory is incomplete", "Agentic Radar 輸出缺少 graph 物件；工作流程盤點不完整"],
  ["Agentic Radar graph lacked its nodes array; the raw artifact was retained, and workflow inventory is incomplete", "Agentic Radar 圖缺少 nodes 陣列；工作流程盤點不完整"],
  ["Agentic Radar graph lacked its edges array; the raw artifact was retained, and workflow inventory is incomplete", "Agentic Radar 圖缺少 edges 陣列；工作流程盤點不完整"],
  ["Agentic Radar graph lacked its agents array; the raw artifact was retained, and workflow inventory is incomplete", "Agentic Radar 圖缺少 agents 陣列；工作流程盤點不完整"],
  ["Agentic Radar graph lacked its tools array; the raw artifact was retained, and workflow inventory is incomplete", "Agentic Radar 圖缺少 tools 陣列；工作流程盤點不完整"],
  ["Agentic Radar graph membership did not agree with its workflow status; the graph was retained, but workflow inventory is incomplete", "Agentic Radar 圖內容與工作流程狀態不一致；工作流程盤點不完整"],
  ["Agentic Radar agents exceeded the record safety boundary; later agent metadata remains only in the raw artifact", "Agentic Radar agents 超過記錄安全界線；額外代理中繼資料未納入"],
  ["Agentic Radar edges exceeded the record safety boundary; later relationships remain only in the raw artifact", "Agentic Radar edges 超過記錄安全界線；額外關係未納入"],
  ["MCP Armor output was not its supported configuration-only JSON document; result processing is incomplete", "MCP Armor 輸出不是支援的僅設定 JSON 文件；結果處理不完整"],
  ["MCP Armor output did not match the supported configuration-only schema, scanner version, and mode; result processing is incomplete", "MCP Armor 輸出不符合支援的僅設定結構描述、掃描工具版本與模式；結果處理不完整"],
  ["MCP Armor input counts did not describe the one approved configuration snapshot; result processing is incomplete", "MCP Armor 輸入計數不符合唯一一份已核准設定快照；結果處理不完整"],
  ["MCP Armor output lacked its completeness flag; result processing is incomplete", "MCP Armor 輸出缺少完整性旗標；結果處理不完整"],
  ["MCP Armor warnings exceeded the result safety boundary; additional diagnostics excluded", "MCP Armor 警告超過結果安全界線；額外診斷未納入"],
  ["MCP Armor output lacked its structured warnings array; result processing is incomplete", "MCP Armor 輸出缺少結構化警告陣列；結果處理不完整"],
  ["MCP Armor check ledger did not contain exactly the two supported configuration checks; result processing is incomplete", "MCP Armor 檢查清冊未恰好包含兩項支援的設定檢查；結果處理不完整"],
  ["MCP Armor output lacked its check ledger; result processing is incomplete", "MCP Armor 輸出缺少檢查清冊；結果處理不完整"],
  ["MCP Armor output lacked its findings array; result processing is incomplete", "MCP Armor 輸出缺少問題陣列；結果處理不完整"],
  ["MCP Armor findings exceeded the result safety boundary; additional findings remain only in raw evidence", "MCP Armor 問題超過結果安全界線；額外問題未納入"],
  ["MCP Armor reported incomplete configuration coverage without a usable structured warning", "MCP Armor 回報設定涵蓋不完整，但沒有可用的結構化警告"],
  ["MCP Armor completeness did not agree with its input and check ledger; result processing is incomplete", "MCP Armor 的完整性狀態與輸入及檢查清冊不一致；結果處理不完整"],
  ["Runtime object ownership is unavailable. Retry uses a new isolated attempt.", "無法確認執行階段物件的所有權；重試會使用新的隔離嘗試。"],
  ["Scan batch stopped. Unfinished work: not tested.", "掃描批次已停止；未完成工作：未檢測。"],
  ["Scan cancelled. Remaining planned work: not tested.", "掃描已取消；其餘規劃工作：未檢測。"],
  ["Framework relationships are unavailable because the saved mapping identity differs from the installed mapping.", "已保存的對照識別資料與已安裝對照不同，因此無法使用框架關聯。"],
  ["Result processing stopped. Start a new scan with the current result reader.", "結果處理已停止；請使用目前的結果讀取器開始新的掃描。"],
  ["Result processing is incomplete. This check is Partial.", "結果處理未完成；這項檢查為部分完成。"],
  ["Automatic cleanup stopped: exact runtime ownership is unavailable.", "自動清理已停止：無法確認執行階段的確切所有權。"],
  ["This saved check no longer matches its original target plan. Start a new scan for this check.", "這項已保存的檢查已不符合原始目標計畫；請為此檢查開始新的掃描。"],
  ["Coverage verification failed for this attempt. Retry this check.", "本次嘗試的涵蓋驗證失敗；請重試這項檢查。"],
  ["Greenbone XML element exceeded the attribute limit", "Greenbone XML 元素超過屬性限制"],
  ["Greenbone XML contained a malformed attribute", "Greenbone XML 含有格式錯誤的屬性"],
  ["Greenbone XML attribute decode failed", "Greenbone XML 屬性解碼失敗"],
  ["This check completed with coverage gaps after one automatic retry per unfinished item. Start a new scan to retry the remaining items.", "每個未完成項目自動重試一次後，這項檢查仍有涵蓋缺口。請開始新的掃描以重試剩餘項目。"],
  ["The installed version does not include this check. Update the app, then start a new scan.", "已安裝版本不包含這項檢查；請更新應用程式後開始新的掃描。"],
  ["The installed result reader cannot continue processing this check. Start a new scan for a fresh result.", "已安裝的結果讀取器無法繼續處理這項檢查；請開始新的掃描。"],
  ["A newer scan state replaced this continuation. Start a new scan for the remaining coverage.", "較新的掃描狀態已取代本次續跑；請為剩餘涵蓋開始新的掃描。"],
  ["This version cannot run the older request. Start a new scan with the current bounded network path.", "目前版本無法執行舊版請求；請使用目前有界的網路路徑開始新的掃描。"],
  ["Reconnect target access for this check, then continue the scan.", "請重新連接這項檢查的目標存取權，再繼續掃描。"],
  ["Saved target access differs from the original scan. Reconnect that target, then start a new scan.", "已保存的目標存取權與原始掃描不同；請重新連接該目標後開始新的掃描。"],
  ["A new bounded scan batch replaced the older request and will continue.", "新的有界掃描批次已取代舊版請求，並會繼續執行。"],
  ["Framework relationships are unavailable for this run because mapping was unavailable during planning.", "規劃時無法取得對照，因此本輪沒有框架關聯。"],
];

/**
 * The counted shortfall descriptions the scanner adapters join into the
 * "did not evaluate every control" disclosure. The report states the same
 * counts beside the result they qualify, so both read one table. An older
 * build's "reserved for manual review" is renamed before this is consulted.
 */
export const recognizedShortfallDescriptionZhTW = (description: string): string | undefined =>
  UNEVALUATED_CONTROL_KINDS.find(([english]) => english === description)?.[1];

const frame = (value: string, expression: RegExp, render: (...values: string[]) => string): string | undefined => {
  const match = value.match(expression);
  return match ? render(...match.slice(1)) : undefined;
};

const normalizeLegacyEngineWarning = (warning: string): string => {
  const normalized = warning
    .replace(
      "Greenbone XML attribute could not be decoded safely",
      "Greenbone XML attribute decode failed",
    )
    .replaceAll(
      "reserved for manual review",
      "left without an automated verdict",
    );
  if (normalized.startsWith("An existing runtime object could not be proven")) {
    return "Runtime object ownership is unavailable. Retry uses a new isolated attempt.";
  }
  if (normalized.startsWith("This scan batch stopped after saving output.")) {
    return "Scan batch stopped. Unfinished work: not tested.";
  }
  if (normalized.startsWith("You stopped this scan after the current batch was saved.")) {
    return "Scan cancelled. Remaining planned work: not tested.";
  }
  if (normalized.startsWith("Framework relationships were omitted because")) {
    return "Framework relationships are unavailable because the saved mapping identity differs from the installed mapping.";
  }
  if (normalized.includes("start a new scan to use the current result reader")) {
    return "Result processing stopped. Start a new scan with the current result reader.";
  }
  if (normalized.includes("clearly marked partial")) {
    return "Result processing is incomplete. This check is Partial.";
  }
  if (normalized.startsWith("Automatic cleanup was skipped because")) {
    return "Automatic cleanup stopped: exact runtime ownership is unavailable.";
  }
  if (normalized.startsWith("This saved check could not be safely matched")) {
    return "This saved check no longer matches its original target plan. Start a new scan for this check.";
  }
  if (normalized.includes("tested coverage could not be verified")) {
    return "Coverage verification failed for this attempt. Retry this check.";
  }
  if (normalized.startsWith("This check finished with partial results after each unfinished item")) {
    return "This check completed with coverage gaps after one automatic retry per unfinished item. Start a new scan to retry the remaining items.";
  }
  if (normalized.startsWith("This check is not available in the installed version.")) {
    return "The installed version does not include this check. Update the app, then start a new scan.";
  }
  if (normalized.includes("installed result reader cannot safely continue")) {
    return "The installed result reader cannot continue processing this check. Start a new scan for a fresh result.";
  }
  if (normalized.includes("continuation race")) {
    return "A newer scan state replaced this continuation. Start a new scan for the remaining coverage.";
  }
  if (normalized.includes("current bounded network path")) {
    return "This version cannot run the older request. Start a new scan with the current bounded network path.";
  }
  if (normalized.startsWith("This check needs renewed target access")) {
    return "Reconnect target access for this check, then continue the scan.";
  }
  if (normalized.includes("saved target access no longer matches")) {
    return "Saved target access differs from the original scan. Reconnect that target, then start a new scan.";
  }
  if (normalized.startsWith("An older scan request was preserved")) {
    return "A new bounded scan batch replaced the older request and will continue.";
  }
  if (normalized.startsWith("Framework mapping was unavailable while this run was planned.")) {
    return "Framework relationships are unavailable for this run because mapping was unavailable during planning.";
  }
  const legacyAdapterMismatch = normalized.match(
    /^(.+) adapter was given a document declaring engine (.+); nothing was normalized from it$/u,
  );
  if (legacyAdapterMismatch) {
    return `${legacyAdapterMismatch[1]} adapter input mismatch: document declares engine ${legacyAdapterMismatch[2]}`;
  }
  const releaseMismatch = normalized.match(
    /^Engine (.+) was not resumed: its frozen release identity differs from the installed release \((.+)\), and (.+)\. Start a new scan/u,
  );
  if (releaseMismatch) {
    return `Engine ${releaseMismatch[1]} uses different release settings (${releaseMismatch[2]}), and ${releaseMismatch[3]}. Start a new scan with the installed release.`;
  }
  const capturedOnly = normalized.match(
    /^The frozen release identity differs from the installed release \((.+)\)\. Resume was allowed only because/u,
  );
  if (capturedOnly) {
    return `Release settings differ (${capturedOnly[1]}). Verified empty JSONL result processing continued without scanner execution or mapping changes.`;
  }
  return normalized;
};

const directEngineWarningEnglish = (warning: string): string => {
  if (warning === "garak native run lacks a matching terminal completion; evaluated sibling results were retained") {
    return "Garak model check incomplete: the run did not finish.";
  }
  if (warning === "garak native profile did not evaluate all 54 approved prompts; evaluated sibling results were retained") {
    return "Garak model check incomplete: not all 54 test prompts were evaluated.";
  }
  if (warning.startsWith("MCP Armor")) {
    return warning
      .replace("pinned check shape", "supported check shape")
      .replace("; additional findings remain only in raw evidence", "; additional findings excluded");
  }
  if (warning.startsWith("Agentic Radar")) {
    return warning
      .replace("did not match the pinned", "did not match the supported")
      .replace("adapter safety boundary", "result safety boundary")
      .replace("; the raw artifact was retained, and workflow inventory is incomplete", "; workflow inventory is incomplete")
      .replace("; the partial graph was retained, but workflow inventory is incomplete", "; workflow inventory is incomplete")
      .replace("; the partial graph was retained", "; workflow inventory is incomplete")
      .replace("; the graph was retained, but workflow inventory is incomplete", "; workflow inventory is incomplete")
      .replace("; later diagnostics remain only in the raw artifact", "; additional diagnostics excluded")
      .replace("; later components remain only in the raw artifact", "; additional components excluded")
      .replace("; later agent metadata remains only in the raw artifact", "; additional agent metadata excluded")
      .replace("; later relationships remain only in the raw artifact", "; additional relationships excluded")
      .replace("; they were ignored, and workflow inventory is incomplete", "; claims excluded; workflow inventory is incomplete");
  }
  if (warning === "Greenbone result lacked an upstream result type and a positive severity; it was retained only as raw evidence and this run cannot be treated as a clean result") {
    return "Greenbone result excluded: upstream result type and positive severity missing. Check result incomplete.";
  }
  if (warning === "Greenbone reported a target it could not evaluate, but the result named no authorized asset; the raw artifact was retained") {
    return "Greenbone result excluded: no authorized asset identified.";
  }
  if (warning === "Greenbone XML contained no complete bounded result records; no findings were inferred") {
    return "Greenbone result processing incomplete: no complete bounded result records.";
  }
  if (warning === "Semgrep output lacked its required errors array; valid findings were preserved, but completeness cannot be established") {
    return "Semgrep results incomplete: required errors array missing.";
  }
  if (warning === "Semgrep reported one or more scanner errors; valid findings were preserved, but the error details remain only in the raw artifact and completeness cannot be established") {
    return "Semgrep results incomplete: scanner errors reported.";
  }
  if (warning === "Cloudsplaining principal context exceeded the bounded report budget; later findings retain policy and action details, while their complete AttachedTo values stay in raw evidence") {
    return "Cloudsplaining principal attribution incomplete: report limit reached.";
  }
  const missingAdapter = warning.match(
    /^scanner output was captured, but no verified adapter is registered for (.+) version (.+)$/u,
  );
  if (missingAdapter) {
    return `${missingAdapter[1]} ${missingAdapter[2]} results unavailable: unsupported result format.`;
  }
  const invalidAdapter = warning.match(
    /^scanner output was captured, but adapter (.+) version (.+) failed validation$/u,
  );
  if (invalidAdapter) {
    return `${invalidAdapter[1]} ${invalidAdapter[2]} result processing failed.`;
  }
  const missingResultCount = warning.match(
    /^(.+) document did not declare how many results it normalized, so nothing can confirm none were lost$/u,
  );
  if (missingResultCount) {
    return `${missingResultCount[1]} document omitted its normalized result count; result completeness unknown.`;
  }
  const launcherCoverage = warning.match(
    /^Captured launcher coverage remained unverified after restart \((.+)\); no unverified work was counted as tested\.$/u,
  );
  if (launcherCoverage) {
    return `Launcher coverage verification failed after restart (${launcherCoverage[1]}).`;
  }
  const tenantDispute = warning.match(
    /^the tenant's ScubaGear configuration disputes the result of (.+) (.+); they are reported on ScubaGear's own determination and tagged tenant-disputed rather than suppressed$/u,
  );
  if (tenantDispute) {
    return `ScubaGear marked ${tenantDispute[1]} ${tenantDispute[2]} tenant-disputed.`;
  }
  const findingLimit = warning.match(
    /^Cloudsplaining reported (\d+) valid policy findings; the bounded report retained (\d+) in Critical, High, Medium, Unknown, Low, then Informational order, and (\d+) remain only in raw evidence$/u,
  );
  if (findingLimit) {
    return `Cloudsplaining report limit reached: ${findingLimit[2]} of ${findingLimit[1]} findings included; ${findingLimit[3]} excluded.`;
  }

  return warning
    .replace(/^(.+) adapter input mismatch: document declares engine (.+)$/u, "$1 results unavailable: document declares engine $2")
    .replace(/^adapter /u, "result processing ")
    .replace(
      "output is inventory evidence; no security issue was invented from inventory rows",
      "output contains inventory, not security findings",
    )
    .replace("did not match the pinned", "did not match the supported")
    .replace("; remaining raw artifacts were retained but not normalized", "; normalized output incomplete")
    .replace("; remaining raw records were retained but not normalized", "; normalized output incomplete")
    .replace("; extra raw artifacts were retained but not normalized", "; normalized output incomplete")
    .replace(/; later ([^;]+) remain only as raw evidence$/u, "; later $1 were not normalized")
    .replace(/ and remains only as raw evidence$/u, " and was not normalized")
    .replace(/ and was retained only as raw evidence$/u, " and was not normalized")
    .replace(/; it was retained only as raw evidence$/u, "; it was not normalized")
    .replace(/ was retained only as raw evidence$/u, " was not normalized")
    .replace(
      /; the raw (?:artifact|record) was retained, and the scan should be retried with (.+)$/u,
      "; retry with $1",
    )
    .replace(
      "; the raw artifact was retained, and the inventory query should be retried",
      "; retry the inventory query",
    )
    .replace(
      /; retry with (?:the )?(?:supported )?pinned (?:Syft )?(?:JSONL output|JSON reporter)$/u,
      "; result excluded",
    )
    .replace(/; the raw (?:artifact|record|value) was retained$/u, "")
    .replace("; its metadata remains in the case", "")
    .replace("; valid sibling findings were preserved", "")
    .replace("; findings were preserved without complete principal attribution", "; principal attribution incomplete")
    .replace("; valid principal names were preserved", "")
    .replace(
      "; bounded valid names were preserved and the remainder stays in raw evidence",
      "; principal attribution incomplete",
    )
    .replace("; a bounded display value was preserved", "; display value bounded")
    .replace(
      "; bounded valid actions were preserved and the complete list stays in raw evidence",
      "; finding actions incomplete",
    )
    .replace("; findings were preserved without those references", "; references unavailable")
    .replace("; findings were preserved without it", "; source description unavailable")
    .replace("; the finding was preserved without that reference", "; reference unavailable")
    .replace(". Raw target text is retained only as untrusted evidence.", ".")
    .replace("Earlier saved error classification was preserved for diagnosis:", "Earlier saved error classification:")
    .replace(
      "Result processing stopped. Start a new scan with the current result reader.",
      "Result processing stopped. Start a new scan.",
    )
    .replace(
      "The installed result reader cannot continue processing this check. Start a new scan for a fresh result.",
      "The installed version cannot process this saved check. Start a new scan.",
    )
    .replace(
      /^Engine (.+) uses knowledge dated (.+) whose declared support ended .+\. Execution retains this explicit stale-knowledge warning; its results must not be presented as current knowledge\.$/u,
      "Scanner $1 knowledge last updated $2.",
    )
    .replace(
      /Verified empty JSONL result processing continued without scanner execution or mapping changes\.$/u,
      "Empty JSONL result processing completed.",
    );
};

const directEngineWarningZhTW = (warning: string): string => {
  if (warning === "Greenbone 結果缺少上游結果類型與正的嚴重程度；只保留為原始證據，本輪不能視為乾淨的結果") {
    return "Greenbone 結果已排除：缺少上游結果類型與正的嚴重程度。檢查結果不完整。";
  }
  if (warning === "Greenbone XML 沒有完整且有界的結果記錄；未推斷任何問題") {
    return "Greenbone 結果處理不完整：沒有完整且有界的結果記錄。";
  }
  if (warning === "Cloudsplaining 主體資訊超過報告的有界容量；後續問題仍保留政策與動作資訊，完整 AttachedTo 值則保留在原始證據中") {
    return "Cloudsplaining 主體歸屬資訊不完整：已達報告限制。";
  }
  const findingLimit = warning.match(
    /^Cloudsplaining 回報 (\d+) 筆有效的 IAM 原則問題；有界報告依重大、高、中、未知、低、資訊的優先順序保留 (\d+) 筆，其餘 (\d+) 筆只保留在原始證據中$/u,
  );
  if (findingLimit) {
    return `Cloudsplaining 已達報告限制：${findingLimit[1]} 筆問題中納入 ${findingLimit[2]} 筆，排除 ${findingLimit[3]} 筆。`;
  }

  return warning
    .replace(/^(.+) 轉接器輸入不符：文件宣告掃描工具為 (.+)$/u, "$1 結果不可用：文件宣告掃描工具為 $2")
    .replace(/^轉接器/u, "結果處理")
    .replace(/^掃描工具輸出已擷取，但沒有為 (.+) (.+) 版登錄經驗證的轉接器$/u, "$1 $2 結果不可用：不支援的結果格式")
    .replace(/^掃描工具輸出已擷取，但 (.+) (.+) 版轉接器驗證失敗$/u, "$1 $2 結果處理失敗")
    .replace(/^(.+) 文件未宣告正規化的結果數量，因此無法確認沒有遺失$/u, "$1 文件缺少正規化結果數量；結果完整性未知")
    .replace(/^重新啟動後，擷取的啟動器涵蓋仍未驗證（(.+)）；未驗證的工作不會計為已檢測。$/u, "重新啟動後啟動器涵蓋驗證失敗（$1）。")
    .replace(/^租用戶的 ScubaGear 設定對 (.+) (.+) 的結果有異議；系統依 ScubaGear 本身的判定回報，並標記為租用戶異議，而不是隱藏$/u, "ScubaGear 將 $1 $2 標記為租用戶異議。")
    .replace("輸出是資產清冊證據；未從清冊資料列臆造安全問題", "輸出是資產清冊，不是安全問題")
    .replace("；其餘原始成品已保留，但未正規化", "；正規化輸出不完整")
    .replace("；其餘原始記錄已保留，但未正規化", "；正規化輸出不完整")
    .replace("；額外的原始成品已保留，但未正規化", "；正規化輸出不完整")
    .replace(/；後續([^；]+)只保留為原始證據$/u, "；後續$1未正規化")
    .replace(/，只保留為原始證據$/u, "，未正規化")
    .replace(/只保留在原始證據中$/u, "未正規化")
    .replace(/只保留為原始證據$/u, "未正規化")
    .replace(/；原始(?:成品|記錄)已保留，請/u, "；請")
    .replace(/；請使用(?:支援的)?固定的? (?:Syft )?(?:JSONL 輸出|JSON 報告器)重試$/u, "；該結果已排除")
    .replace(/；原始(?:成品|記錄|值)已保留$/u, "")
    .replace("；其中繼資料仍保留在案件中", "")
    .replace("；已保留其他有效問題", "")
    .replace("；問題已保留，但主體歸屬資訊不完整", "；主體歸屬資訊不完整")
    .replace("；已保留有效的主體名稱", "")
    .replace("；已保留有界的有效名稱，其餘仍在原始證據中", "；主體歸屬資訊不完整")
    .replace("；已保留有界的顯示值", "；顯示值已限制長度")
    .replace("；已保留有界的有效動作，完整清單仍在原始證據中", "；問題動作不完整")
    .replace("；問題已保留，但不含那些參照", "；參照不可用")
    .replace("；問題已保留，但不含該說明", "；來源說明不可用")
    .replace("；問題已保留，但不含該參照", "；參照不可用")
    .replace("；有效問題已保留，但無法確認完整性", "；結果不完整")
    .replace("；有效問題已保留，錯誤細節只留在原始成品中，且無法確認完整性", "；結果不完整")
    .replace("。原始目標文字只保留為不受信任的證據。", "。")
    .replace("已保留先前儲存的錯誤分類供診斷：", "先前儲存的錯誤分類：")
    .replace("結果處理已停止；請使用目前的結果讀取器開始新的掃描。", "結果處理已停止；請開始新的掃描。")
    .replace("已安裝的結果讀取器無法繼續處理這項檢查；請開始新的掃描。", "已安裝版本無法處理這項已保存的檢查；請開始新的掃描。")
    .replace("已驗證的空白 JSONL 結果已繼續處理，沒有重新執行掃描工具或變更對照。", "空白 JSONL 結果處理完成。");
};

export const recognizedEngineWarningZhTW = (warning: string): string | undefined => {
  const normalized = normalizeLegacyEngineWarning(warning);
  const fixed = FIXED_ENGINE_WARNINGS.find(([english]) => english === normalized)?.[1];
  if (fixed) return directEngineWarningZhTW(fixed);
  const rules: ReadonlyArray<readonly [RegExp, (...values: string[]) => string]> = [
    [/^MCP Armor warning at (.+) was malformed; result processing is incomplete$/u, (pointer) => `${pointer} 的 MCP Armor 警告格式錯誤；結果處理不完整`],
    [/^MCP Armor warning at (.+) lacked a bounded code; result processing is incomplete$/u, (pointer) => `${pointer} 的 MCP Armor 警告缺少有界代碼；結果處理不完整`],
    [/^MCP Armor warning at (.+) used an unsupported code; result processing is incomplete$/u, (pointer) => `${pointer} 的 MCP Armor 警告使用不支援的代碼；結果處理不完整`],
    [/^MCP Armor warning at (.+) lacked a bounded message; result processing is incomplete$/u, (pointer) => `${pointer} 的 MCP Armor 警告缺少有界訊息；結果處理不完整`],
    [/^MCP Armor warning at (.+) had invalid context; result processing is incomplete$/u, (pointer) => `${pointer} 的 MCP Armor 警告帶有無效的上下文；結果處理不完整`],
    [/^MCP Armor reported incomplete configuration coverage \((.+)\) for (.+)$/u, (code, context) => `MCP Armor 回報 ${context} 的設定涵蓋不完整（${code}）`],
    [/^MCP Armor check at (.+) was malformed; result processing is incomplete$/u, (pointer) => `${pointer} 的 MCP Armor 檢查格式錯誤；結果處理不完整`],
    [/^MCP Armor check at (.+) lacked a bounded id; result processing is incomplete$/u, (pointer) => `${pointer} 的 MCP Armor 檢查缺少有界識別碼；結果處理不完整`],
    [/^MCP Armor check at (.+) named an unsupported id; result processing is incomplete$/u, (pointer) => `${pointer} 的 MCP Armor 檢查指名不支援的識別碼；結果處理不完整`],
    [/^MCP Armor check (.+) had an unsupported status; result processing is incomplete$/u, (check) => `MCP Armor 檢查 ${check} 使用不支援的狀態；結果處理不完整`],
    [/^MCP Armor check (.+) lacked its finding count; result processing is incomplete$/u, (check) => `MCP Armor 檢查 ${check} 缺少問題計數；結果處理不完整`],
    [/^MCP Armor check (.+) exceeded the finding safety boundary; result processing is incomplete$/u, (check) => `MCP Armor 檢查 ${check} 超過問題安全界線；結果處理不完整`],
    [/^MCP Armor check (.+) reported findings without completing; result processing is incomplete$/u, (check) => `MCP Armor 檢查 ${check} 未完成卻回報問題；結果處理不完整`],
    [/^MCP Armor check ledger repeated (.+); result processing is incomplete$/u, (check) => `MCP Armor 檢查清冊重複列出 ${check}；結果處理不完整`],
    [/^MCP Armor did not complete configuration check (.+)$/u, (check) => `MCP Armor 未完成設定檢查 ${check}`],
    [/^MCP Armor check ledger lacked (.+); result processing is incomplete$/u, (check) => `MCP Armor 檢查清冊缺少 ${check}；結果處理不完整`],
    [/^MCP Armor finding at (.+) was malformed and was not normalized$/u, (pointer) => `${pointer} 的 MCP Armor 問題格式錯誤，因此未正規化`],
    [/^MCP Armor finding at (.+) lacked a bounded check id and was not normalized$/u, (pointer) => `${pointer} 的 MCP Armor 問題缺少有界檢查識別碼，因此未正規化`],
    [/^MCP Armor finding at (.+) named an unsupported check and was not normalized$/u, (pointer) => `${pointer} 的 MCP Armor 問題指名不支援的檢查，因此未正規化`],
    [/^MCP Armor finding at (.+) belonged to a check that did not complete and was not normalized$/u, (pointer) => `${pointer} 的 MCP Armor 問題屬於未完成的檢查，因此未正規化`],
    [/^MCP Armor finding at (.+) did not match its pinned check shape and was not normalized$/u, (pointer) => `${pointer} 的 MCP Armor 問題不符合支援的檢查格式，因此未正規化`],
    [/^MCP Armor finding at (.+) lacked a bounded configuration path and was not normalized$/u, (pointer) => `${pointer} 的 MCP Armor 問題缺少有界設定路徑，因此未正規化`],
    [/^MCP Armor finding at (.+) carried unsupported detail fields and was not normalized$/u, (pointer) => `${pointer} 的 MCP Armor 問題帶有不支援的詳細欄位，因此未正規化`],
    [/^MCP Armor finding at (.+) lacked a bounded server name and was not normalized$/u, (pointer) => `${pointer} 的 MCP Armor 問題缺少有界伺服器名稱，因此未正規化`],
    [/^MCP Armor finding at (.+) lacked bounded affected entities and was not normalized$/u, (pointer) => `${pointer} 的 MCP Armor 問題缺少有界受影響實體，因此未正規化`],
    [/^MCP Armor finding at (.+) lacked a bounded secret type and was not normalized$/u, (pointer) => `${pointer} 的 MCP Armor 問題缺少有界機密類型，因此未正規化`],
    [/^MCP Armor finding at (.+) lacked a valid line number and was not normalized$/u, (pointer) => `${pointer} 的 MCP Armor 問題缺少有效行號，因此未正規化`],
    [/^MCP Armor finding at (.+) lacked its redacted match marker and was not normalized$/u, (pointer) => `${pointer} 的 MCP Armor 問題缺少遮蔽後的比對標記，因此未正規化`],
    [/^MCP Armor finding at (.+) carried malformed permission evidence and was not normalized$/u, (pointer) => `${pointer} 的 MCP Armor 問題帶有格式錯誤的權限證據，因此未正規化`],
    [/^MCP Armor finding at (.+) carried no permission evidence and was not normalized$/u, (pointer) => `${pointer} 的 MCP Armor 問題沒有權限證據，因此未正規化`],
    [/^MCP Armor check (.+) finding count did not match its findings; result processing is incomplete$/u, (check) => `MCP Armor 檢查 ${check} 的問題計數與問題資料不一致；結果處理不完整`],
    [/^Agentic Radar warning at (.+) was malformed; the partial graph was retained$/u, (pointer) => `${pointer} 的 Agentic Radar 警告格式錯誤；工作流程盤點不完整`],
    [/^Agentic Radar warning at (.+) used an unsupported code; the partial graph was retained$/u, (pointer) => `${pointer} 的 Agentic Radar 警告使用不支援的代碼；工作流程盤點不完整`],
    [/^Agentic Radar warning at (.+) lacked a bounded message; the partial graph was retained$/u, (pointer) => `${pointer} 的 Agentic Radar 警告缺少有界訊息；工作流程盤點不完整`],
    [/^Agentic Radar reported incomplete workflow inventory: (.+)$/u, (message) => `Agentic Radar 回報工作流程盤點不完整：${message}`],
    [/^Agentic Radar (.+) exceeded the record safety boundary; later components remain only in the raw artifact$/u, (collection) => `Agentic Radar ${collection} 超過記錄安全界線；額外元件未納入`],
    [/^Agentic Radar component at (.+) was not an object and was not normalized$/u, (pointer) => `${pointer} 的 Agentic Radar 元件不是物件，因此未正規化`],
    [/^Agentic Radar component at (.+) lacked its node type and was not normalized$/u, (pointer) => `${pointer} 的 Agentic Radar 元件缺少節點類型，因此未正規化`],
    [/^Agentic Radar component at (.+) used an unsupported node type and was not normalized$/u, (pointer) => `${pointer} 的 Agentic Radar 元件使用不支援的節點類型，因此未正規化`],
    [/^Agentic Radar component at (.+) lacked its name and was not normalized$/u, (pointer) => `${pointer} 的 Agentic Radar 元件缺少名稱，因此未正規化`],
    [/^Agentic Radar agent at (.+) was not an object and was not normalized$/u, (pointer) => `${pointer} 的 Agentic Radar 代理不是物件，因此未正規化`],
    [/^Agentic Radar agent at (.+) lacked its name and was not normalized$/u, (pointer) => `${pointer} 的 Agentic Radar 代理缺少名稱，因此未正規化`],
    [/^Agentic Radar agent at (.+) had no bounded model identifier$/u, (pointer) => `${pointer} 的 Agentic Radar 代理沒有有界的模型識別碼`],
    [/^Agentic Radar agent at (.+) had an invalid guardrail flag$/u, (pointer) => `${pointer} 的 Agentic Radar 代理含有無效的護欄旗標`],
    [/^Agentic Radar relationship at (.+) was not an object and was not normalized$/u, (pointer) => `${pointer} 的 Agentic Radar 關係不是物件，因此未正規化`],
    [/^Agentic Radar relationship at (.+) lacked an endpoint and was not normalized$/u, (pointer) => `${pointer} 的 Agentic Radar 關係缺少端點，因此未正規化`],
    [/^Agentic Radar relationship at (.+) had no bounded condition$/u, (pointer) => `${pointer} 的 Agentic Radar 關係沒有有界的條件`],
    [/^Agentic Radar relationship at (.+) had an invalid condition$/u, (pointer) => `${pointer} 的 Agentic Radar 關係含有無效的條件`],
    [/^Agentic Radar record at (.+) carried vulnerability claims; they were ignored, and workflow inventory is incomplete$/u, (pointer) => `${pointer} 的 Agentic Radar 記錄帶有漏洞宣稱；該宣稱已排除，工作流程盤點不完整`],
    [/^Agentic Radar record at (.+) lacked its empty vulnerability array; workflow inventory is incomplete$/u, (pointer) => `${pointer} 的 Agentic Radar 記錄缺少空白的漏洞陣列；工作流程盤點不完整`],
    [/^(.+) produced no raw artifacts to normalize$/u, (engine) => `${engine} 未產生可正規化的原始成品`],
    [/^(.+) output is inventory evidence; no security issue was invented from inventory rows$/u, (engine) => `${engine} 輸出是資產清冊證據；未從清冊資料列臆造安全問題`],
    [/^artifact (.+) exceeded the per-file byte limit and was not parsed$/u, (id) => `成品 ${id} 超過單檔位元組限制，因此未解析`],
    [/^artifact (.+) could not be read; its metadata remains in the case$/u, (id) => `無法讀取成品 ${id}；其中繼資料仍保留在案件中`],
    [/^JSONL line (.+) exceeded the line limit and was skipped$/u, (line) => `JSONL 第 ${line} 行超過行限制，因此已略過`],
    [/^malformed JSONL line (.+) was skipped$/u, (line) => `已略過格式錯誤的 JSONL 第 ${line} 行`],
    [/^artifact (.+) was neither valid bounded JSON nor JSONL: (.+)$/u, (id, detail) => `成品 ${id} 既不是有效且有界的 JSON，也不是 JSONL：${detail}`],
    [/^artifact (.+) was neither valid bounded JSON nor JSONL$/u, (id) => `成品 ${id} 既不是有效且有界的 JSON，也不是 JSONL`],
    [/^Greenbone XML parsing stopped at byte (.+): (.+)$/u, (byte, detail) => `Greenbone XML 解析在位元組 ${byte} 停止：${detail}`],
    [/^non-object Prowler record at (.+) was skipped$/u, (pointer) => `已略過 ${pointer} 的非物件 Prowler 記錄`],
    [/^non-object Checkov framework result at (.+) was skipped$/u, (pointer) => `已略過 ${pointer} 的非物件 Checkov 框架結果`],
    [/^Checkov framework result at (.+) had no results object$/u, (pointer) => `${pointer} 的 Checkov 框架結果沒有 results 物件`],
    [/^Checkov results at (.+) were not an object$/u, (pointer) => `${pointer} 的 Checkov results 不是物件`],
    [/^Checkov output at (.+) was not an array$/u, (pointer) => `${pointer} 的 Checkov 輸出不是陣列`],
    [/^non-object Checkov failed check at (.+) was skipped$/u, (pointer) => `已略過 ${pointer} 的非物件 Checkov 失敗檢查`],
    [/^Checkov failed check at (.+) had no valid check_id and was skipped$/u, (pointer) => `已略過 ${pointer} 缺少有效 check_id 的 Checkov 失敗檢查`],
    [/^Prowler record at (.+) had no explicit failing status$/u, (pointer) => `${pointer} 的 Prowler 記錄沒有明確的失敗狀態`],
    [/^Prowler failure at (.+) lacked a check id$/u, (pointer) => `${pointer} 的 Prowler 失敗結果缺少檢查識別碼`],
    [/^Cloudsplaining policy section (.+) was not an object; valid sibling findings were preserved$/u, (section) => `Cloudsplaining 原則區段 ${section} 不是物件；已保留其他有效問題`],
    [/^Cloudsplaining output lacked required policy section (.+); valid sibling findings were preserved$/u, (section) => `Cloudsplaining 輸出缺少必要的原則區段 ${section}；已保留其他有效問題`],
    [/^Cloudsplaining policy at (.+) was not an object; valid sibling findings were preserved$/u, (pointer) => `${pointer} 的 Cloudsplaining 原則不是物件；已保留其他有效問題`],
    [/^Cloudsplaining policy at (.+) did not carry its required boolean is_excluded value and was retained only as raw evidence$/u, (pointer) => `${pointer} 的 Cloudsplaining 原則缺少必要的布林 is_excluded 值，因此只保留在原始證據中`],
    [/^Cloudsplaining policy at (.+) lacked its required AttachedTo object; findings were preserved without complete principal attribution$/u, (pointer) => `${pointer} 的 Cloudsplaining 原則缺少必要的 AttachedTo 物件；問題已保留，但主體歸屬資訊不完整`],
    [/^Cloudsplaining AttachedTo\.(.+) at (.+)\/AttachedTo was not an array; valid principal names were preserved$/u, (kind, pointer) => `${pointer}/AttachedTo 的 Cloudsplaining AttachedTo.${kind} 不是陣列；已保留有效的主體名稱`],
    [/^Cloudsplaining AttachedTo\.(.+) at (.+)\/AttachedTo contained invalid, overlong, or excess entries; bounded valid names were preserved and the remainder stays in raw evidence$/u, (kind, pointer) => `${pointer}/AttachedTo 的 Cloudsplaining AttachedTo.${kind} 含有無效、過長或超量項目；已保留有界的有效名稱，其餘仍在原始證據中`],
    [/^Cloudsplaining policy at (.+) had no bounded nonempty identity or name and was retained only as raw evidence$/u, (pointer) => `${pointer} 的 Cloudsplaining 原則沒有有界且非空的識別或名稱，因此只保留在原始證據中`],
    [/^Cloudsplaining policy identity at (.+) contained control characters or exceeded its presentation boundary; a bounded display value was preserved$/u, (pointer) => `${pointer} 的 Cloudsplaining 原則識別含有控制字元或超過顯示界線；已保留有界的顯示值`],
    [/^Cloudsplaining category at (.+) was not an object; valid sibling findings were preserved$/u, (pointer) => `${pointer} 的 Cloudsplaining 風險類別不是物件；已保留其他有效問題`],
    [/^Cloudsplaining policy at (.+) lacked category (.+); valid sibling findings were preserved$/u, (pointer, category) => `${pointer} 的 Cloudsplaining 原則缺少風險類別 ${category}；已保留其他有效問題`],
    [/^Cloudsplaining category at (.+) lacked its findings array; valid sibling findings were preserved$/u, (pointer) => `${pointer} 的 Cloudsplaining 風險類別缺少 findings 陣列；已保留其他有效問題`],
    [/^Cloudsplaining category at (.+) lacked its source severity; valid sibling findings were preserved$/u, (pointer) => `${pointer} 的 Cloudsplaining 風險類別缺少來源嚴重性；已保留其他有效問題`],
    [/^Cloudsplaining category at (.+) lacked its source description; findings were preserved without it$/u, (pointer) => `${pointer} 的 Cloudsplaining 風險類別缺少來源說明；問題已保留，但不含該說明`],
    [/^Cloudsplaining PrivilegeEscalation category at (.+) lacked its required links object; findings were preserved without those references$/u, (pointer) => `${pointer} 的 Cloudsplaining 權限提升類別缺少必要的 links 物件；問題已保留，但不含那些參照`],
    [/^Cloudsplaining category links at (.+) were not an object; findings were preserved without those references$/u, (pointer) => `${pointer} 的 Cloudsplaining 風險類別 links 不是物件；問題已保留，但不含那些參照`],
    [/^Cloudsplaining finding at (.+) did not match the pinned (.+) entry shape and was retained only as raw evidence$/u, (pointer, risk) => `${pointer} 的 Cloudsplaining 問題不符合此版本採用的 ${risk} 項目格式，因此只保留在原始證據中`],
    [/^Cloudsplaining finding at (.+) had no bounded nonempty identity and was retained only as raw evidence$/u, (pointer) => `${pointer} 的 Cloudsplaining 問題沒有有界且非空的識別，因此只保留在原始證據中`],
    [/^Cloudsplaining finding identity at (.+) contained control characters or exceeded its presentation boundary; a bounded display value was preserved$/u, (pointer) => `${pointer} 的 Cloudsplaining 問題識別含有控制字元或超過顯示界線；已保留有界的顯示值`],
    [/^Cloudsplaining finding actions at (.+) contained sanitized or excess values; bounded valid actions were preserved and the complete list stays in raw evidence$/u, (pointer) => `${pointer} 的 Cloudsplaining 問題動作含有經清理或超量的值；已保留有界的有效動作，完整清單仍在原始證據中`],
    [/^Cloudsplaining privilege-escalation finding at (.+) lacked its required method link; the finding was preserved without that reference$/u, (pointer) => `${pointer} 的 Cloudsplaining 權限提升問題缺少必要的方法參照連結；問題已保留，但不含該參照`],
    [/^Cloudsplaining action link for (.+) was malformed; the finding was preserved without that reference$/u, (action) => `Cloudsplaining 操作 ${action} 的參照連結格式錯誤；問題已保留，但不含該參照`],
    [/^Cloudsplaining reported (\d+) valid policy findings; the bounded report retained (\d+) in Critical, High, Medium, Unknown, Low, then Informational order, and (\d+) remain only in raw evidence$/u, (total, retained, omitted) => `Cloudsplaining 回報 ${total} 筆有效的 IAM 原則問題；有界報告依重大、高、中、未知、低、資訊的優先順序保留 ${retained} 筆，其餘 ${omitted} 筆只保留在原始證據中`],
    [/^(.+) adapter input mismatch: document declares engine (.+)$/u, (engine, declared) => `${engine} 轉接器輸入不符：文件宣告掃描工具為 ${declared}`],
    [/^(.+) document did not name the engine that wrote it; it was normalized but not verified as this engine's own output$/u, (engine) => `${engine} 文件未指明產生它的掃描工具；已正規化，但未驗證為該工具本身的輸出`],
    [/^(.+) document declared no Results list and was not normalized$/u, (engine) => `${engine} 文件未宣告 Results 清單，因此未正規化`],
    [/^(.+) reported writing (.+) normalized results but its Results list holds (.+)$/u, (engine, declared, actual) => `${engine} 回報寫入 ${declared} 筆正規化結果，但 Results 清單含有 ${actual} 筆`],
    [/^(.+) document did not declare how many results it normalized, so nothing can confirm none were lost$/u, (engine) => `${engine} 文件未宣告正規化的結果數量，因此無法確認沒有遺失`],
    [/^(.+) listed a result at (.+) that is not an object; it was not normalized$/u, (engine, pointer) => `${engine} 在 ${pointer} 列出的結果不是物件；因此未正規化`],
    [/^(.+) result at (.+) carried no recognizable status; it was not normalized$/u, (engine, pointer) => `${engine} 在 ${pointer} 的結果沒有可辨識的狀態；因此未正規化`],
    [/^(.+) evaluated result at (.+) lacked a rule id$/u, (engine, pointer) => `${engine} 在 ${pointer} 的已評估結果缺少規則識別碼`],
    [/^(.+) evaluated result at (.+) lacked a usable rule id$/u, (engine, pointer) => `${engine} 在 ${pointer} 的已評估結果缺少可用的規則識別碼`],
    [/^Naabu record at (.+) was not an object and was not normalized$/u, (pointer) => `${pointer} 的 Naabu 記錄不是物件，因此未正規化`],
    [/^Naabu record at (.+) had no bounded host and was not normalized$/u, (pointer) => `${pointer} 的 Naabu 記錄沒有有界的主機，因此未正規化`],
    [/^Naabu record at (.+) had no bounded port and was not normalized$/u, (pointer) => `${pointer} 的 Naabu 記錄沒有有界的連接埠，因此未正規化`],
    [/^HTTPx record at (.+) was not an object; retry with the supported pinned JSONL output$/u, (pointer) => `${pointer} 的 HTTPx 記錄不是物件；請使用支援的固定 JSONL 輸出重試`],
    [/^HTTPx record at (.+) lacked its target; the raw record was retained, and the scan should be retried with the supported pinned JSONL output$/u, (pointer) => `${pointer} 的 HTTPx 記錄缺少目標；原始記錄已保留，請使用支援的固定 JSONL 輸出重試`],
    [/^HTTPx record at (.+) lacked its HTTP status; the raw record was retained, and the scan should be retried with the supported pinned JSONL output$/u, (pointer) => `${pointer} 的 HTTPx 記錄缺少 HTTP 狀態；原始記錄已保留，請使用支援的固定 JSONL 輸出重試`],
    [/^Nuclei record at (.+) was not an object; retry with the supported pinned JSONL output$/u, (pointer) => `${pointer} 的 Nuclei 記錄不是物件；請使用支援的固定 JSONL 輸出重試`],
    [/^Nuclei record at (.+) lacked its template id; the raw record was retained, and the scan should be retried with the supported pinned JSONL output$/u, (pointer) => `${pointer} 的 Nuclei 記錄缺少範本識別碼；原始記錄已保留，請使用支援的固定 JSONL 輸出重試`],
    [/^Nuclei non-match at (.+) lacked a bounded template or normalized asset id; it was not accepted as execution evidence$/u, (pointer) => `${pointer} 的 Nuclei 未命中記錄缺少有界的範本識別碼或正規化資產識別碼，因此未被採納為執行證據`],
    [/^Nuclei record at (.+) had a malformed matcher status and was not normalized$/u, (pointer) => `${pointer} 的 Nuclei 記錄含有格式錯誤的比對狀態，因此未正規化`],
    [/^ZAP site at (.+) was not an object; the raw record was retained$/u, (pointer) => `${pointer} 的 ZAP 網站記錄不是物件；原始記錄已保留`],
    [/^ZAP site at (.+) lacked its alerts array; the raw record was retained$/u, (pointer) => `${pointer} 的 ZAP 網站記錄缺少 alerts 陣列；原始記錄已保留`],
    [/^ZAP alert at (.+) was not an object; the raw record was retained$/u, (pointer) => `${pointer} 的 ZAP 警示不是物件；原始記錄已保留`],
    [/^ZAP alert at (.+) lacked its pluginid; the raw record was retained$/u, (pointer) => `${pointer} 的 ZAP 警示缺少 pluginid；原始記錄已保留`],
    [/^ZAP alert at (.+) lacked its alert title; the raw record was retained$/u, (pointer) => `${pointer} 的 ZAP 警示缺少警示標題；原始記錄已保留`],
    [/^ZAP alert at (.+) lacked its riskcode; the raw record was retained$/u, (pointer) => `${pointer} 的 ZAP 警示缺少 riskcode；原始記錄已保留`],
    [/^ZAP alert at (.+) had an unsupported riskcode and was not normalized$/u, (pointer) => `${pointer} 的 ZAP 警示使用不支援的 riskcode，因此未正規化`],
    [/^ZAP alert at (.+) lacked its confidence; the raw record was retained$/u, (pointer) => `${pointer} 的 ZAP 警示缺少信賴度；原始記錄已保留`],
    [/^ZAP alert at (.+) had an unsupported confidence and was not normalized$/u, (pointer) => `${pointer} 的 ZAP 警示使用不支援的信賴度，因此未正規化`],
    [/^ZAP alert at (.+) lacked its instances array; the raw record was retained$/u, (pointer) => `${pointer} 的 ZAP 警示缺少 instances 陣列；原始記錄已保留`],
    [/^ZAP instance at (.+) was not an object; the raw record was retained$/u, (pointer) => `${pointer} 的 ZAP 執行個體不是物件；原始記錄已保留`],
    [/^ZAP instance at (.+) lacked its (.+); the raw record was retained$/u, (pointer, field) => `${pointer} 的 ZAP 執行個體缺少 ${field}；原始記錄已保留`],
    [/^Gitleaks output was not its supported JSON finding array; the raw artifact was retained, and the scan should be retried with the pinned JSON reporter$/u, () => `Gitleaks 輸出不是支援的 JSON 問題陣列；原始成品已保留，請使用固定的 JSON 報告器重試`],
    [/^Gitleaks finding at (.+) was not an object; the raw record was retained$/u, (pointer) => `${pointer} 的 Gitleaks 問題不是物件；原始記錄已保留`],
    [/^Gitleaks finding at (.+) lacked its RuleID; the raw record was retained, and the scan should be retried with the pinned JSON reporter$/u, (pointer) => `${pointer} 的 Gitleaks 問題缺少 RuleID；原始記錄已保留，請使用固定的 JSON 報告器重試`],
    [/^Semgrep finding at (.+) was not an object; the raw record was retained$/u, (pointer) => `${pointer} 的 Semgrep 問題不是物件；原始記錄已保留`],
    [/^Semgrep finding at (.+) lacked its check_id; the raw record was retained$/u, (pointer) => `${pointer} 的 Semgrep 問題缺少 check_id；原始記錄已保留`],
    [/^KICS query at (.+) was not an object; the raw record was retained$/u, (pointer) => `${pointer} 的 KICS 查詢不是物件；原始記錄已保留`],
    [/^KICS reported failures in (.+); review the scan evidence and retry the affected checks$/u, (field) => `KICS 的 ${field} 回報檢查失敗；請查看掃描證據並重試受影響的檢查`],
    [/^KICS (.+) counter was not a non-negative integer; scan completeness cannot be established$/u, (field) => `KICS 的 ${field} 計數格式不正確；無法確認掃描完整性`],
    [/^KICS query at (.+) lacked a valid query_id; the raw record was retained$/u, (pointer) => `${pointer} 的 KICS 查詢缺少有效的 query_id；原始記錄已保留`],
    [/^KICS query at (.+) lacked its files array; the raw record was retained$/u, (pointer) => `${pointer} 的 KICS 查詢缺少 files 陣列；原始記錄已保留`],
    [/^KICS file at (.+) was not an object; the raw record was retained$/u, (pointer) => `${pointer} 的 KICS 檔案記錄不是物件；原始記錄已保留`],
    [/^TruffleHog record at (.+) was not an object; retry with the supported pinned JSONL output$/u, (pointer) => `${pointer} 的 TruffleHog 記錄不是物件；請使用支援的固定 JSONL 輸出重試`],
    [/^TruffleHog record at (.+) lacked its detector identity; the raw record was retained, and the scan should be retried with the supported pinned JSONL output$/u, (pointer) => `${pointer} 的 TruffleHog 記錄缺少偵測器識別資料；原始記錄已保留，請使用支援的固定 JSONL 輸出重試`],
    [/^Trivy output lacked its Results array; the raw artifact was retained, and the scan should be retried with the pinned JSON reporter$/u, () => `Trivy 輸出缺少 Results 陣列；原始成品已保留，請使用固定的 JSON 報告器重試`],
    [/^Trivy (.+) at (.+) was not an object and remains only as raw evidence$/u, (recordKind, pointer) => `${pointer} 的 Trivy ${recordKind} 記錄不是物件，只保留為原始證據`],
    [/^Trivy (.+) at (.+) lacked its native rule id; the raw record was retained, and the scan should be retried with the pinned JSON reporter$/u, (recordKind, pointer) => `${pointer} 的 Trivy ${recordKind} 記錄缺少原生規則識別碼；原始記錄已保留，請使用固定的 JSON 報告器重試`],
    [/^Trivy result at (.+) was not an object; the raw record was retained$/u, (pointer) => `${pointer} 的 Trivy 結果不是物件；原始記錄已保留`],
    [/^Trivy (.+) at (.+) was present but not an array; the raw value was retained$/u, (category, pointer) => `${pointer} 的 Trivy ${category} 已存在但不是陣列；原始值已保留`],
    [/^Grype output lacked its matches array; the raw artifact was retained, and the scan should be retried with the pinned JSON reporter$/u, () => `Grype 輸出缺少 matches 陣列；原始成品已保留，請使用固定的 JSON 報告器重試`],
    [/^Grype match at (.+) was not an object; the raw record was retained$/u, (pointer) => `${pointer} 的 Grype 配對記錄不是物件；原始記錄已保留`],
    [/^Grype match at (.+) lacked vulnerability\.id; the raw record was retained$/u, (pointer) => `${pointer} 的 Grype 配對記錄缺少 vulnerability.id；原始記錄已保留`],
    [/^kube-bench output lacked its Controls array; the raw artifact was retained, and the scan should be retried with the pinned JSON reporter$/u, () => `kube-bench 輸出缺少 Controls 陣列；原始成品已保留，請使用固定的 JSON 報告器重試`],
    [/^Kubescape result at (.+) was not an object; result processing is incomplete$/u, (pointer) => `${pointer} 的 Kubescape 結果不是物件；結果處理不完整`],
    [/^Kubescape result at (.+) had an invalid controls array; result processing is incomplete$/u, (pointer) => `${pointer} 的 Kubescape 結果含有無效的 controls 陣列；結果處理不完整`],
    [/^Kubescape control at (.+) was not an object; result processing is incomplete$/u, (pointer) => `${pointer} 的 Kubescape 控制項不是物件；結果處理不完整`],
    [/^Kubescape control at (.+) lacked its controlID; result processing is incomplete$/u, (pointer) => `${pointer} 的 Kubescape 控制項缺少 controlID；結果處理不完整`],
    [/^Kubescape control at (.+) lacked a supported status; result processing is incomplete$/u, (pointer) => `${pointer} 的 Kubescape 控制項缺少支援的狀態；結果處理不完整`],
    [/^Kubescape control at (.+) was not evaluated; check coverage is incomplete$/u, (pointer) => `${pointer} 的 Kubescape 控制項未完成評估；檢查涵蓋不完整`],
    [/^garak output contained no eval rows, so no probe result was evaluated$/u, () => `garak 輸出沒有任何評估列，因此沒有任何探測結果被評估`],
    [/^garak native run lacks a matching terminal completion; evaluated sibling results were retained$/u, () => "Garak 模型檢查未完成：執行尚未結束。"],
    [/^garak native profile did not evaluate all 54 approved prompts; evaluated sibling results were retained$/u, () => "Garak 模型檢查未完成：尚未評估全部 54 個測試提示。"],
    [/^garak eval row at (.+) counted more failures than evaluated attempts; the rate was not shown$/u, (pointer) => `${pointer} 的 garak 評估列所記的失敗次數多於已評估的嘗試次數；因此未顯示比率`],
    [/^garak eval row at (.+) did not name both its probe and its detector; the raw record was retained$/u, (pointer) => `${pointer} 的 garak 評估列未同時載明探測項目與偵測器；原始記錄已保留`],
    [/^garak eval row at (.+) carried no failure count; the raw record was retained$/u, (pointer) => `${pointer} 的 garak 評估列未提供失敗次數；原始記錄已保留`],
    [/^CloudQuery artifact basename was not one of the fixed seven IAM tables; it was retained only as raw evidence$/u, () => `CloudQuery 成品名稱不屬於固定的七個 IAM 資料表；只保留為原始證據`],
    [/^CloudQuery inventory record at (.+) was not an object and was not normalized$/u, (pointer) => `${pointer} 的 CloudQuery 盤點記錄不是物件，因此未正規化`],
    [/^CloudQuery inventory record at (.+) lacked its account_id and was not normalized$/u, (pointer) => `${pointer} 的 CloudQuery 盤點記錄缺少 account_id，因此未正規化`],
    [/^Steampipe inventory record at (.+) was not an object and was not normalized$/u, (pointer) => `${pointer} 的 Steampipe 盤點記錄不是物件，因此未正規化`],
    [/^Steampipe inventory record at (.+) lacked its account identifier and was not normalized$/u, (pointer) => `${pointer} 的 Steampipe 盤點記錄缺少帳號識別碼，因此未正規化`],
    [/^Steampipe inventory record at (.+) did not identify an aws_iam_user and was not normalized$/u, (pointer) => `${pointer} 的 Steampipe 盤點記錄未識別為 aws_iam_user，因此未正規化`],
    [/^Steampipe inventory record at (.+) carried an IAM user ARN outside its declared account and was not normalized$/u, (pointer) => `${pointer} 的 Steampipe 盤點記錄所含的 IAM 使用者 ARN 不屬於其宣告的帳號，因此未正規化`],
    [/^Steampipe inventory record at (.+) was not the supported legacy IAM-user shape and was not normalized$/u, (pointer) => `${pointer} 的 Steampipe 盤點記錄不符合支援的舊版 IAM 使用者格式，因此未正規化`],
    [/^Steampipe inventory record at (.+) lacked its IAM user ARN or user_id and was not normalized$/u, (pointer) => `${pointer} 的 Steampipe 盤點記錄未提供 IAM 使用者 ARN，也未提供 user_id，因此未正規化`],
    [/^Syft output was not its supported JSON document; the raw artifact was retained, and the scan should be retried with the pinned Syft JSON reporter$/u, () => `Syft 輸出不是支援的 JSON 文件；原始成品已保留，請使用固定的 Syft JSON 報告器重試`],
    [/^Syft output lacked its artifacts array; the raw artifact was retained, and the scan should be retried with the pinned Syft JSON reporter$/u, () => `Syft 輸出缺少 artifacts 陣列；原始成品已保留，請使用固定的 Syft JSON 報告器重試`],
    [/^Syft component at (.+) was not an object and was not normalized$/u, (pointer) => `${pointer} 的 Syft 元件不是物件，因此未正規化`],
    [/^Syft component at (.+) lacked its name and was not normalized$/u, (pointer) => `${pointer} 的 Syft 元件缺少名稱，因此未正規化`],
    [/^inventory record named an asset outside this engine task and was not normalized$/u, () => `盤點記錄指向這項掃描任務以外的資產，因此未正規化`],
    [/^inventory record matched an ambiguous native asset identifier and was not normalized$/u, () => `盤點記錄對應到有歧義的原生資產識別碼，因此未正規化`],
    [/^inventory record had no exact authorized provider identifier match and was not normalized$/u, () => `盤點記錄沒有完全相符的已授權供應商識別碼，因此未正規化`],
    [/^inventory record carried no asset identifier in a multi-asset task and was not normalized$/u, () => `多資產任務的盤點記錄未附資產識別碼，因此未正規化`],
    [/^Greenbone result (.+) lacked a valid NVT OID or CVE and was not normalized$/u, (id) => `Greenbone 結果 ${id} 缺少有效的 NVT OID 或 CVE，因此未正規化`],
    [/^record (.+) matched an ambiguous native asset identifier and was not normalized$/u, (rule) => `記錄 ${rule} 對應到有歧義的原生資產識別碼，因此未正規化`],
    [/^record (.+) had no exact authorized provider identifier match and was not normalized$/u, (rule) => `記錄 ${rule} 沒有完全相符的已授權供應商識別碼，因此未正規化`],
    [/^record (.+) could not be mapped unambiguously to an authorized asset and was not normalized$/u, (rule) => `記錄 ${rule} 無法明確對應到已授權資產，因此未正規化`],
    [/^(.+) did not evaluate every control in scope \((.+)\); those controls are absent from findings and this run does not establish their state$/u, (engine, controls) => `${engine} 未評估範圍內的所有控制措施（${unevaluatedControlItemsZhTW(controls)}）；這些控制措施未列於問題中，本輪也無法確認其狀態`],
    [/^scanner output was captured, but no verified adapter is registered for (.+) version (.+)$/u, (engine, version) => `掃描工具輸出已擷取，但沒有為 ${engine} ${version} 版登錄經驗證的轉接器`],
    [/^scanner output was captured, but adapter (.+) version (.+) failed validation$/u, (engine, version) => `掃描工具輸出已擷取，但 ${engine} ${version} 版轉接器驗證失敗`],
    [/^Zeroized and removed (.+) crash-left credential envelope\(s\) from this exact execution attempt\.$/u, (count) => `已從這次確切執行嘗試中清零並移除 ${count} 個因當機遺留的認證封套。`],
    [/^Zeroized and removed (.+) leftover credential envelope\(s\) from this exact execution attempt\.$/u, (count) => `已從這次確切執行嘗試中清零並移除 ${count} 個殘留的認證封套。`],
    [/^Captured launcher coverage remained unverified after restart \((.+)\); no unverified work was counted as tested\.$/u, (reason) => `重新啟動後，擷取的啟動器涵蓋仍未驗證（${reason}）；未驗證的工作不會計為已檢測。`],
    [/^Earlier saved error classification was preserved for diagnosis: (.+)\.$/u, (code) => `已保留先前儲存的錯誤分類供診斷：${code}。`],
    [/^the tenant's ScubaGear configuration disputes the result of (.+) (.+); they are reported on ScubaGear's own determination and tagged tenant-disputed rather than suppressed$/u, (count) => `租用戶的 ScubaGear 設定對 ${count} 個控制措施的結果有異議；系統依 ScubaGear 本身的判定回報，並標記為租用戶異議，而不是隱藏`],
    [/^Engine (.+) uses knowledge dated (.+) whose declared support ended .+\. Execution retains this explicit stale-knowledge warning; its results must not be presented as current knowledge\.$/u, (engine, date) => `掃描工具 ${engine} 知識最後更新：${date}。`],
    [/^Engine (.+) uses different release settings \((.+)\), and (.+)\. Start a new scan with the installed release\.$/u, (engine, differences, reason) => `掃描工具 ${engine} 使用不同的版本設定（${differences}），且${reason}。請使用已安裝版本開始新的掃描。`],
    [/^Release settings differ \((.+)\)\. Verified empty JSONL result processing continued without scanner execution or mapping changes\.$/u, (differences) => `版本設定不同（${differences}）。已驗證的空白 JSONL 結果已繼續處理，沒有重新執行掃描工具或變更對照。`],
  ];
  for (const [expression, render] of rules) {
    const translated = frame(normalized, expression, render);
    if (translated) return directEngineWarningZhTW(translated);
  }
  return undefined;
};

export const localizedEngineWarning = (warning: string, locale: Locale): string => {
  const normalized = normalizeLegacyEngineWarning(warning);
  return locale !== "zh-TW"
    ? directEngineWarningEnglish(normalized)
    : recognizedEngineWarningZhTW(normalized) ?? directEngineWarningEnglish(normalized);
};
