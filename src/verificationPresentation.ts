import type { Locale } from "./i18n/core";
import type { FindingDiffReasonCode } from "./types";

export interface ComparisonLimitation {
  code: FindingDiffReasonCode;
  engineId?: string;
}

interface FindingDiffReasonPresentation {
  code: FindingDiffReasonCode;
  engineId?: string;
  assetId?: string;
  detail: string;
}

interface FindingDiffPresentationInput {
  explanation: string;
  comparisonStatus?: string;
  beforeSeverity?: unknown;
  afterSeverity?: unknown;
  changeReasons?: readonly FindingDiffReasonPresentation[];
}

/**
 * Human labels for every comparison-reason code this build understands.
 * Kept in this screen-only module because the HTML report does not render a
 * finding diff explanation.
 */
const reasonLabelsZhTW: Readonly<Record<FindingDiffReasonCode, string>> = {
  coordinate_not_completed: "掃描座標未完成",
  comparison_identity_missing: "比較識別資料缺失",
  scope_contract_changed: "範圍、權限或目標合約有變更",
  manifest_schema_changed: "清單結構版本有變更",
  engine_version_changed: "掃描工具版本有變更",
  image_changed: "映像來源或不可變摘要有變更",
  rule_version_changed: "規則或範本版本有變更",
  knowledge_input_changed: "資料庫、資訊來源或知識時間範圍有變更",
  adapter_version_changed: "轉接器版本有變更",
  source_revision_changed: "來源修訂版本有變更",
  repository_changed: "來源儲存庫有變更",
  distribution_mode_changed: "發佈模式有變更",
  command_changed: "掃描工具命令合約有變更",
  mapping_version_changed: "控制對照目錄版本或正式來源有變更",
  fingerprint_schema_changed: "指紋結構版本有變更",
  severity_changed: "嚴重程度有變更",
  confidence_changed: "信心程度有變更",
  evidence_changed: "證據雜湊有變更",
  affected_assets_changed: "受影響的資產有變更",
  observing_engines_changed: "觀察到問題的掃描工具有變更",
  location_moved: "在同一個檔案中的位置改變",
};

const fixedReasonDetailsZhTW: Readonly<Record<string, readonly [string, string]>> = {
  scope_contract_changed: ["scope, permission, or target contract changed", "範圍、權限或目標合約有變更"],
  manifest_schema_changed: ["manifest schema changed", "清單結構版本有變更"],
  engine_version_changed: ["engine version changed", "掃描工具版本有變更"],
  image_changed: ["image repository or immutable digest changed", "映像儲存庫或不可變摘要有變更"],
  rule_version_changed: ["rule or template version changed", "規則或範本版本有變更"],
  knowledge_input_changed: ["database, feed, live source, or knowledge window changed", "資料庫、資訊饋送、即時來源或知識時間範圍有變更"],
  adapter_version_changed: ["adapter version changed without an explicit fingerprint migration", "轉接器版本有變更，且沒有明確的指紋遷移"],
  source_revision_changed: ["source revision changed", "來源修訂版本有變更"],
  repository_changed: ["source repository changed", "來源儲存庫有變更"],
  distribution_mode_changed: ["distribution mode changed", "發佈模式有變更"],
  command_changed: ["engine command contract changed", "掃描工具命令合約有變更"],
  mapping_version_changed: ["control-mapping catalog version or canonical provenance changed", "控制對照目錄版本或正式來源有變更"],
  fingerprint_schema_changed: ["fingerprint schema changed without an explicit migration", "指紋結構版本有變更，且沒有明確的遷移"],
  evidence_changed: ["evidence hashes changed", "證據雜湊有變更"],
  affected_assets_changed: ["affected assets changed", "受影響的資產有變更"],
  observing_engines_changed: ["observing engines changed", "觀察到問題的掃描工具有變更"],
};

export const verificationDiffReasonLabelZhTW = (code: string): string | undefined =>
  reasonLabelsZhTW[code as FindingDiffReasonCode];

interface TranslatedReasonDetail {
  text: string;
  carriesCoordinate?: boolean;
}

const translatedReasonDetailZhTW = (
  code: string,
  detail: string,
): TranslatedReasonDetail | undefined => {
  const fixed = fixedReasonDetailsZhTW[code];
  if (fixed?.[0] === detail) return { text: fixed[1] };

  if (code === "severity_changed") {
    const match = detail.match(/^severity changed from (.+) to (.+)$/u);
    if (match) return { text: `嚴重程度從 ${match[1]} 變更為 ${match[2]}` };
  }
  if (code === "confidence_changed") {
    const match = detail.match(/^confidence changed from (.+) to (.+)$/u);
    if (match) return { text: `信心程度從 ${match[1]} 變更為 ${match[2]}` };
  }
  if (code === "coordinate_not_completed") {
    const match = detail.match(/^(reference|candidate) engine=(.+), asset=(.+) did not complete$/u);
    if (match) {
      const side = match[1] === "reference" ? "參考掃描" : "候選掃描";
      return {
        text: `${side}的掃描工具=${match[2]}、資產=${match[3]} 未完成`,
        carriesCoordinate: true,
      };
    }
  }
  if (code === "comparison_identity_missing") {
    if (detail === "both runs lack planned engine/asset coordinates") {
      return { text: "兩次掃描都缺少已規劃的掃描工具／資產座標" };
    }
    if (detail === "observation has no originating engine") {
      return { text: "觀察記錄沒有來源掃描工具" };
    }
    const fingerprint = detail.match(/^finding fingerprint (.+) could not be compared$/u);
    if (fingerprint) return { text: `問題指紋 ${fingerprint[1]} 無法比較` };
    const execution = detail.match(/^engine=(.+), asset=(.+) has no comparable execution identity$/u);
    if (execution) {
      return {
        text: `掃描工具=${execution[1]}、資產=${execution[2]} 沒有可比較的執行識別資料`,
        carriesCoordinate: true,
      };
    }
    const scope = detail.match(/^(reference|candidate) run lacks a complete immutable scope-grant snapshot for engine=(.+), asset=(.+)$/u);
    if (scope) {
      const side = scope[1] === "reference" ? "參考掃描" : "候選掃描";
      return {
        text: `${side}缺少掃描工具=${scope[2]}、資產=${scope[3]} 的完整且不可變範圍授權快照`,
        carriesCoordinate: true,
      };
    }
    const missing = detail.split("; ").map((part) =>
      part.match(/^(reference|candidate) missing (.+)$/u),
    );
    if (missing.length > 0 && missing.every(Boolean)) {
      return {
        text: missing.map((match) =>
          `${match?.[1] === "reference" ? "參考執行" : "候選執行"}缺少 ${match?.[2]}`,
        ).join("；"),
      };
    }
  }
  if (code === "location_moved") {
    const moved = detail.match(/^location moved from line (\d+) to line (\d+) in the same file$/u);
    if (moved) return { text: `同一個檔案中的位置從第 ${moved[1]} 行移到第 ${moved[2]} 行` };
    if (detail === "location moved within the same file") {
      return { text: "在同一個檔案中的位置改變" };
    }
  }
  return undefined;
};

export const isVerificationDiffReasonDetailRecognized = (code: string, detail: string): boolean =>
  translatedReasonDetailZhTW(code, detail) !== undefined;

const coordinatePrefixZhTW = (reason: FindingDiffReasonPresentation): string => {
  const coordinates = [
    reason.engineId ? `掃描工具=${reason.engineId}` : undefined,
    reason.assetId ? `資產=${reason.assetId}` : undefined,
  ].filter((value): value is string => Boolean(value));
  return coordinates.join("、");
};

const reasonZhTW = (reason: FindingDiffReasonPresentation, withCoordinates: boolean): string => {
  const label = verificationDiffReasonLabelZhTW(reason.code);
  if (!label) return reason.detail;
  const translated = translatedReasonDetailZhTW(reason.code, reason.detail);
  const prefix = withCoordinates && !translated?.carriesCoordinate ? coordinatePrefixZhTW(reason) : "";
  const body = translated?.text ?? `${label}：${reason.detail}`;
  return prefix ? `${prefix}：${body}` : body;
};

/** A stored finding-comparison explanation in the reader's language. */
export const verificationDiffExplanation = (
  locale: Locale,
  diff: FindingDiffPresentationInput,
): string => {
  if (locale !== "zh-TW") return diff.explanation;

  const reasons = (diff.changeReasons ?? []).map((reason) => reasonZhTW(reason, true)).join("；");
  switch (diff.comparisonStatus) {
    case "still_present":
      return "目前掃描再次觀察到相同的指紋、嚴重程度、信心程度、資產、掃描工具與證據。";
    case "changed": {
      // Like the English explanation, a problem that is still observed names no scanner or asset.
      const changes = (diff.changeReasons ?? []).map((reason) => reasonZhTW(reason, false)).join("；");
      return changes ? `仍可觀察到這個問題，但${changes}。` : diff.explanation;
    }
    case "resolved":
      return "目前掃描已針對原始座標，完成版本、知識、對照映射、範圍與目標合約完全可比較的檢查，且未再次出現這個指紋。";
    case "newly_observed":
      return "基準掃描已完成版本、知識、對照映射、範圍與目標合約完全可比較的檢查，當時沒有這個指紋；目前掃描則觀察到它。";
    case "unable_to_verify":
      if (!reasons) return diff.explanation;
      if (diff.beforeSeverity !== undefined && diff.afterSeverity !== undefined) {
        return `兩次掃描都觀察到這個問題，但其座標無法比較：${reasons}。`;
      }
      if (diff.beforeSeverity !== undefined) {
        return `目前掃描未觀察到這個指紋，但因目前掃描的座標無法比較，無法判定已解決：${reasons}。`;
      }
      if (diff.afterSeverity !== undefined) {
        return `這個指紋出現在目前掃描中，但因基準掃描的座標無法比較，無法判定為新問題：${reasons}。`;
      }
      return diff.explanation;
    default:
      return diff.explanation;
  }
};

const mappingVersionChanged = "mapping_version_changed";

export function isOnlyMappingVersionDrift(issues: readonly ComparisonLimitation[]): boolean {
  return issues.length > 0 && issues.every((issue) => issue.code === mappingVersionChanged);
}

export function affectedEngineCount(issues: readonly ComparisonLimitation[]): number {
  return new Set(
    issues
      .map((issue) => issue.engineId?.trim())
      .filter((engineId): engineId is string => Boolean(engineId)),
  ).size;
}
