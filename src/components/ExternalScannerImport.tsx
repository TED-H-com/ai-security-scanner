import { useState } from "react";
import { useI18n } from "../i18n";
import { scannerService, type ExternalScannerImportPreview } from "../services/scanner";
import type { Asset } from "../types";

interface ImportRow {
  path: string;
  preview: ExternalScannerImportPreview;
  assetId: string;
  target: string;
}

export function ExternalScannerImport({ caseId, assets, nativeMode, busy, onImported }: {
  caseId: string;
  assets: Asset[];
  nativeMode: boolean;
  busy?: boolean;
  onImported: () => Promise<void>;
}) {
  const { text } = useI18n();
  const [rows, setRows] = useState<ImportRow[]>([]);
  const [working, setWorking] = useState(false);
  const [message, setMessage] = useState("");
  const choose = async () => {
    setWorking(true);
    setMessage("");
    try {
      const path = await scannerService.chooseExternalScannerReport();
      if (!path) return;
      const preview = await scannerService.previewExternalScannerImport(path);
      setRows((current) => [...current, { path, preview,
        assetId: assets.length === 1 ? assets[0]!.id : "",
        target: preview.targets.length === 1 ? preview.targets[0]! : "" }]);
    } catch (error) {
      setMessage(String(error));
    } finally {
      setWorking(false);
    }
  };
  const importReports = async () => {
    if (!rows.length || rows.some((row) => !row.assetId || !row.target)) return;
    setWorking(true);
    setMessage("");
    try {
      const result = await scannerService.importExternalScannerReports(caseId, rows.map((row) => ({
        report_path: row.path, source_sha256: row.preview.source_sha256, asset_id: row.assetId, upstream_target: row.target,
      })));
      setMessage(result.data.message);
      if (result.data.accepted) { setRows([]); await onImported(); }
    } catch (error) {
      setMessage(String(error));
    } finally {
      setWorking(false);
    }
  };
  const update = (index: number, patch: Partial<ImportRow>) =>
    setRows((current) => current.map((row, i) => i === index ? { ...row, ...patch } : row));
  return (
    <details className="coverage-form-technical page-secondary-feature">
      <summary>{text({ en: "Add existing Strix results", zhTW: "加入既有的 Strix 掃描結果" })}</summary>
      <p>{text({ en: "Choose a native vulnerabilities.json report and the asset its selected target belongs to. Imported findings join one report with their source evidence.",
        zhTW: "選擇原生 vulnerabilities.json 報告，並指定其中目標所屬的資產；匯入發現會連同來源證據整理為同一份報告。" })}</p>
      <p>{text({ en: "Import reads saved files. Live Strix testing and Anthropic OSS Scanner enrollment are separate services.",
        zhTW: "匯入會讀取已保存的檔案；Strix 即時測試與 Anthropic OSS Scanner 註冊屬於獨立服務。" })}</p>
      {rows.map((row, index) => (
        <div className="scope-confirmation-panel" key={`${row.path}-${index}`}>
          <strong>{row.path.split(/[\\/]/).at(-1)}</strong>
          <label className="field"><span>{text({ en: "Target in report", zhTW: "報告中的目標" })}</span>
            <select value={row.target} disabled={working || busy} onChange={(event) => update(index, { target: event.target.value })}>
              <option value="">{text({ en: "Choose a target", zhTW: "選擇目標" })}</option>
              {row.preview.targets.map((target) => <option key={target} value={target}>{target}</option>)}
            </select>
          </label>
          <label className="field"><span>{text({ en: "Existing asset", zhTW: "現有資產" })}</span>
            <select value={row.assetId} disabled={working || busy} onChange={(event) => update(index, { assetId: event.target.value })}>
              <option value="">{text({ en: "Choose an asset", zhTW: "選擇資產" })}</option>
              {assets.map((asset) => <option key={asset.id} value={asset.id}>{asset.name}</option>)}
            </select>
          </label>
          <button className="button button--secondary button--small" type="button" disabled={working || busy}
            onClick={() => setRows((current) => current.filter((_, i) => i !== index))}>{text({ en: "Remove", zhTW: "移除" })}</button>
        </div>
      ))}
      <div className="form-actions">
        <button className="button button--secondary" type="button" disabled={!nativeMode || busy || working || rows.length >= 16 || !assets.length}
          onClick={() => void choose()}>{text({ en: "Choose Strix report", zhTW: "選擇 Strix 報告" })}</button>
        {rows.length > 0 && <button className="button button--primary" type="button"
          disabled={!nativeMode || busy || working || rows.some((row) => !row.assetId || !row.target)}
          onClick={() => void importReports()}>{text({ en: "Import into one report", zhTW: "匯入並整合為一份報告" })}</button>}
      </div>
      {message && <p role="status">{message}</p>}
    </details>
  );
}
