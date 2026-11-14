import assert from "node:assert/strict";
import test from "node:test";

import {
  controlMappingRationaleZhHant, coverageProducedObservations, findingUnconfirmedByCoverage,
  localizedControlMappingRationale, localizedCoverageDimension, localizedCoverageRecordDetail,
  localizedDataQualityWarning, localizedRequestedLimitKind, localizedRequestedLimitName,
  localizedRequestedLimitValue, localizedTestedValue, requestedLimitParts,
  testedObservationProse, testedValueZhHant,
} from "../../src/findingNarrative.ts";

const dimensionCases = [
  ["Source audit coverage", "原始碼稽核涵蓋範圍", "ソースコード監査の確認範囲"],
  ["TCP reachability", "TCP 連線狀態", "TCP 到達性"],
  ["Nuclei: failed check dimension", "Nuclei 檢查", "Nuclei の確認"],
  ["Nuclei: remaining requested dimensions", "Nuclei 未完成的部分", "Nuclei の未完了部分"],
  ["Maester: no verdict for PR.AA-03", "Maester：未回傳判定的控制項 PR.AA-03", "Maester：判定のないコントロール PR.AA-03"],
  ["Maester: manual review for PR.AA-03", "Maester：未回傳判定的控制項 PR.AA-03", "Maester：判定のないコントロール PR.AA-03"],
  ["Nuclei failed scan batches (003)", "Nuclei 的失敗的掃描批次（003）", "Nuclei の失敗したスキャンバッチ（003）"],
  ["Nuclei completed-check time", "Nuclei 的檢查完成時間", "Nuclei の確認完了時刻"],
  ["Nuclei: scanner errors", "Nuclei 的掃描工具錯誤", "Nuclei のスキャナーエラー"],
  ["requested check scanner-id", "要求的檢查項目：scanner-id", "依頼した確認：scanner-id"],
  ["unknown dimension /path", "涵蓋範圍細節：unknown dimension /path", "確認範囲の詳細：unknown dimension /path"],
] as const;

test("coverage dimension shapes translate their labels while retaining identifiers", () => {
  for (const [en, zh, ja] of dimensionCases) {
    const english = en === "Nuclei: failed check dimension" ? "Nuclei"
      : en === "Nuclei: remaining requested dimensions" ? "Nuclei: unfinished part" : en;
    assert.equal(localizedCoverageDimension(en, "en"), english, en);
    assert.equal(localizedCoverageDimension(en, "zh-TW"), zh, en);
    assert.equal(localizedCoverageDimension(en, "ja"), ja, en);
  }
});

test("tested observations and control rationales translate only known prose", () => {
  const observation = "The port accepted the bounded TCP connection.";
  assert.equal(testedObservationProse("en", observation), observation);
  assert.equal(testedObservationProse("zh-TW", observation), "這個連接埠接受了受限的 TCP 連線。");
  assert.equal(testedObservationProse("ja", observation), "このポートは制限された TCP 接続を受け入れました。");
  assert.equal(testedObservationProse("ja", "Recorded source audit"), "記録済みのソースコード監査");
  assert.equal(testedObservationProse("zh-TW", "Recorded source audit"), "已記錄的原始碼稽核");
  const rationale = "Evidence that an identity has no registered multi-factor device is related to authenticating users and safeguarding authentication information.";
  assert.equal(localizedControlMappingRationale(rationale, "en"), rationale);
  assert.equal(localizedControlMappingRationale(rationale, "zh-TW"), "某個身分未登記多重要素驗證裝置的證據，與驗證使用者及保護驗證資訊有關。");
  assert.equal(localizedControlMappingRationale(rationale, "ja"), "ID に多要素認証デバイスが登録されていない証拠は、ユーザーの認証と認証情報の保護に関連します。");
  assert.equal(controlMappingRationaleZhHant("Unknown rationale."), undefined);
  for (const locale of ["en", "zh-TW", "ja"] as const) {
    assert.equal(localizedControlMappingRationale("Unknown rationale.", locale), "Unknown rationale.");
    assert.equal(testedObservationProse(locale, "Unknown observation."), "Unknown observation.");
  }
  assert.equal(testedObservationProse("ja", " Unknown observation. "), " Unknown observation. ");
  assert.equal(testedObservationProse("en", " Unknown observation. "), "Unknown observation.");
});

const valueCases = [
  ["bounded connection contract", "one connection attempt; 003 ms timeout; 0 application-payload bytes", "一次連線嘗試；逾時 003 毫秒；應用層酬載 0 位元組", "接続試行 1 回、タイムアウト 003 ミリ秒、アプリケーションペイロード 0 バイト"],
  ["completed check-to-target coordinate", "nuclei on asset asset-{id}", "nuclei 對資產 asset-{id}", "資産 asset-{id} に対する nuclei"],
  ["completed planned scan batches", "03 of 005", "005 個中的 03 個", "005 件中 03 件"],
  ["internal-device TLS vulnerability checks", "010 frozen Greenbone TLS tests on asset host-1", "對資產 host-1 的 010 項已凍結 Greenbone TLS 檢查", "資産 host-1 に対する確定済み：Greenbone TLS 確認 010 件"],
  ["SSH service vulnerability checks", "2 frozen upstream Greenbone SSH tests on asset host-1", "對資產 host-1 的 2 項已凍結 上游 Greenbone SSH 檢查", "資産 host-1 に対する確定済み：上流 Greenbone SSH 確認 2 件"],
  ["Nuclei upstream website scan", "technology-aware upstream profile on exact website origin for asset web-1", "依技術偵測選擇的上游設定檔，套用於資產 web-1 的確切網站來源", "資産 web-1 の指定 Web サイトのオリジンに適用した、技術検出に基づく上流プロファイル"],
  ["Greenbone remote vulnerability scan", "applicability-driven upstream profile on asset host-1 across 004 approved TCP ports", "依適用性選擇的上游設定檔，套用於資產 host-1 的 004 個已核准 TCP 連接埠", "資産 host-1 の承認済み TCP ポート 004 件に適用した、適用性に基づく上流プロファイル"],
  ["SMTP fixed security profile attempt", "exact 011-check upstream Greenbone SMTP profile on asset host-1", "對資產 host-1 的確切上游 Greenbone SMTP 設定檔，共 011 項檢查", "資産 host-1 に対する指定の上流 Greenbone SMTP プロファイル（確認 011 件）"],
  ["SMTP TLS checks with selected-run evidence", "02 of 010 selected TLS checks on asset host-1", "對資產 host-1 已選取的 010 項 TLS 檢查中的 02 項", "資産 host-1 で選択した TLS 確認 010 件中 02 件"],
] as const;

test("tested values translate every data frame without altering stored values", () => {
  for (const [dimension, value, zh, ja] of valueCases) {
    assert.equal(localizedTestedValue("en", dimension, value), value, dimension);
    assert.equal(testedValueZhHant(dimension, value), zh, dimension);
    assert.equal(localizedTestedValue("zh-TW", dimension, value), zh, dimension);
    assert.equal(localizedTestedValue("ja", dimension, value), ja, dimension);
  }
  for (const [dimension, value] of [["Source audit coverage", "/repo/file.ts"], ["TCP reachability", "host:443"], ["unknown dimension", "unknown value"], ["completed planned scan batches", "1.5 of 2"]] as const) {
    for (const locale of ["en", "zh-TW", "ja"] as const) assert.equal(localizedTestedValue(locale, dimension, value), value);
  }
  assert.equal(testedValueZhHant("unknown dimension", "unknown value"), undefined);
});

const detailCases = [
  ["Choose the AI workflow framework for this repository before running its workflow inventory.", "請先選擇這個專案的 AI 工作流程框架，再執行工作流程盤點。", "このリポジトリのワークフローを棚卸しする前に、AI ワークフローフレームワークを選択してください。"],
  ["The source area is explicitly outside this case: custom /path This is a scoped applicability statement, not a successful scan result.", "此來源範圍明確不在本案件內：custom /path 這是範圍適用性的說明，不是掃描成功的結果。", "このソース領域はこのケースの対象外です：custom /path これは対象範囲の説明であり、スキャンの成功結果ではありません。"],
  ["The source is connected and the latest attributable discovery returned no assets. This is not a successful scan result; 003 prior asset observation(s) remain retained.", "來源已連線，且最近一次可歸屬的探索未傳回任何資產。這不是掃描成功的結果；仍保留 003 筆先前的資產觀察結果。", "ソースは接続されていますが、直近の帰属可能な検出では資産が見つかりませんでした。これはスキャンの成功結果ではありません。以前の資産の観測 003 件は保持されています。"],
  ["The source is not currently connected (status: upstream-unknown). Its present coverage is unknown; 03 previously attributed asset(s) are retained but do not make the source green.", "來源目前未連線（狀態：upstream-unknown）。目前的涵蓋未知；仍保留 03 筆先前歸屬的資產，但這不會讓來源顯示為綠色。", "ソースは現在接続されていません（状態：upstream-unknown）。現在の確認範囲は不明です。以前に帰属した資産 03 件は保持されていますが、ソースは正常と表示されません。"],
  ["The scan's frozen authorization evidence is incomplete: upstream detail. Live grants are never used to reconstruct historical scan permission.", "掃描中凍結的授權證據不完整：upstream detail。絕不會用現行授權重建過去的掃描權限。", "スキャン時に確定した許可の証拠が不完全です：upstream detail。現在の許可から過去のスキャン権限を復元することはありません。"],
  ["All 03 compatible engine run(s) planned for this asset completed.", "為此資產規劃的 03 項相容掃描工具工作皆已完成。", "この資産に予定された互換エンジンの実行 03 件がすべて完了しました。"],
  ["All 03 planned task(s) for this asset completed their exact declared dimensions.", "為此資產規劃的 03 項工作，皆已完成各自明確宣告的檢查範圍。", "この資産に予定されたタスク 03 件は、宣言された確認範囲をそれぞれ完了しました。"],
  ["The authorized scan is incomplete: timeout /path. Only completed compatible catalog-engine runs or exact completed built-in tasks can produce scanned coverage.", "已授權的掃描未完成：timeout /path。只有已完成且相容的目錄掃描工具工作，或精確完成的內建工作，才能產生已掃描涵蓋。", "許可されたスキャンは未完了です：timeout /path。スキャン済みの確認範囲として扱えるのは、完了した互換カタログエンジンの実行または指定どおり完了した組み込みタスクのみです。"],
] as const;

test("coverage record detail translates fixed sentences and data frames", () => {
  for (const [en, zh, ja] of detailCases) {
    assert.equal(localizedCoverageRecordDetail(en, "en"), en);
    assert.equal(localizedCoverageRecordDetail(en, "zh-TW"), zh, en);
    assert.equal(localizedCoverageRecordDetail(en, "ja"), ja, en);
  }
  for (const locale of ["en", "zh-TW", "ja"] as const) {
    assert.equal(localizedCoverageRecordDetail("Unknown coverage detail.", locale), "Unknown coverage detail.");
    assert.equal(localizedCoverageRecordDetail("All 1.5 compatible engine run(s) planned for this asset completed.", locale), "All 1.5 compatible engine run(s) planned for this asset completed.");
  }
});

test("coverage record appended frames retain the upstream data and translate recursively", () => {
  const base = detailCases[0][0], zhBase = detailCases[0][1], jaBase = detailCases[0][2];
  const frames = [
    [" Explicit stale-knowledge warning: upstream {x}. Completion proves execution, not current knowledge.", " 明確的過時知識警告：upstream {x}。完成只證明已執行，不代表知識仍為最新。", "検出情報の古さに関する警告：upstream {x}。完了は実行を示すもので、情報が最新であることは示しません。"],
    [" Exact built-in localhost TCP attempt(s): 127.0.0.1:80. This records only those connection attempts; it does not establish that the service or computer is secure, and it does not cover other ports or hosts.", " 精確的內建 localhost TCP 嘗試：127.0.0.1:80。這只記錄這些連線嘗試；無法證明服務或電腦安全，也不涵蓋其他連接埠或主機。", "組み込みの指定 localhost TCP 接続試行：127.0.0.1:80。これは接続試行の記録のみであり、サービスやコンピューターの安全性を示すものではなく、他のポートやホストも対象外です。"],
    [" Latest provider discovery: detail /path", " 最近一次供應商探索：detail /path", "直近のプロバイダー検出：detail /path"],
    [" This state is independent of how many findings were reported.", " 此狀態與回報了多少個問題無關。", "この状態は報告された検出結果の数とは無関係です。"],
  ] as const;
  for (const [suffix, zh, ja] of frames) {
    assert.equal(localizedCoverageRecordDetail(base + suffix, "en"), base + suffix);
    assert.equal(localizedCoverageRecordDetail(base + suffix, "zh-TW"), zhBase + zh);
    assert.equal(localizedCoverageRecordDetail(base + suffix, "ja"), jaBase + ja);
    assert.equal(localizedCoverageRecordDetail("Unknown base." + suffix, "ja"), "Unknown base." + suffix);
    assert.equal(localizedCoverageRecordDetail("Unknown base." + suffix, "zh-TW"), "Unknown base." + suffix);
  }
  // Matches the backend/zh-TW append order: state summary before warning or provider discovery.
  assert.equal(
    localizedCoverageRecordDetail(base + frames[3][0] + frames[0][0], "ja"),
    jaBase + frames[3][2] + frames[0][2],
  );
  assert.equal(
    localizedCoverageRecordDetail(base + frames[3][0] + frames[2][0], "ja"),
    jaBase + frames[3][2] + frames[2][2],
  );
  assert.equal(
    localizedCoverageRecordDetail(base + frames[3][0] + frames[2][0], "zh-TW"),
    zhBase + frames[3][1] + frames[2][1],
  );
});

test("data quality warning shapes translate around finding IDs", () => {
  const cases = [
    ["This run has inconsistent request and check data.", "本輪的請求與檢查資料不一致。", "この実行の依頼データと確認データに不整合があります。"],
    ["Finding F-{id} selected-run presentation snapshot: unavailable. Display wording: current canonical text.", "問題 F-{id} 所選輪次呈現快照：無法取得；顯示文字：目前正式版本。", "検出結果 F-{id} の選択した実行時の表示スナップショットは取得できません。現在の正式な文言を表示しています。"],
    ["Finding F-{id} presentation detail: unavailable. Retained run observation: available.", "問題 F-{id} 呈現細節：無法取得；保留的輪次觀察：可用。", "検出結果 F-{id} の表示詳細は取得できません。保持された実行時の観測は利用できます。"],
    ["Unknown warning.", "Unknown warning.", "Unknown warning."],
  ] as const;
  for (const [en, zh, ja] of cases) {
    assert.equal(localizedDataQualityWarning(en, "en"), en);
    assert.equal(localizedDataQualityWarning(en, "zh-TW"), zh);
    assert.equal(localizedDataQualityWarning(en, "ja"), ja);
  }
});

test("requested limit names and values retain holders, numbers, and unknown data", () => {
  assert.deepEqual(requestedLimitParts("engine-1 request rate"), { holder: "engine-1", kind: "request rate" });
  assert.deepEqual(requestedLimitParts("future limit"), { holder: "", kind: "future limit" });
  for (const [kind, en, zh, ja] of [
    ["request rate", "Request rate", "請求速率", "リクエストレート"],
    ["connection timeout", "Connection timeout", "連線逾時限制", "接続タイムアウト"],
    ["issued invocations", "Issued invocations", "已發出的呼叫次數", "発行済みの呼び出し回数"],
    ["future limit", "future limit", "本輪使用的限制：future limit", "この実行で使用した制限：future limit"],
  ] as const) {
    assert.equal(localizedRequestedLimitKind(kind, "en"), en);
    assert.equal(localizedRequestedLimitKind(kind, "zh-TW"), zh);
    assert.equal(localizedRequestedLimitKind(kind, "ja"), ja);
  }
  for (const [name, zh, ja] of [
    ["engine-1 request rate", "請求速率（engine-1）", "リクエストレート（engine-1）"],
    ["future limit", "本輪使用的限制：future limit", "この実行で使用した制限：future limit"],
  ] as const) {
    assert.equal(localizedRequestedLimitName(name, "en"), name);
    assert.equal(localizedRequestedLimitName(name, "zh-TW"), zh);
    assert.equal(localizedRequestedLimitName(name, "ja"), ja);
  }
  for (const [value, zh, ja] of [
    ["003 ms", "003 毫秒", "003 ミリ秒"], ["000 bytes", "000 位元組", "000 バイト"],
    ["007 seconds", "007 秒", "007 秒"],
    ["02 per second, concurrency 004", "每秒 02 次，並行 004", "毎秒 02 件、同時実行 004 件"],
    ["1.5 ms", "1.5 ms", "1.5 ms"], ["host:443", "host:443", "host:443"],
  ] as const) {
    assert.equal(localizedRequestedLimitValue("request rate", value, "en"), value);
    assert.equal(localizedRequestedLimitValue("request rate", value, "zh-TW"), zh);
    assert.equal(localizedRequestedLimitValue("request rate", value, "ja"), ja);
  }
});

test("coverage observation classification and unconfirmed findings retain their decisions", () => {
  for (const status of ["tested_complete", "tested_partial"] as const) assert.equal(coverageProducedObservations(status), true);
  for (const status of ["failed", "timed_out", "cancelled", "not_tested"] as const) assert.equal(coverageProducedObservations(status), false);
  const checks = [{ taskId: "done", status: "tested_partial" }, { taskId: "failed", status: "failed" }] as const;
  assert.equal(findingUnconfirmedByCoverage([{ engineRunId: "done" }, { engineRunId: "failed" }], checks), false);
  for (const refs of [[], [{}], [{ engineRunId: "missing" }], [{ engineRunId: "failed" }]] as const) {
    assert.equal(findingUnconfirmedByCoverage(refs, checks), true);
  }
});
