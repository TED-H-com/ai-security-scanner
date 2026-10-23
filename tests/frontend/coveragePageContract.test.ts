import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const source = readFileSync(
  new URL("../../src/pages/CoveragePage.tsx", import.meta.url),
  "utf8",
);
const localInputProfileSource = readFileSync(
  new URL("../../src/localInputProfiles.ts", import.meta.url),
  "utf8",
);
const coverageCss = readFileSync(
  new URL("../../src/coverage-page.css", import.meta.url),
  "utf8",
);
const providerPanelSource = readFileSync(
  new URL("../../src/components/ProviderAuthorizationPanel.tsx", import.meta.url),
  "utf8",
);
const appSource = readFileSync(
  new URL("../../src/App.tsx", import.meta.url),
  "utf8",
);
const scannerServiceSource = readFileSync(
  new URL("../../src/services/scanner.ts", import.meta.url),
  "utf8",
);

test("coverage onboarding keeps the complete input and permission surface", () => {
  for (const capability of [
    "ProviderAuthorizationPanel",
    "engineManifests",
    "onConnectSourceSnapshot",
    "onAttachWorkspaceSnapshot",
    "onStartDiscovery",
    "onStartScan",
    "externalTarget",
    "externalPorts",
    "externalProtocol",
    "requestsPerSecond",
    "externalConcurrency",
    "externalTimeout",
    "templateRevision",
    "allowedTemplateIds",
    "allowSensitiveNetworks",
  ]) {
    assert.ok(source.includes(capability), `missing Coverage capability: ${capability}`);
  }
});

test("coverage source selection receives and labels installed-product capability without claiming run evidence", () => {
  assert.match(source, /engineManifests: EngineManifest\[\]/u);
  assert.match(appSource, /<CoveragePage[\s\S]*engineManifests=\{snapshot\?\.engineManifests \?\? \[\]\}/u);
  assert.match(source, /<ProviderAuthorizationPanel[\s\S]*engineManifests=\{engineManifests\}/u);
  assert.match(providerPanelSource, /projectSourceCapabilityView\(\{ provider, source: selectedSource, manifests: engineManifests \}\)/u);
  for (const phrase of [
    "Declared capabilities for this installed product version.",
    "Selected-scan evidence and coverage appear in Results.",
    "目前安裝版本宣告的能力",
    "所選掃描的證據與涵蓋範圍顯示在「結果」",
  ]) assert.ok(providerPanelSource.includes(phrase), phrase);

  for (const retiredBroadClaim of [
    "Cloud resources, configuration, identities and access, security posture, and audit metadata",
    "Resources, configuration, identities and access, security posture, and audit metadata",
    "Directory configuration, identities and access, security posture, and audit metadata",
    "雲端資源、設定、身分與存取、安全狀態及稽核中繼資料",
  ]) assert.ok(!providerPanelSource.includes(retiredBroadClaim), retiredBroadClaim);
});

test("coverage onboarding does not repeat the start-page use-case catalog", () => {
  assert.ok(!source.includes("const useCaseNextSteps"));
  assert.ok(!source.includes("coverage-situation-help"));
  assert.ok(!source.includes("pageCopy.situationSummary"));
  assert.ok(!source.includes("pageCopy.situationIntro"));
});

test("source details and repeated advice do not bury the item that needs action", () => {
  assert.match(source, /coverage\.length === 0[\s\S]*coverage-source-ledger page-secondary-feature[\s\S]*<summary>\{text\(pageCopy\.sourcesTitle/u);
  assert.match(source, /const showAssetNext = asset\.authorizationState !== "authorized"[\s\S]*\|\| readyForFirstScan[\s\S]*\|\| selectedAssets\.includes\(asset\.id\)/u);
  assert.match(source, /showAssetNext && \([\s\S]*asset-review-card__next/u);
});

test("technical detail is progressive and a website service remains a preset, not permission", () => {
  assert.ok(source.includes("coverage-technical-details"));
  assert.ok(source.includes("source-card__technical"));
  assert.ok(source.includes("asset-review-card__technical"));
  assert.ok(source.includes("selectedExternalAsset.declaredWebService"));
  assert.match(source, /setExternalProtocol\(service\.protocol\)/);
  assert.match(source, /setExternalPorts\(String\(service\.port\)\)/);
  assert.ok(source.includes("the path remains context"));
  assert.ok(source.includes("路徑保留為背景資訊"));
  assert.match(source, /internetExposed === false && effectiveAllowSensitiveNetworks/);
  assert.match(source, /internetExposed === undefined/);

  const advancedStart = source.search(/<details\r?\n\s+className="coverage-form-technical coverage-scan-advanced"/u);
  const advancedEnd = source.indexOf("</details>", advancedStart);
  assert.notEqual(advancedStart, -1);
  assert.notEqual(advancedEnd, -1);
  const advancedSettings = source.slice(advancedStart, advancedEnd);
  for (const technicalControl of [
    "pageCopy.declaredServiceTitle",
    "pageCopy.canonicalTarget",
    "pageCopy.protocol",
    "pageCopy.ports",
    "pageCopy.rateTitle",
    "pageCopy.templateIds",
    "pageCopy.sensitiveTechnicalBody",
  ]) {
    assert.ok(advancedSettings.includes(technicalControl), `${technicalControl} must stay behind advanced details`);
  }
  assert.ok(source.indexOf("pageCopy.sensitiveTitle", advancedEnd) > advancedEnd, "custom and active internal-network confirmation must remain available");
  assert.match(
    source.slice(advancedEnd, source.indexOf("</section>", advancedEnd)),
    /isDirectExternal && selectedExternalAsset\.internetExposed === false && !guidedLowImpactNetwork/,
    "the extra internal-network toggle must not clutter the guided low-impact setup",
  );
  assert.doesNotMatch(source.slice(advancedEnd, source.indexOf("</section>", advancedEnd)), /asset\.locator/);
});

test("guided public and internal inventory routes retain the bounded TCP preset", () => {
  assert.ok(source.includes("recommendedGuidedNetworkPreset"));
  assert.ok(source.includes("recommendedGuidedLowImpactRatePolicy"));
  assert.match(source, /assessmentIntent === "external_ip_or_domain" \|\| assessmentIntent === "internal_it_environment"/u);
  assert.match(source, /setExternalProtocol\(preset\.protocol\)/u);
  assert.match(source, /setExternalPorts\(preset\.ports\.join\(", "\)\)/u);
  assert.match(source, /setRequestsPerSecond\(policy\.requestsPerSecond\)/u);
  assert.match(source, /setExternalConcurrency\(policy\.concurrency\)/u);
  assert.match(source, /setExternalTimeout\(policy\.timeoutSeconds\)/u);
  assert.ok(source.includes("pageCopy.guidedNetworkBoundary"));
  assert.ok(source.includes("pageCopy.presetTitle"));
  assert.match(source, /coverage-guided-boundary[\s\S]*target: externalTarget[\s\S]*protocol: externalProtocol[\s\S]*ports: parsedPorts\.join[\s\S]*rate: formatNumber\(requestsPerSecond\)[\s\S]*concurrency: formatNumber\(externalConcurrency\)[\s\S]*timeout: formatNumber\(externalTimeout\)/u);
  for (const phrase of [
    "No exploitation, credentials, destructive actions, or added targets.",
    "不會利用弱點、使用憑證、執行破壞性操作或加入其他目標",
    "Start confirms authorization.",
    "開始即確認已獲授權。",
  ]) assert.ok(source.includes(phrase), phrase);
  assert.match(source, /coverage-technical-preset-summary[\s\S]*guidedNetworkTechnicalPreset[\s\S]*protocol: externalProtocol[\s\S]*count: formatNumber\(parsedPorts\.length\)[\s\S]*concurrency: formatNumber\(externalConcurrency\)/u);
  assert.ok(source.includes("up to {concurrency} simultaneous connections"));
  assert.ok(source.includes("最多 {concurrency} 個並行連線"));
  assert.doesNotMatch(source, /one connection at a time|一次一個連線/u);
  assert.match(source, /Math\.min\(current, limits\.rate\)/u);
  assert.match(source, /Math\.min\(current, limits\.concurrency\)/u);
  assert.match(source, /Math\.min\(current, limits\.timeout\)/u);
});

test("every low-impact IPv4 CIDR setup gets an effective-rate and host-ceiling warning", () => {
  assert.match(
    source,
    /networkScanEstimate = externalActivity === "low_impact_external" && parsedPorts[\s\S]*requestsPerSecond,[\s\S]*externalConcurrency,[\s\S]*externalTimeout/u,
  );
  assert.doesNotMatch(
    source,
    /networkScanEstimate = guidedLowImpactNetwork/u,
  );
  for (const phrase of [
    "Pacing floor: {effectiveRate}/s; requested rate: {requestedRate}/s; concurrency: {concurrency}.",
    "速率下限採用每秒 {effectiveRate} 次檢查，也就是每秒請求 {requestedRate} 次與 {concurrency} 個並行檢查中較低的數值。",
    "Estimated upper bound: {upperHours} hr {upperMinutes} min; scanner limit: {ceilingHours} hr.",
    "預估上限：{upperHours} 小時 {upperMinutes} 分鐘；掃描限制：{ceilingHours} 小時。",
    "Narrow the CIDR, ports, or {timeout}-second timeout before starting.",
    "開始前請縮小 CIDR、連接埠或 {timeout} 秒逾時。",
  ]) assert.ok(source.includes(phrase), phrase);
  assert.match(source, /networkScanEstimate\.mayExceedEngineCeiling[\s\S]*durationCeilingRiskBody[\s\S]*durationCeilingWithinBody/u);
});

test("advanced target boundaries distinguish public and authorized internal scans in both locales", () => {
  for (const phrase of [
    "Exact public-target boundary",
    "公開目標的精確界線",
    "Private, loopback, link-local, and metadata addresses remain blocked",
    "private、loopback、link-local 與 metadata 位址仍保持阻擋",
  ]) assert.ok(source.includes(phrase), phrase);

  assert.match(
    source,
    /effectiveAllowSensitiveNetworks[\s\S]*pageCopy\.sensitiveTechnicalTitle[\s\S]*pageCopy\.publicBoundaryTitle/u,
  );
  assert.match(
    source,
    /effectiveAllowSensitiveNetworks[\s\S]*pageCopy\.sensitiveTechnicalBody[\s\S]*pageCopy\.publicBoundaryBody/u,
  );
});

test("an internal network asset is not summarized as a public web platform", () => {
  assert.ok(source.includes('internalAssetPlatform: bilingual("Internal system / LAN", "內部系統／區域網路")'));
  assert.match(source, /asset\.platform === "external" && asset\.internetExposed === false[\s\S]*pageCopy\.internalAssetPlatform/u);
});

test("the saved assessment intent opens one guided route and moves unrelated inputs under advanced options", () => {
  assert.ok(source.includes("assessmentIntent?: UseCaseId"));
  assert.ok(source.includes("localProfileByAssessmentIntent"));
  assert.ok(source.includes("setShowProviderSetup(guidedCloudRoute)"));
  assert.ok(source.includes("setShowWorkspaceForm(Boolean(guidedLocalProfile))"));
  assert.ok(source.includes("guidedNetworkInputCard"));
  assert.ok(source.includes('className="coverage-situation-details coverage-advanced-inputs"'));
  assert.ok(source.includes("pageCopy.otherInputsSummary"));
});

test("a readiness fix opens the exact cloud, workspace, or read-only source step", () => {
  assert.ok(source.includes("focusSetup?: CoverageSetupFocus"));
  assert.match(source, /focusSetup === "provider"[\s\S]*focusSetup === "source"[\s\S]*focusSetup === "workspace"/u);
  assert.match(source, /"coverage-cloud-connection"[\s\S]*"source-snapshot-form"[\s\S]*"workspace-snapshot-form"/u);
  assert.match(source, /getElementById\(targetId\)\?\.scrollIntoView/u);
  assert.match(source, /id="coverage-cloud-connection" className="coverage-provider-slot"/u);
  assert.match(source, /id="source-snapshot-form"/u);
  assert.match(source, /id="workspace-snapshot-form"/u);
});

test("guided network, website quick profile, local, and signed-in cloud setup combine confirmation and Start", () => {
  assert.ok(source.includes("conciseGuidedConsent = guidedLowImpactNetwork || guidedWebsiteQuickProfile || guidedLocalConsent || guidedCloudConsent"));
  assert.ok(source.includes("pageCopy.confirmAndStart"));
  assert.ok(source.includes("pageCopy.scanSignedInCloud"));
  assert.ok(source.includes("pageCopy.guidedCloudConfirmation"));
  assert.ok(source.includes("pageCopy.changeScanType"));
  assert.ok(source.includes("effectiveAllowSensitiveNetworks"));
  const start = source.indexOf("const startScan = async () =>");
  const end = source.indexOf("const changeSourceKind", start);
  assert.notEqual(start, -1);
  assert.notEqual(end, -1);
  assert.ok(source.slice(start, end).includes("onStartScan("));
  assert.equal(source.slice(0, start).includes("onStartScan("), false, "route setup must not contact a target before Start");
  assert.doesNotMatch(source, /Next, open Scan progress and press Start/u);
  assert.ok(source.includes("This saves the exact target and limits, then starts the scan."));
  assert.ok(source.includes("這會保存精確目標與限制並開始掃描"));
});

test("new scan setup does not expose the no-engine public-record permission", () => {
  assert.doesNotMatch(source, /passivePublicConsent|simpleGuidedConsent/u);
  for (const retiredSurface of [
    "publicRecordsGrantDescription",
    "publicRecordsBoundaryHelp",
    "publicRecordsStart",
    "publicRecordsConfirmation",
    "No check in this version reads public records",
  ]) assert.ok(!source.includes(retiredSurface), retiredSurface);
  assert.match(source, /requiresAuthorizationReference = externalActivity === "active_external"/u);
  assert.match(source, /!conciseGuidedConsent && \([\s\S]*ownershipConfirmed/u);
  assert.match(source, /isDirectExternal && selectedExternalAsset && limits/u);
});

test("network authorization guidance states requirements without transferring the decision", () => {
  for (const phrase of [
    "Scan authorization must cover every selected item before Start.",
    "開始前，掃描授權必須涵蓋每一個已選項目。",
    "System-owner approval for access from this computer is required.",
    "從這台電腦存取必須取得系統負責人核准",
    "Required record: ticket, contract, or approver confirming this scan.",
    "必要紀錄：確認本次掃描的工單、合約或核准人。",
  ]) assert.ok(source.includes(phrase), phrase);

  for (const retiredInstruction of [
    "If you are unsure, ask the system owner before continuing.",
    "Turn this on only when the system owner approved access from this computer.",
    "Never enter a password, key, or token here.",
    "Choose public-record review or a light connection check",
  ]) assert.ok(!source.includes(retiredInstruction), retiredInstruction);
});

test("the desktop submits authorization and Start through one native command", () => {
  const coverageStart = appSource.indexOf("case \"coverage\"");
  const progressStart = appSource.indexOf("case \"progress\"", coverageStart);
  const coverageWiring = appSource.slice(coverageStart, progressStart);
  assert.match(coverageWiring, /onStartScan=\{[\s\S]*startScan\(\{[\s\S]*authorization:/u);
  assert.match(coverageWiring, /onStartScan=\{\(assetIds, modes, confirmation, externalScope, engineIds, campaignId\)[\s\S]*engineIds,[\s\S]*campaignId,/u);
  assert.doesNotMatch(coverageWiring, /scannerService\.approveScope|executeAction\("scope"/u);

  const serviceStart = scannerServiceSource.indexOf("async startScan(input: StartScanInput)");
  const serviceEnd = scannerServiceSource.indexOf("async startLocalhostQuickScan", serviceStart);
  const service = scannerServiceSource.slice(serviceStart, serviceEnd);
  assert.match(service, /COMMANDS\.startScan/u);
  assert.match(service, /caseId: input\.caseId,[\s\S]*decisions,[\s\S]*engineIds:/u);
  assert.doesNotMatch(service, /COMMANDS\.approveScope/u);

  const appStart = appSource.indexOf("const startScan = async (");
  const appStartEnd = appSource.indexOf("const deleteCase", appStart);
  const appStartFlow = appSource.slice(appStart, appStartEnd);
  assert.match(appStartFlow, /existingRunIds = new Set\(/u);
  assert.match(appStartFlow, /response\.workspace \?\? response\.snapshot\?\.workspace/u);
  assert.match(appStartFlow, /findRunCreatedAfterStart\(returnedWorkspace\.runs, existingRunIds\)/u);
  assert.match(appStartFlow, /setSelectedReportRunId\(createdRunId\)[\s\S]*navigate\("progress"\)/u);
});

test("cloud sign-in leads to one exact read-only scan confirmation instead of another ownership form", () => {
  assert.match(source, /guidedCloudRoute[\s\S]*hasExactGuidedCloudConsent\(selectedScopeAssets, providerConnection\)/u);
  assert.match(source, /asset\.platform === "external" \|\| selectedIncludesExternal \|\| guidedCloudRoute/u);
  assert.match(source, /!conciseGuidedConsent && \([\s\S]*ownershipConfirmed/u);
  assert.match(source, /guidedCloudConsent \? \([\s\S]*pageCopy\.changeScanType/u);
  for (const [english, traditionalChinese] of [
    ["Signed-in account: {account}", "已登入帳號：{account}"],
    ["Signed-in account: {account} · Read-only checks: {checks}.", "已登入帳號：{account} · 唯讀檢查：{checks}。"],
    ["Scan this signed-in account", "掃描這個已登入帳號"],
  ]) {
    assert.ok(source.includes(english), english);
    assert.ok(source.includes(traditionalChinese), traditionalChinese);
  }
  assert.match(source, /guidedCloudConsent && \([\s\S]*pageCopy\.guidedCloudBoundary[\s\S]*account: selectedScopeAssets\.map[\s\S]*checks: scopeModes\.map/u);
});

test("guided cloud discovery is one explicit continuation after sign-in", () => {
  assert.match(source, /actions=\{focusedGuidedReview \? \([\s\S]*nativeMode && guidedCoverageRoute\.kind === "none" \? \(/u);
  assert.match(source, /!guidedNetworkRoute && !guidedCloudRoute && knownTargetsInputCard/u);
  assert.match(source, /findingAssets=\{discoveryBusy\}/u);
  assert.match(source, /onFindAssets=\{onStartDiscovery\}/u);

  const installedStart = providerPanelSource.indexOf("{installed && (");
  const setupStart = providerPanelSource.indexOf("{!installed && !prompt", installedStart);
  const installedMarkup = providerPanelSource.slice(installedStart, setupStart);
  assert.match(installedMarkup, /copy\.findAssets/u);
  assert.match(installedMarkup, /onClick=\{\(\) => void onFindAssets\(\)\}/u);
  assert.doesNotMatch(installedMarkup, /copy\.connectedTitle|copy\.connectedBody|copy\.findAssetsHelp/u);
  assert.doesNotMatch(installedMarkup, /onAuthorizationChanged\(/u);

  const pollingStart = providerPanelSource.indexOf("const schedulePoll");
  const beginStart = providerPanelSource.indexOf("const beginPreferred", pollingStart);
  const polling = providerPanelSource.slice(pollingStart, beginStart);
  assert.match(polling, /await onAuthorizationChanged\(\)/u);
  assert.doesNotMatch(polling, /onFindAssets|startDiscovery/u);

  for (const [english, traditionalChinese] of [
    ["Continue: find cloud assets", "繼續：尋找雲端資產"],
    ["Starting a scan remains a separate step", "開始掃描是另一個獨立步驟"],
    ["The next step lists its dedicated IAM resources before creation", "下一步會在建立前列出專用 IAM 資源"],
  ]) {
    assert.ok(providerPanelSource.includes(english), english);
    assert.ok(providerPanelSource.includes(traditionalChinese), traditionalChinese);
  }
});

test("the first layer uses plain-language scan choices in both locales", () => {
  for (const [english, traditionalChinese] of [
    ["Items found", "找到的項目"],
    ["Setup required", "需要設定"],
    ["Recommended settings are ready", "建議設定已準備好"],
    ["I confirm this is my website or a system I am allowed to scan", "我確認這是我的網站，或是我有權掃描的系統"],
    ["I confirm this scan may connect to the selected internal network", "我確認這次掃描可以連線到所選內部網路"],
  ]) {
    assert.ok(source.includes(english), `missing plain-language English copy: ${english}`);
    assert.ok(source.includes(traditionalChinese), `missing plain-language Traditional Chinese copy: ${traditionalChinese}`);
  }
  assert.ok(source.includes("setShowAdvancedExternalSettings(false)"));
  assert.ok(!source.includes('setShowAdvancedExternalSettings(externalActivity === "active_external")'));
});

test("local-project formats stay available behind technical details", () => {
  const workspaceStart = source.indexOf('id="workspace-snapshot-form"');
  const technicalStart = source.indexOf('<details className="coverage-form-technical">', workspaceStart);
  const technicalEnd = source.indexOf("</details>", technicalStart);
  assert.notEqual(workspaceStart, -1);
  assert.notEqual(technicalStart, -1);
  assert.notEqual(technicalEnd, -1);
  const visibleSetup = source.slice(workspaceStart, technicalStart);
  const technicalSetup = source.slice(technicalStart, technicalEnd);
  assert.ok(visibleSetup.includes("selectedLocalInput.cautionBody"));
  assert.ok(visibleSetup.includes("localInputDefinitions[workspaceInputProfile].detail"));
  assert.match(visibleSetup, /!guidedLocalProfile && <label className="field">[\s\S]*pageCopy\.inputType/u);
  assert.match(technicalSetup, /guidedLocalProfile && \([\s\S]*pageCopy\.advancedLocalInputSummary[\s\S]*Object\.keys\(localInputDefinitions\)/u);
  assert.ok(technicalSetup.includes("pageCopy.gitTechnicalBody"));
  assert.ok(technicalSetup.includes("localInputDefinitions[workspaceInputProfile].technical"));
  assert.ok(source.includes("Prepare this project for scanning"));
  assert.ok(source.includes("準備這份專案進行掃描"));
});

test("choosing a local folder authorizes its private read-only snapshot without a second ownership form", () => {
  for (const phrase of [
    "Choose once, then scan the private copy",
    "選擇一次，再掃描私密副本",
    "Choosing a folder creates a private read-only snapshot.",
    "選擇資料夾會建立私密唯讀快照。",
  ]) {
    assert.ok(source.includes(phrase), `missing local one-step permission contract: ${phrase}`);
  }
  for (const retired of [
    "attaching it does not grant scan permission",
    "附加動作不會授予掃描權限",
    "Confirm ownership and read-only local review in step 3",
    "請在步驟 3 確認所有權與本機唯讀檢查",
  ]) {
    assert.ok(!source.includes(retired), `retired duplicate local consent remains: ${retired}`);
  }
  for (const phrase of [
    "Saved copy: {copy} · Read-only checks: {checks}.",
    "已保存副本：{copy} · 唯讀檢查：{checks}。",
  ]) assert.ok(source.includes(phrase), phrase);
  assert.match(source, /guidedLocalConsent && \([\s\S]*pageCopy\.guidedLocalBoundary[\s\S]*copy: selectedScopeAssets\.map[\s\S]*checks: \(guidedLocalEngineIds \?\? \[\]\)\.map\(\(engineId\) => text\(engineOutcomeForId\(engineId\)\)\)/u);
});

test("source-code setup says private and masked instead of asking users to remove secrets", () => {
  for (const phrase of [
    "Code you wrote or generated with AI",
    "自己寫或 AI 生成的程式碼",
    "Scan a private local copy",
    "掃描私密的本機副本",
    "Detected secret values are masked in results",
    "找到的秘密值會在結果中遮罩",
  ]) {
    assert.ok(`${source}\n${localInputProfileSource}`.includes(phrase), phrase);
  }

  for (const outdated of [
    "Remove passwords, keys, and tokens from this folder first",
    "請先移除這個資料夾裡的密碼、金鑰與 token",
    "Remove secrets before you continue",
    "繼續前請先移除秘密值",
  ]) {
    assert.ok(!source.includes(outdated), outdated);
  }
});

test("repository technical details disclose every planned engine", () => {
  assert.ok(localInputProfileSource.includes(
    'repository_working_tree: "Gitleaks, Semgrep, Syft, Trivy, Grype, TruffleHog, KICS, Checkov"',
  ));
  assert.ok(localInputProfileSource.includes('iac_working_tree: "Checkov, KICS, Trivy"'));
  assert.ok(localInputProfileSource.includes('container_image_oci_layout: "Syft, Trivy, Grype"'));
});

test("a failed workspace copy stays visible and suggests a source-only folder", () => {
  assert.match(source, /onAttachWorkspaceSnapshot: \(input: AttachWorkspaceSnapshotInput\) => Promise<boolean>/u);
  assert.match(source, /const attached = await onAttachWorkspaceSnapshot/u);
  assert.match(source, /if \(!attached\) setWorkspaceFormError\(pageCopy\.workspaceErrorCopy\)/u);
  assert.match(source, /Copying and verifying locally/u);
  assert.match(source, /source-only project folder without generated dependencies or build output/u);
  assert.match(source, /正在本機複製並驗證/u);
});

test("each guided local route has plain-language first-layer copy in both locales", () => {
  for (const [english, traditionalChinese] of [
    ["Choose code you wrote or generated with AI", "選擇自己寫或 AI 生成的程式碼"],
    ["Choose the infrastructure code you want checked", "選擇想檢查的基礎設施程式碼"],
    ["Choose the container image you want checked", "選擇想檢查的容器映像"],
    ["Choose the Kubernetes settings you want checked", "選擇想檢查的 Kubernetes 設定"],
    ["Add this source-code project", "加入這份程式碼專案"],
    ["Add this infrastructure code", "加入這份基礎設施程式碼"],
    ["Add this container image", "加入這份容器映像"],
    ["Add these Kubernetes settings", "加入這些 Kubernetes 設定"],
  ]) {
    assert.ok(localInputProfileSource.includes(english), english);
    assert.ok(localInputProfileSource.includes(traditionalChinese), traditionalChinese);
  }

  for (const phrase of [
    "Syft inventories its software components, while Trivy and Grype check them for known vulnerabilities.",
    "Syft 會盤點其中的軟體元件，Trivy 與 Grype 會檢查已知弱點。",
  ]) assert.ok(localInputProfileSource.includes(phrase), phrase);
});

test("saved-input cautions state direct requirements without preflight instruction copy", () => {
  for (const phrase of [
    "Inventory requirement: no passwords, tokens, private keys, or other secret values",
    "盤點檔規格：不得包含密碼、token、私鑰或其他秘密值",
    "Deployment files must not contain secret values",
    "部署檔案不得包含秘密值",
    "Input: exported settings without live-cluster credentials",
    "輸入：不含正式叢集憑證的匯出設定",
    "Input requirement: no live-cluster credentials or unrelated host files",
    "輸入規格：不得包含正式叢集憑證或無關的主機檔案",
  ]) assert.ok(`${source}\n${localInputProfileSource}`.includes(phrase), phrase);

  for (const retiredInstruction of [
    "Remove secret values from deployment files first",
    "Replace embedded passwords, keys, and tokens before adding the folder",
    "Do not include kubeconfig files, tokens, or certificates",
    "Do not add live-cluster credentials or unrelated host files",
    "Remove passwords, tokens, private keys, and other secrets first",
  ]) assert.ok(!`${source}\n${localInputProfileSource}`.includes(retiredInstruction), retiredInstruction);
});

test("guided selection status is honest and does not keep prompting after auto-selection", () => {
  const authorizationLabels = source.slice(
    source.indexOf("const authorizationStateLabels"),
    source.indexOf("const prohibitedCapabilities"),
  );
  assert.doesNotMatch(authorizationLabels, /Ready to scan|準備掃描|Choose your first item/u);
  assert.ok(source.includes('authorized: bilingual("Target confirmed", "目標已確認")'));
  assert.ok(source.includes("shouldPromptForFirstAsset(pendingAssets.length, selectedAssets.length)"));
});

test("saved permission without a scan attempt is shown as ready instead of failed", () => {
  for (const phrase of [
    "Permission saved. Start this item.",
    "掃描許可已儲存；開始這個項目。",
    "Permission saved. Start the scan.",
    "掃描許可已儲存；開始掃描。",
    "Not scanned",
    "未掃描",
  ]) assert.ok(source.includes(phrase), phrase);
  assert.match(source, /state === "authorized_incomplete" && scanAttempted === false/u);
  assert.match(source, /asset\.coverageState === "authorized_incomplete" && asset\.scanAttempted !== false/u);
  assert.match(source, /readyForFirstScan \? text\(pageCopy\.readyToScan\) : meta\.shortLabel/u);
  assert.match(source, /readyForFirstScan[\s\S]*pageCopy\.notScannedYet[\s\S]*record\.lastCheckedAt/u);
  assert.match(source, /isAwaitingFirstScan\(asset\.coverageState, asset\.scanAttempted\)/u);
});

test("saved sensitive-network access is labeled as internal, not external", () => {
  assert.ok(source.includes('lowImpactInternalActivity: bilingual("Low-impact internal checks", "低影響內部連線")'));
  assert.match(
    source,
    /scope\.activity === "low_impact_external" && scope\.allowSensitiveNetworks[\s\S]*pageCopy\.lowImpactInternalActivity/u,
  );
});

test("the concise three-step form keeps setup state mounted and lets review flow directly into Start", () => {
  assert.ok(!source.includes("coverage-journey"));
  assert.ok(!source.includes("coverageJourneySteps"));
  assert.ok(!source.includes('href="#coverage-step-3"'));
  assert.ok(source.includes('scrollToCoverageStep("coverage-step-3")'));
  assert.ok(source.includes('(prefers-reduced-motion: reduce)'));
  assert.ok(source.includes('id="coverage-step-1"'));
  assert.ok(source.includes('id="coverage-step-2"'));
  assert.ok(source.includes('id="coverage-step-3"'));
  assert.ok(!source.includes("continueStep3"));
  assert.ok(source.includes('className="coverage-source-setup"'));
  assert.ok(source.includes("open={sourceSetupOpen}"));
  assert.match(source, /className="coverage-provider-slot" hidden=\{!showProviderSetup\}[\s\S]*<ProviderAuthorizationPanel/u);
  assert.doesNotMatch(source, /showProviderSetup && \([\s\S]{0,200}<ProviderAuthorizationPanel/u);
  assert.ok(source.includes('className="coverage-summary-row"'));
  assert.ok(source.includes('"asset-review-list asset-review-list--compact"'));
  assert.match(
    coverageCss,
    /@media \(max-width: 600px\)[\s\S]*\.asset-review-list--compact \.asset-review-card--list-row \{[\s\S]*grid-template-columns: 1fr/u,
  );
});

test("the rendered Coverage tree has no hard-coded Traditional Chinese UI copy", () => {
  const renderStart = source.search(/\r?\n  return \(\r?\n    <div className="page page--coverage">/u);
  assert.notEqual(renderStart, -1);
  const renderedTree = source.slice(renderStart);
  assert.doesNotMatch(renderedTree, /[\u3400-\u9fff]/u);
  assert.ok(renderedTree.includes("text(compactGuidedReview ? pageCopy.focusedReviewTitle : pageCopy.headerTitle)"));
});
