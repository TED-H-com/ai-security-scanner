import { cleanup, fireEvent, render, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, expect, test, vi } from "vitest";

import { CoveragePage } from "../../src/pages/CoveragePage";
import { I18nProvider, localeStorageKey } from "../../src/i18n";
import { scannerService } from "../../src/services/scanner";
import type { Asset, BootstrapCleanupObligationSummary, ConnectedSource, CoverageRecord, EngineManifest, InstalledProviderAuthorization } from "../../src/types";
import { internalDeviceHttpsProfile } from "../../src/internalDeviceProfile";
import { internalEndpointProfiles } from "../../src/internalEndpointProfile";
import { internalHostGreenboneProfile } from "../../src/internalHostProfile";
import { websitePassiveProfile, websiteQuickProfile } from "../../src/websiteQuickProfile";

const pendingAsset = (overrides: Partial<Asset>): Asset => ({
  id: "asset-1",
  name: "asset-1",
  type: "repository",
  platform: "code",
  locator: "private-copy://asset-1",
  coverageState: "discovered_not_authorized",
  authorizationState: "pending",
  allowedModes: [],
  findingCount: 0,
  scanAttempted: false,
  ...overrides,
});

type RouteOptions = Pick<React.ComponentProps<typeof CoveragePage>, "assessmentIntent" | "requestedActivities" | "assets"> & {
  caseId?: string;
  sources?: ConnectedSource[];
  coverage?: CoverageRecord[];
  nativeMode?: boolean;
  busy?: boolean;
  runtimeSetupNotice?: React.ReactNode;
  engineManifests?: EngineManifest[];
  onStartScan?: React.ComponentProps<typeof CoveragePage>["onStartScan"];
  onStartEnvironmentScan?: React.ComponentProps<typeof CoveragePage>["onStartEnvironmentScan"];
  onSelectAgenticFramework?: React.ComponentProps<typeof CoveragePage>["onSelectAgenticFramework"];
};

const routeElement = ({
  caseId = "case-1",
  assessmentIntent,
  requestedActivities,
  assets,
  coverage = [],
  sources = [],
  nativeMode = true,
  busy = false,
  runtimeSetupNotice,
  engineManifests = [],
  onStartScan = () => Promise.resolve(true),
  onStartEnvironmentScan = () => Promise.resolve(true),
  onSelectAgenticFramework,
}: RouteOptions) => (
  <I18nProvider>
    <CoveragePage
      caseId={caseId}
      assessmentIntent={assessmentIntent}
      requestedActivities={requestedActivities}
      coverage={coverage}
      sources={sources}
      engineManifests={engineManifests}
      assets={assets}
      scopeGrants={[]}
      nativeMode={nativeMode}
      busy={busy}
      runtimeSetupNotice={runtimeSetupNotice}
      onChooseSnapshot={() => Promise.resolve(null)}
      onConnectSourceSnapshot={() => Promise.resolve()}
      onChooseWorkspace={() => Promise.resolve(null)}
      onAttachWorkspaceSnapshot={() => Promise.resolve(true)}
      onStartDiscovery={() => Promise.resolve()}
      onAuthorizationChanged={() => Promise.resolve()}
      onStartScan={onStartScan}
      onStartEnvironmentScan={onStartEnvironmentScan}
      onSelectAgenticFramework={onSelectAgenticFramework}
    />
  </I18nProvider>
);

const renderRoute = (options: RouteOptions) => render(routeElement(options));

beforeEach(() => {
  window.localStorage.setItem(localeStorageKey, "en");
  Object.defineProperty(window, "requestAnimationFrame", {
    configurable: true,
    value: (callback: FrameRequestCallback) => window.setTimeout(() => callback(performance.now()), 0),
  });
  Object.defineProperty(window, "cancelAnimationFrame", {
    configurable: true,
    value: (handle: number) => window.clearTimeout(handle),
  });
  Object.defineProperty(HTMLElement.prototype, "scrollIntoView", {
    configurable: true,
    value: () => undefined,
  });
});

afterEach(() => {
  cleanup();
  window.localStorage.clear();
});

test("existing inputs collapse source setup without unmounting the cloud panel", () => {
  const source: ConnectedSource = {
    id: "source-aws",
    kind: "aws_organization",
    label: "Production AWS",
    status: "not_connected",
    readOnly: true,
  };
  vi.spyOn(scannerService, "providerAuthorizationStatus").mockResolvedValue({
    data: null,
    mode: "native",
  });
  const { container, getByRole } = renderRoute({
    assessmentIntent: undefined,
    requestedActivities: [],
    assets: [pendingAsset({ name: "existing-project" })],
    sources: [source],
  });

  const setup = container.querySelector<HTMLDetailsElement>(".coverage-source-setup");
  expect(setup).not.toBeNull();
  expect(setup!.open).toBe(false);
  expect(setup!.querySelectorAll(".coverage-input-card")).toHaveLength(4);
  const providerSlot = setup!.querySelector<HTMLElement>(".coverage-provider-slot");
  const providerPanel = providerSlot?.querySelector(".provider-auth-panel");
  expect(providerSlot?.hidden).toBe(true);
  expect(providerPanel).not.toBeNull();

  fireEvent.click(setup!.querySelector("summary")!);
  expect(setup!.open).toBe(true);
  fireEvent.click(getByRole("button", { name: "Connect a cloud account" }));
  expect(providerSlot?.hidden).toBe(false);
  fireEvent.click(getByRole("button", { name: "Close cloud setup" }));
  expect(providerSlot?.hidden).toBe(true);
  expect(providerSlot?.querySelector(".provider-auth-panel")).toBe(providerPanel);
});

test("a new cloud project opens on its sign-in guide although native projects list every planned source", async () => {
  const sources: ConnectedSource[] = [
    { id: "source-m365", kind: "microsoft365_tenant", label: "Microsoft 365 tenant", status: "not_connected", readOnly: true },
    { id: "source-dns", kind: "dns", label: "DNS", status: "not_connected", readOnly: true },
    { id: "source-files", kind: "file_system", label: "Files", status: "not_connected", readOnly: true },
  ];
  vi.spyOn(scannerService, "providerAuthorizationStatus").mockResolvedValue({ data: null, mode: "native" });
  vi.spyOn(scannerService, "listProviderBootstrapCleanup").mockResolvedValue({ data: [], mode: "native" });

  const { container } = renderRoute({
    assessmentIntent: "cloud_account",
    requestedActivities: ["configuration_assessment"],
    assets: [],
    sources,
  });

  const setup = container.querySelector<HTMLDetailsElement>(".coverage-source-setup");
  expect(setup?.open).toBe(true);
  expect(container.querySelector<HTMLElement>(".coverage-provider-slot")?.hidden).toBe(false);
  await waitFor(() => {
    expect(container.querySelector(".provider-connection-guide > summary")?.textContent).toBe("Open the connection guide");
  });
});

test("a collapsed source setup keeps unresolved temporary-cloud cleanup visible and directly reviewable", async () => {
  const source: ConnectedSource = {
    id: "source-aws",
    kind: "aws_organization",
    label: "Production AWS",
    status: "not_connected",
    readOnly: true,
  };
  const obligation: BootstrapCleanupObligationSummary = {
    operationId: "bootstrap-1",
    provider: "aws",
    caseId: "case-1",
    schemaVersion: "1.0.0",
    status: "waiting_for_credential_expiry",
    totalItems: 1,
    pendingItems: 0,
    inProgressItems: 0,
    retryableItems: 0,
    waitingItems: 1,
    completedItems: 0,
    createdAt: "2026-09-07T12:00:00Z",
  };
  vi.spyOn(scannerService, "providerAuthorizationStatus").mockResolvedValue({ data: null, mode: "native" });
  vi.spyOn(scannerService, "listProviderBootstrapCleanup").mockResolvedValue({ data: [obligation], mode: "native" });

  const { container, getByRole, getByText } = renderRoute({
    assessmentIntent: undefined,
    requestedActivities: [],
    assets: [pendingAsset({ name: "existing-project" })],
    sources: [source],
  });

  const setup = container.querySelector<HTMLDetailsElement>(".coverage-source-setup")!;
  expect(setup.open).toBe(false);
  await waitFor(() => expect(setup.querySelector("summary")?.textContent).toBe("Temporary cloud cleanup required"));
  const attention = container.querySelector<HTMLElement>("[role='alert']");
  expect(attention?.textContent).toContain("Temporary cloud cleanup required");
  expect(attention?.textContent).toContain("Open the recorded cleanup");
  expect(attention?.textContent).not.toMatch(/before closing the app/iu);

  fireEvent.click(getByRole("button", { name: "Review cleanup" }));
  expect(setup.open).toBe(true);
  expect(container.querySelector<HTMLElement>(".coverage-provider-slot")?.hidden).toBe(false);
  expect(getByRole("heading", { name: "Cleanup records requiring action" })).not.toBeNull();
  expect(getByText(/AWS · Temporary access expiry pending/u)).not.toBeNull();
  expect(container.textContent).not.toMatch(/waiting for temporary access to expire/iu);
  expect(getByRole("button", { name: "Reconnect and continue cleanup" })).not.toBeNull();
  const cleanupRegion = getByRole("region", { name: "Temporary-access cleanup" });
  await waitFor(() => expect(document.activeElement).toBe(cleanupRegion));
});

test("an unresolved cleanup record remains actionable when its provider source is missing", async () => {
  const obligation: BootstrapCleanupObligationSummary = {
    operationId: "bootstrap-missing-source",
    provider: "aws",
    caseId: "case-1",
    schemaVersion: "1.0.0",
    status: "pending",
    totalItems: 1,
    pendingItems: 1,
    inProgressItems: 0,
    retryableItems: 0,
    waitingItems: 0,
    completedItems: 0,
    createdAt: "2026-09-07T12:00:00Z",
  };
  vi.spyOn(scannerService, "listProviderBootstrapCleanup").mockResolvedValue({ data: [obligation], mode: "native" });

  const { container, getByRole, getByText } = renderRoute({
    assessmentIntent: undefined,
    requestedActivities: [],
    assets: [pendingAsset({ name: "existing-project" })],
    sources: [],
  });

  const setup = container.querySelector<HTMLDetailsElement>(".coverage-source-setup")!;
  await waitFor(() => expect(setup.querySelector("summary")?.textContent).toBe("Temporary cloud cleanup required"));
  fireEvent.click(getByRole("button", { name: "Review cleanup" }));

  expect(getByText("Use Add an inventory file above to add the matching cloud account. Then return here to reconnect and remove only its recorded temporary resources.")).not.toBeNull();
  expect(getByRole("heading", { name: "Cleanup records requiring action" })).not.toBeNull();
  expect((getByRole("button", { name: "Select the AWS source first" }) as HTMLButtonElement).disabled).toBe(true);
  const cleanupRegion = getByRole("region", { name: "Temporary-access cleanup" });
  await waitFor(() => expect(document.activeElement).toBe(cleanupRegion));
});

test("a failed cleanup lookup remains actionable without a provider source and offers a retry", async () => {
  const cleanupLookup = vi.spyOn(scannerService, "listProviderBootstrapCleanup")
    .mockRejectedValueOnce(new Error("private backend detail"))
    .mockResolvedValue({ data: [], mode: "native" });

  const { container, getByRole, getByText, queryByText } = renderRoute({
    assessmentIntent: undefined,
    requestedActivities: [],
    assets: [pendingAsset({ name: "existing-project" })],
    sources: [],
  });

  const setup = container.querySelector<HTMLDetailsElement>(".coverage-source-setup")!;
  await waitFor(() => expect(setup.querySelector("summary")?.textContent).toBe("Temporary cloud cleanup required"));
  fireEvent.click(getByRole("button", { name: "Review cleanup" }));
  expect(getByText("Use Add an inventory file above to add the matching cloud account. Then return here to reconnect and remove only its recorded temporary resources.")).not.toBeNull();
  const cleanupError = getByText("Temporary-access cleanup status unavailable. Check again.").closest<HTMLElement>("[role='alert']")!;
  expect(cleanupError).not.toBeNull();
  const cleanupRegion = getByRole("region", { name: "Temporary-access cleanup" });
  await waitFor(() => expect(document.activeElement).toBe(cleanupRegion));

  fireEvent.click(within(cleanupError).getByRole("button", { name: "Check cleanup again" }));
  await waitFor(() => expect(cleanupLookup).toHaveBeenCalledTimes(2));
  await waitFor(() => expect(queryByText("Temporary-access cleanup status unavailable. Check again.")).toBeNull());
  expect(setup.querySelector("summary")?.textContent).toBe("Add or change source");
});

test("changing scan projects remounts and clears the hidden provider subtree", () => {
  const sources: ConnectedSource[] = [
    {
      id: "source-aws",
      kind: "aws_organization",
      label: "Production AWS",
      status: "not_connected",
      readOnly: true,
    },
    {
      id: "source-m365",
      kind: "microsoft365_tenant",
      label: "Microsoft 365",
      status: "not_connected",
      readOnly: true,
    },
  ];
  const route = {
    assessmentIntent: undefined,
    requestedActivities: [],
    assets: [pendingAsset({ name: "existing-project" })],
    sources,
    nativeMode: false,
  } satisfies RouteOptions;
  const { container, getByLabelText, rerender } = renderRoute({ ...route, caseId: "case-1" });

  const firstPanel = container.querySelector(".provider-auth-panel");
  const firstSelect = getByLabelText("Account to scan") as HTMLSelectElement;
  fireEvent.change(firstSelect, { target: { value: "source-m365" } });
  expect(firstSelect.value).toBe("source-m365");

  rerender(routeElement({ ...route, caseId: "case-2" }));

  const nextPanel = container.querySelector(".provider-auth-panel");
  const nextSelect = getByLabelText("Account to scan") as HTMLSelectElement;
  expect(nextPanel).not.toBe(firstPanel);
  expect(nextSelect.value).toBe("source-aws");
});

test("a fresh project keeps all source choices visible", () => {
  const { container } = renderRoute({
    assessmentIntent: undefined,
    requestedActivities: [],
    assets: [],
  });

  const setup = container.querySelector<HTMLDetailsElement>(".coverage-source-setup");
  expect(setup?.open).toBe(true);
  expect(setup?.querySelector("summary")?.textContent).toBe("Add or change source");
  expect(setup?.querySelectorAll(".coverage-input-card")).toHaveLength(4);
});

test("review uses compact summary chips and keeps missing-source truth visible", () => {
  const unknownSource: CoverageRecord = {
    id: "coverage-unknown",
    label: "AWS inventory",
    platform: "aws",
    sourceKind: "aws_organization",
    state: "source_unavailable_unknown",
    assetCount: 0,
    detail: "not connected",
  };
  const { container, queryByText } = renderRoute({
    assessmentIntent: undefined,
    requestedActivities: [],
    assets: [pendingAsset({
      name: "existing-project",
      coverageState: "discovered_authorized_scanned",
      authorizationState: "authorized",
      allowedModes: ["inventory"],
      scanAttempted: true,
    })],
    coverage: [unknownSource],
  });

  const step = container.querySelector("#coverage-step-2");
  expect(step?.querySelector(".coverage-step-heading p")).toBeNull();
  expect(step?.querySelector(".coverage-step-heading .button")).toBeNull();
  expect(step?.querySelectorAll(".metric-card")).toHaveLength(0);
  expect(step?.querySelector(".coverage-summary-row")?.textContent).toContain("Items found1");
  expect(step?.querySelector(".coverage-summary-row")?.textContent).toContain("Items fully checked1");
  expect(step?.querySelector(".coverage-summary-row")?.textContent).not.toContain("Checks completed");
  expect(queryByText("Sources without data: 1")).not.toBeNull();
  expect(container.querySelector(".page-header p")).toBeNull();
});

test("many assets render as compact selectable rows with closed technical details", () => {
  const assets = Array.from({ length: 8 }, (_, index) => pendingAsset({
    id: `asset-${index + 1}`,
    name: `project-${index + 1}`,
  }));
  const { container } = renderRoute({
    assessmentIntent: undefined,
    requestedActivities: [],
    assets,
  });

  const list = container.querySelector(".asset-review-list--compact");
  expect(list?.getAttribute("role")).toBe("list");
  expect(list?.querySelectorAll(".asset-review-card--list-row")).toHaveLength(8);
  expect(list?.querySelectorAll(".asset-review-card__next")).toHaveLength(0);
  expect(list?.querySelectorAll(".asset-review-card__next-inline")).toHaveLength(8);
  expect(Array.from(list?.querySelectorAll<HTMLDetailsElement>(".asset-review-card__technical") ?? [])
    .every((details) => details.open === false)).toBe(true);
});

test("a host-shaped local snapshot keeps local guidance instead of external-target guidance", () => {
  const { queryByText, getByText } = renderRoute({
    assessmentIntent: undefined,
    requestedActivities: ["local_artifact_analysis"],
    assets: [pendingAsset({
      id: "node-snapshot",
      name: "saved-node-settings",
      type: "service",
      platform: "external",
      locator: "private-copy://node-snapshot",
      internetExposed: false,
      localInputProfile: "kubernetes_node_snapshot",
      scanAttempted: true,
    })],
  });

  expect(getByText("Allow offline review of this saved Kubernetes input only.")).not.toBeNull();
  expect(queryByText(/Confirm this is your internal system/u)).toBeNull();
});

test("guided Kubernetes setup renders the saved-input boundary as a direct requirement", () => {
  const { container } = renderRoute({
    assessmentIntent: "kubernetes",
    requestedActivities: ["local_artifact_analysis"],
    assets: [],
  });

  expect(container.textContent).toContain("Input: exported settings without live-cluster credentials");
  expect(container.textContent).toContain("Input requirement: no kubeconfig files, tokens, or certificates");
  expect(container.textContent).not.toMatch(/do not include kubeconfig|use exported settings/iu);
});

test("guided local Start keeps the exact copy, read-only check, and unchanged-source boundary visible", async () => {
  const onStartScan = vi.fn().mockResolvedValue(true);
  const { container } = renderRoute({
    assessmentIntent: "source_code",
    requestedActivities: ["local_artifact_analysis"],
    onStartScan,
    assets: [pendingAsset({
      name: "source-tree-copy",
      localInputProfile: "repository_working_tree",
    })],
  });

  await waitFor(() => {
    expect(container.querySelector(".coverage-guided-boundary")?.textContent).toBe(
      "Saved copy: source-tree-copy · Read-only checks: Exposed secrets in code, Risky code patterns, Software ingredients, Known package vulnerabilities, Known software vulnerabilities, Exposed credentials and secrets, Infrastructure-code mistakes, Risky infrastructure settings.",
    );
  });
  expect(container.querySelector(".coverage-review-timing")?.textContent).toBe(
    "Timing target: a useful result within minutes after tools are ready.",
  );
  expect(container.querySelector(".scope-mode-fieldset")).toBeNull();

  const start = Array.from(container.querySelectorAll<HTMLButtonElement>(".scope-confirmation-panel button[type='submit']"))
    .find((button) => button.textContent?.includes("Confirm and start scan"));
  expect(start).toBeTruthy();
  fireEvent.click(start!);

  expect(onStartScan).toHaveBeenCalledWith(
    ["asset-1"],
    ["local_artifact"],
    "The user explicitly selected this saved local copy and confirmed the recommended read-only checks.",
    undefined,
    ["gitleaks", "semgrep", "syft", "trivy", "grype", "trufflehog", "kics", "checkov"],
  );
});

test("guided container Start routes Syft inventory with Trivy and Grype vulnerability checks", async () => {
  const onStartScan = vi.fn().mockResolvedValue(true);
  const { container, getByText } = renderRoute({
    assessmentIntent: "container_image",
    requestedActivities: ["local_artifact_analysis"],
    onStartScan,
    assets: [pendingAsset({
      name: "payments-image-copy",
      type: "image",
      platform: "container",
      localInputProfile: "container_image_oci_layout",
    })],
  });

  expect(getByText(
    "Pick one exported OCI image folder. Syft inventories its software components, while Trivy and Grype check them for known vulnerabilities. Everything runs locally without starting the image.",
  )).not.toBeNull();

  await waitFor(() => {
    expect(container.querySelector(".coverage-guided-boundary")?.textContent).toBe(
      "Saved copy: payments-image-copy · Read-only checks: Software ingredients, Known package vulnerabilities, Known software vulnerabilities.",
    );
  });

  const start = Array.from(container.querySelectorAll<HTMLButtonElement>(".scope-confirmation-panel button[type='submit']"))
    .find((button) => button.textContent?.includes("Confirm and start scan"));
  expect(start).toBeTruthy();
  fireEvent.click(start!);

  expect(onStartScan).toHaveBeenCalledWith(
    ["asset-1"],
    ["local_artifact"],
    "The user explicitly selected this saved local copy and confirmed the recommended read-only checks.",
    undefined,
    ["syft", "trivy", "grype"],
  );
});

test("guided local Review names the same checks in Traditional Chinese", async () => {
  window.localStorage.setItem(localeStorageKey, "zh-TW");
  const { container } = renderRoute({
    assessmentIntent: "source_code",
    requestedActivities: ["local_artifact_analysis"],
    assets: [pendingAsset({
      name: "source-tree-copy",
      localInputProfile: "repository_working_tree",
    })],
  });

  await waitFor(() => {
    expect(container.querySelector(".coverage-guided-boundary")?.textContent).toBe(
      "已保存副本：source-tree-copy · 唯讀檢查：程式碼中暴露的秘密、程式碼中的危險寫法、軟體包含的元件、套件中的已知弱點、軟體中的已知弱點、外洩的憑證與機密資料、基礎設施程式碼錯誤、基礎設施設定風險。",
    );
  });
});

test("an AI project with a selected MCP configuration lists the MCP check it will run", async () => {
  const onStartScan = vi.fn().mockResolvedValue(true);
  const mcpArmorManifest: EngineManifest = {
    id: "mcp-armor",
    name: "mcp-armor",
    category: "ai_mcp_configuration",
    version: "1.0.2",
    imageDigest: "sha256:mcp-armor",
    license: "Apache-2.0",
    redistribution: "on_demand",
    platforms: [],
    supportedProviders: [],
    status: "ready",
    runnable: true,
    blockedBy: [],
    compatibilityValid: true,
    providerExecutionProfiles: [],
  };

  const { container } = renderRoute({
    assessmentIntent: "ai_application",
    requestedActivities: ["local_artifact_analysis"],
    onStartScan,
    engineManifests: [mcpArmorManifest],
    assets: [pendingAsset({
      name: "agent-copy",
      localInputProfile: "repository_working_tree",
      selectedMcpConfiguration: "mcp.json",
      mcpConfigurationCandidates: [
        { relativePath: "mcp.json", sha256: "0".repeat(64), byteLength: 42 },
      ],
    })],
  });

  await waitFor(() => {
    expect(container.querySelector(".coverage-guided-boundary")).not.toBeNull();
  });
  expect(container.querySelector(".coverage-guided-boundary")?.textContent).toMatch(
    /Risky infrastructure settings, MCP configuration risks\.$/u,
  );

  const start = Array.from(container.querySelectorAll<HTMLButtonElement>(".scope-confirmation-panel button[type='submit']"))
    .find((button) => button.textContent?.includes("Confirm and start scan"));
  expect(start).toBeTruthy();
  fireEvent.click(start!);

  expect(onStartScan).toHaveBeenCalledWith(
    ["asset-1"],
    ["local_artifact"],
    "The user explicitly selected this saved local copy and confirmed the recommended read-only checks.",
    undefined,
    ["gitleaks", "semgrep", "syft", "trivy", "grype", "trufflehog", "kics", "checkov", "mcp-armor"],
  );
});

test("guided cloud Start keeps the exact signed-in account, checks, and no-change boundary visible", async () => {
  const source: ConnectedSource = {
    id: "source-aws",
    kind: "aws_organization",
    label: "Production AWS",
    status: "connected",
    readOnly: true,
  };
  const authorization: InstalledProviderAuthorization = {
    schema_version: "1.0.0",
    case_id: "case-1",
    source_id: source.id,
    provider: "aws",
    source_kind: source.kind,
    profile: "aws_read_only_role",
    credential_source: "provider_hosted",
    provider_identity: "123456789012",
    permissions: ["inventory", "configuration"],
    expires_at: "2099-01-01T00:00:00.000Z",
    allowed_engine_ids: [],
    max_checkouts: 1,
    safety_notice: "Read-only",
  };
  vi.spyOn(scannerService, "providerAuthorizationStatus").mockResolvedValue({
    data: authorization,
    mode: "native",
  });

  const { container } = renderRoute({
    assessmentIntent: "cloud_account",
    requestedActivities: ["configuration_assessment"],
    sources: [source],
    assets: [pendingAsset({
      name: "Production AWS (123456789012)",
      type: "cloud_account",
      platform: "aws",
      locator: "aws://123456789012",
      discoveredFromSourceIds: [source.id],
    })],
  });

  await waitFor(() => {
    expect(container.querySelector(".coverage-guided-boundary")?.textContent).toBe(
      "Signed-in account: Production AWS (123456789012) · Read-only checks: Read-only inventory, Review settings.",
    );
  });
  const advanced = container.querySelector<HTMLDetailsElement>(".coverage-scan-type-advanced");
  expect(advanced).not.toBeNull();
  expect(advanced?.open).toBe(false);
});

test("public website flow applies the fixed Nuclei quick profile and starts without another form", async () => {
  const onStartScan = vi.fn().mockResolvedValue(true);
  const { container, queryByText } = renderRoute({
    assessmentIntent: "deployed_website",
    requestedActivities: ["active_external_vulnerability_tests"],
    nativeMode: false,
    onStartScan,
    assets: [pendingAsset({
      id: "asset-example",
      name: "https://example.com:443",
      type: "service",
      platform: "external",
      locator: "https://example.com:443",
      identifiers: [
        { namespace: "web_origin", value: "https://example.com:443" },
        { namespace: "dns_name", value: "example.com" },
      ],
      internetExposed: true,
      declaredWebService: { protocol: "https", port: 443, path: "/account" },
    })],
  });

  await waitFor(() => {
    expect(container.querySelector(".coverage-guided-boundary")?.textContent).toBe(
      "Scope: https://example.com:443, not only /account. Nuclei applies matching pinned read-only checks at max 10/s, 5 concurrent, and 10s timeout. No sign-in, forms, redirects, or exploitation. Start only with permission for the full origin.",
    );
  });
  expect(container.querySelector(".coverage-review-timing")?.textContent).toBe(
    "Timing target: a useful result within minutes after tools are ready.",
  );

  const pageHeader = container.querySelector(".page-header");
  expect(pageHeader?.querySelector("h1")?.textContent).toBe("Review and start");
  expect(pageHeader?.querySelector("p")?.textContent).toBe("Confirm the target and limits.");
  expect(container.querySelector<HTMLElement>("#coverage-step-1")?.hidden).toBe(true);
  expect(container.querySelector("#coverage-step-2")).toBeNull();
  expect(Array.from(container.querySelectorAll("button")).filter((button) => button.textContent?.trim() === "Refresh items")).toHaveLength(0);
  expect(queryByText("1 selected")).toBeNull();
  expect(container.querySelector(".scope-confirmation-panel__heading")).toBeNull();
  expect(container.querySelector(".scope-confirmation-panel__assets")).toBeNull();
  expect(container.querySelector(".asset-review-list")).toBeNull();
  expect(container.querySelector(".coverage-scan-type-advanced")).toBeNull();
  expect(queryByText("Use a different scan type (advanced)")).toBeNull();
  expect(queryByText("I confirm this is my website or a system I am allowed to scan")).toBeNull();
  expect(queryByText("Note (optional)")).toBeNull();
  expect(queryByText("Approval reference (required)")).toBeNull();

  const advancedSettings = container.querySelectorAll<HTMLDetailsElement>("details.coverage-scan-advanced");
  expect(advancedSettings).toHaveLength(1);
  const advancedSummary = advancedSettings[0]?.querySelector("summary");
  expect(advancedSummary?.textContent).toContain("Advanced scan settings");
  fireEvent.click(advancedSummary!);
  expect(advancedSettings[0]?.open).toBe(true);
  expect((within(advancedSettings[0]).getByLabelText(/Website or system to check/) as HTMLSelectElement).value).toBe("example.com");
  expect((within(advancedSettings[0]).getByLabelText(/Allowed ports/) as HTMLInputElement).value).toBe("443");
  expect(within(advancedSettings[0]).queryByLabelText(/Exact active-test IDs/)).toBeNull();

  const editInputs = Array.from(pageHeader?.querySelectorAll<HTMLButtonElement>("button") ?? [])
    .find((button) => button.textContent?.includes("Edit inputs"));
  expect(editInputs).toBeTruthy();
  fireEvent.click(editInputs!);
  expect(container.querySelector<HTMLElement>("#coverage-step-1")?.hidden).toBe(false);
  expect(container.querySelector("#coverage-step-2")).not.toBeNull();
  const backToReview = Array.from(pageHeader?.querySelectorAll<HTMLButtonElement>("button") ?? [])
    .find((button) => button.textContent?.includes("Back to review"));
  expect(backToReview).toBeTruthy();
  fireEvent.click(backToReview!);
  expect(container.querySelector<HTMLElement>("#coverage-step-1")?.hidden).toBe(true);
  expect(container.querySelector("#coverage-step-2")).toBeNull();

  const start = Array.from(container.querySelectorAll<HTMLButtonElement>(".scope-confirmation-panel button[type='submit']"))
    .find((button) => button.textContent?.includes("Confirm and start scan"));
  expect(start).toBeTruthy();
  expect(start!.disabled).toBe(false);
  fireEvent.click(start!);

  expect(onStartScan).toHaveBeenCalledTimes(1);
  expect(onStartScan).toHaveBeenCalledWith(
    ["asset-example"],
    ["active_external"],
    "The user explicitly confirmed authorization to scan the exact https://example.com:443 origin with the displayed fixed quick profile.",
    {
      target: "example.com",
      protocol: "https",
      ports: [443],
      activity: "active_external",
      ratePolicy: {
        requestsPerSecond: 10,
        concurrency: 5,
        timeoutSeconds: 10,
      },
      templatePolicy: {
        revision: "nuclei-templates@f938a3dd530c283e9387b518b97911152ff5846c",
        profileId: "nuclei_web_safe_v1",
        allowedTemplateIds: [],
        allowHeadless: false,
        allowOutOfBand: false,
        allowFuzzing: false,
        allowFileUpload: false,
        allowDenialOfService: false,
        allowCredentialAttacks: false,
      },
      assertedAuthority: "The user explicitly confirmed authorization to scan the exact https://example.com:443 origin with the displayed fixed quick profile.",
      allowSensitiveNetworks: false,
    },
    ["nuclei"],
  );
}, 15_000);

test("one IT-environment Start routes repositories and exact website origins into one combined run", async () => {
  const onStartScan = vi.fn().mockResolvedValue(true);
  const onStartEnvironmentScan = vi.fn().mockResolvedValue(true);
  const { container, getAllByText, getByRole, getByText } = renderRoute({
    assessmentIntent: "internal_it_environment",
    requestedActivities: ["local_artifact_analysis", "active_external_vulnerability_tests"],
    nativeMode: false,
    onStartScan,
    onStartEnvironmentScan,
    assets: [
      pendingAsset({
        id: "repo-a",
        name: "billing-api",
        locator: "private-copy://repo-a",
        localInputProfile: "repository_working_tree",
      }),
      pendingAsset({
        id: "repo-b",
        name: "customer-portal",
        locator: "private-copy://repo-b",
        localInputProfile: "repository_working_tree",
      }),
      pendingAsset({
        id: "website-public",
        name: "https://portal.example.com:443",
        type: "service",
        platform: "external",
        locator: "https://portal.example.com:443",
        identifiers: [
          { namespace: "web_origin", value: "https://portal.example.com:443" },
          { namespace: "dns_name", value: "portal.example.com" },
        ],
        internetExposed: true,
        declaredWebService: { protocol: "https", port: 443, path: "/login" },
      }),
      pendingAsset({
        id: "website-internal",
        name: "https://10.20.0.5:8443",
        type: "service",
        platform: "external",
        locator: "https://10.20.0.5:8443",
        identifiers: [
          { namespace: "web_origin", value: "https://10.20.0.5:8443" },
          { namespace: "ip_address", value: "10.20.0.5" },
        ],
        internetExposed: false,
        declaredWebService: { protocol: "https", port: 8443, path: "/admin" },
      }),
      pendingAsset({
        id: "internal-host",
        name: "host.internal.example",
        type: "domain",
        platform: "external",
        locator: "host.internal.example",
        identifiers: [{ namespace: "dns_name", value: "host.internal.example" }],
        internetExposed: false,
        declaredHostScan: {
          protocol: "tcp",
          ports: [22, 25, 443, 445, 3389],
          scanProfile: "internal_host_greenbone_remote_safe",
        },
      }),
      pendingAsset({
        id: "device-gateway",
        name: "https://10.20.0.8:443",
        type: "service",
        platform: "external",
        locator: "https://10.20.0.8:443",
        identifiers: [
          { namespace: "web_origin", value: "https://10.20.0.8:443" },
          { namespace: "ip_address", value: "10.20.0.8" },
        ],
        internetExposed: false,
        declaredWebService: {
          protocol: "https",
          port: 443,
          path: "/",
          scanProfile: "internal_device_https",
        },
      }),
      pendingAsset({
        id: "endpoint-ssh",
        name: "server.internal.example",
        type: "service",
        platform: "external",
        locator: "server.internal.example",
        identifiers: [{ namespace: "dns_name", value: "server.internal.example" }],
        internetExposed: false,
        declaredNetworkService: {
          protocol: "tcp",
          port: 2222,
          scanProfile: "internal_endpoint_ssh",
        },
      }),
      pendingAsset({
        id: "endpoint-rdp",
        name: "desktop.internal.example",
        type: "service",
        platform: "external",
        locator: "desktop.internal.example",
        identifiers: [{ namespace: "dns_name", value: "desktop.internal.example" }],
        internetExposed: false,
        declaredNetworkService: {
          protocol: "tcp",
          port: 3389,
          scanProfile: "internal_endpoint_rdp_tls",
        },
      }),
      pendingAsset({
        id: "endpoint-vnc",
        name: "workstation.internal.example",
        type: "service",
        platform: "external",
        locator: "workstation.internal.example",
        identifiers: [{ namespace: "dns_name", value: "workstation.internal.example" }],
        internetExposed: false,
        declaredNetworkService: {
          protocol: "tcp",
          port: 5900,
          scanProfile: "internal_endpoint_vnc",
        },
      }),
      pendingAsset({
        id: "endpoint-smtp",
        name: "mail.internal.example",
        type: "service",
        platform: "external",
        locator: "mail.internal.example",
        identifiers: [{ namespace: "dns_name", value: "mail.internal.example" }],
        internetExposed: false,
        declaredNetworkService: {
          protocol: "tcp",
          port: 587,
          scanProfile: "internal_endpoint_smtp",
        },
      }),
      pendingAsset({
        id: "endpoint-telnet",
        name: "switch.internal.example",
        type: "service",
        platform: "external",
        locator: "switch.internal.example",
        identifiers: [{ namespace: "dns_name", value: "switch.internal.example" }],
        internetExposed: false,
        declaredNetworkService: {
          protocol: "tcp",
          port: 23,
          scanProfile: "internal_endpoint_telnet",
        },
      }),
      pendingAsset({
        id: "device-switch",
        name: "https://10.20.0.9:8080",
        type: "service",
        platform: "external",
        locator: "https://10.20.0.9:8080",
        identifiers: [
          { namespace: "web_origin", value: "https://10.20.0.9:8080" },
          { namespace: "ip_address", value: "10.20.0.9" },
        ],
        internetExposed: false,
        declaredWebService: {
          protocol: "https",
          port: 8080,
          path: "/",
          scanProfile: "internal_device_https",
        },
      }),
      pendingAsset({
        id: "inventory-only",
        name: "10.20.0.19",
        type: "ip",
        platform: "external",
        locator: "10.20.0.19",
        identifiers: [{ namespace: "ip_address", value: "10.20.0.19" }],
        internetExposed: false,
      }),
    ],
  });

  expect(getByText(
    "Timing target: a useful result within minutes after tools are ready.",
  )).not.toBeNull();
  expect(getByText("Recorded for inventory, not scanned")).not.toBeNull();
  expect(getByText(
    "The report lists these as not tested. To check one of these hosts, start a new scan and add it under Internal systems.",
  )).not.toBeNull();
  expect(
    Array.from(container.querySelectorAll("button")).find((button) => button.textContent?.includes("Edit inputs")),
    "a case with scan-ready assets opens in the focused review, with Edit inputs in the header",
  ).toBeTruthy();
  expect(getByText("10.20.0.19")).not.toBeNull();
  expect(getByText("host.internal.example")).not.toBeNull();
  expect(getByText("Greenbone remote-safe profile · TCP 22, 25, 443, 445, 3389")).not.toBeNull();
  expect(getByText("host.internal.example").closest("label")?.textContent).not.toContain(
    "the remote-safe checks that match this exact host",
  );
  expect(getByText("server.internal.example:2222")).not.toBeNull();
  expect(getByText("desktop.internal.example:3389")).not.toBeNull();
  expect(getByText("workstation.internal.example:5900")).not.toBeNull();
  expect(getByText("mail.internal.example:587")).not.toBeNull();
  expect(getByText("switch.internal.example:23")).not.toBeNull();
  expect(getByText("SSH service · Greenbone · 7 security checks")).not.toBeNull();
  expect(getByText("RDP transport security · Greenbone · 11 security checks")).not.toBeNull();
  expect(getByText("VNC transport security · Greenbone · 1 security check")).not.toBeNull();
  expect(getByText("SMTP transport security · Greenbone · 11 security checks")).not.toBeNull();
  expect(getByText("Telnet cleartext exposure · Greenbone · 1 security check")).not.toBeNull();
  expect(getByText(/Reads the RFB security types offered by the exact VNC service/i)).not.toBeNull();
  expect(getByText(/It does not sign in, start a desktop session/i)).not.toBeNull();
  expect(getAllByText(/HTTPS management-service security · Greenbone · 11 TLS vulnerability checks/i)).toHaveLength(2);
  expect(getAllByText(/does not sign in, inspect the whole device/i)).toHaveLength(1);

  const start = getByRole("button", { name: "Start one combined scan" });
  await waitFor(() => expect((start as HTMLButtonElement).disabled).toBe(true));
  fireEvent.click(getByRole("checkbox", {
    name: /I confirm I am allowed to scan every selected website, API, and internal system/i,
  }));
  expect((start as HTMLButtonElement).disabled).toBe(false);
  fireEvent.click(start);

  await waitFor(() => expect(onStartEnvironmentScan).toHaveBeenCalledTimes(1));
  expect(onStartScan).not.toHaveBeenCalled();
  const [authorizations, routes] = onStartEnvironmentScan.mock.calls[0] as [
    Array<{ assetIds: string[]; modes: string[]; externalScope?: Record<string, unknown> }>,
    Array<{ engineId: string; assetIds: string[] }>,
  ];
  expect(authorizations).toHaveLength(12);
  expect(authorizations.filter(({ modes }) => modes.includes("local_artifact"))).toHaveLength(2);
  expect(authorizations.find(({ assetIds }) => assetIds[0] === "website-public")?.externalScope).toMatchObject({
    target: "portal.example.com",
    ports: [443],
    protocol: "https",
    activity: "active_external",
    allowSensitiveNetworks: false,
    templatePolicy: {
      revision: websiteQuickProfile.templateRevision,
      profileId: websiteQuickProfile.profileId,
      allowedTemplateIds: [...websiteQuickProfile.allowedTemplateIds],
    },
  });
  expect(authorizations.find(({ assetIds }) => assetIds[0] === "website-internal")?.externalScope).toMatchObject({
    target: "10.20.0.5",
    ports: [8443],
    allowSensitiveNetworks: true,
  });
  expect(authorizations.find(({ assetIds }) => assetIds[0] === "internal-host")?.externalScope).toMatchObject({
    target: "host.internal.example",
    ports: [22, 25, 443, 445, 3389],
    protocol: "tcp",
    activity: "active_external",
    allowSensitiveNetworks: true,
    ratePolicy: internalHostGreenboneProfile.ratePolicy,
    templatePolicy: {
      revision: internalHostGreenboneProfile.templateRevision,
      profileId: "greenbone_remote_safe_v1",
      allowedTemplateIds: [],
      allowCredentialAttacks: false,
      allowDenialOfService: false,
    },
  });
  expect(authorizations.find(({ assetIds }) => assetIds[0] === "endpoint-ssh")?.externalScope).toMatchObject({
    target: "server.internal.example",
    ports: [2222],
    protocol: "tcp",
    activity: "active_external",
    allowSensitiveNetworks: true,
    ratePolicy: internalEndpointProfiles.ssh.ratePolicy,
    templatePolicy: {
      revision: internalEndpointProfiles.ssh.templateRevision,
      allowedTemplateIds: [...internalEndpointProfiles.ssh.allowedTemplateIds],
      allowCredentialAttacks: false,
    },
  });
  expect(authorizations.find(({ assetIds }) => assetIds[0] === "endpoint-rdp")?.externalScope).toMatchObject({
    target: "desktop.internal.example",
    ports: [3389],
    protocol: "tcp",
    activity: "active_external",
    allowSensitiveNetworks: true,
    ratePolicy: internalEndpointProfiles.rdp_tls.ratePolicy,
    templatePolicy: {
      revision: internalEndpointProfiles.rdp_tls.templateRevision,
      allowedTemplateIds: [...internalEndpointProfiles.rdp_tls.allowedTemplateIds],
      allowCredentialAttacks: false,
      allowDenialOfService: false,
      allowFileUpload: false,
      allowFuzzing: false,
      allowHeadless: false,
      allowOutOfBand: false,
    },
  });
  expect(authorizations.find(({ assetIds }) => assetIds[0] === "endpoint-vnc")?.externalScope).toMatchObject({
    target: "workstation.internal.example",
    ports: [5900],
    protocol: "tcp",
    activity: "active_external",
    allowSensitiveNetworks: true,
    ratePolicy: internalEndpointProfiles.vnc.ratePolicy,
    templatePolicy: {
      revision: internalEndpointProfiles.vnc.templateRevision,
      allowedTemplateIds: [...internalEndpointProfiles.vnc.allowedTemplateIds],
      allowCredentialAttacks: false,
      allowDenialOfService: false,
      allowFileUpload: false,
      allowFuzzing: false,
      allowHeadless: false,
      allowOutOfBand: false,
    },
  });
  expect(authorizations.find(({ assetIds }) => assetIds[0] === "endpoint-smtp")?.externalScope).toMatchObject({
    target: "mail.internal.example",
    ports: [587],
    protocol: "tcp",
    activity: "active_external",
    allowSensitiveNetworks: true,
    ratePolicy: internalEndpointProfiles.smtp.ratePolicy,
    templatePolicy: {
      revision: internalEndpointProfiles.smtp.templateRevision,
      allowedTemplateIds: [...internalEndpointProfiles.smtp.allowedTemplateIds],
      allowCredentialAttacks: false,
      allowDenialOfService: false,
      allowFileUpload: false,
      allowFuzzing: false,
      allowHeadless: false,
      allowOutOfBand: false,
    },
  });
  expect(authorizations.find(({ assetIds }) => assetIds[0] === "endpoint-telnet")?.externalScope).toMatchObject({
    target: "switch.internal.example",
    ports: [23],
    protocol: "tcp",
    activity: "active_external",
    allowSensitiveNetworks: true,
    ratePolicy: internalEndpointProfiles.telnet.ratePolicy,
    templatePolicy: {
      revision: internalEndpointProfiles.telnet.templateRevision,
      allowedTemplateIds: [...internalEndpointProfiles.telnet.allowedTemplateIds],
      allowCredentialAttacks: false,
      allowDenialOfService: false,
      allowFileUpload: false,
      allowFuzzing: false,
      allowHeadless: false,
      allowOutOfBand: false,
    },
  });
  expect(authorizations.find(({ assetIds }) => assetIds[0] === "device-gateway")?.externalScope).toMatchObject({
    target: "10.20.0.8",
    ports: [443],
    protocol: "https",
    activity: "active_external",
    allowSensitiveNetworks: true,
    templatePolicy: {
      revision: internalDeviceHttpsProfile.templateRevision,
      allowedTemplateIds: [...internalDeviceHttpsProfile.allowedTemplateIds],
    },
  });
  expect(authorizations.find(({ assetIds }) => assetIds[0] === "device-switch")?.externalScope).toMatchObject({
    target: "10.20.0.9",
    ports: [8080],
    templatePolicy: {
      revision: internalDeviceHttpsProfile.templateRevision,
      allowedTemplateIds: [...internalDeviceHttpsProfile.allowedTemplateIds],
    },
  });
  expect(routes.find(({ engineId }) => engineId === "semgrep")).toEqual({
    engineId: "semgrep",
    assetIds: ["repo-a", "repo-b"],
  });
  expect(routes.find(({ engineId }) => engineId === "grype")).toEqual({
    engineId: "grype",
    assetIds: ["repo-a", "repo-b"],
  });
  expect(routes.find(({ engineId }) => engineId === "nuclei")).toEqual({
    engineId: "nuclei",
    assetIds: ["website-public", "website-internal"],
  });
  expect(routes.find(({ engineId }) => engineId === "greenbone")).toEqual({
    engineId: "greenbone",
    assetIds: [
      "internal-host",
      "endpoint-ssh",
      "endpoint-rdp",
      "endpoint-vnc",
      "endpoint-smtp",
      "endpoint-telnet",
      "device-gateway",
      "device-switch",
    ],
  });
  expect(routes.flatMap(({ assetIds }) => assetIds)).not.toContain("inventory-only");
  expect(routes.some(({ engineId }) => engineId === "naabu" || engineId === "httpx")).toBe(false);
}, 15_000);

const oneRepositoryAndOneWebsiteEnvironmentAssets = () => [
  pendingAsset({
    id: "repo-a",
    name: "billing-api",
    locator: "private-copy://repo-a",
    localInputProfile: "repository_working_tree",
  }),
  pendingAsset({
    id: "website-public",
    name: "https://portal.example.com:443",
    type: "service",
    platform: "external",
    locator: "https://portal.example.com:443",
    identifiers: [
      { namespace: "web_origin", value: "https://portal.example.com:443" },
      { namespace: "dns_name", value: "portal.example.com" },
    ],
    internetExposed: true,
    declaredWebService: { protocol: "https", port: 443, path: "/login" },
  }),
];

const oneUnknownSourceCoverage = (): CoverageRecord[] => [{
  id: "coverage-unknown",
  label: "AWS inventory",
  platform: "aws",
  sourceKind: "aws_organization",
  state: "source_unavailable_unknown",
  assetCount: 0,
  detail: "not connected",
}];

// Section 1 stays mounted while hidden, so only a button outside a hidden
// section is one the reader can see.
const visibleButtonsNamed = (container: HTMLElement, name: string) =>
  Array.from(container.querySelectorAll("button"))
    .filter((button) => button.textContent?.trim() === name && button.closest("[hidden]") === null);

const visibleText = (container: HTMLElement) => {
  const copy = container.cloneNode(true) as HTMLElement;
  copy.querySelectorAll("[hidden]").forEach((element) => element.remove());
  return copy.textContent ?? "";
};

test("the IT-environment review leads with its plan and one Start", () => {
  const { container, queryByText, getByText, getByRole } = renderRoute({
    assessmentIntent: "internal_it_environment",
    requestedActivities: ["local_artifact_analysis", "active_external_vulnerability_tests"],
    coverage: oneUnknownSourceCoverage(),
    assets: oneRepositoryAndOneWebsiteEnvironmentAssets(),
  });

  const pageHeader = container.querySelector(".page-header");
  expect(pageHeader?.querySelector("h1")?.textContent).toBe("Review and start");
  expect(pageHeader?.querySelector("p")?.textContent).toBe("Confirm the target and limits.");
  expect(container.querySelector<HTMLElement>("#coverage-step-1")?.hidden).toBe(true);
  expect(container.querySelector("#coverage-step-2")).toBeNull();
  expect(container.textContent).not.toContain("Sources without data");
  expect(visibleButtonsNamed(container, "Refresh items")).toHaveLength(0);
  expect(queryByText("3. Review and start")).toBeNull();
  expect(getByText("One scan for this IT environment")).not.toBeNull();
  expect(getByRole("button", { name: "Start one combined scan" })).not.toBeNull();
  // Every item here is scan-ready, so the review has no inventory or
  // not-tested caveat to state.
  expect(visibleText(container)).not.toMatch(/inventory|not tested/iu);

  const editInputs = Array.from(pageHeader?.querySelectorAll<HTMLButtonElement>("button") ?? [])
    .find((button) => button.textContent?.includes("Edit inputs"));
  expect(editInputs).toBeTruthy();
  fireEvent.click(editInputs!);
  expect(container.querySelector<HTMLElement>("#coverage-step-1")?.hidden).toBe(false);
  expect(container.querySelector("#coverage-step-2")).not.toBeNull();
  expect(queryByText("Sources without data: 1")).not.toBeNull();

  const backToReview = Array.from(pageHeader?.querySelectorAll<HTMLButtonElement>("button") ?? [])
    .find((button) => button.textContent?.includes("Back to review"));
  expect(backToReview).toBeTruthy();
  fireEvent.click(backToReview!);
  expect(container.querySelector<HTMLElement>("#coverage-step-1")?.hidden).toBe(true);
  expect(container.querySelector("#coverage-step-2")).toBeNull();
});

test("the IT-environment review leads with its plan and one Start in Traditional Chinese", () => {
  window.localStorage.setItem(localeStorageKey, "zh-TW");
  const { container } = renderRoute({
    assessmentIntent: "internal_it_environment",
    requestedActivities: ["local_artifact_analysis", "active_external_vulnerability_tests"],
    coverage: oneUnknownSourceCoverage(),
    assets: oneRepositoryAndOneWebsiteEnvironmentAssets(),
  });

  const pageHeader = container.querySelector(".page-header");
  expect(pageHeader?.querySelector("h1")?.textContent).toBe("確認後開始");
  expect(container.textContent).not.toContain("沒有資料的來源");
  expect(visibleText(container)).not.toMatch(/盤點|未測試/u);
  expect(visibleButtonsNamed(container, "重新整理項目")).toHaveLength(0);
  const editInputs = Array.from(pageHeader?.querySelectorAll<HTMLButtonElement>("button") ?? [])
    .find((button) => button.textContent?.includes("編輯輸入"));
  expect(editInputs).toBeTruthy();
});

test("the IT-environment review still names an inventory-only item as not scanned", () => {
  const { container } = renderRoute({
    assessmentIntent: "internal_it_environment",
    requestedActivities: ["local_artifact_analysis", "active_external_vulnerability_tests"],
    assets: [
      ...oneRepositoryAndOneWebsiteEnvironmentAssets(),
      pendingAsset({
        id: "inventory-only",
        name: "10.20.0.19",
        type: "ip",
        platform: "external",
        locator: "10.20.0.19",
        identifiers: [{ namespace: "ip_address", value: "10.20.0.19" }],
        internetExposed: false,
      }),
    ],
  });

  expect(container.querySelector(".page-header h1")?.textContent).toBe("Review and start");
  const text = visibleText(container);
  expect(text).toContain("Recorded for inventory, not scanned");
  expect(text).toContain("10.20.0.19");
  expect(text).not.toContain("bare host");
  expect(text).not.toContain("legacy");
});

test("the IT-environment review still names an inventory-only item as not scanned in Traditional Chinese", () => {
  window.localStorage.setItem(localeStorageKey, "zh-TW");
  const { container } = renderRoute({
    assessmentIntent: "internal_it_environment",
    requestedActivities: ["local_artifact_analysis", "active_external_vulnerability_tests"],
    assets: [
      ...oneRepositoryAndOneWebsiteEnvironmentAssets(),
      pendingAsset({
        id: "inventory-only",
        name: "10.20.0.19",
        type: "ip",
        platform: "external",
        locator: "10.20.0.19",
        identifiers: [{ namespace: "ip_address", value: "10.20.0.19" }],
        internetExposed: false,
      }),
    ],
  });

  expect(container.querySelector(".page-header h1")?.textContent).toBe("確認後開始");
  expect(container.querySelector(".scope-mode-fieldset legend")?.textContent).toBe("專案資料夾");
  const text = visibleText(container);
  expect(text).toContain("僅記錄於盤點，不會掃描");
  expect(text).toContain("若要檢查其中的主機，請開始新的掃描，並在「內部系統」加入該主機。");
  expect(text).not.toContain("裸主機");
  expect(text).not.toContain("舊版");
  expect(text).not.toContain("精確");
  expect(text).not.toContain("開發案");
});

test("an IT-environment case with nothing scan-ready keeps the full setup page", () => {
  const { container, getByText } = renderRoute({
    assessmentIntent: "internal_it_environment",
    requestedActivities: ["active_external_vulnerability_tests"],
    assets: [
      pendingAsset({
        id: "inventory-only",
        name: "10.20.0.19",
        type: "ip",
        platform: "external",
        locator: "10.20.0.19",
        identifiers: [{ namespace: "ip_address", value: "10.20.0.19" }],
        internetExposed: false,
      }),
    ],
  });

  const pageHeader = container.querySelector(".page-header");
  expect(pageHeader?.querySelector("h1")?.textContent).toBe("Scan setup");
  expect(container.querySelector<HTMLElement>("#coverage-step-1")?.hidden).toBe(false);
  expect(getByText("Add one scan-ready item")).not.toBeNull();
});

test("changing the selected environment network targets requires authorization again", async () => {
  const onStartEnvironmentScan = vi.fn().mockResolvedValue(true);
  const { getByRole } = renderRoute({
    assessmentIntent: "internal_it_environment",
    requestedActivities: ["local_artifact_analysis", "active_external_vulnerability_tests"],
    nativeMode: false,
    onStartEnvironmentScan,
    assets: [
      pendingAsset({
        id: "repo-a",
        name: "billing-api",
        locator: "private-copy://repo-a",
        localInputProfile: "repository_working_tree",
      }),
      pendingAsset({
        id: "website-a",
        name: "https://portal.example.com:443",
        type: "service",
        platform: "external",
        locator: "https://portal.example.com:443",
        identifiers: [
          { namespace: "web_origin", value: "https://portal.example.com:443" },
          { namespace: "dns_name", value: "portal.example.com" },
        ],
        internetExposed: true,
        declaredWebService: { protocol: "https", port: 443, path: "/" },
      }),
      pendingAsset({
        id: "website-b",
        name: "https://api.example.com:443",
        type: "service",
        platform: "external",
        locator: "https://api.example.com:443",
        identifiers: [
          { namespace: "web_origin", value: "https://api.example.com:443" },
          { namespace: "dns_name", value: "api.example.com" },
        ],
        internetExposed: true,
        declaredWebService: { protocol: "https", port: 443, path: "/" },
      }),
    ],
  });

  const start = getByRole("button", { name: "Start one combined scan" }) as HTMLButtonElement;
  const confirmation = getByRole("checkbox", {
    name: /I confirm I am allowed to scan every selected website, API, and internal system/i,
  }) as HTMLInputElement;

  await waitFor(() => expect(start.disabled).toBe(true));
  fireEvent.click(confirmation);
  expect(confirmation.checked).toBe(true);
  expect(start.disabled).toBe(false);

  fireEvent.click(getByRole("checkbox", { name: "Choose billing-api" }));
  expect(confirmation.checked).toBe(true);
  expect(start.disabled).toBe(false);

  fireEvent.click(getByRole("checkbox", { name: "Choose https://portal.example.com:443" }));
  expect(confirmation.checked).toBe(false);
  expect(start.disabled).toBe(true);

  fireEvent.click(confirmation);
  expect(start.disabled).toBe(false);
  fireEvent.click(getByRole("checkbox", { name: "Choose https://portal.example.com:443" }));
  expect(confirmation.checked).toBe(false);
  expect(start.disabled).toBe(true);
  expect(onStartEnvironmentScan).not.toHaveBeenCalled();
});

test("a scan waiting for its tools keeps the reviewed website request immutable", async () => {
  const { container } = renderRoute({
    assessmentIntent: "deployed_website",
    requestedActivities: ["active_external_vulnerability_tests"],
    busy: true,
    runtimeSetupNotice: <div data-testid="runtime-progress">Downloading scan tools: 42%</div>,
    assets: [pendingAsset({
      id: "asset-example",
      name: "example.com",
      type: "domain",
      platform: "external",
      locator: "example.com",
      identifiers: [{ namespace: "dns_name", value: "example.com" }],
      internetExposed: true,
      declaredWebService: { protocol: "https", port: 443, path: "/" },
    })],
  });

  await waitFor(() => expect(container.querySelector(".scope-confirmation-panel")).not.toBeNull());
  const reviewControls = Array.from(container.querySelectorAll<
    HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement | HTMLButtonElement
  >(".scope-confirmation-panel input, .scope-confirmation-panel select, .scope-confirmation-panel textarea, .scope-confirmation-panel button"));
  expect(reviewControls.length).toBeGreaterThan(0);
  expect(reviewControls.every((control) => control.disabled)).toBe(true);
  expect(container.querySelector('[data-testid="runtime-progress"]')?.textContent).toContain("42%");
  expect(container.querySelector(".scope-confirmation-panel .button--primary")?.textContent).toContain("Preparing scan tools");

  const editInputs = Array.from(container.querySelectorAll<HTMLButtonElement>(".page-header button"))
    .find((button) => button.textContent?.includes("Edit inputs"));
  expect(editInputs?.disabled).toBe(true);
});

test("external setup omits the public-record mode when no shipped scanner can run it", async () => {
  const { container } = renderRoute({
    assessmentIntent: "external_ip_or_domain",
    requestedActivities: [],
    nativeMode: false,
    assets: [pendingAsset({
      id: "asset-public-records",
      name: "example.com",
      type: "domain",
      platform: "external",
      locator: "example.com",
      identifiers: [{ namespace: "dns_name", value: "example.com" }],
      internetExposed: true,
      declaredWebService: { protocol: "https", port: 443, path: "/" },
    })],
  });

  await waitFor(() => expect(container.querySelector(".scope-mode-fieldset")).not.toBeNull());
  expect(container.querySelector(".page-header h1")?.textContent).toBe("Scan setup");
  expect(container.querySelector(".asset-review-list")?.textContent).toContain("example.com");
  expect(container.querySelector(".asset-review-list input")?.getAttribute("aria-label")).toBe("Choose example.com");
  expect(container.textContent).not.toContain("Use public records");
  expect(container.textContent).not.toContain("No check in this version reads public records");
}, 15_000);

test("an internal website uses the fixed Nuclei profile only after explicit private-network confirmation", async () => {
  const onStartScan = vi.fn().mockResolvedValue(true);
  const { container, getByRole, queryByText } = renderRoute({
    assessmentIntent: "deployed_website",
    requestedActivities: ["active_external_vulnerability_tests"],
    onStartScan,
    assets: [pendingAsset({
      id: "asset-internal-website",
      name: "app.internal.test",
      type: "domain",
      platform: "external",
      locator: "app.internal.test",
      identifiers: [{ namespace: "dns_name", value: "app.internal.test" }],
      internetExposed: false,
      declaredWebService: { protocol: "https", port: 8443, path: "/health" },
    })],
  });

  await waitFor(() => expect(container.querySelector(".coverage-guided-boundary")?.textContent).toContain(
    "Scope: https://app.internal.test:8443, not only /health.",
  ));

  expect(container.querySelector(".scope-mode-fieldset")).toBeNull();
  expect(queryByText("Approval reference (required)")).toBeNull();
  expect(queryByText("Exact active-test IDs (required)")).toBeNull();

  const start = getByRole("button", { name: "Confirm and start scan" }) as HTMLButtonElement;
  const privateNetworkConfirmation = getByRole("checkbox", {
    name: /I confirm this scan may connect to the selected internal network/i,
  }) as HTMLInputElement;
  expect(privateNetworkConfirmation.checked).toBe(false);
  expect(start.disabled).toBe(true);
  expect(onStartScan).not.toHaveBeenCalled();

  fireEvent.click(privateNetworkConfirmation);
  expect(privateNetworkConfirmation.checked).toBe(true);
  expect(start.disabled).toBe(false);
  fireEvent.click(start);

  await waitFor(() => expect(onStartScan).toHaveBeenCalledTimes(1));
  expect(onStartScan).toHaveBeenCalledWith(
    ["asset-internal-website"],
    ["active_external"],
    "The user explicitly confirmed authorization to scan the exact https://app.internal.test:8443 origin with the displayed fixed quick profile.",
    {
      target: "app.internal.test",
      protocol: "https",
      ports: [8443],
      activity: "active_external",
      ratePolicy: {
        requestsPerSecond: 10,
        concurrency: 5,
        timeoutSeconds: 10,
      },
      templatePolicy: {
        revision: websiteQuickProfile.templateRevision,
        profileId: websiteQuickProfile.profileId,
        allowedTemplateIds: [],
        allowHeadless: false,
        allowOutOfBand: false,
        allowFuzzing: false,
        allowFileUpload: false,
        allowDenialOfService: false,
        allowCredentialAttacks: false,
      },
      assertedAuthority: "The user explicitly confirmed authorization to scan the exact https://app.internal.test:8443 origin with the displayed fixed quick profile.",
      allowSensitiveNetworks: true,
    },
    ["nuclei"],
  );
});


const zapManifest: EngineManifest = {
  id: "zap", name: "ZAP", category: "external_attack_surface", version: "2.17.0",
  imageDigest: "sha256:781a2bdaea47324e7bab583e2263f21d257b0aee61ed51521a5be45f5f5081ef",
  license: "Apache-2.0", redistribution: "on_demand", platforms: ["external"], supportedProviders: [],
  status: "ready", runnable: true, blockedBy: [], compatibilityValid: true,
  providerExecutionProfiles: [],
};

for (const locale of ["en", "zh-TW"] as const) {
  test(`the explicit passive website choice freezes ZAP's profile and limits in ${locale}`, async () => {
    window.localStorage.setItem(localeStorageKey, locale);
    const onStartScan = vi.fn().mockResolvedValue(false);
    const { container, getByLabelText } = renderRoute({
      assessmentIntent: "deployed_website", requestedActivities: ["active_external_vulnerability_tests"],
      nativeMode: false, engineManifests: [zapManifest], onStartScan,
      assets: [oneRepositoryAndOneWebsiteEnvironmentAssets()[1]!],
    });
    const details = container.querySelector<HTMLDetailsElement>(".coverage-scan-advanced")!;
    expect(details.open).toBe(false);
    fireEvent.click(details.querySelector("summary")!);
    fireEvent.change(getByLabelText(locale === "en" ? "Website checks" : "網站檢查方式"), { target: { value: "passive" } });
    await waitFor(() => expect(container.querySelector(".coverage-guided-boundary")?.textContent).toContain("ZAP"));
    const start = container.querySelector<HTMLButtonElement>(".scope-confirmation-panel button[type=submit]")!;
    fireEvent.click(start);
    await waitFor(() => expect(onStartScan).toHaveBeenCalledTimes(1));
    expect(onStartScan.mock.calls[0]![4]).toEqual(["zap"]);
    const scope = onStartScan.mock.calls[0]![3];
    expect(scope).toMatchObject({
      target: "portal.example.com", ports: [443], protocol: "https", activity: "active_external",
      ratePolicy: websitePassiveProfile.ratePolicy,
      templatePolicy: { revision: websitePassiveProfile.templateRevision, profileId: websitePassiveProfile.profileId,
        allowedTemplateIds: [], allowHeadless: false, allowOutOfBand: false, allowFuzzing: false,
        allowFileUpload: false, allowDenialOfService: false, allowCredentialAttacks: false },
    });
  });
}

test("changing a mixed run's website profile requires review and keeps local engines on their own assets", async () => {
  const onStartEnvironmentScan = vi.fn().mockResolvedValue(false);
  const { container, getByLabelText } = renderRoute({
    assessmentIntent: "internal_it_environment", requestedActivities: ["local_artifact_analysis", "active_external_vulnerability_tests"],
    nativeMode: false, engineManifests: [zapManifest], onStartEnvironmentScan,
    assets: oneRepositoryAndOneWebsiteEnvironmentAssets(),
  });
  const confirmation = Array.from(container.querySelectorAll<HTMLInputElement>('input[type=checkbox]'))
    .find(input => input.closest('label')?.textContent?.includes('I confirm I am allowed'))!;
  expect(confirmation).toBeTruthy();
  fireEvent.click(confirmation);
  fireEvent.change(getByLabelText("Website checks"), { target: { value: "passive" } });
  expect(confirmation.checked).toBe(false);
  fireEvent.click(confirmation);
  fireEvent.click(container.querySelector<HTMLButtonElement>('form button[type=submit]')!);
  await waitFor(() => expect(onStartEnvironmentScan).toHaveBeenCalledTimes(1));
  const [authorizations, routes] = onStartEnvironmentScan.mock.calls[0]!;
  expect(authorizations.find((authorization: { assetIds: string[] }) => authorization.assetIds.includes("website-public"))).toMatchObject({
    externalScope: { ratePolicy: websitePassiveProfile.ratePolicy,
      templatePolicy: { profileId: websitePassiveProfile.profileId, revision: websitePassiveProfile.templateRevision } },
  });
  expect(routes.find((route: { engineId: string }) => route.engineId === "zap")).toEqual({ engineId: "zap", assetIds: ["website-public"] });
  expect(routes.filter((route: { engineId: string }) => route.engineId !== "zap").every((route: { assetIds: string[] }) => route.assetIds.length === 1 && route.assetIds[0] === "repo-a")).toBe(true);
});


const agenticManifest: EngineManifest = {
  id: "agentic-radar", name: "Agentic Radar", category: "ai_agent_framework", version: "0.14.1",
  imageDigest: "sha256:synthetic-admission", license: "Apache-2.0", redistribution: "on_demand",
  platforms: ["code"], supportedProviders: [], status: "ready", runnable: true,
  blockedBy: [], compatibilityValid: true, providerExecutionProfiles: [],
};

for (const locale of ["en", "zh-TW"] as const) {
  test(`optional workflow inventory waits for persisted framework selection in ${locale}`, async () => {
    window.localStorage.setItem(localeStorageKey, locale);
    const onStartScan = vi.fn().mockResolvedValue(false);
    const onSelectAgenticFramework = vi.fn().mockResolvedValue(true);
    const repository = pendingAsset({ name: "agent-copy", localInputProfile: "repository_working_tree" });
    const options: RouteOptions = {
      assessmentIntent: "ai_application", requestedActivities: ["local_artifact_analysis"],
      assets: [repository], engineManifests: [agenticManifest], nativeMode: false,
      onStartScan, onSelectAgenticFramework,
    };
    const { container, getByLabelText, rerender } = renderRoute(options);
    await waitFor(() => expect(container.querySelector(".coverage-guided-boundary")).not.toBeNull());
    const label = locale === "en" ? "Workflow framework" : "工作流程框架";
    const selector = getByLabelText(label) as HTMLSelectElement;
    expect(selector.value).toBe("");
    expect(container.querySelector<HTMLDetailsElement>("[data-agentic-inventory]")!.open).toBe(false);
    const start = container.querySelector<HTMLButtonElement>(".scope-confirmation-panel button[type=submit]")!;
    fireEvent.click(start);
    await waitFor(() => expect(onStartScan).toHaveBeenCalledTimes(1));
    expect(onStartScan.mock.calls[0]![4]).not.toContain("agentic-radar");
    onStartScan.mockClear();
    fireEvent.change(selector, { target: { value: "openai-agents" } });
    expect(onSelectAgenticFramework).toHaveBeenCalledWith(repository.id, "openai-agents");
    // The selected value is controlled by the backend-saved asset, not optimistic local state.
    expect(selector.value).toBe("");
    rerender(routeElement({ ...options, assets: [{ ...repository, agenticRadarFramework: "openai-agents" }] }));
    await waitFor(() => expect((getByLabelText(label) as HTMLSelectElement).value).toBe("openai-agents"));
    fireEvent.click(container.querySelector<HTMLButtonElement>(".scope-confirmation-panel button[type=submit]")!);
    await waitFor(() => expect(onStartScan).toHaveBeenCalledTimes(1));
    expect(onStartScan.mock.calls[0]![4]).toContain("agentic-radar");
    expect(onStartScan.mock.calls[0]![0]).toEqual([repository.id]);
    expect(onStartScan.mock.calls[0]![1]).toEqual(["local_artifact"]);
    fireEvent.change(getByLabelText(label), { target: { value: "" } });
    expect(onSelectAgenticFramework).toHaveBeenLastCalledWith(repository.id, null);
  });
}

test("workflow inventory is hidden without an admitted image and outside repository inputs", () => {
  const options: RouteOptions = { assessmentIntent: "ai_application", requestedActivities: ["local_artifact_analysis"],
    assets: [pendingAsset({ localInputProfile: "repository_working_tree", agenticRadarFramework: "langgraph" })],
    engineManifests: [{ ...agenticManifest, runnable: false }], nativeMode: false,
  };
  const { container, rerender } = renderRoute(options);
  expect(container.querySelector("[data-agentic-inventory]")).toBeNull();
  rerender(routeElement({ ...options, assessmentIntent: "container_image", engineManifests: [agenticManifest],
    assets: [pendingAsset({ type: "image", platform: "container", localInputProfile: "container_image_oci_layout" })] }));
  expect(container.querySelector("[data-agentic-inventory]")).toBeNull();
});

test("mixed workflow inventory dispatch stays on its selected repository and requires fresh review", async () => {
  const onStartEnvironmentScan = vi.fn().mockResolvedValue(false);
  const onSelectAgenticFramework = vi.fn().mockResolvedValue(true);
  const assets = oneRepositoryAndOneWebsiteEnvironmentAssets();
  const options: RouteOptions = { assessmentIntent: "internal_it_environment",
    requestedActivities: ["local_artifact_analysis", "active_external_vulnerability_tests"],
    nativeMode: false, engineManifests: [agenticManifest], assets,
    onStartEnvironmentScan, onSelectAgenticFramework,
  };
  const { container, getByLabelText, rerender } = renderRoute(options);
  const confirmation = Array.from(container.querySelectorAll<HTMLInputElement>('input[type=checkbox]'))
    .find(input => input.closest('label')?.textContent?.includes('I confirm I am allowed'))!;
  fireEvent.click(confirmation);
  fireEvent.change(getByLabelText("Workflow framework"), { target: { value: "langgraph" } });
  expect(confirmation.checked).toBe(false);
  expect(onSelectAgenticFramework).toHaveBeenCalledWith("repo-a", "langgraph");
  rerender(routeElement({ ...options, assets: assets.map(asset => asset.id === "repo-a"
    ? { ...asset, agenticRadarFramework: "langgraph" } : asset) }));
  fireEvent.click(confirmation);
  fireEvent.click(container.querySelector<HTMLButtonElement>('form button[type=submit]')!);
  await waitFor(() => expect(onStartEnvironmentScan).toHaveBeenCalledTimes(1));
  const [authorizations, routes] = onStartEnvironmentScan.mock.calls[0]!;
  expect(routes.find((route: { engineId: string }) => route.engineId === "agentic-radar"))
    .toEqual({ engineId: "agentic-radar", assetIds: ["repo-a"] });
  expect(authorizations.find((a: { assetIds: string[] }) => a.assetIds.includes("repo-a")).modes).toEqual(["local_artifact"]);
});

test("incident triage narrows the local scan while freezing the campaign selection", async () => {
  const onStartScan = vi.fn().mockResolvedValue(true);
  const { getByRole, getByLabelText, container } = renderRoute({
    assessmentIntent: "source_code", requestedActivities: ["local_artifact_analysis"], onStartScan,
    assets: [pendingAsset({ name: "incident-copy", localInputProfile: "repository_working_tree" })],
  });
  fireEvent.click(getByLabelText(/October 21–22 incident triage/u));
  await waitFor(() => expect(container.querySelector(".coverage-guided-boundary")?.textContent)
    .toContain("Read-only checks: Known package vulnerabilities."));
  fireEvent.click(getByRole("button", { name: "Confirm and start scan" }));
  expect(onStartScan).toHaveBeenCalledWith(["asset-1"], ["local_artifact"],
    "The user explicitly selected this saved local copy and confirmed the recommended read-only checks.",
    undefined, ["trivy"], "october-2026");
});

test("package incident triage excludes every external route and unsupported local input before authorization", async () => {
  const onStartEnvironmentScan = vi.fn().mockResolvedValue(false);
  const external = (id: string, details: Partial<Asset>) => pendingAsset({
    id, name: id, platform: "external", type: "service", locator: `${id}.example.invalid`,
    identifiers: [{ namespace: "dns_name", value: `${id}.example.invalid` }],
    internetExposed: false, ...details,
  });
  const { getByLabelText, getByText, getByRole, queryByText } = renderRoute({
    assessmentIntent: "internal_it_environment", nativeMode: false,
    requestedActivities: ["local_artifact_analysis", "active_external_vulnerability_tests"],
    onStartEnvironmentScan,
    assets: [
      pendingAsset({ id: "repo", name: "package-copy", localInputProfile: "repository_working_tree" }),
      pendingAsset({ id: "node", name: "node-config", localInputProfile: "kubernetes_node_snapshot" }),
      external("website", { declaredWebService: { protocol: "https", port: 443, path: "/" } }),
      external("host", { type: "domain", declaredHostScan: { protocol: "tcp", ports: [22,443], scanProfile: "internal_host_greenbone_remote_safe" } }),
      external("endpoint", { declaredNetworkService: { protocol: "tcp", port: 22, scanProfile: "internal_endpoint_ssh" } }),
      external("device", { declaredWebService: { protocol: "https", port: 443, path: "/", scanProfile: "internal_device_https" } }),
    ],
  });
  fireEvent.click(getByLabelText(/October 21–22 incident triage/u));
  expect(getByText("5 assets excluded from package incident checks")).toBeTruthy();
  expect(queryByText(/I confirm I am allowed/u)).toBeNull();
  const submit = getByRole("button", { name: "Start one combined scan" });
  fireEvent.click(submit);
  await waitFor(() => expect(onStartEnvironmentScan).toHaveBeenCalledTimes(1));
  const [authorizations, routes, campaign] = onStartEnvironmentScan.mock.calls[0]!;
  expect(authorizations).toEqual([{
    assetIds: ["repo"], modes: ["local_artifact"],
    confirmation: "The user explicitly selected this saved local copy and confirmed the recommended read-only checks.",
  }]);
  expect(routes).toEqual([{ engineId: "trivy", assetIds: ["repo"] }]);
  expect(campaign).toBe("october-2026");
  fireEvent.click(getByLabelText("Choose package-copy"));
  expect((submit as HTMLButtonElement).disabled).toBe(true);
  fireEvent.click(submit);
  expect(onStartEnvironmentScan).toHaveBeenCalledTimes(1);
});

test.each(["deployed_website", "internal_it_environment"] as const)("%s without package inputs does not offer unsupported incident triage", (assessmentIntent) => {
  const { queryByLabelText } = renderRoute({ assessmentIntent,
    requestedActivities: ["active_external_vulnerability_tests"],
    assets: [pendingAsset({ id: "site", platform: "external", type: "service", name: "website",
      locator: "https://example.invalid", identifiers: [{ namespace: "dns_name", value: "example.invalid" }],
      declaredWebService: { protocol: "https", port: 443, path: "/" }, internetExposed: true })],
  });
  expect(queryByLabelText(/October 21–22 incident triage/u)).toBeNull();
});
