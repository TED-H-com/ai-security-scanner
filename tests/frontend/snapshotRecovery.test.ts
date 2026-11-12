import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { build } from "esbuild";

const originalWindow = Object.getOwnPropertyDescriptor(globalThis, "window");

const setTestWindow = (value: object): void => {
  Object.defineProperty(globalThis, "window", {
    configurable: true,
    writable: true,
    value,
  });
};

test.after(() => {
  if (originalWindow) Object.defineProperty(globalThis, "window", originalWindow);
  else Reflect.deleteProperty(globalThis, "window");
});

const bundled = await build({
  stdin: {
    contents: 'export { COMMANDS, scannerService } from "./src/services/scanner.ts";',
    loader: "ts",
    resolveDir: process.cwd(),
    sourcefile: "snapshot-recovery-test-entry.ts",
  },
  bundle: true,
  format: "esm",
  platform: "node",
  target: "node22",
  write: false,
});
const bundledSource = bundled.outputFiles[0]?.text;
assert.ok(bundledSource, "scanner service test bundle should contain JavaScript");
const { COMMANDS, scannerService } = await import(
  `data:text/javascript;base64,${Buffer.from(bundledSource).toString("base64")}`
);

const packagedBundle = await build({
  stdin: {
    contents: 'export { COMMANDS, scannerService } from "./src/services/scanner.ts";',
    loader: "ts",
    resolveDir: process.cwd(),
    sourcefile: "packaged-snapshot-recovery-test-entry.ts",
  },
  bundle: true,
  define: {
    "import.meta.env.TAURI_ENV_PLATFORM": JSON.stringify("windows"),
  },
  format: "esm",
  platform: "node",
  target: "node22",
  write: false,
});
const packagedBundleSource = packagedBundle.outputFiles[0]?.text;
assert.ok(packagedBundleSource, "packaged scanner service test bundle should contain JavaScript");
const { scannerService: packagedScannerService } = await import(
  `data:text/javascript;base64,${Buffer.from(packagedBundleSource).toString("base64")}`
);

const queuedLocalhostNativeCase = () => ({
  id: "localhost-case",
  title: "This computer · 127.0.0.1:9001",
  assessment_intent: "internal_it_environment",
  profile: {
    organization_name: "This computer",
    employee_range: "Not provided",
    data_classes: ["general"],
    notes: null,
  },
  status: "scanning",
  created_at: "2026-08-30T12:00:00.000000001Z",
  updated_at: "2026-08-30T12:00:00.000000002Z",
  is_demo: false,
  requested_activities: ["low_impact_external_checks"],
  data_sources: [],
  assets: [{
    id: "localhost-asset",
    kind: "web_service",
    name: "127.0.0.1:9001",
    provider: null,
    region: null,
    identifiers: [{ namespace: "localhost_tcp_endpoint", value: "127.0.0.1:9001" }],
    discovered_from: [],
    candidate: false,
    owner_confirmed: true,
    internet_exposed: false,
    contains_sensitive_data: false,
    metadata: {},
  }],
  scope_grants: [],
  coverage: [],
  scan_runs: [{
    id: "localhost-run",
    case_id: "localhost-case",
    sequence: 1,
    created_at: "2026-08-30T12:00:00.000000001Z",
    completed_at: null,
    knowledge_cutoff: "2026-08-30T00:00:00Z",
    engine_runs: [{
      id: "localhost-task",
      engine_id: "built-in-localhost-tcp",
      task_kind: {
        kind: "built_in_localhost_tcp",
        port: 9001,
        timeout_ms: 3000,
        payload_bytes: 0,
      },
      localhost_tcp_observation: null,
      asset_ids: ["localhost-asset"],
      status: "queued",
      progress_percent: 0,
      phase: "queued",
      started_at: null,
      finished_at: null,
      resume_token: null,
      engine_version: null,
      image_digest: null,
      rule_version: null,
      adapter_version: "built-in",
      raw_artifact_ids: [],
      error_code: null,
      error_message: null,
      warnings: [],
    }],
  }],
  findings: [],
  exports: [],
  comparisons: [],
});

test("native snapshot failures reject instead of returning synthetic demo projects", async () => {
  setTestWindow({
    __TAURI_INTERNALS__: {
      invoke: async (command: string) => {
        assert.equal(command, COMMANDS.getSnapshot);
        throw new Error("test-only native database failure");
      },
    },
  });

  await assert.rejects(
    () => scannerService.getSnapshot(),
    /test-only native database failure/u,
  );
});

test("the browser development preview remains explicitly demo", async () => {
  setTestWindow({});

  const result = await scannerService.getSnapshot();

  assert.equal(result.mode, "demo");
  assert.equal(result.data.workspace?.case.isDemo, true);
  assert.ok(result.notice);
});

test("the browser preview never runs or claims a localhost quick scan", async () => {
  setTestWindow({});

  const result = await scannerService.startLocalhostQuickScan();

  assert.equal(result.mode, "demo");
  assert.equal(result.data.accepted, false);
  assert.equal(result.data.workspace, undefined);
  assert.ok(result.notice);
});

test("the browser preview deletes only its own exact-name stored project and reports no file cleanup", async () => {
  let storedValue = JSON.stringify([{
    id: "case-local-delete",
    name: "Delete this preview",
    aiGeneratedArtifact: "unknown",
  }]);
  setTestWindow({
    localStorage: {
      getItem: () => storedValue,
      setItem: (_key: string, value: string) => {
        storedValue = value;
      },
    },
  });

  const rejected = await scannerService.deleteCase("case-local-delete", "wrong name");
  assert.equal(rejected.mode, "demo");
  assert.equal(rejected.data.accepted, false);
  assert.notEqual(storedValue, "[]");

  const deleted = await scannerService.deleteCase("case-local-delete", "Delete this preview");
  assert.equal(deleted.mode, "demo");
  assert.equal(deleted.data.accepted, true);
  assert.equal(deleted.data.databaseRecordDeleted, true);
  assert.deepEqual(deleted.data.artifacts, {
    caseId: "case-local-delete",
    exactPath: "",
    exists: false,
    requiresExplicitConfirmation: false,
  });
  assert.equal(storedValue, "[]");

  const builtIn = await scannerService.deleteCase(
    "case-demo-northstar",
    "Northstar initial security review",
  );
  assert.equal(builtIn.data.accepted, false);
});

test("native case creation sends the closed internal-device profile in snake case", async () => {
  const invocations: { command: string; args: unknown }[] = [];
  setTestWindow({
    __TAURI_INTERNALS__: {
      invoke: async (command: string, args: unknown) => {
        invocations.push({ command, args });
        throw new Error("test-only stop after capturing case creation");
      },
    },
  });

  await assert.rejects(() => scannerService.createCase({
    name: "Internal device review",
    assessmentIntent: "internal_it_environment",
    aiGeneratedArtifact: "no",
    organizationName: "Example",
    companySize: "unknown",
    dataClasses: ["none"],
    requestedActivities: ["active_external_vulnerability_tests"],
    platforms: ["external"],
    knownAssets: [{
      kind: "external_target",
      value: "10.20.30.40",
      internetExposure: "internal",
      webService: {
        protocol: "https",
        port: 8080,
        path: "/",
        scanProfile: "internal_device_https",
      },
    }],
  }), /test-only stop/u);

  assert.equal(invocations[0]?.command, COMMANDS.createCase);
  assert.equal(
    (invocations[0]?.args as { request: { employee_range: string } }).request.employee_range,
    "Not provided",
  );
  assert.deepEqual(
    (invocations[0]?.args as {
      request: { declared_assets: Array<{ web_service: unknown }> };
    }).request.declared_assets[0]?.web_service,
    {
      protocol: "https",
      port: 8080,
      path: "/",
      scan_profile: "internal_device_https",
    },
  );
});

test("native case creation sends one exact generic host profile and selected ports", async () => {
  const invocations: { command: string; args: unknown }[] = [];
  setTestWindow({
    __TAURI_INTERNALS__: {
      invoke: async (command: string, args: unknown) => {
        invocations.push({ command, args });
        throw new Error("test-only stop after capturing generic host case creation");
      },
    },
  });

  await assert.rejects(() => scannerService.createCase({
    name: "Internal host review",
    assessmentIntent: "internal_it_environment",
    aiGeneratedArtifact: "no",
    organizationName: "Example",
    companySize: "small",
    dataClasses: ["none"],
    requestedActivities: ["active_external_vulnerability_tests"],
    platforms: ["external"],
    knownAssets: [{
      kind: "external_target",
      value: "host.example.test",
      internetExposure: "internal",
      hostScan: {
        protocol: "tcp",
        ports: [22, 25, 443, 445, 3389],
        scanProfile: "internal_host_greenbone_remote_safe",
      },
    }],
  }), /test-only stop/u);

  const declaredAsset = (invocations[0]?.args as {
    request: { declared_assets: Array<{ web_service: unknown; network_service: unknown; host_scan: unknown }> };
  }).request.declared_assets[0];
  assert.equal(declaredAsset?.web_service, null);
  assert.equal(declaredAsset?.network_service, null);
  assert.deepEqual(declaredAsset?.host_scan, {
    protocol: "tcp",
    ports: [22, 25, 443, 445, 3389],
    profile: "greenbone_remote_safe_v1",
  });
});

test("native case creation preserves each typed endpoint profile without a web-service fallback", async () => {
  for (const endpoint of [
    { name: "SSH endpoint review", target: "server.example.test", port: 2222, scanProfile: "internal_endpoint_ssh" },
    { name: "RDP transport review", target: "desktop.example.test", port: 3389, scanProfile: "internal_endpoint_rdp_tls" },
    { name: "VNC transport review", target: "workstation.example.test", port: 5900, scanProfile: "internal_endpoint_vnc" },
    { name: "SMTP transport review", target: "mail.example.test", port: 587, scanProfile: "internal_endpoint_smtp" },
    { name: "Telnet cleartext review", target: "switch.example.test", port: 23, scanProfile: "internal_endpoint_telnet" },
  ] as const) {
    const invocations: { command: string; args: unknown }[] = [];
    setTestWindow({
      __TAURI_INTERNALS__: {
        invoke: async (command: string, args: unknown) => {
          invocations.push({ command, args });
          throw new Error("test-only stop after capturing endpoint case creation");
        },
      },
    });

    await assert.rejects(() => scannerService.createCase({
      name: endpoint.name,
      assessmentIntent: "internal_it_environment",
      aiGeneratedArtifact: "no",
      organizationName: "Example",
      companySize: "small",
      dataClasses: ["none"],
      requestedActivities: ["active_external_vulnerability_tests"],
      platforms: ["external"],
      knownAssets: [{
        kind: "external_target",
        value: endpoint.target,
        internetExposure: "internal",
        networkService: {
          protocol: "tcp",
          port: endpoint.port,
          scanProfile: endpoint.scanProfile,
        },
      }],
    }), /test-only stop/u);

    const declaredAsset = (invocations[0]?.args as {
      request: { declared_assets: Array<{ web_service: unknown; network_service: unknown }> };
    }).request.declared_assets[0];
    assert.equal(declaredAsset?.web_service, null);
    assert.deepEqual(declaredAsset?.network_service, {
      protocol: "tcp",
      port: endpoint.port,
      scan_profile: endpoint.scanProfile,
    });
  }
});

test("accepted deletion preserves the latest selection and distinguishes its cleanup outcomes", async () => {
  const app = await readFile(new URL("../../src/App.tsx", import.meta.url), "utf8");
  const start = app.indexOf("const deleteCase = async");
  const end = app.indexOf("const deleteCaseArtifacts = async", start);
  const deletion = app.slice(start, end);

  assert.ok(start >= 0 && end > start);
  assert.match(deletion, /result\.data\.artifacts\.exists[\s\S]*Evidence cleanup requires separate confirmation/u);
  assert.match(deletion, /result\.mode === "demo"[\s\S]*Browser project record deleted/u);
  assert.match(deletion, /Evidence status: none/iu);
  assert.match(
    deletion,
    /setArtifactCleanupPlan\(result\.data\.artifacts\.exists \? result\.data\.artifacts : undefined\)/u,
  );
  const deletionRequest = deletion.indexOf("await scannerService.deleteCase(caseId, confirmation)");
  const latestSelectionRead = deletion.indexOf("const selectedCaseIdAfterDeletion = selectedCaseIdRef.current");
  assert.ok(deletionRequest >= 0);
  assert.ok(latestSelectionRead > deletionRequest, "selection must be read after the deletion request settles");
  assert.doesNotMatch(deletion, /selectedCaseIdBeforeDeletion/u);
  assert.match(
    deletion,
    /await afterLatestCaseSelection\([\s\S]*caseSelectionBarrierRef\.current[\s\S]*const selectedCaseIdAfterDeletion/u,
  );
  assert.match(
    deletion,
    /selectedCaseIdAfterDeletion && selectedCaseIdAfterDeletion !== caseId[\s\S]*\? selectedCaseIdAfterDeletion[\s\S]*: undefined/u,
  );
});

test("the native localhost quick scan invokes its command once with the default and exact edited ports", async () => {
  const invocations: { command: string; args: unknown }[] = [];
  setTestWindow({
    __TAURI_INTERNALS__: {
      invoke: async (command: string, args: unknown) => {
        invocations.push({ command, args });
        throw new Error("test-only quick-scan stop");
      },
    },
  });

  const defaultResult = await scannerService.startLocalhostQuickScan();
  const editedResult = await scannerService.startLocalhostQuickScan(43_123);

  assert.deepEqual(invocations, [
    { command: COMMANDS.startLocalhostQuickScan, args: { port: 9001 } },
    { command: COMMANDS.startLocalhostQuickScan, args: { port: 43_123 } },
  ]);
  for (const result of [defaultResult, editedResult]) {
    assert.equal(result.mode, "native");
    assert.equal(result.data.accepted, false);
    assert.equal(result.data.workspace, undefined);
  }
});

test("queued localhost connection utility does not wait for an unrelated manifest read", async () => {
  let manifestReads = 0;
  setTestWindow({
    __TAURI_INTERNALS__: {
      invoke: async (command: string, args: unknown) => {
        if (command === COMMANDS.startLocalhostQuickScan) {
          assert.deepEqual(args, { port: 9001 });
          return queuedLocalhostNativeCase();
        }
        if (command === COMMANDS.listEngineManifests) {
          manifestReads += 1;
          return new Promise<never>(() => undefined);
        }
        throw new Error(`unexpected command: ${command}`);
      },
    },
  });

  const result = await Promise.race([
    scannerService.startLocalhostQuickScan(),
    new Promise<never>((_resolve, reject) => {
      setTimeout(() => reject(new Error("localhost start waited for engine manifests")), 250);
    }),
  ]);

  assert.equal(result.mode, "native");
  assert.equal(result.data.accepted, true);
  assert.equal(result.data.workspace?.case.id, "localhost-case");
  assert.equal(result.data.workspace?.runs[0]?.status, "queued");
  assert.deepEqual(result.data.workspace?.runs[0]?.engineRuns[0]?.taskKind, {
    kind: "built_in_localhost_tcp",
    port: 9001,
    timeoutMs: 3000,
    payloadBytes: 0,
  });
  assert.equal(manifestReads, 0);
});

test("guided internal Start submits the exact private target and full preset once", async () => {
  const invocations: { command: string; args: unknown }[] = [];
  setTestWindow({
    __TAURI_INTERNALS__: {
      invoke: async (command: string, args: unknown) => {
        invocations.push({ command, args });
        throw new Error("test-only stop after capturing guided internal Start");
      },
    },
  });
  const ports = [
    80, 443, 22, 445, 3389, 8080, 8443, 21, 25, 53, 110, 139, 143, 465, 587, 993, 995,
    3306, 5432, 6379, 9100,
  ];
  const confirmation = "I confirm this scan may connect to the selected internal network";

  const result = await scannerService.startScan({
    caseId: "internal-case",
    authorization: {
      assetIds: ["internal-asset"],
      modes: ["low_impact_external"],
      confirmation,
      externalScope: {
        target: "192.168.50.0/24",
        ports,
        protocol: "tcp",
        activity: "low_impact_external",
        ratePolicy: {
          requestsPerSecond: 25,
          concurrency: 10,
          timeoutSeconds: 3,
        },
        templatePolicy: {
          revision: "not_applicable",
          allowedTemplateIds: [],
          allowHeadless: false,
          allowOutOfBand: false,
          allowFuzzing: false,
          allowFileUpload: false,
          allowDenialOfService: false,
          allowCredentialAttacks: false,
        },
        assertedAuthority: confirmation,
        allowSensitiveNetworks: true,
      },
    },
  });

  assert.equal(result.mode, "native");
  assert.equal(result.data.accepted, false);
  assert.equal(invocations.length, 1);
  const submitted = invocations[0] as {
    command: string;
    args: { decisions: Array<Record<string, unknown>> };
  };
  assert.ok(
    ["Local user", "本機使用者"].includes(String(submitted.args.decisions[0]?.confirmed_by)),
  );
  assert.deepEqual(invocations[0], {
    command: COMMANDS.startScan,
    args: {
      caseId: "internal-case",
      decisions: [{
        asset_id: "internal-asset",
        permissions: ["low_impact_external_connection"],
        confirmed_by: submitted.args.decisions[0]?.confirmed_by,
        authorization_reference: confirmation,
        notes: confirmation,
        external_scope: {
          target: "192.168.50.0/24",
          ports,
          protocol: "tcp",
          activity: "low_impact_external",
          rate_policy: {
            requests_per_second: 25,
            concurrency: 10,
            timeout_seconds: 3,
          },
          template_policy: {
            revision: "not_applicable",
            allowed_template_ids: [],
            allow_headless: false,
            allow_out_of_band: false,
            allow_fuzzing: false,
            allow_file_upload: false,
            allow_denial_of_service: false,
            allow_credential_attacks: false,
          },
          asserted_authority: confirmation,
          allow_sensitive_networks: true,
        },
      }],
      engineIds: [],
      engineAssetRoutes: [],
    },
  });
});

test("one Start submits independent target boundaries and exact engine-to-asset routes", async () => {
  const invocations: { command: string; args: unknown }[] = [];
  setTestWindow({
    __TAURI_INTERNALS__: {
      invoke: async (command: string, args: unknown) => {
        invocations.push({ command, args });
        throw new Error("test-only stop after capturing combined Start");
      },
    },
  });

  const result = await scannerService.startScan({
    caseId: "company-environment",
    authorizations: [
      {
        assetIds: ["repo-a", "repo-b"],
        modes: ["local_artifact"],
        confirmation: "Review the two selected read-only project snapshots.",
      },
      {
        assetIds: ["website-a"],
        modes: ["active_external"],
        confirmation: "Authorized exact website A origin",
        externalScope: {
          target: "a.example.test",
          ports: [443],
          protocol: "https",
          activity: "active_external",
          ratePolicy: { requestsPerSecond: 3, concurrency: 2, timeoutSeconds: 10 },
          templatePolicy: {
            revision: "nuclei-templates@test",
            allowedTemplateIds: ["safe-template"],
            allowHeadless: false,
            allowOutOfBand: false,
            allowFuzzing: false,
            allowFileUpload: false,
            allowDenialOfService: false,
            allowCredentialAttacks: false,
          },
          assertedAuthority: "Authorized exact website A origin",
          allowSensitiveNetworks: false,
        },
      },
      {
        assetIds: ["endpoint-a"],
        modes: ["active_external"],
        confirmation: "Authorized exact internal endpoint A",
        externalScope: {
          target: "192.168.50.10",
          ports: [443],
          protocol: "https",
          activity: "active_external",
          ratePolicy: { requestsPerSecond: 3, concurrency: 1, timeoutSeconds: 10 },
          templatePolicy: {
            revision: "greenbone-community-feed@test",
            profileId: "greenbone_remote_safe_v1",
            allowedTemplateIds: [],
            allowHeadless: false,
            allowOutOfBand: false,
            allowFuzzing: false,
            allowFileUpload: false,
            allowDenialOfService: false,
            allowCredentialAttacks: false,
          },
          assertedAuthority: "Authorized exact internal endpoint A",
          allowSensitiveNetworks: true,
        },
      },
    ],
    engineAssetRoutes: [
      { engineId: "semgrep", assetIds: ["repo-a", "repo-b"] },
      { engineId: "gitleaks", assetIds: ["repo-a", "repo-b"] },
      { engineId: "nuclei", assetIds: ["website-a"] },
      { engineId: "greenbone", assetIds: ["endpoint-a"] },
    ],
  });

  assert.equal(result.mode, "native");
  assert.equal(result.data.accepted, false);
  assert.equal(invocations.length, 1);
  const submitted = invocations[0] as {
    command: string;
    args: {
      decisions: Array<{
        asset_id: string;
        external_scope?: { target: string; template_policy: { profile_id?: string } } | null;
      }>;
      engineIds: string[];
      engineAssetRoutes: Array<{ engine_id: string; asset_ids: string[] }>;
    };
  };
  assert.equal(submitted.command, COMMANDS.startScan);
  assert.deepEqual(submitted.args.decisions.map((decision) => decision.asset_id), [
    "repo-a",
    "repo-b",
    "website-a",
    "endpoint-a",
  ]);
  assert.equal(submitted.args.decisions[2]?.external_scope?.target, "a.example.test");
  assert.equal(submitted.args.decisions[3]?.external_scope?.target, "192.168.50.10");
  assert.equal(
    submitted.args.decisions[3]?.external_scope?.template_policy.profile_id,
    "greenbone_remote_safe_v1",
  );
  assert.deepEqual(submitted.args.engineIds, []);
  assert.deepEqual(submitted.args.engineAssetRoutes, [
    { engine_id: "semgrep", asset_ids: ["repo-a", "repo-b"] },
    { engine_id: "gitleaks", asset_ids: ["repo-a", "repo-b"] },
    { engine_id: "nuclei", asset_ids: ["website-a"] },
    { engine_id: "greenbone", asset_ids: ["endpoint-a"] },
  ]);
});

test("scan lifecycle mutation acknowledgements never read optional manifests", async () => {
  const mutations = [
    {
      command: COMMANDS.startScan,
      run: () => scannerService.startScan({ caseId: "localhost-case" }),
    },
    {
      command: COMMANDS.pauseScan,
      run: () => scannerService.pauseScan("localhost-case", "localhost-run"),
    },
    {
      command: COMMANDS.resumeScan,
      run: () => scannerService.resumeScan("localhost-case", "localhost-run"),
      lifecycleOutcome: "queued",
    },
    {
      command: COMMANDS.cancelScan,
      run: () => scannerService.cancelScan("localhost-case", "localhost-run"),
      lifecycleOutcome: "requested",
    },
    {
      command: COMMANDS.startRescan,
      run: () => scannerService.startRescan("localhost-case", "localhost-run"),
    },
  ] as const;

  for (const mutation of mutations) {
    let manifestReads = 0;
    let commandCalls = 0;
    setTestWindow({
      __TAURI_INTERNALS__: {
        invoke: async (command: string) => {
          if (command === mutation.command) {
            commandCalls += 1;
            const nativeCase = queuedLocalhostNativeCase();
            if (command === COMMANDS.cancelScan) {
              nativeCase.scan_runs[0]!.engine_runs[0]!.phase = "cancel_requested";
            }
            return nativeCase;
          }
          if (command === COMMANDS.listEngineManifests) {
            manifestReads += 1;
            return new Promise<never>(() => undefined);
          }
          throw new Error(`unexpected command: ${command}`);
        },
      },
    });

    let timeout: ReturnType<typeof setTimeout> | undefined;
    try {
      const result = await Promise.race([
        mutation.run(),
        new Promise<never>((_resolve, reject) => {
          timeout = setTimeout(
            () => reject(new Error(`${mutation.command} waited for engine manifests`)),
            250,
          );
        }),
      ]);
      assert.equal(result.mode, "native", mutation.command);
      assert.equal(result.data.accepted, true, mutation.command);
      assert.equal(result.data.workspace?.case.id, "localhost-case", mutation.command);
      if ("lifecycleOutcome" in mutation) {
        assert.equal(result.data.lifecycleDisposition?.outcome, mutation.lifecycleOutcome, mutation.command);
      } else {
        assert.equal(result.data.lifecycleDisposition, undefined, mutation.command);
      }
    } finally {
      if (timeout) clearTimeout(timeout);
    }
    assert.equal(commandCalls, 1, mutation.command);
    assert.equal(manifestReads, 0, mutation.command);
  }
});

test("a retained terminal Resume response reports the saved result instead of a queued restart", async () => {
  let manifestReads = 0;
  setTestWindow({
    __TAURI_INTERNALS__: {
      invoke: async (command: string) => {
        if (command === COMMANDS.resumeScan) {
          const nativeCase = queuedLocalhostNativeCase();
          nativeCase.status = "completed";
          const nativeRun = nativeCase.scan_runs[0]!;
          nativeRun.completed_at = "2026-08-30T12:00:01Z";
          const nativeEngine = nativeRun.engine_runs[0]!;
          nativeEngine.status = "completed";
          nativeEngine.progress_percent = 100;
          nativeEngine.phase = "completed";
          nativeEngine.started_at = "2026-08-30T12:00:00Z";
          nativeEngine.finished_at = "2026-08-30T12:00:01Z";
          nativeEngine.localhost_tcp_observation = {
            outcome: "reachable",
            observed_at: "2026-08-30T12:00:01Z",
          };
          return nativeCase;
        }
        if (command === COMMANDS.listEngineManifests) {
          manifestReads += 1;
          return new Promise<never>(() => undefined);
        }
        throw new Error(`unexpected command: ${command}`);
      },
    },
  });

  const result = await scannerService.resumeScan("localhost-case", "localhost-run");
  assert.equal(result.data.accepted, true);
  assert.equal(result.data.lifecycleDisposition?.outcome, "result_already_final");
  assert.equal(
    result.data.lifecycleDisposition?.outcome === "result_already_final"
      ? result.data.lifecycleDisposition.resultStatus
      : undefined,
    "completed",
  );
  assert.doesNotMatch(result.data.message, /queued|started|排入佇列|開始/u);
  assert.equal(manifestReads, 0);
});

test("native Cancel carries only an exact job acknowledgement through the workspace response", async () => {
  for (const acknowledgement of [undefined, "another-run", "localhost-run"]) {
    setTestWindow({
      __TAURI_INTERNALS__: {
        invoke: async (command: string) => {
          assert.equal(command, COMMANDS.cancelScan, "cancellation must not wait for optional reads");
          return { ...queuedLocalhostNativeCase(), cancel_requested_run_id: acknowledgement };
        },
      },
    });
    const result = await scannerService.cancelScan("localhost-case", "localhost-run");
    const exact = acknowledgement === "localhost-run";
    assert.equal(result.data.accepted, true);
    assert.equal(result.data.cancelRequestedRunId, exact ? "localhost-run" : undefined);
    assert.equal(result.data.lifecycleDisposition?.outcome, exact ? "requested" : "unconfirmed");
    assert.ok(result.data.workspace);
    assert.equal("cancel_requested_run_id" in result.data.workspace.case, false);
  }
});

test("an uncertain native Cancel outcome is typed unconfirmed and does not read manifests", async () => {
  let manifestReads = 0;
  setTestWindow({
    __TAURI_INTERNALS__: {
      invoke: async (command: string) => {
        if (command === COMMANDS.cancelScan) throw new Error("command response was lost");
        if (command === COMMANDS.listEngineManifests) {
          manifestReads += 1;
          return new Promise<never>(() => undefined);
        }
        throw new Error(`unexpected command: ${command}`);
      },
    },
  });

  const result = await scannerService.cancelScan("localhost-case", "localhost-run");
  assert.equal(result.mode, "native");
  assert.equal(result.data.accepted, false);
  assert.deepEqual(result.data.lifecycleDisposition, {
    action: "cancel",
    outcome: "unconfirmed",
    runId: "localhost-run",
  });
  assert.equal(manifestReads, 0);
});

test("a packaged surface with a missing bridge stays native and fails visibly", async () => {
  setTestWindow({});

  assert.equal(packagedScannerService.isNative(), true);
  await assert.rejects(
    () => packagedScannerService.getSnapshot(),
    /(?:Desktop service unavailable\. Restart ai-security-scanner|桌面服務無法使用；請重新啟動 ai-security-scanner)/u,
  );

  const manifests = await packagedScannerService.listEngineManifests();
  assert.equal(manifests.mode, "native");
  assert.deepEqual(manifests.data, []);
  assert.equal(manifests.notice, undefined);
});

test("combined report export forwards selected sources and the native save path", async () => {
  const destination = String.raw`C:\Users\example\Downloads\combined-report.html`;
  const calls: Array<{ command: string; args: unknown }> = [];
  const receipt = { case_id: "case-1", selected_run_ids: ["native-run", "strix-run"], format: "html",
    path: destination, sha256: "a".repeat(64), created_at: "2026-10-22T12:00:00Z", redaction_profile: "standard" };
  setTestWindow({ __TAURI_INTERNALS__: { invoke: async (command: string, args: unknown) => {
    calls.push({ command, args });
    if (command === "plugin:dialog|save") return destination;
    if (command === COMMANDS.exportSelectedRunReport) return receipt;
    throw new Error(`Unexpected command: ${command}`);
  } } });
  const input = { caseId: "case-1", runIds: ["native-run", "strix-run"], locale: "zh-Hant" as const,
    format: "html" as const, redactSensitiveValues: true };
  const result = await scannerService.exportSelectedRunReport(input);
  assert.equal(result.mode, "native");
  assert.deepEqual(result.data, receipt);
  assert.deepEqual(calls.map((call) => call.command), ["plugin:dialog|save", COMMANDS.exportSelectedRunReport]);
  assert.deepEqual(calls[1]?.args, { input: { ...input, destination } });
});

test("cancelling a combined report save creates no native export", async () => {
  const calls: string[] = [];
  setTestWindow({ __TAURI_INTERNALS__: { invoke: async (command: string) => {
    calls.push(command);
    if (command === "plugin:dialog|save") return null;
    throw new Error(`Unexpected command: ${command}`);
  } } });
  const result = await scannerService.exportSelectedRunReport({ caseId: "case-1", runIds: ["one", "two"],
    locale: "en", format: "json", redactSensitiveValues: true });
  assert.equal(result.data, null);
  assert.deepEqual(calls, ["plugin:dialog|save"]);
});

test("snapshot errors keep real state visible with persistent bilingual retry UI", async () => {
  const [app, shell, scanner, english, chinese] = await Promise.all([
    readFile(new URL("../../src/App.tsx", import.meta.url), "utf8"),
    readFile(new URL("../../src/components/AppShell.tsx", import.meta.url), "utf8"),
    readFile(new URL("../../src/services/scanner.ts", import.meta.url), "utf8"),
    readFile(new URL("../../src/i18n/locales/en.ts", import.meta.url), "utf8"),
    readFile(new URL("../../src/i18n/locales/zh-TW.ts", import.meta.url), "utf8"),
  ]);

  const snapshotStart = scanner.indexOf("async getSnapshot");
  const snapshotEnd = scanner.indexOf("async setupManagedRuntime", snapshotStart);
  const getSnapshot = scanner.slice(snapshotStart, snapshotEnd);
  assert.ok(snapshotStart >= 0 && snapshotEnd > snapshotStart);
  assert.match(getSnapshot, /if \(!isNativeSurface\(\)\) return demoResult/u);
  assert.match(getSnapshot, /await invoke<NativeAppSnapshot>\(COMMANDS\.getSnapshot\)/u);
  assert.doesNotMatch(getSnapshot, /catch|return demoResult\([^]*error/u);
  assert.match(scanner, /TAURI_ENV_PLATFORM/u);
  assert.match(scanner, /Boolean\(packagedTauriPlatform\) \|\| hasLiveTauriBridge\(\)/u);

  const loadStart = app.indexOf("const loadSnapshot");
  const loadEnd = app.indexOf("useEffect(() =>", loadStart);
  const loadSnapshot = app.slice(loadStart, loadEnd);
  assert.ok(loadStart >= 0 && loadEnd > loadStart);
  assert.match(loadSnapshot, /setSnapshotRefreshUnavailable\(false\)/u);
  assert.match(loadSnapshot, /catch \(error\)[\s\S]*setSnapshotRefreshUnavailable\(true\)/u);
  assert.doesNotMatch(loadSnapshot, /setSnapshot\((?:undefined|null)\)/u);

  assert.match(app, /snapshotRefreshUnavailable && !snapshot/u);
  assert.match(app, /dataUnavailable=\{snapshotRefreshUnavailable && snapshot !== undefined\}/u);
  assert.match(app, /onRetryData=\{\(\) => void loadSnapshot\(snapshot\?\.selectedCaseId\)\}/u);
  assert.doesNotMatch(app, /switch to demo data|\u5207\u63db\u6210\u5c55\u793a\u8cc7\u6599/u);

  assert.match(shell, /className="data-status-banner" role="alert"/u);
  assert.match(shell, /disabled=\{dataRetrying\}/u);
  assert.match(shell, /onClick=\{onRetryData\}/u);
  assert.match(shell, /shell\.data\.refreshErrorTitle/u);
  assert.match(shell, /shell\.data\.refreshErrorDetail/u);

  const selectStart = app.indexOf("const selectCase");
  const selectEnd = app.indexOf("const retryScanReadiness", selectStart);
  const selectCase = app.slice(selectStart, selectEnd);
  assert.ok(selectStart >= 0 && selectEnd > selectStart);
  assert.match(selectCase, /supersedeCaseSelectionRef\.current\(\)/u);
  assert.match(selectCase, /caseSelectionBarrierRef\.current = \{[\s\S]*settled,[\s\S]*superseded,/u);
  assert.match(selectCase, /supersedeCaseSelectionRef\.current = supersedeSelection/u);
  assert.match(
    selectCase,
    /finally[\s\S]*caseSelectionBarrierRef\.current\.generation === selectionGeneration[\s\S]*setLoading\(false\)[\s\S]*settleSelection\(\)/u,
  );
  assert.match(selectCase, /setCaseSelectionUnavailableId\(undefined\)/u);
  assert.match(selectCase, /catch \(error\)[\s\S]*setCaseSelectionUnavailableId\(caseId\)/u);
  assert.doesNotMatch(selectCase, /setSnapshot\((?:undefined|null)\)/u);
  assert.match(app, /caseSelectionUnavailable=\{caseSelectionUnavailableId !== undefined\}/u);
  assert.match(app, /onRetryCaseSelection=\{\(\) => \{[\s\S]*selectCase\(caseSelectionUnavailableId\)/u);
  assert.match(shell, /caseSelectionUnavailable && \([\s\S]*shell\.data\.selectionErrorTitle/u);
  assert.match(shell, /onClick=\{onRetryCaseSelection\}/u);

  for (const source of [english, chinese]) {
    for (const key of [
      "shell.data.initialErrorTitle",
      "shell.data.initialErrorDetail",
      "shell.data.refreshErrorTitle",
      "shell.data.refreshErrorDetail",
      "shell.data.selectionErrorTitle",
      "shell.data.selectionErrorDetail",
      "shell.data.retry",
      "shell.data.retrying",
    ]) assert.ok(source.includes(`\"${key}\"`), `${key} must be translated`);
  }
});
