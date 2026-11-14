# API Reference

This document provides a reference for the core backend APIs exposed to the frontend via Tauri, and usage examples for interacting with the backend services.

The development CLI shares the core but has a separate command contract: [bootstrap](skill-bootstrap.md), [foreground execution](foreground-scans.md), [report snapshots](report-snapshots.md), [case archives](case-archives.md), and [Cloudflare validation/retention](cloudflare-provider.md). These newer commands are not in the v0.6.2 installers; see [publication status](release-model.md). They are CLI commands, not new Tauri invoke names.

## Core Modules

The backend logic is divided into several core modules:

*   **`core_state` / `scan_coordinator`**: Shared headless state and foreground worker ownership, cancellation, receipts and captured-evidence recovery.
*   **`report_renderer` / `report_snapshot`**: Shared rendering, saved report bytes and exact-compatible offline replay.
*   **`case_archive`**: Private portable case preservation and restore into a new workspace.
*   **`cloudflare_provider` / `provider_report` / `agent_audit_admission`**: Pinned document/bundle validation, host-led audit custody through sealing, case admission into the shared report, and private offline retention.
*   **`case_service`**: Manages the lifecycle of assessment cases, including creation, updates, and state transitions.
*   **`orchestrator`**: Coordinates the execution of various scanning engines, handling dependencies and concurrency.
*   **`managed_runtime`**: Responsible for the setup and teardown of isolated runtime environments for scanning engines (e.g., containers, dedicated network namespaces).
*   **`export`**: Handles the generation and formatting of security reports in various formats (HTML, JSON).
*   **`storage`**: Provides persistent storage for cases, findings, and configuration data using SQLite.

## API Specifications

The following commands are exposed to the frontend via Tauri's `invoke` API.

### `start_scan`

Starts a new scan for a given case.

**Arguments:**

*   `case_id`: (string) The ID of the assessment case.
*   `decisions`: (array of ScopeDecision, optional) List of scope decisions.
*   `engine_ids`: (array of string, optional) List of engine IDs to run.
*   `engine_asset_routes`: (array of EngineAssetRoute, optional) List of engine asset routes.
*   `campaign_id`: (string, optional) An optional campaign ID.

**Returns:**

Returns the updated `AssessmentCase` object representing the new scan state.

**Usage Example:**

```typescript
import { invoke } from "@tauri-apps/api/core";

async function runScan() {
  const caseId = "my-case-id";
  const updatedCase = await invoke("start_scan", {
    caseId,
    decisions: [],
    engineIds: ["engine1", "engine2"],
    engineAssetRoutes: null
  });
  console.log("Scan started:", updatedCase);
}
```

### `resume_scan`

Resumes a previously paused or interrupted scan.

**Arguments:**

*   `case_id`: (string) The ID of the assessment case.
*   `run_id`: (string, optional) The scan run to resume; defaults to the latest run.

**Returns:**

Returns the updated `AssessmentCase` object.

**Usage Example:**

```typescript
import { invoke } from "@tauri-apps/api/core";

async function resumeExistingScan() {
  const updatedCase = await invoke("resume_scan", {
    caseId: "my-case-id",
    runId: "my-run-id"
  });
  console.log("Scan resumed:", updatedCase);
}
```

### `export_selected_run_report`

Exports the report for a selected scan run.

**Arguments:**

*   `input`: (ExportSelectedRunReportInput) The input containing the case ID, run IDs, and export format preferences.

**Returns:**

Returns the exported report data.

**Usage Example:**

```typescript
import { invoke } from "@tauri-apps/api/core";

async function exportReport() {
  const report = await invoke("export_selected_run_report", {
    input: {
      caseId: "my-case-id",
      runIds: ["my-run-id"],
      locale: "en",
      format: "html",
      redactSensitiveValues: true,
      destination: "/path/to/report.html"
    }
  });
  console.log("Exported report:", report);
}
```

### `execute_provider_bootstrap`

Executes the reviewed setup for cloud provider read-only access (e.g., AWS, Azure) for one case source.

**Arguments:**

*   `input`: (ExecuteProviderBootstrapInput) `operationId`, the reviewed `execution` request, `sourceId`, `allowedEngineIds` and `maxCheckouts`. Unknown fields are rejected. Credentials never pass through this call; administrator sign-in happens in the provider's own flow.

**Returns:**

Returns the installed source authorization for that operation.
