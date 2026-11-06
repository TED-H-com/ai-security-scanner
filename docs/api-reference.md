# API Reference

This document provides a reference for the core backend APIs exposed to the frontend via Tauri, and usage examples for interacting with the backend services.

## Core Modules

The backend logic is divided into several core modules:

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
*   `run_id`: (string) The ID of the scan run to resume.

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

Executes the setup process for cloud provider read-only access (e.g., AWS, Azure).

**Arguments:**

*   `input`: (ProviderBootstrapInput) Configuration for the provider setup.

**Returns:**

Returns the status of the bootstrap process.

**Usage Example:**

```typescript
import { invoke } from "@tauri-apps/api/core";

async function setupProvider() {
  const status = await invoke("execute_provider_bootstrap", {
    input: {
      provider: "aws",
      method: "read_only",
      credentials: { /* ... */ }
    }
  });
  console.log("Bootstrap status:", status);
}
```
