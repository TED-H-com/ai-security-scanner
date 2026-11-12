use crate::bootstrap::executor::{
    BootstrapBrokerCommand, BootstrapCleanupObligationSummary, BootstrapCleanupResult,
    BootstrapExecutionRequest, BootstrapOperatorConfig, bootstrap_cleanup_obligation_summary,
    list_bootstrap_cleanup_obligations,
};
use crate::bootstrap::{BootstrapPlan, BootstrapRequest, create_bootstrap_plan};
use crate::case_service::{
    ArtifactDeletionResult, CaseDeletionResult, CaseExportFormat, EngineAssetRoute, ExportPreview,
    FindingGroupRequest, FindingUngroupRequest, FindingWorkflowRequest,
    LiveProviderDiscoveryOutcome, ScanPlanRequest, ScanReadiness, ScopeApprovalRequest,
};
use crate::connectors::{SNAPSHOT_ARTIFACT_METADATA_KEY, SnapshotConnectorRegistry};
use crate::core_state::CoreState;
use crate::correlation::{CorrelationReport, correlation_report};
use crate::demo::build_demo_case;
use crate::discovery::run_connector;
use crate::domain::*;
use crate::error::{AppError, AppResult};
use crate::export::{ExportOptions, RedactionProfile, ReportLocale, verify_case_bundle};
use crate::job_manager::{JobKey, JobSnapshot};
use crate::local_tcp_probe::DesktopHostTcpConnector;
use crate::localhost_quick_scan::{
    execute_managed_localhost_quick_scan, live_localhost_quick_scan_for_port,
    localhost_quick_scan_for_snapshot, prepare_localhost_quick_scan,
    reconcile_interrupted_localhost_quick_scan, run_is_exact_localhost_quick_scan,
};
use crate::managed_runtime::ManagedRuntimeSetupStatus;
use crate::scan_coordinator::*;
use crate::source_authorization::discovery::{
    LiveProviderFailure, LiveProviderFailureKind, capture_provider_inventory,
};
use crate::source_authorization::provider::ReqwestProviderHttp;
use crate::source_authorization::session::{
    BeginProviderAuthorizationRequest, ProviderAuthorizationConfig, ProviderAuthorizationProgress,
    ProviderAuthorizationPrompt, ProviderSessionPoll,
};
use crate::source_authorization::{
    InstalledSourceAuthorization, PROVIDER_RESOURCE_SCOPE_METADATA_KEY, ProviderSourceProfile,
};
use crate::state::AppState;
use crate::workspace_snapshot::{
    WORKSPACE_SNAPSHOT_REFERENCE_METADATA_KEY, WorkspaceInputProfile, WorkspaceSnapshotLimits,
    WorkspaceSnapshotReference, create_workspace_snapshot_with_profile, inspect_workspace_snapshot,
    resolve_workspace_snapshot,
};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command as ProcessCommand, ExitStatus, Stdio};
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::{Duration as StdDuration, Instant};
use tauri::{AppHandle, Emitter, Manager, State};

const COVERAGE_CHANGED_EVENT: &str = "case://coverage-changed";
const RUN_PROGRESS_EVENT: &str = "scan://run-progress";
const RUN_FINISHED_EVENT: &str = "scan://run-finished";
const EXPORT_PROGRESS_EVENT: &str = "export://progress";
const BOOTSTRAP_MESSAGE_EVENT: &str = "provider://bootstrap-message";
const BOOTSTRAP_BROKER_DEADLINE: StdDuration = StdDuration::from_secs(20 * 60);
const BOOTSTRAP_PIPE_DRAIN_DEADLINE: StdDuration = StdDuration::from_secs(2);

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExportCaseInput {
    pub case_id: Id,
    pub run_id: Id,
    pub locale: ReportLocale,
    pub format: CaseExportFormat,
    #[serde(default)]
    pub include_raw_evidence: bool,
    #[serde(default = "default_true")]
    pub redact_sensitive_values: bool,
    pub destination: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PreviewExportInput {
    pub case_id: Id,
    pub run_id: Id,
    pub locale: ReportLocale,
    pub format: CaseExportFormat,
    #[serde(default)]
    pub include_raw_evidence: bool,
    #[serde(default = "default_true")]
    pub redact_sensitive_values: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExportSelectedRunsInput {
    #[serde(default)]
    pub include_raw_artifacts: bool,
    #[serde(default)]
    pub acknowledge_sensitive_raw_artifacts: bool,
    #[serde(default)]
    pub acknowledge_sensitive_data: bool,
    pub case_id: Id,
    pub run_ids: Vec<Id>,
    pub locale: ReportLocale,
    pub format: crate::selected_run_report::SelectedRunReportFormat,
    #[serde(default = "default_true")]
    pub redact_sensitive_values: bool,
    pub destination: String,
}

#[derive(Debug, Serialize)]
pub struct IntegrityResponse {
    pub accepted: bool,
    pub message: String,
}

#[tauri::command]
pub async fn setup_managed_runtime(state: State<'_, AppState>) -> AppResult<IntegrityResponse> {
    ensure_verified_managed_runtime_for_setup(&state)?;
    let manager = state
        .managed_runtime()
        .cloned()
        .expect("the immutable setup guard verified a managed runtime manager");
    let worker_setup = state.managed_runtime_setup().clone();
    state.invalidate_runtime_health();
    let status =
        match tauri::async_runtime::spawn_blocking(move || manager.setup(worker_setup.as_ref()))
            .await
        {
            Ok(result) => result?,
            Err(_) => {
                let message = "managed runtime setup worker terminated unexpectedly";
                return Err(AppError::Internal(message.into()));
            }
        };
    state.record_managed_runtime_health(&status);
    if !status.available {
        return Err(AppError::Runtime(format!(
            "managed runtime setup ended in phase {}: {}",
            status.phase.as_str(),
            status.detail
        )));
    }
    Ok(IntegrityResponse {
        accepted: true,
        message: format!(
            "Managed rootless runtime {} is running and ready for isolated local engines.",
            status.runtime_version
        ),
    })
}

fn ensure_verified_managed_runtime_for_setup(state: &CoreState) -> AppResult<()> {
    if state.managed_runtime().is_some() {
        return Ok(());
    }
    let status = state.managed_runtime_setup().status()?;
    if !status.can_retry && status.failure_reason.is_some() && status.next_action.is_none() {
        return Err(AppError::NotAvailable(status.detail));
    }
    Err(AppError::NotAvailable(
        "verified scan tools are unavailable; install the latest app version".into(),
    ))
}

#[tauri::command]
pub fn get_managed_runtime_setup_status(
    state: State<'_, AppState>,
) -> AppResult<ManagedRuntimeSetupStatus> {
    state.managed_runtime_setup().status()
}

#[tauri::command]
pub fn cancel_managed_runtime_setup(
    state: State<'_, AppState>,
) -> AppResult<ManagedRuntimeSetupStatus> {
    state.managed_runtime_setup().request_cancel()
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize)]
pub struct DesktopAppSnapshot {
    #[serde(flatten)]
    pub snapshot: AppSnapshot,
    /// One pure, run-bound report projection per terminal selected-case run.
    /// Active work is represented only by the Progress data in `snapshot`.
    pub beginner_reports: Vec<crate::beginner_report::BeginnerMasterReport>,
    /// Isolated packaged-catalog problems. They never gate the shell or
    /// admitted sibling checks; default scans freeze relevant limitations so
    /// reports cannot silently imply full scanner availability.
    pub engine_admission_issues: Vec<EngineAdmissionIssue>,
    /// Project-scoped recovery notices. Unreadable case bytes remain in the
    /// database unchanged and never prevent healthy projects or the shell from
    /// opening.
    pub case_recovery_diagnostics: Vec<crate::storage::CaseRecoveryDiagnostic>,
}

struct ReadableDesktopCases {
    cases: Vec<CaseSummary>,
    selected_case: Option<AssessmentCase>,
    recovery_diagnostics: Vec<crate::storage::CaseRecoveryDiagnostic>,
}

fn schedule_retained_terminal_reconciliation(app: &AppHandle) {
    let background_app = app.clone();
    std::mem::drop(tauri::async_runtime::spawn_blocking(move || {
        let state = background_app.state::<AppState>();
        let summary = reconcile_retained_terminal_jobs(&state);
        if summary.reconciled > 0 || summary.pending > 0 {
            tracing::info!(
                reconciled = summary.reconciled,
                pending = summary.pending,
                "retained terminal scan outcomes were reconciled in the background"
            );
        }
    }));
}

/// Reconciles one exact retained terminal generation without making the UI
/// wait for report persistence or product-owned runtime cleanup. A concurrent
/// callback may already own the exact-generation claim; in that case this
/// detached attempt simply observes `InProgress` and leaves durable truth to
/// that owner.
fn schedule_exact_terminal_reconciliation(app: &AppHandle, key: JobKey, snapshot: JobSnapshot) {
    let background_app = app.clone();
    std::mem::drop(tauri::async_runtime::spawn_blocking(move || {
        if let Err(error) =
            reconcile_terminal_job(&desktop_scan_coordinator(&background_app), &key, &snapshot)
        {
            tracing::warn!(
                error = %error,
                case_id = %key.case_id,
                scan_run_id = %key.scan_run_id,
                "exact retained terminal scan outcome is still waiting for durable reconciliation"
            );
        }
    }));
}

/// Retries exact product-owned cleanup for one durable run off the command
/// path. The reconciler never repeats target-facing scanner work and its
/// ownership rules preserve any resource whose exact identity is unavailable.
fn schedule_exact_runtime_cleanup_reconciliation(app: &AppHandle, case_id: String, run_id: String) {
    let background_app = app.clone();
    std::mem::drop(tauri::async_runtime::spawn_blocking(move || {
        let state = background_app.state::<AppState>();
        match reconcile_interrupted_scan_resources(&state, Some((&case_id, &run_id))) {
            Ok(summary) if summary.reconciled > 0 || summary.pending > 0 => tracing::info!(
                reconciled = summary.reconciled,
                pending = summary.pending,
                details = ?summary.details,
                case_id = %case_id,
                scan_run_id = %run_id,
                "exact scanner runtime cleanup was reconciled in the background"
            ),
            Ok(_) => {}
            Err(error) => tracing::warn!(
                error = %error,
                case_id = %case_id,
                scan_run_id = %run_id,
                "exact scanner runtime cleanup remains pending after a background retry"
            ),
        }
    }));
}

fn load_readable_desktop_cases(state: &CoreState) -> AppResult<ReadableDesktopCases> {
    let listing = state.storage.list_cases_with_recovery_diagnostics()?;
    let mut recovery_diagnostics = listing.recovery_diagnostics;
    let selected_id = state.storage.selected_case_id()?;
    let selected_is_unreadable = selected_id.as_ref().is_some_and(|selected_id| {
        recovery_diagnostics
            .iter()
            .any(|diagnostic| diagnostic.case_id == *selected_id)
    });
    let selected_is_readable = selected_id
        .as_ref()
        .is_some_and(|selected_id| listing.cases.iter().any(|case| case.id == *selected_id));

    if let Some(selected_id) = selected_id.as_ref()
        && !selected_is_unreadable
        && !selected_is_readable
    {
        recovery_diagnostics.push(crate::storage::CaseRecoveryDiagnostic {
            case_id: selected_id.clone(),
            title: "Saved project".into(),
            updated_at: Utc::now().to_rfc3339(),
            revision: 0,
            document_bytes: 0,
            code: "selected_case_missing".into(),
            message: "The selected project is absent from local storage. Choose another saved project or create a new one.".into(),
            preserved: false,
        });
    }

    let fallback_id = listing.cases.first().map(|case| case.id.as_str());
    let case_id = selected_id
        .as_deref()
        .filter(|_| selected_is_readable)
        .or(fallback_id);
    let selected_case = case_id
        .map(|case_id| state.storage.get_case(case_id))
        .transpose()?;

    Ok(ReadableDesktopCases {
        cases: listing.cases,
        selected_case,
        recovery_diagnostics,
    })
}

#[tauri::command]
pub async fn get_app_snapshot(
    app: AppHandle,
    state: State<'_, AppState>,
) -> AppResult<DesktopAppSnapshot> {
    let _ = state.request_runtime_health_refresh();
    schedule_retained_terminal_reconciliation(&app);
    let service = state.case_service();
    let readable = load_readable_desktop_cases(&state)?;
    let selected_case = readable.selected_case;
    let beginner_reports = selected_case
        .as_ref()
        .map(|case| {
            case.scan_runs
                .iter()
                .filter(|run| crate::beginner_report::run_is_authoritatively_final(run))
                .map(|run| {
                    crate::beginner_report::build_beginner_master_report(case, &run.id).map_err(
                        |error| {
                            AppError::InvalidRequest(format!(
                                "could not derive the saved report for run {}: {error}",
                                run.id
                            ))
                        },
                    )
                })
                .collect::<AppResult<Vec<_>>>()
        })
        .transpose()?
        .unwrap_or_default();

    Ok(DesktopAppSnapshot {
        snapshot: AppSnapshot {
            product_name: "ai-security-scanner".into(),
            product_version: env!("CARGO_PKG_VERSION").into(),
            storage_path: state.storage.path().display().to_string(),
            cases: readable.cases,
            selected_case,
            runtime: state.runtime_health(),
            artifact_cleanup_obligations: service.list_artifact_deletion_obligations()?,
            engine_count: state.engines.manifests().len(),
        },
        beginner_reports,
        engine_admission_issues: state.engines.admission_issues().to_vec(),
        case_recovery_diagnostics: readable.recovery_diagnostics,
    })
}

#[tauri::command]
pub fn detect_local_private_subnets() -> crate::target_candidates::LocalNetworkCandidateInventory {
    crate::target_candidates::detect_local_private_subnets()
}

#[tauri::command]
pub fn get_scan_readiness(case_id: String, state: State<'_, AppState>) -> AppResult<ScanReadiness> {
    let _ = state.request_runtime_health_refresh();
    let service = state.case_service();
    let mut readiness = service.scan_readiness(&case_id)?;
    if !readiness.ready {
        return Ok(readiness);
    }
    let plan = service.preview_scan_for_execution(&case_id, ScanPlanRequest::default())?;
    if let Err(error) = validate_provider_execution_demands(&state, &plan, Utc::now()) {
        block_scan_readiness(&mut readiness, error.blocker());
        return Ok(readiness);
    }
    if let Err(blocker) = validate_execution_inputs_static(&state, &plan) {
        block_scan_readiness(&mut readiness, blocker);
        return Ok(readiness);
    }
    // Runtime health is a nonblocking, cached shell observation. In
    // particular, the first observation is deliberately `checking` and must
    // not turn an otherwise valid Start action into a gate. Execution first
    // persists the requested work and then performs authoritative per-task
    // runtime preparation; unavailable engines report an honest partial or
    // failed outcome without erasing work that can still run.
    Ok(readiness)
}

#[tauri::command]
pub async fn preview_external_scanner_import(
    report_path: String,
) -> AppResult<crate::external_scanner_import::ExternalScannerImportPreview> {
    tauri::async_runtime::spawn_blocking(move || {
        crate::external_scanner_import::preview_external_scanner_import(std::path::Path::new(
            &report_path,
        ))
    })
    .await
    .map_err(|_| AppError::Internal("Report preview could not finish".into()))?
}

#[tauri::command]
pub fn import_external_scanner_reports(
    case_id: String,
    requests: Vec<crate::external_scanner_import::ExternalScannerImportRequest>,
    state: State<'_, AppState>,
) -> AppResult<AssessmentCase> {
    crate::external_scanner_import::import_external_scanner_reports(
        &state.storage,
        state.artifact_root(),
        &case_id,
        &requests,
    )
}

#[tauri::command]
pub fn create_case(
    request: CreateCaseRequest,
    state: State<'_, AppState>,
) -> AppResult<AssessmentCase> {
    state.case_service().create_case(&request)
}

#[tauri::command]
pub fn select_case(case_id: String, state: State<'_, AppState>) -> AppResult<AssessmentCase> {
    state.case_service().select_case(&case_id)
}

#[tauri::command]
pub fn archive_case(case_id: String, state: State<'_, AppState>) -> AppResult<AssessmentCase> {
    state.case_service().archive_case(&case_id)
}

#[tauri::command]
pub fn delete_case(
    case_id: String,
    confirmation: String,
    state: State<'_, AppState>,
) -> AppResult<CaseDeletionResult> {
    let service = state.case_service();
    let case = service.show_case(&case_id)?;
    if confirmation != case.title {
        return Err(AppError::NotAuthorized(
            "case deletion confirmation must exactly match the case title".into(),
        ));
    }
    service.validate_case_deletion(&case_id)?;
    if state
        .jobs
        .live_snapshots()
        .iter()
        .any(|job| job.key.case_id == case_id)
    {
        return Err(AppError::InvalidRequest(
            "Case deletion blocked: active scan has no terminal result.".into(),
        ));
    }
    if state.provider_discovery_jobs.is_active(&case_id)? {
        state.provider_discovery_jobs.cancel(&case_id)?;
        return Err(AppError::InvalidRequest(
            "Case deletion blocked: provider discovery cancellation is in progress.".into(),
        ));
    }
    state
        .provider_authorization_sessions
        .cancel_case(&case_id)?;
    state
        .source_authorizations
        .revoke_case(&case_id, Utc::now())?;
    state.model_endpoint_sessions.revoke_case(&case_id)?;
    service.delete_case(&case_id)
}

#[tauri::command]
pub fn delete_case_artifacts(
    case_id: String,
    exact_path: String,
    confirmation: String,
    state: State<'_, AppState>,
) -> AppResult<ArtifactDeletionResult> {
    state
        .case_service()
        .delete_case_artifacts(&case_id, &exact_path, &confirmation)
}

#[tauri::command]
pub fn connect_source_snapshot(
    case_id: Id,
    source_kind: SourceKind,
    label: String,
    profile: String,
    selected_path: String,
    app: AppHandle,
    state: State<'_, AppState>,
) -> AppResult<AssessmentCase> {
    if selected_path.trim().is_empty() {
        return Err(AppError::InvalidRequest(
            "an explicitly selected snapshot file is required".into(),
        ));
    }
    let service = state.case_service();
    let case = service.show_case(&case_id)?;
    if case.is_demo || case.status == CaseStatus::Archived {
        return Err(AppError::NotAuthorized(
            "demo or archived cases cannot ingest source snapshots".into(),
        ));
    }
    let connector_root = state.connector_artifact_root(&case_id)?;
    let registry = SnapshotConnectorRegistry::new(&connector_root)
        .map_err(|error| AppError::InvalidRequest(error.to_string()))?;
    let reference = registry
        .ingest_selected_snapshot(
            &source_kind,
            Path::new(&selected_path),
            &profile,
            Utc::now(),
        )
        .map_err(|error| AppError::InvalidRequest(error.to_string()))?;
    service.connect_snapshot_source(&case_id, source_kind, &label, reference)?;
    let case = service.show_case(&case_id)?;
    emit(&app, COVERAGE_CHANGED_EVENT, &case)?;
    Ok(case)
}

#[tauri::command]
pub fn begin_provider_authorization(
    request: BeginProviderAuthorizationRequest,
    state: State<'_, AppState>,
) -> AppResult<ProviderAuthorizationPrompt> {
    let case = state.case_service().show_case(&request.case_id)?;
    if case.is_demo || case.status == CaseStatus::Archived {
        return Err(AppError::NotAuthorized(
            "demo or archived cases cannot start provider authorization".into(),
        ));
    }
    let source = case
        .data_sources
        .iter()
        .find(|source| source.id == request.source_id)
        .ok_or_else(|| AppError::InvalidRequest("provider source does not exist".into()))?;
    let expected_kind = provider_authorization_source_kind(&request.authorization);
    if source.kind != expected_kind || !source.read_only {
        return Err(AppError::NotAuthorized(
            "provider authorization must bind an existing matching read-only source".into(),
        ));
    }
    let http = ReqwestProviderHttp::new()?;
    state
        .provider_authorization_sessions
        .begin(&http, request, Utc::now())
}

#[tauri::command]
pub fn poll_provider_authorization(
    session_id: String,
    app: AppHandle,
    state: State<'_, AppState>,
) -> AppResult<ProviderAuthorizationProgress> {
    let http = ReqwestProviderHttp::new()?;
    match state
        .provider_authorization_sessions
        .poll(&http, &session_id, Utc::now())?
    {
        ProviderSessionPoll::Pending {
            session_id,
            retry_after_seconds,
        } => Ok(ProviderAuthorizationProgress::Pending {
            session_id,
            retry_after_seconds,
        }),
        ProviderSessionPoll::Complete(request) => {
            let case_id = request.case_id.clone();
            let installed = install_verified_provider_authorization(&state, *request)?;
            let case = state.case_service().show_case(&case_id)?;
            emit(&app, COVERAGE_CHANGED_EVENT, &case)?;
            Ok(ProviderAuthorizationProgress::Installed {
                authorization: Box::new(installed),
            })
        }
    }
}

#[tauri::command]
pub fn cancel_provider_authorization(
    session_id: String,
    state: State<'_, AppState>,
) -> AppResult<bool> {
    state.provider_authorization_sessions.cancel(&session_id)
}

#[tauri::command]
pub fn provider_authorization_status(
    case_id: String,
    source_id: String,
    state: State<'_, AppState>,
) -> AppResult<Option<crate::source_authorization::InstalledSourceAuthorization>> {
    state
        .source_authorizations
        .status(&case_id, &source_id, Utc::now())
}

#[tauri::command]
pub fn revoke_provider_authorization(
    case_id: String,
    source_id: String,
    state: State<'_, AppState>,
) -> AppResult<crate::source_authorization::SourceAuthorizationRevocation> {
    state
        .source_authorizations
        .revoke_source(&case_id, &source_id, Utc::now())
}

fn provider_authorization_source_kind(config: &ProviderAuthorizationConfig) -> SourceKind {
    match config {
        ProviderAuthorizationConfig::Aws { .. } => SourceKind::AwsOrganization,
        ProviderAuthorizationConfig::Azure { .. } => SourceKind::AzureTenant,
        ProviderAuthorizationConfig::Gcp { .. } => SourceKind::GcpOrganization,
        ProviderAuthorizationConfig::Microsoft365 { .. } => SourceKind::Microsoft365Tenant,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExecuteProviderBootstrapInput {
    pub operation_id: String,
    pub execution: BootstrapExecutionRequest,
    pub source_id: String,
    pub allowed_engine_ids: BTreeSet<String>,
    pub max_checkouts: u16,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderBootstrapInstalled {
    pub operation_id: String,
    pub authorization: crate::source_authorization::InstalledSourceAuthorization,
    pub cleanup_ledger_path: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct BootstrapMessage {
    operation_id: String,
    message: String,
}

#[tauri::command]
pub fn plan_provider_bootstrap(request: BootstrapRequest) -> AppResult<BootstrapPlan> {
    create_bootstrap_plan(request, Utc::now())
}

#[tauri::command]
pub async fn execute_provider_bootstrap(
    input: ExecuteProviderBootstrapInput,
    app: AppHandle,
    state: State<'_, AppState>,
) -> AppResult<ProviderBootstrapInstalled> {
    validate_operation_id(&input.operation_id)?;
    let case_id = input.execution.bootstrap.case_id.clone();
    let case = state.case_service().show_case(&case_id)?;
    if case.is_demo || case.status == CaseStatus::Archived {
        return Err(AppError::NotAuthorized(
            "demo or archived cases cannot run provider bootstrap".into(),
        ));
    }
    let source = case
        .data_sources
        .iter()
        .find(|source| source.id == input.source_id)
        .cloned()
        .ok_or_else(|| AppError::InvalidRequest("provider source does not exist".into()))?;
    let (expected_kind, expected_profile) = match input.execution.bootstrap.provider {
        crate::bootstrap::BootstrapProvider::Aws => (
            SourceKind::AwsOrganization,
            ProviderSourceProfile::AwsOrganizationReadOnlySession,
        ),
        crate::bootstrap::BootstrapProvider::Azure => (
            SourceKind::AzureTenant,
            ProviderSourceProfile::AzureTenantReadOnlyAccessToken,
        ),
        crate::bootstrap::BootstrapProvider::Gcp => (
            SourceKind::GcpOrganization,
            ProviderSourceProfile::GcpOrganizationReadOnlyAccessToken,
        ),
        crate::bootstrap::BootstrapProvider::Microsoft365 => (
            SourceKind::Microsoft365Tenant,
            ProviderSourceProfile::Microsoft365TenantReadOnlyAccessToken,
        ),
    };
    if source.kind != expected_kind
        || !source.read_only
        || input.allowed_engine_ids.is_empty()
        || input.max_checkouts == 0
        || input.max_checkouts > expected_profile.max_checkouts()
    {
        return Err(AppError::NotAuthorized(
            "bootstrap must bind an existing matching read-only source and bounded engines".into(),
        ));
    }
    let cleanup_root = state.bootstrap_artifact_root(&case_id)?;
    let cleanup_path = bootstrap_cleanup_path(&cleanup_root, &input.operation_id)?;
    let broker = locate_bootstrap_broker_binary()?;
    let operation_id = input.operation_id.clone();
    let command = BootstrapBrokerCommand::Execute {
        execution: input.execution,
        cleanup_ledger_path: cleanup_path.display().to_string(),
    };
    let app_for_worker = app.clone();
    let operation_for_worker = operation_id.clone();
    let authorization = tauri::async_runtime::spawn_blocking(move || {
        run_bootstrap_broker_execute(&broker, &command, &operation_for_worker, &app_for_worker)
    })
    .await
    .map_err(|_| AppError::Internal("bootstrap worker terminated unexpectedly".into()))??;
    let verification = authorization.verification().clone();
    if verification.profile.source_kind() != source.kind {
        return Err(AppError::NotAuthorized(
            "bootstrap verification profile does not match its source".into(),
        ));
    }
    let mut allowed_engine_ids = input.allowed_engine_ids;
    allowed_engine_ids.insert(crate::source_authorization::PROVIDER_DISCOVERY_ENGINE_ID.into());
    let installed = install_verified_provider_authorization(
        &state,
        crate::source_authorization::SourceAuthorizationRequest {
            case_id: case_id.clone(),
            source_id: input.source_id.clone(),
            allowed_engine_ids,
            max_checkouts: input.max_checkouts,
            verified_authorization: authorization,
        },
    )?;
    let case = state.case_service().show_case(&case_id)?;
    emit(&app, COVERAGE_CHANGED_EVENT, &case)?;
    Ok(ProviderBootstrapInstalled {
        operation_id,
        authorization: installed,
        cleanup_ledger_path: cleanup_path.display().to_string(),
    })
}

#[tauri::command]
pub async fn cleanup_provider_bootstrap(
    case_id: String,
    operation_id: String,
    operator: BootstrapOperatorConfig,
    app: AppHandle,
    state: State<'_, AppState>,
) -> AppResult<BootstrapCleanupResult> {
    validate_operation_id(&operation_id)?;
    state.case_service().show_case(&case_id)?;
    let cleanup_root = state.bootstrap_artifact_root(&case_id)?;
    let cleanup_path = bootstrap_cleanup_path(&cleanup_root, &operation_id)?;
    let broker = locate_bootstrap_broker_binary()?;
    let command = BootstrapBrokerCommand::Cleanup {
        operator,
        case_id: case_id.clone(),
        operation_id: operation_id.clone(),
        cleanup_ledger_path: cleanup_path.display().to_string(),
    };
    let case_for_worker = case_id.clone();
    let operation_for_worker = operation_id.clone();
    let cleanup_path_for_worker = cleanup_path.clone();
    tauri::async_runtime::spawn_blocking(move || {
        run_bootstrap_broker_cleanup(
            &broker,
            &command,
            &case_for_worker,
            &operation_for_worker,
            &cleanup_path_for_worker,
            &app,
        )
    })
    .await
    .map_err(|_| AppError::Internal("bootstrap cleanup worker terminated unexpectedly".into()))?
}

#[tauri::command]
pub fn list_provider_bootstrap_cleanup(
    case_id: String,
    state: State<'_, AppState>,
) -> AppResult<Vec<BootstrapCleanupObligationSummary>> {
    state.case_service().show_case(&case_id)?;
    let cleanup_root = state.bootstrap_artifact_root(&case_id)?;
    list_bootstrap_cleanup_obligations(&cleanup_root, &case_id)
}

/// Installs a verified provider sign-in for its bound source and marks the
/// source connected. If the source cannot record the connection, the
/// capability installed a moment earlier is revoked.
fn install_verified_provider_authorization(
    state: &CoreState,
    request: crate::source_authorization::SourceAuthorizationRequest,
) -> AppResult<InstalledSourceAuthorization> {
    let case_id = request.case_id.clone();
    let source_id = request.source_id.clone();
    let verification = request.verified_authorization.verification().clone();
    let case = state.case_service().show_case(&case_id)?;
    let source = case
        .data_sources
        .iter()
        .find(|source| source.id == source_id)
        .ok_or_else(|| {
            AppError::InvalidRequest("provider source was removed during authorization".into())
        })?;
    if source.kind != verification.profile.source_kind() || !source.read_only {
        return Err(AppError::NotAuthorized(
            "verified provider profile no longer matches the bound source".into(),
        ));
    }
    let installed = state.source_authorizations.install_now(request)?;
    if let Err(error) =
        state
            .case_service()
            .connect_verified_provider_source(&case_id, &source_id, &verification)
    {
        let _ = state
            .source_authorizations
            .revoke_source(&case_id, &source_id, Utc::now());
        return Err(error);
    }
    Ok(installed)
}

fn validate_operation_id(value: &str) -> AppResult<()> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
    {
        return Err(AppError::InvalidRequest(
            "bootstrap operation ID is invalid".into(),
        ));
    }
    Ok(())
}

fn bootstrap_cleanup_path(root: &Path, operation_id: &str) -> AppResult<PathBuf> {
    validate_operation_id(operation_id)?;
    Ok(root.join(format!("cleanup-{operation_id}.json")))
}

fn locate_bootstrap_broker_binary() -> AppResult<PathBuf> {
    let current = std::env::current_exe()
        .map_err(|_| AppError::Runtime("desktop executable path could not be resolved".into()))?;
    let parent = current.parent().ok_or_else(|| {
        AppError::Runtime("desktop executable has no containing directory".into())
    })?;
    let name = if cfg!(windows) {
        "ai-security-scanner-bootstrap-broker.exe"
    } else {
        "ai-security-scanner-bootstrap-broker"
    };
    let candidate = parent.join(name);
    let metadata = std::fs::symlink_metadata(&candidate).map_err(|_| {
        AppError::NotAvailable(
            "the isolated bootstrap broker is not installed beside the desktop executable".into(),
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() == 0 {
        return Err(AppError::NotAuthorized(
            "the isolated bootstrap broker is not a regular non-symlink file".into(),
        ));
    }
    candidate.canonicalize().map_err(AppError::from)
}

fn spawn_bootstrap_broker(
    binary: &Path,
    command: &BootstrapBrokerCommand,
    operation_id: &str,
    app: &AppHandle,
) -> AppResult<(std::process::Child, std::thread::JoinHandle<()>)> {
    let mut child = ProcessCommand::new(binary)
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| AppError::NotAvailable("bootstrap broker could not start".into()))?;
    let encoded = serde_json::to_vec(command)
        .map_err(|_| AppError::Internal("bootstrap command could not be encoded".into()))?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| AppError::Internal("bootstrap broker stdin is unavailable".into()))?;
    stdin.write_all(&encoded)?;
    stdin.flush()?;
    drop(stdin);
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| AppError::Internal("bootstrap broker stderr is unavailable".into()))?;
    let operation_id = operation_id.to_owned();
    let app = app.clone();
    let reader = std::thread::spawn(move || {
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            if line.len() <= 4096 && !line.chars().any(char::is_control) {
                let _ = emit(
                    &app,
                    BOOTSTRAP_MESSAGE_EVENT,
                    &BootstrapMessage {
                        operation_id: operation_id.clone(),
                        message: line,
                    },
                );
            }
        }
    });
    Ok((child, reader))
}

fn run_bootstrap_broker_execute(
    binary: &Path,
    command: &BootstrapBrokerCommand,
    operation_id: &str,
    app: &AppHandle,
) -> AppResult<crate::source_authorization::VerifiedProviderAuthorization> {
    let (mut child, stderr_reader) = spawn_bootstrap_broker(binary, command, operation_id, app)?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| AppError::Internal("bootstrap broker stdout is unavailable".into()))?;
    let (authorization_sender, authorization_receiver) = mpsc::sync_channel(1);
    let authorization_reader = thread::spawn(move || {
        let result = crate::source_authorization::read_verified_authorization_one_shot(stdout);
        let _ = authorization_sender.send(result);
    });
    let status = wait_for_bootstrap_broker(&mut child, BOOTSTRAP_BROKER_DEADLINE)?;
    let authorization = authorization_receiver
        .recv_timeout(BOOTSTRAP_PIPE_DRAIN_DEADLINE)
        .map_err(|_| {
            AppError::NotAvailable(
                "isolated bootstrap broker did not close its authorization channel".into(),
            )
        })?;
    let _ = authorization_reader.join();
    let _ = stderr_reader.join();
    if !status.success() {
        return Err(AppError::NotAuthorized(
            "isolated bootstrap broker failed; partial cleanup items recorded".into(),
        ));
    }
    authorization
}

fn run_bootstrap_broker_cleanup(
    binary: &Path,
    command: &BootstrapBrokerCommand,
    case_id: &str,
    operation_id: &str,
    cleanup_path: &Path,
    app: &AppHandle,
) -> AppResult<BootstrapCleanupResult> {
    let (mut child, stderr_reader) = spawn_bootstrap_broker(binary, command, operation_id, app)?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| AppError::Internal("bootstrap broker stdout is unavailable".into()))?;
    let (output_sender, output_receiver) = mpsc::sync_channel(1);
    let output_reader = thread::spawn(move || {
        let mut encoded = Vec::new();
        let result = stdout
            .take(1024 * 1024 + 1)
            .read_to_end(&mut encoded)
            .map(|_| encoded);
        let _ = output_sender.send(result);
    });
    let status = wait_for_bootstrap_broker(&mut child, BOOTSTRAP_BROKER_DEADLINE)?;
    let encoded = output_receiver
        .recv_timeout(BOOTSTRAP_PIPE_DRAIN_DEADLINE)
        .map_err(|_| {
            AppError::NotAvailable(
                "isolated bootstrap broker did not close its cleanup result channel".into(),
            )
        })??;
    let _ = output_reader.join();
    let _ = stderr_reader.join();
    if !status.success() || encoded.len() > 1024 * 1024 {
        return Err(AppError::NotAuthorized(
            "isolated bootstrap cleanup failed; unresolved items recorded".into(),
        ));
    }
    let result: BootstrapCleanupResult = serde_json::from_slice(&encoded)
        .map_err(|_| AppError::Internal("bootstrap cleanup result is malformed".into()))?;
    let durable = bootstrap_cleanup_obligation_summary(cleanup_path, case_id, operation_id)?;
    if result.summary() != &durable {
        return Err(AppError::NotAuthorized(
            "isolated bootstrap cleanup result does not match its durable ledger".into(),
        ));
    }
    Ok(result)
}

fn wait_for_bootstrap_broker(child: &mut Child, timeout: StdDuration) -> AppResult<ExitStatus> {
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) => {}
            Err(_) => {
                terminate_bootstrap_broker_bounded(child);
                return Err(AppError::NotAvailable(
                    "isolated bootstrap broker status could not be verified; exact partial cleanup remains in its ledger"
                        .into(),
                ));
            }
        }
        if Instant::now() >= deadline {
            terminate_bootstrap_broker_bounded(child);
            return Err(AppError::NotAvailable(
                "isolated bootstrap broker exceeded its bounded authorization window; exact partial cleanup remains in its ledger"
                    .into(),
            ));
        }
        thread::sleep(StdDuration::from_millis(50));
    }
}

fn terminate_bootstrap_broker_bounded(child: &mut Child) {
    let _ = child.kill();
    let reap_deadline = Instant::now() + BOOTSTRAP_PIPE_DRAIN_DEADLINE;
    loop {
        match child.try_wait() {
            Ok(Some(_)) | Err(_) => return,
            Ok(None) if Instant::now() >= reap_deadline => return,
            Ok(None) => thread::sleep(StdDuration::from_millis(25)),
        }
    }
}

#[tauri::command]
pub fn attach_workspace_snapshot(
    case_id: Id,
    label: String,
    selected_path: String,
    input_profile: WorkspaceInputProfile,
    app: AppHandle,
    state: State<'_, AppState>,
) -> AppResult<AssessmentCase> {
    let selected_path = Path::new(&selected_path);
    if !selected_path.is_absolute() {
        return Err(AppError::InvalidRequest(
            "the working-tree selection must be an explicit absolute directory".into(),
        ));
    }
    let service = state.case_service();
    let case = service.show_case(&case_id)?;
    if case.is_demo || case.status == CaseStatus::Archived {
        return Err(AppError::NotAuthorized(
            "demo or archived cases cannot attach working-tree snapshots".into(),
        ));
    }
    let source_id = new_id();
    let snapshot = create_workspace_snapshot_with_profile(
        state.artifact_root(),
        &case_id,
        &source_id,
        selected_path,
        input_profile,
        WorkspaceSnapshotLimits::default(),
    )?;
    // Re-resolve through the persisted reference before it enters the case.
    // This exercises the same no-symlink/hash boundary used by execution.
    resolve_workspace_snapshot(state.artifact_root(), &case_id, &snapshot.reference)?;
    let case = service.attach_workspace_snapshot(&case_id, &label, snapshot)?;
    emit(&app, COVERAGE_CHANGED_EVENT, &case)?;
    Ok(case)
}

#[tauri::command]
pub fn refresh_workspace_snapshot(
    case_id: Id,
    asset_id: Id,
    selected_path: String,
    app: AppHandle,
    state: State<'_, AppState>,
) -> AppResult<AssessmentCase> {
    let selected_path = Path::new(&selected_path);
    if !selected_path.is_absolute() {
        return Err(AppError::InvalidRequest(
            "the working-tree selection must be an explicit absolute directory".into(),
        ));
    }
    let service = state.case_service();
    let case = service.show_case(&case_id)?;
    if case.is_demo || case.status == CaseStatus::Archived {
        return Err(AppError::NotAuthorized(
            "demo or archived cases cannot refresh working-tree snapshots".into(),
        ));
    }
    let (source_id, profile) = service.workspace_refresh_target(&case_id, &asset_id)?;
    let snapshot = create_workspace_snapshot_with_profile(
        state.artifact_root(),
        &case_id,
        &source_id,
        selected_path,
        profile,
        WorkspaceSnapshotLimits::default(),
    )?;
    // Re-resolve through the persisted reference before it enters the case.
    // This exercises the same no-symlink/hash boundary used by execution.
    resolve_workspace_snapshot(state.artifact_root(), &case_id, &snapshot.reference)?;
    let case = service.refresh_workspace_snapshot(&case_id, &asset_id, snapshot)?;
    emit(&app, COVERAGE_CHANGED_EVENT, &case)?;
    Ok(case)
}

#[tauri::command]
pub fn select_mcp_configuration(
    case_id: Id,
    asset_id: Id,
    relative_path: String,
    app: AppHandle,
    state: State<'_, AppState>,
) -> AppResult<AssessmentCase> {
    let case = state.case_service().show_case(&case_id)?;
    if case.is_demo || case.status == CaseStatus::Archived {
        return Err(AppError::NotAuthorized(
            "demo or archived cases cannot change MCP configuration selection".into(),
        ));
    }
    let asset = case
        .assets
        .iter()
        .find(|asset| asset.id == asset_id)
        .ok_or_else(|| AppError::InvalidRequest(format!("asset not found: {asset_id}")))?;
    let references = asset
        .discovered_from
        .iter()
        .filter_map(|source_id| {
            case.data_sources.iter().find(|source| {
                source.id == *source_id
                    && source.read_only
                    && source.status == SourceConnectionStatus::Connected
            })
        })
        .filter_map(|source| {
            source
                .metadata
                .get(WORKSPACE_SNAPSHOT_REFERENCE_METADATA_KEY)
        })
        .map(|value| {
            serde_json::from_value::<WorkspaceSnapshotReference>(value.clone()).map_err(|_| {
                AppError::InvalidRequest(
                    "workspace source has an invalid backend snapshot reference".into(),
                )
            })
        })
        .collect::<AppResult<Vec<_>>>()?;
    let [reference] = references.as_slice() else {
        return Err(AppError::NotAuthorized(
            "MCP configuration selection requires exactly one immutable repository snapshot".into(),
        ));
    };
    if asset
        .metadata
        .get("workspace_snapshot_sha256")
        .and_then(serde_json::Value::as_str)
        != Some(reference.sha256.as_str())
    {
        return Err(AppError::NotAuthorized(
            "workspace asset digest does not match its backend snapshot reference".into(),
        ));
    }
    let resolved = inspect_workspace_snapshot(state.artifact_root(), &case_id, reference)?;
    let updated = state.case_service().select_mcp_configuration(
        &case_id,
        &asset_id,
        &reference.sha256,
        &resolved.manifest,
        &relative_path,
    )?;
    emit(&app, COVERAGE_CHANGED_EVENT, &updated)?;
    Ok(updated)
}

#[tauri::command]
pub fn configure_model_endpoint(
    case_id: String,
    input: crate::garak_input::ModelEndpointInput,
    internet_exposed: bool,
    state: State<'_, AppState>,
    app: AppHandle,
) -> AppResult<AssessmentCase> {
    let updated =
        state
            .case_service()
            .configure_model_endpoint(&case_id, input, internet_exposed)?;
    emit(&app, COVERAGE_CHANGED_EVENT, &updated)?;
    Ok(updated)
}

#[tauri::command]
pub fn set_model_endpoint_key(
    case_id: String,
    asset_id: String,
    key: String,
    state: State<'_, AppState>,
) -> AppResult<()> {
    let key = zeroize::Zeroizing::new(key);
    let case = state.case_service().show_case(&case_id)?;
    if case.scan_runs.iter().any(|run| run.completed_at.is_none()) {
        return Err(AppError::InvalidRequest(
            "wait for the active scan before entering a new model key".into(),
        ));
    }
    let asset = case
        .assets
        .iter()
        .find(|a| a.id == asset_id)
        .ok_or_else(|| AppError::InvalidRequest("model asset not found".into()))?;
    state
        .model_endpoint_sessions
        .put(&case_id, asset, key, Utc::now())
}

#[tauri::command]
pub fn select_agentic_framework(
    case_id: Id,
    asset_id: Id,
    framework: Option<crate::agentic_radar_input::AgenticFramework>,
    app: AppHandle,
    state: State<'_, AppState>,
) -> AppResult<AssessmentCase> {
    let case = state.case_service().show_case(&case_id)?;
    if case.is_demo || case.status == CaseStatus::Archived {
        return Err(AppError::NotAuthorized(
            "demo or archived cases cannot change AI workflow framework selection".into(),
        ));
    }
    let asset = case
        .assets
        .iter()
        .find(|asset| asset.id == asset_id)
        .ok_or_else(|| AppError::InvalidRequest(format!("asset not found: {asset_id}")))?;
    let references = asset
        .discovered_from
        .iter()
        .filter_map(|source_id| {
            case.data_sources.iter().find(|source| {
                source.id == *source_id
                    && source.read_only
                    && source.status == SourceConnectionStatus::Connected
            })
        })
        .filter_map(|source| {
            source
                .metadata
                .get(WORKSPACE_SNAPSHOT_REFERENCE_METADATA_KEY)
        })
        .map(|value| {
            serde_json::from_value::<WorkspaceSnapshotReference>(value.clone()).map_err(|_| {
                AppError::InvalidRequest(
                    "workspace source has an invalid backend snapshot reference".into(),
                )
            })
        })
        .collect::<AppResult<Vec<_>>>()?;
    let [reference] = references.as_slice() else {
        return Err(AppError::NotAuthorized(
            "AI workflow framework selection requires exactly one immutable repository snapshot"
                .into(),
        ));
    };
    if asset
        .metadata
        .get("workspace_snapshot_sha256")
        .and_then(serde_json::Value::as_str)
        != Some(reference.sha256.as_str())
    {
        return Err(AppError::NotAuthorized(
            "workspace asset digest does not match its backend snapshot reference".into(),
        ));
    }
    inspect_workspace_snapshot(state.artifact_root(), &case_id, reference)?;
    let updated = state.case_service().select_agentic_framework(
        &case_id,
        &asset_id,
        &reference.sha256,
        framework,
    )?;
    emit(&app, COVERAGE_CHANGED_EVENT, &updated)?;
    Ok(updated)
}

#[tauri::command]
pub fn seed_demo_case(state: State<'_, AppState>) -> AppResult<AssessmentCase> {
    if let Some(summary) = state
        .case_service()
        .list_cases()?
        .into_iter()
        .find(|summary| summary.is_demo)
    {
        return state.case_service().select_case(&summary.id);
    }

    let mut case = build_demo_case();
    state.storage.save_case(&mut case, "case.demo_seeded")?;
    state.storage.set_selected_case(Some(&case.id))?;
    Ok(case)
}

#[tauri::command]
pub fn list_engine_manifests(state: State<'_, AppState>) -> Vec<EngineManifest> {
    state.engines.manifests().to_vec()
}

#[tauri::command]
pub fn list_engine_admission_issues(state: State<'_, AppState>) -> Vec<EngineAdmissionIssue> {
    state.engines.admission_issues().to_vec()
}

#[tauri::command]
pub async fn start_discovery(case_id: String, app: AppHandle) -> AppResult<AssessmentCase> {
    let cancelled = app
        .state::<AppState>()
        .provider_discovery_jobs
        .begin(&case_id)?;
    let worker_app = app.clone();
    let worker_case_id = case_id.clone();
    let joined = tauri::async_runtime::spawn_blocking(move || {
        let state = worker_app.state::<AppState>();
        perform_discovery(&worker_case_id, &state, cancelled.as_ref())
    })
    .await;
    let finish = app
        .state::<AppState>()
        .provider_discovery_jobs
        .finish(&case_id);
    let result = joined.map_err(|_| {
        AppError::Internal("provider discovery worker terminated unexpectedly".into())
    })?;
    finish?;
    if let Ok(case) = &result {
        emit(&app, COVERAGE_CHANGED_EVENT, case)?;
    }
    result
}

#[tauri::command]
pub fn cancel_discovery(case_id: String, state: State<'_, AppState>) -> AppResult<bool> {
    state.provider_discovery_jobs.cancel(&case_id)
}

fn perform_discovery(
    case_id: &str,
    state: &CoreState,
    cancelled: &std::sync::atomic::AtomicBool,
) -> AppResult<AssessmentCase> {
    let service = state.case_service();
    let case = service.show_case(case_id)?;
    if case.is_demo || case.status == CaseStatus::Archived {
        return Err(AppError::NotAuthorized(
            "demo or archived cases cannot run source discovery".into(),
        ));
    }
    let sources = case
        .data_sources
        .iter()
        .filter(|source| {
            source.status == SourceConnectionStatus::Connected
                && source.read_only
                && (source.metadata.contains_key(SNAPSHOT_ARTIFACT_METADATA_KEY)
                    || source.metadata.contains_key("provider_profile"))
        })
        .cloned()
        .collect::<Vec<_>>();
    if sources.is_empty() {
        return Err(AppError::InvalidRequest(
            "connect at least one read-only source snapshot or live provider authorization before discovery"
                .into(),
        ));
    }

    let connector_root = state.connector_artifact_root(case_id)?;
    let registry = SnapshotConnectorRegistry::new(&connector_root)
        .map_err(|error| AppError::Runtime(error.to_string()))?;
    for source in sources {
        if cancelled.load(std::sync::atomic::Ordering::Acquire) {
            break;
        }
        if source.metadata.contains_key(SNAPSHOT_ARTIFACT_METADATA_KEY)
            && !source.metadata.contains_key("provider_profile")
        {
            let connector = registry.connector_for(&source.kind);
            let batch = run_connector(&connector, &source)
                .map_err(|error| AppError::Runtime(error.to_string()))?;
            service.reconcile_discovery_batch(case_id, &batch)?;
            continue;
        }

        let profile = source
            .metadata
            .get("provider_profile")
            .cloned()
            .ok_or_else(|| {
                AppError::NotAuthorized(
                    "connected live provider source has no verified profile metadata".into(),
                )
            })
            .and_then(|value| {
                serde_json::from_value::<crate::source_authorization::ProviderSourceProfile>(value)
                    .map_err(|_| {
                        AppError::NotAuthorized(
                            "connected live provider source profile metadata is malformed".into(),
                        )
                    })
            })?;
        let authorization = match state.source_authorizations.status(
            case_id,
            &source.id,
            Utc::now(),
        )? {
            Some(authorization) => authorization,
            None => {
                service.record_live_provider_discovery_outcome(
                    case_id,
                    &source.id,
                    LiveProviderDiscoveryOutcome {
                        status: SourceConnectionStatus::NeedsReauthorization,
                        code: "provider_discovery_authorization_missing".into(),
                        message: "the process-memory provider capability is missing or expired; reconnect this source before live discovery".into(),
                        complete: false,
                        successful_pages: 0,
                        record_count: 0,
                        notices: vec!["Persisted source coordinates are not credentials and cannot be used after an application restart.".into()],
                        observed_at: Utc::now(),
                    },
                )?;
                continue;
            }
        };
        let persisted_identity = source
            .metadata
            .get("provider_identity")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        let persisted_proof = source
            .metadata
            .get("verification_evidence_sha256")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        let persisted_resource_scope = source
            .metadata
            .get(PROVIDER_RESOURCE_SCOPE_METADATA_KEY)
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        if authorization.case_id != case_id
            || authorization.source_id != source.id
            || authorization.source_kind != source.kind
            || authorization.profile != profile
            || authorization.provider_verification.profile != profile
            || authorization.provider_identity != persisted_identity
            || authorization.provider_verification.evidence_sha256 != persisted_proof
            || authorization.provider_verification.resource_scope != persisted_resource_scope
            || !authorization
                .allowed_engine_ids
                .contains(crate::source_authorization::PROVIDER_DISCOVERY_ENGINE_ID)
        {
            service.record_live_provider_discovery_outcome(
                case_id,
                &source.id,
                failed_live_outcome(
                    LiveProviderFailure {
                        kind: LiveProviderFailureKind::Authorization,
                        code: "provider_discovery_authorization_binding",
                        message: "live provider capability does not match the persisted source identity and verification proof".into(),
                    },
                    Utc::now(),
                    0,
                    0,
                    vec![],
                ),
            )?;
            continue;
        }

        let credentials = match state.source_authorizations.checkout_now(
            case_id,
            &source.id,
            crate::source_authorization::PROVIDER_DISCOVERY_ENGINE_ID,
        ) {
            Ok(credentials) => credentials,
            Err(_) => {
                service.record_live_provider_discovery_outcome(
                    case_id,
                    &source.id,
                    failed_live_outcome(
                        LiveProviderFailure {
                            kind: LiveProviderFailureKind::Authorization,
                            code: "provider_discovery_authorization_checkout",
                            message: "provider capability expired, was revoked, or exhausted before discovery".into(),
                        },
                        Utc::now(),
                        0,
                        0,
                        vec![],
                    ),
                )?;
                continue;
            }
        };
        let http = ReqwestProviderHttp::new_discovery()?;
        let mut persist = |_: &str,
                           _: u16,
                           bytes: &[u8],
                           parser_profile: &str,
                           observed_at: chrono::DateTime<Utc>| {
            registry
                .ingest_provider_response(&source.kind, bytes, parser_profile, observed_at)
                .map_err(|error| AppError::Storage(error.to_string()))
        };
        let mut capture = capture_provider_inventory(
            &http,
            &authorization,
            &credentials,
            cancelled,
            Utc::now(),
            &mut persist,
        );
        let observed_at = capture
            .artifact_set
            .as_ref()
            .map(|set| set.observed_at)
            .unwrap_or_else(Utc::now);
        if let Some(artifacts) = capture.artifact_set.clone() {
            service.attach_live_provider_capture(case_id, &source.id, artifacts)?;
        }

        let mut connector_notices = Vec::new();
        if capture.successful_pages > 0 && capture.artifact_set.is_some() {
            let refreshed = service.show_case(case_id)?;
            let captured_source = refreshed
                .data_sources
                .iter()
                .find(|candidate| candidate.id == source.id)
                .cloned()
                .ok_or_else(|| AppError::Internal("captured provider source disappeared".into()))?;
            let connector = registry.connector_for(&source.kind);
            match run_connector(&connector, &captured_source) {
                Ok(batch) => match service.reconcile_discovery_batch(case_id, &batch) {
                    Ok(report) => connector_notices.extend(report.notices),
                    Err(error) => {
                        capture.failure = Some(LiveProviderFailure {
                            kind: LiveProviderFailureKind::InvalidResponse,
                            code: "provider_discovery_reconciliation_failed",
                            message: format!(
                                "preserved provider inventory could not be reconciled: {}",
                                safe_diagnostic(&error.to_string())
                            ),
                        });
                    }
                },
                Err(error) => {
                    capture.failure = Some(LiveProviderFailure {
                        kind: LiveProviderFailureKind::InvalidResponse,
                        code: "provider_discovery_connector_failed",
                        message: format!(
                            "preserved provider response did not match its bounded connector profile: {}",
                            safe_diagnostic(&error.to_string())
                        ),
                    });
                }
            }
        }
        connector_notices.extend(capture.notices.clone());
        let outcome = if let Some(failure) = capture.failure {
            failed_live_outcome(
                failure,
                observed_at,
                capture.successful_pages,
                capture.record_count,
                connector_notices,
            )
        } else {
            LiveProviderDiscoveryOutcome {
                status: SourceConnectionStatus::Connected,
                code: "provider_discovery_complete".into(),
                message: format!(
                    "bounded live provider discovery completed with {} preserved successful page(s) and {} inventory record(s)",
                    capture.successful_pages, capture.record_count
                ),
                complete: true,
                successful_pages: capture.successful_pages,
                record_count: capture.record_count,
                notices: connector_notices,
                observed_at,
            }
        };
        service.record_live_provider_discovery_outcome(case_id, &source.id, outcome)?;
    }
    service.show_case(case_id)
}

fn failed_live_outcome(
    failure: LiveProviderFailure,
    observed_at: chrono::DateTime<Utc>,
    successful_pages: usize,
    record_count: usize,
    notices: Vec<String>,
) -> LiveProviderDiscoveryOutcome {
    LiveProviderDiscoveryOutcome {
        status: if failure.kind == LiveProviderFailureKind::Authorization {
            SourceConnectionStatus::NeedsReauthorization
        } else {
            SourceConnectionStatus::Failed
        },
        code: failure.code.into(),
        message: failure.message,
        complete: false,
        successful_pages,
        record_count,
        notices,
        observed_at,
    }
}

fn safe_diagnostic(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_control())
        .take(512)
        .collect()
}

#[tauri::command]
pub fn approve_scope(
    case_id: String,
    decisions: Vec<ScopeDecision>,
    app: AppHandle,
    state: State<'_, AppState>,
) -> AppResult<AssessmentCase> {
    if decisions.is_empty() {
        return Err(AppError::InvalidRequest(
            "at least one scope decision is required".into(),
        ));
    }
    let service = state.case_service();
    let expires_at = Utc::now() + Duration::days(30);
    service.approve_scopes(
        &case_id,
        decisions
            .into_iter()
            .map(|decision| ScopeApprovalRequest {
                asset_id: decision.asset_id,
                permissions: decision.permissions,
                confirmed_by: decision.confirmed_by,
                expires_at: Some(
                    if decision.external_scope.as_ref().is_some_and(|scope| {
                        scope.template_policy.profile_id.as_deref()
                            == Some(crate::garak_input::PROFILE_ID)
                    }) {
                        Utc::now() + Duration::minutes(30)
                    } else {
                        expires_at
                    },
                ),
                authorization_reference: decision.authorization_reference,
                notes: decision.notes,
                external_scope: decision.external_scope,
            })
            .collect(),
    )?;
    let case = service.show_case(&case_id)?;
    emit(&app, COVERAGE_CHANGED_EVENT, &case)?;
    Ok(case)
}

#[tauri::command]
pub fn update_finding_workflow(
    case_id: String,
    request: FindingWorkflowRequest,
    app: AppHandle,
    state: State<'_, AppState>,
) -> AppResult<AssessmentCase> {
    let case = state
        .case_service()
        .update_finding_workflow(&case_id, request)?;
    emit(&app, COVERAGE_CHANGED_EVENT, &case)?;
    Ok(case)
}

/// Proposes which findings from different engines describe one issue.
///
/// Read-only by construction: it takes no request body, saves nothing, and
/// emits no event. Acting on a suggestion is a separate, explicit
/// `group_findings` call the user makes.
#[tauri::command]
pub fn suggest_finding_correlations(
    case_id: String,
    state: State<'_, AppState>,
) -> AppResult<CorrelationReport> {
    let case = state.case_service().show_case(&case_id)?;
    Ok(correlation_report(&case))
}

#[tauri::command]
pub fn group_findings(
    case_id: String,
    request: FindingGroupRequest,
    app: AppHandle,
    state: State<'_, AppState>,
) -> AppResult<AssessmentCase> {
    let case = state.case_service().group_findings(&case_id, request)?;
    emit(&app, COVERAGE_CHANGED_EVENT, &case)?;
    Ok(case)
}

#[tauri::command]
pub fn ungroup_findings(
    case_id: String,
    request: FindingUngroupRequest,
    app: AppHandle,
    state: State<'_, AppState>,
) -> AppResult<AssessmentCase> {
    let case = state.case_service().ungroup_findings(&case_id, request)?;
    emit(&app, COVERAGE_CHANGED_EVENT, &case)?;
    Ok(case)
}

#[tauri::command]
pub async fn start_scan(
    case_id: String,
    decisions: Option<Vec<ScopeDecision>>,
    engine_ids: Option<Vec<String>>,
    engine_asset_routes: Option<Vec<EngineAssetRoute>>,
    campaign_id: Option<String>,
    app: AppHandle,
) -> AppResult<AssessmentCase> {
    let expires_at = Utc::now() + Duration::days(30);
    desktop_scan_coordinator(&app)
        .start_scan(
            &case_id,
            decisions
                .unwrap_or_default()
                .into_iter()
                .map(|decision| ScopeApprovalRequest {
                    asset_id: decision.asset_id,
                    permissions: decision.permissions,
                    confirmed_by: decision.confirmed_by,
                    expires_at: Some(
                        if decision.external_scope.as_ref().is_some_and(|scope| {
                            scope.template_policy.profile_id.as_deref()
                                == Some(crate::garak_input::PROFILE_ID)
                        }) {
                            Utc::now() + Duration::minutes(30)
                        } else {
                            expires_at
                        },
                    ),
                    authorization_reference: decision.authorization_reference,
                    notes: decision.notes,
                    external_scope: decision.external_scope,
                })
                .collect(),
            ScanPlanRequest {
                campaign_id,
                engine_ids: engine_ids.unwrap_or_default(),
                engine_asset_routes: engine_asset_routes.unwrap_or_default(),
            },
        )
        .map(|admission| admission.case)
}

fn snapshot_localhost_quick_scan(
    state: &CoreState,
    snapshot: &JobSnapshot,
) -> Option<crate::localhost_quick_scan::PreparedLocalhostQuickScan> {
    let (_, prepared) = localhost_quick_scan_for_snapshot(&state.storage, snapshot)
        .ok()
        .flatten()?;
    Some(prepared)
}

/// This connection utility is deliberately independent of the managed runtime
/// and catalog engines. Preparation and JobManager admission share one short
/// boundary; the detached worker owns the only bounded, payload-free contact.
#[tauri::command]
pub async fn start_localhost_quick_scan(port: u16, app: AppHandle) -> AppResult<AssessmentCase> {
    let state = app.state::<AppState>();
    state.jobs.coordinate_admission(|| {
        if let Some(case) =
            live_localhost_quick_scan_for_port(&state.storage, &state.jobs.live_snapshots(), port)
        {
            return Ok(case);
        }
        // A retained result from an older localhost run needs durable
        // reconciliation, but it must never turn a new user action into a
        // replay of that old case. Reconcile it in the background and admit a
        // newly persisted task below.
        for snapshot in state
            .jobs
            .terminal_snapshots()
            .into_iter()
            .filter(|snapshot| snapshot_localhost_quick_scan(&state, snapshot).is_some())
        {
            schedule_exact_terminal_reconciliation(&app, snapshot.key.clone(), snapshot);
        }

        let prepared =
            prepare_localhost_quick_scan(&state.storage, state.engines.manifests(), port)?;
        let queued_case = prepared.case;
        let exact_task = prepared.prepared;
        let key = JobKey::new(exact_task.case_id.clone(), exact_task.scan_run_id.clone())
            .map_err(|error| AppError::InvalidRequest(error.to_string()))?;
        let worker_task = exact_task.clone();
        let worker_app = app.clone();
        let terminal_key = key.clone();
        let terminal_app = app.clone();
        if let Err(error) = state.jobs.start_job(
            key,
            [exact_task.engine_run_id.clone()],
            move |context| {
                let state = worker_app.state::<AppState>();
                execute_managed_localhost_quick_scan(
                    &state.storage,
                    state.engines.manifests(),
                    &worker_task,
                    &DesktopHostTcpConnector,
                    &context,
                )
            },
            move |snapshot| {
                if let Err(error) = reconcile_terminal_job(&desktop_scan_coordinator(&terminal_app), &terminal_key, &snapshot)
                {
                    tracing::error!(
                        error = %error,
                        case_id = %terminal_key.case_id,
                        scan_run_id = %terminal_key.scan_run_id,
                        "localhost terminal outcome is waiting for background reconciliation"
                    );
                }
            },
        ) {
            tracing::error!(
                error = %error,
                case_id = %exact_task.case_id,
                scan_run_id = %exact_task.scan_run_id,
                "localhost worker thread could not be admitted"
            );
            return reconcile_interrupted_localhost_quick_scan(
                &state.storage,
                state.engines.manifests(),
                &exact_task,
            );
        }

        if let Err(error) = emit(&app, RUN_PROGRESS_EVENT, &queued_case) {
            tracing::warn!(error = %error, "queued local connection test event could not be emitted");
        }
        Ok(queued_case)
    })
}

#[tauri::command]
pub fn pause_scan(
    case_id: String,
    run_id: Option<String>,
    app: AppHandle,
    state: State<'_, AppState>,
) -> AppResult<AssessmentCase> {
    let service = state.case_service();
    let run_id = requested_or_latest_run(&service, &case_id, run_id.as_deref())?;
    let durable = service.show_case(&case_id)?;
    if durable
        .scan_runs
        .iter()
        .find(|run| run.id == run_id)
        .is_some_and(run_is_exact_localhost_quick_scan)
    {
        return Err(AppError::NotAvailable(
            "the fixed three-second local connection test cannot be paused".into(),
        ));
    }
    let key = JobKey::new(case_id.clone(), run_id.clone())
        .map_err(|error| AppError::InvalidRequest(error.to_string()))?;
    let case = state
        .jobs
        .pause_with_durable_transition(&key, || service.pause_scan(&case_id, &run_id))
        .map_err(|error| {
            AppError::NotAvailable(format!(
                "the scan has no live local worker to pause: {error}"
            ))
        })??;
    emit(&app, RUN_PROGRESS_EVENT, &case)?;
    Ok(case)
}

#[tauri::command]
pub async fn resume_scan(
    case_id: String,
    run_id: Option<String>,
    app: AppHandle,
) -> AppResult<AssessmentCase> {
    let state = app.state::<AppState>();
    let run_id = requested_or_latest_run(&state.case_service(), &case_id, run_id.as_deref())?;
    let durable = state.case_service().show_case(&case_id)?;
    if durable
        .scan_runs
        .iter()
        .find(|run| run.id == run_id)
        .is_some_and(run_is_exact_localhost_quick_scan)
    {
        return Err(AppError::NotAvailable(
            "the fixed three-second local connection test cannot be resumed; start a new test after it finishes"
                .into(),
        ));
    }
    let key = JobKey::new(case_id.clone(), run_id.clone())
        .map_err(|error| AppError::InvalidRequest(error.to_string()))?;

    // Exact terminal persistence can include bounded provider cleanup. Keep
    // that work detached from Resume: the retained generation itself prevents
    // a same-key retry until its callback/background owner saves the report.
    if let Some(snapshot) = state.jobs.snapshot(&key)
        && snapshot.is_terminal()
    {
        schedule_exact_terminal_reconciliation(&app, key.clone(), snapshot);
        let case = state.case_service().show_case(&case_id)?;
        let _ = emit(&app, RUN_PROGRESS_EVENT, &case);
        return Ok(case);
    }

    state.jobs.coordinate_admission(|| {
        if let Some(snapshot) = state.jobs.snapshot(&key) {
            if !snapshot.is_terminal() {
                let service = state.case_service();
                let case = state
                    .jobs
                    .resume_with_durable_transition(&key, || service.resume_scan(&case_id, &run_id))
                    .map_err(|error| {
                        AppError::Runtime(format!(
                            "live scan resume could not be signalled: {error}"
                        ))
                    })??;
                emit(&app, RUN_PROGRESS_EVENT, &case)?;
                return Ok(case);
            }
            // The worker became terminal after the out-of-lock check. Keep
            // its current durable truth and let the callback/background owner
            // finish reconciliation; never queue a retry while the retained
            // exact generation still closes same-key admission.
            schedule_exact_terminal_reconciliation(&app, key.clone(), snapshot);
            let case = state.case_service().show_case(&case_id)?;
            let _ = emit(&app, RUN_PROGRESS_EVENT, &case);
            return Ok(case);
        }
        let plan = state
            .case_service()
            .persist_resume_before_execution_preflight(&case_id, &run_id);
        match plan {
            Ok(plan) => {
                let needs_cleanup = durable_run_needs_background_cleanup(&plan.scan_run);
                // Start valid sibling work first. Exact target-free cleanup is
                // detached so slow or temporarily unavailable local runtime
                // housekeeping can never strand the persisted plan in Queued.
                let started = start_persisted_scan_job(&desktop_scan_coordinator(&app), plan);
                if needs_cleanup {
                    schedule_exact_runtime_cleanup_reconciliation(
                        &app,
                        case_id.clone(),
                        run_id.clone(),
                    );
                }
                started
            }
            Err(error) => {
                let Ok(case) = state.case_service().show_case(&case_id) else {
                    return Err(error);
                };
                let needs_cleanup = case
                    .scan_runs
                    .iter()
                    .find(|run| run.id == run_id)
                    .is_some_and(durable_run_needs_background_cleanup);
                if !needs_cleanup {
                    return Err(error);
                }
                schedule_exact_runtime_cleanup_reconciliation(
                    &app,
                    case_id.clone(),
                    run_id.clone(),
                );
                let _ = emit(&app, RUN_PROGRESS_EVENT, &case);
                tracing::info!(
                    case_id = %case_id,
                    scan_run_id = %run_id,
                    resume_error = %error,
                    "resume scheduled bounded runtime reconciliation without runnable scanner work"
                );
                Ok(case)
            }
        }
    })
}

#[derive(Serialize)]
pub struct CancelScanResponse {
    #[serde(flatten)]
    case: AssessmentCase,
    /// Process-local acknowledgement, never persisted as a finished scan.
    cancel_requested_run_id: Option<Id>,
}

fn live_cancel_request_run_id(
    case: &AssessmentCase,
    requested: Option<&str>,
    jobs: &crate::job_manager::JobManager,
) -> Option<Id> {
    let run_id = requested
        .filter(|id| !id.trim().is_empty())
        .or_else(|| case.scan_runs.last().map(|run| run.id.as_str()))?;
    case.scan_runs.iter().find(|run| run.id == run_id)?;
    let key = JobKey::new(&case.id, run_id).ok()?;
    let snapshot = jobs.snapshot(&key)?;
    matches!(
        snapshot.status,
        crate::job_manager::JobStatus::CancelRequested | crate::job_manager::JobStatus::Cancelled
    )
    .then(|| run_id.to_owned())
}

#[tauri::command]
pub fn cancel_scan(
    case_id: String,
    run_id: Option<String>,
    app: AppHandle,
    state: State<'_, AppState>,
) -> AppResult<CancelScanResponse> {
    let case = crate::scan_coordinator::cancel_scan_case(
        case_id,
        run_id.clone(),
        desktop_scan_coordinator(&app),
        &state,
    )?;
    let cancel_requested_run_id =
        live_cancel_request_run_id(&case, run_id.as_deref(), &app.state::<AppState>().jobs);
    Ok(CancelScanResponse {
        case,
        cancel_requested_run_id,
    })
}

#[tauri::command]
pub async fn start_rescan(
    case_id: String,
    baseline_run_id: String,
    engine_ids: Option<Vec<String>>,
    engine_asset_routes: Option<Vec<EngineAssetRoute>>,
    app: AppHandle,
) -> AppResult<AssessmentCase> {
    let state = app.state::<AppState>();
    state.jobs.coordinate_admission(|| {
        let rescan = state
            .case_service()
            .persist_rescan_before_execution_preflight(
                &case_id,
                &baseline_run_id,
                ScanPlanRequest {
                    campaign_id: None,
                    engine_ids: engine_ids.unwrap_or_default(),
                    engine_asset_routes: engine_asset_routes.unwrap_or_default(),
                },
            )?;
        start_persisted_scan_job(&desktop_scan_coordinator(&app), rescan.plan)
    })
}

#[tauri::command]
pub fn preview_export(
    input: PreviewExportInput,
    state: State<'_, AppState>,
) -> AppResult<ExportPreview> {
    let service = state.case_service();
    service.preview_export(
        &input.case_id,
        &input.run_id,
        input.format,
        &ExportOptions {
            redaction: if input.redact_sensitive_values {
                RedactionProfile::Standard
            } else {
                RedactionProfile::None
            },
            include_raw_artifacts: input.include_raw_evidence,
            locale: input.locale,
        },
    )
}

#[tauri::command]
pub fn export_case(
    input: ExportCaseInput,
    app: AppHandle,
    state: State<'_, AppState>,
) -> AppResult<CaseExport> {
    if input.destination.trim().is_empty() {
        return Err(AppError::InvalidRequest(
            "an explicit export destination is required".into(),
        ));
    }
    let service = state.case_service();
    let options = ExportOptions {
        redaction: if input.redact_sensitive_values {
            RedactionProfile::Standard
        } else {
            RedactionProfile::None
        },
        include_raw_artifacts: input.include_raw_evidence,
        locale: input.locale,
    };
    emit(&app, EXPORT_PROGRESS_EVENT, &"preparing")?;
    let exported = service.export_case(
        &input.case_id,
        &input.run_id,
        input.format,
        Path::new(&input.destination),
        options,
    )?;
    emit(&app, EXPORT_PROGRESS_EVENT, &"completed")?;
    Ok(exported)
}

#[tauri::command]
pub async fn export_selected_run_report(
    input: ExportSelectedRunsInput,
    state: State<'_, AppState>,
) -> AppResult<crate::selected_run_report::SelectedRunReportExport> {
    if input.destination.trim().is_empty() {
        return Err(AppError::InvalidRequest(
            "an explicit export destination is required".into(),
        ));
    }
    if input.include_raw_artifacts && !input.acknowledge_sensitive_raw_artifacts {
        return Err(AppError::InvalidRequest(
            "original attachments require explicit acknowledgement".into(),
        ));
    }
    let state = Arc::clone(state.inner());
    tauri::async_runtime::spawn_blocking(move || {
        state.case_service().export_selected_runs_with_archive(
            &input.case_id,
            &input.run_ids,
            input.format,
            Path::new(&input.destination),
            ExportOptions {
                redaction: if input.redact_sensitive_values {
                    RedactionProfile::Standard
                } else {
                    RedactionProfile::None
                },
                include_raw_artifacts: input.include_raw_artifacts,
                locale: input.locale,
            },
            input.acknowledge_sensitive_data,
        )
    })
    .await
    .map_err(|_| AppError::Internal("Combined report export could not finish".into()))?
}

#[tauri::command]
pub fn verify_case_export(
    path: String,
    state: State<'_, AppState>,
) -> AppResult<IntegrityResponse> {
    if path.trim().is_empty() {
        return Err(AppError::InvalidRequest("export path is required".into()));
    }
    let service = state.case_service();
    for summary in service.list_cases()? {
        let case = service.show_case(&summary.id)?;
        if let Some(export) = case.exports.iter().find(|export| export.path == path) {
            let verification = service.verify_stored_export(&case.id, &export.id)?;
            return Ok(IntegrityResponse {
                accepted: verification.valid,
                message: if verification.valid {
                    format!(
                        "Integrity verification passed for SHA-256 {}. This establishes file integrity only, not audit or forensic validity.",
                        verification.observed_sha256
                    )
                } else {
                    "Integrity verification failed.".into()
                },
            });
        }
    }
    let verification = verify_case_bundle(Path::new(&path))?;
    Ok(IntegrityResponse {
        accepted: verification.valid,
        message: format!(
            "Portable bundle signature and all manifest entry hashes passed for SHA-256 {} (signer key ID {}; {} raw artifact file(s) included). The embedded key is self-asserted unless independently pinned. This establishes package integrity only, not audit or forensic validity.",
            verification.archive_sha256,
            verification.signer_key_id,
            verification.raw_artifacts_included,
        ),
    })
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProductEventEnvelope<T> {
    schema_version: &'static str,
    event_type: String,
    occurred_at: String,
    payload: T,
}

struct DesktopScanEvents(AppHandle);

impl ScanEventSink for DesktopScanEvents {
    fn emit(&self, kind: ScanEventKind, case: &AssessmentCase) -> AppResult<()> {
        let name = match kind {
            ScanEventKind::Progress => RUN_PROGRESS_EVENT,
            ScanEventKind::Finished => RUN_FINISHED_EVENT,
        };
        emit(&self.0, name, case)
    }
}

fn desktop_scan_coordinator(app: &AppHandle) -> ScanCoordinator {
    ScanCoordinator::new(
        Arc::clone(app.state::<AppState>().inner()),
        Arc::new(DesktopScanEvents(app.clone())),
    )
}

fn emit<T: Serialize + Clone>(app: &AppHandle, event: &str, payload: &T) -> AppResult<()> {
    app.emit(
        event,
        ProductEventEnvelope {
            schema_version: "1.0.0",
            event_type: event.to_owned(),
            occurred_at: Utc::now().to_rfc3339(),
            payload: payload.clone(),
        },
    )
    .map_err(|error| AppError::Internal(format!("event {event} could not be emitted: {error}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::case_service::LiveProviderDiscoveryOutcome;
    use crate::job_manager::JobCompletion;
    use crate::scan_coordinator::tests::create_test_case;
    use crate::scan_coordinator::tests::{
        ready_aws_state, ready_repository_state, test_state, verified_aws_authorization_for_account,
    };
    use crate::source_authorization::SourceAuthorizationRequest;
    #[test]
    fn product_events_use_a_versioned_consistent_envelope() {
        let value = serde_json::to_value(ProductEventEnvelope {
            schema_version: "1.0.0",
            event_type: RUN_PROGRESS_EVENT.into(),
            occurred_at: "2026-08-24T12:00:00Z".into(),
            payload: serde_json::json!({ "case_id": "case-1" }),
        })
        .unwrap();
        assert_eq!(value["schemaVersion"], "1.0.0");
        assert_eq!(value["eventType"], RUN_PROGRESS_EVENT);
        assert_eq!(value["occurredAt"], "2026-08-24T12:00:00Z");
        assert_eq!(value["payload"]["case_id"], "case-1");
    }

    #[test]
    fn export_commands_require_and_preserve_an_explicit_run_id() {
        let preview: PreviewExportInput = serde_json::from_value(serde_json::json!({
            "caseId": "case-1",
            "runId": "run-history",
            "locale": "zh-Hant",
            "format": "html",
            "includeRawEvidence": false,
            "redactSensitiveValues": true
        }))
        .unwrap();
        assert_eq!(preview.run_id, "run-history");
        assert_eq!(preview.locale, ReportLocale::ZhHant);

        let exported: ExportCaseInput = serde_json::from_value(serde_json::json!({
            "caseId": "case-1",
            "runId": "run-history",
            "locale": "zh-Hant",
            "format": "html",
            "includeRawEvidence": false,
            "redactSensitiveValues": true,
            "destination": "C:\\\\Users\\\\example\\\\report.html"
        }))
        .unwrap();
        assert_eq!(exported.run_id, "run-history");
        assert_eq!(exported.locale, ReportLocale::ZhHant);

        assert!(
            serde_json::from_value::<PreviewExportInput>(serde_json::json!({
                "caseId": "case-1",
                "runId": "run-history",
                "locale": "fr",
                "format": "html"
            }))
            .is_err()
        );

        assert!(
            serde_json::from_value::<PreviewExportInput>(serde_json::json!({
                "caseId": "case-1",
                "runId": "run-history",
                "format": "html"
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<PreviewExportInput>(serde_json::json!({
                "caseId": "case-1",
                "format": "html"
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<ExportCaseInput>(serde_json::json!({
                "caseId": "case-1",
                "format": "html",
                "destination": "report.html"
            }))
            .is_err()
        );
    }

    #[test]
    fn rejected_packaged_runtime_cannot_create_or_reset_a_setup_operation() {
        use crate::managed_runtime::{
            ManagedRuntimeSetupFailureReason, ManagedRuntimeSetupPhase,
            PackagedManagedRuntimeAdmission,
        };

        for (admission, expected_reason) in [
            (
                PackagedManagedRuntimeAdmission::Missing,
                ManagedRuntimeSetupFailureReason::PackagedRuntimeMissing,
            ),
            (
                PackagedManagedRuntimeAdmission::VerificationFailed,
                ManagedRuntimeSetupFailureReason::PackagedRuntimeVerificationFailed,
            ),
            (
                PackagedManagedRuntimeAdmission::UnpackagedDeveloperBuild,
                ManagedRuntimeSetupFailureReason::DeveloperBuildWithoutPackagedRuntime,
            ),
            (
                PackagedManagedRuntimeAdmission::UnpackagedDeveloperBuildVerificationFailed,
                ManagedRuntimeSetupFailureReason::DeveloperBuildPackagedRuntimeVerificationFailed,
            ),
        ] {
            let (_directory, state) = test_state();
            let state = state.with_packaged_managed_runtime_admission(admission);
            let before = state
                .managed_runtime_setup()
                .status()
                .expect("terminal setup status");

            let error = ensure_verified_managed_runtime_for_setup(&state)
                .expect_err("rejected package cannot start setup");
            assert!(matches!(error, AppError::NotAvailable(_)));

            let after = state
                .managed_runtime_setup()
                .status()
                .expect("stable terminal setup status");
            assert_eq!(after, before);
            assert_eq!(after.phase, ManagedRuntimeSetupPhase::Failed);
            assert_eq!(after.failure_reason, Some(expected_reason));
            assert!(after.operation_id.is_none());
            assert!(!after.active);
            assert!(!after.can_retry);
            assert!(!after.can_cancel);
            assert!(after.next_action.is_none());
        }
    }

    #[test]
    fn cancel_response_acknowledges_only_the_exact_live_job_without_rewriting_saved_state() {
        let (_directory, state, case_id) = ready_repository_state();
        let service = state.case_service();
        let plan = service
            .persist_scan_before_execution_preflight(
                &case_id,
                ScanPlanRequest {
                    campaign_id: None,
                    engine_ids: vec!["gitleaks".into()],
                    engine_asset_routes: Vec::new(),
                },
            )
            .unwrap();
        let case = service.show_case(&case_id).unwrap();
        let run_id = plan.scan_run.id;
        let saved = serde_json::to_value(&case).unwrap();
        let key = JobKey::new(&case_id, &run_id).unwrap();
        let manager = crate::job_manager::JobManager::default();
        assert_eq!(
            live_cancel_request_run_id(&case, Some(&run_id), &manager),
            None
        );
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let (terminal_tx, terminal_rx) = std::sync::mpsc::channel();
        manager
            .start_job(
                key.clone(),
                ["gitleaks"],
                move |context| {
                    release_rx.recv().unwrap();
                    context
                        .engine("gitleaks")
                        .unwrap()
                        .mark_cancelled()
                        .unwrap();
                    JobCompletion::Cancelled
                },
                move |snapshot| terminal_tx.send(snapshot).unwrap(),
            )
            .unwrap();
        assert_eq!(
            live_cancel_request_run_id(&case, Some(&run_id), &manager),
            None
        );
        manager.cancel(&key).unwrap();
        assert_eq!(
            live_cancel_request_run_id(&case, None, &manager),
            Some(run_id.clone())
        );
        assert_eq!(
            live_cancel_request_run_id(&case, Some("another-run"), &manager),
            None
        );
        let mut other_case = case.clone();
        other_case.id = "another-case".into();
        assert_eq!(
            live_cancel_request_run_id(&other_case, Some(&run_id), &manager),
            None
        );
        let mut missing_run = case.clone();
        missing_run.scan_runs.clear();
        assert_eq!(
            live_cancel_request_run_id(&missing_run, Some(&run_id), &manager),
            None
        );
        let response = CancelScanResponse {
            cancel_requested_run_id: live_cancel_request_run_id(&case, Some(&run_id), &manager),
            case,
        };
        let mut encoded = serde_json::to_value(response).unwrap();
        assert_eq!(
            encoded
                .as_object_mut()
                .unwrap()
                .remove("cancel_requested_run_id"),
            Some(serde_json::json!(run_id))
        );
        assert_eq!(
            encoded, saved,
            "acknowledgement preserves the existing case response shape"
        );
        assert_eq!(
            serde_json::to_value(service.show_case(&case_id).unwrap()).unwrap(),
            saved
        );
        release_tx.send(()).unwrap();
        assert_eq!(
            terminal_rx
                .recv_timeout(StdDuration::from_secs(2))
                .unwrap()
                .status,
            crate::job_manager::JobStatus::Cancelled
        );
        let case = service.show_case(&case_id).unwrap();
        assert_eq!(
            live_cancel_request_run_id(&case, Some(&run_id), &manager),
            Some(run_id)
        );
    }

    #[test]
    fn signing_in_again_after_the_capability_expired_reconnects_the_source() {
        let (_directory, state, case_id, source_id) = ready_aws_state(Utc::now(), 4);
        state
            .case_service()
            .record_live_provider_discovery_outcome(
                &case_id,
                &source_id,
                LiveProviderDiscoveryOutcome {
                    status: SourceConnectionStatus::NeedsReauthorization,
                    code: "provider_discovery_authorization_missing".into(),
                    message: "reconnect this source before live discovery".into(),
                    complete: false,
                    successful_pages: 0,
                    record_count: 0,
                    notices: vec![],
                    observed_at: Utc::now(),
                },
            )
            .unwrap();

        let installed = install_verified_provider_authorization(
            &state,
            SourceAuthorizationRequest {
                case_id: case_id.clone(),
                source_id: source_id.clone(),
                allowed_engine_ids: BTreeSet::from([
                    "steampipe".into(),
                    crate::source_authorization::PROVIDER_DISCOVERY_ENGINE_ID.into(),
                ]),
                max_checkouts: 4,
                verified_authorization: verified_aws_authorization_for_account(
                    Utc::now(),
                    "111122223333",
                    "b",
                ),
            },
        )
        .unwrap();

        assert_eq!(
            installed.provider_verification.evidence_sha256,
            "b".repeat(64)
        );
        let source = state
            .case_service()
            .show_case(&case_id)
            .unwrap()
            .data_sources
            .into_iter()
            .find(|source| source.id == source_id)
            .unwrap();
        assert_eq!(source.status, SourceConnectionStatus::Connected);
        assert_eq!(
            source.metadata["verification_evidence_sha256"],
            serde_json::Value::String("b".repeat(64))
        );
        assert!(
            source
                .metadata
                .contains_key("ai_security_scanner.live_discovery_outcome")
        );
        assert!(
            state
                .source_authorizations
                .status(&case_id, &source_id, Utc::now())
                .unwrap()
                .is_some()
        );
    }
    #[test]
    fn startup_isolates_an_unreadable_selected_case_and_recovers_healthy_siblings() {
        let (_directory, state, healthy_case_id) = ready_repository_state();
        state
            .case_service()
            .plan_scan(
                &healthy_case_id,
                ScanPlanRequest {
                    campaign_id: None,
                    engine_ids: vec!["gitleaks".into()],
                    engine_asset_routes: Vec::new(),
                },
            )
            .expect("persist interrupted healthy scan");
        let unreadable = create_test_case(&state, "Unreadable selected project");
        let preserved_bytes = "{preserved malformed project bytes";
        let database = rusqlite::Connection::open(state.storage.path()).expect("open fixture db");
        database
            .execute(
                "UPDATE cases SET document_json = ?2 WHERE id = ?1",
                rusqlite::params![unreadable.id, preserved_bytes],
            )
            .expect("inject unreadable selected case");
        drop(database);

        assert_eq!(
            state
                .case_service()
                .recover_interrupted_scans()
                .expect("recover healthy sibling only"),
            1
        );
        let desktop = load_readable_desktop_cases(&state).expect("resilient desktop cases");
        assert_eq!(desktop.cases.len(), 1);
        assert_eq!(desktop.cases[0].id, healthy_case_id);
        let selected = desktop.selected_case.expect("healthy fallback selection");
        assert_eq!(selected.id, healthy_case_id);
        assert!(!selected.is_demo, "startup must never substitute demo data");
        assert_eq!(desktop.recovery_diagnostics.len(), 1);
        assert_eq!(
            desktop.recovery_diagnostics[0].code,
            "stored_case_unreadable"
        );
        assert!(desktop.recovery_diagnostics[0].preserved);

        let database = rusqlite::Connection::open(state.storage.path()).expect("reopen fixture db");
        let still_preserved: String = database
            .query_row(
                "SELECT document_json FROM cases WHERE id = ?1",
                [&unreadable.id],
                |row| row.get(0),
            )
            .expect("read preserved bytes");
        assert_eq!(still_preserved, preserved_bytes);
    }
}
