//! Shared durable scan coordination; desktop and foreground owners use one worker.
use crate::artifact_store::{ArtifactContext, ArtifactStore, inspect_raw_artifacts};
#[cfg(any(feature = "desktop", test))]
use crate::case_service::NoWorkerNaabuCancellation;
use crate::case_service::{
    DurableExecutionReport, ExactRuntimeCleanupSuccess, NaabuLauncherV2CoverageApplyOutcome,
    PersistedPreDispatchTaskOutcome, PersistedPreDispatchTransition,
    PersistedScanPreflightFailureReason, PlannedEngineExecution, ScanPlan, ScanPlanRequest,
    ScanReadinessBlocker, ScopeApprovalRequest,
};
#[cfg(feature = "desktop")]
use crate::case_service::{ScanReadiness, ScanReadinessNextStep, ScanReadinessState};
use crate::connectors::{
    SNAPSHOT_ARTIFACT_METADATA_KEY, SnapshotArtifactReference, preflight_snapshot_artifact,
};
use crate::core_state::CoreState;
use crate::domain::*;
use crate::error::{AppError, AppResult};
use crate::execution_coverage::{
    LAUNCHER_V2_JOURNAL_SCHEMA_VERSION, reduce_naabu_attempt_coverage,
};
use crate::external_scope::{ExternalScopeGrant, ResolvedExternalPlan, resolve_external_plan};
use crate::gateway_release::managed_egress_gateway_spec;
#[cfg(feature = "desktop")]
use crate::job_manager::DurableCancellationOutcome;
use crate::localhost_quick_scan::{
    prepared_localhost_quick_scan_for_job, reconcile_managed_localhost_terminal,
};
#[cfg(feature = "desktop")]
use crate::localhost_quick_scan::{
    record_localhost_cancel_transition, record_localhost_cancelled,
    run_is_exact_localhost_quick_scan,
};
use crate::managed_network::{
    GatewayContainerSpec, ManagedNetworkCleanupOutcome, ManagedNetworkController,
    ManagedNetworkLease, ManagedNetworkOwner, ProviderServiceEgressRequest,
    resolve_provider_service_plan, validate_provider_service_request_static,
};
use crate::mcp_armor_input::verify_mcp_configuration_selection;
use crate::naabu_work_plan::{
    NAABU_ENGINE_ID, NaabuAttemptSelection, NaabuLauncherPlanDocument, NaabuWorkPlanIdentity,
    NaabuWorkPlanV1, build_naabu_work_plan, select_naabu_attempt,
};
use crate::source_authorization::{
    BoundSourceCheckoutDemand, InstalledSourceAuthorization, PROVIDER_RESOURCE_SCOPE_METADATA_KEY,
    ProviderSourceProfile, ReservedScannerCredentialBundle, SourceAuthorizationBindingSnapshot,
    SourceCheckoutPreflightFailure, SourceCheckoutReservationHandle, validate_aws_execution_target,
};
use crate::workspace_snapshot::{
    WORKSPACE_SNAPSHOT_REFERENCE_METADATA_KEY, WorkspaceSnapshotReference,
    inspect_workspace_snapshot, resolve_workspace_snapshot,
};
use crate::{
    container_runtime::{
        CleanupOutcome, ContainerRuntime, NetworkPolicy, OwnedContainerCleanupRequest, PinnedImage,
        ProcessContainerRuntime, ResourceLimits, RuntimeCommandProvenance, RuntimeProvider,
        ScannerCredentialSet, cleanup_orphaned_credentials,
    },
    job_manager::{
        EngineJobControl, EngineJobStatus, JobActivationOutcome, JobCompletion, JobContext, JobKey,
        JobManagerError, JobSnapshot, TerminalReconciliationOutcome,
    },
    orchestrator::{
        EngineExecutionRequest, ExecutionCheckpoint, ExecutionReport, ExecutionStage, Orchestrator,
        ResumeAction, resume_captured_artifacts,
    },
};
use chrono::{Duration, Utc};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration as StdDuration, Instant};

use std::sync::{Arc, Mutex};

const RUN_PROGRESS_EVENT: &str = "scan://run-progress";
const RUN_FINISHED_EVENT: &str = "scan://run-finished";
const SCAN_RUNTIME_PREPARATION_DEADLINE: StdDuration = StdDuration::from_secs(5 * 60);
const SCAN_RUNTIME_PREPARATION_POLL: StdDuration = StdDuration::from_millis(100);
const PRE_DISPATCH_CANCEL_PERSISTENCE_ATTEMPTS: usize = 3;
const PRE_DISPATCH_CANCEL_RETRY_DELAY: StdDuration = StdDuration::from_millis(25);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanEventKind {
    Progress,
    Finished,
}

pub trait ScanEventSink: Send + Sync {
    fn emit(&self, kind: ScanEventKind, case: &AssessmentCase) -> AppResult<()>;
}

#[derive(Clone)]
pub struct ScanCoordinator {
    state: Arc<CoreState>,
    events: Arc<dyn ScanEventSink>,
    preparers: Arc<Mutex<Vec<thread::JoinHandle<()>>>>,
    cancel_on_sink_failure: bool,
    captured_recovery_only: bool,
    job_key: Option<JobKey>,
}

pub struct ScanAdmission {
    pub case: AssessmentCase,
    pub snapshot: Option<JobSnapshot>,
    pub owned_job: Option<crate::job_manager::OwnedJobHandle>,
}

impl ScanAdmission {
    fn inactive(case: AssessmentCase) -> Self {
        Self {
            case,
            snapshot: None,
            owned_job: None,
        }
    }
}

impl ScanCoordinator {
    pub fn new(state: Arc<CoreState>, events: Arc<dyn ScanEventSink>) -> Self {
        Self {
            state,
            events,
            preparers: Arc::new(Mutex::new(Vec::new())),
            cancel_on_sink_failure: false,
            captured_recovery_only: false,
            job_key: None,
        }
    }

    pub fn state(&self) -> &CoreState {
        &self.state
    }

    pub fn start_scan(
        &self,
        case_id: &str,
        approvals: Vec<ScopeApprovalRequest>,
        request: ScanPlanRequest,
    ) -> AppResult<ScanAdmission> {
        self.admit(case_id, approvals, request, false)
    }

    pub fn start_owned(
        &self,
        case_id: &str,
        approvals: Vec<ScopeApprovalRequest>,
        request: ScanPlanRequest,
    ) -> AppResult<ScanAdmission> {
        self.admit(case_id, approvals, request, true)
    }

    fn admit(
        &self,
        case_id: &str,
        approvals: Vec<ScopeApprovalRequest>,
        request: ScanPlanRequest,
        owned: bool,
    ) -> AppResult<ScanAdmission> {
        self.state.jobs.coordinate_admission(|| {
            let plan = self
                .state
                .case_service()
                .authorize_and_persist_scan_before_execution_preflight(
                    case_id, approvals, request,
                )?;
            admit_persisted_scan_job(self, plan, owned)
        })
    }

    pub fn start_persisted(&self, plan: ScanPlan) -> AppResult<ScanAdmission> {
        admit_persisted_scan_job(self, plan, false)
    }

    pub fn recover_owned(&self, case_id: &str, run_id: &str) -> AppResult<ScanAdmission> {
        let key = JobKey::new(case_id, run_id)
            .map_err(|error| AppError::InvalidRequest(error.to_string()))?;
        self.state.jobs.coordinate_admission(|| {
            if self.state.jobs.snapshot(&key).is_some() {
                return Err(AppError::Conflict(
                    "the exact run still has a local worker owner".into(),
                ));
            }
            let original = self.state.case_service().show_case(case_id)?;
            if original.scan_runs.iter().filter(|r| r.id == run_id).flat_map(|r| &r.engine_runs).any(|t| matches!(t.task_kind, crate::domain::EngineTaskKind::AgentAuditFailure { .. })) {
                return Err(AppError::NotAvailable("Replay the identical Cloudflare preparation or termination request to retain its report.".into()));
            }
            if original.scan_runs.iter().filter(|r| r.id == run_id).flat_map(|r| &r.engine_runs)
                .any(|t| matches!(t.task_kind, crate::domain::EngineTaskKind::AgentAudit { .. })) {
                return Err(AppError::NotAvailable("Replay the original provider cloudflare admit request to retain its report (admit_replay).".into()));
            }
            let has_captured = validate_recovery_without_target_contact(&original, run_id)?;
            self.state
                .case_service()
                .recover_interrupted_run(case_id, run_id)?;
            reconcile_interrupted_scan_resources(&self.state, Some((case_id, run_id)))?;
            if !has_captured {
                let service = self.state.case_service();
                service.finalize_verification_if_terminal(case_id, run_id)?;
                // The foreground owner publishes the report after joining all
                // preparers, preserving admission errors as non-mutating errors.
                return service.show_case(case_id).map(ScanAdmission::inactive);
            }
            let plan = self
                .state
                .case_service()
                .persist_captured_recovery_before_execution_preflight(case_id, run_id)?;
            let recovery = Self {
                captured_recovery_only: true,
                ..self.clone()
            };
            admit_persisted_scan_job(&recovery, plan, true)
        })
    }

    /// Publishes cancellation intent without competing with the foreground
    /// owner's exact-generation terminal reconciliation.
    pub fn cancel_owned(&self, case_id: &str, run_id: &str) -> AppResult<()> {
        let key = JobKey::new(case_id, run_id)
            .map_err(|error| AppError::InvalidRequest(error.to_string()))?;
        match self.state.jobs.cancel(&key) {
            Ok(_) | Err(JobManagerError::LiveJobNotFound(_)) => Ok(()),
            Err(error) => Err(AppError::Runtime(error.to_string())),
        }
    }

    pub fn cancel(&self, case_id: &str, run_id: &str) -> AppResult<AssessmentCase> {
        self.cancel_owned(case_id, run_id)?;
        self.state.case_service().show_case(case_id)
    }

    pub fn reconcile_terminal(
        &self,
        snapshot: &JobSnapshot,
    ) -> AppResult<TerminalJobReconciliation> {
        reconcile_terminal_job(self, &snapshot.key, snapshot)
    }

    /// Foreground owners retain runtime preparation helpers until they stop;
    /// cancelling a scan cannot detach a still-running runtime bootstrap.
    pub fn join_preparers(&self) -> AppResult<()> {
        let handles = std::mem::take(
            &mut *self
                .preparers
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
        let mut panicked = false;
        for handle in handles {
            panicked |= handle.join().is_err();
        }
        if panicked {
            Err(AppError::Runtime(
                "a scan preparation or reconciliation worker panicked".into(),
            ))
        } else {
            Ok(())
        }
    }
}

/// Whether this task still has captured output awaiting host-side processing.
/// A normalized Naabu batch can retain its checkpoint while waiting for a new
/// target-facing batch; that is incomplete coverage, not pending normalization.
pub fn task_requires_captured_recovery(task: &EngineRun) -> bool {
    let Some(checkpoint) = task
        .resume_token
        .as_deref()
        .and_then(|token| ExecutionCheckpoint::from_resume_token(token).ok())
    else {
        return false;
    };
    if checkpoint.resume_action() != ResumeAction::AdaptCapturedArtifacts {
        return false;
    }
    !(task.engine_id == NAABU_ENGINE_ID
        && checkpoint.launcher_plan_sha256.is_some()
        && task.naabu_attempt_results.iter().any(|result| {
            result.execution_attempt == checkpoint.attempt
                && result.coverage.engine_run_id == task.id
                && result.coverage.execution_attempt == checkpoint.attempt
        })
        && task.naabu_attempt_requests.iter().any(|request| {
            request.execution_attempt == checkpoint.attempt
                && Some(request.launcher_plan_sha256.as_str())
                    == checkpoint.launcher_plan_sha256.as_deref()
        })
        && task
            .naabu_attempt_results
            .iter()
            .all(|result| result.normalization_complete))
}

/// Validate the complete selected run before recovery can mutate any saved
/// state or contact a recorded runtime for exact housekeeping. The boolean
/// indicates captured results to process; `Ok(false)` permits cleanup only.
pub fn validate_recovery_without_target_contact(
    case: &AssessmentCase,
    run_id: &str,
) -> AppResult<bool> {
    let run = case
        .scan_runs
        .iter()
        .find(|run| run.id == run_id && run.case_id == case.id)
        .ok_or_else(|| AppError::InvalidRequest(format!("scan run not found: {run_id}")))?;
    let mut has_captured = false;
    for task in &run.engine_runs {
        let decoded = task
            .resume_token
            .as_deref()
            .map(ExecutionCheckpoint::from_resume_token)
            .transpose()?;
        if let Some(checkpoint) = &decoded
            && (checkpoint.case_id != case.id
                || checkpoint.scan_run_id != run.id
                || checkpoint.engine_run_id != task.id
                || checkpoint.engine_id != task.engine_id
                || task.scan_run_id != run.id)
        {
            return Err(AppError::NotAuthorized(
                "the saved recovery checkpoint does not match its exact case, run, and task".into(),
            ));
        }
        if matches!(
            task.status,
            EngineRunStatus::Completed | EngineRunStatus::NotExecuted
        ) {
            if decoded.as_ref().is_some_and(|checkpoint| {
                !checkpoint.cleanup_completed
                    && (checkpoint.container_name.is_some()
                        || checkpoint.managed_network.is_some()
                        || checkpoint.stage == ExecutionStage::CleanupPending)
            }) || task.phase == "cleanup_pending"
            {
                return Err(AppError::NotAvailable(
                    "the terminal task has an inconsistent pending cleanup checkpoint".into(),
                ));
            }
            continue;
        }
        let eligible = task.status == EngineRunStatus::Paused || decoded.is_some();
        if !eligible {
            if matches!(
                task.status,
                EngineRunStatus::Queued | EngineRunStatus::Preparing | EngineRunStatus::Running
            ) || (task.started_at.is_some() && task.cleanup_removed != Some(true))
            {
                return Err(AppError::NotAvailable("this saved task requires a new scan; recovery only processes captured results or exact cleanup".into()));
            }
            continue;
        }
        let checkpoint = decoded.ok_or_else(|| {
            AppError::NotAvailable("the saved task has no recovery checkpoint".into())
        })?;
        if task.status == EngineRunStatus::Failed
            && task.phase == "preflight_failed"
            && task.error_code.as_deref() == Some("captured_evidence_unavailable")
            && checkpoint.resume_action() == ResumeAction::AdaptCapturedArtifacts
        {
            return Err(AppError::NotAvailable(
                "the saved captured evidence failed verification and cannot be retried from this checkpoint".into(),
            ));
        }
        let has_recorded_resource =
            checkpoint.container_name.is_some() || checkpoint.managed_network.is_some();
        if !checkpoint.cleanup_completed && has_recorded_resource {
            let recoverable_lifecycle = matches!(
                task.status,
                EngineRunStatus::Queued
                    | EngineRunStatus::Preparing
                    | EngineRunStatus::Running
                    | EngineRunStatus::Paused
            ) || (task.status == EngineRunStatus::PartiallyCompleted
                && task.phase == "cleanup_pending")
                || (task.status == EngineRunStatus::Failed
                    && task.phase == "interrupted_restart_cleanup_pending");
            if !recoverable_lifecycle {
                return Err(AppError::NotAvailable(
                    "the saved cleanup checkpoint is outside a supported recovery lifecycle".into(),
                ));
            }
            if let Some(problem) = untrusted_static_cleanup_proof(task, &checkpoint) {
                return Err(AppError::NotAuthorized(problem.into()));
            }
            // A crashed worker's exact resource may need cleanup even while
            // its checkpoint still says Running. Only the cleanup phase is
            // permitted; the captured-only planner never retries the scanner.
            has_captured |= task_requires_captured_recovery(task);
            continue;
        }
        if checkpoint.cleanup_completed
            && matches!(
                checkpoint.stage,
                ExecutionStage::Failed | ExecutionStage::Cancelled
            )
            && matches!(
                task.status,
                EngineRunStatus::Failed
                    | EngineRunStatus::Cancelled
                    | EngineRunStatus::PartiallyCompleted
            )
        {
            // A completed sibling failure remains historical truth. Recovering
            // captured output elsewhere does not retry or rewrite this task.
            continue;
        }
        if task.engine_id == NAABU_ENGINE_ID
            && checkpoint.launcher_plan_sha256.is_some()
            && checkpoint.resume_action() == ResumeAction::AdaptCapturedArtifacts
            && checkpoint.cleanup_completed
            && (!task.naabu_attempt_results.iter().any(|result| {
                result.execution_attempt == checkpoint.attempt
                    && result.coverage.engine_run_id == task.id
                    && result.coverage.execution_attempt == checkpoint.attempt
            }) || !task.naabu_attempt_requests.iter().any(|request| {
                request.execution_attempt == checkpoint.attempt
                    && Some(request.launcher_plan_sha256.as_str())
                        == checkpoint.launcher_plan_sha256.as_deref()
            }))
        {
            return Err(AppError::NotAvailable(
                "the saved captured batch has no matching attempt result and request".into(),
            ));
        }
        match checkpoint.resume_action() {
            ResumeAction::AdaptCapturedArtifacts if checkpoint.cleanup_completed => { has_captured |= task_requires_captured_recovery(task); },
            ResumeAction::AlreadyComplete => {}
            _ => return Err(AppError::NotAvailable("this saved task requires a new scan; recovery only processes captured results or exact cleanup".into())),
        }
    }
    Ok(has_captured)
}

fn emit(app: &ScanCoordinator, event: &str, case: &AssessmentCase) -> AppResult<()> {
    let kind = if event == RUN_FINISHED_EVENT {
        ScanEventKind::Finished
    } else {
        ScanEventKind::Progress
    };
    let result = app.events.emit(kind, case);
    if result.is_err()
        && app.cancel_on_sink_failure
        && let Some(key) = &app.job_key
    {
        // Publish intent before another task can dispatch; never make output
        // failure discard the owned worker or its durable reconciliation.
        let _ = app.state.jobs.cancel(key);
    }
    result
}

#[cfg(feature = "desktop")]
pub(crate) fn schedule_exact_terminal_reconciliation(
    app: &ScanCoordinator,
    key: JobKey,
    snapshot: JobSnapshot,
) {
    let worker = app.clone();
    if let Ok(handle) = thread::Builder::new()
        .name("scan-terminal-reconciliation".into())
        .spawn(move || {
            if let Err(error) = reconcile_terminal_job(&worker, &key, &snapshot) {
                tracing::warn!(error = %error, "terminal reconciliation remains pending");
            }
        })
    {
        app.preparers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(handle);
    }
}

#[cfg(feature = "desktop")]
pub(crate) fn schedule_exact_runtime_cleanup_reconciliation(
    app: &ScanCoordinator,
    case_id: String,
    run_id: String,
) {
    let worker = app.clone();
    if let Ok(handle) = thread::Builder::new()
        .name("scan-runtime-reconciliation".into())
        .spawn(move || {
            let settled = (|| -> AppResult<()> {
                reconcile_interrupted_scan_resources(worker.state(), Some((&case_id, &run_id)))?;
                let service = worker.state().case_service();
                service.finalize_verification_if_terminal(&case_id, &run_id)?;
                let case = service.retain_terminal_report_snapshot(&case_id, &run_id)?;
                let terminal = case.scan_runs.iter().find(|run| run.id == run_id)
                    .is_some_and(crate::report_snapshot::terminal_snapshot_ready);
                emit(&worker, if terminal { RUN_FINISHED_EVENT } else { RUN_PROGRESS_EVENT }, &case)
            })();
            if let Err(error) = settled {
                tracing::warn!(error = %error, "runtime cleanup or terminal report remains pending");
            }
        })
    {
        app.preparers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(handle);
    }
}

#[derive(Debug, Default)]
pub(crate) struct RuntimeCleanupReconciliationSummary {
    pub reconciled: usize,
    pub pending: usize,
    pub details: Vec<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct ExactRuntimeCleanupObligation {
    pub(crate) case_id: String,
    pub(crate) run_id: String,
    pub(crate) engine_run: EngineRun,
    pub(crate) resume_token: String,
}

#[derive(Debug, Clone)]
pub(crate) struct UntrustedRuntimeCleanupMarker {
    pub(crate) case_id: String,
    pub(crate) run_id: String,
    pub(crate) engine_run_id: String,
    pub(crate) problem: &'static str,
}

/// Reconciles product housekeeping after startup. Interrupted attempts and
/// ordinary terminal partial results are selected independently; every
/// removal is bound to exact durable identity. A failure remains pending and
/// never turns into a successful scanner outcome.
pub(crate) fn reconcile_interrupted_scan_resources(
    state: &CoreState,
    exact_case_run: Option<(&str, &str)>,
) -> AppResult<RuntimeCleanupReconciliationSummary> {
    reconcile_interrupted_scan_resources_with(state, exact_case_run, |obligation| {
        reconcile_exact_runtime_cleanup(state, obligation)
    })
}

pub(crate) fn reconcile_interrupted_scan_resources_with<F>(
    state: &CoreState,
    exact_case_run: Option<(&str, &str)>,
    mut cleanup_exact: F,
) -> AppResult<RuntimeCleanupReconciliationSummary>
where
    F: FnMut(&ExactRuntimeCleanupObligation) -> AppResult<(CleanupOutcome, usize)>,
{
    let service = state.case_service();
    let mut obligations = Vec::<ExactRuntimeCleanupObligation>::new();
    let mut untrusted_markers = Vec::<UntrustedRuntimeCleanupMarker>::new();
    for summary in service.list_cases()? {
        if exact_case_run.is_some_and(|(case_id, _)| summary.id != case_id) {
            continue;
        }
        let case = service.show_case(&summary.id)?;
        for run in &case.scan_runs {
            if exact_case_run.is_some_and(|(_, run_id)| run.id != run_id) {
                continue;
            }
            for engine_run in &run.engine_runs {
                let retryable_cleanup_obligation = matches!(
                    (&engine_run.status, engine_run.phase.as_str()),
                    (
                        EngineRunStatus::Paused,
                        "interrupted_restart" | "interrupted_restart_cleanup_pending"
                    ) | (
                        EngineRunStatus::Failed,
                        "interrupted_restart_cleanup_pending"
                    )
                );
                if !retryable_cleanup_obligation {
                    continue;
                }
                let Some(resume_token) = engine_run.resume_token.clone() else {
                    untrusted_markers.push(UntrustedRuntimeCleanupMarker {
                        case_id: case.id.clone(),
                        run_id: run.id.clone(),
                        engine_run_id: engine_run.id.clone(),
                        problem: "The saved interrupted cleanup checkpoint is missing.",
                    });
                    continue;
                };
                let Ok(checkpoint) = ExecutionCheckpoint::from_resume_token(&resume_token) else {
                    untrusted_markers.push(UntrustedRuntimeCleanupMarker {
                        case_id: case.id.clone(),
                        run_id: run.id.clone(),
                        engine_run_id: engine_run.id.clone(),
                        problem: "The saved interrupted cleanup checkpoint could not be decoded.",
                    });
                    continue;
                };
                if checkpoint.case_id != case.id
                    || checkpoint.scan_run_id != run.id
                    || checkpoint.engine_run_id != engine_run.id
                    || checkpoint.engine_id != engine_run.engine_id
                {
                    untrusted_markers.push(UntrustedRuntimeCleanupMarker {
                        case_id: case.id.clone(),
                        run_id: run.id.clone(),
                        engine_run_id: engine_run.id.clone(),
                        problem: "The saved interrupted cleanup checkpoint conflicts with its durable case, run, or engine identity.",
                    });
                    continue;
                };
                if let Some(problem) = untrusted_static_cleanup_proof(engine_run, &checkpoint) {
                    untrusted_markers.push(UntrustedRuntimeCleanupMarker {
                        case_id: case.id.clone(),
                        run_id: run.id.clone(),
                        engine_run_id: engine_run.id.clone(),
                        problem,
                    });
                    continue;
                }
                obligations.push(ExactRuntimeCleanupObligation {
                    case_id: case.id.clone(),
                    run_id: run.id.clone(),
                    engine_run: engine_run.clone(),
                    resume_token,
                });
            }
        }
    }

    let mut summary = RuntimeCleanupReconciliationSummary::default();
    for marker in untrusted_markers {
        match state
            .case_service()
            .record_interrupted_cleanup_identity_unavailable(
                &marker.case_id,
                &marker.run_id,
                &marker.engine_run_id,
                marker.problem,
            ) {
            Ok(_) => {
                summary.reconciled = summary.reconciled.saturating_add(1);
                summary.details.push(bounded_text(
                    &format!(
                        "{} / {}: cleanup status: unresolved; {}",
                        marker.run_id, marker.engine_run_id, marker.problem
                    ),
                    2_000,
                ));
            }
            Err(error) => {
                summary.pending = summary.pending.saturating_add(1);
                summary.details.push(bounded_text(
                    &format!(
                        "{} / {}: interrupted cleanup status: pending; saved status update failed: {error}",
                        marker.run_id, marker.engine_run_id
                    ),
                    2_000,
                ));
            }
        }
    }
    for obligation in obligations {
        match cleanup_exact(&obligation) {
            Ok((cleanup, orphan_credentials_removed)) => {
                match state.case_service().record_interrupted_cleanup_success(
                    &obligation.case_id,
                    &obligation.run_id,
                    &obligation.engine_run.id,
                    ExactRuntimeCleanupSuccess {
                        expected_resume_token: obligation.resume_token.clone(),
                        cleanup,
                        orphan_credentials_removed,
                    },
                ) {
                    Ok(recovered) => {
                        summary.reconciled = summary.reconciled.saturating_add(1);
                        let captured_attempt = recovered
                            .scan_runs
                            .iter()
                            .find(|run| run.id == obligation.run_id)
                            .and_then(|run| {
                                run.engine_runs.iter().find(|engine_run| {
                                    engine_run.id == obligation.engine_run.id
                                        && engine_run.phase == "captured_awaiting_adapter"
                                })
                            })
                            .and_then(|engine_run| engine_run.resume_token.as_deref())
                            .and_then(|token| ExecutionCheckpoint::from_resume_token(token).ok())
                            .map(|checkpoint| checkpoint.attempt);
                        if let Some(attempt) = captured_attempt
                            && let Err(error) =
                                state.case_service().resume_naabu_launcher_v2_adaptation(
                                    &obligation.case_id,
                                    &obligation.run_id,
                                    &obligation.engine_run.id,
                                    attempt,
                                )
                        {
                            summary.details.push(bounded_text(
                                &format!(
                                    "{} / {}: cleanup status: completed; result organization: partial; {error}",
                                    obligation.run_id, obligation.engine_run.id
                                ),
                                2_000,
                            ));
                        }
                    }
                    Err(error) => {
                        summary.pending = summary.pending.saturating_add(1);
                        summary.details.push(bounded_text(
                            &format!(
                                "{} / {}: cleanup status: completed; saved status update failed: {error}",
                                obligation.run_id, obligation.engine_run.id
                            ),
                            2_000,
                        ));
                    }
                }
            }
            Err(AppError::NotAuthorized(problem)) => {
                match state
                    .case_service()
                    .record_interrupted_cleanup_identity_unavailable(
                        &obligation.case_id,
                        &obligation.run_id,
                        &obligation.engine_run.id,
                        &format!("Interrupted cleanup ownership unavailable: {problem}"),
                    ) {
                    Ok(_) => {
                        summary.reconciled = summary.reconciled.saturating_add(1);
                        summary.details.push(bounded_text(
                            &format!(
                                "{} / {}: cleanup status: unresolved; ownership proof unavailable.",
                                obligation.run_id, obligation.engine_run.id
                            ),
                            2_000,
                        ));
                    }
                    Err(error) => {
                        summary.pending = summary.pending.saturating_add(1);
                        summary.details.push(bounded_text(
                            &format!(
                                "{} / {}: interrupted cleanup status: pending; saved status update failed: {error}",
                                obligation.run_id, obligation.engine_run.id
                            ),
                            2_000,
                        ));
                    }
                }
            }
            Err(error) => {
                let explanation = bounded_text(
                    &format!("Interrupted runtime cleanup status: pending. {error}"),
                    2_000,
                );
                let persisted = state.case_service().record_interrupted_cleanup_failure(
                    &obligation.case_id,
                    &obligation.run_id,
                    &obligation.engine_run.id,
                    &obligation.resume_token,
                    &explanation,
                );
                summary.pending = summary.pending.saturating_add(1);
                summary.details.push(bounded_text(
                    &match persisted {
                        Ok(_) => format!(
                            "{} / {}: {explanation}",
                            obligation.run_id, obligation.engine_run.id
                        ),
                        Err(record_error) => format!(
                            "{} / {}: {explanation}; durable pending-state update also failed: {record_error}",
                            obligation.run_id, obligation.engine_run.id
                        ),
                    },
                    2_000,
                ));
            }
        }
    }
    let ordinary = reconcile_pending_scan_cleanup(state, exact_case_run)?;
    summary.reconciled = summary.reconciled.saturating_add(ordinary.reconciled);
    summary.pending = summary.pending.saturating_add(ordinary.pending);
    summary.details.extend(ordinary.details);
    Ok(summary)
}

/// Collects only the ordinary terminal shape produced by a durable execution
/// report whose scanner work ended but exact product-owned cleanup did not:
/// partial + cleanup_pending + a matching decoded CleanupPending checkpoint.
/// It never infers an object from a runtime/container name and never executes
/// target-facing scanner work.
pub(crate) fn reconcile_pending_scan_cleanup(
    state: &CoreState,
    exact_case_run: Option<(&str, &str)>,
) -> AppResult<RuntimeCleanupReconciliationSummary> {
    reconcile_pending_scan_cleanup_with(state, exact_case_run, |obligation| {
        reconcile_exact_runtime_cleanup(state, obligation)
    })
}

pub(crate) fn reconcile_pending_scan_cleanup_with<F>(
    state: &CoreState,
    exact_case_run: Option<(&str, &str)>,
    mut cleanup_exact: F,
) -> AppResult<RuntimeCleanupReconciliationSummary>
where
    F: FnMut(&ExactRuntimeCleanupObligation) -> AppResult<(CleanupOutcome, usize)>,
{
    let service = state.case_service();
    let mut obligations = Vec::<ExactRuntimeCleanupObligation>::new();
    let mut untrusted_markers = Vec::<UntrustedRuntimeCleanupMarker>::new();
    for case_summary in service.list_cases()? {
        if exact_case_run.is_some_and(|(case_id, _)| case_summary.id != case_id) {
            continue;
        }
        let case = service.show_case(&case_summary.id)?;
        for run in &case.scan_runs {
            if exact_case_run.is_some_and(|(_, run_id)| run.id != run_id) {
                continue;
            }
            for engine_run in &run.engine_runs {
                if engine_run.status != EngineRunStatus::PartiallyCompleted
                    || engine_run.phase != "cleanup_pending"
                {
                    continue;
                }
                let Some(resume_token) = engine_run.resume_token.clone() else {
                    untrusted_markers.push(UntrustedRuntimeCleanupMarker {
                        case_id: case.id.clone(),
                        run_id: run.id.clone(),
                        engine_run_id: engine_run.id.clone(),
                        problem: "The saved cleanup checkpoint is missing.",
                    });
                    continue;
                };
                let Ok(checkpoint) = ExecutionCheckpoint::from_resume_token(&resume_token) else {
                    untrusted_markers.push(UntrustedRuntimeCleanupMarker {
                        case_id: case.id.clone(),
                        run_id: run.id.clone(),
                        engine_run_id: engine_run.id.clone(),
                        problem: "Saved cleanup checkpoint unreadable.",
                    });
                    continue;
                };
                if checkpoint.case_id != case.id
                    || checkpoint.scan_run_id != run.id
                    || checkpoint.engine_run_id != engine_run.id
                    || checkpoint.engine_id != engine_run.engine_id
                {
                    untrusted_markers.push(UntrustedRuntimeCleanupMarker {
                        case_id: case.id.clone(),
                        run_id: run.id.clone(),
                        engine_run_id: engine_run.id.clone(),
                        problem: "The saved cleanup checkpoint conflicts with its durable case, run, or engine identity.",
                    });
                    continue;
                }
                if checkpoint.stage != ExecutionStage::CleanupPending
                    || checkpoint.cleanup_completed
                {
                    untrusted_markers.push(UntrustedRuntimeCleanupMarker {
                        case_id: case.id.clone(),
                        run_id: run.id.clone(),
                        engine_run_id: engine_run.id.clone(),
                        problem: "The saved checkpoint does not describe an unfinished cleanup obligation.",
                    });
                    continue;
                }
                if let Some(problem) = untrusted_static_cleanup_proof(engine_run, &checkpoint) {
                    untrusted_markers.push(UntrustedRuntimeCleanupMarker {
                        case_id: case.id.clone(),
                        run_id: run.id.clone(),
                        engine_run_id: engine_run.id.clone(),
                        problem,
                    });
                    continue;
                }
                obligations.push(ExactRuntimeCleanupObligation {
                    case_id: case.id.clone(),
                    run_id: run.id.clone(),
                    engine_run: engine_run.clone(),
                    resume_token,
                });
            }
        }
    }

    let mut summary = RuntimeCleanupReconciliationSummary::default();
    for marker in untrusted_markers {
        match state.case_service().record_cleanup_identity_unavailable(
            &marker.case_id,
            &marker.run_id,
            &marker.engine_run_id,
            marker.problem,
        ) {
            Ok(_) => {
                summary.reconciled = summary.reconciled.saturating_add(1);
                summary.details.push(bounded_text(
                    &format!(
                        "{} / {}: cleanup status: unresolved; {}",
                        marker.run_id, marker.engine_run_id, marker.problem
                    ),
                    2_000,
                ));
            }
            Err(error) => {
                summary.pending = summary.pending.saturating_add(1);
                summary.details.push(bounded_text(
                    &format!(
                        "{} / {}: cleanup status: pending; saved status update failed: {error}",
                        marker.run_id, marker.engine_run_id
                    ),
                    2_000,
                ));
            }
        }
    }
    for obligation in obligations {
        match cleanup_exact(&obligation) {
            Ok((cleanup, orphan_credentials_removed)) => {
                let result = ExactRuntimeCleanupSuccess {
                    expected_resume_token: obligation.resume_token.clone(),
                    cleanup,
                    orphan_credentials_removed,
                };
                match state.case_service().record_cleanup_pending_success(
                    &obligation.case_id,
                    &obligation.run_id,
                    &obligation.engine_run.id,
                    result,
                ) {
                    Ok(_) => summary.reconciled = summary.reconciled.saturating_add(1),
                    Err(error) => {
                        summary.pending = summary.pending.saturating_add(1);
                        summary.details.push(bounded_text(
                            &format!(
                                "{} / {}: cleanup status: completed; saved status update failed: {error}",
                                obligation.run_id, obligation.engine_run.id
                            ),
                            2_000,
                        ));
                    }
                }
            }
            Err(AppError::NotAuthorized(problem)) => {
                match state.case_service().record_cleanup_identity_unavailable(
                    &obligation.case_id,
                    &obligation.run_id,
                    &obligation.engine_run.id,
                    &format!("Runtime cleanup ownership unavailable: {problem}"),
                ) {
                    Ok(_) => {
                        summary.reconciled = summary.reconciled.saturating_add(1);
                        summary.details.push(bounded_text(
                            &format!(
                                "{} / {}: cleanup status: unresolved; ownership proof unavailable.",
                                obligation.run_id, obligation.engine_run.id
                            ),
                            2_000,
                        ));
                    }
                    Err(error) => {
                        summary.pending = summary.pending.saturating_add(1);
                        summary.details.push(bounded_text(
                            &format!(
                                "{} / {}: cleanup status: pending; saved status update failed: {error}",
                                obligation.run_id, obligation.engine_run.id
                            ),
                            2_000,
                        ));
                    }
                }
            }
            Err(error) => {
                let explanation =
                    bounded_text(&format!("Runtime cleanup status: pending. {error}"), 2_000);
                let persisted = state.case_service().record_cleanup_pending_failure(
                    &obligation.case_id,
                    &obligation.run_id,
                    &obligation.engine_run.id,
                    &obligation.resume_token,
                    &explanation,
                );
                summary.pending = summary.pending.saturating_add(1);
                summary.details.push(bounded_text(
                    &match persisted {
                        Ok(_) => format!(
                            "{} / {}: {explanation}",
                            obligation.run_id, obligation.engine_run.id
                        ),
                        Err(record_error) => format!(
                            "{} / {}: {explanation}; durable pending-state update also failed: {record_error}",
                            obligation.run_id, obligation.engine_run.id
                        ),
                    },
                    2_000,
                ));
            }
        }
    }
    Ok(summary)
}

pub(crate) fn untrusted_static_cleanup_proof(
    engine_run: &EngineRun,
    checkpoint: &ExecutionCheckpoint,
) -> Option<&'static str> {
    let resource_free_plan = checkpoint.stage == ExecutionStage::Planned
        && checkpoint.cleanup_completed
        && checkpoint.container_name.is_none()
        && checkpoint.managed_network.is_none()
        && checkpoint.runtime_provider.is_none()
        && checkpoint.runtime_command_provenance.is_none();
    if resource_free_plan {
        return None;
    }
    let (Some(repository), Some(digest)) = (
        engine_run.image_repository.as_deref(),
        engine_run.image_digest.as_deref(),
    ) else {
        return Some("The saved cleanup record has no complete pinned image identity.");
    };
    if PinnedImage::new(repository, digest).is_err() {
        return Some("The saved cleanup record has an invalid pinned image identity.");
    }
    if checkpoint.scope_sha256.is_none() {
        return Some("The saved cleanup record has no frozen scope identity.");
    }
    if checkpoint.runtime_provider.is_none() || checkpoint.runtime_command_provenance.is_none() {
        return Some("The saved cleanup record has no exact runtime provenance.");
    }
    if let Some(container_name) = checkpoint.container_name.as_deref() {
        let Ok(expected) = crate::container_runtime::planned_container_name(
            &checkpoint.engine_id,
            &checkpoint.engine_run_id,
            checkpoint.attempt,
        ) else {
            return Some(
                "The saved cleanup record has an invalid deterministic container identity.",
            );
        };
        if expected != container_name {
            return Some(
                "The saved cleanup record conflicts with its deterministic container identity.",
            );
        }
    }
    None
}

pub(crate) fn reconcile_exact_runtime_cleanup(
    state: &CoreState,
    obligation: &ExactRuntimeCleanupObligation,
) -> AppResult<(CleanupOutcome, usize)> {
    let checkpoint = ExecutionCheckpoint::from_resume_token(&obligation.resume_token)?;
    if checkpoint.case_id != obligation.case_id
        || checkpoint.scan_run_id != obligation.run_id
        || checkpoint.engine_run_id != obligation.engine_run.id
        || checkpoint.engine_id != obligation.engine_run.engine_id
    {
        return Err(AppError::NotAuthorized(
            "cleanup checkpoint does not match its exact durable execution".into(),
        ));
    }

    // A synthetic planned checkpoint means the process ended before any
    // runtime identity, container, network, scope file, or credential channel
    // existed. There is deliberately nothing to infer or enumerate.
    if checkpoint.stage == ExecutionStage::Planned
        && checkpoint.cleanup_completed
        && checkpoint.container_name.is_none()
        && checkpoint.managed_network.is_none()
        && checkpoint.runtime_provider.is_none()
        && checkpoint.runtime_command_provenance.is_none()
    {
        return Ok((
            CleanupOutcome {
                removed: false,
                detail: "desktop ended before runtime resources were created".into(),

                gateway_refusals: None,
            },
            0,
        ));
    }

    let image = PinnedImage::new(
        obligation
            .engine_run
            .image_repository
            .as_deref()
            .ok_or_else(|| {
                AppError::NotAuthorized("cleanup execution has no pinned image repository".into())
            })?,
        obligation
            .engine_run
            .image_digest
            .as_deref()
            .ok_or_else(|| {
                AppError::NotAuthorized("cleanup execution has no image digest".into())
            })?,
    )
    .map_err(|_| {
        AppError::NotAuthorized("cleanup execution has an invalid pinned image identity".into())
    })?;
    let owned = OwnedContainerCleanupRequest {
        case_id: obligation.case_id.clone(),
        scan_run_id: obligation.run_id.clone(),
        engine_run_id: obligation.engine_run.id.clone(),
        engine_id: obligation.engine_run.engine_id.clone(),
        attempt: checkpoint.attempt,
        scope_sha256: checkpoint.scope_sha256.clone().ok_or_else(|| {
            AppError::NotAuthorized("cleanup checkpoint has no frozen scope digest".into())
        })?,
        launcher_plan_sha256: checkpoint.launcher_plan_sha256.clone(),
        zap_plan_sha256: checkpoint.zap_plan_sha256.clone(),
        image,
    };
    if let Some(container_name) = checkpoint.container_name.as_deref()
        && owned.container_name()? != container_name
    {
        return Err(AppError::NotAuthorized(
            "cleanup container name conflicts with its deterministic execution identity".into(),
        ));
    }
    let provider = checkpoint.runtime_provider.ok_or_else(|| {
        AppError::NotAuthorized("cleanup checkpoint has no exact runtime provider".into())
    })?;
    let provenance = checkpoint
        .runtime_command_provenance
        .as_ref()
        .ok_or_else(|| {
            AppError::NotAuthorized("cleanup checkpoint has no exact runtime provenance".into())
        })?;
    let runtime = state.runtime_for_recorded_execution(provider, provenance)?;
    let container = match checkpoint.container_name.as_ref() {
        Some(_) => runtime.cleanup_owned_container(&owned)?,
        None => CleanupOutcome {
            removed: false,
            detail: "scanner container: not created".into(),

            gateway_refusals: None,
        },
    };
    let managed = checkpoint
        .managed_network
        .as_ref()
        .map(|identity| {
            let owner = ManagedNetworkOwner::new(
                checkpoint.case_id.clone(),
                checkpoint.scan_run_id.clone(),
                checkpoint.engine_run_id.clone(),
                checkpoint.attempt,
            )?;
            state
                .managed_network_registry_with_context(runtime.command_context())?
                .reconcile_identity(&owner, identity, Utc::now())
        })
        .transpose()
        .map_err(retryable_error_after_cleanup_started)?;
    let orphan_credentials_removed = cleanup_orphaned_credentials(state.artifact_root(), &owned)
        .map_err(retryable_error_after_cleanup_started)?;
    let gateway_refusals = managed
        .as_ref()
        .and_then(|outcome| outcome.gateway_refusals);
    let detail = bounded_text(
        &match &managed {
            Some(managed) => format!(
                "{}; managed egress: {}; orphan credential envelopes removed: {}",
                container.detail, managed.detail, orphan_credentials_removed
            ),
            None => format!(
                "{}; orphan credential envelopes removed: {}",
                container.detail, orphan_credentials_removed
            ),
        },
        2_000,
    );
    Ok((
        CleanupOutcome {
            removed: container.removed,
            detail,
            gateway_refusals,
        },
        orphan_credentials_removed,
    ))
}

pub(crate) fn retryable_error_after_cleanup_started(error: AppError) -> AppError {
    match error {
        AppError::NotAuthorized(message) => AppError::Runtime(format!(
            "cleanup status: partial; ownership check incomplete: {message}"
        )),
        other => other,
    }
}

#[cfg(any(feature = "desktop", test))]
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct RetainedTerminalReconciliationSummary {
    pub(crate) reconciled: usize,
    pub(crate) pending: usize,
}

/// Replays retained in-process terminal outcomes into durable case state.
///
/// The worker callback normally performs this write immediately. If that one
/// write loses a storage race or hits a transient I/O error, frontend polling
/// must still converge without restarting the app or contacting the target a
/// second time. The JobManager's terminal snapshot contains no
/// executable closure, so replay only applies the existing checkpoint result.
#[cfg(any(feature = "desktop", test))]
pub(crate) fn reconcile_retained_terminal_jobs(
    state: &CoreState,
) -> RetainedTerminalReconciliationSummary {
    let mut summary = RetainedTerminalReconciliationSummary::default();
    for snapshot in state.jobs.terminal_snapshots() {
        match state.jobs.reconcile_terminal_snapshot(&snapshot, || {
            persist_terminal_job_reconciliation(state, &snapshot.key, &snapshot)
        }) {
            Ok(TerminalReconciliationOutcome::Reconciled(_)) => {
                summary.reconciled = summary.reconciled.saturating_add(1);
            }
            Ok(TerminalReconciliationOutcome::InProgress) => {
                summary.pending = summary.pending.saturating_add(1);
            }
            Ok(TerminalReconciliationOutcome::NotCurrent) => {}
            Err(error) => {
                summary.pending = summary.pending.saturating_add(1);
                tracing::warn!(
                    error = %error,
                    case_id = %snapshot.key.case_id,
                    scan_run_id = %snapshot.key.scan_run_id,
                    "retained terminal scan outcome is still waiting for durable reconciliation"
                );
            }
        }
    }
    summary
}

pub(crate) type DesktopExecutionBlocker = ScanReadinessBlocker;

impl ScanReadinessBlocker {
    #[cfg(feature = "desktop")]
    pub(crate) fn readiness_state(self) -> ScanReadinessState {
        match self {
            Self::DemoCase | Self::ArchivedCase => ScanReadinessState::CaseUnavailable,
            Self::ScanAlreadyActive => ScanReadinessState::ScanInProgress,
            Self::NoEffectiveScopeGrants => ScanReadinessState::ScopeRequired,
            Self::NoOwnershipConfirmedTargets => ScanReadinessState::OwnershipRequired,
            Self::NoCompatibleAuthorizedTargets => {
                ScanReadinessState::NoCompatibleAuthorizedTargets
            }
            Self::NoRunnableAuthorizedTargets => ScanReadinessState::NoRunnableAuthorizedTargets,
            Self::RuntimeUnavailable => ScanReadinessState::RuntimeUnavailable,
            Self::ProviderSourceRequired => ScanReadinessState::ProviderConnectionRequired,
            Self::ProviderCapabilityUnavailable => ScanReadinessState::ProviderCapabilityRequired,
            Self::ProviderSourceAmbiguous
            | Self::ProviderAuthorizationBindingMismatch
            | Self::ProviderTargetBindingMismatch => ScanReadinessState::ProviderReviewRequired,
            Self::ProviderPreflightUnavailable => ScanReadinessState::ProviderCheckUnavailable,
            Self::WorkspaceSnapshotUnavailable
            | Self::PassiveSourceUnavailable
            | Self::CapturedEvidenceUnavailable => ScanReadinessState::ExecutionInputUnavailable,
            Self::EgressGatewayUnavailable | Self::EngineExecutionContractInvalid => {
                ScanReadinessState::ScannerSetupRequired
            }
            Self::ExecutionPreflightUnavailable => ScanReadinessState::ExecutionCheckUnavailable,
        }
    }

    pub(crate) fn blocker_code(self) -> ScanReadinessBlocker {
        self
    }

    #[cfg(feature = "desktop")]
    pub(crate) fn next_step(self) -> ScanReadinessNextStep {
        match self {
            Self::DemoCase | Self::ArchivedCase => ScanReadinessNextStep::Cases,
            Self::ScanAlreadyActive | Self::CapturedEvidenceUnavailable => {
                ScanReadinessNextStep::Progress
            }
            Self::NoEffectiveScopeGrants
            | Self::NoOwnershipConfirmedTargets
            | Self::NoCompatibleAuthorizedTargets
            | Self::NoRunnableAuthorizedTargets
            | Self::ProviderSourceRequired
            | Self::ProviderCapabilityUnavailable
            | Self::ProviderSourceAmbiguous
            | Self::ProviderAuthorizationBindingMismatch
            | Self::ProviderTargetBindingMismatch
            | Self::WorkspaceSnapshotUnavailable
            | Self::PassiveSourceUnavailable => ScanReadinessNextStep::Coverage,
            Self::RuntimeUnavailable
            | Self::EgressGatewayUnavailable
            | Self::EngineExecutionContractInvalid => ScanReadinessNextStep::ScannerSetup,
            Self::ProviderPreflightUnavailable | Self::ExecutionPreflightUnavailable => {
                ScanReadinessNextStep::Retry
            }
        }
    }

    pub(crate) fn persisted_reason(self) -> PersistedScanPreflightFailureReason {
        self
    }

    #[cfg(test)]
    pub(crate) fn into_error(self) -> AppError {
        AppError::NotAvailable(format!(
            "scan_preflight:{}: {}",
            self.as_str(),
            self.diagnostic()
        ))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProviderPreflightFailure {
    SourceRequired,
    CapabilityUnavailable,
    SourceAmbiguous,
    AuthorizationBindingMismatch,
    TargetBindingMismatch,
    PreflightUnavailable,
}

impl ProviderPreflightFailure {
    pub(crate) fn blocker(self) -> DesktopExecutionBlocker {
        match self {
            Self::SourceRequired => DesktopExecutionBlocker::ProviderSourceRequired,
            Self::CapabilityUnavailable => DesktopExecutionBlocker::ProviderCapabilityUnavailable,
            Self::SourceAmbiguous => DesktopExecutionBlocker::ProviderSourceAmbiguous,
            Self::AuthorizationBindingMismatch => {
                DesktopExecutionBlocker::ProviderAuthorizationBindingMismatch
            }
            Self::TargetBindingMismatch => DesktopExecutionBlocker::ProviderTargetBindingMismatch,
            Self::PreflightUnavailable => DesktopExecutionBlocker::ProviderPreflightUnavailable,
        }
    }

    #[cfg(test)]
    pub(crate) fn into_error(self) -> AppError {
        self.blocker().into_error()
    }
}

pub(crate) struct OwnedSourceCheckoutDemand {
    pub(crate) case_id: String,
    pub(crate) source_id: String,
    pub(crate) engine_id: String,
    pub(crate) binding: SourceAuthorizationBindingSnapshot,
    pub(crate) context: ProviderExecutionContext,
}

#[derive(Clone)]
pub(crate) struct ProviderExecutionContext {
    pub(crate) engine_run_id: String,
    pub(crate) source: DataSource,
    pub(crate) authorization: InstalledSourceAuthorization,
}

pub(crate) struct ProviderExecutionReservation {
    pub(crate) handle: SourceCheckoutReservationHandle,
    pub(crate) credentials: ReservedScannerCredentialBundle,
    pub(crate) contexts: Vec<ProviderExecutionContext>,
}

#[cfg(feature = "desktop")]
pub(crate) fn block_scan_readiness(
    readiness: &mut ScanReadiness,
    blocker: DesktopExecutionBlocker,
) {
    readiness.ready = false;
    readiness.state = blocker.readiness_state();
    readiness.blocker_code = Some(blocker.blocker_code());
    readiness.next_step = Some(blocker.next_step());
}

pub(crate) fn execution_requires_provider_capability(execution: &PlannedEngineExecution) -> bool {
    // Captured-artifact resume never contacts the provider, provisions an
    // egress network, or checks out credentials. Requiring a fresh live
    // capability here would strand already-preserved evidence after the
    // short-lived provider session expires. Every action that can reexecute
    // the scanner remains subject to the ordinary provider-demand checks.
    if execution
        .resume_checkpoint
        .as_ref()
        .is_some_and(|checkpoint| {
            checkpoint.resume_action() == ResumeAction::AdaptCapturedArtifacts
        })
    {
        return false;
    }
    execution
        .manifest
        .required_permissions
        .iter()
        .any(|permission| {
            matches!(
                permission,
                ScanPermission::InventoryRead | ScanPermission::ConfigurationRead
            )
        })
        && execution.assets.iter().any(|asset| {
            matches!(
                asset.kind,
                AssetKind::CloudOrganization
                    | AssetKind::CloudAccount
                    | AssetKind::Subscription
                    | AssetKind::Project
                    | AssetKind::Tenant
            )
        })
}

pub(crate) fn provider_source_for_preflight(
    state: &CoreState,
    execution: &PlannedEngineExecution,
) -> Result<DataSource, ProviderPreflightFailure> {
    match provider_source_for_execution(state, execution) {
        Ok(Some(source)) => Ok(source),
        Ok(None) => {
            let case = state
                .case_service()
                .show_case(&execution.case_id)
                .map_err(|_| ProviderPreflightFailure::PreflightUnavailable)?;
            let candidate_ids = execution
                .assets
                .iter()
                .flat_map(|asset| asset.discovered_from.iter())
                .filter_map(|source_id| {
                    case.data_sources
                        .iter()
                        .find(|source| {
                            source.id == *source_id
                                && source.read_only
                                && matches!(
                                    source.kind,
                                    SourceKind::AwsOrganization
                                        | SourceKind::AzureTenant
                                        | SourceKind::GcpOrganization
                                        | SourceKind::Microsoft365Tenant
                                )
                        })
                        .map(|source| source.id.clone())
                })
                .collect::<BTreeSet<_>>();
            if candidate_ids.len() > 1 {
                return Err(ProviderPreflightFailure::SourceAmbiguous);
            }
            let Some(source_id) = candidate_ids.into_iter().next() else {
                return Err(ProviderPreflightFailure::SourceRequired);
            };
            let source = case
                .data_sources
                .iter()
                .find(|source| source.id == source_id)
                .expect("provider preflight source id came from this case");
            match &source.status {
                SourceConnectionStatus::NeedsReauthorization | SourceConnectionStatus::Failed => {
                    Err(ProviderPreflightFailure::CapabilityUnavailable)
                }
                SourceConnectionStatus::Connecting => {
                    Err(ProviderPreflightFailure::PreflightUnavailable)
                }
                _ => Err(ProviderPreflightFailure::SourceRequired),
            }
        }
        Err(AppError::InvalidRequest(_)) => Err(ProviderPreflightFailure::SourceAmbiguous),
        Err(AppError::NotAuthorized(_)) => Err(ProviderPreflightFailure::TargetBindingMismatch),
        Err(_) => Err(ProviderPreflightFailure::PreflightUnavailable),
    }
}

pub(crate) fn map_source_checkout_preflight_failure(
    failure: SourceCheckoutPreflightFailure,
) -> ProviderPreflightFailure {
    match failure {
        SourceCheckoutPreflightFailure::CapabilityUnavailable => {
            ProviderPreflightFailure::CapabilityUnavailable
        }
        SourceCheckoutPreflightFailure::BindingMismatch => {
            ProviderPreflightFailure::AuthorizationBindingMismatch
        }
        SourceCheckoutPreflightFailure::Internal => ProviderPreflightFailure::PreflightUnavailable,
    }
}

pub(crate) fn provider_authorization_snapshot_for_preflight(
    state: &CoreState,
    source: &DataSource,
    execution: &PlannedEngineExecution,
    now: chrono::DateTime<Utc>,
) -> Result<SourceAuthorizationBindingSnapshot, ProviderPreflightFailure> {
    let binding = state
        .source_authorizations
        .binding_snapshot(&execution.case_id, &source.id, now)
        .map_err(map_source_checkout_preflight_failure)?
        .ok_or(ProviderPreflightFailure::CapabilityUnavailable)?;
    let authorization = binding.authorization();
    let persisted_profile = source
        .metadata
        .get("provider_profile")
        .cloned()
        .and_then(|value| serde_json::from_value::<ProviderSourceProfile>(value).ok());
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
    if authorization.case_id != execution.case_id
        || authorization.source_id != source.id
        || authorization.source_kind != source.kind
        || authorization.provider_verification.profile != authorization.profile
        || persisted_profile != Some(authorization.profile)
        || authorization.provider_identity != persisted_identity
        || authorization.provider_verification.evidence_sha256 != persisted_proof
        || !authorization
            .allowed_engine_ids
            .contains(&execution.manifest.id)
    {
        return Err(ProviderPreflightFailure::AuthorizationBindingMismatch);
    }
    validate_provider_execution_target(state, source, execution, authorization).map_err(
        |error| match error {
            AppError::Internal(_) | AppError::Storage(_) | AppError::CaseNotFound(_) => {
                ProviderPreflightFailure::PreflightUnavailable
            }
            _ => ProviderPreflightFailure::TargetBindingMismatch,
        },
    )?;
    Ok(binding)
}

/// Builds the exact, duplicate-preserving provider demand. Every planned cloud
/// group is rebound to its persisted provider identity, proof, and exact
/// resource scope before a capability is inspected or reserved.
pub(crate) fn provider_execution_demands(
    state: &CoreState,
    plan: &ScanPlan,
    now: chrono::DateTime<Utc>,
) -> Result<Vec<OwnedSourceCheckoutDemand>, ProviderPreflightFailure> {
    let mut owned_demands = Vec::new();
    for execution in &plan.executable {
        if !execution_requires_provider_capability(execution) {
            continue;
        }
        let source = provider_source_for_preflight(state, execution)?;
        let binding =
            provider_authorization_snapshot_for_preflight(state, &source, execution, now)?;
        let authorization = binding.authorization().clone();
        owned_demands.push(OwnedSourceCheckoutDemand {
            case_id: execution.case_id.clone(),
            source_id: source.id.clone(),
            engine_id: execution.manifest.id.clone(),
            binding,
            context: ProviderExecutionContext {
                engine_run_id: execution.engine_run_id.clone(),
                source,
                authorization,
            },
        });
    }
    Ok(owned_demands)
}

pub(crate) fn borrowed_bound_checkout_demands(
    owned_demands: &[OwnedSourceCheckoutDemand],
) -> Vec<BoundSourceCheckoutDemand<'_>> {
    owned_demands
        .iter()
        .map(|demand| BoundSourceCheckoutDemand {
            case_id: &demand.case_id,
            source_id: &demand.source_id,
            engine_id: &demand.engine_id,
            binding: &demand.binding,
        })
        .collect()
}

/// Non-mutating readiness snapshot. Desktop execution revalidates through the
/// reservation path below after the exact run is durable and before dispatch.
pub(crate) fn validate_provider_execution_demands(
    state: &CoreState,
    plan: &ScanPlan,
    now: chrono::DateTime<Utc>,
) -> Result<(), ProviderPreflightFailure> {
    let owned_demands = provider_execution_demands(state, plan, now)?;
    if owned_demands.is_empty() {
        return Ok(());
    }
    state
        .source_authorizations
        .validate_bound_checkout_demands(&borrowed_bound_checkout_demands(&owned_demands), now)
        .map_err(map_source_checkout_preflight_failure)
}

pub(crate) fn reserve_provider_execution_demands(
    state: &CoreState,
    plan: &ScanPlan,
    now: chrono::DateTime<Utc>,
) -> Result<Option<ProviderExecutionReservation>, ProviderPreflightFailure> {
    let owned_demands = provider_execution_demands(state, plan, now)?;
    if owned_demands.is_empty() {
        return Ok(None);
    }
    let (handle, credentials) = state
        .source_authorizations
        .reserve_bound_checkout_demands(&borrowed_bound_checkout_demands(&owned_demands), now)
        .map_err(map_source_checkout_preflight_failure)?;
    if credentials.remaining() != owned_demands.len() {
        let reservation = ProviderExecutionReservation {
            handle,
            credentials,
            contexts: Vec::new(),
        };
        release_provider_execution_reservation(
            state,
            Some(reservation),
            "provider reservation cardinality validation",
        );
        return Err(ProviderPreflightFailure::PreflightUnavailable);
    }
    Ok(Some(ProviderExecutionReservation {
        handle,
        credentials,
        contexts: owned_demands
            .into_iter()
            .map(|demand| demand.context)
            .collect(),
    }))
}

pub(crate) fn validate_scan_dispatch_identity(plan: &ScanPlan) -> AppResult<()> {
    JobKey::new(plan.scan_run.case_id.clone(), plan.scan_run.id.clone())
        .map_err(|error| AppError::InvalidRequest(error.to_string()))?;
    let mut engine_run_ids = BTreeSet::new();
    for execution in &plan.executable {
        if execution.case_id != plan.scan_run.case_id
            || execution.scan_run_id != plan.scan_run.id
            || !engine_run_ids.insert(execution.engine_run_id.as_str())
        {
            return Err(AppError::Internal(
                "planned scan dispatch identities are inconsistent or duplicated".into(),
            ));
        }
        JobKey::new(&execution.case_id, &execution.engine_run_id)
            .map_err(|error| AppError::InvalidRequest(error.to_string()))?;
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn validate_desktop_execution_with_runtime<F>(
    state: &CoreState,
    plan: &ScanPlan,
    mut runtime_preflight: F,
) -> AppResult<()>
where
    F: FnMut() -> AppResult<()>,
{
    validate_scan_dispatch_identity(plan)?;
    validate_provider_execution_demands(state, plan, Utc::now())
        .map_err(ProviderPreflightFailure::into_error)?;
    runtime_preflight().map_err(|_| DesktopExecutionBlocker::RuntimeUnavailable.into_error())?;
    // Managed runtime setup can take long enough for a short-lived provider
    // capability to expire or be consumed elsewhere. Recheck immediately
    // before dispatch. Callers decide whether the plan is already durable.
    validate_provider_execution_demands(state, plan, Utc::now())
        .map_err(ProviderPreflightFailure::into_error)
}

pub(crate) type TaskPreflightFailures =
    BTreeMap<PersistedScanPreflightFailureReason, Vec<PlannedEngineExecution>>;

#[derive(Clone, Default)]
pub(crate) struct PreparedRuntimeSet {
    pub(crate) fresh: Option<ProcessContainerRuntime>,
    pub(crate) recorded: Vec<PreparedRecordedRuntime>,
}

#[derive(Clone)]
pub(crate) struct PreparedRecordedRuntime {
    pub(crate) provider: RuntimeProvider,
    pub(crate) provenance: RuntimeCommandProvenance,
    pub(crate) runtime: ProcessContainerRuntime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RuntimePreparationIdentity {
    Fresh,
    Recorded {
        provider: RuntimeProvider,
        provenance: RuntimeCommandProvenance,
    },
}

pub(crate) struct RuntimePreparationGroup {
    pub(crate) identity: RuntimePreparationIdentity,
    pub(crate) executions: Vec<PlannedEngineExecution>,
}

pub(crate) struct RuntimeTaskPreparation {
    pub(crate) runnable: Vec<PlannedEngineExecution>,
    pub(crate) failures: TaskPreflightFailures,
    pub(crate) prepared_runtimes: PreparedRuntimeSet,
    pub(crate) cancelled: bool,
}

impl PreparedRuntimeSet {
    #[cfg(test)]
    pub(crate) fn with_fresh(runtime: ProcessContainerRuntime) -> Self {
        Self {
            fresh: Some(runtime),
            recorded: Vec::new(),
        }
    }

    pub(crate) fn runtime_for(
        &self,
        execution: &PlannedEngineExecution,
    ) -> Option<&ProcessContainerRuntime> {
        match execution.resume_checkpoint.as_ref() {
            Some(checkpoint) => match (
                checkpoint.runtime_provider,
                checkpoint.runtime_command_provenance.as_ref(),
            ) {
                (Some(provider), Some(provenance)) => self
                    .recorded
                    .iter()
                    .find(|prepared| {
                        prepared.provider == provider && &prepared.provenance == provenance
                    })
                    .map(|prepared| &prepared.runtime),
                (None, None) if checkpoint.cleanup_completed => self.fresh.as_ref(),
                _ => None,
            },
            None => self.fresh.as_ref(),
        }
    }

    pub(crate) fn insert_for_execution(
        &mut self,
        execution: &PlannedEngineExecution,
        runtime: ProcessContainerRuntime,
    ) -> AppResult<()> {
        match execution.resume_checkpoint.as_ref() {
            Some(checkpoint) => match (
                checkpoint.runtime_provider,
                checkpoint.runtime_command_provenance.as_ref(),
            ) {
                (Some(provider), Some(provenance)) => {
                    self.recorded.push(PreparedRecordedRuntime {
                        provider,
                        provenance: provenance.clone(),
                        runtime,
                    });
                    Ok(())
                }
                (None, None) if checkpoint.cleanup_completed => {
                    self.fresh = Some(runtime);
                    Ok(())
                }
                _ => Err(AppError::NotAuthorized(
                    "resumable execution has incomplete durable runtime provenance".into(),
                )),
            },
            None => {
                self.fresh = Some(runtime);
                Ok(())
            }
        }
    }
}

pub(crate) fn captured_resume_is_runtime_independent(execution: &PlannedEngineExecution) -> bool {
    // A managed-network identity is retained as historical provenance even
    // after its lease cleanup succeeds. `cleanup_completed` is the durable
    // obligation boundary; a completed captured checkpoint needs only bounded
    // artifact inspection and adapter normalization.
    execution
        .resume_checkpoint
        .as_ref()
        .is_some_and(|checkpoint| {
            checkpoint.resume_action() == ResumeAction::AdaptCapturedArtifacts
                && checkpoint.cleanup_completed
        })
}

pub(crate) struct PreparedPersistedNewScan {
    pub(crate) plan: ScanPlan,
    pub(crate) failures: TaskPreflightFailures,
    pub(crate) prepared_runtimes: Option<PreparedRuntimeSet>,
}

pub(crate) enum RuntimePreparationOutcome {
    Prepared(Box<ProcessContainerRuntime>),
    Cancelled,
    Unavailable,
}

#[cfg(test)]
pub(crate) fn prepare_runtime_with_deadline(
    resolve: impl FnOnce() -> AppResult<ProcessContainerRuntime> + Send + 'static,
    context: &JobContext,
    deadline: StdDuration,
) -> RuntimePreparationOutcome {
    prepare_runtime_with_deadline_tracked(resolve, context, deadline, None)
}

fn prepare_runtime_with_deadline_tracked(
    resolve: impl FnOnce() -> AppResult<ProcessContainerRuntime> + Send + 'static,
    context: &JobContext,
    deadline: StdDuration,
    tracker: Option<&Mutex<Vec<thread::JoinHandle<()>>>>,
) -> RuntimePreparationOutcome {
    let (sender, receiver) = mpsc::sync_channel(1);
    let spawned = thread::Builder::new()
        .name("scan-runtime-preflight".into())
        .spawn(move || {
            let prepared = resolve().and_then(|runtime| runtime.preflight().map(|_| runtime));
            let _ = sender.send(prepared.ok());
        });
    let handle = match spawned {
        Ok(handle) => handle,
        Err(_) => return RuntimePreparationOutcome::Unavailable,
    };
    if let Some(tracker) = tracker {
        tracker
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(handle);
    }
    let started = Instant::now();
    loop {
        if context.is_cancelled() {
            return RuntimePreparationOutcome::Cancelled;
        }
        let remaining = deadline.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            return RuntimePreparationOutcome::Unavailable;
        }
        match receiver.recv_timeout(remaining.min(SCAN_RUNTIME_PREPARATION_POLL)) {
            Ok(Some(runtime)) => return RuntimePreparationOutcome::Prepared(Box::new(runtime)),
            Ok(None) | Err(mpsc::RecvTimeoutError::Disconnected) => {
                return RuntimePreparationOutcome::Unavailable;
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
    }
}

pub(crate) fn plan_with_executions(
    plan: &ScanPlan,
    executions: Vec<PlannedEngineExecution>,
) -> ScanPlan {
    ScanPlan {
        scan_run: plan.scan_run.clone(),
        executable: executions,
        not_executed: plan.not_executed.clone(),
    }
}

pub(crate) fn inspect_persisted_new_scan_task(
    state: &CoreState,
    plan: &ScanPlan,
    execution: &PlannedEngineExecution,
) -> Result<(), PersistedScanPreflightFailureReason> {
    let task_plan = plan_with_executions(plan, vec![execution.clone()]);
    validate_scan_dispatch_identity(&task_plan)
        .map_err(|_| PersistedScanPreflightFailureReason::EngineExecutionContractInvalid)?;
    validate_provider_execution_demands(state, &task_plan, Utc::now())
        .map_err(|failure| failure.blocker().persisted_reason())?;
    validate_execution_inputs_static(state, &task_plan)
        .map_err(DesktopExecutionBlocker::persisted_reason)
}

pub(crate) fn merge_task_preflight_failures(
    destination: &mut TaskPreflightFailures,
    incoming: TaskPreflightFailures,
) {
    for (reason, mut executions) in incoming {
        destination
            .entry(reason)
            .or_default()
            .append(&mut executions);
    }
}

pub(crate) fn record_task_preflight_failure(
    failures: &mut TaskPreflightFailures,
    reason: PersistedScanPreflightFailureReason,
    executions: impl IntoIterator<Item = PlannedEngineExecution>,
) {
    failures.entry(reason).or_default().extend(executions);
}

pub(crate) fn runtime_preparation_identity(
    execution: &PlannedEngineExecution,
) -> Result<RuntimePreparationIdentity, PersistedScanPreflightFailureReason> {
    match execution.resume_checkpoint.as_ref() {
        Some(checkpoint) => match (
            checkpoint.runtime_provider,
            checkpoint.runtime_command_provenance.clone(),
        ) {
            (Some(provider), Some(provenance)) => Ok(RuntimePreparationIdentity::Recorded {
                provider,
                provenance,
            }),
            (None, None) if checkpoint.cleanup_completed => Ok(RuntimePreparationIdentity::Fresh),
            _ => Err(PersistedScanPreflightFailureReason::RuntimeUnavailable),
        },
        None => Ok(RuntimePreparationIdentity::Fresh),
    }
}

/// Prepares each shared runtime identity once. A failed or timed-out attempt is
/// fanned out as one honest task-scoped outcome for every dependent execution;
/// another task in the same run never repeats the same five-minute wait.
pub(crate) fn prepare_runtime_task_groups(
    executions: Vec<PlannedEngineExecution>,
    mut prepare: impl FnMut(
        &RuntimePreparationIdentity,
        &PlannedEngineExecution,
    ) -> RuntimePreparationOutcome,
) -> RuntimeTaskPreparation {
    let mut runnable = Vec::new();
    let mut failures = TaskPreflightFailures::new();
    let mut groups = Vec::<RuntimePreparationGroup>::new();

    for execution in executions {
        if captured_resume_is_runtime_independent(&execution) {
            runnable.push(execution);
            continue;
        }
        let identity = match runtime_preparation_identity(&execution) {
            Ok(identity) => identity,
            Err(reason) => {
                record_task_preflight_failure(&mut failures, reason, [execution]);
                continue;
            }
        };
        if let Some(group) = groups.iter_mut().find(|group| group.identity == identity) {
            group.executions.push(execution);
        } else {
            groups.push(RuntimePreparationGroup {
                identity,
                executions: vec![execution],
            });
        }
    }

    let mut prepared_runtimes = PreparedRuntimeSet::default();
    for group in groups {
        let representative = group
            .executions
            .first()
            .expect("runtime preparation groups are never empty");
        match prepare(&group.identity, representative) {
            RuntimePreparationOutcome::Prepared(runtime) => {
                if prepared_runtimes
                    .insert_for_execution(representative, *runtime)
                    .is_ok()
                {
                    runnable.extend(group.executions);
                } else {
                    record_task_preflight_failure(
                        &mut failures,
                        PersistedScanPreflightFailureReason::RuntimeUnavailable,
                        group.executions,
                    );
                }
            }
            RuntimePreparationOutcome::Unavailable => record_task_preflight_failure(
                &mut failures,
                PersistedScanPreflightFailureReason::RuntimeUnavailable,
                group.executions,
            ),
            RuntimePreparationOutcome::Cancelled => {
                return RuntimeTaskPreparation {
                    runnable,
                    failures,
                    prepared_runtimes,
                    cancelled: true,
                };
            }
        }
    }

    RuntimeTaskPreparation {
        runnable,
        failures,
        prepared_runtimes,
        cancelled: false,
    }
}

pub(crate) fn partition_persisted_new_scan_tasks(
    state: &CoreState,
    plan: &ScanPlan,
    executions: Vec<PlannedEngineExecution>,
) -> (Vec<PlannedEngineExecution>, TaskPreflightFailures) {
    let mut runnable = Vec::new();
    let mut failures = TaskPreflightFailures::new();
    for execution in executions {
        match inspect_persisted_new_scan_task(state, plan, &execution) {
            Ok(()) => runnable.push(execution),
            Err(reason) => failures.entry(reason).or_default().push(execution),
        }
    }
    (runnable, failures)
}

pub(crate) fn prepare_persisted_new_scan(
    app: &ScanCoordinator,
    plan: ScanPlan,
    context: &JobContext,
) -> PreparedPersistedNewScan {
    let state = app.state();
    // Slow preparation only computes typed outcomes. Durable failure writes
    // happen afterward through the live job's cancellation coordinator.
    let (mut runnable, mut failures) =
        partition_persisted_new_scan_tasks(state, &plan, plan.executable.clone());
    if runnable.is_empty() {
        return PreparedPersistedNewScan {
            plan: plan_with_executions(&plan, Vec::new()),
            failures,
            prepared_runtimes: None,
        };
    }

    let runtime_preparation = prepare_runtime_task_groups(runnable, |identity, _representative| {
        let runtime_app = app.clone();
        let identity = identity.clone();
        let resolve = move || {
            let state = runtime_app.state();
            match identity {
                RuntimePreparationIdentity::Recorded {
                    provider,
                    provenance,
                } => state.runtime_for_recorded_execution(provider, &provenance),
                RuntimePreparationIdentity::Fresh => state.runtime_for_execution(),
            }
        };
        prepare_runtime_with_deadline_tracked(
            resolve,
            context,
            SCAN_RUNTIME_PREPARATION_DEADLINE,
            Some(&app.preparers),
        )
    });
    merge_task_preflight_failures(&mut failures, runtime_preparation.failures);
    let prepared_runtimes = runtime_preparation.prepared_runtimes;
    if runtime_preparation.cancelled {
        return PreparedPersistedNewScan {
            plan: plan_with_executions(&plan, Vec::new()),
            failures,
            prepared_runtimes: Some(prepared_runtimes),
        };
    }
    let runtime_ready = runtime_preparation.runnable;

    // Runtime setup can take minutes. Repeat every task-local inspection so a
    // changed snapshot, gateway contract, or provider binding is not contacted.
    let (second_pass, second_failures) =
        partition_persisted_new_scan_tasks(state, &plan, runtime_ready);
    runnable = second_pass;
    merge_task_preflight_failures(&mut failures, second_failures);
    if runnable.is_empty() {
        return PreparedPersistedNewScan {
            plan: plan_with_executions(&plan, Vec::new()),
            failures,
            prepared_runtimes: Some(prepared_runtimes),
        };
    }

    PreparedPersistedNewScan {
        plan: plan_with_executions(&plan, runnable),
        failures,
        prepared_runtimes: Some(prepared_runtimes),
    }
}

#[cfg(feature = "desktop")]
pub(crate) fn start_persisted_scan_job(
    app: &ScanCoordinator,
    plan: ScanPlan,
) -> AppResult<AssessmentCase> {
    admit_persisted_scan_job(app, plan, false).map(|admission| admission.case)
}

fn admit_persisted_scan_job(
    app: &ScanCoordinator,
    plan: ScanPlan,
    owned: bool,
) -> AppResult<ScanAdmission> {
    if app.captured_recovery_only
        && plan
            .executable
            .iter()
            .any(|execution| !captured_resume_is_runtime_independent(execution))
    {
        return Err(AppError::NotAuthorized(
            "captured-result recovery cannot dispatch a new scanner execution".into(),
        ));
    }
    if plan.executable.is_empty() {
        let case = app
            .state()
            .case_service()
            .retain_terminal_report_snapshot(&plan.scan_run.case_id, &plan.scan_run.id)?;
        emit_inactive_scan_terminal(app, &case);
        return Ok(ScanAdmission::inactive(case));
    }

    let key = JobKey::new(plan.scan_run.case_id.clone(), plan.scan_run.id.clone())
        .map_err(|error| AppError::InvalidRequest(error.to_string()))?;
    let scoped = ScanCoordinator {
        cancel_on_sink_failure: owned,
        job_key: Some(key.clone()),
        ..app.clone()
    };
    let app = &scoped;
    let engine_run_ids = plan
        .executable
        .iter()
        .map(|execution| execution.engine_run_id.clone())
        .collect::<Vec<_>>();
    let worker_app = app.clone();
    let worker_plan = plan.clone();
    let terminal_app = app.clone();
    let terminal_key = key.clone();
    let before_start = app
        .state()
        .case_service()
        .show_case(&plan.scan_run.case_id)?;
    let started = app.state().jobs.start_owned_job(
        key,
        engine_run_ids,
        move |context| {
            if context.is_cancelled() {
                return cancel_new_scan_before_dispatch(
                    &worker_app,
                    &worker_plan.executable,
                    &context,
                );
            }
            run_persisted_new_scan_worker(worker_app, worker_plan, context)
        },
        move |snapshot| {
            if !owned && reconcile_terminal_job(&terminal_app, &terminal_key, &snapshot).is_err() {
                tracing::error!(
                    case_id = %terminal_key.case_id,
                    scan_run_id = %terminal_key.scan_run_id,
                    "terminal new-scan reconciliation failed"
                );
            }
        },
    );
    let admitted = match started {
        Ok(job) => job,
        Err(
            JobManagerError::DuplicateLiveJob(_)
            | JobManagerError::TerminalReconciliationPending(_),
        ) => {
            if owned {
                return Err(AppError::Conflict(
                    "the exact run already has an owner or awaits terminal reconciliation".into(),
                ));
            }
            // Concurrent Start/Resume is idempotent. Never turn an admission
            // race into a durable failure for the worker that already owns the
            // exact run; return the newest saved truth and let normal polling
            // follow it.
            let current = app
                .state()
                .case_service()
                .show_case(&plan.scan_run.case_id)?;
            let _ = emit(app, RUN_PROGRESS_EVENT, &current);
            return Ok(ScanAdmission::inactive(current));
        }
        Err(_admission_error) => {
            let state = app.state();
            let task_outcomes = plan
                .executable
                .iter()
                .map(|execution| PersistedPreDispatchTaskOutcome::Failed {
                    engine_run_id: execution.engine_run_id.clone(),
                    reason: ScanReadinessBlocker::ExecutionPreflightUnavailable,
                })
                .collect();
            let case = state
                .case_service()
                .transition_persisted_scan_pre_dispatch(
                    &plan.scan_run.case_id,
                    &plan.scan_run.id,
                    &PersistedPreDispatchTransition::ApplyOutcome { task_outcomes },
                )?;
            let case = state
                .case_service()
                .retain_terminal_report_snapshot(&case.id, &plan.scan_run.id)?;
            emit_inactive_scan_terminal(app, &case);
            return Ok(ScanAdmission::inactive(case));
        }
    };

    let queued_case = app
        .state()
        .case_service()
        .show_case(&plan.scan_run.case_id)
        .unwrap_or(before_start);
    if emit(app, RUN_PROGRESS_EVENT, &queued_case).is_err() {
        tracing::warn!("persisted scan queued event could not be emitted");
    }
    let snapshot = admitted.initial_snapshot().clone();
    Ok(ScanAdmission {
        case: queued_case,
        snapshot: Some(snapshot),
        owned_job: owned.then_some(admitted),
    })
}

#[cfg(feature = "desktop")]
pub(crate) fn requested_or_latest_run(
    service: &crate::case_service::CaseService<'_>,
    case_id: &str,
    requested: Option<&str>,
) -> AppResult<Id> {
    if let Some(run_id) = requested.filter(|value| !value.trim().is_empty()) {
        return Ok(run_id.to_owned());
    }
    service
        .show_case(case_id)?
        .scan_runs
        .last()
        .map(|run| run.id.clone())
        .ok_or_else(|| AppError::InvalidRequest("case has no scan run".into()))
}

pub(crate) fn durable_run_has_final_outcome(run: &ScanRun) -> bool {
    run.is_terminal_no_checks()
        || (!run.engine_runs.is_empty()
            && run.engine_runs.iter().all(|engine_run| {
                matches!(
                    engine_run.status,
                    EngineRunStatus::NotExecuted
                        | EngineRunStatus::Completed
                        | EngineRunStatus::PartiallyCompleted
                        | EngineRunStatus::Failed
                        | EngineRunStatus::Cancelled
                )
            }))
}

pub(crate) fn durable_run_needs_background_cleanup(run: &ScanRun) -> bool {
    run.engine_runs.iter().any(|engine_run| {
        matches!(
            engine_run.phase.as_str(),
            "cleanup_pending" | "interrupted_restart" | "interrupted_restart_cleanup_pending"
        )
    })
}

/// Identifies the exact durable handoff where one Naabu batch has already
/// been normalized but the worker disappeared before it could either plan the
/// next batch or observe Cancel. `PartiallyCompleted` is ordinarily terminal,
/// so this narrow state must be recognized before the generic final-outcome
/// shortcut or Cancel would silently leave unfinished work unchanged.
#[cfg(any(feature = "desktop", test))]
pub(crate) fn unfinished_clean_naabu_between_batch_cancel_target(
    run: &ScanRun,
) -> AppResult<Option<(Id, u32)>> {
    let mut target = None;
    for engine_run in &run.engine_runs {
        if engine_run.engine_id != NAABU_ENGINE_ID
            || engine_run.status != EngineRunStatus::PartiallyCompleted
            || engine_run.phase != "captured_awaiting_adapter"
            || engine_run.error_code.is_some()
            || engine_run.error_message.is_some()
        {
            continue;
        }
        let (Some(request), Some(result)) = (
            engine_run.naabu_attempt_requests.last(),
            engine_run.naabu_attempt_results.last(),
        ) else {
            continue;
        };
        if request.execution_attempt != result.execution_attempt || !result.normalization_complete {
            continue;
        }
        let plan = engine_run.naabu_work_plan.as_ref().ok_or_else(|| {
            AppError::Conflict(
                "normalized Naabu work is missing its immutable work plan before cancellation"
                    .into(),
            )
        })?;
        let cumulative = reduce_naabu_attempt_coverage(
            plan,
            &engine_run.naabu_attempt_requests,
            &engine_run.naabu_attempt_results,
        )
        .map_err(|error| {
            AppError::Conflict(format!(
                "saved Naabu result history is invalid before cancellation: {error}"
            ))
        })?;
        if cumulative.fully_complete {
            continue;
        }
        if target.is_some() {
            return Err(AppError::Conflict(
                "scan run contains more than one unfinished Naabu between-batch handoff".into(),
            ));
        }
        target = Some((engine_run.id.clone(), request.execution_attempt));
    }
    Ok(target)
}

/// Returns only tasks whose exact saved checkpoint proves that no scanner,
/// target connection, container, managed network, or captured evidence is
/// active. The CaseService transition revalidates the same identities before
/// committing all selected siblings together.
#[cfg(any(feature = "desktop", test))]
pub(crate) fn locally_cancellable_resource_free_engine_ids(run: &ScanRun) -> Vec<Id> {
    run.engine_runs
        .iter()
        .filter(|engine_run| {
            matches!(
                engine_run.status,
                EngineRunStatus::Queued | EngineRunStatus::Preparing | EngineRunStatus::Paused
            ) && matches!(
                engine_run.phase.as_str(),
                "queued"
                    | "queued_for_resume"
                    | "queued_for_next_phase"
                    | "preflight_preparing"
                    | "dispatch_activated"
            ) && engine_run.finished_at.is_none()
        })
        .filter_map(|engine_run| {
            let checkpoint = engine_run
                .resume_token
                .as_deref()
                .and_then(|token| ExecutionCheckpoint::from_resume_token(token).ok())?;
            (checkpoint.case_id == run.case_id
                && checkpoint.scan_run_id == run.id
                && checkpoint.engine_run_id == engine_run.id
                && checkpoint.engine_id == engine_run.engine_id
                && checkpoint.attempt > 0
                && checkpoint.stage == ExecutionStage::Planned
                && checkpoint.container_name.is_none()
                && checkpoint.scope_sha256.is_none()
                && checkpoint.launcher_plan_sha256.is_none()
                && checkpoint.artifact_ids.is_empty()
                && checkpoint.cleanup_completed
                && checkpoint.last_error.is_none()
                && checkpoint.managed_network.is_none())
            .then(|| engine_run.id.clone())
        })
        .collect()
}

#[cfg(any(feature = "desktop", test))]
pub(crate) enum NoWorkerCancelAdmission {
    #[cfg(feature = "desktop")]
    LiveAppeared,
    #[cfg(feature = "desktop")]
    TerminalAppeared(JobSnapshot),
    #[cfg(feature = "desktop")]
    ManagedLocalhost(AssessmentCase),
    CleanupPending(AssessmentCase),
    DurableUnchanged(AssessmentCase),
    DurableFinal(AssessmentCase),
    Cancelled(AssessmentCase),
}

#[cfg(feature = "desktop")]
pub(crate) struct NoWorkerCancelResolution {
    pub(crate) admission: NoWorkerCancelAdmission,
    pub(crate) needs_cleanup: bool,
}

#[cfg(any(feature = "desktop", test))]
pub(crate) fn apply_no_worker_durable_cancel(
    service: &crate::case_service::CaseService<'_>,
    case_id: &str,
    run_id: &str,
    durable: AssessmentCase,
) -> AppResult<NoWorkerCancelAdmission> {
    let run = durable
        .scan_runs
        .iter()
        .find(|run| run.id == run_id)
        .ok_or_else(|| AppError::InvalidRequest(format!("scan run not found: {run_id}")))?;
    let between_batch = unfinished_clean_naabu_between_batch_cancel_target(run)?;
    let resource_free_ids = locally_cancellable_resource_free_engine_ids(run);
    let needs_cleanup = durable_run_needs_background_cleanup(run);
    if !resource_free_ids.is_empty() || between_batch.is_some() {
        let naabu =
            between_batch.map(
                |(engine_run_id, completed_attempt)| NoWorkerNaabuCancellation {
                    engine_run_id,
                    completed_attempt,
                },
            );
        let current = service.cancel_no_worker_scan_work(
            case_id,
            run_id,
            &resource_free_ids,
            naabu.as_ref(),
        )?;
        return Ok(NoWorkerCancelAdmission::Cancelled(current));
    }

    let current_run = durable
        .scan_runs
        .iter()
        .find(|run| run.id == run_id)
        .ok_or_else(|| AppError::InvalidRequest(format!("scan run not found: {run_id}")))?;
    if durable_run_has_final_outcome(current_run) {
        return Ok(NoWorkerCancelAdmission::DurableFinal(durable));
    }
    if needs_cleanup {
        return Ok(NoWorkerCancelAdmission::CleanupPending(durable));
    }

    // A malformed, ambiguous, runtime-bearing, or evidence-bearing checkpoint
    // is not safe to relabel locally. Preserve it for reconciliation and keep
    // the UI in progress instead of inventing a finished cancellation.
    Ok(NoWorkerCancelAdmission::DurableUnchanged(durable))
}

#[cfg(feature = "desktop")]
pub(crate) fn coordinate_no_worker_cancel(
    state: &CoreState,
    key: &JobKey,
) -> AppResult<NoWorkerCancelResolution> {
    state.jobs.coordinate_admission(|| {
        match state.jobs.snapshot(key) {
            Some(snapshot) if snapshot.is_terminal() => {
                return Ok(NoWorkerCancelResolution {
                    admission: NoWorkerCancelAdmission::TerminalAppeared(snapshot),
                    needs_cleanup: false,
                });
            }
            Some(_) => {
                return Ok(NoWorkerCancelResolution {
                    admission: NoWorkerCancelAdmission::LiveAppeared,
                    needs_cleanup: false,
                });
            }
            None => {}
        }

        let service = state.case_service();
        let durable = service.show_case(&key.case_id)?;
        let run = durable
            .scan_runs
            .iter()
            .find(|run| run.id == key.scan_run_id)
            .ok_or_else(|| {
                AppError::InvalidRequest(format!("scan run not found: {}", key.scan_run_id))
            })?;
        let admission = if run_is_exact_localhost_quick_scan(run) {
            if durable_run_has_final_outcome(run) {
                NoWorkerCancelAdmission::DurableFinal(durable)
            } else {
                let prepared =
                    prepared_localhost_quick_scan_for_job(&durable, key)?.ok_or_else(|| {
                        AppError::Internal("localhost task identity disappeared".into())
                    })?;
                NoWorkerCancelAdmission::ManagedLocalhost(record_localhost_cancelled(
                    &state.storage,
                    state.engines.manifests(),
                    &prepared,
                    true,
                )?)
            }
        } else {
            apply_no_worker_durable_cancel(&service, &key.case_id, &key.scan_run_id, durable)?
        };
        let needs_cleanup = match &admission {
            NoWorkerCancelAdmission::ManagedLocalhost(case)
            | NoWorkerCancelAdmission::CleanupPending(case)
            | NoWorkerCancelAdmission::DurableUnchanged(case)
            | NoWorkerCancelAdmission::DurableFinal(case)
            | NoWorkerCancelAdmission::Cancelled(case) => case
                .scan_runs
                .iter()
                .find(|run| run.id == key.scan_run_id)
                .is_some_and(durable_run_needs_background_cleanup),
            NoWorkerCancelAdmission::LiveAppeared
            | NoWorkerCancelAdmission::TerminalAppeared(_) => false,
        };
        Ok(NoWorkerCancelResolution {
            admission,
            needs_cleanup,
        })
    })
}

#[cfg(feature = "desktop")]
pub(crate) fn emit_cancel_resolution(
    app: &ScanCoordinator,
    case: &AssessmentCase,
    run_id: &str,
    needs_cleanup: bool,
) -> AppResult<()> {
    let terminal = case
        .scan_runs
        .iter()
        .find(|run| run.id == run_id)
        .is_some_and(crate::report_snapshot::terminal_snapshot_ready)
        && !needs_cleanup;
    emit(
        app,
        if terminal {
            RUN_FINISHED_EVENT
        } else {
            RUN_PROGRESS_EVENT
        },
        case,
    )
}

#[cfg(feature = "desktop")]
pub(crate) fn finish_no_worker_cancel_resolution(
    app: &ScanCoordinator,
    state: &CoreState,
    key: &JobKey,
    resolution: NoWorkerCancelResolution,
    signal_live_if_appeared: bool,
) -> AppResult<AssessmentCase> {
    let needs_cleanup = resolution.needs_cleanup;
    if needs_cleanup {
        schedule_exact_runtime_cleanup_reconciliation(
            app,
            key.case_id.clone(),
            key.scan_run_id.clone(),
        );
    }
    match resolution.admission {
        NoWorkerCancelAdmission::TerminalAppeared(snapshot) => {
            match state.jobs.reconcile_terminal_snapshot(&snapshot, || {
                persist_terminal_job_state_reconciliation(state, key, &snapshot)
            })? {
                TerminalReconciliationOutcome::Reconciled(_)
                | TerminalReconciliationOutcome::NotCurrent => {
                    let next = coordinate_no_worker_cancel(state, key)?;
                    finish_no_worker_cancel_resolution(app, state, key, next, false)
                }
                TerminalReconciliationOutcome::InProgress => {
                    let case = state.case_service().show_case(&key.case_id)?;
                    let _ = emit(app, RUN_PROGRESS_EVENT, &case);
                    Ok(case)
                }
            }
        }
        NoWorkerCancelAdmission::LiveAppeared if signal_live_if_appeared => {
            signal_live_cancel_or_preserve_terminal(app, state, key)
        }
        NoWorkerCancelAdmission::LiveAppeared => {
            // A same-key generation appeared only after the prior live worker
            // vanished. Publish one bounded cancellation signal; if it also
            // crosses terminal now, the retained snapshot remains available
            // to the ordinary background reconciler.
            match state.jobs.cancel(key) {
                Ok(_) | Err(JobManagerError::CancellationPending(_)) => {}
                Err(JobManagerError::LiveJobNotFound(_)) => {}
                Err(error) => {
                    return Err(AppError::Runtime(format!(
                        "replacement scan cancellation could not be signalled: {error}"
                    )));
                }
            }
            let case = state.case_service().show_case(&key.case_id)?;
            let _ = emit(app, RUN_PROGRESS_EVENT, &case);
            Ok(case)
        }
        NoWorkerCancelAdmission::ManagedLocalhost(case)
        | NoWorkerCancelAdmission::CleanupPending(case)
        | NoWorkerCancelAdmission::DurableUnchanged(case)
        | NoWorkerCancelAdmission::DurableFinal(case)
        | NoWorkerCancelAdmission::Cancelled(case) => {
            if !needs_cleanup
                && case
                    .scan_runs
                    .iter()
                    .find(|run| run.id == key.scan_run_id)
                    .is_some_and(crate::report_snapshot::terminal_snapshot_ready)
            {
                // Cancel stays responsive even for a large report. The tracked
                // finisher owns verification, snapshot publication and Finished.
                let _ = emit(app, RUN_PROGRESS_EVENT, &case);
                schedule_exact_runtime_cleanup_reconciliation(
                    app,
                    key.case_id.clone(),
                    key.scan_run_id.clone(),
                );
            } else {
                let _ = emit_cancel_resolution(app, &case, &key.scan_run_id, needs_cleanup);
            }
            Ok(case)
        }
    }
}

#[cfg(feature = "desktop")]
pub(crate) fn signal_live_cancel_or_preserve_terminal(
    app: &ScanCoordinator,
    state: &CoreState,
    key: &JobKey,
) -> AppResult<AssessmentCase> {
    let durable = state.case_service().show_case(&key.case_id)?;
    if let Some(prepared) = prepared_localhost_quick_scan_for_job(&durable, key)? {
        return signal_live_localhost_cancel(app, state, key, &prepared);
    }
    match state.jobs.cancel(key) {
        Ok(_) | Err(JobManagerError::CancellationPending(_)) => {}
        Err(JobManagerError::LiveJobNotFound(_)) => {
            // The worker crossed its terminal boundary after the caller's
            // live snapshot. Re-enter the exact admission boundary: a clean
            // normalized between-batch handoff is durable user-cancellable
            // work, while all other terminal truth remains authoritative.
            let resolution = coordinate_no_worker_cancel(state, key)?;
            return finish_no_worker_cancel_resolution(app, state, key, resolution, false);
        }
        Err(error) => {
            return Err(AppError::Runtime(format!(
                "live scan cancellation could not be signalled: {error}"
            )));
        }
    }
    // The live worker owns stop, capture closure, credential zeroization,
    // container removal, and managed-egress cleanup. Do not mark the durable
    // run cancelled before that worker reports the real terminal result.
    let case = state.case_service().show_case(&key.case_id)?;
    let _ = emit(app, RUN_PROGRESS_EVENT, &case);
    Ok(case)
}

#[cfg(feature = "desktop")]
pub(crate) fn signal_live_localhost_cancel(
    app: &ScanCoordinator,
    state: &CoreState,
    key: &JobKey,
    prepared: &crate::localhost_quick_scan::PreparedLocalhostQuickScan,
) -> AppResult<AssessmentCase> {
    match state.jobs.cancel_with_durable_transition(key, || {
        record_localhost_cancel_transition(&state.storage, state.engines.manifests(), prepared)
    }) {
        Ok(Ok(DurableCancellationOutcome::Requested { durable, .. })) => {
            let _ = emit(app, RUN_PROGRESS_EVENT, &durable);
            Ok(durable)
        }
        Ok(Ok(DurableCancellationOutcome::TerminalWon { snapshot, durable })) => {
            if snapshot.is_terminal() {
                schedule_exact_terminal_reconciliation(app, key.clone(), snapshot);
            }
            let case = match durable {
                Some(case) => case,
                None => state.case_service().show_case(&key.case_id)?,
            };
            let _ = emit(app, RUN_PROGRESS_EVENT, &case);
            Ok(case)
        }
        Ok(Err(error)) => Err(error),
        Err(JobManagerError::LiveJobNotFound(_)) => {
            if let Some(snapshot) = state.jobs.snapshot(key)
                && snapshot.is_terminal()
            {
                schedule_exact_terminal_reconciliation(app, key.clone(), snapshot);
            }
            let case = state.case_service().show_case(&key.case_id)?;
            let _ = emit(app, RUN_PROGRESS_EVENT, &case);
            Ok(case)
        }
        Err(error) => Err(AppError::Runtime(format!(
            "localhost cancellation could not be coordinated: {error}"
        ))),
    }
}

#[cfg(feature = "desktop")]
pub(crate) fn cancel_scan_case(
    case_id: String,
    run_id: Option<String>,
    app: ScanCoordinator,
    state: &CoreState,
) -> AppResult<AssessmentCase> {
    let service = state.case_service();
    let run_id = requested_or_latest_run(&service, &case_id, run_id.as_deref())?;
    let key = JobKey::new(case_id.clone(), run_id.clone())
        .map_err(|error| AppError::InvalidRequest(error.to_string()))?;
    match state.jobs.snapshot(&key) {
        Some(snapshot) if snapshot.is_terminal() => {
            // Claim and persist authoritative worker truth first, without
            // cleanup or events. Only after that exact generation is either
            // acknowledged or already reconciled may this same Cancel close
            // work that is still durably unfinished.
            match state.jobs.reconcile_terminal_snapshot(&snapshot, || {
                persist_terminal_job_state_reconciliation(state, &key, &snapshot)
            })? {
                TerminalReconciliationOutcome::Reconciled(_)
                | TerminalReconciliationOutcome::NotCurrent => {}
                TerminalReconciliationOutcome::InProgress => {
                    let case = service.show_case(&case_id)?;
                    let _ = emit(&app, RUN_PROGRESS_EVENT, &case);
                    return Ok(case);
                }
            }
        }
        Some(_) => {
            return signal_live_cancel_or_preserve_terminal(&app, state, &key);
        }
        None => {}
    }
    let resolution = coordinate_no_worker_cancel(state, &key)?;
    finish_no_worker_cancel_resolution(&app, state, &key, resolution, true)
}

pub(crate) fn release_provider_execution_reservation(
    state: &CoreState,
    reservation: Option<ProviderExecutionReservation>,
    operation: &'static str,
) {
    let Some(reservation) = reservation else {
        return;
    };
    if state
        .source_authorizations
        .release_checkout_reservation(&reservation.handle)
        .is_err()
    {
        tracing::error!(
            operation,
            "provider checkout reservation could not be released"
        );
    }
}

pub(crate) fn release_after_provider_commit_error(
    state: &CoreState,
    reservation: ProviderExecutionReservation,
) {
    match state
        .source_authorizations
        .release_checkout_reservation(&reservation.handle)
    {
        Ok(()) | Err(AppError::NotAuthorized(_)) => {}
        Err(_) => tracing::error!(
            "provider checkout reservation could not be finalized after activation failed"
        ),
    }
}

pub(crate) fn map_provider_reservation_commit_error(error: AppError) -> ProviderPreflightFailure {
    match error {
        AppError::NotAuthorized(_) => ProviderPreflightFailure::CapabilityUnavailable,
        _ => ProviderPreflightFailure::PreflightUnavailable,
    }
}

/// Checks out one exact provider task only after its durable pre-dispatch
/// outcome authorized dispatch. A failure is therefore isolated to one
/// source/task and cannot suppress another account or local work.
pub(crate) fn reserve_and_commit_provider_execution(
    state: &CoreState,
    plan: &ScanPlan,
    execution: &PlannedEngineExecution,
) -> Result<Option<ReservedProviderExecutionBundle>, ProviderPreflightFailure> {
    if !execution_requires_provider_capability(execution) {
        return Ok(None);
    }
    let task_plan = plan_with_executions(plan, vec![execution.clone()]);
    let Some(reservation) = reserve_provider_execution_demands(state, &task_plan, Utc::now())?
    else {
        return Err(ProviderPreflightFailure::PreflightUnavailable);
    };
    match state
        .source_authorizations
        .commit_checkout_reservation(&reservation.handle, Utc::now())
    {
        Ok(()) => Ok(Some(ReservedProviderExecutionBundle {
            credentials: reservation.credentials,
            contexts: reservation.contexts,
        })),
        Err(error) => {
            let failure = map_provider_reservation_commit_error(error);
            release_after_provider_commit_error(state, reservation);
            Err(failure)
        }
    }
}

pub(crate) struct ReservedProviderExecutionBundle {
    pub(crate) credentials: ReservedScannerCredentialBundle,
    pub(crate) contexts: Vec<ProviderExecutionContext>,
}

impl ReservedProviderExecutionBundle {
    pub(crate) fn context_for(
        &self,
        execution: &PlannedEngineExecution,
    ) -> AppResult<&ProviderExecutionContext> {
        self.contexts
            .iter()
            .find(|context| context.engine_run_id == execution.engine_run_id)
            .ok_or_else(|| {
                AppError::NotAuthorized(
                    "provider execution has no reserved dispatch connection context".into(),
                )
            })
    }

    pub(crate) fn take_credentials(
        &mut self,
        execution: &PlannedEngineExecution,
        context: &ProviderExecutionContext,
    ) -> AppResult<ScannerCredentialSet> {
        self.credentials.take(
            &execution.case_id,
            &context.source.id,
            &execution.manifest.id,
        )
    }
}

pub(crate) fn mark_preflight_tasks_failed(
    executions: &[PlannedEngineExecution],
    context: &JobContext,
) {
    for execution in executions {
        if let Ok(control) = context.engine(&execution.engine_run_id) {
            let _ = control.mark_failed();
        }
    }
}

pub(crate) fn cancel_new_scan_before_dispatch(
    app: &ScanCoordinator,
    executions: &[PlannedEngineExecution],
    context: &JobContext,
) -> JobCompletion {
    let engine_run_ids = executions
        .iter()
        .map(|execution| execution.engine_run_id.clone())
        .collect::<Vec<_>>();
    if engine_run_ids.is_empty() {
        return JobCompletion::Cancelled;
    }
    let state = app.state();
    let cancelled = retry_pre_dispatch_cancellation(
        || {
            context.coordinate_durable_write(|| {
                state.case_service().transition_persisted_scan_pre_dispatch(
                    context.key().case_id.as_str(),
                    context.key().scan_run_id.as_str(),
                    &PersistedPreDispatchTransition::Cancel {
                        engine_run_ids: engine_run_ids.clone(),
                    },
                )
            })
        },
        || thread::sleep(PRE_DISPATCH_CANCEL_RETRY_DELAY),
    );
    let case = match cancelled {
        Ok(case) => case,
        Err(error) => {
            tracing::error!(
                error = %error,
                case_id = %context.key().case_id,
                scan_run_id = %context.key().scan_run_id,
                attempts = PRE_DISPATCH_CANCEL_PERSISTENCE_ATTEMPTS,
                "pre-dispatch cancellation exhausted its bounded durable retry budget"
            );
            // No provider checkout or target contact has happened. Finish the
            // in-memory worker as an explicit persistence-pending failure;
            // the terminal callback gets one more ordinary report write and
            // startup recovery deterministically terminalizes any remaining
            // resource-free pre-dispatch state.
            return JobCompletion::PersistencePending;
        }
    };
    let _ = emit(app, RUN_PROGRESS_EVENT, &case);
    for execution in executions {
        if let Ok(control) = context.engine(&execution.engine_run_id) {
            let _ = control.mark_cancelled();
        }
    }
    JobCompletion::Cancelled
}

pub(crate) fn retry_pre_dispatch_cancellation<T>(
    mut write: impl FnMut() -> AppResult<T>,
    mut wait: impl FnMut(),
) -> AppResult<T> {
    let mut last_retryable = None;
    for attempt in 0..PRE_DISPATCH_CANCEL_PERSISTENCE_ATTEMPTS {
        match write() {
            Ok(value) => return Ok(value),
            Err(error @ (AppError::Conflict(_) | AppError::Storage(_))) => {
                last_retryable = Some(error);
                if attempt + 1 < PRE_DISPATCH_CANCEL_PERSISTENCE_ATTEMPTS {
                    wait();
                }
            }
            Err(error) => return Err(error),
        }
    }
    Err(last_retryable.expect("at least one cancellation persistence attempt ran"))
}

pub(crate) fn complete_preflight_outcomes(
    plan: &ScanPlan,
    runnable: &[PlannedEngineExecution],
    failures: &TaskPreflightFailures,
) -> AppResult<Vec<PersistedPreDispatchTaskOutcome>> {
    let runnable_ids = runnable
        .iter()
        .map(|execution| execution.engine_run_id.as_str())
        .collect::<BTreeSet<_>>();
    let mut failure_reasons = BTreeMap::new();
    for (reason, executions) in failures {
        for execution in executions {
            if failure_reasons
                .insert(execution.engine_run_id.as_str(), *reason)
                .is_some()
            {
                return Err(AppError::Internal(
                    "preflight produced two outcomes for one engine run".into(),
                ));
            }
        }
    }
    let mut outcomes = Vec::with_capacity(plan.executable.len());
    for execution in &plan.executable {
        if let Some(reason) = failure_reasons.remove(execution.engine_run_id.as_str()) {
            outcomes.push(PersistedPreDispatchTaskOutcome::Failed {
                engine_run_id: execution.engine_run_id.clone(),
                reason,
            });
        } else if runnable_ids.contains(execution.engine_run_id.as_str()) {
            outcomes.push(PersistedPreDispatchTaskOutcome::Runnable {
                engine_run_id: execution.engine_run_id.clone(),
            });
        } else {
            return Err(AppError::Internal(
                "preflight omitted an engine run from its complete outcome".into(),
            ));
        }
    }
    if !failure_reasons.is_empty() {
        return Err(AppError::Internal(
            "preflight outcome refers to an execution outside its persisted plan".into(),
        ));
    }
    Ok(outcomes)
}

pub(crate) fn run_persisted_new_scan_worker(
    app: ScanCoordinator,
    plan: ScanPlan,
    context: JobContext,
) -> JobCompletion {
    let all_executions = plan.executable.clone();
    let all_ids = all_executions
        .iter()
        .map(|execution| execution.engine_run_id.clone())
        .collect::<Vec<_>>();

    let preparing = {
        let state = app.state();
        context.activate_with_transition(|| {
            state.case_service().transition_persisted_scan_pre_dispatch(
                context.key().case_id.as_str(),
                context.key().scan_run_id.as_str(),
                &PersistedPreDispatchTransition::Preparing {
                    engine_run_ids: all_ids.clone(),
                },
            )
        })
    };
    match preparing {
        JobActivationOutcome::Activated(case) => {
            if emit(&app, RUN_PROGRESS_EVENT, &case).is_err() {
                tracing::warn!("scan preparing event could not be emitted");
            }
        }
        JobActivationOutcome::Cancelled => {
            return cancel_new_scan_before_dispatch(&app, &all_executions, &context);
        }
        JobActivationOutcome::Failed(_) => {
            mark_preflight_tasks_failed(&all_executions, &context);
            return JobCompletion::Failed;
        }
    }

    let prepared = prepare_persisted_new_scan(&app, plan.clone(), &context);
    if context.is_cancelled() {
        return cancel_new_scan_before_dispatch(&app, &all_executions, &context);
    }
    let runnable = prepared.plan.executable;
    let task_outcomes = match complete_preflight_outcomes(&plan, &runnable, &prepared.failures) {
        Ok(outcomes) => outcomes,
        Err(_) => {
            mark_preflight_tasks_failed(&all_executions, &context);
            return JobCompletion::Failed;
        }
    };
    let activation = {
        let state = app.state();
        context.activate_with_transition(|| {
            state.case_service().transition_persisted_scan_pre_dispatch(
                context.key().case_id.as_str(),
                context.key().scan_run_id.as_str(),
                &PersistedPreDispatchTransition::ApplyOutcome { task_outcomes },
            )
        })
    };
    match activation {
        JobActivationOutcome::Activated(case) => {
            if emit(&app, RUN_PROGRESS_EVENT, &case).is_err() {
                tracing::warn!("scan activation event could not be emitted");
            }
        }
        JobActivationOutcome::Cancelled => {
            return cancel_new_scan_before_dispatch(&app, &all_executions, &context);
        }
        JobActivationOutcome::Failed(_) => {
            mark_preflight_tasks_failed(&all_executions, &context);
            return JobCompletion::Failed;
        }
    }
    for executions in prepared.failures.values() {
        mark_preflight_tasks_failed(executions, &context);
    }
    if context.is_cancelled() {
        return cancel_new_scan_before_dispatch(&app, &all_executions, &context);
    }
    if runnable.is_empty() {
        return JobCompletion::Failed;
    }

    let prepared_runtimes = match prepared.prepared_runtimes {
        Some(runtimes) => runtimes,
        None => {
            mark_preflight_tasks_failed(&runnable, &context);
            return JobCompletion::Failed;
        }
    };
    run_scan_worker(
        app,
        plan_with_executions(&plan, runnable),
        prepared_runtimes,
        context,
    )
}

pub(crate) fn emit_inactive_scan_terminal(app: &ScanCoordinator, case: &AssessmentCase) {
    if let Err(error) = emit(app, RUN_PROGRESS_EVENT, case) {
        tracing::warn!(
            error = %error,
            "inactive scan was terminalized but its final progress event was not emitted"
        );
    }
    if let Err(error) = emit(app, RUN_FINISHED_EVENT, case) {
        tracing::warn!(
            error = %error,
            "inactive scan was terminalized but its finished event was not emitted"
        );
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DurableWorkerTaskOutcome {
    Completed,
    Cancelled,
    Failed,
}

pub(crate) fn finish_worker_task_from_durable_case(
    control: &EngineJobControl,
    execution: &PlannedEngineExecution,
    applied: &AssessmentCase,
    captured_stage: Option<&ExecutionStage>,
) -> DurableWorkerTaskOutcome {
    let durable_outcome = applied
        .scan_runs
        .iter()
        .find(|run| run.id == execution.scan_run_id)
        .and_then(|run| {
            run.engine_runs
                .iter()
                .find(|engine_run| engine_run.id == execution.engine_run_id)
        })
        .map(|engine_run| (engine_run.status.clone(), engine_run.phase.clone()));
    match durable_outcome.as_ref() {
        Some((EngineRunStatus::Completed, _)) => {
            if control.mark_completed().is_ok() {
                DurableWorkerTaskOutcome::Completed
            } else {
                DurableWorkerTaskOutcome::Failed
            }
        }
        Some((EngineRunStatus::PartiallyCompleted, phase)) if phase != "cleanup_pending" => {
            if control.mark_completed().is_ok() {
                DurableWorkerTaskOutcome::Completed
            } else {
                DurableWorkerTaskOutcome::Failed
            }
        }
        Some((EngineRunStatus::Cancelled, _)) => {
            let _ = control.mark_cancelled();
            DurableWorkerTaskOutcome::Cancelled
        }
        _ => {
            tracing::warn!(
                case_id = %execution.case_id,
                scan_run_id = %execution.scan_run_id,
                engine_run_id = %execution.engine_run_id,
                captured_stage = ?captured_stage,
                durable_outcome = ?durable_outcome,
                "scanner worker ended without a durable completed or cancelled task"
            );
            let _ = control.mark_failed();
            DurableWorkerTaskOutcome::Failed
        }
    }
}

pub(crate) fn is_naabu_launcher_v2_adapter_resume(execution: &PlannedEngineExecution) -> bool {
    manifest_uses_naabu_launcher_v2(&execution.manifest)
        && captured_resume_is_runtime_independent(execution)
        && execution
            .resume_checkpoint
            .as_ref()
            .is_some_and(|checkpoint| {
                checkpoint.engine_id == NAABU_ENGINE_ID
                    && checkpoint.launcher_plan_sha256.is_some()
                    && matches!(
                        checkpoint.stage,
                        ExecutionStage::CapturedAwaitingAdapter | ExecutionStage::AdaptingArtifacts
                    )
            })
}

pub(crate) fn continued_naabu_launcher_v2_execution(
    current: &PlannedEngineExecution,
    case: &AssessmentCase,
) -> AppResult<PlannedEngineExecution> {
    if !manifest_uses_naabu_launcher_v2(&current.manifest) {
        return Err(AppError::InvalidRequest(
            "only launcher-v2 Naabu work can continue inside one scan job".into(),
        ));
    }
    let run = case
        .scan_runs
        .iter()
        .find(|run| run.id == current.scan_run_id && run.case_id == current.case_id)
        .ok_or_else(|| AppError::Conflict("continued scan run is no longer current".into()))?;
    let engine_run = run
        .engine_runs
        .iter()
        .find(|engine_run| engine_run.id == current.engine_run_id)
        .ok_or_else(|| AppError::Conflict("continued scanner task is no longer current".into()))?;
    if engine_run.engine_id != NAABU_ENGINE_ID
        || engine_run.status != EngineRunStatus::Queued
        || engine_run.phase != "queued_for_next_phase"
        || engine_run.error_code.is_some()
        || engine_run.error_message.is_some()
    {
        return Err(AppError::NotAuthorized(
            "continued scanner task is not in the exact saved next-phase state".into(),
        ));
    }
    let checkpoint = engine_run
        .resume_token
        .as_deref()
        .map(ExecutionCheckpoint::from_resume_token)
        .transpose()?
        .ok_or_else(|| {
            AppError::Conflict("continued scanner task has no saved checkpoint".into())
        })?;
    let expected_attempt = current
        .attempt
        .checked_add(1)
        .ok_or_else(|| AppError::Conflict("scanner attempt sequence overflowed".into()))?;
    let resource_free = checkpoint.container_name.is_none()
        && checkpoint.scope_sha256.is_none()
        && checkpoint.launcher_plan_sha256.is_none()
        && checkpoint.artifact_ids.is_empty()
        && checkpoint.cleanup_completed
        && checkpoint.runtime_command_provenance.is_none()
        && checkpoint.runtime_provider.is_none()
        && checkpoint.managed_network.is_none();
    if checkpoint.case_id != current.case_id
        || checkpoint.scan_run_id != current.scan_run_id
        || checkpoint.engine_run_id != current.engine_run_id
        || checkpoint.engine_id != NAABU_ENGINE_ID
        || checkpoint.attempt != expected_attempt
        || checkpoint.stage != ExecutionStage::Planned
        || checkpoint.last_error.is_some()
        || !resource_free
        || !engine_run
            .naabu_attempt_requests
            .iter()
            .any(|request| request.execution_attempt == expected_attempt)
    {
        return Err(AppError::NotAuthorized(
            "continued scanner task does not match its exact resource-free saved request".into(),
        ));
    }

    let mut next = current.clone();
    next.attempt = expected_attempt;
    next.resume_checkpoint = Some(checkpoint);
    next.naabu_work_plan = engine_run.naabu_work_plan.clone();
    Ok(next)
}

#[derive(Debug)]
pub(crate) enum NaabuPostBatchSettlement {
    NotApplicable,
    Cancelled(AssessmentCase),
    ContinuationPlanned(AssessmentCase),
    TerminalPartial(AssessmentCase),
    WorkComplete,
}

pub(crate) fn clean_normalized_naabu_batch_awaits_continuation(
    case: &AssessmentCase,
    execution: &PlannedEngineExecution,
) -> bool {
    case.scan_runs
        .iter()
        .find(|run| run.id == execution.scan_run_id && run.case_id == execution.case_id)
        .and_then(|run| {
            run.engine_runs
                .iter()
                .find(|engine_run| engine_run.id == execution.engine_run_id)
        })
        .is_some_and(|engine_run| {
            engine_run.engine_id == NAABU_ENGINE_ID
                && engine_run.status == EngineRunStatus::PartiallyCompleted
                && engine_run.phase == "captured_awaiting_adapter"
                && engine_run.error_code.is_none()
                && engine_run.error_message.is_none()
                && engine_run
                    .naabu_attempt_requests
                    .last()
                    .is_some_and(|request| request.execution_attempt == execution.attempt)
                && engine_run
                    .naabu_attempt_results
                    .last()
                    .is_some_and(|result| {
                        result.execution_attempt == execution.attempt
                            && result.normalization_complete
                    })
        })
}

/// Makes the between-batch decision beneath the same per-job coordinator used
/// by Cancel. If cancellation was already published, its durable lifecycle
/// transition is saved instead of planning another attempt. If it arrives
/// afterward, the newly saved resource-free attempt is cancelled by the next
/// worker iteration before target contact.
pub(crate) fn settle_clean_naabu_launcher_v2_batch(
    state: &CoreState,
    context: &JobContext,
    execution: &PlannedEngineExecution,
    durable: &AssessmentCase,
) -> AppResult<NaabuPostBatchSettlement> {
    if !manifest_uses_naabu_launcher_v2(&execution.manifest)
        || !clean_normalized_naabu_batch_awaits_continuation(durable, execution)
    {
        return Ok(NaabuPostBatchSettlement::NotApplicable);
    }

    context.coordinate_durable_write(|| {
        if context.is_cancelled() {
            state
                .case_service()
                .cancel_naabu_launcher_v2_remaining_work(
                    &execution.case_id,
                    &execution.scan_run_id,
                    &execution.engine_run_id,
                    execution.attempt,
                )
                .map(NaabuPostBatchSettlement::Cancelled)
        } else {
            let next = state
                .case_service()
                .plan_next_naabu_launcher_v2_attempt(
                    &execution.case_id,
                    &execution.scan_run_id,
                    &execution.engine_run_id,
                    execution.attempt,
                )?;
            let Some(case) = next else {
                return Ok(NaabuPostBatchSettlement::WorkComplete);
            };
            let engine_run = case
                .scan_runs
                .iter()
                .find(|run| {
                    run.id == execution.scan_run_id && run.case_id == execution.case_id
                })
                .and_then(|run| {
                    run.engine_runs
                        .iter()
                        .find(|engine_run| engine_run.id == execution.engine_run_id)
                })
                .ok_or_else(|| {
                    AppError::Conflict(
                        "Naabu continuation result lost its exact durable engine run".into(),
                    )
                })?;
            match (&engine_run.status, engine_run.phase.as_str()) {
                (EngineRunStatus::Queued, "queued_for_next_phase") => {
                    Ok(NaabuPostBatchSettlement::ContinuationPlanned(case))
                }
                (EngineRunStatus::PartiallyCompleted, "results_partial") => {
                    Ok(NaabuPostBatchSettlement::TerminalPartial(case))
                }
                _ => Err(AppError::Conflict(
                    "Naabu continuation produced neither a queued batch nor a terminal partial result"
                        .into(),
                )),
            }
        }
    })
}

fn settle_worker_naabu_batch(
    app: &ScanCoordinator,
    context: &JobContext,
    execution: &PlannedEngineExecution,
    durable: &AssessmentCase,
) -> AppResult<NaabuPostBatchSettlement> {
    if app.captured_recovery_only {
        // Normalization preserves the saved coverage and pending work. A
        // result-only recovery never plans or dispatches another target batch.
        return Ok(NaabuPostBatchSettlement::NotApplicable);
    }
    settle_clean_naabu_launcher_v2_batch(app.state(), context, execution, durable)
}

pub(crate) fn run_scan_worker(
    app: ScanCoordinator,
    plan: ScanPlan,
    prepared_runtimes: PreparedRuntimeSet,
    context: JobContext,
) -> JobCompletion {
    let state = app.state();
    let mut failed = false;
    let mut cancelled = false;

    let mut prioritized_executions = plan.executable.clone();
    prioritize_first_meaningful_results(&mut prioritized_executions);
    let mut pending_executions = VecDeque::from(prioritized_executions);
    while let Some(execution) = pending_executions.pop_front() {
        let Ok(control) = context.engine(&execution.engine_run_id) else {
            failed = true;
            continue;
        };
        if !context.wait_until_runnable() || context.is_cancelled() {
            let report = terminal_report(
                &execution,
                ExecutionStage::Cancelled,
                "scan cancellation was requested before this engine started",
            );
            let _ = context.coordinate_durable_write(|| {
                state
                    .case_service()
                    .apply_execution_report(&execution.case_id, &report)
            });
            let _ = control.mark_cancelled();
            cancelled = true;
            continue;
        }
        if is_naabu_launcher_v2_adapter_resume(&execution) {
            if control.mark_running().is_err() {
                failed = true;
                continue;
            }
            match context.coordinate_durable_write(|| {
                state.case_service().resume_naabu_launcher_v2_adaptation(
                    &execution.case_id,
                    &execution.scan_run_id,
                    &execution.engine_run_id,
                    execution.attempt,
                )
            }) {
                Ok(applied) => {
                    let _ = emit(&app, RUN_PROGRESS_EVENT, &applied);
                    let mut durable = applied;
                    match settle_worker_naabu_batch(&app, &context, &execution, &durable) {
                        Ok(NaabuPostBatchSettlement::Cancelled(cancelled_case)) => {
                            let _ = emit(&app, RUN_PROGRESS_EVENT, &cancelled_case);
                            durable = cancelled_case;
                        }
                        Ok(NaabuPostBatchSettlement::TerminalPartial(partial_case)) => {
                            let _ = emit(&app, RUN_PROGRESS_EVENT, &partial_case);
                            durable = partial_case;
                        }
                        Ok(NaabuPostBatchSettlement::ContinuationPlanned(next_case)) => {
                            match continued_naabu_launcher_v2_execution(&execution, &next_case) {
                                Ok(next_execution) => {
                                    let _ = emit(&app, RUN_PROGRESS_EVENT, &next_case);
                                    pending_executions.push_back(next_execution);
                                    continue;
                                }
                                Err(error) => {
                                    tracing::error!(
                                        case_id = %execution.case_id,
                                        scan_run_id = %execution.scan_run_id,
                                        engine_run_id = %execution.engine_run_id,
                                        error = %error,
                                        "saved next scanner phase could not be reconstructed after result-only resume"
                                    );
                                    durable = next_case;
                                }
                            }
                        }
                        Ok(
                            NaabuPostBatchSettlement::NotApplicable
                            | NaabuPostBatchSettlement::WorkComplete,
                        ) => {}
                        Err(error) => {
                            tracing::warn!(
                                case_id = %execution.case_id,
                                scan_run_id = %execution.scan_run_id,
                                engine_run_id = %execution.engine_run_id,
                                execution_attempt = execution.attempt,
                                error = %error,
                                "result-only resume stayed partial"
                            );
                            if let Ok(current) = state.case_service().show_case(&execution.case_id)
                            {
                                durable = current;
                            }
                        }
                    }
                    match finish_worker_task_from_durable_case(&control, &execution, &durable, None)
                    {
                        DurableWorkerTaskOutcome::Completed => {}
                        DurableWorkerTaskOutcome::Cancelled => cancelled = true,
                        DurableWorkerTaskOutcome::Failed => failed = true,
                    }
                }
                Err(error) => {
                    tracing::warn!(
                        case_id = %execution.case_id,
                        scan_run_id = %execution.scan_run_id,
                        engine_run_id = %execution.engine_run_id,
                        error = %error,
                        "host-only launcher-v2 result resume could not be reconciled"
                    );
                    let _ = control.mark_failed();
                    failed = true;
                }
            }
            continue;
        }
        let mut reserved_provider = if execution_requires_provider_capability(&execution) {
            let checkout = context.activate_with_transition(|| {
                reserve_and_commit_provider_execution(state, &plan, &execution)
            });
            match checkout {
                JobActivationOutcome::Activated(bundle) => bundle,
                JobActivationOutcome::Cancelled => {
                    let report = terminal_report(
                        &execution,
                        ExecutionStage::Cancelled,
                        "scan cancellation was requested before provider checkout",
                    );
                    let _ = context.coordinate_durable_write(|| {
                        state
                            .case_service()
                            .apply_execution_report(&execution.case_id, &report)
                    });
                    let _ = control.mark_cancelled();
                    cancelled = true;
                    continue;
                }
                JobActivationOutcome::Failed(reason) => {
                    let transition = PersistedPreDispatchTransition::FailActivated {
                        task_failures: vec![PersistedPreDispatchTaskOutcome::Failed {
                            engine_run_id: execution.engine_run_id.clone(),
                            reason: reason.blocker().persisted_reason(),
                        }],
                    };
                    if let Ok(case) = context.coordinate_durable_write(|| {
                        state.case_service().transition_persisted_scan_pre_dispatch(
                            &execution.case_id,
                            &execution.scan_run_id,
                            &transition,
                        )
                    }) {
                        let _ = emit(&app, RUN_PROGRESS_EVENT, &case);
                    }
                    let _ = control.mark_failed();
                    failed = true;
                    continue;
                }
            }
        } else {
            None
        };
        // Cancellation published during a successful provider checkout is
        // observed here before any network/runtime call. Capacity belongs to
        // the already-durable dispatch-authorized attempt; no target contact
        // occurs.
        if context.is_cancelled() {
            drop(reserved_provider);
            let report = terminal_report(
                &execution,
                ExecutionStage::Cancelled,
                "scan cancellation was requested before this engine contacted its target",
            );
            let _ = context.coordinate_durable_write(|| {
                state
                    .case_service()
                    .apply_execution_report(&execution.case_id, &report)
            });
            let _ = control.mark_cancelled();
            cancelled = true;
            continue;
        }
        if control.mark_running().is_err() {
            failed = true;
            continue;
        }

        let artifacts = ArtifactStore::open(state.artifact_root());
        let outcome = match &artifacts {
            Ok(artifacts) if captured_resume_is_runtime_independent(&execution) => {
                resume_captured_execution(state, artifacts, &execution)
            }
            Ok(artifacts) => match prepared_runtimes.runtime_for(&execution) {
                Some(runtime) => execute_planned_engine(
                    PlannedEngineExecutionContext {
                        app: &app,
                        state,
                        runtime,
                        artifacts,
                        cancellation: &control.cancellation_token(),
                        job_context: &context,
                    },
                    &execution,
                    reserved_provider.as_mut(),
                ),
                None => Err(AppError::Internal(
                    "scan worker received no prepared runtime matching its durable execution"
                        .into(),
                )),
            },
            Err(error) => Err(AppError::Runtime(error.to_string())),
        };

        match outcome {
            Ok(report) => {
                let stage = report.checkpoint.stage.clone();
                match context.coordinate_durable_write(|| {
                    apply_worker_execution_report(state, &execution, &report)
                }) {
                    Ok(applied) => {
                        let _ = emit(&app, RUN_PROGRESS_EVENT, &applied);
                        let mut durable = applied;
                        match settle_worker_naabu_batch(&app, &context, &execution, &durable) {
                            Ok(NaabuPostBatchSettlement::Cancelled(cancelled_case)) => {
                                let _ = emit(&app, RUN_PROGRESS_EVENT, &cancelled_case);
                                durable = cancelled_case;
                            }
                            Ok(NaabuPostBatchSettlement::TerminalPartial(partial_case)) => {
                                let _ = emit(&app, RUN_PROGRESS_EVENT, &partial_case);
                                durable = partial_case;
                            }
                            Ok(NaabuPostBatchSettlement::ContinuationPlanned(next_case)) => {
                                match continued_naabu_launcher_v2_execution(&execution, &next_case)
                                {
                                    Ok(next_execution) => {
                                        let _ = emit(&app, RUN_PROGRESS_EVENT, &next_case);
                                        // Give every independent check its first
                                        // useful pass before deeper inventory
                                        // batches continue.
                                        pending_executions.push_back(next_execution);
                                        continue;
                                    }
                                    Err(error) => {
                                        tracing::error!(
                                            case_id = %execution.case_id,
                                            scan_run_id = %execution.scan_run_id,
                                            engine_run_id = %execution.engine_run_id,
                                            error = %error,
                                            "saved next scanner phase could not be reconstructed"
                                        );
                                        durable = next_case;
                                    }
                                }
                            }
                            Ok(
                                NaabuPostBatchSettlement::NotApplicable
                                | NaabuPostBatchSettlement::WorkComplete,
                            ) => {}
                            Err(error) => {
                                tracing::warn!(
                                    case_id = %execution.case_id,
                                    scan_run_id = %execution.scan_run_id,
                                    engine_run_id = %execution.engine_run_id,
                                    execution_attempt = execution.attempt,
                                    error = %error,
                                    "scanner phase continuation stopped"
                                );
                                if let Ok(current) =
                                    state.case_service().show_case(&execution.case_id)
                                {
                                    durable = current;
                                }
                            }
                        }
                        match finish_worker_task_from_durable_case(
                            &control,
                            &execution,
                            &durable,
                            Some(&stage),
                        ) {
                            DurableWorkerTaskOutcome::Completed => {}
                            DurableWorkerTaskOutcome::Cancelled => cancelled = true,
                            DurableWorkerTaskOutcome::Failed => failed = true,
                        }
                    }
                    Err(_) => {
                        let _ = control.mark_failed();
                        failed = true;
                    }
                }
            }
            Err(error) => {
                let report = terminal_report(
                    &execution,
                    if control.cancellation_token().is_cancelled() {
                        ExecutionStage::Cancelled
                    } else {
                        ExecutionStage::Failed
                    },
                    &bounded_error(&error),
                );
                if let Ok(applied) = context.coordinate_durable_write(|| {
                    state
                        .case_service()
                        .apply_execution_report(&execution.case_id, &report)
                }) {
                    let _ = emit(&app, RUN_PROGRESS_EVENT, &applied.case);
                }
                if report.checkpoint.stage == ExecutionStage::Cancelled {
                    let _ = control.mark_cancelled();
                    cancelled = true;
                } else {
                    let _ = control.mark_failed();
                    failed = true;
                }
            }
        }
    }

    if failed {
        JobCompletion::Failed
    } else if cancelled || context.is_cancelled() {
        JobCompletion::Cancelled
    } else {
        JobCompletion::Completed
    }
}

/// Changes only the in-memory worker queue. The durable run plan and every
/// engine/asset identity remain untouched, while quick finding-capable checks
/// finish early and the unified report remains reserved for terminal results.
pub(crate) fn prioritize_first_meaningful_results(executions: &mut [PlannedEngineExecution]) {
    executions.sort_by_key(|execution| beginner_execution_priority(&execution.manifest.id));
}

pub(crate) fn beginner_execution_priority(engine_id: &str) -> u8 {
    match engine_id {
        "gitleaks" => 0,
        "nuclei" => 1,
        "semgrep" => 2,
        "trivy" => 3,
        "trufflehog" => 4,
        "kics" => 5,
        "checkov" => 6,
        // Greenbone can use the full deep-network execution window for each
        // device. Do not make every remaining repository result wait behind it.
        "greenbone" => 7,
        // Inventory remains useful in a full run, but it must not delay the
        // first vulnerability, secret, or unsafe-configuration result.
        "syft" => 100,
        _ => 50,
    }
}

#[derive(Debug)]
pub(crate) struct PreparedNaabuLauncherAttempt {
    pub(crate) work_plan: NaabuWorkPlanV1,
    pub(crate) request: NaabuAttemptRequest,
    pub(crate) launcher_plan: NaabuLauncherPlanDocument,
    pub(crate) gateway_plans: Vec<ResolvedExternalPlan>,
}

pub(crate) fn manifest_uses_naabu_launcher_v2(manifest: &EngineManifest) -> bool {
    manifest.id == NAABU_ENGINE_ID
        && manifest
            .execution
            .as_ref()
            .and_then(|execution| execution.launcher_journal_version)
            == Some(LAUNCHER_V2_JOURNAL_SCHEMA_VERSION)
}

/// The reviewed CPU allowance, capped at this computer's CPUs so a smaller
/// host still starts the container. Upstream runtimes size their worker pools
/// from the CPUs they can see; openvasd with one CPU stops answering its own
/// status API while a scan runs. The managed runtime VM has two CPUs, which
/// covers every reviewed allowance.
pub(crate) fn engine_container_cpu_millis(manifest: &EngineManifest) -> u32 {
    let host_cpu_millis = std::thread::available_parallelism()
        .map_or(1, std::num::NonZeroUsize::get)
        .saturating_mul(1_000);
    manifest
        .execution_cpu_millis()
        .min(u32::try_from(host_cpu_millis).unwrap_or(u32::MAX))
}

pub(crate) fn apply_worker_execution_report(
    state: &CoreState,
    execution: &PlannedEngineExecution,
    report: &DurableExecutionReport,
) -> AppResult<AssessmentCase> {
    if !manifest_uses_naabu_launcher_v2(&execution.manifest)
        || report.checkpoint.launcher_plan_sha256.is_none()
    {
        return state
            .case_service()
            .apply_execution_report(&execution.case_id, report)
            .map(|applied| applied.case);
    }

    let applied = state
        .case_service()
        .apply_naabu_launcher_v2_execution_report(&execution.case_id, report)?;
    let attempt_with_result = match applied.coverage {
        NaabuLauncherV2CoverageApplyOutcome::Persisted {
            execution_attempt, ..
        } => Some(execution_attempt),
        NaabuLauncherV2CoverageApplyOutcome::ExactReplay {
            execution_attempt,
            result_present: true,
        } => Some(execution_attempt),
        NaabuLauncherV2CoverageApplyOutcome::EvidencePreserved { .. }
        | NaabuLauncherV2CoverageApplyOutcome::ExactReplay {
            result_present: false,
            ..
        } => None,
    };
    let Some(execution_attempt) = attempt_with_result else {
        return Ok(applied.case);
    };

    // Adapter availability is task-local. The atomic report/result is already
    // durable, so a normalization problem must leave that useful partial
    // evidence reportable instead of rolling the whole scan back.
    let service = state.case_service();
    match service.adapt_and_persist_naabu_attempt(
        &execution.case_id,
        &execution.scan_run_id,
        &execution.engine_run_id,
        execution_attempt,
    ) {
        Ok(_) => service.finish_naabu_launcher_v2_normalization(
            &execution.case_id,
            &execution.scan_run_id,
            &execution.engine_run_id,
            false,
        ),
        Err(error) => {
            tracing::warn!(
                case_id = %execution.case_id,
                scan_run_id = %execution.scan_run_id,
                engine_run_id = %execution.engine_run_id,
                execution_attempt,
                error = %error,
                "launcher-v2 evidence was saved but trusted normalization remains incomplete"
            );
            service.finish_naabu_launcher_v2_normalization(
                &execution.case_id,
                &execution.scan_run_id,
                &execution.engine_run_id,
                true,
            )
        }
    }
}

/// Builds or replays one exact launcher-v2 attempt without contacting a
/// runtime or target. New work resolves DNS once; resumed work reconstructs
/// the gateway input from the immutable saved plan and never consults DNS.
pub(crate) fn prepare_naabu_launcher_attempt(
    state: &CoreState,
    execution: &PlannedEngineExecution,
    now: chrono::DateTime<Utc>,
) -> AppResult<Option<PreparedNaabuLauncherAttempt>> {
    if !manifest_uses_naabu_launcher_v2(&execution.manifest) {
        return Ok(None);
    }

    let case = state.case_service().show_case(&execution.case_id)?;
    let run = case
        .scan_runs
        .iter()
        .find(|run| run.id == execution.scan_run_id)
        .ok_or_else(|| AppError::InvalidRequest("Naabu scan run not found".into()))?;
    let engine_run = run
        .engine_runs
        .iter()
        .find(|engine_run| engine_run.id == execution.engine_run_id)
        .ok_or_else(|| AppError::InvalidRequest("Naabu engine run not found".into()))?;
    if engine_run.engine_id != NAABU_ENGINE_ID
        || engine_run.scan_run_id != execution.scan_run_id
        || run.case_id != execution.case_id
    {
        return Err(AppError::NotAuthorized(
            "launcher-v2 preparation does not belong to the exact Naabu execution".into(),
        ));
    }

    let work_plan = if let Some(saved) = engine_run.naabu_work_plan.as_ref() {
        if execution
            .naabu_work_plan
            .as_ref()
            .is_some_and(|planned| planned != saved)
        {
            return Err(AppError::Conflict(
                "the scheduled Naabu plan differs from the latest durable plan".into(),
            ));
        }
        saved.validate().map_err(|error| {
            AppError::Conflict(format!("saved Naabu work plan is invalid: {error}"))
        })?;
        saved.clone()
    } else {
        if execution.naabu_work_plan.is_some() {
            return Err(AppError::Conflict(
                "the scheduled Naabu plan is absent from durable case state".into(),
            ));
        }
        let resolved = direct_external_grants(execution, now)?
            .into_iter()
            .map(|grant| resolve_external_plan(grant, now))
            .collect::<AppResult<Vec<_>>>()?;
        let identity = NaabuWorkPlanIdentity::new(
            execution.case_id.clone(),
            execution.scan_run_id.clone(),
            execution.engine_run_id.clone(),
            now,
        );
        build_naabu_work_plan(identity, &resolved, None).map_err(|error| {
            AppError::InvalidRequest(format!("Naabu work division failed: {error}"))
        })?
    };

    let existing_request = engine_run
        .naabu_attempt_requests
        .iter()
        .find(|request| request.execution_attempt == execution.attempt);
    let (request, launcher_plan) = if let Some(existing) = existing_request {
        let selected = existing
            .requested_unit_ids
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        if selected.len() != existing.requested_unit_ids.len() {
            return Err(AppError::Conflict(
                "saved Naabu launcher request contains duplicate work units".into(),
            ));
        }
        let launcher = match existing.schema_version {
            LEGACY_NAABU_ATTEMPT_REQUEST_SCHEMA_VERSION => {
                work_plan.legacy_launcher_plan_v2(execution.attempt, Some(&selected))
            }
            NAABU_ATTEMPT_REQUEST_SCHEMA_VERSION => {
                work_plan.launcher_plan_v3(execution.attempt, Some(&selected))
            }
            _ => {
                return Err(AppError::Conflict(
                    "saved Naabu launcher request schema is unsupported".into(),
                ));
            }
        }
        .map_err(|error| {
            AppError::Conflict(format!("saved Naabu launcher request is invalid: {error}"))
        })?;
        let digest = hex::encode(Sha256::digest(serde_json::to_vec(&launcher)?));
        if digest != existing.launcher_plan_sha256 {
            return Err(AppError::Conflict(
                "saved Naabu launcher request digest does not match its immutable work units"
                    .into(),
            ));
        }
        if existing.schema_version == LEGACY_NAABU_ATTEMPT_REQUEST_SCHEMA_VERSION {
            return Err(AppError::NotAvailable(
                "The older Naabu request was preserved and verified, but it cannot be sent through the current bounded network path. Resume the scan so the app can create a current request when no-contact history proves that is safe, or start a new scan."
                    .into(),
            ));
        }
        (existing.clone(), launcher)
    } else {
        let cumulative = reduce_naabu_attempt_coverage(
            &work_plan,
            &engine_run.naabu_attempt_requests,
            &engine_run.naabu_attempt_results,
        )
        .map_err(|error| {
            AppError::Conflict(format!("saved Naabu attempt history is invalid: {error}"))
        })?;
        let selected = match select_naabu_attempt(
            &work_plan,
            &cumulative.tested_complete_unit_ids,
            execution.manifest.execution_timeout_seconds(),
        )
        .map_err(|error| {
            AppError::InvalidRequest(format!("Naabu work does not fit this attempt: {error}"))
        })? {
            NaabuAttemptSelection::AllTestedComplete => {
                return Err(AppError::Conflict(
                    "all frozen Naabu work is already complete; no target contact is required"
                        .into(),
                ));
            }
            NaabuAttemptSelection::Selected {
                selected_unit_ids, ..
            } => selected_unit_ids,
        };
        let selected_set = selected.iter().cloned().collect::<BTreeSet<_>>();
        let launcher = work_plan
            .launcher_plan_v3(execution.attempt, Some(&selected_set))
            .map_err(|error| {
                AppError::InvalidRequest(format!("Naabu launcher plan is invalid: {error}"))
            })?;
        let request = NaabuAttemptRequest {
            schema_version: NAABU_ATTEMPT_REQUEST_SCHEMA_VERSION,
            execution_attempt: execution.attempt,
            requested_unit_ids: selected,
            launcher_plan_sha256: hex::encode(Sha256::digest(serde_json::to_vec(&launcher)?)),
        };
        (request, launcher)
    };

    let gateway_plans = work_plan
        .resolved_plans_for_work_units(&request.requested_unit_ids)
        .map_err(|error| {
            if engine_run.naabu_work_plan.is_some() {
                AppError::Conflict(format!(
                    "saved Naabu attempt gateway projection is invalid: {error}"
                ))
            } else {
                AppError::InvalidRequest(format!(
                    "Naabu attempt gateway projection is invalid: {error}"
                ))
            }
        })?;

    Ok(Some(PreparedNaabuLauncherAttempt {
        work_plan,
        request,
        launcher_plan,
        gateway_plans,
    }))
}

pub(crate) struct PlannedEngineExecutionContext<'a> {
    pub(crate) app: &'a ScanCoordinator,
    pub(crate) state: &'a CoreState,
    pub(crate) runtime: &'a ProcessContainerRuntime,
    pub(crate) artifacts: &'a ArtifactStore,
    pub(crate) cancellation: &'a crate::container_runtime::CancellationToken,
    pub(crate) job_context: &'a JobContext,
}

pub(crate) fn execute_planned_engine(
    context: PlannedEngineExecutionContext<'_>,
    execution: &PlannedEngineExecution,
    reserved_provider: Option<&mut ReservedProviderExecutionBundle>,
) -> AppResult<DurableExecutionReport> {
    let PlannedEngineExecutionContext {
        app,
        state,
        runtime,
        artifacts,
        cancellation,
        job_context,
    } = context;
    let mut reconciled_cleanup = None::<ManagedNetworkCleanupOutcome>;
    let runtime_context = runtime.command_context();
    let runtime_provider = runtime_context.provider();
    let runtime_provenance = runtime_context.provenance().clone();
    if let Some(checkpoint) = execution.resume_checkpoint.as_ref() {
        match checkpoint.resume_action() {
            ResumeAction::AlreadyComplete => {
                return Err(AppError::InvalidRequest(
                    "completed execution was incorrectly scheduled for resume".into(),
                ));
            }
            ResumeAction::AdaptCapturedArtifacts => {
                if checkpoint.managed_network.is_some() {
                    let container_name = checkpoint.container_name.as_deref().ok_or_else(|| {
                        AppError::Runtime(
                            "captured execution with managed egress has no exact container identity"
                                .into(),
                        )
                    })?;
                    let cleanup =
                        cleanup_resume_container(runtime, execution, checkpoint, container_name)?;
                    merge_container_cleanup(&mut reconciled_cleanup, &cleanup);
                }
            }
            ResumeAction::CleanupContainer | ResumeAction::ReconcileContainerThenReexecute => {
                let container_name = checkpoint.container_name.as_deref().ok_or_else(|| {
                    AppError::Runtime(
                        "interrupted container checkpoint has no exact container identity".into(),
                    )
                })?;
                let cleanup =
                    cleanup_resume_container(runtime, execution, checkpoint, container_name)?;
                merge_container_cleanup(&mut reconciled_cleanup, &cleanup);
            }
            ResumeAction::Reexecute
                if !checkpoint.cleanup_completed || checkpoint.managed_network.is_some() =>
            {
                if let Some(container_name) = checkpoint.container_name.as_deref() {
                    let cleanup =
                        cleanup_resume_container(runtime, execution, checkpoint, container_name)?;
                    merge_container_cleanup(&mut reconciled_cleanup, &cleanup);
                }
            }
            ResumeAction::Reexecute => {}
        }
        if let Some(identity) = checkpoint.managed_network.as_ref() {
            let checkpoint_owner = ManagedNetworkOwner::new(
                execution.case_id.clone(),
                execution.scan_run_id.clone(),
                execution.engine_run_id.clone(),
                checkpoint.attempt,
            )?;
            let managed = state
                .managed_network_registry_with_context(runtime.command_context())?
                .reconcile_identity(&checkpoint_owner, identity, Utc::now())?;
            merge_reconciled_managed_cleanup(&mut reconciled_cleanup, managed);
        }
        if checkpoint.resume_action() == ResumeAction::AdaptCapturedArtifacts {
            let mut durable = resume_captured_execution(state, artifacts, execution)?;
            if let Some(outcome) = reconciled_cleanup.as_ref() {
                merge_managed_cleanup(&mut durable.cleanup, outcome);
            }
            durable.checkpoint.cleanup_completed = true;
            return Ok(durable);
        }
    }
    let provider_context = if execution_requires_provider_capability(execution) {
        let context = reserved_provider
            .as_deref()
            .ok_or_else(|| {
                AppError::NotAuthorized("provider execution has no reserved dispatch bundle".into())
            })?
            .context_for(execution)?
            .clone();
        if Utc::now() >= context.authorization.expires_at {
            return Err(AppError::NotAuthorized(
                "the frozen provider connection expired before scanner dispatch".into(),
            ));
        }
        Some(context)
    } else {
        None
    };
    let resolved_workspace = resolve_execution_workspace(state, execution)?;
    if cancellation.is_cancelled() {
        return Ok(terminal_report(
            execution,
            ExecutionStage::Cancelled,
            "scan cancellation was requested before launcher planning",
        ));
    }
    let prepared_naabu = prepare_naabu_launcher_attempt(state, execution, Utc::now())?;
    if let Some(prepared) = prepared_naabu.as_ref() {
        let persisted = job_context.coordinate_durable_write(|| {
            state.case_service().persist_naabu_attempt_request(
                &execution.case_id,
                &execution.scan_run_id,
                &execution.engine_run_id,
                &prepared.work_plan,
                &prepared.request,
            )
        })?;
        let _ = emit(app, RUN_PROGRESS_EVENT, &persisted);
        if cancellation.is_cancelled() {
            return Ok(terminal_report(
                execution,
                ExecutionStage::Cancelled,
                "scan cancellation was requested after the exact work request was saved and before any target contact",
            ));
        }
    }
    let limits = ResourceLimits {
        memory_mb: execution.manifest.estimated_memory_mb.clamp(128, 262_144),
        // `/output` is a bounded host artifact mount, while engines such as
        // Steampipe materialize a pinned embedded database in the isolated
        // `/tmp` tmpfs. Size that tmpfs from the reviewed manifest estimate
        // instead of the generic 64 MiB default.
        tmpfs_mb: execution.manifest.estimated_disk_mb.clamp(16, 4_096),
        cpu_millis: engine_container_cpu_millis(&execution.manifest),
        ..ResourceLimits::default()
    };
    let mut network_lease = provision_execution_network(
        state,
        runtime,
        execution,
        provider_context.as_ref(),
        prepared_naabu
            .as_ref()
            .map(|prepared| prepared.gateway_plans.as_slice()),
    )?;
    let network_identity = network_lease
        .as_ref()
        .map(ManagedNetworkLease::durable_identity)
        .transpose()?;
    let network = network_lease
        .as_ref()
        .map(|lease| lease.network_policy().clone())
        .unwrap_or(NetworkPolicy::Disabled);
    let credentials = match resolve_execution_credentials(
        state,
        execution,
        reserved_provider,
        provider_context.as_ref(),
    ) {
        Ok(credentials) => credentials,
        Err(error) => {
            return Ok(terminal_after_prestart_error(
                execution,
                &error,
                network_identity.as_ref(),
                &mut network_lease,
                reconciled_cleanup.as_ref(),
                RuntimeCheckpointIdentity {
                    provenance: &runtime_provenance,
                    provider: runtime_provider,
                },
                prepared_naabu
                    .as_ref()
                    .map(|prepared| prepared.request.launcher_plan_sha256.as_str()),
            ));
        }
    };
    let orchestrator = Orchestrator::new(runtime, artifacts, &state.adapters);
    let frozen_destinations = network_lease
        .as_ref()
        .map(|lease| lease.egress_policy().destinations());
    let request = EngineExecutionRequest {
        case_id: &execution.case_id,
        scan_run_id: &execution.scan_run_id,
        engine_run_id: &execution.engine_run_id,
        manifest: &execution.manifest,
        ai_system_applicable: execution.ai_system_applicable,
        ai_generated_artifact_applicable: execution.ai_generated_artifact
            == crate::domain::AiGeneratedArtifactAnswer::Yes,
        assets: &execution.assets,
        scope_grants: &execution.scope_grants,
        frozen_destinations,
        naabu_launcher_plan: prepared_naabu
            .as_ref()
            .map(|prepared| &prepared.launcher_plan),
        expected_naabu_launcher_plan_sha256: prepared_naabu
            .as_ref()
            .map(|prepared| prepared.request.launcher_plan_sha256.as_str()),
        workspace: resolved_workspace
            .as_ref()
            .map(|workspace| workspace.tree_path.as_path()),
        network_policy: &network,
        resource_limits: &limits,
        credentials: &credentials,
        attempt: execution.attempt,
    };
    let mut report =
        match orchestrator.execute_with_observer(&request, cancellation, |checkpoint_report| {
            let mut durable = DurableExecutionReport::from(checkpoint_report);
            durable.checkpoint.runtime_command_provenance = Some(runtime_provenance.clone());
            durable.checkpoint.runtime_provider = Some(runtime_provider);
            durable.checkpoint.managed_network = network_identity.clone();
            durable.checkpoint.cleanup_completed =
                network_identity.is_none() && durable.checkpoint.cleanup_completed;
            let applied = job_context.coordinate_durable_write(|| {
                state
                    .case_service()
                    .apply_execution_report(&execution.case_id, &durable)
            })?;
            let _ = emit(app, RUN_PROGRESS_EVENT, &applied.case);
            Ok(())
        }) {
            Ok(report) => report,
            Err(error) => {
                return Ok(terminal_after_prestart_error(
                    execution,
                    &error,
                    network_identity.as_ref(),
                    &mut network_lease,
                    reconciled_cleanup.as_ref(),
                    RuntimeCheckpointIdentity {
                        provenance: &runtime_provenance,
                        provider: runtime_provider,
                    },
                    prepared_naabu
                        .as_ref()
                        .map(|prepared| prepared.request.launcher_plan_sha256.as_str()),
                ));
            }
        };
    report.checkpoint.runtime_command_provenance = Some(runtime_provenance);
    report.checkpoint.runtime_provider = Some(runtime_provider);
    report.checkpoint.managed_network = network_identity;
    if let Some(outcome) = reconciled_cleanup.as_ref() {
        let mut durable_cleanup = report.cleanup.clone();
        merge_managed_cleanup(&mut durable_cleanup, outcome);
        report.cleanup = durable_cleanup;
    }
    if let Some(lease) = network_lease.as_mut() {
        match lease.cleanup_with_outcome() {
            Ok(outcome) => {
                let mut durable_cleanup = report.cleanup.clone();
                merge_managed_cleanup(&mut durable_cleanup, &outcome);
                report.cleanup = durable_cleanup;
            }
            Err(error) => {
                record_managed_cleanup_failure(
                    &mut report.checkpoint,
                    &mut report.cleanup,
                    &mut report.warnings,
                    &error.to_string(),
                    "The isolated external network or gateway did not confirm complete cleanup; no successful result is claimed.",
                );
            }
        }
    }
    Ok(DurableExecutionReport::from(&report))
}

pub(crate) fn cleanup_resume_container(
    runtime: &ProcessContainerRuntime,
    execution: &PlannedEngineExecution,
    checkpoint: &ExecutionCheckpoint,
    persisted_container_name: &str,
) -> AppResult<CleanupOutcome> {
    if checkpoint.case_id != execution.case_id
        || checkpoint.scan_run_id != execution.scan_run_id
        || checkpoint.engine_run_id != execution.engine_run_id
        || checkpoint.engine_id != execution.manifest.id
    {
        return Err(AppError::NotAuthorized(
            "resume cleanup checkpoint does not match the planned execution".into(),
        ));
    }
    let ownership = OwnedContainerCleanupRequest {
        case_id: checkpoint.case_id.clone(),
        scan_run_id: checkpoint.scan_run_id.clone(),
        engine_run_id: checkpoint.engine_run_id.clone(),
        engine_id: checkpoint.engine_id.clone(),
        attempt: checkpoint.attempt,
        scope_sha256: checkpoint.scope_sha256.clone().ok_or_else(|| {
            AppError::NotAuthorized("resume cleanup checkpoint has no frozen scope digest".into())
        })?,
        launcher_plan_sha256: checkpoint.launcher_plan_sha256.clone(),
        zap_plan_sha256: checkpoint.zap_plan_sha256.clone(),
        image: PinnedImage::from_manifest(&execution.manifest)?,
    };
    if ownership.container_name()? != persisted_container_name {
        return Err(AppError::NotAuthorized(
            "resume cleanup container name conflicts with its execution ownership proof".into(),
        ));
    }
    runtime.cleanup_owned_container(&ownership)
}

pub(crate) fn resume_captured_execution(
    state: &CoreState,
    artifacts: &ArtifactStore,
    execution: &PlannedEngineExecution,
) -> AppResult<DurableExecutionReport> {
    if manifest_uses_naabu_launcher_v2(&execution.manifest) {
        return Err(AppError::Internal(
            "launcher-v2 captured results must use the dedicated host-only adaptation resume path"
                .into(),
        ));
    }
    let checkpoint = execution.resume_checkpoint.as_ref().ok_or_else(|| {
        AppError::InvalidRequest("captured-artifact resume has no durable checkpoint".into())
    })?;
    let raw_artifacts = captured_execution_artifacts(state, execution, checkpoint)?;
    // Repeat the exact read-only check in the worker so a file changed after
    // planning/preflight cannot be normalized (TOCTOU defense).
    inspect_raw_artifacts(artifacts.root(), &raw_artifacts)?;
    let directories = artifacts.prepare_run(
        &ArtifactContext {
            case_id: execution.case_id.clone(),
            scan_run_id: execution.scan_run_id.clone(),
            engine_run_id: execution.engine_run_id.clone(),
        },
        checkpoint.attempt,
    )?;
    let previous = ExecutionReport {
        checkpoint: checkpoint.clone(),
        runtime_preflight: None,
        cleanup: None,
        exit_code: None,
        raw_artifacts,
        findings: Vec::new(),
        observations: Vec::new(),
        warnings: vec![
            "Normalization resumed from previously hashed local artifacts; the scanner container was not re-run."
                .into(),
        ],
        unattributed: Vec::new(),
        unevaluated_targets: Vec::new(),
        security_template_executions: Vec::new(),
        manual_review_controls: Vec::new(),
        artifact_root: artifacts.root().to_path_buf(),
        output_directory: directories.output,
    };
    let limits = ResourceLimits {
        memory_mb: execution.manifest.estimated_memory_mb.clamp(128, 262_144),
        cpu_millis: engine_container_cpu_millis(&execution.manifest),
        ..ResourceLimits::default()
    };
    let network = NetworkPolicy::Disabled;
    let credentials = ScannerCredentialSet::default();
    let request = EngineExecutionRequest {
        case_id: &execution.case_id,
        scan_run_id: &execution.scan_run_id,
        engine_run_id: &execution.engine_run_id,
        manifest: &execution.manifest,
        ai_system_applicable: execution.ai_system_applicable,
        ai_generated_artifact_applicable: execution.ai_generated_artifact
            == crate::domain::AiGeneratedArtifactAnswer::Yes,
        assets: &execution.assets,
        scope_grants: &execution.scope_grants,
        frozen_destinations: None,
        naabu_launcher_plan: None,
        expected_naabu_launcher_plan_sha256: None,
        workspace: None,
        network_policy: &network,
        resource_limits: &limits,
        credentials: &credentials,
        attempt: checkpoint.attempt,
    };
    let report = resume_captured_artifacts(&state.adapters, &request, &previous)?;
    Ok(DurableExecutionReport::from(&report))
}

pub(crate) fn captured_execution_artifacts(
    state: &CoreState,
    execution: &PlannedEngineExecution,
    checkpoint: &ExecutionCheckpoint,
) -> AppResult<Vec<RawArtifact>> {
    if checkpoint.resume_action() != ResumeAction::AdaptCapturedArtifacts
        || checkpoint.case_id != execution.case_id
        || checkpoint.scan_run_id != execution.scan_run_id
        || checkpoint.engine_run_id != execution.engine_run_id
        || checkpoint.engine_id != execution.manifest.id
    {
        return Err(AppError::NotAuthorized(
            "captured-artifact checkpoint does not match the planned execution".into(),
        ));
    }

    let case = state.case_service().show_case(&execution.case_id)?;
    let engine_run = case
        .scan_runs
        .iter()
        .find(|run| run.id == execution.scan_run_id)
        .and_then(|run| {
            run.engine_runs
                .iter()
                .find(|engine_run| engine_run.id == execution.engine_run_id)
        })
        .ok_or_else(|| AppError::InvalidRequest("resume engine run no longer exists".into()))?;
    let expected_artifact_ids = engine_run
        .raw_artifact_ids
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let checkpoint_artifact_ids = checkpoint
        .artifact_ids
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if expected_artifact_ids.is_empty()
        || expected_artifact_ids.len() != engine_run.raw_artifact_ids.len()
        || checkpoint_artifact_ids.len() != checkpoint.artifact_ids.len()
        || checkpoint_artifact_ids != expected_artifact_ids
    {
        return Err(AppError::Runtime(
            "captured-artifact checkpoint does not exactly match the durable evidence IDs".into(),
        ));
    }

    let mut raw_artifacts = Vec::with_capacity(engine_run.raw_artifact_ids.len());
    for artifact_id in &engine_run.raw_artifact_ids {
        let mut matching = case
            .raw_artifacts
            .iter()
            .filter(|artifact| artifact.id == *artifact_id);
        let artifact = matching.next().ok_or_else(|| {
            AppError::Runtime(format!(
                "captured evidence {artifact_id} is missing from the durable case"
            ))
        })?;
        if matching.next().is_some() {
            return Err(AppError::Runtime(format!(
                "captured evidence {artifact_id} is duplicated in the durable case"
            )));
        }
        if artifact.case_id != execution.case_id
            || artifact.run_id != execution.scan_run_id
            || artifact.engine_run_id != execution.engine_run_id
        {
            return Err(AppError::NotAuthorized(format!(
                "captured evidence {artifact_id} does not belong to this exact execution"
            )));
        }
        raw_artifacts.push(artifact.clone());
    }
    Ok(raw_artifacts)
}

pub(crate) fn direct_external_grants(
    execution: &PlannedEngineExecution,
    now: chrono::DateTime<Utc>,
) -> AppResult<Vec<&ExternalScopeGrant>> {
    let mut grants = Vec::new();
    for asset in &execution.assets {
        let mut asset_grants = execution
            .scope_grants
            .iter()
            .filter(|grant| grant.asset_id == asset.id)
            .filter(|grant| {
                execution
                    .manifest
                    .required_permissions
                    .contains(&grant.permission)
            })
            .map(|grant| {
                let external = grant.external_scope.as_ref().ok_or_else(|| {
                    AppError::NotAuthorized(format!(
                        "direct external grant {} has no structured policy",
                        grant.id
                    ))
                })?;
                let expected_activity = match grant.permission {
                    ScanPermission::LowImpactExternalConnection => {
                        crate::external_scope::ExternalActivity::LowImpactExternal
                    }
                    ScanPermission::ActiveExternalTesting => {
                        crate::external_scope::ExternalActivity::ActiveExternal
                    }
                    _ => {
                        return Err(AppError::NotAuthorized(
                            "direct external network was requested for a non-direct permission"
                                .into(),
                        ));
                    }
                };
                if external.id != grant.id
                    || external.asset_id != asset.id
                    || external.case_id != execution.case_id
                    || external.activity != expected_activity
                {
                    return Err(AppError::NotAuthorized(
                        "structured external grant identity or activity does not match the execution"
                            .into(),
                    ));
                }
                external.validate(now)?;
                Ok(external)
            })
            .collect::<AppResult<Vec<_>>>()?;
        if asset_grants.is_empty() {
            return Err(AppError::NotAuthorized(format!(
                "direct external asset {} has no frozen structured target/port/rate policy",
                asset.id
            )));
        }
        grants.append(&mut asset_grants);
    }
    grants.sort_by(|left, right| {
        left.asset_id
            .cmp(&right.asset_id)
            .then_with(|| left.id.cmp(&right.id))
    });
    if grants.windows(2).any(|pair| pair[0].id == pair[1].id) {
        return Err(AppError::InvalidRequest(
            "direct external execution contains duplicate grant identities".into(),
        ));
    }
    Ok(grants)
}

pub(crate) fn provider_service_egress_request(
    state: &CoreState,
    execution: &PlannedEngineExecution,
    provider_context: Option<&ProviderExecutionContext>,
    exact_destinations: Vec<String>,
    now: chrono::DateTime<Utc>,
) -> AppResult<ProviderServiceEgressRequest> {
    let provider_read = execution
        .manifest
        .required_permissions
        .iter()
        .any(|permission| {
            matches!(
                permission,
                ScanPermission::InventoryRead | ScanPermission::ConfigurationRead
            )
        });
    let (source_id, source_kind, source_profile, expires_at) = if provider_read {
        match provider_context {
            Some(context) => (
                context.source.id.clone(),
                serialized_token(&context.source.kind, "source kind")?,
                serialized_token(&context.authorization.profile, "source profile")?,
                approved_execution_expiry(execution, now, context.authorization.expires_at)?,
            ),
            None => {
                let (source, authorization) = provider_egress_source(state, execution, now)?;
                (
                    source.id,
                    serialized_token(&source.kind, "source kind")?,
                    serialized_token(&authorization.profile, "source profile")?,
                    approved_execution_expiry(execution, now, authorization.expires_at)?,
                )
            }
        }
    } else if execution
        .manifest
        .required_permissions
        .contains(&ScanPermission::PassiveExternalDiscovery)
    {
        passive_service_egress_source(state, execution, now)?
    } else {
        return Err(AppError::NotAvailable(
            "engine network destinations are not tied to a supported provider-service or passive-service profile"
                .into(),
        ));
    };
    let manifest_revision = execution
        .manifest
        .source_revision
        .clone()
        .or_else(|| {
            execution
                .manifest
                .image
                .as_ref()
                .and_then(|image| image.digest.clone())
        })
        .or_else(|| execution.manifest.engine_version.clone())
        .ok_or_else(|| {
            AppError::NotAvailable(
                "provider-service engine has no pinned manifest revision provenance".into(),
            )
        })?;
    Ok(ProviderServiceEgressRequest {
        case_id: execution.case_id.clone(),
        source_id,
        source_kind,
        source_profile,
        manifest_id: execution.manifest.id.clone(),
        manifest_revision,
        exact_destinations,
        expires_at,
    })
}

pub(crate) fn trace_execution_preflight_failure(
    execution: &PlannedEngineExecution,
    intended_blocker: DesktopExecutionBlocker,
    error: &AppError,
) -> DesktopExecutionBlocker {
    let blocker = classify_execution_preflight_error(intended_blocker, error);
    tracing::warn!(
        case_id = %execution.case_id,
        scan_run_id = %execution.scan_run_id,
        engine_id = %execution.manifest.id,
        blocker = blocker.blocker_code().as_str(),
        "scan execution input preflight blocked before scanner dispatch"
    );
    blocker
}

/// Keep actionable input failures distinct from backend failures that the
/// person using the app cannot repair by choosing the same input again.
pub(crate) fn classify_execution_preflight_error(
    intended_blocker: DesktopExecutionBlocker,
    error: &AppError,
) -> DesktopExecutionBlocker {
    match error {
        AppError::Storage(_) | AppError::Internal(_) | AppError::CaseNotFound(_) => {
            DesktopExecutionBlocker::ExecutionPreflightUnavailable
        }
        _ => intended_blocker,
    }
}

pub(crate) fn validate_execution_network_static_with_gateway<F>(
    state: &CoreState,
    execution: &PlannedEngineExecution,
    now: chrono::DateTime<Utc>,
    locate_gateway: &mut F,
) -> Result<(), DesktopExecutionBlocker>
where
    F: FnMut() -> AppResult<GatewayContainerSpec>,
{
    let direct_external = execution
        .manifest
        .required_permissions
        .iter()
        .any(|permission| {
            matches!(
                permission,
                ScanPermission::LowImpactExternalConnection | ScanPermission::ActiveExternalTesting
            )
        });
    let exact_destinations = exact_execution_network_destinations(execution).map_err(|error| {
        trace_execution_preflight_failure(
            execution,
            DesktopExecutionBlocker::EngineExecutionContractInvalid,
            &error,
        )
    })?;
    if !direct_external && exact_destinations.is_empty() {
        return Ok(());
    }

    locate_gateway().map_err(|error| {
        trace_execution_preflight_failure(
            execution,
            DesktopExecutionBlocker::EgressGatewayUnavailable,
            &error,
        )
    })?;

    if direct_external {
        direct_external_grants(execution, now).map_err(|error| {
            trace_execution_preflight_failure(
                execution,
                DesktopExecutionBlocker::EngineExecutionContractInvalid,
                &error,
            )
        })?;
        return Ok(());
    }

    let passive = execution
        .manifest
        .required_permissions
        .contains(&ScanPermission::PassiveExternalDiscovery);
    let request = provider_service_egress_request(state, execution, None, exact_destinations, now)
        .map_err(|error| {
            trace_execution_preflight_failure(
                execution,
                if passive {
                    DesktopExecutionBlocker::PassiveSourceUnavailable
                } else {
                    DesktopExecutionBlocker::EngineExecutionContractInvalid
                },
                &error,
            )
        })?;
    validate_provider_service_request_static(&request, now).map_err(|error| {
        trace_execution_preflight_failure(
            execution,
            if passive {
                DesktopExecutionBlocker::PassiveSourceUnavailable
            } else {
                DesktopExecutionBlocker::EngineExecutionContractInvalid
            },
            &error,
        )
    })
}

pub(crate) fn validate_execution_inputs_static(
    state: &CoreState,
    plan: &ScanPlan,
) -> Result<(), DesktopExecutionBlocker> {
    validate_execution_inputs_static_with_gateway(state, plan, managed_egress_gateway_spec)
}

pub(crate) fn validate_execution_inputs_static_with_gateway<F>(
    state: &CoreState,
    plan: &ScanPlan,
    mut locate_gateway: F,
) -> Result<(), DesktopExecutionBlocker>
where
    F: FnMut() -> AppResult<GatewayContainerSpec>,
{
    if plan.executable.is_empty() {
        tracing::error!(
            case_id = %plan.scan_run.case_id,
            scan_run_id = %plan.scan_run.id,
            "execution input preflight received an empty executable plan"
        );
        return Err(DesktopExecutionBlocker::ExecutionPreflightUnavailable);
    }
    let now = Utc::now();
    let mut inspected_workspaces = BTreeSet::<(String, String, String)>::new();
    for execution in &plan.executable {
        if is_naabu_launcher_v2_adapter_resume(execution) {
            state
                .case_service()
                .inspect_naabu_launcher_v2_adaptation_resume(
                    &execution.case_id,
                    &execution.scan_run_id,
                    &execution.engine_run_id,
                    execution.attempt,
                )
                .map_err(|error| {
                    trace_execution_preflight_failure(
                        execution,
                        DesktopExecutionBlocker::CapturedEvidenceUnavailable,
                        &error,
                    )
                })?;
            continue;
        }
        if let Some(checkpoint) = execution
            .resume_checkpoint
            .as_ref()
            .filter(|checkpoint| checkpoint.resume_action() == ResumeAction::AdaptCapturedArtifacts)
        {
            let raw_artifacts = captured_execution_artifacts(state, execution, checkpoint)
                .map_err(|error| {
                    trace_execution_preflight_failure(
                        execution,
                        DesktopExecutionBlocker::CapturedEvidenceUnavailable,
                        &error,
                    )
                })?;
            inspect_raw_artifacts(state.artifact_root(), &raw_artifacts).map_err(|error| {
                trace_execution_preflight_failure(
                    execution,
                    DesktopExecutionBlocker::CapturedEvidenceUnavailable,
                    &error,
                )
            })?;
            continue;
        }
        let workspace = execution_workspace_reference(state, execution).map_err(|error| {
            trace_execution_preflight_failure(
                execution,
                DesktopExecutionBlocker::WorkspaceSnapshotUnavailable,
                &error,
            )
        })?;
        if let Some(reference) = workspace
            && inspected_workspaces.insert((
                execution.case_id.clone(),
                reference.storage_id.clone(),
                reference.sha256.clone(),
            ))
        {
            inspect_workspace_snapshot(state.artifact_root(), &execution.case_id, &reference)
                .map_err(|error| {
                    trace_execution_preflight_failure(
                        execution,
                        DesktopExecutionBlocker::WorkspaceSnapshotUnavailable,
                        &error,
                    )
                })?;
        }
        validate_execution_network_static_with_gateway(state, execution, now, &mut locate_gateway)?;
    }
    Ok(())
}

pub(crate) fn provision_execution_network(
    state: &CoreState,
    runtime: &ProcessContainerRuntime,
    execution: &PlannedEngineExecution,
    provider_context: Option<&ProviderExecutionContext>,
    frozen_direct_plans: Option<&[ResolvedExternalPlan]>,
) -> AppResult<Option<ManagedNetworkLease>> {
    let direct_external = execution
        .manifest
        .required_permissions
        .iter()
        .any(|permission| {
            matches!(
                permission,
                ScanPermission::LowImpactExternalConnection | ScanPermission::ActiveExternalTesting
            )
        });
    let exact_network_destinations = exact_execution_network_destinations(execution)?;
    if !direct_external && exact_network_destinations.is_empty() {
        return Ok(None);
    }
    let now = Utc::now();
    let gateway = managed_egress_gateway_spec()?;
    let policy_root = state.network_policy_root(&execution.case_id)?;
    let context = runtime.command_context();
    let registry = state.managed_network_registry_with_context(context.clone())?;
    let owner = ManagedNetworkOwner::new(
        execution.case_id.clone(),
        execution.scan_run_id.clone(),
        execution.engine_run_id.clone(),
        execution.attempt,
    )?;
    let controller = ManagedNetworkController::new_with_registry_context_and_container(
        context,
        gateway,
        policy_root,
        registry.root(),
    )?;
    if direct_external {
        if let Some(plans) = frozen_direct_plans {
            if plans.is_empty() {
                return Err(AppError::InvalidRequest(
                    "frozen direct-network execution has no target plan".into(),
                ));
            }
            return controller.provision(&owner, plans, now).map(Some);
        }
        let plans = direct_external_grants(execution, now)?
            .into_iter()
            .map(|grant| resolve_external_plan(grant, now))
            .collect::<AppResult<Vec<ResolvedExternalPlan>>>()?;
        return controller.provision(&owner, &plans, now).map(Some);
    }

    let request = provider_service_egress_request(
        state,
        execution,
        provider_context,
        exact_network_destinations,
        now,
    )?;
    let plan = resolve_provider_service_plan(request, now)?;
    controller
        .provision_provider_service(&owner, &plan, now)
        .map(Some)
}

pub(crate) fn exact_execution_network_destinations(
    execution: &PlannedEngineExecution,
) -> AppResult<Vec<String>> {
    if execution.manifest.provider_execution_contracts.is_empty() {
        return Ok(execution.manifest.network_destinations.clone());
    }
    let [asset] = execution.assets.as_slice() else {
        return Err(AppError::NotAuthorized(
            "a provider-profile execution must contain exactly one asset".into(),
        ));
    };
    let contract = execution
        .manifest
        .provider_execution_contract(asset.provider.as_deref(), &asset.kind)
        .ok_or_else(|| {
            AppError::NotAuthorized(
                "execution asset has no exact provider profile in the frozen manifest".into(),
            )
        })?;
    if contract.network_destinations.is_empty()
        || contract.network_destinations.iter().any(|destination| {
            !execution
                .manifest
                .network_destinations
                .contains(destination)
        })
    {
        return Err(AppError::EngineRegistry(format!(
            "engine {} provider profile has an invalid network closure",
            execution.manifest.id
        )));
    }
    Ok(contract.network_destinations.clone())
}

pub(crate) fn resolve_execution_credentials(
    state: &CoreState,
    execution: &PlannedEngineExecution,
    reserved_provider: Option<&mut ReservedProviderExecutionBundle>,
    provider_context: Option<&ProviderExecutionContext>,
) -> AppResult<ScannerCredentialSet> {
    if execution.manifest.id == crate::garak_input::ENGINE_ID {
        let [asset] = execution.assets.as_slice() else {
            return Err(AppError::NotAuthorized(
                "model check requires one exact model asset".into(),
            ));
        };
        return state.model_endpoint_sessions.take(
            &execution.case_id,
            asset,
            &execution.scope_grants,
            Utc::now(),
        );
    }
    let provider_read = execution
        .manifest
        .required_permissions
        .iter()
        .any(|permission| {
            matches!(
                permission,
                ScanPermission::InventoryRead | ScanPermission::ConfigurationRead
            )
        });
    if !provider_read {
        return Ok(ScannerCredentialSet::default());
    }

    let cloud_asset = execution.assets.iter().any(|asset| {
        matches!(
            asset.kind,
            AssetKind::CloudOrganization
                | AssetKind::CloudAccount
                | AssetKind::Subscription
                | AssetKind::Project
                | AssetKind::Tenant
        )
    });
    if cloud_asset {
        let context = provider_context.ok_or_else(|| {
            AppError::NotAuthorized(
                "cloud execution has no frozen provider connection context".into(),
            )
        })?;
        if context.engine_run_id != execution.engine_run_id
            || context.authorization.case_id != execution.case_id
            || context.authorization.source_id != context.source.id
            || !context
                .authorization
                .allowed_engine_ids
                .contains(&execution.manifest.id)
        {
            return Err(AppError::NotAuthorized(
                "frozen provider connection context does not bind this execution".into(),
            ));
        }
        return reserved_provider
            .ok_or_else(|| {
                AppError::NotAuthorized(
                    "provider execution has no reserved dispatch credential set".into(),
                )
            })?
            .take_credentials(execution, context);
    }

    let Some(source) = provider_source_for_execution(state, execution)? else {
        return Ok(ScannerCredentialSet::default());
    };
    validate_installed_provider_authorization(state, &source, execution, Utc::now())?;
    Err(AppError::NotAuthorized(
        "non-cloud provider credentials cannot be checked out by desktop execution".into(),
    ))
}

pub(crate) fn provider_egress_source(
    state: &CoreState,
    execution: &PlannedEngineExecution,
    now: chrono::DateTime<Utc>,
) -> AppResult<(
    DataSource,
    crate::source_authorization::InstalledSourceAuthorization,
)> {
    let source = provider_source_for_execution(state, execution)?.ok_or_else(|| {
        AppError::NotAuthorized(
            "provider-service egress has no connected attributable read-only source".into(),
        )
    })?;
    let authorization = validate_installed_provider_authorization(state, &source, execution, now)?;
    Ok((source, authorization))
}

pub(crate) fn validate_installed_provider_authorization(
    state: &CoreState,
    source: &DataSource,
    execution: &PlannedEngineExecution,
    now: chrono::DateTime<Utc>,
) -> AppResult<InstalledSourceAuthorization> {
    let authorization = state
        .source_authorizations
        .status(&execution.case_id, &source.id, now)?
        .ok_or_else(|| {
            AppError::NotAuthorized(
                "provider execution has no live source authorization profile".into(),
            )
        })?;
    let persisted_profile = source
        .metadata
        .get("provider_profile")
        .cloned()
        .and_then(|value| serde_json::from_value::<ProviderSourceProfile>(value).ok());
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
    if authorization.case_id != execution.case_id
        || authorization.source_id != source.id
        || authorization.source_kind != source.kind
        || authorization.provider_verification.profile != authorization.profile
        || persisted_profile != Some(authorization.profile)
        || authorization.provider_identity != persisted_identity
        || authorization.provider_verification.evidence_sha256 != persisted_proof
        || !authorization
            .allowed_engine_ids
            .contains(&execution.manifest.id)
    {
        return Err(AppError::NotAuthorized(
            "provider source authorization does not bind this source, proof, and engine".into(),
        ));
    }
    validate_provider_execution_target(state, source, execution, &authorization)?;
    Ok(authorization)
}

pub(crate) fn validate_provider_execution_target(
    state: &CoreState,
    source: &DataSource,
    execution: &PlannedEngineExecution,
    authorization: &InstalledSourceAuthorization,
) -> AppResult<()> {
    let persisted_resource_scope = source
        .metadata
        .get(PROVIDER_RESOURCE_SCOPE_METADATA_KEY)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            AppError::NotAuthorized(
                "provider source has no persisted verified resource scope".into(),
            )
        })?;
    if persisted_resource_scope != authorization.provider_verification.resource_scope {
        return Err(AppError::NotAuthorized(
            "provider live authorization resource scope differs from its persisted proof".into(),
        ));
    }
    let [asset] = execution.assets.as_slice() else {
        return Err(AppError::NotAuthorized(
            "provider execution must contain exactly one asset".into(),
        ));
    };
    match source.kind {
        SourceKind::AwsOrganization => {
            if authorization.profile != ProviderSourceProfile::AwsOrganizationReadOnlySession {
                return Err(AppError::NotAuthorized(
                    "AWS execution does not use the verified organization read-only profile".into(),
                ));
            }
            validate_aws_execution_target(&execution.assets, persisted_resource_scope)
        }
        SourceKind::AzureTenant => {
            if authorization.profile != ProviderSourceProfile::AzureTenantReadOnlyAccessToken
                || asset.kind != AssetKind::Subscription
                || asset.provider.as_deref() != Some("azure")
            {
                return Err(AppError::NotAuthorized(
                    "Azure execution does not match the verified subscription profile".into(),
                ));
            }
            let subscription_id = unique_native_identifier(asset, "azure_subscription_id")?;
            if !valid_azure_subscription_id(subscription_id)
                || persisted_resource_scope != format!("azure-subscription:{subscription_id}")
            {
                return Err(AppError::NotAuthorized(
                    "Azure execution subscription differs from its verified proof".into(),
                ));
            }
            Ok(())
        }
        SourceKind::GcpOrganization => {
            if authorization.profile != ProviderSourceProfile::GcpOrganizationReadOnlyAccessToken
                || asset.kind != AssetKind::Project
                || asset.provider.as_deref() != Some("gcp")
            {
                return Err(AppError::NotAuthorized(
                    "GCP execution does not match the verified organization profile".into(),
                ));
            }
            let project_id = unique_native_identifier(asset, "gcp_project_id")?;
            if !valid_gcp_project_id(project_id) {
                return Err(AppError::NotAuthorized(
                    "GCP execution project identifier is malformed".into(),
                ));
            }
            let organization_id = persisted_resource_scope
                .strip_prefix("gcp-organization:")
                .filter(|value| {
                    !value.is_empty()
                        && value.len() <= 32
                        && value.bytes().all(|byte| byte.is_ascii_digit())
                })
                .ok_or_else(|| {
                    AppError::NotAuthorized(
                        "GCP source proof is not bound to one organization".into(),
                    )
                })?;
            let case = state.case_service().show_case(&execution.case_id)?;
            let related = case.asset_relations.iter().any(|relation| {
                relation.kind == crate::domain::RelationKind::Contains
                    && relation.to_asset_id == asset.id
                    && case.assets.iter().any(|parent| {
                        parent.id == relation.from_asset_id
                            && parent.kind == AssetKind::CloudOrganization
                            && parent.provider.as_deref() == Some("gcp")
                            && parent.discovered_from.contains(&source.id)
                            && ["gcp_organization_id", "gcp_organization_number"]
                                .iter()
                                .any(|namespace| {
                                    unique_native_identifier(parent, namespace).ok()
                                        == Some(organization_id)
                                })
                    })
            });
            if !related {
                return Err(AppError::NotAuthorized(
                    "GCP project is not attributable to the verified organization".into(),
                ));
            }
            Ok(())
        }
        SourceKind::Microsoft365Tenant => {
            if authorization.profile != ProviderSourceProfile::Microsoft365TenantReadOnlyAccessToken
                || asset.kind != AssetKind::Tenant
                || asset.provider.as_deref() != Some("microsoft365")
            {
                return Err(AppError::NotAuthorized(
                    "Microsoft 365 execution does not match the verified tenant profile".into(),
                ));
            }
            let tenant_id = unique_native_identifier(asset, "microsoft_tenant_id")?;
            if uuid::Uuid::parse_str(tenant_id).is_err()
                || persisted_resource_scope != format!("microsoft365-tenant:{tenant_id}")
            {
                return Err(AppError::NotAuthorized(
                    "Microsoft 365 execution tenant differs from its verified proof".into(),
                ));
            }
            Ok(())
        }
        _ => Err(AppError::NotAuthorized(
            "provider execution source kind has no exact target contract".into(),
        )),
    }
}

pub(crate) fn unique_native_identifier<'a>(
    asset: &'a crate::domain::Asset,
    namespace: &str,
) -> AppResult<&'a str> {
    let mut values = asset
        .identifiers
        .iter()
        .filter(|identifier| identifier.namespace == namespace)
        .map(|identifier| identifier.value.as_str());
    let value = values.next().ok_or_else(|| {
        AppError::NotAuthorized(format!(
            "asset {} lacks exact provider identifier {namespace}",
            asset.id
        ))
    })?;
    if values.next().is_some() {
        return Err(AppError::NotAuthorized(format!(
            "asset {} has an ambiguous provider identifier {namespace}",
            asset.id
        )));
    }
    Ok(value)
}

pub(crate) fn passive_service_egress_source(
    state: &CoreState,
    execution: &PlannedEngineExecution,
    now: chrono::DateTime<Utc>,
) -> AppResult<(String, String, String, chrono::DateTime<Utc>)> {
    let case = state.case_service().show_case(&execution.case_id)?;
    let candidates = case
        .data_sources
        .iter()
        .filter(|source| {
            source.read_only
                && source.status == SourceConnectionStatus::Connected
                && matches!(
                    source.kind,
                    SourceKind::Dns | SourceKind::CertificateTransparency
                )
                && execution
                    .assets
                    .iter()
                    .all(|asset| asset.discovered_from.contains(&source.id))
        })
        .collect::<Vec<_>>();
    let [source] = candidates.as_slice() else {
        return Err(AppError::NotAuthorized(
            "passive-service egress requires exactly one attributable connected DNS or certificate-transparency source"
                .into(),
        ));
    };
    let reference: SnapshotArtifactReference = source
        .metadata
        .get(SNAPSHOT_ARTIFACT_METADATA_KEY)
        .cloned()
        .ok_or_else(|| {
            AppError::NotAuthorized(
                "passive-service source has no backend-owned parser profile".into(),
            )
        })
        .and_then(|value| {
            serde_json::from_value(value).map_err(|_| {
                AppError::InvalidRequest(
                    "passive-service source parser profile is malformed".into(),
                )
            })
        })?;
    let connector_root = state
        .artifact_root()
        .join(&execution.case_id)
        .join("connector-snapshots");
    preflight_snapshot_artifact(&connector_root, &source.kind, &reference).map_err(|error| {
        AppError::NotAuthorized(format!(
            "passive-service source snapshot is unavailable or changed: {error}"
        ))
    })?;
    let mut expires_at = now + Duration::hours(1);
    for asset in &execution.assets {
        let grant = execution
            .scope_grants
            .iter()
            .find(|grant| {
                grant.asset_id == asset.id
                    && grant.permission == ScanPermission::PassiveExternalDiscovery
                    && grant.confirmed_at <= now
                    && grant.expires_at.is_some_and(|expires| expires > now)
            })
            .ok_or_else(|| {
                AppError::NotAuthorized(format!(
                    "passive-service asset {} has no live discovery grant",
                    asset.id
                ))
            })?;
        expires_at = expires_at.min(grant.expires_at.expect("checked as present"));
    }
    Ok((
        source.id.clone(),
        serialized_token(&source.kind, "source kind")?,
        format!("snapshot:{}", reference.profile),
        expires_at,
    ))
}

pub(crate) fn serialized_token<T: serde::Serialize>(value: &T, label: &str) -> AppResult<String> {
    serde_json::to_value(value)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .ok_or_else(|| AppError::Internal(format!("{label} serialization failed")))
}

pub(crate) fn approved_execution_expiry(
    execution: &PlannedEngineExecution,
    now: chrono::DateTime<Utc>,
    mut ceiling: chrono::DateTime<Utc>,
) -> AppResult<chrono::DateTime<Utc>> {
    for asset in &execution.assets {
        for permission in &execution.manifest.required_permissions {
            let grant = execution
                .scope_grants
                .iter()
                .find(|grant| {
                    crate::domain::grant_is_effective(grant, &asset.id, permission.clone(), now)
                })
                .ok_or_else(|| {
                    AppError::NotAuthorized(format!(
                        "asset {} has no current {:?} grant for provider-service egress",
                        asset.id, permission
                    ))
                })?;
            if let Some(expires_at) = grant.expires_at {
                ceiling = ceiling.min(expires_at);
            }
        }
    }
    if ceiling <= now {
        return Err(AppError::NotAuthorized(
            "provider-service execution authorization expired before network provisioning".into(),
        ));
    }
    Ok(ceiling.min(now + Duration::hours(1)))
}

pub(crate) fn provider_source_for_execution(
    state: &CoreState,
    execution: &PlannedEngineExecution,
) -> AppResult<Option<DataSource>> {
    let case = state.case_service().show_case(&execution.case_id)?;
    let candidate_source_ids = execution
        .assets
        .iter()
        .flat_map(|asset| asset.discovered_from.iter())
        .filter_map(|source_id| {
            case.data_sources
                .iter()
                .find(|source| {
                    source.id == *source_id
                        && source.read_only
                        && source.status == SourceConnectionStatus::Connected
                        && matches!(
                            source.kind,
                            SourceKind::AwsOrganization
                                | SourceKind::AzureTenant
                                | SourceKind::GcpOrganization
                                | SourceKind::Microsoft365Tenant
                        )
                })
                .map(|source| source.id.clone())
        })
        .collect::<std::collections::BTreeSet<_>>();
    if candidate_source_ids.is_empty() {
        return Ok(None);
    }
    if candidate_source_ids.len() != 1 {
        return Err(AppError::InvalidRequest(
            "one engine execution cannot combine multiple provider sources".into(),
        ));
    }
    let source_id = candidate_source_ids
        .into_iter()
        .next()
        .expect("one source id");
    if execution
        .assets
        .iter()
        .any(|asset| !asset.discovered_from.contains(&source_id))
    {
        return Err(AppError::NotAuthorized(
            "provider source is not attributable to every execution target".into(),
        ));
    }
    let source = case
        .data_sources
        .into_iter()
        .find(|source| source.id == source_id)
        .expect("source id came from this case");
    for asset in &execution.assets {
        let Some(provider) = asset.provider.as_deref() else {
            continue;
        };
        if !provider_matches_source(provider, &source.kind) {
            return Err(AppError::NotAuthorized(format!(
                "asset {} provider conflicts with its connected source kind",
                asset.id
            )));
        }
    }
    Ok(Some(source))
}

pub(crate) fn provider_matches_source(provider: &str, source_kind: &SourceKind) -> bool {
    let normalized = provider
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect::<String>();
    match source_kind {
        SourceKind::AwsOrganization => matches!(normalized.as_str(), "aws" | "amazonwebservices"),
        SourceKind::AzureTenant => matches!(normalized.as_str(), "azure" | "microsoftazure"),
        SourceKind::GcpOrganization => {
            matches!(
                normalized.as_str(),
                "gcp" | "googlecloud" | "googlecloudplatform"
            )
        }
        SourceKind::Microsoft365Tenant => {
            matches!(normalized.as_str(), "m365" | "microsoft365" | "office365")
        }
        _ => false,
    }
}

pub(crate) fn resolve_execution_workspace(
    state: &CoreState,
    execution: &PlannedEngineExecution,
) -> AppResult<Option<crate::workspace_snapshot::ResolvedWorkspaceSnapshot>> {
    let Some(reference) = execution_workspace_reference(state, execution)? else {
        return Ok(None);
    };
    let resolved =
        resolve_workspace_snapshot(state.artifact_root(), &execution.case_id, &reference)?;
    if execution.manifest.id == crate::mcp_armor_input::MCP_ARMOR_ENGINE_ID {
        let [asset] = execution.assets.as_slice() else {
            return Err(AppError::InvalidRequest(
                "MCP Armor requires exactly one immutable repository asset".into(),
            ));
        };
        verify_mcp_configuration_selection(asset, &resolved.manifest)?;
    }
    if execution.manifest.id == crate::agentic_radar_input::AGENTIC_RADAR_ENGINE_ID {
        let [asset] = execution.assets.as_slice() else {
            return Err(AppError::InvalidRequest(
                "AI workflow inventory requires exactly one immutable repository asset".into(),
            ));
        };
        if crate::agentic_radar_input::selected_framework(asset)?.is_none() {
            return Err(AppError::NotAuthorized(
                "Choose an AI workflow framework before running inventory".into(),
            ));
        }
    }
    Ok(Some(resolved))
}

pub(crate) fn execution_workspace_reference(
    state: &CoreState,
    execution: &PlannedEngineExecution,
) -> AppResult<Option<WorkspaceSnapshotReference>> {
    if !execution
        .manifest
        .required_permissions
        .contains(&ScanPermission::LocalArtifactRead)
    {
        return Ok(None);
    }
    let [asset] = execution.assets.as_slice() else {
        return Err(AppError::InvalidRequest(format!(
            "local engine {} requires exactly one immutable workspace asset per execution",
            execution.manifest.id
        )));
    };
    let case = state.case_service().show_case(&execution.case_id)?;
    let mut references = Vec::<WorkspaceSnapshotReference>::new();
    for source_id in &asset.discovered_from {
        let Some(source) = case
            .data_sources
            .iter()
            .find(|source| source.id == *source_id)
        else {
            continue;
        };
        if source.status != SourceConnectionStatus::Connected || !source.read_only {
            continue;
        }
        let Some(value) = source
            .metadata
            .get(WORKSPACE_SNAPSHOT_REFERENCE_METADATA_KEY)
        else {
            continue;
        };
        references.push(serde_json::from_value(value.clone()).map_err(|_| {
            AppError::InvalidRequest(
                "workspace source has an invalid backend snapshot reference".into(),
            )
        })?);
    }
    references.sort_by(|left, right| left.storage_id.cmp(&right.storage_id));
    references.dedup_by(|left, right| left.storage_id == right.storage_id);
    if references.len() > 1 {
        return Err(AppError::NotAuthorized(
            "authorized local asset resolves to more than one immutable input snapshot".into(),
        ));
    }
    let reference = references.into_iter().next().ok_or_else(|| {
        AppError::NotAuthorized(
            "authorized local asset has no immutable backend input snapshot".into(),
        )
    })?;
    if asset.kind != reference.input_profile.asset_kind() {
        return Err(AppError::NotAuthorized(
            "local asset kind conflicts with its backend-attested input profile".into(),
        ));
    }
    let input_contract = execution
        .manifest
        .input_contracts
        .iter()
        .find(|contract| contract.asset_kind == asset.kind)
        .ok_or_else(|| {
            AppError::InvalidRequest(format!(
                "engine {} has no typed input contract for the authorized local asset",
                execution.manifest.id
            ))
        })?;
    if input_contract.input_profile != reference.input_profile {
        return Err(AppError::NotAuthorized(format!(
            "engine {} input contract conflicts with the backend-attested snapshot profile",
            execution.manifest.id
        )));
    }
    let expected_sha = asset
        .metadata
        .get("workspace_snapshot_sha256")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            AppError::InvalidRequest("workspace asset has no canonical snapshot digest".into())
        })?;
    if expected_sha != reference.sha256 {
        return Err(AppError::NotAuthorized(
            "workspace asset digest does not match its backend snapshot reference".into(),
        ));
    }
    Ok(Some(reference))
}

pub(crate) fn checkpoint_for(
    execution: &PlannedEngineExecution,
    stage: ExecutionStage,
    last_error: Option<String>,
) -> ExecutionCheckpoint {
    let same_attempt_checkpoint = execution
        .resume_checkpoint
        .as_ref()
        .filter(|checkpoint| checkpoint.attempt == execution.attempt);
    let runtime_command_provenance = execution
        .resume_checkpoint
        .as_ref()
        .filter(|checkpoint| checkpoint.attempt == execution.attempt)
        .and_then(|checkpoint| checkpoint.runtime_command_provenance.clone());
    let runtime_provider =
        same_attempt_checkpoint.and_then(|checkpoint| checkpoint.runtime_provider);
    let managed_network =
        same_attempt_checkpoint.and_then(|checkpoint| checkpoint.managed_network.clone());
    ExecutionCheckpoint {
        case_id: execution.case_id.clone(),
        scan_run_id: execution.scan_run_id.clone(),
        engine_run_id: execution.engine_run_id.clone(),
        engine_id: execution.manifest.id.clone(),
        attempt: execution.attempt,
        stage,
        container_name: None,
        scope_sha256: None,
        zap_plan_sha256: None,
        launcher_plan_sha256: None,
        artifact_ids: vec![],
        cleanup_completed: managed_network.is_none(),
        last_error,
        failure_code: None,
        runtime_command_provenance,
        runtime_provider,
        managed_network,
    }
}

pub(crate) fn terminal_report(
    execution: &PlannedEngineExecution,
    stage: ExecutionStage,
    message: &str,
) -> DurableExecutionReport {
    DurableExecutionReport {
        checkpoint: checkpoint_for(execution, stage, Some(bounded_text(message, 2_000))),
        runtime_preflight: None,
        cleanup: None,
        exit_code: None,
        raw_artifacts: vec![],
        findings: vec![],
        observations: vec![],
        warnings: vec![],
        unattributed: vec![],
        unevaluated_targets: vec![],
        security_template_executions: Vec::new(),
        manual_review_controls: vec![],
    }
}

pub(crate) fn bounded_error(error: &AppError) -> String {
    bounded_text(&error.to_string(), 2_000)
}

pub(crate) fn bounded_text(value: &str, maximum: usize) -> String {
    value.chars().take(maximum).collect()
}

pub(crate) fn managed_cleanup_pending_error(
    prior_error: Option<&str>,
    cleanup_error: &str,
) -> String {
    const MAX_ERROR_CHARS: usize = 2_000;
    const MAX_CLEANUP_CONTEXT_CHARS: usize = 512;

    let cleanup_error = cleanup_error.trim();
    let cleanup_error = if cleanup_error.is_empty() {
        "managed egress cleanup failed without an error detail"
    } else {
        cleanup_error
    };
    match prior_error.map(str::trim).filter(|error| !error.is_empty()) {
        Some(primary) => {
            let prefix = "; managed egress cleanup also failed: ";
            let detail_budget = MAX_CLEANUP_CONTEXT_CHARS.saturating_sub(prefix.chars().count());
            let suffix = format!("{prefix}{}", bounded_text(cleanup_error, detail_budget));
            let primary_budget = MAX_ERROR_CHARS.saturating_sub(suffix.chars().count());
            format!("{}{}", bounded_text(primary, primary_budget), suffix)
        }
        None => bounded_text(
            &format!("managed egress cleanup failed: {cleanup_error}"),
            MAX_CLEANUP_CONTEXT_CHARS,
        ),
    }
}

pub(crate) fn record_managed_cleanup_failure(
    checkpoint: &mut ExecutionCheckpoint,
    cleanup: &mut Option<CleanupOutcome>,
    warnings: &mut Vec<String>,
    cleanup_error: &str,
    warning: &str,
) {
    let retained_error =
        managed_cleanup_pending_error(checkpoint.last_error.as_deref(), cleanup_error);
    checkpoint.stage = ExecutionStage::CleanupPending;
    checkpoint.cleanup_completed = false;
    checkpoint.last_error = Some(retained_error);
    *cleanup = Some(CleanupOutcome {
        removed: false,
        detail: bounded_text(cleanup_error, 2_000),
        gateway_refusals: None,
    });
    warnings.push(warning.into());
}

pub(crate) struct RuntimeCheckpointIdentity<'a> {
    pub(crate) provenance: &'a RuntimeCommandProvenance,
    pub(crate) provider: RuntimeProvider,
}

pub(crate) fn terminal_after_prestart_error(
    execution: &PlannedEngineExecution,
    error: &AppError,
    network_identity: Option<&crate::managed_network::ManagedNetworkIdentity>,
    network_lease: &mut Option<ManagedNetworkLease>,
    reconciled_cleanup: Option<&ManagedNetworkCleanupOutcome>,
    runtime_identity: RuntimeCheckpointIdentity<'_>,
    launcher_plan_sha256: Option<&str>,
) -> DurableExecutionReport {
    let mut durable = terminal_report(execution, ExecutionStage::Failed, &bounded_error(error));
    durable.checkpoint.launcher_plan_sha256 = launcher_plan_sha256.map(str::to_owned);
    durable.checkpoint.runtime_command_provenance = Some(runtime_identity.provenance.clone());
    durable.checkpoint.runtime_provider = Some(runtime_identity.provider);
    durable.checkpoint.managed_network = network_identity.cloned();
    if let Some(outcome) = reconciled_cleanup {
        merge_managed_cleanup(&mut durable.cleanup, outcome);
    }
    if let Some(lease) = network_lease.as_mut() {
        match lease.cleanup_with_outcome() {
            Ok(outcome) => {
                merge_managed_cleanup(&mut durable.cleanup, &outcome);
                durable.checkpoint.cleanup_completed = true;
            }
            Err(cleanup_error) => {
                record_managed_cleanup_failure(
                    &mut durable.checkpoint,
                    &mut durable.cleanup,
                    &mut durable.warnings,
                    &cleanup_error.to_string(),
                    "Managed egress cleanup status: pending.",
                );
            }
        }
    }
    durable
}

pub(crate) fn merge_managed_cleanup(
    cleanup: &mut Option<CleanupOutcome>,
    managed: &ManagedNetworkCleanupOutcome,
) {
    let previous = cleanup.take();
    // A later cleanup that did not read a status document must not erase a
    // record an earlier one already read. A later read replaces it.
    let gateway_refusals = managed.gateway_refusals.or(previous
        .as_ref()
        .and_then(|outcome| outcome.gateway_refusals));
    *cleanup = Some(CleanupOutcome {
        removed: previous.as_ref().is_none_or(|outcome| outcome.removed) && managed.removed,
        detail: bounded_text(
            &match previous {
                Some(outcome) if !outcome.detail.is_empty() => {
                    format!("{}; managed egress: {}", outcome.detail, managed.detail)
                }
                _ => format!("managed egress: {}", managed.detail),
            },
            4_000,
        ),
        gateway_refusals,
    });
}

pub(crate) fn merge_container_cleanup(
    managed: &mut Option<ManagedNetworkCleanupOutcome>,
    container: &CleanupOutcome,
) {
    let prior = managed.take();
    let gateway_refusals = prior.as_ref().and_then(|outcome| outcome.gateway_refusals);
    *managed = Some(ManagedNetworkCleanupOutcome {
        removed: prior.as_ref().is_none_or(|outcome| outcome.removed) && container.removed,
        detail: bounded_text(
            &match prior {
                Some(outcome) => format!(
                    "{}; interrupted container cleanup: {}",
                    outcome.detail, container.detail
                ),
                None => format!("interrupted container cleanup: {}", container.detail),
            },
            2_000,
        ),
        gateway_refusals,
    });
}

pub(crate) fn merge_reconciled_managed_cleanup(
    combined: &mut Option<ManagedNetworkCleanupOutcome>,
    managed: ManagedNetworkCleanupOutcome,
) {
    let prior = combined.take();
    let gateway_refusals = managed
        .gateway_refusals
        .or(prior.as_ref().and_then(|outcome| outcome.gateway_refusals));
    *combined = Some(ManagedNetworkCleanupOutcome {
        removed: prior.as_ref().is_none_or(|outcome| outcome.removed) && managed.removed,
        detail: bounded_text(
            &match prior {
                Some(outcome) => format!("{}; managed egress: {}", outcome.detail, managed.detail),
                None => format!("managed egress: {}", managed.detail),
            },
            2_000,
        ),
        gateway_refusals,
    });
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TerminalJobReconciliation {
    Reconciled,
    InProgress,
    NotCurrent,
}

pub(crate) fn reconcile_terminal_job(
    app: &ScanCoordinator,
    key: &JobKey,
    snapshot: &JobSnapshot,
) -> AppResult<TerminalJobReconciliation> {
    let state = app.state();
    let case = match state.jobs.reconcile_terminal_snapshot(snapshot, || {
        persist_terminal_job_reconciliation(state, key, snapshot)
    })? {
        TerminalReconciliationOutcome::Reconciled(case) => case,
        TerminalReconciliationOutcome::InProgress => {
            return Ok(TerminalJobReconciliation::InProgress);
        }
        TerminalReconciliationOutcome::NotCurrent => {
            return Ok(TerminalJobReconciliation::NotCurrent);
        }
    };
    let run = case.scan_runs.iter().find(|run| run.id == key.scan_run_id);
    let fully_terminal = run.is_some_and(crate::report_snapshot::terminal_snapshot_ready);
    let event = if fully_terminal {
        RUN_FINISHED_EVENT
    } else {
        RUN_PROGRESS_EVENT
    };
    if let Err(error) = emit(app, event, &case) {
        tracing::warn!(
            error = %error,
            case_id = %key.case_id,
            scan_run_id = %key.scan_run_id,
            fully_terminal,
            "terminal worker truth was persisted but its truthful lifecycle event was not emitted"
        );
    }
    Ok(TerminalJobReconciliation::Reconciled)
}

pub(crate) fn persist_terminal_job_reconciliation(
    state: &CoreState,
    key: &JobKey,
    snapshot: &JobSnapshot,
) -> AppResult<AssessmentCase> {
    persist_terminal_job_reconciliation_with(state, key, snapshot, |obligation| {
        reconcile_exact_runtime_cleanup(state, obligation)
    })
}

pub(crate) fn persist_terminal_job_reconciliation_with<F>(
    state: &CoreState,
    key: &JobKey,
    snapshot: &JobSnapshot,
    cleanup_exact: F,
) -> AppResult<AssessmentCase>
where
    F: FnMut(&ExactRuntimeCleanupObligation) -> AppResult<(CleanupOutcome, usize)>,
{
    persist_terminal_job_state_reconciliation(state, key, snapshot)?;
    let cleanup = reconcile_pending_scan_cleanup_with(
        state,
        Some((key.case_id.as_str(), key.scan_run_id.as_str())),
        cleanup_exact,
    )?;
    if cleanup.reconciled > 0 || cleanup.pending > 0 {
        tracing::info!(
            reconciled = cleanup.reconciled,
            pending = cleanup.pending,
            case_id = %key.case_id,
            scan_run_id = %key.scan_run_id,
            "ordinary terminal runtime cleanup was reconciled after the scan worker stopped"
        );
    }
    let service = state.case_service();
    service.finalize_verification_if_terminal(&key.case_id, &key.scan_run_id)?;
    service.retain_terminal_report_snapshot(&key.case_id, &key.scan_run_id)
}

/// Persists only the exact terminal-generation lifecycle projection. It does
/// not emit, execute cleanup, touch a runtime, or contact a target, so Cancel
/// can synchronously honor authoritative worker truth before deciding which
/// still-unfinished resource-free work the user may close.
pub(crate) fn persist_terminal_job_state_reconciliation(
    state: &CoreState,
    key: &JobKey,
    snapshot: &JobSnapshot,
) -> AppResult<AssessmentCase> {
    let service = state.case_service();
    let case = service.show_case(&key.case_id)?;
    if let Some(prepared) = prepared_localhost_quick_scan_for_job(&case, key)? {
        if snapshot.engines.len() != 1 || snapshot.engines[0].engine_id != prepared.engine_run_id {
            return Err(AppError::NotAuthorized(
                "retained localhost job identity conflicts with its exact durable task".into(),
            ));
        }
        return reconcile_managed_localhost_terminal(
            &state.storage,
            state.engines.manifests(),
            &prepared,
            snapshot.status,
        );
    }
    let run = case
        .scan_runs
        .iter()
        .find(|run| run.id == key.scan_run_id)
        .ok_or_else(|| {
            AppError::Internal(format!(
                "terminal reconciliation could not find persisted scan run {}",
                key.scan_run_id
            ))
        })?;
    for engine_snapshot in &snapshot.engines {
        let engine_run = run
            .engine_runs
            .iter()
            .find(|engine_run| engine_run.id == engine_snapshot.engine_id)
            .ok_or_else(|| {
                AppError::Internal(format!(
                    "terminal reconciliation could not find persisted engine run {}",
                    engine_snapshot.engine_id
                ))
            })?;
        if matches!(
            engine_run.status,
            EngineRunStatus::Completed
                | EngineRunStatus::PartiallyCompleted
                | EngineRunStatus::Failed
                | EngineRunStatus::Cancelled
                | EngineRunStatus::NotExecuted
        ) {
            continue;
        }
        let token = engine_run.resume_token.as_deref().ok_or_else(|| {
            AppError::Internal(format!(
                "terminal reconciliation found no checkpoint for engine run {}",
                engine_run.id
            ))
        })?;
        let mut checkpoint = ExecutionCheckpoint::from_resume_token(token).map_err(|error| {
            AppError::Internal(format!(
                "terminal reconciliation could not read checkpoint for engine run {}: {}",
                engine_run.id,
                bounded_error(&error)
            ))
        })?;
        let stage = if !checkpoint.cleanup_completed {
            ExecutionStage::CleanupPending
        } else if checkpoint.resume_action() == ResumeAction::AdaptCapturedArtifacts {
            ExecutionStage::CapturedAwaitingAdapter
        } else if engine_snapshot.status == EngineJobStatus::Cancelled {
            ExecutionStage::Cancelled
        } else {
            ExecutionStage::Failed
        };
        checkpoint.stage = stage;
        let terminal_context = match snapshot.failure_kind {
            Some(_) => "background scan worker stopped before a durable terminal report",
            None => "scan worker ended before this engine reached a durable terminal state",
        };
        checkpoint.last_error = Some(
            match checkpoint
                .last_error
                .as_deref()
                .filter(|message| !message.trim().is_empty())
                .or_else(|| {
                    engine_run
                        .error_message
                        .as_deref()
                        .filter(|message| !message.trim().is_empty())
                }) {
                Some(actionable) => {
                    // Resume planning changes the presentation state to queued but
                    // deliberately retains the prior checkpoint. If the new worker
                    // stops before producing a newer report, keep that actionable
                    // cause and add worker context instead of replacing it with a
                    // generic handoff failure. Reserve space for the suffix so the
                    // new token differs and can restore the checkpoint projection.
                    let suffix = format!("; {terminal_context}");
                    let retained = 2_000_usize.saturating_sub(suffix.chars().count());
                    format!("{}{}", bounded_text(actionable, retained), suffix)
                }
                None => terminal_context.into(),
            },
        );
        let raw_artifacts = checkpoint
            .artifact_ids
            .iter()
            .map(|artifact_id| {
                case.raw_artifacts
                    .iter()
                    .find(|artifact| artifact.id == *artifact_id)
                    .cloned()
                    .ok_or_else(|| {
                        AppError::Internal(format!(
                            "terminal reconciliation could not find raw artifact {artifact_id}"
                        ))
                    })
            })
            .collect::<AppResult<Vec<_>>>()?;
        let report = DurableExecutionReport {
            checkpoint,
            runtime_preflight: None,
            cleanup: None,
            exit_code: None,
            raw_artifacts,
            findings: vec![],
            observations: vec![],
            warnings: vec![],
            unattributed: vec![],
            unevaluated_targets: vec![],
            security_template_executions: Vec::new(),
            manual_review_controls: vec![],
        };
        service.apply_execution_report(&key.case_id, &report)?;
    }
    service.show_case(&key.case_id)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::bootstrap::BootstrapProvider;
    use crate::case_service::{
        CaseExportFormat, ScanPlanRequest, ScopeApprovalRequest, SourceMutation,
    };
    use crate::core_state::CoreState as AppState;
    use crate::credential_vault::ReadOnlyCredentialSource;
    use crate::discovery::{DiscoveredAsset, DiscoveryBatch};
    use crate::domain::{
        AssetIdentifier, AssetKind, CreateCaseRequest, DataClass, ScanPermission,
        SourceConnectionStatus, SourceKind,
    };
    use crate::export::ExportOptions;
    use crate::registry::EngineRegistry;
    use crate::source_authorization::{
        ProviderSecretMaterial, ProviderVerificationState, SecretEnvironmentValue,
        SourceAuthorizationRequest, VerifiedProviderAuthorization,
    };
    use crate::storage::Storage;
    use crate::workspace_snapshot::{
        WorkspaceInputProfile, WorkspaceSnapshotLimits, create_workspace_snapshot_with_profile,
    };
    use std::collections::{BTreeMap, BTreeSet};
    use std::path::{Path, PathBuf};
    use zeroize::Zeroizing;

    #[test]
    fn engine_container_receives_its_reviewed_cpu_allowance_up_to_this_computer() {
        let registry = EngineRegistry::load_builtin().unwrap();
        let host_cpu_millis = u32::try_from(
            std::thread::available_parallelism()
                .map_or(1, std::num::NonZeroUsize::get)
                .saturating_mul(1_000),
        )
        .unwrap_or(u32::MAX);
        let greenbone = registry.get("greenbone").unwrap();
        assert_eq!(
            engine_container_cpu_millis(greenbone),
            2_000.min(host_cpu_millis)
        );
        let gitleaks = registry.get("gitleaks").unwrap();
        assert_eq!(engine_container_cpu_millis(gitleaks), 1_000);

        let mut legacy = greenbone.clone();
        legacy.execution = None;
        assert_eq!(engine_container_cpu_millis(&legacy), 1_000);
    }

    #[test]
    fn merge_managed_cleanup_keeps_a_read_refusal_record() {
        let counted = GatewayRefusalRecord::Counted {
            rate: 2,
            destination: 0,
            unauthorized_client: 0,
        };
        let mut cleanup = None;
        merge_managed_cleanup(
            &mut cleanup,
            &ManagedNetworkCleanupOutcome {
                removed: true,
                detail: "gateway refused connections: rate 2, destination 0, unauthorized client 0"
                    .into(),
                gateway_refusals: Some(counted),
            },
        );
        merge_managed_cleanup(
            &mut cleanup,
            &ManagedNetworkCleanupOutcome {
                removed: true,
                detail: "exact internal network removed or already absent".into(),
                gateway_refusals: None,
            },
        );
        let outcome = cleanup.as_ref().expect("merged cleanup");
        assert_eq!(outcome.gateway_refusals, Some(counted));
        assert!(outcome.detail.contains("managed egress:"));

        let later = GatewayRefusalRecord::Counted {
            rate: 0,
            destination: 5,
            unauthorized_client: 1,
        };
        merge_managed_cleanup(
            &mut cleanup,
            &ManagedNetworkCleanupOutcome {
                removed: true,
                detail: "gateway refused connections: rate 0, destination 5, unauthorized client 1"
                    .into(),
                gateway_refusals: Some(later),
            },
        );
        assert_eq!(cleanup.expect("later read").gateway_refusals, Some(later));
    }

    fn make_test_file_writable(path: &Path) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let mut permissions = std::fs::metadata(path).unwrap().permissions();
            permissions.set_mode(permissions.mode() | 0o200);
            std::fs::set_permissions(path, permissions).unwrap();
        }
        #[cfg(windows)]
        {
            use std::os::windows::ffi::OsStrExt;
            use windows_sys::Win32::Storage::FileSystem::{
                FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_READONLY, GetFileAttributesW,
                INVALID_FILE_ATTRIBUTES, SetFileAttributesW,
            };

            let encoded = path
                .as_os_str()
                .encode_wide()
                .chain(std::iter::once(0))
                .collect::<Vec<_>>();
            // SAFETY: `encoded` is NUL-terminated and lives for both API calls.
            let attributes = unsafe { GetFileAttributesW(encoded.as_ptr()) };
            assert_ne!(
                attributes,
                INVALID_FILE_ATTRIBUTES,
                "inspect test file attributes: {}",
                std::io::Error::last_os_error()
            );
            if attributes & FILE_ATTRIBUTE_READONLY != 0 {
                let writable_attributes = match attributes & !FILE_ATTRIBUTE_READONLY {
                    0 => FILE_ATTRIBUTE_NORMAL,
                    remaining => remaining,
                };
                // SAFETY: `encoded` remains valid and the new mask preserves every
                // attribute except read-only.
                let status = unsafe { SetFileAttributesW(encoded.as_ptr(), writable_attributes) };
                assert_ne!(
                    status,
                    0,
                    "make test file writable: {}",
                    std::io::Error::last_os_error()
                );
            }
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = path;
        }
    }

    #[test]
    fn beginner_worker_priority_puts_fast_security_results_before_supplemental_work() {
        let mut engine_ids = vec![
            "checkov",
            "unknown-a",
            "syft",
            "trivy",
            "nuclei",
            "unknown-b",
            "semgrep",
            "gitleaks",
            "trufflehog",
            "greenbone",
            "kics",
        ];
        engine_ids.sort_by_key(|engine_id| beginner_execution_priority(engine_id));

        assert_eq!(
            engine_ids,
            [
                "gitleaks",
                "nuclei",
                "semgrep",
                "trivy",
                "trufflehog",
                "kics",
                "checkov",
                "greenbone",
                "unknown-a",
                "unknown-b",
                "syft",
            ]
        );
    }

    #[test]
    fn managed_egress_cleanup_failure_preserves_existing_error_and_cleanup_identity() {
        let identity = crate::managed_network::ManagedNetworkIdentity {
            schema_version: "1.0.0".into(),
            provider: RuntimeProvider::Docker,
            network_name: "ass-egress-test".into(),
            network_id: "network-id".into(),
            uplink_network_name: None,
            uplink_network_id: None,
            gateway_container_name: None,
            gateway_container_id: None,
            gateway_listener_ip: None,
            gateway_image_repository: None,
            gateway_image_digest: None,
            policy_id: "egress-test".into(),
            policy_sha256: "a".repeat(64),
            expires_at: Utc::now(),
            provenance: crate::managed_network::EgressGatewayProvenance::ReleaseQualification {
                case_id: "case-1".into(),
                qualification_id: "qualification-1".into(),
            },
        };
        let mut checkpoint = ExecutionCheckpoint {
            case_id: "case-1".into(),
            scan_run_id: "run-1".into(),
            engine_run_id: "engine-run-1".into(),
            engine_id: "scanner".into(),
            attempt: 1,
            stage: ExecutionStage::Failed,
            container_name: Some("ass-scanner-engine-run-1-a1".into()),
            scope_sha256: Some("b".repeat(64)),
            zap_plan_sha256: None,
            launcher_plan_sha256: None,
            artifact_ids: vec!["artifact-1".into()],
            cleanup_completed: true,
            last_error: Some("adapter rejected the captured result".into()),
            failure_code: None,
            runtime_command_provenance: Some(RuntimeCommandProvenance::Compatibility),
            runtime_provider: Some(RuntimeProvider::Docker),
            managed_network: Some(identity.clone()),
        };
        let mut cleanup = None;
        let mut warnings = Vec::new();
        let cleanup_error = format!("gateway cleanup marker: {}", "x".repeat(3_000));

        record_managed_cleanup_failure(
            &mut checkpoint,
            &mut cleanup,
            &mut warnings,
            &cleanup_error,
            "managed cleanup remains pending",
        );

        assert_eq!(checkpoint.stage, ExecutionStage::CleanupPending);
        assert!(!checkpoint.cleanup_completed);
        assert_eq!(checkpoint.managed_network, Some(identity));
        assert_eq!(
            checkpoint.container_name.as_deref(),
            Some("ass-scanner-engine-run-1-a1")
        );
        let retained = checkpoint.last_error.as_deref().unwrap();
        assert!(retained.starts_with("adapter rejected the captured result"));
        assert!(retained.contains("managed egress cleanup also failed"));
        assert!(retained.contains("gateway cleanup marker"));
        assert!(retained.chars().count() <= 2_000);
        let cleanup = cleanup.expect("cleanup outcome");
        assert!(!cleanup.removed);
        assert!(cleanup.detail.starts_with("gateway cleanup marker"));
        assert_eq!(cleanup.detail.chars().count(), 2_000);
        assert_eq!(warnings, vec!["managed cleanup remains pending".to_owned()]);
    }

    #[test]
    fn preflight_classification_does_not_blame_inputs_for_backend_failures() {
        for error in [
            AppError::Storage("database unavailable".into()),
            AppError::Internal("worker unavailable".into()),
            AppError::CaseNotFound("case-1".into()),
        ] {
            assert_eq!(
                classify_execution_preflight_error(
                    DesktopExecutionBlocker::WorkspaceSnapshotUnavailable,
                    &error,
                ),
                DesktopExecutionBlocker::ExecutionPreflightUnavailable
            );
        }

        for error in [
            AppError::InvalidRequest("saved input changed".into()),
            AppError::Runtime("saved input is missing".into()),
            AppError::NotAuthorized("saved input escaped its root".into()),
        ] {
            assert_eq!(
                classify_execution_preflight_error(
                    DesktopExecutionBlocker::WorkspaceSnapshotUnavailable,
                    &error,
                ),
                DesktopExecutionBlocker::WorkspaceSnapshotUnavailable
            );
        }
    }

    pub(crate) fn test_state() -> (crate::test_temp::TempDir, AppState) {
        let directory = crate::test_temp::tempdir().unwrap();
        let artifact_root = directory.path().join("artifacts");
        std::fs::create_dir_all(&artifact_root).unwrap();
        let state = AppState::new(
            Storage::open(directory.path().join("casework.db")).unwrap(),
            EngineRegistry::load_builtin().unwrap(),
            crate::adapters::builtin_adapter_registry().unwrap(),
            artifact_root,
            directory.path().join("signing.key"),
        );
        (directory, state)
    }

    pub(crate) fn create_test_case(state: &CoreState, title: &str) -> AssessmentCase {
        state
            .case_service()
            .create_case(&CreateCaseRequest {
                title: title.into(),
                organization_name: "Example Co".into(),
                employee_range: "1-10".into(),
                assessment_intent: None,
                ai_generated_artifact: Default::default(),
                data_classes: vec![DataClass::General],
                requested_activities: vec![],
                source_kinds: vec![],
                not_applicable_source_kinds: vec![],
                declared_assets: vec![],
                notes: None,
            })
            .unwrap()
    }

    pub(crate) fn ready_repository_state() -> (crate::test_temp::TempDir, AppState, Id) {
        let (directory, state, case_id, _) = ready_repository_snapshot_state();
        (directory, state, case_id)
    }

    fn ready_repository_snapshot_state() -> (crate::test_temp::TempDir, AppState, Id, PathBuf) {
        let (directory, state) = test_state();
        let case = create_test_case(&state, "Workspace input preflight");
        let source_directory = directory.path().join("selected-repository");
        std::fs::create_dir_all(&source_directory).unwrap();
        std::fs::write(source_directory.join("main.rs"), b"fn main() {}\n").unwrap();
        let source_id = new_id();
        let snapshot = create_workspace_snapshot_with_profile(
            state.artifact_root(),
            &case.id,
            &source_id,
            &source_directory,
            WorkspaceInputProfile::RepositoryWorkingTree,
            WorkspaceSnapshotLimits::default(),
        )
        .unwrap();
        let stored_file = state
            .artifact_root()
            .join(&case.id)
            .join("workspace-snapshots")
            .join(&snapshot.reference.storage_id)
            .join("payload")
            .join("tree")
            .join("main.rs");
        let asset_id = snapshot.asset.id.clone();
        let service = state.case_service();
        service
            .attach_workspace_snapshot(&case.id, "Selected repository", snapshot)
            .unwrap();
        service
            .approve_scope(
                &case.id,
                ScopeApprovalRequest {
                    asset_id,
                    permissions: vec![ScanPermission::LocalArtifactRead],
                    confirmed_by: "Owner".into(),
                    expires_at: None,
                    authorization_reference: None,
                    notes: None,
                    external_scope: None,
                },
            )
            .unwrap();
        (directory, state, case.id, stored_file)
    }

    fn ready_internal_network_state() -> (crate::test_temp::TempDir, AppState, Id) {
        let (directory, state) = test_state();
        let case = create_test_case(&state, "Home network preflight");
        let service = state.case_service();
        let source = service
            .upsert_source(
                &case.id,
                SourceMutation {
                    id: None,
                    kind: SourceKind::UserDeclared,
                    label: "Home network".into(),
                    status: SourceConnectionStatus::Connected,
                    read_only: true,
                    metadata: BTreeMap::new(),
                },
            )
            .unwrap();
        service
            .reconcile_discovery_batch(
                &case.id,
                &DiscoveryBatch {
                    source_id: source.id,
                    source_kind: SourceKind::UserDeclared,
                    connector_id: "test".into(),
                    connector_version: "1".into(),
                    observed_at: Utc::now(),
                    assets: vec![DiscoveredAsset {
                        observation_key: "home-network".into(),
                        kind: AssetKind::IpAddress,
                        name: "192.168.50.0/30".into(),
                        provider: None,
                        region: None,
                        stable_identifier: AssetIdentifier {
                            namespace: "network:cidr".into(),
                            value: "192.168.50.0/30".into(),
                        },
                        additional_identifiers: vec![],
                        internet_exposed: Some(false),
                        contains_sensitive_data: None,
                        metadata: BTreeMap::new(),
                    }],
                    relations: vec![],
                    notices: vec![],
                },
            )
            .unwrap();
        let asset_id = service.show_case(&case.id).unwrap().assets[0].id.clone();
        service
            .approve_scope(
                &case.id,
                ScopeApprovalRequest {
                    asset_id,
                    permissions: vec![ScanPermission::LowImpactExternalConnection],
                    confirmed_by: "Home network owner".into(),
                    expires_at: Some(Utc::now() + Duration::hours(1)),
                    authorization_reference: Some("local-owner-confirmation".into()),
                    notes: None,
                    external_scope: Some(crate::external_scope::ExternalScopeRequest {
                        target: "192.168.50.0/30".into(),
                        ports: [443].into_iter().collect(),
                        protocol: crate::external_scope::TransportProtocol::Tcp,
                        activity: crate::external_scope::ExternalActivity::LowImpactExternal,
                        rate_policy: crate::external_scope::RatePolicy {
                            requests_per_second: 2,
                            concurrency: 1,
                            timeout_seconds: 300,
                        },
                        template_policy: crate::external_scope::TemplatePolicy::conservative(
                            "not_applicable",
                            vec![],
                        ),
                        asserted_authority: "Confirmed by the home network owner".into(),
                        allow_sensitive_networks: true,
                    }),
                },
            )
            .unwrap();
        (directory, state, case.id)
    }

    #[test]
    fn missing_workspace_is_reported_after_the_scan_run_is_persisted() {
        let (_directory, state, case_id, stored_file) = ready_repository_snapshot_state();
        let service = state.case_service();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(
                stored_file.parent().unwrap(),
                std::fs::Permissions::from_mode(0o700),
            )
            .unwrap();
        }
        #[cfg(windows)]
        {
            make_test_file_writable(&stored_file);
        }
        std::fs::remove_file(stored_file).unwrap();

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
        let error = validate_execution_inputs_static(&state, &plan)
            .map_err(DesktopExecutionBlocker::into_error)
            .unwrap_err();

        assert!(error.to_string().contains("workspace_snapshot_unavailable"));
        assert_eq!(service.show_case(&case_id).unwrap().scan_runs.len(), 1);
    }

    #[test]
    fn changed_workspace_is_reported_after_a_scan_run_is_persisted() {
        let (_directory, state, case_id, stored_file) = ready_repository_snapshot_state();
        let service = state.case_service();
        let preview = service
            .preview_scan_for_execution(
                &case_id,
                ScanPlanRequest {
                    campaign_id: None,
                    engine_ids: vec!["gitleaks".into()],
                    engine_asset_routes: Vec::new(),
                },
            )
            .unwrap();
        validate_execution_inputs_static(&state, &preview).unwrap();

        make_test_file_writable(&stored_file);
        std::fs::write(&stored_file, b"fn changed_after_setup() {}\n").unwrap();
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
        let error = validate_execution_inputs_static(&state, &plan)
            .map_err(DesktopExecutionBlocker::into_error)
            .unwrap_err();

        assert!(error.to_string().contains("workspace_snapshot_unavailable"));
        assert_eq!(service.show_case(&case_id).unwrap().scan_runs.len(), 1);
    }

    #[test]
    fn invalid_release_gateway_manifest_is_reported_after_persistence() {
        let (_directory, state, case_id) = ready_internal_network_state();
        let service = state.case_service();

        let plan = service
            .persist_scan_before_execution_preflight(
                &case_id,
                ScanPlanRequest {
                    campaign_id: None,
                    engine_ids: vec!["naabu".into()],
                    engine_asset_routes: Vec::new(),
                },
            )
            .unwrap();
        let error = validate_execution_inputs_static_with_gateway(&state, &plan, || {
            Err(AppError::NotAvailable(
                "release gateway manifest unavailable".into(),
            ))
        })
        .map_err(DesktopExecutionBlocker::into_error)
        .unwrap_err();

        assert!(error.to_string().contains("egress_gateway_unavailable"));
        assert_eq!(service.show_case(&case_id).unwrap().scan_runs.len(), 1);
    }

    #[test]
    fn reviewed_launcher_v2_preparation_freezes_and_replays_one_exact_attempt() {
        let (_directory, state, case_id) = ready_internal_network_state();
        let service = state.case_service();
        let plan = service
            .persist_scan_before_execution_preflight(
                &case_id,
                ScanPlanRequest {
                    campaign_id: None,
                    engine_ids: vec![NAABU_ENGINE_ID.into()],
                    engine_asset_routes: Vec::new(),
                },
            )
            .expect("persist Naabu run");
        let mut execution = plan.executable.into_iter().next().expect("Naabu execution");
        execution.manifest.execution = Some(EngineExecutionContract {
            resources: EngineExecutionResources {
                timeout_seconds: 3_600,
                cpu_millis: 1_000,
            },
            launcher_journal_version: Some(LAUNCHER_V2_JOURNAL_SCHEMA_VERSION),
        });

        let first = prepare_naabu_launcher_attempt(&state, &execution, Utc::now())
            .expect("prepare launcher attempt")
            .expect("v2 preparation");
        assert_eq!(first.request.execution_attempt, 1);
        assert!(!first.request.requested_unit_ids.is_empty());
        assert_eq!(
            first.request.launcher_plan_sha256,
            hex::encode(Sha256::digest(
                serde_json::to_vec(&first.launcher_plan).unwrap()
            ))
        );
        assert_eq!(
            first
                .work_plan
                .resolved_plans_for_work_units(&first.request.requested_unit_ids)
                .unwrap(),
            first.gateway_plans
        );

        service
            .persist_naabu_attempt_request(
                &execution.case_id,
                &execution.scan_run_id,
                &execution.engine_run_id,
                &first.work_plan,
                &first.request,
            )
            .expect("persist exact launcher request");

        // Once durable, preparation is reconstructed from the saved plan and
        // request. It does not need the mutable grant snapshot or a new DNS
        // lookup to reproduce the exact sidecar and gateway inputs.
        execution.naabu_work_plan = Some(first.work_plan.clone());
        execution.scope_grants.clear();
        let replay = prepare_naabu_launcher_attempt(&state, &execution, Utc::now())
            .expect("replay launcher attempt")
            .expect("v2 replay");
        assert_eq!(replay.request, first.request);
        assert_eq!(replay.launcher_plan, first.launcher_plan);
        assert_eq!(replay.gateway_plans, first.gateway_plans);

        let saved = service.show_case(&case_id).expect("saved case");
        let saved_engine = &saved.scan_runs[0].engine_runs[0];
        assert_eq!(
            saved_engine.naabu_work_plan.as_ref(),
            Some(&first.work_plan)
        );
        assert_eq!(saved_engine.naabu_attempt_requests, vec![first.request]);
    }

    fn normalized_naabu_pending_state() -> (
        crate::test_temp::TempDir,
        CoreState,
        Id,
        PlannedEngineExecution,
        NaabuAttemptResult,
    ) {
        let (_directory, state, case_id) = ready_internal_network_state();
        let service = state.case_service();
        let plan = service
            .persist_scan_before_execution_preflight(
                &case_id,
                ScanPlanRequest {
                    campaign_id: None,
                    engine_ids: vec![NAABU_ENGINE_ID.into()],
                    engine_asset_routes: Vec::new(),
                },
            )
            .expect("persist Naabu run");
        let mut execution = plan.executable.into_iter().next().expect("Naabu execution");
        execution.manifest.execution = Some(EngineExecutionContract {
            resources: EngineExecutionResources {
                timeout_seconds: 3_600,
                cpu_millis: 1_000,
            },
            launcher_journal_version: Some(LAUNCHER_V2_JOURNAL_SCHEMA_VERSION),
        });
        let prepared = prepare_naabu_launcher_attempt(&state, &execution, Utc::now())
            .expect("prepare launcher attempt")
            .expect("current launcher preparation");
        service
            .persist_naabu_attempt_request(
                &execution.case_id,
                &execution.scan_run_id,
                &execution.engine_run_id,
                &prepared.work_plan,
                &prepared.request,
            )
            .expect("persist exact attempt request");

        // Model the exact process-free handoff left after the latest batch was
        // normalized but before a continuation worker could be registered.
        // A not-tested unit keeps the plan honestly unfinished without needing
        // any fabricated evidence or target contact in this command test.
        let work_units = prepared
            .request
            .requested_unit_ids
            .iter()
            .map(|unit_id| {
                let unit = prepared
                    .work_plan
                    .work_units
                    .iter()
                    .find(|unit| &unit.unit_id == unit_id)
                    .unwrap();
                crate::execution_coverage::WorkUnitCoverage {
                    unit_id: unit.unit_id.clone(),
                    scope_sha256: unit.scope_sha256.clone(),
                    outcome: crate::execution_coverage::WorkUnitOutcome::NotTested,
                    attempts: vec![],
                }
            })
            .collect::<Vec<_>>();
        let requested = work_units.len();
        let normalized_result = NaabuAttemptResult {
            schema_version: NAABU_ATTEMPT_RESULT_SCHEMA_VERSION,
            execution_attempt: prepared.request.execution_attempt,
            journal_raw_artifact_id: "saved-naabu-journal-attempt-1".into(),
            coverage: crate::execution_coverage::ValidatedExecutionCoverage {
                schema_version: crate::execution_coverage::LAUNCHER_V2_JOURNAL_SCHEMA_VERSION,
                engine_run_id: execution.engine_run_id.clone(),
                execution_attempt: prepared.request.execution_attempt,
                recovered_trailing_record: false,
                validated_artifact_bindings: vec![],
                unreferenced_final_artifacts: vec![],
                work_units,
                summary: crate::execution_coverage::ExecutionCoverageSummary {
                    requested,
                    tested_complete: 0,
                    tested_partial: 0,
                    failed: 0,
                    timed_out: 0,
                    cancelled: 0,
                    not_tested: requested,
                    partial: true,
                    has_usable_results: false,
                },
            },
            normalization_complete: true,
        };

        let mut stored = service.show_case(&case_id).unwrap();
        let run = stored
            .scan_runs
            .iter_mut()
            .find(|run| run.id == execution.scan_run_id)
            .unwrap();
        let engine_run = run
            .engine_runs
            .iter_mut()
            .find(|engine_run| engine_run.id == execution.engine_run_id)
            .unwrap();
        let mut checkpoint =
            ExecutionCheckpoint::from_resume_token(engine_run.resume_token.as_deref().unwrap())
                .unwrap();
        checkpoint.stage = ExecutionStage::CapturedAwaitingAdapter;
        // A launcher digest is meaningful only alongside the immutable scope
        // document that the modeled attempt already handed to the runtime.
        checkpoint.scope_sha256 = Some("b".repeat(64));
        checkpoint.launcher_plan_sha256 = Some(prepared.request.launcher_plan_sha256.clone());
        checkpoint.cleanup_completed = true;
        checkpoint.last_error = None;
        engine_run.status = EngineRunStatus::PartiallyCompleted;
        engine_run.phase = "captured_awaiting_adapter".into();
        engine_run.progress_percent = 41;
        engine_run.finished_at = Some(Utc::now());
        engine_run.exit_code = Some(0);
        engine_run.error_code = None;
        engine_run.error_message = None;
        engine_run.resume_token = Some(checkpoint.resume_token().unwrap());
        engine_run.naabu_attempt_results = vec![normalized_result.clone()];
        run.completed_at = Some(Utc::now());
        stored.status = CaseStatus::NeedsAttention;
        state
            .storage
            .save_case(&mut stored, "test.no_worker_naabu_between_batch")
            .unwrap();

        (_directory, state, case_id, execution, normalized_result)
    }

    #[test]
    fn no_worker_cancel_closes_normalized_naabu_work_before_terminal_shortcut() {
        let (_directory, state, case_id, execution, normalized_result) =
            normalized_naabu_pending_state();
        let service = state.case_service();
        let before = service.show_case(&case_id).unwrap();
        let before_run = before
            .scan_runs
            .iter()
            .find(|run| run.id == execution.scan_run_id)
            .unwrap();
        assert!(durable_run_has_final_outcome(before_run));
        assert_eq!(
            unfinished_clean_naabu_between_batch_cancel_target(before_run).unwrap(),
            Some((execution.engine_run_id.clone(), execution.attempt))
        );
        let before_engine = before_run
            .engine_runs
            .iter()
            .find(|engine_run| engine_run.id == execution.engine_run_id)
            .unwrap()
            .clone();

        let NoWorkerCancelAdmission::Cancelled(cancelled) =
            apply_no_worker_durable_cancel(&service, &case_id, &execution.scan_run_id, before)
                .expect("command decision uses one durable no-worker transition")
        else {
            panic!("normalized unfinished Naabu work must be durably cancelled")
        };
        let cancelled_engine = cancelled
            .scan_runs
            .iter()
            .find(|run| run.id == execution.scan_run_id)
            .and_then(|run| {
                run.engine_runs
                    .iter()
                    .find(|engine_run| engine_run.id == execution.engine_run_id)
            })
            .unwrap();
        assert_eq!(cancelled_engine.status, EngineRunStatus::Cancelled);
        assert_eq!(cancelled_engine.phase, "cancelled_after_partial_results");
        assert_eq!(cancelled_engine.progress_percent, 41);
        assert_eq!(
            cancelled_engine.naabu_attempt_requests,
            before_engine.naabu_attempt_requests
        );
        assert_eq!(
            cancelled_engine.naabu_attempt_results,
            vec![normalized_result]
        );
        assert_eq!(cancelled_engine.resume_token, before_engine.resume_token);
    }

    #[test]
    fn saved_next_phase_reconstructs_one_exact_resource_free_worker_attempt() {
        let (_directory, state, case_id) = ready_internal_network_state();
        let service = state.case_service();
        let plan = service
            .persist_scan_before_execution_preflight(
                &case_id,
                ScanPlanRequest {
                    campaign_id: None,
                    engine_ids: vec![NAABU_ENGINE_ID.into()],
                    engine_asset_routes: Vec::new(),
                },
            )
            .expect("persist Naabu run");
        let mut execution = plan.executable.into_iter().next().expect("Naabu execution");
        execution.manifest.execution = Some(EngineExecutionContract {
            resources: EngineExecutionResources {
                timeout_seconds: 3_600,
                cpu_millis: 1_000,
            },
            launcher_journal_version: Some(LAUNCHER_V2_JOURNAL_SCHEMA_VERSION),
        });
        execution.attempt = 1;

        let mut case = service.show_case(&case_id).unwrap();
        let engine_run = &mut case.scan_runs[0].engine_runs[0];
        engine_run.status = EngineRunStatus::Queued;
        engine_run.phase = "queued_for_next_phase".into();
        engine_run.error_code = None;
        engine_run.error_message = None;
        engine_run.naabu_attempt_requests.push(NaabuAttemptRequest {
            schema_version: NAABU_ATTEMPT_REQUEST_SCHEMA_VERSION,
            execution_attempt: 2,
            requested_unit_ids: vec!["unit-2".into()],
            launcher_plan_sha256: "a".repeat(64),
        });
        let checkpoint = ExecutionCheckpoint {
            case_id: case.id.clone(),
            scan_run_id: execution.scan_run_id.clone(),
            engine_run_id: execution.engine_run_id.clone(),
            engine_id: NAABU_ENGINE_ID.into(),
            attempt: 2,
            stage: ExecutionStage::Planned,
            container_name: None,
            scope_sha256: None,
            zap_plan_sha256: None,
            launcher_plan_sha256: None,
            artifact_ids: vec![],
            cleanup_completed: true,
            last_error: None,
            failure_code: None,
            runtime_command_provenance: None,
            runtime_provider: None,
            managed_network: None,
        };
        let checkpoint_token = checkpoint.resume_token().unwrap();
        engine_run.resume_token = Some(checkpoint_token.clone());

        let continued = continued_naabu_launcher_v2_execution(&execution, &case)
            .expect("exact saved next phase");
        assert_eq!(continued.attempt, 2);
        assert_eq!(
            continued
                .resume_checkpoint
                .as_ref()
                .expect("continued checkpoint")
                .resume_token()
                .expect("continued checkpoint token"),
            checkpoint_token
        );
    }

    #[test]
    fn legacy_naabu_manifest_does_not_activate_launcher_v2_planning() {
        let (_directory, state, case_id) = ready_internal_network_state();
        let plan = state
            .case_service()
            .persist_scan_before_execution_preflight(
                &case_id,
                ScanPlanRequest {
                    campaign_id: None,
                    engine_ids: vec![NAABU_ENGINE_ID.into()],
                    engine_asset_routes: Vec::new(),
                },
            )
            .expect("persist legacy Naabu run");
        let mut execution = plan.executable.into_iter().next().expect("Naabu execution");
        execution
            .manifest
            .execution
            .as_mut()
            .expect("Naabu execution contract")
            .launcher_journal_version = None;

        assert!(
            prepare_naabu_launcher_attempt(&state, &execution, Utc::now())
                .expect("legacy preparation check")
                .is_none()
        );
        let saved = state.case_service().show_case(&case_id).unwrap();
        assert!(
            saved.scan_runs[0].engine_runs[0]
                .naabu_attempt_requests
                .is_empty()
        );
    }

    pub(crate) fn verified_aws_authorization_for_account(
        issued_at: chrono::DateTime<Utc>,
        account_id: &str,
        evidence_character: &str,
    ) -> VerifiedProviderAuthorization {
        let profile = ProviderSourceProfile::AwsOrganizationReadOnlySession;
        let provider_identity =
            format!("arn:aws:sts::{account_id}:assumed-role/security-audit-reader/session");
        let expires_at = issued_at + Duration::minutes(30);
        let verification = ProviderVerificationState {
            schema_version: "1.0.0".into(),
            provider: BootstrapProvider::Aws,
            profile,
            authentication_method: "fixture_short_lived_session".into(),
            provider_identity: provider_identity.clone(),
            subject_id: "fixture-subject".into(),
            resource_scope: format!("aws-account:{account_id}"),
            verified_at: issued_at,
            credential_expires_at: expires_at,
            identity_endpoint: "https://sts.amazonaws.com/".into(),
            permission_endpoints: vec!["https://iam.amazonaws.com/".into()],
            required_permissions_verified: vec!["inventory.read".into()],
            prohibited_permissions_denied: vec!["inventory.write".into()],
            provider_request_ids: vec!["fixture-request".into()],
            evidence_sha256: evidence_character.repeat(64),
        };
        VerifiedProviderAuthorization::new_verified(
            profile,
            ReadOnlyCredentialSource::ProviderNative,
            provider_identity,
            expires_at,
            verification,
            ProviderSecretMaterial::new(vec![
                SecretEnvironmentValue::new(
                    "AWS_ACCESS_KEY_ID",
                    Zeroizing::new("fixture-access-key".into()),
                ),
                SecretEnvironmentValue::new(
                    "AWS_SECRET_ACCESS_KEY",
                    Zeroizing::new("fixture-secret-key".into()),
                ),
                SecretEnvironmentValue::new(
                    "AWS_SESSION_TOKEN",
                    Zeroizing::new("fixture-session-token".into()),
                ),
            ]),
        )
        .unwrap()
    }

    fn add_ready_aws_account(
        state: &CoreState,
        case_id: &str,
        issued_at: chrono::DateTime<Utc>,
        account_id: &str,
        evidence_character: &str,
        max_checkouts: u16,
    ) -> (Id, Id) {
        let service = state.case_service();
        let source = service
            .upsert_source(
                case_id,
                SourceMutation {
                    id: None,
                    kind: SourceKind::AwsOrganization,
                    label: format!("AWS account {account_id}"),
                    status: SourceConnectionStatus::Connected,
                    read_only: true,
                    metadata: BTreeMap::new(),
                },
            )
            .unwrap();
        service
            .reconcile_discovery_batch(
                case_id,
                &DiscoveryBatch {
                    source_id: source.id.clone(),
                    source_kind: SourceKind::AwsOrganization,
                    connector_id: "aws-organizations-list-accounts".into(),
                    connector_version: "1".into(),
                    observed_at: issued_at,
                    assets: vec![DiscoveredAsset {
                        observation_key: format!("aws-account-{account_id}"),
                        kind: AssetKind::CloudAccount,
                        name: format!("AWS account {account_id}"),
                        provider: Some("aws".into()),
                        region: None,
                        stable_identifier: AssetIdentifier {
                            namespace: "aws_account_id".into(),
                            value: account_id.into(),
                        },
                        additional_identifiers: vec![],
                        internet_exposed: None,
                        contains_sensitive_data: None,
                        metadata: BTreeMap::new(),
                    }],
                    relations: vec![],
                    notices: vec![],
                },
            )
            .unwrap();
        let asset_id = service
            .show_case(case_id)
            .unwrap()
            .assets
            .into_iter()
            .find(|asset| {
                asset.identifiers.iter().any(|identifier| {
                    identifier.namespace == "aws_account_id" && identifier.value == account_id
                })
            })
            .unwrap()
            .id;
        service
            .approve_scope(
                case_id,
                ScopeApprovalRequest {
                    asset_id: asset_id.clone(),
                    permissions: vec![ScanPermission::InventoryRead],
                    confirmed_by: "Cloud owner".into(),
                    expires_at: None,
                    authorization_reference: None,
                    notes: None,
                    external_scope: None,
                },
            )
            .unwrap();
        let verified =
            verified_aws_authorization_for_account(issued_at, account_id, evidence_character);
        let verification = verified.verification().clone();
        state
            .source_authorizations
            .install(
                SourceAuthorizationRequest {
                    case_id: case_id.into(),
                    source_id: source.id.clone(),
                    allowed_engine_ids: BTreeSet::from(["steampipe".into()]),
                    max_checkouts,
                    verified_authorization: verified,
                },
                issued_at,
            )
            .unwrap();
        state
            .case_service()
            .connect_verified_provider_source(case_id, &source.id, &verification)
            .unwrap();
        (source.id, asset_id)
    }

    pub(crate) fn ready_aws_state(
        issued_at: chrono::DateTime<Utc>,
        max_checkouts: u16,
    ) -> (crate::test_temp::TempDir, AppState, Id, Id) {
        let (directory, state) = test_state();
        let case = create_test_case(&state, "Provider preflight");
        let (source_id, _) = add_ready_aws_account(
            &state,
            &case.id,
            issued_at,
            "111122223333",
            "a",
            max_checkouts,
        );
        (directory, state, case.id, source_id)
    }

    fn completed_baseline(state: &CoreState, case_id: &str, engine_id: &str) -> Id {
        let service = state.case_service();
        let baseline = service
            .plan_scan(
                case_id,
                ScanPlanRequest {
                    campaign_id: None,
                    engine_ids: vec![engine_id.into()],
                    engine_asset_routes: Vec::new(),
                },
            )
            .unwrap();
        let mut stored = service.show_case(case_id).unwrap();
        let run = stored
            .scan_runs
            .iter_mut()
            .find(|run| run.id == baseline.scan_run.id)
            .unwrap();
        run.completed_at = Some(baseline.scan_run.created_at);
        for engine_run in &mut run.engine_runs {
            engine_run.status = EngineRunStatus::Completed;
            engine_run.progress_percent = 100;
            engine_run.phase = "completed".into();
            engine_run.started_at = Some(baseline.scan_run.created_at);
            engine_run.finished_at = Some(baseline.scan_run.created_at);
            engine_run.exit_code = Some(0);
        }
        stored.status = CaseStatus::ReadyForHandoff;
        state
            .storage
            .save_case(&mut stored, "test.completed_baseline")
            .unwrap();
        baseline.scan_run.id
    }

    fn interrupted_repository_state(
        checkpoint_stage: ExecutionStage,
    ) -> (crate::test_temp::TempDir, AppState, Id, Id) {
        let (directory, state, case_id, _) = ready_repository_snapshot_state();
        let service = state.case_service();
        let plan = service
            .plan_scan(
                &case_id,
                ScanPlanRequest {
                    campaign_id: None,
                    engine_ids: vec!["gitleaks".into()],
                    engine_asset_routes: Vec::new(),
                },
            )
            .unwrap();
        if checkpoint_stage != ExecutionStage::Planned {
            let mut stored = service.show_case(&case_id).unwrap();
            let engine_run = &mut stored.scan_runs[0].engine_runs[0];
            let mut checkpoint =
                ExecutionCheckpoint::from_resume_token(engine_run.resume_token.as_deref().unwrap())
                    .unwrap();
            checkpoint.stage = checkpoint_stage;
            engine_run.resume_token = Some(checkpoint.resume_token().unwrap());
            state
                .storage
                .save_case(&mut stored, "test.interrupted_checkpoint")
                .unwrap();
        }
        assert_eq!(service.recover_interrupted_scans().unwrap(), 1);
        (directory, state, case_id, plan.scan_run.id)
    }

    fn ordinary_cleanup_pending_state() -> (crate::test_temp::TempDir, AppState, Id, Id, Id) {
        let (directory, state, case_id) = ready_repository_state();
        let service = state.case_service();
        let plan = service
            .plan_scan(
                &case_id,
                ScanPlanRequest {
                    campaign_id: None,
                    engine_ids: vec!["gitleaks".into()],
                    engine_asset_routes: Vec::new(),
                },
            )
            .unwrap();
        let run_id = plan.scan_run.id.clone();
        let engine_run_id = plan.executable[0].engine_run_id.clone();
        let mut stored = service.show_case(&case_id).unwrap();
        let run = stored
            .scan_runs
            .iter_mut()
            .find(|run| run.id == run_id)
            .unwrap();
        let engine_run = run
            .engine_runs
            .iter_mut()
            .find(|engine| engine.id == engine_run_id)
            .unwrap();
        let mut checkpoint =
            ExecutionCheckpoint::from_resume_token(engine_run.resume_token.as_deref().unwrap())
                .unwrap();
        checkpoint.stage = ExecutionStage::CleanupPending;
        checkpoint.cleanup_completed = false;
        checkpoint.container_name = Some(
            crate::container_runtime::planned_container_name(
                &checkpoint.engine_id,
                &checkpoint.engine_run_id,
                checkpoint.attempt,
            )
            .unwrap(),
        );
        checkpoint.scope_sha256 = Some("a".repeat(64));
        checkpoint.runtime_provider = Some(RuntimeProvider::Podman);
        checkpoint.runtime_command_provenance = Some(RuntimeCommandProvenance::Compatibility);
        checkpoint.artifact_ids = vec!["retained-ordinary-evidence".into()];
        checkpoint.last_error = Some("managed egress cleanup did not finish".into());
        engine_run.status = EngineRunStatus::PartiallyCompleted;
        engine_run.phase = "cleanup_pending".into();
        engine_run.progress_percent = 95;
        engine_run.finished_at = Some(Utc::now());
        engine_run.resume_token = Some(checkpoint.resume_token().unwrap());
        engine_run.raw_artifact_ids = checkpoint.artifact_ids.clone();
        engine_run.cleanup_removed = Some(false);
        engine_run.cleanup_detail = checkpoint.last_error.clone();
        engine_run.error_code = Some("runtime_cleanup_pending".into());
        engine_run.error_message = checkpoint.last_error.clone();
        engine_run
            .warnings
            .push("scanner output was saved before cleanup stopped".into());
        run.completed_at = Some(Utc::now());
        stored.status = CaseStatus::NeedsAttention;
        state
            .storage
            .save_case(&mut stored, "test.ordinary_cleanup_pending")
            .unwrap();
        (directory, state, case_id, run_id, engine_run_id)
    }

    #[test]
    fn startup_recovery_terminalizes_a_resource_free_planned_checkpoint_once() {
        let (_directory, state, case_id, run_id) =
            interrupted_repository_state(ExecutionStage::Planned);
        let first =
            reconcile_interrupted_scan_resources(&state, Some((&case_id, &run_id))).unwrap();
        assert_eq!(first.reconciled, 0);
        assert_eq!(first.pending, 0);
        let stored = state.case_service().show_case(&case_id).unwrap();
        assert_eq!(
            stored.scan_runs[0].engine_runs[0].phase,
            "preflight_interrupted"
        );
        assert_eq!(
            stored.scan_runs[0].engine_runs[0].status,
            EngineRunStatus::Failed
        );
        assert!(stored.scan_runs[0].completed_at.is_some());
        assert_eq!(state.case_service().recover_interrupted_scans().unwrap(), 0);
        let replay =
            reconcile_interrupted_scan_resources(&state, Some((&case_id, &run_id))).unwrap();
        assert_eq!(replay.reconciled, 0);
        assert_eq!(replay.pending, 0);
        assert_eq!(
            state
                .case_service()
                .plan_resume(&case_id, &run_id)
                .unwrap()
                .executable[0]
                .attempt,
            2
        );
    }

    #[test]
    fn startup_reconciliation_never_infers_preflight_checkpoint_was_resource_free() {
        let (_directory, state, case_id, run_id) =
            interrupted_repository_state(ExecutionStage::Preflight);
        let first =
            reconcile_interrupted_scan_resources(&state, Some((&case_id, &run_id))).unwrap();
        assert_eq!(first.reconciled, 1);
        assert_eq!(first.pending, 0);
        let stored = state.case_service().show_case(&case_id).unwrap();
        assert_eq!(
            stored.scan_runs[0].engine_runs[0].phase,
            "interrupted_restart_cleanup_identity_unavailable"
        );
        assert_eq!(
            stored.scan_runs[0].engine_runs[0].status,
            EngineRunStatus::Failed
        );
        assert!(stored.scan_runs[0].completed_at.is_some());
        assert_eq!(state.case_service().recover_interrupted_scans().unwrap(), 0);
        let retry =
            reconcile_interrupted_scan_resources(&state, Some((&case_id, &run_id))).unwrap();
        assert_eq!(retry.reconciled, 0);
        assert_eq!(retry.pending, 0);
        state
            .case_service()
            .plan_scan(
                &case_id,
                ScanPlanRequest {
                    campaign_id: None,
                    engine_ids: vec!["gitleaks".into()],
                    engine_asset_routes: Vec::new(),
                },
            )
            .expect("untrusted preflight state must not block a new isolated scan");
    }

    #[test]
    fn interrupted_cleanup_preserves_untrusted_markers_without_runtime_cleanup() {
        enum UntrustedShape {
            Missing,
            Corrupt,
            IdentityMismatch,
        }

        for shape in [
            UntrustedShape::Missing,
            UntrustedShape::Corrupt,
            UntrustedShape::IdentityMismatch,
        ] {
            let (_directory, state, case_id, run_id) =
                interrupted_repository_state(ExecutionStage::Preflight);
            let mut stored = state.case_service().show_case(&case_id).unwrap();
            let engine = &mut stored.scan_runs[0].engine_runs[0];
            let engine_run_id = engine.id.clone();
            match shape {
                UntrustedShape::Missing => engine.resume_token = None,
                UntrustedShape::Corrupt => {
                    engine.resume_token = Some("{preserved-corrupt-interrupted-token".into())
                }
                UntrustedShape::IdentityMismatch => {
                    let mut checkpoint = ExecutionCheckpoint::from_resume_token(
                        engine.resume_token.as_deref().unwrap(),
                    )
                    .unwrap();
                    checkpoint.engine_run_id = "different-engine-run".into();
                    engine.resume_token = Some(checkpoint.resume_token().unwrap());
                }
            }
            let preserved_token = engine.resume_token.clone();
            let preserved_artifacts = engine.raw_artifact_ids.clone();
            state
                .storage
                .save_case(&mut stored, "test.untrusted_interrupted_cleanup_marker")
                .unwrap();

            let mut cleanup_calls = 0_usize;
            let summary = reconcile_interrupted_scan_resources_with(
                &state,
                Some((&case_id, &run_id)),
                |_| -> AppResult<(CleanupOutcome, usize)> {
                    cleanup_calls = cleanup_calls.saturating_add(1);
                    panic!("untrusted interrupted marker must not invoke runtime cleanup")
                },
            )
            .unwrap();
            assert_eq!(cleanup_calls, 0);
            assert_eq!(summary.reconciled, 1);
            assert_eq!(summary.pending, 0);
            assert!(
                summary
                    .details
                    .iter()
                    .any(|detail| { detail.contains("cleanup status: unresolved") })
            );

            let after = state.case_service().show_case(&case_id).unwrap();
            let engine = after.scan_runs[0]
                .engine_runs
                .iter()
                .find(|engine| engine.id == engine_run_id)
                .unwrap();
            assert_eq!(engine.status, EngineRunStatus::Failed);
            assert_eq!(
                engine.phase,
                "interrupted_restart_cleanup_identity_unavailable"
            );
            assert_eq!(
                engine.error_code.as_deref(),
                Some("runtime_cleanup_identity_unavailable")
            );
            assert_eq!(engine.resume_token, preserved_token);
            assert_eq!(engine.raw_artifact_ids, preserved_artifacts);
            assert_eq!(engine.cleanup_removed, Some(false));

            let new_run = state
                .case_service()
                .plan_scan(
                    &case_id,
                    ScanPlanRequest {
                        campaign_id: None,
                        engine_ids: vec!["gitleaks".into()],
                        engine_asset_routes: Vec::new(),
                    },
                )
                .expect("untrusted old state must not block a new isolated scan");
            assert_ne!(new_run.scan_run.id, run_id);
        }
    }

    #[test]
    fn ordinary_cleanup_reconciliation_preserves_partial_output_and_later_run_state() {
        let (_directory, state, case_id, run_id, engine_run_id) = ordinary_cleanup_pending_state();
        let later = state
            .case_service()
            .plan_scan(
                &case_id,
                ScanPlanRequest {
                    campaign_id: None,
                    engine_ids: vec!["gitleaks".into()],
                    engine_asset_routes: Vec::new(),
                },
            )
            .expect("start a later independent run");
        let before = state.case_service().show_case(&case_id).unwrap();
        let visible_status = before.status.clone();
        let original = before
            .scan_runs
            .iter()
            .find(|run| run.id == run_id)
            .unwrap()
            .engine_runs
            .iter()
            .find(|engine| engine.id == engine_run_id)
            .unwrap();
        let retained_artifacts = original.raw_artifact_ids.clone();
        let retained_warnings = original.warnings.clone();
        let retained_findings = serde_json::to_value(&before.findings).unwrap();

        let summary =
            reconcile_pending_scan_cleanup_with(&state, Some((&case_id, &run_id)), |obligation| {
                let checkpoint =
                    ExecutionCheckpoint::from_resume_token(&obligation.resume_token).unwrap();
                assert_eq!(checkpoint.case_id, case_id);
                assert_eq!(checkpoint.scan_run_id, run_id);
                assert_eq!(checkpoint.engine_run_id, engine_run_id);
                assert_eq!(checkpoint.stage, ExecutionStage::CleanupPending);
                assert!(!checkpoint.cleanup_completed);
                Ok((
                    CleanupOutcome {
                        removed: true,
                        detail: "removed only the exact product-owned runtime resources".into(),

                        gateway_refusals: None,
                    },
                    0,
                ))
            })
            .unwrap();
        assert_eq!(summary.reconciled, 1);
        assert_eq!(summary.pending, 0);

        let after = state.case_service().show_case(&case_id).unwrap();
        assert_eq!(after.status, visible_status);
        assert_eq!(
            serde_json::to_value(&after.findings).unwrap(),
            retained_findings
        );
        let cleaned = after
            .scan_runs
            .iter()
            .find(|run| run.id == run_id)
            .unwrap()
            .engine_runs
            .iter()
            .find(|engine| engine.id == engine_run_id)
            .unwrap();
        assert_eq!(cleaned.status, EngineRunStatus::PartiallyCompleted);
        assert_eq!(cleaned.phase, "cleanup_reconciled");
        assert_eq!(cleaned.raw_artifact_ids, retained_artifacts);
        assert_eq!(cleaned.warnings, retained_warnings);
        assert_eq!(cleaned.cleanup_removed, Some(true));
        let checkpoint =
            ExecutionCheckpoint::from_resume_token(cleaned.resume_token.as_deref().unwrap())
                .unwrap();
        assert_eq!(checkpoint.stage, ExecutionStage::Failed);
        assert!(checkpoint.cleanup_completed);
        assert_eq!(checkpoint.artifact_ids, retained_artifacts);
        assert!(checkpoint.managed_network.is_none());
        assert!(
            checkpoint
                .last_error
                .as_deref()
                .unwrap()
                .contains("Runtime cleanup: complete. Scanner outcome: Partial.")
        );
        let later_engine = after
            .scan_runs
            .iter()
            .find(|run| run.id == later.scan_run.id)
            .unwrap()
            .engine_runs
            .iter()
            .find(|engine| engine.id == later.executable[0].engine_run_id)
            .unwrap();
        assert_eq!(later_engine.status, EngineRunStatus::Queued);

        let replay = reconcile_pending_scan_cleanup_with(
            &state,
            Some((&case_id, &run_id)),
            |_| -> AppResult<(CleanupOutcome, usize)> {
                panic!("a cleared cleanup obligation must not execute twice")
            },
        )
        .unwrap();
        assert_eq!(replay.reconciled, 0);
        assert_eq!(replay.pending, 0);
    }

    #[test]
    fn ordinary_cleanup_failure_remains_exact_pending_with_a_bounded_reason() {
        let (_directory, state, case_id, run_id, engine_run_id) = ordinary_cleanup_pending_state();
        let summary =
            reconcile_pending_scan_cleanup_with(&state, Some((&case_id, &run_id)), |_| {
                Err(AppError::Runtime(format!(
                    "cleanup probe: {}",
                    "x".repeat(3_000)
                )))
            })
            .unwrap();
        assert_eq!(summary.reconciled, 0);
        assert_eq!(summary.pending, 1);

        let stored = state.case_service().show_case(&case_id).unwrap();
        let engine = stored
            .scan_runs
            .iter()
            .find(|run| run.id == run_id)
            .unwrap()
            .engine_runs
            .iter()
            .find(|engine| engine.id == engine_run_id)
            .unwrap();
        assert_eq!(engine.status, EngineRunStatus::PartiallyCompleted);
        assert_eq!(engine.phase, "cleanup_pending");
        assert_eq!(engine.cleanup_removed, Some(false));
        let reason = engine.error_message.as_deref().unwrap();
        assert!(reason.contains("Runtime cleanup status: pending"));
        assert!(reason.chars().count() <= 2_000);
        let checkpoint =
            ExecutionCheckpoint::from_resume_token(engine.resume_token.as_deref().unwrap())
                .unwrap();
        assert_eq!(checkpoint.stage, ExecutionStage::CleanupPending);
        assert!(!checkpoint.cleanup_completed);
        assert_eq!(checkpoint.last_error.as_deref(), Some(reason));
    }

    #[test]
    fn ordinary_cleanup_collector_ignores_non_partial_status() {
        let (_directory, state, case_id, run_id, engine_run_id) = ordinary_cleanup_pending_state();
        let mut stored = state.case_service().show_case(&case_id).unwrap();
        let engine = stored
            .scan_runs
            .iter_mut()
            .find(|run| run.id == run_id)
            .unwrap()
            .engine_runs
            .iter_mut()
            .find(|engine| engine.id == engine_run_id)
            .unwrap();
        engine.status = EngineRunStatus::Failed;
        state
            .storage
            .save_case(&mut stored, "test.non_partial_cleanup_shape")
            .unwrap();
        let rejected_status = reconcile_pending_scan_cleanup_with(
            &state,
            Some((&case_id, &run_id)),
            |_| -> AppResult<(CleanupOutcome, usize)> { panic!("non-partial status was accepted") },
        )
        .unwrap();
        assert_eq!(rejected_status.reconciled, 0);
        assert_eq!(rejected_status.pending, 0);
    }

    #[test]
    fn ordinary_cleanup_collector_preserves_untrusted_markers_without_runtime_cleanup() {
        #[derive(Clone, Copy)]
        enum UntrustedShape {
            Missing,
            Corrupt,
            IdentityMismatch,
            WrongStage,
            MissingImage,
            MissingScope,
            OwnershipLabelMismatch,
        }

        for shape in [
            UntrustedShape::Missing,
            UntrustedShape::Corrupt,
            UntrustedShape::IdentityMismatch,
            UntrustedShape::WrongStage,
            UntrustedShape::MissingImage,
            UntrustedShape::MissingScope,
            UntrustedShape::OwnershipLabelMismatch,
        ] {
            let (_directory, state, case_id, run_id, engine_run_id) =
                ordinary_cleanup_pending_state();
            let mut stored = state.case_service().show_case(&case_id).unwrap();
            let engine = stored
                .scan_runs
                .iter_mut()
                .find(|run| run.id == run_id)
                .unwrap()
                .engine_runs
                .iter_mut()
                .find(|engine| engine.id == engine_run_id)
                .unwrap();
            let original_artifacts = engine.raw_artifact_ids.clone();
            let original_warning = engine.warnings[0].clone();
            match shape {
                UntrustedShape::Missing => engine.resume_token = None,
                UntrustedShape::Corrupt => {
                    engine.resume_token = Some("{preserved-corrupt-checkpoint".into())
                }
                UntrustedShape::IdentityMismatch => {
                    let mut checkpoint = ExecutionCheckpoint::from_resume_token(
                        engine.resume_token.as_deref().unwrap(),
                    )
                    .unwrap();
                    checkpoint.case_id = "different-case".into();
                    engine.resume_token = Some(checkpoint.resume_token().unwrap());
                }
                UntrustedShape::WrongStage => {
                    let mut checkpoint = ExecutionCheckpoint::from_resume_token(
                        engine.resume_token.as_deref().unwrap(),
                    )
                    .unwrap();
                    checkpoint.stage = ExecutionStage::Failed;
                    engine.resume_token = Some(checkpoint.resume_token().unwrap());
                }
                UntrustedShape::MissingImage => engine.image_digest = None,
                UntrustedShape::MissingScope => {
                    let mut checkpoint = ExecutionCheckpoint::from_resume_token(
                        engine.resume_token.as_deref().unwrap(),
                    )
                    .unwrap();
                    checkpoint.scope_sha256 = None;
                    engine.resume_token = Some(checkpoint.resume_token().unwrap());
                }
                UntrustedShape::OwnershipLabelMismatch => {}
            }
            let preserved_token = engine.resume_token.clone();
            state
                .storage
                .save_case(&mut stored, "test.untrusted_cleanup_marker")
                .unwrap();

            let mut cleanup_calls = 0_usize;
            let ownership_label_mismatch = matches!(shape, UntrustedShape::OwnershipLabelMismatch);
            let summary = reconcile_pending_scan_cleanup_with(
                &state,
                Some((&case_id, &run_id)),
                |_| -> AppResult<(CleanupOutcome, usize)> {
                    cleanup_calls = cleanup_calls.saturating_add(1);
                    if ownership_label_mismatch {
                        return Err(AppError::NotAuthorized(
                            "container ownership labels do not match the exact execution".into(),
                        ));
                    }
                    panic!("untrusted marker must not invoke runtime cleanup")
                },
            )
            .unwrap();
            assert_eq!(cleanup_calls, if ownership_label_mismatch { 1 } else { 0 });
            assert_eq!(summary.reconciled, 1);
            assert_eq!(summary.pending, 0);
            assert!(
                summary
                    .details
                    .iter()
                    .any(|detail| detail.contains("cleanup status: unresolved"))
            );

            let after = state.case_service().show_case(&case_id).unwrap();
            let engine = after
                .scan_runs
                .iter()
                .find(|run| run.id == run_id)
                .unwrap()
                .engine_runs
                .iter()
                .find(|engine| engine.id == engine_run_id)
                .unwrap();
            assert_eq!(engine.status, EngineRunStatus::PartiallyCompleted);
            assert_eq!(engine.phase, "cleanup_identity_unavailable");
            assert_eq!(
                engine.error_code.as_deref(),
                Some("runtime_cleanup_identity_unavailable")
            );
            assert_eq!(engine.cleanup_removed, Some(false));
            assert_eq!(engine.resume_token, preserved_token);
            assert_eq!(engine.raw_artifact_ids, original_artifacts);
            assert!(engine.warnings.contains(&original_warning));
            assert!(
                engine
                    .error_message
                    .as_deref()
                    .unwrap()
                    .contains("Start a new isolated scan.")
            );

            let new_run = state
                .case_service()
                .plan_scan(
                    &case_id,
                    ScanPlanRequest {
                        campaign_id: None,
                        engine_ids: vec!["gitleaks".into()],
                        engine_asset_routes: Vec::new(),
                    },
                )
                .expect("untrusted cleanup proof must not block a new isolated scan");
            assert_ne!(new_run.scan_run.id, run_id);

            let replay = reconcile_pending_scan_cleanup_with(
                &state,
                Some((&case_id, &run_id)),
                |_| -> AppResult<(CleanupOutcome, usize)> {
                    panic!("terminalized untrusted marker must not run again")
                },
            )
            .unwrap();
            assert_eq!(replay.reconciled, 0);
            assert_eq!(replay.pending, 0);
        }
    }

    #[test]
    fn no_worker_cancel_accepts_runtime_bound_plans_but_not_execution_resources() {
        let (_directory, state, case_id) = ready_repository_state();
        let mut plan = state
            .case_service()
            .persist_scan_before_execution_preflight(
                &case_id,
                ScanPlanRequest {
                    campaign_id: None,
                    engine_ids: vec!["gitleaks".into()],
                    engine_asset_routes: Vec::new(),
                },
            )
            .unwrap();
        let engine = &plan.scan_run.engine_runs[0];
        let engine_id = engine.id.clone();
        let mut checkpoint =
            ExecutionCheckpoint::from_resume_token(engine.resume_token.as_deref().unwrap())
                .unwrap();
        checkpoint.runtime_provider = Some(crate::container_runtime::RuntimeProvider::Docker);
        checkpoint.runtime_command_provenance =
            Some(crate::container_runtime::RuntimeCommandProvenance::Compatibility);
        plan.scan_run.engine_runs[0].resume_token = Some(checkpoint.resume_token().unwrap());
        assert_eq!(
            locally_cancellable_resource_free_engine_ids(&plan.scan_run),
            vec![engine_id]
        );

        let clean = checkpoint.clone();
        for mutation in ["container", "scope", "artifact", "cleanup", "runtime_pair"] {
            let mut checkpoint = clean.clone();
            match mutation {
                "container" => {
                    checkpoint.container_name = Some(
                        crate::container_runtime::planned_container_name(
                            &checkpoint.engine_id,
                            &checkpoint.engine_run_id,
                            checkpoint.attempt,
                        )
                        .unwrap(),
                    )
                }
                "scope" => checkpoint.scope_sha256 = Some("a".repeat(64)),
                "artifact" => checkpoint.artifact_ids.push("captured-evidence".into()),
                "cleanup" => checkpoint.cleanup_completed = false,
                "runtime_pair" => checkpoint.runtime_provider = None,
                _ => unreachable!(),
            }
            // Serialize the deliberately invalid pair too, to exercise parse validation.
            plan.scan_run.engine_runs[0].resume_token =
                Some(serde_json::to_string(&checkpoint).unwrap());
            assert!(
                locally_cancellable_resource_free_engine_ids(&plan.scan_run).is_empty(),
                "{mutation}"
            );
        }
    }

    #[test]
    fn unavailable_runtime_preflight_is_classified_after_new_run_persistence() {
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
        let error = validate_desktop_execution_with_runtime(&state, &plan, || {
            Err(AppError::Runtime("fixture runtime is unavailable".into()))
        })
        .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("scan_preflight:runtime_unavailable")
        );
        let after = service.show_case(&case_id).unwrap();
        assert_eq!(after.scan_runs.len(), 1);
    }

    fn assert_saved_preflight_failure(
        state: &CoreState,
        case_id: &str,
        engine_id: &str,
        blocker: DesktopExecutionBlocker,
    ) {
        let expected_code = blocker.blocker_code().as_str();
        let reason = blocker.persisted_reason();
        let plan = state
            .case_service()
            .persist_scan_before_execution_preflight(
                case_id,
                ScanPlanRequest {
                    campaign_id: None,
                    engine_ids: vec![engine_id.into()],
                    engine_asset_routes: Vec::new(),
                },
            )
            .unwrap();
        let task_outcomes = plan
            .executable
            .iter()
            .map(|execution| PersistedPreDispatchTaskOutcome::Failed {
                engine_run_id: execution.engine_run_id.clone(),
                reason,
            })
            .collect();
        let returned = state
            .case_service()
            .transition_persisted_scan_pre_dispatch(
                case_id,
                &plan.scan_run.id,
                &PersistedPreDispatchTransition::ApplyOutcome { task_outcomes },
            )
            .expect("post-persistence preflight failure must become a saved terminal outcome");

        assert_eq!(returned.scan_runs.len(), 1);
        let run = &returned.scan_runs[0];
        assert!(run.completed_at.is_some());
        assert_eq!(run.engine_runs.len(), 1);
        let engine_run = &run.engine_runs[0];
        assert_eq!(engine_run.status, EngineRunStatus::Failed);
        assert_eq!(engine_run.phase, "preflight_failed");
        assert_eq!(engine_run.progress_percent, 0);
        assert!(engine_run.started_at.is_none());
        assert!(engine_run.finished_at.is_some());
        assert_eq!(engine_run.error_code.as_deref(), Some(expected_code));
        let diagnostic = engine_run.error_message.as_deref().unwrap();
        assert_eq!(diagnostic, reason.diagnostic());
        assert!(diagnostic.chars().count() <= 512);
        assert!(
            run.engine_runs
                .iter()
                .all(|engine| engine.raw_artifact_ids.is_empty())
        );
        assert_eq!(returned.status, CaseStatus::NeedsAttention);

        let reopened = state.case_service().show_case(case_id).unwrap();
        assert_eq!(reopened.scan_runs.len(), 1);
        assert_eq!(reopened.scan_runs[0].id, run.id);
        assert!(reopened.scan_runs[0].completed_at.is_some());
    }

    #[test]
    fn normal_start_runtime_preflight_failure_leaves_one_durable_terminal_run() {
        let (_directory, state, case_id) = ready_repository_state();
        assert_saved_preflight_failure(
            &state,
            &case_id,
            "gitleaks",
            DesktopExecutionBlocker::RuntimeUnavailable,
        );
    }

    #[test]
    fn normal_start_gateway_preflight_failure_leaves_one_durable_terminal_run() {
        let (_directory, state, case_id) = ready_internal_network_state();
        assert_saved_preflight_failure(
            &state,
            &case_id,
            "naabu",
            DesktopExecutionBlocker::EgressGatewayUnavailable,
        );
    }

    #[test]
    fn normal_start_input_preflight_failure_leaves_one_durable_terminal_run() {
        let (_directory, state, case_id) = ready_repository_state();
        assert_saved_preflight_failure(
            &state,
            &case_id,
            "gitleaks",
            DesktopExecutionBlocker::WorkspaceSnapshotUnavailable,
        );
    }

    #[test]
    fn normal_start_shared_runtime_failure_atomically_closes_every_runtime_sibling() {
        let (_directory, state, case_id) = ready_repository_state();
        let plan = state
            .case_service()
            .persist_scan_before_execution_preflight(
                &case_id,
                ScanPlanRequest {
                    campaign_id: None,
                    engine_ids: vec!["gitleaks".into(), "semgrep".into()],
                    engine_asset_routes: Vec::new(),
                },
            )
            .unwrap();
        let task_outcomes = plan
            .executable
            .iter()
            .map(|execution| PersistedPreDispatchTaskOutcome::Failed {
                engine_run_id: execution.engine_run_id.clone(),
                reason: PersistedScanPreflightFailureReason::RuntimeUnavailable,
            })
            .collect();
        let returned = state
            .case_service()
            .transition_persisted_scan_pre_dispatch(
                &case_id,
                &plan.scan_run.id,
                &PersistedPreDispatchTransition::ApplyOutcome { task_outcomes },
            )
            .unwrap();

        assert_eq!(returned.scan_runs.len(), 1);
        let run = &returned.scan_runs[0];
        assert!(run.completed_at.is_some());
        assert_eq!(run.engine_runs.len(), 2);
        assert!(run.engine_runs.iter().all(|engine_run| {
            engine_run.status == EngineRunStatus::Failed
                && engine_run.phase == "preflight_failed"
                && engine_run.finished_at.is_some()
        }));
        assert!(!run.engine_runs.iter().any(|engine_run| {
            matches!(
                engine_run.status,
                EngineRunStatus::Queued
                    | EngineRunStatus::Preparing
                    | EngineRunStatus::Running
                    | EngineRunStatus::Paused
            )
        }));
    }

    #[test]
    fn normal_start_preflight_diagnostic_never_persists_arbitrary_error_text() {
        let reason = PersistedScanPreflightFailureReason::ExecutionPreflightUnavailable;
        let diagnostic = reason.diagnostic();
        assert_eq!(reason.as_str(), "execution_preflight_unavailable");
        assert!(!diagnostic.contains("fixture-secret"));
        assert!(!diagnostic.contains("example.test"));
        assert!(!diagnostic.contains("Users"));
        assert!(diagnostic.chars().count() <= 512);
    }

    #[test]
    fn normal_start_with_only_not_executed_coverage_is_terminal_and_reportable() {
        let (_directory, state, case_id) = ready_repository_state();
        let plan = state
            .case_service()
            .persist_scan_before_execution_preflight(
                &case_id,
                ScanPlanRequest {
                    campaign_id: None,
                    engine_ids: vec!["missing-engine".into()],
                    engine_asset_routes: Vec::new(),
                },
            )
            .unwrap();
        assert!(plan.executable.is_empty());
        let returned = state.case_service().show_case(&case_id).unwrap();

        assert_eq!(returned.scan_runs.len(), 1);
        let run = &returned.scan_runs[0];
        assert!(run.completed_at.is_some());
        assert_eq!(run.engine_runs.len(), 1);
        assert_eq!(run.engine_runs[0].status, EngineRunStatus::NotExecuted);
        assert_eq!(run.engine_runs[0].phase, "not_executed");
        assert_eq!(returned.status, CaseStatus::NeedsAttention);

        let preview = state
            .case_service()
            .preview_export(
                &case_id,
                &run.id,
                CaseExportFormat::FrameworkReport,
                &ExportOptions::default(),
            )
            .expect("terminal coverage-only run must be available to the master report");
        assert_eq!(preview.scan_run_count, 1);
        assert_eq!(preview.selected_engine_run_count, 1);
        assert_eq!(preview.not_executed_engine_run_count, 1);
    }

    #[test]
    fn unavailable_runtime_preflight_is_classified_after_rescan_persistence() {
        let (_directory, state, case_id) = ready_repository_state();
        let baseline_run_id = completed_baseline(&state, &case_id, "gitleaks");
        let service = state.case_service();
        let rescan = service
            .persist_rescan_before_execution_preflight(
                &case_id,
                &baseline_run_id,
                ScanPlanRequest {
                    campaign_id: None,
                    engine_ids: vec!["gitleaks".into()],
                    engine_asset_routes: Vec::new(),
                },
            )
            .unwrap();
        let error = validate_desktop_execution_with_runtime(&state, &rescan.plan, || {
            Err(AppError::Runtime("fixture runtime is unavailable".into()))
        })
        .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("scan_preflight:runtime_unavailable")
        );
        let after = service.show_case(&case_id).unwrap();
        assert_eq!(after.scan_runs.len(), 2);
        assert_eq!(after.scan_runs[0].id, baseline_run_id);
    }

    #[test]
    fn expired_provider_capability_is_classified_after_new_run_persistence() {
        let issued_at = Utc::now() - Duration::minutes(40);
        let (_directory, state, case_id, _source_id) = ready_aws_state(issued_at, 1);
        let service = state.case_service();
        let plan = service
            .persist_scan_before_execution_preflight(
                &case_id,
                ScanPlanRequest {
                    campaign_id: None,
                    engine_ids: vec!["steampipe".into()],
                    engine_asset_routes: Vec::new(),
                },
            )
            .unwrap();
        let error = validate_desktop_execution_with_runtime(&state, &plan, || Ok(())).unwrap_err();

        assert!(
            error
                .to_string()
                .contains("scan_preflight:provider_capability_unavailable")
        );
        let after = service.show_case(&case_id).unwrap();
        assert_eq!(after.scan_runs.len(), 1);
    }

    #[test]
    fn exhausted_provider_capability_is_classified_after_rescan_persistence() {
        let issued_at = Utc::now();
        let (_directory, state, case_id, source_id) = ready_aws_state(issued_at, 1);
        let baseline_run_id = completed_baseline(&state, &case_id, "steampipe");
        state
            .source_authorizations
            .checkout(&case_id, &source_id, "steampipe", issued_at)
            .unwrap();
        let service = state.case_service();
        let rescan = service
            .persist_rescan_before_execution_preflight(
                &case_id,
                &baseline_run_id,
                ScanPlanRequest {
                    campaign_id: None,
                    engine_ids: vec!["steampipe".into()],
                    engine_asset_routes: Vec::new(),
                },
            )
            .unwrap();
        let error =
            validate_desktop_execution_with_runtime(&state, &rescan.plan, || Ok(())).unwrap_err();

        assert!(
            error
                .to_string()
                .contains("scan_preflight:provider_capability_unavailable")
        );
        let after = service.show_case(&case_id).unwrap();
        assert_eq!(after.scan_runs.len(), 2);
        assert_eq!(after.scan_runs[0].id, baseline_run_id);
    }

    #[test]
    fn provider_preflight_distinguishes_connection_proof_and_target_errors() {
        let issued_at = Utc::now();

        let (_directory, state, case_id, source_id) = ready_aws_state(issued_at, 2);
        let mut stored = state.case_service().show_case(&case_id).unwrap();
        stored
            .data_sources
            .iter_mut()
            .find(|source| source.id == source_id)
            .unwrap()
            .metadata
            .insert(
                "verification_evidence_sha256".into(),
                serde_json::Value::String("sentinel-proof-mismatch".into()),
            );
        state
            .storage
            .save_case(&mut stored, "test.provider_proof_mismatch")
            .unwrap();
        let proof_plan = state
            .case_service()
            .preview_scan_for_execution(
                &case_id,
                ScanPlanRequest {
                    campaign_id: None,
                    engine_ids: vec!["steampipe".into()],
                    engine_asset_routes: Vec::new(),
                },
            )
            .unwrap();
        let proof_error =
            validate_provider_execution_demands(&state, &proof_plan, issued_at).unwrap_err();
        assert_eq!(
            proof_error,
            ProviderPreflightFailure::AuthorizationBindingMismatch
        );
        let safe = proof_error.into_error().to_string();
        assert!(safe.contains("provider_authorization_binding_mismatch"));
        assert!(!safe.contains("sentinel-proof-mismatch"));

        let (_directory, state, case_id, source_id) = ready_aws_state(issued_at, 2);
        let target_plan = state
            .case_service()
            .preview_scan_for_execution(
                &case_id,
                ScanPlanRequest {
                    campaign_id: None,
                    engine_ids: vec!["steampipe".into()],
                    engine_asset_routes: Vec::new(),
                },
            )
            .unwrap();
        let mut stored = state.case_service().show_case(&case_id).unwrap();
        stored
            .data_sources
            .iter_mut()
            .find(|source| source.id == source_id)
            .unwrap()
            .kind = SourceKind::AzureTenant;
        state
            .storage
            .save_case(&mut stored, "test.provider_target_mismatch")
            .unwrap();
        assert_eq!(
            validate_provider_execution_demands(&state, &target_plan, issued_at).unwrap_err(),
            ProviderPreflightFailure::TargetBindingMismatch
        );

        let (_directory, state, case_id, source_id) = ready_aws_state(issued_at, 2);
        let mut ambiguous_plan = state
            .case_service()
            .preview_scan_for_execution(
                &case_id,
                ScanPlanRequest {
                    campaign_id: None,
                    engine_ids: vec!["steampipe".into()],
                    engine_asset_routes: Vec::new(),
                },
            )
            .unwrap();
        let mut stored = state.case_service().show_case(&case_id).unwrap();
        let mut second_source = stored
            .data_sources
            .iter()
            .find(|source| source.id == source_id)
            .unwrap()
            .clone();
        second_source.id = "source-second-aws".into();
        stored.data_sources.push(second_source);
        stored.assets[0]
            .discovered_from
            .push("source-second-aws".into());
        state
            .storage
            .save_case(&mut stored, "test.provider_source_ambiguous")
            .unwrap();
        ambiguous_plan.executable[0].assets[0]
            .discovered_from
            .push("source-second-aws".into());
        assert_eq!(
            validate_provider_execution_demands(&state, &ambiguous_plan, issued_at).unwrap_err(),
            ProviderPreflightFailure::SourceAmbiguous
        );

        let (_directory, state, case_id, source_id) = ready_aws_state(issued_at, 2);
        let reconnect_plan = state
            .case_service()
            .preview_scan_for_execution(
                &case_id,
                ScanPlanRequest {
                    campaign_id: None,
                    engine_ids: vec!["steampipe".into()],
                    engine_asset_routes: Vec::new(),
                },
            )
            .unwrap();
        let mut stored = state.case_service().show_case(&case_id).unwrap();
        stored
            .data_sources
            .iter_mut()
            .find(|source| source.id == source_id)
            .unwrap()
            .status = SourceConnectionStatus::NeedsReauthorization;
        state
            .storage
            .save_case(&mut stored, "test.provider_needs_reauthorization")
            .unwrap();
        assert_eq!(
            validate_provider_execution_demands(&state, &reconnect_plan, issued_at).unwrap_err(),
            ProviderPreflightFailure::CapabilityUnavailable
        );
    }

    #[test]
    fn one_provider_failure_does_not_suppress_another_provider_or_local_task() {
        let issued_at = Utc::now();
        let (_directory, state, case_id) = ready_repository_state();
        let (failed_source_id, _) =
            add_ready_aws_account(&state, &case_id, issued_at, "111122223333", "a", 1);
        let (ready_source_id, _) =
            add_ready_aws_account(&state, &case_id, issued_at, "444455556666", "b", 1);
        let plan = state
            .case_service()
            .persist_scan_before_execution_preflight(
                &case_id,
                ScanPlanRequest {
                    campaign_id: None,
                    engine_ids: vec!["steampipe".into(), "gitleaks".into()],
                    engine_asset_routes: Vec::new(),
                },
            )
            .unwrap();
        assert_eq!(plan.executable.len(), 3);

        let failed_provider = plan
            .executable
            .iter()
            .find(|execution| {
                execution.manifest.id == "steampipe"
                    && execution.assets[0]
                        .discovered_from
                        .contains(&failed_source_id)
            })
            .unwrap()
            .clone();
        let ready_provider = plan
            .executable
            .iter()
            .find(|execution| {
                execution.manifest.id == "steampipe"
                    && execution.assets[0]
                        .discovered_from
                        .contains(&ready_source_id)
            })
            .unwrap()
            .clone();
        let local = plan
            .executable
            .iter()
            .find(|execution| execution.manifest.id == "gitleaks")
            .unwrap()
            .clone();

        state
            .source_authorizations
            .revoke_source(&case_id, &failed_source_id, issued_at)
            .unwrap();
        let (runnable, failures) =
            partition_persisted_new_scan_tasks(&state, &plan, plan.executable.clone());
        assert_eq!(runnable.len(), 2);
        assert!(
            runnable
                .iter()
                .any(|execution| { execution.engine_run_id == ready_provider.engine_run_id })
        );
        assert!(
            runnable
                .iter()
                .any(|execution| execution.engine_run_id == local.engine_run_id)
        );
        assert_eq!(
            failures
                .get(&PersistedScanPreflightFailureReason::ProviderCapabilityUnavailable)
                .unwrap()
                .iter()
                .map(|execution| execution.engine_run_id.as_str())
                .collect::<Vec<_>>(),
            vec![failed_provider.engine_run_id.as_str()]
        );

        assert!(matches!(
            reserve_and_commit_provider_execution(&state, &plan, &failed_provider),
            Err(ProviderPreflightFailure::CapabilityUnavailable)
        ));
        let committed = reserve_and_commit_provider_execution(&state, &plan, &ready_provider)
            .unwrap()
            .expect("the independent provider task commits its exact checkout");
        assert_eq!(
            committed.context_for(&ready_provider).unwrap().source.id,
            ready_source_id
        );
        assert!(
            reserve_and_commit_provider_execution(&state, &plan, &local)
                .unwrap()
                .is_none()
        );

        let task_outcomes = complete_preflight_outcomes(&plan, &runnable, &failures).unwrap();
        let stored = state
            .case_service()
            .transition_persisted_scan_pre_dispatch(
                &case_id,
                &plan.scan_run.id,
                &PersistedPreDispatchTransition::ApplyOutcome { task_outcomes },
            )
            .unwrap();
        let run = stored
            .scan_runs
            .iter()
            .find(|run| run.id == plan.scan_run.id)
            .unwrap();
        assert_eq!(
            run.engine_runs
                .iter()
                .find(|engine| engine.id == failed_provider.engine_run_id)
                .unwrap()
                .status,
            EngineRunStatus::Failed
        );
        for runnable_id in [&ready_provider.engine_run_id, &local.engine_run_id] {
            let engine = run
                .engine_runs
                .iter()
                .find(|engine| &engine.id == runnable_id)
                .unwrap();
            assert_eq!(engine.status, EngineRunStatus::Preparing);
            assert_eq!(engine.phase, "dispatch_activated");
        }
        drop(committed);
    }

    #[test]
    fn prepared_fresh_runtime_is_reused_for_every_engine_in_the_scan_plan() {
        let (_directory, state, case_id) = ready_repository_state();
        let plan = state
            .case_service()
            .plan_scan(
                &case_id,
                ScanPlanRequest {
                    campaign_id: None,
                    engine_ids: vec!["gitleaks".into(), "semgrep".into()],
                    engine_asset_routes: Vec::new(),
                },
            )
            .unwrap();
        let prepared = PreparedRuntimeSet::with_fresh(
            ProcessContainerRuntime::new(RuntimeProvider::Docker, "prepared-runtime")
                .expect("construct compatibility runtime"),
        );

        assert_eq!(plan.executable.len(), 2);
        for execution in &plan.executable {
            let runtime = prepared
                .runtime_for(execution)
                .expect("fresh execution reuses its preflighted runtime");
            assert_eq!(
                runtime.command_context().binary(),
                Path::new("prepared-runtime")
            );
        }
    }

    #[test]
    fn shared_runtime_failure_is_computed_once_and_unaffected_group_continues() {
        let (_directory, state, case_id) = ready_repository_state();
        let plan = state
            .case_service()
            .plan_scan(
                &case_id,
                ScanPlanRequest {
                    campaign_id: None,
                    engine_ids: vec!["gitleaks".into(), "semgrep".into(), "trufflehog".into()],
                    engine_asset_routes: Vec::new(),
                },
            )
            .unwrap();
        assert_eq!(plan.executable.len(), 3);

        let mut executions = plan.executable.clone();
        let mut recorded = executions.pop().expect("recorded runtime fixture");
        recorded.resume_checkpoint = Some(ExecutionCheckpoint {
            case_id: recorded.case_id.clone(),
            scan_run_id: recorded.scan_run_id.clone(),
            engine_run_id: recorded.engine_run_id.clone(),
            engine_id: recorded.manifest.id.clone(),
            attempt: recorded.attempt,
            stage: ExecutionStage::Planned,
            container_name: None,
            scope_sha256: None,
            zap_plan_sha256: None,
            launcher_plan_sha256: None,
            artifact_ids: vec![],
            cleanup_completed: false,
            last_error: None,
            failure_code: None,
            runtime_command_provenance: Some(RuntimeCommandProvenance::Compatibility),
            runtime_provider: Some(RuntimeProvider::Docker),
            managed_network: None,
        });
        let recorded_id = recorded.engine_run_id.clone();
        let fresh_ids = executions
            .iter()
            .map(|execution| execution.engine_run_id.clone())
            .collect::<BTreeSet<_>>();
        executions.push(recorded.clone());

        let mut preparation_calls = Vec::new();
        let prepared = prepare_runtime_task_groups(executions, |identity, _representative| {
            preparation_calls.push(identity.clone());
            match identity {
                RuntimePreparationIdentity::Fresh => RuntimePreparationOutcome::Unavailable,
                RuntimePreparationIdentity::Recorded { .. } => {
                    RuntimePreparationOutcome::Prepared(Box::new(
                        ProcessContainerRuntime::new(
                            RuntimeProvider::Docker,
                            "prepared-recorded-runtime",
                        )
                        .expect("construct compatibility runtime"),
                    ))
                }
            }
        });

        assert_eq!(
            preparation_calls
                .iter()
                .filter(|identity| matches!(identity, RuntimePreparationIdentity::Fresh))
                .count(),
            1,
            "two fresh tasks share one failed/timeout computation"
        );
        assert_eq!(preparation_calls.len(), 2, "one call per runtime group");
        assert!(!prepared.cancelled);
        assert_eq!(
            prepared
                .failures
                .get(&PersistedScanPreflightFailureReason::RuntimeUnavailable)
                .expect("shared failure is persisted per dependent task")
                .iter()
                .map(|execution| execution.engine_run_id.clone())
                .collect::<BTreeSet<_>>(),
            fresh_ids
        );
        assert_eq!(prepared.runnable.len(), 1);
        assert_eq!(prepared.runnable[0].engine_run_id, recorded_id);
        assert!(
            prepared
                .prepared_runtimes
                .runtime_for(&prepared.runnable[0])
                .is_some(),
            "the unaffected runtime group remains runnable"
        );

        let task_outcomes =
            complete_preflight_outcomes(&plan, &prepared.runnable, &prepared.failures)
                .expect("one durable outcome per task");
        let stored = state
            .case_service()
            .transition_persisted_scan_pre_dispatch(
                &case_id,
                &plan.scan_run.id,
                &PersistedPreDispatchTransition::ApplyOutcome { task_outcomes },
            )
            .expect("persist grouped runtime outcomes");
        let run = stored
            .scan_runs
            .iter()
            .find(|run| run.id == plan.scan_run.id)
            .expect("stored run");
        for engine_run in &run.engine_runs {
            if engine_run.id == recorded_id {
                assert_eq!(engine_run.status, EngineRunStatus::Preparing);
                assert_eq!(engine_run.phase, "dispatch_activated");
            } else {
                assert_eq!(engine_run.status, EngineRunStatus::Failed);
                assert_eq!(
                    engine_run.error_code.as_deref(),
                    Some("runtime_unavailable")
                );
            }
        }
    }

    #[test]
    fn permanent_cancellation_persistence_failure_exhausts_a_bounded_budget() {
        let mut writes = 0_usize;
        let mut waits = 0_usize;

        let result = retry_pre_dispatch_cancellation::<()>(
            || {
                writes += 1;
                Err(AppError::Storage("permanent fixture failure".into()))
            },
            || waits += 1,
        );

        assert!(matches!(result, Err(AppError::Storage(_))));
        assert_eq!(writes, PRE_DISPATCH_CANCEL_PERSISTENCE_ATTEMPTS);
        assert_eq!(
            waits,
            PRE_DISPATCH_CANCEL_PERSISTENCE_ATTEMPTS.saturating_sub(1)
        );
    }

    #[test]
    fn runtime_resolution_and_preflight_are_cancel_aware_and_bounded() {
        let manager = crate::job_manager::JobManager::default();
        let key = JobKey::new("case-runtime", "run-runtime").unwrap();
        let (resolution_entered_tx, resolution_entered_rx) = std::sync::mpsc::channel();
        let (release_resolution_tx, release_resolution_rx) = std::sync::mpsc::channel::<()>();
        let (outcome_tx, outcome_rx) = std::sync::mpsc::channel();
        let (terminal_tx, terminal_rx) = std::sync::mpsc::channel();

        manager
            .start_job(
                key.clone(),
                ["engine-run-runtime"],
                move |context| {
                    let outcome = prepare_runtime_with_deadline(
                        move || {
                            resolution_entered_tx.send(()).unwrap();
                            let _ = release_resolution_rx.recv();
                            Err(AppError::Runtime("fixture runtime stayed blocked".into()))
                        },
                        &context,
                        StdDuration::from_secs(30),
                    );
                    let control = context.engine("engine-run-runtime").unwrap();
                    match outcome {
                        RuntimePreparationOutcome::Cancelled => {
                            control.mark_cancelled().unwrap();
                            outcome_tx.send("cancelled").unwrap();
                            JobCompletion::Cancelled
                        }
                        RuntimePreparationOutcome::Prepared(_) => {
                            control.mark_completed().unwrap();
                            outcome_tx.send("prepared").unwrap();
                            JobCompletion::Completed
                        }
                        RuntimePreparationOutcome::Unavailable => {
                            control.mark_failed().unwrap();
                            outcome_tx.send("unavailable").unwrap();
                            JobCompletion::Failed
                        }
                    }
                },
                move |snapshot| terminal_tx.send(snapshot).unwrap(),
            )
            .unwrap();

        resolution_entered_rx
            .recv_timeout(StdDuration::from_secs(2))
            .unwrap();
        assert_eq!(
            manager.cancel(&key).unwrap().status,
            crate::job_manager::JobStatus::CancelRequested
        );
        assert_eq!(
            outcome_rx.recv_timeout(StdDuration::from_secs(2)).unwrap(),
            "cancelled"
        );
        assert_eq!(
            terminal_rx
                .recv_timeout(StdDuration::from_secs(2))
                .unwrap()
                .status,
            crate::job_manager::JobStatus::Cancelled
        );
        drop(release_resolution_tx);
    }

    #[test]
    fn failed_handoff_reconciliation_terminalizes_the_persisted_execution() {
        let (_directory, state, case_id) = ready_repository_state();
        let plan = state
            .case_service()
            .persist_scan_before_execution_preflight(
                &case_id,
                ScanPlanRequest {
                    campaign_id: None,
                    engine_ids: vec!["gitleaks".into()],
                    engine_asset_routes: Vec::new(),
                },
            )
            .unwrap();
        let execution = plan.executable.first().unwrap();
        let key = JobKey::new(&case_id, &plan.scan_run.id).unwrap();
        let snapshot = JobSnapshot {
            key: key.clone(),
            status: crate::job_manager::JobStatus::Failed,
            engines: vec![crate::job_manager::EngineJobSnapshot {
                engine_id: execution.engine_run_id.clone(),
                status: EngineJobStatus::Failed,
            }],
            failure_kind: Some(crate::job_manager::JobFailureKind::WorkerPanicked),
            generation: 0,
        };

        let stored = persist_terminal_job_reconciliation(&state, &key, &snapshot).unwrap();
        let run = stored
            .scan_runs
            .iter()
            .find(|run| run.id == plan.scan_run.id)
            .unwrap();
        let engine_run = run
            .engine_runs
            .iter()
            .find(|engine_run| engine_run.id == execution.engine_run_id)
            .unwrap();
        assert_eq!(engine_run.status, EngineRunStatus::Failed);
        assert_eq!(engine_run.phase, "failed");
        assert!(engine_run.finished_at.is_some());
        assert!(run.completed_at.is_some());
        assert_eq!(
            engine_run.error_message.as_deref(),
            Some("background scan worker stopped before a durable terminal report")
        );
    }

    #[test]
    fn snapshot_refresh_replays_a_retained_terminal_outcome_without_rerunning_work() {
        let (_directory, state, case_id) = ready_repository_state();
        let plan = state
            .case_service()
            .persist_scan_before_execution_preflight(
                &case_id,
                ScanPlanRequest {
                    campaign_id: None,
                    engine_ids: vec!["gitleaks".into()],
                    engine_asset_routes: Vec::new(),
                },
            )
            .unwrap();
        let execution = plan.executable.first().unwrap();
        let engine_run_id = execution.engine_run_id.clone();
        let worker_engine_run_id = engine_run_id.clone();
        let key = JobKey::new(&case_id, &plan.scan_run.id).unwrap();
        let (terminal_tx, terminal_rx) = std::sync::mpsc::channel();

        state
            .jobs
            .start_job(
                key.clone(),
                [engine_run_id.clone()],
                move |context| {
                    context
                        .engine(&worker_engine_run_id)
                        .unwrap()
                        .mark_failed()
                        .unwrap();
                    JobCompletion::Failed
                },
                move |snapshot| terminal_tx.send(snapshot).unwrap(),
            )
            .unwrap();
        terminal_rx
            .recv_timeout(StdDuration::from_secs(2))
            .expect("worker reaches its in-memory terminal outcome");

        let before = state.case_service().show_case(&case_id).unwrap();
        let before_engine = before
            .scan_runs
            .iter()
            .find(|run| run.id == plan.scan_run.id)
            .unwrap()
            .engine_runs
            .iter()
            .find(|engine| engine.id == engine_run_id)
            .unwrap();
        assert!(!matches!(before_engine.status, EngineRunStatus::Failed));
        assert_eq!(state.jobs.terminal_snapshots().len(), 1);

        assert_eq!(
            reconcile_retained_terminal_jobs(&state),
            RetainedTerminalReconciliationSummary {
                reconciled: 1,
                pending: 0,
            }
        );
        assert!(state.jobs.terminal_snapshots().is_empty());

        let after = state.case_service().show_case(&case_id).unwrap();
        let after_engine = after
            .scan_runs
            .iter()
            .find(|run| run.id == plan.scan_run.id)
            .unwrap()
            .engine_runs
            .iter()
            .find(|engine| engine.id == engine_run_id)
            .unwrap();
        assert_eq!(after_engine.status, EngineRunStatus::Failed);
        assert!(after_engine.finished_at.is_some());
        assert_eq!(
            reconcile_retained_terminal_jobs(&state),
            RetainedTerminalReconciliationSummary::default(),
            "a second refresh is idempotent and has no work to replay"
        );
    }

    #[test]
    fn failed_resume_reconciliation_preserves_cleanup_identity_and_actionable_error() {
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
        let execution = plan.executable.first().unwrap();
        let mut stored = service.show_case(&case_id).unwrap();
        let run = stored
            .scan_runs
            .iter_mut()
            .find(|run| run.id == plan.scan_run.id)
            .unwrap();
        let engine_run = run
            .engine_runs
            .iter_mut()
            .find(|engine_run| engine_run.id == execution.engine_run_id)
            .unwrap();
        let mut checkpoint =
            ExecutionCheckpoint::from_resume_token(engine_run.resume_token.as_deref().unwrap())
                .unwrap();
        let container_name = crate::container_runtime::planned_container_name(
            &checkpoint.engine_id,
            &checkpoint.engine_run_id,
            checkpoint.attempt,
        )
        .unwrap();
        checkpoint.stage = ExecutionStage::CleanupPending;
        checkpoint.container_name = Some(container_name.clone());
        checkpoint.scope_sha256 = Some("a".repeat(64));
        checkpoint.cleanup_completed = false;
        checkpoint.last_error = Some(
            "operation is not authorized: container image does not match the persisted pinned image"
                .into(),
        );
        checkpoint.runtime_command_provenance = Some(RuntimeCommandProvenance::Compatibility);
        checkpoint.runtime_provider = Some(RuntimeProvider::Podman);
        engine_run.status = EngineRunStatus::PartiallyCompleted;
        engine_run.phase = "cleanup_pending".into();
        engine_run.progress_percent = 95;
        engine_run.finished_at = Some(Utc::now());
        engine_run.resume_token = Some(checkpoint.resume_token().unwrap());
        engine_run.cleanup_removed = Some(false);
        engine_run.cleanup_detail = Some("exact container cleanup is still required".into());
        engine_run.error_code = Some("execution_failed".into());
        engine_run.error_message = checkpoint.last_error.clone();
        run.completed_at = Some(Utc::now());
        stored.status = CaseStatus::NeedsAttention;
        state
            .storage
            .save_case(&mut stored, "test.cleanup_pending_before_resume")
            .unwrap();

        let resumed = service.plan_resume(&case_id, &plan.scan_run.id).unwrap();
        let resumed_execution = resumed.executable.first().unwrap();
        assert_eq!(resumed_execution.attempt, 2);
        let key = JobKey::new(&case_id, &plan.scan_run.id).unwrap();
        let snapshot = JobSnapshot {
            key: key.clone(),
            status: crate::job_manager::JobStatus::Failed,
            engines: vec![crate::job_manager::EngineJobSnapshot {
                engine_id: execution.engine_run_id.clone(),
                status: EngineJobStatus::Failed,
            }],
            failure_kind: Some(crate::job_manager::JobFailureKind::WorkerPanicked),
            generation: 0,
        };

        // Terminal projection and cleanup persistence are the behavior under
        // test. Inject the exact absent-resource result so the fixture never
        // depends on a host Podman installation or contacts a real runtime.
        let reconciled = persist_terminal_job_reconciliation_with(&state, &key, &snapshot, |_| {
            Ok((
                CleanupOutcome {
                    removed: false,
                    detail: "ownership-proven container was already absent".into(),

                    gateway_refusals: None,
                },
                0,
            ))
        })
        .unwrap();
        let run = reconciled
            .scan_runs
            .iter()
            .find(|run| run.id == plan.scan_run.id)
            .unwrap();
        let engine_run = run
            .engine_runs
            .iter()
            .find(|engine_run| engine_run.id == execution.engine_run_id)
            .unwrap();
        assert_eq!(engine_run.status, EngineRunStatus::PartiallyCompleted);
        assert_eq!(engine_run.phase, "cleanup_reconciled");
        assert_eq!(engine_run.progress_percent, 95);
        assert_eq!(engine_run.cleanup_removed, Some(false));
        assert!(
            engine_run
                .cleanup_detail
                .as_deref()
                .unwrap()
                .contains("ownership-proven container was already absent")
        );
        let message = engine_run.error_message.as_deref().unwrap();
        assert!(message.contains("container image does not match the persisted pinned image"));
        assert!(message.contains("background scan worker stopped"));
        assert!(message.contains("Runtime cleanup: complete. Scanner outcome: Partial."));
        assert_ne!(
            message,
            "background scan worker stopped before a durable terminal report"
        );
        let retained =
            ExecutionCheckpoint::from_resume_token(engine_run.resume_token.as_deref().unwrap())
                .unwrap();
        assert_eq!(retained.stage, ExecutionStage::Failed);
        assert_eq!(
            retained.container_name.as_deref(),
            Some(container_name.as_str())
        );
        assert_eq!(retained.scope_sha256, Some("a".repeat(64)));
        assert_eq!(retained.runtime_provider, Some(RuntimeProvider::Podman));
        assert_eq!(
            retained.runtime_command_provenance,
            Some(RuntimeCommandProvenance::Compatibility)
        );
        assert!(retained.cleanup_completed);
        assert!(run.completed_at.is_some());
    }

    #[test]
    fn captured_cloud_resume_skips_provider_demand_but_reexecution_does_not() {
        let issued_at = Utc::now();
        let (_directory, state, case_id, source_id) = ready_aws_state(issued_at, 4);
        let service = state.case_service();
        let initial = service
            .plan_scan(
                &case_id,
                ScanPlanRequest {
                    campaign_id: None,
                    engine_ids: vec!["steampipe".into()],
                    engine_asset_routes: Vec::new(),
                },
            )
            .unwrap();
        let initial_execution = initial.executable.first().unwrap();
        let artifact_context = ArtifactContext {
            case_id: case_id.clone(),
            scan_run_id: initial.scan_run.id.clone(),
            engine_run_id: initial_execution.engine_run_id.clone(),
        };
        let artifacts = ArtifactStore::open(state.artifact_root()).unwrap();
        let directories = artifacts
            .prepare_run(&artifact_context, initial_execution.attempt)
            .unwrap();
        let output = directories.output.join("steampipe.json");
        std::fs::write(&output, b"[]").unwrap();
        let artifact = artifacts
            .describe_file(&artifact_context, &output, "application/json", true)
            .unwrap();

        let mut stored = service.show_case(&case_id).unwrap();
        let run = stored
            .scan_runs
            .iter_mut()
            .find(|run| run.id == initial.scan_run.id)
            .unwrap();
        let engine_run = run
            .engine_runs
            .iter_mut()
            .find(|engine_run| engine_run.id == initial_execution.engine_run_id)
            .unwrap();
        let mut checkpoint =
            ExecutionCheckpoint::from_resume_token(engine_run.resume_token.as_deref().unwrap())
                .unwrap();
        checkpoint.stage = ExecutionStage::CapturedAwaitingAdapter;
        checkpoint.artifact_ids = vec![artifact.id.clone()];
        checkpoint.cleanup_completed = true;
        checkpoint.runtime_provider = Some(RuntimeProvider::Docker);
        checkpoint.runtime_command_provenance = Some(RuntimeCommandProvenance::Compatibility);
        engine_run.status = EngineRunStatus::PartiallyCompleted;
        engine_run.progress_percent = 85;
        engine_run.phase = "captured_awaiting_adapter".into();
        engine_run.raw_artifact_ids = vec![artifact.id.clone()];
        engine_run.resume_token = Some(checkpoint.resume_token().unwrap());
        run.completed_at = Some(Utc::now());
        stored.raw_artifacts.push(artifact);
        stored.status = CaseStatus::NeedsAttention;
        state
            .storage
            .save_case(&mut stored, "test.captured_cloud_resume")
            .unwrap();

        let mut captured_execution = initial_execution.clone();
        captured_execution.resume_checkpoint = Some(checkpoint.clone());
        let mut missing_ids = checkpoint.clone();
        missing_ids.artifact_ids.clear();
        assert!(
            captured_execution_artifacts(&state, &captured_execution, &missing_ids)
                .unwrap_err()
                .to_string()
                .contains("exactly match")
        );
        let mut duplicate_ids = checkpoint.clone();
        let duplicated_id = duplicate_ids.artifact_ids[0].clone();
        duplicate_ids.artifact_ids.push(duplicated_id);
        assert!(
            captured_execution_artifacts(&state, &captured_execution, &duplicate_ids)
                .unwrap_err()
                .to_string()
                .contains("exactly match")
        );

        state
            .source_authorizations
            .revoke_source(&case_id, &source_id, Utc::now())
            .unwrap();
        assert!(
            state
                .source_authorizations
                .status(&case_id, &source_id, Utc::now())
                .unwrap()
                .is_none()
        );

        std::fs::write(&output, b"tampered-after-capture").unwrap();
        let tampered_resume = service
            .persist_resume_before_execution_preflight(&case_id, &initial.scan_run.id)
            .unwrap();
        let blocker = validate_execution_inputs_static(&state, &tampered_resume)
            .expect_err("changed captured evidence must fail after durable resume intent");
        assert_eq!(
            blocker,
            DesktopExecutionBlocker::CapturedEvidenceUnavailable
        );
        let outcomes = tampered_resume
            .executable
            .iter()
            .map(|execution| PersistedPreDispatchTaskOutcome::Failed {
                engine_run_id: execution.engine_run_id.clone(),
                reason: blocker.persisted_reason(),
            })
            .collect();
        let failed = service
            .transition_persisted_scan_pre_dispatch(
                &case_id,
                &initial.scan_run.id,
                &PersistedPreDispatchTransition::ApplyOutcome {
                    task_outcomes: outcomes,
                },
            )
            .unwrap();
        let failed_run = failed
            .scan_runs
            .iter()
            .find(|run| run.id == initial.scan_run.id)
            .unwrap();
        let failed_engine = failed_run
            .engine_runs
            .iter()
            .find(|engine_run| engine_run.id == initial_execution.engine_run_id)
            .unwrap();
        assert_eq!(failed_engine.status, EngineRunStatus::Failed);
        assert_eq!(failed_engine.phase, "preflight_failed");
        assert!(failed_run.completed_at.is_some());

        std::fs::write(&output, b"[]").unwrap();
        let resume = service
            .persist_resume_before_execution_preflight(&case_id, &initial.scan_run.id)
            .unwrap();
        validate_execution_inputs_static(&state, &resume).unwrap();
        let resumed_execution = resume.executable.first().unwrap();
        let resumed_checkpoint = resumed_execution.resume_checkpoint.as_ref().unwrap();
        assert_eq!(
            resumed_checkpoint.resume_action(),
            ResumeAction::AdaptCapturedArtifacts
        );
        assert!(captured_resume_is_runtime_independent(resumed_execution));
        let mut retained_network_execution = resumed_execution.clone();
        let retained_checkpoint = retained_network_execution
            .resume_checkpoint
            .as_mut()
            .unwrap();
        let policy_unique = "d".repeat(32);
        retained_checkpoint.managed_network =
            Some(crate::managed_network::ManagedNetworkIdentity {
                schema_version: "1.0.0".into(),
                provider: RuntimeProvider::Docker,
                network_name: format!("ass-egress-{policy_unique}"),
                network_id: "historical-network-id".into(),
                uplink_network_name: None,
                uplink_network_id: None,
                gateway_container_name: None,
                gateway_container_id: None,
                gateway_listener_ip: None,
                gateway_image_repository: None,
                gateway_image_digest: None,
                policy_id: format!("egress-{policy_unique}"),
                policy_sha256: "e".repeat(64),
                expires_at: Utc::now(),
                provenance: crate::managed_network::EgressGatewayProvenance::ReleaseQualification {
                    case_id: case_id.clone(),
                    qualification_id: "historical-cleanup-proof".into(),
                },
            });
        retained_checkpoint.resume_token().unwrap();
        assert!(captured_resume_is_runtime_independent(
            &retained_network_execution
        ));

        let report = resume_captured_execution(&state, &artifacts, resumed_execution).unwrap();
        assert!(matches!(
            report.checkpoint.stage,
            ExecutionStage::Completed | ExecutionStage::CapturedAwaitingAdapter
        ));
        assert!(report.runtime_preflight.is_none());
        assert!(report.checkpoint.managed_network.is_none());
        assert!(
            state
                .source_authorizations
                .status(&case_id, &source_id, Utc::now())
                .unwrap()
                .is_none()
        );

        for stage in [ExecutionStage::Failed, ExecutionStage::Running] {
            let mut reexecution = resume.clone();
            reexecution.executable[0]
                .resume_checkpoint
                .as_mut()
                .unwrap()
                .stage = stage;
            let error = validate_desktop_execution_with_runtime(&state, &reexecution, || Ok(()))
                .unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("scan_preflight:provider_capability_unavailable")
            );
        }
    }

    struct DiscardEvents;
    impl ScanEventSink for DiscardEvents {
        fn emit(&self, _: ScanEventKind, _: &AssessmentCase) -> AppResult<()> {
            Ok(())
        }
    }

    #[test]
    fn owned_cancel_after_worker_completion_leaves_exact_generation_for_owner_ack() {
        let (_directory, state, case_id) = ready_repository_state();
        let plan = state
            .case_service()
            .persist_scan_before_execution_preflight(
                &case_id,
                ScanPlanRequest {
                    campaign_id: None,
                    engine_ids: vec!["gitleaks".into()],
                    engine_asset_routes: vec![],
                },
            )
            .unwrap();
        let state = Arc::new(state);
        let coordinator = ScanCoordinator::new(state.clone(), Arc::new(DiscardEvents));
        let key = JobKey::new(&case_id, &plan.scan_run.id).unwrap();
        let task_id = plan.executable[0].engine_run_id.clone();
        let worker_task_id = task_id.clone();
        let owner = state
            .jobs
            .start_owned_job(
                key.clone(),
                [task_id],
                move |context| {
                    context
                        .engine(&worker_task_id)
                        .unwrap()
                        .mark_failed()
                        .unwrap();
                    JobCompletion::Failed
                },
                |_| {},
            )
            .unwrap();
        let completion = owner.join().unwrap();
        coordinator
            .cancel_owned(&case_id, &plan.scan_run.id)
            .unwrap();
        assert_eq!(
            state.jobs.snapshot(&key).unwrap().generation,
            completion.snapshot.generation
        );
        assert_eq!(
            coordinator
                .reconcile_terminal(&completion.snapshot)
                .unwrap(),
            TerminalJobReconciliation::Reconciled
        );
        assert!(state.jobs.snapshot(&key).is_none());
        let saved = state.case_service().show_case(&case_id).unwrap();
        assert!(saved.scan_runs[0].completed_at.is_some());
        assert_eq!(
            saved.scan_runs[0].engine_runs[0].status,
            EngineRunStatus::Failed
        );
    }

    #[test]
    fn owned_initial_output_failure_preserves_handle_until_durable_ack() {
        struct FailedOutput;
        impl ScanEventSink for FailedOutput {
            fn emit(&self, _: ScanEventKind, _: &AssessmentCase) -> AppResult<()> {
                Err(AppError::Runtime("fixture output closed".into()))
            }
        }
        let (_directory, state, case_id) = ready_repository_state();
        let state =
            Arc::new(state.with_runtime_initialization_error("fixture runtime unavailable".into()));
        let coordinator = ScanCoordinator::new(state.clone(), Arc::new(FailedOutput));
        let admission = coordinator
            .start_owned(
                &case_id,
                vec![],
                ScanPlanRequest {
                    campaign_id: None,
                    engine_ids: vec!["gitleaks".into()],
                    engine_asset_routes: vec![],
                },
            )
            .unwrap();
        let completion = admission
            .owned_job
            .expect("failed output must retain the worker owner")
            .join()
            .unwrap();
        coordinator.join_preparers().unwrap();
        assert!(!completion.callback_panicked);
        assert_eq!(
            coordinator
                .reconcile_terminal(&completion.snapshot)
                .unwrap(),
            TerminalJobReconciliation::Reconciled
        );
        let saved = state.case_service().show_case(&case_id).unwrap();
        assert!(saved.scan_runs[0].completed_at.is_some());
        assert!(matches!(
            saved.scan_runs[0].engine_runs[0].status,
            EngineRunStatus::Cancelled | EngineRunStatus::Failed
        ));
        assert!(state.jobs.snapshot(&completion.snapshot.key).is_none());
    }

    #[test]
    fn captured_recovery_refuses_new_contact_before_any_saved_mutation() {
        let (_directory, state, case_id) = ready_repository_state();
        let plan = state
            .case_service()
            .persist_scan_before_execution_preflight(
                &case_id,
                ScanPlanRequest {
                    campaign_id: None,
                    engine_ids: vec!["gitleaks".into()],
                    engine_asset_routes: vec![],
                },
            )
            .unwrap();
        let state = Arc::new(state);
        let coordinator = ScanCoordinator::new(state.clone(), Arc::new(DiscardEvents));
        let original =
            serde_json::to_value(state.case_service().show_case(&case_id).unwrap()).unwrap();
        assert!(matches!(
            coordinator.recover_owned(&case_id, &plan.scan_run.id),
            Err(AppError::NotAvailable(_))
        ));
        assert_eq!(
            serde_json::to_value(state.case_service().show_case(&case_id).unwrap()).unwrap(),
            original
        );
        assert!(
            state
                .jobs
                .snapshot(&JobKey::new(&case_id, &plan.scan_run.id).unwrap())
                .is_none()
        );
    }

    #[test]
    fn captured_naabu_settlement_preserves_partial_work_without_next_attempt() {
        let (_directory, state, case_id, execution, _) = normalized_naabu_pending_state();
        let before = state.case_service().show_case(&case_id).unwrap();
        assert!(clean_normalized_naabu_batch_awaits_continuation(
            &before, &execution
        ));
        let task = &before.scan_runs[0].engine_runs[0];
        assert!(!task_requires_captured_recovery(task));
        assert!(
            !validate_recovery_without_target_contact(&before, &execution.scan_run_id).unwrap()
        );
        let state = Arc::new(state);
        let coordinator = ScanCoordinator {
            captured_recovery_only: true,
            ..ScanCoordinator::new(state.clone(), Arc::new(DiscardEvents))
        };
        let worker = coordinator.clone();
        let key = JobKey::new(&case_id, &execution.scan_run_id).unwrap();
        let task_id = execution.engine_run_id.clone();
        let worker_before = before.clone();
        let owner = state
            .jobs
            .start_owned_job(
                key,
                [task_id.clone()],
                move |context| {
                    assert!(matches!(
                        settle_worker_naabu_batch(&worker, &context, &execution, &worker_before)
                            .unwrap(),
                        NaabuPostBatchSettlement::NotApplicable
                    ));
                    context.engine(&task_id).unwrap().mark_completed().unwrap();
                    JobCompletion::Completed
                },
                |_| {},
            )
            .unwrap();
        let completion = owner.join().unwrap();
        assert!(!completion.callback_panicked);
        assert_eq!(
            completion.snapshot.status,
            crate::job_manager::JobStatus::Completed
        );
        assert_eq!(
            serde_json::to_value(state.case_service().show_case(&case_id).unwrap()).unwrap(),
            serde_json::to_value(before).unwrap()
        );
    }

    #[test]
    fn captured_recovery_preserves_clean_failed_siblings_and_validates_their_identity() {
        let (_directory, state, case_id) = ready_repository_state();
        let plan = state
            .case_service()
            .persist_scan_before_execution_preflight(
                &case_id,
                ScanPlanRequest {
                    campaign_id: None,
                    engine_ids: vec!["gitleaks".into(), "semgrep".into()],
                    engine_asset_routes: vec![],
                },
            )
            .unwrap();
        let mut case = state.case_service().show_case(&case_id).unwrap();
        let run = case
            .scan_runs
            .iter_mut()
            .find(|run| run.id == plan.scan_run.id)
            .unwrap();
        for task in &mut run.engine_runs {
            let mut checkpoint =
                ExecutionCheckpoint::from_resume_token(task.resume_token.as_deref().unwrap())
                    .unwrap();
            checkpoint.cleanup_completed = true;
            if task.engine_id == "gitleaks" {
                checkpoint.stage = ExecutionStage::CapturedAwaitingAdapter;
                task.status = EngineRunStatus::PartiallyCompleted;
                task.phase = "captured_awaiting_adapter".into();
            } else {
                checkpoint.stage = ExecutionStage::Failed;
                task.status = EngineRunStatus::Failed;
                task.phase = "failed".into();
            }
            task.resume_token = Some(checkpoint.resume_token().unwrap());
        }
        assert!(validate_recovery_without_target_contact(&case, &plan.scan_run.id).unwrap());
        let failed = case.scan_runs[0]
            .engine_runs
            .iter_mut()
            .find(|task| task.engine_id == "semgrep")
            .unwrap();
        let mut checkpoint =
            ExecutionCheckpoint::from_resume_token(failed.resume_token.as_deref().unwrap())
                .unwrap();
        checkpoint.case_id = "foreign-case".into();
        failed.resume_token = Some(checkpoint.resume_token().unwrap());
        assert!(matches!(
            validate_recovery_without_target_contact(&case, &plan.scan_run.id),
            Err(AppError::NotAuthorized(_))
        ));
    }

    #[test]
    fn no_worker_cancel_returns_unchanged_durable_truth_for_unowned_or_cleanup_work() {
        let (_directory, state, case_id, run_id, _) = ordinary_cleanup_pending_state();
        let service = state.case_service();
        let original = service.show_case(&case_id).unwrap();
        for (status, phase, variant) in [
            (
                EngineRunStatus::PartiallyCompleted,
                "cleanup_pending",
                "final",
            ),
            (EngineRunStatus::Paused, "cleanup_pending", "cleanup"),
            (EngineRunStatus::Paused, "untrusted_checkpoint", "unchanged"),
        ] {
            let mut selected = original.clone();
            let run = selected
                .scan_runs
                .iter_mut()
                .find(|run| run.id == run_id)
                .unwrap();
            run.engine_runs[0].status = status;
            run.engine_runs[0].phase = phase.into();
            let expected = serde_json::to_value(&selected).unwrap();
            let returned = match apply_no_worker_durable_cancel(
                &service, &case_id, &run_id, selected,
            )
            .unwrap()
            {
                NoWorkerCancelAdmission::DurableFinal(case) => {
                    assert_eq!(variant, "final");
                    case
                }
                NoWorkerCancelAdmission::CleanupPending(case) => {
                    assert_eq!(variant, "cleanup");
                    case
                }
                NoWorkerCancelAdmission::DurableUnchanged(case) => {
                    assert_eq!(variant, "unchanged");
                    case
                }
                _ => panic!("unowned work must not be relabelled as cancelled"),
            };
            assert_eq!(serde_json::to_value(returned).unwrap(), expected);
            assert_eq!(
                serde_json::to_value(service.show_case(&case_id).unwrap()).unwrap(),
                serde_json::to_value(&original).unwrap()
            );
        }
    }

    #[test]
    fn rejected_captured_evidence_remains_pending_without_an_immediate_recovery_retry() {
        let (_directory, state, case_id) = ready_repository_state();
        let plan = state
            .case_service()
            .persist_scan_before_execution_preflight(
                &case_id,
                ScanPlanRequest {
                    campaign_id: None,
                    engine_ids: vec!["gitleaks".into()],
                    engine_asset_routes: vec![],
                },
            )
            .unwrap();
        let execution = &plan.executable[0];
        let context = ArtifactContext {
            case_id: case_id.clone(),
            scan_run_id: plan.scan_run.id.clone(),
            engine_run_id: execution.engine_run_id.clone(),
        };
        let artifacts = ArtifactStore::open(state.artifact_root()).unwrap();
        let directories = artifacts.prepare_run(&context, execution.attempt).unwrap();
        let captured_file = directories.output.join("gitleaks.json");
        std::fs::write(&captured_file, b"[]").unwrap();
        let artifact = artifacts
            .describe_file(&context, &captured_file, "application/json", true)
            .unwrap();
        let mut case = state.case_service().show_case(&case_id).unwrap();
        let run = case
            .scan_runs
            .iter_mut()
            .find(|run| run.id == plan.scan_run.id)
            .unwrap();
        let task = run
            .engine_runs
            .iter_mut()
            .find(|task| task.id == execution.engine_run_id)
            .unwrap();
        let mut checkpoint =
            ExecutionCheckpoint::from_resume_token(task.resume_token.as_deref().unwrap()).unwrap();
        checkpoint.stage = ExecutionStage::CapturedAwaitingAdapter;
        checkpoint.cleanup_completed = true;
        checkpoint.artifact_ids = vec![artifact.id.clone()];
        task.status = EngineRunStatus::Failed;
        task.phase = "preflight_failed".into();
        task.error_code = Some("captured_evidence_unavailable".into());
        task.finished_at = Some(Utc::now());
        task.resume_token = Some(checkpoint.resume_token().unwrap());
        task.raw_artifact_ids = vec![artifact.id.clone()];
        run.completed_at = Some(Utc::now());
        case.raw_artifacts.push(artifact);
        case.status = CaseStatus::NeedsAttention;
        state
            .storage
            .save_case(&mut case, "test.captured_evidence_rejected")
            .unwrap();
        std::fs::write(&captured_file, b"tampered capture retained").unwrap();
        assert!(
            task_requires_captured_recovery(&case.scan_runs[0].engine_runs[0]),
            "failed verification must not become completed normalization"
        );
        let saved = serde_json::to_value(&case).unwrap();
        let state = Arc::new(state);
        let coordinator = ScanCoordinator::new(state.clone(), Arc::new(DiscardEvents));
        assert!(matches!(
            validate_recovery_without_target_contact(&case, &plan.scan_run.id),
            Err(AppError::NotAvailable(_))
        ));
        assert!(matches!(
            coordinator.recover_owned(&case_id, &plan.scan_run.id),
            Err(AppError::NotAvailable(_))
        ));
        assert_eq!(
            serde_json::to_value(state.case_service().show_case(&case_id).unwrap()).unwrap(),
            saved
        );
        assert_eq!(
            std::fs::read(&captured_file).unwrap(),
            b"tampered capture retained"
        );
        assert!(
            state
                .jobs
                .snapshot(&JobKey::new(&case_id, &plan.scan_run.id).unwrap())
                .is_none()
        );
    }
}
