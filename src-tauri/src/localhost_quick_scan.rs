//! Durable, product-owned connection diagnostic for one TCP service on this
//! computer. It is not a vulnerability scan or a measure of first product value.
//!
//! The user starts this check with one explicit action. The exact loopback
//! target, permission, task contract, and queued state are committed before
//! the operating system is asked to make a connection. The task is independent
//! of WSL, a container runtime, the engine catalog, and result adapters.

use crate::coverage::refresh_coverage_ledger;
use crate::domain::{
    AiGeneratedArtifactAnswer, AiSystemApplicabilityAnswer, AssessmentCase, AssessmentIntent,
    Asset, AssetIdentifier, AssetKind, BUILT_IN_LOCALHOST_TCP_ASSET_IDENTIFIER_NAMESPACE,
    BUILT_IN_LOCALHOST_TCP_AUTHORIZATION_REFERENCE, BUILT_IN_LOCALHOST_TCP_ENGINE_ID, CaseStatus,
    DataClass, DataSource, EngineManifest, EngineRun, EngineRunStatus, EngineTaskKind,
    LocalhostTcpObservation, LocalhostTcpOutcome, OrganizationProfile, ScanPermission, ScanRun,
    ScopeGrant, SourceConnectionStatus, SourceKind, new_id,
};
use crate::error::{AppError, AppResult};
use crate::job_manager::{
    DurableCancellationWrite, EngineJobControl, JobActivationOutcome, JobCompletion, JobContext,
    JobKey, JobSnapshot, JobStatus,
};
use crate::local_tcp_probe::{
    LocalTcpConnector, LocalTcpProbeFailure, LocalTcpProbeOutcome, probe_localhost_tcp_port_with,
};
use crate::storage::Storage;
use chrono::Utc;
use serde_json::Value;
use std::collections::BTreeMap;

const LOCALHOST_PERSISTENCE_ATTEMPTS: usize = 3;

pub const LOCALHOST_TCP_ENGINE_ID: &str = BUILT_IN_LOCALHOST_TCP_ENGINE_ID;
pub const LOCALHOST_TCP_ASSET_IDENTIFIER_NAMESPACE: &str =
    BUILT_IN_LOCALHOST_TCP_ASSET_IDENTIFIER_NAMESPACE;
pub const LOCALHOST_TCP_AUTHORIZATION_REFERENCE: &str =
    BUILT_IN_LOCALHOST_TCP_AUTHORIZATION_REFERENCE;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedLocalhostQuickScan {
    pub case_id: String,
    pub scan_run_id: String,
    pub engine_run_id: String,
    pub port: u16,
}

#[derive(Debug, Clone)]
pub struct PreparedLocalhostQuickScanResult {
    pub case: AssessmentCase,
    pub prepared: PreparedLocalhostQuickScan,
}

pub fn run_is_exact_localhost_quick_scan(run: &ScanRun) -> bool {
    run.engine_runs.len() == 1
        && run.engine_runs[0].engine_id == LOCALHOST_TCP_ENGINE_ID
        && run.engine_runs[0]
            .task_kind
            .is_exact_built_in_localhost_tcp_contract()
}

/// Create and select a complete minimal case, including its exact task and
/// permission snapshot. This function never contacts the target.
pub fn prepare_localhost_quick_scan(
    storage: &Storage,
    manifests: &[EngineManifest],
    port: u16,
) -> AppResult<PreparedLocalhostQuickScanResult> {
    if port == 0 {
        return Err(AppError::InvalidRequest(
            "local TCP port must be between 1 and 65535".into(),
        ));
    }

    let now = Utc::now();
    let endpoint = format!("127.0.0.1:{port}");
    let source_id = new_id();
    let asset_id = new_id();
    let grant_id = new_id();
    let scan_run_id = new_id();
    let engine_run_id = new_id();

    let mut case = AssessmentCase::new(
        format!("This computer · {endpoint}"),
        OrganizationProfile {
            organization_name: "This computer".into(),
            employee_range: "Not provided".into(),
            data_classes: vec![DataClass::General],
            notes: None,
        },
    );
    case.assessment_intent = Some(AssessmentIntent::InternalItEnvironment);
    case.requested_activities = vec![crate::domain::AssessmentActivity::LowImpactExternalChecks];
    case.status = CaseStatus::Scanning;
    case.knowledge_cutoff = Some(now);

    case.data_sources.push(DataSource {
        id: source_id.clone(),
        kind: SourceKind::UserDeclared,
        label: "This computer".into(),
        status: SourceConnectionStatus::Connected,
        connected_at: Some(now),
        last_discovered_at: Some(now),
        read_only: true,
        metadata: BTreeMap::from([(
            "scan_boundary".into(),
            Value::String("one product-owned IPv4 loopback TCP connection attempt".into()),
        )]),
    });
    case.assets.push(Asset {
        id: asset_id.clone(),
        kind: AssetKind::WebService,
        name: endpoint.clone(),
        provider: None,
        region: None,
        identifiers: vec![AssetIdentifier {
            namespace: LOCALHOST_TCP_ASSET_IDENTIFIER_NAMESPACE.into(),
            value: endpoint,
        }],
        discovered_from: vec![source_id],
        candidate: false,
        owner_confirmed: true,
        internet_exposed: Some(false),
        contains_sensitive_data: Some(false),
        metadata: BTreeMap::from([
            (
                "localhost_address".into(),
                Value::String("127.0.0.1".into()),
            ),
            ("tcp_port".into(), Value::from(port)),
        ]),
    });

    let grant = ScopeGrant {
        id: grant_id.clone(),
        asset_id: asset_id.clone(),
        permission: ScanPermission::LowImpactExternalConnection,
        confirmed_by: "Local user".into(),
        confirmed_at: now,
        expires_at: None,
        authorization_reference: Some(LOCALHOST_TCP_AUTHORIZATION_REFERENCE.into()),
        notes: Some(
            "The Start action authorizes one payload-free TCP connection to this exact loopback port."
                .into(),
        ),
        external_scope: None,
    };
    case.scope_grants.push(grant.clone());

    let engine_run = EngineRun {
        id: engine_run_id.clone(),
        scan_run_id: scan_run_id.clone(),
        engine_id: LOCALHOST_TCP_ENGINE_ID.into(),
        task_kind: EngineTaskKind::built_in_localhost_tcp(port),
        localhost_tcp_observation: None,
        asset_ids: vec![asset_id],
        status: EngineRunStatus::Queued,
        progress_percent: 0,
        phase: "queued".into(),
        started_at: None,
        finished_at: None,
        resume_token: None,
        last_execution_report_sha256: None,
        engine_version: None,
        reported_version: None,
        image_digest: None,
        rule_version: None,
        adapter_version: "built-in".into(),
        manifest_schema_version: None,
        source_revision: None,
        repository_url: None,
        distribution_mode: None,
        image_repository: None,
        command_sha256: None,
        execution_timeout_seconds: Some(3),
        knowledge_input: None,
        scope_contract_sha256: None,
        comparison_scope_sha256: None,
        execution_scope_grant_ids: None,
        naabu_work_plan: None,
        naabu_attempt_requests: Vec::new(),
        naabu_attempt_results: Vec::new(),
        mapping_version: None,
        mapping_provenance: None,
        fingerprint_schema_version: None,
        runtime_provider: None,
        runtime_version: None,
        runtime_security_options: None,
        exit_code: None,
        cleanup_removed: None,
        cleanup_detail: None,
        gateway_refusals: None,
        warnings: Vec::new(),
        unattributed: Vec::new(),
        unevaluated_targets: Vec::new(),
        security_template_executions: Vec::new(),
        manual_review_controls: Vec::new(),
        raw_artifact_ids: Vec::new(),
        error_code: None,
        error_message: None,
    };
    case.scan_runs.push(ScanRun {
        campaign_id: None,
        id: scan_run_id.clone(),
        case_id: case.id.clone(),
        sequence: 1,
        created_at: now,
        completed_at: None,
        request_outcome: None,
        report_asset_snapshots: Vec::new(),
        knowledge_cutoff: now,
        ai_system_applicable: false,
        ai_system_applicability: AiSystemApplicabilityAnswer::NotApplicable,
        ai_generated_artifact: AiGeneratedArtifactAnswer::No,
        verification_baseline_run_id: None,
        scope_grant_ids: vec![grant_id],
        scope_grant_snapshots: vec![grant],
        engine_admission_issues: Vec::new(),
        engine_runs: vec![engine_run],
    });

    refresh_coverage_ledger(&mut case, manifests, now);
    storage.save_case(&mut case, "scan.localhost_quick_queued")?;
    // Selection is navigation convenience, not part of the durable scan
    // contract. A settings-row failure must not orphan or suppress work that
    // is already safely queued.
    if let Err(error) = storage.set_selected_case(Some(&case.id)) {
        tracing::warn!(
            error = %error,
            case_id = %case.id,
            "local connection test was queued but could not become the selected case"
        );
    }

    Ok(PreparedLocalhostQuickScanResult {
        prepared: PreparedLocalhostQuickScan {
            case_id: case.id.clone(),
            scan_run_id,
            engine_run_id,
            port,
        },
        case,
    })
}

pub fn prepared_localhost_quick_scan_for_job(
    case: &AssessmentCase,
    key: &JobKey,
) -> AppResult<Option<PreparedLocalhostQuickScan>> {
    if case.id != key.case_id {
        return Err(AppError::NotAuthorized(
            "localhost job key does not match its durable case".into(),
        ));
    }
    let Some(run) = case.scan_runs.iter().find(|run| run.id == key.scan_run_id) else {
        return Ok(None);
    };
    if !run_is_exact_localhost_quick_scan(run) {
        return Ok(None);
    }
    let engine_run = &run.engine_runs[0];
    let EngineTaskKind::BuiltInLocalhostTcp {
        port,
        timeout_ms,
        payload_bytes,
    } = engine_run.task_kind
    else {
        unreachable!("exact localhost task kind was validated")
    };
    if timeout_ms != crate::domain::BUILT_IN_LOCALHOST_TCP_TIMEOUT_MS
        || payload_bytes != crate::domain::BUILT_IN_LOCALHOST_TCP_PAYLOAD_BYTES
    {
        return Err(AppError::NotAuthorized(
            "localhost job no longer matches its fixed bounded task contract".into(),
        ));
    }
    Ok(Some(PreparedLocalhostQuickScan {
        case_id: case.id.clone(),
        scan_run_id: run.id.clone(),
        engine_run_id: engine_run.id.clone(),
        port,
    }))
}

/// Resolve one retained/live JobManager snapshot back to the exact durable
/// localhost task it represents. Unrelated snapshots return `None`; identity
/// mismatch is never guessed from a case name or port alone.
pub fn localhost_quick_scan_for_snapshot(
    storage: &Storage,
    snapshot: &JobSnapshot,
) -> AppResult<Option<(AssessmentCase, PreparedLocalhostQuickScan)>> {
    let case = storage.get_case(&snapshot.key.case_id)?;
    let Some(prepared) = prepared_localhost_quick_scan_for_job(&case, &snapshot.key)? else {
        return Ok(None);
    };
    if snapshot.engines.len() != 1 || snapshot.engines[0].engine_id != prepared.engine_run_id {
        return Err(AppError::NotAuthorized(
            "localhost job engine identity does not match its durable task".into(),
        ));
    }
    Ok(Some((case, prepared)))
}

/// Find the already-live exact task for one requested port. Snapshot or
/// storage corruption is advisory here: it must not turn an unrelated old job
/// into a global connection-utility blocker, and JobManager still protects every exact
/// `(case, run)` identity independently.
pub fn live_localhost_quick_scan_for_port(
    storage: &Storage,
    snapshots: &[JobSnapshot],
    port: u16,
) -> Option<AssessmentCase> {
    snapshots.iter().find_map(|snapshot| {
        localhost_quick_scan_for_snapshot(storage, snapshot)
            .ok()
            .flatten()
            .and_then(|(case, prepared)| (prepared.port == port).then_some(case))
    })
}

/// Executes one exact localhost task as a `JobManager` worker. Every durable
/// transition is short and serialized with Cancel, while the fixed three-
/// second connector call runs outside the manager's control lock.
pub fn execute_managed_localhost_quick_scan(
    storage: &Storage,
    manifests: &[EngineManifest],
    prepared: &PreparedLocalhostQuickScan,
    connector: &dyn LocalTcpConnector,
    context: &JobContext,
) -> JobCompletion {
    execute_managed_localhost_quick_scan_with_hooks(
        storage,
        manifests,
        prepared,
        connector,
        context,
        &ManagedLocalhostExecutionHooks::default(),
    )
}

#[derive(Default)]
struct ManagedLocalhostExecutionHooks<'a> {
    before_dispatch: Option<&'a dyn Fn()>,
    after_terminal_mark: Option<&'a dyn Fn()>,
}

fn execute_managed_localhost_quick_scan_with_hooks(
    storage: &Storage,
    manifests: &[EngineManifest],
    prepared: &PreparedLocalhostQuickScan,
    connector: &dyn LocalTcpConnector,
    context: &JobContext,
    hooks: &ManagedLocalhostExecutionHooks<'_>,
) -> JobCompletion {
    let Ok(control) = context.engine(&prepared.engine_run_id) else {
        return JobCompletion::Failed;
    };

    if let Some(before_dispatch) = hooks.before_dispatch {
        before_dispatch();
    }

    match context.coordinate_durable_write_if_not_cancelled(|| {
        let case = retry_localhost_persistence(|| {
            persist_localhost_running_once(storage, manifests, prepared)
        })?;
        control
            .mark_running()
            .map_err(|error| AppError::Runtime(error.to_string()))?;
        Ok::<_, AppError>(case)
    }) {
        JobActivationOutcome::Cancelled => {
            return persist_managed_localhost_cancelled(
                storage, manifests, prepared, context, &control,
            );
        }
        JobActivationOutcome::Failed(error) => {
            tracing::error!(
                error = %error,
                case_id = %prepared.case_id,
                scan_run_id = %prepared.scan_run_id,
                "managed localhost worker could not persist its pre-contact state"
            );
            return persist_managed_localhost_interrupted(
                storage, manifests, prepared, context, &control,
            );
        }
        JobActivationOutcome::Activated(_) => {}
    }

    if context.is_cancelled() {
        return persist_managed_localhost_cancelled(
            storage, manifests, prepared, context, &control,
        );
    }

    // Exactly one payload-free connection attempt. Production remains bounded
    // by LOCAL_TCP_CONNECT_TIMEOUT; tests inject a barrier at this seam.
    let result = probe_localhost_tcp_port_with(connector, prepared.port);
    context.coordinate_durable_write(|| {
        if context.is_cancelled() {
            return persist_managed_localhost_cancelled_under_lock(
                storage,
                manifests,
                prepared,
                &control,
                !context.durable_terminal_truth_won(),
            );
        }

        let saved = retry_localhost_persistence(|| {
            complete_localhost_quick_scan_once(storage, manifests, prepared, result)
        });
        match saved {
            Ok(case) => {
                // Cancel publishes before waiting for this lock. If it arrived
                // while the result save was in progress, cancellation wins
                // and the just-saved observation is replaced before the engine
                // is marked terminal.
                if context.is_cancelled() {
                    return persist_managed_localhost_cancelled_under_lock(
                        storage,
                        manifests,
                        prepared,
                        &control,
                        !context.durable_terminal_truth_won(),
                    );
                }
                let completion = mark_managed_localhost_terminal(&case, prepared, &control);
                if let Some(after_terminal_mark) = hooks.after_terminal_mark {
                    after_terminal_mark();
                }
                completion
            }
            Err(error) => {
                tracing::error!(
                    error = %error,
                    case_id = %prepared.case_id,
                    scan_run_id = %prepared.scan_run_id,
                    "managed localhost result could not be persisted"
                );
                if context.is_cancelled() {
                    persist_managed_localhost_cancelled_under_lock(
                        storage,
                        manifests,
                        prepared,
                        &control,
                        !context.durable_terminal_truth_won(),
                    )
                } else {
                    persist_managed_localhost_interrupted_under_lock(
                        storage, manifests, prepared, &control,
                    )
                }
            }
        }
    })
}

fn persist_managed_localhost_cancelled(
    storage: &Storage,
    manifests: &[EngineManifest],
    prepared: &PreparedLocalhostQuickScan,
    context: &JobContext,
    control: &EngineJobControl,
) -> JobCompletion {
    context.coordinate_durable_write(|| {
        persist_managed_localhost_cancelled_under_lock(
            storage,
            manifests,
            prepared,
            control,
            !context.durable_terminal_truth_won(),
        )
    })
}

fn persist_managed_localhost_cancelled_under_lock(
    storage: &Storage,
    manifests: &[EngineManifest],
    prepared: &PreparedLocalhostQuickScan,
    control: &EngineJobControl,
    discard_unmarked_observation: bool,
) -> JobCompletion {
    match record_localhost_cancelled(storage, manifests, prepared, discard_unmarked_observation) {
        Ok(case) => mark_managed_localhost_terminal(&case, prepared, control),
        Err(error) => {
            tracing::error!(
                error = %error,
                case_id = %prepared.case_id,
                scan_run_id = %prepared.scan_run_id,
                "localhost cancellation could not be saved"
            );
            JobCompletion::PersistencePending
        }
    }
}

fn persist_managed_localhost_interrupted(
    storage: &Storage,
    manifests: &[EngineManifest],
    prepared: &PreparedLocalhostQuickScan,
    context: &JobContext,
    control: &EngineJobControl,
) -> JobCompletion {
    context.coordinate_durable_write(|| {
        persist_managed_localhost_interrupted_under_lock(storage, manifests, prepared, control)
    })
}

fn persist_managed_localhost_interrupted_under_lock(
    storage: &Storage,
    manifests: &[EngineManifest],
    prepared: &PreparedLocalhostQuickScan,
    control: &EngineJobControl,
) -> JobCompletion {
    match reconcile_interrupted_localhost_quick_scan(storage, manifests, prepared) {
        Ok(case) => mark_managed_localhost_terminal(&case, prepared, control),
        Err(error) => {
            tracing::error!(
                error = %error,
                case_id = %prepared.case_id,
                scan_run_id = %prepared.scan_run_id,
                "localhost interruption could not be saved"
            );
            JobCompletion::PersistencePending
        }
    }
}

fn mark_managed_localhost_terminal(
    case: &AssessmentCase,
    prepared: &PreparedLocalhostQuickScan,
    control: &EngineJobControl,
) -> JobCompletion {
    let status = case
        .scan_runs
        .iter()
        .find(|run| run.id == prepared.scan_run_id)
        .and_then(|run| {
            run.engine_runs
                .iter()
                .find(|engine| engine.id == prepared.engine_run_id)
        })
        .map(|engine| engine.status.clone());
    match status {
        Some(EngineRunStatus::Completed | EngineRunStatus::PartiallyCompleted) => {
            match control.mark_completed() {
                Ok(()) => JobCompletion::Completed,
                Err(_) => JobCompletion::PersistencePending,
            }
        }
        Some(EngineRunStatus::Failed) => match control.mark_failed() {
            Ok(()) => JobCompletion::Failed,
            Err(_) => JobCompletion::PersistencePending,
        },
        Some(EngineRunStatus::Cancelled) => match control.mark_cancelled() {
            Ok(()) => JobCompletion::Cancelled,
            Err(_) => JobCompletion::PersistencePending,
        },
        _ => JobCompletion::PersistencePending,
    }
}

fn persist_localhost_running_once(
    storage: &Storage,
    manifests: &[EngineManifest],
    prepared: &PreparedLocalhostQuickScan,
) -> AppResult<AssessmentCase> {
    let mut case = storage.get_case(&prepared.case_id)?;
    let now = Utc::now();
    let already_running;
    {
        let engine_run = exact_prepared_task_mut(&mut case, prepared)?;
        already_running =
            engine_run.status == EngineRunStatus::Running && engine_run.phase == "connecting";
        if !already_running
            && (engine_run.status != EngineRunStatus::Queued || engine_run.phase != "queued")
        {
            return Err(AppError::Conflict(
                "the local connection test is no longer queued".into(),
            ));
        }
        if !already_running {
            engine_run.status = EngineRunStatus::Running;
            engine_run.progress_percent = 10;
            engine_run.phase = "connecting".into();
            engine_run.started_at = Some(now);
        }
    }
    if already_running {
        return Ok(case);
    }
    case.touch();
    refresh_coverage_ledger(&mut case, manifests, now);
    storage.save_case(&mut case, "scan.localhost_quick_running")?;
    Ok(case)
}

fn complete_localhost_quick_scan_once(
    storage: &Storage,
    manifests: &[EngineManifest],
    prepared: &PreparedLocalhostQuickScan,
    result: Result<LocalTcpProbeOutcome, LocalTcpProbeFailure>,
) -> AppResult<AssessmentCase> {
    let mut case = storage.get_case(&prepared.case_id)?;
    let now = Utc::now();
    let mut terminal_status = None;
    let already_terminal;
    {
        let engine_run = exact_prepared_task_mut(&mut case, prepared)?;
        already_terminal = matches!(
            engine_run.status,
            EngineRunStatus::Completed
                | EngineRunStatus::PartiallyCompleted
                | EngineRunStatus::Failed
                | EngineRunStatus::Cancelled
                | EngineRunStatus::NotExecuted
        );
        if !already_terminal
            && (engine_run.status != EngineRunStatus::Running || engine_run.phase != "connecting")
        {
            return Err(AppError::Conflict(
                "the local connection test is no longer running".into(),
            ));
        }
        if !already_terminal {
            engine_run.progress_percent = 100;
            engine_run.finished_at = Some(now);
            match result {
                Ok(LocalTcpProbeOutcome::Reachable) => {
                    engine_run.status = EngineRunStatus::Completed;
                    engine_run.phase = "completed".into();
                    engine_run.error_code = None;
                    engine_run.error_message = None;
                    engine_run.localhost_tcp_observation = Some(LocalhostTcpObservation {
                        outcome: LocalhostTcpOutcome::Reachable,
                        observed_at: now,
                    });
                }
                Ok(LocalTcpProbeOutcome::Closed) => {
                    engine_run.status = EngineRunStatus::Completed;
                    engine_run.phase = "completed".into();
                    engine_run.error_code = None;
                    engine_run.error_message = None;
                    engine_run.localhost_tcp_observation = Some(LocalhostTcpObservation {
                        outcome: LocalhostTcpOutcome::Closed,
                        observed_at: now,
                    });
                }
                Ok(LocalTcpProbeOutcome::TimedOut) => {
                    engine_run.status = EngineRunStatus::PartiallyCompleted;
                    engine_run.phase = "timed_out".into();
                    engine_run.localhost_tcp_observation = Some(LocalhostTcpObservation {
                        outcome: LocalhostTcpOutcome::TimedOut,
                        observed_at: now,
                    });
                    engine_run.error_code = Some("localhost_tcp_timed_out".into());
                    engine_run.error_message = Some(
                        "No answer arrived within three seconds, so the port was not marked open or closed."
                            .into(),
                    );
                }
                Err(failure) => {
                    engine_run.status = EngineRunStatus::Failed;
                    engine_run.phase = "failed".into();
                    engine_run.localhost_tcp_observation = None;
                    engine_run.error_code = Some(failure.code.as_str().into());
                    engine_run.error_message =
                        Some("Local connection failed. Result: not recorded.".into());
                }
            }
            terminal_status = Some(engine_run.status.clone());
        }
    }
    if already_terminal {
        return Ok(case);
    }
    let run = case
        .scan_runs
        .iter_mut()
        .find(|run| run.id == prepared.scan_run_id)
        .ok_or_else(|| AppError::Conflict("the localhost scan run disappeared".into()))?;
    run.completed_at = Some(now);
    case.status = if terminal_status.expect("new terminal status was projected")
        == EngineRunStatus::Completed
    {
        CaseStatus::ReadyForHandoff
    } else {
        CaseStatus::NeedsAttention
    };
    case.touch();
    refresh_coverage_ledger(&mut case, manifests, now);
    storage.save_case(&mut case, "scan.localhost_quick_finished")?;
    Ok(case)
}

pub fn record_localhost_cancel_requested(
    storage: &Storage,
    manifests: &[EngineManifest],
    prepared: &PreparedLocalhostQuickScan,
) -> AppResult<AssessmentCase> {
    retry_localhost_persistence(|| {
        record_localhost_cancel_requested_once(storage, manifests, prepared)
    })
}

fn record_localhost_cancel_requested_once(
    storage: &Storage,
    manifests: &[EngineManifest],
    prepared: &PreparedLocalhostQuickScan,
) -> AppResult<AssessmentCase> {
    let mut case = storage.get_case(&prepared.case_id)?;
    let already_requested;
    {
        let engine_run = exact_prepared_task_mut(&mut case, prepared)?;
        if matches!(
            engine_run.status,
            EngineRunStatus::Completed
                | EngineRunStatus::PartiallyCompleted
                | EngineRunStatus::Failed
                | EngineRunStatus::Cancelled
                | EngineRunStatus::NotExecuted
        ) {
            return Ok(case);
        }
        if !matches!(
            engine_run.status,
            EngineRunStatus::Queued | EngineRunStatus::Preparing | EngineRunStatus::Running
        ) || !matches!(
            engine_run.phase.as_str(),
            "queued" | "connecting" | "cancel_requested"
        ) {
            return Err(AppError::Conflict(
                "the local connection test cannot accept cancellation from its saved state".into(),
            ));
        }
        already_requested = engine_run.phase == "cancel_requested";
        if !already_requested {
            engine_run.phase = "cancel_requested".into();
            engine_run.error_message = Some(
                "Stopping this local connection test. Any connection result that has not already been saved will be discarded."
                    .into(),
            );
        }
    }
    if already_requested {
        return Ok(case);
    }
    let now = Utc::now();
    case.touch();
    refresh_coverage_ledger(&mut case, manifests, now);
    storage.save_case(&mut case, "scan.localhost_quick_cancel_requested")?;
    Ok(case)
}

/// Persist a cancellation request and classify the exact durable truth while
/// the caller owns the matching JobManager control transition. Returning
/// `Requested` is intentionally narrow: the same task must remain active and
/// its saved phase must be `cancel_requested`. Any already-terminal payload is
/// authoritative and is returned as `TerminalWon` unchanged.
pub fn record_localhost_cancel_transition(
    storage: &Storage,
    manifests: &[EngineManifest],
    prepared: &PreparedLocalhostQuickScan,
) -> AppResult<DurableCancellationWrite<AssessmentCase>> {
    let case = record_localhost_cancel_requested(storage, manifests, prepared)?;
    let engine_run = case
        .scan_runs
        .iter()
        .find(|run| run.id == prepared.scan_run_id)
        .and_then(|run| {
            run.engine_runs
                .iter()
                .find(|engine| engine.id == prepared.engine_run_id)
        })
        .ok_or_else(|| AppError::Conflict("the local connection test disappeared".into()))?;
    if matches!(
        engine_run.status,
        EngineRunStatus::Queued | EngineRunStatus::Preparing | EngineRunStatus::Running
    ) && engine_run.phase == "cancel_requested"
    {
        return Ok(DurableCancellationWrite::Requested(case));
    }
    if matches!(
        engine_run.status,
        EngineRunStatus::Completed
            | EngineRunStatus::PartiallyCompleted
            | EngineRunStatus::Failed
            | EngineRunStatus::Cancelled
            | EngineRunStatus::NotExecuted
    ) {
        return Ok(DurableCancellationWrite::TerminalWon(case));
    }
    Err(AppError::Conflict(
        "the saved localhost task did not confirm cancellation or a terminal result".into(),
    ))
}

pub fn record_localhost_cancelled(
    storage: &Storage,
    manifests: &[EngineManifest],
    prepared: &PreparedLocalhostQuickScan,
    discard_unmarked_observation: bool,
) -> AppResult<AssessmentCase> {
    retry_localhost_persistence(|| {
        record_localhost_cancelled_once(storage, manifests, prepared, discard_unmarked_observation)
    })
}

fn record_localhost_cancelled_once(
    storage: &Storage,
    manifests: &[EngineManifest],
    prepared: &PreparedLocalhostQuickScan,
    discard_unmarked_observation: bool,
) -> AppResult<AssessmentCase> {
    let mut case = storage.get_case(&prepared.case_id)?;
    let now = Utc::now();
    {
        let engine_run = exact_prepared_task_mut(&mut case, prepared)?;
        let already_cancelled = engine_run.status == EngineRunStatus::Cancelled;
        let other_terminal = matches!(
            engine_run.status,
            EngineRunStatus::Completed
                | EngineRunStatus::PartiallyCompleted
                | EngineRunStatus::Failed
                | EngineRunStatus::NotExecuted
        );
        if already_cancelled || (other_terminal && !discard_unmarked_observation) {
            return Ok(case);
        }
        if !discard_unmarked_observation
            || (!other_terminal
                && !matches!(
                    engine_run.status,
                    EngineRunStatus::Queued | EngineRunStatus::Preparing | EngineRunStatus::Running
                ))
        {
            return Err(AppError::Conflict(
                "the localhost cancellation no longer owns this exact task transition".into(),
            ));
        }
        engine_run.status = EngineRunStatus::Cancelled;
        engine_run.progress_percent = 100;
        engine_run.phase = "cancelled".into();
        engine_run.finished_at = Some(now);
        engine_run.resume_token = None;
        engine_run.localhost_tcp_observation = None;
        engine_run.error_code = Some("cancelled_without_observation".into());
        engine_run.error_message = Some("Connection test cancelled. Result: not recorded.".into());
    }
    let run = case
        .scan_runs
        .iter_mut()
        .find(|run| run.id == prepared.scan_run_id)
        .ok_or_else(|| AppError::Conflict("the localhost scan run disappeared".into()))?;
    run.completed_at = Some(now);
    case.status = CaseStatus::NeedsAttention;
    case.touch();
    refresh_coverage_ledger(&mut case, manifests, now);
    storage.save_case(&mut case, "scan.localhost_quick_cancelled")?;
    Ok(case)
}

pub fn reconcile_managed_localhost_terminal(
    storage: &Storage,
    manifests: &[EngineManifest],
    prepared: &PreparedLocalhostQuickScan,
    job_status: JobStatus,
) -> AppResult<AssessmentCase> {
    let case = storage.get_case(&prepared.case_id)?;
    let engine_run = case
        .scan_runs
        .iter()
        .find(|run| run.id == prepared.scan_run_id)
        .and_then(|run| {
            run.engine_runs
                .iter()
                .find(|engine| engine.id == prepared.engine_run_id)
        })
        .ok_or_else(|| AppError::Conflict("the local connection test disappeared".into()))?;
    if matches!(
        engine_run.status,
        EngineRunStatus::Completed
            | EngineRunStatus::PartiallyCompleted
            | EngineRunStatus::Failed
            | EngineRunStatus::Cancelled
            | EngineRunStatus::NotExecuted
    ) {
        return Ok(case);
    }
    if job_status == JobStatus::Cancelled || engine_run.phase == "cancel_requested" {
        return record_localhost_cancelled(storage, manifests, prepared, true);
    }
    reconcile_interrupted_localhost_quick_scan(storage, manifests, prepared)
}

/// Terminalize one exact product-owned localhost task after a worker, process,
/// or persistence interruption. This never repeats target contact. It is safe
/// to call after any error and returns an existing terminal outcome unchanged.
pub fn reconcile_interrupted_localhost_quick_scan(
    storage: &Storage,
    manifests: &[EngineManifest],
    prepared: &PreparedLocalhostQuickScan,
) -> AppResult<AssessmentCase> {
    retry_localhost_persistence(|| {
        reconcile_interrupted_localhost_quick_scan_once(storage, manifests, prepared)
    })
}

fn reconcile_interrupted_localhost_quick_scan_once(
    storage: &Storage,
    manifests: &[EngineManifest],
    prepared: &PreparedLocalhostQuickScan,
) -> AppResult<AssessmentCase> {
    let mut case = storage.get_case(&prepared.case_id)?;
    let now = Utc::now();
    let already_terminal;
    {
        let engine_run = exact_prepared_task_mut(&mut case, prepared)?;
        already_terminal = matches!(
            engine_run.status,
            EngineRunStatus::Completed
                | EngineRunStatus::PartiallyCompleted
                | EngineRunStatus::Failed
                | EngineRunStatus::Cancelled
                | EngineRunStatus::NotExecuted
        );
        if !already_terminal
            && !matches!(
                engine_run.status,
                EngineRunStatus::Queued
                    | EngineRunStatus::Preparing
                    | EngineRunStatus::Running
                    | EngineRunStatus::Paused
            )
        {
            return Err(AppError::Conflict(
                "the local connection test cannot be reconciled from its saved state".into(),
            ));
        }
        if !already_terminal {
            engine_run.status = EngineRunStatus::Failed;
            engine_run.progress_percent = 100;
            engine_run.phase = "localhost_probe_interrupted".into();
            engine_run.finished_at = Some(now);
            engine_run.resume_token = None;
            engine_run.localhost_tcp_observation = None;
            engine_run.error_code = Some("localhost_probe_interrupted".into());
            engine_run.error_message =
                Some("Connection test interrupted. Result: not recorded. Start a new test.".into());
        }
    }
    if already_terminal {
        return Ok(case);
    }
    let run = case
        .scan_runs
        .iter_mut()
        .find(|run| run.id == prepared.scan_run_id)
        .ok_or_else(|| AppError::Conflict("the localhost scan run disappeared".into()))?;
    run.completed_at = Some(now);
    case.status = CaseStatus::NeedsAttention;
    case.touch();
    refresh_coverage_ledger(&mut case, manifests, now);
    storage.save_case(&mut case, "scan.localhost_quick_interrupted")?;
    Ok(case)
}

fn retry_localhost_persistence<T>(mut operation: impl FnMut() -> AppResult<T>) -> AppResult<T> {
    let mut last_retryable = None;
    for attempt in 0..LOCALHOST_PERSISTENCE_ATTEMPTS {
        match operation() {
            Ok(value) => return Ok(value),
            Err(error @ (AppError::Conflict(_) | AppError::Storage(_))) => {
                last_retryable = Some(error);
                if attempt + 1 < LOCALHOST_PERSISTENCE_ATTEMPTS {
                    std::thread::yield_now();
                }
            }
            Err(error) => return Err(error),
        }
    }
    Err(last_retryable.expect("at least one persistence attempt ran"))
}

fn exact_prepared_task_mut<'a>(
    case: &'a mut AssessmentCase,
    prepared: &PreparedLocalhostQuickScan,
) -> AppResult<&'a mut EngineRun> {
    let run = case
        .scan_runs
        .iter_mut()
        .find(|run| run.id == prepared.scan_run_id && run.case_id == prepared.case_id)
        .ok_or_else(|| AppError::Conflict("the localhost scan run disappeared".into()))?;
    let engine_run = run
        .engine_runs
        .iter_mut()
        .find(|engine_run| engine_run.id == prepared.engine_run_id)
        .ok_or_else(|| AppError::Conflict("the local connection test disappeared".into()))?;
    if engine_run.engine_id != LOCALHOST_TCP_ENGINE_ID
        || engine_run.task_kind != EngineTaskKind::built_in_localhost_tcp(prepared.port)
        || engine_run.asset_ids.len() != 1
    {
        return Err(AppError::NotAuthorized(
            "the saved local connection test no longer matches its exact loopback contract".into(),
        ));
    }
    Ok(engine_run)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::beginner_report::{
        BeginnerReportSummary, ReportLifecycle, build_beginner_master_report,
    };
    use crate::case_service::{CaseExportFormat, CaseService};
    use crate::coverage::compute_coverage_ledger;
    use crate::domain::CoverageStatus;
    use crate::export::{ExportOptions, RedactionProfile};
    use crate::job_manager::{
        DurableCancellationOutcome, DurableCancellationWrite, JobManager, JobStatus,
    };
    use crate::local_tcp_probe::LOCAL_TCP_CONNECT_TIMEOUT;
    use crate::storage::SaveCaseFault;
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Barrier, Mutex, mpsc};
    use std::thread;
    use std::time::{Duration, Instant};
    use std::{fs, io};

    fn storage() -> (tempfile::TempDir, Storage) {
        let directory = tempfile::tempdir().expect("tempdir");
        let storage = Storage::open(directory.path().join("casework.db")).expect("storage");
        (directory, storage)
    }

    struct PersistedBeforeContactConnector {
        storage: Arc<Storage>,
        prepared: PreparedLocalhostQuickScan,
        result: Result<(), io::ErrorKind>,
        calls: Arc<Mutex<Vec<(SocketAddr, std::time::Duration)>>>,
    }

    impl LocalTcpConnector for PersistedBeforeContactConnector {
        fn connect(&self, endpoint: SocketAddr, timeout: std::time::Duration) -> io::Result<()> {
            let persisted = self
                .storage
                .get_case(&self.prepared.case_id)
                .expect("queued case must already be durable");
            let task = &persisted.scan_runs[0].engine_runs[0];
            assert_eq!(task.status, EngineRunStatus::Running);
            assert_eq!(task.phase, "connecting");
            self.calls.lock().expect("calls").push((endpoint, timeout));
            match self.result {
                Ok(()) => Ok(()),
                Err(kind) => Err(io::Error::new(kind, "test connector result")),
            }
        }
    }

    struct BlockingConnector {
        entered: Arc<Barrier>,
        release: Arc<Barrier>,
        calls: Arc<AtomicUsize>,
    }

    impl LocalTcpConnector for BlockingConnector {
        fn connect(&self, _endpoint: SocketAddr, _timeout: std::time::Duration) -> io::Result<()> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.entered.wait();
            self.release.wait();
            Ok(())
        }
    }

    type ManagedTerminal = (JobSnapshot, AppResult<AssessmentCase>);

    fn start_managed_test_job(
        storage: Arc<Storage>,
        prepared: PreparedLocalhostQuickScan,
        connector: Arc<dyn LocalTcpConnector>,
        before_dispatch: Option<Arc<dyn Fn() + Send + Sync>>,
        after_terminal_mark: Option<Arc<dyn Fn() + Send + Sync>>,
    ) -> (JobManager, JobKey, mpsc::Receiver<ManagedTerminal>) {
        let manager = JobManager::default();
        let key =
            JobKey::new(prepared.case_id.clone(), prepared.scan_run_id.clone()).expect("job key");
        let worker_storage = Arc::clone(&storage);
        let worker_prepared = prepared.clone();
        let callback_storage = Arc::clone(&storage);
        let callback_prepared = prepared.clone();
        let (terminal_tx, terminal_rx) = mpsc::channel();
        manager
            .start_job(
                key.clone(),
                [prepared.engine_run_id.clone()],
                move |context| {
                    let hooks = ManagedLocalhostExecutionHooks {
                        before_dispatch: before_dispatch.as_deref().map(|hook| hook as &dyn Fn()),
                        after_terminal_mark: after_terminal_mark
                            .as_deref()
                            .map(|hook| hook as &dyn Fn()),
                    };
                    execute_managed_localhost_quick_scan_with_hooks(
                        &worker_storage,
                        &[],
                        &worker_prepared,
                        connector.as_ref(),
                        &context,
                        &hooks,
                    )
                },
                move |snapshot| {
                    let reconciled = reconcile_managed_localhost_terminal(
                        &callback_storage,
                        &[],
                        &callback_prepared,
                        snapshot.status,
                    );
                    terminal_tx
                        .send((snapshot, reconciled))
                        .expect("terminal receiver");
                },
            )
            .expect("managed job starts");
        (manager, key, terminal_rx)
    }

    fn wait_for_job_status(manager: &JobManager, key: &JobKey, expected: JobStatus) {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let snapshot = manager
                .snapshot(key)
                .expect("job remains observable at the synchronization point");
            if snapshot.status == expected {
                return;
            }
            assert!(
                !matches!(
                    snapshot.status,
                    JobStatus::Completed | JobStatus::Cancelled | JobStatus::Failed
                ),
                "job became terminal before reaching {expected:?}: {snapshot:?}"
            );
            assert!(
                Instant::now() < deadline,
                "job did not reach {expected:?} before the test deadline: {snapshot:?}"
            );
            thread::yield_now();
        }
    }

    fn run_managed_test_job(
        storage: Arc<Storage>,
        prepared: PreparedLocalhostQuickScan,
        connector: Arc<dyn LocalTcpConnector>,
    ) -> AssessmentCase {
        let (_manager, _key, terminal_rx) =
            start_managed_test_job(storage, prepared, connector, None, None);
        let (_snapshot, reconciled) = terminal_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("managed terminal callback");
        reconciled.expect("managed durable reconciliation")
    }

    #[test]
    fn preparation_persists_one_exact_authorized_loopback_task_without_contact() {
        let (_directory, storage) = storage();

        let result = prepare_localhost_quick_scan(&storage, &[], 9_001).expect("prepare");
        let persisted = storage.get_case(&result.case.id).expect("persisted case");

        assert_eq!(persisted.data_sources.len(), 1);
        assert_eq!(persisted.assets.len(), 1);
        assert_eq!(persisted.scope_grants.len(), 1);
        assert_eq!(persisted.scan_runs.len(), 1);
        let asset = &persisted.assets[0];
        assert_eq!(asset.kind, AssetKind::WebService);
        assert_eq!(asset.name, "127.0.0.1:9001");
        assert!(asset.owner_confirmed);
        assert!(!asset.candidate);
        assert_eq!(asset.identifiers.len(), 1);
        assert_eq!(
            asset.identifiers[0].namespace,
            LOCALHOST_TCP_ASSET_IDENTIFIER_NAMESPACE
        );
        assert_eq!(asset.identifiers[0].value, "127.0.0.1:9001");
        let grant = &persisted.scope_grants[0];
        assert_eq!(
            grant.permission,
            ScanPermission::LowImpactExternalConnection
        );
        assert_eq!(
            grant.authorization_reference.as_deref(),
            Some(LOCALHOST_TCP_AUTHORIZATION_REFERENCE)
        );
        let task = &persisted.scan_runs[0].engine_runs[0];
        assert_eq!(task.status, EngineRunStatus::Queued);
        assert_eq!(
            task.task_kind,
            EngineTaskKind::built_in_localhost_tcp(9_001)
        );
        assert_eq!(task.asset_ids, vec![asset.id.clone()]);
        assert!(task.localhost_tcp_observation.is_none());
        assert_eq!(
            storage.selected_case_id().expect("selected"),
            Some(persisted.id)
        );
    }

    #[test]
    fn managed_dispatch_returns_queued_immediately_and_refuses_pause_or_resume() {
        let (directory, storage) = storage();
        let storage = Arc::new(storage);
        let prepared = prepare_localhost_quick_scan(&storage, &[], 9_001)
            .expect("prepare")
            .prepared;
        let before_entered = Arc::new(Barrier::new(2));
        let before_release = Arc::new(Barrier::new(2));
        let hook_entered = Arc::clone(&before_entered);
        let hook_release = Arc::clone(&before_release);
        let before_dispatch: Arc<dyn Fn() + Send + Sync> = Arc::new(move || {
            hook_entered.wait();
            hook_release.wait();
        });
        let connector_calls = Arc::new(Mutex::new(Vec::new()));
        let connector: Arc<dyn LocalTcpConnector> = Arc::new(PersistedBeforeContactConnector {
            storage: Arc::clone(&storage),
            prepared: prepared.clone(),
            result: Ok(()),
            calls: Arc::clone(&connector_calls),
        });

        let (_manager, _key, terminal_rx) = start_managed_test_job(
            Arc::clone(&storage),
            prepared.clone(),
            connector,
            Some(before_dispatch),
            None,
        );
        // The worker cannot cross its injected pre-dispatch barrier until the
        // test releases it, so returning here proves admission is detached.
        let queued = storage.get_case(&prepared.case_id).expect("queued case");
        assert_eq!(
            queued.scan_runs[0].engine_runs[0].status,
            EngineRunStatus::Queued
        );
        before_entered.wait();

        let engines = crate::registry::EngineRegistry::load_builtin().expect("engine registry");
        let adapters = crate::adapters::builtin_adapter_registry().expect("adapter registry");
        let service = CaseService::new(
            &storage,
            &engines,
            &adapters,
            directory.path().join("artifacts"),
            directory.path().join("signing.key"),
        );
        assert!(matches!(
            service
                .pause_scan(&prepared.case_id, &prepared.scan_run_id)
                .expect_err("built-in task cannot pause"),
            AppError::NotAvailable(_)
        ));
        assert!(matches!(
            service
                .resume_scan(&prepared.case_id, &prepared.scan_run_id)
                .expect_err("built-in task cannot resume"),
            AppError::NotAvailable(_)
        ));

        before_release.wait();
        let (_snapshot, completed) = terminal_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("completed callback");
        assert_eq!(
            completed.expect("durable result").scan_runs[0].engine_runs[0].status,
            EngineRunStatus::Completed
        );
        assert_eq!(connector_calls.lock().expect("calls").len(), 1);
    }

    #[test]
    fn connection_diagnostic_reopens_and_exports_the_same_durable_result() {
        let (directory, storage) = storage();
        let database_path = directory.path().join("casework.db");
        let storage = Arc::new(storage);
        let prepared = prepare_localhost_quick_scan(&storage, &[], 9_001)
            .expect("prepare exact localhost work")
            .prepared;
        let connector_calls = Arc::new(Mutex::new(Vec::new()));
        let connector: Arc<dyn LocalTcpConnector> = Arc::new(PersistedBeforeContactConnector {
            storage: Arc::clone(&storage),
            prepared: prepared.clone(),
            result: Err(io::ErrorKind::ConnectionRefused),
            calls: Arc::clone(&connector_calls),
        });

        let completed = run_managed_test_job(Arc::clone(&storage), prepared.clone(), connector);
        assert_eq!(connector_calls.lock().expect("calls").len(), 1);
        assert!(completed.scan_runs[0].completed_at.is_some());
        assert_eq!(
            completed.scan_runs[0].engine_runs[0].status,
            EngineRunStatus::Completed,
        );
        assert_eq!(
            completed.scan_runs[0].engine_runs[0]
                .localhost_tcp_observation
                .as_ref()
                .map(|observation| &observation.outcome),
            Some(&LocalhostTcpOutcome::Closed),
        );

        drop(storage);
        let reopened_storage = Storage::open(&database_path).expect("reopen durable case database");
        let reopened = reopened_storage
            .get_case(&prepared.case_id)
            .expect("reopen the same saved project");
        let report = build_beginner_master_report(&reopened, &prepared.scan_run_id)
            .expect("build beginner report from reopened data");
        assert_eq!(report.state.summary, BeginnerReportSummary::Complete);
        assert_eq!(report.state.lifecycle, ReportLifecycle::Final);
        assert!(report.coverage_gaps.is_empty());
        assert!(report.actual.checks.iter().any(|check| {
            check.tested_dimensions.iter().any(|dimension| {
                dimension.value == "127.0.0.1:9001" && dimension.observation.contains("refused")
            })
        }));

        let engines = crate::registry::EngineRegistry::load_builtin().expect("engine registry");
        let adapters = crate::adapters::builtin_adapter_registry().expect("adapter registry");
        let service = CaseService::new(
            &reopened_storage,
            &engines,
            &adapters,
            directory.path().join("artifacts"),
            directory.path().join("signing.key"),
        );
        let destination = directory.path().join("connection-diagnostic-report.html");
        let exported = service
            .export_case(
                &prepared.case_id,
                &prepared.scan_run_id,
                CaseExportFormat::Html,
                &destination,
                ExportOptions {
                    redaction: RedactionProfile::None,
                    include_raw_artifacts: false,
                    locale: crate::export::ReportLocale::En,
                },
            )
            .expect("export reopened beginner report");
        assert!(
            service
                .verify_stored_export(&prepared.case_id, &exported.id)
                .expect("verify stored export")
                .valid
        );
        let html = fs::read_to_string(destination).expect("read exported HTML");
        for expected in [
            "Complete",
            "Which assets need attention",
            "127.0.0.1:9001",
            "What was actually tested",
            "What was not tested",
            "What to do next",
            "This report is not an audit, certification",
            "Content-Security-Policy",
        ] {
            assert!(
                html.contains(expected),
                "missing readable report text: {expected}"
            );
        }
        assert!(!html.contains("<script"));
    }

    #[test]
    fn predispatch_cancel_saves_intent_makes_zero_contacts_and_finishes_cancelled() {
        let (_directory, storage) = storage();
        let storage = Arc::new(storage);
        let prepared = prepare_localhost_quick_scan(&storage, &[], 9_001)
            .expect("prepare")
            .prepared;
        let before_entered = Arc::new(Barrier::new(2));
        let before_release = Arc::new(Barrier::new(2));
        let hook_entered = Arc::clone(&before_entered);
        let hook_release = Arc::clone(&before_release);
        let before_dispatch: Arc<dyn Fn() + Send + Sync> = Arc::new(move || {
            hook_entered.wait();
            hook_release.wait();
        });
        let calls = Arc::new(Mutex::new(Vec::new()));
        let connector: Arc<dyn LocalTcpConnector> = Arc::new(PersistedBeforeContactConnector {
            storage: Arc::clone(&storage),
            prepared: prepared.clone(),
            result: Ok(()),
            calls: Arc::clone(&calls),
        });
        let (manager, key, terminal_rx) = start_managed_test_job(
            Arc::clone(&storage),
            prepared.clone(),
            connector,
            Some(before_dispatch),
            None,
        );
        before_entered.wait();

        let outcome = manager
            .cancel_with_durable_transition(&key, || {
                record_localhost_cancel_transition(&storage, &[], &prepared)
            })
            .expect("manager cancellation")
            .expect("durable cancellation");
        let DurableCancellationOutcome::Requested { durable, .. } = outcome else {
            panic!("active queued task must save cancel_requested")
        };
        let requested = &durable.scan_runs[0].engine_runs[0];
        assert_eq!(requested.status, EngineRunStatus::Queued);
        assert_eq!(requested.phase, "cancel_requested");

        before_release.wait();
        let (snapshot, reconciled) = terminal_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("cancelled callback");
        assert_eq!(snapshot.status, JobStatus::Cancelled);
        let cancelled = reconciled.expect("durable cancellation terminal");
        let task = &cancelled.scan_runs[0].engine_runs[0];
        assert_eq!(task.status, EngineRunStatus::Cancelled);
        assert_eq!(
            task.error_code.as_deref(),
            Some("cancelled_without_observation")
        );
        assert_eq!(
            task.error_message.as_deref(),
            Some("Connection test cancelled. Result: not recorded.")
        );
        assert!(task.localhost_tcp_observation.is_none());
        assert!(calls.lock().expect("calls").is_empty());
    }

    #[test]
    fn cancel_during_connector_returns_before_release_and_discards_late_observation() {
        let (_directory, storage) = storage();
        let storage = Arc::new(storage);
        let prepared = prepare_localhost_quick_scan(&storage, &[], 9_001)
            .expect("prepare")
            .prepared;
        let connector_entered = Arc::new(Barrier::new(2));
        let connector_release = Arc::new(Barrier::new(2));
        let calls = Arc::new(AtomicUsize::new(0));
        let connector: Arc<dyn LocalTcpConnector> = Arc::new(BlockingConnector {
            entered: Arc::clone(&connector_entered),
            release: Arc::clone(&connector_release),
            calls: Arc::clone(&calls),
        });
        let (manager, key, terminal_rx) = start_managed_test_job(
            Arc::clone(&storage),
            prepared.clone(),
            connector,
            None,
            None,
        );
        connector_entered.wait();

        let cancel_manager = manager.clone();
        let cancel_key = key.clone();
        let cancel_storage = Arc::clone(&storage);
        let cancel_prepared = prepared.clone();
        let cancel_started = Arc::new(Barrier::new(2));
        let thread_started = Arc::clone(&cancel_started);
        let (cancel_tx, cancel_rx) = mpsc::channel();
        let cancel_thread = thread::spawn(move || {
            thread_started.wait();
            cancel_tx
                .send(
                    cancel_manager.cancel_with_durable_transition(&cancel_key, || {
                        record_localhost_cancel_transition(&cancel_storage, &[], &cancel_prepared)
                    }),
                )
                .expect("cancel receiver");
        });
        cancel_started.wait();
        wait_for_job_status(&manager, &key, JobStatus::CancelRequested);
        let outcome = cancel_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("cancel must not wait for connector")
            .expect("manager cancellation")
            .expect("durable cancellation");
        assert!(matches!(
            outcome,
            DurableCancellationOutcome::Requested { .. }
        ));
        let saved = storage.get_case(&prepared.case_id).expect("saved request");
        assert_eq!(
            saved.scan_runs[0].engine_runs[0].status,
            EngineRunStatus::Running
        );
        assert_eq!(saved.scan_runs[0].engine_runs[0].phase, "cancel_requested");

        connector_release.wait();
        cancel_thread.join().expect("cancel thread");
        let (snapshot, reconciled) = terminal_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("cancelled callback");
        assert_eq!(snapshot.status, JobStatus::Cancelled);
        let cancelled = reconciled.expect("durable cancellation terminal");
        let task = &cancelled.scan_runs[0].engine_runs[0];
        assert_eq!(task.status, EngineRunStatus::Cancelled);
        assert_eq!(
            task.error_code.as_deref(),
            Some("cancelled_without_observation")
        );
        assert_eq!(
            task.error_message.as_deref(),
            Some("Connection test cancelled. Result: not recorded.")
        );
        assert!(task.localhost_tcp_observation.is_none());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn durable_result_and_terminal_mark_beat_a_late_cancel_forever() {
        let (_directory, storage) = storage();
        let storage = Arc::new(storage);
        let prepared = prepare_localhost_quick_scan(&storage, &[], 9_001)
            .expect("prepare")
            .prepared;
        let calls = Arc::new(Mutex::new(Vec::new()));
        let connector: Arc<dyn LocalTcpConnector> = Arc::new(PersistedBeforeContactConnector {
            storage: Arc::clone(&storage),
            prepared: prepared.clone(),
            result: Ok(()),
            calls: Arc::clone(&calls),
        });
        let terminal_marked = Arc::new(Barrier::new(2));
        let terminal_release = Arc::new(Barrier::new(2));
        let hook_marked = Arc::clone(&terminal_marked);
        let hook_release = Arc::clone(&terminal_release);
        let after_terminal_mark: Arc<dyn Fn() + Send + Sync> = Arc::new(move || {
            hook_marked.wait();
            hook_release.wait();
        });
        let (manager, key, terminal_rx) = start_managed_test_job(
            Arc::clone(&storage),
            prepared.clone(),
            connector,
            None,
            Some(after_terminal_mark),
        );
        terminal_marked.wait();

        let durable_writes = Arc::new(AtomicUsize::new(0));
        let writes = Arc::clone(&durable_writes);
        let cancel_manager = manager.clone();
        let cancel_key = key.clone();
        let cancel_started = Arc::new(Barrier::new(2));
        let thread_started = Arc::clone(&cancel_started);
        let (cancel_tx, cancel_rx) = mpsc::channel();
        let cancel_thread = thread::spawn(move || {
            thread_started.wait();
            cancel_tx
                .send(
                    cancel_manager.cancel_with_durable_transition(&cancel_key, move || {
                        writes.fetch_add(1, Ordering::SeqCst);
                        Ok::<_, AppError>(DurableCancellationWrite::Requested(()))
                    }),
                )
                .expect("cancel receiver");
        });
        cancel_started.wait();
        wait_for_job_status(&manager, &key, JobStatus::CancelRequested);
        assert!(matches!(
            cancel_rx.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));
        terminal_release.wait();

        let outcome = cancel_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("late cancel returns")
            .expect("manager transition")
            .expect("typed outcome");
        assert!(matches!(
            outcome,
            DurableCancellationOutcome::TerminalWon { durable: None, .. }
        ));
        assert_eq!(durable_writes.load(Ordering::SeqCst), 0);
        cancel_thread.join().expect("cancel thread");
        let (snapshot, reconciled) = terminal_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("completed callback");
        assert_eq!(snapshot.status, JobStatus::Completed);
        let completed = reconciled.expect("durable result");
        let task = &completed.scan_runs[0].engine_runs[0];
        assert_eq!(task.status, EngineRunStatus::Completed);
        assert_eq!(
            task.localhost_tcp_observation
                .as_ref()
                .map(|observation| &observation.outcome),
            Some(&LocalhostTcpOutcome::Reachable)
        );
        assert_eq!(calls.lock().expect("calls").len(), 1);
    }

    #[test]
    fn durable_terminal_truth_beats_lagging_job_control_and_one_way_cancel_token() {
        let (_directory, storage) = storage();
        let storage = Arc::new(storage);
        let prepared = prepare_localhost_quick_scan(&storage, &[], 9_001)
            .expect("prepare")
            .prepared;
        let before_entered = Arc::new(Barrier::new(2));
        let before_release = Arc::new(Barrier::new(2));
        let hook_entered = Arc::clone(&before_entered);
        let hook_release = Arc::clone(&before_release);
        let before_dispatch: Arc<dyn Fn() + Send + Sync> = Arc::new(move || {
            hook_entered.wait();
            hook_release.wait();
        });
        let calls = Arc::new(Mutex::new(Vec::new()));
        let connector: Arc<dyn LocalTcpConnector> = Arc::new(PersistedBeforeContactConnector {
            storage: Arc::clone(&storage),
            prepared: prepared.clone(),
            result: Ok(()),
            calls: Arc::clone(&calls),
        });
        let (manager, key, terminal_rx) = start_managed_test_job(
            Arc::clone(&storage),
            prepared.clone(),
            connector,
            Some(before_dispatch),
            None,
        );
        before_entered.wait();

        persist_localhost_running_once(&storage, &[], &prepared).expect("simulate durable running");
        let durable_terminal = complete_localhost_quick_scan_once(
            &storage,
            &[],
            &prepared,
            Ok(LocalTcpProbeOutcome::Reachable),
        )
        .expect("simulate durable terminal truth");
        let outcome = manager
            .cancel_with_durable_transition(&key, || {
                record_localhost_cancel_transition(&storage, &[], &prepared)
            })
            .expect("manager transition")
            .expect("typed transition");
        let DurableCancellationOutcome::TerminalWon {
            durable: Some(returned),
            ..
        } = outcome
        else {
            panic!("durable terminal truth must win")
        };
        assert_eq!(returned.storage_revision, durable_terminal.storage_revision);
        assert_eq!(returned.scan_runs[0].engine_runs[0].phase, "completed");
        assert!(
            returned.scan_runs[0].engine_runs[0]
                .localhost_tcp_observation
                .is_some()
        );

        before_release.wait();
        let (snapshot, reconciled) = terminal_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("terminal callback");
        assert_eq!(snapshot.status, JobStatus::Completed);
        let preserved = reconciled.expect("preserved durable truth");
        assert_eq!(preserved.scan_runs[0].engine_runs[0].phase, "completed");
        assert!(
            preserved.scan_runs[0].engine_runs[0]
                .localhost_tcp_observation
                .is_some()
        );
        assert!(calls.lock().expect("calls").is_empty());
    }

    #[test]
    fn cancel_persistence_fault_reconciles_without_recontact() {
        let (_directory, storage) = storage();
        let storage = Arc::new(storage);
        let prepared = prepare_localhost_quick_scan(&storage, &[], 9_001)
            .expect("prepare")
            .prepared;
        let connector_entered = Arc::new(Barrier::new(2));
        let connector_release = Arc::new(Barrier::new(2));
        let calls = Arc::new(AtomicUsize::new(0));
        let connector: Arc<dyn LocalTcpConnector> = Arc::new(BlockingConnector {
            entered: Arc::clone(&connector_entered),
            release: Arc::clone(&connector_release),
            calls: Arc::clone(&calls),
        });
        let (manager, key, terminal_rx) = start_managed_test_job(
            Arc::clone(&storage),
            prepared.clone(),
            connector,
            None,
            None,
        );
        connector_entered.wait();
        let outcome = manager
            .cancel_with_durable_transition(&key, || {
                record_localhost_cancel_transition(&storage, &[], &prepared)
            })
            .expect("manager cancellation")
            .expect("durable request");
        assert!(matches!(
            outcome,
            DurableCancellationOutcome::Requested { .. }
        ));
        storage.inject_save_case_faults(
            "scan.localhost_quick_cancelled",
            LOCALHOST_PERSISTENCE_ATTEMPTS,
            SaveCaseFault::Storage,
        );
        connector_release.wait();
        let (snapshot, reconciled) = terminal_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("persistence-pending callback");
        assert_eq!(snapshot.status, JobStatus::Failed);
        let cancelled = reconciled.expect("callback retries exact durable cancellation");
        assert_eq!(
            cancelled.scan_runs[0].engine_runs[0].status,
            EngineRunStatus::Cancelled
        );
        assert!(
            cancelled.scan_runs[0].engine_runs[0]
                .localhost_tcp_observation
                .is_none()
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn exact_port_selector_dedupes_only_same_port_and_different_ports_each_run_once() {
        let (_directory, storage) = storage();
        let storage = Arc::new(storage);
        let first = prepare_localhost_quick_scan(&storage, &[], 9_001)
            .expect("first prepare")
            .prepared;
        let second = prepare_localhost_quick_scan(&storage, &[], 9_002)
            .expect("second prepare")
            .prepared;
        let first_entered = Arc::new(Barrier::new(2));
        let first_release = Arc::new(Barrier::new(2));
        let first_calls = Arc::new(AtomicUsize::new(0));
        let second_entered = Arc::new(Barrier::new(2));
        let second_release = Arc::new(Barrier::new(2));
        let second_calls = Arc::new(AtomicUsize::new(0));
        let (first_manager, first_key, first_terminal) = start_managed_test_job(
            Arc::clone(&storage),
            first.clone(),
            Arc::new(BlockingConnector {
                entered: Arc::clone(&first_entered),
                release: Arc::clone(&first_release),
                calls: Arc::clone(&first_calls),
            }),
            None,
            None,
        );
        let (second_manager, second_key, second_terminal) = start_managed_test_job(
            Arc::clone(&storage),
            second.clone(),
            Arc::new(BlockingConnector {
                entered: Arc::clone(&second_entered),
                release: Arc::clone(&second_release),
                calls: Arc::clone(&second_calls),
            }),
            None,
            None,
        );
        first_entered.wait();
        second_entered.wait();

        let first_live = first_manager.live_snapshots();
        let second_live = second_manager.live_snapshots();
        assert_eq!(
            live_localhost_quick_scan_for_port(&storage, &first_live, 9_001)
                .expect("same-port live case")
                .id,
            first.case_id
        );
        assert!(live_localhost_quick_scan_for_port(&storage, &first_live, 9_002).is_none());
        assert_eq!(
            live_localhost_quick_scan_for_port(&storage, &second_live, 9_002)
                .expect("different-port live case")
                .id,
            second.case_id
        );
        assert_ne!(first_key, second_key);

        first_release.wait();
        second_release.wait();
        first_terminal
            .recv_timeout(Duration::from_secs(2))
            .expect("first terminal")
            .1
            .expect("first durable terminal");
        second_terminal
            .recv_timeout(Duration::from_secs(2))
            .expect("second terminal")
            .1
            .expect("second durable terminal");
        assert_eq!(first_calls.load(Ordering::SeqCst), 1);
        assert_eq!(second_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn execution_contacts_only_exact_loopback_after_running_state_is_durable() {
        let (_directory, storage) = storage();
        let storage = Arc::new(storage);
        let prepared = prepare_localhost_quick_scan(&storage, &[], 42_001)
            .expect("prepare")
            .prepared;
        let calls = Arc::new(Mutex::new(Vec::new()));
        let connector: Arc<dyn LocalTcpConnector> = Arc::new(PersistedBeforeContactConnector {
            storage: Arc::clone(&storage),
            prepared: prepared.clone(),
            result: Ok(()),
            calls: Arc::clone(&calls),
        });

        let completed = run_managed_test_job(Arc::clone(&storage), prepared, connector);

        assert_eq!(
            *calls.lock().expect("calls"),
            vec![(
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 42_001)),
                LOCAL_TCP_CONNECT_TIMEOUT,
            )]
        );
        let task = &completed.scan_runs[0].engine_runs[0];
        assert_eq!(task.status, EngineRunStatus::Completed);
        assert_eq!(
            task.localhost_tcp_observation
                .as_ref()
                .map(|value| &value.outcome),
            Some(&LocalhostTcpOutcome::Reachable)
        );
        assert!(completed.scan_runs[0].completed_at.is_some());
    }

    #[test]
    fn timeout_is_a_truthful_partial_result_and_refusal_is_a_completed_observation() {
        for (kind, expected_status, expected_outcome) in [
            (
                io::ErrorKind::TimedOut,
                EngineRunStatus::PartiallyCompleted,
                LocalhostTcpOutcome::TimedOut,
            ),
            (
                io::ErrorKind::ConnectionRefused,
                EngineRunStatus::Completed,
                LocalhostTcpOutcome::Closed,
            ),
        ] {
            let (_directory, storage) = storage();
            let storage = Arc::new(storage);
            let prepared = prepare_localhost_quick_scan(&storage, &[], 9_001)
                .expect("prepare")
                .prepared;
            let connector: Arc<dyn LocalTcpConnector> = Arc::new(PersistedBeforeContactConnector {
                storage: Arc::clone(&storage),
                prepared: prepared.clone(),
                result: Err(kind),
                calls: Arc::new(Mutex::new(Vec::new())),
            });

            let completed = run_managed_test_job(storage, prepared, connector);
            let task = &completed.scan_runs[0].engine_runs[0];
            assert_eq!(task.status, expected_status);
            assert_eq!(
                task.localhost_tcp_observation
                    .as_ref()
                    .map(|value| &value.outcome),
                Some(&expected_outcome)
            );
        }
    }

    #[test]
    fn terminal_persistence_fault_is_bounded_and_reconciled_without_second_contact() {
        let (_directory, storage) = storage();
        let storage = Arc::new(storage);
        let prepared = prepare_localhost_quick_scan(&storage, &[], 9_001)
            .expect("prepare")
            .prepared;
        storage.inject_save_case_faults(
            "scan.localhost_quick_finished",
            LOCALHOST_PERSISTENCE_ATTEMPTS,
            SaveCaseFault::Storage,
        );
        let calls = Arc::new(Mutex::new(Vec::new()));
        let connector: Arc<dyn LocalTcpConnector> = Arc::new(PersistedBeforeContactConnector {
            storage: Arc::clone(&storage),
            prepared: prepared.clone(),
            result: Ok(()),
            calls: Arc::clone(&calls),
        });

        let reconciled = run_managed_test_job(Arc::clone(&storage), prepared.clone(), connector);

        assert_eq!(calls.lock().expect("calls").len(), 1);
        let task = &reconciled.scan_runs[0].engine_runs[0];
        assert_eq!(task.status, EngineRunStatus::Failed);
        assert_eq!(task.phase, "localhost_probe_interrupted");
        assert_eq!(
            task.error_message.as_deref(),
            Some("Connection test interrupted. Result: not recorded. Start a new test.")
        );
        assert!(task.localhost_tcp_observation.is_none());
        assert!(reconciled.scan_runs[0].completed_at.is_some());
        let persisted = storage
            .get_case(&prepared.case_id)
            .expect("persisted failure");
        assert_eq!(
            persisted.scan_runs[0].engine_runs[0].phase,
            "localhost_probe_interrupted"
        );
        assert_eq!(
            reconcile_interrupted_localhost_quick_scan(&storage, &[], &prepared)
                .expect("idempotent reconciliation")
                .storage_revision,
            persisted.storage_revision
        );
    }

    #[test]
    fn running_persistence_fault_terminalizes_without_target_contact() {
        let (_directory, storage) = storage();
        let storage = Arc::new(storage);
        let prepared = prepare_localhost_quick_scan(&storage, &[], 9_001)
            .expect("prepare")
            .prepared;
        storage.inject_save_case_faults(
            "scan.localhost_quick_running",
            LOCALHOST_PERSISTENCE_ATTEMPTS,
            SaveCaseFault::Conflict,
        );
        let calls = Arc::new(Mutex::new(Vec::new()));
        let connector: Arc<dyn LocalTcpConnector> = Arc::new(PersistedBeforeContactConnector {
            storage: Arc::clone(&storage),
            prepared: prepared.clone(),
            result: Ok(()),
            calls: Arc::clone(&calls),
        });

        let reconciled = run_managed_test_job(storage, prepared, connector);

        assert!(calls.lock().expect("calls").is_empty());
        let task = &reconciled.scan_runs[0].engine_runs[0];
        assert_eq!(task.status, EngineRunStatus::Failed);
        assert_eq!(task.phase, "localhost_probe_interrupted");
        assert!(task.localhost_tcp_observation.is_none());
    }

    #[test]
    fn invalid_port_creates_no_case_and_contacts_nothing() {
        let (_directory, storage) = storage();

        let error = prepare_localhost_quick_scan(&storage, &[], 0).unwrap_err();

        assert!(matches!(error, AppError::InvalidRequest(_)));
        assert!(storage.list_cases().expect("cases").is_empty());
    }

    fn asset_coverage(case: &AssessmentCase) -> CoverageStatus {
        let asset_id = &case.assets[0].id;
        compute_coverage_ledger(case, &[], Utc::now())
            .into_iter()
            .find(|entry| entry.asset_id.as_ref() == Some(asset_id))
            .expect("asset coverage")
            .status
    }

    #[test]
    fn green_coverage_requires_the_complete_exact_target_and_permission_binding() {
        let (_directory, storage) = storage();
        let storage = Arc::new(storage);
        let prepared = prepare_localhost_quick_scan(&storage, &[], 9_001)
            .expect("prepare")
            .prepared;
        let connector: Arc<dyn LocalTcpConnector> = Arc::new(PersistedBeforeContactConnector {
            storage: Arc::clone(&storage),
            prepared: prepared.clone(),
            result: Ok(()),
            calls: Arc::new(Mutex::new(Vec::new())),
        });
        let completed = run_managed_test_job(storage, prepared, connector);
        assert_eq!(
            asset_coverage(&completed),
            CoverageStatus::DiscoveredAuthorizedScanned
        );

        let mut changed_target = completed.clone();
        changed_target.assets[0].identifiers[0].value = "127.0.0.1:9002".into();
        let mut expanded_assets = completed.clone();
        expanded_assets.scan_runs[0].engine_runs[0]
            .asset_ids
            .push("another-asset".into());
        let mut changed_permission = completed.clone();
        changed_permission.scan_runs[0].scope_grant_snapshots[0].authorization_reference =
            Some("different action".into());
        let mut expanded_run = completed.clone();
        let duplicate_task = expanded_run.scan_runs[0].engine_runs[0].clone();
        expanded_run.scan_runs[0].engine_runs.push(duplicate_task);
        let mut impossible_observation = completed.clone();
        impossible_observation.scan_runs[0].engine_runs[0]
            .localhost_tcp_observation
            .as_mut()
            .expect("observation")
            .observed_at = completed.scan_runs[0].created_at - chrono::Duration::seconds(1);

        for changed in [
            changed_target,
            expanded_assets,
            changed_permission,
            expanded_run,
            impossible_observation,
        ] {
            assert_eq!(
                asset_coverage(&changed),
                CoverageStatus::AuthorizedScanIncomplete
            );
        }
    }
}
