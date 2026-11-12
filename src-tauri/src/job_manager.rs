//! Thread-safe lifecycle control for long-running assessment scan jobs.
//!
//! The manager deliberately knows nothing about Tauri, storage, adapters, or
//! scanners. Callers provide an owned worker closure and a terminal callback,
//! which keeps dependency lifetimes at the integration boundary. A live job is
//! identified only by its `(case_id, scan_run_id)` pair.

use crate::container_runtime::CancellationToken;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::panic::{self, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread;
use thiserror::Error;

#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JobKey {
    pub case_id: String,
    pub scan_run_id: String,
}

impl JobKey {
    pub fn new(
        case_id: impl Into<String>,
        scan_run_id: impl Into<String>,
    ) -> Result<Self, JobManagerError> {
        let key = Self {
            case_id: case_id.into(),
            scan_run_id: scan_run_id.into(),
        };
        validate_identity(&key.case_id, "case id")?;
        validate_identity(&key.scan_run_id, "scan run id")?;
        Ok(key)
    }
}

impl fmt::Debug for JobKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("JobKey")
            .field(&self.case_id)
            .field(&self.scan_run_id)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum JobStatus {
    Starting,
    Running,
    PauseRequested,
    Paused,
    ResumeRequested,
    CancelRequested,
    Completed,
    Cancelled,
    Failed,
}

impl JobStatus {
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Cancelled | Self::Failed)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EngineJobStatus {
    Queued,
    Running,
    PauseRequested,
    Paused,
    ResumeRequested,
    CancelRequested,
    Completed,
    Cancelled,
    Failed,
}

impl EngineJobStatus {
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Cancelled | Self::Failed)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum JobFailureKind {
    WorkerReported,
    WorkerPanicked,
    WorkerReturnedEarly,
    /// The worker stopped safely before target contact, but its terminal
    /// durable transition could not be committed within the bounded retry
    /// budget. Startup reconciliation owns the remaining persistence work.
    PersistencePending,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EngineJobSnapshot {
    pub engine_id: String,
    pub status: EngineJobStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JobSnapshot {
    pub key: JobKey,
    pub status: JobStatus,
    pub engines: Vec<EngineJobSnapshot>,
    pub failure_kind: Option<JobFailureKind>,
    /// Process-local identity used only to acknowledge the exact retained
    /// outcome that was durably reconciled. It is deliberately omitted from
    /// serialized product events and cannot become a user-visible contract.
    #[serde(skip)]
    pub(crate) generation: u64,
}

impl JobSnapshot {
    pub fn is_terminal(&self) -> bool {
        self.status.is_terminal()
    }
}

/// The worker's aggregate result. For `Completed`, every engine must already
/// have been marked terminal by its [`EngineJobControl`]; otherwise the manager
/// records a fail-closed `WorkerReturnedEarly` result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobCompletion {
    Completed,
    Cancelled,
    Failed,
    /// No target contact occurred, but the requested terminal state is not yet
    /// durable. This is an explicit terminal in-memory failure rather than an
    /// indefinitely live `CancelRequested` job.
    PersistencePending,
}

/// Result of the one-time transition that makes a newly persisted job
/// executable. Activation waits while the job is paused and shares the same
/// per-job coordinator as pause, resume, and cancellation. The activation
/// closure therefore runs exactly once only when cancellation is not pending.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JobActivationOutcome<T, E> {
    Activated(T),
    Cancelled,
    Failed(E),
}

/// Durable classification returned by the caller while one exact cancellation
/// transition owns the per-job coordinator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DurableCancellationWrite<T> {
    /// The durable store now contains the cancellation request.
    Requested(T),
    /// The durable store already contains an authoritative terminal result.
    /// A lagging in-memory worker must preserve that payload even though the
    /// one-way cancellation token has already been published.
    TerminalWon(T),
}

/// Result of publishing one cancellation intent and serializing its durable
/// projection with the exact live generation. `TerminalWon` means either the
/// worker committed and marked its terminal result before this transition, or
/// the durable closure found terminal truth while JobControl lagged. Callers
/// must return that saved truth and must not claim a cancellation was saved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DurableCancellationOutcome<T> {
    Requested {
        snapshot: JobSnapshot,
        durable: T,
    },
    TerminalWon {
        snapshot: JobSnapshot,
        durable: Option<T>,
    },
}

/// Exact retained-terminal reconciliation result. `InProgress` is distinct
/// from `NotCurrent`: callers must not mutate or restart the durable run while
/// another owner is reconciling that same terminal generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TerminalReconciliationOutcome<T> {
    Reconciled(T),
    InProgress,
    NotCurrent,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum JobManagerError {
    #[error("invalid {field}")]
    InvalidIdentity { field: &'static str },
    #[error("job must contain at least one unique engine")]
    InvalidEngineSet,
    #[error("a live job already exists for {0:?}")]
    DuplicateLiveJob(JobKey),
    #[error("the prior terminal job is still waiting for durable reconciliation for {0:?}")]
    TerminalReconciliationPending(JobKey),
    #[error("no live job exists for {0:?}")]
    LiveJobNotFound(JobKey),
    #[error("job cancellation is already pending for {0:?}")]
    CancellationPending(JobKey),
    #[error("engine {engine_id} is not registered in job {key:?}")]
    EngineNotFound { key: JobKey, engine_id: String },
    #[error("engine {engine_id} in job {key:?} is already terminal")]
    EngineAlreadyTerminal { key: JobKey, engine_id: String },
    #[error("scan worker thread could not be started")]
    ThreadSpawnFailed,
}

#[derive(Clone, Default)]
pub struct JobManager {
    inner: Arc<ManagerInner>,
}

impl fmt::Debug for JobManager {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = lock(&self.inner.state);
        formatter
            .debug_struct("JobManager")
            .field("live_jobs", &state.live.len())
            .field("terminal_jobs", &state.terminal.len())
            .finish()
    }
}

impl JobManager {
    /// Serializes the short durable-plan + worker-admission boundary. This is
    /// deliberately separate from worker execution: the lock is released as
    /// soon as a job is registered, so unrelated scans never wait for target
    /// work or runtime preparation.
    pub fn coordinate_admission<T>(&self, admit: impl FnOnce() -> T) -> T {
        let _admission = lock(&self.inner.admission);
        admit()
    }

    /// Starts one owned worker on a dedicated thread. The callback is invoked
    /// after the live entry has been atomically replaced by its terminal
    /// snapshot. The exact terminal generation must be durably reconciled
    /// before the same key can start again.
    pub fn start_job<W, C, I, S>(
        &self,
        key: JobKey,
        engine_ids: I,
        worker: W,
        on_terminal: C,
    ) -> Result<JobSnapshot, JobManagerError>
    where
        W: FnOnce(JobContext) -> JobCompletion + Send + 'static,
        C: FnOnce(JobSnapshot) + Send + 'static,
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        validate_identity(&key.case_id, "case id")?;
        validate_identity(&key.scan_run_id, "scan run id")?;
        let engines = build_engine_records(engine_ids)?;

        let record = {
            let mut state = lock(&self.inner.state);
            if state.live.contains_key(&key) {
                return Err(JobManagerError::DuplicateLiveJob(key));
            }
            if state.terminal.contains_key(&key) {
                return Err(JobManagerError::TerminalReconciliationPending(key));
            }
            state.next_generation = state.next_generation.wrapping_add(1).max(1);
            let record = Arc::new(JobRecord::new(key.clone(), state.next_generation, engines));
            state.live.insert(key.clone(), Arc::clone(&record));
            record
        };

        let initial = record.snapshot();
        let manager = self.clone();
        let thread_record = Arc::clone(&record);
        let thread_name = format!("assessment-job-{}", record.generation);
        let spawn = thread::Builder::new().name(thread_name).spawn(move || {
            thread_record.mark_running();
            let context = JobContext {
                record: Arc::clone(&thread_record),
            };
            let outcome = panic::catch_unwind(AssertUnwindSafe(|| worker(context)));
            let (completion, forced_failure) = match outcome {
                Ok(completion) => (completion, None),
                Err(_) => (JobCompletion::Failed, Some(JobFailureKind::WorkerPanicked)),
            };
            let terminal = manager.finalize_job(&thread_record, completion, forced_failure);
            let _ = panic::catch_unwind(AssertUnwindSafe(|| on_terminal(terminal)));
        });

        if spawn.is_err() {
            let mut state = lock(&self.inner.state);
            if state
                .live
                .get(&key)
                .is_some_and(|candidate| candidate.generation == record.generation)
            {
                state.live.remove(&key);
            }
            return Err(JobManagerError::ThreadSpawnFailed);
        }

        Ok(initial)
    }

    pub fn snapshot(&self, key: &JobKey) -> Option<JobSnapshot> {
        let state = lock(&self.inner.state);
        state
            .live
            .get(key)
            .map(|record| record.snapshot())
            .or_else(|| state.terminal.get(key).cloned())
    }

    pub fn live_snapshots(&self) -> Vec<JobSnapshot> {
        let state = lock(&self.inner.state);
        let mut snapshots = state
            .live
            .values()
            .map(|record| record.snapshot())
            .collect::<Vec<_>>();
        snapshots.sort_by(|left, right| {
            (&left.key.case_id, &left.key.scan_run_id)
                .cmp(&(&right.key.case_id, &right.key.scan_run_id))
        });
        snapshots
    }

    /// Returns retained terminal outcomes that callers may need to reconcile
    /// into their durable store. A terminal callback is best-effort, so the
    /// manager retains each small, closure-free snapshot until the persistence
    /// owner confirms the exact job can be forgotten. Undurable truth is never
    /// evicted merely because other jobs finished.
    pub fn terminal_snapshots(&self) -> Vec<JobSnapshot> {
        let state = lock(&self.inner.state);
        let mut snapshots = state.terminal.values().cloned().collect::<Vec<_>>();
        snapshots.sort_by(|left, right| {
            (&left.key.case_id, &left.key.scan_run_id)
                .cmp(&(&right.key.case_id, &right.key.scan_run_id))
        });
        snapshots
    }

    pub fn live_count(&self) -> usize {
        lock(&self.inner.state).live.len()
    }

    pub fn pause(&self, key: &JobKey) -> Result<JobSnapshot, JobManagerError> {
        self.pause_transition(key).map(|(snapshot, _)| snapshot)
    }

    /// Signals a pause and reports whether this call changed the live worker.
    /// Callers may compensate a failed durable mutation only when `changed` is
    /// true; duplicate requests must never reverse an earlier transition.
    pub fn pause_transition(&self, key: &JobKey) -> Result<(JobSnapshot, bool), JobManagerError> {
        let record = self.live_record(key)?;
        let _control = lock(&record.control_transition);
        self.require_current_live_record(key, &record)?;
        if record.cancel_requested.load(Ordering::SeqCst) {
            return Err(JobManagerError::CancellationPending(key.clone()));
        }
        let changed = record.request_pause();
        Ok((record.snapshot(), changed))
    }

    pub fn resume(&self, key: &JobKey) -> Result<JobSnapshot, JobManagerError> {
        self.resume_transition(key).map(|(snapshot, _)| snapshot)
    }

    /// Signals a resume and reports whether this call cleared a prior pause.
    pub fn resume_transition(&self, key: &JobKey) -> Result<(JobSnapshot, bool), JobManagerError> {
        let record = self.live_record(key)?;
        let _control = lock(&record.control_transition);
        self.require_current_live_record(key, &record)?;
        if record.cancel_requested.load(Ordering::SeqCst) {
            return Err(JobManagerError::CancellationPending(key.clone()));
        }
        let changed = record.request_resume();
        Ok((record.snapshot(), changed))
    }

    /// Serializes the live-worker pause signal, durable case mutation, and
    /// compensation for one exact job. The inner result belongs to the caller's
    /// persistence layer; manager/lifecycle errors remain the outer result.
    pub fn pause_with_durable_transition<T, E, F>(
        &self,
        key: &JobKey,
        durable: F,
    ) -> Result<Result<T, E>, JobManagerError>
    where
        F: FnOnce() -> Result<T, E>,
    {
        let record = self.live_record(key)?;
        let _control = lock(&record.control_transition);
        self.require_current_live_record(key, &record)?;
        if record.cancel_requested.load(Ordering::SeqCst) {
            return Err(JobManagerError::CancellationPending(key.clone()));
        }
        let changed = record.request_pause();
        let result = durable();
        if result.is_err() && changed {
            record.request_resume();
        }
        Ok(result)
    }

    /// Resume counterpart to [`Self::pause_with_durable_transition`].
    pub fn resume_with_durable_transition<T, E, F>(
        &self,
        key: &JobKey,
        durable: F,
    ) -> Result<Result<T, E>, JobManagerError>
    where
        F: FnOnce() -> Result<T, E>,
    {
        let record = self.live_record(key)?;
        let _control = lock(&record.control_transition);
        self.require_current_live_record(key, &record)?;
        if record.cancel_requested.load(Ordering::SeqCst) {
            return Err(JobManagerError::CancellationPending(key.clone()));
        }
        let changed = record.request_resume();
        let result = durable();
        if result.is_err() && changed {
            record.request_pause();
        }
        Ok(result)
    }

    pub fn cancel(&self, key: &JobKey) -> Result<JobSnapshot, JobManagerError> {
        let record = self.live_record(key)?;
        // Publish intent before waiting on a preflight/activation transition.
        // The worker can therefore observe a cancel invocation that began
        // while its reversible closure was still in progress and must not
        // contact a target afterward.
        record.publish_cancel_intent();
        let _control = lock(&record.control_transition);
        match self.require_current_live_record(key, &record) {
            Ok(()) => Ok(record.snapshot()),
            Err(error) => {
                // The worker may observe the published intent, finalize as
                // cancelled, and remove the live entry before this caller gets
                // the coordinator. That is a successful cancellation, not a
                // missing-job error.
                let snapshot = record.snapshot();
                if snapshot.status == JobStatus::Cancelled {
                    Ok(snapshot)
                } else {
                    Err(error)
                }
            }
        }
    }

    /// Publishes cancellation immediately, then performs one short durable
    /// cancel-request write under the same exact per-job coordinator used by
    /// worker dispatch and terminal persistence. The durable closure must not
    /// perform target work or wait on a scanner/connector.
    ///
    /// A worker that already committed its durable result and marked every
    /// engine terminal wins permanently. In that case the just-published
    /// intent is retracted before finalization and the caller receives the
    /// exact terminal snapshot without invoking `durable`.
    pub fn cancel_with_durable_transition<T, E, F>(
        &self,
        key: &JobKey,
        durable: F,
    ) -> Result<Result<DurableCancellationOutcome<T>, E>, JobManagerError>
    where
        F: FnOnce() -> Result<DurableCancellationWrite<T>, E>,
    {
        let record = self.live_record(key)?;
        record.publish_cancel_intent();
        let _control = lock(&record.control_transition);
        if let Err(error) = self.require_current_live_record(key, &record) {
            let snapshot = record.snapshot();
            return if snapshot.is_terminal() {
                Ok(Ok(DurableCancellationOutcome::TerminalWon {
                    snapshot,
                    durable: None,
                }))
            } else {
                Err(error)
            };
        }
        if record.all_engines_terminal() {
            record.retract_cancel_intent_after_terminal();
            return Ok(Ok(DurableCancellationOutcome::TerminalWon {
                snapshot: record.snapshot(),
                durable: None,
            }));
        }
        Ok(durable().map(|write| match write {
            DurableCancellationWrite::Requested(durable) => DurableCancellationOutcome::Requested {
                snapshot: record.snapshot(),
                durable,
            },
            DurableCancellationWrite::TerminalWon(durable) => {
                // CancellationToken is deliberately one-way. Record this
                // exceptional durable-truth precedence so the lagging worker
                // and finalizer preserve the terminal payload rather than
                // projecting the already-published control signal over it.
                record.mark_durable_terminal_truth_won();
                DurableCancellationOutcome::TerminalWon {
                    snapshot: record.snapshot(),
                    durable: Some(durable),
                }
            }
        }))
    }

    fn live_record(&self, key: &JobKey) -> Result<Arc<JobRecord>, JobManagerError> {
        lock(&self.inner.state)
            .live
            .get(key)
            .cloned()
            .ok_or_else(|| JobManagerError::LiveJobNotFound(key.clone()))
    }

    fn require_current_live_record(
        &self,
        key: &JobKey,
        record: &Arc<JobRecord>,
    ) -> Result<(), JobManagerError> {
        if lock(&self.inner.state)
            .live
            .get(key)
            .is_some_and(|current| current.generation == record.generation)
        {
            Ok(())
        } else {
            Err(JobManagerError::LiveJobNotFound(key.clone()))
        }
    }

    /// Runs one persistence acknowledgement only while this exact retained
    /// generation is still current. The exact generation is claimed under the
    /// manager lock, but the caller's persistence/reconciliation closure runs
    /// after that lock is released. The retained terminal entry continues to
    /// refuse same-key restarts while unrelated jobs remain responsive.
    pub fn reconcile_terminal_snapshot<T, E>(
        &self,
        acknowledged: &JobSnapshot,
        reconcile: impl FnOnce() -> Result<T, E>,
    ) -> Result<TerminalReconciliationOutcome<T>, E> {
        let claim = match self.claim_terminal_reconciliation(acknowledged) {
            TerminalReconciliationClaimOutcome::Claimed(claim) => claim,
            TerminalReconciliationClaimOutcome::InProgress => {
                return Ok(TerminalReconciliationOutcome::InProgress);
            }
            TerminalReconciliationClaimOutcome::NotCurrent => {
                return Ok(TerminalReconciliationOutcome::NotCurrent);
            }
        };
        let reconciled = reconcile()?;
        if claim.acknowledge() {
            Ok(TerminalReconciliationOutcome::Reconciled(reconciled))
        } else {
            Ok(TerminalReconciliationOutcome::NotCurrent)
        }
    }

    fn claim_terminal_reconciliation(
        &self,
        acknowledged: &JobSnapshot,
    ) -> TerminalReconciliationClaimOutcome {
        let mut state = lock(&self.inner.state);
        if !state
            .terminal
            .get(&acknowledged.key)
            .is_some_and(|snapshot| snapshot.generation == acknowledged.generation)
        {
            return TerminalReconciliationClaimOutcome::NotCurrent;
        }
        if state
            .terminal_reconciliation_claims
            .get(&acknowledged.key)
            .is_some_and(|generation| *generation == acknowledged.generation)
        {
            return TerminalReconciliationClaimOutcome::InProgress;
        }
        if state
            .terminal_reconciliation_claims
            .contains_key(&acknowledged.key)
        {
            // A different claimed generation cannot normally coexist with the
            // exact retained snapshot, but conservatively refuse mutation if
            // process-local state was externally corrupted.
            return TerminalReconciliationClaimOutcome::InProgress;
        }
        state
            .terminal_reconciliation_claims
            .insert(acknowledged.key.clone(), acknowledged.generation);
        TerminalReconciliationClaimOutcome::Claimed(TerminalReconciliationClaim {
            inner: Arc::clone(&self.inner),
            key: acknowledged.key.clone(),
            generation: acknowledged.generation,
            active: true,
        })
    }

    fn finalize_job(
        &self,
        record: &Arc<JobRecord>,
        completion: JobCompletion,
        forced_failure: Option<JobFailureKind>,
    ) -> JobSnapshot {
        let _control = lock(&record.control_transition);
        let mut state = lock(&self.inner.state);
        let still_current = state
            .live
            .get(&record.key)
            .is_some_and(|candidate| candidate.generation == record.generation);
        if !still_current {
            return record.snapshot();
        }
        let terminal = record.finalize(completion, forced_failure);
        state.live.remove(&record.key);
        state.terminal.insert(record.key.clone(), terminal.clone());
        terminal
    }
}

#[derive(Clone)]
pub struct JobContext {
    record: Arc<JobRecord>,
}

impl fmt::Debug for JobContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("JobContext")
            .field("key", &self.record.key)
            .field("engine_ids", &self.engine_ids())
            .field("cancelled", &self.is_cancelled())
            .field("pause_requested", &self.is_pause_requested())
            .finish()
    }
}

impl JobContext {
    pub fn key(&self) -> &JobKey {
        &self.record.key
    }

    pub fn engine_ids(&self) -> Vec<String> {
        self.record.engines.keys().cloned().collect()
    }

    /// Runs one durable worker-state write under the same per-job coordinator
    /// used by pause, resume, cancellation, and terminalization. This prevents
    /// a worker checkpoint/final report from racing the case revision changed
    /// by a control request.
    pub fn coordinate_durable_write<T>(&self, write: impl FnOnce() -> T) -> T {
        let _control = lock(&self.record.control_transition);
        write()
    }

    /// Cancellation-aware counterpart for reversible before-dispatch writes.
    /// A cancellation published before entry skips the write. If cancellation
    /// is published while the closure is in progress, the caller receives
    /// `Cancelled` and must apply its narrowly scoped compensation before any
    /// target contact or failure projection is exposed.
    pub fn coordinate_durable_write_if_not_cancelled<T, E>(
        &self,
        write: impl FnOnce() -> Result<T, E>,
    ) -> JobActivationOutcome<T, E> {
        if self.record.cancel_requested.load(Ordering::SeqCst) {
            return JobActivationOutcome::Cancelled;
        }
        let _control = lock(&self.record.control_transition);
        if self.record.cancel_requested.load(Ordering::SeqCst) {
            return JobActivationOutcome::Cancelled;
        }
        let result = write();
        if self.record.cancel_requested.load(Ordering::SeqCst) {
            return JobActivationOutcome::Cancelled;
        }
        match result {
            Ok(value) => JobActivationOutcome::Activated(value),
            Err(error) => JobActivationOutcome::Failed(error),
        }
    }

    /// Runs the worker's one-time dispatch activation under the same
    /// coordinator used by pause, resume, cancellation, and durable writes. A
    /// pause delays activation without invoking `activate`; cancellation wins
    /// without invoking it. Once activation begins, a concurrent control
    /// request waits until the closure has completed.
    pub fn activate_with_transition<T, E, F>(&self, activate: F) -> JobActivationOutcome<T, E>
    where
        F: FnOnce() -> Result<T, E>,
    {
        let mut activate = Some(activate);
        loop {
            if !self.record.wait_until_runnable() {
                return JobActivationOutcome::Cancelled;
            }

            let _control = lock(&self.record.control_transition);
            if self.record.cancel_requested.load(Ordering::SeqCst) {
                return JobActivationOutcome::Cancelled;
            }
            if self.record.pause_requested.load(Ordering::SeqCst) {
                continue;
            }

            let activate = activate
                .take()
                .expect("job activation closure is consumed exactly once");
            let result = activate();
            // Once a successful activation closure returns, its irreversible
            // work belongs to a durable dispatch-authorized attempt. A cancel
            // published during the closure is observed by the engine token
            // before target contact; discarding the successful value here can
            // leak committed provider checkout capacity without an owner.
            return match result {
                Ok(value) => JobActivationOutcome::Activated(value),
                Err(error) => JobActivationOutcome::Failed(error),
            };
        }
    }

    pub fn engine(&self, engine_id: &str) -> Result<EngineJobControl, JobManagerError> {
        self.record
            .engines
            .get(engine_id)
            .cloned()
            .map(|record| EngineJobControl {
                key: self.record.key.clone(),
                record,
            })
            .ok_or_else(|| JobManagerError::EngineNotFound {
                key: self.record.key.clone(),
                engine_id: engine_id.to_owned(),
            })
    }

    pub fn is_cancelled(&self) -> bool {
        self.record.cancel_requested.load(Ordering::SeqCst)
    }

    /// True only for the corruption/recovery edge where durable terminal data
    /// was found after a one-way cancel token was published but before the
    /// lagging in-memory JobControl reached terminal. Workers must preserve the
    /// durable payload in this state.
    pub fn durable_terminal_truth_won(&self) -> bool {
        self.record
            .durable_terminal_truth_won
            .load(Ordering::SeqCst)
    }

    pub fn is_pause_requested(&self) -> bool {
        self.record.pause_requested.load(Ordering::SeqCst)
    }

    /// Blocks dispatch between engines while a pause is requested. Returns
    /// `false` if cancellation won the race, allowing the worker to stop before
    /// starting another engine.
    pub fn wait_until_runnable(&self) -> bool {
        self.record.wait_until_runnable()
    }
}

#[derive(Clone)]
pub struct EngineJobControl {
    key: JobKey,
    record: Arc<EngineRecord>,
}

impl fmt::Debug for EngineJobControl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EngineJobControl")
            .field("key", &self.key)
            .field("engine_id", &self.record.engine_id)
            .field("status", &self.record.snapshot_status())
            .finish()
    }
}

impl EngineJobControl {
    pub fn engine_id(&self) -> &str {
        &self.record.engine_id
    }

    pub fn cancellation_token(&self) -> CancellationToken {
        self.record.token.clone()
    }

    pub fn status(&self) -> EngineJobStatus {
        self.record.snapshot_status()
    }

    pub fn mark_running(&self) -> Result<(), JobManagerError> {
        self.record.transition_running(&self.key)
    }

    pub fn mark_completed(&self) -> Result<(), JobManagerError> {
        self.record
            .transition_terminal(&self.key, BaseEngineStatus::Completed)
    }

    pub fn mark_cancelled(&self) -> Result<(), JobManagerError> {
        self.record
            .transition_terminal(&self.key, BaseEngineStatus::Cancelled)
    }

    pub fn mark_failed(&self) -> Result<(), JobManagerError> {
        self.record
            .transition_terminal(&self.key, BaseEngineStatus::Failed)
    }
}

#[derive(Default)]
struct ManagerInner {
    state: Mutex<ManagerState>,
    admission: Mutex<()>,
}

#[derive(Default)]
struct ManagerState {
    live: HashMap<JobKey, Arc<JobRecord>>,
    terminal: HashMap<JobKey, JobSnapshot>,
    terminal_reconciliation_claims: HashMap<JobKey, u64>,
    next_generation: u64,
}

/// Process-local lease for one retained terminal generation. Dropping the
/// lease after an error or panic releases only the matching claim and leaves
/// the terminal snapshot available for a later retry.
struct TerminalReconciliationClaim {
    inner: Arc<ManagerInner>,
    key: JobKey,
    generation: u64,
    active: bool,
}

enum TerminalReconciliationClaimOutcome {
    Claimed(TerminalReconciliationClaim),
    InProgress,
    NotCurrent,
}

impl TerminalReconciliationClaim {
    fn acknowledge(mut self) -> bool {
        let mut state = lock(&self.inner.state);
        let claim_is_current = state
            .terminal_reconciliation_claims
            .get(&self.key)
            .is_some_and(|generation| *generation == self.generation);
        if !claim_is_current {
            self.active = false;
            return false;
        }
        state.terminal_reconciliation_claims.remove(&self.key);
        let terminal_is_current = state
            .terminal
            .get(&self.key)
            .is_some_and(|snapshot| snapshot.generation == self.generation);
        if terminal_is_current {
            state.terminal.remove(&self.key);
        }
        self.active = false;
        terminal_is_current
    }
}

impl Drop for TerminalReconciliationClaim {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        let mut state = lock(&self.inner.state);
        if state
            .terminal_reconciliation_claims
            .get(&self.key)
            .is_some_and(|generation| *generation == self.generation)
        {
            state.terminal_reconciliation_claims.remove(&self.key);
        }
    }
}

struct JobRecord {
    key: JobKey,
    generation: u64,
    phase: Mutex<RecordPhase>,
    engines: BTreeMap<String, Arc<EngineRecord>>,
    pause_requested: AtomicBool,
    cancel_requested: AtomicBool,
    durable_terminal_truth_won: AtomicBool,
    control_transition: Mutex<()>,
    gate: Mutex<()>,
    gate_changed: Condvar,
}

impl JobRecord {
    fn new(key: JobKey, generation: u64, engines: BTreeMap<String, Arc<EngineRecord>>) -> Self {
        Self {
            key,
            generation,
            phase: Mutex::new(RecordPhase::Starting),
            engines,
            pause_requested: AtomicBool::new(false),
            cancel_requested: AtomicBool::new(false),
            durable_terminal_truth_won: AtomicBool::new(false),
            control_transition: Mutex::new(()),
            gate: Mutex::new(()),
            gate_changed: Condvar::new(),
        }
    }

    fn mark_running(&self) {
        let mut phase = lock(&self.phase);
        if matches!(*phase, RecordPhase::Starting) {
            *phase = RecordPhase::Running;
        }
    }

    fn request_pause(&self) -> bool {
        let _gate = lock(&self.gate);
        if self.cancel_requested.load(Ordering::SeqCst) {
            return false;
        }
        if self.pause_requested.swap(true, Ordering::SeqCst) {
            return false;
        }
        for engine in self.engines.values() {
            if !engine.base_status().is_terminal() {
                engine.token.request_pause();
            }
        }
        true
    }

    fn request_resume(&self) -> bool {
        let _gate = lock(&self.gate);
        if !self.pause_requested.swap(false, Ordering::SeqCst) {
            return false;
        }
        for engine in self.engines.values() {
            if !engine.base_status().is_terminal() {
                engine.token.resume();
            }
        }
        self.gate_changed.notify_all();
        true
    }

    fn publish_cancel_intent(&self) {
        self.cancel_requested.store(true, Ordering::SeqCst);
        let _gate = lock(&self.gate);
        for engine in self.engines.values() {
            if !engine.base_status().is_terminal() {
                engine.token.cancel();
            }
        }
        self.gate_changed.notify_all();
    }

    fn all_engines_terminal(&self) -> bool {
        self.engines
            .values()
            .all(|engine| engine.base_status().is_terminal())
    }

    fn retract_cancel_intent_after_terminal(&self) {
        debug_assert!(self.all_engines_terminal());
        self.cancel_requested.store(false, Ordering::SeqCst);
    }

    fn mark_durable_terminal_truth_won(&self) {
        self.durable_terminal_truth_won
            .store(true, Ordering::SeqCst);
    }

    fn wait_until_runnable(&self) -> bool {
        let mut guard = lock(&self.gate);
        while self.pause_requested.load(Ordering::SeqCst)
            && !self.cancel_requested.load(Ordering::SeqCst)
        {
            guard = self
                .gate_changed
                .wait(guard)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
        }
        !self.cancel_requested.load(Ordering::SeqCst)
    }

    fn snapshot(&self) -> JobSnapshot {
        let phase = *lock(&self.phase);
        let engines = self
            .engines
            .values()
            .map(|engine| EngineJobSnapshot {
                engine_id: engine.engine_id.clone(),
                status: engine.snapshot_status(),
            })
            .collect::<Vec<_>>();
        let (status, failure_kind) = match phase {
            RecordPhase::Terminal {
                status,
                failure_kind,
            } => (status, failure_kind),
            RecordPhase::Starting if self.cancel_requested.load(Ordering::SeqCst) => {
                (JobStatus::CancelRequested, None)
            }
            RecordPhase::Starting if self.pause_requested.load(Ordering::SeqCst) => {
                (JobStatus::Paused, None)
            }
            RecordPhase::Starting => (JobStatus::Starting, None),
            RecordPhase::Running if self.cancel_requested.load(Ordering::SeqCst) => {
                (JobStatus::CancelRequested, None)
            }
            RecordPhase::Running if self.pause_requested.load(Ordering::SeqCst) => {
                let running = self
                    .engines
                    .values()
                    .filter(|engine| engine.base_status() == BaseEngineStatus::Running)
                    .collect::<Vec<_>>();
                if running.iter().all(|engine| engine.token.is_paused()) {
                    (JobStatus::Paused, None)
                } else {
                    (JobStatus::PauseRequested, None)
                }
            }
            RecordPhase::Running
                if self.engines.values().any(|engine| {
                    engine.base_status() == BaseEngineStatus::Running && engine.token.is_paused()
                }) =>
            {
                (JobStatus::ResumeRequested, None)
            }
            RecordPhase::Running => (JobStatus::Running, None),
        };
        JobSnapshot {
            key: self.key.clone(),
            status,
            engines,
            failure_kind,
            generation: self.generation,
        }
    }

    fn finalize(
        &self,
        completion: JobCompletion,
        forced_failure: Option<JobFailureKind>,
    ) -> JobSnapshot {
        let cancel_won = self.cancel_requested.load(Ordering::SeqCst)
            && !self.durable_terminal_truth_won.load(Ordering::SeqCst);
        let persistence_pending = completion == JobCompletion::PersistencePending;
        let completion = if cancel_won && !persistence_pending {
            JobCompletion::Cancelled
        } else {
            completion
        };
        let mut failure_kind = if persistence_pending {
            Some(JobFailureKind::PersistencePending)
        } else if cancel_won {
            None
        } else {
            forced_failure
        };
        match completion {
            JobCompletion::Completed => {
                let incomplete = self
                    .engines
                    .values()
                    .filter(|engine| !engine.base_status().is_terminal())
                    .collect::<Vec<_>>();
                if !incomplete.is_empty() {
                    failure_kind.get_or_insert(JobFailureKind::WorkerReturnedEarly);
                    for engine in incomplete {
                        engine.force_terminal(BaseEngineStatus::Failed);
                    }
                }
            }
            JobCompletion::Cancelled => {
                for engine in self.engines.values() {
                    if !engine.base_status().is_terminal() {
                        engine.force_terminal(BaseEngineStatus::Cancelled);
                    }
                }
            }
            JobCompletion::Failed => {
                failure_kind.get_or_insert(JobFailureKind::WorkerReported);
                for engine in self.engines.values() {
                    if !engine.base_status().is_terminal() {
                        engine.force_terminal(BaseEngineStatus::Failed);
                    }
                }
            }
            JobCompletion::PersistencePending => {
                for engine in self.engines.values() {
                    if !engine.base_status().is_terminal() {
                        engine.force_terminal(BaseEngineStatus::Failed);
                    }
                }
            }
        }

        let statuses = self
            .engines
            .values()
            .map(|engine| engine.base_status())
            .collect::<Vec<_>>();
        let status = if failure_kind.is_some() || statuses.contains(&BaseEngineStatus::Failed) {
            failure_kind.get_or_insert(JobFailureKind::WorkerReported);
            JobStatus::Failed
        } else if statuses.contains(&BaseEngineStatus::Cancelled) {
            JobStatus::Cancelled
        } else {
            JobStatus::Completed
        };
        *lock(&self.phase) = RecordPhase::Terminal {
            status,
            failure_kind,
        };
        self.pause_requested.store(false, Ordering::SeqCst);
        self.gate_changed.notify_all();
        self.snapshot()
    }
}

#[derive(Clone, Copy)]
enum RecordPhase {
    Starting,
    Running,
    Terminal {
        status: JobStatus,
        failure_kind: Option<JobFailureKind>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BaseEngineStatus {
    Queued,
    Running,
    Completed,
    Cancelled,
    Failed,
}

impl BaseEngineStatus {
    fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Cancelled | Self::Failed)
    }
}

struct EngineRecord {
    engine_id: String,
    status: Mutex<BaseEngineStatus>,
    token: CancellationToken,
}

impl EngineRecord {
    fn base_status(&self) -> BaseEngineStatus {
        *lock(&self.status)
    }

    fn snapshot_status(&self) -> EngineJobStatus {
        let base = self.base_status();
        match base {
            BaseEngineStatus::Completed => EngineJobStatus::Completed,
            BaseEngineStatus::Cancelled => EngineJobStatus::Cancelled,
            BaseEngineStatus::Failed => EngineJobStatus::Failed,
            _ if self.token.is_cancelled() => EngineJobStatus::CancelRequested,
            _ if self.token.is_paused() && self.token.is_pause_requested() => {
                EngineJobStatus::Paused
            }
            _ if self.token.is_paused() => EngineJobStatus::ResumeRequested,
            _ if self.token.is_pause_requested() => EngineJobStatus::PauseRequested,
            BaseEngineStatus::Queued => EngineJobStatus::Queued,
            BaseEngineStatus::Running => EngineJobStatus::Running,
        }
    }

    fn transition_running(&self, key: &JobKey) -> Result<(), JobManagerError> {
        let mut status = lock(&self.status);
        match *status {
            BaseEngineStatus::Queued => {
                *status = BaseEngineStatus::Running;
                Ok(())
            }
            BaseEngineStatus::Running => Ok(()),
            BaseEngineStatus::Completed
            | BaseEngineStatus::Cancelled
            | BaseEngineStatus::Failed => Err(JobManagerError::EngineAlreadyTerminal {
                key: key.clone(),
                engine_id: self.engine_id.clone(),
            }),
        }
    }

    fn transition_terminal(
        &self,
        key: &JobKey,
        next: BaseEngineStatus,
    ) -> Result<(), JobManagerError> {
        debug_assert!(next.is_terminal());
        let mut status = lock(&self.status);
        if status.is_terminal() {
            return Err(JobManagerError::EngineAlreadyTerminal {
                key: key.clone(),
                engine_id: self.engine_id.clone(),
            });
        }
        *status = next;
        Ok(())
    }

    fn force_terminal(&self, next: BaseEngineStatus) {
        debug_assert!(next.is_terminal());
        *lock(&self.status) = next;
    }
}

fn build_engine_records<I, S>(
    engine_ids: I,
) -> Result<BTreeMap<String, Arc<EngineRecord>>, JobManagerError>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let mut records = BTreeMap::new();
    for raw in engine_ids {
        let engine_id = raw.into();
        validate_identity(&engine_id, "engine id")?;
        let record = Arc::new(EngineRecord {
            engine_id: engine_id.clone(),
            status: Mutex::new(BaseEngineStatus::Queued),
            token: CancellationToken::default(),
        });
        if records.insert(engine_id, record).is_some() {
            return Err(JobManagerError::InvalidEngineSet);
        }
    }
    if records.is_empty() {
        return Err(JobManagerError::InvalidEngineSet);
    }
    Ok(records)
}

fn validate_identity(value: &str, field: &'static str) -> Result<(), JobManagerError> {
    if value.is_empty()
        || value.len() > 256
        || value.trim() != value
        || value.contains(['\0', '\n', '\r'])
    {
        return Err(JobManagerError::InvalidIdentity { field });
    }
    Ok(())
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}
