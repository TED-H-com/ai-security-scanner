use crate::domain::RuntimeHealth;
#[cfg(any(feature = "desktop", test))]
use crate::managed_runtime::{ManagedRuntimePhase, ManagedRuntimeStatus};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

/// Live provider checks may each consume a bounded OS-command deadline and
/// hold the provider lifecycle lock. A five-minute observation is fresh
/// enough for shell copy; execution still performs its own authoritative
/// preparation. Lifecycle transitions explicitly invalidate this cache.
const RUNTIME_HEALTH_FRESHNESS: Duration = Duration::from_secs(5 * 60);

/// Upper bound on how long consecutive `Reconciling` readings delay the next
/// probe.
const RUNTIME_HEALTH_RECONCILING_RETRY_CAP: Duration = Duration::from_secs(60);

/// Delay before the next probe is allowed to start, given `consecutive`
/// consecutive accepted `Reconciling` readings (counting from 1). The first
/// reading never delays; from the second reading on, the delay doubles each
/// time and is capped at `RUNTIME_HEALTH_RECONCILING_RETRY_CAP`. The exponent
/// is capped before shifting so this never overflows, for any `u32`.
fn reconciling_retry_delay(consecutive: u32) -> Duration {
    if consecutive < 2 {
        return Duration::ZERO;
    }
    let exponent = (consecutive - 2).min(6);
    Duration::from_secs(1u64 << exponent).min(RUNTIME_HEALTH_RECONCILING_RETRY_CAP)
}

pub enum RuntimeHealthObservation {
    /// A completed check whose answer will not change until a lifecycle event
    /// changes it. Starts a fresh freshness window.
    Settled(RuntimeHealth),
    /// The provider is mid-transition, or could not be queried inside the
    /// bounded status budget. The reading is publishable copy.
    ///
    /// The first reading does not delay the next probe. Consecutive readings
    /// back off up to a minute, so a condition that never resolves, such as a
    /// persistent status error, cannot keep a detector running continuously.
    /// A settled reading or any lifecycle event resets the backoff.
    Reconciling(RuntimeHealth),
}

#[cfg(any(feature = "desktop", test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuntimeHealthConfidence {
    Settled,
    Reconciling,
}

#[cfg(any(feature = "desktop", test))]
impl RuntimeHealthConfidence {
    fn observe(self, health: RuntimeHealth) -> RuntimeHealthObservation {
        match self {
            Self::Settled => RuntimeHealthObservation::Settled(health),
            Self::Reconciling => RuntimeHealthObservation::Reconciling(health),
        }
    }
}

#[cfg(any(feature = "desktop", test))]
fn managed_runtime_health_confidence(phase: ManagedRuntimePhase) -> RuntimeHealthConfidence {
    match phase {
        ManagedRuntimePhase::Running
        | ManagedRuntimePhase::NotInstalled
        | ManagedRuntimePhase::Installed
        | ManagedRuntimePhase::Stopped
        | ManagedRuntimePhase::Corrupt
        | ManagedRuntimePhase::Unsupported => RuntimeHealthConfidence::Settled,
        ManagedRuntimePhase::Starting => RuntimeHealthConfidence::Reconciling,
    }
}

#[cfg(any(feature = "desktop", test))]
pub(crate) fn managed_runtime_health_observation(
    status: &ManagedRuntimeStatus,
) -> RuntimeHealthObservation {
    managed_runtime_health_confidence(status.phase).observe(RuntimeHealth {
        provider: status.provider.clone(),
        available: status.available,
        phase: status.phase.as_str().into(),
        version: Some(status.runtime_version.clone()),
        prerequisite: status.prerequisite.clone(),
        detail: status.detail.clone(),
    })
}

#[cfg(any(feature = "desktop", test))]
pub(crate) fn managed_runtime_health_precludes_fallback(
    observation: &RuntimeHealthObservation,
) -> bool {
    match observation {
        RuntimeHealthObservation::Settled(health) => health.available,
        RuntimeHealthObservation::Reconciling(_) => false,
    }
}

#[cfg(any(feature = "desktop", test))]
pub(crate) fn select_runtime_health(
    managed: Option<RuntimeHealthObservation>,
    compatibility: RuntimeHealthObservation,
) -> RuntimeHealthObservation {
    match managed {
        Some(observation) if managed_runtime_health_precludes_fallback(&observation) => observation,
        Some(RuntimeHealthObservation::Reconciling(managed)) => match compatibility {
            RuntimeHealthObservation::Settled(health)
            | RuntimeHealthObservation::Reconciling(health)
                if health.available =>
            {
                RuntimeHealthObservation::Reconciling(describe_reconciling_compatibility_fallback(
                    health,
                ))
            }
            _ => RuntimeHealthObservation::Reconciling(managed),
        },
        Some(RuntimeHealthObservation::Settled(_)) => {
            describe_compatibility_fallback(compatibility)
        }
        None => compatibility,
    }
}

#[cfg(any(feature = "desktop", test))]
fn describe_reconciling_compatibility_fallback(mut health: RuntimeHealth) -> RuntimeHealth {
    health.detail = format!(
        "advanced isolated runtime has not reported its state yet and is not in use; scans will run with the {} compatibility runtime",
        health.provider
    );
    health
}

#[cfg(any(feature = "desktop", test))]
fn describe_compatibility_fallback(
    observation: RuntimeHealthObservation,
) -> RuntimeHealthObservation {
    let describe = |mut health: RuntimeHealth| {
        if health.available {
            health.detail = format!(
                "advanced isolated runtime is unavailable and is not in use; scans will run with the {} compatibility runtime",
                health.provider
            );
        }
        health
    };
    match observation {
        RuntimeHealthObservation::Settled(health) => {
            RuntimeHealthObservation::Settled(describe(health))
        }
        RuntimeHealthObservation::Reconciling(health) => {
            RuntimeHealthObservation::Reconciling(describe(health))
        }
    }
}

#[cfg(any(feature = "desktop", test))]
pub(crate) fn is_available_compatibility_runtime(health: &RuntimeHealth) -> bool {
    health.available && matches!(health.provider.as_str(), "docker" | "podman")
}

#[cfg(any(feature = "desktop", test))]
pub(crate) fn select_recorded_managed_runtime_health(
    managed: RuntimeHealthObservation,
    cached: RuntimeHealth,
) -> RuntimeHealthObservation {
    if is_available_compatibility_runtime(&cached) {
        select_runtime_health(Some(managed), RuntimeHealthObservation::Settled(cached))
    } else {
        managed
    }
}

#[derive(Debug)]
struct RuntimeHealthMonitorState {
    cached: RuntimeHealth,
    refresh_active: bool,
    last_completed_at: Option<Instant>,
    lifecycle_epoch: u64,
    consecutive_reconciling: u32,
    retry_not_before: Option<Instant>,
}

/// Keeps slow provider detection off commands that only need saved app data.
///
/// Callers always receive the last completed observation immediately. At most
/// one background detector may run at a time; repeated shell/readiness reads
/// therefore cannot queue uncancelled WSL or container-service commands.
#[derive(Debug, Clone)]
pub struct RuntimeHealthMonitor {
    state: Arc<Mutex<RuntimeHealthMonitorState>>,
}

impl RuntimeHealthMonitor {
    pub fn new(initial: RuntimeHealth) -> Self {
        Self {
            state: Arc::new(Mutex::new(RuntimeHealthMonitorState {
                cached: initial,
                refresh_active: false,
                last_completed_at: None,
                lifecycle_epoch: 0,
                consecutive_reconciling: 0,
                retry_not_before: None,
            })),
        }
    }

    pub fn cached(&self) -> RuntimeHealth {
        self.lock().cached.clone()
    }

    pub fn replace_cached(&self, health: RuntimeHealth) {
        let mut state = self.lock();
        state.lifecycle_epoch = state.lifecycle_epoch.wrapping_add(1);
        state.cached = health;
        state.last_completed_at = None;
        state.consecutive_reconciling = 0;
        state.retry_not_before = None;
    }

    /// Records health produced by an actual lifecycle operation. It is more
    /// authoritative than a shell probe and starts a new freshness window.
    pub fn record_observation(&self, health: RuntimeHealth) {
        let mut state = self.lock();
        state.lifecycle_epoch = state.lifecycle_epoch.wrapping_add(1);
        state.cached = health;
        state.last_completed_at = Some(Instant::now());
        state.consecutive_reconciling = 0;
        state.retry_not_before = None;
    }

    pub fn invalidate(&self) {
        let mut state = self.lock();
        state.lifecycle_epoch = state.lifecycle_epoch.wrapping_add(1);
        state.last_completed_at = None;
        state.consecutive_reconciling = 0;
        state.retry_not_before = None;
    }

    /// Starts one best-effort refresh without making the caller wait.
    ///
    /// `false` means an exact refresh is already active, the reconciling
    /// backoff has not elapsed, or the worker could not be spawned. A
    /// detector panic leaves the previous observation unchanged and releases
    /// the slot so a later read can retry.
    pub fn request_refresh<F>(&self, detector: F) -> bool
    where
        F: FnOnce() -> RuntimeHealthObservation + Send + 'static,
    {
        let lifecycle_epoch = {
            let mut state = self.lock();
            if state.refresh_active {
                return false;
            }
            if state
                .last_completed_at
                .is_some_and(|completed| completed.elapsed() < RUNTIME_HEALTH_FRESHNESS)
            {
                return false;
            }
            if state
                .retry_not_before
                .is_some_and(|not_before| Instant::now() < not_before)
            {
                return false;
            }
            state.refresh_active = true;
            state.lifecycle_epoch
        };

        let shared = Arc::clone(&self.state);
        let spawn = std::thread::Builder::new()
            .name("runtime-health-refresh".into())
            .spawn(move || {
                let detected = catch_unwind(AssertUnwindSafe(detector));
                let mut state = lock_recovering_poison(&shared);
                if state.lifecycle_epoch == lifecycle_epoch
                    && let Ok(observation) = detected
                {
                    match observation {
                        RuntimeHealthObservation::Settled(health) => {
                            state.cached = health;
                            state.last_completed_at = Some(Instant::now());
                            state.consecutive_reconciling = 0;
                            state.retry_not_before = None;
                        }
                        RuntimeHealthObservation::Reconciling(health) => {
                            state.cached = health;
                            state.consecutive_reconciling =
                                state.consecutive_reconciling.saturating_add(1);
                            let delay = reconciling_retry_delay(state.consecutive_reconciling);
                            state.retry_not_before = if delay.is_zero() {
                                None
                            } else {
                                Some(Instant::now() + delay)
                            };
                        }
                    }
                }
                state.refresh_active = false;
            });

        if spawn.is_err() {
            self.lock().refresh_active = false;
            return false;
        }
        true
    }

    #[cfg(test)]
    fn refresh_active(&self) -> bool {
        self.lock().refresh_active
    }

    fn lock(&self) -> MutexGuard<'_, RuntimeHealthMonitorState> {
        lock_recovering_poison(&self.state)
    }
}

fn lock_recovering_poison(
    state: &Mutex<RuntimeHealthMonitorState>,
) -> MutexGuard<'_, RuntimeHealthMonitorState> {
    state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    fn runtime_health(provider: &str, available: bool, phase: &str, detail: &str) -> RuntimeHealth {
        RuntimeHealth {
            provider: provider.into(),
            available,
            phase: phase.into(),
            version: Some(format!("{provider}-version")),
            prerequisite: Some(format!("{provider}-prerequisite")),
            detail: detail.into(),
        }
    }

    fn managed_runtime_status(phase: ManagedRuntimePhase) -> ManagedRuntimeStatus {
        ManagedRuntimeStatus {
            provider: "managed_local".into(),
            phase,
            available: matches!(phase, ManagedRuntimePhase::Running),
            runtime_version: "managed-version".into(),
            manifest_sha256: "a".repeat(64),
            machine_image_sha256: None,
            operating_system: None,
            architecture: None,
            machine_provider: None,
            prerequisite: None,
            detail: phase.as_str().into(),
        }
    }

    #[test]
    fn managed_unavailable_reports_the_available_compatibility_runtime() {
        let managed = RuntimeHealthObservation::Settled(runtime_health(
            "managed_local",
            false,
            "unsupported",
            "managed runtime is unavailable",
        ));
        let compatibility = RuntimeHealthObservation::Settled(runtime_health(
            "docker",
            true,
            "running",
            "docker service is available",
        ));

        let RuntimeHealthObservation::Settled(reported) =
            select_runtime_health(Some(managed), compatibility)
        else {
            panic!("an available compatibility runtime must be a settled reading");
        };

        assert!(reported.available);
        assert_eq!(reported.provider, "docker");
        assert_ne!(reported.provider, "managed_local");
        assert!(
            reported
                .detail
                .contains("advanced isolated runtime is unavailable and is not in use")
        );
    }

    #[test]
    fn settled_available_managed_reading_wins_unchanged() {
        let managed = runtime_health(
            "managed_local",
            true,
            "running",
            "managed runtime is available",
        );
        let expected = managed.clone();
        let compatibility = RuntimeHealthObservation::Settled(runtime_health(
            "docker",
            true,
            "running",
            "docker service is available",
        ));

        let RuntimeHealthObservation::Settled(reported) = select_runtime_health(
            Some(RuntimeHealthObservation::Settled(managed)),
            compatibility,
        ) else {
            panic!("an available managed runtime must be a settled reading");
        };

        assert_eq!(reported.provider, expected.provider);
        assert_eq!(reported.available, expected.available);
        assert_eq!(reported.phase, expected.phase);
        assert_eq!(reported.version, expected.version);
        assert_eq!(reported.prerequisite, expected.prerequisite);
        assert_eq!(reported.detail, expected.detail);
    }

    #[test]
    fn managed_and_compatibility_unavailable_reports_unavailable() {
        let managed = RuntimeHealthObservation::Settled(runtime_health(
            "managed_local",
            false,
            "unsupported",
            "managed runtime is unavailable",
        ));
        let compatibility_detail = "no compatible runtime was detected";
        let compatibility = RuntimeHealthObservation::Settled(runtime_health(
            "none",
            false,
            "unavailable",
            compatibility_detail,
        ));

        let RuntimeHealthObservation::Settled(reported) =
            select_runtime_health(Some(managed), compatibility)
        else {
            panic!("two completed unavailable readings must stay settled");
        };

        assert!(!reported.available);
        assert_eq!(reported.provider, "none");
        assert_eq!(reported.phase, "unavailable");
        assert_eq!(reported.detail, compatibility_detail);
    }

    #[test]
    fn managed_starting_reports_available_compatibility_runtime_while_staying_reconciling() {
        let managed = RuntimeHealthObservation::Reconciling(runtime_health(
            "managed_local",
            false,
            "starting",
            "managed runtime is still starting",
        ));
        let compatibility = RuntimeHealthObservation::Settled(runtime_health(
            "docker",
            true,
            "running",
            "docker service is available",
        ));

        let RuntimeHealthObservation::Reconciling(reported) =
            select_runtime_health(Some(managed), compatibility)
        else {
            panic!("a starting managed runtime must remain reconciling");
        };

        assert!(reported.available);
        assert_eq!(reported.provider, "docker");
        assert_eq!(reported.phase, "running");
        assert!(
            reported
                .detail
                .contains("advanced isolated runtime has not reported its state yet")
        );
        assert!(!reported.detail.contains("failed"));
        assert!(!reported.detail.contains("unavailable"));
    }

    #[test]
    fn managed_starting_without_available_compatibility_stays_unchanged() {
        let managed_detail = "managed runtime is still starting";
        let managed = RuntimeHealthObservation::Reconciling(runtime_health(
            "managed_local",
            false,
            "starting",
            managed_detail,
        ));
        let compatibility = RuntimeHealthObservation::Settled(runtime_health(
            "none",
            false,
            "unavailable",
            "no compatible runtime was detected",
        ));

        let RuntimeHealthObservation::Reconciling(reported) =
            select_runtime_health(Some(managed), compatibility)
        else {
            panic!("a starting managed runtime must remain reconciling");
        };

        assert!(!reported.available);
        assert_eq!(reported.provider, "managed_local");
        assert_eq!(reported.phase, "starting");
        assert_eq!(reported.detail, managed_detail);
    }

    #[test]
    fn managed_status_error_reports_available_compatibility_runtime_while_staying_reconciling() {
        let managed = RuntimeHealthObservation::Reconciling(runtime_health(
            "managed_local",
            false,
            "error",
            "operation is not authorized",
        ));
        let compatibility = RuntimeHealthObservation::Settled(runtime_health(
            "podman",
            true,
            "running",
            "podman service is available",
        ));

        let RuntimeHealthObservation::Reconciling(reported) =
            select_runtime_health(Some(managed), compatibility)
        else {
            panic!("a managed status error must remain reconciling");
        };

        assert!(reported.available);
        assert_eq!(reported.provider, "podman");
        assert_eq!(reported.phase, "running");
        assert!(
            reported
                .detail
                .contains("advanced isolated runtime has not reported its state yet")
        );
        assert!(!reported.detail.contains("failed"));
        assert!(!reported.detail.contains("unavailable"));
    }

    #[test]
    fn managed_failure_recording_preserves_known_available_compatibility_runtime() {
        let managed = RuntimeHealthObservation::Settled(runtime_health(
            "managed_local",
            false,
            "unsupported",
            "managed runtime setup failed",
        ));
        let cached = runtime_health("podman", true, "running", "podman service is available");

        let RuntimeHealthObservation::Settled(recorded) =
            select_recorded_managed_runtime_health(managed, cached)
        else {
            panic!("a known available compatibility runtime must stay settled");
        };

        assert!(recorded.available);
        assert_eq!(recorded.provider, "podman");
        assert!(
            recorded
                .detail
                .contains("advanced isolated runtime is unavailable and is not in use")
        );
    }

    #[test]
    fn managed_success_recording_replaces_known_available_compatibility_runtime() {
        let managed = runtime_health(
            "managed_local",
            true,
            "running",
            "managed runtime setup completed",
        );
        let expected = managed.clone();
        let cached = runtime_health("docker", true, "running", "docker service is available");

        let RuntimeHealthObservation::Settled(recorded) = select_recorded_managed_runtime_health(
            RuntimeHealthObservation::Settled(managed),
            cached,
        ) else {
            panic!("a successful managed setup must be a settled reading");
        };

        assert_eq!(recorded.provider, expected.provider);
        assert_eq!(recorded.available, expected.available);
        assert_eq!(recorded.phase, expected.phase);
        assert_eq!(recorded.version, expected.version);
        assert_eq!(recorded.prerequisite, expected.prerequisite);
        assert_eq!(recorded.detail, expected.detail);
    }

    #[test]
    fn only_starting_managed_runtime_health_is_reconciling() {
        let expectations = [
            (
                ManagedRuntimePhase::NotInstalled,
                RuntimeHealthConfidence::Settled,
            ),
            (
                ManagedRuntimePhase::Installed,
                RuntimeHealthConfidence::Settled,
            ),
            (
                ManagedRuntimePhase::Stopped,
                RuntimeHealthConfidence::Settled,
            ),
            (
                ManagedRuntimePhase::Starting,
                RuntimeHealthConfidence::Reconciling,
            ),
            (
                ManagedRuntimePhase::Running,
                RuntimeHealthConfidence::Settled,
            ),
            (
                ManagedRuntimePhase::Corrupt,
                RuntimeHealthConfidence::Settled,
            ),
            (
                ManagedRuntimePhase::Unsupported,
                RuntimeHealthConfidence::Settled,
            ),
        ];

        for (phase, expected) in expectations {
            assert_eq!(managed_runtime_health_confidence(phase), expected);
            let observation = managed_runtime_health_observation(&managed_runtime_status(phase));
            match expected {
                RuntimeHealthConfidence::Settled => {
                    assert!(matches!(observation, RuntimeHealthObservation::Settled(_)))
                }
                RuntimeHealthConfidence::Reconciling => assert!(matches!(
                    observation,
                    RuntimeHealthObservation::Reconciling(_)
                )),
            }
        }
    }

    fn health(phase: &str, available: bool) -> RuntimeHealth {
        RuntimeHealth {
            provider: "managed_local".into(),
            available,
            phase: phase.into(),
            version: None,
            prerequisite: None,
            detail: phase.into(),
        }
    }

    fn wait_for_refresh(monitor: &RuntimeHealthMonitor) {
        let deadline = Instant::now() + Duration::from_secs(1);
        while monitor.refresh_active() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(!monitor.refresh_active(), "refresh did not settle in time");
    }

    #[test]
    fn slow_refresh_never_blocks_reads_or_queues_duplicate_detectors() {
        let monitor = RuntimeHealthMonitor::new(health("checking", false));
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();

        assert!(monitor.request_refresh(move || {
            entered_tx.send(()).expect("signal detector entry");
            release_rx.recv().expect("release detector");
            RuntimeHealthObservation::Settled(health("running", true))
        }));
        entered_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("detector started");

        assert_eq!(monitor.cached().phase, "checking");
        assert!(
            !monitor.request_refresh(|| {
                RuntimeHealthObservation::Settled(health("duplicate", false))
            })
        );

        release_tx.send(()).expect("release slow detector");
        wait_for_refresh(&monitor);
        assert_eq!(monitor.cached().phase, "running");
        assert!(monitor.cached().available);
        assert!(
            !monitor
                .request_refresh(|| RuntimeHealthObservation::Settled(health("too_soon", false))),
            "repeated shell reads inside the freshness window must not relaunch detection",
        );
    }

    #[test]
    fn panicking_detector_preserves_cache_and_allows_retry() {
        let monitor = RuntimeHealthMonitor::new(health("last_known", true));
        let (entered_tx, entered_rx) = mpsc::channel();

        assert!(monitor.request_refresh(move || {
            entered_tx.send(()).expect("signal detector entry");
            panic!("detector panic fixture")
        }));
        entered_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("detector started");
        wait_for_refresh(&monitor);

        assert_eq!(monitor.cached().phase, "last_known");
        assert!(
            monitor.request_refresh(|| {
                RuntimeHealthObservation::Settled(health("recovered", true))
            })
        );
    }

    #[test]
    fn lifecycle_observation_is_fresh_until_explicitly_invalidated() {
        let monitor = RuntimeHealthMonitor::new(health("checking", false));
        monitor.record_observation(health("running", true));

        assert!(!monitor.request_refresh(|| {
            RuntimeHealthObservation::Settled(health("unexpected", false))
        }));
        monitor.invalidate();
        assert!(
            monitor.request_refresh(|| {
                RuntimeHealthObservation::Settled(health("stopped", false))
            })
        );
    }

    #[test]
    fn lifecycle_change_rejects_an_older_probe_result() {
        let monitor = RuntimeHealthMonitor::new(health("checking", false));
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();

        assert!(monitor.request_refresh(move || {
            entered_tx.send(()).expect("signal detector entry");
            release_rx.recv().expect("release detector");
            RuntimeHealthObservation::Settled(health("stale_probe", false))
        }));
        entered_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("detector started");

        monitor.record_observation(health("setup_completed", true));
        release_tx.send(()).expect("release stale detector");
        wait_for_refresh(&monitor);

        assert_eq!(monitor.cached().phase, "setup_completed");
        assert!(monitor.cached().available);
    }

    #[test]
    fn reconciling_health_is_visible_without_delaying_the_next_check() {
        let monitor = RuntimeHealthMonitor::new(health("checking", false));

        assert!(monitor.request_refresh(|| {
            RuntimeHealthObservation::Reconciling(health("starting", false))
        }));
        wait_for_refresh(&monitor);

        assert_eq!(monitor.cached().phase, "starting");
        assert!(
            monitor
                .request_refresh(|| { RuntimeHealthObservation::Settled(health("running", true)) })
        );
        wait_for_refresh(&monitor);
    }

    #[test]
    fn settled_health_is_visible_and_remains_fresh() {
        let monitor = RuntimeHealthMonitor::new(health("checking", false));

        assert!(
            monitor
                .request_refresh(|| { RuntimeHealthObservation::Settled(health("running", true)) })
        );
        wait_for_refresh(&monitor);

        assert_eq!(monitor.cached().phase, "running");
        assert!(!monitor.request_refresh(|| {
            RuntimeHealthObservation::Settled(health("unexpected", false))
        }));
    }

    #[test]
    fn reconciling_health_preserves_the_prior_settled_freshness_record() {
        let monitor = RuntimeHealthMonitor::new(health("checking", false));
        monitor.record_observation(health("running", true));
        let settled_at = Instant::now() - RUNTIME_HEALTH_FRESHNESS;
        monitor.lock().last_completed_at = Some(settled_at);

        assert!(monitor.request_refresh(|| {
            RuntimeHealthObservation::Reconciling(health("starting", false))
        }));
        wait_for_refresh(&monitor);

        assert_eq!(monitor.cached().phase, "starting");
        assert_eq!(monitor.lock().last_completed_at, Some(settled_at));
    }

    #[test]
    fn reconciling_retry_delay_doubles_from_the_second_reading_and_caps_at_a_minute() {
        let cases: [(u32, u64); 10] = [
            (0, 0),
            (1, 0),
            (2, 1),
            (3, 2),
            (4, 4),
            (7, 32),
            (8, 60),
            (9, 60),
            (100, 60),
            (u32::MAX, 60),
        ];

        for (consecutive, expected_seconds) in cases {
            assert_eq!(
                reconciling_retry_delay(consecutive),
                Duration::from_secs(expected_seconds),
                "consecutive = {consecutive}",
            );
        }
    }

    #[test]
    fn repeated_reconciling_health_backs_off_before_the_next_check() {
        let monitor = RuntimeHealthMonitor::new(health("checking", false));

        assert!(monitor.request_refresh(|| {
            RuntimeHealthObservation::Reconciling(health("starting", false))
        }));
        wait_for_refresh(&monitor);
        {
            let state = monitor.lock();
            assert_eq!(state.consecutive_reconciling, 1);
            assert_eq!(state.retry_not_before, None);
        }

        let before_second = Instant::now();
        assert!(monitor.request_refresh(|| {
            RuntimeHealthObservation::Reconciling(health("starting", false))
        }));
        wait_for_refresh(&monitor);
        {
            let state = monitor.lock();
            assert_eq!(state.consecutive_reconciling, 2);
            let at = state
                .retry_not_before
                .expect("a second consecutive reconciling reading must set a retry delay");
            assert!(at >= before_second + Duration::from_secs(1));
        }

        monitor.lock().retry_not_before = Some(Instant::now() + Duration::from_secs(60));
        assert!(
            !monitor.request_refresh(|| -> RuntimeHealthObservation {
                panic!("a gated detector must never run")
            }),
            "a request before the retry delay elapses must be refused"
        );

        monitor.lock().retry_not_before = Some(Instant::now() - Duration::from_millis(1));
        assert!(
            monitor
                .request_refresh(|| { RuntimeHealthObservation::Settled(health("running", true)) })
        );
        wait_for_refresh(&monitor);
        assert_eq!(monitor.cached().phase, "running");
        let state = monitor.lock();
        assert_eq!(state.consecutive_reconciling, 0);
        assert_eq!(state.retry_not_before, None);
    }

    #[test]
    fn lifecycle_events_reset_the_reconciling_backoff() {
        fn seeded_monitor() -> RuntimeHealthMonitor {
            let monitor = RuntimeHealthMonitor::new(health("checking", false));
            let mut state = monitor.lock();
            state.consecutive_reconciling = 2;
            state.retry_not_before = Some(Instant::now() + Duration::from_secs(60));
            drop(state);
            monitor
        }

        fn assert_refused_by_the_seeded_backoff(monitor: &RuntimeHealthMonitor) {
            assert!(
                !monitor.request_refresh(|| -> RuntimeHealthObservation {
                    panic!("a gated detector must never run")
                }),
                "the seeded backoff must refuse a request before any reset"
            );
        }

        let monitor = seeded_monitor();
        assert_refused_by_the_seeded_backoff(&monitor);
        monitor.invalidate();
        assert!(
            monitor
                .request_refresh(|| { RuntimeHealthObservation::Settled(health("running", true)) })
        );
        wait_for_refresh(&monitor);

        let monitor = seeded_monitor();
        assert_refused_by_the_seeded_backoff(&monitor);
        monitor.replace_cached(health("replaced", true));
        assert!(
            monitor
                .request_refresh(|| { RuntimeHealthObservation::Settled(health("running", true)) })
        );
        wait_for_refresh(&monitor);

        let monitor = seeded_monitor();
        assert_refused_by_the_seeded_backoff(&monitor);
        monitor.record_observation(health("observed", true));
        assert!(
            !monitor
                .request_refresh(|| { RuntimeHealthObservation::Settled(health("running", true)) }),
            "the freshness window record_observation starts still refuses this request"
        );
        let state = monitor.lock();
        assert_eq!(state.consecutive_reconciling, 0);
        assert_eq!(state.retry_not_before, None);
    }

    #[test]
    fn a_stale_or_panicked_probe_does_not_advance_the_backoff() {
        // Panic case: the seeded fields are non-default, so the request
        // passes the gate, but a panicking detector must leave them exactly
        // as they were.
        let monitor = RuntimeHealthMonitor::new(health("checking", false));
        let seeded_instant = Instant::now() - Duration::from_millis(1);
        {
            let mut state = monitor.lock();
            state.consecutive_reconciling = 3;
            state.retry_not_before = Some(seeded_instant);
        }

        assert!(
            monitor.request_refresh(|| -> RuntimeHealthObservation {
                panic!("detector panic fixture")
            })
        );
        wait_for_refresh(&monitor);

        let state = monitor.lock();
        assert_eq!(state.consecutive_reconciling, 3);
        assert_eq!(state.retry_not_before, Some(seeded_instant));
        drop(state);

        // Stale case: follows lifecycle_change_rejects_an_older_probe_result,
        // but invalidate() during the blocked probe is what resets the
        // backoff fields; the discarded Reconciling result must not.
        let monitor = RuntimeHealthMonitor::new(health("checking", false));
        let seeded_instant = Instant::now() - Duration::from_millis(1);
        {
            let mut state = monitor.lock();
            state.consecutive_reconciling = 3;
            state.retry_not_before = Some(seeded_instant);
        }

        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();

        assert!(monitor.request_refresh(move || {
            entered_tx.send(()).expect("signal detector entry");
            release_rx.recv().expect("release detector");
            RuntimeHealthObservation::Reconciling(health("stale_probe", false))
        }));
        entered_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("detector started");

        monitor.invalidate();
        release_tx.send(()).expect("release stale detector");
        wait_for_refresh(&monitor);

        assert_eq!(monitor.cached().phase, "checking");
        let state = monitor.lock();
        assert_eq!(state.consecutive_reconciling, 0);
        assert_eq!(state.retry_not_before, None);
    }
}
