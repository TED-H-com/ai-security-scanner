use ai_security_scanner_lib::job_manager::{
    DurableCancellationOutcome, DurableCancellationWrite, EngineJobStatus, JobActivationOutcome,
    JobCompletion, JobFailureKind, JobKey, JobManager, JobManagerError, JobStatus,
    TerminalReconciliationOutcome,
};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Condvar, Mutex, mpsc};
use std::thread;
use std::time::Duration;

fn key() -> JobKey {
    JobKey::new("case-1", "scan-run-1").expect("valid key")
}

#[test]
fn duplicate_live_job_is_rejected_for_the_exact_case_and_run_pair() {
    let manager = JobManager::default();
    let key = key();
    let release = Arc::new((Mutex::new(false), Condvar::new()));
    let worker_release = Arc::clone(&release);
    let (started_tx, started_rx) = mpsc::channel();
    let (terminal_tx, terminal_rx) = mpsc::channel();

    manager
        .start_job(
            key.clone(),
            ["gitleaks"],
            move |context| {
                let engine = context.engine("gitleaks").expect("engine control");
                engine.mark_running().expect("running");
                started_tx.send(()).expect("started event");
                let (mutex, changed) = &*worker_release;
                let mut released = mutex.lock().expect("release lock");
                while !*released {
                    released = changed.wait(released).expect("release wait");
                }
                engine.mark_completed().expect("completed");
                JobCompletion::Completed
            },
            move |snapshot| terminal_tx.send(snapshot).expect("terminal event"),
        )
        .expect("first job starts");
    started_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("worker started");

    let duplicate = manager
        .start_job(
            key.clone(),
            ["semgrep"],
            |_| JobCompletion::Completed,
            |_| {},
        )
        .expect_err("duplicate rejected");
    assert_eq!(duplicate, JobManagerError::DuplicateLiveJob(key.clone()));

    let (mutex, changed) = &*release;
    *mutex.lock().expect("release lock") = true;
    changed.notify_all();
    let terminal = terminal_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("terminal callback");
    assert_eq!(terminal.status, JobStatus::Completed);
    assert_eq!(manager.live_count(), 0);
}

#[test]
fn pause_resume_and_cancel_requests_reach_each_engine_control() {
    let manager = JobManager::default();
    let key = key();
    let (token_tx, token_rx) = mpsc::channel();
    let (terminal_tx, terminal_rx) = mpsc::channel();

    manager
        .start_job(
            key.clone(),
            ["gitleaks"],
            move |context| {
                let engine = context.engine("gitleaks").expect("engine control");
                engine.mark_running().expect("running");
                let token = engine.cancellation_token();
                token_tx.send(token.clone()).expect("token");
                while !token.is_cancelled() {
                    thread::sleep(Duration::from_millis(2));
                }
                engine.mark_cancelled().expect("cancelled");
                JobCompletion::Cancelled
            },
            move |snapshot| terminal_tx.send(snapshot).expect("terminal event"),
        )
        .expect("job starts");
    let token = token_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("engine token");

    let (paused, pause_changed) = manager.pause_transition(&key).expect("pause request");
    assert!(pause_changed);
    assert_eq!(paused.status, JobStatus::PauseRequested);
    assert_eq!(paused.engines[0].status, EngineJobStatus::PauseRequested);
    assert!(token.is_pause_requested());
    assert!(!token.is_paused(), "a request is not an acknowledged pause");
    let (_, duplicate_pause_changed) = manager
        .pause_transition(&key)
        .expect("duplicate pause request");
    assert!(!duplicate_pause_changed);
    assert!(token.is_pause_requested());

    let (resumed, resume_changed) = manager.resume_transition(&key).expect("resume request");
    assert!(resume_changed);
    assert_eq!(resumed.status, JobStatus::Running);
    assert_eq!(resumed.engines[0].status, EngineJobStatus::Running);
    assert!(!token.is_pause_requested());
    let (_, duplicate_resume_changed) = manager
        .resume_transition(&key)
        .expect("duplicate resume request");
    assert!(!duplicate_resume_changed);
    assert!(!token.is_pause_requested());

    let cancelling = manager.cancel(&key).expect("cancel request");
    assert_eq!(cancelling.status, JobStatus::CancelRequested);
    assert_eq!(
        cancelling.engines[0].status,
        EngineJobStatus::CancelRequested
    );
    assert!(token.is_cancelled());
    assert!(matches!(
        manager.pause_transition(&key),
        Err(JobManagerError::CancellationPending(_))
    ));
    assert!(matches!(
        manager.resume_transition(&key),
        Err(JobManagerError::CancellationPending(_))
    ));

    let terminal = terminal_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("terminal callback");
    assert_eq!(terminal.status, JobStatus::Cancelled);
    assert_eq!(terminal.engines[0].status, EngineJobStatus::Cancelled);
    assert_eq!(manager.live_count(), 0);
}

#[test]
fn persistence_pending_is_terminal_even_when_cancellation_was_requested() {
    let manager = JobManager::default();
    let key = key();
    let release = Arc::new((Mutex::new(false), Condvar::new()));
    let worker_release = Arc::clone(&release);
    let (started_tx, started_rx) = mpsc::channel();
    let (terminal_tx, terminal_rx) = mpsc::channel();

    manager
        .start_job(
            key.clone(),
            ["gitleaks"],
            move |_| {
                started_tx.send(()).expect("worker started");
                let (mutex, changed) = &*worker_release;
                let mut released = mutex.lock().expect("release lock");
                while !*released {
                    released = changed.wait(released).expect("release wait");
                }
                JobCompletion::PersistencePending
            },
            move |snapshot| terminal_tx.send(snapshot).expect("terminal event"),
        )
        .expect("job starts");
    started_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("worker started");
    assert_eq!(
        manager.cancel(&key).expect("cancel intent").status,
        JobStatus::CancelRequested
    );
    let (mutex, changed) = &*release;
    *mutex.lock().expect("release lock") = true;
    changed.notify_all();

    let terminal = terminal_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("terminal callback");
    assert_eq!(terminal.status, JobStatus::Failed);
    assert_eq!(
        terminal.failure_kind,
        Some(JobFailureKind::PersistencePending)
    );
    assert_eq!(terminal.engines[0].status, EngineJobStatus::Failed);
    assert_eq!(manager.live_count(), 0);
}

#[test]
fn durable_pause_and_resume_transitions_are_serialized_per_job() {
    let manager = JobManager::default();
    let key = key();
    let (token_tx, token_rx) = mpsc::channel();
    let (terminal_tx, terminal_rx) = mpsc::channel();
    manager
        .start_job(
            key.clone(),
            ["gitleaks"],
            move |context| {
                let engine = context.engine("gitleaks").expect("engine control");
                engine.mark_running().expect("running");
                let token = engine.cancellation_token();
                token_tx.send(token.clone()).expect("token");
                while !token.is_cancelled() {
                    thread::sleep(Duration::from_millis(2));
                }
                engine.mark_cancelled().expect("cancelled");
                JobCompletion::Cancelled
            },
            move |snapshot| terminal_tx.send(snapshot).expect("terminal event"),
        )
        .expect("job starts");
    let token = token_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("engine token");

    let pause_release = Arc::new(Barrier::new(2));
    let (pause_a_entered_tx, pause_a_entered_rx) = mpsc::channel();
    let pause_a_manager = manager.clone();
    let pause_a_key = key.clone();
    let pause_a_release = Arc::clone(&pause_release);
    let pause_a = thread::spawn(move || {
        pause_a_manager.pause_with_durable_transition(&pause_a_key, || {
            pause_a_entered_tx.send(()).expect("pause A entered");
            pause_a_release.wait();
            Err::<(), _>("simulated revision conflict")
        })
    });
    pause_a_entered_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("pause A entered durable mutation");

    let (pause_b_entered_tx, pause_b_entered_rx) = mpsc::channel();
    let pause_b_manager = manager.clone();
    let pause_b_key = key.clone();
    let pause_b = thread::spawn(move || {
        pause_b_manager.pause_with_durable_transition(&pause_b_key, || {
            pause_b_entered_tx.send(()).expect("pause B entered");
            Ok::<_, &str>(())
        })
    });
    assert!(
        pause_b_entered_rx
            .recv_timeout(Duration::from_millis(100))
            .is_err(),
        "duplicate durable pause must wait for the first transition"
    );
    pause_release.wait();
    assert!(pause_a.join().expect("pause A thread").unwrap().is_err());
    assert!(pause_b.join().expect("pause B thread").unwrap().is_ok());
    assert!(token.is_pause_requested());

    let resume_release = Arc::new(Barrier::new(2));
    let (resume_a_entered_tx, resume_a_entered_rx) = mpsc::channel();
    let resume_a_manager = manager.clone();
    let resume_a_key = key.clone();
    let resume_a_release = Arc::clone(&resume_release);
    let resume_a = thread::spawn(move || {
        resume_a_manager.resume_with_durable_transition(&resume_a_key, || {
            resume_a_entered_tx.send(()).expect("resume A entered");
            resume_a_release.wait();
            Err::<(), _>("simulated revision conflict")
        })
    });
    resume_a_entered_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("resume A entered durable mutation");

    let (resume_b_entered_tx, resume_b_entered_rx) = mpsc::channel();
    let resume_b_manager = manager.clone();
    let resume_b_key = key.clone();
    let resume_b = thread::spawn(move || {
        resume_b_manager.resume_with_durable_transition(&resume_b_key, || {
            resume_b_entered_tx.send(()).expect("resume B entered");
            Ok::<_, &str>(())
        })
    });
    assert!(
        resume_b_entered_rx
            .recv_timeout(Duration::from_millis(100))
            .is_err(),
        "duplicate durable resume must wait for the first transition"
    );
    resume_release.wait();
    assert!(resume_a.join().expect("resume A thread").unwrap().is_err());
    assert!(resume_b.join().expect("resume B thread").unwrap().is_ok());
    assert!(!token.is_pause_requested());

    manager.cancel(&key).expect("cancel worker");
    let terminal = terminal_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("terminal callback");
    assert_eq!(terminal.status, JobStatus::Cancelled);
}

#[test]
fn paused_job_defers_activation_and_cancel_wins_without_invoking_it() {
    let manager = JobManager::default();
    let key = key();
    let (worker_started_tx, worker_started_rx) = mpsc::channel();
    let (begin_activation_tx, begin_activation_rx) = mpsc::channel();
    let (activation_entered_tx, activation_entered_rx) = mpsc::channel();
    let (activation_result_tx, activation_result_rx) = mpsc::channel();
    let (terminal_tx, terminal_rx) = mpsc::channel();
    manager
        .start_job(
            key.clone(),
            ["gitleaks"],
            move |context| {
                worker_started_tx.send(()).expect("worker started");
                begin_activation_rx.recv().expect("begin activation");
                let activation = context.activate_with_transition(|| {
                    activation_entered_tx.send(()).expect("activation entered");
                    Ok::<_, ()>(())
                });
                activation_result_tx
                    .send(activation.clone())
                    .expect("activation result");
                let engine = context.engine("gitleaks").expect("engine");
                match activation {
                    JobActivationOutcome::Cancelled => {
                        engine.mark_cancelled().expect("cancelled");
                        JobCompletion::Cancelled
                    }
                    JobActivationOutcome::Activated(()) | JobActivationOutcome::Failed(()) => {
                        engine.mark_failed().expect("failed");
                        JobCompletion::Failed
                    }
                }
            },
            move |snapshot| terminal_tx.send(snapshot).expect("terminal event"),
        )
        .expect("job starts");
    worker_started_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("worker started");
    manager.pause(&key).expect("pause before activation");
    begin_activation_tx.send(()).expect("release worker");
    assert!(
        activation_entered_rx
            .recv_timeout(Duration::from_millis(100))
            .is_err(),
        "pause must keep the activation closure dormant"
    );

    manager.cancel(&key).expect("cancel before activation");
    assert_eq!(
        activation_result_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("cancelled activation"),
        JobActivationOutcome::Cancelled
    );
    assert!(
        activation_entered_rx.try_recv().is_err(),
        "cancelled activation closure must never run"
    );
    assert_eq!(
        terminal_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("terminal callback")
            .status,
        JobStatus::Cancelled
    );
}

#[test]
fn cancel_returned_before_activation_deterministically_skips_activation() {
    let manager = JobManager::default();
    let key = key();
    let activation_called = Arc::new(AtomicBool::new(false));
    let worker_activation_called = Arc::clone(&activation_called);
    let (worker_ready_tx, worker_ready_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let (outcome_tx, outcome_rx) = mpsc::channel();
    let (terminal_tx, terminal_rx) = mpsc::channel();

    manager
        .start_job(
            key.clone(),
            ["gitleaks"],
            move |context| {
                worker_ready_tx.send(()).expect("worker ready");
                release_rx.recv().expect("release activation");
                let outcome = context.activate_with_transition(|| {
                    worker_activation_called.store(true, Ordering::SeqCst);
                    Ok::<_, ()>(())
                });
                outcome_tx
                    .send(outcome.clone())
                    .expect("activation outcome");
                context
                    .engine("gitleaks")
                    .expect("engine")
                    .mark_cancelled()
                    .expect("cancelled");
                JobCompletion::Cancelled
            },
            move |snapshot| terminal_tx.send(snapshot).expect("terminal"),
        )
        .expect("job starts");
    worker_ready_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("worker ready");

    manager.cancel(&key).expect("cancel returns");
    release_tx.send(()).expect("release worker");

    assert_eq!(
        outcome_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("activation outcome"),
        JobActivationOutcome::Cancelled
    );
    assert!(!activation_called.load(Ordering::SeqCst));
    assert_eq!(
        terminal_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("terminal")
            .status,
        JobStatus::Cancelled
    );
}

#[test]
fn cancel_returned_before_preflight_write_deterministically_skips_write() {
    let manager = JobManager::default();
    let key = key();
    let write_called = Arc::new(AtomicBool::new(false));
    let worker_write_called = Arc::clone(&write_called);
    let (worker_ready_tx, worker_ready_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let (outcome_tx, outcome_rx) = mpsc::channel();
    let (terminal_tx, terminal_rx) = mpsc::channel();

    manager
        .start_job(
            key.clone(),
            ["gitleaks"],
            move |context| {
                worker_ready_tx.send(()).expect("worker ready");
                release_rx.recv().expect("release preflight");
                let outcome = context.coordinate_durable_write_if_not_cancelled(|| {
                    worker_write_called.store(true, Ordering::SeqCst);
                    Ok::<_, ()>(())
                });
                outcome_tx.send(outcome.clone()).expect("write outcome");
                context
                    .engine("gitleaks")
                    .expect("engine")
                    .mark_cancelled()
                    .expect("cancelled");
                JobCompletion::Cancelled
            },
            move |snapshot| terminal_tx.send(snapshot).expect("terminal"),
        )
        .expect("job starts");
    worker_ready_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("worker ready");

    manager.cancel(&key).expect("cancel returns");
    release_tx.send(()).expect("release worker");

    assert_eq!(
        outcome_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("write outcome"),
        JobActivationOutcome::Cancelled
    );
    assert!(!write_called.load(Ordering::SeqCst));
    assert_eq!(
        terminal_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("terminal")
            .status,
        JobStatus::Cancelled
    );
}

#[test]
fn accepted_cancel_dominates_a_later_worker_panic() {
    let manager = JobManager::default();
    let key = key();
    let (worker_ready_tx, worker_ready_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let (terminal_tx, terminal_rx) = mpsc::channel();

    manager
        .start_job(
            key.clone(),
            ["gitleaks"],
            move |_| {
                worker_ready_tx.send(()).expect("worker ready");
                release_rx.recv().expect("release panic");
                panic!("panic after accepted cancellation");
            },
            move |snapshot| terminal_tx.send(snapshot).expect("terminal"),
        )
        .expect("job starts");
    worker_ready_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("worker ready");

    manager.cancel(&key).expect("cancel returns");
    release_tx.send(()).expect("release worker");

    let terminal = terminal_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("terminal");
    assert_eq!(terminal.status, JobStatus::Cancelled);
    assert_eq!(terminal.failure_kind, None);
    assert_eq!(terminal.engines[0].status, EngineJobStatus::Cancelled);
}

#[test]
fn cancel_intent_published_during_activation_prevents_later_target_contact() {
    let manager = JobManager::default();
    let key = key();
    let activation_release = Arc::new(Barrier::new(2));
    let activation_worker_release = Arc::clone(&activation_release);
    let fake_contacts = Arc::new(AtomicUsize::new(0));
    let worker_fake_contacts = Arc::clone(&fake_contacts);
    let (activation_entered_tx, activation_entered_rx) = mpsc::channel();
    let (activation_result_tx, activation_result_rx) = mpsc::channel();
    let (terminal_tx, terminal_rx) = mpsc::channel();
    manager
        .start_job(
            key.clone(),
            ["gitleaks"],
            move |context| {
                let activation = context.activate_with_transition(|| {
                    activation_entered_tx.send(()).expect("activation entered");
                    activation_worker_release.wait();
                    Ok::<_, ()>("activated")
                });
                activation_result_tx
                    .send(activation.clone())
                    .expect("activation result");
                // A successful activation owns any irreversible capacity it
                // committed even when cancellation was published during the
                // closure. The mandatory post-activation token check is the
                // zero-contact boundary.
                if matches!(activation, JobActivationOutcome::Activated(_))
                    && !context.is_cancelled()
                {
                    worker_fake_contacts.fetch_add(1, Ordering::SeqCst);
                }
                while !context.is_cancelled() {
                    thread::yield_now();
                }
                let engine = context.engine("gitleaks").expect("engine");
                engine.mark_cancelled().expect("cancelled");
                JobCompletion::Cancelled
            },
            move |snapshot| terminal_tx.send(snapshot).expect("terminal event"),
        )
        .expect("job starts");
    activation_entered_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("activation entered");

    let cancel_manager = manager.clone();
    let cancel_key = key.clone();
    let (cancelled_tx, cancelled_rx) = mpsc::channel();
    let cancel = thread::spawn(move || {
        let result = cancel_manager.cancel(&cancel_key);
        cancelled_tx.send(result).expect("cancel result");
    });
    assert!(
        cancelled_rx
            .recv_timeout(Duration::from_millis(100))
            .is_err(),
        "cancel must wait for the one-time activation boundary"
    );

    activation_release.wait();
    assert_eq!(
        activation_result_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("activation result"),
        JobActivationOutcome::Activated("activated")
    );
    cancelled_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("cancel completed")
        .expect("cancel request");
    cancel.join().expect("cancel thread");
    assert_eq!(fake_contacts.load(Ordering::SeqCst), 0);
    assert_eq!(
        terminal_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("terminal callback")
            .status,
        JobStatus::Cancelled
    );
}

#[test]
fn worker_durable_write_is_serialized_with_pause_transition() {
    let manager = JobManager::default();
    let key = key();
    let durable_release = Arc::new(Barrier::new(2));
    let worker_release = Arc::clone(&durable_release);
    let (durable_entered_tx, durable_entered_rx) = mpsc::channel();
    let (token_tx, token_rx) = mpsc::channel();
    let (terminal_tx, terminal_rx) = mpsc::channel();

    manager
        .start_job(
            key.clone(),
            ["gitleaks"],
            move |context| {
                let engine = context.engine("gitleaks").expect("engine control");
                engine.mark_running().expect("running");
                let token = engine.cancellation_token();
                token_tx.send(token.clone()).expect("token");
                context.coordinate_durable_write(|| {
                    durable_entered_tx.send(()).expect("worker write entered");
                    worker_release.wait();
                });
                while !token.is_cancelled() {
                    thread::sleep(Duration::from_millis(2));
                }
                engine.mark_cancelled().expect("cancelled");
                JobCompletion::Cancelled
            },
            move |snapshot| terminal_tx.send(snapshot).expect("terminal event"),
        )
        .expect("job starts");
    let token = token_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("engine token");
    durable_entered_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("worker durable write entered");

    let (pause_entered_tx, pause_entered_rx) = mpsc::channel();
    let pause_manager = manager.clone();
    let pause_key = key.clone();
    let pause = thread::spawn(move || {
        pause_manager.pause_with_durable_transition(&pause_key, || {
            pause_entered_tx
                .send(())
                .expect("pause durable write entered");
            Ok::<_, &str>(())
        })
    });
    assert!(
        pause_entered_rx
            .recv_timeout(Duration::from_millis(100))
            .is_err(),
        "pause persistence must wait for the worker's report persistence"
    );

    durable_release.wait();
    assert!(pause.join().expect("pause thread").unwrap().is_ok());
    assert!(token.is_pause_requested());

    manager.cancel(&key).expect("cancel worker");
    let terminal = terminal_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("terminal callback");
    assert_eq!(terminal.status, JobStatus::Cancelled);
}

#[test]
fn same_key_restart_waits_for_exact_terminal_reconciliation() {
    let manager = JobManager::default();
    let key = key();
    let (first_terminal_tx, first_terminal_rx) = mpsc::channel();
    manager
        .start_job(
            key.clone(),
            ["first"],
            |context| {
                context
                    .engine("first")
                    .expect("engine")
                    .mark_completed()
                    .expect("complete");
                JobCompletion::Completed
            },
            move |terminal| {
                first_terminal_tx
                    .send(terminal)
                    .expect("first terminal event")
            },
        )
        .expect("first job starts");
    let first_terminal = first_terminal_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("first terminal callback snapshot");

    let error = manager
        .start_job(
            key.clone(),
            ["second"],
            |_| JobCompletion::Completed,
            |_| {},
        )
        .expect_err("unacknowledged terminal truth blocks only the same key");
    assert_eq!(
        error,
        JobManagerError::TerminalReconciliationPending(key.clone())
    );
    assert_eq!(
        manager
            .reconcile_terminal_snapshot(&first_terminal, || Ok::<_, ()>(()))
            .unwrap(),
        TerminalReconciliationOutcome::Reconciled(())
    );

    let (second_terminal_tx, second_terminal_rx) = mpsc::channel();
    manager
        .start_job(
            key.clone(),
            ["second"],
            |context| {
                context
                    .engine("second")
                    .expect("engine")
                    .mark_completed()
                    .expect("complete");
                JobCompletion::Completed
            },
            move |terminal| {
                second_terminal_tx
                    .send(terminal)
                    .expect("second terminal event")
            },
        )
        .expect("same key starts after reconciliation");
    let second_terminal = second_terminal_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("second terminal callback");
    assert_eq!(second_terminal.engines[0].engine_id, "second");
    assert_eq!(
        manager
            .reconcile_terminal_snapshot(&first_terminal, || Ok::<_, ()>(()))
            .unwrap(),
        TerminalReconciliationOutcome::NotCurrent,
        "a delayed old acknowledgement cannot remove the newer generation"
    );
    assert_eq!(manager.terminal_snapshots(), vec![second_terminal.clone()]);
    assert_eq!(
        manager
            .reconcile_terminal_snapshot(&second_terminal, || Ok::<_, ()>(()))
            .unwrap(),
        TerminalReconciliationOutcome::Reconciled(())
    );
}

#[test]
fn blocked_terminal_reconciliation_refuses_same_key_but_keeps_unrelated_jobs_responsive() {
    let manager = JobManager::default();
    let key = key();
    let (terminal_tx, terminal_rx) = mpsc::channel();
    manager
        .start_job(
            key.clone(),
            ["first"],
            |context| {
                context
                    .engine("first")
                    .expect("engine")
                    .mark_completed()
                    .expect("complete");
                JobCompletion::Completed
            },
            move |terminal| terminal_tx.send(terminal).expect("terminal event"),
        )
        .expect("first job starts");
    let terminal = terminal_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("first job terminal");

    let reconcile_manager = manager.clone();
    let reconcile_terminal = terminal.clone();
    let persistence_entered = Arc::new(Barrier::new(2));
    let persistence_release = Arc::new(Barrier::new(2));
    let entered_for_reconcile = Arc::clone(&persistence_entered);
    let release_for_reconcile = Arc::clone(&persistence_release);
    let reconciliation = thread::spawn(move || {
        reconcile_manager
            .reconcile_terminal_snapshot(&reconcile_terminal, || {
                entered_for_reconcile.wait();
                release_for_reconcile.wait();
                Ok::<_, ()>(())
            })
            .expect("reconcile terminal")
    });
    persistence_entered.wait();

    assert_eq!(
        manager
            .reconcile_terminal_snapshot(&terminal, || Ok::<_, ()>(()))
            .expect("observe active exact claim"),
        TerminalReconciliationOutcome::InProgress
    );

    let same_key_manager = manager.clone();
    let same_key = key.clone();
    let (same_key_tx, same_key_rx) = mpsc::channel();
    let same_key_attempt = thread::spawn(move || {
        let result = same_key_manager.start_job(
            same_key,
            ["second"],
            |context| {
                context
                    .engine("second")
                    .expect("engine")
                    .mark_completed()
                    .expect("complete");
                JobCompletion::Completed
            },
            |_| {},
        );
        same_key_tx.send(result).expect("same-key result");
    });
    assert!(matches!(
        same_key_rx
            .recv_timeout(Duration::from_millis(250))
            .expect("same-key attempt returns promptly"),
        Err(JobManagerError::TerminalReconciliationPending(_))
    ));
    same_key_attempt.join().expect("same-key attempt thread");

    let unrelated_key = JobKey::new("case-2", "scan-run-2").expect("unrelated key");
    let (unrelated_terminal_tx, unrelated_terminal_rx) = mpsc::channel();
    manager
        .start_job(
            unrelated_key,
            ["unrelated"],
            |context| {
                context
                    .engine("unrelated")
                    .expect("unrelated engine")
                    .mark_completed()
                    .expect("complete unrelated job");
                JobCompletion::Completed
            },
            move |snapshot| {
                unrelated_terminal_tx
                    .send(snapshot)
                    .expect("unrelated terminal")
            },
        )
        .expect("unrelated job admission stays responsive");
    unrelated_terminal_rx
        .recv_timeout(Duration::from_millis(250))
        .expect("unrelated worker stays responsive");
    assert_eq!(
        manager.snapshot(&key),
        Some(terminal.clone()),
        "the exact terminal generation remains retained during reconciliation"
    );

    persistence_release.wait();
    assert_eq!(
        reconciliation.join().expect("reconciliation thread"),
        TerminalReconciliationOutcome::Reconciled(())
    );

    manager
        .start_job(
            key,
            ["after-ack"],
            |context| {
                context
                    .engine("after-ack")
                    .expect("engine")
                    .mark_completed()
                    .expect("complete");
                JobCompletion::Completed
            },
            |_| {},
        )
        .expect("explicit same-key retry is admitted after acknowledgement");
}

#[test]
fn retained_terminal_generation_is_not_a_live_cancellation_target() {
    let manager = JobManager::default();
    let key = key();
    let (terminal_tx, terminal_rx) = mpsc::channel();
    manager
        .start_job(
            key.clone(),
            ["engine"],
            |context| {
                context
                    .engine("engine")
                    .expect("engine")
                    .mark_completed()
                    .expect("complete");
                JobCompletion::Completed
            },
            move |terminal| terminal_tx.send(terminal).expect("terminal event"),
        )
        .expect("job starts");
    let terminal = terminal_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("terminal snapshot");

    assert!(terminal.is_terminal());
    assert_eq!(
        manager.cancel(&key),
        Err(JobManagerError::LiveJobNotFound(key.clone())),
        "Cancel signals only a live worker"
    );
    assert_eq!(manager.snapshot(&key), Some(terminal.clone()));
    assert_eq!(manager.terminal_snapshots(), vec![terminal]);
}

#[test]
fn durable_cancel_transition_is_short_while_worker_waits_outside_control_boundary() {
    let manager = JobManager::default();
    let key = key();
    let entered_target = Arc::new(Barrier::new(2));
    let release_target = Arc::new(Barrier::new(2));
    let worker_entered = Arc::clone(&entered_target);
    let worker_release = Arc::clone(&release_target);
    let (terminal_tx, terminal_rx) = mpsc::channel();
    manager
        .start_job(
            key.clone(),
            ["engine"],
            move |context| {
                let engine = context.engine("engine").expect("engine");
                context.coordinate_durable_write(|| engine.mark_running().expect("running"));
                worker_entered.wait();
                worker_release.wait();
                context.coordinate_durable_write(|| {
                    assert!(context.is_cancelled());
                    engine.mark_cancelled().expect("cancelled");
                });
                JobCompletion::Cancelled
            },
            move |terminal| terminal_tx.send(terminal).expect("terminal"),
        )
        .expect("job starts");
    entered_target.wait();

    let durable_writes = Arc::new(AtomicUsize::new(0));
    let writes = Arc::clone(&durable_writes);
    let outcome = manager
        .cancel_with_durable_transition(&key, move || {
            writes.fetch_add(1, Ordering::SeqCst);
            Ok::<_, ()>(DurableCancellationWrite::Requested("saved"))
        })
        .expect("manager transition")
        .expect("durable transition");
    assert!(matches!(
        outcome,
        DurableCancellationOutcome::Requested {
            durable: "saved",
            ..
        }
    ));
    assert_eq!(durable_writes.load(Ordering::SeqCst), 1);

    release_target.wait();
    let terminal = terminal_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("cancelled terminal");
    assert_eq!(terminal.status, JobStatus::Cancelled);
}

#[test]
fn durable_terminal_mark_beats_a_late_cancel_without_invoking_its_write() {
    let manager = JobManager::default();
    let key = key();
    let result_marked = Arc::new(Barrier::new(2));
    let release_result = Arc::new(Barrier::new(2));
    let worker_marked = Arc::clone(&result_marked);
    let worker_release = Arc::clone(&release_result);
    let (terminal_tx, terminal_rx) = mpsc::channel();
    manager
        .start_job(
            key.clone(),
            ["engine"],
            move |context| {
                let engine = context.engine("engine").expect("engine");
                context.coordinate_durable_write(|| {
                    engine.mark_running().expect("running");
                    engine.mark_completed().expect("completed");
                    worker_marked.wait();
                    worker_release.wait();
                });
                JobCompletion::Completed
            },
            move |terminal| terminal_tx.send(terminal).expect("terminal"),
        )
        .expect("job starts");
    result_marked.wait();

    let cancel_manager = manager.clone();
    let cancel_key = key.clone();
    let durable_writes = Arc::new(AtomicUsize::new(0));
    let writes = Arc::clone(&durable_writes);
    let (cancel_tx, cancel_rx) = mpsc::channel();
    let cancel = thread::spawn(move || {
        let outcome = cancel_manager.cancel_with_durable_transition(&cancel_key, move || {
            writes.fetch_add(1, Ordering::SeqCst);
            Ok::<_, ()>(DurableCancellationWrite::Requested(()))
        });
        cancel_tx.send(outcome).expect("cancel outcome");
    });
    assert!(cancel_rx.recv_timeout(Duration::from_millis(100)).is_err());
    release_result.wait();

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
    cancel.join().expect("cancel thread");
    let terminal = terminal_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("completed terminal");
    assert_eq!(terminal.status, JobStatus::Completed);
}

#[test]
fn terminal_reconciliation_error_and_panic_release_the_exact_claim_for_retry() {
    for panic_during_reconciliation in [false, true] {
        let manager = JobManager::default();
        let key = key();
        let (terminal_tx, terminal_rx) = mpsc::channel();
        manager
            .start_job(
                key,
                ["engine"],
                |context| {
                    context
                        .engine("engine")
                        .expect("engine")
                        .mark_completed()
                        .expect("complete");
                    JobCompletion::Completed
                },
                move |snapshot| terminal_tx.send(snapshot).expect("terminal"),
            )
            .expect("job starts");
        let terminal = terminal_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("terminal snapshot");

        if panic_during_reconciliation {
            let panic = std::panic::catch_unwind({
                let manager = manager.clone();
                let terminal = terminal.clone();
                move || {
                    let _ = manager.reconcile_terminal_snapshot(&terminal, || -> Result<(), ()> {
                        panic!("injected reconciliation panic")
                    });
                }
            });
            assert!(panic.is_err());
        } else {
            assert_eq!(
                manager.reconcile_terminal_snapshot(&terminal, || Err::<(), _>("write failed")),
                Err("write failed")
            );
        }

        assert_eq!(
            manager
                .reconcile_terminal_snapshot(&terminal, || Ok::<_, ()>(()))
                .expect("claim can be retried"),
            TerminalReconciliationOutcome::Reconciled(())
        );
    }
}

#[test]
fn worker_panic_is_sanitized_and_reported_as_terminal_failure() {
    let manager = JobManager::default();
    let key = key();
    let (terminal_tx, terminal_rx) = mpsc::channel();

    manager
        .start_job(
            key.clone(),
            ["gitleaks"],
            |context| {
                context
                    .engine("gitleaks")
                    .expect("engine")
                    .mark_running()
                    .expect("running");
                panic!("sensitive panic payload must not escape");
            },
            move |snapshot| terminal_tx.send(snapshot).expect("terminal event"),
        )
        .expect("job starts");

    let terminal = terminal_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("terminal callback");
    assert_eq!(terminal.status, JobStatus::Failed);
    assert_eq!(terminal.failure_kind, Some(JobFailureKind::WorkerPanicked));
    assert_eq!(terminal.engines[0].status, EngineJobStatus::Failed);
    assert!(!format!("{terminal:?}").contains("sensitive panic payload"));
    assert!(
        !serde_json::to_string(&terminal)
            .expect("serialize snapshot")
            .contains("sensitive panic payload")
    );
    assert_eq!(manager.live_count(), 0);
}

#[test]
fn panic_after_engine_completion_cannot_report_a_successful_job() {
    let manager = JobManager::default();
    let key = key();
    let (terminal_tx, terminal_rx) = mpsc::channel();

    manager
        .start_job(
            key,
            ["gitleaks"],
            |context| {
                let engine = context.engine("gitleaks").expect("engine");
                engine.mark_running().expect("running");
                engine.mark_completed().expect("completed engine report");
                panic!("panic after durable engine completion");
            },
            move |snapshot| terminal_tx.send(snapshot).expect("terminal event"),
        )
        .expect("job starts");

    let terminal = terminal_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("terminal callback");
    assert_eq!(terminal.engines[0].status, EngineJobStatus::Completed);
    assert_eq!(terminal.status, JobStatus::Failed);
    assert_eq!(terminal.failure_kind, Some(JobFailureKind::WorkerPanicked));
}

#[test]
fn completed_worker_must_account_for_every_engine() {
    let manager = JobManager::default();
    let key = key();
    let (terminal_tx, terminal_rx) = mpsc::channel();
    manager
        .start_job(
            key.clone(),
            ["gitleaks", "semgrep"],
            |context| {
                let engine = context.engine("gitleaks").expect("engine");
                engine.mark_running().expect("running");
                engine.mark_completed().expect("completed");
                JobCompletion::Completed
            },
            move |snapshot| terminal_tx.send(snapshot).expect("terminal event"),
        )
        .expect("job starts");

    let terminal = terminal_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("terminal callback");
    assert_eq!(terminal.status, JobStatus::Failed);
    assert_eq!(
        terminal.failure_kind,
        Some(JobFailureKind::WorkerReturnedEarly)
    );
    assert_eq!(
        terminal
            .engines
            .iter()
            .find(|engine| engine.engine_id == "semgrep")
            .expect("semgrep")
            .status,
        EngineJobStatus::Failed
    );
}

#[test]
fn concurrent_starts_admit_exactly_one_live_worker() {
    const CONTENDERS: usize = 16;
    let manager = JobManager::default();
    let key = key();
    let start_barrier = Arc::new(Barrier::new(CONTENDERS));
    let release = Arc::new((Mutex::new(false), Condvar::new()));
    let (terminal_tx, terminal_rx) = mpsc::channel();
    let mut contenders = Vec::new();

    for index in 0..CONTENDERS {
        let contender_manager = manager.clone();
        let contender_key = key.clone();
        let contender_barrier = Arc::clone(&start_barrier);
        let worker_release = Arc::clone(&release);
        let contender_terminal = terminal_tx.clone();
        contenders.push(thread::spawn(move || {
            contender_barrier.wait();
            contender_manager.start_job(
                contender_key,
                [format!("engine-{index}")],
                move |context| {
                    let engine_id = context.engine_ids().remove(0);
                    let engine = context.engine(&engine_id).expect("engine");
                    engine.mark_running().expect("running");
                    let (mutex, changed) = &*worker_release;
                    let mut released = mutex.lock().expect("release lock");
                    while !*released {
                        released = changed.wait(released).expect("release wait");
                    }
                    engine.mark_completed().expect("completed");
                    JobCompletion::Completed
                },
                move |snapshot| contender_terminal.send(snapshot).expect("terminal event"),
            )
        }));
    }
    drop(terminal_tx);

    let results = contenders
        .into_iter()
        .map(|contender| contender.join().expect("contender thread"))
        .collect::<Vec<_>>();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Err(JobManagerError::DuplicateLiveJob(_))))
            .count(),
        CONTENDERS - 1
    );
    assert_eq!(manager.live_count(), 1);

    let (mutex, changed) = &*release;
    *mutex.lock().expect("release lock") = true;
    changed.notify_all();
    assert_eq!(
        terminal_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("terminal callback")
            .status,
        JobStatus::Completed
    );
    assert_eq!(manager.live_count(), 0);
}

#[test]
fn manager_debug_and_snapshots_do_not_capture_worker_closure_data() {
    let manager = JobManager::default();
    let key = key();
    let secret = String::from("never-serialize-this-secret-value");
    let release = Arc::new((Mutex::new(false), Condvar::new()));
    let worker_release = Arc::clone(&release);
    let (started_tx, started_rx) = mpsc::channel();
    let (terminal_tx, terminal_rx) = mpsc::channel();

    manager
        .start_job(
            key.clone(),
            ["gitleaks"],
            move |context| {
                let _owned_sensitive_context = secret;
                let engine = context.engine("gitleaks").expect("engine");
                engine.mark_running().expect("running");
                started_tx.send(()).expect("started");
                let (mutex, changed) = &*worker_release;
                let mut released = mutex.lock().expect("release lock");
                while !*released {
                    released = changed.wait(released).expect("release wait");
                }
                engine.mark_completed().expect("completed");
                JobCompletion::Completed
            },
            move |snapshot| terminal_tx.send(snapshot).expect("terminal event"),
        )
        .expect("job starts");
    started_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("worker started");

    let snapshot = manager.snapshot(&key).expect("live snapshot");
    assert!(!format!("{manager:?}").contains("never-serialize-this-secret-value"));
    assert!(
        !serde_json::to_string(&snapshot)
            .expect("snapshot json")
            .contains("never-serialize-this-secret-value")
    );

    let (mutex, changed) = &*release;
    *mutex.lock().expect("release lock") = true;
    changed.notify_all();
    terminal_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("terminal callback");
}
