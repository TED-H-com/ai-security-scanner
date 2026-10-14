pub mod adapter;
pub mod adapters;
pub mod agentic_radar_input;
pub mod artifact_store;
pub mod augustus_preflight;
pub mod augustus_terminal;
pub mod beginner_report;
pub mod bootstrap;
pub mod case_service;
#[cfg(feature = "desktop")]
mod commands;
pub mod connectors;
pub mod container_runtime;
pub mod correlation;
pub mod coverage;
pub mod credential_vault;
pub mod demo;
pub mod diff;
pub mod discovery;
pub mod domain;
pub mod error;
pub mod execution_coverage;
pub mod export;
pub mod export_identity;
pub mod exporters;
pub mod external_scope;
pub mod finding_narrative;
pub mod garak_input;
#[cfg(any(feature = "desktop", feature = "cli"))]
pub mod gateway_release;
pub mod job_manager;
pub mod local_tcp_probe;
pub mod localhost_quick_scan;
pub mod managed_network;
pub mod managed_runtime;
pub mod mcp_armor_input;
pub mod naabu_work_plan;
pub mod orchestrator;
pub mod prioritization;
pub mod priority_guidance;
pub mod process_lease;
pub mod product_uninstall;
pub mod publication_origins;
pub mod registry;
mod report_attachments;
mod report_problem_groups;
pub mod runtime;
pub mod runtime_health_monitor;
pub mod source_authorization;
#[cfg(any(feature = "desktop", test))]
mod startup_failure;
#[cfg(feature = "desktop")]
mod state;
pub mod storage;
pub mod target_candidates;
pub mod workspace_snapshot;
pub mod zap_work_plan;

#[cfg(feature = "desktop")]
use error::AppError;
#[cfg(any(feature = "desktop", test))]
use error::AppResult;
#[cfg(any(feature = "desktop", test))]
use managed_runtime::ensure_private_product_data_directory;
#[cfg(any(feature = "desktop", test))]
use process_lease::DataDirectoryExclusiveLease;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

#[cfg(feature = "desktop")]
use artifact_store::ArtifactStore;
#[cfg(feature = "desktop")]
use managed_runtime::admit_packaged_managed_runtime;
#[cfg(feature = "desktop")]
use registry::EngineRegistry;
#[cfg(feature = "desktop")]
use state::AppState;
#[cfg(feature = "desktop")]
use storage::Storage;
#[cfg(feature = "desktop")]
use tauri::Manager;
#[cfg(feature = "desktop")]
use tauri_plugin_dialog::{DialogExt, MessageDialogKind};

#[cfg(feature = "desktop")]
use startup_failure::{StartupFailure, StartupResource, display_language};

#[cfg(feature = "desktop")]
const DATA_DIRECTORY_ENVIRONMENT_VARIABLE: &str = "AI_SECURITY_SCANNER_DATA_DIR";
#[cfg(feature = "desktop")]
const MANAGED_RUNTIME_BUNDLE_ENVIRONMENT_VARIABLE: &str =
    "AI_SECURITY_SCANNER_MANAGED_RUNTIME_BUNDLE";
pub const RELEASE_APPROVED_LOCAL_IMAGE_DIRECTORY_ENVIRONMENT_VARIABLE: &str =
    container_runtime::RELEASE_APPROVED_LOCAL_IMAGE_DIRECTORY_ENVIRONMENT_VARIABLE;

#[cfg_attr(not(feature = "desktop"), allow(dead_code))]
fn select_environment_path(
    environment_value: Option<&OsStr>,
    platform_default: &Path,
) -> (PathBuf, bool) {
    match environment_value.filter(|value| !value.is_empty()) {
        Some(path) => (PathBuf::from(path), true),
        None => (platform_default.to_path_buf(), false),
    }
}

#[cfg(any(feature = "desktop", test))]
fn prepare_and_lease_desktop_data_directory(
    data_directory: &Path,
    was_overridden: bool,
) -> AppResult<DataDirectoryExclusiveLease> {
    let process_lease = {
        let _product_data_guard: Option<_> = if was_overridden {
            std::fs::create_dir_all(data_directory)?;
            None
        } else {
            Some(ensure_private_product_data_directory(data_directory)?)
        };
        DataDirectoryExclusiveLease::acquire(data_directory)?
    };
    // The process lease now pins the exact root and its parent for the
    // desktop lifetime, so the creation/verification guard can yield.
    Ok(process_lease)
}

#[cfg(feature = "desktop")]
fn data_root_startup_failure(
    resource: StartupResource,
    error: impl std::fmt::Display,
    data_root: &Path,
    was_overridden: bool,
) -> StartupFailure {
    if was_overridden {
        StartupFailure::preparation(
            resource,
            format!(
                "data root `{}` selected by environment variable {DATA_DIRECTORY_ENVIRONMENT_VARIABLE}: {error}",
                data_root.display()
            ),
        )
    } else {
        StartupFailure::preparation(resource, error)
    }
}

#[cfg(feature = "desktop")]
fn data_root_lease_failure(
    error: AppError,
    data_root: &Path,
    was_overridden: bool,
) -> StartupFailure {
    if was_overridden {
        data_root_startup_failure(StartupResource::LocalDataDirectory, error, data_root, true)
    } else {
        StartupFailure::lease(error)
    }
}

/// Provider/container reconciliation may execute slow local commands. It runs
/// only after the shell owns managed state and never propagates an error into
/// desktop setup; unresolved obligations remain durable for a later retry.
#[cfg(feature = "desktop")]
fn reconcile_live_startup_resources(state: &AppState) {
    match state.reconcile_managed_networks() {
        Ok(network_recovery)
            if network_recovery.reconciled > 0 || network_recovery.incomplete > 0 =>
        {
            tracing::warn!(
                reconciled = network_recovery.reconciled,
                incomplete = network_recovery.incomplete,
                details = ?network_recovery.details,
                "managed egress resources were reconciled after the desktop shell opened"
            );
        }
        Ok(_) => {}
        Err(error) => tracing::error!(
            error = %error,
            "managed egress background reconciliation was incomplete"
        ),
    }

    match commands::reconcile_interrupted_scan_resources(state, None) {
        Ok(cleanup) if cleanup.reconciled > 0 || cleanup.pending > 0 => tracing::warn!(
            reconciled = cleanup.reconciled,
            pending = cleanup.pending,
            details = ?cleanup.details,
            "scanner runtime resources were reconciled after the desktop shell opened"
        ),
        Ok(_) => {}
        Err(error) => tracing::error!(
            error = %error,
            "scanner runtime background reconciliation was incomplete"
        ),
    }
}

#[cfg(feature = "desktop")]
fn prepare_desktop_state(app: &mut tauri::App) -> Result<AppState, StartupFailure> {
    let platform_app_data = app
        .path()
        .app_local_data_dir()
        .map_err(|error| StartupFailure::preparation(StartupResource::LocalDataDirectory, error))?;
    let data_environment_value = std::env::var_os(DATA_DIRECTORY_ENVIRONMENT_VARIABLE);
    let (app_data, data_dir_was_overridden) =
        select_environment_path(data_environment_value.as_deref(), &platform_app_data);
    if data_dir_was_overridden {
        tracing::info!(
            data_root = %app_data.display(),
            environment_variable = DATA_DIRECTORY_ENVIRONMENT_VARIABLE,
            "desktop data root was selected from the environment"
        );
    }
    let process_lease =
        prepare_and_lease_desktop_data_directory(&app_data, data_dir_was_overridden)
            .map_err(|error| data_root_lease_failure(error, &app_data, data_dir_was_overridden))?;

    let platform_managed_bundle = app
        .path()
        .resource_dir()
        .map_err(|error| StartupFailure::preparation(StartupResource::InstalledResources, error))?
        .join("managed-runtime");
    let bundle_environment_value = std::env::var_os(MANAGED_RUNTIME_BUNDLE_ENVIRONMENT_VARIABLE);
    let (managed_bundle, managed_bundle_was_overridden) = select_environment_path(
        bundle_environment_value.as_deref(),
        &platform_managed_bundle,
    );
    if managed_bundle_was_overridden {
        tracing::info!(
            managed_runtime_bundle = %managed_bundle.display(),
            environment_variable = MANAGED_RUNTIME_BUNDLE_ENVIRONMENT_VARIABLE,
            "desktop managed-runtime bundle was selected from the environment"
        );
    }
    let managed_bundle_source = if managed_bundle_was_overridden {
        MANAGED_RUNTIME_BUNDLE_ENVIRONMENT_VARIABLE
    } else {
        "installed application resources"
    };
    let managed_runtime_admission = admit_packaged_managed_runtime(&app_data, &managed_bundle);
    if let Some(receipt) = managed_runtime_admission.recovery_receipt() {
        tracing::warn!(
            boundary = receipt.boundary,
            source = receipt.source,
            manifest_sha256 = receipt.manifest_sha256,
            packaged_failure_reason = receipt.packaged_failure_reason.as_str(),
            managed_runtime_bundle = %managed_bundle.display(),
            managed_runtime_bundle_source = managed_bundle_source,
            "packaged scan tools were recovered from the exact verified private copy; installed application resources still require repair"
        );
    }
    if let Some(reason) = managed_runtime_admission.failure_reason() {
        tracing::warn!(
            failure_reason = reason.as_str(),
            managed_runtime_bundle = %managed_bundle.display(),
            managed_runtime_bundle_source = managed_bundle_source,
            "packaged scan tools are unavailable"
        );
    }
    let storage = Storage::open(app_data.join("casework.db")).map_err(|error| {
        data_root_startup_failure(
            StartupResource::CaseDatabase,
            error,
            &app_data,
            data_dir_was_overridden,
        )
    })?;
    let engines = EngineRegistry::load_builtin().unwrap_or_else(|error| {
        tracing::error!(
            error = %error,
            "built-in engine catalog is unavailable; catalog-backed checks remain unavailable"
        );
        EngineRegistry::empty()
    });
    for issue in engines.admission_issues() {
        tracing::warn!(
            engine_id = issue.engine_id.as_deref().unwrap_or("unidentified"),
            issue_code = %issue.code,
            detail = %issue.detail,
            "catalog engine is unavailable"
        );
    }
    let adapters = adapters::builtin_adapter_registry().unwrap_or_else(|error| {
        tracing::error!(
            error = %error,
            "built-in adapter registry is unavailable; catalog-backed checks remain unavailable"
        );
        adapter::AdapterRegistry::default()
    });
    let artifact_store = ArtifactStore::open(app_data.join("artifacts")).map_err(|error| {
        data_root_startup_failure(
            StartupResource::ArtifactStorage,
            error,
            &app_data,
            data_dir_was_overridden,
        )
    })?;
    let artifact_root = artifact_store.root().to_path_buf();
    Ok(AppState::new(
        storage,
        engines,
        adapters,
        artifact_root,
        app_data.join("integrity-signing-key"),
    )
    .with_process_lease(process_lease)
    .with_packaged_managed_runtime_admission(managed_runtime_admission))
}

#[cfg(feature = "desktop")]
fn report_desktop_startup_failure(app: &tauri::App, failure: StartupFailure) {
    let message = failure.message(display_language());
    eprintln!("{message}");
    app.dialog()
        .message(message)
        .kind(MessageDialogKind::Error)
        .blocking_show();
    app.handle().exit(1);
}

#[cfg(feature = "desktop")]
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "ai_security_scanner=info".into()),
        )
        .with_target(false)
        .try_init()
        .ok();

    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_process::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .setup(|app| {
            let state = match prepare_desktop_state(app) {
                Ok(state) => state,
                Err(failure) => {
                    report_desktop_startup_failure(app, failure);
                    return Ok(());
                }
            };
            // Prepare and harden the local export identity early, but never
            // turn a damaged optional export identity into a scanner startup
            // gate. Signed bundle creation remains fail-closed and reports the
            // exact identity recovery action when the user chooses to export.
            match state.case_service().ensure_export_signing_identity() {
                Ok(signing_identity) => tracing::info!(
                    key_id = %signing_identity.key_id,
                    continuity_event = ?signing_identity.continuity_event,
                    "local export-integrity identity is ready"
                ),
                Err(error) => tracing::error!(
                    error = %error,
                    "local export-integrity identity needs repair"
                ),
            }
            match state.case_service().recover_interrupted_scans() {
                Ok(recovered) if recovered > 0 => tracing::warn!(
                    recovered_runs = recovered,
                    "persisted scans were paused after a desktop process restart"
                ),
                Ok(_) => {}
                Err(error) => tracing::error!(
                    error = %error,
                    "persisted scan restart classification failed"
                ),
            }
            match state.case_service().reconcile_terminal_verifications() {
                Ok(reconciled) if reconciled > 0 => tracing::info!(
                    reconciled_verifications = reconciled,
                    "terminal verification comparisons were reconciled after desktop startup"
                ),
                Ok(_) => {}
                Err(error) => tracing::error!(
                    error = %error,
                    "terminal verification reconciliation failed"
                ),
            }
            app.manage(state);
            let startup_app = app.handle().clone();
            std::mem::drop(tauri::async_runtime::spawn_blocking(move || {
                let state = startup_app.state::<AppState>();
                reconcile_live_startup_resources(&state);
            }));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::get_app_snapshot,
            commands::detect_local_private_subnets,
            commands::get_scan_readiness,
            commands::setup_managed_runtime,
            commands::get_managed_runtime_setup_status,
            commands::cancel_managed_runtime_setup,
            commands::create_case,
            commands::select_case,
            commands::archive_case,
            commands::delete_case,
            commands::delete_case_artifacts,
            commands::connect_source_snapshot,
            commands::begin_provider_authorization,
            commands::poll_provider_authorization,
            commands::cancel_provider_authorization,
            commands::provider_authorization_status,
            commands::revoke_provider_authorization,
            commands::plan_provider_bootstrap,
            commands::execute_provider_bootstrap,
            commands::cleanup_provider_bootstrap,
            commands::list_provider_bootstrap_cleanup,
            commands::attach_workspace_snapshot,
            commands::refresh_workspace_snapshot,
            commands::select_mcp_configuration,
            commands::select_agentic_framework,
            commands::configure_model_endpoint,
            commands::set_model_endpoint_key,
            commands::seed_demo_case,
            commands::list_engine_manifests,
            commands::list_engine_admission_issues,
            commands::start_discovery,
            commands::cancel_discovery,
            commands::approve_scope,
            commands::update_finding_workflow,
            commands::suggest_finding_correlations,
            commands::group_findings,
            commands::ungroup_findings,
            commands::start_scan,
            commands::start_localhost_quick_scan,
            commands::pause_scan,
            commands::resume_scan,
            commands::cancel_scan,
            commands::start_rescan,
            commands::preview_export,
            commands::export_case,
            commands::verify_case_export,
        ])
        .run(tauri::generate_context!())
        .unwrap_or_else(|error| {
            let failure = StartupFailure::preparation(StartupResource::Application, error);
            eprintln!("{}", failure.message(display_language()));
            std::process::exit(1);
        });
}

#[cfg(test)]
mod desktop_environment_path_tests {
    use super::*;

    #[test]
    fn environment_path_selects_a_present_override() {
        let platform_default = Path::new("platform-default");
        let (selected, was_overridden) =
            select_environment_path(Some(OsStr::new("operator-data")), platform_default);

        assert_eq!(selected, PathBuf::from("operator-data"));
        assert!(was_overridden);
    }

    #[test]
    fn environment_path_selects_the_platform_default_when_absent() {
        let platform_default = Path::new("platform-default");
        let (selected, was_overridden) = select_environment_path(None, platform_default);

        assert_eq!(selected, platform_default);
        assert!(!was_overridden);
    }

    #[test]
    fn environment_path_treats_an_empty_value_as_unset() {
        let platform_default = Path::new("platform-default");
        let (selected, was_overridden) =
            select_environment_path(Some(OsStr::new("")), platform_default);

        assert_eq!(selected, platform_default);
        assert!(!was_overridden);
    }

    #[test]
    fn environment_path_preserves_a_relative_override() {
        let platform_default = Path::new("platform-default");
        let relative = Path::new("relative/operator-data");
        let (selected, was_overridden) =
            select_environment_path(Some(relative.as_os_str()), platform_default);

        assert_eq!(selected, relative);
        assert!(was_overridden);
    }

    #[test]
    fn platform_default_is_unchanged_without_an_override() {
        let platform_default = PathBuf::from("platform/owned/default");
        let original_default = platform_default.clone();

        let (selected, was_overridden) = select_environment_path(None, &platform_default);

        assert_eq!(selected, original_default);
        assert_eq!(platform_default, original_default);
        assert!(!was_overridden);
    }

    #[test]
    fn overridden_data_root_is_still_exclusively_leased() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let override_path = temporary.path().join("operator-data");

        let lease = prepare_and_lease_desktop_data_directory(&override_path, true)
            .expect("desktop override lease");

        assert_eq!(lease.path(), override_path.join(".exclusive-process.lock"));
        assert!(DataDirectoryExclusiveLease::acquire(&override_path).is_err());
    }
}

#[cfg(test)]
mod desktop_nonblocking_source_invariants {
    fn normalized_source(source: &str) -> String {
        source.replace("\r\n", "\n")
    }

    #[test]
    fn desktop_manages_state_before_scheduling_live_startup_reconciliation() {
        let source = normalized_source(include_str!("lib.rs"));
        let setup_start = source.find(".setup(|app| {").expect("desktop setup");
        let manage = source[setup_start..]
            .find("app.manage(state);")
            .map(|offset| setup_start + offset)
            .expect("managed state boundary");
        let schedule = source[manage..]
            .find("let startup_app = app.handle().clone();")
            .map(|offset| manage + offset)
            .expect("background startup scheduling");
        let background_call = source[schedule..]
            .find("reconcile_live_startup_resources(&state);")
            .map(|offset| schedule + offset)
            .expect("live startup reconciler");
        assert!(manage < schedule && schedule < background_call);

        let synchronous_setup = &source[setup_start..manage];
        assert!(!synchronous_setup.contains("state.reconcile_managed_networks()"));
        assert!(
            !synchronous_setup
                .contains("commands::reconcile_interrupted_scan_resources(&state, None)")
        );

        let helper_start = source
            .find("fn reconcile_live_startup_resources(state: &AppState)")
            .expect("background helper");
        let helper_end = source[helper_start..]
            .find("\n#[cfg(feature = \"desktop\")]\nfn prepare_desktop_state")
            .map(|offset| helper_start + offset)
            .expect("background helper end");
        let helper = &source[helper_start..helper_end];
        assert!(!helper.lines().any(|line| line.trim_end().ends_with("?;")));
        assert!(!helper.contains(".map_err("));
    }

    #[test]
    fn desktop_setup_reports_startup_failures_without_propagating_them() {
        let source = normalized_source(include_str!("lib.rs"));
        let setup_start = source.find(".setup(|app| {").expect("desktop setup");
        let setup_end = source[setup_start..]
            .find("\n        .invoke_handler(")
            .map(|offset| setup_start + offset)
            .expect("desktop setup end");
        let setup = &source[setup_start..setup_end];

        assert!(setup.contains("report_desktop_startup_failure(app, failure);"));
        assert!(setup.contains("return Ok(());"));
        assert!(!setup.lines().any(|line| line.trim_end().ends_with("?;")));

        let reporter_start = source
            .find("fn report_desktop_startup_failure(app: &tauri::App, failure: StartupFailure)")
            .expect("startup failure reporter");
        let reporter_end = source[reporter_start..]
            .find("\n#[cfg(feature = \"desktop\")]\n#[cfg_attr")
            .map(|offset| reporter_start + offset)
            .expect("startup failure reporter end");
        let reporter = &source[reporter_start..reporter_end];
        assert!(reporter.contains("eprintln!(\"{message}\");"));
        assert!(reporter.contains(".blocking_show();"));
        assert!(reporter.contains("app.handle().exit(1);"));

        assert!(!source.contains(".expect(\"error while running ai-security-scanner\")"));
    }

    #[test]
    fn snapshot_and_resume_paths_do_not_wait_or_plan_through_an_active_terminal_claim() {
        let source = normalized_source(include_str!("commands.rs"));
        let snapshot_start = source
            .find("pub async fn get_app_snapshot(")
            .expect("snapshot command");
        let snapshot_end = source[snapshot_start..]
            .find("\n#[tauri::command]\npub fn get_scan_readiness")
            .map(|offset| snapshot_start + offset)
            .expect("snapshot command end");
        let snapshot = &source[snapshot_start..snapshot_end];
        assert!(snapshot.contains("schedule_retained_terminal_reconciliation(&app);"));
        assert!(!snapshot.contains("reconcile_retained_terminal_jobs(&state)"));

        let schedule_start = source
            .find("fn schedule_retained_terminal_reconciliation(app: &AppHandle)")
            .expect("snapshot reconciliation scheduler");
        let schedule_end = source[schedule_start..]
            .find("\nfn load_readable_desktop_cases")
            .map(|offset| schedule_start + offset)
            .expect("snapshot scheduler end");
        let schedule = &source[schedule_start..schedule_end];
        assert!(schedule.contains("tauri::async_runtime::spawn_blocking"));
        assert!(schedule.contains("reconcile_retained_terminal_jobs(&state)"));

        let resume_start = source
            .find("pub async fn resume_scan(")
            .expect("resume command");
        let resume_end = source[resume_start..]
            .find("\n#[tauri::command]\npub fn cancel_scan")
            .map(|offset| resume_start + offset)
            .expect("resume command end");
        let resume = &source[resume_start..resume_end];
        let detached_terminal = resume
            .find("schedule_exact_terminal_reconciliation(&app, key.clone(), snapshot);")
            .expect("detached terminal reconciliation");
        let admission = resume
            .find("state.jobs.coordinate_admission")
            .expect("resume admission boundary");
        let retry_plan = resume
            .find("persist_resume_before_execution_preflight")
            .expect("retry planning boundary");
        assert!(detached_terminal < admission && admission < retry_plan);
        assert!(resume[detached_terminal..admission].contains("return Ok(case);"));
        assert!(!resume.contains("reconcile_terminal_job("));
        assert!(
            resume[admission..retry_plan]
                .contains("schedule_exact_terminal_reconciliation(&app, key.clone(), snapshot);")
        );
    }

    #[test]
    fn cached_runtime_health_is_advisory_and_never_blocks_scan_readiness() {
        let source = normalized_source(include_str!("commands.rs"));
        let readiness_start = source
            .find("pub fn get_scan_readiness(")
            .expect("scan readiness command");
        let readiness_end = source[readiness_start..]
            .find("\n#[tauri::command]\npub fn create_case")
            .map(|offset| readiness_start + offset)
            .expect("scan readiness command end");
        let readiness = &source[readiness_start..readiness_end];

        assert!(readiness.contains("request_runtime_health_refresh()"));
        assert!(!readiness.contains("runtime_health().available"));
        assert!(!readiness.contains("DesktopExecutionBlocker::RuntimeUnavailable"));
    }

    #[test]
    fn cancel_preserves_terminal_truth_and_never_waits_for_no_worker_cleanup() {
        let source = normalized_source(include_str!("commands.rs"));
        let cancel_start = source.find("pub fn cancel_scan(").expect("cancel command");
        let cancel_end = source[cancel_start..]
            .find("\n#[tauri::command]\npub async fn start_rescan")
            .map(|offset| cancel_start + offset)
            .expect("cancel command end");
        let cancel = &source[cancel_start..cancel_end];

        let terminal_branch = cancel
            .find("Some(snapshot) if snapshot.is_terminal()")
            .expect("retained terminal branch");
        let terminal_claim = cancel
            .find("state.jobs.reconcile_terminal_snapshot(&snapshot")
            .expect("exact retained terminal claim");
        let terminal_projection = cancel
            .find("persist_terminal_job_state_reconciliation(&state, &key, &snapshot)")
            .expect("runtime-free terminal truth projection");
        let live_cancel = cancel
            .find("signal_live_cancel_or_preserve_terminal(&app, &state, &key)")
            .expect("live-worker cancel helper");
        let coordinated_cancel = cancel
            .find("coordinate_no_worker_cancel(&state, &key)")
            .expect("no-worker admission decision");
        assert!(
            terminal_branch < terminal_claim
                && terminal_claim < terminal_projection
                && terminal_projection < live_cancel
                && live_cancel < coordinated_cancel
        );
        assert!(
            cancel[terminal_projection..live_cancel]
                .contains("TerminalReconciliationOutcome::InProgress")
        );
        assert!(
            !cancel[terminal_branch..live_cancel]
                .contains("schedule_exact_terminal_reconciliation")
        );

        let live_helper_start = source
            .find("fn signal_live_cancel_or_preserve_terminal(")
            .expect("live cancellation helper");
        let live_helper_end = source[live_helper_start..]
            .find("\n#[tauri::command]\npub fn pause_scan")
            .map(|offset| live_helper_start + offset)
            .expect("live cancellation helper end");
        let live_helper = &source[live_helper_start..live_helper_end];
        assert!(live_helper.contains("state.jobs.cancel(key)"));
        let terminal_edge = live_helper
            .find("Err(JobManagerError::LiveJobNotFound(_))")
            .expect("terminal-edge race branch");
        assert!(live_helper[terminal_edge..].contains("coordinate_no_worker_cancel(state, key)"));
        assert!(
            live_helper[terminal_edge..]
                .contains("finish_no_worker_cancel_resolution(app, state, key, resolution, false)")
        );
        assert!(!live_helper.contains("case_service().cancel_scan"));

        assert!(!cancel.contains("reconcile_interrupted_scan_resources(&state"));
        assert!(!cancel.contains("spawn_blocking"));

        let apply_start = source
            .find("fn apply_no_worker_durable_cancel(")
            .expect("pure no-worker durable decision");
        let apply_end = source[apply_start..]
            .find("\nfn coordinate_no_worker_cancel(")
            .map(|offset| apply_start + offset)
            .expect("durable decision end");
        let apply = &source[apply_start..apply_end];
        let normalized = apply
            .find("unfinished_clean_naabu_between_batch_cancel_target(run)")
            .expect("normalized Naabu handoff detection");
        let siblings = apply
            .find("locally_cancellable_resource_free_engine_ids(run)")
            .expect("resource-free sibling detection");
        let atomic = apply
            .find("service.cancel_no_worker_scan_work(")
            .expect("single atomic service transition");
        let generic_final = apply
            .find("durable_run_has_final_outcome(current_run)")
            .expect("generic terminal shortcut");
        assert!(normalized < atomic && siblings < atomic && atomic < generic_final);
        assert!(apply.contains("NoWorkerCancelAdmission::DurableUnchanged(durable)"));
        assert!(!apply.contains("service.cancel_scan("));

        let finish_start = source
            .find("fn finish_no_worker_cancel_resolution(")
            .expect("no-worker resolution finisher");
        let finish_end = source[finish_start..]
            .find("\nfn signal_live_cancel_or_preserve_terminal(")
            .map(|offset| finish_start + offset)
            .expect("no-worker resolution finisher end");
        let finish = &source[finish_start..finish_end];
        assert!(
            finish.contains("persist_terminal_job_state_reconciliation(state, key, &snapshot)")
        );
        assert!(finish.contains("schedule_exact_runtime_cleanup_reconciliation("));
        assert!(
            finish.contains("emit_cancel_resolution(app, &case, &key.scan_run_id, needs_cleanup)")
        );

        let emit_resolution_start = source
            .find("fn emit_cancel_resolution(")
            .expect("truthful cancel event helper");
        let emit_resolution_end = source[emit_resolution_start..]
            .find("\nfn finish_no_worker_cancel_resolution(")
            .map(|offset| emit_resolution_start + offset)
            .expect("truthful cancel event helper end");
        let emit_resolution = &source[emit_resolution_start..emit_resolution_end];
        assert!(emit_resolution.contains("durable_run_has_final_outcome"));
        assert!(emit_resolution.contains("&& !needs_cleanup"));

        let ordinary_reconcile_start = source
            .find("fn reconcile_terminal_job(")
            .expect("ordinary retained-terminal reconciler");
        let ordinary_reconcile_end = source[ordinary_reconcile_start..]
            .find("\nfn persist_terminal_job_reconciliation(")
            .map(|offset| ordinary_reconcile_start + offset)
            .expect("ordinary retained-terminal reconciler end");
        let ordinary_reconcile = &source[ordinary_reconcile_start..ordinary_reconcile_end];
        assert!(ordinary_reconcile.contains("durable_run_has_final_outcome"));
        assert!(ordinary_reconcile.contains("durable_run_needs_background_cleanup"));
        assert!(ordinary_reconcile.contains("RUN_PROGRESS_EVENT"));
        assert!(ordinary_reconcile.contains("RUN_FINISHED_EVENT"));

        assert!(live_helper.contains("cancel_with_durable_transition"));
        assert!(live_helper.contains("record_localhost_cancel_transition"));
        assert!(live_helper.contains("DurableCancellationOutcome::TerminalWon"));

        let scheduler_start = source
            .find("fn schedule_exact_runtime_cleanup_reconciliation(")
            .expect("exact cleanup scheduler");
        let scheduler_end = source[scheduler_start..]
            .find("\nfn load_readable_desktop_cases")
            .map(|offset| scheduler_start + offset)
            .expect("exact cleanup scheduler end");
        let scheduler = &source[scheduler_start..scheduler_end];
        assert!(scheduler.contains("tauri::async_runtime::spawn_blocking"));
        assert!(scheduler.contains("reconcile_interrupted_scan_resources("));
    }

    #[test]
    fn localhost_connection_utility_has_one_managed_detached_lifecycle() {
        let commands = normalized_source(include_str!("commands.rs"));
        let start = commands
            .find("pub async fn start_localhost_quick_scan(")
            .expect("localhost start command");
        let end = commands[start..]
            .find("\nfn requested_or_latest_run(")
            .map(|offset| start + offset)
            .expect("localhost start command end");
        let start = &commands[start..end];
        assert!(start.contains("state.jobs.coordinate_admission"));
        assert!(start.contains("live_localhost_quick_scan_for_port("));
        assert!(start.contains("state.jobs.start_job("));
        assert!(start.contains("execute_managed_localhost_quick_scan("));
        assert!(start.contains("Ok(queued_case)"));
        assert!(!start.contains(".await"));
        assert!(!start.contains("spawn_blocking"));

        let retained = start
            .find(".terminal_snapshots()")
            .expect("retained terminal reconciliation");
        let new_case = start
            .find("prepare_localhost_quick_scan(")
            .expect("new exact task preparation");
        assert!(
            retained < new_case,
            "old terminals cannot replace the new action"
        );

        let localhost = normalized_source(include_str!("localhost_quick_scan.rs"));
        assert!(!localhost.contains("execute_prepared_localhost_quick_scan"));
        assert!(localhost.contains("pub fn execute_managed_localhost_quick_scan("));
        assert!(localhost.contains("cancelled_without_observation"));
    }
}
