//! Foreground, target-independent preparation through the existing runtime.

use super::*;
use ai_security_scanner_lib::managed_runtime::ensure_private_product_data_directory;
use ai_security_scanner_lib::runtime_preparation::{
    RuntimePreparationPlan, resolve_preparation_runtime,
};
use sha2::{Digest, Sha256};
use std::io::Write;

const SCHEMA: &str = "ai-security-scanner.runtime-preparation/v1";

#[derive(Debug, Clone, Args)]
pub(super) struct PrepareArgs {
    /// Exact catalog engine IDs, separated by commas. No target is contacted.
    #[arg(long, required = true, value_delimiter = ',')]
    engine: Vec<String>,
    /// Use only a running runtime and existing or verified local images.
    #[arg(long)]
    offline: bool,
    /// Fixed parent cancellation pipe; EOF also cancels preparation.
    #[arg(long, hide = true)]
    bootstrap_control_stdin: bool,
}

#[derive(Clone)]
struct Request {
    id: String,
    args: PrepareArgs,
    data_dir: Option<PathBuf>,
    managed_bundle: Option<PathBuf>,
    local_images: Option<PathBuf>,
}

fn failure(request: &Request, error: &AppError) -> Value {
    let (code, error_code, _) = foreground_error_class(error);
    json!({
        "schema_version": SCHEMA,
        "operation": "runtime.prepare",
        "request_id": request.id,
        "command_outcome": if code == 4 { "failed" } else { "rejected" },
        "exit_code": code,
        "ready": false,
        "offline": request.args.offline,
        "engines": request.args.engine,
        "runtime": null,
        "images": [],
        "error_code": error_code,
        "error": error.to_string(),
        "target_contact": false,
        "receipt_path": null,
    })
}

pub(super) async fn execute(cli: &Cli, args: &PrepareArgs, sources: GlobalOptionSources) -> u8 {
    let request = Request {
        id: new_id(),
        args: args.clone(),
        data_dir: cli.data_dir.clone(),
        managed_bundle: cli.managed_runtime_bundle.clone(),
        local_images: cli.release_approved_local_image_directory.clone(),
    };
    if !sources.data_dir_was_explicit() || request.data_dir.is_none() {
        let result = failure(&request, &AppError::InvalidRequest(
            "runtime prepare requires an explicit --data-dir; it never defaults to desktop data".into(),
        ));
        return deliver(result, cli.json);
    }
    // Validate the complete selection before even creating a data directory or
    // probing a runtime. Preparation never accepts target or credential input.
    let plan = EngineRegistry::load_builtin().and_then(|engines| {
        RuntimePreparationPlan::new(&engines, &builtin_adapter_registry()?, &args.engine)
    });
    let plan = match plan {
        Ok(plan) => plan,
        Err(error) => return deliver(failure(&request, &error), cli.json),
    };
    let cancelled = Arc::new(AtomicBool::new(false));
    let exit_signal = Arc::new(AtomicU8::new(0));
    if args.bootstrap_control_stdin {
        let control_cancelled = cancelled.clone();
        let control_signal = exit_signal.clone();
        if let Err(error) = parent_control::listen(move |code| {
            let _ = control_signal.compare_exchange(0, code, Ordering::AcqRel, Ordering::Acquire);
            control_cancelled.store(true, Ordering::Release);
        }) {
            return deliver(failure(&request, &error.into()), cli.json);
        }
    }
    #[cfg(unix)]
    let signals = (|| -> io::Result<_> {
        Ok((
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?,
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?,
        ))
    })();
    #[cfg(unix)]
    let (mut interrupt, mut terminate) = match signals {
        Ok(signals) => signals,
        Err(error) => return deliver(failure(&request, &error.into()), cli.json),
    };
    #[cfg(not(unix))]
    let interrupt = tokio::signal::ctrl_c();
    #[cfg(not(unix))]
    tokio::pin!(interrupt);
    let worker_request = request.clone();
    let worker_cancelled = cancelled.clone();
    let worker_signal = exit_signal.clone();
    let mut owner = tokio::task::spawn_blocking(move || {
        owned_prepare(&worker_request, &plan, &worker_cancelled, &worker_signal)
            .unwrap_or_else(|error| failure(&worker_request, &error))
    });
    // Signals request cancellation, then wait for every runtime operation to
    // finish or terminate its owned subprocess. Never detach the lease owner.
    let joined = loop {
        #[cfg(unix)]
        tokio::select! {
            result = &mut owner => break result,
            _ = interrupt.recv() => {
                let _ = exit_signal.compare_exchange(0, 130, Ordering::AcqRel, Ordering::Acquire);
                cancelled.store(true, Ordering::Release);
            },
            _ = terminate.recv() => {
                let _ = exit_signal.compare_exchange(0, 143, Ordering::AcqRel, Ordering::Acquire);
                cancelled.store(true, Ordering::Release);
            },
        }
        #[cfg(not(unix))]
        tokio::select! {
            result = &mut owner => break result,
            signal = &mut interrupt, if !cancelled.load(Ordering::Acquire) => {
                exit_signal.store(if signal.is_ok() { 130 } else { 4 }, Ordering::Release);
                cancelled.store(true, Ordering::Release);
            },
        }
    };
    let result = match joined {
        Ok(result) => result,
        Err(error) => failure(
            &request,
            &AppError::Internal(format!("runtime preparation owner failed: {error}")),
        ),
    };
    deliver(result, cli.json)
}

fn owned_prepare(
    request: &Request,
    plan: &RuntimePreparationPlan,
    cancelled: &Arc<AtomicBool>,
    exit_signal: &AtomicU8,
) -> AppResult<Value> {
    let data_dir = request
        .data_dir
        .as_ref()
        .expect("explicit directory checked");
    let _directory_guard = ensure_private_product_data_directory(data_dir)?;
    let data_dir = ai_security_scanner_lib::internal_paths::canonicalize(data_dir)?;
    let _lease = DataDirectoryExclusiveLease::acquire(&data_dir)?;
    let receipt_dir = data_dir.join("runtime-preparations");
    let _receipt_guard = ensure_private_product_data_directory(&receipt_dir)?;
    let started_at = chrono::Utc::now();
    let prepared = if cancelled.load(Ordering::Acquire) {
        plan.report_for_failure(request.args.offline, "Preparation was cancelled.", true)
    } else {
        let resolved = (|| {
            let managed =
                match open_managed_runtime_manager(&data_dir, request.managed_bundle.as_deref()) {
                    Ok(manager) => Some(manager),
                    Err(error) if request.managed_bundle.is_some() => return Err(error),
                    Err(_) => None,
                };
            resolve_preparation_runtime(
                managed.as_ref(),
                request.local_images.as_deref(),
                !request.args.offline,
                cancelled,
            )
        })();
        match resolved {
            Ok(runtime) => plan.prepare(&runtime, request.args.offline, cancelled),
            Err(error) => plan.report_for_failure(
                request.args.offline,
                &error.to_string(),
                cancelled.load(Ordering::Acquire),
            ),
        }
    };
    let mut result = serde_json::to_value(prepared)?;
    let signal = exit_signal.load(Ordering::Acquire);
    let exit_code = if signal != 0 {
        signal
    } else if result["ready"] == true {
        0
    } else {
        4
    };
    if signal != 0 {
        result["ready"] = json!(false);
    }
    let receipt_path = receipt_dir.join(format!("{}.json", request.id));
    result["operation"] = json!("runtime.prepare");
    result["request_id"] = json!(request.id);
    result["command_outcome"] = json!(match exit_code {
        0 => "completed",
        130 | 143 => "cancelled",
        _ => "failed",
    });
    result["exit_code"] = json!(exit_code);
    result["target_contact"] = json!(false);
    result["started_at"] = json!(started_at);
    result["completed_at"] = json!(chrono::Utc::now());
    result["receipt_path"] = json!(receipt_path);
    result["receipt_sha256"] = json!(hex::encode(Sha256::digest(serde_json::to_vec(&result)?)));
    // A final stdout failure cannot erase the already committed observation.
    // Preparation receipts are observations, never permission to start a scan.
    let bytes = serde_json::to_vec_pretty(&result)?;
    let mut temporary = tempfile::NamedTempFile::new_in(&receipt_dir)?;
    temporary.write_all(&bytes)?;
    temporary.as_file().sync_all()?;
    temporary
        .persist_noclobber(&receipt_path)
        .map_err(|error| error.error)?;
    #[cfg(unix)]
    fs::File::open(&receipt_dir)?.sync_all()?;
    Ok(result)
}

fn deliver(result: Value, json_output: bool) -> u8 {
    let exit_code = result["exit_code"].as_u64().unwrap_or(4) as u8;
    if let Err(error) = print_value(&result, json_output) {
        eprintln!(
            "runtime preparation output failed: {error}; saved receipt: {}",
            result["receipt_path"]
        );
        return 4;
    }
    exit_code
}
