use super::*;
use ai_security_scanner_lib::cloudflare_provider::source_view::OwnedContext;

pub(super) fn envelope(operation: &str) -> Value {
    json!({"schema_version":"ai-security-scanner.source-view-command/v1","type":"terminal",
        "operation":format!("provider.cloudflare.{operation}"),"request_id":null,
        "command_outcome":"completed","error_code":null,"retryable":false,"exit_code":0,
        "case_id":null,"run_id":null,"task_id":null,"session_id":null,"case_revision":null,
        "receipt":null,"result":null})
}
pub(super) fn error(mut envelope: Value, error: AppError) -> Value {
    let (code, error_code, retryable) = foreground_error_class(&error);
    envelope["command_outcome"] = json!(if code == 4 { "failed" } else { "rejected" });
    envelope["exit_code"] = json!(code);
    envelope["error_code"] = json!(error_code);
    envelope["retryable"] = json!(retryable);
    envelope["error"] = json!(error.to_string());
    envelope
}
pub(super) fn deliver(value: Value, json_output: bool) -> u8 {
    let code = value["exit_code"].as_u64().unwrap_or(4) as u8;
    let write = || -> AppResult<()> {
        use std::io::Write;
        let mut bytes = if json_output {
            serde_json::to_vec(&value)?
        } else {
            serde_json::to_vec_pretty(&value)?
        };
        bytes.push(b'\n');
        let mut stdout = std::io::stdout().lock();
        stdout.write_all(&bytes)?;
        stdout.flush()?;
        Ok(())
    };
    if let Err(error) = write() {
        use std::io::Write;
        let _ = writeln!(std::io::stderr().lock(), "provider output failed: {error}");
        return 4;
    }
    code
}
pub(super) async fn mutate<T: Send + 'static>(
    data: PathBuf,
    case_id: String,
    work: impl FnOnce(&OwnedContext<'_>) -> AppResult<T> + Send + 'static,
) -> AppResult<(Result<AppResult<T>, tokio::task::JoinError>, u8)> {
    let stopped = Arc::new(AtomicU8::new(0));
    let worker_stop = stopped.clone();
    #[cfg(unix)]
    let signals = (|| -> io::Result<_> {
        Ok((
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?,
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?,
        ))
    })();
    #[cfg(unix)]
    let (mut interrupt, mut terminate) = match signals {
        Ok(s) => s,
        Err(e) => return Err(e.into()),
    };
    #[cfg(not(unix))]
    let interrupt = tokio::signal::ctrl_c();
    #[cfg(not(unix))]
    tokio::pin!(interrupt);
    let mut worker = tokio::task::spawn_blocking(move || -> AppResult<_> {
        // Require an existing workspace; preparation cannot create a case.
        let probe = Storage::open_read_only(data.join("casework.db"))?;
        probe.get_case(&case_id)?;
        drop(probe);
        let lease = DataDirectoryExclusiveLease::acquire(&data)?;
        let storage = Storage::open(data.join("casework.db"))?;
        work(&OwnedContext {
            storage: &storage,
            data_dir: &data,
            lease: &lease,
            cancelled: Some(&worker_stop),
        })
    });
    let result = loop {
        #[cfg(unix)]
        tokio::select! {
            result = &mut worker => break result,
            _ = interrupt.recv() => { stopped.store(130,Ordering::Release); },
            _ = terminate.recv() => { stopped.store(143,Ordering::Release); },
        }
        #[cfg(not(unix))]
        tokio::select! {
            result = &mut worker => break result,
            _ = &mut interrupt, if stopped.load(Ordering::Acquire) == 0 => { stopped.store(130,Ordering::Release); },
        }
    };
    Ok((result, stopped.load(Ordering::Acquire)))
}
