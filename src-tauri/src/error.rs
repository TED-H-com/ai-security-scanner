use serde::Serialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    #[error(
        "This audit was restored from an archive and is read-only history. Start a new audit with current authorization."
    )]
    RestoredSessionInert,
    #[error(
        "This audit was explicitly terminated and is read-only history. Start a new audit with current authorization."
    )]
    RunTerminated,
    #[error("{message}")]
    ArchiveProvider {
        code: &'static str,
        message: &'static str,
    },
    #[error("invalid request: case archive: archive parent has an untrusted writable ancestor")]
    UnsafeArchiveParent,
    #[error(
        "temporary directory has an untrusted writable ancestor; point TMPDIR at a private directory"
    )]
    UnsafeTemporaryDirectory,
    #[error("Cloudflare package contains an unsafe filesystem entry")]
    UnsafeFilesystemEntry,
    #[error("case not found: {0}")]
    CaseNotFound(String),
    #[error("invalid request: {0}")]
    InvalidRequest(String),
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("request conflict: {0}")]
    RequestConflict(String),
    #[error("data directory busy: {0}")]
    DataDirectoryBusy(String),
    #[error("storage error: {0}")]
    Storage(String),
    #[error("storage error: {0}")]
    InvalidCloudflareRecord(String),
    #[error("engine registry error: {0}")]
    EngineRegistry(String),
    #[error("runtime error: {0}")]
    Runtime(String),
    #[error("operation is not authorized: {0}")]
    NotAuthorized(String),
    #[error("operation is not available yet: {0}")]
    NotAvailable(String),
    #[error("internal error: {0}")]
    Internal(String),
}

/// Stable foreground command exit code, error code, and retryability.
pub fn foreground_error_class(error: &AppError) -> (u8, &'static str, bool) {
    match error {
        AppError::RunTerminated => (2, "run_terminated", false),
        AppError::RestoredSessionInert => (2, "restored_session_inert", false),
        AppError::ArchiveProvider { code, .. } => (1, code, false),
        AppError::UnsafeTemporaryDirectory => (2, "unsafe_temporary_directory", false),
        AppError::UnsafeArchiveParent => (2, "invalid_request", false),
        AppError::UnsafeFilesystemEntry => (2, "unsafe_filesystem_entry", false),
        AppError::DataDirectoryBusy(_) => (3, "data_directory_busy", true),
        AppError::Conflict(_) => (3, "conflict", true),
        AppError::RequestConflict(_) => (3, "request_conflict", false),
        AppError::CaseNotFound(_) => (2, "case_not_found", false),
        AppError::InvalidRequest(_) => (2, "invalid_request", false),
        AppError::NotAuthorized(_) => (2, "not_authorized", false),
        AppError::NotAvailable(_) => (2, "not_available", false),
        AppError::Storage(_) | AppError::InvalidCloudflareRecord(_) => (4, "storage_failed", true),
        AppError::EngineRegistry(_) => (4, "engine_registry_failed", false),
        AppError::Runtime(_) => (4, "runtime_failed", true),
        AppError::Internal(_) => (4, "internal_failed", true),
    }
}

impl Serialize for AppError {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl From<rusqlite::Error> for AppError {
    fn from(value: rusqlite::Error) -> Self {
        if matches!(
            value.sqlite_error_code(),
            Some(rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked)
        ) {
            return Self::DataDirectoryBusy("case database is busy".into());
        }
        Self::Storage(value.to_string())
    }
}

impl From<serde_json::Error> for AppError {
    fn from(value: serde_json::Error) -> Self {
        Self::Storage(value.to_string())
    }
}

impl From<std::io::Error> for AppError {
    fn from(value: std::io::Error) -> Self {
        Self::Internal(value.to_string())
    }
}

pub type AppResult<T> = Result<T, AppError>;
