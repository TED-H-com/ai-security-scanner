use serde::Serialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("case not found: {0}")]
    CaseNotFound(String),
    #[error("invalid request: {0}")]
    InvalidRequest(String),
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("storage error: {0}")]
    Storage(String),
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
