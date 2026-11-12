use std::path::{Path, PathBuf};

pub fn canonical(path: impl AsRef<Path>) -> PathBuf {
    ai_security_scanner_lib::internal_paths::canonicalize(path).unwrap()
}
