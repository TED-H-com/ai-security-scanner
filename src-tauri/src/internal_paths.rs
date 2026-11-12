//! Canonical paths used by new product internals and child processes.
use std::path::{Path, PathBuf};

/// Preserve canonical identity while using an ordinary Windows path whenever safe.
/// User input must still pass its own validation before reaching this helper.
pub fn canonicalize(path: impl AsRef<Path>) -> std::io::Result<PathBuf> {
    dunce::canonicalize(path)
}
