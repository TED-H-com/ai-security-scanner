// Temporary roots for tests that publish read-only product data.
// Cleanup runs only on drop, after the test's permission/deletion assertions.
// One file for every test target: the library declares it, the CLI unit tests
// include it and integration targets load it with `#[path]`. Keep it free of
// tests and inner attributes; its tests are in test_temp_tests.rs.
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub struct TempDir {
    path: PathBuf,
}

pub fn tempdir() -> io::Result<TempDir> {
    TempDir::new()
}

impl TempDir {
    pub fn new() -> io::Result<Self> {
        tempfile::tempdir().map(Self::from)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

// Keep tempfile's naming, prefix, permissions and parent-directory options.
impl From<tempfile::TempDir> for TempDir {
    fn from(directory: tempfile::TempDir) -> Self {
        Self {
            path: directory.keep(),
        }
    }
}

impl AsRef<Path> for TempDir {
    fn as_ref(&self) -> &Path {
        self.path()
    }
}

struct CleanupError {
    path: PathBuf,
    error: io::Error,
}

fn remove_tree(path: &Path) -> Result<(), CleanupError> {
    let at_path = |error| CleanupError {
        path: path.to_path_buf(),
        error,
    };
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(at_path(error)),
    };
    let is_link = metadata.file_type().is_symlink();
    #[cfg(windows)]
    let is_link = {
        use std::os::windows::fs::MetadataExt;
        // Junctions and other reparse points must not be traversed either.
        is_link || metadata.file_attributes() & 0x400 != 0
    };
    if is_link {
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            // symlink_metadata reports a link, even for directory symlinks.
            if metadata.file_attributes() & 0x10 != 0 {
                return fs::remove_dir(path).map_err(at_path);
            }
        }
        return fs::remove_file(path).map_err(at_path);
    }
    #[cfg(unix)]
    if metadata.is_dir() {
        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode() | 0o700;
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(at_path)?;
    }
    #[cfg(windows)]
    {
        let mut permissions = metadata.permissions();
        permissions.set_readonly(false);
        fs::set_permissions(path, permissions).map_err(at_path)?;
    }
    if metadata.is_dir() {
        for entry in fs::read_dir(path).map_err(at_path)? {
            remove_tree(&entry.map_err(at_path)?.path())?;
        }
        fs::remove_dir(path).map_err(at_path)
    } else {
        fs::remove_file(path).map_err(at_path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let result = remove_tree(&self.path);
        #[cfg(windows)]
        let result = {
            let mut result = result;
            for _ in 0..3 {
                if result.is_ok() {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(25));
                result = remove_tree(&self.path);
            }
            result
        };
        if let Err(failure) = result {
            let message = format!(
                "temporary root {} could not be removed; first failed entry {}: {}",
                self.path.display(),
                failure.path.display(),
                failure.error
            );
            #[cfg(unix)]
            if !std::thread::panicking() {
                panic!("{message}");
            }
            eprintln!("warning: {message}");
        }
    }
}
