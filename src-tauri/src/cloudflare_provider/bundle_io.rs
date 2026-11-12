//! Root-relative reads. Every ancestor is opened without following links.
use crate::case_archive_io::validate_path;
use crate::error::{AppError, AppResult};
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::time::SystemTime;

fn invalid() -> AppError {
    AppError::InvalidRequest(
        "Cloudflare bundle contains an unsafe or changed filesystem entry".into(),
    )
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Stamp {
    identity: (u64, u64),
    length: u64,
    modified: SystemTime,
    changed: (i64, i64),
}

fn stamp(file: &File, directory: bool) -> AppResult<Stamp> {
    let metadata = file.metadata()?;
    if (directory && !metadata.is_dir()) || (!directory && !metadata.is_file()) {
        return Err(AppError::UnsafeFilesystemEntry);
    }
    #[cfg(unix)]
    let (identity, changed) = {
        use std::os::unix::fs::MetadataExt;
        if !directory && metadata.nlink() != 1 {
            return Err(AppError::UnsafeFilesystemEntry);
        }
        (
            (metadata.dev(), metadata.ino()),
            (metadata.ctime(), metadata.ctime_nsec()),
        )
    };
    #[cfg(windows)]
    let (identity, changed) = {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Storage::FileSystem::{
            BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
        };
        let mut info = BY_HANDLE_FILE_INFORMATION::default();
        // SAFETY: file owns the live handle; info is a correctly sized output.
        if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &raw mut info) } == 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        if info.dwFileAttributes & 0x400 != 0 || (!directory && info.nNumberOfLinks != 1) {
            return Err(AppError::UnsafeFilesystemEntry);
        }
        (
            (
                u64::from(info.dwVolumeSerialNumber),
                (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
            ),
            (0, 0),
        )
    };
    #[cfg(not(any(unix, windows)))]
    return Err(AppError::NotAvailable(
        "safe provider bundle reads are unavailable on this platform".into(),
    ));
    #[cfg(any(unix, windows))]
    Ok(Stamp {
        identity,
        length: metadata.len(),
        modified: metadata.modified()?,
        changed,
    })
}

// On Unix, openat anchors every lookup to the already opened directory. On
// Windows, held directory handles deny deletion/rename while child paths open.
fn open_child(
    parent: &File,
    parent_path: &Path,
    name: &std::ffi::OsStr,
    directory: bool,
) -> AppResult<File> {
    #[cfg(unix)]
    {
        use std::os::fd::{AsRawFd, FromRawFd};
        use std::os::unix::ffi::OsStrExt;
        let _ = parent_path;
        let name = std::ffi::CString::new(name.as_bytes()).map_err(|_| invalid())?;
        let flags = libc::O_RDONLY
            | libc::O_NOFOLLOW
            | libc::O_NONBLOCK
            | libc::O_CLOEXEC
            | if directory { libc::O_DIRECTORY } else { 0 };
        // SAFETY: parent is live, name is terminated, and openat creates a new fd.
        let fd = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags) };
        if fd < 0 {
            let error = std::io::Error::last_os_error();
            if matches!(error.raw_os_error(), Some(libc::ELOOP | libc::ENOTDIR)) {
                return Err(AppError::UnsafeFilesystemEntry);
            }
            return Err(error.into());
        }
        // SAFETY: this call exclusively adopts the successfully opened fd.
        let file = unsafe { File::from_raw_fd(fd) };
        stamp(&file, directory)?;
        Ok(file)
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ, FILE_SHARE_WRITE,
        };
        let _ = parent;
        let mut options = OpenOptions::new();
        if directory {
            options
                .access_mode(FILE_READ_ATTRIBUTES)
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE);
        } else {
            options.read(true).share_mode(FILE_SHARE_READ);
        }
        let file = options
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
            .open(parent_path.join(name))?;
        stamp(&file, directory)?;
        Ok(file)
    }
    #[cfg(not(any(unix, windows)))]
    Err(AppError::NotAvailable(
        "safe provider bundle reads are unavailable on this platform".into(),
    ))
}

pub(crate) struct BundleRoot {
    path: PathBuf,
    // Retain the selected root's entire namespace on Windows, too.
    ancestors: Vec<File>,
    root_identity: (u64, u64),
    reads: BTreeMap<String, Stamp>,
    inventories: BTreeMap<String, Stamp>,
    read_identities: BTreeMap<(u64, u64), String>,
}

impl BundleRoot {
    pub fn check_inventory(
        &mut self,
        expected: &std::collections::BTreeSet<String>,
    ) -> AppResult<()> {
        let mut pending = vec![String::new()];
        let mut seen = std::collections::BTreeSet::new();
        let mut dirs = std::collections::BTreeSet::new();
        for path in expected {
            for (i, _) in path.match_indices('/') {
                dirs.insert(path[..i].to_owned());
            }
        }
        while let Some(prefix) = pending.pop() {
            self.enumerate(&prefix, |name| {
                let relative = if prefix.is_empty() {
                    name.to_owned()
                } else {
                    format!("{prefix}/{name}")
                };
                if dirs.remove(&relative) {
                    pending.push(relative);
                } else if expected.contains(&relative) && seen.insert(relative) {
                    // Indexed files were read through no-follow regular-file handles.
                } else {
                    return Err(invalid());
                }
                Ok(())
            })?;
        }
        if seen != *expected || !dirs.is_empty() {
            return Err(invalid());
        }
        Ok(())
    }

    pub fn open(path: &Path) -> AppResult<Self> {
        let path = std::path::absolute(path)?;
        let mut base = PathBuf::new();
        let mut ancestors: Vec<File> = Vec::new();
        for component in path.components() {
            match component {
                Component::Prefix(prefix) => {
                    #[cfg(windows)]
                    if !matches!(
                        prefix.kind(),
                        std::path::Prefix::Disk(_) | std::path::Prefix::VerbatimDisk(_)
                    ) {
                        return Err(invalid());
                    }
                    base.push(prefix.as_os_str());
                }
                Component::RootDir => {
                    base.push(component.as_os_str());
                    let mut options = OpenOptions::new();
                    options.read(true);
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::OpenOptionsExt;
                        options
                            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC);
                    }
                    #[cfg(windows)]
                    {
                        use std::os::windows::fs::OpenOptionsExt;
                        use windows_sys::Win32::Storage::FileSystem::*;
                        options
                            .access_mode(FILE_READ_ATTRIBUTES)
                            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
                            .custom_flags(
                                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                            );
                    }
                    let file = options.open(&base)?;
                    stamp(&file, true)?;
                    ancestors.push(file);
                }
                Component::Normal(name) => {
                    #[cfg(windows)]
                    validate_path(name.to_str().ok_or_else(invalid)?)?;
                    let parent = ancestors.last().ok_or_else(invalid)?;
                    let file = open_child(parent, &base, name, true)?;
                    base.push(name);
                    ancestors.push(file);
                }
                _ => return Err(invalid()),
            }
            if ancestors.len() > 128 {
                return Err(invalid());
            }
        }
        let root_identity = stamp(ancestors.last().ok_or_else(invalid)?, true)?.identity;
        Ok(Self {
            path,
            ancestors,
            root_identity,
            reads: BTreeMap::new(),
            inventories: BTreeMap::new(),
            read_identities: BTreeMap::new(),
        })
    }

    fn open_member(&self, relative: &str) -> AppResult<(File, Vec<File>)> {
        validate_path(relative)?;
        let parts = relative.split('/').collect::<Vec<_>>();
        if parts.len() > 32 {
            return Err(invalid());
        }
        let mut path = self.path.clone();
        let mut directories = Vec::new();
        for (index, part) in parts.iter().enumerate() {
            let parent = directories
                .last()
                .unwrap_or_else(|| self.ancestors.last().unwrap());
            let directory = index + 1 != parts.len();
            let file = open_child(parent, &path, std::ffi::OsStr::new(part), directory)?;
            if !directory {
                return Ok((file, directories));
            }
            path.push(part);
            directories.push(file);
        }
        Err(invalid())
    }

    fn open_directory(&self, relative: &str) -> AppResult<(File, Vec<File>)> {
        let mut path = self.path.clone();
        let mut guards = Vec::new();
        if !relative.is_empty() {
            validate_path(relative)?;
            if relative.split('/').count() > 32 {
                return Err(invalid());
            }
            for part in relative.split('/') {
                let parent = guards
                    .last()
                    .unwrap_or_else(|| self.ancestors.last().unwrap());
                let file = open_child(parent, &path, std::ffi::OsStr::new(part), true)?;
                path.push(part);
                guards.push(file);
            }
        }
        let file = guards
            .last()
            .unwrap_or_else(|| self.ancestors.last().unwrap())
            .try_clone()?;
        Ok((file, guards))
    }

    /// Stream names from the anchored directory; callers can reject the first surplus entry.
    /// Only users of this inventory API acquire inventory stability checks.
    pub fn enumerate(
        &mut self,
        relative: &str,
        mut visit: impl FnMut(&str) -> AppResult<()>,
    ) -> AppResult<()> {
        let (file, _guards) = self.open_directory(relative)?;
        let before = stamp(&file, true)?;
        #[cfg(unix)]
        {
            use std::os::fd::{AsRawFd, IntoRawFd};
            // A separate open description avoids sharing the enumeration offset.
            let directory = open_child(&file, &self.path, std::ffi::OsStr::new("."), true)?;
            let fd = directory.as_raw_fd();
            // SAFETY: fd is a live directory; ownership transfers only on success.
            let stream = unsafe { libc::fdopendir(fd) };
            if stream.is_null() {
                return Err(std::io::Error::last_os_error().into());
            }
            let _ = directory.into_raw_fd();
            struct Stream(*mut libc::DIR);
            impl Drop for Stream {
                fn drop(&mut self) {
                    // SAFETY: this guard exclusively owns the stream.
                    unsafe {
                        libc::closedir(self.0);
                    }
                }
            }
            let stream = Stream(stream);
            loop {
                // SAFETY: stream is live; rewind/error state belongs to this thread.
                #[cfg(any(target_os = "linux", target_os = "android"))]
                unsafe {
                    *libc::__errno_location() = 0;
                }
                #[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
                unsafe {
                    *libc::__error() = 0;
                }
                // SAFETY: returned entry remains valid until the next readdir call.
                let entry = unsafe { libc::readdir(stream.0) };
                if entry.is_null() {
                    let error = std::io::Error::last_os_error();
                    if error.raw_os_error().unwrap_or(0) != 0 {
                        return Err(error.into());
                    }
                    break;
                }
                // SAFETY: d_name is a terminated directory-entry name.
                let name = unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) };
                let name = name.to_str().map_err(|_| invalid())?;
                if name != "." && name != ".." {
                    visit(name)?;
                }
            }
        }
        #[cfg(windows)]
        for entry in std::fs::read_dir(self.path.join(relative))? {
            let name = entry?.file_name();
            visit(name.to_str().ok_or_else(invalid)?)?;
        }
        if stamp(&file, true)? != before {
            return Err(invalid());
        }
        if self
            .inventories
            .get(relative)
            .is_some_and(|old| old != &before)
        {
            return Err(invalid());
        }
        self.inventories.insert(relative.into(), before);
        Ok(())
    }

    pub fn read(&mut self, relative: &str, maximum: u64) -> AppResult<Vec<u8>> {
        let (mut file, _directories) = self.open_member(relative)?;
        let before = stamp(&file, false)?;
        if self
            .read_identities
            .get(&before.identity)
            .is_some_and(|path| path != relative)
        {
            return Err(invalid());
        }
        if before.length > maximum {
            return Err(invalid());
        }
        let mut bytes = Vec::new();
        (&mut file).take(maximum + 1).read_to_end(&mut bytes)?;
        if before.length != bytes.len() as u64 || stamp(&file, false)? != before {
            return Err(invalid());
        }
        let (reopened, _guard) = self.open_member(relative)?;
        if stamp(&reopened, false)? != before {
            return Err(invalid());
        }
        if self.reads.get(relative).is_some_and(|old| old != &before) {
            return Err(invalid());
        }
        self.read_identities
            .insert(before.identity, relative.to_owned());
        self.reads.insert(relative.to_owned(), before);
        Ok(bytes)
    }

    pub fn verify_unchanged(&self) -> AppResult<()> {
        let current_root = Self::open(&self.path)?;
        if current_root.root_identity != self.root_identity {
            return Err(invalid());
        }
        for (relative, before) in &self.inventories {
            let (file, _guards) = self.open_directory(relative)?;
            if &stamp(&file, true)? != before {
                return Err(invalid());
            }
        }
        for (relative, before) in &self.reads {
            let (file, _directories) = self.open_member(relative)?;
            if &stamp(&file, false)? != before {
                return Err(invalid());
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn enumerated_directory_detects_added_and_removed_entries() {
        for remove in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let root = crate::internal_paths::canonicalize(temp.path()).unwrap();
            std::fs::create_dir(root.join("tree")).unwrap();
            std::fs::write(root.join("tree/file"), b"safe").unwrap();
            let mut reader = BundleRoot::open(&root).unwrap();
            reader.enumerate("tree", |_| Ok(())).unwrap();
            reader.verify_unchanged().unwrap();
            if remove {
                std::fs::remove_file(root.join("tree/file")).unwrap();
            } else {
                std::fs::write(root.join("tree/extra"), b"extra").unwrap();
            }
            assert!(reader.verify_unchanged().is_err());
        }
    }

    #[test]
    fn reads_detect_later_content_and_root_replacement() {
        let temporary = tempfile::tempdir().unwrap();
        let root = crate::internal_paths::canonicalize(temporary.path()).unwrap();
        std::fs::write(root.join("file"), b"a").unwrap();
        let mut reader = BundleRoot::open(&root).unwrap();
        assert_eq!(reader.read("file", 1).unwrap(), b"a");
        std::fs::write(root.join("file"), b"changed").unwrap();
        assert!(reader.verify_unchanged().is_err());
        assert!(reader.read("../file", 10).is_err());
        assert!(reader.read("file", 1).is_err());
    }
    #[cfg(unix)]
    #[test]
    fn root_parent_member_symlinks_hardlinks_and_pipes_are_refused() {
        use std::os::unix::fs::symlink;
        let temporary = tempfile::tempdir().unwrap();
        let root = crate::internal_paths::canonicalize(temporary.path()).unwrap();
        std::fs::create_dir(root.join("real")).unwrap();
        std::fs::write(root.join("real/file"), b"[]").unwrap();
        symlink(root.join("real"), root.join("redirect")).unwrap();
        assert!(BundleRoot::open(&root.join("redirect")).is_err());
        let mut reader = BundleRoot::open(&root).unwrap();
        assert!(reader.read("redirect/file", 10).is_err());
        symlink(root.join("real/file"), root.join("link")).unwrap();
        assert!(reader.read("link", 10).is_err());
        std::fs::hard_link(root.join("real/file"), root.join("hard")).unwrap();
        assert!(reader.read("hard", 10).is_err());
        let pipe =
            std::ffi::CString::new(root.join("pipe").as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: the string is terminated and names an owned test entry.
        assert_eq!(unsafe { libc::mkfifo(pipe.as_ptr(), 0o600) }, 0);
        assert!(reader.read("pipe", 10).is_err());
        std::fs::create_dir(root.join("selected")).unwrap();
        let selected = BundleRoot::open(&root.join("selected")).unwrap();
        crate::case_archive_io::rename_entry_no_replace(
            &root.join("selected"),
            &root.join("moved"),
        )
        .unwrap();
        std::fs::create_dir(root.join("selected")).unwrap();
        assert!(selected.verify_unchanged().is_err());
    }
}
