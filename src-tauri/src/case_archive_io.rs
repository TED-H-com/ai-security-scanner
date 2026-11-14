//! Bounded archive transport. Hashes establish internal byte consistency,
//! never authorship, scan authorization, or security-finding correctness.
//!
//! The wire format is one gzip member (without optional header fields) holding
//! USTAR regular files, with archive-manifest.json first. A bounded GNU LongName
//! record may immediately precede one regular file when USTAR cannot encode its
//! path. We parse every header ourselves; tar::unpack is deliberately unused.

use crate::error::{AppError, AppResult};
use chrono::{DateTime, Utc};
use flate2::{Compression, GzBuilder, bufread::GzDecoder};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::time::SystemTime;
use tempfile::NamedTempFile;
#[cfg(unix)]
use tempfile::TempDir;

pub const ARCHIVE_SCHEMA: &str = "ai-security-scanner.archive/v1";
pub const MANIFEST_PATH: &str = "archive-manifest.json";
pub const MAX_ARCHIVE_ENTRIES: usize = 100_000;
const MAX_ARCHIVE_DIRECTORIES: usize = MAX_ARCHIVE_ENTRIES;
pub const MAX_ARCHIVE_ENTRY_BYTES: u64 = 512 * 1024 * 1024;
pub const MAX_ARCHIVE_MANIFEST_BYTES: u64 = 16 * 1024 * 1024;
pub const MAX_ARCHIVE_DECOMPRESSED_BYTES: u64 = 50 * 1024 * 1024 * 1024;
const MAX_ARCHIVE_COMPRESSED_BYTES: u64 = MAX_ARCHIVE_DECOMPRESSED_BYTES + 128 * 1024 * 1024;
const MAX_TAR_TRAILER_BYTES: usize = 10 * 1024;
const MAX_PATH_BYTES: usize = 4096;
const GNU_LONG_NAME: &str = "././@LongLink";
const LONG_NAME_PLACEHOLDER: &str = "__archive_long_path__";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ArchiveEntry {
    pub path: String,
    pub sha256: String,
    pub byte_length: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchiveManifest {
    pub schema_version: String,
    pub archive_id: String,
    pub created_at: DateTime<Utc>,
    pub producer_version: String,
    pub case_id: String,
    pub source_case_revision: i64,
    pub case_document_sha256: String,
    pub raw_artifacts_included: bool,
    pub source_snapshots_included: bool,
    pub omissions: Vec<String>,
    pub entries: Vec<ArchiveEntry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_capabilities: Vec<String>,
}

#[derive(Debug)]
pub struct VerifiedArchive {
    directory: PrivateArchiveDirectory,
    // Drop the owned extraction tree before releasing its namespace guard.
    _parent_guard: ArchiveParentGuard,
    pub manifest: ArchiveManifest,
    pub archive_sha256: String,
}

impl VerifiedArchive {
    pub fn root(&self) -> &Path {
        self.directory.path()
    }

    pub fn entry_path(&self, path: &str) -> AppResult<PathBuf> {
        validate_path(path)?;
        if !self.manifest.entries.iter().any(|entry| entry.path == path) {
            return Err(invalid("entry is absent from the verified manifest"));
        }
        Ok(self.directory.path().join(path))
    }
}

fn invalid(message: &str) -> AppError {
    AppError::InvalidRequest(format!("case archive: {message}"))
}

pub(crate) fn temporary_directory_error(error: AppError) -> AppError {
    match error {
        AppError::UnsafeArchiveParent => AppError::UnsafeTemporaryDirectory,
        other => other,
    }
}

/// Keep the existing staging/publication namespace verified for its lifetime.
/// The caller must use this canonical path for subsequent child operations.
#[derive(Debug)]
pub(crate) struct ArchiveParentGuard {
    path: PathBuf,
    #[cfg(unix)]
    _directories: Vec<File>,
    #[cfg(windows)]
    _namespace: crate::managed_runtime::PrivateProductDataDirectoryGuard,
    #[cfg(windows)]
    _existing_directory: File,
}

impl ArchiveParentGuard {
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// Link and unlink relative to pinned directories on Unix. Windows namespace
    /// guards prevent parent replacement through deny-delete sharing.
    pub(crate) fn publish_private_file(
        &self,
        source: &Path,
        name: &std::ffi::OsStr,
    ) -> AppResult<()> {
        let staged = guard_archive_parent(
            source
                .parent()
                .ok_or_else(|| invalid("missing staging parent"))?,
        )?;
        staged.verify_unchanged()?;
        self.verify_unchanged()?;
        #[cfg(unix)]
        let (link, unlink_source, unlink_target) = {
            use std::os::{fd::AsRawFd, unix::ffi::OsStrExt};
            let from = std::ffi::CString::new(source.file_name().unwrap().as_bytes())
                .map_err(|_| invalid("invalid staging name"))?;
            let to = std::ffi::CString::new(name.as_bytes())
                .map_err(|_| invalid("invalid destination name"))?;
            let source_fd = staged._directories.last().unwrap().as_raw_fd();
            let target_fd = self._directories.last().unwrap().as_raw_fd();
            let syscall = |code| {
                if code == 0 {
                    Ok(())
                } else {
                    Err(io::Error::last_os_error())
                }
            };
            // SAFETY: guards own the directory descriptors; C strings live through each call.
            let link = syscall(unsafe {
                libc::linkat(source_fd, from.as_ptr(), target_fd, to.as_ptr(), 0)
            });
            let unlink_source =
                move || syscall(unsafe { libc::unlinkat(source_fd, from.as_ptr(), 0) });
            let unlink_target =
                move || syscall(unsafe { libc::unlinkat(target_fd, to.as_ptr(), 0) });
            (link, unlink_source, unlink_target)
        };
        #[cfg(not(unix))]
        let (link, unlink_source, unlink_target) = (
            fs::hard_link(source, self.path.join(name)),
            || fs::remove_file(source),
            || fs::remove_file(self.path.join(name)),
        );
        link.map_err(|e| {
            if e.kind() == io::ErrorKind::AlreadyExists {
                invalid("destination already exists")
            } else {
                e.into()
            }
        })?;
        if let Err(e) = unlink_source() {
            let _ = unlink_target();
            return Err(e.into());
        }
        if let Err(e) = self.verify_unchanged() {
            let _ = unlink_target();
            return Err(e);
        }
        #[cfg(unix)]
        self._directories.last().unwrap().sync_all()?;
        Ok(())
    }

    /// Recheck every pinned ancestor before publishing through this namespace.
    pub(crate) fn verify_unchanged(&self) -> AppResult<()> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            for (path, pinned) in self
                .path
                .ancestors()
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .zip(&self._directories)
            {
                let current = fs::symlink_metadata(path)?;
                let original = pinned.metadata()?;
                if !current.is_dir()
                    || current.dev() != original.dev()
                    || current.ino() != original.ino()
                {
                    return Err(invalid("destination parent changed"));
                }
            }
        }
        // Windows guards deny delete sharing for the entire namespace.
        Ok(())
    }
}

/// An owned private staging directory. Keep the parent guard until cleanup so
/// a caller cannot accidentally shorten the checked namespace's lifetime.
#[derive(Debug)]
pub(crate) struct PrivateArchiveDirectory {
    path: PathBuf,
    #[cfg(unix)]
    _directory: TempDir,
    _parent_guard: ArchiveParentGuard,
}

impl PrivateArchiveDirectory {
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(windows)]
impl Drop for PrivateArchiveDirectory {
    fn drop(&mut self) {
        // The parent namespace remains pinned while this owned tree is removed.
        // A published tree no longer exists at the old staging path.
        let _ = fs::remove_dir_all(&self.path);
    }
}

/// Create an owned directory with private permissions from the first instant
/// it exists. The existing parent is verified, never repaired or created.
pub(crate) fn private_tempdir_in(
    parent: &Path,
    prefix: &str,
) -> AppResult<PrivateArchiveDirectory> {
    validate_path(prefix)?;
    if prefix.contains('/') {
        return Err(invalid(
            "temporary-directory prefix must be a single component",
        ));
    }
    let parent_guard = guard_archive_parent(parent)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::Builder::new()
            .prefix(prefix)
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir_in(parent_guard.path())?;
        make_private(directory.path(), true)?;
        Ok(PrivateArchiveDirectory {
            path: directory.path().to_owned(),
            _directory: directory,
            _parent_guard: parent_guard,
        })
    }
    #[cfg(windows)]
    {
        for _ in 0..16 {
            let name = format!("{prefix}{}", uuid::Uuid::new_v4());
            validate_path(&name)?;
            let path = parent_guard.path().join(name);
            match fs::symlink_metadata(&path) {
                Ok(_) => continue,
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
            // This creates an absent final component atomically with an
            // explicit TokenUser owner and protected current-user-only ACL.
            let created = crate::managed_runtime::ensure_private_product_data_directory(
                &fs::canonicalize(parent_guard.path())?.join(path.file_name().unwrap()),
            )?;
            if !created.was_created() {
                // A competing creator owns this candidate: do not adopt it,
                // change its ACL, or later delete it.
                continue;
            }
            // Release the final-component no-delete-sharing handle before
            // adopting cleanup ownership; the parent remains guarded.
            drop(created);
            let directory = PrivateArchiveDirectory {
                path,
                _parent_guard: parent_guard,
            };
            make_private(directory.path(), true)?;
            return Ok(directory);
        }
        Err(invalid(
            "could not create a unique private archive directory",
        ))
    }
    #[cfg(not(any(unix, windows)))]
    Err(AppError::NotAvailable(
        "private archive staging is unavailable on this platform".into(),
    ))
}

/// Verify an existing real directory without creating or repairing it. A
/// private child cannot protect its name from an untrusted writable ancestor.
pub(crate) fn guard_archive_parent(path: &Path) -> AppResult<ArchiveParentGuard> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(invalid("archive parent must be an existing real directory"));
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ, FILE_SHARE_WRITE, READ_CONTROL,
        };
        if metadata.file_attributes() & 0x400 != 0 {
            return Err(invalid("archive parent must not be a reparse point"));
        }
        // Pin the already existing final component without delete sharing
        // before invoking the managed namespace verifier's existing-root path.
        let existing_directory = OpenOptions::new()
            .access_mode(FILE_READ_ATTRIBUTES | READ_CONTROL)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)?;
        let pinned = existing_directory.metadata()?;
        if !pinned.is_dir() || pinned.file_attributes() & 0x400 != 0 {
            return Err(invalid("archive parent changed to an unsafe directory"));
        }
        let path = crate::internal_paths::canonicalize(path)?;
        // Only the released Win32 verifier receives std's extended canonical form.
        let namespace = crate::managed_runtime::ensure_private_product_data_directory(
            &fs::canonicalize(&path)?,
        )?;
        if namespace.was_created() {
            return Err(invalid("archive parent must already exist"));
        }
        Ok(ArchiveParentGuard {
            path,
            _namespace: namespace,
            _existing_directory: existing_directory,
        })
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        let path = crate::internal_paths::canonicalize(path)?;
        let ancestors = path.ancestors().collect::<Vec<_>>();
        let mut directories = Vec::with_capacity(ancestors.len());
        // SAFETY: geteuid has no arguments or memory-safety preconditions.
        let user = unsafe { libc::geteuid() };
        for ancestor in ancestors.into_iter().rev() {
            let directory = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(ancestor)?;
            let metadata = directory.metadata()?;
            if !metadata.is_dir()
                || (metadata.uid() != 0 && metadata.uid() != user)
                || (metadata.mode() & 0o022 != 0 && metadata.mode() & 0o1000 == 0)
            {
                return Err(AppError::UnsafeArchiveParent);
            }
            directories.push(directory);
        }
        Ok(ArchiveParentGuard {
            path,
            _directories: directories,
        })
    }
    #[cfg(not(any(unix, windows)))]
    Err(AppError::NotAvailable(
        "archive parent namespace verification is unavailable on this platform".into(),
    ))
}

#[cfg(test)]
fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Validate names before either archive extraction or domain-path restoration.
pub(crate) fn validate_path(path: &str) -> AppResult<()> {
    if path.is_empty()
        || path.len() > MAX_PATH_BYTES
        || path.starts_with('/')
        || path.contains('\\')
    {
        return Err(invalid("unsafe portable path"));
    }
    for component in path.split('/') {
        if component.is_empty()
            || component == "."
            || component == ".."
            || component.len() > 255
            || component.ends_with([' ', '.'])
            || component
                .chars()
                .any(|character| character.is_control() || "<>:\"|?*".contains(character))
        {
            return Err(invalid("unsafe portable path component"));
        }
        let stem = component
            .split('.')
            .next()
            .unwrap()
            .trim_end_matches(' ')
            .to_uppercase();
        if matches!(
            stem.as_str(),
            "CON" | "PRN" | "AUX" | "NUL" | "CLOCK$" | "CONIN$" | "CONOUT$"
        ) || ["COM", "LPT"].iter().any(|prefix| {
            stem.strip_prefix(prefix).is_some_and(|suffix| {
                matches!(
                    suffix,
                    "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
                )
            })
        }) {
            return Err(invalid("Windows reserved path component"));
        }
    }
    Ok(())
}

#[derive(Default)]
pub(crate) struct Paths {
    files: BTreeSet<String>,
    directories: BTreeMap<String, String>,
}

impl Paths {
    pub(crate) fn insert(&mut self, path: &str) -> AppResult<()> {
        validate_path(path)?;
        let key = path.to_lowercase();
        if self.files.contains(&key) || self.directories.contains_key(&key) {
            return Err(invalid(
                "duplicate, case-folded, or file/directory path collision",
            ));
        }
        for (offset, _) in path.match_indices('/') {
            let prefix = &path[..offset];
            let folded = prefix.to_lowercase();
            if self.files.contains(&folded)
                || self
                    .directories
                    .get(&folded)
                    .is_some_and(|existing| existing != prefix)
            {
                return Err(invalid("case-folded or file/directory path collision"));
            }
            if !self.directories.contains_key(&folded) {
                if self.directories.len() >= MAX_ARCHIVE_DIRECTORIES {
                    return Err(invalid("archive exceeds 100,000 parent directories"));
                }
                self.directories.insert(folded, prefix.into());
            }
        }
        self.files.insert(key);
        Ok(())
    }
}

/// Everything an archive may place at its top level: exactly what the archive
/// writer emits. Every other name in a restored workspace belongs to the
/// restoring core, which creates its own database, receipt and runtime state,
/// so an archive must never be able to supply one.
const ARCHIVE_ROOT_FILES: [&str; 4] = [
    "case.json",
    "original-case.json",
    "archive-index.json",
    "provider-history.json",
];
const ARCHIVE_ROOT_DIRECTORIES: [&str; 3] = ["artifacts", "exports", "report-snapshots"];

fn within_archive_layout(path: &str) -> bool {
    match path.split_once('/') {
        Some((directory, _)) => ARCHIVE_ROOT_DIRECTORIES.contains(&directory),
        None => ARCHIVE_ROOT_FILES.contains(&path),
    }
}

fn validate_manifest(manifest: &ArchiveManifest) -> AppResult<BTreeMap<&str, &ArchiveEntry>> {
    if manifest.required_capabilities.iter().any(|c| {
        !matches!(
            c.as_str(),
            "cloudflare_audit_admission/v1"
                | "provider_archive_history/v1"
                | "cloudflare_audit_terminal/v1"
        )
    }) {
        return Err(AppError::ArchiveProvider {
            code: "archive_capability_unsupported",
            message: "This archive requires an unsupported capability.",
        });
    }
    if manifest.schema_version != ARCHIVE_SCHEMA {
        return Err(invalid("unsupported archive schema"));
    }
    if manifest.archive_id.trim().is_empty()
        || manifest.case_id.trim().is_empty()
        || manifest.producer_version.trim().is_empty()
        || manifest.source_case_revision < 0
        || !valid_digest(&manifest.case_document_sha256)
    {
        return Err(invalid("invalid manifest identity or case digest"));
    }
    // The manifest itself occupies one of the 100,000 physical tar entries.
    if manifest.entries.is_empty() || manifest.entries.len() >= MAX_ARCHIVE_ENTRIES {
        return Err(invalid("manifest entry count exceeds the supported bounds"));
    }
    let mut paths = Paths::default();
    paths.insert(MANIFEST_PATH)?;
    let mut expected = BTreeMap::new();
    let mut total = 0u64;
    let mut physical_entries = 1usize;
    for entry in &manifest.entries {
        paths.insert(&entry.path)?;
        if !within_archive_layout(&entry.path) {
            return Err(invalid("entry is outside the archive layout"));
        }
        physical_entries += 1 + usize::from(needs_long_name(&entry.path));
        if physical_entries > MAX_ARCHIVE_ENTRIES {
            return Err(invalid(
                "entry count including long-name metadata exceeds 100,000",
            ));
        }
        if !valid_digest(&entry.sha256) || entry.byte_length > MAX_ARCHIVE_ENTRY_BYTES {
            return Err(invalid("invalid entry digest or entry exceeds 512 MiB"));
        }
        total = total
            .checked_add(entry.byte_length)
            .ok_or_else(|| invalid("entry size overflow"))?;
        if total > MAX_ARCHIVE_DECOMPRESSED_BYTES {
            return Err(invalid("archive exceeds 50 GiB decompressed"));
        }
        expected.insert(entry.path.as_str(), entry);
    }
    if expected
        .get("case.json")
        .is_none_or(|entry| entry.sha256 != manifest.case_document_sha256)
    {
        return Err(invalid("case.json must match case_document_sha256"));
    }
    Ok(expected)
}

/// Write a new private archive on the destination filesystem, without replacing
/// any existing path. Source bytes are streamed and checked on the same handle.
pub fn write_archive(
    manifest: &ArchiveManifest,
    files: &BTreeMap<String, PathBuf>,
    destination: &Path,
) -> AppResult<()> {
    let expected = validate_manifest(manifest)?;
    if files.len() != expected.len()
        || files
            .keys()
            .any(|path| !expected.contains_key(path.as_str()))
    {
        return Err(invalid("source files do not exactly match the manifest"));
    }
    let manifest_bytes = serde_json::to_vec(manifest)?;
    if manifest_bytes.len() as u64 > MAX_ARCHIVE_MANIFEST_BYTES {
        return Err(invalid("manifest exceeds 16 MiB"));
    }
    // Include headers, padding, and terminal blocks in the decompressed bound.
    let wire_size = manifest.entries.iter().try_fold(
        tar_size(manifest_bytes.len() as u64) + 1024,
        |total, entry| {
            total
                .checked_add(
                    tar_size(entry.byte_length)
                        + if needs_long_name(&entry.path) {
                            tar_size(entry.path.len() as u64 + 1)
                        } else {
                            0
                        },
                )
                .ok_or_else(|| invalid("archive size overflow"))
        },
    )?;
    if wire_size > MAX_ARCHIVE_DECOMPRESSED_BYTES {
        return Err(invalid("archive exceeds 50 GiB decompressed"));
    }
    let parent = destination
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let parent_guard = guard_archive_parent(parent)?;
    let parent = parent_guard.path();
    let name = destination
        .file_name()
        .ok_or_else(|| invalid("destination filename is required"))?;
    let destination = parent.join(name);
    if fs::symlink_metadata(&destination).is_ok() {
        return Err(invalid("destination already exists"));
    }
    // Keep the empty file inside a private directory until its own ACL is
    // protected, so an inherited reader cannot retain a handle before writes.
    let staging = private_tempdir_in(parent, ".scanner-archive-output-")?;
    let mut temporary = NamedTempFile::new_in(staging.path())?;
    make_private(temporary.path(), false)?;
    {
        let mut gzip = GzBuilder::new()
            .mtime(0)
            .write(temporary.as_file_mut(), Compression::default());
        write_header(&mut gzip, MANIFEST_PATH, manifest_bytes.len() as u64)?;
        gzip.write_all(&manifest_bytes)?;
        write_padding(&mut gzip, manifest_bytes.len() as u64)?;
        for (path, source) in files {
            let entry = expected[path.as_str()];
            let (mut file, before) = open_regular(source, MAX_ARCHIVE_ENTRY_BYTES)?;
            if before.length != entry.byte_length {
                return Err(invalid("source length differs from its manifest"));
            }
            write_header(&mut gzip, path, entry.byte_length)?;
            let observed = copy_exact_hashed(&mut file, &mut gzip, entry.byte_length)?;
            let mut extra = [0u8; 1];
            if file.read(&mut extra)? != 0 || observed != entry.sha256 {
                return Err(invalid("source content differs from its manifest"));
            }
            verify_unchanged(source, &file, &before)?;
            write_padding(&mut gzip, entry.byte_length)?;
        }
        gzip.write_all(&[0u8; 1024])?;
        gzip.finish()?;
    }
    temporary.as_file().sync_all()?;
    temporary.persist_noclobber(&destination).map_err(|error| {
        invalid(&format!(
            "could not publish without overwrite: {}",
            error.error
        ))
    })?;
    sync_directory(parent)?;
    Ok(())
}

fn tar_size(length: u64) -> u64 {
    512 + length.div_ceil(512) * 512
}

fn write_header(writer: &mut impl Write, path: &str, length: u64) -> AppResult<()> {
    validate_path(path)?;
    if needs_long_name(path) {
        let metadata_length = path.len() as u64 + 1;
        write_raw_header(
            writer,
            GNU_LONG_NAME,
            metadata_length,
            tar::EntryType::GNULongName,
        )?;
        writer.write_all(path.as_bytes())?;
        writer.write_all(&[0])?;
        write_padding(writer, metadata_length)?;
        write_raw_header(
            writer,
            LONG_NAME_PLACEHOLDER,
            length,
            tar::EntryType::Regular,
        )
    } else {
        write_raw_header(writer, path, length, tar::EntryType::Regular)
    }
}

fn needs_long_name(path: &str) -> bool {
    tar::Header::new_ustar().set_path(path).is_err()
}

fn write_raw_header(
    writer: &mut impl Write,
    path: &str,
    length: u64,
    kind: tar::EntryType,
) -> AppResult<()> {
    let mut header = tar::Header::new_ustar();
    if kind == tar::EntryType::GNULongName {
        // This fixed marker is metadata, never an extraction destination.
        header.as_mut_bytes()[..GNU_LONG_NAME.len()].copy_from_slice(GNU_LONG_NAME.as_bytes());
    } else {
        header
            .set_path(path)
            .map_err(|_| invalid("invalid USTAR entry path"))?;
    }
    header.set_entry_type(kind);
    header.set_mode(0o600);
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(0);
    header.set_size(length);
    header.set_cksum();
    writer.write_all(header.as_bytes())?;
    Ok(())
}

fn write_padding(writer: &mut impl Write, length: u64) -> AppResult<()> {
    writer.write_all(&[0u8; 512][..((512 - length % 512) % 512) as usize])?;
    Ok(())
}

fn copy_exact_hashed(
    reader: &mut impl Read,
    writer: &mut impl Write,
    length: u64,
) -> AppResult<String> {
    let mut remaining = length;
    let mut buffer = [0u8; 64 * 1024];
    let mut hasher = Sha256::new();
    while remaining != 0 {
        let chunk = remaining.min(buffer.len() as u64) as usize;
        reader.read_exact(&mut buffer[..chunk])?;
        writer.write_all(&buffer[..chunk])?;
        hasher.update(&buffer[..chunk]);
        remaining -= chunk as u64;
    }
    Ok(hex::encode(hasher.finalize()))
}

/// Verify and extract to a private owned temporary directory. All verification
/// must finish before the caller can access a verified entry or publish a case.
pub fn read_archive(path: &Path) -> AppResult<VerifiedArchive> {
    read_archive_in(path, None)
}

pub(crate) fn read_archive_for_restore(path: &Path) -> AppResult<VerifiedArchive> {
    read_archive_in(path, None)
}

fn read_archive_in(path: &Path, temporary_parent: Option<&Path>) -> AppResult<VerifiedArchive> {
    let (mut file, before) = open_regular(path, MAX_ARCHIVE_COMPRESSED_BYTES)?;
    let hashing = HashingReader {
        inner: &mut file,
        hasher: Sha256::new(),
        bytes: 0,
    };
    let mut compressed = BufReader::with_capacity(64 * 1024, hashing);
    let header = compressed.fill_buf()?;
    if header.len() < 10 || header[..4] != [0x1f, 0x8b, 8, 0] {
        return Err(invalid(
            "expected one gzip member without optional header fields",
        ));
    }
    let gzip = GzDecoder::new(compressed);
    let mut reader = BoundedReader {
        inner: gzip,
        bytes: 0,
        limit: MAX_ARCHIVE_DECOMPRESSED_BYTES,
    };
    let (first_path, length, first_headers) =
        read_header(&mut reader)?.ok_or_else(|| invalid("missing manifest"))?;
    if first_path != MANIFEST_PATH || first_headers != 1 || length > MAX_ARCHIVE_MANIFEST_BYTES {
        return Err(invalid("first entry must be a manifest of at most 16 MiB"));
    }
    let mut manifest_bytes = Vec::with_capacity(length as usize);
    copy_exact_hashed(&mut reader, &mut manifest_bytes, length)?;
    read_padding(&mut reader, length)?;
    let manifest: ArchiveManifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|error| invalid(&format!("invalid manifest: {error}")))?;
    let expected = validate_manifest(&manifest)?;
    // macOS exposes some system temporary roots through trusted symlink aliases;
    // resolve the platform default before verifying the real namespace.
    let parent = match temporary_parent {
        Some(parent) => parent.to_owned(),
        None => crate::internal_paths::canonicalize(std::env::temp_dir())?,
    };
    let parent_guard = guard_archive_parent(&parent).map_err(temporary_directory_error)?;
    let directory = private_tempdir_in(parent_guard.path(), "ai-scanner-verified-archive-")
        .map_err(temporary_directory_error)?;
    let mut seen = BTreeSet::new();
    let mut physical_entries = 1usize;
    while let Some((entry_path, length, headers)) = read_header(&mut reader)? {
        physical_entries += headers;
        if physical_entries > MAX_ARCHIVE_ENTRIES || !seen.insert(entry_path.clone()) {
            return Err(invalid("duplicate entry or archive entry count exceeded"));
        }
        let expected_entry = expected
            .get(entry_path.as_str())
            .ok_or_else(|| invalid("unexpected archive entry"))?;
        if length != expected_entry.byte_length || length > MAX_ARCHIVE_ENTRY_BYTES {
            return Err(invalid(
                "entry length differs from manifest or exceeds 512 MiB",
            ));
        }
        let output_path = directory.path().join(&entry_path);
        private_parents(directory.path(), output_path.parent().unwrap())?;
        let mut output = create_private_new(&output_path)?;
        let observed = copy_exact_hashed(&mut reader, &mut output, length)?;
        if observed != expected_entry.sha256 {
            return Err(invalid("entry SHA-256 mismatch"));
        }
        output.sync_all()?;
        read_padding(&mut reader, length)?;
    }
    if seen.len() != expected.len() {
        return Err(invalid("archive is missing manifest entries"));
    }
    // read_header consumed the first zero block. Require the second block,
    // then a bounded all-zero record padding tail, and drain to gzip EOF so its
    // CRC and uncompressed-length trailer must also validate.
    let mut second = [0u8; 512];
    reader.read_exact(&mut second)?;
    if second.iter().any(|byte| *byte != 0) {
        return Err(invalid("invalid tar terminator or trailing tar payload"));
    }
    let mut trailing = [0u8; 1024];
    let mut trailing_bytes = 0usize;
    loop {
        let count = reader.read(&mut trailing)?;
        if count == 0 {
            break;
        }
        trailing_bytes += count;
        if trailing_bytes > MAX_TAR_TRAILER_BYTES || trailing[..count].iter().any(|byte| *byte != 0)
        {
            return Err(invalid("unexpected trailing tar payload"));
        }
    }
    if !trailing_bytes.is_multiple_of(512) {
        return Err(invalid("unaligned tar record padding"));
    }
    let mut compressed = reader.inner.into_inner();
    if !compressed.fill_buf()?.is_empty() {
        return Err(invalid(
            "trailing compressed payload or multiple gzip members",
        ));
    }
    let hashing = compressed.into_inner();
    if hashing.bytes != before.length {
        return Err(invalid("archive changed length while being read"));
    }
    let archive_sha256 = hex::encode(hashing.hasher.finalize());
    verify_unchanged(path, &file, &before)?;
    Ok(VerifiedArchive {
        directory,
        _parent_guard: parent_guard,
        manifest,
        archive_sha256,
    })
}

fn read_header(reader: &mut impl Read) -> AppResult<Option<(String, u64, usize)>> {
    let Some((path, length, kind)) = read_raw_header(reader)? else {
        return Ok(None);
    };
    if kind == tar::EntryType::Regular {
        validate_path(&path)?;
        return Ok(Some((path, length, 1)));
    }
    if path != GNU_LONG_NAME || !(2..=MAX_PATH_BYTES as u64 + 1).contains(&length) {
        return Err(invalid("invalid or oversized GNU long-name metadata"));
    }
    let mut bytes = vec![0u8; length as usize];
    reader.read_exact(&mut bytes)?;
    read_padding(reader, length)?;
    if bytes.last() != Some(&0) || bytes[..bytes.len() - 1].contains(&0) {
        return Err(invalid(
            "long-name metadata requires exactly one terminating NUL",
        ));
    }
    let long_path = std::str::from_utf8(&bytes[..bytes.len() - 1])
        .map_err(|_| invalid("long-name path is not UTF-8"))?;
    validate_path(long_path)?;
    if !needs_long_name(long_path) {
        return Err(invalid("unnecessary or ambiguous long-name metadata"));
    }
    let Some((following_path, following_length, following_kind)) = read_raw_header(reader)? else {
        return Err(invalid("long-name metadata has no following regular file"));
    };
    if following_kind != tar::EntryType::Regular || following_path != LONG_NAME_PLACEHOLDER {
        return Err(invalid(
            "long-name metadata must immediately precede one canonical regular-file header",
        ));
    }
    // The caller checks this exact resolved name against the manifest before
    // opening any output; metadata is never applied to a later unrelated entry.
    Ok(Some((long_path.to_owned(), following_length, 2)))
}

fn read_raw_header(reader: &mut impl Read) -> AppResult<Option<(String, u64, tar::EntryType)>> {
    let mut block = [0u8; 512];
    reader.read_exact(&mut block)?;
    if block.iter().all(|byte| *byte == 0) {
        return Ok(None);
    }
    let header = tar::Header::from_byte_slice(&block);
    let checksum = block
        .iter()
        .enumerate()
        .map(|(index, byte)| {
            if (148..156).contains(&index) {
                32
            } else {
                u32::from(*byte)
            }
        })
        .sum::<u32>();
    if header.cksum()? != checksum || &block[257..263] != b"ustar\0" || &block[263..265] != b"00" {
        return Err(invalid("invalid checksum or unsupported tar header"));
    }
    if !matches!(
        header.entry_type(),
        tar::EntryType::Regular | tar::EntryType::GNULongName
    ) || block[157..257].iter().any(|byte| *byte != 0)
    {
        return Err(invalid(
            "only regular files and bounded local long-name metadata are allowed",
        ));
    }
    let bytes = header.path_bytes();
    let path = std::str::from_utf8(&bytes)
        .map_err(|_| invalid("archive entry path is not UTF-8"))?
        .to_owned();
    Ok(Some((path, header.size()?, header.entry_type())))
}

fn read_padding(reader: &mut impl Read, length: u64) -> AppResult<()> {
    let mut padding = [0u8; 512];
    let count = ((512 - length % 512) % 512) as usize;
    reader.read_exact(&mut padding[..count])?;
    if padding[..count].iter().any(|byte| *byte != 0) {
        return Err(invalid("nonzero tar entry padding"));
    }
    Ok(())
}

struct HashingReader<R> {
    inner: R,
    hasher: Sha256,
    bytes: u64,
}
impl<R: Read> Read for HashingReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let count = self.inner.read(buffer)?;
        self.bytes += count as u64;
        if self.bytes > MAX_ARCHIVE_COMPRESSED_BYTES {
            return Err(io::Error::other("compressed archive exceeds its bound"));
        }
        self.hasher.update(&buffer[..count]);
        Ok(count)
    }
}

struct BoundedReader<R> {
    inner: R,
    bytes: u64,
    limit: u64,
}
impl<R: Read> Read for BoundedReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let count = self.inner.read(buffer)?;
        self.bytes += count as u64;
        if self.bytes > self.limit {
            return Err(io::Error::other("archive exceeds decompressed size bound"));
        }
        Ok(count)
    }
}

#[derive(Debug, PartialEq, Eq)]
struct FileStamp {
    length: u64,
    modified: SystemTime,
    identity: (u64, u64),
    change: (i64, i64),
}

/// Reject physical links and special files before publishing or reusing originals.
pub(crate) fn verify_regular_original(file: &File) -> AppResult<()> {
    stamp(file).map(|_| ())
}

fn stamp(file: &File) -> AppResult<FileStamp> {
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(invalid("input must be a regular file"));
    }
    #[cfg(unix)]
    let (identity, change) = {
        use std::os::unix::fs::MetadataExt;
        if metadata.nlink() != 1 {
            return Err(invalid("physical hard-linked inputs are rejected"));
        }
        (
            (metadata.dev(), metadata.ino()),
            (metadata.ctime(), metadata.ctime_nsec()),
        )
    };
    #[cfg(windows)]
    let (identity, change) = {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Storage::FileSystem::{
            BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
        };
        let mut info = BY_HANDLE_FILE_INFORMATION::default();
        // SAFETY: file owns a live handle and info is a correctly sized output.
        if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &raw mut info) } == 0 {
            return Err(io::Error::last_os_error().into());
        }
        if info.nNumberOfLinks != 1 || info.dwFileAttributes & 0x400 != 0 {
            return Err(invalid(
                "physical links and reparse-point inputs are rejected",
            ));
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
        "archive file identity checks are unavailable on this platform".into(),
    ));
    #[cfg(any(unix, windows))]
    Ok(FileStamp {
        length: metadata.len(),
        modified: metadata.modified()?,
        identity,
        change,
    })
}

fn open_regular(path: &Path, maximum: u64) -> AppResult<(File, FileStamp)> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options.open(path)?;
    let before = stamp(&file)?;
    if before.length > maximum {
        return Err(invalid("physical input exceeds its size bound"));
    }
    Ok((file, before))
}

// Permission changes during confirmed deletion must not affect an outside
// alias. Reuse the same regular-file/reparse/link-count boundary as reads.
#[cfg(windows)]
pub(crate) fn single_link_regular_file(path: &Path) -> AppResult<File> {
    Ok(open_regular(path, u64::MAX)?.0)
}

fn verify_unchanged(path: &Path, file: &File, before: &FileStamp) -> AppResult<()> {
    if &stamp(file)? != before {
        return Err(invalid("input changed while being read"));
    }
    let (_, current) = open_regular(path, before.length)?;
    if &current != before {
        return Err(invalid("input path was replaced while being read"));
    }
    Ok(())
}

/// Read one bounded document using the archive transport's file identity checks.
/// This reads an explicitly selected standalone file, not a relative bundle
/// member. It deliberately does not apply output-directory ownership policy to
/// an input's parent; full bundle traversal needs its own root-bound reader.
pub(crate) fn read_bounded_regular(path: &Path, maximum: u64) -> AppResult<Vec<u8>> {
    let path = std::path::absolute(path)?;
    #[cfg(windows)]
    {
        use std::path::{Component, Prefix};
        // A Windows named pipe or device can block before metadata is available;
        // remote namespaces also violate this command's local-document boundary.
        let mut components = path.components();
        if !matches!(
            components.next(),
            Some(Component::Prefix(prefix))
                if matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_))
        ) {
            return Err(invalid("input must use a local disk path"));
        }
        for component in components {
            if let Component::Normal(name) = component {
                validate_path(name.to_str().ok_or_else(|| invalid("invalid input path"))?)?;
            }
        }
    }
    let (mut file, before) = open_regular(&path, maximum)?;
    let mut bytes = Vec::new();
    (&mut file).take(maximum + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 != before.length {
        return Err(invalid("input changed while being read"));
    }
    verify_unchanged(&path, &file, &before)?;
    Ok(bytes)
}

fn private_parents(root: &Path, parent: &Path) -> AppResult<()> {
    let relative = parent
        .strip_prefix(root)
        .map_err(|_| invalid("staging parent escaped the private root"))?;
    let mut path = root.to_owned();
    for component in relative.components() {
        path.push(component);
        match fs::create_dir(&path) {
            Ok(()) => make_private(&path, true)?,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                let metadata = fs::symlink_metadata(&path)?;
                if !metadata.is_dir() || metadata.file_type().is_symlink() {
                    return Err(invalid("staging parent is not a private directory"));
                }
            }
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn create_private_new(path: &Path) -> AppResult<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(path)?;
    make_private(path, false)?;
    Ok(file)
}

#[cfg(unix)]
pub(crate) fn make_private(path: &Path, directory: bool) -> AppResult<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(
        path,
        fs::Permissions::from_mode(if directory { 0o700 } else { 0o600 }),
    )?;
    Ok(())
}

#[cfg(windows)]
fn windows_current_user_sid_string() -> io::Result<String> {
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use windows_sys::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, LocalFree};
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows_sys::Win32::Security::{
        GetTokenInformation, IsValidSid, TOKEN_QUERY, TOKEN_USER, TokenUser,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let mut raw_token = std::ptr::null_mut();
    // SAFETY: the process pseudo-handle is valid and raw_token is writable.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut raw_token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: OpenProcessToken returned a uniquely owned kernel handle.
    let token = unsafe { OwnedHandle::from_raw_handle(raw_token) };
    let mut required = 0_u32;
    // SAFETY: the null/zero probe obtains the required TOKEN_USER buffer size.
    let probe = unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            std::ptr::null_mut(),
            0,
            &raw mut required,
        )
    };
    let probe_error = io::Error::last_os_error();
    if probe != 0
        || required < std::mem::size_of::<TOKEN_USER>() as u32
        || probe_error.raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Windows returned an invalid current-user token size",
        ));
    }
    let mut token_information =
        vec![0_usize; (required as usize).div_ceil(std::mem::size_of::<usize>())];
    // SAFETY: the aligned buffer has at least required writable bytes.
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            token_information.as_mut_ptr().cast(),
            required,
            &raw mut required,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: GetTokenInformation initialized a correctly aligned TOKEN_USER.
    let user = unsafe { &*token_information.as_ptr().cast::<TOKEN_USER>() };
    // SAFETY: a non-null SID from the live token buffer can be validated.
    if user.User.Sid.is_null() || unsafe { IsValidSid(user.User.Sid) } == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Windows returned an invalid current-user SID",
        ));
    }
    let mut raw_string = std::ptr::null_mut();
    // SAFETY: the valid SID remains live and raw_string is writable output.
    if unsafe { ConvertSidToStringSidW(user.User.Sid, &raw mut raw_string) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if raw_string.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Windows returned a null current-user SID string",
        ));
    }
    let mut length = 0_usize;
    // SAFETY: Windows returns an allocated NUL-terminated SID string.
    while length < 256 && unsafe { *raw_string.add(length) } != 0 {
        length += 1;
    }
    let result = if length == 256 {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Windows current-user SID string was not bounded",
        ))
    } else {
        // SAFETY: the preceding loop identified this live string's extent.
        Ok(String::from_utf16_lossy(unsafe {
            std::slice::from_raw_parts(raw_string, length)
        }))
    };
    // SAFETY: ConvertSidToStringSidW allocated this string with LocalAlloc.
    unsafe {
        LocalFree(raw_string.cast());
    }
    result
}

#[cfg(windows)]
pub(crate) fn make_private(path: &Path, directory: bool) -> AppResult<()> {
    use std::os::windows::{fs::OpenOptionsExt, io::AsRawHandle};
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1, SE_FILE_OBJECT,
        SetSecurityInfo,
    };
    use windows_sys::Win32::Security::{
        DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl, GetSecurityDescriptorOwner,
        OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES,
        READ_CONTROL, WRITE_DAC, WRITE_OWNER,
    };
    // TokenOwner can be the Administrators group for an elevated process.
    // Bind both ownership and inherited access to TokenUser so the same user
    // can reopen restored evidence without elevation.
    let user_sid = windows_current_user_sid_string()?;
    let flags = if directory { "OICI" } else { "" };
    let sddl = format!("O:{user_sid}D:P(A;{flags};FA;;;{user_sid})")
        .encode_utf16()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let mut descriptor = std::ptr::null_mut();
    // SAFETY: nul-terminated SDDL and writable descriptor output stay live.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &raw mut descriptor,
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error().into());
    }
    let result = (|| -> AppResult<()> {
        let mut present = 0;
        let mut defaulted = 0;
        let mut owner_defaulted = 0;
        let mut owner = std::ptr::null_mut();
        let mut acl = std::ptr::null_mut();
        // SAFETY: descriptor came from the Windows parser and remains allocated.
        if unsafe {
            GetSecurityDescriptorDacl(
                descriptor,
                &raw mut present,
                &raw mut acl,
                &raw mut defaulted,
            )
        } == 0
            || present == 0
            || acl.is_null()
        {
            return Err(invalid("could not construct a private archive ACL"));
        }
        // SAFETY: descriptor is live and both owner output pointers are writable.
        if unsafe {
            GetSecurityDescriptorOwner(descriptor, &raw mut owner, &raw mut owner_defaulted)
        } == 0
            || owner.is_null()
            || owner_defaulted != 0
        {
            return Err(invalid("could not construct an explicit archive owner"));
        }
        let file = OpenOptions::new()
            .access_mode(READ_CONTROL | FILE_READ_ATTRIBUTES | WRITE_DAC | WRITE_OWNER)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)?;
        use std::os::windows::fs::MetadataExt;
        let metadata = file.metadata()?;
        if metadata.file_attributes() & 0x400 != 0
            || metadata.is_dir() != directory
            || (!directory && !metadata.is_file())
        {
            return Err(invalid("private archive path has an unexpected file type"));
        }
        // SAFETY: file owns a WRITE_DAC/WRITE_OWNER handle; descriptor stays live.
        let status = unsafe {
            SetSecurityInfo(
                file.as_raw_handle(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION
                    | DACL_SECURITY_INFORMATION
                    | PROTECTED_DACL_SECURITY_INFORMATION,
                owner,
                std::ptr::null_mut(),
                acl,
                std::ptr::null_mut(),
            )
        };
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status as i32).into());
        }
        verify_windows_private_security(&file, descriptor)
    })();
    // SAFETY: descriptor is the allocation returned by the Windows parser.
    unsafe {
        LocalFree(descriptor);
    }
    result
}

#[cfg(windows)]
fn verify_windows_private_security(
    file: &File,
    expected: windows_sys::Win32::Security::PSECURITY_DESCRIPTOR,
) -> AppResult<()> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
    use windows_sys::Win32::Security::{
        ACE_HEADER, DACL_SECURITY_INFORMATION, EqualSid, GetAce, GetSecurityDescriptorControl,
        GetSecurityDescriptorDacl, GetSecurityDescriptorOwner, IsValidAcl, IsValidSid,
        OWNER_SECURITY_INFORMATION, SE_DACL_PROTECTED,
    };

    let mut actual = std::ptr::null_mut();
    // SAFETY: file has READ_CONTROL and actual is writable descriptor output.
    let status = unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &raw mut actual,
        )
    };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status as i32).into());
    }
    if actual.is_null() {
        return Err(invalid("Windows returned no archive security descriptor"));
    }
    let result = (|| -> AppResult<()> {
        let mut expected_owner = std::ptr::null_mut();
        let mut actual_owner = std::ptr::null_mut();
        let mut defaulted = 0;
        // SAFETY: both descriptors are allocated and live; outputs are writable.
        if unsafe {
            GetSecurityDescriptorOwner(expected, &raw mut expected_owner, &raw mut defaulted)
        } == 0
            || unsafe {
                GetSecurityDescriptorOwner(actual, &raw mut actual_owner, &raw mut defaulted)
            } == 0
            || actual_owner.is_null()
            || defaulted != 0
            || unsafe { IsValidSid(actual_owner) } == 0
            || unsafe { EqualSid(actual_owner, expected_owner) } == 0
        {
            return Err(invalid(
                "archive owner is not the explicit current Windows user",
            ));
        }
        let mut control = 0_u16;
        let mut revision = 0_u32;
        // SAFETY: actual is live and both outputs are writable.
        if unsafe { GetSecurityDescriptorControl(actual, &raw mut control, &raw mut revision) } == 0
            || control & SE_DACL_PROTECTED == 0
        {
            return Err(invalid("archive DACL is not protected from inheritance"));
        }
        let mut expected_acl = std::ptr::null_mut();
        let mut actual_acl = std::ptr::null_mut();
        let mut present = 0;
        // SAFETY: descriptors are live and the DACL outputs are writable.
        if unsafe {
            GetSecurityDescriptorDacl(
                expected,
                &raw mut present,
                &raw mut expected_acl,
                &raw mut defaulted,
            )
        } == 0
            || unsafe {
                GetSecurityDescriptorDacl(
                    actual,
                    &raw mut present,
                    &raw mut actual_acl,
                    &raw mut defaulted,
                )
            } == 0
            || present == 0
            || defaulted != 0
            || actual_acl.is_null()
            || unsafe { IsValidAcl(actual_acl) } == 0
            || unsafe { (*actual_acl).AceCount } != 1
        {
            return Err(invalid("archive DACL is not current-user-only"));
        }
        let mut expected_ace = std::ptr::null_mut();
        let mut actual_ace = std::ptr::null_mut();
        // SAFETY: expected has one constructed ACE; actual was validated above.
        if unsafe { GetAce(expected_acl, 0, &raw mut expected_ace) } == 0
            || unsafe { GetAce(actual_acl, 0, &raw mut actual_ace) } == 0
            || expected_ace.is_null()
            || actual_ace.is_null()
        {
            return Err(invalid(
                "archive DACL does not contain its private access rule",
            ));
        }
        // SAFETY: GetAce returned live ACEs contained in valid ACL storage.
        let expected_size = unsafe { (*expected_ace.cast::<ACE_HEADER>()).AceSize } as usize;
        let actual_size = unsafe { (*actual_ace.cast::<ACE_HEADER>()).AceSize } as usize;
        if expected_size != actual_size
            || unsafe { std::slice::from_raw_parts(expected_ace.cast::<u8>(), expected_size) }
                != unsafe { std::slice::from_raw_parts(actual_ace.cast::<u8>(), actual_size) }
        {
            return Err(invalid("archive DACL grants unexpected Windows access"));
        }
        Ok(())
    })();
    // SAFETY: GetSecurityInfo allocated this descriptor with LocalAlloc.
    unsafe {
        LocalFree(actual);
    }
    result
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn make_private(_path: &Path, _directory: bool) -> AppResult<()> {
    Err(AppError::NotAvailable(
        "private archives are unavailable on this platform".into(),
    ))
}

fn sync_directory(path: &Path) -> AppResult<()> {
    #[cfg(unix)]
    File::open(path)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

/// Seal descendants while leaving the publication root movable on macOS.
pub(crate) fn seal_directory_contents(root: &Path) -> AppResult<()> {
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let metadata = fs::symlink_metadata(entry.path())?;
        if metadata.is_dir() && !metadata.file_type().is_symlink() {
            crate::workspace_snapshot::make_snapshot_tree_readonly(&entry.path())?;
        } else if metadata.is_file() {
            #[cfg(unix)]
            let permissions = {
                use std::os::unix::fs::PermissionsExt;
                fs::Permissions::from_mode(0o400)
            };
            #[cfg(not(unix))]
            let permissions = {
                let mut permissions = metadata.permissions();
                permissions.set_readonly(true);
                permissions
            };
            fs::set_permissions(entry.path(), permissions)?;
        } else {
            return Err(AppError::UnsafeFilesystemEntry);
        }
    }
    Ok(())
}

/// Finish publication only after the directory has its final name.
pub(crate) fn seal_directory_root(root: &Path) -> AppResult<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let directory = File::options()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(root)?;
        directory.set_permissions(fs::Permissions::from_mode(0o500))?;
        directory.sync_all()?;
    }
    #[cfg(not(unix))]
    let _ = root;
    Ok(())
}

/// Managed readers must not admit an interrupted source-view publication.
pub(crate) fn require_sealed_directory_root(root: &Path) -> AppResult<()> {
    let metadata = fs::symlink_metadata(root)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(AppError::UnsafeFilesystemEntry);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o222 != 0 {
            return Err(invalid("directory publication is not sealed"));
        }
    }
    Ok(())
}

/// Move damaged owned bytes aside without opening their descendants for writes.
/// The pinned directory restores its original permissions even if rename fails.
pub(crate) fn move_preserving_root_permissions(source: &Path, target: &Path) -> AppResult<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        if fs::symlink_metadata(source)?.is_dir() {
            let directory = File::options()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(source)?;
            let original = directory.metadata()?.permissions();
            directory.set_permissions(fs::Permissions::from_mode(original.mode() | 0o200))?;
            let renamed = rename_entry_no_replace(source, target);
            let restored = directory.set_permissions(original);
            directory.sync_all()?;
            restored?;
            return renamed;
        }
    }
    rename_entry_no_replace(source, target)
}

/// Publish a prepared directory atomically on one filesystem. Existing paths
/// are never replaced, and unsupported filesystems/platforms fail closed.
pub(crate) fn publish_directory_no_replace(stage: &Path, destination: &Path) -> AppResult<()> {
    let metadata: Metadata = fs::symlink_metadata(stage)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(invalid("publish stage must be a real directory"));
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            return Err(invalid("publish stage must not be a reparse point"));
        }
    }
    rename_entry_no_replace(stage, destination)
}

/// Move an entry itself, including a symlink, without following it or replacing a target.
/// Callers retain responsibility for guarding both parents.
pub(crate) fn rename_entry_no_replace(stage: &Path, destination: &Path) -> AppResult<()> {
    // Enforce macOS's directory-owner-write requirement on every Unix host so
    // Linux tests exercise the same publication order.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = fs::symlink_metadata(stage)?;
        if metadata.is_dir() && metadata.permissions().mode() & 0o200 == 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "directory root must be owner-writable before rename",
            )
            .into());
        }
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        let source = CString::new(stage.as_os_str().as_bytes())
            .map_err(|_| invalid("invalid stage path"))?;
        let target = CString::new(destination.as_os_str().as_bytes())
            .map_err(|_| invalid("invalid destination path"))?;
        #[cfg(target_os = "linux")]
        // SAFETY: both paths are live nul-terminated strings; NOREPLACE forbids replacement.
        let result = unsafe {
            libc::renameat2(
                libc::AT_FDCWD,
                source.as_ptr(),
                libc::AT_FDCWD,
                target.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        };
        #[cfg(target_os = "macos")]
        // SAFETY: same as above; EXCL is the platform's atomic no-replace operation.
        let result =
            unsafe { libc::renamex_np(source.as_ptr(), target.as_ptr(), libc::RENAME_EXCL) };
        if result != 0 {
            return Err(io::Error::last_os_error().into());
        }
    }
    #[cfg(windows)]
    {
        use windows_sys::Win32::Storage::FileSystem::{MOVEFILE_WRITE_THROUGH, MoveFileExW};
        let source = crate::internal_paths::win32_path(stage)?;
        let target = crate::internal_paths::win32_path(destination)?;
        // SAFETY: paths are nul terminated; neither REPLACE_EXISTING nor COPY_ALLOWED is set.
        if unsafe { MoveFileExW(source.as_ptr(), target.as_ptr(), MOVEFILE_WRITE_THROUGH) } == 0 {
            return Err(io::Error::last_os_error().into());
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    return Err(AppError::NotAvailable(
        "atomic directory publication is unavailable on this platform".into(),
    ));
    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    {
        sync_directory(destination.parent().unwrap_or_else(|| Path::new(".")))?;
        if stage.parent() != destination.parent() {
            sync_directory(stage.parent().unwrap_or_else(|| Path::new(".")))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn private_fixture() -> PrivateArchiveDirectory {
        let parent = crate::internal_paths::canonicalize(std::env::temp_dir()).unwrap();
        private_tempdir_in(&parent, "ai-scanner-archive-test-").unwrap()
    }

    fn private_fixture_directory(path: &Path) {
        fs::create_dir(path).unwrap();
        make_private(path, true).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn sealed_directory_publication_and_move_aside_preserve_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        let stage = root.path().join("stage");
        let published = root.path().join("published");
        let retained = root.path().join("retained");
        fs::create_dir(&stage).unwrap();
        fs::write(stage.join("member"), b"evidence").unwrap();
        seal_directory_contents(&stage).unwrap();
        assert!(require_sealed_directory_root(&stage).is_err());
        seal_directory_root(&stage).unwrap();
        let error = rename_entry_no_replace(&stage, &published).unwrap_err();
        assert!(error.to_string().contains("owner-writable"));
        assert!(stage.exists());
        move_preserving_root_permissions(&stage, &published).unwrap();
        require_sealed_directory_root(&published).unwrap();
        fs::create_dir(&retained).unwrap();
        assert!(move_preserving_root_permissions(&published, &retained).is_err());
        require_sealed_directory_root(&published).unwrap();
        fs::remove_dir(&retained).unwrap();
        move_preserving_root_permissions(&published, &retained).unwrap();
        assert_eq!(
            fs::metadata(&retained).unwrap().permissions().mode() & 0o777,
            0o500
        );
        assert_eq!(
            fs::metadata(retained.join("member"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o400
        );
        crate::workspace_snapshot::make_tree_deletable(&retained);
    }

    #[test]
    fn private_staging_is_owned_and_cleans_up_under_an_existing_parent() {
        let parent = private_fixture();
        let directory = private_tempdir_in(parent.path(), "owned-").unwrap();
        let path = directory.path().to_owned();
        assert_eq!(path.parent(), Some(parent.path()));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o700
            );
        }
        fs::write(path.join("payload"), b"owned bytes").unwrap();
        drop(directory);
        assert!(!path.exists());
        assert!(private_tempdir_in(parent.path(), "../escaped-").is_err());
        let missing = parent.path().join("missing");
        assert!(private_tempdir_in(&missing, "owned-").is_err());
        assert!(!missing.exists());
    }

    fn entry(path: &str, bytes: &[u8]) -> ArchiveEntry {
        ArchiveEntry {
            path: path.into(),
            sha256: digest(bytes),
            byte_length: bytes.len() as u64,
        }
    }

    fn manifest(entries: Vec<ArchiveEntry>) -> ArchiveManifest {
        ArchiveManifest {
            schema_version: ARCHIVE_SCHEMA.into(),
            archive_id: "transport-fixture".into(),
            created_at: "2026-11-08T12:00:00Z".parse().unwrap(),
            producer_version: "fixture".into(),
            case_id: "case-fixture".into(),
            source_case_revision: 1,
            case_document_sha256: entries
                .iter()
                .find(|entry| entry.path == "case.json")
                .map(|entry| entry.sha256.clone())
                .unwrap_or_else(|| "0".repeat(64)),
            required_capabilities: Vec::new(),
            raw_artifacts_included: true,
            source_snapshots_included: false,
            omissions: vec!["source snapshots not selected".into()],
            entries,
        }
    }

    fn append_untrusted(tar: &mut Vec<u8>, path: &[u8], contents: &[u8], kind: tar::EntryType) {
        assert!(path.len() <= 100);
        let mut header = tar::Header::new_ustar();
        header.set_path("placeholder").unwrap();
        header.as_mut_bytes()[..100].fill(0);
        header.as_mut_bytes()[..path.len()].copy_from_slice(path);
        header.set_entry_type(kind);
        header.set_size(contents.len() as u64);
        header.set_mode(0o777);
        header.set_mtime(0);
        header.set_cksum();
        tar.extend_from_slice(header.as_bytes());
        tar.extend_from_slice(contents);
        tar.extend_from_slice(&[0u8; 512][..((512 - contents.len() % 512) % 512)]);
    }

    fn tar_bytes(manifest: &[u8], entries: &[(&str, &[u8], tar::EntryType)]) -> Vec<u8> {
        let mut tar = Vec::new();
        append_untrusted(
            &mut tar,
            MANIFEST_PATH.as_bytes(),
            manifest,
            tar::EntryType::Regular,
        );
        for (name, contents, kind) in entries {
            append_untrusted(&mut tar, name.as_bytes(), contents, *kind);
        }
        tar.extend_from_slice(&[0u8; 1024]);
        tar
    }

    fn compressed(tar: &[u8]) -> Vec<u8> {
        let mut encoder = GzBuilder::new()
            .mtime(0)
            .write(Vec::new(), Compression::fast());
        encoder.write_all(tar).unwrap();
        encoder.finish().unwrap()
    }

    fn reject(bytes: &[u8]) {
        let directory = private_fixture();
        let input = directory.path().join("untrusted.tar.gz");
        let staging = directory.path().join("staging");
        private_fixture_directory(&staging);
        fs::write(&input, bytes).unwrap();
        assert!(
            read_archive_in(&input, Some(&staging)).is_err(),
            "malformed archive was accepted"
        );
        assert_eq!(
            fs::read_dir(&staging).unwrap().count(),
            0,
            "failed extraction leaked staging files"
        );
    }

    #[test]
    fn archive_roundtrip_is_streamed_private_and_owned_by_verified_handle() {
        let directory = private_fixture();
        let case = br#"{"schema_version":"fixture","case":{"id":"case-fixture"}}"#;
        let evidence = b"opaque bytes\0\xff\nnot executable";
        let manifest = manifest(vec![
            entry("case.json", case),
            entry("artifacts/run/task/evidence.bin", evidence),
        ]);
        let case_path = directory.path().join("source-case");
        let evidence_path = directory.path().join("source-evidence");
        fs::write(&case_path, case).unwrap();
        fs::write(&evidence_path, evidence).unwrap();
        let files = BTreeMap::from([
            ("case.json".into(), case_path),
            ("artifacts/run/task/evidence.bin".into(), evidence_path),
        ]);
        let first = directory.path().join("one.tar.gz");
        let second = directory.path().join("two.tar.gz");
        write_archive(&manifest, &files, &first).unwrap();
        write_archive(&manifest, &files, &second).unwrap();
        assert_eq!(fs::read(&first).unwrap(), fs::read(&second).unwrap());
        let verified = read_archive(&first).unwrap();
        assert_eq!(verified.archive_sha256, digest(&fs::read(&first).unwrap()));
        assert_eq!(verified.manifest.entries, manifest.entries);
        assert_eq!(
            fs::read(verified.entry_path("case.json").unwrap()).unwrap(),
            case
        );
        assert_eq!(
            fs::read(
                verified
                    .entry_path("artifacts/run/task/evidence.bin")
                    .unwrap()
            )
            .unwrap(),
            evidence
        );
        assert!(verified.entry_path("../escape").is_err());
        assert!(verified.entry_path("absent").is_err());
        let stage = verified.root().to_owned();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&first).unwrap().permissions().mode() & 0o777,
                0o600
            );
            assert_eq!(
                fs::metadata(&stage).unwrap().permissions().mode() & 0o777,
                0o700
            );
            assert_eq!(
                fs::metadata(verified.entry_path("case.json").unwrap())
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        drop(verified);
        assert!(!stage.exists());
        let before = fs::read(&first).unwrap();
        assert!(write_archive(&manifest, &files, &first).is_err());
        assert_eq!(fs::read(&first).unwrap(), before);
    }

    #[test]
    fn bounded_long_names_preserve_deep_and_multibyte_source_paths() {
        let directory = private_fixture();
        let deep = format!("artifacts/{}evidence.json", "source/nested/".repeat(30));
        let multibyte = format!("artifacts/{}.json", "資".repeat(40));
        assert!(needs_long_name(&deep));
        assert!(needs_long_name(&multibyte));
        let contents = [
            ("case.json".to_owned(), b"case".as_slice()),
            (deep.clone(), b"deep source evidence".as_slice()),
            (multibyte.clone(), b"multibyte filename evidence".as_slice()),
        ];
        let manifest = manifest(
            contents
                .iter()
                .map(|(path, bytes)| entry(path, bytes))
                .collect(),
        );
        let mut files = BTreeMap::new();
        for (index, (path, bytes)) in contents.iter().enumerate() {
            let source = directory.path().join(format!("input-{index}"));
            fs::write(&source, bytes).unwrap();
            files.insert(path.clone(), source);
        }
        let archive = directory.path().join("long-names.tar.gz");
        write_archive(&manifest, &files, &archive).unwrap();
        let verified = read_archive(&archive).unwrap();
        for (path, expected) in &contents {
            assert_eq!(
                fs::read(verified.entry_path(path).unwrap()).unwrap(),
                *expected
            );
        }
        // Ordinary tar readers also see the original long paths, not metadata
        // placeholders. This checks the manually written extension encoding.
        let mut compatible =
            tar::Archive::new(flate2::read::GzDecoder::new(File::open(&archive).unwrap()));
        let observed = compatible
            .entries()
            .unwrap()
            .map(|entry| entry.unwrap().path().unwrap().to_str().unwrap().to_owned())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            observed,
            BTreeSet::from([
                MANIFEST_PATH.to_owned(),
                "case.json".into(),
                deep,
                multibyte
            ])
        );
    }

    #[test]
    fn malicious_long_name_metadata_cannot_stack_redirect_hide_or_escape() {
        let long_name = format!("artifacts/{}evidence.json", "nested/".repeat(45));
        let manifest = serde_json::to_vec(&manifest(vec![
            entry("case.json", b"case"),
            entry(&long_name, b"evidence"),
        ]))
        .unwrap();
        let mut canonical = long_name.as_bytes().to_vec();
        canonical.push(0);
        let make = |metadata: &[u8],
                    marker: &str,
                    following: Option<(&str, tar::EntryType)>,
                    stacked: bool| {
            let mut bytes = Vec::new();
            append_untrusted(
                &mut bytes,
                MANIFEST_PATH.as_bytes(),
                &manifest,
                tar::EntryType::Regular,
            );
            append_untrusted(&mut bytes, b"case.json", b"case", tar::EntryType::Regular);
            append_untrusted(
                &mut bytes,
                marker.as_bytes(),
                metadata,
                tar::EntryType::GNULongName,
            );
            if stacked {
                append_untrusted(
                    &mut bytes,
                    GNU_LONG_NAME.as_bytes(),
                    &canonical,
                    tar::EntryType::GNULongName,
                );
            }
            if let Some((path, kind)) = following {
                append_untrusted(&mut bytes, path.as_bytes(), b"evidence", kind);
            }
            bytes.extend_from_slice(&[0; 1024]);
            compressed(&bytes)
        };
        let regular = Some((LONG_NAME_PLACEHOLDER, tar::EntryType::Regular));
        let mut embedded_nul = canonical.clone();
        embedded_nul[12] = 0;
        let mut invalid_utf8 = canonical.clone();
        invalid_utf8[12] = 0xff;
        let mut redirected = format!("artifacts/{}other.json", "nested/".repeat(45)).into_bytes();
        redirected.push(0);
        let mut oversized = vec![b'a'; MAX_PATH_BYTES + 1];
        oversized.push(0);
        for bytes in [
            canonical[..canonical.len() - 1].to_vec(),
            embedded_nul,
            invalid_utf8,
            redirected,
            oversized,
            b"../escape\0".to_vec(),
            b"case.json\0".to_vec(),
        ] {
            reject(&make(&bytes, GNU_LONG_NAME, regular, false));
        }
        reject(&make(&canonical, "wrong-marker", regular, false));
        reject(&make(&canonical, GNU_LONG_NAME, regular, true));
        reject(&make(&canonical, GNU_LONG_NAME, None, false));
        reject(&make(
            &canonical,
            GNU_LONG_NAME,
            Some(("case.json", tar::EntryType::Regular)),
            false,
        ));
        for kind in [
            tar::EntryType::Symlink,
            tar::EntryType::Directory,
            tar::EntryType::XHeader,
            tar::EntryType::XGlobalHeader,
        ] {
            reject(&make(
                &canonical,
                GNU_LONG_NAME,
                Some((LONG_NAME_PLACEHOLDER, kind)),
                false,
            ));
        }
    }

    #[test]
    fn writer_rejects_stale_hash_length_or_file_set_without_publishing() {
        let directory = private_fixture();
        let source = directory.path().join("source");
        fs::write(&source, b"case").unwrap();
        let correct = manifest(vec![entry("case.json", b"case")]);
        let files = BTreeMap::from([("case.json".into(), source)]);
        let destination = directory.path().join("archive.tar.gz");
        let mut wrong_hash = correct.clone();
        wrong_hash.entries[0].sha256 = "0".repeat(64);
        wrong_hash.case_document_sha256 = "0".repeat(64);
        let mut wrong_length = correct.clone();
        wrong_length.entries[0].byte_length += 1;
        for bad in [wrong_hash, wrong_length] {
            assert!(write_archive(&bad, &files, &destination).is_err());
            assert!(!destination.exists());
        }
        assert!(write_archive(&correct, &BTreeMap::new(), &destination).is_err());
        let mut extra = files.clone();
        extra.insert("unexpected".into(), files["case.json"].clone());
        assert!(write_archive(&correct, &extra, &destination).is_err());
        assert_eq!(
            fs::read_dir(directory.path()).unwrap().count(),
            1,
            "writer left a temporary archive"
        );
    }

    #[test]
    fn manifest_accepts_only_the_names_the_archive_writer_emits() {
        for name in [
            "original-case.json",
            "archive-index.json",
            "provider-history.json",
            "artifacts/run/task/evidence.bin",
            "exports/1/report.html",
            "exports/combined-1/originals.case.tar.gz",
            "report-snapshots/snapshot.json",
        ] {
            let candidate = manifest(vec![entry("case.json", b"case"), entry(name, b"payload")]);
            assert!(validate_manifest(&candidate).is_ok(), "{name}");
        }
        // Names the restoring core writes or reads itself, in any letter case,
        // and anything else outside the writer's folders.
        for name in [
            "casework.db",
            "casework.db-wal",
            "casework.db-shm",
            "casework.db-journal",
            "CaseWork.DB",
            "restore-receipt.json",
            "restore-intent.json",
            "restore-intent.json/child",
            "managed-runtime/versions/one/manifest.json",
            "runtime-preparations/receipt.json",
            "Artifacts/run/task/evidence.bin",
            "artifacts",
            "unexpected.json",
        ] {
            let candidate = manifest(vec![entry("case.json", b"case"), entry(name, b"payload")]);
            let error = validate_manifest(&candidate).unwrap_err().to_string();
            assert!(
                error.contains("outside the archive layout"),
                "{name}: {error}"
            );
        }
    }

    #[test]
    fn manifest_schema_unknown_fields_case_binding_and_size_limits_fail_closed() {
        let correct = manifest(vec![entry("case.json", b"case")]);
        let mut unknown_schema = correct.clone();
        unknown_schema.schema_version.push_str("-future");
        let mut bad_binding = correct.clone();
        bad_binding.case_document_sha256 = "0".repeat(64);
        let mut oversized = correct.clone();
        oversized.entries[0].byte_length = MAX_ARCHIVE_ENTRY_BYTES + 1;
        for bad in [unknown_schema, bad_binding, oversized] {
            reject(&compressed(&tar_bytes(
                &serde_json::to_vec(&bad).unwrap(),
                &[],
            )));
        }
        let mut unknown_field = serde_json::to_value(&correct).unwrap();
        unknown_field["unexpected"] = true.into();
        reject(&compressed(&tar_bytes(
            &serde_json::to_vec(&unknown_field).unwrap(),
            &[],
        )));
        let mut nested_unknown = serde_json::to_value(&correct).unwrap();
        nested_unknown["entries"][0]["unexpected"] = true.into();
        reject(&compressed(&tar_bytes(
            &serde_json::to_vec(&nested_unknown).unwrap(),
            &[],
        )));
        let missing_case = manifest(vec![entry("original-case.json", b"case")]);
        assert!(validate_manifest(&missing_case).is_err());
        let mut too_many = correct.clone();
        too_many.entries = vec![entry("case.json", b"case"); MAX_ARCHIVE_ENTRIES];
        assert!(validate_manifest(&too_many).is_err());
        let mut total = correct.clone();
        total.entries.extend((0..100).map(|index| ArchiveEntry {
            path: format!("artifacts/{index}"),
            sha256: "0".repeat(64),
            byte_length: MAX_ARCHIVE_ENTRY_BYTES,
        }));
        assert!(validate_manifest(&total).is_err());
        let mut header = Vec::new();
        write_header(&mut header, MANIFEST_PATH, MAX_ARCHIVE_MANIFEST_BYTES + 1).unwrap();
        reject(&compressed(&header));
    }

    #[test]
    fn unsafe_portable_names_and_manifest_collisions_are_rejected_before_extraction() {
        for name in [
            "../escape",
            "/absolute",
            "C:/drive",
            "a\\b",
            "dir/../escape",
            "./case",
            "a//b",
            "NUL",
            "a/CON.txt",
            "COM1.log",
            "LPT².txt",
            "CONIN$",
            "trailing.",
            "trailing ",
            "a:b",
            "a?b",
            "line\nbreak",
            "",
        ] {
            assert!(validate_path(name).is_err(), "accepted {name:?}");
            let bad = manifest(vec![entry("case.json", b"case"), entry(name, b"x")]);
            reject(&compressed(&tar_bytes(
                &serde_json::to_vec(&bad).unwrap(),
                &[],
            )));
        }
        for names in [
            ["file", "FILE"],
            ["file", "file/child"],
            ["file/child", "file"],
            ["Dir/a", "dir/b"],
            ["archive-manifest.json", "other"],
        ] {
            let bad = manifest(vec![
                entry("case.json", b"case"),
                entry(names[0], b"a"),
                entry(names[1], b"b"),
            ]);
            reject(&compressed(&tar_bytes(
                &serde_json::to_vec(&bad).unwrap(),
                &[],
            )));
        }
        for name in [
            "artifacts/繁體中文.json",
            "file.CSV",
            ".hidden/config",
            "COM10.txt",
        ] {
            validate_path(name).unwrap();
        }
    }

    #[test]
    fn implicit_directory_expansion_is_bounded_before_any_extraction() {
        let mut entries = vec![entry("case.json", b"case")];
        // Only 1,002 files and a small manifest, but each distinct branch would
        // otherwise create 101 directories even when every payload is empty.
        entries.extend((0..1001).map(|index| {
            entry(
                &format!("artifacts/branch-{index}/{}empty", "p/".repeat(100)),
                b"",
            )
        }));
        let expanded = manifest(entries);
        let encoded = serde_json::to_vec(&expanded).unwrap();
        assert!(encoded.len() < MAX_ARCHIVE_MANIFEST_BYTES as usize);
        let error = validate_manifest(&expanded).unwrap_err().to_string();
        assert!(error.contains("parent directories"), "{error}");
        reject(&compressed(&tar_bytes(&encoded, &[])));

        // The budget measures unique directories, not repeated prefixes.
        let mut paths = Paths::default();
        for index in 0..1001 {
            paths
                .insert(&format!("shared/{}file-{index}", "p/".repeat(100)))
                .unwrap();
        }
        assert_eq!(paths.directories.len(), 101);
    }

    #[cfg(windows)]
    #[test]
    fn windows_private_paths_have_explicit_user_owner_and_protected_user_only_acl() {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Foundation::LocalFree;
        use windows_sys::Win32::Security::Authorization::{
            ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
        };
        use windows_sys::Win32::Storage::FileSystem::{FILE_FLAG_BACKUP_SEMANTICS, READ_CONTROL};

        let root = private_fixture();
        make_private(root.path(), true).unwrap();
        let child = root.path().join("nested");
        private_fixture_directory(&child);
        make_private(&child, true).unwrap();
        let payload = child.join("evidence.json");
        create_private_new(&payload)
            .unwrap()
            .write_all(b"private evidence")
            .unwrap();

        let user_sid = windows_current_user_sid_string().unwrap();
        for (path, is_directory) in [(root.path(), true), (&child, true), (&payload, false)] {
            let flags = if is_directory { "OICI" } else { "" };
            let sddl = format!("O:{user_sid}D:P(A;{flags};FA;;;{user_sid})")
                .encode_utf16()
                .chain(Some(0))
                .collect::<Vec<_>>();
            let mut expected = std::ptr::null_mut();
            // SAFETY: SDDL is NUL-terminated and expected is writable output.
            assert_ne!(
                unsafe {
                    ConvertStringSecurityDescriptorToSecurityDescriptorW(
                        sddl.as_ptr(),
                        SDDL_REVISION_1,
                        &raw mut expected,
                        std::ptr::null_mut(),
                    )
                },
                0
            );
            let handle = OpenOptions::new()
                .access_mode(READ_CONTROL)
                .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
                .open(path)
                .unwrap();
            let verified = verify_windows_private_security(&handle, expected);
            // SAFETY: the Windows parser allocated this descriptor with LocalAlloc.
            unsafe {
                LocalFree(expected);
            }
            verified.unwrap();
        }
        assert_eq!(fs::read(&payload).unwrap(), b"private evidence");
        assert!(make_private(&payload, true).is_err());
        assert!(make_private(&child, false).is_err());
    }

    #[test]
    fn physical_archive_members_must_be_regular_ustar_files() {
        let manifest = serde_json::to_vec(&manifest(vec![entry("case.json", b"case")])).unwrap();
        for byte in *b"1234567LKxgSV" {
            reject(&compressed(&tar_bytes(
                &manifest,
                &[("case.json", b"case", tar::EntryType::new(byte))],
            )));
        }
        let mut invalid_utf8 = Vec::new();
        append_untrusted(
            &mut invalid_utf8,
            MANIFEST_PATH.as_bytes(),
            &manifest,
            tar::EntryType::Regular,
        );
        append_untrusted(
            &mut invalid_utf8,
            b"bad\xff",
            b"case",
            tar::EntryType::Regular,
        );
        invalid_utf8.extend_from_slice(&[0; 1024]);
        reject(&compressed(&invalid_utf8));
        let mut checksum = tar_bytes(
            &manifest,
            &[("case.json", b"case", tar::EntryType::Regular)],
        );
        checksum[0] ^= 1;
        reject(&compressed(&checksum));
        let mut no_manifest = Vec::new();
        append_untrusted(
            &mut no_manifest,
            b"case.json",
            b"case",
            tar::EntryType::Regular,
        );
        no_manifest.extend_from_slice(&[0; 1024]);
        reject(&compressed(&no_manifest));
    }

    #[test]
    fn missing_extra_duplicate_mismatched_and_corrupt_entries_leave_no_staging() {
        let manifest = serde_json::to_vec(&manifest(vec![
            entry("case.json", b"case"),
            entry("artifacts/evidence", b"good"),
        ]))
        .unwrap();
        let regular = tar::EntryType::Regular;
        for entries in [
            vec![("case.json", b"case".as_slice(), regular)],
            vec![
                ("case.json", b"case".as_slice(), regular),
                ("artifacts/evidence", b"good".as_slice(), regular),
                ("unexpected", b"x".as_slice(), regular),
            ],
            vec![
                ("case.json", b"case".as_slice(), regular),
                ("case.json", b"case".as_slice(), regular),
            ],
            vec![
                ("case.json", b"case".as_slice(), regular),
                ("artifacts/evidence", b"bad!".as_slice(), regular),
            ],
            vec![
                ("case.json", b"case".as_slice(), regular),
                ("artifacts/evidence", b"short".as_slice(), regular),
            ],
        ] {
            reject(&compressed(&tar_bytes(&manifest, &entries)));
        }
    }

    #[test]
    fn gzip_and_tar_truncation_trailers_crc_and_additional_members_are_rejected() {
        let manifest = serde_json::to_vec(&manifest(vec![entry("case.json", b"case")])).unwrap();
        let tar = tar_bytes(
            &manifest,
            &[("case.json", b"case", tar::EntryType::Regular)],
        );
        let valid = compressed(&tar);
        for cut in [1, 8, valid.len() / 2] {
            reject(&valid[..valid.len() - cut]);
        }
        let mut bad_crc = valid.clone();
        let offset = bad_crc.len() - 8;
        bad_crc[offset] ^= 1;
        reject(&bad_crc);
        let mut trailing_bytes = valid.clone();
        trailing_bytes.extend_from_slice(b"unexpected payload");
        reject(&trailing_bytes);
        let mut concatenated = valid.clone();
        concatenated.extend_from_slice(&valid);
        reject(&concatenated);
        for length in [tar.len() - 512, tar.len() - 1024, tar.len() - 1536] {
            reject(&compressed(&tar[..length]));
        }
        let mut trailing_tar = tar.clone();
        trailing_tar.extend_from_slice(b"unexpected payload");
        reject(&compressed(&trailing_tar));
        let mut too_much_padding = tar.clone();
        too_much_padding.extend_from_slice(&[0; MAX_TAR_TRAILER_BYTES + 512]);
        reject(&compressed(&too_much_padding));
        for flag in [0x01, 0x02, 0x04, 0x08, 0x10, 0x20] {
            let mut header = valid.clone();
            header[3] = flag;
            reject(&header);
        }
    }

    #[test]
    fn decompression_counter_stops_at_bound_without_unbounded_allocation() {
        let mut reader = BoundedReader {
            inner: Cursor::new([1u8; 32]),
            bytes: 0,
            limit: 8,
        };
        let mut buffer = [0u8; 16];
        assert!(reader.read(&mut buffer).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn parent_guards_reject_replaceable_namespaces_without_repairing_or_creating_them() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let root = private_fixture();
        let guard = guard_archive_parent(root.path()).unwrap();
        assert_eq!(
            guard.path(),
            crate::internal_paths::canonicalize(root.path()).unwrap()
        );
        let unsafe_parent = root.path().join("shared");
        fs::create_dir(&unsafe_parent).unwrap();
        fs::set_permissions(&unsafe_parent, fs::Permissions::from_mode(0o777)).unwrap();
        let private_child = unsafe_parent.join("private");
        fs::create_dir(&private_child).unwrap();
        make_private(&private_child, true).unwrap();
        assert!(guard_archive_parent(&unsafe_parent).is_err());
        assert!(guard_archive_parent(&private_child).is_err());
        assert_eq!(
            fs::metadata(&unsafe_parent).unwrap().permissions().mode() & 0o7777,
            0o777
        );

        // A trusted sticky ancestor protects the current user's child names,
        // matching the ordinary /tmp namespace without rewriting that root.
        fs::set_permissions(&unsafe_parent, fs::Permissions::from_mode(0o1777)).unwrap();
        guard_archive_parent(&private_child).unwrap();
        let alias = root.path().join("alias");
        symlink(&private_child, &alias).unwrap();
        assert!(guard_archive_parent(&alias).is_err());
        let regular = root.path().join("regular");
        fs::write(&regular, b"not a directory").unwrap();
        assert!(guard_archive_parent(&regular).is_err());
        let missing = root.path().join("missing");
        assert!(guard_archive_parent(&missing).is_err());
        assert!(!missing.exists());
    }

    #[cfg(unix)]
    #[test]
    fn archive_transport_guards_parents_before_staging_or_publication() {
        use std::os::unix::fs::PermissionsExt;

        let root = private_fixture();
        let source = root.path().join("source");
        fs::write(&source, b"case").unwrap();
        let manifest = manifest(vec![entry("case.json", b"case")]);
        let files = BTreeMap::from([("case.json".into(), source)]);
        let unsafe_parent = root.path().join("shared");
        fs::create_dir(&unsafe_parent).unwrap();
        fs::set_permissions(&unsafe_parent, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(write_archive(&manifest, &files, &unsafe_parent.join("case.tar.gz")).is_err());
        assert_eq!(fs::read_dir(&unsafe_parent).unwrap().count(), 0);
        let missing_parent = root.path().join("not-created");
        assert!(write_archive(&manifest, &files, &missing_parent.join("case.tar.gz")).is_err());
        assert!(!missing_parent.exists());

        let archive = root.path().join("case.tar.gz");
        write_archive(&manifest, &files, &archive).unwrap();
        assert!(read_archive_in(&archive, Some(&unsafe_parent)).is_err());
        assert_eq!(fs::read_dir(&unsafe_parent).unwrap().count(), 0);
        let verified = read_archive_in(&archive, Some(root.path())).unwrap();
        assert_eq!(
            fs::read(verified.entry_path("case.json").unwrap()).unwrap(),
            b"case"
        );
        let extracted = verified.root().to_owned();
        drop(verified);
        assert!(!extracted.exists());
    }

    #[cfg(unix)]
    #[test]
    fn physical_symlinks_hardlinks_and_fifo_inputs_are_rejected() {
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::symlink;
        let directory = private_fixture();
        let source = directory.path().join("source");
        let alias = directory.path().join("alias");
        fs::write(&source, b"case").unwrap();
        symlink(&source, &alias).unwrap();
        assert!(open_regular(&alias, MAX_ARCHIVE_ENTRY_BYTES).is_err());
        fs::remove_file(&alias).unwrap();
        fs::hard_link(&source, &alias).unwrap();
        assert!(open_regular(&source, MAX_ARCHIVE_ENTRY_BYTES).is_err());
        fs::remove_file(&alias).unwrap();
        let fifo = directory.path().join("fifo");
        let fifo_c = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        // SAFETY: a nul-terminated path into the owned temporary test directory.
        assert_eq!(unsafe { libc::mkfifo(fifo_c.as_ptr(), 0o600) }, 0);
        assert!(open_regular(&fifo, MAX_ARCHIVE_ENTRY_BYTES).is_err());
    }

    #[test]
    fn same_handle_verification_rejects_in_place_mutation_and_path_replacement() {
        let directory = private_fixture();
        let source = directory.path().join("source");
        fs::write(&source, b"original").unwrap();
        let (file, before) = open_regular(&source, MAX_ARCHIVE_ENTRY_BYTES).unwrap();
        fs::write(&source, b"changed and longer").unwrap();
        assert!(verify_unchanged(&source, &file, &before).is_err());
        drop(file);
        fs::write(&source, b"original").unwrap();
        let (file, before) = open_regular(&source, MAX_ARCHIVE_ENTRY_BYTES).unwrap();
        rename_entry_no_replace(&source, &directory.path().join("old-source")).unwrap();
        fs::write(&source, b"original").unwrap();
        assert!(verify_unchanged(&source, &file, &before).is_err());
    }

    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    #[test]
    fn directory_publication_is_atomic_and_never_replaces_an_existing_destination() {
        let directory = private_fixture();
        let stage = directory.path().join("staging");
        let destination = directory.path().join("restored");
        private_fixture_directory(&stage);
        fs::write(stage.join("casework.db"), b"complete staged fixture").unwrap();
        private_fixture_directory(&destination);
        assert!(publish_directory_no_replace(&stage, &destination).is_err());
        assert!(stage.join("casework.db").exists());
        assert_eq!(fs::read_dir(&destination).unwrap().count(), 0);
        fs::remove_dir(&destination).unwrap();
        publish_directory_no_replace(&stage, &destination).unwrap();
        assert!(!stage.exists());
        assert_eq!(
            fs::read(destination.join("casework.db")).unwrap(),
            b"complete staged fixture"
        );
    }
}

#[cfg(all(test, unix))]
#[test]
fn unsafe_parent_keeps_case_archive_wording() {
    use std::os::unix::fs::PermissionsExt;
    let temp = crate::test_temp::tempdir().unwrap();
    let parent = temp.path().join("untrusted");
    fs::create_dir(&parent).unwrap();
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o770)).unwrap();
    let error = match guard_archive_parent(&parent) {
        Ok(_) => panic!("unsafe ancestor accepted"),
        Err(error) => error,
    };
    assert!(matches!(error, AppError::UnsafeArchiveParent));
    assert_eq!(
        error.to_string(),
        "invalid request: case archive: archive parent has an untrusted writable ancestor"
    );
}
