use super::*;
use crate::case_archive_io::{
    guard_archive_parent, make_private, private_tempdir_in, rename_entry_no_replace,
};
use crate::cloudflare_provider::bundle_io::BundleRoot;
use std::{fs, io::Write};

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DescriptorState {
    Verified,
    Missing,
    Mismatch,
}
pub(super) fn directory(data: &Path, receipt: &PreparationReceipt) -> Option<PathBuf> {
    receipt.session_id().map(|id| {
        data.join("artifacts")
            .join(&receipt.case_id)
            .join("cloudflare-sessions")
            .join(id)
    })
}
pub fn descriptor_state(data: &Path, receipt: &PreparationReceipt) -> DescriptorState {
    let Some(path) = directory(data, receipt) else {
        return DescriptorState::Missing;
    };
    let file = path.join("session.json");
    let read = || -> AppResult<Vec<u8>> {
        let mut root = BundleRoot::open(&path)?;
        let bytes = root.read("session.json", 1024 * 1024)?;
        root.verify_unchanged()?;
        Ok(bytes)
    };
    match read() {
        Ok(bytes) => match &receipt.result {
            PreparationResult::Prepared {
                facts,
                descriptor_sha256,
            } if digest(&bytes) == *descriptor_sha256
                && canonical_bytes(facts).is_ok_and(|b| b == bytes) =>
            {
                DescriptorState::Verified
            }
            _ => DescriptorState::Mismatch,
        },
        Err(_) => {
            // A dangling link or unsafe ancestor is a mismatch, not a recoverable absence.
            let mut cursor = Some(file.as_path());
            while let Some(path) = cursor {
                match fs::symlink_metadata(path) {
                    Ok(m) if m.file_type().is_symlink() => return DescriptorState::Mismatch,
                    Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                        return DescriptorState::Mismatch;
                    }
                    _ => {}
                }
                cursor = path.parent();
            }
            if fs::symlink_metadata(file).is_err() {
                DescriptorState::Missing
            } else {
                DescriptorState::Mismatch
            }
        }
    }
}
pub(super) fn publish(data: &Path, receipt: &PreparationReceipt) -> AppResult<()> {
    let PreparationResult::Prepared { facts, .. } = &receipt.result else {
        return Ok(());
    };
    match descriptor_state(data, receipt) {
        DescriptorState::Verified => return Ok(()),
        DescriptorState::Mismatch => {
            return Err(AppError::Storage(
                "audit descriptor mismatch; existing bytes preserved".into(),
            ));
        }
        DescriptorState::Missing => {}
    }
    let directory = directory(data, receipt).unwrap();
    ensure_directory(directory.parent().unwrap())?;
    ensure_directory(&directory)?;
    publish_bytes(&directory, "session.json", &canonical_bytes(facts)?)
}
pub(super) fn ensure_directory(path: &Path) -> AppResult<()> {
    let _root = BundleRoot::open(path.parent().unwrap())?;
    let _guard = guard_archive_parent(path.parent().unwrap())?;
    #[cfg(unix)]
    let created = {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new().mode(0o700).create(path)
    };
    #[cfg(not(unix))]
    let created = fs::create_dir(path);
    match created {
        Ok(()) => make_private(path, true)?,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            let _ = BundleRoot::open(path)?;
        }
        Err(e) => return Err(e.into()),
    }
    #[cfg(unix)]
    fs::File::open(path.parent().unwrap())?.sync_all()?;
    Ok(())
}
pub(super) fn publish_bytes(directory: &Path, name: &str, bytes: &[u8]) -> AppResult<()> {
    let _guard = guard_archive_parent(directory)?;
    let temporary = private_tempdir_in(directory, ".publish-")?;
    let staged = temporary.path().join(name);
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&staged)?;
    make_private(&staged, false)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    rename_entry_no_replace(&staged, &directory.join(name))?;
    #[cfg(unix)]
    fs::File::open(directory)?.sync_all()?;
    Ok(())
}

/// Publish captured bytes before committing their record entry. Orphans are reusable.
pub(super) fn publish_object(
    data: &Path,
    receipt: &PreparationReceipt,
    bytes: &[u8],
) -> AppResult<()> {
    let path = directory(data, receipt)
        .ok_or_else(|| invalid("object requires prepared run"))?
        .join("objects");
    ensure_directory(&path)
        .and_then(|()| object(&path, bytes))
        .map_err(|e| AppError::Storage(e.to_string()))
}
fn object(directory: &Path, bytes: &[u8]) -> AppResult<()> {
    let _guard = guard_archive_parent(directory)?;
    let name = digest(bytes);
    let check = || verified_object(directory, &name, bytes.len() as u64).map(|_| ());
    match fs::symlink_metadata(directory.join(&name)) {
        Ok(_) => return check(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    publish_bytes(directory, &name, bytes)?;
    check()
}

pub(super) fn read_object(
    data: &Path,
    receipt: &PreparationReceipt,
    sha256: &str,
    length: u64,
) -> AppResult<Vec<u8>> {
    let path = directory(data, receipt)
        .ok_or_else(|| invalid("object requires prepared run"))?
        .join("objects");
    verified_object(&path, sha256, length).map_err(|e| AppError::Storage(e.to_string()))
}
fn verified_object(directory: &Path, name: &str, length: u64) -> AppResult<Vec<u8>> {
    if !valid_hash(name) {
        return Err(invalid("invalid object digest"));
    }
    let mut root = BundleRoot::open(directory)?;
    let bytes = root.read(name, length)?;
    root.verify_unchanged()?;
    if bytes.len() as u64 != length || digest(&bytes) != name {
        return Err(AppError::Storage(
            "audit object mismatch; existing bytes preserved".into(),
        ));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn audit_objects_reuse_orphans_preserve_corruption_and_are_private() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().canonicalize().unwrap();
        make_private(&path, true).unwrap();
        object(&path, b"captured").unwrap();
        let file = path.join(digest(b"captured"));
        let original = fs::metadata(&file).unwrap();
        object(&path, b"captured").unwrap();
        assert_eq!(
            fs::metadata(&file).unwrap().modified().unwrap(),
            original.modified().unwrap()
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(original.permissions().mode() & 0o777, 0o600);
        }
        fs::write(&file, b"corrupt!").unwrap();
        assert!(object(&path, b"captured").is_err());
        assert_eq!(fs::read(file).unwrap(), b"corrupt!");
        assert_eq!(fs::read_dir(path).unwrap().count(), 1);
    }
}
