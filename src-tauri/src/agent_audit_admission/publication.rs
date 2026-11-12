//! Admission-specific publication using the shared artifact path checks.
use crate::artifact_store::{
    ArtifactStore, inspect_raw_artifacts, normalized_artifact_relative_path,
    open_read_write_no_follow, prepare_private_directory_component, sha256_bytes,
    unsafe_artifact_path, verify_control_path_identity,
};
use crate::domain::RawArtifact;
use crate::error::AppError;
use std::fs;
#[cfg(unix)]
use std::fs::OpenOptions;
use std::io::Write;

/// A pre-existing original is reusable only when its complete bytes match.
#[derive(Debug, thiserror::Error)]
pub(crate) enum OriginalPublicationError {
    #[error("artifact_conflict")]
    Conflict,
    #[error(transparent)]
    Other(#[from] AppError),
}
impl From<std::io::Error> for OriginalPublicationError {
    fn from(error: std::io::Error) -> Self {
        Self::Other(error.into())
    }
}

impl ArtifactStore {
    pub(crate) fn publish_original(
        &self,
        artifact: &RawArtifact,
        bytes: &[u8],
        planned: &[RawArtifact],
    ) -> Result<(), OriginalPublicationError> {
        use OriginalPublicationError::Conflict;
        if bytes.len() as u64 != artifact.byte_length || sha256_bytes(bytes) != artifact.sha256 {
            return Err(Conflict);
        }
        let relative = normalized_artifact_relative_path(artifact)?;
        let _parent_guard = crate::case_archive_io::guard_archive_parent(self.root())?;
        let mut parent = self.root().to_path_buf();
        let mut directories = vec![parent.clone()];
        for component in relative.parent().unwrap().components() {
            let name = component
                .as_os_str()
                .to_str()
                .ok_or_else(|| unsafe_artifact_path(artifact))?;
            parent = prepare_private_directory_component(self.root(), &parent, name)?;
            crate::case_archive_io::make_private(&parent, true)?;
            directories.push(parent.clone());
        }
        let path = parent.join(relative.file_name().unwrap());
        // Only crash leftovers in this publication namespace are disposable.
        // A package member can itself have this spelling; preserve every planned path.
        for entry in fs::read_dir(&parent)? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            if !name.starts_with(".admission-") || !name.ends_with(".tmp") {
                continue;
            }
            let candidate = entry.path();
            if candidate == path
                || planned
                    .iter()
                    .any(|a| self.root().join(&a.relative_path) == candidate)
            {
                continue;
            }
            let metadata = fs::symlink_metadata(&candidate)?;
            if !metadata.file_type().is_file() {
                continue;
            }
            #[cfg(windows)]
            {
                use std::os::windows::fs::MetadataExt;
                if metadata.file_attributes()
                    & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
                    != 0
                {
                    continue;
                }
            }
            fs::remove_file(candidate)?;
        }
        let reuse = || -> Result<(), OriginalPublicationError> {
            inspect_raw_artifacts(self.root(), std::slice::from_ref(artifact))
                .map_err(|_| Conflict)?;
            let file = open_read_write_no_follow(&path)?;
            verify_control_path_identity(self.root(), &path, &file)?;
            crate::case_archive_io::verify_regular_original(&file).map_err(|_| Conflict)?;
            crate::case_archive_io::make_private(&path, false)?;
            file.sync_all()?;
            Ok(())
        };
        match fs::symlink_metadata(&path) {
            Ok(_) => reuse()?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                // NamedTempFile creates a new file without following links, with
                // owner-only mode on Unix and the private parent's ACL on Windows.
                // Its drop removes the temporary on every ordinary error path.
                let mut temporary = tempfile::Builder::new()
                    .prefix(".admission-")
                    .suffix(".tmp")
                    .tempfile_in(&parent)?;
                verify_control_path_identity(self.root(), temporary.path(), temporary.as_file())?;
                crate::case_archive_io::verify_regular_original(temporary.as_file())
                    .map_err(|_| Conflict)?;
                crate::case_archive_io::make_private(temporary.path(), false)?;
                temporary.write_all(bytes)?;
                temporary.as_file().sync_all()?;
                match temporary.persist_noclobber(&path) {
                    Ok(file) => {
                        verify_control_path_identity(self.root(), &path, &file)?;
                        crate::case_archive_io::verify_regular_original(&file)
                            .map_err(|_| Conflict)?;
                        crate::case_archive_io::make_private(&path, false)?;
                    }
                    Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {
                        drop(error);
                        reuse()?;
                    }
                    Err(error) => return Err(error.error.into()),
                }
            }
            Err(error) => return Err(error.into()),
        }
        for directory in directories.iter().rev() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                    .open(directory)?
                    .sync_all()?;
            }
            #[cfg(not(unix))]
            let _ = directory;
        }
        inspect_raw_artifacts(self.root(), std::slice::from_ref(artifact)).map_err(|_| Conflict)?;
        Ok(())
    }
}

#[cfg(test)]
mod admitted_original_tests {
    use super::*;
    use chrono::Utc;
    use std::fs;
    #[test]
    fn admission_original_create_reuse_conflict_and_no_links() {
        let temp = crate::test_temp::tempdir().unwrap();
        crate::case_archive_io::make_private(temp.path(), true).unwrap();
        let store = ArtifactStore::open(temp.path().join("artifacts")).unwrap();
        let bytes = b"original";
        let artifact = RawArtifact {
            id: "original".into(),
            case_id: "case".into(),
            run_id: "run".into(),
            engine_run_id: "task".into(),
            relative_path: "case/run/task/retained/findings.json".into(),
            media_type: "application/json".into(),
            sha256: sha256_bytes(bytes),
            byte_length: bytes.len() as u64,
            created_at: Utc::now(),
            contains_sensitive_data: true,
        };
        let path = store.root().join(&artifact.relative_path);
        let parent = path.parent().unwrap();
        fs::create_dir_all(parent).unwrap();
        let stale = parent.join(".admission-crashed.tmp");
        fs::write(&stale, b"partial").unwrap();
        let unrelated = parent.join("keep.tmp");
        fs::write(&unrelated, b"unrelated").unwrap();
        let unrelated_prefix = parent.join(".admission-keep.txt");
        fs::write(&unrelated_prefix, b"unrelated prefix").unwrap();
        let directory = parent.join(".admission-directory.tmp");
        fs::create_dir(&directory).unwrap();
        let mut reserved = artifact.clone();
        reserved.relative_path = "case/run/task/retained/.admission-member.tmp".into();
        let reserved_path = store.root().join(&reserved.relative_path);
        fs::write(&reserved_path, bytes).unwrap();
        let planned = [artifact.clone(), reserved];
        #[cfg(unix)]
        let link = {
            let link = parent.join(".admission-link.tmp");
            std::os::unix::fs::symlink(&unrelated, &link).unwrap();
            link
        };
        store.publish_original(&artifact, bytes, &planned).unwrap();
        assert!(!stale.exists());
        assert_eq!(fs::read(&reserved_path).unwrap(), bytes);
        assert_eq!(fs::read(&unrelated).unwrap(), b"unrelated");
        assert_eq!(fs::read(&unrelated_prefix).unwrap(), b"unrelated prefix");
        assert!(directory.is_dir());
        #[cfg(unix)]
        assert!(fs::symlink_metadata(link).unwrap().file_type().is_symlink());
        fs::remove_file(reserved_path).unwrap();
        store
            .publish_original(&artifact, bytes, std::slice::from_ref(&artifact))
            .unwrap();
        store
            .publish_original(&artifact, bytes, std::slice::from_ref(&artifact))
            .unwrap();
        let path = store.root().join(&artifact.relative_path);
        fs::write(&path, b"different").unwrap();
        assert!(matches!(
            store.publish_original(&artifact, bytes, std::slice::from_ref(&artifact)),
            Err(OriginalPublicationError::Conflict)
        ));
        assert_eq!(fs::read(&path).unwrap(), b"different");
        #[cfg(unix)]
        {
            fs::remove_file(&path).unwrap();
            let outside = temp.path().join("outside");
            fs::write(&outside, bytes).unwrap();
            std::os::unix::fs::symlink(&outside, &path).unwrap();
            assert!(matches!(
                store.publish_original(&artifact, bytes, std::slice::from_ref(&artifact)),
                Err(OriginalPublicationError::Conflict)
            ));
            assert_eq!(fs::read(&outside).unwrap(), bytes);
            fs::remove_file(&path).unwrap();
            fs::hard_link(&outside, &path).unwrap();
            assert!(matches!(
                store.publish_original(&artifact, bytes, std::slice::from_ref(&artifact)),
                Err(OriginalPublicationError::Conflict)
            ));
        }
    }
}
