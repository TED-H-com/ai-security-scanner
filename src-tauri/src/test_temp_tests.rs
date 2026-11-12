// Unit tests for the shared temporary-root helper. They live here, not in
// test_temp.rs, so the targets that include that file do not run them again.
use crate::test_temp::{TempDir, tempdir};
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::{PermissionsExt, symlink};

#[cfg(unix)]
#[test]
fn canonicalizes_temporary_roots_reached_through_symlinked_parents() {
    let parent = tempdir().unwrap();
    let real = parent.path().join("real");
    let alias = parent.path().join("alias");
    fs::create_dir(&real).unwrap();
    symlink(&real, &alias).unwrap();
    let root = TempDir::from(tempfile::tempdir_in(&alias).unwrap());
    let path = root.path().to_owned();
    assert_eq!(path, path.canonicalize().unwrap());
    assert_eq!(path.parent(), Some(real.as_path()));
    drop(root);
    assert!(!path.exists());
    assert!(alias.is_symlink());
}

#[cfg(unix)]
#[test]
fn removes_read_only_nested_directories_and_files() {
    let root = tempdir().unwrap();
    let path = root.path().to_path_buf();
    let nested = path.join("published/nested");
    fs::create_dir_all(&nested).unwrap();
    fs::write(nested.join("payload"), b"read only").unwrap();
    fs::set_permissions(nested.join("payload"), fs::Permissions::from_mode(0o400)).unwrap();
    fs::set_permissions(&nested, fs::Permissions::from_mode(0o000)).unwrap();
    fs::set_permissions(path.join("published"), fs::Permissions::from_mode(0o500)).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o500)).unwrap();
    drop(root);
    assert!(!path.exists());
}

#[cfg(unix)]
#[test]
fn removes_links_without_changing_external_targets() {
    let outside = TempDir::new().unwrap();
    let target = outside.path().join("target");
    fs::create_dir(&target).unwrap();
    let file = target.join("payload");
    fs::write(&file, b"external").unwrap();
    fs::set_permissions(&file, fs::Permissions::from_mode(0o400)).unwrap();
    fs::set_permissions(&target, fs::Permissions::from_mode(0o500)).unwrap();
    let root = tempdir().unwrap();
    let path = root.path().to_path_buf();
    symlink(&target, path.join("directory-link")).unwrap();
    symlink(&file, path.join("file-link")).unwrap();
    symlink(target.join("missing"), path.join("dangling-link")).unwrap();
    drop(root);
    assert!(!path.exists());
    assert_eq!(
        fs::metadata(&target).unwrap().permissions().mode() & 0o777,
        0o500
    );
    assert_eq!(
        fs::metadata(&file).unwrap().permissions().mode() & 0o777,
        0o400
    );
    assert_eq!(fs::read(file).unwrap(), b"external");
}

#[cfg(unix)]
#[test]
fn failed_removal_panics_with_root_and_failed_entry() {
    let owner = tempdir().unwrap();
    let parent = owner.path().join("parent");
    let moved = owner.path().join("moved-parent");
    fs::create_dir(&parent).unwrap();
    let root = TempDir::from(tempfile::tempdir_in(&parent).unwrap());
    let path = root.path().to_path_buf();
    // A non-directory ancestor prevents removal even when tests run as root.
    fs::rename(&parent, &moved).unwrap();
    fs::write(&parent, b"blocked ancestor").unwrap();
    let panic = std::panic::catch_unwind(|| drop(root));
    fs::remove_file(&parent).unwrap();
    fs::rename(&moved, &parent).unwrap();
    let message = panic.unwrap_err().downcast::<String>().unwrap();
    assert!(message.contains(&format!("temporary root {}", path.display())));
    assert!(message.contains(&format!("first failed entry {}", path.display())));
    assert!(path.exists());
    // The outer owner removes the restored tree, including the failed root.
}

#[test]
fn preserves_builder_options_and_accepts_an_already_removed_root() {
    let parent = tempdir().unwrap();
    let mut builder = tempfile::Builder::new();
    builder.prefix("product-test-");
    #[cfg(unix)]
    builder.permissions(fs::Permissions::from_mode(0o700));
    let root = TempDir::from(builder.tempdir_in(parent.path()).unwrap());
    assert_eq!(root.path().parent(), Some(parent.path()));
    assert!(
        root.path()
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("product-test-")
    );
    #[cfg(unix)]
    assert_eq!(
        fs::metadata(root.path()).unwrap().permissions().mode() & 0o777,
        0o700
    );
    fs::remove_dir(root.path()).unwrap();
    drop(root);
}
