//! Canonical paths used by new product internals and child processes.
use std::path::{Path, PathBuf};

/// Preserve canonical identity while using an ordinary Windows path whenever safe.
/// User input must still pass its own validation before reaching this helper.
pub fn canonicalize(path: impl AsRef<Path>) -> std::io::Result<PathBuf> {
    dunce::canonicalize(path)
}

/// Apply std's 248-code-unit threshold to an absolute Windows path (without NUL).
/// Keep device namespaces intact; only ordinary drive and UNC paths need a prefix.
#[cfg(any(windows, test))]
fn extended_windows_path(path: &[u16]) -> Vec<u16> {
    const SLASH: u16 = b'\\' as u16;
    if path.len() < 248
        || path.starts_with(&[SLASH, SLASH, b'?' as u16, SLASH])
        || path.starts_with(&[SLASH, SLASH, b'.' as u16, SLASH])
        || path.starts_with(&[SLASH, b'?' as u16, b'?' as u16, SLASH])
    {
        return path.to_vec();
    }
    let (prefix, tail) = if path.get(1..3) == Some(&[b':' as u16, SLASH]) {
        (r"\\?\", path)
    } else if path.starts_with(&[SLASH, SLASH]) {
        (r"\\?\UNC\", &path[2..])
    } else {
        return path.to_vec();
    };
    prefix.encode_utf16().chain(tail.iter().copied()).collect()
}

#[cfg(any(windows, test))]
fn windows_path_buffer(path: &[u16]) -> std::io::Result<Vec<u16>> {
    if path.contains(&0) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Windows path contains NUL",
        ));
    }
    Ok(extended_windows_path(path)
        .into_iter()
        .chain(Some(0))
        .collect())
}

/// Encode only at the direct Win32 boundary; stored/internal paths stay ordinary.
#[cfg(windows)]
pub(crate) fn win32_path(path: &Path) -> std::io::Result<Vec<u16>> {
    use std::os::windows::ffi::OsStrExt;
    let path = std::path::absolute(path)?;
    windows_path_buffer(&path.as_os_str().encode_wide().collect::<Vec<_>>())
}

#[cfg(test)]
mod tests {
    use super::{extended_windows_path, windows_path_buffer};

    fn check(path: &str, expected: &str) {
        assert_eq!(
            extended_windows_path(&path.encode_utf16().collect::<Vec<_>>()),
            expected.encode_utf16().collect::<Vec<_>>()
        );
        assert_eq!(
            windows_path_buffer(&path.encode_utf16().collect::<Vec<_>>()).unwrap(),
            expected.encode_utf16().chain(Some(0)).collect::<Vec<_>>()
        );
    }

    #[test]
    fn windows_path_buffer_rejects_embedded_nul() {
        assert_eq!(
            windows_path_buffer(&[b'C' as u16, 0, b'x' as u16])
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn windows_short_drive_path_stays_ordinary() {
        check(r"C:\short\file", r"C:\short\file");
        let path = format!("C:\\{}", "a".repeat(244));
        check(&path, &path); // 247 UTF-16 units, excluding the terminator.
    }

    #[test]
    fn windows_long_drive_path_gets_extended_prefix() {
        let path = format!("C:\\{}", "a".repeat(245));
        check(&path, &format!(r"\\?\{path}"));
        let path = format!("C:\\a{}", "😀".repeat(122));
        check(&path, &format!(r"\\?\{path}")); // UTF-16 units, not characters.
    }

    #[test]
    fn windows_long_unc_path_gets_extended_unc_prefix() {
        let tail = format!("server\\share\\{}", "a".repeat(248));
        check(&format!(r"\\{tail}"), &format!(r"\\?\UNC\{tail}"));
        check(r"\\server\share\short", r"\\server\share\short");
    }

    #[test]
    fn windows_device_paths_stay_unchanged() {
        for prefix in [
            r"\\?\C:\",
            r"\\?\UNC\server\share\",
            r"\??\C:\",
            r"\\.\",
            r"\Device\",
        ] {
            let path = format!("{prefix}{}", "a".repeat(248));
            check(&path, &path);
        }
    }
}
