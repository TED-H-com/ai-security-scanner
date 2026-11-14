use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;

#[allow(dead_code)]
#[path = "../fixtures/runtime/fixture_runtime.rs"]
mod fixture_program;
const SOURCE: &str = include_str!("../fixtures/runtime/fixture_runtime.rs");

fn built() -> &'static Path {
    static BUILT: OnceLock<PathBuf> = OnceLock::new();
    BUILT
        .get_or_init(|| {
            let mut hash = 0xcbf29ce484222325u64;
            for byte in SOURCE.bytes() {
                hash = (hash ^ u64::from(byte)).wrapping_mul(0x100000001b3);
            }
            let cache = Path::new(env!("CARGO_TARGET_TMPDIR"))
                .join("fixture-runtime")
                .join(format!("{hash:016x}"));
            fs::create_dir_all(&cache).unwrap();
            let final_path = cache.join(format!("fixture-runtime{}", std::env::consts::EXE_SUFFIX));
            if final_path.is_file() {
                return final_path;
            }
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let build = cache.join(format!("build-{}-{nanos}", std::process::id()));
            fs::create_dir(&build).unwrap();
            fs::write(build.join("main.rs"), SOURCE).unwrap();
            let output = build.join(format!("fixture-runtime{}", std::env::consts::EXE_SUFFIX));
            let rustc = std::env::var_os("RUSTC")
                .map(PathBuf::from)
                .or_else(|| {
                    std::env::var_os("CARGO").and_then(|cargo| {
                        let path = PathBuf::from(cargo)
                            .with_file_name(format!("rustc{}", std::env::consts::EXE_SUFFIX));
                        path.is_file().then_some(path)
                    })
                })
                .unwrap_or_else(|| PathBuf::from("rustc"));
            let result = Command::new(rustc)
                .args([
                    "--edition",
                    "2024",
                    "--crate-name",
                    "fixture_runtime",
                    "-C",
                    "debuginfo=0",
                    "-C",
                    "opt-level=0",
                    "-o",
                ])
                .arg(&output)
                .arg("main.rs")
                .current_dir(&build)
                .stdin(Stdio::null())
                .output()
                .expect("start rustc");
            assert!(
                result.status.success(),
                "fixture rustc failed: stdout={} stderr={}",
                String::from_utf8_lossy(&result.stdout),
                String::from_utf8_lossy(&result.stderr)
            );
            if let Err(e) = fs::rename(&output, &final_path) {
                assert!(final_path.is_file(), "publish fixture: {e}");
            }
            let _ = fs::remove_dir_all(&build);
            final_path
        })
        .as_path()
}
pub fn install(directory: &Path, personality: &str, mode: &str) {
    let executable = directory.join(format!("docker{}", std::env::consts::EXE_SUFFIX));
    fs::copy(built(), &executable).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
    }
    fs::write(directory.join("personality"), personality).unwrap();
    fs::write(directory.join("mode"), mode).unwrap();
}
pub fn process_is_gone(pid: u32) -> bool {
    #[cfg(unix)]
    {
        unsafe { libc::kill(pid as libc::pid_t, 0) == -1 }
    }
    #[cfg(windows)]
    {
        use windows_sys::Win32::Foundation::{CloseHandle, WAIT_OBJECT_0};
        use windows_sys::Win32::System::Threading::{
            OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
            WaitForSingleObject,
        };
        unsafe {
            let handle = OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
                0,
                pid,
            );
            if handle.is_null() {
                true
            } else {
                let gone = WaitForSingleObject(handle, 0) == WAIT_OBJECT_0;
                CloseHandle(handle);
                gone
            }
        }
    }
}

pub struct ReleaseOnDrop(pub PathBuf);

impl Drop for ReleaseOnDrop {
    fn drop(&mut self) {
        let _ = fs::write(&self.0, "release fixture");
        let Some(root) = self.0.parent() else {
            return;
        };
        let mut pids = Vec::new();
        for name in ["blocked.json", "running.json", "cleanup.json"] {
            if let Ok(bytes) = fs::read(root.join(name))
                && let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes)
                && let Some(pid) = value["pid"].as_u64()
            {
                pids.push(pid as u32);
            }
        }
        if let Ok(pid) = fs::read_to_string(root.join("holder.pid"))
            && let Ok(pid) = pid.parse::<u32>()
        {
            pids.push(pid);
        }
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        while pids.iter().any(|pid| !process_is_gone(*pid)) && std::time::Instant::now() < deadline
        {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }
}

#[cfg(windows)]
pub fn new_console_process_group(command: &mut Command) {
    use std::os::windows::process::CommandExt;
    use windows_sys::Win32::System::Console::{AllocConsole, GetConsoleCP};
    use windows_sys::Win32::System::Threading::CREATE_NEW_PROCESS_GROUP;

    if unsafe { GetConsoleCP() } == 0 {
        assert_ne!(unsafe { AllocConsole() }, 0, "allocate test console");
    }
    command.creation_flags(CREATE_NEW_PROCESS_GROUP);
}

#[cfg(windows)]
pub fn send_ctrl_break(pid: u32) {
    use windows_sys::Win32::System::Console::{CTRL_BREAK_EVENT, GenerateConsoleCtrlEvent};

    assert_ne!(
        unsafe { GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, pid) },
        0,
        "send Ctrl+Break: {}",
        std::io::Error::last_os_error()
    );
}
#[allow(dead_code)]
pub fn make_tree_removable(path: &Path) {
    let metadata = fs::symlink_metadata(path).unwrap();
    assert!(!metadata.file_type().is_symlink());
    #[cfg(unix)]
    if metadata.is_dir() {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    #[cfg(windows)]
    {
        let mut permissions = metadata.permissions();
        permissions.set_readonly(false);
        fs::set_permissions(path, permissions).unwrap();
    }
    if metadata.is_dir() {
        for entry in fs::read_dir(path).unwrap() {
            make_tree_removable(&entry.unwrap().path());
        }
    }
}
#[allow(dead_code)]
pub fn node() -> PathBuf {
    std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
        .map(|dir| dir.join(format!("node{}", std::env::consts::EXE_SUFFIX)))
        .find(|path| path.is_file())
        .expect("bootstrap integration requires Node.js")
}
