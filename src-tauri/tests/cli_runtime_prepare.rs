//! Runtime preparation uses a private executable fixture. No container service,
//! registry, scan target, or real scanner is contacted by these tests.
#![cfg(feature = "cli")]

#[path = "support/fixture_runtime.rs"]
mod fixture_runtime;

use ai_security_scanner_lib::process_lease::DataDirectoryExclusiveLease;
use ai_security_scanner_lib::registry::EngineRegistry;
use serde_json::{Value, json};
use std::fs;
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

struct Fixture {
    _root: tempfile::TempDir,
    data: PathBuf,
    bin: PathBuf,
}

impl Fixture {
    fn new(mode: &str) -> Self {
        let root = tempfile::tempdir().unwrap();
        let directory = paths::canonical(root.path());
        let bin = directory.join("fake-runtime");
        fs::create_dir(&bin).unwrap();
        fixture_runtime::install(&bin, "preparation", mode);
        Self {
            data: directory.join("data"),
            _root: root,
            bin,
        }
    }

    fn command(&self, explicit_data: bool) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_ai-security-scanner-cli"));
        if explicit_data {
            command.arg("--data-dir").arg(&self.data);
        }
        command.arg("--json");
        command.env("PATH", &self.bin);
        command.env_remove("AI_SECURITY_SCANNER_MANAGED_RUNTIME_BUNDLE");
        command.env_remove("AI_SECURITY_SCANNER_RELEASE_APPROVED_LOCAL_IMAGE_DIRECTORY");
        command
    }

    fn prepare(&self, engines: &str, offline: bool) -> Command {
        let mut command = self.command(true);
        command.args(["runtime", "prepare", "--engine", engines]);
        if offline {
            command.arg("--offline");
        }
        command
    }

    fn calls(&self) -> Vec<Value> {
        fs::read_to_string(self.bin.join("calls.jsonl"))
            .unwrap_or_default()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    fn assert_no_execution(&self) {
        for call in self.calls() {
            assert!(
                matches!(
                    call[0].as_str(),
                    Some("version" | "info" | "image" | "pull")
                ),
                "preparation attempted a target-facing or unrelated runtime operation: {call}"
            );
            if call[0] == "image" {
                assert_eq!(call[1], "inspect");
            }
        }
        assert!(!self.data.join("artifacts").exists());
        assert!(!self.data.join("casework.db").exists());
    }

    fn assert_receipt(&self, result: &Value) {
        assert_eq!(
            result["schema_version"],
            "ai-security-scanner.runtime-preparation/v1"
        );
        let path = Path::new(result["receipt_path"].as_str().expect("receipt path"));
        assert!(path.is_absolute());
        assert!(
            path.canonicalize()
                .unwrap()
                .starts_with(self.data.canonicalize().unwrap())
        );
        #[cfg(unix)]
        assert_eq!(fs::metadata(path).unwrap().permissions().mode() & 0o077, 0);
        let saved: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        for field in ["schema_version", "engines", "offline", "ready", "images"] {
            assert_eq!(
                saved[field], result[field],
                "persisted receipt field {field}"
            );
        }
        self.assert_no_execution();
    }
}

struct Running {
    child: Option<Child>,
    stdout: Option<JoinHandle<Vec<u8>>>,
    stderr: Option<JoinHandle<Vec<u8>>>,
}

fn read_pipe(mut pipe: impl Read + Send + 'static) -> JoinHandle<Vec<u8>> {
    thread::spawn(move || {
        let mut bytes = Vec::new();
        pipe.read_to_end(&mut bytes).unwrap();
        bytes
    })
}

impl Running {
    fn spawn(mut command: Command) -> Self {
        let mut child = command
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let stdout = Some(read_pipe(child.stdout.take().unwrap()));
        let stderr = Some(read_pipe(child.stderr.take().unwrap()));
        Self {
            child: Some(child),
            stdout,
            stderr,
        }
    }

    fn await_blocked(&mut self, fixture: &Fixture) -> Value {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Ok(bytes) = fs::read(fixture.bin.join("blocked.json"))
                && let Ok(value) = serde_json::from_slice(&bytes)
            {
                return value;
            }
            assert!(
                self.child.as_mut().unwrap().try_wait().unwrap().is_none(),
                "CLI exited before controlled image inspection: {:?}",
                fixture.calls()
            );
            assert!(Instant::now() < deadline, "image inspection did not start");
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn wait(mut self) -> Output {
        let deadline = Instant::now() + Duration::from_secs(20);
        let status = loop {
            if let Some(status) = self.child.as_mut().unwrap().try_wait().unwrap() {
                break status;
            }
            assert!(
                Instant::now() < deadline,
                "runtime preparation exceeded its test deadline"
            );
            thread::sleep(Duration::from_millis(10));
        };
        self.child.take();
        Output {
            status,
            stdout: self.stdout.take().unwrap().join().unwrap(),
            stderr: self.stderr.take().unwrap().join().unwrap(),
        }
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        if let Some(child) = self.child.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn result(output: &Output, code: i32) -> Value {
    assert_eq!(
        output.status.code(),
        Some(code),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("one JSON preparation outcome")
}

fn image_for(engine_id: &str) -> String {
    let registry = EngineRegistry::load_builtin().unwrap();
    let image = registry.get(engine_id).unwrap().image.as_ref().unwrap();
    format!(
        "{}@{}",
        image.repository,
        image
            .digest
            .as_ref()
            .expect("catalog image is digest pinned")
    )
}

#[test]
fn offline_prepares_only_selected_pins_and_gateway_without_creating_scan_work() {
    let fixture = Fixture::new("present");
    let output = Running::spawn(fixture.prepare("gitleaks,nuclei", true)).wait();
    let value = result(&output, 0);
    assert_eq!(value["ready"], true);
    assert_eq!(value["offline"], true);
    assert_eq!(value["engines"], json!(["gitleaks", "nuclei"]));
    assert!(value["runtime"].is_object());
    let images = value["images"].as_array().unwrap();
    assert_eq!(images.len(), 3);
    for id in ["gitleaks", "nuclei"] {
        assert!(images.iter().any(|image| image["role"] == "engine"
            && image["engine_ids"] == json!([id])
            && image["image"] == image_for(id)
            && image["status"] == "ready"
            && image["error"].is_null()));
    }
    assert!(images.iter().any(|image| image["role"] == "gateway"
        && image["engine_ids"] == json!(["nuclei"])
        && image["status"] == "ready"));
    assert!(fixture.calls().iter().all(|call| call[0] != "pull"));
    fixture.assert_receipt(&value);
}

#[test]
fn offline_missing_pin_is_a_durable_failure_without_registry_contact() {
    let fixture = Fixture::new("missing");
    let output = Running::spawn(fixture.prepare("gitleaks", true)).wait();
    let value = result(&output, 4);
    assert_eq!(value["ready"], false);
    assert_eq!(value["images"][0]["status"], "failed");
    assert!(value["images"][0]["error"].as_str().is_some());
    assert!(fixture.calls().iter().all(|call| call[0] != "pull"));
    fixture.assert_receipt(&value);
}

#[test]
fn one_failed_pin_preserves_prepared_siblings_and_exact_retrieval_scope() {
    let fixture = Fixture::new("mixed");
    let output = Running::spawn(fixture.prepare("gitleaks,nuclei", false)).wait();
    let value = result(&output, 4);
    assert_eq!(value["ready"], false);
    let images = value["images"].as_array().unwrap();
    assert_eq!(images.len(), 3);
    assert_eq!(
        images
            .iter()
            .filter(|image| image["status"] == "ready")
            .count(),
        2
    );
    assert!(
        images
            .iter()
            .any(|image| image["image"] == image_for("gitleaks") && image["status"] == "failed")
    );
    let requested = images
        .iter()
        .map(|image| image["image"].as_str().unwrap())
        .collect::<Vec<_>>();
    let pulls = fixture
        .calls()
        .into_iter()
        .filter(|call| call[0] == "pull")
        .collect::<Vec<_>>();
    assert_eq!(pulls.len(), 3);
    for call in pulls {
        assert!(requested.contains(&call[1].as_str().unwrap()));
        assert!(call[1].as_str().unwrap().contains("@sha256:"));
    }
    fixture.assert_receipt(&value);
}

#[cfg(unix)]
fn assert_receipt_failure_preserves_prepared_images(signal: Option<i32>) {
    let fixture = Fixture::new("block-nuclei");
    let mut running = Running::spawn(fixture.prepare("gitleaks,nuclei", true));
    let blocked = running.await_blocked(&fixture);
    let receipt_dir = fixture.data.join("runtime-preparations");
    fs::rename(&receipt_dir, fixture.data.join("displaced-preparations")).unwrap();
    fs::write(&receipt_dir, b"cannot create a receipt here").unwrap();
    if let Some(signal) = signal {
        let pid = running.child.as_ref().unwrap().id();
        assert_eq!(unsafe { libc::kill(pid as libc::pid_t, signal) }, 0);
        thread::sleep(Duration::from_millis(100));
    }
    fs::write(fixture.bin.join("release"), "finish fixture operation").unwrap();
    let output = running.wait();
    let expected_exit = match signal {
        Some(libc::SIGINT) => 130,
        Some(libc::SIGTERM) => 143,
        _ => 4,
    };
    let value = result(&output, expected_exit);
    assert!(
        value["images"]
            .as_array()
            .unwrap()
            .iter()
            .any(|image| { image["image"] == image_for("gitleaks") && image["status"] == "ready" })
    );
    assert!(value["runtime"].is_object());
    assert_eq!(value["receipt_path"], Value::Null);
    assert!(
        value["receipt_error"]
            .as_str()
            .is_some_and(|error| !error.is_empty() && error.chars().count() <= 2000)
    );
    assert_eq!(value["error_code"], "receipt_persistence_failed");
    assert_eq!(value["command_outcome"], "failed");
    assert!(fixture_runtime::process_is_gone(
        blocked["pid"].as_u64().unwrap() as u32
    ));
}

#[cfg(unix)]
#[test]
fn receipt_failure_preserves_prepared_images() {
    assert_receipt_failure_preserves_prepared_images(None);
}

#[cfg(unix)]
#[test]
fn receipt_failure_preserves_prepared_images_and_interrupt_exit() {
    assert_receipt_failure_preserves_prepared_images(Some(libc::SIGINT));
}

#[cfg(unix)]
#[test]
fn receipt_failure_preserves_prepared_images_and_termination_exit() {
    assert_receipt_failure_preserves_prepared_images(Some(libc::SIGTERM));
}

#[test]
fn malformed_engine_selection_and_missing_data_directory_fail_before_runtime_or_data_mutation() {
    for selection in [
        "unknown-fixture-engine",
        "gitleaks,gitleaks",
        "gitleaks,",
        "",
    ] {
        let fixture = Fixture::new("deny");
        let output = Running::spawn(fixture.prepare(selection, false)).wait();
        assert_eq!(
            output.status.code(),
            Some(2),
            "selection {selection:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(fixture.calls().is_empty());
        assert!(!fixture.data.exists());
    }
    let fixture = Fixture::new("deny");
    let mut command = fixture.command(false);
    command.args(["runtime", "prepare", "--engine", "gitleaks"]);
    let output = Running::spawn(command).wait();
    assert_eq!(output.status.code(), Some(2));
    assert!(fixture.calls().is_empty());
    assert!(!fixture.data.exists());
}

#[test]
fn held_writer_lease_rejects_preparation_before_runtime_contact() {
    let fixture = Fixture::new("deny");
    let _lease = DataDirectoryExclusiveLease::acquire(&fixture.data).unwrap();
    let output = Running::spawn(fixture.prepare("gitleaks", true)).wait();
    assert_eq!(
        output.status.code(),
        Some(3),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(fixture.calls().is_empty());
}

#[cfg(unix)]
#[test]
fn sigint_waits_for_the_bounded_runtime_operation_then_saves_cancellation_and_releases_lease() {
    let fixture = Fixture::new("block");
    let mut running = Running::spawn(fixture.prepare("gitleaks,nuclei", true));
    let blocked = running.await_blocked(&fixture);
    assert!(DataDirectoryExclusiveLease::acquire(&fixture.data).is_err());
    let pid = running.child.as_ref().unwrap().id();
    assert_eq!(unsafe { libc::kill(pid as libc::pid_t, libc::SIGINT) }, 0);
    thread::sleep(Duration::from_millis(100));
    if running
        .child
        .as_mut()
        .unwrap()
        .try_wait()
        .unwrap()
        .is_none()
    {
        assert!(DataDirectoryExclusiveLease::acquire(&fixture.data).is_err());
    }
    fs::write(
        fixture.bin.join("release"),
        "complete the admitted fixture operation",
    )
    .unwrap();
    let output = running.wait();
    let value = result(&output, 130);
    assert_eq!(value["ready"], false);
    assert!(
        value["images"]
            .as_array()
            .unwrap()
            .iter()
            .any(|image| image["status"] == "cancelled")
    );
    fixture.assert_receipt(&value);
    assert!(
        fixture_runtime::process_is_gone(blocked["pid"].as_u64().unwrap() as u32),
        "runtime child must exit before preparation releases ownership"
    );
    DataDirectoryExclusiveLease::acquire(&fixture.data).unwrap();
}

#[test]
fn bootstrap_control_pipe_eof_cancel_and_terminate_preserve_owned_cleanup_and_receipts() {
    for (control, code) in [
        (None, 130),
        (Some("cancel\n"), 130),
        (Some("terminate\n"), 143),
    ] {
        let fixture = Fixture::new("block");
        let mut command = fixture.command(true);
        command
            .args([
                "runtime",
                "prepare",
                "--bootstrap-control-stdin",
                "--engine",
                "gitleaks,nuclei",
                "--offline",
            ])
            .stdin(Stdio::piped());
        let mut running = Running::spawn(command);
        let blocked = running.await_blocked(&fixture);
        assert!(DataDirectoryExclusiveLease::acquire(&fixture.data).is_err());
        let mut input = running.child.as_mut().unwrap().stdin.take().unwrap();
        if let Some(control) = control {
            input.write_all(control.as_bytes()).unwrap();
            input.flush().unwrap();
        }
        drop(input);
        thread::sleep(Duration::from_millis(100));
        if running
            .child
            .as_mut()
            .unwrap()
            .try_wait()
            .unwrap()
            .is_none()
        {
            assert!(DataDirectoryExclusiveLease::acquire(&fixture.data).is_err());
        }
        fs::write(fixture.bin.join("release"), "complete admitted operation").unwrap();
        let output = running.wait();
        let value = result(&output, code);
        assert_eq!(value["ready"], false, "control {control:?}");
        assert!(
            value["images"]
                .as_array()
                .unwrap()
                .iter()
                .any(|image| image["status"] == "cancelled")
        );
        fixture.assert_receipt(&value);
        assert!(
            fixture_runtime::process_is_gone(blocked["pid"].as_u64().unwrap() as u32),
            "parent control must not orphan the runtime operation"
        );
        DataDirectoryExclusiveLease::acquire(&fixture.data).unwrap();
    }
}

#[test]
fn bootstrap_runtime_preparation_returns_the_core_receipt_for_the_selected_engine() {
    let fixture = Fixture::new("present");
    let bootstrap =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../scripts/skill/bootstrap-core.mjs");
    let output = Command::new(fixture_runtime::node())
        .args(["--input-type=module", "-e", r#"
            import { pathToFileURL } from 'node:url';
            const [module, executable, dataDir] = process.argv.slice(1);
            const { invokeRuntimePreparation } = await import(pathToFileURL(module));
            const result = await invokeRuntimePreparation(executable, { dataDir, engineIds: ['gitleaks'], offline: true }, { environment: process.env });
            process.stdout.write(JSON.stringify(result));
        "#])
        .arg(bootstrap)
        .arg(env!("CARGO_BIN_EXE_ai-security-scanner-cli"))
        .arg(&fixture.data)
        .env("PATH", &fixture.bin)
        .env_remove("AI_SECURITY_SCANNER_MANAGED_RUNTIME_BUNDLE")
        .env_remove("AI_SECURITY_SCANNER_RELEASE_APPROVED_LOCAL_IMAGE_DIRECTORY")
        .output().unwrap();
    let value = result(&output, 0);
    assert_eq!(value["ready"], true);
    assert_eq!(value["engines"], json!(["gitleaks"]));
    fixture.assert_receipt(&value);
    fixture.assert_no_execution();
    assert!(fixture.calls().iter().all(|call| call[0] != "pull"));
}

#[path = "support/paths.rs"]
mod paths;
