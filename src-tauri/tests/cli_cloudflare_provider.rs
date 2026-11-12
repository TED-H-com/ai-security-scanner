#![cfg(feature = "cli")]

use ai_security_scanner_lib::process_lease::DataDirectoryExclusiveLease;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::Path;
use std::process::{Command, Output};

fn command(input: &Path, document: &str, data: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_ai-security-scanner-cli"));
    command
        .args(["--json", "--data-dir"])
        .arg(data)
        .args([
            "provider",
            "cloudflare",
            "validate-document",
            "--document",
            document,
            "--input",
        ])
        .arg(input);
    command
}

fn receipt(output: &Output, code: i32) -> Value {
    assert_eq!(
        output.status.code(),
        Some(code),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["validation_scope"], "single_document");
    assert_eq!(value["audit_performed"], false);
    assert_eq!(value["admission_ready"], false);
    assert_eq!(
        value["upstream_commit"],
        "c1c8a8c1471069fb0e188eeaff69b8e8db6564a8"
    );
    value
}

#[test]
fn native_documents_validate_without_creating_data_or_acquiring_its_lease() {
    let temporary = tempfile::tempdir().unwrap();
    let missing = temporary.path().join("missing-data");
    let held = temporary.path().join("held-data");
    let _lease = DataDirectoryExclusiveLease::acquire(&held).unwrap();
    let before = std::fs::read_dir(&held).unwrap().count();
    for (document, contents) in [
        (
            "findings",
            include_bytes!("../../tests/fixtures/cloudflare/findings.json").as_slice(),
        ),
        (
            "coverage-ledger",
            include_bytes!("../../tests/fixtures/cloudflare/coverage-ledger.json").as_slice(),
        ),
    ] {
        let input = temporary.path().join(format!("{document}.json"));
        std::fs::write(&input, contents).unwrap();
        for data in [&missing, &held] {
            let output = command(&input, document, data)
                .arg("--managed-runtime-bundle")
                .arg(temporary.path().join("missing-runtime"))
                .output()
                .unwrap();
            let value = receipt(&output, 0);
            assert_eq!(value["validation"]["valid"], true);
            assert_eq!(value["validation"]["phase"], "upstream");
            assert_eq!(value["input_sha256"], hex::encode(Sha256::digest(contents)));
            assert_eq!(value["input_byte_length"], contents.len());
            assert_eq!(std::fs::read(&input).unwrap(), contents);
        }
    }
    assert!(!missing.exists());
    assert_eq!(std::fs::read_dir(&held).unwrap().count(), before);
}

#[test]
fn invalid_documents_return_structured_failure_and_nonzero_exit() {
    let temporary = tempfile::tempdir().unwrap();
    let input = temporary.path().join("invalid.json");
    for (contents, phase) in [
        (b"{}".as_slice(), "upstream"),
        (b"[{\"x\":1,\"x\":2}]".as_slice(), "preflight"),
        (b"[{".as_slice(), "parse"),
    ] {
        std::fs::write(&input, contents).unwrap();
        let value = receipt(
            &command(&input, "findings", &temporary.path().join("data"))
                .output()
                .unwrap(),
            2,
        );
        assert_eq!(value["validation"]["valid"], false);
        assert_eq!(value["validation"]["phase"], phase);
        assert!(!value["validation"]["errors"].as_array().unwrap().is_empty());
    }
}

#[test]
fn invalid_file_bytes_fail_before_starting_a_runtime() {
    let temporary = tempfile::tempdir().unwrap();
    let input = temporary.path().join("input.json");
    for bytes in [vec![0xff, 0xfe], vec![b' '; 5 * 1024 * 1024 + 1]] {
        std::fs::write(&input, bytes).unwrap();
        let output = command(&input, "findings", &temporary.path().join("data"))
            .env("PATH", "")
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1));
        let error: Value = serde_json::from_slice(&output.stderr).unwrap();
        assert!(
            !error["error"]
                .as_str()
                .unwrap()
                .contains("requires Node.js")
        );
    }
}

#[test]
fn node_options_and_report_commands_cannot_execute_input() {
    let temporary = tempfile::tempdir().unwrap();
    let marker = temporary.path().join("must-not-exist");
    let malicious_module = temporary.path().join("injected.cjs");
    std::fs::write(
        &malicious_module,
        format!(
            "require('node:fs').writeFileSync({}, 'executed');",
            serde_json::to_string(&marker).unwrap()
        ),
    )
    .unwrap();
    let mut findings: Value = serde_json::from_slice(include_bytes!(
        "../../tests/fixtures/cloudflare/findings.json"
    ))
    .unwrap();
    findings[0]["execution"]["instructions"] =
        serde_json::json!([format!("node {}", malicious_module.display())]);
    let input = temporary.path().join("--require=payload.json");
    std::fs::write(&input, serde_json::to_vec(&findings).unwrap()).unwrap();
    let output = command(&input, "findings", &temporary.path().join("data"))
        .env(
            "NODE_OPTIONS",
            format!(
                "--require {}",
                serde_json::to_string(&malicious_module).unwrap()
            ),
        )
        .env("NODE_PATH", temporary.path())
        .output()
        .unwrap();
    receipt(&output, 0);
    assert!(!marker.exists());
}

#[test]
fn absent_node_is_an_operational_error_without_scan_state() {
    let temporary = tempfile::tempdir().unwrap();
    let input = temporary.path().join("findings.json");
    let data = temporary.path().join("data");
    std::fs::write(&input, "[]").unwrap();
    let output = command(&input, "findings", &data)
        .env("PATH", "")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("requires Node.js"));
    assert!(!data.exists());
}

#[cfg(windows)]
#[test]
fn windows_device_network_and_stream_paths_are_refused_before_open() {
    let temporary = tempfile::tempdir().unwrap();
    for path in [
        r"\\.\pipe\scanner-validator-test",
        r"\\server\share\findings.json",
        r"\\?\UNC\server\share\findings.json",
        r"C:\NUL",
        r"C:\findings.json:stream",
    ] {
        let output = command(Path::new(path), "findings", &temporary.path().join("data"))
            .env("PATH", "")
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1));
        let error: Value = serde_json::from_slice(&output.stderr).unwrap();
        let message = error["error"].as_str().unwrap();
        assert!(
            message.contains("local disk path") || message.contains("path component"),
            "{message}"
        );
    }
}

#[cfg(unix)]
#[test]
fn links_and_named_pipes_are_rejected_without_blocking() {
    use std::os::unix::fs::symlink;
    let temporary = tempfile::tempdir().unwrap();
    let original = temporary.path().join("original.json");
    std::fs::write(&original, "[]").unwrap();
    let link = temporary.path().join("symlink.json");
    symlink(&original, &link).unwrap();
    let hard = temporary.path().join("hardlink.json");
    std::fs::hard_link(&original, &hard).unwrap();
    let pipe = temporary.path().join("pipe.json");
    let name = std::ffi::CString::new(pipe.as_os_str().as_encoded_bytes()).unwrap();
    // SAFETY: name is a valid NUL-terminated path within the owned test directory.
    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
    let started = std::time::Instant::now();
    for input in [&link, &hard, &original, &pipe, temporary.path()] {
        let output = command(input, "findings", &temporary.path().join("data"))
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1));
    }
    assert!(started.elapsed() < std::time::Duration::from_secs(5));
}
