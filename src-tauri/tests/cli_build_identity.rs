#![cfg(feature = "cli")]

use ai_security_scanner_lib::process_lease::DataDirectoryExclusiveLease;
use serde_json::Value;
use std::process::Command;

#[test]
fn build_identity_needs_no_workspace_runtime_or_writer_lease() {
    let temporary = tempfile::tempdir().unwrap();
    let missing = temporary.path().join("must-not-create");
    let held = temporary.path().join("held-workspace");
    let _lease = DataDirectoryExclusiveLease::acquire(&held).unwrap();
    let before = std::fs::read_dir(&held).unwrap().count();
    for data in [&missing, &held] {
        let result = Command::new(env!("CARGO_BIN_EXE_ai-security-scanner-cli"))
            .args(["--json", "--data-dir"])
            .arg(data)
            .arg("--managed-runtime-bundle")
            .arg(temporary.path().join("invalid-runtime"))
            .arg("build-identity")
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let identity: Value = serde_json::from_slice(&result.stdout).unwrap();
        assert_eq!(
            identity["schema_version"],
            "ai-security-scanner.build-identity/v1"
        );
        assert_eq!(identity["product"], "ai-security-scanner");
        assert_eq!(identity["target"], env!("AI_SECURITY_SCANNER_BUILD_TARGET"));
        assert_eq!(identity["product_version"], env!("CARGO_PKG_VERSION"));
        assert!(
            identity["features"]
                .as_array()
                .unwrap()
                .contains(&Value::String("cli".into()))
        );
        assert!(
            identity["rustc_version"]
                .as_str()
                .unwrap()
                .contains("host: ")
        );
        let digest = identity["report_source_sha256"].as_str().unwrap();
        assert!(digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit()));
    }
    assert!(!missing.exists());
    assert_eq!(std::fs::read_dir(&held).unwrap().count(), before);
}
