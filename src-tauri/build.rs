use sha2::{Digest, Sha256};
use std::fmt::Write as _;
use std::path::PathBuf;

const MANAGED_RUNTIME_MANIFEST_RELATIVE_PATH: &str =
    "../runtime/staged/managed-runtime/manifest.json";
const MANAGED_RUNTIME_MANIFEST_SHA256_ENV: &str =
    "AI_SECURITY_SCANNER_MANAGED_RUNTIME_MANIFEST_SHA256";

fn main() {
    record_build_identity();
    record_report_core_identity();
    let desktop = std::env::var_os("CARGO_FEATURE_DESKTOP").is_some();
    let installer_runtime_cache =
        std::env::var_os("CARGO_FEATURE_INSTALLER_RUNTIME_CACHE").is_some();
    let needs_managed_runtime_anchor = desktop || installer_runtime_cache;
    let release = std::env::var_os("PROFILE").is_some_and(|profile| profile == "release");
    let manifest_path = PathBuf::from(
        std::env::var_os("CARGO_MANIFEST_DIR")
            .expect("Cargo must provide CARGO_MANIFEST_DIR to the package build script"),
    )
    .join(MANAGED_RUNTIME_MANIFEST_RELATIVE_PATH);

    println!("cargo:rerun-if-changed={MANAGED_RUNTIME_MANIFEST_RELATIVE_PATH}");

    let manifest_sha256 = if needs_managed_runtime_anchor {
        match std::fs::read(&manifest_path) {
            Ok(manifest) => lowercase_sha256(&manifest),
            Err(error) if release => panic!(
                "release desktop or installer-cache build requires readable managed runtime manifest {}: {error}",
                manifest_path.display()
            ),
            Err(_) => {
                println!(
                    "cargo:warning=managed runtime recovery anchor disabled because {} is missing or unreadable; the resulting debug binary cannot recover scan tools from the private versions cache",
                    manifest_path.display()
                );
                String::new()
            }
        }
    } else {
        String::new()
    };
    println!("cargo:rustc-env={MANAGED_RUNTIME_MANIFEST_SHA256_ENV}={manifest_sha256}");

    if desktop {
        tauri_build::build()
    }
}

/// Read-only provenance for the native bootstrap. This identifies a build; it
/// does not grant scan authorization or attest that its runtime is available.
fn record_build_identity() {
    let target = std::env::var("TARGET").expect("Cargo target");
    println!("cargo:rustc-env=AI_SECURITY_SCANNER_BUILD_TARGET={target}");
    let output = std::process::Command::new(std::env::var_os("RUSTC").expect("Cargo rustc"))
        .arg("--version")
        .arg("--verbose")
        .output()
        .expect("read Rust compiler identity");
    assert!(output.status.success(), "Rust compiler identity failed");
    let compiler = String::from_utf8(output.stdout).expect("Rust compiler identity is UTF-8");
    // Cargo directives are line-oriented. Store the exact verbose identity as
    // hex and decode it in the CLI without losing its original line boundaries.
    let compiler_hex = compiler
        .trim()
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    println!("cargo:rustc-env=AI_SECURITY_SCANNER_BUILD_RUSTC_HEX={compiler_hex}");
    let mut features = std::env::vars()
        .filter_map(|(name, _)| {
            name.strip_prefix("CARGO_FEATURE_")
                .map(|feature| feature.to_ascii_lowercase().replace('_', "-"))
        })
        .collect::<Vec<_>>();
    features.sort();
    println!(
        "cargo:rustc-env=AI_SECURITY_SCANNER_BUILD_FEATURES={}",
        features.join(",")
    );
    for name in [
        "AI_SECURITY_SCANNER_BOOTSTRAP_INPUT_SHA256",
        "AI_SECURITY_SCANNER_BOOTSTRAP_RECIPE",
    ] {
        println!("cargo:rerun-if-env-changed={name}");
        let value = std::env::var(name).unwrap_or_default();
        if !value.is_empty() {
            if name.ends_with("SHA256") {
                assert!(
                    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()),
                    "bootstrap input identity must be a SHA-256 digest"
                );
            } else {
                assert!(
                    value.len() <= 128
                        && value
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte)),
                    "bootstrap recipe identity must be a bounded identifier"
                );
            }
        }
        println!("cargo:rustc-env={name}={value}");
    }
}

/// Conservative replay admission: a snapshot can use this core's renderer only
/// when the implementation and embedded report inputs are exactly the same.
/// Git revision alone is insufficient for local development or copied sources.
fn record_report_core_identity() {
    let package = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let root = package.parent().expect("workspace root");
    let mut inputs = Vec::new();
    collect_rust_sources(&package.join("src"), &mut inputs);
    inputs.extend([
        package.join("build.rs"),
        package.join("Cargo.toml"),
        root.join("Cargo.toml"),
        root.join("Cargo.lock"),
        root.join("engines/catalog.json"),
        root.join("engines/campaigns/october-2026.json"),
        root.join("mappings/control-mappings.json"),
        root.join("providers/cloudflare/validate-document.cjs"),
        root.join("providers/cloudflare/upstream/LICENSE"),
        root.join("providers/cloudflare/upstream/skills/security-audit/report-schema.json"),
        root.join("providers/cloudflare/upstream/skills/security-audit/validate-findings.cjs"),
        root.join(
            "providers/cloudflare/upstream/skills/security-audit/validate-coverage-ledger.cjs",
        ),
    ]);
    inputs.sort();
    let mut digest = Sha256::new();
    for path in inputs {
        println!("cargo:rerun-if-changed={}", path.display());
        let name = path
            .strip_prefix(root)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        let bytes = std::fs::read(&path).unwrap_or_else(|error| {
            panic!(
                "report identity input {} is unreadable: {error}",
                path.display()
            )
        });
        digest.update((name.len() as u64).to_le_bytes());
        digest.update(name.as_bytes());
        digest.update((bytes.len() as u64).to_le_bytes());
        digest.update(bytes);
    }
    let encoded = digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    println!("cargo:rustc-env=AI_SECURITY_SCANNER_REPORT_CORE_SHA256={encoded}");
}

fn collect_rust_sources(directory: &std::path::Path, inputs: &mut Vec<PathBuf>) {
    println!("cargo:rerun-if-changed={}", directory.display());
    for entry in std::fs::read_dir(directory).expect("read core sources") {
        let path = entry.expect("read source entry").path();
        if path.is_dir() {
            collect_rust_sources(&path, inputs);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            inputs.push(path);
        }
    }
}

fn lowercase_sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        write!(&mut encoded, "{byte:02x}").expect("writing to a String cannot fail");
    }
    debug_assert!(encoded.len() == 64 && encoded.bytes().all(|byte| byte.is_ascii_hexdigit()));
    encoded
}
