use sha2::{Digest, Sha256};
use std::fmt::Write as _;
use std::path::PathBuf;

const MANAGED_RUNTIME_MANIFEST_RELATIVE_PATH: &str =
    "../runtime/staged/managed-runtime/manifest.json";
const MANAGED_RUNTIME_MANIFEST_SHA256_ENV: &str =
    "AI_SECURITY_SCANNER_MANAGED_RUNTIME_MANIFEST_SHA256";

fn main() {
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

fn lowercase_sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        write!(&mut encoded, "{byte:02x}").expect("writing to a String cannot fail");
    }
    debug_assert!(encoded.len() == 64 && encoded.bytes().all(|byte| byte.is_ascii_hexdigit()));
    encoded
}
