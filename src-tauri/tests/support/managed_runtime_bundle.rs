//! Adapted from the managed-runtime library's healthy packaged-bundle fixture.

use ai_security_scanner_lib::managed_runtime::ManagedRuntimeManager;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

pub fn create(root: &Path) -> (PathBuf, String) {
    let bundle = root.join("managed-bundle");
    fs::create_dir_all(bundle.join("bin")).unwrap();
    let driver = b"managed-podman-driver";
    fs::write(bundle.join("bin/podman"), driver).unwrap();
    let driver_sha = hex::encode(Sha256::digest(driver));
    let image = b"pinned-machine-image";
    let image_sha = hex::encode(Sha256::digest(image));
    let image_url = "https://github.com/podman-container-tools/podman-machine-os/releases/download/v5.8.2/machine.zst";
    let architecture = match std::env::consts::ARCH {
        "x86_64" => "x86_64",
        "aarch64" => "aarch64",
        other => panic!("unsupported fixture architecture: {other}"),
    };
    let manifest = json!({
        "schema_version": "3",
        "management_contract_revision": "2026-08-29.1",
        "bundle_id": "podman-machine",
        "runtime_version": "5.8.2",
        "driver_path": "bin/podman",
        "files": [{"path": "bin/podman", "sha256": driver_sha, "size_bytes": driver.len(), "executable": true}],
        "components": [
            {"id": "podman", "name": "Podman remote client", "version": "5.8.2", "repository_url": "https://github.com/containers/podman", "source_revision": "5b263b5", "license_spdx": "Apache-2.0", "relationship": "Bundled rootless machine client", "artifacts": [{"delivery": "bundled_file", "locator": "bin/podman", "sha256": driver_sha, "size_bytes": driver.len()}]},
            {"id": "podman-machine-os", "name": "Podman machine OS", "version": "5.8.2", "repository_url": "https://github.com/containers/podman-machine-os", "source_revision": "08298cbc1d1d5440fb0f071470b35abc37d31050", "license_spdx": "Apache-2.0", "relationship": "Pinned VM image downloaded on first setup", "artifacts": [{"delivery": "runtime_download", "locator": image_url, "sha256": image_sha, "size_bytes": image.len()}]}
        ],
        "targets": [{"operating_system": "linux", "architecture": architecture, "provider": "qemu", "machine_image": {"url": image_url, "sha256": image_sha, "size_bytes": image.len()}}],
        "resources": {"cpus": 2, "memory_mb": 4096, "disk_size_gb": 40},
        "source": {"repository_url": "https://github.com/containers/podman", "source_revision": "5b263b5", "license_spdx": "Apache-2.0"}
    });
    let bytes = serde_json::to_vec(&manifest).unwrap();
    fs::write(bundle.join("manifest.json"), &bytes).unwrap();
    let digest = hex::encode(Sha256::digest(&bytes));
    let manager = ManagedRuntimeManager::open(
        &root.join("bundle-open-probe"),
        &bundle,
        &bundle.join("manifest.json"),
    )
    .expect("existing managed-runtime fixture must be accepted");
    assert_eq!(manager.manifest_sha256(), digest);
    (bundle, digest)
}
