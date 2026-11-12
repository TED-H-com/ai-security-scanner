//! Lifecycle and supply-chain boundary for the product-managed container runtime.
//!
//! The desktop application never installs a system service, edits the user's PATH,
//! or invokes an operating-system package manager. A release carries a small,
//! platform-specific Podman machine client bundle. This module verifies and copies
//! that bundle into the application's private data directory, downloads the exact
//! Podman machine image declared by the release manifest, and owns one rootless VM.
//! Docker and a user-installed Podman remain compatibility providers elsewhere.

use crate::error::{AppError, AppResult};
use chrono::{DateTime, Utc};
use reqwest::blocking::{Client, Response};
use reqwest::header::{ACCEPT_ENCODING, CONTENT_RANGE, RANGE};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use ssh_key::{Algorithm, LineEnding, PrivateKey, PublicKey, rand_core::OsRng};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use url::Url;
use uuid::Uuid;
use zeroize::Zeroizing;

const LEGACY_MANIFEST_SCHEMA_VERSION: &str = "2";
const MANIFEST_SCHEMA_VERSION: &str = "3";
const MANAGEMENT_CONTRACT_REVISION: &str = "2026-08-29.1";
pub const PRODUCT_DATA_DIRECTORY_NAME: &str = "dev.teddashh.ai-security-scanner";
const MAX_MANIFEST_BYTES: u64 = 256 * 1024;
const MAX_BUNDLE_FILES: usize = 128;
const MAX_INSTALLED_VERSIONS: usize = 32;
const MAX_BUNDLE_FILE_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_BUNDLE_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const MAX_MACHINE_IMAGE_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const MAX_COMMAND_OUTPUT_BYTES: u64 = 1024 * 1024;
const MAX_COMMAND_DIAGNOSTIC_CHARS: usize = 4096;
const COMMAND_TIMEOUT: Duration = Duration::from_secs(30);
const MACHINE_INIT_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const MACHINE_START_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const SERVER_READINESS_PROBE_TIMEOUT: Duration = Duration::from_secs(5);
const SERVER_READINESS_RETRY_INTERVAL: Duration = Duration::from_millis(250);
// Status is a foreground/read-only UX boundary, not a lifecycle operation. A
// wedged provider inventory must therefore never inherit the ordinary 30-second
// command timeout. Keep all provider commands issued by one status
// reconciliation inside one shared three-second budget; the direct runner may
// then spend at most two additional seconds draining terminated child pipes.
const STATUS_RECONCILIATION_COMMAND_BUDGET: Duration = Duration::from_secs(3);
const MACHINE_STOP_TIMEOUT: Duration = Duration::from_secs(90);
#[cfg(any(windows, test))]
const WINDOWS_WSL_PREREQUISITE_REPAIR_TIMEOUT: Duration = Duration::from_secs(5 * 60);
#[cfg(any(windows, test))]
const WINDOWS_WSL_MISSING_BINARY_STAGE_TIMEOUT: Duration = Duration::from_secs(150);
#[cfg(any(windows, test))]
const WINDOWS_WSL_SERVICING_COOLDOWN: Duration = Duration::from_secs(15 * 60);
#[cfg(windows)]
const WINDOWS_PREREQUISITE_REGISTRY_PATH: &str =
    "Software\\ai-security-scanner contributors\\ai-security-scanner";
#[cfg(windows)]
const WINDOWS_WSL_SERVICING_COOLDOWN_VALUE: &str = "WindowsPrerequisiteServicingCooldownUntilUnix";
const MAX_AUTOMATIC_WINDOWS_WSL_PREREQUISITE_REPAIRS: usize = 3;
#[cfg(windows)]
const WINDOWS_WSL_PROVIDER_DELETE_TIMEOUT: Duration = Duration::from_secs(10);
#[cfg(windows)]
const WINDOWS_WSL_PROVIDER_DELETE_POLL: Duration = Duration::from_millis(100);
const DOWNLOAD_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const DOWNLOAD_TOTAL_TIMEOUT: Duration = Duration::from_secs(4 * 60 * 60);
const DOWNLOAD_CHUNK_BYTES: usize = 128 * 1024;
// The longest setup command is a ten-minute machine init/start. Download work
// emits byte heartbeats, so eleven minutes without a milestone is stale.
const MANAGED_RUNTIME_SETUP_STALE_AFTER: Duration = Duration::from_secs(11 * 60);
const MACHINE_PREFIX: &str = "assm1";
const WINDOWS_MACHINE_PREFIX: &str = "assm2";
const MAX_MACHINE_NAME_BYTES: usize = 30;
const MACHINE_IMAGE_ID_HEX_CHARS: usize = 12;
const MAX_WSL_DISTRIBUTIONS: usize = 1024;
const MAX_WSL_DISTRIBUTION_NAME_BYTES: usize = 256;
const MAX_SSH_PRIVATE_KEY_BYTES: u64 = 16 * 1024;
const MAX_SSH_PUBLIC_KEY_BYTES: u64 = 4 * 1024;
const PODMAN_MACHINE_IDENTITY_NAME: &str = "machine";
const PODMAN_WSL_DISTRIBUTION_STORAGE_DIRECTORY: &str = "wsldist";
const MANAGED_SSH_KEY_COMMENT: &str = "ai-security-scanner-managed-runtime";
const WINDOWS_WSL_OWNERSHIP_PROOF_SCHEMA: &str = "ai-security-scanner.managed-wsl-ownership/v1";
const WINDOWS_WSL_OWNERSHIP_DIRECTORY: &str = "wsl-ownership";
const WINDOWS_WSL_GENERATION_SELECTION_SCHEMA: &str =
    "ai-security-scanner.managed-wsl-generation-selection/v1";
const WINDOWS_WSL_GENERATION_DIRECTORY: &str = "wsl-generations";
const WINDOWS_WSL_ISOLATED_MACHINE_PREFIX: &str = "assm2-iso-";
const WINDOWS_WSL_ISOLATED_MACHINE_DIGEST_HEX_CHARS: usize = 20;
const MAX_WINDOWS_WSL_ISOLATED_GENERATION_ATTEMPTS: u32 = 32;
#[cfg(any(windows, test))]
const MAX_WINDOWS_REGISTRY_STRING_BYTES: u32 = 64 * 1024;
#[cfg(unix)]
const LINUX_SHORT_RUNTIME_BASE: &str = "/tmp";
#[cfg(unix)]
const LINUX_SHORT_RUNTIME_PREFIX: &str = "assm1-";
#[cfg(unix)]
const LINUX_SHORT_RUNTIME_DIGEST_HEX_CHARS: usize = 32;
#[cfg(unix)]
const PODMAN_LINUX_MAX_SOCKET_PATH_BYTES: usize = 103;
#[cfg(unix)]
const PODMAN_LINUX_RUNTIME_DIRECTORY: &str = "podman";
#[cfg(unix)]
const PODMAN_LINUX_EAGER_STORAGE_DIRECTORY: &str = "containers";
#[cfg(unix)]
const PODMAN_LINUX_EAGER_LIBPOD_DIRECTORY: &str = "libpod";
#[cfg(unix)]
const PODMAN_GVPROXY_SOCKET_SUFFIX: &str = "-gvproxy.sock";
#[cfg(unix)]
const PODMAN_GVPROXY_LOG_NAME: &str = "gvproxy.log";
#[cfg(unix)]
const PODMAN_VIRTIOFS_SOCKET_NAME: &str = "virtiofschar0";
#[cfg(unix)]
const PODMAN_VIRTIOFS_PID_NAME: &str = "virtiofschar0.pid";
#[cfg(unix)]
const LINUX_VIRTIOFS_CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);
#[cfg(unix)]
const LINUX_VIRTIOFS_CLEANUP_POLL: Duration = Duration::from_millis(25);
#[cfg(unix)]
const MACOS_SHORT_HOME_BASE: &str = "/tmp";
#[cfg(unix)]
const MACOS_SHORT_HOME_PREFIX: &str = "assm1-";
#[cfg(unix)]
const MACOS_SHORT_HOME_DIGEST_HEX_CHARS: usize = 32;
#[cfg(unix)]
const PODMAN_MACOS_MAX_SOCKET_PATH_BYTES: usize = 103;
#[cfg(unix)]
const PODMAN_IGNITION_SOCKET_SUFFIX: &str = "-ignition.sock";
#[cfg(unix)]
const PODMAN_MACOS_SSH_DIRECTORY: &str = ".ssh";
#[cfg(unix)]
const PODMAN_MACOS_KNOWN_HOSTS_FILE: &str = "known_hosts";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ManagedOperatingSystem {
    Linux,
    Macos,
    Windows,
}

impl ManagedOperatingSystem {
    fn current() -> Option<Self> {
        if cfg!(target_os = "linux") {
            Some(Self::Linux)
        } else if cfg!(target_os = "macos") {
            Some(Self::Macos)
        } else if cfg!(target_os = "windows") {
            Some(Self::Windows)
        } else {
            None
        }
    }

    fn key(self) -> &'static str {
        match self {
            Self::Linux => "linux",
            Self::Macos => "macos",
            Self::Windows => "windows",
        }
    }

    fn machine_name_key(self) -> &'static str {
        match self {
            Self::Linux => "linux",
            Self::Macos => "macos",
            Self::Windows => "win",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ManagedArchitecture {
    X86_64,
    Aarch64,
}

impl ManagedArchitecture {
    fn current() -> Option<Self> {
        if cfg!(target_arch = "x86_64") {
            Some(Self::X86_64)
        } else if cfg!(target_arch = "aarch64") {
            Some(Self::Aarch64)
        } else {
            None
        }
    }

    fn key(self) -> &'static str {
        match self {
            Self::X86_64 => "x86-64",
            Self::Aarch64 => "aarch64",
        }
    }

    fn machine_name_key(self) -> &'static str {
        match self {
            Self::X86_64 => "x64",
            Self::Aarch64 => "arm64",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ManagedMachineProvider {
    Applehv,
    Qemu,
    Wsl,
}

impl ManagedMachineProvider {
    fn argument(self) -> &'static str {
        match self {
            Self::Applehv => "applehv",
            Self::Qemu => "qemu",
            Self::Wsl => "wsl",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ManagedRuntimeSource {
    pub repository_url: String,
    pub source_revision: String,
    pub license_spdx: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ManagedRuntimeFile {
    pub path: String,
    pub sha256: String,
    pub size_bytes: u64,
    #[serde(default)]
    pub executable: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ManagedRuntimeArtifactDelivery {
    BundledFile,
    RuntimeDownload,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ManagedRuntimeComponentArtifact {
    pub delivery: ManagedRuntimeArtifactDelivery,
    /// Bundle-relative path for `bundled_file`, exact HTTPS URL for
    /// `runtime_download`.
    pub locator: String,
    pub sha256: String,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ManagedRuntimeSourceArchive {
    pub url: String,
    pub sha256: String,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ManagedRuntimeComponent {
    pub id: String,
    pub name: String,
    pub version: String,
    pub repository_url: String,
    pub source_revision: String,
    pub license_spdx: String,
    pub relationship: String,
    pub artifacts: Vec<ManagedRuntimeComponentArtifact>,
    #[serde(default)]
    pub source_archive: Option<ManagedRuntimeSourceArchive>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ManagedMachineImage {
    pub url: String,
    pub sha256: String,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ManagedTarget {
    pub operating_system: ManagedOperatingSystem,
    pub architecture: ManagedArchitecture,
    pub provider: ManagedMachineProvider,
    pub machine_image: ManagedMachineImage,
    #[serde(default)]
    pub prerequisite: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum WindowsWslOwnershipBasis {
    InitIntent,
    ProvenMachine,
}

/// Durable routing for the one current Windows runtime generation.
///
/// This record is deliberately not ownership evidence and can never authorize
/// cleanup. It only makes a side-by-side choice stable across cancellation,
/// process termination, and repeated setup attempts. Any WSL registration or
/// provider storage that caused isolation remains byte-for-byte untouched.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct WindowsWslGenerationSelection {
    schema_version: String,
    authorizes_cleanup: bool,
    manifest_sha256: String,
    machine_image_sha256: String,
    default_machine_name: String,
    selected_machine_name: String,
    generation_index: u32,
    preserved_collision_names: Vec<String>,
}

#[derive(Debug)]
enum MachineInitializationAttemptFailure {
    Initialization(AppError),
    OwnershipJournal(AppError),
}

#[derive(Debug)]
enum MachineStartAttemptFailure {
    Lifecycle(AppError),
    MachineStart(AppError),
    ServerReadiness(AppError),
}

impl std::fmt::Display for MachineInitializationAttemptFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Initialization(error) | Self::OwnershipJournal(error) => error.fmt(formatter),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct WindowsWslOwnershipProof {
    schema_version: String,
    bundle_id: String,
    runtime_version: String,
    manifest_sha256: String,
    machine_name: String,
    distribution_name: String,
    machine_image_sha256: String,
    operating_system: ManagedOperatingSystem,
    architecture: ManagedArchitecture,
    provider: ManagedMachineProvider,
    ownership_basis: WindowsWslOwnershipBasis,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct WindowsWslRegistration {
    registration_id: String,
    distribution_name: String,
    base_path: PathBuf,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct WindowsWslRegistrationInventory {
    registrations: Vec<WindowsWslRegistration>,
    observed_distribution_names: Vec<String>,
    complete: bool,
}

#[derive(Debug, Clone, Copy)]
struct WindowsWslGenerationSelectionInput<'a> {
    machines: &'a [MachineListEntry],
    distributions: &'a [String],
    registrations: &'a [WindowsWslRegistration],
    observed_registration_names: &'a [String],
    registration_inventory_complete: bool,
    provider_inventory_complete: bool,
}

impl WindowsWslRegistrationInventory {
    fn complete(registrations: Vec<WindowsWslRegistration>) -> Self {
        let observed_distribution_names = registrations
            .iter()
            .map(|registration| registration.distribution_name.clone())
            .collect();
        Self {
            registrations,
            observed_distribution_names,
            complete: true,
        }
    }

    fn merge_conservatively(mut self, newer: Self) -> Self {
        for name in newer.observed_distribution_names {
            if !self
                .observed_distribution_names
                .iter()
                .any(|observed| observed.eq_ignore_ascii_case(&name))
            {
                self.observed_distribution_names.push(name);
            }
        }
        for registration in newer.registrations {
            if !self.registrations.iter().any(|observed| {
                observed.registration_id == registration.registration_id
                    && observed
                        .distribution_name
                        .eq_ignore_ascii_case(&registration.distribution_name)
                    && observed.base_path == registration.base_path
            }) {
                self.registrations.push(registration);
            }
        }
        self.complete = self.complete || newer.complete;
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ManagedMachineResources {
    pub cpus: u8,
    pub memory_mb: u32,
    pub disk_size_gb: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ManagedRuntimeManifest {
    pub schema_version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub management_contract_revision: Option<String>,
    pub bundle_id: String,
    pub runtime_version: String,
    pub driver_path: String,
    pub files: Vec<ManagedRuntimeFile>,
    pub components: Vec<ManagedRuntimeComponent>,
    pub targets: Vec<ManagedTarget>,
    pub resources: ManagedMachineResources,
    pub source: ManagedRuntimeSource,
}

#[derive(Debug, Clone)]
pub struct LoadedManagedRuntimeManifest {
    manifest: ManagedRuntimeManifest,
    encoded: Arc<[u8]>,
    sha256: String,
}

impl LoadedManagedRuntimeManifest {
    pub fn parse(bytes: &[u8]) -> AppResult<Self> {
        if bytes.is_empty() || bytes.len() as u64 > MAX_MANIFEST_BYTES {
            return Err(AppError::Runtime(
                "managed runtime manifest is empty or oversized".into(),
            ));
        }
        let manifest: ManagedRuntimeManifest = serde_json::from_slice(bytes).map_err(|error| {
            AppError::Runtime(format!("managed runtime manifest is malformed: {error}"))
        })?;
        validate_manifest(&manifest)?;
        Ok(Self {
            manifest,
            encoded: Arc::from(bytes),
            sha256: sha256_bytes(bytes),
        })
    }

    pub fn read(path: &Path) -> AppResult<Self> {
        let metadata = fs::symlink_metadata(path).map_err(|error| {
            AppError::NotAvailable(format!(
                "managed runtime release manifest is unavailable: {error}"
            ))
        })?;
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.len() == 0
            || metadata.len() > MAX_MANIFEST_BYTES
        {
            return Err(AppError::NotAuthorized(
                "managed runtime release manifest must be a bounded regular file".into(),
            ));
        }
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        File::open(path)?
            .take(MAX_MANIFEST_BYTES + 1)
            .read_to_end(&mut bytes)?;
        Self::parse(&bytes)
    }

    pub fn manifest(&self) -> &ManagedRuntimeManifest {
        &self.manifest
    }

    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    fn target(&self) -> AppResult<&ManagedTarget> {
        let operating_system = ManagedOperatingSystem::current().ok_or_else(|| {
            AppError::NotAvailable("managed runtime does not support this operating system".into())
        })?;
        let architecture = ManagedArchitecture::current().ok_or_else(|| {
            AppError::NotAvailable("managed runtime does not support this CPU architecture".into())
        })?;
        self.manifest
            .targets
            .iter()
            .find(|target| {
                target.operating_system == operating_system && target.architecture == architecture
            })
            .ok_or_else(|| {
                AppError::NotAvailable(format!(
                    "managed runtime release has no payload for {} {}",
                    operating_system.key(),
                    architecture.key()
                ))
            })
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ManagedRuntimePhase {
    NotInstalled,
    Installed,
    Stopped,
    Starting,
    Running,
    Corrupt,
    Unsupported,
}

impl ManagedRuntimePhase {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotInstalled => "not_installed",
            Self::Installed => "installed",
            Self::Stopped => "stopped",
            Self::Starting => "starting",
            Self::Running => "running",
            Self::Corrupt => "corrupt",
            Self::Unsupported => "unsupported",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManagedRuntimeStatus {
    pub provider: String,
    pub phase: ManagedRuntimePhase,
    pub available: bool,
    pub runtime_version: String,
    pub manifest_sha256: String,
    pub machine_image_sha256: Option<String>,
    pub operating_system: Option<ManagedOperatingSystem>,
    pub architecture: Option<ManagedArchitecture>,
    pub machine_provider: Option<ManagedMachineProvider>,
    pub prerequisite: Option<String>,
    pub detail: String,
}

/// Observable lifecycle of one first-run managed-runtime setup attempt.
///
/// This is deliberately separate from [`ManagedRuntimeStatus`]: runtime status
/// describes durable machine truth, while setup status describes the one
/// currently active (or most recently finished) setup operation.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ManagedRuntimeSetupPhase {
    Idle,
    Install,
    Prerequisite,
    Download,
    Recovery,
    Init,
    Start,
    Verify,
    Completed,
    Failed,
    Cancelled,
}

/// Stable setup failure categories for UI localization and automation.
///
/// These values deliberately describe only conclusions the product can prove
/// from packaged-resource admission or read-only prerequisite checks. They
/// never imply that the product executed rejected bytes, enabled a Windows
/// feature, or elevated itself.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ManagedRuntimeSetupFailureReason {
    #[serde(rename = "packaged_runtime_missing")]
    PackagedRuntimeMissing,
    #[serde(rename = "packaged_runtime_verification_failed")]
    PackagedRuntimeVerificationFailed,
    #[serde(rename = "developer_build_without_packaged_runtime")]
    DeveloperBuildWithoutPackagedRuntime,
    #[serde(rename = "developer_build_packaged_runtime_verification_failed")]
    DeveloperBuildPackagedRuntimeVerificationFailed,
    #[serde(rename = "windows_wsl_not_installed")]
    WslNotInstalled,
    #[serde(rename = "windows_wsl_optional_feature_disabled")]
    WslOptionalFeatureDisabled,
    #[serde(rename = "windows_wsl_update_required")]
    WslUpdateRequired,
    #[serde(rename = "windows_restart_required")]
    RestartRequired,
    #[serde(rename = "windows_wsl_command_failed")]
    WslCommandFailed,
}

impl ManagedRuntimeSetupFailureReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PackagedRuntimeMissing => "packaged_runtime_missing",
            Self::PackagedRuntimeVerificationFailed => "packaged_runtime_verification_failed",
            Self::DeveloperBuildWithoutPackagedRuntime => {
                "developer_build_without_packaged_runtime"
            }
            Self::DeveloperBuildPackagedRuntimeVerificationFailed => {
                "developer_build_packaged_runtime_verification_failed"
            }
            Self::WslNotInstalled => "windows_wsl_not_installed",
            Self::WslOptionalFeatureDisabled => "windows_wsl_optional_feature_disabled",
            Self::WslUpdateRequired => "windows_wsl_update_required",
            Self::RestartRequired => "windows_restart_required",
            Self::WslCommandFailed => "windows_wsl_command_failed",
        }
    }

    fn is_packaged_runtime_admission_failure(self) -> bool {
        matches!(
            self,
            Self::PackagedRuntimeMissing
                | Self::PackagedRuntimeVerificationFailed
                | Self::DeveloperBuildWithoutPackagedRuntime
                | Self::DeveloperBuildPackagedRuntimeVerificationFailed
        )
    }

    fn packaged_runtime_admission_detail(self) -> Option<&'static str> {
        match self {
            Self::PackagedRuntimeMissing => {
                Some("The installed scan tools are unavailable. Install the latest app version.")
            }
            Self::PackagedRuntimeVerificationFailed => Some(
                "The installed scan tools failed verification. Install the latest app version.",
            ),
            Self::DeveloperBuildWithoutPackagedRuntime => Some(
                "This developer build carries no packaged scan tools. Point it at a verified managed-runtime bundle override.",
            ),
            Self::DeveloperBuildPackagedRuntimeVerificationFailed => Some(
                "This developer build's supplied scan-tool bundle failed verification. Fix the bundle or point it at a verified managed-runtime bundle override.",
            ),
            Self::WslNotInstalled
            | Self::WslOptionalFeatureDisabled
            | Self::WslUpdateRequired
            | Self::RestartRequired
            | Self::WslCommandFailed => None,
        }
    }
}

/// Stable next actions paired with [`ManagedRuntimeSetupFailureReason`].
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ManagedRuntimeSetupNextAction {
    InstallWsl,
    EnableWslOptionalFeatures,
    UpdateWsl,
    RestartWindows,
    RetryWslCheck,
}

/// Terminal result of the deliberately narrow Windows prerequisite repair.
/// The backend derives the action from its current typed failure state;
/// executable paths and arguments can never be supplied by the webview.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ManagedRuntimePrerequisiteRepairOutcome {
    Completed,
    Cancelled,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManagedRuntimePrerequisiteRepairResult {
    pub outcome: ManagedRuntimePrerequisiteRepairOutcome,
    pub restart_required: bool,
    pub detail: String,
}

/// Stable, zero-input outcome for the signed Windows installer prerequisite
/// coordinator. The caller cannot choose a program, argument, provider, path,
/// or servicing action; this module derives the one fixed action from a fresh
/// read-only WSL probe.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WindowsInstallerPrerequisiteClass {
    Ready,
    Serviced,
    RestartRequired,
    Cancelled,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WindowsInstallerPrerequisiteResult {
    pub class: WindowsInstallerPrerequisiteClass,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ManagedRuntimeSetupStatus {
    /// Identity of the active or most recently completed setup episode.
    pub operation_id: Option<String>,
    pub started_at: Option<DateTime<Utc>>,
    pub last_heartbeat_at: Option<DateTime<Utc>>,
    /// Backend-derived liveness conclusion. This is never inferred by a UI
    /// timer and is false for terminal episodes.
    pub stale: bool,
    pub phase: ManagedRuntimeSetupPhase,
    pub active: bool,
    /// A separate Windows servicing operation is waiting for UAC or WSL to
    /// finish. It cannot be cancelled through the runtime download control.
    pub prerequisite_repair_active: bool,
    pub cancel_requested: bool,
    pub received_bytes: u64,
    pub total_bytes: Option<u64>,
    /// Percentage derived from the exact byte counters. It is `None` before
    /// the locked image size is known and always lies in `0..=100`.
    pub progress_percent: Option<f64>,
    /// Existing verified regular-file bytes reused by this setup attempt.
    pub resumed_from_bytes: u64,
    pub can_cancel: bool,
    pub can_retry: bool,
    /// Machine-readable failure category. `None` outside a failed setup.
    pub failure_reason: Option<ManagedRuntimeSetupFailureReason>,
    /// Machine-readable user action. `None` outside a failed setup.
    pub next_action: Option<ManagedRuntimeSetupNextAction>,
    pub detail: String,
}

impl Default for ManagedRuntimeSetupStatus {
    fn default() -> Self {
        Self {
            operation_id: None,
            started_at: None,
            last_heartbeat_at: None,
            stale: false,
            phase: ManagedRuntimeSetupPhase::Idle,
            active: false,
            prerequisite_repair_active: false,
            cancel_requested: false,
            received_bytes: 0,
            total_bytes: None,
            progress_percent: None,
            resumed_from_bytes: 0,
            can_cancel: false,
            can_retry: true,
            failure_reason: None,
            next_action: None,
            detail: "managed runtime setup has not started".into(),
        }
    }
}

impl ManagedRuntimeSetupStatus {
    #[cfg(any(feature = "desktop", test))]
    fn packaged_runtime_admission_failure(reason: ManagedRuntimeSetupFailureReason) -> Self {
        let detail = reason
            .packaged_runtime_admission_detail()
            .expect("only packaged-runtime admission failures use this status");
        Self {
            operation_id: None,
            started_at: None,
            last_heartbeat_at: None,
            stale: false,
            phase: ManagedRuntimeSetupPhase::Failed,
            active: false,
            prerequisite_repair_active: false,
            cancel_requested: false,
            received_bytes: 0,
            total_bytes: None,
            progress_percent: None,
            resumed_from_bytes: 0,
            can_cancel: false,
            can_retry: false,
            failure_reason: Some(reason),
            next_action: None,
            detail: detail.into(),
        }
    }
}

/// Process-local coordinator for desktop setup. Its mutex is held only for
/// small status mutations; cancellation uses an atomic flag so a second Tauri
/// command can interrupt the bounded download loop without waiting on runtime
/// lifecycle locks.
#[derive(Debug, Default)]
pub struct ManagedRuntimeSetupController {
    status: Mutex<ManagedRuntimeSetupStatus>,
    cancel_requested: AtomicBool,
    prerequisite_repair_active: AtomicBool,
}

impl ManagedRuntimeSetupController {
    #[cfg(any(feature = "desktop", test))]
    pub(crate) fn for_packaged_runtime_admission_failure(
        reason: ManagedRuntimeSetupFailureReason,
    ) -> Self {
        Self {
            status: Mutex::new(
                ManagedRuntimeSetupStatus::packaged_runtime_admission_failure(reason),
            ),
            cancel_requested: AtomicBool::new(false),
            prerequisite_repair_active: AtomicBool::new(false),
        }
    }

    pub fn status(&self) -> AppResult<ManagedRuntimeSetupStatus> {
        self.status
            .lock()
            .map(|mut status| {
                self.reconcile_staleness(&mut status, Utc::now());
                public_managed_runtime_setup_status(status.clone())
            })
            .map_err(|_| {
                AppError::Internal("managed runtime setup status lock was poisoned".into())
            })
    }

    pub fn begin(&self) -> AppResult<String> {
        self.begin_at(Utc::now())
    }

    fn begin_at(&self, now: DateTime<Utc>) -> AppResult<String> {
        let mut status = self.status.lock().map_err(|_| {
            AppError::Internal("managed runtime setup status lock was poisoned".into())
        })?;
        if status
            .failure_reason
            .is_some_and(ManagedRuntimeSetupFailureReason::is_packaged_runtime_admission_failure)
            && !status.can_retry
        {
            let detail = status
                .failure_reason
                .and_then(ManagedRuntimeSetupFailureReason::packaged_runtime_admission_detail)
                .unwrap_or("verified scan tools are unavailable; install the latest app version");
            return Err(AppError::NotAvailable(detail.into()));
        }
        if self.prerequisite_repair_active.load(Ordering::Acquire) {
            return Err(AppError::Conflict(
                "a Windows prerequisite repair is already active".into(),
            ));
        }
        if status.active {
            return Err(AppError::InvalidRequest(
                "managed runtime setup is already active".into(),
            ));
        }
        self.cancel_requested.store(false, Ordering::Release);
        let operation_id = Uuid::new_v4().hyphenated().to_string();
        *status = ManagedRuntimeSetupStatus {
            operation_id: Some(operation_id.clone()),
            started_at: Some(now),
            last_heartbeat_at: Some(now),
            stale: false,
            phase: ManagedRuntimeSetupPhase::Install,
            active: true,
            prerequisite_repair_active: false,
            cancel_requested: false,
            received_bytes: 0,
            total_bytes: None,
            progress_percent: None,
            resumed_from_bytes: 0,
            can_cancel: true,
            can_retry: false,
            failure_reason: None,
            next_action: None,
            detail: "installing and verifying the release-managed runtime payload".into(),
        };
        Ok(operation_id)
    }

    #[cfg(test)]
    fn begin_prerequisite_repair(
        &self,
        operation_id: &str,
    ) -> AppResult<ManagedRuntimeSetupNextAction> {
        let mut status = self.status.lock().map_err(|_| {
            AppError::Internal("managed runtime setup status lock was poisoned".into())
        })?;
        self.reserve_prerequisite_repair(&mut status, operation_id)
    }

    fn begin_automatic_prerequisite_repair(
        &self,
        operation_id: &str,
        attempted_actions: &[ManagedRuntimeSetupNextAction],
    ) -> AppResult<Option<ManagedRuntimeSetupNextAction>> {
        let mut status = self.status.lock().map_err(|_| {
            AppError::Internal("managed runtime setup status lock was poisoned".into())
        })?;
        self.reconcile_staleness(&mut status, Utc::now());
        if status.cancel_requested {
            return Err(setup_cancelled_error());
        }
        let Some(action) = automatic_windows_wsl_prerequisite_action(&status) else {
            return Ok(None);
        };
        if attempted_actions.len() >= MAX_AUTOMATIC_WINDOWS_WSL_PREREQUISITE_REPAIRS
            || attempted_actions.contains(&action)
        {
            return Ok(None);
        }
        let reserved = self.reserve_prerequisite_repair(&mut status, operation_id)?;
        debug_assert_eq!(reserved, action);
        Ok(Some(reserved))
    }

    fn reserve_prerequisite_repair(
        &self,
        status: &mut ManagedRuntimeSetupStatus,
        operation_id: &str,
    ) -> AppResult<ManagedRuntimeSetupNextAction> {
        if status.operation_id.as_deref() != Some(operation_id) {
            return Err(AppError::Conflict(
                "the managed runtime setup operation changed before Windows preparation began"
                    .into(),
            ));
        }
        let action = status.next_action.ok_or_else(|| {
            AppError::Conflict("there is no current Windows prerequisite action to repair".into())
        })?;
        let has_exact_repair_pair = matches!(
            (status.failure_reason, action),
            (
                Some(ManagedRuntimeSetupFailureReason::WslNotInstalled),
                ManagedRuntimeSetupNextAction::InstallWsl,
            ) | (
                Some(ManagedRuntimeSetupFailureReason::WslOptionalFeatureDisabled),
                ManagedRuntimeSetupNextAction::EnableWslOptionalFeatures,
            ) | (
                Some(ManagedRuntimeSetupFailureReason::WslUpdateRequired),
                ManagedRuntimeSetupNextAction::UpdateWsl,
            )
        );
        if !has_exact_repair_pair {
            return Err(AppError::InvalidRequest(
                "this managed runtime prerequisite cannot be changed automatically".into(),
            ));
        }
        if status.cancel_requested || self.cancel_requested.load(Ordering::Acquire) {
            return Err(setup_cancelled_error());
        }
        if !status.active && status.phase != ManagedRuntimeSetupPhase::Failed {
            return Err(AppError::Conflict(
                "the Windows prerequisite no longer needs automatic repair".into(),
            ));
        }
        if self.prerequisite_repair_active.swap(true, Ordering::AcqRel) {
            return Err(AppError::Conflict(
                "a Windows prerequisite repair is already active".into(),
            ));
        }
        status.prerequisite_repair_active = true;
        status.can_cancel = false;
        status.can_retry = false;
        record_managed_runtime_setup_heartbeat(status, Utc::now());
        Ok(action)
    }

    fn reconcile_staleness(&self, status: &mut ManagedRuntimeSetupStatus, now: DateTime<Utc>) {
        refresh_managed_runtime_setup_staleness(status, now);
        if status.stale {
            // Do not detach or supersede a worker that may still own an OS
            // command. Request its existing cooperative cancellation path and
            // keep Retry disabled until that exact worker terminalizes. This
            // is a persistent backend outcome, not a UI timer changing copy
            // over an otherwise active spinner.
            self.cancel_requested.store(true, Ordering::Release);
            status.cancel_requested = true;
            status.can_cancel = false;
            status.can_retry = false;
            status.detail = "Scan-tool preparation stalled. This attempt is stopping.".into();
        }
    }

    pub(crate) fn finish_prerequisite_repair(
        &self,
        operation_id: &str,
        result: Option<&ManagedRuntimePrerequisiteRepairResult>,
    ) {
        let Ok(mut status) = self.status.lock() else {
            self.prerequisite_repair_active
                .store(false, Ordering::Release);
            return;
        };
        if status.operation_id.as_deref() != Some(operation_id) {
            return;
        }
        status.prerequisite_repair_active = false;
        status.can_retry = !status.active;
        record_managed_runtime_setup_heartbeat(&mut status, Utc::now());
        if let Some(result) = result {
            if result.restart_required {
                status.phase = ManagedRuntimeSetupPhase::Failed;
                status.active = false;
                status.can_cancel = false;
                status.can_retry = true;
                status.failure_reason = Some(ManagedRuntimeSetupFailureReason::RestartRequired);
                status.next_action = Some(ManagedRuntimeSetupNextAction::RestartWindows);
                status.detail = result.detail.clone();
            } else if result.outcome != ManagedRuntimePrerequisiteRepairOutcome::Completed {
                status.detail = result.detail.clone();
            }
        }
        self.prerequisite_repair_active
            .store(false, Ordering::Release);
    }

    fn continue_after_prerequisite_repair(&self, operation_id: &str) -> AppResult<()> {
        self.check_cancelled()?;
        let mut status = self.status.lock().map_err(|_| {
            AppError::Internal("managed runtime setup status lock was poisoned".into())
        })?;
        if status.operation_id.as_deref() != Some(operation_id) || !status.active {
            return Err(AppError::Conflict(
                "the managed runtime setup operation changed before preparation could continue"
                    .into(),
            ));
        }
        if status.prerequisite_repair_active
            || self.prerequisite_repair_active.load(Ordering::Acquire)
        {
            return Err(AppError::Conflict(
                "Windows preparation has not reached a terminal result".into(),
            ));
        }
        status.phase = ManagedRuntimeSetupPhase::Install;
        status.can_cancel = true;
        status.can_retry = false;
        status.failure_reason = None;
        status.next_action = None;
        status.detail =
            "checking the isolated scan tools after automatic Windows preparation".into();
        record_managed_runtime_setup_heartbeat(&mut status, Utc::now());
        Ok(())
    }

    pub fn request_cancel(&self) -> AppResult<ManagedRuntimeSetupStatus> {
        let mut status = self.status.lock().map_err(|_| {
            AppError::Internal("managed runtime setup status lock was poisoned".into())
        })?;
        if status.active && status.can_cancel {
            self.cancel_requested.store(true, Ordering::Release);
            status.cancel_requested = true;
            status.detail = "Scan-tool preparation is stopping.".into();
        } else if status.active {
            // Export/import/unregister is a short transaction with a durable
            // recovery copy. Interrupting it between those boundaries would
            // make the next launch harder to explain, so finish the coherent
            // recovery step before accepting cancellation again.
            status.detail = "Scan-tool preparation stop status: current step completing.".into();
        } else if status.prerequisite_repair_active {
            status.detail = "Windows preparation stop status: current step completing.".into();
        } else {
            // A stale cancel must never poison the next setup attempt.
            self.cancel_requested.store(false, Ordering::Release);
        }
        if status.active || status.prerequisite_repair_active {
            record_managed_runtime_setup_heartbeat(&mut status, Utc::now());
        }
        Ok(public_managed_runtime_setup_status(status.clone()))
    }

    fn set_phase(
        &self,
        phase: ManagedRuntimeSetupPhase,
        detail: impl Into<String>,
    ) -> AppResult<()> {
        self.check_cancelled()?;
        let mut status = self.status.lock().map_err(|_| {
            AppError::Internal("managed runtime setup status lock was poisoned".into())
        })?;
        status.phase = phase;
        status.can_cancel = phase != ManagedRuntimeSetupPhase::Recovery;
        status.detail = detail.into();
        record_managed_runtime_setup_heartbeat(&mut status, Utc::now());
        drop(status);
        self.check_cancelled()
    }

    fn report_download(&self, received: u64, total: u64, resumed_from: u64) -> AppResult<()> {
        if received > total {
            return Err(AppError::Runtime(
                "managed runtime download progress exceeded its locked size".into(),
            ));
        }
        let mut status = self.status.lock().map_err(|_| {
            AppError::Internal("managed runtime setup status lock was poisoned".into())
        })?;
        status.phase = ManagedRuntimeSetupPhase::Download;
        status.received_bytes = received;
        status.total_bytes = Some(total);
        status.progress_percent = Some(if total == 0 {
            100.0
        } else {
            received as f64 * 100.0 / total as f64
        });
        status.resumed_from_bytes = resumed_from;
        status.detail = if resumed_from > 0 {
            format!("resuming managed runtime image download at {received} of {total} bytes")
        } else {
            format!("downloading managed runtime image: {received} of {total} bytes")
        };
        record_managed_runtime_setup_heartbeat(&mut status, Utc::now());
        drop(status);
        self.check_cancelled()
    }

    fn check_cancelled(&self) -> AppResult<()> {
        self.record_heartbeat()?;
        if self.cancel_requested.load(Ordering::Acquire) {
            return Err(setup_cancelled_error());
        }
        Ok(())
    }

    fn record_heartbeat(&self) -> AppResult<()> {
        let mut status = self.status.lock().map_err(|_| {
            AppError::Internal("managed runtime setup status lock was poisoned".into())
        })?;
        if status.active || status.prerequisite_repair_active {
            record_managed_runtime_setup_heartbeat(&mut status, Utc::now());
        }
        Ok(())
    }

    fn finish_completed(&self, operation_id: &str, detail: impl Into<String>) -> AppResult<()> {
        self.finish(
            operation_id,
            ManagedRuntimeSetupPhase::Completed,
            detail.into(),
        )
    }

    fn finish_failed(&self, operation_id: &str, detail: impl Into<String>) -> AppResult<()> {
        self.finish(
            operation_id,
            ManagedRuntimeSetupPhase::Failed,
            detail.into(),
        )
    }

    fn record_failure(
        &self,
        reason: ManagedRuntimeSetupFailureReason,
        action: ManagedRuntimeSetupNextAction,
        detail: impl Into<String>,
    ) -> AppResult<()> {
        let mut status = self.status.lock().map_err(|_| {
            AppError::Internal("managed runtime setup status lock was poisoned".into())
        })?;
        status.failure_reason = Some(reason);
        status.next_action = Some(action);
        status.detail = detail.into();
        record_managed_runtime_setup_heartbeat(&mut status, Utc::now());
        Ok(())
    }

    fn finish_cancelled(&self, operation_id: &str) -> AppResult<()> {
        self.finish(
            operation_id,
            ManagedRuntimeSetupPhase::Cancelled,
            "Scan-tool preparation cancelled.".into(),
        )
    }

    fn finish_worker_failure(
        &self,
        operation_id: &str,
        detail: impl Into<String>,
    ) -> AppResult<()> {
        self.finish_failed(operation_id, detail)
    }

    fn finish(
        &self,
        operation_id: &str,
        phase: ManagedRuntimeSetupPhase,
        detail: String,
    ) -> AppResult<()> {
        let mut status = self.status.lock().map_err(|_| {
            AppError::Internal("managed runtime setup status lock was poisoned".into())
        })?;
        if status.operation_id.as_deref() != Some(operation_id) {
            return Ok(());
        }
        status.phase = phase;
        status.active = false;
        status.prerequisite_repair_active = false;
        status.cancel_requested = false;
        status.can_cancel = false;
        status.can_retry = phase != ManagedRuntimeSetupPhase::Completed;
        status.stale = false;
        if phase != ManagedRuntimeSetupPhase::Failed {
            status.failure_reason = None;
            status.next_action = None;
        }
        if phase != ManagedRuntimeSetupPhase::Failed || status.failure_reason.is_none() {
            status.detail = detail;
        }
        self.cancel_requested.store(false, Ordering::Release);
        self.prerequisite_repair_active
            .store(false, Ordering::Release);
        record_managed_runtime_setup_heartbeat(&mut status, Utc::now());
        Ok(())
    }
}

fn chrono_duration(duration: Duration) -> chrono::Duration {
    chrono::Duration::seconds(
        i64::try_from(duration.as_secs()).expect("fixed managed-runtime duration fits in i64"),
    )
}

fn record_managed_runtime_setup_heartbeat(
    status: &mut ManagedRuntimeSetupStatus,
    now: DateTime<Utc>,
) {
    status.last_heartbeat_at = Some(now);
}

fn refresh_managed_runtime_setup_staleness(
    status: &mut ManagedRuntimeSetupStatus,
    now: DateTime<Utc>,
) {
    if !status.active && !status.prerequisite_repair_active {
        status.stale = false;
        return;
    }
    if status.stale && status.cancel_requested {
        // Staleness is a latched cancellation outcome. A late heartbeat from
        // the same worker cannot turn it back into an apparently healthy
        // spinner; only that operation's terminal transition clears it.
        return;
    }
    let missed_heartbeat = status.last_heartbeat_at.is_none_or(|heartbeat| {
        heartbeat + chrono_duration(MANAGED_RUNTIME_SETUP_STALE_AFTER) <= now
    });
    status.stale = missed_heartbeat;
}

/// Worker-owned terminalizer. It is constructed immediately after `begin` and
/// therefore runs during unwinding even if the originating webview invocation
/// has already disappeared. The operation identity prevents an old worker from
/// overwriting a newer retry.
struct ManagedRuntimeSetupWorkerGuard<'a> {
    controller: &'a ManagedRuntimeSetupController,
    operation_id: String,
    armed: bool,
}

impl<'a> ManagedRuntimeSetupWorkerGuard<'a> {
    fn new(controller: &'a ManagedRuntimeSetupController, operation_id: String) -> Self {
        Self {
            controller,
            operation_id,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for ManagedRuntimeSetupWorkerGuard<'_> {
    fn drop(&mut self) {
        if self.armed {
            let _ = self.controller.finish_worker_failure(
                &self.operation_id,
                "managed runtime setup worker terminated unexpectedly",
            );
        }
    }
}

fn automatic_windows_wsl_prerequisite_action(
    status: &ManagedRuntimeSetupStatus,
) -> Option<ManagedRuntimeSetupNextAction> {
    match (status.failure_reason, status.next_action) {
        (
            Some(ManagedRuntimeSetupFailureReason::WslNotInstalled),
            Some(ManagedRuntimeSetupNextAction::InstallWsl),
        ) => Some(ManagedRuntimeSetupNextAction::InstallWsl),
        (
            Some(ManagedRuntimeSetupFailureReason::WslOptionalFeatureDisabled),
            Some(ManagedRuntimeSetupNextAction::EnableWslOptionalFeatures),
        ) => Some(ManagedRuntimeSetupNextAction::EnableWslOptionalFeatures),
        (
            Some(ManagedRuntimeSetupFailureReason::WslUpdateRequired),
            Some(ManagedRuntimeSetupNextAction::UpdateWsl),
        ) => Some(ManagedRuntimeSetupNextAction::UpdateWsl),
        _ => None,
    }
}

/// Keeps the serialized/Tauri status contract internally consistent while a
/// worker is unwinding a classified failure. `record_failure` intentionally
/// stores the recovery pair before returning its error so `finish_failed` can
/// preserve it, but a concurrent poll must not observe that pair while the
/// public phase is still `prerequisite` (or while cancellation wins the race).
fn public_managed_runtime_setup_status(
    mut status: ManagedRuntimeSetupStatus,
) -> ManagedRuntimeSetupStatus {
    let has_complete_failed_recovery = status.phase == ManagedRuntimeSetupPhase::Failed
        && status.failure_reason.is_some()
        && status.next_action.is_some();
    let has_terminal_packaged_runtime_admission_failure = status.phase
        == ManagedRuntimeSetupPhase::Failed
        && !status.active
        && !status.can_retry
        && status.next_action.is_none()
        && status
            .failure_reason
            .is_some_and(ManagedRuntimeSetupFailureReason::is_packaged_runtime_admission_failure);
    if !has_complete_failed_recovery && !has_terminal_packaged_runtime_admission_failure {
        status.failure_reason = None;
        status.next_action = None;
    }
    status
}

fn setup_cancelled_error() -> AppError {
    AppError::InvalidRequest("Scan-tool preparation cancelled.".into())
}

#[derive(Debug, Clone)]
pub struct ManagedRuntimeCommand {
    binary: PathBuf,
    environment: BTreeMap<OsString, OsString>,
    working_directory: PathBuf,
    runtime_version: String,
    manifest_sha256: String,
    machine_image_sha256: String,
    #[cfg(windows)]
    windows_launch_authorization: WindowsManagedRuntimeLaunchAuthorization,
}

#[cfg(windows)]
#[derive(Debug, Clone)]
enum WindowsManagedRuntimeLaunchAuthorization {
    PrivateBundle(Arc<WindowsManagedRuntimeLaunchContract>),
    VerifiedSystem32Wsl,
    MetadataOnly,
}

impl ManagedRuntimeCommand {
    pub fn binary(&self) -> &Path {
        &self.binary
    }

    pub fn environment(&self) -> &BTreeMap<OsString, OsString> {
        &self.environment
    }

    pub fn working_directory(&self) -> &Path {
        &self.working_directory
    }

    pub fn runtime_version(&self) -> &str {
        &self.runtime_version
    }

    pub fn manifest_sha256(&self) -> &str {
        &self.manifest_sha256
    }

    pub fn machine_image_sha256(&self) -> &str {
        &self.machine_image_sha256
    }

    #[cfg(windows)]
    pub(crate) fn windows_launch_contract(
        &self,
    ) -> Option<Arc<WindowsManagedRuntimeLaunchContract>> {
        match &self.windows_launch_authorization {
            WindowsManagedRuntimeLaunchAuthorization::PrivateBundle(contract) => {
                Some(contract.clone())
            }
            WindowsManagedRuntimeLaunchAuthorization::VerifiedSystem32Wsl
            | WindowsManagedRuntimeLaunchAuthorization::MetadataOnly => None,
        }
    }

    #[cfg(windows)]
    fn acquire_windows_execution_guard(
        &self,
        deadline: Instant,
        is_cancelled: &dyn Fn() -> bool,
    ) -> io::Result<Option<WindowsManagedRuntimeExecutionGuard>> {
        match &self.windows_launch_authorization {
            WindowsManagedRuntimeLaunchAuthorization::PrivateBundle(contract) => contract
                .acquire(&self.binary, deadline, is_cancelled)
                .map(Some),
            WindowsManagedRuntimeLaunchAuthorization::VerifiedSystem32Wsl => {
                check_windows_launch_guard_budget(deadline, is_cancelled)?;
                verify_windows_system32_wsl_command(self)?;
                check_windows_launch_guard_budget(deadline, is_cancelled)?;
                Ok(None)
            }
            WindowsManagedRuntimeLaunchAuthorization::MetadataOnly => Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "managed runtime metadata-only command is not authorized for execution",
            )),
        }
    }
}

#[cfg(windows)]
fn verify_windows_system32_wsl_command(command: &ManagedRuntimeCommand) -> io::Result<()> {
    let directories = windows_system_directories()
        .map_err(|error| io::Error::new(io::ErrorKind::PermissionDenied, error.to_string()))?;
    if command.binary != directories.system32.join("wsl.exe") {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "managed runtime system command is not the verified System32 wsl.exe",
        ));
    }
    verify_regular_file(&command.binary, "Windows System32 wsl.exe")
        .map_err(|error| io::Error::new(io::ErrorKind::PermissionDenied, error.to_string()))
}

/// Immutable release identity needed to re-prove and pin one Windows managed
/// runtime invocation. It contains no live handles so commands may be cloned
/// and retained without preventing an idle repair or uninstall.
#[cfg(windows)]
#[derive(Debug, Clone)]
pub(crate) struct WindowsManagedRuntimeLaunchContract {
    install_root: PathBuf,
    versions_root: PathBuf,
    driver: PathBuf,
    bundle_directories: Vec<PathBuf>,
    files: Vec<WindowsManagedRuntimeLaunchFile>,
}

#[cfg(windows)]
#[derive(Debug, Clone)]
struct WindowsManagedRuntimeLaunchFile {
    path: PathBuf,
    size_bytes: u64,
    sha256: String,
}

/// Live only for one invocation. The directory handles deny rename/delete of
/// the verified namespace, while the file handles deny write/delete access to
/// the exact objects that were hashed for this launch.
#[cfg(windows)]
#[derive(Debug)]
pub(crate) struct WindowsManagedRuntimeExecutionGuard {
    _directory_handles: Vec<File>,
    _file_handles: Vec<File>,
}

#[cfg(windows)]
impl WindowsManagedRuntimeLaunchContract {
    /// Re-proves the exact installed bundle immediately before one process
    /// launch and keeps every directory/file handle alive until that process
    /// has finished. Listed-file handles deliberately allow only read sharing:
    /// an already-open writer makes admission fail, existing hard links are
    /// rejected, and a later writer, rename, or delete of those files remains
    /// blocked for the guard's life. Directory handles pin the checked
    /// directory objects against rename/delete; the closed inventory is a
    /// pre-launch check, not a same-user directory-write isolation boundary.
    pub(crate) fn acquire(
        &self,
        requested_binary: &Path,
        deadline: Instant,
        is_cancelled: &dyn Fn() -> bool,
    ) -> io::Result<WindowsManagedRuntimeExecutionGuard> {
        use windows_sys::Win32::Security::{CONTAINER_INHERIT_ACE, OBJECT_INHERIT_ACE};

        check_windows_launch_guard_budget(deadline, is_cancelled)?;
        if requested_binary != self.driver
            || self.install_root.parent() != Some(self.versions_root.as_path())
            || !self.driver.starts_with(&self.install_root)
            || !self.files.iter().any(|file| file.path == self.driver)
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "managed runtime launch contract does not identify the requested driver",
            ));
        }

        // Pin every canonical ancestor first. In particular, moving an
        // otherwise verified parent must not let the path used by
        // CreateProcess resolve into a replacement tree.
        let mut directory_handles =
            verify_windows_managed_namespace_ancestor_chain(&self.versions_root)?;
        check_windows_launch_guard_budget(deadline, is_cancelled)?;
        let inheritance = u8::try_from(OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE)
            .expect("Windows inheritance flags fit in an ACE header");
        let versions = directory_handles.first().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "managed runtime versions directory could not be pinned",
            )
        })?;
        verify_windows_current_user_only_dacl_with_ace_flags(versions, inheritance)?;
        verify_windows_directory_path_identity(&self.versions_root, versions)?;

        for directory in &self.bundle_directories {
            check_windows_launch_guard_budget(deadline, is_cancelled)?;
            if directory != &self.install_root && !directory.starts_with(&self.install_root) {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "managed runtime bundle directory escaped its installed root",
                ));
            }
            let handle = open_windows_managed_runtime_directory(directory, inheritance)?;
            directory_handles.push(handle);
        }

        let mut file_handles = Vec::with_capacity(self.files.len());
        for expected in &self.files {
            check_windows_launch_guard_budget(deadline, is_cancelled)?;
            if !expected.path.starts_with(&self.install_root) {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "managed runtime launch file escaped its installed root",
                ));
            }
            let mut handle =
                open_windows_managed_runtime_file(&expected.path, Some(expected.size_bytes))?;
            verify_windows_managed_runtime_file_hash(
                &mut handle,
                expected.size_bytes,
                &expected.sha256,
                deadline,
                is_cancelled,
            )?;
            file_handles.push(handle);
        }
        self.verify_closed_bundle_inventory(deadline, is_cancelled)?;
        check_windows_launch_guard_budget(deadline, is_cancelled)?;

        Ok(WindowsManagedRuntimeExecutionGuard {
            _directory_handles: directory_handles,
            _file_handles: file_handles,
        })
    }

    fn verify_closed_bundle_inventory(
        &self,
        deadline: Instant,
        is_cancelled: &dyn Fn() -> bool,
    ) -> io::Result<()> {
        check_windows_launch_guard_budget(deadline, is_cancelled)?;
        let expected_directories = self
            .bundle_directories
            .iter()
            .filter(|path| *path != &self.install_root)
            .cloned()
            .collect::<BTreeSet<_>>();
        let expected_files = self
            .files
            .iter()
            .map(|file| file.path.clone())
            .collect::<BTreeSet<_>>();
        if expected_files.len() != self.files.len()
            || !self
                .bundle_directories
                .iter()
                .any(|directory| directory == &self.install_root)
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "managed runtime launch contract contains a duplicate or incomplete inventory",
            ));
        }

        let mut observed_directories = BTreeSet::new();
        let mut observed_files = BTreeSet::new();
        for directory in &self.bundle_directories {
            check_windows_launch_guard_budget(deadline, is_cancelled)?;
            for entry in fs::read_dir(directory)? {
                check_windows_launch_guard_budget(deadline, is_cancelled)?;
                let entry = entry?;
                let path = entry.path();
                let metadata = fs::symlink_metadata(&path)?;
                if expected_directories.contains(&path) {
                    if metadata.file_type().is_symlink() || !metadata.is_dir() {
                        return Err(io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            "managed runtime bundle inventory contains a non-directory entry",
                        ));
                    }
                    observed_directories.insert(path);
                } else if expected_files.contains(&path) {
                    if metadata.file_type().is_symlink() || !metadata.is_file() {
                        return Err(io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            "managed runtime bundle inventory contains a non-file entry",
                        ));
                    }
                    observed_files.insert(path);
                } else {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "managed runtime bundle contains an unlisted launch-time entry",
                    ));
                }
            }
        }
        check_windows_launch_guard_budget(deadline, is_cancelled)?;
        if observed_directories != expected_directories || observed_files != expected_files {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "managed runtime bundle inventory differs from the release manifest",
            ));
        }
        Ok(())
    }
}

#[cfg(windows)]
fn check_windows_launch_guard_budget(
    deadline: Instant,
    is_cancelled: &dyn Fn() -> bool,
) -> io::Result<()> {
    if is_cancelled() {
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "managed runtime launch verification was cancelled",
        ));
    }
    if Instant::now() >= deadline {
        return Err(managed_command_deadline_error());
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagedStopMode {
    OnlyIfIdle,
    Force,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ManagedUninstallOptions {
    pub stop_mode: ManagedStopMode,
    pub remove_machine_image_cache: bool,
}

impl Default for ManagedUninstallOptions {
    fn default() -> Self {
        Self {
            stop_mode: ManagedStopMode::OnlyIfIdle,
            remove_machine_image_cache: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManagedRuntimeUpdateResult {
    pub status: ManagedRuntimeStatus,
    pub superseded_installations: Vec<String>,
}

#[derive(Debug)]
struct ManagedCommandOutput {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

#[derive(Debug)]
enum StatusMachineInventoryFailure {
    Reconciliation(AppError),
    Invalid(AppError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ManagedCommandOperation {
    MachineInitialization,
    MachineInventory,
    MachineStart,
    MachineStop,
    MachineRemoval,
    WslDistributionInventory,
    ActiveContainerInventory,
    VersionPreflight,
}

impl ManagedCommandOperation {
    fn label(self) -> &'static str {
        match self {
            Self::MachineInitialization => "managed runtime machine initialization",
            Self::MachineInventory => "managed runtime machine inventory",
            Self::MachineStart => "managed runtime machine start",
            Self::MachineStop => "managed runtime machine stop",
            Self::MachineRemoval => "managed runtime machine removal",
            Self::WslDistributionInventory => "managed Windows WSL distribution inventory",
            Self::ActiveContainerInventory => "managed runtime active-container inventory",
            Self::VersionPreflight => "managed runtime version preflight",
        }
    }
}

trait ManagedCommandRunner: Send + Sync {
    fn output(
        &self,
        command: &ManagedRuntimeCommand,
        args: &[OsString],
        timeout: Duration,
    ) -> io::Result<ManagedCommandOutput>;
}

trait WindowsWslRegistrationReader: Send + Sync {
    fn registrations(&self) -> AppResult<Vec<WindowsWslRegistration>>;

    fn inventory(&self) -> AppResult<WindowsWslRegistrationInventory> {
        self.registrations()
            .map(WindowsWslRegistrationInventory::complete)
    }
}

trait WindowsWslPrerequisiteRepairer: Send + Sync {
    fn repair(
        &self,
        action: ManagedRuntimeSetupNextAction,
    ) -> AppResult<ManagedRuntimePrerequisiteRepairResult>;
}

#[derive(Debug, Default)]
struct DirectWindowsWslRegistrationReader;

impl WindowsWslRegistrationReader for DirectWindowsWslRegistrationReader {
    fn registrations(&self) -> AppResult<Vec<WindowsWslRegistration>> {
        let inventory = windows_wsl_registration_inventory()?;
        if !inventory.complete {
            return Err(AppError::NotAvailable(
                "Windows WSL registration inventory was incomplete; no existing registration may be adopted or changed"
                    .into(),
            ));
        }
        Ok(inventory.registrations)
    }

    fn inventory(&self) -> AppResult<WindowsWslRegistrationInventory> {
        windows_wsl_registration_inventory()
    }
}

#[derive(Debug, Default)]
struct DirectWindowsWslPrerequisiteRepairer;

impl WindowsWslPrerequisiteRepairer for DirectWindowsWslPrerequisiteRepairer {
    fn repair(
        &self,
        action: ManagedRuntimeSetupNextAction,
    ) -> AppResult<ManagedRuntimePrerequisiteRepairResult> {
        repair_windows_wsl_prerequisite(action)
    }
}

#[derive(Debug, Default)]
struct DirectManagedCommandRunner;

const MANAGED_COMMAND_PIPE_DRAIN_TIMEOUT: Duration = Duration::from_secs(2);

impl ManagedCommandRunner for DirectManagedCommandRunner {
    fn output(
        &self,
        command: &ManagedRuntimeCommand,
        args: &[OsString],
        timeout: Duration,
    ) -> io::Result<ManagedCommandOutput> {
        let deadline = Instant::now().checked_add(timeout).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "managed runtime command deadline exceeded the platform range",
            )
        })?;
        #[cfg(windows)]
        let _execution_guard = command.acquire_windows_execution_guard(deadline, &|| false)?;
        if Instant::now() >= deadline {
            return Err(managed_command_deadline_error());
        }
        let mut process = Command::new(&command.binary);
        process
            .args(args)
            .env_clear()
            .envs(command.environment.iter())
            .current_dir(&command.working_directory)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut process_tree = ManagedCommandProcessTree::prepare(&mut process)?;
        if Instant::now() >= deadline {
            return Err(managed_command_deadline_error());
        }
        let mut child = process.spawn()?;
        if let Err(error) = process_tree.attach(&child) {
            return Err(managed_command_error_with_cleanup(
                error,
                process_tree.terminate_and_wait(&mut child),
            ));
        }
        if Instant::now() >= deadline {
            return Err(managed_command_error_with_cleanup(
                managed_command_deadline_error(),
                process_tree.terminate_and_wait(&mut child),
            ));
        }
        if let Err(error) = process_tree.start(&child) {
            return Err(managed_command_error_with_cleanup(
                error,
                process_tree.terminate_and_wait(&mut child),
            ));
        }
        if Instant::now() >= deadline {
            return Err(managed_command_error_with_cleanup(
                managed_command_deadline_error(),
                process_tree.terminate_and_wait(&mut child),
            ));
        }
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| io::Error::other("managed runtime stdout pipe was unavailable"))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| io::Error::other("managed runtime stderr pipe was unavailable"))?;
        let captured = Arc::new(AtomicU64::new(0));
        let oversized = Arc::new(AtomicBool::new(false));
        let mut stdout_capture = spawn_bounded_capture(
            stdout,
            captured.clone(),
            oversized.clone(),
            MAX_COMMAND_OUTPUT_BYTES,
        );
        let mut stderr_capture = spawn_bounded_capture(
            stderr,
            captured,
            oversized.clone(),
            MAX_COMMAND_OUTPUT_BYTES,
        );

        let mut terminated = false;
        let process_result = loop {
            if oversized.load(Ordering::Acquire) {
                terminated = true;
                break Err(managed_command_error_with_cleanup(
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "managed runtime command output exceeded its aggregate limit",
                    ),
                    process_tree.terminate_and_wait(&mut child),
                ));
            }
            if Instant::now() >= deadline {
                terminated = true;
                break Err(managed_command_error_with_cleanup(
                    managed_command_deadline_error(),
                    process_tree.terminate_and_wait(&mut child),
                ));
            }
            match child.try_wait() {
                Ok(Some(status)) => {
                    if Instant::now() >= deadline {
                        terminated = true;
                        break Err(managed_command_error_with_cleanup(
                            managed_command_deadline_error(),
                            process_tree.terminate_and_wait(&mut child),
                        ));
                    }
                    if !status.success() {
                        terminated = true;
                        if let Err(error) = process_tree.terminate_and_wait(&mut child) {
                            break Err(io::Error::new(
                                error.kind(),
                                format!(
                                    "managed runtime command exited unsuccessfully and its process tree could not be cleaned up: {error}"
                                ),
                            ));
                        }
                    }
                    break Ok(status);
                }
                Ok(None) => {}
                Err(error) => {
                    terminated = true;
                    break Err(managed_command_error_with_cleanup(
                        error,
                        process_tree.terminate_and_wait(&mut child),
                    ));
                }
            }
            thread::sleep(
                deadline
                    .saturating_duration_since(Instant::now())
                    .min(Duration::from_millis(25)),
            );
        };
        let drain_deadline = if terminated {
            Instant::now() + MANAGED_COMMAND_PIPE_DRAIN_TIMEOUT
        } else {
            deadline
        };
        let capture_result = finish_managed_command_captures(
            &mut stdout_capture,
            &mut stderr_capture,
            drain_deadline,
            &mut terminated,
            oversized.as_ref(),
            &process_tree,
            &mut child,
        );
        if oversized.load(Ordering::Acquire) {
            let mut error = if terminated {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "managed runtime command output exceeded its aggregate limit",
                )
            } else {
                managed_command_error_with_cleanup(
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "managed runtime command output exceeded its aggregate limit",
                    ),
                    process_tree.terminate_and_wait(&mut child),
                )
            };
            if let Err(process_error) = &process_result {
                error = io::Error::new(
                    error.kind(),
                    format!("{error}; command completion diagnostic: {process_error}"),
                );
            }
            if let Err(capture_error) = &capture_result {
                error = io::Error::new(
                    error.kind(),
                    format!("{error}; output-capture diagnostic: {capture_error}"),
                );
            }
            return Err(error);
        }
        let (status, stdout, stderr) = match (process_result, capture_result) {
            (Err(process_error), Err(capture_error)) => {
                return Err(io::Error::new(
                    process_error.kind(),
                    format!(
                        "{process_error}; managed runtime output capture also failed: {capture_error}"
                    ),
                ));
            }
            (Err(process_error), Ok(_)) => return Err(process_error),
            (Ok(_), Err(capture_error)) => return Err(capture_error),
            (Ok(status), Ok((stdout, stderr))) => (status, stdout, stderr),
        };
        if status.success()
            && let Err(error) = process_tree.preserve_descendants()
        {
            return Err(managed_command_error_with_cleanup(
                error,
                process_tree.terminate_and_wait(&mut child),
            ));
        }
        Ok(ManagedCommandOutput {
            status,
            stdout,
            stderr,
        })
    }
}

fn managed_command_deadline_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::TimedOut,
        "managed runtime command exceeded its deadline",
    )
}

fn remaining_command_budget(deadline: Instant) -> Option<Duration> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    (!remaining.is_zero()).then_some(remaining)
}

fn managed_command_error_with_cleanup(primary: io::Error, cleanup: io::Result<()>) -> io::Error {
    managed_command_error_with_optional_cleanup(primary, cleanup.err())
}

fn managed_command_error_with_optional_cleanup(
    primary: io::Error,
    cleanup: Option<io::Error>,
) -> io::Error {
    match cleanup {
        Some(cleanup) => io::Error::new(
            primary.kind(),
            format!("{primary}; managed runtime process-tree cleanup also failed: {cleanup}"),
        ),
        None => primary,
    }
}

struct ManagedMemoryCapture {
    result: std::sync::mpsc::Receiver<io::Result<Vec<u8>>>,
    worker: Option<thread::JoinHandle<()>>,
}

impl ManagedMemoryCapture {
    #[cfg(all(test, unix))]
    fn finish_by(&mut self, deadline: Instant) -> io::Result<Vec<u8>> {
        let remaining = deadline.saturating_duration_since(Instant::now());
        match self.result.recv_timeout(remaining) {
            Ok(result) => self.finish_received(result),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "managed runtime output pipes did not close before the bounded drain deadline",
            )),
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => self.finish_disconnected(),
        }
    }

    fn try_finish(&mut self) -> Option<io::Result<Vec<u8>>> {
        match self.result.try_recv() {
            Ok(result) => Some(self.finish_received(result)),
            Err(std::sync::mpsc::TryRecvError::Empty) => None,
            Err(std::sync::mpsc::TryRecvError::Disconnected) => Some(self.finish_disconnected()),
        }
    }

    fn finish_received(&mut self, result: io::Result<Vec<u8>>) -> io::Result<Vec<u8>> {
        let worker = self.worker.take().ok_or_else(|| {
            io::Error::other("managed runtime output capture worker was already consumed")
        })?;
        match worker.join() {
            Ok(()) => result,
            Err(_) => match result {
                Ok(_) => Err(io::Error::other(
                    "managed runtime output capture thread failed",
                )),
                Err(error) => Err(io::Error::new(
                    error.kind(),
                    format!("{error}; managed runtime output capture thread also failed"),
                )),
            },
        }
    }

    fn finish_disconnected(&mut self) -> io::Result<Vec<u8>> {
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
        Err(io::Error::other(
            "managed runtime output capture thread failed",
        ))
    }
}

fn record_managed_capture_error(primary: &mut Option<io::Error>, stream: &str, error: io::Error) {
    let error = io::Error::new(
        error.kind(),
        format!("managed runtime {stream} capture failed: {error}"),
    );
    *primary = Some(match primary.take() {
        Some(primary) => io::Error::new(
            primary.kind(),
            format!("{primary}; additional capture failure: {error}"),
        ),
        None => error,
    });
}

#[allow(clippy::too_many_arguments)]
fn finish_managed_command_captures(
    stdout_capture: &mut ManagedMemoryCapture,
    stderr_capture: &mut ManagedMemoryCapture,
    initial_deadline: Instant,
    process_tree_terminated: &mut bool,
    oversized: &AtomicBool,
    process_tree: &ManagedCommandProcessTree,
    child: &mut Child,
) -> io::Result<(Vec<u8>, Vec<u8>)> {
    let mut stdout = None;
    let mut stderr = None;
    let mut stdout_complete = false;
    let mut stderr_complete = false;
    let mut primary_error = None;
    let mut drain_deadline = initial_deadline;
    let mut post_kill = *process_tree_terminated;

    loop {
        let mut stdout_failed = false;
        if !stdout_complete && let Some(result) = stdout_capture.try_finish() {
            stdout_complete = true;
            match result {
                Ok(output) => stdout = Some(output),
                Err(error) => {
                    record_managed_capture_error(&mut primary_error, "stdout", error);
                    stdout_failed = true;
                }
            }
        }
        if stdout_failed && !post_kill {
            let cleanup = process_tree.terminate_and_wait(child);
            *process_tree_terminated = true;
            post_kill = true;
            drain_deadline = Instant::now() + MANAGED_COMMAND_PIPE_DRAIN_TIMEOUT;
            if let Some(error) = primary_error.take() {
                primary_error = Some(managed_command_error_with_cleanup(error, cleanup));
            }
        }

        let mut stderr_failed = false;
        if !stderr_complete && let Some(result) = stderr_capture.try_finish() {
            stderr_complete = true;
            match result {
                Ok(output) => stderr = Some(output),
                Err(error) => {
                    record_managed_capture_error(&mut primary_error, "stderr", error);
                    stderr_failed = true;
                }
            }
        }
        if stderr_failed && !post_kill {
            let cleanup = process_tree.terminate_and_wait(child);
            *process_tree_terminated = true;
            post_kill = true;
            drain_deadline = Instant::now() + MANAGED_COMMAND_PIPE_DRAIN_TIMEOUT;
            if let Some(error) = primary_error.take() {
                primary_error = Some(managed_command_error_with_cleanup(error, cleanup));
            }
        }

        if oversized.load(Ordering::Acquire) && !post_kill {
            if let Err(error) = process_tree.terminate_and_wait(child) {
                record_managed_capture_error(&mut primary_error, "output-limit cleanup", error);
            }
            *process_tree_terminated = true;
            post_kill = true;
            drain_deadline = Instant::now() + MANAGED_COMMAND_PIPE_DRAIN_TIMEOUT;
        }

        if stdout_complete && stderr_complete {
            break;
        }

        let now = Instant::now();
        if now >= drain_deadline {
            let timeout = || {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "managed runtime output pipes did not close before the bounded drain deadline",
                )
            };
            if !post_kill {
                if !stdout_complete {
                    record_managed_capture_error(&mut primary_error, "stdout", timeout());
                }
                if !stderr_complete {
                    record_managed_capture_error(&mut primary_error, "stderr", timeout());
                }
                let cleanup = process_tree.terminate_and_wait(child);
                *process_tree_terminated = true;
                post_kill = true;
                drain_deadline = Instant::now() + MANAGED_COMMAND_PIPE_DRAIN_TIMEOUT;
                if let Some(error) = primary_error.take() {
                    primary_error = Some(managed_command_error_with_cleanup(error, cleanup));
                }
                continue;
            }
            if !stdout_complete {
                record_managed_capture_error(
                    &mut primary_error,
                    "stdout post-termination drain",
                    timeout(),
                );
            }
            if !stderr_complete {
                record_managed_capture_error(
                    &mut primary_error,
                    "stderr post-termination drain",
                    timeout(),
                );
            }
            break;
        }
        thread::sleep(
            drain_deadline
                .saturating_duration_since(now)
                .min(Duration::from_millis(5)),
        );
    }

    match primary_error {
        Some(error) => Err(error),
        None => Ok((
            stdout.ok_or_else(|| io::Error::other("managed runtime stdout capture was empty"))?,
            stderr.ok_or_else(|| io::Error::other("managed runtime stderr capture was empty"))?,
        )),
    }
}

fn spawn_bounded_capture<R>(
    mut reader: R,
    captured: Arc<AtomicU64>,
    oversized: Arc<AtomicBool>,
    maximum: u64,
) -> ManagedMemoryCapture
where
    R: Read + Send + 'static,
{
    let (sender, result) = std::sync::mpsc::sync_channel(1);
    let worker = thread::spawn(move || {
        let mut output = Vec::new();
        let mut buffer = [0_u8; 16 * 1024];
        let capture = (|| {
            loop {
                let read = reader.read(&mut buffer)?;
                if read == 0 {
                    break;
                }
                let previous = captured.fetch_add(read as u64, Ordering::AcqRel);
                let remaining = maximum.saturating_sub(previous) as usize;
                output.extend_from_slice(&buffer[..read.min(remaining)]);
                if read > remaining {
                    oversized.store(true, Ordering::Release);
                }
            }
            Ok(output)
        })();
        let _ = sender.send(capture);
    });
    ManagedMemoryCapture {
        result,
        worker: Some(worker),
    }
}

struct ManagedCommandProcessTree {
    #[cfg(unix)]
    process_group: Option<i32>,
    #[cfg(windows)]
    job: std::os::windows::io::OwnedHandle,
    preserved: bool,
}

impl ManagedCommandProcessTree {
    fn prepare(command: &mut Command) -> io::Result<Self> {
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            command.process_group(0);
            Ok(Self {
                process_group: None,
                preserved: false,
            })
        }
        #[cfg(windows)]
        {
            use std::os::windows::io::{FromRawHandle, OwnedHandle};
            use std::os::windows::process::CommandExt;
            use windows_sys::Win32::System::JobObjects::{
                CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
                JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
                SetInformationJobObject,
            };
            use windows_sys::Win32::System::Threading::{CREATE_NO_WINDOW, CREATE_SUSPENDED};

            command.creation_flags(CREATE_NO_WINDOW | CREATE_SUSPENDED);
            let raw_job = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
            if raw_job.is_null() {
                return Err(io::Error::last_os_error());
            }
            let job = unsafe { OwnedHandle::from_raw_handle(raw_job.cast()) };
            let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
            limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            let configured = unsafe {
                SetInformationJobObject(
                    std::os::windows::io::AsRawHandle::as_raw_handle(&job).cast(),
                    JobObjectExtendedLimitInformation,
                    std::ptr::addr_of!(limits).cast(),
                    std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                )
            };
            if configured == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(Self {
                job,
                preserved: false,
            })
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = command;
            Ok(Self { preserved: false })
        }
    }

    fn attach(&mut self, child: &Child) -> io::Result<()> {
        #[cfg(unix)]
        {
            self.process_group = Some(i32::try_from(child.id()).map_err(|_| {
                io::Error::other("managed runtime child process ID exceeded the platform range")
            })?);
            Ok(())
        }
        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawHandle;
            use windows_sys::Win32::System::JobObjects::AssignProcessToJobObject;
            let assigned = unsafe {
                AssignProcessToJobObject(
                    self.job.as_raw_handle().cast(),
                    child.as_raw_handle().cast(),
                )
            };
            if assigned == 0 {
                let error = io::Error::last_os_error();
                Err(io::Error::new(
                    error.kind(),
                    format!(
                        "managed runtime child could not join its containment job, possibly because of an incompatible outer job: {error}"
                    ),
                ))
            } else {
                Ok(())
            }
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = child;
            Ok(())
        }
    }

    fn start(&self, child: &Child) -> io::Result<()> {
        #[cfg(windows)]
        {
            use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
            use windows_sys::Win32::Foundation::{ERROR_NO_MORE_FILES, INVALID_HANDLE_VALUE};
            use windows_sys::Win32::System::Diagnostics::ToolHelp::{
                CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First,
                Thread32Next,
            };
            use windows_sys::Win32::System::Threading::{
                OpenThread, ResumeThread, THREAD_SUSPEND_RESUME,
            };

            let raw_snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
            if raw_snapshot == INVALID_HANDLE_VALUE {
                return Err(io::Error::last_os_error());
            }
            let snapshot = unsafe { OwnedHandle::from_raw_handle(raw_snapshot.cast()) };
            let mut entry = THREADENTRY32 {
                dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
                ..THREADENTRY32::default()
            };
            if unsafe { Thread32First(snapshot.as_raw_handle().cast(), &mut entry) } == 0 {
                return Err(io::Error::last_os_error());
            }
            let mut primary_thread = None;
            loop {
                if entry.th32OwnerProcessID == child.id()
                    && primary_thread.replace(entry.th32ThreadID).is_some()
                {
                    return Err(io::Error::other(
                        "managed runtime suspended child had more than one initial thread",
                    ));
                }
                if unsafe { Thread32Next(snapshot.as_raw_handle().cast(), &mut entry) } == 0 {
                    let error = io::Error::last_os_error();
                    if error.raw_os_error() == Some(ERROR_NO_MORE_FILES as i32) {
                        break;
                    }
                    return Err(error);
                }
            }
            let primary_thread = primary_thread.ok_or_else(|| {
                io::Error::other("managed runtime suspended child primary thread was unavailable")
            })?;
            let raw_thread = unsafe { OpenThread(THREAD_SUSPEND_RESUME, 0, primary_thread) };
            if raw_thread.is_null() {
                return Err(io::Error::last_os_error());
            }
            let thread = unsafe { OwnedHandle::from_raw_handle(raw_thread.cast()) };
            let previous_suspend_count = unsafe { ResumeThread(thread.as_raw_handle().cast()) };
            if previous_suspend_count == u32::MAX {
                return Err(io::Error::last_os_error());
            }
            if previous_suspend_count != 1 {
                return Err(io::Error::other(format!(
                    "managed runtime child had unexpected suspend count {previous_suspend_count}"
                )));
            }
        }
        #[cfg(not(windows))]
        let _ = child;
        Ok(())
    }

    fn terminate_and_wait(&self, child: &mut Child) -> io::Result<()> {
        let mut cleanup_errors = Vec::new();
        let mut cleanup_error_kind = None;
        #[cfg(unix)]
        if let Some(process_group) = self.process_group
            && unsafe { libc::kill(-process_group, libc::SIGKILL) } != 0
        {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::ESRCH) {
                cleanup_error_kind.get_or_insert(error.kind());
                cleanup_errors.push(format!("process-group termination failed: {error}"));
            }
        }
        #[cfg(windows)]
        if unsafe {
            windows_sys::Win32::System::JobObjects::TerminateJobObject(
                std::os::windows::io::AsRawHandle::as_raw_handle(&self.job).cast(),
                1,
            )
        } == 0
        {
            let error = io::Error::last_os_error();
            cleanup_error_kind.get_or_insert(error.kind());
            cleanup_errors.push(format!("containment-job termination failed: {error}"));
        }
        match child.try_wait() {
            Ok(Some(_)) => {}
            Ok(None) => {
                if let Err(error) = child.kill() {
                    cleanup_error_kind.get_or_insert(error.kind());
                    cleanup_errors.push(format!("direct-child termination failed: {error}"));
                }
            }
            Err(error) => {
                cleanup_error_kind.get_or_insert(error.kind());
                cleanup_errors.push(format!("direct-child status check failed: {error}"));
                if let Err(error) = child.kill() {
                    cleanup_error_kind.get_or_insert(error.kind());
                    cleanup_errors.push(format!("direct-child termination failed: {error}"));
                }
            }
        }
        if let Err(error) = child.wait() {
            cleanup_error_kind.get_or_insert(error.kind());
            cleanup_errors.push(format!("direct-child wait failed: {error}"));
        }
        match cleanup_error_kind {
            Some(kind) => Err(io::Error::new(kind, cleanup_errors.join("; "))),
            None => Ok(()),
        }
    }

    fn preserve_descendants(&mut self) -> io::Result<()> {
        #[cfg(windows)]
        {
            use windows_sys::Win32::System::JobObjects::{
                JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
                SetInformationJobObject,
            };
            let limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
            let configured = unsafe {
                SetInformationJobObject(
                    std::os::windows::io::AsRawHandle::as_raw_handle(&self.job).cast(),
                    JobObjectExtendedLimitInformation,
                    std::ptr::addr_of!(limits).cast(),
                    std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                )
            };
            if configured == 0 {
                return Err(io::Error::last_os_error());
            }
        }
        self.preserved = true;
        Ok(())
    }
}

impl Drop for ManagedCommandProcessTree {
    fn drop(&mut self) {
        #[cfg(unix)]
        if !self.preserved
            && let Some(process_group) = self.process_group
        {
            unsafe {
                libc::kill(-process_group, libc::SIGKILL);
            }
        }
    }
}

trait ManagedArtifactDownloader: Send + Sync {
    fn acquire(
        &self,
        image: &ManagedMachineImage,
        destination: &Path,
        progress: &mut dyn FnMut(u64, u64, u64) -> AppResult<()>,
    ) -> AppResult<()>;
}

#[derive(Debug, Default)]
struct HttpsManagedArtifactDownloader;

impl HttpsManagedArtifactDownloader {
    fn new() -> AppResult<Self> {
        Ok(Self)
    }

    fn client() -> AppResult<Client> {
        Client::builder()
            .connect_timeout(DOWNLOAD_CONNECT_TIMEOUT)
            .timeout(DOWNLOAD_TOTAL_TIMEOUT)
            .redirect(reqwest::redirect::Policy::custom(|attempt| {
                if attempt.previous().len() >= 5 {
                    return attempt.error("too many managed runtime artifact redirects");
                }
                if attempt.url().scheme() != "https" || !allowed_download_host(attempt.url()) {
                    return attempt.error("managed runtime artifact redirect was not approved");
                }
                attempt.follow()
            }))
            .user_agent(concat!("ai-security-scanner/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|error| {
                AppError::Runtime(format!(
                    "managed runtime HTTPS client could not be initialized: {error}"
                ))
            })
    }

    fn response(client: &Client, image: &ManagedMachineImage, offset: u64) -> AppResult<Response> {
        let mut request = client.get(&image.url).header(ACCEPT_ENCODING, "identity");
        if offset > 0 {
            request = request.header(RANGE, format!("bytes={offset}-"));
        }
        let response = request.send().map_err(|error| {
            AppError::Runtime(format!("managed runtime image download failed: {error}"))
        })?;
        if !response.status().is_success() {
            return Err(AppError::Runtime(format!(
                "managed runtime image server returned HTTP {}",
                response.status()
            )));
        }
        Ok(response)
    }
}

impl ManagedArtifactDownloader for HttpsManagedArtifactDownloader {
    fn acquire(
        &self,
        image: &ManagedMachineImage,
        destination: &Path,
        progress: &mut dyn FnMut(u64, u64, u64) -> AppResult<()>,
    ) -> AppResult<()> {
        let mut existing = regular_file_length_or_zero(destination)?;
        if existing > image.size_bytes {
            return Err(AppError::NotAuthorized(
                "partial managed runtime image exceeds its locked size".into(),
            ));
        }
        if existing == image.size_bytes {
            if verify_file_hash_size(
                destination,
                image.size_bytes,
                &image.sha256,
                "completed managed runtime partial image",
            )
            .is_ok()
            {
                progress(existing, image.size_bytes, existing)?;
                return Ok(());
            }
            // A complete-length prefix with the wrong digest can never be
            // resumed safely. Truncate only this exact private partial and
            // reacquire the locked object from byte zero.
            let mut file = open_private_download_file(destination, false)?;
            file.flush()?;
            file.sync_all()?;
            existing = 0;
        }
        progress(existing, image.size_bytes, existing)?;
        // reqwest's blocking client owns a small internal async runtime. Keep
        // that runtime scoped to this inherently blocking operation so merely
        // opening or inspecting a manager is safe in an async application.
        let client = Self::client()?;
        let mut response = Self::response(&client, image, existing)?;
        let resumed = existing > 0 && response.status() == reqwest::StatusCode::PARTIAL_CONTENT;
        if resumed {
            let content_range = response
                .headers()
                .get(CONTENT_RANGE)
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default();
            validate_resume_content_range(content_range, existing, image.size_bytes)?;
        }

        let mut file = open_private_download_file(destination, resumed)?;
        let mut written = if resumed { existing } else { 0 };
        let resumed_from = if resumed { existing } else { 0 };
        if !resumed {
            // A server may legally ignore Range and return the full object. The
            // partial is then truncated and the observable counters restart at
            // zero instead of pretending old bytes were reused.
            progress(0, image.size_bytes, 0)?;
        }
        written = write_download_body(
            &mut response,
            &mut file,
            written,
            image.size_bytes,
            resumed_from,
            progress,
        )?;
        if written != image.size_bytes {
            return Err(AppError::Runtime(format!(
                "managed runtime image is incomplete: received {written} of {} bytes",
                image.size_bytes
            )));
        }
        Ok(())
    }
}

fn validate_resume_content_range(value: &str, offset: u64, total: u64) -> AppResult<()> {
    let invalid = || {
        AppError::Runtime(
            "managed runtime image server returned an invalid resume Content-Range".into(),
        )
    };
    let (unit, value) = value.split_once(' ').ok_or_else(invalid)?;
    let (range, declared_total) = value.split_once('/').ok_or_else(invalid)?;
    let (start, end) = range.split_once('-').ok_or_else(invalid)?;
    let start = start.parse::<u64>().map_err(|_| invalid())?;
    let end = end.parse::<u64>().map_err(|_| invalid())?;
    let declared_total = declared_total.parse::<u64>().map_err(|_| invalid())?;
    if unit != "bytes"
        || start != offset
        || end != total.checked_sub(1).ok_or_else(invalid)?
        || declared_total != total
    {
        return Err(invalid());
    }
    Ok(())
}

fn write_download_body<R: Read>(
    reader: &mut R,
    file: &mut File,
    mut written: u64,
    total: u64,
    resumed_from: u64,
    progress: &mut dyn FnMut(u64, u64, u64) -> AppResult<()>,
) -> AppResult<u64> {
    let mut buffer = [0_u8; DOWNLOAD_CHUNK_BYTES];
    loop {
        let read = reader.read(&mut buffer).map_err(|error| {
            AppError::Runtime(format!(
                "managed runtime image download was interrupted: {error}"
            ))
        })?;
        if read == 0 {
            break;
        }
        written = written
            .checked_add(read as u64)
            .ok_or_else(|| AppError::Runtime("managed runtime image size overflowed".into()))?;
        if written > total || written > MAX_MACHINE_IMAGE_BYTES {
            return Err(AppError::NotAuthorized(
                "managed runtime image exceeded its locked size".into(),
            ));
        }
        file.write_all(&buffer[..read])?;
        if let Err(error) = progress(written, total, resumed_from) {
            // Cancellation and observer failures retain a durable prefix; the
            // next setup sends Range from this exact regular-file length.
            file.flush()?;
            file.sync_all()?;
            return Err(error);
        }
    }
    file.flush()?;
    file.sync_all()?;
    Ok(written)
}

pub struct ManagedRuntimeManager {
    state_root: PathBuf,
    /// Keeps the verified state-root object and its canonical ancestor chain
    /// open without delete sharing for the manager lifetime. The retained
    /// ancestor handles let ordinary per-user LocalAppData capability ACLs be
    /// accepted without making any verified namespace component replaceable.
    #[cfg(windows)]
    _state_root_guard: WindowsManagedDirectoryGuard,
    resource_root: PathBuf,
    loaded: LoadedManagedRuntimeManifest,
    commands: Arc<dyn ManagedCommandRunner>,
    wsl_registrations: Arc<dyn WindowsWslRegistrationReader>,
    prerequisite_repairer: Arc<dyn WindowsWslPrerequisiteRepairer>,
    downloader: Arc<dyn ManagedArtifactDownloader>,
}

/// Result of admitting the packaged runtime into the trusted execution path.
/// Rejections intentionally carry no filesystem path, parser error, or
/// attacker-controlled bytes; callers expose only the stable typed reason.
#[cfg(any(feature = "desktop", test))]
pub(crate) enum PackagedManagedRuntimeAdmission {
    Verified(Box<ManagedRuntimeManager>),
    /// The packaged resource tree was missing or rejected, but the desktop
    /// build's independently embedded manifest digest selected one exact,
    /// fully verified private copy. This keeps the manager available without
    /// treating the damaged packaged bytes as a repair source.
    RecoveredFromPrivateCache {
        manager: Box<ManagedRuntimeManager>,
        packaged_failure_reason: ManagedRuntimeSetupFailureReason,
    },
    Missing,
    VerificationFailed,
    /// The running binary has no compiled recovery anchor and no packaged
    /// resource tree. This is an unpackaged developer build, not a damaged
    /// installation.
    UnpackagedDeveloperBuild,
    /// The running binary has no compiled recovery anchor. A managed-runtime
    /// resource tree was present but could not be opened. This is an unpackaged
    /// developer build with a supplied bundle that failed verification, not a
    /// damaged installation.
    UnpackagedDeveloperBuildVerificationFailed,
}

#[cfg(any(feature = "desktop", test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PackagedManagedRuntimeRecoveryReceipt<'a> {
    pub(crate) boundary: &'static str,
    pub(crate) source: &'static str,
    pub(crate) manifest_sha256: &'a str,
    pub(crate) packaged_failure_reason: ManagedRuntimeSetupFailureReason,
}

#[cfg(any(feature = "desktop", test))]
impl PackagedManagedRuntimeAdmission {
    pub(crate) fn failure_reason(&self) -> Option<ManagedRuntimeSetupFailureReason> {
        match self {
            Self::Verified(_) | Self::RecoveredFromPrivateCache { .. } => None,
            Self::Missing => Some(ManagedRuntimeSetupFailureReason::PackagedRuntimeMissing),
            Self::VerificationFailed => {
                Some(ManagedRuntimeSetupFailureReason::PackagedRuntimeVerificationFailed)
            }
            Self::UnpackagedDeveloperBuild => {
                Some(ManagedRuntimeSetupFailureReason::DeveloperBuildWithoutPackagedRuntime)
            }
            Self::UnpackagedDeveloperBuildVerificationFailed => Some(
                ManagedRuntimeSetupFailureReason::DeveloperBuildPackagedRuntimeVerificationFailed,
            ),
        }
    }

    pub(crate) fn recovery_receipt(&self) -> Option<PackagedManagedRuntimeRecoveryReceipt<'_>> {
        match self {
            Self::RecoveredFromPrivateCache {
                manager,
                packaged_failure_reason,
            } => Some(PackagedManagedRuntimeRecoveryReceipt {
                boundary: "packaged_component_auto_recovery",
                source: "private_installed_copy",
                manifest_sha256: manager.manifest_sha256(),
                packaged_failure_reason: *packaged_failure_reason,
            }),
            Self::Verified(_)
            | Self::Missing
            | Self::VerificationFailed
            | Self::UnpackagedDeveloperBuild
            | Self::UnpackagedDeveloperBuildVerificationFailed => None,
        }
    }
}

/// Admits only the exact packaged manifest and payload accepted by
/// [`ManagedRuntimeManager::open`]. Missing and rejected bundles remain data,
/// never commands, and collapse to redacted stable outcomes for the desktop.
#[cfg(any(feature = "desktop", test))]
pub(crate) fn admit_packaged_managed_runtime(
    app_local_data_directory: &Path,
    resource_root: &Path,
) -> PackagedManagedRuntimeAdmission {
    admit_packaged_managed_runtime_with_recovery_digest(
        app_local_data_directory,
        resource_root,
        packaged_managed_runtime_manifest_digest_anchor(),
    )
}

/// The recovery selector is compiled into the already-running desktop binary
/// from the staged release manifest. An empty or malformed value disables the
/// fallback; it is never replaced with data from the rejected resource tree,
/// registry, case database, or a directory scan.
#[cfg(any(feature = "desktop", test))]
fn packaged_managed_runtime_manifest_digest_anchor() -> Option<&'static str> {
    let digest = option_env!("AI_SECURITY_SCANNER_MANAGED_RUNTIME_MANIFEST_SHA256")?;
    validate_sha256(digest, "packaged managed runtime manifest digest anchor")
        .ok()
        .map(|()| digest)
}

#[cfg(any(feature = "desktop", test))]
fn admit_packaged_managed_runtime_with_recovery_digest(
    app_local_data_directory: &Path,
    resource_root: &Path,
    expected_manifest_sha256: Option<&str>,
) -> PackagedManagedRuntimeAdmission {
    let manifest_path = resource_root.join("manifest.json");
    let rejected = match manifest_path.try_exists() {
        Ok(false) => PackagedManagedRuntimeAdmission::Missing,
        Ok(true) => match ManagedRuntimeManager::open(
            app_local_data_directory,
            resource_root,
            &manifest_path,
        ) {
            Ok(manager) => return PackagedManagedRuntimeAdmission::Verified(Box::new(manager)),
            Err(_) => PackagedManagedRuntimeAdmission::VerificationFailed,
        },
        Err(_) => PackagedManagedRuntimeAdmission::VerificationFailed,
    };

    let expected_manifest_sha256 = expected_manifest_sha256.filter(|digest| {
        validate_sha256(digest, "packaged managed runtime manifest digest anchor").is_ok()
    });
    let Some(expected_manifest_sha256) = expected_manifest_sha256 else {
        return match rejected {
            PackagedManagedRuntimeAdmission::Missing => {
                PackagedManagedRuntimeAdmission::UnpackagedDeveloperBuild
            }
            PackagedManagedRuntimeAdmission::VerificationFailed => {
                PackagedManagedRuntimeAdmission::UnpackagedDeveloperBuildVerificationFailed
            }
            other => other,
        };
    };
    let packaged_failure_reason = rejected
        .failure_reason()
        .expect("rejected packaged runtime has a stable typed failure reason");
    match ManagedRuntimeManager::open_exact_private_recovery_cache(
        app_local_data_directory,
        expected_manifest_sha256,
    ) {
        Ok(manager) => PackagedManagedRuntimeAdmission::RecoveredFromPrivateCache {
            manager: Box::new(manager),
            packaged_failure_reason,
        },
        Err(_) => rejected,
    }
}

impl std::fmt::Debug for ManagedRuntimeManager {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ManagedRuntimeManager")
            .field("state_root", &self.state_root)
            .field("resource_root", &self.resource_root)
            .field("manifest_sha256", &self.loaded.sha256)
            .finish_non_exhaustive()
    }
}

impl ManagedRuntimeManager {
    pub fn open(
        app_local_data_directory: &Path,
        resource_root: &Path,
        manifest_path: &Path,
    ) -> AppResult<Self> {
        let state_root = app_local_data_directory.join("managed-runtime");
        #[cfg(windows)]
        let product_data_guard = ensure_private_product_data_directory(app_local_data_directory)?;
        #[cfg(not(windows))]
        ensure_private_product_data_directory(app_local_data_directory)?;
        #[cfg(windows)]
        let (state_root, state_root_guard) =
            open_or_create_windows_managed_private_directory_guard(&state_root, true)
                .map_err(windows_managed_namespace_error)?;
        #[cfg(not(windows))]
        ensure_managed_private_directory(&state_root)?;
        // The Windows state-root guard now pins the same complete ancestor
        // chain. Non-Windows platforms need no long-lived creation guard.
        #[cfg(windows)]
        drop(product_data_guard);
        let resource_root = canonical_real_directory(resource_root, "managed runtime resource")?;
        verify_regular_file(manifest_path, "managed runtime release manifest")?;
        let canonical_manifest = manifest_path.canonicalize()?;
        if canonical_manifest != resource_root.join("manifest.json") {
            return Err(AppError::NotAuthorized(
                "managed runtime manifest must be the release bundle's canonical manifest.json"
                    .into(),
            ));
        }
        let loaded = LoadedManagedRuntimeManifest::read(&canonical_manifest)?;
        validate_current_release_manifest(&loaded.manifest)?;
        let downloader = Arc::new(HttpsManagedArtifactDownloader::new()?);
        let manager = Self {
            state_root,
            #[cfg(windows)]
            _state_root_guard: state_root_guard,
            resource_root,
            loaded,
            commands: Arc::new(DirectManagedCommandRunner),
            wsl_registrations: Arc::new(DirectWindowsWslRegistrationReader),
            prerequisite_repairer: Arc::new(DirectWindowsWslPrerequisiteRepairer),
            downloader,
        };
        manager.verify_resource_bundle()?;
        Ok(manager)
    }

    /// Reconstructs a trusted command context using only a complete, previously
    /// installed private payload. This is used by the standalone CLI, which has
    /// no Tauri resource-directory API. Ambiguous installations fail closed
    /// unless the durable caller supplies the exact manifest SHA-256.
    pub fn open_installed(
        app_local_data_directory: &Path,
        expected_manifest_sha256: Option<&str>,
    ) -> AppResult<Self> {
        Self::open_installed_with_sibling_policy(
            app_local_data_directory,
            expected_manifest_sha256,
            false,
        )
    }

    /// Opens one exact verified installation for product uninstall while
    /// treating unrelated malformed siblings as preserved ambiguity. A broken
    /// or symlinked sibling must not prevent a separately verified runtime from
    /// receiving its bounded stop, and is never traversed or deleted here.
    pub fn open_installed_for_product_uninstall(
        app_local_data_directory: &Path,
        expected_manifest_sha256: &str,
    ) -> AppResult<Self> {
        Self::open_installed_with_sibling_policy(
            app_local_data_directory,
            Some(expected_manifest_sha256),
            true,
        )
    }

    /// Reopens only the private copy selected by the desktop build's exact
    /// manifest digest. Malformed or unrelated siblings are preserved and
    /// ignored, while the selected copy must satisfy the current management
    /// contract plus every ordinary private-tree, manifest, size, and file
    /// digest check before any command can be constructed from it.
    #[cfg(any(feature = "desktop", test))]
    fn open_exact_private_recovery_cache(
        app_local_data_directory: &Path,
        expected_manifest_sha256: &str,
    ) -> AppResult<Self> {
        let manager = Self::open_installed_with_sibling_policy(
            app_local_data_directory,
            Some(expected_manifest_sha256),
            true,
        )?;
        validate_current_release_manifest(manager.manifest())?;
        manager.loaded.target()?;
        Ok(manager)
    }

    fn open_installed_with_sibling_policy(
        app_local_data_directory: &Path,
        expected_manifest_sha256: Option<&str>,
        preserve_ambiguous_siblings: bool,
    ) -> AppResult<Self> {
        if let Some(expected) = expected_manifest_sha256 {
            validate_sha256(expected, "managed runtime expected manifest digest")?;
        }
        let state_root = app_local_data_directory.join("managed-runtime");
        #[cfg(windows)]
        let (state_root, state_root_guard) =
            open_or_create_windows_managed_private_directory_guard(&state_root, true)
                .map_err(windows_managed_namespace_error)?;
        #[cfg(not(windows))]
        ensure_managed_private_directory(&state_root)?;
        let versions_root =
            canonical_real_directory(&state_root.join("versions"), "managed runtime versions")?;
        let mut entries = fs::read_dir(&versions_root)?.collect::<Result<Vec<_>, _>>()?;
        entries.sort_by_key(|entry| entry.file_name());
        let mut candidates = Vec::new();
        let mut retained_entry_count = 0_usize;
        for entry in entries {
            let is_install_staging = is_managed_runtime_install_staging_name(&entry.file_name());
            if !is_install_staging {
                retained_entry_count += 1;
                if retained_entry_count > MAX_INSTALLED_VERSIONS {
                    return Err(AppError::NotAuthorized(format!(
                        "managed runtime has more than {MAX_INSTALLED_VERSIONS} installed payloads"
                    )));
                }
            }
            let path = entry.path();
            let metadata = match fs::symlink_metadata(&path) {
                Ok(metadata) => metadata,
                Err(_) if preserve_ambiguous_siblings => continue,
                Err(error) => return Err(error.into()),
            };
            if metadata.file_type().is_symlink() {
                if preserve_ambiguous_siblings {
                    continue;
                }
                return Err(AppError::NotAuthorized(
                    "managed runtime versions directory contains a symlink".into(),
                ));
            }
            if !metadata.is_dir() {
                continue;
            }
            if is_install_staging {
                continue;
            }
            let manifest_path = path.join("manifest.json");
            if !manifest_path.exists() {
                if preserve_ambiguous_siblings {
                    continue;
                }
                return Err(AppError::NotAuthorized(
                    "managed runtime installation has no release manifest".into(),
                ));
            }
            let loaded = match LoadedManagedRuntimeManifest::read(&manifest_path) {
                Ok(loaded) => loaded,
                Err(_) if preserve_ambiguous_siblings => continue,
                Err(error) => return Err(error),
            };
            if expected_manifest_sha256.is_some_and(|expected| expected != loaded.sha256()) {
                continue;
            }
            let expected_name = installation_directory_name(&loaded);
            if entry.file_name() != OsStr::new(&expected_name) {
                if preserve_ambiguous_siblings {
                    continue;
                }
                return Err(AppError::NotAuthorized(
                    "managed runtime installation directory does not match its manifest identity"
                        .into(),
                ));
            }
            candidates.push((path, loaded));
        }
        if candidates.len() != 1 {
            return Err(AppError::NotAvailable(match expected_manifest_sha256 {
                Some(_) => {
                    "the exact managed runtime installation was not found in private state".into()
                }
                None => "managed runtime installation is absent or ambiguous; an exact manifest digest is required"
                    .into(),
            }));
        }
        let (resource_root, loaded) = candidates.pop().expect("one candidate");
        let downloader = Arc::new(HttpsManagedArtifactDownloader::new()?);
        let manager = Self {
            state_root,
            #[cfg(windows)]
            _state_root_guard: state_root_guard,
            resource_root: canonical_real_directory(
                &resource_root,
                "managed runtime installed resource",
            )?,
            loaded,
            commands: Arc::new(DirectManagedCommandRunner),
            wsl_registrations: Arc::new(DirectWindowsWslRegistrationReader),
            prerequisite_repairer: Arc::new(DirectWindowsWslPrerequisiteRepairer),
            downloader,
        };
        manager.verify_installation()?;
        Ok(manager)
    }

    #[cfg(test)]
    fn with_backends(
        state_root: PathBuf,
        resource_root: PathBuf,
        loaded: LoadedManagedRuntimeManifest,
        commands: Arc<dyn ManagedCommandRunner>,
        downloader: Arc<dyn ManagedArtifactDownloader>,
    ) -> AppResult<Self> {
        #[cfg(windows)]
        let (state_root, state_root_guard) =
            open_or_create_windows_managed_private_directory_guard(&state_root, true)
                .map_err(windows_managed_namespace_error)?;
        #[cfg(not(windows))]
        ensure_managed_private_directory(&state_root)?;
        let resource_root = canonical_real_directory(&resource_root, "managed runtime resource")?;
        let manager = Self {
            state_root,
            #[cfg(windows)]
            _state_root_guard: state_root_guard,
            resource_root,
            loaded,
            commands,
            wsl_registrations: Arc::new(DirectWindowsWslRegistrationReader),
            prerequisite_repairer: Arc::new(DirectWindowsWslPrerequisiteRepairer),
            downloader,
        };
        manager.verify_resource_bundle()?;
        Ok(manager)
    }

    pub fn manifest(&self) -> &ManagedRuntimeManifest {
        self.loaded.manifest()
    }

    pub fn manifest_sha256(&self) -> &str {
        self.loaded.sha256()
    }

    pub fn install(&self) -> AppResult<ManagedRuntimeStatus> {
        let _lock = self.lock()?;
        self.install_locked()?;
        let target = self.loaded.target()?;
        Ok(self.status_value(
            ManagedRuntimePhase::Installed,
            false,
            Some(target),
            "managed runtime payload is installed and verified; start initializes its rootless machine"
                .into(),
        ))
    }

    /// Installs the release payload, acquires the exact VM image, initializes
    /// the rootless machine if necessary, and waits for a live server preflight.
    pub fn start(&self) -> AppResult<ManagedRuntimeCommand> {
        let _lock = self.lock()?;
        self.start_locked(None)
    }

    /// Runs the same lifecycle as [`Self::start`] while publishing a
    /// queryable, cancellable first-run setup state. Only one setup may be
    /// active for a controller at a time. Ordinary on-demand starts remain
    /// backward-compatible and do not overwrite setup history.
    pub fn setup(
        &self,
        controller: &ManagedRuntimeSetupController,
    ) -> AppResult<ManagedRuntimeStatus> {
        self.setup_with_attempt(controller, || self.run_setup_attempt(controller))
    }

    fn run_setup_attempt(
        &self,
        controller: &ManagedRuntimeSetupController,
    ) -> AppResult<ManagedRuntimeStatus> {
        let _lock = self.lock()?;
        let (_command, version) = self.start_locked_with_startup_timeout_and_version(
            Some(controller),
            MACHINE_START_TIMEOUT,
        )?;
        let target = self.loaded.target()?;
        Ok(self.status_value(
            ManagedRuntimePhase::Running,
            true,
            Some(target),
            format!("managed rootless Podman {version} is available"),
        ))
    }

    fn setup_with_attempt<F>(
        &self,
        controller: &ManagedRuntimeSetupController,
        mut attempt: F,
    ) -> AppResult<ManagedRuntimeStatus>
    where
        F: FnMut() -> AppResult<ManagedRuntimeStatus>,
    {
        let mut attempted_prerequisite_repairs = Vec::new();
        let operation_id = controller.begin()?;
        let mut worker_guard =
            ManagedRuntimeSetupWorkerGuard::new(controller, operation_id.clone());
        loop {
            match attempt() {
                Ok(status) => {
                    controller.finish_completed(
                        &operation_id,
                        format!(
                            "managed rootless runtime {} is running and verified",
                            status.runtime_version
                        ),
                    )?;
                    worker_guard.disarm();
                    return Ok(status);
                }
                Err(_error) if controller.cancel_requested.load(Ordering::Acquire) => {
                    controller.finish_cancelled(&operation_id)?;
                    worker_guard.disarm();
                    return Err(setup_cancelled_error());
                }
                Err(error) => {
                    // Keep the original operation active while atomically
                    // reserving an eligible automatic Windows repair. A user
                    // retry cannot replace this worker between the typed
                    // failure and its repair decision.
                    let automatic_repair = self.run_automatic_windows_wsl_prerequisite_repair(
                        controller,
                        &operation_id,
                        &attempted_prerequisite_repairs,
                    );
                    let Some((action, repair)) = (match automatic_repair {
                        Ok(repair) => repair,
                        Err(_repair_error)
                            if controller.cancel_requested.load(Ordering::Acquire) =>
                        {
                            controller.finish_cancelled(&operation_id)?;
                            worker_guard.disarm();
                            return Err(setup_cancelled_error());
                        }
                        Err(repair_error) => {
                            controller.finish_failed(&operation_id, repair_error.to_string())?;
                            worker_guard.disarm();
                            return Err(repair_error);
                        }
                    }) else {
                        controller.finish_failed(&operation_id, error.to_string())?;
                        worker_guard.disarm();
                        return Err(error);
                    };
                    attempted_prerequisite_repairs.push(action);

                    if repair.restart_required
                        || repair.outcome != ManagedRuntimePrerequisiteRepairOutcome::Completed
                    {
                        // The runtime-dependent task degrades to a retryable
                        // failure. The workspace, saved projects, reports, and
                        // independent tasks remain available because no
                        // lifecycle lock is held while Windows services WSL.
                        controller.finish_failed(&operation_id, repair.detail.clone())?;
                        worker_guard.disarm();
                        return Err(AppError::NotAvailable(repair.detail));
                    }
                    if controller.cancel_requested.load(Ordering::Acquire) {
                        controller.finish_cancelled(&operation_id)?;
                        worker_guard.disarm();
                        return Err(setup_cancelled_error());
                    }

                    // A successful Windows change is reconciled through the
                    // normal read-only checks under the same operation
                    // identity. Never assume the requested feature or update
                    // became usable merely from its exit code.
                    controller.continue_after_prerequisite_repair(&operation_id)?;
                }
            }
        }
    }

    fn run_automatic_windows_wsl_prerequisite_repair(
        &self,
        controller: &ManagedRuntimeSetupController,
        operation_id: &str,
        attempted_actions: &[ManagedRuntimeSetupNextAction],
    ) -> AppResult<
        Option<(
            ManagedRuntimeSetupNextAction,
            ManagedRuntimePrerequisiteRepairResult,
        )>,
    > {
        let Some(action) =
            controller.begin_automatic_prerequisite_repair(operation_id, attempted_actions)?
        else {
            return Ok(None);
        };
        let repair = self
            .prerequisite_repairer
            .repair(action)
            .unwrap_or_else(|_error| ManagedRuntimePrerequisiteRepairResult {
                outcome: ManagedRuntimePrerequisiteRepairOutcome::Failed,
                restart_required: false,
                detail: "Automatic Windows setup stopped. Try automatic preparation again.".into(),
            });
        controller.finish_prerequisite_repair(operation_id, Some(&repair));
        Ok(Some((action, repair)))
    }

    fn start_locked(
        &self,
        setup: Option<&ManagedRuntimeSetupController>,
    ) -> AppResult<ManagedRuntimeCommand> {
        self.start_locked_with_startup_timeout(setup, MACHINE_START_TIMEOUT)
    }

    fn start_locked_with_startup_timeout(
        &self,
        setup: Option<&ManagedRuntimeSetupController>,
        startup_timeout: Duration,
    ) -> AppResult<ManagedRuntimeCommand> {
        self.start_locked_with_startup_timeout_and_version(setup, startup_timeout)
            .map(|(command, _version)| command)
    }

    fn start_locked_with_startup_timeout_and_version(
        &self,
        setup: Option<&ManagedRuntimeSetupController>,
        startup_timeout: Duration,
    ) -> AppResult<(ManagedRuntimeCommand, String)> {
        if let Some(setup) = setup {
            setup.set_phase(
                ManagedRuntimeSetupPhase::Install,
                "installing and verifying the release-managed runtime payload",
            )?;
        }
        let target = self.loaded.target()?;
        self.install_locked()?;
        let mut command;
        if target.operating_system == ManagedOperatingSystem::Windows {
            let read_only_command = self.windows_wsl_read_only_command(target)?;
            if let Some(setup) = setup {
                setup.set_phase(
                    ManagedRuntimeSetupPhase::Prerequisite,
                    "checking whether Windows has WSL 2 ready for the isolated scanner",
                )?;
            }
            self.require_windows_wsl_prerequisite_locked(target, &read_only_command, setup)?;
            let selected = self.resolve_windows_machine_generation_locked(
                target,
                &read_only_command,
                &[],
                false,
            )?;
            if !self.has_exact_windows_wsl_ownership_proof_locked(
                target,
                &selected,
                WindowsWslOwnershipBasis::ProvenMachine,
            )? {
                // The durable generation identity is chosen before its mutable
                // provider home exists. This exact one-shot proof lets a
                // relaunch reuse an empty/in-progress product-owned home while
                // unknown homes without it remain preserved collisions.
                self.ensure_windows_wsl_ownership_proof_locked(
                    target,
                    &selected,
                    WindowsWslOwnershipBasis::InitIntent,
                )?;
            }
            command = self.runtime_command(target)?;
        } else {
            command = self.runtime_command(target)?;
        }
        if let Some(setup) = setup {
            setup.set_phase(
                ManagedRuntimeSetupPhase::Download,
                "preparing the exact release-locked managed runtime image download",
            )?;
        }
        let image = self.acquire_machine_image_locked(target, setup)?;
        if let Some(setup) = setup {
            setup.set_phase(
                ManagedRuntimeSetupPhase::Init,
                "initializing the private rootless managed runtime machine",
            )?;
        }
        let initial_machines = self.list_machines(&command)?;
        let mut machine_name = self.resolve_windows_machine_generation_locked(
            target,
            &command,
            &initial_machines,
            true,
        )?;
        let machines = if target.operating_system == ManagedOperatingSystem::Windows {
            // A collision may have selected a generation-specific provider
            // home. Rebuild the command only after that durable choice so no
            // file in the ambiguous provider namespace is rewritten or reused.
            command = self.runtime_command(target)?;
            self.list_machines(&command)?
        } else {
            initial_machines
        };
        if let Some(machine) = machines.iter().find(|machine| machine.name == machine_name) {
            if target.operating_system == ManagedOperatingSystem::Windows {
                self.prove_machine_named(machine, target, &machine_name)?;
                self.verify_current_windows_wsl_machine_registration_binding(&machine_name)?;
                match self.require_existing_machine_ssh_identity_locked() {
                    Ok(()) => {}
                    Err(identity_error @ AppError::NotAuthorized(_)) => {
                        // A positively invalid immutable identity must never be
                        // rotated in place because the selected workspace may
                        // still trust its original key. Preserve the complete
                        // generation and continue once in a fresh isolated
                        // provider home instead.
                        return self.rebuild_unhealthy_windows_machine_once_locked(
                            &command,
                            target,
                            &machine_name,
                            identity_error,
                            setup,
                            startup_timeout,
                        );
                    }
                    Err(error) => return Err(error),
                }
                self.ensure_windows_wsl_ownership_proof_locked(
                    target,
                    &machine_name,
                    WindowsWslOwnershipBasis::ProvenMachine,
                )?;
                // ProvenMachine is the stronger, durable proof. A stale or
                // unreadable one-shot InitIntent must not make an otherwise
                // exact existing generation unavailable; preserve it here and
                // leave destructive cleanup to the fully verified uninstall
                // path.
            } else {
                self.require_existing_machine_ssh_identity_locked()?;
                self.prove_machine_named(machine, target, &machine_name)?;
            }
        } else {
            self.remove_windows_wsl_ownership_proof_locked(target, &machine_name)?;
            self.prepare_machine_ssh_identity_locked()?;
            let initialized = self.initialize_machine_with_one_bounded_windows_retry(
                &command,
                target,
                &image,
                &machine_name,
                setup,
            )?;
            command = initialized.0;
            machine_name = initialized.1;
        }
        if let Some(setup) = setup {
            setup.check_cancelled()?;
        }

        let machines = self.list_machines(&command)?;
        let machine = machines
            .iter()
            .find(|machine| machine.name == machine_name)
            .ok_or_else(|| {
                AppError::Runtime(
                    "managed runtime did not report the machine after initialization".into(),
                )
            })?;
        self.prove_machine_named(machine, target, &machine_name)?;
        if target.operating_system == ManagedOperatingSystem::Windows {
            self.verify_current_windows_wsl_machine_registration_binding(&machine_name)?;
            self.ensure_windows_wsl_ownership_proof_locked(
                target,
                &machine_name,
                WindowsWslOwnershipBasis::ProvenMachine,
            )?;
        }
        match self.start_machine_and_wait_locked(
            &command,
            &machine_name,
            machine.running,
            setup,
            startup_timeout,
        ) {
            Ok(version) => Ok((command, version)),
            Err(MachineStartAttemptFailure::Lifecycle(error)) => Err(error),
            Err(MachineStartAttemptFailure::MachineStart(error)) => {
                Err(retryable_machine_start_error(error))
            }
            Err(MachineStartAttemptFailure::ServerReadiness(error)) => {
                Err(retryable_server_readiness_error(error))
            }
        }
    }

    fn start_machine_and_wait_locked(
        &self,
        command: &ManagedRuntimeCommand,
        machine_name: &str,
        machine_running: bool,
        setup: Option<&ManagedRuntimeSetupController>,
        startup_timeout: Duration,
    ) -> Result<String, MachineStartAttemptFailure> {
        let deadline = Instant::now().checked_add(startup_timeout).ok_or_else(|| {
            MachineStartAttemptFailure::Lifecycle(AppError::Runtime(
                "managed runtime startup deadline overflowed".into(),
            ))
        })?;
        if let Some(setup) = setup {
            setup
                .set_phase(
                    ManagedRuntimeSetupPhase::Start,
                    "starting the private rootless managed runtime machine",
                )
                .map_err(MachineStartAttemptFailure::Lifecycle)?;
        }
        if !machine_running {
            let target = self
                .loaded
                .target()
                .map_err(MachineStartAttemptFailure::MachineStart)?;
            let can_reconcile_in_place = target.operating_system == ManagedOperatingSystem::Windows
                && target.provider == ManagedMachineProvider::Wsl;
            let mut first_start_error = None;
            for start_attempt in 1..=2 {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Err(MachineStartAttemptFailure::MachineStart(
                        AppError::Runtime(
                            "managed runtime machine start did not begin before the shared startup deadline"
                                .into(),
                        ),
                    ));
                }
                let start_result = self
                    .run_command(
                        ManagedCommandOperation::MachineStart,
                        command,
                        ["machine", "start", "--quiet", machine_name],
                        remaining.min(MACHINE_START_TIMEOUT),
                    )
                    .and_then(|output| require_success("managed runtime machine start", &output));
                let Err(start_error) = start_result else {
                    break;
                };
                let first_detail = first_start_error
                    .get_or_insert_with(|| start_error.to_string())
                    .clone();
                if !can_reconcile_in_place {
                    return Err(MachineStartAttemptFailure::MachineStart(start_error));
                }
                if let Some(setup) = setup {
                    setup
                        .check_cancelled()
                        .map_err(MachineStartAttemptFailure::Lifecycle)?;
                }
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Err(MachineStartAttemptFailure::MachineStart(AppError::Runtime(
                        format!(
                            "managed runtime machine start failed and exhausted the shared startup deadline before authoritative reconciliation: {first_detail}"
                        ),
                    )));
                }
                let machines = self
                    .list_machines_with_timeout(command, remaining.min(COMMAND_TIMEOUT))
                    .map_err(|reconciliation_error| {
                        MachineStartAttemptFailure::MachineStart(AppError::Runtime(format!(
                            "managed runtime machine start failed and its exact selected machine could not be reconciled: {first_detail}; reconciliation: {reconciliation_error}"
                        )))
                    })?;
                let machine = machines
                    .iter()
                    .find(|machine| machine.name.eq_ignore_ascii_case(machine_name))
                    .ok_or_else(|| {
                        MachineStartAttemptFailure::MachineStart(AppError::Runtime(format!(
                            "managed runtime machine start failed and authoritative inventory did not report the exact selected machine: {first_detail}"
                        )))
                    })?;
                self.prove_machine_named(machine, target, machine_name)
                    .and_then(|_| {
                        self.prove_current_windows_machine_ownership_locked(target, machine_name)
                    })
                    .map_err(|reconciliation_error| {
                        MachineStartAttemptFailure::MachineStart(AppError::Runtime(format!(
                            "managed runtime machine start failed and the exact selected machine could not be re-proven: {first_detail}; reconciliation: {reconciliation_error}"
                        )))
                    })?;
                if machine.running {
                    break;
                }
                if start_attempt == 2 {
                    return Err(MachineStartAttemptFailure::MachineStart(AppError::Runtime(
                        format!(
                            "managed runtime machine start failed twice while the exact selected machine remained stopped: {first_detail}; retry: {start_error}"
                        ),
                    )));
                }
            }
        }
        if let Some(setup) = setup {
            setup
                .set_phase(
                    ManagedRuntimeSetupPhase::Verify,
                    "verifying the managed runtime server is ready",
                )
                .map_err(MachineStartAttemptFailure::Lifecycle)?;
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(MachineStartAttemptFailure::ServerReadiness(
                AppError::Runtime(
                    "managed runtime machine start consumed the shared startup budget before server readiness could be verified"
                        .into(),
                ),
            ));
        }
        self.wait_for_server(command, remaining, setup)
            .map_err(MachineStartAttemptFailure::ServerReadiness)
    }

    /// A selected Windows machine can still become unusable when its immutable
    /// SSH identity is positively proven missing or inconsistent. Preserve that
    /// complete generation exactly as it stands, append one fresh isolated
    /// generation, and try the replacement once. Machine-start and
    /// server-readiness failures never enter this path: neither proves the
    /// machine is corrupt, so both preserve and retry the exact owned
    /// generation. This path never unregisters, exports, imports, or deletes WSL
    /// state, and it does not recurse if the replacement is also unhealthy.
    fn rebuild_unhealthy_windows_machine_once_locked(
        &self,
        failed_command: &ManagedRuntimeCommand,
        target: &ManagedTarget,
        failed_machine_name: &str,
        first_error: AppError,
        setup: Option<&ManagedRuntimeSetupController>,
        startup_timeout: Duration,
    ) -> AppResult<(ManagedRuntimeCommand, String)> {
        if target.operating_system != ManagedOperatingSystem::Windows {
            return Err(first_error);
        }
        if let Some(setup) = setup {
            setup.check_cancelled()?;
            setup.set_phase(
                ManagedRuntimeSetupPhase::Recovery,
                "preserving an unavailable scan workspace and preparing a fresh isolated one",
            )?;
        }
        let first_detail = first_error.to_string();
        let replacement = (|| -> AppResult<(ManagedRuntimeCommand, String)> {
            let mut distributions = self.windows_wsl_distribution_inventory(failed_command)?;
            let registration_inventory =
                self.windows_wsl_registration_inventory_with_one_retry()?;
            for name in registration_inventory.observed_distribution_names {
                if !distributions
                    .iter()
                    .any(|observed| observed.eq_ignore_ascii_case(&name))
                {
                    distributions.push(name);
                }
            }
            let machines = self.list_machines(failed_command)?;
            let fresh_machine_name = self
                .select_fresh_windows_machine_generation_after_runtime_failure_locked(
                    target,
                    failed_machine_name,
                    &machines,
                    &distributions,
                )?;
            self.ensure_windows_wsl_ownership_proof_locked(
                target,
                &fresh_machine_name,
                WindowsWslOwnershipBasis::InitIntent,
            )?;
            let fresh_command = self.runtime_command(target)?;
            self.prepare_machine_ssh_identity_locked()?;
            self.initialize_machine_with_one_shot_wsl_intent(
                &fresh_command,
                target,
                &self.machine_image_path(target),
                &fresh_machine_name,
            )
            .map_err(|error| {
                AppError::Runtime(format!(
                    "fresh isolated Windows scan workspace initialization failed: {error}"
                ))
            })?;

            let fresh_machines = self.list_machines(&fresh_command)?;
            let fresh_machine = fresh_machines
                .iter()
                .find(|machine| machine.name == fresh_machine_name)
                .ok_or_else(|| {
                    AppError::Runtime(
                        "managed runtime did not report the fresh isolated Windows machine after initialization"
                            .into(),
                    )
                })?;
            self.prove_machine_named(fresh_machine, target, &fresh_machine_name)?;
            self.verify_current_windows_wsl_machine_registration_binding(&fresh_machine_name)?;
            self.ensure_windows_wsl_ownership_proof_locked(
                target,
                &fresh_machine_name,
                WindowsWslOwnershipBasis::ProvenMachine,
            )?;
            let version = match self.start_machine_and_wait_locked(
                &fresh_command,
                &fresh_machine_name,
                fresh_machine.running,
                setup,
                startup_timeout,
            ) {
                Ok(version) => version,
                Err(MachineStartAttemptFailure::Lifecycle(error)) => return Err(error),
                Err(MachineStartAttemptFailure::MachineStart(error)) => {
                    return Err(retryable_machine_start_error(error));
                }
                Err(MachineStartAttemptFailure::ServerReadiness(error)) => {
                    return Err(retryable_server_readiness_error(error));
                }
            };
            Ok((fresh_command, version))
        })();
        replacement.map_err(|replacement_error| {
            let detail = format!(
                "the selected Windows scan workspace became unavailable and was preserved ({first_detail}); its one automatic isolated replacement also did not finish: {replacement_error}"
            );
            if matches!(replacement_error, AppError::NotAvailable(_)) {
                AppError::NotAvailable(detail)
            } else {
                AppError::Runtime(detail)
            }
        })
    }

    /// Proves the Windows-owned WSL boundary before downloading the release
    /// machine image. This probe is intentionally read-only. The separate,
    /// explicit prerequisite-repair command may request one Windows UAC
    /// approval, then this probe remains the authority on whether setup can
    /// continue.
    fn require_windows_wsl_prerequisite_locked(
        &self,
        target: &ManagedTarget,
        managed_command: &ManagedRuntimeCommand,
        setup: Option<&ManagedRuntimeSetupController>,
    ) -> AppResult<()> {
        if target.operating_system != ManagedOperatingSystem::Windows {
            return Ok(());
        }
        if target.provider != ManagedMachineProvider::Wsl {
            return Err(AppError::NotAuthorized(
                "managed Windows runtime target did not use the WSL provider".into(),
            ));
        }

        let directories = match windows_system_directories() {
            Ok(directories) => directories,
            Err(_) => {
                return fail_windows_wsl_prerequisite(
                    setup,
                    WindowsWslPrerequisiteFailure::command_failed(None),
                );
            }
        };
        let wsl_binary = directories.system32.join("wsl.exe");
        match fs::symlink_metadata(&wsl_binary) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return fail_windows_wsl_prerequisite(
                    setup,
                    WindowsWslPrerequisiteFailure::not_installed(None),
                );
            }
            Err(_) => {
                return fail_windows_wsl_prerequisite(
                    setup,
                    WindowsWslPrerequisiteFailure::command_failed(None),
                );
            }
            Ok(_) => {}
        }
        let command =
            match windows_wsl_inventory_command_with_directories(managed_command, &directories) {
                Ok(command) => command,
                Err(_) => {
                    return fail_windows_wsl_prerequisite(
                        setup,
                        WindowsWslPrerequisiteFailure::command_failed(None),
                    );
                }
            };

        // `--status` catches an unavailable WSL 2 kernel or Windows feature
        // before Podman can begin importing the release image. Pinned Podman
        // 5.8.2's WSL provider then calls `wsl.exe -l --quiet` from
        // `getAllWSLDistros` before machine initialization. Exercise that exact
        // read-only command here so a missing or incomplete WSL installation is
        // classified as a prerequisite failure instead of surfacing later as
        // Podman's generic exit status 125.
        for arguments in [
            &[OsString::from("--status")][..],
            &[OsString::from("-l"), OsString::from("--quiet")][..],
        ] {
            let output = match self.commands.output(&command, arguments, COMMAND_TIMEOUT) {
                Ok(output) => output,
                Err(_) => {
                    return fail_windows_wsl_prerequisite(
                        setup,
                        WindowsWslPrerequisiteFailure::command_failed(None),
                    );
                }
            };
            if !output.status.success() {
                return fail_windows_wsl_prerequisite(
                    setup,
                    classify_windows_wsl_prerequisite_failure(&output),
                );
            }
        }
        Ok(())
    }

    pub fn stop(&self, mode: ManagedStopMode) -> AppResult<ManagedRuntimeStatus> {
        let _lock = self.lock()?;
        if !self.install_directory().exists() {
            return self.status_locked();
        }
        let target = self.loaded.target()?;
        if !self.provider_generation_is_selected_locked(target)? {
            return self.status_locked();
        }
        let command = self.runtime_command(target)?;
        let machine_name = self.effective_machine_name_locked(target)?;
        let machines = self.list_machines(&command)?;
        let Some(machine) = machines.iter().find(|machine| machine.name == machine_name) else {
            return Ok(self.status_value(
                ManagedRuntimePhase::Installed,
                false,
                Some(target),
                "managed runtime payload is verified; its rootless machine has not been initialized"
                    .into(),
            ));
        };
        self.prove_machine_named(machine, target, &machine_name)?;
        self.prove_current_windows_machine_ownership_locked(target, &machine_name)?;
        if machine.running {
            if mode == ManagedStopMode::OnlyIfIdle {
                let containers = self.running_containers(&command)?;
                if !containers.is_empty() {
                    return Err(AppError::InvalidRequest(format!(
                        "managed runtime still has {} running engine container(s); cancel the scan or request an explicit forced stop",
                        containers.len()
                    )));
                }
            }
            let output = self.run_command(
                ManagedCommandOperation::MachineStop,
                &command,
                ["machine", "stop", machine_name.as_str()],
                MACHINE_STOP_TIMEOUT,
            )?;
            require_success("managed runtime machine stop", &output)?;
            self.wait_for_machine_stopped(&command, &machine_name, MACHINE_STOP_TIMEOUT)?;
        }
        Ok(self.status_value(
            ManagedRuntimePhase::Stopped,
            false,
            Some(target),
            "managed runtime machine is stopped".into(),
        ))
    }

    /// Proves target contact stopped for product uninstall without treating a
    /// no-op lifecycle status as success.
    ///
    /// Ordinary `stop` is intentionally tolerant when setup has not selected a
    /// generation. Uninstall has a stricter contract: nonempty unclassified
    /// provider state or an unexpected running private-provider machine means
    /// contact cannot be proven stopped. The exact selected machine is still
    /// stopped first when possible, but the caller receives an error and does
    /// not begin deletion while another running machine remains.
    pub fn stop_for_product_uninstall(&self) -> AppResult<ManagedRuntimeStatus> {
        let _lock = self.lock()?;
        if !self.install_directory().exists() {
            return self.status_locked();
        }
        self.verify_installation()?;
        let target = self.loaded.target()?;
        if !self.provider_generation_is_selected_locked(target)? {
            let provider_root = self.state_root.join("provider-home");
            match fs::symlink_metadata(&provider_root) {
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
                    if fs::read_dir(&provider_root)?.next().transpose()?.is_some() {
                        return Err(AppError::NotAuthorized(
                            "managed runtime has unclassified provider state; target contact cannot be proven stopped"
                                .into(),
                        ));
                    }
                }
                Ok(_) => {
                    return Err(AppError::NotAuthorized(
                        "managed runtime provider state is ambiguous; target contact cannot be proven stopped"
                            .into(),
                    ));
                }
                Err(error) => return Err(error.into()),
            }
            return Ok(self.status_value(
                ManagedRuntimePhase::Stopped,
                false,
                Some(target),
                "no classified managed runtime can contact a target".into(),
            ));
        }

        let command = self.runtime_command(target)?;
        let machine_name = self.effective_machine_name_locked(target)?;
        let machines = self.list_machines(&command)?;
        let unexpected_running = machines
            .iter()
            .any(|machine| machine.name != machine_name && machine.running);
        if let Some(machine) = machines.iter().find(|machine| machine.name == machine_name) {
            self.prove_machine_named(machine, target, &machine_name)?;
            self.prove_current_windows_machine_ownership_locked(target, &machine_name)?;
            if machine.running {
                let output = self.run_command(
                    ManagedCommandOperation::MachineStop,
                    &command,
                    ["machine", "stop", machine_name.as_str()],
                    MACHINE_STOP_TIMEOUT,
                )?;
                require_success("managed runtime machine stop", &output)?;
                self.wait_for_machine_stopped(&command, &machine_name, MACHINE_STOP_TIMEOUT)?;
            }
        }
        if unexpected_running {
            return Err(AppError::NotAuthorized(
                "managed runtime private provider reported another running machine; target contact cannot be proven stopped"
                    .into(),
            ));
        }
        Ok(self.status_value(
            ManagedRuntimePhase::Stopped,
            false,
            Some(target),
            "managed runtime target contact is stopped".into(),
        ))
    }

    pub fn uninstall(&self, options: ManagedUninstallOptions) -> AppResult<ManagedRuntimeStatus> {
        #[cfg(windows)]
        let (provider_delete_timeout, provider_delete_poll) = (
            WINDOWS_WSL_PROVIDER_DELETE_TIMEOUT,
            WINDOWS_WSL_PROVIDER_DELETE_POLL,
        );
        #[cfg(not(windows))]
        let (provider_delete_timeout, provider_delete_poll) = (Duration::ZERO, Duration::ZERO);
        self.uninstall_with_windows_provider_delete_timing(
            options,
            provider_delete_timeout,
            provider_delete_poll,
        )
    }

    fn uninstall_with_windows_provider_delete_timing(
        &self,
        options: ManagedUninstallOptions,
        provider_delete_timeout: Duration,
        provider_delete_poll: Duration,
    ) -> AppResult<ManagedRuntimeStatus> {
        let _lock = self.lock()?;
        let target = self.loaded.target()?;
        let generation_selected = self.provider_generation_is_selected_locked(target)?;
        let machine_name = self.effective_machine_name_locked(target)?;
        let install = self.install_directory();
        let provider_home = self.effective_provider_home_locked(target)?;
        if target.operating_system == ManagedOperatingSystem::Windows && !generation_selected {
            // No routing record means no provider namespace has been classified
            // as this release's current generation. Uninstall the verified app
            // payload while preserving every provider byte for a later bounded
            // reconciliation; never manufacture a command environment merely
            // to decide what may be deleted.
            if private_entry_exists(&install)? {
                remove_private_tree(&install, &self.versions_root())?;
            }
            if options.remove_machine_image_cache {
                let image = self.machine_image_path(target);
                if private_entry_exists(&image)? {
                    remove_private_tree(&image, &self.image_cache_root())?;
                }
            }
            return self.status_locked();
        }
        if private_entry_exists(&install)? || private_entry_exists(&provider_home)? {
            let windows_cleanup_proven = target.operating_system != ManagedOperatingSystem::Windows
                || self.has_exact_windows_wsl_ownership_proof_locked(
                    target,
                    &machine_name,
                    WindowsWslOwnershipBasis::ProvenMachine,
                )?;
            if target.operating_system == ManagedOperatingSystem::Windows && !windows_cleanup_proven
            {
                // A generation selection is a routing journal, not deletion
                // authority. Preserve an interrupted/ambiguous provider home,
                // but still allow the verified application payload to uninstall.
                if private_entry_exists(&install)? {
                    remove_private_tree(&install, &self.versions_root())?;
                }
                if options.remove_machine_image_cache {
                    let image = self.machine_image_path(target);
                    if private_entry_exists(&image)? {
                        remove_private_tree(&image, &self.image_cache_root())?;
                    }
                }
                return self.status_locked();
            }
            // Repair a corrupted release payload from the verified application
            // resources before invoking it for owned-machine cleanup. This also
            // lets a retry safely prove and remove provider state left by an
            // interrupted older uninstall after its client was deleted.
            self.install_locked()?;
            let command = self.runtime_command(target)?;
            let machines = self.list_machines(&command)?;
            if machines.len() > 1 || machines.iter().any(|machine| machine.name != machine_name) {
                return Err(AppError::NotAuthorized(
                    "managed runtime release-private provider reported an unexpected machine; refusing to remove its state"
                        .into(),
                ));
            }
            if let Some(machine) = machines.iter().find(|machine| machine.name == machine_name) {
                self.prove_machine_named(machine, target, &machine_name)?;
                self.prove_current_windows_machine_ownership_locked(target, &machine_name)?;
                if machine.running {
                    if options.stop_mode == ManagedStopMode::OnlyIfIdle
                        && !self.running_containers(&command)?.is_empty()
                    {
                        return Err(AppError::InvalidRequest(
                            "managed runtime has active engine containers; uninstall requires cancellation or an explicit forced stop"
                                .into(),
                        ));
                    }
                    let output = self.run_command(
                        ManagedCommandOperation::MachineStop,
                        &command,
                        ["machine", "stop", machine_name.as_str()],
                        MACHINE_STOP_TIMEOUT,
                    )?;
                    require_success("managed runtime machine stop", &output)?;
                }
                let output = self.run_command(
                    ManagedCommandOperation::MachineRemoval,
                    &command,
                    ["machine", "rm", "--force", machine_name.as_str()],
                    MACHINE_STOP_TIMEOUT,
                )?;
                require_success("managed runtime machine removal", &output)?;
            }
            if target.operating_system == ManagedOperatingSystem::Windows {
                self.require_current_windows_wsl_distribution_absent_for_cleanup_locked(
                    target,
                    &command,
                    &machine_name,
                )?;
            }
            self.remove_temporary_command_state_after_machine_removal_locked(target)?;
            if private_entry_exists(&provider_home)? {
                remove_provider_home_after_machine_removal(
                    &provider_home,
                    &self.state_root.join("provider-home"),
                    provider_delete_timeout,
                    provider_delete_poll,
                )?;
            }
            remove_private_tree(&install, &self.versions_root())?;
            self.remove_windows_wsl_ownership_proof_locked(target, &machine_name)?;
        }
        if options.remove_machine_image_cache {
            let image = self.machine_image_path(target);
            if private_entry_exists(&image)? {
                remove_private_tree(&image, &self.image_cache_root())?;
            }
        }
        self.status_locked()
    }

    /// An application update installs and proves the new release payload first.
    /// Old verified payloads remain on disk as rollback material and are returned
    /// to the caller for an explicit later cleanup operation.
    pub fn update(&self) -> AppResult<ManagedRuntimeUpdateResult> {
        let _command = self.start()?;
        let current = self.install_directory();
        let mut superseded = Vec::new();
        if let Ok(entries) = fs::read_dir(self.versions_root()) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path != current && path.is_dir() {
                    superseded.push(entry.file_name().to_string_lossy().into_owned());
                }
            }
        }
        superseded.sort();
        Ok(ManagedRuntimeUpdateResult {
            status: self.status()?,
            superseded_installations: superseded,
        })
    }

    pub fn status(&self) -> AppResult<ManagedRuntimeStatus> {
        ensure_managed_private_directory(&self.state_root)?;
        let Some(_lock) = ManagedRuntimeLock::try_acquire(&self.state_root.join("lifecycle.lock"))?
        else {
            let target = self.loaded.target().ok();
            return Ok(self.status_value(
                ManagedRuntimePhase::Starting,
                false,
                target,
                "a managed runtime lifecycle operation is active; status will reconcile after it completes"
                    .into(),
            ));
        };
        self.status_locked()
    }

    pub fn runtime_command_if_running(&self) -> AppResult<Option<ManagedRuntimeCommand>> {
        let _lock = self.lock()?;
        if !self.verify_installation().is_ok() {
            return Ok(None);
        }
        let target = self.loaded.target()?;
        if !self.provider_generation_is_selected_locked(target)? {
            return Ok(None);
        }
        let command = self.runtime_command(target)?;
        let machine_name = self.effective_machine_name_locked(target)?;
        let machines = self.list_machines(&command)?;
        let Some(machine) = machines.iter().find(|machine| machine.name == machine_name) else {
            return Ok(None);
        };
        self.prove_machine_named(machine, target, &machine_name)?;
        if self
            .prove_current_windows_machine_ownership_locked(target, &machine_name)
            .is_err()
        {
            return Ok(None);
        }
        if !machine.running
            || self
                .server_version_with_timeout(&command, SERVER_READINESS_PROBE_TIMEOUT)
                .is_err()
        {
            return Ok(None);
        }
        Ok(Some(command))
    }

    fn status_locked(&self) -> AppResult<ManagedRuntimeStatus> {
        self.status_locked_with_command_budget(STATUS_RECONCILIATION_COMMAND_BUDGET)
    }

    fn status_locked_with_command_budget(
        &self,
        command_budget: Duration,
    ) -> AppResult<ManagedRuntimeStatus> {
        let target = match self.loaded.target() {
            Ok(target) => target,
            Err(error) => {
                return Ok(self.status_value(
                    ManagedRuntimePhase::Unsupported,
                    false,
                    None,
                    error.to_string(),
                ));
            }
        };
        if !self.install_directory().exists() {
            return Ok(self.status_value(
                ManagedRuntimePhase::NotInstalled,
                false,
                Some(target),
                "managed runtime payload has not been installed for this application release"
                    .into(),
            ));
        }
        if let Err(error) = self.verify_installation() {
            return Ok(self.status_value(
                ManagedRuntimePhase::Corrupt,
                false,
                Some(target),
                error.to_string(),
            ));
        }
        if !self.provider_generation_is_selected_locked(target)? {
            return Ok(self.status_value(
                ManagedRuntimePhase::Installed,
                false,
                Some(target),
                "managed runtime payload is verified; automatic setup has not selected a Windows workspace yet"
                    .into(),
            ));
        }
        let command = self.runtime_command(target)?;
        // Payload verification and command preparation may take longer than
        // the provider-command budget. Start that budget only once they finish,
        // so large verified bundles still get a bounded machine-state query.
        // Inventory and server readiness continue to share this one deadline.
        let command_deadline = Instant::now().checked_add(command_budget).ok_or_else(|| {
            AppError::Runtime("managed runtime status deadline overflowed".into())
        })?;
        let Some(inventory_timeout) = remaining_command_budget(command_deadline) else {
            return Ok(self.status_value(
                // The payload is installed, but the machine truth is unknown.
                // `Installed` is an actionable first-launch state in the UI;
                // reporting it here would turn a read-only status timeout into
                // an automatic lifecycle mutation. `Starting` is the existing
                // transient/reconciling state and is deliberately not eligible
                // for automatic setup.
                ManagedRuntimePhase::Starting,
                false,
                Some(target),
                "managed runtime payload is verified, but its machine state was not queried because the bounded status budget elapsed"
                    .into(),
            ));
        };
        let machines = match self.list_machines_for_status(&command, inventory_timeout) {
            Ok(machines) => machines,
            Err(StatusMachineInventoryFailure::Reconciliation(error)) => {
                return Ok(self.status_value(
                    ManagedRuntimePhase::Starting,
                    false,
                    Some(target),
                    format!(
                        "managed runtime payload is verified, but its machine state could not be confirmed within the bounded status budget: {error}"
                    ),
                ));
            }
            Err(StatusMachineInventoryFailure::Invalid(error)) => {
                return Ok(self.status_value(
                    ManagedRuntimePhase::Corrupt,
                    false,
                    Some(target),
                    format!(
                        "managed runtime payload is verified, but its machine inventory contract is invalid and needs repair: {error}"
                    ),
                ));
            }
        };
        let machine_name = self.effective_machine_name_locked(target)?;
        let Some(machine) = machines.iter().find(|machine| machine.name == machine_name) else {
            return Ok(self.status_value(
                ManagedRuntimePhase::Installed,
                false,
                Some(target),
                "managed runtime payload is verified; its rootless machine has not been initialized"
                    .into(),
            ));
        };
        if let Err(error) = self.prove_machine_named(machine, target, &machine_name) {
            return Ok(self.status_value(
                ManagedRuntimePhase::Corrupt,
                false,
                Some(target),
                error.to_string(),
            ));
        }
        if let Err(error) =
            self.prove_current_windows_machine_ownership_locked(target, &machine_name)
        {
            return Ok(self.status_value(
                ManagedRuntimePhase::Corrupt,
                false,
                Some(target),
                error.to_string(),
            ));
        }
        if !machine.running {
            return Ok(self.status_value(
                ManagedRuntimePhase::Stopped,
                false,
                Some(target),
                "managed runtime machine is stopped".into(),
            ));
        }
        let Some(probe_timeout) = remaining_command_budget(command_deadline) else {
            return Ok(self.status_value(
                ManagedRuntimePhase::Starting,
                false,
                Some(target),
                "managed runtime machine is running, but the bounded status budget elapsed before its rootless server could be checked"
                    .into(),
            ));
        };
        match self.server_version_with_timeout(&command, probe_timeout) {
            Ok(version) => Ok(self.status_value(
                ManagedRuntimePhase::Running,
                true,
                Some(target),
                format!("managed rootless Podman {version} is available"),
            )),
            Err(error) => Ok(self.status_value(
                ManagedRuntimePhase::Starting,
                false,
                Some(target),
                format!(
                    "managed runtime machine is running, but its rootless server is not ready; retry is safe and preserves the exact owned machine: {error}"
                ),
            )),
        }
    }

    fn status_value(
        &self,
        phase: ManagedRuntimePhase,
        available: bool,
        target: Option<&ManagedTarget>,
        detail: String,
    ) -> ManagedRuntimeStatus {
        ManagedRuntimeStatus {
            provider: "managed_local".into(),
            phase,
            available,
            runtime_version: self.loaded.manifest.runtime_version.clone(),
            manifest_sha256: self.loaded.sha256.clone(),
            machine_image_sha256: target.map(|target| target.machine_image.sha256.clone()),
            operating_system: target
                .map(|target| target.operating_system)
                .or_else(ManagedOperatingSystem::current),
            architecture: target
                .map(|target| target.architecture)
                .or_else(ManagedArchitecture::current),
            machine_provider: target.map(|target| target.provider),
            prerequisite: target.and_then(|target| target.prerequisite.clone()),
            detail,
        }
    }

    fn install_locked(&self) -> AppResult<()> {
        self.loaded.target()?;
        self.verify_resource_bundle()?;
        ensure_managed_private_directory(&self.versions_root())?;
        self.remove_abandoned_install_staging_directories_locked()?;
        let destination = self.install_directory();
        if private_entry_exists(&destination)? {
            match self.verify_installation() {
                Ok(()) => return Ok(()),
                Err(_) => {
                    remove_private_tree(&destination, &self.versions_root())?;
                    sync_directory(&self.versions_root())?;
                }
            }
        }
        let staging = self
            .versions_root()
            .join(format!(".installing-{}", Uuid::new_v4()));
        ensure_managed_private_directory(&staging)?;
        let result = (|| {
            for entry in &self.loaded.manifest.files {
                let source = safe_join(&self.resource_root, &entry.path)?;
                let target = safe_join(&staging, &entry.path)?;
                if let Some(parent) = target.parent() {
                    ensure_private_directory_tree(&staging, parent)?;
                }
                copy_verified_file(&source, &target, entry)?;
            }
            let manifest_path = staging.join("manifest.json");
            let mut manifest_file = create_private_file(&manifest_path)?;
            manifest_file.write_all(&self.loaded.encoded)?;
            manifest_file.flush()?;
            manifest_file.sync_all()?;
            // Windows refuses to rename a directory while a child file is
            // still open without delete sharing. Close the manifest handle
            // before the atomic directory commit on every platform.
            drop(manifest_file);
            fs::rename(&staging, &destination).map_err(|error| {
                AppError::Runtime(format!(
                    "managed runtime payload could not be committed atomically: {error}"
                ))
            })?;
            sync_directory(&self.versions_root())?;
            self.verify_installation()
        })();
        if result.is_err() && staging.exists() {
            let _ = remove_private_tree(&staging, &self.versions_root());
        }
        result
    }

    /// A terminated copy can leave only its random private staging directory.
    /// The lifecycle lock proves no other product install is active, so a later
    /// attempt may remove exactly names this implementation generates. Similar
    /// or malformed siblings remain untouched as ambiguous user state.
    fn remove_abandoned_install_staging_directories_locked(&self) -> AppResult<()> {
        let versions_root = self.versions_root();
        let staging_paths = fs::read_dir(&versions_root)?
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .filter(|entry| is_managed_runtime_install_staging_name(&entry.file_name()))
            .map(|entry| entry.path())
            .collect::<Vec<_>>();
        for staging in staging_paths {
            remove_private_tree(&staging, &versions_root)?;
        }
        Ok(())
    }

    fn verify_resource_bundle(&self) -> AppResult<()> {
        verify_bundle_files(&self.resource_root, &self.loaded.manifest.files)
    }

    fn verify_installation(&self) -> AppResult<()> {
        let root = canonical_real_directory(&self.install_directory(), "managed runtime install")?;
        verify_installed_permissions(&root, &self.versions_root(), &self.loaded.manifest.files)?;
        verify_bundle_files(&root, &self.loaded.manifest.files)?;
        let installed_manifest = LoadedManagedRuntimeManifest::read(&root.join("manifest.json"))?;
        if installed_manifest.sha256 != self.loaded.sha256 {
            return Err(AppError::NotAuthorized(
                "installed managed runtime manifest differs from this application release".into(),
            ));
        }
        Ok(())
    }

    #[cfg(windows)]
    fn windows_launch_contract(
        &self,
        install_root: &Path,
    ) -> AppResult<Arc<WindowsManagedRuntimeLaunchContract>> {
        let versions_root = install_root.parent().ok_or_else(|| {
            AppError::Internal("managed runtime installation has no versions directory".into())
        })?;
        let canonical_versions =
            canonical_real_directory(&self.versions_root(), "managed runtime versions")?;
        if versions_root != canonical_versions.as_path() {
            return Err(AppError::NotAuthorized(
                "managed runtime installation is outside this manager's canonical versions directory"
                    .into(),
            ));
        }

        let driver = safe_join(install_root, &self.loaded.manifest.driver_path)?;
        let mut bundle_directories = BTreeSet::from([install_root.to_path_buf()]);
        let mut files = Vec::with_capacity(self.loaded.manifest.files.len() + 1);
        files.push(WindowsManagedRuntimeLaunchFile {
            path: install_root.join("manifest.json"),
            size_bytes: u64::try_from(self.loaded.encoded.len()).map_err(|_| {
                AppError::Internal("managed runtime manifest length exceeded this platform".into())
            })?,
            sha256: self.loaded.sha256.clone(),
        });
        for entry in &self.loaded.manifest.files {
            let path = safe_join(install_root, &entry.path)?;
            let parent = path.parent().ok_or_else(|| {
                AppError::Internal("managed runtime payload has no parent directory".into())
            })?;
            let relative_parent = parent.strip_prefix(install_root).map_err(|_| {
                AppError::NotAuthorized(
                    "managed runtime payload escaped its installation directory".into(),
                )
            })?;
            let mut current = install_root.to_path_buf();
            for component in relative_parent.components() {
                let Component::Normal(component) = component else {
                    return Err(AppError::NotAuthorized(
                        "managed runtime payload contains an unsafe directory component".into(),
                    ));
                };
                current.push(component);
                bundle_directories.insert(current.clone());
            }
            files.push(WindowsManagedRuntimeLaunchFile {
                path,
                size_bytes: entry.size_bytes,
                sha256: entry.sha256.clone(),
            });
        }
        let mut bundle_directories = bundle_directories.into_iter().collect::<Vec<_>>();
        bundle_directories.sort_by(|left, right| {
            left.components()
                .count()
                .cmp(&right.components().count())
                .then_with(|| left.cmp(right))
        });
        Ok(Arc::new(WindowsManagedRuntimeLaunchContract {
            install_root: install_root.to_path_buf(),
            versions_root: canonical_versions,
            driver,
            bundle_directories,
            files,
        }))
    }

    fn runtime_command(&self, target: &ManagedTarget) -> AppResult<ManagedRuntimeCommand> {
        self.verify_installation()?;
        let install =
            canonical_real_directory(&self.install_directory(), "managed runtime install")?;
        let binary = safe_join(&install, &self.loaded.manifest.driver_path)?;
        verify_regular_file(&binary, "managed runtime driver")?;
        #[cfg(windows)]
        let windows_launch_contract = self.windows_launch_contract(&install)?;
        let provider_root = self.state_root.join("provider-home");
        ensure_managed_private_directory(&provider_root)?;
        let provider_home = self.effective_provider_home_locked(target)?;
        let config = provider_home.join("config");
        let data = provider_home.join("data");
        let cache = provider_home.join("cache");
        let persistent_run = provider_home.join("run");
        for directory in [&provider_home, &config, &data, &cache, &persistent_run] {
            ensure_managed_private_directory(directory)?;
        }
        let containers = config.join("containers");
        ensure_managed_private_directory(&containers)?;
        if target.operating_system == ManagedOperatingSystem::Windows {
            // Pinned Podman 5.8.2 GetMachineDirs uses os.MkdirAll before every
            // machine operation. On an administrator token, those defaulted
            // children can be owned by TokenOwner (Administrators), not
            // TokenUser. Pre-create the complete fixed WSL namespace with the
            // product's protected current-user-only descriptor before Podman
            // can create any ancestor with ambient Windows defaults. WSL's
            // service boundary additionally needs LocalSystem access only on
            // the distribution-storage subtree; keep every ancestor and the
            // adjacent image cache current-user-only.
            let provider = target.provider.argument();
            ensure_private_directory_tree(&persistent_run, &persistent_run.join("podman"))?;
            ensure_private_directory_tree(
                &config,
                &containers.join("podman").join("machine").join(provider),
            )?;
            ensure_private_directory_tree(
                &data,
                &data
                    .join("containers")
                    .join("podman")
                    .join("machine")
                    .join(provider)
                    .join("cache"),
            )?;
            let machine_provider_data = data
                .join("containers")
                .join("podman")
                .join("machine")
                .join(provider);
            ensure_managed_wsl_distribution_storage_directory(
                &machine_provider_data.join(PODMAN_WSL_DISTRIBUTION_STORAGE_DIRECTORY),
            )?;
        }
        self.write_containers_config(&containers.join("containers.conf"), &install, target)?;

        let storage_config = containers.join("storage.conf");
        if target.operating_system == ManagedOperatingSystem::Linux {
            // Pinned containers/storage otherwise derives RunRoot as
            // $XDG_RUNTIME_DIR/containers. Keep that durable storage state out
            // of Linux's socket-length-bounded short runtime while retaining
            // the conventional release-private rootless subpaths.
            let storage_runroot = persistent_run.join("containers");
            let storage_graphroot = data.join("containers").join("storage");
            ensure_private_directory_tree(&persistent_run, &storage_runroot)?;
            ensure_private_directory_tree(&data, &storage_graphroot)?;
            self.write_containers_storage_config(
                &storage_config,
                &storage_runroot,
                &storage_graphroot,
            )?;
        }

        let command_home = self.command_home(target)?;
        let runtime_directory = self.runtime_directory(target, &persistent_run)?;
        let windows_directories = if target.operating_system == ManagedOperatingSystem::Windows {
            Some(windows_system_directories()?)
        } else {
            None
        };
        let mut environment = BTreeMap::new();
        let home_value = command_home.as_os_str().to_owned();
        environment.insert(OsString::from("HOME"), home_value.clone());
        environment.insert(OsString::from("USERPROFILE"), home_value);
        environment.insert(
            OsString::from("XDG_CONFIG_HOME"),
            config.as_os_str().to_owned(),
        );
        environment.insert(OsString::from("XDG_DATA_HOME"), data.as_os_str().to_owned());
        environment.insert(
            OsString::from("XDG_CACHE_HOME"),
            cache.as_os_str().to_owned(),
        );
        environment.insert(
            OsString::from("XDG_RUNTIME_DIR"),
            runtime_directory.as_os_str().to_owned(),
        );
        environment.insert(OsString::from("APPDATA"), config.as_os_str().to_owned());
        environment.insert(OsString::from("LOCALAPPDATA"), data.as_os_str().to_owned());
        environment.insert(
            OsString::from("CONTAINERS_CONF"),
            containers.join("containers.conf").into_os_string(),
        );
        if target.operating_system == ManagedOperatingSystem::Linux {
            environment.insert(
                OsString::from("CONTAINERS_STORAGE_CONF"),
                storage_config.into_os_string(),
            );
        }
        environment.insert(
            OsString::from("CONTAINERS_MACHINE_PROVIDER"),
            OsString::from(target.provider.argument()),
        );
        environment.insert(
            OsString::from("PATH"),
            managed_path(&install, target, windows_directories.as_ref())?,
        );
        if let Some(directories) = &windows_directories {
            let system_root = directories.system_root.as_os_str().to_owned();
            environment.insert(OsString::from("SystemRoot"), system_root.clone());
            environment.insert(OsString::from("WINDIR"), system_root);
        }
        environment.insert(OsString::from("LANG"), OsString::from("C.UTF-8"));
        environment.insert(OsString::from("LC_ALL"), OsString::from("C.UTF-8"));
        apply_platform_command_environment(&mut environment, target.operating_system);

        Ok(ManagedRuntimeCommand {
            binary,
            environment,
            working_directory: command_home,
            runtime_version: self.loaded.manifest.runtime_version.clone(),
            manifest_sha256: self.loaded.sha256.clone(),
            machine_image_sha256: target.machine_image.sha256.clone(),
            #[cfg(windows)]
            windows_launch_authorization: WindowsManagedRuntimeLaunchAuthorization::PrivateBundle(
                windows_launch_contract,
            ),
        })
    }

    /// Builds only the metadata shell needed to derive the verified
    /// `%SystemRoot%\\System32\\wsl.exe` read-only command. It never creates or
    /// rewrites a provider home, so generation selection can happen before an
    /// ambiguous legacy namespace is touched.
    fn windows_wsl_read_only_command(
        &self,
        target: &ManagedTarget,
    ) -> AppResult<ManagedRuntimeCommand> {
        if target.operating_system != ManagedOperatingSystem::Windows
            || target.provider != ManagedMachineProvider::Wsl
        {
            return Err(AppError::InvalidRequest(
                "a Windows WSL inventory command was requested for another managed target".into(),
            ));
        }
        self.verify_installation()?;
        let install =
            canonical_real_directory(&self.install_directory(), "managed runtime install")?;
        let binary = safe_join(&install, &self.loaded.manifest.driver_path)?;
        verify_regular_file(&binary, "managed runtime driver")?;
        Ok(ManagedRuntimeCommand {
            binary,
            environment: BTreeMap::new(),
            working_directory: install,
            runtime_version: self.loaded.manifest.runtime_version.clone(),
            manifest_sha256: self.loaded.sha256.clone(),
            machine_image_sha256: target.machine_image.sha256.clone(),
            #[cfg(windows)]
            windows_launch_authorization: WindowsManagedRuntimeLaunchAuthorization::MetadataOnly,
        })
    }

    /// Destructive provider cleanup has a stricter contract than setup
    /// routing. The current generation is removable only after both Windows'
    /// WSL inventory and its registration inventory confirm that the exact
    /// distribution is gone. A routing selection never satisfies this proof.
    fn require_current_windows_wsl_distribution_absent_for_cleanup_locked(
        &self,
        target: &ManagedTarget,
        managed_command: &ManagedRuntimeCommand,
        machine_name: &str,
    ) -> AppResult<()> {
        if target.operating_system != ManagedOperatingSystem::Windows {
            return Ok(());
        }
        if target.provider != ManagedMachineProvider::Wsl {
            return Err(AppError::NotAuthorized(
                "managed Windows runtime target did not use the WSL provider".into(),
            ));
        }
        let distribution_name = format!("podman-{machine_name}");
        let distributions = self.windows_wsl_distribution_inventory(managed_command)?;
        if distributions
            .iter()
            .any(|name| name.eq_ignore_ascii_case(&distribution_name))
        {
            return Err(AppError::NotAuthorized(
                "Windows still reports the selected scan workspace; its provider data was preserved"
                    .into(),
            ));
        }
        let registrations = self.wsl_registrations.registrations()?;
        if registrations.iter().any(|registration| {
            registration
                .distribution_name
                .eq_ignore_ascii_case(&distribution_name)
        }) {
            return Err(AppError::NotAuthorized(
                "Windows still registers the selected scan workspace; its provider data was preserved"
                    .into(),
            ));
        }
        Ok(())
    }

    fn windows_wsl_distribution_inventory(
        &self,
        managed_command: &ManagedRuntimeCommand,
    ) -> AppResult<Vec<String>> {
        let command = windows_wsl_inventory_command(managed_command)?;
        let output = self.run_command(
            ManagedCommandOperation::WslDistributionInventory,
            &command,
            ["--list", "--quiet"],
            COMMAND_TIMEOUT,
        )?;
        require_success("managed Windows WSL distribution inventory", &output)?;
        parse_windows_wsl_distribution_inventory(&output.stdout)
    }

    fn windows_wsl_generation_selection_path(&self, generation_index: u32) -> PathBuf {
        self.state_root
            .join(WINDOWS_WSL_GENERATION_DIRECTORY)
            .join(format!("{}.{}.json", self.loaded.sha256, generation_index))
    }

    fn isolated_windows_machine_name(
        &self,
        target: &ManagedTarget,
        generation_index: u32,
    ) -> String {
        let mut digest = Sha256::new();
        digest.update(b"ai-security-scanner/windows-wsl-isolated-generation/v1\0");
        digest.update(self.state_root.as_os_str().to_string_lossy().as_bytes());
        digest.update(b"\0");
        digest.update(self.loaded.sha256.as_bytes());
        digest.update(b"\0");
        digest.update(target.machine_image.sha256.as_bytes());
        digest.update(b"\0");
        digest.update(generation_index.to_le_bytes());
        let suffix = hex::encode(digest.finalize());
        format!(
            "{WINDOWS_WSL_ISOLATED_MACHINE_PREFIX}{}",
            &suffix[..WINDOWS_WSL_ISOLATED_MACHINE_DIGEST_HEX_CHARS]
        )
    }

    fn validate_windows_wsl_generation_selection(
        &self,
        target: &ManagedTarget,
        selection: &WindowsWslGenerationSelection,
    ) -> AppResult<()> {
        let default_machine_name = machine_name(target);
        let selected_is_expected = if selection.generation_index == 0 {
            selection.selected_machine_name == default_machine_name
        } else {
            selection.selected_machine_name
                == self.isolated_windows_machine_name(target, selection.generation_index)
        };
        if selection.schema_version != WINDOWS_WSL_GENERATION_SELECTION_SCHEMA
            || selection.authorizes_cleanup
            || selection.manifest_sha256 != self.loaded.sha256
            || selection.machine_image_sha256 != target.machine_image.sha256
            || selection.default_machine_name != default_machine_name
            || selection.generation_index > MAX_WINDOWS_WSL_ISOLATED_GENERATION_ATTEMPTS
            || !selected_is_expected
            || selection.selected_machine_name.len() > MAX_MACHINE_NAME_BYTES
            || selection.preserved_collision_names.len()
                > MAX_WINDOWS_WSL_ISOLATED_GENERATION_ATTEMPTS as usize
            || selection.preserved_collision_names.iter().any(|name| {
                name.len() > MAX_MACHINE_NAME_BYTES
                    || (!name.eq_ignore_ascii_case(&default_machine_name)
                        && !windows_machine_uses_current_compatibility_generation(name))
            })
        {
            return Err(AppError::NotAuthorized(
                "managed Windows runtime generation selection does not match this release".into(),
            ));
        }
        Ok(())
    }

    fn read_windows_wsl_generation_selection_locked(
        &self,
        target: &ManagedTarget,
    ) -> AppResult<Option<WindowsWslGenerationSelection>> {
        if target.operating_system != ManagedOperatingSystem::Windows {
            return Ok(None);
        }
        let mut selected = None;
        for generation_index in 0..=MAX_WINDOWS_WSL_ISOLATED_GENERATION_ATTEMPTS {
            let path = self.windows_wsl_generation_selection_path(generation_index);
            if !private_entry_exists(&path)
                .map_err(retryable_generation_selection_inspection_error)?
            {
                continue;
            }
            // A malformed old routing record is observation-only state. Never
            // overwrite or delete it; a later valid append-only generation can
            // still let setup reconcile automatically.
            let encoded = match read_bounded_regular_bytes(
                &path,
                64 * 1024,
                "managed Windows WSL generation selection",
            ) {
                Ok(encoded) => encoded,
                // Structurally invalid append-only entries are preserved and
                // remain occupied, but cannot permanently hide a later valid
                // generation. Actual I/O/sharing failures remain retryable.
                Err(AppError::NotAuthorized(_)) => continue,
                Err(error) => {
                    return Err(retryable_generation_selection_inspection_error(error));
                }
            };
            let Ok(selection) = serde_json::from_slice::<WindowsWslGenerationSelection>(&encoded)
            else {
                continue;
            };
            match self.validate_windows_wsl_generation_selection(target, &selection) {
                Ok(()) if selection.generation_index == generation_index => {
                    selected = Some(selection);
                }
                Ok(()) | Err(AppError::NotAuthorized(_)) => {}
                Err(error) => {
                    return Err(retryable_generation_selection_inspection_error(error));
                }
            }
        }
        Ok(selected)
    }

    fn write_windows_wsl_generation_selection_locked(
        &self,
        target: &ManagedTarget,
        selection: &WindowsWslGenerationSelection,
    ) -> AppResult<()> {
        self.validate_windows_wsl_generation_selection(target, selection)?;
        let encoded = serde_json::to_vec(selection).map_err(|error| {
            AppError::Internal(format!(
                "managed Windows WSL generation selection could not be encoded: {error}"
            ))
        })?;
        let path = self.windows_wsl_generation_selection_path(selection.generation_index);
        write_private_atomic(&path, &encoded)?;
        let persisted: WindowsWslGenerationSelection = read_bounded_private_json(
            &path,
            64 * 1024,
            "managed Windows WSL generation selection",
        )?;
        if persisted != *selection {
            return Err(AppError::Internal(
                "managed Windows WSL generation selection changed during its durable commit".into(),
            ));
        }
        Ok(())
    }

    fn windows_wsl_distribution_storage_path(
        &self,
        target: &ManagedTarget,
        machine_name: &str,
        generation_index: u32,
    ) -> PathBuf {
        self.windows_provider_home_for_generation(target, generation_index)
            .join("data")
            .join("containers")
            .join("podman")
            .join("machine")
            .join(target.provider.argument())
            .join(PODMAN_WSL_DISTRIBUTION_STORAGE_DIRECTORY)
            .join(machine_name)
    }

    fn windows_machine_generation_is_occupied(
        &self,
        target: &ManagedTarget,
        machine_name: &str,
        generation_index: u32,
        distributions: &[String],
        machines: &[MachineListEntry],
    ) -> AppResult<bool> {
        let distribution_name = format!("podman-{machine_name}");
        Ok(distributions
            .iter()
            .any(|name| name.eq_ignore_ascii_case(&distribution_name))
            || machines
                .iter()
                .any(|machine| machine.name.eq_ignore_ascii_case(machine_name))
            || private_entry_exists(&self.windows_wsl_distribution_storage_path(
                target,
                machine_name,
                generation_index,
            ))?)
    }

    fn windows_generation_selection_exists(&self, generation_index: u32) -> AppResult<bool> {
        private_entry_exists(&self.windows_wsl_generation_selection_path(generation_index))
    }

    /// Chooses one durable Windows generation without reclaiming any existing
    /// WSL name or storage path. A collision causes a fresh release-private
    /// name to be selected and persisted before `podman machine init` runs.
    /// Repeated setup attempts reuse that exact selection.
    fn resolve_windows_machine_generation_locked(
        &self,
        target: &ManagedTarget,
        managed_command: &ManagedRuntimeCommand,
        machines: &[MachineListEntry],
        provider_inventory_complete: bool,
    ) -> AppResult<String> {
        if target.operating_system != ManagedOperatingSystem::Windows {
            return Ok(machine_name(target));
        }
        if target.provider != ManagedMachineProvider::Wsl {
            return Err(AppError::NotAuthorized(
                "managed Windows runtime target did not use the WSL provider".into(),
            ));
        }
        let distributions = self.windows_wsl_distribution_inventory(managed_command)?;
        self.select_windows_machine_generation_from_inventory_locked(
            target,
            machines,
            &distributions,
            provider_inventory_complete,
        )
    }

    fn select_windows_machine_generation_from_inventory_locked(
        &self,
        target: &ManagedTarget,
        machines: &[MachineListEntry],
        distributions: &[String],
        provider_inventory_complete: bool,
    ) -> AppResult<String> {
        if target.operating_system != ManagedOperatingSystem::Windows {
            return Ok(machine_name(target));
        }
        if target.provider != ManagedMachineProvider::Wsl {
            return Err(AppError::NotAuthorized(
                "managed Windows runtime target did not use the WSL provider".into(),
            ));
        }
        let registration_inventory = self.windows_wsl_registration_inventory_with_one_retry()?;
        self.select_windows_machine_generation_with_registration_inventory_locked(
            target,
            WindowsWslGenerationSelectionInput {
                machines,
                distributions,
                registrations: &registration_inventory.registrations,
                observed_registration_names: &registration_inventory.observed_distribution_names,
                registration_inventory_complete: registration_inventory.complete,
                provider_inventory_complete,
            },
        )
    }

    /// One complete retry distinguishes a transient registry race from a
    /// persistently partial inventory. Partial observations are still useful
    /// collision evidence, but can never authorize adoption or mutation.
    fn windows_wsl_registration_inventory_with_one_retry(
        &self,
    ) -> AppResult<WindowsWslRegistrationInventory> {
        let first = self
            .wsl_registrations
            .inventory()
            .map_err(retryable_windows_registration_inspection_error)?;
        if first.complete {
            return Ok(first);
        }
        let second = self
            .wsl_registrations
            .inventory()
            .map_err(retryable_windows_registration_inspection_error)?;
        if second.complete {
            return Ok(second);
        }
        Ok(first.merge_conservatively(second))
    }

    fn select_windows_machine_generation_from_complete_inventory_locked(
        &self,
        target: &ManagedTarget,
        machines: &[MachineListEntry],
        distributions: &[String],
        registrations: &[WindowsWslRegistration],
        provider_inventory_complete: bool,
    ) -> AppResult<String> {
        let observed_distribution_names = registrations
            .iter()
            .map(|registration| registration.distribution_name.clone())
            .collect::<Vec<_>>();
        self.select_windows_machine_generation_with_registration_inventory_locked(
            target,
            WindowsWslGenerationSelectionInput {
                machines,
                distributions,
                registrations,
                observed_registration_names: &observed_distribution_names,
                registration_inventory_complete: true,
                provider_inventory_complete,
            },
        )
    }

    fn select_windows_machine_generation_with_registration_inventory_locked(
        &self,
        target: &ManagedTarget,
        input: WindowsWslGenerationSelectionInput<'_>,
    ) -> AppResult<String> {
        let mut complete_distributions = input.distributions.to_vec();
        for distribution_name in input.observed_registration_names {
            if !complete_distributions
                .iter()
                .any(|name| name.eq_ignore_ascii_case(distribution_name))
            {
                complete_distributions.push(distribution_name.clone());
            }
        }
        let existing = self.read_windows_wsl_generation_selection_locked(target)?;
        let default_machine_name = machine_name(target);
        let selected = existing
            .as_ref()
            .map(|selection| selection.selected_machine_name.as_str())
            .unwrap_or(default_machine_name.as_str());

        let selected_generation_index = existing
            .as_ref()
            .map(|selection| selection.generation_index)
            .unwrap_or(0);
        let exact_registration_binding = (input.registration_inventory_complete
            || existing.is_some())
            && match self.verify_windows_wsl_machine_registration_binding_from_inventory(
                selected,
                input.registrations,
            ) {
                Ok(_) => true,
                Err(AppError::NotAuthorized(_)) => false,
                Err(error) => {
                    return Err(retryable_windows_registration_inspection_error(error));
                }
            };
        // No matching complete registration means this namespace is not ours.
        // Do not inspect a possibly locked identity or ownership journal in an
        // ambiguous provider home merely to decide that it must be preserved.
        let exact_product_binding = if exact_registration_binding {
            inspect_managed_ssh_identity(&self.machine_ssh_identity_path())
                .map_err(retryable_machine_identity_inspection_error)?
                == ManagedSshIdentityState::Valid
                && self.has_exact_windows_wsl_ownership_proof_locked(
                    target,
                    selected,
                    WindowsWslOwnershipBasis::ProvenMachine,
                )?
        } else {
            false
        };
        let selected_has_init_entry = self
            .windows_wsl_ownership_entry_exists(selected, WindowsWslOwnershipBasis::InitIntent)?;
        let selected_has_proven_entry = self.windows_wsl_ownership_entry_exists(
            selected,
            WindowsWslOwnershipBasis::ProvenMachine,
        )?;
        let exact_initialization_intent = if exact_product_binding {
            false
        } else if existing.is_some() || exact_registration_binding {
            self.has_exact_windows_wsl_ownership_proof_locked(
                target,
                selected,
                WindowsWslOwnershipBasis::InitIntent,
            )?
        } else {
            false
        };
        // A name match alone is never ownership. Reuse requires the exact
        // frozen machine contract, product SSH identity, and WSL registration
        // binding to this verified provider generation. Any failed proof turns
        // the row into a preserved collision and routes setup side-by-side.
        if let Some(machine) = input
            .machines
            .iter()
            .find(|machine| machine.name.eq_ignore_ascii_case(selected))
            && self.prove_machine_named(machine, target, selected).is_ok()
            && exact_product_binding
        {
            return Ok(selected.to_owned());
        }
        let selected_provider_home =
            self.windows_provider_home_for_generation(target, selected_generation_index);
        let occupied = self.windows_machine_generation_is_occupied(
            target,
            selected,
            selected_generation_index,
            &complete_distributions,
            input.machines,
        )? || (private_entry_exists(&selected_provider_home)?
            && !exact_product_binding
            && !exact_initialization_intent)
            || (selected_has_init_entry && !exact_initialization_intent)
            || (selected_has_proven_entry && !exact_product_binding)
            || (existing.is_none()
                && self.windows_generation_selection_exists(selected_generation_index)?)
            || (!input.registration_inventory_complete
                && existing.is_none()
                && selected_generation_index == 0);
        // Generation zero is a compatibility namespace for an exact runtime
        // selected by an older build. A genuinely new preparation must start
        // in the isolated append-only namespace, even when the deterministic
        // compatibility name is currently unused.
        let allocating_new_generation =
            existing.is_none() && !exact_product_binding && !exact_initialization_intent;
        if (!occupied || (exact_product_binding && !input.provider_inventory_complete))
            && !allocating_new_generation
        {
            if existing.is_none() {
                self.write_windows_wsl_generation_selection_locked(
                    target,
                    &WindowsWslGenerationSelection {
                        schema_version: WINDOWS_WSL_GENERATION_SELECTION_SCHEMA.into(),
                        authorizes_cleanup: false,
                        manifest_sha256: self.loaded.sha256.clone(),
                        machine_image_sha256: target.machine_image.sha256.clone(),
                        default_machine_name: default_machine_name.clone(),
                        selected_machine_name: default_machine_name.clone(),
                        generation_index: 0,
                        preserved_collision_names: Vec::new(),
                    },
                )?;
            }
            return Ok(selected.to_owned());
        }

        let mut preserved_collision_names = existing
            .as_ref()
            .map(|selection| selection.preserved_collision_names.clone())
            .unwrap_or_default();
        if occupied
            && !preserved_collision_names
                .iter()
                .any(|name| name.eq_ignore_ascii_case(selected))
        {
            preserved_collision_names.push(selected.to_owned());
        }
        let first_index = existing
            .as_ref()
            .map(|selection| selection.generation_index.saturating_add(1).max(1))
            .unwrap_or(1);
        for generation_index in first_index..=MAX_WINDOWS_WSL_ISOLATED_GENERATION_ATTEMPTS {
            let candidate = self.isolated_windows_machine_name(target, generation_index);
            if self.windows_machine_generation_is_occupied(
                target,
                &candidate,
                generation_index,
                &complete_distributions,
                input.machines,
            )? || private_entry_exists(
                &self.windows_provider_home_for_generation(target, generation_index),
            )? || self.windows_generation_selection_exists(generation_index)?
                || self.windows_wsl_any_ownership_entry_exists(&candidate)?
            {
                continue;
            }
            let selection = WindowsWslGenerationSelection {
                schema_version: WINDOWS_WSL_GENERATION_SELECTION_SCHEMA.into(),
                authorizes_cleanup: false,
                manifest_sha256: self.loaded.sha256.clone(),
                machine_image_sha256: target.machine_image.sha256.clone(),
                default_machine_name,
                selected_machine_name: candidate.clone(),
                generation_index,
                preserved_collision_names,
            };
            self.write_windows_wsl_generation_selection_locked(target, &selection)?;
            return Ok(candidate);
        }
        Err(AppError::NotAvailable(
            "managed Windows runtime could not allocate a fresh isolated generation within its bounded retry budget"
                .into(),
        ))
    }

    fn select_fresh_windows_machine_generation_after_runtime_failure_locked(
        &self,
        target: &ManagedTarget,
        failed_machine_name: &str,
        machines: &[MachineListEntry],
        distributions: &[String],
    ) -> AppResult<String> {
        if target.operating_system != ManagedOperatingSystem::Windows
            || target.provider != ManagedMachineProvider::Wsl
        {
            return Err(AppError::InvalidRequest(
                "an isolated Windows replacement was requested for another managed target".into(),
            ));
        }
        let existing = self
            .read_windows_wsl_generation_selection_locked(target)?
            .ok_or_else(|| {
                AppError::NotAvailable(
                    "the unavailable Windows scan workspace had no durable generation selection"
                        .into(),
                )
            })?;
        if !existing
            .selected_machine_name
            .eq_ignore_ascii_case(failed_machine_name)
        {
            return Err(AppError::NotAuthorized(
                "the unavailable Windows scan workspace changed before isolated replacement".into(),
            ));
        }

        let mut preserved_collision_names = existing.preserved_collision_names.clone();
        if !preserved_collision_names
            .iter()
            .any(|name| name.eq_ignore_ascii_case(failed_machine_name))
        {
            preserved_collision_names.push(failed_machine_name.to_owned());
        }
        let first_index = existing.generation_index.saturating_add(1).max(1);
        for generation_index in first_index..=MAX_WINDOWS_WSL_ISOLATED_GENERATION_ATTEMPTS {
            let candidate = self.isolated_windows_machine_name(target, generation_index);
            if self.windows_machine_generation_is_occupied(
                target,
                &candidate,
                generation_index,
                distributions,
                machines,
            )? || private_entry_exists(
                &self.windows_provider_home_for_generation(target, generation_index),
            )? || self.windows_generation_selection_exists(generation_index)?
                || self.windows_wsl_any_ownership_entry_exists(&candidate)?
            {
                continue;
            }
            let selection = WindowsWslGenerationSelection {
                schema_version: WINDOWS_WSL_GENERATION_SELECTION_SCHEMA.into(),
                authorizes_cleanup: false,
                manifest_sha256: self.loaded.sha256.clone(),
                machine_image_sha256: target.machine_image.sha256.clone(),
                default_machine_name: machine_name(target),
                selected_machine_name: candidate.clone(),
                generation_index,
                preserved_collision_names,
            };
            self.write_windows_wsl_generation_selection_locked(target, &selection)?;
            return Ok(candidate);
        }
        Err(AppError::NotAvailable(
            "managed Windows runtime could not allocate one isolated replacement within its bounded generation budget"
                .into(),
        ))
    }

    fn effective_machine_name_locked(&self, target: &ManagedTarget) -> AppResult<String> {
        Ok(self
            .read_windows_wsl_generation_selection_locked(target)?
            .map(|selection| selection.selected_machine_name)
            .unwrap_or_else(|| machine_name(target)))
    }

    /// Provider commands are allowed to create their private configuration
    /// tree. On Windows that must happen only after setup has durably selected
    /// one generation. Before selection, status and other ordinary lifecycle
    /// reads preserve every existing provider namespace as unclassified state.
    fn provider_generation_is_selected_locked(&self, target: &ManagedTarget) -> AppResult<bool> {
        if target.operating_system != ManagedOperatingSystem::Windows {
            return Ok(true);
        }
        Ok(self
            .read_windows_wsl_generation_selection_locked(target)?
            .is_some())
    }

    fn verify_current_windows_wsl_machine_registration_binding(
        &self,
        machine_name: &str,
    ) -> AppResult<PathBuf> {
        // This is a non-destructive proof for one already selected product
        // generation. An unrelated malformed WSL registry entry must not make
        // that exact generation unusable: a partial inventory may prove one
        // exact name/path binding, but it may never authorize adoption or
        // cleanup of anything else.
        let inventory = self.windows_wsl_registration_inventory_with_one_retry()?;
        self.verify_windows_wsl_machine_registration_binding_from_inventory(
            machine_name,
            &inventory.registrations,
        )
    }

    fn verify_windows_wsl_machine_registration_binding_from_inventory(
        &self,
        machine_name: &str,
        registrations: &[WindowsWslRegistration],
    ) -> AppResult<PathBuf> {
        let distribution_name = format!("podman-{machine_name}");
        let matching = registrations
            .iter()
            .filter(|registration| {
                registration
                    .distribution_name
                    .eq_ignore_ascii_case(&distribution_name)
            })
            .collect::<Vec<_>>();
        if matching.len() != 1 {
            return Err(AppError::NotAuthorized(
                "Windows did not expose one exact registration for the replacement scan workspace"
                    .into(),
            ));
        }
        let target = self.loaded.target()?;
        let isolated_selection = self
            .read_windows_wsl_generation_selection_locked(target)?
            .filter(|selection| selection.generation_index > 0);
        let (actual_base, actual_provider, expected_provider) =
            if let Some(selection) = isolated_selection {
                if selection.selected_machine_name != machine_name {
                    return Err(AppError::NotAuthorized(
                        "Windows WSL isolated generation does not match the selected scan workspace"
                            .into(),
                    ));
                }
                self.require_isolated_windows_generation_ownership_locked(
                    target,
                    machine_name,
                    &selection,
                )?;
                let actual_base = canonical_real_directory(
                    &matching[0].base_path,
                    "managed Windows WSL isolated registration",
                )?;
                let actual_provider = windows_wsl_provider_home_from_registration_path(
                    &self.state_root,
                    &actual_base,
                    machine_name,
                )?;
                let expected_provider = canonical_real_directory(
                    &self.windows_provider_home_for_generation(target, selection.generation_index),
                    "isolated managed runtime provider home",
                )?;
                verify_windows_wsl_product_storage_directory(&actual_provider, &actual_base)?;
                (actual_base, actual_provider, expected_provider)
            } else {
                let (actual_base, actual_provider) = self
                    .verify_windows_wsl_registration_binding_is_product_owned(
                        machine_name,
                        &matching[0].base_path,
                    )?;
                let expected_provider = canonical_real_directory(
                    &self.provider_home(),
                    "replacement managed runtime provider home",
                )?;
                (actual_base, actual_provider, expected_provider)
            };
        let expected_base = canonical_real_directory(
            &expected_provider
                .join("data")
                .join("containers")
                .join("podman")
                .join("machine")
                .join("wsl")
                .join(PODMAN_WSL_DISTRIBUTION_STORAGE_DIRECTORY)
                .join(machine_name),
            "replacement managed Windows WSL workspace",
        )?;
        if !windows_paths_refer_to_same_location(&actual_provider, &expected_provider)?
            || !windows_paths_refer_to_same_location(&actual_base, &expected_base)?
        {
            return Err(AppError::NotAuthorized(
                "Windows WSL replacement registration is not bound to this app release".into(),
            ));
        }
        Ok(actual_base)
    }

    fn require_isolated_windows_generation_ownership_locked(
        &self,
        target: &ManagedTarget,
        machine_name: &str,
        selection: &WindowsWslGenerationSelection,
    ) -> AppResult<()> {
        self.validate_windows_wsl_generation_selection(target, selection)?;
        if selection.generation_index == 0 || selection.selected_machine_name != machine_name {
            return Err(AppError::NotAuthorized(
                "Windows WSL isolated generation does not match the selected scan workspace".into(),
            ));
        }
        // The routing record only selects a path; it is never ownership
        // authority. A successful init is accepted only while its exact
        // one-shot intent exists, or after the exact proven-machine journal has
        // been committed. The installed current manifest is independently
        // re-verified before either proof is considered.
        self.verify_installation()?;
        let has_proven_machine = self.has_exact_windows_wsl_ownership_proof_locked(
            target,
            machine_name,
            WindowsWslOwnershipBasis::ProvenMachine,
        )?;
        if has_proven_machine {
            return Ok(());
        }
        let has_init_intent = self.has_exact_windows_wsl_ownership_proof_locked(
            target,
            machine_name,
            WindowsWslOwnershipBasis::InitIntent,
        )?;
        if !has_init_intent {
            return Err(AppError::NotAuthorized(
                "Windows WSL isolated generation has no exact product ownership proof".into(),
            ));
        }
        Ok(())
    }

    fn verify_windows_wsl_registration_binding_is_product_owned(
        &self,
        machine_name: &str,
        base_path: &Path,
    ) -> AppResult<(PathBuf, PathBuf)> {
        let canonical_base =
            canonical_real_directory(base_path, "managed Windows WSL registration")?;
        let provider_home = windows_wsl_provider_home_from_registration_path(
            &self.state_root,
            &canonical_base,
            machine_name,
        )?;
        if self
            .provider_home_matches_verified_manifest(&provider_home)?
            .is_none()
        {
            return Err(AppError::NotAuthorized(
                "Windows WSL workspace is not bound to a verified ai-security-scanner release; it was preserved"
                    .into(),
            ));
        }
        verify_windows_wsl_product_storage_directory(&provider_home, &canonical_base)?;
        Ok((canonical_base, provider_home))
    }

    fn provider_home_matches_verified_manifest(
        &self,
        provider_home: &Path,
    ) -> AppResult<Option<String>> {
        let Some(namespace) = provider_home.file_name().and_then(OsStr::to_str) else {
            return Ok(None);
        };
        let mut entries = fs::read_dir(self.versions_root())?.collect::<Result<Vec<_>, _>>()?;
        entries.sort_by_key(|entry| entry.file_name());
        let mut retained_entry_count = 0_usize;
        for entry in entries {
            let is_install_staging = is_managed_runtime_install_staging_name(&entry.file_name());
            if !is_install_staging {
                retained_entry_count += 1;
                if retained_entry_count > MAX_INSTALLED_VERSIONS {
                    return Err(AppError::NotAuthorized(format!(
                        "managed runtime has more than {MAX_INSTALLED_VERSIONS} installed payloads"
                    )));
                }
            }
            let metadata = fs::symlink_metadata(entry.path())?;
            if metadata.file_type().is_symlink() {
                return Err(AppError::NotAuthorized(
                    "managed runtime versions directory contains a symlink".into(),
                ));
            }
            if !metadata.is_dir() || is_install_staging {
                continue;
            }
            let manifest_path = entry.path().join("manifest.json");
            if !private_entry_exists(&manifest_path)? {
                return Err(AppError::NotAuthorized(
                    "managed runtime installation has no release manifest".into(),
                ));
            }
            let loaded = LoadedManagedRuntimeManifest::read(&manifest_path)?;
            if entry.file_name() != OsStr::new(&installation_directory_name(&loaded)) {
                return Err(AppError::NotAuthorized(
                    "managed runtime installation directory does not match its manifest identity"
                        .into(),
                ));
            }
            let root =
                canonical_real_directory(&entry.path(), "previous managed runtime installation")?;
            verify_installed_permissions(&root, &self.versions_root(), &loaded.manifest.files)?;
            verify_bundle_files(&root, &loaded.manifest.files)?;
            if namespace.eq_ignore_ascii_case(&loaded.sha256[..16]) {
                if namespace.eq_ignore_ascii_case(&self.loaded.sha256[..16])
                    && !loaded.sha256.eq_ignore_ascii_case(&self.loaded.sha256)
                {
                    return Err(AppError::NotAuthorized(
                        "current managed runtime provider namespace is not backed by this release manifest"
                            .into(),
                    ));
                }
                return Ok(Some(loaded.sha256));
            }
        }
        Ok(None)
    }

    fn windows_wsl_ownership_proof_path(
        &self,
        machine_name: &str,
        ownership_basis: WindowsWslOwnershipBasis,
    ) -> PathBuf {
        let suffix = match ownership_basis {
            WindowsWslOwnershipBasis::InitIntent => "init-intent",
            WindowsWslOwnershipBasis::ProvenMachine => "proven-machine",
        };
        self.state_root
            .join(WINDOWS_WSL_OWNERSHIP_DIRECTORY)
            .join(format!("{machine_name}.{suffix}.json"))
    }

    fn windows_wsl_any_ownership_entry_exists(&self, machine_name: &str) -> AppResult<bool> {
        for ownership_basis in [
            WindowsWslOwnershipBasis::InitIntent,
            WindowsWslOwnershipBasis::ProvenMachine,
        ] {
            if private_entry_exists(
                &self.windows_wsl_ownership_proof_path(machine_name, ownership_basis),
            )? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn windows_wsl_ownership_entry_exists(
        &self,
        machine_name: &str,
        ownership_basis: WindowsWslOwnershipBasis,
    ) -> AppResult<bool> {
        private_entry_exists(&self.windows_wsl_ownership_proof_path(machine_name, ownership_basis))
    }

    fn expected_windows_wsl_ownership_proof(
        &self,
        target: &ManagedTarget,
        machine_name: &str,
        ownership_basis: WindowsWslOwnershipBasis,
    ) -> WindowsWslOwnershipProof {
        WindowsWslOwnershipProof {
            schema_version: WINDOWS_WSL_OWNERSHIP_PROOF_SCHEMA.into(),
            bundle_id: self.loaded.manifest.bundle_id.clone(),
            runtime_version: self.loaded.manifest.runtime_version.clone(),
            manifest_sha256: self.loaded.sha256.clone(),
            machine_name: machine_name.into(),
            distribution_name: format!("podman-{machine_name}"),
            machine_image_sha256: target.machine_image.sha256.clone(),
            operating_system: target.operating_system,
            architecture: target.architecture,
            provider: target.provider,
            ownership_basis,
        }
    }

    fn ensure_windows_wsl_ownership_proof_locked(
        &self,
        target: &ManagedTarget,
        machine_name: &str,
        ownership_basis: WindowsWslOwnershipBasis,
    ) -> AppResult<()> {
        if target.operating_system != ManagedOperatingSystem::Windows {
            return Ok(());
        }
        if target.provider != ManagedMachineProvider::Wsl {
            return Err(AppError::NotAuthorized(
                "managed Windows runtime target did not use the WSL provider".into(),
            ));
        }
        let proof =
            self.expected_windows_wsl_ownership_proof(target, machine_name, ownership_basis);
        let bytes = serde_json::to_vec(&proof).map_err(|error| {
            AppError::Internal(format!(
                "managed Windows WSL ownership proof could not be encoded: {error}"
            ))
        })?;
        write_private_atomic(
            &self.windows_wsl_ownership_proof_path(machine_name, ownership_basis),
            &bytes,
        )
    }

    fn has_exact_windows_wsl_ownership_proof_locked(
        &self,
        target: &ManagedTarget,
        machine_name: &str,
        ownership_basis: WindowsWslOwnershipBasis,
    ) -> AppResult<bool> {
        if target.operating_system != ManagedOperatingSystem::Windows {
            return Ok(false);
        }
        let path = self.windows_wsl_ownership_proof_path(machine_name, ownership_basis);
        if !private_entry_exists(&path).map_err(retryable_ownership_proof_inspection_error)? {
            return Ok(false);
        }
        let encoded = match read_bounded_regular_bytes(
            &path,
            64 * 1024,
            "managed Windows WSL ownership proof",
        ) {
            Ok(encoded) => encoded,
            // A directory, reparse point, hard link, or oversized file cannot
            // prove ownership. Preserve it and route safely instead of turning
            // unrelated malformed state into a permanent setup gate.
            Err(AppError::NotAuthorized(_)) => return Ok(false),
            Err(error) => return Err(retryable_ownership_proof_inspection_error(error)),
        };
        let actual = match serde_json::from_slice::<WindowsWslOwnershipProof>(&encoded) {
            Ok(actual) => actual,
            Err(_) => return Ok(false),
        };
        Ok(actual
            == self.expected_windows_wsl_ownership_proof(target, machine_name, ownership_basis))
    }

    fn prove_current_windows_machine_ownership_locked(
        &self,
        target: &ManagedTarget,
        machine_name: &str,
    ) -> AppResult<()> {
        if target.operating_system != ManagedOperatingSystem::Windows {
            return Ok(());
        }
        self.require_existing_machine_ssh_identity_locked()?;
        if !self.has_exact_windows_wsl_ownership_proof_locked(
            target,
            machine_name,
            WindowsWslOwnershipBasis::ProvenMachine,
        )? {
            return Err(AppError::NotAuthorized(
                "the selected Windows scan workspace has no exact ownership proof; it was preserved"
                    .into(),
            ));
        }
        self.verify_current_windows_wsl_machine_registration_binding(machine_name)?;
        Ok(())
    }

    fn remove_windows_wsl_ownership_proof_locked(
        &self,
        target: &ManagedTarget,
        machine_name: &str,
    ) -> AppResult<()> {
        if target.operating_system == ManagedOperatingSystem::Windows {
            let parent = self.state_root.join(WINDOWS_WSL_OWNERSHIP_DIRECTORY);
            let mut first_error = None;
            for ownership_basis in [
                WindowsWslOwnershipBasis::InitIntent,
                WindowsWslOwnershipBasis::ProvenMachine,
            ] {
                if let Err(error) = remove_regular_file(
                    &self.windows_wsl_ownership_proof_path(machine_name, ownership_basis),
                ) {
                    first_error.get_or_insert(error);
                }
            }
            let sync_result = if private_entry_exists(&parent)? {
                sync_directory(&parent)
            } else {
                Ok(())
            };
            if let Err(error) = sync_result {
                first_error.get_or_insert(error);
            }
            if let Some(error) = first_error {
                return Err(error);
            }
        }
        Ok(())
    }

    fn remove_windows_wsl_ownership_basis_proof_locked(
        &self,
        target: &ManagedTarget,
        machine_name: &str,
        ownership_basis: WindowsWslOwnershipBasis,
    ) -> AppResult<()> {
        if target.operating_system != ManagedOperatingSystem::Windows {
            return Ok(());
        }
        let parent = self.state_root.join(WINDOWS_WSL_OWNERSHIP_DIRECTORY);
        remove_regular_file(&self.windows_wsl_ownership_proof_path(machine_name, ownership_basis))?;
        if private_entry_exists(&parent)? {
            sync_directory(&parent)?;
        }
        Ok(())
    }

    fn windows_provider_home_for_generation(
        &self,
        target: &ManagedTarget,
        generation_index: u32,
    ) -> PathBuf {
        let namespace = if generation_index == 0 {
            self.loaded.sha256[..16].to_owned()
        } else {
            let machine_name = self.isolated_windows_machine_name(target, generation_index);
            let suffix = machine_name
                .strip_prefix(WINDOWS_WSL_ISOLATED_MACHINE_PREFIX)
                .expect("isolated Windows machine name has fixed prefix");
            format!("{}-iso-{}", &self.loaded.sha256[..8], &suffix[..12])
        };
        self.state_root.join("provider-home").join(namespace)
    }

    fn effective_provider_home_locked(&self, target: &ManagedTarget) -> AppResult<PathBuf> {
        if target.operating_system == ManagedOperatingSystem::Windows {
            let generation_index = self
                .read_windows_wsl_generation_selection_locked(target)?
                .map(|selection| selection.generation_index)
                .unwrap_or(0);
            return Ok(self.windows_provider_home_for_generation(target, generation_index));
        }
        Ok(self
            .state_root
            .join("provider-home")
            .join(&self.loaded.sha256[..16]))
    }

    fn provider_home(&self) -> PathBuf {
        self.loaded
            .target()
            .ok()
            .and_then(|target| self.effective_provider_home_locked(target).ok())
            .unwrap_or_else(|| {
                self.state_root
                    .join("provider-home")
                    .join(&self.loaded.sha256[..16])
            })
    }

    fn canonical_application_data_root(&self) -> AppResult<PathBuf> {
        let application_data = self.state_root.parent().ok_or_else(|| {
            AppError::Internal("managed runtime state has no application-data parent".into())
        })?;
        let application_data =
            canonical_real_directory(application_data, "managed runtime application data")?;
        let state_root = canonical_real_directory(&self.state_root, "managed runtime state")?;
        if state_root.parent() != Some(application_data.as_path()) {
            return Err(AppError::NotAuthorized(
                "managed runtime state escaped its canonical application-data root".into(),
            ));
        }
        Ok(application_data)
    }

    fn machine_application_data_volume(
        &self,
        target: &ManagedTarget,
    ) -> AppResult<Option<OsString>> {
        match target.operating_system {
            ManagedOperatingSystem::Linux => {
                let application_data = self.canonical_application_data_root()?;
                Ok(Some(linux_machine_volume_spec(&application_data)?))
            }
            // Podman's AppleHV defaults already project /Users, /private, and
            // /var/folders. WSL projects Windows drives below /mnt and ignores
            // podman-machine --volume. Neither platform accepts the Linux
            // source:target contract used by the QEMU provider here.
            ManagedOperatingSystem::Macos | ManagedOperatingSystem::Windows => Ok(None),
        }
    }

    fn runtime_directory(
        &self,
        target: &ManagedTarget,
        persistent_run: &Path,
    ) -> AppResult<PathBuf> {
        if target.operating_system != ManagedOperatingSystem::Linux {
            return Ok(persistent_run.to_path_buf());
        }
        #[cfg(unix)]
        {
            let runtime = self.linux_short_runtime_directory()?;
            let socket = linux_podman_gvproxy_socket_path(&runtime, &machine_name(target));
            use std::os::unix::ffi::OsStrExt;
            if socket.as_os_str().as_bytes().len() > PODMAN_LINUX_MAX_SOCKET_PATH_BYTES {
                return Err(AppError::NotAuthorized(
                    "managed runtime Linux gvproxy socket exceeds Podman's safe path budget".into(),
                ));
            }
            ensure_linux_short_runtime_directory_at(
                &runtime,
                Path::new(LINUX_SHORT_RUNTIME_BASE),
                effective_uid(),
            )?;
            Ok(runtime)
        }
        #[cfg(not(unix))]
        Err(AppError::NotAvailable(
            "managed runtime Linux command isolation is unavailable on this host".into(),
        ))
    }

    #[cfg(unix)]
    fn linux_short_runtime_directory(&self) -> AppResult<PathBuf> {
        let state_root = canonical_real_directory(&self.state_root, "managed runtime state")?;
        Ok(linux_short_runtime_path(
            Path::new(LINUX_SHORT_RUNTIME_BASE),
            &state_root,
            &self.loaded.sha256,
            effective_uid(),
        ))
    }

    fn command_home(&self, target: &ManagedTarget) -> AppResult<PathBuf> {
        if target.operating_system != ManagedOperatingSystem::Macos {
            return Ok(self.provider_home());
        }
        #[cfg(unix)]
        {
            let state_root = canonical_real_directory(&self.state_root, "managed runtime state")?;
            // SAFETY: geteuid has no preconditions and does not dereference memory.
            let effective_uid = unsafe { libc::geteuid() };
            let home = macos_short_home_path(
                Path::new(MACOS_SHORT_HOME_BASE),
                &state_root,
                &self.loaded.sha256,
                effective_uid,
            );
            ensure_macos_short_home_directory(&home, effective_uid)?;
            let socket_alias = macos_podman_ignition_socket_alias(&home, &machine_name(target));
            use std::os::unix::ffi::OsStrExt;
            if socket_alias.as_os_str().as_bytes().len() > PODMAN_MACOS_MAX_SOCKET_PATH_BYTES {
                return Err(AppError::NotAuthorized(
                    "managed runtime macOS socket alias exceeds Podman's safe path budget".into(),
                ));
            }
            Ok(home)
        }
        #[cfg(not(unix))]
        Err(AppError::NotAvailable(
            "managed runtime macOS command isolation is unavailable on this host".into(),
        ))
    }

    fn remove_temporary_command_state_after_machine_removal_locked(
        &self,
        target: &ManagedTarget,
    ) -> AppResult<()> {
        match target.operating_system {
            ManagedOperatingSystem::Linux => {
                #[cfg(unix)]
                {
                    let runtime = self.linux_short_runtime_directory()?;
                    remove_linux_short_runtime_directory_at(
                        &runtime,
                        Path::new(LINUX_SHORT_RUNTIME_BASE),
                        effective_uid(),
                    )
                }
                #[cfg(not(unix))]
                Err(AppError::NotAvailable(
                    "managed runtime Linux command cleanup is unavailable on this host".into(),
                ))
            }
            ManagedOperatingSystem::Macos => {
                #[cfg(unix)]
                {
                    let state_root =
                        canonical_real_directory(&self.state_root, "managed runtime state")?;
                    let effective_uid = effective_uid();
                    let home = macos_short_home_path(
                        Path::new(MACOS_SHORT_HOME_BASE),
                        &state_root,
                        &self.loaded.sha256,
                        effective_uid,
                    );
                    remove_macos_short_home_directory(&home, effective_uid, &machine_name(target))
                }
                #[cfg(not(unix))]
                Err(AppError::NotAvailable(
                    "managed runtime macOS command cleanup is unavailable on this host".into(),
                ))
            }
            ManagedOperatingSystem::Windows => Ok(()),
        }
    }

    /// Podman 5.8.2 resolves `define.DefaultIdentityName` beneath its XDG data
    /// home as `containers/podman/machine/machine`. The managed command sets
    /// that XDG root to this release-private provider home.
    fn machine_ssh_identity_path(&self) -> PathBuf {
        self.provider_home()
            .join("data")
            .join("containers")
            .join("podman")
            .join("machine")
            .join(PODMAN_MACHINE_IDENTITY_NAME)
    }

    /// Called only while the manager's lifecycle lock is held. An existing VM
    /// already trusts this exact public key, so a missing or inconsistent pair
    /// must fail closed instead of silently rotating the identity.
    fn require_existing_machine_ssh_identity_locked(&self) -> AppResult<()> {
        let state = inspect_managed_ssh_identity(&self.machine_ssh_identity_path())
            .map_err(retryable_machine_identity_inspection_error)?;
        match state {
            ManagedSshIdentityState::Valid => Ok(()),
            ManagedSshIdentityState::Absent | ManagedSshIdentityState::Invalid => {
                Err(AppError::NotAuthorized(
                    "managed runtime machine SSH identity is missing or inconsistent; refusing to rotate the key of an initialized machine"
                        .into(),
                ))
            }
        }
    }

    /// Called only while the manager's lifecycle lock is held and before
    /// `podman machine init`. Regular partial/corrupt files are safe to repair
    /// because no exact managed machine exists yet; non-regular entries always
    /// fail closed.
    fn prepare_machine_ssh_identity_locked(&self) -> AppResult<()> {
        let identity = self.machine_ssh_identity_path();
        let parent = identity.parent().ok_or_else(|| {
            AppError::Internal("managed runtime SSH identity has no parent".into())
        })?;
        let data_root = self.provider_home().join("data");
        ensure_private_directory_tree(&data_root, parent)?;
        cleanup_managed_ssh_identity_temporaries(&identity)?;

        match inspect_managed_ssh_identity(&identity)? {
            ManagedSshIdentityState::Valid => return Ok(()),
            ManagedSshIdentityState::Absent => {}
            ManagedSshIdentityState::Invalid => {
                remove_repairable_managed_ssh_identity(&identity)?;
            }
        }

        generate_managed_ssh_identity(&identity)?;
        match inspect_managed_ssh_identity(&identity)? {
            ManagedSshIdentityState::Valid => Ok(()),
            ManagedSshIdentityState::Absent | ManagedSshIdentityState::Invalid => {
                Err(AppError::Runtime(
                    "managed runtime SSH identity did not verify after atomic publication".into(),
                ))
            }
        }
    }

    fn write_containers_config(
        &self,
        path: &Path,
        install: &Path,
        target: &ManagedTarget,
    ) -> AppResult<()> {
        let helper = install.join("bin");
        let config = format!(
            "[engine]\nhelper_binaries_dir = [{}]\n\n[machine]\ncpus = {}\ndisk_size = {}\nmemory = {}\nprovider = {}\n",
            toml_string(&helper)?,
            self.loaded.manifest.resources.cpus,
            self.loaded.manifest.resources.disk_size_gb,
            self.loaded.manifest.resources.memory_mb,
            toml_scalar(target.provider.argument())
        );
        write_private_atomic(path, config.as_bytes())
    }

    fn write_containers_storage_config(
        &self,
        path: &Path,
        runroot: &Path,
        graphroot: &Path,
    ) -> AppResult<()> {
        let config = format!(
            "[storage]\nrunroot = {}\ngraphroot = {}\n",
            toml_string(runroot)?,
            toml_string(graphroot)?,
        );
        write_private_atomic(path, config.as_bytes())
    }

    fn acquire_machine_image_locked(
        &self,
        target: &ManagedTarget,
        setup: Option<&ManagedRuntimeSetupController>,
    ) -> AppResult<PathBuf> {
        ensure_managed_private_directory(&self.image_cache_root())?;
        let destination = self.machine_image_path(target);
        if private_entry_exists(&destination)? {
            if verify_file_hash_size(
                &destination,
                target.machine_image.size_bytes,
                &target.machine_image.sha256,
                "cached managed runtime machine image",
            )
            .is_ok()
            {
                if let Some(setup) = setup {
                    setup.report_download(
                        target.machine_image.size_bytes,
                        target.machine_image.size_bytes,
                        target.machine_image.size_bytes,
                    )?;
                }
                return Ok(destination);
            }
            remove_private_tree(&destination, &self.image_cache_root())?;
            sync_directory(&self.image_cache_root())?;
        }
        let partial = destination.with_extension("download-part");
        match fs::symlink_metadata(&partial) {
            Ok(metadata) if !metadata.is_file() => {
                remove_private_tree(&partial, &self.image_cache_root())?;
                sync_directory(&self.image_cache_root())?;
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        let mut verified = false;
        for attempt in 0..2 {
            let mut progress = |received, total, resumed_from| match setup {
                Some(setup) => setup.report_download(received, total, resumed_from),
                None => Ok(()),
            };
            self.downloader
                .acquire(&target.machine_image, &partial, &mut progress)?;
            match verify_file_hash_size(
                &partial,
                target.machine_image.size_bytes,
                &target.machine_image.sha256,
                "downloaded managed runtime machine image",
            ) {
                Ok(()) => {
                    verified = true;
                    break;
                }
                Err(_) if attempt == 0 => {
                    remove_private_tree(&partial, &self.image_cache_root())?;
                    sync_directory(&self.image_cache_root())?;
                    if let Some(setup) = setup {
                        setup.report_download(0, target.machine_image.size_bytes, 0)?;
                    }
                }
                Err(error) => return Err(error),
            }
        }
        if !verified {
            return Err(AppError::Runtime(
                "managed runtime machine image could not be verified".into(),
            ));
        }
        fs::rename(&partial, &destination).map_err(|error| {
            AppError::Runtime(format!(
                "managed runtime machine image could not be committed: {error}"
            ))
        })?;
        sync_directory(&self.image_cache_root())?;
        Ok(destination)
    }

    fn initialize_machine(
        &self,
        command: &ManagedRuntimeCommand,
        target: &ManagedTarget,
        image: &Path,
        machine_name: &str,
    ) -> AppResult<()> {
        let image = image.to_str().ok_or_else(|| {
            AppError::Runtime(
                "managed runtime machine image path is not representable for Podman".into(),
            )
        })?;
        let cpus = self.loaded.manifest.resources.cpus.to_string();
        let memory = self.loaded.manifest.resources.memory_mb.to_string();
        let disk = self.loaded.manifest.resources.disk_size_gb.to_string();
        let mut args = vec![
            OsString::from("machine"),
            OsString::from("init"),
            OsString::from("--cpus"),
            OsString::from(cpus),
            OsString::from("--memory"),
            OsString::from(memory),
            OsString::from("--disk-size"),
            OsString::from(disk),
            OsString::from("--rootful=false"),
        ];
        if let Some(volume) = self.machine_application_data_volume(target)? {
            args.extend([OsString::from("--volume"), volume]);
        }
        args.extend([
            OsString::from("--image"),
            OsString::from(image),
            OsString::from(machine_name),
        ]);
        let output = self.run_command_args(
            ManagedCommandOperation::MachineInitialization,
            command,
            &args,
            MACHINE_INIT_TIMEOUT,
        )?;
        require_success("managed runtime machine initialization", &output)
    }

    fn initialize_machine_with_one_shot_wsl_intent(
        &self,
        command: &ManagedRuntimeCommand,
        target: &ManagedTarget,
        image: &Path,
        machine_name: &str,
    ) -> Result<(), MachineInitializationAttemptFailure> {
        if target.operating_system != ManagedOperatingSystem::Windows {
            return self
                .initialize_machine(command, target, image, machine_name)
                .map_err(MachineInitializationAttemptFailure::Initialization);
        }
        self.ensure_windows_wsl_ownership_proof_locked(
            target,
            machine_name,
            WindowsWslOwnershipBasis::InitIntent,
        )
        .map_err(MachineInitializationAttemptFailure::OwnershipJournal)?;
        let initialization = self.initialize_machine(command, target, image, machine_name);
        let proven_machine = if initialization.is_ok() {
            self.verify_current_windows_wsl_machine_registration_binding(machine_name)
                .and_then(|_| {
                    self.ensure_windows_wsl_ownership_proof_locked(
                        target,
                        machine_name,
                        WindowsWslOwnershipBasis::ProvenMachine,
                    )
                })
        } else {
            Ok(())
        };
        let proof_cleanup = self.remove_windows_wsl_ownership_basis_proof_locked(
            target,
            machine_name,
            WindowsWslOwnershipBasis::InitIntent,
        );
        if let Err(error) = proof_cleanup {
            return Err(MachineInitializationAttemptFailure::OwnershipJournal(
                AppError::Runtime(format!(
                    "managed Windows WSL initialization journal processing failed: {error}"
                )),
            ));
        }
        proven_machine.map_err(MachineInitializationAttemptFailure::OwnershipJournal)?;
        initialization.map_err(MachineInitializationAttemptFailure::Initialization)
    }

    /// A fresh Windows WSL import can fail transiently even after both
    /// prerequisite probes pass. Retry that exact initialization at most once,
    /// and only after independently proving that the failed attempt did not
    /// publish either the expected WSL registration or any provider machine
    /// state. No cleanup or unregister is attempted here: ambiguous or partial
    /// state remains untouched while one fresh isolated generation is prepared
    /// automatically. A returned failure never asks the user to administer WSL.
    fn initialize_machine_with_one_bounded_windows_retry(
        &self,
        command: &ManagedRuntimeCommand,
        target: &ManagedTarget,
        image: &Path,
        machine_name: &str,
        setup: Option<&ManagedRuntimeSetupController>,
    ) -> AppResult<(ManagedRuntimeCommand, String)> {
        let first_error = match self.initialize_machine_with_one_shot_wsl_intent(
            command,
            target,
            image,
            machine_name,
        ) {
            Ok(()) => return Ok((command.clone(), machine_name.into())),
            Err(MachineInitializationAttemptFailure::Initialization(error)) => error,
            Err(MachineInitializationAttemptFailure::OwnershipJournal(error)) => {
                return Err(error);
            }
        };
        if target.operating_system != ManagedOperatingSystem::Windows {
            return Err(first_error);
        }

        if let Some(setup) = setup {
            setup.set_phase(
                ManagedRuntimeSetupPhase::Prerequisite,
                "checking Windows after a failed scan-tool initialization before one automatic retry",
            )?;
        }
        self.require_windows_wsl_prerequisite_locked(target, command, setup)?;

        let distributions = self.windows_wsl_distribution_inventory(command)?;
        let registration_inventory = self.windows_wsl_registration_inventory_with_one_retry()?;
        let mut collision_distributions = distributions.clone();
        for name in &registration_inventory.observed_distribution_names {
            if !collision_distributions
                .iter()
                .any(|observed| observed.eq_ignore_ascii_case(name))
            {
                collision_distributions.push(name.clone());
            }
        }
        let expected_distribution = format!("podman-{machine_name}");
        let distribution_present = collision_distributions
            .iter()
            .any(|distribution| distribution.eq_ignore_ascii_case(&expected_distribution));
        let registration_present =
            registration_inventory
                .registrations
                .iter()
                .any(|registration| {
                    registration
                        .distribution_name
                        .eq_ignore_ascii_case(&expected_distribution)
                });

        let machines = self.list_machines(command)?;
        // Podman 5.8.2 creates only the fixed `wsldist` parent before calling
        // `wsl --import`. The WSL client owns the per-machine child and removes
        // a newly created child on import failure. A surviving child therefore
        // means Windows did not complete that rollback; it is not safe to
        // reinterpret or recursively clean as an absent distribution.
        let generation_index = self
            .read_windows_wsl_generation_selection_locked(target)?
            .map(|selection| selection.generation_index)
            .unwrap_or(0);
        let distribution_storage =
            self.windows_wsl_distribution_storage_path(target, machine_name, generation_index);
        let partial_or_ambiguous = distribution_present
            || registration_present
            || !registration_inventory.complete
            || !machines.is_empty()
            || private_entry_exists(&distribution_storage)?;
        if partial_or_ambiguous {
            if let Some(setup) = setup {
                setup.set_phase(
                    ManagedRuntimeSetupPhase::Recovery,
                    "preserving the interrupted scan workspace and preparing a fresh isolated one",
                )?;
            }
            let fresh_machine_name = if registration_inventory.complete {
                self.select_windows_machine_generation_from_complete_inventory_locked(
                    target,
                    &machines,
                    &collision_distributions,
                    &registration_inventory.registrations,
                    true,
                )?
            } else {
                self.select_fresh_windows_machine_generation_after_runtime_failure_locked(
                    target,
                    machine_name,
                    &machines,
                    &collision_distributions,
                )?
            };
            if fresh_machine_name.eq_ignore_ascii_case(machine_name) {
                return Ok((command.clone(), machine_name.into()));
            }
            let fresh_command = self.runtime_command(target)?;
            self.prepare_machine_ssh_identity_locked()?;
            self.initialize_machine_with_one_shot_wsl_intent(
                &fresh_command,
                target,
                image,
                &fresh_machine_name,
            )
            .map_err(|error| {
                AppError::Runtime(format!(
                    "managed Windows runtime preserved an interrupted workspace, but its fresh isolated initialization did not finish: {error}"
                ))
            })?;
            return Ok((fresh_command, fresh_machine_name));
        }

        if let Some(setup) = setup {
            setup.set_phase(
                ManagedRuntimeSetupPhase::Init,
                "retrying the private scan-tool initialization once after Windows confirmed no partial workspace",
            )?;
        }
        match self.initialize_machine_with_one_shot_wsl_intent(command, target, image, machine_name)
        {
            Ok(()) => Ok((command.clone(), machine_name.into())),
            Err(MachineInitializationAttemptFailure::OwnershipJournal(error)) => Err(error),
            Err(MachineInitializationAttemptFailure::Initialization(retry_error)) => {
                Err(AppError::Runtime(format!(
                    "managed Windows runtime initialization failed again after one bounded automatic retry; first attempt: {first_error}; retry: {retry_error}"
                )))
            }
        }
    }

    fn list_machines(&self, command: &ManagedRuntimeCommand) -> AppResult<Vec<MachineListEntry>> {
        self.list_machines_with_timeout(command, COMMAND_TIMEOUT)
    }

    fn list_machines_with_timeout(
        &self,
        command: &ManagedRuntimeCommand,
        timeout: Duration,
    ) -> AppResult<Vec<MachineListEntry>> {
        let output = self.run_command(
            ManagedCommandOperation::MachineInventory,
            command,
            ["machine", "list", "--format", "json"],
            timeout,
        )?;
        require_success("managed runtime machine inventory", &output)?;
        serde_json::from_slice(&output.stdout).map_err(|error| {
            AppError::Runtime(format!(
                "managed runtime returned malformed machine inventory: {error}"
            ))
        })
    }

    fn list_machines_for_status(
        &self,
        command: &ManagedRuntimeCommand,
        timeout: Duration,
    ) -> Result<Vec<MachineListEntry>, StatusMachineInventoryFailure> {
        let args = ["machine", "list", "--format", "json"]
            .into_iter()
            .map(OsString::from)
            .collect::<Vec<_>>();
        let output = self
            .commands
            .output(command, &args, timeout)
            .map_err(|error| {
                let transient = matches!(
                    error.kind(),
                    io::ErrorKind::TimedOut
                        | io::ErrorKind::WouldBlock
                        | io::ErrorKind::Interrupted
                );
                let error = AppError::Runtime(format!(
                    "{} could not execute: {error}",
                    ManagedCommandOperation::MachineInventory.label()
                ));
                if transient {
                    StatusMachineInventoryFailure::Reconciliation(error)
                } else {
                    StatusMachineInventoryFailure::Invalid(error)
                }
            })?;
        require_success("managed runtime machine inventory", &output)
            .map_err(StatusMachineInventoryFailure::Invalid)?;
        serde_json::from_slice(&output.stdout).map_err(|error| {
            StatusMachineInventoryFailure::Invalid(AppError::Runtime(format!(
                "managed runtime returned malformed machine inventory: {error}"
            )))
        })
    }

    fn prove_machine_named(
        &self,
        machine: &MachineListEntry,
        target: &ManagedTarget,
        expected_name: &str,
    ) -> AppResult<()> {
        let expected_provider = target.provider.argument();
        if machine.name != expected_name
            || !machine.vm_type.eq_ignore_ascii_case(expected_provider)
            || machine.cpus != self.loaded.manifest.resources.cpus as u64
            || machine.memory != self.loaded.manifest.resources.memory_mb as u64 * 1024 * 1024
            || machine.disk_size
                != self.loaded.manifest.resources.disk_size_gb as u64 * 1024 * 1024 * 1024
        {
            return Err(AppError::NotAuthorized(format!(
                "managed runtime machine {expected_name} does not match the frozen provider and resource contract"
            )));
        }
        Ok(())
    }

    fn running_containers(&self, command: &ManagedRuntimeCommand) -> AppResult<Vec<String>> {
        let output = self.run_command(
            ManagedCommandOperation::ActiveContainerInventory,
            command,
            ["ps", "--format", "{{.Names}}"],
            COMMAND_TIMEOUT,
        )?;
        require_success("managed runtime active-container inventory", &output)?;
        let text = bounded_utf8(&output.stdout, "managed runtime container inventory")?;
        let mut containers = Vec::new();
        for line in text.lines().map(str::trim).filter(|line| !line.is_empty()) {
            if line.len() > 256 || line.contains(['\0', '\r', '\n']) {
                return Err(AppError::Runtime(
                    "managed runtime returned an invalid container name".into(),
                ));
            }
            containers.push(line.to_owned());
        }
        Ok(containers)
    }

    fn wait_for_server(
        &self,
        command: &ManagedRuntimeCommand,
        timeout: Duration,
        setup: Option<&ManagedRuntimeSetupController>,
    ) -> AppResult<String> {
        let deadline = Instant::now().checked_add(timeout).ok_or_else(|| {
            AppError::Runtime("managed runtime server readiness deadline overflowed".into())
        })?;
        let mut last_error = None;
        loop {
            if let Some(setup) = setup {
                setup.check_cancelled()?;
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            let probe_timeout = remaining.min(SERVER_READINESS_PROBE_TIMEOUT);
            match self.server_version_with_timeout(command, probe_timeout) {
                Ok(version) => return Ok(version),
                Err(error) => last_error = Some(error),
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            thread::sleep(remaining.min(SERVER_READINESS_RETRY_INTERVAL));
        }
        let last_detail = last_error
            .map(|error| error.to_string())
            .unwrap_or_else(|| "no readiness probe completed within the budget".into());
        Err(AppError::Runtime(format!(
            "managed runtime server did not become ready before its bounded deadline; last preflight: {last_detail}"
        )))
    }

    fn server_version_with_timeout(
        &self,
        command: &ManagedRuntimeCommand,
        timeout: Duration,
    ) -> AppResult<String> {
        let output = self.run_command(
            ManagedCommandOperation::VersionPreflight,
            command,
            ["version", "--format", "{{.Server.Version}}"],
            timeout,
        )?;
        require_success("managed runtime version preflight", &output)?;
        let version = bounded_utf8(&output.stdout, "managed runtime version")?
            .trim()
            .to_owned();
        if version.is_empty() || version.len() > 128 || version.contains(['\0', '\r', '\n']) {
            return Err(AppError::Runtime(
                "managed runtime returned an invalid server version".into(),
            ));
        }
        Ok(version)
    }

    fn wait_for_machine_stopped(
        &self,
        command: &ManagedRuntimeCommand,
        machine_name: &str,
        timeout: Duration,
    ) -> AppResult<()> {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            let machines = self.list_machines(command)?;
            match machines.iter().find(|machine| machine.name == machine_name) {
                None => return Ok(()),
                Some(machine) if !machine.running => return Ok(()),
                Some(_) => thread::sleep(Duration::from_millis(250)),
            }
        }
        Err(AppError::Runtime(
            "managed runtime machine did not confirm it stopped before the deadline".into(),
        ))
    }

    fn run_command<const N: usize>(
        &self,
        operation: ManagedCommandOperation,
        command: &ManagedRuntimeCommand,
        args: [&str; N],
        timeout: Duration,
    ) -> AppResult<ManagedCommandOutput> {
        let args = args.into_iter().map(OsString::from).collect::<Vec<_>>();
        self.run_command_args(operation, command, &args, timeout)
    }

    fn run_command_args(
        &self,
        operation: ManagedCommandOperation,
        command: &ManagedRuntimeCommand,
        args: &[OsString],
        timeout: Duration,
    ) -> AppResult<ManagedCommandOutput> {
        self.commands
            .output(command, args, timeout)
            .map_err(|error| {
                AppError::Runtime(format!("{} could not execute: {error}", operation.label()))
            })
    }

    fn lock(&self) -> AppResult<ManagedRuntimeLock> {
        ensure_managed_private_directory(&self.state_root)?;
        ManagedRuntimeLock::acquire(&self.state_root.join("lifecycle.lock"))
    }

    fn versions_root(&self) -> PathBuf {
        self.state_root.join("versions")
    }

    fn install_directory(&self) -> PathBuf {
        self.versions_root()
            .join(installation_directory_name(&self.loaded))
    }

    fn image_cache_root(&self) -> PathBuf {
        self.state_root.join("machine-images")
    }

    fn machine_image_path(&self, target: &ManagedTarget) -> PathBuf {
        self.image_cache_root()
            .join(format!("{}.zst", target.machine_image.sha256))
    }
}

#[cfg(unix)]
fn verify_installed_permissions(
    root: &Path,
    _versions_root: &Path,
    files: &[ManagedRuntimeFile],
) -> AppResult<()> {
    use std::os::unix::fs::PermissionsExt;

    let root_mode = fs::symlink_metadata(root)?.permissions().mode() & 0o777;
    if root_mode != 0o700 {
        return Err(AppError::NotAuthorized(
            "managed runtime install directory permissions are not private and traversable".into(),
        ));
    }
    let mut directories = BTreeSet::new();
    for entry in files {
        let path = safe_join(root, &entry.path)?;
        let expected_mode = if entry.executable { 0o500 } else { 0o400 };
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.permissions().mode() & 0o777 != expected_mode
        {
            return Err(AppError::NotAuthorized(format!(
                "managed runtime installed file permissions differ from the release contract: {}",
                entry.path
            )));
        }
        let mut parent = path.parent();
        while let Some(directory) = parent {
            if directory == root {
                break;
            }
            directories.insert(directory.to_path_buf());
            parent = directory.parent();
        }
    }
    for directory in directories {
        let metadata = fs::symlink_metadata(&directory)?;
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || metadata.permissions().mode() & 0o777 != 0o700
        {
            return Err(AppError::NotAuthorized(
                "managed runtime install contains a non-private or non-traversable directory"
                    .into(),
            ));
        }
    }
    Ok(())
}

#[cfg(windows)]
fn verify_installed_permissions(
    root: &Path,
    expected_versions_root: &Path,
    files: &[ManagedRuntimeFile],
) -> AppResult<()> {
    use windows_sys::Win32::Security::{CONTAINER_INHERIT_ACE, OBJECT_INHERIT_ACE};

    let versions_root = root.parent().ok_or_else(|| {
        AppError::NotAuthorized("managed runtime install has no versions directory".into())
    })?;
    let canonical_expected_versions =
        canonical_real_directory(expected_versions_root, "managed runtime expected versions")?;
    if versions_root != canonical_expected_versions.as_path() {
        return Err(AppError::NotAuthorized(
            "managed runtime install is outside its canonical versions directory".into(),
        ));
    }
    let inheritance = u8::try_from(OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE)
        .expect("Windows inheritance flags fit in an ACE header");

    // Keep the canonical ancestor chain and every admitted subtree object
    // pinned for this whole verification pass. This function never repairs an
    // inherited or legacy descriptor: anything except the exact protected
    // current-user policy is rejected.
    let mut directory_handles = verify_windows_managed_namespace_ancestor_chain(versions_root)
        .map_err(|error| {
            AppError::NotAuthorized(format!(
                "managed runtime installed namespace could not be verified: {error}"
            ))
        })?;
    let versions = directory_handles.first().ok_or_else(|| {
        AppError::NotAuthorized("managed runtime versions directory could not be pinned".into())
    })?;
    verify_windows_current_user_only_dacl_with_ace_flags(versions, inheritance).map_err(
        |error| {
            AppError::NotAuthorized(format!(
                "managed runtime versions directory has an unsafe Windows DACL: {error}"
            ))
        },
    )?;
    verify_windows_directory_path_identity(versions_root, versions).map_err(|error| {
        AppError::NotAuthorized(format!(
            "managed runtime versions directory identity could not be pinned: {error}"
        ))
    })?;

    let mut directories = BTreeSet::from([root.to_path_buf()]);
    for entry in files {
        let path = safe_join(root, &entry.path)?;
        let mut parent = path.parent();
        while let Some(directory) = parent {
            if directory == root {
                break;
            }
            if !directory.starts_with(root) {
                return Err(AppError::NotAuthorized(
                    "managed runtime installed directory escaped its release root".into(),
                ));
            }
            directories.insert(directory.to_path_buf());
            parent = directory.parent();
        }
    }
    let mut directories = directories.into_iter().collect::<Vec<_>>();
    directories.sort_by(|left, right| {
        left.components()
            .count()
            .cmp(&right.components().count())
            .then_with(|| left.cmp(right))
    });
    for directory in directories {
        let handle = open_windows_managed_runtime_directory(&directory, inheritance).map_err(
            |error| {
                AppError::NotAuthorized(format!(
                    "managed runtime installed directory has unsafe Windows permissions or identity: {error}"
                ))
            },
        )?;
        directory_handles.push(handle);
    }

    let manifest = open_windows_managed_runtime_file(&root.join("manifest.json"), None).map_err(
        |error| {
            AppError::NotAuthorized(format!(
                "managed runtime installed manifest has unsafe Windows permissions or identity: {error}"
            ))
        },
    )?;
    let manifest_size = windows_file_information(&manifest)?.size;
    if manifest_size == 0 || manifest_size > MAX_MANIFEST_BYTES {
        return Err(AppError::NotAuthorized(
            "managed runtime installed manifest is empty or oversized".into(),
        ));
    }
    let mut file_handles = Vec::with_capacity(files.len() + 1);
    file_handles.push(manifest);
    for entry in files {
        let path = safe_join(root, &entry.path)?;
        let handle = open_windows_managed_runtime_file(&path, Some(entry.size_bytes)).map_err(
            |error| {
                AppError::NotAuthorized(format!(
                    "managed runtime installed file has unsafe Windows permissions or identity: {error}"
                ))
            },
        )?;
        file_handles.push(handle);
    }

    // Explicit drops document the intended lifetime: no checked directory or
    // file can be replaced until the complete subtree has passed admission.
    drop(file_handles);
    drop(directory_handles);
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn verify_installed_permissions(
    _root: &Path,
    _versions_root: &Path,
    _files: &[ManagedRuntimeFile],
) -> AppResult<()> {
    Ok(())
}

struct ManagedRuntimeLock {
    file: File,
}

impl ManagedRuntimeLock {
    fn try_acquire(path: &Path) -> AppResult<Option<Self>> {
        let file = open_nofollow_lock_file(path)?;
        let contention = fs2::lock_contended_error();
        match fs2::FileExt::try_lock_exclusive(&file) {
            Ok(()) => Ok(Some(Self { file })),
            Err(error)
                if error.kind() == contention.kind()
                    && error.raw_os_error() == contention.raw_os_error() =>
            {
                Ok(None)
            }
            Err(error) => Err(AppError::Runtime(format!(
                "managed runtime lifecycle lock failed: {error}"
            ))),
        }
    }

    fn acquire(path: &Path) -> AppResult<Self> {
        let deadline = Instant::now() + COMMAND_TIMEOUT;
        loop {
            match Self::try_acquire(path)? {
                Some(lock) => return Ok(lock),
                None => {
                    if Instant::now() >= deadline {
                        return Err(AppError::Runtime(
                            "managed runtime lifecycle is busy past its bounded deadline".into(),
                        ));
                    }
                    thread::sleep(Duration::from_millis(50));
                }
            }
        }
    }
}

fn retryable_server_readiness_error(error: AppError) -> AppError {
    AppError::NotAvailable(format!(
        "managed runtime server readiness check incomplete: {error}"
    ))
}

fn retryable_machine_start_error(error: AppError) -> AppError {
    AppError::NotAvailable(format!("managed runtime machine start incomplete: {error}"))
}

fn retryable_machine_identity_inspection_error(error: AppError) -> AppError {
    AppError::NotAvailable(format!(
        "managed runtime machine-identity check incomplete: {error}"
    ))
}

fn retryable_windows_registration_inspection_error(error: AppError) -> AppError {
    AppError::NotAvailable(format!(
        "managed runtime Windows registration binding check incomplete: {error}"
    ))
}

fn retryable_generation_selection_inspection_error(error: AppError) -> AppError {
    AppError::NotAvailable(format!(
        "managed runtime Windows generation selection unreadable: {error}"
    ))
}

fn retryable_ownership_proof_inspection_error(error: AppError) -> AppError {
    AppError::NotAvailable(format!(
        "managed runtime Windows ownership proof unreadable: {error}"
    ))
}

impl Drop for ManagedRuntimeLock {
    fn drop(&mut self) {
        let _ = fs2::FileExt::unlock(&self.file);
    }
}

#[derive(Debug, Deserialize)]
struct MachineListEntry {
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Running")]
    running: bool,
    #[serde(rename = "VMType")]
    vm_type: String,
    #[serde(rename = "CPUs")]
    cpus: u64,
    #[serde(
        rename = "Memory",
        deserialize_with = "deserialize_u64_string_or_number"
    )]
    memory: u64,
    #[serde(
        rename = "DiskSize",
        deserialize_with = "deserialize_u64_string_or_number"
    )]
    disk_size: u64,
}

fn deserialize_u64_string_or_number<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Value {
        Number(u64),
        String(String),
    }
    match Value::deserialize(deserializer)? {
        Value::Number(value) => Ok(value),
        Value::String(value) => value.parse().map_err(serde::de::Error::custom),
    }
}

fn validate_manifest(manifest: &ManagedRuntimeManifest) -> AppResult<()> {
    match manifest.schema_version.as_str() {
        LEGACY_MANIFEST_SCHEMA_VERSION => {
            if manifest.management_contract_revision.is_some() {
                return Err(AppError::Runtime(
                    "managed runtime schema 2 must not declare a management contract revision"
                        .into(),
                ));
            }
        }
        MANIFEST_SCHEMA_VERSION => {
            let revision = manifest
                .management_contract_revision
                .as_deref()
                .ok_or_else(|| {
                    AppError::Runtime(
                        "managed runtime schema 3 requires a management contract revision".into(),
                    )
                })?;
            validate_management_contract_revision(revision)?;
            if revision != MANAGEMENT_CONTRACT_REVISION {
                return Err(AppError::Runtime(format!(
                    "unsupported managed runtime management contract revision {revision}"
                )));
            }
        }
        _ => {
            return Err(AppError::Runtime(format!(
                "unsupported managed runtime manifest schema {}",
                manifest.schema_version
            )));
        }
    }
    validate_identifier(&manifest.bundle_id, "managed runtime bundle id")?;
    validate_version(&manifest.runtime_version)?;
    validate_relative_path(&manifest.driver_path)?;
    if manifest.files.is_empty() || manifest.files.len() > MAX_BUNDLE_FILES {
        return Err(AppError::Runtime(
            "managed runtime manifest has an invalid file count".into(),
        ));
    }
    let mut paths = BTreeSet::new();
    let mut total = 0_u64;
    for file in &manifest.files {
        validate_relative_path(&file.path)?;
        if !paths.insert(file.path.as_str()) {
            return Err(AppError::Runtime(format!(
                "managed runtime manifest repeats file {}",
                file.path
            )));
        }
        if file.size_bytes == 0 || file.size_bytes > MAX_BUNDLE_FILE_BYTES {
            return Err(AppError::Runtime(format!(
                "managed runtime file {} has an invalid size",
                file.path
            )));
        }
        total = total
            .checked_add(file.size_bytes)
            .ok_or_else(|| AppError::Runtime("managed runtime bundle size overflowed".into()))?;
        validate_sha256(&file.sha256, "managed runtime file digest")?;
    }
    if total > MAX_BUNDLE_BYTES {
        return Err(AppError::Runtime(
            "managed runtime bundle exceeds its maximum size".into(),
        ));
    }
    let driver = manifest
        .files
        .iter()
        .find(|file| file.path == manifest.driver_path)
        .ok_or_else(|| {
            AppError::Runtime("managed runtime driver is absent from the file manifest".into())
        })?;
    if !driver.executable {
        return Err(AppError::Runtime(
            "managed runtime driver is not declared executable".into(),
        ));
    }
    if manifest.targets.is_empty() || manifest.targets.len() > 8 {
        return Err(AppError::Runtime(
            "managed runtime manifest has an invalid target count".into(),
        ));
    }
    let mut target_keys = BTreeSet::new();
    for target in &manifest.targets {
        if !target_keys.insert((target.operating_system, target.architecture)) {
            return Err(AppError::Runtime(
                "managed runtime manifest repeats an operating-system target".into(),
            ));
        }
        match (target.operating_system, target.provider) {
            (ManagedOperatingSystem::Macos, ManagedMachineProvider::Applehv)
            | (ManagedOperatingSystem::Linux, ManagedMachineProvider::Qemu)
            | (ManagedOperatingSystem::Windows, ManagedMachineProvider::Wsl) => {}
            _ => {
                return Err(AppError::Runtime(
                    "managed runtime target uses an unsupported provider combination".into(),
                ));
            }
        }
        validate_machine_image(&target.machine_image)?;
        if let Some(prerequisite) = &target.prerequisite {
            validate_bounded_text(prerequisite, 1024, "managed runtime prerequisite")?;
        }
    }
    if manifest.components.is_empty() || manifest.components.len() > 32 {
        return Err(AppError::Runtime(
            "managed runtime manifest has an invalid component inventory".into(),
        ));
    }
    let mut component_ids = BTreeSet::new();
    let mut covered_files = BTreeSet::new();
    let mut covered_downloads = BTreeSet::new();
    for component in &manifest.components {
        validate_identifier(&component.id, "managed runtime component id")?;
        if !component_ids.insert(component.id.as_str()) {
            return Err(AppError::Runtime(
                "managed runtime component inventory repeats an id".into(),
            ));
        }
        validate_bounded_text(&component.name, 128, "managed runtime component name")?;
        validate_version(&component.version)?;
        validate_https_url(&component.repository_url, false)?;
        validate_bounded_text(
            &component.source_revision,
            128,
            "managed runtime component source revision",
        )?;
        validate_bounded_text(
            &component.license_spdx,
            128,
            "managed runtime component license",
        )?;
        validate_bounded_text(
            &component.relationship,
            512,
            "managed runtime component relationship",
        )?;
        if component.artifacts.is_empty() || component.artifacts.len() > MAX_BUNDLE_FILES + 8 {
            return Err(AppError::Runtime(format!(
                "managed runtime component {} has an invalid artifact inventory",
                component.id
            )));
        }
        for artifact in &component.artifacts {
            validate_sha256(
                &artifact.sha256,
                "managed runtime component artifact digest",
            )?;
            if artifact.size_bytes == 0 || artifact.size_bytes > MAX_MACHINE_IMAGE_BYTES {
                return Err(AppError::Runtime(
                    "managed runtime component artifact has an invalid size".into(),
                ));
            }
            match artifact.delivery {
                ManagedRuntimeArtifactDelivery::BundledFile => {
                    validate_relative_path(&artifact.locator)?;
                    let file = manifest
                        .files
                        .iter()
                        .find(|file| file.path == artifact.locator)
                        .ok_or_else(|| {
                            AppError::Runtime(format!(
                                "component {} references an unknown bundled file {}",
                                component.id, artifact.locator
                            ))
                        })?;
                    if file.sha256 != artifact.sha256 || file.size_bytes != artifact.size_bytes {
                        return Err(AppError::Runtime(format!(
                            "component {} bundled-file identity does not match {}",
                            component.id, artifact.locator
                        )));
                    }
                    covered_files.insert(artifact.locator.as_str());
                }
                ManagedRuntimeArtifactDelivery::RuntimeDownload => {
                    validate_https_url(&artifact.locator, true)?;
                    let image = manifest
                        .targets
                        .iter()
                        .map(|target| &target.machine_image)
                        .find(|image| image.url == artifact.locator)
                        .ok_or_else(|| {
                            AppError::Runtime(format!(
                                "component {} references an unknown runtime download",
                                component.id
                            ))
                        })?;
                    if image.sha256 != artifact.sha256 || image.size_bytes != artifact.size_bytes {
                        return Err(AppError::Runtime(format!(
                            "component {} runtime-download identity does not match its target",
                            component.id
                        )));
                    }
                    covered_downloads.insert(artifact.locator.as_str());
                }
            }
        }
        if let Some(source) = &component.source_archive {
            validate_https_url(&source.url, false)?;
            validate_sha256(&source.sha256, "managed runtime component source digest")?;
            if source.size_bytes == 0 || source.size_bytes > MAX_MACHINE_IMAGE_BYTES {
                return Err(AppError::Runtime(
                    "managed runtime component source archive has an invalid size".into(),
                ));
            }
        }
    }
    if manifest
        .files
        .iter()
        .any(|file| !covered_files.contains(file.path.as_str()))
        || manifest
            .targets
            .iter()
            .any(|target| !covered_downloads.contains(target.machine_image.url.as_str()))
    {
        return Err(AppError::Runtime(
            "managed runtime component inventory does not cover every distributed file and runtime download"
                .into(),
        ));
    }
    if !(1..=32).contains(&manifest.resources.cpus)
        || !(2048..=65_536).contains(&manifest.resources.memory_mb)
        || !(20..=1024).contains(&manifest.resources.disk_size_gb)
    {
        return Err(AppError::Runtime(
            "managed runtime machine resources are outside supported bounds".into(),
        ));
    }
    validate_https_url(&manifest.source.repository_url, false)?;
    validate_bounded_text(
        &manifest.source.source_revision,
        128,
        "managed runtime source revision",
    )?;
    validate_bounded_text(
        &manifest.source.license_spdx,
        128,
        "managed runtime license",
    )?;
    Ok(())
}

fn validate_current_release_manifest(manifest: &ManagedRuntimeManifest) -> AppResult<()> {
    if manifest.schema_version != MANIFEST_SCHEMA_VERSION
        || manifest.management_contract_revision.as_deref() != Some(MANAGEMENT_CONTRACT_REVISION)
    {
        return Err(AppError::NotAuthorized(
            "the bundled managed runtime does not use this release's exact management contract"
                .into(),
        ));
    }
    Ok(())
}

fn validate_machine_image(image: &ManagedMachineImage) -> AppResult<()> {
    validate_https_url(&image.url, true)?;
    validate_sha256(&image.sha256, "managed runtime machine image digest")?;
    if image.size_bytes == 0 || image.size_bytes > MAX_MACHINE_IMAGE_BYTES {
        return Err(AppError::Runtime(
            "managed runtime machine image has an invalid locked size".into(),
        ));
    }
    Ok(())
}

fn validate_https_url(value: &str, download: bool) -> AppResult<()> {
    let url = Url::parse(value)
        .map_err(|_| AppError::Runtime("managed runtime URL is malformed".into()))?;
    if url.scheme() != "https"
        || url.username() != ""
        || url.password().is_some()
        || url.fragment().is_some()
        || (download && !allowed_download_host(&url))
    {
        return Err(AppError::NotAuthorized(
            "managed runtime URL is not an approved credential-free HTTPS origin".into(),
        ));
    }
    Ok(())
}

fn allowed_download_host(url: &Url) -> bool {
    matches!(
        url.host_str()
            .map(|host| host.to_ascii_lowercase())
            .as_deref(),
        Some("github.com")
            | Some("objects.githubusercontent.com")
            | Some("release-assets.githubusercontent.com")
    )
}

fn validate_identifier(value: &str, label: &str) -> AppResult<()> {
    if value.is_empty()
        || value.len() > 64
        || !value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
    {
        return Err(AppError::Runtime(format!("{label} is invalid")));
    }
    Ok(())
}

fn validate_management_contract_revision(value: &str) -> AppResult<()> {
    let invalid = || {
        AppError::Runtime(
            "managed runtime management contract revision must be a valid date and positive revision"
                .into(),
        )
    };
    let (date, revision) = value.split_once('.').ok_or_else(invalid)?;
    if revision.is_empty()
        || revision.len() > 4
        || revision.starts_with('0')
        || !revision.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(invalid());
    }
    let mut date_parts = date.split('-');
    let year_text = date_parts.next().ok_or_else(invalid)?;
    let month_text = date_parts.next().ok_or_else(invalid)?;
    let day_text = date_parts.next().ok_or_else(invalid)?;
    if date_parts.next().is_some()
        || year_text.len() != 4
        || month_text.len() != 2
        || day_text.len() != 2
        || !year_text.bytes().all(|byte| byte.is_ascii_digit())
        || !month_text.bytes().all(|byte| byte.is_ascii_digit())
        || !day_text.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(invalid());
    }
    let year = year_text.parse::<u16>().map_err(|_| invalid())?;
    let month = month_text.parse::<u8>().map_err(|_| invalid())?;
    let day = day_text.parse::<u8>().map_err(|_| invalid())?;
    let leap_year =
        year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    let maximum_day = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap_year => 29,
        2 => 28,
        _ => return Err(invalid()),
    };
    if year == 0 || day == 0 || day > maximum_day {
        return Err(invalid());
    }
    Ok(())
}

fn validate_version(value: &str) -> AppResult<()> {
    if value.is_empty()
        || value.len() > 64
        || !value.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | '-' | '_')
        })
    {
        return Err(AppError::Runtime(
            "managed runtime version is invalid".into(),
        ));
    }
    Ok(())
}

fn validate_sha256(value: &str, label: &str) -> AppResult<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(AppError::Runtime(format!("{label} is invalid")));
    }
    Ok(())
}

fn validate_bounded_text(value: &str, maximum: usize, label: &str) -> AppResult<()> {
    if value.trim().is_empty()
        || value.len() > maximum
        || value.contains(['\0', '\r', '\n'])
        || value.chars().any(|character| character.is_control())
    {
        return Err(AppError::Runtime(format!("{label} is invalid")));
    }
    Ok(())
}

fn validate_relative_path(value: &str) -> AppResult<()> {
    if value.is_empty() || value.len() > 1024 || value.contains(['\\', '\0', '\r', '\n']) {
        return Err(AppError::Runtime(
            "managed runtime bundle path is invalid".into(),
        ));
    }
    let path = Path::new(value);
    if path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(AppError::Runtime(
            "managed runtime bundle path must remain relative".into(),
        ));
    }
    Ok(())
}

fn safe_join(root: &Path, relative: &str) -> AppResult<PathBuf> {
    validate_relative_path(relative)?;
    Ok(root.join(relative))
}

fn verify_bundle_files(root: &Path, files: &[ManagedRuntimeFile]) -> AppResult<()> {
    let canonical_root = canonical_real_directory(root, "managed runtime bundle")?;
    for entry in files {
        let path = safe_join(&canonical_root, &entry.path)?;
        verify_file_hash_size(
            &path,
            entry.size_bytes,
            &entry.sha256,
            "managed runtime bundle file",
        )?;
        let canonical = path.canonicalize()?;
        if !canonical.starts_with(&canonical_root) {
            return Err(AppError::NotAuthorized(
                "managed runtime bundle file escaped its resource root".into(),
            ));
        }
    }
    Ok(())
}

fn copy_verified_file(
    source: &Path,
    destination: &Path,
    entry: &ManagedRuntimeFile,
) -> AppResult<()> {
    verify_regular_file(source, "managed runtime release file")?;
    let mut input = File::open(source)?;
    let mut output = create_private_file(destination)?;
    let mut hasher = Sha256::new();
    let mut copied = 0_u64;
    let mut buffer = [0_u8; 128 * 1024];
    loop {
        let read = input.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        copied = copied
            .checked_add(read as u64)
            .ok_or_else(|| AppError::Runtime("managed runtime file size overflowed".into()))?;
        if copied > entry.size_bytes {
            return Err(AppError::NotAuthorized(format!(
                "managed runtime file {} exceeded its locked size",
                entry.path
            )));
        }
        hasher.update(&buffer[..read]);
        output.write_all(&buffer[..read])?;
    }
    output.flush()?;
    output.sync_all()?;
    let digest = hex::encode(hasher.finalize());
    if copied != entry.size_bytes || !digest.eq_ignore_ascii_case(&entry.sha256) {
        return Err(AppError::NotAuthorized(format!(
            "managed runtime file {} failed its size or SHA-256 check",
            entry.path
        )));
    }
    // FILE_SHARE_NONE keeps a Windows private file unavailable while it is
    // populated. Close that handle before updating path-based attributes.
    drop(output);
    set_installed_permissions(destination, entry.executable)?;
    Ok(())
}

fn verify_file_hash_size(path: &Path, size: u64, digest: &str, label: &str) -> AppResult<()> {
    verify_file_hash_size_with_progress(path, size, digest, label, &mut |_, _| Ok(()))
}

fn verify_file_hash_size_with_progress(
    path: &Path,
    size: u64,
    digest: &str,
    label: &str,
    progress: &mut dyn FnMut(u64, u64) -> AppResult<()>,
) -> AppResult<()> {
    verify_regular_file(path, label)?;
    let metadata = fs::symlink_metadata(path)?;
    if metadata.len() != size {
        return Err(AppError::NotAuthorized(format!(
            "{label} has a size that differs from the release manifest"
        )));
    }
    let mut file = File::open(path)?;
    let opened = file.metadata()?;
    if !opened.is_file() || opened.len() != size {
        return Err(AppError::NotAuthorized(format!(
            "{label} changed while it was being opened"
        )));
    }
    let mut hasher = Sha256::new();
    let mut copied = 0_u64;
    let mut next_progress = 0_u64;
    let mut buffer = [0_u8; 128 * 1024];
    progress(0, size)?;
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        copied = copied
            .checked_add(read as u64)
            .ok_or_else(|| AppError::Runtime(format!("{label} size overflowed while hashing")))?;
        if copied > size {
            return Err(AppError::NotAuthorized(format!(
                "{label} grew beyond its locked size while hashing"
            )));
        }
        hasher.update(&buffer[..read]);
        if copied >= next_progress || copied == size {
            progress(copied, size)?;
            next_progress = copied.saturating_add(16 * 1024 * 1024);
        }
    }
    let actual = hex::encode(hasher.finalize());
    if copied != size || !actual.eq_ignore_ascii_case(digest) {
        return Err(AppError::NotAuthorized(format!(
            "{label} failed its SHA-256 check"
        )));
    }
    Ok(())
}

fn verify_regular_file(path: &Path, label: &str) -> AppResult<()> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| AppError::NotAvailable(format!("{label} is unavailable: {error}")))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(AppError::NotAuthorized(format!(
            "{label} must be a real regular file"
        )));
    }
    Ok(())
}

fn read_bounded_private_json<T: DeserializeOwned>(
    path: &Path,
    max_bytes: u64,
    label: &str,
) -> AppResult<T> {
    let encoded = read_bounded_regular_bytes(path, max_bytes, label)?;
    serde_json::from_slice(&encoded)
        .map_err(|error| AppError::NotAuthorized(format!("{label} is malformed: {error}")))
}

fn read_bounded_regular_bytes(path: &Path, max_bytes: u64, label: &str) -> AppResult<Vec<u8>> {
    #[cfg(windows)]
    {
        let snapshot = match inspect_managed_ssh_identity_file(
            path,
            max_bytes,
            label,
            ManagedSshIdentityFileKind::Private,
        )? {
            ManagedSshIdentityFileState::Bounded(snapshot) => snapshot,
            ManagedSshIdentityFileState::Absent => {
                return Err(AppError::NotAvailable(format!("{label} is unavailable")));
            }
            ManagedSshIdentityFileState::Invalid => {
                return Err(AppError::NotAuthorized(format!(
                    "{label} has an invalid size"
                )));
            }
        };
        let bytes = read_managed_ssh_identity_file(
            path,
            snapshot,
            max_bytes,
            label,
            ManagedSshIdentityFileKind::Private,
        )?;
        Ok(bytes.to_vec())
    }

    #[cfg(not(windows))]
    {
        verify_regular_file(path, label)?;
        let metadata = fs::symlink_metadata(path)?;
        if metadata.len() == 0 || metadata.len() > max_bytes {
            return Err(AppError::NotAuthorized(format!(
                "{label} has an invalid size"
            )));
        }
        let mut encoded = Vec::with_capacity(metadata.len() as usize);
        File::open(path)?
            .take(max_bytes + 1)
            .read_to_end(&mut encoded)?;
        if encoded.len() as u64 != metadata.len() {
            return Err(AppError::NotAuthorized(format!(
                "{label} changed while it was read"
            )));
        }
        Ok(encoded)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ManagedSshIdentityState {
    Absent,
    Valid,
    Invalid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ManagedSshIdentityFileState {
    Absent,
    Bounded(ManagedSshIdentityFileSnapshot),
    Invalid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ManagedSshIdentityFileKind {
    Private,
    Public,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ManagedSshIdentityFileSnapshot {
    size: u64,
    #[cfg(windows)]
    identity: WindowsFileIdentity,
}

#[cfg(windows)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct WindowsFileIdentity {
    volume_serial_number: u32,
    file_index: u64,
}

#[cfg(windows)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct WindowsFileInformation {
    identity: WindowsFileIdentity,
    size: u64,
    number_of_links: u32,
    attributes: u32,
}

#[cfg(windows)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct WindowsStableFileIdentity {
    volume_serial_number: u64,
    file_id: [u8; 16],
}

#[cfg(windows)]
struct WindowsCurrentUserSid {
    storage: Vec<u32>,
}

#[cfg(windows)]
impl WindowsCurrentUserSid {
    fn as_ptr(&self) -> windows_sys::Win32::Security::PSID {
        self.storage.as_ptr().cast_mut().cast()
    }
}

#[cfg(windows)]
struct WindowsLocalSystemSid {
    storage: Vec<u32>,
}

#[cfg(windows)]
impl WindowsLocalSystemSid {
    fn as_ptr(&self) -> windows_sys::Win32::Security::PSID {
        self.storage.as_ptr().cast_mut().cast()
    }
}

#[cfg(windows)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WindowsManagedDirectoryAclPolicy {
    CurrentUserOnly,
    CurrentUserAndLocalSystem,
}

#[cfg(windows)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WindowsManagedNamespaceAncestorAclPolicy {
    Strict,
    PinnedLocalAppDataCapability,
    ProductDataRoot,
}

#[cfg(windows)]
#[derive(Debug)]
struct WindowsManagedDirectoryGuard {
    directory: File,
    // These handles deliberately omit FILE_SHARE_DELETE. Keeping the complete
    // canonical chain alive prevents a principal with delete-child rights on
    // an ordinary LocalAppData ancestor from replacing a verified component.
    _ancestor_guards: Vec<File>,
    created: bool,
}

#[cfg(windows)]
impl std::ops::Deref for WindowsManagedDirectoryGuard {
    type Target = File;

    fn deref(&self) -> &Self::Target {
        &self.directory
    }
}

#[cfg(windows)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct WindowsLocalAppDataAncestorIdentities {
    local_app_data: WindowsFileIdentity,
    app_data: WindowsFileIdentity,
}

#[cfg(windows)]
struct WindowsCurrentUserOnlyAcl {
    raw: *mut windows_sys::Win32::Security::ACL,
}

#[cfg(windows)]
impl WindowsCurrentUserOnlyAcl {
    fn as_ptr(&self) -> *const windows_sys::Win32::Security::ACL {
        self.raw
    }
}

#[cfg(windows)]
impl Drop for WindowsCurrentUserOnlyAcl {
    fn drop(&mut self) {
        use windows_sys::Win32::Foundation::LocalFree;

        // SAFETY: SetEntriesInAclW allocated this ACL with LocalAlloc.
        unsafe {
            LocalFree(self.raw.cast());
        }
    }
}

#[cfg(windows)]
fn windows_current_user_sid() -> io::Result<WindowsCurrentUserSid> {
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use windows_sys::Win32::Foundation::ERROR_INSUFFICIENT_BUFFER;
    use windows_sys::Win32::Security::{
        CopySid, GetLengthSid, GetTokenInformation, IsValidSid, TOKEN_QUERY, TOKEN_USER, TokenUser,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let mut raw_token = std::ptr::null_mut();
    // SAFETY: GetCurrentProcess returns a process pseudo-handle and raw_token
    // points to writable storage for the newly opened token handle.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut raw_token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: OpenProcessToken returned a uniquely owned kernel handle.
    let token = unsafe { OwnedHandle::from_raw_handle(raw_token) };

    let mut required = 0_u32;
    // SAFETY: the null/zero probe is the documented way to obtain the required
    // TOKEN_USER buffer size; required points to initialized writable storage.
    let probe = unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            std::ptr::null_mut(),
            0,
            &raw mut required,
        )
    };
    let probe_error = io::Error::last_os_error();
    if probe != 0
        || required < std::mem::size_of::<TOKEN_USER>() as u32
        || probe_error.raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32)
    {
        return Err(if probe_error.raw_os_error().is_some() {
            probe_error
        } else {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "Windows returned an invalid current-user token size",
            )
        });
    }
    let mut token_information =
        vec![0_usize; (required as usize).div_ceil(std::mem::size_of::<usize>())];
    // SAFETY: token_information is pointer-aligned and has at least required
    // writable bytes; the token handle remains valid for the call.
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            token_information.as_mut_ptr().cast(),
            required,
            &raw mut required,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a successful TokenUser query initialized a TOKEN_USER at the
    // start of the suitably aligned buffer.
    let token_user = unsafe { &*token_information.as_ptr().cast::<TOKEN_USER>() };
    // SAFETY: the SID pointer belongs to the live token-information buffer.
    if token_user.User.Sid.is_null() || unsafe { IsValidSid(token_user.User.Sid) } == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Windows returned an invalid current-user SID",
        ));
    }
    // SAFETY: IsValidSid established that the SID pointer is valid.
    let sid_length = unsafe { GetLengthSid(token_user.User.Sid) };
    if sid_length == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Windows returned an empty current-user SID",
        ));
    }
    let mut storage = vec![0_u32; (sid_length as usize).div_ceil(std::mem::size_of::<u32>())];
    // SAFETY: storage is DWORD-aligned and contains at least sid_length bytes;
    // the source SID remains live in token_information for the call.
    if unsafe { CopySid(sid_length, storage.as_mut_ptr().cast(), token_user.User.Sid) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(WindowsCurrentUserSid { storage })
}

#[cfg(windows)]
fn windows_local_system_sid() -> io::Result<WindowsLocalSystemSid> {
    use windows_sys::Win32::Security::{
        CreateWellKnownSid, IsValidSid, IsWellKnownSid, SECURITY_MAX_SID_SIZE, WinLocalSystemSid,
    };

    let mut storage =
        vec![0_u32; (SECURITY_MAX_SID_SIZE as usize).div_ceil(std::mem::size_of::<u32>())];
    let mut length = u32::try_from(storage.len() * std::mem::size_of::<u32>()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "Windows SID buffer is too large",
        )
    })?;
    // SAFETY: storage is DWORD-aligned and exposes length writable bytes;
    // WinLocalSystemSid does not require a domain SID.
    if unsafe {
        CreateWellKnownSid(
            WinLocalSystemSid,
            std::ptr::null_mut(),
            storage.as_mut_ptr().cast(),
            &raw mut length,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let sid = WindowsLocalSystemSid { storage };
    // SAFETY: CreateWellKnownSid initialized the SID in storage and storage
    // remains live for both validation calls.
    if length == 0
        || length as usize > sid.storage.len() * std::mem::size_of::<u32>()
        || unsafe { IsValidSid(sid.as_ptr()) } == 0
        || unsafe { IsWellKnownSid(sid.as_ptr(), WinLocalSystemSid) } == 0
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Windows returned an invalid LocalSystem SID",
        ));
    }
    Ok(sid)
}

#[cfg(windows)]
fn windows_current_user_only_acl(
    user: &WindowsCurrentUserSid,
) -> io::Result<WindowsCurrentUserOnlyAcl> {
    use windows_sys::Win32::Security::NO_INHERITANCE;

    windows_current_user_acl(user, NO_INHERITANCE, 0)
}

#[cfg(windows)]
fn windows_current_user_acl(
    user: &WindowsCurrentUserSid,
    inheritance: u32,
    expected_ace_flags: u8,
) -> io::Result<WindowsCurrentUserOnlyAcl> {
    use std::ffi::c_void;
    use windows_sys::Win32::Security::Authorization::{
        EXPLICIT_ACCESS_W, NO_MULTIPLE_TRUSTEE, SET_ACCESS, SetEntriesInAclW, TRUSTEE_IS_SID,
        TRUSTEE_IS_USER, TRUSTEE_W,
    };
    use windows_sys::Win32::Security::{
        ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_SIZE_INFORMATION, AclSizeInformation, EqualSid,
        GetAce, GetAclInformation, GetLengthSid, IsValidAcl, IsValidSid,
    };
    use windows_sys::Win32::Storage::FileSystem::FILE_ALL_ACCESS;
    use windows_sys::Win32::System::SystemServices::ACCESS_ALLOWED_ACE_TYPE;

    let explicit = EXPLICIT_ACCESS_W {
        grfAccessPermissions: FILE_ALL_ACCESS,
        grfAccessMode: SET_ACCESS,
        grfInheritance: inheritance,
        Trustee: TRUSTEE_W {
            pMultipleTrustee: std::ptr::null_mut(),
            MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: TRUSTEE_IS_USER,
            // TRUSTEE_W reuses this field for a SID when TrusteeForm is
            // TRUSTEE_IS_SID; no UTF-16 string is read in that form.
            ptstrName: user.as_ptr().cast(),
        },
    };
    let mut raw = std::ptr::null_mut::<ACL>();
    // SAFETY: explicit is fully initialized, user remains live, and raw is
    // writable output storage. A null old ACL requests a fresh one-entry ACL.
    let status =
        unsafe { SetEntriesInAclW(1, &raw const explicit, std::ptr::null(), &raw mut raw) };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    if raw.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Windows returned a null current-user ACL",
        ));
    }
    let acl = WindowsCurrentUserOnlyAcl { raw };
    // Validate the provider-built ACL before it is ever attached to a security
    // descriptor. This distinguishes ACL construction from filesystem
    // inheritance behavior and keeps malformed policy from reaching CreateFileW.
    // SAFETY: acl owns the live SetEntriesInAclW allocation.
    if unsafe { IsValidAcl(acl.raw) } == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Windows built an invalid current-user ACL",
        ));
    }
    let mut information = ACL_SIZE_INFORMATION::default();
    // SAFETY: acl is valid and information is writable storage of the declared size.
    if unsafe {
        GetAclInformation(
            acl.raw,
            (&raw mut information).cast(),
            std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if information.AceCount != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Windows current-user ACL does not contain exactly one access rule",
        ));
    }
    let mut raw_ace = std::ptr::null_mut::<c_void>();
    // SAFETY: the valid ACL reports one ACE, so index zero exists.
    if unsafe { GetAce(acl.raw, 0, &raw mut raw_ace) } == 0 || raw_ace.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: GetAce returned a pointer to at least an ACE_HEADER in the live ACL.
    let header = unsafe { &*raw_ace.cast::<ACE_HEADER>() };
    if u32::from(header.AceType) != ACCESS_ALLOWED_ACE_TYPE
        || header.AceFlags != expected_ace_flags
        || usize::from(header.AceSize) < std::mem::size_of::<ACCESS_ALLOWED_ACE>()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Windows current-user ACL contains an unexpected access rule",
        ));
    }
    // SAFETY: the ACE type and size establish its fixed ACCESS_ALLOWED_ACE prefix.
    let allowed = unsafe { &*raw_ace.cast::<ACCESS_ALLOWED_ACE>() };
    let ace_sid = std::ptr::addr_of!(allowed.SidStart).cast_mut().cast();
    // SAFETY: the fixed prefix is bounded by a valid ACL and user owns a valid SID.
    if allowed.Mask != FILE_ALL_ACCESS
        || unsafe { IsValidSid(ace_sid) } == 0
        || unsafe { EqualSid(ace_sid, user.as_ptr()) } == 0
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Windows current-user ACL was built for the wrong principal",
        ));
    }
    // SAFETY: both SIDs were validated above.
    let user_sid_length = unsafe { GetLengthSid(user.as_ptr()) } as usize;
    let expected_ace_size = std::mem::size_of::<ACCESS_ALLOWED_ACE>()
        .checked_sub(std::mem::size_of::<u32>())
        .and_then(|prefix| prefix.checked_add(user_sid_length))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Windows ACE size overflowed"))?;
    if usize::from(header.AceSize) != expected_ace_size {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Windows current-user ACL contains a malformed SID boundary",
        ));
    }
    Ok(acl)
}

#[cfg(windows)]
fn windows_file_information(file: &File) -> io::Result<WindowsFileInformation> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
    };

    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: file owns a valid handle and information is a correctly sized,
    // writable BY_HANDLE_FILE_INFORMATION output buffer.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &raw mut information) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(WindowsFileInformation {
        identity: WindowsFileIdentity {
            volume_serial_number: information.dwVolumeSerialNumber,
            file_index: (u64::from(information.nFileIndexHigh) << 32)
                | u64::from(information.nFileIndexLow),
        },
        size: (u64::from(information.nFileSizeHigh) << 32) | u64::from(information.nFileSizeLow),
        number_of_links: information.nNumberOfLinks,
        attributes: information.dwFileAttributes,
    })
}

#[cfg(windows)]
fn windows_stable_file_identity(file: &File) -> io::Result<WindowsStableFileIdentity> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ID_INFO, FileIdInfo, GetFileInformationByHandleEx,
    };

    let mut information = FILE_ID_INFO::default();
    // SAFETY: file owns a live filesystem handle and information is a
    // correctly sized writable FILE_ID_INFO output buffer.
    if unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            FileIdInfo,
            (&raw mut information).cast(),
            std::mem::size_of::<FILE_ID_INFO>() as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(WindowsStableFileIdentity {
        volume_serial_number: information.VolumeSerialNumber,
        file_id: information.FileId.Identifier,
    })
}

#[cfg(windows)]
fn verify_windows_directory_path_identity(path: &Path, directory: &File) -> io::Result<()> {
    let expected = windows_stable_file_identity(directory)?;
    let path_probe = open_windows_real_directory_security_handle(path)?;
    if windows_stable_file_identity(&path_probe)? != expected {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "managed runtime directory path changed while it was being pinned",
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn open_windows_managed_runtime_directory(path: &Path, inheritance: u8) -> io::Result<File> {
    let directory = open_windows_real_directory_security_handle(path)?;
    verify_windows_current_user_only_dacl_with_ace_flags(&directory, inheritance)?;
    verify_windows_directory_path_identity(path, &directory)?;
    Ok(directory)
}

#[cfg(windows)]
fn open_windows_managed_runtime_file(path: &Path, expected_size: Option<u64>) -> io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_GENERIC_READ, FILE_SHARE_READ, READ_CONTROL,
    };

    let mut options = OpenOptions::new();
    options
        .read(true)
        .access_mode(FILE_GENERIC_READ | READ_CONTROL)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    let file = options.open(path)?;
    let information = windows_file_information(&file)?;
    if information.attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT) != 0
        || information.number_of_links != 1
        || expected_size.is_some_and(|size| information.size != size)
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "managed runtime installed file is not the expected single-link real file",
        ));
    }
    verify_windows_current_user_only_dacl(&file)?;

    // The primary handle already denies write/delete sharing. Reopen the same
    // still-pinned name without following a final reparse point and bind that
    // namespace to a 128-bit stable file ID before retaining the primary.
    let path_identity = windows_stable_file_identity(&file)?;
    let mut probe_options = OpenOptions::new();
    probe_options
        .read(true)
        .access_mode(FILE_GENERIC_READ | READ_CONTROL)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    let path_probe = probe_options.open(path)?;
    if windows_stable_file_identity(&path_probe)? != path_identity
        || windows_file_information(&path_probe)? != information
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "managed runtime installed file path changed while it was being pinned",
        ));
    }
    Ok(file)
}

#[cfg(windows)]
fn verify_windows_managed_runtime_file_hash(
    file: &mut File,
    expected_size: u64,
    expected_sha256: &str,
    deadline: Instant,
    is_cancelled: &dyn Fn() -> bool,
) -> io::Result<()> {
    check_windows_launch_guard_budget(deadline, is_cancelled)?;
    let before = windows_file_information(file)?;
    if before.size != expected_size || before.number_of_links != 1 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "managed runtime installed file size or link count changed before launch",
        ));
    }

    let mut hasher = Sha256::new();
    let mut observed = 0_u64;
    let mut buffer = [0_u8; 128 * 1024];
    loop {
        check_windows_launch_guard_budget(deadline, is_cancelled)?;
        let read = file.read(&mut buffer)?;
        check_windows_launch_guard_budget(deadline, is_cancelled)?;
        if read == 0 {
            break;
        }
        observed = observed.checked_add(read as u64).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "managed runtime installed file size overflowed while hashing",
            )
        })?;
        if observed > expected_size {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "managed runtime installed file exceeded its release-locked size",
            ));
        }
        hasher.update(&buffer[..read]);
    }
    let actual = hex::encode(hasher.finalize());
    if observed != expected_size || !actual.eq_ignore_ascii_case(expected_sha256) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "managed runtime installed file failed its release-locked digest",
        ));
    }
    if windows_file_information(file)? != before {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "managed runtime installed file changed while it was being hashed",
        ));
    }
    check_windows_launch_guard_budget(deadline, is_cancelled)?;
    verify_windows_current_user_only_dacl(file)
}

#[cfg(windows)]
fn windows_owner_dacl_security_descriptor(file: &File) -> io::Result<Vec<usize>> {
    use std::ffi::c_void;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
    use windows_sys::Win32::Security::{
        DACL_SECURITY_INFORMATION, GetSecurityDescriptorLength, IsValidSecurityDescriptor,
        OWNER_SECURITY_INFORMATION,
    };

    struct LocalSecurityDescriptor(*mut c_void);

    impl Drop for LocalSecurityDescriptor {
        fn drop(&mut self) {
            // SAFETY: GetSecurityInfo allocated this descriptor with LocalAlloc.
            unsafe {
                LocalFree(self.0);
            }
        }
    }

    let requested = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
    let mut raw_descriptor = std::ptr::null_mut();
    // SAFETY: file owns a live filesystem handle; all unused optional outputs
    // are null and raw_descriptor is writable output storage. GetSecurityInfo
    // returns the descriptor in LocalAlloc storage owned by this function.
    let status = unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            requested,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &raw mut raw_descriptor,
        )
    };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    if raw_descriptor.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Windows returned a null file security descriptor",
        ));
    }
    let descriptor_guard = LocalSecurityDescriptor(raw_descriptor);
    // SAFETY: a successful GetSecurityInfo returned this live descriptor.
    if unsafe { IsValidSecurityDescriptor(descriptor_guard.0) } == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Windows returned an invalid file security descriptor",
        ));
    }
    // SAFETY: IsValidSecurityDescriptor established a valid descriptor.
    let required = unsafe { GetSecurityDescriptorLength(descriptor_guard.0) } as usize;
    if required == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Windows returned an empty file security descriptor",
        ));
    }
    let mut descriptor = vec![0_usize; required.div_ceil(std::mem::size_of::<usize>())];
    // SAFETY: descriptor is pointer-aligned and provides at least required
    // writable bytes; descriptor_guard owns that many readable source bytes.
    unsafe {
        std::ptr::copy_nonoverlapping(
            descriptor_guard.0.cast::<u8>(),
            descriptor.as_mut_ptr().cast::<u8>(),
            required,
        );
    }
    Ok(descriptor)
}

#[cfg(windows)]
fn verify_windows_current_user_only_dacl(file: &File) -> io::Result<()> {
    verify_windows_current_user_only_dacl_with_ace_flags(file, 0)
}

#[cfg(windows)]
fn verify_windows_current_user_only_dacl_allowing_defaulted_owner(file: &File) -> io::Result<()> {
    verify_windows_managed_directory_dacl_with_ace_flags(
        file,
        0,
        WindowsManagedDirectoryAclPolicy::CurrentUserOnly,
        true,
    )
}

#[cfg(windows)]
fn verify_windows_current_user_only_dacl_with_ace_flags(
    file: &File,
    expected_ace_flags: u8,
) -> io::Result<()> {
    verify_windows_managed_directory_dacl_with_ace_flags(
        file,
        expected_ace_flags,
        WindowsManagedDirectoryAclPolicy::CurrentUserOnly,
        false,
    )
}

#[cfg(windows)]
fn verify_windows_wsl_distribution_storage_dacl_with_ace_flags(
    file: &File,
    expected_ace_flags: u8,
) -> io::Result<()> {
    verify_windows_managed_directory_dacl_with_ace_flags(
        file,
        expected_ace_flags,
        WindowsManagedDirectoryAclPolicy::CurrentUserAndLocalSystem,
        false,
    )
}

#[cfg(windows)]
fn verify_windows_managed_directory_dacl_with_ace_flags(
    file: &File,
    expected_ace_flags: u8,
    policy: WindowsManagedDirectoryAclPolicy,
    allow_defaulted_owner: bool,
) -> io::Result<()> {
    use std::ffi::c_void;
    use windows_sys::Win32::Security::{
        ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_SIZE_INFORMATION, AclSizeInformation, EqualSid,
        GetAce, GetAclInformation, GetLengthSid, GetSecurityDescriptorControl,
        GetSecurityDescriptorDacl, GetSecurityDescriptorOwner, IsValidAcl, IsValidSid, PSID,
        SE_DACL_PROTECTED, SE_SELF_RELATIVE,
    };
    use windows_sys::Win32::Storage::FileSystem::FILE_ALL_ACCESS;
    use windows_sys::Win32::System::SystemServices::{
        ACCESS_ALLOWED_ACE_TYPE, SECURITY_DESCRIPTOR_REVISION,
    };

    let user = windows_current_user_sid()?;
    let local_system = if policy == WindowsManagedDirectoryAclPolicy::CurrentUserAndLocalSystem {
        let local_system = windows_local_system_sid()?;
        // SAFETY: both SID wrappers own valid, live SID storage.
        if unsafe { EqualSid(user.as_ptr(), local_system.as_ptr()) } != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "managed WSL storage cannot use LocalSystem as its interactive owner",
            ));
        }
        Some(local_system)
    } else {
        None
    };
    let mut descriptor = windows_owner_dacl_security_descriptor(file)?;
    let security_descriptor = descriptor.as_mut_ptr().cast::<c_void>();

    let mut owner = std::ptr::null_mut();
    let mut owner_defaulted = 0;
    // SAFETY: security_descriptor contains the valid descriptor returned by
    // GetKernelObjectSecurity and the output pointers are writable.
    if unsafe {
        GetSecurityDescriptorOwner(
            security_descriptor,
            &raw mut owner,
            &raw mut owner_defaulted,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if owner.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "file has no Windows owner SID",
        ));
    }
    // SAFETY: owner points inside the live descriptor buffer.
    if unsafe { IsValidSid(owner) } == 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "file has an invalid Windows owner SID",
        ));
    }
    // SAFETY: owner and user are valid SIDs backed by live aligned storage.
    if unsafe { EqualSid(owner, user.as_ptr()) } == 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "file owner is not the current Windows user",
        ));
    }
    // Product-created private entries always provide an explicit TokenUser
    // owner. Keep that provenance check separate from the actual SID check so
    // a default TokenOwner (commonly Administrators on hosted runners) cannot
    // be mistaken for an app-owned namespace.
    if owner_defaulted != 0 && !allow_defaulted_owner {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "file owner was supplied by the Windows default mechanism",
        ));
    }

    let mut control = 0_u16;
    let mut revision = 0_u32;
    // SAFETY: security_descriptor is valid and both output pointers are writable.
    if unsafe {
        GetSecurityDescriptorControl(security_descriptor, &raw mut control, &raw mut revision)
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if revision != SECURITY_DESCRIPTOR_REVISION
        || control & (SE_DACL_PROTECTED | SE_SELF_RELATIVE)
            != (SE_DACL_PROTECTED | SE_SELF_RELATIVE)
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "file DACL is not a protected self-relative revision-1 descriptor",
        ));
    }

    let mut dacl_present = 0;
    let mut dacl_defaulted = 0;
    let mut dacl = std::ptr::null_mut::<ACL>();
    // SAFETY: security_descriptor is valid and all output pointers are writable.
    if unsafe {
        GetSecurityDescriptorDacl(
            security_descriptor,
            &raw mut dacl_present,
            &raw mut dacl,
            &raw mut dacl_defaulted,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a non-null DACL returned from the valid descriptor may be passed
    // to IsValidAcl.
    if dacl_present == 0
        || dacl_defaulted != 0
        || dacl.is_null()
        || unsafe { IsValidAcl(dacl) } == 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "file does not have an explicit valid DACL",
        ));
    }

    let mut acl_information = ACL_SIZE_INFORMATION::default();
    // SAFETY: dacl is valid and acl_information is a correctly sized writable
    // ACL_SIZE_INFORMATION output buffer.
    if unsafe {
        GetAclInformation(
            dacl,
            (&raw mut acl_information).cast(),
            std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let expected_ace_count = match policy {
        WindowsManagedDirectoryAclPolicy::CurrentUserOnly => 1,
        WindowsManagedDirectoryAclPolicy::CurrentUserAndLocalSystem => 2,
    };
    if acl_information.AceCount != expected_ace_count {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("file DACL must contain exactly {expected_ace_count} explicit access rule(s)"),
        ));
    }

    let mut saw_current_user = false;
    let mut saw_local_system = false;
    for ace_index in 0..acl_information.AceCount {
        let mut raw_ace = std::ptr::null_mut::<c_void>();
        // SAFETY: ace_index is bounded by the count reported by the valid DACL
        // and raw_ace is writable output storage.
        if unsafe { GetAce(dacl, ace_index, &raw mut raw_ace) } == 0 || raw_ace.is_null() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: GetAce returned a pointer to at least an ACE_HEADER in the live DACL.
        let header = unsafe { &*raw_ace.cast::<ACE_HEADER>() };
        if u32::from(header.AceType) != ACCESS_ALLOWED_ACE_TYPE
            || header.AceFlags != expected_ace_flags
            || usize::from(header.AceSize) < std::mem::size_of::<ACCESS_ALLOWED_ACE>()
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "file DACL contains an unexpected access rule",
            ));
        }
        // SAFETY: the ACE type and minimum size establish the ACCESS_ALLOWED_ACE
        // fixed prefix, which is contained in the valid DACL.
        let allowed = unsafe { &*raw_ace.cast::<ACCESS_ALLOWED_ACE>() };
        let ace_sid: PSID = std::ptr::addr_of!(allowed.SidStart).cast_mut().cast();
        // SAFETY: ace_sid points to the SID payload of a valid, sufficiently large ACE.
        if allowed.Mask != FILE_ALL_ACCESS || unsafe { IsValidSid(ace_sid) } == 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "file DACL does not grant only the expected private access",
            ));
        }
        // SAFETY: IsValidSid established that ace_sid is a valid SID.
        let sid_length = unsafe { GetLengthSid(ace_sid) } as usize;
        let expected_ace_size = std::mem::size_of::<ACCESS_ALLOWED_ACE>()
            .checked_sub(std::mem::size_of::<u32>())
            .and_then(|prefix| prefix.checked_add(sid_length))
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "Windows ACE size overflowed")
            })?;
        if usize::from(header.AceSize) != expected_ace_size {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "file DACL contains a malformed SID boundary",
            ));
        }

        // SAFETY: ace_sid and the expected principal SIDs are valid and live.
        if unsafe { EqualSid(ace_sid, user.as_ptr()) } != 0 {
            if saw_current_user {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "file DACL contains a duplicate current-user access rule",
                ));
            }
            saw_current_user = true;
            continue;
        }
        let matches_local_system = local_system
            .as_ref()
            // SAFETY: both SIDs are valid and live for the comparison.
            .is_some_and(|system| unsafe { EqualSid(ace_sid, system.as_ptr()) } != 0);
        if matches_local_system {
            if saw_local_system {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "file DACL contains a duplicate LocalSystem access rule",
                ));
            }
            saw_local_system = true;
            continue;
        }
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "file DACL grants access to an unexpected Windows principal",
        ));
    }
    if !saw_current_user
        || (policy == WindowsManagedDirectoryAclPolicy::CurrentUserAndLocalSystem
            && !saw_local_system)
        || (policy == WindowsManagedDirectoryAclPolicy::CurrentUserOnly && saw_local_system)
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "file DACL does not contain the exact expected Windows principal set",
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn open_windows_managed_ssh_identity_file(path: &Path) -> io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ};

    let mut options = OpenOptions::new();
    options
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    options.open(path)
}

#[cfg(windows)]
fn open_windows_managed_ssh_cleanup_file(path: &Path, delete_access: bool) -> io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{
        DELETE, FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ, FILE_SHARE_DELETE, FILE_SHARE_READ,
    };

    let mut options = OpenOptions::new();
    let access = if delete_access {
        FILE_GENERIC_READ | DELETE
    } else {
        FILE_GENERIC_READ
    };
    // The staging handle denies new delete/write opens. The destination handle
    // shares delete so it remains compatible with the already-open staging
    // handle when both names refer to the same hard-linked file object.
    let sharing = if delete_access {
        FILE_SHARE_READ
    } else {
        FILE_SHARE_READ | FILE_SHARE_DELETE
    };
    options
        .read(true)
        .access_mode(access)
        .share_mode(sharing)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    options.open(path)
}

#[cfg(windows)]
fn mark_windows_file_handle_for_deletion(file: &File) -> io::Result<()> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_DISPOSITION_INFO, FileDispositionInfo, SetFileInformationByHandle,
    };

    let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
    // SAFETY: file was opened through the exact staging name with DELETE
    // access; disposition is a fully initialized input buffer of the declared
    // size. Deletion is applied to that opened link when the handle closes.
    if unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle(),
            FileDispositionInfo,
            std::ptr::addr_of!(disposition).cast(),
            std::mem::size_of::<FILE_DISPOSITION_INFO>() as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(windows)]
fn mark_windows_managed_ssh_staging_handle_for_deletion(file: &File) -> AppResult<()> {
    mark_windows_file_handle_for_deletion(file)?;
    Ok(())
}

#[cfg(windows)]
fn windows_managed_acl_verification_error(label: &str, error: io::Error) -> AppError {
    if error.raw_os_error().is_some() {
        AppError::NotAvailable(format!(
            "{label} ownership and permissions could not be inspected: {error}"
        ))
    } else {
        AppError::NotAuthorized(format!(
            "{label} has unsafe ownership or permissions: {error}"
        ))
    }
}

#[cfg(windows)]
fn windows_managed_ssh_identity_handle_information(
    file: &File,
    label: &str,
) -> AppResult<WindowsFileInformation> {
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
    };

    let information = windows_file_information(file).map_err(|error| {
        AppError::NotAvailable(format!("{label} could not be inspected by handle: {error}"))
    })?;
    if information.attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
        return Err(AppError::NotAuthorized(format!(
            "{label} must be a real regular file"
        )));
    }
    Ok(information)
}

#[cfg(windows)]
fn verify_windows_managed_ssh_identity_handle(
    file: &File,
    label: &str,
    kind: ManagedSshIdentityFileKind,
) -> AppResult<ManagedSshIdentityFileSnapshot> {
    let information = windows_managed_ssh_identity_handle_information(file, label)?;
    if information.number_of_links != 1 {
        return Err(AppError::NotAuthorized(format!(
            "{label} must not be hard-linked"
        )));
    }
    if kind == ManagedSshIdentityFileKind::Private {
        verify_windows_current_user_only_dacl(file)
            .map_err(|error| windows_managed_acl_verification_error(label, error))?;
    }
    Ok(ManagedSshIdentityFileSnapshot {
        size: information.size,
        identity: information.identity,
    })
}

#[cfg(unix)]
fn managed_ssh_identity_mode_is_safe(kind: ManagedSshIdentityFileKind, mode: u32) -> bool {
    match kind {
        ManagedSshIdentityFileKind::Private => matches!(mode, 0o400 | 0o600),
        ManagedSshIdentityFileKind::Public => matches!(mode, 0o400 | 0o444 | 0o600 | 0o644),
    }
}

fn managed_ssh_public_key_path(private_key_path: &Path) -> PathBuf {
    let mut path = private_key_path.as_os_str().to_os_string();
    path.push(".pub");
    PathBuf::from(path)
}

fn managed_ssh_identity_temporary_paths(private_key_path: &Path) -> AppResult<(PathBuf, PathBuf)> {
    let parent = private_key_path
        .parent()
        .ok_or_else(|| AppError::Internal("managed runtime SSH identity has no parent".into()))?;
    Ok((
        parent.join(".machine.private-key-new"),
        parent.join(".machine.public-key-new"),
    ))
}

fn inspect_managed_ssh_identity_file(
    path: &Path,
    maximum: u64,
    label: &str,
    kind: ManagedSshIdentityFileKind,
) -> AppResult<ManagedSshIdentityFileState> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(AppError::NotAuthorized(format!(
                    "{label} must be a real regular file"
                )));
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::{MetadataExt, PermissionsExt};
                // SAFETY: geteuid has no preconditions and does not dereference memory.
                let effective_uid = unsafe { libc::geteuid() };
                if metadata.uid() != effective_uid || metadata.nlink() != 1 {
                    return Err(AppError::NotAuthorized(format!(
                        "{label} must be owned by the current user and must not be hard-linked"
                    )));
                }
                let mode = metadata.permissions().mode() & 0o777;
                if !managed_ssh_identity_mode_is_safe(kind, mode) {
                    return Err(AppError::NotAuthorized(format!(
                        "{label} has unsafe permissions"
                    )));
                }
            }
            #[cfg(windows)]
            let snapshot = {
                let file = open_windows_managed_ssh_identity_file(path).map_err(|error| {
                    AppError::NotAvailable(format!(
                        "{label} could not be opened without following links: {error}"
                    ))
                })?;
                verify_windows_managed_ssh_identity_handle(&file, label, kind)?
            };
            #[cfg(not(windows))]
            let snapshot = ManagedSshIdentityFileSnapshot {
                size: metadata.len(),
            };
            if snapshot.size == 0 || snapshot.size > maximum {
                return Ok(ManagedSshIdentityFileState::Invalid);
            }
            Ok(ManagedSshIdentityFileState::Bounded(snapshot))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            Ok(ManagedSshIdentityFileState::Absent)
        }
        Err(error) => Err(error.into()),
    }
}

fn read_managed_ssh_identity_file(
    path: &Path,
    expected: ManagedSshIdentityFileSnapshot,
    maximum: u64,
    label: &str,
    kind: ManagedSshIdentityFileKind,
) -> AppResult<Zeroizing<Vec<u8>>> {
    #[cfg(not(windows))]
    let mut options = OpenOptions::new();
    #[cfg(not(windows))]
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    let mut file = open_windows_managed_ssh_identity_file(path).map_err(|error| {
        AppError::NotAvailable(format!(
            "{label} could not be opened without following links: {error}"
        ))
    })?;
    #[cfg(not(windows))]
    let mut file = options.open(path).map_err(|error| {
        AppError::NotAuthorized(format!(
            "{label} could not be opened without following links: {error}"
        ))
    })?;
    let expected_size = expected.size;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.len() != expected_size
        || metadata.len() == 0
        || metadata.len() > maximum
    {
        return Err(AppError::NotAuthorized(format!(
            "{label} changed while it was being verified"
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        // SAFETY: geteuid has no preconditions and does not dereference memory.
        let effective_uid = unsafe { libc::geteuid() };
        if metadata.uid() != effective_uid || metadata.nlink() != 1 {
            return Err(AppError::NotAuthorized(format!(
                "{label} ownership or link count changed while it was being verified"
            )));
        }
        let mode = metadata.permissions().mode() & 0o777;
        if !managed_ssh_identity_mode_is_safe(kind, mode) {
            return Err(AppError::NotAuthorized(format!(
                "{label} permissions changed or are unsafe"
            )));
        }
    }
    #[cfg(windows)]
    let windows_before = {
        let snapshot = verify_windows_managed_ssh_identity_handle(&file, label, kind)?;
        if snapshot != expected {
            return Err(AppError::NotAuthorized(format!(
                "{label} changed while it was being verified"
            )));
        }
        snapshot
    };
    let mut bytes = Zeroizing::new(Vec::with_capacity(metadata.len() as usize));
    (&mut file).take(maximum + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 != expected_size || bytes.len() as u64 > maximum {
        return Err(AppError::NotAuthorized(format!(
            "{label} changed while it was being read"
        )));
    }
    let after = file.metadata()?;
    if !after.is_file() || after.len() != expected_size || after.len() != metadata.len() {
        return Err(AppError::NotAuthorized(format!(
            "{label} changed while it was being read"
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        // SAFETY: geteuid has no preconditions and does not dereference memory.
        let effective_uid = unsafe { libc::geteuid() };
        let mode = after.permissions().mode() & 0o777;
        if after.dev() != metadata.dev()
            || after.ino() != metadata.ino()
            || after.uid() != effective_uid
            || after.nlink() != 1
            || !managed_ssh_identity_mode_is_safe(kind, mode)
        {
            return Err(AppError::NotAuthorized(format!(
                "{label} changed while it was being read"
            )));
        }
    }
    #[cfg(windows)]
    {
        let windows_after = verify_windows_managed_ssh_identity_handle(&file, label, kind)?;
        if windows_after != windows_before {
            return Err(AppError::NotAuthorized(format!(
                "{label} changed while it was being read"
            )));
        }
    }
    Ok(bytes)
}

fn inspect_managed_ssh_identity(private_key_path: &Path) -> AppResult<ManagedSshIdentityState> {
    let public_key_path = managed_ssh_public_key_path(private_key_path);
    let private_state = inspect_managed_ssh_identity_file(
        private_key_path,
        MAX_SSH_PRIVATE_KEY_BYTES,
        "managed runtime SSH private key",
        ManagedSshIdentityFileKind::Private,
    )?;
    let public_state = inspect_managed_ssh_identity_file(
        &public_key_path,
        MAX_SSH_PUBLIC_KEY_BYTES,
        "managed runtime SSH public key",
        ManagedSshIdentityFileKind::Public,
    )?;
    let (private_snapshot, public_snapshot) = match (private_state, public_state) {
        (ManagedSshIdentityFileState::Absent, ManagedSshIdentityFileState::Absent) => {
            return Ok(ManagedSshIdentityState::Absent);
        }
        (
            ManagedSshIdentityFileState::Bounded(private_snapshot),
            ManagedSshIdentityFileState::Bounded(public_snapshot),
        ) => (private_snapshot, public_snapshot),
        _ => return Ok(ManagedSshIdentityState::Invalid),
    };

    let private_bytes = read_managed_ssh_identity_file(
        private_key_path,
        private_snapshot,
        MAX_SSH_PRIVATE_KEY_BYTES,
        "managed runtime SSH private key",
        ManagedSshIdentityFileKind::Private,
    )?;
    let public_bytes = read_managed_ssh_identity_file(
        &public_key_path,
        public_snapshot,
        MAX_SSH_PUBLIC_KEY_BYTES,
        "managed runtime SSH public key",
        ManagedSshIdentityFileKind::Public,
    )?;
    let Ok(private_key) = PrivateKey::from_openssh(private_bytes.as_slice()) else {
        return Ok(ManagedSshIdentityState::Invalid);
    };
    let Ok(public_text) = std::str::from_utf8(public_bytes.as_slice()) else {
        return Ok(ManagedSshIdentityState::Invalid);
    };
    let Ok(public_key) = PublicKey::from_openssh(public_text) else {
        return Ok(ManagedSshIdentityState::Invalid);
    };
    if private_key.is_encrypted()
        || private_key.algorithm() != Algorithm::Ed25519
        || public_key.algorithm() != Algorithm::Ed25519
        || private_key.comment() != MANAGED_SSH_KEY_COMMENT
        || public_key.comment() != MANAGED_SSH_KEY_COMMENT
        || private_key.public_key().key_data() != public_key.key_data()
    {
        return Ok(ManagedSshIdentityState::Invalid);
    }
    Ok(ManagedSshIdentityState::Valid)
}

#[cfg(windows)]
fn remove_windows_verified_managed_ssh_identity_file_if_present(
    path: &Path,
    label: &str,
    kind: ManagedSshIdentityFileKind,
) -> AppResult<()> {
    let file = match open_windows_managed_ssh_cleanup_file(path, true) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(AppError::NotAuthorized(format!(
                "{label} could not be opened for verified cleanup: {error}"
            )));
        }
    };
    let information = windows_managed_ssh_identity_handle_information(&file, label)?;
    if information.number_of_links != 1 {
        return Err(AppError::NotAuthorized(format!(
            "{label} must not be hard-linked"
        )));
    }
    if kind == ManagedSshIdentityFileKind::Private {
        verify_windows_current_user_only_dacl(&file).map_err(|error| {
            AppError::NotAuthorized(format!(
                "{label} has unsafe Windows ownership or permissions: {error}"
            ))
        })?;
    }
    let before_delete = windows_file_information(&file)?;
    if before_delete != information {
        return Err(AppError::NotAuthorized(format!(
            "{label} changed during verified cleanup"
        )));
    }
    mark_windows_managed_ssh_staging_handle_for_deletion(&file)?;
    drop(file);
    Ok(())
}

#[cfg(windows)]
fn cleanup_windows_managed_ssh_identity_staging_file(
    staging: &Path,
    destination: &Path,
    label: &str,
    kind: ManagedSshIdentityFileKind,
) -> AppResult<()> {
    let staging_file = match open_windows_managed_ssh_cleanup_file(staging, true) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(AppError::NotAuthorized(format!(
                "{label} could not be opened for verified cleanup: {error}"
            )));
        }
    };
    let staging_information =
        windows_managed_ssh_identity_handle_information(&staging_file, label)?;
    match staging_information.number_of_links {
        1 => {
            if kind == ManagedSshIdentityFileKind::Private {
                verify_windows_current_user_only_dacl(&staging_file).map_err(|error| {
                    AppError::NotAuthorized(format!(
                        "{label} has unsafe Windows ownership or permissions: {error}"
                    ))
                })?;
            }
            let before_delete = windows_file_information(&staging_file)?;
            if before_delete != staging_information {
                return Err(AppError::NotAuthorized(format!(
                    "{label} changed during verified cleanup"
                )));
            }
            mark_windows_managed_ssh_staging_handle_for_deletion(&staging_file)?;
            drop(staging_file);
            Ok(())
        }
        2 => {
            let destination_label = format!("{label} exact published destination");
            let destination_file = open_windows_managed_ssh_cleanup_file(destination, false)
                .map_err(|error| {
                    AppError::NotAuthorized(format!(
                        "{label} must not be hard-linked outside its exact destination: {error}"
                    ))
                })?;
            let destination_information = windows_managed_ssh_identity_handle_information(
                &destination_file,
                &destination_label,
            )?;
            if destination_information.number_of_links != 2
                || destination_information.identity != staging_information.identity
            {
                return Err(AppError::NotAuthorized(format!(
                    "{label} must not be hard-linked outside its exact destination"
                )));
            }
            if kind == ManagedSshIdentityFileKind::Private {
                for (file, checked_label) in [
                    (&staging_file, label),
                    (&destination_file, destination_label.as_str()),
                ] {
                    verify_windows_current_user_only_dacl(file).map_err(|error| {
                        AppError::NotAuthorized(format!(
                            "{checked_label} has unsafe Windows ownership or permissions: {error}"
                        ))
                    })?;
                }
            }
            let staging_before_delete = windows_file_information(&staging_file)?;
            let destination_before_delete = windows_file_information(&destination_file)?;
            if staging_before_delete != staging_information
                || destination_before_delete != destination_information
            {
                return Err(AppError::NotAuthorized(format!(
                    "{label} changed during verified crash recovery"
                )));
            }
            mark_windows_managed_ssh_staging_handle_for_deletion(&staging_file)?;
            // The destination handle shares delete with the staging handle.
            // Close both so NTFS can remove only the link used to open staging.
            drop(destination_file);
            drop(staging_file);
            Ok(())
        }
        _ => Err(AppError::NotAuthorized(format!(
            "{label} must not be hard-linked"
        ))),
    }
}

#[cfg(unix)]
fn cleanup_unix_managed_ssh_identity_staging_file(
    staging: &Path,
    destination: &Path,
    label: &str,
    kind: ManagedSshIdentityFileKind,
) -> AppResult<()> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

    let open = |path: &Path| {
        let mut options = OpenOptions::new();
        options.read(true).custom_flags(libc::O_NOFOLLOW);
        options.open(path)
    };
    let staging_file = match open(staging) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(AppError::NotAuthorized(format!(
                "{label} could not be opened for verified cleanup: {error}"
            )));
        }
    };
    let staging_metadata = staging_file.metadata()?;
    let effective_uid = unsafe { libc::geteuid() };
    let staging_mode = staging_metadata.permissions().mode() & 0o777;
    if !staging_metadata.is_file() || staging_metadata.uid() != effective_uid {
        return Err(AppError::NotAuthorized(format!(
            "{label} is unsafe for verified cleanup"
        )));
    }
    match staging_metadata.nlink() {
        1 => {
            if !managed_ssh_identity_mode_is_safe(kind, staging_mode) {
                return Err(AppError::NotAuthorized(format!(
                    "{label} is unsafe for verified cleanup"
                )));
            }
            remove_regular_file(staging)
        }
        2 => {
            let destination_file = open(destination).map_err(|error| {
                AppError::NotAuthorized(format!(
                    "{label} must not be hard-linked outside its exact destination: {error}"
                ))
            })?;
            let destination_metadata = destination_file.metadata()?;
            let destination_mode = destination_metadata.permissions().mode() & 0o777;
            if !destination_metadata.is_file()
                || destination_metadata.dev() != staging_metadata.dev()
                || destination_metadata.ino() != staging_metadata.ino()
                || destination_metadata.nlink() != 2
                || destination_metadata.uid() != effective_uid
                || !managed_ssh_identity_mode_is_safe(kind, staging_mode)
                || !managed_ssh_identity_mode_is_safe(kind, destination_mode)
            {
                return Err(AppError::NotAuthorized(format!(
                    "{label} must not be hard-linked outside its exact destination"
                )));
            }
            let before_delete = fs::symlink_metadata(staging)?;
            if before_delete.dev() != staging_metadata.dev()
                || before_delete.ino() != staging_metadata.ino()
                || before_delete.nlink() != 2
            {
                return Err(AppError::NotAuthorized(format!(
                    "{label} changed during verified crash recovery"
                )));
            }
            fs::remove_file(staging)?;
            drop(destination_file);
            drop(staging_file);
            Ok(())
        }
        _ => Err(AppError::NotAuthorized(format!(
            "{label} must not be hard-linked"
        ))),
    }
}

fn cleanup_managed_ssh_identity_staging_file(
    staging: &Path,
    destination: &Path,
    maximum: u64,
    label: &str,
    kind: ManagedSshIdentityFileKind,
) -> AppResult<()> {
    #[cfg(windows)]
    {
        let _ = maximum;
        cleanup_windows_managed_ssh_identity_staging_file(staging, destination, label, kind)
    }
    #[cfg(unix)]
    {
        let _ = maximum;
        cleanup_unix_managed_ssh_identity_staging_file(staging, destination, label, kind)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = destination;
        remove_verified_managed_ssh_identity_file_if_present(staging, maximum, label, kind)
    }
}

fn remove_repairable_managed_ssh_identity(private_key_path: &Path) -> AppResult<()> {
    let public_key_path = managed_ssh_public_key_path(private_key_path);
    remove_verified_managed_ssh_identity_file_if_present(
        private_key_path,
        MAX_SSH_PRIVATE_KEY_BYTES,
        "managed runtime SSH private key",
        ManagedSshIdentityFileKind::Private,
    )?;
    remove_verified_managed_ssh_identity_file_if_present(
        &public_key_path,
        MAX_SSH_PUBLIC_KEY_BYTES,
        "managed runtime SSH public key",
        ManagedSshIdentityFileKind::Public,
    )?;
    let parent = private_key_path
        .parent()
        .ok_or_else(|| AppError::Internal("managed runtime SSH identity has no parent".into()))?;
    sync_directory(parent)
}

fn remove_verified_managed_ssh_identity_file_if_present(
    path: &Path,
    maximum: u64,
    label: &str,
    kind: ManagedSshIdentityFileKind,
) -> AppResult<()> {
    #[cfg(windows)]
    {
        let _ = maximum;
        remove_windows_verified_managed_ssh_identity_file_if_present(path, label, kind)
    }
    #[cfg(not(windows))]
    {
        match inspect_managed_ssh_identity_file(path, maximum, label, kind)? {
            ManagedSshIdentityFileState::Absent => Ok(()),
            ManagedSshIdentityFileState::Bounded(_) | ManagedSshIdentityFileState::Invalid => {
                remove_regular_file(path)
            }
        }
    }
}

fn cleanup_managed_ssh_identity_temporaries(private_key_path: &Path) -> AppResult<()> {
    let (private_temporary, public_temporary) =
        managed_ssh_identity_temporary_paths(private_key_path)?;
    cleanup_managed_ssh_identity_staging_file(
        &private_temporary,
        private_key_path,
        MAX_SSH_PRIVATE_KEY_BYTES,
        "managed runtime SSH private-key staging file",
        ManagedSshIdentityFileKind::Private,
    )?;
    cleanup_managed_ssh_identity_staging_file(
        &public_temporary,
        &managed_ssh_public_key_path(private_key_path),
        MAX_SSH_PUBLIC_KEY_BYTES,
        "managed runtime SSH public-key staging file",
        ManagedSshIdentityFileKind::Public,
    )
}

fn write_managed_ssh_identity_temporary(path: &Path, bytes: &[u8]) -> AppResult<()> {
    let mut file = create_private_file(path)?;
    file.write_all(bytes)?;
    file.flush()?;
    file.sync_all()?;
    Ok(())
}

fn publish_managed_ssh_identity_file(temporary: &Path, destination: &Path) -> AppResult<()> {
    // A same-directory hard link publishes fully written bytes atomically and
    // fails if an unexpected destination entry (including a symlink) appeared.
    fs::hard_link(temporary, destination).map_err(|error| {
        AppError::NotAuthorized(format!(
            "managed runtime SSH identity could not be published without replacing an existing entry: {error}"
        ))
    })?;
    remove_regular_file(temporary)
}

fn generate_managed_ssh_identity(private_key_path: &Path) -> AppResult<()> {
    let parent = private_key_path
        .parent()
        .ok_or_else(|| AppError::Internal("managed runtime SSH identity has no parent".into()))?;
    let public_key_path = managed_ssh_public_key_path(private_key_path);
    if private_entry_exists(private_key_path)? || private_entry_exists(&public_key_path)? {
        return Err(AppError::NotAuthorized(
            "managed runtime SSH identity destination appeared before publication".into(),
        ));
    }
    let (private_temporary, public_temporary) =
        managed_ssh_identity_temporary_paths(private_key_path)?;
    cleanup_managed_ssh_identity_temporaries(private_key_path)?;

    let mut private_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).map_err(|_| {
        AppError::Runtime("managed runtime Ed25519 SSH identity generation failed".into())
    })?;
    private_key.set_comment(MANAGED_SSH_KEY_COMMENT);
    let private_encoding = private_key.to_openssh(LineEnding::LF).map_err(|_| {
        AppError::Runtime("managed runtime OpenSSH private key encoding failed".into())
    })?;
    let mut public_encoding = private_key.public_key().to_openssh().map_err(|_| {
        AppError::Runtime("managed runtime OpenSSH public key encoding failed".into())
    })?;
    public_encoding.push('\n');
    if private_encoding.is_empty()
        || private_encoding.len() as u64 > MAX_SSH_PRIVATE_KEY_BYTES
        || public_encoding.is_empty()
        || public_encoding.len() as u64 > MAX_SSH_PUBLIC_KEY_BYTES
    {
        return Err(AppError::Runtime(
            "managed runtime generated an unexpectedly sized SSH identity".into(),
        ));
    }

    let mut public_published = false;
    let result = (|| {
        write_managed_ssh_identity_temporary(&private_temporary, private_encoding.as_bytes())?;
        write_managed_ssh_identity_temporary(&public_temporary, public_encoding.as_bytes())?;
        // Publish the public half first. A crash can therefore leave only a
        // non-secret partial pair, which the next locked setup safely repairs.
        publish_managed_ssh_identity_file(&public_temporary, &public_key_path)?;
        public_published = true;
        publish_managed_ssh_identity_file(&private_temporary, private_key_path)?;
        sync_directory(parent)
    })();
    if result.is_err() {
        let _ = cleanup_managed_ssh_identity_staging_file(
            &private_temporary,
            private_key_path,
            MAX_SSH_PRIVATE_KEY_BYTES,
            "managed runtime SSH private-key staging file",
            ManagedSshIdentityFileKind::Private,
        );
        let _ = cleanup_managed_ssh_identity_staging_file(
            &public_temporary,
            &public_key_path,
            MAX_SSH_PUBLIC_KEY_BYTES,
            "managed runtime SSH public-key staging file",
            ManagedSshIdentityFileKind::Public,
        );
        if public_published && !private_entry_exists(private_key_path).unwrap_or(true) {
            let _ = remove_verified_managed_ssh_identity_file_if_present(
                &public_key_path,
                MAX_SSH_PUBLIC_KEY_BYTES,
                "managed runtime SSH public key",
                ManagedSshIdentityFileKind::Public,
            );
        }
        let _ = sync_directory(parent);
    }
    result
}

fn windows_machine_uses_current_compatibility_generation(machine_name: &str) -> bool {
    machine_name
        .strip_prefix(WINDOWS_MACHINE_PREFIX)
        .and_then(|suffix| suffix.strip_prefix('-'))
        .is_some_and(|suffix| !suffix.is_empty())
}

fn machine_name(target: &ManagedTarget) -> String {
    let prefix = if target.operating_system == ManagedOperatingSystem::Windows {
        WINDOWS_MACHINE_PREFIX
    } else {
        MACHINE_PREFIX
    };
    let name = format!(
        "{prefix}-{}-{}-{}",
        target.operating_system.machine_name_key(),
        target.architecture.machine_name_key(),
        &target.machine_image.sha256[..MACHINE_IMAGE_ID_HEX_CHARS]
    );
    debug_assert!(name.len() <= MAX_MACHINE_NAME_BYTES);
    name
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg(any(windows, test))]
enum WindowsWslServicingCommand {
    WslInstall,
    WslUpdate,
    EnableWindowsSubsystemForLinux,
    EnableVirtualMachinePlatform,
}

#[cfg(any(windows, test))]
impl WindowsWslServicingCommand {
    fn executable_name(self) -> &'static str {
        match self {
            Self::WslInstall | Self::WslUpdate => "wsl.exe",
            Self::EnableWindowsSubsystemForLinux | Self::EnableVirtualMachinePlatform => "dism.exe",
        }
    }

    fn parameters(self) -> &'static str {
        match self {
            Self::WslInstall => "--install --no-distribution",
            Self::WslUpdate => "--update",
            Self::EnableWindowsSubsystemForLinux => {
                "/Online /Enable-Feature /FeatureName:Microsoft-Windows-Subsystem-Linux /All /NoRestart"
            }
            Self::EnableVirtualMachinePlatform => {
                "/Online /Enable-Feature /FeatureName:VirtualMachinePlatform /All /NoRestart"
            }
        }
    }

    fn timeout(self) -> Duration {
        match self {
            Self::WslInstall | Self::WslUpdate => WINDOWS_WSL_PREREQUISITE_REPAIR_TIMEOUT,
            Self::EnableWindowsSubsystemForLinux | Self::EnableVirtualMachinePlatform => {
                WINDOWS_WSL_MISSING_BINARY_STAGE_TIMEOUT
            }
        }
    }
}

#[cfg(any(windows, test))]
fn windows_wsl_servicing_commands(
    action: ManagedRuntimeSetupNextAction,
    wsl_binary_exists: bool,
) -> AppResult<Vec<WindowsWslServicingCommand>> {
    if !wsl_binary_exists {
        return match action {
            ManagedRuntimeSetupNextAction::InstallWsl
            | ManagedRuntimeSetupNextAction::EnableWslOptionalFeatures => Ok(vec![
                WindowsWslServicingCommand::EnableWindowsSubsystemForLinux,
                WindowsWslServicingCommand::EnableVirtualMachinePlatform,
            ]),
            ManagedRuntimeSetupNextAction::UpdateWsl
            | ManagedRuntimeSetupNextAction::RestartWindows
            | ManagedRuntimeSetupNextAction::RetryWslCheck => Err(AppError::InvalidRequest(
                "the selected Windows prerequisite action does not match the current WSL state"
                    .into(),
            )),
        };
    }
    match action {
        ManagedRuntimeSetupNextAction::InstallWsl
        | ManagedRuntimeSetupNextAction::EnableWslOptionalFeatures => {
            Ok(vec![WindowsWslServicingCommand::WslInstall])
        }
        ManagedRuntimeSetupNextAction::UpdateWsl => Ok(vec![WindowsWslServicingCommand::WslUpdate]),
        ManagedRuntimeSetupNextAction::RestartWindows
        | ManagedRuntimeSetupNextAction::RetryWslCheck => Err(AppError::InvalidRequest(
            "this managed runtime prerequisite cannot be changed automatically".into(),
        )),
    }
}

fn windows_wsl_repair_parameters(action: ManagedRuntimeSetupNextAction) -> AppResult<&'static str> {
    match action {
        ManagedRuntimeSetupNextAction::InstallWsl
        | ManagedRuntimeSetupNextAction::EnableWslOptionalFeatures => {
            Ok("--install --no-distribution")
        }
        ManagedRuntimeSetupNextAction::UpdateWsl => Ok("--update"),
        ManagedRuntimeSetupNextAction::RestartWindows
        | ManagedRuntimeSetupNextAction::RetryWslCheck => Err(AppError::InvalidRequest(
            "this managed runtime prerequisite cannot be changed automatically".into(),
        )),
    }
}

#[cfg(any(windows, test))]
fn bounded_windows_wsl_servicing_cooldown_remaining(
    now_unix_seconds: u64,
    deadline_unix_seconds: u64,
) -> Option<Duration> {
    let remaining = deadline_unix_seconds.checked_sub(now_unix_seconds)?;
    (remaining > 0 && remaining <= WINDOWS_WSL_SERVICING_COOLDOWN.as_secs())
        .then(|| Duration::from_secs(remaining))
}

#[cfg(any(windows, test))]
fn windows_wsl_servicing_completion_requires_restart(
    wsl_binary_existed_before_servicing: bool,
    reported_restart_required: bool,
) -> bool {
    reported_restart_required || !wsl_binary_existed_before_servicing
}

#[cfg(any(windows, test))]
fn windows_wsl_repair_result_from_exit_code(
    exit_code: u32,
) -> ManagedRuntimePrerequisiteRepairResult {
    match exit_code {
        0 => ManagedRuntimePrerequisiteRepairResult {
            outcome: ManagedRuntimePrerequisiteRepairOutcome::Completed,
            restart_required: false,
            detail: "Windows completed the requested WSL change".into(),
        },
        // Windows Installer and DISM both use these stable success codes when
        // the requested change has been accepted but requires a restart.
        1641 | 3010 | 3011 | 0x8007_0bc2 | 0x8007_0bc3 | 0xc004_000d => {
            ManagedRuntimePrerequisiteRepairResult {
                outcome: ManagedRuntimePrerequisiteRepairOutcome::Completed,
                restart_required: true,
                detail: "Windows completed the requested WSL change and needs a restart".into(),
            }
        }
        _ => ManagedRuntimePrerequisiteRepairResult {
            outcome: ManagedRuntimePrerequisiteRepairOutcome::Failed,
            restart_required: false,
            detail: format!("Windows did not complete the requested WSL change (code {exit_code})"),
        },
    }
}

#[cfg(any(windows, test))]
fn windows_wsl_repair_timeout_result() -> ManagedRuntimePrerequisiteRepairResult {
    ManagedRuntimePrerequisiteRepairResult {
        outcome: ManagedRuntimePrerequisiteRepairOutcome::Failed,
        restart_required: false,
        detail: "Windows setup completion status unavailable.".into(),
    }
}

#[cfg(windows)]
fn windows_wsl_servicing_cooldown_deadline() -> AppResult<Option<u64>> {
    use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_SUCCESS};
    use windows_sys::Win32::System::Registry::{
        HKEY_CURRENT_USER, REG_QWORD, RRF_RT_REG_QWORD, RRF_ZEROONFAILURE, RegGetValueW,
    };

    let subkey = windows_registry_wide(WINDOWS_PREREQUISITE_REGISTRY_PATH)?;
    let value_name = windows_registry_wide(WINDOWS_WSL_SERVICING_COOLDOWN_VALUE)?;
    let mut value_type = 0_u32;
    let mut deadline = 0_u64;
    let mut size = u32::try_from(std::mem::size_of::<u64>()).expect("u64 size fits u32");
    let status = unsafe {
        RegGetValueW(
            HKEY_CURRENT_USER,
            subkey.as_ptr(),
            value_name.as_ptr(),
            RRF_RT_REG_QWORD | RRF_ZEROONFAILURE,
            &raw mut value_type,
            (&raw mut deadline).cast(),
            &raw mut size,
        )
    };
    if status == ERROR_FILE_NOT_FOUND {
        return Ok(None);
    }
    if status != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(status as i32).into());
    }
    if value_type != REG_QWORD || size as usize != std::mem::size_of::<u64>() {
        return Err(AppError::NotAuthorized(
            "Windows prerequisite cooldown receipt had an invalid type or size".into(),
        ));
    }
    Ok(Some(deadline))
}

#[cfg(windows)]
fn record_windows_wsl_servicing_cooldown() -> AppResult<()> {
    use windows_sys::Win32::Foundation::ERROR_SUCCESS;
    use windows_sys::Win32::System::Registry::{
        HKEY_CURRENT_USER, KEY_SET_VALUE, REG_OPTION_NON_VOLATILE, REG_QWORD, RegCreateKeyExW,
        RegSetValueExW,
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| AppError::NotAvailable("Windows system clock is unavailable".into()))?
        .as_secs();
    let deadline = now
        .checked_add(WINDOWS_WSL_SERVICING_COOLDOWN.as_secs())
        .ok_or_else(|| AppError::Internal("Windows prerequisite cooldown overflowed".into()))?;
    let subkey = windows_registry_wide(WINDOWS_PREREQUISITE_REGISTRY_PATH)?;
    let value_name = windows_registry_wide(WINDOWS_WSL_SERVICING_COOLDOWN_VALUE)?;
    let mut raw_key = std::ptr::null_mut();
    let mut disposition = 0_u32;
    let status = unsafe {
        RegCreateKeyExW(
            HKEY_CURRENT_USER,
            subkey.as_ptr(),
            0,
            std::ptr::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_SET_VALUE,
            std::ptr::null(),
            &raw mut raw_key,
            &raw mut disposition,
        )
    };
    if status != ERROR_SUCCESS || raw_key.is_null() {
        return Err(io::Error::from_raw_os_error(status as i32).into());
    }
    let key = WindowsRegistryKey(raw_key);
    let status = unsafe {
        RegSetValueExW(
            key.0,
            value_name.as_ptr(),
            0,
            REG_QWORD,
            (&raw const deadline).cast(),
            u32::try_from(std::mem::size_of::<u64>()).expect("u64 size fits u32"),
        )
    };
    if status != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(status as i32).into());
    }
    Ok(())
}

#[cfg(windows)]
fn clear_windows_wsl_servicing_cooldown() -> AppResult<()> {
    use windows_sys::Win32::Foundation::{
        ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND, ERROR_SUCCESS,
    };
    use windows_sys::Win32::System::Registry::{
        HKEY_CURRENT_USER, KEY_SET_VALUE, RegDeleteValueW, RegOpenKeyExW,
    };

    let subkey = windows_registry_wide(WINDOWS_PREREQUISITE_REGISTRY_PATH)?;
    let value_name = windows_registry_wide(WINDOWS_WSL_SERVICING_COOLDOWN_VALUE)?;
    let mut raw_key = std::ptr::null_mut();
    let status = unsafe {
        RegOpenKeyExW(
            HKEY_CURRENT_USER,
            subkey.as_ptr(),
            0,
            KEY_SET_VALUE,
            &raw mut raw_key,
        )
    };
    if status == ERROR_FILE_NOT_FOUND || status == ERROR_PATH_NOT_FOUND {
        return Ok(());
    }
    if status != ERROR_SUCCESS || raw_key.is_null() {
        return Err(io::Error::from_raw_os_error(status as i32).into());
    }
    let key = WindowsRegistryKey(raw_key);
    let status = unsafe { RegDeleteValueW(key.0, value_name.as_ptr()) };
    if status == ERROR_SUCCESS || status == ERROR_FILE_NOT_FOUND {
        return Ok(());
    }
    Err(io::Error::from_raw_os_error(status as i32).into())
}

#[cfg(windows)]
fn active_windows_wsl_servicing_cooldown() -> AppResult<Option<Duration>> {
    // This receipt is intentionally non-authoritative. An unreadable or
    // malformed value cannot become a permanent setup gate.
    let Some(deadline) = windows_wsl_servicing_cooldown_deadline().unwrap_or_default() else {
        return Ok(None);
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| AppError::NotAvailable("Windows system clock is unavailable".into()))?
        .as_secs();
    // The receipt suppresses duplicate elevation only inside this one fixed
    // window. A corrupt value or clock rollback can never create a permanent
    // setup gate, and the fresh WSL probe remains the readiness authority.
    Ok(bounded_windows_wsl_servicing_cooldown_remaining(
        now, deadline,
    ))
}

#[cfg(not(windows))]
fn active_windows_wsl_servicing_cooldown() -> AppResult<Option<Duration>> {
    Ok(None)
}

fn repair_windows_wsl_prerequisite_with_cooldown<C, R>(
    action: ManagedRuntimeSetupNextAction,
    mut cooldown: C,
    mut repair: R,
) -> AppResult<ManagedRuntimePrerequisiteRepairResult>
where
    C: FnMut() -> AppResult<Option<Duration>>,
    R: FnMut(ManagedRuntimeSetupNextAction) -> AppResult<ManagedRuntimePrerequisiteRepairResult>,
{
    windows_wsl_repair_parameters(action)?;
    if cooldown()?.is_some() {
        return Ok(ManagedRuntimePrerequisiteRepairResult {
            outcome: ManagedRuntimePrerequisiteRepairOutcome::Failed,
            restart_required: false,
            detail: "Windows setup action already submitted. Completion status unavailable.".into(),
        });
    }
    repair(action)
}

/// Runs one product-defined WSL prerequisite sequence through Windows' standard
/// UAC prompt. A host without the inbox `wsl.exe` uses exactly the two fixed
/// Microsoft feature-enablement stages; no executable, parameter,
/// working-directory, secret, or environment input crosses the webview boundary.
pub(crate) fn repair_windows_wsl_prerequisite(
    action: ManagedRuntimeSetupNextAction,
) -> AppResult<ManagedRuntimePrerequisiteRepairResult> {
    repair_windows_wsl_prerequisite_with_cooldown(
        action,
        active_windows_wsl_servicing_cooldown,
        repair_windows_wsl_prerequisite_platform,
    )
}

/// Detects and, when Windows can do so without a separate user-authored
/// command, services the fixed WSL prerequisite needed by the packaged scan
/// tools. This is deliberately a zero-input installer boundary: all paths,
/// probes, UAC behavior, arguments, timeouts, and the servicing action are
/// selected here from trusted product code.
pub fn prepare_windows_installer_prerequisite() -> AppResult<WindowsInstallerPrerequisiteResult> {
    coordinate_windows_installer_prerequisite(
        probe_windows_installer_wsl_prerequisite,
        repair_windows_wsl_prerequisite,
    )
}

fn coordinate_windows_installer_prerequisite<P, R>(
    mut probe: P,
    mut repair: R,
) -> AppResult<WindowsInstallerPrerequisiteResult>
where
    P: FnMut() -> Result<(), WindowsWslPrerequisiteFailure>,
    R: FnMut(ManagedRuntimeSetupNextAction) -> AppResult<ManagedRuntimePrerequisiteRepairResult>,
{
    let initial_failure = match probe() {
        Ok(()) => {
            return Ok(WindowsInstallerPrerequisiteResult {
                class: WindowsInstallerPrerequisiteClass::Ready,
                detail: "Windows is ready for the local scan tools".into(),
            });
        }
        Err(failure) => failure,
    };

    if initial_failure.action == ManagedRuntimeSetupNextAction::RestartWindows {
        return Ok(WindowsInstallerPrerequisiteResult {
            class: WindowsInstallerPrerequisiteClass::RestartRequired,
            detail: initial_failure.detail(),
        });
    }
    if initial_failure.action == ManagedRuntimeSetupNextAction::RetryWslCheck {
        return Ok(WindowsInstallerPrerequisiteResult {
            class: WindowsInstallerPrerequisiteClass::Failed,
            detail: initial_failure.detail(),
        });
    }

    let repaired = repair(initial_failure.action)?;
    match repaired.outcome {
        ManagedRuntimePrerequisiteRepairOutcome::Cancelled => {
            Ok(WindowsInstallerPrerequisiteResult {
                class: WindowsInstallerPrerequisiteClass::Cancelled,
                detail: repaired.detail,
            })
        }
        ManagedRuntimePrerequisiteRepairOutcome::Failed => Ok(WindowsInstallerPrerequisiteResult {
            class: WindowsInstallerPrerequisiteClass::Failed,
            detail: repaired.detail,
        }),
        ManagedRuntimePrerequisiteRepairOutcome::Completed if repaired.restart_required => {
            Ok(WindowsInstallerPrerequisiteResult {
                class: WindowsInstallerPrerequisiteClass::RestartRequired,
                detail: repaired.detail,
            })
        }
        ManagedRuntimePrerequisiteRepairOutcome::Completed => match probe() {
            Ok(()) => Ok(WindowsInstallerPrerequisiteResult {
                class: WindowsInstallerPrerequisiteClass::Serviced,
                detail: "Windows finished preparing the local scan tools".into(),
            }),
            Err(failure) if failure.action == ManagedRuntimeSetupNextAction::RestartWindows => {
                Ok(WindowsInstallerPrerequisiteResult {
                    class: WindowsInstallerPrerequisiteClass::RestartRequired,
                    detail: failure.detail(),
                })
            }
            Err(failure) => Ok(WindowsInstallerPrerequisiteResult {
                class: WindowsInstallerPrerequisiteClass::Failed,
                detail: failure.detail(),
            }),
        },
    }
}

#[cfg(windows)]
fn probe_windows_installer_wsl_prerequisite() -> Result<(), WindowsWslPrerequisiteFailure> {
    let directories = windows_system_directories()
        .map_err(|_| WindowsWslPrerequisiteFailure::command_failed(None))?;
    let wsl_binary = directories.system32.join("wsl.exe");
    match fs::symlink_metadata(&wsl_binary) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Err(WindowsWslPrerequisiteFailure::not_installed(None));
        }
        Err(_) => return Err(WindowsWslPrerequisiteFailure::command_failed(None)),
        Ok(_) => {}
    }
    let seed = ManagedRuntimeCommand {
        binary: wsl_binary,
        environment: BTreeMap::new(),
        working_directory: directories.system32.clone(),
        runtime_version: "installer-prerequisite".into(),
        manifest_sha256: "installer-prerequisite".into(),
        machine_image_sha256: "installer-prerequisite".into(),
        windows_launch_authorization: WindowsManagedRuntimeLaunchAuthorization::MetadataOnly,
    };
    let command = windows_wsl_inventory_command_with_directories(&seed, &directories)
        .map_err(|_| WindowsWslPrerequisiteFailure::command_failed(None))?;
    let runner = DirectManagedCommandRunner;
    for arguments in [
        &[OsString::from("--status")][..],
        &[OsString::from("-l"), OsString::from("--quiet")][..],
    ] {
        let output = runner
            .output(&command, arguments, COMMAND_TIMEOUT)
            .map_err(|_| WindowsWslPrerequisiteFailure::command_failed(None))?;
        if !output.status.success() {
            return Err(classify_windows_wsl_prerequisite_failure(&output));
        }
    }
    Ok(())
}

#[cfg(not(windows))]
fn probe_windows_installer_wsl_prerequisite() -> Result<(), WindowsWslPrerequisiteFailure> {
    Err(WindowsWslPrerequisiteFailure::command_failed(None))
}

#[cfg(windows)]
fn repair_windows_wsl_prerequisite_platform(
    action: ManagedRuntimeSetupNextAction,
) -> AppResult<ManagedRuntimePrerequisiteRepairResult> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::{
        CloseHandle, ERROR_CANCELLED, HANDLE, RPC_E_CHANGED_MODE, WAIT_FAILED, WAIT_OBJECT_0,
        WAIT_TIMEOUT,
    };
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;
    use windows_sys::Win32::System::Com::{
        COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE, CoInitializeEx, CoUninitialize,
    };
    use windows_sys::Win32::System::Threading::{GetExitCodeProcess, WaitForSingleObject};
    use windows_sys::Win32::UI::Shell::{
        SEE_MASK_FLAG_NO_UI, SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW,
        ShellExecuteExW,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

    struct OwnedProcessHandle(HANDLE);

    struct ComInitializationGuard(bool);

    impl Drop for ComInitializationGuard {
        fn drop(&mut self) {
            if self.0 {
                unsafe {
                    CoUninitialize();
                }
            }
        }
    }

    impl Drop for OwnedProcessHandle {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    CloseHandle(self.0);
                }
            }
        }
    }

    fn wide_nul(value: &OsStr) -> AppResult<Vec<u16>> {
        let encoded = value.encode_wide().collect::<Vec<_>>();
        if encoded.contains(&0) {
            return Err(AppError::NotAuthorized(
                "Windows prerequisite repair input contained an invalid NUL".into(),
            ));
        }
        Ok(encoded.into_iter().chain(std::iter::once(0)).collect())
    }

    fn shell_execute_path_wide_nul(value: &OsStr) -> AppResult<Vec<u16>> {
        const VERBATIM_PREFIX: &[u16] = &[b'\\' as u16, b'\\' as u16, b'?' as u16, b'\\' as u16];
        const UNC_PREFIX: &[u16] = &[b'U' as u16, b'N' as u16, b'C' as u16, b'\\' as u16];
        let encoded = value.encode_wide().collect::<Vec<_>>();
        let shell_path = if let Some(remainder) = encoded.strip_prefix(VERBATIM_PREFIX) {
            if let Some(unc) = remainder.strip_prefix(UNC_PREFIX) {
                let mut path = vec![b'\\' as u16, b'\\' as u16];
                path.extend_from_slice(unc);
                path
            } else if remainder.len() >= 3
                && remainder[0] <= u16::from(b'z')
                && (remainder[0] as u8).is_ascii_alphabetic()
                && remainder[1] == b':' as u16
                && remainder[2] == b'\\' as u16
            {
                remainder.to_vec()
            } else {
                return Err(AppError::NotAuthorized(
                    "Windows prerequisite repair path used an unsupported namespace".into(),
                ));
            }
        } else {
            encoded
        };
        if shell_path.contains(&0) {
            return Err(AppError::NotAuthorized(
                "Windows prerequisite repair path contained an invalid NUL".into(),
            ));
        }
        Ok(shell_path.into_iter().chain(std::iter::once(0)).collect())
    }

    fn execute_fixed_servicing_command(
        directories: &WindowsSystemDirectories,
        command: WindowsWslServicingCommand,
    ) -> AppResult<ManagedRuntimePrerequisiteRepairResult> {
        let executable = directories.system32.join(command.executable_name());
        verify_regular_file(
            &executable,
            "Windows System32 prerequisite servicing executable",
        )?;
        use std::os::windows::fs::MetadataExt;
        let executable_metadata = fs::symlink_metadata(&executable).map_err(|error| {
            AppError::NotAvailable(format!(
                "Windows prerequisite servicing executable is unavailable: {error}"
            ))
        })?;
        if executable_metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(AppError::NotAuthorized(
                "Windows prerequisite servicing executable must not be a reparse point".into(),
            ));
        }

        let verb = wide_nul(OsStr::new("runas"))?;
        let executable = shell_execute_path_wide_nul(executable.as_os_str())?;
        let parameters = wide_nul(OsStr::new(command.parameters()))?;
        let working_directory = shell_execute_path_wide_nul(directories.system32.as_os_str())?;

        // Persist only a bounded timestamp before the side effect. It is not
        // readiness proof: every caller has already run the authoritative WSL
        // probe. It exists solely so a killed installer or a timed-out child
        // cannot immediately launch a duplicate elevated servicing action.
        record_windows_wsl_servicing_cooldown()?;
        let mut execution = SHELLEXECUTEINFOW {
            cbSize: u32::try_from(std::mem::size_of::<SHELLEXECUTEINFOW>())
                .expect("SHELLEXECUTEINFOW size fits u32"),
            fMask: SEE_MASK_FLAG_NO_UI | SEE_MASK_NOASYNC | SEE_MASK_NOCLOSEPROCESS,
            lpVerb: verb.as_ptr(),
            lpFile: executable.as_ptr(),
            lpParameters: parameters.as_ptr(),
            lpDirectory: working_directory.as_ptr(),
            nShow: SW_SHOWNORMAL,
            ..SHELLEXECUTEINFOW::default()
        };
        if unsafe { ShellExecuteExW(&mut execution) } == 0 {
            let error = io::Error::last_os_error();
            // No child started, so this attempt cannot overlap a later retry.
            let _ = clear_windows_wsl_servicing_cooldown();
            if error.raw_os_error() == Some(ERROR_CANCELLED as i32) {
                return Ok(ManagedRuntimePrerequisiteRepairResult {
                    outcome: ManagedRuntimePrerequisiteRepairOutcome::Cancelled,
                    restart_required: false,
                    detail: "Windows administrator confirmation cancelled.".into(),
                });
            }
            return Ok(ManagedRuntimePrerequisiteRepairResult {
                outcome: ManagedRuntimePrerequisiteRepairOutcome::Failed,
                restart_required: false,
                detail: "Windows setup change failed to start.".into(),
            });
        }
        if execution.hProcess.is_null() {
            return Ok(ManagedRuntimePrerequisiteRepairResult {
                outcome: ManagedRuntimePrerequisiteRepairOutcome::Failed,
                restart_required: false,
                detail: "Windows setup change status unavailable.".into(),
            });
        }
        let process = OwnedProcessHandle(execution.hProcess);
        let timeout_milliseconds = u32::try_from(command.timeout().as_millis())
            .expect("the fixed Windows prerequisite timeout fits a Win32 wait");
        match unsafe { WaitForSingleObject(process.0, timeout_milliseconds) } {
            WAIT_OBJECT_0 => {}
            WAIT_TIMEOUT => return Ok(windows_wsl_repair_timeout_result()),
            WAIT_FAILED => {
                return Ok(ManagedRuntimePrerequisiteRepairResult {
                    outcome: ManagedRuntimePrerequisiteRepairOutcome::Failed,
                    restart_required: false,
                    detail: "Windows setup completion status unavailable.".into(),
                });
            }
            _ => {
                return Ok(ManagedRuntimePrerequisiteRepairResult {
                    outcome: ManagedRuntimePrerequisiteRepairOutcome::Failed,
                    restart_required: false,
                    detail: "Windows returned an unexpected setup state".into(),
                });
            }
        }
        let mut exit_code = 0_u32;
        if unsafe { GetExitCodeProcess(process.0, &mut exit_code) } == 0 {
            // WAIT_OBJECT_0 proved the child terminal even though Windows did
            // not return its code. A later retry cannot overlap this process.
            let _ = clear_windows_wsl_servicing_cooldown();
            return Ok(ManagedRuntimePrerequisiteRepairResult {
                outcome: ManagedRuntimePrerequisiteRepairOutcome::Failed,
                restart_required: false,
                detail: "Windows setup result unavailable.".into(),
            });
        }
        let result = windows_wsl_repair_result_from_exit_code(exit_code);
        // A terminal child no longer needs duplicate-elevation suppression.
        // Readiness is still decided only by the caller's next WSL probe.
        let _ = clear_windows_wsl_servicing_cooldown();
        Ok(result)
    }

    let com_result = unsafe {
        CoInitializeEx(
            std::ptr::null(),
            (COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE) as u32,
        )
    };
    let _com = if com_result >= 0 {
        ComInitializationGuard(true)
    } else if com_result == RPC_E_CHANGED_MODE {
        ComInitializationGuard(false)
    } else {
        return Ok(ManagedRuntimePrerequisiteRepairResult {
            outcome: ManagedRuntimePrerequisiteRepairOutcome::Failed,
            restart_required: false,
            detail: "Windows administrator confirmation unavailable.".into(),
        });
    };

    let directories = windows_system_directories()?;
    let wsl_binary = directories.system32.join("wsl.exe");
    let wsl_binary_exists = match fs::symlink_metadata(&wsl_binary) {
        Ok(_) => true,
        Err(error) if error.kind() == io::ErrorKind::NotFound => false,
        Err(error) => return Err(error.into()),
    };
    let commands = windows_wsl_servicing_commands(action, wsl_binary_exists)?;
    let missing_binary_bootstrap = !wsl_binary_exists;
    let mut restart_required = false;
    for command in commands {
        let result = execute_fixed_servicing_command(&directories, command)?;
        if result.outcome != ManagedRuntimePrerequisiteRepairOutcome::Completed {
            if restart_required {
                return Ok(ManagedRuntimePrerequisiteRepairResult {
                    outcome: ManagedRuntimePrerequisiteRepairOutcome::Completed,
                    restart_required: true,
                    detail: "Windows completed one required setup change and needs a restart before automatic preparation can continue"
                        .into(),
                });
            }
            return Ok(result);
        }
        restart_required |= result.restart_required;
    }
    // Enabling inbox Windows features from a genuinely missing `wsl.exe`
    // requires a Windows restart before the fixed binary/probe contract can be
    // authoritative, even when DISM reports a terminal zero exit code.
    restart_required = windows_wsl_servicing_completion_requires_restart(
        !missing_binary_bootstrap,
        restart_required,
    );
    Ok(ManagedRuntimePrerequisiteRepairResult {
        outcome: ManagedRuntimePrerequisiteRepairOutcome::Completed,
        restart_required,
        detail: if restart_required {
            "Windows completed the required setup changes and needs a restart".into()
        } else {
            "Windows completed the required setup changes".into()
        },
    })
}

#[cfg(not(windows))]
fn repair_windows_wsl_prerequisite_platform(
    _action: ManagedRuntimeSetupNextAction,
) -> AppResult<ManagedRuntimePrerequisiteRepairResult> {
    Err(AppError::NotAvailable(
        "Windows prerequisite repair is unavailable on this host".into(),
    ))
}

fn linux_machine_volume_spec(application_data: &Path) -> AppResult<OsString> {
    if !application_data.is_absolute() {
        return Err(AppError::NotAuthorized(
            "managed runtime application-data mount must be absolute".into(),
        ));
    }
    let rendered = application_data.to_str().ok_or_else(|| {
        AppError::NotAvailable(
            "managed runtime application-data mount is not representable for Podman".into(),
        )
    })?;
    if rendered.contains([':', ',', '\n', '\r', '\0']) {
        return Err(AppError::NotAuthorized(
            "managed runtime application-data mount contains unsupported volume syntax".into(),
        ));
    }
    Ok(OsString::from(format!("{rendered}:{rendered}")))
}

fn installation_directory_name(loaded: &LoadedManagedRuntimeManifest) -> String {
    format!(
        "{}-{}-{}",
        loaded.manifest.bundle_id,
        loaded.manifest.runtime_version,
        &loaded.sha256[..16]
    )
}

fn is_managed_runtime_install_staging_name(name: &OsStr) -> bool {
    let Some(encoded) = name
        .to_str()
        .and_then(|name| name.strip_prefix(".installing-"))
    else {
        return false;
    };
    let Ok(identifier) = Uuid::parse_str(encoded) else {
        return false;
    };
    // `Uuid::new_v4()` is the only producer. Requiring its exact lower-case,
    // hyphenated representation and version bits prevents cleanup from
    // broadening to merely similar or caller-chosen names.
    identifier.as_bytes()[6] & 0xf0 == 0x40
        && identifier.as_bytes()[8] & 0xc0 == 0x80
        && identifier.hyphenated().to_string() == encoded
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct WindowsWslPrerequisiteFailure {
    reason: ManagedRuntimeSetupFailureReason,
    action: ManagedRuntimeSetupNextAction,
    exit_code: Option<i32>,
}

impl WindowsWslPrerequisiteFailure {
    fn not_installed(exit_code: Option<i32>) -> Self {
        Self {
            reason: ManagedRuntimeSetupFailureReason::WslNotInstalled,
            action: ManagedRuntimeSetupNextAction::InstallWsl,
            exit_code,
        }
    }

    fn optional_feature_disabled(exit_code: Option<i32>) -> Self {
        Self {
            reason: ManagedRuntimeSetupFailureReason::WslOptionalFeatureDisabled,
            action: ManagedRuntimeSetupNextAction::EnableWslOptionalFeatures,
            exit_code,
        }
    }

    fn update_required(exit_code: Option<i32>) -> Self {
        Self {
            reason: ManagedRuntimeSetupFailureReason::WslUpdateRequired,
            action: ManagedRuntimeSetupNextAction::UpdateWsl,
            exit_code,
        }
    }

    fn restart_required(exit_code: Option<i32>) -> Self {
        Self {
            reason: ManagedRuntimeSetupFailureReason::RestartRequired,
            action: ManagedRuntimeSetupNextAction::RestartWindows,
            exit_code,
        }
    }

    fn command_failed(exit_code: Option<i32>) -> Self {
        Self {
            reason: ManagedRuntimeSetupFailureReason::WslCommandFailed,
            action: ManagedRuntimeSetupNextAction::RetryWslCheck,
            exit_code,
        }
    }

    fn detail(self) -> String {
        let status = self
            .exit_code
            .map(|code| format!(" The read-only WSL check exited with code {code}."))
            .unwrap_or_default();
        if let Some(detail) = self.reason.packaged_runtime_admission_detail() {
            return detail.into();
        }
        match self.reason {
            ManagedRuntimeSetupFailureReason::PackagedRuntimeMissing
            | ManagedRuntimeSetupFailureReason::PackagedRuntimeVerificationFailed
            | ManagedRuntimeSetupFailureReason::DeveloperBuildWithoutPackagedRuntime
            | ManagedRuntimeSetupFailureReason::DeveloperBuildPackagedRuntimeVerificationFailed => {
                unreachable!("packaged-runtime failures returned above")
            }
            ManagedRuntimeSetupFailureReason::WslNotInstalled => format!(
                "Windows has not installed the component needed by the local scan tools.{status} Retry automatic preparation; ai-security-scanner will use the fixed Windows setup action and the standard Windows approval prompt."
            ),
            ManagedRuntimeSetupFailureReason::WslOptionalFeatureDisabled => format!(
                "Windows has not enabled the components needed by the local scan tools.{status} Retry automatic preparation; restart Windows when requested."
            ),
            ManagedRuntimeSetupFailureReason::WslUpdateRequired => format!(
                "A Windows component used by the local scan tools needs an update.{status} Retry automatic preparation; ai-security-scanner will use the fixed Windows update action and the standard Windows approval prompt."
            ),
            ManagedRuntimeSetupFailureReason::RestartRequired => format!(
                "Windows must restart to finish preparing the local scan tools.{status} Restart Windows and reopen ai-security-scanner; automatic preparation will continue."
            ),
            ManagedRuntimeSetupFailureReason::WslCommandFailed => format!(
                "Local scan-tool readiness unconfirmed.{status} Run automatic preparation again."
            ),
        }
    }
}

fn fail_windows_wsl_prerequisite(
    setup: Option<&ManagedRuntimeSetupController>,
    failure: WindowsWslPrerequisiteFailure,
) -> AppResult<()> {
    let detail = failure.detail();
    if let Some(setup) = setup {
        setup.record_failure(failure.reason, failure.action, detail.clone())?;
    }
    Err(AppError::NotAvailable(detail))
}

fn classify_windows_wsl_prerequisite_failure(
    output: &ManagedCommandOutput,
) -> WindowsWslPrerequisiteFailure {
    let diagnostic = [output.stdout.as_slice(), output.stderr.as_slice()]
        .into_iter()
        .filter_map(safe_command_diagnostic)
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_uppercase();
    let exit_code = output.status.code();

    // WSL retains these symbolic names and hexadecimal codes outside its
    // localized prose. Prefer narrowly actionable classifications and fall
    // back to a generic, read-only retry action for every unknown result.
    if diagnostic_contains_any(
        &diagnostic,
        &[
            "ERROR_SUCCESS_REBOOT_REQUIRED",
            "ERROR_SUCCESS_RESTART_REQUIRED",
            "0X80070BC2",
            "0X80070BC3",
            // Inbox WSL can surface this after CBS stages WSL features but a
            // real Windows restart has not completed the transaction.
            "0XC004000D",
        ],
    ) {
        WindowsWslPrerequisiteFailure::restart_required(exit_code)
    } else if diagnostic_contains_any(
        &diagnostic,
        &[
            "WSL_E_WSL_NOT_INSTALLED",
            "WSL_E_NOT_INSTALLED",
            "WSL_NOT_INSTALLED",
            "AKA.MS/WSLINSTALL",
        ],
    ) {
        WindowsWslPrerequisiteFailure::not_installed(exit_code)
    } else if diagnostic_contains_any(
        &diagnostic,
        &[
            "WSL_E_WSL_OPTIONAL_COMPONENT_REQUIRED",
            "WSL_E_VIRTUAL_MACHINE_PLATFORM_REQUIRED",
            "HCS_E_HYPERV_NOT_INSTALLED",
            "0X8007019E",
            "0X8004032D",
            "0X80370102",
        ],
    ) {
        WindowsWslPrerequisiteFailure::optional_feature_disabled(exit_code)
    } else if diagnostic_contains_any(
        &diagnostic,
        &[
            "WSL_E_KERNEL_UPDATE_REQUIRED",
            "WSL_E_WSL2_KERNEL_NOT_FOUND",
            "WSL_E_PLUGIN_REQUIRES_UPDATE",
            "WSL_E_VERSION_OUTDATED",
            "WSL_E_WSL2_NEEDED",
            "WSL_E_INVALID_USAGE",
            "INVALID COMMAND LINE OPTION: --STATUS",
            "0X800701BC",
        ],
    ) {
        WindowsWslPrerequisiteFailure::update_required(exit_code)
    } else {
        WindowsWslPrerequisiteFailure::command_failed(exit_code)
    }
}

fn diagnostic_contains_any(diagnostic: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| diagnostic.contains(needle))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct WindowsSystemDirectories {
    system_root: PathBuf,
    system32: PathBuf,
}

#[cfg(any(windows, test))]
fn verified_windows_system_directories(system_root: &Path) -> AppResult<WindowsSystemDirectories> {
    if !system_root.is_absolute() {
        return Err(AppError::NotAuthorized(
            "Windows system directory API did not return an absolute directory".into(),
        ));
    }
    let system_root = canonical_real_directory(system_root, "Windows SystemRoot")?;
    let system32 =
        canonical_real_directory(&system_root.join("System32"), "Windows SystemRoot System32")?;
    if !system32.starts_with(&system_root) {
        return Err(AppError::NotAuthorized(
            "Windows System32 directory escaped the canonical Windows root".into(),
        ));
    }
    Ok(WindowsSystemDirectories {
        system_root,
        system32,
    })
}

#[cfg(windows)]
fn windows_system_directories() -> AppResult<WindowsSystemDirectories> {
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::System::SystemInformation::GetSystemWindowsDirectoryW;

    const MAX_WINDOWS_DIRECTORY_UTF16_CODE_UNITS: usize = 32_768;
    let mut encoded = vec![0_u16; MAX_WINDOWS_DIRECTORY_UTF16_CODE_UNITS];
    let length = unsafe {
        GetSystemWindowsDirectoryW(
            encoded.as_mut_ptr(),
            u32::try_from(encoded.len()).expect("Windows directory buffer fits u32"),
        )
    };
    if length == 0 {
        return Err(AppError::NotAvailable(format!(
            "Windows system directory API failed: {}",
            io::Error::last_os_error()
        )));
    }
    let length = usize::try_from(length).map_err(|_| {
        AppError::NotAvailable("Windows system directory length exceeded this platform".into())
    })?;
    if length >= encoded.len() || encoded[length] != 0 || encoded[..length].contains(&0) {
        return Err(AppError::NotAvailable(
            "Windows system directory API returned an invalid or oversized path".into(),
        ));
    }
    verified_windows_system_directories(&PathBuf::from(OsString::from_wide(&encoded[..length])))
}

#[cfg(not(windows))]
fn windows_system_directories() -> AppResult<WindowsSystemDirectories> {
    Err(AppError::NotAvailable(
        "Windows system directory API is unavailable on this host".into(),
    ))
}

fn windows_wsl_inventory_command(
    managed_command: &ManagedRuntimeCommand,
) -> AppResult<ManagedRuntimeCommand> {
    let directories = windows_system_directories()?;
    windows_wsl_inventory_command_with_directories(managed_command, &directories)
}

fn windows_wsl_inventory_command_with_directories(
    managed_command: &ManagedRuntimeCommand,
    directories: &WindowsSystemDirectories,
) -> AppResult<ManagedRuntimeCommand> {
    let system_root = &directories.system_root;
    let system32 = &directories.system32;
    let binary = system32.join("wsl.exe");
    if !binary.is_absolute() {
        return Err(AppError::NotAuthorized(
            "Windows WSL inventory executable was not absolute".into(),
        ));
    }
    verify_regular_file(&binary, "Windows System32 wsl.exe")?;
    let working_directory = canonical_real_directory(
        &managed_command.working_directory,
        "managed Windows WSL inventory working",
    )?;
    let path = std::env::join_paths([system32.clone()])
        .map_err(|_| AppError::Runtime("managed Windows WSL inventory PATH is invalid".into()))?;
    let mut environment = BTreeMap::new();
    environment.insert(
        OsString::from("SystemRoot"),
        system_root.as_os_str().to_owned(),
    );
    environment.insert(OsString::from("WINDIR"), system_root.as_os_str().to_owned());
    environment.insert(OsString::from("PATH"), path);
    environment.insert(
        OsString::from("NoDefaultCurrentDirectoryInExePath"),
        OsString::from("1"),
    );
    // Pinned Podman 5.8.2 sets this on every WSL child. Mirroring it keeps the
    // product's prerequisite and cleanup probes on the same output contract,
    // while the decoder still accepts UTF-16LE from older inbox WSL builds that
    // ignore the flag.
    environment.insert(OsString::from("WSL_UTF8"), OsString::from("1"));

    Ok(ManagedRuntimeCommand {
        binary,
        environment,
        working_directory,
        runtime_version: managed_command.runtime_version.clone(),
        manifest_sha256: managed_command.manifest_sha256.clone(),
        machine_image_sha256: managed_command.machine_image_sha256.clone(),
        #[cfg(windows)]
        windows_launch_authorization: WindowsManagedRuntimeLaunchAuthorization::VerifiedSystem32Wsl,
    })
}

fn windows_wsl_provider_home_from_registration_path(
    state_root: &Path,
    registration_base_path: &Path,
    machine_name: &str,
) -> AppResult<PathBuf> {
    let provider_root = state_root.join("provider-home");
    let relative = registration_base_path
        .strip_prefix(&provider_root)
        .map_err(|_| {
            AppError::NotAuthorized(
                "Windows WSL registration is outside ai-security-scanner's private runtime area"
                    .into(),
            )
        })?;
    let components = relative
        .components()
        .map(|component| match component {
            Component::Normal(value) => Ok(value.to_os_string()),
            _ => Err(AppError::NotAuthorized(
                "Windows WSL registration contains an unsafe path component".into(),
            )),
        })
        .collect::<AppResult<Vec<_>>>()?;
    let fixed = [
        "data",
        "containers",
        "podman",
        "machine",
        "wsl",
        PODMAN_WSL_DISTRIBUTION_STORAGE_DIRECTORY,
    ];
    let namespace = components.first().and_then(|value| value.to_str());
    let has_expected_shape = components.len() == 8
        && namespace.is_some_and(windows_wsl_provider_namespace_has_expected_shape)
        && components[1..7]
            .iter()
            .zip(fixed)
            .all(|(actual, expected)| {
                actual
                    .to_str()
                    .is_some_and(|actual| actual.eq_ignore_ascii_case(expected))
            })
        && components[7]
            .to_str()
            .is_some_and(|actual| actual.eq_ignore_ascii_case(machine_name));
    if !has_expected_shape {
        return Err(AppError::NotAuthorized(
            "Windows WSL registration does not match a private scan-tool workspace".into(),
        ));
    }
    Ok(provider_root.join(&components[0]))
}

fn windows_wsl_provider_namespace_has_expected_shape(value: &str) -> bool {
    let verified_manifest_namespace =
        value.len() == 16 && value.bytes().all(|byte| byte.is_ascii_hexdigit());
    let isolated_generation_namespace = value.len() == 25
        && value
            .get(..8)
            .is_some_and(|prefix| prefix.bytes().all(|byte| byte.is_ascii_hexdigit()))
        && value.get(8..13) == Some("-iso-")
        && value
            .get(13..)
            .is_some_and(|suffix| suffix.bytes().all(|byte| byte.is_ascii_hexdigit()));
    verified_manifest_namespace || isolated_generation_namespace
}

#[cfg(windows)]
fn verify_windows_wsl_product_storage_directory(
    provider_home: &Path,
    registration_base_path: &Path,
) -> AppResult<()> {
    use windows_sys::Win32::Security::{CONTAINER_INHERIT_ACE, OBJECT_INHERIT_ACE};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
    };

    let wsldist = registration_base_path.parent().ok_or_else(|| {
        AppError::NotAuthorized("Windows WSL registration has no storage parent".into())
    })?;
    let expected_wsldist = provider_home
        .join("data")
        .join("containers")
        .join("podman")
        .join("machine")
        .join("wsl")
        .join(PODMAN_WSL_DISTRIBUTION_STORAGE_DIRECTORY);
    if wsldist != expected_wsldist {
        return Err(AppError::NotAuthorized(
            "Windows WSL registration storage changed during verification".into(),
        ));
    }
    let storage = open_windows_real_directory_security_handle(wsldist).map_err(|error| {
        AppError::NotAvailable(format!("Windows WSL storage inspection failed: {error}"))
    })?;
    let inheritance = u8::try_from(OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE)
        .expect("Windows inheritance flags fit in an ACE header");
    verify_windows_wsl_distribution_storage_dacl_with_ace_flags(&storage, inheritance)
        .map_err(|error| windows_managed_acl_verification_error("Windows WSL storage", error))?;
    let distribution = open_windows_real_directory_security_handle(registration_base_path)
        .map_err(|error| {
            AppError::NotAvailable(format!("Windows WSL workspace inspection failed: {error}"))
        })?;
    let information = windows_file_information(&distribution).map_err(|error| {
        AppError::NotAvailable(format!(
            "Windows WSL workspace metadata could not be inspected: {error}"
        ))
    })?;
    if information.attributes & FILE_ATTRIBUTE_DIRECTORY == 0
        || information.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        return Err(AppError::NotAuthorized(
            "Windows WSL workspace is not a real directory".into(),
        ));
    }
    Ok(())
}

#[cfg(not(windows))]
fn verify_windows_wsl_product_storage_directory(
    _provider_home: &Path,
    _registration_base_path: &Path,
) -> AppResult<()> {
    Err(AppError::NotAvailable(
        "Windows WSL storage verification is unavailable on this host".into(),
    ))
}

#[cfg(windows)]
fn windows_paths_refer_to_same_location(first: &Path, second: &Path) -> AppResult<bool> {
    let first = open_windows_real_directory_security_handle(first)?;
    let second = open_windows_real_directory_security_handle(second)?;
    Ok(windows_file_information(&first)?.identity == windows_file_information(&second)?.identity)
}

#[cfg(not(windows))]
fn windows_paths_refer_to_same_location(first: &Path, second: &Path) -> AppResult<bool> {
    Ok(first == second)
}

#[cfg(windows)]
struct WindowsRegistryKey(windows_sys::Win32::System::Registry::HKEY);

#[cfg(windows)]
impl Drop for WindowsRegistryKey {
    fn drop(&mut self) {
        unsafe {
            windows_sys::Win32::System::Registry::RegCloseKey(self.0);
        }
    }
}

#[cfg(windows)]
fn windows_registry_wide(value: &str) -> AppResult<Vec<u16>> {
    use std::os::windows::ffi::OsStrExt;
    let mut encoded = OsStr::new(value).encode_wide().collect::<Vec<_>>();
    if encoded.contains(&0) {
        return Err(AppError::NotAuthorized(
            "Windows registry name contains a NUL code unit".into(),
        ));
    }
    encoded.push(0);
    Ok(encoded)
}

#[cfg(any(windows, test))]
fn decode_windows_registry_string_read(encoded: &[u16], returned_bytes: u32) -> AppResult<String> {
    if !(2..=MAX_WINDOWS_REGISTRY_STRING_BYTES).contains(&returned_bytes)
        || !returned_bytes.is_multiple_of(2)
    {
        return Err(AppError::NotAuthorized(
            "Windows registry string read returned an invalid size".into(),
        ));
    }
    let returned_units = returned_bytes as usize / 2;
    if returned_units > encoded.len()
        || encoded[returned_units - 1] != 0
        || encoded[..returned_units - 1].contains(&0)
    {
        return Err(AppError::NotAuthorized(
            "Windows registry string read was malformed".into(),
        ));
    }
    String::from_utf16(&encoded[..returned_units - 1])
        .map_err(|_| AppError::NotAuthorized("Windows registry string is not valid UTF-16".into()))
}

#[cfg(any(windows, test))]
fn decode_stable_windows_registry_string_reads(
    first: &[u16],
    first_returned_bytes: u32,
    second: &[u16],
    second_returned_bytes: u32,
) -> AppResult<String> {
    let first_value = decode_windows_registry_string_read(first, first_returned_bytes)?;
    let second_value = decode_windows_registry_string_read(second, second_returned_bytes)?;
    let first_units = first_returned_bytes as usize / 2;
    let second_units = second_returned_bytes as usize / 2;
    if first_returned_bytes != second_returned_bytes
        || first[..first_units] != second[..second_units]
        || first_value != second_value
    {
        return Err(AppError::NotAuthorized(
            "Windows registry string changed while it was read".into(),
        ));
    }
    Ok(second_value)
}

#[cfg(windows)]
fn read_windows_registry_string_once(
    key: &WindowsRegistryKey,
    value_name: &[u16],
    capacity_bytes: u32,
) -> AppResult<(Vec<u16>, u32)> {
    use windows_sys::Win32::Foundation::{ERROR_MORE_DATA, ERROR_SUCCESS};
    use windows_sys::Win32::System::Registry::{
        REG_SZ, RRF_NOEXPAND, RRF_RT_REG_SZ, RRF_ZEROONFAILURE, RegGetValueW,
    };

    let mut value_type = 0;
    let mut encoded = vec![0xa5a5_u16; capacity_bytes as usize / 2];
    let mut returned_bytes = capacity_bytes;
    let status = unsafe {
        RegGetValueW(
            key.0,
            std::ptr::null(),
            value_name.as_ptr(),
            RRF_RT_REG_SZ | RRF_NOEXPAND | RRF_ZEROONFAILURE,
            &raw mut value_type,
            encoded.as_mut_ptr().cast(),
            &raw mut returned_bytes,
        )
    };
    if status == ERROR_MORE_DATA {
        return Err(AppError::NotAuthorized(
            "Windows registry string grew while it was read".into(),
        ));
    }
    if status != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(status as i32).into());
    }
    if value_type != REG_SZ {
        return Err(AppError::NotAuthorized(
            "Windows registry string type changed while it was read".into(),
        ));
    }
    decode_windows_registry_string_read(&encoded, returned_bytes)?;
    Ok((encoded, returned_bytes))
}

#[cfg(windows)]
fn windows_registry_string(key: &WindowsRegistryKey, value_name: &str) -> AppResult<String> {
    use windows_sys::Win32::Foundation::ERROR_SUCCESS;
    use windows_sys::Win32::System::Registry::{
        REG_SZ, RRF_NOEXPAND, RRF_RT_REG_SZ, RRF_ZEROONFAILURE, RegGetValueW,
    };

    let value_name = windows_registry_wide(value_name)?;
    let mut value_type = 0;
    let mut size_bytes = 0_u32;
    let status = unsafe {
        RegGetValueW(
            key.0,
            std::ptr::null(),
            value_name.as_ptr(),
            RRF_RT_REG_SZ | RRF_NOEXPAND | RRF_ZEROONFAILURE,
            &raw mut value_type,
            std::ptr::null_mut(),
            &raw mut size_bytes,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(status as i32).into());
    }
    if value_type != REG_SZ
        || !(2..=MAX_WINDOWS_REGISTRY_STRING_BYTES).contains(&size_bytes)
        || !size_bytes.is_multiple_of(2)
    {
        return Err(AppError::NotAuthorized(
            "Windows registry string has an invalid type or size".into(),
        ));
    }
    // RegGetValueW's buffered success reports the bytes actually copied, and
    // the probe plus later reads are separate, non-atomic calls. Keep one
    // UTF-16 code unit of bounded slack for a missing stored terminator, then
    // require two identical, well-formed reads instead of comparing either
    // result with the probe byte count.
    let capacity_bytes = size_bytes
        .checked_add(2)
        .filter(|candidate| *candidate <= MAX_WINDOWS_REGISTRY_STRING_BYTES)
        .unwrap_or(size_bytes);
    let (first, first_returned_bytes) =
        read_windows_registry_string_once(key, &value_name, capacity_bytes)?;
    let (second, second_returned_bytes) =
        read_windows_registry_string_once(key, &value_name, capacity_bytes)?;
    decode_stable_windows_registry_string_reads(
        &first,
        first_returned_bytes,
        &second,
        second_returned_bytes,
    )
}

#[cfg(windows)]
fn windows_wsl_registration_inventory() -> AppResult<WindowsWslRegistrationInventory> {
    use windows_sys::Win32::Foundation::{
        ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA, ERROR_NO_MORE_ITEMS, ERROR_SUCCESS,
    };
    use windows_sys::Win32::System::Registry::{
        HKEY_CURRENT_USER, KEY_READ, RegEnumKeyExW, RegOpenKeyExW,
    };

    let lxss_path = windows_registry_wide("Software\\Microsoft\\Windows\\CurrentVersion\\Lxss")?;
    let mut raw_root = std::ptr::null_mut();
    let status = unsafe {
        RegOpenKeyExW(
            HKEY_CURRENT_USER,
            lxss_path.as_ptr(),
            0,
            KEY_READ,
            &raw mut raw_root,
        )
    };
    if status == ERROR_FILE_NOT_FOUND {
        return Ok(WindowsWslRegistrationInventory::complete(Vec::new()));
    }
    if status != ERROR_SUCCESS || raw_root.is_null() {
        return Err(AppError::NotAvailable(format!(
            "Windows could not open the WSL registration inventory root (Win32 status {status}): {}",
            io::Error::from_raw_os_error(status as i32)
        )));
    }
    let root = WindowsRegistryKey(raw_root);
    let mut inventory = WindowsWslRegistrationInventory {
        complete: true,
        ..WindowsWslRegistrationInventory::default()
    };
    for index in 0..=MAX_WSL_DISTRIBUTIONS {
        if index == MAX_WSL_DISTRIBUTIONS {
            inventory.complete = false;
            break;
        }
        let mut name = vec![0_u16; 256];
        let mut name_length = u32::try_from(name.len()).expect("registry buffer fits u32");
        let status = unsafe {
            RegEnumKeyExW(
                root.0,
                index as u32,
                name.as_mut_ptr(),
                &raw mut name_length,
                std::ptr::null(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if status == ERROR_NO_MORE_ITEMS {
            break;
        }
        if status == ERROR_MORE_DATA {
            inventory.complete = false;
            continue;
        }
        if status != ERROR_SUCCESS || name_length == 0 || name_length as usize >= name.len() {
            inventory.complete = false;
            continue;
        }
        let Ok(subkey_name) = String::from_utf16(&name[..name_length as usize]) else {
            inventory.complete = false;
            continue;
        };
        let Ok(registration_id) = Uuid::parse_str(subkey_name.trim_matches(['{', '}'])) else {
            inventory.complete = false;
            continue;
        };
        let registration_id = registration_id.hyphenated().to_string();
        let Ok(subkey_name_wide) = windows_registry_wide(&subkey_name) else {
            inventory.complete = false;
            continue;
        };
        let mut raw_subkey = std::ptr::null_mut();
        let status = unsafe {
            RegOpenKeyExW(
                root.0,
                subkey_name_wide.as_ptr(),
                0,
                KEY_READ,
                &raw mut raw_subkey,
            )
        };
        if status != ERROR_SUCCESS || raw_subkey.is_null() {
            inventory.complete = false;
            continue;
        }
        let subkey = WindowsRegistryKey(raw_subkey);
        let Ok(distribution_name) = windows_registry_string(&subkey, "DistributionName") else {
            inventory.complete = false;
            continue;
        };
        if distribution_name.is_empty()
            || distribution_name.len() > MAX_WSL_DISTRIBUTION_NAME_BYTES
            || distribution_name.trim() != distribution_name
            || distribution_name.chars().any(|character| {
                character.is_control()
                    || matches!(character, '\u{2028}' | '\u{2029}')
                    || unicode_code_point_is_noncharacter(character)
            })
        {
            inventory.complete = false;
            continue;
        }
        if !inventory
            .observed_distribution_names
            .iter()
            .any(|observed| observed.eq_ignore_ascii_case(&distribution_name))
        {
            inventory
                .observed_distribution_names
                .push(distribution_name.clone());
        }
        let Ok(base_path) = windows_registry_string(&subkey, "BasePath").map(PathBuf::from) else {
            inventory.complete = false;
            continue;
        };
        if base_path.as_os_str().is_empty() {
            inventory.complete = false;
            continue;
        }
        inventory.registrations.push(WindowsWslRegistration {
            registration_id,
            distribution_name,
            base_path,
        });
    }
    Ok(inventory)
}

#[cfg(not(windows))]
fn windows_wsl_registration_inventory() -> AppResult<WindowsWslRegistrationInventory> {
    Err(AppError::NotAvailable(
        "Windows WSL registrations are unavailable on this host".into(),
    ))
}

fn parse_windows_wsl_distribution_inventory(bytes: &[u8]) -> AppResult<Vec<String>> {
    let decoded = decode_windows_command_text(bytes, "managed Windows WSL distribution inventory")?;

    if decoded.contains(['\0', '\u{feff}']) {
        return Err(AppError::Runtime(
            "managed Windows WSL distribution inventory contained an invalid code point".into(),
        ));
    }
    let mut distributions = Vec::new();
    let mut lines = decoded.split('\n').peekable();
    while let Some(encoded_line) = lines.next() {
        if encoded_line.is_empty() && lines.peek().is_none() {
            break;
        }
        let line = encoded_line.strip_suffix('\r').unwrap_or(encoded_line);
        if line.is_empty()
            || line.len() > MAX_WSL_DISTRIBUTION_NAME_BYTES
            || line.trim() != line
            || line.chars().any(|character| {
                character.is_control()
                    || matches!(character, '\u{2028}' | '\u{2029}')
                    || unicode_code_point_is_noncharacter(character)
            })
        {
            return Err(AppError::Runtime(
                "managed Windows WSL distribution inventory contained an invalid name".into(),
            ));
        }
        if distributions.len() == MAX_WSL_DISTRIBUTIONS {
            return Err(AppError::Runtime(
                "managed Windows WSL distribution inventory contained too many names".into(),
            ));
        }
        distributions.push(line.to_owned());
    }
    Ok(distributions)
}

/// Decodes the encodings emitted by Windows console applications when their
/// output is redirected to a pipe. WSL commonly uses UTF-16LE for localized
/// text, sometimes without a BOM; modern builds may emit UTF-8 instead.
fn decode_windows_command_text(bytes: &[u8], label: &str) -> AppResult<String> {
    if bytes.len() as u64 > MAX_COMMAND_OUTPUT_BYTES {
        return Err(AppError::Runtime(format!("{label} was oversized")));
    }
    if let Some(encoded) = bytes.strip_prefix(&[0xef, 0xbb, 0xbf]) {
        std::str::from_utf8(encoded)
            .map(str::to_owned)
            .map_err(|_| AppError::Runtime(format!("{label} was not valid UTF-8")))
    } else if let Some(encoded) = bytes.strip_prefix(&[0xff, 0xfe]) {
        decode_windows_utf16le(encoded, label)
    } else if bytes.starts_with(&[0xfe, 0xff]) {
        Err(AppError::Runtime(format!(
            "{label} used unsupported UTF-16BE"
        )))
    } else if let Ok(decoded) = std::str::from_utf8(bytes) {
        if decoded.contains('\0') {
            decode_windows_utf16le(bytes, label)
        } else {
            Ok(decoded.to_owned())
        }
    } else {
        decode_windows_utf16le(bytes, label)
    }
}

fn decode_windows_utf16le(bytes: &[u8], label: &str) -> AppResult<String> {
    if !bytes.len().is_multiple_of(2) {
        return Err(AppError::Runtime(format!(
            "{label} had invalid UTF-16LE length"
        )));
    }
    let code_units = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect::<Vec<_>>();
    String::from_utf16(&code_units)
        .map_err(|_| AppError::Runtime(format!("{label} was not valid UTF-16LE")))
}

fn unicode_code_point_is_noncharacter(character: char) -> bool {
    let code_point = character as u32;
    (0xfdd0..=0xfdef).contains(&code_point) || code_point & 0xfffe == 0xfffe
}

fn require_success(operation: &str, output: &ManagedCommandOutput) -> AppResult<()> {
    if output.status.success() {
        return Ok(());
    }
    let detail = safe_command_diagnostic(&output.stderr)
        .or_else(|| safe_command_diagnostic(&output.stdout))
        .unwrap_or_else(|| "No readable diagnostic was returned.".into());
    Err(AppError::Runtime(format!(
        "{operation} failed with status {}: {}",
        output.status, detail
    )))
}

/// Returns a bounded single-line diagnostic or `None` when the child output
/// cannot be decoded without replacement characters or unsafe controls. Raw
/// bytes are never interpolated into an application error.
fn safe_command_diagnostic(bytes: &[u8]) -> Option<String> {
    if !windows_command_text_has_known_encoding(bytes) {
        return None;
    }
    let decoded = decode_windows_command_text(bytes, "managed runtime command diagnostic").ok()?;
    let mut sanitized = String::new();
    let mut previous_was_space = true;
    for (retained, character) in decoded.chars().enumerate() {
        if retained == MAX_COMMAND_DIAGNOSTIC_CHARS {
            break;
        }
        if character == '\u{fffd}'
            || character == '\u{feff}'
            || unicode_code_point_is_noncharacter(character)
            || (character.is_control() && !character.is_whitespace())
        {
            return None;
        }
        if character.is_whitespace() {
            if !previous_was_space {
                sanitized.push(' ');
                previous_was_space = true;
            }
        } else {
            sanitized.push(character);
            previous_was_space = false;
        }
    }
    let sanitized = sanitized.trim().to_owned();
    (!sanitized.is_empty()).then_some(sanitized)
}

fn windows_command_text_has_known_encoding(bytes: &[u8]) -> bool {
    if bytes.starts_with(&[0xef, 0xbb, 0xbf]) || bytes.starts_with(&[0xff, 0xfe]) {
        return true;
    }
    if bytes.starts_with(&[0xfe, 0xff]) || !bytes.len().is_multiple_of(2) {
        return std::str::from_utf8(bytes).is_ok_and(|text| !text.contains('\0'));
    }
    if let Ok(text) = std::str::from_utf8(bytes) {
        return !text.contains('\0') || looks_like_unmarked_utf16le_console_text(bytes);
    }
    looks_like_unmarked_utf16le_console_text(bytes)
}

fn looks_like_unmarked_utf16le_console_text(bytes: &[u8]) -> bool {
    if bytes.is_empty() || !bytes.len().is_multiple_of(2) {
        return false;
    }
    let pairs = bytes.len() / 2;
    let odd_nuls = bytes
        .iter()
        .skip(1)
        .step_by(2)
        .filter(|byte| **byte == 0)
        .count();
    let even_nuls = bytes.iter().step_by(2).filter(|byte| **byte == 0).count();
    let has_utf16_ascii_signal = odd_nuls > 0 && odd_nuls * 8 >= pairs && even_nuls * 8 < pairs;
    let has_mixed_ascii_prefix = bytes
        .split(|byte| !byte.is_ascii_graphic() && *byte != b' ')
        .any(|run| run.len() >= 8);
    has_utf16_ascii_signal && !has_mixed_ascii_prefix
}

fn bounded_utf8<'a>(bytes: &'a [u8], label: &str) -> AppResult<&'a str> {
    if bytes.len() as u64 > MAX_COMMAND_OUTPUT_BYTES {
        return Err(AppError::Runtime(format!("{label} was oversized")));
    }
    std::str::from_utf8(bytes)
        .map_err(|_| AppError::Runtime(format!("{label} was not valid UTF-8")))
}

fn sha256_bytes(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[cfg(unix)]
fn effective_uid() -> libc::uid_t {
    // SAFETY: geteuid has no preconditions and does not dereference memory.
    unsafe { libc::geteuid() }
}

#[cfg(unix)]
fn linux_short_runtime_path(
    base: &Path,
    canonical_state_root: &Path,
    manifest_sha256: &str,
    effective_uid: libc::uid_t,
) -> PathBuf {
    use std::os::unix::ffi::OsStrExt;

    let state_bytes = canonical_state_root.as_os_str().as_bytes();
    let mut digest = Sha256::new();
    digest.update(b"ai-security-scanner-linux-xdg-runtime-v1\0");
    digest.update(effective_uid.to_be_bytes());
    digest.update((state_bytes.len() as u64).to_be_bytes());
    digest.update(state_bytes);
    digest.update((manifest_sha256.len() as u64).to_be_bytes());
    digest.update(manifest_sha256.as_bytes());
    let encoded = hex::encode(digest.finalize());
    base.join(format!(
        "{LINUX_SHORT_RUNTIME_PREFIX}{}",
        &encoded[..LINUX_SHORT_RUNTIME_DIGEST_HEX_CHARS]
    ))
}

#[cfg(unix)]
fn linux_podman_gvproxy_socket_path(runtime: &Path, machine_name: &str) -> PathBuf {
    runtime
        .join(PODMAN_LINUX_RUNTIME_DIRECTORY)
        .join(format!("{machine_name}{PODMAN_GVPROXY_SOCKET_SUFFIX}"))
}

#[cfg(unix)]
fn verify_linux_temporary_base(base: &Path) -> AppResult<()> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    let metadata = fs::symlink_metadata(base)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(AppError::NotAuthorized(
            "managed runtime Linux temporary base must be a real directory".into(),
        ));
    }
    if base.canonicalize()? != base {
        return Err(AppError::NotAuthorized(
            "managed runtime Linux temporary base must be canonical".into(),
        ));
    }
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW);
    let directory = options.open(base).map_err(|error| {
        AppError::NotAuthorized(format!(
            "managed runtime Linux temporary base could not be opened without following links: {error}"
        ))
    })?;
    let opened = directory.metadata()?;
    if !opened.is_dir() || opened.dev() != metadata.dev() || opened.ino() != metadata.ino() {
        return Err(AppError::NotAuthorized(
            "managed runtime Linux temporary base changed while it was being verified".into(),
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn ensure_linux_short_runtime_directory_at(
    path: &Path,
    base: &Path,
    effective_uid: libc::uid_t,
) -> AppResult<()> {
    use std::os::unix::fs::DirBuilderExt;

    verify_linux_temporary_base(base)?;
    if path.parent() != Some(base) {
        return Err(AppError::NotAuthorized(
            "managed runtime Linux short-runtime path escaped its exact temporary base".into(),
        ));
    }
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700);
    match builder.create(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    verify_linux_short_runtime_directory(path, effective_uid)
}

#[cfg(unix)]
fn verify_linux_short_runtime_directory(path: &Path, effective_uid: libc::uid_t) -> AppResult<()> {
    drop(open_verified_linux_short_runtime_directory(
        path,
        effective_uid,
    )?);
    Ok(())
}

#[cfg(unix)]
fn open_verified_linux_short_runtime_directory(
    path: &Path,
    effective_uid: libc::uid_t,
) -> AppResult<File> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(AppError::NotAuthorized(
            "managed runtime Linux short runtime must be a real directory".into(),
        ));
    }
    if metadata.uid() != effective_uid || metadata.mode() & 0o7777 != 0o700 {
        return Err(AppError::NotAuthorized(
            "managed runtime Linux short runtime has unsafe ownership or permissions".into(),
        ));
    }
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW);
    let directory = options.open(path).map_err(|error| {
        AppError::NotAuthorized(format!(
            "managed runtime Linux short runtime could not be opened without following links: {error}"
        ))
    })?;
    let opened = directory.metadata()?;
    if !opened.is_dir()
        || opened.dev() != metadata.dev()
        || opened.ino() != metadata.ino()
        || opened.uid() != effective_uid
        || opened.mode() & 0o7777 != 0o700
    {
        return Err(AppError::NotAuthorized(
            "managed runtime Linux short runtime changed while it was being verified".into(),
        ));
    }
    Ok(directory)
}

#[cfg(unix)]
fn verify_linux_podman_runtime_directory(path: &Path, effective_uid: libc::uid_t) -> AppResult<()> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    let metadata = fs::symlink_metadata(path)?;
    let mode = metadata.mode() & 0o7777;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != effective_uid
        || mode & 0o700 != 0o700
        || mode & !0o755 != 0
    {
        return Err(AppError::NotAuthorized(
            "managed runtime Linux Podman runtime directory is unsafe".into(),
        ));
    }
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW);
    let directory = options.open(path).map_err(|error| {
        AppError::NotAuthorized(format!(
            "managed runtime Linux Podman runtime directory could not be opened without following links: {error}"
        ))
    })?;
    let opened = directory.metadata()?;
    if !opened.is_dir()
        || opened.dev() != metadata.dev()
        || opened.ino() != metadata.ino()
        || opened.uid() != effective_uid
        || opened.mode() & 0o7777 != mode
    {
        return Err(AppError::NotAuthorized(
            "managed runtime Linux Podman runtime directory changed while it was being verified"
                .into(),
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn remove_expected_linux_gvproxy_log(path: &Path, effective_uid: libc::uid_t) -> AppResult<()> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    let mode = metadata.mode() & 0o7777;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != effective_uid
        || mode & 0o600 != 0o600
        || mode & !0o666 != 0
    {
        return Err(AppError::NotAuthorized(
            "managed runtime Linux gvproxy log is not an expected current-user single-link regular file"
                .into(),
        ));
    }
    let mut options = OpenOptions::new();
    options.read(true).custom_flags(libc::O_NOFOLLOW);
    let file = options.open(path).map_err(|error| {
        AppError::NotAuthorized(format!(
            "managed runtime Linux gvproxy log could not be opened without following links: {error}"
        ))
    })?;
    let opened = file.metadata()?;
    if !opened.is_file()
        || opened.dev() != metadata.dev()
        || opened.ino() != metadata.ino()
        || opened.nlink() != 1
        || opened.uid() != effective_uid
        || opened.mode() & 0o7777 != mode
    {
        return Err(AppError::NotAuthorized(
            "managed runtime Linux gvproxy log changed while it was being verified".into(),
        ));
    }
    fs::remove_file(path)?;
    Ok(())
}

#[cfg(unix)]
fn open_expected_linux_virtiofs_pid(path: &Path, effective_uid: libc::uid_t) -> AppResult<File> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != effective_uid
        || metadata.mode() & 0o7777 != 0o600
    {
        return Err(AppError::NotAuthorized(
            "managed runtime Linux virtiofsd pid is not an expected current-user single-link mode-0600 regular file"
                .into(),
        ));
    }
    let mut options = OpenOptions::new();
    options.read(true).custom_flags(libc::O_NOFOLLOW);
    let file = options.open(path).map_err(|error| {
        AppError::NotAuthorized(format!(
            "managed runtime Linux virtiofsd pid could not be opened without following links: {error}"
        ))
    })?;
    verify_opened_linux_virtiofs_pid(path, &file, &metadata, effective_uid)?;
    Ok(file)
}

#[cfg(unix)]
fn verify_opened_linux_virtiofs_pid(
    path: &Path,
    file: &File,
    expected: &fs::Metadata,
    effective_uid: libc::uid_t,
) -> AppResult<()> {
    use std::os::unix::fs::MetadataExt;

    let current = fs::symlink_metadata(path)?;
    let opened = file.metadata()?;
    if current.file_type().is_symlink()
        || !current.is_file()
        || current.dev() != expected.dev()
        || current.ino() != expected.ino()
        || current.nlink() != 1
        || current.uid() != effective_uid
        || current.mode() & 0o7777 != 0o600
        || !opened.is_file()
        || opened.dev() != current.dev()
        || opened.ino() != current.ino()
        || opened.nlink() != 1
        || opened.uid() != effective_uid
        || opened.mode() & 0o7777 != 0o600
    {
        return Err(AppError::NotAuthorized(
            "managed runtime Linux virtiofsd pid changed while it was being verified".into(),
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn wait_for_unlocked_linux_virtiofs_pid(
    path: &Path,
    effective_uid: libc::uid_t,
    timeout: Duration,
) -> AppResult<Option<File>> {
    use std::os::fd::AsRawFd;

    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let file = open_expected_linux_virtiofs_pid(path, effective_uid)?;
    let deadline = Instant::now() + timeout;
    loop {
        // SAFETY: file owns a valid descriptor; flock neither retains the pointer nor
        // accesses memory. The acquired lock remains held by this File until cleanup.
        let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if result == 0 {
            verify_opened_linux_virtiofs_pid(path, &file, &metadata, effective_uid)?;
            return Ok(Some(file));
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EWOULDBLOCK) {
            return Err(error.into());
        }
        let now = Instant::now();
        if now >= deadline {
            return Err(AppError::Runtime(
                "managed runtime Linux virtiofsd remained live after exact machine removal".into(),
            ));
        }
        thread::sleep(LINUX_VIRTIOFS_CLEANUP_POLL.min(deadline.saturating_duration_since(now)));
    }
}

#[cfg(unix)]
fn verify_linux_virtiofs_socket(path: &Path, effective_uid: libc::uid_t) -> AppResult<()> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};

    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_socket()
        || metadata.nlink() != 1
        || metadata.uid() != effective_uid
        || metadata.mode() & 0o7777 != 0o700
    {
        return Err(AppError::NotAuthorized(
            "managed runtime Linux virtiofsd socket is not the expected current-user single-link mode-0700 Unix socket"
                .into(),
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn remove_expected_linux_virtiofs_residue(
    podman: &Path,
    effective_uid: libc::uid_t,
    timeout: Duration,
) -> AppResult<()> {
    let pid_path = podman.join(PODMAN_VIRTIOFS_PID_NAME);
    let socket_path = podman.join(PODMAN_VIRTIOFS_SOCKET_NAME);
    let Some(pid_file) = wait_for_unlocked_linux_virtiofs_pid(&pid_path, effective_uid, timeout)?
    else {
        if private_entry_exists(&socket_path)? {
            return Err(AppError::NotAuthorized(
                "managed runtime Linux virtiofsd socket had no exact pid-lock ownership proof"
                    .into(),
            ));
        }
        return Ok(());
    };

    match fs::symlink_metadata(&socket_path) {
        Ok(_) => {
            verify_linux_virtiofs_socket(&socket_path, effective_uid)?;
            fs::remove_file(&socket_path)?;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let expected = pid_file.metadata()?;
    verify_opened_linux_virtiofs_pid(&pid_path, &pid_file, &expected, effective_uid)?;
    fs::remove_file(&pid_path)?;
    Ok(())
}

#[cfg(unix)]
fn linux_runtime_child_stat(
    parent: &File,
    basename: &std::ffi::CStr,
) -> AppResult<Option<libc::stat>> {
    use std::os::fd::AsRawFd;

    let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: parent owns a live directory descriptor, basename is a
    // NUL-terminated relative name, and metadata points to writable storage.
    if unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            basename.as_ptr(),
            metadata.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ENOENT) {
            return Ok(None);
        }
        return Err(AppError::NotAuthorized(format!(
            "managed runtime Linux eager runtime directory could not be inspected without following links: {error}"
        )));
    }
    // SAFETY: successful fstatat initialized every field of metadata.
    Ok(Some(unsafe { metadata.assume_init() }))
}

#[cfg(unix)]
fn linux_runtime_opened_stat(directory: &File) -> AppResult<libc::stat> {
    use std::os::fd::AsRawFd;

    let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: directory owns a live descriptor and metadata points to writable storage.
    if unsafe { libc::fstat(directory.as_raw_fd(), metadata.as_mut_ptr()) } != 0 {
        let error = io::Error::last_os_error();
        return Err(AppError::NotAuthorized(format!(
            "managed runtime Linux eager runtime directory descriptor could not be inspected: {error}"
        )));
    }
    // SAFETY: successful fstat initialized every field of metadata.
    Ok(unsafe { metadata.assume_init() })
}

#[cfg(unix)]
fn remove_expected_empty_linux_runtime_directory(
    parent_path: &Path,
    parent: &File,
    basename: &str,
    expected_mode: libc::mode_t,
    effective_uid: libc::uid_t,
) -> AppResult<()> {
    use std::ffi::CString;
    use std::os::fd::{AsRawFd, FromRawFd};

    if basename.is_empty() || basename.contains(['/', '\0']) {
        return Err(AppError::Internal(
            "managed runtime Linux eager runtime basename is invalid".into(),
        ));
    }
    let c_basename = CString::new(basename.as_bytes()).map_err(|_| {
        AppError::Internal(
            "managed runtime Linux eager runtime basename was not representable".into(),
        )
    })?;
    let Some(expected) = linux_runtime_child_stat(parent, &c_basename)? else {
        return Ok(());
    };
    if expected.st_mode & libc::S_IFMT != libc::S_IFDIR
        || expected.st_uid != effective_uid
        || expected.st_mode & 0o7777 != expected_mode
    {
        return Err(AppError::NotAuthorized(format!(
            "managed runtime Linux eager {basename} directory has unsafe type, ownership, or permissions"
        )));
    }

    // SAFETY: parent is a verified directory descriptor and c_basename is a
    // fixed relative child name. O_NOFOLLOW rejects a link replacement.
    let raw = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            c_basename.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if raw < 0 {
        let error = io::Error::last_os_error();
        return Err(AppError::NotAuthorized(format!(
            "managed runtime Linux eager {basename} directory could not be opened without following links: {error}"
        )));
    }
    // SAFETY: openat returned a fresh owned descriptor that is transferred to File.
    let directory = unsafe { File::from_raw_fd(raw) };
    let opened = linux_runtime_opened_stat(&directory)?;
    if opened.st_mode & libc::S_IFMT != libc::S_IFDIR
        || opened.st_dev != expected.st_dev
        || opened.st_ino != expected.st_ino
        || opened.st_uid != effective_uid
        || opened.st_mode & 0o7777 != expected_mode
    {
        return Err(AppError::NotAuthorized(format!(
            "managed runtime Linux eager {basename} directory changed while it was opened"
        )));
    }
    if fs::read_dir(parent_path.join(basename))?
        .next()
        .transpose()?
        .is_some()
    {
        return Err(AppError::NotAuthorized(format!(
            "managed runtime Linux eager {basename} directory was not empty after machine removal"
        )));
    }

    let current = linux_runtime_child_stat(parent, &c_basename)?.ok_or_else(|| {
        AppError::NotAuthorized(format!(
            "managed runtime Linux eager {basename} directory disappeared during verification"
        ))
    })?;
    let reopened = linux_runtime_opened_stat(&directory)?;
    if current.st_dev != expected.st_dev
        || current.st_ino != expected.st_ino
        || current.st_mode != expected.st_mode
        || current.st_uid != expected.st_uid
        || reopened.st_dev != current.st_dev
        || reopened.st_ino != current.st_ino
        || reopened.st_uid != effective_uid
        || reopened.st_mode & 0o7777 != expected_mode
    {
        return Err(AppError::NotAuthorized(format!(
            "managed runtime Linux eager {basename} directory changed during exact cleanup"
        )));
    }
    // SAFETY: parent remains the verified short-runtime descriptor and the
    // exact child was proved to be the same empty directory through its live descriptor.
    if unsafe { libc::unlinkat(parent.as_raw_fd(), c_basename.as_ptr(), libc::AT_REMOVEDIR) } != 0 {
        let error = io::Error::last_os_error();
        return Err(AppError::Runtime(format!(
            "managed runtime Linux eager {basename} directory could not be removed: {error}"
        )));
    }
    parent.sync_all()?;
    Ok(())
}

#[cfg(unix)]
fn remove_linux_short_runtime_directory_at(
    path: &Path,
    base: &Path,
    effective_uid: libc::uid_t,
) -> AppResult<()> {
    verify_linux_temporary_base(base)?;
    if path.parent() != Some(base) {
        return Err(AppError::NotAuthorized(
            "managed runtime Linux short-runtime cleanup escaped its exact temporary base".into(),
        ));
    }
    match fs::symlink_metadata(path) {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    }
    let short_directory = open_verified_linux_short_runtime_directory(path, effective_uid)?;

    let podman = path.join(PODMAN_LINUX_RUNTIME_DIRECTORY);
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        if !matches!(
            entry.file_name().to_str(),
            Some(PODMAN_LINUX_RUNTIME_DIRECTORY)
                | Some(PODMAN_LINUX_EAGER_STORAGE_DIRECTORY)
                | Some(PODMAN_LINUX_EAGER_LIBPOD_DIRECTORY)
        ) {
            return Err(AppError::NotAuthorized(
                "managed runtime Linux short runtime contained an unexpected entry after machine removal"
                    .into(),
            ));
        }
    }
    match fs::symlink_metadata(&podman) {
        Ok(_) => {
            verify_linux_podman_runtime_directory(&podman, effective_uid)?;
            for entry in fs::read_dir(&podman)? {
                let entry = entry?;
                if !matches!(
                    entry.file_name().to_str(),
                    Some(PODMAN_GVPROXY_LOG_NAME)
                        | Some(PODMAN_VIRTIOFS_SOCKET_NAME)
                        | Some(PODMAN_VIRTIOFS_PID_NAME)
                ) {
                    return Err(AppError::NotAuthorized(
                        "managed runtime Linux Podman runtime directory contained an unexpected entry after machine removal"
                            .into(),
                    ));
                }
            }
            remove_expected_linux_virtiofs_residue(
                &podman,
                effective_uid,
                LINUX_VIRTIOFS_CLEANUP_TIMEOUT,
            )?;
            remove_expected_linux_gvproxy_log(
                &podman.join(PODMAN_GVPROXY_LOG_NAME),
                effective_uid,
            )?;
            if fs::read_dir(&podman)?.next().transpose()?.is_some() {
                return Err(AppError::NotAuthorized(
                    "managed runtime Linux Podman runtime directory was not empty after exact log cleanup"
                        .into(),
                ));
            }
            fs::remove_dir(&podman)?;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    // Pinned containers/storage v1.62.0 and containers/common eagerly create
    // these exact roots from XDG_RUNTIME_DIR before the release-private
    // storage.conf and containers.conf overrides are applied. Neither may
    // contain state: accept only the observed exact modes and empty real dirs.
    remove_expected_empty_linux_runtime_directory(
        path,
        &short_directory,
        PODMAN_LINUX_EAGER_STORAGE_DIRECTORY,
        0o700,
        effective_uid,
    )?;
    remove_expected_empty_linux_runtime_directory(
        path,
        &short_directory,
        PODMAN_LINUX_EAGER_LIBPOD_DIRECTORY,
        0o1700,
        effective_uid,
    )?;
    if fs::read_dir(path)?.next().transpose()?.is_some() {
        return Err(AppError::NotAuthorized(
            "managed runtime Linux short runtime was not empty after machine removal".into(),
        ));
    }
    fs::remove_dir(path)?;
    sync_directory(base)
}

#[cfg(unix)]
fn macos_short_home_path(
    base: &Path,
    canonical_state_root: &Path,
    manifest_sha256: &str,
    effective_uid: libc::uid_t,
) -> PathBuf {
    use std::os::unix::ffi::OsStrExt;

    let state_bytes = canonical_state_root.as_os_str().as_bytes();
    let mut digest = Sha256::new();
    digest.update(b"ai-security-scanner-macos-command-home-v1\0");
    digest.update(effective_uid.to_be_bytes());
    digest.update((state_bytes.len() as u64).to_be_bytes());
    digest.update(state_bytes);
    digest.update((manifest_sha256.len() as u64).to_be_bytes());
    digest.update(manifest_sha256.as_bytes());
    let encoded = hex::encode(digest.finalize());
    base.join(format!(
        "{MACOS_SHORT_HOME_PREFIX}{}",
        &encoded[..MACOS_SHORT_HOME_DIGEST_HEX_CHARS]
    ))
}

#[cfg(unix)]
fn macos_podman_ignition_socket_alias(home: &Path, machine_name: &str) -> PathBuf {
    home.join(".podman")
        .join(format!("{machine_name}{PODMAN_IGNITION_SOCKET_SUFFIX}"))
}

#[cfg(unix)]
fn ensure_macos_short_home_directory(path: &Path, effective_uid: libc::uid_t) -> AppResult<()> {
    use std::os::unix::fs::DirBuilderExt;

    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700);
    match builder.create(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }

    verify_macos_short_home_directory(path, effective_uid)
}

#[cfg(unix)]
fn verify_macos_short_home_directory(path: &Path, effective_uid: libc::uid_t) -> AppResult<()> {
    drop(open_verified_macos_short_home_directory(
        path,
        effective_uid,
    )?);
    Ok(())
}

#[cfg(unix)]
fn open_verified_macos_short_home_directory(
    path: &Path,
    effective_uid: libc::uid_t,
) -> AppResult<File> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(AppError::NotAuthorized(
            "managed runtime macOS command home must be a real directory".into(),
        ));
    }
    if metadata.uid() != effective_uid || metadata.mode() & 0o7777 != 0o700 {
        return Err(AppError::NotAuthorized(
            "managed runtime macOS command home has unsafe ownership or permissions".into(),
        ));
    }

    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW);
    let directory = options.open(path).map_err(|error| {
        AppError::NotAuthorized(format!(
            "managed runtime macOS command home could not be opened without following links: {error}"
        ))
    })?;
    let opened = directory.metadata()?;
    if !opened.is_dir()
        || opened.dev() != metadata.dev()
        || opened.ino() != metadata.ino()
        || opened.uid() != effective_uid
        || opened.mode() & 0o7777 != 0o700
    {
        return Err(AppError::NotAuthorized(
            "managed runtime macOS command home changed while it was being verified".into(),
        ));
    }
    Ok(directory)
}

#[cfg(unix)]
fn open_verified_macos_socket_alias_directory(
    path: &Path,
    effective_uid: libc::uid_t,
) -> AppResult<File> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != effective_uid
        || metadata.mode() & 0o7777 != 0o700
    {
        return Err(AppError::NotAuthorized(
            "managed runtime macOS socket-alias directory is unsafe".into(),
        ));
    }
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW);
    let directory = options.open(path).map_err(|error| {
        AppError::NotAuthorized(format!(
            "managed runtime macOS socket-alias directory could not be opened without following links: {error}"
        ))
    })?;
    verify_opened_macos_socket_alias_directory(path, &directory, &metadata, effective_uid)?;
    Ok(directory)
}

#[cfg(unix)]
fn verify_opened_macos_socket_alias_directory(
    path: &Path,
    directory: &File,
    expected: &fs::Metadata,
    effective_uid: libc::uid_t,
) -> AppResult<()> {
    use std::os::unix::fs::MetadataExt;

    let current = fs::symlink_metadata(path)?;
    let opened = directory.metadata()?;
    if current.file_type().is_symlink()
        || !current.is_dir()
        || current.dev() != expected.dev()
        || current.ino() != expected.ino()
        || current.uid() != effective_uid
        || current.mode() & 0o7777 != 0o700
        || !opened.is_dir()
        || opened.dev() != current.dev()
        || opened.ino() != current.ino()
        || opened.uid() != effective_uid
        || opened.mode() & 0o7777 != 0o700
    {
        return Err(AppError::NotAuthorized(
            "managed runtime macOS socket-alias directory changed while it was being verified"
                .into(),
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn macos_socket_alias_stat(directory: &File, basename: &std::ffi::CStr) -> AppResult<libc::stat> {
    use std::os::fd::AsRawFd;

    let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: directory owns a live directory descriptor, basename is a
    // NUL-terminated relative name, and metadata points to writable storage.
    if unsafe {
        libc::fstatat(
            directory.as_raw_fd(),
            basename.as_ptr(),
            metadata.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        let error = io::Error::last_os_error();
        return Err(AppError::NotAuthorized(format!(
            "managed runtime macOS ignition socket could not be inspected without following links: {error}"
        )));
    }
    // SAFETY: successful fstatat initialized every field of metadata.
    Ok(unsafe { metadata.assume_init() })
}

#[cfg(unix)]
fn remove_expected_macos_ignition_socket_alias(
    aliases: &Path,
    effective_uid: libc::uid_t,
    machine_name: &str,
) -> AppResult<()> {
    use std::ffi::CString;
    use std::os::fd::AsRawFd;

    if machine_name.is_empty()
        || machine_name.len() > MAX_MACHINE_NAME_BYTES
        || !machine_name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err(AppError::NotAuthorized(
            "managed runtime macOS machine name is invalid for exact socket cleanup".into(),
        ));
    }
    let expected_basename = format!("{machine_name}{PODMAN_IGNITION_SOCKET_SUFFIX}");
    let expected_c_basename = CString::new(expected_basename.as_bytes()).map_err(|_| {
        AppError::Internal(
            "managed runtime macOS ignition socket basename was not representable".into(),
        )
    })?;
    let directory = open_verified_macos_socket_alias_directory(aliases, effective_uid)?;

    let mut entries = fs::read_dir(aliases)?;
    let first = entries.next().transpose()?.map(|entry| entry.file_name());
    if entries.next().transpose()?.is_some()
        || first
            .as_ref()
            .is_some_and(|name| name != OsStr::new(&expected_basename))
    {
        return Err(AppError::NotAuthorized(
            "managed runtime macOS socket-alias directory contained an unexpected entry after machine removal"
                .into(),
        ));
    }

    verify_opened_macos_socket_alias_directory(
        aliases,
        &directory,
        &directory.metadata()?,
        effective_uid,
    )?;
    if first.is_some() {
        let expected = macos_socket_alias_stat(&directory, &expected_c_basename)?;
        if expected.st_mode & libc::S_IFMT != libc::S_IFSOCK
            || expected.st_uid != effective_uid
            || expected.st_nlink != 1
            || expected.st_mode & 0o7000 != 0
        {
            return Err(AppError::NotAuthorized(
                "managed runtime macOS ignition socket is not an expected current-user single-link Unix socket"
                    .into(),
            ));
        }
        let current = macos_socket_alias_stat(&directory, &expected_c_basename)?;
        if current.st_dev != expected.st_dev
            || current.st_ino != expected.st_ino
            || current.st_mode != expected.st_mode
            || current.st_uid != expected.st_uid
            || current.st_nlink != expected.st_nlink
        {
            return Err(AppError::NotAuthorized(
                "managed runtime macOS ignition socket changed while it was being verified".into(),
            ));
        }
        // SAFETY: directory is the verified .podman descriptor and the fixed
        // relative basename was checked twice with AT_SYMLINK_NOFOLLOW.
        if unsafe { libc::unlinkat(directory.as_raw_fd(), expected_c_basename.as_ptr(), 0) } != 0 {
            let error = io::Error::last_os_error();
            return Err(AppError::Runtime(format!(
                "managed runtime macOS ignition socket could not be removed: {error}"
            )));
        }
    }

    verify_opened_macos_socket_alias_directory(
        aliases,
        &directory,
        &directory.metadata()?,
        effective_uid,
    )?;
    if fs::read_dir(aliases)?.next().transpose()?.is_some() {
        return Err(AppError::NotAuthorized(
            "managed runtime macOS socket-alias directory changed during exact cleanup".into(),
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn macos_runtime_child_stat(
    parent: &File,
    basename: &std::ffi::CStr,
    label: &str,
) -> AppResult<Option<libc::stat>> {
    use std::os::fd::AsRawFd;

    let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: parent owns a live directory descriptor, basename is a
    // NUL-terminated relative name, and metadata points to writable storage.
    if unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            basename.as_ptr(),
            metadata.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ENOENT) {
            return Ok(None);
        }
        return Err(AppError::NotAuthorized(format!(
            "managed runtime macOS {label} could not be inspected without following links: {error}"
        )));
    }
    // SAFETY: successful fstatat initialized every field of metadata.
    Ok(Some(unsafe { metadata.assume_init() }))
}

#[cfg(unix)]
fn macos_runtime_opened_stat(file: &File, label: &str) -> AppResult<libc::stat> {
    use std::os::fd::AsRawFd;

    let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: file owns a live descriptor and metadata points to writable storage.
    if unsafe { libc::fstat(file.as_raw_fd(), metadata.as_mut_ptr()) } != 0 {
        let error = io::Error::last_os_error();
        return Err(AppError::NotAuthorized(format!(
            "managed runtime macOS {label} descriptor could not be inspected: {error}"
        )));
    }
    // SAFETY: successful fstat initialized every field of metadata.
    Ok(unsafe { metadata.assume_init() })
}

#[cfg(unix)]
fn verify_exact_macos_known_hosts_entry(ssh_directory: &Path) -> AppResult<()> {
    let mut entries = fs::read_dir(ssh_directory)?;
    let first = entries.next().transpose()?.map(|entry| entry.file_name());
    if first.as_deref() != Some(OsStr::new(PODMAN_MACOS_KNOWN_HOSTS_FILE))
        || entries.next().transpose()?.is_some()
    {
        return Err(AppError::NotAuthorized(
            "managed runtime macOS SSH directory did not contain exactly the expected empty known_hosts file"
                .into(),
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn remove_expected_macos_known_hosts(
    home_path: &Path,
    home: &File,
    effective_uid: libc::uid_t,
) -> AppResult<()> {
    use std::ffi::CString;
    use std::os::fd::{AsRawFd, FromRawFd};

    let ssh_basename = CString::new(PODMAN_MACOS_SSH_DIRECTORY).map_err(|_| {
        AppError::Internal("managed runtime macOS SSH directory name was invalid".into())
    })?;
    let known_hosts_basename = CString::new(PODMAN_MACOS_KNOWN_HOSTS_FILE).map_err(|_| {
        AppError::Internal("managed runtime macOS known_hosts filename was invalid".into())
    })?;
    let Some(expected_directory) = macos_runtime_child_stat(home, &ssh_basename, "SSH directory")?
    else {
        return Ok(());
    };
    if expected_directory.st_mode & libc::S_IFMT != libc::S_IFDIR
        || expected_directory.st_uid != effective_uid
        || expected_directory.st_mode & 0o7777 != 0o700
    {
        return Err(AppError::NotAuthorized(
            "managed runtime macOS SSH directory has unsafe type, ownership, or permissions".into(),
        ));
    }

    // SAFETY: home is a verified command-home descriptor and ssh_basename is
    // the fixed relative .ssh child. O_NOFOLLOW rejects a link replacement.
    let raw_directory = unsafe {
        libc::openat(
            home.as_raw_fd(),
            ssh_basename.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if raw_directory < 0 {
        let error = io::Error::last_os_error();
        return Err(AppError::NotAuthorized(format!(
            "managed runtime macOS SSH directory could not be opened without following links: {error}"
        )));
    }
    // SAFETY: openat returned a fresh owned descriptor that is transferred to File.
    let directory = unsafe { File::from_raw_fd(raw_directory) };
    let opened_directory = macos_runtime_opened_stat(&directory, "SSH directory")?;
    if opened_directory.st_mode & libc::S_IFMT != libc::S_IFDIR
        || opened_directory.st_dev != expected_directory.st_dev
        || opened_directory.st_ino != expected_directory.st_ino
        || opened_directory.st_uid != effective_uid
        || opened_directory.st_mode & 0o7777 != 0o700
    {
        return Err(AppError::NotAuthorized(
            "managed runtime macOS SSH directory changed while it was opened".into(),
        ));
    }

    let ssh_directory = home_path.join(PODMAN_MACOS_SSH_DIRECTORY);
    verify_exact_macos_known_hosts_entry(&ssh_directory)?;
    let expected_file =
        macos_runtime_child_stat(&directory, &known_hosts_basename, "known_hosts file")?
            .ok_or_else(|| {
                AppError::NotAuthorized(
                    "managed runtime macOS known_hosts file disappeared during verification".into(),
                )
            })?;
    if expected_file.st_mode & libc::S_IFMT != libc::S_IFREG
        || expected_file.st_uid != effective_uid
        || expected_file.st_nlink != 1
        || expected_file.st_mode & 0o7777 != 0o600
        || expected_file.st_size != 0
    {
        return Err(AppError::NotAuthorized(
            "managed runtime macOS known_hosts file is not the expected current-user, single-link, mode-0600 empty regular file"
                .into(),
        ));
    }

    // SAFETY: directory is the verified .ssh descriptor and the basename is
    // fixed. O_NOFOLLOW prevents opening a symlink replacement.
    let raw_file = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            known_hosts_basename.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if raw_file < 0 {
        let error = io::Error::last_os_error();
        return Err(AppError::NotAuthorized(format!(
            "managed runtime macOS known_hosts file could not be opened without following links: {error}"
        )));
    }
    // SAFETY: openat returned a fresh owned descriptor that is transferred to File.
    let file = unsafe { File::from_raw_fd(raw_file) };
    let opened_file = macos_runtime_opened_stat(&file, "known_hosts file")?;
    if opened_file.st_mode & libc::S_IFMT != libc::S_IFREG
        || opened_file.st_dev != expected_file.st_dev
        || opened_file.st_ino != expected_file.st_ino
        || opened_file.st_uid != effective_uid
        || opened_file.st_nlink != 1
        || opened_file.st_mode & 0o7777 != 0o600
        || opened_file.st_size != 0
    {
        return Err(AppError::NotAuthorized(
            "managed runtime macOS known_hosts file changed while it was opened".into(),
        ));
    }

    verify_exact_macos_known_hosts_entry(&ssh_directory)?;
    let current_file =
        macos_runtime_child_stat(&directory, &known_hosts_basename, "known_hosts file")?
            .ok_or_else(|| {
                AppError::NotAuthorized(
                    "managed runtime macOS known_hosts file disappeared during exact cleanup"
                        .into(),
                )
            })?;
    let reopened_file = macos_runtime_opened_stat(&file, "known_hosts file")?;
    let current_directory = macos_runtime_child_stat(home, &ssh_basename, "SSH directory")?
        .ok_or_else(|| {
            AppError::NotAuthorized(
                "managed runtime macOS SSH directory disappeared during exact cleanup".into(),
            )
        })?;
    let reopened_directory = macos_runtime_opened_stat(&directory, "SSH directory")?;
    if current_file.st_dev != expected_file.st_dev
        || current_file.st_ino != expected_file.st_ino
        || current_file.st_mode != expected_file.st_mode
        || current_file.st_uid != expected_file.st_uid
        || current_file.st_nlink != expected_file.st_nlink
        || current_file.st_size != 0
        || reopened_file.st_dev != current_file.st_dev
        || reopened_file.st_ino != current_file.st_ino
        || reopened_file.st_mode != current_file.st_mode
        || reopened_file.st_uid != effective_uid
        || reopened_file.st_nlink != 1
        || reopened_file.st_size != 0
        || current_directory.st_dev != expected_directory.st_dev
        || current_directory.st_ino != expected_directory.st_ino
        || current_directory.st_mode != expected_directory.st_mode
        || current_directory.st_uid != expected_directory.st_uid
        || reopened_directory.st_dev != current_directory.st_dev
        || reopened_directory.st_ino != current_directory.st_ino
        || reopened_directory.st_uid != effective_uid
        || reopened_directory.st_mode & 0o7777 != 0o700
    {
        return Err(AppError::NotAuthorized(
            "managed runtime macOS SSH residue changed during exact cleanup".into(),
        ));
    }

    // SAFETY: directory is the verified .ssh descriptor, and the exact file
    // was proved unchanged through its still-live no-follow descriptor.
    if unsafe { libc::unlinkat(directory.as_raw_fd(), known_hosts_basename.as_ptr(), 0) } != 0 {
        let error = io::Error::last_os_error();
        return Err(AppError::Runtime(format!(
            "managed runtime macOS known_hosts file could not be removed: {error}"
        )));
    }
    directory.sync_all()?;
    if fs::read_dir(&ssh_directory)?.next().transpose()?.is_some() {
        return Err(AppError::NotAuthorized(
            "managed runtime macOS SSH directory changed after exact known_hosts cleanup".into(),
        ));
    }
    let final_directory = macos_runtime_child_stat(home, &ssh_basename, "SSH directory")?
        .ok_or_else(|| {
            AppError::NotAuthorized(
                "managed runtime macOS SSH directory disappeared before exact removal".into(),
            )
        })?;
    let final_opened_directory = macos_runtime_opened_stat(&directory, "SSH directory")?;
    if final_directory.st_dev != expected_directory.st_dev
        || final_directory.st_ino != expected_directory.st_ino
        || final_directory.st_mode != expected_directory.st_mode
        || final_directory.st_uid != expected_directory.st_uid
        || final_opened_directory.st_dev != final_directory.st_dev
        || final_opened_directory.st_ino != final_directory.st_ino
        || final_opened_directory.st_uid != effective_uid
        || final_opened_directory.st_mode & 0o7777 != 0o700
    {
        return Err(AppError::NotAuthorized(
            "managed runtime macOS SSH directory changed before exact removal".into(),
        ));
    }
    // SAFETY: home is the verified command-home descriptor and .ssh is still
    // the same empty directory held open above.
    if unsafe { libc::unlinkat(home.as_raw_fd(), ssh_basename.as_ptr(), libc::AT_REMOVEDIR) } != 0 {
        let error = io::Error::last_os_error();
        return Err(AppError::Runtime(format!(
            "managed runtime macOS SSH directory could not be removed: {error}"
        )));
    }
    home.sync_all()?;
    Ok(())
}

#[cfg(unix)]
fn remove_macos_short_home_directory(
    path: &Path,
    effective_uid: libc::uid_t,
    machine_name: &str,
) -> AppResult<()> {
    remove_macos_short_home_directory_at(
        path,
        Path::new(MACOS_SHORT_HOME_BASE),
        effective_uid,
        machine_name,
    )
}

#[cfg(unix)]
fn remove_macos_short_home_directory_at(
    path: &Path,
    base: &Path,
    effective_uid: libc::uid_t,
    machine_name: &str,
) -> AppResult<()> {
    if path.parent() != Some(base) {
        return Err(AppError::NotAuthorized(
            "managed runtime macOS command-home cleanup escaped its exact temporary base".into(),
        ));
    }
    match fs::symlink_metadata(path) {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    }
    let home = open_verified_macos_short_home_directory(path, effective_uid)?;
    let base = base.canonicalize()?;
    let base_metadata = fs::symlink_metadata(&base)?;
    if !base_metadata.is_dir() || base_metadata.file_type().is_symlink() {
        return Err(AppError::NotAuthorized(
            "managed runtime macOS temporary base is not a real directory".into(),
        ));
    }

    // Complete the root whitelist before deleting either recognized provider
    // residue. This prevents an unknown peer entry from being hidden by a
    // partial cleanup of .podman or .ssh.
    for entry in fs::read_dir(path)? {
        let name = entry?.file_name();
        if name != OsStr::new(".podman") && name != OsStr::new(PODMAN_MACOS_SSH_DIRECTORY) {
            return Err(AppError::NotAuthorized(
                "managed runtime macOS command home contained an unexpected entry after machine removal"
                    .into(),
            ));
        }
    }
    let aliases = path.join(".podman");
    match fs::symlink_metadata(&aliases) {
        Ok(_) => {
            remove_expected_macos_ignition_socket_alias(&aliases, effective_uid, machine_name)?;
            fs::remove_dir(&aliases)?;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    // Pinned Podman 5.8.2's Go SSH backend creates this empty file before it
    // selects the insecure host-key callback used only for machine connections.
    // Accept only the exact observed empty artifact; it is never provider state.
    remove_expected_macos_known_hosts(path, &home, effective_uid)?;
    if fs::read_dir(path)?.next().transpose()?.is_some() {
        return Err(AppError::NotAuthorized(
            "managed runtime macOS command home contained an unexpected entry after machine removal"
                .into(),
        ));
    }
    fs::remove_dir(path)?;
    sync_directory(&base)
}

fn managed_path(
    install: &Path,
    target: &ManagedTarget,
    windows_directories: Option<&WindowsSystemDirectories>,
) -> AppResult<OsString> {
    let bin = install.join("bin");
    let rendered = bin.to_str().ok_or_else(|| {
        AppError::Runtime("managed runtime install path is not representable".into())
    })?;
    let path = match target.operating_system {
        ManagedOperatingSystem::Windows => {
            let system32 = &windows_directories
                .ok_or_else(|| {
                    AppError::Internal(
                        "managed Windows PATH did not receive verified system directories".into(),
                    )
                })?
                .system32;
            // Resolve Windows-owned utilities (notably wsl.exe) from the
            // verified System32 directory before consulting the managed
            // helper bundle. Podman's explicit helper_binaries_dir still
            // selects release-pinned gvproxy/win-sshproxy binaries.
            std::env::join_paths([system32.clone(), PathBuf::from(rendered)])
                .map_err(|_| AppError::Runtime("managed Windows runtime PATH is invalid".into()))?
        }
        ManagedOperatingSystem::Linux | ManagedOperatingSystem::Macos => std::env::join_paths([
            PathBuf::from(rendered),
            PathBuf::from("/usr/bin"),
            PathBuf::from("/bin"),
        ])
        .map_err(|_| AppError::Runtime("managed runtime PATH is invalid".into()))?,
    };
    Ok(path)
}

fn apply_platform_command_environment(
    environment: &mut BTreeMap<OsString, OsString>,
    operating_system: ManagedOperatingSystem,
) {
    let key = OsString::from("NoDefaultCurrentDirectoryInExePath");
    if operating_system == ManagedOperatingSystem::Windows {
        // Go's os/exec honors this process environment switch on Windows and
        // therefore never searches the private current directory ahead of the
        // already constrained managed PATH for helper executables.
        environment.insert(key, OsString::from("1"));
    } else {
        environment.remove(&key);
    }
}

fn toml_string(path: &Path) -> AppResult<String> {
    let value = path.to_str().ok_or_else(|| {
        AppError::Runtime("managed runtime helper path is not representable".into())
    })?;
    Ok(toml_scalar(value))
}

fn toml_scalar(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len() + 2);
    escaped.push('"');
    for character in value.chars() {
        match character {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            character if character.is_control() => {
                use std::fmt::Write as _;
                let _ = write!(escaped, "\\u{:04x}", character as u32);
            }
            character => escaped.push(character),
        }
    }
    escaped.push('"');
    escaped
}

#[cfg(windows)]
fn windows_well_known_sid(
    kind: windows_sys::Win32::Security::WELL_KNOWN_SID_TYPE,
) -> io::Result<WindowsCurrentUserSid> {
    use windows_sys::Win32::Security::{CreateWellKnownSid, IsValidSid, SECURITY_MAX_SID_SIZE};

    let mut storage =
        vec![0_u32; (SECURITY_MAX_SID_SIZE as usize).div_ceil(std::mem::size_of::<u32>())];
    let mut length = (storage.len() * std::mem::size_of::<u32>()) as u32;
    // SAFETY: storage is aligned and contains length writable bytes; these
    // well-known SID kinds do not require a domain SID.
    if unsafe {
        CreateWellKnownSid(
            kind,
            std::ptr::null_mut(),
            storage.as_mut_ptr().cast(),
            &raw mut length,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: CreateWellKnownSid initialized the SID in storage.
    if unsafe { IsValidSid(storage.as_mut_ptr().cast()) } == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Windows returned an invalid well-known SID",
        ));
    }
    Ok(WindowsCurrentUserSid { storage })
}

#[cfg(windows)]
fn windows_managed_namespace_error(error: io::Error) -> AppError {
    if error.kind() == io::ErrorKind::PermissionDenied {
        AppError::NotAuthorized(format!(
            "managed runtime Windows namespace is replaceable or unsafe: {error}"
        ))
    } else {
        error.into()
    }
}

#[cfg(windows)]
fn windows_trusted_installer_sid() -> io::Result<WindowsCurrentUserSid> {
    use windows_sys::Win32::Security::IsValidSid;

    // S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464.
    // TrustedInstaller commonly owns/protects Windows volume-root ancestors.
    let subauthorities = [
        80_u32,
        956_008_885,
        3_418_522_649,
        1_831_038_044,
        1_853_292_631,
        2_271_478_464,
    ];
    let byte_length = 8 + subauthorities.len() * std::mem::size_of::<u32>();
    let mut storage = vec![0_u32; byte_length.div_ceil(std::mem::size_of::<u32>())];
    let bytes = unsafe {
        // SAFETY: storage is live, aligned, and byte_length is within its allocation.
        std::slice::from_raw_parts_mut(storage.as_mut_ptr().cast::<u8>(), byte_length)
    };
    bytes[0] = 1;
    bytes[1] = subauthorities.len() as u8;
    bytes[2..8].copy_from_slice(&[0, 0, 0, 0, 0, 5]);
    for (index, value) in subauthorities.into_iter().enumerate() {
        let offset = 8 + index * std::mem::size_of::<u32>();
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    let sid = WindowsCurrentUserSid { storage };
    // SAFETY: the storage above contains a complete aligned SID encoding.
    if unsafe { IsValidSid(sid.as_ptr()) } == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "the built-in TrustedInstaller SID encoding is invalid",
        ));
    }
    Ok(sid)
}

#[cfg(windows)]
fn windows_sid_is_trusted_for_managed_namespace(
    sid: windows_sys::Win32::Security::PSID,
    trusted: &[WindowsCurrentUserSid],
) -> bool {
    use windows_sys::Win32::Security::{EqualSid, IsValidSid};

    if sid.is_null() || unsafe { IsValidSid(sid) } == 0 {
        return false;
    }
    trusted
        .iter()
        // SAFETY: sid and each trusted SID were validated and remain live.
        .any(|candidate| unsafe { EqualSid(sid, candidate.as_ptr()) } != 0)
}

#[cfg(windows)]
fn windows_sid_is_app_capability(sid: windows_sys::Win32::Security::PSID) -> bool {
    use windows_sys::Win32::Security::{
        GetSidIdentifierAuthority, GetSidSubAuthority, GetSidSubAuthorityCount, IsValidSid,
    };

    if sid.is_null() || unsafe { IsValidSid(sid) } == 0 {
        return false;
    }
    // Capability SIDs use SECURITY_APP_PACKAGE_AUTHORITY (S-1-15) and the
    // SECURITY_CAPABILITY_BASE_RID (3). Require a concrete capability RID or
    // hash after the base RID; package identities (S-1-15-2-*) do not qualify.
    // SAFETY: IsValidSid established readable authority/count/subauthority data.
    let authority = unsafe { GetSidIdentifierAuthority(sid) };
    let count = unsafe { GetSidSubAuthorityCount(sid) };
    if authority.is_null() || count.is_null() || unsafe { *count } < 2 {
        return false;
    }
    // SAFETY: the authority pointer and first subauthority are part of the
    // valid SID, and the count above proves subauthority zero exists.
    unsafe { (*authority).Value == [0, 0, 0, 0, 0, 15] && *GetSidSubAuthority(sid, 0) == 3 }
}

#[cfg(windows)]
fn windows_local_app_data_directory() -> io::Result<PathBuf> {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::System::Com::CoTaskMemFree;
    use windows_sys::Win32::UI::Shell::{
        FOLDERID_LocalAppData, KF_FLAG_DEFAULT, SHGetKnownFolderPath,
    };

    struct KnownFolderPath(*mut u16);

    impl Drop for KnownFolderPath {
        fn drop(&mut self) {
            // SAFETY: SHGetKnownFolderPath allocates this buffer with the COM
            // task allocator, and this guard owns the single corresponding free.
            unsafe { CoTaskMemFree(self.0.cast()) };
        }
    }

    let mut raw = std::ptr::null_mut();
    let folder_id = FOLDERID_LocalAppData;
    // SAFETY: FOLDERID_LocalAppData is a valid known-folder identifier, the
    // current-user token is selected by a null token, and raw is writable.
    let status = unsafe {
        SHGetKnownFolderPath(
            &raw const folder_id,
            KF_FLAG_DEFAULT as u32,
            std::ptr::null_mut(),
            &raw mut raw,
        )
    };
    if status < 0 {
        return Err(io::Error::other(format!(
            "Windows could not resolve the current user's LocalAppData directory (HRESULT 0x{:08x})",
            status as u32
        )));
    }
    if raw.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Windows returned a null LocalAppData directory",
        ));
    }
    let allocation = KnownFolderPath(raw);
    const MAX_KNOWN_FOLDER_CODE_UNITS: usize = 32_768;
    let mut length = 0_usize;
    // SAFETY: SHGetKnownFolderPath returned a NUL-terminated task allocation.
    while length < MAX_KNOWN_FOLDER_CODE_UNITS && unsafe { *allocation.0.add(length) } != 0 {
        length += 1;
    }
    if length == 0 || length == MAX_KNOWN_FOLDER_CODE_UNITS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Windows returned an invalid LocalAppData directory",
        ));
    }
    // SAFETY: the bounded scan above found the terminator, so these code units
    // are readable within the live task allocation.
    let encoded = unsafe { std::slice::from_raw_parts(allocation.0, length) };
    Ok(PathBuf::from(OsString::from_wide(encoded)))
}

#[cfg(windows)]
fn windows_current_local_app_data_ancestor_identities()
-> io::Result<WindowsLocalAppDataAncestorIdentities> {
    let local_app_data_path = windows_local_app_data_directory()?.canonicalize()?;
    let app_data_path = local_app_data_path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "Windows LocalAppData directory has no AppData parent",
        )
    })?;
    if app_data_path.parent().is_none() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Windows LocalAppData directory is anchored directly at a filesystem root",
        ));
    }
    let local_app_data = open_windows_real_directory_security_handle(&local_app_data_path)?;
    let app_data = open_windows_real_directory_security_handle(app_data_path)?;
    Ok(WindowsLocalAppDataAncestorIdentities {
        local_app_data: windows_file_information(&local_app_data)?.identity,
        app_data: windows_file_information(&app_data)?.identity,
    })
}

#[cfg(windows)]
fn windows_local_app_data_ancestor_identities(
    guards: &[File],
) -> io::Result<Option<WindowsLocalAppDataAncestorIdentities>> {
    let identities = windows_current_local_app_data_ancestor_identities()?;
    let chain_contains_local_app_data = guards.iter().try_fold(false, |found, guard| {
        Ok::<_, io::Error>(
            found || windows_file_information(guard)?.identity == identities.local_app_data,
        )
    })?;
    Ok(chain_contains_local_app_data.then_some(identities))
}

#[cfg(windows)]
fn windows_managed_namespace_ancestor_acl_policy(
    identity: WindowsFileIdentity,
    local_app_data: Option<WindowsLocalAppDataAncestorIdentities>,
) -> WindowsManagedNamespaceAncestorAclPolicy {
    match local_app_data {
        Some(identities)
            if identity == identities.local_app_data || identity == identities.app_data =>
        {
            WindowsManagedNamespaceAncestorAclPolicy::PinnedLocalAppDataCapability
        }
        _ => WindowsManagedNamespaceAncestorAclPolicy::Strict,
    }
}

#[cfg(windows)]
fn windows_basic_ace_sid(
    raw_ace: *mut std::ffi::c_void,
    ace_size: usize,
) -> io::Result<windows_sys::Win32::Security::PSID> {
    use windows_sys::Win32::Security::{ACCESS_ALLOWED_ACE, GetLengthSid, IsValidSid, PSID};
    use windows_sys::Win32::System::SystemServices::SID_REVISION;

    let sid_offset = std::mem::size_of::<ACCESS_ALLOWED_ACE>()
        .checked_sub(std::mem::size_of::<u32>())
        .expect("ACCESS_ALLOWED_ACE contains SidStart");
    let minimum_sid_bytes = 8_usize;
    if ace_size < sid_offset + minimum_sid_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "managed runtime namespace ancestor has a truncated basic ACE",
        ));
    }
    // Read only the bounded SID header before asking Win32 to validate it.
    // SAFETY: the checks above establish that both header bytes are inside the ACE.
    let sid_bytes = unsafe { raw_ace.cast::<u8>().add(sid_offset) };
    let revision = unsafe { *sid_bytes };
    let subauthority_count = usize::from(unsafe { *sid_bytes.add(1) });
    let sid_length = minimum_sid_bytes
        .checked_add(
            subauthority_count
                .checked_mul(std::mem::size_of::<u32>())
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "Windows SID size overflowed")
                })?,
        )
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Windows SID size overflowed"))?;
    if revision != SID_REVISION as u8
        || sid_offset
            .checked_add(sid_length)
            .is_none_or(|expected| expected != ace_size)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "managed runtime namespace ancestor has a malformed bounded SID",
        ));
    }
    let sid: PSID = sid_bytes.cast();
    // SAFETY: the SID header-derived length was proven to be exactly bounded by the ACE.
    if unsafe { IsValidSid(sid) } == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "managed runtime namespace ancestor has an invalid basic ACE SID",
        ));
    }
    // SAFETY: IsValidSid established that the embedded SID is readable.
    if unsafe { GetLengthSid(sid) } as usize != sid_length {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "managed runtime namespace ancestor has a malformed basic ACE",
        ));
    }
    Ok(sid)
}

#[cfg(windows)]
fn verify_windows_managed_namespace_ancestor_handle(
    directory: &File,
    allow_trusted_installer_anchor: bool,
    policy: WindowsManagedNamespaceAncestorAclPolicy,
) -> io::Result<()> {
    use std::ffi::c_void;
    use windows_sys::Win32::Security::{
        ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_SIZE_INFORMATION, AclSizeInformation,
        GENERIC_MAPPING, GetAce, GetAclInformation, GetSecurityDescriptorDacl,
        GetSecurityDescriptorOwner, INHERIT_ONLY_ACE, IsValidAcl, MapGenericMask,
        WinBuiltinAdministratorsSid, WinLocalSystemSid,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        DELETE, FILE_ALL_ACCESS, FILE_APPEND_DATA, FILE_DELETE_CHILD, FILE_GENERIC_EXECUTE,
        FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA,
        FILE_WRITE_EA, WRITE_DAC, WRITE_OWNER,
    };
    use windows_sys::Win32::System::SystemServices::{
        ACCESS_ALLOWED_ACE_TYPE, ACCESS_ALLOWED_CALLBACK_ACE_TYPE,
        ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE, ACCESS_ALLOWED_COMPOUND_ACE_TYPE,
        ACCESS_ALLOWED_OBJECT_ACE_TYPE, ACCESS_DENIED_ACE_TYPE,
    };

    let mut trusted = vec![
        windows_current_user_sid()?,
        windows_well_known_sid(WinLocalSystemSid)?,
        windows_well_known_sid(WinBuiltinAdministratorsSid)?,
    ];
    if allow_trusted_installer_anchor {
        trusted.push(windows_trusted_installer_sid()?);
    }
    let mut descriptor = windows_owner_dacl_security_descriptor(directory)?;
    let security_descriptor = descriptor.as_mut_ptr().cast::<c_void>();

    let mut owner = std::ptr::null_mut();
    let mut owner_defaulted = 0;
    // SAFETY: security_descriptor is the live descriptor returned by the kernel.
    if unsafe {
        GetSecurityDescriptorOwner(
            security_descriptor,
            &raw mut owner,
            &raw mut owner_defaulted,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if !windows_sid_is_trusted_for_managed_namespace(owner, &trusted) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "managed runtime namespace ancestor has an untrusted Windows owner",
        ));
    }

    let mut dacl_present = 0;
    let mut dacl_defaulted = 0;
    let mut dacl = std::ptr::null_mut::<ACL>();
    // SAFETY: security_descriptor is valid and all output pointers are writable.
    if unsafe {
        GetSecurityDescriptorDacl(
            security_descriptor,
            &raw mut dacl_present,
            &raw mut dacl,
            &raw mut dacl_defaulted,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if dacl_present == 0 || dacl.is_null() || unsafe { IsValidAcl(dacl) } == 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "managed runtime namespace ancestor has no valid Windows DACL",
        ));
    }

    let mut acl_information = ACL_SIZE_INFORMATION::default();
    // SAFETY: dacl is valid and acl_information is writable storage of the declared size.
    if unsafe {
        GetAclInformation(
            dacl,
            (&raw mut acl_information).cast(),
            std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }

    let mapping = GENERIC_MAPPING {
        GenericRead: FILE_GENERIC_READ,
        GenericWrite: FILE_GENERIC_WRITE,
        GenericExecute: FILE_GENERIC_EXECUTE,
        GenericAll: FILE_ALL_ACCESS,
    };
    let dangerous = FILE_DELETE_CHILD | DELETE | WRITE_DAC | WRITE_OWNER;
    for index in 0..acl_information.AceCount {
        let mut raw_ace = std::ptr::null_mut::<c_void>();
        // SAFETY: index is bounded by the ACE count returned for this valid ACL.
        if unsafe { GetAce(dacl, index, &raw mut raw_ace) } == 0 || raw_ace.is_null() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: GetAce returned at least an ACE_HEADER inside the live ACL.
        let header = unsafe { &*raw_ace.cast::<ACE_HEADER>() };
        if header.AceFlags & (INHERIT_ONLY_ACE as u8) != 0
            && policy != WindowsManagedNamespaceAncestorAclPolicy::ProductDataRoot
        {
            continue;
        }
        let ace_type = u32::from(header.AceType);
        let ace_size = usize::from(header.AceSize);
        match ace_type {
            ACCESS_ALLOWED_ACE_TYPE => {
                let sid = windows_basic_ace_sid(raw_ace, ace_size)?;
                // SAFETY: the validated basic ACE contains the fixed Mask field.
                let mut mask = unsafe { (*raw_ace.cast::<ACCESS_ALLOWED_ACE>()).Mask };
                // SAFETY: mask and mapping are initialized writable/readable values.
                unsafe { MapGenericMask(&raw mut mask, &raw const mapping) };
                let trusted_principal = windows_sid_is_trusted_for_managed_namespace(sid, &trusted);
                let pinned_local_app_data_capability = policy
                    == WindowsManagedNamespaceAncestorAclPolicy::PinnedLocalAppDataCapability
                    && windows_sid_is_app_capability(sid);
                let forbidden =
                    if policy == WindowsManagedNamespaceAncestorAclPolicy::ProductDataRoot {
                        dangerous
                            | FILE_WRITE_DATA
                            | FILE_APPEND_DATA
                            | FILE_WRITE_EA
                            | FILE_WRITE_ATTRIBUTES
                    } else {
                        dangerous
                    };
                if mask & forbidden != 0 && !trusted_principal && !pinned_local_app_data_capability
                {
                    let detail = if policy
                        == WindowsManagedNamespaceAncestorAclPolicy::ProductDataRoot
                    {
                        "product data root grants write or replacement rights to an untrusted Windows principal"
                    } else {
                        "managed runtime namespace ancestor grants replacement rights to an untrusted Windows principal"
                    };
                    return Err(io::Error::new(io::ErrorKind::PermissionDenied, detail));
                }
                // Ordinary Users/AppPackages read/execute rules are harmless
                // and remain compatible with LocalAppData/runner temp roots.
            }
            ACCESS_DENIED_ACE_TYPE => {
                // A basic deny ACE cannot grant replacement rights, but still
                // require its encoded SID/size to be structurally exact.
                let _ = windows_basic_ace_sid(raw_ace, ace_size)?;
            }
            ACCESS_ALLOWED_CALLBACK_ACE_TYPE
            | ACCESS_ALLOWED_OBJECT_ACE_TYPE
            | ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE
            | ACCESS_ALLOWED_COMPOUND_ACE_TYPE => {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "managed runtime namespace ancestor has a conditional or object allow ACE",
                ));
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "managed runtime namespace ancestor has an unsupported Windows ACE",
                ));
            }
        }
    }
    Ok(())
}

#[cfg(windows)]
fn open_windows_real_directory_security_handle(path: &Path) -> io::Result<File> {
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::FromRawHandle;
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TRAVERSE, OPEN_EXISTING, READ_CONTROL,
    };

    let mut encoded = path.as_os_str().encode_wide().collect::<Vec<_>>();
    if encoded.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Windows path contains a NUL code unit",
        ));
    }
    encoded.push(0);
    // FILE_TRAVERSE is the minimum directory-specific read category that
    // participates in Windows share-mode arbitration without listing entries.
    // No FILE_SHARE_DELETE keeps this exact ancestor object pinned while the
    // remaining chain and managed child are opened and verified.
    let raw = unsafe {
        CreateFileW(
            encoded.as_ptr(),
            FILE_TRAVERSE | FILE_READ_ATTRIBUTES | READ_CONTROL,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: CreateFileW returned a uniquely owned handle.
    let directory = unsafe { File::from_raw_handle(raw) };
    let information = windows_file_information(&directory)?;
    if information.attributes & FILE_ATTRIBUTE_DIRECTORY == 0
        || information.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "managed runtime namespace ancestor is not a real directory",
        ));
    }
    Ok(directory)
}

#[cfg(windows)]
fn verify_windows_managed_namespace_ancestor_chain(
    canonical_parent: &Path,
) -> io::Result<Vec<File>> {
    let mut guards = Vec::new();
    for ancestor in canonical_parent.ancestors() {
        if ancestor.as_os_str().is_empty() {
            continue;
        }
        guards.push(open_windows_real_directory_security_handle(ancestor)?);
    }
    if guards.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Windows managed namespace has no canonical ancestor chain",
        ));
    }
    // Known-folder lookup is advisory only for the narrow capability-SID
    // compatibility rule. If Windows cannot bind this chain to the current
    // user's canonical LocalAppData directory, every ancestor remains strict.
    let local_app_data = windows_local_app_data_ancestor_identities(&guards)
        .ok()
        .flatten();
    for (index, guard) in guards.iter().enumerate() {
        let information = windows_file_information(guard)?;
        let policy =
            windows_managed_namespace_ancestor_acl_policy(information.identity, local_app_data);
        verify_windows_managed_namespace_ancestor_handle(guard, index + 1 == guards.len(), policy)?;
    }
    Ok(guards)
}

#[cfg(windows)]
fn open_or_create_windows_managed_private_directory_guard(
    path: &Path,
    verify_ancestor_chain: bool,
) -> io::Result<(PathBuf, WindowsManagedDirectoryGuard)> {
    open_or_create_windows_managed_directory_guard(
        path,
        verify_ancestor_chain,
        WindowsManagedDirectoryAclPolicy::CurrentUserOnly,
    )
}

#[cfg(windows)]
fn open_or_create_windows_managed_wsl_distribution_storage_guard(
    path: &Path,
) -> io::Result<(PathBuf, WindowsManagedDirectoryGuard)> {
    open_or_create_windows_managed_directory_guard(
        path,
        false,
        WindowsManagedDirectoryAclPolicy::CurrentUserAndLocalSystem,
    )
}

#[cfg(windows)]
fn open_or_create_windows_managed_directory_guard(
    path: &Path,
    verify_ancestor_chain: bool,
    policy: WindowsManagedDirectoryAclPolicy,
) -> io::Result<(PathBuf, WindowsManagedDirectoryGuard)> {
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::FromRawHandle;
    use windows_sys::Win32::Foundation::{FALSE, INVALID_HANDLE_VALUE, TRUE};
    use windows_sys::Win32::Security::{
        ACCESS_ALLOWED_ACE, ACL, ACL_REVISION, AddAccessAllowedAceEx, CONTAINER_INHERIT_ACE,
        InitializeAcl, InitializeSecurityDescriptor, OBJECT_INHERIT_ACE, SE_DACL_PROTECTED,
        SECURITY_ATTRIBUTES, SECURITY_DESCRIPTOR, SetSecurityDescriptorControl,
        SetSecurityDescriptorDacl, SetSecurityDescriptorOwner,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CreateDirectoryW, CreateFileW, FILE_ALL_ACCESS, FILE_ATTRIBUTE_DIRECTORY,
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_READ_ATTRIBUTES, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TRAVERSE, OPEN_EXISTING,
        READ_CONTROL,
    };
    use windows_sys::Win32::System::SystemServices::SECURITY_DESCRIPTOR_REVISION;

    let user = windows_current_user_sid()?;
    let local_system = if policy == WindowsManagedDirectoryAclPolicy::CurrentUserAndLocalSystem {
        let local_system = windows_local_system_sid()?;
        // SAFETY: both SID wrappers own valid, live SID storage.
        if unsafe { windows_sys::Win32::Security::EqualSid(user.as_ptr(), local_system.as_ptr()) }
            != 0
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "managed WSL storage cannot use LocalSystem as its interactive owner",
            ));
        }
        Some(local_system)
    } else {
        None
    };
    let mut acl_bytes = std::mem::size_of::<ACL>();
    let mut append_ace_size = |sid: windows_sys::Win32::Security::PSID| -> io::Result<()> {
        // SAFETY: each pointer comes from a validated SID wrapper that remains live.
        let sid_length = unsafe { windows_sys::Win32::Security::GetLengthSid(sid) } as usize;
        let ace_bytes = std::mem::size_of::<ACCESS_ALLOWED_ACE>()
            .checked_sub(std::mem::size_of::<u32>())
            .and_then(|size| size.checked_add(sid_length))
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "Windows ACE size overflowed")
            })?;
        acl_bytes = acl_bytes.checked_add(ace_bytes).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "Windows ACL size overflowed")
        })?;
        Ok(())
    };
    append_ace_size(user.as_ptr())?;
    if let Some(local_system) = local_system.as_ref() {
        append_ace_size(local_system.as_ptr())?;
    }
    let acl_bytes = acl_bytes
        .checked_add(std::mem::size_of::<u32>() - 1)
        .map(|size| size & !(std::mem::size_of::<u32>() - 1))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Windows ACL size overflowed"))?;
    let acl_length = u32::try_from(acl_bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Windows ACL is too large"))?;
    let mut acl = vec![0_u32; acl_bytes.div_ceil(std::mem::size_of::<u32>())];
    // SAFETY: acl is DWORD-aligned and has acl_length writable bytes.
    if unsafe { InitializeAcl(acl.as_mut_ptr().cast(), acl_length, ACL_REVISION) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let inheritance = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE;
    // SAFETY: the ACL was initialized and user owns a valid SID. The ACE
    // applies to this directory and is inherited by its child files/directories.
    if unsafe {
        AddAccessAllowedAceEx(
            acl.as_mut_ptr().cast(),
            ACL_REVISION,
            inheritance,
            FILE_ALL_ACCESS,
            user.as_ptr(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if let Some(local_system) = local_system.as_ref() {
        // SAFETY: the ACL remains initialized and local_system owns a valid
        // SID. This second inheritable ACE is present only for WSL's
        // distribution-storage service boundary.
        if unsafe {
            AddAccessAllowedAceEx(
                acl.as_mut_ptr().cast(),
                ACL_REVISION,
                inheritance,
                FILE_ALL_ACCESS,
                local_system.as_ptr(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
    }

    let mut descriptor = SECURITY_DESCRIPTOR::default();
    // SAFETY: descriptor is correctly sized writable storage.
    if unsafe {
        InitializeSecurityDescriptor(
            std::ptr::addr_of_mut!(descriptor).cast(),
            SECURITY_DESCRIPTOR_REVISION,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: descriptor is initialized and user remains live through directory creation.
    if unsafe {
        SetSecurityDescriptorOwner(
            std::ptr::addr_of_mut!(descriptor).cast(),
            user.as_ptr(),
            FALSE,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: descriptor and ACL are initialized and remain live through creation.
    if unsafe {
        SetSecurityDescriptorDacl(
            std::ptr::addr_of_mut!(descriptor).cast(),
            TRUE,
            acl.as_ptr().cast(),
            FALSE,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: descriptor is initialized; protection prevents parent ACEs from
    // being merged into the app-created namespace.
    if unsafe {
        SetSecurityDescriptorControl(
            std::ptr::addr_of_mut!(descriptor).cast(),
            SE_DACL_PROTECTED,
            SE_DACL_PROTECTED,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: std::ptr::addr_of_mut!(descriptor).cast(),
        bInheritHandle: FALSE,
    };

    let parent = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "Windows managed private directory has no parent",
        )
    })?;
    let file_name = path.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "Windows managed private directory has no final component",
        )
    })?;
    let canonical_parent = if parent.as_os_str().is_empty() {
        Path::new(".").canonicalize()?
    } else {
        parent.canonicalize()?
    };
    // Validate every canonical ancestor through the volume/share root. A
    // protected child DACL alone cannot stop FILE_DELETE_CHILD granted by any
    // ancestor from redirecting the caller-supplied namespace path.
    let ancestor_guards = if verify_ancestor_chain {
        verify_windows_managed_namespace_ancestor_chain(&canonical_parent)?
    } else {
        Vec::new()
    };
    let exact_path = canonical_parent.join(file_name);
    let mut encoded = exact_path.as_os_str().encode_wide().collect::<Vec<_>>();
    if encoded.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Windows path contains a NUL code unit",
        ));
    }
    encoded.push(0);
    // SAFETY: encoded is NUL-terminated; attributes and all descriptor backing
    // storage remain live for this call.
    let created = unsafe { CreateDirectoryW(encoded.as_ptr(), &raw const attributes) };
    if created == 0 {
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::AlreadyExists {
            return Err(error);
        }
    }

    // Open the exact final component without traversing a junction. The
    // directory-specific FILE_TRAVERSE bit participates in share arbitration
    // without listing entries; omitted delete sharing pins this object while
    // ownership, type, and DACL are verified by handle.
    // SAFETY: encoded remains NUL-terminated and live for this call.
    let raw = unsafe {
        CreateFileW(
            encoded.as_ptr(),
            FILE_TRAVERSE | FILE_READ_ATTRIBUTES | READ_CONTROL,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: CreateFileW returned a uniquely owned directory handle.
    let directory = unsafe { File::from_raw_handle(raw) };
    let information = windows_file_information(&directory)?;
    if information.attributes & FILE_ATTRIBUTE_DIRECTORY == 0
        || information.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "private product path must be a real directory, not a reparse point or non-directory",
        ));
    }
    let inheritance =
        u8::try_from(inheritance).expect("Windows inheritance flags fit in an ACE header");
    match policy {
        WindowsManagedDirectoryAclPolicy::CurrentUserOnly => {
            verify_windows_current_user_only_dacl_with_ace_flags(&directory, inheritance)?;
        }
        WindowsManagedDirectoryAclPolicy::CurrentUserAndLocalSystem => {
            verify_windows_wsl_distribution_storage_dacl_with_ace_flags(&directory, inheritance)?;
        }
    }
    Ok((
        exact_path,
        WindowsManagedDirectoryGuard {
            directory,
            _ancestor_guards: ancestor_guards,
            created: created != 0,
        },
    ))
}

#[cfg(windows)]
fn ensure_windows_managed_private_directory(path: &Path) -> io::Result<()> {
    drop(open_or_create_windows_managed_private_directory_guard(
        path, false,
    )?);
    Ok(())
}

#[cfg(windows)]
fn ensure_windows_managed_wsl_distribution_storage_directory(path: &Path) -> io::Result<()> {
    drop(open_or_create_windows_managed_wsl_distribution_storage_guard(path)?);
    Ok(())
}

fn ensure_managed_private_directory(path: &Path) -> io::Result<()> {
    #[cfg(windows)]
    {
        ensure_windows_managed_private_directory(path)
    }
    #[cfg(not(windows))]
    {
        ensure_private_directory(path)
    }
}

fn ensure_managed_wsl_distribution_storage_directory(path: &Path) -> io::Result<()> {
    #[cfg(windows)]
    {
        ensure_windows_managed_wsl_distribution_storage_directory(path)
    }
    #[cfg(not(windows))]
    {
        ensure_managed_private_directory(path)
    }
}

/// Pins the verified product-data namespace until the caller has acquired its
/// process lease or another longer-lived child guard.
#[derive(Debug)]
pub struct PrivateProductDataDirectoryGuard {
    #[cfg(windows)]
    _directories: Vec<File>,
    created: bool,
}

#[cfg(not(windows))]
fn ensure_known_canonical_product_data_parent(
    path: &Path,
    platform_local_data: &Path,
) -> io::Result<()> {
    if path == platform_local_data.join(PRODUCT_DATA_DIRECTORY_NAME) {
        fs::create_dir_all(platform_local_data)?;
    }
    Ok(())
}

impl PrivateProductDataDirectoryGuard {
    /// Reports whether this guarded call won the atomic final-component
    /// creation. Callers use this only to distinguish a genuinely empty
    /// first-run root from a directory created concurrently by another owner.
    pub fn was_created(&self) -> bool {
        self.created
    }
}

/// Creates or verifies the data directory before any database, artifact, or
/// managed-runtime state is written beneath it.
///
/// On Windows an absent final component is created with the same protected,
/// current-user-only DACL used by the managed runtime. Every existing real
/// ancestor is pinned without delete sharing and checked for namespace-
/// replacement grants. A fixed canonical root created by an older release may
/// retain its bounded inherited LocalAppData DACL so upgrades can reopen saved
/// work; it is pinned and verified in place but never repaired. Existing roots
/// with untrusted replacement rights still fail closed without rewriting their
/// descriptor or any descendants.
pub fn ensure_private_product_data_directory(
    path: &Path,
) -> AppResult<PrivateProductDataDirectoryGuard> {
    #[cfg(windows)]
    {
        let (directories, created) = match fs::symlink_metadata(path) {
            Ok(_) => {
                let directories = if windows_is_canonical_product_data_directory(path)? {
                    verify_windows_existing_product_data_directory(path)
                } else {
                    // Caller-selected and legacy roots are verified in place,
                    // but never receive automatic owner or ACL changes.
                    verify_windows_managed_namespace_ancestor_chain(path)
                }
                .map_err(windows_product_data_namespace_error)?;
                (directories, false)
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let (_, guard) = open_or_create_windows_managed_private_directory_guard(path, true)
                    .map_err(windows_product_data_namespace_error)?;
                let WindowsManagedDirectoryGuard {
                    directory,
                    mut _ancestor_guards,
                    created,
                } = guard;
                _ancestor_guards.push(directory);
                (_ancestor_guards, created)
            }
            Err(error) => return Err(error.into()),
        };
        Ok(PrivateProductDataDirectoryGuard {
            _directories: directories,
            created,
        })
    }
    #[cfg(not(windows))]
    {
        let platform_local_data = directories::BaseDirs::new()
            .map(|directories| directories.data_local_dir().to_path_buf())
            .ok_or_else(|| {
                AppError::Internal("platform local-data directory unavailable".into())
            })?;
        // Only the desktop/default-CLI root may bootstrap a missing platform
        // parent. Managed-runtime fixtures and caller-selected roots retain the
        // ordinary single-component creation contract.
        ensure_known_canonical_product_data_parent(path, &platform_local_data)?;
        let existed_before = match fs::symlink_metadata(path) {
            Ok(_) => true,
            Err(error) if error.kind() == io::ErrorKind::NotFound => false,
            Err(error) => return Err(error.into()),
        };
        ensure_private_directory(path)?;
        Ok(PrivateProductDataDirectoryGuard {
            created: !existed_before,
        })
    }
}

/// Test-only Windows seam for isolated temporary roots whose `%TEMP%`
/// ancestors intentionally do not satisfy the production LocalAppData
/// namespace policy. The final component still receives and verifies the exact
/// protected current-user DACL and remains pinned without delete sharing.
#[cfg(all(test, windows))]
pub(crate) fn ensure_private_product_data_directory_for_isolated_test(
    path: &Path,
) -> AppResult<PrivateProductDataDirectoryGuard> {
    let (_, guard) = open_or_create_windows_managed_private_directory_guard(path, false)
        .map_err(windows_product_data_namespace_error)?;
    let WindowsManagedDirectoryGuard {
        directory,
        mut _ancestor_guards,
        created,
    } = guard;
    _ancestor_guards.push(directory);
    Ok(PrivateProductDataDirectoryGuard {
        _directories: _ancestor_guards,
        created,
    })
}

#[cfg(windows)]
fn windows_product_data_namespace_error(error: io::Error) -> AppError {
    if error.kind() == io::ErrorKind::PermissionDenied {
        AppError::NotAuthorized(format!(
            "product data Windows namespace is replaceable or unsafe: {error}"
        ))
    } else {
        error.into()
    }
}

#[cfg(all(windows, test))]
fn verify_windows_product_data_directory_dacl(directory: &File) -> io::Result<()> {
    use windows_sys::Win32::Security::{CONTAINER_INHERIT_ACE, OBJECT_INHERIT_ACE};

    verify_windows_current_user_only_dacl_with_ace_flags(
        directory,
        u8::try_from(OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE)
            .expect("Windows inheritance flags fit in an ACE header"),
    )
}

/// Verifies an existing product-data root after the caller has established
/// that it is the fixed canonical LocalAppData child. The ancestor-chain policy
/// accepts both the exact protected DACL used for fresh roots and the bounded
/// inherited LocalAppData DACL produced by older releases. It rejects any
/// untrusted namespace-replacement grant. No accepted or rejected descriptor is
/// rewritten because Windows ACL setters may propagate an inheritable change
/// into existing descendants, violating product-data preservation.
#[cfg(windows)]
fn verify_windows_existing_product_data_directory(path: &Path) -> io::Result<Vec<File>> {
    let directories = verify_windows_managed_namespace_ancestor_chain(path)?;
    let directory = directories.first().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "canonical product data directory has no pinned Windows root",
        )
    })?;
    verify_windows_directory_owner_is_current_user(directory)?;
    verify_windows_managed_namespace_ancestor_handle(
        directory,
        false,
        WindowsManagedNamespaceAncestorAclPolicy::ProductDataRoot,
    )?;
    Ok(directories)
}

#[cfg(windows)]
fn windows_is_canonical_product_data_directory(path: &Path) -> io::Result<bool> {
    let Some(parent) = path.parent() else {
        return Ok(false);
    };
    let Some(leaf) = path.file_name().and_then(|leaf| leaf.to_str()) else {
        return Ok(false);
    };
    if !leaf.eq_ignore_ascii_case(PRODUCT_DATA_DIRECTORY_NAME) {
        return Ok(false);
    }
    Ok(parent.canonicalize()? == windows_local_app_data_directory()?.canonicalize()?)
}

#[cfg(windows)]
fn verify_windows_directory_owner_is_current_user(directory: &File) -> io::Result<()> {
    use windows_sys::Win32::Security::{EqualSid, GetSecurityDescriptorOwner, IsValidSid};

    let user = windows_current_user_sid()?;
    let mut descriptor = windows_owner_dacl_security_descriptor(directory)?;
    let mut owner = std::ptr::null_mut();
    let mut owner_defaulted = 0;
    // SAFETY: descriptor is the live, kernel-returned security descriptor and
    // both output pointers are writable.
    if unsafe {
        GetSecurityDescriptorOwner(
            descriptor.as_mut_ptr().cast(),
            &raw mut owner,
            &raw mut owner_defaulted,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if owner.is_null()
        || unsafe { IsValidSid(owner) } == 0
        || unsafe { EqualSid(owner, user.as_ptr()) } == 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "canonical product data directory is not owned by the current Windows user",
        ));
    }
    Ok(())
}

fn ensure_private_directory_tree(root: &Path, destination: &Path) -> AppResult<()> {
    if !destination.starts_with(root) {
        return Err(AppError::NotAuthorized(
            "managed runtime directory escaped its staging root".into(),
        ));
    }
    let relative = destination.strip_prefix(root).map_err(|_| {
        AppError::NotAuthorized("managed runtime directory escaped its staging root".into())
    })?;
    let mut current = root.to_path_buf();
    for component in relative.components() {
        let Component::Normal(component) = component else {
            return Err(AppError::NotAuthorized(
                "managed runtime directory contains an unsafe component".into(),
            ));
        };
        current.push(component);
        ensure_managed_private_directory(&current)?;
    }
    Ok(())
}

#[cfg(any(not(windows), test))]
fn ensure_private_directory(path: &Path) -> io::Result<()> {
    match fs::create_dir(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "private product path must be a real directory, not a symbolic link or non-directory",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn canonical_real_directory(path: &Path, label: &str) -> AppResult<PathBuf> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        AppError::NotAvailable(format!("{label} directory is unavailable: {error}"))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(AppError::NotAuthorized(format!(
            "{label} directory must be a real directory"
        )));
    }
    path.canonicalize().map_err(AppError::from)
}

#[cfg(windows)]
#[derive(Clone, Copy)]
enum WindowsPrivateFileParentPolicy {
    ExactCurrentUserOnly,
    PinnedRealDirectory,
}

#[cfg(windows)]
fn create_windows_current_user_only_file(
    path: &Path,
    parent_policy: WindowsPrivateFileParentPolicy,
) -> io::Result<File> {
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::FromRawHandle;
    use windows_sys::Win32::Foundation::{FALSE, INVALID_HANDLE_VALUE, TRUE};
    use windows_sys::Win32::Security::{
        CONTAINER_INHERIT_ACE, InitializeSecurityDescriptor, OBJECT_INHERIT_ACE, SE_DACL_PROTECTED,
        SECURITY_ATTRIBUTES, SECURITY_DESCRIPTOR, SetSecurityDescriptorControl,
        SetSecurityDescriptorDacl, SetSecurityDescriptorOwner,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CREATE_NEW, CreateFileW, DELETE, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL,
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_NONE,
    };
    use windows_sys::Win32::System::SystemServices::SECURITY_DESCRIPTOR_REVISION;

    let user = windows_current_user_sid()?;
    let creation_acl = windows_current_user_only_acl(&user)?;

    let mut descriptor = SECURITY_DESCRIPTOR::default();
    // SAFETY: descriptor is correctly sized writable storage and revision is
    // the version supported by InitializeSecurityDescriptor.
    if unsafe {
        InitializeSecurityDescriptor(
            std::ptr::addr_of_mut!(descriptor).cast(),
            SECURITY_DESCRIPTOR_REVISION,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: descriptor was initialized and user owns a valid SID which stays
    // live until CreateFileW returns.
    if unsafe {
        SetSecurityDescriptorOwner(
            std::ptr::addr_of_mut!(descriptor).cast(),
            user.as_ptr(),
            FALSE,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: descriptor and ACL are initialized and remain live through the
    // CreateFileW call.
    if unsafe {
        SetSecurityDescriptorDacl(
            std::ptr::addr_of_mut!(descriptor).cast(),
            TRUE,
            creation_acl.as_ptr(),
            FALSE,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: descriptor is initialized; setting SE_DACL_PROTECTED prevents
    // permissive inheritable parent ACEs from being merged into this DACL.
    if unsafe {
        SetSecurityDescriptorControl(
            std::ptr::addr_of_mut!(descriptor).cast(),
            SE_DACL_PROTECTED,
            SE_DACL_PROTECTED,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: std::ptr::addr_of_mut!(descriptor).cast(),
        bInheritHandle: FALSE,
    };

    let parent = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "Windows private file path has no parent",
        )
    })?;
    let file_name = path.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "Windows private file path has no file name",
        )
    })?;
    // Rust's Windows canonicalize returns an absolute verbatim path. Resolve
    // only the existing parent because CREATE_NEW requires the final file to be
    // absent, then append the exact final component. This preserves long-path
    // support and avoids interpreting a relative path in CreateFileW.
    let canonical_parent = if parent.as_os_str().is_empty() {
        Path::new(".").canonicalize()?
    } else {
        parent.canonicalize()?
    };
    // Pin the exact immediate parent through creation. Managed-runtime callers
    // additionally require its exact inheritable DACL; generic product files
    // still receive and read back their own protected descriptor without
    // rewriting a caller-selected or legacy parent.
    let parent_guard = open_windows_real_directory_security_handle(&canonical_parent)?;
    if matches!(
        parent_policy,
        WindowsPrivateFileParentPolicy::ExactCurrentUserOnly
    ) {
        let inheritance = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE;
        verify_windows_current_user_only_dacl_with_ace_flags(
            &parent_guard,
            u8::try_from(inheritance).expect("Windows inheritance flags fit in an ACE header"),
        )?;
    }
    let creation_path = canonical_parent.join(file_name);
    let mut encoded = creation_path.as_os_str().encode_wide().collect::<Vec<_>>();
    if encoded.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Windows path contains a NUL code unit",
        ));
    }
    encoded.push(0);
    // SAFETY: encoded is NUL-terminated; attributes points to a live descriptor
    // whose SID and ACL storage also remain live for the call.
    let raw = unsafe {
        CreateFileW(
            encoded.as_ptr(),
            FILE_GENERIC_READ | FILE_GENERIC_WRITE | DELETE,
            FILE_SHARE_NONE,
            &raw const attributes,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL,
            std::ptr::null_mut(),
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: CreateFileW returned a uniquely owned file handle.
    let file = unsafe { File::from_raw_handle(raw) };
    let secure = (|| {
        let information = windows_file_information(&file)?;
        if information.attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT) != 0
            || information.number_of_links != 1
            || information.size != 0
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "new Windows private file is not an empty unlinked regular file",
            ));
        }
        verify_windows_current_user_only_dacl(&file)
    })();
    if let Err(error) = secure {
        let cleanup = mark_windows_file_handle_for_deletion(&file);
        drop(file);
        return Err(match cleanup {
            Ok(()) => error,
            Err(cleanup) => io::Error::new(
                error.kind(),
                format!(
                    "{error}; empty Windows private staging file cleanup also failed: {cleanup}"
                ),
            ),
        });
    }
    // Keep the no-share-delete parent handle live through the child's strict
    // readback so its checked namespace component cannot be swapped mid-create.
    drop(parent_guard);
    Ok(file)
}

#[cfg(windows)]
fn create_windows_private_file(path: &Path) -> io::Result<File> {
    create_windows_current_user_only_file(
        path,
        WindowsPrivateFileParentPolicy::ExactCurrentUserOnly,
    )
}

/// Creates one new product-owned file with an exact protected current-user
/// Windows DACL. The immediate real parent is pinned through creation, but is
/// never repaired: caller-selected and legacy directory ACLs remain unchanged.
#[cfg(windows)]
pub(crate) fn create_current_user_only_product_file(path: &Path) -> io::Result<File> {
    create_windows_current_user_only_file(path, WindowsPrivateFileParentPolicy::PinnedRealDirectory)
}

/// A same-handle proof boundary for one existing file below the fixed
/// canonical product-data root. Opening this guard never changes the file.
#[cfg(windows)]
struct CanonicalProductFileDaclRepairGuard {
    file: File,
    information: WindowsFileInformation,
    _product_root_guard: PrivateProductDataDirectoryGuard,
    _directory_guards: Vec<File>,
}

#[cfg(windows)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum WindowsExistingProductFileAccess {
    #[allow(dead_code)] // Retained by the read-only wrapper's stable access contract.
    ReadOnly,
    DurableWrite,
}

#[cfg(windows)]
impl CanonicalProductFileDaclRepairGuard {
    fn repair_after_content_proof(self) -> io::Result<()> {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Security::Authorization::{SE_FILE_OBJECT, SetSecurityInfo};
        use windows_sys::Win32::Security::{
            DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
        };

        let observed = windows_file_information(&self.file)?;
        if observed != self.information || observed.number_of_links != 1 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "canonical product file changed before its Windows DACL repair",
            ));
        }
        verify_windows_directory_owner_is_current_user(&self.file)?;
        if verify_windows_current_user_only_dacl_allowing_defaulted_owner(&self.file).is_ok() {
            return Ok(());
        }

        let user = windows_current_user_sid()?;
        let acl = windows_current_user_only_acl(&user)?;
        // SAFETY: the guard owns an exact live file handle opened with
        // WRITE_DAC; the current-user ACL remains live for the call. Owner and
        // bytes are intentionally not changed.
        let status = unsafe {
            SetSecurityInfo(
                self.file.as_raw_handle(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                acl.raw,
                std::ptr::null_mut(),
            )
        };
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        if windows_file_information(&self.file)? != self.information {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "canonical product file changed during its Windows DACL repair",
            ));
        }
        verify_windows_current_user_only_dacl_allowing_defaulted_owner(&self.file)
    }
}

#[cfg(windows)]
fn open_canonical_product_file_dacl_repair_guard_at_root(
    path: &Path,
    product_root: &Path,
    product_root_guard: PrivateProductDataDirectoryGuard,
    access: WindowsExistingProductFileAccess,
) -> io::Result<CanonicalProductFileDaclRepairGuard> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_READ, FILE_SHARE_WRITE, READ_CONTROL,
        WRITE_DAC,
    };

    let canonical_root = product_root.canonicalize()?;
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "canonical product file has no parent",
        )
    })?;
    let file_name = path.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "canonical product file has no final component",
        )
    })?;
    let relative_parent = parent.strip_prefix(product_root).map_err(|_| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "existing file parent escaped the fixed canonical product-data root",
        )
    })?;
    let canonical_parent = parent.canonicalize()?;
    if canonical_parent != canonical_root && !canonical_parent.starts_with(&canonical_root) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "existing file is outside the fixed canonical product-data root",
        ));
    }

    let mut directory_guards = Vec::new();
    let mut current = canonical_root.clone();
    for component in relative_parent.components() {
        let Component::Normal(component) = component else {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "existing file parent contains an unsafe component",
            ));
        };
        current.push(component);
        let guard = open_windows_real_directory_security_handle(&current)?;
        verify_windows_managed_namespace_ancestor_handle(
            &guard,
            false,
            WindowsManagedNamespaceAncestorAclPolicy::Strict,
        )?;
        directory_guards.push(guard);
    }
    if current.canonicalize()? != canonical_parent {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "existing file parent traversed a reparse point",
        ));
    }

    let exact_path = current.join(file_name);
    let mut desired_access = FILE_GENERIC_READ | READ_CONTROL | WRITE_DAC;
    if access == WindowsExistingProductFileAccess::DurableWrite {
        desired_access |= FILE_GENERIC_WRITE;
    }
    let mut options = OpenOptions::new();
    options
        .read(true)
        .access_mode(desired_access)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    let file = options.open(&exact_path)?;
    let information = windows_file_information(&file)?;
    if information.attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT) != 0
        || information.number_of_links != 1
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "existing canonical product file is not a single-link real file",
        ));
    }
    verify_windows_directory_owner_is_current_user(&file)?;

    // FILE_SHARE_READ deliberately excludes write and delete sharing. The
    // exact file cannot be modified, renamed, or unlinked while content proof
    // and repair use this handle. Reopen the still-pinned pathname without
    // following a final reparse point and prove it resolves to this object.
    // A durability-capable primary handle has write access, so this read-only
    // identity probe must share that already-pinned access. The primary handle
    // itself still excludes write and delete sharing for every other opener.
    let probe_share_mode = if access == WindowsExistingProductFileAccess::DurableWrite {
        FILE_SHARE_READ | FILE_SHARE_WRITE
    } else {
        FILE_SHARE_READ
    };
    let mut probe_options = OpenOptions::new();
    probe_options
        .read(true)
        .share_mode(probe_share_mode)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    let path_probe = probe_options.open(&exact_path)?;
    if windows_file_information(&path_probe)? != information {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "canonical product file pathname does not identify the guarded file",
        ));
    }
    let canonical_file = exact_path.canonicalize()?;
    if canonical_file.parent() != Some(canonical_parent.as_path())
        || !canonical_file.starts_with(&canonical_root)
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "existing file escaped the fixed canonical product-data root",
        ));
    }

    Ok(CanonicalProductFileDaclRepairGuard {
        file,
        information,
        _product_root_guard: product_root_guard,
        _directory_guards: directory_guards,
    })
}

#[cfg(windows)]
fn open_canonical_product_file_dacl_repair_guard(
    path: &Path,
    access: WindowsExistingProductFileAccess,
) -> io::Result<CanonicalProductFileDaclRepairGuard> {
    let product_root = windows_local_app_data_directory()?.join(PRODUCT_DATA_DIRECTORY_NAME);
    let canonical_root = product_root.canonicalize()?;
    let canonical_path = path.canonicalize()?;
    if canonical_path == canonical_root || !canonical_path.starts_with(&canonical_root) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "existing file is outside the fixed canonical product-data root",
        ));
    }
    let product_root_guard = ensure_private_product_data_directory(&product_root)
        .map_err(|error| io::Error::other(error.to_string()))?;
    open_canonical_product_file_dacl_repair_guard_at_root(
        path,
        &product_root,
        product_root_guard,
        access,
    )
}

#[cfg(windows)]
fn verify_then_repair_product_file_dacl<E>(
    mut guard: CanonicalProductFileDaclRepairGuard,
    verify: impl FnOnce(&mut File) -> Result<(), E>,
    after_verify: impl FnOnce(&File) -> Result<(), E>,
    map_io_error: impl Fn(io::Error) -> E,
) -> Result<(), E> {
    verify(&mut guard.file)?;
    after_verify(&guard.file)?;
    guard.repair_after_content_proof().map_err(map_io_error)
}

#[cfg(windows)]
fn windows_product_file_has_canonical_repair_authority(path: &Path) -> io::Result<bool> {
    let mut root = None;
    for ancestor in path.ancestors() {
        if ancestor
            .file_name()
            .and_then(|leaf| leaf.to_str())
            .is_some_and(|leaf| leaf.eq_ignore_ascii_case(PRODUCT_DATA_DIRECTORY_NAME))
            && windows_is_canonical_product_data_directory(ancestor)?
        {
            root = Some(ancestor);
            break;
        }
    }
    let Some(root) = root else {
        return Ok(false);
    };
    let canonical_root = root.canonicalize()?;
    let canonical_path = path.canonicalize()?;
    if canonical_path == canonical_root || !canonical_path.starts_with(&canonical_root) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "canonical product file escaped its fixed product-data root",
        ));
    }
    Ok(true)
}

#[cfg(windows)]
fn verify_private_product_file_without_repair<E>(
    path: &Path,
    authority_root: &Path,
    access: WindowsExistingProductFileAccess,
    verify: impl FnOnce(&mut File) -> Result<(), E>,
    after_verify: impl FnOnce(&File) -> Result<(), E>,
    map_io_error: impl Fn(io::Error) -> E,
) -> Result<(), E> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_READ, FILE_SHARE_WRITE, READ_CONTROL,
    };

    let parent = path.parent().ok_or_else(|| {
        map_io_error(io::Error::new(
            io::ErrorKind::InvalidInput,
            "private product file has no parent",
        ))
    })?;
    let file_name = path.file_name().ok_or_else(|| {
        map_io_error(io::Error::new(
            io::ErrorKind::InvalidInput,
            "private product file has no final component",
        ))
    })?;
    let canonical_authority_root = authority_root.canonicalize().map_err(&map_io_error)?;
    if parent.canonicalize().map_err(&map_io_error)? != canonical_authority_root {
        return Err(map_io_error(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "private product file is not a direct child of its artifact authority root",
        )));
    }
    let _parent_guard = open_windows_real_directory_security_handle(&canonical_authority_root)
        .map_err(&map_io_error)?;
    let exact_path = canonical_authority_root.join(file_name);
    let mut desired_access = FILE_GENERIC_READ | READ_CONTROL;
    if access == WindowsExistingProductFileAccess::DurableWrite {
        desired_access |= FILE_GENERIC_WRITE;
    }
    let mut options = OpenOptions::new();
    options
        .read(true)
        .access_mode(desired_access)
        // Excluding write and delete sharing pins the verified object while
        // the caller proves its contents. This path never requests WRITE_DAC.
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    let mut file = options.open(&exact_path).map_err(&map_io_error)?;
    let information = windows_file_information(&file).map_err(&map_io_error)?;
    if information.attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT) != 0
        || information.number_of_links != 1
    {
        return Err(map_io_error(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "existing private product file is not a single-link real file",
        )));
    }
    verify_windows_directory_owner_is_current_user(&file).map_err(&map_io_error)?;
    verify_windows_current_user_only_dacl(&file).map_err(&map_io_error)?;

    let probe_share_mode = if access == WindowsExistingProductFileAccess::DurableWrite {
        FILE_SHARE_READ | FILE_SHARE_WRITE
    } else {
        FILE_SHARE_READ
    };
    let mut probe_options = OpenOptions::new();
    probe_options
        .read(true)
        .share_mode(probe_share_mode)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    let path_probe = probe_options.open(&exact_path).map_err(&map_io_error)?;
    if windows_file_information(&path_probe).map_err(&map_io_error)? != information {
        return Err(map_io_error(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "private product file pathname does not identify the guarded file",
        )));
    }
    let canonical_file = exact_path.canonicalize().map_err(&map_io_error)?;
    if canonical_file.parent() != Some(canonical_authority_root.as_path()) {
        return Err(map_io_error(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "private product file escaped its pinned parent",
        )));
    }

    verify(&mut file)?;
    after_verify(&file)?;
    if windows_file_information(&file).map_err(&map_io_error)? != information {
        return Err(map_io_error(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "private product file changed during content verification",
        )));
    }
    verify_windows_directory_owner_is_current_user(&file).map_err(&map_io_error)?;
    verify_windows_current_user_only_dacl(&file).map_err(map_io_error)
}

#[cfg(windows)]
fn verify_then_repair_canonical_or_verify_private_product_file_dacl_with_access<E>(
    path: &Path,
    authority_root: &Path,
    access: WindowsExistingProductFileAccess,
    verify: impl FnOnce(&mut File) -> Result<(), E>,
    after_verify: impl FnOnce(&File) -> Result<(), E>,
    map_io_error: impl Fn(io::Error) -> E,
) -> Result<(), E> {
    let parent = path.parent().ok_or_else(|| {
        map_io_error(io::Error::new(
            io::ErrorKind::InvalidInput,
            "private product file has no parent",
        ))
    })?;
    if parent.canonicalize().map_err(&map_io_error)?
        != authority_root.canonicalize().map_err(&map_io_error)?
    {
        return Err(map_io_error(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "private product file is not a direct child of its artifact authority root",
        )));
    }
    if windows_product_file_has_canonical_repair_authority(path).map_err(&map_io_error)? {
        let guard =
            open_canonical_product_file_dacl_repair_guard(path, access).map_err(&map_io_error)?;
        verify_then_repair_product_file_dacl(guard, verify, after_verify, map_io_error)
    } else {
        verify_private_product_file_without_repair(
            path,
            authority_root,
            access,
            verify,
            after_verify,
            map_io_error,
        )
    }
}

/// Runs `verify` against one exact, non-replaceable existing file handle. A
/// file lexically below the fixed canonical product-data root may receive the
/// bounded DACL repair after successful proof; every other path is strictly
/// verify-only and must already have the exact product-created descriptor.
/// This entry point remains read-only and does not require write access.
#[cfg(windows)]
#[allow(dead_code)] // Durable callers must not silently widen this read-only API.
pub(crate) fn verify_then_repair_canonical_or_verify_private_product_file_dacl<E>(
    path: &Path,
    authority_root: &Path,
    verify: impl FnOnce(&mut File) -> Result<(), E>,
    map_io_error: impl Fn(io::Error) -> E,
) -> Result<(), E> {
    verify_then_repair_canonical_or_verify_private_product_file_dacl_with_access(
        path,
        authority_root,
        WindowsExistingProductFileAccess::ReadOnly,
        verify,
        |_| Ok(()),
        map_io_error,
    )
}

/// Runs content proof and a caller-supplied durability barrier against the
/// same write-capable, non-replaceable file handle. Canonical product files
/// may then receive their bounded DACL repair; custom-authority files remain
/// verify-only and are never opened with `WRITE_DAC`.
#[cfg(windows)]
pub(crate) fn verify_then_sync_and_repair_canonical_or_verify_private_product_file_dacl<E>(
    path: &Path,
    authority_root: &Path,
    verify: impl FnOnce(&mut File) -> Result<(), E>,
    durability_barrier: impl FnOnce(&File) -> Result<(), E>,
    map_io_error: impl Fn(io::Error) -> E,
) -> Result<(), E> {
    verify_then_repair_canonical_or_verify_private_product_file_dacl_with_access(
        path,
        authority_root,
        WindowsExistingProductFileAccess::DurableWrite,
        verify,
        durability_barrier,
        map_io_error,
    )
}

#[cfg(all(test, windows))]
#[allow(dead_code)] // Kept as the read-only isolated sibling of the durability helper.
pub(crate) fn verify_then_repair_isolated_product_file_dacl<E>(
    path: &Path,
    product_root: &Path,
    verify: impl FnOnce(&mut File) -> Result<(), E>,
    map_io_error: impl Fn(io::Error) -> E,
) -> Result<(), E> {
    let product_root_guard = ensure_private_product_data_directory_for_isolated_test(product_root)
        .map_err(|error| map_io_error(io::Error::other(error.to_string())))?;
    let guard = open_canonical_product_file_dacl_repair_guard_at_root(
        path,
        product_root,
        product_root_guard,
        WindowsExistingProductFileAccess::ReadOnly,
    )
    .map_err(&map_io_error)?;
    verify_then_repair_product_file_dacl(guard, verify, |_| Ok(()), map_io_error)
}

#[cfg(all(test, windows))]
pub(crate) fn verify_then_sync_and_repair_isolated_product_file_dacl<E>(
    path: &Path,
    product_root: &Path,
    verify: impl FnOnce(&mut File) -> Result<(), E>,
    durability_barrier: impl FnOnce(&File) -> Result<(), E>,
    map_io_error: impl Fn(io::Error) -> E,
) -> Result<(), E> {
    let product_root_guard = ensure_private_product_data_directory_for_isolated_test(product_root)
        .map_err(|error| map_io_error(io::Error::other(error.to_string())))?;
    let guard = open_canonical_product_file_dacl_repair_guard_at_root(
        path,
        product_root,
        product_root_guard,
        WindowsExistingProductFileAccess::DurableWrite,
    )
    .map_err(&map_io_error)?;
    verify_then_repair_product_file_dacl(guard, verify, durability_barrier, map_io_error)
}

#[cfg(all(test, windows))]
fn set_test_world_product_entry_dacl(path: &Path, world_permissions: u32) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Security::Authorization::{
        EXPLICIT_ACCESS_W, NO_MULTIPLE_TRUSTEE, SE_FILE_OBJECT, SET_ACCESS, SetEntriesInAclW,
        SetNamedSecurityInfoW, TRUSTEE_IS_GROUP, TRUSTEE_IS_SID, TRUSTEE_IS_USER, TRUSTEE_W,
    };
    use windows_sys::Win32::Security::{
        DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, WinWorldSid,
    };
    use windows_sys::Win32::Storage::FileSystem::FILE_ALL_ACCESS;

    let user = windows_current_user_sid()?;
    let world = windows_well_known_sid(WinWorldSid)?;
    let mut entries = [
        EXPLICIT_ACCESS_W {
            grfAccessPermissions: FILE_ALL_ACCESS,
            grfAccessMode: SET_ACCESS,
            grfInheritance: 0,
            Trustee: TRUSTEE_W {
                pMultipleTrustee: std::ptr::null_mut(),
                MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
                TrusteeForm: TRUSTEE_IS_SID,
                TrusteeType: TRUSTEE_IS_USER,
                ptstrName: user.as_ptr().cast(),
            },
        },
        EXPLICIT_ACCESS_W {
            grfAccessPermissions: world_permissions,
            grfAccessMode: SET_ACCESS,
            grfInheritance: 0,
            Trustee: TRUSTEE_W {
                pMultipleTrustee: std::ptr::null_mut(),
                MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
                TrusteeForm: TRUSTEE_IS_SID,
                TrusteeType: TRUSTEE_IS_GROUP,
                ptstrName: world.as_ptr().cast(),
            },
        },
    ];
    let mut raw_acl = std::ptr::null_mut();
    // SAFETY: entries contain two live SID-backed trustees and raw_acl is
    // writable output storage.
    let status = unsafe {
        SetEntriesInAclW(
            entries.len() as u32,
            entries.as_mut_ptr(),
            std::ptr::null(),
            &raw mut raw_acl,
        )
    };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    if raw_acl.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Windows returned a null test ACL",
        ));
    }
    let acl = WindowsCurrentUserOnlyAcl { raw: raw_acl };
    let mut encoded = path.as_os_str().encode_wide().collect::<Vec<_>>();
    if encoded.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Windows test path contains a NUL code unit",
        ));
    }
    encoded.push(0);
    // SAFETY: encoded and ACL remain live for this bounded test-fixture
    // mutation. Owner, bytes, and attributes are not changed.
    let status = unsafe {
        SetNamedSecurityInfoW(
            encoded.as_mut_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            acl.raw,
            std::ptr::null_mut(),
        )
    };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    Ok(())
}

#[cfg(all(test, windows))]
pub(crate) fn set_test_world_readable_product_file_dacl(path: &Path) -> io::Result<()> {
    use windows_sys::Win32::Storage::FileSystem::FILE_GENERIC_READ;

    set_test_world_product_entry_dacl(path, FILE_GENERIC_READ)
}

#[cfg(all(test, windows))]
pub(crate) fn set_test_world_writable_product_directory_dacl(path: &Path) -> io::Result<()> {
    use windows_sys::Win32::Storage::FileSystem::FILE_ALL_ACCESS;

    set_test_world_product_entry_dacl(path, FILE_ALL_ACCESS)
}

#[cfg(all(test, windows))]
pub(crate) fn test_windows_product_file_security_descriptor(path: &Path) -> io::Result<Vec<usize>> {
    windows_owner_dacl_security_descriptor(&File::open(path)?)
}

#[cfg(all(test, windows))]
pub(crate) fn test_verify_current_user_only_product_file(path: &Path) -> io::Result<()> {
    verify_windows_current_user_only_dacl_allowing_defaulted_owner(&File::open(path)?)
}

#[cfg(all(test, windows))]
pub(crate) fn test_windows_product_file_information(
    path: &Path,
) -> io::Result<(u32, u64, u64, u32, u32)> {
    let information = windows_file_information(&File::open(path)?)?;
    Ok((
        information.identity.volume_serial_number,
        information.identity.file_index,
        information.size,
        information.number_of_links,
        information.attributes,
    ))
}

fn create_private_file(path: &Path) -> io::Result<File> {
    #[cfg(windows)]
    {
        create_windows_private_file(path)
    }
    #[cfg(not(windows))]
    {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        }
        let file = options.open(path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(fs::Permissions::from_mode(0o600))?;
        }
        Ok(file)
    }
}

fn open_private_download_file(path: &Path, append: bool) -> AppResult<File> {
    if path.exists() {
        verify_regular_file(path, "managed runtime partial download")?;
    }
    let mut options = OpenOptions::new();
    options.write(true).create(true);
    if append {
        options.append(true);
    } else {
        options.truncate(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let file = options.open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    Ok(file)
}

fn open_nofollow_lock_file(path: &Path) -> AppResult<File> {
    if path.exists() {
        verify_regular_file(path, "managed runtime lifecycle lock")?;
    }
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(AppError::NotAuthorized(
            "managed runtime lifecycle lock is not a regular file".into(),
        ));
    }
    Ok(file)
}

fn regular_file_length_or_zero(path: &Path) -> AppResult<u64> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(AppError::NotAuthorized(
                    "managed runtime partial download is not a regular file".into(),
                ));
            }
            Ok(metadata.len())
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(0),
        Err(error) => Err(error.into()),
    }
}

fn set_installed_permissions(path: &Path, executable: bool) -> AppResult<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(
            path,
            fs::Permissions::from_mode(if executable { 0o500 } else { 0o400 }),
        )?;
    }
    #[cfg(not(unix))]
    {
        let mut permissions = fs::metadata(path)?.permissions();
        permissions.set_readonly(!executable);
        fs::set_permissions(path, permissions)?;
    }
    Ok(())
}

fn write_private_atomic(path: &Path, bytes: &[u8]) -> AppResult<()> {
    if bytes.len() > 64 * 1024 {
        return Err(AppError::Runtime(
            "managed runtime configuration is oversized".into(),
        ));
    }
    let parent = path
        .parent()
        .ok_or_else(|| AppError::Runtime("managed runtime configuration has no parent".into()))?;
    ensure_managed_private_directory(parent)?;
    if path.exists() {
        verify_regular_file(path, "managed runtime configuration")?;
        let metadata = fs::symlink_metadata(path)?;
        if metadata.len() > 64 * 1024 {
            return Err(AppError::NotAuthorized(
                "managed runtime configuration is unexpectedly oversized".into(),
            ));
        }
        let mut existing = Vec::with_capacity(metadata.len() as usize);
        File::open(path)?
            .take(64 * 1024 + 1)
            .read_to_end(&mut existing)?;
        if existing == bytes {
            return Ok(());
        }
        return Err(AppError::NotAuthorized(
            "managed runtime immutable configuration differs from its release contract".into(),
        ));
    }
    let temporary = parent.join(format!(".config-{}", Uuid::new_v4()));
    let result = (|| {
        let mut file = create_private_file(&temporary)?;
        file.write_all(bytes)?;
        file.flush()?;
        file.sync_all()?;
        // Windows cannot rename a file while its FILE_SHARE_NONE writer is open.
        drop(file);
        commit_private_atomic_rename(&temporary, path)?;
        sync_directory(parent)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = remove_regular_file(&temporary);
    }
    result
}

#[cfg(windows)]
fn commit_private_atomic_rename(source: &Path, destination: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{MOVEFILE_WRITE_THROUGH, MoveFileExW};

    let encode = |path: &Path| -> io::Result<Vec<u16>> {
        let mut encoded = path.as_os_str().encode_wide().collect::<Vec<_>>();
        if encoded.contains(&0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "managed runtime atomic path contains a NUL code unit",
            ));
        }
        encoded.push(0);
        Ok(encoded)
    };
    let source = encode(source)?;
    let destination = encode(destination)?;
    // The temporary file was already flushed. MOVEFILE_WRITE_THROUGH makes
    // the same-volume namespace commit synchronous before an installer
    // transition can be consumed from the registry.
    if unsafe {
        MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_WRITE_THROUGH,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(windows))]
fn commit_private_atomic_rename(source: &Path, destination: &Path) -> io::Result<()> {
    fs::rename(source, destination)
}

fn remove_regular_file(path: &Path) -> AppResult<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(AppError::NotAuthorized(
                    "managed runtime refused to remove a non-regular file".into(),
                ));
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
            }
            fs::remove_file(path)?;
            Ok(())
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn private_entry_exists(path: &Path) -> AppResult<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn private_tree_removal_parent(path: &Path, expected_parent: &Path) -> AppResult<PathBuf> {
    let parent = canonical_real_directory(expected_parent, "managed runtime versions")?;
    let requested_parent = path
        .parent()
        .ok_or_else(|| {
            AppError::NotAuthorized("managed runtime removal path has no parent".into())
        })?
        .canonicalize()?;
    if requested_parent != parent {
        return Err(AppError::NotAuthorized(
            "managed runtime payload removal escaped its private parent".into(),
        ));
    }
    Ok(parent)
}

/// Removes one exact backend-owned entry without following a symlink. A
/// corrupted install/cache path may itself be a file or symlink; refusing to
/// unlink that directory entry would permanently wedge verified repair.
fn remove_private_tree(path: &Path, expected_parent: &Path) -> AppResult<()> {
    let parent = private_tree_removal_parent(path, expected_parent)?;
    let metadata = fs::symlink_metadata(path)?;
    #[cfg(windows)]
    {
        let _ = metadata;
        remove_windows_private_entry_tree(path, WindowsPrivateFileDeletePolicy::Immediate)?;
        sync_directory(&parent)?;
        Ok(())
    }
    #[cfg(not(windows))]
    {
        if !metadata.is_dir() {
            fs::remove_file(path)?;
            sync_directory(&parent)?;
            return Ok(());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        }
        let canonical = path.canonicalize()?;
        if canonical.parent() != Some(parent.as_path()) {
            return Err(AppError::NotAuthorized(
                "managed runtime payload removal escaped the versions directory".into(),
            ));
        }
        #[cfg(unix)]
        make_tree_owner_writable(&canonical)?;
        fs::remove_dir_all(canonical)?;
        sync_directory(&parent)?;
        Ok(())
    }
}

fn remove_provider_home_after_machine_removal(
    path: &Path,
    expected_parent: &Path,
    timeout: Duration,
    poll: Duration,
) -> AppResult<()> {
    #[cfg(windows)]
    {
        remove_provider_home_after_machine_removal_with_timing(path, expected_parent, timeout, poll)
    }
    #[cfg(not(windows))]
    {
        let _ = (timeout, poll);
        remove_private_tree(path, expected_parent)
    }
}

#[cfg(windows)]
fn remove_provider_home_after_machine_removal_with_timing(
    path: &Path,
    expected_parent: &Path,
    timeout: Duration,
    poll: Duration,
) -> AppResult<()> {
    if poll.is_zero() {
        return Err(AppError::Internal(
            "managed Windows WSL provider deletion poll interval was zero".into(),
        ));
    }
    let parent = private_tree_removal_parent(path, expected_parent)?;
    let _ = fs::symlink_metadata(path)?;
    let deadline = Instant::now().checked_add(timeout).ok_or_else(|| {
        AppError::Internal("managed Windows WSL provider deletion deadline overflowed".into())
    })?;
    remove_windows_private_entry_tree(
        path,
        WindowsPrivateFileDeletePolicy::RetrySharingViolation { deadline, poll },
    )?;
    sync_directory(&parent)
}

#[cfg(unix)]
fn make_tree_owner_writable(path: &Path) -> AppResult<()> {
    use std::os::unix::fs::PermissionsExt;
    // Make each directory traversable before attempting read_dir or descent;
    // corruption may have removed every permission bit.
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let metadata = fs::symlink_metadata(entry.path())?;
        if metadata.file_type().is_symlink() {
            // remove_dir_all unlinks a child symlink rather than following it;
            // do not chmod or canonicalize its target.
            continue;
        }
        if metadata.is_dir() {
            make_tree_owner_writable(&entry.path())?;
        }
    }
    Ok(())
}

#[cfg(windows)]
#[derive(Clone, Copy)]
enum WindowsPrivateFileDeletePolicy {
    Immediate,
    RetrySharingViolation { deadline: Instant, poll: Duration },
}

#[cfg(windows)]
fn remove_windows_private_entry_tree(
    path: &Path,
    delete_policy: WindowsPrivateFileDeletePolicy,
) -> AppResult<()> {
    use std::os::windows::fs::MetadataExt;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
    };

    let Some(metadata) = windows_private_entry_metadata_with_policy(path, delete_policy)? else {
        return Ok(());
    };
    let attributes = metadata.file_attributes();
    let directory = attributes & FILE_ATTRIBUTE_DIRECTORY != 0;
    let reparse = attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0;

    if directory && !reparse {
        set_windows_entry_readonly_nofollow(path, false)?;
        for entry in fs::read_dir(path)? {
            remove_windows_private_entry_tree(&entry?.path(), delete_policy)?;
        }
        set_windows_entry_readonly_nofollow(path, false)?;
        fs::remove_dir(path)?;
    } else {
        // FILE_FLAG_OPEN_REPARSE_POINT ensures the attribute update targets
        // the link/junction entry itself. DeleteFileW/RemoveDirectoryW then
        // unlink that entry rather than traversing its target.
        if directory {
            set_windows_entry_readonly_nofollow(path, false)?;
            fs::remove_dir(path)?;
        } else {
            remove_windows_private_file(path, delete_policy)?;
        }
    }
    Ok(())
}

#[cfg(windows)]
fn windows_error_is_sharing_violation(error: &io::Error) -> bool {
    use windows_sys::Win32::Foundation::ERROR_SHARING_VIOLATION;

    error.raw_os_error() == Some(ERROR_SHARING_VIOLATION as i32)
}

#[cfg(windows)]
fn wait_for_windows_private_file_release_if_allowed(
    error: &io::Error,
    delete_policy: WindowsPrivateFileDeletePolicy,
) -> AppResult<bool> {
    if !windows_error_is_sharing_violation(error) {
        return Ok(false);
    }
    let WindowsPrivateFileDeletePolicy::RetrySharingViolation { deadline, poll } = delete_policy
    else {
        return Ok(false);
    };
    let now = Instant::now();
    if now >= deadline {
        return Err(AppError::Runtime(format!(
            "managed Windows WSL provider storage remained in use after its bounded release wait; retaining remaining provider, installation, and image-cache state for a safe retry: {error}"
        )));
    }
    thread::sleep(poll.min(deadline.saturating_duration_since(now)));
    Ok(true)
}

#[cfg(windows)]
fn windows_private_entry_metadata_with_policy(
    path: &Path,
    delete_policy: WindowsPrivateFileDeletePolicy,
) -> AppResult<Option<fs::Metadata>> {
    loop {
        match fs::symlink_metadata(path) {
            Ok(metadata) => return Ok(Some(metadata)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                if wait_for_windows_private_file_release_if_allowed(&error, delete_policy)? {
                    continue;
                }
                return Err(error.into());
            }
        }
    }
}

#[cfg(windows)]
fn remove_windows_private_file(
    path: &Path,
    delete_policy: WindowsPrivateFileDeletePolicy,
) -> AppResult<()> {
    loop {
        match set_windows_entry_readonly_nofollow(path, false) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => {
                if wait_for_windows_private_file_release_if_allowed(&error, delete_policy)? {
                    continue;
                }
                return Err(error.into());
            }
        }
        match fs::remove_file(path) {
            Ok(()) => return Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => {
                if wait_for_windows_private_file_release_if_allowed(&error, delete_policy)? {
                    continue;
                }
                return Err(error.into());
            }
        }
    }
}

#[cfg(windows)]
fn set_windows_entry_readonly_nofollow(path: &Path, readonly: bool) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_READONLY, FILE_BASIC_INFO,
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES,
        FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_WRITE_ATTRIBUTES, FileBasicInfo,
        GetFileInformationByHandleEx, OPEN_EXISTING, SetFileInformationByHandle,
    };

    let encoded = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    // SAFETY: `encoded` is NUL-terminated and lives for the call. The returned
    // owned handle is closed exactly once below.
    let raw = unsafe {
        CreateFileW(
            encoded.as_ptr(),
            FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `raw` was returned by CreateFileW and is now uniquely owned.
    let handle = unsafe { OwnedHandle::from_raw_handle(raw) };
    let mut information = FILE_BASIC_INFO::default();
    // SAFETY: the handle is valid and the output buffer has the declared size.
    if unsafe {
        GetFileInformationByHandleEx(
            handle.as_raw_handle(),
            FileBasicInfo,
            (&raw mut information).cast(),
            std::mem::size_of::<FILE_BASIC_INFO>() as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let has_readonly = information.FileAttributes & FILE_ATTRIBUTE_READONLY != 0;
    if has_readonly == readonly {
        return Ok(());
    }
    if readonly {
        information.FileAttributes &= !FILE_ATTRIBUTE_NORMAL;
        information.FileAttributes |= FILE_ATTRIBUTE_READONLY;
    } else {
        information.FileAttributes &= !FILE_ATTRIBUTE_READONLY;
        if information.FileAttributes == 0 {
            information.FileAttributes = FILE_ATTRIBUTE_NORMAL;
        }
    }
    // SAFETY: the handle was opened with FILE_WRITE_ATTRIBUTES and the input
    // buffer is a fully initialized FILE_BASIC_INFO value.
    if unsafe {
        SetFileInformationByHandle(
            handle.as_raw_handle(),
            FileBasicInfo,
            (&raw const information).cast(),
            std::mem::size_of::<FILE_BASIC_INFO>() as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn sync_directory(path: &Path) -> AppResult<()> {
    #[cfg(unix)]
    File::open(path)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    #[cfg(unix)]
    use std::os::unix::process::ExitStatusExt;
    #[cfg(windows)]
    use std::os::windows::process::ExitStatusExt;
    use std::sync::Mutex;
    use tempfile::TempDir;

    #[cfg(windows)]
    fn windows_test_nofollow_security_file(path: &Path) -> File {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ,
            FILE_SHARE_WRITE, READ_CONTROL,
        };

        let mut options = OpenOptions::new();
        options
            .access_mode(FILE_READ_ATTRIBUTES | READ_CONTROL)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
        options.open(path).expect("open no-follow security fixture")
    }

    #[cfg(windows)]
    fn windows_test_security_snapshot(file: &File) -> (WindowsFileInformation, Vec<usize>) {
        (
            windows_file_information(file).expect("fixture file information"),
            windows_owner_dacl_security_descriptor(file).expect("fixture security descriptor"),
        )
    }

    fn assert_redacted_terminal_packaged_runtime_admission(
        admission: PackagedManagedRuntimeAdmission,
        expected_reason: ManagedRuntimeSetupFailureReason,
        forbidden: &[&str],
    ) {
        assert_eq!(admission.failure_reason(), Some(expected_reason));
        assert_eq!(admission.recovery_receipt(), None);
        match admission {
            PackagedManagedRuntimeAdmission::Verified(manager)
            | PackagedManagedRuntimeAdmission::RecoveredFromPrivateCache { manager, .. } => {
                let _ = manager.manifest_sha256();
                panic!("rejected fixture unexpectedly admitted a runtime manager");
            }
            PackagedManagedRuntimeAdmission::Missing
            | PackagedManagedRuntimeAdmission::VerificationFailed
            | PackagedManagedRuntimeAdmission::UnpackagedDeveloperBuild
            | PackagedManagedRuntimeAdmission::UnpackagedDeveloperBuildVerificationFailed => {}
        }

        let controller =
            ManagedRuntimeSetupController::for_packaged_runtime_admission_failure(expected_reason);
        let first = controller.status().expect("first admission status");
        let second = controller.status().expect("stable admission status");
        assert_eq!(second, first);
        assert_eq!(first.phase, ManagedRuntimeSetupPhase::Failed);
        assert_eq!(first.failure_reason, Some(expected_reason));
        assert!(first.operation_id.is_none());
        assert!(!first.active);
        assert!(!first.can_cancel);
        assert!(!first.can_retry);
        assert!(first.next_action.is_none());
        let expected_detail = expected_reason
            .packaged_runtime_admission_detail()
            .expect("admission failures have copy");
        assert_eq!(first.detail, expected_detail);

        let begin_error = controller
            .begin()
            .expect_err("terminal admission failure cannot begin setup");
        assert!(matches!(begin_error, AppError::NotAvailable(_)));
        assert!(begin_error.to_string().contains(expected_detail));
        assert_eq!(
            controller.status().expect("status after rejected begin"),
            first
        );

        let public_json = serde_json::to_string(&first).expect("serialize public status");
        assert!(public_json.contains(expected_reason.as_str()));
        for sensitive in forbidden {
            assert!(!public_json.contains(sensitive));
            assert!(!begin_error.to_string().contains(sensitive));
        }
    }

    #[test]
    fn missing_packaged_runtime_has_a_stable_redacted_non_retryable_status() {
        let temporary = tempfile::tempdir().expect("temporary admission fixture");
        let app_data = temporary.path().join("private-app-data");
        let resources = temporary.path().join("missing-runtime-bundle");
        fs::create_dir(&resources).expect("empty resource directory");
        let private_path = temporary.path().to_string_lossy().into_owned();
        let packaged_anchor = sha256_bytes(b"packaged-runtime-admission-anchor");

        let admission = admit_packaged_managed_runtime_with_recovery_digest(
            &app_data,
            &resources,
            Some(&packaged_anchor),
        );
        assert_redacted_terminal_packaged_runtime_admission(
            admission,
            ManagedRuntimeSetupFailureReason::PackagedRuntimeMissing,
            &[&private_path],
        );
        assert_eq!(
            ManagedRuntimeSetupFailureReason::PackagedRuntimeMissing
                .packaged_runtime_admission_detail(),
            Some("The installed scan tools are unavailable. Install the latest app version.")
        );
        assert!(
            !app_data.exists(),
            "a missing package must not initialize managed runtime state"
        );
    }

    #[test]
    fn unpackaged_developer_build_without_packaged_runtime_has_distinct_non_install_copy() {
        let temporary = tempfile::tempdir().expect("temporary admission fixture");
        let app_data = temporary.path().join("private-app-data");
        let resources = temporary.path().join("missing-runtime-bundle");
        fs::create_dir(&resources).expect("empty resource directory");
        let private_path = temporary.path().to_string_lossy().into_owned();

        let admission =
            admit_packaged_managed_runtime_with_recovery_digest(&app_data, &resources, None);
        assert_redacted_terminal_packaged_runtime_admission(
            admission,
            ManagedRuntimeSetupFailureReason::DeveloperBuildWithoutPackagedRuntime,
            &[&private_path],
        );
        let detail = ManagedRuntimeSetupFailureReason::DeveloperBuildWithoutPackagedRuntime
            .packaged_runtime_admission_detail()
            .expect("developer-build admission copy");
        let lowered = detail.to_ascii_lowercase();
        assert!(
            !lowered.contains("install the")
                && !lowered.contains("reinstall")
                && !lowered.contains("latest app version")
                && !lowered.contains("compatible app version"),
            "developer-build copy prescribed an install: {detail}"
        );
        assert!(
            !app_data.exists(),
            "an unpackaged developer build must not initialize managed runtime state"
        );

        let production = admit_packaged_managed_runtime(&app_data, &resources);
        let expected_production = if packaged_managed_runtime_manifest_digest_anchor().is_some() {
            ManagedRuntimeSetupFailureReason::PackagedRuntimeMissing
        } else {
            ManagedRuntimeSetupFailureReason::DeveloperBuildWithoutPackagedRuntime
        };
        assert_eq!(production.failure_reason(), Some(expected_production));
    }

    #[test]
    fn rejected_packaged_runtime_has_a_stable_redacted_non_retryable_status() {
        let temporary = tempfile::tempdir().expect("temporary admission fixture");
        let app_data = temporary.path().join("private-app-data");
        let resources = temporary.path().join("invalid-runtime-bundle");
        fs::create_dir(&resources).expect("resource directory");
        let rejected_bytes = r#"{"private":"DO-NOT-LEAK-REJECTED-BYTES"}"#;
        fs::write(resources.join("manifest.json"), rejected_bytes)
            .expect("invalid packaged manifest");
        let private_path = temporary.path().to_string_lossy().into_owned();

        let packaged_anchor = sha256_bytes(b"packaged-runtime-admission-anchor");
        let admission = admit_packaged_managed_runtime_with_recovery_digest(
            &app_data,
            &resources,
            Some(&packaged_anchor),
        );
        assert_redacted_terminal_packaged_runtime_admission(
            admission,
            ManagedRuntimeSetupFailureReason::PackagedRuntimeVerificationFailed,
            &[&private_path, rejected_bytes, "DO-NOT-LEAK-REJECTED-BYTES"],
        );
        assert_eq!(
            ManagedRuntimeSetupFailureReason::PackagedRuntimeVerificationFailed
                .packaged_runtime_admission_detail(),
            Some("The installed scan tools failed verification. Install the latest app version.")
        );
    }

    #[test]
    fn unpackaged_developer_build_with_unopenable_runtime_has_distinct_non_install_copy() {
        let temporary = tempfile::tempdir().expect("temporary admission fixture");
        let app_data = temporary.path().join("private-app-data");
        let resources = temporary.path().join("invalid-runtime-bundle");
        fs::create_dir(&resources).expect("resource directory");
        let rejected_bytes = r#"{"private":"DO-NOT-LEAK-REJECTED-BYTES"}"#;
        fs::write(resources.join("manifest.json"), rejected_bytes)
            .expect("invalid packaged manifest");
        let private_path = temporary.path().to_string_lossy().into_owned();

        let admission =
            admit_packaged_managed_runtime_with_recovery_digest(&app_data, &resources, None);
        assert_redacted_terminal_packaged_runtime_admission(
            admission,
            ManagedRuntimeSetupFailureReason::DeveloperBuildPackagedRuntimeVerificationFailed,
            &[&private_path, rejected_bytes, "DO-NOT-LEAK-REJECTED-BYTES"],
        );
        let detail =
            ManagedRuntimeSetupFailureReason::DeveloperBuildPackagedRuntimeVerificationFailed
                .packaged_runtime_admission_detail()
                .expect("developer-build verification-failure copy");
        let lowered = detail.to_ascii_lowercase();
        assert!(
            !lowered.contains("install") && !lowered.contains("reinstall"),
            "developer-build verification-failure copy prescribed an install: {detail}"
        );

        let production = admit_packaged_managed_runtime(&app_data, &resources);
        let expected_production = if packaged_managed_runtime_manifest_digest_anchor().is_some() {
            ManagedRuntimeSetupFailureReason::PackagedRuntimeVerificationFailed
        } else {
            ManagedRuntimeSetupFailureReason::DeveloperBuildPackagedRuntimeVerificationFailed
        };
        assert_eq!(production.failure_reason(), Some(expected_production));
    }

    #[test]
    fn packaged_runtime_admission_classifies_the_anchor_and_resource_matrix() {
        let temporary = tempfile::tempdir().expect("temporary admission fixture");
        let app_data = temporary.path().join("private-app-data");
        let missing = temporary.path().join("missing-runtime-bundle");
        fs::create_dir(&missing).expect("empty resource directory");
        let unopenable = temporary.path().join("invalid-runtime-bundle");
        fs::create_dir(&unopenable).expect("resource directory");
        fs::write(
            unopenable.join("manifest.json"),
            r#"{"private":"DO-NOT-LEAK-REJECTED-BYTES"}"#,
        )
        .expect("invalid packaged manifest");
        let packaged_anchor = sha256_bytes(b"packaged-runtime-admission-anchor");

        let cases = [
            (
                None,
                unopenable.as_path(),
                ManagedRuntimeSetupFailureReason::DeveloperBuildPackagedRuntimeVerificationFailed,
                None,
            ),
            (
                None,
                missing.as_path(),
                ManagedRuntimeSetupFailureReason::DeveloperBuildWithoutPackagedRuntime,
                None,
            ),
            (
                Some(packaged_anchor.as_str()),
                unopenable.as_path(),
                ManagedRuntimeSetupFailureReason::PackagedRuntimeVerificationFailed,
                Some(
                    "The installed scan tools failed verification. Install the latest app version.",
                ),
            ),
            (
                Some(packaged_anchor.as_str()),
                missing.as_path(),
                ManagedRuntimeSetupFailureReason::PackagedRuntimeMissing,
                Some("The installed scan tools are unavailable. Install the latest app version."),
            ),
        ];

        for (anchor, resources, expected, packaged_copy) in cases {
            let admission =
                admit_packaged_managed_runtime_with_recovery_digest(&app_data, resources, anchor);
            assert_eq!(
                admission.failure_reason(),
                Some(expected),
                "anchor={anchor:?} resources={}",
                resources.display()
            );
            let detail = expected
                .packaged_runtime_admission_detail()
                .expect("admission failures have copy");
            if let Some(packaged_copy) = packaged_copy {
                assert_eq!(detail, packaged_copy, "{expected:?}");
            } else {
                let lowered = detail.to_ascii_lowercase();
                assert!(
                    !lowered.contains("install") && !lowered.contains("reinstall"),
                    "{expected:?} prescribed an install: {detail}"
                );
            }
        }
    }

    #[test]
    fn missing_packaged_runtime_recovers_only_the_exact_intact_private_copy() {
        let fixture = fixture();
        fixture
            .manager
            .install()
            .expect("seed private runtime copy");
        let app_data = fixture
            .manager
            .state_root
            .parent()
            .expect("application data parent")
            .to_path_buf();
        let resources = fixture.manager.resource_root.clone();
        let expected_digest = fixture.manager.manifest_sha256().to_owned();
        let expected_private_root = fixture
            .manager
            .install_directory()
            .canonicalize()
            .expect("canonical private runtime copy");
        fs::remove_dir_all(&resources).expect("remove packaged runtime tree");

        let admission = admit_packaged_managed_runtime_with_recovery_digest(
            &app_data,
            &resources,
            Some(&expected_digest),
        );

        assert_eq!(admission.failure_reason(), None);
        assert_eq!(
            admission.recovery_receipt(),
            Some(PackagedManagedRuntimeRecoveryReceipt {
                boundary: "packaged_component_auto_recovery",
                source: "private_installed_copy",
                manifest_sha256: &expected_digest,
                packaged_failure_reason: ManagedRuntimeSetupFailureReason::PackagedRuntimeMissing,
            })
        );
        let recovered = match admission {
            PackagedManagedRuntimeAdmission::RecoveredFromPrivateCache { manager, .. } => manager,
            PackagedManagedRuntimeAdmission::Verified(_) => {
                panic!("a missing packaged tree cannot be the verified source")
            }
            PackagedManagedRuntimeAdmission::Missing
            | PackagedManagedRuntimeAdmission::VerificationFailed
            | PackagedManagedRuntimeAdmission::UnpackagedDeveloperBuild
            | PackagedManagedRuntimeAdmission::UnpackagedDeveloperBuildVerificationFailed => {
                panic!("the exact intact private copy was not recovered")
            }
        };
        assert_eq!(recovered.manifest_sha256(), expected_digest);
        assert_eq!(recovered.resource_root, expected_private_root);
        recovered
            .verify_installation()
            .expect("recovered private copy remains fully verified");
        assert_eq!(fixture.commands.calls(), Vec::<Vec<String>>::new());
    }

    #[test]
    fn tampered_packaged_runtime_never_becomes_the_recovered_command_source() {
        let fixture = fixture();
        fixture
            .manager
            .install()
            .expect("seed private runtime copy");
        let app_data = fixture
            .manager
            .state_root
            .parent()
            .expect("application data parent")
            .to_path_buf();
        let resources = fixture.manager.resource_root.clone();
        let expected_digest = fixture.manager.manifest_sha256().to_owned();
        let expected_private_root = fixture
            .manager
            .install_directory()
            .canonicalize()
            .expect("canonical private runtime copy");
        let rejected_driver = b"DO-NOT-EXECUTE-TAMPERED-PACKAGED-DRIVER";
        fs::write(
            resources.join("manifest.json"),
            &fixture.manager.loaded.encoded,
        )
        .expect("write packaged manifest");
        fs::write(resources.join("bin/podman"), rejected_driver).expect("tamper packaged driver");

        let admission = admit_packaged_managed_runtime_with_recovery_digest(
            &app_data,
            &resources,
            Some(&expected_digest),
        );

        assert_eq!(admission.failure_reason(), None);
        assert_eq!(
            admission.recovery_receipt(),
            Some(PackagedManagedRuntimeRecoveryReceipt {
                boundary: "packaged_component_auto_recovery",
                source: "private_installed_copy",
                manifest_sha256: &expected_digest,
                packaged_failure_reason:
                    ManagedRuntimeSetupFailureReason::PackagedRuntimeVerificationFailed,
            })
        );
        let recovered = match admission {
            PackagedManagedRuntimeAdmission::RecoveredFromPrivateCache { manager, .. } => manager,
            PackagedManagedRuntimeAdmission::Verified(_) => {
                panic!("tampered packaged bytes were admitted as verified")
            }
            PackagedManagedRuntimeAdmission::Missing
            | PackagedManagedRuntimeAdmission::VerificationFailed
            | PackagedManagedRuntimeAdmission::UnpackagedDeveloperBuild
            | PackagedManagedRuntimeAdmission::UnpackagedDeveloperBuildVerificationFailed => {
                panic!("the exact intact private copy was not recovered")
            }
        };
        assert_eq!(recovered.resource_root, expected_private_root);
        assert_ne!(
            recovered.resource_root,
            resources
                .canonicalize()
                .expect("canonical packaged resources")
        );
        assert_eq!(
            fs::read(resources.join("bin/podman")).expect("read rejected driver"),
            rejected_driver
        );
        recovered
            .verify_installation()
            .expect("recovered command source remains fully verified");
        assert_eq!(fixture.commands.calls(), Vec::<Vec<String>>::new());
    }

    #[test]
    fn missing_packaged_runtime_rejects_absent_wrong_or_malformed_recovery_digests() {
        let fixture = fixture();
        fixture
            .manager
            .install()
            .expect("seed private runtime copy");
        let app_data = fixture
            .manager
            .state_root
            .parent()
            .expect("application data parent")
            .to_path_buf();
        let resources = fixture.manager.resource_root.clone();
        let wrong_digest = sha256_bytes(b"different private runtime identity");
        let malformed_digest = "DO-NOT-LEAK-MALFORMED-RECOVERY-DIGEST";
        let private_path = app_data.to_string_lossy().into_owned();
        fs::remove_dir_all(&resources).expect("remove packaged runtime tree");

        let admission = admit_packaged_managed_runtime_with_recovery_digest(
            &app_data,
            &resources,
            Some(wrong_digest.as_str()),
        );
        assert_redacted_terminal_packaged_runtime_admission(
            admission,
            ManagedRuntimeSetupFailureReason::PackagedRuntimeMissing,
            &[
                &private_path,
                wrong_digest.as_str(),
                malformed_digest,
                "managed-podman-driver",
            ],
        );

        for recovery_digest in [None, Some(malformed_digest)] {
            let admission = admit_packaged_managed_runtime_with_recovery_digest(
                &app_data,
                &resources,
                recovery_digest,
            );
            assert_redacted_terminal_packaged_runtime_admission(
                admission,
                ManagedRuntimeSetupFailureReason::DeveloperBuildWithoutPackagedRuntime,
                &[
                    &private_path,
                    wrong_digest.as_str(),
                    malformed_digest,
                    "managed-podman-driver",
                ],
            );
        }
        assert_eq!(fixture.commands.calls(), Vec::<Vec<String>>::new());
    }

    #[test]
    fn tampered_private_copy_retains_the_original_redacted_package_rejection() {
        let fixture = fixture();
        fixture
            .manager
            .install()
            .expect("seed private runtime copy");
        let app_data = fixture
            .manager
            .state_root
            .parent()
            .expect("application data parent")
            .to_path_buf();
        let resources = fixture.manager.resource_root.clone();
        let expected_digest = fixture.manager.manifest_sha256().to_owned();
        let installed_driver = fixture.manager.install_directory().join("bin/podman");
        let rejected_packaged_driver = b"DO-NOT-LEAK-TAMPERED-PACKAGED-DRIVER";
        let rejected_private_driver = b"tampered-runtime";
        fs::write(
            resources.join("manifest.json"),
            &fixture.manager.loaded.encoded,
        )
        .expect("write packaged manifest");
        fs::write(resources.join("bin/podman"), rejected_packaged_driver)
            .expect("tamper packaged driver");
        tamper_installed_driver(&fixture.manager);
        let packaged_path = resources.to_string_lossy().into_owned();
        let private_path = installed_driver.to_string_lossy().into_owned();

        let admission = admit_packaged_managed_runtime_with_recovery_digest(
            &app_data,
            &resources,
            Some(&expected_digest),
        );

        assert_redacted_terminal_packaged_runtime_admission(
            admission,
            ManagedRuntimeSetupFailureReason::PackagedRuntimeVerificationFailed,
            &[
                &packaged_path,
                &private_path,
                std::str::from_utf8(rejected_packaged_driver).expect("UTF-8 fixture"),
                std::str::from_utf8(rejected_private_driver).expect("UTF-8 fixture"),
            ],
        );
        assert_eq!(
            fs::read(resources.join("bin/podman")).expect("read rejected packaged driver"),
            rejected_packaged_driver
        );
        assert_eq!(
            fs::read(installed_driver).expect("read rejected private driver"),
            rejected_private_driver
        );
        assert_eq!(fixture.commands.calls(), Vec::<Vec<String>>::new());
    }

    #[test]
    fn healthy_packaged_runtime_wins_without_consulting_a_recovery_digest() {
        let fixture = fixture();
        let app_data = fixture
            .manager
            .state_root
            .parent()
            .expect("application data parent")
            .to_path_buf();
        let resources = fixture.manager.resource_root.clone();
        fs::write(
            resources.join("manifest.json"),
            &fixture.manager.loaded.encoded,
        )
        .expect("write healthy packaged manifest");

        let admission = admit_packaged_managed_runtime_with_recovery_digest(
            &app_data,
            &resources,
            Some("not-a-valid-or-consulted-recovery-digest"),
        );

        assert_eq!(admission.recovery_receipt(), None);
        match admission {
            PackagedManagedRuntimeAdmission::Verified(manager) => {
                assert_eq!(manager.manifest_sha256(), fixture.manager.manifest_sha256());
            }
            PackagedManagedRuntimeAdmission::RecoveredFromPrivateCache { .. } => {
                panic!("healthy packaged resources must remain the primary source")
            }
            PackagedManagedRuntimeAdmission::Missing
            | PackagedManagedRuntimeAdmission::VerificationFailed
            | PackagedManagedRuntimeAdmission::UnpackagedDeveloperBuild
            | PackagedManagedRuntimeAdmission::UnpackagedDeveloperBuildVerificationFailed => {
                panic!("healthy packaged resources were unexpectedly rejected")
            }
        }
        assert_eq!(fixture.commands.calls(), Vec::<Vec<String>>::new());
    }

    #[test]
    fn exact_legacy_private_copy_is_not_a_current_desktop_recovery_source() {
        let mut fixture = fixture();
        let mut legacy_manifest = fixture.manager.loaded.manifest.clone();
        legacy_manifest.schema_version = LEGACY_MANIFEST_SCHEMA_VERSION.into();
        legacy_manifest.management_contract_revision = None;
        let legacy_bytes = serde_json::to_vec(&legacy_manifest).expect("legacy manifest");
        fixture.manager.loaded =
            LoadedManagedRuntimeManifest::parse(&legacy_bytes).expect("strict legacy manifest");
        fixture
            .manager
            .install()
            .expect("seed exact legacy private copy");
        let app_data = fixture
            .manager
            .state_root
            .parent()
            .expect("application data parent")
            .to_path_buf();
        let resources = fixture.manager.resource_root.clone();
        let legacy_digest = fixture.manager.manifest_sha256().to_owned();
        fs::remove_dir_all(&resources).expect("remove packaged runtime tree");

        let admission = admit_packaged_managed_runtime_with_recovery_digest(
            &app_data,
            &resources,
            Some(&legacy_digest),
        );

        assert_redacted_terminal_packaged_runtime_admission(
            admission,
            ManagedRuntimeSetupFailureReason::PackagedRuntimeMissing,
            &[legacy_digest.as_str()],
        );
        assert_eq!(fixture.commands.calls(), Vec::<Vec<String>>::new());
    }

    #[test]
    fn every_setup_failure_reason_has_user_facing_copy() {
        fn copy_for(reason: ManagedRuntimeSetupFailureReason) -> String {
            match reason {
                ManagedRuntimeSetupFailureReason::PackagedRuntimeMissing
                | ManagedRuntimeSetupFailureReason::PackagedRuntimeVerificationFailed
                | ManagedRuntimeSetupFailureReason::DeveloperBuildWithoutPackagedRuntime
                | ManagedRuntimeSetupFailureReason::DeveloperBuildPackagedRuntimeVerificationFailed => {
                    reason
                        .packaged_runtime_admission_detail()
                        .expect("packaged-runtime admission failures have copy")
                        .into()
                }
                ManagedRuntimeSetupFailureReason::WslNotInstalled
                | ManagedRuntimeSetupFailureReason::WslOptionalFeatureDisabled
                | ManagedRuntimeSetupFailureReason::WslUpdateRequired
                | ManagedRuntimeSetupFailureReason::RestartRequired
                | ManagedRuntimeSetupFailureReason::WslCommandFailed => {
                    WindowsWslPrerequisiteFailure {
                        reason,
                        action: ManagedRuntimeSetupNextAction::RetryWslCheck,
                        exit_code: None,
                    }
                    .detail()
                }
            }
        }

        for reason in [
            ManagedRuntimeSetupFailureReason::PackagedRuntimeMissing,
            ManagedRuntimeSetupFailureReason::PackagedRuntimeVerificationFailed,
            ManagedRuntimeSetupFailureReason::DeveloperBuildWithoutPackagedRuntime,
            ManagedRuntimeSetupFailureReason::DeveloperBuildPackagedRuntimeVerificationFailed,
            ManagedRuntimeSetupFailureReason::WslNotInstalled,
            ManagedRuntimeSetupFailureReason::WslOptionalFeatureDisabled,
            ManagedRuntimeSetupFailureReason::WslUpdateRequired,
            ManagedRuntimeSetupFailureReason::RestartRequired,
            ManagedRuntimeSetupFailureReason::WslCommandFailed,
        ] {
            let copy = copy_for(reason);
            assert!(!copy.is_empty(), "{reason:?} has empty copy");
            assert!(
                !copy.contains(reason.as_str()),
                "{reason:?} leaked its raw code into copy: {copy}"
            );
            assert_eq!(
                reason.packaged_runtime_admission_detail().is_some(),
                reason.is_packaged_runtime_admission_failure(),
                "{reason:?} admission-copy presence must match the admission-failure set"
            );
        }
    }

    #[test]
    fn desktop_build_anchor_matches_the_staged_manifest_used_for_packaging() {
        if !cfg!(feature = "desktop") {
            assert_eq!(
                packaged_managed_runtime_manifest_digest_anchor(),
                None,
                "a non-desktop build must not embed a packaged-runtime anchor"
            );
            return;
        }
        let manifest_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../runtime/staged/managed-runtime/manifest.json");
        match fs::read(&manifest_path) {
            Ok(manifest) => {
                let expected_digest = sha256_bytes(&manifest);
                assert_eq!(
                    packaged_managed_runtime_manifest_digest_anchor(),
                    Some(expected_digest.as_str()),
                    "the runtime trust anchor must be emitted from the staged manifest"
                );
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => assert_eq!(
                packaged_managed_runtime_manifest_digest_anchor(),
                None,
                "a debug desktop build without staged resources must not invent an anchor"
            ),
            Err(error) => panic!("could not read staged managed-runtime manifest: {error}"),
        }
    }

    #[cfg(windows)]
    fn installed_windows_runtime_command(fixture: &Fixture) -> ManagedRuntimeCommand {
        fixture
            .manager
            .install()
            .expect("install protected Windows runtime fixture");
        let target = fixture.manager.loaded.target().expect("Windows target");
        fixture
            .manager
            .runtime_command(target)
            .expect("construct protected Windows runtime command")
    }

    #[cfg(windows)]
    #[test]
    fn windows_installed_runtime_rejects_non_exact_directory_and_file_dacls() {
        let directory_fixture = fixture();
        directory_fixture
            .manager
            .install()
            .expect("install directory-DACL fixture");
        let unsafe_directory = directory_fixture.manager.install_directory().join("bin");
        set_windows_permissive_inheritable_dacl(&unsafe_directory);
        let directory_before = windows_test_security_snapshot(
            &open_windows_real_directory_security_handle(&unsafe_directory)
                .expect("open widened directory"),
        );
        assert!(
            directory_fixture.manager.verify_installation().is_err(),
            "an extra directory principal must invalidate the installed runtime"
        );
        assert_eq!(
            windows_test_security_snapshot(
                &open_windows_real_directory_security_handle(&unsafe_directory)
                    .expect("reopen widened directory"),
            ),
            directory_before,
            "verification must not repair a rejected directory DACL"
        );

        let file_fixture = fixture();
        file_fixture
            .manager
            .install()
            .expect("install file-DACL fixture");
        let unsafe_file = file_fixture.manager.install_directory().join("bin/podman");
        set_test_world_readable_product_file_dacl(&unsafe_file)
            .expect("add one foreign read principal to payload");
        let file_before =
            windows_test_security_snapshot(&windows_test_nofollow_security_file(&unsafe_file));
        assert!(
            file_fixture.manager.verify_installation().is_err(),
            "an extra file principal must invalidate the installed runtime"
        );
        assert_eq!(
            windows_test_security_snapshot(&windows_test_nofollow_security_file(&unsafe_file)),
            file_before,
            "verification must not repair a rejected file DACL"
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_installed_runtime_rejects_a_non_exact_versions_root_dacl() {
        let fixture = fixture();
        fixture
            .manager
            .install()
            .expect("install versions-DACL fixture");
        let versions = fixture.manager.versions_root();
        set_windows_permissive_inheritable_dacl(&versions);
        let before = windows_test_security_snapshot(
            &open_windows_real_directory_security_handle(&versions)
                .expect("open widened versions root"),
        );

        assert!(
            fixture.manager.verify_installation().is_err(),
            "an extra versions-root principal must invalidate the installed runtime"
        );
        assert_eq!(
            windows_test_security_snapshot(
                &open_windows_real_directory_security_handle(&versions)
                    .expect("reopen widened versions root"),
            ),
            before,
            "verification must not repair a rejected versions-root DACL"
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_launch_guard_pins_ancestor_directories_and_payload_until_drop() {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        };

        let fixture = fixture();
        let command = installed_windows_runtime_command(&fixture);
        let state_root = fixture.manager.state_root.clone();
        let contract = command
            .windows_launch_contract()
            .expect("managed command carries its Windows launch contract");
        let install_root = contract.install_root.clone();
        drop(fixture.manager);
        let guard = contract
            .acquire(command.binary(), Instant::now() + COMMAND_TIMEOUT, &|| {
                false
            })
            .expect("acquire exact Windows execution guard");

        let write_attempt = OpenOptions::new()
            .write(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .open(command.binary());
        assert!(
            write_attempt.is_err(),
            "a guarded payload must reject a concurrent writer"
        );
        let moved = command.binary().with_extension("guarded-move");
        let moved_install = install_root.with_extension("guarded-move");
        let moved_state = state_root.with_extension("guarded-move");
        assert!(
            fs::rename(command.binary(), &moved).is_err(),
            "a guarded payload must reject rename/delete replacement"
        );
        assert!(
            fs::rename(&install_root, &moved_install).is_err(),
            "the guard must pin the installed directory"
        );
        assert!(
            fs::rename(&state_root, &moved_state).is_err(),
            "the guard must pin the state-root ancestor even after the manager is dropped"
        );

        drop(guard);
        drop(
            OpenOptions::new()
                .write(true)
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
                .open(command.binary())
                .expect("idle payload becomes writable for bounded repair"),
        );
        fs::rename(command.binary(), &moved).expect("idle payload can be moved for repair");
        fs::rename(&moved, command.binary()).expect("restore payload after lock-lifetime proof");
        fs::rename(&install_root, &moved_install)
            .expect("idle install root can be moved for repair");
        fs::rename(&moved_install, &install_root).expect("restore install root after guard proof");
        fs::rename(&state_root, &moved_state).expect("idle state root can be moved for repair");
        fs::rename(&moved_state, &state_root).expect("restore state root after guard proof");
    }

    #[cfg(windows)]
    #[test]
    fn windows_launch_contract_rejects_post_command_tamper_and_survives_manager_drop() {
        let fixture = fixture();
        let command = installed_windows_runtime_command(&fixture);
        let binary = command.binary().to_path_buf();
        let runtime = crate::container_runtime::ProcessContainerRuntime::from_managed(command)
            .expect("retain managed runtime context");

        let mut tampered = fs::read(&binary).expect("read idle payload");
        tampered[0] ^= 0xff;
        fs::write(&binary, tampered).expect("tamper idle payload without changing its size");
        drop(fixture.manager);

        let error = runtime
            .command_context()
            .output(&[], 1024, Duration::from_secs(1))
            .expect_err("context must re-prove the payload before process creation");
        assert!(
            error.to_string().contains("release-locked digest"),
            "the retained context must fail in its pre-spawn guard: {error}"
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_managed_container_context_rejects_a_missing_launch_contract() {
        let fixture = fixture();
        let command = ManagedRuntimeCommand {
            binary: fixture.manager.resource_root.join("bin/podman"),
            environment: BTreeMap::new(),
            working_directory: fixture.manager.resource_root.clone(),
            runtime_version: "fixture".into(),
            manifest_sha256: "a".repeat(64),
            machine_image_sha256: "b".repeat(64),
            windows_launch_authorization: WindowsManagedRuntimeLaunchAuthorization::MetadataOnly,
        };

        let error = crate::container_runtime::ProcessContainerRuntime::from_managed(command)
            .expect_err("Windows managed-local context must fail closed without a contract");
        assert!(error.to_string().contains("missing its pre-spawn"));
    }

    #[cfg(windows)]
    #[test]
    fn windows_metadata_only_command_cannot_reach_the_direct_runner() {
        let fixture = fixture();
        let command = ManagedRuntimeCommand {
            binary: fixture.manager.resource_root.join("bin/podman"),
            environment: BTreeMap::new(),
            working_directory: fixture.manager.resource_root.clone(),
            runtime_version: "fixture".into(),
            manifest_sha256: "a".repeat(64),
            machine_image_sha256: "b".repeat(64),
            windows_launch_authorization: WindowsManagedRuntimeLaunchAuthorization::MetadataOnly,
        };

        let error = DirectManagedCommandRunner
            .output(&command, &[], COMMAND_TIMEOUT)
            .expect_err("metadata-only commands must fail before process creation");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(error.to_string().contains("metadata-only"));
    }

    #[cfg(windows)]
    #[test]
    fn windows_system32_authorization_rejects_a_forged_binary_path() {
        let fixture = fixture();
        let command = ManagedRuntimeCommand {
            binary: fixture.manager.resource_root.join("bin/podman"),
            environment: BTreeMap::new(),
            working_directory: fixture.manager.resource_root.clone(),
            runtime_version: "fixture".into(),
            manifest_sha256: "a".repeat(64),
            machine_image_sha256: "b".repeat(64),
            windows_launch_authorization:
                WindowsManagedRuntimeLaunchAuthorization::VerifiedSystem32Wsl,
        };

        let error = DirectManagedCommandRunner
            .output(&command, &[], COMMAND_TIMEOUT)
            .expect_err("a forged system-command path must fail before process creation");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(error.to_string().contains("System32"));
    }

    #[cfg(windows)]
    #[test]
    fn windows_launch_contract_rejects_a_post_command_hard_link() {
        let fixture = fixture();
        let command = installed_windows_runtime_command(&fixture);
        let contract = command
            .windows_launch_contract()
            .expect("managed command carries its Windows launch contract");
        let alias = command.binary().with_extension("hard-link-alias");
        fs::hard_link(command.binary(), &alias).expect("add adversarial hard link");

        let error = contract
            .acquire(command.binary(), Instant::now() + COMMAND_TIMEOUT, &|| {
                false
            })
            .expect_err("multi-link payload must fail before process creation");
        assert!(
            error.to_string().contains("single-link"),
            "hard-link rejection should remain attributable: {error}"
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_launch_contract_rejects_an_unlisted_helper_added_after_verification() {
        let fixture = fixture();
        let command = installed_windows_runtime_command(&fixture);
        let contract = command
            .windows_launch_contract()
            .expect("managed command carries its Windows launch contract");
        let injected = fixture.manager.install_directory().join("bin/wsl.exe");
        fs::write(&injected, b"unlisted helper").expect("add unlisted helper");

        let error = contract
            .acquire(command.binary(), Instant::now() + COMMAND_TIMEOUT, &|| {
                false
            })
            .expect_err("an unlisted helper must fail before process creation");
        assert!(
            error.to_string().contains("unlisted launch-time entry"),
            "closed-inventory rejection should remain attributable: {error}"
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_launch_contract_honors_deadline_and_cooperative_cancellation() {
        use std::cell::Cell;

        let fixture = fixture();
        let command = installed_windows_runtime_command(&fixture);
        let contract = command
            .windows_launch_contract()
            .expect("managed command carries its Windows launch contract");

        let timeout = contract
            .acquire(command.binary(), Instant::now(), &|| false)
            .expect_err("an expired command budget must stop launch verification");
        assert_eq!(timeout.kind(), io::ErrorKind::TimedOut);

        let cancelled = contract
            .acquire(command.binary(), Instant::now() + COMMAND_TIMEOUT, &|| true)
            .expect_err("cancellation must stop launch verification");
        assert_eq!(cancelled.kind(), io::ErrorKind::Interrupted);

        let checks = Cell::new(0_usize);
        let cancel_during_file_verification = || {
            let next = checks.get() + 1;
            checks.set(next);
            next >= 15
        };
        let cancelled = contract
            .acquire(
                command.binary(),
                Instant::now() + COMMAND_TIMEOUT,
                &cancel_during_file_verification,
            )
            .expect_err("cancellation between hash chunks must stop launch verification");
        assert_eq!(cancelled.kind(), io::ErrorKind::Interrupted);
        assert!(
            checks.get() >= 15,
            "launch verification must poll beyond its initial filesystem checks"
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_launch_guard_is_compatible_with_a_real_pe_and_lives_through_child_exit() {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        };

        let mut fixture = fixture();
        let system = windows_system_directories().expect("verified Windows system directories");
        let source = system.system32.join("cmd.exe");
        let resource_driver = fixture.manager.resource_root.join("bin/podman.exe");
        fs::copy(&source, &resource_driver).expect("copy a real PE test driver");
        let driver_bytes = fs::read(&resource_driver).expect("read PE fixture");
        let driver_digest = sha256_bytes(&driver_bytes);
        let mut manifest = fixture.manager.loaded.manifest.clone();
        manifest.driver_path = "bin/podman.exe".into();
        manifest.files[0].path = manifest.driver_path.clone();
        manifest.files[0].size_bytes = driver_bytes.len() as u64;
        manifest.files[0].sha256 = driver_digest.clone();
        let driver_artifact = manifest
            .components
            .iter_mut()
            .flat_map(|component| component.artifacts.iter_mut())
            .find(|artifact| artifact.delivery == ManagedRuntimeArtifactDelivery::BundledFile)
            .expect("bundled driver artifact");
        driver_artifact.locator = manifest.driver_path.clone();
        driver_artifact.size_bytes = driver_bytes.len() as u64;
        driver_artifact.sha256 = driver_digest;
        let encoded = serde_json::to_vec(&manifest).expect("PE fixture manifest");
        fixture.manager.loaded =
            LoadedManagedRuntimeManifest::parse(&encoded).expect("validated PE fixture manifest");

        let mut command = installed_windows_runtime_command(&fixture);
        let context =
            crate::container_runtime::ProcessContainerRuntime::from_managed(command.clone())
                .expect("construct retained PE command context")
                .command_context();
        let simple_args = ["/D", "/Q", "/C", "exit /b 0"]
            .into_iter()
            .map(OsString::from)
            .collect::<Vec<_>>();
        let simple = context
            .output(&simple_args, 1024, Duration::from_secs(10))
            .expect("a guarded PE can be launched through the retained context");
        assert!(simple.status.success());

        let ready = fixture._temp.path().join("guarded-child-ready");
        command.environment.insert(
            OsString::from("AI_SECURITY_SCANNER_GUARD_READY"),
            ready.as_os_str().to_owned(),
        );
        // `Command` quotes this argument with CRT rules and escapes an embedded
        // quote as `\"`. cmd.exe has no backslash escaping, so those arrive
        // literally and corrupt both the redirect target and the ping path.
        // Keep the command line quote-free, which requires space-free paths.
        assert!(
            !ready.as_os_str().to_string_lossy().contains(' '),
            "the readiness marker path must be space-free to stay quote-free: {}",
            ready.display()
        );
        // `SystemRoot` carries the canonicalised `\\?\` form, which cmd.exe
        // cannot execute, so resolve the sleep helper to its drive-letter form.
        let ping = system.system32.join("ping.exe");
        let ping = ping.to_string_lossy();
        let ping = ping.strip_prefix(r"\\?\").unwrap_or(&ping);
        assert!(
            !ping.contains(' '),
            "the sleep helper path must be space-free to stay quote-free: {ping}"
        );
        let long_args = [
            OsString::from("/D"),
            OsString::from("/Q"),
            OsString::from("/C"),
            OsString::from(format!(
                "(echo ready)>%AI_SECURITY_SCANNER_GUARD_READY% & {ping} -n 4 127.0.0.1 >nul"
            )),
        ];
        let manifest_path = fixture.manager.install_directory().join("manifest.json");
        let moved_manifest = manifest_path.with_extension("guarded-move");
        let mut worker = Some(thread::spawn(move || {
            DirectManagedCommandRunner.output(&command, &long_args, Duration::from_secs(10))
        }));
        // Outlast the worker's own ten-second timeout so a stalled child always
        // resolves into a reported outcome rather than racing this deadline.
        let ready_deadline = Instant::now() + Duration::from_secs(30);
        // The launch can fail before the child ever runs (guard rejection, spawn
        // error). Report that outcome instead of only observing a missing marker.
        let mut early_exit = None;
        while !ready.exists() && Instant::now() < ready_deadline {
            if worker.as_ref().is_some_and(thread::JoinHandle::is_finished) {
                early_exit = Some(worker.take().expect("worker handle").join());
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        assert!(
            ready.exists(),
            "the guarded PE child did not reach its marker; launch outcome: {}",
            match &early_exit {
                None => "the worker is still running".to_owned(),
                Some(Err(_)) => "the worker panicked".to_owned(),
                Some(Ok(Err(error))) => format!("the launch failed: {error}"),
                Some(Ok(Ok(output))) => format!(
                    "the child exited early with {:?}; stdout={:?}; stderr={:?}",
                    output.status,
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr),
                ),
            }
        );
        let worker = worker.expect("the guarded PE worker is still running");

        assert!(
            OpenOptions::new()
                .write(true)
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
                .open(&manifest_path)
                .is_err(),
            "the manifest must remain write-locked while the child is alive"
        );
        assert!(
            fs::rename(&manifest_path, &moved_manifest).is_err(),
            "the manifest must remain rename-locked while the child is alive"
        );
        let output = worker
            .join()
            .expect("guarded PE worker")
            .expect("guarded PE output");
        assert!(
            output.status.success(),
            "the guarded PE child exited with {:?}; stdout={:?}; stderr={:?}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );

        drop(
            OpenOptions::new()
                .write(true)
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
                .open(&manifest_path)
                .expect("manifest write lock is released after child output drains"),
        );
    }

    fn success(stdout: impl Into<Vec<u8>>) -> ManagedCommandOutput {
        ManagedCommandOutput {
            status: ExitStatus::from_raw(0),
            stdout: stdout.into(),
            stderr: Vec::new(),
        }
    }

    fn failure(stderr: impl Into<Vec<u8>>) -> ManagedCommandOutput {
        failure_with_status(1, stderr)
    }

    fn failure_with_status(code: i32, stderr: impl Into<Vec<u8>>) -> ManagedCommandOutput {
        #[cfg(unix)]
        let status = ExitStatus::from_raw(code << 8);
        #[cfg(windows)]
        let status = ExitStatus::from_raw(code as u32);
        ManagedCommandOutput {
            status,
            stdout: Vec::new(),
            stderr: stderr.into(),
        }
    }

    fn utf16le(value: &str) -> Vec<u8> {
        value.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    #[cfg(unix)]
    fn direct_unix_test_command(
        working_directory: &Path,
        environment: BTreeMap<OsString, OsString>,
    ) -> ManagedRuntimeCommand {
        ManagedRuntimeCommand {
            binary: PathBuf::from("/bin/sh"),
            environment,
            working_directory: working_directory.to_path_buf(),
            runtime_version: "test".into(),
            manifest_sha256: "a".repeat(64),
            machine_image_sha256: "b".repeat(64),
        }
    }

    #[cfg(unix)]
    fn assert_unix_process_is_reaped(pid: i32) {
        let reap_deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let gone = unsafe { libc::kill(pid, 0) } == -1
                && io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH);
            if gone {
                return;
            }
            assert!(
                Instant::now() < reap_deadline,
                "managed runtime descendant survived process-group termination"
            );
            thread::sleep(Duration::from_millis(5));
        }
    }

    #[cfg(unix)]
    #[test]
    fn direct_command_zero_deadline_cannot_report_a_fast_exit_as_success() {
        let temp = TempDir::new().expect("temporary root");
        let command = direct_unix_test_command(temp.path(), BTreeMap::new());
        let started = Instant::now();

        let error = DirectManagedCommandRunner
            .output(
                &command,
                &[OsString::from("-c"), OsString::from("exit 0")],
                Duration::ZERO,
            )
            .expect_err("a zero-deadline command must fail closed");

        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(error.to_string().contains("command exceeded its deadline"));
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn command_cleanup_failure_preserves_the_primary_error_kind() {
        let error = managed_command_error_with_cleanup(
            managed_command_deadline_error(),
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "fixture cleanup denial",
            )),
        );

        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(error.to_string().contains("fixture cleanup denial"));
        assert!(error.to_string().contains("cleanup also failed"));
    }

    #[cfg(windows)]
    fn set_windows_inheritable_allow_dacl(
        path: &Path,
        sid_kind: windows_sys::Win32::Security::WELL_KNOWN_SID_TYPE,
        mask: u32,
    ) {
        use windows_sys::Win32::Security::{CONTAINER_INHERIT_ACE, OBJECT_INHERIT_ACE};

        set_windows_allow_dacl_with_flags(
            path,
            sid_kind,
            mask,
            OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE,
        );
    }

    #[cfg(windows)]
    fn set_windows_allow_dacl_with_flags(
        path: &Path,
        sid_kind: windows_sys::Win32::Security::WELL_KNOWN_SID_TYPE,
        mask: u32,
        principal_ace_flags: u32,
    ) {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Foundation::TRUE;
        use windows_sys::Win32::Security::{
            ACCESS_ALLOWED_ACE, ACL, ACL_REVISION, AddAccessAllowedAceEx, CONTAINER_INHERIT_ACE,
            CreateWellKnownSid, DACL_SECURITY_INFORMATION, GetLengthSid, InitializeAcl,
            InitializeSecurityDescriptor, OBJECT_INHERIT_ACE, OWNER_SECURITY_INFORMATION,
            SECURITY_DESCRIPTOR, SECURITY_MAX_SID_SIZE, SetFileSecurityW,
            SetSecurityDescriptorDacl, SetSecurityDescriptorOwner,
        };
        use windows_sys::Win32::Storage::FileSystem::FILE_ALL_ACCESS;
        use windows_sys::Win32::System::SystemServices::SECURITY_DESCRIPTOR_REVISION;

        let user = windows_current_user_sid().expect("current-user SID");
        let mut principal =
            vec![0_u32; (SECURITY_MAX_SID_SIZE as usize).div_ceil(std::mem::size_of::<u32>())];
        let mut principal_size = (principal.len() * std::mem::size_of::<u32>()) as u32;
        // SAFETY: principal is an aligned writable buffer of principal_size
        // bytes; these well-known SID kinds do not require a domain SID.
        assert_ne!(
            unsafe {
                CreateWellKnownSid(
                    sid_kind,
                    std::ptr::null_mut(),
                    principal.as_mut_ptr().cast(),
                    &raw mut principal_size,
                )
            },
            0,
            "create test principal SID: {}",
            io::Error::last_os_error()
        );
        // SAFETY: the current-user wrapper owns a valid live SID.
        let user_size = unsafe { GetLengthSid(user.as_ptr()) } as usize;
        let ace_prefix = std::mem::size_of::<ACCESS_ALLOWED_ACE>() - std::mem::size_of::<u32>();
        let acl_bytes = std::mem::size_of::<ACL>()
            + ace_prefix
            + user_size
            + ace_prefix
            + principal_size as usize;
        let user_ace_flags = if path.is_dir() {
            OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE
        } else {
            0
        };
        let mut acl = vec![0_u32; acl_bytes.div_ceil(std::mem::size_of::<u32>())];
        // SAFETY: acl is DWORD-aligned and provides at least acl_bytes writable bytes.
        assert_ne!(
            unsafe { InitializeAcl(acl.as_mut_ptr().cast(), acl_bytes as u32, ACL_REVISION) },
            0,
            "initialize permissive parent ACL: {}",
            io::Error::last_os_error()
        );
        // Keep the fixture usable and removable by its owner while adding the
        // exact untrusted grant under test.
        assert_ne!(
            unsafe {
                AddAccessAllowedAceEx(
                    acl.as_mut_ptr().cast(),
                    ACL_REVISION,
                    user_ace_flags,
                    FILE_ALL_ACCESS,
                    user.as_ptr(),
                )
            },
            0,
            "add current-user fixture ACE: {}",
            io::Error::last_os_error()
        );
        // SAFETY: acl is initialized and principal contains a valid SID.
        assert_ne!(
            unsafe {
                AddAccessAllowedAceEx(
                    acl.as_mut_ptr().cast(),
                    ACL_REVISION,
                    principal_ace_flags,
                    mask,
                    principal.as_mut_ptr().cast(),
                )
            },
            0,
            "add permissive inheritable parent ACE: {}",
            io::Error::last_os_error()
        );

        let mut descriptor = SECURITY_DESCRIPTOR::default();
        // SAFETY: descriptor is correctly sized writable storage.
        assert_ne!(
            unsafe {
                InitializeSecurityDescriptor(
                    std::ptr::addr_of_mut!(descriptor).cast(),
                    SECURITY_DESCRIPTOR_REVISION,
                )
            },
            0,
            "initialize permissive parent descriptor: {}",
            io::Error::last_os_error()
        );
        // SAFETY: descriptor and acl are initialized and remain live for SetFileSecurityW.
        assert_ne!(
            unsafe {
                SetSecurityDescriptorDacl(
                    std::ptr::addr_of_mut!(descriptor).cast(),
                    TRUE,
                    acl.as_ptr().cast(),
                    0,
                )
            },
            0,
            "attach permissive parent DACL: {}",
            io::Error::last_os_error()
        );
        // Hosted Windows runners can create a user-writable LocalAppData child
        // whose default owner is the Administrators group. These fixtures model
        // the product's accepted user-owned legacy root, so bind that ownership
        // explicitly instead of relying on the runner token's default owner.
        // SAFETY: descriptor is initialized and user owns a valid live SID.
        assert_ne!(
            unsafe {
                SetSecurityDescriptorOwner(
                    std::ptr::addr_of_mut!(descriptor).cast(),
                    user.as_ptr(),
                    0,
                )
            },
            0,
            "attach current-user fixture owner: {}",
            io::Error::last_os_error()
        );
        let mut encoded = path.as_os_str().encode_wide().collect::<Vec<_>>();
        assert!(!encoded.contains(&0), "fixture path contains NUL");
        encoded.push(0);
        // SAFETY: encoded is NUL-terminated and descriptor references the live ACL.
        assert_ne!(
            unsafe {
                SetFileSecurityW(
                    encoded.as_ptr(),
                    DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION,
                    std::ptr::addr_of_mut!(descriptor).cast(),
                )
            },
            0,
            "set permissive parent DACL: {}",
            io::Error::last_os_error()
        );
    }

    #[cfg(windows)]
    fn set_windows_permissive_inheritable_dacl(path: &Path) {
        use windows_sys::Win32::Security::WinWorldSid;
        use windows_sys::Win32::Storage::FileSystem::FILE_ALL_ACCESS;

        set_windows_inheritable_allow_dacl(path, WinWorldSid, FILE_ALL_ACCESS);
    }

    #[cfg(windows)]
    #[test]
    fn windows_canonical_local_app_data_chain_allows_only_its_pinned_capability_layers() {
        let local_app_data = windows_local_app_data_directory()
            .expect("resolve LocalAppData through the Windows known-folder API")
            .canonicalize()
            .expect("canonical LocalAppData");
        let guards = verify_windows_managed_namespace_ancestor_chain(&local_app_data)
            .expect("the canonical LocalAppData chain must accept bounded capability ACLs");
        let identities = windows_local_app_data_ancestor_identities(&guards)
            .expect("inspect canonical LocalAppData identities")
            .expect("chain contains canonical LocalAppData");

        assert_eq!(
            windows_managed_namespace_ancestor_acl_policy(
                identities.local_app_data,
                Some(identities)
            ),
            WindowsManagedNamespaceAncestorAclPolicy::PinnedLocalAppDataCapability
        );
        assert_eq!(
            windows_managed_namespace_ancestor_acl_policy(identities.app_data, Some(identities)),
            WindowsManagedNamespaceAncestorAclPolicy::PinnedLocalAppDataCapability
        );
        assert!(
            guards.len() >= 2,
            "the canonical chain must retain its ancestors"
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn non_windows_parent_bootstrap_is_limited_to_the_known_canonical_product_root() {
        let temporary = tempfile::tempdir().expect("temporary root");
        let platform_local_data = temporary.path().join("missing-platform-local-data");
        let canonical = platform_local_data.join(PRODUCT_DATA_DIRECTORY_NAME);

        ensure_known_canonical_product_data_parent(&canonical, &platform_local_data)
            .expect("bootstrap the known canonical platform parent");
        assert!(platform_local_data.is_dir());

        let arbitrary_parent = temporary.path().join("missing-arbitrary-parent");
        let arbitrary = arbitrary_parent.join("caller-selected-data");
        ensure_known_canonical_product_data_parent(&arbitrary, &platform_local_data)
            .expect("arbitrary roots remain untouched");
        assert!(!arbitrary_parent.exists());
    }

    #[cfg(not(windows))]
    #[test]
    fn non_windows_private_product_root_does_not_create_an_arbitrary_missing_parent() {
        let temporary = tempfile::tempdir().expect("temporary root");
        let arbitrary_parent = temporary.path().join("missing-arbitrary-parent");
        let arbitrary = arbitrary_parent.join("caller-selected-data");

        assert!(ensure_private_product_data_directory(&arbitrary).is_err());
        assert!(!arbitrary_parent.exists());
    }

    #[cfg(windows)]
    #[test]
    fn windows_private_product_data_directory_is_secure_on_first_creation() {
        use windows_sys::Win32::Security::{CONTAINER_INHERIT_ACE, OBJECT_INHERIT_ACE};

        let local_app_data = windows_local_app_data_directory()
            .expect("resolve the canonical LocalAppData test parent");
        let temporary = tempfile::Builder::new()
            .prefix("ai-security-scanner-product-data-test-")
            .tempdir_in(&local_app_data)
            .expect("reserve a unique product-data path");
        fs::remove_dir(temporary.path()).expect("remove the inherited-ACL reservation");

        let guard = ensure_private_product_data_directory(temporary.path())
            .expect("create the product-data root with a protected DACL");
        assert!(
            guard.was_created(),
            "the guard must report that this call won final-component creation"
        );

        let existing_guard = ensure_private_product_data_directory(temporary.path())
            .expect("verify the already-created protected product-data root");
        assert!(
            !existing_guard.was_created(),
            "an existing root must never be treated as empty first-run state"
        );

        let handle = open_windows_real_directory_security_handle(temporary.path())
            .expect("open the new product-data root");
        verify_windows_current_user_only_dacl_with_ace_flags(
            &handle,
            (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE) as u8,
        )
        .expect("new product-data root has the exact protected DACL");

        let renamed = temporary.path().with_extension("replacement-attempt");
        assert!(
            fs::rename(temporary.path(), &renamed).is_err(),
            "the preparation guard must pin the root until lease handoff"
        );
        let lease = crate::process_lease::DataDirectoryExclusiveLease::acquire(temporary.path())
            .expect("acquire the process lease while the preparation guard is live");
        drop(guard);
        drop(existing_guard);
        assert!(
            fs::rename(temporary.path(), &renamed).is_err(),
            "the process lease must keep the exact root pinned after handoff"
        );
        drop(lease);
    }

    #[cfg(windows)]
    #[test]
    fn windows_legacy_existing_product_root_reopens_without_rewriting_its_inherited_dacl() {
        use windows_sys::Win32::Security::WinWorldSid;
        use windows_sys::Win32::Storage::FileSystem::{FILE_GENERIC_EXECUTE, FILE_GENERIC_READ};

        let local_app_data = windows_local_app_data_directory()
            .expect("resolve the canonical LocalAppData test parent");
        let temporary = tempfile::Builder::new()
            .prefix("ai-security-scanner-existing-legacy-test-")
            .tempdir_in(&local_app_data)
            .expect("create ordinary inherited-ACL legacy root");
        let data_root = temporary.path().to_path_buf();
        set_windows_inheritable_allow_dacl(
            &data_root,
            WinWorldSid,
            FILE_GENERIC_READ | FILE_GENERIC_EXECUTE,
        );

        let before_handle = open_windows_real_directory_security_handle(&data_root)
            .expect("open inherited-ACL legacy root");
        let before = windows_owner_dacl_security_descriptor(&before_handle)
            .expect("snapshot inherited legacy ACL");
        let _error = verify_windows_product_data_directory_dacl(&before_handle)
            .expect_err("legacy fixture must not already have the product-created DACL");
        drop(before_handle);

        let guards = verify_windows_existing_product_data_directory(&data_root)
            .expect("a bounded inherited legacy root must reopen without ACL repair");
        assert!(
            !guards.is_empty(),
            "the legacy root and its real ancestor chain must remain pinned"
        );
        drop(guards);

        let after_handle = open_windows_real_directory_security_handle(&data_root)
            .expect("reopen inherited-ACL legacy root");
        let after = windows_owner_dacl_security_descriptor(&after_handle)
            .expect("snapshot legacy ACL after verification");
        assert_eq!(
            after, before,
            "legacy roots must never receive automatic ACL repair"
        );
        assert!(
            verify_windows_product_data_directory_dacl(&after_handle).is_err(),
            "accepted legacy root must retain its inherited non-product ACL shape"
        );
        drop(after_handle);
    }

    #[cfg(windows)]
    #[test]
    fn windows_legacy_product_root_rejects_foreign_write_without_rewriting() {
        use windows_sys::Win32::Security::WinWorldSid;
        use windows_sys::Win32::Storage::FileSystem::FILE_WRITE_DATA;

        let local_app_data = windows_local_app_data_directory()
            .expect("resolve the canonical LocalAppData test parent");
        let temporary = tempfile::Builder::new()
            .prefix("ai-security-scanner-legacy-write-test-")
            .tempdir_in(&local_app_data)
            .expect("create legacy product-data fixture");
        let data_root = temporary.path().to_path_buf();
        set_windows_inheritable_allow_dacl(&data_root, WinWorldSid, FILE_WRITE_DATA);
        let before = windows_test_security_snapshot(
            &open_windows_real_directory_security_handle(&data_root)
                .expect("open foreign-writable legacy root"),
        );

        let error = verify_windows_existing_product_data_directory(&data_root)
            .expect_err("foreign write access must not become legacy compatibility");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(error.to_string().contains("write or replacement rights"));
        assert_eq!(
            windows_test_security_snapshot(
                &open_windows_real_directory_security_handle(&data_root)
                    .expect("reopen foreign-writable legacy root"),
            ),
            before,
            "legacy rejection must not rewrite the root descriptor"
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_legacy_product_root_rejects_inherit_only_foreign_write_without_rewriting() {
        use windows_sys::Win32::Security::{
            CONTAINER_INHERIT_ACE, INHERIT_ONLY_ACE, OBJECT_INHERIT_ACE, WinWorldSid,
        };
        use windows_sys::Win32::Storage::FileSystem::FILE_ALL_ACCESS;

        let local_app_data = windows_local_app_data_directory()
            .expect("resolve the canonical LocalAppData test parent");
        let temporary = tempfile::Builder::new()
            .prefix("ai-security-scanner-legacy-inherit-only-test-")
            .tempdir_in(&local_app_data)
            .expect("create legacy product-data fixture");
        let data_root = temporary.path().to_path_buf();
        set_windows_allow_dacl_with_flags(
            &data_root,
            WinWorldSid,
            FILE_ALL_ACCESS,
            OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE | INHERIT_ONLY_ACE,
        );
        let before = windows_test_security_snapshot(
            &open_windows_real_directory_security_handle(&data_root)
                .expect("open inherit-only foreign-writable legacy root"),
        );

        let error = verify_windows_existing_product_data_directory(&data_root)
            .expect_err("foreign inherited write access must fail closed");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(error.to_string().contains("write or replacement rights"));
        assert_eq!(
            windows_test_security_snapshot(
                &open_windows_real_directory_security_handle(&data_root)
                    .expect("reopen inherit-only foreign-writable legacy root"),
            ),
            before,
            "inherit-only rejection must not rewrite the root descriptor"
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_private_product_data_directory_rejects_existing_unsafe_acl_without_rewriting() {
        let temporary = managed_runtime_fixture_tempdir();
        let data_root = temporary.path().join("existing-product-data");
        fs::create_dir(&data_root).expect("existing product-data root");
        set_windows_permissive_inheritable_dacl(&data_root);
        let before_handle =
            open_windows_real_directory_security_handle(&data_root).expect("open unsafe root");
        let before = windows_owner_dacl_security_descriptor(&before_handle)
            .expect("snapshot unsafe root ACL");
        drop(before_handle);

        let error = ensure_private_product_data_directory(&data_root)
            .expect_err("existing unsafe product-data root must fail closed");
        assert!(matches!(error, AppError::NotAuthorized(_)));

        let after_handle =
            open_windows_real_directory_security_handle(&data_root).expect("reopen unsafe root");
        let after = windows_owner_dacl_security_descriptor(&after_handle)
            .expect("snapshot root ACL after rejection");
        assert_eq!(after, before, "rejection must not rewrite existing ACLs");
    }

    #[cfg(windows)]
    #[test]
    fn windows_unsafe_existing_product_root_rejects_without_rewriting_descendants() {
        use std::os::windows::fs::symlink_file;
        use windows_sys::Win32::Foundation::ERROR_PRIVILEGE_NOT_HELD;

        let temporary = managed_runtime_fixture_tempdir();
        let data_root = temporary.path().join("canonical-product-data-fixture");
        fs::create_dir(&data_root).expect("existing product-data fixture");
        set_windows_permissive_inheritable_dacl(&data_root);

        let ordinary = data_root.join("existing-child.txt");
        fs::write(&ordinary, b"existing child").expect("ordinary child");
        let ordinary_before = windows_test_security_snapshot(&File::open(&ordinary).unwrap());

        let outside_hardlink = temporary.path().join("outside-hardlink.txt");
        fs::write(&outside_hardlink, b"outside hardlink object").expect("outside hardlink");
        let inside_hardlink = data_root.join("existing-hardlink.txt");
        fs::hard_link(&outside_hardlink, &inside_hardlink).expect("inside hardlink name");
        let outside_hardlink_before =
            windows_test_security_snapshot(&File::open(&outside_hardlink).unwrap());
        let inside_hardlink_before =
            windows_test_security_snapshot(&File::open(&inside_hardlink).unwrap());

        let outside_symlink_target = temporary.path().join("outside-symlink-target.txt");
        fs::write(&outside_symlink_target, b"outside symlink target").expect("symlink target");
        let inside_symlink = data_root.join("existing-symlink.txt");
        let symlink_before = match symlink_file(&outside_symlink_target, &inside_symlink) {
            Ok(()) => Some(windows_test_security_snapshot(
                &windows_test_nofollow_security_file(&inside_symlink),
            )),
            Err(error) if error.raw_os_error() == Some(ERROR_PRIVILEGE_NOT_HELD as i32) => {
                eprintln!("skipping symlink portion: host lacks symbolic-link privilege");
                None
            }
            Err(error) => panic!("create file symlink: {error}"),
        };
        let symlink_target_before =
            windows_test_security_snapshot(&File::open(&outside_symlink_target).unwrap());
        let root_before = windows_test_security_snapshot(
            &open_windows_real_directory_security_handle(&data_root).expect("open unsafe root"),
        );

        let error = verify_windows_existing_product_data_directory(&data_root)
            .expect_err("an unsafe existing root must fail closed");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);

        assert_eq!(
            windows_test_security_snapshot(
                &open_windows_real_directory_security_handle(&data_root)
                    .expect("reopen unsafe root")
            ),
            root_before,
            "rejection must preserve the unsafe root's identity and descriptor"
        );

        assert_eq!(
            windows_test_security_snapshot(&File::open(&ordinary).unwrap()),
            ordinary_before,
            "rejection must preserve an ordinary existing child's identity and descriptor"
        );
        assert_eq!(
            windows_test_security_snapshot(&File::open(&outside_hardlink).unwrap()),
            outside_hardlink_before,
            "rejection must not change an outside object through an inside hardlink"
        );
        assert_eq!(
            windows_test_security_snapshot(&File::open(&inside_hardlink).unwrap()),
            inside_hardlink_before,
            "rejection must preserve the inside hardlink name's identity and descriptor"
        );
        if let Some(symlink_before) = symlink_before {
            assert_eq!(
                windows_test_security_snapshot(&windows_test_nofollow_security_file(
                    &inside_symlink,
                )),
                symlink_before,
                "rejection must preserve the existing reparse point"
            );
        }
        assert_eq!(
            windows_test_security_snapshot(&File::open(&outside_symlink_target).unwrap()),
            symlink_target_before,
            "rejection must not reach an outside reparse target"
        );
        assert!(
            verify_windows_product_data_directory_dacl(
                &open_windows_real_directory_security_handle(&data_root)
                    .expect("inspect retained unsafe root")
            )
            .is_err(),
            "rejection must retain the root's unsafe ACL for explicit recovery"
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_canonical_product_data_path_matches_the_tauri_identifier_leaf() {
        let expected = windows_local_app_data_directory()
            .expect("LocalAppData")
            .join(PRODUCT_DATA_DIRECTORY_NAME);
        assert!(
            windows_is_canonical_product_data_directory(&expected)
                .expect("validate canonical product-data path")
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_pinned_local_app_data_policy_accepts_a_capability_replacement_ace() {
        use windows_sys::Win32::Security::WinCapabilityInternetClientSid;
        use windows_sys::Win32::Storage::FileSystem::FILE_ALL_ACCESS;

        let temp = TempDir::new().expect("temporary root");
        let ancestor = temp.path().join("pinned-local-app-data-ancestor");
        fs::create_dir(&ancestor).expect("test ancestor");
        let handle = open_windows_real_directory_security_handle(&ancestor)
            .expect("open capability-protected ancestor before replacing its DACL");
        set_windows_inheritable_allow_dacl(
            &ancestor,
            WinCapabilityInternetClientSid,
            FILE_ALL_ACCESS,
        );

        verify_windows_managed_namespace_ancestor_handle(
            &handle,
            false,
            WindowsManagedNamespaceAncestorAclPolicy::PinnedLocalAppDataCapability,
        )
        .expect("a pinned LocalAppData capability ACE is compatible");
    }

    #[cfg(windows)]
    #[test]
    fn windows_capability_replacement_ace_on_an_arbitrary_ancestor_is_rejected() {
        use windows_sys::Win32::Security::WinCapabilityInternetClientSid;
        use windows_sys::Win32::Storage::FileSystem::FILE_ALL_ACCESS;

        let temp = TempDir::new().expect("temporary root");
        let ancestor = temp.path().join("arbitrary-capability-ancestor");
        fs::create_dir(&ancestor).expect("test ancestor");
        let handle = open_windows_real_directory_security_handle(&ancestor)
            .expect("open arbitrary capability ancestor before replacing its DACL");
        set_windows_inheritable_allow_dacl(
            &ancestor,
            WinCapabilityInternetClientSid,
            FILE_ALL_ACCESS,
        );

        let error = verify_windows_managed_namespace_ancestor_handle(
            &handle,
            false,
            WindowsManagedNamespaceAncestorAclPolicy::Strict,
        )
        .expect_err("the same capability ACE outside canonical LocalAppData must fail closed");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(error.to_string().contains("replacement rights"));
    }

    #[cfg(windows)]
    #[test]
    fn windows_read_execute_principal_is_not_a_namespace_replacement_grant() {
        use windows_sys::Win32::Security::WinWorldSid;
        use windows_sys::Win32::Storage::FileSystem::{FILE_GENERIC_EXECUTE, FILE_GENERIC_READ};

        let temp = TempDir::new().expect("temporary root");
        let ancestor = temp.path().join("read-only-ancestor");
        fs::create_dir(&ancestor).expect("test ancestor");
        set_windows_inheritable_allow_dacl(
            &ancestor,
            WinWorldSid,
            FILE_GENERIC_READ | FILE_GENERIC_EXECUTE,
        );
        let handle = open_windows_real_directory_security_handle(&ancestor)
            .expect("open read-only ancestor");

        verify_windows_managed_namespace_ancestor_handle(
            &handle,
            false,
            WindowsManagedNamespaceAncestorAclPolicy::Strict,
        )
        .expect("read/execute does not permit namespace replacement");
    }

    #[cfg(windows)]
    #[test]
    fn windows_writable_arbitrary_principal_remains_rejected() {
        let temp = TempDir::new().expect("temporary root");
        let ancestor = temp.path().join("writable-arbitrary-ancestor");
        fs::create_dir(&ancestor).expect("test ancestor");
        set_windows_permissive_inheritable_dacl(&ancestor);
        let handle = open_windows_real_directory_security_handle(&ancestor)
            .expect("open writable arbitrary ancestor");

        let error = verify_windows_managed_namespace_ancestor_handle(
            &handle,
            false,
            WindowsManagedNamespaceAncestorAclPolicy::Strict,
        )
        .expect_err("a writable arbitrary principal must fail closed");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(error.to_string().contains("replacement rights"));
    }

    #[cfg(windows)]
    #[test]
    fn windows_local_app_data_capability_policy_does_not_extend_to_descendants() {
        let temp = TempDir::new().expect("temporary root");
        let product = temp.path().join("product");
        let state = product.join("managed-runtime");
        fs::create_dir_all(&state).expect("product state descendants");
        let product_handle =
            open_windows_real_directory_security_handle(&product).expect("open product root");
        let state_handle =
            open_windows_real_directory_security_handle(&state).expect("open state root");
        let identities = windows_current_local_app_data_ancestor_identities()
            .expect("resolve canonical LocalAppData identities");

        for handle in [&product_handle, &state_handle] {
            assert_eq!(
                windows_managed_namespace_ancestor_acl_policy(
                    windows_file_information(handle)
                        .expect("descendant identity")
                        .identity,
                    Some(identities),
                ),
                WindowsManagedNamespaceAncestorAclPolicy::Strict,
                "app-owned descendants must never receive the capability exception"
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_manager_rejects_a_replaceable_data_root_without_rewriting_its_acl() {
        let temp = TempDir::new().expect("temporary root");
        let data_root = temp.path().join("user-selected-data-root");
        fs::create_dir(&data_root).expect("data root");
        set_windows_permissive_inheritable_dacl(&data_root);

        let before_handle =
            open_windows_real_directory_security_handle(&data_root).expect("open data root");
        let before = windows_owner_dacl_security_descriptor(&before_handle)
            .expect("snapshot permissive data-root ACL");
        drop(before_handle);

        let state_root = data_root.join("managed-runtime");
        let error = ManagedRuntimeManager::open(
            &data_root,
            temp.path(),
            &temp.path().join("unreachable-manifest.json"),
        )
        .expect_err("replaceable caller-owned data root must fail closed in the constructor");
        assert!(matches!(error, AppError::NotAuthorized(_)));
        assert!(!state_root.exists());

        let after_handle =
            open_windows_real_directory_security_handle(&data_root).expect("reopen data root");
        let after = windows_owner_dacl_security_descriptor(&after_handle)
            .expect("snapshot data-root ACL after rejection");
        assert_eq!(
            after, before,
            "constructor rejection must not rewrite the caller-owned data root"
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_directory_guards_block_replacement_until_release() {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{
            DELETE, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE,
            FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TRAVERSE,
        };

        let temp = TempDir::new().expect("temporary root");
        let directory = temp.path().join("raw-directory-guard");
        fs::create_dir(&directory).expect("raw guarded directory");
        let renamed = temp.path().join("raw-directory-renamed");
        let guard = open_windows_real_directory_security_handle(&directory)
            .expect("open first real-directory guard");
        let compatible_guard = open_windows_real_directory_security_handle(&directory)
            .expect("a second read-category guard remains compatible");
        let delete_error = OpenOptions::new()
            .access_mode(FILE_TRAVERSE | DELETE)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&directory)
            .expect_err("the real-directory guard must reject delete access");
        assert!(windows_error_is_sharing_violation(&delete_error));
        assert!(fs::rename(&directory, &renamed).is_err());

        drop(compatible_guard);
        drop(guard);
        fs::rename(&directory, &renamed).expect("rename after real-directory guard release");
        fs::rename(&renamed, &directory).expect("restore raw guarded directory name");

        let managed = temp.path().join("managed-directory-guard");
        let managed_renamed = temp.path().join("managed-directory-renamed");
        let (_, managed_guard) =
            open_or_create_windows_managed_private_directory_guard(&managed, false)
                .expect("create managed-directory guard");
        assert!(fs::rename(&managed, &managed_renamed).is_err());
        drop(managed_guard);
        fs::rename(&managed, &managed_renamed)
            .expect("rename after managed-directory guard release");
    }

    #[cfg(windows)]
    #[test]
    fn windows_state_root_guard_pins_a_canonical_protected_directory() {
        use windows_sys::Win32::Security::{CONTAINER_INHERIT_ACE, OBJECT_INHERIT_ACE};
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
        };

        let temp = managed_runtime_fixture_tempdir();
        let data_root = temp.path().join("ordinary-data-root");
        fs::create_dir(&data_root).expect("ordinary data root");
        let requested_state_root = data_root.join("managed-runtime");

        let (canonical_state_root, guard) =
            open_or_create_windows_managed_private_directory_guard(&requested_state_root, true)
                .expect("create canonical protected state-root guard");

        assert_eq!(
            canonical_state_root,
            requested_state_root
                .canonicalize()
                .expect("canonical state root")
        );
        let information = windows_file_information(&guard).expect("guard information");
        assert_ne!(information.attributes & FILE_ATTRIBUTE_DIRECTORY, 0);
        assert_eq!(information.attributes & FILE_ATTRIBUTE_REPARSE_POINT, 0);
        verify_windows_current_user_only_dacl_with_ace_flags(
            &guard,
            (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE) as u8,
        )
        .expect("guarded state root has the exact protected DACL");
    }

    #[cfg(windows)]
    #[test]
    fn windows_runtime_command_precreates_the_exact_private_podman_machine_namespace() {
        use windows_sys::Win32::Security::{CONTAINER_INHERIT_ACE, OBJECT_INHERIT_ACE};

        let fixture = fixture();
        fixture.manager.install().expect("install");
        let target = fixture.manager.loaded.target().expect("target");
        assert_eq!(target.operating_system, ManagedOperatingSystem::Windows);

        fixture
            .manager
            .runtime_command(target)
            .expect("prepare managed command namespace");

        assert!(
            fixture.commands.calls().is_empty(),
            "namespace must be complete before the first provider command"
        );
        let provider_home = fixture.manager.provider_home();
        let identity_parent = fixture
            .manager
            .machine_ssh_identity_path()
            .parent()
            .expect("identity parent")
            .to_path_buf();
        let config = provider_home.join("config");
        let data = provider_home.join("data");
        let machine_provider_data = data
            .join("containers")
            .join("podman")
            .join("machine")
            .join(target.provider.argument());
        let expected = [
            provider_home.clone(),
            provider_home.join("cache"),
            provider_home.join("run"),
            provider_home.join("run").join("podman"),
            config.clone(),
            config.join("containers"),
            config.join("containers").join("podman"),
            config.join("containers").join("podman").join("machine"),
            config
                .join("containers")
                .join("podman")
                .join("machine")
                .join(target.provider.argument()),
            data.clone(),
            data.join("containers"),
            data.join("containers").join("podman"),
            identity_parent,
            machine_provider_data.clone(),
            machine_provider_data.join("cache"),
        ];
        let inheritance = u8::try_from(OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE)
            .expect("inheritance flags fit in an ACE header");
        for directory in expected {
            let handle = open_windows_real_directory_security_handle(&directory)
                .unwrap_or_else(|error| panic!("open {}: {error}", directory.display()));
            verify_windows_current_user_only_dacl_with_ace_flags(&handle, inheritance)
                .unwrap_or_else(|error| panic!("verify {}: {error}", directory.display()));
        }

        let distribution_storage =
            machine_provider_data.join(PODMAN_WSL_DISTRIBUTION_STORAGE_DIRECTORY);
        let distribution_storage_handle =
            open_windows_real_directory_security_handle(&distribution_storage)
                .unwrap_or_else(|error| panic!("open {}: {error}", distribution_storage.display()));
        verify_windows_wsl_distribution_storage_dacl_with_ace_flags(
            &distribution_storage_handle,
            inheritance,
        )
        .unwrap_or_else(|error| panic!("verify {}: {error}", distribution_storage.display()));
        assert!(
            verify_windows_current_user_only_dacl_with_ace_flags(
                &distribution_storage_handle,
                inheritance,
            )
            .is_err(),
            "WSL distribution storage must have the narrow LocalSystem exception"
        );
        assert!(
            !private_entry_exists(&distribution_storage.join(machine_name(target))).unwrap(),
            "the product must leave the per-machine import target for WSL to create"
        );
    }

    #[cfg(unix)]
    #[test]
    fn direct_command_timeout_bounds_inherited_pipes_and_terminates_the_process_group() {
        let temp = TempDir::new().expect("temporary root");
        let pid_file = temp.path().join("descendant.pid");
        let command = direct_unix_test_command(
            temp.path(),
            BTreeMap::from([(OsString::from("PID_FILE"), pid_file.as_os_str().to_owned())]),
        );
        let args = [
            OsString::from("-c"),
            OsString::from(
                "/bin/sleep 30 & child=$!; printf '%s' \"$child\" > \"$PID_FILE\"; wait",
            ),
        ];
        let started = Instant::now();

        let error = DirectManagedCommandRunner
            .output(&command, &args, Duration::from_millis(250))
            .expect_err("inherited pipes must not outlive the command deadline");

        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(error.to_string().contains("command exceeded its deadline"));
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "bounded post-kill drain must return promptly"
        );
        let pid = fs::read_to_string(pid_file)
            .expect("descendant pid")
            .parse::<i32>()
            .expect("numeric descendant pid");
        assert_unix_process_is_reaped(pid);
    }

    #[cfg(unix)]
    #[test]
    fn direct_command_bounds_a_pipe_inherited_after_the_leader_exits() {
        let temp = TempDir::new().expect("temporary root");
        let pid_file = temp.path().join("descendant.pid");
        let command = direct_unix_test_command(
            temp.path(),
            BTreeMap::from([(OsString::from("PID_FILE"), pid_file.as_os_str().to_owned())]),
        );
        let args = [
            OsString::from("-c"),
            OsString::from("/bin/sleep 30 & child=$!; printf '%s' \"$child\" > \"$PID_FILE\""),
        ];
        let started = Instant::now();

        let error = DirectManagedCommandRunner
            .output(&command, &args, Duration::from_millis(250))
            .expect_err("a successful leader must not leave inherited pipes unbounded");

        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(error.to_string().contains("output pipes did not close"));
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "inherited-pipe cleanup must remain bounded"
        );
        let pid = fs::read_to_string(pid_file)
            .expect("descendant pid")
            .parse::<i32>()
            .expect("numeric descendant pid");
        assert_unix_process_is_reaped(pid);
    }

    #[cfg(unix)]
    #[test]
    fn managed_memory_capture_never_joins_a_pipe_with_a_live_writer() {
        use std::os::unix::net::UnixStream;

        let (reader, writer) = UnixStream::pair().expect("capture pipe pair");
        let mut capture = spawn_bounded_capture(
            reader,
            Arc::new(AtomicU64::new(0)),
            Arc::new(AtomicBool::new(false)),
            1024,
        );
        let started = Instant::now();

        let error = capture
            .finish_by(Instant::now() + Duration::from_millis(100))
            .expect_err("live inherited writer must hit the bounded drain deadline");

        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(started.elapsed() < Duration::from_secs(1));
        drop(writer);
        assert_eq!(
            capture
                .finish_by(Instant::now() + Duration::from_secs(1))
                .expect("capture must join after its writer closes"),
            Vec::<u8>::new()
        );
        assert!(capture.worker.is_none());
    }

    #[cfg(windows)]
    enum FakeCommandSideEffect {
        CreateManagedWslVhd { path: PathBuf, bytes: Vec<u8> },
        ReplaceFileWithDirectory { path: PathBuf },
        WriteFile { path: PathBuf, bytes: Vec<u8> },
    }

    struct FakeCommandResponse {
        output: ManagedCommandOutput,
        delay: Duration,
        #[cfg(windows)]
        side_effect: Option<FakeCommandSideEffect>,
    }

    #[derive(Default)]
    struct FakeCommands {
        calls: Mutex<Vec<Vec<String>>>,
        commands: Mutex<Vec<ManagedRuntimeCommand>>,
        timeouts: Mutex<Vec<Duration>>,
        outputs: Mutex<VecDeque<FakeCommandResponse>>,
    }

    #[derive(Default)]
    struct DeadlineFailingCommands {
        calls: Mutex<Vec<Vec<String>>>,
        timeouts: Mutex<Vec<Duration>>,
    }

    impl ManagedCommandRunner for DeadlineFailingCommands {
        fn output(
            &self,
            _command: &ManagedRuntimeCommand,
            args: &[OsString],
            timeout: Duration,
        ) -> io::Result<ManagedCommandOutput> {
            self.calls.lock().expect("calls").push(
                args.iter()
                    .map(|value| value.to_string_lossy().into_owned())
                    .collect(),
            );
            self.timeouts.lock().expect("timeouts").push(timeout);
            Err(managed_command_deadline_error())
        }
    }

    impl FakeCommands {
        fn push(&self, output: ManagedCommandOutput) {
            self.outputs
                .lock()
                .expect("outputs")
                .push_back(FakeCommandResponse {
                    output,
                    delay: Duration::ZERO,
                    #[cfg(windows)]
                    side_effect: None,
                });
        }

        fn push_with_delay(&self, output: ManagedCommandOutput, delay: Duration) {
            self.outputs
                .lock()
                .expect("outputs")
                .push_back(FakeCommandResponse {
                    output,
                    delay,
                    #[cfg(windows)]
                    side_effect: None,
                });
        }

        #[cfg(windows)]
        fn push_with_side_effect(
            &self,
            output: ManagedCommandOutput,
            side_effect: FakeCommandSideEffect,
        ) {
            self.outputs
                .lock()
                .expect("outputs")
                .push_back(FakeCommandResponse {
                    output,
                    delay: Duration::ZERO,
                    side_effect: Some(side_effect),
                });
        }

        fn calls(&self) -> Vec<Vec<String>> {
            self.calls.lock().expect("calls").clone()
        }

        #[cfg(windows)]
        fn commands(&self) -> Vec<ManagedRuntimeCommand> {
            self.commands.lock().expect("commands").clone()
        }

        fn timeouts(&self) -> Vec<Duration> {
            self.timeouts.lock().expect("timeouts").clone()
        }
    }

    impl ManagedCommandRunner for FakeCommands {
        fn output(
            &self,
            command: &ManagedRuntimeCommand,
            args: &[OsString],
            timeout: Duration,
        ) -> io::Result<ManagedCommandOutput> {
            self.calls.lock().expect("calls").push(
                args.iter()
                    .map(|value| value.to_string_lossy().into_owned())
                    .collect(),
            );
            self.commands
                .lock()
                .expect("commands")
                .push(command.clone());
            self.timeouts.lock().expect("timeouts").push(timeout);
            let response = self
                .outputs
                .lock()
                .expect("outputs")
                .pop_front()
                .ok_or_else(|| io::Error::other("no fake output"))?;
            if !response.delay.is_zero() {
                thread::sleep(response.delay);
            }
            #[cfg(windows)]
            if let Some(effect) = response.side_effect {
                match effect {
                    FakeCommandSideEffect::CreateManagedWslVhd { path, bytes } => {
                        let parent = path.parent().ok_or_else(|| {
                            io::Error::new(io::ErrorKind::InvalidInput, "fake VHD has no parent")
                        })?;
                        ensure_managed_wsl_distribution_storage_directory(parent)?;
                        fs::write(path, bytes)?;
                    }
                    FakeCommandSideEffect::ReplaceFileWithDirectory { path } => {
                        fs::remove_file(&path)?;
                        fs::create_dir(&path)?;
                    }
                    FakeCommandSideEffect::WriteFile { path, bytes } => {
                        fs::write(path, bytes)?;
                    }
                }
            }
            Ok(response.output)
        }
    }

    enum FakeWindowsWslPrerequisiteRepairResponse {
        Result(ManagedRuntimePrerequisiteRepairResult),
        Error,
    }

    struct FakeWindowsWslPrerequisiteRepairer {
        responses: Mutex<VecDeque<FakeWindowsWslPrerequisiteRepairResponse>>,
        actions: Mutex<Vec<ManagedRuntimeSetupNextAction>>,
        lifecycle_lock_path: Option<PathBuf>,
    }

    impl FakeWindowsWslPrerequisiteRepairer {
        fn new(responses: Vec<FakeWindowsWslPrerequisiteRepairResponse>) -> Self {
            Self {
                responses: Mutex::new(responses.into()),
                actions: Mutex::new(Vec::new()),
                lifecycle_lock_path: None,
            }
        }

        fn with_lifecycle_lock_probe(mut self, path: PathBuf) -> Self {
            self.lifecycle_lock_path = Some(path);
            self
        }

        fn actions(&self) -> Vec<ManagedRuntimeSetupNextAction> {
            self.actions.lock().expect("repair actions").clone()
        }
    }

    impl WindowsWslPrerequisiteRepairer for FakeWindowsWslPrerequisiteRepairer {
        fn repair(
            &self,
            action: ManagedRuntimeSetupNextAction,
        ) -> AppResult<ManagedRuntimePrerequisiteRepairResult> {
            self.actions.lock().expect("repair actions").push(action);
            let _lock_probe = if let Some(path) = &self.lifecycle_lock_path {
                let file = open_nofollow_lock_file(path)?;
                fs2::FileExt::try_lock_exclusive(&file).map_err(|_| {
                    AppError::Runtime(
                        "the managed runtime lifecycle lock remained held during Windows setup"
                            .into(),
                    )
                })?;
                Some(file)
            } else {
                None
            };
            match self
                .responses
                .lock()
                .expect("repair responses")
                .pop_front()
                .expect("one repair response")
            {
                FakeWindowsWslPrerequisiteRepairResponse::Result(result) => Ok(result),
                FakeWindowsWslPrerequisiteRepairResponse::Error => Err(AppError::Runtime(
                    "injected Windows prerequisite repair failure".into(),
                )),
            }
        }
    }

    struct FixedWindowsWslRegistrations(Vec<WindowsWslRegistration>);

    impl WindowsWslRegistrationReader for FixedWindowsWslRegistrations {
        fn registrations(&self) -> AppResult<Vec<WindowsWslRegistration>> {
            Ok(self.0.clone())
        }
    }

    #[cfg(windows)]
    struct SequencedWindowsWslRegistrationInventories(
        Mutex<VecDeque<WindowsWslRegistrationInventory>>,
    );

    #[cfg(windows)]
    impl WindowsWslRegistrationReader for SequencedWindowsWslRegistrationInventories {
        fn registrations(&self) -> AppResult<Vec<WindowsWslRegistration>> {
            let inventory = self.inventory()?;
            if inventory.complete {
                Ok(inventory.registrations)
            } else {
                Err(AppError::NotAvailable(
                    "injected incomplete WSL registration inventory".into(),
                ))
            }
        }

        fn inventory(&self) -> AppResult<WindowsWslRegistrationInventory> {
            let mut snapshots = self.0.lock().expect("WSL registration inventories");
            let snapshot = snapshots
                .front()
                .cloned()
                .unwrap_or_else(WindowsWslRegistrationInventory::default);
            if snapshots.len() > 1 {
                snapshots.pop_front();
            }
            Ok(snapshot)
        }
    }

    #[cfg(windows)]
    struct FailingWindowsWslRegistrations;

    #[cfg(windows)]
    impl WindowsWslRegistrationReader for FailingWindowsWslRegistrations {
        fn registrations(&self) -> AppResult<Vec<WindowsWslRegistration>> {
            Err(AppError::Internal(
                "injected transient WSL registration reader failure".into(),
            ))
        }
    }

    #[cfg(windows)]
    struct SequencedWindowsWslRegistrations(Mutex<VecDeque<Vec<WindowsWslRegistration>>>);

    #[cfg(windows)]
    impl WindowsWslRegistrationReader for SequencedWindowsWslRegistrations {
        fn registrations(&self) -> AppResult<Vec<WindowsWslRegistration>> {
            let mut snapshots = self.0.lock().expect("WSL registration snapshots");
            if snapshots.len() > 1 {
                Ok(snapshots.pop_front().expect("one WSL snapshot"))
            } else {
                snapshots.front().cloned().ok_or_else(|| {
                    AppError::Internal("no fake Windows WSL registration snapshot".into())
                })
            }
        }
    }

    #[cfg(windows)]
    struct WindowsWslRegistrationAfterVhdExists {
        registration: WindowsWslRegistration,
        vhd: PathBuf,
    }

    #[cfg(windows)]
    impl WindowsWslRegistrationReader for WindowsWslRegistrationAfterVhdExists {
        fn registrations(&self) -> AppResult<Vec<WindowsWslRegistration>> {
            if self.vhd.is_file() {
                Ok(vec![self.registration.clone()])
            } else {
                Ok(Vec::new())
            }
        }
    }

    #[cfg(windows)]
    struct PartialWindowsWslRegistrationAfterVhdExists {
        registration: WindowsWslRegistration,
        vhd: PathBuf,
    }

    #[cfg(windows)]
    impl WindowsWslRegistrationReader for PartialWindowsWslRegistrationAfterVhdExists {
        fn registrations(&self) -> AppResult<Vec<WindowsWslRegistration>> {
            Err(AppError::NotAvailable(
                "injected unrelated malformed WSL registration entry".into(),
            ))
        }

        fn inventory(&self) -> AppResult<WindowsWslRegistrationInventory> {
            let mut observed_distribution_names = vec!["Malformed-Unrelated-Entry".into()];
            let registrations = if self.vhd.is_file() {
                observed_distribution_names.push(self.registration.distribution_name.clone());
                vec![self.registration.clone()]
            } else {
                Vec::new()
            };
            Ok(WindowsWslRegistrationInventory {
                registrations,
                observed_distribution_names,
                complete: false,
            })
        }
    }

    #[cfg(windows)]
    struct WindowsWslRegistrationsForExistingPaths(Vec<(PathBuf, WindowsWslRegistration)>);

    #[cfg(windows)]
    impl WindowsWslRegistrationReader for WindowsWslRegistrationsForExistingPaths {
        fn registrations(&self) -> AppResult<Vec<WindowsWslRegistration>> {
            Ok(self
                .0
                .iter()
                .filter(|(path, _)| path.is_file())
                .map(|(_, registration)| registration.clone())
                .collect())
        }
    }

    struct FakeDownloader {
        bytes: Vec<u8>,
        calls: Mutex<usize>,
    }

    impl ManagedArtifactDownloader for FakeDownloader {
        fn acquire(
            &self,
            image: &ManagedMachineImage,
            destination: &Path,
            progress: &mut dyn FnMut(u64, u64, u64) -> AppResult<()>,
        ) -> AppResult<()> {
            *self.calls.lock().expect("calls") += 1;
            let mut file = open_private_download_file(destination, false)?;
            file.write_all(&self.bytes)?;
            file.sync_all()?;
            progress(self.bytes.len() as u64, image.size_bytes, 0)?;
            Ok(())
        }
    }

    struct Fixture {
        manager: ManagedRuntimeManager,
        // Drop the manager's Windows namespace guard before TempDir removes
        // the fixture tree.
        _temp: TempDir,
        commands: Arc<FakeCommands>,
        #[cfg(windows)]
        downloader: Arc<FakeDownloader>,
        image: Vec<u8>,
    }

    #[cfg(windows)]
    fn managed_runtime_fixture_tempdir() -> TempDir {
        let local_app_data = windows_local_app_data_directory()
            .expect("resolve the canonical LocalAppData test parent");
        let temp = tempfile::Builder::new()
            .prefix("ai-security-scanner-managed-runtime-test-")
            .tempdir_in(&local_app_data)
            .expect("create a unique LocalAppData test directory");
        let parent = temp
            .path()
            .parent()
            .expect("test directory has a LocalAppData parent")
            .canonicalize()
            .expect("canonicalize the test directory parent");
        assert_eq!(
            parent,
            local_app_data
                .canonicalize()
                .expect("canonicalize LocalAppData"),
            "the removable empty fixture directory must be directly beneath LocalAppData"
        );
        fs::remove_dir(temp.path()).expect("remove the empty inherited-ACL fixture directory");
        let (_, guard) = open_or_create_windows_managed_private_directory_guard(temp.path(), true)
            .expect("recreate the fixture root with the product's protected DACL");
        drop(guard);
        temp
    }

    #[cfg(not(windows))]
    fn managed_runtime_fixture_tempdir() -> TempDir {
        tempfile::tempdir().expect("temp")
    }

    #[cfg(all(unix, target_os = "linux"))]
    impl Drop for Fixture {
        fn drop(&mut self) {
            if let Ok(runtime) = self.manager.linux_short_runtime_directory() {
                let _ = remove_linux_short_runtime_directory_at(
                    &runtime,
                    Path::new(LINUX_SHORT_RUNTIME_BASE),
                    effective_uid(),
                );
            }
        }
    }

    fn fixture() -> Fixture {
        let temp = managed_runtime_fixture_tempdir();
        let resources = temp.path().join("resources");
        let app_data = temp.path().join("app-data");
        fs::create_dir(&app_data).expect("app data");
        let state = app_data.join("managed-runtime");
        fs::create_dir(&resources).expect("resources");
        let bin = resources.join("bin");
        fs::create_dir(&bin).expect("bin");
        let driver = bin.join("podman");
        fs::write(&driver, b"managed-podman-driver").expect("driver");
        let image = b"pinned-machine-image".to_vec();
        let operating_system = ManagedOperatingSystem::current().expect("supported test OS");
        let architecture = ManagedArchitecture::current().expect("supported test arch");
        let provider = match operating_system {
            ManagedOperatingSystem::Linux => ManagedMachineProvider::Qemu,
            ManagedOperatingSystem::Macos => ManagedMachineProvider::Applehv,
            ManagedOperatingSystem::Windows => ManagedMachineProvider::Wsl,
        };
        let manifest = ManagedRuntimeManifest {
            schema_version: MANIFEST_SCHEMA_VERSION.into(),
            management_contract_revision: Some(MANAGEMENT_CONTRACT_REVISION.into()),
            bundle_id: "podman-machine".into(),
            runtime_version: "5.8.2".into(),
            driver_path: "bin/podman".into(),
            files: vec![ManagedRuntimeFile {
                path: "bin/podman".into(),
                sha256: sha256_bytes(b"managed-podman-driver"),
                size_bytes: b"managed-podman-driver".len() as u64,
                executable: true,
            }],
            components: vec![
                ManagedRuntimeComponent {
                    id: "podman".into(),
                    name: "Podman remote client".into(),
                    version: "5.8.2".into(),
                    repository_url: "https://github.com/containers/podman".into(),
                    source_revision: "5b263b5".into(),
                    license_spdx: "Apache-2.0".into(),
                    relationship: "Bundled rootless machine client".into(),
                    artifacts: vec![ManagedRuntimeComponentArtifact {
                        delivery: ManagedRuntimeArtifactDelivery::BundledFile,
                        locator: "bin/podman".into(),
                        sha256: sha256_bytes(b"managed-podman-driver"),
                        size_bytes: b"managed-podman-driver".len() as u64,
                    }],
                    source_archive: None,
                },
                ManagedRuntimeComponent {
                    id: "podman-machine-os".into(),
                    name: "Podman machine OS".into(),
                    version: "5.8.2".into(),
                    repository_url: "https://github.com/containers/podman-machine-os".into(),
                    source_revision: "08298cbc1d1d5440fb0f071470b35abc37d31050".into(),
                    license_spdx: "Apache-2.0".into(),
                    relationship: "Pinned VM image downloaded on first setup".into(),
                    artifacts: vec![ManagedRuntimeComponentArtifact {
                        delivery: ManagedRuntimeArtifactDelivery::RuntimeDownload,
                        locator: "https://github.com/podman-container-tools/podman-machine-os/releases/download/v5.8.2/machine.zst".into(),
                        sha256: sha256_bytes(&image),
                        size_bytes: image.len() as u64,
                    }],
                    source_archive: None,
                },
            ],
            targets: vec![ManagedTarget {
                operating_system,
                architecture,
                provider,
                machine_image: ManagedMachineImage {
                    url: "https://github.com/podman-container-tools/podman-machine-os/releases/download/v5.8.2/machine.zst".into(),
                    sha256: sha256_bytes(&image),
                    size_bytes: image.len() as u64,
                },
                prerequisite: None,
            }],
            resources: ManagedMachineResources {
                cpus: 2,
                memory_mb: 4096,
                disk_size_gb: 40,
            },
            source: ManagedRuntimeSource {
                repository_url: "https://github.com/containers/podman".into(),
                source_revision: "5b263b5".into(),
                license_spdx: "Apache-2.0".into(),
            },
        };
        let encoded = serde_json::to_vec(&manifest).expect("manifest");
        let loaded = LoadedManagedRuntimeManifest::parse(&encoded).expect("loaded");
        let commands = Arc::new(FakeCommands::default());
        let downloader = Arc::new(FakeDownloader {
            bytes: image.clone(),
            calls: Mutex::new(0),
        });
        let manager = ManagedRuntimeManager::with_backends(
            state,
            resources,
            loaded,
            commands.clone(),
            downloader.clone(),
        )
        .expect("manager");
        Fixture {
            _temp: temp,
            manager,
            commands,
            #[cfg(windows)]
            downloader,
            image,
        }
    }

    fn modeled_windows_target(fixture: &mut Fixture) -> ManagedTarget {
        fixture.manager.wsl_registrations = Arc::new(FixedWindowsWslRegistrations(Vec::new()));
        let mut target = fixture.manager.loaded.target().expect("target").clone();
        target.operating_system = ManagedOperatingSystem::Windows;
        target.provider = ManagedMachineProvider::Wsl;
        target
    }

    #[test]
    fn ambiguous_same_name_is_preserved_and_routes_to_one_durable_isolated_generation() {
        let mut fixture = fixture();
        let target = modeled_windows_target(&mut fixture);
        let default_machine = machine_name(&target);
        let default_distribution = format!("podman-{default_machine}");
        let ambiguous_storage =
            fixture
                .manager
                .windows_wsl_distribution_storage_path(&target, &default_machine, 0);
        fs::create_dir_all(&ambiguous_storage).expect("ambiguous storage fixture");
        let sentinel = ambiguous_storage.join("ext4.vhdx");
        fs::write(&sentinel, b"unproven-user-bytes").expect("ambiguous bytes");
        let before = fs::read(&sentinel).expect("snapshot ambiguous bytes");

        let selected = fixture
            .manager
            .select_windows_machine_generation_from_inventory_locked(
                &target,
                &[],
                std::slice::from_ref(&default_distribution),
                true,
            )
            .expect("side-by-side selection");
        let repeated = fixture
            .manager
            .select_windows_machine_generation_from_inventory_locked(
                &target,
                &[],
                std::slice::from_ref(&default_distribution),
                true,
            )
            .expect("idempotent retry");

        assert_ne!(selected, default_machine);
        assert_eq!(selected, repeated);
        assert!(selected.starts_with(WINDOWS_WSL_ISOLATED_MACHINE_PREFIX));
        assert_eq!(selected.len(), MAX_MACHINE_NAME_BYTES);
        assert_eq!(fs::read(&sentinel).unwrap(), before);
        let durable = fixture
            .manager
            .read_windows_wsl_generation_selection_locked(&target)
            .expect("durable selection")
            .expect("one selection");
        assert!(!durable.authorizes_cleanup);
        assert_eq!(durable.generation_index, 1);
        assert_eq!(durable.selected_machine_name, selected);
        assert_eq!(durable.preserved_collision_names, vec![default_machine]);
        assert_eq!(fixture.commands.calls(), Vec::<Vec<String>>::new());
    }

    #[test]
    fn n_minus_one_ghost_without_manifest_or_proof_is_preserved_while_fresh_generation_continues() {
        let mut fixture = fixture();
        let target = modeled_windows_target(&mut fixture);
        let legacy_machine = "assm1-win-x64-e2b6cbcadd8b";
        let legacy_distribution = format!("podman-{legacy_machine}");
        let legacy_provider = fixture
            .manager
            .state_root
            .join("provider-home")
            .join("8b2257ace33ecb14");
        let legacy_storage = legacy_provider
            .join("data")
            .join("containers")
            .join("podman")
            .join("machine")
            .join("wsl")
            .join(PODMAN_WSL_DISTRIBUTION_STORAGE_DIRECTORY)
            .join(legacy_machine);
        fs::create_dir_all(&legacy_storage).expect("N-1 ghost provider fixture");
        let vhd = legacy_storage.join("ext4.vhdx");
        let sentinel = legacy_provider.join("legacy-provider-state.json");
        fs::write(&vhd, b"N-1 ghost VHD bytes").expect("ghost VHD bytes");
        fs::write(&sentinel, b"missing-manifest-ghost").expect("ghost provider bytes");
        let vhd_before = fs::read(&vhd).unwrap();
        let sentinel_before = fs::read(&sentinel).unwrap();
        assert!(
            !fixture
                .manager
                .versions_root()
                .join("8b2257ace33ecb14")
                .join("manifest.json")
                .exists(),
            "the N-1 ghost fixture intentionally has no versions manifest"
        );
        assert!(
            !fixture
                .manager
                .windows_wsl_ownership_proof_path(
                    legacy_machine,
                    WindowsWslOwnershipBasis::ProvenMachine,
                )
                .exists(),
            "the N-1 ghost fixture intentionally has no durable ownership proof"
        );

        let selected = fixture
            .manager
            .select_windows_machine_generation_from_inventory_locked(
                &target,
                &[],
                std::slice::from_ref(&legacy_distribution),
                true,
            )
            .expect("a fresh product generation continues beside the N-1 ghost");

        assert_eq!(
            selected,
            fixture.manager.isolated_windows_machine_name(&target, 1)
        );
        assert_ne!(selected, legacy_machine);
        assert_eq!(fs::read(&vhd).unwrap(), vhd_before);
        assert_eq!(fs::read(&sentinel).unwrap(), sentinel_before);
        assert!(legacy_provider.is_dir());
        let durable = fixture
            .manager
            .read_windows_wsl_generation_selection_locked(&target)
            .unwrap()
            .unwrap();
        assert_eq!(durable.generation_index, 1);
        assert!(durable.preserved_collision_names.is_empty());
        assert_eq!(fixture.commands.calls(), Vec::<Vec<String>>::new());
    }

    #[test]
    fn unrelated_wsl_distribution_does_not_change_or_block_unique_fresh_generation() {
        let mut fixture = fixture();
        let target = modeled_windows_target(&mut fixture);

        let selected = fixture
            .manager
            .select_windows_machine_generation_from_inventory_locked(
                &target,
                &[],
                &["Ubuntu-24.04".into(), "Debian".into()],
                true,
            )
            .expect("unrelated WSL state is ignored");

        assert_eq!(
            selected,
            fixture.manager.isolated_windows_machine_name(&target, 1)
        );
        let durable = fixture
            .manager
            .read_windows_wsl_generation_selection_locked(&target)
            .unwrap()
            .unwrap();
        assert_eq!(durable.generation_index, 1);
        assert!(durable.preserved_collision_names.is_empty());
        assert_eq!(fixture.commands.calls(), Vec::<Vec<String>>::new());
    }

    #[test]
    fn structurally_invalid_old_generation_journal_does_not_hide_a_later_valid_generation() {
        let mut fixture = fixture();
        let target = modeled_windows_target(&mut fixture);
        let default_machine = machine_name(&target);
        let invalid_generation_zero = fixture.manager.windows_wsl_generation_selection_path(0);
        let valid_generation_one = WindowsWslGenerationSelection {
            schema_version: WINDOWS_WSL_GENERATION_SELECTION_SCHEMA.into(),
            authorizes_cleanup: false,
            manifest_sha256: fixture.manager.loaded.sha256.clone(),
            machine_image_sha256: target.machine_image.sha256.clone(),
            default_machine_name: default_machine.clone(),
            selected_machine_name: fixture.manager.isolated_windows_machine_name(&target, 1),
            generation_index: 1,
            preserved_collision_names: vec![default_machine],
        };
        fixture
            .manager
            .write_windows_wsl_generation_selection_locked(&target, &valid_generation_one)
            .expect("write later valid generation");
        fs::create_dir(&invalid_generation_zero)
            .expect("structurally invalid generation-zero journal fixture");

        let selected = fixture
            .manager
            .read_windows_wsl_generation_selection_locked(&target)
            .expect("structural old entry is preserved but skipped")
            .expect("later valid generation remains visible");

        assert_eq!(selected, valid_generation_one);
        assert!(invalid_generation_zero.is_dir());
        assert!(fixture.commands.calls().is_empty());
    }

    #[test]
    fn orphan_ownership_entry_keeps_generation_occupied_and_routes_fresh_setup_forward() {
        let mut fixture = fixture();
        let target = modeled_windows_target(&mut fixture);
        let default_machine = machine_name(&target);
        let generation_one = fixture.manager.isolated_windows_machine_name(&target, 1);
        let orphan = fixture.manager.windows_wsl_ownership_proof_path(
            &generation_one,
            WindowsWslOwnershipBasis::InitIntent,
        );
        fs::create_dir_all(&orphan).expect("orphan structural ownership entry");

        let selected = fixture
            .manager
            .select_windows_machine_generation_from_inventory_locked(
                &target,
                &[],
                &[format!("podman-{default_machine}")],
                true,
            )
            .expect("fresh setup should skip the occupied orphan generation");

        assert_eq!(
            selected,
            fixture.manager.isolated_windows_machine_name(&target, 2)
        );
        assert!(orphan.is_dir());
        assert!(
            !fixture
                .manager
                .windows_generation_selection_exists(1)
                .expect("inspect skipped generation")
        );
        assert!(
            fixture
                .manager
                .windows_generation_selection_exists(2)
                .expect("inspect selected generation")
        );
        assert!(fixture.commands.calls().is_empty());
    }

    #[test]
    fn structurally_invalid_proof_on_selected_generation_routes_retry_forward_without_mutation() {
        let mut fixture = fixture();
        let target = modeled_windows_target(&mut fixture);
        let default_machine = machine_name(&target);
        let generation_one = fixture.manager.isolated_windows_machine_name(&target, 1);
        let selection = WindowsWslGenerationSelection {
            schema_version: WINDOWS_WSL_GENERATION_SELECTION_SCHEMA.into(),
            authorizes_cleanup: false,
            manifest_sha256: fixture.manager.loaded.sha256.clone(),
            machine_image_sha256: target.machine_image.sha256.clone(),
            default_machine_name: default_machine.clone(),
            selected_machine_name: generation_one.clone(),
            generation_index: 1,
            preserved_collision_names: vec![default_machine],
        };
        fixture
            .manager
            .write_windows_wsl_generation_selection_locked(&target, &selection)
            .expect("write selected generation");
        let invalid_proof = fixture.manager.windows_wsl_ownership_proof_path(
            &generation_one,
            WindowsWslOwnershipBasis::ProvenMachine,
        );
        fs::create_dir_all(&invalid_proof).expect("structurally invalid selected proof");

        let selected = fixture
            .manager
            .select_windows_machine_generation_from_inventory_locked(&target, &[], &[], true)
            .expect("retry should preserve and advance past the invalid proof");

        assert_eq!(
            selected,
            fixture.manager.isolated_windows_machine_name(&target, 2)
        );
        assert!(invalid_proof.is_dir());
        assert!(
            fixture
                .manager
                .windows_generation_selection_exists(1)
                .expect("preserve old selection")
        );
        assert!(
            fixture
                .manager
                .windows_generation_selection_exists(2)
                .expect("append replacement selection")
        );
        assert!(fixture.commands.calls().is_empty());
    }

    #[test]
    fn exact_init_intent_never_masks_an_invalid_proven_machine_entry() {
        let mut fixture = fixture();
        let target = modeled_windows_target(&mut fixture);
        fixture.manager.install().expect("install current payload");
        let default_machine = machine_name(&target);
        let generation_one = fixture.manager.isolated_windows_machine_name(&target, 1);
        let selection = WindowsWslGenerationSelection {
            schema_version: WINDOWS_WSL_GENERATION_SELECTION_SCHEMA.into(),
            authorizes_cleanup: false,
            manifest_sha256: fixture.manager.loaded.sha256.clone(),
            machine_image_sha256: target.machine_image.sha256.clone(),
            default_machine_name: default_machine.clone(),
            selected_machine_name: generation_one.clone(),
            generation_index: 1,
            preserved_collision_names: vec![default_machine],
        };
        fixture
            .manager
            .write_windows_wsl_generation_selection_locked(&target, &selection)
            .expect("write selected generation");
        fixture
            .manager
            .ensure_windows_wsl_ownership_proof_locked(
                &target,
                &generation_one,
                WindowsWslOwnershipBasis::InitIntent,
            )
            .expect("write exact initialization intent");
        let init_intent = fixture.manager.windows_wsl_ownership_proof_path(
            &generation_one,
            WindowsWslOwnershipBasis::InitIntent,
        );
        let init_before = fs::read(&init_intent).expect("snapshot exact intent");
        let invalid_proven = fixture.manager.windows_wsl_ownership_proof_path(
            &generation_one,
            WindowsWslOwnershipBasis::ProvenMachine,
        );
        fs::create_dir(&invalid_proven).expect("structurally invalid proven-machine entry");

        let selected = fixture
            .manager
            .select_windows_machine_generation_from_inventory_locked(&target, &[], &[], true)
            .expect("invalid stronger proof should route setup forward immediately");

        assert_eq!(
            selected,
            fixture.manager.isolated_windows_machine_name(&target, 2)
        );
        assert_eq!(fs::read(&init_intent).unwrap(), init_before);
        assert!(invalid_proven.is_dir());
        assert!(
            fixture
                .manager
                .windows_generation_selection_exists(2)
                .expect("append replacement selection")
        );
        assert!(fixture.commands.calls().is_empty());
    }

    #[test]
    fn current_windows_generation_has_no_legacy_recovery_route() {
        let production = include_str!("managed_runtime.rs")
            .split("\n#[cfg(test)]")
            .next()
            .expect("production source");
        assert!(!production.contains("prove_windows_wsl_distribution_absent_locked"));
        assert!(!production.contains("self.recover_windows_wsl_distribution_locked("));
        assert!(!production.contains("WslDistributionExport"));
        assert!(!production.contains("WslDistributionImport"));
        assert!(!production.contains("WslDistributionRemoval"));
    }

    #[test]
    fn matching_provider_row_without_exact_binding_is_a_collision_not_ownership() {
        let mut fixture = fixture();
        let target = modeled_windows_target(&mut fixture);
        let default_machine = machine_name(&target);
        let machine_row = MachineListEntry {
            name: default_machine.clone(),
            running: true,
            vm_type: target.provider.argument().into(),
            cpus: fixture.manager.loaded.manifest.resources.cpus as u64,
            memory: fixture.manager.loaded.manifest.resources.memory_mb as u64 * 1024 * 1024,
            disk_size: fixture.manager.loaded.manifest.resources.disk_size_gb as u64
                * 1024
                * 1024
                * 1024,
        };

        let selected = fixture
            .manager
            .select_windows_machine_generation_from_inventory_locked(
                &target,
                &[machine_row],
                &[format!("podman-{default_machine}")],
                true,
            )
            .expect("unproven row is isolated");

        assert_ne!(selected, default_machine);
        let durable = fixture
            .manager
            .read_windows_wsl_generation_selection_locked(&target)
            .unwrap()
            .unwrap();
        assert_eq!(durable.generation_index, 1);
        assert_eq!(durable.preserved_collision_names, vec![default_machine]);
        assert_eq!(fixture.commands.calls(), Vec::<Vec<String>>::new());
    }

    #[test]
    fn isolated_generation_requires_exact_init_or_proven_machine_ownership() {
        let mut fixture = fixture();
        fixture.manager.install().expect("verified current payload");
        let target = modeled_windows_target(&mut fixture);
        let machine = fixture.manager.isolated_windows_machine_name(&target, 1);
        let selection = WindowsWslGenerationSelection {
            schema_version: WINDOWS_WSL_GENERATION_SELECTION_SCHEMA.into(),
            authorizes_cleanup: false,
            manifest_sha256: fixture.manager.loaded.sha256.clone(),
            machine_image_sha256: target.machine_image.sha256.clone(),
            default_machine_name: machine_name(&target),
            selected_machine_name: machine.clone(),
            generation_index: 1,
            preserved_collision_names: vec![machine_name(&target)],
        };
        fixture
            .manager
            .write_windows_wsl_generation_selection_locked(&target, &selection)
            .expect("durable isolated selection");

        let no_proof = fixture
            .manager
            .require_isolated_windows_generation_ownership_locked(&target, &machine, &selection)
            .expect_err("routing alone is not ownership");
        assert!(
            no_proof
                .to_string()
                .contains("no exact product ownership proof")
        );

        fixture
            .manager
            .ensure_windows_wsl_ownership_proof_locked(
                &target,
                &machine,
                WindowsWslOwnershipBasis::InitIntent,
            )
            .expect("exact init intent");
        fixture
            .manager
            .require_isolated_windows_generation_ownership_locked(&target, &machine, &selection)
            .expect("exact init intent authorizes post-init binding verification");

        fixture
            .manager
            .remove_windows_wsl_ownership_basis_proof_locked(
                &target,
                &machine,
                WindowsWslOwnershipBasis::InitIntent,
            )
            .unwrap();
        fixture
            .manager
            .ensure_windows_wsl_ownership_proof_locked(
                &target,
                &machine,
                WindowsWslOwnershipBasis::ProvenMachine,
            )
            .expect("exact proven-machine proof");
        fixture
            .manager
            .require_isolated_windows_generation_ownership_locked(&target, &machine, &selection)
            .expect("exact proven-machine proof authorizes later binding verification");
        assert_eq!(fixture.commands.calls(), Vec::<Vec<String>>::new());
    }

    #[test]
    fn generation_allocator_preserves_unknown_candidate_home_and_routing_record() {
        let mut fixture = fixture();
        let target = modeled_windows_target(&mut fixture);
        let default_machine = machine_name(&target);
        let candidate_home = fixture
            .manager
            .windows_provider_home_for_generation(&target, 1);
        fs::create_dir_all(&candidate_home).expect("ambiguous candidate home");
        let provider_sentinel = candidate_home.join("unknown-provider-state");
        fs::write(&provider_sentinel, b"preserve-provider").unwrap();
        let selection_path = fixture.manager.windows_wsl_generation_selection_path(1);
        ensure_managed_private_directory(selection_path.parent().unwrap()).unwrap();
        write_private_atomic(&selection_path, b"malformed-routing-record").unwrap();

        let selected = fixture
            .manager
            .select_windows_machine_generation_from_inventory_locked(
                &target,
                &[],
                &[format!("podman-{default_machine}")],
                true,
            )
            .expect("fresh generation after preserved collision");

        assert_eq!(
            selected,
            fixture.manager.isolated_windows_machine_name(&target, 2)
        );
        assert_eq!(fs::read(&provider_sentinel).unwrap(), b"preserve-provider");
        assert_eq!(
            fs::read(&selection_path).unwrap(),
            b"malformed-routing-record"
        );
        assert_eq!(fixture.commands.calls(), Vec::<Vec<String>>::new());
    }

    #[test]
    fn provider_access_without_a_durable_windows_generation_is_observation_only() {
        let mut fixture = fixture();
        let target = modeled_windows_target(&mut fixture);
        let default_home = fixture
            .manager
            .windows_provider_home_for_generation(&target, 0);
        fs::create_dir_all(&default_home).expect("ambiguous default provider");
        let sentinel = default_home.join("unknown-provider-state");
        fs::write(&sentinel, b"leave-untouched").unwrap();

        assert!(
            !fixture
                .manager
                .provider_generation_is_selected_locked(&target)
                .unwrap()
        );
        assert_eq!(fs::read(&sentinel).unwrap(), b"leave-untouched");
        assert_eq!(fixture.commands.calls(), Vec::<Vec<String>>::new());
    }

    #[test]
    fn clean_read_then_setup_allocates_one_durable_unique_generation_without_provider_mutation() {
        let mut fixture = fixture();
        let target = modeled_windows_target(&mut fixture);
        let default_home = fixture
            .manager
            .windows_provider_home_for_generation(&target, 0);
        let isolated_home = fixture
            .manager
            .windows_provider_home_for_generation(&target, 1);

        assert!(
            !fixture
                .manager
                .provider_generation_is_selected_locked(&target)
                .unwrap()
        );
        assert!(!private_entry_exists(&default_home).unwrap());

        let selected = fixture
            .manager
            .select_windows_machine_generation_from_inventory_locked(&target, &[], &[], false)
            .expect("clean setup selection");
        let repeated = fixture
            .manager
            .select_windows_machine_generation_from_inventory_locked(&target, &[], &[], false)
            .expect("clean setup retry reuses its durable selection");

        assert_eq!(
            selected,
            fixture.manager.isolated_windows_machine_name(&target, 1)
        );
        assert_ne!(selected, machine_name(&target));
        assert_eq!(repeated, selected);
        assert!(
            fixture
                .manager
                .provider_generation_is_selected_locked(&target)
                .unwrap()
        );
        assert!(!private_entry_exists(&default_home).unwrap());
        assert!(!private_entry_exists(&isolated_home).unwrap());
        let durable = fixture
            .manager
            .read_windows_wsl_generation_selection_locked(&target)
            .unwrap()
            .expect("one fresh generation selection");
        assert_eq!(durable.generation_index, 1);
        assert_eq!(durable.selected_machine_name, selected);
        assert!(durable.preserved_collision_names.is_empty());
        assert!(
            !fixture
                .manager
                .windows_generation_selection_exists(2)
                .expect("inspect unused next generation")
        );
        assert_eq!(fixture.commands.calls(), Vec::<Vec<String>>::new());
    }

    #[cfg(windows)]
    #[test]
    fn exact_deployed_generation_zero_is_reused_without_allocating_a_new_generation() {
        let mut fixture = fixture();
        let (target, machine, vhd, registration) =
            seed_verified_existing_windows_machine(&mut fixture);
        let vhd_before = fs::read(&vhd).expect("generation-zero VHD snapshot");
        let selection_before = fixture
            .manager
            .read_windows_wsl_generation_selection_locked(&target)
            .expect("read deployed selection")
            .expect("deployed generation-zero selection");
        let machines = [MachineListEntry {
            name: machine.clone(),
            running: true,
            vm_type: target.provider.argument().into(),
            cpus: u64::from(fixture.manager.loaded.manifest.resources.cpus),
            memory: u64::from(fixture.manager.loaded.manifest.resources.memory_mb) * 1024 * 1024,
            disk_size: u64::from(fixture.manager.loaded.manifest.resources.disk_size_gb)
                * 1024
                * 1024
                * 1024,
        }];
        let distributions = [registration.distribution_name.clone()];

        let selected = fixture
            .manager
            .select_windows_machine_generation_from_complete_inventory_locked(
                &target,
                &machines,
                &distributions,
                std::slice::from_ref(&registration),
                true,
            )
            .expect("exact deployed generation remains reusable");

        assert_eq!(selected, machine);
        assert_eq!(selection_before.generation_index, 0);
        assert_eq!(
            fixture
                .manager
                .read_windows_wsl_generation_selection_locked(&target)
                .unwrap()
                .unwrap(),
            selection_before
        );
        assert!(
            !fixture
                .manager
                .windows_generation_selection_exists(1)
                .expect("inspect unused isolated generation")
        );
        assert_eq!(fs::read(vhd).unwrap(), vhd_before);
        assert!(fixture.commands.calls().is_empty());
    }

    #[test]
    fn exact_init_intent_reuses_its_in_progress_provider_home_on_retry() {
        let mut fixture = fixture();
        fixture.manager.install().expect("verified current payload");
        let target = modeled_windows_target(&mut fixture);
        let selected = fixture
            .manager
            .select_windows_machine_generation_from_inventory_locked(&target, &[], &[], false)
            .expect("clean setup selection");
        fixture
            .manager
            .ensure_windows_wsl_ownership_proof_locked(
                &target,
                &selected,
                WindowsWslOwnershipBasis::InitIntent,
            )
            .expect("exact one-shot initialization intent");

        let provider_home = fixture
            .manager
            .windows_provider_home_for_generation(&target, 1);
        fs::create_dir_all(&provider_home).expect("in-progress provider home");
        let sentinel = provider_home.join("in-progress-state");
        fs::write(&sentinel, b"product-owned-in-progress").unwrap();

        let retried = fixture
            .manager
            .select_windows_machine_generation_from_inventory_locked(&target, &[], &[], false)
            .expect("retry reuses exact product-owned generation");

        assert_eq!(retried, selected);
        assert_eq!(fs::read(&sentinel).unwrap(), b"product-owned-in-progress");
        assert_eq!(fixture.commands.calls(), Vec::<Vec<String>>::new());
    }

    fn machine_json_named(
        manager: &ManagedRuntimeManager,
        selected_machine_name: &str,
        running: bool,
    ) -> Vec<u8> {
        let target = manager.loaded.target().expect("target");
        serde_json::to_vec(&serde_json::json!([{
            "Name": selected_machine_name,
            "Running": running,
            "VMType": target.provider.argument(),
            "CPUs": 2,
            "Memory": (4096_u64 * 1024 * 1024).to_string(),
            "DiskSize": (40_u64 * 1024 * 1024 * 1024).to_string()
        }]))
        .expect("json")
    }

    fn machine_json(manager: &ManagedRuntimeManager, running: bool) -> Vec<u8> {
        let target = manager.loaded.target().expect("target");
        machine_json_named(manager, &machine_name(target), running)
    }

    fn fresh_machine_json(manager: &ManagedRuntimeManager, running: bool) -> Vec<u8> {
        let target = manager.loaded.target().expect("target");
        let selected = if target.operating_system == ManagedOperatingSystem::Windows {
            manager.isolated_windows_machine_name(target, 1)
        } else {
            machine_name(target)
        };
        machine_json_named(manager, &selected, running)
    }

    #[cfg(windows)]
    fn push_windows_wsl_absent(commands: &FakeCommands) {
        commands.push(success(Vec::new()));
    }

    #[cfg(not(windows))]
    fn push_windows_wsl_absent(_commands: &FakeCommands) {}

    #[cfg(windows)]
    fn push_windows_wsl_ready(commands: &FakeCommands) {
        commands.push(success(utf16le(
            "Default Version: 2\r\nKernel version: 6.6.87.2\r\n",
        )));
        commands.push(success(Vec::new()));
    }

    #[cfg(not(windows))]
    fn push_windows_wsl_ready(_commands: &FakeCommands) {}

    #[cfg(windows)]
    fn windows_fixture_vhd_path(
        manager: &ManagedRuntimeManager,
        target: &ManagedTarget,
    ) -> PathBuf {
        manager
            .provider_home()
            .join("data")
            .join("containers")
            .join("podman")
            .join("machine")
            .join(target.provider.argument())
            .join(PODMAN_WSL_DISTRIBUTION_STORAGE_DIRECTORY)
            .join(machine_name(target))
            .join("ext4.vhdx")
    }

    #[cfg(windows)]
    fn seed_verified_existing_windows_machine(
        fixture: &mut Fixture,
    ) -> (ManagedTarget, String, PathBuf, WindowsWslRegistration) {
        fixture.manager.wsl_registrations = Arc::new(FixedWindowsWslRegistrations(Vec::new()));
        fixture.manager.install().expect("install current payload");
        let target = fixture
            .manager
            .loaded
            .target()
            .expect("Windows target")
            .clone();
        let machine = machine_name(&target);
        fixture
            .manager
            .write_windows_wsl_generation_selection_locked(
                &target,
                &WindowsWslGenerationSelection {
                    schema_version: WINDOWS_WSL_GENERATION_SELECTION_SCHEMA.into(),
                    authorizes_cleanup: false,
                    manifest_sha256: fixture.manager.loaded.sha256.clone(),
                    machine_image_sha256: target.machine_image.sha256.clone(),
                    default_machine_name: machine.clone(),
                    selected_machine_name: machine.clone(),
                    generation_index: 0,
                    preserved_collision_names: Vec::new(),
                },
            )
            .expect("seed deployed generation-zero selection");
        fixture
            .manager
            .runtime_command(&target)
            .expect("prepare current provider home");
        fixture
            .manager
            .prepare_machine_ssh_identity_locked()
            .expect("prepare current product identity");
        let vhd = fixture
            .manager
            .windows_wsl_distribution_storage_path(&target, &machine, 0)
            .join("ext4.vhdx");
        ensure_managed_wsl_distribution_storage_directory(vhd.parent().expect("VHD parent"))
            .expect("create verified existing WSL storage");
        fs::write(&vhd, b"verified-existing-generation").expect("write existing VHD fixture");
        fixture
            .manager
            .ensure_windows_wsl_ownership_proof_locked(
                &target,
                &machine,
                WindowsWslOwnershipBasis::ProvenMachine,
            )
            .expect("prove current product generation");
        let registration = WindowsWslRegistration {
            registration_id: "00000000-0000-0000-0000-000000000051".into(),
            distribution_name: format!("podman-{machine}"),
            base_path: vhd.parent().expect("registration base").to_path_buf(),
        };
        (target, machine, vhd, registration)
    }

    #[derive(Clone, Copy)]
    enum FixtureWindowsRegistrationLifecycle {
        Absent,
        Present,
        PresentThenAbsent,
    }

    /// Older lifecycle tests model a machine that predates the append-only
    /// Windows generation journal. Bring those fixtures up to the current
    /// ownership contract explicitly instead of weakening production's
    /// preserve-on-ambiguity behavior.
    fn seed_owned_windows_lifecycle_fixture(
        fixture: &mut Fixture,
        registration_lifecycle: FixtureWindowsRegistrationLifecycle,
    ) {
        #[cfg(windows)]
        {
            let (_, _, _, registration) = seed_verified_existing_windows_machine(fixture);
            let registrations: Arc<dyn WindowsWslRegistrationReader> = match registration_lifecycle
            {
                FixtureWindowsRegistrationLifecycle::Absent => {
                    Arc::new(FixedWindowsWslRegistrations(Vec::new()))
                }
                FixtureWindowsRegistrationLifecycle::Present => {
                    Arc::new(FixedWindowsWslRegistrations(vec![registration]))
                }
                FixtureWindowsRegistrationLifecycle::PresentThenAbsent => {
                    Arc::new(SequencedWindowsWslRegistrations(Mutex::new(
                        VecDeque::from([vec![registration], Vec::new()]),
                    )))
                }
            };
            fixture.manager.wsl_registrations = registrations;
        }
        #[cfg(not(windows))]
        let _ = (fixture, registration_lifecycle);
    }

    #[cfg(windows)]
    fn configure_fresh_windows_machine_registration(fixture: &mut Fixture) -> PathBuf {
        let target = fixture
            .manager
            .loaded
            .target()
            .expect("Windows target")
            .clone();
        let machine = fixture.manager.isolated_windows_machine_name(&target, 1);
        let storage = fixture
            .manager
            .windows_wsl_distribution_storage_path(&target, &machine, 1);
        let registration = WindowsWslRegistration {
            registration_id: "00000000-0000-0000-0000-000000000061".into(),
            distribution_name: format!("podman-{machine}"),
            base_path: storage.clone(),
        };
        let vhd = storage.join("ext4.vhdx");
        fixture.manager.wsl_registrations = Arc::new(WindowsWslRegistrationAfterVhdExists {
            registration,
            vhd: vhd.clone(),
        });
        vhd
    }

    #[cfg(not(windows))]
    fn configure_fresh_windows_machine_registration(fixture: &mut Fixture) -> PathBuf {
        let _ = fixture;
        PathBuf::new()
    }

    #[cfg(windows)]
    fn open_without_windows_delete_sharing(path: &Path) -> File {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{FILE_SHARE_READ, FILE_SHARE_WRITE};

        OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .open(path)
            .expect("open fixture without delete sharing")
    }

    #[cfg(windows)]
    fn open_without_windows_write_or_delete_sharing(path: &Path) -> File {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ;

        OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .open(path)
            .expect("open fixture without write or delete sharing")
    }

    #[cfg(windows)]
    fn open_without_windows_sharing(path: &Path) -> File {
        use std::os::windows::fs::OpenOptionsExt;

        OpenOptions::new()
            .read(true)
            .share_mode(0)
            .open(path)
            .expect("open fixture without sharing")
    }

    #[cfg(windows)]
    fn open_windows_directory_without_sharing(path: &Path) -> File {
        use std::os::windows::ffi::OsStrExt;
        use std::os::windows::io::FromRawHandle;
        use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
        use windows_sys::Win32::Storage::FileSystem::{
            CreateFileW, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
            FILE_READ_ATTRIBUTES, FILE_TRAVERSE, OPEN_EXISTING, READ_CONTROL,
        };

        let mut encoded = path.as_os_str().encode_wide().collect::<Vec<_>>();
        assert!(!encoded.contains(&0), "fixture directory contains a NUL");
        encoded.push(0);
        // SAFETY: encoded is NUL-terminated and remains live for the call.
        let raw = unsafe {
            CreateFileW(
                encoded.as_ptr(),
                FILE_TRAVERSE | FILE_READ_ATTRIBUTES | READ_CONTROL,
                0,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                std::ptr::null_mut(),
            )
        };
        assert_ne!(raw, INVALID_HANDLE_VALUE, "open fixture without sharing");
        // SAFETY: CreateFileW returned a uniquely owned handle.
        unsafe { File::from_raw_handle(raw) }
    }

    #[test]
    fn machine_names_are_deterministic_unique_and_within_podman_limit() {
        let image = ManagedMachineImage {
            url: "https://github.com/podman-container-tools/podman-machine-os/releases/download/v5.8.2/machine.zst".into(),
            sha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                .into(),
            size_bytes: 1,
        };
        let operating_systems = [
            (ManagedOperatingSystem::Linux, ManagedMachineProvider::Qemu),
            (
                ManagedOperatingSystem::Macos,
                ManagedMachineProvider::Applehv,
            ),
            (ManagedOperatingSystem::Windows, ManagedMachineProvider::Wsl),
        ];
        let architectures = [ManagedArchitecture::X86_64, ManagedArchitecture::Aarch64];
        let mut names = BTreeSet::new();

        for (operating_system, provider) in operating_systems {
            for architecture in architectures {
                let target = ManagedTarget {
                    operating_system,
                    architecture,
                    provider,
                    machine_image: image.clone(),
                    prerequisite: None,
                };
                let name = machine_name(&target);
                assert_eq!(name, machine_name(&target));
                assert!(name.is_ascii());
                assert!(name.len() <= MAX_MACHINE_NAME_BYTES, "{name}");
                assert!(names.insert(name));
            }
        }

        assert_eq!(names.iter().map(String::len).max(), Some(30));
        assert!(names.contains("assm1-linux-arm64-0123456789ab"));
        assert!(names.contains("assm1-macos-arm64-0123456789ab"));
        assert!(names.contains("assm2-win-x64-0123456789ab"));
    }

    #[cfg(windows)]
    #[test]
    fn transient_incomplete_windows_registration_inventory_reuses_verified_selection_after_retry() {
        let mut fixture = fixture();
        let (target, selected_machine, _selected_vhd, registration) =
            seed_verified_existing_windows_machine(&mut fixture);
        fixture.manager.wsl_registrations = Arc::new(SequencedWindowsWslRegistrationInventories(
            Mutex::new(VecDeque::from([
                WindowsWslRegistrationInventory {
                    registrations: Vec::new(),
                    observed_distribution_names: vec![registration.distribution_name.clone()],
                    complete: false,
                },
                WindowsWslRegistrationInventory::complete(vec![registration]),
            ])),
        ));
        let machines = [MachineListEntry {
            name: selected_machine.clone(),
            running: true,
            vm_type: target.provider.argument().into(),
            cpus: u64::from(fixture.manager.loaded.manifest.resources.cpus),
            memory: u64::from(fixture.manager.loaded.manifest.resources.memory_mb) * 1024 * 1024,
            disk_size: u64::from(fixture.manager.loaded.manifest.resources.disk_size_gb)
                * 1024
                * 1024
                * 1024,
        }];
        let distributions = [format!("podman-{selected_machine}")];
        let selection_before = fixture
            .manager
            .read_windows_wsl_generation_selection_locked(&target)
            .expect("read generation selection")
            .expect("selected generation");
        let _lock = fixture.manager.lock().expect("lifecycle lock");

        let selected = fixture
            .manager
            .select_windows_machine_generation_from_inventory_locked(
                &target,
                &machines,
                &distributions,
                true,
            )
            .expect("bounded reread should recover the exact registration binding");

        assert_eq!(selected, selected_machine);
        assert_eq!(
            fixture
                .manager
                .read_windows_wsl_generation_selection_locked(&target)
                .expect("read preserved selection")
                .expect("preserved generation"),
            selection_before
        );
        assert!(fixture.commands.calls().is_empty());
    }

    #[cfg(windows)]
    #[test]
    fn unrelated_incomplete_windows_inventory_does_not_block_exact_product_binding() {
        let mut fixture = fixture();
        let (_target, selected_machine, selected_vhd, registration) =
            seed_verified_existing_windows_machine(&mut fixture);
        let partial = WindowsWslRegistrationInventory {
            registrations: vec![registration.clone()],
            observed_distribution_names: vec![
                "Malformed-Unrelated-Entry".into(),
                registration.distribution_name,
            ],
            complete: false,
        };
        fixture.manager.wsl_registrations = Arc::new(SequencedWindowsWslRegistrationInventories(
            Mutex::new(VecDeque::from([partial.clone(), partial])),
        ));

        let verified_base = fixture
            .manager
            .verify_current_windows_wsl_machine_registration_binding(&selected_machine)
            .expect("one exact product registration remains provable in a partial inventory");

        assert_eq!(
            verified_base,
            selected_vhd
                .parent()
                .expect("registration base")
                .canonicalize()
                .expect("canonical registration base")
        );
        assert_eq!(
            fs::read(&selected_vhd).expect("preserved selected VHD"),
            b"verified-existing-generation"
        );
        assert!(fixture.commands.calls().is_empty());
    }

    #[cfg(windows)]
    #[test]
    fn persistently_incomplete_fresh_windows_inventory_uses_isolated_generation_without_reading_old_intent()
     {
        let mut fixture = fixture();
        let target = modeled_windows_target(&mut fixture);
        fixture.manager.install().expect("install current payload");
        let default_machine = machine_name(&target);
        let stale_intent = fixture.manager.windows_wsl_ownership_proof_path(
            &default_machine,
            WindowsWslOwnershipBasis::InitIntent,
        );
        ensure_managed_private_directory(
            stale_intent
                .parent()
                .expect("ownership proof parent directory"),
        )
        .expect("private ownership proof parent");
        fs::create_dir_all(&stale_intent).expect("unreadable old intent fixture");
        let partial = WindowsWslRegistrationInventory {
            registrations: Vec::new(),
            observed_distribution_names: vec![format!("podman-{default_machine}")],
            complete: false,
        };
        fixture.manager.wsl_registrations = Arc::new(SequencedWindowsWslRegistrationInventories(
            Mutex::new(VecDeque::from([partial.clone(), partial])),
        ));
        let _lock = fixture.manager.lock().expect("lifecycle lock");

        let selected = fixture
            .manager
            .select_windows_machine_generation_from_inventory_locked(&target, &[], &[], true)
            .expect("partial fresh inventory should route to a private isolated generation");

        assert_ne!(selected, default_machine);
        assert_eq!(
            selected,
            fixture.manager.isolated_windows_machine_name(&target, 1)
        );
        assert!(stale_intent.is_dir());
        let durable = fixture
            .manager
            .read_windows_wsl_generation_selection_locked(&target)
            .expect("read isolated selection")
            .expect("isolated generation");
        assert_eq!(durable.generation_index, 1);
        assert_eq!(durable.preserved_collision_names, vec![default_machine]);

        fixture
            .manager
            .runtime_command(&target)
            .expect("prepare isolated provider home");
        fixture
            .manager
            .prepare_machine_ssh_identity_locked()
            .expect("prepare exact product identity");
        let selected_storage = fixture
            .manager
            .windows_wsl_distribution_storage_path(&target, &selected, 1);
        ensure_managed_wsl_distribution_storage_directory(&selected_storage)
            .expect("create selected WSL storage");
        let selected_vhd = selected_storage.join("ext4.vhdx");
        fs::write(&selected_vhd, b"isolated-product-generation")
            .expect("write selected VHD fixture");
        fixture
            .manager
            .ensure_windows_wsl_ownership_proof_locked(
                &target,
                &selected,
                WindowsWslOwnershipBasis::ProvenMachine,
            )
            .expect("prove selected product generation");
        let registration = WindowsWslRegistration {
            registration_id: "00000000-0000-0000-0000-000000000071".into(),
            distribution_name: format!("podman-{selected}"),
            base_path: selected_storage,
        };
        let partial = WindowsWslRegistrationInventory {
            registrations: vec![registration.clone()],
            observed_distribution_names: vec![
                "Malformed-Unrelated-Entry".into(),
                registration.distribution_name.clone(),
            ],
            complete: false,
        };
        fixture.manager.wsl_registrations = Arc::new(SequencedWindowsWslRegistrationInventories(
            Mutex::new(VecDeque::from([partial.clone(), partial])),
        ));
        let machines = [MachineListEntry {
            name: selected.clone(),
            running: true,
            vm_type: target.provider.argument().into(),
            cpus: u64::from(fixture.manager.loaded.manifest.resources.cpus),
            memory: u64::from(fixture.manager.loaded.manifest.resources.memory_mb) * 1024 * 1024,
            disk_size: u64::from(fixture.manager.loaded.manifest.resources.disk_size_gb)
                * 1024
                * 1024
                * 1024,
        }];

        let repeated = fixture
            .manager
            .select_windows_machine_generation_from_inventory_locked(
                &target,
                &machines,
                &[registration.distribution_name],
                true,
            )
            .expect("exact selected generation should remain reusable in a partial inventory");

        assert_eq!(repeated, selected);
        assert!(
            !fixture
                .manager
                .windows_generation_selection_exists(2)
                .expect("inspect next generation selection"),
            "partial unrelated registry state must not advance a proven product generation"
        );
        assert_eq!(
            fs::read(&selected_vhd).expect("preserved selected VHD"),
            b"isolated-product-generation"
        );
        assert!(fixture.commands.calls().is_empty());
    }

    #[cfg(windows)]
    #[test]
    fn transient_windows_registration_reader_error_preserves_selected_generation() {
        let mut fixture = fixture();
        let (target, selected_machine, selected_vhd, _registration) =
            seed_verified_existing_windows_machine(&mut fixture);
        let selected_vhd_bytes = fs::read(&selected_vhd).expect("selected VHD snapshot");
        let selection_before = fixture
            .manager
            .read_windows_wsl_generation_selection_locked(&target)
            .expect("read generation selection")
            .expect("selected generation");
        fixture.manager.wsl_registrations = Arc::new(FailingWindowsWslRegistrations);
        let machines = [MachineListEntry {
            name: selected_machine.clone(),
            running: true,
            vm_type: target.provider.argument().into(),
            cpus: u64::from(fixture.manager.loaded.manifest.resources.cpus),
            memory: u64::from(fixture.manager.loaded.manifest.resources.memory_mb) * 1024 * 1024,
            disk_size: u64::from(fixture.manager.loaded.manifest.resources.disk_size_gb)
                * 1024
                * 1024
                * 1024,
        }];
        let distributions = [format!("podman-{selected_machine}")];
        let _lock = fixture.manager.lock().expect("lifecycle lock");

        let error = fixture
            .manager
            .select_windows_machine_generation_from_inventory_locked(
                &target,
                &machines,
                &distributions,
                true,
            )
            .expect_err("transient registry failure must not allocate another generation");

        assert!(matches!(&error, AppError::NotAvailable(_)));
        assert!(!error.to_string().contains("preserved for retry"));
        assert_eq!(
            fixture
                .manager
                .read_windows_wsl_generation_selection_locked(&target)
                .expect("read preserved selection")
                .expect("preserved generation"),
            selection_before
        );
        assert_eq!(fs::read(&selected_vhd).unwrap(), selected_vhd_bytes);
        assert!(fixture.commands.calls().is_empty());
    }

    #[cfg(windows)]
    #[test]
    fn transient_windows_wsl_storage_sharing_violation_preserves_selected_generation() {
        let mut fixture = fixture();
        let (target, selected_machine, selected_vhd, registration) =
            seed_verified_existing_windows_machine(&mut fixture);
        let selected_vhd_bytes = fs::read(&selected_vhd).expect("selected VHD snapshot");
        let selection_before = fixture
            .manager
            .read_windows_wsl_generation_selection_locked(&target)
            .expect("read generation selection")
            .expect("selected generation");
        fixture.manager.wsl_registrations =
            Arc::new(FixedWindowsWslRegistrations(vec![registration.clone()]));
        let machines = [MachineListEntry {
            name: selected_machine.clone(),
            running: true,
            vm_type: target.provider.argument().into(),
            cpus: u64::from(fixture.manager.loaded.manifest.resources.cpus),
            memory: u64::from(fixture.manager.loaded.manifest.resources.memory_mb) * 1024 * 1024,
            disk_size: u64::from(fixture.manager.loaded.manifest.resources.disk_size_gb)
                * 1024
                * 1024
                * 1024,
        }];
        let distributions = [registration.distribution_name.clone()];
        let storage = registration.base_path.parent().expect("WSL storage parent");
        let _exclusive_storage = open_windows_directory_without_sharing(storage);
        let _lock = fixture.manager.lock().expect("lifecycle lock");

        let error = fixture
            .manager
            .select_windows_machine_generation_from_inventory_locked(
                &target,
                &machines,
                &distributions,
                true,
            )
            .expect_err("a transient storage-sharing failure must preserve the generation");

        assert!(matches!(&error, AppError::NotAvailable(_)));
        assert!(!error.to_string().contains("preserved for retry"));
        assert_eq!(
            fixture
                .manager
                .read_windows_wsl_generation_selection_locked(&target)
                .expect("read preserved selection")
                .expect("preserved generation"),
            selection_before
        );
        assert_eq!(fs::read(&selected_vhd).unwrap(), selected_vhd_bytes);
        assert!(fixture.commands.calls().is_empty());
    }

    #[test]
    fn current_windows_compatibility_generation_match_is_exact_and_bounded() {
        assert!(windows_machine_uses_current_compatibility_generation(
            "assm2-win-x64-0123456789ab"
        ));
        for unrelated in [
            "assm2",
            "assm2-",
            "assm20-win-x64-0123456789ab",
            "assm1-win-x64-0123456789ab",
            "podman-assm2-win-x64-0123456789ab",
            "ASSM2-win-x64-0123456789ab",
        ] {
            assert!(
                !windows_machine_uses_current_compatibility_generation(unrelated),
                "unrelated machine name matched current compatibility generation: {unrelated}"
            );
        }
    }
    #[cfg(unix)]
    #[test]
    fn linux_short_runtime_is_domain_separated_private_and_socket_bounded() {
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::MetadataExt;

        let temp = TempDir::new().expect("temporary root");
        let base = temp.path().join("short-runtimes");
        let first_state = temp.path().join("first-state");
        let second_state = temp.path().join("second-state");
        for directory in [&base, &first_state, &second_state] {
            ensure_private_directory(directory).expect("private directory");
        }
        let first_state = canonical_real_directory(&first_state, "first test state").unwrap();
        let second_state = canonical_real_directory(&second_state, "second test state").unwrap();
        let effective_uid = effective_uid();
        let first_manifest = "a".repeat(64);
        let second_manifest = "b".repeat(64);

        let runtime = linux_short_runtime_path(&base, &first_state, &first_manifest, effective_uid);
        assert_eq!(
            runtime,
            linux_short_runtime_path(&base, &first_state, &first_manifest, effective_uid)
        );
        assert_ne!(
            runtime,
            linux_short_runtime_path(&base, &second_state, &first_manifest, effective_uid)
        );
        assert_ne!(
            runtime,
            linux_short_runtime_path(&base, &first_state, &second_manifest, effective_uid)
        );
        assert_ne!(
            runtime,
            linux_short_runtime_path(
                &base,
                &first_state,
                &first_manifest,
                effective_uid.wrapping_add(1)
            )
        );
        assert_ne!(
            runtime,
            macos_short_home_path(&base, &first_state, &first_manifest, effective_uid),
            "Linux and macOS temporary namespaces must use different hash domains"
        );
        assert_eq!(runtime.parent(), Some(base.as_path()));
        assert_eq!(
            runtime.file_name().unwrap().as_bytes().len(),
            LINUX_SHORT_RUNTIME_PREFIX.len() + LINUX_SHORT_RUNTIME_DIGEST_HEX_CHARS
        );

        ensure_linux_short_runtime_directory_at(&runtime, &base, effective_uid)
            .expect("create short runtime");
        ensure_linux_short_runtime_directory_at(&runtime, &base, effective_uid)
            .expect("reuse short runtime");
        let metadata = fs::symlink_metadata(&runtime).unwrap();
        assert!(metadata.is_dir());
        assert!(!metadata.file_type().is_symlink());
        assert_eq!(metadata.uid(), effective_uid);
        assert_eq!(metadata.mode() & 0o7777, 0o700);

        let production_runtime = linux_short_runtime_path(
            Path::new(LINUX_SHORT_RUNTIME_BASE),
            &first_state,
            &first_manifest,
            effective_uid,
        );
        let longest_socket = linux_podman_gvproxy_socket_path(
            &production_runtime,
            &"m".repeat(MAX_MACHINE_NAME_BYTES),
        );
        assert_eq!(longest_socket.as_os_str().as_bytes().len(), 94);
        assert!(longest_socket.as_os_str().as_bytes().len() <= PODMAN_LINUX_MAX_SOCKET_PATH_BYTES);
    }

    #[cfg(unix)]
    #[test]
    fn linux_short_runtime_cleanup_is_exact_and_unsafe_entries_fail_closed() {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
        use std::os::unix::net::UnixListener;

        let temp = TempDir::new().expect("temporary root");
        let base = temp.path().join("short-runtimes");
        let state = temp.path().join("state");
        ensure_private_directory(&base).unwrap();
        ensure_private_directory(&state).unwrap();
        let state = canonical_real_directory(&state, "test state").unwrap();
        let effective_uid = effective_uid();

        let runtime = linux_short_runtime_path(&base, &state, &"a".repeat(64), effective_uid);
        ensure_linux_short_runtime_directory_at(&runtime, &base, effective_uid).unwrap();
        for (basename, mode) in [
            (PODMAN_LINUX_EAGER_STORAGE_DIRECTORY, 0o700),
            (PODMAN_LINUX_EAGER_LIBPOD_DIRECTORY, 0o1700),
        ] {
            let directory = runtime.join(basename);
            fs::create_dir(&directory).unwrap();
            fs::set_permissions(&directory, fs::Permissions::from_mode(mode)).unwrap();
        }
        let podman = runtime.join(PODMAN_LINUX_RUNTIME_DIRECTORY);
        fs::create_dir(&podman).unwrap();
        fs::set_permissions(&podman, fs::Permissions::from_mode(0o750)).unwrap();
        let log = podman.join(PODMAN_GVPROXY_LOG_NAME);
        fs::write(&log, b"pinned gvproxy log\n").unwrap();
        fs::set_permissions(&log, fs::Permissions::from_mode(0o644)).unwrap();
        let virtiofs_pid = podman.join(PODMAN_VIRTIOFS_PID_NAME);
        fs::write(&virtiofs_pid, b"12345\n").unwrap();
        fs::set_permissions(&virtiofs_pid, fs::Permissions::from_mode(0o600)).unwrap();
        let virtiofs_socket = podman.join(PODMAN_VIRTIOFS_SOCKET_NAME);
        let listener = UnixListener::bind(&virtiofs_socket).unwrap();
        drop(listener);
        fs::set_permissions(&virtiofs_socket, fs::Permissions::from_mode(0o700)).unwrap();
        remove_linux_short_runtime_directory_at(&runtime, &base, effective_uid)
            .expect("remove exact Podman, gvproxy, and unlocked virtiofsd residue");
        assert!(!private_entry_exists(&runtime).unwrap());

        let unexpected = linux_short_runtime_path(&base, &state, &"b".repeat(64), effective_uid);
        ensure_linux_short_runtime_directory_at(&unexpected, &base, effective_uid).unwrap();
        let podman = unexpected.join(PODMAN_LINUX_RUNTIME_DIRECTORY);
        fs::create_dir(&podman).unwrap();
        fs::set_permissions(&podman, fs::Permissions::from_mode(0o755)).unwrap();
        fs::write(podman.join("unexpected.sock"), b"must remain").unwrap();
        let error = remove_linux_short_runtime_directory_at(&unexpected, &base, effective_uid)
            .expect_err("unexpected Podman entry must fail closed");
        assert!(error.to_string().contains("unexpected entry"));
        assert_eq!(
            fs::read(podman.join("unexpected.sock")).unwrap(),
            b"must remain"
        );
        assert!(unexpected.is_dir());

        let legacy_storage_runtime =
            linux_short_runtime_path(&base, &state, &"1".repeat(64), effective_uid);
        ensure_linux_short_runtime_directory_at(&legacy_storage_runtime, &base, effective_uid)
            .unwrap();
        let legacy_storage = legacy_storage_runtime.join("containers");
        fs::create_dir(&legacy_storage).unwrap();
        fs::set_permissions(&legacy_storage, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(legacy_storage.join("must-remain"), b"legacy storage state").unwrap();
        let error =
            remove_linux_short_runtime_directory_at(&legacy_storage_runtime, &base, effective_uid)
                .expect_err("legacy containers/storage state must never be removed recursively");
        assert!(error.to_string().contains("was not empty"));
        assert_eq!(
            fs::read(legacy_storage.join("must-remain")).unwrap(),
            b"legacy storage state"
        );

        let linked_eager_runtime =
            linux_short_runtime_path(&base, &state, &"2".repeat(64), effective_uid);
        ensure_linux_short_runtime_directory_at(&linked_eager_runtime, &base, effective_uid)
            .unwrap();
        let outside_eager = temp.path().join("outside-eager-runtime");
        ensure_private_directory(&outside_eager).unwrap();
        fs::write(outside_eager.join("must-remain"), b"outside eager state").unwrap();
        symlink(
            &outside_eager,
            linked_eager_runtime.join(PODMAN_LINUX_EAGER_STORAGE_DIRECTORY),
        )
        .unwrap();
        let error =
            remove_linux_short_runtime_directory_at(&linked_eager_runtime, &base, effective_uid)
                .expect_err("an exact-name eager-runtime symlink must fail closed");
        assert!(error.to_string().contains("unsafe type"));
        assert_eq!(
            fs::read(outside_eager.join("must-remain")).unwrap(),
            b"outside eager state"
        );

        let wrong_mode_runtime =
            linux_short_runtime_path(&base, &state, &"3".repeat(64), effective_uid);
        ensure_linux_short_runtime_directory_at(&wrong_mode_runtime, &base, effective_uid).unwrap();
        let wrong_mode_libpod = wrong_mode_runtime.join(PODMAN_LINUX_EAGER_LIBPOD_DIRECTORY);
        fs::create_dir(&wrong_mode_libpod).unwrap();
        fs::set_permissions(&wrong_mode_libpod, fs::Permissions::from_mode(0o700)).unwrap();
        let error =
            remove_linux_short_runtime_directory_at(&wrong_mode_runtime, &base, effective_uid)
                .expect_err("libpod without its exact sticky mode must fail closed");
        assert!(error.to_string().contains("unsafe type"));
        assert!(wrong_mode_libpod.is_dir());

        let linked_log_runtime =
            linux_short_runtime_path(&base, &state, &"c".repeat(64), effective_uid);
        ensure_linux_short_runtime_directory_at(&linked_log_runtime, &base, effective_uid).unwrap();
        let podman = linked_log_runtime.join(PODMAN_LINUX_RUNTIME_DIRECTORY);
        fs::create_dir(&podman).unwrap();
        fs::set_permissions(&podman, fs::Permissions::from_mode(0o755)).unwrap();
        let outside = temp.path().join("outside-log");
        fs::write(&outside, b"outside remains").unwrap();
        symlink(&outside, podman.join(PODMAN_GVPROXY_LOG_NAME)).unwrap();
        assert!(
            remove_linux_short_runtime_directory_at(&linked_log_runtime, &base, effective_uid)
                .is_err()
        );
        assert_eq!(fs::read(&outside).unwrap(), b"outside remains");
        assert!(
            fs::symlink_metadata(podman.join(PODMAN_GVPROXY_LOG_NAME))
                .unwrap()
                .file_type()
                .is_symlink()
        );

        let hard_link_runtime =
            linux_short_runtime_path(&base, &state, &"d".repeat(64), effective_uid);
        ensure_linux_short_runtime_directory_at(&hard_link_runtime, &base, effective_uid).unwrap();
        let podman = hard_link_runtime.join(PODMAN_LINUX_RUNTIME_DIRECTORY);
        fs::create_dir(&podman).unwrap();
        fs::set_permissions(&podman, fs::Permissions::from_mode(0o755)).unwrap();
        let outside = temp.path().join("outside-hard-link");
        fs::write(&outside, b"hard link remains").unwrap();
        fs::hard_link(&outside, podman.join(PODMAN_GVPROXY_LOG_NAME)).unwrap();
        assert!(
            remove_linux_short_runtime_directory_at(&hard_link_runtime, &base, effective_uid)
                .is_err()
        );
        assert_eq!(fs::read(&outside).unwrap(), b"hard link remains");
        assert_eq!(
            fs::symlink_metadata(podman.join(PODMAN_GVPROXY_LOG_NAME))
                .unwrap()
                .nlink(),
            2
        );

        let locked_runtime =
            linux_short_runtime_path(&base, &state, &"e".repeat(64), effective_uid);
        ensure_linux_short_runtime_directory_at(&locked_runtime, &base, effective_uid).unwrap();
        let podman = locked_runtime.join(PODMAN_LINUX_RUNTIME_DIRECTORY);
        fs::create_dir(&podman).unwrap();
        fs::set_permissions(&podman, fs::Permissions::from_mode(0o755)).unwrap();
        let pid = podman.join(PODMAN_VIRTIOFS_PID_NAME);
        fs::write(&pid, b"12345\n").unwrap();
        fs::set_permissions(&pid, fs::Permissions::from_mode(0o600)).unwrap();
        let locked_pid = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&pid)
            .unwrap();
        // SAFETY: locked_pid owns a valid descriptor for this test fixture.
        assert_eq!(
            unsafe { libc::flock(locked_pid.as_raw_fd(), libc::LOCK_EX) },
            0
        );
        let started = Instant::now();
        let error = remove_expected_linux_virtiofs_residue(
            &podman,
            effective_uid,
            Duration::from_millis(50),
        )
        .expect_err("a live virtiofsd pid lock must not be removed");
        assert!(error.to_string().contains("remained live"));
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(pid.is_file());
        drop(locked_pid);
        remove_linux_short_runtime_directory_at(&locked_runtime, &base, effective_uid)
            .expect("cleanup succeeds after the exact pid lock is released");

        let unproven_socket_runtime =
            linux_short_runtime_path(&base, &state, &"f".repeat(64), effective_uid);
        ensure_linux_short_runtime_directory_at(&unproven_socket_runtime, &base, effective_uid)
            .unwrap();
        let podman = unproven_socket_runtime.join(PODMAN_LINUX_RUNTIME_DIRECTORY);
        fs::create_dir(&podman).unwrap();
        fs::set_permissions(&podman, fs::Permissions::from_mode(0o755)).unwrap();
        let socket = podman.join(PODMAN_VIRTIOFS_SOCKET_NAME);
        let listener = UnixListener::bind(&socket).unwrap();
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(
            remove_expected_linux_virtiofs_residue(
                &podman,
                effective_uid,
                Duration::from_millis(50)
            )
            .is_err()
        );
        assert!(socket.exists());
        drop(listener);

        let permissive = linux_short_runtime_path(&base, &state, &"e".repeat(64), effective_uid);
        fs::create_dir(&permissive).unwrap();
        fs::set_permissions(&permissive, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(
            ensure_linux_short_runtime_directory_at(&permissive, &base, effective_uid).is_err()
        );
        assert!(
            remove_linux_short_runtime_directory_at(&permissive, &base, effective_uid).is_err()
        );

        let linked = linux_short_runtime_path(&base, &state, &"0".repeat(64), effective_uid);
        let outside_directory = temp.path().join("outside-directory");
        ensure_private_directory(&outside_directory).unwrap();
        symlink(&outside_directory, &linked).unwrap();
        assert!(ensure_linux_short_runtime_directory_at(&linked, &base, effective_uid).is_err());
        assert!(remove_linux_short_runtime_directory_at(&linked, &base, effective_uid).is_err());
        assert!(
            fs::symlink_metadata(&linked)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert!(outside_directory.is_dir());

        let escaped = base.join("nested").join("assm1-escaped");
        assert!(ensure_linux_short_runtime_directory_at(&escaped, &base, effective_uid).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn macos_short_home_is_stable_private_and_keeps_the_longest_socket_alias_bounded() {
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::MetadataExt;

        let temp = TempDir::new().expect("temporary root");
        let base = temp.path().join("short-homes");
        let first_state = temp.path().join("first-state");
        let second_state = temp.path().join("second-state");
        for directory in [&base, &first_state, &second_state] {
            ensure_private_directory(directory).expect("private directory");
        }
        let first_state = canonical_real_directory(&first_state, "first test state").unwrap();
        let second_state = canonical_real_directory(&second_state, "second test state").unwrap();
        // SAFETY: geteuid has no preconditions and does not dereference memory.
        let effective_uid = unsafe { libc::geteuid() };
        let first_manifest = "a".repeat(64);
        let second_manifest = "b".repeat(64);

        let home = macos_short_home_path(&base, &first_state, &first_manifest, effective_uid);
        assert_eq!(
            home,
            macos_short_home_path(&base, &first_state, &first_manifest, effective_uid)
        );
        assert_ne!(
            home,
            macos_short_home_path(&base, &second_state, &first_manifest, effective_uid)
        );
        assert_ne!(
            home,
            macos_short_home_path(&base, &first_state, &second_manifest, effective_uid)
        );
        assert_eq!(home.parent(), Some(base.as_path()));
        assert_eq!(
            home.file_name().unwrap().as_bytes().len(),
            MACOS_SHORT_HOME_PREFIX.len() + MACOS_SHORT_HOME_DIGEST_HEX_CHARS
        );

        ensure_macos_short_home_directory(&home, effective_uid).expect("create short home");
        ensure_macos_short_home_directory(&home, effective_uid).expect("reuse short home");
        let metadata = fs::symlink_metadata(&home).unwrap();
        assert!(metadata.is_dir());
        assert!(!metadata.file_type().is_symlink());
        assert_eq!(metadata.uid(), effective_uid);
        assert_eq!(metadata.mode() & 0o7777, 0o700);

        let production_home = macos_short_home_path(
            Path::new(MACOS_SHORT_HOME_BASE),
            &first_state,
            &first_manifest,
            effective_uid,
        );
        let longest_alias = macos_podman_ignition_socket_alias(
            &production_home,
            &"m".repeat(MAX_MACHINE_NAME_BYTES),
        );
        assert_eq!(longest_alias.as_os_str().as_bytes().len(), 96);
        assert!(longest_alias.as_os_str().as_bytes().len() <= PODMAN_MACOS_MAX_SOCKET_PATH_BYTES);
    }

    #[cfg(unix)]
    #[test]
    fn macos_short_home_cleanup_is_exact_and_unsafe_preexisting_entries_fail_closed() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        use std::os::unix::net::UnixListener;

        let temp = TempDir::new().expect("temporary root");
        let base = temp.path().join("s");
        let state = temp.path().join("state");
        ensure_private_directory(&base).unwrap();
        ensure_private_directory(&state).unwrap();
        let state = canonical_real_directory(&state, "test state").unwrap();
        // SAFETY: geteuid has no preconditions and does not dereference memory.
        let effective_uid = unsafe { libc::geteuid() };
        let machine_name = "m";
        let seed_known_hosts = |home: &Path, contents: &[u8], mode: u32| {
            let ssh_directory = home.join(PODMAN_MACOS_SSH_DIRECTORY);
            ensure_private_directory(&ssh_directory).unwrap();
            let known_hosts = ssh_directory.join(PODMAN_MACOS_KNOWN_HOSTS_FILE);
            fs::write(&known_hosts, contents).unwrap();
            fs::set_permissions(&known_hosts, fs::Permissions::from_mode(mode)).unwrap();
            known_hosts
        };

        let home = macos_short_home_path(&base, &state, &"a".repeat(64), effective_uid);
        ensure_macos_short_home_directory(&home, effective_uid).unwrap();
        let aliases = home.join(".podman");
        ensure_private_directory(&aliases).unwrap();
        remove_macos_short_home_directory_at(&home, &base, effective_uid, machine_name)
            .expect("remove empty exact home after machine removal");
        assert!(!private_entry_exists(&home).unwrap());

        let socket_home = macos_short_home_path(&base, &state, &"d".repeat(64), effective_uid);
        ensure_macos_short_home_directory(&socket_home, effective_uid).unwrap();
        let aliases = socket_home.join(".podman");
        ensure_private_directory(&aliases).unwrap();
        let exact_socket = macos_podman_ignition_socket_alias(&socket_home, machine_name);
        let listener = UnixListener::bind(&exact_socket).unwrap();
        drop(listener);
        remove_macos_short_home_directory_at(&socket_home, &base, effective_uid, machine_name)
            .expect("remove exact stale pinned-Podman ignition socket and short home");
        assert!(!private_entry_exists(&socket_home).unwrap());

        let ssh_home = macos_short_home_path(&base, &state, &"1".repeat(64), effective_uid);
        ensure_macos_short_home_directory(&ssh_home, effective_uid).unwrap();
        let known_hosts = seed_known_hosts(&ssh_home, b"", 0o600);
        let metadata = fs::symlink_metadata(&known_hosts).unwrap();
        assert!(metadata.is_file());
        assert_eq!(metadata.len(), 0);
        remove_macos_short_home_directory_at(&ssh_home, &base, effective_uid, machine_name)
            .expect("remove exact pinned-Podman empty known_hosts residue and short home");
        assert!(!private_entry_exists(&ssh_home).unwrap());

        let combined_home = macos_short_home_path(&base, &state, &"ab".repeat(32), effective_uid);
        ensure_macos_short_home_directory(&combined_home, effective_uid).unwrap();
        let combined_aliases = combined_home.join(".podman");
        ensure_private_directory(&combined_aliases).unwrap();
        let combined_socket = macos_podman_ignition_socket_alias(&combined_home, machine_name);
        let listener = UnixListener::bind(&combined_socket).unwrap();
        drop(listener);
        seed_known_hosts(&combined_home, b"", 0o600);
        remove_macos_short_home_directory_at(&combined_home, &base, effective_uid, machine_name)
            .expect("remove both exact pinned-Podman residue namespaces");
        assert!(!private_entry_exists(&combined_home).unwrap());

        let unexpected = macos_short_home_path(&base, &state, &"d".repeat(64), effective_uid);
        ensure_macos_short_home_directory(&unexpected, effective_uid).unwrap();
        let aliases = unexpected.join(".podman");
        ensure_private_directory(&aliases).unwrap();
        let outside = temp.path().join("outside-socket-target");
        fs::write(&outside, b"must remain").unwrap();
        symlink(&outside, aliases.join("owned-alias.sock")).unwrap();

        // Ordinary stop/update does not invoke cleanup; the stable namespace
        // and any live socket aliases remain available until machine removal.
        assert!(unexpected.is_dir());
        let error =
            remove_macos_short_home_directory_at(&unexpected, &base, effective_uid, machine_name)
                .expect_err("unexpected alias entry must fail closed");
        assert!(error.to_string().contains("unexpected entry"));
        assert_eq!(fs::read(&outside).unwrap(), b"must remain");
        assert!(unexpected.is_dir());

        let linked_alias_home =
            macos_short_home_path(&base, &state, &"e".repeat(64), effective_uid);
        ensure_macos_short_home_directory(&linked_alias_home, effective_uid).unwrap();
        let aliases = linked_alias_home.join(".podman");
        ensure_private_directory(&aliases).unwrap();
        let exact_alias = macos_podman_ignition_socket_alias(&linked_alias_home, machine_name);
        symlink(&outside, &exact_alias).unwrap();
        let error = remove_macos_short_home_directory_at(
            &linked_alias_home,
            &base,
            effective_uid,
            machine_name,
        )
        .expect_err("an exact-name symlink must not be treated as Podman's socket residue");
        assert!(error.to_string().contains("single-link Unix socket"));
        assert!(
            fs::symlink_metadata(&exact_alias)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(fs::read(&outside).unwrap(), b"must remain");

        let regular_alias_home =
            macos_short_home_path(&base, &state, &"f".repeat(64), effective_uid);
        ensure_macos_short_home_directory(&regular_alias_home, effective_uid).unwrap();
        let aliases = regular_alias_home.join(".podman");
        ensure_private_directory(&aliases).unwrap();
        let exact_alias = macos_podman_ignition_socket_alias(&regular_alias_home, machine_name);
        fs::write(&exact_alias, b"must remain").unwrap();
        assert!(
            remove_macos_short_home_directory_at(
                &regular_alias_home,
                &base,
                effective_uid,
                machine_name,
            )
            .is_err()
        );
        assert_eq!(fs::read(&exact_alias).unwrap(), b"must remain");

        let extra_entry_home = macos_short_home_path(&base, &state, &"0".repeat(64), effective_uid);
        ensure_macos_short_home_directory(&extra_entry_home, effective_uid).unwrap();
        let aliases = extra_entry_home.join(".podman");
        ensure_private_directory(&aliases).unwrap();
        let exact_socket = macos_podman_ignition_socket_alias(&extra_entry_home, machine_name);
        let listener = UnixListener::bind(&exact_socket).unwrap();
        drop(listener);
        fs::write(aliases.join("unexpected"), b"must remain").unwrap();
        assert!(
            remove_macos_short_home_directory_at(
                &extra_entry_home,
                &base,
                effective_uid,
                machine_name,
            )
            .is_err()
        );
        assert!(private_entry_exists(&exact_socket).unwrap());
        assert_eq!(
            fs::read(aliases.join("unexpected")).unwrap(),
            b"must remain"
        );

        let root_extra_home = macos_short_home_path(&base, &state, &"2".repeat(64), effective_uid);
        ensure_macos_short_home_directory(&root_extra_home, effective_uid).unwrap();
        let root_extra_aliases = root_extra_home.join(".podman");
        ensure_private_directory(&root_extra_aliases).unwrap();
        fs::write(root_extra_home.join("unexpected"), b"must remain").unwrap();
        let error = remove_macos_short_home_directory_at(
            &root_extra_home,
            &base,
            effective_uid,
            machine_name,
        )
        .expect_err("an unknown root entry must fail before recognized residue is removed");
        assert!(error.to_string().contains("unexpected entry"));
        assert!(root_extra_aliases.is_dir());
        assert_eq!(
            fs::read(root_extra_home.join("unexpected")).unwrap(),
            b"must remain"
        );

        let linked_ssh_home = macos_short_home_path(&base, &state, &"3".repeat(64), effective_uid);
        ensure_macos_short_home_directory(&linked_ssh_home, effective_uid).unwrap();
        let outside_ssh_directory = temp.path().join("outside-ssh-directory");
        ensure_private_directory(&outside_ssh_directory).unwrap();
        fs::write(
            outside_ssh_directory.join("must-remain"),
            b"outside ssh state",
        )
        .unwrap();
        symlink(
            &outside_ssh_directory,
            linked_ssh_home.join(PODMAN_MACOS_SSH_DIRECTORY),
        )
        .unwrap();
        let error = remove_macos_short_home_directory_at(
            &linked_ssh_home,
            &base,
            effective_uid,
            machine_name,
        )
        .expect_err("an exact-name .ssh symlink must fail closed");
        assert!(error.to_string().contains("unsafe type"));
        assert_eq!(
            fs::read(outside_ssh_directory.join("must-remain")).unwrap(),
            b"outside ssh state"
        );

        let linked_known_hosts_home =
            macos_short_home_path(&base, &state, &"4".repeat(64), effective_uid);
        ensure_macos_short_home_directory(&linked_known_hosts_home, effective_uid).unwrap();
        let linked_known_hosts_directory = linked_known_hosts_home.join(PODMAN_MACOS_SSH_DIRECTORY);
        ensure_private_directory(&linked_known_hosts_directory).unwrap();
        symlink(
            &outside,
            linked_known_hosts_directory.join(PODMAN_MACOS_KNOWN_HOSTS_FILE),
        )
        .unwrap();
        let error = remove_macos_short_home_directory_at(
            &linked_known_hosts_home,
            &base,
            effective_uid,
            machine_name,
        )
        .expect_err("an exact-name known_hosts symlink must fail closed");
        assert!(error.to_string().contains("empty regular file"));
        assert_eq!(fs::read(&outside).unwrap(), b"must remain");

        let hardlinked_known_hosts_home =
            macos_short_home_path(&base, &state, &"5".repeat(64), effective_uid);
        ensure_macos_short_home_directory(&hardlinked_known_hosts_home, effective_uid).unwrap();
        let hardlinked_known_hosts_directory =
            hardlinked_known_hosts_home.join(PODMAN_MACOS_SSH_DIRECTORY);
        ensure_private_directory(&hardlinked_known_hosts_directory).unwrap();
        let outside_hardlink = temp.path().join("outside-known-hosts-hardlink");
        fs::write(&outside_hardlink, b"").unwrap();
        fs::set_permissions(&outside_hardlink, fs::Permissions::from_mode(0o600)).unwrap();
        let hardlinked_known_hosts =
            hardlinked_known_hosts_directory.join(PODMAN_MACOS_KNOWN_HOSTS_FILE);
        fs::hard_link(&outside_hardlink, &hardlinked_known_hosts).unwrap();
        let error = remove_macos_short_home_directory_at(
            &hardlinked_known_hosts_home,
            &base,
            effective_uid,
            machine_name,
        )
        .expect_err("a multiply-linked known_hosts file must fail closed");
        assert!(error.to_string().contains("single-link"));
        assert!(hardlinked_known_hosts.is_file());
        assert!(outside_hardlink.is_file());

        let nonempty_known_hosts_home =
            macos_short_home_path(&base, &state, &"6".repeat(64), effective_uid);
        ensure_macos_short_home_directory(&nonempty_known_hosts_home, effective_uid).unwrap();
        let nonempty_known_hosts =
            seed_known_hosts(&nonempty_known_hosts_home, b"must remain", 0o600);
        let error = remove_macos_short_home_directory_at(
            &nonempty_known_hosts_home,
            &base,
            effective_uid,
            machine_name,
        )
        .expect_err("a nonempty known_hosts file must fail closed");
        assert!(error.to_string().contains("empty regular file"));
        assert_eq!(fs::read(nonempty_known_hosts).unwrap(), b"must remain");

        let wrong_mode_known_hosts_home =
            macos_short_home_path(&base, &state, &"7".repeat(64), effective_uid);
        ensure_macos_short_home_directory(&wrong_mode_known_hosts_home, effective_uid).unwrap();
        let wrong_mode_known_hosts = seed_known_hosts(&wrong_mode_known_hosts_home, b"", 0o644);
        let error = remove_macos_short_home_directory_at(
            &wrong_mode_known_hosts_home,
            &base,
            effective_uid,
            machine_name,
        )
        .expect_err("known_hosts without exact mode 0600 must fail closed");
        assert!(error.to_string().contains("mode-0600"));
        assert!(wrong_mode_known_hosts.is_file());

        let extra_ssh_entry_home =
            macos_short_home_path(&base, &state, &"8".repeat(64), effective_uid);
        ensure_macos_short_home_directory(&extra_ssh_entry_home, effective_uid).unwrap();
        let exact_known_hosts = seed_known_hosts(&extra_ssh_entry_home, b"", 0o600);
        let extra_ssh_entry = extra_ssh_entry_home
            .join(PODMAN_MACOS_SSH_DIRECTORY)
            .join("unexpected");
        fs::write(&extra_ssh_entry, b"must remain").unwrap();
        let error = remove_macos_short_home_directory_at(
            &extra_ssh_entry_home,
            &base,
            effective_uid,
            machine_name,
        )
        .expect_err("an extra .ssh entry must fail closed");
        assert!(error.to_string().contains("exactly the expected"));
        assert!(exact_known_hosts.is_file());
        assert_eq!(fs::read(extra_ssh_entry).unwrap(), b"must remain");

        let permissive_ssh_home =
            macos_short_home_path(&base, &state, &"9".repeat(64), effective_uid);
        ensure_macos_short_home_directory(&permissive_ssh_home, effective_uid).unwrap();
        let permissive_known_hosts = seed_known_hosts(&permissive_ssh_home, b"", 0o600);
        let permissive_ssh_directory = permissive_ssh_home.join(PODMAN_MACOS_SSH_DIRECTORY);
        fs::set_permissions(&permissive_ssh_directory, fs::Permissions::from_mode(0o755)).unwrap();
        let error = remove_macos_short_home_directory_at(
            &permissive_ssh_home,
            &base,
            effective_uid,
            machine_name,
        )
        .expect_err("a permissive .ssh directory must fail closed");
        assert!(error.to_string().contains("unsafe type"));
        assert!(permissive_known_hosts.is_file());

        let permissive = macos_short_home_path(&base, &state, &"b".repeat(64), effective_uid);
        fs::create_dir(&permissive).unwrap();
        fs::set_permissions(&permissive, fs::Permissions::from_mode(0o755)).unwrap();
        let error = ensure_macos_short_home_directory(&permissive, effective_uid)
            .expect_err("permissive preexisting directory must fail closed");
        assert!(
            error
                .to_string()
                .contains("unsafe ownership or permissions")
        );
        assert!(
            remove_macos_short_home_directory_at(&permissive, &base, effective_uid, machine_name)
                .is_err()
        );
        assert!(permissive.is_dir());

        let linked = macos_short_home_path(&base, &state, &"c".repeat(64), effective_uid);
        let outside_directory = temp.path().join("outside-directory");
        ensure_private_directory(&outside_directory).unwrap();
        symlink(&outside_directory, &linked).unwrap();
        assert!(ensure_macos_short_home_directory(&linked, effective_uid).is_err());
        assert!(
            remove_macos_short_home_directory_at(&linked, &base, effective_uid, machine_name)
                .is_err()
        );
        assert!(
            fs::symlink_metadata(&linked)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert!(outside_directory.is_dir());
    }

    fn tamper_installed_driver(manager: &ManagedRuntimeManager) {
        let installed = manager.install_directory().join("bin/podman");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&installed, fs::Permissions::from_mode(0o600))
                .expect("make test payload writable");
        }
        fs::write(installed, b"tampered-runtime").expect("tamper installed payload");
    }

    #[test]
    fn manifest_schema_evolution_keeps_v2_strict_and_requires_a_real_v3_revision() {
        let fixture = fixture();

        let mut legacy = fixture.manager.loaded.manifest.clone();
        legacy.schema_version = LEGACY_MANIFEST_SCHEMA_VERSION.into();
        legacy.management_contract_revision = None;
        let legacy_bytes = serde_json::to_vec(&legacy).expect("legacy manifest");
        let legacy_json: serde_json::Value =
            serde_json::from_slice(&legacy_bytes).expect("legacy JSON");
        assert!(legacy_json.get("management_contract_revision").is_none());
        let loaded_legacy = LoadedManagedRuntimeManifest::parse(&legacy_bytes)
            .expect("strict schema 2 remains readable");
        assert!(validate_current_release_manifest(&loaded_legacy.manifest).is_err());

        legacy.management_contract_revision = Some(MANAGEMENT_CONTRACT_REVISION.into());
        let mixed_legacy = serde_json::to_vec(&legacy).expect("mixed legacy manifest");
        assert!(LoadedManagedRuntimeManifest::parse(&mixed_legacy).is_err());

        let mut current = fixture.manager.loaded.manifest.clone();
        current.management_contract_revision = None;
        let missing_revision = serde_json::to_vec(&current).expect("missing revision manifest");
        assert!(LoadedManagedRuntimeManifest::parse(&missing_revision).is_err());

        for invalid in [
            "2026-02-30.1",
            "2026-08-29.0",
            "2026-08-29.01",
            "2026-8-29.1",
            "2026-08-30.1",
            "not-a-revision",
        ] {
            current.management_contract_revision = Some(invalid.into());
            let bytes = serde_json::to_vec(&current).expect("invalid revision manifest");
            assert!(
                LoadedManagedRuntimeManifest::parse(&bytes).is_err(),
                "invalid management contract revision was accepted: {invalid}"
            );
        }
    }

    #[test]
    fn current_bundle_open_rejects_a_legacy_v2_resource_manifest() {
        let mut legacy = fixture().manager.loaded.manifest.clone();
        legacy.schema_version = LEGACY_MANIFEST_SCHEMA_VERSION.into();
        legacy.management_contract_revision = None;
        let temporary = managed_runtime_fixture_tempdir();
        let app_data = temporary.path().join("app-data");
        let resources = temporary.path().join("resources");
        ensure_private_directory(&app_data).expect("private app data");
        ensure_private_directory(&resources).expect("private resources");
        fs::create_dir(resources.join("bin")).expect("bundle bin");
        fs::write(resources.join("bin/podman"), b"managed-podman-driver").expect("bundle driver");
        let manifest_path = resources.join("manifest.json");
        fs::write(
            &manifest_path,
            serde_json::to_vec(&legacy).expect("legacy manifest"),
        )
        .expect("legacy resource manifest");

        let error = ManagedRuntimeManager::open(&app_data, &resources, &manifest_path)
            .expect_err("v0.1.8 must not open schema 2 as its bundled resource");
        assert!(error.to_string().contains("exact management contract"));
    }

    #[test]
    fn manifest_rejects_traversal_duplicate_targets_and_unapproved_downloads() {
        let fixture = fixture();
        let mut manifest = fixture.manager.loaded.manifest.clone();
        manifest.files[0].path = "../podman".into();
        let bytes = serde_json::to_vec(&manifest).expect("manifest");
        assert!(LoadedManagedRuntimeManifest::parse(&bytes).is_err());

        let mut manifest = fixture.manager.loaded.manifest.clone();
        manifest.targets.push(manifest.targets[0].clone());
        let bytes = serde_json::to_vec(&manifest).expect("manifest");
        assert!(LoadedManagedRuntimeManifest::parse(&bytes).is_err());

        let mut manifest = fixture.manager.loaded.manifest.clone();
        manifest.targets[0].machine_image.url = "https://example.com/machine.zst".into();
        let bytes = serde_json::to_vec(&manifest).expect("manifest");
        assert!(LoadedManagedRuntimeManifest::parse(&bytes).is_err());
    }

    #[test]
    fn install_is_private_hash_verified_and_idempotent() {
        let fixture = fixture();
        let first = fixture.manager.install().expect("install");
        assert_eq!(first.phase, ManagedRuntimePhase::Installed);
        let installed = fixture.manager.install_directory().join("bin/podman");
        verify_file_hash_size(
            &installed,
            b"managed-podman-driver".len() as u64,
            &sha256_bytes(b"managed-podman-driver"),
            "test driver",
        )
        .expect("verified");
        fixture.manager.install().expect("idempotent");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(installed)
                    .expect("metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o500
            );
        }
    }

    #[test]
    fn interrupted_install_staging_does_not_wedge_recovery_and_is_cleaned_exactly() {
        let fixture = fixture();
        fixture.manager.install().expect("install current payload");
        let versions = fixture.manager.versions_root();
        let expected_digest = fixture.manager.manifest_sha256().to_owned();
        let app_data = fixture
            .manager
            .state_root
            .parent()
            .expect("application data parent")
            .to_path_buf();
        let mut abandoned = Vec::new();
        for _ in 0..=MAX_INSTALLED_VERSIONS {
            let path = versions.join(format!(".installing-{}", Uuid::new_v4()));
            ensure_managed_private_directory(&path).expect("abandoned private staging directory");
            abandoned.push(path);
        }

        let reopened = ManagedRuntimeManager::open_installed(&app_data, Some(&expected_digest))
            .expect("exact committed payload remains recoverable despite abandoned staging");
        assert_eq!(reopened.manifest_sha256(), expected_digest);
        drop(reopened);

        let malformed = versions.join(".installing-not-a-product-uuid");
        ensure_managed_private_directory(&malformed).expect("ambiguous similar sibling");
        let uppercase = versions.join(format!(
            ".installing-{}",
            Uuid::new_v4().hyphenated().to_string().to_ascii_uppercase()
        ));
        ensure_managed_private_directory(&uppercase).expect("noncanonical similar sibling");

        fixture
            .manager
            .install()
            .expect("retry cleans only exact abandoned product staging");
        assert!(abandoned.iter().all(|path| !path.exists()));
        assert!(malformed.is_dir());
        assert!(uppercase.is_dir());
        assert!(fixture.manager.install_directory().is_dir());
    }

    #[test]
    fn windows_registry_string_accepts_a_bounded_size_probe_overestimate_only_when_reads_stabilize()
    {
        let mut first = "C:\\Users\\runner\\AppData\\Local\\Packages"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        let returned_bytes = u32::try_from(first.len() * 2).unwrap();
        first.extend([0x1111, 0x2222, 0x3333]);
        let mut second = first.clone();
        second[first.len() - 1] = 0x4444;

        assert_eq!(
            decode_stable_windows_registry_string_reads(
                &first,
                returned_bytes,
                &second,
                returned_bytes,
            )
            .unwrap(),
            "C:\\Users\\runner\\AppData\\Local\\Packages"
        );

        second[0] = 'D' as u16;
        assert!(
            decode_stable_windows_registry_string_reads(
                &first,
                returned_bytes,
                &second,
                returned_bytes,
            )
            .unwrap_err()
            .to_string()
            .contains("changed while it was read")
        );
    }

    #[test]
    fn windows_registry_string_rejects_unbounded_or_malformed_reads() {
        for (encoded, returned_bytes) in [
            (vec![0], 0),
            (vec!['A' as u16, 0], 3),
            (vec!['A' as u16, 'B' as u16], 4),
            (vec!['A' as u16, 0, 'B' as u16, 0], 8),
            (vec![0xd800, 0], 4),
            (vec!['A' as u16, 0], 6),
            (vec![0], MAX_WINDOWS_REGISTRY_STRING_BYTES + 2),
        ] {
            assert!(
                decode_windows_registry_string_read(&encoded, returned_bytes).is_err(),
                "accepted malformed registry read {encoded:?} / {returned_bytes}"
            );
        }
    }

    #[test]
    fn windows_wsl_inventory_parser_accepts_strict_utf8_and_utf16le_only() {
        assert!(
            parse_windows_wsl_distribution_inventory(b"")
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            parse_windows_wsl_distribution_inventory(
                b"\xef\xbb\xbfpodman-assm1-win-x64-0123456789ab\r\nUbuntu\n"
            )
            .unwrap(),
            ["podman-assm1-win-x64-0123456789ab", "Ubuntu"]
        );
        let utf16 = utf16le("podman-assm1-win-x64-0123456789ab\r\nUbuntu\r\n");
        assert_eq!(
            parse_windows_wsl_distribution_inventory(&utf16).unwrap(),
            ["podman-assm1-win-x64-0123456789ab", "Ubuntu"]
        );
        let mut utf16_with_bom = vec![0xff, 0xfe];
        utf16_with_bom.extend_from_slice(&utf16);
        assert_eq!(
            parse_windows_wsl_distribution_inventory(&utf16_with_bom).unwrap(),
            ["podman-assm1-win-x64-0123456789ab", "Ubuntu"]
        );
        for malformed in [
            vec![0xfe, 0xff, 0, b'A'],
            vec![0xff, 0xfe, b'A'],
            b" podman-assm1-win-x64-0123456789ab\n".to_vec(),
            b"podman-assm1-win-x64-0123456789ab\0\n".to_vec(),
            b"podman-assm1-win-x64-0123456789ab\n\n".to_vec(),
        ] {
            assert!(parse_windows_wsl_distribution_inventory(&malformed).is_err());
        }
        assert!(
            parse_windows_wsl_distribution_inventory(
                &vec!["A"; MAX_WSL_DISTRIBUTIONS + 1].join("\n").into_bytes(),
            )
            .is_err()
        );
        assert!(
            parse_windows_wsl_distribution_inventory(&vec![
                b'A';
                MAX_COMMAND_OUTPUT_BYTES as usize + 1
            ])
            .is_err()
        );
    }

    #[test]
    fn windows_wsl_registration_path_requires_the_exact_product_private_shape() {
        let root =
            PathBuf::from("C:/Users/alice/AppData/Local/ai-security-scanner/managed-runtime");
        let machine = "assm1-win-x64-0123456789ab";
        let provider = root.join("provider-home").join("0123456789abcdef");
        let exact = provider
            .join("data/containers/podman/machine/wsl/wsldist")
            .join(machine);
        assert_eq!(
            windows_wsl_provider_home_from_registration_path(&root, &exact, machine).unwrap(),
            provider
        );

        let isolated_provider = root.join("provider-home").join("01234567-iso-89abcdef0123");
        let isolated_machine = "assm2-iso-0123456789abcdef0123";
        let isolated = isolated_provider
            .join("data/containers/podman/machine/wsl/wsldist")
            .join(isolated_machine);
        assert_eq!(
            windows_wsl_provider_home_from_registration_path(&root, &isolated, isolated_machine,)
                .unwrap(),
            isolated_provider
        );

        for invalid in [
            root.join("provider-home/not-a-digest/data/containers/podman/machine/wsl/wsldist")
                .join(machine),
            root.join("provider-home/0123456g-iso-89abcdef0123/data/containers/podman/machine/wsl/wsldist")
                .join(isolated_machine),
            root.join("provider-home/01234567-iso-89abcdef012/data/containers/podman/machine/wsl/wsldist")
                .join(isolated_machine),
            root.join("provider-home/0123456789abcdef/data/containers/podman/machine/wsl/wsldist")
                .join("podman-user-owned"),
            root.join("provider-home/0123456789abcdef/data/containers/podman/machine/wsl/wsldist")
                .join(machine)
                .join("nested"),
            PathBuf::from("C:/Users/alice/unrelated").join(machine),
        ] {
            assert!(
                windows_wsl_provider_home_from_registration_path(&root, &invalid, machine).is_err(),
                "accepted unsafe registration path {invalid:?}"
            );
        }
    }
    #[test]
    fn windows_console_diagnostics_decode_utf16le_and_reject_mixed_garbage() {
        let localized =
            "Windows 子系統尚未就緒。\r\nError code: Wsl/WSL_E_WSL_OPTIONAL_COMPONENT_REQUIRED\r\n";
        assert_eq!(
            safe_command_diagnostic(&utf16le(localized)).as_deref(),
            Some("Windows 子系統尚未就緒。 Error code: Wsl/WSL_E_WSL_OPTIONAL_COMPONENT_REQUIRED")
        );
        let mut bom = vec![0xff, 0xfe];
        bom.extend_from_slice(&utf16le(localized));
        assert!(
            safe_command_diagnostic(&bom)
                .expect("UTF-16LE BOM diagnostic")
                .contains("Windows 子系統")
        );
        assert_eq!(
            safe_command_diagnostic(b"plain UTF-8 diagnostic\r\nsecond line").as_deref(),
            Some("plain UTF-8 diagnostic second line")
        );

        let mut mixed = b"Error command C:\\Windows\\System32\\wsl.exe: ".to_vec();
        mixed.extend_from_slice(&utf16le("子系統尚未就緒"));
        assert!(safe_command_diagnostic(&mixed).is_none());
        assert!(safe_command_diagnostic(b"unsafe\0control").is_none());

        let output = failure(mixed);
        let error = require_success("managed runtime machine initialization", &output)
            .expect_err("mixed console encodings must fail without raw output");
        let message = error.to_string();
        assert!(message.contains("No readable diagnostic was returned"));
        assert!(!message.contains("wsl.exe"));
        assert!(!message.contains(['\0', '\u{fffd}']));
    }

    #[test]
    fn windows_wsl_prerequisite_classifier_maps_stable_codes_to_actions() {
        let cases = [
            (
                "錯誤碼: Wsl/WSL_E_WSL_NOT_INSTALLED",
                ManagedRuntimeSetupFailureReason::WslNotInstalled,
                ManagedRuntimeSetupNextAction::InstallWsl,
            ),
            (
                "請執行 wsl.exe --install。https://aka.ms/wslinstall",
                ManagedRuntimeSetupFailureReason::WslNotInstalled,
                ManagedRuntimeSetupNextAction::InstallWsl,
            ),
            (
                "錯誤碼: Wsl/WSL_E_WSL_OPTIONAL_COMPONENT_REQUIRED",
                ManagedRuntimeSetupFailureReason::WslOptionalFeatureDisabled,
                ManagedRuntimeSetupNextAction::EnableWslOptionalFeatures,
            ),
            (
                "錯誤: 0x800701bc",
                ManagedRuntimeSetupFailureReason::WslUpdateRequired,
                ManagedRuntimeSetupNextAction::UpdateWsl,
            ),
            (
                "Error code: Wsl/WSL_E_INVALID_USAGE",
                ManagedRuntimeSetupFailureReason::WslUpdateRequired,
                ManagedRuntimeSetupNextAction::UpdateWsl,
            ),
            (
                "Error: ERROR_SUCCESS_REBOOT_REQUIRED",
                ManagedRuntimeSetupFailureReason::RestartRequired,
                ManagedRuntimeSetupNextAction::RestartWindows,
            ),
            (
                "Error code: Wsl/Service/E_UNEXPECTED",
                ManagedRuntimeSetupFailureReason::WslCommandFailed,
                ManagedRuntimeSetupNextAction::RetryWslCheck,
            ),
        ];

        for (diagnostic, reason, action) in cases {
            let output = failure(utf16le(diagnostic));
            let classified = classify_windows_wsl_prerequisite_failure(&output);
            assert_eq!(classified.reason, reason, "{diagnostic}");
            assert_eq!(classified.action, action, "{diagnostic}");
            assert_eq!(classified.exit_code, Some(1));
        }
    }

    #[test]
    fn installer_prerequisite_coordinator_is_zero_input_and_reprobes_after_service() {
        let probes = Mutex::new(VecDeque::from([
            Err(WindowsWslPrerequisiteFailure::not_installed(Some(1))),
            Ok(()),
        ]));
        let actions = Mutex::new(Vec::new());
        let result = coordinate_windows_installer_prerequisite(
            || probes.lock().unwrap().pop_front().expect("bounded probe"),
            |action| {
                actions.lock().unwrap().push(action);
                Ok(ManagedRuntimePrerequisiteRepairResult {
                    outcome: ManagedRuntimePrerequisiteRepairOutcome::Completed,
                    restart_required: false,
                    detail: "serviced".into(),
                })
            },
        )
        .expect("coordinator");

        assert_eq!(result.class, WindowsInstallerPrerequisiteClass::Serviced);
        assert_eq!(
            actions.into_inner().unwrap(),
            [ManagedRuntimeSetupNextAction::InstallWsl]
        );
        assert!(probes.into_inner().unwrap().is_empty());
    }

    #[test]
    fn installer_prerequisite_coordinator_never_services_restart_or_unknown_failure() {
        for (failure, expected) in [
            (
                WindowsWslPrerequisiteFailure::restart_required(Some(3010)),
                WindowsInstallerPrerequisiteClass::RestartRequired,
            ),
            (
                WindowsWslPrerequisiteFailure::command_failed(Some(125)),
                WindowsInstallerPrerequisiteClass::Failed,
            ),
        ] {
            let repair_calls = AtomicU64::new(0);
            let result = coordinate_windows_installer_prerequisite(
                || Err(failure),
                |_| {
                    repair_calls.fetch_add(1, Ordering::AcqRel);
                    unreachable!("restart/unknown failure cannot select a servicing action")
                },
            )
            .expect("terminal classification");
            assert_eq!(result.class, expected);
            assert_eq!(repair_calls.load(Ordering::Acquire), 0);
        }
    }

    #[test]
    fn installer_prerequisite_coordinator_preserves_cancel_as_terminal() {
        let result = coordinate_windows_installer_prerequisite(
            || Err(WindowsWslPrerequisiteFailure::update_required(Some(1))),
            |action| {
                assert_eq!(action, ManagedRuntimeSetupNextAction::UpdateWsl);
                Ok(ManagedRuntimePrerequisiteRepairResult {
                    outcome: ManagedRuntimePrerequisiteRepairOutcome::Cancelled,
                    restart_required: false,
                    detail: "cancelled".into(),
                })
            },
        )
        .expect("cancelled classification");
        assert_eq!(result.class, WindowsInstallerPrerequisiteClass::Cancelled);
        assert_eq!(result.detail, "cancelled");
    }

    #[test]
    fn windows_prerequisite_details_never_assign_wsl_administration_to_the_user() {
        for failure in [
            WindowsWslPrerequisiteFailure::not_installed(Some(1)),
            WindowsWslPrerequisiteFailure::optional_feature_disabled(Some(1)),
            WindowsWslPrerequisiteFailure::update_required(Some(1)),
            WindowsWslPrerequisiteFailure::restart_required(Some(1)),
            WindowsWslPrerequisiteFailure::command_failed(Some(1)),
        ] {
            let detail = failure.detail().to_ascii_lowercase();
            for prohibited in [
                "open windows terminal",
                "open powershell",
                "run `wsl",
                "install wsl",
                "enable windows subsystem",
                "update wsl",
            ] {
                assert!(
                    !detail.contains(prohibited),
                    "prerequisite detail assigned a technical setup task to the beginner: {detail}"
                );
            }
        }

        let retry_detail = WindowsWslPrerequisiteFailure::command_failed(Some(1))
            .detail()
            .to_ascii_lowercase();
        assert!(retry_detail.contains("run automatic preparation again"));
        assert!(
            !retry_detail.contains("it will retry automatic preparation"),
            "a user-triggered retry must not be described as automatic: {retry_detail}"
        );
    }

    #[test]
    fn windows_wsl_repair_uses_only_fixed_backend_arguments() {
        let _typed_entrypoint: fn(
            ManagedRuntimeSetupNextAction,
        ) -> AppResult<ManagedRuntimePrerequisiteRepairResult> = repair_windows_wsl_prerequisite;
        assert_eq!(
            windows_wsl_repair_parameters(ManagedRuntimeSetupNextAction::InstallWsl).unwrap(),
            "--install --no-distribution"
        );
        assert_eq!(
            windows_wsl_repair_parameters(ManagedRuntimeSetupNextAction::EnableWslOptionalFeatures)
                .unwrap(),
            "--install --no-distribution"
        );
        assert_eq!(
            windows_wsl_repair_parameters(ManagedRuntimeSetupNextAction::UpdateWsl).unwrap(),
            "--update"
        );
        for action in [
            ManagedRuntimeSetupNextAction::RestartWindows,
            ManagedRuntimeSetupNextAction::RetryWslCheck,
        ] {
            assert!(windows_wsl_repair_parameters(action).is_err());
        }
    }

    #[test]
    fn missing_wsl_binary_uses_only_two_fixed_bounded_system32_dism_stages() {
        let commands =
            windows_wsl_servicing_commands(ManagedRuntimeSetupNextAction::InstallWsl, false)
                .expect("fixed missing-WSL bootstrap");
        assert_eq!(
            commands,
            [
                WindowsWslServicingCommand::EnableWindowsSubsystemForLinux,
                WindowsWslServicingCommand::EnableVirtualMachinePlatform,
            ]
        );
        assert_eq!(
            commands
                .iter()
                .map(|command| command.timeout())
                .sum::<Duration>(),
            WINDOWS_WSL_PREREQUISITE_REPAIR_TIMEOUT
        );
        for command in commands {
            assert_eq!(command.executable_name(), "dism.exe");
            let parameters = command.parameters();
            assert!(parameters.starts_with("/Online /Enable-Feature /FeatureName:"));
            assert!(parameters.ends_with(" /All /NoRestart"));
            for forbidden in [
                "powershell",
                "pwsh",
                "cmd.exe",
                "&",
                "|",
                ">",
                "<",
                "\\",
                "\"",
                "'",
            ] {
                assert!(
                    !parameters.to_ascii_lowercase().contains(forbidden),
                    "fixed DISM bootstrap exposed shell syntax: {parameters}"
                );
            }
        }
        assert!(
            windows_wsl_servicing_commands(ManagedRuntimeSetupNextAction::UpdateWsl, false,)
                .is_err(),
            "a missing WSL binary cannot be redirected into an unrelated update action"
        );
        assert!(windows_wsl_servicing_completion_requires_restart(
            false, false
        ));
        assert!(windows_wsl_servicing_completion_requires_restart(
            true, true
        ));
        assert!(!windows_wsl_servicing_completion_requires_restart(
            true, false
        ));
    }

    #[test]
    fn servicing_cooldown_is_bounded_and_never_becomes_readiness_proof() {
        let now = 10_000_u64;
        assert_eq!(
            bounded_windows_wsl_servicing_cooldown_remaining(now, now + 42),
            Some(Duration::from_secs(42))
        );
        assert_eq!(
            bounded_windows_wsl_servicing_cooldown_remaining(now, now),
            None
        );
        assert_eq!(
            bounded_windows_wsl_servicing_cooldown_remaining(now, now - 1),
            None
        );
        assert_eq!(
            bounded_windows_wsl_servicing_cooldown_remaining(
                now,
                now + WINDOWS_WSL_SERVICING_COOLDOWN.as_secs() + 1,
            ),
            None,
            "a corrupt far-future receipt must not create a permanent gate"
        );

        let repair_calls = AtomicU64::new(0);
        let waiting = repair_windows_wsl_prerequisite_with_cooldown(
            ManagedRuntimeSetupNextAction::InstallWsl,
            || Ok(Some(Duration::from_secs(60))),
            |_| {
                repair_calls.fetch_add(1, Ordering::AcqRel);
                unreachable!("active reconciliation cooldown cannot re-elevate")
            },
        )
        .expect("cooldown degrades runtime-dependent work only");
        assert_eq!(
            waiting.outcome,
            ManagedRuntimePrerequisiteRepairOutcome::Failed
        );
        assert!(!waiting.restart_required);
        assert_eq!(repair_calls.load(Ordering::Acquire), 0);
        assert_eq!(
            waiting.detail,
            "Windows setup action already submitted. Completion status unavailable."
        );

        let completed = repair_windows_wsl_prerequisite_with_cooldown(
            ManagedRuntimeSetupNextAction::InstallWsl,
            || Ok(None),
            |action| {
                repair_calls.fetch_add(1, Ordering::AcqRel);
                assert_eq!(action, ManagedRuntimeSetupNextAction::InstallWsl);
                Ok(ManagedRuntimePrerequisiteRepairResult {
                    outcome: ManagedRuntimePrerequisiteRepairOutcome::Completed,
                    restart_required: false,
                    detail: "completed".into(),
                })
            },
        )
        .expect("expired cooldown permits one fixed action");
        assert_eq!(
            completed.outcome,
            ManagedRuntimePrerequisiteRepairOutcome::Completed
        );
        assert_eq!(repair_calls.load(Ordering::Acquire), 1);
    }

    #[test]
    fn windows_wsl_repair_exit_codes_preserve_restart_requirements() {
        let completed = windows_wsl_repair_result_from_exit_code(0);
        assert_eq!(
            completed.outcome,
            ManagedRuntimePrerequisiteRepairOutcome::Completed
        );
        assert!(!completed.restart_required);

        for exit_code in [1641, 3010, 3011, 0x8007_0bc2, 0x8007_0bc3, 0xc004_000d] {
            let result = windows_wsl_repair_result_from_exit_code(exit_code);
            assert_eq!(
                result.outcome,
                ManagedRuntimePrerequisiteRepairOutcome::Completed,
                "exit code {exit_code:#x}"
            );
            assert!(result.restart_required, "exit code {exit_code:#x}");
        }

        let failed = windows_wsl_repair_result_from_exit_code(1);
        assert_eq!(
            failed.outcome,
            ManagedRuntimePrerequisiteRepairOutcome::Failed
        );
        assert!(!failed.restart_required);
    }

    #[test]
    fn automatic_windows_wsl_repair_retries_setup_without_holding_the_lifecycle_lock() {
        let mut fixture = fixture();
        let repairer = Arc::new(
            FakeWindowsWslPrerequisiteRepairer::new(vec![
                FakeWindowsWslPrerequisiteRepairResponse::Result(
                    ManagedRuntimePrerequisiteRepairResult {
                        outcome: ManagedRuntimePrerequisiteRepairOutcome::Completed,
                        restart_required: false,
                        detail: "Windows completed the requested WSL change".into(),
                    },
                ),
            ])
            .with_lifecycle_lock_probe(fixture.manager.state_root.join("lifecycle.lock")),
        );
        fixture.manager.prerequisite_repairer = repairer.clone();
        let controller = ManagedRuntimeSetupController::default();
        let running = fixture.manager.status_value(
            ManagedRuntimePhase::Running,
            true,
            None,
            "modeled runtime is ready".into(),
        );
        let mut attempts = 0;

        let status = fixture
            .manager
            .setup_with_attempt(&controller, || {
                attempts += 1;
                let _lifecycle = fixture.manager.lock()?;
                if attempts == 1 {
                    let error = fail_windows_wsl_prerequisite(
                        Some(&controller),
                        WindowsWslPrerequisiteFailure::not_installed(Some(1)),
                    )
                    .expect_err("first attempt requires WSL installation");
                    Err(error)
                } else {
                    Ok(running.clone())
                }
            })
            .expect("completed repair is reconciled by a new setup attempt");

        assert!(status.available);
        assert_eq!(attempts, 2);
        assert_eq!(
            repairer.actions(),
            [ManagedRuntimeSetupNextAction::InstallWsl]
        );
        let setup = controller.status().expect("completed setup status");
        assert_eq!(setup.phase, ManagedRuntimeSetupPhase::Completed);
        assert!(!setup.active);
        assert!(!setup.prerequisite_repair_active);
        assert_eq!(setup.failure_reason, None);
        assert_eq!(setup.next_action, None);
    }

    #[test]
    fn automatic_windows_wsl_repair_cancellation_is_retryable_and_does_not_loop() {
        let mut fixture = fixture();
        let repairer = Arc::new(FakeWindowsWslPrerequisiteRepairer::new(vec![
            FakeWindowsWslPrerequisiteRepairResponse::Result(
                ManagedRuntimePrerequisiteRepairResult {
                    outcome: ManagedRuntimePrerequisiteRepairOutcome::Cancelled,
                    restart_required: false,
                    detail: "Windows administrator confirmation cancelled.".into(),
                },
            ),
        ]));
        fixture.manager.prerequisite_repairer = repairer.clone();
        let controller = ManagedRuntimeSetupController::default();
        let mut attempts = 0;

        let error = fixture
            .manager
            .setup_with_attempt(&controller, || {
                attempts += 1;
                let error = fail_windows_wsl_prerequisite(
                    Some(&controller),
                    WindowsWslPrerequisiteFailure::optional_feature_disabled(Some(1)),
                )
                .expect_err("modeled Windows feature is unavailable");
                Err(error)
            })
            .expect_err("cancelled UAC affects only the runtime-dependent setup");

        assert!(
            error
                .to_string()
                .contains("administrator confirmation cancelled")
        );
        assert_eq!(attempts, 1);
        assert_eq!(
            repairer.actions(),
            [ManagedRuntimeSetupNextAction::EnableWslOptionalFeatures]
        );
        let setup = controller.status().expect("retryable setup status");
        assert_eq!(setup.phase, ManagedRuntimeSetupPhase::Failed);
        assert!(setup.can_retry);
        assert!(!setup.prerequisite_repair_active);
        assert_eq!(
            setup.failure_reason,
            Some(ManagedRuntimeSetupFailureReason::WslOptionalFeatureDisabled)
        );
        assert_eq!(
            setup.next_action,
            Some(ManagedRuntimeSetupNextAction::EnableWslOptionalFeatures)
        );
        assert!(
            setup
                .detail
                .contains("administrator confirmation cancelled")
        );
    }

    #[test]
    fn automatic_windows_wsl_repair_failure_degrades_without_raw_backend_error() {
        let mut fixture = fixture();
        let repairer = Arc::new(FakeWindowsWslPrerequisiteRepairer::new(vec![
            FakeWindowsWslPrerequisiteRepairResponse::Error,
        ]));
        fixture.manager.prerequisite_repairer = repairer.clone();
        let controller = ManagedRuntimeSetupController::default();
        let mut attempts = 0;

        let error = fixture
            .manager
            .setup_with_attempt(&controller, || {
                attempts += 1;
                let error = fail_windows_wsl_prerequisite(
                    Some(&controller),
                    WindowsWslPrerequisiteFailure::update_required(Some(1)),
                )
                .expect_err("modeled WSL update is required");
                Err(error)
            })
            .expect_err("repair failure leaves a retryable dependent task");

        assert_eq!(attempts, 1);
        assert_eq!(
            repairer.actions(),
            [ManagedRuntimeSetupNextAction::UpdateWsl]
        );
        assert!(
            error
                .to_string()
                .contains("Try automatic preparation again")
        );
        assert!(!error.to_string().contains("injected"));
        let setup = controller.status().expect("retryable failed setup");
        assert!(setup.can_retry);
        assert_eq!(
            setup.failure_reason,
            Some(ManagedRuntimeSetupFailureReason::WslUpdateRequired)
        );
        assert_eq!(
            setup.next_action,
            Some(ManagedRuntimeSetupNextAction::UpdateWsl)
        );
    }

    #[test]
    fn automatic_windows_wsl_repair_preserves_restart_as_the_only_next_action() {
        let mut fixture = fixture();
        let repairer = Arc::new(FakeWindowsWslPrerequisiteRepairer::new(vec![
            FakeWindowsWslPrerequisiteRepairResponse::Result(
                ManagedRuntimePrerequisiteRepairResult {
                    outcome: ManagedRuntimePrerequisiteRepairOutcome::Completed,
                    restart_required: true,
                    detail: "Windows completed the WSL change and needs a restart".into(),
                },
            ),
        ]));
        fixture.manager.prerequisite_repairer = repairer;
        let controller = ManagedRuntimeSetupController::default();

        let error = fixture
            .manager
            .setup_with_attempt(&controller, || {
                let error = fail_windows_wsl_prerequisite(
                    Some(&controller),
                    WindowsWslPrerequisiteFailure::not_installed(Some(1)),
                )
                .expect_err("modeled WSL installation is required");
                Err(error)
            })
            .expect_err("Windows restart is preserved for the user");

        assert!(error.to_string().contains("needs a restart"));
        let setup = controller.status().expect("restart status");
        assert_eq!(
            setup.failure_reason,
            Some(ManagedRuntimeSetupFailureReason::RestartRequired)
        );
        assert_eq!(
            setup.next_action,
            Some(ManagedRuntimeSetupNextAction::RestartWindows)
        );
        assert!(setup.can_retry);
        assert!(!setup.prerequisite_repair_active);
    }

    #[test]
    fn automatic_windows_wsl_repair_never_repeats_the_same_action_in_one_setup() {
        let mut fixture = fixture();
        let repairer = Arc::new(FakeWindowsWslPrerequisiteRepairer::new(vec![
            FakeWindowsWslPrerequisiteRepairResponse::Result(
                ManagedRuntimePrerequisiteRepairResult {
                    outcome: ManagedRuntimePrerequisiteRepairOutcome::Completed,
                    restart_required: false,
                    detail: "Windows completed the requested WSL change".into(),
                },
            ),
        ]));
        fixture.manager.prerequisite_repairer = repairer.clone();
        let controller = ManagedRuntimeSetupController::default();
        let mut attempts = 0;

        fixture
            .manager
            .setup_with_attempt(&controller, || {
                attempts += 1;
                let error = fail_windows_wsl_prerequisite(
                    Some(&controller),
                    WindowsWslPrerequisiteFailure::update_required(Some(1)),
                )
                .expect_err("modeled update remains unavailable");
                Err(error)
            })
            .expect_err("a repeated typed failure must not create a UAC loop");

        assert_eq!(attempts, 2);
        assert_eq!(
            repairer.actions(),
            [ManagedRuntimeSetupNextAction::UpdateWsl]
        );
        assert_eq!(MAX_AUTOMATIC_WINDOWS_WSL_PREREQUISITE_REPAIRS, 3);
    }

    #[test]
    fn windows_wsl_repair_timeout_is_bounded_and_reports_one_direct_outcome() {
        assert_eq!(
            WINDOWS_WSL_PREREQUISITE_REPAIR_TIMEOUT,
            Duration::from_secs(5 * 60)
        );
        let result = windows_wsl_repair_timeout_result();
        assert_eq!(
            result.outcome,
            ManagedRuntimePrerequisiteRepairOutcome::Failed
        );
        assert!(!result.restart_required);
        assert_eq!(
            result.detail,
            "Windows setup completion status unavailable."
        );
    }

    #[test]
    fn windows_wsl_repair_is_derived_from_exact_failed_pair_and_single_flight() {
        let controller = ManagedRuntimeSetupController::default();
        let operation_id = controller.begin().expect("begin setup");
        {
            let mut status = controller.status.lock().expect("setup status");
            status.phase = ManagedRuntimeSetupPhase::Failed;
            status.active = false;
            status.failure_reason = Some(ManagedRuntimeSetupFailureReason::WslUpdateRequired);
            status.next_action = Some(ManagedRuntimeSetupNextAction::UpdateWsl);
        }
        assert_eq!(
            controller.begin_prerequisite_repair(&operation_id).unwrap(),
            ManagedRuntimeSetupNextAction::UpdateWsl
        );
        let repairing = controller.status().expect("repairing status");
        assert!(repairing.prerequisite_repair_active);
        assert!(!repairing.can_retry);
        assert!(controller.begin_prerequisite_repair(&operation_id).is_err());
        assert!(controller.begin().is_err());

        let completed = windows_wsl_repair_result_from_exit_code(0);
        controller.finish_prerequisite_repair(&operation_id, Some(&completed));
        let repaired = controller.status().expect("repaired status");
        assert!(!repaired.prerequisite_repair_active);
        assert!(repaired.can_retry);
        assert_eq!(
            controller.begin_prerequisite_repair(&operation_id).unwrap(),
            ManagedRuntimeSetupNextAction::UpdateWsl
        );
        controller.finish_prerequisite_repair(&operation_id, None);

        {
            let mut status = controller.status.lock().expect("setup status");
            status.failure_reason = Some(ManagedRuntimeSetupFailureReason::WslNotInstalled);
            status.next_action = Some(ManagedRuntimeSetupNextAction::UpdateWsl);
        }
        assert!(controller.begin_prerequisite_repair(&operation_id).is_err());
    }

    #[test]
    fn windows_wsl_repair_restart_result_becomes_the_only_next_action() {
        let controller = ManagedRuntimeSetupController::default();
        let operation_id = controller.begin().expect("begin setup");
        {
            let mut status = controller.status.lock().expect("setup status");
            status.phase = ManagedRuntimeSetupPhase::Failed;
            status.active = false;
            status.failure_reason = Some(ManagedRuntimeSetupFailureReason::WslNotInstalled);
            status.next_action = Some(ManagedRuntimeSetupNextAction::InstallWsl);
        }
        assert_eq!(
            controller.begin_prerequisite_repair(&operation_id).unwrap(),
            ManagedRuntimeSetupNextAction::InstallWsl
        );
        let restart = windows_wsl_repair_result_from_exit_code(3010);
        controller.finish_prerequisite_repair(&operation_id, Some(&restart));

        let status = controller.status().expect("restart status");
        assert_eq!(
            status.failure_reason,
            Some(ManagedRuntimeSetupFailureReason::RestartRequired)
        );
        assert_eq!(
            status.next_action,
            Some(ManagedRuntimeSetupNextAction::RestartWindows)
        );
        assert!(controller.begin_prerequisite_repair(&operation_id).is_err());
    }

    #[test]
    fn windows_wsl_prerequisite_failure_persists_machine_readable_recovery() {
        let controller = ManagedRuntimeSetupController::default();
        let operation_id = controller.begin().expect("begin setup");
        controller
            .set_phase(
                ManagedRuntimeSetupPhase::Prerequisite,
                "checking Windows WSL 2",
            )
            .expect("prerequisite phase");
        let failure = WindowsWslPrerequisiteFailure::update_required(Some(1));
        let error = fail_windows_wsl_prerequisite(Some(&controller), failure)
            .expect_err("missing prerequisite");

        // The worker has recorded the classified pair internally so the
        // terminal failure can preserve it, but concurrent Tauri polling must
        // not receive recovery fields before the public phase becomes failed.
        let unwinding = controller.status().expect("unwinding status");
        assert_eq!(unwinding.phase, ManagedRuntimeSetupPhase::Prerequisite);
        assert!(unwinding.active);
        assert_eq!(unwinding.failure_reason, None);
        assert_eq!(unwinding.next_action, None);
        let encoded_unwinding =
            serde_json::to_value(&unwinding).expect("serialize unwinding setup status");
        assert_eq!(encoded_unwinding["failure_reason"], serde_json::Value::Null);
        assert_eq!(encoded_unwinding["next_action"], serde_json::Value::Null);

        controller
            .finish_failed(&operation_id, error.to_string())
            .expect("finish failed setup");

        let status = controller.status().expect("failed status");
        assert_eq!(status.phase, ManagedRuntimeSetupPhase::Failed);
        assert!(!status.active);
        assert!(status.can_retry);
        assert_eq!(
            status.failure_reason,
            Some(ManagedRuntimeSetupFailureReason::WslUpdateRequired)
        );
        assert_eq!(
            status.next_action,
            Some(ManagedRuntimeSetupNextAction::UpdateWsl)
        );
        assert!(status.detail.contains("needs an update"));
        assert!(!status.detail.contains("operation is not available yet"));
        let encoded = serde_json::to_value(&status).expect("serialize setup status");
        assert_eq!(encoded["phase"], "failed");
        assert_eq!(encoded["failure_reason"], "windows_wsl_update_required");
        assert_eq!(encoded["next_action"], "update_wsl");

        controller.begin().expect("retry begins cleanly");
        let retried = controller.status().expect("retry status");
        assert_eq!(retried.phase, ManagedRuntimeSetupPhase::Install);
        assert_eq!(retried.failure_reason, None);
        assert_eq!(retried.next_action, None);
    }

    #[cfg(windows)]
    #[test]
    fn windows_setup_checks_wsl_before_machine_image_download() {
        let mut fixture = fixture();
        let repairer = Arc::new(FakeWindowsWslPrerequisiteRepairer::new(vec![
            FakeWindowsWslPrerequisiteRepairResponse::Error,
        ]));
        fixture.manager.prerequisite_repairer = repairer.clone();
        fixture.commands.push(failure(utf16le(
            "此應用程式需要適用於 Linux 的 Windows 子系統選用元件。\r\nError code: Wsl/WSL_E_WSL_OPTIONAL_COMPONENT_REQUIRED\r\n",
        )));
        let setup = ManagedRuntimeSetupController::default();

        let error = fixture
            .manager
            .setup(&setup)
            .expect_err("unavailable WSL must stop setup before download");

        assert!(
            error
                .to_string()
                .contains("Try automatic preparation again")
        );
        assert_eq!(
            repairer.actions(),
            [ManagedRuntimeSetupNextAction::EnableWslOptionalFeatures]
        );
        assert_eq!(*fixture.downloader.calls.lock().expect("downloads"), 0);
        assert_eq!(
            fixture.commands.calls(),
            vec![vec![String::from("--status")]]
        );
        let status = setup.status().expect("failed setup status");
        assert_eq!(status.phase, ManagedRuntimeSetupPhase::Failed);
        assert_eq!(status.received_bytes, 0);
        assert_eq!(status.total_bytes, None);
        assert_eq!(
            status.failure_reason,
            Some(ManagedRuntimeSetupFailureReason::WslOptionalFeatureDisabled)
        );
        assert_eq!(
            status.next_action,
            Some(ManagedRuntimeSetupNextAction::EnableWslOptionalFeatures)
        );
        assert!(!status.detail.contains("wsl.exe"));
        assert!(!status.detail.contains(['\0', '\u{fffd}']));
    }

    #[cfg(windows)]
    #[test]
    fn windows_setup_classifies_podmans_exact_wsl_inventory_failure_before_download() {
        let mut fixture = fixture();
        let repairer = Arc::new(FakeWindowsWslPrerequisiteRepairer::new(vec![
            FakeWindowsWslPrerequisiteRepairResponse::Error,
        ]));
        fixture.manager.prerequisite_repairer = repairer.clone();
        fixture.commands.push(success(utf16le(
            "Default Version: 2\r\nKernel version: 6.6.87.2\r\n",
        )));
        fixture.commands.push(failure(utf16le(
            "Windows Subsystem for Linux is not installed. Run wsl.exe --install.\r\nFor more information visit https://aka.ms/wslinstall\r\n",
        )));
        let setup = ManagedRuntimeSetupController::default();

        let error = fixture
            .manager
            .setup(&setup)
            .expect_err("Podman's failing WSL inventory boundary must stop setup");

        assert!(
            error
                .to_string()
                .contains("Try automatic preparation again")
        );
        assert_eq!(
            repairer.actions(),
            [ManagedRuntimeSetupNextAction::InstallWsl]
        );
        assert_eq!(*fixture.downloader.calls.lock().expect("downloads"), 0);
        assert_eq!(
            fixture.commands.calls(),
            vec![
                vec![String::from("--status")],
                vec![String::from("-l"), String::from("--quiet")],
            ]
        );
        let status = setup.status().expect("failed setup status");
        assert_eq!(status.phase, ManagedRuntimeSetupPhase::Failed);
        assert!(!status.active);
        assert!(status.can_retry);
        assert_eq!(status.received_bytes, 0);
        assert_eq!(status.total_bytes, None);
        assert_eq!(
            status.failure_reason,
            Some(ManagedRuntimeSetupFailureReason::WslNotInstalled)
        );
        assert_eq!(
            status.next_action,
            Some(ManagedRuntimeSetupNextAction::InstallWsl)
        );
        assert!(!status.detail.contains("status 125"));
        assert!(!status.detail.contains("C:\\Windows"));
        assert!(!status.detail.contains(['\0', '\u{fffd}']));
    }

    #[test]
    fn windows_wsl_command_uses_verified_system_directories_not_managed_environment() {
        let temp = TempDir::new().expect("temporary root");
        let system_root = temp.path().join("trusted-windows-root");
        let system32 = system_root.join("System32");
        let working_directory = temp.path().join("provider-home");
        fs::create_dir(&system_root).expect("Windows root");
        fs::create_dir(&system32).expect("System32");
        fs::create_dir(&working_directory).expect("provider home");
        fs::write(system32.join("wsl.exe"), b"fixture wsl").expect("fixture wsl.exe");
        let directories =
            verified_windows_system_directories(&system_root).expect("verified directories");
        let managed_command = ManagedRuntimeCommand {
            binary: temp.path().join("managed-podman"),
            environment: BTreeMap::from([
                (
                    OsString::from("SystemRoot"),
                    OsString::from("C:\\attacker-controlled"),
                ),
                (
                    OsString::from("PATH"),
                    OsString::from("C:\\attacker-controlled\\System32"),
                ),
            ]),
            working_directory: working_directory.clone(),
            runtime_version: "test".into(),
            manifest_sha256: "a".repeat(64),
            machine_image_sha256: "b".repeat(64),
            #[cfg(windows)]
            windows_launch_authorization: WindowsManagedRuntimeLaunchAuthorization::MetadataOnly,
        };

        let command =
            windows_wsl_inventory_command_with_directories(&managed_command, &directories)
                .expect("trusted WSL command");

        assert_eq!(command.binary, directories.system32.join("wsl.exe"));
        assert_eq!(
            command.environment.get(OsStr::new("SystemRoot")),
            Some(&directories.system_root.as_os_str().to_owned())
        );
        assert_eq!(
            command.environment.get(OsStr::new("WINDIR")),
            command.environment.get(OsStr::new("SystemRoot"))
        );
        let path = command
            .environment
            .get(OsStr::new("PATH"))
            .expect("trusted PATH");
        assert_eq!(
            std::env::split_paths(path).collect::<Vec<_>>(),
            [directories.system32]
        );
        assert_eq!(
            command.working_directory,
            working_directory
                .canonicalize()
                .expect("canonical provider home")
        );
        assert_eq!(command.environment.len(), 5);
        assert_eq!(
            command.environment.get(OsStr::new("WSL_UTF8")),
            Some(&OsString::from("1"))
        );
    }

    #[test]
    fn corrupted_install_is_replaced_from_verified_release_resources() {
        let fixture = fixture();
        fixture.manager.install().expect("initial install");
        let installed = fixture.manager.install_directory().join("bin/podman");
        tamper_installed_driver(&fixture.manager);

        fixture.manager.install().expect("repair install");

        assert_eq!(
            fs::read(installed).expect("repaired driver"),
            b"managed-podman-driver"
        );
        fixture
            .manager
            .verify_installation()
            .expect("repaired installation verifies");
    }

    #[test]
    fn corrupted_machine_image_cache_is_removed_and_downloaded_again() {
        let fixture = fixture();
        let target = fixture.manager.loaded.target().expect("target");
        let cached = fixture
            .manager
            .acquire_machine_image_locked(target, None)
            .expect("initial image");
        fs::write(&cached, vec![b'x'; fixture.image.len()]).expect("tamper cache");

        let repaired = fixture
            .manager
            .acquire_machine_image_locked(target, None)
            .expect("repair image");

        assert_eq!(repaired, cached);
        assert_eq!(fs::read(repaired).expect("repaired image"), fixture.image);
    }

    #[cfg(unix)]
    #[test]
    fn exact_install_symlink_is_unlinked_without_touching_its_target() {
        use std::os::unix::fs::symlink;

        let fixture = fixture();
        fixture.manager.install().expect("initial install");
        let install = fixture.manager.install_directory();
        fs::remove_dir_all(&install).expect("remove test install");
        let outside = fixture._temp.path().join("outside-install-target");
        fs::create_dir(&outside).expect("outside directory");
        fs::write(outside.join("keep"), b"outside").expect("outside marker");
        symlink(&outside, &install).expect("corrupt install symlink");

        fixture.manager.install().expect("repair symlink");

        assert_eq!(fs::read(outside.join("keep")).unwrap(), b"outside");
        assert!(
            !fs::symlink_metadata(&install)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        fixture
            .manager
            .verify_installation()
            .expect("repaired install");
    }

    #[cfg(unix)]
    #[test]
    fn exact_image_symlink_is_unlinked_and_redownloaded() {
        use std::os::unix::fs::symlink;

        let fixture = fixture();
        let target = fixture.manager.loaded.target().expect("target");
        let cached = fixture
            .manager
            .acquire_machine_image_locked(target, None)
            .expect("initial image");
        fs::remove_file(&cached).expect("remove cached image");
        let outside = fixture._temp.path().join("outside-image");
        fs::write(&outside, b"outside").expect("outside image");
        symlink(&outside, &cached).expect("corrupt cache symlink");

        let repaired = fixture
            .manager
            .acquire_machine_image_locked(target, None)
            .expect("repair image symlink");

        assert_eq!(fs::read(outside).unwrap(), b"outside");
        assert_eq!(fs::read(repaired).unwrap(), fixture.image);
    }

    #[cfg(unix)]
    #[test]
    fn non_traversable_install_directories_are_repaired() {
        use std::os::unix::fs::PermissionsExt;

        let fixture = fixture();
        fixture.manager.install().expect("initial install");
        let install = fixture.manager.install_directory();
        fs::set_permissions(install.join("bin"), fs::Permissions::from_mode(0o000)).unwrap();
        fs::set_permissions(&install, fs::Permissions::from_mode(0o000)).unwrap();

        fixture.manager.install().expect("repair directory modes");

        fixture
            .manager
            .verify_installation()
            .expect("repaired install");
        assert_eq!(
            fs::metadata(install).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }

    #[cfg(windows)]
    #[test]
    fn readonly_windows_payload_tree_can_be_removed_for_repair() {
        let fixture = fixture();
        let versions = fixture.manager.versions_root();
        let install = versions.join("readonly-repair-fixture");
        let nested = install.join("nested");
        fs::create_dir_all(&nested).expect("create readonly fixture");
        let payload = nested.join("payload.dat");
        fs::write(&payload, b"payload").expect("write readonly fixture");

        for path in [&payload, &nested, &install] {
            let mut permissions = fs::metadata(path).unwrap().permissions();
            permissions.set_readonly(true);
            fs::set_permissions(path, permissions).unwrap();
        }

        remove_private_tree(&install, &versions).expect("remove readonly tree");
        assert!(!private_entry_exists(&install).unwrap());
    }

    #[cfg(windows)]
    #[test]
    fn readonly_windows_top_level_cache_file_can_be_removed_for_repair() {
        let fixture = fixture();
        let cache = fixture.manager.image_cache_root();
        ensure_private_directory(&cache).unwrap();
        let payload = cache.join("readonly-top-level.zst");
        fs::write(&payload, b"corrupt cache").unwrap();
        set_windows_entry_readonly_nofollow(&payload, true).unwrap();

        remove_private_tree(&payload, &cache).expect("remove readonly cache file");
        assert!(!private_entry_exists(&payload).unwrap());
    }

    #[cfg(windows)]
    #[test]
    fn readonly_windows_child_symlink_is_unlinked_without_touching_target() {
        use std::os::windows::fs::symlink_file;
        use windows_sys::Win32::Foundation::ERROR_PRIVILEGE_NOT_HELD;

        let fixture = fixture();
        let versions = fixture.manager.versions_root();
        ensure_private_directory(&versions).unwrap();
        let install = versions.join("readonly-link-repair-fixture");
        fs::create_dir(&install).unwrap();
        let outside = fixture._temp.path().join("outside-readonly-target");
        fs::write(&outside, b"outside remains").unwrap();
        let link = install.join("payload-link");
        if let Err(error) = symlink_file(&outside, &link) {
            if error.raw_os_error() == Some(ERROR_PRIVILEGE_NOT_HELD as i32) {
                eprintln!("skipping symlink test: host lacks symbolic-link privilege");
                return;
            }
            panic!("create file symlink: {error}");
        }
        set_windows_entry_readonly_nofollow(&link, true).unwrap();

        remove_private_tree(&install, &versions).expect("remove tree with readonly link");
        assert!(!private_entry_exists(&install).unwrap());
        assert_eq!(fs::read(&outside).unwrap(), b"outside remains");
    }

    #[cfg(windows)]
    #[test]
    fn windows_provider_delete_retry_classifies_only_sharing_violations() {
        use windows_sys::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_SHARING_VIOLATION};

        assert!(windows_error_is_sharing_violation(
            &io::Error::from_raw_os_error(ERROR_SHARING_VIOLATION as i32)
        ));
        assert!(!windows_error_is_sharing_violation(
            &io::Error::from_raw_os_error(ERROR_ACCESS_DENIED as i32)
        ));
    }

    #[cfg(windows)]
    #[test]
    fn windows_provider_delete_accepts_a_concurrent_not_found() {
        let fixture = fixture();
        let missing = fixture
            .manager
            .versions_root()
            .join("already-released.vhdx");
        ensure_private_directory(&fixture.manager.versions_root()).unwrap();

        remove_windows_private_file(
            &missing,
            WindowsPrivateFileDeletePolicy::RetrySharingViolation {
                deadline: Instant::now() + Duration::from_secs(1),
                poll: Duration::from_millis(10),
            },
        )
        .expect("a concurrently removed exact entry is already clean");
    }
    #[cfg(windows)]
    #[test]
    fn uninstall_waits_for_exact_windows_wsl_vhd_release() {
        let mut fixture = fixture();
        fixture.manager.install().expect("install");
        seed_owned_windows_lifecycle_fixture(
            &mut fixture,
            FixtureWindowsRegistrationLifecycle::Absent,
        );
        let target = fixture.manager.loaded.target().expect("target");
        fixture
            .manager
            .runtime_command(target)
            .expect("private provider home");
        let vhd = windows_fixture_vhd_path(&fixture.manager, target);
        fs::write(&vhd, b"fixture VHD").expect("write fixture VHD");
        // WSL can retain an ext4.vhdx handle that blocks both the no-follow
        // FILE_WRITE_ATTRIBUTES open and the eventual delete. Both operations
        // must use the same bounded release deadline.
        let locked_vhd = open_without_windows_write_or_delete_sharing(&vhd);
        let started = Instant::now();
        let release = thread::spawn(move || {
            thread::sleep(Duration::from_millis(250));
            drop(locked_vhd);
        });
        fixture.commands.push(success(b"[]".to_vec()));
        push_windows_wsl_absent(&fixture.commands);

        let result = fixture
            .manager
            .uninstall(ManagedUninstallOptions::default());
        release.join().expect("release fixture VHD handle");
        let status = result.expect("uninstall after bounded VHD release wait");

        assert_eq!(status.phase, ManagedRuntimePhase::NotInstalled);
        assert!(started.elapsed() >= Duration::from_millis(250));
        assert!(!private_entry_exists(&fixture.manager.provider_home()).unwrap());
        assert!(!private_entry_exists(&fixture.manager.install_directory()).unwrap());
    }

    #[cfg(windows)]
    #[test]
    fn uninstall_provider_delete_timeout_retains_install_and_image_cache() {
        let mut fixture = fixture();
        fixture.manager.install().expect("install");
        seed_owned_windows_lifecycle_fixture(
            &mut fixture,
            FixtureWindowsRegistrationLifecycle::Absent,
        );
        let target = fixture.manager.loaded.target().expect("target");
        fixture
            .manager
            .runtime_command(target)
            .expect("private provider home");
        let image = fixture
            .manager
            .acquire_machine_image_locked(target, None)
            .expect("cache exact machine image");
        let provider_home = fixture.manager.provider_home();
        let vhd = windows_fixture_vhd_path(&fixture.manager, target);
        fs::write(&vhd, b"fixture VHD").expect("write fixture VHD");
        let locked_vhd = open_without_windows_delete_sharing(&vhd);
        fixture.commands.push(success(b"[]".to_vec()));
        push_windows_wsl_absent(&fixture.commands);
        let started = Instant::now();

        let error = fixture
            .manager
            .uninstall_with_windows_provider_delete_timing(
                ManagedUninstallOptions {
                    stop_mode: ManagedStopMode::Force,
                    remove_machine_image_cache: true,
                },
                Duration::from_millis(150),
                Duration::from_millis(25),
            )
            .expect_err("an unreleased VHD must stop provider deletion at its deadline");

        assert!(error.to_string().contains("remained in use"));
        assert!(started.elapsed() >= Duration::from_millis(150));
        assert!(private_entry_exists(&provider_home).unwrap());
        assert!(private_entry_exists(&vhd).unwrap());
        assert!(private_entry_exists(&fixture.manager.install_directory()).unwrap());
        assert_eq!(fs::read(image).unwrap(), fixture.image);
        assert_eq!(fixture.commands.calls().len(), 2);
        drop(locked_vhd);
    }

    #[cfg(windows)]
    #[test]
    fn uninstall_provider_attribute_open_timeout_retains_install_and_image_cache() {
        let mut fixture = fixture();
        fixture.manager.install().expect("install");
        seed_owned_windows_lifecycle_fixture(
            &mut fixture,
            FixtureWindowsRegistrationLifecycle::Absent,
        );
        let target = fixture.manager.loaded.target().expect("target");
        fixture
            .manager
            .runtime_command(target)
            .expect("private provider home");
        let image = fixture
            .manager
            .acquire_machine_image_locked(target, None)
            .expect("cache exact machine image");
        let provider_home = fixture.manager.provider_home();
        let vhd = windows_fixture_vhd_path(&fixture.manager, target);
        fs::write(&vhd, b"fixture VHD").expect("write fixture VHD");
        let locked_vhd = open_without_windows_write_or_delete_sharing(&vhd);
        fixture.commands.push(success(b"[]".to_vec()));
        push_windows_wsl_absent(&fixture.commands);
        let started = Instant::now();

        let error = fixture
            .manager
            .uninstall_with_windows_provider_delete_timing(
                ManagedUninstallOptions {
                    stop_mode: ManagedStopMode::Force,
                    remove_machine_image_cache: true,
                },
                Duration::from_millis(150),
                Duration::from_millis(25),
            )
            .expect_err("an attribute-locked VHD must stop deletion at its deadline");

        assert!(error.to_string().contains("remained in use"));
        assert!(started.elapsed() >= Duration::from_millis(150));
        assert!(private_entry_exists(&provider_home).unwrap());
        assert!(private_entry_exists(&vhd).unwrap());
        assert!(private_entry_exists(&fixture.manager.install_directory()).unwrap());
        assert_eq!(fs::read(image).unwrap(), fixture.image);
        assert_eq!(fixture.commands.calls().len(), 2);
        drop(locked_vhd);
    }

    #[test]
    fn corrupted_install_does_not_wedge_uninstall() {
        let fixture = fixture();
        fixture.manager.install().expect("initial install");
        tamper_installed_driver(&fixture.manager);
        fixture.commands.push(success(b"[]".to_vec()));
        push_windows_wsl_absent(&fixture.commands);

        let status = fixture
            .manager
            .uninstall(ManagedUninstallOptions::default())
            .expect("repair then uninstall");

        assert_eq!(status.phase, ManagedRuntimePhase::NotInstalled);
        assert!(!fixture.manager.install_directory().exists());
        assert!(!fixture.manager.provider_home().exists());
    }

    #[test]
    fn uninstall_removes_private_provider_state_retains_cache_and_later_purge_removes_it() {
        let mut fixture = fixture();
        fixture.manager.install().expect("install");
        seed_owned_windows_lifecycle_fixture(
            &mut fixture,
            FixtureWindowsRegistrationLifecycle::Absent,
        );
        let target = fixture.manager.loaded.target().expect("target");
        fixture
            .manager
            .runtime_command(target)
            .expect("private provider home");
        #[cfg(target_os = "linux")]
        let linux_runtime = {
            use std::os::unix::fs::PermissionsExt;

            let runtime = fixture
                .manager
                .linux_short_runtime_directory()
                .expect("Linux short runtime");
            let podman = runtime.join(PODMAN_LINUX_RUNTIME_DIRECTORY);
            fs::create_dir(&podman).expect("Podman runtime directory");
            fs::set_permissions(&podman, fs::Permissions::from_mode(0o755)).unwrap();
            let log = podman.join(PODMAN_GVPROXY_LOG_NAME);
            fs::write(&log, b"pinned gvproxy residue\n").unwrap();
            fs::set_permissions(&log, fs::Permissions::from_mode(0o644)).unwrap();
            runtime
        };
        let identity = fixture.manager.machine_ssh_identity_path();
        let image = {
            let _lock = fixture.manager.lock().expect("lifecycle lock");
            fixture
                .manager
                .prepare_machine_ssh_identity_locked()
                .expect("generate identity");
            fixture
                .manager
                .acquire_machine_image_locked(target, None)
                .expect("cache exact machine image")
        };
        let (private_temporary, _) = managed_ssh_identity_temporary_paths(&identity).unwrap();
        fs::write(&private_temporary, b"interrupted-staging-secret").unwrap();
        assert!(identity.is_file());
        assert!(managed_ssh_public_key_path(&identity).is_file());
        assert_eq!(fs::read(&image).unwrap(), fixture.image);
        fixture.commands.push(success(b"[]".to_vec()));
        push_windows_wsl_absent(&fixture.commands);

        let status = fixture
            .manager
            .uninstall(ManagedUninstallOptions::default())
            .expect("uninstall release-private state");

        assert_eq!(status.phase, ManagedRuntimePhase::NotInstalled);
        assert!(!fixture.manager.install_directory().exists());
        assert!(!fixture.manager.provider_home().exists());
        #[cfg(target_os = "linux")]
        assert!(!private_entry_exists(&linux_runtime).unwrap());
        assert!(!private_entry_exists(&identity).unwrap());
        assert!(!private_entry_exists(&managed_ssh_public_key_path(&identity)).unwrap());
        assert!(!private_entry_exists(&private_temporary).unwrap());
        assert_eq!(fs::read(&image).unwrap(), fixture.image);

        let calls_before_purge = fixture.commands.calls().len();
        let status = fixture
            .manager
            .uninstall(ManagedUninstallOptions {
                stop_mode: ManagedStopMode::OnlyIfIdle,
                remove_machine_image_cache: true,
            })
            .expect("purge retained image cache without reinstalling the runtime");
        assert_eq!(status.phase, ManagedRuntimePhase::NotInstalled);
        assert!(!private_entry_exists(&image).unwrap());
        assert_eq!(fixture.commands.calls().len(), calls_before_purge);
    }

    #[test]
    fn uninstall_removes_the_exact_stopped_machine_before_private_state() {
        let mut fixture = fixture();
        fixture.manager.install().expect("install");
        seed_owned_windows_lifecycle_fixture(
            &mut fixture,
            FixtureWindowsRegistrationLifecycle::PresentThenAbsent,
        );
        let target = fixture.manager.loaded.target().expect("target");
        fixture
            .manager
            .runtime_command(target)
            .expect("private provider home");
        #[cfg(target_os = "linux")]
        let linux_runtime_after_machine_removal = {
            use std::os::unix::fs::PermissionsExt;

            let runtime = fixture
                .manager
                .linux_short_runtime_directory()
                .expect("Linux short runtime");
            let podman = runtime.join(PODMAN_LINUX_RUNTIME_DIRECTORY);
            fs::create_dir(&podman).expect("Podman runtime directory");
            fs::set_permissions(&podman, fs::Permissions::from_mode(0o755)).unwrap();
            let log = podman.join(PODMAN_GVPROXY_LOG_NAME);
            fs::write(&log, b"pinned gvproxy residue after machine stop\n").unwrap();
            fs::set_permissions(&log, fs::Permissions::from_mode(0o644)).unwrap();
            runtime
        };
        let identity = fixture.manager.machine_ssh_identity_path();
        let image = {
            let _lock = fixture.manager.lock().expect("lifecycle lock");
            fixture
                .manager
                .prepare_machine_ssh_identity_locked()
                .expect("generate identity");
            fixture
                .manager
                .acquire_machine_image_locked(target, None)
                .expect("cache exact machine image")
        };
        #[cfg(windows)]
        let canonical_provider_home = fixture
            .manager
            .provider_home()
            .canonicalize()
            .expect("canonical provider home");
        let expected_machine = machine_name(target);
        fixture
            .commands
            .push(success(machine_json(&fixture.manager, false)));
        fixture.commands.push(success(Vec::new()));
        push_windows_wsl_absent(&fixture.commands);

        let status = fixture
            .manager
            .uninstall(ManagedUninstallOptions::default())
            .expect("remove exact stopped machine");

        assert_eq!(status.phase, ManagedRuntimePhase::NotInstalled);
        assert!(!fixture.manager.install_directory().exists());
        assert!(!fixture.manager.provider_home().exists());
        #[cfg(target_os = "linux")]
        assert!(!private_entry_exists(&linux_runtime_after_machine_removal).unwrap());
        assert!(!private_entry_exists(&identity).unwrap());
        assert_eq!(fs::read(&image).unwrap(), fixture.image);
        let calls = fixture.commands.calls();
        assert_eq!(calls[0], ["machine", "list", "--format", "json"]);
        assert_eq!(
            calls[1],
            ["machine", "rm", "--force", expected_machine.as_str()]
        );
        #[cfg(windows)]
        {
            assert_eq!(calls[2], ["--list", "--quiet"]);
            let commands = fixture.commands.commands();
            let wsl = &commands[2];
            assert!(wsl.binary.is_absolute());
            assert_eq!(wsl.binary.file_name(), Some(OsStr::new("wsl.exe")));
            assert_eq!(
                wsl.binary.parent().and_then(Path::file_name),
                Some(OsStr::new("System32"))
            );
            assert_eq!(wsl.working_directory, canonical_provider_home);
            assert_eq!(wsl.environment.len(), 5);
            assert_eq!(
                wsl.environment
                    .get(OsStr::new("NoDefaultCurrentDirectoryInExePath")),
                Some(&OsString::from("1"))
            );
            assert_eq!(
                wsl.environment.get(OsStr::new("WSL_UTF8")),
                Some(&OsString::from("1"))
            );
        }
    }

    #[test]
    fn uninstall_machine_removal_failure_retains_provider_install_and_cache() {
        let mut fixture = fixture();
        fixture.manager.install().expect("install");
        seed_owned_windows_lifecycle_fixture(
            &mut fixture,
            FixtureWindowsRegistrationLifecycle::Present,
        );
        let target = fixture.manager.loaded.target().expect("target");
        fixture
            .manager
            .runtime_command(target)
            .expect("private provider home");
        #[cfg(target_os = "linux")]
        let linux_runtime = fixture
            .manager
            .linux_short_runtime_directory()
            .expect("Linux short runtime");
        let identity = fixture.manager.machine_ssh_identity_path();
        let image = {
            let _lock = fixture.manager.lock().expect("lifecycle lock");
            fixture
                .manager
                .prepare_machine_ssh_identity_locked()
                .expect("generate identity");
            fixture
                .manager
                .acquire_machine_image_locked(target, None)
                .expect("cache exact machine image")
        };
        fixture
            .commands
            .push(success(machine_json(&fixture.manager, false)));
        fixture.commands.push(failure(b"exact removal failed"));

        let error = fixture
            .manager
            .uninstall(ManagedUninstallOptions {
                stop_mode: ManagedStopMode::Force,
                remove_machine_image_cache: true,
            })
            .expect_err("nonzero machine removal must retain all private state");

        assert!(error.to_string().contains("exact removal failed"));
        assert!(fixture.manager.install_directory().exists());
        assert!(fixture.manager.provider_home().exists());
        #[cfg(target_os = "linux")]
        assert!(private_entry_exists(&linux_runtime).unwrap());
        assert!(identity.is_file());
        assert_eq!(fs::read(&image).unwrap(), fixture.image);
        assert_eq!(fixture.commands.calls().len(), 2);
    }

    #[cfg(windows)]
    #[test]
    fn uninstall_preserves_private_state_when_wsl_distribution_survives_machine_rm() {
        let mut fixture = fixture();
        fixture.manager.install().expect("install");
        seed_owned_windows_lifecycle_fixture(
            &mut fixture,
            FixtureWindowsRegistrationLifecycle::Present,
        );
        let target = fixture.manager.loaded.target().expect("target");
        fixture
            .manager
            .runtime_command(target)
            .expect("private provider home");
        let identity = fixture.manager.machine_ssh_identity_path();
        let image = {
            let _lock = fixture.manager.lock().expect("lifecycle lock");
            fixture
                .manager
                .prepare_machine_ssh_identity_locked()
                .expect("generate identity");
            fixture
                .manager
                .acquire_machine_image_locked(target, None)
                .expect("cache exact machine image")
        };
        let expected_distribution = format!("podman-{}", machine_name(target));
        let listed = utf16le(&format!("{expected_distribution}\r\n"));
        fixture
            .commands
            .push(success(machine_json(&fixture.manager, false)));
        fixture.commands.push(success(Vec::new()));
        let mut first_inventory = success(listed.clone());
        first_inventory.stderr = b"WSL update notice".to_vec();
        fixture.commands.push(first_inventory);

        let error = fixture
            .manager
            .uninstall(ManagedUninstallOptions {
                stop_mode: ManagedStopMode::Force,
                remove_machine_image_cache: true,
            })
            .expect_err("a still-registered exact WSL distro must retain all private state");

        assert!(
            error
                .to_string()
                .contains("Windows still reports the selected scan workspace")
        );
        assert!(error.to_string().contains("provider data was preserved"));
        assert!(fixture.manager.install_directory().exists());
        assert!(fixture.manager.provider_home().exists());
        assert!(identity.is_file());
        assert_eq!(fs::read(&image).unwrap(), fixture.image);
        let calls = fixture.commands.calls();
        assert_eq!(calls[2], ["--list", "--quiet"]);
        assert_eq!(calls.len(), 3);
        let commands = fixture.commands.commands();
        assert_eq!(commands[2].binary.file_name(), Some(OsStr::new("wsl.exe")));
    }

    #[cfg(windows)]
    #[test]
    fn uninstall_uses_verified_machine_rm_then_proves_wsl_distribution_absent() {
        let mut fixture = fixture();
        fixture.manager.install().expect("install");
        seed_owned_windows_lifecycle_fixture(
            &mut fixture,
            FixtureWindowsRegistrationLifecycle::PresentThenAbsent,
        );
        let target = fixture.manager.loaded.target().expect("target");
        fixture
            .manager
            .runtime_command(target)
            .expect("private provider home");
        fixture
            .commands
            .push(success(machine_json(&fixture.manager, false)));
        fixture.commands.push(success(Vec::new()));
        fixture.commands.push(success(utf16le("Ubuntu\r\n")));

        let status = fixture
            .manager
            .uninstall(ManagedUninstallOptions::default())
            .expect("verified machine removal and read-only WSL absence proof");

        assert_eq!(status.phase, ManagedRuntimePhase::NotInstalled);
        assert!(!fixture.manager.install_directory().exists());
        assert!(!fixture.manager.provider_home().exists());
        let calls = fixture.commands.calls();
        assert_eq!(calls[1][..3], ["machine", "rm", "--force"]);
        assert_eq!(calls[2], ["--list", "--quiet"]);
        assert_eq!(calls.len(), 3);
        assert!(
            calls
                .iter()
                .flatten()
                .all(|argument| !argument.contains("podman-*") && !argument.contains("assm1-*"))
        );
    }

    #[test]
    fn uninstall_recovers_stale_provider_state_after_the_install_payload_was_lost() {
        let mut fixture = fixture();
        fixture.manager.install().expect("install");
        seed_owned_windows_lifecycle_fixture(
            &mut fixture,
            FixtureWindowsRegistrationLifecycle::Absent,
        );
        let target = fixture.manager.loaded.target().expect("target");
        fixture
            .manager
            .runtime_command(target)
            .expect("private provider home");
        {
            let _lock = fixture.manager.lock().expect("lifecycle lock");
            fixture
                .manager
                .prepare_machine_ssh_identity_locked()
                .expect("generate identity");
        }
        remove_private_tree(
            &fixture.manager.install_directory(),
            &fixture.manager.versions_root(),
        )
        .expect("simulate interrupted older uninstall");
        assert!(!fixture.manager.install_directory().exists());
        assert!(fixture.manager.provider_home().exists());
        fixture.commands.push(success(b"[]".to_vec()));
        push_windows_wsl_absent(&fixture.commands);

        let status = fixture
            .manager
            .uninstall(ManagedUninstallOptions::default())
            .expect("restore the verified client and clean stale provider state");

        assert_eq!(status.phase, ManagedRuntimePhase::NotInstalled);
        assert!(!fixture.manager.install_directory().exists());
        assert!(!fixture.manager.provider_home().exists());
        assert_eq!(
            fixture.commands.calls().len(),
            if cfg!(windows) { 2 } else { 1 }
        );
    }

    #[test]
    fn uninstall_rejects_an_unexpected_machine_before_removing_provider_state() {
        let mut fixture = fixture();
        fixture.manager.install().expect("install");
        seed_owned_windows_lifecycle_fixture(
            &mut fixture,
            FixtureWindowsRegistrationLifecycle::Absent,
        );
        let target = fixture.manager.loaded.target().expect("target");
        fixture
            .manager
            .runtime_command(target)
            .expect("private provider home");
        let identity = fixture.manager.machine_ssh_identity_path();
        {
            let _lock = fixture.manager.lock().expect("lifecycle lock");
            fixture
                .manager
                .prepare_machine_ssh_identity_locked()
                .expect("generate identity");
        }
        fixture.commands.push(success(
            serde_json::to_vec(&serde_json::json!([{
                "Name": "unexpected-private-machine",
                "Running": false,
                "VMType": target.provider.argument(),
                "CPUs": 2,
                "Memory": (4096_u64 * 1024 * 1024).to_string(),
                "DiskSize": (40_u64 * 1024 * 1024 * 1024).to_string()
            }]))
            .unwrap(),
        ));

        let error = fixture
            .manager
            .uninstall(ManagedUninstallOptions::default())
            .expect_err("unexpected machine must fail closed");

        assert!(error.to_string().contains("unexpected machine"));
        assert!(fixture.manager.install_directory().exists());
        assert!(fixture.manager.provider_home().exists());
        assert!(identity.is_file());
        assert_eq!(fixture.commands.calls().len(), 1);
    }

    #[test]
    fn installed_runtime_reopens_by_exact_manifest_and_ambiguity_fails_closed() {
        let fixture = fixture();
        fixture.manager.install().expect("install");
        let expected_digest = fixture.manager.manifest_sha256().to_owned();
        let app_data = fixture
            .manager
            .state_root
            .parent()
            .expect("app data parent")
            .to_path_buf();

        let reopened = ManagedRuntimeManager::open_installed(&app_data, Some(&expected_digest))
            .expect("reopen exact installation");
        assert_eq!(reopened.manifest_sha256(), expected_digest);

        let mut alternate_manifest = fixture.manager.loaded.manifest.clone();
        alternate_manifest.runtime_version = "5.8.1".into();
        let alternate_bytes = serde_json::to_vec(&alternate_manifest).expect("alternate manifest");
        let alternate = LoadedManagedRuntimeManifest::parse(&alternate_bytes).expect("alternate");
        let alternate_root = fixture
            .manager
            .versions_root()
            .join(installation_directory_name(&alternate));
        fs::create_dir(&alternate_root).expect("alternate root");
        fs::create_dir(alternate_root.join("bin")).expect("alternate bin");
        fs::write(alternate_root.join("manifest.json"), alternate_bytes)
            .expect("alternate manifest file");
        fs::write(alternate_root.join("bin/podman"), b"managed-podman-driver")
            .expect("alternate driver");

        let error = ManagedRuntimeManager::open_installed(&app_data, None)
            .expect_err("ambiguous install must fail closed");
        assert!(error.to_string().contains("exact manifest digest"));
        let exact = ManagedRuntimeManager::open_installed(&app_data, Some(&expected_digest))
            .expect("exact installation remains resolvable");
        assert_eq!(exact.manifest_sha256(), expected_digest);
    }

    #[test]
    fn product_uninstall_opens_an_exact_runtime_despite_a_malformed_sibling() {
        let fixture = fixture();
        fixture.manager.install().expect("install");
        let expected_digest = fixture.manager.manifest_sha256().to_owned();
        let app_data = fixture
            .manager
            .state_root
            .parent()
            .expect("app data parent")
            .to_path_buf();
        let malformed = fixture
            .manager
            .versions_root()
            .join("unknown-provider-state");
        fs::create_dir(&malformed).expect("malformed sibling");
        fs::write(malformed.join("must-remain"), b"ambiguous state").expect("ambiguous marker");

        assert!(
            ManagedRuntimeManager::open_installed(&app_data, Some(&expected_digest)).is_err(),
            "ordinary exact open retains its strict sibling policy"
        );
        let exact = ManagedRuntimeManager::open_installed_for_product_uninstall(
            &app_data,
            &expected_digest,
        )
        .expect("uninstall must still stop the separately verified runtime");

        assert_eq!(exact.manifest_sha256(), expected_digest);
        assert_eq!(
            fs::read(malformed.join("must-remain")).unwrap(),
            b"ambiguous state"
        );
    }

    #[test]
    fn exact_legacy_v2_installation_reopens_without_weakening_current_bundle_rules() {
        let mut fixture = fixture();
        let mut legacy_manifest = fixture.manager.loaded.manifest.clone();
        legacy_manifest.schema_version = LEGACY_MANIFEST_SCHEMA_VERSION.into();
        legacy_manifest.management_contract_revision = None;
        let legacy_bytes = serde_json::to_vec(&legacy_manifest).expect("legacy manifest");
        let legacy_loaded =
            LoadedManagedRuntimeManifest::parse(&legacy_bytes).expect("strict legacy manifest");
        let expected_digest = legacy_loaded.sha256.clone();
        fixture.manager.loaded = legacy_loaded;
        fixture.manager.install().expect("install legacy payload");
        let app_data = fixture
            .manager
            .state_root
            .parent()
            .expect("app data parent")
            .to_path_buf();

        let reopened = ManagedRuntimeManager::open_installed(&app_data, Some(&expected_digest))
            .expect("reopen exact legacy schema 2 installation");
        assert_eq!(reopened.manifest_sha256(), expected_digest);
        assert_eq!(
            reopened.loaded.manifest.schema_version,
            LEGACY_MANIFEST_SCHEMA_VERSION
        );
        assert!(
            reopened
                .loaded
                .manifest
                .management_contract_revision
                .is_none()
        );
    }

    #[test]
    fn changed_release_file_is_never_installed() {
        let fixture = fixture();
        fs::write(
            fixture.manager.resource_root.join("bin/podman"),
            b"tampered-driver",
        )
        .expect("tamper");
        assert!(fixture.manager.install().is_err());
        assert!(!fixture.manager.install_directory().exists());
    }

    #[test]
    fn start_acquires_exact_image_initializes_rootless_machine_and_preflights() {
        let mut fixture = fixture();
        let _initialized_vhd = configure_fresh_windows_machine_registration(&mut fixture);
        push_windows_wsl_ready(&fixture.commands);
        push_windows_wsl_absent(&fixture.commands);
        fixture.commands.push(success(b"[]".to_vec()));
        push_windows_wsl_absent(&fixture.commands);
        #[cfg(windows)]
        fixture.commands.push(success(b"[]".to_vec()));
        #[cfg(windows)]
        fixture.commands.push_with_side_effect(
            success(Vec::new()),
            FakeCommandSideEffect::CreateManagedWslVhd {
                path: _initialized_vhd,
                bytes: b"fresh-initialized-generation".to_vec(),
            },
        );
        #[cfg(not(windows))]
        fixture.commands.push(success(Vec::new()));
        fixture
            .commands
            .push(success(fresh_machine_json(&fixture.manager, false)));
        fixture.commands.push(success(Vec::new()));
        fixture.commands.push(success(b"5.8.2\n".to_vec()));

        let command = fixture.manager.start().expect("start");
        assert_eq!(command.runtime_version(), "5.8.2");
        let calls = fixture.commands.calls();
        let first_machine_inventory = if cfg!(windows) { 3 } else { 0 };
        if cfg!(windows) {
            assert_eq!(calls[0], ["--status"]);
            assert_eq!(calls[1], ["-l", "--quiet"]);
            assert_eq!(calls[2], ["--list", "--quiet"]);
        }
        assert_eq!(
            calls[first_machine_inventory],
            ["machine", "list", "--format", "json"]
        );
        let init_index = if cfg!(windows) { 6 } else { 1 };
        if cfg!(windows) {
            assert_eq!(calls[4], ["--list", "--quiet"]);
            assert_eq!(calls[5], ["machine", "list", "--format", "json"]);
        }
        let init = &calls[init_index];
        assert_eq!(&init[..2], ["machine", "init"]);
        assert!(init.contains(&"--rootful=false".into()));
        assert!(init.contains(&"--image".into()));
        assert!(!init.contains(&"--provider".into()));
        let target = fixture.manager.loaded.target().expect("target");
        let volume_values = init
            .windows(2)
            .filter_map(|arguments| (arguments[0] == "--volume").then_some(arguments[1].clone()))
            .collect::<Vec<_>>();
        if target.operating_system == ManagedOperatingSystem::Linux {
            let application_data = fixture
                .manager
                .canonical_application_data_root()
                .expect("canonical application data");
            assert_eq!(
                volume_values,
                [linux_machine_volume_spec(&application_data)
                    .expect("Linux volume")
                    .to_string_lossy()
                    .into_owned()]
            );
        } else {
            assert!(volume_values.is_empty());
        }
        assert!(
            !init
                .iter()
                .any(|argument| argument == "sudo" || argument == "sh")
        );
        assert_eq!(calls[init_index + 2][..3], ["machine", "start", "--quiet"]);
        assert_eq!(
            calls[init_index + 3],
            ["version", "--format", "{{.Server.Version}}"]
        );
        let mut expected_timeouts = vec![];
        if cfg!(windows) {
            expected_timeouts.extend([
                COMMAND_TIMEOUT,
                COMMAND_TIMEOUT,
                COMMAND_TIMEOUT,
                COMMAND_TIMEOUT,
                COMMAND_TIMEOUT,
                COMMAND_TIMEOUT,
            ]);
        } else {
            expected_timeouts.push(COMMAND_TIMEOUT);
        }
        expected_timeouts.extend([MACHINE_INIT_TIMEOUT, COMMAND_TIMEOUT]);
        let actual_timeouts = fixture.commands.timeouts();
        assert_eq!(
            &actual_timeouts[..actual_timeouts.len() - 2],
            expected_timeouts.as_slice()
        );
        let machine_start_timeout = actual_timeouts[actual_timeouts.len() - 2];
        assert!(machine_start_timeout > Duration::ZERO);
        assert!(machine_start_timeout <= MACHINE_START_TIMEOUT);
        assert_eq!(
            actual_timeouts.last(),
            Some(&SERVER_READINESS_PROBE_TIMEOUT)
        );
        let cached = fixture
            .manager
            .machine_image_path(fixture.manager.loaded.target().expect("target"));
        assert_eq!(fs::read(cached).expect("cached"), fixture.image);

        let identity = fixture.manager.machine_ssh_identity_path();
        let private_bytes = Zeroizing::new(fs::read(&identity).expect("private identity"));
        let private_key =
            PrivateKey::from_openssh(private_bytes.as_slice()).expect("OpenSSH private key");
        let public_text =
            fs::read_to_string(managed_ssh_public_key_path(&identity)).expect("public identity");
        let public_key = PublicKey::from_openssh(&public_text).expect("OpenSSH public key");
        assert_eq!(private_key.algorithm(), Algorithm::Ed25519);
        assert!(!private_key.is_encrypted());
        assert_eq!(public_key.algorithm(), Algorithm::Ed25519);
        assert_eq!(private_key.public_key().key_data(), public_key.key_data());
        assert_eq!(private_key.comment(), MANAGED_SSH_KEY_COMMENT);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&identity).unwrap().permissions().mode() & 0o777,
                0o600
            );
            assert_eq!(
                fs::metadata(managed_ssh_public_key_path(&identity))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn persistent_unrelated_malformed_registration_does_not_churn_a_proven_isolated_runtime() {
        let mut fixture = fixture();
        let target = fixture
            .manager
            .loaded
            .target()
            .expect("Windows target")
            .clone();
        let selected_machine = fixture.manager.isolated_windows_machine_name(&target, 1);
        let selected_storage =
            fixture
                .manager
                .windows_wsl_distribution_storage_path(&target, &selected_machine, 1);
        let selected_vhd = selected_storage.join("ext4.vhdx");
        let registration = WindowsWslRegistration {
            registration_id: "00000000-0000-0000-0000-000000000081".into(),
            distribution_name: format!("podman-{selected_machine}"),
            base_path: selected_storage,
        };
        fixture.manager.wsl_registrations = Arc::new(PartialWindowsWslRegistrationAfterVhdExists {
            registration: registration.clone(),
            vhd: selected_vhd.clone(),
        });

        push_windows_wsl_ready(&fixture.commands);
        push_windows_wsl_absent(&fixture.commands);
        fixture.commands.push(success(b"[]".to_vec()));
        push_windows_wsl_absent(&fixture.commands);
        fixture.commands.push(success(b"[]".to_vec()));
        fixture.commands.push_with_side_effect(
            success(Vec::new()),
            FakeCommandSideEffect::CreateManagedWslVhd {
                path: selected_vhd.clone(),
                bytes: b"partial-inventory-product-generation".to_vec(),
            },
        );
        fixture.commands.push(success(machine_json_named(
            &fixture.manager,
            &selected_machine,
            false,
        )));
        fixture.commands.push(success(Vec::new()));
        fixture.commands.push(success(b"5.8.2\n".to_vec()));

        fixture
            .manager
            .start()
            .expect("fresh partial inventory should initialize one isolated generation");

        let first_selection = fixture
            .manager
            .read_windows_wsl_generation_selection_locked(&target)
            .expect("read first selection")
            .expect("first isolated generation");
        assert_eq!(first_selection.generation_index, 1);
        assert_eq!(first_selection.selected_machine_name, selected_machine);
        assert!(
            fixture
                .manager
                .has_exact_windows_wsl_ownership_proof_locked(
                    &target,
                    &selected_machine,
                    WindowsWslOwnershipBasis::ProvenMachine,
                )
                .expect("read promoted product proof")
        );
        let stale_intent = fixture.manager.windows_wsl_ownership_proof_path(
            &selected_machine,
            WindowsWslOwnershipBasis::InitIntent,
        );
        fs::create_dir_all(&stale_intent).expect("unreadable stale init-intent fixture");

        fixture.commands.push(success(machine_json_named(
            &fixture.manager,
            &selected_machine,
            true,
        )));
        fixture.commands.push(success(b"5.8.2\n".to_vec()));
        let status = fixture
            .manager
            // This fixture proves inventory classification, not the production
            // timeout boundary. Full-suite Windows ACL and filesystem load can
            // otherwise consume the synthetic two-second budget before the
            // queued fake machine/server probes run.
            .status_locked_with_command_budget(COMMAND_TIMEOUT)
            .expect("status should prove the selected runtime from the exact partial binding");
        assert_eq!(status.phase, ManagedRuntimePhase::Running);
        assert!(status.available);
        assert!(stale_intent.is_dir());

        let selected_distribution = registration.distribution_name.clone();
        push_windows_wsl_ready(&fixture.commands);
        fixture
            .commands
            .push(success(utf16le(&format!("{selected_distribution}\r\n"))));
        fixture.commands.push(success(machine_json_named(
            &fixture.manager,
            &selected_machine,
            true,
        )));
        fixture
            .commands
            .push(success(utf16le(&format!("{selected_distribution}\r\n"))));
        for _ in 0..2 {
            fixture.commands.push(success(machine_json_named(
                &fixture.manager,
                &selected_machine,
                true,
            )));
        }
        fixture.commands.push(success(b"5.8.2\n".to_vec()));

        fixture
            .manager
            .start()
            .expect("a second start should reuse the same proven generation");

        let repeated_selection = fixture
            .manager
            .read_windows_wsl_generation_selection_locked(&target)
            .expect("read repeated selection")
            .expect("reused isolated generation");
        assert_eq!(repeated_selection, first_selection);
        assert!(stale_intent.is_dir());
        assert!(
            !fixture
                .manager
                .windows_generation_selection_exists(2)
                .expect("inspect generation two selection")
        );
        assert_eq!(
            fixture
                .commands
                .calls()
                .iter()
                .filter(|call| call.len() >= 2 && call[0] == "machine" && call[1] == "init")
                .count(),
            1
        );
        assert_eq!(
            fs::read(&selected_vhd).expect("preserved selected VHD"),
            b"partial-inventory-product-generation"
        );

        let command = fixture
            .manager
            .runtime_command(&target)
            .expect("selected runtime command");
        push_windows_wsl_absent(&fixture.commands);
        let cleanup_error = fixture
            .manager
            .require_current_windows_wsl_distribution_absent_for_cleanup_locked(
                &target,
                &command,
                &selected_machine,
            )
            .expect_err("partial registration inventory must never authorize cleanup");
        assert!(matches!(cleanup_error, AppError::NotAvailable(_)));
        assert_eq!(
            fs::read(&selected_vhd).expect("VHD remains after refused cleanup"),
            b"partial-inventory-product-generation"
        );
    }

    #[cfg(windows)]
    #[test]
    fn verified_windows_machine_start_exit_125_reconciles_running_state_in_one_call() {
        let mut fixture = fixture();
        let (target, existing_machine, existing_vhd, existing_registration) =
            seed_verified_existing_windows_machine(&mut fixture);
        let existing_bytes = fs::read(&existing_vhd).expect("existing VHD snapshot");
        fixture.manager.wsl_registrations =
            Arc::new(FixedWindowsWslRegistrations(vec![existing_registration]));

        let existing_distribution = format!("podman-{existing_machine}");
        push_windows_wsl_ready(&fixture.commands);
        fixture
            .commands
            .push(success(utf16le(&format!("{existing_distribution}\r\n"))));
        fixture.commands.push(success(machine_json_named(
            &fixture.manager,
            &existing_machine,
            false,
        )));
        fixture
            .commands
            .push(success(utf16le(&format!("{existing_distribution}\r\n"))));
        for _ in 0..2 {
            fixture.commands.push(success(machine_json_named(
                &fixture.manager,
                &existing_machine,
                false,
            )));
        }
        fixture
            .commands
            .push(failure_with_status(125, b"transient SSH port race"));
        fixture.commands.push(success(machine_json_named(
            &fixture.manager,
            &existing_machine,
            true,
        )));
        fixture.commands.push(success(b"5.8.2\n".to_vec()));

        let retried = fixture
            .manager
            .start()
            .expect("the same setup call should reconcile a transient start race");

        assert_eq!(retried.runtime_version(), "5.8.2");
        assert_eq!(fs::read(&existing_vhd).unwrap(), existing_bytes);
        let selection = fixture
            .manager
            .read_windows_wsl_generation_selection_locked(&target)
            .unwrap()
            .unwrap();
        assert_eq!(selection.generation_index, 0);
        assert_eq!(selection.selected_machine_name, existing_machine);
        assert!(selection.preserved_collision_names.is_empty());
        let calls = fixture.commands.calls();
        assert_eq!(
            calls
                .iter()
                .filter(|call| call.len() >= 2 && call[0] == "machine" && call[1] == "init")
                .count(),
            0
        );
        assert_eq!(
            calls
                .iter()
                .filter(|call| call.len() >= 2 && call[0] == "machine" && call[1] == "start")
                .count(),
            1,
            "exit 125 can race with a machine that is already running; one setup call must reconcile it without another mutation"
        );
        assert!(calls.iter().flatten().all(|argument| {
            argument != "--unregister" && argument != "--export" && argument != "--import"
        }));
    }

    #[cfg(windows)]
    #[test]
    fn verified_windows_readiness_failure_is_retryable_without_creating_a_generation() {
        let mut fixture = fixture();
        let (target, existing_machine, existing_vhd, existing_registration) =
            seed_verified_existing_windows_machine(&mut fixture);
        let existing_bytes = fs::read(&existing_vhd).expect("existing VHD snapshot");
        fixture.manager.wsl_registrations =
            Arc::new(FixedWindowsWslRegistrations(vec![existing_registration]));

        let existing_distribution = format!("podman-{existing_machine}");
        push_windows_wsl_ready(&fixture.commands);
        fixture
            .commands
            .push(success(utf16le(&format!("{existing_distribution}\r\n"))));
        fixture.commands.push(success(machine_json_named(
            &fixture.manager,
            &existing_machine,
            true,
        )));
        fixture
            .commands
            .push(success(utf16le(&format!("{existing_distribution}\r\n"))));
        for _ in 0..2 {
            fixture.commands.push(success(machine_json_named(
                &fixture.manager,
                &existing_machine,
                true,
            )));
        }
        fixture
            .commands
            .push(failure(b"server preflight unavailable"));

        let _lock = fixture.manager.lock().expect("lifecycle lock");
        let error = fixture
            .manager
            .start_locked_with_startup_timeout(None, Duration::from_millis(20))
            .expect_err("readiness failure must remain retryable on the exact owned machine");

        assert!(matches!(&error, AppError::NotAvailable(_)));
        assert!(
            error
                .to_string()
                .contains("managed runtime server readiness check incomplete")
        );
        assert_eq!(fs::read(&existing_vhd).unwrap(), existing_bytes);
        let first_probe_timeout = *fixture.commands.timeouts().last().expect("probe timeout");
        assert!(first_probe_timeout > Duration::ZERO);
        assert!(first_probe_timeout <= Duration::from_millis(20));

        push_windows_wsl_ready(&fixture.commands);
        fixture
            .commands
            .push(success(utf16le(&format!("{existing_distribution}\r\n"))));
        fixture.commands.push(success(machine_json_named(
            &fixture.manager,
            &existing_machine,
            true,
        )));
        fixture
            .commands
            .push(success(utf16le(&format!("{existing_distribution}\r\n"))));
        for _ in 0..2 {
            fixture.commands.push(success(machine_json_named(
                &fixture.manager,
                &existing_machine,
                true,
            )));
        }
        fixture.commands.push(success(b"5.8.2\n".to_vec()));

        let retried = fixture
            .manager
            .start_locked_with_startup_timeout(None, Duration::from_secs(1))
            .expect("retry must reuse the same generation once its server is ready");
        assert_eq!(retried.runtime_version(), "5.8.2");

        let selection = fixture
            .manager
            .read_windows_wsl_generation_selection_locked(&target)
            .unwrap()
            .unwrap();
        assert_eq!(selection.generation_index, 0);
        assert_eq!(selection.selected_machine_name, existing_machine);
        assert!(selection.preserved_collision_names.is_empty());
        let calls = fixture.commands.calls();
        assert_eq!(
            calls
                .iter()
                .filter(|call| call.len() >= 2 && call[0] == "machine" && call[1] == "init")
                .count(),
            0
        );
        assert_eq!(
            calls
                .iter()
                .filter(|call| call.len() >= 2 && call[0] == "machine" && call[1] == "start")
                .count(),
            0,
            "the already-running exact-owned machine must be left in place"
        );
        assert_eq!(
            calls
                .iter()
                .filter(|call| call.first().is_some_and(|argument| argument == "version"))
                .count(),
            2
        );
        assert!(calls.iter().flatten().all(|argument| {
            argument != "--unregister" && argument != "--export" && argument != "--import"
        }));
    }

    #[test]
    fn server_readiness_probe_is_capped_by_the_remaining_total_budget() {
        let fixture = fixture();
        let command = ManagedRuntimeCommand {
            binary: fixture._temp.path().join("managed-podman"),
            environment: BTreeMap::new(),
            working_directory: fixture.manager.state_root.clone(),
            runtime_version: "5.8.2".into(),
            manifest_sha256: "a".repeat(64),
            machine_image_sha256: "b".repeat(64),
            #[cfg(windows)]
            windows_launch_authorization: WindowsManagedRuntimeLaunchAuthorization::MetadataOnly,
        };
        fixture
            .commands
            .push(failure(b"server transport unavailable"));
        let total_budget = Duration::from_millis(20);

        let error = fixture
            .manager
            .wait_for_server(&command, total_budget, None)
            .expect_err("server must remain unavailable within the fixture budget");

        assert!(error.to_string().contains("bounded deadline"));
        assert_eq!(
            fixture.commands.calls(),
            [vec![
                String::from("version"),
                String::from("--format"),
                String::from("{{.Server.Version}}"),
            ]]
        );
        let timeouts = fixture.commands.timeouts();
        assert_eq!(timeouts.len(), 1);
        assert!(timeouts[0] > Duration::ZERO);
        assert!(timeouts[0] <= total_budget);
        assert!(timeouts[0] < COMMAND_TIMEOUT);
    }

    #[test]
    fn machine_start_and_server_readiness_share_one_total_budget() {
        let fixture = fixture();
        let command = ManagedRuntimeCommand {
            binary: fixture._temp.path().join("managed-podman"),
            environment: BTreeMap::new(),
            working_directory: fixture.manager.state_root.clone(),
            runtime_version: "5.8.2".into(),
            manifest_sha256: "a".repeat(64),
            machine_image_sha256: "b".repeat(64),
            #[cfg(windows)]
            windows_launch_authorization: WindowsManagedRuntimeLaunchAuthorization::MetadataOnly,
        };
        let total_budget = Duration::from_millis(10);
        fixture
            .commands
            .push_with_delay(success(Vec::new()), Duration::from_millis(30));
        let started = Instant::now();

        let error = fixture
            .manager
            .start_machine_and_wait_locked(
                &command,
                "exact-owned-machine",
                false,
                None,
                total_budget,
            )
            .expect_err("an exhausted shared budget must not open a second readiness window");

        match error {
            MachineStartAttemptFailure::ServerReadiness(error) => {
                assert!(error.to_string().contains("shared startup budget"));
            }
            other => panic!("unexpected startup failure classification: {other:?}"),
        }
        assert!(started.elapsed() < Duration::from_secs(1));
        assert_eq!(
            fixture.commands.calls(),
            [vec![
                String::from("machine"),
                String::from("start"),
                String::from("--quiet"),
                String::from("exact-owned-machine"),
            ]],
            "no version probe may begin after machine start exhausts the shared budget"
        );
        let timeouts = fixture.commands.timeouts();
        assert_eq!(timeouts.len(), 1);
        assert!(timeouts[0] > Duration::ZERO);
        assert!(timeouts[0] <= total_budget);
    }

    #[test]
    fn status_reports_lifecycle_contention_without_waiting_for_the_lock_deadline() {
        let fixture = fixture();
        let _lock = fixture.manager.lock().expect("hold lifecycle lock");
        let started = Instant::now();

        let status = fixture.manager.status().expect("busy status");

        assert!(started.elapsed() < Duration::from_secs(1));
        assert_eq!(status.phase, ManagedRuntimePhase::Starting);
        assert!(!status.available);
        assert!(status.detail.contains("lifecycle operation is active"));
        assert!(fixture.commands.calls().is_empty());
    }

    #[test]
    fn status_machine_inventory_uses_a_short_budget_and_returns_truthful_state_on_timeout() {
        let mut fixture = fixture();
        #[cfg(windows)]
        {
            let (_, _, _, registration) = seed_verified_existing_windows_machine(&mut fixture);
            fixture.manager.wsl_registrations =
                Arc::new(FixedWindowsWslRegistrations(vec![registration]));
        }
        #[cfg(not(windows))]
        fixture.manager.install().expect("install current payload");
        let commands = Arc::new(DeadlineFailingCommands::default());
        fixture.manager.commands = commands.clone();

        let status = fixture.manager.status().expect("bounded status result");

        assert_eq!(status.phase, ManagedRuntimePhase::Starting);
        assert!(!status.available);
        assert!(
            status
                .detail
                .contains("machine state could not be confirmed")
        );
        assert!(status.detail.contains("command exceeded its deadline"));
        assert_eq!(
            commands.calls.lock().expect("calls").as_slice(),
            [vec![
                String::from("machine"),
                String::from("list"),
                String::from("--format"),
                String::from("json"),
            ]]
        );
        let timeouts = commands.timeouts.lock().expect("timeouts");
        assert_eq!(timeouts.len(), 1);
        assert!(timeouts[0] > Duration::ZERO);
        assert!(timeouts[0] <= STATUS_RECONCILIATION_COMMAND_BUDGET);
        assert!(timeouts[0] < COMMAND_TIMEOUT);
    }

    #[test]
    fn status_reports_invalid_machine_inventory_as_repairable_corruption() {
        for output in [
            success(b"not-json".to_vec()),
            failure(b"inventory failed".to_vec()),
        ] {
            #[cfg(windows)]
            let mut fixture = fixture();
            #[cfg(not(windows))]
            let fixture = fixture();
            #[cfg(windows)]
            {
                let (_, _, _, registration) = seed_verified_existing_windows_machine(&mut fixture);
                fixture.manager.wsl_registrations =
                    Arc::new(FixedWindowsWslRegistrations(vec![registration]));
            }
            #[cfg(not(windows))]
            fixture.manager.install().expect("install current payload");
            fixture.commands.push(output);

            // This test classifies an immediate fake response, not the
            // separate bounded-status timeout path. Leave enough budget for
            // fixture ACL and manifest verification under a parallel suite.
            let status = fixture
                .manager
                .status_locked_with_command_budget(COMMAND_TIMEOUT)
                .expect("invalid inventory status");

            assert_eq!(status.phase, ManagedRuntimePhase::Corrupt);
            assert!(!status.available);
            assert!(
                status
                    .detail
                    .contains("machine inventory contract is invalid and needs repair")
            );
            assert!(!status.detail.contains("within the bounded status budget"));
        }
    }

    #[test]
    fn status_with_no_inventory_budget_reports_reconciling_without_running_a_command() {
        #[cfg(windows)]
        let mut fixture = fixture();
        #[cfg(not(windows))]
        let fixture = fixture();
        #[cfg(windows)]
        {
            let (_, _, _, registration) = seed_verified_existing_windows_machine(&mut fixture);
            fixture.manager.wsl_registrations =
                Arc::new(FixedWindowsWslRegistrations(vec![registration]));
        }
        #[cfg(not(windows))]
        fixture.manager.install().expect("install current payload");

        let status = fixture
            .manager
            .status_locked_with_command_budget(Duration::ZERO)
            .expect("bounded status result");

        assert_eq!(status.phase, ManagedRuntimePhase::Starting);
        assert!(!status.available);
        assert!(status.detail.contains("was not queried"));
        assert!(fixture.commands.calls().is_empty());
    }

    #[test]
    fn status_with_confirmed_empty_inventory_remains_first_launch_installed() {
        #[cfg(windows)]
        let mut fixture = fixture();
        #[cfg(not(windows))]
        let fixture = fixture();
        #[cfg(windows)]
        {
            let (_, _, _, registration) = seed_verified_existing_windows_machine(&mut fixture);
            fixture.manager.wsl_registrations =
                Arc::new(FixedWindowsWslRegistrations(vec![registration]));
        }
        #[cfg(not(windows))]
        fixture.manager.install().expect("install current payload");
        fixture.commands.push(success(b"[]".to_vec()));

        let status = fixture
            .manager
            .status_locked_with_command_budget(Duration::from_secs(2))
            .expect("confirmed first-launch status");

        assert_eq!(status.phase, ManagedRuntimePhase::Installed);
        assert!(!status.available);
        assert!(status.detail.contains("has not been initialized"));
        assert_eq!(
            fixture.commands.calls(),
            [vec![
                String::from("machine"),
                String::from("list"),
                String::from("--format"),
                String::from("json"),
            ]]
        );
    }

    #[test]
    fn status_inventory_and_server_probe_share_one_command_deadline() {
        #[cfg(windows)]
        let mut fixture = fixture();
        #[cfg(not(windows))]
        let fixture = fixture();
        #[cfg(windows)]
        {
            let (_, _, _, registration) = seed_verified_existing_windows_machine(&mut fixture);
            fixture.manager.wsl_registrations =
                Arc::new(FixedWindowsWslRegistrations(vec![registration]));
        }
        #[cfg(not(windows))]
        fixture.manager.install().expect("install current payload");
        fixture.commands.push_with_delay(
            success(machine_json(&fixture.manager, true)),
            Duration::from_millis(25),
        );
        fixture.commands.push(success(b"5.8.2\n".to_vec()));
        let budget = Duration::from_secs(2);

        let status = fixture
            .manager
            .status_locked_with_command_budget(budget)
            .expect("running status");

        assert_eq!(status.phase, ManagedRuntimePhase::Running);
        assert!(status.available);
        let timeouts = fixture.commands.timeouts();
        assert_eq!(timeouts.len(), 2);
        assert!(timeouts[0] > Duration::ZERO);
        assert!(timeouts[0] <= budget);
        assert!(timeouts[1] > Duration::ZERO);
        assert!(timeouts[1] < timeouts[0]);
        assert!(timeouts[1] <= budget);
    }

    #[cfg(windows)]
    #[test]
    fn windows_machine_init_retries_once_after_reproving_complete_absence() {
        let mut fixture = fixture();
        let initialized_vhd = configure_fresh_windows_machine_registration(&mut fixture);

        push_windows_wsl_ready(&fixture.commands);
        push_windows_wsl_absent(&fixture.commands);
        fixture.commands.push(success(b"[]".to_vec()));
        push_windows_wsl_absent(&fixture.commands);
        fixture.commands.push(success(b"[]".to_vec()));
        fixture
            .commands
            .push(failure(b"transient WSL import failure"));

        push_windows_wsl_ready(&fixture.commands);
        push_windows_wsl_absent(&fixture.commands);
        fixture.commands.push(success(b"[]".to_vec()));
        fixture.commands.push_with_side_effect(
            success(Vec::new()),
            FakeCommandSideEffect::CreateManagedWslVhd {
                path: initialized_vhd,
                bytes: b"bounded-retry-generation".to_vec(),
            },
        );

        fixture
            .commands
            .push(success(fresh_machine_json(&fixture.manager, false)));
        fixture.commands.push(success(Vec::new()));
        fixture.commands.push(success(b"5.8.2\n".to_vec()));

        let command = fixture.manager.start().expect("bounded Windows retry");
        assert_eq!(command.runtime_version(), "5.8.2");

        let calls = fixture.commands.calls();
        assert_eq!(calls.len(), 15);
        assert_eq!(calls[0], ["--status"]);
        assert_eq!(calls[1], ["-l", "--quiet"]);
        assert_eq!(calls[2], ["--list", "--quiet"]);
        assert_eq!(calls[3], ["machine", "list", "--format", "json"]);
        assert_eq!(calls[4], ["--list", "--quiet"]);
        assert_eq!(calls[5], ["machine", "list", "--format", "json"]);
        assert_eq!(calls[7], ["--status"]);
        assert_eq!(calls[8], ["-l", "--quiet"]);
        assert_eq!(calls[9], ["--list", "--quiet"]);
        assert_eq!(calls[10], ["machine", "list", "--format", "json"]);
        assert_eq!(calls[12], ["machine", "list", "--format", "json"]);
        assert_eq!(calls[13][..3], ["machine", "start", "--quiet"]);
        assert_eq!(calls[14], ["version", "--format", "{{.Server.Version}}"]);
        assert_eq!(
            calls
                .iter()
                .filter(|arguments| {
                    arguments.len() >= 2 && arguments[0] == "machine" && arguments[1] == "init"
                })
                .count(),
            2,
            "one initial attempt and one bounded retry are allowed"
        );
    }

    #[cfg(windows)]
    #[test]
    fn interrupted_windows_init_is_preserved_and_continues_in_a_fresh_generation() {
        let mut fixture = fixture();
        let target = fixture
            .manager
            .loaded
            .target()
            .expect("Windows target")
            .clone();
        let initial_machine = fixture.manager.isolated_windows_machine_name(&target, 1);
        let initial_distribution = format!("podman-{initial_machine}");
        let initial_vhd = fixture
            .manager
            .windows_wsl_distribution_storage_path(&target, &initial_machine, 1)
            .join("ext4.vhdx");
        let replacement_machine = fixture.manager.isolated_windows_machine_name(&target, 2);
        let replacement_storage =
            fixture
                .manager
                .windows_wsl_distribution_storage_path(&target, &replacement_machine, 2);
        let replacement_vhd = replacement_storage.join("ext4.vhdx");
        let replacement_registration = WindowsWslRegistration {
            registration_id: "00000000-0000-0000-0000-000000000041".into(),
            distribution_name: format!("podman-{replacement_machine}"),
            base_path: replacement_storage,
        };
        fixture.manager.wsl_registrations = Arc::new(WindowsWslRegistrationsForExistingPaths(
            vec![(replacement_vhd.clone(), replacement_registration)],
        ));

        push_windows_wsl_ready(&fixture.commands);
        push_windows_wsl_absent(&fixture.commands);
        fixture.commands.push(success(b"[]".to_vec()));
        push_windows_wsl_absent(&fixture.commands);
        fixture.commands.push(success(b"[]".to_vec()));
        fixture.commands.push_with_side_effect(
            failure(b"partial WSL import failure"),
            FakeCommandSideEffect::CreateManagedWslVhd {
                path: initial_vhd.clone(),
                bytes: b"interrupted-initial-generation".to_vec(),
            },
        );
        push_windows_wsl_ready(&fixture.commands);
        fixture
            .commands
            .push(success(utf16le(&format!("{initial_distribution}\r\n"))));
        fixture.commands.push(success(b"[]".to_vec()));
        fixture.commands.push_with_side_effect(
            success(Vec::new()),
            FakeCommandSideEffect::CreateManagedWslVhd {
                path: replacement_vhd.clone(),
                bytes: b"fresh-isolated-generation".to_vec(),
            },
        );
        fixture.commands.push(success(machine_json_named(
            &fixture.manager,
            &replacement_machine,
            false,
        )));
        fixture.commands.push(success(Vec::new()));
        fixture.commands.push(success(b"5.8.2\n".to_vec()));

        let command = fixture
            .manager
            .start()
            .expect("an interrupted product workspace must not block a fresh generation");

        assert_eq!(command.runtime_version(), "5.8.2");
        assert_eq!(
            fs::read(&initial_vhd).expect("preserved interrupted workspace"),
            b"interrupted-initial-generation"
        );
        assert_eq!(
            fs::read(&replacement_vhd).expect("fresh isolated workspace"),
            b"fresh-isolated-generation"
        );
        let selection = fixture
            .manager
            .read_windows_wsl_generation_selection_locked(&target)
            .expect("durable generation selection")
            .expect("one generation selection");
        assert_eq!(selection.generation_index, 2);
        assert_eq!(selection.selected_machine_name, replacement_machine);
        assert_eq!(
            selection.preserved_collision_names,
            vec![initial_machine.clone()]
        );

        let calls = fixture.commands.calls();
        let init_calls = calls
            .iter()
            .filter(|arguments| {
                arguments.len() >= 2 && arguments[0] == "machine" && arguments[1] == "init"
            })
            .collect::<Vec<_>>();
        assert_eq!(init_calls.len(), 2);
        assert_eq!(init_calls[0].last(), Some(&initial_machine));
        assert_eq!(init_calls[1].last(), Some(&selection.selected_machine_name));
        assert!(calls.iter().flatten().all(|argument| {
            argument != "--unregister" && argument != "--export" && argument != "--import"
        }));
    }

    #[cfg(windows)]
    #[test]
    fn windows_machine_init_never_retries_when_fresh_inventory_is_unknown() {
        let mut fixture = fixture();
        fixture.manager.wsl_registrations = Arc::new(FixedWindowsWslRegistrations(Vec::new()));

        push_windows_wsl_ready(&fixture.commands);
        push_windows_wsl_absent(&fixture.commands);
        fixture.commands.push(success(b"[]".to_vec()));
        push_windows_wsl_absent(&fixture.commands);
        fixture.commands.push(success(b"[]".to_vec()));
        fixture
            .commands
            .push(failure(b"transient WSL import failure"));
        push_windows_wsl_ready(&fixture.commands);
        fixture
            .commands
            .push(failure(b"fresh WSL inventory unavailable"));

        let error = fixture
            .manager
            .start()
            .expect_err("unknown WSL inventory must stop automatic retry");

        assert!(
            error
                .to_string()
                .contains("fresh WSL inventory unavailable")
        );
        let calls = fixture.commands.calls();
        assert_eq!(calls.len(), 10);
        assert_eq!(calls[9], ["--list", "--quiet"]);
        assert_eq!(
            calls
                .iter()
                .filter(|arguments| {
                    arguments.len() >= 2 && arguments[0] == "machine" && arguments[1] == "init"
                })
                .count(),
            1
        );
    }

    #[cfg(windows)]
    #[test]
    fn ambiguous_windows_registration_is_preserved_while_start_uses_fresh_generation() {
        let mut fixture = fixture();
        let target = fixture
            .manager
            .loaded
            .target()
            .expect("Windows target")
            .clone();
        let default_machine = machine_name(&target);
        let hidden_base = fixture._temp.path().join("unowned-wsl-registration");
        fs::create_dir(&hidden_base).expect("ambiguous registration directory");
        let sentinel = hidden_base.join("must-remain");
        fs::write(&sentinel, b"unowned-registration-bytes").expect("ambiguous bytes");
        let hidden_registration = WindowsWslRegistration {
            registration_id: "00000000-0000-0000-0000-000000000004".into(),
            distribution_name: format!("podman-{default_machine}"),
            base_path: hidden_base,
        };
        let isolated_machine = fixture.manager.isolated_windows_machine_name(&target, 1);
        let isolated_storage =
            fixture
                .manager
                .windows_wsl_distribution_storage_path(&target, &isolated_machine, 1);
        let isolated_vhd = isolated_storage.join("ext4.vhdx");
        let isolated_registration = WindowsWslRegistration {
            registration_id: "00000000-0000-0000-0000-000000000042".into(),
            distribution_name: format!("podman-{isolated_machine}"),
            base_path: isolated_storage,
        };
        fixture.manager.wsl_registrations =
            Arc::new(WindowsWslRegistrationsForExistingPaths(vec![
                (sentinel.clone(), hidden_registration),
                (isolated_vhd.clone(), isolated_registration),
            ]));

        push_windows_wsl_ready(&fixture.commands);
        push_windows_wsl_absent(&fixture.commands);
        fixture.commands.push(success(b"[]".to_vec()));
        push_windows_wsl_absent(&fixture.commands);
        fixture.commands.push(success(b"[]".to_vec()));
        fixture.commands.push_with_side_effect(
            success(Vec::new()),
            FakeCommandSideEffect::CreateManagedWslVhd {
                path: isolated_vhd,
                bytes: b"fresh-isolated-generation".to_vec(),
            },
        );
        fixture.commands.push(success(machine_json_named(
            &fixture.manager,
            &isolated_machine,
            false,
        )));
        fixture.commands.push(success(Vec::new()));
        fixture.commands.push(success(b"5.8.2\n".to_vec()));

        fixture
            .manager
            .start()
            .expect("an ambiguous registration must route setup side-by-side");

        assert_eq!(fs::read(&sentinel).unwrap(), b"unowned-registration-bytes");
        let selection = fixture
            .manager
            .read_windows_wsl_generation_selection_locked(&target)
            .unwrap()
            .unwrap();
        assert_eq!(selection.generation_index, 1);
        assert_eq!(selection.selected_machine_name, isolated_machine);
        assert_eq!(selection.preserved_collision_names, vec![default_machine]);
        let calls = fixture.commands.calls();
        assert_eq!(
            calls
                .iter()
                .filter(|arguments| {
                    arguments.len() >= 2 && arguments[0] == "machine" && arguments[1] == "init"
                })
                .count(),
            1
        );
        assert!(calls.iter().flatten().all(|argument| {
            argument != "--unregister" && argument != "--export" && argument != "--import"
        }));
    }

    #[cfg(windows)]
    #[test]
    fn windows_machine_init_never_retries_after_ownership_journal_cleanup_failure() {
        let mut fixture = fixture();
        fixture.manager.wsl_registrations = Arc::new(FixedWindowsWslRegistrations(Vec::new()));
        let target = fixture.manager.loaded.target().expect("Windows target");
        let selected_machine = fixture.manager.isolated_windows_machine_name(target, 1);
        let intent = fixture.manager.windows_wsl_ownership_proof_path(
            &selected_machine,
            WindowsWslOwnershipBasis::InitIntent,
        );

        push_windows_wsl_ready(&fixture.commands);
        push_windows_wsl_absent(&fixture.commands);
        fixture.commands.push(success(b"[]".to_vec()));
        push_windows_wsl_absent(&fixture.commands);
        fixture.commands.push(success(b"[]".to_vec()));
        fixture.commands.push_with_side_effect(
            failure(b"transient WSL import failure"),
            FakeCommandSideEffect::ReplaceFileWithDirectory {
                path: intent.clone(),
            },
        );

        let error = fixture
            .manager
            .start()
            .expect_err("ownership-journal cleanup failure must never retry");

        assert!(
            error
                .to_string()
                .contains("initialization journal processing failed")
        );
        assert!(intent.is_dir());
        let calls = fixture.commands.calls();
        assert_eq!(calls.len(), 7);
        assert_eq!(
            calls
                .iter()
                .filter(|arguments| {
                    arguments.len() >= 2 && arguments[0] == "machine" && arguments[1] == "init"
                })
                .count(),
            1
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_machine_init_never_retries_when_prerequisite_recheck_fails() {
        let mut fixture = fixture();
        fixture.manager.wsl_registrations = Arc::new(FixedWindowsWslRegistrations(Vec::new()));

        push_windows_wsl_ready(&fixture.commands);
        push_windows_wsl_absent(&fixture.commands);
        fixture.commands.push(success(b"[]".to_vec()));
        push_windows_wsl_absent(&fixture.commands);
        fixture.commands.push(success(b"[]".to_vec()));
        fixture
            .commands
            .push(failure(b"transient WSL import failure"));
        fixture
            .commands
            .push(failure(utf16le("Error code: Wsl/Service/E_UNEXPECTED\r\n")));

        let setup = ManagedRuntimeSetupController::default();
        fixture
            .manager
            .setup(&setup)
            .expect_err("failed WSL prerequisite recheck must stop automatic retry");

        let status = setup.status().expect("typed prerequisite failure");
        assert_eq!(
            status.failure_reason,
            Some(ManagedRuntimeSetupFailureReason::WslCommandFailed)
        );
        assert_eq!(
            status.next_action,
            Some(ManagedRuntimeSetupNextAction::RetryWslCheck)
        );
        let calls = fixture.commands.calls();
        assert_eq!(calls.len(), 8);
        assert_eq!(calls[7], ["--status"]);
        assert_eq!(
            calls
                .iter()
                .filter(|arguments| {
                    arguments.len() >= 2 && arguments[0] == "machine" && arguments[1] == "init"
                })
                .count(),
            1
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_machine_init_retry_stays_bounded_when_second_import_fails() {
        let mut fixture = fixture();
        fixture.manager.wsl_registrations = Arc::new(FixedWindowsWslRegistrations(Vec::new()));

        push_windows_wsl_ready(&fixture.commands);
        push_windows_wsl_absent(&fixture.commands);
        fixture.commands.push(success(b"[]".to_vec()));
        push_windows_wsl_absent(&fixture.commands);
        fixture.commands.push(success(b"[]".to_vec()));
        fixture
            .commands
            .push(failure(b"first transient WSL import failure"));
        push_windows_wsl_ready(&fixture.commands);
        push_windows_wsl_absent(&fixture.commands);
        fixture.commands.push(success(b"[]".to_vec()));
        fixture
            .commands
            .push(failure(b"second transient WSL import failure"));

        let error = fixture
            .manager
            .start()
            .expect_err("a second import failure must not trigger a third attempt");

        let message = error.to_string();
        assert!(message.contains("one bounded automatic retry"));
        assert!(message.contains("first transient WSL import failure"));
        assert!(message.contains("second transient WSL import failure"));
        let calls = fixture.commands.calls();
        assert_eq!(calls.len(), 12);
        assert_eq!(
            calls
                .iter()
                .filter(|arguments| {
                    arguments.len() >= 2 && arguments[0] == "machine" && arguments[1] == "init"
                })
                .count(),
            2
        );
        assert_eq!(
            calls
                .iter()
                .filter(|arguments| {
                    arguments.len() == 2 && arguments[0] == "--list" && arguments[1] == "--quiet"
                })
                .count(),
            3,
            "generation selection and the retry each require a fresh parsed WSL inventory"
        );
    }
    #[test]
    fn machine_application_data_volume_is_linux_only() {
        let fixture = fixture();
        let mut target = fixture.manager.loaded.target().expect("target").clone();

        target.operating_system = ManagedOperatingSystem::Macos;
        target.provider = ManagedMachineProvider::Applehv;
        assert_eq!(
            fixture
                .manager
                .machine_application_data_volume(&target)
                .expect("macOS volume policy"),
            None
        );

        target.operating_system = ManagedOperatingSystem::Windows;
        target.provider = ManagedMachineProvider::Wsl;
        assert_eq!(
            fixture
                .manager
                .machine_application_data_volume(&target)
                .expect("Windows volume policy"),
            None
        );
    }

    #[test]
    fn stale_wsl_journals_are_consumed_before_retry_and_cleanup_is_idempotent() {
        let fixture = fixture();
        let mut target = fixture.manager.loaded.target().expect("target").clone();
        target.operating_system = ManagedOperatingSystem::Windows;
        target.provider = ManagedMachineProvider::Wsl;
        let expected_machine = machine_name(&target);

        fixture
            .manager
            .ensure_windows_wsl_ownership_proof_locked(
                &target,
                &expected_machine,
                WindowsWslOwnershipBasis::InitIntent,
            )
            .expect("persist interrupted initialization journal");
        fixture
            .manager
            .ensure_windows_wsl_ownership_proof_locked(
                &target,
                &expected_machine,
                WindowsWslOwnershipBasis::ProvenMachine,
            )
            .expect("persist legacy stronger journal");
        for basis in [
            WindowsWslOwnershipBasis::InitIntent,
            WindowsWslOwnershipBasis::ProvenMachine,
        ] {
            assert!(
                fixture
                    .manager
                    .windows_wsl_ownership_proof_path(&expected_machine, basis)
                    .is_file()
            );
        }

        fixture
            .manager
            .remove_windows_wsl_ownership_proof_locked(&target, &expected_machine)
            .expect("retry consumes all stale journals");
        fixture
            .manager
            .remove_windows_wsl_ownership_proof_locked(&target, &expected_machine)
            .expect("journal consumption is retry-safe and idempotent");
        for basis in [
            WindowsWslOwnershipBasis::InitIntent,
            WindowsWslOwnershipBasis::ProvenMachine,
        ] {
            assert!(
                !fixture
                    .manager
                    .windows_wsl_ownership_proof_path(&expected_machine, basis)
                    .exists()
            );
        }
    }

    #[test]
    fn returned_machine_init_failure_consumes_one_shot_wsl_journal() {
        let fixture = fixture();
        fixture.manager.install().expect("install");
        let current_target = fixture.manager.loaded.target().expect("target");
        let command = fixture
            .manager
            .runtime_command(current_target)
            .expect("private command");
        let image = fixture
            .manager
            .acquire_machine_image_locked(current_target, None)
            .expect("machine image");
        let mut windows_target = current_target.clone();
        windows_target.operating_system = ManagedOperatingSystem::Windows;
        windows_target.provider = ManagedMachineProvider::Wsl;
        let expected_machine = machine_name(&windows_target);
        fixture.commands.push(failure(b"fixture init failed"));

        let error = fixture
            .manager
            .initialize_machine_with_one_shot_wsl_intent(
                &command,
                &windows_target,
                &image,
                &expected_machine,
            )
            .expect_err("fixture initialization fails");

        assert!(error.to_string().contains("fixture init failed"));
        assert!(
            !fixture
                .manager
                .windows_wsl_ownership_proof_path(
                    &expected_machine,
                    WindowsWslOwnershipBasis::InitIntent,
                )
                .exists()
        );
    }
    #[test]
    fn legacy_destructive_wsl_recovery_surface_is_absent() {
        let production = include_str!("managed_runtime.rs")
            .split("\n#[cfg(test)]")
            .next()
            .expect("production source");
        for forbidden in [
            "recover_windows_wsl_distribution_locked",
            "complete_windows_wsl_recovery_locked",
            "WslDistributionTerminate",
            "WslDistributionExport",
            "WslDistributionImport",
            "WslDistributionRemoval",
            "\"--unregister\"",
            "\"--export\"",
            "\"--import\"",
            "\"--shutdown\"",
        ] {
            assert!(
                !production.contains(forbidden),
                "retired destructive WSL recovery surface remains: {forbidden}"
            );
        }
    }

    #[test]
    fn managed_ssh_identity_is_reused_and_partial_regular_pair_is_safely_repaired() {
        let fixture = fixture();
        fixture.manager.install().expect("install");
        let target = fixture.manager.loaded.target().expect("target");
        fixture
            .manager
            .runtime_command(target)
            .expect("private command home");
        let identity = fixture.manager.machine_ssh_identity_path();
        let public_identity = managed_ssh_public_key_path(&identity);

        {
            let _lock = fixture.manager.lock().expect("lifecycle lock");
            fixture
                .manager
                .prepare_machine_ssh_identity_locked()
                .expect("generate identity");
        }
        let first_private = fs::read(&identity).expect("first private key");
        let first_public = fs::read(&public_identity).expect("first public key");
        {
            let _lock = fixture.manager.lock().expect("lifecycle lock");
            fixture
                .manager
                .prepare_machine_ssh_identity_locked()
                .expect("reuse valid identity");
        }
        assert_eq!(fs::read(&identity).unwrap(), first_private);
        assert_eq!(fs::read(&public_identity).unwrap(), first_public);

        fs::remove_file(&public_identity).expect("make partial pair");
        {
            let _lock = fixture.manager.lock().expect("lifecycle lock");
            fixture
                .manager
                .prepare_machine_ssh_identity_locked()
                .expect("repair partial identity before init");
        }
        assert_eq!(
            inspect_managed_ssh_identity(&identity).expect("inspect repaired pair"),
            ManagedSshIdentityState::Valid
        );
        assert!(private_entry_exists(&public_identity).unwrap());
    }

    #[test]
    fn existing_machine_ssh_identity_guard_preserves_an_inconsistent_pair() {
        let mut fixture = fixture();
        fixture.manager.install().expect("install");
        seed_owned_windows_lifecycle_fixture(
            &mut fixture,
            FixtureWindowsRegistrationLifecycle::Present,
        );
        let target = fixture.manager.loaded.target().expect("target");
        fixture
            .manager
            .runtime_command(target)
            .expect("private command home");
        let identity = fixture.manager.machine_ssh_identity_path();
        {
            let _lock = fixture.manager.lock().expect("lifecycle lock");
            fixture
                .manager
                .prepare_machine_ssh_identity_locked()
                .expect("generate identity");
        }
        let private_before = fs::read(&identity).expect("private key before failure");
        fs::write(
            managed_ssh_public_key_path(&identity),
            b"not-an-openssh-public-key\n",
        )
        .expect("corrupt public half");

        let error = fixture
            .manager
            .require_existing_machine_ssh_identity_locked()
            .expect_err("initialized machine identity mismatch must fail closed");

        assert!(error.to_string().contains("refusing to rotate"));
        assert_eq!(fs::read(&identity).unwrap(), private_before);
        assert!(fixture.commands.calls().is_empty());
    }

    #[cfg(windows)]
    #[test]
    fn transient_windows_identity_sharing_violation_is_retryable_not_corruption() {
        let mut fixture = fixture();
        let (_target, _machine, _vhd, _registration) =
            seed_verified_existing_windows_machine(&mut fixture);
        let identity = fixture.manager.machine_ssh_identity_path();
        let identity_before = fs::read(&identity).expect("identity snapshot");

        let error = {
            let _exclusive = open_without_windows_sharing(&identity);
            fixture
                .manager
                .require_existing_machine_ssh_identity_locked()
                .expect_err("sharing violation must be a retryable inspection failure")
        };

        assert!(matches!(&error, AppError::NotAvailable(_)));
        assert!(
            error
                .to_string()
                .contains("managed runtime machine-identity check incomplete")
        );
        assert_eq!(fs::read(&identity).unwrap(), identity_before);
        assert_eq!(
            inspect_managed_ssh_identity(&identity).unwrap(),
            ManagedSshIdentityState::Valid
        );
        assert!(fixture.commands.calls().is_empty());
    }

    #[cfg(windows)]
    #[test]
    fn transient_generation_selection_sharing_violation_preserves_routing_record() {
        let mut fixture = fixture();
        let (target, _machine, _vhd, _registration) =
            seed_verified_existing_windows_machine(&mut fixture);
        let selection_path = fixture.manager.windows_wsl_generation_selection_path(0);
        let selection_before = fs::read(&selection_path).expect("selection snapshot");

        let error = {
            let _exclusive = open_without_windows_sharing(&selection_path);
            fixture
                .manager
                .read_windows_wsl_generation_selection_locked(&target)
                .expect_err("sharing violation must not discard the routing record")
        };

        assert!(matches!(&error, AppError::NotAvailable(_)));
        assert!(
            error
                .to_string()
                .contains("managed runtime Windows generation selection unreadable")
        );
        assert_eq!(fs::read(&selection_path).unwrap(), selection_before);
        assert_eq!(
            fixture
                .manager
                .read_windows_wsl_generation_selection_locked(&target)
                .expect("read preserved routing record")
                .expect("preserved selected generation")
                .generation_index,
            0
        );
        assert!(fixture.commands.calls().is_empty());
    }

    #[cfg(windows)]
    #[test]
    fn inconsistent_windows_machine_ssh_identity_is_preserved_and_rebuilt_side_by_side() {
        let mut fixture = fixture();
        let (target, existing_machine, existing_vhd, existing_registration) =
            seed_verified_existing_windows_machine(&mut fixture);
        let existing_vhd_bytes = fs::read(&existing_vhd).expect("existing VHD snapshot");
        let existing_provider = fixture.manager.provider_home();
        let provider_sentinel = existing_provider.join("preserve-on-identity-recovery");
        fs::write(&provider_sentinel, b"existing-provider-bytes").expect("provider sentinel");
        let existing_identity = fixture.manager.machine_ssh_identity_path();
        let existing_private = fs::read(&existing_identity).expect("existing private identity");
        let existing_public = managed_ssh_public_key_path(&existing_identity);
        let existing_proof = fixture.manager.windows_wsl_ownership_proof_path(
            &existing_machine,
            WindowsWslOwnershipBasis::ProvenMachine,
        );
        let existing_proof_bytes = fs::read(&existing_proof).expect("existing ownership proof");
        let corrupt_public = b"not-an-openssh-public-key\n";

        let replacement_machine = fixture.manager.isolated_windows_machine_name(&target, 1);
        let replacement_storage =
            fixture
                .manager
                .windows_wsl_distribution_storage_path(&target, &replacement_machine, 1);
        let replacement_vhd = replacement_storage.join("ext4.vhdx");
        let replacement_registration = WindowsWslRegistration {
            registration_id: "00000000-0000-0000-0000-000000000054".into(),
            distribution_name: format!("podman-{replacement_machine}"),
            base_path: replacement_storage,
        };
        fixture.manager.wsl_registrations =
            Arc::new(WindowsWslRegistrationsForExistingPaths(vec![
                (existing_vhd.clone(), existing_registration),
                (replacement_vhd.clone(), replacement_registration),
            ]));

        let existing_distribution = format!("podman-{existing_machine}");
        push_windows_wsl_ready(&fixture.commands);
        fixture
            .commands
            .push(success(utf16le(&format!("{existing_distribution}\r\n"))));
        fixture.commands.push(success(machine_json_named(
            &fixture.manager,
            &existing_machine,
            false,
        )));
        fixture
            .commands
            .push(success(utf16le(&format!("{existing_distribution}\r\n"))));
        fixture.commands.push_with_side_effect(
            success(machine_json_named(
                &fixture.manager,
                &existing_machine,
                false,
            )),
            FakeCommandSideEffect::WriteFile {
                path: existing_public.clone(),
                bytes: corrupt_public.to_vec(),
            },
        );
        fixture
            .commands
            .push(success(utf16le(&format!("{existing_distribution}\r\n"))));
        fixture.commands.push(success(machine_json_named(
            &fixture.manager,
            &existing_machine,
            false,
        )));
        fixture.commands.push_with_side_effect(
            success(Vec::new()),
            FakeCommandSideEffect::CreateManagedWslVhd {
                path: replacement_vhd.clone(),
                bytes: b"replacement-after-identity-failure".to_vec(),
            },
        );
        fixture.commands.push(success(machine_json_named(
            &fixture.manager,
            &replacement_machine,
            false,
        )));
        fixture.commands.push(success(Vec::new()));
        fixture.commands.push(success(b"5.8.2\n".to_vec()));

        let command = fixture
            .manager
            .start()
            .expect("identity failure is reconciled with one isolated replacement");

        assert_eq!(command.runtime_version(), "5.8.2");
        assert_eq!(fs::read(&existing_vhd).unwrap(), existing_vhd_bytes);
        assert_eq!(
            fs::read(&provider_sentinel).unwrap(),
            b"existing-provider-bytes"
        );
        assert_eq!(fs::read(&existing_identity).unwrap(), existing_private);
        assert_eq!(fs::read(&existing_public).unwrap(), corrupt_public);
        assert_eq!(fs::read(&existing_proof).unwrap(), existing_proof_bytes);
        assert_eq!(
            fs::read(&replacement_vhd).unwrap(),
            b"replacement-after-identity-failure"
        );
        let selection = fixture
            .manager
            .read_windows_wsl_generation_selection_locked(&target)
            .unwrap()
            .unwrap();
        assert_eq!(selection.generation_index, 1);
        assert_eq!(selection.selected_machine_name, replacement_machine);
        assert_eq!(selection.preserved_collision_names, vec![existing_machine]);
        assert_eq!(
            inspect_managed_ssh_identity(&fixture.manager.machine_ssh_identity_path()).unwrap(),
            ManagedSshIdentityState::Valid
        );
        let calls = fixture.commands.calls();
        assert_eq!(calls.len(), 12);
        assert_eq!(calls[5], ["machine", "list", "--format", "json"]);
        assert_eq!(calls[6], ["--list", "--quiet"]);
        assert_eq!(calls[7], ["machine", "list", "--format", "json"]);
        assert_eq!(calls[8][..2], ["machine", "init"]);
        assert_eq!(
            calls
                .iter()
                .filter(|call| call.len() >= 2 && call[0] == "machine" && call[1] == "init")
                .count(),
            1
        );
        assert!(calls.iter().all(|call| {
            !(call.len() >= 2 && call[0] == "machine" && matches!(call[1].as_str(), "rm" | "stop"))
        }));
        assert!(calls.iter().flatten().all(|argument| {
            argument != "--unregister" && argument != "--export" && argument != "--import"
        }));
    }

    #[cfg(unix)]
    #[test]
    fn initialized_machine_rejects_an_overexposed_private_ssh_key_without_changing_its_mode() {
        use std::os::unix::fs::PermissionsExt;

        let fixture = fixture();
        fixture.manager.install().expect("install");
        let target = fixture.manager.loaded.target().expect("target");
        fixture
            .manager
            .runtime_command(target)
            .expect("private command home");
        let identity = fixture.manager.machine_ssh_identity_path();
        {
            let _lock = fixture.manager.lock().expect("lifecycle lock");
            fixture
                .manager
                .prepare_machine_ssh_identity_locked()
                .expect("generate identity");
        }
        fs::set_permissions(&identity, fs::Permissions::from_mode(0o644))
            .expect("overexpose private key");
        fixture
            .commands
            .push(success(machine_json(&fixture.manager, false)));

        let error = fixture
            .manager
            .start()
            .expect_err("initialized machine must reject an overexposed private key");

        assert!(error.to_string().contains("unsafe permissions"));
        assert_eq!(
            fs::metadata(&identity).unwrap().permissions().mode() & 0o777,
            0o644
        );
        assert_eq!(fixture.commands.calls().len(), 1);
    }

    #[cfg(windows)]
    #[test]
    fn windows_managed_ssh_identity_refuses_a_permissive_parent_before_creation() {
        let fixture = fixture();
        fixture.manager.install().expect("install");
        let target = fixture.manager.loaded.target().expect("target");
        fixture
            .manager
            .runtime_command(target)
            .expect("private command home");
        let identity = fixture.manager.machine_ssh_identity_path();
        let identity_parent = identity.parent().expect("identity parent");
        ensure_private_directory_tree(
            &fixture.manager.provider_home().join("data"),
            identity_parent,
        )
        .expect("identity directory");
        set_windows_permissive_inheritable_dacl(identity_parent);

        let inherited_probe = identity_parent.join("inherited-acl-probe");
        fs::write(&inherited_probe, b"probe").expect("create inherited ACL probe");
        let probe = File::open(&inherited_probe).expect("open inherited ACL probe");
        assert!(
            verify_windows_current_user_only_dacl(&probe).is_err(),
            "ordinary child must demonstrate that the parent DACL is permissive"
        );
        drop(probe);
        fs::remove_file(&inherited_probe).expect("remove inherited ACL probe");

        let error = {
            let _lock = fixture.manager.lock().expect("lifecycle lock");
            fixture
                .manager
                .prepare_machine_ssh_identity_locked()
                .expect_err("permissive identity parent must fail closed")
        };

        let public_identity = managed_ssh_public_key_path(&identity);
        let (private_temporary, public_temporary) =
            managed_ssh_identity_temporary_paths(&identity).expect("temporary paths");
        assert!(error.to_string().contains("DACL"));
        for unexpected in [
            &identity,
            &public_identity,
            &private_temporary,
            &public_temporary,
        ] {
            assert!(
                !private_entry_exists(unexpected).expect("inspect rejected identity path"),
                "unsafe parent must not receive any identity entry: {}",
                unexpected.display()
            );
        }
        let parent = open_windows_real_directory_security_handle(identity_parent)
            .expect("reopen permissive parent");
        assert!(
            verify_windows_current_user_only_dacl_with_ace_flags(
                &parent,
                u8::try_from(
                    windows_sys::Win32::Security::OBJECT_INHERIT_ACE
                        | windows_sys::Win32::Security::CONTAINER_INHERIT_ACE,
                )
                .expect("inheritance flags")
            )
            .is_err(),
            "the rejected parent DACL must not be repaired as a side effect"
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_managed_ssh_identity_rejects_ntfs_hard_links_without_repairing_them() {
        let fixture = fixture();
        fixture.manager.install().expect("install");
        let target = fixture.manager.loaded.target().expect("target");
        fixture
            .manager
            .runtime_command(target)
            .expect("private command home");
        let identity = fixture.manager.machine_ssh_identity_path();
        ensure_private_directory_tree(
            &fixture.manager.provider_home().join("data"),
            identity.parent().expect("identity parent"),
        )
        .expect("identity directory");
        let outside = fixture._temp.path().join("outside-hard-linked-identity");
        fs::write(&outside, b"outside-remains").expect("outside file");
        fs::hard_link(&outside, &identity).expect("NTFS identity hard link");

        let _lock = fixture.manager.lock().expect("lifecycle lock");
        let error = fixture
            .manager
            .prepare_machine_ssh_identity_locked()
            .expect_err("identity hard link must fail closed before repair");

        assert!(error.to_string().contains("must not be hard-linked"));
        assert_eq!(fs::read(&outside).unwrap(), b"outside-remains");
        assert_eq!(fs::read(&identity).unwrap(), b"outside-remains");
        let outside_file = File::open(&outside).expect("open outside file");
        assert_eq!(
            windows_file_information(&outside_file)
                .expect("outside handle information")
                .number_of_links,
            2
        );
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn managed_ssh_identity_recovers_a_public_publish_crash_link() {
        let fixture = fixture();
        fixture.manager.install().expect("install");
        let target = fixture.manager.loaded.target().expect("target");
        fixture
            .manager
            .runtime_command(target)
            .expect("private command home");
        let identity = fixture.manager.machine_ssh_identity_path();
        let parent = identity.parent().expect("identity parent");
        ensure_private_directory_tree(&fixture.manager.provider_home().join("data"), parent)
            .expect("identity directory");
        let (_, public_temporary) = managed_ssh_identity_temporary_paths(&identity).unwrap();
        let public_identity = managed_ssh_public_key_path(&identity);
        let mut staging = create_private_file(&public_temporary).expect("public staging file");
        staging
            .write_all(b"interrupted-publication")
            .expect("write public staging");
        staging.sync_all().expect("sync public staging");
        drop(staging);
        fs::hard_link(&public_temporary, &public_identity)
            .expect("simulate public hard-link publication before staging unlink");

        {
            let _lock = fixture.manager.lock().expect("lifecycle lock");
            fixture
                .manager
                .prepare_machine_ssh_identity_locked()
                .expect("recover public publication crash");
        }

        assert!(!private_entry_exists(&public_temporary).unwrap());
        assert_eq!(
            inspect_managed_ssh_identity(&identity).expect("inspect recovered identity"),
            ManagedSshIdentityState::Valid
        );
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn managed_ssh_identity_recovers_a_private_publish_crash_link() {
        let fixture = fixture();
        fixture.manager.install().expect("install");
        let target = fixture.manager.loaded.target().expect("target");
        fixture
            .manager
            .runtime_command(target)
            .expect("private command home");
        let identity = fixture.manager.machine_ssh_identity_path();
        let parent = identity.parent().expect("identity parent");
        ensure_private_directory_tree(&fixture.manager.provider_home().join("data"), parent)
            .expect("identity directory");
        let (private_temporary, _) = managed_ssh_identity_temporary_paths(&identity).unwrap();
        let mut staging = create_private_file(&private_temporary).expect("private staging file");
        staging
            .write_all(b"interrupted-private-publication")
            .expect("write private staging");
        staging.sync_all().expect("sync private staging");
        drop(staging);
        fs::hard_link(&private_temporary, &identity)
            .expect("simulate private hard-link publication before staging unlink");

        {
            let _lock = fixture.manager.lock().expect("lifecycle lock");
            fixture
                .manager
                .prepare_machine_ssh_identity_locked()
                .expect("recover private publication crash");
        }

        assert!(!private_entry_exists(&private_temporary).unwrap());
        assert_eq!(
            inspect_managed_ssh_identity(&identity).expect("inspect recovered identity"),
            ManagedSshIdentityState::Valid
        );
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn managed_ssh_identity_rejects_a_hard_linked_staging_file_without_mutating_it() {
        let fixture = fixture();
        fixture.manager.install().expect("install");
        let target = fixture.manager.loaded.target().expect("target");
        fixture
            .manager
            .runtime_command(target)
            .expect("private command home");
        let identity = fixture.manager.machine_ssh_identity_path();
        let parent = identity.parent().expect("identity parent");
        ensure_private_directory_tree(&fixture.manager.provider_home().join("data"), parent)
            .expect("identity directory");
        let (private_temporary, _) = managed_ssh_identity_temporary_paths(&identity).unwrap();
        let outside = fixture._temp.path().join("outside-staging-hard-link");
        fs::write(&outside, b"outside-remains").expect("outside file");
        fs::hard_link(&outside, &private_temporary).expect("staging hard link");

        let _lock = fixture.manager.lock().expect("lifecycle lock");
        let error = fixture
            .manager
            .prepare_machine_ssh_identity_locked()
            .expect_err("hard-linked staging file must fail closed");

        assert!(error.to_string().contains("must not be hard-linked"));
        assert_eq!(fs::read(&outside).unwrap(), b"outside-remains");
        assert_eq!(fs::read(&private_temporary).unwrap(), b"outside-remains");
    }

    #[cfg(unix)]
    #[test]
    fn managed_ssh_identity_rejects_symlinks_without_touching_the_target() {
        use std::os::unix::fs::symlink;

        let fixture = fixture();
        fixture.manager.install().expect("install");
        let target = fixture.manager.loaded.target().expect("target");
        fixture
            .manager
            .runtime_command(target)
            .expect("private command home");
        let identity = fixture.manager.machine_ssh_identity_path();
        ensure_private_directory_tree(
            &fixture.manager.provider_home().join("data"),
            identity.parent().expect("identity parent"),
        )
        .expect("identity directory");
        let outside = fixture._temp.path().join("outside-identity");
        fs::write(&outside, b"outside-remains").expect("outside file");
        symlink(&outside, &identity).expect("identity symlink");

        let _lock = fixture.manager.lock().expect("lifecycle lock");
        let error = fixture
            .manager
            .prepare_machine_ssh_identity_locked()
            .expect_err("identity symlink must fail closed");

        assert!(error.to_string().contains("real regular file"));
        assert_eq!(fs::read(&outside).unwrap(), b"outside-remains");
        assert!(
            fs::symlink_metadata(&identity)
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[cfg(unix)]
    #[test]
    fn managed_ssh_identity_rejects_hard_links_without_mutating_the_other_name() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let fixture = fixture();
        fixture.manager.install().expect("install");
        let target = fixture.manager.loaded.target().expect("target");
        fixture
            .manager
            .runtime_command(target)
            .expect("private command home");
        let identity = fixture.manager.machine_ssh_identity_path();
        ensure_private_directory_tree(
            &fixture.manager.provider_home().join("data"),
            identity.parent().expect("identity parent"),
        )
        .expect("identity directory");
        let outside = fixture._temp.path().join("outside-hard-linked-identity");
        fs::write(&outside, b"outside-remains").expect("outside file");
        let mode_before = fs::metadata(&outside).unwrap().permissions().mode() & 0o777;
        fs::hard_link(&outside, &identity).expect("identity hard link");

        let _lock = fixture.manager.lock().expect("lifecycle lock");
        let error = fixture
            .manager
            .prepare_machine_ssh_identity_locked()
            .expect_err("identity hard link must fail closed");

        assert!(error.to_string().contains("must not be hard-linked"));
        assert_eq!(fs::read(&outside).unwrap(), b"outside-remains");
        assert_eq!(
            fs::metadata(&outside).unwrap().permissions().mode() & 0o777,
            mode_before
        );
        assert_eq!(fs::metadata(&outside).unwrap().nlink(), 2);
    }

    #[test]
    fn observable_setup_reaches_verified_completed_state() {
        let mut fixture = fixture();
        let _initialized_vhd = configure_fresh_windows_machine_registration(&mut fixture);
        push_windows_wsl_ready(&fixture.commands);
        push_windows_wsl_absent(&fixture.commands);
        fixture.commands.push(success(b"[]".to_vec()));
        push_windows_wsl_absent(&fixture.commands);
        #[cfg(windows)]
        fixture.commands.push(success(b"[]".to_vec()));
        #[cfg(windows)]
        fixture.commands.push_with_side_effect(
            success(Vec::new()),
            FakeCommandSideEffect::CreateManagedWslVhd {
                path: _initialized_vhd,
                bytes: b"fresh-observable-generation".to_vec(),
            },
        );
        #[cfg(not(windows))]
        fixture.commands.push(success(Vec::new()));
        fixture
            .commands
            .push(success(fresh_machine_json(&fixture.manager, false)));
        fixture.commands.push(success(Vec::new()));
        fixture.commands.push(success(b"5.8.2\n".to_vec()));
        let setup = ManagedRuntimeSetupController::default();

        let runtime = fixture.manager.setup(&setup).expect("observable setup");
        assert!(runtime.available);
        assert_eq!(runtime.phase, ManagedRuntimePhase::Running);
        let setup_status = setup.status().expect("setup status");
        assert_eq!(setup_status.phase, ManagedRuntimeSetupPhase::Completed);
        assert!(!setup_status.active);
        assert!(!setup_status.can_retry);
        assert_eq!(setup_status.received_bytes, fixture.image.len() as u64);
        assert_eq!(setup_status.total_bytes, Some(fixture.image.len() as u64));
        assert_eq!(setup_status.progress_percent, Some(100.0));
        assert_eq!(setup_status.failure_reason, None);
        assert_eq!(setup_status.next_action, None);
        assert_eq!(
            fixture
                .commands
                .calls()
                .iter()
                .filter(|call| call.first().is_some_and(|argument| argument == "version"))
                .count(),
            1,
            "setup must reuse the server version returned by its successful readiness probe"
        );
    }

    #[test]
    fn wrong_machine_contract_fails_closed() {
        let fixture = fixture();
        fixture.manager.install().expect("install");
        let target = fixture.manager.loaded.target().expect("target");
        let inventory = serde_json::to_vec(&serde_json::json!([{
            "Name": machine_name(target),
            "Running": false,
            "VMType": target.provider.argument(),
            "CPUs": 99,
            "Memory": (4096_u64 * 1024 * 1024).to_string(),
            "DiskSize": (40_u64 * 1024 * 1024 * 1024).to_string()
        }]))
        .expect("json");
        push_windows_wsl_ready(&fixture.commands);
        fixture.commands.push(success(inventory));
        assert!(fixture.manager.start().is_err());
    }

    #[test]
    fn idle_stop_refuses_to_interrupt_a_container_and_force_is_explicit() {
        let mut fixture = fixture();
        fixture.manager.install().expect("install");
        seed_owned_windows_lifecycle_fixture(
            &mut fixture,
            FixtureWindowsRegistrationLifecycle::Present,
        );
        fixture
            .commands
            .push(success(machine_json(&fixture.manager, true)));
        fixture.commands.push(success(b"engine-one\n".to_vec()));
        let error = fixture
            .manager
            .stop(ManagedStopMode::OnlyIfIdle)
            .expect_err("must refuse");
        assert!(error.to_string().contains("running engine"));

        fixture
            .commands
            .push(success(machine_json(&fixture.manager, true)));
        fixture.commands.push(success(Vec::new()));
        fixture
            .commands
            .push(success(machine_json(&fixture.manager, false)));
        let status = fixture
            .manager
            .stop(ManagedStopMode::Force)
            .expect("force stop");
        assert_eq!(status.phase, ManagedRuntimePhase::Stopped);
    }

    #[test]
    fn product_uninstall_stop_stops_the_expected_machine_but_rejects_another_running_machine() {
        let mut fixture = fixture();
        fixture.manager.install().expect("install");
        seed_owned_windows_lifecycle_fixture(
            &mut fixture,
            FixtureWindowsRegistrationLifecycle::Present,
        );
        let target = fixture.manager.loaded.target().expect("target");
        let expected = machine_name(target);
        let inventory = |expected_running| {
            serde_json::to_vec(&serde_json::json!([
                {
                    "Name": expected,
                    "Running": expected_running,
                    "VMType": target.provider.argument(),
                    "CPUs": 2,
                    "Memory": (4096_u64 * 1024 * 1024).to_string(),
                    "DiskSize": (40_u64 * 1024 * 1024 * 1024).to_string()
                },
                {
                    "Name": "unexpected-private-machine",
                    "Running": true,
                    "VMType": target.provider.argument(),
                    "CPUs": 2,
                    "Memory": (4096_u64 * 1024 * 1024).to_string(),
                    "DiskSize": (40_u64 * 1024 * 1024 * 1024).to_string()
                }
            ]))
            .unwrap()
        };
        fixture.commands.push(success(inventory(true)));
        fixture.commands.push(success(Vec::new()));
        fixture.commands.push(success(inventory(false)));

        let error = fixture
            .manager
            .stop_for_product_uninstall()
            .expect_err("another running private-provider machine is unresolved contact");

        assert!(error.to_string().contains("another running machine"));
        assert!(
            fixture.commands.calls().iter().any(|call| {
                call == &["machine".to_owned(), "stop".to_owned(), expected.clone()]
            })
        );
    }

    #[test]
    fn command_environment_is_private_and_does_not_inherit_container_hosts() {
        let fixture = fixture();
        fixture.manager.install().expect("install");
        let target = fixture.manager.loaded.target().expect("target");
        let command = fixture.manager.runtime_command(target).expect("command");
        let command_home = PathBuf::from(
            command
                .environment
                .get(OsStr::new("HOME"))
                .expect("command HOME"),
        );
        assert_eq!(
            command.environment.get(OsStr::new("USERPROFILE")),
            command.environment.get(OsStr::new("HOME"))
        );
        assert_eq!(command.working_directory, command_home);
        assert!(
            command
                .environment
                .contains_key(OsStr::new("XDG_CONFIG_HOME"))
        );
        assert!(
            command
                .environment
                .contains_key(OsStr::new("XDG_DATA_HOME"))
        );
        assert!(!command.environment.contains_key(OsStr::new("DOCKER_HOST")));
        assert!(
            !command
                .environment
                .contains_key(OsStr::new("CONTAINER_HOST"))
        );
        let xdg_data_home = PathBuf::from(
            command
                .environment
                .get(OsStr::new("XDG_DATA_HOME"))
                .expect("XDG data home"),
        );
        assert_eq!(
            fixture.manager.machine_ssh_identity_path(),
            xdg_data_home.join("containers/podman/machine/machine")
        );
        let xdg_runtime_directory = PathBuf::from(
            command
                .environment
                .get(OsStr::new("XDG_RUNTIME_DIR"))
                .expect("XDG runtime directory"),
        );
        if target.operating_system == ManagedOperatingSystem::Linux {
            #[cfg(unix)]
            {
                use std::os::unix::ffi::OsStrExt;
                use std::os::unix::fs::MetadataExt;

                assert_eq!(
                    xdg_runtime_directory,
                    fixture
                        .manager
                        .linux_short_runtime_directory()
                        .expect("deterministic Linux short runtime")
                );
                assert_eq!(xdg_runtime_directory.parent(), Some(Path::new("/tmp")));
                verify_linux_short_runtime_directory(&xdg_runtime_directory, effective_uid())
                    .expect("private Linux short runtime");
                let socket =
                    linux_podman_gvproxy_socket_path(&xdg_runtime_directory, &machine_name(target));
                assert!(socket.as_os_str().as_bytes().len() <= PODMAN_LINUX_MAX_SOCKET_PATH_BYTES);
                assert!(
                    !private_entry_exists(&xdg_runtime_directory.join("containers")).unwrap(),
                    "containers/storage state must not be created in the socket-bounded runtime"
                );

                let provider_home = fixture.manager.provider_home();
                let storage_config = provider_home
                    .join("config")
                    .join("containers")
                    .join("storage.conf");
                assert_eq!(
                    command
                        .environment
                        .get(OsStr::new("CONTAINERS_STORAGE_CONF"))
                        .map(OsString::as_os_str),
                    Some(storage_config.as_os_str())
                );
                let storage_runroot = provider_home.join("run").join("containers");
                let storage_graphroot = provider_home
                    .join("data")
                    .join("containers")
                    .join("storage");
                assert_eq!(
                    fs::read_to_string(&storage_config).expect("private storage config"),
                    format!(
                        "[storage]\nrunroot = {}\ngraphroot = {}\n",
                        toml_string(&storage_runroot).unwrap(),
                        toml_string(&storage_graphroot).unwrap(),
                    )
                );
                let storage_metadata = fs::symlink_metadata(&storage_config).unwrap();
                assert!(storage_metadata.is_file());
                assert!(!storage_metadata.file_type().is_symlink());
                assert_eq!(storage_metadata.uid(), effective_uid());
                assert_eq!(storage_metadata.mode() & 0o7777, 0o600);
                for directory in [storage_runroot, storage_graphroot] {
                    let metadata = fs::symlink_metadata(&directory).unwrap();
                    assert!(metadata.is_dir());
                    assert!(!metadata.file_type().is_symlink());
                    assert_eq!(metadata.uid(), effective_uid());
                    assert_eq!(metadata.mode() & 0o7777, 0o700);
                }
            }
        } else {
            assert!(
                !command
                    .environment
                    .contains_key(OsStr::new("CONTAINERS_STORAGE_CONF"))
            );
            assert_eq!(
                xdg_runtime_directory,
                fixture.manager.provider_home().join("run")
            );
        }
        if target.operating_system == ManagedOperatingSystem::Macos {
            assert_ne!(command_home, fixture.manager.provider_home());
            #[cfg(unix)]
            assert!(command_home.starts_with(MACOS_SHORT_HOME_BASE));
        } else {
            assert_eq!(command_home, fixture.manager.provider_home());
        }
        let windows_lookup_guard = command
            .environment
            .get(OsStr::new("NoDefaultCurrentDirectoryInExePath"));
        if target.operating_system == ManagedOperatingSystem::Windows {
            assert_eq!(
                windows_lookup_guard.map(OsString::as_os_str),
                Some(OsStr::new("1"))
            );
            assert_eq!(
                command.environment.get(OsStr::new("WINDIR")),
                command.environment.get(OsStr::new("SystemRoot"))
            );
            let system_root = PathBuf::from(
                command
                    .environment
                    .get(OsStr::new("SystemRoot"))
                    .expect("trusted Windows root"),
            );
            let managed_paths = std::env::split_paths(
                command
                    .environment
                    .get(OsStr::new("PATH"))
                    .expect("managed PATH"),
            )
            .collect::<Vec<_>>();
            assert_eq!(managed_paths.first(), Some(&system_root.join("System32")));
        } else {
            assert!(windows_lookup_guard.is_none());
        }
        for value in command.environment.values() {
            assert!(!value.to_string_lossy().contains('\n'));
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_storage_configuration_is_immutable() {
        let fixture = fixture();
        fixture.manager.install().expect("install");
        let target = fixture.manager.loaded.target().expect("target");
        let command = fixture.manager.runtime_command(target).expect("command");
        let storage_config = PathBuf::from(
            command
                .environment
                .get(OsStr::new("CONTAINERS_STORAGE_CONF"))
                .expect("Linux storage config"),
        );
        fs::write(&storage_config, b"[storage]\nrunroot = \"tampered\"\n")
            .expect("tamper storage config");

        let error = fixture
            .manager
            .runtime_command(target)
            .expect_err("immutable storage config mismatch must fail closed");

        assert!(
            error
                .to_string()
                .contains("immutable configuration differs")
        );
        assert_eq!(
            fs::read(&storage_config).unwrap(),
            b"[storage]\nrunroot = \"tampered\"\n"
        );
    }

    #[test]
    fn current_directory_helper_lookup_is_disabled_only_for_windows_commands() {
        let key = OsString::from("NoDefaultCurrentDirectoryInExePath");
        let mut environment = BTreeMap::new();

        apply_platform_command_environment(&mut environment, ManagedOperatingSystem::Windows);
        assert_eq!(environment.get(&key), Some(&OsString::from("1")));

        for operating_system in [ManagedOperatingSystem::Linux, ManagedOperatingSystem::Macos] {
            apply_platform_command_environment(&mut environment, operating_system);
            assert!(!environment.contains_key(&key));
            apply_platform_command_environment(&mut environment, ManagedOperatingSystem::Windows);
        }
    }

    #[test]
    fn command_execution_errors_use_fixed_operation_labels_without_arguments() {
        let fixture = fixture();
        fixture.manager.install().expect("install");
        let target = fixture.manager.loaded.target().expect("target");
        let command = fixture.manager.runtime_command(target).expect("command");
        let operations = [
            ManagedCommandOperation::MachineInitialization,
            ManagedCommandOperation::MachineInventory,
            ManagedCommandOperation::MachineStart,
            ManagedCommandOperation::MachineStop,
            ManagedCommandOperation::MachineRemoval,
            ManagedCommandOperation::WslDistributionInventory,
            ManagedCommandOperation::ActiveContainerInventory,
            ManagedCommandOperation::VersionPreflight,
        ];
        let mut labels = BTreeSet::new();

        for operation in operations {
            assert!(labels.insert(operation.label()));
            let error = fixture
                .manager
                .run_command(
                    operation,
                    &command,
                    ["--credential=must-not-appear"],
                    COMMAND_TIMEOUT,
                )
                .expect_err("empty fake output queue must fail");
            let message = error.to_string();
            assert!(message.contains(operation.label()));
            assert!(!message.contains("must-not-appear"));
        }
    }

    #[test]
    fn setup_terminal_paths_clear_every_process_local_activity_flag() {
        for phase in [
            ManagedRuntimeSetupPhase::Completed,
            ManagedRuntimeSetupPhase::Failed,
            ManagedRuntimeSetupPhase::Cancelled,
        ] {
            let controller = ManagedRuntimeSetupController::default();
            let operation_id = controller.begin().expect("begin setup");
            {
                let mut status = controller.status.lock().expect("setup status");
                status.prerequisite_repair_active = true;
                status.cancel_requested = true;
                status.stale = true;
            }
            controller
                .prerequisite_repair_active
                .store(true, Ordering::Release);
            controller.cancel_requested.store(true, Ordering::Release);

            controller
                .finish(&operation_id, phase, "terminal fixture".into())
                .expect("terminalize setup");

            let status = controller.status().expect("terminal setup status");
            assert!(!status.active, "{phase:?}");
            assert!(!status.prerequisite_repair_active, "{phase:?}");
            assert!(!status.cancel_requested, "{phase:?}");
            assert!(!status.can_cancel, "{phase:?}");
            assert!(!status.stale, "{phase:?}");
            assert!(
                !controller
                    .prerequisite_repair_active
                    .load(Ordering::Acquire),
                "{phase:?}"
            );
            assert!(
                !controller.cancel_requested.load(Ordering::Acquire),
                "{phase:?}"
            );
        }
    }

    #[test]
    fn worker_guard_terminalizes_a_panicking_prerequisite_repair_without_clobbering_retry() {
        let controller = ManagedRuntimeSetupController::default();
        let operation_id = controller.begin().expect("begin setup");
        let panic_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _worker_guard =
                ManagedRuntimeSetupWorkerGuard::new(&controller, operation_id.clone());
            controller
                .record_failure(
                    ManagedRuntimeSetupFailureReason::WslUpdateRequired,
                    ManagedRuntimeSetupNextAction::UpdateWsl,
                    "Windows WSL needs an update",
                )
                .expect("record typed failure");
            controller
                .finish_failed(&operation_id, "failed prerequisite")
                .expect("publish failed prerequisite");
            controller
                .begin_prerequisite_repair(&operation_id)
                .expect("begin automatic prerequisite repair");
            panic!("injected prerequisite repair panic");
        }));
        assert!(panic_result.is_err());

        let failed = controller.status().expect("worker failure status");
        assert_eq!(failed.operation_id.as_deref(), Some(operation_id.as_str()));
        assert_eq!(failed.phase, ManagedRuntimeSetupPhase::Failed);
        assert!(!failed.active);
        assert!(!failed.prerequisite_repair_active);
        assert!(!failed.cancel_requested);
        assert!(failed.can_retry);
        assert!(
            !controller
                .prerequisite_repair_active
                .load(Ordering::Acquire)
        );

        let retry_operation_id = controller.begin().expect("begin retry");
        controller
            .finish_worker_failure(&operation_id, "late old worker failure")
            .expect("ignore old terminal write");
        let retried = controller.status().expect("retry remains active");
        assert_eq!(
            retried.operation_id.as_deref(),
            Some(retry_operation_id.as_str())
        );
        assert_eq!(retried.phase, ManagedRuntimeSetupPhase::Install);
        assert!(retried.active);
    }

    #[test]
    fn automatic_prerequisite_reservation_blocks_retry_and_keeps_one_operation_identity() {
        let controller = ManagedRuntimeSetupController::default();
        let operation_id = controller.begin().expect("begin setup");
        controller
            .record_failure(
                ManagedRuntimeSetupFailureReason::WslNotInstalled,
                ManagedRuntimeSetupNextAction::InstallWsl,
                "Windows WSL needs installation",
            )
            .expect("record typed prerequisite failure");

        assert_eq!(
            controller
                .begin_automatic_prerequisite_repair(&operation_id, &[])
                .expect("reserve automatic prerequisite repair"),
            Some(ManagedRuntimeSetupNextAction::InstallWsl)
        );
        let repairing = controller.status().expect("reserved repair status");
        assert_eq!(
            repairing.operation_id.as_deref(),
            Some(operation_id.as_str())
        );
        assert!(repairing.active);
        assert!(repairing.prerequisite_repair_active);
        assert!(!repairing.can_retry);
        assert!(
            controller.begin().is_err(),
            "a retry cannot replace the worker while its automatic repair is active"
        );

        let completed = ManagedRuntimePrerequisiteRepairResult {
            outcome: ManagedRuntimePrerequisiteRepairOutcome::Completed,
            restart_required: false,
            detail: "Windows preparation completed".into(),
        };
        controller.finish_prerequisite_repair(&operation_id, Some(&completed));
        controller
            .continue_after_prerequisite_repair(&operation_id)
            .expect("continue the same setup operation");

        let continued = controller.status().expect("continued setup status");
        assert_eq!(
            continued.operation_id.as_deref(),
            Some(operation_id.as_str())
        );
        assert!(continued.active);
        assert!(!continued.prerequisite_repair_active);
        assert!(!continued.can_retry);
        assert_eq!(continued.failure_reason, None);
        assert_eq!(continued.next_action, None);
    }

    #[test]
    fn setup_liveness_is_backend_derived_and_stale_requests_bounded_cancellation() {
        let controller = ManagedRuntimeSetupController::default();
        let now = Utc::now();
        let operation_id = controller.begin_at(now).expect("begin setup");
        let started = controller.status().expect("started setup status");
        assert_eq!(started.operation_id.as_deref(), Some(operation_id.as_str()));
        assert_eq!(started.started_at, Some(now));
        assert_eq!(started.last_heartbeat_at, Some(now));
        assert!(!started.stale);

        let missed_heartbeat =
            now - chrono_duration(MANAGED_RUNTIME_SETUP_STALE_AFTER) - chrono::Duration::seconds(1);
        {
            let mut status = controller.status.lock().expect("setup status");
            status.last_heartbeat_at = Some(missed_heartbeat);
        }
        controller
            .record_heartbeat()
            .expect("record worker heartbeat before the stale threshold is observed");
        let alive = controller.status().expect("live setup status");
        assert!(!alive.stale);
        assert!(
            alive
                .last_heartbeat_at
                .is_some_and(|heartbeat| heartbeat > missed_heartbeat)
        );

        {
            let mut status = controller.status.lock().expect("setup status");
            status.last_heartbeat_at = Some(missed_heartbeat);
        }
        let stale = controller.status().expect("stale setup status");
        assert!(stale.stale);
        assert!(stale.active);
        assert!(stale.cancel_requested);
        assert!(!stale.can_cancel);
        assert!(!stale.can_retry);
        assert_eq!(
            stale.detail,
            "Scan-tool preparation stalled. This attempt is stopping."
        );
        assert!(controller.cancel_requested.load(Ordering::Acquire));
        assert!(controller.check_cancelled().is_err());

        controller
            .finish_cancelled(&operation_id)
            .expect("stale worker reaches its bounded cancellation point");
        let terminal = controller.status().expect("terminal stale setup status");
        assert_eq!(terminal.phase, ManagedRuntimeSetupPhase::Cancelled);
        assert!(!terminal.active);
        assert!(!terminal.stale);
        assert!(terminal.can_retry);
    }

    #[test]
    fn setup_controller_rejects_parallel_attempts_and_allows_retry_after_cancel() {
        let controller = ManagedRuntimeSetupController::default();
        let operation_id = controller.begin().expect("first setup");
        let error = controller.begin().expect_err("parallel setup rejected");
        assert!(error.to_string().contains("already active"));

        let requested = controller.request_cancel().expect("request cancellation");
        assert!(requested.active);
        assert!(requested.cancel_requested);
        assert_eq!(requested.detail, "Scan-tool preparation is stopping.");
        assert_eq!(
            controller.check_cancelled().unwrap_err().to_string(),
            "invalid request: Scan-tool preparation cancelled."
        );
        controller
            .finish_cancelled(&operation_id)
            .expect("finish cancelled");
        let cancelled = controller.status().expect("cancelled status");
        assert_eq!(cancelled.phase, ManagedRuntimeSetupPhase::Cancelled);
        assert!(!cancelled.active);
        assert!(cancelled.can_retry);
        assert_eq!(cancelled.detail, "Scan-tool preparation cancelled.");

        controller.begin().expect("retry starts");
        assert_eq!(
            controller.status().expect("retry status").phase,
            ManagedRuntimeSetupPhase::Install
        );
    }

    #[test]
    fn resume_content_range_must_match_exact_locked_suffix() {
        validate_resume_content_range("bytes 131072-262460/262461", 131_072, 262_461)
            .expect("exact range");
        for invalid in [
            "bytes 0-262460/262461",
            "bytes 131072-200000/262461",
            "bytes 131072-262460/999999",
            "items 131072-262460/262461",
            "garbage",
        ] {
            assert!(
                validate_resume_content_range(invalid, 131_072, 262_461).is_err(),
                "accepted {invalid}"
            );
        }
    }

    #[test]
    fn chunk_progress_cancel_retains_partial_and_next_attempt_resumes_exactly() {
        let temp = tempfile::tempdir().expect("temp");
        let partial = temp.path().join("machine.download-part");
        let total = (DOWNLOAD_CHUNK_BYTES * 2 + 317) as u64;
        let bytes = (0..total)
            .map(|index| (index % 251) as u8)
            .collect::<Vec<_>>();
        let controller = ManagedRuntimeSetupController::default();
        let operation_id = controller.begin().expect("begin download");
        controller
            .report_download(0, total, 0)
            .expect("initial progress");

        let mut first_observations = Vec::new();
        let mut requested_cancel = false;
        let mut first_reader = io::Cursor::new(bytes.as_slice());
        let mut first_file = open_private_download_file(&partial, false).expect("partial file");
        let error = write_download_body(
            &mut first_reader,
            &mut first_file,
            0,
            total,
            0,
            &mut |received, observed_total, resumed_from| {
                first_observations.push((received, observed_total, resumed_from));
                if !requested_cancel {
                    requested_cancel = true;
                    controller.request_cancel()?;
                }
                controller.report_download(received, observed_total, resumed_from)
            },
        )
        .expect_err("cancel stops bounded chunk loop");
        assert!(error.to_string().contains("cancelled"));
        drop(first_file);
        let retained = fs::metadata(&partial).expect("partial metadata").len();
        assert_eq!(retained, DOWNLOAD_CHUNK_BYTES as u64);
        assert_eq!(
            first_observations,
            vec![(DOWNLOAD_CHUNK_BYTES as u64, total, 0)]
        );
        let cancelled_progress = controller.status().expect("progress status");
        assert_eq!(cancelled_progress.received_bytes, retained);
        assert_eq!(cancelled_progress.total_bytes, Some(total));
        assert_eq!(cancelled_progress.resumed_from_bytes, 0);
        controller
            .finish_cancelled(&operation_id)
            .expect("finish cancellation");

        controller.begin().expect("begin resume");
        controller
            .report_download(retained, total, retained)
            .expect("resume progress");
        let mut resumed_observations = Vec::new();
        let mut remainder = io::Cursor::new(&bytes[retained as usize..]);
        let mut resumed_file = open_private_download_file(&partial, true).expect("append partial");
        let written = write_download_body(
            &mut remainder,
            &mut resumed_file,
            retained,
            total,
            retained,
            &mut |received, observed_total, resumed_from| {
                resumed_observations.push((received, observed_total, resumed_from));
                controller.report_download(received, observed_total, resumed_from)
            },
        )
        .expect("resume completes");
        drop(resumed_file);
        assert_eq!(written, total);
        assert_eq!(fs::read(&partial).expect("resumed bytes"), bytes);
        assert_eq!(
            resumed_observations,
            vec![
                ((DOWNLOAD_CHUNK_BYTES * 2) as u64, total, retained),
                (total, total, retained),
            ]
        );
        let resumed = controller.status().expect("resumed status");
        assert_eq!(resumed.received_bytes, total);
        assert_eq!(resumed.progress_percent, Some(100.0));
        assert_eq!(resumed.resumed_from_bytes, retained);
    }
}
