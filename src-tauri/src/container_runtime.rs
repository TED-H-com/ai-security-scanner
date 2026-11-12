use crate::artifact_store::{CapturePaths, CaptureWriter, RunDirectories};
use crate::domain::{
    EngineManifest, GatewayRefusalRecord, MAX_ENGINE_EXECUTION_TIMEOUT_SECONDS,
    MIN_ENGINE_EXECUTION_TIMEOUT_SECONDS, ScanPermission,
};
use crate::error::{AppError, AppResult};
use crate::execution_coverage::LAUNCHER_V2_JOURNAL_SCHEMA_VERSION;
use crate::naabu_work_plan::{MAX_NAABU_LAUNCHER_PLAN_BYTES, NAABU_ENGINE_ID};
use crate::zap_work_plan::{MAX_ZAP_PLAN_BYTES, ZAP_ENGINE_ID};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration as StdDuration;
use zeroize::Zeroizing;

const CONTAINER_SCOPE_PATH: &str = "/run/ai-security-scanner/scope.json";
pub(crate) const NAABU_LAUNCHER_PLAN_CONTROL_FILE: &str = "execution-journal-v2.json";
pub(crate) const CONTAINER_NAABU_LAUNCHER_PLAN_PATH: &str =
    "/run/ai-security-scanner/execution-journal-v2.json";
pub(crate) const ZAP_PLAN_CONTROL_FILE: &str = "zap-plan.yaml";
pub(crate) const CONTAINER_ZAP_PLAN_PATH: &str = "/run/ai-security-scanner/zap-plan.yaml";
const CONTAINER_CREDENTIAL_PATH: &str = "/run/ai-security-scanner/credentials.json";
/// Also read by `adapters::redact_location`, which strips this prefix back off
/// engine-reported paths. Sharing the constant is what keeps a finding from
/// naming a directory the user does not have.
pub(crate) const CONTAINER_WORKSPACE_PATH: &str = "/workspace";
const CONTAINER_OUTPUT_PATH: &str = "/output";
const MAX_SCOPE_DOCUMENT_BYTES: u64 = 4 * 1024 * 1024;
const MAX_CREDENTIAL_DOCUMENT_BYTES: u64 = 256 * 1024;
const MAX_NETWORK_INSPECT_BYTES: usize = 2 * 1024 * 1024;
const MAX_CONTAINER_INSPECT_BYTES: usize = 2 * 1024 * 1024;
const MIN_OUTPUT_BYTES: u64 = 1024 * 1024;
const MAX_OUTPUT_BYTES: u64 = 64 * 1024 * 1024 * 1024;
const DEFAULT_OUTPUT_BYTES: u64 = 512 * 1024 * 1024;
const MAX_OUTPUT_ENTRIES: usize = 10_000;
const MAX_OUTPUT_DEPTH: usize = 32;
const MAX_RUNTIME_COMMAND_OUTPUT_BYTES: u64 = 2 * 1024 * 1024;
const MAX_RUNTIME_SECURITY_OPTIONS_BYTES: usize = 8 * 1024;
const MAX_RUNTIME_EXECUTION_INFO_BYTES: usize = 16 * 1024;
#[doc(hidden)]
pub const RELEASE_APPROVED_LOCAL_IMAGE_DIRECTORY_ENVIRONMENT_VARIABLE: &str =
    "AI_SECURITY_SCANNER_RELEASE_APPROVED_LOCAL_IMAGE_DIRECTORY";
const RUNTIME_COMMAND_TIMEOUT: StdDuration = StdDuration::from_secs(30);
// Removing an exited engine container waits on the runtime's storage cleanup,
// which took 35 seconds on a busy Docker host after a finished Greenbone scan.
// A removal that outlives its deadline leaves cleanup pending, and the scan is
// then recorded as partial even though the scanner finished.
const OWNED_CONTAINER_REMOVAL_TIMEOUT: StdDuration = StdDuration::from_secs(2 * 60);
// Loading a release archive can transfer and unpack several hundred MB into a
// provider VM. Keep it independent of short control-plane commands and pulls.
const LOCAL_PINNED_IMAGE_LOAD_TIMEOUT: StdDuration = StdDuration::from_secs(15 * 60);
// A cold pull transfers and unpacks the release-pinned image inside the provider VM;
// keep that data-plane deadline separate from short control-plane commands.
const PINNED_IMAGE_PULL_TIMEOUT: StdDuration = StdDuration::from_secs(10 * 60);
const MAX_OCI_LAYOUT_DOCUMENT_BYTES: u64 = 16 * 1024;
const MAX_OCI_INDEX_DOCUMENT_BYTES: u64 = 1024 * 1024;
const MAX_OCI_MANIFEST_DOCUMENT_BYTES: u64 = 4 * 1024 * 1024;
const OCI_IMAGE_MANIFEST_MEDIA_TYPE: &str = "application/vnd.oci.image.manifest.v1+json";
const RUNTIME_PIPE_DRAIN_TIMEOUT: StdDuration = StdDuration::from_secs(2);
const CONTAINER_CAPTURE_DRAIN_TIMEOUT: StdDuration = StdDuration::from_secs(30);
/// The one sentence a host-deadline timeout is recorded as.
///
/// Public because the shared report reads it back: every recorded execution
/// error reconciles to the same `error_code`, so this sentence is what
/// separates "the check ran out of time" from "the check failed", and those
/// two send the reader to different next steps.
pub const CONTAINER_EXECUTION_TIMEOUT_ERROR: &str =
    "scanner execution exceeded its configured host deadline";
/// The product's own local launcher emits this when an engine's image cannot
/// consume the typed input the host mounted. Matched as a product-owned
/// constant, exactly like [`CONTAINER_EXECUTION_TIMEOUT_ERROR`]; a CI parity
/// test binds it to the Go source so a launcher reword cannot silently unbind it.
pub const LOCAL_INPUT_PROFILE_REJECTION_MARKER: &str = "cannot consume local input profile";
const MANAGED_NETWORK_LABEL_KEY: &str = "ai.security-scanner.managed";
const NETWORK_POLICY_LABEL_KEY: &str = "ai.security-scanner.policy-id";
const CONTAINER_MANAGED_LABEL_KEY: &str = "ai.security-scanner.managed";
const CONTAINER_CASE_LABEL_KEY: &str = "ai.security-scanner.case";
const CONTAINER_SCAN_RUN_LABEL_KEY: &str = "ai.security-scanner.scan-run";
const CONTAINER_ENGINE_LABEL_KEY: &str = "ai.security-scanner.engine";
const CONTAINER_ENGINE_RUN_LABEL_KEY: &str = "ai.security-scanner.engine-run";
const CONTAINER_ATTEMPT_LABEL_KEY: &str = "ai.security-scanner.attempt";
const CONTAINER_SCOPE_LABEL_KEY: &str = "ai.security-scanner.scope-sha256";
const CONTAINER_NAABU_LAUNCHER_PLAN_LABEL_KEY: &str =
    "ai.security-scanner.naabu-launcher-plan-sha256";
const CONTAINER_ZAP_PLAN_LABEL_KEY: &str = "ai.security-scanner.zap-plan-sha256";
const NAABU_LAUNCHER_COMMAND: [&str; 10] = [
    "--engine",
    "naabu",
    "--scope",
    CONTAINER_SCOPE_PATH,
    "--output",
    CONTAINER_OUTPUT_PATH,
    "--journal-version",
    "2",
    "--journal-plan",
    CONTAINER_NAABU_LAUNCHER_PLAN_PATH,
];

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeProvider {
    ManagedLocal,
    Docker,
    Podman,
}

impl RuntimeProvider {
    fn program_name(self) -> &'static str {
        match self {
            Self::ManagedLocal => "managed-local",
            Self::Docker => "docker",
            Self::Podman => "podman",
        }
    }

    fn uses_podman_dialect(self) -> bool {
        matches!(self, Self::ManagedLocal | Self::Podman)
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RuntimeCommandProvenance {
    #[default]
    Compatibility,
    ManagedLocal {
        runtime_version: String,
        manifest_sha256: String,
        machine_image_sha256: String,
    },
}

impl RuntimeCommandProvenance {
    /// Returns the immutable managed-runtime manifest identity, when this
    /// command was resolved from a verified managed installation.
    pub fn managed_manifest_sha256(&self) -> Option<&str> {
        match self {
            Self::Compatibility => None,
            Self::ManagedLocal {
                manifest_sha256, ..
            } => Some(manifest_sha256),
        }
    }
}

/// An already-resolved, typed command context. Managed-local contexts can only
/// be created from the verified lifecycle manager; durable records persist the
/// provider/provenance, never an arbitrary binary or environment map.
#[derive(Debug, Clone)]
pub struct RuntimeCommandContext {
    provider: RuntimeProvider,
    binary: PathBuf,
    environment: BTreeMap<OsString, OsString>,
    working_directory: Option<PathBuf>,
    clear_environment: bool,
    provenance: RuntimeCommandProvenance,
    #[cfg(windows)]
    windows_launch_contract:
        Option<Arc<crate::managed_runtime::WindowsManagedRuntimeLaunchContract>>,
}

impl RuntimeCommandContext {
    pub(crate) fn compatibility(provider: RuntimeProvider, binary: PathBuf) -> AppResult<Self> {
        match provider {
            RuntimeProvider::Docker | RuntimeProvider::Podman => {}
            RuntimeProvider::ManagedLocal => {
                return Err(AppError::NotAuthorized(
                    "managed-local runtime requires its verified private command context".into(),
                ));
            }
        }
        Ok(Self {
            provider,
            binary,
            environment: BTreeMap::new(),
            working_directory: None,
            clear_environment: false,
            provenance: RuntimeCommandProvenance::Compatibility,
            #[cfg(windows)]
            windows_launch_contract: None,
        })
    }

    fn managed(command: crate::managed_runtime::ManagedRuntimeCommand) -> AppResult<Self> {
        if !command.binary().is_absolute() {
            return Err(AppError::NotAuthorized(
                "managed runtime driver must have an absolute verified path".into(),
            ));
        }
        validate_mount_file(command.binary(), "managed runtime driver")?;
        validate_mount_directory(command.working_directory(), "managed runtime home")?;
        #[cfg(windows)]
        let windows_launch_contract = Some(command.windows_launch_contract().ok_or_else(|| {
            AppError::NotAuthorized(
                "managed Windows runtime command is missing its pre-spawn launch contract".into(),
            )
        })?);
        Ok(Self {
            provider: RuntimeProvider::ManagedLocal,
            binary: command.binary().to_path_buf(),
            environment: command.environment().clone(),
            working_directory: Some(command.working_directory().to_path_buf()),
            clear_environment: true,
            provenance: RuntimeCommandProvenance::ManagedLocal {
                runtime_version: command.runtime_version().to_owned(),
                manifest_sha256: command.manifest_sha256().to_owned(),
                machine_image_sha256: command.machine_image_sha256().to_owned(),
            },
            #[cfg(windows)]
            windows_launch_contract,
        })
    }

    pub fn provider(&self) -> RuntimeProvider {
        self.provider
    }

    pub fn binary(&self) -> &Path {
        &self.binary
    }

    pub fn provenance(&self) -> &RuntimeCommandProvenance {
        &self.provenance
    }

    pub(crate) fn output(
        &self,
        args: &[OsString],
        maximum: u64,
        timeout: StdDuration,
    ) -> io::Result<std::process::Output> {
        let deadline = std::time::Instant::now()
            .checked_add(timeout)
            .ok_or_else(runtime_command_deadline_error)?;
        #[cfg(windows)]
        let _execution_guard = self.acquire_windows_execution_guard(deadline, &|| false)?;
        if std::time::Instant::now() >= deadline {
            return Err(runtime_command_deadline_error());
        }
        let mut command = Command::new(&self.binary);
        command.args(args);
        self.apply(&mut command);
        bounded_command_output_until(&mut command, maximum, deadline)
    }

    fn output_with_stdin(
        &self,
        args: &[OsString],
        stdin: File,
        maximum: u64,
        timeout: StdDuration,
    ) -> io::Result<std::process::Output> {
        let deadline = std::time::Instant::now()
            .checked_add(timeout)
            .ok_or_else(runtime_command_deadline_error)?;
        #[cfg(windows)]
        let _execution_guard = self.acquire_windows_execution_guard(deadline, &|| false)?;
        if std::time::Instant::now() >= deadline {
            return Err(runtime_command_deadline_error());
        }
        let mut command = Command::new(&self.binary);
        command.args(args).stdin(Stdio::from(stdin));
        self.apply(&mut command);
        bounded_command_output_with_configured_stdin_until(&mut command, maximum, deadline)
    }

    #[cfg(windows)]
    fn acquire_windows_execution_guard(
        &self,
        deadline: std::time::Instant,
        is_cancelled: &dyn Fn() -> bool,
    ) -> io::Result<Option<crate::managed_runtime::WindowsManagedRuntimeExecutionGuard>> {
        self.windows_launch_contract
            .as_deref()
            .map(|contract| contract.acquire(&self.binary, deadline, is_cancelled))
            .transpose()
    }

    fn apply(&self, command: &mut Command) {
        if self.clear_environment {
            command.env_clear();
            command.envs(self.environment.iter());
            if let Some(directory) = &self.working_directory {
                command.current_dir(directory);
            }
        } else {
            apply_runtime_environment(command);
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimePreflight {
    pub provider: RuntimeProvider,
    pub server_version: String,
    pub security_options: String,
    /// Durable, typed identity for the exact command source used by this run.
    /// Older records deserialize as `Compatibility`.
    #[serde(default)]
    pub command_provenance: RuntimeCommandProvenance,
}

#[derive(Debug, Serialize, Deserialize)]
struct PodmanSecurityInfo {
    #[serde(rename = "apparmorEnabled")]
    apparmor_enabled: bool,
    capabilities: String,
    rootless: bool,
    #[serde(rename = "seccompEnabled")]
    seccomp_enabled: bool,
    #[serde(rename = "seccompProfilePath")]
    seccomp_profile_path: String,
    #[serde(rename = "selinuxEnabled")]
    selinux_enabled: bool,
}

fn runtime_security_info_template(provider: RuntimeProvider) -> &'static str {
    match provider {
        RuntimeProvider::Docker => "{{json .SecurityOptions}}",
        RuntimeProvider::ManagedLocal | RuntimeProvider::Podman => "{{json .Host.Security}}",
    }
}

/// A single, bounded control-plane query used immediately before an engine
/// starts. Keeping the server version and security options in one response
/// avoids repeating the two-command prepare-time inspection for every engine
/// while still proving that the current daemon is alive and describing the
/// security boundary that will execute this engine.
fn runtime_execution_info_template(provider: RuntimeProvider) -> &'static str {
    match provider {
        RuntimeProvider::Docker => {
            r#"{"serverVersion":{{json .ServerVersion}},"securityOptions":{{json .SecurityOptions}}}"#
        }
        RuntimeProvider::ManagedLocal | RuntimeProvider::Podman => {
            r#"{"serverVersion":{{json .Version.Version}},"securityOptions":{{json .Host.Security}}}"#
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RuntimeExecutionInfo {
    server_version: String,
    security_options: serde_json::Value,
}

fn runtime_preflight_from_execution_info(
    provider: RuntimeProvider,
    provenance: RuntimeCommandProvenance,
    document: &[u8],
) -> AppResult<RuntimePreflight> {
    if document.is_empty() || document.len() > MAX_RUNTIME_EXECUTION_INFO_BYTES {
        return Err(AppError::Runtime(
            "container runtime execution information exceeded its bounded JSON contract".into(),
        ));
    }
    let observed: RuntimeExecutionInfo = serde_json::from_slice(document).map_err(|error| {
        AppError::Runtime(format!(
            "container runtime returned malformed execution-preflight JSON: {error}"
        ))
    })?;
    let server_version = observed.server_version.trim().to_owned();
    if server_version.is_empty()
        || server_version.len() > 1024
        || server_version.chars().any(char::is_control)
    {
        return Err(AppError::Runtime(
            "container runtime returned a malformed server version".into(),
        ));
    }
    let security_document = serde_json::to_vec(&observed.security_options).map_err(|error| {
        AppError::Runtime(format!(
            "container runtime security information could not be encoded: {error}"
        ))
    })?;
    let security_options = validate_runtime_security_options(provider, &security_document)?;
    Ok(RuntimePreflight {
        provider,
        server_version,
        security_options,
        command_provenance: provenance,
    })
}

fn validate_runtime_security_options(
    provider: RuntimeProvider,
    document: &[u8],
) -> AppResult<String> {
    if document.is_empty() || document.len() > MAX_RUNTIME_SECURITY_OPTIONS_BYTES {
        return Err(AppError::Runtime(
            "container runtime security information exceeded its bounded JSON contract".into(),
        ));
    }
    let validate_text = |value: &str, label: &str, allow_empty: bool| -> AppResult<()> {
        if (!allow_empty && value.is_empty())
            || value.len() > 4096
            || value.chars().any(char::is_control)
        {
            return Err(AppError::Runtime(format!(
                "container runtime {label} is malformed"
            )));
        }
        Ok(())
    };

    match provider {
        RuntimeProvider::Docker => {
            let options: Vec<String> = serde_json::from_slice(document).map_err(|error| {
                AppError::Runtime(format!(
                    "Docker returned malformed security-options JSON: {error}"
                ))
            })?;
            if options.len() > 256 {
                return Err(AppError::Runtime(
                    "Docker returned too many security options".into(),
                ));
            }
            for option in &options {
                validate_text(option, "security option", false)?;
            }
            serde_json::to_string(&options).map_err(|error| {
                AppError::Runtime(format!(
                    "Docker security options could not be canonicalized: {error}"
                ))
            })
        }
        RuntimeProvider::ManagedLocal | RuntimeProvider::Podman => {
            let security: PodmanSecurityInfo =
                serde_json::from_slice(document).map_err(|error| {
                    AppError::Runtime(format!(
                        "Podman returned malformed host-security JSON: {error}"
                    ))
                })?;
            validate_text(&security.capabilities, "capabilities", false)?;
            validate_text(
                &security.seccomp_profile_path,
                "seccomp profile path",
                !security.seccomp_enabled,
            )?;
            if provider == RuntimeProvider::ManagedLocal
                && (!security.rootless || !security.seccomp_enabled)
            {
                return Err(AppError::NotAuthorized(
                    "release-managed Podman did not report rootless seccomp isolation".into(),
                ));
            }
            serde_json::to_string(&security).map_err(|error| {
                AppError::Runtime(format!(
                    "Podman host security information could not be canonicalized: {error}"
                ))
            })
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedImage {
    repository: String,
    digest: String,
}

impl PinnedImage {
    pub fn from_manifest(manifest: &EngineManifest) -> AppResult<Self> {
        if let Some(blocker) = manifest.release_blocker() {
            return Err(AppError::EngineRegistry(format!(
                "engine {} cannot be executed: {blocker}",
                manifest.id
            )));
        }
        let image = manifest.image.as_ref().ok_or_else(|| {
            AppError::Runtime(format!(
                "engine {} has no container image configured",
                manifest.id
            ))
        })?;
        Self::new(
            &image.repository,
            image.digest.as_deref().unwrap_or_default(),
        )
    }

    pub fn new(repository: &str, digest: &str) -> AppResult<Self> {
        let repository = repository.trim();
        if repository.is_empty()
            || repository.len() > 2048
            || repository.starts_with('-')
            || repository.contains('@')
            || repository.chars().any(char::is_whitespace)
            || repository.contains(['\n', '\r', '\0'])
        {
            return Err(AppError::Runtime(
                "container image repository is invalid".into(),
            ));
        }
        if !valid_sha256_digest(digest) {
            return Err(AppError::Runtime(format!(
                "container image {repository} must include a sha256 digest"
            )));
        }
        Ok(Self {
            repository: repository.to_owned(),
            digest: digest.to_ascii_lowercase(),
        })
    }

    pub fn repository(&self) -> &str {
        &self.repository
    }

    pub fn digest(&self) -> &str {
        &self.digest
    }

    pub fn reference(&self) -> String {
        format!("{}@{}", self.repository, self.digest)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResourceLimits {
    pub memory_mb: u32,
    pub pids: u32,
    pub cpu_millis: u32,
    pub tmpfs_mb: u32,
    pub output_bytes: u64,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            memory_mb: 1024,
            pids: 256,
            cpu_millis: 1000,
            tmpfs_mb: 64,
            output_bytes: DEFAULT_OUTPUT_BYTES,
        }
    }
}

impl ResourceLimits {
    fn validate(&self) -> AppResult<()> {
        if !(128..=262_144).contains(&self.memory_mb) {
            return Err(AppError::InvalidRequest(
                "container memory limit must be between 128 MiB and 256 GiB".into(),
            ));
        }
        if !(16..=16_384).contains(&self.pids) {
            return Err(AppError::InvalidRequest(
                "container pids limit must be between 16 and 16384".into(),
            ));
        }
        if !(50..=64_000).contains(&self.cpu_millis) {
            return Err(AppError::InvalidRequest(
                "container CPU limit must be between 50 and 64000 millicores".into(),
            ));
        }
        if !(16..=4096).contains(&self.tmpfs_mb) {
            return Err(AppError::InvalidRequest(
                "container tmpfs limit must be between 16 MiB and 4 GiB".into(),
            ));
        }
        if !(MIN_OUTPUT_BYTES..=MAX_OUTPUT_BYTES).contains(&self.output_bytes) {
            return Err(AppError::InvalidRequest(
                "container aggregate output limit must be between 1 MiB and 64 GiB".into(),
            ));
        }
        Ok(())
    }
}

fn validate_execution_timeout_seconds(timeout_seconds: u64) -> AppResult<()> {
    if !(MIN_ENGINE_EXECUTION_TIMEOUT_SECONDS..=MAX_ENGINE_EXECUTION_TIMEOUT_SECONDS)
        .contains(&timeout_seconds)
    {
        return Err(AppError::InvalidRequest(
            "container execution timeout must be between 30 and 86400 seconds".into(),
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum NetworkPolicy {
    Disabled,
    Managed {
        network_name: String,
        policy_id: String,
        allowed_destinations: Vec<String>,
        gateway_endpoint: String,
    },
}

impl NetworkPolicy {
    pub fn managed(
        network_name: impl Into<String>,
        policy_id: impl Into<String>,
        allowed_destinations: Vec<String>,
        gateway_endpoint: impl Into<String>,
    ) -> AppResult<Self> {
        let policy = Self::Managed {
            network_name: network_name.into(),
            policy_id: policy_id.into(),
            allowed_destinations,
            gateway_endpoint: gateway_endpoint.into(),
        };
        policy.validate()?;
        Ok(policy)
    }

    pub fn allowed_destinations(&self) -> &[String] {
        match self {
            Self::Disabled => &[],
            Self::Managed {
                allowed_destinations,
                ..
            } => allowed_destinations,
        }
    }

    pub fn policy_id(&self) -> Option<&str> {
        match self {
            Self::Disabled => None,
            Self::Managed { policy_id, .. } => Some(policy_id),
        }
    }

    pub fn gateway_endpoint(&self) -> Option<&str> {
        match self {
            Self::Disabled => None,
            Self::Managed {
                gateway_endpoint, ..
            } => Some(gateway_endpoint),
        }
    }

    fn validate(&self) -> AppResult<()> {
        let Self::Managed {
            network_name,
            policy_id,
            allowed_destinations,
            gateway_endpoint,
        } = self
        else {
            return Ok(());
        };
        if !valid_runtime_name(network_name) {
            return Err(AppError::InvalidRequest(
                "managed container network name is invalid".into(),
            ));
        }
        if policy_id.is_empty()
            || policy_id.len() > 128
            || !policy_id.chars().all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.')
            })
        {
            return Err(AppError::InvalidRequest(
                "managed network policy id is invalid".into(),
            ));
        }
        if allowed_destinations.is_empty() {
            return Err(AppError::InvalidRequest(
                "managed network policy must have an explicit destination allowlist".into(),
            ));
        }
        for destination in allowed_destinations {
            let trimmed = destination.trim();
            if trimmed.is_empty()
                || trimmed == "*"
                || trimmed.contains(['\n', '\r', '\0'])
                || trimmed.chars().any(char::is_whitespace)
            {
                return Err(AppError::InvalidRequest(format!(
                    "invalid network destination in policy {policy_id}"
                )));
            }
        }
        validate_gateway_endpoint(gateway_endpoint)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CredentialSource {
    EphemeralScanRole,
    ExternalReadOnlyGrant,
    LocalModelEndpoint,
}

pub struct ScannerCredential {
    environment_key: String,
    value: Zeroizing<String>,
    expires_at: DateTime<Utc>,
    source: CredentialSource,
}

impl fmt::Debug for ScannerCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ScannerCredential")
            .field("environment_key", &self.environment_key)
            .field("value", &"[REDACTED]")
            .field("expires_at", &self.expires_at)
            .field("source", &self.source)
            .finish()
    }
}

impl ScannerCredential {
    #[cfg(test)]
    pub(crate) fn ephemeral_read_only(
        environment_key: impl Into<String>,
        value: impl Into<String>,
        expires_at: DateTime<Utc>,
        source: CredentialSource,
    ) -> AppResult<Self> {
        Self::from_vault(
            environment_key,
            Zeroizing::new(value.into()),
            expires_at,
            source,
        )
    }

    pub(crate) fn from_vault(
        environment_key: impl Into<String>,
        value: Zeroizing<String>,
        expires_at: DateTime<Utc>,
        source: CredentialSource,
    ) -> AppResult<Self> {
        let environment_key = environment_key.into();
        if !valid_environment_key(&environment_key) {
            return Err(AppError::InvalidRequest(format!(
                "invalid scanner credential environment key: {environment_key}"
            )));
        }
        let upper = environment_key.to_ascii_uppercase();
        if upper.contains("ADMIN") || upper.contains("BROKER") || upper.contains("ROOT_PASSWORD") {
            return Err(AppError::NotAuthorized(format!(
                "admin or bootstrap broker credential cannot enter a scanner container: {environment_key}"
            )));
        }
        if value.is_empty() {
            return Err(AppError::InvalidRequest(
                "scanner credential value cannot be empty".into(),
            ));
        }
        if expires_at <= Utc::now() {
            return Err(AppError::NotAuthorized(
                "scanner credential is already expired".into(),
            ));
        }
        Ok(Self {
            environment_key,
            value,
            expires_at,
            source,
        })
    }

    pub fn environment_key(&self) -> &str {
        &self.environment_key
    }

    pub fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }

    pub fn source(&self) -> CredentialSource {
        self.source
    }

    fn expose_value(&self) -> &str {
        self.value.as_str()
    }
}

#[derive(Default)]
pub struct ScannerCredentialSet {
    credentials: Vec<ScannerCredential>,
}

impl fmt::Debug for ScannerCredentialSet {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ScannerCredentialSet")
            .field(
                "environment_keys",
                &self
                    .credentials
                    .iter()
                    .map(ScannerCredential::environment_key)
                    .collect::<Vec<_>>(),
            )
            .finish()
    }
}

impl ScannerCredentialSet {
    pub(crate) fn new(credentials: Vec<ScannerCredential>) -> AppResult<Self> {
        let mut keys = BTreeSet::new();
        for credential in &credentials {
            if !keys.insert(credential.environment_key()) {
                return Err(AppError::InvalidRequest(format!(
                    "duplicate scanner credential environment key: {}",
                    credential.environment_key()
                )));
            }
        }
        Ok(Self { credentials })
    }

    pub fn is_empty(&self) -> bool {
        self.credentials.is_empty()
    }

    pub fn environment_keys(&self) -> impl Iterator<Item = &str> {
        self.credentials
            .iter()
            .map(ScannerCredential::environment_key)
    }

    /// Backend-only access for an in-process provider client. This deliberately
    /// does not return an owned value and is never exposed through serde, CLI
    /// arguments, process environment, or logging.
    pub(crate) fn provider_secret(&self, environment_key: &str) -> Option<&str> {
        self.credentials
            .iter()
            .find(|credential| credential.environment_key == environment_key)
            .map(ScannerCredential::expose_value)
    }

    fn validate_fresh(&self) -> AppResult<()> {
        let now = Utc::now();
        for credential in &self.credentials {
            if credential.expires_at <= now {
                return Err(AppError::NotAuthorized(format!(
                    "scanner credential {} expired before execution",
                    credential.environment_key
                )));
            }
        }
        Ok(())
    }

    fn write_envelope(&self, path: &Path) -> AppResult<SecretFileGuard> {
        #[derive(Serialize)]
        struct Envelope<'a> {
            schema_version: &'static str,
            credentials: Vec<Entry<'a>>,
        }

        #[derive(Serialize)]
        struct Entry<'a> {
            key: &'a str,
            value: &'a str,
            expires_at: DateTime<Utc>,
            source: CredentialSource,
        }

        let envelope = Envelope {
            schema_version: "1.0.0",
            credentials: self
                .credentials
                .iter()
                .map(|credential| Entry {
                    key: credential.environment_key(),
                    value: credential.expose_value(),
                    expires_at: credential.expires_at(),
                    source: credential.source(),
                })
                .collect(),
        };
        let bytes = Zeroizing::new(serde_json::to_vec(&envelope).map_err(|error| {
            AppError::Internal(format!("credential envelope could not be encoded: {error}"))
        })?);
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(path).map_err(|error| {
            AppError::Runtime(format!(
                "protected credential channel could not be created: {error}"
            ))
        })?;
        // Take ownership immediately after create_new succeeds. Permission,
        // write, sync, canonicalization and hashing failures must all remove
        // this file, while a pre-existing file must never be touched.
        let mut guard = SecretFileGuard {
            path: path.to_path_buf(),
            sha256: String::new(),
            cleaned: false,
        };
        // Drop the open handle before the guard on an error (also on Windows).
        let mut file = file;
        restrict_secret_file(path, false)?;
        file.write_all(bytes.as_slice())?;
        file.sync_all()?;
        restrict_secret_file(path, true)?;
        guard.path = canonical_mount_path(path, "credential channel")?;
        guard.sha256 = hash_bounded_control_file(
            &guard.path,
            MAX_CREDENTIAL_DOCUMENT_BYTES,
            "credential channel",
        )?;
        Ok(guard)
    }
}

struct SecretFileGuard {
    path: PathBuf,
    sha256: String,
    cleaned: bool,
}

impl fmt::Debug for SecretFileGuard {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretFileGuard")
            .field("path", &self.path)
            .field("sha256", &self.sha256)
            .field("contents", &"[REDACTED]")
            .finish()
    }
}

impl SecretFileGuard {
    fn create(control_dir: &Path, credentials: &ScannerCredentialSet) -> AppResult<Option<Self>> {
        credentials.validate_fresh()?;
        if credentials.is_empty() {
            return Ok(None);
        }
        validate_mount_directory(control_dir, "credential control")?;
        let mut nonce = [0_u8; 16];
        getrandom::fill(&mut nonce)
            .map_err(|_| AppError::Internal("operating system random source failed".into()))?;
        let path = control_dir.join(format!("credentials-{}.json", hex::encode(nonce)));
        credentials.write_envelope(&path).map(Some)
    }

    fn validate_integrity(&self) -> AppResult<()> {
        let current = hash_bounded_control_file(
            &self.path,
            MAX_CREDENTIAL_DOCUMENT_BYTES,
            "credential channel",
        )?;
        if current != self.sha256 {
            return Err(AppError::NotAuthorized(
                "credential channel changed after creation".into(),
            ));
        }
        Ok(())
    }

    fn cleanup(&mut self) -> AppResult<()> {
        if self.cleaned {
            return Ok(());
        }
        secure_remove_secret_file(&self.path)?;
        self.cleaned = true;
        Ok(())
    }
}

impl Drop for SecretFileGuard {
    fn drop(&mut self) {
        if !self.cleaned {
            let _ = secure_remove_secret_file(&self.path);
        }
    }
}

struct ContainerIdFileGuard {
    path: PathBuf,
}

impl ContainerIdFileGuard {
    fn prepare(control_dir: &Path) -> AppResult<Self> {
        validate_mount_directory(control_dir, "container ID control")?;
        for _ in 0..4 {
            let mut nonce = [0_u8; 16];
            getrandom::fill(&mut nonce)
                .map_err(|_| AppError::Internal("operating system random source failed".into()))?;
            let path = control_dir.join(format!("container-{}.cid", hex::encode(nonce)));
            match fs::symlink_metadata(&path) {
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    return Ok(Self { path });
                }
                Ok(_) => continue,
                Err(error) => return Err(error.into()),
            }
        }
        Err(AppError::Runtime(
            "could not reserve a unique container created-object tracking path".into(),
        ))
    }

    fn argument(&self) -> AppResult<String> {
        let value = self.path.to_str().ok_or_else(|| {
            AppError::Runtime("container ID tracking path is not valid UTF-8".into())
        })?;
        if value.contains(['\n', '\r', '\0']) {
            return Err(AppError::Runtime(
                "container ID tracking path contains an invalid character".into(),
            ));
        }
        Ok(value.to_owned())
    }

    fn created_container(&self) -> AppResult<Option<CreatedContainer>> {
        let metadata = match fs::symlink_metadata(&self.path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > 129 {
            return Err(AppError::NotAuthorized(
                "container created-object tracking file was not a bounded regular file".into(),
            ));
        }
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW);
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
            options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
        }
        let file = options.open(&self.path)?;
        let opened_metadata = file.metadata()?;
        if opened_metadata.file_type().is_symlink()
            || !opened_metadata.is_file()
            || opened_metadata.len() > 129
        {
            return Err(AppError::NotAuthorized(
                "opened container created-object tracking handle was not a bounded regular file"
                    .into(),
            ));
        }
        let mut value = String::new();
        file.take(130).read_to_string(&mut value)?;
        if value.len() > 129 {
            return Err(AppError::NotAuthorized(
                "container created-object tracking file exceeded its bound".into(),
            ));
        }
        CreatedContainer::from_runtime_id(&value).map(Some)
    }

    fn created_container_if_ready(&self) -> AppResult<Option<CreatedContainer>> {
        let metadata = match fs::symlink_metadata(&self.path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > 129 {
            return Err(AppError::NotAuthorized(
                "container created-object tracking file was not a bounded regular file".into(),
            ));
        }
        if metadata.len() < 64 {
            return Ok(None);
        }
        self.created_container()
    }
}

impl Drop for ContainerIdFileGuard {
    fn drop(&mut self) {
        if fs::symlink_metadata(&self.path).is_ok() {
            let _ = fs::remove_file(&self.path);
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RootlessContainerUser {
    user_spec: String,
    podman_userns: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerRunPlan {
    engine_id: String,
    container_name: String,
    image: PinnedImage,
    runtime_args: Vec<String>,
    rootless_user: RootlessContainerUser,
    workspace: PathBuf,
    output: PathBuf,
    scope_file: PathBuf,
    scope_sha256: String,
    launcher_plan_file: Option<PathBuf>,
    launcher_plan_sha256: Option<String>,
    zap_plan_file: Option<PathBuf>,
    zap_plan_sha256: Option<String>,
    credential_control_dir: PathBuf,
    network_policy: NetworkPolicy,
    output_bytes: u64,
    execution_timeout_seconds: u64,
    ownership: OwnedContainerCleanupRequest,
}

impl ContainerRunPlan {
    pub fn engine_id(&self) -> &str {
        &self.engine_id
    }

    pub fn container_name(&self) -> &str {
        &self.container_name
    }

    pub fn image(&self) -> &PinnedImage {
        &self.image
    }

    pub fn runtime_args(&self) -> &[String] {
        &self.runtime_args
    }

    pub fn workspace(&self) -> &Path {
        &self.workspace
    }

    pub fn output(&self) -> &Path {
        &self.output
    }

    pub fn scope_file(&self) -> &Path {
        &self.scope_file
    }

    pub fn scope_sha256(&self) -> &str {
        &self.scope_sha256
    }

    pub fn launcher_plan_file(&self) -> Option<&Path> {
        self.launcher_plan_file.as_deref()
    }

    pub fn launcher_plan_sha256(&self) -> Option<&str> {
        self.launcher_plan_sha256.as_deref()
    }

    pub fn zap_plan_file(&self) -> Option<&Path> {
        self.zap_plan_file.as_deref()
    }

    pub fn zap_plan_sha256(&self) -> Option<&str> {
        self.zap_plan_sha256.as_deref()
    }

    fn credential_control_dir(&self) -> &Path {
        &self.credential_control_dir
    }

    pub fn network_policy(&self) -> &NetworkPolicy {
        &self.network_policy
    }

    pub fn output_bytes(&self) -> u64 {
        self.output_bytes
    }

    pub fn execution_timeout_seconds(&self) -> u64 {
        self.execution_timeout_seconds
    }

    pub fn ownership(&self) -> &OwnedContainerCleanupRequest {
        &self.ownership
    }
}

pub struct ContainerPlanBuilder<'a> {
    manifest: &'a EngineManifest,
    image: &'a PinnedImage,
    directories: &'a RunDirectories,
    scope_file: &'a Path,
    launcher_plan_file: Option<&'a Path>,
    zap_plan_file: Option<&'a Path>,
    limits: &'a ResourceLimits,
    network_policy: &'a NetworkPolicy,
    credential_set: &'a ScannerCredentialSet,
    case_id: &'a str,
    scan_run_id: &'a str,
    engine_run_id: &'a str,
    attempt: u32,
}

impl<'a> ContainerPlanBuilder<'a> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        manifest: &'a EngineManifest,
        image: &'a PinnedImage,
        directories: &'a RunDirectories,
        scope_file: &'a Path,
        limits: &'a ResourceLimits,
        network_policy: &'a NetworkPolicy,
        credential_set: &'a ScannerCredentialSet,
        case_id: &'a str,
        scan_run_id: &'a str,
        engine_run_id: &'a str,
        attempt: u32,
    ) -> Self {
        Self {
            manifest,
            image,
            directories,
            scope_file,
            launcher_plan_file: None,
            zap_plan_file: None,
            limits,
            network_policy,
            credential_set,
            case_id,
            scan_run_id,
            engine_run_id,
            attempt,
        }
    }

    /// Adds the private launcher-v2 execution document. The builder accepts
    /// this only for an explicitly reviewed Naabu v2 manifest and only at the
    /// product-owned fixed control-file location.
    pub fn with_launcher_plan_file(mut self, launcher_plan_file: Option<&'a Path>) -> Self {
        self.launcher_plan_file = launcher_plan_file;
        self
    }

    /// Adds the generated ZAP Automation Framework plan. The builder accepts this
    /// only for the reviewed ZAP manifest and only at the product-owned fixed
    /// control-file location.
    pub fn with_zap_plan_file(mut self, zap_plan_file: Option<&'a Path>) -> Self {
        self.zap_plan_file = zap_plan_file;
        self
    }

    pub fn build(&self) -> AppResult<ContainerRunPlan> {
        let manifest_image = PinnedImage::from_manifest(self.manifest)?;
        if manifest_image != *self.image {
            return Err(AppError::EngineRegistry(format!(
                "run-plan image does not match the pinned manifest image for {}",
                self.manifest.id
            )));
        }
        self.limits.validate()?;
        let execution_timeout_seconds = self.manifest.execution_timeout_seconds();
        validate_execution_timeout_seconds(execution_timeout_seconds)?;
        self.network_policy.validate()?;
        self.credential_set.validate_fresh()?;
        validate_container_owner_id(self.case_id, "case id")?;
        validate_container_owner_id(self.scan_run_id, "scan run id")?;
        validate_container_owner_id(self.engine_run_id, "engine run id")?;
        validate_static_manifest_command(&self.manifest.command)?;
        validate_mount_directory(&self.directories.workspace, "workspace")?;
        validate_mount_directory(&self.directories.output, "output")?;
        validate_mount_directory(&self.directories.control, "control")?;
        validate_mount_file(self.scope_file, "scope document")?;
        validate_naabu_launcher_manifest_contract(
            self.manifest,
            self.launcher_plan_file.is_some(),
        )?;
        validate_zap_plan_manifest_contract(self.manifest, self.zap_plan_file.is_some())?;
        let manifest_requires_network = self.manifest.active_external
            || !self.manifest.network_destinations.is_empty()
            || self.manifest.required_permissions.iter().any(|permission| {
                matches!(
                    permission,
                    ScanPermission::LowImpactExternalConnection
                        | ScanPermission::ActiveExternalTesting
                )
            });
        match (manifest_requires_network, self.network_policy) {
            (true, NetworkPolicy::Disabled) => {
                return Err(AppError::NotAuthorized(format!(
                    "engine {} requires an enforced managed network policy",
                    self.manifest.id
                )));
            }
            (false, NetworkPolicy::Managed { .. }) => {
                return Err(AppError::NotAuthorized(format!(
                    "engine {} did not declare any network access",
                    self.manifest.id
                )));
            }
            _ => {}
        }

        let container_name =
            planned_container_name(&self.manifest.id, self.engine_run_id, self.attempt)?;
        let workspace = canonical_mount_path(&self.directories.workspace, "workspace")?;
        let output = canonical_mount_path(&self.directories.output, "output")?;
        let credential_control_dir = canonical_mount_path(&self.directories.control, "control")?;
        let scope_file = canonical_mount_path(self.scope_file, "scope document")?;
        let scope_sha256 = hash_control_file(&scope_file)?;
        let (launcher_plan_file, launcher_plan_sha256) = match self.launcher_plan_file {
            Some(path) => {
                validate_mount_file(path, "Naabu launcher plan")?;
                let canonical = canonical_mount_path(path, "Naabu launcher plan")?;
                let expected = credential_control_dir.join(NAABU_LAUNCHER_PLAN_CONTROL_FILE);
                if canonical != expected {
                    return Err(AppError::NotAuthorized(
                        "Naabu launcher plan must use the fixed product-owned control path".into(),
                    ));
                }
                let digest = hash_bounded_control_file(
                    &canonical,
                    MAX_NAABU_LAUNCHER_PLAN_BYTES as u64,
                    "Naabu launcher plan",
                )?;
                (Some(canonical), Some(digest))
            }
            None => (None, None),
        };
        let (zap_plan_file, zap_plan_sha256) = match self.zap_plan_file {
            Some(path) => {
                validate_mount_file(path, "ZAP automation plan")?;
                let canonical = canonical_mount_path(path, "ZAP automation plan")?;
                let expected = credential_control_dir.join(ZAP_PLAN_CONTROL_FILE);
                if canonical != expected {
                    return Err(AppError::NotAuthorized(
                        "ZAP automation plan must use the fixed product-owned control path".into(),
                    ));
                }
                let digest = hash_bounded_control_file(
                    &canonical,
                    MAX_ZAP_PLAN_BYTES as u64,
                    "ZAP automation plan",
                )?;
                (Some(canonical), Some(digest))
            }
            None => (None, None),
        };
        let rootless_user = runtime_user_mapping()?;
        let mut runtime_args = vec![
            "run".into(),
            "--name".into(),
            container_name.clone(),
            "--read-only".into(),
            "--cap-drop=ALL".into(),
            "--security-opt=no-new-privileges:true".into(),
            format!("--user={}", rootless_user.user_spec),
            "--pids-limit".into(),
            self.limits.pids.to_string(),
            "--memory".into(),
            format!("{}m", self.limits.memory_mb),
            "--cpus".into(),
            format!("{:.3}", self.limits.cpu_millis as f64 / 1000.0),
            "--ulimit".into(),
            format!("fsize={0}:{0}", self.limits.output_bytes),
            "--log-driver=none".into(),
            "--tmpfs".into(),
            format!(
                "/tmp:rw,noexec,nosuid,nodev,mode=1777,size={}m",
                self.limits.tmpfs_mb
            ),
            "--workdir".into(),
            CONTAINER_WORKSPACE_PATH.into(),
            "--mount".into(),
            bind_mount(&workspace, CONTAINER_WORKSPACE_PATH, true)?,
            "--mount".into(),
            bind_mount(&output, CONTAINER_OUTPUT_PATH, false)?,
            "--mount".into(),
            bind_mount(&scope_file, CONTAINER_SCOPE_PATH, true)?,
            "--label".into(),
            format!("{CONTAINER_MANAGED_LABEL_KEY}=true"),
            "--label".into(),
            format!("{CONTAINER_CASE_LABEL_KEY}={}", self.case_id),
            "--label".into(),
            format!("{CONTAINER_SCAN_RUN_LABEL_KEY}={}", self.scan_run_id),
            "--label".into(),
            format!("{CONTAINER_ENGINE_LABEL_KEY}={}", self.manifest.id),
            "--label".into(),
            format!("{CONTAINER_ENGINE_RUN_LABEL_KEY}={}", self.engine_run_id),
            "--label".into(),
            format!("{CONTAINER_ATTEMPT_LABEL_KEY}={}", self.attempt),
            "--label".into(),
            format!("{CONTAINER_SCOPE_LABEL_KEY}={scope_sha256}"),
        ];

        if let Some(digest) = launcher_plan_sha256.as_ref() {
            runtime_args.extend([
                "--label".into(),
                format!("{CONTAINER_NAABU_LAUNCHER_PLAN_LABEL_KEY}={digest}"),
            ]);
        }
        if let Some(digest) = zap_plan_sha256.as_ref() {
            runtime_args.extend([
                "--label".into(),
                format!("{CONTAINER_ZAP_PLAN_LABEL_KEY}={digest}"),
            ]);
        }

        match self.network_policy {
            NetworkPolicy::Disabled => {
                runtime_args.extend(["--network".into(), "none".into()]);
            }
            NetworkPolicy::Managed {
                network_name,
                policy_id,
                gateway_endpoint,
                ..
            } => {
                runtime_args.extend(["--network".into(), network_name.clone()]);
                runtime_args.extend([
                    "--label".into(),
                    format!("ai.security-scanner.network-policy={policy_id}"),
                ]);
                for key in [
                    "ALL_PROXY",
                    "all_proxy",
                    "HTTP_PROXY",
                    "http_proxy",
                    "HTTPS_PROXY",
                    "https_proxy",
                    "AI_SECURITY_SCANNER_PROXY",
                ] {
                    runtime_args.extend(["--env".into(), format!("{key}={gateway_endpoint}")]);
                }
                runtime_args.extend([
                    "--env".into(),
                    "NO_PROXY=".into(),
                    "--env".into(),
                    "no_proxy=".into(),
                ]);
            }
        }

        if let Some(path) = &launcher_plan_file {
            runtime_args.extend([
                "--mount".into(),
                bind_mount(path, CONTAINER_NAABU_LAUNCHER_PLAN_PATH, true)?,
            ]);
        }
        if let Some(path) = &zap_plan_file {
            runtime_args.extend([
                "--mount".into(),
                bind_mount(path, CONTAINER_ZAP_PLAN_PATH, true)?,
            ]);
        }

        runtime_args.push(self.image.reference());
        runtime_args.extend(self.manifest.command.iter().cloned());

        Ok(ContainerRunPlan {
            engine_id: self.manifest.id.clone(),
            container_name,
            image: self.image.clone(),
            runtime_args,
            rootless_user,
            workspace,
            output,
            scope_file,
            scope_sha256: scope_sha256.clone(),
            launcher_plan_file,
            launcher_plan_sha256: launcher_plan_sha256.clone(),
            zap_plan_file,
            zap_plan_sha256: zap_plan_sha256.clone(),
            credential_control_dir,
            network_policy: self.network_policy.clone(),
            output_bytes: self.limits.output_bytes,
            execution_timeout_seconds,
            ownership: OwnedContainerCleanupRequest {
                case_id: self.case_id.to_owned(),
                scan_run_id: self.scan_run_id.to_owned(),
                engine_run_id: self.engine_run_id.to_owned(),
                engine_id: self.manifest.id.clone(),
                attempt: self.attempt,
                scope_sha256,
                launcher_plan_sha256: launcher_plan_sha256.clone(),
                zap_plan_sha256: zap_plan_sha256.clone(),
                image: self.image.clone(),
            },
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeOutcome {
    pub exit_code: Option<i32>,
    pub cancelled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CleanupOutcome {
    pub removed: bool,
    pub detail: String,
    /// Present only when managed-egress cleanup read a gateway refusal record.
    /// Container cleanup leaves this empty. Skipped when empty so an older
    /// execution-report commitment stays byte-stable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway_refusals: Option<GatewayRefusalRecord>,
}

/// Immutable identity emitted by the runtime only when this invocation
/// actually created a container. Cleanup accepts this handle instead of a
/// deterministic name so a failed name-collision launch cannot delete a
/// pre-existing object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreatedContainer {
    immutable_id: String,
}

impl CreatedContainer {
    fn from_runtime_id(value: &str) -> AppResult<Self> {
        let immutable_id = value.trim().to_ascii_lowercase();
        if immutable_id.len() != 64
            || !immutable_id
                .chars()
                .all(|character| character.is_ascii_hexdigit())
        {
            return Err(AppError::NotAuthorized(
                "container runtime returned an invalid immutable created-object ID".into(),
            ));
        }
        Ok(Self { immutable_id })
    }

    pub fn immutable_id(&self) -> &str {
        &self.immutable_id
    }
}

/// Exact, non-secret ownership proof required before crash recovery may remove
/// a container. Runtime provenance is resolved separately by `AppState`; this
/// value binds the runtime object to one persisted execution and pinned image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedContainerCleanupRequest {
    pub case_id: String,
    pub scan_run_id: String,
    pub engine_run_id: String,
    pub engine_id: String,
    pub attempt: u32,
    pub scope_sha256: String,
    /// Exact digest of the private versioned launcher work plan. Legacy executions
    /// have no such document or ownership label and therefore retain `None`.
    pub launcher_plan_sha256: Option<String>,
    /// Exact digest of the generated ZAP Automation Framework plan. Executions
    /// without that plan have no such document or ownership label and therefore
    /// retain `None`.
    pub zap_plan_sha256: Option<String>,
    pub image: PinnedImage,
}

impl OwnedContainerCleanupRequest {
    pub fn container_name(&self) -> AppResult<String> {
        self.validate()?;
        planned_container_name(&self.engine_id, &self.engine_run_id, self.attempt)
    }

    fn validate(&self) -> AppResult<()> {
        validate_container_owner_id(&self.case_id, "case id")?;
        validate_container_owner_id(&self.scan_run_id, "scan run id")?;
        validate_container_owner_id(&self.engine_run_id, "engine run id")?;
        if !valid_runtime_name(&self.engine_id) || self.attempt == 0 {
            return Err(AppError::InvalidRequest(
                "engine identity is invalid for owned container cleanup".into(),
            ));
        }
        if self.scope_sha256.len() != 64
            || !self
                .scope_sha256
                .chars()
                .all(|character| character.is_ascii_hexdigit())
        {
            return Err(AppError::InvalidRequest(
                "scope digest is invalid for owned container cleanup".into(),
            ));
        }
        if let Some(digest) = self.launcher_plan_sha256.as_deref() {
            if self.engine_id != NAABU_ENGINE_ID {
                return Err(AppError::InvalidRequest(
                    "a launcher plan digest is valid only for owned Naabu container cleanup".into(),
                ));
            }
            if !is_lowercase_sha256(digest) {
                return Err(AppError::InvalidRequest(
                    "Naabu launcher plan digest is invalid for owned container cleanup".into(),
                ));
            }
        }
        if let Some(digest) = self.zap_plan_sha256.as_deref() {
            if self.engine_id != ZAP_ENGINE_ID {
                return Err(AppError::InvalidRequest(
                    "a ZAP automation plan digest is valid only for owned ZAP container cleanup"
                        .into(),
                ));
            }
            if !is_lowercase_sha256(digest) {
                return Err(AppError::InvalidRequest(
                    "ZAP automation plan digest is invalid for owned container cleanup".into(),
                ));
            }
        }
        Ok(())
    }

    fn expected_labels(&self) -> BTreeMap<&'static str, String> {
        let mut labels = BTreeMap::from([
            (CONTAINER_MANAGED_LABEL_KEY, "true".into()),
            (CONTAINER_CASE_LABEL_KEY, self.case_id.clone()),
            (CONTAINER_SCAN_RUN_LABEL_KEY, self.scan_run_id.clone()),
            (CONTAINER_ENGINE_LABEL_KEY, self.engine_id.clone()),
            (CONTAINER_ENGINE_RUN_LABEL_KEY, self.engine_run_id.clone()),
            (CONTAINER_ATTEMPT_LABEL_KEY, self.attempt.to_string()),
            (
                CONTAINER_SCOPE_LABEL_KEY,
                self.scope_sha256.to_ascii_lowercase(),
            ),
        ]);
        if let Some(digest) = self.launcher_plan_sha256.as_ref() {
            labels.insert(CONTAINER_NAABU_LAUNCHER_PLAN_LABEL_KEY, digest.clone());
        }
        if let Some(digest) = self.zap_plan_sha256.as_ref() {
            labels.insert(CONTAINER_ZAP_PLAN_LABEL_KEY, digest.clone());
        }
        labels
    }
}

fn is_lowercase_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

#[derive(Clone, Default)]
pub struct CancellationToken {
    cancelled: Arc<AtomicBool>,
    pause_requested: Arc<AtomicBool>,
    paused: Arc<AtomicBool>,
}

impl CancellationToken {
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }

    /// Requests a cooperative pause. The request is distinct from an
    /// acknowledged pause so callers never report a container as paused before
    /// the runtime has successfully issued its pause operation.
    pub fn request_pause(&self) {
        if !self.is_cancelled() {
            self.pause_requested.store(true, Ordering::SeqCst);
        }
    }

    /// Clears a cooperative pause request. A currently paused runtime remains
    /// acknowledged as paused until its unpause operation succeeds.
    pub fn resume(&self) {
        self.pause_requested.store(false, Ordering::SeqCst);
    }

    pub fn is_pause_requested(&self) -> bool {
        self.pause_requested.load(Ordering::SeqCst)
    }

    pub fn is_paused(&self) -> bool {
        self.paused.load(Ordering::SeqCst)
    }

    fn acknowledge_paused(&self) {
        self.paused.store(true, Ordering::SeqCst);
    }

    fn acknowledge_resumed(&self) {
        self.paused.store(false, Ordering::SeqCst);
    }
}

impl fmt::Debug for CancellationToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CancellationToken")
            .field("cancelled", &self.is_cancelled())
            .field("pause_requested", &self.is_pause_requested())
            .field("paused", &self.is_paused())
            .finish()
    }
}

pub trait ContainerRuntime: Send + Sync {
    fn preflight(&self) -> AppResult<RuntimePreflight>;
    /// Reinspect the live daemon immediately before a real engine execution.
    /// Implementations may use a cheaper combined control-plane query than
    /// the prepare-time preflight, but must not return a batch-cached proof.
    fn execution_preflight(&self) -> AppResult<RuntimePreflight>;
    fn verify_network(&self, policy: &NetworkPolicy) -> AppResult<()>;
    fn pull(&self, image: &PinnedImage) -> AppResult<()>;
    /// Runs one exact container plan. Implementations must reset both output
    /// parameters. `creation_may_be_untracked` becomes true as soon as a
    /// runtime process could have created the planned object; a missing
    /// `created_container` after that point requires ownership-label
    /// reconciliation by the caller and is not proof of absence.
    fn run(
        &self,
        plan: &ContainerRunPlan,
        credentials: &ScannerCredentialSet,
        cancellation: &CancellationToken,
        capture: &CapturePaths,
        created_container: &mut Option<CreatedContainer>,
        creation_may_be_untracked: &mut bool,
    ) -> AppResult<RuntimeOutcome>;
    fn cleanup(
        &self,
        ownership: &OwnedContainerCleanupRequest,
        created_container: Option<&CreatedContainer>,
    ) -> AppResult<CleanupOutcome>;
}

#[derive(Debug, Clone)]
pub struct ProcessContainerRuntime {
    context: RuntimeCommandContext,
    release_approved_local_image_directory: Option<PathBuf>,
    // A runtime value is resolved immediately before a scan batch is
    // persisted, then that exact value is moved into the worker. Keep the
    // successful prepare-time proof attached to that immutable command
    // context so clones share one initial two-command inspection. Every real
    // engine still replaces it with a fresh, single-command execution proof.
    // Failures are deliberately not cached.
    preflight_cache: Arc<RuntimePreflightCache>,
    #[cfg(test)]
    test_execution_timeout: Option<StdDuration>,
    #[cfg(test)]
    test_capture_drain_timeout: Option<StdDuration>,
}

#[derive(Debug, Default)]
struct RuntimePreflightCache {
    observed: Mutex<Option<RuntimePreflight>>,
}

impl RuntimePreflightCache {
    fn get_or_try_init<F>(&self, inspect: F) -> AppResult<RuntimePreflight>
    where
        F: FnOnce() -> AppResult<RuntimePreflight>,
    {
        // Hold the lock while inspecting so clones of one prepared runtime
        // cannot race and launch duplicate control-plane probes.
        let mut observed = self.preflight_cache_lock()?;
        if let Some(preflight) = observed.as_ref() {
            return Ok(preflight.clone());
        }
        let preflight = inspect()?;
        *observed = Some(preflight.clone());
        Ok(preflight)
    }

    fn refresh<F>(&self, inspect: F) -> AppResult<RuntimePreflight>
    where
        F: FnOnce() -> AppResult<RuntimePreflight>,
    {
        // Serialize refreshes with prepare-time inspection so an older probe
        // cannot overwrite a newer execution proof. A failed live inspection
        // invalidates the prepared proof: callers must never fall back to a
        // daemon state observed earlier in the batch.
        let mut observed = self.preflight_cache_lock()?;
        match inspect() {
            Ok(preflight) => {
                *observed = Some(preflight.clone());
                Ok(preflight)
            }
            Err(error) => {
                *observed = None;
                Err(error)
            }
        }
    }

    fn preflight_cache_lock(
        &self,
    ) -> AppResult<std::sync::MutexGuard<'_, Option<RuntimePreflight>>> {
        self.observed
            .lock()
            .map_err(|_| AppError::Internal("runtime preflight cache lock was poisoned".into()))
    }
}

/// Monotonic execution budget that advances only while scanner work is active.
/// A pause takes effect only after the runtime has acknowledged the container
/// control command, so time spent issuing `pause` remains charged while time
/// between that acknowledgement and a successful `unpause` does not.
#[derive(Debug)]
struct ActiveExecutionBudget {
    remaining: StdDuration,
    observed_at: std::time::Instant,
    paused: bool,
}

impl ActiveExecutionBudget {
    fn started(timeout: StdDuration, started_at: std::time::Instant) -> Self {
        Self {
            remaining: timeout,
            observed_at: started_at,
            paused: false,
        }
    }

    fn charge_until(&mut self, now: std::time::Instant) {
        if !self.paused {
            self.remaining = self
                .remaining
                .saturating_sub(now.saturating_duration_since(self.observed_at));
        }
        self.observed_at = now;
    }

    fn expired_at(&mut self, now: std::time::Instant) -> bool {
        self.charge_until(now);
        self.remaining.is_zero()
    }

    fn acknowledge_paused_at(&mut self, now: std::time::Instant) {
        self.charge_until(now);
        self.paused = true;
    }

    fn acknowledge_resumed_at(&mut self, now: std::time::Instant) {
        self.observed_at = now;
        self.paused = false;
    }

    fn is_paused(&self) -> bool {
        self.paused
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DirectRuntimeOperation {
    RuntimeVersionPreflight,
    RuntimeSecurityPreflight,
    RuntimeExecutionPreflight,
    ManagedNetworkPreflight,
    LocalPinnedImageInspection,
    LocalPinnedImageLoad,
    PinnedImagePull,
    ContainerPause,
    ContainerUnpause,
    ContainerStop,
    CreatedContainerOwnershipInspection,
    OwnedContainerInspection,
    OwnedContainerCleanup,
}

impl DirectRuntimeOperation {
    fn label(self) -> &'static str {
        match self {
            Self::RuntimeVersionPreflight => "runtime version preflight",
            Self::RuntimeSecurityPreflight => "runtime security preflight",
            Self::RuntimeExecutionPreflight => "runtime execution preflight",
            Self::ManagedNetworkPreflight => "managed network preflight",
            Self::LocalPinnedImageInspection => "local pinned image inspection",
            Self::LocalPinnedImageLoad => "local pinned image load",
            Self::PinnedImagePull => "pinned image pull",
            Self::ContainerPause => "container pause",
            Self::ContainerUnpause => "container unpause",
            Self::ContainerStop => "container stop",
            Self::CreatedContainerOwnershipInspection => "created container ownership inspection",
            Self::OwnedContainerInspection => "owned container inspection",
            Self::OwnedContainerCleanup => "owned container cleanup",
        }
    }

    fn timeout(self) -> StdDuration {
        match self {
            Self::LocalPinnedImageLoad => LOCAL_PINNED_IMAGE_LOAD_TIMEOUT,
            Self::PinnedImagePull => PINNED_IMAGE_PULL_TIMEOUT,
            Self::OwnedContainerCleanup => OWNED_CONTAINER_REMOVAL_TIMEOUT,
            _ => RUNTIME_COMMAND_TIMEOUT,
        }
    }
}

#[derive(Debug, Deserialize)]
struct OwnedContainerInspect {
    #[serde(rename = "Id", alias = "ID")]
    id: String,
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "ImageName", default)]
    image_name: Option<String>,
    #[serde(rename = "Config")]
    config: OwnedContainerInspectConfig,
}

#[derive(Debug, Deserialize)]
struct OwnedContainerInspectConfig {
    #[serde(rename = "Image", default)]
    image: Option<String>,
    #[serde(rename = "Labels", default)]
    labels: BTreeMap<String, String>,
}

fn canonical_container_repository(repository: &str) -> String {
    // Docker and Podman qualify unqualified image names with Docker Hub in
    // inspect output. Preserve every explicit registry byte-for-byte and
    // normalize only that deterministic default-registry spelling.
    let first_component = repository.split('/').next().unwrap_or_default();
    if first_component.contains('.')
        || first_component.contains(':')
        || first_component == "localhost"
    {
        repository.to_owned()
    } else if repository.contains('/') {
        format!("docker.io/{repository}")
    } else {
        format!("docker.io/library/{repository}")
    }
}

fn image_reference_matches_pinned(reference: &str, image: &PinnedImage) -> bool {
    let digest_suffix = format!("@{}", image.digest());
    let Some(repository) = reference.strip_suffix(&digest_suffix) else {
        return false;
    };
    if repository.is_empty() || repository.contains('@') {
        return false;
    }
    canonical_container_repository(repository) == canonical_container_repository(image.repository())
}

fn prove_owned_container(
    document: &[u8],
    request: &OwnedContainerCleanupRequest,
) -> AppResult<String> {
    request.validate()?;
    if document.is_empty() || document.len() > MAX_CONTAINER_INSPECT_BYTES {
        return Err(AppError::NotAuthorized(
            "owned container inspection was empty or oversized".into(),
        ));
    }
    let inspected = serde_json::from_slice::<Vec<OwnedContainerInspect>>(document)
        .map_err(|_| AppError::NotAuthorized("owned container inspection was malformed".into()))?;
    if inspected.len() != 1 {
        return Err(AppError::NotAuthorized(
            "owned container inspection did not identify exactly one object".into(),
        ));
    }
    let inspected = &inspected[0];
    let expected_name = request.container_name()?;
    if inspected.name.trim_start_matches('/') != expected_name {
        return Err(AppError::NotAuthorized(
            "container name does not match the persisted execution identity".into(),
        ));
    }
    if inspected.id.len() < 12
        || inspected.id.len() > 128
        || !inspected
            .id
            .chars()
            .all(|character| character.is_ascii_hexdigit())
    {
        return Err(AppError::NotAuthorized(
            "container runtime returned an invalid immutable object ID".into(),
        ));
    }
    for (key, expected) in request.expected_labels() {
        if inspected.config.labels.get(key) != Some(&expected) {
            return Err(AppError::NotAuthorized(format!(
                "container ownership label {key} does not match the persisted execution"
            )));
        }
    }
    if request.launcher_plan_sha256.is_none()
        && inspected
            .config
            .labels
            .contains_key(CONTAINER_NAABU_LAUNCHER_PLAN_LABEL_KEY)
    {
        return Err(AppError::NotAuthorized(format!(
            "container ownership label {CONTAINER_NAABU_LAUNCHER_PLAN_LABEL_KEY} was not present in the persisted execution"
        )));
    }
    if request.zap_plan_sha256.is_none()
        && inspected
            .config
            .labels
            .contains_key(CONTAINER_ZAP_PLAN_LABEL_KEY)
    {
        return Err(AppError::NotAuthorized(format!(
            "container ownership label {CONTAINER_ZAP_PLAN_LABEL_KEY} was not present in the persisted execution"
        )));
    }
    let image_matches = inspected
        .config
        .image
        .as_deref()
        .is_some_and(|reference| image_reference_matches_pinned(reference, &request.image))
        || inspected
            .image_name
            .as_deref()
            .is_some_and(|reference| image_reference_matches_pinned(reference, &request.image));
    if !image_matches {
        return Err(AppError::NotAuthorized(
            "container image does not match the persisted pinned image".into(),
        ));
    }
    Ok(inspected.id.clone())
}

#[derive(Debug, Deserialize)]
struct DockerRuntimeNetworkInspect {
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Id")]
    id: String,
    #[serde(rename = "Driver")]
    driver: String,
    #[serde(rename = "Internal")]
    internal: bool,
    #[serde(rename = "Labels")]
    labels: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
struct PodmanRuntimeNetworkInspect {
    name: String,
    id: String,
    driver: String,
    internal: bool,
    labels: BTreeMap<String, String>,
}

fn prove_managed_internal_network(
    provider: RuntimeProvider,
    document: &[u8],
    expected_name: &str,
    expected_policy_id: &str,
) -> AppResult<()> {
    debug_assert!(provider == RuntimeProvider::Docker || provider.uses_podman_dialect());
    if document.is_empty() || document.len() > MAX_NETWORK_INSPECT_BYTES {
        return Err(AppError::Runtime(
            "container network inspection was empty or oversized".into(),
        ));
    }

    let (name, id, driver, internal, labels) = match provider {
        RuntimeProvider::Docker => {
            let mut networks: Vec<DockerRuntimeNetworkInspect> = serde_json::from_slice(document)
                .map_err(|_| {
                AppError::Runtime("Docker network inspection was malformed".into())
            })?;
            if networks.len() != 1 {
                return Err(AppError::Runtime(
                    "Docker must return exactly one inspected network".into(),
                ));
            }
            let network = networks.pop().expect("one Docker network");
            (
                network.name,
                network.id,
                network.driver,
                network.internal,
                network.labels,
            )
        }
        RuntimeProvider::ManagedLocal | RuntimeProvider::Podman => {
            let mut networks: Vec<PodmanRuntimeNetworkInspect> = serde_json::from_slice(document)
                .map_err(|_| {
                AppError::Runtime("Podman network inspection was malformed".into())
            })?;
            if networks.len() != 1 {
                return Err(AppError::Runtime(
                    "Podman must return exactly one inspected network".into(),
                ));
            }
            let network = networks.pop().expect("one Podman network");
            (
                network.name,
                network.id,
                network.driver,
                network.internal,
                network.labels,
            )
        }
    };

    let expected_labels = BTreeMap::from([
        (MANAGED_NETWORK_LABEL_KEY.to_owned(), "true".to_owned()),
        (
            NETWORK_POLICY_LABEL_KEY.to_owned(),
            expected_policy_id.to_owned(),
        ),
    ]);
    if name != expected_name
        || id.trim().is_empty()
        || id.len() > 256
        || id.contains(['\n', '\r', '\0'])
        || driver != "bridge"
        || !internal
        || labels != expected_labels
    {
        return Err(AppError::NotAuthorized(format!(
            "container runtime did not prove managed network {expected_name} is the exact internal bridge for policy {expected_policy_id}"
        )));
    }
    Ok(())
}

// Only the Unix inherited-pipe test constructs a relative deadline; scoping this
// helper to that exact configuration keeps `-D warnings` clean on Windows.
#[cfg(all(test, unix))]
fn bounded_command_output(
    command: &mut Command,
    maximum: u64,
    timeout: StdDuration,
) -> io::Result<std::process::Output> {
    let deadline = std::time::Instant::now()
        .checked_add(timeout)
        .ok_or_else(runtime_command_deadline_error)?;
    bounded_command_output_until(command, maximum, deadline)
}

fn runtime_command_deadline_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::TimedOut,
        "runtime command exceeded its deadline",
    )
}

fn bounded_command_output_until(
    command: &mut Command,
    maximum: u64,
    deadline: std::time::Instant,
) -> io::Result<std::process::Output> {
    command.stdin(Stdio::null());
    bounded_command_output_with_configured_stdin_until(command, maximum, deadline)
}

fn bounded_command_output_with_configured_stdin_until(
    command: &mut Command,
    maximum: u64,
    deadline: std::time::Instant,
) -> io::Result<std::process::Output> {
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    if std::time::Instant::now() >= deadline {
        return Err(runtime_command_deadline_error());
    }
    let mut process_tree = CommandProcessTree::prepare(command)?;
    if std::time::Instant::now() >= deadline {
        return Err(runtime_command_deadline_error());
    }
    let mut child = command.spawn()?;
    if let Err(error) = process_tree.attach(&child) {
        let _ = child.kill();
        let _ = child.wait();
        return Err(error);
    }
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("runtime stdout pipe was unavailable"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| io::Error::other("runtime stderr pipe was unavailable"))?;
    let captured = Arc::new(AtomicU64::new(0));
    let oversized = Arc::new(AtomicBool::new(false));
    let stdout_capture = spawn_memory_capture(stdout, captured.clone(), oversized.clone(), maximum);
    let stderr_capture = spawn_memory_capture(stderr, captured, oversized.clone(), maximum);
    let process_result = loop {
        if let Some(status) = child.try_wait()? {
            break Ok(status);
        }
        if oversized.load(Ordering::Acquire) {
            process_tree.terminate_and_wait(&mut child);
            break Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "runtime command output exceeded its aggregate limit",
            ));
        }
        if std::time::Instant::now() >= deadline {
            process_tree.terminate_and_wait(&mut child);
            break Err(runtime_command_deadline_error());
        }
        thread::sleep(StdDuration::from_millis(25));
    };
    let drain_deadline = if process_result.is_err() {
        std::time::Instant::now() + RUNTIME_PIPE_DRAIN_TIMEOUT
    } else {
        deadline
    };
    let stdout = stdout_capture.finish_by(drain_deadline);
    let stderr = stderr_capture.finish_by(drain_deadline);
    if stdout
        .as_ref()
        .err()
        .is_some_and(|error| error.kind() == io::ErrorKind::TimedOut)
        || stderr
            .as_ref()
            .err()
            .is_some_and(|error| error.kind() == io::ErrorKind::TimedOut)
    {
        process_tree.terminate_and_wait(&mut child);
    }
    let status = process_result?;
    let stdout = stdout?;
    let stderr = stderr?;
    if oversized.load(Ordering::Acquire) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "runtime command output exceeded its aggregate limit",
        ));
    }
    Ok(std::process::Output {
        status,
        stdout,
        stderr,
    })
}

struct MemoryCapture {
    result: std::sync::mpsc::Receiver<io::Result<Vec<u8>>>,
    worker: Option<thread::JoinHandle<()>>,
}

impl MemoryCapture {
    fn finish_by(mut self, deadline: std::time::Instant) -> io::Result<Vec<u8>> {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        let result = match self.result.recv_timeout(remaining) {
            Ok(result) => result,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "runtime output pipes did not close before the bounded drain deadline",
            )),
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                Err(io::Error::other("runtime output capture thread failed"))
            }
        };
        if result.is_ok()
            && let Some(worker) = self.worker.take()
        {
            worker
                .join()
                .map_err(|_| io::Error::other("runtime output capture thread failed"))?;
        }
        result
    }
}

fn spawn_memory_capture<R>(
    mut reader: R,
    captured: Arc<AtomicU64>,
    oversized: Arc<AtomicBool>,
    maximum: u64,
) -> MemoryCapture
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
    MemoryCapture {
        result,
        worker: Some(worker),
    }
}

struct CommandProcessTree {
    #[cfg(unix)]
    process_group: Option<i32>,
    #[cfg(windows)]
    job: windows_sys::Win32::Foundation::HANDLE,
}

impl CommandProcessTree {
    fn prepare(command: &mut Command) -> io::Result<Self> {
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            command.process_group(0);
            Ok(Self {
                process_group: None,
            })
        }
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            use windows_sys::Win32::System::JobObjects::{
                CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
                JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
                SetInformationJobObject,
            };
            use windows_sys::Win32::System::Threading::CREATE_NO_WINDOW;

            // Runtime commands are background implementation details of the
            // desktop app. Without this flag, Windows can open its configured
            // terminal host for Podman and steal focus for every scanner.
            command.creation_flags(CREATE_NO_WINDOW);
            let job = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
            if job.is_null() {
                return Err(io::Error::last_os_error());
            }
            let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
            limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            let configured = unsafe {
                SetInformationJobObject(
                    job,
                    JobObjectExtendedLimitInformation,
                    std::ptr::addr_of!(limits).cast(),
                    std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                )
            };
            if configured == 0 {
                unsafe {
                    windows_sys::Win32::Foundation::CloseHandle(job);
                }
                return Err(io::Error::last_os_error());
            }
            Ok(Self { job })
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = command;
            Ok(Self {})
        }
    }

    fn attach(&mut self, child: &Child) -> io::Result<()> {
        #[cfg(unix)]
        {
            self.process_group = Some(i32::try_from(child.id()).map_err(|_| {
                io::Error::other("runtime child process ID exceeded the platform range")
            })?);
            Ok(())
        }
        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawHandle;
            use windows_sys::Win32::System::JobObjects::AssignProcessToJobObject;
            let assigned =
                unsafe { AssignProcessToJobObject(self.job, child.as_raw_handle().cast()) };
            if assigned == 0 {
                Err(io::Error::last_os_error())
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

    fn terminate_and_wait(&self, child: &mut Child) {
        #[cfg(unix)]
        if let Some(process_group) = self.process_group {
            unsafe {
                libc::kill(-process_group, libc::SIGKILL);
            }
        }
        #[cfg(windows)]
        unsafe {
            windows_sys::Win32::System::JobObjects::TerminateJobObject(self.job, 1);
        }
        let _ = child.kill();
        let _ = child.wait();
    }
}

#[cfg(windows)]
impl Drop for CommandProcessTree {
    fn drop(&mut self) {
        unsafe {
            windows_sys::Win32::Foundation::CloseHandle(self.job);
        }
    }
}

struct ContainerWaitContext<'a> {
    plan: &'a ContainerRunPlan,
    execution_started: std::time::Instant,
    execution_timeout: StdDuration,
    cancellation: &'a CancellationToken,
    budget: &'a OutputBudget,
    container_id_file: &'a ContainerIdFileGuard,
}

#[derive(Clone)]
struct OutputBudget {
    maximum: u64,
    stream_bytes: Arc<AtomicU64>,
    oversized: Arc<AtomicBool>,
    capture_failed: Arc<AtomicBool>,
}

impl OutputBudget {
    fn new(maximum: u64) -> Self {
        Self {
            maximum,
            stream_bytes: Arc::new(AtomicU64::new(0)),
            oversized: Arc::new(AtomicBool::new(false)),
            capture_failed: Arc::new(AtomicBool::new(false)),
        }
    }

    fn check(&self, output_root: &Path) -> AppResult<()> {
        if self.capture_failed.load(Ordering::Acquire) {
            return Err(AppError::Runtime(
                "engine output capture failed; scan coverage is incomplete".into(),
            ));
        }
        if self.oversized.load(Ordering::Acquire) {
            return Err(output_limit_error(self.maximum));
        }
        let mut entries = 0_usize;
        let files = measure_output_tree(output_root, 0, &mut entries, self.maximum)?;
        let streams = self.stream_bytes.load(Ordering::Acquire);
        if files
            .checked_add(streams)
            .is_none_or(|total| total > self.maximum)
        {
            self.oversized.store(true, Ordering::Release);
            return Err(output_limit_error(self.maximum));
        }
        Ok(())
    }
}

struct OutputCaptureWorkers {
    stdout: FileCapture,
    stderr: FileCapture,
}

impl OutputCaptureWorkers {
    fn start(
        child: &mut Child,
        stdout_file: CaptureWriter,
        stderr_file: CaptureWriter,
        budget: &OutputBudget,
    ) -> AppResult<Self> {
        let stdout_pipe = child
            .stdout
            .take()
            .ok_or_else(|| AppError::Runtime("container stdout pipe was unavailable".into()))?;
        let stderr_pipe = child
            .stderr
            .take()
            .ok_or_else(|| AppError::Runtime("container stderr pipe was unavailable".into()))?;
        Ok(Self {
            stdout: spawn_file_capture(stdout_pipe, stdout_file, budget.clone()),
            stderr: spawn_file_capture(stderr_pipe, stderr_file, budget.clone()),
        })
    }

    fn finish_by(&mut self, deadline: std::time::Instant) -> io::Result<()> {
        // Wait for both readers against one shared deadline. If a descendant
        // inherited a pipe, callers can terminate the process tree and return
        // without an unbounded JoinHandle wait.
        let stdout = self.stdout.finish_by(deadline);
        let stderr = self.stderr.finish_by(deadline);
        stdout?;
        stderr?;
        Ok(())
    }
}

struct FileCapture {
    result: std::sync::mpsc::Receiver<io::Result<()>>,
    worker: Option<thread::JoinHandle<()>>,
    completion: Option<Result<(), StoredCaptureError>>,
}

#[derive(Clone)]
struct StoredCaptureError {
    kind: io::ErrorKind,
    message: String,
}

impl StoredCaptureError {
    fn from_io(error: io::Error) -> Self {
        Self {
            kind: error.kind(),
            message: error.to_string(),
        }
    }

    fn to_io(&self) -> io::Error {
        io::Error::new(self.kind, self.message.clone())
    }
}

impl FileCapture {
    fn finish_by(&mut self, deadline: std::time::Instant) -> io::Result<()> {
        if let Some(completion) = self.completion.as_ref() {
            return completion
                .as_ref()
                .map(|_| ())
                .map_err(StoredCaptureError::to_io);
        }
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        let result = match self.result.recv_timeout(remaining) {
            Ok(result) => result,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "container output pipes did not close before the bounded drain deadline",
                ));
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                Err(io::Error::other("container output capture thread failed"))
            }
        };
        let worker_failed = self
            .worker
            .take()
            .is_some_and(|worker| worker.join().is_err());
        let result = if worker_failed {
            Err(io::Error::other("container output capture thread failed"))
        } else {
            result
        };
        self.completion = Some(result.map_err(StoredCaptureError::from_io));
        match self.completion.as_ref().expect("capture completion stored") {
            Ok(()) => Ok(()),
            Err(error) => Err(error.to_io()),
        }
    }
}

fn spawn_file_capture<R>(
    mut reader: R,
    mut file: CaptureWriter,
    budget: OutputBudget,
) -> FileCapture
where
    R: Read + Send + 'static,
{
    let (sender, result) = std::sync::mpsc::sync_channel(1);
    let worker = thread::spawn(move || {
        let result = (|| {
            let mut buffer = [0_u8; 16 * 1024];
            loop {
                let read = reader.read(&mut buffer)?;
                if read == 0 {
                    break;
                }
                let previous = budget.stream_bytes.fetch_add(read as u64, Ordering::AcqRel);
                let remaining = budget.maximum.saturating_sub(previous) as usize;
                file.write_all(&buffer[..read.min(remaining)])?;
                if read > remaining {
                    budget.oversized.store(true, Ordering::Release);
                }
            }
            file.flush()?;
            file.sync_all()?;
            Ok(())
        })();
        if result.is_err() {
            budget.capture_failed.store(true, Ordering::Release);
        }
        let _ = sender.send(result);
    });
    FileCapture {
        result,
        worker: Some(worker),
        completion: None,
    }
}

fn measure_output_tree(
    directory: &Path,
    depth: usize,
    entries: &mut usize,
    maximum: u64,
) -> AppResult<u64> {
    if depth > MAX_OUTPUT_DEPTH {
        return Err(AppError::Runtime(
            "engine output exceeded the directory-depth limit; scan coverage is incomplete".into(),
        ));
    }
    let metadata = fs::symlink_metadata(directory)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(AppError::NotAuthorized(
            "engine output directory changed type; scan coverage is incomplete".into(),
        ));
    }
    let mut total = 0_u64;
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        *entries = entries
            .checked_add(1)
            .ok_or_else(|| AppError::Runtime("engine output entry count overflowed".into()))?;
        if *entries > MAX_OUTPUT_ENTRIES {
            return Err(AppError::Runtime(
                "engine output exceeded the file-count limit; scan coverage is incomplete".into(),
            ));
        }
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() {
            return Err(AppError::NotAuthorized(
                "engine output contains a symlink; scan coverage is incomplete".into(),
            ));
        }
        let length = if metadata.is_dir() {
            measure_output_tree(&path, depth + 1, entries, maximum)?
        } else if metadata.is_file() {
            metadata.len()
        } else {
            return Err(AppError::NotAuthorized(
                "engine output contains a non-regular filesystem object; scan coverage is incomplete"
                    .into(),
            ));
        };
        total = total
            .checked_add(length)
            .ok_or_else(|| output_limit_error(maximum))?;
        if total > maximum {
            return Err(output_limit_error(maximum));
        }
    }
    Ok(total)
}

fn output_limit_error(maximum: u64) -> AppError {
    AppError::Runtime(format!(
        "engine output exceeded the {maximum}-byte aggregate stdout/stderr/artifact limit; scan coverage is incomplete"
    ))
}

impl ProcessContainerRuntime {
    pub fn new(provider: RuntimeProvider, binary: impl Into<PathBuf>) -> AppResult<Self> {
        Ok(Self {
            context: RuntimeCommandContext::compatibility(provider, binary.into())?,
            release_approved_local_image_directory:
                release_approved_local_image_directory_from_environment(),
            preflight_cache: Arc::default(),
            #[cfg(test)]
            test_execution_timeout: None,
            #[cfg(test)]
            test_capture_drain_timeout: None,
        })
    }

    pub fn from_managed(command: crate::managed_runtime::ManagedRuntimeCommand) -> AppResult<Self> {
        Ok(Self {
            context: RuntimeCommandContext::managed(command)?,
            release_approved_local_image_directory:
                release_approved_local_image_directory_from_environment(),
            preflight_cache: Arc::default(),
            #[cfg(test)]
            test_execution_timeout: None,
            #[cfg(test)]
            test_capture_drain_timeout: None,
        })
    }

    pub fn from_command_context(context: RuntimeCommandContext) -> Self {
        Self {
            context,
            release_approved_local_image_directory:
                release_approved_local_image_directory_from_environment(),
            preflight_cache: Arc::default(),
            #[cfg(test)]
            test_execution_timeout: None,
            #[cfg(test)]
            test_capture_drain_timeout: None,
        }
    }

    pub fn with_release_approved_local_image_directory(
        mut self,
        directory: Option<PathBuf>,
    ) -> Self {
        self.release_approved_local_image_directory = directory;
        self
    }

    #[cfg(all(test, unix))]
    fn with_test_execution_timeout(mut self, timeout: StdDuration) -> Self {
        self.test_execution_timeout = Some(timeout);
        self
    }

    #[cfg(all(test, unix))]
    fn with_test_capture_drain_timeout(mut self, timeout: StdDuration) -> Self {
        self.test_capture_drain_timeout = Some(timeout);
        self
    }

    pub fn command_context(&self) -> RuntimeCommandContext {
        self.context.clone()
    }

    pub fn provider(&self) -> RuntimeProvider {
        self.context.provider
    }

    fn inspect_preflight(&self) -> AppResult<RuntimePreflight> {
        let version_operation = DirectRuntimeOperation::RuntimeVersionPreflight;
        let version = self.direct_output(
            version_operation,
            ["version", "--format", "{{.Server.Version}}"],
        )?;
        if !version.status.success() {
            return Err(process_failure(version_operation.label(), &version));
        }
        let server_version = String::from_utf8_lossy(&version.stdout).trim().to_owned();
        if server_version.is_empty() {
            return Err(AppError::Runtime(
                "container runtime returned an empty server version".into(),
            ));
        }

        let security_operation = DirectRuntimeOperation::RuntimeSecurityPreflight;
        let info = self.direct_output(
            security_operation,
            [
                "info",
                "--format",
                runtime_security_info_template(self.context.provider),
            ],
        )?;
        if !info.status.success() {
            return Err(process_failure(security_operation.label(), &info));
        }
        let security_options =
            validate_runtime_security_options(self.context.provider, &info.stdout)?;
        Ok(RuntimePreflight {
            provider: self.context.provider,
            server_version,
            security_options,
            command_provenance: self.context.provenance.clone(),
        })
    }

    fn inspect_execution_preflight(&self) -> AppResult<RuntimePreflight> {
        let operation = DirectRuntimeOperation::RuntimeExecutionPreflight;
        let info = self.direct_output(
            operation,
            [
                "info",
                "--format",
                runtime_execution_info_template(self.context.provider),
            ],
        )?;
        if !info.status.success() {
            return Err(process_failure(operation.label(), &info));
        }
        runtime_preflight_from_execution_info(
            self.context.provider,
            self.context.provenance.clone(),
            &info.stdout,
        )
    }

    /// Removes a crash-left container only after proving its immutable object
    /// ID, complete execution ownership labels, deterministic name, and pinned
    /// image. The final removal targets the inspected object ID so a name swap
    /// between inspection and deletion cannot redirect cleanup.
    pub fn cleanup_owned_container(
        &self,
        request: &OwnedContainerCleanupRequest,
    ) -> AppResult<CleanupOutcome> {
        <Self as ContainerRuntime>::cleanup(self, request, None)
    }

    pub fn detect() -> AppResult<Self> {
        let mut errors = Vec::new();
        for provider in [RuntimeProvider::Docker, RuntimeProvider::Podman] {
            let runtime = Self::new(provider, provider.program_name())?;
            match runtime.preflight() {
                Ok(_) => return Ok(runtime),
                Err(error) => errors.push(format!("{}: {error}", provider.program_name())),
            }
        }
        Err(AppError::Runtime(format!(
            "no usable Docker or Podman service detected ({})",
            errors.join("; ")
        )))
    }

    fn direct_output<I, S>(
        &self,
        operation: DirectRuntimeOperation,
        args: I,
    ) -> AppResult<std::process::Output>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        self.direct_output_with_timeout(operation, args, operation.timeout())
    }

    fn direct_output_with_timeout<I, S>(
        &self,
        operation: DirectRuntimeOperation,
        args: I,
        timeout: StdDuration,
    ) -> AppResult<std::process::Output>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let args = args
            .into_iter()
            .map(|value| value.as_ref().to_os_string())
            .collect::<Vec<_>>();
        self.context
            .output(&args, MAX_RUNTIME_COMMAND_OUTPUT_BYTES, timeout)
            .map_err(|error| {
                AppError::Runtime(format!(
                    "{} via {} could not be executed directly: {error}",
                    operation.label(),
                    self.context.binary.display()
                ))
            })
    }

    fn direct_output_with_stdin(
        &self,
        operation: DirectRuntimeOperation,
        args: impl IntoIterator<Item = impl AsRef<OsStr>>,
        stdin: File,
    ) -> AppResult<std::process::Output> {
        let args = args
            .into_iter()
            .map(|value| value.as_ref().to_os_string())
            .collect::<Vec<_>>();
        self.context
            .output_with_stdin(
                &args,
                stdin,
                MAX_RUNTIME_COMMAND_OUTPUT_BYTES,
                operation.timeout(),
            )
            .map_err(|error| {
                AppError::Runtime(format!(
                    "{} via {} could not be executed directly: {error}",
                    operation.label(),
                    self.context.binary.display()
                ))
            })
    }

    fn container_control(&self, operation: &'static str, immutable_id: &str) -> AppResult<()> {
        let direct_operation = match operation {
            "pause" => DirectRuntimeOperation::ContainerPause,
            "unpause" => DirectRuntimeOperation::ContainerUnpause,
            _ => unreachable!("container control operation is fixed by the caller"),
        };
        let output = self.direct_output(direct_operation, [operation, immutable_id])?;
        if output.status.success() {
            Ok(())
        } else {
            Err(process_failure(direct_operation.label(), &output))
        }
    }

    fn stop_container(&self, immutable_id: &str) -> AppResult<()> {
        let operation = DirectRuntimeOperation::ContainerStop;
        let output = self.direct_output(operation, ["stop", "--time", "5", immutable_id])?;
        if output.status.success() {
            Ok(())
        } else {
            Err(process_failure(operation.label(), &output))
        }
    }

    fn refresh_active_container(
        &self,
        plan: &ContainerRunPlan,
        container_id_file: &ContainerIdFileGuard,
        created_container: &mut Option<CreatedContainer>,
        active_container: &mut Option<CreatedContainer>,
    ) -> AppResult<()> {
        if created_container.is_none() {
            *created_container = container_id_file.created_container_if_ready()?;
        }
        let Some(created) = created_container.as_ref() else {
            return Ok(());
        };
        if active_container.is_some() {
            return Ok(());
        }
        let operation = DirectRuntimeOperation::CreatedContainerOwnershipInspection;
        let inspection =
            self.direct_output(operation, ["container", "inspect", created.immutable_id()])?;
        if !inspection.status.success() {
            if runtime_object_is_absent(&inspection.stderr) {
                return Ok(());
            }
            return Err(process_failure(operation.label(), &inspection));
        }
        let inspected_id = prove_owned_container(&inspection.stdout, plan.ownership())?;
        if !inspected_id.eq_ignore_ascii_case(created.immutable_id()) {
            return Err(AppError::NotAuthorized(
                "active container ID does not match this invocation's created-object tracking"
                    .into(),
            ));
        }
        *active_container = Some(created.clone());
        Ok(())
    }

    fn wait_for_container(
        &self,
        child: &mut Child,
        context: ContainerWaitContext<'_>,
        created_container: &mut Option<CreatedContainer>,
    ) -> AppResult<RuntimeOutcome> {
        let ContainerWaitContext {
            plan,
            execution_started,
            execution_timeout,
            cancellation,
            budget,
            container_id_file,
        } = context;
        let mut execution_budget =
            ActiveExecutionBudget::started(execution_timeout, execution_started);
        let mut active_container = None;
        loop {
            self.refresh_active_container(
                plan,
                container_id_file,
                created_container,
                &mut active_container,
            )?;
            if let Err(output_error) = budget.check(plan.output()) {
                let stop_error = active_container
                    .as_ref()
                    .and_then(|container| self.stop_container(container.immutable_id()).err());
                let _ = child.kill();
                let _ = child.wait();
                return Err(AppError::Runtime(match stop_error {
                    Some(stop_error) => format!(
                        "{output_error}; fail-closed container stop also failed: {stop_error}"
                    ),
                    None => output_error.to_string(),
                }));
            }
            if cancellation.is_cancelled() {
                if execution_budget.is_paused() {
                    let active = active_container.as_ref().ok_or_else(|| {
                        AppError::Internal(
                            "runtime pause acknowledgement lost its created container identity"
                                .into(),
                        )
                    })?;
                    if let Err(unpause_error) =
                        self.container_control("unpause", active.immutable_id())
                    {
                        let stop_error = self.stop_container(active.immutable_id()).err();
                        let _ = child.kill();
                        let _ = child.wait();
                        return Err(AppError::Runtime(match stop_error {
                            Some(stop_error) => format!(
                                "{unpause_error}; fail-closed container stop also failed: {stop_error}"
                            ),
                            None => format!("{unpause_error}; container was stopped fail-closed"),
                        }));
                    }
                    execution_budget.acknowledge_resumed_at(std::time::Instant::now());
                    cancellation.acknowledge_resumed();
                }
                let stop_result = active_container
                    .as_ref()
                    .map(|container| self.stop_container(container.immutable_id()))
                    .transpose();
                let _ = child.kill();
                let _ = child.wait();
                stop_result?;
                return Ok(RuntimeOutcome {
                    exit_code: None,
                    cancelled: true,
                });
            }
            if let Some(status) = child.try_wait().map_err(|error| {
                AppError::Runtime(format!("container process could not be observed: {error}"))
            })? {
                cancellation.acknowledge_resumed();
                return Ok(RuntimeOutcome {
                    exit_code: status.code(),
                    cancelled: false,
                });
            }

            if execution_budget.expired_at(std::time::Instant::now()) {
                if let Some(active) = active_container.as_ref() {
                    // This ID was read from the invocation-only cidfile and
                    // then matched against the complete ownership proof. A
                    // deterministic container name is never enough to stop.
                    if execution_budget.is_paused() {
                        let _ = self.container_control("unpause", active.immutable_id());
                    }
                    let _ = self.stop_container(active.immutable_id());
                }
                let _ = child.kill();
                let _ = child.wait();
                cancellation.acknowledge_resumed();
                return Err(AppError::Runtime(CONTAINER_EXECUTION_TIMEOUT_ERROR.into()));
            }

            let pause_requested = cancellation.is_pause_requested();
            if pause_requested && !execution_budget.is_paused() {
                if let Some(active) = active_container.as_ref() {
                    if let Err(pause_error) = self.container_control("pause", active.immutable_id())
                    {
                        let stop_error = self.stop_container(active.immutable_id()).err();
                        let _ = child.kill();
                        let _ = child.wait();
                        return Err(AppError::Runtime(match stop_error {
                            Some(stop_error) => format!(
                                "{pause_error}; fail-closed container stop also failed: {stop_error}"
                            ),
                            None => format!("{pause_error}; container was stopped fail-closed"),
                        }));
                    }
                    execution_budget.acknowledge_paused_at(std::time::Instant::now());
                    cancellation.acknowledge_paused();
                }
            } else if !pause_requested && execution_budget.is_paused() {
                let active = active_container.as_ref().ok_or_else(|| {
                    AppError::Internal(
                        "runtime pause acknowledgement lost its created container identity".into(),
                    )
                })?;
                if let Err(unpause_error) = self.container_control("unpause", active.immutable_id())
                {
                    let stop_error = self.stop_container(active.immutable_id()).err();
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(AppError::Runtime(match stop_error {
                        Some(stop_error) => format!(
                            "{unpause_error}; fail-closed container stop also failed: {stop_error}"
                        ),
                        None => format!("{unpause_error}; container was stopped fail-closed"),
                    }));
                }
                execution_budget.acknowledge_resumed_at(std::time::Instant::now());
                cancellation.acknowledge_resumed();
            }
            thread::sleep(StdDuration::from_millis(25));
        }
    }
}

fn runtime_object_is_absent(stderr: &[u8]) -> bool {
    let stderr = String::from_utf8_lossy(stderr).to_ascii_lowercase();
    stderr.contains("no such container")
        || stderr.contains("no container with name")
        || stderr.contains("no such object")
}

impl ContainerRuntime for ProcessContainerRuntime {
    fn preflight(&self) -> AppResult<RuntimePreflight> {
        self.preflight_cache
            .get_or_try_init(|| self.inspect_preflight())
    }

    fn execution_preflight(&self) -> AppResult<RuntimePreflight> {
        self.preflight_cache
            .refresh(|| self.inspect_execution_preflight())
    }

    fn verify_network(&self, policy: &NetworkPolicy) -> AppResult<()> {
        let NetworkPolicy::Managed {
            network_name,
            policy_id,
            ..
        } = policy
        else {
            return Ok(());
        };
        policy.validate()?;
        let operation = DirectRuntimeOperation::ManagedNetworkPreflight;
        let output = self.direct_output(operation, ["network", "inspect", network_name])?;
        if !output.status.success() {
            return Err(process_failure(operation.label(), &output));
        }
        prove_managed_internal_network(
            self.context.provider,
            &output.stdout,
            network_name,
            policy_id,
        )
    }

    fn pull(&self, image: &PinnedImage) -> AppResult<()> {
        let reference = image.reference();
        // Local load / pin path: if the exact digest is already in the local
        // store, do not call the registry. Unpublished GHCR pins otherwise fail
        // `docker pull` even when `docker image inspect` succeeds.
        let inspect = self.direct_output(
            DirectRuntimeOperation::LocalPinnedImageInspection,
            ["image", "inspect", reference.as_str()],
        )?;
        if inspect.status.success() {
            return Ok(());
        }
        if let Some(directory) = self.release_approved_local_image_directory.as_deref()
            && let Some(archive) = verified_release_approved_oci_archive(directory, image)?
        {
            let operation = DirectRuntimeOperation::LocalPinnedImageLoad;
            let output = self.direct_output_with_stdin(operation, ["load"], archive)?;
            if !output.status.success() {
                return Err(process_failure(operation.label(), &output));
            }
            let inspect = self.direct_output(
                DirectRuntimeOperation::LocalPinnedImageInspection,
                ["image", "inspect", reference.as_str()],
            )?;
            if inspect.status.success() {
                return Ok(());
            }
            return Err(AppError::Runtime(
                "local pinned image load completed without making the exact pinned digest available"
                    .into(),
            ));
        }
        let operation = DirectRuntimeOperation::PinnedImagePull;
        let output = self.direct_output(operation, ["pull", reference.as_str()])?;
        if !output.status.success() {
            return Err(process_failure(operation.label(), &output));
        }
        Ok(())
    }

    fn run(
        &self,
        plan: &ContainerRunPlan,
        credentials: &ScannerCredentialSet,
        cancellation: &CancellationToken,
        capture: &CapturePaths,
        created_container: &mut Option<CreatedContainer>,
        creation_may_be_untracked: &mut bool,
    ) -> AppResult<RuntimeOutcome> {
        *created_container = None;
        *creation_may_be_untracked = false;
        validate_run_plan_integrity(plan)?;
        credentials.validate_fresh()?;
        if cancellation.is_cancelled() {
            return Ok(RuntimeOutcome {
                exit_code: None,
                cancelled: true,
            });
        }
        // Keep the proof adjacent to process creation as well as the
        // orchestrator preflight. This prevents direct runtime callers, or a
        // network replaced while a pinned image is pulled, from bypassing the
        // internal-network invariant.
        self.verify_network(plan.network_policy())?;
        let mut secret = SecretFileGuard::create(plan.credential_control_dir(), credentials)?;
        let container_id_file = ContainerIdFileGuard::prepare(plan.credential_control_dir())?;
        let runtime_args = runtime_args_with_secret(
            plan,
            self.context.provider,
            secret.as_ref(),
            Some(&container_id_file),
        )?;
        let execution = (|| -> AppResult<RuntimeOutcome> {
            // Capture paths are verified and opened by ArtifactStore. Clone
            // those exact handles before process creation; never reopen or
            // truncate a path that could have been replaced with a Windows
            // reparse point (or a Unix symlink) after preparation.
            let (stdout_file, stderr_file) = capture.clone_empty_writers()?;
            let execution_timeout = StdDuration::from_secs(plan.execution_timeout_seconds());
            #[cfg(test)]
            let execution_timeout = self.test_execution_timeout.unwrap_or(execution_timeout);
            let capture_drain_timeout = CONTAINER_CAPTURE_DRAIN_TIMEOUT;
            #[cfg(test)]
            let capture_drain_timeout = self
                .test_capture_drain_timeout
                .unwrap_or(capture_drain_timeout);
            // A deliberately short test deadline may be used to prove that an
            // inherited pipe is detected. Do not reuse that detection deadline
            // after terminating the process tree: the capture workers still
            // need a bounded scheduling window to observe EOF, sync their
            // files, and drop the tracked writers before this call returns.
            let post_termination_capture_drain_timeout =
                capture_drain_timeout.max(RUNTIME_PIPE_DRAIN_TIMEOUT);
            let execution_started = std::time::Instant::now();
            let execution_deadline = execution_started
                .checked_add(execution_timeout)
                .ok_or_else(|| AppError::Runtime(CONTAINER_EXECUTION_TIMEOUT_ERROR.into()))?;
            #[cfg(windows)]
            let _execution_guard = match self
                .context
                .acquire_windows_execution_guard(execution_deadline, &|| {
                    cancellation.is_cancelled()
                }) {
                Ok(guard) => guard,
                Err(error)
                    if error.kind() == io::ErrorKind::Interrupted
                        && cancellation.is_cancelled() =>
                {
                    return Ok(RuntimeOutcome {
                        exit_code: None,
                        cancelled: true,
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::TimedOut => {
                    return Err(AppError::Runtime(CONTAINER_EXECUTION_TIMEOUT_ERROR.into()));
                }
                Err(error) => {
                    return Err(AppError::NotAuthorized(format!(
                        "managed runtime launch identity could not be pinned: {error}"
                    )));
                }
            };
            if cancellation.is_cancelled() {
                return Ok(RuntimeOutcome {
                    exit_code: None,
                    cancelled: true,
                });
            }
            if std::time::Instant::now() >= execution_deadline {
                return Err(AppError::Runtime(CONTAINER_EXECUTION_TIMEOUT_ERROR.into()));
            }
            let mut command = Command::new(&self.context.binary);
            command.args(&runtime_args);
            self.context.apply(&mut command);
            command
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            let mut process_tree = CommandProcessTree::prepare(&mut command).map_err(|error| {
                AppError::Runtime(format!(
                    "container process tree could not be prepared: {error}"
                ))
            })?;
            if cancellation.is_cancelled() {
                return Ok(RuntimeOutcome {
                    exit_code: None,
                    cancelled: true,
                });
            }
            if std::time::Instant::now() >= execution_deadline {
                return Err(AppError::Runtime(CONTAINER_EXECUTION_TIMEOUT_ERROR.into()));
            }
            let mut child = command.spawn().map_err(|error| {
                AppError::Runtime(format!("container run could not start: {error}"))
            })?;
            // From this point until an invocation-only cidfile is verified,
            // the runtime process may have created the planned object without
            // returning its immutable ID. The caller must reconcile by the
            // complete ownership labels and must not treat a missing ID as
            // proof that no container exists.
            *creation_may_be_untracked = true;
            if let Err(error) = process_tree.attach(&child) {
                process_tree.terminate_and_wait(&mut child);
                return Err(AppError::Runtime(format!(
                    "container process tree could not be attached: {error}"
                )));
            }
            let budget = OutputBudget::new(plan.output_bytes());
            let mut capture_workers =
                match OutputCaptureWorkers::start(&mut child, stdout_file, stderr_file, &budget) {
                    Ok(workers) => workers,
                    Err(error) => {
                        process_tree.terminate_and_wait(&mut child);
                        return Err(error);
                    }
                };
            let wait_context = ContainerWaitContext {
                plan,
                execution_started,
                execution_timeout,
                cancellation,
                budget: &budget,
                container_id_file: &container_id_file,
            };
            let outcome = self.wait_for_container(&mut child, wait_context, created_container);
            if outcome.as_ref().is_err() || outcome.as_ref().is_ok_and(|outcome| outcome.cancelled)
            {
                process_tree.terminate_and_wait(&mut child);
            }
            let mut capture_result =
                capture_workers.finish_by(std::time::Instant::now() + capture_drain_timeout);
            if capture_result.is_err() {
                process_tree.terminate_and_wait(&mut child);
                if capture_result
                    .as_ref()
                    .is_err_and(|error| error.kind() == io::ErrorKind::TimedOut)
                {
                    let post_termination = capture_workers.finish_by(
                        std::time::Instant::now() + post_termination_capture_drain_timeout,
                    );
                    if let Err(post_termination) = post_termination {
                        let initial =
                            capture_result.expect_err("capture result was checked as an error");
                        capture_result = Err(io::Error::new(
                            post_termination.kind(),
                            format!(
                                "{initial}; output writers did not quiesce after process-tree termination: {post_termination}"
                            ),
                        ));
                    }
                }
            }
            let budget_result = budget.check(plan.output());
            match (outcome, capture_result, budget_result) {
                (Ok(outcome), Ok(()), Ok(())) => Ok(outcome),
                (Err(error), _, _) => Err(error),
                (Ok(_), Err(error), _) => Err(AppError::Runtime(format!(
                    "{error}; scan coverage is incomplete"
                ))),
                (Ok(_), Ok(()), Err(error)) => Err(error),
            }
        })();
        let tracking = container_id_file.created_container();
        if let Ok(Some(created)) = tracking.as_ref() {
            *created_container = Some(created.clone());
        }
        let execution = match (execution, tracking) {
            (Ok(outcome), Ok(Some(_))) => Ok(outcome),
            (Ok(outcome), Ok(None))
                if outcome.exit_code == Some(0) && !outcome.cancelled =>
            {
                Err(AppError::Runtime(
                    "container runtime reported success without a created-object ID; cleanup cannot be proven"
                        .into(),
                ))
            }
            (Ok(outcome), Ok(None)) => Ok(outcome),
            (Err(error), Ok(_)) => Err(error),
            (Ok(_), Err(tracking)) => Err(tracking),
            (Err(execution), Err(tracking)) => Err(AppError::Runtime(format!(
                "{execution}; container created-object tracking also failed: {tracking}"
            ))),
        };
        let secret_cleanup = secret.as_mut().map_or(Ok(()), SecretFileGuard::cleanup);
        match (execution, secret_cleanup) {
            (Ok(outcome), Ok(())) => Ok(outcome),
            (Err(error), Ok(())) => Err(error),
            (Ok(_), Err(cleanup)) => Err(cleanup),
            (Err(execution), Err(cleanup)) => Err(AppError::Runtime(format!(
                "{execution}; protected credential cleanup also failed: {cleanup}"
            ))),
        }
    }

    fn cleanup(
        &self,
        ownership: &OwnedContainerCleanupRequest,
        created_container: Option<&CreatedContainer>,
    ) -> AppResult<CleanupOutcome> {
        ownership.validate()?;
        let target = match created_container {
            Some(created) => created.immutable_id().to_owned(),
            None => ownership.container_name()?,
        };
        let inspect_operation = DirectRuntimeOperation::OwnedContainerInspection;
        let inspection =
            self.direct_output(inspect_operation, ["container", "inspect", target.as_str()])?;
        if !inspection.status.success() {
            if runtime_object_is_absent(&inspection.stderr) {
                return Ok(CleanupOutcome {
                    removed: false,
                    detail: "ownership-proven container was already absent".into(),

                    gateway_refusals: None,
                });
            }
            return Err(process_failure(inspect_operation.label(), &inspection));
        }
        let immutable_id = prove_owned_container(&inspection.stdout, ownership)?;
        if created_container
            .is_some_and(|created| !immutable_id.eq_ignore_ascii_case(created.immutable_id()))
        {
            return Err(AppError::NotAuthorized(
                "inspected container ID does not match the object created by this invocation"
                    .into(),
            ));
        }
        let cleanup_operation = DirectRuntimeOperation::OwnedContainerCleanup;
        let removal =
            self.direct_output(cleanup_operation, ["rm", "--force", immutable_id.as_str()])?;
        if removal.status.success() {
            return Ok(CleanupOutcome {
                removed: true,
                detail: "ownership-proven container removed by immutable object ID".into(),

                gateway_refusals: None,
            });
        }
        if runtime_object_is_absent(&removal.stderr) {
            return Ok(CleanupOutcome {
                removed: false,
                detail: "ownership-proven container disappeared before removal".into(),

                gateway_refusals: None,
            });
        }
        Err(process_failure(cleanup_operation.label(), &removal))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeCall {
    Preflight,
    ExecutionPreflight,
    VerifyNetwork(String),
    Pull(String),
    Run(String),
    Cleanup(String),
}

#[derive(Debug, Clone)]
pub struct FakeRunBehavior {
    pub exit_code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub output_files: BTreeMap<String, Vec<u8>>,
}

impl Default for FakeRunBehavior {
    fn default() -> Self {
        Self {
            exit_code: Some(0),
            stdout: Vec::new(),
            stderr: Vec::new(),
            output_files: BTreeMap::new(),
        }
    }
}

#[derive(Default)]
pub struct FakeContainerRuntime {
    calls: Mutex<Vec<RuntimeCall>>,
    behavior: Mutex<FakeRunBehavior>,
    execution_preflight_override: Mutex<Option<RuntimePreflight>>,
    fail_preflight: AtomicBool,
    fail_execution_preflight: AtomicBool,
    fail_network: AtomicBool,
    fail_pull: AtomicBool,
    fail_cleanup: AtomicBool,
    foreign_cleanup_mismatch: AtomicBool,
    skip_creation: AtomicBool,
    untracked_creation: AtomicBool,
}

impl FakeContainerRuntime {
    pub fn set_behavior(&self, behavior: FakeRunBehavior) {
        *self.behavior.lock().expect("fake behavior lock") = behavior;
    }

    pub fn set_fail_preflight(&self, fail: bool) {
        self.fail_preflight.store(fail, Ordering::SeqCst);
    }

    pub fn set_fail_execution_preflight(&self, fail: bool) {
        self.fail_execution_preflight.store(fail, Ordering::SeqCst);
    }

    pub fn set_execution_preflight(&self, preflight: RuntimePreflight) {
        *self
            .execution_preflight_override
            .lock()
            .expect("fake execution preflight lock") = Some(preflight);
    }

    pub fn set_fail_network(&self, fail: bool) {
        self.fail_network.store(fail, Ordering::SeqCst);
    }

    pub fn set_fail_pull(&self, fail: bool) {
        self.fail_pull.store(fail, Ordering::SeqCst);
    }

    pub fn set_fail_cleanup(&self, fail: bool) {
        self.fail_cleanup.store(fail, Ordering::SeqCst);
    }

    pub fn set_foreign_cleanup_mismatch(&self, mismatch: bool) {
        self.foreign_cleanup_mismatch
            .store(mismatch, Ordering::SeqCst);
    }

    pub fn set_skip_creation(&self, skip: bool) {
        self.skip_creation.store(skip, Ordering::SeqCst);
    }

    pub fn set_untracked_creation(&self, untracked: bool) {
        self.untracked_creation.store(untracked, Ordering::SeqCst);
    }

    pub fn calls(&self) -> Vec<RuntimeCall> {
        self.calls.lock().expect("fake calls lock").clone()
    }
}

impl ContainerRuntime for FakeContainerRuntime {
    fn preflight(&self) -> AppResult<RuntimePreflight> {
        self.calls
            .lock()
            .expect("fake calls lock")
            .push(RuntimeCall::Preflight);
        if self.fail_preflight.load(Ordering::SeqCst) {
            return Err(AppError::Runtime("fake preflight failure".into()));
        }
        Ok(RuntimePreflight {
            provider: RuntimeProvider::Docker,
            server_version: "fake-1.0".into(),
            security_options: "fake-seccomp".into(),
            command_provenance: RuntimeCommandProvenance::Compatibility,
        })
    }

    fn execution_preflight(&self) -> AppResult<RuntimePreflight> {
        self.calls
            .lock()
            .expect("fake calls lock")
            .push(RuntimeCall::ExecutionPreflight);
        if self.fail_execution_preflight.load(Ordering::SeqCst) {
            return Err(AppError::Runtime("fake execution preflight failure".into()));
        }
        Ok(self
            .execution_preflight_override
            .lock()
            .expect("fake execution preflight lock")
            .clone()
            .unwrap_or_else(|| RuntimePreflight {
                provider: RuntimeProvider::Docker,
                server_version: "fake-1.0".into(),
                security_options: "fake-seccomp".into(),
                command_provenance: RuntimeCommandProvenance::Compatibility,
            }))
    }

    fn verify_network(&self, policy: &NetworkPolicy) -> AppResult<()> {
        self.calls
            .lock()
            .expect("fake calls lock")
            .push(RuntimeCall::VerifyNetwork(
                policy.policy_id().unwrap_or("disabled").into(),
            ));
        if self.fail_network.load(Ordering::SeqCst) {
            return Err(AppError::NotAuthorized(
                "fake managed network rejected".into(),
            ));
        }
        Ok(())
    }

    fn pull(&self, image: &PinnedImage) -> AppResult<()> {
        self.calls
            .lock()
            .expect("fake calls lock")
            .push(RuntimeCall::Pull(image.reference()));
        if self.fail_pull.load(Ordering::SeqCst) {
            return Err(AppError::Runtime("fake pull failure".into()));
        }
        Ok(())
    }

    fn run(
        &self,
        plan: &ContainerRunPlan,
        credentials: &ScannerCredentialSet,
        cancellation: &CancellationToken,
        capture: &CapturePaths,
        created_container: &mut Option<CreatedContainer>,
        creation_may_be_untracked: &mut bool,
    ) -> AppResult<RuntimeOutcome> {
        *created_container = None;
        *creation_may_be_untracked = false;
        validate_run_plan_integrity(plan)?;
        credentials.validate_fresh()?;
        self.calls
            .lock()
            .expect("fake calls lock")
            .push(RuntimeCall::Run(plan.container_name.clone()));
        if cancellation.is_cancelled() {
            return Ok(RuntimeOutcome {
                exit_code: None,
                cancelled: true,
            });
        }
        if self.untracked_creation.load(Ordering::SeqCst) {
            *creation_may_be_untracked = true;
        } else if !self.skip_creation.load(Ordering::SeqCst) {
            *creation_may_be_untracked = true;
            *created_container = Some(CreatedContainer::from_runtime_id(&"f".repeat(64))?);
        }
        let behavior = self.behavior.lock().expect("fake behavior lock").clone();
        let mut bytes = behavior
            .stdout
            .len()
            .checked_add(behavior.stderr.len())
            .ok_or_else(|| output_limit_error(plan.output_bytes()))? as u64;
        if behavior.output_files.len() > MAX_OUTPUT_ENTRIES {
            return Err(AppError::Runtime(
                "engine output exceeded the file-count limit; scan coverage is incomplete".into(),
            ));
        }
        for output in behavior.output_files.values() {
            bytes = bytes
                .checked_add(output.len() as u64)
                .ok_or_else(|| output_limit_error(plan.output_bytes()))?;
        }
        let mut existing_entries = 0_usize;
        bytes = bytes
            .checked_add(measure_output_tree(
                plan.output(),
                0,
                &mut existing_entries,
                plan.output_bytes(),
            )?)
            .ok_or_else(|| output_limit_error(plan.output_bytes()))?;
        if bytes > plan.output_bytes() {
            return Err(output_limit_error(plan.output_bytes()));
        }
        let (mut stdout, mut stderr) = capture.clone_empty_writers()?;
        stdout.write_all(&behavior.stdout)?;
        stderr.write_all(&behavior.stderr)?;
        stdout.sync_all()?;
        stderr.sync_all()?;
        for (relative, bytes) in behavior.output_files {
            let path = safe_fake_output_path(&plan.output, &relative)?;
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(path, bytes)?;
        }
        Ok(RuntimeOutcome {
            exit_code: behavior.exit_code,
            cancelled: false,
        })
    }

    fn cleanup(
        &self,
        ownership: &OwnedContainerCleanupRequest,
        _created_container: Option<&CreatedContainer>,
    ) -> AppResult<CleanupOutcome> {
        let container_name = ownership.container_name()?;
        self.calls
            .lock()
            .expect("fake calls lock")
            .push(RuntimeCall::Cleanup(container_name));
        if self.foreign_cleanup_mismatch.load(Ordering::SeqCst) {
            return Err(AppError::NotAuthorized(
                "fake foreign ownership mismatch".into(),
            ));
        }
        if self.fail_cleanup.load(Ordering::SeqCst) {
            return Err(AppError::Runtime("fake cleanup failure".into()));
        }
        Ok(CleanupOutcome {
            removed: true,
            detail: "fake container removed".into(),

            gateway_refusals: None,
        })
    }
}

pub(crate) fn validate_static_manifest_command(command: &[String]) -> AppResult<()> {
    if command.is_empty() || command.len() > 128 {
        return Err(AppError::EngineRegistry(
            "engine command must contain between 1 and 128 static argv tokens".into(),
        ));
    }
    let program = Path::new(&command[0])
        .file_name()
        .and_then(OsStr::to_str)
        .unwrap_or_default()
        .to_ascii_lowercase();
    if matches!(
        program.as_str(),
        "sh" | "bash"
            | "zsh"
            | "fish"
            | "dash"
            | "cmd"
            | "cmd.exe"
            | "powershell"
            | "powershell.exe"
            | "pwsh"
            | "pwsh.exe"
    ) {
        return Err(AppError::EngineRegistry(format!(
            "engine command may not invoke a shell: {}",
            command[0]
        )));
    }
    for token in command {
        if token.is_empty() || token.len() > 4096 || token.contains('\0') {
            return Err(AppError::EngineRegistry(
                "engine command contains an invalid argv token".into(),
            ));
        }
        let lower = token.to_ascii_lowercase();
        let dynamic_placeholder = lower.contains("${")
            || lower.contains("$(")
            || lower.contains("{{")
            || lower.contains("<target")
            || lower.contains("{target")
            || lower.contains("{secret")
            || lower.contains("%target%")
            || lower.contains("%secret%");
        let shell_operator = matches!(token.as_str(), ";" | "&&" | "||" | "|" | ">" | ">>" | "<")
            || token.contains('`');
        if dynamic_placeholder || shell_operator {
            return Err(AppError::EngineRegistry(
                "engine command must be static argv and may not interpolate targets or secrets"
                    .into(),
            ));
        }
    }
    Ok(())
}

fn validate_naabu_launcher_manifest_contract(
    manifest: &EngineManifest,
    has_launcher_plan: bool,
) -> AppResult<()> {
    let version = manifest
        .execution
        .as_ref()
        .and_then(|execution| execution.launcher_journal_version);
    let has_any_launcher_flag = manifest.command.iter().any(|part| {
        ["--journal-version", "--journal-plan"].iter().any(|flag| {
            part == flag
                || part
                    .strip_prefix(flag)
                    .is_some_and(|suffix| suffix.starts_with('='))
        })
    });
    match version {
        Some(version) if version == LAUNCHER_V2_JOURNAL_SCHEMA_VERSION => {
            if manifest.id != NAABU_ENGINE_ID {
                return Err(AppError::EngineRegistry(
                    "launcher journal version 2 is supported only by the reviewed Naabu contract"
                        .into(),
                ));
            }
            if manifest
                .command
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
                != NAABU_LAUNCHER_COMMAND
            {
                return Err(AppError::EngineRegistry(
                    "Naabu launcher journal version 2 requires the exact reviewed static command"
                        .into(),
                ));
            }
            if !has_launcher_plan {
                return Err(AppError::InvalidRequest(
                    "Naabu launcher journal version 2 requires its private execution plan".into(),
                ));
            }
        }
        Some(_) => {
            return Err(AppError::EngineRegistry(
                "engine declares an unsupported launcher journal version".into(),
            ));
        }
        None => {
            if has_any_launcher_flag {
                return Err(AppError::EngineRegistry(
                    "launcher journal flags require an explicit reviewed launcher version".into(),
                ));
            }
            if has_launcher_plan {
                return Err(AppError::InvalidRequest(
                    "a launcher execution plan cannot be mounted for a legacy engine contract"
                        .into(),
                ));
            }
        }
    }
    Ok(())
}

/// The pinned ZAP command names its automation plan by absolute path. A manifest
/// that names that path without a mounted plan would start the engine against an
/// empty file, and a plan mounted for any other engine would be an unreviewed file
/// inside a scanner container. Both are refused here rather than at runtime.
fn validate_zap_plan_manifest_contract(
    manifest: &EngineManifest,
    has_zap_plan: bool,
) -> AppResult<()> {
    let names_plan = manifest
        .command
        .iter()
        .any(|part| part == CONTAINER_ZAP_PLAN_PATH);
    if names_plan && manifest.id != ZAP_ENGINE_ID {
        return Err(AppError::EngineRegistry(
            "the ZAP automation plan path is reserved for the reviewed ZAP contract".into(),
        ));
    }
    if has_zap_plan && manifest.id != ZAP_ENGINE_ID {
        return Err(AppError::EngineRegistry(
            "the ZAP automation plan is supported only by the reviewed ZAP contract".into(),
        ));
    }
    if has_zap_plan && !names_plan {
        return Err(AppError::EngineRegistry(
            "the ZAP manifest must invoke its automation plan at the product-owned path".into(),
        ));
    }
    if names_plan && !has_zap_plan {
        return Err(AppError::InvalidRequest(
            "the ZAP automation framework run requires its generated plan".into(),
        ));
    }
    // ZAP reads the mounted file only when it is the argument of `-autorun`.
    // Any other placement would start the engine without the plan it was given.
    if names_plan
        && !manifest.command.iter().enumerate().all(|(index, part)| {
            part != CONTAINER_ZAP_PLAN_PATH
                || index
                    .checked_sub(1)
                    .and_then(|previous| manifest.command.get(previous))
                    .is_some_and(|flag| flag == "-autorun")
        })
    {
        return Err(AppError::EngineRegistry(
            "the ZAP manifest must invoke its automation plan with -autorun".into(),
        ));
    }
    Ok(())
}

fn validate_mount_directory(path: &Path, label: &str) -> AppResult<()> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        AppError::Runtime(format!(
            "{label} mount {} is unavailable: {error}",
            path.display()
        ))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(AppError::Runtime(format!(
            "{label} mount must be a real directory, not a symlink: {}",
            path.display()
        )));
    }
    Ok(())
}

fn validate_mount_file(path: &Path, label: &str) -> AppResult<()> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        AppError::Runtime(format!(
            "{label} mount {} is unavailable: {error}",
            path.display()
        ))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(AppError::Runtime(format!(
            "{label} mount must be a real file, not a symlink: {}",
            path.display()
        )));
    }
    Ok(())
}

fn canonical_mount_path(path: &Path, label: &str) -> AppResult<PathBuf> {
    let canonical = fs::canonicalize(path)?;
    let rendered = canonical.to_string_lossy();
    if rendered.contains([',', '\n', '\r', '\0']) {
        return Err(AppError::Runtime(format!(
            "{label} mount contains characters unsupported by the container runtime"
        )));
    }
    Ok(canonical)
}

fn validate_run_plan_integrity(plan: &ContainerRunPlan) -> AppResult<()> {
    validate_execution_timeout_seconds(plan.execution_timeout_seconds)?;
    validate_mount_directory(&plan.workspace, "workspace")?;
    validate_mount_directory(&plan.output, "output")?;
    validate_mount_directory(&plan.credential_control_dir, "credential control")?;
    validate_mount_file(&plan.scope_file, "scope document")?;
    validate_run_plan_user_integrity(plan)?;
    validate_run_plan_network_integrity(plan)?;
    validate_run_plan_output_integrity(plan)?;
    validate_run_plan_launcher_integrity(plan)?;
    let current_scope_sha256 = hash_control_file(&plan.scope_file)?;
    if current_scope_sha256 != plan.scope_sha256 {
        return Err(AppError::NotAuthorized(
            "scope document changed after the immutable run plan was built".into(),
        ));
    }
    Ok(())
}

fn validate_run_plan_launcher_integrity(plan: &ContainerRunPlan) -> AppResult<()> {
    let image_reference = plan.image.reference();
    let image_index = plan
        .runtime_args
        .iter()
        .position(|argument| argument == &image_reference)
        .ok_or_else(|| {
            AppError::Runtime("container run plan lost its pinned image reference".into())
        })?;
    let launch_arguments = &plan.runtime_args[..image_index];
    match (&plan.launcher_plan_file, &plan.launcher_plan_sha256) {
        (None, None) => {
            if plan.ownership.launcher_plan_sha256.is_some() {
                return Err(AppError::NotAuthorized(
                    "legacy run plan gained a Naabu launcher ownership digest".into(),
                ));
            }
            if launch_arguments.iter().any(|argument| {
                argument.contains(CONTAINER_NAABU_LAUNCHER_PLAN_PATH)
                    || argument.starts_with(CONTAINER_NAABU_LAUNCHER_PLAN_LABEL_KEY)
            }) {
                return Err(AppError::NotAuthorized(
                    "legacy run plan gained an unbound Naabu launcher mount or ownership label"
                        .into(),
                ));
            }
        }
        (Some(path), Some(expected_sha256)) => {
            if plan.ownership.launcher_plan_sha256.as_deref() != Some(expected_sha256.as_str()) {
                return Err(AppError::NotAuthorized(
                    "Naabu launcher plan digest does not match its container ownership proof"
                        .into(),
                ));
            }
            validate_mount_file(path, "Naabu launcher plan")?;
            let current_sha256 = hash_bounded_control_file(
                path,
                MAX_NAABU_LAUNCHER_PLAN_BYTES as u64,
                "Naabu launcher plan",
            )?;
            if &current_sha256 != expected_sha256 {
                return Err(AppError::NotAuthorized(
                    "Naabu launcher plan changed after the immutable run plan was built".into(),
                ));
            }
            let expected_mount = bind_mount(path, CONTAINER_NAABU_LAUNCHER_PLAN_PATH, true)?;
            let mount_values = launch_arguments
                .windows(2)
                .filter_map(|arguments| {
                    (arguments[0] == "--mount"
                        && arguments[1].contains(CONTAINER_NAABU_LAUNCHER_PLAN_PATH))
                    .then_some(arguments[1].as_str())
                })
                .collect::<Vec<_>>();
            if mount_values != [expected_mount.as_str()] {
                return Err(AppError::NotAuthorized(
                    "container run plan did not preserve the exact read-only Naabu launcher mount"
                        .into(),
                ));
            }
            let expected_label =
                format!("{CONTAINER_NAABU_LAUNCHER_PLAN_LABEL_KEY}={expected_sha256}");
            let label_values = launch_arguments
                .windows(2)
                .filter_map(|arguments| {
                    (arguments[0] == "--label"
                        && arguments[1].starts_with(CONTAINER_NAABU_LAUNCHER_PLAN_LABEL_KEY))
                    .then_some(arguments[1].as_str())
                })
                .collect::<Vec<_>>();
            if label_values != [expected_label.as_str()] {
                return Err(AppError::NotAuthorized(
                    "container run plan did not preserve the exact Naabu launcher ownership label"
                        .into(),
                ));
            }
        }
        _ => {
            return Err(AppError::NotAuthorized(
                "Naabu launcher plan identity is incomplete".into(),
            ));
        }
    }
    Ok(())
}

fn validate_run_plan_user_integrity(plan: &ContainerRunPlan) -> AppResult<()> {
    let image_reference = plan.image.reference();
    let image_index = plan
        .runtime_args
        .iter()
        .position(|argument| argument == &image_reference)
        .ok_or_else(|| {
            AppError::Runtime("container run plan lost its pinned image reference".into())
        })?;
    let launch_arguments = &plan.runtime_args[..image_index];
    let expected_user = format!("--user={}", plan.rootless_user.user_spec);
    let exact_user_count = launch_arguments
        .iter()
        .filter(|argument| *argument == &expected_user)
        .count();
    let user_option_count = launch_arguments
        .iter()
        .filter(|argument| argument.as_str() == "--user" || argument.starts_with("--user="))
        .count();
    let contains_user_namespace = launch_arguments
        .iter()
        .any(|argument| argument.as_str() == "--userns" || argument.starts_with("--userns="));
    if exact_user_count != 1 || user_option_count != 1 || contains_user_namespace {
        return Err(AppError::NotAuthorized(
            "container run plan did not preserve its exact non-root user contract".into(),
        ));
    }
    Ok(())
}

fn validate_run_plan_output_integrity(plan: &ContainerRunPlan) -> AppResult<()> {
    let image_reference = plan.image.reference();
    let image_index = plan
        .runtime_args
        .iter()
        .position(|argument| argument == &image_reference)
        .ok_or_else(|| {
            AppError::Runtime("container run plan lost its pinned image reference".into())
        })?;
    let launch_arguments = &plan.runtime_args[..image_index];
    let expected = format!("fsize={0}:{0}", plan.output_bytes);
    let values = launch_arguments
        .windows(2)
        .filter_map(|arguments| (arguments[0] == "--ulimit").then_some(arguments[1].as_str()))
        .collect::<Vec<_>>();
    let ulimit_count = launch_arguments
        .iter()
        .filter(|argument| argument.as_str() == "--ulimit")
        .count();
    let log_driver_count = launch_arguments
        .iter()
        .filter(|argument| argument.as_str() == "--log-driver=none")
        .count();
    if ulimit_count != 1 || values != [expected.as_str()] || log_driver_count != 1 {
        return Err(AppError::NotAuthorized(
            "container run plan did not preserve its output-size and runtime-log limits".into(),
        ));
    }
    Ok(())
}

fn validate_run_plan_network_integrity(plan: &ContainerRunPlan) -> AppResult<()> {
    plan.network_policy.validate()?;
    let image_reference = plan.image.reference();
    let image_index = plan
        .runtime_args
        .iter()
        .position(|argument| argument == &image_reference)
        .ok_or_else(|| {
            AppError::Runtime("container run plan lost its pinned image reference".into())
        })?;
    let launch_arguments = &plan.runtime_args[..image_index];
    if launch_arguments
        .iter()
        .any(|argument| argument.starts_with("--network="))
    {
        return Err(AppError::NotAuthorized(
            "container run plan contains an unverified network option".into(),
        ));
    }
    let network_values: Vec<&str> = launch_arguments
        .windows(2)
        .filter_map(|arguments| (arguments[0] == "--network").then_some(arguments[1].as_str()))
        .collect();
    let network_option_count = launch_arguments
        .iter()
        .filter(|argument| argument.as_str() == "--network")
        .count();
    let expected_network = match &plan.network_policy {
        NetworkPolicy::Disabled => "none",
        NetworkPolicy::Managed { network_name, .. } => network_name,
    };
    if network_option_count != 1 || network_values != [expected_network] {
        return Err(AppError::NotAuthorized(format!(
            "container run plan did not preserve the exact {expected_network} network isolation"
        )));
    }
    Ok(())
}

fn hash_control_file(path: &Path) -> AppResult<String> {
    hash_bounded_control_file(path, MAX_SCOPE_DOCUMENT_BYTES, "scope document")
}

fn hash_bounded_control_file(path: &Path, max_bytes: u64, label: &str) -> AppResult<String> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(AppError::Runtime(format!(
            "{label} must remain a regular file"
        )));
    }
    if metadata.len() > max_bytes {
        return Err(AppError::Runtime(format!(
            "{label} exceeds the {max_bytes} byte limit"
        )));
    }
    let mut file = File::open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(hex::encode(digest.finalize()))
}

fn runtime_args_with_secret(
    plan: &ContainerRunPlan,
    provider: RuntimeProvider,
    secret: Option<&SecretFileGuard>,
    container_id_file: Option<&ContainerIdFileGuard>,
) -> AppResult<Vec<String>> {
    let image_reference = plan.image.reference();
    let image_index = plan
        .runtime_args
        .iter()
        .position(|argument| argument == &image_reference)
        .ok_or_else(|| {
            AppError::Runtime("container run plan lost its pinned image reference".into())
        })?;
    let mut arguments = plan.runtime_args.clone();
    let mut injected = Vec::new();
    if provider.uses_podman_dialect() {
        injected.push(format!("--userns={}", plan.rootless_user.podman_userns));
    }
    if let Some(container_id_file) = container_id_file {
        injected.extend(["--cidfile".into(), container_id_file.argument()?]);
    }
    if let Some(secret) = secret {
        secret.validate_integrity()?;
        let mount = bind_mount(&secret.path, CONTAINER_CREDENTIAL_PATH, true)?;
        injected.extend(["--mount".into(), mount]);
    }
    arguments.splice(image_index..image_index, injected);
    Ok(arguments)
}

fn secure_remove_secret_file(path: &Path) -> AppResult<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(AppError::Runtime(
            "protected credential channel is not a regular file".into(),
        ));
    }
    restrict_secret_file(path, false)?;
    let mut file = OpenOptions::new().write(true).open(path)?;
    file.seek(SeekFrom::Start(0))?;
    let zeros = Zeroizing::new(vec![0_u8; 16 * 1024]);
    let mut remaining = metadata.len();
    while remaining > 0 {
        let count = usize::try_from(remaining.min(zeros.len() as u64))
            .map_err(|_| AppError::Internal("credential cleanup length overflow".into()))?;
        file.write_all(&zeros[..count])?;
        remaining -= count as u64;
    }
    file.set_len(0)?;
    file.sync_all()?;
    drop(file);
    fs::remove_file(path)?;
    Ok(())
}

/// Zeroizes credential envelopes left by an abrupt desktop/process exit. The
/// caller must first reconcile the exact owned container, so no running engine
/// loses its credential channel. This function never follows symlinks and only
/// touches the bounded credential filename inside one persisted attempt.
pub fn cleanup_orphaned_credentials(
    artifact_root: &Path,
    request: &OwnedContainerCleanupRequest,
) -> AppResult<usize> {
    request.validate()?;
    let root_metadata = fs::symlink_metadata(artifact_root)?;
    if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
        return Err(AppError::NotAuthorized(
            "artifact root is not a regular private directory".into(),
        ));
    }
    let root = fs::canonicalize(artifact_root)?;
    let components = [
        request.case_id.clone(),
        request.scan_run_id.clone(),
        request.engine_run_id.clone(),
        format!("attempt-{}", request.attempt),
        "control".into(),
    ];
    let mut control = root.clone();
    for component in components {
        control.push(component);
        let metadata = match fs::symlink_metadata(&control) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(0),
            Err(error) => return Err(error.into()),
        };
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(AppError::NotAuthorized(
                "credential cleanup path contains a symlink or non-directory".into(),
            ));
        }
    }
    let canonical_control = fs::canonicalize(&control)?;
    if !canonical_control.starts_with(&root) {
        return Err(AppError::NotAuthorized(
            "credential cleanup path escaped the artifact root".into(),
        ));
    }
    let mut removed = 0_usize;
    for entry in fs::read_dir(&canonical_control)? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| AppError::NotAuthorized("credential filename is not UTF-8".into()))?;
        if !is_credential_envelope_name(&name) {
            continue;
        }
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.len() > MAX_CREDENTIAL_DOCUMENT_BYTES
        {
            return Err(AppError::NotAuthorized(
                "orphan credential envelope is not a bounded regular file".into(),
            ));
        }
        secure_remove_secret_file(&path)?;
        removed = removed.saturating_add(1);
    }
    Ok(removed)
}

fn is_credential_envelope_name(name: &str) -> bool {
    name.strip_prefix("credentials-")
        .and_then(|suffix| suffix.strip_suffix(".json"))
        .is_some_and(|nonce| {
            nonce.len() == 32 && nonce.chars().all(|character| character.is_ascii_hexdigit())
        })
}

#[cfg(unix)]
fn restrict_secret_file(path: &Path, readonly: bool) -> AppResult<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = if readonly { 0o400 } else { 0o600 };
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    Ok(())
}

#[cfg(not(unix))]
fn restrict_secret_file(path: &Path, readonly: bool) -> AppResult<()> {
    let mut permissions = fs::metadata(path)?.permissions();
    permissions.set_readonly(readonly);
    fs::set_permissions(path, permissions)?;
    Ok(())
}

fn bind_mount(source: &Path, destination: &str, read_only: bool) -> AppResult<String> {
    let source = source
        .to_str()
        .ok_or_else(|| AppError::Runtime("container bind mount path is not valid UTF-8".into()))?;
    let suffix = if read_only { ",readonly" } else { "" };
    Ok(format!("type=bind,src={source},dst={destination}{suffix}"))
}

pub(crate) fn planned_container_name(
    engine_id: &str,
    engine_run_id: &str,
    attempt: u32,
) -> AppResult<String> {
    if attempt == 0 || !valid_runtime_name(engine_id) || !valid_runtime_name(engine_run_id) {
        return Err(AppError::InvalidRequest(
            "engine id, run id, or attempt is invalid for a container name".into(),
        ));
    }
    let run_fragment: String = engine_run_id.chars().take(20).collect();
    let name = format!("ass-{engine_id}-{run_fragment}-a{attempt}");
    if name.len() > 128 {
        return Err(AppError::InvalidRequest(
            "generated container name exceeds runtime limits".into(),
        ));
    }
    Ok(name)
}

fn valid_runtime_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.')
        })
}

fn validate_container_owner_id(value: &str, label: &str) -> AppResult<()> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
    {
        return Err(AppError::InvalidRequest(format!(
            "{label} is invalid for container ownership"
        )));
    }
    Ok(())
}

fn valid_environment_key(value: &str) -> bool {
    let mut characters = value.chars();
    matches!(characters.next(), Some(first) if first == '_' || first.is_ascii_uppercase())
        && characters.all(|character| {
            character == '_' || character.is_ascii_uppercase() || character.is_ascii_digit()
        })
}

fn valid_sha256_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64 && hex.chars().all(|character| character.is_ascii_hexdigit())
    })
}

fn release_approved_local_image_directory_from_environment() -> Option<PathBuf> {
    std::env::var_os(RELEASE_APPROVED_LOCAL_IMAGE_DIRECTORY_ENVIRONMENT_VARIABLE)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

fn verified_release_approved_oci_archive(
    directory: &Path,
    image: &PinnedImage,
) -> AppResult<Option<File>> {
    let digest_hex = image
        .digest()
        .strip_prefix("sha256:")
        .expect("PinnedImage always contains a validated sha256 digest");
    let archive_path = directory.join("sha256").join(format!("{digest_hex}.tar"));
    let metadata = match fs::symlink_metadata(&archive_path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(AppError::Runtime(
            "local pinned image load source entry must be a regular OCI archive".into(),
        ));
    }

    let mut archive_file = File::open(&archive_path)?;
    verify_oci_archive_manifest(&mut archive_file, image.digest())?;
    archive_file.seek(SeekFrom::Start(0))?;
    Ok(Some(archive_file))
}

fn verify_oci_archive_manifest(archive_file: &mut File, pinned_digest: &str) -> AppResult<()> {
    let digest_hex = pinned_digest
        .strip_prefix("sha256:")
        .expect("PinnedImage always contains a validated sha256 digest");
    let manifest_path = PathBuf::from(format!("blobs/sha256/{digest_hex}"));
    let mut layout_document = None;
    let mut index_document = None;
    let mut manifest_document = None;
    let mut archive = tar::Archive::new(archive_file);

    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.into_owned();
        let destination = if path == Path::new("oci-layout") {
            Some((&mut layout_document, MAX_OCI_LAYOUT_DOCUMENT_BYTES))
        } else if path == Path::new("index.json") {
            Some((&mut index_document, MAX_OCI_INDEX_DOCUMENT_BYTES))
        } else if path == manifest_path {
            Some((&mut manifest_document, MAX_OCI_MANIFEST_DOCUMENT_BYTES))
        } else {
            None
        };
        let Some((document, maximum)) = destination else {
            continue;
        };
        if document.is_some() {
            return Err(AppError::Runtime(
                "local pinned image load rejected an OCI archive with duplicate required entries"
                    .into(),
            ));
        }
        let entry_type = entry.header().entry_type();
        if entry_type != tar::EntryType::Regular && entry_type != tar::EntryType::Continuous {
            return Err(AppError::Runtime(
                "local pinned image load rejected a non-regular required OCI archive entry".into(),
            ));
        }
        if entry.size() > maximum {
            return Err(AppError::Runtime(
                "local pinned image load rejected an oversized OCI metadata document".into(),
            ));
        }
        let mut bytes = Vec::with_capacity(entry.size() as usize);
        entry.read_to_end(&mut bytes)?;
        *document = Some(bytes);
    }

    let layout: serde_json::Value =
        serde_json::from_slice(layout_document.as_deref().ok_or_else(|| {
            AppError::Runtime("local pinned image load source is missing oci-layout".into())
        })?)
        .map_err(|error| {
            AppError::Runtime(format!(
                "local pinned image load source has invalid oci-layout JSON: {error}"
            ))
        })?;
    if layout
        .get("imageLayoutVersion")
        .and_then(|value| value.as_str())
        != Some("1.0.0")
    {
        return Err(AppError::Runtime(
            "local pinned image load source has an unsupported OCI image layout version".into(),
        ));
    }

    let index: serde_json::Value =
        serde_json::from_slice(index_document.as_deref().ok_or_else(|| {
            AppError::Runtime("local pinned image load source is missing index.json".into())
        })?)
        .map_err(|error| {
            AppError::Runtime(format!(
                "local pinned image load source has invalid index.json: {error}"
            ))
        })?;
    let pinned_manifest_descriptor = index
        .get("manifests")
        .and_then(|value| value.as_array())
        .and_then(|manifests| {
            manifests.iter().find(|descriptor| {
                descriptor.get("digest").and_then(|value| value.as_str()) == Some(pinned_digest)
            })
        });
    if index.get("schemaVersion").and_then(|value| value.as_u64()) != Some(2)
        || pinned_manifest_descriptor.is_none()
    {
        return Err(AppError::Runtime(
            "local pinned image load source index does not name the pinned manifest digest".into(),
        ));
    }
    let pinned_manifest_descriptor = pinned_manifest_descriptor.expect("descriptor was checked");
    let pinned_media_type = pinned_manifest_descriptor
        .get("mediaType")
        .and_then(|value| value.as_str());
    if !matches!(
        pinned_media_type,
        Some(OCI_IMAGE_MANIFEST_MEDIA_TYPE | "application/vnd.oci.image.index.v1+json")
    ) {
        return Err(AppError::Runtime(
            "local pinned image load source index does not identify an OCI image manifest".into(),
        ));
    }

    // For a multi-arch pin, verifying the content-addressed index is sufficient:
    // it names child manifests by digest, and the runtime verifies them during load.
    // Do not duplicate that traversal here.

    let manifest_document = manifest_document.as_deref().ok_or_else(|| {
        AppError::Runtime(
            "local pinned image load source is missing the pinned manifest blob".into(),
        )
    })?;
    let observed_digest = format!("sha256:{}", hex::encode(Sha256::digest(manifest_document)));
    if observed_digest != pinned_digest {
        return Err(AppError::Runtime(
            "local pinned image load source manifest bytes do not match the pinned digest".into(),
        ));
    }
    if pinned_manifest_descriptor
        .get("size")
        .and_then(|value| value.as_u64())
        != Some(manifest_document.len() as u64)
    {
        return Err(AppError::Runtime(
            "local pinned image load source manifest size does not match its OCI descriptor".into(),
        ));
    }
    let manifest: serde_json::Value =
        serde_json::from_slice(manifest_document).map_err(|error| {
            AppError::Runtime(format!(
                "local pinned image load source has invalid manifest JSON: {error}"
            ))
        })?;
    if manifest
        .get("schemaVersion")
        .and_then(|value| value.as_u64())
        != Some(2)
    {
        return Err(AppError::Runtime(
            "local pinned image load source manifest has an unsupported schema version".into(),
        ));
    }
    Ok(())
}

fn rootless_user_mapping_for_ids(uid: u32, gid: u32) -> AppResult<RootlessContainerUser> {
    if uid == 0 {
        return Err(AppError::NotAuthorized(
            "scanner containers cannot be launched from a root-owned desktop process".into(),
        ));
    }
    Ok(RootlessContainerUser {
        user_spec: format!("{uid}:{gid}"),
        // Podman's default rootless user namespace maps the caller to
        // container root. keep-id maps the machine/host caller to the exact
        // non-root identity used by the scanner process instead, preserving
        // access to its private bind-mounted case artifacts.
        podman_userns: format!("keep-id:uid={uid},gid={gid}"),
    })
}

#[cfg(unix)]
fn runtime_user_mapping() -> AppResult<RootlessContainerUser> {
    // The case artifact tree is private to the desktop user. Running as that
    // same non-root uid/gid lets the container read the explicit workspace and
    // write only its case-scoped output without broadening host permissions.
    let uid = unsafe { libc::geteuid() };
    let gid = unsafe { libc::getegid() };
    rootless_user_mapping_for_ids(uid, gid)
}

#[cfg(not(unix))]
fn runtime_user_mapping() -> AppResult<RootlessContainerUser> {
    // WSL exposes Windows bind mounts to Podman's rootless machine user. Map
    // that caller to the fixed non-root scanner identity inside the container;
    // podman-machine --volume is redundant on WSL because drives are already
    // projected below /mnt.
    rootless_user_mapping_for_ids(65532, 65532)
}

fn validate_gateway_endpoint(value: &str) -> AppResult<()> {
    let endpoint = url::Url::parse(value).map_err(|_| {
        AppError::InvalidRequest("managed network gateway endpoint is malformed".into())
    })?;
    if endpoint.scheme() != "socks5h"
        || !endpoint.username().is_empty()
        || endpoint.password().is_some()
        || !matches!(endpoint.path(), "" | "/")
        || endpoint.query().is_some()
        || endpoint.fragment().is_some()
        || endpoint.port().is_none()
    {
        return Err(AppError::InvalidRequest(
            "managed network gateway must be a credential-free socks5h IP endpoint".into(),
        ));
    }
    let address = endpoint
        .host_str()
        .and_then(|host| host.parse::<IpAddr>().ok())
        .ok_or_else(|| {
            AppError::InvalidRequest(
                "managed network gateway must use the private bridge IP directly".into(),
            )
        })?;
    let private = match address {
        IpAddr::V4(address) => {
            address.is_private()
                && address != Ipv4Addr::new(169, 254, 169, 254)
                && address != Ipv4Addr::new(169, 254, 170, 2)
                && address != Ipv4Addr::new(100, 100, 100, 200)
        }
        IpAddr::V6(address) => {
            (address.segments()[0] & 0xfe00) == 0xfc00
                && address != "fd00:ec2::254".parse::<Ipv6Addr>().expect("literal")
        }
    };
    if !private {
        return Err(AppError::InvalidRequest(
            "managed network gateway is outside a private container bridge".into(),
        ));
    }
    Ok(())
}

fn apply_runtime_environment(command: &mut Command) {
    const ALLOWED: &[&str] = &[
        "PATH",
        "HOME",
        "USERPROFILE",
        "SystemRoot",
        "DOCKER_HOST",
        "DOCKER_CONFIG",
        "XDG_RUNTIME_DIR",
        "CONTAINER_HOST",
    ];
    command.env_clear();
    for key in ALLOWED {
        if let Some(value) = std::env::var_os(key) {
            command.env(key, value);
        }
    }
}

fn process_failure(operation: &str, output: &std::process::Output) -> AppError {
    let stderr = String::from_utf8_lossy(&output.stderr);
    let detail: String = stderr.chars().take(2048).collect();
    AppError::Runtime(format!(
        "{operation} failed with status {}: {}",
        output.status,
        detail.trim()
    ))
}

fn safe_fake_output_path(root: &Path, relative: &str) -> AppResult<PathBuf> {
    let path = Path::new(relative);
    if path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        return Err(AppError::Runtime(
            "fake runtime output path must remain relative".into(),
        ));
    }
    Ok(root.join(path))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact_store::{ArtifactContext, ArtifactStore};
    use crate::domain::{
        AssetKind, DistributionMode, EngineCategory, EngineCompatibility, EngineExecutionContract,
        EngineExecutionResources, ImageReference, ManifestStatus, ScanPermission,
    };
    use chrono::Duration;
    #[cfg(unix)]
    use std::time::Instant;

    #[cfg(unix)]
    fn write_release_approved_oci_archive_with_media_type(
        source: &Path,
        pinned_digest: &str,
        manifest: &[u8],
        descriptor_media_type: &str,
    ) {
        let digest_hex = pinned_digest
            .strip_prefix("sha256:")
            .expect("test digest uses sha256");
        let archive_directory = source.join("sha256");
        fs::create_dir_all(&archive_directory).expect("create OCI archive directory");
        let archive_file = File::create(archive_directory.join(format!("{digest_hex}.tar")))
            .expect("create OCI archive");
        let mut archive = tar::Builder::new(archive_file);
        let index = serde_json::to_vec(&serde_json::json!({
            "schemaVersion": 2,
            "manifests": [{
                "mediaType": descriptor_media_type,
                "digest": pinned_digest,
                "size": manifest.len(),
            }],
        }))
        .expect("serialize OCI index");
        for (path, contents) in [
            (
                "oci-layout".to_owned(),
                br#"{"imageLayoutVersion":"1.0.0"}"#.as_slice(),
            ),
            ("index.json".to_owned(), index.as_slice()),
            (format!("blobs/sha256/{digest_hex}"), manifest),
        ] {
            let mut header = tar::Header::new_gnu();
            header.set_size(contents.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            archive
                .append_data(&mut header, path, contents)
                .expect("append OCI archive entry");
        }
        archive.finish().expect("finish OCI archive");
    }

    #[cfg(unix)]
    fn write_release_approved_oci_archive(source: &Path, pinned_digest: &str, manifest: &[u8]) {
        write_release_approved_oci_archive_with_media_type(
            source,
            pinned_digest,
            manifest,
            OCI_IMAGE_MANIFEST_MEDIA_TYPE,
        );
    }

    #[test]
    fn compatibility_runtime_rejects_an_arbitrary_managed_local_binary() {
        let assert_rejected = |error: AppError| {
            assert!(matches!(error, AppError::NotAuthorized(_)));
            assert!(
                error
                    .to_string()
                    .contains("requires its verified private command context")
            );
        };

        assert_rejected(
            RuntimeCommandContext::compatibility(
                RuntimeProvider::ManagedLocal,
                PathBuf::from("attacker-selected-managed-runtime"),
            )
            .expect_err("managed-local compatibility context must be rejected"),
        );
        assert_rejected(
            ProcessContainerRuntime::new(
                RuntimeProvider::ManagedLocal,
                "attacker-selected-managed-runtime",
            )
            .expect_err("managed-local runtime must require a verified private command"),
        );
    }

    #[test]
    fn direct_runtime_operations_keep_image_pull_timeout_separate() {
        assert_eq!(
            DirectRuntimeOperation::LocalPinnedImageLoad.timeout(),
            StdDuration::from_secs(15 * 60)
        );
        assert_eq!(
            DirectRuntimeOperation::PinnedImagePull.timeout(),
            StdDuration::from_secs(10 * 60)
        );
        assert_eq!(
            DirectRuntimeOperation::OwnedContainerCleanup.timeout(),
            StdDuration::from_secs(2 * 60)
        );
        for operation in [
            DirectRuntimeOperation::RuntimeVersionPreflight,
            DirectRuntimeOperation::RuntimeSecurityPreflight,
            DirectRuntimeOperation::RuntimeExecutionPreflight,
            DirectRuntimeOperation::ManagedNetworkPreflight,
            DirectRuntimeOperation::LocalPinnedImageInspection,
            DirectRuntimeOperation::ContainerPause,
            DirectRuntimeOperation::ContainerUnpause,
            DirectRuntimeOperation::ContainerStop,
            DirectRuntimeOperation::CreatedContainerOwnershipInspection,
            DirectRuntimeOperation::OwnedContainerInspection,
        ] {
            assert_eq!(operation.timeout(), StdDuration::from_secs(30));
        }
    }

    #[test]
    fn runtime_preflight_cache_retries_failures_and_reuses_only_a_successful_proof() {
        let cache = RuntimePreflightCache::default();
        let inspections = std::sync::atomic::AtomicUsize::new(0);
        let first = cache.get_or_try_init(|| {
            inspections.fetch_add(1, Ordering::SeqCst);
            Err(AppError::Runtime("temporary runtime failure".into()))
        });
        assert!(first.is_err(), "a failed inspection must fail closed");
        assert_eq!(inspections.load(Ordering::SeqCst), 1);

        let expected = RuntimePreflight {
            provider: RuntimeProvider::ManagedLocal,
            server_version: "5.8.2".into(),
            security_options: "verified-rootless-security".into(),
            command_provenance: RuntimeCommandProvenance::ManagedLocal {
                runtime_version: "1.0.0".into(),
                manifest_sha256: "a".repeat(64),
                machine_image_sha256: "b".repeat(64),
            },
        };
        let observed = cache
            .get_or_try_init(|| {
                inspections.fetch_add(1, Ordering::SeqCst);
                Ok(expected.clone())
            })
            .expect("retry obtains a valid proof");
        let reused = cache
            .get_or_try_init(|| -> AppResult<RuntimePreflight> {
                panic!("a successful proof must prevent another inspection")
            })
            .expect("successful proof is reusable");

        assert_eq!(observed, expected);
        assert_eq!(reused, expected);
        assert_eq!(inspections.load(Ordering::SeqCst), 2);

        let refresh = cache.refresh(|| {
            inspections.fetch_add(1, Ordering::SeqCst);
            Err(AppError::Runtime("daemon stopped before execution".into()))
        });
        assert!(refresh.is_err(), "a failed live refresh must fail closed");
        let recovered = cache
            .get_or_try_init(|| {
                inspections.fetch_add(1, Ordering::SeqCst);
                Ok(RuntimePreflight {
                    server_version: "5.8.3".into(),
                    ..expected.clone()
                })
            })
            .expect("a later prepare must reinspect after refresh failure");
        assert_eq!(recovered.server_version, "5.8.3");
        assert_eq!(inspections.load(Ordering::SeqCst), 4);
    }

    #[cfg(unix)]
    #[test]
    fn direct_runtime_timeout_uses_a_fixed_label_without_echoing_arguments() {
        let temp = tempfile::tempdir().expect("temporary runtime");
        let binary = temp.path().join("slow-runtime");
        write_executable_fixture(&binary, "#!/bin/sh\nsleep 5\n");
        let runtime = ProcessContainerRuntime::new(RuntimeProvider::Podman, binary)
            .expect("construct compatibility runtime");
        let sensitive_argument =
            "ghcr.io/example/private@sha256:do-not-echo-this-sensitive-reference";

        let started = Instant::now();
        let error = runtime
            .direct_output_with_timeout(
                DirectRuntimeOperation::PinnedImagePull,
                ["pull", sensitive_argument],
                StdDuration::from_millis(25),
            )
            .expect_err("slow image pull must reach its test deadline");
        let message = error.to_string();

        assert!(message.contains("pinned image pull"));
        assert!(message.contains("runtime command exceeded its deadline"));
        assert!(!message.contains(sensitive_argument));
        assert!(
            started.elapsed() < StdDuration::from_secs(3),
            "timed-out direct command must terminate promptly"
        );
    }

    #[cfg(unix)]
    #[test]
    fn pull_does_not_contact_the_registry_when_the_pinned_digest_is_already_local() {
        let temp = tempfile::tempdir().expect("temporary runtime");
        let binary = temp.path().join("podman-fixture");
        let log = temp.path().join("subcommands.log");
        write_executable_fixture(
            &binary,
            r#"#!/bin/sh
script_root=${0%/*}
printf '%s\n' "$1" >> "$script_root/subcommands.log"
if [ "$1" = image ] && [ "$2" = inspect ]; then exit 0; fi
if [ "$1" = load ]; then exit 0; fi
if [ "$1" = pull ]; then exit 0; fi
exit 29
"#,
        );
        let runtime = ProcessContainerRuntime::new(RuntimeProvider::Podman, binary)
            .expect("construct compatibility runtime")
            .with_release_approved_local_image_directory(None);
        let image = PinnedImage::new(
            "ghcr.io/example/private",
            &format!("sha256:{}", "a".repeat(64)),
        )
        .expect("pinned image");

        runtime.pull(&image).expect("local image skips pulling");

        let invocations = fs::read_to_string(log).expect("runtime invocation log");
        assert!(invocations.lines().any(|subcommand| subcommand == "image"));
        assert!(
            !invocations.lines().any(|subcommand| subcommand == "load"),
            "an already present digest must never be loaded"
        );
        assert!(
            !invocations.lines().any(|subcommand| subcommand == "pull"),
            "a locally present digest must never contact the registry"
        );
    }

    #[cfg(unix)]
    #[test]
    fn pull_loads_verified_release_approved_archive_and_skips_registry_when_digest_becomes_present()
    {
        let temp = tempfile::tempdir().expect("temporary runtime");
        let binary = temp.path().join("podman-fixture");
        let log = temp.path().join("subcommands.log");
        let source = temp.path().join("release-images");
        let manifest = br#"{"schemaVersion":2}"#;
        let digest = format!("sha256:{}", hex::encode(Sha256::digest(manifest)));
        write_release_approved_oci_archive(&source, &digest, manifest);
        write_executable_fixture(
            &binary,
            r#"#!/bin/sh
script_root=${0%/*}
printf '%s\n' "$1" >> "$script_root/subcommands.log"
if [ "$1" = image ] && [ "$2" = inspect ]; then
  if [ -f "$script_root/image-loaded" ]; then exit 0; fi
  exit 1
fi
if [ "$1" = load ]; then
  touch "$script_root/image-loaded"
  exit 0
fi
if [ "$1" = pull ]; then exit 0; fi
exit 29
"#,
        );
        let runtime = ProcessContainerRuntime::new(RuntimeProvider::Podman, binary)
            .expect("construct compatibility runtime")
            .with_release_approved_local_image_directory(Some(source));
        let image = PinnedImage::new("ghcr.io/example/private", &digest).expect("pinned image");

        runtime
            .pull(&image)
            .expect("verified local archive makes the digest available");

        let invocations = fs::read_to_string(log).expect("runtime invocation log");
        assert_eq!(
            invocations.lines().collect::<Vec<_>>(),
            vec!["image", "load", "image"]
        );
        assert!(
            !invocations.lines().any(|subcommand| subcommand == "pull"),
            "a successfully loaded digest must never contact the registry"
        );
    }

    #[cfg(unix)]
    #[test]
    fn pull_loads_verified_release_approved_multi_arch_index_and_skips_registry() {
        let temp = tempfile::tempdir().expect("temporary runtime");
        let binary = temp.path().join("podman-fixture");
        let log = temp.path().join("subcommands.log");
        let source = temp.path().join("release-images");
        let index_document = br#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[]}"#;
        let digest = format!("sha256:{}", hex::encode(Sha256::digest(index_document)));
        write_release_approved_oci_archive_with_media_type(
            &source,
            &digest,
            index_document,
            "application/vnd.oci.image.index.v1+json",
        );
        write_executable_fixture(
            &binary,
            r#"#!/bin/sh
script_root=${0%/*}
printf '%s\n' "$1" >> "$script_root/subcommands.log"
if [ "$1" = image ] && [ "$2" = inspect ]; then
  if [ -f "$script_root/image-loaded" ]; then exit 0; fi
  exit 1
fi
if [ "$1" = load ]; then
  touch "$script_root/image-loaded"
  exit 0
fi
if [ "$1" = pull ]; then exit 0; fi
exit 29
"#,
        );
        let runtime = ProcessContainerRuntime::new(RuntimeProvider::Podman, binary)
            .expect("construct compatibility runtime")
            .with_release_approved_local_image_directory(Some(source));
        let image = PinnedImage::new("ghcr.io/example/private", &digest).expect("pinned image");

        runtime
            .pull(&image)
            .expect("verified multi-arch index archive makes the digest available");

        let invocations = fs::read_to_string(log).expect("runtime invocation log");
        assert_eq!(
            invocations.lines().collect::<Vec<_>>(),
            vec!["image", "load", "image"]
        );
        assert!(
            !invocations.lines().any(|subcommand| subcommand == "pull"),
            "a successfully loaded multi-arch digest must never contact the registry"
        );
    }

    #[cfg(unix)]
    #[test]
    fn pull_rejects_release_approved_archive_with_unrelated_descriptor_media_type() {
        let temp = tempfile::tempdir().expect("temporary runtime");
        let binary = temp.path().join("podman-fixture");
        let log = temp.path().join("subcommands.log");
        let source = temp.path().join("release-images");
        let manifest = br#"{"schemaVersion":2}"#;
        let digest = format!("sha256:{}", hex::encode(Sha256::digest(manifest)));
        write_release_approved_oci_archive_with_media_type(
            &source,
            &digest,
            manifest,
            "application/vnd.example.unrelated+json",
        );
        write_executable_fixture(
            &binary,
            r#"#!/bin/sh
script_root=${0%/*}
printf '%s\n' "$1" >> "$script_root/subcommands.log"
if [ "$1" = image ] && [ "$2" = inspect ]; then exit 1; fi
if [ "$1" = load ]; then exit 0; fi
if [ "$1" = pull ]; then exit 0; fi
exit 29
"#,
        );
        let runtime = ProcessContainerRuntime::new(RuntimeProvider::Podman, binary)
            .expect("construct compatibility runtime")
            .with_release_approved_local_image_directory(Some(source));
        let image = PinnedImage::new("ghcr.io/example/private", &digest).expect("pinned image");

        let error = runtime
            .pull(&image)
            .expect_err("an unrelated descriptor media type must be rejected");

        assert!(
            error
                .to_string()
                .contains("does not identify an OCI image manifest")
        );
        let invocations = fs::read_to_string(log).expect("runtime invocation log");
        assert_eq!(invocations.lines().collect::<Vec<_>>(), vec!["image"]);
    }

    #[cfg(unix)]
    #[test]
    fn pull_does_not_accept_successful_local_load_without_pinned_digest() {
        let temp = tempfile::tempdir().expect("temporary runtime");
        let binary = temp.path().join("podman-fixture");
        let log = temp.path().join("subcommands.log");
        let source = temp.path().join("release-images");
        let manifest = br#"{"schemaVersion":2}"#;
        let digest = format!("sha256:{}", hex::encode(Sha256::digest(manifest)));
        write_release_approved_oci_archive(&source, &digest, manifest);
        write_executable_fixture(
            &binary,
            r#"#!/bin/sh
script_root=${0%/*}
printf '%s\n' "$1" >> "$script_root/subcommands.log"
if [ "$1" = image ] && [ "$2" = inspect ]; then exit 1; fi
if [ "$1" = load ]; then exit 0; fi
if [ "$1" = pull ]; then exit 0; fi
exit 29
"#,
        );
        let runtime = ProcessContainerRuntime::new(RuntimeProvider::Podman, binary)
            .expect("construct compatibility runtime")
            .with_release_approved_local_image_directory(Some(source));
        let image = PinnedImage::new("ghcr.io/example/private", &digest).expect("pinned image");
        let reference = image.reference();

        let error = runtime
            .pull(&image)
            .expect_err("a successful load must still prove the pinned digest");

        let message = error.to_string();
        assert!(message.contains("local pinned image load"));
        assert!(!message.contains(&reference));
        let invocations = fs::read_to_string(log).expect("runtime invocation log");
        assert_eq!(
            invocations.lines().collect::<Vec<_>>(),
            vec!["image", "load", "image"]
        );
        assert!(!invocations.lines().any(|subcommand| subcommand == "pull"));
    }

    #[cfg(unix)]
    #[test]
    fn pull_contacts_registry_when_release_approved_local_image_source_is_not_configured() {
        let temp = tempfile::tempdir().expect("temporary runtime");
        let binary = temp.path().join("podman-fixture");
        let log = temp.path().join("subcommands.log");
        write_executable_fixture(
            &binary,
            r#"#!/bin/sh
script_root=${0%/*}
printf '%s\n' "$1" >> "$script_root/subcommands.log"
if [ "$1" = image ] && [ "$2" = inspect ]; then exit 1; fi
if [ "$1" = pull ]; then exit 0; fi
exit 29
"#,
        );
        let runtime = ProcessContainerRuntime::new(RuntimeProvider::Podman, binary)
            .expect("construct compatibility runtime")
            .with_release_approved_local_image_directory(None);
        let image = PinnedImage::new(
            "ghcr.io/example/private",
            &format!("sha256:{}", "b".repeat(64)),
        )
        .expect("pinned image");

        runtime.pull(&image).expect("absent image is pulled");

        let invocations = fs::read_to_string(log).expect("runtime invocation log");
        assert!(
            invocations.lines().any(|subcommand| subcommand == "pull"),
            "an absent digest must be fetched"
        );
    }

    #[cfg(unix)]
    #[test]
    fn pull_contacts_registry_when_release_approved_local_image_source_has_no_digest_entry() {
        let temp = tempfile::tempdir().expect("temporary runtime");
        let binary = temp.path().join("podman-fixture");
        let log = temp.path().join("subcommands.log");
        let source = temp.path().join("release-images");
        fs::create_dir(&source).expect("create empty local image source");
        write_executable_fixture(
            &binary,
            r#"#!/bin/sh
script_root=${0%/*}
printf '%s\n' "$1" >> "$script_root/subcommands.log"
if [ "$1" = image ] && [ "$2" = inspect ]; then exit 1; fi
if [ "$1" = pull ]; then exit 0; fi
exit 29
"#,
        );
        let runtime = ProcessContainerRuntime::new(RuntimeProvider::Podman, binary)
            .expect("construct compatibility runtime")
            .with_release_approved_local_image_directory(Some(source));
        let image = PinnedImage::new(
            "ghcr.io/example/private",
            &format!("sha256:{}", "d".repeat(64)),
        )
        .expect("pinned image");

        runtime
            .pull(&image)
            .expect("a missing local source entry falls through to pull");

        let invocations = fs::read_to_string(log).expect("runtime invocation log");
        assert_eq!(
            invocations.lines().collect::<Vec<_>>(),
            vec!["image", "pull"]
        );
    }

    #[cfg(unix)]
    #[test]
    fn pull_rejects_local_archive_when_manifest_bytes_do_not_match_pinned_digest_without_loading() {
        let temp = tempfile::tempdir().expect("temporary runtime");
        let binary = temp.path().join("podman-fixture");
        let log = temp.path().join("subcommands.log");
        let source = temp.path().join("release-images");
        let expected_manifest = br#"{"schemaVersion":2,"expected":true}"#;
        let substituted_manifest = br#"{"schemaVersion":2,"expected":false}"#;
        let digest = format!("sha256:{}", hex::encode(Sha256::digest(expected_manifest)));
        write_release_approved_oci_archive(&source, &digest, substituted_manifest);
        write_executable_fixture(
            &binary,
            r#"#!/bin/sh
script_root=${0%/*}
printf '%s\n' "$1" >> "$script_root/subcommands.log"
if [ "$1" = image ] && [ "$2" = inspect ]; then exit 1; fi
if [ "$1" = load ]; then exit 0; fi
if [ "$1" = pull ]; then exit 0; fi
exit 29
"#,
        );
        let runtime = ProcessContainerRuntime::new(RuntimeProvider::Podman, binary)
            .expect("construct compatibility runtime")
            .with_release_approved_local_image_directory(Some(source));
        let image = PinnedImage::new("ghcr.io/example/private", &digest).expect("pinned image");

        let error = runtime
            .pull(&image)
            .expect_err("substituted manifest bytes must be rejected before load");

        assert!(error.to_string().contains("manifest bytes do not match"));
        let invocations = fs::read_to_string(log).expect("runtime invocation log");
        assert_eq!(invocations.lines().collect::<Vec<_>>(), vec!["image"]);
    }

    #[cfg(unix)]
    #[test]
    fn local_pinned_image_load_failure_names_operation_without_echoing_pinned_reference() {
        let temp = tempfile::tempdir().expect("temporary runtime");
        let binary = temp.path().join("podman-fixture");
        let source = temp.path().join("release-images");
        let manifest = br#"{"schemaVersion":2}"#;
        let digest = format!("sha256:{}", hex::encode(Sha256::digest(manifest)));
        write_release_approved_oci_archive(&source, &digest, manifest);
        write_executable_fixture(
            &binary,
            r#"#!/bin/sh
script_root=${0%/*}
printf '%s\n' "$1" >> "$script_root/subcommands.log"
if [ "$1" = image ] && [ "$2" = inspect ]; then exit 1; fi
if [ "$1" = load ]; then
  printf '%s\n' 'archive import was rejected' >&2
  exit 1
fi
if [ "$1" = pull ]; then exit 0; fi
exit 29
"#,
        );
        let runtime = ProcessContainerRuntime::new(RuntimeProvider::Podman, binary)
            .expect("construct compatibility runtime")
            .with_release_approved_local_image_directory(Some(source));
        let image = PinnedImage::new("ghcr.io/example/private", &digest).expect("pinned image");
        let reference = image.reference();

        let error = runtime
            .pull(&image)
            .expect_err("failed local load is reported");
        let message = error.to_string();

        assert!(message.contains("local pinned image load"));
        assert!(!message.contains(&reference));
    }

    #[cfg(unix)]
    #[test]
    fn pull_failure_names_the_pull_operation_without_echoing_the_pinned_reference() {
        let temp = tempfile::tempdir().expect("temporary runtime");
        let binary = temp.path().join("podman-fixture");
        write_executable_fixture(
            &binary,
            r#"#!/bin/sh
script_root=${0%/*}
printf '%s\n' "$1" >> "$script_root/subcommands.log"
if [ "$1" = image ] && [ "$2" = inspect ]; then exit 1; fi
if [ "$1" = pull ]; then
  printf '%s\n' 'registry rejected image' >&2
  exit 1
fi
exit 29
"#,
        );
        let runtime = ProcessContainerRuntime::new(RuntimeProvider::Podman, binary)
            .expect("construct compatibility runtime")
            .with_release_approved_local_image_directory(None);
        let image = PinnedImage::new(
            "ghcr.io/example/private",
            &format!("sha256:{}", "c".repeat(64)),
        )
        .expect("pinned image");
        let reference = image.reference();

        let error = runtime
            .pull(&image)
            .expect_err("failed registry pull is reported");
        let message = error.to_string();

        assert!(message.contains("pinned image pull"));
        assert!(!message.contains("local pinned image inspection"));
        assert!(!message.contains(&reference));
    }

    #[test]
    fn security_preflight_uses_the_provider_native_template_and_bounded_schema() {
        assert_eq!(
            runtime_security_info_template(RuntimeProvider::Docker),
            "{{json .SecurityOptions}}"
        );
        assert_eq!(
            runtime_execution_info_template(RuntimeProvider::Docker),
            r#"{"serverVersion":{{json .ServerVersion}},"securityOptions":{{json .SecurityOptions}}}"#
        );
        for provider in [RuntimeProvider::ManagedLocal, RuntimeProvider::Podman] {
            assert_eq!(
                runtime_security_info_template(provider),
                "{{json .Host.Security}}"
            );
            assert_eq!(
                runtime_execution_info_template(provider),
                r#"{"serverVersion":{{json .Version.Version}},"securityOptions":{{json .Host.Security}}}"#
            );
        }

        let podman = br#"{
            "selinuxEnabled": false,
            "seccompProfilePath": "/usr/share/containers/seccomp.json",
            "rootless": true,
            "capabilities": "CAP_CHOWN,CAP_SETUID",
            "apparmorEnabled": false,
            "seccompEnabled": true,
            "futureField": "ignored after validation"
        }"#;
        assert_eq!(
            validate_runtime_security_options(RuntimeProvider::ManagedLocal, podman).unwrap(),
            r#"{"apparmorEnabled":false,"capabilities":"CAP_CHOWN,CAP_SETUID","rootless":true,"seccompEnabled":true,"seccompProfilePath":"/usr/share/containers/seccomp.json","selinuxEnabled":false}"#
        );

        let compatibility = br#"{
            "apparmorEnabled": false,
            "capabilities": "CAP_CHOWN",
            "rootless": false,
            "seccompEnabled": false,
            "seccompProfilePath": "",
            "selinuxEnabled": false
        }"#;
        assert!(
            validate_runtime_security_options(RuntimeProvider::Podman, compatibility).is_ok(),
            "compatibility Podman may intentionally be rootful"
        );
        assert!(matches!(
            validate_runtime_security_options(RuntimeProvider::ManagedLocal, compatibility),
            Err(AppError::NotAuthorized(_))
        ));

        let docker = br#"["name=seccomp,profile=default","name=apparmor"]"#;
        assert_eq!(
            validate_runtime_security_options(RuntimeProvider::Docker, docker).unwrap(),
            r#"["name=seccomp,profile=default","name=apparmor"]"#
        );
        assert!(validate_runtime_security_options(RuntimeProvider::Docker, b"null").is_err());
        assert!(validate_runtime_security_options(RuntimeProvider::Docker, b"{}").is_err());

        for malformed in [
            &b""[..],
            &b"null"[..],
            &b"[]"[..],
            &b"{\"apparmorEnabled\":false}"[..],
            &b"{\"apparmorEnabled\":false,\"apparmorEnabled\":true}"[..],
            &b"{\"apparmorEnabled\":false} trailing"[..],
            &b"\xff"[..],
        ] {
            assert!(
                validate_runtime_security_options(RuntimeProvider::Podman, malformed).is_err(),
                "malformed Podman security information must fail closed"
            );
        }
        assert!(
            validate_runtime_security_options(
                RuntimeProvider::Podman,
                &vec![b' '; MAX_RUNTIME_SECURITY_OPTIONS_BYTES + 1],
            )
            .is_err()
        );

        let controlled = br#"{
            "apparmorEnabled": false,
            "capabilities": "CAP_CHOWN\u0000",
            "rootless": true,
            "seccompEnabled": true,
            "seccompProfilePath": "/profile",
            "selinuxEnabled": false
        }"#;
        assert!(
            validate_runtime_security_options(RuntimeProvider::ManagedLocal, controlled).is_err()
        );
    }

    #[cfg(unix)]
    #[test]
    fn process_preflight_invokes_the_exact_podman_security_selector() {
        let temp = tempfile::tempdir().expect("temporary runtime");
        let binary = temp.path().join("podman-fixture");
        let log = temp.path().join("commands.log");
        write_executable_fixture(
            &binary,
            r#"#!/bin/sh
set -eu
script_root=${0%/*}
printf '%s\n' "$*" >> "$script_root/commands.log"
case "$1" in
  version) printf '%s\n' '5.8.2' ;;
  info) printf '%s\n' '{"apparmorEnabled":false,"capabilities":"CAP_CHOWN","rootless":true,"seccompEnabled":true,"seccompProfilePath":"/profile","selinuxEnabled":false}' ;;
  *) exit 9 ;;
esac
"#,
        );

        let runtime = ProcessContainerRuntime::new(RuntimeProvider::Podman, &binary)
            .expect("construct compatibility runtime");
        let preflight = runtime.preflight().expect("Podman preflight");
        let reused = runtime
            .clone()
            .preflight()
            .expect("prepared runtime clone reuses the successful proof");

        assert_eq!(preflight.provider, RuntimeProvider::Podman);
        assert_eq!(preflight.server_version, "5.8.2");
        assert_eq!(
            preflight.security_options,
            r#"{"apparmorEnabled":false,"capabilities":"CAP_CHOWN","rootless":true,"seccompEnabled":true,"seccompProfilePath":"/profile","selinuxEnabled":false}"#
        );
        assert_eq!(reused, preflight);
        assert_eq!(
            fs::read_to_string(log).expect("runtime command log"),
            "version --format {{.Server.Version}}\ninfo --format {{json .Host.Security}}\n"
        );
    }

    #[cfg(unix)]
    #[test]
    fn execution_preflight_refreshes_daemon_version_and_security_with_one_query() {
        let temp = tempfile::tempdir().expect("temporary runtime");
        let binary = temp.path().join("podman-fixture");
        let log = temp.path().join("commands.log");
        let execution_response = temp.path().join("execution.json");
        fs::write(
            &execution_response,
            r#"{"serverVersion":"5.9.0","securityOptions":{"apparmorEnabled":true,"capabilities":"CAP_CHOWN","rootless":true,"seccompEnabled":true,"seccompProfilePath":"/new-profile","selinuxEnabled":false}}"#,
        )
        .expect("write execution response");
        write_executable_fixture(
            &binary,
            r#"#!/bin/sh
set -eu
script_root=${0%/*}
printf '%s\n' "$*" >> "$script_root/commands.log"
case "$1" in
  version) printf '%s\n' '5.8.2' ;;
  info)
    case "$*" in
      *serverVersion*) cat "$script_root/execution.json" ;;
      *) printf '%s\n' '{"apparmorEnabled":false,"capabilities":"CAP_CHOWN","rootless":true,"seccompEnabled":true,"seccompProfilePath":"/old-profile","selinuxEnabled":false}' ;;
    esac
    ;;
  *) exit 9 ;;
esac
"#,
        );

        let runtime = ProcessContainerRuntime::new(RuntimeProvider::Podman, &binary)
            .expect("construct compatibility runtime");
        let prepared = runtime.preflight().expect("prepare-time preflight");
        assert_eq!(prepared.server_version, "5.8.2");
        assert!(prepared.security_options.contains("/old-profile"));

        let execution = runtime
            .execution_preflight()
            .expect("fresh execution preflight");
        assert_eq!(execution.server_version, "5.9.0");
        assert!(execution.security_options.contains("/new-profile"));
        assert_eq!(runtime.preflight().expect("refreshed cache"), execution);

        let repeated = runtime
            .execution_preflight()
            .expect("every execution refreshes again");
        assert_eq!(repeated, execution);
        assert_eq!(
            fs::read_to_string(log).expect("runtime command log"),
            concat!(
                "version --format {{.Server.Version}}\n",
                "info --format {{json .Host.Security}}\n",
                "info --format {\"serverVersion\":{{json .Version.Version}},\"securityOptions\":{{json .Host.Security}}}\n",
                "info --format {\"serverVersion\":{{json .Version.Version}},\"securityOptions\":{{json .Host.Security}}}\n",
            )
        );
    }

    fn manifest(command: Vec<String>) -> EngineManifest {
        EngineManifest {
            schema_version: "1".into(),
            id: "scanner".into(),
            display_name: "Scanner".into(),
            category: EngineCategory::CodeAndSecrets,
            description: "test".into(),
            repository_url: "https://example.invalid/scanner".into(),
            homepage_url: None,
            license_spdx: "Apache-2.0".into(),
            distribution_mode: DistributionMode::PullPinnedImage,
            image: Some(ImageReference {
                repository: "registry.example/scanner".into(),
                tag: None,
                digest: Some(format!("sha256:{}", "a".repeat(64))),
                signature_identity: None,
            }),
            source_revision: None,
            engine_version: Some("1.0".into()),
            reported_version: None,
            rule_version: Some("1".into()),
            adapter_version: "1".into(),
            supported_providers: vec![],
            supported_asset_kinds: vec![AssetKind::Repository],
            input_contracts: vec![],
            provider_execution_contracts: vec![],
            direct_network_contract: None,
            required_permissions: vec![ScanPermission::LocalArtifactRead],
            active_external: false,
            default_enabled: false,
            estimated_memory_mb: 512,
            estimated_disk_mb: 512,
            network_destinations: vec![],
            output_formats: vec!["json".into()],
            command,
            status: ManifestStatus::Integrated,
            notices: vec![],
            compatibility: EngineCompatibility {
                runnable: true,
                blocked_by: vec![],
                ..EngineCompatibility::default()
            },
            execution: None,
        }
    }

    fn plan_fixture(
        command: Vec<String>,
    ) -> (
        tempfile::TempDir,
        ArtifactStore,
        RunDirectories,
        PathBuf,
        EngineManifest,
        PinnedImage,
    ) {
        let temp = tempfile::tempdir().expect("temp directory");
        let store = ArtifactStore::open(temp.path().join("artifacts")).expect("store");
        let directories = store
            .prepare_run(
                &ArtifactContext {
                    case_id: "case-1".into(),
                    scan_run_id: "run-1".into(),
                    engine_run_id: "engine-run-1".into(),
                },
                1,
            )
            .expect("directories");
        let scope = store
            .write_control_json(
                &directories,
                "scope.json",
                &serde_json::json!({"assets": []}),
            )
            .expect("scope")
            .path;
        let manifest = manifest(command);
        let image = PinnedImage::from_manifest(&manifest).expect("image");
        (temp, store, directories, scope, manifest, image)
    }

    fn enable_naabu_launcher_v2(manifest: &mut EngineManifest) {
        manifest.id = NAABU_ENGINE_ID.into();
        manifest.command = NAABU_LAUNCHER_COMMAND
            .iter()
            .map(|part| (*part).to_owned())
            .collect();
        manifest.execution = Some(EngineExecutionContract {
            resources: EngineExecutionResources {
                timeout_seconds: 14_400,
                cpu_millis: 1_000,
            },
            launcher_journal_version: Some(LAUNCHER_V2_JOURNAL_SCHEMA_VERSION),
        });
    }

    fn enable_zap_automation_plan(manifest: &mut EngineManifest) {
        manifest.id = ZAP_ENGINE_ID.into();
        manifest.command = vec![
            "-cmd".into(),
            "-silent".into(),
            "-autorun".into(),
            CONTAINER_ZAP_PLAN_PATH.into(),
        ];
    }

    fn owned_cleanup_request(scope: &Path, image: &PinnedImage) -> OwnedContainerCleanupRequest {
        OwnedContainerCleanupRequest {
            case_id: "case-1".into(),
            scan_run_id: "run-1".into(),
            engine_run_id: "engine-run-1".into(),
            engine_id: "scanner".into(),
            attempt: 1,
            scope_sha256: hash_control_file(scope).expect("scope digest"),
            launcher_plan_sha256: None,
            zap_plan_sha256: None,
            image: image.clone(),
        }
    }

    #[cfg(unix)]
    fn owned_container_inspect(plan: &ContainerRunPlan, immutable_id: &str) -> Vec<u8> {
        let labels = plan
            .ownership()
            .expected_labels()
            .into_iter()
            .collect::<BTreeMap<_, _>>();
        serde_json::to_vec(&serde_json::json!([{
            "Id": immutable_id,
            "Name": plan.container_name(),
            "Config": {
                "Image": plan.image().reference(),
                "Labels": labels,
            }
        }]))
        .expect("owned container inspect JSON")
    }

    fn docker_network_inspect(internal: bool, policy_id: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!([{
            "Name": "ass-egress",
            "Id": "docker-network-id",
            "Driver": "bridge",
            "Internal": internal,
            "Labels": {
                (MANAGED_NETWORK_LABEL_KEY): "true",
                (NETWORK_POLICY_LABEL_KEY): policy_id,
            }
        }]))
        .expect("Docker network inspection JSON")
    }

    fn podman_network_inspect(internal: bool, policy_id: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!([{
            "name": "ass-egress",
            "id": "podman-network-id",
            "driver": "bridge",
            "internal": internal,
            "labels": {
                (MANAGED_NETWORK_LABEL_KEY): "true",
                (NETWORK_POLICY_LABEL_KEY): policy_id,
            }
        }]))
        .expect("Podman network inspection JSON")
    }

    /// Installs an executable fixture without this process ever holding a
    /// writable descriptor on it.
    ///
    /// `fs::write` opens the fixture for writing, and a `Command::spawn` on any
    /// other test thread can fork inside that window and inherit the descriptor
    /// until it execs. Linux refuses to exec a file that anyone holds open for
    /// writing, so the fixture intermittently failed with ETXTBSY ("Text file
    /// busy") in roughly one full-suite run in six. Retrying at the call sites
    /// would not work: the command logs are asserted byte for byte, and a
    /// partially executed attempt has already appended to them.
    ///
    /// Delegating the write to a child process keeps the writable descriptor
    /// out of this process entirely, so no fork of ours can inherit one. The
    /// child's own descriptor dies with it, before `wait` returns.
    #[cfg(unix)]
    fn write_executable_fixture(path: &Path, script: impl AsRef<[u8]>) {
        use std::io::Write;

        let mut installer = Command::new("/bin/sh")
            .arg("-c")
            .arg(r#"cat > "$1" && chmod 700 "$1""#)
            .arg("sh")
            .arg(path)
            .stdin(Stdio::piped())
            .spawn()
            .expect("spawn the fixture installer");
        installer
            .stdin
            .take()
            .expect("fixture installer stdin")
            .write_all(script.as_ref())
            .expect("stream the fixture script");
        let status = installer.wait().expect("await the fixture installer");
        assert!(
            status.success(),
            "the fixture installer failed for {}: {status:?}",
            path.display()
        );
    }

    #[cfg(unix)]
    fn fake_runtime(
        temp: &tempfile::TempDir,
        plan: &ContainerRunPlan,
        fail_pause: bool,
    ) -> (PathBuf, PathBuf) {
        let binary = temp.path().join("fake-container-runtime");
        let log = temp.path().join("fake-container-runtime.log");
        let response = temp.path().join("fake-container-inspect.json");
        let immutable_id = "c".repeat(64);
        fs::write(&response, owned_container_inspect(plan, &immutable_id))
            .expect("owned inspect fixture");
        let pause_exit = if fail_pause { "exit 23" } else { "exit 0" };
        let script = format!(
            "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\nprevious=''\nfor argument in \"$@\"; do\n  if [ \"$previous\" = --cidfile ]; then printf '%s\\n' '{}' > \"$argument\"; fi\n  previous=$argument\ndone\nif [ \"$1\" = container ] && [ \"$2\" = inspect ]; then /bin/cat '{}'; exit 0; fi
case \"$1\" in
  run) exec /bin/sleep 30 ;;
  pause) {pause_exit} ;;
  *) exit 0 ;;
esac\n",
            log.display(),
            immutable_id,
            response.display(),
        );
        write_executable_fixture(&binary, script);
        (binary, log)
    }

    #[cfg(unix)]
    fn fake_capture_runtime(
        temp: &tempfile::TempDir,
        plan: &ContainerRunPlan,
    ) -> (PathBuf, PathBuf) {
        let binary = temp.path().join("fake-capture-runtime");
        let log = temp.path().join("fake-capture-runtime.log");
        let response = temp.path().join("fake-capture-inspect.json");
        let immutable_id = "9".repeat(64);
        fs::write(&response, owned_container_inspect(plan, &immutable_id))
            .expect("owned inspect fixture");
        let script = format!(
            "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\nprevious=''\nfor argument in \"$@\"; do\n  if [ \"$previous\" = --cidfile ]; then printf '%s\\n' '{}' > \"$argument\"; fi\n  previous=$argument\ndone\nif [ \"$1\" = container ] && [ \"$2\" = inspect ]; then /bin/cat '{}'; exit 0; fi\ncase \"$1\" in\n  run) printf 'runtime-stdout\\n'; printf 'runtime-stderr\\n' >&2; exit 0 ;;\n  *) exit 0 ;;\nesac\n",
            log.display(),
            immutable_id,
            response.display(),
        );
        write_executable_fixture(&binary, script);
        (binary, log)
    }

    #[cfg(unix)]
    fn fake_inherited_capture_runtime(
        temp: &tempfile::TempDir,
        plan: &ContainerRunPlan,
    ) -> PathBuf {
        let binary = temp.path().join("fake-inherited-capture-runtime");
        let response = temp.path().join("fake-inherited-capture-inspect.json");
        let immutable_id = "8".repeat(64);
        fs::write(&response, owned_container_inspect(plan, &immutable_id))
            .expect("owned inspect fixture");
        let script = format!(
            "#!/bin/sh\nprevious=''\nfor argument in \"$@\"; do\n  if [ \"$previous\" = --cidfile ]; then printf '%s\\n' '{}' > \"$argument\"; fi\n  previous=$argument\ndone\nif [ \"$1\" = container ] && [ \"$2\" = inspect ]; then /bin/cat '{}'; exit 0; fi\ncase \"$1\" in\n  run) printf 'before-descendant\\n'; /bin/sleep 30 & exit 0 ;;\n  stop) exit 0 ;;\n  *) exit 0 ;;\nesac\n",
            immutable_id,
            response.display(),
        );
        write_executable_fixture(&binary, script);
        binary
    }

    #[cfg(unix)]
    fn fake_output_flood_runtime(
        temp: &tempfile::TempDir,
        plan: &ContainerRunPlan,
    ) -> (PathBuf, PathBuf) {
        let binary = temp.path().join("fake-output-flood-runtime");
        let log = temp.path().join("fake-output-flood-runtime.log");
        let response = temp.path().join("fake-output-flood-inspect.json");
        let immutable_id = "e".repeat(64);
        fs::write(&response, owned_container_inspect(plan, &immutable_id))
            .expect("owned inspect fixture");
        let script = format!(
            "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\nprevious=''\nfor argument in \"$@\"; do\n  if [ \"$previous\" = --cidfile ]; then printf '%s\\n' '{}' > \"$argument\"; fi\n  previous=$argument\ndone\nif [ \"$1\" = container ] && [ \"$2\" = inspect ]; then /bin/cat '{}'; exit 0; fi\ncase \"$1\" in\n  run) exec /bin/dd if=/dev/zero bs=65536 count=1024 2>/dev/null ;;\n  stop) exit 0 ;;\n  *) exit 0 ;;\nesac\n",
            log.display(),
            immutable_id,
            response.display(),
        );
        write_executable_fixture(&binary, script);
        (binary, log)
    }

    #[cfg(unix)]
    fn fake_name_collision_runtime(temp: &tempfile::TempDir) -> (PathBuf, PathBuf) {
        let binary = temp.path().join("fake-name-collision-runtime");
        let log = temp.path().join("fake-name-collision-runtime.log");
        let script = format!(
            "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\ncase \"$1\" in\n  run) exec /bin/sleep 30 ;;\n  *) exit 0 ;;\nesac\n",
            log.display(),
        );
        write_executable_fixture(&binary, script);
        (binary, log)
    }

    #[cfg(unix)]
    fn wait_for_executable_fixture(binary: &Path, label: &str) {
        // Hosted runners can briefly report ETXTBSY after creating an executable
        // fixture. Absorb it while publishing the fixture, never in runtime code.
        let deadline = Instant::now() + StdDuration::from_secs(1);
        loop {
            match Command::new(binary)
                .arg("__fixture_ready__")
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
            {
                Ok(status) => {
                    assert!(status.success(), "{label} readiness");
                    break;
                }
                Err(error)
                    if error.raw_os_error() == Some(libc::ETXTBSY) && Instant::now() < deadline =>
                {
                    thread::yield_now();
                }
                Err(error) => panic!("{label} readiness failed: {error}"),
            }
        }
    }

    #[cfg(unix)]
    fn fake_network_inspect_runtime(temp: &tempfile::TempDir) -> (PathBuf, PathBuf, PathBuf) {
        let binary = temp.path().join("fake-network-runtime");
        let log = temp.path().join("fake-network-runtime.log");
        let response = temp.path().join("network-inspect.json");
        let script = format!(
            "#!/bin/sh\nif [ \"$1\" = __fixture_ready__ ]; then exit 0; fi\nprintf '%s\\n' \"$*\" >> '{}'\nif [ \"$1\" = network ] && [ \"$2\" = inspect ] && [ \"$3\" = ass-egress ]; then\n  /bin/cat '{}'\n  exit 0\nfi\nexit 29\n",
            log.display(),
            response.display()
        );
        write_executable_fixture(&binary, script);
        wait_for_executable_fixture(&binary, "fake network runtime");
        (binary, log, response)
    }

    #[cfg(unix)]
    fn fake_owned_cleanup_runtime(temp: &tempfile::TempDir) -> (PathBuf, PathBuf, PathBuf) {
        let binary = temp.path().join("fake-owned-cleanup-runtime");
        let log = temp.path().join("fake-owned-cleanup-runtime.log");
        let response = temp.path().join("container-inspect.json");
        let script = format!(
            "#!/bin/sh\nif [ \"$1\" = __fixture_ready__ ]; then exit 0; fi\nprintf '%s\\n' \"$*\" >> '{}'\nif [ \"$1\" = container ] && [ \"$2\" = inspect ]; then\n  /bin/cat '{}'\n  exit 0\nfi\nif [ \"$1\" = rm ] && [ \"$2\" = --force ]; then\n  exit 0\nfi\nexit 29\n",
            log.display(),
            response.display()
        );
        write_executable_fixture(&binary, script);
        wait_for_executable_fixture(&binary, "fake owned cleanup runtime");
        (binary, log, response)
    }

    #[cfg(unix)]
    fn wait_until(mut predicate: impl FnMut() -> bool) {
        let deadline = Instant::now() + StdDuration::from_secs(5);
        while !predicate() {
            assert!(
                Instant::now() < deadline,
                "timed out waiting for runtime state"
            );
            thread::sleep(StdDuration::from_millis(5));
        }
    }

    #[test]
    fn image_digest_is_mandatory() {
        let mut manifest = manifest(vec!["scanner".into()]);
        manifest.image.as_mut().expect("image").digest = None;
        let error = PinnedImage::from_manifest(&manifest).expect_err("digest rejected");
        assert!(error.to_string().contains("sha256 digest"));
    }

    #[test]
    fn image_reference_cannot_be_interpreted_as_a_runtime_option() {
        let error = PinnedImage::new(
            "--platform=host/repository",
            &format!("sha256:{}", "a".repeat(64)),
        )
        .expect_err("option-like repository rejected");
        assert!(error.to_string().contains("repository is invalid"));
    }

    #[test]
    fn reviewed_execution_timeout_is_validated_and_propagated_into_the_run_plan() {
        let (_temp, _store, directories, scope, mut manifest, image) =
            plan_fixture(vec!["scanner".into()]);
        manifest.execution = Some(EngineExecutionContract {
            resources: EngineExecutionResources {
                timeout_seconds: 7_200,
                cpu_millis: 1_000,
            },
            launcher_journal_version: None,
        });
        let plan = ContainerPlanBuilder::new(
            &manifest,
            &image,
            &directories,
            &scope,
            &ResourceLimits::default(),
            &NetworkPolicy::Disabled,
            &ScannerCredentialSet::default(),
            "case-1",
            "run-1",
            "engine-run-1",
            1,
        )
        .build()
        .expect("reviewed timeout plan");
        assert_eq!(plan.execution_timeout_seconds(), 7_200);

        manifest.execution = None;
        let legacy_plan = ContainerPlanBuilder::new(
            &manifest,
            &image,
            &directories,
            &scope,
            &ResourceLimits::default(),
            &NetworkPolicy::Disabled,
            &ScannerCredentialSet::default(),
            "case-1",
            "run-1",
            "engine-run-1",
            1,
        )
        .build()
        .expect("legacy manifest fallback plan");
        assert_eq!(
            legacy_plan.execution_timeout_seconds(),
            crate::domain::DEFAULT_ENGINE_EXECUTION_TIMEOUT_SECONDS
        );

        for invalid in [29, 86_401] {
            manifest.execution = Some(EngineExecutionContract {
                resources: EngineExecutionResources {
                    timeout_seconds: invalid,
                    cpu_millis: 1_000,
                },
                launcher_journal_version: None,
            });
            let error = ContainerPlanBuilder::new(
                &manifest,
                &image,
                &directories,
                &scope,
                &ResourceLimits::default(),
                &NetworkPolicy::Disabled,
                &ScannerCredentialSet::default(),
                "case-1",
                "run-1",
                "engine-run-1",
                1,
            )
            .build()
            .expect_err("out-of-range execution timeout rejected");
            assert!(error.to_string().contains("between 30 and 86400 seconds"));
        }
    }

    #[test]
    fn interrupted_container_requires_complete_ownership_proof() {
        let (_temp, _store, _directories, scope, _manifest, image) =
            plan_fixture(vec!["scanner".into()]);
        let request = owned_cleanup_request(&scope, &image);
        let labels = request
            .expected_labels()
            .into_iter()
            .collect::<BTreeMap<_, _>>();
        let document = serde_json::to_vec(&serde_json::json!([{
            "Id": "b".repeat(64),
            "Name": format!("/{}", request.container_name().expect("name")),
            "Config": {
                "Image": request.image.reference(),
                "Labels": labels,
            }
        }]))
        .expect("inspect document");
        assert_eq!(
            prove_owned_container(&document, &request).unwrap(),
            "b".repeat(64)
        );

        let mut mismatched: serde_json::Value =
            serde_json::from_slice(&document).expect("inspect value");
        mismatched[0]["Config"]["Labels"][CONTAINER_CASE_LABEL_KEY] =
            serde_json::Value::String("other-case".into());
        let error = prove_owned_container(
            &serde_json::to_vec(&mismatched).expect("mismatch document"),
            &request,
        )
        .expect_err("foreign container rejected");
        assert!(error.to_string().contains(CONTAINER_CASE_LABEL_KEY));
    }

    #[test]
    fn launcher_v2_cleanup_requires_the_exact_digest_label() {
        let (_temp, _store, _directories, scope, _manifest, image) =
            plan_fixture(vec!["scanner".into()]);
        let mut request = owned_cleanup_request(&scope, &image);
        let expected_digest = "c".repeat(64);
        request.engine_id = NAABU_ENGINE_ID.into();
        request.launcher_plan_sha256 = Some(expected_digest);
        let exact_labels = request.expected_labels();
        let document = |labels: BTreeMap<&'static str, String>| {
            serde_json::to_vec(&serde_json::json!([{
                "Id": "b".repeat(64),
                "Name": request.container_name().expect("name"),
                "Config": {
                    "Image": request.image.reference(),
                    "Labels": labels,
                }
            }]))
            .expect("inspect document")
        };

        assert_eq!(
            prove_owned_container(&document(exact_labels.clone()), &request)
                .expect("exact launcher digest label"),
            "b".repeat(64)
        );

        let mut missing = exact_labels.clone();
        missing.remove(CONTAINER_NAABU_LAUNCHER_PLAN_LABEL_KEY);
        let missing_error = prove_owned_container(&document(missing), &request)
            .expect_err("missing launcher digest label rejected");
        assert!(
            missing_error
                .to_string()
                .contains(CONTAINER_NAABU_LAUNCHER_PLAN_LABEL_KEY)
        );

        let mut foreign = exact_labels;
        foreign.insert(CONTAINER_NAABU_LAUNCHER_PLAN_LABEL_KEY, "d".repeat(64));
        let foreign_error = prove_owned_container(&document(foreign), &request)
            .expect_err("foreign launcher digest label rejected");
        assert!(
            foreign_error
                .to_string()
                .contains(CONTAINER_NAABU_LAUNCHER_PLAN_LABEL_KEY)
        );
    }

    #[test]
    fn legacy_cleanup_refuses_an_unexpected_launcher_digest_label() {
        let (_temp, _store, _directories, scope, _manifest, image) =
            plan_fixture(vec!["scanner".into()]);
        let request = owned_cleanup_request(&scope, &image);
        let mut labels = request.expected_labels();
        labels.insert(CONTAINER_NAABU_LAUNCHER_PLAN_LABEL_KEY, "e".repeat(64));
        let document = serde_json::to_vec(&serde_json::json!([{
            "Id": "b".repeat(64),
            "Name": request.container_name().expect("name"),
            "Config": {
                "Image": request.image.reference(),
                "Labels": labels,
            }
        }]))
        .expect("inspect document");

        let error = prove_owned_container(&document, &request)
            .expect_err("unexpected launcher ownership label rejected");
        assert!(
            error
                .to_string()
                .contains(CONTAINER_NAABU_LAUNCHER_PLAN_LABEL_KEY)
        );
    }

    #[test]
    fn cleanup_refuses_an_unexpected_zap_plan_label() {
        let (_temp, _store, _directories, scope, _manifest, image) =
            plan_fixture(vec!["scanner".into()]);
        let request = owned_cleanup_request(&scope, &image);
        let mut labels = request.expected_labels();
        labels.insert(CONTAINER_ZAP_PLAN_LABEL_KEY, "e".repeat(64));
        let document = serde_json::to_vec(&serde_json::json!([{
            "Id": "b".repeat(64),
            "Name": request.container_name().expect("name"),
            "Config": {
                "Image": request.image.reference(),
                "Labels": labels,
            }
        }]))
        .expect("inspect document");

        let error = prove_owned_container(&document, &request)
            .expect_err("unexpected ZAP plan ownership label rejected");
        assert!(error.to_string().contains(CONTAINER_ZAP_PLAN_LABEL_KEY));
    }

    #[test]
    fn launcher_cleanup_digest_must_be_lowercase_sha256() {
        let (_temp, _store, _directories, scope, _manifest, image) =
            plan_fixture(vec!["scanner".into()]);
        let mut request = owned_cleanup_request(&scope, &image);
        request.engine_id = NAABU_ENGINE_ID.into();
        request.launcher_plan_sha256 = Some("A".repeat(64));

        let error = request
            .container_name()
            .expect_err("uppercase launcher digest rejected");
        assert!(error.to_string().contains("launcher plan digest"));
    }

    #[test]
    fn launcher_cleanup_digest_is_rejected_for_a_non_naabu_owner() {
        let (_temp, _store, _directories, scope, _manifest, image) =
            plan_fixture(vec!["scanner".into()]);
        let mut request = owned_cleanup_request(&scope, &image);
        request.launcher_plan_sha256 = Some("a".repeat(64));

        let error = request
            .container_name()
            .expect_err("non-Naabu launcher digest rejected");
        assert!(error.to_string().contains("only for owned Naabu"));
    }

    #[test]
    fn zap_plan_cleanup_digest_requires_the_zap_engine() {
        let (_temp, _store, _directories, scope, _manifest, image) =
            plan_fixture(vec!["scanner".into()]);
        let mut request = owned_cleanup_request(&scope, &image);
        let digest = "a".repeat(64);
        request.zap_plan_sha256 = Some(digest.clone());

        let error = request
            .container_name()
            .expect_err("non-ZAP plan digest rejected");
        assert!(error.to_string().contains("only for owned ZAP"));

        request.engine_id = ZAP_ENGINE_ID.into();
        request.zap_plan_sha256 = Some("A".repeat(64));
        let error = request
            .container_name()
            .expect_err("uppercase ZAP plan digest rejected");
        assert!(error.to_string().contains("ZAP automation plan digest"));

        request.zap_plan_sha256 = Some(digest.clone());
        request
            .validate()
            .expect("ZAP plan digest is valid for owned ZAP cleanup");
        assert_eq!(
            request.expected_labels().get(CONTAINER_ZAP_PLAN_LABEL_KEY),
            Some(&digest)
        );
    }

    #[test]
    fn owned_container_image_proof_accepts_default_registry_canonicalization() {
        let (_temp, _store, _directories, scope, _manifest, _image) =
            plan_fixture(vec!["scanner".into()]);
        let digest = format!("sha256:{}", "a".repeat(64));
        let image = PinnedImage::new("checkmarx/kics", &digest).expect("KICS image");
        let request = owned_cleanup_request(&scope, &image);
        let labels = request
            .expected_labels()
            .into_iter()
            .collect::<BTreeMap<_, _>>();
        let document = serde_json::to_vec(&serde_json::json!([{
            "Id": "c".repeat(64),
            "Name": request.container_name().expect("name"),
            "ImageName": format!("docker.io/checkmarx/kics@{digest}"),
            "Config": {
                "Image": format!("sha256:{}", "d".repeat(64)),
                "Labels": labels,
            }
        }]))
        .expect("inspect document");

        assert_eq!(
            prove_owned_container(&document, &request).expect("canonical image accepted"),
            "c".repeat(64)
        );
    }

    #[test]
    fn owned_container_image_proof_rejects_tag_digest_and_repository_mismatches() {
        let (_temp, _store, _directories, scope, _manifest, _image) =
            plan_fixture(vec!["scanner".into()]);
        let digest = format!("sha256:{}", "a".repeat(64));
        let image = PinnedImage::new("checkmarx/kics", &digest).expect("KICS image");
        let request = owned_cleanup_request(&scope, &image);

        for mismatched_reference in [
            format!("docker.io/checkmarx/kics:v2.1.19@{digest}"),
            format!("docker.io/checkmarx/kics@sha256:{}", "b".repeat(64)),
            format!("docker.io/checkmarx/not-kics@{digest}"),
            format!("ghcr.io/checkmarx/kics@{digest}"),
        ] {
            let labels = request
                .expected_labels()
                .into_iter()
                .collect::<BTreeMap<_, _>>();
            let document = serde_json::to_vec(&serde_json::json!([{
                "Id": "e".repeat(64),
                "Name": request.container_name().expect("name"),
                "ImageName": mismatched_reference,
                "Config": {
                    "Image": null,
                    "Labels": labels,
                }
            }]))
            .expect("inspect document");
            let error = prove_owned_container(&document, &request)
                .expect_err("mismatched image reference rejected");
            assert!(
                error
                    .to_string()
                    .contains("container image does not match the persisted pinned image"),
                "unexpected error for mismatched image reference: {error}"
            );
        }
    }

    #[test]
    fn fake_cleanup_can_model_a_foreign_same_name_ownership_mismatch() {
        let (_temp, _store, _directories, scope, _manifest, image) =
            plan_fixture(vec!["scanner".into()]);
        let request = owned_cleanup_request(&scope, &image);
        let runtime = FakeContainerRuntime::default();
        runtime.set_foreign_cleanup_mismatch(true);

        let error = runtime
            .cleanup(&request, None)
            .expect_err("foreign same-name cleanup must be refused");

        assert!(matches!(&error, AppError::NotAuthorized(_)));
        assert!(
            error
                .to_string()
                .contains("fake foreign ownership mismatch")
        );
    }

    #[cfg(unix)]
    #[test]
    fn owned_cleanup_removes_the_inspected_immutable_object_id() {
        let (temp, _store, _directories, scope, _manifest, image) =
            plan_fixture(vec!["scanner".into()]);
        let request = owned_cleanup_request(&scope, &image);
        let immutable_id = "d".repeat(64);
        let labels = request
            .expected_labels()
            .into_iter()
            .collect::<BTreeMap<_, _>>();
        let (binary, log, response) = fake_owned_cleanup_runtime(&temp);
        fs::write(
            response,
            serde_json::to_vec(&serde_json::json!([{
                "Id": immutable_id,
                "Name": request.container_name().expect("name"),
                "Config": {
                    "Image": request.image.reference(),
                    "Labels": labels,
                }
            }]))
            .expect("inspect document"),
        )
        .expect("inspect fixture");
        let runtime = ProcessContainerRuntime::new(RuntimeProvider::Docker, binary)
            .expect("construct compatibility runtime");
        assert!(runtime.cleanup_owned_container(&request).unwrap().removed);
        let commands = fs::read_to_string(log).expect("runtime log");
        assert!(commands.lines().any(|line| {
            line == format!(
                "container inspect {}",
                request.container_name().expect("name")
            )
        }));
        assert!(
            commands
                .lines()
                .any(|line| line == format!("rm --force {}", "d".repeat(64)))
        );
    }

    #[cfg(unix)]
    #[test]
    fn resume_cleanup_refuses_a_foreign_same_name_container_without_removing_it() {
        let (temp, _store, _directories, scope, _manifest, image) =
            plan_fixture(vec!["scanner".into()]);
        let request = owned_cleanup_request(&scope, &image);
        let mut labels = request
            .expected_labels()
            .into_iter()
            .collect::<BTreeMap<_, _>>();
        labels.insert(CONTAINER_CASE_LABEL_KEY, "foreign-case".into());
        let (binary, log, response) = fake_owned_cleanup_runtime(&temp);
        fs::write(
            response,
            serde_json::to_vec(&serde_json::json!([{
                "Id": "7".repeat(64),
                "Name": request.container_name().expect("name"),
                "Config": {
                    "Image": request.image.reference(),
                    "Labels": labels,
                }
            }]))
            .expect("inspect document"),
        )
        .expect("inspect fixture");
        let runtime = ProcessContainerRuntime::new(RuntimeProvider::Docker, binary)
            .expect("construct compatibility runtime");

        let error = runtime
            .cleanup_owned_container(&request)
            .expect_err("foreign container must not be removed");

        assert!(error.to_string().contains(CONTAINER_CASE_LABEL_KEY));
        let commands = fs::read_to_string(log).expect("runtime log");
        assert!(
            commands
                .lines()
                .any(|line| line.starts_with("container inspect "))
        );
        assert!(!commands.lines().any(|line| line.starts_with("rm --force ")));
    }

    #[cfg(unix)]
    #[test]
    fn created_container_cleanup_inspects_and_removes_only_the_tracked_id() {
        let (temp, _store, _directories, scope, _manifest, image) =
            plan_fixture(vec!["scanner".into()]);
        let request = owned_cleanup_request(&scope, &image);
        let immutable_id = "9".repeat(64);
        let labels = request
            .expected_labels()
            .into_iter()
            .collect::<BTreeMap<_, _>>();
        let (binary, log, response) = fake_owned_cleanup_runtime(&temp);
        fs::write(
            response,
            serde_json::to_vec(&serde_json::json!([{
                "Id": immutable_id,
                "Name": request.container_name().expect("name"),
                "Config": {
                    "Image": request.image.reference(),
                    "Labels": labels,
                }
            }]))
            .expect("inspect document"),
        )
        .expect("inspect fixture");
        let runtime = ProcessContainerRuntime::new(RuntimeProvider::Docker, binary)
            .expect("construct compatibility runtime");
        let created = CreatedContainer::from_runtime_id(&"9".repeat(64)).expect("created ID");

        assert!(runtime.cleanup(&request, Some(&created)).unwrap().removed);

        let commands = fs::read_to_string(log).expect("runtime log");
        assert!(
            commands
                .lines()
                .any(|line| line == format!("container inspect {}", "9".repeat(64)))
        );
        assert!(
            commands
                .lines()
                .any(|line| line == format!("rm --force {}", "9".repeat(64)))
        );
        assert!(!commands.lines().any(|line| {
            line == format!(
                "rm --force {}",
                request.container_name().expect("container name")
            )
        }));
    }

    #[cfg(unix)]
    #[test]
    fn inherited_output_pipe_is_bounded_and_its_process_group_is_terminated() {
        let temp = tempfile::tempdir().expect("temp directory");
        let pid_file = temp.path().join("descendant.pid");
        let mut command = Command::new("/bin/sh");
        command
            .arg("-c")
            .arg("/bin/sleep 30 & child=$!; printf '%s' \"$child\" > \"$PID_FILE\"")
            .env("PID_FILE", &pid_file);
        let started = Instant::now();

        let error = bounded_command_output(&mut command, 1024, StdDuration::from_millis(250))
            .expect_err("inherited pipe must not outlive the command deadline");

        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(
            started.elapsed() < StdDuration::from_secs(3),
            "bounded drain must return promptly"
        );
        let pid = fs::read_to_string(pid_file)
            .expect("descendant pid")
            .parse::<i32>()
            .expect("numeric descendant pid");
        wait_until(|| unsafe {
            libc::kill(pid, 0) == -1
                && io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
        });
    }

    #[test]
    fn credential_envelope_validation_failure_removes_the_created_file() {
        let temp = tempfile::tempdir().expect("private test directory");
        let path = temp.path().join("credential.json");
        let credentials = ScannerCredentialSet::new(vec![
            ScannerCredential::ephemeral_read_only(
                "AWS_SESSION_TOKEN",
                "x".repeat(MAX_CREDENTIAL_DOCUMENT_BYTES as usize + 1),
                Utc::now() + Duration::minutes(10),
                CredentialSource::EphemeralScanRole,
            )
            .expect("test credential"),
        ])
        .expect("test credential set");

        assert!(credentials.write_envelope(&path).is_err());
        assert!(
            !path.exists(),
            "failed creation must not leave secret bytes"
        );
    }

    #[test]
    fn credential_envelope_creation_never_removes_an_existing_file() {
        let temp = tempfile::tempdir().expect("private test directory");
        let path = temp.path().join("existing.json");
        fs::write(&path, b"unrelated data").expect("existing file");

        assert!(
            ScannerCredentialSet::default()
                .write_envelope(&path)
                .is_err()
        );
        assert_eq!(fs::read(&path).unwrap(), b"unrelated data");
    }

    #[test]
    fn crash_left_credential_envelopes_are_bounded_and_zeroized() {
        let (_temp, store, directories, scope, _manifest, image) =
            plan_fixture(vec!["scanner".into()]);
        let credential = directories
            .control
            .join(format!("credentials-{}.json", "c".repeat(32)));
        fs::write(&credential, b"highly-sensitive-test-value").expect("orphan credential");
        let request = owned_cleanup_request(&scope, &image);
        assert_eq!(
            cleanup_orphaned_credentials(store.root(), &request).expect("credential cleanup"),
            1
        );
        assert!(!credential.exists());
        assert!(scope.exists(), "non-credential control files remain intact");
    }

    #[test]
    fn plan_image_must_match_the_manifest_digest() {
        let (_temp, _store, directories, scope, manifest, _image) =
            plan_fixture(vec!["scanner".into()]);
        let other_image = PinnedImage::new(
            "registry.example/scanner",
            &format!("sha256:{}", "b".repeat(64)),
        )
        .expect("other pinned image");
        let error = ContainerPlanBuilder::new(
            &manifest,
            &other_image,
            &directories,
            &scope,
            &ResourceLimits::default(),
            &NetworkPolicy::Disabled,
            &ScannerCredentialSet::default(),
            "case-1",
            "run-1",
            "engine-run-1",
            1,
        )
        .build()
        .expect_err("manifest mismatch rejected");
        assert!(error.to_string().contains("does not match"));
    }

    #[test]
    fn plan_has_hardening_and_only_fixed_mounts() {
        let (_temp, _store, directories, scope, manifest, image) =
            plan_fixture(vec!["scanner".into(), "--json".into()]);
        let credentials = ScannerCredentialSet::new(vec![
            ScannerCredential::ephemeral_read_only(
                "AWS_SESSION_TOKEN",
                "do-not-put-this-in-argv",
                Utc::now() + Duration::minutes(10),
                CredentialSource::EphemeralScanRole,
            )
            .expect("credential"),
        ])
        .expect("credential set");
        let plan = ContainerPlanBuilder::new(
            &manifest,
            &image,
            &directories,
            &scope,
            &ResourceLimits::default(),
            &NetworkPolicy::Disabled,
            &credentials,
            "case-1",
            "run-1",
            "engine-run-1",
            1,
        )
        .build()
        .expect("plan");

        assert!(plan.runtime_args.contains(&"--read-only".into()));
        assert!(plan.runtime_args.contains(&"--cap-drop=ALL".into()));
        assert!(
            plan.runtime_args
                .contains(&"--security-opt=no-new-privileges:true".into())
        );
        assert!(plan.runtime_args.contains(&"--pids-limit".into()));
        assert!(plan.runtime_args.contains(&"--memory".into()));
        assert!(plan.runtime_args.contains(&"--cpus".into()));
        assert!(plan.runtime_args.windows(2).any(|arguments| {
            arguments[0] == "--ulimit"
                && arguments[1] == format!("fsize={0}:{0}", ResourceLimits::default().output_bytes)
        }));
        assert_eq!(
            plan.runtime_args
                .iter()
                .filter(|argument| argument.as_str() == "--log-driver=none")
                .count(),
            1
        );
        assert!(plan.runtime_args.windows(2).any(|arguments| {
            arguments[0] == "--tmpfs"
                && arguments[1] == "/tmp:rw,noexec,nosuid,nodev,mode=1777,size=64m"
        }));
        assert_eq!(
            plan.runtime_args
                .iter()
                .filter(|argument| argument.as_str() == "--mount")
                .count(),
            3
        );
        assert!(
            plan.runtime_args
                .iter()
                .all(|argument| !argument.contains("do-not-put-this-in-argv"))
        );
        assert!(!plan.runtime_args.iter().any(|argument| argument == "--env"));
        assert!(plan.ownership().launcher_plan_sha256.is_none());
        assert!(
            !plan
                .ownership()
                .expected_labels()
                .contains_key(CONTAINER_NAABU_LAUNCHER_PLAN_LABEL_KEY)
        );
        assert!(
            !plan
                .runtime_args
                .iter()
                .any(|argument| argument.starts_with(CONTAINER_NAABU_LAUNCHER_PLAN_LABEL_KEY))
        );
    }

    #[test]
    fn naabu_launcher_v2_plan_has_one_exact_read_only_control_mount() {
        let (_temp, store, directories, scope, mut manifest, _) =
            plan_fixture(vec!["scanner".into()]);
        enable_naabu_launcher_v2(&mut manifest);
        let image = PinnedImage::from_manifest(&manifest).expect("Naabu image");
        let launcher_plan = store
            .write_control_json(
                &directories,
                NAABU_LAUNCHER_PLAN_CONTROL_FILE,
                &serde_json::json!({
                    "schema_version": 2,
                    "engine_id": "naabu",
                    "engine_run_id": "engine-run-1",
                    "execution_attempt": 1,
                    "frozen_grants": [],
                    "requested_work_units": []
                }),
            )
            .expect("launcher plan");
        let plan = ContainerPlanBuilder::new(
            &manifest,
            &image,
            &directories,
            &scope,
            &ResourceLimits::default(),
            &NetworkPolicy::Disabled,
            &ScannerCredentialSet::default(),
            "case-1",
            "run-1",
            "engine-run-1",
            1,
        )
        .with_launcher_plan_file(Some(&launcher_plan.path))
        .build()
        .expect("launcher-v2 run plan");

        let canonical = fs::canonicalize(&launcher_plan.path).expect("canonical plan");
        assert_eq!(plan.launcher_plan_file(), Some(canonical.as_path()));
        let expected_digest = hash_bounded_control_file(
            &canonical,
            MAX_NAABU_LAUNCHER_PLAN_BYTES as u64,
            "Naabu launcher plan",
        )
        .expect("launcher digest");
        assert_eq!(plan.launcher_plan_sha256(), Some(expected_digest.as_str()));
        assert_eq!(
            plan.ownership().launcher_plan_sha256.as_deref(),
            Some(expected_digest.as_str())
        );
        assert_eq!(
            plan.ownership()
                .expected_labels()
                .get(CONTAINER_NAABU_LAUNCHER_PLAN_LABEL_KEY),
            Some(&expected_digest)
        );
        let expected_label = format!("{CONTAINER_NAABU_LAUNCHER_PLAN_LABEL_KEY}={expected_digest}");
        assert_eq!(
            plan.runtime_args
                .windows(2)
                .filter_map(|arguments| {
                    (arguments[0] == "--label"
                        && arguments[1].starts_with(CONTAINER_NAABU_LAUNCHER_PLAN_LABEL_KEY))
                    .then_some(arguments[1].as_str())
                })
                .collect::<Vec<_>>(),
            [expected_label.as_str()]
        );
        let expected_mount =
            bind_mount(&canonical, CONTAINER_NAABU_LAUNCHER_PLAN_PATH, true).expect("mount");
        assert_eq!(
            plan.runtime_args
                .windows(2)
                .filter_map(|arguments| {
                    (arguments[0] == "--mount"
                        && arguments[1].contains(CONTAINER_NAABU_LAUNCHER_PLAN_PATH))
                    .then_some(arguments[1].as_str())
                })
                .collect::<Vec<_>>(),
            [expected_mount.as_str()]
        );
        let image_index = plan
            .runtime_args
            .iter()
            .position(|argument| argument == &image.reference())
            .expect("image argument");
        assert_eq!(
            plan.runtime_args[image_index + 1..],
            NAABU_LAUNCHER_COMMAND.map(str::to_owned)
        );
        validate_run_plan_integrity(&plan).expect("immutable launcher plan");
    }

    #[test]
    fn launcher_plan_and_manifest_must_opt_in_together() {
        let (_temp, store, directories, scope, mut manifest, image) =
            plan_fixture(vec!["scanner".into()]);
        let launcher_plan = store
            .write_control_json(
                &directories,
                NAABU_LAUNCHER_PLAN_CONTROL_FILE,
                &serde_json::json!({"schema_version": 2}),
            )
            .expect("launcher plan");

        let error = ContainerPlanBuilder::new(
            &manifest,
            &image,
            &directories,
            &scope,
            &ResourceLimits::default(),
            &NetworkPolicy::Disabled,
            &ScannerCredentialSet::default(),
            "case-1",
            "run-1",
            "engine-run-1",
            1,
        )
        .with_launcher_plan_file(Some(&launcher_plan.path))
        .build()
        .expect_err("legacy engine cannot gain a sidecar");
        assert!(error.to_string().contains("legacy engine contract"));

        let mut undeclared = manifest.clone();
        undeclared.command.push("--journal-version=2".into());
        let undeclared_image = PinnedImage::from_manifest(&undeclared).expect("legacy image");
        let error = ContainerPlanBuilder::new(
            &undeclared,
            &undeclared_image,
            &directories,
            &scope,
            &ResourceLimits::default(),
            &NetworkPolicy::Disabled,
            &ScannerCredentialSet::default(),
            "case-1",
            "run-1",
            "engine-run-1",
            1,
        )
        .build()
        .expect_err("undeclared equals-form launcher flag rejected");
        assert!(error.to_string().contains("require an explicit reviewed"));

        enable_naabu_launcher_v2(&mut manifest);
        let image = PinnedImage::from_manifest(&manifest).expect("Naabu image");
        let error = ContainerPlanBuilder::new(
            &manifest,
            &image,
            &directories,
            &scope,
            &ResourceLimits::default(),
            &NetworkPolicy::Disabled,
            &ScannerCredentialSet::default(),
            "case-1",
            "run-1",
            "engine-run-1",
            1,
        )
        .build()
        .expect_err("v2 manifest requires a sidecar");
        assert!(
            error
                .to_string()
                .contains("requires its private execution plan")
        );
    }

    #[test]
    fn changed_naabu_launcher_plan_is_rejected_before_runtime_creation() {
        let (_temp, store, directories, scope, mut manifest, _) =
            plan_fixture(vec!["scanner".into()]);
        enable_naabu_launcher_v2(&mut manifest);
        let image = PinnedImage::from_manifest(&manifest).expect("Naabu image");
        let launcher_plan = store
            .write_control_json(
                &directories,
                NAABU_LAUNCHER_PLAN_CONTROL_FILE,
                &serde_json::json!({"schema_version": 2}),
            )
            .expect("launcher plan");
        let plan = ContainerPlanBuilder::new(
            &manifest,
            &image,
            &directories,
            &scope,
            &ResourceLimits::default(),
            &NetworkPolicy::Disabled,
            &ScannerCredentialSet::default(),
            "case-1",
            "run-1",
            "engine-run-1",
            1,
        )
        .with_launcher_plan_file(Some(&launcher_plan.path))
        .build()
        .expect("launcher-v2 run plan");

        restrict_secret_file(&launcher_plan.path, false).expect("make test sidecar writable");
        fs::write(
            &launcher_plan.path,
            br#"{"schema_version":2,"changed":true}"#,
        )
        .expect("mutate sidecar");
        let error = validate_run_plan_integrity(&plan).expect_err("changed sidecar rejected");
        assert!(
            error
                .to_string()
                .contains("changed after the immutable run plan")
        );
    }

    #[test]
    fn zap_plan_has_one_exact_read_only_control_mount() {
        let (_temp, store, directories, scope, mut manifest, _) =
            plan_fixture(vec!["scanner".into()]);
        enable_zap_automation_plan(&mut manifest);
        let image = PinnedImage::from_manifest(&manifest).expect("ZAP image");
        let zap_plan = store
            .write_control_json(
                &directories,
                ZAP_PLAN_CONTROL_FILE,
                &serde_json::json!({"jobs": []}),
            )
            .expect("zap plan");
        let plan = ContainerPlanBuilder::new(
            &manifest,
            &image,
            &directories,
            &scope,
            &ResourceLimits::default(),
            &NetworkPolicy::Disabled,
            &ScannerCredentialSet::default(),
            "case-1",
            "run-1",
            "engine-run-1",
            1,
        )
        .with_zap_plan_file(Some(&zap_plan.path))
        .build()
        .expect("zap run plan");

        let canonical = fs::canonicalize(&zap_plan.path).expect("canonical plan");
        assert_eq!(plan.zap_plan_file(), Some(canonical.as_path()));
        let expected_digest =
            hash_bounded_control_file(&canonical, MAX_ZAP_PLAN_BYTES as u64, "ZAP automation plan")
                .expect("zap plan digest");
        assert_eq!(plan.zap_plan_sha256(), Some(expected_digest.as_str()));
        assert_eq!(
            plan.ownership().zap_plan_sha256.as_deref(),
            Some(expected_digest.as_str())
        );
        assert_eq!(
            plan.ownership()
                .expected_labels()
                .get(CONTAINER_ZAP_PLAN_LABEL_KEY),
            Some(&expected_digest)
        );
        let expected_label = format!("{CONTAINER_ZAP_PLAN_LABEL_KEY}={expected_digest}");
        assert_eq!(
            plan.runtime_args
                .windows(2)
                .filter_map(|arguments| {
                    (arguments[0] == "--label"
                        && arguments[1].starts_with(CONTAINER_ZAP_PLAN_LABEL_KEY))
                    .then_some(arguments[1].as_str())
                })
                .collect::<Vec<_>>(),
            [expected_label.as_str()]
        );
        let expected_mount = bind_mount(&canonical, CONTAINER_ZAP_PLAN_PATH, true).expect("mount");
        assert_eq!(
            plan.runtime_args
                .windows(2)
                .filter_map(|arguments| {
                    (arguments[0] == "--mount" && arguments[1].contains(CONTAINER_ZAP_PLAN_PATH))
                        .then_some(arguments[1].as_str())
                })
                .collect::<Vec<_>>(),
            [expected_mount.as_str()]
        );
        let image_index = plan
            .runtime_args
            .iter()
            .position(|argument| argument == &image.reference())
            .expect("image argument");
        assert_eq!(plan.runtime_args[image_index + 1..], manifest.command);
        validate_run_plan_integrity(&plan).expect("immutable zap plan");
    }

    #[test]
    fn zap_plan_must_use_the_fixed_control_path() {
        let (_temp, store, directories, scope, mut manifest, _) =
            plan_fixture(vec!["scanner".into()]);
        enable_zap_automation_plan(&mut manifest);
        let image = PinnedImage::from_manifest(&manifest).expect("ZAP image");
        let other_plan = store
            .write_control_json(
                &directories,
                "other-plan.yaml",
                &serde_json::json!({"jobs": []}),
            )
            .expect("misplaced zap plan");
        let error = ContainerPlanBuilder::new(
            &manifest,
            &image,
            &directories,
            &scope,
            &ResourceLimits::default(),
            &NetworkPolicy::Disabled,
            &ScannerCredentialSet::default(),
            "case-1",
            "run-1",
            "engine-run-1",
            1,
        )
        .with_zap_plan_file(Some(&other_plan.path))
        .build()
        .expect_err("zap plan outside the fixed control path rejected");
        assert!(
            error
                .to_string()
                .contains("fixed product-owned control path")
        );
    }

    #[test]
    fn zap_manifest_that_names_the_plan_requires_the_generated_file() {
        let (_temp, _store, directories, scope, mut manifest, _) =
            plan_fixture(vec!["scanner".into()]);
        enable_zap_automation_plan(&mut manifest);
        let image = PinnedImage::from_manifest(&manifest).expect("ZAP image");
        let error = ContainerPlanBuilder::new(
            &manifest,
            &image,
            &directories,
            &scope,
            &ResourceLimits::default(),
            &NetworkPolicy::Disabled,
            &ScannerCredentialSet::default(),
            "case-1",
            "run-1",
            "engine-run-1",
            1,
        )
        .build()
        .expect_err("named zap plan path requires the generated file");
        assert!(error.to_string().contains("requires its generated plan"));
    }

    #[test]
    fn zap_plan_file_is_rejected_for_a_non_zap_manifest() {
        let (_temp, store, directories, scope, manifest, image) =
            plan_fixture(vec!["scanner".into()]);
        let zap_plan = store
            .write_control_json(
                &directories,
                ZAP_PLAN_CONTROL_FILE,
                &serde_json::json!({"jobs": []}),
            )
            .expect("zap plan");
        let error = ContainerPlanBuilder::new(
            &manifest,
            &image,
            &directories,
            &scope,
            &ResourceLimits::default(),
            &NetworkPolicy::Disabled,
            &ScannerCredentialSet::default(),
            "case-1",
            "run-1",
            "engine-run-1",
            1,
        )
        .with_zap_plan_file(Some(&zap_plan.path))
        .build()
        .expect_err("non-ZAP engine cannot receive a zap plan");
        assert!(
            error
                .to_string()
                .contains("supported only by the reviewed ZAP contract")
        );
    }

    #[test]
    fn zap_plan_path_is_reserved_for_the_zap_manifest() {
        let (_temp, _store, directories, scope, manifest, image) =
            plan_fixture(vec!["-autorun".into(), CONTAINER_ZAP_PLAN_PATH.into()]);
        let error = ContainerPlanBuilder::new(
            &manifest,
            &image,
            &directories,
            &scope,
            &ResourceLimits::default(),
            &NetworkPolicy::Disabled,
            &ScannerCredentialSet::default(),
            "case-1",
            "run-1",
            "engine-run-1",
            1,
        )
        .build()
        .expect_err("non-ZAP command cannot name the zap plan path");
        assert!(
            error
                .to_string()
                .contains("reserved for the reviewed ZAP contract")
        );
    }

    #[test]
    fn zap_plan_must_be_invoked_at_the_product_owned_path() {
        let (_temp, store, directories, scope, mut manifest, _) =
            plan_fixture(vec!["scanner".into()]);
        manifest.id = ZAP_ENGINE_ID.into();
        let image = PinnedImage::from_manifest(&manifest).expect("ZAP image");
        let zap_plan = store
            .write_control_json(
                &directories,
                ZAP_PLAN_CONTROL_FILE,
                &serde_json::json!({"jobs": []}),
            )
            .expect("zap plan");
        let error = ContainerPlanBuilder::new(
            &manifest,
            &image,
            &directories,
            &scope,
            &ResourceLimits::default(),
            &NetworkPolicy::Disabled,
            &ScannerCredentialSet::default(),
            "case-1",
            "run-1",
            "engine-run-1",
            1,
        )
        .with_zap_plan_file(Some(&zap_plan.path))
        .build()
        .expect_err("zap plan without the product-owned path rejected");
        assert!(error.to_string().contains("product-owned path"));
    }

    #[test]
    fn zap_plan_must_be_the_autorun_argument() {
        let (_temp, store, directories, scope, mut manifest, _) =
            plan_fixture(vec!["scanner".into()]);
        manifest.id = ZAP_ENGINE_ID.into();
        manifest.command = vec![
            "-autorun".into(),
            "-silent".into(),
            CONTAINER_ZAP_PLAN_PATH.into(),
        ];
        let image = PinnedImage::from_manifest(&manifest).expect("ZAP image");
        let zap_plan = store
            .write_control_json(
                &directories,
                ZAP_PLAN_CONTROL_FILE,
                &serde_json::json!({"jobs": []}),
            )
            .expect("zap plan");
        let error = ContainerPlanBuilder::new(
            &manifest,
            &image,
            &directories,
            &scope,
            &ResourceLimits::default(),
            &NetworkPolicy::Disabled,
            &ScannerCredentialSet::default(),
            "case-1",
            "run-1",
            "engine-run-1",
            1,
        )
        .with_zap_plan_file(Some(&zap_plan.path))
        .build()
        .expect_err("zap plan path without an immediate -autorun rejected");
        assert!(error.to_string().contains("with -autorun"));
    }

    #[test]
    fn oversized_zap_plan_is_rejected() {
        let (_temp, store, directories, scope, mut manifest, _) =
            plan_fixture(vec!["scanner".into()]);
        enable_zap_automation_plan(&mut manifest);
        let image = PinnedImage::from_manifest(&manifest).expect("ZAP image");
        let zap_plan = store
            .write_control_json(
                &directories,
                ZAP_PLAN_CONTROL_FILE,
                &"a".repeat(MAX_ZAP_PLAN_BYTES + 1),
            )
            .expect("oversized zap plan");
        let error = ContainerPlanBuilder::new(
            &manifest,
            &image,
            &directories,
            &scope,
            &ResourceLimits::default(),
            &NetworkPolicy::Disabled,
            &ScannerCredentialSet::default(),
            "case-1",
            "run-1",
            "engine-run-1",
            1,
        )
        .with_zap_plan_file(Some(&zap_plan.path))
        .build()
        .expect_err("oversized zap plan rejected");
        assert!(error.to_string().contains(&format!(
            "ZAP automation plan exceeds the {} byte limit",
            MAX_ZAP_PLAN_BYTES
        )));
    }

    #[test]
    fn podman_execution_injects_exact_keep_id_mapping_but_docker_does_not() {
        let (_temp, _store, directories, scope, manifest, image) =
            plan_fixture(vec!["scanner".into()]);
        let plan = ContainerPlanBuilder::new(
            &manifest,
            &image,
            &directories,
            &scope,
            &ResourceLimits::default(),
            &NetworkPolicy::Disabled,
            &ScannerCredentialSet::default(),
            "case-1",
            "run-1",
            "engine-run-1",
            1,
        )
        .build()
        .expect("plan");
        let expected_user = format!("--user={}", plan.rootless_user.user_spec);
        let expected_userns = format!("--userns={}", plan.rootless_user.podman_userns);

        for provider in [RuntimeProvider::ManagedLocal, RuntimeProvider::Podman] {
            let arguments = runtime_args_with_secret(&plan, provider, None, None)
                .expect("Podman-dialect arguments");
            assert_eq!(
                arguments
                    .iter()
                    .filter(|argument| *argument == &expected_userns)
                    .count(),
                1
            );
            assert_eq!(
                arguments
                    .iter()
                    .filter(|argument| *argument == &expected_user)
                    .count(),
                1
            );
        }

        let docker = runtime_args_with_secret(&plan, RuntimeProvider::Docker, None, None)
            .expect("Docker arguments");
        assert!(docker.contains(&expected_user));
        assert!(!docker.iter().any(|argument| {
            argument.as_str() == "--userns" || argument.starts_with("--userns=")
        }));
    }

    #[test]
    fn fixed_windows_container_identity_has_an_exact_keep_id_mapping() {
        let mapping = rootless_user_mapping_for_ids(65532, 65532).expect("mapping");
        assert_eq!(mapping.user_spec, "65532:65532");
        assert_eq!(mapping.podman_userns, "keep-id:uid=65532,gid=65532");
        assert!(rootless_user_mapping_for_ids(0, 65532).is_err());
    }

    #[test]
    fn mutated_run_plan_user_contract_fails_closed() {
        let (_temp, _store, directories, scope, manifest, image) =
            plan_fixture(vec!["scanner".into()]);
        let mut plan = ContainerPlanBuilder::new(
            &manifest,
            &image,
            &directories,
            &scope,
            &ResourceLimits::default(),
            &NetworkPolicy::Disabled,
            &ScannerCredentialSet::default(),
            "case-1",
            "run-1",
            "engine-run-1",
            1,
        )
        .build()
        .expect("plan");
        let user = plan
            .runtime_args
            .iter()
            .position(|argument| argument.starts_with("--user="))
            .expect("user argument");
        plan.runtime_args[user] = "--user=0:0".into();

        let error = validate_run_plan_integrity(&plan).expect_err("mutated user must fail closed");
        assert!(error.to_string().contains("non-root user contract"));
    }

    #[test]
    fn credentials_use_a_short_lived_read_only_mount_not_process_environment() {
        let (_temp, _store, directories, scope, manifest, image) =
            plan_fixture(vec!["scanner".into(), "--json".into()]);
        let credentials = ScannerCredentialSet::new(vec![
            ScannerCredential::ephemeral_read_only(
                "AWS_SESSION_TOKEN",
                "protected-session-value",
                Utc::now() + Duration::minutes(10),
                CredentialSource::EphemeralScanRole,
            )
            .expect("credential"),
        ])
        .expect("credential set");
        let plan = ContainerPlanBuilder::new(
            &manifest,
            &image,
            &directories,
            &scope,
            &ResourceLimits::default(),
            &NetworkPolicy::Disabled,
            &credentials,
            "case-1",
            "run-1",
            "engine-run-1",
            1,
        )
        .build()
        .expect("plan");
        let mut secret = SecretFileGuard::create(plan.credential_control_dir(), &credentials)
            .expect("secret channel")
            .expect("nonempty channel");
        let arguments =
            runtime_args_with_secret(&plan, RuntimeProvider::ManagedLocal, Some(&secret), None)
                .expect("runtime args");

        assert_eq!(
            arguments
                .iter()
                .filter(|argument| argument.as_str() == "--mount")
                .count(),
            4
        );
        assert!(arguments.iter().all(|argument| {
            !argument.contains("protected-session-value") && argument != "--env"
        }));
        assert!(
            fs::read_to_string(&secret.path)
                .expect("credential envelope")
                .contains("protected-session-value")
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&secret.path)
                    .expect("metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o400
            );
        }
        let secret_path = secret.path.clone();
        secret.cleanup().expect("secret cleanup");
        assert!(!secret_path.exists());
    }

    #[test]
    fn scope_document_cannot_change_after_plan_creation() {
        let (_temp, store, directories, scope, manifest, image) =
            plan_fixture(vec!["scanner".into()]);
        let credentials = ScannerCredentialSet::default();
        let plan = ContainerPlanBuilder::new(
            &manifest,
            &image,
            &directories,
            &scope,
            &ResourceLimits::default(),
            &NetworkPolicy::Disabled,
            &credentials,
            "case-1",
            "run-1",
            "engine-run-1",
            1,
        )
        .build()
        .expect("plan");
        fs::remove_file(&scope).expect("remove original scope");
        fs::write(&scope, br#"{"assets":[{"id":"unauthorized"}]}"#).expect("replace scope");
        let capture = store.prepare_capture(&directories).expect("capture");

        let error = FakeContainerRuntime::default()
            .run(
                &plan,
                &credentials,
                &CancellationToken::default(),
                &capture,
                &mut None,
                &mut false,
            )
            .expect_err("changed scope rejected");
        assert!(error.to_string().contains("scope document changed"));
    }

    #[test]
    fn shell_and_dynamic_target_commands_are_rejected() {
        let (_temp, _store, directories, scope, manifest, image) = plan_fixture(vec![
            "sh".into(),
            "-c".into(),
            "scanner --target ${TARGET}".into(),
        ]);
        let error = ContainerPlanBuilder::new(
            &manifest,
            &image,
            &directories,
            &scope,
            &ResourceLimits::default(),
            &NetworkPolicy::Disabled,
            &ScannerCredentialSet::default(),
            "case-1",
            "run-1",
            "engine-run-1",
            1,
        )
        .build()
        .expect_err("shell rejected");
        assert!(error.to_string().contains("may not invoke a shell"));
    }

    #[test]
    fn docker_and_podman_must_prove_the_exact_internal_managed_bridge() {
        prove_managed_internal_network(
            RuntimeProvider::Docker,
            &docker_network_inspect(true, "policy-1"),
            "ass-egress",
            "policy-1",
        )
        .expect("Docker internal bridge proof");
        prove_managed_internal_network(
            RuntimeProvider::Podman,
            &podman_network_inspect(true, "policy-1"),
            "ass-egress",
            "policy-1",
        )
        .expect("Podman internal bridge proof");

        for (provider, document) in [
            (
                RuntimeProvider::Docker,
                docker_network_inspect(false, "policy-1"),
            ),
            (
                RuntimeProvider::Podman,
                podman_network_inspect(false, "policy-1"),
            ),
            (
                RuntimeProvider::Docker,
                docker_network_inspect(true, "other-policy"),
            ),
            (
                RuntimeProvider::Podman,
                podman_network_inspect(true, "other-policy"),
            ),
        ] {
            let error =
                prove_managed_internal_network(provider, &document, "ass-egress", "policy-1")
                    .expect_err("unproven network rejected");
            assert!(error.to_string().contains("exact internal bridge"));
        }
    }

    #[test]
    fn malformed_empty_or_ambiguous_network_inspection_is_rejected() {
        for document in [
            Vec::new(),
            b"not JSON".to_vec(),
            serde_json::to_vec(&serde_json::json!([])).expect("empty JSON array"),
            serde_json::to_vec(&serde_json::json!([
                {
                    "Name": "ass-egress",
                    "Id": "one",
                    "Driver": "bridge",
                    "Internal": true,
                    "Labels": {
                        (MANAGED_NETWORK_LABEL_KEY): "true",
                        (NETWORK_POLICY_LABEL_KEY): "policy-1",
                    }
                },
                {
                    "Name": "ass-egress",
                    "Id": "two",
                    "Driver": "bridge",
                    "Internal": true,
                    "Labels": {
                        (MANAGED_NETWORK_LABEL_KEY): "true",
                        (NETWORK_POLICY_LABEL_KEY): "policy-1",
                    }
                }
            ]))
            .expect("ambiguous JSON array"),
        ] {
            assert!(
                prove_managed_internal_network(
                    RuntimeProvider::Docker,
                    &document,
                    "ass-egress",
                    "policy-1"
                )
                .is_err()
            );
        }
    }

    #[test]
    fn disabled_plan_network_is_revalidated_fail_closed_before_run() {
        let (_temp, store, directories, scope, manifest, image) =
            plan_fixture(vec!["scanner".into()]);
        let credentials = ScannerCredentialSet::default();
        let mut plan = ContainerPlanBuilder::new(
            &manifest,
            &image,
            &directories,
            &scope,
            &ResourceLimits::default(),
            &NetworkPolicy::Disabled,
            &credentials,
            "case-1",
            "run-1",
            "engine-run-1",
            1,
        )
        .build()
        .expect("disabled plan");
        let network_value = plan
            .runtime_args
            .windows(2)
            .position(|arguments| arguments[0] == "--network")
            .map(|index| index + 1)
            .expect("network option");
        assert_eq!(plan.runtime_args[network_value], "none");
        plan.runtime_args[network_value] = "bridge".into();
        let capture = store.prepare_capture(&directories).expect("capture");

        let error = FakeContainerRuntime::default()
            .run(
                &plan,
                &credentials,
                &CancellationToken::default(),
                &capture,
                &mut None,
                &mut false,
            )
            .expect_err("weakened network isolation rejected");
        assert!(error.to_string().contains("exact none network isolation"));
    }

    #[cfg(unix)]
    #[test]
    fn process_runtime_inspects_full_network_state_and_disabled_needs_no_runtime_call() {
        let temp = tempfile::tempdir().expect("temp directory");
        let (binary, log, response) = fake_network_inspect_runtime(&temp);
        let runtime = ProcessContainerRuntime::new(RuntimeProvider::Docker, binary)
            .expect("construct compatibility runtime");
        let policy = NetworkPolicy::managed(
            "ass-egress",
            "policy-1",
            vec!["target.example".into()],
            "socks5h://172.29.0.1:1080",
        )
        .expect("managed policy");
        fs::write(&response, docker_network_inspect(true, "policy-1"))
            .expect("valid inspect response");

        runtime.verify_network(&policy).expect("verified network");
        assert_eq!(
            fs::read_to_string(&log).expect("runtime log"),
            "network inspect ass-egress\n"
        );

        fs::write(&response, docker_network_inspect(false, "policy-1"))
            .expect("non-internal inspect response");
        let error = runtime
            .verify_network(&policy)
            .expect_err("non-internal network rejected");
        assert!(error.to_string().contains("exact internal bridge"));

        let calls_before_disabled = fs::read_to_string(&log).expect("runtime log");
        runtime
            .verify_network(&NetworkPolicy::Disabled)
            .expect("disabled policy needs no runtime network");
        assert_eq!(
            fs::read_to_string(&log).expect("runtime log"),
            calls_before_disabled
        );
    }

    #[cfg(unix)]
    #[test]
    fn process_run_cannot_bypass_the_managed_internal_network_proof() {
        let (temp, store, directories, scope, mut manifest, image) =
            plan_fixture(vec!["scanner".into()]);
        manifest.active_external = true;
        manifest.network_destinations = vec!["authorized target".into()];
        let policy = NetworkPolicy::managed(
            "ass-egress",
            "policy-1",
            vec!["target.example".into()],
            "socks5h://172.29.0.1:1080",
        )
        .expect("managed policy");
        let credentials = ScannerCredentialSet::default();
        let plan = ContainerPlanBuilder::new(
            &manifest,
            &image,
            &directories,
            &scope,
            &ResourceLimits::default(),
            &policy,
            &credentials,
            "case-1",
            "run-1",
            "engine-run-1",
            1,
        )
        .build()
        .expect("managed plan");
        let capture = store.prepare_capture(&directories).expect("capture");
        let (binary, log, response) = fake_network_inspect_runtime(&temp);
        fs::write(&response, docker_network_inspect(false, "policy-1"))
            .expect("non-internal inspect response");
        let runtime = ProcessContainerRuntime::new(RuntimeProvider::Docker, binary)
            .expect("construct compatibility runtime");

        let error = runtime
            .run(
                &plan,
                &credentials,
                &CancellationToken::default(),
                &capture,
                &mut None,
                &mut false,
            )
            .expect_err("direct process run rejected");

        assert!(error.to_string().contains("exact internal bridge"));
        assert_eq!(
            fs::read_to_string(log).expect("runtime log"),
            "network inspect ass-egress\n"
        );
    }

    #[test]
    fn networked_engine_requires_managed_policy() {
        let (_temp, _store, directories, scope, mut manifest, image) =
            plan_fixture(vec!["scanner".into()]);
        manifest.active_external = true;
        manifest.network_destinations = vec!["authorized target".into()];
        let error = ContainerPlanBuilder::new(
            &manifest,
            &image,
            &directories,
            &scope,
            &ResourceLimits::default(),
            &NetworkPolicy::Disabled,
            &ScannerCredentialSet::default(),
            "case-1",
            "run-1",
            "engine-run-1",
            1,
        )
        .build()
        .expect_err("network rejected");
        assert!(error.to_string().contains("managed network policy"));
    }

    #[test]
    fn low_impact_external_permission_requires_managed_policy() {
        let (_temp, _store, directories, scope, mut manifest, image) =
            plan_fixture(vec!["scanner".into()]);
        manifest.required_permissions = vec![ScanPermission::LowImpactExternalConnection];
        let error = ContainerPlanBuilder::new(
            &manifest,
            &image,
            &directories,
            &scope,
            &ResourceLimits::default(),
            &NetworkPolicy::Disabled,
            &ScannerCredentialSet::default(),
            "case-1",
            "run-1",
            "engine-run-1",
            1,
        )
        .build()
        .expect_err("network-capable permission rejected without policy");
        assert!(error.to_string().contains("managed network policy"));
    }

    #[test]
    fn fake_runtime_rejects_aggregate_output_before_writing_any_bytes() {
        let (_temp, store, directories, scope, manifest, image) =
            plan_fixture(vec!["scanner".into()]);
        let limits = ResourceLimits {
            output_bytes: MIN_OUTPUT_BYTES,
            ..ResourceLimits::default()
        };
        let plan = ContainerPlanBuilder::new(
            &manifest,
            &image,
            &directories,
            &scope,
            &limits,
            &NetworkPolicy::Disabled,
            &ScannerCredentialSet::default(),
            "case-1",
            "run-1",
            "engine-run-1",
            1,
        )
        .build()
        .expect("bounded plan");
        let capture = store.prepare_capture(&directories).expect("capture");
        let runtime = FakeContainerRuntime::default();
        let mut behavior = FakeRunBehavior {
            stdout: vec![0_u8; 700 * 1024],
            ..FakeRunBehavior::default()
        };
        behavior
            .output_files
            .insert("report.bin".into(), vec![0_u8; 400 * 1024]);
        runtime.set_behavior(behavior);

        let error = runtime
            .run(
                &plan,
                &ScannerCredentialSet::default(),
                &CancellationToken::default(),
                &capture,
                &mut None,
                &mut false,
            )
            .expect_err("aggregate output must be rejected");
        assert!(
            error.to_string().contains("scan coverage is incomplete"),
            "the user must be told coverage is incomplete, but the error was: {error}"
        );
        assert_eq!(fs::metadata(&capture.stdout).expect("stdout").len(), 0);
        assert_eq!(fs::metadata(&capture.stderr).expect("stderr").len(), 0);
        assert_eq!(fs::read_dir(plan.output()).expect("output").count(), 0);
    }

    #[cfg(unix)]
    #[test]
    fn process_runtime_capture_cannot_be_redirected_by_path_replacement() {
        use std::os::unix::fs::symlink;

        let (temp, store, directories, scope, manifest, image) =
            plan_fixture(vec!["scanner".into()]);
        let plan = ContainerPlanBuilder::new(
            &manifest,
            &image,
            &directories,
            &scope,
            &ResourceLimits::default(),
            &NetworkPolicy::Disabled,
            &ScannerCredentialSet::default(),
            "case-1",
            "run-1",
            "engine-run-1",
            1,
        )
        .build()
        .expect("capture plan");
        let capture = store.prepare_capture(&directories).expect("capture");
        let retained_stdout = directories.raw.join("retained-stdout.log");
        let retained_stderr = directories.raw.join("retained-stderr.log");
        fs::rename(&capture.stdout, &retained_stdout).expect("retain stdout inode");
        fs::rename(&capture.stderr, &retained_stderr).expect("retain stderr inode");
        let outside_stdout = temp.path().join("outside-stdout.log");
        let outside_stderr = temp.path().join("outside-stderr.log");
        fs::write(&outside_stdout, b"outside-stdout-sentinel").expect("stdout sentinel");
        fs::write(&outside_stderr, b"outside-stderr-sentinel").expect("stderr sentinel");
        symlink(&outside_stdout, &capture.stdout).expect("replace stdout path");
        symlink(&outside_stderr, &capture.stderr).expect("replace stderr path");
        let (binary, _log) = fake_capture_runtime(&temp, &plan);
        let runtime = ProcessContainerRuntime::new(RuntimeProvider::Docker, binary)
            .expect("construct compatibility runtime");
        let mut created = None;
        let mut creation_may_be_untracked = false;

        let outcome = runtime
            .run(
                &plan,
                &ScannerCredentialSet::default(),
                &CancellationToken::default(),
                &capture,
                &mut created,
                &mut creation_may_be_untracked,
            )
            .expect("runtime uses retained capture handles");

        assert_eq!(outcome.exit_code, Some(0));
        assert!(!outcome.cancelled);
        assert!(created.is_some());
        assert!(creation_may_be_untracked);
        assert_eq!(fs::read(&retained_stdout).unwrap(), b"runtime-stdout\n");
        assert_eq!(fs::read(&retained_stderr).unwrap(), b"runtime-stderr\n");
        assert_eq!(
            fs::read(&outside_stdout).unwrap(),
            b"outside-stdout-sentinel"
        );
        assert_eq!(
            fs::read(&outside_stderr).unwrap(),
            b"outside-stderr-sentinel"
        );
    }

    #[cfg(unix)]
    #[test]
    fn inherited_capture_pipe_cannot_write_after_runtime_returns() {
        let (temp, store, directories, scope, manifest, image) =
            plan_fixture(vec!["scanner".into()]);
        let plan = ContainerPlanBuilder::new(
            &manifest,
            &image,
            &directories,
            &scope,
            &ResourceLimits::default(),
            &NetworkPolicy::Disabled,
            &ScannerCredentialSet::default(),
            "case-1",
            "run-1",
            "engine-run-1",
            1,
        )
        .build()
        .expect("inherited capture plan");
        let capture = store.prepare_capture(&directories).expect("capture");
        let binary = fake_inherited_capture_runtime(&temp, &plan);
        let runtime = ProcessContainerRuntime::new(RuntimeProvider::Docker, binary)
            .expect("construct compatibility runtime")
            .with_test_capture_drain_timeout(StdDuration::from_millis(100));

        let error = runtime
            .run(
                &plan,
                &ScannerCredentialSet::default(),
                &CancellationToken::default(),
                &capture,
                &mut None,
                &mut false,
            )
            .expect_err("inherited pipe must make coverage incomplete");
        assert!(error.to_string().contains("pipes did not close"));

        let first = store
            .finalize_capture(
                &ArtifactContext {
                    case_id: "case-1".into(),
                    scan_run_id: "run-1".into(),
                    engine_run_id: "engine-run-1".into(),
                },
                &capture,
            )
            .expect("writers quiesced before runtime return");
        thread::sleep(StdDuration::from_millis(200));
        let second = store
            .finalize_capture(
                &ArtifactContext {
                    case_id: "case-1".into(),
                    scan_run_id: "run-1".into(),
                    engine_run_id: "engine-run-1".into(),
                },
                &capture,
            )
            .expect("capture remains stable");
        assert_eq!(first[0].sha256, second[0].sha256);
        assert_eq!(first[0].byte_length, second[0].byte_length);
        assert_eq!(fs::read(&capture.stdout).unwrap(), b"before-descendant\n");
    }

    #[cfg(unix)]
    #[test]
    fn process_runtime_stops_a_stdout_flood_and_bounds_capture_size() {
        let (temp, store, directories, scope, manifest, image) =
            plan_fixture(vec!["scanner".into()]);
        let limits = ResourceLimits {
            output_bytes: MIN_OUTPUT_BYTES,
            ..ResourceLimits::default()
        };
        let plan = ContainerPlanBuilder::new(
            &manifest,
            &image,
            &directories,
            &scope,
            &limits,
            &NetworkPolicy::Disabled,
            &ScannerCredentialSet::default(),
            "case-1",
            "run-1",
            "engine-run-1",
            1,
        )
        .build()
        .expect("bounded plan");
        let immutable_id = "e".repeat(64);
        let capture = store.prepare_capture(&directories).expect("capture");
        let (binary, log) = fake_output_flood_runtime(&temp, &plan);
        let runtime = ProcessContainerRuntime::new(RuntimeProvider::Docker, binary)
            .expect("construct compatibility runtime");

        let error = runtime
            .run(
                &plan,
                &ScannerCredentialSet::default(),
                &CancellationToken::default(),
                &capture,
                &mut None,
                &mut false,
            )
            .expect_err("stdout flood must terminate the run");
        assert!(
            error.to_string().contains("scan coverage is incomplete"),
            "the user must be told coverage is incomplete, but the error was: {error}"
        );
        assert!(
            fs::metadata(&capture.stdout).expect("stdout").len() <= MIN_OUTPUT_BYTES,
            "captured stdout must remain within the aggregate cap"
        );
        assert!(
            fs::read_to_string(log)
                .expect("runtime log")
                .lines()
                .any(|line| line == format!("stop --time 5 {immutable_id}"))
        );
    }

    #[cfg(unix)]
    #[test]
    fn process_runtime_deadline_stops_only_the_ownership_proven_container() {
        let (temp, store, directories, scope, manifest, image) =
            plan_fixture(vec!["scanner".into()]);
        let plan = ContainerPlanBuilder::new(
            &manifest,
            &image,
            &directories,
            &scope,
            &ResourceLimits::default(),
            &NetworkPolicy::Disabled,
            &ScannerCredentialSet::default(),
            "case-1",
            "run-1",
            "engine-run-1",
            1,
        )
        .build()
        .expect("deadline plan");
        let immutable_id = "c".repeat(64);
        let capture = store.prepare_capture(&directories).expect("capture");
        let (binary, log) = fake_runtime(&temp, &plan, false);
        let runtime = ProcessContainerRuntime::new(RuntimeProvider::Docker, binary)
            .expect("construct compatibility runtime")
            .with_test_execution_timeout(StdDuration::from_millis(200));
        let mut created = None;

        let started = Instant::now();
        let error = runtime
            .run(
                &plan,
                &ScannerCredentialSet::default(),
                &CancellationToken::default(),
                &capture,
                &mut created,
                &mut false,
            )
            .expect_err("slow scanner must reach its host deadline");
        let message = error.to_string();
        assert!(message.contains(CONTAINER_EXECUTION_TIMEOUT_ERROR));
        assert!(!message.contains(plan.image().reference().as_str()));
        assert!(
            started.elapsed() < StdDuration::from_secs(5),
            "timed-out scanner must terminate promptly"
        );
        assert_eq!(
            created.as_ref().map(CreatedContainer::immutable_id),
            Some(immutable_id.as_str())
        );

        let commands = fs::read_to_string(&log).expect("runtime log");
        assert!(
            commands
                .lines()
                .any(|line| line == format!("container inspect {immutable_id}"))
        );
        assert!(
            commands
                .lines()
                .any(|line| line == format!("stop --time 5 {immutable_id}"))
        );
        runtime
            .cleanup(plan.ownership(), created.as_ref())
            .expect("normal ownership-proven cleanup remains available");
        let commands = fs::read_to_string(log).expect("cleanup log");
        assert!(
            commands
                .lines()
                .any(|line| line == format!("rm --force {immutable_id}"))
        );
    }

    #[cfg(unix)]
    #[test]
    fn process_runtime_pause_does_not_consume_the_execution_timeout() {
        let (temp, store, directories, scope, manifest, image) =
            plan_fixture(vec!["scanner".into()]);
        let plan = ContainerPlanBuilder::new(
            &manifest,
            &image,
            &directories,
            &scope,
            &ResourceLimits::default(),
            &NetworkPolicy::Disabled,
            &ScannerCredentialSet::default(),
            "case-1",
            "run-1",
            "engine-run-1",
            1,
        )
        .build()
        .expect("pause-aware deadline plan");
        let immutable_id = "c".repeat(64);
        let capture = store.prepare_capture(&directories).expect("capture");
        let (binary, log) = fake_runtime(&temp, &plan, false);
        let runtime = ProcessContainerRuntime::new(RuntimeProvider::Docker, binary)
            .expect("construct compatibility runtime")
            .with_test_execution_timeout(StdDuration::from_millis(750));
        let cancellation = CancellationToken::default();
        let worker_token = cancellation.clone();
        let worker = thread::spawn(move || {
            let mut created = None;
            let mut creation_may_be_untracked = false;
            let outcome = runtime.run(
                &plan,
                &ScannerCredentialSet::default(),
                &worker_token,
                &capture,
                &mut created,
                &mut creation_may_be_untracked,
            );
            (outcome, created, creation_may_be_untracked)
        });
        wait_until(|| {
            fs::read_to_string(&log)
                .is_ok_and(|contents| contents.lines().any(|line| line.starts_with("run ")))
        });

        cancellation.request_pause();
        wait_until(|| cancellation.is_paused());
        thread::sleep(StdDuration::from_millis(1_000));
        assert!(
            !worker.is_finished(),
            "time spent in an acknowledged pause must not exhaust the active execution budget"
        );

        cancellation.resume();
        wait_until(|| !cancellation.is_paused());
        wait_until(|| worker.is_finished());
        let (outcome, created, creation_may_be_untracked) = worker.join().expect("runtime thread");
        let error = outcome.expect_err("active execution must exhaust its remaining timeout");
        assert!(
            error
                .to_string()
                .contains(CONTAINER_EXECUTION_TIMEOUT_ERROR)
        );
        assert_eq!(
            created.as_ref().map(CreatedContainer::immutable_id),
            Some(immutable_id.as_str())
        );
        assert!(creation_may_be_untracked);

        let commands = fs::read_to_string(log).expect("runtime log");
        assert!(
            commands
                .lines()
                .any(|line| line == format!("pause {immutable_id}"))
        );
        assert!(
            commands
                .lines()
                .any(|line| line == format!("unpause {immutable_id}"))
        );
        assert!(
            commands
                .lines()
                .any(|line| line == format!("stop --time 5 {immutable_id}"))
        );
    }

    #[test]
    fn offline_engine_cannot_be_given_extra_network_access() {
        let (_temp, _store, directories, scope, manifest, image) =
            plan_fixture(vec!["scanner".into()]);
        let policy = NetworkPolicy::managed(
            "ass-egress",
            "policy-1",
            vec!["unexpected.example".into()],
            "socks5h://172.29.0.1:1080",
        )
        .expect("policy syntax");
        let error = ContainerPlanBuilder::new(
            &manifest,
            &image,
            &directories,
            &scope,
            &ResourceLimits::default(),
            &policy,
            &ScannerCredentialSet::default(),
            "case-1",
            "run-1",
            "engine-run-1",
            1,
        )
        .build()
        .expect_err("undeclared network rejected");
        assert!(error.to_string().contains("did not declare"));
    }

    #[test]
    fn admin_or_broker_credentials_have_no_scanner_api() {
        let error = ScannerCredential::ephemeral_read_only(
            "BROKER_ADMIN_PASSWORD",
            "secret",
            Utc::now() + Duration::minutes(10),
            CredentialSource::EphemeralScanRole,
        )
        .expect_err("credential rejected");
        assert!(
            error
                .to_string()
                .contains("cannot enter a scanner container")
        );
    }

    #[cfg(unix)]
    #[test]
    fn cancellation_without_a_created_id_never_controls_a_same_name_container() {
        let (temp, store, directories, scope, manifest, image) =
            plan_fixture(vec!["scanner".into()]);
        let plan = ContainerPlanBuilder::new(
            &manifest,
            &image,
            &directories,
            &scope,
            &ResourceLimits::default(),
            &NetworkPolicy::Disabled,
            &ScannerCredentialSet::default(),
            "case-1",
            "run-1",
            "engine-run-1",
            1,
        )
        .build()
        .expect("plan");
        let capture = store.prepare_capture(&directories).expect("capture");
        let (binary, log) = fake_name_collision_runtime(&temp);
        let runtime = ProcessContainerRuntime::new(RuntimeProvider::Docker, binary)
            .expect("construct compatibility runtime");
        let cancellation = CancellationToken::default();
        let worker_token = cancellation.clone();
        let worker = thread::spawn(move || {
            let mut created = None;
            let mut creation_may_be_untracked = false;
            let outcome = runtime.run(
                &plan,
                &ScannerCredentialSet::default(),
                &worker_token,
                &capture,
                &mut created,
                &mut creation_may_be_untracked,
            );
            (outcome, created, creation_may_be_untracked)
        });
        wait_until(|| {
            fs::read_to_string(&log)
                .is_ok_and(|contents| contents.lines().any(|line| line.starts_with("run ")))
        });

        cancellation.cancel();
        let (outcome, created, creation_may_be_untracked) = worker.join().expect("runtime thread");
        let outcome = outcome.expect("cancelled runtime outcome");

        assert!(outcome.cancelled);
        assert!(created.is_none());
        assert!(creation_may_be_untracked);
        let commands = fs::read_to_string(log).expect("runtime log");
        assert!(!commands.lines().any(|line| {
            line.starts_with("pause ")
                || line.starts_with("unpause ")
                || line.starts_with("stop ")
                || line.starts_with("container inspect ")
        }));
    }

    #[cfg(unix)]
    #[test]
    fn process_runtime_pauses_and_unpauses_exactly_once_per_request() {
        let (temp, store, directories, scope, manifest, image) =
            plan_fixture(vec!["scanner".into()]);
        let plan = ContainerPlanBuilder::new(
            &manifest,
            &image,
            &directories,
            &scope,
            &ResourceLimits::default(),
            &NetworkPolicy::Disabled,
            &ScannerCredentialSet::default(),
            "case-1",
            "run-1",
            "engine-run-1",
            1,
        )
        .build()
        .expect("plan");
        let immutable_id = "c".repeat(64);
        let capture = store.prepare_capture(&directories).expect("capture");
        let (binary, log) = fake_runtime(&temp, &plan, false);
        let runtime = ProcessContainerRuntime::new(RuntimeProvider::Docker, binary)
            .expect("construct compatibility runtime");
        let cancellation = CancellationToken::default();
        let worker_token = cancellation.clone();
        let worker = thread::spawn(move || {
            runtime.run(
                &plan,
                &ScannerCredentialSet::default(),
                &worker_token,
                &capture,
                &mut None,
                &mut false,
            )
        });
        wait_until(|| {
            fs::read_to_string(&log)
                .is_ok_and(|contents| contents.lines().any(|line| line.starts_with("run ")))
        });

        cancellation.request_pause();
        wait_until(|| cancellation.is_paused());
        cancellation.resume();
        wait_until(|| !cancellation.is_paused());
        cancellation.cancel();

        let outcome = worker
            .join()
            .expect("runtime thread")
            .expect("runtime outcome");
        assert!(outcome.cancelled);
        let commands = fs::read_to_string(log).expect("runtime log");
        assert_eq!(
            commands
                .lines()
                .filter(|line| *line == format!("pause {immutable_id}"))
                .count(),
            1
        );
        assert_eq!(
            commands
                .lines()
                .filter(|line| *line == format!("unpause {immutable_id}"))
                .count(),
            1
        );
        assert!(
            commands
                .lines()
                .any(|line| { line == format!("stop --time 5 {immutable_id}") })
        );
    }

    #[cfg(unix)]
    #[test]
    fn cancelling_a_paused_container_unpauses_before_stopping() {
        let (temp, store, directories, scope, manifest, image) =
            plan_fixture(vec!["scanner".into()]);
        let plan = ContainerPlanBuilder::new(
            &manifest,
            &image,
            &directories,
            &scope,
            &ResourceLimits::default(),
            &NetworkPolicy::Disabled,
            &ScannerCredentialSet::default(),
            "case-1",
            "run-1",
            "engine-run-1",
            1,
        )
        .build()
        .expect("plan");
        let immutable_id = "c".repeat(64);
        let capture = store.prepare_capture(&directories).expect("capture");
        let (binary, log) = fake_runtime(&temp, &plan, false);
        let runtime = ProcessContainerRuntime::new(RuntimeProvider::Podman, binary)
            .expect("construct compatibility runtime");
        let cancellation = CancellationToken::default();
        let worker_token = cancellation.clone();
        let worker = thread::spawn(move || {
            runtime.run(
                &plan,
                &ScannerCredentialSet::default(),
                &worker_token,
                &capture,
                &mut None,
                &mut false,
            )
        });
        wait_until(|| {
            fs::read_to_string(&log)
                .is_ok_and(|contents| contents.lines().any(|line| line.starts_with("run ")))
        });

        cancellation.request_pause();
        wait_until(|| cancellation.is_paused());
        cancellation.cancel();
        let outcome = worker
            .join()
            .expect("runtime thread")
            .expect("runtime outcome");
        assert!(outcome.cancelled);
        assert!(!cancellation.is_paused());

        let commands = fs::read_to_string(log).expect("runtime log");
        let unpause = commands
            .lines()
            .position(|line| line == format!("unpause {immutable_id}"))
            .expect("unpause command");
        let stop = commands
            .lines()
            .position(|line| line == format!("stop --time 5 {immutable_id}"))
            .expect("stop command");
        assert!(
            unpause < stop,
            "paused cancellation must unpause before stop"
        );
    }

    #[cfg(unix)]
    #[test]
    fn pause_failure_stops_the_container_fail_closed() {
        let (temp, store, directories, scope, manifest, image) =
            plan_fixture(vec!["scanner".into()]);
        let plan = ContainerPlanBuilder::new(
            &manifest,
            &image,
            &directories,
            &scope,
            &ResourceLimits::default(),
            &NetworkPolicy::Disabled,
            &ScannerCredentialSet::default(),
            "case-1",
            "run-1",
            "engine-run-1",
            1,
        )
        .build()
        .expect("plan");
        let immutable_id = "c".repeat(64);
        let capture = store.prepare_capture(&directories).expect("capture");
        let (binary, log) = fake_runtime(&temp, &plan, true);
        let runtime = ProcessContainerRuntime::new(RuntimeProvider::Docker, binary)
            .expect("construct compatibility runtime");
        let cancellation = CancellationToken::default();
        let worker_token = cancellation.clone();
        let worker = thread::spawn(move || {
            runtime.run(
                &plan,
                &ScannerCredentialSet::default(),
                &worker_token,
                &capture,
                &mut None,
                &mut false,
            )
        });
        // A pause may race runtime startup. The runtime must defer the control
        // command until it has proven the created container's immutable ID.
        cancellation.request_pause();
        let error = worker
            .join()
            .expect("runtime thread")
            .expect_err("pause failure is terminal");
        assert!(error.to_string().contains("container pause"));
        assert!(error.to_string().contains("stopped fail-closed"));
        assert!(!cancellation.is_paused());
        let commands = fs::read_to_string(log).expect("runtime log");
        assert!(
            commands
                .lines()
                .any(|line| { line == format!("stop --time 5 {immutable_id}") })
        );
    }
}
