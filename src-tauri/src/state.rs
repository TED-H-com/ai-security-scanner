use crate::adapter::AdapterRegistry;
use crate::case_service::CaseService;
use crate::container_runtime::{
    ContainerRuntime, ProcessContainerRuntime, RuntimeCommandContext, RuntimeCommandProvenance,
    RuntimeProvider,
};
use crate::domain::RuntimeHealth;
use crate::error::{AppError, AppResult};
use crate::job_manager::JobManager;
use crate::managed_network::{ManagedNetworkReconciliationSummary, ManagedNetworkRegistry};
use crate::managed_runtime::{
    ManagedRuntimeManager, ManagedRuntimeSetupController, ManagedRuntimeStatus,
    PackagedManagedRuntimeAdmission,
};
use crate::process_lease::DataDirectoryExclusiveLease;
use crate::registry::EngineRegistry;
use crate::runtime_health_monitor::{
    RuntimeHealthMonitor, RuntimeHealthObservation, is_available_compatibility_runtime,
    managed_runtime_health_observation, managed_runtime_health_precludes_fallback,
    select_recorded_managed_runtime_health, select_runtime_health,
};
use crate::source_authorization::SourceAuthorizationBindings;
use crate::source_authorization::discovery::ProviderDiscoveryJobs;
use crate::source_authorization::session::ProviderAuthorizationSessions;
use crate::storage::Storage;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub struct AppState {
    pub storage: Storage,
    pub engines: EngineRegistry,
    pub adapters: AdapterRegistry,
    pub jobs: JobManager,
    pub source_authorizations: SourceAuthorizationBindings,
    pub provider_authorization_sessions: ProviderAuthorizationSessions,
    pub provider_discovery_jobs: ProviderDiscoveryJobs,
    pub model_endpoint_sessions: crate::garak_input::ModelEndpointSessions,
    artifact_root: PathBuf,
    signing_key_path: PathBuf,
    managed_runtime: Option<Arc<ManagedRuntimeManager>>,
    managed_runtime_setup: Arc<ManagedRuntimeSetupController>,
    runtime_health: RuntimeHealthMonitor,
    process_lease: Option<DataDirectoryExclusiveLease>,
}

impl AppState {
    pub fn new(
        storage: Storage,
        engines: EngineRegistry,
        adapters: AdapterRegistry,
        artifact_root: PathBuf,
        signing_key_path: PathBuf,
    ) -> Self {
        Self {
            storage,
            engines,
            adapters,
            jobs: JobManager::default(),
            source_authorizations: SourceAuthorizationBindings::default(),
            provider_authorization_sessions: ProviderAuthorizationSessions::default(),
            provider_discovery_jobs: ProviderDiscoveryJobs::default(),
            model_endpoint_sessions: crate::garak_input::ModelEndpointSessions::default(),
            artifact_root,
            signing_key_path,
            managed_runtime: None,
            managed_runtime_setup: Arc::new(ManagedRuntimeSetupController::default()),
            runtime_health: RuntimeHealthMonitor::new(checking_runtime_health("none")),
            process_lease: None,
        }
    }

    pub fn with_process_lease(mut self, lease: DataDirectoryExclusiveLease) -> Self {
        self.process_lease = Some(lease);
        self
    }

    pub fn with_managed_runtime(mut self, manager: ManagedRuntimeManager) -> Self {
        self.managed_runtime = Some(Arc::new(manager));
        self.runtime_health
            .replace_cached(checking_runtime_health("managed_local"));
        self
    }

    /// Applies the desktop's one-time admission decision without turning an
    /// absent or rejected package into a startup gate. The rejected bytes are
    /// never retained by state, while independent checks and compatibility
    /// providers continue to use their existing paths.
    pub(crate) fn with_packaged_managed_runtime_admission(
        mut self,
        admission: PackagedManagedRuntimeAdmission,
    ) -> Self {
        let failure_reason = admission.failure_reason();
        match admission {
            PackagedManagedRuntimeAdmission::Verified(manager)
            | PackagedManagedRuntimeAdmission::RecoveredFromPrivateCache { manager, .. } => {
                self = self.with_managed_runtime(*manager);
            }
            PackagedManagedRuntimeAdmission::Missing
            | PackagedManagedRuntimeAdmission::VerificationFailed
            | PackagedManagedRuntimeAdmission::UnpackagedDeveloperBuild
            | PackagedManagedRuntimeAdmission::UnpackagedDeveloperBuildVerificationFailed => {
                self.managed_runtime_setup = Arc::new(
                    ManagedRuntimeSetupController::for_packaged_runtime_admission_failure(
                        failure_reason.expect("rejected admission has a stable failure reason"),
                    ),
                );
            }
        }
        self
    }

    pub fn managed_runtime(&self) -> Option<&Arc<ManagedRuntimeManager>> {
        self.managed_runtime.as_ref()
    }

    pub fn managed_runtime_setup(&self) -> &Arc<ManagedRuntimeSetupController> {
        &self.managed_runtime_setup
    }

    pub fn runtime_for_execution(&self) -> AppResult<ProcessContainerRuntime> {
        let mut managed_error = None;
        if let Some(manager) = &self.managed_runtime {
            match manager
                .start()
                .and_then(ProcessContainerRuntime::from_managed)
            {
                Ok(runtime) => return Ok(runtime),
                Err(error) => managed_error = Some(error),
            }
        }
        ProcessContainerRuntime::detect().map_err(|compatibility| {
            AppError::Runtime(match managed_error {
                Some(managed) => format!(
                    "managed-local runtime was unavailable ({managed}); Docker/Podman compatibility detection also failed ({compatibility})"
                ),
                None => compatibility.to_string(),
            })
        })
    }

    /// Reopens the exact runtime recorded by a durable checkpoint. This is
    /// intentionally separate from new-execution provider selection: an app
    /// update may leave cleanup work in an older verified managed runtime.
    pub fn runtime_for_recorded_execution(
        &self,
        provider: RuntimeProvider,
        provenance: &RuntimeCommandProvenance,
    ) -> AppResult<ProcessContainerRuntime> {
        let runtime = match (provider, provenance) {
            (
                RuntimeProvider::ManagedLocal,
                RuntimeCommandProvenance::ManagedLocal {
                    manifest_sha256, ..
                },
            ) => {
                let app_data = self.artifact_root.parent().ok_or_else(|| {
                    AppError::Internal("artifact root has no application-data parent".into())
                })?;
                let manager = ManagedRuntimeManager::open_installed(
                    app_data,
                    Some(manifest_sha256.as_str()),
                )?;
                ProcessContainerRuntime::from_managed(manager.start()?)?
            }
            (RuntimeProvider::Docker, RuntimeCommandProvenance::Compatibility) => {
                ProcessContainerRuntime::new(RuntimeProvider::Docker, "docker")?
            }
            (RuntimeProvider::Podman, RuntimeCommandProvenance::Compatibility) => {
                ProcessContainerRuntime::new(RuntimeProvider::Podman, "podman")?
            }
            _ => {
                return Err(AppError::NotAuthorized(
                    "durable runtime provider conflicts with command provenance".into(),
                ));
            }
        };
        let observed = runtime.preflight()?;
        if observed.provider != provider || observed.command_provenance != *provenance {
            return Err(AppError::NotAuthorized(
                "resolved runtime does not match the durable execution provenance".into(),
            ));
        }
        Ok(runtime)
    }

    pub fn runtime_health(&self) -> RuntimeHealth {
        self.runtime_health.cached()
    }

    /// Starts at most one slow WSL/container-provider probe and returns
    /// immediately. Shell snapshots and readiness reads consume only the last
    /// completed observation so saved work never waits on provider commands.
    pub fn request_runtime_health_refresh(&self) -> bool {
        let managed_runtime = self.managed_runtime.clone();
        self.runtime_health
            .request_refresh(move || detect_runtime_health(managed_runtime.as_deref()))
    }

    pub fn invalidate_runtime_health(&self) {
        self.runtime_health.invalidate();
    }

    pub fn record_managed_runtime_health(&self, status: &ManagedRuntimeStatus) {
        let observation = select_recorded_managed_runtime_health(
            managed_runtime_health_observation(status),
            self.runtime_health.cached(),
        );
        match observation {
            RuntimeHealthObservation::Settled(health)
                if !status.available && is_available_compatibility_runtime(&health) =>
            {
                self.runtime_health.replace_cached(health);
            }
            RuntimeHealthObservation::Settled(health) => {
                self.runtime_health.record_observation(health);
            }
            RuntimeHealthObservation::Reconciling(health) => {
                self.runtime_health.replace_cached(health);
            }
        }
    }

    pub fn case_service(&self) -> CaseService<'_> {
        CaseService::new(
            &self.storage,
            &self.engines,
            &self.adapters,
            &self.artifact_root,
            &self.signing_key_path,
        )
    }

    pub fn artifact_root(&self) -> &Path {
        &self.artifact_root
    }

    pub fn connector_artifact_root(&self, case_id: &str) -> AppResult<PathBuf> {
        if case_id.is_empty()
            || case_id.len() > 128
            || !case_id.chars().all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '-' | '_')
            })
        {
            return Err(AppError::InvalidRequest(
                "case id is unsafe for connector artifact storage".into(),
            ));
        }
        let case_root = ensure_private_child(&self.artifact_root, case_id)?;
        ensure_private_child(&case_root, "connector-snapshots")
    }

    pub fn bootstrap_artifact_root(&self, case_id: &str) -> AppResult<PathBuf> {
        if case_id.is_empty()
            || case_id.len() > 128
            || !case_id.chars().all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '-' | '_')
            })
        {
            return Err(AppError::InvalidRequest(
                "case id is unsafe for bootstrap artifact storage".into(),
            ));
        }
        let case_root = ensure_private_child(&self.artifact_root, case_id)?;
        ensure_private_child(&case_root, "provider-bootstrap")
    }

    pub fn network_policy_root(&self, case_id: &str) -> AppResult<PathBuf> {
        if case_id.is_empty()
            || case_id.len() > 128
            || !case_id.chars().all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '-' | '_')
            })
        {
            return Err(AppError::InvalidRequest(
                "case id is unsafe for network policy storage".into(),
            ));
        }
        let case_root = ensure_private_child(&self.artifact_root, case_id)?;
        ensure_private_child(&case_root, "network-policies")
    }

    pub fn managed_network_registry(&self) -> AppResult<ManagedNetworkRegistry> {
        let root = ensure_private_child(&self.artifact_root, ".managed-egress-registry")?;
        if let Some(manager) = &self.managed_runtime
            && let Some(command) = manager.runtime_command_if_running()?
        {
            let runtime = ProcessContainerRuntime::from_managed(command)?;
            return ManagedNetworkRegistry::new_with_runtime_context(
                root,
                &self.artifact_root,
                runtime.command_context(),
            );
        }
        ManagedNetworkRegistry::new(root, &self.artifact_root)
    }

    pub fn managed_network_registry_with_context(
        &self,
        context: RuntimeCommandContext,
    ) -> AppResult<ManagedNetworkRegistry> {
        let root = ensure_private_child(&self.artifact_root, ".managed-egress-registry")?;
        ManagedNetworkRegistry::new_with_runtime_context(root, &self.artifact_root, context)
    }

    pub fn reconcile_managed_networks(&self) -> AppResult<ManagedNetworkReconciliationSummary> {
        self.managed_network_registry()?
            .reconcile_all(chrono::Utc::now())
    }
}

fn checking_runtime_health(provider: &str) -> RuntimeHealth {
    RuntimeHealth {
        provider: provider.into(),
        available: false,
        phase: "checking".into(),
        version: None,
        prerequisite: None,
        detail: "Checking local scan-tool availability in the background.".into(),
    }
}

fn detect_compatibility_runtime_health() -> RuntimeHealthObservation {
    match ProcessContainerRuntime::detect().and_then(|runtime| {
        use crate::container_runtime::ContainerRuntime as _;
        runtime.preflight()
    }) {
        Ok(preflight) => {
            let provider = format!("{:?}", preflight.provider).to_ascii_lowercase();
            RuntimeHealthObservation::Settled(RuntimeHealth {
                provider,
                available: true,
                phase: "running".into(),
                version: Some(preflight.server_version),
                prerequisite: None,
                detail: "compatibility container service is available".into(),
            })
        }
        Err(error) => RuntimeHealthObservation::Settled(RuntimeHealth {
            provider: "none".into(),
            available: false,
            phase: "unavailable".into(),
            version: None,
            prerequisite: None,
            detail: error.to_string(),
        }),
    }
}

fn detect_runtime_health(
    managed_runtime: Option<&ManagedRuntimeManager>,
) -> RuntimeHealthObservation {
    let managed = managed_runtime.map(|manager| match manager.status() {
        Ok(status) => managed_runtime_health_observation(&status),
        Err(error) => RuntimeHealthObservation::Reconciling(RuntimeHealth {
            provider: "managed_local".into(),
            available: false,
            phase: "error".into(),
            version: None,
            prerequisite: None,
            detail: error.to_string(),
        }),
    });

    if managed
        .as_ref()
        .is_some_and(managed_runtime_health_precludes_fallback)
    {
        return managed.expect("a conclusive managed observation is present");
    }

    select_runtime_health(managed, detect_compatibility_runtime_health())
}

fn ensure_private_child(parent: &Path, name: &str) -> AppResult<PathBuf> {
    let child = parent.join(name);
    match fs::create_dir(&child) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    let metadata = fs::symlink_metadata(&child)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(AppError::NotAuthorized(
            "case artifact directory is not a real directory".into(),
        ));
    }
    let canonical_parent = parent.canonicalize()?;
    let canonical_child = child.canonicalize()?;
    if canonical_child.parent() != Some(canonical_parent.as_path()) {
        return Err(AppError::NotAuthorized(
            "case artifact directory escaped its backend-owned parent".into(),
        ));
    }
    restrict_directory(&canonical_child)?;
    Ok(canonical_child)
}

#[cfg(unix)]
fn restrict_directory(path: &Path) -> AppResult<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
fn restrict_directory(_path: &Path) -> AppResult<()> {
    Ok(())
}
