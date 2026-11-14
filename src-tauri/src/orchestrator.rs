use crate::adapter::{AdapterAssetIdentifierMap, AdapterInput, AdapterRegistry};
use crate::artifact_store::{ArtifactContext, ArtifactStore, CapturePaths, RunDirectories};
use crate::container_runtime::{
    CancellationToken, CleanupOutcome, ContainerPlanBuilder, ContainerRuntime,
    LOCAL_INPUT_PROFILE_REJECTION_MARKER, NAABU_LAUNCHER_PLAN_CONTROL_FILE, NetworkPolicy,
    PinnedImage, ResourceLimits, RuntimeCommandProvenance, RuntimePreflight, ScannerCredentialSet,
    ZAP_PLAN_CONTROL_FILE, planned_container_name,
};
use crate::domain::{
    Asset, AssetIdentifier, EngineManifest, Finding, RawArtifact, ScanPermission, ScopeGrant,
};
use crate::error::{AppError, AppResult};
use crate::execution_coverage::LAUNCHER_V2_JOURNAL_SCHEMA_VERSION;
use crate::managed_network::{GatewayDestination, ManagedNetworkIdentity};
use crate::naabu_work_plan::{
    LEGACY_NAABU_LAUNCHER_PLAN_SCHEMA_VERSION, MAX_NAABU_ENDPOINT_PAIRS_PER_ATTEMPT,
    MAX_NAABU_ENDPOINT_PAIRS_PER_UNIT, MAX_NAABU_FROZEN_ADDRESSES, MAX_NAABU_LAUNCHER_PLAN_BYTES,
    MAX_NAABU_WORK_UNITS, MAX_NAABU_WORK_UNITS_PER_ATTEMPT, NAABU_ENGINE_ID,
    NAABU_LAUNCHER_PLAN_SCHEMA_VERSION, NaabuLauncherPlanDocument,
};
use crate::zap_work_plan::{
    ZAP_ENGINE_ID, ZapGatewayEndpoint, ZapPassiveBounds, ZapPlanDocument, build_zap_passive_plan,
    matches_zap_passive_profile,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionStage {
    Planned,
    Preflight,
    PullingImage,
    Running,
    CapturingArtifacts,
    AdaptingArtifacts,
    CapturedAwaitingAdapter,
    CleanupPending,
    Completed,
    Cancelled,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ResumeAction {
    AlreadyComplete,
    AdaptCapturedArtifacts,
    CleanupContainer,
    ReconcileContainerThenReexecute,
    Reexecute,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionCheckpoint {
    pub case_id: String,
    pub scan_run_id: String,
    pub engine_run_id: String,
    pub engine_id: String,
    pub attempt: u32,
    pub stage: ExecutionStage,
    pub container_name: Option<String>,
    pub scope_sha256: Option<String>,
    /// Exact digest of the private versioned launcher work plan mounted into this
    /// container. Legacy executions omit it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub launcher_plan_sha256: Option<String>,
    /// Exact private ZAP automation plan bound to the container ownership proof.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zap_plan_sha256: Option<String>,
    pub artifact_ids: Vec<String>,
    pub cleanup_completed: bool,
    pub last_error: Option<String>,
    /// Stable product classification for a known execution failure. Legacy
    /// checkpoints omit it and remain unclassified.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_code: Option<String>,
    /// Exact, non-secret runtime identity needed to recover this execution
    /// after an application update. It is populated immediately after the
    /// runtime preflight and is therefore mandatory for cleanup-pending work.
    #[serde(default)]
    pub runtime_command_provenance: Option<RuntimeCommandProvenance>,
    #[serde(default)]
    pub runtime_provider: Option<crate::container_runtime::RuntimeProvider>,
    #[serde(default)]
    pub managed_network: Option<ManagedNetworkIdentity>,
}

impl ExecutionCheckpoint {
    pub fn resume_action(&self) -> ResumeAction {
        match self.stage {
            ExecutionStage::Completed => ResumeAction::AlreadyComplete,
            ExecutionStage::CapturedAwaitingAdapter | ExecutionStage::AdaptingArtifacts => {
                ResumeAction::AdaptCapturedArtifacts
            }
            ExecutionStage::CleanupPending => ResumeAction::CleanupContainer,
            ExecutionStage::Running | ExecutionStage::CapturingArtifacts => {
                ResumeAction::ReconcileContainerThenReexecute
            }
            ExecutionStage::Planned
            | ExecutionStage::Preflight
            | ExecutionStage::PullingImage
            | ExecutionStage::Cancelled
            | ExecutionStage::Failed => ResumeAction::Reexecute,
        }
    }

    pub fn resume_token(&self) -> AppResult<String> {
        self.validate()?;
        serde_json::to_string(self)
            .map_err(|error| AppError::Runtime(format!("checkpoint encode failed: {error}")))
    }

    pub fn from_resume_token(token: &str) -> AppResult<Self> {
        let checkpoint: Self = serde_json::from_str(token)
            .map_err(|error| AppError::InvalidRequest(format!("invalid resume token: {error}")))?;
        checkpoint.validate()?;
        Ok(checkpoint)
    }

    fn validate(&self) -> AppResult<()> {
        if let Some(identity) = self.managed_network.as_ref() {
            identity.validate()?;
        }
        if self.runtime_command_provenance.is_some() != self.runtime_provider.is_some() {
            return Err(AppError::InvalidRequest(
                "checkpoint runtime provider and provenance must be recorded together".into(),
            ));
        }
        if let Some(digest) = self.launcher_plan_sha256.as_deref() {
            if self.engine_id != NAABU_ENGINE_ID || self.scope_sha256.is_none() {
                return Err(AppError::InvalidRequest(
                    "checkpoint launcher plan digest requires a Naabu execution scope".into(),
                ));
            }
            if !is_lowercase_sha256(digest) {
                return Err(AppError::InvalidRequest(
                    "checkpoint Naabu launcher plan digest is invalid".into(),
                ));
            }
        }
        if let Some(digest) = self.zap_plan_sha256.as_deref()
            && (self.engine_id != ZAP_ENGINE_ID
                || self.scope_sha256.is_none()
                || !is_lowercase_sha256(digest))
        {
            return Err(AppError::InvalidRequest(
                "checkpoint ZAP automation plan digest requires its exact ZAP execution scope"
                    .into(),
            ));
        }
        let expected = planned_container_name(&self.engine_id, &self.engine_run_id, self.attempt)?;
        if self
            .container_name
            .as_deref()
            .is_some_and(|actual| actual != expected)
        {
            return Err(AppError::InvalidRequest(
                "checkpoint container name does not match its execution identity".into(),
            ));
        }
        if self.stage == ExecutionStage::CleanupPending
            && self.container_name.is_none()
            && self.managed_network.is_none()
        {
            return Err(AppError::InvalidRequest(
                "cleanup checkpoint has neither a container nor a managed-network identity".into(),
            ));
        }
        if self.stage == ExecutionStage::CleanupPending
            && (self.runtime_command_provenance.is_none() || self.runtime_provider.is_none())
        {
            return Err(AppError::InvalidRequest(
                "cleanup checkpoint has no exact runtime provider and provenance".into(),
            ));
        }
        if let Some(identity) = self.managed_network.as_ref() {
            let provenance = self.runtime_command_provenance.as_ref().ok_or_else(|| {
                AppError::InvalidRequest(
                    "managed-network checkpoint has no exact runtime provenance".into(),
                )
            })?;
            if self.runtime_provider != Some(identity.provider) {
                return Err(AppError::InvalidRequest(
                    "managed-network provider conflicts with checkpoint runtime provider".into(),
                ));
            }
            let provider_matches = matches!(
                (identity.provider, provenance),
                (
                    crate::container_runtime::RuntimeProvider::ManagedLocal,
                    RuntimeCommandProvenance::ManagedLocal { .. }
                ) | (
                    crate::container_runtime::RuntimeProvider::Docker
                        | crate::container_runtime::RuntimeProvider::Podman,
                    RuntimeCommandProvenance::Compatibility
                )
            );
            if !provider_matches {
                return Err(AppError::InvalidRequest(
                    "managed-network provider conflicts with runtime provenance".into(),
                ));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct ExecutionReport {
    pub checkpoint: ExecutionCheckpoint,
    pub runtime_preflight: Option<RuntimePreflight>,
    pub cleanup: Option<CleanupOutcome>,
    pub exit_code: Option<i32>,
    pub raw_artifacts: Vec<RawArtifact>,
    pub findings: Vec<Finding>,
    pub observations: Vec<crate::domain::InventoryObservation>,
    pub warnings: Vec<String>,
    /// Identifiers the adapter could not attribute to an authorized asset.
    pub unattributed: Vec<crate::domain::UnattributedResults>,
    pub unevaluated_targets: Vec<crate::domain::UnevaluatedTarget>,
    pub security_template_executions: Vec<crate::domain::SecurityTemplateExecution>,
    pub manual_review_controls: Vec<crate::domain::ManualReviewControl>,
    pub artifact_root: PathBuf,
    pub output_directory: PathBuf,
}

impl ExecutionReport {
    fn empty(
        checkpoint: ExecutionCheckpoint,
        artifact_root: PathBuf,
        output_directory: PathBuf,
    ) -> Self {
        Self {
            checkpoint,
            runtime_preflight: None,
            cleanup: None,
            exit_code: None,
            raw_artifacts: Vec::new(),
            findings: Vec::new(),
            observations: Vec::new(),
            warnings: Vec::new(),
            unattributed: Vec::new(),
            unevaluated_targets: Vec::new(),
            security_template_executions: Vec::new(),
            manual_review_controls: Vec::new(),
            artifact_root,
            output_directory,
        }
    }

    fn fail(&mut self, message: impl Into<String>) {
        let message = message.into();
        self.checkpoint.stage = ExecutionStage::Failed;
        self.checkpoint.last_error = Some(message);
    }
}

fn combined_cleanup_pending_error(
    runtime_error: Option<&str>,
    prior_error: Option<&str>,
    cleanup_error: &str,
) -> String {
    let mut primary = Vec::<String>::new();
    for candidate in [runtime_error, prior_error].into_iter().flatten() {
        let candidate = candidate.trim();
        if !candidate.is_empty() && !primary.iter().any(|message| message == candidate) {
            primary.push(candidate.to_owned());
        }
    }
    let cleanup_error = cleanup_error.trim();
    if primary.is_empty() {
        format!("container cleanup failed: {cleanup_error}")
    } else {
        format!(
            "{}; container cleanup also failed: {cleanup_error}",
            primary.join("; ")
        )
    }
}

pub struct EngineExecutionRequest<'a> {
    pub case_id: &'a str,
    pub scan_run_id: &'a str,
    pub engine_run_id: &'a str,
    pub manifest: &'a EngineManifest,
    /// Framework-classification context frozen by case planning. This never
    /// authorizes a target or changes the engine command.
    pub ai_system_applicable: bool,
    /// Framework-classification context frozen by case planning. `false`
    /// includes both an explicit no and an unknown answer.
    pub ai_generated_artifact_applicable: bool,
    pub assets: &'a [Asset],
    pub scope_grants: &'a [ScopeGrant],
    /// Exact host-side DNS/address snapshot represented by the managed egress
    /// policy. Only the project-owned external launcher receives these
    /// addresses in its scope document; every other engine keeps its existing
    /// strict scope schema.
    pub frozen_destinations: Option<&'a [GatewayDestination]>,
    /// Private, exact launcher work-unit document. New execution uses compact
    /// plan schema 3 while journal output remains schema 2.
    pub naabu_launcher_plan: Option<&'a NaabuLauncherPlanDocument>,
    /// Durable digest chosen by host planning for the exact serialized
    /// sidecar. The orchestrator verifies the file it wrote before it builds
    /// or invokes any runtime plan.
    pub expected_naabu_launcher_plan_sha256: Option<&'a str>,
    pub workspace: Option<&'a Path>,
    pub network_policy: &'a NetworkPolicy,
    pub resource_limits: &'a ResourceLimits,
    pub credentials: &'a ScannerCredentialSet,
    pub attempt: u32,
}

fn is_lowercase_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn validate_naabu_launcher_request(request: &EngineExecutionRequest<'_>) -> AppResult<()> {
    let declared_version = request
        .manifest
        .execution
        .as_ref()
        .and_then(|execution| execution.launcher_journal_version);
    match declared_version {
        Some(version) if version != LAUNCHER_V2_JOURNAL_SCHEMA_VERSION => {
            return Err(AppError::EngineRegistry(format!(
                "engine {} declares unsupported launcher journal version {version}",
                request.manifest.id
            )));
        }
        Some(_)
            if request.naabu_launcher_plan.is_none()
                || request.expected_naabu_launcher_plan_sha256.is_none() =>
        {
            return Err(AppError::InvalidRequest(
                "the current Naabu launcher requires its private execution plan and exact digest"
                    .into(),
            ));
        }
        None if request.naabu_launcher_plan.is_some()
            || request.expected_naabu_launcher_plan_sha256.is_some() =>
        {
            return Err(AppError::InvalidRequest(
                "a launcher execution plan or digest requires an explicit reviewed launcher version"
                    .into(),
            ));
        }
        _ => {}
    }

    let Some(plan) = request.naabu_launcher_plan else {
        return Ok(());
    };
    let expected_digest = request
        .expected_naabu_launcher_plan_sha256
        .expect("launcher v2 presence was validated together");
    if !is_lowercase_sha256(expected_digest) {
        return Err(AppError::InvalidRequest(
            "expected Naabu launcher plan digest is not lowercase SHA-256".into(),
        ));
    }
    if request.manifest.id != NAABU_ENGINE_ID
        || !matches!(
            plan.schema_version,
            LEGACY_NAABU_LAUNCHER_PLAN_SCHEMA_VERSION | NAABU_LAUNCHER_PLAN_SCHEMA_VERSION
        )
        || plan.engine_id != NAABU_ENGINE_ID
    {
        return Err(AppError::InvalidRequest(
            "the current launcher accepts only reviewed Naabu plan schema 3 or exact legacy schema 2"
                .into(),
        ));
    }
    if plan.engine_run_id != request.engine_run_id || plan.execution_attempt != request.attempt {
        return Err(AppError::InvalidRequest(
            "Naabu launcher plan identity does not match this engine execution".into(),
        ));
    }
    if plan.frozen_grants.is_empty() || plan.requested_work_units.is_empty() {
        return Err(AppError::InvalidRequest(
            "Naabu launcher plan must contain frozen grants and requested work units".into(),
        ));
    }
    let encoded = serde_json::to_vec(plan).map_err(|error| {
        AppError::InvalidRequest(format!("invalid Naabu launcher plan: {error}"))
    })?;
    if encoded.len() > MAX_NAABU_LAUNCHER_PLAN_BYTES {
        return Err(AppError::InvalidRequest(format!(
            "Naabu launcher plan exceeds the {}-byte private control limit",
            MAX_NAABU_LAUNCHER_PLAN_BYTES
        )));
    }
    Ok(())
}

pub struct Orchestrator<'a, R: ContainerRuntime> {
    runtime: &'a R,
    artifacts: &'a ArtifactStore,
    adapters: &'a AdapterRegistry,
}

impl<'a, R: ContainerRuntime> Orchestrator<'a, R> {
    pub fn new(
        runtime: &'a R,
        artifacts: &'a ArtifactStore,
        adapters: &'a AdapterRegistry,
    ) -> Self {
        Self {
            runtime,
            artifacts,
            adapters,
        }
    }

    pub fn execute(
        &self,
        request: &EngineExecutionRequest<'_>,
        cancellation: &CancellationToken,
    ) -> AppResult<ExecutionReport> {
        self.execute_with_observer(request, cancellation, |_| Ok(()))
    }

    /// Executes an engine while exposing non-terminal durable reports at safe
    /// state boundaries. The observer runs before any container starts and
    /// again after captured artifacts are safely closed and the container has
    /// been cleaned. Terminal reconciliation remains the caller's
    /// responsibility so findings and raw artifacts commit atomically.
    pub fn execute_with_observer<F>(
        &self,
        request: &EngineExecutionRequest<'_>,
        cancellation: &CancellationToken,
        mut observer: F,
    ) -> AppResult<ExecutionReport>
    where
        F: FnMut(&ExecutionReport) -> AppResult<()>,
    {
        if let Some(blocker) = request.manifest.release_blocker() {
            return Err(AppError::EngineRegistry(format!(
                "engine {} cannot be executed: {blocker}",
                request.manifest.id
            )));
        }
        validate_naabu_launcher_request(request)?;
        let validated_scope = validate_execution_scope_for_request(
            request.manifest,
            request.assets,
            request.scope_grants,
            request.network_policy,
            request.frozen_destinations,
            request.naabu_launcher_plan,
        )?;
        let zap_plan_document = zap_plan_for_request(request, &validated_scope)?;
        let image = PinnedImage::from_manifest(request.manifest)?;
        if request.attempt == 0 {
            return Err(AppError::InvalidRequest(
                "execution attempt must start at one".into(),
            ));
        }
        if request
            .manifest
            .required_permissions
            .contains(&ScanPermission::LocalArtifactRead)
            && request.workspace.is_none()
        {
            return Err(AppError::InvalidRequest(format!(
                "engine {} requires an explicitly selected local workspace",
                request.manifest.id
            )));
        }

        let context = ArtifactContext {
            case_id: request.case_id.into(),
            scan_run_id: request.scan_run_id.into(),
            engine_run_id: request.engine_run_id.into(),
        };
        let directories = self.artifacts.prepare_run(&context, request.attempt)?;
        let scope_document = ScopeDocument::new_for_request(
            request.manifest,
            &validated_scope,
            request.frozen_destinations,
            request.naabu_launcher_plan,
        )?;
        let scope_file =
            self.artifacts
                .write_control_json(&directories, "scope.json", &scope_document)?;
        let launcher_plan_file = request
            .naabu_launcher_plan
            .map(|launcher_plan| {
                self.artifacts.write_control_json(
                    &directories,
                    NAABU_LAUNCHER_PLAN_CONTROL_FILE,
                    launcher_plan,
                )
            })
            .transpose()?;
        if launcher_plan_file
            .as_ref()
            .map(|control_file| control_file.sha256.as_str())
            != request.expected_naabu_launcher_plan_sha256
        {
            return Err(AppError::NotAuthorized(
                "written Naabu launcher plan does not match its durable expected digest".into(),
            ));
        }
        let zap_plan_file = zap_plan_document
            .as_ref()
            .map(|document| {
                self.artifacts
                    .write_control_json(&directories, ZAP_PLAN_CONTROL_FILE, document)
            })
            .transpose()?;
        let plan_directories = run_directories_with_workspace(
            &directories,
            request.workspace.unwrap_or(&directories.workspace),
        );
        let plan = ContainerPlanBuilder::new(
            request.manifest,
            &image,
            &plan_directories,
            &scope_file.path,
            request.resource_limits,
            request.network_policy,
            request.credentials,
            request.case_id,
            request.scan_run_id,
            request.engine_run_id,
            request.attempt,
        )
        .with_launcher_plan_file(
            launcher_plan_file
                .as_ref()
                .map(|control_file| control_file.path.as_path()),
        )
        .with_zap_plan_file(zap_plan_file.as_ref().map(|file| file.path.as_path()))
        .build()?;
        if plan.launcher_plan_sha256() != request.expected_naabu_launcher_plan_sha256 {
            return Err(AppError::NotAuthorized(
                "container plan changed the expected Naabu launcher plan digest".into(),
            ));
        }

        let checkpoint = ExecutionCheckpoint {
            case_id: request.case_id.into(),
            scan_run_id: request.scan_run_id.into(),
            engine_run_id: request.engine_run_id.into(),
            engine_id: request.manifest.id.clone(),
            attempt: request.attempt,
            stage: ExecutionStage::Planned,
            container_name: Some(plan.container_name().to_owned()),
            scope_sha256: Some(plan.scope_sha256().to_owned()),
            zap_plan_sha256: plan.zap_plan_sha256().map(str::to_owned),
            launcher_plan_sha256: plan.launcher_plan_sha256().map(str::to_owned),
            artifact_ids: Vec::new(),
            // Planning, runtime preflight, and image pull cannot create the
            // attempt container. Keep the cleanup obligation closed until
            // immediately before the runtime call that can create it.
            cleanup_completed: true,
            last_error: None,
            failure_code: None,
            runtime_command_provenance: None,
            runtime_provider: None,
            managed_network: None,
        };
        let mut report = ExecutionReport::empty(
            checkpoint,
            self.artifacts.root().to_path_buf(),
            directories.output.clone(),
        );
        observer(&report)?;

        if cancellation.is_cancelled() {
            report.checkpoint.stage = ExecutionStage::Cancelled;
            report.checkpoint.cleanup_completed = true;
            return Ok(report);
        }

        report.checkpoint.stage = ExecutionStage::Preflight;
        observer(&report)?;
        let preflight = match self.runtime.preflight() {
            Ok(preflight) => preflight,
            Err(error) => {
                report.checkpoint.cleanup_completed = true;
                report.fail(error.to_string());
                return Ok(report);
            }
        };
        report.checkpoint.runtime_command_provenance = Some(preflight.command_provenance.clone());
        report.checkpoint.runtime_provider = Some(preflight.provider);
        report.runtime_preflight = Some(preflight);
        if let Err(error) = self.runtime.verify_network(request.network_policy) {
            report.checkpoint.cleanup_completed = true;
            report.fail(error.to_string());
            return Ok(report);
        }

        report.checkpoint.stage = ExecutionStage::PullingImage;
        observer(&report)?;
        if let Err(error) = self.runtime.pull(&image) {
            report.checkpoint.cleanup_completed = true;
            report.fail(error.to_string());
            return Ok(report);
        }
        if cancellation.is_cancelled() {
            report.checkpoint.stage = ExecutionStage::Cancelled;
            report.checkpoint.cleanup_completed = true;
            return Ok(report);
        }

        // The runtime may have stopped, restarted, or changed its security
        // configuration since the batch-level prepare proof above (and an
        // image pull can be long-running). Reinspect the live daemon directly
        // before this engine starts and persist that fresh proof. Never leave
        // the earlier batch proof attached to an execution-preflight failure.
        let execution_preflight = match self.runtime.execution_preflight() {
            Ok(preflight) => preflight,
            Err(error) => {
                report.runtime_preflight = None;
                report.checkpoint.cleanup_completed = true;
                report.fail(error.to_string());
                return Ok(report);
            }
        };
        report.checkpoint.runtime_command_provenance =
            Some(execution_preflight.command_provenance.clone());
        report.checkpoint.runtime_provider = Some(execution_preflight.provider);
        report.runtime_preflight = Some(execution_preflight);

        // Create capture files only after the live daemon proof succeeds. A
        // preflight failure has no scanner output and must not leave empty,
        // untracked evidence files behind.
        let capture = self.artifacts.prepare_capture(&directories)?;

        report.checkpoint.stage = ExecutionStage::Running;
        // Persist the exact cleanup identity before the first call that may
        // create a container. A crash after this observer can therefore run
        // bounded cleanup; an earlier crash has no container obligation.
        report.checkpoint.cleanup_completed = false;
        observer(&report)?;
        let mut created_container = None;
        let mut creation_may_be_untracked = false;
        let runtime_result = self.runtime.run(
            &plan,
            request.credentials,
            cancellation,
            &capture,
            &mut created_container,
            &mut creation_may_be_untracked,
        );
        if let Ok(outcome) = runtime_result.as_ref() {
            report.exit_code = outcome.exit_code;
        }

        report.checkpoint.stage = ExecutionStage::CapturingArtifacts;
        let artifact_result = (|| -> AppResult<Vec<RawArtifact>> {
            let mut artifacts = self.artifacts.finalize_capture(&context, &capture)?;
            artifacts.extend(
                self.artifacts
                    .collect_output_artifacts(&context, &directories)?,
            );
            Ok(artifacts)
        })();
        let cleanup_result = match (created_container.as_ref(), creation_may_be_untracked) {
            (Some(created), _) => self.runtime.cleanup(plan.ownership(), Some(created)),
            (None, true) => self.runtime.cleanup(plan.ownership(), None),
            (None, false) => Ok(CleanupOutcome {
                removed: false,
                detail: "the runtime invocation ended before container creation was possible"
                    .into(),

                gateway_refusals: None,
            }),
        };

        match artifact_result {
            Ok(artifacts) => {
                report.checkpoint.artifact_ids = artifacts
                    .iter()
                    .map(|artifact| artifact.id.clone())
                    .collect();
                report.raw_artifacts = artifacts;
            }
            Err(error) => report.fail(error.to_string()),
        }

        match cleanup_result {
            Ok(cleanup) => {
                report.checkpoint.cleanup_completed = true;
                report.cleanup = Some(cleanup);
            }
            Err(AppError::NotAuthorized(_problem)) => {
                // A same-name object whose exact ownership labels cannot be
                // proven belongs outside this attempt's cleanup authority.
                // Preserve it, close this attempt's cleanup obligation, and
                // let a later attempt use its own unique name. Treating this
                // as retryable cleanup would permanently gate the user's scan
                // on an object the product must never change.
                report.checkpoint.cleanup_completed = true;
                report.cleanup = Some(CleanupOutcome {
                    removed: false,
                    detail: "Runtime object unchanged. Ownership status: unverified.".into(),

                    gateway_refusals: None,
                });
                report.warnings.push(
                    "Runtime object ownership is unavailable. Retry uses a new isolated attempt."
                        .into(),
                );
                // The same ownership ambiguity also means this attempt's
                // runtime output cannot be promoted to trusted findings, even
                // if the client process reported exit zero. Raw capture stays
                // available for diagnosis, while the attempt ends truthfully
                // and a new isolated attempt can continue.
                report.fail(
                    "Runtime ownership status: unverified after launch. Attempt status: failed. Retry: new isolated attempt.",
                );
            }
            Err(error) => {
                let runtime_error = match runtime_result.as_ref() {
                    Ok(outcome) if outcome.exit_code.is_some_and(|code| code != 0) => {
                        Some(format!(
                            "scanner container exited with status {:?}",
                            outcome.exit_code
                        ))
                    }
                    Ok(_) => None,
                    Err(runtime_error) => Some(runtime_error.to_string()),
                };
                let combined = combined_cleanup_pending_error(
                    runtime_error.as_deref(),
                    report.checkpoint.last_error.as_deref(),
                    &error.to_string(),
                );
                report.checkpoint.stage = ExecutionStage::CleanupPending;
                report.checkpoint.cleanup_completed = false;
                report.checkpoint.last_error = Some(combined);
                return Ok(report);
            }
        }

        // A launcher-v2 process exit is not the coverage authority. Journal
        // append/sync/close can fail after one or more earlier terminal
        // records and finals were already durably published. Once capture
        // and cleanup both finish, hand every such invocation to the host
        // validator: it accepts only the longest complete, newline-terminated
        // journal prefix and exact matching finals. Missing records remain
        // not-tested, while an absent or invalid journal stays evidence-only.
        // Other engines retain the ordinary nonzero-exit failure path below.
        let launcher_v2_capture_complete = request
            .manifest
            .execution
            .as_ref()
            .and_then(|execution| execution.launcher_journal_version)
            == Some(LAUNCHER_V2_JOURNAL_SCHEMA_VERSION)
            && report.checkpoint.stage != ExecutionStage::Failed
            && report.checkpoint.cleanup_completed;
        if launcher_v2_capture_complete {
            if cancellation.is_cancelled()
                || runtime_result.as_ref().is_err()
                || runtime_result
                    .as_ref()
                    .is_ok_and(|outcome| outcome.cancelled || outcome.exit_code != Some(0))
            {
                report
                    .warnings
                    .push("Scan batch stopped. Unfinished work: not tested.".into());
            }
            report.checkpoint.stage = ExecutionStage::CapturedAwaitingAdapter;
            report.checkpoint.last_error = None;
            // Persistable hand-off before caller-owned managed-network
            // cleanup closes the final crash window. The observer receives
            // the exact captured artifact membership; it must not infer
            // coverage until cleanup is durably complete.
            observer(&report)?;
            return Ok(report);
        }

        let outcome = match runtime_result {
            Ok(outcome) => outcome,
            Err(error) => {
                report.fail(error.to_string());
                return Ok(report);
            }
        };
        report.exit_code = outcome.exit_code;
        if outcome.cancelled || cancellation.is_cancelled() {
            report.checkpoint.stage = ExecutionStage::Cancelled;
            return Ok(report);
        }
        if outcome.exit_code != Some(0) {
            if captured_stderr_contains_local_input_profile_rejection(&capture) {
                report.checkpoint.failure_code = Some("local_input_profile_unsupported".into());
                report.fail(
                    "This check could not read the kind of local input this target provides.",
                );
            } else {
                report.fail(format!(
                    "scanner container exited with status {:?}",
                    outcome.exit_code
                ));
            }
            return Ok(report);
        }
        if report.checkpoint.stage == ExecutionStage::Failed {
            return Ok(report);
        }

        report.checkpoint.stage = ExecutionStage::AdaptingArtifacts;
        observer(&report)?;
        self.adapt_captured(request, &mut report);
        Ok(report)
    }

    pub fn resume_captured(
        &self,
        request: &EngineExecutionRequest<'_>,
        previous: &ExecutionReport,
    ) -> AppResult<ExecutionReport> {
        resume_captured_artifacts(self.adapters, request, previous)
    }

    pub fn cleanup_checkpoint(
        &self,
        checkpoint: &ExecutionCheckpoint,
        ownership: &crate::container_runtime::OwnedContainerCleanupRequest,
    ) -> AppResult<ExecutionCheckpoint> {
        if checkpoint.resume_action() != ResumeAction::CleanupContainer {
            return Err(AppError::InvalidRequest(
                "checkpoint does not require cleanup".into(),
            ));
        }
        checkpoint.validate()?;
        if checkpoint.managed_network.is_some() {
            return Err(AppError::NotAvailable(
                "container-only cleanup cannot close a managed egress obligation; reconcile the exact durable network identity first"
                    .into(),
            ));
        }
        let container_name = checkpoint
            .container_name
            .as_deref()
            .ok_or_else(|| AppError::Runtime("cleanup checkpoint has no container name".into()))?;
        if ownership.container_name()? != container_name
            || ownership.case_id != checkpoint.case_id
            || ownership.scan_run_id != checkpoint.scan_run_id
            || ownership.engine_run_id != checkpoint.engine_run_id
            || ownership.engine_id != checkpoint.engine_id
            || ownership.attempt != checkpoint.attempt
            || Some(ownership.scope_sha256.as_str()) != checkpoint.scope_sha256.as_deref()
            || ownership.launcher_plan_sha256.as_deref()
                != checkpoint.launcher_plan_sha256.as_deref()
            || ownership.zap_plan_sha256.as_deref() != checkpoint.zap_plan_sha256.as_deref()
        {
            return Err(AppError::NotAuthorized(
                "cleanup ownership proof does not match the saved execution checkpoint".into(),
            ));
        }
        self.runtime.cleanup(ownership, None)?;
        let mut updated = checkpoint.clone();
        updated.cleanup_completed = true;
        updated.stage = ExecutionStage::Failed;
        updated.last_error = Some("container cleanup completed; execution may be retried".into());
        Ok(updated)
    }

    fn adapt_captured(&self, request: &EngineExecutionRequest<'_>, report: &mut ExecutionReport) {
        adapt_captured_artifacts(self.adapters, request, report);
    }
}

const STDERR_FAILURE_CLASSIFICATION_TAIL_BYTES: usize = 64 * 1024;

fn captured_stderr_contains_local_input_profile_rejection(capture: &CapturePaths) -> bool {
    stderr_tail_contains_local_input_profile_rejection(
        capture.read_stderr_tail(STDERR_FAILURE_CLASSIFICATION_TAIL_BYTES),
    )
}

fn stderr_tail_contains_local_input_profile_rejection(stderr: std::io::Result<Vec<u8>>) -> bool {
    stderr.ok().is_some_and(|stderr| {
        stderr
            .windows(LOCAL_INPUT_PROFILE_REJECTION_MARKER.len())
            .any(|window| window == LOCAL_INPUT_PROFILE_REJECTION_MARKER.as_bytes())
    })
}

/// Re-runs only the bounded adapter over already-hashed artifacts. Runtime
/// cleanup and managed-network reconciliation remain the caller's obligation;
/// when those are already durably complete, this function needs no container
/// runtime and cannot contend with a newly starting scan.
pub fn resume_captured_artifacts(
    adapters: &AdapterRegistry,
    request: &EngineExecutionRequest<'_>,
    previous: &ExecutionReport,
) -> AppResult<ExecutionReport> {
    if previous.checkpoint.resume_action() != ResumeAction::AdaptCapturedArtifacts {
        return Err(AppError::InvalidRequest(format!(
            "execution at stage {:?} cannot resume from captured artifacts",
            previous.checkpoint.stage
        )));
    }
    if previous.checkpoint.case_id != request.case_id
        || previous.checkpoint.scan_run_id != request.scan_run_id
        || previous.checkpoint.engine_run_id != request.engine_run_id
        || previous.checkpoint.engine_id != request.manifest.id
    {
        return Err(AppError::InvalidRequest(
            "resume request does not match the saved execution checkpoint".into(),
        ));
    }
    let mut report = previous.clone();
    adapt_captured_artifacts(adapters, request, &mut report);
    Ok(report)
}

fn adapt_captured_artifacts(
    adapters: &AdapterRegistry,
    request: &EngineExecutionRequest<'_>,
    report: &mut ExecutionReport,
) {
    report.checkpoint.stage = ExecutionStage::AdaptingArtifacts;
    let asset_ids: Vec<String> = request
        .assets
        .iter()
        .map(|asset| asset.id.clone())
        .collect();
    let asset_identifier_map = AdapterAssetIdentifierMap::from_assets(request.assets);
    let input = AdapterInput {
        case_id: request.case_id,
        scan_run_id: request.scan_run_id,
        engine_run_id: request.engine_run_id,
        manifest: request.manifest,
        ai_system_applicable: request.ai_system_applicable,
        ai_generated_artifact_applicable: request.ai_generated_artifact_applicable,
        asset_ids: &asset_ids,
        asset_identifier_map: &asset_identifier_map,
        artifact_root: &report.artifact_root,
        raw_artifacts: &report.raw_artifacts,
    };
    match adapters.normalize(&input) {
        Ok(Some(output)) => {
            report.findings = output.findings;
            report.observations = output.observations;
            report.warnings.extend(output.warnings);
            report.unattributed = output.unattributed;
            report.unevaluated_targets = output.unevaluated_targets;
            report.security_template_executions = output.security_template_executions;
            report.manual_review_controls = output.manual_review_controls;
            if output.complete {
                report.checkpoint.stage = ExecutionStage::Completed;
                report.checkpoint.last_error = None;
            } else {
                report.checkpoint.stage = ExecutionStage::CapturedAwaitingAdapter;
                report.checkpoint.last_error =
                    Some("adapter normalization was incomplete; raw evidence was retained".into());
            }
        }
        Ok(None) => {
            report.findings.clear();
            report.observations.clear();
            report.unevaluated_targets.clear();
            report.security_template_executions.clear();
            report.manual_review_controls.clear();
            report.warnings.push(format!(
                "scanner output was captured, but no verified adapter is registered for {} version {}",
                request.manifest.id, request.manifest.adapter_version
            ));
            report.checkpoint.stage = ExecutionStage::CapturedAwaitingAdapter;
            report.checkpoint.last_error = None;
        }
        Err(error) => {
            report.findings.clear();
            report.observations.clear();
            report.unevaluated_targets.clear();
            report.security_template_executions.clear();
            report.manual_review_controls.clear();
            report.warnings.push(format!(
                "scanner output was captured, but adapter {} version {} failed validation",
                request.manifest.id, request.manifest.adapter_version
            ));
            report.checkpoint.stage = ExecutionStage::CapturedAwaitingAdapter;
            report.checkpoint.last_error = Some(error.to_string());
        }
    }
}

#[derive(Debug, Clone)]
struct ValidatedAssetScope<'a> {
    asset: &'a Asset,
    identifiers: Vec<&'a AssetIdentifier>,
    grants: Vec<&'a ScopeGrant>,
}

/// Derive the private plan from the validated frozen grant, never from a
/// caller-provided command or automation document. One grant is one task.
fn zap_plan_for_request(
    request: &EngineExecutionRequest<'_>,
    scope: &[ValidatedAssetScope<'_>],
) -> AppResult<Option<ZapPlanDocument>> {
    if request.manifest.id != ZAP_ENGINE_ID {
        return Ok(None);
    }
    if scope.len() != 1 || request.scope_grants.len() != 1 || scope[0].grants.len() != 1 {
        return Err(AppError::NotAuthorized(
            "ZAP requires one exact website authorization per check".into(),
        ));
    }
    let external = scope[0].grants[0].external_scope.as_ref().ok_or_else(|| {
        AppError::NotAuthorized("ZAP requires a structured website authorization".into())
    })?;
    if !matches_zap_passive_profile(
        external.activity,
        external.protocol,
        &external.ports,
        &external.rate_policy,
        &external.template_policy,
    ) {
        return Err(AppError::NotAuthorized(
            "ZAP requires its reviewed passive website profile".into(),
        ));
    }
    let gateway = url::Url::parse(request.network_policy.gateway_endpoint().ok_or_else(|| {
        AppError::NotAuthorized("ZAP requires the managed-network gateway".into())
    })?)
    .map_err(|_| AppError::NotAuthorized("ZAP gateway endpoint is malformed".into()))?;
    let host = match &external.target {
        crate::external_scope::CanonicalTarget::Hostname(host) => host.clone(),
        crate::external_scope::CanonicalTarget::Address(std::net::IpAddr::V4(ip)) => ip.to_string(),
        crate::external_scope::CanonicalTarget::Address(std::net::IpAddr::V6(ip)) => {
            format!("[{ip}]")
        }
        crate::external_scope::CanonicalTarget::Network(_) => {
            return Err(AppError::NotAuthorized(
                "ZAP cannot crawl a network range".into(),
            ));
        }
    };
    let scheme = match external.protocol {
        crate::external_scope::TransportProtocol::Http => "http",
        crate::external_scope::TransportProtocol::Https => "https",
        _ => return Err(AppError::NotAuthorized("ZAP requires HTTP or HTTPS".into())),
    };
    let port = external
        .ports
        .iter()
        .next()
        .expect("reviewed profile has one port");
    let origin = url::Url::parse(&format!("{scheme}://{host}:{port}/"))
        .map_err(|_| AppError::NotAuthorized("ZAP approved origin is malformed".into()))?;
    let plan = build_zap_passive_plan(
        &origin,
        &ZapGatewayEndpoint {
            host: gateway
                .host_str()
                .ok_or_else(|| AppError::NotAuthorized("ZAP gateway has no host".into()))?
                .into(),
            port: gateway
                .port()
                .ok_or_else(|| AppError::NotAuthorized("ZAP gateway has no port".into()))?,
        },
        &ZapPassiveBounds {
            requests_per_second: external.rate_policy.requests_per_second,
            request_timeout_seconds: 10,
            thread_count: external.rate_policy.concurrency,
            max_depth: 5,
            max_children: 100,
            spider_max_duration_minutes: 2,
            passive_wait_max_duration_minutes: 2,
            max_alerts_per_rule: 100,
        },
        "/output",
        "zap",
    )
    .map_err(|error| AppError::NotAuthorized(error.to_string()))?;
    Ok(Some(plan))
}

#[cfg(test)]
fn validate_execution_scope<'a>(
    manifest: &EngineManifest,
    assets: &'a [Asset],
    grants: &'a [ScopeGrant],
    network_policy: &NetworkPolicy,
) -> AppResult<Vec<ValidatedAssetScope<'a>>> {
    validate_execution_scope_for_request(manifest, assets, grants, network_policy, None, None)
}

fn validate_execution_scope_for_request<'a>(
    manifest: &EngineManifest,
    assets: &'a [Asset],
    grants: &'a [ScopeGrant],
    network_policy: &NetworkPolicy,
    frozen_destinations: Option<&[GatewayDestination]>,
    naabu_launcher_plan: Option<&NaabuLauncherPlanDocument>,
) -> AppResult<Vec<ValidatedAssetScope<'a>>> {
    if assets.is_empty() {
        return Err(AppError::NotAuthorized(format!(
            "engine {} has no explicitly selected assets",
            manifest.id
        )));
    }
    if manifest.id == crate::garak_input::ENGINE_ID && (assets.len() != 1 || grants.len() != 1) {
        return Err(AppError::NotAuthorized(
            "model check requires one exact asset and authorization".into(),
        ));
    }
    let direct_external = manifest.required_permissions.iter().any(|permission| {
        matches!(
            permission,
            ScanPermission::LowImpactExternalConnection | ScanPermission::ActiveExternalTesting
        )
    });
    if manifest.active_external && !direct_external {
        return Err(AppError::EngineRegistry(format!(
            "external target engine {} must require low-impact or active external permission",
            manifest.id
        )));
    }
    let mut asset_ids = BTreeSet::new();
    let now = Utc::now();
    let mut validated = Vec::new();

    for asset in assets {
        if !asset_ids.insert(asset.id.as_str()) {
            return Err(AppError::InvalidRequest(format!(
                "asset {} appears more than once in the engine run",
                asset.id
            )));
        }
        if !manifest.supports_asset(asset) {
            return Err(AppError::InvalidRequest(format!(
                "engine {} does not support the provider and kind contract for asset {} ({:?})",
                manifest.id, asset.id, asset.kind
            )));
        }

        let mut matched = Vec::new();
        for permission in &manifest.required_permissions {
            let grant = grants
                .iter()
                .find(|grant| {
                    grant.asset_id == asset.id
                        && grant.permission == *permission
                        && !grant.confirmed_by.trim().is_empty()
                        && grant.confirmed_at <= now
                        && grant.expires_at.is_none_or(|expires_at| expires_at > now)
                        && (!direct_external || grant.expires_at.is_some())
                })
                .ok_or_else(|| {
                    AppError::NotAuthorized(format!(
                        "asset {} lacks a current {:?} scope grant for engine {}",
                        asset.id, permission, manifest.id
                    ))
                })?;
            matched.push(grant);
        }

        let identifiers = if direct_external {
            if asset.candidate || !asset.owner_confirmed {
                return Err(AppError::NotAuthorized(format!(
                    "direct external engine {} requires confirmed ownership for asset {}",
                    manifest.id, asset.id
                )));
            }
            if matched.is_empty()
                || matched.iter().any(|grant| {
                    grant
                        .authorization_reference
                        .as_deref()
                        .unwrap_or_default()
                        .trim()
                        .is_empty()
                })
            {
                return Err(AppError::NotAuthorized(format!(
                    "direct external engine {} requires a written authorization reference for every permission on asset {}",
                    manifest.id, asset.id
                )));
            }
            let allowed_targets: BTreeSet<&str> = network_policy
                .allowed_destinations()
                .iter()
                .map(String::as_str)
                .collect();
            let mut structured_targets = BTreeSet::new();
            for grant in &matched {
                let external = grant.external_scope.as_ref().ok_or_else(|| {
                    AppError::NotAuthorized(format!(
                        "direct external grant {} has no structured target policy",
                        grant.id
                    ))
                })?;
                external.validate(now)?;
                if external.id != grant.id || external.asset_id != asset.id {
                    return Err(AppError::NotAuthorized(
                        "structured external policy does not match its grant and asset".into(),
                    ));
                }
                let expected_activity = match grant.permission {
                    ScanPermission::LowImpactExternalConnection => {
                        crate::external_scope::ExternalActivity::LowImpactExternal
                    }
                    ScanPermission::ActiveExternalTesting => {
                        crate::external_scope::ExternalActivity::ActiveExternal
                    }
                    _ => continue,
                };
                let gateway_represents_scope = if naabu_launcher_plan.is_some() {
                    true
                } else {
                    external_destination_is_frozen(external, &allowed_targets)
                };
                if external.activity != expected_activity || !gateway_represents_scope {
                    return Err(AppError::NotAuthorized(format!(
                        "structured external policy {} is not represented by the frozen managed gateway",
                        external.id
                    )));
                }
                structured_targets.insert(external.target.canonical_text());
            }
            let identifiers: Vec<&AssetIdentifier> =
                if manifest.id == crate::garak_input::ENGINE_ID {
                    let input = crate::garak_input::asset_input(asset)?;
                    if !matched.iter().all(|grant| {
                        grant.external_scope.as_ref().is_some_and(|external| {
                            input.matches_scope(external, now).unwrap_or(false)
                        })
                    }) {
                        return Err(AppError::NotAuthorized(
                            "model check does not match its exact endpoint authorization".into(),
                        ));
                    }
                    // The native launcher needs both the full URL and model. The
                    // validated typed input binds their host and port to the grant;
                    // matching an origin identifier would discard these coordinates.
                    asset
                        .identifiers
                        .iter()
                        .filter(|identifier| {
                            matches!(
                                identifier.namespace.as_str(),
                                crate::garak_input::ENDPOINT_NAMESPACE
                                    | crate::garak_input::MODEL_NAMESPACE
                            )
                        })
                        .collect()
                } else {
                    asset
                        .identifiers
                        .iter()
                        .filter(|identifier| structured_targets.contains(identifier.value.as_str()))
                        .collect()
                };
            if identifiers.is_empty() {
                return Err(AppError::NotAuthorized(format!(
                    "managed network policy does not allow an exact identifier for external asset {}",
                    asset.id
                )));
            }
            identifiers
        } else {
            asset.identifiers.iter().collect()
        };

        validated.push(ValidatedAssetScope {
            asset,
            identifiers,
            grants: matched,
        });
    }
    if let Some(plan) = naabu_launcher_plan {
        validate_naabu_launcher_gateway_binding(
            plan,
            &validated,
            frozen_destinations.ok_or_else(|| {
                AppError::NotAuthorized(
                    "Naabu launcher-v2 execution has no exact attempt gateway snapshot".into(),
                )
            })?,
            network_policy,
        )?;
    }
    Ok(validated)
}

fn external_destination_is_frozen(
    grant: &crate::external_scope::ExternalScopeGrant,
    destinations: &BTreeSet<&str>,
) -> bool {
    match &grant.target {
        crate::external_scope::CanonicalTarget::Hostname(hostname) => grant
            .ports
            .iter()
            .all(|port| destinations.contains(format!("{hostname}:{port}").as_str())),
        crate::external_scope::CanonicalTarget::Address(address) => {
            grant.ports.iter().all(|port| {
                destinations.contains(
                    std::net::SocketAddr::new(*address, *port)
                        .to_string()
                        .as_str(),
                )
            })
        }
        crate::external_scope::CanonicalTarget::Network(network) => {
            grant.ports.iter().all(|port| {
                destinations.iter().any(|destination| {
                    destination
                        .parse::<std::net::SocketAddr>()
                        .is_ok_and(|socket| {
                            socket.port() == *port && network.contains(&socket.ip())
                        })
                })
            })
        }
    }
}

/// Binds one versioned launcher attempt corpus to the original grants while
/// requiring the live managed gateway to expose exactly the rectangles chosen
/// for this one attempt. The current compact form has tighter aggregate bounds;
/// the legacy form retains its historical per-unit bounds only so frozen wire
/// evidence can be reconstructed and validated. Production network constructors
/// reject the legacy schema before provisioning.
fn validate_naabu_launcher_gateway_binding(
    plan: &NaabuLauncherPlanDocument,
    scope: &[ValidatedAssetScope<'_>],
    frozen_destinations: &[GatewayDestination],
    network_policy: &NetworkPolicy,
) -> AppResult<()> {
    let max_requested_work_units = match plan.schema_version {
        LEGACY_NAABU_LAUNCHER_PLAN_SCHEMA_VERSION => MAX_NAABU_WORK_UNITS,
        NAABU_LAUNCHER_PLAN_SCHEMA_VERSION => MAX_NAABU_WORK_UNITS_PER_ATTEMPT,
        _ => {
            return Err(AppError::InvalidRequest(
                "Naabu launcher gateway binding uses an unsupported plan schema".into(),
            ));
        }
    };
    if plan.frozen_grants.is_empty()
        || plan.requested_work_units.is_empty()
        || plan.requested_work_units.len() > max_requested_work_units
    {
        return Err(AppError::InvalidRequest(
            "Naabu launcher requires a bounded non-empty attempt".into(),
        ));
    }

    let mut external_by_grant = BTreeMap::new();
    for entry in scope {
        for grant in &entry.grants {
            let external = grant.external_scope.as_ref().ok_or_else(|| {
                AppError::NotAuthorized(format!(
                    "Naabu launcher grant {} has no structured external scope",
                    grant.id
                ))
            })?;
            if external_by_grant
                .insert(grant.id.as_str(), external)
                .is_some()
            {
                return Err(AppError::NotAuthorized(
                    "Naabu launcher scope contains a duplicate grant identity".into(),
                ));
            }
        }
    }
    let mut seen_frozen_grants = BTreeSet::new();
    let mut external_by_index = Vec::with_capacity(plan.frozen_grants.len());
    for frozen in &plan.frozen_grants {
        if frozen.scope_grant_id.is_empty()
            || frozen.scope_grant_id.len() > 256
            || !seen_frozen_grants.insert(frozen.scope_grant_id.as_str())
            || frozen.addresses.is_empty()
            || frozen.addresses.len() > MAX_NAABU_FROZEN_ADDRESSES
            || frozen.addresses.windows(2).any(|pair| pair[0] >= pair[1])
            || frozen.ports.is_empty()
            || frozen.ports.contains(&0)
            || frozen.ports.iter().copied().collect::<BTreeSet<_>>().len() != frozen.ports.len()
        {
            return Err(AppError::InvalidRequest(
                "Naabu launcher frozen grant corpus is not canonical and bounded".into(),
            ));
        }
        let external = external_by_grant
            .get(frozen.scope_grant_id.as_str())
            .copied()
            .ok_or_else(|| {
                AppError::NotAuthorized(format!(
                    "Naabu launcher frozen grant {} is outside the validated scope",
                    frozen.scope_grant_id
                ))
            })?;
        if frozen
            .ports
            .iter()
            .any(|port| !external.ports.contains(port))
            || frozen
                .addresses
                .iter()
                .any(|address| !external_target_contains_address(&external.target, *address))
        {
            return Err(AppError::NotAuthorized(format!(
                "Naabu launcher frozen grant {} changed its authorized address or port corpus",
                frozen.scope_grant_id
            )));
        }
        external_by_index.push(external);
    }

    let mut seen_units = BTreeSet::new();
    let mut seen_scope_hashes = BTreeSet::new();
    let mut referenced_grant_indices = BTreeSet::new();
    let mut rectangles_by_grant = BTreeMap::<usize, Vec<(usize, usize, usize, usize)>>::new();
    let mut endpoint_pairs = 0_u64;
    let mut expected_destinations = Vec::with_capacity(plan.requested_work_units.len());
    for unit in &plan.requested_work_units {
        if unit.unit_id.is_empty()
            || !seen_units.insert(unit.unit_id.as_str())
            || unit.scope_sha256.len() != 64
            || !unit
                .scope_sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
            || !seen_scope_hashes.insert(unit.scope_sha256.as_str())
            || unit.address_len == 0
            || unit.port_len == 0
        {
            return Err(AppError::InvalidRequest(
                "Naabu launcher work-unit identity or rectangle is invalid".into(),
            ));
        }
        let grant_index = usize::try_from(unit.grant_index)
            .map_err(|_| AppError::InvalidRequest("Naabu grant index overflowed".into()))?;
        let frozen = plan.frozen_grants.get(grant_index).ok_or_else(|| {
            AppError::InvalidRequest("Naabu work unit refers to a missing frozen grant".into())
        })?;
        referenced_grant_indices.insert(grant_index);
        let external = external_by_index[grant_index];
        let address_start = usize::try_from(unit.address_start)
            .map_err(|_| AppError::InvalidRequest("Naabu address offset overflowed".into()))?;
        let address_len = usize::try_from(unit.address_len)
            .map_err(|_| AppError::InvalidRequest("Naabu address length overflowed".into()))?;
        let port_start = usize::try_from(unit.port_start)
            .map_err(|_| AppError::InvalidRequest("Naabu port offset overflowed".into()))?;
        let port_len = usize::try_from(unit.port_len)
            .map_err(|_| AppError::InvalidRequest("Naabu port length overflowed".into()))?;
        let address_end = address_start
            .checked_add(address_len)
            .ok_or_else(|| AppError::InvalidRequest("Naabu address range overflowed".into()))?;
        let port_end = port_start
            .checked_add(port_len)
            .ok_or_else(|| AppError::InvalidRequest("Naabu port range overflowed".into()))?;
        let addresses = frozen
            .addresses
            .get(address_start..address_end)
            .ok_or_else(|| {
                AppError::InvalidRequest("Naabu work unit exceeds its frozen address corpus".into())
            })?;
        let ports = frozen.ports.get(port_start..port_end).ok_or_else(|| {
            AppError::InvalidRequest("Naabu work unit exceeds its frozen port corpus".into())
        })?;
        let pair_count = u64::try_from(addresses.len())
            .ok()
            .and_then(|addresses| {
                u64::try_from(ports.len())
                    .ok()
                    .and_then(|ports| addresses.checked_mul(ports))
            })
            .ok_or_else(|| AppError::InvalidRequest("Naabu endpoint count overflowed".into()))?;
        if pair_count > MAX_NAABU_ENDPOINT_PAIRS_PER_UNIT || pair_count != unit.endpoint_pair_count
        {
            return Err(AppError::InvalidRequest(
                "Naabu work-unit endpoint count is outside its per-unit bound or does not match its exact rectangle"
                    .into(),
            ));
        }
        let prior_rectangles = rectangles_by_grant.entry(grant_index).or_default();
        if prior_rectangles.iter().any(
            |(prior_address_start, prior_address_end, prior_port_start, prior_port_end)| {
                address_start < *prior_address_end
                    && *prior_address_start < address_end
                    && port_start < *prior_port_end
                    && *prior_port_start < port_end
            },
        ) {
            return Err(AppError::InvalidRequest(
                "Naabu launcher work units overlap within one frozen grant".into(),
            ));
        }
        prior_rectangles.push((address_start, address_end, port_start, port_end));
        endpoint_pairs = endpoint_pairs
            .checked_add(pair_count)
            .ok_or_else(|| AppError::InvalidRequest("Naabu attempt size overflowed".into()))?;
        expected_destinations.push(GatewayDestination {
            hostname: match &external.target {
                crate::external_scope::CanonicalTarget::Hostname(hostname) => {
                    Some(hostname.clone())
                }
                crate::external_scope::CanonicalTarget::Address(_)
                | crate::external_scope::CanonicalTarget::Network(_) => None,
            },
            addresses: addresses.iter().copied().collect(),
            ports: ports.iter().copied().collect(),
            allow_sensitive_networks: external.allow_sensitive_networks,
        });
    }
    if plan.schema_version == NAABU_LAUNCHER_PLAN_SCHEMA_VERSION
        && (referenced_grant_indices.len() != plan.frozen_grants.len()
            || !(0..plan.frozen_grants.len())
                .all(|index| referenced_grant_indices.contains(&index)))
    {
        return Err(AppError::InvalidRequest(
            "Naabu compact frozen grants must all be referenced by this exact attempt".into(),
        ));
    }
    if plan.schema_version == NAABU_LAUNCHER_PLAN_SCHEMA_VERSION
        && endpoint_pairs > MAX_NAABU_ENDPOINT_PAIRS_PER_ATTEMPT
    {
        return Err(AppError::InvalidRequest(format!(
            "Naabu launcher attempt exceeds {MAX_NAABU_ENDPOINT_PAIRS_PER_ATTEMPT} exact endpoints"
        )));
    }

    expected_destinations.sort();
    // Distinct grants may authorize the same exact endpoint rectangle. The
    // managed gateway canonicalizes those equal destinations, so bind against
    // that same canonical set after validating each grant and each unit above.
    expected_destinations.dedup();
    let mut actual_destinations = frozen_destinations.to_vec();
    let actual_count = actual_destinations.len();
    actual_destinations.sort();
    actual_destinations.dedup();
    if actual_destinations.len() != actual_count || actual_destinations != expected_destinations {
        return Err(AppError::NotAuthorized(
            "Naabu attempt gateway is not exactly equal to its selected work-unit rectangles"
                .into(),
        ));
    }
    let expected_labels = gateway_destination_labels(&expected_destinations);
    let actual_labels = network_policy
        .allowed_destinations()
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    if actual_labels.len() != network_policy.allowed_destinations().len()
        || actual_labels != expected_labels
    {
        return Err(AppError::NotAuthorized(
            "Naabu managed network policy is not exact for this launcher attempt".into(),
        ));
    }
    Ok(())
}

fn external_target_contains_address(
    target: &crate::external_scope::CanonicalTarget,
    address: IpAddr,
) -> bool {
    match target {
        crate::external_scope::CanonicalTarget::Hostname(_) => true,
        crate::external_scope::CanonicalTarget::Address(expected) => *expected == address,
        crate::external_scope::CanonicalTarget::Network(network) => network.contains(&address),
    }
}

fn gateway_destination_labels(destinations: &[GatewayDestination]) -> BTreeSet<String> {
    let mut labels = BTreeSet::new();
    for destination in destinations {
        for port in &destination.ports {
            if let Some(hostname) = destination.hostname.as_deref() {
                labels.insert(format!("{hostname}:{port}"));
            } else {
                for address in &destination.addresses {
                    labels.insert(std::net::SocketAddr::new(*address, *port).to_string());
                }
            }
        }
    }
    labels
}

#[derive(Debug, Serialize)]
struct ScopeDocument<'a> {
    schema_version: &'static str,
    engine_id: &'a str,
    generated_at: String,
    assets: Vec<ScopeAssetDocument<'a>>,
}

#[derive(Debug, Serialize)]
struct ScopeAssetDocument<'a> {
    id: &'a str,
    name: &'a str,
    kind: &'a crate::domain::AssetKind,
    provider: Option<&'a str>,
    region: Option<&'a str>,
    identifiers: Vec<&'a AssetIdentifier>,
    grants: Vec<ScopeGrantDocument<'a>>,
}

#[derive(Debug, Serialize)]
struct ScopeGrantDocument<'a> {
    id: &'a str,
    permission: &'a ScanPermission,
    confirmed_by: &'a str,
    confirmed_at: String,
    expires_at: Option<String>,
    authorization_reference: Option<&'a str>,
    external_scope: Option<Cow<'a, crate::external_scope::ExternalScopeGrant>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    resolved_addresses: Option<Vec<String>>,
}

impl<'a> ScopeDocument<'a> {
    #[cfg(test)]
    fn new(
        manifest: &'a EngineManifest,
        scope: &'a [ValidatedAssetScope<'a>],
        frozen_destinations: Option<&[GatewayDestination]>,
    ) -> AppResult<Self> {
        Self::new_for_request(manifest, scope, frozen_destinations, None)
    }

    fn new_for_request(
        manifest: &'a EngineManifest,
        scope: &'a [ValidatedAssetScope<'a>],
        frozen_destinations: Option<&[GatewayDestination]>,
        naabu_launcher_plan: Option<&NaabuLauncherPlanDocument>,
    ) -> AppResult<Self> {
        let external_launcher = uses_external_launcher(&manifest.id);
        let destinations = if external_launcher {
            frozen_destinations.ok_or_else(|| {
                AppError::NotAuthorized(format!(
                    "engine {} has no frozen address snapshot for its external launcher",
                    manifest.id
                ))
            })?;
            Some(frozen_destinations.expect("external launcher destination was required"))
        } else {
            None
        };
        let launcher_grant_ids = naabu_launcher_plan.map(|plan| {
            plan.frozen_grants
                .iter()
                .map(|grant| grant.scope_grant_id.as_str())
                .collect::<BTreeSet<_>>()
        });
        // The control file is exact-only and may already exist after a crash.
        // Anchor its required timestamp to durable authorization input rather
        // than wall-clock serialization time so replaying the same attempt is
        // byte-for-byte identical. Validated execution scope always contains
        // at least one grant.
        let generated_at = scope
            .iter()
            .flat_map(|entry| entry.grants.iter())
            .filter(|grant| {
                launcher_grant_ids
                    .as_ref()
                    .is_none_or(|selected| selected.contains(grant.id.as_str()))
            })
            .map(|grant| grant.confirmed_at)
            .max()
            .ok_or_else(|| {
                AppError::NotAuthorized(
                    "validated execution scope contains no durable authorization timestamp".into(),
                )
            })?
            .to_rfc3339();
        let mut assets = Vec::new();
        for entry in scope {
            let mut grants = Vec::new();
            for grant in &entry.grants {
                if launcher_grant_ids
                    .as_ref()
                    .is_some_and(|selected| !selected.contains(grant.id.as_str()))
                {
                    continue;
                }
                let resolved_addresses = match (destinations, naabu_launcher_plan) {
                    (Some(_), Some(plan)) => {
                        let external = grant.external_scope.as_ref().ok_or_else(|| {
                            AppError::NotAuthorized(format!(
                                "external launcher grant {} has no structured target policy",
                                grant.id
                            ))
                        })?;
                        Some(frozen_addresses_for_launcher_grant(external, plan)?)
                    }
                    (Some(destinations), None) => {
                        let external = grant.external_scope.as_ref().ok_or_else(|| {
                            AppError::NotAuthorized(format!(
                                "external launcher grant {} has no structured target policy",
                                grant.id
                            ))
                        })?;
                        Some(frozen_addresses_for_grant(external, destinations)?)
                    }
                    (None, None) => None,
                    (None, Some(_)) => {
                        return Err(AppError::NotAuthorized(
                            "Naabu launcher plan requires a managed gateway snapshot".into(),
                        ));
                    }
                };
                let external_scope = match (grant.external_scope.as_ref(), naabu_launcher_plan) {
                    (Some(external), Some(plan))
                        if plan.schema_version == NAABU_LAUNCHER_PLAN_SCHEMA_VERSION =>
                    {
                        let frozen = unique_launcher_grant(plan, &grant.id)?;
                        let mut projected = external.clone();
                        projected.ports = frozen.ports.iter().copied().collect();
                        Some(Cow::Owned(projected))
                    }
                    (Some(external), _) => Some(Cow::Borrowed(external)),
                    (None, _) => None,
                };
                grants.push(ScopeGrantDocument {
                    id: &grant.id,
                    permission: &grant.permission,
                    confirmed_by: &grant.confirmed_by,
                    confirmed_at: grant.confirmed_at.to_rfc3339(),
                    expires_at: grant.expires_at.map(|value| value.to_rfc3339()),
                    authorization_reference: grant.authorization_reference.as_deref(),
                    external_scope,
                    resolved_addresses,
                });
            }
            if !grants.is_empty() {
                assets.push(ScopeAssetDocument {
                    id: &entry.asset.id,
                    name: &entry.asset.name,
                    kind: &entry.asset.kind,
                    provider: entry.asset.provider.as_deref(),
                    region: entry.asset.region.as_deref(),
                    identifiers: entry.identifiers.clone(),
                    grants,
                });
            }
        }
        if assets.is_empty() {
            return Err(AppError::NotAuthorized(
                "Naabu compact launcher scope contains no selected asset grant".into(),
            ));
        }
        Ok(Self {
            schema_version: if external_launcher { "2" } else { "1" },
            engine_id: &manifest.id,
            generated_at,
            assets,
        })
    }
}

fn uses_external_launcher(engine_id: &str) -> bool {
    matches!(engine_id, "naabu" | "httpx" | "nuclei")
}

fn frozen_addresses_for_launcher_grant(
    grant: &crate::external_scope::ExternalScopeGrant,
    plan: &NaabuLauncherPlanDocument,
) -> AppResult<Vec<String>> {
    let frozen = unique_launcher_grant(plan, &grant.id)?;
    if frozen.addresses.is_empty()
        || frozen.addresses.len() > MAX_NAABU_FROZEN_ADDRESSES
        || frozen
            .addresses
            .iter()
            .any(|address| !external_target_contains_address(&grant.target, *address))
        || frozen.ports.iter().any(|port| !grant.ports.contains(port))
    {
        return Err(AppError::NotAuthorized(format!(
            "external grant {} does not contain the launcher frozen corpus",
            grant.id
        )));
    }
    Ok(frozen.addresses.iter().map(ToString::to_string).collect())
}

fn unique_launcher_grant<'a>(
    plan: &'a NaabuLauncherPlanDocument,
    grant_id: &str,
) -> AppResult<&'a crate::naabu_work_plan::NaabuLauncherFrozenGrant> {
    let mut matches = plan
        .frozen_grants
        .iter()
        .filter(|frozen| frozen.scope_grant_id == grant_id);
    let frozen = matches.next().ok_or_else(|| {
        AppError::NotAuthorized(format!(
            "external grant {grant_id} is absent from the launcher frozen corpus"
        ))
    })?;
    if matches.next().is_some() {
        return Err(AppError::NotAuthorized(format!(
            "external grant {grant_id} appears more than once in the launcher frozen corpus"
        )));
    }
    Ok(frozen)
}

fn frozen_addresses_for_grant(
    grant: &crate::external_scope::ExternalScopeGrant,
    destinations: &[GatewayDestination],
) -> AppResult<Vec<String>> {
    const MAX_FROZEN_ADDRESSES: usize = 4_096;

    let expected_static_addresses = match &grant.target {
        crate::external_scope::CanonicalTarget::Address(address) => {
            Some(BTreeSet::from([*address]))
        }
        crate::external_scope::CanonicalTarget::Network(network) => {
            let addresses = network
                .hosts()
                .take(MAX_FROZEN_ADDRESSES + 1)
                .collect::<BTreeSet<_>>();
            if addresses.len() > MAX_FROZEN_ADDRESSES {
                return Err(AppError::InvalidRequest(format!(
                    "external grant {} expands beyond the frozen address limit",
                    grant.id
                )));
            }
            Some(addresses)
        }
        crate::external_scope::CanonicalTarget::Hostname(_) => None,
    };
    let mut addresses = BTreeSet::<IpAddr>::new();
    for destination in destinations {
        if destination.ports != grant.ports
            || destination.allow_sensitive_networks != grant.allow_sensitive_networks
        {
            continue;
        }
        let matches_target = match (&grant.target, &expected_static_addresses) {
            (crate::external_scope::CanonicalTarget::Hostname(hostname), None) => {
                destination.hostname.as_deref() == Some(hostname.as_str())
            }
            (
                crate::external_scope::CanonicalTarget::Address(_)
                | crate::external_scope::CanonicalTarget::Network(_),
                Some(expected),
            ) => destination.hostname.is_none() && destination.addresses == *expected,
            _ => false,
        };
        if matches_target {
            addresses.extend(destination.addresses.iter().copied());
        }
    }
    if addresses.is_empty() || addresses.len() > MAX_FROZEN_ADDRESSES {
        return Err(AppError::NotAuthorized(format!(
            "external grant {} is not represented by one bounded frozen address set",
            grant.id
        )));
    }
    Ok(addresses
        .into_iter()
        .map(|address| address.to_string())
        .collect())
}

fn run_directories_with_workspace(
    directories: &RunDirectories,
    workspace: &Path,
) -> RunDirectories {
    RunDirectories {
        root: directories.root.clone(),
        workspace: workspace.to_path_buf(),
        output: directories.output.clone(),
        control: directories.control.clone(),
        raw: directories.raw.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapter::{AdapterOutput, EngineAdapter};
    use crate::artifact_store::CapturePaths;
    use crate::container_runtime::{
        ContainerRunPlan, CreatedContainer, FakeContainerRuntime, FakeRunBehavior,
        OwnedContainerCleanupRequest, RuntimeCall, RuntimeOutcome,
    };
    use crate::domain::{
        AssetIdentifier, AssetKind, DistributionMode, EngineCategory, EngineCompatibility,
        EngineExecutionContract, EngineExecutionResources, ImageReference, ManifestStatus,
    };
    use crate::external_scope::{
        CanonicalTarget, ExternalActivity, ExternalScopeGrant, RatePolicy, TemplatePolicy,
        TransportProtocol,
    };
    use crate::naabu_work_plan::{NaabuLauncherFrozenGrant, NaabuLauncherWorkUnit};
    use chrono::Duration;
    use sha2::{Digest, Sha256};
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex};

    #[test]
    fn model_scope_retains_full_coordinates_and_rejects_mismatched_authorization() {
        use crate::garak_input::{
            ENDPOINT_NAMESPACE, METADATA_KEY, MODEL_NAMESPACE, ModelEndpointInput,
        };
        let catalog: Vec<EngineManifest> =
            serde_json::from_str(include_str!("../../engines/catalog.json")).unwrap();
        let manifest = catalog.iter().find(|entry| entry.id == "garak").unwrap();
        let input = ModelEndpointInput::validated(
            "https://model.example.test:8443/v1/chat/completions",
            "fixture/model",
        )
        .unwrap();
        let model_asset = Asset {
            id: "model-1".into(),
            kind: AssetKind::AiModelEndpoint,
            name: "Fixture model".into(),
            provider: None,
            region: None,
            identifiers: vec![
                AssetIdentifier {
                    namespace: ENDPOINT_NAMESPACE.into(),
                    value: input.endpoint.clone(),
                },
                AssetIdentifier {
                    namespace: MODEL_NAMESPACE.into(),
                    value: input.model.clone(),
                },
            ],
            discovered_from: vec![],
            candidate: false,
            owner_confirmed: true,
            internet_exposed: Some(true),
            contains_sensitive_data: None,
            metadata: BTreeMap::from([(METADATA_KEY.into(), serde_json::json!(input))]),
        };
        let mut model_grant = grant(&model_asset.id, ScanPermission::ActiveExternalTesting, true);
        let external = model_grant.external_scope.as_mut().unwrap();
        external.id = model_grant.id.clone();
        external.target = input.target().unwrap();
        external.ports = BTreeSet::from([8443]);
        external.protocol = TransportProtocol::Https;
        external.rate_policy = RatePolicy {
            requests_per_second: 1,
            concurrency: 1,
            timeout_seconds: 20,
        };
        external.template_policy = TemplatePolicy::conservative_profile(
            crate::garak_input::SOURCE_REVISION,
            crate::garak_input::PROFILE_ID,
        );
        let policy = NetworkPolicy::managed(
            "model-network",
            "model-policy",
            vec!["model.example.test:8443".into()],
            "socks5h://172.29.0.1:1080",
        )
        .unwrap();
        let assets = [model_asset.clone()];
        let grants = [model_grant.clone()];
        let scope = validate_execution_scope(manifest, &assets, &grants, &policy).unwrap();
        let document =
            serde_json::to_value(ScopeDocument::new(manifest, &scope, None).unwrap()).unwrap();
        assert_eq!(
            document["assets"][0]["identifiers"],
            serde_json::json!(model_asset.identifiers)
        );

        for mismatch in ["host", "port", "rate", "profile"] {
            let mut changed = model_grant.clone();
            let external = changed.external_scope.as_mut().unwrap();
            match mismatch {
                "host" => external.target = CanonicalTarget::parse("other.example.test").unwrap(),
                "port" => {
                    external.ports.insert(443);
                }
                "rate" => external.rate_policy.requests_per_second = 2,
                "profile" => external.template_policy.profile_id = Some("other".into()),
                _ => unreachable!(),
            }
            assert!(
                validate_execution_scope(manifest, &assets, &[changed], &policy).is_err(),
                "{mismatch}"
            );
        }
        let mut changed = model_asset.clone();
        changed.identifiers[1].value = "different/model".into();
        assert!(validate_execution_scope(manifest, &[changed], &grants, &policy).is_err());
        assert!(
            validate_execution_scope(
                manifest,
                &assets,
                &[model_grant.clone(), model_grant],
                &policy
            )
            .is_err()
        );
    }

    struct IncompleteAdapter;

    impl EngineAdapter for IncompleteAdapter {
        fn engine_id(&self) -> &str {
            "scanner"
        }

        fn adapter_version(&self) -> &str {
            "adapter-1"
        }

        fn normalize(&self, input: &AdapterInput<'_>) -> AppResult<AdapterOutput> {
            let artifact = input
                .raw_artifacts
                .first()
                .expect("captured adapter input includes raw evidence");
            Ok(AdapterOutput {
                unattributed: Vec::new(),
                unevaluated_targets: Vec::new(),
                security_template_executions: Vec::new(),
                manual_review_controls: Vec::new(),
                findings: Vec::new(),
                observations: vec![crate::domain::InventoryObservation {
                    id: "adapter-inventory-observation".into(),
                    case_id: input.case_id.into(),
                    run_id: input.scan_run_id.into(),
                    engine_run_id: input.engine_run_id.into(),
                    asset_id: input.asset_ids[0].clone(),
                    engine_id: input.manifest.id.clone(),
                    kind: crate::domain::InventoryObservationKind::CloudResource {
                        resource_type: "test_resource".into(),
                        native_id: Some("resource-1".into()),
                        display_name: None,
                    },
                    artifact_id: artifact.id.clone(),
                    artifact_sha256: artifact.sha256.clone(),
                    pointer: "/resources/0".into(),
                    observed_at: artifact.created_at,
                }],
                warnings: vec!["one malformed record was retained only as raw evidence".into()],
                complete: false,
            })
        }
    }

    struct MustNotRunAdapter;

    impl EngineAdapter for MustNotRunAdapter {
        fn engine_id(&self) -> &str {
            "scanner"
        }

        fn adapter_version(&self) -> &str {
            "adapter-1"
        }

        fn normalize(&self, _input: &AdapterInput<'_>) -> AppResult<AdapterOutput> {
            panic!("ownership-ambiguous runtime output must never reach an adapter")
        }
    }

    struct NaabuLauncherMustNotRunGenericAdapter;

    impl EngineAdapter for NaabuLauncherMustNotRunGenericAdapter {
        fn engine_id(&self) -> &str {
            NAABU_ENGINE_ID
        }

        fn adapter_version(&self) -> &str {
            "adapter-1"
        }

        fn normalize(&self, _input: &AdapterInput<'_>) -> AppResult<AdapterOutput> {
            panic!(
                "launcher-v2 journal, quarantine, and unvalidated finals must not reach the generic adapter"
            )
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct ObservedLauncherPlan {
        path: PathBuf,
        bytes: Vec<u8>,
        runtime_args: Vec<String>,
    }

    #[derive(Default)]
    struct LauncherPlanCaptureRuntime {
        observed: Mutex<Option<ObservedLauncherPlan>>,
    }

    impl LauncherPlanCaptureRuntime {
        fn observed(&self) -> Option<ObservedLauncherPlan> {
            self.observed.lock().expect("observed plan lock").clone()
        }

        fn preflight_result() -> RuntimePreflight {
            RuntimePreflight {
                provider: crate::container_runtime::RuntimeProvider::Docker,
                server_version: "launcher-plan-test".into(),
                security_options: "test-seccomp".into(),
                command_provenance: RuntimeCommandProvenance::Compatibility,
            }
        }
    }

    impl ContainerRuntime for LauncherPlanCaptureRuntime {
        fn preflight(&self) -> AppResult<RuntimePreflight> {
            Ok(Self::preflight_result())
        }

        fn execution_preflight(&self) -> AppResult<RuntimePreflight> {
            Ok(Self::preflight_result())
        }

        fn verify_network(&self, _policy: &NetworkPolicy) -> AppResult<()> {
            Ok(())
        }

        fn pull(&self, _image: &PinnedImage) -> AppResult<()> {
            Ok(())
        }

        fn run(
            &self,
            plan: &ContainerRunPlan,
            _credentials: &ScannerCredentialSet,
            _cancellation: &CancellationToken,
            _capture: &CapturePaths,
            created_container: &mut Option<CreatedContainer>,
            creation_may_be_untracked: &mut bool,
        ) -> AppResult<RuntimeOutcome> {
            *created_container = None;
            *creation_may_be_untracked = false;
            let path = plan
                .launcher_plan_file()
                .or_else(|| plan.zap_plan_file())
                .ok_or_else(|| {
                    AppError::Internal(
                        "versioned launcher plan was not mounted into the run plan".into(),
                    )
                })?;
            *self.observed.lock().expect("observed plan lock") = Some(ObservedLauncherPlan {
                path: path.to_path_buf(),
                bytes: std::fs::read(path)?,
                runtime_args: plan.runtime_args().to_vec(),
            });
            Err(AppError::Runtime(
                "test runtime stopped after observing the run plan".into(),
            ))
        }

        fn cleanup(
            &self,
            _ownership: &OwnedContainerCleanupRequest,
            _created_container: Option<&CreatedContainer>,
        ) -> AppResult<CleanupOutcome> {
            Err(AppError::Internal(
                "launcher-plan capture runtime must not create a container".into(),
            ))
        }
    }

    fn manifest(active_external: bool) -> EngineManifest {
        EngineManifest {
            schema_version: "1".into(),
            id: "scanner".into(),
            display_name: "Scanner".into(),
            category: if active_external {
                EngineCategory::ExternalAttackSurface
            } else {
                EngineCategory::CodeAndSecrets
            },
            description: "test scanner".into(),
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
            engine_version: Some("1".into()),
            reported_version: None,
            rule_version: Some("rules-1".into()),
            adapter_version: "adapter-1".into(),
            supported_providers: vec![],
            supported_asset_kinds: vec![if active_external {
                AssetKind::Domain
            } else {
                AssetKind::Repository
            }],
            input_contracts: vec![],
            provider_execution_contracts: vec![],
            direct_network_contract: active_external.then(|| {
                crate::domain::DirectNetworkExecutionContract {
                    target_kinds: vec![crate::external_scope::DirectNetworkTargetKind::Hostname],
                    protocols: vec![TransportProtocol::Https],
                }
            }),
            required_permissions: vec![if active_external {
                ScanPermission::ActiveExternalTesting
            } else {
                ScanPermission::LocalArtifactRead
            }],
            active_external,
            default_enabled: false,
            estimated_memory_mb: 512,
            estimated_disk_mb: 512,
            network_destinations: if active_external {
                vec!["authorized target services".into()]
            } else {
                vec![]
            },
            output_formats: vec!["json".into()],
            command: vec!["scanner".into(), "--json".into()],
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

    fn current_naabu_launcher_manifest() -> EngineManifest {
        let mut manifest = manifest(true);
        manifest.id = NAABU_ENGINE_ID.into();
        manifest.display_name = "Naabu".into();
        manifest.required_permissions = vec![ScanPermission::LowImpactExternalConnection];
        manifest.command = [
            "--engine",
            "naabu",
            "--scope",
            "/run/ai-security-scanner/scope.json",
            "--output",
            "/output",
            "--journal-version",
            "2",
            "--journal-plan",
            "/run/ai-security-scanner/execution-journal-v2.json",
        ]
        .map(str::to_owned)
        .to_vec();
        manifest.execution = Some(EngineExecutionContract {
            resources: EngineExecutionResources {
                timeout_seconds: 3_600,
                cpu_millis: 1_000,
            },
            launcher_journal_version: Some(LAUNCHER_V2_JOURNAL_SCHEMA_VERSION),
        });
        manifest
    }

    fn naabu_launcher_plan(engine_run_id: &str, attempt: u32) -> NaabuLauncherPlanDocument {
        NaabuLauncherPlanDocument {
            schema_version: NAABU_LAUNCHER_PLAN_SCHEMA_VERSION,
            engine_id: NAABU_ENGINE_ID.into(),
            engine_run_id: engine_run_id.into(),
            execution_attempt: attempt,
            frozen_grants: vec![NaabuLauncherFrozenGrant {
                scope_grant_id: "grant-one".into(),
                addresses: vec!["192.0.2.10".parse().expect("test address")],
                ports: vec![443],
            }],
            requested_work_units: vec![NaabuLauncherWorkUnit {
                unit_id: "wu_0123456789abcdef0123456789abcdef".into(),
                scope_sha256: "b".repeat(64),
                grant_index: 0,
                address_start: 0,
                address_len: 1,
                port_start: 0,
                port_len: 1,
                endpoint_pair_count: 1,
                conservative_deadline_seconds: 36,
            }],
        }
    }

    fn naabu_launcher_plan_sha256(plan: &NaabuLauncherPlanDocument) -> String {
        let encoded = serde_json::to_vec(plan).expect("launcher plan JSON");
        hex::encode(Sha256::digest(encoded))
    }

    #[test]
    fn compatible_launcher_accepts_legacy_v2_corpus_with_an_exact_attempt_gateway() {
        let manifest = current_naabu_launcher_manifest();
        let assets = vec![asset("one", true), asset("two", true)];
        let mut grants = vec![
            grant("one", ScanPermission::LowImpactExternalConnection, true),
            grant("two", ScanPermission::LowImpactExternalConnection, true),
        ];
        grants[0]
            .external_scope
            .as_mut()
            .expect("first scope")
            .ports = [80, 443].into_iter().collect();
        grants[1]
            .external_scope
            .as_mut()
            .expect("second scope")
            .ports = [22, 443].into_iter().collect();

        let plan = NaabuLauncherPlanDocument {
            schema_version: LEGACY_NAABU_LAUNCHER_PLAN_SCHEMA_VERSION,
            engine_id: NAABU_ENGINE_ID.into(),
            engine_run_id: "legacy-engine-run".into(),
            execution_attempt: 2,
            frozen_grants: vec![
                NaabuLauncherFrozenGrant {
                    scope_grant_id: "grant-one".into(),
                    addresses: vec!["192.0.2.11".parse().expect("first address")],
                    ports: vec![80, 443],
                },
                NaabuLauncherFrozenGrant {
                    scope_grant_id: "grant-two".into(),
                    addresses: vec!["198.51.100.22".parse().expect("second address")],
                    ports: vec![22, 443],
                },
            ],
            requested_work_units: vec![NaabuLauncherWorkUnit {
                unit_id: "wu_abcdefabcdefabcdefabcdefabcdefab".into(),
                scope_sha256: "c".repeat(64),
                grant_index: 0,
                address_start: 0,
                address_len: 1,
                port_start: 1,
                port_len: 1,
                endpoint_pair_count: 1,
                conservative_deadline_seconds: 36,
            }],
        };
        let plan_digest = naabu_launcher_plan_sha256(&plan);
        let frozen_destinations = vec![GatewayDestination {
            hostname: Some("one.example".into()),
            addresses: ["192.0.2.11".parse().expect("gateway address")]
                .into_iter()
                .collect(),
            ports: [443].into_iter().collect(),
            allow_sensitive_networks: false,
        }];
        let policy = NetworkPolicy::managed(
            "ass-egress",
            "policy-legacy-replay",
            vec!["one.example:443".into()],
            "socks5h://172.29.0.1:1080",
        )
        .expect("managed policy");
        let limits = ResourceLimits::default();
        let credentials = ScannerCredentialSet::default();
        let request = EngineExecutionRequest {
            case_id: "case-1",
            scan_run_id: "scan-run-1",
            engine_run_id: "legacy-engine-run",
            manifest: &manifest,
            ai_system_applicable: false,
            ai_generated_artifact_applicable: false,
            assets: &assets,
            scope_grants: &grants,
            frozen_destinations: Some(&frozen_destinations),
            naabu_launcher_plan: Some(&plan),
            expected_naabu_launcher_plan_sha256: Some(&plan_digest),
            workspace: None,
            network_policy: &policy,
            resource_limits: &limits,
            credentials: &credentials,
            attempt: 2,
        };

        validate_naabu_launcher_request(&request)
            .expect("current launcher must accept an exact legacy plan");
        let validated = validate_execution_scope_for_request(
            &manifest,
            &assets,
            &grants,
            &policy,
            Some(&frozen_destinations),
            Some(&plan),
        )
        .expect("legacy corpus with an exact selected gateway");
        let document = ScopeDocument::new_for_request(
            &manifest,
            &validated,
            Some(&frozen_destinations),
            Some(&plan),
        )
        .expect("legacy full-corpus scope document");
        let json = serde_json::to_value(document).expect("scope JSON");

        assert_eq!(json["assets"].as_array().map(Vec::len), Some(2));
        assert_eq!(
            json["assets"][0]["grants"][0]["external_scope"]["ports"],
            serde_json::json!([80, 443])
        );
        assert_eq!(
            json["assets"][1]["grants"][0]["external_scope"]["ports"],
            serde_json::json!([22, 443])
        );
        assert_eq!(policy.allowed_destinations(), ["one.example:443"]);
    }

    #[test]
    fn exact_gateway_binding_canonicalizes_duplicate_rectangles_across_grants_only() {
        let manifest = current_naabu_launcher_manifest();
        let mut second_asset = asset("two", true);
        second_asset.identifiers[0].value = "one.example".into();
        let assets = vec![asset("one", true), second_asset];
        let first = grant("one", ScanPermission::LowImpactExternalConnection, true);
        let mut second = grant("two", ScanPermission::LowImpactExternalConnection, true);
        let second_external = second.external_scope.as_mut().expect("second scope");
        second_external.target = CanonicalTarget::Hostname("one.example".into());
        let grants = vec![first, second];
        let address = "192.0.2.10".parse().expect("shared address");
        let plan = NaabuLauncherPlanDocument {
            schema_version: NAABU_LAUNCHER_PLAN_SCHEMA_VERSION,
            engine_id: NAABU_ENGINE_ID.into(),
            engine_run_id: "overlap-engine-run".into(),
            execution_attempt: 1,
            frozen_grants: vec![
                NaabuLauncherFrozenGrant {
                    scope_grant_id: "grant-one".into(),
                    addresses: vec![address],
                    ports: vec![443],
                },
                NaabuLauncherFrozenGrant {
                    scope_grant_id: "grant-two".into(),
                    addresses: vec![address],
                    ports: vec![443],
                },
            ],
            requested_work_units: vec![
                NaabuLauncherWorkUnit {
                    unit_id: "wu_11111111111111111111111111111111".into(),
                    scope_sha256: "1".repeat(64),
                    grant_index: 0,
                    address_start: 0,
                    address_len: 1,
                    port_start: 0,
                    port_len: 1,
                    endpoint_pair_count: 1,
                    conservative_deadline_seconds: 36,
                },
                NaabuLauncherWorkUnit {
                    unit_id: "wu_22222222222222222222222222222222".into(),
                    scope_sha256: "2".repeat(64),
                    grant_index: 1,
                    address_start: 0,
                    address_len: 1,
                    port_start: 0,
                    port_len: 1,
                    endpoint_pair_count: 1,
                    conservative_deadline_seconds: 36,
                },
            ],
        };
        let frozen_destinations = vec![GatewayDestination {
            hostname: Some("one.example".into()),
            addresses: [address].into_iter().collect(),
            ports: [443].into_iter().collect(),
            allow_sensitive_networks: false,
        }];
        let policy = NetworkPolicy::managed(
            "ass-egress",
            "policy-cross-grant-overlap",
            vec!["one.example:443".into()],
            "socks5h://172.29.0.1:1080",
        )
        .expect("managed policy");

        validate_execution_scope_for_request(
            &manifest,
            &assets,
            &grants,
            &policy,
            Some(&frozen_destinations),
            Some(&plan),
        )
        .expect("equal rectangles from distinct grants canonicalize to one gateway destination");

        let mut invalid_same_grant = plan.clone();
        invalid_same_grant.frozen_grants.truncate(1);
        invalid_same_grant.requested_work_units[1].grant_index = 0;
        let error = validate_execution_scope_for_request(
            &manifest,
            &assets,
            &grants,
            &policy,
            Some(&frozen_destinations),
            Some(&invalid_same_grant),
        )
        .expect_err("duplicate rectangles within one grant remain invalid");
        assert!(
            error
                .to_string()
                .contains("overlap within one frozen grant")
        );
    }

    #[test]
    fn cross_grant_partial_overlap_is_the_exact_union_without_scope_expansion() {
        let manifest = current_naabu_launcher_manifest();
        let mut second_asset = asset("two", true);
        second_asset.identifiers[0].value = "one.example".into();
        let assets = vec![asset("one", true), second_asset];
        let mut first = grant("one", ScanPermission::LowImpactExternalConnection, true);
        first.external_scope.as_mut().expect("first scope").ports = [80, 443].into_iter().collect();
        let mut second = grant("two", ScanPermission::LowImpactExternalConnection, true);
        let second_external = second.external_scope.as_mut().expect("second scope");
        second_external.target = CanonicalTarget::Hostname("one.example".into());
        second_external.ports = [443, 8443].into_iter().collect();
        let grants = vec![first, second];
        let address = "192.0.2.10".parse().expect("shared address");
        let plan = NaabuLauncherPlanDocument {
            schema_version: NAABU_LAUNCHER_PLAN_SCHEMA_VERSION,
            engine_id: NAABU_ENGINE_ID.into(),
            engine_run_id: "partial-overlap-engine-run".into(),
            execution_attempt: 1,
            frozen_grants: vec![
                NaabuLauncherFrozenGrant {
                    scope_grant_id: "grant-one".into(),
                    addresses: vec![address],
                    ports: vec![80, 443],
                },
                NaabuLauncherFrozenGrant {
                    scope_grant_id: "grant-two".into(),
                    addresses: vec![address],
                    ports: vec![443, 8443],
                },
            ],
            requested_work_units: vec![
                NaabuLauncherWorkUnit {
                    unit_id: "wu_33333333333333333333333333333333".into(),
                    scope_sha256: "3".repeat(64),
                    grant_index: 0,
                    address_start: 0,
                    address_len: 1,
                    port_start: 0,
                    port_len: 2,
                    endpoint_pair_count: 2,
                    conservative_deadline_seconds: 36,
                },
                NaabuLauncherWorkUnit {
                    unit_id: "wu_44444444444444444444444444444444".into(),
                    scope_sha256: "4".repeat(64),
                    grant_index: 1,
                    address_start: 0,
                    address_len: 1,
                    port_start: 0,
                    port_len: 2,
                    endpoint_pair_count: 2,
                    conservative_deadline_seconds: 36,
                },
            ],
        };
        let frozen_destinations = vec![
            GatewayDestination {
                hostname: Some("one.example".into()),
                addresses: [address].into_iter().collect(),
                ports: [80, 443].into_iter().collect(),
                allow_sensitive_networks: false,
            },
            GatewayDestination {
                hostname: Some("one.example".into()),
                addresses: [address].into_iter().collect(),
                ports: [443, 8443].into_iter().collect(),
                allow_sensitive_networks: false,
            },
        ];
        let exact_labels = gateway_destination_labels(&frozen_destinations);
        assert_eq!(
            exact_labels,
            [
                "one.example:80".to_string(),
                "one.example:443".to_string(),
                "one.example:8443".to_string(),
            ]
            .into_iter()
            .collect()
        );
        let policy = NetworkPolicy::managed(
            "ass-egress",
            "policy-cross-grant-partial-overlap",
            exact_labels.iter().cloned().collect(),
            "socks5h://172.29.0.1:1080",
        )
        .expect("managed policy");

        validate_execution_scope_for_request(
            &manifest,
            &assets,
            &grants,
            &policy,
            Some(&frozen_destinations),
            Some(&plan),
        )
        .expect("partial overlap across grants is one exact endpoint union");

        let wider = NetworkPolicy::managed(
            "ass-egress",
            "policy-cross-grant-partial-overlap-wider",
            vec![
                "one.example:22".to_string(),
                "one.example:80".to_string(),
                "one.example:443".to_string(),
                "one.example:8443".to_string(),
            ],
            "socks5h://172.29.0.1:1080",
        )
        .expect("syntactically valid wider policy");
        validate_execution_scope_for_request(
            &manifest,
            &assets,
            &grants,
            &wider,
            Some(&frozen_destinations),
            Some(&plan),
        )
        .expect_err("a port outside the exact cross-grant union must remain rejected");
    }

    #[test]
    fn legacy_gateway_binding_retains_its_historical_per_unit_bound() {
        let manifest = current_naabu_launcher_manifest();
        let assets = vec![asset("one", true)];
        let mut grants = vec![grant(
            "one",
            ScanPermission::LowImpactExternalConnection,
            true,
        )];
        grants[0]
            .external_scope
            .as_mut()
            .expect("external scope")
            .ports = (1..=100).collect();
        let addresses = (1_u8..=120)
            .map(|last| IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, last)))
            .collect::<Vec<_>>();
        let ports = (1..=100).collect::<Vec<_>>();
        let mut plan = NaabuLauncherPlanDocument {
            schema_version: LEGACY_NAABU_LAUNCHER_PLAN_SCHEMA_VERSION,
            engine_id: NAABU_ENGINE_ID.into(),
            engine_run_id: "legacy-large-engine-run".into(),
            execution_attempt: 1,
            frozen_grants: vec![NaabuLauncherFrozenGrant {
                scope_grant_id: "grant-one".into(),
                addresses: addresses.clone(),
                ports,
            }],
            requested_work_units: vec![
                NaabuLauncherWorkUnit {
                    unit_id: "wu_33333333333333333333333333333333".into(),
                    scope_sha256: "3".repeat(64),
                    grant_index: 0,
                    address_start: 0,
                    address_len: 120,
                    port_start: 0,
                    port_len: 50,
                    endpoint_pair_count: 6_000,
                    conservative_deadline_seconds: 300,
                },
                NaabuLauncherWorkUnit {
                    unit_id: "wu_44444444444444444444444444444444".into(),
                    scope_sha256: "4".repeat(64),
                    grant_index: 0,
                    address_start: 0,
                    address_len: 120,
                    port_start: 50,
                    port_len: 50,
                    endpoint_pair_count: 6_000,
                    conservative_deadline_seconds: 300,
                },
            ],
        };
        let address_set = addresses.into_iter().collect::<BTreeSet<_>>();
        let frozen_destinations = vec![
            GatewayDestination {
                hostname: Some("one.example".into()),
                addresses: address_set.clone(),
                ports: (1..=50).collect(),
                allow_sensitive_networks: false,
            },
            GatewayDestination {
                hostname: Some("one.example".into()),
                addresses: address_set,
                ports: (51..=100).collect(),
                allow_sensitive_networks: false,
            },
        ];
        let policy = NetworkPolicy::managed(
            "ass-egress",
            "policy-legacy-large",
            (1..=100)
                .map(|port| format!("one.example:{port}"))
                .collect(),
            "socks5h://172.29.0.1:1080",
        )
        .expect("managed policy");

        validate_execution_scope_for_request(
            &manifest,
            &assets,
            &grants,
            &policy,
            Some(&frozen_destinations),
            Some(&plan),
        )
        .expect("legacy schema keeps 10,000 endpoints per unit, not per attempt");

        plan.schema_version = NAABU_LAUNCHER_PLAN_SCHEMA_VERSION;
        let error = validate_execution_scope_for_request(
            &manifest,
            &assets,
            &grants,
            &policy,
            Some(&frozen_destinations),
            Some(&plan),
        )
        .expect_err("current schema retains its aggregate endpoint bound");
        assert!(error.to_string().contains("10000 exact endpoints"));
    }

    #[test]
    fn launcher_v3_projects_eleven_max_port_grants_below_the_scope_limit() {
        let manifest = current_naabu_launcher_manifest();
        let mut assets = Vec::new();
        let mut grants = Vec::new();
        for index in 0..11 {
            let id = format!("wide-{index:02}");
            assets.push(asset(&id, true));
            let mut value = grant(&id, ScanPermission::LowImpactExternalConnection, true);
            value.external_scope.as_mut().expect("external scope").ports = (1..=u16::MAX).collect();
            grants.push(value);
        }
        let validated = assets
            .iter()
            .zip(&grants)
            .map(|(asset, grant)| ValidatedAssetScope {
                asset,
                identifiers: vec![&asset.identifiers[0]],
                grants: vec![grant],
            })
            .collect::<Vec<_>>();
        let plan = NaabuLauncherPlanDocument {
            schema_version: NAABU_LAUNCHER_PLAN_SCHEMA_VERSION,
            engine_id: NAABU_ENGINE_ID.into(),
            engine_run_id: "run-eleven-wide-grants".into(),
            execution_attempt: 1,
            frozen_grants: grants
                .iter()
                .enumerate()
                .map(|(index, grant)| NaabuLauncherFrozenGrant {
                    scope_grant_id: grant.id.clone(),
                    addresses: vec![format!("192.0.2.{}", index + 1).parse().unwrap()],
                    ports: vec![443],
                })
                .collect(),
            requested_work_units: (0..11)
                .map(|index| NaabuLauncherWorkUnit {
                    unit_id: format!("wu_{:032x}", index + 1),
                    scope_sha256: format!("{:064x}", index + 1),
                    grant_index: index,
                    address_start: 0,
                    address_len: 1,
                    port_start: 0,
                    port_len: 1,
                    endpoint_pair_count: 1,
                    conservative_deadline_seconds: 36,
                })
                .collect(),
        };
        let document =
            ScopeDocument::new_for_request(&manifest, &validated, Some(&[]), Some(&plan))
                .expect("compact scope document");
        let scope_json = serde_json::to_vec(&document).expect("scope JSON");
        let plan_json = serde_json::to_vec(&plan).expect("plan JSON");

        assert!(scope_json.len() < 4 * 1024 * 1024);
        assert!(plan_json.len() < 4 * 1024 * 1024);
        let scope: serde_json::Value = serde_json::from_slice(&scope_json).unwrap();
        for asset in scope["assets"].as_array().unwrap() {
            assert_eq!(
                asset["grants"][0]["external_scope"]["ports"],
                serde_json::json!([443])
            );
        }

        let mut legacy_plan = plan.clone();
        legacy_plan.schema_version =
            crate::naabu_work_plan::LEGACY_NAABU_LAUNCHER_PLAN_SCHEMA_VERSION;
        let legacy_document =
            ScopeDocument::new_for_request(&manifest, &validated, Some(&[]), Some(&legacy_plan))
                .expect("legacy full scope document");
        let legacy_scope_json = serde_json::to_vec(&legacy_document).expect("legacy scope JSON");
        assert!(
            legacy_scope_json.len() > 4 * 1024 * 1024,
            "fixture must demonstrate why the v3 scope projection is required"
        );
    }

    fn asset(id: &str, active_external: bool) -> Asset {
        Asset {
            id: id.into(),
            kind: if active_external {
                AssetKind::Domain
            } else {
                AssetKind::Repository
            },
            name: id.into(),
            provider: None,
            region: None,
            identifiers: vec![AssetIdentifier {
                namespace: if active_external { "dns_name" } else { "path" }.into(),
                value: if active_external {
                    format!("{id}.example")
                } else {
                    id.into()
                },
            }],
            discovered_from: vec![],
            candidate: false,
            owner_confirmed: true,
            internet_exposed: Some(active_external),
            contains_sensitive_data: None,
            metadata: BTreeMap::new(),
        }
    }

    fn grant(asset_id: &str, permission: ScanPermission, external: bool) -> ScopeGrant {
        let now = Utc::now();
        let id = format!("grant-{asset_id}");
        let external_scope = external.then(|| {
            let activity = match permission {
                ScanPermission::LowImpactExternalConnection => ExternalActivity::LowImpactExternal,
                _ => ExternalActivity::ActiveExternal,
            };
            ExternalScopeGrant {
                id: id.clone(),
                case_id: "case-1".into(),
                asset_id: asset_id.into(),
                target: CanonicalTarget::Hostname(format!("{asset_id}.example")),
                ports: [443].into_iter().collect(),
                protocol: TransportProtocol::Https,
                activity,
                rate_policy: RatePolicy {
                    requests_per_second: 2,
                    concurrency: 1,
                    timeout_seconds: 30,
                },
                template_policy: TemplatePolicy::conservative(
                    if activity == ExternalActivity::ActiveExternal {
                        "nuclei-templates@0123456789abcdef0123456789abcdef01234567"
                    } else {
                        "not_applicable"
                    },
                    if activity == ExternalActivity::ActiveExternal {
                        vec!["http/misconfiguration/example".into()]
                    } else {
                        vec![]
                    },
                ),
                asserted_authority: format!("AUTH-{asset_id}"),
                approved_by: "operator".into(),
                approved_at: now - Duration::minutes(1),
                expires_at: now + Duration::hours(1),
                allow_sensitive_networks: false,
            }
        });
        ScopeGrant {
            id,
            asset_id: asset_id.into(),
            permission,
            confirmed_by: "operator".into(),
            confirmed_at: now,
            expires_at: Some(now + Duration::hours(1)),
            authorization_reference: external.then(|| format!("AUTH-{asset_id}")),
            notes: None,
            external_scope,
        }
    }

    #[test]
    fn zap_execution_writes_and_mounts_only_its_exact_frozen_profile() {
        let temp = tempfile::tempdir().unwrap();
        let store = ArtifactStore::open(temp.path().join("artifacts")).unwrap();
        let runtime = LauncherPlanCaptureRuntime::default();
        let adapters = AdapterRegistry::default();
        let orchestrator = Orchestrator::new(&runtime, &store, &adapters);
        let manifest =
            serde_json::from_str::<Vec<EngineManifest>>(include_str!("../../engines/catalog.json"))
                .unwrap()
                .into_iter()
                .find(|manifest| manifest.id == ZAP_ENGINE_ID)
                .unwrap();
        let assets = vec![asset("one", true)];
        let mut grants = vec![grant("one", ScanPermission::ActiveExternalTesting, true)];
        let external = grants[0].external_scope.as_mut().unwrap();
        external.rate_policy = RatePolicy {
            requests_per_second: 5,
            concurrency: 5,
            timeout_seconds: 10,
        };
        external.template_policy = TemplatePolicy::conservative_profile(
            crate::zap_work_plan::ZAP_PASSIVE_TEMPLATE_REVISION,
            crate::zap_work_plan::ZAP_PASSIVE_PROFILE_ID,
        );
        let policy = NetworkPolicy::managed(
            "ass-zap",
            "policy-zap",
            vec!["one.example:443".into()],
            "socks5h://172.29.0.1:1080",
        )
        .unwrap();
        let limits = ResourceLimits::default();
        let credentials = ScannerCredentialSet::default();
        let request = EngineExecutionRequest {
            case_id: "case-1",
            scan_run_id: "run-1",
            engine_run_id: "zap-run-1",
            manifest: &manifest,
            ai_system_applicable: false,
            ai_generated_artifact_applicable: false,
            assets: &assets,
            scope_grants: &grants,
            frozen_destinations: None,
            naabu_launcher_plan: None,
            expected_naabu_launcher_plan_sha256: None,
            workspace: None,
            network_policy: &policy,
            resource_limits: &limits,
            credentials: &credentials,
            attempt: 1,
        };
        let report = orchestrator
            .execute(&request, &CancellationToken::default())
            .unwrap();
        let observed = runtime.observed().unwrap();
        let document: serde_json::Value = serde_json::from_slice(&observed.bytes).unwrap();
        assert_eq!(
            document["env"]["contexts"][0]["urls"][0],
            "https://one.example/"
        );
        assert_eq!(
            document["env"]["configs"]["network.ratelimit.rules.rule(0).reqsPerSec"],
            "5"
        );
        assert_eq!(
            document["env"]["configs"]["network.connection.timeoutInSecs"],
            "10"
        );
        assert_eq!(document["jobs"][3]["parameters"]["reportFile"], "zap");
        assert_eq!(observed.path.file_name().unwrap(), ZAP_PLAN_CONTROL_FILE);
        assert!(observed.runtime_args.iter().any(|arg| arg == "/zap/zap.sh"));
        let digest = hex::encode(Sha256::digest(&observed.bytes));
        assert_eq!(
            report.checkpoint.zap_plan_sha256.as_deref(),
            Some(digest.as_str())
        );
        let mut invalid_grants = grants.clone();
        invalid_grants[0]
            .external_scope
            .as_mut()
            .unwrap()
            .rate_policy
            .requests_per_second = 10;
        let invalid_request = EngineExecutionRequest {
            scope_grants: &invalid_grants,
            ..request
        };
        assert!(matches!(
            orchestrator.execute(&invalid_request, &CancellationToken::default()),
            Err(AppError::NotAuthorized(_))
        ));
        let mut cross_engine = report.checkpoint.clone();
        cross_engine.engine_id = "nuclei".into();
        assert!(cross_engine.resume_token().is_err());
    }

    fn execute_failed_local_check(stderr: Vec<u8>) -> ExecutionReport {
        let temp = tempfile::tempdir().expect("temp directory");
        let workspace = temp.path().join("workspace");
        std::fs::create_dir(&workspace).expect("workspace");
        let store = ArtifactStore::open(temp.path().join("artifacts")).expect("store");
        let runtime = FakeContainerRuntime::default();
        runtime.set_behavior(FakeRunBehavior {
            exit_code: Some(126),
            stderr,
            ..FakeRunBehavior::default()
        });
        let adapters = AdapterRegistry::default();
        let orchestrator = Orchestrator::new(&runtime, &store, &adapters);
        let manifest = manifest(false);
        let assets = vec![asset("asset-1", false)];
        let grants = vec![grant("asset-1", ScanPermission::LocalArtifactRead, false)];
        let policy = NetworkPolicy::Disabled;
        let limits = ResourceLimits::default();
        let credentials = ScannerCredentialSet::default();
        let request = EngineExecutionRequest {
            case_id: "case-1",
            scan_run_id: "run-1",
            engine_run_id: "engine-run-1",
            manifest: &manifest,
            ai_system_applicable: false,
            ai_generated_artifact_applicable: false,
            assets: &assets,
            scope_grants: &grants,
            frozen_destinations: None,
            naabu_launcher_plan: None,
            expected_naabu_launcher_plan_sha256: None,
            workspace: Some(&workspace),
            network_policy: &policy,
            resource_limits: &limits,
            credentials: &credentials,
            attempt: 1,
        };

        orchestrator
            .execute(&request, &CancellationToken::default())
            .expect("failed execution report")
    }

    #[test]
    fn a_check_that_cannot_read_its_input_records_an_honest_failure() {
        let report = execute_failed_local_check(
            b"local-launcher: engine grype cannot consume local input profile repository_working_tree\n"
                .to_vec(),
        );

        assert_eq!(report.checkpoint.stage, ExecutionStage::Failed);
        assert_eq!(report.exit_code, Some(126));
        assert_eq!(
            report.checkpoint.failure_code.as_deref(),
            Some("local_input_profile_unsupported")
        );
        let error = report.checkpoint.last_error.as_deref().expect("failure");
        assert!(error.contains("could not read"));
        assert!(!error.contains("exited with status"));
    }

    #[test]
    fn an_ordinary_nonzero_exit_remains_a_generic_execution_failure() {
        let report = execute_failed_local_check(b"scanner failed for another reason\n".to_vec());

        assert_eq!(report.checkpoint.stage, ExecutionStage::Failed);
        assert_eq!(report.checkpoint.failure_code, None);
        assert_eq!(
            report.checkpoint.last_error.as_deref(),
            Some("scanner container exited with status Some(126)")
        );
    }

    #[test]
    fn unreadable_stderr_does_not_guess_that_the_input_was_unsupported() {
        let unavailable = std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "stderr capture unavailable",
        );

        assert!(!stderr_tail_contains_local_input_profile_rejection(Err(
            unavailable
        )));
    }

    #[test]
    fn active_external_scope_is_checked_for_every_asset() {
        let manifest = manifest(true);
        let assets = vec![asset("one", true), asset("two", true)];
        let grants = vec![grant("one", ScanPermission::ActiveExternalTesting, true)];
        let policy = NetworkPolicy::managed(
            "ass-egress",
            "policy-1",
            vec!["one.example:443".into(), "two.example:443".into()],
            "socks5h://172.29.0.1:1080",
        )
        .expect("policy");

        let error = validate_execution_scope(&manifest, &assets, &grants, &policy)
            .expect_err("second asset must be rejected");
        assert!(error.to_string().contains("asset two lacks"));
    }

    #[test]
    fn active_scope_document_only_contains_policy_allowed_identifiers() {
        let manifest = manifest(true);
        let mut selected = asset("one", true);
        selected.identifiers.push(AssetIdentifier {
            namespace: "dns_name".into(),
            value: "not-authorized.example".into(),
        });
        let assets = vec![selected];
        let grants = vec![grant("one", ScanPermission::ActiveExternalTesting, true)];
        let policy = NetworkPolicy::managed(
            "ass-egress",
            "policy-1",
            vec!["one.example:443".into()],
            "socks5h://172.29.0.1:1080",
        )
        .expect("policy");

        let scope = validate_execution_scope(&manifest, &assets, &grants, &policy)
            .expect("authorized scope");
        let document = ScopeDocument::new(&manifest, &scope, None).expect("scope document");
        let json = serde_json::to_value(document).expect("scope json");

        assert_eq!(
            json["assets"][0]["identifiers"].as_array().unwrap().len(),
            1
        );
        assert_eq!(json["assets"][0]["identifiers"][0]["value"], "one.example");
        assert!(!json.to_string().contains("not-authorized.example"));
        assert_eq!(json["schema_version"], "1");
        assert!(
            json["assets"][0]["grants"][0]
                .get("resolved_addresses")
                .is_none()
        );
    }

    #[test]
    fn website_origin_identity_never_reaches_direct_external_launcher_identifiers() {
        let mut selected = asset("one", true);
        selected.kind = AssetKind::WebService;
        selected.name = "https://one.example:443".into();
        selected.identifiers.insert(
            0,
            AssetIdentifier {
                namespace: "web_origin".into(),
                value: "https://one.example:443".into(),
            },
        );
        let assets = vec![selected];
        let grants = vec![grant("one", ScanPermission::ActiveExternalTesting, true)];
        let policy = NetworkPolicy::managed(
            "ass-egress",
            "policy-web-origin",
            vec!["one.example:443".into()],
            "socks5h://172.29.0.1:1080",
        )
        .expect("policy");
        let destinations = vec![GatewayDestination {
            hostname: Some("one.example".into()),
            addresses: ["192.0.2.10".parse().unwrap()].into_iter().collect(),
            ports: [443].into_iter().collect(),
            allow_sensitive_networks: false,
        }];

        for engine_id in ["nuclei", "greenbone"] {
            let mut manifest = manifest(true);
            manifest.id = engine_id.into();
            manifest.supported_asset_kinds = vec![AssetKind::WebService];
            let scope = validate_execution_scope(&manifest, &assets, &grants, &policy)
                .expect("authorized website scope");
            let frozen_destinations = (engine_id == "nuclei").then_some(destinations.as_slice());
            let document = ScopeDocument::new(&manifest, &scope, frozen_destinations)
                .expect("direct external scope document");
            let json = serde_json::to_value(document).expect("scope json");
            let identifiers = json["assets"][0]["identifiers"].as_array().unwrap();

            assert_eq!(identifiers.len(), 1, "{engine_id}");
            assert_eq!(identifiers[0]["namespace"], "dns_name", "{engine_id}");
            assert_eq!(identifiers[0]["value"], "one.example", "{engine_id}");
            assert!(
                !identifiers
                    .iter()
                    .any(|identifier| identifier.to_string().contains("https://one.example:443"))
            );
        }
    }

    #[test]
    fn replaying_the_same_attempt_reuses_identical_scope_and_reaches_the_observer() {
        let temp = tempfile::tempdir().expect("temporary run root");
        let workspace = temp.path().join("workspace");
        std::fs::create_dir(&workspace).expect("workspace");
        let store = ArtifactStore::open(temp.path().join("artifacts")).expect("artifact store");
        let runtime = FakeContainerRuntime::default();
        let adapters = AdapterRegistry::default();
        let orchestrator = Orchestrator::new(&runtime, &store, &adapters);
        let manifest = manifest(false);
        let assets = vec![asset("asset-1", false)];
        let grants = vec![grant("asset-1", ScanPermission::LocalArtifactRead, false)];
        let policy = NetworkPolicy::Disabled;
        let limits = ResourceLimits::default();
        let credentials = ScannerCredentialSet::default();
        let request = EngineExecutionRequest {
            case_id: "case-1",
            scan_run_id: "run-1",
            engine_run_id: "engine-run-1",
            manifest: &manifest,
            ai_system_applicable: false,
            ai_generated_artifact_applicable: false,
            assets: &assets,
            scope_grants: &grants,
            frozen_destinations: None,
            naabu_launcher_plan: None,
            expected_naabu_launcher_plan_sha256: None,
            workspace: Some(&workspace),
            network_policy: &policy,
            resource_limits: &limits,
            credentials: &credentials,
            attempt: 1,
        };
        let cancellation = CancellationToken::default();
        cancellation.cancel();

        let mut first_observer_calls = 0;
        let first = orchestrator
            .execute_with_observer(&request, &cancellation, |_| {
                first_observer_calls += 1;
                Ok(())
            })
            .expect("first attempt checkpoint");
        assert_eq!(first_observer_calls, 1);
        assert_eq!(first.checkpoint.stage, ExecutionStage::Cancelled);

        std::thread::sleep(std::time::Duration::from_millis(5));
        let mut replay_observer_calls = 0;
        let replay = orchestrator
            .execute_with_observer(&request, &cancellation, |_| {
                replay_observer_calls += 1;
                Ok(())
            })
            .expect("same durable attempt reuses its exact control file");

        assert_eq!(replay_observer_calls, 1);
        assert_eq!(replay.checkpoint.stage, ExecutionStage::Cancelled);
        assert_eq!(
            replay.checkpoint.scope_sha256,
            first.checkpoint.scope_sha256
        );
        assert_eq!(
            runtime.calls(),
            Vec::<RuntimeCall>::new(),
            "a cancelled exact replay must reach the observer without contacting a runtime"
        );
    }

    #[test]
    fn scope_document_preserves_only_the_exact_structured_external_grant() {
        let manifest = manifest(true);
        let assets = vec![asset("one", true)];
        let now = Utc::now();
        let mut selected_grant = grant("one", ScanPermission::ActiveExternalTesting, true);
        selected_grant.external_scope = Some(ExternalScopeGrant {
            id: selected_grant.id.clone(),
            case_id: "case-1".into(),
            asset_id: "one".into(),
            target: CanonicalTarget::Hostname("one.example".into()),
            ports: [443].into_iter().collect(),
            protocol: TransportProtocol::Https,
            activity: ExternalActivity::ActiveExternal,
            rate_policy: RatePolicy {
                requests_per_second: 2,
                concurrency: 1,
                timeout_seconds: 30,
            },
            template_policy: TemplatePolicy::conservative(
                "nuclei-templates@0123456789abcdef0123456789abcdef01234567",
                vec!["http/misconfiguration/example".into()],
            ),
            asserted_authority: "AUTH-one".into(),
            approved_by: "operator".into(),
            approved_at: now - Duration::minutes(1),
            expires_at: now + Duration::hours(1),
            allow_sensitive_networks: false,
        });
        let grants = vec![selected_grant];
        let policy = NetworkPolicy::managed(
            "ass-egress",
            "policy-1",
            vec!["one.example:443".into()],
            "socks5h://172.29.0.1:1080",
        )
        .expect("policy");
        let scope = validate_execution_scope(&manifest, &assets, &grants, &policy)
            .expect("authorized scope");
        let json = serde_json::to_value(
            ScopeDocument::new(&manifest, &scope, None).expect("scope document"),
        )
        .expect("scope json");
        let external = &json["assets"][0]["grants"][0]["external_scope"];

        assert_eq!(external["target"]["kind"], "hostname");
        assert_eq!(external["target"]["value"], "one.example");
        assert_eq!(external["ports"], serde_json::json!([443]));
        assert_eq!(external["protocol"], "https");
        assert_eq!(external["rate_policy"]["requests_per_second"], 2);
        assert_eq!(
            external["template_policy"]["allowed_template_ids"],
            serde_json::json!(["http/misconfiguration/example"])
        );
        assert!(!json.to_string().contains("not-authorized.example"));
    }

    #[test]
    fn external_launcher_scope_receives_only_the_gateway_frozen_addresses() {
        let mut manifest = manifest(true);
        manifest.id = "httpx".into();
        let assets = vec![asset("one", true)];
        let grants = vec![grant("one", ScanPermission::ActiveExternalTesting, true)];
        let policy = NetworkPolicy::managed(
            "ass-egress",
            "policy-1",
            vec!["one.example:443".into()],
            "socks5h://172.29.0.1:1080",
        )
        .expect("policy");
        let scope = validate_execution_scope(&manifest, &assets, &grants, &policy)
            .expect("authorized scope");
        let destinations = vec![GatewayDestination {
            hostname: Some("one.example".into()),
            addresses: [
                "192.0.2.10".parse().unwrap(),
                "2001:db8::10".parse().unwrap(),
            ]
            .into_iter()
            .collect(),
            ports: [443].into_iter().collect(),
            allow_sensitive_networks: false,
        }];
        let document = ScopeDocument::new(&manifest, &scope, Some(&destinations))
            .expect("frozen launcher scope");
        let json = serde_json::to_value(document).expect("scope json");

        assert_eq!(
            json["assets"][0]["grants"][0]["resolved_addresses"],
            serde_json::json!(["192.0.2.10", "2001:db8::10"])
        );
        assert_eq!(json["schema_version"], "2");
        assert!(ScopeDocument::new(&manifest, &scope, None).is_err());

        let unrelated = vec![GatewayDestination {
            hostname: Some("other.example".into()),
            addresses: ["198.51.100.10".parse().unwrap()].into_iter().collect(),
            ports: [443].into_iter().collect(),
            allow_sensitive_networks: false,
        }];
        assert!(ScopeDocument::new(&manifest, &scope, Some(&unrelated)).is_err());
    }

    #[test]
    fn low_impact_external_manifest_uses_the_same_frozen_gateway_contract() {
        let mut manifest = manifest(true);
        manifest.required_permissions = vec![ScanPermission::LowImpactExternalConnection];
        let assets = vec![asset("one", true)];
        let grants = vec![grant(
            "one",
            ScanPermission::LowImpactExternalConnection,
            true,
        )];
        let policy = NetworkPolicy::managed(
            "ass-egress",
            "policy-1",
            vec!["one.example:443".into()],
            "socks5h://172.29.0.1:1080",
        )
        .expect("policy");

        let scope = validate_execution_scope(&manifest, &assets, &grants, &policy)
            .expect("low-impact target scope");
        assert_eq!(scope.len(), 1);
    }

    #[test]
    fn current_naabu_launcher_sidecar_reaches_the_exact_read_only_run_plan_mount() {
        let temp = tempfile::tempdir().expect("temp directory");
        let store = ArtifactStore::open(temp.path().join("artifacts")).expect("store");
        let runtime = LauncherPlanCaptureRuntime::default();
        let adapters = AdapterRegistry::default();
        let orchestrator = Orchestrator::new(&runtime, &store, &adapters);
        let manifest = current_naabu_launcher_manifest();
        let assets = vec![asset("one", true), asset("two", true)];
        let mut grants = vec![
            grant("one", ScanPermission::LowImpactExternalConnection, true),
            grant("two", ScanPermission::LowImpactExternalConnection, true),
        ];
        grants[0].external_scope.as_mut().unwrap().ports = [80, 443].into_iter().collect();
        let frozen_destinations = vec![GatewayDestination {
            hostname: Some("one.example".into()),
            addresses: ["192.0.2.11".parse().expect("test address")]
                .into_iter()
                .collect(),
            ports: [443].into_iter().collect(),
            allow_sensitive_networks: false,
        }];
        let policy = NetworkPolicy::managed(
            "ass-egress",
            "policy-1",
            vec!["one.example:443".into()],
            "socks5h://172.29.0.1:1080",
        )
        .expect("managed policy");
        let limits = ResourceLimits::default();
        let credentials = ScannerCredentialSet::default();
        let mut launcher_plan = naabu_launcher_plan("engine-run-1", 1);
        launcher_plan.frozen_grants[0].addresses =
            vec!["192.0.2.11".parse().expect("test address")];
        launcher_plan.frozen_grants[0].ports = vec![443];
        let expected_launcher_digest = naabu_launcher_plan_sha256(&launcher_plan);
        let wider_destinations = vec![GatewayDestination {
            hostname: Some("one.example".into()),
            addresses: [
                "192.0.2.10".parse().expect("test address"),
                "192.0.2.11".parse().expect("test address"),
            ]
            .into_iter()
            .collect(),
            ports: [80, 443].into_iter().collect(),
            allow_sensitive_networks: false,
        }];
        assert!(
            validate_execution_scope_for_request(
                &manifest,
                &assets,
                &grants,
                &policy,
                Some(&wider_destinations),
                Some(&launcher_plan),
            )
            .is_err(),
            "a gateway wider than the selected launcher rectangle must be rejected"
        );
        let wider_policy = NetworkPolicy::managed(
            "ass-egress",
            "policy-wide",
            vec!["one.example:80".into(), "one.example:443".into()],
            "socks5h://172.29.0.1:1080",
        )
        .expect("wider policy fixture");
        assert!(
            validate_execution_scope_for_request(
                &manifest,
                &assets,
                &grants,
                &wider_policy,
                Some(&frozen_destinations),
                Some(&launcher_plan),
            )
            .is_err(),
            "container network labels wider than the selected launcher rectangle must be rejected"
        );
        let request = EngineExecutionRequest {
            case_id: "case-1",
            scan_run_id: "run-1",
            engine_run_id: "engine-run-1",
            manifest: &manifest,
            ai_system_applicable: false,
            ai_generated_artifact_applicable: false,
            assets: &assets,
            scope_grants: &grants,
            frozen_destinations: Some(&frozen_destinations),
            naabu_launcher_plan: Some(&launcher_plan),
            expected_naabu_launcher_plan_sha256: Some(&expected_launcher_digest),
            workspace: None,
            network_policy: &policy,
            resource_limits: &limits,
            credentials: &credentials,
            attempt: 1,
        };

        let mut observed_checkpoint_digests = Vec::new();
        let report = orchestrator
            .execute_with_observer(&request, &CancellationToken::default(), |checkpoint| {
                observed_checkpoint_digests
                    .push(checkpoint.checkpoint.launcher_plan_sha256.clone());
                Ok(())
            })
            .expect("captured launcher plan report");
        assert_eq!(
            report.checkpoint.stage,
            ExecutionStage::CapturedAwaitingAdapter
        );
        assert_eq!(
            report.checkpoint.container_name.as_deref(),
            Some(
                planned_container_name(NAABU_ENGINE_ID, "engine-run-1", 1)
                    .unwrap()
                    .as_str()
            )
        );
        assert_eq!(
            report.checkpoint.launcher_plan_sha256.as_deref(),
            Some(expected_launcher_digest.as_str())
        );
        assert!(report.checkpoint.resume_token().is_ok());
        assert!(!observed_checkpoint_digests.is_empty());
        assert!(
            observed_checkpoint_digests
                .iter()
                .all(|digest| { digest.as_deref() == Some(expected_launcher_digest.as_str()) })
        );
        assert!(report.checkpoint.last_error.is_none());
        assert!(
            report
                .warnings
                .iter()
                .any(|warning| warning == "Scan batch stopped. Unfinished work: not tested.")
        );

        let observed = runtime
            .observed()
            .expect("run plan reached runtime boundary");
        let expected_path = std::fs::canonicalize(
            temp.path()
                .join("artifacts/case-1/run-1/engine-run-1/attempt-1/control")
                .join(NAABU_LAUNCHER_PLAN_CONTROL_FILE),
        )
        .expect("canonical launcher plan");
        assert_eq!(observed.path, expected_path);
        assert!(
            std::fs::metadata(&observed.path)
                .expect("launcher plan metadata")
                .permissions()
                .readonly()
        );
        assert_eq!(
            serde_json::from_slice::<NaabuLauncherPlanDocument>(&observed.bytes)
                .expect("typed launcher plan"),
            launcher_plan
        );
        let expected_mount = format!(
            "type=bind,src={},dst=/run/ai-security-scanner/execution-journal-v2.json,readonly",
            observed.path.display()
        );
        assert_eq!(
            observed
                .runtime_args
                .windows(2)
                .filter_map(|arguments| {
                    (arguments[0] == "--mount"
                        && arguments[1]
                            .contains("/run/ai-security-scanner/execution-journal-v2.json"))
                    .then_some(arguments[1].as_str())
                })
                .collect::<Vec<_>>(),
            [expected_mount.as_str()]
        );
        let scope_path = temp
            .path()
            .join("artifacts/case-1/run-1/engine-run-1/attempt-1/control/scope.json");
        let scope_json: serde_json::Value =
            serde_json::from_slice(&std::fs::read(scope_path).expect("launcher scope document"))
                .expect("launcher scope JSON");
        assert_eq!(
            scope_json["assets"][0]["grants"][0]["resolved_addresses"],
            serde_json::json!(["192.0.2.11"])
        );
        assert_eq!(
            scope_json["assets"][0]["grants"][0]["external_scope"]["ports"],
            serde_json::json!([443]),
            "scope schema 2 must carry the same compact port set as launcher plan schema 3"
        );
        assert_eq!(
            scope_json["assets"].as_array().map(Vec::len),
            Some(1),
            "unselected grants and assets must stay out of the compact attempt scope"
        );
    }

    #[test]
    fn successful_naabu_launcher_v2_capture_waits_for_host_verified_normalization() {
        let temp = tempfile::tempdir().expect("temp directory");
        let store = ArtifactStore::open(temp.path().join("artifacts")).expect("store");
        let runtime = FakeContainerRuntime::default();
        runtime.set_behavior(FakeRunBehavior {
            exit_code: Some(0),
            stdout: b"launcher stdout".to_vec(),
            stderr: Vec::new(),
            output_files: BTreeMap::from([
                (
                    "launcher-v2/journal.jsonl".into(),
                    b"unparsed host-verification fixture\n".to_vec(),
                ),
                (
                    "launcher-v2/quarantine/unit-000000/attempt-1.raw.jsonl".into(),
                    b"untrusted quarantine fixture".to_vec(),
                ),
                (
                    "launcher-v2/units/unit-000000/attempt-1.jsonl".into(),
                    b"candidate final fixture".to_vec(),
                ),
            ]),
        });
        let mut adapters = AdapterRegistry::default();
        adapters
            .register(Arc::new(NaabuLauncherMustNotRunGenericAdapter))
            .expect("register launcher tripwire adapter");
        let orchestrator = Orchestrator::new(&runtime, &store, &adapters);
        let manifest = current_naabu_launcher_manifest();
        let assets = vec![asset("one", true)];
        let grants = vec![grant(
            "one",
            ScanPermission::LowImpactExternalConnection,
            true,
        )];
        let frozen_destinations = vec![GatewayDestination {
            hostname: Some("one.example".into()),
            addresses: ["192.0.2.10".parse().expect("test address")]
                .into_iter()
                .collect(),
            ports: [443].into_iter().collect(),
            allow_sensitive_networks: false,
        }];
        let policy = NetworkPolicy::managed(
            "ass-egress",
            "policy-1",
            vec!["one.example:443".into()],
            "socks5h://172.29.0.1:1080",
        )
        .expect("managed policy");
        let limits = ResourceLimits::default();
        let credentials = ScannerCredentialSet::default();
        let launcher_plan = naabu_launcher_plan("engine-run-1", 1);
        let expected_launcher_digest = naabu_launcher_plan_sha256(&launcher_plan);
        let request = EngineExecutionRequest {
            case_id: "case-1",
            scan_run_id: "run-1",
            engine_run_id: "engine-run-1",
            manifest: &manifest,
            ai_system_applicable: false,
            ai_generated_artifact_applicable: false,
            assets: &assets,
            scope_grants: &grants,
            frozen_destinations: Some(&frozen_destinations),
            naabu_launcher_plan: Some(&launcher_plan),
            expected_naabu_launcher_plan_sha256: Some(&expected_launcher_digest),
            workspace: None,
            network_policy: &policy,
            resource_limits: &limits,
            credentials: &credentials,
            attempt: 1,
        };

        let mut captured_handoffs = Vec::new();
        let report = orchestrator
            .execute_with_observer(&request, &CancellationToken::default(), |checkpoint| {
                if checkpoint.checkpoint.stage == ExecutionStage::CapturedAwaitingAdapter {
                    captured_handoffs.push((
                        checkpoint.checkpoint.artifact_ids.clone(),
                        checkpoint.raw_artifacts.len(),
                    ));
                }
                Ok(())
            })
            .expect("launcher capture report");

        assert_eq!(
            report.checkpoint.stage,
            ExecutionStage::CapturedAwaitingAdapter
        );
        assert_eq!(report.exit_code, Some(0));
        assert!(report.findings.is_empty());
        assert!(report.checkpoint.last_error.is_none());
        assert_eq!(report.raw_artifacts.len(), 5);
        assert!(report.raw_artifacts.iter().any(|artifact| {
            artifact
                .relative_path
                .ends_with("/output/launcher-v2/journal.jsonl")
        }));
        assert_eq!(captured_handoffs.len(), 1);
        assert_eq!(captured_handoffs[0].0, report.checkpoint.artifact_ids);
        assert_eq!(captured_handoffs[0].1, report.raw_artifacts.len());
    }

    #[test]
    fn nonzero_naabu_launcher_capture_still_reaches_the_verified_journal_handoff() {
        let temp = tempfile::tempdir().expect("temp directory");
        let store = ArtifactStore::open(temp.path().join("artifacts")).expect("store");
        let runtime = FakeContainerRuntime::default();
        runtime.set_behavior(FakeRunBehavior {
            exit_code: Some(126),
            output_files: BTreeMap::from([
                (
                    "launcher-v2/journal.jsonl".into(),
                    b"durable complete prefix\n{\"truncated\"".to_vec(),
                ),
                (
                    "launcher-v2/units/unit-000000/attempt-1.jsonl".into(),
                    b"candidate final fixture".to_vec(),
                ),
            ]),
            ..FakeRunBehavior::default()
        });
        let adapters = AdapterRegistry::default();
        let orchestrator = Orchestrator::new(&runtime, &store, &adapters);
        let manifest = current_naabu_launcher_manifest();
        let assets = vec![asset("one", true)];
        let grants = vec![grant(
            "one",
            ScanPermission::LowImpactExternalConnection,
            true,
        )];
        let frozen_destinations = vec![GatewayDestination {
            hostname: Some("one.example".into()),
            addresses: ["192.0.2.10".parse().expect("test address")]
                .into_iter()
                .collect(),
            ports: [443].into_iter().collect(),
            allow_sensitive_networks: false,
        }];
        let policy = NetworkPolicy::managed(
            "ass-egress",
            "policy-1",
            vec!["one.example:443".into()],
            "socks5h://172.29.0.1:1080",
        )
        .expect("managed policy");
        let limits = ResourceLimits::default();
        let credentials = ScannerCredentialSet::default();
        let launcher_plan = naabu_launcher_plan("engine-run-1", 1);
        let expected_launcher_digest = naabu_launcher_plan_sha256(&launcher_plan);
        let request = EngineExecutionRequest {
            case_id: "case-1",
            scan_run_id: "run-1",
            engine_run_id: "engine-run-1",
            manifest: &manifest,
            ai_system_applicable: false,
            ai_generated_artifact_applicable: false,
            assets: &assets,
            scope_grants: &grants,
            frozen_destinations: Some(&frozen_destinations),
            naabu_launcher_plan: Some(&launcher_plan),
            expected_naabu_launcher_plan_sha256: Some(&expected_launcher_digest),
            workspace: None,
            network_policy: &policy,
            resource_limits: &limits,
            credentials: &credentials,
            attempt: 1,
        };

        let report = orchestrator
            .execute(&request, &CancellationToken::default())
            .expect("captured launcher report");

        assert_eq!(
            report.checkpoint.stage,
            ExecutionStage::CapturedAwaitingAdapter
        );
        assert_eq!(report.exit_code, Some(126));
        assert!(report.checkpoint.cleanup_completed);
        assert!(report.checkpoint.last_error.is_none());
        assert!(report.findings.is_empty());
        assert!(
            report
                .warnings
                .iter()
                .any(|warning| warning == "Scan batch stopped. Unfinished work: not tested.")
        );
        assert!(report.raw_artifacts.iter().any(|artifact| {
            artifact
                .relative_path
                .ends_with("/output/launcher-v2/journal.jsonl")
        }));
        assert!(
            runtime
                .calls()
                .iter()
                .any(|call| matches!(call, RuntimeCall::Cleanup(_)))
        );
    }

    #[test]
    fn mismatched_naabu_launcher_identity_is_rejected_before_runtime_or_sidecar_write() {
        let temp = tempfile::tempdir().expect("temp directory");
        let store = ArtifactStore::open(temp.path().join("artifacts")).expect("store");
        let runtime = FakeContainerRuntime::default();
        let adapters = AdapterRegistry::default();
        let orchestrator = Orchestrator::new(&runtime, &store, &adapters);
        let manifest = current_naabu_launcher_manifest();
        let assets = vec![asset("one", true)];
        let grants = vec![grant(
            "one",
            ScanPermission::LowImpactExternalConnection,
            true,
        )];
        let frozen_destinations = vec![GatewayDestination {
            hostname: Some("one.example".into()),
            addresses: ["192.0.2.10".parse().expect("test address")]
                .into_iter()
                .collect(),
            ports: [443].into_iter().collect(),
            allow_sensitive_networks: false,
        }];
        let policy = NetworkPolicy::managed(
            "ass-egress",
            "policy-1",
            vec!["one.example:443".into()],
            "socks5h://172.29.0.1:1080",
        )
        .expect("managed policy");
        let limits = ResourceLimits::default();
        let credentials = ScannerCredentialSet::default();
        let launcher_plan = naabu_launcher_plan("another-engine-run", 1);
        let expected_launcher_digest = naabu_launcher_plan_sha256(&launcher_plan);
        let request = EngineExecutionRequest {
            case_id: "case-1",
            scan_run_id: "run-1",
            engine_run_id: "engine-run-1",
            manifest: &manifest,
            ai_system_applicable: false,
            ai_generated_artifact_applicable: false,
            assets: &assets,
            scope_grants: &grants,
            frozen_destinations: Some(&frozen_destinations),
            naabu_launcher_plan: Some(&launcher_plan),
            expected_naabu_launcher_plan_sha256: Some(&expected_launcher_digest),
            workspace: None,
            network_policy: &policy,
            resource_limits: &limits,
            credentials: &credentials,
            attempt: 1,
        };

        let error = orchestrator
            .execute(&request, &CancellationToken::default())
            .expect_err("mismatched launcher identity must fail closed");
        assert!(error.to_string().contains("identity does not match"));
        assert!(runtime.calls().is_empty());
        assert!(
            !temp
                .path()
                .join("artifacts/case-1/run-1/engine-run-1/attempt-1/control")
                .join(NAABU_LAUNCHER_PLAN_CONTROL_FILE)
                .exists()
        );
    }

    #[test]
    fn mismatched_naabu_launcher_digest_is_rejected_before_runtime_creation() {
        let temp = tempfile::tempdir().expect("temp directory");
        let store = ArtifactStore::open(temp.path().join("artifacts")).expect("store");
        let runtime = FakeContainerRuntime::default();
        let adapters = AdapterRegistry::default();
        let orchestrator = Orchestrator::new(&runtime, &store, &adapters);
        let manifest = current_naabu_launcher_manifest();
        let assets = vec![asset("one", true)];
        let grants = vec![grant(
            "one",
            ScanPermission::LowImpactExternalConnection,
            true,
        )];
        let frozen_destinations = vec![GatewayDestination {
            hostname: Some("one.example".into()),
            addresses: ["192.0.2.10".parse().expect("test address")]
                .into_iter()
                .collect(),
            ports: [443].into_iter().collect(),
            allow_sensitive_networks: false,
        }];
        let policy = NetworkPolicy::managed(
            "ass-egress",
            "policy-1",
            vec!["one.example:443".into()],
            "socks5h://172.29.0.1:1080",
        )
        .expect("managed policy");
        let limits = ResourceLimits::default();
        let credentials = ScannerCredentialSet::default();
        let launcher_plan = naabu_launcher_plan("engine-run-1", 1);
        let wrong_digest = "f".repeat(64);
        assert_ne!(wrong_digest, naabu_launcher_plan_sha256(&launcher_plan));
        let request = EngineExecutionRequest {
            case_id: "case-1",
            scan_run_id: "run-1",
            engine_run_id: "engine-run-1",
            manifest: &manifest,
            ai_system_applicable: false,
            ai_generated_artifact_applicable: false,
            assets: &assets,
            scope_grants: &grants,
            frozen_destinations: Some(&frozen_destinations),
            naabu_launcher_plan: Some(&launcher_plan),
            expected_naabu_launcher_plan_sha256: Some(&wrong_digest),
            workspace: None,
            network_policy: &policy,
            resource_limits: &limits,
            credentials: &credentials,
            attempt: 1,
        };

        let error = orchestrator
            .execute(&request, &CancellationToken::default())
            .expect_err("mismatched launcher digest must fail closed");
        assert!(error.to_string().contains("durable expected digest"));
        assert!(runtime.calls().is_empty());
    }

    #[test]
    fn successful_runtime_without_adapter_stops_at_captured_artifacts() {
        let temp = tempfile::tempdir().expect("temp directory");
        let workspace = temp.path().join("workspace");
        std::fs::create_dir(&workspace).expect("workspace");
        let store = ArtifactStore::open(temp.path().join("artifacts")).expect("store");
        let runtime = FakeContainerRuntime::default();
        let execution_preflight = RuntimePreflight {
            provider: crate::container_runtime::RuntimeProvider::Docker,
            server_version: "fake-2.0-after-restart".into(),
            security_options: "fake-updated-seccomp".into(),
            command_provenance: crate::container_runtime::RuntimeCommandProvenance::Compatibility,
        };
        runtime.set_execution_preflight(execution_preflight.clone());
        runtime.set_behavior(FakeRunBehavior {
            exit_code: Some(0),
            stdout: b"scanner stdout".to_vec(),
            stderr: b"scanner stderr".to_vec(),
            output_files: BTreeMap::from([("result.json".into(), b"{}".to_vec())]),
        });
        let adapters = AdapterRegistry::default();
        let orchestrator = Orchestrator::new(&runtime, &store, &adapters);
        let manifest = manifest(false);
        let assets = vec![asset("asset-1", false)];
        let grants = vec![grant("asset-1", ScanPermission::LocalArtifactRead, false)];
        let policy = NetworkPolicy::Disabled;
        let limits = ResourceLimits::default();
        let credentials = ScannerCredentialSet::default();
        let request = EngineExecutionRequest {
            case_id: "case-1",
            scan_run_id: "run-1",
            engine_run_id: "engine-run-1",
            manifest: &manifest,
            ai_system_applicable: false,
            ai_generated_artifact_applicable: false,
            assets: &assets,
            scope_grants: &grants,
            frozen_destinations: None,
            naabu_launcher_plan: None,
            expected_naabu_launcher_plan_sha256: None,
            workspace: Some(&workspace),
            network_policy: &policy,
            resource_limits: &limits,
            credentials: &credentials,
            attempt: 1,
        };

        let report = orchestrator
            .execute(&request, &CancellationToken::default())
            .expect("execution report");

        assert_eq!(
            report.checkpoint.stage,
            ExecutionStage::CapturedAwaitingAdapter
        );
        assert!(report.findings.is_empty());
        assert_eq!(report.runtime_preflight, Some(execution_preflight));
        assert_eq!(report.raw_artifacts.len(), 3);
        assert_eq!(report.raw_artifacts[0].byte_length, 14);
        assert_eq!(
            runtime.calls(),
            vec![
                RuntimeCall::Preflight,
                RuntimeCall::VerifyNetwork("disabled".into()),
                RuntimeCall::Pull(format!(
                    "registry.example/scanner@sha256:{}",
                    "a".repeat(64)
                )),
                RuntimeCall::ExecutionPreflight,
                RuntimeCall::Run("ass-scanner-engine-run-1-a1".into()),
                RuntimeCall::Cleanup("ass-scanner-engine-run-1-a1".into()),
            ]
        );
    }

    #[test]
    fn stale_batch_preflight_is_not_reused_when_execution_preflight_fails() {
        let temp = tempfile::tempdir().expect("temp directory");
        let workspace = temp.path().join("workspace");
        std::fs::create_dir(&workspace).expect("workspace");
        let store = ArtifactStore::open(temp.path().join("artifacts")).expect("store");
        let runtime = FakeContainerRuntime::default();
        runtime.set_fail_execution_preflight(true);
        let adapters = AdapterRegistry::default();
        let orchestrator = Orchestrator::new(&runtime, &store, &adapters);
        let manifest = manifest(false);
        let assets = vec![asset("asset-1", false)];
        let grants = vec![grant("asset-1", ScanPermission::LocalArtifactRead, false)];
        let policy = NetworkPolicy::Disabled;
        let limits = ResourceLimits::default();
        let credentials = ScannerCredentialSet::default();
        let request = EngineExecutionRequest {
            case_id: "case-1",
            scan_run_id: "run-1",
            engine_run_id: "engine-run-1",
            manifest: &manifest,
            ai_system_applicable: false,
            ai_generated_artifact_applicable: false,
            assets: &assets,
            scope_grants: &grants,
            frozen_destinations: None,
            naabu_launcher_plan: None,
            expected_naabu_launcher_plan_sha256: None,
            workspace: Some(&workspace),
            network_policy: &policy,
            resource_limits: &limits,
            credentials: &credentials,
            attempt: 1,
        };

        let report = orchestrator
            .execute(&request, &CancellationToken::default())
            .expect("failed execution report");

        assert_eq!(report.checkpoint.stage, ExecutionStage::Failed);
        assert!(report.checkpoint.cleanup_completed);
        assert_eq!(report.runtime_preflight, None);
        let raw_directory = temp
            .path()
            .join("artifacts/case-1/run-1/engine-run-1/attempt-1/raw");
        assert_eq!(
            std::fs::read_dir(raw_directory)
                .expect("raw capture directory")
                .count(),
            0,
            "execution preflight failure must not leave capture files",
        );
        assert!(
            report
                .checkpoint
                .last_error
                .as_deref()
                .is_some_and(|message| message.contains("execution preflight failure"))
        );
        assert_eq!(
            runtime.calls(),
            vec![
                RuntimeCall::Preflight,
                RuntimeCall::VerifyNetwork("disabled".into()),
                RuntimeCall::Pull(format!(
                    "registry.example/scanner@sha256:{}",
                    "a".repeat(64)
                )),
                RuntimeCall::ExecutionPreflight,
            ]
        );
    }

    #[test]
    fn failed_launch_without_a_created_object_never_cleans_a_same_name_container() {
        let temp = tempfile::tempdir().expect("temp directory");
        let workspace = temp.path().join("workspace");
        std::fs::create_dir(&workspace).expect("workspace");
        let store = ArtifactStore::open(temp.path().join("artifacts")).expect("store");
        let runtime = FakeContainerRuntime::default();
        runtime.set_skip_creation(true);
        runtime.set_behavior(FakeRunBehavior {
            exit_code: Some(125),
            ..FakeRunBehavior::default()
        });
        let adapters = AdapterRegistry::default();
        let orchestrator = Orchestrator::new(&runtime, &store, &adapters);
        let manifest = manifest(false);
        let assets = vec![asset("asset-1", false)];
        let grants = vec![grant("asset-1", ScanPermission::LocalArtifactRead, false)];
        let policy = NetworkPolicy::Disabled;
        let limits = ResourceLimits::default();
        let credentials = ScannerCredentialSet::default();
        let request = EngineExecutionRequest {
            case_id: "case-1",
            scan_run_id: "run-1",
            engine_run_id: "engine-run-1",
            manifest: &manifest,
            ai_system_applicable: false,
            ai_generated_artifact_applicable: false,
            assets: &assets,
            scope_grants: &grants,
            frozen_destinations: None,
            naabu_launcher_plan: None,
            expected_naabu_launcher_plan_sha256: None,
            workspace: Some(&workspace),
            network_policy: &policy,
            resource_limits: &limits,
            credentials: &credentials,
            attempt: 1,
        };

        let report = orchestrator
            .execute(&request, &CancellationToken::default())
            .expect("failed launch report");

        assert_eq!(report.checkpoint.stage, ExecutionStage::Failed);
        assert_eq!(
            report.checkpoint.container_name.as_deref(),
            Some(
                planned_container_name("scanner", "engine-run-1", 1)
                    .unwrap()
                    .as_str()
            )
        );
        assert!(report.checkpoint.cleanup_completed);
        assert!(
            !runtime
                .calls()
                .iter()
                .any(|call| matches!(call, RuntimeCall::Cleanup(_)))
        );
    }

    #[test]
    fn untracked_runtime_creation_is_reconciled_by_exact_planned_ownership() {
        let temp = tempfile::tempdir().expect("temp directory");
        let workspace = temp.path().join("workspace");
        std::fs::create_dir(&workspace).expect("workspace");
        let store = ArtifactStore::open(temp.path().join("artifacts")).expect("store");
        let runtime = FakeContainerRuntime::default();
        runtime.set_untracked_creation(true);
        runtime.set_behavior(FakeRunBehavior {
            exit_code: Some(125),
            ..FakeRunBehavior::default()
        });
        let adapters = AdapterRegistry::default();
        let orchestrator = Orchestrator::new(&runtime, &store, &adapters);
        let manifest = manifest(false);
        let assets = vec![asset("asset-1", false)];
        let grants = vec![grant("asset-1", ScanPermission::LocalArtifactRead, false)];
        let policy = NetworkPolicy::Disabled;
        let limits = ResourceLimits::default();
        let credentials = ScannerCredentialSet::default();
        let request = EngineExecutionRequest {
            case_id: "case-1",
            scan_run_id: "run-1",
            engine_run_id: "engine-run-1",
            manifest: &manifest,
            ai_system_applicable: false,
            ai_generated_artifact_applicable: false,
            assets: &assets,
            scope_grants: &grants,
            frozen_destinations: None,
            naabu_launcher_plan: None,
            expected_naabu_launcher_plan_sha256: None,
            workspace: Some(&workspace),
            network_policy: &policy,
            resource_limits: &limits,
            credentials: &credentials,
            attempt: 1,
        };

        let report = orchestrator
            .execute(&request, &CancellationToken::default())
            .expect("untracked launch report");

        let expected_name = planned_container_name("scanner", "engine-run-1", 1).unwrap();
        assert_eq!(report.checkpoint.stage, ExecutionStage::Failed);
        assert_eq!(
            report.checkpoint.container_name.as_deref(),
            Some(expected_name.as_str())
        );
        assert!(report.checkpoint.cleanup_completed);
        assert!(report.findings.is_empty());
        assert!(report.observations.is_empty());
        assert!(
            !report.raw_artifacts.is_empty(),
            "failed output remains captured without being misreported as inventory"
        );
        assert_eq!(
            runtime.calls().last(),
            Some(&RuntimeCall::Cleanup(expected_name))
        );
    }

    #[test]
    fn foreign_runtime_ownership_is_preserved_without_green_or_blocking_retry() {
        for untracked_creation in [false, true] {
            let temp = tempfile::tempdir().expect("temp directory");
            let workspace = temp.path().join("workspace");
            std::fs::create_dir(&workspace).expect("workspace");
            let store = ArtifactStore::open(temp.path().join("artifacts")).expect("artifact store");
            let runtime = FakeContainerRuntime::default();
            runtime.set_untracked_creation(untracked_creation);
            runtime.set_foreign_cleanup_mismatch(true);
            runtime.set_behavior(FakeRunBehavior {
                exit_code: Some(0),
                stdout: b"untrusted runtime output".to_vec(),
                stderr: Vec::new(),
                output_files: BTreeMap::from([(
                    "result.json".into(),
                    br#"{"would":"be-a-finding"}"#.to_vec(),
                )]),
            });
            let mut adapters = AdapterRegistry::default();
            adapters
                .register(Arc::new(MustNotRunAdapter))
                .expect("register tripwire adapter");
            let orchestrator = Orchestrator::new(&runtime, &store, &adapters);
            let manifest = manifest(false);
            let assets = vec![asset("asset-1", false)];
            let grants = vec![grant("asset-1", ScanPermission::LocalArtifactRead, false)];
            let policy = NetworkPolicy::Disabled;
            let limits = ResourceLimits::default();
            let credentials = ScannerCredentialSet::default();
            let request = EngineExecutionRequest {
                case_id: "case-1",
                scan_run_id: "run-1",
                engine_run_id: "engine-run-1",
                manifest: &manifest,
                ai_system_applicable: false,
                ai_generated_artifact_applicable: false,
                assets: &assets,
                scope_grants: &grants,
                frozen_destinations: None,
                naabu_launcher_plan: None,
                expected_naabu_launcher_plan_sha256: None,
                workspace: Some(&workspace),
                network_policy: &policy,
                resource_limits: &limits,
                credentials: &credentials,
                attempt: 1,
            };

            let report = orchestrator
                .execute(&request, &CancellationToken::default())
                .expect("ambiguous ownership is a terminal attempt outcome");

            let first_name = planned_container_name("scanner", "engine-run-1", 1).unwrap();
            let retry_name = planned_container_name("scanner", "engine-run-1", 2).unwrap();
            assert_ne!(first_name, retry_name);
            assert_eq!(report.checkpoint.stage, ExecutionStage::Failed);
            assert!(report.checkpoint.cleanup_completed);
            assert_eq!(
                report.checkpoint.container_name.as_deref(),
                Some(first_name.as_str())
            );
            assert!(
                report.raw_artifacts.len() >= 3,
                "raw capture remains available"
            );
            assert!(report.findings.is_empty());
            assert!(report.cleanup.as_ref().is_some_and(|cleanup| {
                !cleanup.removed && cleanup.detail.contains("Ownership status: unverified")
            }));
            assert!(report.warnings.iter().any(|warning| {
                warning.contains("ownership is unavailable")
                    && warning.contains("new isolated attempt")
            }));
            assert_eq!(
                runtime.calls().last(),
                Some(&RuntimeCall::Cleanup(first_name))
            );
        }
    }

    #[test]
    fn incomplete_normalization_cannot_complete_or_green_the_engine_run() {
        let temp = tempfile::tempdir().expect("temp directory");
        let workspace = temp.path().join("workspace");
        std::fs::create_dir(&workspace).expect("workspace");
        let store = ArtifactStore::open(temp.path().join("artifacts")).expect("store");
        let runtime = FakeContainerRuntime::default();
        runtime.set_behavior(FakeRunBehavior {
            exit_code: Some(0),
            stdout: b"scanner stdout".to_vec(),
            stderr: vec![],
            output_files: BTreeMap::from([("result.json".into(), b"{}".to_vec())]),
        });
        let mut adapters = AdapterRegistry::default();
        adapters
            .register(Arc::new(IncompleteAdapter))
            .expect("register adapter");
        let orchestrator = Orchestrator::new(&runtime, &store, &adapters);
        let manifest = manifest(false);
        let assets = vec![asset("asset-1", false)];
        let grants = vec![grant("asset-1", ScanPermission::LocalArtifactRead, false)];
        let policy = NetworkPolicy::Disabled;
        let limits = ResourceLimits::default();
        let credentials = ScannerCredentialSet::default();
        let request = EngineExecutionRequest {
            case_id: "case-1",
            scan_run_id: "run-1",
            engine_run_id: "engine-run-1",
            manifest: &manifest,
            ai_system_applicable: false,
            ai_generated_artifact_applicable: false,
            assets: &assets,
            scope_grants: &grants,
            frozen_destinations: None,
            naabu_launcher_plan: None,
            expected_naabu_launcher_plan_sha256: None,
            workspace: Some(&workspace),
            network_policy: &policy,
            resource_limits: &limits,
            credentials: &credentials,
            attempt: 1,
        };

        let report = orchestrator
            .execute(&request, &CancellationToken::default())
            .expect("execution report");

        assert_eq!(
            report.checkpoint.stage,
            ExecutionStage::CapturedAwaitingAdapter
        );
        assert!(report.checkpoint.cleanup_completed);
        assert_eq!(
            report.checkpoint.last_error.as_deref(),
            Some("adapter normalization was incomplete; raw evidence was retained")
        );
        assert!(
            report
                .warnings
                .iter()
                .any(|warning| warning.contains("malformed record"))
        );
    }

    #[test]
    fn observer_receives_durable_non_terminal_stages_and_captured_artifacts() {
        let temp = tempfile::tempdir().expect("temp directory");
        let workspace = temp.path().join("workspace");
        std::fs::create_dir(&workspace).expect("workspace");
        let store = ArtifactStore::open(temp.path().join("artifacts")).expect("store");
        let runtime = FakeContainerRuntime::default();
        runtime.set_behavior(FakeRunBehavior {
            exit_code: Some(0),
            stdout: b"stdout".to_vec(),
            stderr: vec![],
            output_files: BTreeMap::from([("result.json".into(), b"{}".to_vec())]),
        });
        let adapters = AdapterRegistry::default();
        let orchestrator = Orchestrator::new(&runtime, &store, &adapters);
        let manifest = manifest(false);
        let assets = vec![asset("asset-1", false)];
        let grants = vec![grant("asset-1", ScanPermission::LocalArtifactRead, false)];
        let policy = NetworkPolicy::Disabled;
        let limits = ResourceLimits::default();
        let credentials = ScannerCredentialSet::default();
        let request = EngineExecutionRequest {
            case_id: "case-1",
            scan_run_id: "run-1",
            engine_run_id: "engine-run-1",
            manifest: &manifest,
            ai_system_applicable: false,
            ai_generated_artifact_applicable: false,
            assets: &assets,
            scope_grants: &grants,
            frozen_destinations: None,
            naabu_launcher_plan: None,
            expected_naabu_launcher_plan_sha256: None,
            workspace: Some(&workspace),
            network_policy: &policy,
            resource_limits: &limits,
            credentials: &credentials,
            attempt: 1,
        };
        let mut observed = Vec::new();
        let report = orchestrator
            .execute_with_observer(
                &request,
                &CancellationToken::default(),
                |checkpoint_report| {
                    observed.push((
                        checkpoint_report.checkpoint.stage.clone(),
                        checkpoint_report.raw_artifacts.len(),
                        checkpoint_report.checkpoint.cleanup_completed,
                    ));
                    Ok(())
                },
            )
            .expect("execution");

        assert_eq!(
            observed
                .iter()
                .map(|(stage, _, _)| stage)
                .collect::<Vec<_>>(),
            vec![
                &ExecutionStage::Planned,
                &ExecutionStage::Preflight,
                &ExecutionStage::PullingImage,
                &ExecutionStage::Running,
                &ExecutionStage::AdaptingArtifacts,
            ]
        );
        assert_eq!(
            observed
                .iter()
                .map(|(_, _, cleanup_completed)| *cleanup_completed)
                .collect::<Vec<_>>(),
            vec![true, true, true, false, true],
            "only the Running checkpoint opens a container cleanup obligation"
        );
        assert!(observed.last().is_some_and(|(_, count, cleaned)| {
            *count == report.raw_artifacts.len() && *cleaned
        }));
    }

    #[test]
    fn failed_managed_network_proof_prevents_image_pull_and_container_run() {
        let temp = tempfile::tempdir().expect("temp directory");
        let store = ArtifactStore::open(temp.path().join("artifacts")).expect("store");
        let runtime = FakeContainerRuntime::default();
        runtime.set_fail_network(true);
        let adapters = AdapterRegistry::default();
        let orchestrator = Orchestrator::new(&runtime, &store, &adapters);
        let manifest = manifest(true);
        let assets = vec![asset("one", true)];
        let grants = vec![grant("one", ScanPermission::ActiveExternalTesting, true)];
        let policy = NetworkPolicy::managed(
            "ass-egress",
            "policy-1",
            vec!["one.example:443".into()],
            "socks5h://172.29.0.1:1080",
        )
        .expect("managed policy");
        let limits = ResourceLimits::default();
        let credentials = ScannerCredentialSet::default();
        let request = EngineExecutionRequest {
            case_id: "case-1",
            scan_run_id: "run-1",
            engine_run_id: "engine-run-1",
            manifest: &manifest,
            ai_system_applicable: false,
            ai_generated_artifact_applicable: false,
            assets: &assets,
            scope_grants: &grants,
            frozen_destinations: None,
            naabu_launcher_plan: None,
            expected_naabu_launcher_plan_sha256: None,
            workspace: None,
            network_policy: &policy,
            resource_limits: &limits,
            credentials: &credentials,
            attempt: 1,
        };

        let report = orchestrator
            .execute(&request, &CancellationToken::default())
            .expect("failure report");

        assert_eq!(report.checkpoint.stage, ExecutionStage::Failed);
        assert!(report.checkpoint.cleanup_completed);
        assert!(
            report
                .checkpoint
                .last_error
                .as_deref()
                .is_some_and(|message| message.contains("fake managed network rejected"))
        );
        assert_eq!(
            runtime.calls(),
            vec![
                RuntimeCall::Preflight,
                RuntimeCall::VerifyNetwork("policy-1".into()),
            ]
        );
    }

    #[test]
    fn cancellation_before_preflight_is_resumable_without_running() {
        let temp = tempfile::tempdir().expect("temp directory");
        let workspace = temp.path().join("workspace");
        std::fs::create_dir(&workspace).expect("workspace");
        let store = ArtifactStore::open(temp.path().join("artifacts")).expect("store");
        let runtime = FakeContainerRuntime::default();
        let adapters = AdapterRegistry::default();
        let orchestrator = Orchestrator::new(&runtime, &store, &adapters);
        let manifest = manifest(false);
        let assets = vec![asset("asset-1", false)];
        let grants = vec![grant("asset-1", ScanPermission::LocalArtifactRead, false)];
        let policy = NetworkPolicy::Disabled;
        let limits = ResourceLimits::default();
        let credentials = ScannerCredentialSet::default();
        let request = EngineExecutionRequest {
            case_id: "case-1",
            scan_run_id: "run-1",
            engine_run_id: "engine-run-1",
            manifest: &manifest,
            ai_system_applicable: false,
            ai_generated_artifact_applicable: false,
            assets: &assets,
            scope_grants: &grants,
            frozen_destinations: None,
            naabu_launcher_plan: None,
            expected_naabu_launcher_plan_sha256: None,
            workspace: Some(&workspace),
            network_policy: &policy,
            resource_limits: &limits,
            credentials: &credentials,
            attempt: 1,
        };
        let cancellation = CancellationToken::default();
        cancellation.cancel();

        let report = orchestrator
            .execute(&request, &cancellation)
            .expect("cancel report");

        assert_eq!(report.checkpoint.stage, ExecutionStage::Cancelled);
        assert_eq!(report.checkpoint.resume_action(), ResumeAction::Reexecute);
        assert!(runtime.calls().is_empty());
    }

    #[test]
    fn captured_checkpoints_follow_completed_container_cleanup() {
        for fail_cleanup in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let workspace = temp.path().join("workspace");
            std::fs::create_dir(&workspace).unwrap();
            let store = ArtifactStore::open(temp.path().join("artifacts")).unwrap();
            let runtime = FakeContainerRuntime::default();
            runtime.set_fail_cleanup(fail_cleanup);
            runtime.set_behavior(FakeRunBehavior {
                exit_code: Some(0),
                stdout: b"fixture".to_vec(),
                stderr: vec![],
                output_files: BTreeMap::from([("result.json".into(), b"{}".to_vec())]),
            });
            let adapters = AdapterRegistry::default();
            let orchestrator = Orchestrator::new(&runtime, &store, &adapters);
            let manifest = manifest(false);
            let assets = vec![asset("asset-1", false)];
            let grants = vec![grant("asset-1", ScanPermission::LocalArtifactRead, false)];
            let policy = NetworkPolicy::Disabled;
            let limits = ResourceLimits::default();
            let credentials = ScannerCredentialSet::default();
            let request = EngineExecutionRequest {
                case_id: "case-1",
                scan_run_id: "run-1",
                engine_run_id: "engine-run-1",
                manifest: &manifest,
                ai_system_applicable: false,
                ai_generated_artifact_applicable: false,
                assets: &assets,
                scope_grants: &grants,
                frozen_destinations: None,
                naabu_launcher_plan: None,
                expected_naabu_launcher_plan_sha256: None,
                workspace: Some(&workspace),
                network_policy: &policy,
                resource_limits: &limits,
                credentials: &credentials,
                attempt: 1,
            };
            let mut checkpoints = Vec::new();
            let report = orchestrator
                .execute_with_observer(&request, &CancellationToken::default(), |report| {
                    checkpoints.push(report.checkpoint.clone());
                    Ok(())
                })
                .unwrap();
            checkpoints.push(report.checkpoint.clone());
            assert!(checkpoints.iter().all(|checkpoint| {
                !matches!(
                    checkpoint.stage,
                    ExecutionStage::CapturedAwaitingAdapter | ExecutionStage::AdaptingArtifacts
                ) || checkpoint.cleanup_completed
            }));
            if fail_cleanup {
                assert_eq!(report.checkpoint.stage, ExecutionStage::CleanupPending);
                assert!(!report.checkpoint.cleanup_completed);
                assert!(report.checkpoint.container_name.is_some());
                assert!(!checkpoints.iter().any(|checkpoint| matches!(
                    checkpoint.stage,
                    ExecutionStage::CapturedAwaitingAdapter | ExecutionStage::AdaptingArtifacts
                )));
            } else {
                assert_eq!(
                    report.checkpoint.stage,
                    ExecutionStage::CapturedAwaitingAdapter
                );
                assert!(report.checkpoint.cleanup_completed);
            }
        }
    }

    #[test]
    fn cleanup_failure_is_a_distinct_resumable_state() {
        let temp = tempfile::tempdir().expect("temp directory");
        let workspace = temp.path().join("workspace");
        std::fs::create_dir(&workspace).expect("workspace");
        let store = ArtifactStore::open(temp.path().join("artifacts")).expect("store");
        let runtime = FakeContainerRuntime::default();
        runtime.set_fail_cleanup(true);
        let adapters = AdapterRegistry::default();
        let orchestrator = Orchestrator::new(&runtime, &store, &adapters);
        let manifest = manifest(false);
        let assets = vec![asset("asset-1", false)];
        let grants = vec![grant("asset-1", ScanPermission::LocalArtifactRead, false)];
        let policy = NetworkPolicy::Disabled;
        let limits = ResourceLimits::default();
        let credentials = ScannerCredentialSet::default();
        let request = EngineExecutionRequest {
            case_id: "case-1",
            scan_run_id: "run-1",
            engine_run_id: "engine-run-1",
            manifest: &manifest,
            ai_system_applicable: false,
            ai_generated_artifact_applicable: false,
            assets: &assets,
            scope_grants: &grants,
            frozen_destinations: None,
            naabu_launcher_plan: None,
            expected_naabu_launcher_plan_sha256: None,
            workspace: Some(&workspace),
            network_policy: &policy,
            resource_limits: &limits,
            credentials: &credentials,
            attempt: 1,
        };

        let report = orchestrator
            .execute(&request, &CancellationToken::default())
            .expect("execution report");

        assert_eq!(report.checkpoint.stage, ExecutionStage::CleanupPending);
        assert_eq!(
            report.checkpoint.resume_action(),
            ResumeAction::CleanupContainer
        );
        assert!(!report.checkpoint.cleanup_completed);
        assert_eq!(
            report.checkpoint.runtime_command_provenance,
            Some(RuntimeCommandProvenance::Compatibility)
        );
        assert_eq!(
            report.checkpoint.runtime_provider,
            Some(crate::container_runtime::RuntimeProvider::Docker)
        );
        assert_eq!(report.exit_code, Some(0));
        assert!(
            report
                .checkpoint
                .last_error
                .as_deref()
                .is_some_and(|message| message.contains("fake cleanup failure"))
        );
    }

    #[test]
    fn cleanup_pending_preserves_a_nonzero_scanner_exit_as_the_primary_failure() {
        let temp = tempfile::tempdir().expect("temp directory");
        let workspace = temp.path().join("workspace");
        std::fs::create_dir(&workspace).expect("workspace");
        let store = ArtifactStore::open(temp.path().join("artifacts")).expect("store");
        let runtime = FakeContainerRuntime::default();
        runtime.set_behavior(FakeRunBehavior {
            exit_code: Some(17),
            ..FakeRunBehavior::default()
        });
        runtime.set_fail_cleanup(true);
        let adapters = AdapterRegistry::default();
        let orchestrator = Orchestrator::new(&runtime, &store, &adapters);
        let manifest = manifest(false);
        let assets = vec![asset("asset-1", false)];
        let grants = vec![grant("asset-1", ScanPermission::LocalArtifactRead, false)];
        let policy = NetworkPolicy::Disabled;
        let limits = ResourceLimits::default();
        let credentials = ScannerCredentialSet::default();
        let request = EngineExecutionRequest {
            case_id: "case-1",
            scan_run_id: "run-1",
            engine_run_id: "engine-run-1",
            manifest: &manifest,
            ai_system_applicable: false,
            ai_generated_artifact_applicable: false,
            assets: &assets,
            scope_grants: &grants,
            frozen_destinations: None,
            naabu_launcher_plan: None,
            expected_naabu_launcher_plan_sha256: None,
            workspace: Some(&workspace),
            network_policy: &policy,
            resource_limits: &limits,
            credentials: &credentials,
            attempt: 1,
        };

        let report = orchestrator
            .execute(&request, &CancellationToken::default())
            .expect("cleanup-pending report");

        assert_eq!(report.checkpoint.stage, ExecutionStage::CleanupPending);
        assert_eq!(report.exit_code, Some(17));
        let error = report.checkpoint.last_error.as_deref().unwrap();
        assert_eq!(
            error,
            "scanner container exited with status Some(17); container cleanup also failed: runtime error: fake cleanup failure"
        );
        assert!(!report.checkpoint.cleanup_completed);
        assert!(report.checkpoint.resume_token().is_ok());
    }

    #[test]
    fn cleanup_pending_preserves_the_runtime_root_cause() {
        let temp = tempfile::tempdir().expect("temp directory");
        let workspace = temp.path().join("workspace");
        std::fs::create_dir(&workspace).expect("workspace");
        let store = ArtifactStore::open(temp.path().join("artifacts")).expect("store");
        let runtime = FakeContainerRuntime::default();
        runtime.set_behavior(FakeRunBehavior {
            stdout: vec![0_u8; 1_048_577],
            ..FakeRunBehavior::default()
        });
        runtime.set_fail_cleanup(true);
        let adapters = AdapterRegistry::default();
        let orchestrator = Orchestrator::new(&runtime, &store, &adapters);
        let manifest = manifest(false);
        let assets = vec![asset("asset-1", false)];
        let grants = vec![grant("asset-1", ScanPermission::LocalArtifactRead, false)];
        let policy = NetworkPolicy::Disabled;
        let limits = ResourceLimits {
            output_bytes: 1_048_576,
            ..ResourceLimits::default()
        };
        let credentials = ScannerCredentialSet::default();
        let request = EngineExecutionRequest {
            case_id: "case-1",
            scan_run_id: "run-1",
            engine_run_id: "engine-run-1",
            manifest: &manifest,
            ai_system_applicable: false,
            ai_generated_artifact_applicable: false,
            assets: &assets,
            scope_grants: &grants,
            frozen_destinations: None,
            naabu_launcher_plan: None,
            expected_naabu_launcher_plan_sha256: None,
            workspace: Some(&workspace),
            network_policy: &policy,
            resource_limits: &limits,
            credentials: &credentials,
            attempt: 1,
        };

        let report = orchestrator
            .execute(&request, &CancellationToken::default())
            .expect("cleanup-pending report");

        assert_eq!(report.checkpoint.stage, ExecutionStage::CleanupPending);
        assert!(!report.checkpoint.cleanup_completed);
        assert_eq!(report.exit_code, None);
        let error = report.checkpoint.last_error.as_deref().unwrap();
        assert!(
            error.contains("scan coverage is incomplete"),
            "the user must be told coverage is incomplete, but the error was: {error}"
        );
        assert!(error.contains("container cleanup also failed"));
        assert!(error.contains("fake cleanup failure"));
        assert!(report.checkpoint.resume_token().is_ok());

        let deadline = combined_cleanup_pending_error(
            Some("managed local engine launcher: engine exceeded its fixed runtime timeout"),
            None,
            "ownership-proven container removal exceeded its deadline",
        );
        assert!(deadline.contains("engine exceeded its fixed runtime timeout"));
        assert!(deadline.contains("container cleanup also failed"));
        assert!(deadline.contains("container removal exceeded its deadline"));
    }

    #[test]
    fn checkpoint_token_round_trips_without_secrets() {
        let checkpoint = ExecutionCheckpoint {
            case_id: "case-1".into(),
            scan_run_id: "run-1".into(),
            engine_run_id: "engine-run-1".into(),
            engine_id: "scanner".into(),
            attempt: 1,
            stage: ExecutionStage::CapturedAwaitingAdapter,
            container_name: Some("ass-scanner-engine-run-1-a1".into()),
            scope_sha256: Some("abc".into()),
            zap_plan_sha256: None,
            launcher_plan_sha256: None,
            artifact_ids: vec!["artifact-1".into()],
            cleanup_completed: true,
            last_error: None,
            failure_code: None,
            runtime_command_provenance: None,
            runtime_provider: None,
            managed_network: None,
        };

        let token = checkpoint.resume_token().expect("token");
        let decoded = ExecutionCheckpoint::from_resume_token(&token).expect("decoded");
        assert_eq!(decoded.stage, ExecutionStage::CapturedAwaitingAdapter);
        assert_eq!(
            decoded.resume_action(),
            ResumeAction::AdaptCapturedArtifacts
        );
        assert!(!token.to_ascii_lowercase().contains("secret"));

        let mut legacy = serde_json::to_value(&checkpoint).expect("legacy checkpoint");
        legacy
            .as_object_mut()
            .expect("checkpoint object")
            .remove("managed_network");
        legacy
            .as_object_mut()
            .expect("checkpoint object")
            .remove("launcher_plan_sha256");
        let legacy = ExecutionCheckpoint::from_resume_token(&legacy.to_string())
            .expect("pre-managed-network checkpoint remains readable");
        assert!(legacy.managed_network.is_none());
        assert!(legacy.launcher_plan_sha256.is_none());
        assert!(legacy.runtime_command_provenance.is_none());
    }

    #[test]
    fn checkpoint_rejects_a_non_lowercase_launcher_digest() {
        let token = serde_json::json!({
            "case_id": "case-1",
            "scan_run_id": "run-1",
            "engine_run_id": "engine-run-1",
            "engine_id": "naabu",
            "attempt": 1,
            "stage": "planned",
            "container_name": "ass-naabu-engine-run-1-a1",
            "scope_sha256": "b".repeat(64),
            "launcher_plan_sha256": "A".repeat(64),
            "artifact_ids": [],
            "cleanup_completed": true,
            "last_error": null
        })
        .to_string();

        let error = ExecutionCheckpoint::from_resume_token(&token)
            .expect_err("uppercase launcher digest rejected");
        assert!(error.to_string().contains("launcher plan digest"));
    }

    #[test]
    fn checkpoint_launcher_digest_requires_a_naabu_scope() {
        let base = serde_json::json!({
            "case_id": "case-1",
            "scan_run_id": "run-1",
            "engine_run_id": "engine-run-1",
            "engine_id": "naabu",
            "attempt": 1,
            "stage": "planned",
            "container_name": "ass-naabu-engine-run-1-a1",
            "scope_sha256": "b".repeat(64),
            "launcher_plan_sha256": "a".repeat(64),
            "artifact_ids": [],
            "cleanup_completed": false,
            "last_error": null
        });

        for (field, replacement) in [
            ("engine_id", serde_json::json!("scanner")),
            ("scope_sha256", serde_json::Value::Null),
        ] {
            let mut malformed = base.clone();
            malformed[field] = replacement;
            let error = ExecutionCheckpoint::from_resume_token(&malformed.to_string())
                .expect_err("unowned launcher digest rejected");
            assert!(
                error
                    .to_string()
                    .contains("requires a Naabu execution scope")
            );
        }
    }

    #[test]
    fn forged_cleanup_container_in_resume_token_is_rejected() {
        let token = serde_json::json!({
            "case_id": "case-1",
            "scan_run_id": "run-1",
            "engine_run_id": "engine-run-1",
            "engine_id": "scanner",
            "attempt": 1,
            "stage": "cleanup_pending",
            "container_name": "unrelated-production-container",
            "scope_sha256": "abc",
            "artifact_ids": [],
            "cleanup_completed": false,
            "last_error": null
        })
        .to_string();

        let error = ExecutionCheckpoint::from_resume_token(&token)
            .expect_err("forged container identity rejected");
        assert!(error.to_string().contains("does not match"));
    }

    #[test]
    fn cleanup_checkpoint_without_runtime_provenance_is_rejected() {
        let token = serde_json::json!({
            "case_id": "case-1",
            "scan_run_id": "run-1",
            "engine_run_id": "engine-run-1",
            "engine_id": "scanner",
            "attempt": 1,
            "stage": "cleanup_pending",
            "container_name": "ass-scanner-engine-run-1-a1",
            "scope_sha256": "abc",
            "artifact_ids": [],
            "cleanup_completed": false,
            "last_error": null,
            "managed_network": null
        })
        .to_string();

        let error = ExecutionCheckpoint::from_resume_token(&token)
            .expect_err("cleanup without runtime provenance rejected");
        assert!(error.to_string().contains("provider and provenance"));
    }
}
