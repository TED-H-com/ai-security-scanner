use ai_security_scanner_lib::adapters::builtin_adapter_registry;
use ai_security_scanner_lib::artifact_store::{ArtifactContext, ArtifactStore};
use ai_security_scanner_lib::bootstrap::executor::{
    bootstrap_cleanup_obligation_summary, list_bootstrap_cleanup_obligations,
};
use ai_security_scanner_lib::case_service::{
    CaseExportFormat, CaseService, DurableExecutionReport, FindingGroupRequest,
    FindingUngroupRequest, FindingWorkflowRequest, ScanPlanRequest, ScopeApprovalRequest,
    SourceMutation,
};
use ai_security_scanner_lib::connectors::MAX_SNAPSHOT_BYTES;
use ai_security_scanner_lib::connectors::SnapshotConnectorRegistry;
use ai_security_scanner_lib::container_runtime::{
    CancellationToken, CleanupOutcome, ContainerPlanBuilder, ContainerRuntime, NetworkPolicy,
    OwnedContainerCleanupRequest, PinnedImage, ProcessContainerRuntime, ResourceLimits,
    RuntimeCommandProvenance, RuntimePreflight, RuntimeProvider, ScannerCredentialSet,
    cleanup_orphaned_credentials,
};
use ai_security_scanner_lib::correlation::correlation_report;
use ai_security_scanner_lib::demo::build_demo_case;
use ai_security_scanner_lib::discovery::run_connector;
use ai_security_scanner_lib::domain::{
    AssessmentActivity, CaseStatus, CreateCaseRequest, DataClass, DistributionMode, EngineManifest,
    EngineRunStatus, FindingStatus, ScanPermission, ScopeGrant, SourceConnectionStatus, SourceKind,
    new_id,
};
use ai_security_scanner_lib::error::{AppError, AppResult};
use ai_security_scanner_lib::export::{
    ExportOptions, RedactionProfile, ReportLocale, verify_case_bundle,
};
use ai_security_scanner_lib::external_scope::ExternalScopeRequest;
use ai_security_scanner_lib::gateway_release::managed_egress_gateway_spec;
use ai_security_scanner_lib::managed_network::{
    ManagedGatewayQualification, ManagedNetworkCleanupOutcome, ManagedNetworkController,
    ManagedNetworkOwner, ManagedNetworkRegistry,
};
use ai_security_scanner_lib::managed_runtime::{
    ManagedRuntimeManager, ManagedStopMode, ManagedUninstallOptions,
    WindowsInstallerPrerequisiteClass, ensure_private_product_data_directory,
    prepare_windows_installer_prerequisite,
};
use ai_security_scanner_lib::orchestrator::{ExecutionCheckpoint, ExecutionStage};
use ai_security_scanner_lib::process_lease::DataDirectoryExclusiveLease;
#[cfg(test)]
use ai_security_scanner_lib::product_uninstall::ALL_DATA_CONFIRMATION;
use ai_security_scanner_lib::product_uninstall::{
    LocalProductUninstallBackend, PRODUCT_DATA_DIRECTORY_NAME, ProductUninstallMode,
    ProductUninstallRequest, ProductUninstallResultClass, coordinate_product_uninstall,
    finalize_all_data_root, prepare_fixed_product_data_root, stage_all_data_root_for_finalization,
};
use ai_security_scanner_lib::registry::EngineRegistry;
use ai_security_scanner_lib::runtime::detect_runtime;
use ai_security_scanner_lib::storage::Storage;
use ai_security_scanner_lib::workspace_snapshot::{
    WorkspaceInputProfile, WorkspaceSnapshotLimits, create_workspace_snapshot_with_profile,
    resolve_workspace_snapshot,
};
use chrono::{DateTime, Utc};
use clap::parser::ValueSource;
use clap::{ArgAction, Args, CommandFactory, FromArgMatches, Subcommand, ValueEnum};
use directories::{BaseDirs, ProjectDirs};
use serde::Serialize;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

const MANAGED_RUNTIME_QUALIFICATION_ENGINE_ID: &str = "gitleaks";
// Keep the release-only artifact prefix compact. Podman's Windows client owns
// the `--cidfile` lifecycle and rejects otherwise valid extended-length paths
// once a long LocalApplicationData prefix, two UUIDs, and its CID filename are
// combined. One fresh engine-run UUID still gives every qualification an
// unpredictable, unique ownership namespace.
const MANAGED_RUNTIME_QUALIFICATION_CASE_ID: &str = "q";
const MANAGED_RUNTIME_QUALIFICATION_SCAN_RUN_ID: &str = "s";
const MANAGED_RUNTIME_QUALIFICATION_IMAGE: &str = concat!(
    "ghcr.io/teddashh/ai-security-scanner-engine-gitleaks@",
    "sha256:95313654f9c37115a906629a82113ba6e1c729950be70909da8362e9482b477e"
);
const MANAGED_RUNTIME_QUALIFICATION_REPORT: &str = "gitleaks.json";
const MAX_MANAGED_RUNTIME_QUALIFICATION_REPORT_BYTES: u64 = 1024 * 1024;

#[derive(Debug, clap::Parser)]
#[command(name = "ai-security-scanner")]
#[command(about = "Local-first security assessment casework CLI")]
#[command(version)]
struct Cli {
    /// Override the local application data directory.
    #[arg(long, global = true, env = "AI_SECURITY_SCANNER_DATA_DIR")]
    data_dir: Option<PathBuf>,

    /// Override the release-managed runtime bundle directory.
    #[arg(
        long,
        global = true,
        env = "AI_SECURITY_SCANNER_MANAGED_RUNTIME_BUNDLE"
    )]
    managed_runtime_bundle: Option<PathBuf>,

    /// Use digest-keyed OCI archives from a release-approved local image directory.
    #[arg(
        long,
        global = true,
        env = "AI_SECURITY_SCANNER_RELEASE_APPROVED_LOCAL_IMAGE_DIRECTORY"
    )]
    release_approved_local_image_directory: Option<PathBuf>,

    /// Emit compact machine-readable JSON.
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    #[cfg(feature = "installer-runtime-cache")]
    /// Verify and seed the installed package's exact managed-runtime payload
    /// into private state before the desktop first opens.
    #[command(hide = true)]
    WindowsInstallerRuntimeCache,
    /// Run the installed package's fixed Windows prerequisite check/servicing
    /// coordinator before opening any project or accepting any caller input.
    #[command(hide = true)]
    WindowsInstallerPrerequisite,
    /// Coordinate one exact installed-product uninstall choice before opening
    /// the case database or engine catalog. Intended for the package uninstaller.
    ProductUninstall(ProductUninstallArgs),
    /// Manage long-lived assessment cases.
    Case {
        #[command(subcommand)]
        command: CaseCommand,
    },
    /// Manage non-secret, read-only discovery source records and snapshots.
    Source {
        #[command(subcommand)]
        command: SourceCommand,
    },
    /// Record explicit human scope decisions.
    Scope {
        #[command(subcommand)]
        command: ScopeCommand,
    },
    /// Record immutable human handling decisions without altering evidence.
    Finding {
        #[command(subcommand)]
        command: FindingCommand,
    },
    /// Plan and inspect scans. Planning never starts a scanner process.
    Scan {
        #[command(subcommand)]
        command: ScanCommand,
    },
    /// Create and verify explicit local exports.
    Export {
        #[command(subcommand)]
        command: ExportCommand,
    },
    /// Compare two terminal runs and persist the coverage-aware result.
    Compare(CompareArgs),
    /// Inspect scanner engine metadata and retrieve release-approved pinned images.
    Engine {
        #[command(subcommand)]
        command: EngineCommand,
    },
    /// Inspect and resolve exact, case-bound local runtime cleanup obligations.
    Runtime {
        #[command(subcommand)]
        command: RuntimeCommand,
    },
    /// Inspect secret-free provider bootstrap cleanup obligations.
    Bootstrap {
        #[command(subcommand)]
        command: BootstrapCommand,
    },
    /// Preview one native Strix vulnerabilities.json report without executing it.
    ExternalReportPreview {
        #[arg(long)]
        report: PathBuf,
    },
    /// Import up to sixteen previewed report bindings with bounded concurrent readers.
    ExternalReportImportBatch {
        #[arg(long)]
        case_id: String,
        #[arg(long)]
        manifest: PathBuf,
    },
    /// Import findings from one previewed target into an existing project asset.
    ExternalReportImport {
        #[arg(long)]
        case_id: String,
        #[arg(long)]
        asset_id: String,
        #[arg(long)]
        report: PathBuf,
        #[arg(long)]
        upstream_target: String,
        #[arg(long)]
        source_sha256: String,
    },
    /// Check local storage, catalog, and container runtime readiness.
    Doctor,
}

#[derive(Debug, Args)]
struct ProductUninstallArgs {
    #[arg(long, value_enum)]
    mode: ProductUninstallModeArg,
    /// Confirms that the package uninstaller, rather than this CLI, owns the
    /// visible choice and any data-loss prompt.
    #[arg(long)]
    non_interactive: bool,
    /// Required only for all-data and compared byte-for-byte with the fixed
    /// confirmation phrase printed by the package uninstaller.
    #[arg(long)]
    confirmation: Option<String>,
    /// Emit the fixed, privacy-safe package-coordinator envelope instead of
    /// the detailed retained-item record.
    #[arg(long, hide = true)]
    coordinator_envelope: bool,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ProductUninstallModeArg {
    AppOnly,
    #[value(alias = "verified-scan-tools")]
    ScanTools,
    AllData,
}

impl From<ProductUninstallModeArg> for ProductUninstallMode {
    fn from(value: ProductUninstallModeArg) -> Self {
        match value {
            ProductUninstallModeArg::AppOnly => Self::AppOnly,
            ProductUninstallModeArg::ScanTools => Self::ScanTools,
            ProductUninstallModeArg::AllData => Self::AllData,
        }
    }
}

#[derive(Debug, Subcommand)]
enum CaseCommand {
    Create(CreateCaseArgs),
    List,
    Show {
        case_id: String,
    },
    Selected,
    Select {
        case_id: String,
    },
    ClearSelection,
    Archive {
        case_id: String,
    },
    /// Inspect the exact artifact path before deleting a database record.
    DeletePlan {
        case_id: String,
    },
    /// Delete only the exact case database record; artifact files are retained.
    Delete {
        case_id: String,
        /// Must exactly match CASE_ID. This never deletes artifact files.
        #[arg(long)]
        confirm_case_id: String,
    },
    /// Delete the exact case artifact directory from a previously inspected plan.
    DeleteArtifacts {
        case_id: String,
        /// Must exactly match the backend-generated path from `case delete-plan`.
        #[arg(long)]
        exact_path: String,
        /// Must exactly equal `DELETE CASE_ID`.
        #[arg(long)]
        confirmation: String,
    },
    Events {
        case_id: String,
    },
    /// Create or select a clearly labeled synthetic demonstration case.
    SeedDemo,
}

#[derive(Debug, Args)]
struct CreateCaseArgs {
    #[arg(long)]
    title: String,
    /// Optional company or team label. It never gates local work.
    #[arg(long)]
    organization: Option<String>,
    #[arg(long, default_value = "unknown")]
    employee_range: String,
    /// Comma-separated values: general, pii, phi, pci, financial, secrets, other.
    #[arg(long, value_delimiter = ',')]
    data_class: Vec<String>,
    /// Comma-separated questionnaire intent only: configuration-assessment,
    /// local-artifact-analysis, low-impact-external-checks, active-external-vulnerability-tests.
    /// This never creates a scope grant.
    #[arg(long, value_enum, value_delimiter = ',')]
    requested_activity: Vec<AssessmentActivityArg>,
    /// Expected source kinds establish unknown coverage only; they do not connect anything.
    #[arg(long, value_enum, value_delimiter = ',')]
    source_kind: Vec<SourceKindArg>,
    #[arg(long)]
    notes: Option<String>,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum AssessmentActivityArg {
    ConfigurationAssessment,
    LocalArtifactAnalysis,
    LowImpactExternalChecks,
    ActiveExternalVulnerabilityTests,
}

impl From<AssessmentActivityArg> for AssessmentActivity {
    fn from(value: AssessmentActivityArg) -> Self {
        match value {
            AssessmentActivityArg::ConfigurationAssessment => Self::ConfigurationAssessment,
            AssessmentActivityArg::LocalArtifactAnalysis => Self::LocalArtifactAnalysis,
            AssessmentActivityArg::LowImpactExternalChecks => Self::LowImpactExternalChecks,
            AssessmentActivityArg::ActiveExternalVulnerabilityTests => {
                Self::ActiveExternalVulnerabilityTests
            }
        }
    }
}

#[derive(Debug, Subcommand)]
enum SourceCommand {
    List {
        case_id: String,
    },
    /// Add a source or update a source that has no backend-owned artifact metadata.
    Upsert(SourceUpsertArgs),
    /// Parse a previously preserved, backend-owned connector artifact.
    Discover {
        case_id: String,
        source_id: String,
    },
    /// Preserve and parse one explicitly selected provider-output snapshot.
    DiscoverFromArtifact(SourceArtifactArgs),
    /// Copy one explicitly selected local directory into a bounded read-only snapshot.
    AttachWorkspace(SourceAttachWorkspaceArgs),
    /// Copy the folder again into a new read-only snapshot for an existing local asset.
    RefreshWorkspace(SourceRefreshWorkspaceArgs),
    /// List bounded artifact parsers and whether the desktop can capture their provider pages live.
    Connectors,
}

#[derive(Debug, Subcommand)]
enum BootstrapCommand {
    /// List bounded cleanup summaries for one exact case.
    CleanupList { case_id: String },
    /// Show one cleanup summary without exposing resource IDs or endpoints.
    CleanupShow {
        case_id: String,
        operation_id: String,
    },
}

#[derive(Debug, Args)]
struct SourceUpsertArgs {
    #[arg(long)]
    case_id: String,
    /// Existing source ID. Omit to add a source.
    #[arg(long)]
    source_id: Option<String>,
    #[arg(long, value_enum)]
    kind: SourceKindArg,
    #[arg(long)]
    label: String,
    #[arg(long, value_enum, default_value_t = SourceStatusArg::NotConnected)]
    status: SourceStatusArg,
    /// Connected sources must remain read-only. Use `--read-only false` only for a disconnected draft.
    #[arg(long, default_value_t = true, action = ArgAction::Set)]
    read_only: bool,
}

#[derive(Debug, Args)]
struct SourceArtifactArgs {
    #[arg(long)]
    case_id: String,
    #[arg(long)]
    source_id: String,
    /// Absolute path to a regular file explicitly selected by the user.
    #[arg(long)]
    snapshot: PathBuf,
    /// One parser profile listed by `source connectors` for this source kind.
    #[arg(long)]
    profile: String,
    /// Observation time in RFC 3339. Defaults to the ingestion time.
    #[arg(long)]
    observed_at: Option<String>,
}

#[derive(Debug, Args)]
struct SourceAttachWorkspaceArgs {
    #[arg(long)]
    case_id: String,
    /// User-facing repository or local-input identity shown in Review and Results.
    #[arg(long)]
    label: String,
    /// Absolute path to a directory explicitly selected by the user.
    #[arg(long, value_name = "PATH")]
    path: PathBuf,
    #[arg(long, value_enum)]
    profile: WorkspaceInputProfileArg,
}

#[derive(Debug, Args)]
struct SourceRefreshWorkspaceArgs {
    #[arg(long)]
    case_id: String,
    #[arg(long)]
    asset_id: String,
    /// Absolute path to a directory explicitly selected by the user.
    #[arg(long, value_name = "PATH")]
    path: PathBuf,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum WorkspaceInputProfileArg {
    RepositoryWorkingTree,
    IacWorkingTree,
    ContainerImageOciLayout,
    KubernetesManifests,
    KubernetesNodeSnapshot,
}

impl From<WorkspaceInputProfileArg> for WorkspaceInputProfile {
    fn from(value: WorkspaceInputProfileArg) -> Self {
        match value {
            WorkspaceInputProfileArg::RepositoryWorkingTree => Self::RepositoryWorkingTree,
            WorkspaceInputProfileArg::IacWorkingTree => Self::IacWorkingTree,
            WorkspaceInputProfileArg::ContainerImageOciLayout => Self::ContainerImageOciLayout,
            WorkspaceInputProfileArg::KubernetesManifests => Self::KubernetesManifests,
            WorkspaceInputProfileArg::KubernetesNodeSnapshot => Self::KubernetesNodeSnapshot,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum SourceKindArg {
    AwsOrganization,
    AzureTenant,
    GcpOrganization,
    Microsoft365Tenant,
    Dns,
    CertificateTransparency,
    Billing,
    GitRepository,
    TerraformState,
    KubernetesCluster,
    ContainerRegistry,
    FileSystem,
    UserDeclared,
}

impl From<SourceKindArg> for SourceKind {
    fn from(value: SourceKindArg) -> Self {
        match value {
            SourceKindArg::AwsOrganization => Self::AwsOrganization,
            SourceKindArg::AzureTenant => Self::AzureTenant,
            SourceKindArg::GcpOrganization => Self::GcpOrganization,
            SourceKindArg::Microsoft365Tenant => Self::Microsoft365Tenant,
            SourceKindArg::Dns => Self::Dns,
            SourceKindArg::CertificateTransparency => Self::CertificateTransparency,
            SourceKindArg::Billing => Self::Billing,
            SourceKindArg::GitRepository => Self::GitRepository,
            SourceKindArg::TerraformState => Self::TerraformState,
            SourceKindArg::KubernetesCluster => Self::KubernetesCluster,
            SourceKindArg::ContainerRegistry => Self::ContainerRegistry,
            SourceKindArg::FileSystem => Self::FileSystem,
            SourceKindArg::UserDeclared => Self::UserDeclared,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum SourceStatusArg {
    NotConnected,
    Connecting,
    Connected,
    NeedsReauthorization,
    Failed,
}

impl From<SourceStatusArg> for SourceConnectionStatus {
    fn from(value: SourceStatusArg) -> Self {
        match value {
            SourceStatusArg::NotConnected => Self::NotConnected,
            SourceStatusArg::Connecting => Self::Connecting,
            SourceStatusArg::Connected => Self::Connected,
            SourceStatusArg::NeedsReauthorization => Self::NeedsReauthorization,
            SourceStatusArg::Failed => Self::Failed,
        }
    }
}

#[derive(Debug, Subcommand)]
enum ScopeCommand {
    List { case_id: String },
    Approve(ScopeApproveArgs),
}

#[derive(Debug, Subcommand)]
enum FindingCommand {
    History {
        case_id: String,
    },
    Groups {
        case_id: String,
    },
    /// Show which findings from different engines may describe one issue.
    /// Read-only: it proposes groups, it never creates one.
    Correlations {
        case_id: String,
    },
    Group(FindingGroupArgs),
    Ungroup(FindingUngroupArgs),
    Update(FindingUpdateArgs),
}

#[derive(Debug, Args)]
struct FindingGroupArgs {
    #[arg(long)]
    case_id: String,
    #[arg(long)]
    title: String,
    /// Two or more exact finding IDs. Grouping never merges or deletes them.
    /// The backend enforces two distinct members and the 100-member limit after
    /// comma-delimited values have been expanded.
    #[arg(long, value_delimiter = ',', required = true)]
    finding_id: Vec<String>,
    #[arg(long)]
    rationale: String,
    #[arg(long)]
    grouped_by: String,
}

#[derive(Debug, Args)]
struct FindingUngroupArgs {
    #[arg(long)]
    case_id: String,
    #[arg(long)]
    group_id: String,
    #[arg(long)]
    removed_by: String,
    #[arg(long)]
    reason: String,
}

#[derive(Debug, Args)]
struct FindingUpdateArgs {
    #[arg(long)]
    case_id: String,
    #[arg(long)]
    finding_id: String,
    #[arg(long, value_enum)]
    status: FindingStatusArg,
    #[arg(long)]
    decided_by: String,
    #[arg(long)]
    reason: String,
    /// RFC 3339 expiry; accepted only for false-positive decisions.
    #[arg(long)]
    expires_at: Option<String>,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum FindingStatusArg {
    Unreviewed,
    ExpertReviewRequested,
    Confirmed,
    FalsePositive,
    RemediationReported,
    VerifiedResolved,
}

impl From<FindingStatusArg> for FindingStatus {
    fn from(value: FindingStatusArg) -> Self {
        match value {
            FindingStatusArg::Unreviewed => Self::Unreviewed,
            FindingStatusArg::ExpertReviewRequested => Self::ExpertReviewRequested,
            FindingStatusArg::Confirmed => Self::Confirmed,
            FindingStatusArg::FalsePositive => Self::FalsePositive,
            FindingStatusArg::RemediationReported => Self::RemediationReported,
            FindingStatusArg::VerifiedResolved => Self::VerifiedResolved,
        }
    }
}

#[derive(Debug, Args)]
struct ScopeApproveArgs {
    #[arg(long)]
    case_id: String,
    #[arg(long)]
    asset_id: String,
    /// Comma-separated, explicit permissions for this asset. The
    /// passive-external-discovery, low-impact-external-connection, and
    /// active-external-testing permissions require --external-scope.
    #[arg(long, value_enum, value_delimiter = ',', required = true)]
    permission: Vec<PermissionArg>,
    /// Human or accountable local identity recording the decision.
    #[arg(long)]
    confirmed_by: String,
    /// RFC 3339 instant. Omit only when the authorization is intentionally open-ended.
    #[arg(long)]
    expires_at: Option<String>,
    /// Required for low-impact or active external activity.
    #[arg(long)]
    authorization_reference: Option<String>,
    /// Absolute path to a regular file explicitly selected by the user. Required
    /// for passive-external-discovery, low-impact-external-connection, and
    /// active-external-testing permissions.
    #[arg(long, value_name = "PATH")]
    external_scope: Option<PathBuf>,
    #[arg(long)]
    notes: Option<String>,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum PermissionArg {
    InventoryRead,
    ConfigurationRead,
    LocalArtifactRead,
    PassiveExternalDiscovery,
    LowImpactExternalConnection,
    ActiveExternalTesting,
}

impl PermissionArg {
    fn is_external(self) -> bool {
        matches!(
            self,
            Self::PassiveExternalDiscovery
                | Self::LowImpactExternalConnection
                | Self::ActiveExternalTesting
        )
    }
}

impl From<PermissionArg> for ScanPermission {
    fn from(value: PermissionArg) -> Self {
        match value {
            PermissionArg::InventoryRead => Self::InventoryRead,
            PermissionArg::ConfigurationRead => Self::ConfigurationRead,
            PermissionArg::LocalArtifactRead => Self::LocalArtifactRead,
            PermissionArg::PassiveExternalDiscovery => Self::PassiveExternalDiscovery,
            PermissionArg::LowImpactExternalConnection => Self::LowImpactExternalConnection,
            PermissionArg::ActiveExternalTesting => Self::ActiveExternalTesting,
        }
    }
}

#[derive(Debug, Subcommand)]
enum ScanCommand {
    /// Persist an immutable, credential-free dispatch plan. Does not execute it.
    Plan(ScanPlanArgs),
    /// Request execution without accepting credentials on the command line.
    Start(ScanTransitionArgs),
    /// Persist a new plan tied to a terminal baseline. Does not execute it.
    RescanPlan(RescanPlanArgs),
    Status(ScanStatusArgs),
    Pause(ScanTransitionArgs),
    Resume(ScanTransitionArgs),
    /// Request cancellation for a persisted plan whose engine runs are queued
    /// or not_executed, with no live status or recorded outcome. A recorded
    /// start is accepted only for queued_for_resume work from an ended attempt.
    /// Only queued work changes to cancelled; a plan with nothing queued is
    /// refused. Preparing, running, or paused work requires desktop scan
    /// controls. Runs that already reached an outcome are also refused.
    Cancel(ScanTransitionArgs),
}

#[derive(Debug, Args)]
struct ScanPlanArgs {
    /// Optional reviewed incident campaign, for example october-2026.
    #[arg(long)]
    campaign: Option<String>,
    #[arg(long)]
    case_id: String,
    /// Exact engine IDs. Omit to automatically plan every catalog engine
    /// applicable to the case assets and effective scope grants.
    #[arg(long, value_delimiter = ',')]
    engine: Vec<String>,
}

#[derive(Debug, Args)]
struct RescanPlanArgs {
    /// Optional reviewed incident campaign, for example october-2026.
    #[arg(long)]
    campaign: Option<String>,
    #[arg(long)]
    case_id: String,
    #[arg(long)]
    baseline_run_id: String,
    #[arg(long, value_delimiter = ',')]
    engine: Vec<String>,
}

#[derive(Debug, Args)]
struct ScanStatusArgs {
    #[arg(long)]
    case_id: String,
    /// Omit to inspect all runs in the case.
    #[arg(long)]
    run_id: Option<String>,
}

#[derive(Debug, Args)]
struct ScanTransitionArgs {
    #[arg(long)]
    case_id: String,
    #[arg(long)]
    run_id: String,
}

#[derive(Debug, Subcommand)]
enum ExportCommand {
    Create(ExportCreateArgs),
    /// Combine explicitly selected finished reports without running new checks.
    Combine(ExportCombineArgs),
    Verify {
        #[arg(long)]
        case_id: Option<String>,
        #[arg(long)]
        export_id: Option<String>,
        /// Verify a received signed `.case.tar.gz` without a local case record.
        /// Its embedded signer key remains self-asserted unless pinned elsewhere.
        #[arg(long)]
        path: Option<PathBuf>,
    },
    Identity {
        #[command(subcommand)]
        command: ExportIdentityCommand,
    },
    Formats,
}

#[derive(Debug, Subcommand)]
enum ExportIdentityCommand {
    /// Show or establish the durable public identity for local signed exports.
    Show,
    /// Replace a private key only after its exact recorded key ID is confirmed lost.
    RotateAfterKeyLoss {
        #[arg(long)]
        acknowledge_lost_key_id: String,
    },
}

#[derive(Debug, Args)]
struct ExportCombineArgs {
    #[arg(long)]
    case_id: String,
    /// Two to sixteen explicit source run IDs, separated by commas or repeated.
    #[arg(long, value_delimiter = ',', required = true)]
    run_id: Vec<String>,
    #[arg(long, value_enum)]
    format: CombinedExportFormatArg,
    /// Explicit local output filename. Existing files are never overwritten.
    #[arg(long)]
    destination: PathBuf,
    #[arg(long, value_enum, default_value_t = RedactionArg::Standard)]
    redaction: RedactionArg,
    #[arg(long, value_enum, default_value_t = ReportLocaleArg::En)]
    locale: ReportLocaleArg,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CombinedExportFormatArg {
    Html,
    Json,
}

#[derive(Debug, Args)]
struct ExportCreateArgs {
    #[arg(long)]
    case_id: String,
    #[arg(long)]
    run_id: String,
    #[arg(long, value_enum)]
    format: ExportFormatArg,
    /// Explicit local output filename. Existing files are never overwritten.
    #[arg(long)]
    destination: PathBuf,
    #[arg(long, value_enum, default_value_t = RedactionArg::Standard)]
    redaction: RedactionArg,
    /// Readable HTML presentation locale. Canonical scan facts stay unchanged.
    #[arg(long, value_enum, default_value_t = ReportLocaleArg::En)]
    locale: ReportLocaleArg,
    /// HTML or bundle. Attach original files, which may contain sensitive data.
    #[arg(long, requires = "acknowledge_sensitive_raw_artifacts")]
    include_raw_artifacts: bool,
    /// Explicit acknowledgement required with --include-raw-artifacts.
    #[arg(long)]
    acknowledge_sensitive_raw_artifacts: bool,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ExportFormatArg {
    CaseBundle,
    Json,
    FrameworkReport,
    Ocsf,
    Oscal,
    Html,
}

impl From<ExportFormatArg> for CaseExportFormat {
    fn from(value: ExportFormatArg) -> Self {
        match value {
            ExportFormatArg::CaseBundle => Self::CaseBundle,
            ExportFormatArg::Json => Self::CanonicalJson,
            ExportFormatArg::FrameworkReport => Self::FrameworkReport,
            ExportFormatArg::Ocsf => Self::OcsfJson,
            ExportFormatArg::Oscal => Self::OscalJson,
            ExportFormatArg::Html => Self::Html,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum RedactionArg {
    Standard,
    None,
}

impl From<RedactionArg> for RedactionProfile {
    fn from(value: RedactionArg) -> Self {
        match value {
            RedactionArg::Standard => Self::Standard,
            RedactionArg::None => Self::None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum ReportLocaleArg {
    En,
    #[value(name = "zh-Hant")]
    ZhHant,
}

impl From<ReportLocaleArg> for ReportLocale {
    fn from(value: ReportLocaleArg) -> Self {
        match value {
            ReportLocaleArg::En => Self::En,
            ReportLocaleArg::ZhHant => Self::ZhHant,
        }
    }
}

#[derive(Debug, Args)]
struct CompareArgs {
    #[arg(long)]
    case_id: String,
    #[arg(long)]
    baseline_run_id: String,
    #[arg(long)]
    current_run_id: String,
}

#[derive(Debug, Subcommand)]
enum EngineCommand {
    List,
    /// Backward-compatible manifest inspection command.
    Show {
        engine_id: String,
    },
    Inspect {
        engine_id: String,
    },
    /// Retrieve one immutable image only when its manifest is release-approved.
    Install {
        engine_id: String,
    },
}

#[derive(Debug, Subcommand)]
enum RuntimeCommand {
    /// Manage the app-private, release-pinned local runtime.
    Managed {
        #[command(subcommand)]
        command: ManagedRuntimeCliCommand,
    },
    /// Inspect runtime health and outstanding cleanup records without mutation.
    Inspect(RuntimeInspectArgs),
    /// Show exact runtime containers and managed networks requiring cleanup for one run.
    CleanupPlan {
        #[arg(long)]
        case_id: String,
        #[arg(long)]
        run_id: String,
    },
    /// Reconcile only resources named by stored, provenance-bound cleanup checkpoints.
    Cleanup {
        #[arg(long)]
        case_id: String,
        #[arg(long)]
        run_id: String,
        /// Must exactly match RUN_ID.
        #[arg(long)]
        confirm_run_id: String,
    },
}

#[derive(Debug, Subcommand)]
enum ManagedRuntimeCliCommand {
    /// Inspect the verified private runtime and its rootless machine.
    Status,
    /// Verify and install the release-pinned runtime payload.
    Install,
    /// Install if needed and start the owned rootless machine.
    Start,
    /// Stop the owned machine; active engine containers fail closed by default.
    Stop {
        /// Stop even when owned engine containers are still running.
        #[arg(long)]
        force: bool,
    },
    /// Install, prove, and start the runtime bundled with this app version.
    Update,
    /// Run the release-fixed, network-disabled managed-container qualification.
    Qualify,
    /// Prove the pinned gateway is reachable without sending an upstream request.
    QualifyEgress,
    /// Remove only this app's exact managed machine and private payload.
    Uninstall {
        /// Stop even when owned engine containers are still running.
        #[arg(long)]
        force: bool,
        /// Also remove the exact verified machine-image cache file.
        #[arg(long)]
        purge_image_cache: bool,
    },
}

#[derive(Debug, Args)]
struct RuntimeInspectArgs {
    /// Limit cleanup inspection to one case.
    #[arg(long)]
    case_id: Option<String>,
    /// Limit cleanup inspection to one run. Requires --case-id.
    #[arg(long, requires = "case_id")]
    run_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct CleanupObligation {
    case_id: String,
    scan_run_id: String,
    engine_run_id: String,
    engine_id: String,
    attempt: u32,
    container_name: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct InvalidCheckpointRecord {
    case_id: String,
    scan_run_id: String,
    engine_run_id: String,
    explanation: &'static str,
}

#[derive(Debug, Default, Serialize)]
struct CleanupInspection {
    pending: Vec<CleanupObligation>,
    invalid_checkpoint_records: Vec<InvalidCheckpointRecord>,
}

#[derive(Debug)]
struct ExactRuntimeCleanup {
    container: CleanupOutcome,
    managed_network: Option<ManagedNetworkCleanupOutcome>,
    orphan_credentials_removed: usize,
}

#[derive(Debug)]
struct ExactRuntimeCleanupFailure {
    container: Option<CleanupOutcome>,
    error: AppError,
}

#[tokio::main]
async fn main() {
    let matches = Cli::command().get_matches();
    let option_sources = GlobalOptionSources {
        data_dir: matches.value_source("data_dir"),
        managed_runtime_bundle: matches.value_source("managed_runtime_bundle"),
    };
    let cli = Cli::from_arg_matches(&matches).unwrap_or_else(|error| error.exit());
    let json_errors = cli.json;
    match execute(cli, option_sources).await {
        Ok(0) => {}
        Ok(exit_code) => std::process::exit(i32::from(exit_code)),
        Err(error) => {
            if json_errors {
                eprintln!("{}", json!({ "error": error.to_string() }));
            } else {
                eprintln!("error: {error}");
            }
            std::process::exit(1);
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct GlobalOptionSources {
    data_dir: Option<ValueSource>,
    managed_runtime_bundle: Option<ValueSource>,
}

#[derive(Debug, Clone, Copy)]
struct RuntimeSourceOverrides<'a> {
    managed_runtime_bundle: Option<&'a Path>,
    release_approved_local_image_directory: Option<&'a Path>,
}

#[derive(Debug, Serialize)]
struct ProductUninstallCoordinatorEnvelope {
    schema_version: &'static str,
    mode: ProductUninstallMode,
    result_class: ProductUninstallResultClass,
    exit_code: u8,
    retained_item_count: usize,
    retained_classes: Vec<&'static str>,
    terminal: &'static str,
}

#[derive(Debug, Serialize)]
struct WindowsInstallerPrerequisiteCoordinatorEnvelope {
    schema_version: &'static str,
    result_class: WindowsInstallerPrerequisiteClass,
    exit_code: u8,
    restart_required: bool,
    terminal: &'static str,
}

#[cfg(feature = "installer-runtime-cache")]
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum WindowsInstallerRuntimeCacheClass {
    Seeded,
    Unavailable,
}

#[cfg(feature = "installer-runtime-cache")]
#[derive(Debug, Serialize)]
struct WindowsInstallerRuntimeCacheCoordinatorEnvelope {
    schema_version: &'static str,
    result_class: WindowsInstallerRuntimeCacheClass,
    exit_code: u8,
    terminal: &'static str,
}

impl GlobalOptionSources {
    fn data_dir_was_explicit(self) -> bool {
        self.data_dir == Some(ValueSource::CommandLine)
    }

    fn managed_runtime_bundle_was_explicit(self) -> bool {
        self.managed_runtime_bundle == Some(ValueSource::CommandLine)
    }
}

async fn execute(cli: Cli, option_sources: GlobalOptionSources) -> AppResult<u8> {
    #[cfg(feature = "installer-runtime-cache")]
    if matches!(cli.command, Command::WindowsInstallerRuntimeCache) {
        return execute_windows_installer_runtime_cache_early(option_sources);
    }
    if matches!(cli.command, Command::WindowsInstallerPrerequisite) {
        return execute_windows_installer_prerequisite_early(option_sources);
    }
    if let Command::ProductUninstall(args) = &cli.command {
        return execute_product_uninstall_early(&cli, args, option_sources);
    }

    let managed_runtime_bundle = cli.managed_runtime_bundle;
    let release_approved_local_image_directory = cli.release_approved_local_image_directory;
    let data_dir_was_overridden = cli.data_dir.is_some();
    let data_dir = resolve_data_dir(cli.data_dir)?;
    let _product_data_guard: Option<_> = if data_dir_was_overridden {
        prepare_overridden_data_directory(&data_dir)?;
        None
    } else {
        Some(ensure_private_product_data_directory(&data_dir)?)
    };
    if !data_dir_was_overridden {
        let legacy_data_dir = legacy_project_data_dir();
        if let Some(notice) = preserved_legacy_data_notice(&data_dir, legacy_data_dir.as_deref()) {
            eprintln!("{notice}");
        }
    }
    // A managed-runtime status query does not need the case database, engine
    // catalog, artifact tree, or signing key. Dispatch it before any of those
    // workspace resources are created or opened. Manager admission can create
    // or restrict its own state directory, so coordinate that bounded mutation
    // with the same data-directory lease used by other runtime commands.
    if command_is_managed_runtime_status(&cli.command) {
        let _exclusive_lease = DataDirectoryExclusiveLease::acquire(&data_dir)?;
        execute_managed_runtime_cli_command(
            &data_dir,
            &data_dir.join("artifacts"),
            managed_runtime_bundle.as_deref(),
            release_approved_local_image_directory.as_deref(),
            ManagedRuntimeCliCommand::Status,
            cli.json,
        )
        .await?;
        return Ok(0);
    }
    let _exclusive_lease = command_requires_exclusive_data_directory(&cli.command)
        .then(|| DataDirectoryExclusiveLease::acquire(&data_dir))
        .transpose()?;
    let artifact_root = data_dir.join("artifacts");
    fs::create_dir_all(&artifact_root)?;

    let storage = Storage::open(data_dir.join("casework.db"))?;
    let engines = EngineRegistry::load_builtin()?;
    let adapters = builtin_adapter_registry()?;
    let service = CaseService::new(
        &storage,
        &engines,
        &adapters,
        &artifact_root,
        data_dir.join("integrity-signing-key"),
    );

    match cli.command {
        Command::ExternalReportPreview { report } => {
            print_value(
                &ai_security_scanner_lib::external_scanner_import::preview_external_scanner_import(
                    &report,
                )?,
                cli.json,
            )?;
        }
        Command::ExternalReportImportBatch { case_id, manifest } => {
            let requests =
                ai_security_scanner_lib::external_scanner_import::read_import_manifest(&manifest)?;
            print_value(
                &ai_security_scanner_lib::external_scanner_import::import_external_scanner_reports(
                    &storage,
                    &artifact_root,
                    &case_id,
                    &requests,
                )?,
                cli.json,
            )?;
        }
        Command::ExternalReportImport {
            case_id,
            asset_id,
            report,
            upstream_target,
            source_sha256,
        } => {
            let request =
                ai_security_scanner_lib::external_scanner_import::ExternalScannerImportRequest {
                    report_path: report,
                    asset_id,
                    upstream_target,
                    source_sha256,
                };
            print_value(
                &ai_security_scanner_lib::external_scanner_import::import_external_scanner_reports(
                    &storage,
                    &artifact_root,
                    &case_id,
                    &[request],
                )?,
                cli.json,
            )?;
        }
        #[cfg(feature = "installer-runtime-cache")]
        Command::WindowsInstallerRuntimeCache => {
            unreachable!("Windows installer runtime cache is early-dispatched")
        }
        Command::WindowsInstallerPrerequisite => {
            unreachable!("Windows installer prerequisite is early-dispatched")
        }
        Command::ProductUninstall(_) => unreachable!("product uninstall is early-dispatched"),
        Command::Case { command } => {
            execute_case(command, &storage, &service, cli.json)?;
        }
        Command::Source { command } => {
            execute_source(command, &storage, &service, &artifact_root, cli.json)?;
        }
        Command::Scope { command } => execute_scope(command, &service, cli.json)?,
        Command::Finding { command } => execute_finding(command, &service, cli.json)?,
        Command::Scan { command } => execute_scan(command, &service, cli.json)?,
        Command::Export { command } => execute_export(command, &service, cli.json)?,
        Command::Compare(args) => {
            let comparison = service.compare_and_persist(
                &args.case_id,
                &args.baseline_run_id,
                &args.current_run_id,
            )?;
            print_value(&comparison, cli.json)?;
        }
        Command::Engine { command } => {
            execute_engine(
                command,
                &engines,
                &adapters,
                release_approved_local_image_directory.as_deref(),
                cli.json,
            )?;
        }
        Command::Runtime { command } => {
            execute_runtime(
                command,
                &service,
                &engines,
                &data_dir,
                &artifact_root,
                RuntimeSourceOverrides {
                    managed_runtime_bundle: managed_runtime_bundle.as_deref(),
                    release_approved_local_image_directory: release_approved_local_image_directory
                        .as_deref(),
                },
                cli.json,
            )
            .await?;
        }
        Command::Bootstrap { command } => {
            service.show_case(match &command {
                BootstrapCommand::CleanupList { case_id }
                | BootstrapCommand::CleanupShow { case_id, .. } => case_id,
            })?;
            match command {
                BootstrapCommand::CleanupList { case_id } => {
                    let root = artifact_root.join(&case_id).join("provider-bootstrap");
                    print_value(
                        &list_bootstrap_cleanup_obligations(&root, &case_id)?,
                        cli.json,
                    )?;
                }
                BootstrapCommand::CleanupShow {
                    case_id,
                    operation_id,
                } => {
                    let path = artifact_root
                        .join(&case_id)
                        .join("provider-bootstrap")
                        .join(format!("cleanup-{operation_id}.json"));
                    print_value(
                        &bootstrap_cleanup_obligation_summary(&path, &case_id, &operation_id)?,
                        cli.json,
                    )?;
                }
            }
        }
        Command::Doctor => {
            let managed_runtime =
                inspect_managed_runtime(&data_dir, managed_runtime_bundle.as_deref()).await;
            let compatibility_runtime = detect_runtime().await;
            let cleanup = inspect_cleanup(&service.list_cases()?, &service, None, None)?;
            let report = json!({
                "product": "ai-security-scanner",
                "product_version": env!("CARGO_PKG_VERSION"),
                "data_dir": data_dir,
                "database": storage.path(),
                "runtime": {
                    "preferred_provider": "managed_local",
                    "managed_local": managed_runtime,
                    "compatibility": compatibility_runtime,
                },
                "engine_manifests": engines.manifests().len(),
                "engine_admission_issues": engines.admission_issues(),
                "release_approved_engines": engines.manifests().iter()
                    .filter(|manifest| manifest.release_blocker().is_none())
                    .count(),
                "pending_runtime_cleanup": cleanup.pending.len(),
                "invalid_checkpoint_records": cleanup.invalid_checkpoint_records.len(),
            });
            print_value(&report, cli.json)?;
        }
    }

    Ok(0)
}

fn validate_product_uninstall_option_sources(option_sources: GlobalOptionSources) -> AppResult<()> {
    if option_sources.data_dir_was_explicit() {
        return Err(AppError::NotAuthorized(
            "product-uninstall refuses an explicit global --data-dir override".into(),
        ));
    }
    if option_sources.managed_runtime_bundle_was_explicit() {
        return Err(AppError::NotAuthorized(
            "product-uninstall refuses an explicit managed-runtime bundle override".into(),
        ));
    }
    Ok(())
}

fn validate_windows_installer_prerequisite_option_sources(
    option_sources: GlobalOptionSources,
) -> AppResult<()> {
    if option_sources.data_dir_was_explicit() {
        return Err(AppError::NotAuthorized(
            "windows-installer-prerequisite refuses an explicit global --data-dir override".into(),
        ));
    }
    if option_sources.managed_runtime_bundle_was_explicit() {
        return Err(AppError::NotAuthorized(
            "windows-installer-prerequisite refuses an explicit managed-runtime bundle override"
                .into(),
        ));
    }
    Ok(())
}

#[cfg(feature = "installer-runtime-cache")]
fn validate_windows_installer_runtime_cache_option_sources(
    option_sources: GlobalOptionSources,
) -> AppResult<()> {
    if option_sources.data_dir_was_explicit() {
        return Err(AppError::NotAuthorized(
            "windows-installer-runtime-cache refuses an explicit global --data-dir override".into(),
        ));
    }
    if option_sources.managed_runtime_bundle_was_explicit() {
        return Err(AppError::NotAuthorized(
            "windows-installer-runtime-cache refuses an explicit managed-runtime bundle override"
                .into(),
        ));
    }
    Ok(())
}

#[cfg(feature = "installer-runtime-cache")]
fn windows_installer_runtime_cache_result<F>(seed: F) -> WindowsInstallerRuntimeCacheClass
where
    F: FnOnce() -> AppResult<()>,
{
    match seed() {
        Ok(()) => WindowsInstallerRuntimeCacheClass::Seeded,
        Err(_) => WindowsInstallerRuntimeCacheClass::Unavailable,
    }
}

#[cfg(feature = "installer-runtime-cache")]
fn execute_windows_installer_runtime_cache_early(
    option_sources: GlobalOptionSources,
) -> AppResult<u8> {
    // Environment-backed development overrides are ignored. The installed
    // package owns both fixed roots; no command-line path can redirect this
    // bounded copy into caller-selected state or toward another bundle.
    validate_windows_installer_runtime_cache_option_sources(option_sources)?;
    let result_class = windows_installer_runtime_cache_result(|| {
        let data_dir = resolve_data_dir(None)?;
        let _product_data_guard = ensure_private_product_data_directory(&data_dir)?;
        let _exclusive_lease = DataDirectoryExclusiveLease::acquire(&data_dir)?;
        let manager = open_exact_packaged_installer_runtime_cache_source(&data_dir)?;
        manager.install()?;
        Ok(())
    });
    let exit_code = match result_class {
        WindowsInstallerRuntimeCacheClass::Seeded => 0,
        WindowsInstallerRuntimeCacheClass::Unavailable => 30,
    };
    let envelope = WindowsInstallerRuntimeCacheCoordinatorEnvelope {
        schema_version: "ai-security-scanner.windows-installer-runtime-cache/v1",
        result_class,
        exit_code,
        terminal: "complete",
    };
    // Never expose the package path, private-data path, parser failure, or
    // attacker-controlled bytes to the installer. NSIS accepts only this exact
    // terminal envelope and treats every failure as non-blocking degradation.
    let stdout = io::stdout();
    let mut stdout = stdout.lock();
    serde_json::to_writer(&mut stdout, &envelope)?;
    stdout.flush()?;
    Ok(exit_code)
}

fn windows_installer_prerequisite_exit(
    result_class: &WindowsInstallerPrerequisiteClass,
) -> (u8, bool) {
    match result_class {
        WindowsInstallerPrerequisiteClass::Ready | WindowsInstallerPrerequisiteClass::Serviced => {
            (0, false)
        }
        WindowsInstallerPrerequisiteClass::RestartRequired => (10, true),
        WindowsInstallerPrerequisiteClass::Cancelled => (20, false),
        WindowsInstallerPrerequisiteClass::Failed => (30, false),
    }
}

fn execute_windows_installer_prerequisite_early(
    option_sources: GlobalOptionSources,
) -> AppResult<u8> {
    // Environment-backed development overrides are ignored. Explicit global
    // overrides are rejected so the package cannot be redirected toward a
    // caller-selected data directory, bundle, executable, action, or argument.
    validate_windows_installer_prerequisite_option_sources(option_sources)?;
    let result = prepare_windows_installer_prerequisite()?;
    let (exit_code, restart_required) = windows_installer_prerequisite_exit(&result.class);
    let envelope = WindowsInstallerPrerequisiteCoordinatorEnvelope {
        schema_version: "ai-security-scanner.windows-installer-prerequisite/v1",
        result_class: result.class,
        exit_code,
        restart_required,
        terminal: "complete",
    };
    // Deliberately no detail and no trailing newline. NSIS accepts only this
    // complete, compact, privacy-safe terminal envelope paired with its exact
    // process exit class. The backend result detail remains in-process.
    let stdout = io::stdout();
    let mut stdout = stdout.lock();
    serde_json::to_writer(&mut stdout, &envelope)?;
    // `main` uses `process::exit` for restart/cancel/failure classes, so the
    // complete envelope must cross the pipe before the nonzero exit occurs.
    stdout.flush()?;
    Ok(exit_code)
}

fn execute_product_uninstall_early(
    cli: &Cli,
    args: &ProductUninstallArgs,
    option_sources: GlobalOptionSources,
) -> AppResult<u8> {
    // Environment-backed overrides are intentionally ignored for this one
    // installed-product command. They are useful for ordinary CLI casework,
    // but must not redirect or block the package uninstaller. Explicit command
    // line overrides remain a contract error.
    validate_product_uninstall_option_sources(option_sources)?;
    if args.coordinator_envelope && !cli.json {
        return Err(AppError::InvalidRequest(
            "--coordinator-envelope requires --json".into(),
        ));
    }
    let request = ProductUninstallRequest {
        mode: args.mode.into(),
        non_interactive: args.non_interactive,
        confirmation: args.confirmation.clone(),
    };
    // Confirmation and mode validation happen before a lock file is created or
    // any runtime inventory can issue a command.
    request.validate()?;

    let local_data_root = BaseDirs::new()
        .map(|directories| directories.data_local_dir().to_path_buf())
        .ok_or_else(|| AppError::Internal("platform local-data directory unavailable".into()))?;
    let data_root = local_data_root.join(PRODUCT_DATA_DIRECTORY_NAME);
    let (data_existed_before, data_root_guard) =
        prepare_fixed_product_data_root(&data_root, &local_data_root)?;
    // Always lease the canonical root, including the absent-root case. A
    // desktop that races to create or acquire it wins or loses the same exact
    // lease before runtime inventory begins; absence is never treated as a
    // concurrency exemption.
    let exclusive_lease = DataDirectoryExclusiveLease::acquire(&data_root)?;
    let mut backend = LocalProductUninstallBackend::new(data_root.clone());
    let mut result = coordinate_product_uninstall(&request, &mut backend)?;
    drop(backend);
    drop(data_root_guard);
    let may_finalize = result.result_class != ProductUninstallResultClass::ContactNotStopped
        && (request.mode == ProductUninstallMode::AllData || !data_existed_before);
    let staged_data_root = if may_finalize {
        if !result.canonical_data_root_can_be_staged() {
            result.record_finalization_retained(
                "product_data",
                "ambiguous_or_unremoved_product_state_preserved",
            );
            None
        } else {
            match stage_all_data_root_for_finalization(&data_root, &exclusive_lease) {
                Ok(staged) => Some(staged),
                Err(_) => {
                    result.record_finalization_retained(
                        "product_data",
                        "product_data_root_staging_incomplete",
                    );
                    None
                }
            }
        }
    } else {
        None
    };
    drop(exclusive_lease);

    if let Some(staged_data_root) = staged_data_root {
        for retained in finalize_all_data_root(&staged_data_root) {
            result.record_finalization_retained(retained.item_class, retained.reason_code);
        }
    }
    if args.coordinator_envelope {
        let retained_classes = result
            .retained_items
            .iter()
            .map(|item| item.item_class)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let envelope = ProductUninstallCoordinatorEnvelope {
            schema_version: result.schema_version,
            mode: result.mode,
            result_class: result.result_class,
            exit_code: result.exit_code,
            retained_item_count: result.retained_items.len(),
            retained_classes,
            terminal: "complete",
        };
        // Deliberately no trailing newline: NSIS compares the complete bounded
        // envelope and never mistakes a truncated detailed record for success.
        print!("{}", serde_json::to_string(&envelope)?);
    } else if cli.json {
        println!("{}", serde_json::to_string(&result)?);
    } else {
        println!("{}", serde_json::to_string_pretty(&result)?);
    }
    Ok(result.exit_code)
}

fn command_requires_exclusive_data_directory(command: &Command) -> bool {
    match command {
        // Package coordinators are early-dispatched before the database,
        // catalog, or any caller-selected runtime state is opened.
        #[cfg(feature = "installer-runtime-cache")]
        Command::WindowsInstallerRuntimeCache => false,
        Command::WindowsInstallerPrerequisite => false,
        // ProductUninstall is early-dispatched and acquires the same lease
        // before database/catalog initialization.
        Command::ProductUninstall(_) => false,
        Command::ExternalReportImport { .. } | Command::ExternalReportImportBatch { .. } => true,
        Command::Case {
            command: CaseCommand::Delete { .. } | CaseCommand::DeleteArtifacts { .. },
        } => true,
        Command::Scan {
            command: ScanCommand::Cancel(_),
        } => true,
        Command::Runtime {
            command: RuntimeCommand::Cleanup { .. },
        } => true,
        Command::Runtime {
            command: RuntimeCommand::Managed { .. },
        } => true,
        Command::Export {
            command: ExportCommand::Identity { .. },
        } => true,
        _ => false,
    }
}

fn command_is_managed_runtime_status(command: &Command) -> bool {
    matches!(
        command,
        Command::Runtime {
            command: RuntimeCommand::Managed {
                command: ManagedRuntimeCliCommand::Status,
            },
        }
    )
}

fn execute_case(
    command: CaseCommand,
    storage: &Storage,
    service: &CaseService<'_>,
    json_output: bool,
) -> AppResult<()> {
    match command {
        CaseCommand::Create(args) => {
            let request = CreateCaseRequest {
                title: args.title,
                organization_name: args.organization.unwrap_or_default(),
                employee_range: args.employee_range,
                assessment_intent: None,
                ai_generated_artifact: Default::default(),
                data_classes: args
                    .data_class
                    .iter()
                    .map(|value| parse_data_class(value))
                    .collect::<AppResult<Vec<_>>>()?,
                requested_activities: args
                    .requested_activity
                    .into_iter()
                    .map(Into::into)
                    .collect(),
                source_kinds: args.source_kind.into_iter().map(Into::into).collect(),
                not_applicable_source_kinds: vec![],
                declared_assets: vec![],
                notes: args.notes,
            };
            print_value(&service.create_case(&request)?, json_output)?;
        }
        CaseCommand::List => print_value(&service.list_cases()?, json_output)?,
        CaseCommand::Show { case_id } => {
            print_value(&service.show_case(&case_id)?, json_output)?;
        }
        CaseCommand::Selected => print_value(&service.selected_case()?, json_output)?,
        CaseCommand::Select { case_id } => {
            print_value(&service.select_case(&case_id)?, json_output)?;
        }
        CaseCommand::ClearSelection => {
            service.clear_selection()?;
            print_value(&json!({ "selected_case_id": null }), json_output)?;
        }
        CaseCommand::Archive { case_id } => {
            print_value(&service.archive_case(&case_id)?, json_output)?;
        }
        CaseCommand::DeletePlan { case_id } => {
            service.show_case(&case_id)?;
            let plan = service.artifact_deletion_plan(&case_id)?;
            print_value(
                &json!({
                    "database_record": case_id,
                    "artifacts": plan,
                    "deleted": false,
                }),
                json_output,
            )?;
        }
        CaseCommand::Delete {
            case_id,
            confirm_case_id,
        } => {
            if confirm_case_id != case_id {
                return Err(AppError::NotAuthorized(
                    "--confirm-case-id must exactly match the case being deleted".into(),
                ));
            }
            let result = service.delete_case(&case_id)?;
            print_value(
                &json!({
                    "result": result,
                    "artifact_action": "retained",
                }),
                json_output,
            )?;
        }
        CaseCommand::DeleteArtifacts {
            case_id,
            exact_path,
            confirmation,
        } => {
            let result = service.delete_case_artifacts(&case_id, &exact_path, &confirmation)?;
            print_value(
                &json!({
                    "result": result,
                    "recoverable": false,
                }),
                json_output,
            )?;
        }
        CaseCommand::Events { case_id } => {
            service.show_case(&case_id)?;
            print_value(&storage.list_case_events(&case_id)?, json_output)?;
        }
        CaseCommand::SeedDemo => {
            let case = if let Some(summary) = storage
                .list_cases()?
                .into_iter()
                .find(|summary| summary.is_demo)
            {
                storage.get_case(&summary.id)?
            } else {
                let mut case = build_demo_case();
                storage.save_case(&mut case, "case.demo_seeded.cli")?;
                case
            };
            storage.set_selected_case(Some(&case.id))?;
            print_value(&case, json_output)?;
        }
    }
    Ok(())
}

fn execute_source(
    command: SourceCommand,
    storage: &Storage,
    service: &CaseService<'_>,
    artifact_root: &Path,
    json_output: bool,
) -> AppResult<()> {
    match command {
        SourceCommand::List { case_id } => {
            print_value(&service.show_case(&case_id)?.data_sources, json_output)?;
        }
        SourceCommand::Upsert(args) => {
            if let Some(source_id) = args.source_id.as_deref() {
                let case = service.show_case(&args.case_id)?;
                let source = case
                    .data_sources
                    .iter()
                    .find(|source| source.id == source_id)
                    .ok_or_else(|| {
                        AppError::InvalidRequest(format!("data source not found: {source_id}"))
                    })?;
                if !source.metadata.is_empty() {
                    return Err(AppError::NotAvailable(
                        "CLI source updates are disabled once backend-owned artifact coordinates exist; this prevents accidental loss of preserved discovery provenance"
                            .into(),
                    ));
                }
            }
            let source = service.upsert_source(
                &args.case_id,
                SourceMutation {
                    id: args.source_id,
                    kind: args.kind.into(),
                    label: args.label,
                    status: args.status.into(),
                    read_only: args.read_only,
                    metadata: BTreeMap::new(),
                },
            )?;
            print_value(&source, json_output)?;
        }
        SourceCommand::Discover { case_id, source_id } => {
            let case = service.show_case(&case_id)?;
            let source = case
                .data_sources
                .iter()
                .find(|source| source.id == source_id)
                .ok_or_else(|| {
                    AppError::InvalidRequest(format!("data source not found: {source_id}"))
                })?;
            let connector_root = case_connector_artifact_root(artifact_root, &case_id)?;
            let registry = SnapshotConnectorRegistry::new(connector_root)
                .map_err(|error| AppError::InvalidRequest(error.to_string()))?;
            let connector = registry.connector_for(&source.kind);
            let batch = run_connector(&connector, source)
                .map_err(|error| AppError::InvalidRequest(error.to_string()))?;
            let report = service.reconcile_discovery_batch(&case_id, &batch)?;
            print_value(
                &json!({
                    "report": report,
                    "live_discovery": false,
                    "discovery_source": "preserved_evidence",
                    "credentials_used": false,
                    "network_contacted": false,
                    "scope_granted": false,
                }),
                json_output,
            )?;
        }
        SourceCommand::DiscoverFromArtifact(args) => {
            let mut case = service.show_case(&args.case_id)?;
            if case.is_demo {
                return Err(AppError::NotAuthorized(
                    "synthetic demo cases are immutable and cannot ingest source artifacts".into(),
                ));
            }
            if case.status == CaseStatus::Archived {
                return Err(AppError::InvalidRequest(
                    "archived cases cannot ingest source artifacts".into(),
                ));
            }
            let source = case
                .data_sources
                .iter_mut()
                .find(|source| source.id == args.source_id)
                .ok_or_else(|| {
                    AppError::InvalidRequest(format!("data source not found: {}", args.source_id))
                })?;
            if source.status != SourceConnectionStatus::Connected || !source.read_only {
                return Err(AppError::NotAuthorized(
                    "snapshot discovery requires a connected source explicitly recorded as read-only"
                        .into(),
                ));
            }
            let connector_root = case_connector_artifact_root(artifact_root, &args.case_id)?;
            let registry = SnapshotConnectorRegistry::new(connector_root)
                .map_err(|error| AppError::InvalidRequest(error.to_string()))?;
            let observed_at = args
                .observed_at
                .as_deref()
                .map(parse_rfc3339)
                .transpose()?
                .unwrap_or_else(Utc::now);
            let reference = registry
                .ingest_selected_snapshot(&source.kind, &args.snapshot, &args.profile, observed_at)
                .map_err(|error| AppError::InvalidRequest(error.to_string()))?;
            reference
                .clone()
                .insert_into(source)
                .map_err(|error| AppError::InvalidRequest(error.to_string()))?;
            case.touch();
            storage.save_case(&mut case, "source.snapshot_ingested.cli")?;

            let source = case
                .data_sources
                .iter()
                .find(|source| source.id == args.source_id)
                .ok_or_else(|| AppError::Internal("ingested source disappeared".into()))?;
            let connector = registry.connector_for(&source.kind);
            let batch = run_connector(&connector, source)
                .map_err(|error| AppError::InvalidRequest(error.to_string()))?;
            let report = service.reconcile_discovery_batch(&args.case_id, &batch)?;
            print_value(
                &json!({
                    "artifact": reference,
                    "report": report,
                    "live_discovery": false,
                    "storage": "private_backend_copy",
                    "credentials_used": false,
                    "network_contacted": false,
                    "contents_emitted": false,
                    "scope_granted": false,
                }),
                json_output,
            )?;
        }
        SourceCommand::AttachWorkspace(args) => {
            let source_id = new_id();
            let output = attach_workspace_source(
                service,
                artifact_root,
                &args.case_id,
                &source_id,
                &args.label,
                &args.path,
                args.profile.into(),
            )?;
            print_value(&output, json_output)?;
        }
        SourceCommand::RefreshWorkspace(args) => {
            let output = refresh_workspace_source(
                service,
                artifact_root,
                &args.case_id,
                &args.asset_id,
                &args.path,
            )?;
            print_value(&output, json_output)?;
        }
        SourceCommand::Connectors => {
            // Listing static connector descriptors never ingests or reads an
            // artifact, so it does not need to create a synthetic case root.
            let registry = SnapshotConnectorRegistry::new(artifact_root)
                .map_err(|error| AppError::InvalidRequest(error.to_string()))?;
            let descriptors = registry
                .descriptors()
                .into_iter()
                .map(|descriptor| {
                    json!({
                        "connector_id": descriptor.connector_id,
                        "source_kind": descriptor.source_kind,
                        "parser_profiles": descriptor.parser_profiles,
                        "live_discovery": descriptor.live_discovery,
                    })
                })
                .collect::<Vec<_>>();
            print_value(&descriptors, json_output)?;
        }
    }
    Ok(())
}

fn attach_workspace_source(
    service: &CaseService<'_>,
    artifact_root: &Path,
    case_id: &str,
    source_id: &str,
    label: &str,
    selected_path: &Path,
    input_profile: WorkspaceInputProfile,
) -> AppResult<Value> {
    if !selected_path.is_absolute() {
        return Err(AppError::InvalidRequest(
            "the working-tree selection must be an explicit absolute directory".into(),
        ));
    }
    let case = service.show_case(case_id)?;
    if case.is_demo || case.status == CaseStatus::Archived {
        return Err(AppError::NotAuthorized(
            "demo or archived cases cannot attach working-tree snapshots".into(),
        ));
    }
    let snapshot = create_workspace_snapshot_with_profile(
        artifact_root,
        case_id,
        source_id,
        selected_path,
        input_profile,
        WorkspaceSnapshotLimits::default(),
    )?;
    let snapshot_sha256 = snapshot.reference.sha256.clone();
    let asset_id = snapshot.asset.id.clone();
    let asset_kind = snapshot.asset.kind.clone();
    let resolved_selected_path = selected_path.canonicalize().map_err(|error| {
        AppError::InvalidRequest(format!(
            "selected working-tree directory could not be resolved for output: {error}"
        ))
    })?;
    // Re-resolve through the persisted reference before it enters the case.
    // This exercises the same no-symlink/hash boundary used by execution.
    resolve_workspace_snapshot(artifact_root, case_id, &snapshot.reference)?;
    service.attach_workspace_snapshot(case_id, label, snapshot)?;

    Ok(json!({
        "label": label,
        "path": resolved_selected_path,
        "profile": input_profile,
        "source_id": source_id,
        "asset_id": asset_id,
        "asset_kind": asset_kind,
        "snapshot_sha256": snapshot_sha256,
    }))
}

fn refresh_workspace_source(
    service: &CaseService<'_>,
    artifact_root: &Path,
    case_id: &str,
    asset_id: &str,
    selected_path: &Path,
) -> AppResult<Value> {
    if !selected_path.is_absolute() {
        return Err(AppError::InvalidRequest(
            "the working-tree selection must be an explicit absolute directory".into(),
        ));
    }
    let case = service.show_case(case_id)?;
    if case.is_demo || case.status == CaseStatus::Archived {
        return Err(AppError::NotAuthorized(
            "demo or archived cases cannot refresh working-tree snapshots".into(),
        ));
    }
    let (source_id, profile) = service.workspace_refresh_target(case_id, asset_id)?;
    let snapshot = create_workspace_snapshot_with_profile(
        artifact_root,
        case_id,
        &source_id,
        selected_path,
        profile,
        WorkspaceSnapshotLimits::default(),
    )?;
    let snapshot_sha256 = snapshot.reference.sha256.clone();
    let resolved_selected_path = selected_path.canonicalize().map_err(|error| {
        AppError::InvalidRequest(format!(
            "selected working-tree directory could not be resolved for output: {error}"
        ))
    })?;
    // Re-resolve through the persisted reference before it enters the case.
    // This exercises the same no-symlink/hash boundary used by execution.
    resolve_workspace_snapshot(artifact_root, case_id, &snapshot.reference)?;
    let updated = service.refresh_workspace_snapshot(case_id, asset_id, snapshot)?;
    let asset = updated
        .assets
        .iter()
        .find(|asset| asset.id == asset_id)
        .ok_or_else(|| AppError::Internal("refreshed workspace asset disappeared".into()))?;
    let previous_sha256 = asset
        .metadata
        .get("workspace_snapshot_previous_sha256")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            AppError::Internal("refreshed workspace asset has no previous snapshot hash".into())
        })?;
    let change = asset
        .metadata
        .get("workspace_snapshot_change")
        .cloned()
        .unwrap_or(Value::Null);
    Ok(json!({
        "asset_id": asset_id,
        "path": resolved_selected_path,
        "previous_sha256": previous_sha256,
        "snapshot_sha256": snapshot_sha256,
        "change": change,
    }))
}

fn execute_scope(
    command: ScopeCommand,
    service: &CaseService<'_>,
    json_output: bool,
) -> AppResult<()> {
    match command {
        ScopeCommand::List { case_id } => {
            let case = service.show_case(&case_id)?;
            print_value(
                &json!({
                    "case_id": case.id,
                    "scope_grants": case.scope_grants,
                    "coverage": case.coverage,
                }),
                json_output,
            )?;
        }
        ScopeCommand::Approve(args) => {
            let requires_external_scope = args
                .permission
                .iter()
                .any(|permission| permission.is_external());
            let external_scope = match args.external_scope.as_deref() {
                Some(path) => Some(read_external_scope_document(path)?),
                None if requires_external_scope => {
                    return Err(AppError::InvalidRequest(
                        "an external permission requires an explicit scope document selected with --external-scope"
                            .into(),
                    ));
                }
                None => None,
            };
            let expires_at = args.expires_at.as_deref().map(parse_rfc3339).transpose()?;
            let grants = service.approve_scope(
                &args.case_id,
                ScopeApprovalRequest {
                    asset_id: args.asset_id,
                    permissions: args.permission.into_iter().map(Into::into).collect(),
                    confirmed_by: args.confirmed_by,
                    expires_at,
                    authorization_reference: args.authorization_reference,
                    notes: args.notes,
                    external_scope,
                },
            )?;
            print_value(&scope_approval_output(grants), json_output)?;
        }
    }
    Ok(())
}

fn scope_approval_output(grants: Vec<ScopeGrant>) -> Value {
    json!({
        "grants": grants,
        "authorization_source": "explicit",
    })
}

fn execute_finding(
    command: FindingCommand,
    service: &CaseService<'_>,
    json_output: bool,
) -> AppResult<()> {
    match command {
        FindingCommand::History { case_id } => {
            let case = service.show_case(&case_id)?;
            print_value(&case.finding_workflow_events, json_output)?;
        }
        FindingCommand::Groups { case_id } => {
            let case = service.show_case(&case_id)?;
            print_value(
                &json!({
                    "active": case.finding_groups,
                    "history": case.finding_group_events,
                    "group_effect": "presentation_only",
                    "canonical_records_changed": false,
                }),
                json_output,
            )?;
        }
        FindingCommand::Correlations { case_id } => {
            let case = service.show_case(&case_id)?;
            let report = correlation_report(&case);
            print_value(
                &json!({
                    "keyVersion": report.key_version,
                    "suggestions": report.suggestions,
                    "unverifiable": report.unverifiable,
                    "truncatedSuggestions": report.truncated_suggestions,
                    "applied": false,
                }),
                json_output,
            )?;
        }
        FindingCommand::Group(args) => {
            let case = service.group_findings(
                &args.case_id,
                FindingGroupRequest {
                    title: args.title,
                    finding_ids: args.finding_id,
                    rationale: args.rationale,
                    grouped_by: args.grouped_by,
                },
            )?;
            print_value(&case, json_output)?;
        }
        FindingCommand::Ungroup(args) => {
            let case = service.ungroup_findings(
                &args.case_id,
                FindingUngroupRequest {
                    group_id: args.group_id,
                    removed_by: args.removed_by,
                    reason: args.reason,
                },
            )?;
            print_value(&case, json_output)?;
        }
        FindingCommand::Update(args) => {
            let expires_at = args.expires_at.as_deref().map(parse_rfc3339).transpose()?;
            let case = service.update_finding_workflow(
                &args.case_id,
                FindingWorkflowRequest {
                    finding_id: args.finding_id,
                    status: args.status.into(),
                    decided_by: args.decided_by,
                    reason: args.reason,
                    expires_at,
                },
            )?;
            print_value(&case, json_output)?;
        }
    }
    Ok(())
}

fn execute_scan(
    command: ScanCommand,
    service: &CaseService<'_>,
    json_output: bool,
) -> AppResult<()> {
    match command {
        ScanCommand::Plan(args) => {
            let plan = service.plan_scan(
                &args.case_id,
                ScanPlanRequest {
                    campaign_id: args.campaign,
                    engine_ids: args.engine,
                    engine_asset_routes: Vec::new(),
                },
            )?;
            print_value(
                &json!({
                    "plan": plan,
                    "execution_state": "not_started",
                }),
                json_output,
            )?;
        }
        ScanCommand::Start(args) => {
            return Err(out_of_process_scan_control_error(
                "start",
                &args.case_id,
                &args.run_id,
            ));
        }
        ScanCommand::RescanPlan(args) => {
            let plan = service.plan_rescan(
                &args.case_id,
                &args.baseline_run_id,
                ScanPlanRequest {
                    campaign_id: args.campaign,
                    engine_ids: args.engine,
                    engine_asset_routes: Vec::new(),
                },
            )?;
            print_value(
                &json!({
                    "rescan": plan,
                    "execution_state": "not_started",
                }),
                json_output,
            )?;
        }
        ScanCommand::Status(args) => {
            let case = service.show_case(&args.case_id)?;
            let runs = match args.run_id.as_deref() {
                Some(run_id) => vec![
                    case.scan_runs
                        .iter()
                        .find(|run| run.id == run_id)
                        .cloned()
                        .ok_or_else(|| {
                            AppError::InvalidRequest(format!("scan run not found: {run_id}"))
                        })?,
                ],
                None => case.scan_runs.clone(),
            };
            print_value(
                &json!({
                    "case_id": case.id,
                    "case_status": case.status,
                    "runs": runs,
                    "coverage": case.coverage,
                }),
                json_output,
            )?;
        }
        ScanCommand::Pause(args) => {
            return Err(out_of_process_scan_control_error(
                "pause",
                &args.case_id,
                &args.run_id,
            ));
        }
        ScanCommand::Resume(args) => {
            return Err(out_of_process_scan_control_error(
                "resume",
                &args.case_id,
                &args.run_id,
            ));
        }
        ScanCommand::Cancel(args) => {
            let case = cancel_never_started_scan(service, &args.case_id, &args.run_id)?;
            print_value(&case, json_output)?;
        }
    }
    Ok(())
}

fn cancel_never_started_scan(
    service: &CaseService<'_>,
    case_id: &str,
    run_id: &str,
) -> AppResult<ai_security_scanner_lib::domain::AssessmentCase> {
    let case = service.show_case(case_id)?;
    let run = case
        .scan_runs
        .iter()
        .find(|run| run.id == run_id)
        .ok_or_else(|| AppError::InvalidRequest(format!("scan run not found: {run_id}")))?;
    if run
        .engine_runs
        .iter()
        .any(|engine_run| engine_run_status_has_live_work(&engine_run.status))
    {
        return Err(out_of_process_scan_control_error("cancel", case_id, run_id));
    }
    if run
        .engine_runs
        .iter()
        .any(|engine_run| engine_run_status_has_outcome(&engine_run.status))
    {
        let observed_statuses = run
            .engine_runs
            .iter()
            .map(|engine_run| engine_run_status_name(&engine_run.status))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>()
            .join(", ");
        return Err(scan_cancel_outcome_error(
            case_id,
            run_id,
            &observed_statuses,
        ));
    }
    if let Some(engine_run) = run.engine_runs.iter().find(|engine_run| {
        engine_run.started_at.is_some()
            && !(engine_run.status == EngineRunStatus::Queued
                && engine_run.phase == "queued_for_resume")
    }) {
        return Err(never_started_scan_cancel_declined_error(
            case_id,
            run_id,
            &format!(
                "engine run {} has status {} and a recorded started_at value",
                engine_run.id,
                engine_run_status_name(&engine_run.status)
            ),
        ));
    }
    service.cancel_scan(case_id, run_id)
}

fn engine_run_status_has_live_work(status: &EngineRunStatus) -> bool {
    match status {
        EngineRunStatus::Preparing | EngineRunStatus::Running | EngineRunStatus::Paused => true,
        EngineRunStatus::NotExecuted
        | EngineRunStatus::Queued
        | EngineRunStatus::Completed
        | EngineRunStatus::PartiallyCompleted
        | EngineRunStatus::Failed
        | EngineRunStatus::Cancelled => false,
    }
}

fn engine_run_status_has_outcome(status: &EngineRunStatus) -> bool {
    match status {
        EngineRunStatus::Completed
        | EngineRunStatus::PartiallyCompleted
        | EngineRunStatus::Failed
        | EngineRunStatus::Cancelled => true,
        EngineRunStatus::NotExecuted
        | EngineRunStatus::Queued
        | EngineRunStatus::Preparing
        | EngineRunStatus::Running
        | EngineRunStatus::Paused => false,
    }
}

fn engine_run_status_name(status: &EngineRunStatus) -> &'static str {
    match status {
        EngineRunStatus::NotExecuted => "not_executed",
        EngineRunStatus::Queued => "queued",
        EngineRunStatus::Preparing => "preparing",
        EngineRunStatus::Running => "running",
        EngineRunStatus::Paused => "paused",
        EngineRunStatus::Completed => "completed",
        EngineRunStatus::PartiallyCompleted => "partially_completed",
        EngineRunStatus::Failed => "failed",
        EngineRunStatus::Cancelled => "cancelled",
    }
}

fn never_started_scan_cancel_declined_error(
    case_id: &str,
    run_id: &str,
    observed: &str,
) -> AppError {
    AppError::NotAvailable(format!(
        "scan cancel declined for case {case_id} run {run_id}: {observed}; CLI cancellation requires every engine run to be queued or not_executed with no live status or recorded outcome; a recorded start is accepted only for queued_for_resume work from an ended attempt"
    ))
}

fn scan_cancel_outcome_error(case_id: &str, run_id: &str, observed_statuses: &str) -> AppError {
    AppError::NotAvailable(format!(
        "scan cancel declined for case {case_id} run {run_id}: the run already reached an outcome; observed engine run statuses: {observed_statuses}"
    ))
}

fn out_of_process_scan_control_error(action: &str, case_id: &str, run_id: &str) -> AppError {
    AppError::NotAvailable(format!(
        "scan {action} unavailable in CLI for case {case_id} run {run_id}; use the desktop scan controls"
    ))
}

fn execute_export(
    command: ExportCommand,
    service: &CaseService<'_>,
    json_output: bool,
) -> AppResult<()> {
    match command {
        ExportCommand::Combine(args) => {
            use ai_security_scanner_lib::selected_run_report::{
                SelectedRunReportFormat, export_selected_run_report,
            };
            let case = service.show_case(&args.case_id)?;
            let format = match args.format {
                CombinedExportFormatArg::Html => SelectedRunReportFormat::Html,
                CombinedExportFormatArg::Json => SelectedRunReportFormat::Json,
            };
            let receipt = export_selected_run_report(
                &case,
                &args.run_id,
                format,
                &args.destination,
                &ExportOptions {
                    redaction: args.redaction.into(),
                    include_raw_artifacts: false,
                    locale: args.locale.into(),
                },
            )?;
            print_value(&receipt, json_output)?;
        }
        ExportCommand::Create(args) => {
            if args.include_raw_artifacts
                && !matches!(
                    args.format,
                    ExportFormatArg::CaseBundle | ExportFormatArg::Html
                )
            {
                return Err(AppError::InvalidRequest(
                    "original files can only be included in HTML reports or signed case bundles"
                        .into(),
                ));
            }
            let export = service.export_case(
                &args.case_id,
                &args.run_id,
                args.format.into(),
                &args.destination,
                ExportOptions {
                    redaction: args.redaction.into(),
                    include_raw_artifacts: args.include_raw_artifacts,
                    locale: args.locale.into(),
                },
            )?;
            print_value(&export, json_output)?;
        }
        ExportCommand::Verify {
            case_id,
            export_id,
            path,
        } => match (case_id, export_id, path) {
            (Some(case_id), Some(export_id), None) => print_value(
                &service.verify_stored_export(&case_id, &export_id)?,
                json_output,
            )?,
            (None, None, Some(path)) => print_value(&verify_case_bundle(path)?, json_output)?,
            _ => {
                return Err(AppError::InvalidRequest(
                    "export verify requires either --path or both --case-id and --export-id".into(),
                ));
            }
        },
        ExportCommand::Identity { command } => match command {
            ExportIdentityCommand::Show => {
                print_value(&service.ensure_export_signing_identity()?, json_output)?;
            }
            ExportIdentityCommand::RotateAfterKeyLoss {
                acknowledge_lost_key_id,
            } => {
                print_value(
                    &service.rotate_export_signing_identity_after_confirmed_loss(
                        &acknowledge_lost_key_id,
                    )?,
                    json_output,
                )?;
            }
        },
        ExportCommand::Formats => print_value(
            &json!([
                { "id": "case-bundle", "signed": true, "portable": true },
                { "id": "json", "signed": false, "schema": "canonical" },
                { "id": "framework-report", "signed": false, "schema": "master NIST CSF, ISO/IEC 27001, and AIDEFEND relationship report with incomplete and unknown coverage" },
                { "id": "ocsf", "signed": false, "schema": "OCSF detection findings" },
                { "id": "oscal", "signed": false, "schema": "OSCAL assessment results; coordinates only" },
                { "id": "html", "signed": false, "schema": "local human-readable report" }
            ]),
            json_output,
        )?,
    }
    Ok(())
}

fn execute_engine(
    command: EngineCommand,
    engines: &EngineRegistry,
    adapters: &ai_security_scanner_lib::adapter::AdapterRegistry,
    release_approved_local_image_directory: Option<&Path>,
    json_output: bool,
) -> AppResult<()> {
    match command {
        EngineCommand::List => {
            let values = engines
                .manifests()
                .iter()
                .map(|manifest| engine_inspection(manifest, adapters))
                .collect::<Vec<_>>();
            print_value(&values, json_output)?;
        }
        EngineCommand::Show { engine_id } | EngineCommand::Inspect { engine_id } => {
            let manifest = engine(engines, &engine_id)?;
            print_value(&engine_inspection(manifest, adapters), json_output)?;
        }
        EngineCommand::Install { engine_id } => {
            let manifest = engine(engines, &engine_id)?;
            if let Some(blocker) = manifest.release_blocker() {
                return Err(AppError::NotAvailable(format!(
                    "engine {engine_id} is not release-approved: {blocker}; no image was retrieved"
                )));
            }
            if matches!(
                manifest.distribution_mode,
                DistributionMode::ExternalExecutable
            ) {
                return Err(AppError::NotAvailable(format!(
                    "engine {engine_id} is configured as an external executable; the constrained CLI only retrieves pinned container images"
                )));
            }
            let image = PinnedImage::from_manifest(manifest)?;
            let runtime = ProcessContainerRuntime::detect()?
                .with_release_approved_local_image_directory(
                    release_approved_local_image_directory.map(Path::to_path_buf),
                );
            let preflight = runtime.preflight()?;
            runtime.pull(&image)?;
            print_value(
                &json!({
                    "engine_id": engine_id,
                    "image": image.reference(),
                    "runtime": preflight,
                    "retrieved": true,
                    "verification": "immutable sha256 digest",
                }),
                json_output,
            )?;
        }
    }
    Ok(())
}

async fn execute_runtime(
    command: RuntimeCommand,
    service: &CaseService<'_>,
    engines: &EngineRegistry,
    data_dir: &Path,
    artifact_root: &Path,
    source_overrides: RuntimeSourceOverrides<'_>,
    json_output: bool,
) -> AppResult<()> {
    match command {
        RuntimeCommand::Managed { command } => {
            execute_managed_runtime_cli_command(
                data_dir,
                artifact_root,
                source_overrides.managed_runtime_bundle,
                source_overrides.release_approved_local_image_directory,
                command,
                json_output,
            )
            .await?;
        }
        RuntimeCommand::Inspect(args) => {
            let cases = service.list_cases()?;
            let cleanup = inspect_cleanup(
                &cases,
                service,
                args.case_id.as_deref(),
                args.run_id.as_deref(),
            )?;
            let managed_runtime =
                inspect_managed_runtime(data_dir, source_overrides.managed_runtime_bundle).await;
            let compatibility_runtime = detect_runtime().await;
            print_value(
                &json!({
                    "runtime": {
                        "preferred_provider": "managed_local",
                        "managed_local": managed_runtime,
                        "compatibility": compatibility_runtime,
                    },
                    "cleanup": cleanup,
                    "artifact_root_policy": "case-scoped paths are reported; this command does not traverse or delete them",
                    "credential_capabilities": "ephemeral in-memory only; no credential values are persisted or shown",
                    "provider_identity_cleanup": "unknown unless separately recorded by the bootstrap workflow",
                    "engine_catalog_count": engines.manifests().len(),
                }),
                json_output,
            )?;
        }
        RuntimeCommand::CleanupPlan { case_id, run_id } => {
            let summaries = service.list_cases()?;
            let cleanup = inspect_cleanup(&summaries, service, Some(&case_id), Some(&run_id))?;
            print_value(
                &json!({
                    "case_id": case_id,
                    "run_id": run_id,
                    "cleanup": cleanup,
                    "action": "No cleanup was performed.",
                }),
                json_output,
            )?;
        }
        RuntimeCommand::Cleanup {
            case_id,
            run_id,
            confirm_run_id,
        } => {
            if confirm_run_id != run_id {
                return Err(AppError::NotAuthorized(
                    "--confirm-run-id must exactly match the run being cleaned".into(),
                ));
            }
            let summaries = service.list_cases()?;
            let inspection = inspect_cleanup(&summaries, service, Some(&case_id), Some(&run_id))?;
            if !inspection.invalid_checkpoint_records.is_empty() {
                return Err(AppError::NotAuthorized(
                    "cleanup refused because this run contains an invalid stored checkpoint".into(),
                ));
            }
            if inspection.pending.is_empty() {
                print_value(
                    &json!({
                        "case_id": case_id,
                        "run_id": run_id,
                        "results": [],
                        "remaining_obligations": 0,
                        "cleanup_state": "complete",
                    }),
                    json_output,
                )?;
                return Ok(());
            }

            let mut results = Vec::new();
            for obligation in inspection.pending {
                let container_name = obligation.container_name.clone();
                let case = service.show_case(&case_id)?;
                let engine_run = case
                    .scan_runs
                    .iter()
                    .find(|run| run.id == run_id)
                    .and_then(|run| {
                        run.engine_runs
                            .iter()
                            .find(|engine_run| engine_run.id == obligation.engine_run_id)
                    })
                    .ok_or_else(|| {
                        AppError::InvalidRequest(
                            "cleanup checkpoint disappeared before execution".into(),
                        )
                    })?;
                let token = engine_run.resume_token.as_deref().ok_or_else(|| {
                    AppError::InvalidRequest("cleanup checkpoint has no resume token".into())
                })?;
                let mut checkpoint = ExecutionCheckpoint::from_resume_token(token)?;
                let scope_sha256 = checkpoint.scope_sha256.clone().ok_or_else(|| {
                    AppError::InvalidRequest("cleanup checkpoint has no frozen scope digest".into())
                })?;
                let image = PinnedImage::new(
                    engine_run.image_repository.as_deref().ok_or_else(|| {
                        AppError::InvalidRequest(
                            "cleanup engine run has no pinned image repository".into(),
                        )
                    })?,
                    engine_run.image_digest.as_deref().ok_or_else(|| {
                        AppError::InvalidRequest("cleanup engine run has no image digest".into())
                    })?,
                )?;
                let owned_container = OwnedContainerCleanupRequest {
                    case_id: case_id.clone(),
                    scan_run_id: run_id.clone(),
                    engine_run_id: engine_run.id.clone(),
                    engine_id: engine_run.engine_id.clone(),
                    attempt: checkpoint.attempt,
                    scope_sha256,
                    launcher_plan_sha256: checkpoint.launcher_plan_sha256.clone(),
                    zap_plan_sha256: None,
                    image,
                };
                if let Some(name) = container_name.as_deref()
                    && owned_container.container_name()? != name
                {
                    return Err(AppError::NotAuthorized(
                        "cleanup obligation container name does not match its execution identity"
                            .into(),
                    ));
                }
                let raw_artifacts = checkpoint
                    .artifact_ids
                    .iter()
                    .map(|artifact_id| {
                        case.raw_artifacts
                            .iter()
                            .find(|artifact| artifact.id == *artifact_id)
                            .cloned()
                            .ok_or_else(|| {
                                AppError::Runtime(format!(
                                    "cleanup checkpoint references missing artifact {artifact_id}"
                                ))
                            })
                    })
                    .collect::<AppResult<Vec<_>>>()?;
                let cleanup_data_dir = data_dir.to_path_buf();
                let cleanup_artifact_root = artifact_root.to_path_buf();
                let cleanup_provider = engine_run.runtime_provider.clone();
                let cleanup_checkpoint = checkpoint.clone();
                let cleanup_container_name = container_name.clone();
                let attempt = match tokio::task::spawn_blocking(move || {
                    perform_exact_runtime_cleanup(
                        &cleanup_data_dir,
                        &cleanup_artifact_root,
                        cleanup_provider.as_deref(),
                        &cleanup_checkpoint,
                        &owned_container,
                        cleanup_container_name.as_deref(),
                    )
                })
                .await
                {
                    Ok(attempt) => attempt,
                    Err(error) => {
                        results.push(json!({
                            "engine_run_id": obligation.engine_run_id,
                            "container_name": container_name,
                            "container_cleanup_completed": false,
                            "managed_network_cleanup_completed": false,
                            "record_updated": false,
                            "obligation_retained": true,
                            "error": format!("exact cleanup worker did not complete: {error}"),
                        }));
                        continue;
                    }
                };
                let ExactRuntimeCleanup {
                    container: container_cleanup,
                    managed_network: managed_cleanup,
                    orphan_credentials_removed,
                } = match attempt {
                    Ok(outcome) => outcome,
                    Err(failure) => {
                        results.push(json!({
                            "engine_run_id": obligation.engine_run_id,
                            "container_name": container_name,
                            "container_cleanup_completed": failure.container.is_some(),
                            "container_removed": failure.container.as_ref().map(|outcome| outcome.removed),
                            "container_detail": failure.container.as_ref().map(|outcome| outcome.detail.as_str()),
                            "managed_network_cleanup_completed": false,
                            "record_updated": false,
                            "obligation_retained": true,
                            "error": failure.error.to_string(),
                        }));
                        continue;
                    }
                };

                checkpoint.managed_network = None;
                checkpoint.cleanup_completed = true;
                checkpoint.stage = ExecutionStage::Failed;
                checkpoint.last_error = Some(
                    "exact container and managed-network cleanup completed; execution may be retried"
                        .into(),
                );
                let cleanup_detail = match managed_cleanup.as_ref() {
                    Some(managed) => format!(
                        "{}; managed egress: {}",
                        container_cleanup.detail, managed.detail
                    ),
                    None => container_cleanup.detail.clone(),
                }
                .chars()
                .take(4_000)
                .collect();
                let gateway_refusals = managed_cleanup
                    .as_ref()
                    .and_then(|outcome| outcome.gateway_refusals);
                let durable = DurableExecutionReport {
                    checkpoint,
                    runtime_preflight: None,
                    cleanup: Some(ai_security_scanner_lib::container_runtime::CleanupOutcome {
                        removed: container_cleanup.removed
                            && managed_cleanup.as_ref().is_none_or(|outcome| outcome.removed),
                        detail: cleanup_detail,
                        gateway_refusals,
                    }),
                    exit_code: None,
                    raw_artifacts,
                    findings: Vec::new(),
                    observations: Vec::new(),
                    warnings: vec![
                        "A prior exact runtime cleanup obligation was resolved without executing a scanner."
                            .into(),
                    ],
                    unattributed: Vec::new(),
                    unevaluated_targets: Vec::new(),
                    security_template_executions: Vec::new(),
                    manual_review_controls: Vec::new(),
                };
                match service.apply_execution_report(&case_id, &durable) {
                    Ok(_) => results.push(json!({
                        "engine_run_id": obligation.engine_run_id,
                        "container_name": container_name,
                        "container_cleanup_completed": true,
                        "container_removed": container_cleanup.removed,
                        "container_detail": container_cleanup.detail,
                        "managed_network_cleanup_completed": true,
                        "managed_network_removed": managed_cleanup.as_ref().map(|outcome| outcome.removed),
                        "managed_network_detail": managed_cleanup.as_ref().map(|outcome| outcome.detail.as_str()),
                        "orphan_credentials_removed": orphan_credentials_removed,
                        "record_updated": true,
                        "obligation_retained": false,
                    })),
                    Err(error) => results.push(json!({
                        "engine_run_id": obligation.engine_run_id,
                        "container_name": container_name,
                        "container_cleanup_completed": true,
                        "container_removed": container_cleanup.removed,
                        "container_detail": container_cleanup.detail,
                        "managed_network_cleanup_completed": true,
                        "managed_network_removed": managed_cleanup.as_ref().map(|outcome| outcome.removed),
                        "managed_network_detail": managed_cleanup.as_ref().map(|outcome| outcome.detail.as_str()),
                        "record_updated": false,
                        "obligation_retained": true,
                        "error": error.to_string(),
                    })),
                }
            }
            let remaining = inspect_cleanup(
                &service.list_cases()?,
                service,
                Some(&case_id),
                Some(&run_id),
            )?;
            print_value(
                &json!({
                    "case_id": case_id,
                    "run_id": run_id,
                    "results": results,
                    "remaining_obligations": remaining.pending.len(),
                    "invalid_checkpoint_records": remaining.invalid_checkpoint_records,
                }),
                json_output,
            )?;
        }
    }
    Ok(())
}

async fn execute_managed_runtime_cli_command(
    data_dir: &Path,
    artifact_root: &Path,
    managed_runtime_bundle: Option<&Path>,
    release_approved_local_image_directory: Option<&Path>,
    command: ManagedRuntimeCliCommand,
    json_output: bool,
) -> AppResult<()> {
    let data_dir = data_dir.to_path_buf();
    let artifact_root = artifact_root.to_path_buf();
    let bundle = managed_runtime_bundle.map(Path::to_path_buf);
    let local_images = release_approved_local_image_directory.map(Path::to_path_buf);
    let value = tokio::task::spawn_blocking(move || {
        execute_managed_runtime_command(
            &data_dir,
            &artifact_root,
            bundle.as_deref(),
            local_images.as_deref(),
            command,
        )
    })
    .await
    .map_err(|error| {
        AppError::Internal(format!("managed runtime worker join failed: {error}"))
    })??;
    print_value(&value, json_output)
}

fn inspect_cleanup(
    summaries: &[ai_security_scanner_lib::domain::CaseSummary],
    service: &CaseService<'_>,
    case_filter: Option<&str>,
    run_filter: Option<&str>,
) -> AppResult<CleanupInspection> {
    if let Some(case_id) = case_filter {
        service.show_case(case_id)?;
    }

    let mut inspection = CleanupInspection::default();
    for summary in summaries
        .iter()
        .filter(|summary| case_filter.is_none_or(|case_id| summary.id == case_id))
    {
        let case = service.show_case(&summary.id)?;
        for run in case
            .scan_runs
            .iter()
            .filter(|run| run_filter.is_none_or(|run_id| run.id == run_id))
        {
            for engine_run in &run.engine_runs {
                let Some(token) = engine_run.resume_token.as_deref() else {
                    continue;
                };
                let Ok(checkpoint) = ExecutionCheckpoint::from_resume_token(token) else {
                    inspection
                        .invalid_checkpoint_records
                        .push(InvalidCheckpointRecord {
                            case_id: case.id.clone(),
                            scan_run_id: run.id.clone(),
                            engine_run_id: engine_run.id.clone(),
                            explanation: "stored checkpoint failed structural validation",
                        });
                    continue;
                };
                if checkpoint.case_id != case.id
                    || checkpoint.scan_run_id != run.id
                    || checkpoint.engine_run_id != engine_run.id
                    || checkpoint.engine_id != engine_run.engine_id
                {
                    inspection
                        .invalid_checkpoint_records
                        .push(InvalidCheckpointRecord {
                            case_id: case.id.clone(),
                            scan_run_id: run.id.clone(),
                            engine_run_id: engine_run.id.clone(),
                            explanation: "stored checkpoint identity does not match its case record",
                        });
                    continue;
                }
                if !checkpoint.cleanup_completed {
                    if checkpoint.container_name.is_none() && checkpoint.managed_network.is_none() {
                        inspection
                            .invalid_checkpoint_records
                            .push(InvalidCheckpointRecord {
                                case_id: case.id.clone(),
                                scan_run_id: run.id.clone(),
                                engine_run_id: engine_run.id.clone(),
                                explanation: "cleanup obligation has neither a container nor a managed-network identity",
                            });
                        continue;
                    }
                    inspection.pending.push(CleanupObligation {
                        case_id: case.id.clone(),
                        scan_run_id: run.id.clone(),
                        engine_run_id: engine_run.id.clone(),
                        engine_id: engine_run.engine_id.clone(),
                        attempt: checkpoint.attempt,
                        container_name: checkpoint.container_name.clone(),
                    });
                }
            }
        }
    }

    if let (Some(case_id), Some(run_id)) = (case_filter, run_filter) {
        let case = service.show_case(case_id)?;
        if !case.scan_runs.iter().any(|run| run.id == run_id) {
            return Err(AppError::InvalidRequest(format!(
                "scan run not found: {run_id}"
            )));
        }
    }
    inspection.pending.sort_by(|left, right| {
        left.case_id
            .cmp(&right.case_id)
            .then_with(|| left.scan_run_id.cmp(&right.scan_run_id))
            .then_with(|| left.engine_run_id.cmp(&right.engine_run_id))
    });
    Ok(inspection)
}

fn engine<'a>(engines: &'a EngineRegistry, engine_id: &str) -> AppResult<&'a EngineManifest> {
    engines
        .get(engine_id)
        .ok_or_else(|| AppError::InvalidRequest(format!("unknown engine: {engine_id}")))
}

fn engine_inspection(
    manifest: &EngineManifest,
    adapters: &ai_security_scanner_lib::adapter::AdapterRegistry,
) -> Value {
    let adapter = adapters.get(&manifest.id);
    let adapter_matches =
        adapter.is_some_and(|adapter| adapter.adapter_version() == manifest.adapter_version);
    let pinned_image = PinnedImage::from_manifest(manifest).ok();
    let release_blocker = manifest.release_blocker();
    let release_approved = release_blocker.is_none();
    let constrained_distribution = !matches!(
        manifest.distribution_mode,
        DistributionMode::ExternalExecutable
    );
    let ready = release_approved
        && adapter_matches
        && pinned_image.is_some()
        && constrained_distribution
        && !manifest.command.is_empty();
    json!({
        "manifest": manifest,
        "readiness": {
            "dispatchable": ready,
            "release_approved": release_approved,
            "adapter_loaded": adapter.is_some(),
            "adapter_version_matches": adapter_matches,
            "pinned_image": pinned_image.as_ref().map(PinnedImage::reference),
            "constrained_distribution": constrained_distribution,
            "compatibility_runnable": manifest.compatibility.runnable,
            "compatibility_blocked_by": manifest.compatibility.blocked_by,
            "not_executed_reason": if ready {
                None
            } else {
                release_blocker.as_deref().or(Some("One or more adapter, immutable-image, distribution, or command requirements are incomplete."))
            },
        }
    })
}

/// Resolves the only connector snapshot root accepted by the CLI for a case.
///
/// Both path components are backend-generated from a strictly bounded case ID,
/// and every existing component must be a real directory. Keeping snapshots
/// below the canonical case artifact root ensures the separately confirmed
/// `CaseService::delete_case_artifacts` operation removes them as part of the
/// same evidence lifecycle.
fn case_connector_artifact_root(artifact_root: &Path, case_id: &str) -> AppResult<PathBuf> {
    if case_id.is_empty()
        || case_id.len() > 128
        || !case_id
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
    {
        return Err(AppError::InvalidRequest(
            "case id is unsafe for connector artifact storage".into(),
        ));
    }

    let metadata = fs::symlink_metadata(artifact_root)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(AppError::NotAuthorized(
            "case artifact root is not a real directory".into(),
        ));
    }
    let canonical_artifact_root = artifact_root.canonicalize()?;
    let case_root = ensure_private_directory_child(&canonical_artifact_root, case_id)?;
    ensure_private_directory_child(&case_root, "connector-snapshots")
}

fn ensure_private_directory_child(parent: &Path, name: &str) -> AppResult<PathBuf> {
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
    restrict_private_directory(&canonical_child)?;
    Ok(canonical_child)
}

#[cfg(unix)]
fn restrict_private_directory(path: &Path) -> AppResult<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
fn restrict_private_directory(_path: &Path) -> AppResult<()> {
    Ok(())
}

fn open_managed_runtime_manager(
    data_dir: &Path,
    bundle_override: Option<&Path>,
) -> AppResult<ManagedRuntimeManager> {
    if let Some(bundle) = bundle_override {
        return ManagedRuntimeManager::open(data_dir, bundle, &bundle.join("manifest.json"));
    }

    let mut bundles = std::collections::BTreeSet::new();
    if let Ok(executable) = std::env::current_exe() {
        for candidate in packaged_managed_runtime_candidates(&executable) {
            if candidate.join("manifest.json").exists() {
                bundles.insert(candidate.canonicalize()?);
            }
        }
    }
    match bundles.len() {
        0 => ManagedRuntimeManager::open_installed(data_dir, None),
        1 => {
            let bundle = bundles.pop_first().expect("one managed runtime bundle");
            ManagedRuntimeManager::open(data_dir, &bundle, &bundle.join("manifest.json"))
        }
        _ => Err(AppError::NotAuthorized(
            "multiple packaged managed-runtime bundles were discovered; select one exact bundle with --managed-runtime-bundle"
                .into(),
        )),
    }
}

#[cfg(feature = "installer-runtime-cache")]
fn installer_runtime_cache_manifest_digest_anchor() -> AppResult<&'static str> {
    let digest = option_env!("AI_SECURITY_SCANNER_MANAGED_RUNTIME_MANIFEST_SHA256")
        .filter(|digest| !digest.is_empty())
        .ok_or_else(|| {
            AppError::NotAvailable(
                "the installed cache coordinator has no managed-runtime build anchor".into(),
            )
        })?;
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(AppError::NotAuthorized(
            "the installed cache coordinator has an invalid managed-runtime build anchor".into(),
        ));
    }
    Ok(digest)
}

/// Opens only the one packaged sibling bundle embedded beside this installed
/// CLI and binds it to the manifest digest compiled into this exact sidecar.
/// Unlike the ordinary maintainer CLI resolver, this path never falls back to
/// an existing private installation when the packaged source is absent.
#[cfg(feature = "installer-runtime-cache")]
fn open_exact_packaged_installer_runtime_cache_source(
    data_dir: &Path,
) -> AppResult<ManagedRuntimeManager> {
    let expected_manifest_sha256 = installer_runtime_cache_manifest_digest_anchor()?;
    let executable = std::env::current_exe().map_err(|_| {
        AppError::NotAvailable("installed cache coordinator executable unresolved".into())
    })?;
    let bundle = exact_packaged_installer_runtime_bundle(&executable)?;
    let manager = ManagedRuntimeManager::open(data_dir, &bundle, &bundle.join("manifest.json"))?;
    if manager.manifest_sha256() != expected_manifest_sha256 {
        return Err(AppError::NotAuthorized(
            "the packaged managed-runtime manifest differs from this installer sidecar build"
                .into(),
        ));
    }
    Ok(manager)
}

#[cfg(feature = "installer-runtime-cache")]
fn exact_packaged_installer_runtime_bundle(executable: &Path) -> AppResult<PathBuf> {
    let executable_directory = executable.parent().ok_or_else(|| {
        AppError::NotAvailable(
            "the installed cache coordinator executable has no package directory".into(),
        )
    })?;
    let directory_metadata = fs::symlink_metadata(executable_directory).map_err(|_| {
        AppError::NotAvailable(
            "the installed cache coordinator package directory is unavailable".into(),
        )
    })?;
    if directory_metadata.file_type().is_symlink() || !directory_metadata.is_dir() {
        return Err(AppError::NotAuthorized(
            "the installed cache coordinator package directory is not a real directory".into(),
        ));
    }
    let canonical_executable_directory = executable_directory.canonicalize()?;
    let packaged_bundle = executable_directory.join("managed-runtime");
    let bundle_metadata = fs::symlink_metadata(&packaged_bundle).map_err(|_| {
        AppError::NotAvailable(
            "the installed cache coordinator packaged source is unavailable".into(),
        )
    })?;
    if bundle_metadata.file_type().is_symlink() || !bundle_metadata.is_dir() {
        return Err(AppError::NotAuthorized(
            "the installed cache coordinator packaged source is not a real directory".into(),
        ));
    }
    let bundle = packaged_bundle.canonicalize()?;
    if bundle != canonical_executable_directory.join("managed-runtime") {
        return Err(AppError::NotAuthorized(
            "the installed cache coordinator packaged source is not the fixed package sibling"
                .into(),
        ));
    }
    Ok(bundle)
}

fn packaged_managed_runtime_candidates(executable: &Path) -> Vec<PathBuf> {
    let Some(parent) = executable.parent() else {
        return Vec::new();
    };
    let candidates = vec![
        parent.join("managed-runtime"),
        parent.join("resources").join("managed-runtime"),
        parent.join("..").join("Resources").join("managed-runtime"),
    ];
    #[cfg(target_os = "linux")]
    let candidates = {
        let mut candidates = candidates;
        if let Some(prefix) = parent.parent() {
            // Tauri's Deb and RPM bundlers install resources below
            // `/usr/lib/<product>`. AppImage reuses the same Debian data tree, so
            // its mounted CLI at `<AppDir>/usr/bin` has this identical relative
            // resource location.
            candidates.push(
                prefix
                    .join("lib")
                    .join("ai-security-scanner")
                    .join("managed-runtime"),
            );
        }
        candidates
    };
    candidates
}

fn execute_managed_runtime_command(
    data_dir: &Path,
    artifact_root: &Path,
    bundle_override: Option<&Path>,
    release_approved_local_image_directory: Option<&Path>,
    command: ManagedRuntimeCliCommand,
) -> AppResult<Value> {
    let manager = open_managed_runtime_manager(data_dir, bundle_override)?;
    let value = match command {
        ManagedRuntimeCliCommand::Status => serde_json::to_value(manager.status()?),
        ManagedRuntimeCliCommand::Install => serde_json::to_value(manager.install()?),
        ManagedRuntimeCliCommand::Start => {
            let _command = manager.start()?;
            serde_json::to_value(manager.status()?)
        }
        ManagedRuntimeCliCommand::Stop { force } => {
            let mode = if force {
                ManagedStopMode::Force
            } else {
                ManagedStopMode::OnlyIfIdle
            };
            serde_json::to_value(manager.stop(mode)?)
        }
        ManagedRuntimeCliCommand::Update => serde_json::to_value(manager.update()?),
        ManagedRuntimeCliCommand::Qualify => {
            return execute_managed_runtime_qualification(
                &manager,
                artifact_root,
                release_approved_local_image_directory,
            );
        }
        ManagedRuntimeCliCommand::QualifyEgress => {
            return execute_managed_egress_gateway_qualification(&manager, artifact_root);
        }
        ManagedRuntimeCliCommand::Uninstall {
            force,
            purge_image_cache,
        } => {
            let stop_mode = if force {
                ManagedStopMode::Force
            } else {
                ManagedStopMode::OnlyIfIdle
            };
            serde_json::to_value(manager.uninstall(ManagedUninstallOptions {
                stop_mode,
                remove_machine_image_cache: purge_image_cache,
            })?)
        }
    };
    value.map_err(|error| {
        AppError::Internal(format!("managed runtime result encoding failed: {error}"))
    })
}

fn execute_managed_runtime_qualification(
    manager: &ManagedRuntimeManager,
    artifact_root: &Path,
    release_approved_local_image_directory: Option<&Path>,
) -> AppResult<Value> {
    let runtime = ProcessContainerRuntime::from_managed(manager.start()?)?
        .with_release_approved_local_image_directory(
            release_approved_local_image_directory.map(Path::to_path_buf),
        );
    let preflight = runtime.preflight()?;
    let engines = EngineRegistry::load_builtin()?;
    let canonical_artifact_root = canonical_private_artifact_root(artifact_root)?;
    execute_fixed_managed_container_qualification(
        &runtime,
        preflight,
        &engines,
        &canonical_artifact_root.join("qualification-artifacts"),
    )
}

fn execute_managed_egress_gateway_qualification(
    manager: &ManagedRuntimeManager,
    artifact_root: &Path,
) -> AppResult<Value> {
    let runtime = ProcessContainerRuntime::from_managed(manager.start()?)?;
    let preflight = runtime.preflight()?;
    if preflight.provider != RuntimeProvider::ManagedLocal
        || !matches!(
            &preflight.command_provenance,
            RuntimeCommandProvenance::ManagedLocal { .. }
        )
    {
        return Err(AppError::NotAuthorized(
            "managed egress qualification requires verified managed-local command provenance"
                .into(),
        ));
    }

    let canonical_artifact_root = canonical_private_artifact_root(artifact_root)?;
    let qualification_case_root = ensure_private_directory_child(&canonical_artifact_root, "q")?;
    let policy_root = ensure_private_directory_child(&qualification_case_root, "network-policies")?;
    let registry_root =
        ensure_private_directory_child(&canonical_artifact_root, ".managed-egress-registry")?;
    let gateway = managed_egress_gateway_spec()?;
    let expected_image = gateway.reference();
    let controller = ManagedNetworkController::new_with_registry_context_and_container(
        runtime.command_context(),
        gateway,
        policy_root,
        registry_root,
    )?;
    let owner = ManagedNetworkOwner::new(
        MANAGED_RUNTIME_QUALIFICATION_CASE_ID,
        MANAGED_RUNTIME_QUALIFICATION_SCAN_RUN_ID,
        new_id(),
        1,
    )?;
    let qualification_id = format!(
        "release_gateway_{}",
        env!("CARGO_PKG_VERSION").replace('.', "_")
    );
    let qualification =
        controller.qualify_gateway_container(&owner, &qualification_id, Utc::now())?;
    managed_egress_gateway_qualification_value(preflight, qualification, &expected_image)
}

fn managed_egress_gateway_qualification_value(
    preflight: RuntimePreflight,
    qualification: ManagedGatewayQualification,
    expected_image: &str,
) -> AppResult<Value> {
    if preflight.provider != RuntimeProvider::ManagedLocal
        || !matches!(
            &preflight.command_provenance,
            RuntimeCommandProvenance::ManagedLocal { .. }
        )
    {
        return Err(AppError::NotAuthorized(
            "managed egress qualification lost verified managed-local command provenance".into(),
        ));
    }
    if qualification.image != expected_image
        || !qualification.gateway_reachable
        || qualification.reachability_probe != "socks5_no_connect_greeting"
        || qualification.upstream_connect_attempted
    {
        return Err(AppError::NotAuthorized(
            "managed egress qualification did not prove the pinned no-upstream gateway contract"
                .into(),
        ));
    }
    if [
        qualification.cleanup.gateway_container_removed,
        qualification.cleanup.probe_container_removed,
        qualification.cleanup.internal_network_removed,
        qualification.cleanup.uplink_network_removed,
        qualification.cleanup.policy_file_removed,
        qualification.cleanup.status_directory_removed,
        qualification.cleanup.registry_record_removed,
    ]
    .contains(&false)
    {
        return Err(AppError::Runtime(
            "managed egress qualification cleanup proof is incomplete".into(),
        ));
    }

    Ok(json!({
        "schema_version": "1.0.0",
        "status": "passed",
        "qualification_kind": "managed_egress_gateway_readiness",
        "product_version": env!("CARGO_PKG_VERSION"),
        "runtime": {
            "provider": preflight.provider,
            "server_version": preflight.server_version,
            "command_provenance": preflight.command_provenance,
        },
        "gateway": {
            "image": qualification.image,
            "backend": "pinned_container",
            "ready": true,
            "scanner_reachable": qualification.gateway_reachable,
            "reachability_probe": qualification.reachability_probe,
            "upstream_connection_attempted": qualification.upstream_connect_attempted,
            "container_id": qualification.gateway_container_id,
            "probe_container_id": qualification.probe_container_id,
            "internal_network_id": qualification.internal_network_id,
            "uplink_network_id": qualification.uplink_network_id,
            "policy_sha256": qualification.policy_sha256,
        },
        "cleanup": qualification.cleanup,
    }))
}

fn canonical_private_artifact_root(artifact_root: &Path) -> AppResult<PathBuf> {
    let metadata = fs::symlink_metadata(artifact_root)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(AppError::NotAuthorized(
            "qualification artifact root must be a real directory".into(),
        ));
    }
    artifact_root.canonicalize().map_err(AppError::from)
}

fn execute_fixed_managed_container_qualification<R: ContainerRuntime>(
    runtime: &R,
    preflight: RuntimePreflight,
    engines: &EngineRegistry,
    evidence_root: &Path,
) -> AppResult<Value> {
    if preflight.provider != RuntimeProvider::ManagedLocal
        || !matches!(
            preflight.command_provenance,
            RuntimeCommandProvenance::ManagedLocal { .. }
        )
    {
        return Err(AppError::NotAuthorized(
            "managed-container qualification requires verified managed-local command provenance"
                .into(),
        ));
    }

    let manifest = engines
        .get(MANAGED_RUNTIME_QUALIFICATION_ENGINE_ID)
        .ok_or_else(|| {
            AppError::EngineRegistry(
                "managed-container qualification engine is absent from the built-in catalog".into(),
            )
        })?;
    let expected_command = ["--workspace", "/workspace", "--output", "/output"];
    if manifest.command.len() != expected_command.len()
        || !manifest
            .command
            .iter()
            .zip(expected_command)
            .all(|(actual, expected)| actual == expected)
        || manifest.active_external
        || !manifest.network_destinations.is_empty()
        || manifest.required_permissions != [ScanPermission::LocalArtifactRead]
    {
        return Err(AppError::EngineRegistry(
            "managed-container qualification manifest differs from its fixed offline contract"
                .into(),
        ));
    }
    if let Some(image) = &manifest.image {
        ai_security_scanner_lib::publication_origins::validate_engine_publication(image)?;
    }
    let image = PinnedImage::from_manifest(manifest)?;
    if image.reference() != MANAGED_RUNTIME_QUALIFICATION_IMAGE {
        return Err(AppError::EngineRegistry(
            "managed-container qualification image differs from the release-fixed digest".into(),
        ));
    }

    let store = ArtifactStore::open(evidence_root)?;
    let context = ArtifactContext {
        case_id: MANAGED_RUNTIME_QUALIFICATION_CASE_ID.into(),
        scan_run_id: MANAGED_RUNTIME_QUALIFICATION_SCAN_RUN_ID.into(),
        engine_run_id: new_id(),
    };
    let directories = store.prepare_run(&context, 1)?;
    fs::write(
        directories.workspace.join("qualification.txt"),
        b"ai-security-scanner managed runtime qualification\n",
    )?;
    let scope = store.write_control_json(
        &directories,
        "scope.json",
        &json!({
            "schema_version": "1.0.0",
            "qualification_kind": "managed_container_execution",
            "case_id": context.case_id,
            "scan_run_id": context.scan_run_id,
            "engine_run_id": context.engine_run_id,
            "engine_id": MANAGED_RUNTIME_QUALIFICATION_ENGINE_ID,
            "asset": { "kind": "repository", "path": "/workspace" },
            "permissions": ["local_artifact_read"],
            "network": "disabled"
        }),
    )?;
    let capture = store.prepare_capture(&directories)?;
    let limits = ResourceLimits {
        memory_mb: 512,
        pids: 64,
        cpu_millis: 1000,
        tmpfs_mb: 32,
        output_bytes: 8 * 1024 * 1024,
    };
    let network_policy = NetworkPolicy::Disabled;
    let credentials = ScannerCredentialSet::default();
    let plan = ContainerPlanBuilder::new(
        manifest,
        &image,
        &directories,
        &scope.path,
        &limits,
        &network_policy,
        &credentials,
        &context.case_id,
        &context.scan_run_id,
        &context.engine_run_id,
        1,
    )
    .build()?;
    let runtime_args = plan.runtime_args();
    let network_none = runtime_args
        .windows(2)
        .filter(|pair| pair[0] == "--network" && pair[1] == "none")
        .count()
        == 1;
    if plan.network_policy() != &NetworkPolicy::Disabled
        || runtime_args
            .iter()
            .filter(|arg| *arg == "--read-only")
            .count()
            != 1
        || runtime_args
            .iter()
            .filter(|arg| *arg == "--cap-drop=ALL")
            .count()
            != 1
        || runtime_args
            .iter()
            .filter(|arg| *arg == "--security-opt=no-new-privileges:true")
            .count()
            != 1
        || runtime_args.iter().any(|arg| arg == "--env")
        || !network_none
        || !credentials.is_empty()
    {
        return Err(AppError::NotAuthorized(
            "managed-container qualification plan lost its fixed isolation contract".into(),
        ));
    }

    runtime.verify_network(&network_policy)?;
    runtime.pull(&image)?;
    let mut created_container = None;
    let mut creation_may_be_untracked = false;
    let run_result = runtime.run(
        &plan,
        &credentials,
        &CancellationToken::default(),
        &capture,
        &mut created_container,
        &mut creation_may_be_untracked,
    );
    let created_object_id = created_container
        .as_ref()
        .map(|created| created.immutable_id().to_owned());
    let cleanup_result = match (created_container.as_ref(), creation_may_be_untracked) {
        (Some(created), _) => Some(runtime.cleanup(plan.ownership(), Some(created))),
        (None, true) => Some(runtime.cleanup(plan.ownership(), None)),
        (None, false) => None,
    };
    let (outcome, cleanup) = match (run_result, cleanup_result) {
        (Ok(outcome), Some(Ok(cleanup))) => (outcome, cleanup),
        (Ok(_), None) => {
            return Err(AppError::Runtime(
                "managed-container qualification returned without a created-object identity".into(),
            ));
        }
        (Ok(_), Some(Err(cleanup))) => return Err(cleanup),
        (Err(run), Some(Err(cleanup))) => {
            return Err(AppError::Runtime(format!(
                "{run}; managed-container qualification cleanup also failed: {cleanup}"
            )));
        }
        (Err(run), _) => return Err(run),
    };
    if outcome.cancelled || outcome.exit_code != Some(0) {
        return Err(AppError::Runtime(format!(
            "managed-container qualification did not complete successfully: exit={:?}, cancelled={}",
            outcome.exit_code, outcome.cancelled
        )));
    }
    if !cleanup.removed {
        return Err(AppError::Runtime(
            "managed-container qualification removal unverified".into(),
        ));
    }
    let created_object_id = created_object_id.ok_or_else(|| {
        AppError::Runtime(
            "managed-container qualification reconciled an untracked invocation but received no immutable created-object identity"
                .into(),
        )
    })?;

    let report_path = directories
        .output
        .join(MANAGED_RUNTIME_QUALIFICATION_REPORT);
    let report_metadata = fs::symlink_metadata(&report_path).map_err(|error| {
        AppError::Runtime(format!(
            "managed-container qualification report is unavailable: {error}"
        ))
    })?;
    if report_metadata.file_type().is_symlink()
        || !report_metadata.is_file()
        || report_metadata.len() > MAX_MANAGED_RUNTIME_QUALIFICATION_REPORT_BYTES
    {
        return Err(AppError::Runtime(
            "managed-container qualification report must be a bounded regular file".into(),
        ));
    }
    let report_bytes = fs::read(&report_path)?;
    let findings = serde_json::from_slice::<Vec<Value>>(&report_bytes).map_err(|error| {
        AppError::Runtime(format!(
            "managed-container qualification report is malformed: {error}"
        ))
    })?;
    if !findings.is_empty() {
        return Err(AppError::Runtime(
            "managed-container qualification fixture unexpectedly produced findings".into(),
        ));
    }
    let report = store.describe_file(&context, &report_path, "application/json", false)?;
    let stdout = store.describe_file(
        &context,
        &capture.stdout,
        "text/plain; charset=utf-8",
        false,
    )?;
    let stderr = store.describe_file(
        &context,
        &capture.stderr,
        "text/plain; charset=utf-8",
        false,
    )?;

    Ok(json!({
        "schema_version": "1.0.0",
        "status": "passed",
        "qualification_kind": "managed_container_execution",
        "product_version": env!("CARGO_PKG_VERSION"),
        "runtime": {
            "provider": preflight.provider,
            "server_version": preflight.server_version,
            "command_provenance": preflight.command_provenance,
        },
        "container": {
            "engine_id": MANAGED_RUNTIME_QUALIFICATION_ENGINE_ID,
            "image": image.reference(),
            "network": "none",
            "read_only_root": true,
            "capabilities": "drop_all",
            "no_new_privileges": true,
            "credential_count": 0,
            "exit_code": outcome.exit_code,
            "cancelled": outcome.cancelled,
            "created_object_id": created_object_id,
            "cleanup_removed": cleanup.removed,
        },
        "evidence": {
            "scope_sha256": scope.sha256,
            "report_sha256": report.sha256,
            "report_bytes": report.byte_length,
            "finding_count": findings.len(),
            "stdout_sha256": stdout.sha256,
            "stderr_sha256": stderr.sha256,
        }
    }))
}

/// Reconstructs only the runtime recorded by a cleanup-pending checkpoint.
/// Managed-local recovery is tied to the exact release manifest SHA-256; the
/// stored command path or environment is never trusted or reconstructed from
/// user input.
fn runtime_for_cleanup(
    data_dir: &Path,
    stored_provider: Option<&str>,
    checkpoint: &ExecutionCheckpoint,
) -> AppResult<ProcessContainerRuntime> {
    let provenance = checkpoint
        .runtime_command_provenance
        .as_ref()
        .ok_or_else(|| {
            AppError::NotAuthorized(
                "cleanup checkpoint does not record exact runtime provenance".into(),
            )
        })?;
    let provider_from_engine_record = match stored_provider {
        Some("managed_local") => Some(RuntimeProvider::ManagedLocal),
        Some("docker") => Some(RuntimeProvider::Docker),
        Some("podman") => Some(RuntimeProvider::Podman),
        Some(_) => {
            return Err(AppError::NotAuthorized(
                "cleanup checkpoint references an unsupported runtime provider".into(),
            ));
        }
        None => None,
    };
    let provider_from_network = checkpoint
        .managed_network
        .as_ref()
        .map(|identity| identity.provider);
    let provider = checkpoint.runtime_provider.ok_or_else(|| {
        AppError::NotAuthorized(
            "cleanup checkpoint does not record an exact runtime provider".into(),
        )
    })?;
    if provider_from_engine_record.is_some_and(|recorded| recorded != provider) {
        return Err(AppError::NotAuthorized(
            "engine runtime record conflicts with checkpoint runtime provenance".into(),
        ));
    }
    if let Some(network) = provider_from_network
        && provider != network
    {
        return Err(AppError::NotAuthorized(
            "checkpoint runtime provider conflicts with managed-network provenance".into(),
        ));
    }

    let runtime = match (provider, provenance) {
        (
            RuntimeProvider::ManagedLocal,
            RuntimeCommandProvenance::ManagedLocal {
                manifest_sha256, ..
            },
        ) => {
            let manager =
                ManagedRuntimeManager::open_installed(data_dir, Some(manifest_sha256.as_str()))?;
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
                "cleanup runtime provider conflicts with its typed command provenance".into(),
            ));
        }
    };
    let observed = runtime.preflight()?;
    if observed.provider != provider || observed.command_provenance != *provenance {
        return Err(AppError::NotAuthorized(
            "resolved cleanup runtime does not match the durable command provenance".into(),
        ));
    }
    Ok(runtime)
}

/// Performs every operation that owns the managed runtime's blocking HTTP
/// client on the caller's blocking thread. Returning only owned cleanup
/// outcomes guarantees the runtime (and its client) is dropped before this
/// function crosses back into Tokio's async worker.
fn perform_exact_runtime_cleanup(
    data_dir: &Path,
    artifact_root: &Path,
    stored_provider: Option<&str>,
    checkpoint: &ExecutionCheckpoint,
    owned_container: &OwnedContainerCleanupRequest,
    container_name: Option<&str>,
) -> Result<ExactRuntimeCleanup, ExactRuntimeCleanupFailure> {
    let runtime = runtime_for_cleanup(data_dir, stored_provider, checkpoint).map_err(|error| {
        ExactRuntimeCleanupFailure {
            container: None,
            error,
        }
    })?;
    let container = match container_name {
        Some(_) => runtime
            .cleanup_owned_container(owned_container)
            .map_err(|error| ExactRuntimeCleanupFailure {
                container: None,
                error,
            })?,
        None => CleanupOutcome {
            removed: false,
            detail: "scanner container cleanup: not applicable".into(),

            gateway_refusals: None,
        },
    };

    let managed_network = if let Some(identity) = checkpoint.managed_network.as_ref() {
        let after_container = |error| ExactRuntimeCleanupFailure {
            container: Some(container.clone()),
            error,
        };
        let canonical_artifact_root = artifact_root
            .canonicalize()
            .map_err(AppError::from)
            .map_err(after_container)?;
        let registry_root =
            ensure_private_directory_child(&canonical_artifact_root, ".managed-egress-registry")
                .map_err(after_container)?;
        let registry = ManagedNetworkRegistry::new_with_runtime_context(
            registry_root,
            artifact_root,
            runtime.command_context(),
        )
        .map_err(after_container)?;
        let owner = ManagedNetworkOwner::new(
            checkpoint.case_id.clone(),
            checkpoint.scan_run_id.clone(),
            checkpoint.engine_run_id.clone(),
            checkpoint.attempt,
        )
        .map_err(after_container)?;
        Some(
            registry
                .reconcile_identity(&owner, identity, Utc::now())
                .map_err(after_container)?,
        )
    } else {
        None
    };

    let orphan_credentials_removed = cleanup_orphaned_credentials(artifact_root, owned_container)
        .map_err(|error| ExactRuntimeCleanupFailure {
        container: Some(container.clone()),
        error,
    })?;

    Ok(ExactRuntimeCleanup {
        container,
        managed_network,
        orphan_credentials_removed,
    })
}

async fn inspect_managed_runtime(data_dir: &Path, bundle_override: Option<&Path>) -> Value {
    let data_dir = data_dir.to_path_buf();
    let bundle = bundle_override.map(Path::to_path_buf);
    match tokio::task::spawn_blocking(move || {
        inspect_managed_runtime_blocking(&data_dir, bundle.as_deref())
    })
    .await
    {
        Ok(value) => value,
        Err(error) => json!({
            "configured": false,
            "available": false,
            "error": format!("managed runtime status worker failed: {error}"),
        }),
    }
}

fn inspect_managed_runtime_blocking(data_dir: &Path, bundle_override: Option<&Path>) -> Value {
    match open_managed_runtime_manager(data_dir, bundle_override) {
        Ok(manager) => match manager.status() {
            Ok(status) => json!({ "configured": true, "status": status }),
            Err(error) => json!({
                "configured": true,
                "available": false,
                "error": error.to_string(),
            }),
        },
        Err(error) => json!({
            "configured": false,
            "available": false,
            "error": error.to_string(),
        }),
    }
}

fn resolve_data_dir(override_path: Option<PathBuf>) -> AppResult<PathBuf> {
    if let Some(path) = override_path {
        return Ok(path);
    }

    BaseDirs::new()
        .map(|directories| canonical_product_data_dir(directories.data_local_dir()))
        .ok_or_else(|| AppError::Internal("platform local-data directory unavailable".into()))
}

fn canonical_product_data_dir(local_data_dir: &Path) -> PathBuf {
    local_data_dir.join(PRODUCT_DATA_DIRECTORY_NAME)
}

fn prepare_overridden_data_directory(path: &Path) -> AppResult<()> {
    fs::create_dir_all(path)?;
    Ok(())
}

fn legacy_project_data_dir() -> Option<PathBuf> {
    ProjectDirs::from("dev", "teddashh", "ai-security-scanner")
        .map(|directories| directories.data_local_dir().to_path_buf())
}

fn legacy_data_dir_contains_durable_entries(path: &Path) -> bool {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return false,
        Err(_) => return true,
    };
    if legacy_path_is_reparse_point(&metadata) || !metadata.is_dir() {
        return true;
    }

    let entries = match fs::read_dir(path) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return false,
        Err(_) => return true,
    };

    for entry in entries {
        let Ok(entry) = entry else {
            return true;
        };
        if entry.file_name() != std::ffi::OsStr::new(".exclusive-process.lock") {
            return true;
        }
        match entry.file_type() {
            Ok(file_type) if file_type.is_file() => {}
            _ => return true,
        }
    }
    false
}

fn legacy_path_is_reparse_point(metadata: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;

        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }
    #[cfg(not(windows))]
    {
        metadata.file_type().is_symlink()
    }
}

fn preserved_legacy_data_notice(
    selected_data_dir: &Path,
    legacy_data_dir: Option<&Path>,
) -> Option<String> {
    let legacy_data_dir = legacy_data_dir?;
    if legacy_data_dir == selected_data_dir
        || !legacy_data_dir_contains_durable_entries(legacy_data_dir)
    {
        return None;
    }

    Some(format!(
        "notice: legacy CLI data was preserved at \"{}\"; use --data-dir \"{}\" to open it explicitly.",
        legacy_data_dir.display(),
        legacy_data_dir.display()
    ))
}

fn parse_data_class(value: &str) -> AppResult<DataClass> {
    match value.trim().to_ascii_lowercase().as_str() {
        "general" => Ok(DataClass::General),
        "pii" => Ok(DataClass::PersonallyIdentifiableInformation),
        "phi" => Ok(DataClass::ProtectedHealthInformation),
        "pci" => Ok(DataClass::PaymentCardInformation),
        "financial" => Ok(DataClass::Financial),
        "secrets" => Ok(DataClass::CredentialsAndSecrets),
        "other" => Ok(DataClass::Other),
        other => Err(AppError::InvalidRequest(format!(
            "unsupported data class: {other}"
        ))),
    }
}

fn parse_rfc3339(value: &str) -> AppResult<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value.trim())
        .map(|value| value.with_timezone(&Utc))
        .map_err(|_| {
            AppError::InvalidRequest("--expires-at must be a valid RFC 3339 instant".into())
        })
}

#[cfg(all(test, unix))]
thread_local! {
    static EXTERNAL_SCOPE_BEFORE_OPEN_HOOK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        std::cell::RefCell::new(None);
}

#[cfg(all(test, unix))]
fn run_external_scope_before_open_hook() {
    let hook = EXTERNAL_SCOPE_BEFORE_OPEN_HOOK.with(|hook| hook.borrow_mut().take());
    if let Some(hook) = hook {
        hook();
    }
}

fn read_external_scope_document(path: &Path) -> AppResult<ExternalScopeRequest> {
    let selected = path.display();
    if !path.is_absolute() {
        return Err(AppError::InvalidRequest(format!(
            "external scope document \"{selected}\" must be an absolute path"
        )));
    }
    if path
        .components()
        .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(AppError::InvalidRequest(format!(
            "external scope document \"{selected}\" contains traversal components"
        )));
    }

    let mut current = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => current.push(prefix.as_os_str()),
            Component::RootDir => current.push(Path::new(std::path::MAIN_SEPARATOR_STR)),
            Component::Normal(name) => {
                current.push(name);
                let metadata = fs::symlink_metadata(&current).map_err(|error| {
                    AppError::InvalidRequest(format!(
                        "external scope document \"{selected}\" could not be inspected: {error}"
                    ))
                })?;
                if metadata.file_type().is_symlink() {
                    return Err(AppError::InvalidRequest(format!(
                        "external scope document \"{selected}\" contains a symlink"
                    )));
                }
            }
            Component::CurDir | Component::ParentDir => {
                return Err(AppError::InvalidRequest(format!(
                    "external scope document \"{selected}\" contains traversal components"
                )));
            }
        }
    }

    let metadata = fs::symlink_metadata(path).map_err(|error| {
        AppError::InvalidRequest(format!(
            "external scope document \"{selected}\" could not be inspected: {error}"
        ))
    })?;
    if !metadata.is_file() {
        return Err(AppError::InvalidRequest(format!(
            "external scope document \"{selected}\" is not a regular file"
        )));
    }
    if metadata.len() > MAX_SNAPSHOT_BYTES {
        return Err(AppError::InvalidRequest(format!(
            "external scope document \"{selected}\" exceeds the {MAX_SNAPSHOT_BYTES} byte limit"
        )));
    }

    #[cfg(all(test, unix))]
    run_external_scope_before_open_hook();

    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let file = options.open(path).map_err(|error| {
        AppError::InvalidRequest(format!(
            "external scope document \"{selected}\" could not be opened without following links: {error}"
        ))
    })?;
    let opened_metadata = file.metadata().map_err(|error| {
        AppError::InvalidRequest(format!(
            "external scope document \"{selected}\" metadata could not be read: {error}"
        ))
    })?;
    if !opened_metadata.is_file() || opened_metadata.len() > MAX_SNAPSHOT_BYTES {
        return Err(AppError::InvalidRequest(format!(
            "external scope document \"{selected}\" changed or exceeded its byte limit while opening"
        )));
    }

    let mut bytes = Vec::with_capacity(opened_metadata.len() as usize);
    let mut reader = file.take(MAX_SNAPSHOT_BYTES + 1);
    reader.read_to_end(&mut bytes).map_err(|error| {
        AppError::InvalidRequest(format!(
            "external scope document \"{selected}\" could not be read: {error}"
        ))
    })?;
    if bytes.len() as u64 > MAX_SNAPSHOT_BYTES {
        return Err(AppError::InvalidRequest(format!(
            "external scope document \"{selected}\" exceeded its byte limit while reading"
        )));
    }

    serde_json::from_slice(&bytes).map_err(|error| {
        AppError::InvalidRequest(format!(
            "external scope document \"{selected}\" is not valid JSON for an external scope request: {error}"
        ))
    })
}

fn print_value(value: &(impl Serialize + ?Sized), compact: bool) -> AppResult<()> {
    if compact {
        println!("{}", serde_json::to_string(value)?);
    } else {
        println!("{}", serde_json::to_string_pretty(value)?);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ai_security_scanner_lib::adapter::AdapterRegistry;
    use ai_security_scanner_lib::case_service::PersistedPreDispatchTransition;
    use ai_security_scanner_lib::container_runtime::{
        FakeContainerRuntime, FakeRunBehavior, RuntimeCall,
    };
    use ai_security_scanner_lib::discovery::{DiscoveredAsset, DiscoveryBatch};
    use ai_security_scanner_lib::domain::{AssetIdentifier, AssetKind};
    use ai_security_scanner_lib::external_scope::{CanonicalTarget, ExternalActivity};
    use chrono::Duration;
    use clap::{CommandFactory, Parser};

    struct CliScopeFixture {
        storage: Storage,
        engines: EngineRegistry,
        adapters: AdapterRegistry,
        artifact_root: PathBuf,
        signing_key_path: PathBuf,
        _directory: tempfile::TempDir,
    }

    impl CliScopeFixture {
        fn new() -> Self {
            let directory = tempfile::tempdir().expect("temporary directory");
            let artifact_root = directory.path().join("artifacts");
            fs::create_dir(&artifact_root).expect("artifact root");
            Self {
                storage: Storage::open(directory.path().join("casework.db")).expect("storage"),
                engines: EngineRegistry::load_builtin().expect("engine catalog"),
                adapters: builtin_adapter_registry().expect("adapter registry"),
                signing_key_path: directory.path().join("integrity-signing-key"),
                artifact_root,
                _directory: directory,
            }
        }

        fn service(&self) -> CaseService<'_> {
            CaseService::new(
                &self.storage,
                &self.engines,
                &self.adapters,
                &self.artifact_root,
                &self.signing_key_path,
            )
        }

        fn create_case(&self, title: &str) -> String {
            self.service()
                .create_case(&CreateCaseRequest {
                    title: title.into(),
                    organization_name: String::new(),
                    employee_range: "unknown".into(),
                    assessment_intent: None,
                    ai_generated_artifact: Default::default(),
                    data_classes: vec![],
                    requested_activities: vec![],
                    source_kinds: vec![],
                    not_applicable_source_kinds: vec![],
                    declared_assets: vec![],
                    notes: None,
                })
                .expect("case")
                .id
        }

        fn authorized_repository_case(&self, title: &str, workspace_name: &str) -> String {
            let case_id = self.create_case(title);
            let selected = self.workspace(workspace_name);
            let service = self.service();
            let attached = attach_workspace_source(
                &service,
                &self.artifact_root,
                &case_id,
                &format!("workspace-source-{workspace_name}"),
                "Selected repository",
                &selected,
                WorkspaceInputProfile::RepositoryWorkingTree,
            )
            .expect("workspace attachment");
            let asset_id = attached["asset_id"]
                .as_str()
                .expect("workspace asset id")
                .to_owned();
            service
                .approve_scope(
                    &case_id,
                    ScopeApprovalRequest {
                        asset_id,
                        permissions: vec![ScanPermission::LocalArtifactRead],
                        confirmed_by: "cli-test-operator".into(),
                        expires_at: Some(Utc::now() + Duration::hours(1)),
                        authorization_reference: None,
                        notes: None,
                        external_scope: None,
                    },
                )
                .expect("local artifact approval");
            case_id
        }

        fn workspace(&self, name: &str) -> PathBuf {
            let path = self._directory.path().join("working-trees").join(name);
            fs::create_dir_all(path.join("src")).expect("working tree");
            fs::write(path.join("src/main.rs"), b"fn main() {}\n").expect("source fixture");
            path
        }

        fn discovered_domain(&self) -> (String, String) {
            let service = self.service();
            let case = service
                .create_case(&CreateCaseRequest {
                    title: "CLI external scope".into(),
                    organization_name: "Example".into(),
                    employee_range: "1-10".into(),
                    assessment_intent: None,
                    ai_generated_artifact: Default::default(),
                    data_classes: vec![],
                    requested_activities: vec![],
                    source_kinds: vec![],
                    not_applicable_source_kinds: vec![],
                    declared_assets: vec![],
                    notes: None,
                })
                .expect("case");
            let source = service
                .upsert_source(
                    &case.id,
                    SourceMutation {
                        id: None,
                        kind: SourceKind::UserDeclared,
                        label: "Declared targets".into(),
                        status: SourceConnectionStatus::Connected,
                        read_only: true,
                        metadata: BTreeMap::new(),
                    },
                )
                .expect("source");
            service
                .reconcile_discovery_batch(
                    &case.id,
                    &DiscoveryBatch {
                        source_id: source.id,
                        source_kind: SourceKind::UserDeclared,
                        connector_id: "cli-test".into(),
                        connector_version: "1".into(),
                        observed_at: Utc::now(),
                        assets: vec![DiscoveredAsset {
                            observation_key: "shop".into(),
                            kind: AssetKind::Domain,
                            name: "shop.example.test".into(),
                            provider: None,
                            region: None,
                            stable_identifier: AssetIdentifier {
                                namespace: "dns_name".into(),
                                value: "shop.example.test".into(),
                            },
                            additional_identifiers: vec![],
                            internet_exposed: Some(true),
                            contains_sensitive_data: None,
                            metadata: BTreeMap::new(),
                        }],
                        relations: vec![],
                        notices: vec![],
                    },
                )
                .expect("discovery");
            let asset_id = service.show_case(&case.id).expect("stored case").assets[0]
                .id
                .clone();
            (case.id, asset_id)
        }
    }

    fn external_scope_value(activity: &str) -> Value {
        let active = activity == "active_external";
        json!({
            "target": "SHOP.Example.Test.",
            "ports": [443],
            "protocol": "tcp",
            "activity": activity,
            "rate_policy": {
                "requests_per_second": 2,
                "concurrency": 1,
                "timeout_seconds": 300
            },
            "template_policy": {
                "revision": if active {
                    "0123456789abcdef0123456789abcdef01234567"
                } else {
                    "not_applicable"
                },
                "allowed_template_ids": if active {
                    vec!["http/fixture"]
                } else {
                    Vec::<&str>::new()
                },
                "allow_headless": false,
                "allow_out_of_band": false,
                "allow_fuzzing": false,
                "allow_file_upload": false,
                "allow_denial_of_service": false,
                "allow_credential_attacks": false
            },
            "asserted_authority": "Approved external scope fixture",
            "allow_sensitive_networks": false
        })
    }

    fn write_external_scope(path: &Path, activity: &str) {
        fs::write(
            path,
            serde_json::to_vec_pretty(&external_scope_value(activity)).expect("scope JSON"),
        )
        .expect("scope document");
    }

    fn scope_approve_args(
        case_id: impl Into<String>,
        asset_id: impl Into<String>,
        permission: PermissionArg,
        external_scope: Option<PathBuf>,
    ) -> ScopeApproveArgs {
        ScopeApproveArgs {
            case_id: case_id.into(),
            asset_id: asset_id.into(),
            permission: vec![permission],
            confirmed_by: "e2e-operator".into(),
            expires_at: Some((Utc::now() + Duration::hours(1)).to_rfc3339()),
            authorization_reference: Some("E2E".into()),
            external_scope,
            notes: None,
        }
    }

    #[test]
    fn repository_workspace_attachment_enables_authorized_gitleaks_plan() {
        let fixture = CliScopeFixture::new();
        let case_id = fixture.create_case("CLI workspace");
        let selected = fixture.workspace("repository");
        let service = fixture.service();

        let output = attach_workspace_source(
            &service,
            &fixture.artifact_root,
            &case_id,
            "workspace-source-1",
            "Selected repository",
            &selected,
            WorkspaceInputProfile::RepositoryWorkingTree,
        )
        .expect("workspace attachment");

        assert_eq!(output["label"], "Selected repository");
        assert_eq!(output["profile"], "repository_working_tree");
        assert_eq!(output["source_id"], "workspace-source-1");
        assert_eq!(output["asset_kind"], "repository");
        let resolved_selection = selected.canonicalize().expect("resolved selection");
        assert_eq!(
            output["path"].as_str().map(Path::new),
            Some(resolved_selection.as_path())
        );
        assert_eq!(output["snapshot_sha256"].as_str().unwrap().len(), 64);

        let attached = service.show_case(&case_id).expect("attached case");
        let source = attached
            .data_sources
            .iter()
            .find(|source| source.id == "workspace-source-1")
            .expect("workspace source");
        assert!(source.read_only);
        assert_eq!(source.status, SourceConnectionStatus::Connected);
        let asset = attached
            .assets
            .iter()
            .find(|asset| asset.id == output["asset_id"])
            .expect("workspace asset");
        assert!(asset.candidate);
        assert!(!asset.owner_confirmed);

        service
            .approve_scope(
                &case_id,
                ScopeApprovalRequest {
                    asset_id: asset.id.clone(),
                    permissions: vec![ScanPermission::LocalArtifactRead],
                    confirmed_by: "e2e-operator".into(),
                    expires_at: Some(Utc::now() + Duration::hours(1)),
                    authorization_reference: None,
                    notes: None,
                    external_scope: None,
                },
            )
            .expect("local artifact approval");
        let plan = service
            .plan_scan(
                &case_id,
                ScanPlanRequest {
                    campaign_id: None,
                    engine_ids: vec!["gitleaks".into()],
                    engine_asset_routes: Vec::new(),
                },
            )
            .expect("gitleaks plan");
        assert!(plan.not_executed.is_empty());
        assert_eq!(plan.executable.len(), 1);
        assert_eq!(plan.executable[0].manifest.id, "gitleaks");
        assert_eq!(plan.executable[0].assets[0].id, asset.id);
    }

    #[test]
    fn queued_plan_can_be_cancelled_then_replanned_with_a_different_engine() {
        let fixture = CliScopeFixture::new();
        let case_id =
            fixture.authorized_repository_case("CLI queued-plan cancellation", "cancel-replan");
        let service = fixture.service();
        let first = service
            .plan_scan(
                &case_id,
                ScanPlanRequest {
                    campaign_id: None,
                    engine_ids: vec!["gitleaks".into()],
                    engine_asset_routes: Vec::new(),
                },
            )
            .expect("first plan");
        let first_run_id = first.scan_run.id.clone();
        assert_eq!(first.executable.len(), 1);
        assert!(
            first
                .scan_run
                .engine_runs
                .iter()
                .all(|engine_run| engine_run.status == EngineRunStatus::Queued)
        );

        execute_scan(
            ScanCommand::Cancel(ScanTransitionArgs {
                case_id: case_id.clone(),
                run_id: first_run_id.clone(),
            }),
            &service,
            true,
        )
        .expect("queued plan cancellation");

        let cancelled = service.show_case(&case_id).expect("cancelled case");
        let cancelled_run = cancelled
            .scan_runs
            .iter()
            .find(|run| run.id == first_run_id)
            .expect("cancelled run");
        assert!(
            cancelled_run
                .engine_runs
                .iter()
                .all(|engine_run| engine_run.status == EngineRunStatus::Cancelled)
        );
        let second = service
            .plan_scan(
                &case_id,
                ScanPlanRequest {
                    campaign_id: None,
                    engine_ids: vec!["trivy".into()],
                    engine_asset_routes: Vec::new(),
                },
            )
            .expect("second plan");
        assert_eq!(second.executable.len(), 1);
        assert_eq!(second.executable[0].manifest.id, "trivy");
    }

    #[test]
    fn cancelled_before_dispatch_then_requeued_for_resume_can_be_cancelled() {
        let fixture = CliScopeFixture::new();
        let case_id = fixture.authorized_repository_case(
            "CLI resumed pre-dispatch cancellation",
            "cancel-resumed-predispatch",
        );
        let service = fixture.service();
        let plan = service
            .plan_scan(
                &case_id,
                ScanPlanRequest {
                    campaign_id: None,
                    engine_ids: vec!["gitleaks".into()],
                    engine_asset_routes: Vec::new(),
                },
            )
            .expect("plan");
        let run_id = plan.scan_run.id.clone();
        let engine_run_id = plan.executable[0].engine_run_id.clone();

        service
            .transition_persisted_scan_pre_dispatch(
                &case_id,
                &run_id,
                &PersistedPreDispatchTransition::Preparing {
                    engine_run_ids: vec![engine_run_id.clone()],
                },
            )
            .expect("pre-dispatch preparation");
        let cancelled = service
            .transition_persisted_scan_pre_dispatch(
                &case_id,
                &run_id,
                &PersistedPreDispatchTransition::Cancel {
                    engine_run_ids: vec![engine_run_id],
                },
            )
            .expect("pre-dispatch cancellation");
        let cancelled_engine = &cancelled.scan_runs[0].engine_runs[0];
        assert_eq!(cancelled_engine.status, EngineRunStatus::Cancelled);
        assert_eq!(cancelled_engine.phase, "cancelled_before_dispatch");
        assert!(cancelled_engine.started_at.is_some());

        let resumed = service.plan_resume(&case_id, &run_id).expect("resume plan");
        assert_eq!(resumed.executable.len(), 1);
        assert_eq!(resumed.executable[0].attempt, 2);
        let resumed_engine = &resumed.scan_run.engine_runs[0];
        assert_eq!(resumed_engine.status, EngineRunStatus::Queued);
        assert_eq!(resumed_engine.phase, "queued_for_resume");
        assert!(resumed_engine.started_at.is_some());

        execute_scan(
            ScanCommand::Cancel(ScanTransitionArgs {
                case_id: case_id.clone(),
                run_id: run_id.clone(),
            }),
            &service,
            true,
        )
        .expect("re-queued pre-dispatch cancellation");

        let cancelled_again = service.show_case(&case_id).expect("cancelled case");
        let engine_run = &cancelled_again.scan_runs[0].engine_runs[0];
        assert_eq!(engine_run.status, EngineRunStatus::Cancelled);
        assert_eq!(engine_run.phase, "cancelled");
    }

    #[test]
    fn queued_next_phase_work_with_a_recorded_start_still_refuses_cli_cancellation() {
        let fixture = CliScopeFixture::new();
        let case_id = fixture.authorized_repository_case(
            "CLI queued next-phase cancellation",
            "queued-next-phase-cancel",
        );
        let service = fixture.service();
        let plan = service
            .plan_scan(
                &case_id,
                ScanPlanRequest {
                    campaign_id: None,
                    engine_ids: vec!["gitleaks".into()],
                    engine_asset_routes: Vec::new(),
                },
            )
            .expect("plan");
        let run_id = plan.scan_run.id.clone();
        let engine_run_id = plan.executable[0].engine_run_id.clone();

        service
            .transition_persisted_scan_pre_dispatch(
                &case_id,
                &run_id,
                &PersistedPreDispatchTransition::Preparing {
                    engine_run_ids: vec![engine_run_id.clone()],
                },
            )
            .expect("pre-dispatch preparation");
        service
            .transition_persisted_scan_pre_dispatch(
                &case_id,
                &run_id,
                &PersistedPreDispatchTransition::Cancel {
                    engine_run_ids: vec![engine_run_id],
                },
            )
            .expect("pre-dispatch cancellation");
        let resumed = service.plan_resume(&case_id, &run_id).expect("resume plan");
        let resumed_engine = &resumed.scan_run.engine_runs[0];
        assert_eq!(resumed_engine.status, EngineRunStatus::Queued);
        assert_eq!(resumed_engine.phase, "queued_for_resume");
        assert!(resumed_engine.started_at.is_some());

        let mut queued_next_phase = service.show_case(&case_id).expect("resumed case");
        queued_next_phase.scan_runs[0].engine_runs[0].phase = "queued_for_next_phase".into();
        fixture
            .storage
            .save_case(&mut queued_next_phase, "test.scan.queued_next_phase")
            .expect("queued next-phase fixture");

        let error = execute_scan(
            ScanCommand::Cancel(ScanTransitionArgs {
                case_id: case_id.clone(),
                run_id: run_id.clone(),
            }),
            &service,
            true,
        )
        .expect_err("queued next-phase work with a recorded start must be refused");
        let AppError::NotAvailable(message) = error else {
            panic!("queued next-phase cancellation did not return NotAvailable");
        };
        assert!(message.contains("recorded started_at value"), "{message}");

        let unchanged = service.show_case(&case_id).expect("unchanged case");
        let engine_run = &unchanged.scan_runs[0].engine_runs[0];
        assert_eq!(engine_run.status, EngineRunStatus::Queued);
        assert_eq!(engine_run.phase, "queued_for_next_phase");
        assert!(engine_run.started_at.is_some());
    }

    #[test]
    fn current_live_engine_statuses_still_refuse_cli_cancellation() {
        let fixture = CliScopeFixture::new();
        for (index, (status, phase)) in [
            (EngineRunStatus::Preparing, "preflight_preparing"),
            (EngineRunStatus::Running, "running"),
            (EngineRunStatus::Paused, "paused"),
        ]
        .into_iter()
        .enumerate()
        {
            let case_id = fixture.authorized_repository_case(
                &format!("CLI current live cancellation {index}"),
                &format!("current-live-cancel-{index}"),
            );
            let service = fixture.service();
            let plan = service
                .plan_scan(
                    &case_id,
                    ScanPlanRequest {
                        campaign_id: None,
                        engine_ids: vec!["gitleaks".into()],
                        engine_asset_routes: Vec::new(),
                    },
                )
                .expect("plan");
            let run_id = plan.scan_run.id;
            let mut live = service.show_case(&case_id).expect("planned case");
            let engine_run = &mut live.scan_runs[0].engine_runs[0];
            engine_run.status = status;
            engine_run.phase = phase.into();
            engine_run.started_at = Some(Utc::now());
            fixture
                .storage
                .save_case(&mut live, "test.scan.current_live")
                .expect("live fixture");

            let error = execute_scan(
                ScanCommand::Cancel(ScanTransitionArgs {
                    case_id: case_id.clone(),
                    run_id: run_id.clone(),
                }),
                &service,
                true,
            )
            .expect_err("current live work must require desktop control");
            assert_eq!(
                error.to_string(),
                out_of_process_scan_control_error("cancel", &case_id, &run_id).to_string()
            );
        }
    }

    #[test]
    fn recorded_engine_outcome_still_refuses_cli_cancellation() {
        let fixture = CliScopeFixture::new();
        let case_id =
            fixture.authorized_repository_case("CLI recorded outcome", "recorded-outcome-cancel");
        let service = fixture.service();
        let plan = service
            .plan_scan(
                &case_id,
                ScanPlanRequest {
                    campaign_id: None,
                    engine_ids: vec!["gitleaks".into()],
                    engine_asset_routes: Vec::new(),
                },
            )
            .expect("plan");
        let run_id = plan.scan_run.id;
        let mut completed = service.show_case(&case_id).expect("planned case");
        let engine_run = &mut completed.scan_runs[0].engine_runs[0];
        engine_run.status = EngineRunStatus::Completed;
        engine_run.phase = "completed".into();
        engine_run.started_at = Some(Utc::now());
        engine_run.finished_at = Some(Utc::now());
        fixture
            .storage
            .save_case(&mut completed, "test.scan.recorded_outcome")
            .expect("completed fixture");

        let error = execute_scan(
            ScanCommand::Cancel(ScanTransitionArgs { case_id, run_id }),
            &service,
            true,
        )
        .expect_err("recorded outcome must be refused");
        let AppError::NotAvailable(message) = error else {
            panic!("recorded outcome did not return NotAvailable");
        };
        assert!(message.contains("already reached an outcome"), "{message}");
        assert!(message.contains("completed"), "{message}");
        assert!(!message.contains("desktop scan controls"), "{message}");
    }

    #[test]
    fn cli_cancel_refuses_a_second_cancel_as_an_already_cancelled_outcome() {
        let fixture = CliScopeFixture::new();
        let case_id =
            fixture.authorized_repository_case("CLI double cancellation", "double-cancel-outcome");
        let service = fixture.service();
        let plan = service
            .plan_scan(
                &case_id,
                ScanPlanRequest {
                    campaign_id: None,
                    engine_ids: vec!["gitleaks".into()],
                    engine_asset_routes: Vec::new(),
                },
            )
            .expect("plan");
        let run_id = plan.scan_run.id;

        execute_scan(
            ScanCommand::Cancel(ScanTransitionArgs {
                case_id: case_id.clone(),
                run_id: run_id.clone(),
            }),
            &service,
            true,
        )
        .expect("first cancellation");
        let before = serde_json::to_value(service.show_case(&case_id).expect("cancelled case"))
            .expect("cancelled case JSON");

        let error = execute_scan(
            ScanCommand::Cancel(ScanTransitionArgs {
                case_id: case_id.clone(),
                run_id: run_id.clone(),
            }),
            &service,
            true,
        )
        .expect_err("second cancellation must be refused");
        let AppError::NotAvailable(message) = error else {
            panic!("second cancellation did not return NotAvailable");
        };
        assert!(message.contains("already reached an outcome"), "{message}");
        assert!(message.contains("cancelled"), "{message}");
        assert!(!message.contains("desktop scan controls"), "{message}");
        assert_eq!(
            serde_json::to_value(service.show_case(&case_id).expect("unchanged case"))
                .expect("unchanged case JSON"),
            before
        );
    }

    #[test]
    fn mixed_queued_and_not_executed_plan_can_be_cancelled_then_replanned() {
        let fixture = CliScopeFixture::new();
        let case_id = fixture
            .authorized_repository_case("CLI mixed-plan cancellation", "cancel-mixed-replan");
        let service = fixture.service();
        let first = service
            .plan_scan(
                &case_id,
                ScanPlanRequest {
                    campaign_id: None,
                    engine_ids: vec!["gitleaks".into(), "mcp-armor".into()],
                    engine_asset_routes: Vec::new(),
                },
            )
            .expect("mixed plan");
        let first_run_id = first.scan_run.id.clone();
        assert_eq!(first.executable.len(), 1);
        assert_eq!(first.executable[0].manifest.id, "gitleaks");
        assert_eq!(first.not_executed.len(), 1);
        assert_eq!(first.not_executed[0].engine_id, "mcp-armor");
        assert_eq!(
            first
                .scan_run
                .engine_runs
                .iter()
                .find(|engine_run| engine_run.engine_id == "gitleaks")
                .expect("gitleaks engine run")
                .status,
            EngineRunStatus::Queued
        );
        assert_eq!(
            first
                .scan_run
                .engine_runs
                .iter()
                .find(|engine_run| engine_run.engine_id == "mcp-armor")
                .expect("mcp-armor engine run")
                .status,
            EngineRunStatus::NotExecuted
        );

        execute_scan(
            ScanCommand::Cancel(ScanTransitionArgs {
                case_id: case_id.clone(),
                run_id: first_run_id.clone(),
            }),
            &service,
            true,
        )
        .expect("mixed plan cancellation");

        let cancelled = service.show_case(&case_id).expect("cancelled case");
        assert_ne!(cancelled.status, CaseStatus::Scanning);
        let cancelled_run = cancelled
            .scan_runs
            .iter()
            .find(|run| run.id == first_run_id)
            .expect("cancelled run");
        assert_eq!(
            cancelled_run
                .engine_runs
                .iter()
                .find(|engine_run| engine_run.engine_id == "gitleaks")
                .expect("cancelled gitleaks engine run")
                .status,
            EngineRunStatus::Cancelled
        );
        assert_eq!(
            cancelled_run
                .engine_runs
                .iter()
                .find(|engine_run| engine_run.engine_id == "mcp-armor")
                .expect("not-executed mcp-armor engine run")
                .status,
            EngineRunStatus::NotExecuted
        );

        let second = service
            .plan_scan(
                &case_id,
                ScanPlanRequest {
                    campaign_id: None,
                    engine_ids: vec!["trivy".into()],
                    engine_asset_routes: Vec::new(),
                },
            )
            .expect("second plan");
        assert_eq!(second.executable.len(), 1);
        assert_eq!(second.executable[0].manifest.id, "trivy");
    }

    #[test]
    fn cli_cancel_refuses_cancelled_and_not_executed_as_an_outcome() {
        let fixture = CliScopeFixture::new();
        let case_id = fixture.authorized_repository_case(
            "CLI mixed cancellation outcome",
            "cancelled-not-executed-outcome",
        );
        let service = fixture.service();
        let plan = service
            .plan_scan(
                &case_id,
                ScanPlanRequest {
                    campaign_id: None,
                    engine_ids: vec!["gitleaks".into(), "mcp-armor".into()],
                    engine_asset_routes: Vec::new(),
                },
            )
            .expect("mixed plan");
        let run_id = plan.scan_run.id;

        execute_scan(
            ScanCommand::Cancel(ScanTransitionArgs {
                case_id: case_id.clone(),
                run_id: run_id.clone(),
            }),
            &service,
            true,
        )
        .expect("mixed plan cancellation");

        let error = execute_scan(
            ScanCommand::Cancel(ScanTransitionArgs { case_id, run_id }),
            &service,
            true,
        )
        .expect_err("cancelled and not-executed run must be refused as an outcome");
        let AppError::NotAvailable(message) = error else {
            panic!("mixed outcome did not return NotAvailable");
        };
        assert!(message.contains("already reached an outcome"), "{message}");
        assert!(message.contains("cancelled"), "{message}");
        assert!(message.contains("not_executed"), "{message}");
        assert!(!message.contains("desktop scan controls"), "{message}");
    }

    #[test]
    fn all_not_executed_plan_is_refused_without_mutation() {
        let fixture = CliScopeFixture::new();
        let case_id = fixture
            .authorized_repository_case("CLI not-executed cancellation", "cancel-not-executed");
        let service = fixture.service();
        let plan = service
            .plan_scan(
                &case_id,
                ScanPlanRequest {
                    campaign_id: None,
                    engine_ids: vec!["mcp-armor".into()],
                    engine_asset_routes: Vec::new(),
                },
            )
            .expect("not-executed plan");
        let run_id = plan.scan_run.id.clone();
        assert!(plan.executable.is_empty());
        assert_eq!(plan.not_executed.len(), 1);
        assert!(
            plan.scan_run
                .engine_runs
                .iter()
                .all(|engine_run| engine_run.status == EngineRunStatus::NotExecuted)
        );
        let before = serde_json::to_value(service.show_case(&case_id).expect("planned case"))
            .expect("planned case JSON");

        let error = execute_scan(
            ScanCommand::Cancel(ScanTransitionArgs {
                case_id: case_id.clone(),
                run_id,
            }),
            &service,
            true,
        )
        .expect_err("all-not-executed plan has nothing to cancel");
        assert_eq!(
            error.to_string(),
            "invalid request: scan has no engine runs eligible to cancel"
        );

        assert_eq!(
            serde_json::to_value(service.show_case(&case_id).expect("unchanged case"))
                .expect("unchanged case JSON"),
            before
        );
    }

    #[test]
    fn cli_cancel_refuses_started_and_interrupted_runs_without_mutation() {
        let fixture = CliScopeFixture::new();
        for (index, (status, phase)) in [
            (EngineRunStatus::Preparing, "preflight_preparing"),
            (EngineRunStatus::Running, "running"),
            (EngineRunStatus::Paused, "interrupted_restart"),
        ]
        .into_iter()
        .enumerate()
        {
            let case_id = fixture.authorized_repository_case(
                &format!("CLI started cancellation {index}"),
                &format!("started-cancel-{index}"),
            );
            let service = fixture.service();
            let plan = service
                .plan_scan(
                    &case_id,
                    ScanPlanRequest {
                        campaign_id: None,
                        engine_ids: vec!["gitleaks".into()],
                        engine_asset_routes: Vec::new(),
                    },
                )
                .expect("plan");
            let run_id = plan.scan_run.id;
            let mut started = service.show_case(&case_id).expect("planned case");
            let engine_run = &mut started.scan_runs[0].engine_runs[0];
            engine_run.status = status;
            engine_run.phase = phase.into();
            engine_run.started_at = Some(Utc::now());
            fixture
                .storage
                .save_case(&mut started, "test.scan.started")
                .expect("started fixture");
            let before = serde_json::to_value(
                started
                    .scan_runs
                    .iter()
                    .find(|run| run.id == run_id)
                    .expect("started run"),
            )
            .expect("started run JSON");

            let error = execute_scan(
                ScanCommand::Cancel(ScanTransitionArgs {
                    case_id: case_id.clone(),
                    run_id: run_id.clone(),
                }),
                &service,
                true,
            )
            .expect_err("started or interrupted run must require desktop control");
            assert_eq!(
                error.to_string(),
                out_of_process_scan_control_error("cancel", &case_id, &run_id).to_string()
            );
            let after = service.show_case(&case_id).expect("unchanged case");
            let after = serde_json::to_value(
                after
                    .scan_runs
                    .iter()
                    .find(|run| run.id == run_id)
                    .expect("unchanged run"),
            )
            .expect("unchanged run JSON");
            assert_eq!(after, before);
        }
    }

    #[test]
    fn cli_cancel_treats_running_and_completed_as_live_work() {
        let fixture = CliScopeFixture::new();
        let case_id = fixture.authorized_repository_case(
            "CLI live and completed cancellation",
            "running-completed-cancel",
        );
        let service = fixture.service();
        let plan = service
            .plan_scan(
                &case_id,
                ScanPlanRequest {
                    campaign_id: None,
                    engine_ids: vec!["gitleaks".into(), "trivy".into()],
                    engine_asset_routes: Vec::new(),
                },
            )
            .expect("plan");
        let run_id = plan.scan_run.id;
        let mut mixed = service.show_case(&case_id).expect("planned case");
        let engine_runs = &mut mixed.scan_runs[0].engine_runs;
        assert_eq!(engine_runs.len(), 2);
        engine_runs[0].status = EngineRunStatus::Running;
        engine_runs[0].phase = "running".into();
        engine_runs[0].started_at = Some(Utc::now());
        engine_runs[1].status = EngineRunStatus::Completed;
        engine_runs[1].phase = "completed".into();
        engine_runs[1].started_at = Some(Utc::now());
        engine_runs[1].finished_at = Some(Utc::now());
        fixture
            .storage
            .save_case(&mut mixed, "test.scan.running_and_completed")
            .expect("mixed live and completed fixture");

        let error = execute_scan(
            ScanCommand::Cancel(ScanTransitionArgs {
                case_id: case_id.clone(),
                run_id: run_id.clone(),
            }),
            &service,
            true,
        )
        .expect_err("live work must take precedence over completed work");
        assert_eq!(
            error.to_string(),
            out_of_process_scan_control_error("cancel", &case_id, &run_id).to_string()
        );
    }

    #[test]
    fn cli_cancel_refuses_terminal_engine_runs_without_mutation() {
        let fixture = CliScopeFixture::new();
        for (index, (status, phase)) in [
            (EngineRunStatus::Completed, "completed"),
            (EngineRunStatus::PartiallyCompleted, "results_partial"),
            (EngineRunStatus::Failed, "failed"),
            (EngineRunStatus::Cancelled, "cancelled"),
        ]
        .into_iter()
        .enumerate()
        {
            let status_name = engine_run_status_name(&status);
            let case_id = fixture.authorized_repository_case(
                &format!("CLI terminal cancellation {index}"),
                &format!("terminal-cancel-{index}"),
            );
            let service = fixture.service();
            let plan = service
                .plan_scan(
                    &case_id,
                    ScanPlanRequest {
                        campaign_id: None,
                        engine_ids: vec!["gitleaks".into()],
                        engine_asset_routes: Vec::new(),
                    },
                )
                .expect("plan");
            let run_id = plan.scan_run.id;
            let mut terminal = service.show_case(&case_id).expect("planned case");
            let engine_run = &mut terminal.scan_runs[0].engine_runs[0];
            engine_run.status = status;
            engine_run.phase = phase.into();
            engine_run.started_at = Some(Utc::now());
            engine_run.finished_at = Some(Utc::now());
            fixture
                .storage
                .save_case(&mut terminal, "test.scan.terminal")
                .expect("terminal fixture");
            let before = serde_json::to_value(
                terminal
                    .scan_runs
                    .iter()
                    .find(|run| run.id == run_id)
                    .expect("terminal run"),
            )
            .expect("terminal run JSON");

            let error = execute_scan(
                ScanCommand::Cancel(ScanTransitionArgs {
                    case_id: case_id.clone(),
                    run_id: run_id.clone(),
                }),
                &service,
                true,
            )
            .expect_err("a run that produced an outcome cannot be cancelled");
            let AppError::NotAvailable(message) = error else {
                panic!("terminal run did not return NotAvailable");
            };
            assert!(message.contains("already reached an outcome"), "{message}");
            assert!(message.contains(status_name), "{message}");
            assert!(!message.contains("desktop scan controls"), "{message}");
            let after = service.show_case(&case_id).expect("unchanged case");
            let after = serde_json::to_value(
                after
                    .scan_runs
                    .iter()
                    .find(|run| run.id == run_id)
                    .expect("unchanged run"),
            )
            .expect("unchanged run JSON");
            assert_eq!(after, before);
        }
    }

    #[test]
    fn cli_cancel_reports_inconsistent_queued_start_time_without_desktop_wording() {
        let fixture = CliScopeFixture::new();
        let case_id =
            fixture.authorized_repository_case("CLI inconsistent queued run", "queued-with-start");
        let service = fixture.service();
        let plan = service
            .plan_scan(
                &case_id,
                ScanPlanRequest {
                    campaign_id: None,
                    engine_ids: vec!["gitleaks".into()],
                    engine_asset_routes: Vec::new(),
                },
            )
            .expect("plan");
        let run_id = plan.scan_run.id;
        let mut inconsistent = service.show_case(&case_id).expect("planned case");
        inconsistent.scan_runs[0].engine_runs[0].started_at = Some(Utc::now());
        fixture
            .storage
            .save_case(&mut inconsistent, "test.scan.inconsistent_queued")
            .expect("inconsistent queued fixture");
        let before = serde_json::to_value(
            inconsistent
                .scan_runs
                .iter()
                .find(|run| run.id == run_id)
                .expect("inconsistent queued run"),
        )
        .expect("inconsistent queued run JSON");

        let error = execute_scan(
            ScanCommand::Cancel(ScanTransitionArgs {
                case_id: case_id.clone(),
                run_id: run_id.clone(),
            }),
            &service,
            true,
        )
        .expect_err("queued run with a start time must be refused");
        let AppError::NotAvailable(message) = error else {
            panic!("inconsistent queued run did not return NotAvailable");
        };
        assert!(message.contains("status queued"), "{message}");
        assert!(message.contains("recorded started_at value"), "{message}");
        assert!(!message.contains("desktop scan controls"), "{message}");

        let after = service.show_case(&case_id).expect("unchanged case");
        let after = serde_json::to_value(
            after
                .scan_runs
                .iter()
                .find(|run| run.id == run_id)
                .expect("unchanged run"),
        )
        .expect("unchanged run JSON");
        assert_eq!(after, before);
    }

    #[test]
    fn pause_and_resume_still_refuse_a_never_started_plan() {
        let fixture = CliScopeFixture::new();
        let case_id = fixture
            .authorized_repository_case("CLI queued pause and resume", "queued-pause-resume");
        let service = fixture.service();
        let plan = service
            .plan_scan(
                &case_id,
                ScanPlanRequest {
                    campaign_id: None,
                    engine_ids: vec!["gitleaks".into()],
                    engine_asset_routes: Vec::new(),
                },
            )
            .expect("plan");
        let run_id = plan.scan_run.id.clone();
        let before = serde_json::to_value(&plan.scan_run).expect("planned run JSON");

        for command in [
            ScanCommand::Pause(ScanTransitionArgs {
                case_id: case_id.clone(),
                run_id: run_id.clone(),
            }),
            ScanCommand::Resume(ScanTransitionArgs {
                case_id: case_id.clone(),
                run_id: run_id.clone(),
            }),
        ] {
            let error = execute_scan(command, &service, true)
                .expect_err("pause and resume remain desktop-only");
            let AppError::NotAvailable(message) = error else {
                panic!("queued plan control did not return NotAvailable");
            };
            assert!(message.contains("use the desktop scan controls"));
        }

        let after = service.show_case(&case_id).expect("unchanged case");
        let after = after
            .scan_runs
            .iter()
            .find(|run| run.id == run_id)
            .expect("unchanged run");
        assert_eq!(serde_json::to_value(after).expect("run JSON"), before);
    }

    #[test]
    fn cli_cancel_rejects_a_run_id_from_another_case() {
        let fixture = CliScopeFixture::new();
        let planned_case_id = fixture.authorized_repository_case("CLI run owner", "run-owner");
        let other_case_id = fixture.create_case("CLI wrong run owner");
        let service = fixture.service();
        let plan = service
            .plan_scan(
                &planned_case_id,
                ScanPlanRequest {
                    campaign_id: None,
                    engine_ids: vec!["gitleaks".into()],
                    engine_asset_routes: Vec::new(),
                },
            )
            .expect("plan");
        let run_id = plan.scan_run.id;

        let error = execute_scan(
            ScanCommand::Cancel(ScanTransitionArgs {
                case_id: other_case_id,
                run_id: run_id.clone(),
            }),
            &service,
            true,
        )
        .expect_err("a run cannot be cancelled through another case");
        assert!(error.to_string().contains("scan run not found"));
        assert!(error.to_string().contains(&run_id));
        let unchanged = service
            .show_case(&planned_case_id)
            .expect("planned case remains");
        assert_eq!(
            unchanged.scan_runs[0].engine_runs[0].status,
            EngineRunStatus::Queued
        );
    }

    #[test]
    fn workspace_attachment_rejects_invalid_paths_without_case_mutation() {
        let fixture = CliScopeFixture::new();
        let case_id = fixture.create_case("Invalid workspace paths");
        let file_path = fixture._directory.path().join("regular-file");
        fs::write(&file_path, b"not a directory").expect("regular file");
        let missing_path = fixture._directory.path().join("missing-directory");
        let cases = [
            (
                PathBuf::from("relative/path"),
                "the working-tree selection must be an explicit absolute directory",
            ),
            (
                missing_path,
                "selected working-tree path component could not be inspected",
            ),
            (
                file_path,
                "selected working-tree path must be a real directory, not a symlink",
            ),
        ];

        for (index, (path, expected_message)) in cases.into_iter().enumerate() {
            let error = attach_workspace_source(
                &fixture.service(),
                &fixture.artifact_root,
                &case_id,
                &format!("invalid-source-{index}"),
                "Invalid workspace",
                &path,
                WorkspaceInputProfile::RepositoryWorkingTree,
            )
            .expect_err("invalid workspace path must fail");
            assert!(
                error.to_string().contains(expected_message),
                "unexpected error: {error}"
            );
            let stored = fixture.service().show_case(&case_id).expect("stored case");
            assert!(stored.data_sources.is_empty());
            assert!(stored.assets.is_empty());
        }
    }

    #[test]
    fn workspace_attachment_rejects_artifact_root_overlap() {
        let fixture = CliScopeFixture::new();
        let case_id = fixture.create_case("Overlapping workspace");

        let error = attach_workspace_source(
            &fixture.service(),
            &fixture.artifact_root,
            &case_id,
            "overlap-source",
            "Overlapping workspace",
            &fixture.artifact_root,
            WorkspaceInputProfile::RepositoryWorkingTree,
        )
        .expect_err("artifact-root overlap must fail");

        assert!(
            error
                .to_string()
                .contains("selected working tree and artifact root must not overlap")
        );
        let stored = fixture.service().show_case(&case_id).expect("stored case");
        assert!(stored.data_sources.is_empty());
        assert!(stored.assets.is_empty());
    }

    #[test]
    fn workspace_attachment_rejects_duplicate_source_id() {
        let fixture = CliScopeFixture::new();
        let case_id = fixture.create_case("Duplicate workspace source");
        let selected = fixture.workspace("duplicate-source");

        attach_workspace_source(
            &fixture.service(),
            &fixture.artifact_root,
            &case_id,
            "workspace-source-duplicate",
            "First attachment",
            &selected,
            WorkspaceInputProfile::RepositoryWorkingTree,
        )
        .expect("first attachment");
        let error = attach_workspace_source(
            &fixture.service(),
            &fixture.artifact_root,
            &case_id,
            "workspace-source-duplicate",
            "Second attachment",
            &selected,
            WorkspaceInputProfile::RepositoryWorkingTree,
        )
        .expect_err("duplicate source id must fail");

        assert!(
            error
                .to_string()
                .contains("workspace source id already exists in this case")
        );
        let stored = fixture.service().show_case(&case_id).expect("stored case");
        assert_eq!(stored.data_sources.len(), 1);
        assert_eq!(stored.assets.len(), 1);
    }

    #[test]
    fn workspace_attachment_rejects_demo_and_archived_cases() {
        let fixture = CliScopeFixture::new();
        let selected = fixture.workspace("immutable-cases");
        let mut demo = build_demo_case();
        fixture
            .storage
            .save_case(&mut demo, "demo.seeded.cli-test")
            .expect("demo case");
        let archived_id = fixture.create_case("Archived workspace");
        fixture
            .service()
            .archive_case(&archived_id)
            .expect("archived case");

        for (case_id, source_id) in [
            (demo.id.as_str(), "demo-workspace-source"),
            (archived_id.as_str(), "archived-workspace-source"),
        ] {
            let before = fixture.service().show_case(case_id).expect("case before");
            let error = attach_workspace_source(
                &fixture.service(),
                &fixture.artifact_root,
                case_id,
                source_id,
                "Immutable workspace",
                &selected,
                WorkspaceInputProfile::RepositoryWorkingTree,
            )
            .expect_err("immutable case must fail");
            assert!(
                error
                    .to_string()
                    .contains("demo or archived cases cannot attach working-tree snapshots")
            );
            let after = fixture.service().show_case(case_id).expect("case after");
            assert_eq!(after.data_sources.len(), before.data_sources.len());
            assert_eq!(after.assets.len(), before.assets.len());
        }
    }

    #[test]
    fn parses_workspace_attachment_profiles() {
        for profile in [
            "repository-working-tree",
            "iac-working-tree",
            "container-image-oci-layout",
            "kubernetes-manifests",
            "kubernetes-node-snapshot",
        ] {
            let cli = Cli::try_parse_from([
                "ai-security-scanner",
                "source",
                "attach-workspace",
                "--case-id",
                "case-1",
                "--label",
                "Selected input",
                "--path",
                "/selected/input",
                "--profile",
                profile,
            ])
            .expect("workspace attachment CLI");
            assert!(matches!(
                cli.command,
                Command::Source {
                    command: SourceCommand::AttachWorkspace(_)
                }
            ));
        }
    }

    #[test]
    fn parses_workspace_refresh() {
        let cli = Cli::try_parse_from([
            "ai-security-scanner",
            "source",
            "refresh-workspace",
            "--case-id",
            "case-1",
            "--asset-id",
            "asset-1",
            "--path",
            "/selected/input",
        ])
        .expect("workspace refresh CLI");
        assert!(matches!(
            cli.command,
            Command::Source {
                command: SourceCommand::RefreshWorkspace(_)
            }
        ));
    }

    fn managed_qualification_preflight() -> RuntimePreflight {
        RuntimePreflight {
            provider: RuntimeProvider::ManagedLocal,
            server_version: "5.8.0".into(),
            security_options: "rootless".into(),
            command_provenance: RuntimeCommandProvenance::ManagedLocal {
                runtime_version: "5.8.0".into(),
                manifest_sha256: "a".repeat(64),
                machine_image_sha256: "b".repeat(64),
            },
        }
    }

    #[test]
    fn parses_supported_data_classes() {
        assert!(matches!(
            parse_data_class("PII"),
            Ok(DataClass::PersonallyIdentifiableInformation)
        ));
        assert!(parse_data_class("legal-opinion").is_err());
    }

    #[test]
    fn cli_data_root_default_uses_the_fixed_product_root() {
        let local_data_dir = Path::new("platform-local-data");

        assert_eq!(
            canonical_product_data_dir(local_data_dir),
            local_data_dir.join(PRODUCT_DATA_DIRECTORY_NAME)
        );
    }

    #[test]
    fn cli_data_root_explicit_override_is_preserved_exactly() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let override_path = temporary.path().join("legacy").join("caller-selected-data");

        assert_eq!(
            resolve_data_dir(Some(override_path.clone())).unwrap(),
            override_path
        );
        prepare_overridden_data_directory(&override_path)
            .expect("ordinary override creation remains available");
        assert!(override_path.is_dir());
    }

    #[test]
    fn cli_data_root_legacy_notice_requires_durable_state_and_never_rewrites_it() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let canonical = temporary.path().join("canonical");
        let legacy = temporary.path().join("legacy");
        fs::create_dir(&legacy).expect("legacy directory");

        assert!(preserved_legacy_data_notice(&canonical, Some(&legacy)).is_none());

        let transient_lock = legacy.join(".exclusive-process.lock");
        fs::write(&transient_lock, b"transient lease").expect("transient lease fixture");
        assert!(preserved_legacy_data_notice(&canonical, Some(&legacy)).is_none());

        let case_database = legacy.join("casework.db");
        fs::write(&case_database, b"preserved case bytes").expect("legacy case fixture");
        let notice = preserved_legacy_data_notice(&canonical, Some(&legacy))
            .expect("durable legacy state notice");

        assert!(notice.starts_with("notice: legacy CLI data was preserved at "));
        assert!(notice.contains("--data-dir"));
        assert!(notice.contains(&legacy.display().to_string()));
        assert_eq!(
            fs::read(&case_database).expect("preserved case bytes"),
            b"preserved case bytes"
        );
        assert_eq!(
            fs::read(&transient_lock).expect("preserved transient lease bytes"),
            b"transient lease"
        );
        assert!(!canonical.exists());
        assert!(preserved_legacy_data_notice(&legacy, Some(&legacy)).is_none());
        assert!(preserved_legacy_data_notice(&canonical, None).is_none());
    }

    #[test]
    fn complete_command_tree_is_valid() {
        Cli::command().debug_assert();
    }

    #[cfg(feature = "installer-runtime-cache")]
    #[test]
    fn windows_installer_runtime_cache_is_hidden_zero_input_and_early_dispatched() {
        let parsed = Cli::try_parse_from([
            "ai-security-scanner",
            "--json",
            "windows-installer-runtime-cache",
        ])
        .expect("fixed installed-package runtime-cache invocation");
        assert!(matches!(
            parsed.command,
            Command::WindowsInstallerRuntimeCache
        ));
        assert!(!command_requires_exclusive_data_directory(&parsed.command));

        for unexpected in ["--action", "--path", "--executable", "--arguments"] {
            assert!(
                Cli::try_parse_from([
                    "ai-security-scanner",
                    "--json",
                    "windows-installer-runtime-cache",
                    unexpected,
                    "caller-selected",
                ])
                .is_err(),
                "hidden package cache coordinator accepted {unexpected}",
            );
        }
    }

    #[cfg(feature = "installer-runtime-cache")]
    #[test]
    fn windows_installer_runtime_cache_envelopes_are_exact_redacted_and_bounded() {
        for (result_class, expected_exit, encoded_class) in [
            (WindowsInstallerRuntimeCacheClass::Seeded, 0, "seeded"),
            (
                WindowsInstallerRuntimeCacheClass::Unavailable,
                30,
                "unavailable",
            ),
        ] {
            let envelope = WindowsInstallerRuntimeCacheCoordinatorEnvelope {
                schema_version: "ai-security-scanner.windows-installer-runtime-cache/v1",
                result_class,
                exit_code: expected_exit,
                terminal: "complete",
            };
            let encoded = serde_json::to_string(&envelope).unwrap();
            assert!(encoded.len() < 192);
            assert!(encoded.starts_with(
                "{\"schema_version\":\"ai-security-scanner.windows-installer-runtime-cache/v1\""
            ));
            assert!(encoded.contains(&format!("\"result_class\":\"{encoded_class}\"")));
            assert!(encoded.contains(&format!("\"exit_code\":{expected_exit}")));
            assert!(encoded.ends_with("\"terminal\":\"complete\"}"));
            for forbidden in [
                "detail",
                "target",
                "path",
                "argument",
                "executable",
                "provider",
                "runtime_name",
                "manifest",
            ] {
                assert!(!encoded.contains(forbidden));
            }
        }
    }

    #[cfg(feature = "installer-runtime-cache")]
    #[test]
    fn windows_installer_runtime_cache_degrades_without_exposing_the_failure() {
        assert_eq!(
            windows_installer_runtime_cache_result(|| Ok(())),
            WindowsInstallerRuntimeCacheClass::Seeded
        );
        assert_eq!(
            windows_installer_runtime_cache_result(|| {
                Err(AppError::NotAuthorized(
                    "attacker-controlled package path and parser detail".into(),
                ))
            }),
            WindowsInstallerRuntimeCacheClass::Unavailable
        );
    }

    #[cfg(feature = "installer-runtime-cache")]
    #[test]
    fn windows_installer_runtime_cache_ignores_environment_overrides_but_rejects_cli_overrides() {
        validate_windows_installer_runtime_cache_option_sources(GlobalOptionSources {
            data_dir: Some(ValueSource::EnvVariable),
            managed_runtime_bundle: Some(ValueSource::EnvVariable),
        })
        .expect("inherited development overrides cannot redirect package cache seeding");

        for option_sources in [
            GlobalOptionSources {
                data_dir: Some(ValueSource::CommandLine),
                managed_runtime_bundle: None,
            },
            GlobalOptionSources {
                data_dir: None,
                managed_runtime_bundle: Some(ValueSource::CommandLine),
            },
        ] {
            assert!(
                validate_windows_installer_runtime_cache_option_sources(option_sources).is_err()
            );
        }
    }

    #[cfg(feature = "installer-runtime-cache")]
    #[test]
    fn windows_installer_runtime_cache_resolves_only_the_real_direct_package_sibling() {
        let temporary = tempfile::tempdir().unwrap();
        let package = temporary.path().join("package");
        fs::create_dir(&package).unwrap();
        let executable = package.join("ai-security-scanner-cli.exe");
        fs::write(&executable, b"test executable").unwrap();
        let direct = package.join("managed-runtime");
        fs::create_dir(&direct).unwrap();
        assert_eq!(
            exact_packaged_installer_runtime_bundle(&executable).unwrap(),
            direct.canonicalize().unwrap()
        );

        fs::remove_dir(&direct).unwrap();
        fs::create_dir_all(package.join("resources/managed-runtime")).unwrap();
        assert!(exact_packaged_installer_runtime_bundle(&executable).is_err());

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;

            let outside = temporary.path().join("outside-runtime");
            fs::create_dir(&outside).unwrap();
            symlink(&outside, &direct).unwrap();
            assert!(exact_packaged_installer_runtime_bundle(&executable).is_err());
            assert!(outside.is_dir());
        }
    }

    #[cfg(feature = "installer-runtime-cache")]
    #[test]
    fn windows_installer_runtime_cache_build_anchor_matches_the_staged_manifest() {
        use sha2::{Digest, Sha256};

        let manifest = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../runtime/staged/managed-runtime/manifest.json");
        let bytes = fs::read(manifest).expect("staged managed-runtime manifest");
        let actual = hex::encode(Sha256::digest(bytes));
        assert_eq!(
            installer_runtime_cache_manifest_digest_anchor()
                .expect("installer runtime-cache build anchor"),
            actual
        );
    }

    #[test]
    fn windows_installer_prerequisite_is_hidden_zero_input_and_early_dispatched() {
        let parsed = Cli::try_parse_from([
            "ai-security-scanner",
            "--json",
            "windows-installer-prerequisite",
        ])
        .expect("fixed installed-package prerequisite invocation");
        assert!(matches!(
            parsed.command,
            Command::WindowsInstallerPrerequisite
        ));
        assert!(!command_requires_exclusive_data_directory(&parsed.command));

        for unexpected in ["--action", "--path", "--executable", "--arguments"] {
            assert!(
                Cli::try_parse_from([
                    "ai-security-scanner",
                    "--json",
                    "windows-installer-prerequisite",
                    unexpected,
                    "caller-selected",
                ])
                .is_err(),
                "hidden package coordinator accepted {unexpected}",
            );
        }
    }

    #[test]
    fn windows_installer_prerequisite_envelopes_are_exact_redacted_and_bounded() {
        let fixtures = [
            (WindowsInstallerPrerequisiteClass::Ready, 0, false, "ready"),
            (
                WindowsInstallerPrerequisiteClass::Serviced,
                0,
                false,
                "serviced",
            ),
            (
                WindowsInstallerPrerequisiteClass::RestartRequired,
                10,
                true,
                "restart_required",
            ),
            (
                WindowsInstallerPrerequisiteClass::Cancelled,
                20,
                false,
                "cancelled",
            ),
            (
                WindowsInstallerPrerequisiteClass::Failed,
                30,
                false,
                "failed",
            ),
        ];
        for (result_class, expected_exit, expected_restart, encoded_class) in fixtures {
            let (exit_code, restart_required) = windows_installer_prerequisite_exit(&result_class);
            assert_eq!(exit_code, expected_exit);
            assert_eq!(restart_required, expected_restart);
            let envelope = WindowsInstallerPrerequisiteCoordinatorEnvelope {
                schema_version: "ai-security-scanner.windows-installer-prerequisite/v1",
                result_class,
                exit_code,
                restart_required,
                terminal: "complete",
            };
            let encoded = serde_json::to_string(&envelope).unwrap();
            assert!(encoded.len() < 256);
            assert!(encoded.starts_with(
                "{\"schema_version\":\"ai-security-scanner.windows-installer-prerequisite/v1\""
            ));
            assert!(encoded.contains(&format!("\"result_class\":\"{encoded_class}\"")));
            assert!(encoded.contains(&format!("\"exit_code\":{expected_exit}")));
            assert!(encoded.contains(&format!("\"restart_required\":{expected_restart}")));
            assert!(encoded.ends_with("\"terminal\":\"complete\"}"));
            for forbidden in [
                "detail",
                "target",
                "path",
                "argument",
                "executable",
                "provider",
                "runtime_name",
            ] {
                assert!(!encoded.contains(forbidden));
            }
        }
    }

    #[test]
    fn windows_installer_prerequisite_ignores_environment_overrides_but_rejects_cli_overrides() {
        validate_windows_installer_prerequisite_option_sources(GlobalOptionSources {
            data_dir: Some(ValueSource::EnvVariable),
            managed_runtime_bundle: Some(ValueSource::EnvVariable),
        })
        .expect("inherited development overrides cannot redirect package preparation");

        for option_sources in [
            GlobalOptionSources {
                data_dir: Some(ValueSource::CommandLine),
                managed_runtime_bundle: None,
            },
            GlobalOptionSources {
                data_dir: None,
                managed_runtime_bundle: Some(ValueSource::CommandLine),
            },
        ] {
            assert!(
                validate_windows_installer_prerequisite_option_sources(option_sources).is_err()
            );
        }
    }

    #[test]
    fn product_uninstall_cli_has_three_fixed_modes_and_a_legacy_scan_tools_alias() {
        for mode in ["app-only", "scan-tools", "verified-scan-tools", "all-data"] {
            let mut arguments = vec![
                "ai-security-scanner",
                "product-uninstall",
                "--mode",
                mode,
                "--non-interactive",
            ];
            if mode == "all-data" {
                arguments.extend(["--confirmation", ALL_DATA_CONFIRMATION]);
            }
            let parsed = Cli::try_parse_from(arguments).expect("fixed uninstall CLI mode");
            assert!(matches!(parsed.command, Command::ProductUninstall(_)));
        }
    }

    #[test]
    fn product_uninstall_accepts_the_hidden_bounded_coordinator_envelope() {
        let parsed = Cli::try_parse_from([
            "ai-security-scanner",
            "--json",
            "product-uninstall",
            "--mode",
            "app-only",
            "--non-interactive",
            "--coordinator-envelope",
        ])
        .expect("installed package coordinator invocation");
        let Command::ProductUninstall(args) = parsed.command else {
            panic!("product uninstall command");
        };
        assert!(args.coordinator_envelope);
    }

    #[test]
    fn product_uninstall_coordinator_envelope_is_complete_redacted_and_bounded() {
        let envelope = ProductUninstallCoordinatorEnvelope {
            schema_version: "ai-security-scanner.product-uninstall/v1",
            mode: ProductUninstallMode::AllData,
            result_class: ProductUninstallResultClass::CompletedWithRetainedState,
            exit_code: 10,
            retained_item_count: 129,
            retained_classes: vec![
                "compatibility_provider_image",
                "managed_runtime_state",
                "product_data",
            ],
            terminal: "complete",
        };
        let encoded = serde_json::to_string(&envelope).unwrap();

        assert!(encoded.len() < 512);
        assert!(
            encoded.starts_with("{\"schema_version\":\"ai-security-scanner.product-uninstall/v1\"")
        );
        assert!(encoded.ends_with("\"terminal\":\"complete\"}"));
        assert!(encoded.contains(
            "\"retained_classes\":[\"compatibility_provider_image\",\"managed_runtime_state\",\"product_data\"]"
        ));
        for forbidden in [
            "target",
            "path",
            "case_id",
            "runtime_name",
            "scanner_message",
        ] {
            assert!(!encoded.contains(forbidden));
        }
    }

    #[test]
    fn product_uninstall_rejects_an_arbitrary_data_directory_before_dispatch() {
        let parsed = Cli::try_parse_from([
            "ai-security-scanner",
            "--data-dir",
            "/tmp/not-the-installed-product-root",
            "product-uninstall",
            "--mode",
            "scan-tools",
            "--non-interactive",
        ])
        .unwrap();
        let Command::ProductUninstall(args) = &parsed.command else {
            panic!("product uninstall command");
        };
        let error = execute_product_uninstall_early(
            &parsed,
            args,
            GlobalOptionSources {
                data_dir: Some(ValueSource::CommandLine),
                managed_runtime_bundle: None,
            },
        )
        .expect_err("arbitrary destructive root must fail before mutation");
        assert!(error.to_string().contains("explicit global --data-dir"));
    }

    #[test]
    fn product_uninstall_ignores_inherited_global_overrides_but_not_explicit_ones() {
        validate_product_uninstall_option_sources(GlobalOptionSources {
            data_dir: Some(ValueSource::EnvVariable),
            managed_runtime_bundle: Some(ValueSource::EnvVariable),
        })
        .expect("inherited development overrides cannot redirect or block package uninstall");

        assert!(
            validate_product_uninstall_option_sources(GlobalOptionSources {
                data_dir: None,
                managed_runtime_bundle: Some(ValueSource::CommandLine),
            })
            .is_err()
        );
    }

    #[test]
    fn destructive_cross_process_commands_require_the_data_directory_lease() {
        let delete = Cli::try_parse_from([
            "ai-security-scanner",
            "case",
            "delete",
            "case-1",
            "--confirm-case-id",
            "case-1",
        ])
        .unwrap();
        let cleanup = Cli::try_parse_from([
            "ai-security-scanner",
            "runtime",
            "cleanup",
            "--case-id",
            "case-1",
            "--run-id",
            "run-1",
            "--confirm-run-id",
            "run-1",
        ])
        .unwrap();
        let cancel = Cli::try_parse_from([
            "ai-security-scanner",
            "scan",
            "cancel",
            "--case-id",
            "case-1",
            "--run-id",
            "run-1",
        ])
        .unwrap();
        let install =
            Cli::try_parse_from(["ai-security-scanner", "runtime", "managed", "install"]).unwrap();
        let qualify =
            Cli::try_parse_from(["ai-security-scanner", "runtime", "managed", "qualify"]).unwrap();
        let qualify_egress = Cli::try_parse_from([
            "ai-security-scanner",
            "runtime",
            "managed",
            "qualify-egress",
        ])
        .unwrap();
        let status =
            Cli::try_parse_from(["ai-security-scanner", "runtime", "managed", "status"]).unwrap();
        let doctor = Cli::try_parse_from(["ai-security-scanner", "doctor"]).unwrap();

        assert!(command_requires_exclusive_data_directory(&delete.command));
        assert!(command_requires_exclusive_data_directory(&cleanup.command));
        assert!(command_requires_exclusive_data_directory(&cancel.command));
        assert!(command_requires_exclusive_data_directory(&install.command));
        assert!(command_requires_exclusive_data_directory(&qualify.command));
        assert!(command_requires_exclusive_data_directory(
            &qualify_egress.command
        ));
        assert!(command_requires_exclusive_data_directory(&status.command));
        assert!(!command_requires_exclusive_data_directory(&doctor.command));
        assert!(command_is_managed_runtime_status(&status.command));
        assert!(!command_is_managed_runtime_status(&install.command));
        assert!(!command_is_managed_runtime_status(&qualify.command));
        assert!(!command_is_managed_runtime_status(&doctor.command));
    }

    #[test]
    fn cli_accepts_a_release_approved_local_image_directory_override() {
        let cli = Cli::try_parse_from([
            "ai-security-scanner",
            "--release-approved-local-image-directory",
            "/release-images",
            "engine",
            "list",
        ])
        .expect("parse local image directory override");

        assert_eq!(
            cli.release_approved_local_image_directory,
            Some(PathBuf::from("/release-images"))
        );
    }

    #[tokio::test]
    async fn cli_cancel_fails_closed_when_the_data_directory_lease_is_owned() {
        let temporary = tempfile::tempdir().expect("temporary data directory");
        let held = DataDirectoryExclusiveLease::acquire(temporary.path()).expect("first lease");
        let expected = DataDirectoryExclusiveLease::acquire(temporary.path())
            .expect_err("second lease must be refused")
            .to_string();
        let cli = Cli {
            data_dir: Some(temporary.path().to_path_buf()),
            managed_runtime_bundle: None,
            release_approved_local_image_directory: None,
            json: true,
            command: Command::Scan {
                command: ScanCommand::Cancel(ScanTransitionArgs {
                    case_id: "case-1".into(),
                    run_id: "run-1".into(),
                }),
            },
        };

        let error = execute(cli, GlobalOptionSources::default())
            .await
            .expect_err("owned data directory must block CLI cancellation");
        assert_eq!(error.to_string(), expected);
        drop(held);
    }

    #[test]
    fn scan_cancel_help_limits_cli_cancellation_to_never_started_plans() {
        let help = Cli::try_parse_from(["ai-security-scanner", "scan", "cancel", "--help"])
            .expect_err("help exits through clap")
            .to_string();

        assert!(help.contains("queued or not_executed"), "{help}");
        assert!(
            help.contains("no live status or recorded outcome"),
            "{help}"
        );
        assert!(
            help.contains("queued_for_resume work from an ended attempt"),
            "{help}"
        );
        assert!(
            help.contains("Only queued work changes to cancelled"),
            "{help}"
        );
        assert!(help.contains("nothing queued is refused"), "{help}");
        assert!(help.contains("Preparing, running, or paused"), "{help}");
        assert!(help.contains("desktop scan controls"), "{help}");
        assert!(help.contains("already reached an outcome"), "{help}");
    }

    #[test]
    fn managed_egress_qualification_envelope_is_exact_and_no_upstream() {
        let image = format!(
            "ghcr.io/teddashh/ai-security-scanner-egress-gateway@sha256:{}",
            "1".repeat(64)
        );
        let result = managed_egress_gateway_qualification_value(
            managed_qualification_preflight(),
            ManagedGatewayQualification {
                image: image.clone(),
                gateway_container_id: "2".repeat(64),
                probe_container_id: "3".repeat(64),
                internal_network_id: "4".repeat(64),
                uplink_network_id: "5".repeat(64),
                policy_sha256: "6".repeat(64),
                reachability_probe: "socks5_no_connect_greeting".into(),
                gateway_reachable: true,
                upstream_connect_attempted: false,
                cleanup:
                    ai_security_scanner_lib::managed_network::ManagedGatewayQualificationCleanup {
                        gateway_container_removed: true,
                        probe_container_removed: true,
                        internal_network_removed: true,
                        uplink_network_removed: true,
                        policy_file_removed: true,
                        status_directory_removed: true,
                        registry_record_removed: true,
                    },
            },
            &image,
        )
        .expect("qualification envelope");

        assert_eq!(
            result.pointer("/qualification_kind"),
            Some(&json!("managed_egress_gateway_readiness"))
        );
        assert_eq!(
            result.pointer("/gateway/backend"),
            Some(&json!("pinned_container"))
        );
        assert_eq!(result.pointer("/gateway/ready"), Some(&json!(true)));
        assert_eq!(
            result.pointer("/gateway/scanner_reachable"),
            Some(&json!(true))
        );
        assert_eq!(
            result.pointer("/gateway/upstream_connection_attempted"),
            Some(&json!(false))
        );
        assert_eq!(
            result.pointer("/cleanup/registry_record_removed"),
            Some(&json!(true))
        );
    }

    #[test]
    fn managed_egress_qualification_refuses_upstream_or_incomplete_cleanup_claims() {
        let image = format!(
            "ghcr.io/teddashh/ai-security-scanner-egress-gateway@sha256:{}",
            "1".repeat(64)
        );
        let qualification = |upstream, registry_removed| ManagedGatewayQualification {
            image: image.clone(),
            gateway_container_id: "2".repeat(64),
            probe_container_id: "3".repeat(64),
            internal_network_id: "4".repeat(64),
            uplink_network_id: "5".repeat(64),
            policy_sha256: "6".repeat(64),
            reachability_probe: "socks5_no_connect_greeting".into(),
            gateway_reachable: true,
            upstream_connect_attempted: upstream,
            cleanup: ai_security_scanner_lib::managed_network::ManagedGatewayQualificationCleanup {
                gateway_container_removed: true,
                probe_container_removed: true,
                internal_network_removed: true,
                uplink_network_removed: true,
                policy_file_removed: true,
                status_directory_removed: true,
                registry_record_removed: registry_removed,
            },
        };

        assert!(
            managed_egress_gateway_qualification_value(
                managed_qualification_preflight(),
                qualification(true, true),
                &image,
            )
            .is_err()
        );
        assert!(
            managed_egress_gateway_qualification_value(
                managed_qualification_preflight(),
                qualification(false, false),
                &image,
            )
            .is_err()
        );
    }

    #[test]
    fn fixed_managed_container_qualification_runs_offline_and_cleans_up() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let evidence_root = temporary.path().join("qualification");
        let runtime = FakeContainerRuntime::default();
        runtime.set_behavior(FakeRunBehavior {
            exit_code: Some(0),
            stdout: b"qualification stdout\n".to_vec(),
            stderr: b"qualification stderr\n".to_vec(),
            output_files: BTreeMap::from([("gitleaks.json".into(), b"[]\n".to_vec())]),
        });
        let engines = EngineRegistry::load_builtin().expect("catalog");

        let result = execute_fixed_managed_container_qualification(
            &runtime,
            managed_qualification_preflight(),
            &engines,
            &evidence_root,
        )
        .expect("qualification");

        assert_eq!(result.pointer("/status"), Some(&json!("passed")));
        assert_eq!(
            result.pointer("/runtime/provider"),
            Some(&json!("managed_local"))
        );
        assert_eq!(
            result.pointer("/container/image"),
            Some(&json!(MANAGED_RUNTIME_QUALIFICATION_IMAGE))
        );
        assert_eq!(
            result.pointer("/container/cleanup_removed"),
            Some(&json!(true))
        );
        assert_eq!(result.pointer("/evidence/finding_count"), Some(&json!(0)));
        let calls = runtime.calls();
        assert_eq!(calls.len(), 4);
        assert_eq!(calls[0], RuntimeCall::VerifyNetwork("disabled".into()));
        assert_eq!(
            calls[1],
            RuntimeCall::Pull(MANAGED_RUNTIME_QUALIFICATION_IMAGE.into())
        );
        let RuntimeCall::Run(run_name) = &calls[2] else {
            panic!("expected fixed runtime run");
        };
        let RuntimeCall::Cleanup(cleanup_name) = &calls[3] else {
            panic!("expected fixed runtime cleanup");
        };
        assert_eq!(run_name, cleanup_name);

        let qualification_scan_root = evidence_root
            .join(MANAGED_RUNTIME_QUALIFICATION_CASE_ID)
            .join(MANAGED_RUNTIME_QUALIFICATION_SCAN_RUN_ID);
        let engine_runs = fs::read_dir(&qualification_scan_root)
            .expect("compact qualification scan root")
            .collect::<Result<Vec<_>, _>>()
            .expect("qualification engine-run entries");
        assert_eq!(engine_runs.len(), 1);
        let projected_cid_file = engine_runs[0]
            .path()
            .join("attempt-1")
            .join("control")
            .join("container-00000000000000000000000000000000.cid");
        let relative_cid_file = projected_cid_file
            .strip_prefix(&evidence_root)
            .expect("qualification CID file remains below evidence root");
        assert!(
            relative_cid_file.to_string_lossy().len() < 128,
            "release qualification reintroduced an unnecessarily long CID path"
        );
        assert!(!evidence_root.join("release-qualification").exists());
    }

    #[test]
    fn fixed_managed_container_qualification_fails_closed_on_cleanup_error() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let runtime = FakeContainerRuntime::default();
        runtime.set_behavior(FakeRunBehavior {
            exit_code: Some(0),
            stdout: Vec::new(),
            stderr: Vec::new(),
            output_files: BTreeMap::from([("gitleaks.json".into(), b"[]\n".to_vec())]),
        });
        runtime.set_fail_cleanup(true);
        let engines = EngineRegistry::load_builtin().expect("catalog");

        let error = execute_fixed_managed_container_qualification(
            &runtime,
            managed_qualification_preflight(),
            &engines,
            &temporary.path().join("qualification"),
        )
        .expect_err("cleanup failure must fail qualification");

        assert!(error.to_string().contains("fake cleanup failure"));
    }

    #[test]
    fn fixed_managed_container_qualification_rejects_compatibility_runtime() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let runtime = FakeContainerRuntime::default();
        let engines = EngineRegistry::load_builtin().expect("catalog");
        let preflight = RuntimePreflight {
            provider: RuntimeProvider::Docker,
            server_version: "compatibility".into(),
            security_options: "unknown".into(),
            command_provenance: RuntimeCommandProvenance::Compatibility,
        };

        let error = execute_fixed_managed_container_qualification(
            &runtime,
            preflight,
            &engines,
            &temporary.path().join("qualification"),
        )
        .expect_err("compatibility runtime must not qualify as managed-local");

        assert!(
            error
                .to_string()
                .contains("managed-local command provenance")
        );
        assert!(runtime.calls().is_empty());
    }

    #[test]
    fn fixed_managed_container_qualification_rejects_findings_after_cleanup() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let runtime = FakeContainerRuntime::default();
        runtime.set_behavior(FakeRunBehavior {
            exit_code: Some(0),
            stdout: Vec::new(),
            stderr: Vec::new(),
            output_files: BTreeMap::from([(
                "gitleaks.json".into(),
                br#"[{"RuleID":"unexpected"}]"#.to_vec(),
            )]),
        });
        let engines = EngineRegistry::load_builtin().expect("catalog");

        let error = execute_fixed_managed_container_qualification(
            &runtime,
            managed_qualification_preflight(),
            &engines,
            &temporary.path().join("qualification"),
        )
        .expect_err("unexpected finding must fail qualification");

        assert!(error.to_string().contains("unexpectedly produced findings"));
        assert!(matches!(
            runtime.calls().last(),
            Some(RuntimeCall::Cleanup(_))
        ));
    }

    #[test]
    fn standalone_live_scan_controls_fail_closed_with_exact_case_and_run() {
        for action in ["start", "pause", "resume", "cancel"] {
            let error = out_of_process_scan_control_error(action, "case-17", "run-23");
            let AppError::NotAvailable(message) = error else {
                panic!("live scan control did not return NotAvailable");
            };
            assert!(message.contains(action));
            assert!(message.contains("case-17"));
            assert!(message.contains("run-23"));
            assert!(message.contains("use the desktop scan controls"));
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn packaged_linux_cli_checks_tauri_deb_rpm_and_appimage_resource_layout() {
        let executable = Path::new("/mounted-or-installed/usr/bin/ai-security-scanner-cli");
        let candidates = packaged_managed_runtime_candidates(executable);
        assert!(candidates.contains(&PathBuf::from(
            "/mounted-or-installed/usr/lib/ai-security-scanner/managed-runtime"
        )));
    }

    #[test]
    fn parses_case_bound_cleanup_confirmation() {
        let cli = Cli::try_parse_from([
            "ai-security-scanner",
            "runtime",
            "cleanup",
            "--case-id",
            "case-1",
            "--run-id",
            "run-1",
            "--confirm-run-id",
            "run-1",
        ])
        .expect("cleanup CLI");
        assert!(matches!(
            cli.command,
            Command::Runtime {
                command: RuntimeCommand::Cleanup { .. }
            }
        ));
    }

    #[test]
    fn parses_separately_confirmed_case_artifact_deletion() {
        let cli = Cli::try_parse_from([
            "ai-security-scanner",
            "case",
            "delete-artifacts",
            "case-1",
            "--exact-path",
            "/private/artifacts/case-1",
            "--confirmation",
            "DELETE case-1",
        ])
        .expect("case artifact deletion CLI");
        assert!(matches!(
            cli.command,
            Command::Case {
                command: CaseCommand::DeleteArtifacts { .. }
            }
        ));
    }

    #[test]
    fn html_export_defaults_to_english_and_accepts_the_closed_report_locale() {
        let default_cli = Cli::try_parse_from([
            "ai-security-scanner",
            "export",
            "create",
            "--case-id",
            "case-1",
            "--run-id",
            "run-1",
            "--format",
            "html",
            "--destination",
            "report.html",
        ])
        .expect("html export CLI");
        match default_cli.command {
            Command::Export {
                command: ExportCommand::Create(args),
            } => {
                assert_eq!(args.locale, ReportLocaleArg::En);
                assert_eq!(ReportLocale::from(args.locale), ReportLocale::En);
            }
            other => panic!("unexpected command: {other:?}"),
        }

        let chinese_cli = Cli::try_parse_from([
            "ai-security-scanner",
            "export",
            "create",
            "--case-id",
            "case-1",
            "--run-id",
            "run-1",
            "--format",
            "html",
            "--destination",
            "report.zh-Hant.html",
            "--locale",
            "zh-Hant",
        ])
        .expect("zh-Hant html export CLI");
        match chinese_cli.command {
            Command::Export {
                command: ExportCommand::Create(args),
            } => {
                assert_eq!(args.locale, ReportLocaleArg::ZhHant);
                assert_eq!(ReportLocale::from(args.locale), ReportLocale::ZhHant);
            }
            other => panic!("unexpected command: {other:?}"),
        }

        assert!(
            Cli::try_parse_from([
                "ai-security-scanner",
                "export",
                "create",
                "--case-id",
                "case-1",
                "--run-id",
                "run-1",
                "--format",
                "html",
                "--destination",
                "report.html",
                "--locale",
                "fr",
            ])
            .is_err()
        );
    }

    #[test]
    fn raw_export_requires_explicit_acknowledgement() {
        let result = Cli::try_parse_from([
            "ai-security-scanner",
            "export",
            "create",
            "--case-id",
            "case-1",
            "--run-id",
            "run-1",
            "--format",
            "case-bundle",
            "--destination",
            "out.case.tar.gz",
            "--include-raw-artifacts",
        ]);
        assert!(result.is_err());
    }

    #[test]
    fn source_upsert_exposes_no_free_form_secret_or_metadata_argument() {
        let help = Cli::try_parse_from(["ai-security-scanner", "source", "upsert", "--help"])
            .expect_err("help exits through clap")
            .to_string();
        for forbidden in ["password", "credential", "token", "metadata-json"] {
            assert!(!help.to_ascii_lowercase().contains(forbidden));
        }
    }

    #[test]
    fn scope_approve_help_marks_every_external_permission_as_requiring_a_document() {
        let help = Cli::try_parse_from(["ai-security-scanner", "scope", "approve", "--help"])
            .expect_err("help exits through clap")
            .to_string();

        for permission in [
            "passive-external-discovery",
            "low-impact-external-connection",
            "active-external-testing",
        ] {
            assert!(
                help.contains(permission),
                "help omitted {permission}: {help}"
            );
        }
        assert!(help.contains("require --external-scope"), "{help}");
        assert!(help.contains("--external-scope <PATH>"), "{help}");
        assert!(
            help.contains("Absolute path to a regular file explicitly selected by the user"),
            "{help}"
        );
    }

    #[test]
    fn scope_approve_external_permissions_round_trip_canonical_scope_and_output() {
        let fixture = CliScopeFixture::new();
        let (case_id, asset_id) = fixture.discovered_domain();
        let documents = tempfile::tempdir().expect("scope document directory");
        let cases = [
            (
                PermissionArg::PassiveExternalDiscovery,
                ScanPermission::PassiveExternalDiscovery,
                "passive_public_discovery",
                ExternalActivity::PassivePublicDiscovery,
            ),
            (
                PermissionArg::LowImpactExternalConnection,
                ScanPermission::LowImpactExternalConnection,
                "low_impact_external",
                ExternalActivity::LowImpactExternal,
            ),
            (
                PermissionArg::ActiveExternalTesting,
                ScanPermission::ActiveExternalTesting,
                "active_external",
                ExternalActivity::ActiveExternal,
            ),
        ];

        for (index, (argument, permission, activity_name, activity)) in
            cases.into_iter().enumerate()
        {
            let path = documents.path().join(format!("scope-{index}.json"));
            write_external_scope(&path, activity_name);
            execute_scope(
                ScopeCommand::Approve(scope_approve_args(
                    &case_id,
                    &asset_id,
                    argument,
                    Some(path),
                )),
                &fixture.service(),
                true,
            )
            .expect("external permission approval");

            let stored = fixture.service().show_case(&case_id).expect("stored case");
            let external = stored
                .scope_grants
                .iter()
                .find(|grant| grant.permission == permission)
                .and_then(|grant| grant.external_scope.as_ref())
                .expect("canonical external scope grant");
            assert_eq!(
                external.target,
                CanonicalTarget::Hostname("shop.example.test".into())
            );
            assert_eq!(external.ports, BTreeSet::from([443]));
            assert_eq!(external.activity, activity);
            assert_eq!(external.rate_policy.requests_per_second, 2);
            assert!(!external.template_policy.allow_denial_of_service);
            assert!(!external.template_policy.allow_credential_attacks);
        }

        let grants = fixture
            .service()
            .show_case(&case_id)
            .expect("stored case")
            .scope_grants;
        assert_eq!(grants.len(), 3);
        let output = scope_approval_output(grants);
        let compact = serde_json::to_string(&output).expect("compact command output");
        let human = serde_json::to_string_pretty(&output).expect("human command output");
        for rendered in [&compact, &human] {
            assert!(rendered.contains("external_scope"));
            assert!(rendered.contains("shop.example.test"));
            assert!(rendered.contains("requests_per_second"));
            assert!(rendered.contains("allow_denial_of_service"));
        }
    }

    #[test]
    fn external_permission_without_document_fails_in_cli_before_case_lookup() {
        let fixture = CliScopeFixture::new();
        let error = execute_scope(
            ScopeCommand::Approve(scope_approve_args(
                "case-that-must-not-be-read",
                "asset-that-must-not-be-read",
                PermissionArg::LowImpactExternalConnection,
                None,
            )),
            &fixture.service(),
            true,
        )
        .expect_err("missing external scope must fail");

        let message = error.to_string();
        assert!(message.contains("external permission requires an explicit scope document"));
        assert!(message.contains("--external-scope"));
        assert!(!message.contains("case not found"));
    }

    #[test]
    fn invalid_external_scope_files_fail_distinctly_before_case_lookup() {
        let fixture = CliScopeFixture::new();
        let documents = tempfile::tempdir().expect("scope document directory");
        let missing = documents.path().join("missing.json");
        let directory = documents.path().join("directory.json");
        fs::create_dir(&directory).expect("non-regular scope fixture");
        let malformed = documents.path().join("malformed.json");
        fs::write(&malformed, b"{").expect("malformed scope fixture");
        let unknown = documents.path().join("unknown.json");
        let mut unknown_value = external_scope_value("low_impact_external");
        unknown_value
            .as_object_mut()
            .expect("scope object")
            .insert("unexpected_policy".into(), Value::Bool(true));
        fs::write(
            &unknown,
            serde_json::to_vec_pretty(&unknown_value).expect("unknown-field JSON"),
        )
        .expect("unknown-field scope fixture");

        let checks = [
            (missing, "could not be inspected"),
            (directory, "is not a regular file"),
            (malformed, "is not valid JSON"),
            (unknown, "unknown field `unexpected_policy`"),
        ];
        let mut messages = Vec::new();
        for (path, expected) in checks {
            let error = execute_scope(
                ScopeCommand::Approve(scope_approve_args(
                    "case-that-must-not-be-read",
                    "asset-that-must-not-be-read",
                    PermissionArg::LowImpactExternalConnection,
                    Some(path.clone()),
                )),
                &fixture.service(),
                true,
            )
            .expect_err("invalid external scope document must fail");
            let message = error.to_string();
            assert!(message.contains(&path.display().to_string()), "{message}");
            assert!(message.contains(expected), "{message}");
            assert!(!message.contains("case not found"), "{message}");
            messages.push(message);
        }
        for left in 0..messages.len() {
            for right in (left + 1)..messages.len() {
                assert_ne!(messages[left], messages[right]);
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn external_scope_document_symlink_is_rejected_before_case_lookup() {
        use std::os::unix::fs::symlink;

        let fixture = CliScopeFixture::new();
        let documents = tempfile::tempdir().expect("scope document directory");
        let target = documents.path().join("valid-target.json");
        write_external_scope(&target, "low_impact_external");
        let selected = documents.path().join("selected-symlink.json");
        symlink(&target, &selected).expect("scope document symlink");

        let error = execute_scope(
            ScopeCommand::Approve(scope_approve_args(
                "case-that-must-not-be-read",
                "asset-that-must-not-be-read",
                PermissionArg::LowImpactExternalConnection,
                Some(selected.clone()),
            )),
            &fixture.service(),
            true,
        )
        .expect_err("symlinked external scope document must fail");

        assert_eq!(
            error.to_string(),
            format!(
                "invalid request: external scope document \"{}\" contains a symlink",
                selected.display()
            )
        );
        assert!(fixture.service().list_cases().unwrap().is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn external_scope_intermediate_directory_symlink_is_rejected_before_case_lookup() {
        use std::os::unix::fs::symlink;

        let fixture = CliScopeFixture::new();
        let documents = tempfile::tempdir().expect("scope document directory");
        let resolved_directory = documents.path().join("resolved-directory");
        fs::create_dir(&resolved_directory).expect("resolved scope directory");
        let target = resolved_directory.join("valid-scope.json");
        write_external_scope(&target, "low_impact_external");
        let linked_directory = documents.path().join("linked-directory");
        symlink(&resolved_directory, &linked_directory).expect("intermediate directory symlink");
        let selected = linked_directory.join("valid-scope.json");

        let error = execute_scope(
            ScopeCommand::Approve(scope_approve_args(
                "case-that-must-not-be-read",
                "asset-that-must-not-be-read",
                PermissionArg::LowImpactExternalConnection,
                Some(selected.clone()),
            )),
            &fixture.service(),
            true,
        )
        .expect_err("external scope beneath a symlinked directory must fail");

        assert_eq!(
            error.to_string(),
            format!(
                "invalid request: external scope document \"{}\" contains a symlink",
                selected.display()
            )
        );
        assert!(fixture.service().list_cases().unwrap().is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn external_scope_document_replaced_by_symlink_before_open_is_not_followed() {
        use std::os::unix::fs::symlink;

        let fixture = CliScopeFixture::new();
        let documents = tempfile::tempdir().expect("scope document directory");
        let selected = documents.path().join("selected-scope.json");
        write_external_scope(&selected, "low_impact_external");
        let target = documents.path().join("replacement-target.json");
        write_external_scope(&target, "low_impact_external");

        let selected_for_hook = selected.clone();
        EXTERNAL_SCOPE_BEFORE_OPEN_HOOK.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                fs::remove_file(&selected_for_hook).expect("remove inspected scope document");
                symlink(&target, &selected_for_hook).expect("replace scope document with symlink");
            }));
        });

        let error = execute_scope(
            ScopeCommand::Approve(scope_approve_args(
                "case-that-must-not-be-read",
                "asset-that-must-not-be-read",
                PermissionArg::LowImpactExternalConnection,
                Some(selected.clone()),
            )),
            &fixture.service(),
            true,
        )
        .expect_err("replacement symlink must not be followed");

        let message = error.to_string();
        assert!(
            message.contains(&format!(
                "external scope document \"{}\" could not be opened without following links",
                selected.display()
            )),
            "{message}"
        );
        assert!(!message.contains("case not found"), "{message}");
        assert!(fixture.service().list_cases().unwrap().is_empty());
    }

    #[test]
    fn external_scope_activity_mismatch_is_still_refused_by_service() {
        let fixture = CliScopeFixture::new();
        let (case_id, asset_id) = fixture.discovered_domain();
        let documents = tempfile::tempdir().expect("scope document directory");
        let path = documents.path().join("mismatched.json");
        write_external_scope(&path, "active_external");

        let error = execute_scope(
            ScopeCommand::Approve(scope_approve_args(
                &case_id,
                &asset_id,
                PermissionArg::LowImpactExternalConnection,
                Some(path),
            )),
            &fixture.service(),
            true,
        )
        .expect_err("service must reject mismatched external activity");

        assert!(
            error
                .to_string()
                .contains("external activity does not match the approved scan permission")
        );
        assert!(
            fixture
                .service()
                .show_case(&case_id)
                .expect("stored case")
                .scope_grants
                .is_empty()
        );
    }

    #[test]
    fn external_scope_without_external_permission_keeps_service_error() {
        let fixture = CliScopeFixture::new();
        let (case_id, asset_id) = fixture.discovered_domain();
        let documents = tempfile::tempdir().expect("scope document directory");
        let path = documents.path().join("inventory.json");
        write_external_scope(&path, "low_impact_external");

        let error = execute_scope(
            ScopeCommand::Approve(scope_approve_args(
                &case_id,
                &asset_id,
                PermissionArg::InventoryRead,
                Some(path),
            )),
            &fixture.service(),
            true,
        )
        .expect_err("service must reject external scope without external permission");

        assert!(
            error
                .to_string()
                .contains("external scope details were supplied without an external permission")
        );
        assert!(
            fixture
                .service()
                .show_case(&case_id)
                .expect("stored case")
                .scope_grants
                .is_empty()
        );
    }

    #[test]
    fn parses_explicit_scope_and_plan_commands() {
        let scope = Cli::try_parse_from([
            "ai-security-scanner",
            "scope",
            "approve",
            "--case-id",
            "case-1",
            "--asset-id",
            "asset-1",
            "--permission",
            "inventory-read,configuration-read",
            "--confirmed-by",
            "local-owner",
        ])
        .expect("scope CLI");
        assert!(matches!(scope.command, Command::Scope { .. }));

        let plan = Cli::try_parse_from([
            "ai-security-scanner",
            "scan",
            "plan",
            "--case-id",
            "case-1",
            "--engine",
            "prowler,cloudquery",
        ])
        .expect("scan plan CLI");
        assert!(matches!(plan.command, Command::Scan { .. }));

        let start = Cli::try_parse_from([
            "ai-security-scanner",
            "scan",
            "start",
            "--case-id",
            "case-1",
            "--run-id",
            "run-1",
        ])
        .expect("scan start CLI");
        assert!(matches!(start.command, Command::Scan { .. }));

        let show = Cli::try_parse_from(["ai-security-scanner", "engine", "show", "prowler"])
            .expect("backward-compatible engine show CLI");
        assert!(matches!(show.command, Command::Engine { .. }));
    }

    #[test]
    fn parses_reversible_finding_group_commands() {
        let group = Cli::try_parse_from([
            "ai-security-scanner",
            "finding",
            "group",
            "--case-id",
            "case-1",
            "--title",
            "Related observations",
            "--finding-id",
            "finding-a,finding-b",
            "--rationale",
            "Review together without merging evidence",
            "--grouped-by",
            "local-reviewer",
        ])
        .expect("finding group CLI");
        let Command::Finding {
            command: FindingCommand::Group(args),
        } = group.command
        else {
            panic!("expected finding group command");
        };
        assert_eq!(args.finding_id, ["finding-a", "finding-b"]);

        let ungroup = Cli::try_parse_from([
            "ai-security-scanner",
            "finding",
            "ungroup",
            "--case-id",
            "case-1",
            "--group-id",
            "group-1",
            "--removed-by",
            "local-reviewer",
            "--reason",
            "The relationship was disproven",
        ])
        .expect("finding ungroup CLI");
        assert!(matches!(
            ungroup.command,
            Command::Finding {
                command: FindingCommand::Ungroup(_)
            }
        ));

        let one_member = Cli::try_parse_from([
            "ai-security-scanner",
            "finding",
            "group",
            "--case-id",
            "case-1",
            "--title",
            "Too small",
            "--finding-id",
            "finding-a",
            "--rationale",
            "One member is not a group",
            "--grouped-by",
            "local-reviewer",
        ])
        .expect("CLI syntax is separate from authoritative membership validation");
        let Command::Finding {
            command: FindingCommand::Group(args),
        } = one_member.command
        else {
            panic!("expected finding group command");
        };
        assert_eq!(args.finding_id, ["finding-a"]);
    }

    #[test]
    fn parses_rfc3339_expiry() {
        let parsed = parse_rfc3339("2030-01-02T03:04:05Z").expect("timestamp");
        assert_eq!(parsed.to_rfc3339(), "2030-01-02T03:04:05+00:00");
        assert!(parse_rfc3339("tomorrow").is_err());
    }

    #[test]
    fn not_executed_is_a_terminal_engine_state() {
        let encoded = serde_json::to_string(&EngineRunStatus::NotExecuted).expect("serialize");
        assert_eq!(encoded, "\"not_executed\"");
    }

    #[test]
    fn engine_readiness_fails_closed_on_compatibility_runnable() {
        let engines = EngineRegistry::load_builtin().expect("catalog");
        let adapters = builtin_adapter_registry().expect("adapters");
        let mut manifest = engines.get("prowler").expect("prowler").clone();
        // This is a release-contract fixture, independent of whether the
        // current built-in Prowler artifact has since been published.
        manifest.compatibility.runnable = false;
        manifest.compatibility.blocked_by = vec!["test_artifact_not_released".into()];
        manifest.default_enabled = false;
        let inspection = engine_inspection(&manifest, &adapters);
        assert_eq!(
            inspection.pointer("/readiness/dispatchable"),
            Some(&Value::Bool(false))
        );
        assert_eq!(
            inspection.pointer("/readiness/compatibility_runnable"),
            Some(&Value::Bool(false))
        );
    }

    #[test]
    fn connector_artifact_root_is_private_and_scoped_to_one_case() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let artifact_root = temporary.path().join("artifacts");
        fs::create_dir(&artifact_root).expect("artifact root");

        let connector_root =
            case_connector_artifact_root(&artifact_root, "case_A-1").expect("case connector root");
        assert_eq!(
            connector_root,
            artifact_root
                .canonicalize()
                .expect("canonical artifact root")
                .join("case_A-1")
                .join("connector-snapshots")
        );
        assert_eq!(
            case_connector_artifact_root(&artifact_root, "case_A-1")
                .expect("stable connector root"),
            connector_root
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let mode = fs::metadata(&connector_root)
                .expect("connector root metadata")
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o700);
        }
    }

    #[test]
    fn connector_artifact_root_rejects_unsafe_case_paths() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let artifact_root = temporary.path().join("artifacts");
        fs::create_dir(&artifact_root).expect("artifact root");

        for unsafe_case_id in ["", ".", "..", "../outside", "case/path", "case\\path"] {
            assert!(
                case_connector_artifact_root(&artifact_root, unsafe_case_id).is_err(),
                "unsafe case id was accepted: {unsafe_case_id:?}"
            );
        }
        assert!(case_connector_artifact_root(&artifact_root, &"a".repeat(129)).is_err());
        assert!(!temporary.path().join("outside").exists());
    }

    #[cfg(unix)]
    #[test]
    fn connector_artifact_root_rejects_symlinked_case_directory() {
        use std::os::unix::fs::symlink;

        let temporary = tempfile::tempdir().expect("temporary directory");
        let artifact_root = temporary.path().join("artifacts");
        let outside = temporary.path().join("outside");
        fs::create_dir(&artifact_root).expect("artifact root");
        fs::create_dir(&outside).expect("outside directory");
        symlink(&outside, artifact_root.join("case-1")).expect("case symlink");

        let result = case_connector_artifact_root(&artifact_root, "case-1");
        assert!(matches!(result, Err(AppError::NotAuthorized(_))));
        assert!(
            fs::read_dir(&outside)
                .expect("outside listing")
                .next()
                .is_none()
        );
    }

    #[test]
    fn case_artifact_deletion_removes_cli_connector_snapshots() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let artifact_root = temporary.path().join("artifacts");
        fs::create_dir(&artifact_root).expect("artifact root");
        let storage = Storage::open(temporary.path().join("casework.db")).expect("storage");
        let engines = EngineRegistry::load_builtin().expect("engine catalog");
        let adapters = builtin_adapter_registry().expect("adapter registry");
        let service = CaseService::new(
            &storage,
            &engines,
            &adapters,
            &artifact_root,
            temporary.path().join("integrity-signing-key"),
        );
        let case = service
            .create_case(&CreateCaseRequest {
                title: "CLI deletion fixture".into(),
                organization_name: "Example".into(),
                employee_range: "1-10".into(),
                assessment_intent: None,
                ai_generated_artifact: Default::default(),
                data_classes: vec![],
                requested_activities: vec![],
                source_kinds: vec![],
                not_applicable_source_kinds: vec![],
                declared_assets: vec![],
                notes: None,
            })
            .expect("case");
        let connector_root =
            case_connector_artifact_root(&artifact_root, &case.id).expect("case connector root");
        let connector_snapshot = connector_root.join("connector-snapshot-test.json");
        fs::write(&connector_snapshot, b"{}\n").expect("connector snapshot");
        let deletion = service.delete_case(&case.id).expect("database deletion");
        let result = service
            .delete_case_artifacts(
                &case.id,
                &deletion.artifacts.exact_path,
                &format!("DELETE {}", case.id),
            )
            .expect("confirmed artifact deletion");

        assert!(result.removed);
        assert!(!connector_snapshot.exists());
        assert!(!artifact_root.join(&case.id).exists());
    }
}
