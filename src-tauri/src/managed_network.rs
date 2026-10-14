use crate::container_runtime::{
    NetworkPolicy, PinnedImage, RuntimeCommandContext, RuntimeProvider,
};
use crate::domain::GatewayRefusalRecord;
use crate::error::{AppError, AppResult};
use crate::external_scope::{
    CanonicalTarget, ExternalActivity, ResolvedExternalPlan, TransportProtocol,
};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};
use uuid::Uuid;

const POLICY_SCHEMA_VERSION: &str = "2.0.0";
const REGISTRY_SCHEMA_VERSION: &str = "1.0.0";
const GATEWAY_PORT: u16 = 1080;
const MAX_POLICY_BYTES: usize = 2 * 1024 * 1024;
const MAX_REGISTRY_RECORD_BYTES: usize = 64 * 1024;
const MAX_REGISTRY_RECORDS: usize = 3_072;
const MAX_INSPECT_BYTES: usize = 2 * 1024 * 1024;
const MAX_GATEWAY_STATUS_BYTES: usize = 1024;
const MAX_DIAGNOSTIC_BYTES: usize = 4 * 1024;
const RUNTIME_COMMAND_TIMEOUT: Duration = Duration::from_secs(30);
const PRODUCT_UNINSTALL_GATEWAY_STOP_DEADLINE: Duration = Duration::from_secs(7 * 60);
const GATEWAY_IMAGE_PULL_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const MAX_DESTINATIONS: usize = 10_000;
const MAX_EXTERNAL_PLANS_PER_LEASE: usize = 128;
const MAX_AUTHORIZED_ENDPOINTS: usize = 10_000;
const GATEWAY_READY_TIMEOUT: Duration = Duration::from_secs(5);
const GATEWAY_READY_INTERVAL: Duration = Duration::from_millis(25);
const GATEWAY_CONNECT_PROBE_TIMEOUT: Duration = Duration::from_millis(50);
const MANAGED_LABEL_KEY: &str = "ai.security-scanner.managed";
const POLICY_LABEL_KEY: &str = "ai.security-scanner.policy-id";
const RESOURCE_ROLE_LABEL_KEY: &str = "ai.security-scanner.resource-role";
const UPLINK_RESOURCE_ROLE: &str = "gateway-uplink";
const GATEWAY_CONTAINER_RESOURCE_ROLE: &str = "egress-gateway";
const GATEWAY_PROBE_RESOURCE_ROLE: &str = "egress-gateway-probe";
const CONTAINER_POLICY_PATH: &str = "/run/ai-security-scanner/egress-policy.json";
const CONTAINER_PROBE_BINARY: &str = "/usr/local/bin/ai-security-scanner-egress-probe";
const GATEWAY_CONTAINER_USER_MEMORY_MB: u16 = 128;
const GATEWAY_CONTAINER_PIDS: u16 = 64;
const GATEWAY_PROBE_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_NETWORK_SUBNET_ATTEMPTS: usize = 24;
const MAX_NETWORK_CANDIDATE_SEARCH: usize = 4_096;

/// Bounded, non-secret identity copied into the durable execution checkpoint.
///
/// The runtime resource is never recovered by a name prefix. Reconciliation
/// requires this exact provider/name/id/policy tuple and re-inspects all labels
/// immediately before removing the network by its immutable runtime id.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ManagedNetworkIdentity {
    pub schema_version: String,
    pub provider: RuntimeProvider,
    pub network_name: String,
    pub network_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uplink_network_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uplink_network_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway_container_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway_container_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway_listener_ip: Option<IpAddr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway_image_repository: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway_image_digest: Option<String>,
    pub policy_id: String,
    pub policy_sha256: String,
    pub expires_at: DateTime<Utc>,
    pub provenance: EgressGatewayProvenance,
}

impl ManagedNetworkIdentity {
    pub fn validate(&self) -> AppResult<()> {
        if self.schema_version != REGISTRY_SCHEMA_VERSION {
            return Err(AppError::InvalidRequest(
                "managed-network checkpoint schema is unsupported".into(),
            ));
        }
        validate_network_name(&self.network_name)?;
        validate_runtime_id(&self.network_id)?;
        validate_policy_id(&self.policy_id)?;
        validate_network_policy_relation(&self.network_name, &self.policy_id)?;
        validate_optional_gateway_identity(
            &self.policy_id,
            self.uplink_network_name.as_deref(),
            self.uplink_network_id.as_deref(),
            self.gateway_container_name.as_deref(),
            self.gateway_container_id.as_deref(),
            self.gateway_listener_ip,
            self.gateway_image_repository.as_deref(),
            self.gateway_image_digest.as_deref(),
        )?;
        decode_sha256(&self.policy_sha256)?;
        validate_egress_provenance(&self.provenance)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ManagedNetworkOwner {
    pub case_id: String,
    pub scan_run_id: String,
    pub engine_run_id: String,
    pub attempt: u32,
}

impl ManagedNetworkOwner {
    pub fn new(
        case_id: impl Into<String>,
        scan_run_id: impl Into<String>,
        engine_run_id: impl Into<String>,
        attempt: u32,
    ) -> AppResult<Self> {
        let owner = Self {
            case_id: case_id.into(),
            scan_run_id: scan_run_id.into(),
            engine_run_id: engine_run_id.into(),
            attempt,
        };
        owner.validate()?;
        Ok(owner)
    }

    fn validate(&self) -> AppResult<()> {
        for (label, value) in [
            ("case", self.case_id.as_str()),
            ("scan run", self.scan_run_id.as_str()),
            ("engine run", self.engine_run_id.as_str()),
        ] {
            if value.is_empty()
                || value.len() > 256
                || !value.chars().all(|character| {
                    character.is_ascii_alphanumeric() || matches!(character, '-' | '_')
                })
            {
                return Err(AppError::InvalidRequest(format!(
                    "managed-network {label} identity is invalid"
                )));
            }
        }
        if self.attempt == 0 {
            return Err(AppError::InvalidRequest(
                "managed-network execution attempt must start at one".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
enum RegistryPhase {
    Intent,
    NetworkVerified,
    /// Final phase written by releases that used a native host process.
    Ready,
    UplinkVerified,
    PolicyReady,
    GatewayContainerVerified,
    ContainerReady,
}

impl RegistryPhase {
    fn sequence(&self) -> u8 {
        match self {
            Self::Intent => 0,
            Self::NetworkVerified => 1,
            Self::Ready => 2,
            Self::UplinkVerified => 3,
            Self::PolicyReady => 4,
            Self::GatewayContainerVerified => 5,
            Self::ContainerReady => 6,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ManagedNetworkRecord {
    schema_version: String,
    owner: ManagedNetworkOwner,
    provider: RuntimeProvider,
    network_name: String,
    policy_id: String,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    phase: RegistryPhase,
    network_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    uplink_network_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    uplink_network_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    gateway_container_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    gateway_container_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    gateway_listener_ip: Option<IpAddr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    gateway_image_repository: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    gateway_image_digest: Option<String>,
    policy_sha256: Option<String>,
}

/// Immutable release input for the first-party managed egress gateway image.
///
/// The repository and digest must come from a verified release manifest. This
/// type intentionally has no default and never accepts a tag-only reference,
/// so an unpublished or mutable image cannot silently enter production.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GatewayContainerSpec {
    repository: String,
    digest: String,
}

impl GatewayContainerSpec {
    pub fn new(repository: impl Into<String>, digest: impl Into<String>) -> AppResult<Self> {
        let repository = repository.into();
        if !crate::publication_origins::validate_gateway_repository(&repository) {
            return Err(AppError::EngineRegistry(
                "unrecognized gateway publication origin".into(),
            ));
        }
        let digest = digest.into();
        let image = PinnedImage::new(&repository, &digest)?;
        let reference = image.reference();
        let (repository, digest) = reference.rsplit_once('@').ok_or_else(|| {
            AppError::Internal("pinned gateway image reference lost its digest".into())
        })?;
        Ok(Self {
            repository: repository.to_owned(),
            digest: digest.to_owned(),
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

    fn validate(&self) -> AppResult<()> {
        let image = PinnedImage::new(&self.repository, &self.digest)?;
        if image.reference() != self.reference() {
            return Err(AppError::NotAuthorized(
                "managed gateway image identity is not canonical".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManagedNetworkCleanupOutcome {
    pub removed: bool,
    pub detail: String,
    /// Structured twin of the refusal sentence in `detail`. `None` means this
    /// cleanup did not read a gateway status document. `None` also covers a
    /// status read from a gateway that does not record refusals.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway_refusals: Option<GatewayRefusalRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ManagedGatewayQualificationCleanup {
    pub gateway_container_removed: bool,
    pub probe_container_removed: bool,
    pub internal_network_removed: bool,
    pub uplink_network_removed: bool,
    pub policy_file_removed: bool,
    pub status_directory_removed: bool,
    pub registry_record_removed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ManagedGatewayQualification {
    pub image: String,
    pub gateway_container_id: String,
    pub probe_container_id: String,
    pub internal_network_id: String,
    pub uplink_network_id: String,
    pub policy_sha256: String,
    pub reachability_probe: String,
    pub gateway_reachable: bool,
    pub upstream_connect_attempted: bool,
    pub cleanup: ManagedGatewayQualificationCleanup,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ManagedNetworkReconciliationSummary {
    pub reconciled: usize,
    pub incomplete: usize,
    pub details: Vec<String>,
}

/// Bounded uninstall-time result for disposable compatibility gateways.
///
/// `exact_stop_failures` means a Docker/Podman gateway named by a complete,
/// durable container identity could not be proven stopped. In contrast,
/// `retained_ambiguities` covers malformed, replaced, or otherwise
/// non-authoritative registry state that was left untouched.
/// `contact_inventory_incomplete` means the bounded registry itself could not
/// be completely enumerated, so an otherwise exact active gateway could be
/// hidden beyond the observed records. Callers must retain the application
/// controller for both an exact stop failure and incomplete contact inventory.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ManagedCompatibilityGatewayStopSummary {
    pub exact_gateways_found: usize,
    pub exact_gateways_stopped: usize,
    pub exact_stop_failures: usize,
    pub retained_ambiguities: usize,
    pub contact_inventory_incomplete: bool,
}

/// The file consumed by the isolated host-side SOCKS gateway.
///
/// It is intentionally derived only from already-frozen external plans. Creating this
/// policy does not imply that an engine is packaged, compatible, or runnable.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EgressGatewayPolicy {
    pub schema_version: String,
    pub policy_id: String,
    pub expires_at: DateTime<Utc>,
    pub listen_address: SocketAddr,
    pub allowed_client_network: IpNet,
    pub limits: EgressGatewayLimits,
    pub provenance: EgressGatewayProvenance,
    pub destinations: Vec<GatewayDestination>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum EgressGatewayProvenance {
    ExternalAssetGrants {
        case_id: String,
        grant_ids: Vec<String>,
        activities: Vec<ExternalActivity>,
    },
    ProviderService {
        case_id: String,
        source_id: String,
        source_kind: String,
        source_profile: String,
        manifest_id: String,
        manifest_revision: String,
    },
    /// Fixed, no-upstream release qualification. This is deliberately
    /// distinct from human asset grants and provider-service authorization.
    ReleaseQualification {
        case_id: String,
        qualification_id: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProviderServiceEgressRequest {
    pub case_id: String,
    pub source_id: String,
    pub source_kind: String,
    pub source_profile: String,
    pub manifest_id: String,
    pub manifest_revision: String,
    pub exact_destinations: Vec<String>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedProviderServicePlan {
    request: ProviderServiceEgressRequest,
    frozen_at: DateTime<Utc>,
    destinations: Vec<GatewayDestination>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EgressGatewayLimits {
    pub max_concurrency: usize,
    pub max_connections_per_second: usize,
    pub connect_timeout_seconds: u64,
    pub max_connection_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct GatewayDestination {
    pub hostname: Option<String>,
    pub addresses: BTreeSet<IpAddr>,
    pub ports: BTreeSet<u16>,
    pub allow_sensitive_networks: bool,
}

impl EgressGatewayPolicy {
    pub fn from_resolved_plans(
        policy_id: impl Into<String>,
        listen_address: SocketAddr,
        allowed_client_network: IpNet,
        plans: &[ResolvedExternalPlan],
        now: DateTime<Utc>,
    ) -> AppResult<Self> {
        let policy_id = policy_id.into();
        validate_policy_id(&policy_id)?;
        validate_bridge_network(allowed_client_network, listen_address.ip())?;
        if listen_address.port() != GATEWAY_PORT {
            return Err(AppError::InvalidRequest(format!(
                "egress gateway must listen on port {GATEWAY_PORT}"
            )));
        }
        if plans.is_empty() || plans.len() > MAX_EXTERNAL_PLANS_PER_LEASE {
            return Err(AppError::NotAuthorized(
                "managed egress requires one or more bounded frozen plans".into(),
            ));
        }

        let expected_case_id = plans[0].case_id.as_str();
        let mut expires_at = now + ChronoDuration::hours(24);
        let mut max_concurrency = usize::MAX;
        let mut max_connections_per_second = usize::MAX;
        let mut timeout_seconds = u64::MAX;
        let mut endpoint_count = 0_usize;
        let mut destinations = Vec::with_capacity(plans.len());
        let mut grant_ids = Vec::with_capacity(plans.len());
        let mut activities = BTreeSet::new();

        for plan in plans {
            validate_resolved_plan(plan, expected_case_id, now)?;
            grant_ids.push(plan.grant_id.clone());
            activities.insert(plan.activity);
            expires_at = expires_at.min(plan.expires_at);
            max_concurrency = max_concurrency.min(usize::from(plan.rate_policy.concurrency));
            max_connections_per_second =
                max_connections_per_second.min(usize::from(plan.rate_policy.requests_per_second));
            timeout_seconds = timeout_seconds.min(u64::from(plan.rate_policy.timeout_seconds));

            let plan_endpoints = plan
                .resolution
                .addresses
                .len()
                .checked_mul(plan.ports.len())
                .ok_or_else(|| {
                    AppError::InvalidRequest("external destination set is too large".into())
                })?;
            endpoint_count = endpoint_count.checked_add(plan_endpoints).ok_or_else(|| {
                AppError::InvalidRequest("external destination set is too large".into())
            })?;
            if endpoint_count > MAX_AUTHORIZED_ENDPOINTS {
                return Err(AppError::InvalidRequest(format!(
                    "managed egress supports at most {MAX_AUTHORIZED_ENDPOINTS} frozen address-port pairs"
                )));
            }
            if plan
                .resolution
                .addresses
                .iter()
                .any(|address| allowed_client_network.contains(address))
            {
                return Err(AppError::NotAuthorized(
                    "an authorized destination overlaps the isolated scanner bridge".into(),
                ));
            }

            destinations.push(GatewayDestination {
                hostname: match &plan.target {
                    CanonicalTarget::Hostname(hostname) => Some(hostname.clone()),
                    CanonicalTarget::Address(_) | CanonicalTarget::Network(_) => None,
                },
                addresses: plan.resolution.addresses.clone(),
                ports: plan.ports.clone(),
                allow_sensitive_networks: plan.allow_sensitive_networks,
            });
        }

        destinations.sort();
        destinations.dedup();
        grant_ids.sort();
        grant_ids.dedup();
        if destinations.is_empty() || expires_at <= now {
            return Err(AppError::NotAuthorized(
                "managed egress policy is empty or expired".into(),
            ));
        }

        Ok(Self {
            schema_version: POLICY_SCHEMA_VERSION.into(),
            policy_id,
            expires_at,
            listen_address,
            allowed_client_network,
            limits: EgressGatewayLimits {
                max_concurrency,
                max_connections_per_second,
                connect_timeout_seconds: timeout_seconds.min(120),
                max_connection_seconds: timeout_seconds.min(86_400),
            },
            provenance: EgressGatewayProvenance::ExternalAssetGrants {
                case_id: expected_case_id.to_owned(),
                grant_ids,
                activities: activities.into_iter().collect(),
            },
            destinations,
        })
    }

    pub fn from_provider_service_plan(
        policy_id: impl Into<String>,
        listen_address: SocketAddr,
        allowed_client_network: IpNet,
        plan: &ResolvedProviderServicePlan,
        now: DateTime<Utc>,
    ) -> AppResult<Self> {
        let policy_id = policy_id.into();
        validate_policy_id(&policy_id)?;
        validate_bridge_network(allowed_client_network, listen_address.ip())?;
        if listen_address.port() != GATEWAY_PORT {
            return Err(AppError::InvalidRequest(format!(
                "egress gateway must listen on port {GATEWAY_PORT}"
            )));
        }
        validate_provider_service_request_static(&plan.request, now)?;
        if plan.frozen_at > now
            || plan.destinations.is_empty()
            || plan.destinations.len() > MAX_DESTINATIONS
        {
            return Err(AppError::NotAuthorized(
                "provider-service plan is empty, future-dated, or oversized".into(),
            ));
        }
        let mut endpoint_count = 0_usize;
        for destination in &plan.destinations {
            endpoint_count = endpoint_count
                .checked_add(destination.addresses.len())
                .ok_or_else(|| {
                    AppError::InvalidRequest("provider endpoint set is too large".into())
                })?;
            if endpoint_count > MAX_AUTHORIZED_ENDPOINTS
                || destination.hostname.is_none()
                || destination.ports != BTreeSet::from([443])
                || destination.allow_sensitive_networks
                || destination.addresses.iter().any(|address| {
                    is_sensitive_address(*address)
                        || is_cloud_metadata(*address)
                        || allowed_client_network.contains(address)
                })
            {
                return Err(AppError::NotAuthorized(
                    "provider-service plan contains an unbounded or sensitive endpoint".into(),
                ));
            }
        }
        Ok(Self {
            schema_version: POLICY_SCHEMA_VERSION.into(),
            policy_id,
            expires_at: plan.request.expires_at.min(now + ChronoDuration::hours(1)),
            listen_address,
            allowed_client_network,
            limits: EgressGatewayLimits {
                max_concurrency: 10,
                max_connections_per_second: 25,
                connect_timeout_seconds: 30,
                max_connection_seconds: 300,
            },
            provenance: EgressGatewayProvenance::ProviderService {
                case_id: plan.request.case_id.clone(),
                source_id: plan.request.source_id.clone(),
                source_kind: plan.request.source_kind.clone(),
                source_profile: plan.request.source_profile.clone(),
                manifest_id: plan.request.manifest_id.clone(),
                manifest_revision: plan.request.manifest_revision.clone(),
            },
            destinations: plan.destinations.clone(),
        })
    }

    fn allowed_destination_labels(&self) -> Vec<String> {
        let mut labels = BTreeSet::new();
        for destination in &self.destinations {
            for port in &destination.ports {
                if let Some(hostname) = &destination.hostname {
                    labels.insert(format!("{hostname}:{port}"));
                } else {
                    for address in &destination.addresses {
                        labels.insert(SocketAddr::new(*address, *port).to_string());
                    }
                }
            }
        }
        labels.into_iter().collect()
    }

    pub fn destinations(&self) -> &[GatewayDestination] {
        &self.destinations
    }
}

pub fn resolve_provider_service_plan(
    request: ProviderServiceEgressRequest,
    now: DateTime<Utc>,
) -> AppResult<ResolvedProviderServicePlan> {
    validate_provider_service_request_static(&request, now)?;
    let mut destinations = Vec::with_capacity(request.exact_destinations.len());
    let mut total_addresses = 0_usize;
    for endpoint in &request.exact_destinations {
        let (hostname, port) = parse_exact_provider_destination(endpoint)?;
        let addresses = (hostname.as_str(), port)
            .to_socket_addrs()
            .map_err(|error| {
                AppError::NotAvailable(format!(
                    "provider endpoint {hostname} DNS resolution failed: {error}"
                ))
            })?
            .map(|socket| socket.ip())
            .collect::<BTreeSet<_>>();
        if addresses.is_empty() || addresses.len() > 64 {
            return Err(AppError::NotAvailable(format!(
                "provider endpoint {hostname} did not resolve to a bounded address set"
            )));
        }
        if addresses
            .iter()
            .any(|address| is_sensitive_address(*address) || is_cloud_metadata(*address))
        {
            return Err(AppError::NotAuthorized(format!(
                "provider endpoint {hostname} resolved to a sensitive or metadata address"
            )));
        }
        total_addresses = total_addresses
            .checked_add(addresses.len())
            .ok_or_else(|| AppError::InvalidRequest("provider endpoint set is too large".into()))?;
        if total_addresses > 1_024 {
            return Err(AppError::InvalidRequest(
                "provider endpoint resolution exceeds 1024 frozen addresses".into(),
            ));
        }
        destinations.push(GatewayDestination {
            hostname: Some(hostname),
            addresses,
            ports: BTreeSet::from([port]),
            allow_sensitive_networks: false,
        });
    }
    destinations.sort();
    destinations.dedup();
    Ok(ResolvedProviderServicePlan {
        request,
        frozen_at: now,
        destinations,
    })
}

/// Validates the complete static provider-service contract without resolving
/// DNS, opening a socket, provisioning a network, or starting the gateway.
/// Execution still resolves and freezes the exact endpoint addresses in
/// [`resolve_provider_service_plan`] immediately before provisioning.
pub(crate) fn validate_provider_service_request_static(
    request: &ProviderServiceEgressRequest,
    now: DateTime<Utc>,
) -> AppResult<()> {
    for (label, value) in [
        ("case", request.case_id.as_str()),
        ("source", request.source_id.as_str()),
        ("source kind", request.source_kind.as_str()),
        ("source profile", request.source_profile.as_str()),
        ("manifest", request.manifest_id.as_str()),
        ("manifest revision", request.manifest_revision.as_str()),
    ] {
        if value.trim().is_empty() || value.len() > 256 || value.contains(['\n', '\r', '\0']) {
            return Err(AppError::InvalidRequest(format!(
                "provider-service {label} provenance is invalid"
            )));
        }
    }
    if request.expires_at <= now || request.expires_at > now + ChronoDuration::hours(1) {
        return Err(AppError::NotAuthorized(
            "provider-service authorization must be live and no longer than one hour".into(),
        ));
    }
    if request.exact_destinations.is_empty()
        || request.exact_destinations.len() > 128
        || request
            .exact_destinations
            .iter()
            .collect::<BTreeSet<_>>()
            .len()
            != request.exact_destinations.len()
    {
        return Err(AppError::InvalidRequest(
            "provider-service manifest must declare a finite unique endpoint list".into(),
        ));
    }
    for endpoint in &request.exact_destinations {
        let (hostname, _) = parse_exact_provider_destination(endpoint)?;
        if !provider_hostname_matches_source(&request.source_kind, &hostname) {
            return Err(AppError::NotAvailable(format!(
                "provider endpoint {hostname} is not valid for source kind {}",
                request.source_kind
            )));
        }
    }
    Ok(())
}

fn provider_hostname_matches_source(source_kind: &str, hostname: &str) -> bool {
    match source_kind {
        "aws_organization" => hostname.ends_with(".amazonaws.com"),
        "azure_tenant" => matches!(
            hostname,
            "management.azure.com" | "graph.microsoft.com" | "login.microsoftonline.com"
        ),
        "gcp_organization" => hostname.ends_with(".googleapis.com"),
        "microsoft365_tenant" => matches!(
            hostname,
            "graph.microsoft.com"
                | "login.microsoftonline.com"
                | "manage.office.com"
                | "outlook.office.com"
        ),
        // These public-source profiles still require a pinned manifest with
        // exact FQDNs; unlike cloud APIs there is no shared vendor suffix.
        "dns" | "certificate_transparency" => true,
        _ => false,
    }
}

fn parse_exact_provider_destination(value: &str) -> AppResult<(String, u16)> {
    if value.is_empty()
        || value.len() > 260
        || value.contains(['*', '/', '\\', '\n', '\r', '\0', '@'])
        || value.contains("://")
    {
        return Err(AppError::NotAvailable(
            "provider-service endpoint is not an exact FQDN:443 destination".into(),
        ));
    }
    let (hostname, port) = value.rsplit_once(':').ok_or_else(|| {
        AppError::NotAvailable(
            "provider-service endpoint must use exact lowercase FQDN:443 syntax".into(),
        )
    })?;
    if port != "443" || hostname.contains(':') || hostname != hostname.to_ascii_lowercase() {
        return Err(AppError::NotAvailable(
            "provider-service endpoint must use exact lowercase FQDN:443 syntax".into(),
        ));
    }
    let canonical = CanonicalTarget::parse(hostname)?;
    let CanonicalTarget::Hostname(canonical) = canonical else {
        return Err(AppError::NotAvailable(
            "provider-service endpoint must be a fully qualified hostname".into(),
        ));
    };
    if canonical != hostname {
        return Err(AppError::NotAvailable(
            "provider-service endpoint is not in canonical lowercase form".into(),
        ));
    }
    Ok((canonical, 443))
}

/// Owns the runtime network and gateway process for one bounded scan operation.
pub struct ManagedNetworkController {
    provider: RuntimeProvider,
    policy_directory: PathBuf,
    registry_directory: PathBuf,
    runtime: Arc<dyn RuntimeCommands>,
    gateway_backend: GatewayBackend,
}

enum GatewayBackend {
    Direct {
        binary: PathBuf,
        launcher: Arc<dyn GatewayLauncher>,
        readiness: Arc<dyn GatewayReadiness>,
    },
    Container {
        spec: GatewayContainerSpec,
        readiness: Arc<dyn GatewayContainerReadiness>,
    },
}

impl ManagedNetworkController {
    pub fn new(
        provider: RuntimeProvider,
        gateway_binary: impl AsRef<Path>,
        policy_directory: impl AsRef<Path>,
    ) -> AppResult<Self> {
        require_compatibility_provider(provider)?;
        let local_registry = policy_directory.as_ref().join(".managed-network-registry");
        ensure_private_directory(&local_registry)?;
        Self::with_components(
            provider,
            gateway_binary.as_ref(),
            policy_directory.as_ref(),
            &local_registry,
            Arc::new(DirectRuntimeCommands),
            Arc::new(DirectGatewayLauncher),
            Arc::new(SocketGatewayReadiness),
        )
    }

    pub fn new_with_registry(
        provider: RuntimeProvider,
        gateway_binary: impl AsRef<Path>,
        policy_directory: impl AsRef<Path>,
        registry_directory: impl AsRef<Path>,
    ) -> AppResult<Self> {
        require_compatibility_provider(provider)?;
        Self::with_components(
            provider,
            gateway_binary.as_ref(),
            policy_directory.as_ref(),
            registry_directory.as_ref(),
            Arc::new(DirectRuntimeCommands),
            Arc::new(DirectGatewayLauncher),
            Arc::new(SocketGatewayReadiness),
        )
    }

    pub fn new_with_registry_context(
        context: RuntimeCommandContext,
        gateway_binary: impl AsRef<Path>,
        policy_directory: impl AsRef<Path>,
        registry_directory: impl AsRef<Path>,
    ) -> AppResult<Self> {
        let provider = context.provider();
        Self::with_components(
            provider,
            gateway_binary.as_ref(),
            policy_directory.as_ref(),
            registry_directory.as_ref(),
            Arc::new(ContextRuntimeCommands { context }),
            Arc::new(DirectGatewayLauncher),
            Arc::new(SocketGatewayReadiness),
        )
    }

    /// Creates the production-safe gateway backend for a runtime whose network
    /// namespace may live in a VM (ManagedLocal, Docker Desktop, or remote
    /// Podman). Both the scanner bridge and the gateway uplink are runtime-owned;
    /// no native host process is asked to bind a guest-only address.
    pub fn new_with_registry_context_and_container(
        context: RuntimeCommandContext,
        gateway: GatewayContainerSpec,
        policy_directory: impl AsRef<Path>,
        registry_directory: impl AsRef<Path>,
    ) -> AppResult<Self> {
        let provider = context.provider();
        Self::with_container_components(
            provider,
            gateway,
            policy_directory.as_ref(),
            registry_directory.as_ref(),
            Arc::new(ContextRuntimeCommands { context }),
            Arc::new(RuntimeGatewayContainerReadiness),
        )
    }

    fn with_components(
        provider: RuntimeProvider,
        gateway_binary: &Path,
        policy_directory: &Path,
        registry_directory: &Path,
        runtime: Arc<dyn RuntimeCommands>,
        gateway_launcher: Arc<dyn GatewayLauncher>,
        readiness: Arc<dyn GatewayReadiness>,
    ) -> AppResult<Self> {
        if provider == RuntimeProvider::ManagedLocal {
            return Err(AppError::NotAvailable(
                "managed-local egress requires the pinned gateway-container backend".into(),
            ));
        }
        let gateway_binary = inspect_gateway_binary(gateway_binary)?;
        let policy_directory = validate_policy_directory(policy_directory)?;
        let registry_directory = validate_policy_directory(registry_directory)?;
        Ok(Self {
            provider,
            policy_directory,
            registry_directory,
            runtime,
            gateway_backend: GatewayBackend::Direct {
                binary: gateway_binary,
                launcher: gateway_launcher,
                readiness,
            },
        })
    }

    fn with_container_components(
        provider: RuntimeProvider,
        gateway: GatewayContainerSpec,
        policy_directory: &Path,
        registry_directory: &Path,
        runtime: Arc<dyn RuntimeCommands>,
        readiness: Arc<dyn GatewayContainerReadiness>,
    ) -> AppResult<Self> {
        gateway.validate()?;
        let policy_directory = validate_policy_directory(policy_directory)?;
        let registry_directory = validate_policy_directory(registry_directory)?;
        Ok(Self {
            provider,
            policy_directory,
            registry_directory,
            runtime,
            gateway_backend: GatewayBackend::Container {
                spec: gateway,
                readiness,
            },
        })
    }

    pub fn provision(
        &self,
        owner: &ManagedNetworkOwner,
        plans: &[ResolvedExternalPlan],
        now: DateTime<Utc>,
    ) -> AppResult<ManagedNetworkLease> {
        owner.validate()?;
        self.validate_gateway_backend()?;
        validate_policy_directory(&self.policy_directory)?;
        validate_policy_directory(&self.registry_directory)?;
        // Validate the plans before making any host or runtime changes. The bridge-specific
        // overlap check is repeated after the runtime allocates its private subnet.
        validate_plans_without_bridge(plans, now)?;
        if plans
            .first()
            .is_none_or(|plan| plan.case_id != owner.case_id)
        {
            return Err(AppError::InvalidRequest(
                "managed-network owner does not match the frozen external plans".into(),
            ));
        }

        let expires_at = plans
            .iter()
            .map(|plan| plan.expires_at)
            .min()
            .unwrap_or(now)
            .min(now + ChronoDuration::hours(24));
        let prohibited_networks = frozen_plan_networks(plans);
        self.provision_policy(
            owner,
            expires_at,
            now,
            &prohibited_networks,
            |policy_id, listen, subnet| {
                EgressGatewayPolicy::from_resolved_plans(policy_id, listen, subnet, plans, now)
            },
        )
    }

    pub fn provision_provider_service(
        &self,
        owner: &ManagedNetworkOwner,
        plan: &ResolvedProviderServicePlan,
        now: DateTime<Utc>,
    ) -> AppResult<ManagedNetworkLease> {
        owner.validate()?;
        self.validate_gateway_backend()?;
        validate_policy_directory(&self.policy_directory)?;
        validate_policy_directory(&self.registry_directory)?;
        validate_provider_service_request_static(&plan.request, now)?;
        if plan.request.case_id != owner.case_id {
            return Err(AppError::InvalidRequest(
                "managed-network owner does not match provider-service provenance".into(),
            ));
        }
        self.provision_policy(
            owner,
            plan.request.expires_at.min(now + ChronoDuration::hours(1)),
            now,
            &provider_plan_networks(plan),
            |policy_id, listen, subnet| {
                EgressGatewayPolicy::from_provider_service_plan(
                    policy_id, listen, subnet, plan, now,
                )
            },
        )
    }

    /// Performs the release-only managed gateway proof. The probe container is
    /// attached only to the isolated scanner bridge, sends one SOCKS greeting,
    /// and exits before any CONNECT request can be sent. It uses the same
    /// immutable image as the gateway and always exact-cleans every resource
    /// before a successful result can be returned.
    pub fn qualify_gateway_container(
        &self,
        owner: &ManagedNetworkOwner,
        qualification_id: &str,
        now: DateTime<Utc>,
    ) -> AppResult<ManagedGatewayQualification> {
        owner.validate()?;
        validate_owner_segment(qualification_id, "qualification")?;
        self.validate_gateway_backend()?;
        let GatewayBackend::Container { spec, .. } = &self.gateway_backend else {
            return Err(AppError::NotAvailable(
                "managed gateway qualification requires the pinned container backend".into(),
            ));
        };
        let expires_at = now + ChronoDuration::minutes(5);
        let qualification_networks = vec![host_network(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)))];
        let mut lease = self.provision_policy(
            owner,
            expires_at,
            now,
            &qualification_networks,
            |policy_id, listen_address, allowed_client_network| {
                validate_bridge_network(allowed_client_network, listen_address.ip())?;
                if listen_address.port() != GATEWAY_PORT {
                    return Err(AppError::Internal(
                        "managed gateway qualification listener used the wrong port".into(),
                    ));
                }
                Ok(EgressGatewayPolicy {
                    schema_version: POLICY_SCHEMA_VERSION.into(),
                    policy_id: policy_id.into(),
                    expires_at,
                    listen_address,
                    allowed_client_network,
                    limits: EgressGatewayLimits {
                        max_concurrency: 1,
                        max_connections_per_second: 1,
                        connect_timeout_seconds: 1,
                        max_connection_seconds: 5,
                    },
                    provenance: EgressGatewayProvenance::ReleaseQualification {
                        case_id: owner.case_id.clone(),
                        qualification_id: qualification_id.into(),
                    },
                    // The gateway's policy format requires one bounded
                    // destination. The probe never sends CONNECT, so this
                    // documentation address is never contacted.
                    destinations: vec![GatewayDestination {
                        hostname: None,
                        addresses: BTreeSet::from([IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))]),
                        ports: BTreeSet::from([9]),
                        allow_sensitive_networks: false,
                    }],
                })
            },
        )?;
        let durable = lease.durable_identity()?;
        let gateway_container_id = durable
            .gateway_container_id
            .clone()
            .ok_or_else(|| AppError::Internal("qualification gateway ID is absent".into()))?;
        let uplink_network_id = durable
            .uplink_network_id
            .clone()
            .ok_or_else(|| AppError::Internal("qualification uplink ID is absent".into()))?;
        let listener_ip = durable
            .gateway_listener_ip
            .ok_or_else(|| AppError::Internal("qualification listener is absent".into()))?;
        let policy_path = lease
            .policy_path()
            .ok_or_else(|| AppError::Internal("qualification policy path is absent".into()))?
            .to_owned();
        let status_path = lease
            .gateway_status_directory
            .as_ref()
            .ok_or_else(|| AppError::Internal("qualification status path is absent".into()))?
            .path
            .clone();
        let registry_paths = lease
            .registry_files
            .iter()
            .map(|file| file.path.clone())
            .collect::<Vec<_>>();
        let unique = durable.policy_id.strip_prefix("egress-").ok_or_else(|| {
            AppError::Internal("qualification policy identity is malformed".into())
        })?;
        let mut probe = GatewayProbeRuntimeIdentity {
            name: format!("ass-probe-{unique}"),
            id: None,
            policy_id: durable.policy_id.clone(),
            image: spec.clone(),
            internal_network_name: durable.network_name.clone(),
            gateway: SocketAddr::new(listener_ip, GATEWAY_PORT),
        };

        let probe_result = (|| {
            create_gateway_probe(self.runtime.as_ref(), self.provider, &mut probe)?;
            run_gateway_probe(self.runtime.as_ref(), self.provider, &probe)
        })();
        let probe_container_id = probe.id.clone();
        let probe_cleanup = remove_gateway_probe(self.runtime.as_ref(), self.provider, &probe);
        let gateway_cleanup = lease.cleanup();

        let mut cleanup_failures = Vec::new();
        if let Err(error) = probe_cleanup {
            cleanup_failures.push(format!("probe cleanup: {error}"));
        }
        if let Err(error) = gateway_cleanup {
            cleanup_failures.push(format!("gateway cleanup: {error}"));
        }
        if !cleanup_failures.is_empty() {
            return Err(AppError::Runtime(format!(
                "managed gateway qualification cleanup was incomplete: {}",
                cleanup_failures.join("; ")
            )));
        }
        let probe_result = probe_result?;
        let probe_container_id = probe_container_id.ok_or_else(|| {
            AppError::Runtime("managed gateway qualification probe had no runtime ID".into())
        })?;
        let policy_file_removed = exact_path_is_absent(&policy_path)?;
        let status_directory_removed = exact_path_is_absent(&status_path)?;
        let registry_record_removed = registry_paths
            .iter()
            .map(|path| exact_path_is_absent(path))
            .collect::<AppResult<Vec<_>>>()?
            .into_iter()
            .all(|absent| absent);
        if lease.is_active()
            || !policy_file_removed
            || !status_directory_removed
            || !registry_record_removed
        {
            return Err(AppError::Runtime(
                "managed gateway qualification retained a durable resource".into(),
            ));
        }
        Ok(ManagedGatewayQualification {
            image: spec.reference(),
            gateway_container_id,
            probe_container_id,
            internal_network_id: durable.network_id,
            uplink_network_id,
            policy_sha256: durable.policy_sha256,
            reachability_probe: probe_result.reachability_probe,
            gateway_reachable: probe_result.gateway_reachable,
            upstream_connect_attempted: probe_result.upstream_connect_attempted,
            cleanup: ManagedGatewayQualificationCleanup {
                gateway_container_removed: true,
                probe_container_removed: true,
                internal_network_removed: true,
                uplink_network_removed: true,
                policy_file_removed,
                status_directory_removed,
                registry_record_removed,
            },
        })
    }

    fn provision_policy<F>(
        &self,
        owner: &ManagedNetworkOwner,
        expires_at: DateTime<Utc>,
        now: DateTime<Utc>,
        prohibited_networks: &[IpNet],
        build_policy: F,
    ) -> AppResult<ManagedNetworkLease>
    where
        F: FnOnce(&str, SocketAddr, IpNet) -> AppResult<EgressGatewayPolicy>,
    {
        match &self.gateway_backend {
            GatewayBackend::Direct { .. } => self.provision_direct_policy(
                owner,
                expires_at,
                now,
                prohibited_networks,
                build_policy,
            ),
            GatewayBackend::Container { .. } => self.provision_container_policy(
                owner,
                expires_at,
                now,
                prohibited_networks,
                build_policy,
            ),
        }
    }

    fn validate_gateway_backend(&self) -> AppResult<()> {
        match &self.gateway_backend {
            GatewayBackend::Direct { binary, .. } => {
                if self.provider == RuntimeProvider::ManagedLocal {
                    return Err(AppError::NotAvailable(
                        "managed-local egress requires the pinned gateway-container backend".into(),
                    ));
                }
                inspect_gateway_binary(binary).map(|_| ())
            }
            GatewayBackend::Container { spec, .. } => spec.validate(),
        }
    }

    fn provision_direct_policy<F>(
        &self,
        owner: &ManagedNetworkOwner,
        expires_at: DateTime<Utc>,
        now: DateTime<Utc>,
        prohibited_networks: &[IpNet],
        build_policy: F,
    ) -> AppResult<ManagedNetworkLease>
    where
        F: FnOnce(&str, SocketAddr, IpNet) -> AppResult<EgressGatewayPolicy>,
    {
        let unique = Uuid::new_v4().simple().to_string();
        let policy_id = format!("egress-{unique}");
        let network_name = format!("ass-egress-{unique}");
        let expected_labels = expected_labels(&policy_id);
        let mut record = ManagedNetworkRecord {
            schema_version: REGISTRY_SCHEMA_VERSION.into(),
            owner: owner.clone(),
            provider: self.provider,
            network_name: network_name.clone(),
            policy_id: policy_id.clone(),
            created_at: now,
            expires_at,
            phase: RegistryPhase::Intent,
            network_id: None,
            uplink_network_name: None,
            uplink_network_id: None,
            gateway_container_name: None,
            gateway_container_id: None,
            gateway_listener_ip: None,
            gateway_image_repository: None,
            gateway_image_digest: None,
            policy_sha256: None,
        };
        let registry_files = vec![write_registry_snapshot(&self.registry_directory, &record)?];
        let mut lease = ManagedNetworkLease {
            provider: self.provider,
            runtime: Arc::clone(&self.runtime),
            network_name: Some(network_name.clone()),
            network_id: None,
            remove_unverified_network: true,
            expected_labels: expected_labels.clone(),
            gateway_process: None,
            gateway_container: None,
            gateway_status_directory: None,
            policy_file: None,
            network_policy: None,
            egress_policy: None,
            registry_files,
            uplink_network_name: None,
            uplink_network_id: None,
            uplink_expected_labels: BTreeMap::new(),
        };
        let inspected = create_internal_network(
            self.runtime.as_ref(),
            self.provider,
            &network_name,
            &expected_labels,
            &policy_id,
            prohibited_networks,
        )?;
        lease.network_id = Some(inspected.id.clone());
        lease.remove_unverified_network = false;
        record.phase = RegistryPhase::NetworkVerified;
        record.network_id = Some(inspected.id.clone());
        lease
            .registry_files
            .push(write_registry_snapshot(&self.registry_directory, &record)?);

        let listen_address = SocketAddr::new(inspected.gateway, GATEWAY_PORT);
        let egress_policy = build_policy(&policy_id, listen_address, inspected.subnet)?;
        if egress_policy.expires_at != expires_at {
            return Err(AppError::Internal(
                "managed egress policy lifetime diverged from its durable registry".into(),
            ));
        }
        let policy_file = write_policy_file(&self.policy_directory, &egress_policy)?;
        record.phase = RegistryPhase::Ready;
        record.policy_sha256 = Some(hex::encode(policy_file.sha256));
        lease
            .registry_files
            .push(write_registry_snapshot(&self.registry_directory, &record)?);
        lease.policy_file = Some(policy_file);

        let GatewayBackend::Direct {
            binary,
            launcher,
            readiness,
        } = &self.gateway_backend
        else {
            return Err(AppError::Internal(
                "managed gateway backend changed while provisioning".into(),
            ));
        };
        let gateway_process = launcher
            .spawn(binary, lease.policy_path().expect("policy path set"))
            .map_err(|error| {
                AppError::Runtime(format!("egress gateway could not start: {error}"))
            })?;
        lease.gateway_process = Some(gateway_process);
        readiness.wait_until_ready(
            lease
                .gateway_process
                .as_mut()
                .expect("gateway process set")
                .as_mut(),
            listen_address,
        )?;

        let endpoint = gateway_endpoint(inspected.gateway);
        let network_policy = NetworkPolicy::managed(
            network_name,
            policy_id,
            egress_policy.allowed_destination_labels(),
            endpoint,
        )?;
        lease.network_policy = Some(network_policy);
        lease.egress_policy = Some(egress_policy);
        Ok(lease)
    }

    fn provision_container_policy<F>(
        &self,
        owner: &ManagedNetworkOwner,
        expires_at: DateTime<Utc>,
        now: DateTime<Utc>,
        prohibited_networks: &[IpNet],
        build_policy: F,
    ) -> AppResult<ManagedNetworkLease>
    where
        F: FnOnce(&str, SocketAddr, IpNet) -> AppResult<EgressGatewayPolicy>,
    {
        let GatewayBackend::Container { spec, readiness } = &self.gateway_backend else {
            return Err(AppError::Internal(
                "managed gateway backend changed while provisioning".into(),
            ));
        };
        ensure_gateway_container_image(self.runtime.as_ref(), self.provider, spec)?;
        let unique = Uuid::new_v4().simple().to_string();
        let policy_id = format!("egress-{unique}");
        let network_name = format!("ass-egress-{unique}");
        let uplink_network_name = format!("ass-uplink-{unique}");
        let gateway_container_name = format!("ass-gateway-{unique}");
        let expected_labels = expected_labels(&policy_id);
        let uplink_expected_labels = expected_uplink_labels(&policy_id);
        let mut record = ManagedNetworkRecord {
            schema_version: REGISTRY_SCHEMA_VERSION.into(),
            owner: owner.clone(),
            provider: self.provider,
            network_name: network_name.clone(),
            policy_id: policy_id.clone(),
            created_at: now,
            expires_at,
            phase: RegistryPhase::Intent,
            network_id: None,
            uplink_network_name: Some(uplink_network_name.clone()),
            uplink_network_id: None,
            gateway_container_name: Some(gateway_container_name.clone()),
            gateway_container_id: None,
            gateway_listener_ip: None,
            gateway_image_repository: Some(spec.repository().to_owned()),
            gateway_image_digest: Some(spec.digest().to_owned()),
            policy_sha256: None,
        };
        let registry_files = vec![write_registry_snapshot(&self.registry_directory, &record)?];
        let mut lease = ManagedNetworkLease {
            provider: self.provider,
            runtime: Arc::clone(&self.runtime),
            network_name: Some(network_name.clone()),
            network_id: None,
            remove_unverified_network: true,
            expected_labels: expected_labels.clone(),
            uplink_network_name: Some(uplink_network_name.clone()),
            uplink_network_id: None,
            uplink_expected_labels: uplink_expected_labels.clone(),
            gateway_process: None,
            gateway_container: None,
            gateway_status_directory: None,
            policy_file: None,
            network_policy: None,
            egress_policy: None,
            registry_files,
        };
        let internal = create_internal_network(
            self.runtime.as_ref(),
            self.provider,
            &network_name,
            &expected_labels,
            &policy_id,
            prohibited_networks,
        )?;
        lease.network_id = Some(internal.id.clone());
        lease.remove_unverified_network = false;
        record.phase = RegistryPhase::NetworkVerified;
        record.network_id = Some(internal.id.clone());
        lease
            .registry_files
            .push(write_registry_snapshot(&self.registry_directory, &record)?);

        let mut uplink_prohibited = prohibited_networks.to_vec();
        uplink_prohibited.push(internal.subnet);
        if let Some(subnet) = internal.ipv6_subnet {
            uplink_prohibited.push(subnet);
        }
        let uplink = create_uplink_network(
            self.runtime.as_ref(),
            self.provider,
            &uplink_network_name,
            &uplink_expected_labels,
            &policy_id,
            &uplink_prohibited,
        )?;
        lease.uplink_network_id = Some(uplink.id.clone());
        record.phase = RegistryPhase::UplinkVerified;
        record.uplink_network_id = Some(uplink.id.clone());
        lease
            .registry_files
            .push(write_registry_snapshot(&self.registry_directory, &record)?);

        let listener_ip = select_gateway_container_ip(internal.subnet, internal.gateway)?;
        let listen_address = SocketAddr::new(listener_ip, GATEWAY_PORT);
        let egress_policy = build_policy(&policy_id, listen_address, internal.subnet)?;
        if egress_policy.expires_at != expires_at {
            return Err(AppError::Internal(
                "managed egress policy lifetime diverged from its durable registry".into(),
            ));
        }
        reject_destination_overlap(&egress_policy, &uplink)?;
        let policy_file = write_policy_file(&self.policy_directory, &egress_policy)?;
        record.phase = RegistryPhase::PolicyReady;
        record.gateway_listener_ip = Some(listener_ip);
        record.policy_sha256 = Some(hex::encode(policy_file.sha256));
        lease.policy_file = Some(policy_file);
        lease
            .registry_files
            .push(write_registry_snapshot(&self.registry_directory, &record)?);

        let status_directory = create_gateway_status_directory(&self.policy_directory, &policy_id)?;
        lease.gateway_status_directory = Some(status_directory);

        let container = GatewayContainerRuntimeIdentity {
            name: gateway_container_name,
            id: None,
            policy_id: policy_id.clone(),
            listener_ip,
            image: spec.clone(),
            internal_network_name: network_name.clone(),
            uplink_network_name,
            uplink_subnets: Some((
                uplink.subnet,
                uplink.ipv6_subnet.ok_or_else(|| {
                    AppError::Internal("verified gateway uplink lost its IPv6 subnet".into())
                })?,
            )),
        };
        lease.gateway_container = Some(container);
        let policy_path = lease.policy_path().expect("policy path set").to_path_buf();
        let gateway_status_directory = lease
            .gateway_status_directory
            .as_ref()
            .expect("status directory set")
            .clone();
        let inspected = create_gateway_container(
            self.runtime.as_ref(),
            self.provider,
            lease
                .gateway_container
                .as_mut()
                .expect("gateway container identity set"),
            &policy_path,
            &gateway_status_directory,
            &policy_id,
        )?;
        record.phase = RegistryPhase::GatewayContainerVerified;
        record.gateway_container_id = Some(inspected.id);
        lease
            .registry_files
            .push(write_registry_snapshot(&self.registry_directory, &record)?);

        let container = lease
            .gateway_container
            .as_ref()
            .expect("verified gateway identity")
            .clone();
        start_gateway_container(
            self.runtime.as_ref(),
            self.provider,
            container.id.as_deref().expect("verified gateway id"),
        )?;
        readiness.wait_until_ready(
            self.runtime.as_ref(),
            self.provider,
            &container,
            lease
                .gateway_status_directory
                .as_ref()
                .expect("status directory set"),
            &policy_id,
        )?;
        inspect_required_gateway_container(
            self.runtime.as_ref(),
            self.provider,
            &container,
            &policy_id,
        )?;
        record.phase = RegistryPhase::ContainerReady;
        lease
            .registry_files
            .push(write_registry_snapshot(&self.registry_directory, &record)?);

        let network_policy = NetworkPolicy::managed(
            network_name,
            policy_id,
            egress_policy.allowed_destination_labels(),
            gateway_endpoint(listener_ip),
        )?;
        lease.network_policy = Some(network_policy);
        lease.egress_policy = Some(egress_policy);
        Ok(lease)
    }
}

/// Keeping this value alive keeps the gateway process and its isolated bridge alive.
/// Explicit cleanup reports failures; `Drop` still performs the same best-effort cleanup.
pub struct ManagedNetworkLease {
    provider: RuntimeProvider,
    runtime: Arc<dyn RuntimeCommands>,
    network_name: Option<String>,
    network_id: Option<String>,
    remove_unverified_network: bool,
    expected_labels: BTreeMap<String, String>,
    uplink_network_name: Option<String>,
    uplink_network_id: Option<String>,
    uplink_expected_labels: BTreeMap<String, String>,
    gateway_process: Option<Box<dyn GatewayProcess>>,
    gateway_container: Option<GatewayContainerRuntimeIdentity>,
    gateway_status_directory: Option<GatewayStatusDirectory>,
    policy_file: Option<PolicyFile>,
    network_policy: Option<NetworkPolicy>,
    egress_policy: Option<EgressGatewayPolicy>,
    registry_files: Vec<RegistryFile>,
}

impl ManagedNetworkLease {
    pub fn network_policy(&self) -> &NetworkPolicy {
        self.network_policy
            .as_ref()
            .expect("a returned managed-network lease always has a policy")
    }

    pub fn egress_policy(&self) -> &EgressGatewayPolicy {
        self.egress_policy
            .as_ref()
            .expect("a returned managed-network lease always has an egress policy")
    }

    pub fn network_name(&self) -> Option<&str> {
        self.network_name.as_deref()
    }

    pub fn durable_identity(&self) -> AppResult<ManagedNetworkIdentity> {
        let policy = self.egress_policy.as_ref().ok_or_else(|| {
            AppError::Runtime("managed network has no verified egress policy".into())
        })?;
        let policy_file = self.policy_file.as_ref().ok_or_else(|| {
            AppError::Runtime("managed network has no verified policy file".into())
        })?;
        let identity = ManagedNetworkIdentity {
            schema_version: REGISTRY_SCHEMA_VERSION.into(),
            provider: self.provider,
            network_name: self
                .network_name
                .clone()
                .ok_or_else(|| AppError::Runtime("managed network has no name".into()))?,
            network_id: self
                .network_id
                .clone()
                .ok_or_else(|| AppError::Runtime("managed network has no runtime id".into()))?,
            uplink_network_name: self.uplink_network_name.clone(),
            uplink_network_id: self.uplink_network_id.clone(),
            gateway_container_name: self
                .gateway_container
                .as_ref()
                .map(|container| container.name.clone()),
            gateway_container_id: self
                .gateway_container
                .as_ref()
                .and_then(|container| container.id.clone()),
            gateway_listener_ip: self
                .gateway_container
                .as_ref()
                .map(|container| container.listener_ip),
            gateway_image_repository: self
                .gateway_container
                .as_ref()
                .map(|container| container.image.repository().to_owned()),
            gateway_image_digest: self
                .gateway_container
                .as_ref()
                .map(|container| container.image.digest().to_owned()),
            policy_id: policy.policy_id.clone(),
            policy_sha256: hex::encode(policy_file.sha256),
            expires_at: policy.expires_at,
            provenance: policy.provenance.clone(),
        };
        identity.validate()?;
        Ok(identity)
    }

    pub fn policy_path(&self) -> Option<&Path> {
        self.policy_file
            .as_ref()
            .map(|policy| policy.path.as_path())
    }

    pub fn is_active(&self) -> bool {
        self.gateway_process.is_some()
            || self.gateway_container.is_some()
            || self.gateway_status_directory.is_some()
            || self.network_name.is_some()
            || self.uplink_network_name.is_some()
            || self.policy_file.is_some()
            || !self.registry_files.is_empty()
    }

    pub fn cleanup(&mut self) -> AppResult<()> {
        self.cleanup_with_outcome().map(|_| ())
    }

    pub fn cleanup_with_outcome(&mut self) -> AppResult<ManagedNetworkCleanupOutcome> {
        let mut failures = Vec::new();
        let mut details = Vec::new();
        let mut gateway_refusals = None;

        if let Some(mut process) = self.gateway_process.take() {
            if let Err(error) = stop_gateway(process.as_mut()) {
                failures.push(error.to_string());
                self.gateway_process = Some(process);
            } else {
                details.push("gateway process stopped".to_owned());
            }
        }

        if let Some(container) = self.gateway_container.take() {
            match remove_gateway_container(
                self.runtime.as_ref(),
                self.provider,
                &container,
                &container.policy_id,
            ) {
                Ok(()) => details.push("exact gateway container removed or already absent".into()),
                Err(error) => {
                    failures.push(error.to_string());
                    self.gateway_container = Some(container);
                }
            }
        }

        if self.gateway_process.is_none()
            && self.gateway_container.is_none()
            && let Some(network_name) = self.network_name.clone()
        {
            let removal = if self.remove_unverified_network {
                remove_intent_network(
                    self.runtime.as_ref(),
                    self.provider,
                    &network_name,
                    &self.expected_labels,
                )
            } else {
                self.remove_verified_network(&network_name)
            };
            match removal {
                Ok(()) => {
                    self.network_name = None;
                    self.network_id = None;
                    details.push("exact internal network removed or already absent".to_owned());
                }
                Err(error) => failures.push(error.to_string()),
            }
        }

        if self.gateway_process.is_none()
            && self.gateway_container.is_none()
            && self.network_name.is_none()
            && let Some(network_name) = self.uplink_network_name.clone()
        {
            let removal = self.remove_verified_uplink_network(&network_name);
            match removal {
                Ok(()) => {
                    self.uplink_network_name = None;
                    self.uplink_network_id = None;
                    details.push("exact gateway uplink removed or already absent".to_owned());
                }
                Err(error) => failures.push(error.to_string()),
            }
        }

        if self.gateway_process.is_none()
            && self.gateway_container.is_none()
            && self.network_name.is_none()
            && self.uplink_network_name.is_none()
            && let Some(status_directory) = self.gateway_status_directory.as_ref()
        {
            // A missing line would make "no refusals" and "no record" look the same.
            let record = gateway_refusal_record(read_gateway_status(status_directory));
            gateway_refusals = record;
            details.push(match record {
                Some(GatewayRefusalRecord::Counted {
                    rate: 0,
                    destination: 0,
                    unauthorized_client: 0,
                }) => "gateway refused no connections".to_owned(),
                Some(GatewayRefusalRecord::Counted {
                    rate,
                    destination,
                    unauthorized_client,
                }) => format!(
                    "gateway refused connections: rate {rate}, destination {destination}, unauthorized client {unauthorized_client}"
                ),
                Some(GatewayRefusalRecord::Unavailable) => {
                    "gateway refusal record was unavailable".to_owned()
                }
                None => "this gateway does not record refused connections".to_owned(),
            });
            match remove_gateway_status_directory(status_directory) {
                Ok(()) => {
                    self.gateway_status_directory = None;
                    details.push("bounded gateway status removed or already absent".to_owned());
                }
                Err(error) => failures.push(error.to_string()),
            }
        }

        if self.gateway_process.is_none()
            && self.gateway_container.is_none()
            && self.network_name.is_none()
            && self.uplink_network_name.is_none()
            && self.gateway_status_directory.is_none()
            && let Some(policy_file) = self.policy_file.as_ref()
        {
            match remove_policy_file(policy_file) {
                Ok(()) => {
                    self.policy_file = None;
                    details.push("exact policy file removed or already absent".to_owned());
                }
                Err(error) => failures.push(error.to_string()),
            }
        }

        if failures.is_empty() {
            for registry_file in std::mem::take(&mut self.registry_files) {
                if let Err(error) = remove_registry_file(&registry_file) {
                    failures.push(error.to_string());
                    self.registry_files.push(registry_file);
                }
            }
        }

        if failures.is_empty() {
            self.network_policy = None;
            self.egress_policy = None;
            details.push("durable recovery records removed".to_owned());
            Ok(ManagedNetworkCleanupOutcome {
                removed: true,
                detail: bounded_cleanup_detail(&details.join("; ")),
                gateway_refusals,
            })
        } else {
            Err(AppError::Runtime(format!(
                "managed network cleanup was incomplete: {}",
                failures.join("; ")
            )))
        }
    }

    fn remove_verified_network(&self, network_name: &str) -> AppResult<()> {
        let output = runtime_output(
            self.runtime.as_ref(),
            self.provider,
            &["network".into(), "inspect".into(), network_name.into()],
        )?;
        if !output.success {
            if runtime_reports_network_absent(&output.stderr, network_name) {
                return Ok(());
            }
            return Err(runtime_failure(
                "managed network cleanup inspection",
                &output,
            ));
        }
        let inspected = parse_network_inspect(
            self.provider,
            &output.stdout,
            network_name,
            &self.expected_labels,
        )?;
        if Some(inspected.id.as_str()) != self.network_id.as_deref() {
            return Err(AppError::NotAuthorized(format!(
                "refusing to remove replaced container network {network_name}"
            )));
        }
        remove_network(self.runtime.as_ref(), self.provider, &inspected.id)
    }

    fn remove_verified_uplink_network(&self, network_name: &str) -> AppResult<()> {
        let inspected = inspect_optional_uplink_network_for_cleanup(
            self.runtime.as_ref(),
            self.provider,
            network_name,
            &self.uplink_expected_labels,
        )?;
        let Some(inspected) = inspected else {
            return Ok(());
        };
        if self
            .uplink_network_id
            .as_deref()
            .is_some_and(|expected| expected != inspected.id)
        {
            return Err(AppError::NotAuthorized(format!(
                "refusing to remove replaced gateway uplink network {network_name}"
            )));
        }
        remove_network(self.runtime.as_ref(), self.provider, &inspected.id)
    }
}

impl Drop for ManagedNetworkLease {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

#[derive(Debug)]
struct InspectedNetwork {
    id: String,
    subnet: IpNet,
    gateway: IpAddr,
    ipv6_subnet: Option<IpNet>,
    ipv6_gateway: Option<IpAddr>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NetworkTopologyRequirement {
    InternalIpv4Only,
    UplinkDualStack,
    UplinkLegacyCompatible,
}

impl NetworkTopologyRequirement {
    fn expected_internal(self) -> bool {
        self == Self::InternalIpv4Only
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct NetworkCandidate {
    ipv4_subnet: IpNet,
    ipv4_gateway: IpAddr,
    ipv6_subnet: Option<IpNet>,
    ipv6_gateway: Option<IpAddr>,
}

#[derive(Debug, Clone)]
struct GatewayContainerRuntimeIdentity {
    name: String,
    id: Option<String>,
    policy_id: String,
    listener_ip: IpAddr,
    image: GatewayContainerSpec,
    internal_network_name: String,
    uplink_network_name: String,
    uplink_subnets: Option<(IpNet, IpNet)>,
}

#[derive(Debug, Clone)]
struct GatewayProbeRuntimeIdentity {
    name: String,
    id: Option<String>,
    policy_id: String,
    image: GatewayContainerSpec,
    internal_network_name: String,
    gateway: SocketAddr,
}

#[derive(Debug)]
struct InspectedGatewayContainer {
    id: String,
    running: bool,
    exit_code: Option<i32>,
}

#[derive(Debug, Clone)]
struct GatewayStatusDirectory {
    path: PathBuf,
}

impl GatewayStatusDirectory {
    fn status_path(&self) -> PathBuf {
        self.path.join("status.json")
    }
}

fn create_gateway_status_directory(
    policy_directory: &Path,
    policy_id: &str,
) -> AppResult<GatewayStatusDirectory> {
    let root = validate_policy_directory(policy_directory)?;
    validate_policy_id(policy_id)?;
    let path = root.join(format!("gateway-status-{policy_id}"));
    if path.parent() != Some(root.as_path()) {
        return Err(AppError::InvalidRequest(
            "gateway status path escaped its control directory".into(),
        ));
    }
    ensure_private_directory(&path)?;
    let canonical = fs::canonicalize(&path).map_err(|error| {
        AppError::Runtime(format!(
            "gateway status directory could not be resolved: {error}"
        ))
    })?;
    if canonical != path {
        return Err(AppError::NotAuthorized(
            "gateway status directory may not traverse symlinks or aliases".into(),
        ));
    }
    Ok(GatewayStatusDirectory { path })
}

/// The refusal record a cleanup can claim from what it read. A gateway that
/// writes `1.0.0` counts no refusals, so it yields no record. Like a case
/// file that predates the field, it claims nothing either way. A status it
/// could not read is recorded as such, never as zero refusals.
fn gateway_refusal_record(
    status: AppResult<Option<GatewayStatusDocument>>,
) -> Option<GatewayRefusalRecord> {
    match status {
        Ok(Some(status)) => status
            .refusals
            .map(|refusals| GatewayRefusalRecord::Counted {
                rate: refusals.rate,
                destination: refusals.destination,
                unauthorized_client: refusals.unauthorized_client,
            }),
        Ok(None) | Err(_) => Some(GatewayRefusalRecord::Unavailable),
    }
}

fn read_gateway_status(
    status_directory: &GatewayStatusDirectory,
) -> AppResult<Option<GatewayStatusDocument>> {
    let path = status_directory.status_path();
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(AppError::Runtime(format!(
                "gateway status could not be inspected: {error}"
            )));
        }
    };
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > MAX_GATEWAY_STATUS_BYTES as u64
    {
        return Err(AppError::NotAuthorized(
            "gateway status was not a bounded regular file".into(),
        ));
    }
    let mut options = OpenOptions::new();
    options.read(true);
    configure_no_follow_open(&mut options);
    let file = match options.open(&path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(AppError::Runtime(format!(
                "gateway status could not be read: {error}"
            )));
        }
    };
    read_opened_gateway_status(file).map(Some)
}

fn read_opened_gateway_status(file: fs::File) -> AppResult<GatewayStatusDocument> {
    let opened = file.metadata()?;
    if !opened.is_file() || opened.len() == 0 || opened.len() > MAX_GATEWAY_STATUS_BYTES as u64 {
        return Err(AppError::NotAuthorized(
            "opened gateway status was not a bounded regular file".into(),
        ));
    }
    let mut bytes = Vec::with_capacity(opened.len() as usize);
    file.take((MAX_GATEWAY_STATUS_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.is_empty() || bytes.len() > MAX_GATEWAY_STATUS_BYTES {
        return Err(AppError::NotAuthorized(
            "gateway status was empty or oversized".into(),
        ));
    }
    // The product runs the digest-pinned gateway image named in
    // runtime/managed-egress-gateway.json, not this source, and that image
    // writes 1.0.0. A reader that accepts only this source's newest schema
    // refuses every gateway the product actually starts. 1.0.0 support stays
    // until the pinned image writes 1.1.0.
    let probe: GatewayStatusSchemaProbe = serde_json::from_slice(&bytes)
        .map_err(|_| AppError::NotAuthorized("gateway status was malformed".into()))?;
    let status = match probe.schema_version.as_str() {
        "1.0.0" => {
            let document: GatewayStatusDocumentV1_0 = serde_json::from_slice(&bytes)
                .map_err(|_| AppError::NotAuthorized("gateway status was malformed".into()))?;
            GatewayStatusDocument {
                schema_version: document.schema_version,
                phase: document.phase,
                code: document.code,
                refusals: None,
            }
        }
        "1.1.0" => {
            let document: GatewayStatusDocumentV1_1 = serde_json::from_slice(&bytes)
                .map_err(|_| AppError::NotAuthorized("gateway status was malformed".into()))?;
            GatewayStatusDocument {
                schema_version: document.schema_version,
                phase: document.phase,
                code: document.code,
                refusals: Some(document.refusals),
            }
        }
        _ => {
            return Err(AppError::NotAuthorized(
                "gateway status schema is unsupported".into(),
            ));
        }
    };
    bounded_gateway_status_code(&status.code)?;
    let valid_pair = match status.phase {
        GatewayStatusPhase::Starting => status.code == "initializing",
        GatewayStatusPhase::Ready => status.code == "ready",
        GatewayStatusPhase::Failed => matches!(
            status.code.as_str(),
            "policy_inspection_failed"
                | "policy_invalid"
                | "listener_bind_failed"
                | "listener_failed"
                | "signal_handler_failed"
                | "status_write_failed"
        ),
        GatewayStatusPhase::Stopped => match status.schema_version.as_str() {
            "1.0.0" => status.code == "policy_expired",
            "1.1.0" => matches!(status.code.as_str(), "policy_expired" | "stopped"),
            _ => false,
        },
    };
    if !valid_pair {
        return Err(AppError::NotAuthorized(
            "gateway status used an unsupported phase/code pair".into(),
        ));
    }
    Ok(status)
}

#[cfg(unix)]
fn configure_no_follow_open(options: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;
    options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
}

#[cfg(not(unix))]
fn configure_no_follow_open(_options: &mut OpenOptions) {}

fn bounded_gateway_status_code(code: &str) -> AppResult<&str> {
    const CODES: &[&str] = &[
        "initializing",
        "ready",
        "policy_inspection_failed",
        "policy_invalid",
        "listener_bind_failed",
        "listener_failed",
        "signal_handler_failed",
        "status_write_failed",
        "policy_expired",
        "stopped",
    ];
    if CODES.contains(&code) {
        Ok(code)
    } else {
        Err(AppError::NotAuthorized(
            "gateway status contained an unsupported code".into(),
        ))
    }
}

fn remove_gateway_status_directory(status_directory: &GatewayStatusDirectory) -> AppResult<()> {
    let metadata = match fs::symlink_metadata(&status_directory.path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(AppError::NotAuthorized(
            "refusing to remove a replaced gateway status path".into(),
        ));
    }
    let mut entries = fs::read_dir(&status_directory.path)?;
    let mut files = Vec::new();
    while let Some(entry) = entries.next().transpose()? {
        let name = entry.file_name();
        if name != OsStr::new("status.json") && name != OsStr::new("status.tmp") {
            return Err(AppError::NotAuthorized(
                "gateway status directory contained an unexpected entry".into(),
            ));
        }
        let metadata = fs::symlink_metadata(entry.path())?;
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.len() > MAX_GATEWAY_STATUS_BYTES as u64
        {
            return Err(AppError::NotAuthorized(
                "gateway status directory contained a replaced entry".into(),
            ));
        }
        files.push(entry.path());
    }
    for file in files {
        fs::remove_file(file)?;
    }
    fs::remove_dir(&status_directory.path)?;
    if let Some(parent) = status_directory.path.parent() {
        sync_directory(parent)?;
    }
    Ok(())
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct GatewayStatusRefusals {
    rate: u64,
    destination: u64,
    unauthorized_client: u64,
}

#[derive(Debug, Deserialize)]
struct GatewayStatusSchemaProbe {
    schema_version: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GatewayStatusDocumentV1_0 {
    schema_version: String,
    phase: GatewayStatusPhase,
    code: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GatewayStatusDocumentV1_1 {
    schema_version: String,
    phase: GatewayStatusPhase,
    code: String,
    refusals: GatewayStatusRefusals,
}

#[derive(Debug, PartialEq, Eq)]
struct GatewayStatusDocument {
    schema_version: String,
    phase: GatewayStatusPhase,
    code: String,
    refusals: Option<GatewayStatusRefusals>,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum GatewayStatusPhase {
    Starting,
    Ready,
    Failed,
    Stopped,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct GatewayProbeDocument {
    schema_version: String,
    reachability_probe: String,
    gateway_reachable: bool,
    upstream_connect_attempted: bool,
}

#[derive(Debug)]
struct RuntimeOutput {
    success: bool,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

trait RuntimeCommands: Send + Sync {
    fn output(&self, provider: RuntimeProvider, args: &[OsString]) -> io::Result<RuntimeOutput>;

    fn output_with_timeout(
        &self,
        provider: RuntimeProvider,
        args: &[OsString],
        _timeout: Duration,
    ) -> io::Result<RuntimeOutput> {
        self.output(provider, args)
    }
}

struct DirectRuntimeCommands;

impl RuntimeCommands for DirectRuntimeCommands {
    fn output(&self, provider: RuntimeProvider, args: &[OsString]) -> io::Result<RuntimeOutput> {
        if provider == RuntimeProvider::ManagedLocal {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "managed-local runtime requires its verified private command context",
            ));
        }
        let context = RuntimeCommandContext::compatibility(
            provider,
            PathBuf::from(runtime_program(provider)),
        )
        .map_err(|error| io::Error::new(io::ErrorKind::PermissionDenied, error.to_string()))?;
        let output = context.output(args, MAX_INSPECT_BYTES as u64, RUNTIME_COMMAND_TIMEOUT)?;
        Ok(RuntimeOutput {
            success: output.status.success(),
            stdout: output.stdout,
            stderr: output.stderr,
        })
    }
}

struct ContextRuntimeCommands {
    context: RuntimeCommandContext,
}

impl RuntimeCommands for ContextRuntimeCommands {
    fn output(&self, provider: RuntimeProvider, args: &[OsString]) -> io::Result<RuntimeOutput> {
        self.output_with_timeout(provider, args, RUNTIME_COMMAND_TIMEOUT)
    }

    fn output_with_timeout(
        &self,
        provider: RuntimeProvider,
        args: &[OsString],
        timeout: Duration,
    ) -> io::Result<RuntimeOutput> {
        if provider != self.context.provider() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "durable managed-network provider differs from the trusted runtime context",
            ));
        }
        let output = self
            .context
            .output(args, MAX_INSPECT_BYTES as u64, timeout)?;
        Ok(RuntimeOutput {
            success: output.status.success(),
            stdout: output.stdout,
            stderr: output.stderr,
        })
    }
}

trait GatewayProcess: Send {
    fn has_exited(&mut self) -> io::Result<bool>;
    fn kill(&mut self) -> io::Result<()>;
    fn wait(&mut self) -> io::Result<()>;
}

impl GatewayProcess for Child {
    fn has_exited(&mut self) -> io::Result<bool> {
        self.try_wait().map(|status| status.is_some())
    }

    fn kill(&mut self) -> io::Result<()> {
        Child::kill(self)
    }

    fn wait(&mut self) -> io::Result<()> {
        Child::wait(self).map(|_| ())
    }
}

trait GatewayLauncher: Send + Sync {
    fn spawn(&self, binary: &Path, policy_path: &Path) -> io::Result<Box<dyn GatewayProcess>>;
}

struct DirectGatewayLauncher;

impl GatewayLauncher for DirectGatewayLauncher {
    fn spawn(&self, binary: &Path, policy_path: &Path) -> io::Result<Box<dyn GatewayProcess>> {
        let mut command = Command::new(binary);
        command.arg("--policy").arg(policy_path);
        command.env_clear();
        command.stdin(Stdio::null());
        command.stdout(Stdio::null());
        command.stderr(Stdio::null());
        command.spawn().map(|child| Box::new(child) as _)
    }
}

trait GatewayReadiness: Send + Sync {
    fn wait_until_ready(
        &self,
        process: &mut dyn GatewayProcess,
        listen_address: SocketAddr,
    ) -> AppResult<()>;
}

struct SocketGatewayReadiness;

impl GatewayReadiness for SocketGatewayReadiness {
    fn wait_until_ready(
        &self,
        process: &mut dyn GatewayProcess,
        listen_address: SocketAddr,
    ) -> AppResult<()> {
        let deadline = Instant::now() + GATEWAY_READY_TIMEOUT;
        loop {
            if process.has_exited().map_err(|error| {
                AppError::Runtime(format!("egress gateway could not be observed: {error}"))
            })? {
                return Err(AppError::Runtime(
                    "egress gateway exited before becoming ready".into(),
                ));
            }
            if TcpStream::connect_timeout(&listen_address, GATEWAY_CONNECT_PROBE_TIMEOUT).is_ok() {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(AppError::Runtime(
                    "egress gateway did not become ready within five seconds".into(),
                ));
            }
            thread::sleep(GATEWAY_READY_INTERVAL);
        }
    }
}

trait GatewayContainerReadiness: Send + Sync {
    fn wait_until_ready(
        &self,
        runtime: &dyn RuntimeCommands,
        provider: RuntimeProvider,
        container: &GatewayContainerRuntimeIdentity,
        status_directory: &GatewayStatusDirectory,
        policy_id: &str,
    ) -> AppResult<()>;
}

struct RuntimeGatewayContainerReadiness;

impl GatewayContainerReadiness for RuntimeGatewayContainerReadiness {
    fn wait_until_ready(
        &self,
        runtime: &dyn RuntimeCommands,
        provider: RuntimeProvider,
        container: &GatewayContainerRuntimeIdentity,
        status_directory: &GatewayStatusDirectory,
        policy_id: &str,
    ) -> AppResult<()> {
        let deadline = Instant::now() + GATEWAY_READY_TIMEOUT;
        loop {
            let ready = match read_gateway_status(status_directory)? {
                Some(status)
                    if status.phase == GatewayStatusPhase::Ready && status.code == "ready" =>
                {
                    true
                }
                Some(status)
                    if matches!(
                        status.phase,
                        GatewayStatusPhase::Failed | GatewayStatusPhase::Stopped
                    ) =>
                {
                    return Err(AppError::Runtime(format!(
                        "egress gateway container reported {}",
                        bounded_gateway_status_code(&status.code)?
                    )));
                }
                Some(status)
                    if status.phase == GatewayStatusPhase::Starting
                        && status.code == "initializing" =>
                {
                    false
                }
                Some(_) => {
                    return Err(AppError::NotAuthorized(
                        "egress gateway status used an unsupported phase/code pair".into(),
                    ));
                }
                None => false,
            };
            let inspected = inspect_required_gateway_container_with_mode(
                runtime,
                provider,
                container,
                policy_id,
                InternalAttachmentMode::PresentAllowUnassigned,
            )?;
            if !inspected.running {
                return Err(AppError::Runtime(format!(
                    "egress gateway container exited before becoming ready (exit code {})",
                    inspected
                        .exit_code
                        .map(|code| code.to_string())
                        .unwrap_or_else(|| "unavailable".into())
                )));
            }
            if ready {
                let exact =
                    inspect_required_gateway_container(runtime, provider, container, policy_id)?;
                if !exact.running {
                    return Err(AppError::Runtime(
                        "egress gateway container exited after reporting ready".into(),
                    ));
                }
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(AppError::Runtime(
                    "egress gateway container did not report ready within five seconds".into(),
                ));
            }
            thread::sleep(GATEWAY_READY_INTERVAL);
        }
    }
}

#[derive(Debug)]
struct PolicyFile {
    path: PathBuf,
    sha256: [u8; 32],
}

#[derive(Debug)]
struct RegistryFile {
    path: PathBuf,
    sha256: [u8; 32],
}

/// Reconciles only resources named by bounded, backend-owned recovery records
/// or by an exact durable execution identity. It deliberately has no prefix or
/// "remove all managed" operation.
pub struct ManagedNetworkRegistry {
    root: PathBuf,
    artifact_root: PathBuf,
    runtime: Arc<dyn RuntimeCommands>,
}

impl ManagedNetworkRegistry {
    pub fn new(root: impl AsRef<Path>, artifact_root: impl AsRef<Path>) -> AppResult<Self> {
        Self::with_runtime(
            root.as_ref(),
            artifact_root.as_ref(),
            Arc::new(DirectRuntimeCommands),
        )
    }

    pub fn new_with_runtime_context(
        root: impl AsRef<Path>,
        artifact_root: impl AsRef<Path>,
        context: RuntimeCommandContext,
    ) -> AppResult<Self> {
        Self::with_runtime(
            root.as_ref(),
            artifact_root.as_ref(),
            Arc::new(ContextRuntimeCommands { context }),
        )
    }

    fn with_runtime(
        root: &Path,
        artifact_root: &Path,
        runtime: Arc<dyn RuntimeCommands>,
    ) -> AppResult<Self> {
        let root = validate_policy_directory(root)?;
        let artifact_root = validate_policy_directory(artifact_root)?;
        if !root.starts_with(&artifact_root) || root == artifact_root {
            return Err(AppError::NotAuthorized(
                "managed-network registry must be a dedicated artifact subdirectory".into(),
            ));
        }
        Ok(Self {
            root,
            artifact_root,
            runtime,
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn reconcile_all(
        &self,
        now: DateTime<Utc>,
    ) -> AppResult<ManagedNetworkReconciliationSummary> {
        let mut summary = ManagedNetworkReconciliationSummary::default();
        let groups = self.load_groups(now, &mut summary)?;
        for (_policy_id, entries) in groups {
            match self.reconcile_record_group(&entries) {
                Ok(outcome) => {
                    summary.reconciled = summary.reconciled.saturating_add(1);
                    push_summary_detail(&mut summary, outcome.detail);
                }
                Err(error) => {
                    summary.incomplete = summary.incomplete.saturating_add(1);
                    push_summary_detail(
                        &mut summary,
                        bounded_cleanup_detail(&format!(
                            "managed-network recovery incomplete: {error}"
                        )),
                    );
                }
            }
        }
        Ok(summary)
    }

    /// Stops only compatibility gateways named by a complete durable container
    /// identity, without reconciling any network, policy, status, or registry
    /// state.
    ///
    /// Intent/network/uplink/policy phases have no exact gateway container ID,
    /// so they issue no runtime command. Managed-local records are owned by the
    /// separately verified managed-machine stop path and are skipped here.
    /// Malformed or inconsistent records remain byte-for-byte intact and are
    /// reported as retained ambiguity; no name or prefix is ever promoted to
    /// mutation authority. Absence from the current provider context is not
    /// absence proof for a container created through an earlier context.
    pub fn stop_verified_compatibility_gateways(
        &self,
        now: DateTime<Utc>,
    ) -> ManagedCompatibilityGatewayStopSummary {
        let mut result = ManagedCompatibilityGatewayStopSummary::default();
        // One exact stop can consume at most three fixed 30-second runtime
        // calls. Stop admitting new calls at seven minutes so the current call
        // still returns within the package coordinator's ten-minute envelope.
        let stop_deadline = Instant::now() + PRODUCT_UNINSTALL_GATEWAY_STOP_DEADLINE;
        let mut load_summary = ManagedNetworkReconciliationSummary::default();
        let groups = match self.load_groups(now, &mut load_summary) {
            Ok(groups) => groups,
            Err(_) => {
                result.retained_ambiguities = load_summary.incomplete.saturating_add(1);
                result.contact_inventory_incomplete = true;
                return result;
            }
        };
        result.retained_ambiguities = load_summary.incomplete;

        for entries in groups.values() {
            let latest = match latest_record(entries) {
                Ok(latest) => latest,
                Err(_) => {
                    result.retained_ambiguities = result.retained_ambiguities.saturating_add(1);
                    continue;
                }
            };
            if latest.provider == RuntimeProvider::ManagedLocal {
                continue;
            }
            if latest.gateway_container_id.is_none() {
                // `Ready` is the terminal phase written by the legacy native
                // host gateway. It has no durable process/container identity,
                // so uninstall cannot prove target contact stopped and must
                // preserve/disclose it without inventing PID or name authority.
                if latest.phase == RegistryPhase::Ready {
                    result.retained_ambiguities = result.retained_ambiguities.saturating_add(1);
                }
                continue;
            }

            let identity = match gateway_container_identity_from_record(latest) {
                Ok(Some(identity)) => identity,
                // A malformed or incomplete record is not authority to assert
                // that one exact product gateway exists. Preserve it as
                // ambiguity instead of turning uncertainty into a hard block.
                Ok(None) | Err(_) => {
                    result.retained_ambiguities = result.retained_ambiguities.saturating_add(1);
                    continue;
                }
            };
            result.exact_gateways_found = result.exact_gateways_found.saturating_add(1);
            if Instant::now() >= stop_deadline {
                result.exact_stop_failures = result.exact_stop_failures.saturating_add(1);
                continue;
            }
            match stop_gateway_container_for_product_uninstall(
                self.runtime.as_ref(),
                latest.provider,
                &identity,
                &latest.policy_id,
            ) {
                Ok(()) => {
                    // The exact container was observed in this provider
                    // context and is now stopped. The registry is intentionally
                    // retained for the later bounded cleanup phase.
                    result.exact_gateways_stopped = result.exact_gateways_stopped.saturating_add(1);
                }
                // An identity mismatch proves only that the live object is not
                // the exact disposable gateway described by this record. It is
                // preserved as unrelated/ambiguous state. Runtime I/O or an
                // exact removal that fails remains a real contact-stop failure.
                Err(AppError::NotAuthorized(_)) => {
                    result.retained_ambiguities = result.retained_ambiguities.saturating_add(1);
                }
                Err(_) => {
                    result.exact_stop_failures = result.exact_stop_failures.saturating_add(1);
                }
            }
        }
        result
    }

    /// Reconciles only validated Docker/Podman records for the disposable
    /// gateway-container backend after the uninstall coordinator has proven
    /// target contact stopped.
    ///
    /// This is intentionally narrower than [`Self::reconcile_all`]. It skips
    /// managed-local records (owned by the managed-machine lifecycle) and all
    /// legacy direct-host records (which have no durable process identity).
    /// Incomplete or malformed state remains recorded in `incomplete` and is
    /// never selected by a name or prefix.
    pub fn reconcile_verified_compatibility_gateway_records(
        &self,
        now: DateTime<Utc>,
    ) -> ManagedNetworkReconciliationSummary {
        let mut summary = ManagedNetworkReconciliationSummary::default();
        let groups = match self.load_groups(now, &mut summary) {
            Ok(groups) => groups,
            Err(error) => {
                summary.incomplete = summary.incomplete.saturating_add(1);
                push_summary_detail(
                    &mut summary,
                    bounded_cleanup_detail(&format!(
                        "compatibility gateway cleanup incomplete: {error}"
                    )),
                );
                return summary;
            }
        };
        for entries in groups.values() {
            let latest = match latest_record(entries) {
                Ok(latest) => latest,
                Err(error) => {
                    summary.incomplete = summary.incomplete.saturating_add(1);
                    push_summary_detail(
                        &mut summary,
                        bounded_cleanup_detail(&format!(
                            "compatibility gateway cleanup incomplete: {error}"
                        )),
                    );
                    continue;
                }
            };
            if latest.provider == RuntimeProvider::ManagedLocal
                || latest.gateway_container_name.is_none()
            {
                continue;
            }
            match self.reconcile_record_group(entries) {
                Ok(outcome) => {
                    summary.reconciled = summary.reconciled.saturating_add(1);
                    push_summary_detail(&mut summary, outcome.detail);
                }
                Err(error) => {
                    summary.incomplete = summary.incomplete.saturating_add(1);
                    push_summary_detail(
                        &mut summary,
                        bounded_cleanup_detail(&format!(
                            "compatibility gateway cleanup incomplete: {error}"
                        )),
                    );
                }
            }
        }
        summary
    }

    pub fn reconcile_identity(
        &self,
        owner: &ManagedNetworkOwner,
        identity: &ManagedNetworkIdentity,
        now: DateTime<Utc>,
    ) -> AppResult<ManagedNetworkCleanupOutcome> {
        owner.validate()?;
        identity.validate()?;
        validate_identity_relation(identity)?;
        let provenance_case = match &identity.provenance {
            EgressGatewayProvenance::ExternalAssetGrants { case_id, .. }
            | EgressGatewayProvenance::ProviderService { case_id, .. }
            | EgressGatewayProvenance::ReleaseQualification { case_id, .. } => case_id,
        };
        if provenance_case != &owner.case_id {
            return Err(AppError::NotAuthorized(
                "managed-network checkpoint provenance belongs to a different case".into(),
            ));
        }

        let mut ignored_summary = ManagedNetworkReconciliationSummary::default();
        let mut groups = self.load_groups(now, &mut ignored_summary)?;
        let entries = groups.remove(&identity.policy_id).unwrap_or_default();
        if !entries.is_empty() {
            let latest = latest_record(&entries)?;
            if latest.owner != *owner
                || latest.provider != identity.provider
                || latest.network_name != identity.network_name
                || latest.policy_id != identity.policy_id
                || latest.expires_at != identity.expires_at
                || latest
                    .network_id
                    .as_deref()
                    .is_some_and(|id| id != identity.network_id)
                || latest
                    .policy_sha256
                    .as_deref()
                    .is_some_and(|sha| sha != identity.policy_sha256)
                || latest.uplink_network_name != identity.uplink_network_name
                || latest
                    .uplink_network_id
                    .as_deref()
                    .is_some_and(|id| Some(id) != identity.uplink_network_id.as_deref())
                || latest.gateway_container_name != identity.gateway_container_name
                || latest
                    .gateway_container_id
                    .as_deref()
                    .is_some_and(|id| Some(id) != identity.gateway_container_id.as_deref())
                || latest.gateway_listener_ip != identity.gateway_listener_ip
                || latest.gateway_image_repository != identity.gateway_image_repository
                || latest.gateway_image_digest != identity.gateway_image_digest
            {
                return Err(AppError::NotAuthorized(
                    "durable checkpoint does not match its managed-network registry record".into(),
                ));
            }
        }

        self.remove_gateway_probe_from_identity(identity)?;
        self.remove_gateway_container_from_identity(identity)?;
        self.remove_exact_runtime_network(
            identity.provider,
            &identity.network_name,
            &identity.network_id,
            &identity.policy_id,
        )?;
        self.remove_uplink_network_from_identity(identity)?;
        let gateway_refusals =
            self.remove_exact_gateway_status(&owner.case_id, &identity.policy_id)?;
        self.remove_exact_policy(
            &owner.case_id,
            &identity.policy_id,
            identity.expires_at,
            Some(&identity.policy_sha256),
        )?;
        for (_, file) in entries {
            remove_registry_file(&file)?;
        }
        Ok(ManagedNetworkCleanupOutcome {
            removed: true,
            detail: format!(
                "exact managed egress policy {} was reconciled before resume",
                identity.policy_id
            ),
            gateway_refusals,
        })
    }

    fn reconcile_record_group(
        &self,
        entries: &[(ManagedNetworkRecord, RegistryFile)],
    ) -> AppResult<ManagedNetworkCleanupOutcome> {
        let latest = latest_record(entries)?;
        self.remove_gateway_probe_from_record(latest)?;
        self.remove_gateway_container_from_record(latest)?;
        let expected_id = latest.network_id.as_deref();
        self.remove_runtime_network_from_record(latest, expected_id)?;
        self.remove_uplink_network_from_record(latest)?;
        let gateway_refusals =
            self.remove_exact_gateway_status(&latest.owner.case_id, &latest.policy_id)?;
        self.remove_exact_policy(
            &latest.owner.case_id,
            &latest.policy_id,
            latest.expires_at,
            latest.policy_sha256.as_deref(),
        )?;
        for (_, file) in entries {
            remove_registry_file(file)?;
        }
        Ok(ManagedNetworkCleanupOutcome {
            removed: true,
            detail: format!(
                "reconciled exact orphaned managed egress policy {}",
                latest.policy_id
            ),
            gateway_refusals,
        })
    }

    fn remove_runtime_network_from_record(
        &self,
        record: &ManagedNetworkRecord,
        expected_id: Option<&str>,
    ) -> AppResult<()> {
        let inspected = inspect_optional_network(
            self.runtime.as_ref(),
            record.provider,
            &record.network_name,
            &expected_labels(&record.policy_id),
        )?;
        let Some(inspected) = inspected else {
            return Ok(());
        };
        if expected_id.is_some_and(|expected| expected != inspected.id) {
            return Err(AppError::NotAuthorized(format!(
                "refusing to remove replaced container network {}",
                record.network_name
            )));
        }
        // Remove by the immutable id returned by the exact name/label/internal
        // inspection, never by a prefix or an unverified reusable name.
        remove_network(self.runtime.as_ref(), record.provider, &inspected.id)
    }

    fn remove_gateway_container_from_record(&self, record: &ManagedNetworkRecord) -> AppResult<()> {
        let Some(identity) = gateway_container_identity_from_record(record)? else {
            return Ok(());
        };
        remove_gateway_container(
            self.runtime.as_ref(),
            record.provider,
            &identity,
            &record.policy_id,
        )
    }

    fn remove_gateway_probe_from_record(&self, record: &ManagedNetworkRecord) -> AppResult<()> {
        let Some(probe) = gateway_probe_identity_from_record(record)? else {
            return Ok(());
        };
        remove_gateway_probe(self.runtime.as_ref(), record.provider, &probe)
    }

    fn remove_gateway_probe_from_identity(
        &self,
        identity: &ManagedNetworkIdentity,
    ) -> AppResult<()> {
        let Some(probe) = gateway_probe_identity_from_durable(identity)? else {
            return Ok(());
        };
        remove_gateway_probe(self.runtime.as_ref(), identity.provider, &probe)
    }

    fn remove_gateway_container_from_identity(
        &self,
        identity: &ManagedNetworkIdentity,
    ) -> AppResult<()> {
        let Some(container) = gateway_container_identity_from_durable(identity)? else {
            return Ok(());
        };
        remove_gateway_container(
            self.runtime.as_ref(),
            identity.provider,
            &container,
            &identity.policy_id,
        )
    }

    fn remove_uplink_network_from_record(&self, record: &ManagedNetworkRecord) -> AppResult<()> {
        let Some(name) = record.uplink_network_name.as_deref() else {
            return Ok(());
        };
        let inspected = inspect_optional_uplink_network_for_cleanup(
            self.runtime.as_ref(),
            record.provider,
            name,
            &expected_uplink_labels(&record.policy_id),
        )?;
        let Some(inspected) = inspected else {
            return Ok(());
        };
        if record
            .uplink_network_id
            .as_deref()
            .is_some_and(|expected| expected != inspected.id)
        {
            return Err(AppError::NotAuthorized(format!(
                "refusing to remove replaced gateway uplink network {name}"
            )));
        }
        remove_network(self.runtime.as_ref(), record.provider, &inspected.id)
    }

    fn remove_uplink_network_from_identity(
        &self,
        identity: &ManagedNetworkIdentity,
    ) -> AppResult<()> {
        let (Some(name), Some(expected_id)) = (
            identity.uplink_network_name.as_deref(),
            identity.uplink_network_id.as_deref(),
        ) else {
            return Ok(());
        };
        let inspected = inspect_optional_uplink_network_for_cleanup(
            self.runtime.as_ref(),
            identity.provider,
            name,
            &expected_uplink_labels(&identity.policy_id),
        )?;
        let Some(inspected) = inspected else {
            return Ok(());
        };
        if inspected.id != expected_id {
            return Err(AppError::NotAuthorized(format!(
                "refusing to remove replaced gateway uplink network {name}"
            )));
        }
        remove_network(self.runtime.as_ref(), identity.provider, expected_id)
    }

    fn remove_exact_runtime_network(
        &self,
        provider: RuntimeProvider,
        network_name: &str,
        network_id: &str,
        policy_id: &str,
    ) -> AppResult<()> {
        let inspected = inspect_optional_network(
            self.runtime.as_ref(),
            provider,
            network_name,
            &expected_labels(policy_id),
        )?;
        let Some(inspected) = inspected else {
            return Ok(());
        };
        if inspected.id != network_id {
            return Err(AppError::NotAuthorized(format!(
                "refusing to remove replaced container network {network_name}"
            )));
        }
        remove_network(self.runtime.as_ref(), provider, network_id)
    }

    fn remove_exact_policy(
        &self,
        case_id: &str,
        policy_id: &str,
        expires_at: DateTime<Utc>,
        expected_sha256: Option<&str>,
    ) -> AppResult<()> {
        validate_owner_segment(case_id, "case")?;
        validate_policy_id(policy_id)?;
        let case_root = self.artifact_root.join(case_id);
        let policy_directory = case_root.join("network-policies");
        for (directory, expected_parent) in [
            (case_root.as_path(), self.artifact_root.as_path()),
            (policy_directory.as_path(), case_root.as_path()),
        ] {
            let metadata = match fs::symlink_metadata(directory) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
                Err(error) => return Err(error.into()),
            };
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(AppError::NotAuthorized(
                    "managed-network recovery case path is not a real directory".into(),
                ));
            }
            let canonical = directory.canonicalize()?;
            let canonical_parent = expected_parent.canonicalize()?;
            if canonical.parent() != Some(canonical_parent.as_path()) {
                return Err(AppError::NotAuthorized(
                    "managed-network recovery case path escaped the artifact root".into(),
                ));
            }
        }
        let path = policy_directory.join(format!("egress-{policy_id}.json"));
        if path.parent() != Some(policy_directory.as_path()) {
            return Err(AppError::NotAuthorized(
                "managed-network recovery policy path escaped its case directory".into(),
            ));
        }
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error.into()),
        };
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.len() == 0
            || metadata.len() > MAX_POLICY_BYTES as u64
        {
            return Err(AppError::NotAuthorized(
                "refusing to remove a replaced managed egress policy path".into(),
            ));
        }
        let bytes = fs::read(&path)?;
        let policy: EgressGatewayPolicy = serde_json::from_slice(&bytes).map_err(|_| {
            AppError::NotAuthorized(
                "refusing to remove a malformed managed egress policy file".into(),
            )
        })?;
        if policy.schema_version != POLICY_SCHEMA_VERSION
            || policy.policy_id != policy_id
            || policy.expires_at != expires_at
        {
            return Err(AppError::NotAuthorized(
                "refusing to remove a policy file with a different durable identity".into(),
            ));
        }
        validate_egress_provenance(&policy.provenance)?;
        let provenance_case = match &policy.provenance {
            EgressGatewayProvenance::ExternalAssetGrants { case_id, .. }
            | EgressGatewayProvenance::ProviderService { case_id, .. }
            | EgressGatewayProvenance::ReleaseQualification { case_id, .. } => case_id,
        };
        if provenance_case != case_id {
            return Err(AppError::NotAuthorized(
                "refusing to remove a policy file owned by a different case".into(),
            ));
        }
        let actual: [u8; 32] = Sha256::digest(&bytes).into();
        if expected_sha256.is_some_and(|expected| hex::encode(actual) != expected) {
            return Err(AppError::NotAuthorized(
                "refusing to remove a modified managed egress policy file".into(),
            ));
        }
        remove_policy_file(&PolicyFile {
            path,
            sha256: actual,
        })
    }

    /// Recovery removes the status document the lease would have read at
    /// cleanup, so it reads it first. Otherwise a run cleaned up after the
    /// desktop restarted reports nothing about the connections its gateway
    /// refused. `None` means no status directory was ever created for this
    /// policy, which is also the case in which the lease reads nothing, or
    /// that the gateway does not record refusals.
    fn remove_exact_gateway_status(
        &self,
        case_id: &str,
        policy_id: &str,
    ) -> AppResult<Option<GatewayRefusalRecord>> {
        validate_owner_segment(case_id, "case")?;
        validate_policy_id(policy_id)?;
        let case_root = self.artifact_root.join(case_id);
        let policy_directory = case_root.join("network-policies");
        for (directory, expected_parent) in [
            (case_root.as_path(), self.artifact_root.as_path()),
            (policy_directory.as_path(), case_root.as_path()),
        ] {
            let metadata = match fs::symlink_metadata(directory) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
                Err(error) => return Err(error.into()),
            };
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(AppError::NotAuthorized(
                    "managed-network recovery status path is not a real directory".into(),
                ));
            }
            let canonical = directory.canonicalize()?;
            let canonical_parent = expected_parent.canonicalize()?;
            if canonical.parent() != Some(canonical_parent.as_path()) {
                return Err(AppError::NotAuthorized(
                    "managed-network recovery status path escaped the artifact root".into(),
                ));
            }
        }
        let path = policy_directory.join(format!("gateway-status-{policy_id}"));
        if path.parent() != Some(policy_directory.as_path()) {
            return Err(AppError::NotAuthorized(
                "managed-network recovery status path escaped its case directory".into(),
            ));
        }
        let directory = GatewayStatusDirectory { path };
        // Read only a real directory, the check the removal below applies, so
        // a replaced path is refused rather than read through.
        let record = match fs::symlink_metadata(&directory.path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
                gateway_refusal_record(read_gateway_status(&directory))
            }
            _ => Some(GatewayRefusalRecord::Unavailable),
        };
        remove_gateway_status_directory(&directory)?;
        Ok(record)
    }

    fn load_groups(
        &self,
        now: DateTime<Utc>,
        summary: &mut ManagedNetworkReconciliationSummary,
    ) -> AppResult<BTreeMap<String, Vec<(ManagedNetworkRecord, RegistryFile)>>> {
        let mut paths = fs::read_dir(&self.root)?
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .map(|entry| entry.path())
            .collect::<Vec<_>>();
        paths.sort();
        if paths.len() > MAX_REGISTRY_RECORDS {
            return Err(AppError::Runtime(format!(
                "managed-network registry exceeds its bounded limit of {MAX_REGISTRY_RECORDS} records"
            )));
        }
        let mut groups = BTreeMap::<String, Vec<(ManagedNetworkRecord, RegistryFile)>>::new();
        for path in paths {
            match read_registry_snapshot(&self.root, &path, now) {
                Ok((record, file)) => groups
                    .entry(record.policy_id.clone())
                    .or_default()
                    .push((record, file)),
                Err(error) => {
                    summary.incomplete = summary.incomplete.saturating_add(1);
                    push_summary_detail(
                        summary,
                        bounded_cleanup_detail(&format!(
                            "unrecognized managed-network recovery record was retained: {error}"
                        )),
                    );
                }
            }
        }
        for entries in groups.values_mut() {
            entries.sort_by_key(|(record, _)| record.phase.sequence());
        }
        Ok(groups)
    }
}

fn validate_record_shape(record: &ManagedNetworkRecord, now: DateTime<Utc>) -> AppResult<()> {
    if record.schema_version != REGISTRY_SCHEMA_VERSION {
        return Err(AppError::InvalidRequest(
            "managed-network registry schema is unsupported".into(),
        ));
    }
    record.owner.validate()?;
    validate_network_name(&record.network_name)?;
    validate_policy_id(&record.policy_id)?;
    validate_network_policy_relation(&record.network_name, &record.policy_id)?;
    if record.created_at > now + ChronoDuration::minutes(5)
        || record.expires_at <= record.created_at
        || record.expires_at > record.created_at + ChronoDuration::hours(24)
    {
        return Err(AppError::InvalidRequest(
            "managed-network registry lifetime is invalid".into(),
        ));
    }
    let container_mode = record.uplink_network_name.is_some()
        || record.uplink_network_id.is_some()
        || record.gateway_container_name.is_some()
        || record.gateway_container_id.is_some()
        || record.gateway_listener_ip.is_some()
        || record.gateway_image_repository.is_some()
        || record.gateway_image_digest.is_some();
    if container_mode {
        validate_gateway_static_identity(
            &record.policy_id,
            record.uplink_network_name.as_deref(),
            record.gateway_container_name.as_deref(),
            record.gateway_image_repository.as_deref(),
            record.gateway_image_digest.as_deref(),
        )?;
        let consistent = match record.phase {
            RegistryPhase::Intent => {
                record.network_id.is_none()
                    && record.uplink_network_id.is_none()
                    && record.gateway_container_id.is_none()
                    && record.gateway_listener_ip.is_none()
                    && record.policy_sha256.is_none()
            }
            RegistryPhase::NetworkVerified => {
                record.network_id.is_some()
                    && record.uplink_network_id.is_none()
                    && record.gateway_container_id.is_none()
                    && record.gateway_listener_ip.is_none()
                    && record.policy_sha256.is_none()
            }
            RegistryPhase::UplinkVerified => {
                record.network_id.is_some()
                    && record.uplink_network_id.is_some()
                    && record.gateway_container_id.is_none()
                    && record.gateway_listener_ip.is_none()
                    && record.policy_sha256.is_none()
            }
            RegistryPhase::PolicyReady => {
                record.network_id.is_some()
                    && record.uplink_network_id.is_some()
                    && record.gateway_container_id.is_none()
                    && record.gateway_listener_ip.is_some()
                    && record.policy_sha256.is_some()
            }
            RegistryPhase::GatewayContainerVerified | RegistryPhase::ContainerReady => {
                record.network_id.is_some()
                    && record.uplink_network_id.is_some()
                    && record.gateway_container_id.is_some()
                    && record.gateway_listener_ip.is_some()
                    && record.policy_sha256.is_some()
            }
            RegistryPhase::Ready => false,
        };
        if !consistent {
            return Err(AppError::InvalidRequest(
                "managed gateway-container registry phase is inconsistent".into(),
            ));
        }
    } else {
        match record.phase {
            RegistryPhase::Intent
                if record.network_id.is_none() && record.policy_sha256.is_none() => {}
            RegistryPhase::NetworkVerified
                if record.network_id.is_some() && record.policy_sha256.is_none() => {}
            RegistryPhase::Ready
                if record.network_id.is_some() && record.policy_sha256.is_some() => {}
            _ => {
                return Err(AppError::InvalidRequest(
                    "managed-network registry phase is inconsistent".into(),
                ));
            }
        }
    }
    if let Some(network_id) = record.network_id.as_deref() {
        validate_runtime_id(network_id)?;
    }
    if let Some(network_id) = record.uplink_network_id.as_deref() {
        validate_runtime_id(network_id)?;
    }
    if let Some(container_id) = record.gateway_container_id.as_deref() {
        validate_runtime_id(container_id)?;
    }
    if let Some(sha256) = record.policy_sha256.as_deref() {
        decode_sha256(sha256)?;
    }
    Ok(())
}

fn validate_record_chain(entries: &[(ManagedNetworkRecord, RegistryFile)]) -> AppResult<()> {
    let Some((first, _)) = entries.first() else {
        return Err(AppError::InvalidRequest(
            "managed-network registry group is empty".into(),
        ));
    };
    let mut previous_sequence = None;
    for (record, _) in entries {
        let sequence = record.phase.sequence();
        if previous_sequence == Some(sequence)
            || record.owner != first.owner
            || record.provider != first.provider
            || record.network_name != first.network_name
            || record.policy_id != first.policy_id
            || record.created_at != first.created_at
            || record.expires_at != first.expires_at
            || record.uplink_network_name != first.uplink_network_name
            || record.gateway_container_name != first.gateway_container_name
            || record.gateway_image_repository != first.gateway_image_repository
            || record.gateway_image_digest != first.gateway_image_digest
        {
            return Err(AppError::NotAuthorized(
                "managed-network registry snapshots do not form one exact identity chain".into(),
            ));
        }
        previous_sequence = Some(sequence);
    }
    Ok(())
}

fn latest_record(
    entries: &[(ManagedNetworkRecord, RegistryFile)],
) -> AppResult<&ManagedNetworkRecord> {
    validate_record_chain(entries)?;
    entries
        .last()
        .map(|(record, _)| record)
        .ok_or_else(|| AppError::InvalidRequest("managed-network registry group is empty".into()))
}

fn registry_filename(record: &ManagedNetworkRecord) -> String {
    format!(
        "{}.{}-{}.json",
        record.policy_id,
        record.phase.sequence(),
        match record.phase {
            RegistryPhase::Intent => "intent",
            RegistryPhase::NetworkVerified => "network",
            RegistryPhase::Ready => "ready",
            RegistryPhase::UplinkVerified => "uplink",
            RegistryPhase::PolicyReady => "policy",
            RegistryPhase::GatewayContainerVerified => "gateway",
            RegistryPhase::ContainerReady => "container-ready",
        }
    )
}

fn write_registry_snapshot(
    directory: &Path,
    record: &ManagedNetworkRecord,
) -> AppResult<RegistryFile> {
    validate_record_shape(record, Utc::now())?;
    let bytes = serde_json::to_vec(record).map_err(|error| {
        AppError::Internal(format!(
            "managed-network registry serialization failed: {error}"
        ))
    })?;
    if bytes.is_empty() || bytes.len() > MAX_REGISTRY_RECORD_BYTES {
        return Err(AppError::InvalidRequest(
            "managed-network registry record exceeds its bounded size".into(),
        ));
    }
    let path = directory.join(registry_filename(record));
    if path.parent() != Some(directory) {
        return Err(AppError::NotAuthorized(
            "managed-network registry path escaped its control directory".into(),
        ));
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    configure_private_create(&mut options);
    let mut file = options.open(&path).map_err(|error| {
        AppError::Runtime(format!(
            "managed-network registry record could not be created: {error}"
        ))
    })?;
    let result = (|| -> AppResult<()> {
        file.write_all(&bytes)?;
        file.sync_all()?;
        restrict_registry_file(&path)?;
        sync_directory(directory)?;
        Ok(())
    })();
    if let Err(error) = result {
        let _ = remove_exact_regular_file(&path);
        return Err(error);
    }
    Ok(RegistryFile {
        path,
        sha256: Sha256::digest(&bytes).into(),
    })
}

fn read_registry_snapshot(
    root: &Path,
    path: &Path,
    now: DateTime<Utc>,
) -> AppResult<(ManagedNetworkRecord, RegistryFile)> {
    if path.parent() != Some(root) {
        return Err(AppError::NotAuthorized(
            "managed-network registry entry escaped its root".into(),
        ));
    }
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > MAX_REGISTRY_RECORD_BYTES as u64
    {
        return Err(AppError::NotAuthorized(
            "managed-network registry entry is not a bounded regular file".into(),
        ));
    }
    let bytes = fs::read(path)?;
    let record: ManagedNetworkRecord = serde_json::from_slice(&bytes).map_err(|_| {
        AppError::InvalidRequest("managed-network registry entry is malformed".into())
    })?;
    validate_record_shape(&record, now)?;
    if path.file_name() != Some(OsStr::new(&registry_filename(&record))) {
        return Err(AppError::NotAuthorized(
            "managed-network registry filename does not match its identity".into(),
        ));
    }
    Ok((
        record,
        RegistryFile {
            path: path.to_owned(),
            sha256: Sha256::digest(&bytes).into(),
        },
    ))
}

fn remove_registry_file(file: &RegistryFile) -> AppResult<()> {
    let metadata = match fs::symlink_metadata(&file.path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > MAX_REGISTRY_RECORD_BYTES as u64
    {
        return Err(AppError::NotAuthorized(
            "refusing to remove a replaced managed-network registry path".into(),
        ));
    }
    let actual: [u8; 32] = Sha256::digest(fs::read(&file.path)?).into();
    if actual != file.sha256 {
        return Err(AppError::NotAuthorized(
            "refusing to remove a modified managed-network registry entry".into(),
        ));
    }
    fs::remove_file(&file.path)?;
    if let Some(parent) = file.path.parent() {
        sync_directory(parent)?;
    }
    Ok(())
}

fn inspect_optional_network(
    runtime: &dyn RuntimeCommands,
    provider: RuntimeProvider,
    network_name: &str,
    labels: &BTreeMap<String, String>,
) -> AppResult<Option<InspectedNetwork>> {
    let output = runtime_output(
        runtime,
        provider,
        &["network".into(), "inspect".into(), network_name.into()],
    )?;
    if !output.success {
        if runtime_reports_network_absent(&output.stderr, network_name) {
            return Ok(None);
        }
        return Err(runtime_failure("managed network inspection", &output));
    }
    parse_network_inspect(provider, &output.stdout, network_name, labels).map(Some)
}

fn remove_intent_network(
    runtime: &dyn RuntimeCommands,
    provider: RuntimeProvider,
    network_name: &str,
    labels: &BTreeMap<String, String>,
) -> AppResult<()> {
    let Some(inspected) = inspect_optional_network(runtime, provider, network_name, labels)? else {
        return Ok(());
    };
    remove_network(runtime, provider, &inspected.id)
}

fn validate_network_name(value: &str) -> AppResult<()> {
    if value.is_empty()
        || value.len() > 128
        || !value.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.')
        })
    {
        return Err(AppError::InvalidRequest(
            "managed-network runtime name is invalid".into(),
        ));
    }
    Ok(())
}

fn validate_runtime_id(value: &str) -> AppResult<()> {
    if value.trim().is_empty()
        || value.len() > 256
        || value.contains(['\n', '\r', '\0'])
        || value.starts_with('-')
        || value.chars().any(char::is_whitespace)
    {
        return Err(AppError::InvalidRequest(
            "managed-network runtime id is invalid".into(),
        ));
    }
    Ok(())
}

fn validate_owner_segment(value: &str, label: &str) -> AppResult<()> {
    if value.is_empty()
        || value.len() > 256
        || !value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
    {
        return Err(AppError::InvalidRequest(format!(
            "managed-network {label} identity is invalid"
        )));
    }
    Ok(())
}

fn validate_network_policy_relation(network_name: &str, policy_id: &str) -> AppResult<()> {
    let unique = policy_id.strip_prefix("egress-").ok_or_else(|| {
        AppError::InvalidRequest("managed egress policy id has no generated prefix".into())
    })?;
    if unique.len() != 32
        || !unique
            .chars()
            .all(|character| character.is_ascii_hexdigit())
        || network_name != format!("ass-egress-{unique}")
    {
        return Err(AppError::InvalidRequest(
            "managed network name does not match its generated policy identity".into(),
        ));
    }
    Ok(())
}

fn validate_gateway_static_identity(
    policy_id: &str,
    uplink_network_name: Option<&str>,
    gateway_container_name: Option<&str>,
    image_repository: Option<&str>,
    image_digest: Option<&str>,
) -> AppResult<()> {
    validate_policy_id(policy_id)?;
    let unique = policy_id.strip_prefix("egress-").ok_or_else(|| {
        AppError::InvalidRequest("managed egress policy id has no generated prefix".into())
    })?;
    let uplink_network_name = uplink_network_name.ok_or_else(|| {
        AppError::InvalidRequest("managed gateway uplink identity is incomplete".into())
    })?;
    let gateway_container_name = gateway_container_name.ok_or_else(|| {
        AppError::InvalidRequest("managed gateway container identity is incomplete".into())
    })?;
    validate_network_name(uplink_network_name)?;
    validate_network_name(gateway_container_name)?;
    if uplink_network_name != format!("ass-uplink-{unique}")
        || gateway_container_name != format!("ass-gateway-{unique}")
    {
        return Err(AppError::NotAuthorized(
            "managed gateway resources do not match their policy identity".into(),
        ));
    }
    GatewayContainerSpec::new(
        image_repository.ok_or_else(|| {
            AppError::InvalidRequest("managed gateway image repository is missing".into())
        })?,
        image_digest.ok_or_else(|| {
            AppError::InvalidRequest("managed gateway image digest is missing".into())
        })?,
    )?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_optional_gateway_identity(
    policy_id: &str,
    uplink_network_name: Option<&str>,
    uplink_network_id: Option<&str>,
    gateway_container_name: Option<&str>,
    gateway_container_id: Option<&str>,
    gateway_listener_ip: Option<IpAddr>,
    image_repository: Option<&str>,
    image_digest: Option<&str>,
) -> AppResult<()> {
    let present = [
        uplink_network_name.is_some(),
        uplink_network_id.is_some(),
        gateway_container_name.is_some(),
        gateway_container_id.is_some(),
        gateway_listener_ip.is_some(),
        image_repository.is_some(),
        image_digest.is_some(),
    ];
    if present.iter().all(|value| !value) {
        return Ok(());
    }
    if !present.iter().all(|value| *value) {
        return Err(AppError::InvalidRequest(
            "managed gateway checkpoint identity is incomplete".into(),
        ));
    }
    validate_gateway_static_identity(
        policy_id,
        uplink_network_name,
        gateway_container_name,
        image_repository,
        image_digest,
    )?;
    validate_runtime_id(uplink_network_id.expect("all optional gateway fields present"))?;
    validate_runtime_id(gateway_container_id.expect("all optional gateway fields present"))?;
    let listener = gateway_listener_ip.expect("all optional gateway fields present");
    if !is_sensitive_address(listener) || is_cloud_metadata(listener) || listener.is_unspecified() {
        return Err(AppError::NotAuthorized(
            "managed gateway listener must be a private runtime address".into(),
        ));
    }
    Ok(())
}

fn validate_identity_relation(identity: &ManagedNetworkIdentity) -> AppResult<()> {
    validate_network_policy_relation(&identity.network_name, &identity.policy_id)
}

fn validate_egress_provenance(provenance: &EgressGatewayProvenance) -> AppResult<()> {
    let valid_text = |value: &str| {
        !value.trim().is_empty() && value.len() <= 256 && !value.contains(['\n', '\r', '\0'])
    };
    let valid = match provenance {
        EgressGatewayProvenance::ExternalAssetGrants {
            case_id,
            grant_ids,
            activities,
        } => {
            valid_text(case_id)
                && !grant_ids.is_empty()
                && grant_ids.len() <= MAX_EXTERNAL_PLANS_PER_LEASE
                && grant_ids.iter().all(|value| valid_text(value))
                && !activities.is_empty()
                && activities.len() <= 3
        }
        EgressGatewayProvenance::ProviderService {
            case_id,
            source_id,
            source_kind,
            source_profile,
            manifest_id,
            manifest_revision,
        } => [
            case_id.as_str(),
            source_id.as_str(),
            source_kind.as_str(),
            source_profile.as_str(),
            manifest_id.as_str(),
            manifest_revision.as_str(),
        ]
        .into_iter()
        .all(valid_text),
        EgressGatewayProvenance::ReleaseQualification {
            case_id,
            qualification_id,
        } => valid_text(case_id) && valid_text(qualification_id),
    };
    if !valid {
        return Err(AppError::InvalidRequest(
            "managed-network policy provenance is invalid".into(),
        ));
    }
    Ok(())
}

fn decode_sha256(value: &str) -> AppResult<[u8; 32]> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(AppError::InvalidRequest(
            "managed-network policy digest is invalid".into(),
        ));
    }
    let mut decoded = [0_u8; 32];
    hex::decode_to_slice(value, &mut decoded)
        .map_err(|_| AppError::InvalidRequest("managed-network policy digest is invalid".into()))?;
    Ok(decoded)
}

fn bounded_cleanup_detail(value: &str) -> String {
    value
        .replace(['\n', '\r', '\0'], " ")
        .chars()
        .take(2_000)
        .collect()
}

fn push_summary_detail(summary: &mut ManagedNetworkReconciliationSummary, detail: String) {
    if summary.details.len() < 128 {
        summary.details.push(detail);
    }
}

fn ensure_private_directory(path: &Path) -> AppResult<()> {
    match fs::create_dir(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(AppError::NotAuthorized(
            "managed-network registry path must be a real directory".into(),
        ));
    }
    restrict_private_directory(path)?;
    Ok(())
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

#[cfg(unix)]
fn sync_directory(path: &Path) -> AppResult<()> {
    std::fs::File::open(path)?.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> AppResult<()> {
    Ok(())
}

#[cfg(unix)]
fn restrict_registry_file(path: &Path) -> AppResult<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o400))?;
    Ok(())
}

#[cfg(not(unix))]
fn restrict_registry_file(path: &Path) -> AppResult<()> {
    let mut permissions = fs::metadata(path)?.permissions();
    permissions.set_readonly(true);
    fs::set_permissions(path, permissions)?;
    Ok(())
}

fn host_network(address: IpAddr) -> IpNet {
    match address {
        IpAddr::V4(address) => IpNet::V4(Ipv4Net::new(address, 32).expect("IPv4 host prefix")),
        IpAddr::V6(address) => IpNet::V6(Ipv6Net::new(address, 128).expect("IPv6 host prefix")),
    }
}

fn frozen_plan_networks(plans: &[ResolvedExternalPlan]) -> Vec<IpNet> {
    let mut networks = BTreeSet::new();
    for plan in plans {
        if let CanonicalTarget::Network(network) = &plan.target {
            networks.insert(*network);
        }
        networks.extend(plan.resolution.addresses.iter().copied().map(host_network));
    }
    networks.into_iter().collect()
}

fn provider_plan_networks(plan: &ResolvedProviderServicePlan) -> Vec<IpNet> {
    plan.destinations
        .iter()
        .flat_map(|destination| destination.addresses.iter().copied())
        .map(host_network)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn networks_overlap(first: IpNet, second: IpNet) -> bool {
    match (first, second) {
        (IpNet::V4(first), IpNet::V4(second)) => {
            first.contains(&second.network()) || second.contains(&first.network())
        }
        (IpNet::V6(first), IpNet::V6(second)) => {
            first.contains(&second.network()) || second.contains(&first.network())
        }
        _ => false,
    }
}

fn candidate_private_networks(
    policy_id: &str,
    role: &str,
    prohibited: &[IpNet],
    dual_stack: bool,
) -> AppResult<Vec<NetworkCandidate>> {
    validate_policy_id(policy_id)?;
    let seed_digest = Sha256::digest(format!("{policy_id}:{role}").as_bytes());
    let seed = u64::from_be_bytes(seed_digest[..8].try_into().expect("eight digest bytes"));
    let mut candidates = Vec::new();
    let mut seen_v4 = BTreeSet::new();
    let mut seen_v6 = BTreeSet::new();
    for ordinal in 0..MAX_NETWORK_CANDIDATE_SEARCH {
        if candidates.len() == MAX_NETWORK_SUBNET_ATTEMPTS {
            break;
        }
        let mixed = seed.wrapping_add((ordinal as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15));
        let pool = (ordinal + usize::from(role == UPLINK_RESOURCE_ROLE)) % 3;
        let (base, count) = match pool {
            0 => (u32::from(Ipv4Addr::new(10, 0, 0, 0)), 1_u64 << 20),
            1 => (u32::from(Ipv4Addr::new(172, 16, 0, 0)), 1_u64 << 16),
            _ => (u32::from(Ipv4Addr::new(192, 168, 0, 0)), 1_u64 << 12),
        };
        let subnet_offset = u32::try_from(mixed % count).expect("private subnet index") * 16;
        let network_address = Ipv4Addr::from(base + subnet_offset);
        let ipv4 = IpNet::V4(
            Ipv4Net::new(network_address, 28)
                .map_err(|_| AppError::Internal("private IPv4 candidate was malformed".into()))?,
        );
        if !seen_v4.insert(ipv4)
            || prohibited
                .iter()
                .any(|network| networks_overlap(ipv4, *network))
        {
            continue;
        }

        let (ipv6_subnet, ipv6_gateway) = if dual_stack {
            let candidate_digest =
                Sha256::digest(format!("{policy_id}:{role}:ipv6:{ordinal}").as_bytes());
            let segments = [
                0xfd00 | u16::from(candidate_digest[0]),
                u16::from_be_bytes([candidate_digest[1], candidate_digest[2]]),
                u16::from_be_bytes([candidate_digest[3], candidate_digest[4]]),
                u16::from_be_bytes([candidate_digest[5], candidate_digest[6]]),
                0,
                0,
                0,
                0,
            ];
            let network =
                IpNet::V6(Ipv6Net::new(Ipv6Addr::from(segments), 64).map_err(|_| {
                    AppError::Internal("private IPv6 candidate was malformed".into())
                })?);
            if !seen_v6.insert(network)
                || prohibited
                    .iter()
                    .any(|prohibited| networks_overlap(network, *prohibited))
            {
                continue;
            }
            let mut gateway_segments = segments;
            gateway_segments[7] = 1;
            (
                Some(network),
                Some(IpAddr::V6(Ipv6Addr::from(gateway_segments))),
            )
        } else {
            (None, None)
        };
        candidates.push(NetworkCandidate {
            ipv4_subnet: ipv4,
            ipv4_gateway: IpAddr::V4(Ipv4Addr::from(base + subnet_offset + 1)),
            ipv6_subnet,
            ipv6_gateway,
        });
    }
    if candidates.is_empty() {
        return Err(AppError::NotAvailable(
            "no collision-free private container subnet is available for this scan".into(),
        ));
    }
    Ok(candidates)
}

fn validate_plans_without_bridge(
    plans: &[ResolvedExternalPlan],
    now: DateTime<Utc>,
) -> AppResult<()> {
    if plans.is_empty() || plans.len() > MAX_EXTERNAL_PLANS_PER_LEASE {
        return Err(AppError::NotAuthorized(
            "managed egress requires one or more bounded frozen plans".into(),
        ));
    }
    let case_id = plans[0].case_id.as_str();
    for plan in plans {
        validate_resolved_plan(plan, case_id, now)?;
    }
    Ok(())
}

fn validate_resolved_plan(
    plan: &ResolvedExternalPlan,
    expected_case_id: &str,
    now: DateTime<Utc>,
) -> AppResult<()> {
    for (name, value) in [
        ("grant", plan.grant_id.as_str()),
        ("case", plan.case_id.as_str()),
        ("asset", plan.asset_id.as_str()),
    ] {
        if value.trim().is_empty() || value.len() > 256 || value.contains(['\n', '\r', '\0']) {
            return Err(AppError::InvalidRequest(format!(
                "external plan {name} identifier is invalid"
            )));
        }
    }
    if expected_case_id.is_empty() || plan.case_id != expected_case_id {
        return Err(AppError::InvalidRequest(
            "one managed network cannot combine plans from different cases".into(),
        ));
    }
    if plan.expires_at <= now
        || plan.frozen_at > now
        || plan.resolution.resolved_at != plan.frozen_at
        || plan.expires_at - plan.frozen_at > ChronoDuration::days(30)
    {
        return Err(AppError::NotAuthorized(
            "external plan is expired, future-dated, or not a frozen resolution".into(),
        ));
    }
    if plan.resolution.addresses.is_empty() || plan.ports.is_empty() {
        return Err(AppError::NotAuthorized(
            "SOCKS egress requires explicit frozen addresses and ports".into(),
        ));
    }
    if plan.ports.contains(&0) {
        return Err(AppError::InvalidRequest(
            "external destination contains port zero".into(),
        ));
    }
    if plan.protocol == TransportProtocol::Udp {
        return Err(AppError::NotAvailable(
            "the managed gateway supports bounded TCP CONNECT only; UDP engines are not runnable through it"
                .into(),
        ));
    }

    validate_plan_rate_policy(plan)?;
    plan.template_policy.validate(plan.activity)?;

    match &plan.target {
        CanonicalTarget::Hostname(hostname) => {
            let reparsed = CanonicalTarget::parse(hostname)?;
            if reparsed != plan.target
                || plan.resolution.hostname.as_deref() != Some(hostname.as_str())
            {
                return Err(AppError::InvalidRequest(
                    "external hostname is not the canonical frozen target".into(),
                ));
            }
        }
        CanonicalTarget::Address(expected) => {
            if plan.resolution.hostname.is_some()
                || plan.resolution.addresses.len() != 1
                || !plan.resolution.addresses.contains(expected)
            {
                return Err(AppError::InvalidRequest(
                    "address target does not match its frozen resolution".into(),
                ));
            }
        }
        CanonicalTarget::Network(network) => {
            if plan.resolution.hostname.is_some()
                || plan
                    .resolution
                    .addresses
                    .iter()
                    .any(|address| !network.contains(address))
            {
                return Err(AppError::InvalidRequest(
                    "network target contains an out-of-scope frozen address".into(),
                ));
            }
        }
    }

    for address in &plan.resolution.addresses {
        if is_cloud_metadata(*address) {
            return Err(AppError::NotAuthorized(format!(
                "cloud metadata address {address} is never an egress destination"
            )));
        }
        if is_sensitive_address(*address) && !plan.allow_sensitive_networks {
            return Err(AppError::NotAuthorized(format!(
                "sensitive address {address} lacks an explicit internal-network grant"
            )));
        }
    }
    Ok(())
}

fn validate_plan_rate_policy(plan: &ResolvedExternalPlan) -> AppResult<()> {
    let (max_rate, max_concurrency, max_timeout) = match plan.activity {
        ExternalActivity::PassivePublicDiscovery => (100, 20, 3_600),
        ExternalActivity::LowImpactExternal => (25, 10, 1_800),
        ExternalActivity::ActiveExternal => (10, 5, 3_600),
    };
    let rate = plan.rate_policy.requests_per_second;
    let concurrency = plan.rate_policy.concurrency;
    let timeout = plan.rate_policy.timeout_seconds;
    if rate == 0
        || rate > max_rate
        || concurrency == 0
        || concurrency > max_concurrency
        || timeout == 0
        || timeout > max_timeout
    {
        return Err(AppError::InvalidRequest(
            "external plan rate, concurrency, or timeout exceeds its activity class".into(),
        ));
    }
    Ok(())
}

fn ensure_gateway_container_image(
    runtime: &dyn RuntimeCommands,
    provider: RuntimeProvider,
    spec: &GatewayContainerSpec,
) -> AppResult<()> {
    spec.validate()?;
    let output = runtime_output_with_timeout(
        runtime,
        provider,
        &["pull".into(), spec.reference().into()],
        GATEWAY_IMAGE_PULL_TIMEOUT,
    )?;
    if output.success {
        Ok(())
    } else {
        Err(runtime_failure("pinned egress gateway image pull", &output))
    }
}

fn create_uplink_network(
    runtime: &dyn RuntimeCommands,
    provider: RuntimeProvider,
    network_name: &str,
    labels: &BTreeMap<String, String>,
    policy_id: &str,
    prohibited: &[IpNet],
) -> AppResult<InspectedNetwork> {
    create_network_with_candidates(
        runtime,
        provider,
        network_name,
        labels,
        policy_id,
        UPLINK_RESOURCE_ROLE,
        false,
        true,
        prohibited,
    )
}

#[allow(clippy::too_many_arguments)]
fn create_network_with_candidates(
    runtime: &dyn RuntimeCommands,
    provider: RuntimeProvider,
    network_name: &str,
    labels: &BTreeMap<String, String>,
    policy_id: &str,
    role: &str,
    internal: bool,
    dual_stack: bool,
    prohibited: &[IpNet],
) -> AppResult<InspectedNetwork> {
    let candidates = candidate_private_networks(policy_id, role, prohibited, dual_stack)?;
    for candidate in candidates {
        let mut args = vec![
            "network".into(),
            "create".into(),
            "--driver".into(),
            "bridge".into(),
        ];
        if internal {
            args.push("--internal".into());
        }
        args.extend([
            "--subnet".into(),
            candidate.ipv4_subnet.to_string().into(),
            "--gateway".into(),
            candidate.ipv4_gateway.to_string().into(),
        ]);
        if let (Some(subnet), Some(gateway)) = (candidate.ipv6_subnet, candidate.ipv6_gateway) {
            args.extend([
                "--ipv6".into(),
                "--subnet".into(),
                subnet.to_string().into(),
                "--gateway".into(),
                gateway.to_string().into(),
            ]);
        }
        for (key, value) in labels {
            args.push("--label".into());
            args.push(format!("{key}={value}").into());
        }
        args.push(network_name.into());
        let output = runtime_output(runtime, provider, &args)?;
        let inspected = if internal {
            inspect_optional_network(runtime, provider, network_name, labels)?
        } else {
            inspect_optional_uplink_network(runtime, provider, network_name, labels)?
        };
        if let Some(inspected) = inspected {
            validate_network_candidate(&inspected, candidate)?;
            return Ok(inspected);
        }
        if output.success {
            return Err(AppError::Runtime(
                "container runtime reported network creation without a verifiable network".into(),
            ));
        }
        if !runtime_reports_subnet_conflict(&output.stderr) {
            return Err(runtime_failure("managed private network creation", &output));
        }
    }
    Err(AppError::NotAvailable(
        "container runtime could not reserve a collision-free private subnet after bounded retries"
            .into(),
    ))
}

fn validate_network_candidate(
    inspected: &InspectedNetwork,
    candidate: NetworkCandidate,
) -> AppResult<()> {
    if inspected.subnet != candidate.ipv4_subnet
        || inspected.gateway != candidate.ipv4_gateway
        || inspected.ipv6_subnet != candidate.ipv6_subnet
        || inspected.ipv6_gateway != candidate.ipv6_gateway
    {
        return Err(AppError::NotAuthorized(
            "container runtime changed the reserved private subnet".into(),
        ));
    }
    Ok(())
}

fn inspect_optional_uplink_network(
    runtime: &dyn RuntimeCommands,
    provider: RuntimeProvider,
    network_name: &str,
    labels: &BTreeMap<String, String>,
) -> AppResult<Option<InspectedNetwork>> {
    inspect_optional_uplink_network_with_requirement(
        runtime,
        provider,
        network_name,
        labels,
        NetworkTopologyRequirement::UplinkDualStack,
    )
}

fn inspect_optional_uplink_network_for_cleanup(
    runtime: &dyn RuntimeCommands,
    provider: RuntimeProvider,
    network_name: &str,
    labels: &BTreeMap<String, String>,
) -> AppResult<Option<InspectedNetwork>> {
    inspect_optional_uplink_network_with_requirement(
        runtime,
        provider,
        network_name,
        labels,
        NetworkTopologyRequirement::UplinkLegacyCompatible,
    )
}

fn inspect_optional_uplink_network_with_requirement(
    runtime: &dyn RuntimeCommands,
    provider: RuntimeProvider,
    network_name: &str,
    labels: &BTreeMap<String, String>,
    requirement: NetworkTopologyRequirement,
) -> AppResult<Option<InspectedNetwork>> {
    let output = runtime_output(
        runtime,
        provider,
        &["network".into(), "inspect".into(), network_name.into()],
    )?;
    if !output.success {
        if runtime_reports_network_absent(&output.stderr, network_name) {
            return Ok(None);
        }
        return Err(runtime_failure("gateway uplink inspection", &output));
    }
    parse_network_inspect_with_mode(provider, &output.stdout, network_name, labels, requirement)
        .map(Some)
}

fn select_gateway_container_ip(subnet: IpNet, gateway: IpAddr) -> AppResult<IpAddr> {
    match (subnet, gateway) {
        (IpNet::V4(network), IpAddr::V4(gateway)) => network
            .hosts()
            .find(|address| *address != gateway)
            .map(IpAddr::V4),
        (IpNet::V6(network), IpAddr::V6(gateway)) => network
            .hosts()
            .find(|address| *address != gateway)
            .map(IpAddr::V6),
        _ => None,
    }
    .ok_or_else(|| {
        AppError::Runtime("internal scanner bridge has no address for its gateway container".into())
    })
}

fn reject_destination_overlap(
    policy: &EgressGatewayPolicy,
    uplink: &InspectedNetwork,
) -> AppResult<()> {
    if policy
        .destinations
        .iter()
        .flat_map(|destination| destination.addresses.iter())
        .any(|address| {
            uplink.subnet.contains(address)
                || uplink
                    .ipv6_subnet
                    .is_some_and(|subnet| subnet.contains(address))
        })
    {
        return Err(AppError::NotAvailable(
            "gateway uplink overlaps an approved destination; retry with a new isolated network"
                .into(),
        ));
    }
    Ok(())
}

fn gateway_container_user(provider: RuntimeProvider) -> AppResult<(String, Option<String>)> {
    #[cfg(unix)]
    let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };
    #[cfg(not(unix))]
    let (uid, gid) = (65_532_u32, 65_532_u32);
    gateway_container_user_for_ids(provider, uid, gid)
}

fn gateway_container_user_for_ids(
    provider: RuntimeProvider,
    uid: u32,
    gid: u32,
) -> AppResult<(String, Option<String>)> {
    if uid == 0 {
        return Err(AppError::NotAuthorized(
            "managed gateway container cannot run from a root-owned desktop process".into(),
        ));
    }
    let user = format!("{uid}:{gid}");
    let userns = matches!(
        provider,
        RuntimeProvider::ManagedLocal | RuntimeProvider::Podman
    )
    .then(|| format!("keep-id:uid={uid},gid={gid}"));
    Ok((user, userns))
}

fn gateway_bind_mount(source: &Path, destination: &str, read_only: bool) -> AppResult<String> {
    let source = source
        .to_str()
        .ok_or_else(|| AppError::Runtime("gateway bind mount path is not valid UTF-8".into()))?;
    if source.contains([',', '\n', '\r', '\0'])
        || !destination.starts_with('/')
        || destination.contains([',', '\n', '\r', '\0'])
    {
        return Err(AppError::NotAuthorized(
            "gateway bind mount cannot be represented by the runtime grammar".into(),
        ));
    }
    let suffix = if read_only { ",readonly" } else { "" };
    Ok(format!("type=bind,src={source},dst={destination}{suffix}"))
}

fn create_gateway_probe(
    runtime: &dyn RuntimeCommands,
    provider: RuntimeProvider,
    probe: &mut GatewayProbeRuntimeIdentity,
) -> AppResult<()> {
    probe.image.validate()?;
    validate_policy_id(&probe.policy_id)?;
    let unique = probe.policy_id.strip_prefix("egress-").ok_or_else(|| {
        AppError::InvalidRequest("gateway probe policy identity is malformed".into())
    })?;
    if probe.name != format!("ass-probe-{unique}") || probe.gateway.port() != GATEWAY_PORT {
        return Err(AppError::NotAuthorized(
            "gateway probe identity does not match its policy".into(),
        ));
    }
    let (user, userns) = gateway_container_user(provider)?;
    let labels = expected_gateway_probe_labels(&probe.policy_id);
    let mut args = vec![
        "container".into(),
        "create".into(),
        "--name".into(),
        probe.name.clone().into(),
        "--pull=never".into(),
        "--read-only".into(),
        "--cap-drop=ALL".into(),
        "--security-opt=no-new-privileges:true".into(),
        format!("--user={user}").into(),
        "--pids-limit".into(),
        "16".into(),
        "--memory".into(),
        "32m".into(),
        "--cpus".into(),
        "0.250".into(),
        "--restart=no".into(),
        "--log-driver=none".into(),
        "--network".into(),
        probe.internal_network_name.clone().into(),
    ];
    if let Some(userns) = userns {
        args.push(format!("--userns={userns}").into());
    }
    for (key, value) in labels {
        args.push("--label".into());
        args.push(format!("{key}={value}").into());
    }
    args.extend([
        "--entrypoint".into(),
        CONTAINER_PROBE_BINARY.into(),
        probe.image.reference().into(),
        "--gateway".into(),
        probe.gateway.to_string().into(),
    ]);
    let output = runtime_output(runtime, provider, &args)?;
    if !output.success {
        return Err(runtime_failure(
            "managed gateway reachability probe creation",
            &output,
        ));
    }
    probe.id = Some(parse_created_container_id(&output.stdout)?);
    inspect_optional_gateway_probe(runtime, provider, probe)?.ok_or_else(|| {
        AppError::Runtime("managed gateway reachability probe disappeared after creation".into())
    })?;
    Ok(())
}

fn run_gateway_probe(
    runtime: &dyn RuntimeCommands,
    provider: RuntimeProvider,
    probe: &GatewayProbeRuntimeIdentity,
) -> AppResult<GatewayProbeDocument> {
    let id = probe.id.as_deref().ok_or_else(|| {
        AppError::Internal("managed gateway reachability probe has no runtime ID".into())
    })?;
    validate_gateway_container_id(id)?;
    let output = runtime_output_with_timeout(
        runtime,
        provider,
        &[
            "container".into(),
            "start".into(),
            "--attach".into(),
            id.into(),
        ],
        GATEWAY_PROBE_TIMEOUT,
    )?;
    if !output.success {
        return Err(runtime_failure(
            "managed gateway reachability probe",
            &output,
        ));
    }
    if output.stdout.is_empty() || output.stdout.len() > MAX_GATEWAY_STATUS_BYTES {
        return Err(AppError::Runtime(
            "managed gateway reachability probe output was empty or oversized".into(),
        ));
    }
    let document: GatewayProbeDocument = serde_json::from_slice(&output.stdout).map_err(|_| {
        AppError::Runtime("managed gateway reachability probe output was malformed".into())
    })?;
    if document.schema_version != "1.0.0"
        || document.reachability_probe != "socks5_no_connect_greeting"
        || !document.gateway_reachable
        || document.upstream_connect_attempted
    {
        return Err(AppError::NotAuthorized(
            "managed gateway reachability probe did not prove a no-CONNECT greeting".into(),
        ));
    }
    let inspected = inspect_optional_gateway_probe(runtime, provider, probe)?.ok_or_else(|| {
        AppError::Runtime("managed gateway reachability probe disappeared before cleanup".into())
    })?;
    if inspected.running || inspected.exit_code != Some(0) {
        return Err(AppError::Runtime(
            "managed gateway reachability probe did not exit successfully".into(),
        ));
    }
    Ok(document)
}

fn inspect_optional_gateway_probe(
    runtime: &dyn RuntimeCommands,
    provider: RuntimeProvider,
    probe: &GatewayProbeRuntimeIdentity,
) -> AppResult<Option<InspectedGatewayContainer>> {
    validate_policy_id(&probe.policy_id)?;
    let selector = probe.id.as_deref().unwrap_or(&probe.name);
    let output = runtime_output(
        runtime,
        provider,
        &["container".into(), "inspect".into(), selector.into()],
    )?;
    if !output.success {
        if runtime_reports_container_absent(&output.stderr) {
            return Ok(None);
        }
        return Err(runtime_failure(
            "gateway reachability probe inspection",
            &output,
        ));
    }
    let mut entries: Vec<GatewayContainerInspect> = serde_json::from_slice(&output.stdout)
        .map_err(|_| {
            AppError::Runtime("gateway reachability probe inspection was malformed".into())
        })?;
    if entries.len() != 1 {
        return Err(AppError::NotAuthorized(
            "runtime did not return exactly one gateway reachability probe".into(),
        ));
    }
    let entry = entries.pop().expect("one gateway probe inspect entry");
    validate_gateway_container_id(&entry.id)?;
    if probe.id.as_deref().is_some_and(|id| id != entry.id) {
        return Err(AppError::NotAuthorized(
            "refusing a replaced gateway reachability probe".into(),
        ));
    }
    if entry.name.strip_prefix('/').unwrap_or(&entry.name) != probe.name {
        return Err(AppError::NotAuthorized(
            "gateway reachability probe name changed during inspection".into(),
        ));
    }
    let expected_image = probe.image.reference();
    if entry
        .image_name
        .as_deref()
        .or(entry.config.image.as_deref())
        != Some(expected_image.as_str())
    {
        return Err(AppError::NotAuthorized(
            "gateway reachability probe did not retain its pinned image".into(),
        ));
    }
    let expected_labels = expected_gateway_probe_labels(&probe.policy_id);
    if expected_labels
        .iter()
        .any(|(key, value)| entry.config.labels.get(key) != Some(value))
        || entry.network_settings.networks.len() != 1
        || !entry
            .network_settings
            .networks
            .contains_key(&probe.internal_network_name)
    {
        return Err(AppError::NotAuthorized(
            "gateway reachability probe is not isolated on the exact scanner bridge".into(),
        ));
    }
    Ok(Some(InspectedGatewayContainer {
        id: entry.id,
        running: entry.state.running,
        exit_code: entry.state.exit_code,
    }))
}

fn remove_gateway_probe(
    runtime: &dyn RuntimeCommands,
    provider: RuntimeProvider,
    probe: &GatewayProbeRuntimeIdentity,
) -> AppResult<()> {
    let Some(inspected) = inspect_optional_gateway_probe(runtime, provider, probe)? else {
        return Ok(());
    };
    let output = runtime_output(
        runtime,
        provider,
        &[
            "container".into(),
            "rm".into(),
            "--force".into(),
            inspected.id.clone().into(),
        ],
    )?;
    if !output.success && !runtime_reports_container_absent(&output.stderr) {
        return Err(runtime_failure(
            "gateway reachability probe removal",
            &output,
        ));
    }
    let mut exact = probe.clone();
    exact.id = Some(inspected.id);
    if inspect_optional_gateway_probe(runtime, provider, &exact)?.is_some() {
        return Err(AppError::Runtime(
            "gateway reachability probe remained after exact removal".into(),
        ));
    }
    Ok(())
}

fn create_gateway_container(
    runtime: &dyn RuntimeCommands,
    provider: RuntimeProvider,
    container: &mut GatewayContainerRuntimeIdentity,
    policy_path: &Path,
    status_directory: &GatewayStatusDirectory,
    policy_id: &str,
) -> AppResult<InspectedGatewayContainer> {
    container.image.validate()?;
    validate_policy_id(policy_id)?;
    if container.policy_id != policy_id {
        return Err(AppError::NotAuthorized(
            "gateway container policy identity changed before creation".into(),
        ));
    }
    let (user, userns) = gateway_container_user(provider)?;
    let labels = expected_gateway_container_labels(policy_id);
    let mut args = vec![
        "container".into(),
        "create".into(),
        "--name".into(),
        container.name.clone().into(),
        "--pull=never".into(),
        "--read-only".into(),
        "--cap-drop=ALL".into(),
        "--security-opt=no-new-privileges:true".into(),
        format!("--user={user}").into(),
        "--pids-limit".into(),
        GATEWAY_CONTAINER_PIDS.to_string().into(),
        "--memory".into(),
        format!("{GATEWAY_CONTAINER_USER_MEMORY_MB}m").into(),
        "--cpus".into(),
        "0.500".into(),
        "--restart=no".into(),
        "--log-driver=none".into(),
        "--tmpfs".into(),
        "/tmp:rw,noexec,nosuid,nodev,mode=1777,size=8m".into(),
        "--network".into(),
        container.uplink_network_name.clone().into(),
    ];
    if let Some(userns) = userns {
        args.push(format!("--userns={userns}").into());
    }
    for (key, value) in labels {
        args.push("--label".into());
        args.push(format!("{key}={value}").into());
    }
    args.extend([
        "--mount".into(),
        gateway_bind_mount(policy_path, CONTAINER_POLICY_PATH, true)?.into(),
        "--mount".into(),
        gateway_bind_mount(
            &status_directory.path,
            "/run/ai-security-scanner/status",
            false,
        )?
        .into(),
        container.image.reference().into(),
        "--policy".into(),
        CONTAINER_POLICY_PATH.into(),
        "--status-file".into(),
        "/run/ai-security-scanner/status/status.json".into(),
    ]);
    let output = runtime_output(runtime, provider, &args)?;
    if !output.success {
        return Err(runtime_failure(
            "egress gateway container creation",
            &output,
        ));
    }
    container.id = Some(parse_created_container_id(&output.stdout)?);
    inspect_required_gateway_container_with_mode(
        runtime,
        provider,
        container,
        policy_id,
        InternalAttachmentMode::Absent,
    )?;

    let connect = runtime_output(
        runtime,
        provider,
        &[
            "network".into(),
            "connect".into(),
            "--ip".into(),
            container.listener_ip.to_string().into(),
            container.internal_network_name.clone().into(),
            container.name.clone().into(),
        ],
    )?;
    if !connect.success {
        return Err(runtime_failure(
            "egress gateway internal-network attachment",
            &connect,
        ));
    }
    inspect_required_gateway_container_with_mode(
        runtime,
        provider,
        container,
        policy_id,
        InternalAttachmentMode::PresentAllowUnassigned,
    )
}

fn start_gateway_container(
    runtime: &dyn RuntimeCommands,
    provider: RuntimeProvider,
    container_id: &str,
) -> AppResult<()> {
    validate_runtime_id(container_id)?;
    let output = runtime_output(
        runtime,
        provider,
        &["container".into(), "start".into(), container_id.into()],
    )?;
    if output.success {
        Ok(())
    } else {
        Err(runtime_failure("egress gateway container start", &output))
    }
}

fn remove_gateway_container(
    runtime: &dyn RuntimeCommands,
    provider: RuntimeProvider,
    container: &GatewayContainerRuntimeIdentity,
    policy_id: &str,
) -> AppResult<()> {
    let Some(inspected) =
        inspect_optional_gateway_container(runtime, provider, container, policy_id)?
    else {
        return Ok(());
    };
    let output = runtime_output(
        runtime,
        provider,
        &[
            "container".into(),
            "rm".into(),
            "--force".into(),
            inspected.id.clone().into(),
        ],
    )?;
    if !output.success && !runtime_reports_container_absent(&output.stderr) {
        return Err(runtime_failure("egress gateway container removal", &output));
    }
    let mut exact = container.clone();
    exact.id = Some(inspected.id);
    if inspect_optional_gateway_container(runtime, provider, &exact, policy_id)?.is_some() {
        return Err(AppError::Runtime(
            "egress gateway container remained after exact removal".into(),
        ));
    }
    Ok(())
}

fn stop_gateway_container_for_product_uninstall(
    runtime: &dyn RuntimeCommands,
    provider: RuntimeProvider,
    container: &GatewayContainerRuntimeIdentity,
    policy_id: &str,
) -> AppResult<()> {
    let Some(inspected) =
        inspect_optional_gateway_container(runtime, provider, container, policy_id)?
    else {
        // Provider alone does not identify a Docker context or Podman
        // connection. Absence from today's context cannot prove that the exact
        // gateway recorded in an earlier context has stopped.
        return Err(AppError::NotAvailable(
            "exact compatibility gateway is absent from the current provider context; target contact cannot be proven stopped"
                .into(),
        ));
    };
    if !inspected.running {
        return Ok(());
    }
    let output = runtime_output(
        runtime,
        provider,
        &[
            "container".into(),
            "stop".into(),
            "--time".into(),
            "10".into(),
            inspected.id.clone().into(),
        ],
    )?;
    if !output.success && !runtime_reports_container_absent(&output.stderr) {
        return Err(runtime_failure("egress gateway container stop", &output));
    }
    let mut exact = container.clone();
    exact.id = Some(inspected.id);
    if inspect_optional_gateway_container(runtime, provider, &exact, policy_id)?
        .is_some_and(|remaining| remaining.running)
    {
        return Err(AppError::Runtime(
            "egress gateway container remained running after exact stop".into(),
        ));
    }
    Ok(())
}

fn gateway_container_identity_from_record(
    record: &ManagedNetworkRecord,
) -> AppResult<Option<GatewayContainerRuntimeIdentity>> {
    let Some(listener_ip) = record.gateway_listener_ip else {
        return Ok(None);
    };
    validate_gateway_static_identity(
        &record.policy_id,
        record.uplink_network_name.as_deref(),
        record.gateway_container_name.as_deref(),
        record.gateway_image_repository.as_deref(),
        record.gateway_image_digest.as_deref(),
    )?;
    if let Some(id) = record.gateway_container_id.as_deref() {
        validate_gateway_container_id(id)?;
    }
    Ok(Some(GatewayContainerRuntimeIdentity {
        name: record
            .gateway_container_name
            .clone()
            .expect("validated gateway name"),
        id: record.gateway_container_id.clone(),
        policy_id: record.policy_id.clone(),
        listener_ip,
        image: GatewayContainerSpec::new(
            record
                .gateway_image_repository
                .clone()
                .expect("validated gateway repository"),
            record
                .gateway_image_digest
                .clone()
                .expect("validated gateway digest"),
        )?,
        internal_network_name: record.network_name.clone(),
        uplink_network_name: record
            .uplink_network_name
            .clone()
            .expect("validated gateway uplink"),
        uplink_subnets: None,
    }))
}

fn gateway_container_identity_from_durable(
    identity: &ManagedNetworkIdentity,
) -> AppResult<Option<GatewayContainerRuntimeIdentity>> {
    identity.validate()?;
    let Some(listener_ip) = identity.gateway_listener_ip else {
        return Ok(None);
    };
    let container_id = identity
        .gateway_container_id
        .clone()
        .expect("validated complete gateway identity");
    validate_gateway_container_id(&container_id)?;
    Ok(Some(GatewayContainerRuntimeIdentity {
        name: identity
            .gateway_container_name
            .clone()
            .expect("validated gateway name"),
        id: Some(container_id),
        policy_id: identity.policy_id.clone(),
        listener_ip,
        image: GatewayContainerSpec::new(
            identity
                .gateway_image_repository
                .clone()
                .expect("validated gateway repository"),
            identity
                .gateway_image_digest
                .clone()
                .expect("validated gateway digest"),
        )?,
        internal_network_name: identity.network_name.clone(),
        uplink_network_name: identity
            .uplink_network_name
            .clone()
            .expect("validated gateway uplink"),
        uplink_subnets: None,
    }))
}

fn gateway_probe_identity_from_record(
    record: &ManagedNetworkRecord,
) -> AppResult<Option<GatewayProbeRuntimeIdentity>> {
    let Some(listener_ip) = record.gateway_listener_ip else {
        return Ok(None);
    };
    validate_gateway_static_identity(
        &record.policy_id,
        record.uplink_network_name.as_deref(),
        record.gateway_container_name.as_deref(),
        record.gateway_image_repository.as_deref(),
        record.gateway_image_digest.as_deref(),
    )?;
    let unique = record
        .policy_id
        .strip_prefix("egress-")
        .expect("validated policy prefix");
    Ok(Some(GatewayProbeRuntimeIdentity {
        name: format!("ass-probe-{unique}"),
        id: None,
        policy_id: record.policy_id.clone(),
        image: GatewayContainerSpec::new(
            record
                .gateway_image_repository
                .clone()
                .expect("validated gateway repository"),
            record
                .gateway_image_digest
                .clone()
                .expect("validated gateway digest"),
        )?,
        internal_network_name: record.network_name.clone(),
        gateway: SocketAddr::new(listener_ip, GATEWAY_PORT),
    }))
}

fn gateway_probe_identity_from_durable(
    identity: &ManagedNetworkIdentity,
) -> AppResult<Option<GatewayProbeRuntimeIdentity>> {
    identity.validate()?;
    let Some(listener_ip) = identity.gateway_listener_ip else {
        return Ok(None);
    };
    let unique = identity
        .policy_id
        .strip_prefix("egress-")
        .expect("validated policy prefix");
    Ok(Some(GatewayProbeRuntimeIdentity {
        name: format!("ass-probe-{unique}"),
        id: None,
        policy_id: identity.policy_id.clone(),
        image: GatewayContainerSpec::new(
            identity
                .gateway_image_repository
                .clone()
                .expect("validated gateway repository"),
            identity
                .gateway_image_digest
                .clone()
                .expect("validated gateway digest"),
        )?,
        internal_network_name: identity.network_name.clone(),
        gateway: SocketAddr::new(listener_ip, GATEWAY_PORT),
    }))
}

fn create_internal_network(
    runtime: &dyn RuntimeCommands,
    provider: RuntimeProvider,
    network_name: &str,
    labels: &BTreeMap<String, String>,
    policy_id: &str,
    prohibited: &[IpNet],
) -> AppResult<InspectedNetwork> {
    create_network_with_candidates(
        runtime,
        provider,
        network_name,
        labels,
        policy_id,
        "scanner-internal",
        true,
        false,
        prohibited,
    )
}

fn remove_network(
    runtime: &dyn RuntimeCommands,
    provider: RuntimeProvider,
    network_name: &str,
) -> AppResult<()> {
    let output = runtime_output(
        runtime,
        provider,
        &["network".into(), "rm".into(), network_name.into()],
    )?;
    if output.success || runtime_reports_network_absent(&output.stderr, network_name) {
        Ok(())
    } else {
        Err(runtime_failure("managed network removal", &output))
    }
}

fn runtime_output(
    runtime: &dyn RuntimeCommands,
    provider: RuntimeProvider,
    args: &[OsString],
) -> AppResult<RuntimeOutput> {
    let output = runtime.output(provider, args).map_err(|error| {
        AppError::Runtime(format!(
            "{} could not be executed directly: {error}",
            runtime_program(provider).to_string_lossy()
        ))
    })?;
    if output.stdout.len() > MAX_INSPECT_BYTES || output.stderr.len() > MAX_INSPECT_BYTES {
        return Err(AppError::Runtime(
            "container runtime returned an oversized response".into(),
        ));
    }
    Ok(output)
}

fn runtime_output_with_timeout(
    runtime: &dyn RuntimeCommands,
    provider: RuntimeProvider,
    args: &[OsString],
    timeout: Duration,
) -> AppResult<RuntimeOutput> {
    let output = runtime
        .output_with_timeout(provider, args, timeout)
        .map_err(|error| {
            AppError::Runtime(format!(
                "{} could not be executed directly: {error}",
                runtime_program(provider).to_string_lossy()
            ))
        })?;
    if output.stdout.len() > MAX_INSPECT_BYTES || output.stderr.len() > MAX_INSPECT_BYTES {
        return Err(AppError::Runtime(
            "container runtime returned an oversized response".into(),
        ));
    }
    Ok(output)
}

fn runtime_program(provider: RuntimeProvider) -> &'static OsStr {
    match provider {
        RuntimeProvider::ManagedLocal => OsStr::new("managed-local-context-required"),
        RuntimeProvider::Docker => OsStr::new("docker"),
        RuntimeProvider::Podman => OsStr::new("podman"),
    }
}

fn require_compatibility_provider(provider: RuntimeProvider) -> AppResult<()> {
    if provider == RuntimeProvider::ManagedLocal {
        return Err(AppError::NotAuthorized(
            "managed-local networking requires its verified private runtime context".into(),
        ));
    }
    Ok(())
}

fn expected_labels(policy_id: &str) -> BTreeMap<String, String> {
    BTreeMap::from([
        (MANAGED_LABEL_KEY.into(), "true".into()),
        (POLICY_LABEL_KEY.into(), policy_id.into()),
    ])
}

fn expected_uplink_labels(policy_id: &str) -> BTreeMap<String, String> {
    let mut labels = expected_labels(policy_id);
    labels.insert(RESOURCE_ROLE_LABEL_KEY.into(), UPLINK_RESOURCE_ROLE.into());
    labels
}

fn expected_gateway_container_labels(policy_id: &str) -> BTreeMap<String, String> {
    let mut labels = expected_labels(policy_id);
    labels.insert(
        RESOURCE_ROLE_LABEL_KEY.into(),
        GATEWAY_CONTAINER_RESOURCE_ROLE.into(),
    );
    labels
}

fn expected_gateway_probe_labels(policy_id: &str) -> BTreeMap<String, String> {
    let mut labels = expected_labels(policy_id);
    labels.insert(
        RESOURCE_ROLE_LABEL_KEY.into(),
        GATEWAY_PROBE_RESOURCE_ROLE.into(),
    );
    labels
}

#[derive(Debug, Deserialize)]
struct DockerNetworkInspect {
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
    #[serde(rename = "IPAM")]
    ipam: DockerIpam,
}

#[derive(Debug, Deserialize)]
struct DockerIpam {
    #[serde(rename = "Config")]
    config: Vec<DockerSubnet>,
}

#[derive(Debug, Deserialize)]
struct DockerSubnet {
    #[serde(rename = "Subnet")]
    subnet: String,
    #[serde(rename = "Gateway")]
    gateway: String,
}

#[derive(Debug, Deserialize)]
struct PodmanNetworkInspect {
    name: String,
    id: String,
    driver: String,
    internal: bool,
    labels: BTreeMap<String, String>,
    subnets: Vec<PodmanSubnet>,
}

#[derive(Debug, Deserialize)]
struct PodmanSubnet {
    subnet: String,
    gateway: String,
}

#[derive(Debug, Deserialize)]
struct GatewayContainerInspect {
    #[serde(rename = "Id", alias = "ID")]
    id: String,
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "ImageName", default)]
    image_name: Option<String>,
    #[serde(rename = "Config")]
    config: GatewayContainerConfig,
    #[serde(rename = "State")]
    state: GatewayContainerState,
    #[serde(rename = "NetworkSettings")]
    network_settings: GatewayContainerNetworkSettings,
}

#[derive(Debug, Deserialize)]
struct GatewayContainerConfig {
    #[serde(rename = "Image", default)]
    image: Option<String>,
    #[serde(rename = "Labels", default)]
    labels: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
struct GatewayContainerState {
    #[serde(rename = "Running", default)]
    running: bool,
    #[serde(rename = "ExitCode", default)]
    exit_code: Option<i32>,
}

#[derive(Debug, Deserialize)]
struct GatewayContainerNetworkSettings {
    #[serde(rename = "Networks", default)]
    networks: BTreeMap<String, GatewayContainerNetworkAttachment>,
}

#[derive(Debug, Deserialize)]
struct GatewayContainerNetworkAttachment {
    #[serde(rename = "IPAddress", default)]
    ipv4_address: String,
    #[serde(rename = "GlobalIPv6Address", default)]
    ipv6_address: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InternalAttachmentMode {
    Absent,
    PresentAllowUnassigned,
    PresentAssigned,
    Either,
}

fn parse_created_container_id(bytes: &[u8]) -> AppResult<String> {
    if bytes.is_empty() || bytes.len() > 256 {
        return Err(AppError::Runtime(
            "container runtime returned an empty or oversized gateway identity".into(),
        ));
    }
    let id = std::str::from_utf8(bytes)
        .map_err(|_| AppError::Runtime("gateway container identity was not UTF-8".into()))?
        .trim();
    validate_gateway_container_id(id)?;
    Ok(id.to_owned())
}

fn validate_gateway_container_id(value: &str) -> AppResult<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(AppError::NotAuthorized(
            "gateway container identity was not an immutable runtime digest".into(),
        ));
    }
    Ok(())
}

fn inspect_required_gateway_container(
    runtime: &dyn RuntimeCommands,
    provider: RuntimeProvider,
    container: &GatewayContainerRuntimeIdentity,
    policy_id: &str,
) -> AppResult<InspectedGatewayContainer> {
    inspect_required_gateway_container_with_mode(
        runtime,
        provider,
        container,
        policy_id,
        InternalAttachmentMode::PresentAssigned,
    )
}

fn inspect_required_gateway_container_with_mode(
    runtime: &dyn RuntimeCommands,
    provider: RuntimeProvider,
    container: &GatewayContainerRuntimeIdentity,
    policy_id: &str,
    internal_mode: InternalAttachmentMode,
) -> AppResult<InspectedGatewayContainer> {
    inspect_gateway_container_with_attachment_mode(
        runtime,
        provider,
        container,
        policy_id,
        internal_mode,
    )?
    .ok_or_else(|| AppError::Runtime("expected gateway container is absent".into()))
}

fn inspect_optional_gateway_container(
    runtime: &dyn RuntimeCommands,
    provider: RuntimeProvider,
    container: &GatewayContainerRuntimeIdentity,
    policy_id: &str,
) -> AppResult<Option<InspectedGatewayContainer>> {
    inspect_gateway_container_with_attachment_mode(
        runtime,
        provider,
        container,
        policy_id,
        InternalAttachmentMode::Either,
    )
}

fn inspect_gateway_container_with_attachment_mode(
    runtime: &dyn RuntimeCommands,
    provider: RuntimeProvider,
    container: &GatewayContainerRuntimeIdentity,
    policy_id: &str,
    internal_mode: InternalAttachmentMode,
) -> AppResult<Option<InspectedGatewayContainer>> {
    validate_policy_id(policy_id)?;
    if container.policy_id != policy_id {
        return Err(AppError::NotAuthorized(
            "gateway container policy identity changed during inspection".into(),
        ));
    }
    let selector = container.id.as_deref().unwrap_or(&container.name);
    let output = runtime_output(
        runtime,
        provider,
        &["container".into(), "inspect".into(), selector.into()],
    )?;
    if !output.success {
        if runtime_reports_container_absent(&output.stderr) {
            return Ok(None);
        }
        return Err(runtime_failure(
            "egress gateway container inspection",
            &output,
        ));
    }
    if output.stdout.is_empty() || output.stdout.len() > MAX_INSPECT_BYTES {
        return Err(AppError::Runtime(
            "gateway container inspection was empty or oversized".into(),
        ));
    }
    let mut entries: Vec<GatewayContainerInspect> = serde_json::from_slice(&output.stdout)
        .map_err(|_| AppError::Runtime("gateway container inspection was malformed".into()))?;
    if entries.len() != 1 {
        return Err(AppError::NotAuthorized(
            "runtime did not return exactly one gateway container".into(),
        ));
    }
    let entry = entries.pop().expect("one gateway inspect entry");
    validate_gateway_container_id(&entry.id)?;
    if container.id.as_deref().is_some_and(|id| id != entry.id) {
        return Err(AppError::NotAuthorized(
            "refusing a replaced gateway container runtime identity".into(),
        ));
    }
    let inspected_name = entry.name.strip_prefix('/').unwrap_or(&entry.name);
    if inspected_name != container.name {
        return Err(AppError::NotAuthorized(
            "gateway container name changed during inspection".into(),
        ));
    }
    let image = entry
        .image_name
        .as_deref()
        .or(entry.config.image.as_deref());
    if image != Some(container.image.reference().as_str()) {
        return Err(AppError::NotAuthorized(
            "gateway container did not retain its pinned image reference".into(),
        ));
    }
    let expected_labels = expected_gateway_container_labels(policy_id);
    if expected_labels
        .iter()
        .any(|(key, value)| entry.config.labels.get(key) != Some(value))
    {
        return Err(AppError::NotAuthorized(
            "gateway container labels do not match its durable policy identity".into(),
        ));
    }
    let networks = &entry.network_settings.networks;
    let has_uplink = networks.contains_key(&container.uplink_network_name);
    let has_internal = networks.contains_key(&container.internal_network_name);
    let expected_count = if has_internal { 2 } else { 1 };
    if !has_uplink
        || networks.len() != expected_count
        || match internal_mode {
            InternalAttachmentMode::Absent => has_internal,
            InternalAttachmentMode::PresentAllowUnassigned
            | InternalAttachmentMode::PresentAssigned => !has_internal,
            InternalAttachmentMode::Either => false,
        }
    {
        return Err(AppError::NotAuthorized(
            "gateway container is not attached to the exact dual-network topology".into(),
        ));
    }
    let uplink_attachment = networks
        .get(&container.uplink_network_name)
        .expect("validated uplink attachment");
    let require_assigned = internal_mode == InternalAttachmentMode::PresentAssigned;
    match container.uplink_subnets {
        Some((ipv4_subnet @ IpNet::V4(_), ipv6_subnet @ IpNet::V6(_))) => {
            validate_gateway_attachment_address(
                &uplink_attachment.ipv4_address,
                ipv4_subnet,
                require_assigned,
                "IPv4 uplink",
            )?;
            validate_gateway_attachment_address(
                &uplink_attachment.ipv6_address,
                ipv6_subnet,
                require_assigned,
                "IPv6 uplink",
            )?;
        }
        Some(_) => {
            return Err(AppError::Internal(
                "gateway uplink identity did not retain one IPv4 and one IPv6 subnet".into(),
            ));
        }
        None if require_assigned => {
            return Err(AppError::Internal(
                "running gateway container has no verified uplink subnet identity".into(),
            ));
        }
        None => {}
    }
    if has_internal {
        let attachment = networks
            .get(&container.internal_network_name)
            .expect("internal attachment present");
        let (raw_address, unexpected_address) = match container.listener_ip {
            IpAddr::V4(_) => (&attachment.ipv4_address, &attachment.ipv6_address),
            IpAddr::V6(_) => (&attachment.ipv6_address, &attachment.ipv4_address),
        };
        if !unexpected_address.is_empty() {
            return Err(AppError::NotAuthorized(
                "gateway container listener attachment changed address families".into(),
            ));
        }
        if !raw_address.is_empty() {
            let address = raw_address.parse::<IpAddr>().map_err(|_| {
                AppError::Runtime("gateway listener attachment was malformed".into())
            })?;
            if address != container.listener_ip {
                return Err(AppError::NotAuthorized(
                    "gateway container listener address changed during inspection".into(),
                ));
            }
        } else if internal_mode == InternalAttachmentMode::PresentAssigned {
            return Err(AppError::Runtime(
                "running gateway container has no assigned listener address".into(),
            ));
        }
    }
    Ok(Some(InspectedGatewayContainer {
        id: entry.id,
        running: entry.state.running,
        exit_code: entry.state.exit_code,
    }))
}

fn validate_gateway_attachment_address(
    raw_address: &str,
    subnet: IpNet,
    required: bool,
    description: &str,
) -> AppResult<()> {
    if raw_address.is_empty() {
        if required {
            return Err(AppError::Runtime(format!(
                "running gateway container has no assigned {description} address"
            )));
        }
        return Ok(());
    }
    let address = raw_address.parse::<IpAddr>().map_err(|_| {
        AppError::Runtime(format!(
            "gateway container {description} address was malformed"
        ))
    })?;
    let unusable = match (subnet, address) {
        (IpNet::V4(network), IpAddr::V4(address)) => {
            address == network.network() || address == network.broadcast()
        }
        (IpNet::V6(network), IpAddr::V6(address)) => address == network.network(),
        _ => true,
    };
    if unusable || !subnet.contains(&address) {
        return Err(AppError::NotAuthorized(format!(
            "gateway container {description} address escaped its verified subnet"
        )));
    }
    Ok(())
}

fn parse_network_inspect(
    provider: RuntimeProvider,
    bytes: &[u8],
    expected_name: &str,
    expected_labels: &BTreeMap<String, String>,
) -> AppResult<InspectedNetwork> {
    parse_network_inspect_with_mode(
        provider,
        bytes,
        expected_name,
        expected_labels,
        NetworkTopologyRequirement::InternalIpv4Only,
    )
}

fn parse_network_inspect_with_mode(
    provider: RuntimeProvider,
    bytes: &[u8],
    expected_name: &str,
    expected_labels: &BTreeMap<String, String>,
    requirement: NetworkTopologyRequirement,
) -> AppResult<InspectedNetwork> {
    if bytes.is_empty() || bytes.len() > MAX_INSPECT_BYTES {
        return Err(AppError::Runtime(
            "container network inspection was empty or oversized".into(),
        ));
    }
    let (name, id, driver, internal, labels, subnets) = match provider {
        RuntimeProvider::Docker => {
            let mut entries: Vec<DockerNetworkInspect> = serde_json::from_slice(bytes)
                .map_err(|_| AppError::Runtime("Docker network inspection was malformed".into()))?;
            if entries.len() != 1 {
                return Err(AppError::Runtime(
                    "Docker must return exactly one inspected network".into(),
                ));
            }
            let entry = entries.pop().expect("one entry");
            (
                entry.name,
                entry.id,
                entry.driver,
                entry.internal,
                entry.labels,
                entry
                    .ipam
                    .config
                    .into_iter()
                    .map(|item| (item.subnet, item.gateway))
                    .collect::<Vec<_>>(),
            )
        }
        RuntimeProvider::ManagedLocal | RuntimeProvider::Podman => {
            let mut entries: Vec<PodmanNetworkInspect> = serde_json::from_slice(bytes)
                .map_err(|_| AppError::Runtime("Podman network inspection was malformed".into()))?;
            if entries.len() != 1 {
                return Err(AppError::Runtime(
                    "Podman must return exactly one inspected network".into(),
                ));
            }
            let entry = entries.pop().expect("one entry");
            (
                entry.name,
                entry.id,
                entry.driver,
                entry.internal,
                entry.labels,
                entry
                    .subnets
                    .into_iter()
                    .map(|item| (item.subnet, item.gateway))
                    .collect::<Vec<_>>(),
            )
        }
    };

    if name != expected_name
        || id.trim().is_empty()
        || id.len() > 256
        || id.contains(['\n', '\r', '\0'])
        || driver != "bridge"
        || internal != requirement.expected_internal()
        || labels != *expected_labels
    {
        return Err(AppError::NotAuthorized(
            "container runtime did not prove the exact internal labeled bridge".into(),
        ));
    }
    let mut ipv4 = None;
    let mut ipv6 = None;
    for (subnet, gateway) in subnets {
        let subnet = subnet
            .parse::<IpNet>()
            .map_err(|_| AppError::Runtime("container bridge subnet is malformed".into()))?;
        let gateway = gateway
            .parse::<IpAddr>()
            .map_err(|_| AppError::Runtime("container bridge gateway is malformed".into()))?;
        validate_bridge_network(subnet, gateway)?;
        let slot = match subnet {
            IpNet::V4(_) => &mut ipv4,
            IpNet::V6(_) => &mut ipv6,
        };
        if slot.replace((subnet, gateway)).is_some() {
            return Err(AppError::NotAuthorized(
                "container bridge returned duplicate address families".into(),
            ));
        }
    }
    let Some((subnet, gateway)) = ipv4 else {
        return Err(AppError::NotAuthorized(
            "container bridge did not prove its exact IPv4 subnet".into(),
        ));
    };
    let address_families_match = match requirement {
        NetworkTopologyRequirement::InternalIpv4Only => ipv6.is_none(),
        NetworkTopologyRequirement::UplinkDualStack => ipv6.is_some(),
        NetworkTopologyRequirement::UplinkLegacyCompatible => true,
    };
    if !address_families_match {
        return Err(AppError::NotAuthorized(
            "container bridge did not prove its required address families".into(),
        ));
    }
    let (ipv6_subnet, ipv6_gateway) = ipv6
        .map(|(subnet, gateway)| (Some(subnet), Some(gateway)))
        .unwrap_or((None, None));
    Ok(InspectedNetwork {
        id,
        subnet,
        gateway,
        ipv6_subnet,
        ipv6_gateway,
    })
}

fn validate_bridge_network(subnet: IpNet, gateway: IpAddr) -> AppResult<()> {
    if subnet.trunc() != subnet || !subnet.contains(&gateway) || is_cloud_metadata(gateway) {
        return Err(AppError::NotAuthorized(
            "container bridge did not provide a canonical private gateway".into(),
        ));
    }
    let valid = match (subnet, gateway) {
        (IpNet::V4(network), IpAddr::V4(address)) => {
            (16..=30).contains(&network.prefix_len())
                && network.network().is_private()
                && address.is_private()
                && address != network.network()
                && address != network.broadcast()
        }
        (IpNet::V6(network), IpAddr::V6(address)) => {
            (48..=126).contains(&network.prefix_len())
                && is_unique_local_v6(network.network())
                && is_unique_local_v6(address)
                && address != network.network()
        }
        _ => false,
    };
    if !valid {
        return Err(AppError::NotAuthorized(
            "container bridge subnet and gateway must be private and bounded".into(),
        ));
    }
    Ok(())
}

fn validate_policy_id(policy_id: &str) -> AppResult<()> {
    if policy_id.is_empty()
        || policy_id.len() > 128
        || !policy_id.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.')
        })
    {
        return Err(AppError::InvalidRequest(
            "managed egress policy id is invalid".into(),
        ));
    }
    Ok(())
}

/// Proves an already-installed gateway path is a canonical, non-symlink,
/// executable regular file. This function is inspection-only: it never
/// creates, chmods, opens for writing, or executes the file.
pub(crate) fn inspect_gateway_binary(path: &Path) -> AppResult<PathBuf> {
    if !path.is_absolute() || path.as_os_str().len() > 4096 {
        return Err(AppError::InvalidRequest(
            "egress gateway binary must be a bounded absolute path".into(),
        ));
    }
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        AppError::Runtime(format!(
            "egress gateway binary could not be inspected: {error}"
        ))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() == 0 {
        return Err(AppError::NotAuthorized(
            "egress gateway must be a non-symlink regular file".into(),
        ));
    }
    let canonical = fs::canonicalize(path).map_err(|error| {
        AppError::Runtime(format!(
            "egress gateway binary could not be resolved: {error}"
        ))
    })?;
    if canonical != path {
        return Err(AppError::NotAuthorized(
            "egress gateway path may not traverse symlinks or aliases".into(),
        ));
    }
    validate_executable_mode(&metadata)?;
    Ok(canonical)
}

/// Resolves the packaged gateway from the canonical directory of the desktop
/// executable that is already running, then applies the strict gateway
/// inspection above. Windows `fs::canonicalize` commonly changes a normal
/// drive path such as `C:\...` into the equivalent `\\?\C:\...` form. If the
/// sibling path is built before that normalization, a correctly installed
/// gateway is rejected by the canonical-path equality check on every poll.
///
/// Canonicalizing the trusted desktop executable first keeps the companion's
/// no-symlink/alias guarantee while ensuring both sides of its comparison use
/// the same platform-native path form. This remains inspection-only.
#[cfg(test)]
pub(crate) fn inspect_installed_gateway_binary(desktop_executable: &Path) -> AppResult<PathBuf> {
    if !desktop_executable.is_absolute() || desktop_executable.as_os_str().len() > 4096 {
        return Err(AppError::Runtime(
            "desktop executable path is not a bounded absolute path".into(),
        ));
    }
    let canonical_desktop = fs::canonicalize(desktop_executable).map_err(|error| {
        AppError::Runtime(format!(
            "desktop executable path could not be resolved: {error}"
        ))
    })?;
    let parent = canonical_desktop.parent().ok_or_else(|| {
        AppError::Runtime("desktop executable has no containing directory".into())
    })?;
    let name = if cfg!(windows) {
        "ai-security-scanner-egress-gateway.exe"
    } else {
        "ai-security-scanner-egress-gateway"
    };
    inspect_gateway_binary(&parent.join(name))
}

fn validate_policy_directory(path: &Path) -> AppResult<PathBuf> {
    if !path.is_absolute() || path.as_os_str().len() > 4096 {
        return Err(AppError::InvalidRequest(
            "egress policy directory must be a bounded absolute path".into(),
        ));
    }
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        AppError::Runtime(format!(
            "egress policy directory could not be inspected: {error}"
        ))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(AppError::NotAuthorized(
            "egress policy directory must be a non-symlink directory".into(),
        ));
    }
    let canonical = fs::canonicalize(path).map_err(|error| {
        AppError::Runtime(format!(
            "egress policy directory could not be resolved: {error}"
        ))
    })?;
    if canonical != path {
        return Err(AppError::NotAuthorized(
            "egress policy directory may not traverse symlinks or aliases".into(),
        ));
    }
    Ok(canonical)
}

#[cfg(unix)]
fn validate_executable_mode(metadata: &fs::Metadata) -> AppResult<()> {
    use std::os::unix::fs::PermissionsExt;
    if metadata.permissions().mode() & 0o111 == 0 {
        return Err(AppError::NotAuthorized(
            "egress gateway regular file is not executable".into(),
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_executable_mode(_metadata: &fs::Metadata) -> AppResult<()> {
    Ok(())
}

fn write_policy_file(directory: &Path, policy: &EgressGatewayPolicy) -> AppResult<PolicyFile> {
    let bytes = serde_json::to_vec(policy).map_err(|error| {
        AppError::Internal(format!("egress policy serialization failed: {error}"))
    })?;
    if bytes.is_empty() || bytes.len() > MAX_POLICY_BYTES {
        return Err(AppError::InvalidRequest(
            "egress policy exceeds its bounded file size".into(),
        ));
    }
    let path = directory.join(format!("egress-{}.json", policy.policy_id));
    if !path.is_absolute() || path.parent() != Some(directory) {
        return Err(AppError::InvalidRequest(
            "egress policy path escaped its control directory".into(),
        ));
    }

    let write_result = (|| -> AppResult<()> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        configure_private_create(&mut options);
        let mut file = options.open(&path).map_err(|error| {
            AppError::Runtime(format!("egress policy could not be created: {error}"))
        })?;
        file.write_all(&bytes).map_err(|error| {
            AppError::Runtime(format!("egress policy could not be written: {error}"))
        })?;
        file.sync_all().map_err(|error| {
            AppError::Runtime(format!("egress policy could not be synchronized: {error}"))
        })?;
        restrict_policy_file(&path)?;
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.len() != bytes.len() as u64
        {
            return Err(AppError::NotAuthorized(
                "egress policy file identity changed while it was written".into(),
            ));
        }
        Ok(())
    })();
    if let Err(error) = write_result {
        let _ = remove_exact_regular_file(&path);
        return Err(error);
    }

    Ok(PolicyFile {
        path,
        sha256: Sha256::digest(&bytes).into(),
    })
}

#[cfg(unix)]
fn configure_private_create(options: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;
    options.mode(0o600);
    options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
}

#[cfg(not(unix))]
fn configure_private_create(_options: &mut OpenOptions) {}

#[cfg(unix)]
fn restrict_policy_file(path: &Path) -> AppResult<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o400)).map_err(|error| {
        AppError::Runtime(format!(
            "egress policy permissions could not be restricted: {error}"
        ))
    })
}

#[cfg(not(unix))]
fn restrict_policy_file(path: &Path) -> AppResult<()> {
    let mut permissions = fs::metadata(path)?.permissions();
    permissions.set_readonly(true);
    fs::set_permissions(path, permissions)?;
    Ok(())
}

fn remove_policy_file(policy_file: &PolicyFile) -> AppResult<()> {
    let metadata = match fs::symlink_metadata(&policy_file.path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(AppError::Runtime(format!(
                "egress policy cleanup inspection failed: {error}"
            )));
        }
    };
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() > MAX_POLICY_BYTES as u64
    {
        return Err(AppError::NotAuthorized(
            "refusing to remove a replaced egress policy path".into(),
        ));
    }
    let bytes = fs::read(&policy_file.path).map_err(|error| {
        AppError::Runtime(format!("egress policy cleanup read failed: {error}"))
    })?;
    let actual: [u8; 32] = Sha256::digest(&bytes).into();
    if actual != policy_file.sha256 {
        return Err(AppError::NotAuthorized(
            "refusing to remove a modified egress policy file".into(),
        ));
    }
    fs::remove_file(&policy_file.path)
        .map_err(|error| AppError::Runtime(format!("egress policy removal failed: {error}")))
}

fn remove_exact_regular_file(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
            fs::remove_file(path)
        }
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "path is not an exact regular file",
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn exact_path_is_absent(path: &Path) -> AppResult<bool> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(true),
        Ok(_) => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn stop_gateway(process: &mut dyn GatewayProcess) -> AppResult<()> {
    let exited = process.has_exited().map_err(|error| {
        AppError::Runtime(format!("egress gateway status could not be read: {error}"))
    })?;
    if !exited {
        process.kill().map_err(|error| {
            AppError::Runtime(format!("egress gateway could not be stopped: {error}"))
        })?;
    }
    process
        .wait()
        .map_err(|error| AppError::Runtime(format!("egress gateway could not be reaped: {error}")))
}

fn gateway_endpoint(gateway: IpAddr) -> String {
    match gateway {
        IpAddr::V4(address) => format!("socks5h://{address}:{GATEWAY_PORT}"),
        IpAddr::V6(address) => format!("socks5h://[{address}]:{GATEWAY_PORT}"),
    }
}

fn runtime_failure(operation: &str, output: &RuntimeOutput) -> AppError {
    let diagnostic = bounded_diagnostic(&output.stderr);
    if diagnostic.is_empty() {
        AppError::Runtime(format!("{operation} failed"))
    } else {
        AppError::Runtime(format!("{operation} failed: {diagnostic}"))
    }
}

fn bounded_diagnostic(bytes: &[u8]) -> String {
    let end = bytes.len().min(MAX_DIAGNOSTIC_BYTES);
    String::from_utf8_lossy(&bytes[..end])
        .replace(['\n', '\r', '\0'], " ")
        .trim()
        .to_owned()
}

fn runtime_reports_network_absent(stderr: &[u8], selector: &str) -> bool {
    let message = bounded_diagnostic(stderr).to_ascii_lowercase();
    // Docker Engine 29 reports a missing network as "network <selector> not found",
    // echoing the selector. The match includes the selector so a missing plugin,
    // sandbox, or other network does not count as absence of this network.
    message.contains("no such network")
        || message.contains("network not found")
        || message.contains("does not exist")
        || message.contains(&format!(
            "network {} not found",
            selector.to_ascii_lowercase()
        ))
}

fn runtime_reports_container_absent(stderr: &[u8]) -> bool {
    let message = bounded_diagnostic(stderr).to_ascii_lowercase();
    message.contains("no such container")
        || message.contains("no such object")
        || message.contains("container not found")
        || (message.contains("container") && message.contains("does not exist"))
}

fn runtime_reports_subnet_conflict(stderr: &[u8]) -> bool {
    let message = bounded_diagnostic(stderr).to_ascii_lowercase();
    message.contains("overlap")
        || message.contains("already allocated")
        || message.contains("address pool") && message.contains("used")
        || message.contains("subnet") && message.contains("conflict")
        || message.contains("subnet") && message.contains("already used")
}

fn is_unique_local_v6(address: Ipv6Addr) -> bool {
    address.segments()[0] & 0xfe00 == 0xfc00
}

fn is_cloud_metadata(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            address == Ipv4Addr::new(169, 254, 169, 254)
                || address == Ipv4Addr::new(169, 254, 170, 2)
                || address == Ipv4Addr::new(100, 100, 100, 200)
        }
        IpAddr::V6(address) => address == "fd00:ec2::254".parse::<Ipv6Addr>().expect("literal"),
    }
}

fn is_sensitive_address(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            address.is_private()
                || address.is_loopback()
                || address.is_link_local()
                || address.is_multicast()
                || address.is_unspecified()
                || address.is_broadcast()
                || address.octets()[0] == 0
                || (address.octets()[0] == 100 && (64..=127).contains(&address.octets()[1]))
                || (address.octets()[0] == 198 && (18..=19).contains(&address.octets()[1]))
                || address.octets()[0] >= 240
        }
        IpAddr::V6(address) => {
            address.is_loopback()
                || address.is_multicast()
                || address.is_unspecified()
                || is_unique_local_v6(address)
                || (address.segments()[0] & 0xffc0) == 0xfe80
                || address
                    .to_ipv4_mapped()
                    .is_some_and(|mapped| is_sensitive_address(IpAddr::V4(mapped)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::external_scope::{RatePolicy, ResolutionSnapshot, TemplatePolicy};
    use serde_json::json;
    use std::sync::Mutex;
    use tempfile::TempDir;

    fn plan(
        now: DateTime<Utc>,
        address: &str,
        rate: u16,
        concurrency: u16,
        timeout: u32,
    ) -> ResolvedExternalPlan {
        let address = address.parse::<IpAddr>().expect("address");
        ResolvedExternalPlan {
            grant_id: format!("grant-{address}"),
            case_id: "case-1".into(),
            asset_id: format!("asset-{address}"),
            target: CanonicalTarget::Hostname("app.example.test".into()),
            resolution: ResolutionSnapshot {
                hostname: Some("app.example.test".into()),
                addresses: [address].into_iter().collect(),
                resolved_at: now,
            },
            ports: [443].into_iter().collect(),
            protocol: TransportProtocol::Https,
            activity: ExternalActivity::ActiveExternal,
            rate_policy: RatePolicy {
                requests_per_second: rate,
                concurrency,
                timeout_seconds: timeout,
            },
            template_policy: TemplatePolicy::conservative(
                "nuclei-templates@0123456789abcdef0123456789abcdef01234567",
                vec!["http/misconfiguration/example".into()],
            ),
            frozen_at: now,
            expires_at: now + ChronoDuration::hours(5),
            allow_sensitive_networks: false,
        }
    }

    #[test]
    fn policy_uses_only_frozen_destinations_and_most_restrictive_limits() {
        let now = Utc::now();
        let mut first = plan(now, "203.0.113.8", 8, 4, 300);
        first.expires_at = now + ChronoDuration::hours(10);
        let second = plan(now, "203.0.113.9", 3, 2, 45);
        let policy = EgressGatewayPolicy::from_resolved_plans(
            "policy-1",
            "172.29.0.1:1080".parse().expect("listener"),
            "172.29.0.0/24".parse().expect("network"),
            &[first, second],
            now,
        )
        .expect("policy");

        assert_eq!(policy.expires_at, now + ChronoDuration::hours(5));
        assert_eq!(policy.limits.max_connections_per_second, 3);
        assert_eq!(policy.limits.max_concurrency, 2);
        assert_eq!(policy.limits.connect_timeout_seconds, 45);
        assert_eq!(policy.limits.max_connection_seconds, 45);
        assert_eq!(policy.destinations.len(), 2);
        let value = serde_json::to_value(&policy).expect("JSON");
        assert!(value.get("limits").is_some());
        assert!(value.get("max_concurrency").is_none());
    }

    #[test]
    fn active_profile_reaches_the_same_exact_destination_policy_as_legacy_template_ids() {
        let now = Utc::now();
        let mut profiled = plan(now, "203.0.113.8", 5, 2, 30);
        profiled.template_policy = TemplatePolicy::conservative_profile(
            "nuclei-templates@0123456789abcdef0123456789abcdef01234567",
            "nuclei_web_safe_v1",
        );

        let policy = EgressGatewayPolicy::from_resolved_plans(
            "policy-profile",
            "172.29.0.1:1080".parse().expect("listener"),
            "172.29.0.0/24".parse().expect("network"),
            &[profiled],
            now,
        )
        .expect("a bounded upstream profile must not be rejected as an empty allowlist");

        assert_eq!(policy.destinations.len(), 1);
        assert_eq!(
            policy.destinations[0].addresses,
            ["203.0.113.8".parse().unwrap()].into_iter().collect()
        );
        assert_eq!(policy.destinations[0].ports, [443].into_iter().collect());
    }

    #[test]
    fn policy_caps_lifetime_and_connect_timeout() {
        let now = Utc::now();
        let mut plan = plan(now, "203.0.113.8", 5, 2, 300);
        plan.expires_at = now + ChronoDuration::hours(25);
        let policy = EgressGatewayPolicy::from_resolved_plans(
            "policy-1",
            "172.29.0.1:1080".parse().expect("listener"),
            "172.29.0.0/24".parse().expect("network"),
            &[plan],
            now,
        )
        .expect("policy");
        assert_eq!(policy.expires_at, now + ChronoDuration::hours(24));
        assert_eq!(policy.limits.connect_timeout_seconds, 120);
        assert_eq!(policy.limits.max_connection_seconds, 300);
    }

    #[test]
    fn provider_service_policy_requires_exact_fqdn_443_and_keeps_distinct_provenance() {
        let now = Utc::now();
        for rejected in [
            "AWS IAM API",
            "*.amazonaws.com:443",
            "https://iam.amazonaws.com:443",
            "iam.amazonaws.com:80",
            "IAM.AMAZONAWS.COM:443",
            "203.0.113.8:443",
        ] {
            assert!(parse_exact_provider_destination(rejected).is_err());
        }
        assert_eq!(
            parse_exact_provider_destination("iam.amazonaws.com:443").expect("endpoint"),
            ("iam.amazonaws.com".into(), 443)
        );
        let request = ProviderServiceEgressRequest {
            case_id: "case-1".into(),
            source_id: "source-1".into(),
            source_kind: "aws_organization".into(),
            source_profile: "aws_organization_read_only_session".into(),
            manifest_id: "cloudsplaining".into(),
            manifest_revision: "0123456789abcdef0123456789abcdef01234567".into(),
            exact_destinations: vec![
                "iam.amazonaws.com:443".into(),
                "sts.amazonaws.com:443".into(),
            ],
            expires_at: now + ChronoDuration::minutes(30),
        };
        let mut mismatched_provider = request.clone();
        mismatched_provider.exact_destinations = vec!["attacker.example:443".into()];
        assert!(validate_provider_service_request_static(&mismatched_provider, now).is_err());
        let plan = ResolvedProviderServicePlan {
            request,
            frozen_at: now,
            destinations: vec![GatewayDestination {
                hostname: Some("iam.amazonaws.com".into()),
                addresses: ["203.0.113.8".parse().expect("address")]
                    .into_iter()
                    .collect(),
                ports: [443].into_iter().collect(),
                allow_sensitive_networks: false,
            }],
        };
        let policy = EgressGatewayPolicy::from_provider_service_plan(
            "policy-1",
            "172.29.0.1:1080".parse().expect("listener"),
            "172.29.0.0/24".parse().expect("network"),
            &plan,
            now,
        )
        .expect("provider policy");
        assert!(matches!(
            policy.provenance,
            EgressGatewayProvenance::ProviderService { ref source_id, ref manifest_id, .. }
                if source_id == "source-1" && manifest_id == "cloudsplaining"
        ));
        assert_eq!(
            policy.allowed_destination_labels(),
            vec!["iam.amazonaws.com:443"]
        );
    }

    #[test]
    fn static_provider_service_validation_rejects_invalid_requests_without_dns() {
        let now = Utc::now();
        let request = ProviderServiceEgressRequest {
            case_id: "case-1".into(),
            source_id: "source-1".into(),
            source_kind: "dns".into(),
            source_profile: "snapshot:dns-response".into(),
            manifest_id: "passive-dns".into(),
            manifest_revision: "0123456789abcdef0123456789abcdef01234567".into(),
            // `.invalid` is deliberately non-resolving. Static validation must
            // accept its canonical shape without attempting a lookup.
            exact_destinations: vec!["preflight-does-not-resolve.invalid:443".into()],
            expires_at: now + ChronoDuration::minutes(30),
        };
        validate_provider_service_request_static(&request, now)
            .expect("static request validation does not resolve DNS");

        let mut expired = request.clone();
        expired.expires_at = now;
        assert!(validate_provider_service_request_static(&expired, now).is_err());

        let mut duplicated = request.clone();
        duplicated
            .exact_destinations
            .push("preflight-does-not-resolve.invalid:443".into());
        assert!(validate_provider_service_request_static(&duplicated, now).is_err());

        let mut unpinned = request.clone();
        unpinned.manifest_revision.clear();
        assert!(validate_provider_service_request_static(&unpinned, now).is_err());

        let mut wrong_provider = request;
        wrong_provider.source_kind = "aws_organization".into();
        assert!(validate_provider_service_request_static(&wrong_provider, now).is_err());
    }

    #[test]
    fn parses_and_proves_docker_and_podman_networks() {
        let labels = expected_labels("policy-1");
        let docker = json!([{
            "Name": "ass-egress-1",
            "Id": "docker-network-id",
            "Driver": "bridge",
            "Internal": true,
            "Labels": labels,
            "IPAM": { "Config": [{ "Subnet": "172.29.0.0/24", "Gateway": "172.29.0.1" }] }
        }]);
        let inspected = parse_network_inspect(
            RuntimeProvider::Docker,
            &serde_json::to_vec(&docker).expect("JSON"),
            "ass-egress-1",
            &expected_labels("policy-1"),
        )
        .expect("Docker network");
        assert_eq!(
            inspected.gateway,
            "172.29.0.1".parse::<IpAddr>().expect("address")
        );

        let podman = json!([{
            "name": "ass-egress-1",
            "id": "podman-network-id",
            "driver": "bridge",
            "internal": true,
            "labels": expected_labels("policy-1"),
            "subnets": [{ "subnet": "10.89.1.0/24", "gateway": "10.89.1.1" }]
        }]);
        let inspected = parse_network_inspect(
            RuntimeProvider::Podman,
            &serde_json::to_vec(&podman).expect("JSON"),
            "ass-egress-1",
            &expected_labels("policy-1"),
        )
        .expect("Podman network");
        assert_eq!(inspected.subnet, "10.89.1.0/24".parse().expect("network"));

        let inspected = parse_network_inspect(
            RuntimeProvider::ManagedLocal,
            &serde_json::to_vec(&podman).expect("JSON"),
            "ass-egress-1",
            &expected_labels("policy-1"),
        )
        .expect("managed-local Podman network");
        assert_eq!(inspected.id, "podman-network-id");

        let uplink_labels = expected_uplink_labels("policy-1");
        let docker_uplink = json!([{
            "Name": "ass-uplink-1",
            "Id": "docker-uplink-id",
            "Driver": "bridge",
            "Internal": false,
            "Labels": uplink_labels,
            "IPAM": { "Config": [
                { "Subnet": "172.30.0.0/28", "Gateway": "172.30.0.1" },
                { "Subnet": "fd42:1234:5678:9abc::/64", "Gateway": "fd42:1234:5678:9abc::1" }
            ] }
        }]);
        let docker_uplink = parse_network_inspect_with_mode(
            RuntimeProvider::Docker,
            &serde_json::to_vec(&docker_uplink).expect("JSON"),
            "ass-uplink-1",
            &expected_uplink_labels("policy-1"),
            NetworkTopologyRequirement::UplinkDualStack,
        )
        .expect("dual-stack Docker uplink");
        assert_eq!(
            docker_uplink.ipv6_subnet,
            Some("fd42:1234:5678:9abc::/64".parse().expect("IPv6 subnet"))
        );

        let podman_uplink = json!([{
            "name": "ass-uplink-1",
            "id": "podman-uplink-id",
            "driver": "bridge",
            "internal": false,
            "labels": expected_uplink_labels("policy-1"),
            "subnets": [
                { "subnet": "10.90.1.0/28", "gateway": "10.90.1.1" },
                { "subnet": "fd55:aaaa:bbbb:cccc::/64", "gateway": "fd55:aaaa:bbbb:cccc::1" }
            ]
        }]);
        let podman_uplink = parse_network_inspect_with_mode(
            RuntimeProvider::Podman,
            &serde_json::to_vec(&podman_uplink).expect("JSON"),
            "ass-uplink-1",
            &expected_uplink_labels("policy-1"),
            NetworkTopologyRequirement::UplinkDualStack,
        )
        .expect("dual-stack Podman uplink");
        assert_eq!(
            podman_uplink.ipv6_gateway,
            Some("fd55:aaaa:bbbb:cccc::1".parse().expect("IPv6 gateway"))
        );

        let ipv4_only_uplink = json!([{
            "name": "ass-uplink-1",
            "id": "podman-uplink-id",
            "driver": "bridge",
            "internal": false,
            "labels": expected_uplink_labels("policy-1"),
            "subnets": [{ "subnet": "10.90.1.0/28", "gateway": "10.90.1.1" }]
        }]);
        assert!(
            parse_network_inspect_with_mode(
                RuntimeProvider::Podman,
                &serde_json::to_vec(&ipv4_only_uplink).expect("JSON"),
                "ass-uplink-1",
                &expected_uplink_labels("policy-1"),
                NetworkTopologyRequirement::UplinkDualStack,
            )
            .is_err()
        );
        assert!(
            parse_network_inspect_with_mode(
                RuntimeProvider::Podman,
                &serde_json::to_vec(&ipv4_only_uplink).expect("JSON"),
                "ass-uplink-1",
                &expected_uplink_labels("policy-1"),
                NetworkTopologyRequirement::UplinkLegacyCompatible,
            )
            .is_ok()
        );
    }

    #[test]
    fn private_network_candidates_exclude_frozen_destinations_in_default_runtime_ranges() {
        let prohibited = vec![
            "10.89.1.8/32".parse::<IpNet>().expect("IPv4 target"),
            "fd42:1234:5678:9abc::8/128"
                .parse::<IpNet>()
                .expect("IPv6 target"),
        ];
        let candidates = candidate_private_networks(
            "egress-0123456789abcdef0123456789abcdef",
            UPLINK_RESOURCE_ROLE,
            &prohibited,
            true,
        )
        .expect("collision-free candidates");
        assert_eq!(candidates.len(), MAX_NETWORK_SUBNET_ATTEMPTS);
        assert!(candidates.iter().all(|candidate| {
            !prohibited
                .iter()
                .any(|network| networks_overlap(candidate.ipv4_subnet, *network))
                && candidate.ipv6_subnet.is_some_and(|subnet| {
                    !prohibited
                        .iter()
                        .any(|network| networks_overlap(subnet, *network))
                })
        }));
    }

    #[test]
    fn podman_already_used_subnet_diagnostic_is_a_bounded_retryable_conflict() {
        assert!(runtime_reports_subnet_conflict(
            b"Error: subnet 10.89.1.0/28 is already used on the host or by another config"
        ));
        assert!(!runtime_reports_subnet_conflict(
            b"Error: permission denied while creating network"
        ));
    }

    #[test]
    fn managed_local_never_uses_a_path_resolved_runtime_command() {
        let error = DirectRuntimeCommands
            .output(
                RuntimeProvider::ManagedLocal,
                &[OsString::from("network"), OsString::from("inspect")],
            )
            .expect_err("managed local requires a verified command context");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(
            error
                .to_string()
                .contains("verified private command context")
        );
    }

    #[test]
    fn rejects_public_non_internal_or_mislabeled_bridges() {
        let expected = expected_labels("policy-1");
        for (internal, labels, subnet, gateway) in [
            (false, expected.clone(), "172.29.0.0/24", "172.29.0.1"),
            (
                true,
                expected_labels("other-policy"),
                "172.29.0.0/24",
                "172.29.0.1",
            ),
            (true, expected.clone(), "203.0.113.0/24", "203.0.113.1"),
        ] {
            let document = json!([{
                "Name": "ass-egress-1",
                "Id": "network-id",
                "Driver": "bridge",
                "Internal": internal,
                "Labels": labels,
                "IPAM": { "Config": [{ "Subnet": subnet, "Gateway": gateway }] }
            }]);
            assert!(
                parse_network_inspect(
                    RuntimeProvider::Docker,
                    &serde_json::to_vec(&document).expect("JSON"),
                    "ass-egress-1",
                    &expected,
                )
                .is_err()
            );
        }
    }

    #[test]
    fn udp_and_unfrozen_targets_do_not_become_runnable() {
        let now = Utc::now();
        let mut udp = plan(now, "203.0.113.8", 5, 2, 30);
        udp.protocol = TransportProtocol::Udp;
        assert!(
            EgressGatewayPolicy::from_resolved_plans(
                "policy-1",
                "172.29.0.1:1080".parse().expect("listener"),
                "172.29.0.0/24".parse().expect("network"),
                &[udp],
                now,
            )
            .is_err()
        );

        let mut empty = plan(now, "203.0.113.8", 5, 2, 30);
        empty.resolution.addresses.clear();
        assert!(
            EgressGatewayPolicy::from_resolved_plans(
                "policy-1",
                "172.29.0.1:1080".parse().expect("listener"),
                "172.29.0.0/24".parse().expect("network"),
                &[empty],
                now,
            )
            .is_err()
        );
    }

    #[derive(Debug, Clone, Copy)]
    enum FakeInspectKind {
        Docker,
        Podman,
    }

    #[derive(Debug)]
    struct FakeRuntimeState {
        kind: FakeInspectKind,
        calls: Vec<(RuntimeProvider, Vec<String>)>,
        network_name: Option<String>,
        labels: BTreeMap<String, String>,
        subnet: Option<String>,
        gateway: Option<String>,
        removed: bool,
    }

    struct FakeRuntime {
        state: Arc<Mutex<FakeRuntimeState>>,
    }

    impl FakeRuntime {
        fn new(kind: FakeInspectKind) -> (Self, Arc<Mutex<FakeRuntimeState>>) {
            let state = Arc::new(Mutex::new(FakeRuntimeState {
                kind,
                calls: Vec::new(),
                network_name: None,
                labels: BTreeMap::new(),
                subnet: None,
                gateway: None,
                removed: false,
            }));
            (
                Self {
                    state: Arc::clone(&state),
                },
                state,
            )
        }
    }

    impl RuntimeCommands for FakeRuntime {
        fn output(
            &self,
            provider: RuntimeProvider,
            args: &[OsString],
        ) -> io::Result<RuntimeOutput> {
            let args = args
                .iter()
                .map(|value| value.to_string_lossy().into_owned())
                .collect::<Vec<_>>();
            let mut state = self.state.lock().expect("fake runtime");
            state.calls.push((provider, args.clone()));
            match args.get(0..2) {
                Some([network, create]) if network == "network" && create == "create" => {
                    let name = args.last().expect("network name").clone();
                    let subnet = args
                        .windows(2)
                        .find(|pair| pair[0] == "--subnet")
                        .map(|pair| pair[1].clone())
                        .expect("explicit network subnet");
                    let gateway = args
                        .windows(2)
                        .find(|pair| pair[0] == "--gateway")
                        .map(|pair| pair[1].clone())
                        .expect("explicit network gateway");
                    let mut labels = BTreeMap::new();
                    let mut index = 0;
                    while index < args.len() {
                        if args[index] == "--label" {
                            let (key, value) =
                                args[index + 1].split_once('=').expect("label assignment");
                            labels.insert(key.into(), value.into());
                            index += 2;
                        } else {
                            index += 1;
                        }
                    }
                    state.network_name = Some(name);
                    state.labels = labels;
                    state.subnet = Some(subnet);
                    state.gateway = Some(gateway);
                    state.removed = false;
                    Ok(success_output(Vec::new()))
                }
                Some([network, inspect]) if network == "network" && inspect == "inspect" => {
                    let Some(name) = state.network_name.as_ref() else {
                        return Ok(failure_output("network not found"));
                    };
                    if state.removed {
                        return Ok(failure_output("network not found"));
                    }
                    let subnet = state.subnet.as_deref().expect("created subnet");
                    let gateway = state.gateway.as_deref().expect("created gateway");
                    let value = match state.kind {
                        FakeInspectKind::Docker => json!([{
                            "Name": name,
                            "Id": "network-id-1",
                            "Driver": "bridge",
                            "Internal": true,
                            "Labels": state.labels.clone(),
                            "IPAM": { "Config": [{ "Subnet": subnet, "Gateway": gateway }] }
                        }]),
                        FakeInspectKind::Podman => json!([{
                            "name": name,
                            "id": "network-id-1",
                            "driver": "bridge",
                            "internal": true,
                            "labels": state.labels.clone(),
                            "subnets": [{ "subnet": subnet, "gateway": gateway }]
                        }]),
                    };
                    Ok(success_output(serde_json::to_vec(&value).expect("JSON")))
                }
                Some([network, remove]) if network == "network" && remove == "rm" => {
                    state.removed = true;
                    Ok(success_output(Vec::new()))
                }
                _ => Ok(failure_output("unexpected command")),
            }
        }
    }

    #[derive(Debug, Clone)]
    struct FakeContainerNetwork {
        id: String,
        internal: bool,
        labels: BTreeMap<String, String>,
        subnet: String,
        gateway: String,
        ipv6_subnet: Option<String>,
        ipv6_gateway: Option<String>,
        removed: bool,
    }

    #[derive(Debug, Clone)]
    struct FakeGatewayContainer {
        id: String,
        name: String,
        image: String,
        labels: BTreeMap<String, String>,
        uplink: String,
        internal: Option<(String, String)>,
        running: bool,
        removed: bool,
    }

    fn fake_assigned_address(subnet: &str) -> String {
        match subnet.parse::<IpNet>().expect("fake network subnet") {
            IpNet::V4(network) => Ipv4Addr::from(u32::from(network.network()) + 2).to_string(),
            IpNet::V6(network) => Ipv6Addr::from(u128::from(network.network()) + 2).to_string(),
        }
    }

    #[derive(Debug, Default)]
    struct FakeContainerRuntimeState {
        calls: Vec<Vec<String>>,
        pull_timeout: Option<Duration>,
        internal_conflicts_remaining: usize,
        uplink_conflicts_remaining: usize,
        docker_engine_29_wording: bool,
        uplink_create_failures_remaining: usize,
        networks: BTreeMap<String, FakeContainerNetwork>,
        container: Option<FakeGatewayContainer>,
        probe: Option<FakeGatewayContainer>,
        container_stop_failures_remaining: usize,
    }

    struct FakeContainerRuntime {
        state: Arc<Mutex<FakeContainerRuntimeState>>,
    }

    impl FakeContainerRuntime {
        fn new() -> (Self, Arc<Mutex<FakeContainerRuntimeState>>) {
            let state = Arc::new(Mutex::new(FakeContainerRuntimeState::default()));
            (
                Self {
                    state: Arc::clone(&state),
                },
                state,
            )
        }

        fn execute(&self, args: &[OsString]) -> io::Result<RuntimeOutput> {
            let args = args
                .iter()
                .map(|value| value.to_string_lossy().into_owned())
                .collect::<Vec<_>>();
            let mut state = self.state.lock().expect("fake container runtime");
            state.calls.push(args.clone());
            let docker_engine_29_wording = state.docker_engine_29_wording;
            if args.first().is_some_and(|argument| argument == "pull") {
                return Ok(success_output(Vec::new()));
            }
            match args.get(0..2) {
                Some([network, create]) if network == "network" && create == "create" => {
                    let name = args.last().expect("network name").clone();
                    let internal = args.iter().any(|argument| argument == "--internal");
                    let subnets = args
                        .windows(2)
                        .filter(|pair| pair[0] == "--subnet")
                        .map(|pair| pair[1].clone())
                        .collect::<Vec<_>>();
                    let gateways = args
                        .windows(2)
                        .filter(|pair| pair[0] == "--gateway")
                        .map(|pair| pair[1].clone())
                        .collect::<Vec<_>>();
                    assert_eq!(subnets.len(), gateways.len());
                    if internal {
                        assert_eq!(subnets.len(), 1);
                        assert!(!args.iter().any(|argument| argument == "--ipv6"));
                    } else {
                        assert_eq!(subnets.len(), 2);
                        assert!(args.iter().any(|argument| argument == "--ipv6"));
                    }
                    if !internal && state.uplink_create_failures_remaining > 0 {
                        state.uplink_create_failures_remaining -= 1;
                        return Ok(failure_output(
                            "Error response from daemon: permission denied",
                        ));
                    }
                    let conflicts_remaining = if internal {
                        &mut state.internal_conflicts_remaining
                    } else {
                        &mut state.uplink_conflicts_remaining
                    };
                    if *conflicts_remaining > 0 {
                        *conflicts_remaining -= 1;
                        let message = if docker_engine_29_wording {
                            "Error response from daemon: invalid pool request: Pool overlaps with other one on this address space"
                                .to_owned()
                        } else {
                            format!(
                                "subnet {} is already used on the host or by another config",
                                subnets[0]
                            )
                        };
                        return Ok(failure_output(&message));
                    }
                    let mut labels = BTreeMap::new();
                    let mut index = 0;
                    while index < args.len() {
                        if args[index] == "--label" {
                            let (key, value) = args[index + 1]
                                .split_once('=')
                                .expect("network label assignment");
                            labels.insert(key.into(), value.into());
                            index += 2;
                        } else {
                            index += 1;
                        }
                    }
                    let id = if internal {
                        "a".repeat(64)
                    } else {
                        "b".repeat(64)
                    };
                    state.networks.insert(
                        name,
                        FakeContainerNetwork {
                            id,
                            internal,
                            labels,
                            subnet: subnets[0].clone(),
                            gateway: gateways[0].clone(),
                            ipv6_subnet: subnets.get(1).cloned(),
                            ipv6_gateway: gateways.get(1).cloned(),
                            removed: false,
                        },
                    );
                    Ok(success_output(Vec::new()))
                }
                Some([network, inspect]) if network == "network" && inspect == "inspect" => {
                    let selector = args.get(2).expect("network selector");
                    let network = state
                        .networks
                        .iter()
                        .find(|(name, network)| {
                            !network.removed && (*name == selector || &network.id == selector)
                        })
                        .map(|(name, network)| (name.clone(), network.clone()));
                    let Some((name, network)) = network else {
                        let message = if docker_engine_29_wording {
                            format!("Error response from daemon: network {selector} not found")
                        } else {
                            "network not found".to_owned()
                        };
                        return Ok(failure_output(&message));
                    };
                    let mut subnets = vec![json!({
                        "subnet": network.subnet,
                        "gateway": network.gateway,
                    })];
                    if let (Some(subnet), Some(gateway)) =
                        (network.ipv6_subnet, network.ipv6_gateway)
                    {
                        subnets.push(json!({ "subnet": subnet, "gateway": gateway }));
                    }
                    let value = json!([{
                        "name": name,
                        "id": network.id,
                        "driver": "bridge",
                        "internal": network.internal,
                        "labels": network.labels,
                        "subnets": subnets,
                    }]);
                    Ok(success_output(
                        serde_json::to_vec(&value).expect("network JSON"),
                    ))
                }
                Some([network, remove]) if network == "network" && remove == "rm" => {
                    let selector = args.get(2).expect("network selector");
                    let Some(network) = state
                        .networks
                        .values_mut()
                        .find(|network| !network.removed && &network.id == selector)
                    else {
                        let message = if docker_engine_29_wording {
                            format!(
                                "Error response from daemon: network {selector} not found\nexit status 1"
                            )
                        } else {
                            "network not found".to_owned()
                        };
                        return Ok(failure_output(&message));
                    };
                    network.removed = true;
                    Ok(success_output(Vec::new()))
                }
                Some([container, create]) if container == "container" && create == "create" => {
                    let name = args
                        .windows(2)
                        .find(|pair| pair[0] == "--name")
                        .map(|pair| pair[1].clone())
                        .expect("container name");
                    let uplink = args
                        .windows(2)
                        .find(|pair| pair[0] == "--network")
                        .map(|pair| pair[1].clone())
                        .expect("container uplink");
                    let image = args
                        .iter()
                        .find(|argument| argument.contains("@sha256:"))
                        .cloned()
                        .expect("pinned container image");
                    let mut labels = BTreeMap::new();
                    for pair in args.windows(2).filter(|pair| pair[0] == "--label") {
                        let (key, value) =
                            pair[1].split_once('=').expect("container label assignment");
                        labels.insert(key.into(), value.into());
                    }
                    let is_probe = name.starts_with("ass-probe-");
                    let id = if is_probe {
                        "e".repeat(64)
                    } else {
                        "c".repeat(64)
                    };
                    let created = FakeGatewayContainer {
                        id: id.clone(),
                        name,
                        image,
                        labels,
                        uplink,
                        internal: None,
                        running: false,
                        removed: false,
                    };
                    if is_probe {
                        state.probe = Some(created);
                    } else {
                        state.container = Some(created);
                    }
                    Ok(success_output(format!("{id}\n").into_bytes()))
                }
                Some([container, inspect]) if container == "container" && inspect == "inspect" => {
                    let selector = args.get(2).expect("container selector");
                    let selected = state
                        .container
                        .as_ref()
                        .into_iter()
                        .chain(state.probe.as_ref())
                        .find(|container| {
                            !container.removed
                                && (&container.id == selector || &container.name == selector)
                        })
                        .cloned();
                    let Some(container) = selected else {
                        return Ok(failure_output("no such container"));
                    };
                    let mut networks = serde_json::Map::new();
                    let attached_network = state
                        .networks
                        .get(&container.uplink)
                        .expect("attached fake network");
                    let ipv4_address = if container.running {
                        fake_assigned_address(&attached_network.subnet)
                    } else {
                        String::new()
                    };
                    let ipv6_address = if container.running {
                        attached_network
                            .ipv6_subnet
                            .as_deref()
                            .map(fake_assigned_address)
                            .unwrap_or_default()
                    } else {
                        String::new()
                    };
                    networks.insert(
                        container.uplink.clone(),
                        json!({
                            "IPAddress": ipv4_address,
                            "GlobalIPv6Address": ipv6_address,
                        }),
                    );
                    if let Some((name, address)) = &container.internal {
                        let inspected_address = if container.running {
                            address.as_str()
                        } else {
                            ""
                        };
                        networks.insert(
                            name.clone(),
                            json!({ "IPAddress": inspected_address, "GlobalIPv6Address": "" }),
                        );
                    }
                    let value = json!([{
                        "Id": container.id,
                        "Name": container.name,
                        "ImageName": container.image,
                        "Config": { "Image": container.image, "Labels": container.labels },
                        "State": { "Running": container.running, "ExitCode": 0 },
                        "NetworkSettings": { "Networks": networks }
                    }]);
                    Ok(success_output(
                        serde_json::to_vec(&value).expect("container JSON"),
                    ))
                }
                Some([network, connect]) if network == "network" && connect == "connect" => {
                    if args.len() != 6 || args[2] != "--ip" {
                        return Ok(failure_output("unexpected network connect argv"));
                    }
                    let Some(container) = state.container.as_mut() else {
                        return Ok(failure_output("no such container"));
                    };
                    if args[5] != container.name {
                        return Ok(failure_output("wrong gateway container"));
                    }
                    container.internal = Some((args[4].clone(), args[3].clone()));
                    Ok(success_output(Vec::new()))
                }
                Some([container, start]) if container == "container" && start == "start" => {
                    if args.get(2).is_some_and(|argument| argument == "--attach") {
                        let Some(probe) = state.probe.as_mut() else {
                            return Ok(failure_output("no such container"));
                        };
                        if args.get(3) != Some(&probe.id) {
                            return Ok(failure_output("wrong gateway probe"));
                        }
                        probe.running = false;
                        return Ok(success_output(
                            "{\"schema_version\":\"1.0.0\",\"reachability_probe\":\"socks5_no_connect_greeting\",\"gateway_reachable\":true,\"upstream_connect_attempted\":false}\n"
                                .as_bytes()
                                .to_vec(),
                        ));
                    }
                    let Some(container) = state.container.as_mut() else {
                        return Ok(failure_output("no such container"));
                    };
                    if args.get(2) != Some(&container.id) {
                        return Ok(failure_output("wrong gateway container"));
                    }
                    container.running = true;
                    Ok(success_output(Vec::new()))
                }
                Some([container, stop]) if container == "container" && stop == "stop" => {
                    if state.container_stop_failures_remaining > 0 {
                        state.container_stop_failures_remaining -= 1;
                        return Ok(failure_output("runtime refused exact container stop"));
                    }
                    let selector = args.get(4).expect("container stop selector");
                    let Some(container) = state.container.as_mut() else {
                        return Ok(failure_output("no such container"));
                    };
                    if &container.id != selector || container.removed {
                        return Ok(failure_output("no such container"));
                    }
                    container.running = false;
                    Ok(success_output(Vec::new()))
                }
                Some([container, remove]) if container == "container" && remove == "rm" => {
                    let selector = args.get(3).expect("container removal selector");
                    let selected =
                        if state.container.as_ref().is_some_and(|container| {
                            !container.removed && &container.id == selector
                        }) {
                            state.container.as_mut()
                        } else if state.probe.as_ref().is_some_and(|container| {
                            !container.removed && &container.id == selector
                        }) {
                            state.probe.as_mut()
                        } else {
                            None
                        };
                    let Some(container) = selected else {
                        return Ok(failure_output("no such container"));
                    };
                    container.removed = true;
                    container.running = false;
                    Ok(success_output(Vec::new()))
                }
                _ => Ok(failure_output("unexpected command")),
            }
        }
    }

    impl RuntimeCommands for FakeContainerRuntime {
        fn output(
            &self,
            _provider: RuntimeProvider,
            args: &[OsString],
        ) -> io::Result<RuntimeOutput> {
            self.execute(args)
        }

        fn output_with_timeout(
            &self,
            _provider: RuntimeProvider,
            args: &[OsString],
            timeout: Duration,
        ) -> io::Result<RuntimeOutput> {
            self.state
                .lock()
                .expect("fake container runtime")
                .pull_timeout = Some(timeout);
            self.execute(args)
        }
    }

    struct FakeContainerReadiness {
        fail: bool,
    }

    impl GatewayContainerReadiness for FakeContainerReadiness {
        fn wait_until_ready(
            &self,
            _runtime: &dyn RuntimeCommands,
            _provider: RuntimeProvider,
            _container: &GatewayContainerRuntimeIdentity,
            _status_directory: &GatewayStatusDirectory,
            _policy_id: &str,
        ) -> AppResult<()> {
            if self.fail {
                Err(AppError::Runtime("fake container readiness failure".into()))
            } else {
                Ok(())
            }
        }
    }

    #[derive(Default)]
    struct FakeProcessState {
        killed: bool,
        waited: bool,
        spawn_binary: Option<PathBuf>,
        spawn_policy: Option<PathBuf>,
    }

    struct FakeProcess {
        state: Arc<Mutex<FakeProcessState>>,
        exited: bool,
    }

    impl GatewayProcess for FakeProcess {
        fn has_exited(&mut self) -> io::Result<bool> {
            Ok(self.exited)
        }

        fn kill(&mut self) -> io::Result<()> {
            self.exited = true;
            self.state.lock().expect("fake process").killed = true;
            Ok(())
        }

        fn wait(&mut self) -> io::Result<()> {
            self.state.lock().expect("fake process").waited = true;
            Ok(())
        }
    }

    struct FakeLauncher {
        state: Arc<Mutex<FakeProcessState>>,
    }

    impl GatewayLauncher for FakeLauncher {
        fn spawn(&self, binary: &Path, policy_path: &Path) -> io::Result<Box<dyn GatewayProcess>> {
            let mut state = self.state.lock().expect("fake process");
            state.spawn_binary = Some(binary.to_owned());
            state.spawn_policy = Some(policy_path.to_owned());
            drop(state);
            Ok(Box::new(FakeProcess {
                state: Arc::clone(&self.state),
                exited: false,
            }))
        }
    }

    struct FakeReadiness {
        fail: bool,
        observed: Arc<Mutex<Vec<SocketAddr>>>,
    }

    impl GatewayReadiness for FakeReadiness {
        fn wait_until_ready(
            &self,
            _process: &mut dyn GatewayProcess,
            listen_address: SocketAddr,
        ) -> AppResult<()> {
            self.observed
                .lock()
                .expect("readiness observations")
                .push(listen_address);
            if self.fail {
                Err(AppError::Runtime("fake readiness failure".into()))
            } else {
                Ok(())
            }
        }
    }

    fn success_output(stdout: Vec<u8>) -> RuntimeOutput {
        RuntimeOutput {
            success: true,
            stdout,
            stderr: Vec::new(),
        }
    }

    fn failure_output(message: &str) -> RuntimeOutput {
        RuntimeOutput {
            success: false,
            stdout: Vec::new(),
            stderr: message.as_bytes().to_vec(),
        }
    }

    fn test_paths() -> (TempDir, PathBuf, PathBuf) {
        let temporary = tempfile::tempdir().expect("temporary directory");
        // Production deliberately accepts only paths that are already in their
        // canonical platform form. On Windows `tempfile` exposes a regular
        // `C:\\...` path while `fs::canonicalize` returns the equivalent
        // `\\\\?\\C:\\...` form, so constructing fixture children from the
        // former would make every test fail at the alias guard before reaching
        // the behavior it is meant to exercise.
        let root = fs::canonicalize(temporary.path()).expect("canonical temporary directory");
        let gateway = root.join("ai-security-scanner-egress-gateway");
        fs::write(&gateway, b"fake executable").expect("gateway file");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&gateway, fs::Permissions::from_mode(0o700)).expect("gateway mode");
        }
        let policies = root.join("policies");
        fs::create_dir(&policies).expect("policy directory");
        (temporary, gateway, policies)
    }

    fn owner() -> ManagedNetworkOwner {
        ManagedNetworkOwner::new("case-1", "run-1", "engine-run-1", 1).expect("owner")
    }

    fn test_registry(policies: &Path) -> PathBuf {
        let registry = policies.join("registry");
        fs::create_dir(&registry).expect("registry directory");
        registry
    }

    fn recovery_paths() -> (TempDir, PathBuf, PathBuf, PathBuf, PathBuf) {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let root = fs::canonicalize(temporary.path()).expect("canonical temporary directory");
        let gateway = root.join("ai-security-scanner-egress-gateway");
        fs::write(&gateway, b"fake executable").expect("gateway file");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&gateway, fs::Permissions::from_mode(0o700)).expect("gateway mode");
        }
        let artifacts = root.join("artifacts");
        let case_root = artifacts.join("case-1");
        let policies = case_root.join("network-policies");
        let registry = artifacts.join(".managed-egress-registry");
        fs::create_dir(&artifacts).expect("artifact root");
        fs::create_dir(&case_root).expect("case root");
        fs::create_dir(&policies).expect("policy directory");
        fs::create_dir(&registry).expect("registry directory");
        (temporary, gateway, artifacts, policies, registry)
    }

    #[test]
    fn gateway_container_spec_requires_an_allowed_publication_origin() {
        for (namespace, _) in crate::publication_origins::PUBLICATION_ORIGINS {
            assert!(
                GatewayContainerSpec::new(
                    format!("{namespace}/ai-security-scanner-egress-gateway"),
                    format!("sha256:{}", "d".repeat(64))
                )
                .is_ok()
            );
        }
        assert!(
            GatewayContainerSpec::new(
                "ghcr.io/unknown/ai-security-scanner-egress-gateway",
                format!("sha256:{}", "d".repeat(64))
            )
            .is_err()
        );
    }

    fn gateway_container_spec() -> GatewayContainerSpec {
        GatewayContainerSpec::new(
            "ghcr.io/teddashh/ai-security-scanner-egress-gateway",
            format!("sha256:{}", "d".repeat(64)),
        )
        .expect("gateway image spec")
    }

    fn compatibility_gateway_record(
        now: DateTime<Utc>,
        unique: &str,
        provider: RuntimeProvider,
        phase: RegistryPhase,
        gateway_container_id: Option<String>,
    ) -> ManagedNetworkRecord {
        let policy_id = format!("egress-{unique}");
        let spec = gateway_container_spec();
        ManagedNetworkRecord {
            schema_version: REGISTRY_SCHEMA_VERSION.into(),
            owner: owner(),
            provider,
            network_name: format!("ass-egress-{unique}"),
            policy_id,
            created_at: now,
            expires_at: now + ChronoDuration::hours(1),
            phase,
            network_id: Some("a".repeat(64)),
            uplink_network_name: Some(format!("ass-uplink-{unique}")),
            uplink_network_id: Some("b".repeat(64)),
            gateway_container_name: Some(format!("ass-gateway-{unique}")),
            gateway_container_id,
            gateway_listener_ip: Some("172.29.0.2".parse().expect("listener IP")),
            gateway_image_repository: Some(spec.repository().into()),
            gateway_image_digest: Some(spec.digest().into()),
            policy_sha256: Some("f".repeat(64)),
        }
    }

    fn install_fake_gateway(
        state: &Arc<Mutex<FakeContainerRuntimeState>>,
        record: &ManagedNetworkRecord,
    ) {
        let internal = record.network_name.clone();
        let uplink = record
            .uplink_network_name
            .clone()
            .expect("gateway uplink name");
        let listener = record.gateway_listener_ip.expect("gateway listener");
        let mut state = state.lock().expect("fake container runtime");
        state.networks.insert(
            internal.clone(),
            FakeContainerNetwork {
                id: record.network_id.clone().expect("internal network ID"),
                internal: true,
                labels: expected_labels(&record.policy_id),
                subnet: "172.29.0.0/24".into(),
                gateway: "172.29.0.1".into(),
                ipv6_subnet: None,
                ipv6_gateway: None,
                removed: false,
            },
        );
        state.networks.insert(
            uplink.clone(),
            FakeContainerNetwork {
                id: record.uplink_network_id.clone().expect("uplink network ID"),
                internal: false,
                labels: expected_uplink_labels(&record.policy_id),
                subnet: "172.30.0.0/24".into(),
                gateway: "172.30.0.1".into(),
                ipv6_subnet: Some("fd00:30::/64".into()),
                ipv6_gateway: Some("fd00:30::1".into()),
                removed: false,
            },
        );
        state.container = Some(FakeGatewayContainer {
            id: record
                .gateway_container_id
                .clone()
                .expect("gateway container ID"),
            name: record
                .gateway_container_name
                .clone()
                .expect("gateway container name"),
            image: gateway_container_spec().reference(),
            labels: expected_gateway_container_labels(&record.policy_id),
            uplink,
            internal: Some((internal, listener.to_string())),
            running: true,
            removed: false,
        });
    }

    #[test]
    fn uninstall_contact_stop_removes_only_an_exact_compatibility_gateway() {
        let (_temporary, _gateway, artifacts, _policies, registry_root) = recovery_paths();
        let (runtime, state) = FakeContainerRuntime::new();
        let runtime = Arc::new(runtime);
        let now = Utc::now();
        let record = compatibility_gateway_record(
            now,
            &"1".repeat(32),
            RuntimeProvider::Docker,
            RegistryPhase::GatewayContainerVerified,
            Some("c".repeat(64)),
        );
        install_fake_gateway(&state, &record);
        write_registry_snapshot(&registry_root, &record).expect("gateway registry record");
        let registry = ManagedNetworkRegistry::with_runtime(&registry_root, &artifacts, runtime)
            .expect("registry");

        let summary = registry.stop_verified_compatibility_gateways(now);

        assert_eq!(summary.exact_gateways_found, 1);
        assert_eq!(summary.exact_gateways_stopped, 1);
        assert_eq!(summary.exact_stop_failures, 0);
        assert_eq!(summary.retained_ambiguities, 0);
        let state = state.lock().expect("fake container runtime");
        assert!(
            state
                .container
                .as_ref()
                .is_some_and(|item| !item.running && !item.removed)
        );
        assert!(state.calls.iter().any(|call| {
            call.get(0..4)
                == Some(&[
                    "container".into(),
                    "stop".into(),
                    "--time".into(),
                    "10".into(),
                ])
        }));
        assert!(
            !state
                .calls
                .iter()
                .any(|call| call.first().is_some_and(|value| value == "network"))
        );
        assert!(
            fs::read_dir(&registry_root)
                .expect("registry")
                .next()
                .is_some()
        );
    }

    #[test]
    fn uninstall_contact_stop_does_not_treat_an_absent_current_context_as_stopped() {
        let (_temporary, _gateway, artifacts, _policies, registry_root) = recovery_paths();
        let (runtime, state) = FakeContainerRuntime::new();
        let now = Utc::now();
        let record = compatibility_gateway_record(
            now,
            &"2".repeat(32),
            RuntimeProvider::Podman,
            RegistryPhase::ContainerReady,
            Some("d".repeat(64)),
        );
        write_registry_snapshot(&registry_root, &record).expect("gateway registry record");
        let registry =
            ManagedNetworkRegistry::with_runtime(&registry_root, &artifacts, Arc::new(runtime))
                .expect("registry");

        let summary = registry.stop_verified_compatibility_gateways(now);

        assert_eq!(summary.exact_gateways_found, 1);
        assert_eq!(summary.exact_gateways_stopped, 0);
        assert_eq!(summary.exact_stop_failures, 1);
        let state = state.lock().expect("fake container runtime");
        assert_eq!(state.calls.len(), 1);
        assert_eq!(state.calls[0][0], "container");
        assert_eq!(state.calls[0][1], "inspect");
    }

    #[test]
    fn uninstall_contact_stop_marks_an_over_limit_registry_incomplete() {
        let (_temporary, _gateway, artifacts, _policies, registry_root) = recovery_paths();
        let (runtime, state) = FakeContainerRuntime::new();
        for index in 0..=MAX_REGISTRY_RECORDS {
            fs::write(
                registry_root.join(format!("bounded-record-{index:04}")),
                b"retained",
            )
            .expect("bounded registry fixture");
        }
        let registry =
            ManagedNetworkRegistry::with_runtime(&registry_root, &artifacts, Arc::new(runtime))
                .expect("registry");

        let summary = registry.stop_verified_compatibility_gateways(Utc::now());

        assert!(summary.contact_inventory_incomplete);
        assert_eq!(summary.exact_gateways_stopped, 0);
        assert_eq!(summary.exact_stop_failures, 0);
        assert_eq!(summary.retained_ambiguities, 1);
        assert!(
            state
                .lock()
                .expect("fake container runtime")
                .calls
                .is_empty()
        );
    }

    #[test]
    fn uninstall_cleanup_reconciles_only_compatibility_container_records_after_stop() {
        let (_temporary, _gateway, artifacts, _policies, registry_root) = recovery_paths();
        let (runtime, state) = FakeContainerRuntime::new();
        let runtime = Arc::new(runtime);
        let now = Utc::now();
        let compatibility = compatibility_gateway_record(
            now,
            &"8".repeat(32),
            RuntimeProvider::Podman,
            RegistryPhase::ContainerReady,
            Some("c".repeat(64)),
        );
        let managed = compatibility_gateway_record(
            now,
            &"9".repeat(32),
            RuntimeProvider::ManagedLocal,
            RegistryPhase::ContainerReady,
            Some("e".repeat(64)),
        );
        let direct_unique = "a".repeat(32);
        let direct = ManagedNetworkRecord {
            schema_version: REGISTRY_SCHEMA_VERSION.into(),
            owner: owner(),
            provider: RuntimeProvider::Docker,
            network_name: format!("ass-egress-{direct_unique}"),
            policy_id: format!("egress-{direct_unique}"),
            created_at: now,
            expires_at: now + ChronoDuration::hours(1),
            phase: RegistryPhase::Ready,
            network_id: Some("1".repeat(64)),
            uplink_network_name: None,
            uplink_network_id: None,
            gateway_container_name: None,
            gateway_container_id: None,
            gateway_listener_ip: None,
            gateway_image_repository: None,
            gateway_image_digest: None,
            policy_sha256: Some("f".repeat(64)),
        };
        install_fake_gateway(&state, &compatibility);
        write_registry_snapshot(&registry_root, &compatibility)
            .expect("compatibility registry record");
        write_registry_snapshot(&registry_root, &managed).expect("managed registry record");
        write_registry_snapshot(&registry_root, &direct).expect("direct registry record");
        let registry = ManagedNetworkRegistry::with_runtime(&registry_root, &artifacts, runtime)
            .expect("registry");
        let stopped = registry.stop_verified_compatibility_gateways(now);
        assert_eq!(stopped.exact_gateways_stopped, 1);

        let cleanup = registry.reconcile_verified_compatibility_gateway_records(now);

        assert_eq!(cleanup.reconciled, 1);
        assert_eq!(cleanup.incomplete, 0);
        let state = state.lock().expect("fake container runtime");
        assert!(state.networks.values().all(|network| network.removed));
        assert!(!state.calls.iter().any(|call| {
            call.get(0..2) == Some(&["network".into(), "inspect".into()])
                && call.get(2) == Some(&direct.network_name)
        }));
        assert_eq!(fs::read_dir(&registry_root).expect("registry").count(), 2);
    }

    #[test]
    fn uninstall_contact_stop_issues_no_command_for_early_or_managed_local_state() {
        let (_temporary, _gateway, artifacts, _policies, registry_root) = recovery_paths();
        let (runtime, state) = FakeContainerRuntime::new();
        let now = Utc::now();
        let early = compatibility_gateway_record(
            now,
            &"3".repeat(32),
            RuntimeProvider::Docker,
            RegistryPhase::PolicyReady,
            None,
        );
        let managed = compatibility_gateway_record(
            now,
            &"4".repeat(32),
            RuntimeProvider::ManagedLocal,
            RegistryPhase::GatewayContainerVerified,
            Some("e".repeat(64)),
        );
        write_registry_snapshot(&registry_root, &early).expect("early registry record");
        write_registry_snapshot(&registry_root, &managed).expect("managed registry record");
        let registry =
            ManagedNetworkRegistry::with_runtime(&registry_root, &artifacts, Arc::new(runtime))
                .expect("registry");

        let summary = registry.stop_verified_compatibility_gateways(now);

        assert_eq!(summary, ManagedCompatibilityGatewayStopSummary::default());
        assert!(
            state
                .lock()
                .expect("fake container runtime")
                .calls
                .is_empty()
        );
    }

    #[test]
    fn uninstall_contact_stop_retains_legacy_direct_host_gateway_without_pid_authority() {
        let (_temporary, _gateway, artifacts, _policies, registry_root) = recovery_paths();
        let (runtime, state) = FakeContainerRuntime::new();
        let now = Utc::now();
        let unique = "6".repeat(32);
        let record = ManagedNetworkRecord {
            schema_version: REGISTRY_SCHEMA_VERSION.into(),
            owner: owner(),
            provider: RuntimeProvider::Docker,
            network_name: format!("ass-egress-{unique}"),
            policy_id: format!("egress-{unique}"),
            created_at: now,
            expires_at: now + ChronoDuration::hours(1),
            phase: RegistryPhase::Ready,
            network_id: Some("a".repeat(64)),
            uplink_network_name: None,
            uplink_network_id: None,
            gateway_container_name: None,
            gateway_container_id: None,
            gateway_listener_ip: None,
            gateway_image_repository: None,
            gateway_image_digest: None,
            policy_sha256: Some("f".repeat(64)),
        };
        write_registry_snapshot(&registry_root, &record).expect("legacy registry record");
        let registry =
            ManagedNetworkRegistry::with_runtime(&registry_root, &artifacts, Arc::new(runtime))
                .expect("registry");

        let summary = registry.stop_verified_compatibility_gateways(now);

        assert_eq!(summary.exact_gateways_found, 0);
        assert_eq!(summary.exact_stop_failures, 0);
        assert_eq!(summary.retained_ambiguities, 1);
        assert!(
            state
                .lock()
                .expect("fake container runtime")
                .calls
                .is_empty()
        );
    }

    #[test]
    fn uninstall_contact_stop_separates_replaced_identity_from_context_absence() {
        let (_temporary, _gateway, artifacts, _policies, registry_root) = recovery_paths();
        let (runtime, state) = FakeContainerRuntime::new();
        let now = Utc::now();
        let record = compatibility_gateway_record(
            now,
            &"5".repeat(32),
            RuntimeProvider::Docker,
            RegistryPhase::ContainerReady,
            Some("f".repeat(64)),
        );
        let absent_sibling = compatibility_gateway_record(
            now,
            &"7".repeat(32),
            RuntimeProvider::Podman,
            RegistryPhase::ContainerReady,
            Some("d".repeat(64)),
        );
        install_fake_gateway(&state, &record);
        state
            .lock()
            .expect("fake container runtime")
            .container
            .as_mut()
            .expect("gateway container")
            .labels
            .insert(POLICY_LABEL_KEY.into(), "replaced-policy".into());
        write_registry_snapshot(&registry_root, &record).expect("gateway registry record");
        write_registry_snapshot(&registry_root, &absent_sibling)
            .expect("sibling gateway registry record");
        fs::write(
            registry_root.join("unrecognized-record"),
            b"not a registry record",
        )
        .expect("malformed retained record");
        let registry =
            ManagedNetworkRegistry::with_runtime(&registry_root, &artifacts, Arc::new(runtime))
                .expect("registry");

        let summary = registry.stop_verified_compatibility_gateways(now);

        assert_eq!(summary.exact_gateways_found, 2);
        assert_eq!(summary.exact_gateways_stopped, 0);
        assert_eq!(summary.exact_stop_failures, 1);
        assert_eq!(summary.retained_ambiguities, 2);
        let state = state.lock().expect("fake container runtime");
        assert!(!state.container.as_ref().is_some_and(|item| item.removed));
        assert!(!state.calls.iter().any(|call| {
            call.get(0..3) == Some(&["container".into(), "rm".into(), "--force".into()])
        }));
        assert!(
            state
                .calls
                .iter()
                .any(|call| call.get(2) == Some(&"f".repeat(64)))
        );
        assert!(
            state
                .calls
                .iter()
                .any(|call| call.get(2) == Some(&"d".repeat(64)))
        );
        assert!(registry_root.join("unrecognized-record").exists());
    }

    #[test]
    fn uninstall_contact_stop_reports_an_exact_runtime_stop_failure() {
        let (_temporary, _gateway, artifacts, _policies, registry_root) = recovery_paths();
        let (runtime, state) = FakeContainerRuntime::new();
        let now = Utc::now();
        let record = compatibility_gateway_record(
            now,
            &"b".repeat(32),
            RuntimeProvider::Docker,
            RegistryPhase::ContainerReady,
            Some("c".repeat(64)),
        );
        install_fake_gateway(&state, &record);
        state
            .lock()
            .expect("fake container runtime")
            .container_stop_failures_remaining = 1;
        write_registry_snapshot(&registry_root, &record).expect("gateway registry record");
        let registry =
            ManagedNetworkRegistry::with_runtime(&registry_root, &artifacts, Arc::new(runtime))
                .expect("registry");

        let summary = registry.stop_verified_compatibility_gateways(now);

        assert_eq!(summary.exact_gateways_found, 1);
        assert_eq!(summary.exact_gateways_stopped, 0);
        assert_eq!(summary.exact_stop_failures, 1);
        assert_eq!(summary.retained_ambiguities, 0);
        assert!(
            !state
                .lock()
                .expect("fake container runtime")
                .container
                .as_ref()
                .is_some_and(|item| item.removed)
        );
    }

    #[test]
    fn managed_local_rejects_the_native_direct_gateway_backend() {
        let (_temporary, gateway, policies) = test_paths();
        let registry = test_registry(&policies);
        let (runtime, _state) = FakeRuntime::new(FakeInspectKind::Podman);
        let process_state = Arc::new(Mutex::new(FakeProcessState::default()));
        let observed = Arc::new(Mutex::new(Vec::new()));
        let error = ManagedNetworkController::with_components(
            RuntimeProvider::ManagedLocal,
            &gateway,
            &policies,
            &registry,
            Arc::new(runtime),
            Arc::new(FakeLauncher {
                state: process_state,
            }),
            Arc::new(FakeReadiness {
                fail: false,
                observed,
            }),
        )
        .err()
        .expect("managed local direct backend must be rejected");
        assert!(error.to_string().contains("gateway-container backend"));
    }

    #[test]
    fn managed_local_maps_the_rootless_machine_user_to_the_container_identity() {
        assert_eq!(
            gateway_container_user_for_ids(RuntimeProvider::ManagedLocal, 65_532, 65_532)
                .expect("managed user mapping"),
            (
                "65532:65532".into(),
                Some("keep-id:uid=65532,gid=65532".into())
            )
        );
        assert!(gateway_container_user_for_ids(RuntimeProvider::ManagedLocal, 0, 0).is_err());
    }

    #[test]
    fn managed_local_container_backend_uses_exact_dual_network_argv_and_cleanup_order() {
        let (_temporary, _gateway, policies) = test_paths();
        let registry = test_registry(&policies);
        let (runtime, state) = FakeContainerRuntime::new();
        let controller = ManagedNetworkController::with_container_components(
            RuntimeProvider::ManagedLocal,
            gateway_container_spec(),
            &policies,
            &registry,
            Arc::new(runtime),
            Arc::new(FakeContainerReadiness { fail: false }),
        )
        .expect("container controller");
        let now = Utc::now();
        let mut lease = controller
            .provision(&owner(), &[plan(now, "203.0.113.8", 5, 2, 30)], now)
            .expect("dual-network gateway");
        let identity = lease.durable_identity().expect("durable identity");
        assert_eq!(
            lease.network_policy().gateway_endpoint(),
            Some(
                format!(
                    "socks5h://{}:1080",
                    identity.gateway_listener_ip.expect("listener")
                )
                .as_str()
            )
        );
        assert_eq!(
            identity
                .gateway_container_id
                .as_deref()
                .expect("container id"),
            "c".repeat(64)
        );
        assert_eq!(identity.network_id, "a".repeat(64));
        assert_eq!(
            identity.uplink_network_id.as_deref().expect("uplink id"),
            "b".repeat(64)
        );

        let status_path = lease
            .gateway_status_directory
            .as_ref()
            .expect("status directory")
            .path
            .clone();
        let policy_path = lease.policy_path().expect("policy path").to_owned();
        {
            let state = state.lock().expect("fake container runtime");
            assert_eq!(state.pull_timeout, Some(GATEWAY_IMAGE_PULL_TIMEOUT));
            let internal_name = identity.network_name.clone();
            let uplink_name = identity.uplink_network_name.clone().expect("uplink name");
            let container_name = identity
                .gateway_container_name
                .clone()
                .expect("container name");
            assert!(state.calls.iter().any(|call| {
                call == &vec![
                    "network".to_owned(),
                    "connect".to_owned(),
                    "--ip".to_owned(),
                    identity
                        .gateway_listener_ip
                        .expect("gateway listener")
                        .to_string(),
                    internal_name.clone(),
                    container_name.clone(),
                ]
            }));
            let create = state
                .calls
                .iter()
                .find(|call| call.get(0..2) == Some(&["container".into(), "create".into()]))
                .expect("container create argv");
            for required in [
                "--pull=never",
                "--read-only",
                "--cap-drop=ALL",
                "--security-opt=no-new-privileges:true",
                "--restart=no",
                "--log-driver=none",
                "--userns=keep-id:uid=1000,gid=1000",
                CONTAINER_POLICY_PATH,
                "/run/ai-security-scanner/status/status.json",
            ] {
                if required.starts_with("--userns")
                    && !create
                        .iter()
                        .any(|value| value.starts_with("--userns=keep-id:"))
                {
                    panic!("container create omitted rootless keep-id mapping");
                }
                if !required.starts_with("--userns") {
                    assert!(
                        create.iter().any(|value| value == required),
                        "missing {required}"
                    );
                }
            }
            assert!(
                create
                    .windows(2)
                    .any(|pair| pair == ["--network", uplink_name.as_str()])
            );
            let mounts = create
                .windows(2)
                .filter(|pair| pair[0] == "--mount")
                .map(|pair| pair[1].as_str())
                .collect::<Vec<_>>();
            assert_eq!(mounts.len(), 2);
            assert!(mounts[0].starts_with(&format!("type=bind,src={}", policy_path.display())));
            assert!(mounts[0].ends_with(&format!("dst={CONTAINER_POLICY_PATH},readonly")));
            assert!(mounts[1].starts_with(&format!("type=bind,src={}", status_path.display())));
            assert!(mounts[1].ends_with("dst=/run/ai-security-scanner/status"));
        }

        state
            .lock()
            .expect("fake container runtime")
            .container
            .as_mut()
            .expect("gateway container")
            .running = false;
        lease.cleanup().expect("exact cleanup");
        assert!(!policy_path.exists());
        assert!(!status_path.exists());
        let state = state.lock().expect("fake container runtime");
        let remove_container = state
            .calls
            .iter()
            .position(|call| {
                call.get(0..3) == Some(&["container".into(), "rm".into(), "--force".into()])
            })
            .expect("container removal");
        let remove_networks = state
            .calls
            .iter()
            .enumerate()
            .filter(|(_, call)| call.get(0..2) == Some(&["network".into(), "rm".into()]))
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        assert_eq!(remove_networks.len(), 2);
        assert!(remove_container < remove_networks[0]);
        assert!(remove_networks[0] < remove_networks[1]);
        assert!(state.networks.values().all(|network| network.removed));
        assert!(
            state
                .container
                .as_ref()
                .is_some_and(|container| container.removed)
        );
    }

    #[test]
    fn container_network_creation_retries_distinct_explicit_internal_and_uplink_subnets() {
        let (_temporary, _gateway, policies) = test_paths();
        let registry = test_registry(&policies);
        let (runtime, state) = FakeContainerRuntime::new();
        {
            let mut state = state.lock().expect("fake container runtime");
            state.internal_conflicts_remaining = 1;
            state.uplink_conflicts_remaining = 1;
        }
        let controller = ManagedNetworkController::with_container_components(
            RuntimeProvider::ManagedLocal,
            gateway_container_spec(),
            &policies,
            &registry,
            Arc::new(runtime),
            Arc::new(FakeContainerReadiness { fail: false }),
        )
        .expect("container controller");
        let now = Utc::now();
        let mut lease = controller
            .provision(&owner(), &[plan(now, "203.0.113.8", 5, 2, 30)], now)
            .expect("network conflict retries");
        {
            let state = state.lock().expect("fake container runtime");
            let creates = state
                .calls
                .iter()
                .filter(|call| call.get(0..2) == Some(&["network".into(), "create".into()]))
                .collect::<Vec<_>>();
            assert_eq!(creates.len(), 4);
            for internal in [true, false] {
                let role_creates = creates
                    .iter()
                    .filter(|call| call.iter().any(|argument| argument == "--internal") == internal)
                    .collect::<Vec<_>>();
                assert_eq!(role_creates.len(), 2);
                let subnets = role_creates
                    .iter()
                    .map(|call| {
                        call.windows(2)
                            .find(|pair| pair[0] == "--subnet")
                            .map(|pair| pair[1].clone())
                            .expect("explicit subnet")
                    })
                    .collect::<BTreeSet<_>>();
                assert_eq!(subnets.len(), 2, "retry must select a new explicit subnet");
            }
        }
        lease.cleanup().expect("retry cleanup");
    }

    #[test]
    fn container_network_creation_retries_a_docker_engine_29_subnet_conflict() {
        let (_temporary, _gateway, policies) = test_paths();
        let registry = test_registry(&policies);
        let (runtime, state) = FakeContainerRuntime::new();
        {
            let mut state = state.lock().expect("fake container runtime");
            state.internal_conflicts_remaining = 1;
            state.uplink_conflicts_remaining = 1;
            state.docker_engine_29_wording = true;
        }
        let controller = ManagedNetworkController::with_container_components(
            RuntimeProvider::ManagedLocal,
            gateway_container_spec(),
            &policies,
            &registry,
            Arc::new(runtime),
            Arc::new(FakeContainerReadiness { fail: false }),
        )
        .expect("container controller");
        let now = Utc::now();
        let mut lease = controller
            .provision(&owner(), &[plan(now, "203.0.113.8", 5, 2, 30)], now)
            .expect("network conflict retries");
        {
            let state = state.lock().expect("fake container runtime");
            let creates = state
                .calls
                .iter()
                .filter(|call| call.get(0..2) == Some(&["network".into(), "create".into()]))
                .collect::<Vec<_>>();
            assert_eq!(creates.len(), 4);
            for internal in [true, false] {
                let role_creates = creates
                    .iter()
                    .filter(|call| call.iter().any(|argument| argument == "--internal") == internal)
                    .collect::<Vec<_>>();
                assert_eq!(role_creates.len(), 2);
                let subnets = role_creates
                    .iter()
                    .map(|call| {
                        call.windows(2)
                            .find(|pair| pair[0] == "--subnet")
                            .map(|pair| pair[1].clone())
                            .expect("explicit subnet")
                    })
                    .collect::<BTreeSet<_>>();
                assert_eq!(subnets.len(), 2, "retry must select a new explicit subnet");
            }
        }
        lease.cleanup().expect("retry cleanup");
    }

    #[test]
    fn failed_uplink_creation_cleanup_treats_the_missing_uplink_as_absent_in_docker_engine_29_wording()
     {
        let (_temporary, _gateway, policies) = test_paths();
        let registry = test_registry(&policies);
        let (runtime, state) = FakeContainerRuntime::new();
        {
            let mut state = state.lock().expect("fake container runtime");
            state.docker_engine_29_wording = true;
            state.uplink_create_failures_remaining = 1;
        }
        let controller = ManagedNetworkController::with_container_components(
            RuntimeProvider::ManagedLocal,
            gateway_container_spec(),
            &policies,
            &registry,
            Arc::new(runtime),
            Arc::new(FakeContainerReadiness { fail: false }),
        )
        .expect("container controller");
        let now = Utc::now();
        let error = controller
            .provision(&owner(), &[plan(now, "203.0.113.8", 5, 2, 30)], now)
            .err()
            .expect("uplink creation must fail");
        let error = error.to_string();
        assert!(
            error.contains("managed private network creation"),
            "{error}"
        );
        assert!(error.contains("permission denied"), "{error}");
        {
            let state = state.lock().expect("fake container runtime");
            assert!(
                state
                    .networks
                    .values()
                    .any(|network| network.internal && network.removed)
            );
            assert!(state.networks.values().all(|network| network.internal));
        }
        assert!(fs::read_dir(&registry).expect("registry").next().is_none());
    }

    #[test]
    fn explicit_container_subnets_do_not_capture_a_frozen_default_podman_range_target() {
        let (_temporary, _gateway, policies) = test_paths();
        let registry = test_registry(&policies);
        let (runtime, state) = FakeContainerRuntime::new();
        let controller = ManagedNetworkController::with_container_components(
            RuntimeProvider::ManagedLocal,
            gateway_container_spec(),
            &policies,
            &registry,
            Arc::new(runtime),
            Arc::new(FakeContainerReadiness { fail: false }),
        )
        .expect("container controller");
        let now = Utc::now();
        let mut internal_plan = plan(now, "10.89.1.8", 5, 2, 30);
        internal_plan.allow_sensitive_networks = true;
        let mut lease = controller
            .provision(&owner(), &[internal_plan], now)
            .expect("private destination scan network");
        {
            let state = state.lock().expect("fake container runtime");
            let target = "10.89.1.8".parse::<IpAddr>().expect("target");
            assert!(state.networks.values().all(|network| {
                !network
                    .subnet
                    .parse::<IpNet>()
                    .expect("runtime subnet")
                    .contains(&target)
            }));
            assert!(
                state
                    .calls
                    .iter()
                    .filter(|call| { call.get(0..2) == Some(&["network".into(), "create".into()]) })
                    .all(|call| call.windows(2).any(|pair| pair[0] == "--subnet"))
            );
        }
        lease.cleanup().expect("private destination cleanup");
    }

    #[test]
    fn ipv6_frozen_destination_runs_through_a_proven_dual_stack_uplink() {
        let (_temporary, _gateway, policies) = test_paths();
        let registry = test_registry(&policies);
        let (runtime, state) = FakeContainerRuntime::new();
        let controller = ManagedNetworkController::with_container_components(
            RuntimeProvider::ManagedLocal,
            gateway_container_spec(),
            &policies,
            &registry,
            Arc::new(runtime),
            Arc::new(FakeContainerReadiness { fail: false }),
        )
        .expect("container controller");
        let now = Utc::now();
        let mut lease = controller
            .provision(&owner(), &[plan(now, "2001:db8::8", 5, 2, 30)], now)
            .expect("IPv6 destination");
        {
            let state = state.lock().expect("fake container runtime");
            let uplink = state
                .networks
                .values()
                .find(|network| !network.internal)
                .expect("gateway uplink");
            assert!(uplink.ipv6_subnet.is_some());
            assert!(uplink.ipv6_gateway.is_some());
            assert!(
                state
                    .container
                    .as_ref()
                    .is_some_and(|container| container.running)
            );
        }
        lease.cleanup().expect("IPv6 cleanup");
    }

    #[test]
    fn release_qualification_uses_same_image_internal_only_greeting_and_exact_cleanup() {
        let (_temporary, _gateway, policies) = test_paths();
        let registry = test_registry(&policies);
        let (runtime, state) = FakeContainerRuntime::new();
        let spec = gateway_container_spec();
        let controller = ManagedNetworkController::with_container_components(
            RuntimeProvider::ManagedLocal,
            spec.clone(),
            &policies,
            &registry,
            Arc::new(runtime),
            Arc::new(FakeContainerReadiness { fail: false }),
        )
        .expect("qualification controller");
        let result = controller
            .qualify_gateway_container(&owner(), "linux-x86_64-deb", Utc::now())
            .expect("gateway qualification");

        assert_eq!(result.image, spec.reference());
        assert_eq!(result.gateway_container_id, "c".repeat(64));
        assert_eq!(result.probe_container_id, "e".repeat(64));
        assert_eq!(result.internal_network_id, "a".repeat(64));
        assert_eq!(result.uplink_network_id, "b".repeat(64));
        assert_eq!(result.reachability_probe, "socks5_no_connect_greeting");
        assert!(result.gateway_reachable);
        assert!(!result.upstream_connect_attempted);
        assert_eq!(
            result.cleanup,
            ManagedGatewayQualificationCleanup {
                gateway_container_removed: true,
                probe_container_removed: true,
                internal_network_removed: true,
                uplink_network_removed: true,
                policy_file_removed: true,
                status_directory_removed: true,
                registry_record_removed: true,
            }
        );

        let state = state.lock().expect("fake container runtime");
        let network_creates = state
            .calls
            .iter()
            .filter(|call| call.get(0..2) == Some(&["network".into(), "create".into()]))
            .collect::<Vec<_>>();
        assert_eq!(network_creates.len(), 2);
        let internal_create = network_creates
            .iter()
            .find(|call| call.iter().any(|argument| argument == "--internal"))
            .expect("qualification internal network");
        assert_eq!(
            internal_create
                .windows(2)
                .filter(|pair| pair[0] == "--subnet")
                .count(),
            1
        );
        let uplink_create = network_creates
            .iter()
            .find(|call| !call.iter().any(|argument| argument == "--internal"))
            .expect("qualification uplink network");
        assert!(uplink_create.iter().any(|argument| argument == "--ipv6"));
        assert_eq!(
            uplink_create
                .windows(2)
                .filter(|pair| pair[0] == "--subnet")
                .count(),
            2
        );
        let listener = state
            .calls
            .iter()
            .find(|call| call.get(0..2) == Some(&["network".into(), "connect".into()]))
            .and_then(|call| call.get(3))
            .expect("gateway listener");
        let probe_create = state
            .calls
            .iter()
            .find(|call| {
                call.get(0..2) == Some(&["container".into(), "create".into()])
                    && call
                        .windows(2)
                        .any(|pair| pair == ["--entrypoint", CONTAINER_PROBE_BINARY])
            })
            .expect("probe create argv");
        assert!(
            probe_create
                .iter()
                .any(|argument| argument == &spec.reference())
        );
        assert!(!probe_create.iter().any(|argument| argument == "--mount"));
        assert_eq!(
            probe_create
                .windows(2)
                .filter(|pair| pair[0] == "--network")
                .count(),
            1
        );
        assert!(
            probe_create
                .windows(2)
                .any(|pair| pair[0] == "--gateway" && pair[1] == format!("{listener}:1080"))
        );
        assert!(state.calls.iter().any(|call| {
            call == &vec![
                "container".to_owned(),
                "start".to_owned(),
                "--attach".to_owned(),
                "e".repeat(64),
            ]
        }));
        assert!(
            state
                .container
                .as_ref()
                .is_some_and(|container| container.removed)
        );
        assert!(state.probe.as_ref().is_some_and(|probe| probe.removed));
        assert!(state.networks.values().all(|network| network.removed));
        assert!(fs::read_dir(&registry).expect("registry").next().is_none());
    }

    #[test]
    fn durable_registry_recovers_gateway_container_before_both_networks() {
        let (_temporary, _gateway, artifacts, policies, registry_root) = recovery_paths();
        let (runtime, state) = FakeContainerRuntime::new();
        let runtime = Arc::new(runtime);
        let controller = ManagedNetworkController::with_container_components(
            RuntimeProvider::ManagedLocal,
            gateway_container_spec(),
            &policies,
            &registry_root,
            runtime.clone(),
            Arc::new(FakeContainerReadiness { fail: false }),
        )
        .expect("container controller");
        let now = Utc::now();
        let lease = controller
            .provision(&owner(), &[plan(now, "203.0.113.8", 5, 2, 30)], now)
            .expect("dual-network gateway");
        let policy_path = lease.policy_path().expect("policy path").to_owned();
        let status_path = lease
            .gateway_status_directory
            .as_ref()
            .expect("status directory")
            .path
            .clone();
        state
            .lock()
            .expect("fake container runtime")
            .container
            .as_mut()
            .expect("gateway container")
            .running = false;
        std::mem::forget(lease);

        let registry = ManagedNetworkRegistry::with_runtime(&registry_root, &artifacts, runtime)
            .expect("durable registry");
        let summary = registry.reconcile_all(now).expect("durable recovery");
        assert_eq!(summary.reconciled, 1);
        assert_eq!(summary.incomplete, 0);
        assert!(!policy_path.exists());
        assert!(!status_path.exists());
        assert!(
            fs::read_dir(&registry_root)
                .expect("registry")
                .next()
                .is_none()
        );
        let state = state.lock().expect("fake container runtime");
        let container_remove = state
            .calls
            .iter()
            .position(|call| {
                call.get(0..3) == Some(&["container".into(), "rm".into(), "--force".into()])
            })
            .expect("gateway removal");
        let network_removes = state
            .calls
            .iter()
            .enumerate()
            .filter(|(_, call)| call.get(0..2) == Some(&["network".into(), "rm".into()]))
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        assert_eq!(network_removes.len(), 2);
        assert!(container_remove < network_removes[0]);
        assert!(network_removes[0] < network_removes[1]);
        assert!(
            state
                .container
                .as_ref()
                .is_some_and(|container| container.removed)
        );
        assert!(state.networks.values().all(|network| network.removed));
    }

    #[test]
    fn durable_registry_recovers_v015_ipv4_only_uplink() {
        let (_temporary, _gateway, artifacts, policies, registry_root) = recovery_paths();
        let (runtime, state) = FakeContainerRuntime::new();
        let runtime = Arc::new(runtime);
        let controller = ManagedNetworkController::with_container_components(
            RuntimeProvider::ManagedLocal,
            gateway_container_spec(),
            &policies,
            &registry_root,
            runtime.clone(),
            Arc::new(FakeContainerReadiness { fail: false }),
        )
        .expect("container controller");
        let now = Utc::now();
        let lease = controller
            .provision(&owner(), &[plan(now, "203.0.113.8", 5, 2, 30)], now)
            .expect("dual-network gateway");
        {
            let mut state = state.lock().expect("fake container runtime");
            let uplink = state
                .networks
                .values_mut()
                .find(|network| !network.internal)
                .expect("gateway uplink");
            // v0.1.5 created this exact labeled non-internal bridge without
            // enabling IPv6. Its durable record did not persist address-family
            // metadata, so upgrade cleanup must accept both that legacy shape
            // and the current dual-stack shape before removing by exact ID.
            uplink.ipv6_subnet = None;
            uplink.ipv6_gateway = None;
            state.container.as_mut().expect("gateway container").running = false;
        }
        std::mem::forget(lease);

        let registry = ManagedNetworkRegistry::with_runtime(&registry_root, &artifacts, runtime)
            .expect("durable registry");
        let summary = registry.reconcile_all(now).expect("legacy recovery");

        assert_eq!(summary.reconciled, 1);
        assert_eq!(summary.incomplete, 0);
        assert!(
            fs::read_dir(&registry_root)
                .expect("registry")
                .next()
                .is_none()
        );
        let state = state.lock().expect("fake container runtime");
        assert!(
            state
                .container
                .as_ref()
                .is_some_and(|container| container.removed)
        );
        assert!(state.networks.values().all(|network| network.removed));
    }

    #[test]
    fn gateway_container_readiness_failure_rolls_back_every_durable_resource() {
        let (_temporary, _gateway, policies) = test_paths();
        let registry = test_registry(&policies);
        let (runtime, state) = FakeContainerRuntime::new();
        let controller = ManagedNetworkController::with_container_components(
            RuntimeProvider::ManagedLocal,
            gateway_container_spec(),
            &policies,
            &registry,
            Arc::new(runtime),
            Arc::new(FakeContainerReadiness { fail: true }),
        )
        .expect("container controller");
        let now = Utc::now();
        let error = controller
            .provision(&owner(), &[plan(now, "203.0.113.8", 5, 2, 30)], now)
            .err()
            .expect("readiness must fail");
        assert!(
            error
                .to_string()
                .contains("fake container readiness failure")
        );
        assert!(fs::read_dir(&registry).expect("registry").next().is_none());
        assert_eq!(
            fs::read_dir(&policies).expect("policy directory").count(),
            1,
            "only the registry directory remains"
        );
        let state = state.lock().expect("fake container runtime");
        assert!(
            state
                .container
                .as_ref()
                .is_some_and(|container| container.removed)
        );
        assert!(state.networks.values().all(|network| network.removed));
    }

    #[test]
    fn gateway_status_contract_is_bounded_and_phase_code_strict() {
        let (_temporary, _gateway, policies) = test_paths();
        let policy_id = format!("egress-{}", "e".repeat(32));
        let status =
            create_gateway_status_directory(&policies, &policy_id).expect("status directory");
        fs::write(
            status.status_path(),
            br#"{"schema_version":"1.1.0","phase":"ready","code":"ready","refusals":{"rate":0,"destination":0,"unauthorized_client":0}}"#,
        )
        .expect("ready status");
        assert_eq!(
            read_gateway_status(&status).expect("read status"),
            Some(GatewayStatusDocument {
                schema_version: "1.1.0".into(),
                phase: GatewayStatusPhase::Ready,
                code: "ready".into(),
                refusals: Some(GatewayStatusRefusals {
                    rate: 0,
                    destination: 0,
                    unauthorized_client: 0,
                }),
            })
        );
        fs::write(
            status.status_path(),
            br#"{"schema_version":"1.1.0","phase":"stopped","code":"ready","refusals":{"rate":0,"destination":0,"unauthorized_client":0}}"#,
        )
        .expect("mismatched status");
        assert!(read_gateway_status(&status).is_err());
        fs::write(status.path.join("status.tmp"), b"bounded temporary").expect("status temporary");
        remove_gateway_status_directory(&status).expect("status cleanup");
        assert!(!status.path.exists());
    }

    #[test]
    fn gateway_status_atomic_replacement_with_a_new_length_is_read_from_the_open_file() {
        let (_temporary, _gateway, policies) = test_paths();
        let policy_id = format!("egress-{}", "7".repeat(32));
        let status =
            create_gateway_status_directory(&policies, &policy_id).expect("status directory");
        let status_path = status.status_path();
        fs::write(
            &status_path,
            br#"{"schema_version":"1.1.0","phase":"starting","code":"initializing","refusals":{"rate":0,"destination":0,"unauthorized_client":0}}"#,
        )
        .expect("starting status");
        let stale_length = fs::symlink_metadata(&status_path)
            .expect("stale status metadata")
            .len();
        let replacement = status.path.join("status.replacement");
        fs::write(
            &replacement,
            br#"{"schema_version":"1.1.0","phase":"ready","code":"ready","refusals":{"rate":0,"destination":0,"unauthorized_client":0}}"#,
        )
        .expect("ready replacement");
        fs::rename(&replacement, &status_path).expect("atomic status replacement");

        let mut options = OpenOptions::new();
        options.read(true);
        configure_no_follow_open(&mut options);
        let opened = options.open(&status_path).expect("replacement status");
        assert_ne!(
            stale_length,
            opened.metadata().expect("opened metadata").len(),
            "fixture must model a replacement between path stat and open"
        );
        assert_eq!(
            read_opened_gateway_status(opened).expect("opened replacement"),
            GatewayStatusDocument {
                schema_version: "1.1.0".into(),
                phase: GatewayStatusPhase::Ready,
                code: "ready".into(),
                refusals: Some(GatewayStatusRefusals {
                    rate: 0,
                    destination: 0,
                    unauthorized_client: 0,
                }),
            }
        );
        remove_gateway_status_directory(&status).expect("status cleanup");
    }

    #[test]
    fn readiness_surfaces_terminal_gateway_status_before_generic_stopped_state() {
        let (_temporary, _gateway, policies) = test_paths();
        let policy_id = format!("egress-{}", "8".repeat(32));
        let status =
            create_gateway_status_directory(&policies, &policy_id).expect("status directory");
        fs::write(
            status.status_path(),
            br#"{"schema_version":"1.1.0","phase":"failed","code":"listener_bind_failed","refusals":{"rate":0,"destination":0,"unauthorized_client":0}}"#,
        )
        .expect("terminal status");
        let (runtime, runtime_state) = FakeContainerRuntime::new();
        let container = GatewayContainerRuntimeIdentity {
            name: format!("ass-gateway-{}", "8".repeat(32)),
            id: Some("c".repeat(64)),
            policy_id: policy_id.clone(),
            listener_ip: "10.89.1.2".parse().expect("listener"),
            image: gateway_container_spec(),
            internal_network_name: format!("ass-egress-{}", "8".repeat(32)),
            uplink_network_name: format!("ass-uplink-{}", "8".repeat(32)),
            uplink_subnets: Some((
                "10.90.1.0/28".parse().expect("IPv4 uplink"),
                "fd55:aaaa:bbbb:cccc::/64".parse().expect("IPv6 uplink"),
            )),
        };
        runtime_state.lock().expect("fake runtime").container = Some(FakeGatewayContainer {
            id: "c".repeat(64),
            name: container.name.clone(),
            image: container.image.reference(),
            labels: expected_gateway_container_labels(&policy_id),
            uplink: container.uplink_network_name.clone(),
            internal: Some((
                container.internal_network_name.clone(),
                container.listener_ip.to_string(),
            )),
            running: false,
            removed: false,
        });

        let error = RuntimeGatewayContainerReadiness
            .wait_until_ready(
                &runtime,
                RuntimeProvider::ManagedLocal,
                &container,
                &status,
                &policy_id,
            )
            .expect_err("terminal status must fail readiness");
        assert!(error.to_string().contains("listener_bind_failed"));
        assert!(
            runtime_state.lock().expect("fake runtime").calls.is_empty(),
            "terminal status must win the fast-exit race before inspect"
        );
        remove_gateway_status_directory(&status).expect("status cleanup");
    }

    #[test]
    fn readiness_reads_the_pinned_gateway_status_schema() {
        let (_temporary, _gateway, policies) = test_paths();
        let policy_id = format!("egress-{}", "2".repeat(32));
        let status =
            create_gateway_status_directory(&policies, &policy_id).expect("status directory");
        fs::write(
            status.status_path(),
            br#"{"schema_version":"1.0.0","phase":"failed","code":"listener_bind_failed"}"#,
        )
        .expect("terminal status");
        let (runtime, runtime_state) = FakeContainerRuntime::new();
        let container = GatewayContainerRuntimeIdentity {
            name: format!("ass-gateway-{}", "2".repeat(32)),
            id: Some("c".repeat(64)),
            policy_id: policy_id.clone(),
            listener_ip: "10.89.1.2".parse().expect("listener"),
            image: gateway_container_spec(),
            internal_network_name: format!("ass-egress-{}", "2".repeat(32)),
            uplink_network_name: format!("ass-uplink-{}", "2".repeat(32)),
            uplink_subnets: Some((
                "10.90.1.0/28".parse().expect("IPv4 uplink"),
                "fd55:aaaa:bbbb:cccc::/64".parse().expect("IPv6 uplink"),
            )),
        };
        runtime_state.lock().expect("fake runtime").container = Some(FakeGatewayContainer {
            id: "c".repeat(64),
            name: container.name.clone(),
            image: container.image.reference(),
            labels: expected_gateway_container_labels(&policy_id),
            uplink: container.uplink_network_name.clone(),
            internal: Some((
                container.internal_network_name.clone(),
                container.listener_ip.to_string(),
            )),
            running: false,
            removed: false,
        });

        let error = RuntimeGatewayContainerReadiness
            .wait_until_ready(
                &runtime,
                RuntimeProvider::ManagedLocal,
                &container,
                &status,
                &policy_id,
            )
            .expect_err("terminal status must fail readiness");
        assert!(error.to_string().contains("listener_bind_failed"));
        assert!(
            runtime_state.lock().expect("fake runtime").calls.is_empty(),
            "terminal status must win the fast-exit race before inspect"
        );
        remove_gateway_status_directory(&status).expect("status cleanup");
    }

    #[test]
    fn docker_no_such_object_is_an_absent_container_result() {
        assert!(runtime_reports_container_absent(
            b"Error response from daemon: No such object: cccccccccccccccc"
        ));
    }

    #[test]
    fn docker_engine_29_reports_a_missing_network_by_its_exact_selector() {
        assert!(runtime_reports_network_absent(
            b"Error response from daemon: network ass-uplink-1 not found",
            "ass-uplink-1",
        ));
        let id = "d".repeat(64);
        let removal =
            format!("Error response from daemon: network {id} not found\nexit status 1\n");
        assert!(runtime_reports_network_absent(removal.as_bytes(), &id));
        assert!(!runtime_reports_network_absent(
            b"Error response from daemon: network ass-uplink-1 not found",
            "ass-uplink-2",
        ));
        assert!(!runtime_reports_network_absent(
            b"Error response from daemon: plugin \"weave\" not found",
            "ass-uplink-1",
        ));
        assert!(!runtime_reports_network_absent(
            b"Error response from daemon: network sandbox for container abc not found",
            "ass-uplink-1",
        ));
        assert!(runtime_reports_network_absent(
            b"Error: No such network: ass-uplink-1",
            "ass-uplink-1",
        ));
        assert!(runtime_reports_network_absent(
            b"network not found",
            "ass-uplink-1",
        ));
    }

    #[test]
    fn provision_writes_private_policy_and_cleanup_removes_exact_resources() {
        let (_temporary, gateway, policies) = test_paths();
        let (runtime, runtime_state) = FakeRuntime::new(FakeInspectKind::Docker);
        let process_state = Arc::new(Mutex::new(FakeProcessState::default()));
        let observed = Arc::new(Mutex::new(Vec::new()));
        let registry = test_registry(&policies);
        let controller = ManagedNetworkController::with_components(
            RuntimeProvider::Docker,
            &gateway,
            &policies,
            &registry,
            Arc::new(runtime),
            Arc::new(FakeLauncher {
                state: Arc::clone(&process_state),
            }),
            Arc::new(FakeReadiness {
                fail: false,
                observed: Arc::clone(&observed),
            }),
        )
        .expect("controller");
        let now = Utc::now();
        let mut lease = controller
            .provision(&owner(), &[plan(now, "203.0.113.8", 5, 2, 30)], now)
            .expect("managed network");

        let observed_address = observed.lock().expect("readiness")[0];
        assert_eq!(
            lease.network_policy().gateway_endpoint(),
            Some(gateway_endpoint(observed_address.ip()).as_str())
        );
        let policy_path = lease.policy_path().expect("policy path").to_owned();
        assert!(policy_path.is_absolute());
        let policy: EgressGatewayPolicy =
            serde_json::from_slice(&fs::read(&policy_path).expect("policy bytes"))
                .expect("policy JSON");
        assert_eq!(policy.schema_version, POLICY_SCHEMA_VERSION);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&policy_path)
                    .expect("policy metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o400
            );
        }
        {
            let state = process_state.lock().expect("process state");
            assert_eq!(state.spawn_binary.as_deref(), Some(gateway.as_path()));
            assert_eq!(state.spawn_policy.as_deref(), Some(policy_path.as_path()));
        }
        {
            let state = runtime_state.lock().expect("runtime state");
            let create = &state.calls[0].1;
            assert_eq!(
                &create[0..5],
                ["network", "create", "--driver", "bridge", "--internal"]
            );
            assert_eq!(
                create
                    .iter()
                    .filter(|argument| *argument == "--label")
                    .count(),
                2
            );
        }

        lease.cleanup().expect("cleanup");
        assert!(!lease.is_active());
        assert!(!policy_path.exists());
        {
            let state = runtime_state.lock().expect("runtime state");
            assert!(state.removed);
            let removal = state
                .calls
                .iter()
                .find(|(_, args)| {
                    args.first().map(String::as_str) == Some("network")
                        && args.get(1).map(String::as_str) == Some("rm")
                })
                .expect("network removal");
            assert_eq!(removal.1.get(2).map(String::as_str), Some("network-id-1"));
        }
        let process = process_state.lock().expect("process state");
        assert!(process.killed);
        assert!(process.waited);
    }

    #[test]
    fn podman_provision_uses_the_verified_private_gateway() {
        let (_temporary, gateway, policies) = test_paths();
        let (runtime, _runtime_state) = FakeRuntime::new(FakeInspectKind::Podman);
        let process_state = Arc::new(Mutex::new(FakeProcessState::default()));
        let observed = Arc::new(Mutex::new(Vec::new()));
        let registry = test_registry(&policies);
        let controller = ManagedNetworkController::with_components(
            RuntimeProvider::Podman,
            &gateway,
            &policies,
            &registry,
            Arc::new(runtime),
            Arc::new(FakeLauncher {
                state: process_state,
            }),
            Arc::new(FakeReadiness {
                fail: false,
                observed: Arc::clone(&observed),
            }),
        )
        .expect("controller");
        let now = Utc::now();
        let lease = controller
            .provision(&owner(), &[plan(now, "203.0.113.8", 5, 2, 30)], now)
            .expect("managed network");
        let observed_address = observed.lock().expect("readiness")[0];
        assert_eq!(
            lease.network_policy().gateway_endpoint(),
            Some(gateway_endpoint(observed_address.ip()).as_str())
        );
    }

    #[test]
    fn readiness_failure_rolls_back_process_network_and_policy() {
        let (_temporary, gateway, policies) = test_paths();
        let (runtime, runtime_state) = FakeRuntime::new(FakeInspectKind::Docker);
        let process_state = Arc::new(Mutex::new(FakeProcessState::default()));
        let registry = test_registry(&policies);
        let controller = ManagedNetworkController::with_components(
            RuntimeProvider::Docker,
            &gateway,
            &policies,
            &registry,
            Arc::new(runtime),
            Arc::new(FakeLauncher {
                state: Arc::clone(&process_state),
            }),
            Arc::new(FakeReadiness {
                fail: true,
                observed: Arc::new(Mutex::new(Vec::new())),
            }),
        )
        .expect("controller");
        let now = Utc::now();
        assert!(
            controller
                .provision(&owner(), &[plan(now, "203.0.113.8", 5, 2, 30)], now)
                .is_err()
        );
        assert!(runtime_state.lock().expect("runtime state").removed);
        assert!(
            fs::read_dir(&policies)
                .expect("policy directory")
                .all(|entry| entry.expect("policy entry").path().is_dir())
        );
        // The process was not installed into the lease until readiness succeeded. The
        // controller must still stop it on this failure path.
        let process = process_state.lock().expect("process state");
        assert!(process.killed);
        assert!(process.waited);
    }

    #[test]
    fn startup_reconciles_only_the_exact_durable_orphan_identity() {
        let (_temporary, gateway, artifacts, policies, registry_root) = recovery_paths();
        let (runtime, runtime_state) = FakeRuntime::new(FakeInspectKind::Docker);
        let runtime = Arc::new(runtime);
        let process_state = Arc::new(Mutex::new(FakeProcessState::default()));
        let controller = ManagedNetworkController::with_components(
            RuntimeProvider::Docker,
            &gateway,
            &policies,
            &registry_root,
            runtime.clone(),
            Arc::new(FakeLauncher {
                state: Arc::clone(&process_state),
            }),
            Arc::new(FakeReadiness {
                fail: false,
                observed: Arc::new(Mutex::new(Vec::new())),
            }),
        )
        .expect("controller");
        let now = Utc::now();
        let lease = controller
            .provision(&owner(), &[plan(now, "203.0.113.8", 5, 2, 30)], now)
            .expect("managed network");
        let policy_path = lease.policy_path().expect("policy path").to_owned();
        std::mem::forget(lease);

        let registry = ManagedNetworkRegistry::with_runtime(&registry_root, &artifacts, runtime)
            .expect("registry");
        let summary = registry
            .reconcile_all(now + ChronoDuration::seconds(1))
            .expect("reconciliation");

        assert_eq!(summary.reconciled, 1);
        assert_eq!(summary.incomplete, 0);
        assert!(runtime_state.lock().expect("runtime").removed);
        assert!(!policy_path.exists());
        assert!(
            fs::read_dir(&registry_root)
                .expect("registry")
                .next()
                .is_none()
        );
        // Startup does not kill a persisted numeric PID. The isolated network
        // is gone and the real sidecar independently exits at policy expiry.
        assert!(!process_state.lock().expect("process").killed);
    }

    /// What an abandoned gateway left where recovery looks for its status.
    enum AbandonedStatus {
        NoDirectory,
        NoDocument,
        Counted(u64, u64, u64),
        Legacy,
    }

    /// A lease the desktop never cleaned up, recovered from its durable
    /// identity the way a restarted desktop recovers it.
    fn recover_abandoned_lease(status: AbandonedStatus) -> (ManagedNetworkCleanupOutcome, bool) {
        let (_temporary, gateway, artifacts, policies, registry_root) = recovery_paths();
        let (runtime, _runtime_state) = FakeRuntime::new(FakeInspectKind::Docker);
        let runtime = Arc::new(runtime);
        let controller = ManagedNetworkController::with_components(
            RuntimeProvider::Docker,
            &gateway,
            &policies,
            &registry_root,
            runtime.clone(),
            Arc::new(FakeLauncher {
                state: Arc::new(Mutex::new(FakeProcessState::default())),
            }),
            Arc::new(FakeReadiness {
                fail: false,
                observed: Arc::new(Mutex::new(Vec::new())),
            }),
        )
        .expect("controller");
        let now = Utc::now();
        let lease = controller
            .provision(&owner(), &[plan(now, "203.0.113.8", 5, 2, 30)], now)
            .expect("managed network");
        let identity = lease.durable_identity().expect("durable identity");
        std::mem::forget(lease);
        // Container provisioning creates the status directory. The process
        // launcher used here does not, so it is created where recovery
        // derives it, as the container gateway would have left it.
        let status_path = policies.join(format!("gateway-status-{}", identity.policy_id));
        match status {
            AbandonedStatus::NoDirectory => {}
            AbandonedStatus::NoDocument => {
                create_gateway_status_directory(&policies, &identity.policy_id)
                    .expect("status directory");
            }
            AbandonedStatus::Counted(rate, destination, unauthorized_client) => {
                let directory = create_gateway_status_directory(&policies, &identity.policy_id)
                    .expect("status directory");
                write_refusal_status(
                    &directory,
                    "ready",
                    "ready",
                    rate,
                    destination,
                    unauthorized_client,
                );
            }
            AbandonedStatus::Legacy => {
                let directory = create_gateway_status_directory(&policies, &identity.policy_id)
                    .expect("status directory");
                fs::write(
                    directory.status_path(),
                    br#"{"schema_version":"1.0.0","phase":"ready","code":"ready"}"#,
                )
                .expect("pinned status");
            }
        }

        let registry = ManagedNetworkRegistry::with_runtime(&registry_root, &artifacts, runtime)
            .expect("registry");
        let outcome = registry
            .reconcile_identity(&owner(), &identity, now + ChronoDuration::seconds(1))
            .expect("recovery");
        (outcome, !status_path.exists())
    }

    #[test]
    fn recovery_reads_the_refusal_record_before_removing_it() {
        let (outcome, removed) = recover_abandoned_lease(AbandonedStatus::Counted(3, 1, 0));
        assert_eq!(
            outcome.gateway_refusals,
            Some(GatewayRefusalRecord::Counted {
                rate: 3,
                destination: 1,
                unauthorized_client: 0,
            })
        );
        assert!(removed, "recovery still removes the status document");
    }

    #[test]
    fn recovery_of_an_unwritten_status_records_it_as_unavailable() {
        // Not zero refusals: nothing was read, so nothing may be claimed.
        let (outcome, removed) = recover_abandoned_lease(AbandonedStatus::NoDocument);
        assert_eq!(
            outcome.gateway_refusals,
            Some(GatewayRefusalRecord::Unavailable)
        );
        assert!(removed);
    }

    #[test]
    fn recovery_without_a_status_directory_claims_no_record() {
        // The lease reads nothing when it was given no status directory, and
        // recovery matches it.
        let (outcome, _) = recover_abandoned_lease(AbandonedStatus::NoDirectory);
        assert_eq!(outcome.gateway_refusals, None);
    }

    #[test]
    fn recovery_of_a_gateway_that_records_no_refusals_claims_no_record() {
        let (outcome, removed) = recover_abandoned_lease(AbandonedStatus::Legacy);
        assert_eq!(outcome.gateway_refusals, None);
        assert!(removed);
    }

    #[test]
    fn startup_refuses_a_replaced_or_mislabeled_network_and_retains_recovery_records() {
        let (_temporary, gateway, artifacts, policies, registry_root) = recovery_paths();
        let (runtime, runtime_state) = FakeRuntime::new(FakeInspectKind::Docker);
        let runtime = Arc::new(runtime);
        let controller = ManagedNetworkController::with_components(
            RuntimeProvider::Docker,
            &gateway,
            &policies,
            &registry_root,
            runtime.clone(),
            Arc::new(FakeLauncher {
                state: Arc::new(Mutex::new(FakeProcessState::default())),
            }),
            Arc::new(FakeReadiness {
                fail: false,
                observed: Arc::new(Mutex::new(Vec::new())),
            }),
        )
        .expect("controller");
        let now = Utc::now();
        let lease = controller
            .provision(&owner(), &[plan(now, "203.0.113.8", 5, 2, 30)], now)
            .expect("managed network");
        std::mem::forget(lease);
        runtime_state
            .lock()
            .expect("runtime")
            .labels
            .insert(POLICY_LABEL_KEY.into(), "attacker-policy".into());

        let registry = ManagedNetworkRegistry::with_runtime(&registry_root, &artifacts, runtime)
            .expect("registry");
        let summary = registry.reconcile_all(now).expect("safe reconciliation");

        assert_eq!(summary.reconciled, 0);
        assert_eq!(summary.incomplete, 1);
        assert!(!runtime_state.lock().expect("runtime").removed);
        assert!(
            fs::read_dir(&registry_root)
                .expect("registry")
                .next()
                .is_some()
        );
    }

    #[test]
    fn intent_record_recovers_a_crash_between_network_create_and_id_checkpoint() {
        let (_temporary, _gateway, artifacts, _policies, registry_root) = recovery_paths();
        let (runtime, runtime_state) = FakeRuntime::new(FakeInspectKind::Docker);
        let runtime = Arc::new(runtime);
        let now = Utc::now();
        let unique = "a".repeat(32);
        let policy_id = format!("egress-{unique}");
        let network_name = format!("ass-egress-{unique}");
        let record = ManagedNetworkRecord {
            schema_version: REGISTRY_SCHEMA_VERSION.into(),
            owner: owner(),
            provider: RuntimeProvider::Docker,
            network_name: network_name.clone(),
            policy_id: policy_id.clone(),
            created_at: now,
            expires_at: now + ChronoDuration::hours(1),
            phase: RegistryPhase::Intent,
            network_id: None,
            uplink_network_name: None,
            uplink_network_id: None,
            gateway_container_name: None,
            gateway_container_id: None,
            gateway_listener_ip: None,
            gateway_image_repository: None,
            gateway_image_digest: None,
            policy_sha256: None,
        };
        write_registry_snapshot(&registry_root, &record).expect("intent record");
        {
            let mut state = runtime_state.lock().expect("runtime");
            state.network_name = Some(network_name);
            state.labels = expected_labels(&policy_id);
            state.subnet = Some("172.29.0.0/24".into());
            state.gateway = Some("172.29.0.1".into());
            state.removed = false;
        }
        let registry = ManagedNetworkRegistry::with_runtime(&registry_root, &artifacts, runtime)
            .expect("registry");
        let summary = registry.reconcile_all(now).expect("reconciliation");

        assert_eq!(summary.reconciled, 1);
        assert!(runtime_state.lock().expect("runtime").removed);
        assert!(
            fs::read_dir(&registry_root)
                .expect("registry")
                .next()
                .is_none()
        );
    }

    #[test]
    fn startup_reconciles_a_never_created_uplink_in_docker_engine_29_wording() {
        let (_temporary, _gateway, artifacts, _policies, registry_root) = recovery_paths();
        let (runtime, state) = FakeContainerRuntime::new();
        state
            .lock()
            .expect("fake container runtime")
            .docker_engine_29_wording = true;
        let runtime = Arc::new(runtime);
        let now = Utc::now();
        let unique = "c".repeat(32);
        let spec = gateway_container_spec();
        let mut record = ManagedNetworkRecord {
            schema_version: REGISTRY_SCHEMA_VERSION.into(),
            owner: owner(),
            provider: RuntimeProvider::ManagedLocal,
            network_name: format!("ass-egress-{unique}"),
            policy_id: format!("egress-{unique}"),
            created_at: now,
            expires_at: now + ChronoDuration::hours(1),
            phase: RegistryPhase::Intent,
            network_id: None,
            uplink_network_name: Some(format!("ass-uplink-{unique}")),
            uplink_network_id: None,
            gateway_container_name: Some(format!("ass-gateway-{unique}")),
            gateway_container_id: None,
            gateway_listener_ip: None,
            gateway_image_repository: Some(spec.repository().into()),
            gateway_image_digest: Some(spec.digest().into()),
            policy_sha256: None,
        };
        write_registry_snapshot(&registry_root, &record).expect("intent record");
        record.phase = RegistryPhase::NetworkVerified;
        record.network_id = Some("a".repeat(64));
        write_registry_snapshot(&registry_root, &record).expect("network record");

        let registry = ManagedNetworkRegistry::with_runtime(&registry_root, &artifacts, runtime)
            .expect("registry");
        let summary = registry.reconcile_all(now).expect("reconciliation");

        assert_eq!(summary.reconciled, 1);
        assert_eq!(summary.incomplete, 0);
        assert!(
            fs::read_dir(&registry_root)
                .expect("registry")
                .next()
                .is_none()
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlink_gateway_binary_is_rejected() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let temporary = tempfile::tempdir().expect("temporary directory");
        let target = temporary.path().join("gateway-real");
        fs::write(&target, b"fake executable").expect("target");
        fs::set_permissions(&target, fs::Permissions::from_mode(0o700)).expect("mode");
        let link = temporary.path().join("ai-security-scanner-egress-gateway");
        symlink(&target, &link).expect("symlink");
        assert!(
            ManagedNetworkController::new(RuntimeProvider::Docker, &link, temporary.path())
                .is_err()
        );
    }

    #[test]
    fn static_gateway_inspection_rejects_a_missing_sidecar_without_creating_it() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let missing = temporary.path().join("ai-security-scanner-egress-gateway");

        let error = inspect_gateway_binary(&missing).expect_err("missing sidecar rejected");

        assert!(error.to_string().contains("could not be inspected"));
        assert!(!missing.exists(), "inspection must not create the sidecar");
        assert!(
            fs::read_dir(temporary.path())
                .expect("temporary directory")
                .next()
                .is_none(),
            "inspection must not create support files"
        );
    }

    #[test]
    fn installed_gateway_is_resolved_from_the_canonical_desktop_directory() {
        let temporary = tempfile::tempdir().expect("temporary install directory");
        let install = temporary.path().join("installed app");
        fs::create_dir(&install).expect("installed app directory");
        let desktop = install.join(if cfg!(windows) {
            "ai-security-scanner.exe"
        } else {
            "ai-security-scanner"
        });
        let gateway = install.join(if cfg!(windows) {
            "ai-security-scanner-egress-gateway.exe"
        } else {
            "ai-security-scanner-egress-gateway"
        });
        fs::write(&desktop, b"desktop fixture").expect("desktop fixture");
        fs::write(&gateway, b"gateway fixture").expect("gateway fixture");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&gateway, fs::Permissions::from_mode(0o700))
                .expect("gateway executable mode");
        }

        let located =
            inspect_installed_gateway_binary(&desktop).expect("installed gateway beside desktop");

        assert_eq!(located, fs::canonicalize(gateway).unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn static_gateway_inspection_never_makes_a_sidecar_executable() {
        use std::os::unix::fs::PermissionsExt;
        let temporary = tempfile::tempdir().expect("temporary directory");
        let gateway = temporary.path().join("ai-security-scanner-egress-gateway");
        fs::write(&gateway, b"not executable").expect("gateway fixture");
        fs::set_permissions(&gateway, fs::Permissions::from_mode(0o600)).expect("gateway mode");

        let error = inspect_gateway_binary(&gateway).expect_err("non-executable sidecar rejected");

        assert!(error.to_string().contains("not executable"));
        assert_eq!(
            fs::metadata(&gateway)
                .expect("gateway metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600,
            "inspection must not chmod the sidecar"
        );
    }

    fn open_gateway_status_file(path: &Path) -> fs::File {
        let mut options = OpenOptions::new();
        options.read(true);
        configure_no_follow_open(&mut options);
        options.open(path).expect("status file")
    }

    fn lease_for_status_cleanup(status: GatewayStatusDirectory) -> ManagedNetworkLease {
        ManagedNetworkLease {
            provider: RuntimeProvider::Docker,
            runtime: Arc::new(DirectRuntimeCommands),
            network_name: None,
            network_id: None,
            remove_unverified_network: false,
            expected_labels: BTreeMap::new(),
            uplink_network_name: None,
            uplink_network_id: None,
            uplink_expected_labels: BTreeMap::new(),
            gateway_process: None,
            gateway_container: None,
            gateway_status_directory: Some(status),
            policy_file: None,
            network_policy: None,
            egress_policy: None,
            registry_files: Vec::new(),
        }
    }

    fn write_refusal_status(
        status: &GatewayStatusDirectory,
        phase: &str,
        code: &str,
        rate: u64,
        destination: u64,
        unauthorized_client: u64,
    ) {
        fs::write(
            status.status_path(),
            format!(
                r#"{{"schema_version":"1.1.0","phase":"{phase}","code":"{code}","refusals":{{"rate":{rate},"destination":{destination},"unauthorized_client":{unauthorized_client}}}}}"#
            ),
        )
        .expect("status document");
    }

    #[test]
    fn opened_gateway_status_accepts_refusal_counts_and_rejects_them_under_schema_1_0_0() {
        let (_temporary, _gateway, policies) = test_paths();
        let policy_id = format!("egress-{}", "b".repeat(32));
        let status =
            create_gateway_status_directory(&policies, &policy_id).expect("status directory");
        write_refusal_status(&status, "ready", "ready", 4, 5, 6);
        assert_eq!(
            read_opened_gateway_status(open_gateway_status_file(&status.status_path()))
                .expect("1.1.0 status"),
            GatewayStatusDocument {
                schema_version: "1.1.0".into(),
                phase: GatewayStatusPhase::Ready,
                code: "ready".into(),
                refusals: Some(GatewayStatusRefusals {
                    rate: 4,
                    destination: 5,
                    unauthorized_client: 6,
                }),
            }
        );
        fs::write(
            status.status_path(),
            br#"{"schema_version":"1.0.0","phase":"ready","code":"ready","refusals":{"rate":4,"destination":5,"unauthorized_client":6}}"#,
        )
        .expect("legacy status");
        let error = read_opened_gateway_status(open_gateway_status_file(&status.status_path()))
            .expect_err("1.0.0 never carries refusal counts");
        assert!(error.to_string().contains("gateway status was malformed"));
        remove_gateway_status_directory(&status).expect("status cleanup");
    }

    #[test]
    fn the_pinned_gateway_image_status_is_read_without_refusal_counts() {
        let (_temporary, _gateway, policies) = test_paths();
        let policy_id = format!("egress-{}", "0".repeat(32));
        let status =
            create_gateway_status_directory(&policies, &policy_id).expect("status directory");
        // The exact bytes the gateway image pinned in
        // runtime/managed-egress-gateway.json writes.
        fs::write(
            status.status_path(),
            br#"{"schema_version":"1.0.0","phase":"ready","code":"ready"}"#,
        )
        .expect("pinned status");
        assert_eq!(
            read_gateway_status(&status).expect("pinned status"),
            Some(GatewayStatusDocument {
                schema_version: "1.0.0".into(),
                phase: GatewayStatusPhase::Ready,
                code: "ready".into(),
                refusals: None,
            })
        );
        assert_eq!(gateway_refusal_record(read_gateway_status(&status)), None);
        remove_gateway_status_directory(&status).expect("status cleanup");
    }

    #[test]
    fn gateway_status_accepts_exactly_the_two_recognized_schemas() {
        let (_temporary, _gateway, policies) = test_paths();
        let policy_id = format!("egress-{}", "1".repeat(32));
        let status =
            create_gateway_status_directory(&policies, &policy_id).expect("status directory");
        let accepted = [
            (
                &br#"{"schema_version":"1.0.0","phase":"ready","code":"ready"}"#[..],
                GatewayStatusDocument {
                    schema_version: "1.0.0".into(),
                    phase: GatewayStatusPhase::Ready,
                    code: "ready".into(),
                    refusals: None,
                },
            ),
            (
                &br#"{"schema_version":"1.0.0","phase":"stopped","code":"policy_expired"}"#[..],
                GatewayStatusDocument {
                    schema_version: "1.0.0".into(),
                    phase: GatewayStatusPhase::Stopped,
                    code: "policy_expired".into(),
                    refusals: None,
                },
            ),
            (
                &br#"{"schema_version":"1.1.0","phase":"ready","code":"ready","refusals":{"rate":0,"destination":0,"unauthorized_client":0}}"#[..],
                GatewayStatusDocument {
                    schema_version: "1.1.0".into(),
                    phase: GatewayStatusPhase::Ready,
                    code: "ready".into(),
                    refusals: Some(GatewayStatusRefusals {
                        rate: 0,
                        destination: 0,
                        unauthorized_client: 0,
                    }),
                },
            ),
            (
                &br#"{"schema_version":"1.1.0","phase":"stopped","code":"stopped","refusals":{"rate":0,"destination":0,"unauthorized_client":0}}"#[..],
                GatewayStatusDocument {
                    schema_version: "1.1.0".into(),
                    phase: GatewayStatusPhase::Stopped,
                    code: "stopped".into(),
                    refusals: Some(GatewayStatusRefusals {
                        rate: 0,
                        destination: 0,
                        unauthorized_client: 0,
                    }),
                },
            ),
        ];
        for (bytes, expected) in accepted {
            fs::write(status.status_path(), bytes).expect("status document");
            assert_eq!(
                read_opened_gateway_status(open_gateway_status_file(&status.status_path()))
                    .expect("recognized schema"),
                expected
            );
        }

        let rejected = [
            (
                &br#"{"schema_version":"1.0.0","phase":"ready","code":"ready","refusals":{"rate":0,"destination":0,"unauthorized_client":0}}"#[..],
                "gateway status was malformed",
            ),
            (
                &br#"{"schema_version":"1.0.0","phase":"ready","code":"ready","refusals":null}"#[..],
                "gateway status was malformed",
            ),
            (
                &br#"{"schema_version":"1.1.0","phase":"ready","code":"ready"}"#[..],
                "gateway status was malformed",
            ),
            (
                &br#"{"schema_version":"1.1.0","phase":"ready","code":"ready","refusals":null}"#[..],
                "gateway status was malformed",
            ),
            (
                &br#"{"schema_version":"1.0.0","phase":"stopped","code":"stopped"}"#[..],
                "gateway status used an unsupported phase/code pair",
            ),
            (
                &br#"{"schema_version":"1.2.0","phase":"ready","code":"ready","refusals":{"rate":0,"destination":0,"unauthorized_client":0}}"#[..],
                "gateway status schema is unsupported",
            ),
            (
                &br#"{"schema_version":"2.0.0","phase":"ready","code":"ready","refusals":{"rate":0,"destination":0,"unauthorized_client":0}}"#[..],
                "gateway status schema is unsupported",
            ),
        ];
        for (bytes, expected_error) in rejected {
            fs::write(status.status_path(), bytes).expect("status document");
            let error = read_opened_gateway_status(open_gateway_status_file(&status.status_path()))
                .expect_err("rejected schema");
            assert!(
                error.to_string().contains(expected_error),
                "expected {expected_error:?}, got {error}"
            );
        }
        remove_gateway_status_directory(&status).expect("status cleanup");
    }

    #[test]
    fn stopped_status_code_is_an_accepted_terminal_pair() {
        let (_temporary, _gateway, policies) = test_paths();
        let policy_id = format!("egress-{}", "c".repeat(32));
        let status =
            create_gateway_status_directory(&policies, &policy_id).expect("status directory");
        for code in ["stopped", "policy_expired"] {
            write_refusal_status(&status, "stopped", code, 0, 0, 0);
            assert_eq!(
                read_opened_gateway_status(open_gateway_status_file(&status.status_path()))
                    .expect("stopped pair")
                    .code,
                code
            );
        }
        remove_gateway_status_directory(&status).expect("status cleanup");
    }

    #[test]
    fn cleanup_records_gateway_refusal_counts_or_their_absence() {
        let (_temporary, _gateway, policies) = test_paths();
        let counted =
            create_gateway_status_directory(&policies, &format!("egress-{}", "d".repeat(32)))
                .expect("counted status");
        write_refusal_status(&counted, "stopped", "stopped", 2, 3, 4);
        let counted_path = counted.path.clone();
        let mut counted_lease = lease_for_status_cleanup(counted);
        let counted_outcome = counted_lease
            .cleanup_with_outcome()
            .expect("counted cleanup");
        assert_eq!(
            counted_outcome.detail,
            "gateway refused connections: rate 2, destination 3, unauthorized client 4; bounded gateway status removed or already absent; durable recovery records removed"
        );
        assert_eq!(
            counted_outcome.gateway_refusals,
            Some(GatewayRefusalRecord::Counted {
                rate: 2,
                destination: 3,
                unauthorized_client: 4,
            })
        );
        assert!(!counted_path.exists());

        let quiet =
            create_gateway_status_directory(&policies, &format!("egress-{}", "e".repeat(32)))
                .expect("quiet status");
        write_refusal_status(&quiet, "stopped", "stopped", 0, 0, 0);
        let mut quiet_lease = lease_for_status_cleanup(quiet);
        let quiet_outcome = quiet_lease.cleanup_with_outcome().expect("quiet cleanup");
        assert_eq!(
            quiet_outcome.detail,
            "gateway refused no connections; bounded gateway status removed or already absent; durable recovery records removed"
        );
        assert_eq!(
            quiet_outcome.gateway_refusals,
            Some(GatewayRefusalRecord::Counted {
                rate: 0,
                destination: 0,
                unauthorized_client: 0,
            })
        );

        let missing =
            create_gateway_status_directory(&policies, &format!("egress-{}", "f".repeat(32)))
                .expect("missing status");
        let mut missing_lease = lease_for_status_cleanup(missing);
        let missing_outcome = missing_lease
            .cleanup_with_outcome()
            .expect("missing cleanup");
        assert_eq!(
            missing_outcome.detail,
            "gateway refusal record was unavailable; bounded gateway status removed or already absent; durable recovery records removed"
        );
        assert_eq!(
            missing_outcome.gateway_refusals,
            Some(GatewayRefusalRecord::Unavailable)
        );

        let malformed =
            create_gateway_status_directory(&policies, &format!("egress-{}", "9".repeat(32)))
                .expect("malformed status");
        fs::write(malformed.status_path(), b"{").expect("malformed document");
        let mut malformed_lease = lease_for_status_cleanup(malformed);
        let malformed_outcome = malformed_lease
            .cleanup_with_outcome()
            .expect("malformed cleanup stays successful");
        assert_eq!(
            malformed_outcome.detail,
            "gateway refusal record was unavailable; bounded gateway status removed or already absent; durable recovery records removed"
        );
        assert_eq!(
            malformed_outcome.gateway_refusals,
            Some(GatewayRefusalRecord::Unavailable)
        );

        let uncounted =
            create_gateway_status_directory(&policies, &format!("egress-{}", "a".repeat(32)))
                .expect("uncounted status");
        fs::write(
            uncounted.status_path(),
            br#"{"schema_version":"1.0.0","phase":"ready","code":"ready"}"#,
        )
        .expect("pinned status");
        let mut uncounted_lease = lease_for_status_cleanup(uncounted);
        let uncounted_outcome = uncounted_lease
            .cleanup_with_outcome()
            .expect("uncounted cleanup");
        assert_eq!(
            uncounted_outcome.detail,
            "this gateway does not record refused connections; bounded gateway status removed or already absent; durable recovery records removed"
        );
        assert_eq!(uncounted_outcome.gateway_refusals, None);
    }
}
