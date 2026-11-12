//! Product-level uninstall coordination for the installed Windows package.
//!
//! This module deliberately does not open the case database or engine catalog.
//! The uninstaller must still be able to stop exact product runtimes when the
//! database is corrupt, and no user-data cleanup may begin until target contact
//! has stopped. Ambiguous runtime state is retained and reported; it is never
//! promoted to deletion authority by a name match.

use crate::error::{AppError, AppResult};
use crate::managed_network::ManagedNetworkRegistry;
use crate::managed_runtime::{
    ManagedRuntimeManager, ManagedStopMode, ManagedUninstallOptions,
    PrivateProductDataDirectoryGuard, ensure_private_product_data_directory,
};
use crate::process_lease::DataDirectoryExclusiveLease;
use chrono::Utc;
#[cfg(windows)]
use serde::Deserialize;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
#[cfg(windows)]
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
#[cfg(windows)]
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub const ALL_DATA_CONFIRMATION: &str = "REMOVE ALL AI-SECURITY-SCANNER DATA";
pub const PRODUCT_DATA_DIRECTORY_NAME: &str = crate::managed_runtime::PRODUCT_DATA_DIRECTORY_NAME;
pub const PRODUCT_UNINSTALL_COMPLETED_EXIT_CODE: u8 = 0;
pub const PRODUCT_UNINSTALL_RETAINED_EXIT_CODE: u8 = 10;
pub const PRODUCT_UNINSTALL_CONTACT_NOT_STOPPED_EXIT_CODE: u8 = 20;

const MANAGED_RUNTIME_DIRECTORY: &str = "managed-runtime";
const MANAGED_RUNTIME_VERSIONS_DIRECTORY: &str = "versions";
const MANAGED_RUNTIME_PROVIDER_DIRECTORY: &str = "provider-home";
const MANAGED_RUNTIME_LIFECYCLE_LOCK: &str = "lifecycle.lock";
const DATA_DIRECTORY_LEASE_FILE: &str = ".exclusive-process.lock";
#[cfg(windows)]
const ALL_DATA_STAGE_JOURNAL_FILE: &str =
    ".dev.teddashh.ai-security-scanner.uninstall-stage-journal-v1.json";
#[cfg(windows)]
const ALL_DATA_STAGE_JOURNAL_TEMP_PREFIX: &str = ".uninstall-stage-journal-v1-tmp-";
#[cfg(windows)]
const ALL_DATA_STAGE_DELETE_AUTHORIZED_RECORD: &[u8] = b"delete_authorized_v1\n";
#[cfg(windows)]
const ALL_DATA_STAGE_PREFIX: &str = ".dev.teddashh.ai-security-scanner.uninstall-staged-";
#[cfg(windows)]
const ALL_DATA_STAGE_JOURNAL_SCHEMA_VERSION: u32 = 1;
#[cfg(windows)]
const MAX_ALL_DATA_STAGE_JOURNAL_BYTES: u64 = 4 * 1024;
#[cfg(windows)]
const MAX_ALL_DATA_STAGE_PARENT_ENTRIES: usize = 4096;
#[cfg(windows)]
const MAX_ALL_DATA_STAGE_CANDIDATES: usize = 16;
#[cfg(windows)]
const ALL_DATA_STAGE_DISCOVERY_TIMEOUT: Duration = Duration::from_secs(2);
const MANAGED_RUNTIME_MANIFEST: &str = "manifest.json";
const ARTIFACT_DIRECTORY: &str = "artifacts";
const MANAGED_NETWORK_REGISTRY_DIRECTORY: &str = ".managed-egress-registry";
const MAX_INSTALLED_RUNTIME_ENTRIES: usize = 32;
const MAX_RUNTIME_MANIFEST_BYTES: u64 = 1024 * 1024;
const MAX_PRODUCT_DATA_ENTRIES: usize = 200_000;
const MAX_PRODUCT_DATA_DEPTH: usize = 64;
const MAX_RETAINED_ITEMS: usize = 128;
const PRODUCT_DATA_CLEANUP_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProductUninstallMode {
    AppOnly,
    ScanTools,
    AllData,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProductUninstallResultClass {
    Completed,
    CompletedWithRetainedState,
    ContactNotStopped,
}

impl ProductUninstallResultClass {
    pub fn exit_code(self) -> u8 {
        match self {
            Self::Completed => PRODUCT_UNINSTALL_COMPLETED_EXIT_CODE,
            Self::CompletedWithRetainedState => PRODUCT_UNINSTALL_RETAINED_EXIT_CODE,
            Self::ContactNotStopped => PRODUCT_UNINSTALL_CONTACT_NOT_STOPPED_EXIT_CODE,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductUninstallRequest {
    pub mode: ProductUninstallMode,
    pub non_interactive: bool,
    pub confirmation: Option<String>,
}

impl ProductUninstallRequest {
    pub fn validate(&self) -> AppResult<()> {
        if !self.non_interactive {
            return Err(AppError::InvalidRequest(
                "product-uninstall requires --non-interactive; the package uninstaller owns the visible choice and confirmation"
                    .into(),
            ));
        }
        match self.mode {
            ProductUninstallMode::AllData
                if self.confirmation.as_deref() != Some(ALL_DATA_CONFIRMATION) =>
            {
                Err(AppError::NotAuthorized(format!(
                    "--confirmation must exactly equal {ALL_DATA_CONFIRMATION:?} for all-data"
                )))
            }
            ProductUninstallMode::AllData => Ok(()),
            _ if self.confirmation.is_some() => Err(AppError::InvalidRequest(
                "--confirmation is accepted only with --mode all-data".into(),
            )),
            _ => Ok(()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProductUninstallRetainedItem {
    /// Stable, non-sensitive class. No filesystem path, runtime name, target,
    /// scanner message, or case identifier is emitted by this result.
    pub item_class: &'static str,
    pub reason_code: &'static str,
}

impl ProductUninstallRetainedItem {
    fn new(item_class: &'static str, reason_code: &'static str) -> Self {
        Self {
            item_class,
            reason_code,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProductUninstallResult {
    pub schema_version: &'static str,
    pub mode: ProductUninstallMode,
    pub result_class: ProductUninstallResultClass,
    pub exit_code: u8,
    pub verified_runtimes_found: usize,
    pub verified_runtimes_stopped: usize,
    pub verified_runtimes_removed: usize,
    pub verified_compatibility_gateways_found: usize,
    pub verified_compatibility_gateways_stopped: usize,
    pub retained_items: Vec<ProductUninstallRetainedItem>,
    pub preserved: Vec<&'static str>,
    pub removed: Vec<&'static str>,
}

impl ProductUninstallResult {
    fn new(mode: ProductUninstallMode) -> Self {
        let preserved = match mode {
            ProductUninstallMode::AppOnly => vec![
                "projects_findings_evidence_and_exports",
                "preferences_and_signing_identity",
                "managed_scan_tools",
            ],
            ProductUninstallMode::ScanTools => vec![
                "projects_findings_evidence_and_exports",
                "preferences_and_signing_identity",
            ],
            ProductUninstallMode::AllData => vec!["ambiguous_or_unrelated_entries"],
        };
        Self {
            schema_version: "ai-security-scanner.product-uninstall/v1",
            mode,
            result_class: ProductUninstallResultClass::Completed,
            exit_code: PRODUCT_UNINSTALL_COMPLETED_EXIT_CODE,
            verified_runtimes_found: 0,
            verified_runtimes_stopped: 0,
            verified_runtimes_removed: 0,
            verified_compatibility_gateways_found: 0,
            verified_compatibility_gateways_stopped: 0,
            retained_items: Vec::new(),
            preserved,
            removed: Vec::new(),
        }
    }

    fn retain(&mut self, item: ProductUninstallRetainedItem) {
        if self.retained_items.iter().any(|existing| existing == &item) {
            return;
        }
        if self.retained_items.len() < MAX_RETAINED_ITEMS {
            self.retained_items.push(item);
        } else if !self
            .retained_items
            .iter()
            .any(|item| item.reason_code == "retained_report_limit_reached")
        {
            self.retained_items.push(ProductUninstallRetainedItem::new(
                "uninstall_result",
                "retained_report_limit_reached",
            ));
        }
    }

    fn finish(&mut self, contact_not_stopped: bool) {
        self.result_class = if contact_not_stopped {
            ProductUninstallResultClass::ContactNotStopped
        } else if self.retained_items.is_empty() {
            ProductUninstallResultClass::Completed
        } else {
            ProductUninstallResultClass::CompletedWithRetainedState
        };
        self.exit_code = self.result_class.exit_code();
    }

    pub fn record_finalization_retained(
        &mut self,
        item_class: &'static str,
        reason_code: &'static str,
    ) {
        if item_class == "product_data" {
            self.removed.retain(|class| *class != "product_user_data");
            if !self.preserved.contains(&"unremoved_product_user_data") {
                self.preserved.push("unremoved_product_user_data");
            }
        }
        self.retain(ProductUninstallRetainedItem::new(item_class, reason_code));
        self.finish(false);
    }

    pub fn canonical_data_root_can_be_staged(&self) -> bool {
        !self.retained_items.iter().any(|item| {
            matches!(
                item.item_class,
                "product_data"
                    | "managed_runtime_state"
                    | "managed_runtime_entry"
                    | "verified_runtime"
                    | "compatibility_gateway_state"
                    | "verified_compatibility_gateway"
            )
        })
    }
}

#[derive(Debug, Default)]
pub struct ProductRuntimeInventory {
    pub verified_manifest_sha256: Vec<String>,
    pub retained: Vec<ProductUninstallRetainedItem>,
    /// True only when a bounded enumeration failed or exceeded its ceiling and
    /// could therefore have hidden an otherwise verifiable active runtime.
    pub contact_inventory_incomplete: bool,
}

#[derive(Debug, Clone, Default)]
pub struct ProductCompatibilityGatewayStopOutcome {
    pub exact_gateways_found: usize,
    pub exact_gateways_stopped: usize,
    pub exact_stop_failures: usize,
    pub retained_ambiguities: usize,
    pub contact_inventory_incomplete: bool,
}

/// Narrow backend seam used to unit-test sequencing without touching a real
/// runtime or real product data.
pub trait ProductUninstallBackend {
    fn inventory_runtimes(&mut self) -> AppResult<ProductRuntimeInventory>;
    fn stop_verified_runtime(&mut self, manifest_sha256: &str) -> bool;
    fn stop_verified_compatibility_gateways(&mut self) -> ProductCompatibilityGatewayStopOutcome;
    fn remove_verified_runtime(&mut self, manifest_sha256: &str) -> bool;
    fn cleanup_scan_tool_residue(&mut self) -> Vec<ProductUninstallRetainedItem>;
    fn cleanup_all_product_user_data(
        &mut self,
        preserve_compatibility_gateway_state: bool,
    ) -> Vec<ProductUninstallRetainedItem>;
}

/// Executes the product contract in two phases. All exact runtimes are given a
/// bounded stop attempt before the first cleanup mutation. If one cannot be
/// stopped, exit class 20 is returned and neither runtime nor user data is
/// removed. Ambiguous and failed-removal state is retained with exit class 10.
pub fn coordinate_product_uninstall<B: ProductUninstallBackend>(
    request: &ProductUninstallRequest,
    backend: &mut B,
) -> AppResult<ProductUninstallResult> {
    request.validate()?;
    let inventory = backend.inventory_runtimes()?;
    let mut result = ProductUninstallResult::new(request.mode);
    result.verified_runtimes_found = inventory.verified_manifest_sha256.len();
    for retained in inventory.retained {
        result.retain(retained);
    }

    let mut contact_not_stopped = false;
    if inventory.contact_inventory_incomplete {
        contact_not_stopped = true;
        result.retain(ProductUninstallRetainedItem::new(
            "managed_runtime_state",
            "target_contact_inventory_incomplete",
        ));
    }
    for manifest_sha256 in &inventory.verified_manifest_sha256 {
        if backend.stop_verified_runtime(manifest_sha256) {
            result.verified_runtimes_stopped += 1;
        } else {
            contact_not_stopped = true;
            result.retain(ProductUninstallRetainedItem::new(
                "verified_runtime",
                "target_contact_not_stopped",
            ));
        }
    }
    // Compatibility gateways are a separate target-contact path from the
    // managed machine. Attempt every exact durable gateway even if one managed
    // machine stop failed; no cleanup begins until both stop passes finish.
    let gateways = backend.stop_verified_compatibility_gateways();
    result.verified_compatibility_gateways_found = gateways.exact_gateways_found;
    result.verified_compatibility_gateways_stopped = gateways.exact_gateways_stopped;
    if gateways.retained_ambiguities > 0 {
        result.retain(ProductUninstallRetainedItem::new(
            "compatibility_gateway_state",
            "ambiguous_gateway_state_preserved",
        ));
    }
    if gateways.exact_stop_failures > 0 {
        contact_not_stopped = true;
        result.retain(ProductUninstallRetainedItem::new(
            "verified_compatibility_gateway",
            "target_contact_not_stopped",
        ));
    }
    if gateways.contact_inventory_incomplete {
        contact_not_stopped = true;
        result.retain(ProductUninstallRetainedItem::new(
            "compatibility_gateway_state",
            "target_contact_inventory_incomplete",
        ));
    }
    if contact_not_stopped {
        result.finish(true);
        return Ok(result);
    }

    if request.mode != ProductUninstallMode::AppOnly
        && (gateways.exact_gateways_found > 0 || gateways.retained_ambiguities > 0)
    {
        // Docker/Podman compatibility images live in a provider-wide cache.
        // The product cannot prove that another container or user does not use
        // the same immutable image, so scan-tool removal leaves that shared
        // cache untouched and says so instead of claiming a complete purge.
        result.retain(ProductUninstallRetainedItem::new(
            "compatibility_provider_image",
            "shared_provider_image_cache_preserved",
        ));
    }

    if request.mode != ProductUninstallMode::AppOnly {
        let retained_before_runtime_removal = result.retained_items.len();
        for manifest_sha256 in &inventory.verified_manifest_sha256 {
            if backend.remove_verified_runtime(manifest_sha256) {
                result.verified_runtimes_removed += 1;
            } else {
                result.retain(ProductUninstallRetainedItem::new(
                    "verified_runtime",
                    "runtime_removal_incomplete",
                ));
            }
        }
        let runtime_residue = backend.cleanup_scan_tool_residue();
        for retained in runtime_residue {
            result.retain(retained);
        }
        if result.verified_runtimes_removed == result.verified_runtimes_found
            && result.retained_items.len() == retained_before_runtime_removal
            && !result.retained_items.iter().any(|item| {
                matches!(
                    item.item_class,
                    "managed_runtime_state"
                        | "managed_runtime_entry"
                        | "verified_runtime"
                        | "compatibility_gateway_state"
                        | "verified_compatibility_gateway"
                        | "compatibility_provider_image"
                )
            })
        {
            result.removed.push("verified_scan_tools");
        } else {
            result
                .preserved
                .push("ambiguous_or_unremoved_scan_tool_state");
        }
    }

    if request.mode == ProductUninstallMode::AllData {
        // Ambiguous compatibility-gateway records are the only durable clue
        // that a legacy or replaced object was deliberately left untouched.
        // An all-data choice is authority to remove verified product data, not
        // authority to erase the record of an object we could not classify.
        let preserve_compatibility_gateway_state = result.retained_items.iter().any(|item| {
            matches!(
                item.item_class,
                "compatibility_gateway_state" | "verified_compatibility_gateway"
            )
        });
        let user_data_residue =
            backend.cleanup_all_product_user_data(preserve_compatibility_gateway_state);
        let user_data_complete = user_data_residue.is_empty();
        for retained in user_data_residue {
            result.retain(retained);
        }
        if user_data_complete {
            result.removed.push("product_user_data");
        }
    }
    result.finish(false);
    Ok(result)
}

#[derive(Debug)]
pub struct LocalProductUninstallBackend {
    data_root: PathBuf,
    verified_digests: BTreeSet<String>,
}

impl LocalProductUninstallBackend {
    pub fn new(data_root: PathBuf) -> Self {
        Self {
            data_root,
            verified_digests: BTreeSet::new(),
        }
    }

    fn managed_root(&self) -> PathBuf {
        self.data_root.join(MANAGED_RUNTIME_DIRECTORY)
    }

    fn compatibility_network_registry(&self) -> Result<Option<ManagedNetworkRegistry>, ()> {
        let artifact_root = self.data_root.join(ARTIFACT_DIRECTORY);
        let registry_root = artifact_root.join(MANAGED_NETWORK_REGISTRY_DIRECTORY);
        let mut guards = Vec::new();
        for path in [&artifact_root, &registry_root] {
            match fs::symlink_metadata(path) {
                Ok(_) => guards.push(open_directory_no_follow(path).map_err(|_| ())?),
                Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
                _ => return Err(()),
            }
        }
        // ManagedNetworkRegistry binds both roots by canonical parent
        // relationship. Canonicalize them together here so Windows' verbatim
        // path representation cannot turn the normal LocalAppData path into a
        // false ambiguity.
        let artifact_root = artifact_root.canonicalize().map_err(|_| ())?;
        let registry_root = registry_root.canonicalize().map_err(|_| ())?;
        let result = ManagedNetworkRegistry::new(&registry_root, &artifact_root)
            .map(Some)
            .map_err(|_| ());
        drop(guards);
        result
    }

    fn record_unclaimed_provider_state(
        managed_root: &Path,
        inventory: &mut ProductRuntimeInventory,
    ) {
        let provider_root = managed_root.join(MANAGED_RUNTIME_PROVIDER_DIRECTORY);
        let _provider_guard = match open_directory_no_follow(&provider_root) {
            Ok(guard) => guard,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return,
            Err(_) => {
                inventory.retained.push(ProductUninstallRetainedItem::new(
                    "managed_runtime_entry",
                    "ambiguous_runtime_entry_preserved",
                ));
                return;
            }
        };

        let first_entry = match fs::read_dir(&provider_root) {
            Ok(mut entries) => entries.next(),
            Err(_) => {
                inventory.retained.push(ProductUninstallRetainedItem::new(
                    "managed_runtime_entry",
                    "ambiguous_runtime_entry_preserved",
                ));
                return;
            }
        };
        match first_entry {
            Some(Ok(_)) => inventory.retained.push(ProductUninstallRetainedItem::new(
                "managed_runtime_state",
                "runtime_ownership_unavailable",
            )),
            Some(Err(_)) => inventory.retained.push(ProductUninstallRetainedItem::new(
                "managed_runtime_entry",
                "ambiguous_runtime_entry_preserved",
            )),
            None => {}
        }
    }

    fn inspect_remaining_runtime_state(&self) -> Vec<ProductUninstallRetainedItem> {
        let root = self.managed_root();
        let mut retained = Vec::new();
        let root_guard = match open_directory_no_follow(&root) {
            Ok(guard) => guard,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return retained,
            Err(_) => {
                retained.push(ProductUninstallRetainedItem::new(
                    "managed_runtime_state",
                    "ambiguous_runtime_root_preserved",
                ));
                return retained;
            }
        };

        // Managers have dropped their lifecycle lock before this method runs.
        // Removing this one exact regular lock file cannot widen runtime
        // ownership. Other regular files remain preserved unless a manager
        // already removed them under an exact manifest contract.
        let lifecycle_lock = root.join(MANAGED_RUNTIME_LIFECYCLE_LOCK);
        if let Ok(lock_guard) = open_file_no_follow(&lifecycle_lock) {
            drop(lock_guard);
            let _ = fs::remove_file(&lifecycle_lock);
        }
        for child in [
            MANAGED_RUNTIME_VERSIONS_DIRECTORY,
            MANAGED_RUNTIME_PROVIDER_DIRECTORY,
            "machine-images",
            "wsl-ownership",
            "wsl-generations",
            "wsl-recovery",
            "wsl-recovery-workspaces",
            "wsl-legacy-retained",
        ] {
            // Reject every reparse form before a single non-recursive removal.
            // This preserves even unusual Windows directory reparse points
            // instead of relying only on FileType::is_symlink.
            let child_path = root.join(child);
            match fs::symlink_metadata(&child_path) {
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Ok(_) => match open_directory_no_follow(&child_path) {
                    Ok(child_guard) => {
                        drop(child_guard);
                        let _ = fs::remove_dir(&child_path);
                    }
                    Err(_) => retained.push(ProductUninstallRetainedItem::new(
                        "managed_runtime_entry",
                        "ambiguous_runtime_entry_preserved",
                    )),
                },
                Err(_) => retained.push(ProductUninstallRetainedItem::new(
                    "managed_runtime_entry",
                    "runtime_entry_inventory_unavailable",
                )),
            }
        }
        drop(root_guard);
        let _ = fs::remove_dir(&root);
        if fs::symlink_metadata(&root).is_ok() {
            let has_entries_or_is_unreadable = fs::read_dir(&root)
                .map(|mut entries| entries.next().is_some())
                .unwrap_or(true);
            if has_entries_or_is_unreadable {
                retained.push(ProductUninstallRetainedItem::new(
                    "managed_runtime_state",
                    "ambiguous_runtime_state_preserved",
                ));
            }
        }
        retained
    }
}

impl ProductUninstallBackend for LocalProductUninstallBackend {
    fn inventory_runtimes(&mut self) -> AppResult<ProductRuntimeInventory> {
        let mut inventory = ProductRuntimeInventory::default();
        let managed_root = self.managed_root();
        let versions = managed_root.join(MANAGED_RUNTIME_VERSIONS_DIRECTORY);
        let managed_metadata = match fs::symlink_metadata(&managed_root) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(inventory),
            Err(_) => {
                inventory.retained.push(ProductUninstallRetainedItem::new(
                    "managed_runtime_state",
                    "runtime_inventory_unavailable",
                ));
                inventory.contact_inventory_incomplete = true;
                return Ok(inventory);
            }
        };
        if managed_metadata.file_type().is_symlink() || !managed_metadata.is_dir() {
            inventory.retained.push(ProductUninstallRetainedItem::new(
                "managed_runtime_state",
                "ambiguous_runtime_root_preserved",
            ));
            return Ok(inventory);
        }
        let _managed_root_guard = match open_directory_no_follow(&managed_root) {
            Ok(guard) => guard,
            Err(_) => {
                inventory.retained.push(ProductUninstallRetainedItem::new(
                    "managed_runtime_state",
                    "ambiguous_runtime_root_preserved",
                ));
                return Ok(inventory);
            }
        };
        let version_metadata = match fs::symlink_metadata(&versions) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                Self::record_unclaimed_provider_state(&managed_root, &mut inventory);
                return Ok(inventory);
            }
            Err(_) => {
                inventory.retained.push(ProductUninstallRetainedItem::new(
                    "managed_runtime_state",
                    "runtime_inventory_unavailable",
                ));
                inventory.contact_inventory_incomplete = true;
                return Ok(inventory);
            }
        };
        if version_metadata.file_type().is_symlink() || !version_metadata.is_dir() {
            inventory.retained.push(ProductUninstallRetainedItem::new(
                "managed_runtime_state",
                "ambiguous_versions_root_preserved",
            ));
            return Ok(inventory);
        }
        let _versions_root_guard = match open_directory_no_follow(&versions) {
            Ok(guard) => guard,
            Err(_) => {
                inventory.retained.push(ProductUninstallRetainedItem::new(
                    "managed_runtime_state",
                    "ambiguous_versions_root_preserved",
                ));
                return Ok(inventory);
            }
        };

        let mut entries = match fs::read_dir(&versions) {
            Ok(entries) => {
                let mut readable = Vec::new();
                for entry in entries {
                    match entry {
                        Ok(entry) => readable.push(entry),
                        Err(_) => inventory.retained.push(ProductUninstallRetainedItem::new(
                            "managed_runtime_entry",
                            "runtime_entry_inventory_unavailable",
                        )),
                    }
                }
                readable
            }
            Err(_) => {
                inventory.retained.push(ProductUninstallRetainedItem::new(
                    "managed_runtime_state",
                    "runtime_inventory_unavailable",
                ));
                inventory.contact_inventory_incomplete = true;
                return Ok(inventory);
            }
        };
        if inventory
            .retained
            .iter()
            .any(|item| item.reason_code == "runtime_entry_inventory_unavailable")
        {
            inventory.contact_inventory_incomplete = true;
        }
        entries.sort_by_key(|entry| entry.file_name());
        if entries.len() > MAX_INSTALLED_RUNTIME_ENTRIES {
            inventory.retained.push(ProductUninstallRetainedItem::new(
                "managed_runtime_state",
                "runtime_inventory_limit_reached",
            ));
            inventory.contact_inventory_incomplete = true;
            entries.truncate(MAX_INSTALLED_RUNTIME_ENTRIES);
        }

        for entry in entries {
            let path = entry.path();
            let exact_digest = (|| -> AppResult<String> {
                let metadata = fs::symlink_metadata(&path)?;
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    return Err(AppError::NotAuthorized(
                        "runtime entry is not a real directory".into(),
                    ));
                }
                let digest = bounded_regular_file_sha256(&path.join(MANAGED_RUNTIME_MANIFEST))?;
                ManagedRuntimeManager::open_installed_for_product_uninstall(
                    &self.data_root,
                    &digest,
                )?;
                Ok(digest)
            })();
            match exact_digest {
                Ok(digest) if self.verified_digests.insert(digest.clone()) => {
                    inventory.verified_manifest_sha256.push(digest);
                }
                Ok(_) => {}
                Err(error) => {
                    if matches!(error, AppError::Internal(_)) {
                        inventory.contact_inventory_incomplete = true;
                    }
                    inventory.retained.push(ProductUninstallRetainedItem::new(
                        "managed_runtime_entry",
                        "unverified_runtime_entry_preserved",
                    ));
                }
            }
        }
        inventory.verified_manifest_sha256.sort();
        if inventory.verified_manifest_sha256.is_empty() {
            Self::record_unclaimed_provider_state(&managed_root, &mut inventory);
        }
        Ok(inventory)
    }

    fn stop_verified_runtime(&mut self, manifest_sha256: &str) -> bool {
        if !self.verified_digests.contains(manifest_sha256) {
            return false;
        }
        ManagedRuntimeManager::open_installed_for_product_uninstall(
            &self.data_root,
            manifest_sha256,
        )
        .and_then(|manager| manager.stop_for_product_uninstall())
        .is_ok()
    }

    fn stop_verified_compatibility_gateways(&mut self) -> ProductCompatibilityGatewayStopOutcome {
        let registry = match self.compatibility_network_registry() {
            Ok(Some(registry)) => registry,
            Ok(None) => return ProductCompatibilityGatewayStopOutcome::default(),
            Err(()) => {
                return ProductCompatibilityGatewayStopOutcome {
                    retained_ambiguities: 1,
                    contact_inventory_incomplete: true,
                    ..Default::default()
                };
            }
        };
        let summary = registry.stop_verified_compatibility_gateways(Utc::now());
        ProductCompatibilityGatewayStopOutcome {
            exact_gateways_found: summary.exact_gateways_found,
            exact_gateways_stopped: summary.exact_gateways_stopped,
            exact_stop_failures: summary.exact_stop_failures,
            retained_ambiguities: summary.retained_ambiguities,
            contact_inventory_incomplete: summary.contact_inventory_incomplete,
        }
    }

    fn remove_verified_runtime(&mut self, manifest_sha256: &str) -> bool {
        if !self.verified_digests.contains(manifest_sha256) {
            return false;
        }
        ManagedRuntimeManager::open_installed_for_product_uninstall(
            &self.data_root,
            manifest_sha256,
        )
        .and_then(|manager| {
            manager.uninstall(ManagedUninstallOptions {
                stop_mode: ManagedStopMode::Force,
                remove_machine_image_cache: true,
            })
        })
        .is_ok()
    }

    fn cleanup_scan_tool_residue(&mut self) -> Vec<ProductUninstallRetainedItem> {
        let mut retained = self.inspect_remaining_runtime_state();
        match self.compatibility_network_registry() {
            Ok(Some(registry)) => {
                let summary = registry.reconcile_verified_compatibility_gateway_records(Utc::now());
                if summary.incomplete > 0 {
                    retained.push(ProductUninstallRetainedItem::new(
                        "compatibility_gateway_state",
                        "compatibility_gateway_cleanup_incomplete",
                    ));
                }
            }
            Ok(None) => {}
            Err(()) => retained.push(ProductUninstallRetainedItem::new(
                "compatibility_gateway_state",
                "ambiguous_gateway_state_preserved",
            )),
        }
        retained
    }

    fn cleanup_all_product_user_data(
        &mut self,
        preserve_compatibility_gateway_state: bool,
    ) -> Vec<ProductUninstallRetainedItem> {
        remove_bounded_product_data(&self.data_root, preserve_compatibility_gateway_state)
    }
}

/// Confirms that a product-uninstall path is the fixed direct child of the
/// platform local-data directory. This validation occurs before the process
/// lease or any runtime command. An arbitrary global `--data-dir` never reaches
/// this function from the CLI.
pub fn validate_fixed_product_data_root(data_root: &Path, local_data_root: &Path) -> AppResult<()> {
    if !data_root.is_absolute() || !local_data_root.is_absolute() {
        return Err(AppError::NotAuthorized(
            "product-uninstall requires an absolute platform data directory".into(),
        ));
    }
    if data_root.file_name().and_then(|name| name.to_str()) != Some(PRODUCT_DATA_DIRECTORY_NAME)
        || data_root.parent() != Some(local_data_root)
    {
        return Err(AppError::NotAuthorized(
            "product-uninstall refused a noncanonical application-data directory".into(),
        ));
    }
    match fs::symlink_metadata(data_root) {
        Ok(_) => {
            open_directory_no_follow(data_root).map_err(|_| {
                AppError::NotAuthorized(
                    "product-uninstall preserved an application-data path that is not a real, non-reparse directory"
                        .into(),
                )
            })?;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

/// Pins the one fixed product root, creating it with private permissions when
/// absent, before the caller acquires its process lease.
///
/// Keeping the returned handle alive prevents Windows from replacing the root
/// while uninstall inventory, target-contact stop, and bounded cleanup run. A
/// concurrent desktop that wins the lease race still causes the lease acquire
/// to fail before the coordinator mutates product state.
pub struct PreparedProductDataRootGuard {
    _directory: File,
    _private_directory: PrivateProductDataDirectoryGuard,
}

pub fn prepare_fixed_product_data_root(
    data_root: &Path,
    local_data_root: &Path,
) -> AppResult<(bool, PreparedProductDataRootGuard)> {
    prepare_fixed_product_data_root_with(
        data_root,
        local_data_root,
        ensure_private_product_data_directory,
    )
}

fn prepare_fixed_product_data_root_with(
    data_root: &Path,
    local_data_root: &Path,
    prepare_private_directory: impl FnOnce(&Path) -> AppResult<PrivateProductDataDirectoryGuard>,
) -> AppResult<(bool, PreparedProductDataRootGuard)> {
    validate_fixed_product_data_root(data_root, local_data_root)?;
    let private_directory = prepare_private_directory(data_root)?;
    // Keep the verified namespace pinned while opening the exact final
    // component. The caller retains both handles until the process lease owns
    // the same root, so there is no pathname-only handoff.
    let directory = open_directory_no_follow(data_root).map_err(|_| {
        AppError::NotAuthorized(
            "product-uninstall could not pin the real application-data directory".into(),
        )
    })?;
    let existed_before = !private_directory.was_created();
    Ok((
        existed_before,
        PreparedProductDataRootGuard {
            _directory: directory,
            _private_directory: private_directory,
        },
    ))
}

#[cfg(test)]
fn prepare_fixed_product_data_root_for_isolated_test(
    data_root: &Path,
    local_data_root: &Path,
) -> AppResult<(bool, PreparedProductDataRootGuard)> {
    #[cfg(windows)]
    let prepare_private_directory =
        crate::managed_runtime::ensure_private_product_data_directory_for_isolated_test;
    #[cfg(not(windows))]
    let prepare_private_directory = ensure_private_product_data_directory;
    prepare_fixed_product_data_root_with(data_root, local_data_root, prepare_private_directory)
}

/// On Windows, atomically moves a fully cleaned canonical product root out of
/// the path used by the desktop while the caller still owns its exclusive
/// lease. Other platforms fail closed before any pathname mutation.
///
/// Dropping the lease and then deleting the canonical root would allow a newly
/// launched process to recreate or write that path between those two steps.
/// Renaming a root that contains exactly the lease sentinel closes that race:
/// any later launch gets a fresh canonical directory, while finalization stays
/// bound to the already isolated empty root. A failed rename is reported and
/// leaves the canonical root untouched.
#[derive(Debug)]
pub struct StagedAllDataRoot {
    path: PathBuf,
    #[cfg(windows)]
    directory: Mutex<Option<File>>,
    #[cfg(windows)]
    journal: Mutex<Option<File>>,
}

impl StagedAllDataRoot {
    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(windows)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum AllDataStageJournalState {
    Prepared,
    DeleteAuthorized,
}

#[cfg(windows)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AllDataStageJournal {
    schema_version: u32,
    staging_id: String,
    destination_leaf: String,
    volume_serial_number: u64,
    file_id_hex: String,
    state: AllDataStageJournalState,
}

#[cfg(windows)]
fn windows_file_identity(file: &File) -> io::Result<(u64, [u8; 16])> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ID_INFO, FileIdInfo, GetFileInformationByHandleEx,
    };

    let mut information = FILE_ID_INFO::default();
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
    Ok((
        information.VolumeSerialNumber,
        information.FileId.Identifier,
    ))
}

#[cfg(windows)]
fn open_windows_all_data_stage_journal(
    path: &Path,
    create_new: bool,
    share_delete: bool,
) -> io::Result<File> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use windows_sys::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE};
    use windows_sys::Win32::Storage::FileSystem::{
        DELETE, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE,
        FILE_SHARE_READ, FILE_SHARE_WRITE,
    };

    let mut options = OpenOptions::new();
    let share_mode = if share_delete {
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE
    } else {
        // Once the fixed journal has been published, withhold both write and
        // delete sharing. Its immutable prepared frame and append-only state
        // tail stay pinned through identity validation and exact cleanup.
        FILE_SHARE_READ
    };
    options
        .read(true)
        .write(true)
        .access_mode(GENERIC_READ | GENERIC_WRITE | DELETE)
        .share_mode(share_mode)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    if create_new {
        options.create_new(true);
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "all-data staging journal is not one real non-reparse regular file",
        ));
    }
    Ok(file)
}

#[cfg(windows)]
fn windows_all_data_stage_prepared_frame(journal: &AllDataStageJournal) -> io::Result<Vec<u8>> {
    if journal.state != AllDataStageJournalState::Prepared {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "the immutable all-data staging frame must be prepared",
        ));
    }
    let mut bytes = serde_json::to_vec(journal)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    bytes.push(b'\n');
    if bytes
        .len()
        .checked_add(ALL_DATA_STAGE_DELETE_AUTHORIZED_RECORD.len())
        .is_none_or(|length| length as u64 > MAX_ALL_DATA_STAGE_JOURNAL_BYTES)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "all-data staging journal exceeded its fixed bound",
        ));
    }
    Ok(bytes)
}

#[cfg(windows)]
fn write_windows_all_data_stage_prepared_frame(
    file: &mut File,
    journal: &AllDataStageJournal,
) -> io::Result<()> {
    let bytes = windows_all_data_stage_prepared_frame(journal)?;
    file.seek(SeekFrom::Start(0))?;
    file.set_len(0)?;
    file.write_all(&bytes)?;
    file.sync_all()
}

#[cfg(windows)]
struct ParsedWindowsAllDataStageJournal {
    journal: AllDataStageJournal,
    prepared_frame_len: u64,
}

#[cfg(windows)]
fn read_windows_all_data_stage_journal(
    file: &mut File,
) -> io::Result<ParsedWindowsAllDataStageJournal> {
    let metadata = file.metadata()?;
    if metadata.len() == 0 || metadata.len() > MAX_ALL_DATA_STAGE_JOURNAL_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "all-data staging journal is empty or oversized",
        ));
    }
    file.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    std::io::Read::by_ref(file)
        .take(MAX_ALL_DATA_STAGE_JOURNAL_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 != metadata.len() || bytes.len() as u64 > MAX_ALL_DATA_STAGE_JOURNAL_BYTES
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "all-data staging journal changed during its bounded read",
        ));
    }
    let newline = bytes
        .iter()
        .position(|byte| *byte == b'\n')
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "all-data staging journal has no complete prepared frame",
            )
        })?;
    let prepared_frame_len = newline
        .checked_add(1)
        .and_then(|length| u64::try_from(length).ok())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "all-data staging prepared frame length overflowed",
            )
        })?;
    let mut journal: AllDataStageJournal = serde_json::from_slice(&bytes[..newline])
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    if journal.state != AllDataStageJournalState::Prepared {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "all-data staging prepared frame has a mutable state",
        ));
    }
    let tail = &bytes[newline + 1..];
    if tail == ALL_DATA_STAGE_DELETE_AUTHORIZED_RECORD {
        journal.state = AllDataStageJournalState::DeleteAuthorized;
    } else if !ALL_DATA_STAGE_DELETE_AUTHORIZED_RECORD.starts_with(tail) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "all-data staging journal has an invalid append-only state tail",
        ));
    }
    Ok(ParsedWindowsAllDataStageJournal {
        journal,
        prepared_frame_len,
    })
}

#[cfg(windows)]
fn authorize_windows_all_data_stage_deletion(file: &mut File) -> io::Result<()> {
    let parsed = read_windows_all_data_stage_journal(file)?;
    if parsed.journal.state == AllDataStageJournalState::DeleteAuthorized {
        return Ok(());
    }

    // A hard crash at any point in this transition leaves either no tail or a
    // strict prefix of the one fixed authorization record. Both are safely
    // interpreted as Prepared and retried; the synced JSON authority is never
    // truncated or rewritten.
    file.set_len(parsed.prepared_frame_len)?;
    file.seek(SeekFrom::Start(parsed.prepared_frame_len))?;
    file.write_all(ALL_DATA_STAGE_DELETE_AUTHORIZED_RECORD)?;
    file.sync_all()
}

#[cfg(windows)]
fn create_windows_all_data_stage_journal(
    data_root: &Path,
    parent: &Path,
    parent_guard: &File,
    staging_id: uuid::Uuid,
    journal: &AllDataStageJournal,
) -> AppResult<File> {
    let prepared_frame = windows_all_data_stage_prepared_frame(journal)?;
    let temp_leaf = format!(
        "{ALL_DATA_STAGE_JOURNAL_TEMP_PREFIX}{}.json",
        staging_id.hyphenated()
    );
    let temp_path = data_root.join(&temp_leaf);
    let fixed_path = parent.join(ALL_DATA_STAGE_JOURNAL_FILE);
    let mut temp =
        open_windows_all_data_stage_journal(&temp_path, true, true).map_err(|error| {
            AppError::NotAvailable(format!(
                "all-data finalization could not create its isolated journal draft: {error}"
            ))
        })?;
    let temp_identity = windows_file_identity(&temp)?;
    if let Err(error) = write_windows_all_data_stage_prepared_frame(&mut temp, journal) {
        let _ = windows_delete_file_or_empty_directory_handle(&temp);
        drop(temp);
        return Err(AppError::NotAvailable(format!(
            "all-data finalization could not durably prepare recovery: {error}"
        )));
    }
    if let Err(error) = windows_rename_handle_no_replace(
        &temp,
        parent_guard,
        std::ffi::OsStr::new(ALL_DATA_STAGE_JOURNAL_FILE),
    ) {
        let _ = windows_delete_file_or_empty_directory_handle(&temp);
        drop(temp);
        return Err(AppError::NotAvailable(format!(
            "all-data finalization could not atomically publish its recovery journal: {error}"
        )));
    }

    // The draft needed delete sharing for its native handle rename. Reopen the
    // published name without write/delete sharing and verify its stable file
    // identity after the necessarily narrow close/reopen handoff. Any namespace
    // substitution fails before the product root is moved.
    drop(temp);
    let mut fixed =
        open_windows_all_data_stage_journal(&fixed_path, false, false).map_err(|error| {
            AppError::NotAvailable(format!(
                "all-data finalization could not pin its published recovery journal: {error}"
            ))
        })?;
    if windows_file_identity(&fixed)? != temp_identity {
        return Err(AppError::NotAuthorized(
            "all-data finalization recovery journal changed during publication".into(),
        ));
    }
    let fixed_len = fixed.metadata()?.len();
    let parsed = read_windows_all_data_stage_journal(&mut fixed).map_err(|error| {
        AppError::NotAuthorized(format!(
            "all-data finalization could not validate its published recovery journal: {error}"
        ))
    })?;
    if parsed.journal != *journal
        || fixed_len != u64::try_from(prepared_frame.len()).unwrap_or(u64::MAX)
    {
        return Err(AppError::NotAuthorized(
            "all-data finalization published recovery journal did not retain its prepared frame"
                .into(),
        ));
    }
    Ok(fixed)
}

#[cfg(windows)]
fn validate_windows_all_data_stage_journal(journal: &AllDataStageJournal) -> AppResult<[u8; 16]> {
    if journal.schema_version != ALL_DATA_STAGE_JOURNAL_SCHEMA_VERSION {
        return Err(AppError::NotAuthorized(
            "all-data staging journal has an unsupported schema".into(),
        ));
    }
    let staging_id = uuid::Uuid::parse_str(&journal.staging_id).map_err(|_| {
        AppError::NotAuthorized("all-data staging journal has an invalid identifier".into())
    })?;
    if journal.staging_id != staging_id.hyphenated().to_string()
        || journal.destination_leaf != format!("{ALL_DATA_STAGE_PREFIX}{}", staging_id.hyphenated())
    {
        return Err(AppError::NotAuthorized(
            "all-data staging journal has a non-canonical destination".into(),
        ));
    }
    let decoded = hex::decode(&journal.file_id_hex).map_err(|_| {
        AppError::NotAuthorized("all-data staging journal has an invalid file identity".into())
    })?;
    let identity: [u8; 16] = decoded.try_into().map_err(|_| {
        AppError::NotAuthorized("all-data staging journal has an invalid file identity".into())
    })?;
    if journal.file_id_hex != hex::encode(identity) {
        return Err(AppError::NotAuthorized(
            "all-data staging journal file identity is not canonical".into(),
        ));
    }
    Ok(identity)
}

#[cfg(windows)]
fn windows_ordinal_ignore_case_equal(
    left: &std::ffi::OsStr,
    right: &std::ffi::OsStr,
) -> io::Result<bool> {
    use std::os::windows::ffi::OsStrExt;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn CompareStringOrdinal(
            left: *const u16,
            left_length: i32,
            right: *const u16,
            right_length: i32,
            ignore_case: i32,
        ) -> i32;
    }

    const CSTR_EQUAL: i32 = 2;
    let left = left.encode_wide().collect::<Vec<_>>();
    let right = right.encode_wide().collect::<Vec<_>>();
    let left_length = i32::try_from(left.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Windows name is too long"))?;
    let right_length = i32::try_from(right.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Windows name is too long"))?;
    let comparison = unsafe {
        CompareStringOrdinal(left.as_ptr(), left_length, right.as_ptr(), right_length, 1)
    };
    if comparison == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(comparison == CSTR_EQUAL)
}

#[cfg(windows)]
fn windows_ordinal_ignore_case_starts_with(
    name: &std::ffi::OsStr,
    prefix: &std::ffi::OsStr,
) -> io::Result<bool> {
    use std::os::windows::ffi::{OsStrExt, OsStringExt};

    let prefix = prefix.encode_wide().collect::<Vec<_>>();
    let name_prefix = name.encode_wide().take(prefix.len()).collect::<Vec<_>>();
    if name_prefix.len() != prefix.len() {
        return Ok(false);
    }
    windows_ordinal_ignore_case_equal(
        &std::ffi::OsString::from_wide(&name_prefix),
        &std::ffi::OsString::from_wide(&prefix),
    )
}

#[cfg(windows)]
struct WindowsAllDataStageParentInventory {
    candidates: Vec<std::ffi::OsString>,
    journals: Vec<std::ffi::OsString>,
}

#[cfg(windows)]
fn windows_all_data_stage_parent_inventory(
    parent: &Path,
) -> AppResult<WindowsAllDataStageParentInventory> {
    let stage_prefix = std::ffi::OsStr::new(ALL_DATA_STAGE_PREFIX);
    let journal_name = std::ffi::OsStr::new(ALL_DATA_STAGE_JOURNAL_FILE);
    let deadline = Instant::now() + ALL_DATA_STAGE_DISCOVERY_TIMEOUT;
    let mut candidates = Vec::new();
    let mut journals = Vec::new();
    for (index, entry) in fs::read_dir(parent)?.enumerate() {
        if index >= MAX_ALL_DATA_STAGE_PARENT_ENTRIES || Instant::now() >= deadline {
            return Err(AppError::NotAvailable(
                "all-data staging recovery could not complete its bounded parent inventory".into(),
            ));
        }
        let entry = entry?;
        let name = entry.file_name();
        if windows_ordinal_ignore_case_starts_with(&name, stage_prefix)? {
            if candidates.len() >= MAX_ALL_DATA_STAGE_CANDIDATES {
                return Err(AppError::NotAvailable(
                    "all-data staging recovery found too many candidate roots".into(),
                ));
            }
            candidates.push(name.clone());
        }
        if windows_ordinal_ignore_case_equal(&name, journal_name)? {
            journals.push(name);
            if journals.len() > 1 {
                return Err(AppError::NotAvailable(
                    "all-data staging recovery found ambiguous fixed journals".into(),
                ));
            }
        }
    }
    Ok(WindowsAllDataStageParentInventory {
        candidates,
        journals,
    })
}

#[cfg(windows)]
fn recover_windows_interrupted_all_data_stage(
    data_root_guard: &File,
    parent: &Path,
    lease: &DataDirectoryExclusiveLease,
) -> AppResult<()> {
    let inventory = windows_all_data_stage_parent_inventory(parent)?;
    let journal_name = match inventory.journals.as_slice() {
        [] => {
            if inventory.candidates.is_empty() {
                return Ok(());
            }
            return Err(AppError::NotAvailable(
                "all-data staging recovery preserved an unjournaled candidate root".into(),
            ));
        }
        [journal_name] => journal_name,
        _ => {
            return Err(AppError::NotAvailable(
                "all-data staging recovery found ambiguous fixed journals".into(),
            ));
        }
    };
    let journal_path = parent.join(journal_name);
    let mut journal_file = match open_windows_all_data_stage_journal(&journal_path, false, false) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Err(AppError::NotAvailable(
                "all-data staging recovery lost its inventoried fixed journal".into(),
            ));
        }
        Err(error) => {
            return Err(AppError::NotAvailable(format!(
                "all-data staging recovery could not open its fixed journal: {error}"
            )));
        }
    };
    let parsed = read_windows_all_data_stage_journal(&mut journal_file).map_err(|error| {
        AppError::NotAuthorized(format!(
            "all-data staging recovery preserved an invalid journal: {error}"
        ))
    })?;
    let journal = parsed.journal;
    let expected_file_id = validate_windows_all_data_stage_journal(&journal)?;
    let expected_name = std::ffi::OsString::from(journal.destination_leaf.as_str());
    if inventory
        .candidates
        .iter()
        .map(|candidate| windows_ordinal_ignore_case_equal(candidate, &expected_name))
        .collect::<io::Result<Vec<_>>>()?
        .into_iter()
        .any(|equal| !equal)
        || inventory.candidates.len() > 1
    {
        return Err(AppError::NotAvailable(
            "all-data staging recovery preserved untracked candidate roots".into(),
        ));
    }

    let expected_identity = (journal.volume_serial_number, expected_file_id);
    if inventory.candidates.is_empty()
        && journal.state == AllDataStageJournalState::Prepared
        && windows_file_identity(data_root_guard)? == expected_identity
    {
        // The atomic root rename never happened. Removing only the exact
        // pinned journal restores the pre-transition state.
        windows_delete_file_or_empty_directory_handle(&journal_file).map_err(|error| {
            AppError::NotAvailable(format!(
                "all-data staging recovery could not remove its completed journal: {error}"
            ))
        })?;
        drop(journal_file);
        return Ok(());
    }

    let Some(candidate_name) = inventory.candidates.first() else {
        return Err(AppError::NotAvailable(
            "all-data staging recovery retained its journal because the journaled destination leaf was absent"
                .into(),
        ));
    };
    let candidate_path = parent.join(candidate_name);
    let candidate = lease
        .open_windows_staged_directory_for_identity_check(&candidate_path)
        .map_err(|error| {
            AppError::NotAvailable(format!(
                "all-data staging recovery preserved a non-directory or reparse journaled candidate: {error}"
            ))
        })?;
    if windows_file_identity(&candidate)? != expected_identity {
        return Err(AppError::NotAuthorized(
            "all-data staging recovery journaled candidate identity did not match its durable journal"
                .into(),
        ));
    }
    if journal.state != AllDataStageJournalState::DeleteAuthorized {
        authorize_windows_all_data_stage_deletion(&mut journal_file).map_err(|error| {
            AppError::NotAvailable(format!(
                "all-data staging recovery could not durably authorize exact deletion: {error}"
            ))
        })?;
    }
    windows_delete_file_or_empty_directory_handle(&candidate).map_err(|error| {
        AppError::NotAvailable(format!(
            "all-data staging recovery preserved a nonempty or busy candidate: {error}"
        ))
    })?;
    drop(candidate);
    windows_delete_file_or_empty_directory_handle(&journal_file).map_err(|error| {
        AppError::NotAvailable(format!(
            "all-data staging recovery could not remove its completed journal: {error}"
        ))
    })?;
    drop(journal_file);
    Ok(())
}

pub fn stage_all_data_root_for_finalization(
    data_root: &Path,
    lease: &DataDirectoryExclusiveLease,
) -> AppResult<StagedAllDataRoot> {
    stage_all_data_root_for_finalization_with_id(data_root, lease, uuid::Uuid::new_v4())
}

#[cfg(windows)]
fn stage_all_data_root_for_finalization_with_id(
    data_root: &Path,
    lease: &DataDirectoryExclusiveLease,
    staging_id: uuid::Uuid,
) -> AppResult<StagedAllDataRoot> {
    if lease.path() != data_root.join(DATA_DIRECTORY_LEASE_FILE) {
        return Err(AppError::NotAuthorized(
            "all-data finalization requires the exact product-directory lease".into(),
        ));
    }
    let data_root_guard = open_directory_no_follow(data_root).map_err(|_| {
        AppError::NotAuthorized(
            "all-data finalization preserved a non-directory or reparse product root".into(),
        )
    })?;
    #[cfg(windows)]
    if !lease.windows_directory_matches(&data_root_guard)? {
        return Err(AppError::NotAuthorized(
            "all-data finalization product root changed after lease acquisition".into(),
        ));
    }
    let parent = data_root.parent().ok_or_else(|| {
        AppError::NotAuthorized("product data root has no local-data parent".into())
    })?;
    #[cfg(windows)]
    recover_windows_interrupted_all_data_stage(&data_root_guard, parent, lease)?;
    let mut entries = fs::read_dir(data_root)?;
    let only = entries.next().transpose()?.ok_or_else(|| {
        AppError::Internal("all-data finalization lost its lease sentinel".into())
    })?;
    #[cfg(windows)]
    if !lease.windows_sentinel_is_held()? {
        return Err(AppError::NotAuthorized(
            "all-data finalization lease sentinel is no longer held by this lease".into(),
        ));
    }
    if entries.next().transpose()?.is_some() || only.file_name() != DATA_DIRECTORY_LEASE_FILE {
        return Err(AppError::NotAvailable(
            "all-data finalization retained product state that was not empty".into(),
        ));
    }
    let staged = parent.join(format!(
        ".{PRODUCT_DATA_DIRECTORY_NAME}.uninstall-staged-{}",
        staging_id.hyphenated()
    ));
    match fs::symlink_metadata(&staged) {
        Ok(_) => {
            return Err(AppError::NotAvailable(
                "all-data finalization staging path already exists".into(),
            ));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(AppError::NotAvailable(format!(
                "all-data finalization could not inspect its staging path: {error}"
            )));
        }
    }
    #[cfg(windows)]
    let mut stage_journal_file = {
        let identity = windows_file_identity(&data_root_guard)?;
        let journal = AllDataStageJournal {
            schema_version: ALL_DATA_STAGE_JOURNAL_SCHEMA_VERSION,
            staging_id: staging_id.hyphenated().to_string(),
            destination_leaf: staged
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(|| {
                    AppError::NotAuthorized("product staging path is not canonical UTF-16".into())
                })?
                .to_owned(),
            volume_serial_number: identity.0,
            file_id_hex: hex::encode(identity.1),
            state: AllDataStageJournalState::Prepared,
        };
        validate_windows_all_data_stage_journal(&journal)?;
        create_windows_all_data_stage_journal(
            data_root,
            parent,
            lease.windows_parent(),
            staging_id,
            &journal,
        )?
    };
    // The lifetime mutex continues to own the canonical Windows pathname after
    // its ordinary sentinel handle is closed for the one pinned-handle rename.
    drop(data_root_guard);
    #[cfg(windows)]
    {
        let staged_directory = lease.prepare_windows_directory_for_staging()?;
        windows_rename_handle_no_replace(
            &staged_directory,
            lease.windows_parent(),
            staged.file_name().ok_or_else(|| {
                AppError::NotAuthorized("product staging path has no final component".into())
            })?,
        )
        .map_err(|error| {
            AppError::NotAvailable(format!(
                "all-data finalization could not isolate the empty product root without replacement: {error}"
            ))
        })?;
        let staged_guard = lease
            .open_windows_staged_directory_for_identity_check(&staged)
            .map_err(|error| {
                AppError::NotAvailable(format!(
                    "all-data finalization could not recheck its staged product root: {error}"
                ))
            })?;
        if !lease.windows_directory_matches(&staged_guard)? {
            return Err(AppError::NotAuthorized(
                "all-data finalization staged path did not retain the leased product-root identity"
                    .into(),
            ));
        }
        authorize_windows_all_data_stage_deletion(&mut stage_journal_file).map_err(|error| {
            AppError::NotAvailable(format!(
                "all-data finalization could not durably authorize exact staged cleanup: {error}"
            ))
        })?;
        Ok(StagedAllDataRoot {
            path: staged,
            directory: Mutex::new(Some(staged_directory)),
            journal: Mutex::new(Some(stage_journal_file)),
        })
    }
}

#[cfg(not(windows))]
fn stage_all_data_root_for_finalization_with_id(
    data_root: &Path,
    lease: &DataDirectoryExclusiveLease,
    _staging_id: uuid::Uuid,
) -> AppResult<StagedAllDataRoot> {
    if lease.path() != data_root.join(DATA_DIRECTORY_LEASE_FILE) {
        return Err(AppError::NotAuthorized(
            "all-data finalization requires the exact product-directory lease".into(),
        ));
    }
    Err(AppError::NotAvailable(
        "all-data finalization retained the product root because handle-bound staging and durable recovery are unavailable on this platform"
            .into(),
    ))
}

#[cfg(windows)]
fn windows_rename_handle_no_replace(
    source: &File,
    parent: &File,
    destination_leaf: &std::ffi::OsStr,
) -> io::Result<()> {
    use std::os::windows::{ffi::OsStrExt, io::AsRawHandle};
    use windows_sys::Win32::Foundation::HANDLE;

    #[repr(C)]
    struct NativeIoStatusBlock {
        // IO_STATUS_BLOCK starts with a union of NTSTATUS and PVOID. Using the
        // pointer-sized member preserves the native union's size/alignment on
        // both supported Windows architectures.
        status_or_pointer: usize,
        information: usize,
    }

    #[repr(C)]
    struct NativeFileRenameInformation {
        replace_if_exists: u8,
        root_directory: HANDLE,
        file_name_length: u32,
        file_name: [u16; 1],
    }

    #[link(name = "ntdll")]
    unsafe extern "system" {
        fn NtSetInformationFile(
            file_handle: HANDLE,
            io_status_block: *mut NativeIoStatusBlock,
            file_information: *mut std::ffi::c_void,
            length: u32,
            file_information_class: u32,
        ) -> i32;
        fn RtlNtStatusToDosError(status: i32) -> u32;
    }

    const FILE_RENAME_INFORMATION_CLASS: u32 = 10;

    let destination = destination_leaf.encode_wide().collect::<Vec<_>>();
    if destination.is_empty()
        || destination == [b'.' as u16]
        || destination == [b'.' as u16, b'.' as u16]
        || destination.iter().any(|unit| {
            let unit = *unit;
            unit != u16::from(b'-')
                && unit != u16::from(b'.')
                && !(u16::from(b'0')..=u16::from(b'9')).contains(&unit)
                && !(u16::from(b'A')..=u16::from(b'Z')).contains(&unit)
                && !(u16::from(b'a')..=u16::from(b'z')).contains(&unit)
        })
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "product staging destination is not one safe final path component",
        ));
    }
    let name_bytes = destination
        .len()
        .checked_mul(std::mem::size_of::<u16>())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "staging name overflowed"))?;
    let prefix = std::mem::offset_of!(NativeFileRenameInformation, file_name);
    let total = prefix
        .checked_add(name_bytes)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "rename buffer overflowed"))?;
    let total_u32 = u32::try_from(total)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "rename buffer is too large"))?;
    let name_bytes_u32 = u32::try_from(name_bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "staging name is too large"))?;
    let mut storage = vec![0_usize; total.div_ceil(std::mem::size_of::<usize>())];
    let information = storage.as_mut_ptr().cast::<NativeFileRenameInformation>();
    unsafe {
        (*information).replace_if_exists = 0;
        (*information).root_directory = parent.as_raw_handle();
        (*information).file_name_length = name_bytes_u32;
        std::ptr::copy_nonoverlapping(
            destination.as_ptr(),
            std::ptr::addr_of_mut!((*information).file_name).cast::<u16>(),
            destination.len(),
        );
    }

    // SetFileInformationByHandle rejects RootDirectory-relative rename
    // requests on supported Windows versions. NtSetInformationFile's legacy
    // FileRenameInformation contract accepts the pinned parent handle. With
    // ReplaceIfExists=FALSE this is one atomic, no-replace namespace operation
    // and never re-resolves an attacker-controlled ancestor pathname.
    let mut io_status = NativeIoStatusBlock {
        status_or_pointer: 0,
        information: 0,
    };
    let status = unsafe {
        NtSetInformationFile(
            source.as_raw_handle(),
            &raw mut io_status,
            information.cast(),
            total_u32,
            FILE_RENAME_INFORMATION_CLASS,
        )
    };
    if status < 0 {
        let win32 = unsafe { RtlNtStatusToDosError(status) };
        return Err(io::Error::from_raw_os_error(win32 as i32));
    }
    Ok(())
}

/// On Windows, removes one handle-pinned staged product root after the
/// coordinator and process lease have both been dropped. A nonempty root is
/// retained. Other platforms return a retained-state result without pathname
/// deletion. This never traverses or removes the local-data parent.
pub fn finalize_all_data_root(staged: &StagedAllDataRoot) -> Vec<ProductUninstallRetainedItem> {
    #[cfg(windows)]
    {
        let mut retained = Vec::new();
        let mut journal = match staged.journal.lock() {
            Ok(journal) => journal,
            Err(_) => {
                retained.push(ProductUninstallRetainedItem::new(
                    "product_data",
                    "staged_product_data_journal_guard_poisoned",
                ));
                return retained;
            }
        };
        if journal.is_none() {
            return retained;
        }
        let mut directory = match staged.directory.lock() {
            Ok(directory) => directory,
            Err(_) => {
                retained.push(ProductUninstallRetainedItem::new(
                    "product_data",
                    "staged_product_data_guard_poisoned",
                ));
                return retained;
            }
        };
        let Some(directory) = directory.take() else {
            retained.push(ProductUninstallRetainedItem::new(
                "product_data",
                "staged_product_data_handle_missing",
            ));
            return retained;
        };
        if windows_delete_file_or_empty_directory_handle(&directory).is_err() {
            retained.push(ProductUninstallRetainedItem::new(
                "product_data",
                "product_data_root_retained",
            ));
            drop(directory);
            return retained;
        }
        drop(directory);
        let Some(journal_file) = journal.take() else {
            retained.push(ProductUninstallRetainedItem::new(
                "product_data",
                "staged_product_data_journal_missing",
            ));
            return retained;
        };
        if windows_delete_file_or_empty_directory_handle(&journal_file).is_err() {
            retained.push(ProductUninstallRetainedItem::new(
                "product_data",
                "staged_product_data_journal_retained",
            ));
        }
        drop(journal_file);
        retained
    }

    #[cfg(not(windows))]
    {
        let _ = staged;
        vec![ProductUninstallRetainedItem::new(
            "product_data",
            "handle_bound_finalization_unavailable_on_platform",
        )]
    }
}

#[cfg(windows)]
fn windows_delete_file_or_empty_directory_handle(file: &File) -> io::Result<()> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_DISPOSITION_INFO, FileDispositionInfo, SetFileInformationByHandle,
    };

    let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
    if unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle(),
            FileDispositionInfo,
            (&raw const disposition).cast(),
            std::mem::size_of::<FILE_DISPOSITION_INFO>() as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn bounded_regular_file_sha256(path: &Path) -> AppResult<String> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > MAX_RUNTIME_MANIFEST_BYTES
    {
        return Err(AppError::NotAuthorized(
            "managed runtime manifest is not one bounded regular file".into(),
        ));
    }
    let mut file = open_file_no_follow(path)?;
    let opened = file.metadata()?;
    if !opened.is_file() || opened.len() != metadata.len() {
        return Err(AppError::NotAuthorized(
            "managed runtime manifest changed during exact inventory".into(),
        ));
    }
    let mut bytes = Vec::with_capacity(opened.len() as usize);
    std::io::Read::by_ref(&mut file)
        .take(MAX_RUNTIME_MANIFEST_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 != opened.len() || bytes.len() as u64 > MAX_RUNTIME_MANIFEST_BYTES {
        return Err(AppError::NotAuthorized(
            "managed runtime manifest changed during bounded inventory".into(),
        ));
    }
    Ok(hex::encode(Sha256::digest(bytes)))
}

fn open_file_no_follow(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
            FILE_SHARE_WRITE,
        };
        // Other readers/writers may finish, but replacement/rename is denied
        // while this inspection handle is alive.
        options.share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE);
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
        let file = options.open(path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "file is not one real non-reparse regular file",
            ));
        }
        Ok(file)
    }
    #[cfg(not(windows))]
    {
        let file = options.open(path)?;
        if !file.metadata()?.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "file is not one real regular file",
            ));
        }
        Ok(file)
    }
}

fn open_directory_no_follow(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
            FILE_SHARE_READ, FILE_SHARE_WRITE,
        };
        options
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
        let directory = options.open(path)?;
        let metadata = directory.metadata()?;
        if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "directory is not one real non-reparse directory",
            ));
        }
        Ok(directory)
    }
    #[cfg(not(windows))]
    {
        let directory = options.open(path)?;
        if !directory.metadata()?.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "directory is not one real directory",
            ));
        }
        Ok(directory)
    }
}

struct CleanupBudget {
    remaining_entries: usize,
    deadline: Instant,
}

impl CleanupBudget {
    fn consume(&mut self) -> bool {
        if self.remaining_entries == 0 || Instant::now() >= self.deadline {
            return false;
        }
        self.remaining_entries -= 1;
        true
    }
}

fn remove_bounded_product_data(
    data_root: &Path,
    preserve_compatibility_gateway_state: bool,
) -> Vec<ProductUninstallRetainedItem> {
    let mut retained = Vec::new();
    match fs::symlink_metadata(data_root) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => return retained,
        _ => {
            retained.push(ProductUninstallRetainedItem::new(
                "product_data",
                "ambiguous_product_data_root_preserved",
            ));
            return retained;
        }
    }
    let mut budget = CleanupBudget {
        remaining_entries: MAX_PRODUCT_DATA_ENTRIES,
        deadline: Instant::now() + PRODUCT_DATA_CLEANUP_TIMEOUT,
    };
    let preserved_gateway_registry = preserve_compatibility_gateway_state.then(|| {
        data_root
            .join(ARTIFACT_DIRECTORY)
            .join(MANAGED_NETWORK_REGISTRY_DIRECTORY)
    });
    let root_guard = match open_directory_no_follow(data_root) {
        Ok(guard) => guard,
        Err(_) => {
            retained.push(ProductUninstallRetainedItem::new(
                "product_data",
                "ambiguous_product_data_root_preserved",
            ));
            return retained;
        }
    };
    let entries = match fs::read_dir(data_root) {
        Ok(entries) => entries.filter_map(Result::ok).collect::<Vec<_>>(),
        Err(error) if error.kind() == io::ErrorKind::NotFound => return retained,
        Err(_) => {
            retained.push(ProductUninstallRetainedItem::new(
                "product_data",
                "product_data_inventory_failed",
            ));
            return retained;
        }
    };
    for entry in entries {
        let name = entry.file_name();
        if name == MANAGED_RUNTIME_DIRECTORY || name == DATA_DIRECTORY_LEASE_FILE {
            continue;
        }
        remove_bounded_entry(
            &entry.path(),
            preserved_gateway_registry.as_deref(),
            0,
            &mut budget,
            &mut retained,
        );
    }
    drop(root_guard);
    retained
}

fn remove_bounded_entry(
    path: &Path,
    preserved_exact_path: Option<&Path>,
    depth: usize,
    budget: &mut CleanupBudget,
    retained: &mut Vec<ProductUninstallRetainedItem>,
) -> bool {
    if preserved_exact_path == Some(path) {
        push_retained_bounded(
            retained,
            ProductUninstallRetainedItem::new(
                "compatibility_gateway_state",
                "ambiguous_gateway_state_preserved",
            ),
        );
        return false;
    }
    if depth > MAX_PRODUCT_DATA_DEPTH || !budget.consume() {
        push_retained_bounded(
            retained,
            ProductUninstallRetainedItem::new("product_data", "cleanup_bound_reached"),
        );
        return false;
    }
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return true,
        Err(_) => {
            push_retained_bounded(
                retained,
                ProductUninstallRetainedItem::new("product_data", "data_entry_inspection_failed"),
            );
            return false;
        }
    };
    if metadata.file_type().is_symlink() {
        push_retained_bounded(
            retained,
            ProductUninstallRetainedItem::new("product_data", "ambiguous_link_preserved"),
        );
        return false;
    }
    if metadata.is_file() {
        if fs::remove_file(path).is_ok() {
            return true;
        }
        push_retained_bounded(
            retained,
            ProductUninstallRetainedItem::new("product_data", "data_file_removal_incomplete"),
        );
        return false;
    }
    if !metadata.is_dir() {
        push_retained_bounded(
            retained,
            ProductUninstallRetainedItem::new("product_data", "special_entry_preserved"),
        );
        return false;
    }

    // Keep a no-reparse directory handle open while enumerating and visiting
    // children. On Windows the handle deliberately withholds delete sharing,
    // so a junction/reparse swap cannot occur between the type check and
    // traversal. It is dropped only before the final non-recursive `remove_dir`.
    let directory_guard = match open_directory_no_follow(path) {
        Ok(guard) => guard,
        Err(_) => {
            push_retained_bounded(
                retained,
                ProductUninstallRetainedItem::new(
                    "product_data",
                    "ambiguous_or_replaced_directory_preserved",
                ),
            );
            return false;
        }
    };

    let entries = match fs::read_dir(path) {
        Ok(entries) => entries.filter_map(Result::ok).collect::<Vec<_>>(),
        Err(_) => {
            push_retained_bounded(
                retained,
                ProductUninstallRetainedItem::new("product_data", "data_tree_inventory_failed"),
            );
            return false;
        }
    };
    let mut complete = true;
    for entry in entries {
        complete &= remove_bounded_entry(
            &entry.path(),
            preserved_exact_path,
            depth + 1,
            budget,
            retained,
        );
    }
    drop(directory_guard);
    if complete && fs::remove_dir(path).is_ok() {
        true
    } else {
        if complete {
            push_retained_bounded(
                retained,
                ProductUninstallRetainedItem::new(
                    "product_data",
                    "data_directory_removal_incomplete",
                ),
            );
        }
        false
    }
}

fn push_retained_bounded(
    retained: &mut Vec<ProductUninstallRetainedItem>,
    item: ProductUninstallRetainedItem,
) {
    if retained.len() < MAX_RETAINED_ITEMS {
        retained.push(item);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[cfg(windows)]
    fn create_windows_directory_junction(link: &Path, target: &Path) {
        use std::process::Command;

        let command = PathBuf::from(std::env::var_os("SystemRoot").expect("SystemRoot"))
            .join("System32")
            .join("cmd.exe");
        let output = Command::new(command)
            .arg("/d")
            .arg("/c")
            .arg("mklink")
            .arg("/J")
            .arg(link)
            .arg(target)
            .output()
            .expect("create Windows junction fixture");
        assert!(
            output.status.success(),
            "mklink fixture failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[derive(Default)]
    struct FakeBackend {
        runtimes: Vec<String>,
        retained: Vec<ProductUninstallRetainedItem>,
        contact_inventory_incomplete: bool,
        stop: BTreeMap<String, bool>,
        gateway_stop: ProductCompatibilityGatewayStopOutcome,
        remove: BTreeMap<String, bool>,
        calls: Vec<String>,
        scan_tool_residue: Vec<ProductUninstallRetainedItem>,
        user_data_residue: Vec<ProductUninstallRetainedItem>,
        preserve_gateway_state_on_user_cleanup: Option<bool>,
    }

    impl ProductUninstallBackend for FakeBackend {
        fn inventory_runtimes(&mut self) -> AppResult<ProductRuntimeInventory> {
            self.calls.push("inventory".into());
            Ok(ProductRuntimeInventory {
                verified_manifest_sha256: self.runtimes.clone(),
                retained: self.retained.clone(),
                contact_inventory_incomplete: self.contact_inventory_incomplete,
            })
        }

        fn stop_verified_runtime(&mut self, manifest_sha256: &str) -> bool {
            self.calls.push(format!("stop:{manifest_sha256}"));
            self.stop.get(manifest_sha256).copied().unwrap_or(true)
        }

        fn stop_verified_compatibility_gateways(
            &mut self,
        ) -> ProductCompatibilityGatewayStopOutcome {
            self.calls.push("stop_gateways".into());
            self.gateway_stop.clone()
        }

        fn remove_verified_runtime(&mut self, manifest_sha256: &str) -> bool {
            self.calls.push(format!("remove:{manifest_sha256}"));
            self.remove.get(manifest_sha256).copied().unwrap_or(true)
        }

        fn cleanup_scan_tool_residue(&mut self) -> Vec<ProductUninstallRetainedItem> {
            self.calls.push("cleanup_scan_tools".into());
            self.scan_tool_residue.clone()
        }

        fn cleanup_all_product_user_data(
            &mut self,
            preserve_compatibility_gateway_state: bool,
        ) -> Vec<ProductUninstallRetainedItem> {
            self.calls.push("cleanup_user_data".into());
            self.preserve_gateway_state_on_user_cleanup =
                Some(preserve_compatibility_gateway_state);
            self.user_data_residue.clone()
        }
    }

    fn request(mode: ProductUninstallMode) -> ProductUninstallRequest {
        ProductUninstallRequest {
            mode,
            non_interactive: true,
            confirmation: (mode == ProductUninstallMode::AllData)
                .then(|| ALL_DATA_CONFIRMATION.into()),
        }
    }

    #[test]
    fn exact_all_data_confirmation_is_required_before_inventory_or_mutation() {
        let mut backend = FakeBackend::default();
        let mut invalid = request(ProductUninstallMode::AllData);
        invalid.confirmation = Some("remove everything".into());
        assert!(coordinate_product_uninstall(&invalid, &mut backend).is_err());
        assert!(backend.calls.is_empty());

        let mut extra = request(ProductUninstallMode::ScanTools);
        extra.confirmation = Some(ALL_DATA_CONFIRMATION.into());
        assert!(coordinate_product_uninstall(&extra, &mut backend).is_err());
        assert!(backend.calls.is_empty());
    }

    #[test]
    fn app_only_stops_all_verified_runtimes_and_preserves_every_data_class() {
        let mut backend = FakeBackend {
            runtimes: vec!["a".repeat(64), "b".repeat(64)],
            ..Default::default()
        };
        let result =
            coordinate_product_uninstall(&request(ProductUninstallMode::AppOnly), &mut backend)
                .unwrap();
        assert_eq!(result.result_class, ProductUninstallResultClass::Completed);
        assert_eq!(result.exit_code, 0);
        assert_eq!(result.verified_runtimes_stopped, 2);
        assert_eq!(result.verified_runtimes_removed, 0);
        assert!(result.preserved.contains(&"managed_scan_tools"));
        assert_eq!(
            backend.calls,
            vec![
                "inventory",
                &format!("stop:{}", "a".repeat(64)),
                &format!("stop:{}", "b".repeat(64)),
                "stop_gateways",
            ]
        );
    }

    #[test]
    fn one_failed_stop_attempts_every_verified_runtime_then_aborts_before_cleanup() {
        let first = "a".repeat(64);
        let second = "b".repeat(64);
        let mut backend = FakeBackend {
            runtimes: vec![first.clone(), second.clone()],
            stop: BTreeMap::from([(first.clone(), false)]),
            ..Default::default()
        };
        let result =
            coordinate_product_uninstall(&request(ProductUninstallMode::AllData), &mut backend)
                .unwrap();
        assert_eq!(
            result.result_class,
            ProductUninstallResultClass::ContactNotStopped
        );
        assert_eq!(result.exit_code, 20);
        assert_eq!(result.verified_runtimes_stopped, 1);
        assert!(backend.calls.contains(&format!("stop:{second}")));
        assert!(backend.calls.contains(&"stop_gateways".into()));
        assert!(!backend.calls.iter().any(|call| call.starts_with("remove:")));
        assert!(!backend.calls.contains(&"cleanup_scan_tools".into()));
        assert!(!backend.calls.contains(&"cleanup_user_data".into()));
    }

    #[test]
    fn incomplete_runtime_inventory_retains_the_controller_before_any_cleanup() {
        let digest = "9".repeat(64);
        let mut backend = FakeBackend {
            runtimes: vec![digest.clone()],
            contact_inventory_incomplete: true,
            ..Default::default()
        };

        let result =
            coordinate_product_uninstall(&request(ProductUninstallMode::AllData), &mut backend)
                .unwrap();

        assert_eq!(result.exit_code, 20);
        assert!(backend.calls.contains(&format!("stop:{digest}")));
        assert!(backend.calls.contains(&"stop_gateways".into()));
        assert!(!backend.calls.contains(&"cleanup_scan_tools".into()));
        assert!(!backend.calls.contains(&"cleanup_user_data".into()));
        assert!(result.retained_items.iter().any(|item| {
            item.item_class == "managed_runtime_state"
                && item.reason_code == "target_contact_inventory_incomplete"
        }));
    }

    #[test]
    fn scan_tools_preserves_user_data_and_reports_incomplete_exact_removal() {
        let digest = "c".repeat(64);
        let mut backend = FakeBackend {
            runtimes: vec![digest.clone()],
            remove: BTreeMap::from([(digest, false)]),
            ..Default::default()
        };
        let result =
            coordinate_product_uninstall(&request(ProductUninstallMode::ScanTools), &mut backend)
                .unwrap();
        assert_eq!(
            result.result_class,
            ProductUninstallResultClass::CompletedWithRetainedState
        );
        assert_eq!(result.exit_code, 10);
        assert!(
            result
                .preserved
                .contains(&"projects_findings_evidence_and_exports")
        );
        assert!(!result.removed.contains(&"verified_scan_tools"));
        assert!(
            result
                .preserved
                .contains(&"ambiguous_or_unremoved_scan_tool_state")
        );
        assert!(!backend.calls.contains(&"cleanup_user_data".into()));
    }

    #[test]
    fn exact_gateway_stop_failure_is_exit_twenty_and_prevents_every_cleanup() {
        let mut backend = FakeBackend {
            gateway_stop: ProductCompatibilityGatewayStopOutcome {
                exact_gateways_found: 2,
                exact_gateways_stopped: 1,
                exact_stop_failures: 1,
                retained_ambiguities: 0,
                contact_inventory_incomplete: false,
            },
            ..Default::default()
        };

        let result =
            coordinate_product_uninstall(&request(ProductUninstallMode::AllData), &mut backend)
                .unwrap();

        assert_eq!(result.exit_code, 20);
        assert_eq!(result.verified_compatibility_gateways_found, 2);
        assert_eq!(result.verified_compatibility_gateways_stopped, 1);
        assert_eq!(backend.calls, vec!["inventory", "stop_gateways"]);
        assert!(!backend.calls.contains(&"cleanup_scan_tools".into()));
        assert!(!backend.calls.contains(&"cleanup_user_data".into()));
    }

    #[test]
    fn incomplete_gateway_inventory_retains_the_controller_before_any_cleanup() {
        let mut backend = FakeBackend {
            gateway_stop: ProductCompatibilityGatewayStopOutcome {
                retained_ambiguities: 1,
                contact_inventory_incomplete: true,
                ..Default::default()
            },
            ..Default::default()
        };

        let result =
            coordinate_product_uninstall(&request(ProductUninstallMode::ScanTools), &mut backend)
                .unwrap();

        assert_eq!(result.exit_code, 20);
        assert_eq!(backend.calls, vec!["inventory", "stop_gateways"]);
        assert!(!backend.calls.contains(&"cleanup_scan_tools".into()));
        assert!(result.retained_items.iter().any(|item| {
            item.item_class == "compatibility_gateway_state"
                && item.reason_code == "target_contact_inventory_incomplete"
        }));
    }

    #[test]
    fn ambiguous_gateway_state_is_exit_ten_but_does_not_block_safe_cleanup() {
        let mut backend = FakeBackend {
            gateway_stop: ProductCompatibilityGatewayStopOutcome {
                retained_ambiguities: 1,
                ..Default::default()
            },
            ..Default::default()
        };

        let result =
            coordinate_product_uninstall(&request(ProductUninstallMode::ScanTools), &mut backend)
                .unwrap();

        assert_eq!(result.exit_code, 10);
        assert!(backend.calls.contains(&"cleanup_scan_tools".into()));
        assert!(!result.removed.contains(&"verified_scan_tools"));
        assert!(
            result
                .preserved
                .contains(&"ambiguous_or_unremoved_scan_tool_state")
        );
        assert!(result.retained_items.iter().any(|item| {
            item.item_class == "compatibility_gateway_state"
                && item.reason_code == "ambiguous_gateway_state_preserved"
        }));
    }

    #[test]
    fn all_data_preserves_the_record_for_ambiguous_gateway_state() {
        let mut backend = FakeBackend {
            gateway_stop: ProductCompatibilityGatewayStopOutcome {
                retained_ambiguities: 1,
                ..Default::default()
            },
            ..Default::default()
        };

        let result =
            coordinate_product_uninstall(&request(ProductUninstallMode::AllData), &mut backend)
                .unwrap();

        assert_eq!(result.exit_code, 10);
        assert_eq!(backend.preserve_gateway_state_on_user_cleanup, Some(true));
        assert!(result.retained_items.iter().any(|item| {
            item.item_class == "compatibility_gateway_state"
                && item.reason_code == "ambiguous_gateway_state_preserved"
        }));
    }

    #[test]
    fn retained_user_data_is_not_reported_as_removed() {
        let mut backend = FakeBackend {
            user_data_residue: vec![ProductUninstallRetainedItem::new(
                "product_data",
                "ambiguous_link_preserved",
            )],
            ..Default::default()
        };

        let result =
            coordinate_product_uninstall(&request(ProductUninstallMode::AllData), &mut backend)
                .unwrap();

        assert_eq!(result.exit_code, 10);
        assert!(!result.removed.contains(&"product_user_data"));
    }

    #[test]
    fn failed_root_finalization_retracts_a_completed_user_data_claim() {
        let mut backend = FakeBackend::default();
        let mut result =
            coordinate_product_uninstall(&request(ProductUninstallMode::AllData), &mut backend)
                .unwrap();
        assert!(result.removed.contains(&"product_user_data"));

        result.record_finalization_retained("product_data", "product_data_root_retained");

        assert_eq!(result.exit_code, 10);
        assert!(!result.removed.contains(&"product_user_data"));
        assert!(result.preserved.contains(&"unremoved_product_user_data"));
    }

    #[test]
    fn ambiguous_runtime_state_is_reported_but_does_not_block_an_exact_stop() {
        let digest = "e".repeat(64);
        let mut backend = FakeBackend {
            runtimes: vec![digest.clone()],
            retained: vec![ProductUninstallRetainedItem::new(
                "managed_runtime_entry",
                "unverified_runtime_entry_preserved",
            )],
            ..Default::default()
        };

        let result =
            coordinate_product_uninstall(&request(ProductUninstallMode::AppOnly), &mut backend)
                .unwrap();

        assert_eq!(result.exit_code, 10);
        assert_eq!(result.verified_runtimes_stopped, 1);
        assert!(backend.calls.contains(&format!("stop:{digest}")));
        assert_eq!(
            result.retained_items[0].reason_code,
            "unverified_runtime_entry_preserved"
        );
    }

    #[test]
    fn successful_all_data_runs_stop_then_runtime_removal_then_user_cleanup() {
        let first = "f".repeat(64);
        let second = "1".repeat(64);
        let mut backend = FakeBackend {
            runtimes: vec![first.clone(), second.clone()],
            ..Default::default()
        };

        let result =
            coordinate_product_uninstall(&request(ProductUninstallMode::AllData), &mut backend)
                .unwrap();

        assert_eq!(result.exit_code, 0);
        assert_eq!(result.verified_runtimes_removed, 2);
        let last_stop = backend
            .calls
            .iter()
            .rposition(|call| call.starts_with("stop:"))
            .unwrap();
        let gateway_stop = backend
            .calls
            .iter()
            .position(|call| call == "stop_gateways")
            .unwrap();
        let first_remove = backend
            .calls
            .iter()
            .position(|call| call.starts_with("remove:"))
            .unwrap();
        let user_cleanup = backend
            .calls
            .iter()
            .position(|call| call == "cleanup_user_data")
            .unwrap();
        assert!(
            last_stop < gateway_stop && gateway_stop < first_remove && first_remove < user_cleanup
        );
    }

    #[test]
    fn corrupt_case_database_is_never_opened_before_runtime_stop() {
        let temporary = tempfile::tempdir().unwrap();
        fs::write(temporary.path().join("casework.db"), b"not sqlite").unwrap();
        let mut backend = FakeBackend {
            runtimes: vec!["d".repeat(64)],
            ..Default::default()
        };
        let result =
            coordinate_product_uninstall(&request(ProductUninstallMode::AppOnly), &mut backend)
                .unwrap();
        assert_eq!(result.verified_runtimes_stopped, 1);
        assert_eq!(
            fs::read(temporary.path().join("casework.db")).unwrap(),
            b"not sqlite"
        );
    }

    #[test]
    fn all_data_keeps_ambiguous_gateway_records_while_removing_other_product_data() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join(PRODUCT_DATA_DIRECTORY_NAME);
        let registry = root
            .join(ARTIFACT_DIRECTORY)
            .join(MANAGED_NETWORK_REGISTRY_DIRECTORY);
        fs::create_dir_all(&registry).unwrap();
        fs::write(registry.join("must-remain"), b"ambiguous gateway record").unwrap();
        fs::write(root.join("casework.db"), b"product data").unwrap();

        let retained = remove_bounded_product_data(&root, true);

        assert!(!root.join("casework.db").exists());
        assert_eq!(
            fs::read(registry.join("must-remain")).unwrap(),
            b"ambiguous gateway record"
        );
        assert!(retained.iter().any(|item| {
            item.item_class == "compatibility_gateway_state"
                && item.reason_code == "ambiguous_gateway_state_preserved"
        }));
    }

    #[cfg(unix)]
    #[test]
    fn all_data_cleanup_does_not_follow_or_remove_an_ambiguous_link() {
        use std::os::unix::fs::symlink;

        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join(PRODUCT_DATA_DIRECTORY_NAME);
        let outside = temporary.path().join("outside");
        fs::create_dir(&root).unwrap();
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("must-remain"), b"user data").unwrap();
        fs::write(root.join("casework.db"), b"corrupt but product-owned").unwrap();
        symlink(&outside, root.join("linked-user-data")).unwrap();

        let retained = remove_bounded_product_data(&root, false);
        assert!(!root.join("casework.db").exists());
        assert!(root.join("linked-user-data").exists());
        assert_eq!(fs::read(outside.join("must-remain")).unwrap(), b"user data");
        assert!(
            retained
                .iter()
                .any(|item| item.reason_code == "ambiguous_link_preserved")
        );
    }

    #[test]
    fn fixed_product_root_validation_rejects_a_sibling_or_nested_override() {
        let temporary = tempfile::tempdir().unwrap();
        let expected = temporary.path().join(PRODUCT_DATA_DIRECTORY_NAME);
        assert!(validate_fixed_product_data_root(&expected, temporary.path()).is_ok());
        assert!(
            validate_fixed_product_data_root(
                &temporary.path().join("some-other-product"),
                temporary.path(),
            )
            .is_err()
        );
        assert!(
            validate_fixed_product_data_root(
                &expected.join(PRODUCT_DATA_DIRECTORY_NAME),
                temporary.path(),
            )
            .is_err()
        );
    }

    #[test]
    fn newly_created_product_root_is_pinned_and_always_leased() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join(PRODUCT_DATA_DIRECTORY_NAME);
        let sibling = temporary.path().join("unrelated-sibling");
        fs::write(&sibling, b"must remain byte-exact").unwrap();

        let (existed_before, guard) =
            prepare_fixed_product_data_root_for_isolated_test(&root, temporary.path()).unwrap();
        assert!(!existed_before);
        #[cfg(windows)]
        let private_verification_guard =
            crate::managed_runtime::ensure_private_product_data_directory_for_isolated_test(&root)
                .expect("product-uninstall must create the absent root with a protected DACL");
        #[cfg(windows)]
        assert!(
            !private_verification_guard.was_created(),
            "verification must observe the exact root prepared by product-uninstall"
        );
        let first = DataDirectoryExclusiveLease::acquire(&root).unwrap();
        assert!(matches!(
            DataDirectoryExclusiveLease::acquire(&root),
            Err(AppError::NotAvailable(_))
        ));

        drop(guard);
        #[cfg(windows)]
        drop(private_verification_guard);
        drop(first);
        assert!(root.exists());
        assert_eq!(fs::read(&sibling).unwrap(), b"must remain byte-exact");
    }

    #[test]
    fn existing_product_root_is_pinned_without_rewriting_product_or_sibling_data() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join(PRODUCT_DATA_DIRECTORY_NAME);
        let product_data = root.join("casework.db");
        let sibling = temporary.path().join("unrelated-sibling");
        {
            #[cfg(windows)]
            let creation_guard =
                crate::managed_runtime::ensure_private_product_data_directory_for_isolated_test(
                    &root,
                )
                .expect("create an existing secure product root fixture");
            #[cfg(not(windows))]
            let creation_guard = ensure_private_product_data_directory(&root)
                .expect("create an existing secure product root fixture");
            assert!(creation_guard.was_created());
        }
        fs::write(&product_data, b"preserved product bytes").unwrap();
        fs::write(&sibling, b"preserved unrelated bytes").unwrap();

        let (existed_before, guard) =
            prepare_fixed_product_data_root_for_isolated_test(&root, temporary.path()).unwrap();

        assert!(existed_before);
        assert_eq!(fs::read(&product_data).unwrap(), b"preserved product bytes");
        assert_eq!(fs::read(&sibling).unwrap(), b"preserved unrelated bytes");
        drop(guard);
    }

    #[cfg(unix)]
    #[test]
    fn fixed_product_root_rejects_a_link_before_creating_its_lease() {
        use std::os::unix::fs::symlink;

        let temporary = tempfile::tempdir().unwrap();
        let outside = temporary.path().join("outside");
        let root = temporary.path().join(PRODUCT_DATA_DIRECTORY_NAME);
        fs::create_dir(&outside).unwrap();
        symlink(&outside, &root).unwrap();

        assert!(prepare_fixed_product_data_root(&root, temporary.path()).is_err());
        assert!(!outside.join(DATA_DIRECTORY_LEASE_FILE).exists());
    }

    #[cfg(windows)]
    #[test]
    fn fixed_product_root_rejects_a_windows_junction_before_creating_its_lease() {
        let temporary = tempfile::tempdir().unwrap();
        let outside = temporary.path().join("outside");
        let root = temporary.path().join(PRODUCT_DATA_DIRECTORY_NAME);
        fs::create_dir(&outside).unwrap();
        create_windows_directory_junction(&root, &outside);

        assert!(prepare_fixed_product_data_root(&root, temporary.path()).is_err());
        assert!(!outside.join(DATA_DIRECTORY_LEASE_FILE).exists());
    }

    #[test]
    fn over_limit_runtime_inventory_cannot_authorize_cleanup() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join(PRODUCT_DATA_DIRECTORY_NAME);
        let versions = root
            .join(MANAGED_RUNTIME_DIRECTORY)
            .join(MANAGED_RUNTIME_VERSIONS_DIRECTORY);
        fs::create_dir_all(&versions).unwrap();
        for index in 0..=MAX_INSTALLED_RUNTIME_ENTRIES {
            fs::create_dir(versions.join(format!("runtime-{index:02}"))).unwrap();
        }
        let mut backend = LocalProductUninstallBackend::new(root);

        let inventory = backend.inventory_runtimes().unwrap();

        assert!(inventory.contact_inventory_incomplete);
        assert!(inventory.retained.iter().any(|item| {
            item.item_class == "managed_runtime_state"
                && item.reason_code == "runtime_inventory_limit_reached"
        }));
    }

    #[test]
    fn empty_versions_with_legacy_provider_is_reported_and_preserved() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join(PRODUCT_DATA_DIRECTORY_NAME);
        let managed = root.join(MANAGED_RUNTIME_DIRECTORY);
        let versions = managed.join(MANAGED_RUNTIME_VERSIONS_DIRECTORY);
        let provider = managed
            .join(MANAGED_RUNTIME_PROVIDER_DIRECTORY)
            .join("8b2257ace33ecb14");
        let sentinel = provider.join("must-remain");
        fs::create_dir_all(&versions).unwrap();
        fs::create_dir_all(&provider).unwrap();
        fs::write(&sentinel, b"ambiguous legacy runtime").unwrap();

        let mut inventory_backend = LocalProductUninstallBackend::new(root.clone());
        let inventory = inventory_backend.inventory_runtimes().unwrap();

        assert!(inventory.verified_manifest_sha256.is_empty());
        assert!(!inventory.contact_inventory_incomplete);
        assert!(inventory.retained.iter().any(|item| {
            item.item_class == "managed_runtime_state"
                && item.reason_code == "runtime_ownership_unavailable"
        }));
        assert_eq!(fs::read(&sentinel).unwrap(), b"ambiguous legacy runtime");

        let mut uninstall_backend = LocalProductUninstallBackend::new(root);
        let result = coordinate_product_uninstall(
            &request(ProductUninstallMode::AppOnly),
            &mut uninstall_backend,
        )
        .unwrap();

        assert_eq!(result.exit_code, PRODUCT_UNINSTALL_RETAINED_EXIT_CODE);
        assert_eq!(
            result.result_class,
            ProductUninstallResultClass::CompletedWithRetainedState
        );
        assert!(result.retained_items.iter().any(|item| {
            item.item_class == "managed_runtime_state"
                && item.reason_code == "runtime_ownership_unavailable"
        }));
        assert_eq!(fs::read(&sentinel).unwrap(), b"ambiguous legacy runtime");
    }

    #[test]
    fn empty_versions_without_provider_residue_remains_completed() {
        for create_empty_provider in [false, true] {
            let temporary = tempfile::tempdir().unwrap();
            let root = temporary.path().join(PRODUCT_DATA_DIRECTORY_NAME);
            let managed = root.join(MANAGED_RUNTIME_DIRECTORY);
            fs::create_dir_all(managed.join(MANAGED_RUNTIME_VERSIONS_DIRECTORY)).unwrap();
            if create_empty_provider {
                fs::create_dir(managed.join(MANAGED_RUNTIME_PROVIDER_DIRECTORY)).unwrap();
            }

            let mut backend = LocalProductUninstallBackend::new(root);
            let result =
                coordinate_product_uninstall(&request(ProductUninstallMode::AppOnly), &mut backend)
                    .unwrap();

            assert_eq!(result.exit_code, PRODUCT_UNINSTALL_COMPLETED_EXIT_CODE);
            assert_eq!(result.result_class, ProductUninstallResultClass::Completed);
            assert!(result.retained_items.is_empty());
        }
    }

    #[cfg(unix)]
    #[test]
    fn scan_tool_residue_preserves_a_linked_managed_root_and_target() {
        use std::os::unix::fs::symlink;

        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join(PRODUCT_DATA_DIRECTORY_NAME);
        let outside = temporary.path().join("outside-runtime");
        fs::create_dir(&root).unwrap();
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("must-remain"), b"unrelated").unwrap();
        symlink(&outside, root.join(MANAGED_RUNTIME_DIRECTORY)).unwrap();
        let mut backend = LocalProductUninstallBackend::new(root.clone());

        let retained = backend.cleanup_scan_tool_residue();

        assert!(root.join(MANAGED_RUNTIME_DIRECTORY).exists());
        assert_eq!(fs::read(outside.join("must-remain")).unwrap(), b"unrelated");
        assert!(retained.iter().any(|item| {
            item.item_class == "managed_runtime_state"
                && item.reason_code == "ambiguous_runtime_root_preserved"
        }));
    }

    #[cfg(unix)]
    #[test]
    fn scan_tool_inventory_and_cleanup_preserve_a_linked_provider_home() {
        use std::os::unix::fs::symlink;

        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join(PRODUCT_DATA_DIRECTORY_NAME);
        let managed = root.join(MANAGED_RUNTIME_DIRECTORY);
        let outside = temporary.path().join("outside-provider-home");
        fs::create_dir_all(&managed).unwrap();
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("must-remain"), b"unrelated").unwrap();
        symlink(&outside, managed.join(MANAGED_RUNTIME_PROVIDER_DIRECTORY)).unwrap();
        let mut backend = LocalProductUninstallBackend::new(root);

        let inventory = backend.inventory_runtimes().unwrap();
        let retained = backend.cleanup_scan_tool_residue();

        assert!(inventory.retained.iter().any(|item| {
            item.item_class == "managed_runtime_entry"
                && item.reason_code == "ambiguous_runtime_entry_preserved"
        }));
        assert!(retained.iter().any(|item| {
            item.item_class == "managed_runtime_entry"
                && item.reason_code == "ambiguous_runtime_entry_preserved"
        }));
        assert_eq!(fs::read(outside.join("must-remain")).unwrap(), b"unrelated");
        assert!(managed.join(MANAGED_RUNTIME_PROVIDER_DIRECTORY).exists());
    }

    #[cfg(windows)]
    #[test]
    fn scan_tool_inventory_and_cleanup_preserve_windows_runtime_junctions() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join(PRODUCT_DATA_DIRECTORY_NAME);
        let outside_managed = temporary.path().join("outside-managed");
        fs::create_dir(&root).unwrap();
        fs::create_dir(&outside_managed).unwrap();
        fs::write(outside_managed.join("must-remain"), b"unrelated").unwrap();
        create_windows_directory_junction(&root.join(MANAGED_RUNTIME_DIRECTORY), &outside_managed);
        let mut backend = LocalProductUninstallBackend::new(root.clone());

        let inventory = backend.inventory_runtimes().unwrap();
        let retained = backend.cleanup_scan_tool_residue();

        assert!(inventory.retained.iter().any(|item| {
            item.item_class == "managed_runtime_state"
                && item.reason_code == "ambiguous_runtime_root_preserved"
        }));
        assert!(retained.iter().any(|item| {
            item.item_class == "managed_runtime_state"
                && item.reason_code == "ambiguous_runtime_root_preserved"
        }));
        assert_eq!(
            fs::read(outside_managed.join("must-remain")).unwrap(),
            b"unrelated"
        );

        fs::remove_dir(root.join(MANAGED_RUNTIME_DIRECTORY)).unwrap();
        let managed = root.join(MANAGED_RUNTIME_DIRECTORY);
        let outside_provider = temporary.path().join("outside-provider");
        fs::create_dir(&managed).unwrap();
        fs::create_dir(&outside_provider).unwrap();
        fs::write(outside_provider.join("must-remain"), b"unrelated").unwrap();
        create_windows_directory_junction(
            &managed.join(MANAGED_RUNTIME_PROVIDER_DIRECTORY),
            &outside_provider,
        );
        let mut backend = LocalProductUninstallBackend::new(root);

        let inventory = backend.inventory_runtimes().unwrap();
        let retained = backend.cleanup_scan_tool_residue();

        assert!(inventory.retained.iter().any(|item| {
            item.item_class == "managed_runtime_entry"
                && item.reason_code == "ambiguous_runtime_entry_preserved"
        }));
        assert!(retained.iter().any(|item| {
            item.item_class == "managed_runtime_entry"
                && item.reason_code == "ambiguous_runtime_entry_preserved"
        }));
        assert_eq!(
            fs::read(outside_provider.join("must-remain")).unwrap(),
            b"unrelated"
        );
    }

    #[cfg(windows)]
    #[test]
    fn successful_all_data_finalization_removes_only_the_empty_exact_root() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join(PRODUCT_DATA_DIRECTORY_NAME);
        let (_, root_guard) =
            prepare_fixed_product_data_root_for_isolated_test(&root, temporary.path()).unwrap();
        let lease = DataDirectoryExclusiveLease::acquire(&root).unwrap();
        drop(root_guard);
        let staged = stage_all_data_root_for_finalization(&root, &lease).unwrap();
        let staged_path = staged.path().to_path_buf();
        drop(lease);

        assert!(finalize_all_data_root(&staged).is_empty());
        assert!(!staged_path.exists());
        assert!(temporary.path().exists());
    }

    #[cfg(windows)]
    #[test]
    fn failed_root_handle_transition_restores_the_live_lease_for_a_safe_retry() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join(PRODUCT_DATA_DIRECTORY_NAME);
        let (_, external_guard) =
            prepare_fixed_product_data_root_for_isolated_test(&root, temporary.path()).unwrap();
        let lease = DataDirectoryExclusiveLease::acquire(&root).unwrap();

        // This reproduces a caller retaining the ordinary no-delete guard. The
        // DELETE-capable staging handle cannot open, and staging must fail
        // without consuming the sentinel or moving the root.
        assert!(stage_all_data_root_for_finalization(&root, &lease).is_err());
        assert!(root.is_dir());
        assert!(root.join(DATA_DIRECTORY_LEASE_FILE).is_file());
        assert!(matches!(
            DataDirectoryExclusiveLease::acquire(&root),
            Err(AppError::NotAvailable(_))
        ));

        drop(external_guard);
        let staged = stage_all_data_root_for_finalization(&root, &lease).unwrap();
        drop(lease);
        assert!(finalize_all_data_root(&staged).is_empty());
    }

    #[cfg(windows)]
    #[test]
    fn staged_finalization_cannot_delete_a_newly_recreated_canonical_root() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join(PRODUCT_DATA_DIRECTORY_NAME);
        let first = DataDirectoryExclusiveLease::acquire(&root).unwrap();

        let staged = stage_all_data_root_for_finalization(&root, &first).unwrap();
        assert!(!root.exists());
        assert!(staged.path().exists());

        // Acquiring recreates the canonical path, so this assertion proves the
        // lifetime mutex is keyed to the canonical namespace rather than only
        // the now-renamed directory object or its former sentinel.
        assert!(matches!(
            DataDirectoryExclusiveLease::acquire(&root),
            Err(AppError::NotAvailable(_))
        ));

        // The Windows namespace mutex deliberately continues to own the
        // canonical path until the lease is dropped, even after its directory
        // has been staged. A replacement process may acquire only afterward.
        drop(first);
        let second = DataDirectoryExclusiveLease::acquire(&root).unwrap();
        fs::write(root.join("new-process-data"), b"must remain").unwrap();
        assert!(finalize_all_data_root(&staged).is_empty());

        assert_eq!(
            fs::read(root.join("new-process-data")).unwrap(),
            b"must remain"
        );
        drop(second);
    }

    #[cfg(windows)]
    #[test]
    fn staging_refuses_a_preexisting_destination_without_touching_either_root() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join(PRODUCT_DATA_DIRECTORY_NAME);
        let lease = DataDirectoryExclusiveLease::acquire(&root).unwrap();
        let staging_id = uuid::Uuid::from_u128(0x9a4e_7fb9_0f21_4ea6_8d17_018b_b521_4763);
        let staged = temporary.path().join(format!(
            ".{PRODUCT_DATA_DIRECTORY_NAME}.uninstall-staged-{}",
            staging_id.hyphenated()
        ));
        fs::create_dir(&staged).unwrap();
        fs::write(staged.join("unrelated"), b"must remain").unwrap();

        assert!(stage_all_data_root_for_finalization_with_id(&root, &lease, staging_id).is_err());
        assert!(root.is_dir());
        assert_eq!(fs::read(staged.join("unrelated")).unwrap(), b"must remain");
        drop(lease);
    }

    #[cfg(not(windows))]
    #[test]
    fn all_data_staging_fails_closed_without_pathname_mutation() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join(PRODUCT_DATA_DIRECTORY_NAME);
        let lease = DataDirectoryExclusiveLease::acquire(&root).unwrap();
        let lease_path = root.join(DATA_DIRECTORY_LEASE_FILE);
        let before = fs::read(&lease_path).unwrap();

        let error = stage_all_data_root_for_finalization(&root, &lease)
            .expect_err("non-Windows finalization must retain the canonical root");

        assert!(matches!(error, AppError::NotAvailable(_)));
        assert!(root.is_dir());
        assert_eq!(fs::read(&lease_path).unwrap(), before);
        assert_eq!(
            fs::read_dir(temporary.path()).unwrap().count(),
            1,
            "fail-closed staging must not create a pathname-based staged root"
        );
        drop(lease);
    }

    #[cfg(windows)]
    #[test]
    fn pinned_handle_rename_never_replaces_a_late_directory_collision() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join(PRODUCT_DATA_DIRECTORY_NAME);
        let lease = DataDirectoryExclusiveLease::acquire(&root).unwrap();
        let destination_leaf =
            std::ffi::OsStr::new(".ai-security-scanner.uninstall-staged-late-directory-collision");
        let destination = temporary.path().join(destination_leaf);

        // This models the destination appearing after the path precheck but
        // before the one namespace operation.
        fs::create_dir(&destination).unwrap();
        fs::write(destination.join("unrelated"), b"must remain").unwrap();
        let source = lease.prepare_windows_directory_for_staging().unwrap();

        assert!(
            windows_rename_handle_no_replace(&source, lease.windows_parent(), destination_leaf,)
                .is_err()
        );
        assert!(root.is_dir());
        assert_eq!(
            fs::read(destination.join("unrelated")).unwrap(),
            b"must remain"
        );
        drop(source);
        drop(lease);
        drop(DataDirectoryExclusiveLease::acquire(&root).unwrap());
    }

    #[cfg(windows)]
    #[test]
    fn pinned_handle_rename_never_replaces_a_late_junction_collision() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join(PRODUCT_DATA_DIRECTORY_NAME);
        let outside = temporary.path().join("outside");
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("unrelated"), b"must remain").unwrap();
        let lease = DataDirectoryExclusiveLease::acquire(&root).unwrap();
        let destination_leaf =
            std::ffi::OsStr::new(".ai-security-scanner.uninstall-staged-late-junction-collision");
        let destination = temporary.path().join(destination_leaf);

        // This models a junction swap after the staging-path precheck. The
        // no-replace handle rename must fail without traversing the junction.
        create_windows_directory_junction(&destination, &outside);
        let source = lease.prepare_windows_directory_for_staging().unwrap();

        assert!(
            windows_rename_handle_no_replace(&source, lease.windows_parent(), destination_leaf,)
                .is_err()
        );
        assert!(root.is_dir());
        assert_eq!(fs::read(outside.join("unrelated")).unwrap(), b"must remain");

        // remove_dir removes the junction itself and never follows it.
        fs::remove_dir(&destination).unwrap();
        assert!(outside.is_dir());
        drop(source);
        drop(lease);
        drop(DataDirectoryExclusiveLease::acquire(&root).unwrap());
    }

    #[cfg(windows)]
    #[test]
    fn finalization_deletes_only_the_pinned_staged_identity_after_path_replacement() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join(PRODUCT_DATA_DIRECTORY_NAME);
        let lease = DataDirectoryExclusiveLease::acquire(&root).unwrap();
        let staged = stage_all_data_root_for_finalization(&root, &lease).unwrap();
        let staged_path = staged.path().to_path_buf();
        let moved_original = temporary.path().join("moved-original-staged-root");
        drop(lease);

        fs::rename(&staged_path, &moved_original).unwrap();
        fs::create_dir(&staged_path).unwrap();
        fs::write(
            staged_path.join(DATA_DIRECTORY_LEASE_FILE),
            b"not product data",
        )
        .unwrap();

        assert!(finalize_all_data_root(&staged).is_empty());
        assert!(!moved_original.exists());
        assert_eq!(
            fs::read(staged_path.join(DATA_DIRECTORY_LEASE_FILE)).unwrap(),
            b"not product data"
        );
    }

    #[cfg(windows)]
    #[test]
    fn restart_discards_a_prepared_journal_when_the_canonical_identity_never_moved() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join(PRODUCT_DATA_DIRECTORY_NAME);
        let first = DataDirectoryExclusiveLease::acquire(&root).unwrap();
        let first_id = uuid::Uuid::from_u128(0x0100_0000_0000_4000_8000_0000_0000_0001);
        let expected_staged = temporary.path().join(format!(
            ".{PRODUCT_DATA_DIRECTORY_NAME}.uninstall-staged-{}",
            first_id.hyphenated()
        ));
        let data_root_guard = open_directory_no_follow(&root).unwrap();
        let identity = windows_file_identity(&data_root_guard).unwrap();
        let journal = AllDataStageJournal {
            schema_version: ALL_DATA_STAGE_JOURNAL_SCHEMA_VERSION,
            staging_id: first_id.hyphenated().to_string(),
            destination_leaf: expected_staged
                .file_name()
                .unwrap()
                .to_string_lossy()
                .into_owned(),
            volume_serial_number: identity.0,
            file_id_hex: hex::encode(identity.1),
            state: AllDataStageJournalState::Prepared,
        };
        let fixed_journal = create_windows_all_data_stage_journal(
            &root,
            temporary.path(),
            first.windows_parent(),
            first_id,
            &journal,
        )
        .unwrap();
        drop(fixed_journal);
        drop(data_root_guard);
        drop(first);
        assert!(!expected_staged.exists());

        let second = DataDirectoryExclusiveLease::acquire(&root).unwrap();
        let second_id = uuid::Uuid::from_u128(0x0200_0000_0000_4000_8000_0000_0000_0002);
        let staged =
            stage_all_data_root_for_finalization_with_id(&root, &second, second_id).unwrap();

        assert!(!expected_staged.exists());
        drop(second);
        assert!(finalize_all_data_root(&staged).is_empty());
        assert!(!temporary.path().join(ALL_DATA_STAGE_JOURNAL_FILE).exists());
    }

    #[cfg(windows)]
    #[test]
    fn restart_recovers_one_durably_journaled_staged_root_before_staging_again() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join(PRODUCT_DATA_DIRECTORY_NAME);
        let first = DataDirectoryExclusiveLease::acquire(&root).unwrap();
        let first_id = uuid::Uuid::from_u128(0x1000_0000_0000_4000_8000_0000_0000_0001);
        let interrupted =
            stage_all_data_root_for_finalization_with_id(&root, &first, first_id).unwrap();
        let interrupted_path = interrupted.path().to_path_buf();
        let journal_path = temporary.path().join(ALL_DATA_STAGE_JOURNAL_FILE);

        // Dropping live handles without finalization models process death: the
        // staged root and synced journal remain, but no in-memory identity does.
        drop(interrupted);
        drop(first);
        assert!(interrupted_path.is_dir());
        assert!(journal_path.is_file());

        let second = DataDirectoryExclusiveLease::acquire(&root).unwrap();
        let second_id = uuid::Uuid::from_u128(0x2000_0000_0000_4000_8000_0000_0000_0002);
        let staged =
            stage_all_data_root_for_finalization_with_id(&root, &second, second_id).unwrap();

        assert!(!interrupted_path.exists());
        assert!(staged.path().is_dir());
        drop(second);
        assert!(finalize_all_data_root(&staged).is_empty());
        assert!(!journal_path.exists());
    }

    #[cfg(windows)]
    #[test]
    fn restart_preserves_a_replacement_at_the_journaled_staged_path() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join(PRODUCT_DATA_DIRECTORY_NAME);
        let first = DataDirectoryExclusiveLease::acquire(&root).unwrap();
        let first_id = uuid::Uuid::from_u128(0x3000_0000_0000_4000_8000_0000_0000_0003);
        let interrupted =
            stage_all_data_root_for_finalization_with_id(&root, &first, first_id).unwrap();
        let interrupted_path = interrupted.path().to_path_buf();
        let moved_original = temporary.path().join("moved-interrupted-product-root");
        let journal_path = temporary.path().join(ALL_DATA_STAGE_JOURNAL_FILE);
        drop(interrupted);
        drop(first);

        fs::rename(&interrupted_path, &moved_original).unwrap();
        fs::create_dir(&interrupted_path).unwrap();
        fs::write(interrupted_path.join("unrelated"), b"must remain").unwrap();

        let second = DataDirectoryExclusiveLease::acquire(&root).unwrap();
        assert!(stage_all_data_root_for_finalization(&root, &second).is_err());
        assert_eq!(
            fs::read(interrupted_path.join("unrelated")).unwrap(),
            b"must remain"
        );
        assert!(moved_original.is_dir());
        assert!(journal_path.is_file());
        drop(second);
    }

    #[cfg(windows)]
    #[test]
    fn restart_retains_a_delete_authorized_journal_when_the_root_is_absent() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join(PRODUCT_DATA_DIRECTORY_NAME);
        let first = DataDirectoryExclusiveLease::acquire(&root).unwrap();
        let first_id = uuid::Uuid::from_u128(0x4000_0000_0000_4000_8000_0000_0000_0004);
        let interrupted =
            stage_all_data_root_for_finalization_with_id(&root, &first, first_id).unwrap();
        let interrupted_path = interrupted.path().to_path_buf();
        let journal_path = temporary.path().join(ALL_DATA_STAGE_JOURNAL_FILE);

        // Model a crash after exact root deletion but before journal deletion.
        let directory = interrupted.directory.lock().unwrap().take().unwrap();
        windows_delete_file_or_empty_directory_handle(&directory).unwrap();
        drop(directory);
        drop(interrupted);
        drop(first);
        assert!(!interrupted_path.exists());
        assert!(journal_path.is_file());

        let second = DataDirectoryExclusiveLease::acquire(&root).unwrap();
        assert!(stage_all_data_root_for_finalization(&root, &second).is_err());
        drop(second);
        assert!(journal_path.is_file());
    }

    #[cfg(windows)]
    #[test]
    fn restart_preserves_a_journaled_stage_renamed_outside_its_exact_leaf() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join(PRODUCT_DATA_DIRECTORY_NAME);
        let first = DataDirectoryExclusiveLease::acquire(&root).unwrap();
        let first_id = uuid::Uuid::from_u128(0x5000_0000_0000_4000_8000_0000_0000_0005);
        let interrupted =
            stage_all_data_root_for_finalization_with_id(&root, &first, first_id).unwrap();
        let interrupted_path = interrupted.path().to_path_buf();
        let unrelated_path = temporary.path().join("renamed-away-from-staging-prefix");
        let journal_path = temporary.path().join(ALL_DATA_STAGE_JOURNAL_FILE);
        drop(interrupted);
        drop(first);

        fs::rename(&interrupted_path, &unrelated_path).unwrap();
        let second = DataDirectoryExclusiveLease::acquire(&root).unwrap();
        let second_id = uuid::Uuid::from_u128(0x5100_0000_0000_4000_8000_0000_0000_0005);
        let error = stage_all_data_root_for_finalization_with_id(&root, &second, second_id)
            .expect_err("recovery must not chase a journaled identity to another parent leaf");
        assert!(matches!(error, AppError::NotAvailable(_)));
        assert!(unrelated_path.is_dir());
        assert!(journal_path.is_file());
        assert!(root.join(DATA_DIRECTORY_LEASE_FILE).is_file());
        drop(second);
    }

    #[cfg(windows)]
    #[test]
    fn restart_repairs_a_partial_append_only_authorization_record() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join(PRODUCT_DATA_DIRECTORY_NAME);
        let first = DataDirectoryExclusiveLease::acquire(&root).unwrap();
        let first_id = uuid::Uuid::from_u128(0x6000_0000_0000_4000_8000_0000_0000_0006);
        let interrupted =
            stage_all_data_root_for_finalization_with_id(&root, &first, first_id).unwrap();
        let interrupted_path = interrupted.path().to_path_buf();
        let journal_path = temporary.path().join(ALL_DATA_STAGE_JOURNAL_FILE);
        drop(interrupted);
        drop(first);

        // Model power/process loss part-way through only the append-only state
        // record. The complete synced Prepared JSON frame remains untouched.
        let mut journal = open_windows_all_data_stage_journal(&journal_path, false, false).unwrap();
        let parsed = read_windows_all_data_stage_journal(&mut journal).unwrap();
        assert_eq!(
            parsed.journal.state,
            AllDataStageJournalState::DeleteAuthorized
        );
        journal.set_len(parsed.prepared_frame_len).unwrap();
        journal
            .seek(SeekFrom::Start(parsed.prepared_frame_len))
            .unwrap();
        journal
            .write_all(&ALL_DATA_STAGE_DELETE_AUTHORIZED_RECORD[..7])
            .unwrap();
        journal.sync_all().unwrap();
        drop(journal);

        let second = DataDirectoryExclusiveLease::acquire(&root).unwrap();
        let second_id = uuid::Uuid::from_u128(0x7000_0000_0000_4000_8000_0000_0000_0007);
        let staged =
            stage_all_data_root_for_finalization_with_id(&root, &second, second_id).unwrap();
        assert!(!interrupted_path.exists());
        drop(second);
        assert!(finalize_all_data_root(&staged).is_empty());
        assert!(!journal_path.exists());
    }

    #[cfg(windows)]
    #[test]
    fn restart_recovers_case_only_renamed_candidate_and_journal() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join(PRODUCT_DATA_DIRECTORY_NAME);
        let first = DataDirectoryExclusiveLease::acquire(&root).unwrap();
        let first_id = uuid::Uuid::from_u128(0x8000_0000_0000_4000_8000_0000_0000_0008);
        let interrupted =
            stage_all_data_root_for_finalization_with_id(&root, &first, first_id).unwrap();
        let interrupted_path = interrupted.path().to_path_buf();
        let journal_path = temporary.path().join(ALL_DATA_STAGE_JOURNAL_FILE);
        drop(interrupted);
        drop(first);

        // NTFS normally resolves these names case-insensitively. Use a neutral
        // intermediate name so the directory entries actually retain a case-
        // variant spelling for the bounded recovery inventory.
        let candidate_intermediate = temporary.path().join("case-candidate-intermediate");
        fs::rename(&interrupted_path, &candidate_intermediate).unwrap();
        let case_candidate = temporary.path().join(
            interrupted_path
                .file_name()
                .unwrap()
                .to_string_lossy()
                .to_uppercase(),
        );
        fs::rename(&candidate_intermediate, &case_candidate).unwrap();
        let journal_intermediate = temporary.path().join("case-journal-intermediate");
        fs::rename(&journal_path, &journal_intermediate).unwrap();
        let case_journal = temporary
            .path()
            .join(ALL_DATA_STAGE_JOURNAL_FILE.to_uppercase());
        fs::rename(&journal_intermediate, &case_journal).unwrap();

        let second = DataDirectoryExclusiveLease::acquire(&root).unwrap();
        let second_id = uuid::Uuid::from_u128(0x9000_0000_0000_4000_8000_0000_0000_0009);
        let staged =
            stage_all_data_root_for_finalization_with_id(&root, &second, second_id).unwrap();
        assert!(!case_candidate.exists());
        drop(second);
        assert!(finalize_all_data_root(&staged).is_empty());
        assert!(!case_journal.exists());
    }
}
