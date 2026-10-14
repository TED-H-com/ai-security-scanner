use crate::container_runtime::validate_static_manifest_command;
use crate::domain::{
    AssetKind, EngineAdmissionIssue, EngineManifest, LocalInputProfile,
    MAX_ENGINE_EXECUTION_CPU_MILLIS, MAX_ENGINE_EXECUTION_TIMEOUT_SECONDS,
    MIN_ENGINE_EXECUTION_CPU_MILLIS, MIN_ENGINE_EXECUTION_TIMEOUT_SECONDS, ScanPermission,
};
use crate::error::{AppError, AppResult};
use chrono::NaiveDate;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

const KNOWN_ENGINE_IDS: [&str; 25] = [
    "cloudquery",
    "steampipe",
    "prowler",
    "scoutsuite",
    "cloudsplaining",
    "scubagear",
    "maester",
    "naabu",
    "httpx",
    "nuclei",
    "greenbone",
    "zap",
    "semgrep",
    "gitleaks",
    "trufflehog",
    "checkov",
    "kics",
    "trivy",
    "grype",
    "syft",
    "kubescape",
    "kube-bench",
    "garak",
    "agentic-radar",
    "mcp-armor",
];

const AWS_ONLY_ENGINE_IDS: [&str; 4] = ["cloudquery", "steampipe", "scoutsuite", "cloudsplaining"];
const MICROSOFT365_ONLY_ENGINE_IDS: [&str; 2] = ["scubagear", "maester"];
const NAABU_LAUNCHER_JOURNAL_VERSION: u32 = 2;
const NAABU_LAUNCHER_JOURNAL_COMMAND: [&str; 10] = [
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
];

const BUILTIN_CATALOG: &str = include_str!("../../engines/catalog.json");

/// Upstream's own spelling for one packaged engine id, or `None` for an id this
/// build does not ship.
///
/// The shared report cites the projects it ran, so it needs their names rather
/// than a humanized identifier: title-casing `httpx`, `kics`, `scoutsuite`,
/// `scubagear` and `kube-bench` printed five scanners under names their own
/// projects do not use. Reading the packaged catalog instead of keeping a
/// second list means a renamed engine cannot leave the report spelling it the
/// old way.
pub fn builtin_display_name(engine_id: &str) -> Option<&'static str> {
    static NAMES: OnceLock<BTreeMap<String, String>> = OnceLock::new();
    NAMES
        .get_or_init(|| {
            serde_json::from_str::<Vec<Value>>(BUILTIN_CATALOG)
                .into_iter()
                .flatten()
                .filter_map(|entry| {
                    let id = entry.get("id")?.as_str()?.to_owned();
                    let name = entry.get("display_name")?.as_str()?.to_owned();
                    Some((id, name))
                })
                .collect()
        })
        .get(engine_id)
        .map(String::as_str)
}

#[derive(Debug)]
pub struct EngineRegistry {
    manifests: Vec<EngineManifest>,
    admission_issues: Vec<EngineAdmissionIssue>,
}

impl EngineRegistry {
    /// Construct a registry with no catalog-backed engines available.
    ///
    /// The desktop uses this degraded state when the embedded catalog cannot
    /// be loaded. Non-catalog product paths remain usable while readiness and
    /// planning naturally expose no catalog-backed checks.
    pub fn empty() -> Self {
        Self {
            manifests: Vec::new(),
            admission_issues: Vec::new(),
        }
    }

    pub fn load_builtin() -> AppResult<Self> {
        Self::load_catalog(BUILTIN_CATALOG)
    }

    pub(crate) fn load_catalog(catalog: &str) -> AppResult<Self> {
        let document: Value = match serde_json::from_str(catalog) {
            Ok(document) => document,
            Err(error) => {
                return Ok(Self::catalog_container_unavailable(format!(
                    "the packaged engine catalog is not valid JSON: {error}"
                )));
            }
        };
        let Some(entries) = document.as_array() else {
            return Ok(Self::catalog_container_unavailable(
                "the packaged engine catalog root is not an array".into(),
            ));
        };
        let known_ids = KNOWN_ENGINE_IDS.into_iter().collect::<BTreeSet<_>>();
        let mut canonical_occurrences = BTreeMap::<String, usize>::new();
        let mut manifests = Vec::new();
        let mut admission_issues = Vec::new();

        // Resolve only present catalog IDs to supported coordinates before
        // decoding any entry. Whitespace never makes an ID admissible, but it
        // still identifies the supported coordinate that was packaged
        // incorrectly. A valid entry beside any such duplicate is ambiguous,
        // so ordering never decides which executable contract is trusted.
        for entry in entries {
            if let Some(id) = entry.get("id").and_then(Value::as_str)
                && let Some(coordinate) = supported_coordinate(id)
            {
                *canonical_occurrences
                    .entry(coordinate.to_owned())
                    .or_insert(0) += 1;
            }
        }
        let duplicate_ids = canonical_occurrences
            .iter()
            .filter(|(_, count)| **count > 1)
            .map(|(id, _)| id.clone())
            .collect::<BTreeSet<_>>();
        for engine_id in &duplicate_ids {
            admission_issues.push(EngineAdmissionIssue {
                engine_id: Some(engine_id.clone()),
                code: "duplicate_engine_id".into(),
                detail: format!(
                    "the packaged catalog contains {} entries for this supported engine coordinate; the coordinate was disabled",
                    canonical_occurrences[engine_id]
                ),
            });
        }

        for (index, entry) in entries.iter().cloned().enumerate() {
            let candidate_id = entry
                .get("id")
                .and_then(Value::as_str)
                .filter(|id| !id.is_empty())
                .map(str::to_owned);
            let candidate_coordinate = candidate_id
                .as_deref()
                .and_then(supported_coordinate)
                .map(str::to_owned);
            if candidate_coordinate
                .as_ref()
                .is_some_and(|id| duplicate_ids.contains(id))
            {
                continue;
            }
            if let (Some(candidate_id), Some(coordinate)) =
                (candidate_id.as_deref(), candidate_coordinate.as_deref())
                && candidate_id != coordinate
            {
                admission_issues.push(EngineAdmissionIssue {
                    engine_id: Some(coordinate.to_owned()),
                    code: "noncanonical_engine_id".into(),
                    detail: "the packaged engine ID contains leading or trailing whitespace; the coordinate was disabled"
                        .into(),
                });
                continue;
            }
            let manifest = match serde_json::from_value::<EngineManifest>(entry) {
                Ok(manifest) => manifest,
                Err(error) => {
                    admission_issues.push(EngineAdmissionIssue {
                        engine_id: candidate_coordinate.or(candidate_id),
                        code: "catalog_entry_invalid".into(),
                        detail: format!(
                            "catalog entry {} could not be decoded and was isolated: {error}",
                            index + 1
                        ),
                    });
                    continue;
                }
            };
            if !known_ids.contains(manifest.id.as_str()) {
                admission_issues.push(EngineAdmissionIssue {
                    engine_id: Some(manifest.id.clone()),
                    code: "unsupported_engine_id".into(),
                    detail: "the engine ID is not a product-supported catalog coordinate".into(),
                });
                continue;
            }
            if let Err(error) = validate_release_contract(&manifest) {
                admission_issues.push(EngineAdmissionIssue {
                    engine_id: Some(manifest.id.clone()),
                    code: "engine_contract_invalid".into(),
                    detail: error.to_string(),
                });
                continue;
            }
            manifests.push(manifest);
        }
        manifests.sort_by_key(|manifest| {
            KNOWN_ENGINE_IDS
                .iter()
                .position(|engine_id| *engine_id == manifest.id)
                .unwrap_or(usize::MAX)
        });

        Ok(Self {
            manifests,
            admission_issues,
        })
    }

    pub fn manifests(&self) -> &[EngineManifest] {
        &self.manifests
    }

    pub fn get(&self, id: &str) -> Option<&EngineManifest> {
        self.manifests.iter().find(|manifest| manifest.id == id)
    }

    pub fn admission_issues(&self) -> &[EngineAdmissionIssue] {
        &self.admission_issues
    }

    /// Freeze only supported coordinates that were present but rejected into
    /// a scan. Optional absent coordinates never become inferred coverage
    /// claims, and unknown extras stay observable only in current diagnostics.
    /// A malformed catalog container is retained once rather than expanded
    /// into synthetic per-engine tasks.
    pub fn run_bound_admission_issues(&self) -> Vec<EngineAdmissionIssue> {
        if let Some(issue) = self
            .admission_issues
            .iter()
            .find(|issue| issue.code == "catalog_container_invalid")
        {
            return vec![issue.clone()];
        }
        let mut retained = self
            .admission_issues
            .iter()
            .filter(|issue| {
                issue.engine_id.as_deref().is_some_and(|engine_id| {
                    KNOWN_ENGINE_IDS.contains(&engine_id) && self.get(engine_id).is_none()
                })
            })
            .cloned()
            .collect::<Vec<_>>();
        retained.sort_by(|left, right| {
            left.engine_id
                .cmp(&right.engine_id)
                .then_with(|| left.code.cmp(&right.code))
        });
        retained.dedup_by(|left, right| left.engine_id == right.engine_id);
        retained
    }

    fn catalog_container_unavailable(detail: String) -> Self {
        Self {
            manifests: Vec::new(),
            admission_issues: vec![EngineAdmissionIssue {
                engine_id: None,
                code: "catalog_container_invalid".into(),
                detail,
            }],
        }
    }
}

/// Return the supported coordinate represented by this exact or
/// whitespace-corrupted packaged ID. The returned coordinate is diagnostic
/// identity only; callers must still reject a non-exact raw ID.
fn supported_coordinate(raw_id: &str) -> Option<&'static str> {
    let trimmed = raw_id.trim();
    KNOWN_ENGINE_IDS
        .into_iter()
        .find(|engine_id| *engine_id == raw_id || *engine_id == trimmed)
}

fn validate_release_contract(manifest: &EngineManifest) -> AppResult<()> {
    if let Some(image) = &manifest.image {
        crate::publication_origins::validate_engine_publication(image)?;
    }
    let fail =
        |message: &str| AppError::EngineRegistry(format!("engine {}: {message}", manifest.id));
    if manifest.schema_version != "2.0.0" {
        return Err(fail("unsupported manifest schema version"));
    }
    let execution = manifest
        .execution
        .as_ref()
        .ok_or_else(|| fail("reviewed execution resource contract is missing"))?;
    if !(MIN_ENGINE_EXECUTION_TIMEOUT_SECONDS..=MAX_ENGINE_EXECUTION_TIMEOUT_SECONDS)
        .contains(&execution.resources.timeout_seconds)
    {
        return Err(fail(
            "execution timeout must be between 30 and 86400 seconds",
        ));
    }
    if !(MIN_ENGINE_EXECUTION_CPU_MILLIS..=MAX_ENGINE_EXECUTION_CPU_MILLIS)
        .contains(&execution.resources.cpu_millis)
    {
        return Err(fail(
            "execution CPU limit must be between 100 and 16000 millicores",
        ));
    }
    let command_contains_journal_flag = |flag: &str| {
        manifest.command.iter().any(|token| {
            token == flag
                || token
                    .strip_prefix(flag)
                    .is_some_and(|suffix| suffix.starts_with('='))
        })
    };
    let has_journal_version_flag = command_contains_journal_flag("--journal-version");
    let has_journal_plan_flag = command_contains_journal_flag("--journal-plan");
    match execution.launcher_journal_version {
        Some(NAABU_LAUNCHER_JOURNAL_VERSION) => {
            if manifest.id != "naabu" {
                return Err(fail(
                    "launcher journal version 2 is supported only by the reviewed Naabu launcher",
                ));
            }
            if !manifest
                .command
                .iter()
                .map(String::as_str)
                .eq(NAABU_LAUNCHER_JOURNAL_COMMAND.iter().copied())
            {
                return Err(fail(
                    "launcher journal version 2 requires the exact reviewed Naabu launcher command",
                ));
            }
        }
        Some(_) => {
            return Err(fail("unsupported launcher journal version"));
        }
        None if has_journal_version_flag || has_journal_plan_flag => {
            return Err(fail(
                "launcher journal command flags require the declared version 2 execution contract",
            ));
        }
        None => {}
    }
    let supported_providers = manifest
        .supported_providers
        .iter()
        .map(String::as_str)
        .collect::<std::collections::BTreeSet<_>>();
    if supported_providers.len() != manifest.supported_providers.len()
        || supported_providers
            .iter()
            .any(|provider| !matches!(*provider, "aws" | "azure" | "gcp" | "microsoft365"))
    {
        return Err(fail(
            "supported providers must be unique exact catalog identifiers",
        ));
    }
    let expected_providers = if manifest.id == "prowler" {
        ["aws", "azure", "gcp"].into_iter().collect()
    } else if AWS_ONLY_ENGINE_IDS.contains(&manifest.id.as_str()) {
        ["aws"].into_iter().collect()
    } else if MICROSOFT365_ONLY_ENGINE_IDS.contains(&manifest.id.as_str()) {
        ["microsoft365"].into_iter().collect()
    } else {
        std::collections::BTreeSet::new()
    };
    if supported_providers != expected_providers {
        return Err(fail(
            "supported providers overstate or omit the released provider applicability contract",
        ));
    }
    if manifest.supported_providers.len() > 1 && manifest.provider_execution_contracts.is_empty() {
        return Err(fail(
            "a multi-provider engine must bind every provider to an exact execution contract",
        ));
    }
    if manifest.supported_providers.is_empty() && !manifest.provider_execution_contracts.is_empty()
    {
        return Err(fail(
            "a provider-agnostic engine cannot declare provider execution contracts",
        ));
    }
    if !manifest.provider_execution_contracts.is_empty() {
        let contract_providers = manifest
            .provider_execution_contracts
            .iter()
            .map(|contract| contract.provider.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        let contract_asset_kinds = manifest
            .provider_execution_contracts
            .iter()
            .map(|contract| &contract.asset_kind)
            .collect::<Vec<_>>();
        let supported_asset_kinds = manifest.supported_asset_kinds.iter().collect::<Vec<_>>();
        let contract_profiles = manifest
            .provider_execution_contracts
            .iter()
            .map(|contract| contract.profile.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        let contract_destinations = manifest
            .provider_execution_contracts
            .iter()
            .flat_map(|contract| contract.network_destinations.iter().map(String::as_str))
            .collect::<std::collections::BTreeSet<_>>();
        let manifest_destinations = manifest
            .network_destinations
            .iter()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>();
        if contract_providers != supported_providers
            || contract_providers.len() != manifest.provider_execution_contracts.len()
            || contract_asset_kinds
                .iter()
                .enumerate()
                .any(|(index, kind)| contract_asset_kinds[..index].contains(kind))
            || contract_asset_kinds.len() != supported_asset_kinds.len()
            || supported_asset_kinds
                .iter()
                .any(|kind| !contract_asset_kinds.contains(kind))
            || contract_profiles.len() != manifest.provider_execution_contracts.len()
            || contract_destinations != manifest_destinations
        {
            return Err(fail(
                "provider execution contracts must uniquely and completely bind provider, asset kind, profile, and the declared network closure",
            ));
        }
        for contract in &manifest.provider_execution_contracts {
            if contract.profile.len() < 3
                || contract.profile.len() > 64
                || !contract.profile.bytes().enumerate().all(|(index, byte)| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || (index > 0 && matches!(byte, b'_' | b'-'))
                })
                || contract.network_destinations.is_empty()
                || contract
                    .network_destinations
                    .iter()
                    .any(|destination| destination.trim().is_empty())
            {
                return Err(fail("provider execution contract is malformed"));
            }
        }
    }
    let local_artifact = manifest
        .required_permissions
        .contains(&ScanPermission::LocalArtifactRead);
    if local_artifact {
        if manifest.input_contracts.len() != manifest.supported_asset_kinds.len()
            || manifest
                .input_contracts
                .iter()
                .zip(&manifest.supported_asset_kinds)
                .any(|(contract, asset_kind)| {
                    contract.asset_kind != *asset_kind
                        || expected_input_profile(asset_kind)
                            .is_none_or(|profile| contract.input_profile != profile)
                })
        {
            return Err(fail(
                "local input contracts must exactly bind every supported asset kind",
            ));
        }
        for contract in &manifest.input_contracts {
            if let Some(command) = contract.command.as_deref() {
                validate_static_manifest_command(command)?;
            }
        }
    } else if !manifest.input_contracts.is_empty() {
        return Err(fail(
            "an engine without local-artifact permission cannot declare local input contracts",
        ));
    }
    let direct_network = manifest.required_permissions.iter().any(|permission| {
        matches!(
            permission,
            ScanPermission::LowImpactExternalConnection | ScanPermission::ActiveExternalTesting
        )
    });
    if direct_network {
        let contract = manifest.direct_network_contract.as_ref().ok_or_else(|| {
            fail("a direct-network engine must declare its accepted target and protocol shapes")
        })?;
        if contract.target_kinds.is_empty()
            || contract.protocols.is_empty()
            || contract
                .target_kinds
                .iter()
                .enumerate()
                .any(|(index, kind)| contract.target_kinds[..index].contains(kind))
            || contract
                .protocols
                .iter()
                .enumerate()
                .any(|(index, protocol)| contract.protocols[..index].contains(protocol))
        {
            return Err(fail(
                "direct-network target kinds and protocols must be non-empty and unique",
            ));
        }
    } else if manifest.direct_network_contract.is_some() {
        return Err(fail(
            "an engine without direct-network permission cannot declare a direct-network contract",
        ));
    }
    let knowledge_date = parse_iso_date(&manifest.compatibility.knowledge_date)
        .ok_or_else(|| fail("compatibility knowledge date is not a real ISO calendar date"))?;
    let support_until = parse_iso_date(&manifest.compatibility.support_until)
        .ok_or_else(|| fail("compatibility support-until date is not a real ISO calendar date"))?;
    if support_until < knowledge_date {
        return Err(fail(
            "compatibility support-until date precedes the knowledge date",
        ));
    }
    let maintenance_owner = manifest.compatibility.maintenance_owner.trim();
    if maintenance_owner.is_empty()
        || maintenance_owner.chars().count() > 200
        || maintenance_owner.chars().any(char::is_control)
    {
        return Err(fail("compatibility maintenance owner is invalid"));
    }
    if manifest.compatibility.update_procedure != "docs/engine-maintenance.md" {
        return Err(fail(
            "compatibility update procedure must reference the release-reviewed engine maintenance procedure",
        ));
    }
    if manifest.compatibility.packaging_plan != format!("engines/images/{}/plan.json", manifest.id)
    {
        return Err(fail("packaging plan path does not match the engine id"));
    }
    if manifest.compatibility.runnable {
        if let Some(blocker) = manifest.release_blocker() {
            return Err(fail(&blocker));
        }
        let image = manifest
            .image
            .as_ref()
            .ok_or_else(|| fail("runnable release has no immutable container image"))?;
        if image.repository.trim().is_empty()
            || !image.digest.as_deref().is_some_and(valid_sha256_digest)
        {
            return Err(fail(
                "runnable release image is not pinned by sha256 digest",
            ));
        }
        if manifest.command.is_empty() || manifest.command.iter().any(|part| part.trim().is_empty())
        {
            return Err(fail("runnable release has no complete static command"));
        }
    } else {
        if manifest.compatibility.blocked_by.is_empty() {
            return Err(fail("non-runnable release must state at least one blocker"));
        }
        if manifest.default_enabled {
            return Err(fail("non-runnable release cannot be enabled by default"));
        }
    }
    Ok(())
}

fn expected_input_profile(asset_kind: &AssetKind) -> Option<LocalInputProfile> {
    match asset_kind {
        AssetKind::Repository => Some(LocalInputProfile::RepositoryWorkingTree),
        AssetKind::IacProject => Some(LocalInputProfile::IacWorkingTree),
        AssetKind::ContainerImage => Some(LocalInputProfile::ContainerImageOciLayout),
        AssetKind::KubernetesCluster => Some(LocalInputProfile::KubernetesManifests),
        AssetKind::Host => Some(LocalInputProfile::KubernetesNodeSnapshot),
        _ => None,
    }
}

fn parse_iso_date(value: &str) -> Option<NaiveDate> {
    if value.len() != 10
        || value.as_bytes().get(4) != Some(&b'-')
        || value.as_bytes().get(7) != Some(&b'-')
    {
        return None;
    }
    NaiveDate::parse_from_str(value, "%Y-%m-%d").ok()
}

fn valid_sha256_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64 && hex.chars().all(|character| character.is_ascii_hexdigit())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::DirectNetworkExecutionContract;
    use crate::external_scope::{DirectNetworkTargetKind, TransportProtocol};

    #[test]
    fn builtin_catalog_has_unique_supported_engines() {
        let registry = EngineRegistry::load_builtin().expect("valid catalog");
        assert!(!registry.manifests().is_empty());
        assert!(registry.admission_issues().is_empty());
        assert!(registry.get("prowler").is_some());
        assert!(registry.get("scubagear").is_some());
        assert!(registry.get("nuclei").is_some());
        for id in AWS_ONLY_ENGINE_IDS {
            assert_eq!(registry.get(id).unwrap().supported_providers, ["aws"]);
        }
        assert_eq!(
            registry.get("prowler").unwrap().supported_providers,
            ["aws", "azure", "gcp"]
        );
        assert!(
            registry
                .get("gitleaks")
                .unwrap()
                .supported_providers
                .is_empty()
        );
        assert_eq!(
            registry
                .get("cloudquery")
                .unwrap()
                .execution_timeout_seconds(),
            3_600
        );
    }

    #[test]
    fn unsafe_typed_input_commands_isolate_only_their_engine() {
        for command in [
            serde_json::json!([]),
            serde_json::json!(["sh", "-c", "syft dir:/workspace"]),
            serde_json::json!(["oci-dir:/workspace", "${target}"]),
        ] {
            let mut entries: Vec<Value> = serde_json::from_str(BUILTIN_CATALOG).unwrap();
            let syft = entries
                .iter_mut()
                .find(|entry| entry["id"] == "syft")
                .expect("Syft catalog entry");
            syft["supported_asset_kinds"] = serde_json::json!(["repository", "container_image"]);
            syft["input_contracts"] = serde_json::json!([
                {
                    "asset_kind": "repository",
                    "input_profile": "repository_working_tree"
                },
                {
                    "asset_kind": "container_image",
                    "input_profile": "container_image_oci_layout",
                    "command": command
                }
            ]);

            let registry = EngineRegistry::load_catalog(&serde_json::to_string(&entries).unwrap())
                .expect("one invalid engine remains isolated");
            assert!(registry.get("syft").is_none());
            assert!(registry.get("grype").is_some());
            assert!(registry.admission_issues().iter().any(|issue| {
                issue.engine_id.as_deref() == Some("syft")
                    && issue.code == "engine_contract_invalid"
            }));
        }
    }

    #[test]
    fn empty_registry_exposes_no_catalog_backed_engines() {
        let registry = EngineRegistry::empty();

        assert!(registry.manifests().is_empty());
        assert!(registry.get("naabu").is_none());
        assert!(registry.admission_issues().is_empty());
    }

    #[test]
    fn one_invalid_engine_is_isolated_without_disabling_its_siblings() {
        let mut entries: Vec<Value> = serde_json::from_str(BUILTIN_CATALOG).unwrap();
        let naabu = entries
            .iter_mut()
            .find(|entry| entry["id"] == "naabu")
            .expect("naabu catalog entry");
        naabu["schema_version"] = Value::String("unsupported-test-schema".into());
        let registry = EngineRegistry::load_catalog(&serde_json::to_string(&entries).unwrap())
            .expect("the catalog container remains readable");

        assert!(registry.get("naabu").is_none());
        assert!(registry.get("httpx").is_some());
        assert!(registry.get("gitleaks").is_some());
        assert!(registry.admission_issues().iter().any(|issue| {
            issue.engine_id.as_deref() == Some("naabu") && issue.code == "engine_contract_invalid"
        }));
        assert!(
            !registry
                .admission_issues()
                .iter()
                .any(|issue| { issue.engine_id.as_deref() == Some("httpx") })
        );
    }

    #[test]
    fn an_absent_optional_engine_does_not_create_an_admission_issue() {
        let mut entries: Vec<Value> = serde_json::from_str(BUILTIN_CATALOG).unwrap();
        entries.retain(|entry| entry["id"] != "gitleaks");
        let registry = EngineRegistry::load_catalog(&serde_json::to_string(&entries).unwrap())
            .expect("a supported catalog subset remains independently admissible");

        assert_eq!(registry.manifests().len(), entries.len());
        assert!(registry.get("gitleaks").is_none());
        assert!(registry.get("semgrep").is_some());
        assert!(registry.admission_issues().is_empty());
        assert!(registry.run_bound_admission_issues().is_empty());
    }

    #[test]
    fn a_duplicate_engine_disables_the_entire_coordinate_and_keeps_siblings() {
        let mut entries: Vec<Value> = serde_json::from_str(BUILTIN_CATALOG).unwrap();
        let duplicate = entries
            .iter()
            .find(|entry| entry["id"] == "httpx")
            .expect("httpx catalog entry")
            .clone();
        entries.push(duplicate);
        let registry = EngineRegistry::load_catalog(&serde_json::to_string(&entries).unwrap())
            .expect("duplicate isolation is not a whole-catalog failure");

        assert!(registry.get("httpx").is_none());
        assert!(registry.get("naabu").is_some());
        assert!(registry.admission_issues().iter().any(|issue| {
            issue.engine_id.as_deref() == Some("httpx") && issue.code == "duplicate_engine_id"
        }));
        assert_eq!(
            registry.run_bound_admission_issues()[0]
                .engine_id
                .as_deref(),
            Some("httpx")
        );
    }

    #[test]
    fn an_invalid_and_valid_duplicate_still_disable_the_coordinate() {
        let mut entries: Vec<Value> = serde_json::from_str(BUILTIN_CATALOG).unwrap();
        let mut duplicate = entries
            .iter()
            .find(|entry| entry["id"] == "httpx")
            .expect("httpx catalog entry")
            .clone();
        duplicate["schema_version"] = Value::String("invalid-duplicate-schema".into());
        entries.push(duplicate);
        let registry = EngineRegistry::load_catalog(&serde_json::to_string(&entries).unwrap())
            .expect("duplicate ambiguity remains isolated");

        assert!(registry.get("httpx").is_none());
        assert!(registry.get("naabu").is_some());
        assert_eq!(
            registry
                .admission_issues()
                .iter()
                .filter(|issue| issue.engine_id.as_deref() == Some("httpx"))
                .count(),
            1
        );
        assert_eq!(
            registry
                .admission_issues()
                .iter()
                .find(|issue| issue.engine_id.as_deref() == Some("httpx"))
                .unwrap()
                .code,
            "duplicate_engine_id"
        );
    }

    #[test]
    fn exact_and_whitespace_forms_are_one_duplicate_supported_coordinate() {
        let mut entries: Vec<Value> = serde_json::from_str(BUILTIN_CATALOG).unwrap();
        let mut duplicate = entries
            .iter()
            .find(|entry| entry["id"] == "httpx")
            .expect("httpx catalog entry")
            .clone();
        duplicate["id"] = Value::String(" httpx ".into());
        entries.push(duplicate);
        let registry = EngineRegistry::load_catalog(&serde_json::to_string(&entries).unwrap())
            .expect("duplicate ambiguity remains isolated");

        assert!(registry.get("httpx").is_none());
        assert!(registry.get("naabu").is_some());
        assert_eq!(registry.admission_issues().len(), 1);
        assert_eq!(
            registry.admission_issues()[0].engine_id.as_deref(),
            Some("httpx")
        );
        assert_eq!(registry.admission_issues()[0].code, "duplicate_engine_id");
        assert_eq!(
            registry.run_bound_admission_issues(),
            registry.admission_issues()
        );
    }

    #[test]
    fn whitespace_engine_id_is_a_present_invalid_supported_coordinate() {
        let mut entries: Vec<Value> = serde_json::from_str(BUILTIN_CATALOG).unwrap();
        let naabu = entries
            .iter_mut()
            .find(|entry| entry["id"] == "naabu")
            .expect("naabu catalog entry");
        naabu["id"] = Value::String(" naabu ".into());
        let registry = EngineRegistry::load_catalog(&serde_json::to_string(&entries).unwrap())
            .expect("noncanonical entry is isolated");

        assert!(registry.get("naabu").is_none());
        assert_eq!(registry.admission_issues().len(), 1);
        assert_eq!(
            registry.admission_issues()[0].engine_id.as_deref(),
            Some("naabu")
        );
        assert_eq!(
            registry.admission_issues()[0].code,
            "noncanonical_engine_id"
        );
        assert_eq!(
            registry.run_bound_admission_issues(),
            registry.admission_issues()
        );
    }

    #[test]
    fn malformed_catalog_container_becomes_one_observable_global_issue() {
        for catalog in ["{not-json", r#"{"engines": []}"#] {
            let registry = EngineRegistry::load_catalog(catalog)
                .expect("catalog container failure must remain a degraded registry");
            assert!(registry.manifests().is_empty());
            assert_eq!(registry.admission_issues().len(), 1);
            assert_eq!(registry.admission_issues()[0].engine_id, None);
            assert_eq!(
                registry.admission_issues()[0].code,
                "catalog_container_invalid"
            );
            assert_eq!(
                registry.run_bound_admission_issues(),
                registry.admission_issues()
            );
            assert!(serde_json::to_value(registry.admission_issues()).is_ok());
        }
    }

    #[test]
    fn registry_publication_origin_checks_apply_to_each_pair() {
        let registry = EngineRegistry::load_builtin().unwrap();
        for (namespace, repository) in crate::publication_origins::PUBLICATION_ORIGINS {
            let mut manifest = registry.get("gitleaks").unwrap().clone();
            let image = manifest.image.as_mut().unwrap();
            image.repository = format!("{namespace}/ai-security-scanner-engine-gitleaks");
            image.signature_identity = Some(format!(
                "https://github.com/{repository}/.github/workflows/engine-image-gitleaks.yml@refs/heads/main"
            ));
            validate_release_contract(&manifest).unwrap();
            manifest.image.as_mut().unwrap().signature_identity = Some("https://github.com/unknown/ai-security-scanner/.github/workflows/build.yml@refs/heads/main".into());
            assert!(validate_release_contract(&manifest).is_err());
        }
    }

    #[test]
    fn release_execution_timeout_is_required_and_bounded() {
        let registry = EngineRegistry::load_builtin().expect("valid catalog");
        let mut manifest = registry.get("cloudquery").unwrap().clone();

        for valid in [30, 86_400] {
            manifest
                .execution
                .as_mut()
                .unwrap()
                .resources
                .timeout_seconds = valid;
            validate_release_contract(&manifest).expect("inclusive timeout boundary");
        }

        manifest
            .execution
            .as_mut()
            .unwrap()
            .resources
            .timeout_seconds = 29;
        assert!(
            validate_release_contract(&manifest)
                .unwrap_err()
                .to_string()
                .contains("between 30 and 86400 seconds")
        );

        manifest
            .execution
            .as_mut()
            .unwrap()
            .resources
            .timeout_seconds = 86_401;
        assert!(
            validate_release_contract(&manifest)
                .unwrap_err()
                .to_string()
                .contains("between 30 and 86400 seconds")
        );

        manifest.execution = None;
        assert!(
            validate_release_contract(&manifest)
                .unwrap_err()
                .to_string()
                .contains("resource contract is missing")
        );
    }

    #[test]
    fn release_execution_cpu_limit_is_bounded() {
        let registry = EngineRegistry::load_builtin().expect("valid catalog");
        // openvasd sizes its API worker pool from the CPUs it can see.
        assert_eq!(
            registry.get("greenbone").unwrap().execution_cpu_millis(),
            2_000
        );
        let mut manifest = registry.get("cloudquery").unwrap().clone();

        for (cpu_millis, valid) in [(99, false), (100, true), (16_000, true), (16_001, false)] {
            manifest.execution.as_mut().unwrap().resources.cpu_millis = cpu_millis;
            let result = validate_release_contract(&manifest);
            if valid {
                result.expect("inclusive CPU boundary");
            } else {
                assert!(
                    result
                        .unwrap_err()
                        .to_string()
                        .contains("between 100 and 16000 millicores")
                );
            }
        }
    }

    #[test]
    fn naabu_launcher_journal_v2_accepts_only_the_exact_reviewed_command() {
        let registry = EngineRegistry::load_builtin().expect("valid catalog");
        let manifest = registry.get("naabu").unwrap().clone();

        assert!(
            manifest.execution_timeout_seconds()
                > crate::naabu_work_plan::HARD_WORK_UNIT_WINDOW_SECONDS
                    + crate::naabu_work_plan::NAABU_HOST_ATTEMPT_MARGIN_SECONDS,
            "the outer host timeout must leave the fixed host margin after the largest valid scanner unit"
        );

        validate_release_contract(&manifest)
            .expect("the built-in exact reviewed Naabu launcher-journal command is admissible");
        assert_eq!(
            manifest
                .execution
                .as_ref()
                .expect("execution contract")
                .launcher_journal_version,
            Some(NAABU_LAUNCHER_JOURNAL_VERSION)
        );
        assert!(
            manifest
                .command
                .iter()
                .map(String::as_str)
                .eq(NAABU_LAUNCHER_JOURNAL_COMMAND.iter().copied())
        );

        let mut missing_plan = manifest.clone();
        missing_plan
            .command
            .truncate(missing_plan.command.len() - 2);
        let mut missing_version = manifest.clone();
        missing_version.command.drain(6..8);
        let mut extra_argument = manifest.clone();
        extra_argument.command.push("--unexpected".into());
        for (name, malformed) in [
            ("missing journal plan", missing_plan),
            ("missing journal version", missing_version),
            ("extra argument", extra_argument),
        ] {
            assert!(
                validate_release_contract(&malformed)
                    .unwrap_err()
                    .to_string()
                    .contains("requires the exact reviewed Naabu launcher command"),
                "{name} must be rejected"
            );
        }

        for (index, replacement) in [(7, "3"), (9, "/tmp/journal.json")] {
            let mut malformed = manifest.clone();
            malformed.command[index] = replacement.into();
            assert!(
                validate_release_contract(&malformed)
                    .unwrap_err()
                    .to_string()
                    .contains("requires the exact reviewed Naabu launcher command")
            );
        }
    }

    #[test]
    fn launcher_journal_flags_and_versions_cannot_escape_the_current_naabu_contract() {
        let registry = EngineRegistry::load_builtin().expect("valid catalog");
        let mut legacy = registry.get("naabu").unwrap().clone();
        legacy
            .execution
            .as_mut()
            .expect("execution contract")
            .launcher_journal_version = None;
        legacy.command.truncate(6);

        for injected in [
            vec!["--journal-version", "2"],
            vec![
                "--journal-plan",
                "/run/ai-security-scanner/execution-journal-v2.json",
            ],
            vec!["--journal-version=2"],
            vec!["--journal-plan=/run/ai-security-scanner/execution-journal-v2.json"],
        ] {
            let mut undeclared = legacy.clone();
            undeclared
                .command
                .extend(injected.into_iter().map(str::to_owned));
            assert!(
                validate_release_contract(&undeclared)
                    .unwrap_err()
                    .to_string()
                    .contains("flags require the declared version 2")
            );
        }

        let mut unsupported = legacy.clone();
        unsupported
            .execution
            .as_mut()
            .expect("execution contract")
            .launcher_journal_version = Some(3);
        assert!(
            validate_release_contract(&unsupported)
                .unwrap_err()
                .to_string()
                .contains("unsupported launcher journal version")
        );

        let mut wrong_engine = registry.get("httpx").unwrap().clone();
        wrong_engine
            .execution
            .as_mut()
            .expect("execution contract")
            .launcher_journal_version = Some(NAABU_LAUNCHER_JOURNAL_VERSION);
        wrong_engine.command = NAABU_LAUNCHER_JOURNAL_COMMAND
            .iter()
            .map(|token| (*token).to_owned())
            .collect();
        assert!(
            validate_release_contract(&wrong_engine)
                .unwrap_err()
                .to_string()
                .contains("supported only by the reviewed Naabu launcher")
        );
    }

    #[test]
    fn naabu_timeout_covers_the_conservative_home_scope_pacing_floor() {
        let registry = EngineRegistry::load_builtin().expect("valid catalog");
        let timeout = registry
            .get("naabu")
            .expect("released Naabu manifest")
            .execution_timeout_seconds();
        let usable_ipv4_hosts_in_23 = 510_u64;
        let approved_ports = 17_u64;
        let requests_per_second = 1_u64;
        let pacing_floor_seconds = usable_ipv4_hosts_in_23 * approved_ports / requests_per_second;

        assert_eq!(pacing_floor_seconds, 8_670);
        assert_eq!(
            timeout,
            crate::naabu_work_plan::HARD_WORK_UNIT_WINDOW_SECONDS
                + crate::naabu_work_plan::NAABU_HOST_ATTEMPT_MARGIN_SECONDS
                + 1
        );
        assert!(timeout > pacing_floor_seconds);
        assert!(timeout <= MAX_ENGINE_EXECUTION_TIMEOUT_SECONDS);
    }

    #[test]
    fn legacy_serialized_manifest_without_execution_contract_remains_readable() {
        let registry = EngineRegistry::load_builtin().expect("valid catalog");
        let mut document =
            serde_json::to_value(registry.get("cloudquery").unwrap()).expect("manifest JSON");
        document
            .as_object_mut()
            .expect("manifest object")
            .remove("execution");

        let legacy: EngineManifest =
            serde_json::from_value(document).expect("legacy manifest remains readable");
        assert!(legacy.execution.is_none());
        assert_eq!(
            legacy.execution_timeout_seconds(),
            crate::domain::DEFAULT_ENGINE_EXECUTION_TIMEOUT_SECONDS
        );
        assert_eq!(
            legacy.execution_cpu_millis(),
            crate::domain::DEFAULT_ENGINE_EXECUTION_CPU_MILLIS
        );
    }

    #[test]
    fn saved_plan_without_a_cpu_allowance_keeps_the_earlier_limit() {
        let registry = EngineRegistry::load_builtin().expect("valid catalog");
        let mut document =
            serde_json::to_value(registry.get("greenbone").unwrap()).expect("manifest JSON");
        document["execution"]["resources"]
            .as_object_mut()
            .expect("resources object")
            .remove("cpu_millis");

        let saved: EngineManifest =
            serde_json::from_value(document).expect("saved manifest remains readable");
        assert_eq!(
            saved.execution_cpu_millis(),
            crate::domain::DEFAULT_ENGINE_EXECUTION_CPU_MILLIS
        );
    }

    #[test]
    fn builtin_direct_network_contracts_match_their_launcher_shapes() {
        let registry = EngineRegistry::load_builtin().expect("valid catalog");
        let contract = |id: &str| {
            registry
                .get(id)
                .and_then(|manifest| manifest.direct_network_contract.as_ref())
                .unwrap_or_else(|| panic!("missing direct-network contract for {id}"))
        };

        assert_eq!(
            contract("naabu"),
            &DirectNetworkExecutionContract {
                target_kinds: vec![
                    DirectNetworkTargetKind::Hostname,
                    DirectNetworkTargetKind::Address,
                    DirectNetworkTargetKind::Network,
                ],
                protocols: vec![
                    TransportProtocol::Tcp,
                    TransportProtocol::Tls,
                    TransportProtocol::Http,
                    TransportProtocol::Https,
                ],
            }
        );
        for id in ["httpx", "nuclei"] {
            assert_eq!(
                contract(id),
                &DirectNetworkExecutionContract {
                    target_kinds: vec![
                        DirectNetworkTargetKind::Hostname,
                        DirectNetworkTargetKind::Address,
                    ],
                    protocols: vec![TransportProtocol::Http, TransportProtocol::Https],
                }
            );
        }
        assert_eq!(
            contract("greenbone"),
            &DirectNetworkExecutionContract {
                target_kinds: vec![
                    DirectNetworkTargetKind::Hostname,
                    DirectNetworkTargetKind::Address,
                ],
                protocols: vec![
                    TransportProtocol::Tcp,
                    TransportProtocol::Tls,
                    TransportProtocol::Http,
                    TransportProtocol::Https,
                ],
            }
        );
    }

    #[test]
    fn direct_network_contract_is_required_only_for_direct_network_permissions() {
        let registry = EngineRegistry::load_builtin().expect("valid catalog");

        let mut missing = registry.get("naabu").unwrap().clone();
        missing.direct_network_contract = None;
        assert!(
            validate_release_contract(&missing)
                .unwrap_err()
                .to_string()
                .contains("must declare its accepted target and protocol shapes")
        );

        let mut misplaced = registry.get("semgrep").unwrap().clone();
        misplaced.direct_network_contract = Some(DirectNetworkExecutionContract {
            target_kinds: vec![DirectNetworkTargetKind::Address],
            protocols: vec![TransportProtocol::Tcp],
        });
        assert!(
            validate_release_contract(&misplaced)
                .unwrap_err()
                .to_string()
                .contains("without direct-network permission")
        );

        let mut duplicate = registry.get("httpx").unwrap().clone();
        duplicate
            .direct_network_contract
            .as_mut()
            .unwrap()
            .protocols
            .push(TransportProtocol::Http);
        assert!(
            validate_release_contract(&duplicate)
                .unwrap_err()
                .to_string()
                .contains("must be non-empty and unique")
        );
    }

    #[test]
    fn every_packaged_engine_offers_its_own_name_to_the_report() {
        // The report reads this instead of humanizing an id. An engine with no
        // entry falls back to that humanizer and reaches a reader under a name
        // its own project does not use.
        for id in KNOWN_ENGINE_IDS {
            let name = builtin_display_name(id)
                .unwrap_or_else(|| panic!("{id} has no display name in the packaged catalog"));
            assert!(!name.is_empty(), "{id}");
        }
        assert_eq!(builtin_display_name("kube-bench"), Some("kube-bench"));
        assert_eq!(builtin_display_name("scoutsuite"), Some("ScoutSuite"));
        // An id this build does not ship stays the caller's problem.
        assert_eq!(builtin_display_name("not-an-engine"), None);
    }

    #[test]
    fn compatibility_dates_require_real_calendar_days() {
        assert_eq!(
            parse_iso_date("2024-02-29"),
            NaiveDate::from_ymd_opt(2024, 2, 29)
        );
        assert!(parse_iso_date("2026-02-29").is_none());
        assert!(parse_iso_date("2026-13-01").is_none());
        assert!(parse_iso_date("2026-8-24").is_none());
        assert!(parse_iso_date("not-a-date").is_none());
    }
}
