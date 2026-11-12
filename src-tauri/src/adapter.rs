use crate::domain::{
    Asset, EngineManifest, Finding, FindingStatus, InventoryObservation, RawArtifact,
};
use crate::error::{AppError, AppResult};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::Arc;

/// Exact native provider identifiers for the assets authorized in one engine
/// run. Candidate sets preserve collisions so adapters can fail closed instead
/// of guessing when two assets expose the same identifier.
#[derive(Debug, Clone, Default)]
pub struct AdapterAssetIdentifierMap {
    by_provider_and_identifier: BTreeMap<(String, String), BTreeSet<String>>,
    by_identifier: BTreeMap<String, BTreeSet<String>>,
}

impl AdapterAssetIdentifierMap {
    pub fn from_assets(assets: &[Asset]) -> Self {
        let mut result = Self::default();
        for asset in assets {
            let asset_id = asset.id.trim();
            if asset_id.is_empty() {
                continue;
            }
            for identifier in &asset.identifiers {
                let Some(identifier_provider) =
                    native_provider_for_namespace(&identifier.namespace)
                else {
                    continue;
                };
                if asset
                    .provider
                    .as_deref()
                    .and_then(normalize_provider)
                    .as_deref()
                    != Some(identifier_provider)
                {
                    continue;
                }
                let value = identifier.value.trim();
                if value.is_empty() {
                    continue;
                }
                result
                    .by_identifier
                    .entry(value.to_owned())
                    .or_default()
                    .insert(asset_id.to_owned());
                result
                    .by_provider_and_identifier
                    .entry((identifier_provider.to_owned(), value.to_owned()))
                    .or_default()
                    .insert(asset_id.to_owned());
            }
        }
        result
    }

    pub(crate) fn candidates(
        &self,
        provider: Option<&str>,
        identifier: &str,
    ) -> Option<&BTreeSet<String>> {
        let identifier = identifier.trim();
        if identifier.is_empty() {
            return None;
        }
        if let Some(provider) = provider.and_then(normalize_provider) {
            return self
                .by_provider_and_identifier
                .get(&(provider, identifier.to_owned()));
        }
        self.by_identifier.get(identifier)
    }
}

fn normalize_provider(provider: &str) -> Option<String> {
    let provider = provider.trim().to_ascii_lowercase();
    (!provider.is_empty()).then_some(provider)
}

fn native_provider_for_namespace(namespace: &str) -> Option<&'static str> {
    match namespace.trim().to_ascii_lowercase().as_str() {
        "aws_account_id" => Some("aws"),
        "azure_subscription_id" => Some("azure"),
        "gcp_project_id" => Some("gcp"),
        _ => None,
    }
}

pub struct AdapterInput<'a> {
    pub case_id: &'a str,
    pub scan_run_id: &'a str,
    pub engine_run_id: &'a str,
    pub manifest: &'a EngineManifest,
    /// True only when the case was explicitly created through the AI
    /// application journey. It controls AI-framework references; it never
    /// changes scan scope, permissions, or scanner execution.
    pub ai_system_applicable: bool,
    /// True only when the user explicitly answered that selected code was
    /// generated or materially changed by AI. Unknown and legacy cases remain
    /// false; this changes references only, never scanner execution.
    pub ai_generated_artifact_applicable: bool,
    pub asset_ids: &'a [String],
    pub asset_identifier_map: &'a AdapterAssetIdentifierMap,
    pub artifact_root: &'a Path,
    pub raw_artifacts: &'a [RawArtifact],
}

#[derive(Debug, Clone)]
pub struct AdapterOutput {
    pub findings: Vec<Finding>,
    /// Scanner-authored inventory facts. These are deliberately separate from
    /// findings because inventory alone is not evidence of a vulnerability.
    pub observations: Vec<InventoryObservation>,
    pub warnings: Vec<String>,
    /// Identifiers the engine reported on that no authorized asset claims.
    /// Beside the warnings rather than instead of them: the warning is the
    /// audit trail, this is what a reading surface composes a sentence from.
    pub unattributed: Vec<crate::domain::UnattributedResults>,
    /// Authorized targets the engine could not fully evaluate. This is
    /// coverage data, never a finding.
    pub unevaluated_targets: Vec<crate::domain::UnevaluatedTarget>,
    /// Authorized targets with genuine upstream per-template execution
    /// records. This is positive coverage evidence, never a finding.
    pub security_template_executions: Vec<crate::domain::SecurityTemplateExecution>,
    /// Controls the engine evaluated without returning a pass/fail verdict. This is
    /// coverage data, never a finding or pass.
    pub manual_review_controls: Vec<crate::domain::ManualReviewControl>,
    /// False when any captured evidence could not be fully normalized. Valid
    /// findings remain usable, but the engine run must not claim completion.
    pub complete: bool,
}

impl Default for AdapterOutput {
    fn default() -> Self {
        Self {
            findings: Vec::new(),
            observations: Vec::new(),
            warnings: Vec::new(),
            unattributed: Vec::new(),
            unevaluated_targets: Vec::new(),
            security_template_executions: Vec::new(),
            manual_review_controls: Vec::new(),
            complete: true,
        }
    }
}

pub trait EngineAdapter: Send + Sync {
    fn engine_id(&self) -> &str;
    fn adapter_version(&self) -> &str;
    fn normalize(&self, input: &AdapterInput<'_>) -> AppResult<AdapterOutput>;
}

#[derive(Default)]
pub struct AdapterRegistry {
    adapters: BTreeMap<String, Arc<dyn EngineAdapter>>,
}

impl AdapterRegistry {
    pub fn register(&mut self, adapter: Arc<dyn EngineAdapter>) -> AppResult<()> {
        let id = adapter.engine_id().trim();
        if id.is_empty() {
            return Err(AppError::EngineRegistry(
                "adapter engine id cannot be empty".into(),
            ));
        }
        if self.adapters.contains_key(id) {
            return Err(AppError::EngineRegistry(format!(
                "duplicate adapter for engine {id}"
            )));
        }
        self.adapters.insert(id.to_owned(), adapter);
        Ok(())
    }

    pub fn get(&self, engine_id: &str) -> Option<&dyn EngineAdapter> {
        self.adapters.get(engine_id).map(AsRef::as_ref)
    }

    pub fn normalize(&self, input: &AdapterInput<'_>) -> AppResult<Option<AdapterOutput>> {
        let Some(adapter) = self.get(&input.manifest.id) else {
            return Ok(None);
        };
        if adapter.adapter_version() != input.manifest.adapter_version {
            return Err(AppError::Runtime(format!(
                "adapter version mismatch for {}: manifest requires {}, loaded {}",
                input.manifest.id,
                input.manifest.adapter_version,
                adapter.adapter_version()
            )));
        }
        let output = adapter.normalize(input)?;
        validate_adapter_output(input, adapter, &output)?;
        Ok(Some(output))
    }
}

pub fn validate_adapter_output(
    input: &AdapterInput<'_>,
    adapter: &dyn EngineAdapter,
    output: &AdapterOutput,
) -> AppResult<()> {
    if adapter.engine_id() != input.manifest.id {
        return Err(AppError::Runtime(format!(
            "adapter {} cannot normalize output for {}",
            adapter.engine_id(),
            input.manifest.id
        )));
    }
    if adapter.adapter_version() != input.manifest.adapter_version {
        return Err(AppError::Runtime(format!(
            "adapter version {} does not match manifest version {}",
            adapter.adapter_version(),
            input.manifest.adapter_version
        )));
    }

    let allowed_assets: BTreeSet<&str> = input.asset_ids.iter().map(String::as_str).collect();
    let artifacts: BTreeMap<&str, &RawArtifact> = input
        .raw_artifacts
        .iter()
        .map(|artifact| (artifact.id.as_str(), artifact))
        .collect();
    let mut fingerprints = BTreeSet::new();

    for finding in &output.findings {
        if finding.case_id != input.case_id || finding.last_seen_run_id != input.scan_run_id {
            return Err(AppError::Runtime(format!(
                "adapter produced a finding outside the current case or scan run: {}",
                finding.fingerprint
            )));
        }
        if finding.fingerprint.trim().is_empty()
            || !fingerprints.insert(finding.fingerprint.as_str())
        {
            return Err(AppError::Runtime(
                "adapter finding fingerprints must be non-empty and unique".into(),
            ));
        }
        if finding.asset_ids.is_empty()
            || finding
                .asset_ids
                .iter()
                .any(|asset_id| !allowed_assets.contains(asset_id.as_str()))
        {
            return Err(AppError::Runtime(format!(
                "adapter finding {} references an asset outside the authorized run",
                finding.fingerprint
            )));
        }
        if finding.evidence.is_empty() {
            return Err(AppError::Runtime(format!(
                "adapter finding {} has no raw evidence",
                finding.fingerprint
            )));
        }
        if finding.status != FindingStatus::Unreviewed {
            return Err(AppError::Runtime(format!(
                "adapter may not assign a human review state to {}",
                finding.fingerprint
            )));
        }
        if finding.tags.iter().any(|tag| tag == "synthetic-demo") {
            return Err(AppError::Runtime(
                "synthetic demo findings cannot be emitted by a scanner adapter".into(),
            ));
        }

        for evidence in &finding.evidence {
            if evidence.finding_id != finding.id
                || evidence.run_id != input.scan_run_id
                || evidence.engine_run_id.as_deref() != Some(input.engine_run_id)
                || evidence.engine_id != input.manifest.id
            {
                return Err(AppError::Runtime(format!(
                    "finding {} has evidence with a mismatched finding, scan run, or engine execution",
                    finding.fingerprint
                )));
            }
            if let Some(details) = &evidence.scanner_details {
                if details.description.is_none()
                    && details.remediation.is_none()
                    && details.installed_version.is_none()
                    && details.fixed_version.is_none()
                    && details.aws_iam_policy.is_none()
                    && details.cwe_ids.is_empty()
                    && details.cvss.is_empty()
                {
                    return Err(AppError::Runtime(format!(
                        "finding {} has an empty scanner-provided detail record",
                        finding.fingerprint
                    )));
                }
                for (label, value, limit) in [
                    ("description", details.description.as_deref(), 2_048),
                    ("remediation", details.remediation.as_deref(), 2_048),
                    (
                        "installed version",
                        details.installed_version.as_deref(),
                        512,
                    ),
                    ("fixed version", details.fixed_version.as_deref(), 512),
                ] {
                    if value.is_some_and(|value| {
                        value.is_empty()
                            || value.chars().count() > limit
                            || value.chars().any(char::is_control)
                    }) {
                        return Err(AppError::Runtime(format!(
                            "finding {} has invalid scanner-provided {label}",
                            finding.fingerprint
                        )));
                    }
                }
                if let Some(iam) = &details.aws_iam_policy {
                    if evidence.engine_id != "cloudsplaining" {
                        return Err(AppError::Runtime(format!(
                            "finding {} attached AWS IAM policy evidence to a non-Cloudsplaining result",
                            finding.fingerprint
                        )));
                    }
                    for (label, value) in [
                        ("policy name", iam.policy_name.as_str()),
                        ("finding identity", iam.finding_identity.as_str()),
                    ] {
                        if value.is_empty()
                            || value.chars().count() > 512
                            || value.chars().any(char::is_control)
                        {
                            return Err(AppError::Runtime(format!(
                                "finding {} has invalid scanner-provided AWS IAM {label}",
                                finding.fingerprint
                            )));
                        }
                    }
                    if iam.actions.len() > 32
                        || iam.attached_to.roles.len() > 32
                        || iam.attached_to.groups.len() > 32
                        || iam.attached_to.users.len() > 32
                    {
                        return Err(AppError::Runtime(format!(
                            "finding {} exceeded the AWS IAM policy evidence list boundary",
                            finding.fingerprint
                        )));
                    }
                    for value in iam
                        .actions
                        .iter()
                        .chain(&iam.attached_to.roles)
                        .chain(&iam.attached_to.groups)
                        .chain(&iam.attached_to.users)
                    {
                        if value.is_empty()
                            || value.chars().count() > 512
                            || value.chars().any(char::is_control)
                        {
                            return Err(AppError::Runtime(format!(
                                "finding {} has invalid scanner-provided AWS IAM policy context",
                                finding.fingerprint
                            )));
                        }
                    }
                }
            }
            let artifact = artifacts
                .get(evidence.artifact_id.as_str())
                .ok_or_else(|| {
                    AppError::Runtime(format!(
                        "finding {} references an unknown raw artifact",
                        finding.fingerprint
                    ))
                })?;
            if artifact.sha256 != evidence.artifact_sha256
                || artifact.case_id != input.case_id
                || artifact.run_id != input.scan_run_id
                || artifact.engine_run_id != input.engine_run_id
            {
                return Err(AppError::Runtime(format!(
                    "finding {} raw artifact hash or execution context does not match",
                    finding.fingerprint
                )));
            }
        }
    }

    if output.security_template_executions.len() > input.asset_ids.len() {
        return Err(AppError::Runtime(
            "adapter produced too many security-template execution aggregates".into(),
        ));
    }
    if !output.security_template_executions.is_empty() && input.manifest.id != "nuclei" {
        return Err(AppError::Runtime(
            "only the Nuclei adapter may emit security-template execution evidence".into(),
        ));
    }
    let mut security_template_assets = BTreeSet::new();
    for execution in &output.security_template_executions {
        if !allowed_assets.contains(execution.asset_id.as_str()) || execution.result_count == 0 {
            return Err(AppError::Runtime(
                "security-template execution evidence is outside the authorized run or has no upstream result"
                    .into(),
            ));
        }
        if !security_template_assets.insert(execution.asset_id.as_str()) {
            return Err(AppError::Runtime(
                "security-template execution evidence must be unique per asset".into(),
            ));
        }
        if output.unevaluated_targets.iter().any(|target| {
            target.asset_id == execution.asset_id
                && target.cause
                    == crate::domain::UnevaluatedTargetCause::NoSecurityTemplateExecutionEvidence
        }) {
            return Err(AppError::Runtime(
                "an asset cannot have both security-template execution proof and a missing-proof outcome"
                    .into(),
            ));
        }
    }
    if output.unevaluated_targets.iter().any(|target| {
        target.cause == crate::domain::UnevaluatedTargetCause::NoSecurityTemplateExecutionEvidence
            && input.manifest.id != "nuclei"
    }) {
        return Err(AppError::Runtime(
            "only the Nuclei adapter may emit a missing security-template execution outcome".into(),
        ));
    }
    if output.unevaluated_targets.iter().any(|target| {
        target.cause == crate::domain::UnevaluatedTargetCause::NoServiceIdentified
            && input.manifest.id != "greenbone"
    }) {
        return Err(AppError::Runtime(
            "only the Greenbone adapter may emit a no-service outcome".into(),
        ));
    }

    if output.manual_review_controls.len() > 10_000 {
        return Err(AppError::Runtime(
            "adapter produced too many manual-review controls".into(),
        ));
    }
    if !output.manual_review_controls.is_empty() && input.manifest.id != "maester" {
        return Err(AppError::Runtime(
            "only the Maester adapter may emit manual-review controls".into(),
        ));
    }
    let mut manual_review_controls = BTreeSet::new();
    for control in &output.manual_review_controls {
        if !allowed_assets.contains(control.asset_id.as_str()) {
            return Err(AppError::Runtime(format!(
                "manual-review control {} references an asset outside the authorized run",
                control.rule_id
            )));
        }
        if !manual_review_controls.insert(control) {
            return Err(AppError::Runtime(
                "adapter manual-review controls must be unique".into(),
            ));
        }
        for (label, value, limit) in [
            ("rule ID", control.rule_id.as_str(), 512),
            ("title", control.title.as_str(), 512),
        ] {
            if value.trim().is_empty()
                || value.chars().count() > limit
                || value.chars().any(char::is_control)
            {
                return Err(AppError::Runtime(format!(
                    "manual-review control has an invalid {label}"
                )));
            }
        }
        if control.detail.as_deref().is_some_and(|detail| {
            detail.trim().is_empty()
                || detail.chars().count() > 4_096
                || detail.chars().any(char::is_control)
        }) {
            return Err(AppError::Runtime(
                "manual-review control has invalid upstream detail".into(),
            ));
        }
    }

    let mut observation_ids = BTreeSet::new();
    for observation in &output.observations {
        if observation.case_id != input.case_id
            || observation.run_id != input.scan_run_id
            || observation.engine_run_id != input.engine_run_id
            || observation.engine_id != input.manifest.id
        {
            return Err(AppError::Runtime(format!(
                "inventory observation {} has mismatched case, run, or engine provenance",
                observation.id
            )));
        }
        if observation.id.trim().is_empty() || !observation_ids.insert(observation.id.as_str()) {
            return Err(AppError::Runtime(
                "adapter inventory observation identifiers must be non-empty and unique".into(),
            ));
        }
        if !allowed_assets.contains(observation.asset_id.as_str()) {
            return Err(AppError::Runtime(format!(
                "inventory observation {} references an asset outside the authorized run",
                observation.id
            )));
        }
        if observation.pointer.is_empty()
            || observation.pointer.chars().count() > 512
            || observation.pointer.chars().any(char::is_control)
        {
            return Err(AppError::Runtime(format!(
                "inventory observation {} has an invalid raw evidence pointer",
                observation.id
            )));
        }
        let mut text_fields: Vec<(&str, &str)> = Vec::new();
        match &observation.kind {
            crate::domain::InventoryObservationKind::Service {
                endpoint,
                port,
                transport,
                scheme,
                http_status,
                ..
            } => {
                if port == &Some(0)
                    || http_status.is_some_and(|status| !(100..=599).contains(&status))
                {
                    return Err(AppError::Runtime(format!(
                        "inventory observation {} has an invalid service coordinate",
                        observation.id
                    )));
                }
                text_fields.push(("service endpoint", endpoint));
                if let Some(value) = transport.as_deref() {
                    text_fields.push(("service transport", value));
                }
                if let Some(value) = scheme.as_deref() {
                    text_fields.push(("service scheme", value));
                }
            }
            crate::domain::InventoryObservationKind::SoftwareComponent {
                name,
                version,
                package_type,
                purl,
            } => {
                text_fields.push(("component name", name));
                for (label, value) in [
                    ("component version", version.as_deref()),
                    ("component package type", package_type.as_deref()),
                    ("component purl", purl.as_deref()),
                ] {
                    if let Some(value) = value {
                        text_fields.push((label, value));
                    }
                }
            }
            crate::domain::InventoryObservationKind::CloudResource {
                resource_type,
                native_id,
                display_name,
            } => {
                text_fields.push(("cloud resource type", resource_type));
                if let Some(value) = native_id.as_deref() {
                    text_fields.push(("cloud native identifier", value));
                }
                if let Some(value) = display_name.as_deref() {
                    text_fields.push(("cloud display name", value));
                }
            }
            crate::domain::InventoryObservationKind::WorkflowComponent {
                component_type,
                name,
                model,
                ..
            } => {
                text_fields.push(("workflow component type", component_type));
                text_fields.push(("workflow component name", name));
                if let Some(value) = model.as_deref() {
                    text_fields.push(("workflow component model", value));
                }
            }
            crate::domain::InventoryObservationKind::WorkflowRelationship {
                source,
                target,
                condition,
            } => {
                text_fields.push(("workflow relationship source", source));
                text_fields.push(("workflow relationship target", target));
                if let Some(value) = condition.as_deref() {
                    text_fields.push(("workflow relationship condition", value));
                }
            }
        }
        for (label, value) in text_fields {
            if value.is_empty()
                || value.chars().count() > 512
                || value.chars().any(char::is_control)
            {
                return Err(AppError::Runtime(format!(
                    "inventory observation {} has invalid {label}",
                    observation.id
                )));
            }
        }
        let artifact = artifacts
            .get(observation.artifact_id.as_str())
            .ok_or_else(|| {
                AppError::Runtime(format!(
                    "inventory observation {} references an unknown raw artifact",
                    observation.id
                ))
            })?;
        if artifact.sha256 != observation.artifact_sha256
            || artifact.case_id != input.case_id
            || artifact.run_id != input.scan_run_id
            || artifact.engine_run_id != input.engine_run_id
        {
            return Err(AppError::Runtime(format!(
                "inventory observation {} raw artifact hash or execution context does not match",
                observation.id
            )));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{
        AssetKind, Confidence, DistributionMode, EngineCategory, EngineCompatibility, Evidence,
        EvidenceKind, FindingStatus, ImageReference, ManifestStatus, ScanPermission, Severity,
    };
    use chrono::Utc;

    struct TestAdapter {
        output: AdapterOutput,
    }

    struct CloudsplainingTestAdapter {
        output: AdapterOutput,
    }

    impl EngineAdapter for TestAdapter {
        fn engine_id(&self) -> &str {
            "scanner"
        }

        fn adapter_version(&self) -> &str {
            "1"
        }

        fn normalize(&self, _input: &AdapterInput<'_>) -> AppResult<AdapterOutput> {
            Ok(self.output.clone())
        }
    }

    impl EngineAdapter for CloudsplainingTestAdapter {
        fn engine_id(&self) -> &str {
            "cloudsplaining"
        }

        fn adapter_version(&self) -> &str {
            "1"
        }

        fn normalize(&self, _input: &AdapterInput<'_>) -> AppResult<AdapterOutput> {
            Ok(self.output.clone())
        }
    }

    fn manifest() -> EngineManifest {
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
            engine_version: Some("1".into()),
            reported_version: None,
            rule_version: None,
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
            command: vec!["scanner".into()],
            status: ManifestStatus::Experimental,
            notices: vec![],
            compatibility: EngineCompatibility::default(),
            execution: None,
        }
    }

    fn artifact() -> RawArtifact {
        RawArtifact {
            id: "artifact-1".into(),
            case_id: "case-1".into(),
            run_id: "run-1".into(),
            engine_run_id: "engine-run-1".into(),
            relative_path: "raw/result.json".into(),
            media_type: "application/json".into(),
            sha256: "abc123".into(),
            byte_length: 2,
            created_at: Utc::now(),
            contains_sensitive_data: true,
        }
    }

    fn finding(artifact: &RawArtifact) -> Finding {
        Finding {
            family: None,
            severity_basis_code: None,
            confidence_basis_code: None,
            context_factors: Vec::new(),
            id: "finding-1".into(),
            case_id: "case-1".into(),
            first_seen_run_id: "run-1".into(),
            last_seen_run_id: "run-1".into(),
            fingerprint: "scanner:asset-1:check-1".into(),
            title: "Finding".into(),
            plain_language_summary: "Summary".into(),
            possible_impact: "Impact".into(),
            severity: Severity::High,
            confidence: Confidence::High,
            priority: 80,
            priority_reasons: vec![],
            asset_ids: vec!["asset-1".into()],
            evidence: vec![Evidence {
                id: "evidence-1".into(),
                finding_id: "finding-1".into(),
                run_id: "run-1".into(),
                engine_run_id: Some(artifact.engine_run_id.clone()),
                kind: EvidenceKind::RawToolOutput,
                engine_id: "scanner".into(),
                scanner_details: None,
                source_rule: None,
                result_pointer_sha256: None,
                observed_at: Utc::now(),
                summary: "raw evidence".into(),
                location: None,
                artifact_id: artifact.id.clone(),
                artifact_sha256: artifact.sha256.clone(),
                pointer: Some("/result/0".into()),
                redacted: false,
            }],
            control_references: vec![],
            recommendation: "Ask an expert".into(),
            verification_guidance: "Run again".into(),
            rollback_considerations: None,
            official_references: vec![],
            recommended_expert_type: "Security engineer".into(),
            status: FindingStatus::Unreviewed,
            tags: vec![],
        }
    }

    fn inventory_observation(artifact: &RawArtifact) -> InventoryObservation {
        InventoryObservation {
            id: "inventory-1".into(),
            case_id: "case-1".into(),
            run_id: "run-1".into(),
            engine_run_id: "engine-run-1".into(),
            asset_id: "asset-1".into(),
            engine_id: "scanner".into(),
            kind: crate::domain::InventoryObservationKind::Service {
                endpoint: "service.example.test".into(),
                port: Some(443),
                transport: Some("tcp".into()),
                scheme: Some("https".into()),
                http_status: Some(200),
                tls: Some(true),
            },
            artifact_id: artifact.id.clone(),
            artifact_sha256: artifact.sha256.clone(),
            pointer: "/lines/1".into(),
            observed_at: artifact.created_at,
        }
    }

    #[test]
    fn native_identifier_map_requires_an_explicit_matching_provider() {
        let make_asset = |id: &str, provider: Option<&str>| Asset {
            id: id.into(),
            kind: AssetKind::CloudAccount,
            name: id.into(),
            provider: provider.map(str::to_owned),
            region: None,
            identifiers: vec![crate::domain::AssetIdentifier {
                namespace: "aws_account_id".into(),
                value: "111122223333".into(),
            }],
            discovered_from: vec![],
            candidate: false,
            owner_confirmed: true,
            internet_exposed: None,
            contains_sensitive_data: None,
            metadata: BTreeMap::new(),
        };
        let map = AdapterAssetIdentifierMap::from_assets(&[
            make_asset("missing-provider", None),
            make_asset("wrong-provider", Some("azure")),
            make_asset("exact-provider", Some("AWS")),
        ]);

        assert_eq!(
            map.candidates(Some("aws"), "111122223333"),
            Some(&BTreeSet::from(["exact-provider".to_owned()]))
        );
    }

    #[test]
    fn missing_adapter_returns_none_instead_of_fake_findings() {
        let manifest = manifest();
        let artifacts = vec![artifact()];
        let assets = vec!["asset-1".into()];
        let asset_identifier_map = AdapterAssetIdentifierMap::default();
        let input = AdapterInput {
            case_id: "case-1",
            scan_run_id: "run-1",
            engine_run_id: "engine-run-1",
            manifest: &manifest,
            ai_system_applicable: false,
            ai_generated_artifact_applicable: false,
            asset_ids: &assets,
            asset_identifier_map: &asset_identifier_map,
            artifact_root: Path::new("/tmp"),
            raw_artifacts: &artifacts,
        };

        let output = AdapterRegistry::default()
            .normalize(&input)
            .expect("registry result");
        assert!(output.is_none());
    }

    #[test]
    fn manual_review_controls_are_reserved_for_bounded_maester_output() {
        let manifest = manifest();
        let artifact = artifact();
        let adapter = TestAdapter {
            output: AdapterOutput {
                unattributed: Vec::new(),
                unevaluated_targets: Vec::new(),
                security_template_executions: Vec::new(),
                manual_review_controls: vec![crate::domain::ManualReviewControl {
                    asset_id: "asset-1".into(),
                    rule_id: "MT.1003".into(),
                    title: "Needs review".into(),
                    detail: Some("Check the tenant exception.".into()),
                }],
                findings: Vec::new(),
                observations: Vec::new(),
                warnings: Vec::new(),
                complete: true,
            },
        };
        let artifacts = vec![artifact];
        let assets = vec!["asset-1".into()];
        let asset_identifier_map = AdapterAssetIdentifierMap::default();
        let input = AdapterInput {
            case_id: "case-1",
            scan_run_id: "run-1",
            engine_run_id: "engine-run-1",
            manifest: &manifest,
            ai_system_applicable: false,
            ai_generated_artifact_applicable: false,
            asset_ids: &assets,
            asset_identifier_map: &asset_identifier_map,
            artifact_root: Path::new("/tmp"),
            raw_artifacts: &artifacts,
        };

        let error = validate_adapter_output(&input, &adapter, &adapter.output)
            .expect_err("a non-Maester adapter must not invent manual-review controls");
        assert!(error.to_string().contains("only the Maester adapter"));
    }

    #[test]
    fn inventory_observations_must_be_bounded_control_clean_and_run_bound() {
        let manifest = manifest();
        let artifact = artifact();
        let mut bad_observation = inventory_observation(&artifact);
        bad_observation.kind = crate::domain::InventoryObservationKind::Service {
            endpoint: "service.example.test\nforged".into(),
            port: Some(443),
            transport: Some("tcp".into()),
            scheme: Some("https".into()),
            http_status: Some(200),
            tls: Some(true),
        };
        let adapter = TestAdapter {
            output: AdapterOutput {
                unattributed: Vec::new(),
                unevaluated_targets: Vec::new(),
                security_template_executions: Vec::new(),
                manual_review_controls: Vec::new(),
                findings: Vec::new(),
                observations: vec![bad_observation],
                warnings: Vec::new(),
                complete: true,
            },
        };
        let artifacts = vec![artifact];
        let assets = vec!["asset-1".into()];
        let asset_identifier_map = AdapterAssetIdentifierMap::default();
        let input = AdapterInput {
            case_id: "case-1",
            scan_run_id: "run-1",
            engine_run_id: "engine-run-1",
            manifest: &manifest,
            ai_system_applicable: false,
            ai_generated_artifact_applicable: false,
            asset_ids: &assets,
            asset_identifier_map: &asset_identifier_map,
            artifact_root: Path::new("/tmp"),
            raw_artifacts: &artifacts,
        };

        let error = validate_adapter_output(&input, &adapter, &adapter.output)
            .expect_err("control characters in inventory text must be rejected");
        assert!(error.to_string().contains("service endpoint"));
    }

    #[test]
    fn evidence_must_reference_the_exact_hashed_artifact() {
        let manifest = manifest();
        let artifact = artifact();
        let mut bad_finding = finding(&artifact);
        bad_finding.evidence[0].artifact_sha256 = "forged".into();
        let adapter = TestAdapter {
            output: AdapterOutput {
                unattributed: Vec::new(),
                unevaluated_targets: Vec::new(),
                security_template_executions: Vec::new(),
                manual_review_controls: Vec::new(),
                findings: vec![bad_finding],
                observations: Vec::new(),
                warnings: vec![],
                complete: true,
            },
        };
        let artifacts = vec![artifact];
        let assets = vec!["asset-1".into()];
        let asset_identifier_map = AdapterAssetIdentifierMap::default();
        let input = AdapterInput {
            case_id: "case-1",
            scan_run_id: "run-1",
            engine_run_id: "engine-run-1",
            manifest: &manifest,
            ai_system_applicable: false,
            ai_generated_artifact_applicable: false,
            asset_ids: &assets,
            asset_identifier_map: &asset_identifier_map,
            artifact_root: Path::new("/tmp"),
            raw_artifacts: &artifacts,
        };

        let error = validate_adapter_output(&input, &adapter, &adapter.output)
            .expect_err("forged evidence rejected");
        assert!(error.to_string().contains("hash or execution context"));
    }

    #[test]
    fn scanner_provided_details_are_bounded_untrusted_evidence() {
        let manifest = manifest();
        let artifact = artifact();
        let mut bad_finding = finding(&artifact);
        bad_finding.evidence[0].scanner_details = Some(crate::domain::ScannerFindingDetails {
            description: Some("rule text with\na control character".into()),
            remediation: None,
            installed_version: None,
            fixed_version: None,
            aws_iam_policy: None,
            cwe_ids: Vec::new(),
            cvss: Vec::new(),
            benchmarks: Vec::new(),
            advisory_aliases: Vec::new(),
        });
        let adapter = TestAdapter {
            output: AdapterOutput {
                unattributed: Vec::new(),
                unevaluated_targets: Vec::new(),
                security_template_executions: Vec::new(),
                manual_review_controls: Vec::new(),
                findings: vec![bad_finding],
                observations: Vec::new(),
                warnings: vec![],
                complete: true,
            },
        };
        let artifacts = vec![artifact];
        let assets = vec!["asset-1".into()];
        let asset_identifier_map = AdapterAssetIdentifierMap::default();
        let input = AdapterInput {
            case_id: "case-1",
            scan_run_id: "run-1",
            engine_run_id: "engine-run-1",
            manifest: &manifest,
            ai_system_applicable: false,
            ai_generated_artifact_applicable: false,
            asset_ids: &assets,
            asset_identifier_map: &asset_identifier_map,
            artifact_root: Path::new("/tmp"),
            raw_artifacts: &artifacts,
        };

        let error = validate_adapter_output(&input, &adapter, &adapter.output)
            .expect_err("control characters in scanner text must be rejected");
        assert!(error.to_string().contains("scanner-provided description"));
    }

    #[test]
    fn aws_iam_policy_context_is_bounded_untrusted_cloudsplaining_evidence() {
        let mut manifest = manifest();
        manifest.id = "cloudsplaining".into();
        let artifact = artifact();
        let mut bad_finding = finding(&artifact);
        bad_finding.evidence[0].engine_id = "cloudsplaining".into();
        bad_finding.evidence[0].scanner_details = Some(crate::domain::ScannerFindingDetails {
            description: None,
            remediation: None,
            installed_version: None,
            fixed_version: None,
            aws_iam_policy: Some(crate::domain::AwsIamPolicyFindingDetails {
                policy_source: crate::domain::AwsIamPolicySource::CustomerManaged,
                policy_name: "Policy".into(),
                finding_identity: "Action".into(),
                actions: vec!["iam:GetObject\nunsafe".into()],
                actions_complete: false,
                attached_to: crate::domain::AwsIamAttachedTo {
                    roles: vec![],
                    groups: vec![],
                    users: vec![],
                    complete: true,
                },
            }),
            cwe_ids: Vec::new(),
            cvss: Vec::new(),
            benchmarks: Vec::new(),
            advisory_aliases: Vec::new(),
        });
        let adapter = CloudsplainingTestAdapter {
            output: AdapterOutput {
                unattributed: Vec::new(),
                unevaluated_targets: Vec::new(),
                security_template_executions: Vec::new(),
                manual_review_controls: Vec::new(),
                findings: vec![bad_finding],
                observations: Vec::new(),
                warnings: vec![],
                complete: true,
            },
        };
        let artifacts = vec![artifact];
        let assets = vec!["asset-1".into()];
        let asset_identifier_map = AdapterAssetIdentifierMap::default();
        let input = AdapterInput {
            case_id: "case-1",
            scan_run_id: "run-1",
            engine_run_id: "engine-run-1",
            manifest: &manifest,
            ai_system_applicable: false,
            ai_generated_artifact_applicable: false,
            asset_ids: &assets,
            asset_identifier_map: &asset_identifier_map,
            artifact_root: Path::new("/tmp"),
            raw_artifacts: &artifacts,
        };

        let error = validate_adapter_output(&input, &adapter, &adapter.output)
            .expect_err("control characters in IAM context must be rejected");
        assert!(
            error
                .to_string()
                .contains("invalid scanner-provided AWS IAM policy context")
        );
    }

    #[test]
    fn evidence_must_name_the_exact_producing_engine_run() {
        let manifest = manifest();
        let artifact = artifact();
        let mut bad_finding = finding(&artifact);
        bad_finding.evidence[0].engine_run_id = Some("another-engine-run".into());
        let adapter = TestAdapter {
            output: AdapterOutput {
                unattributed: Vec::new(),
                unevaluated_targets: Vec::new(),
                security_template_executions: Vec::new(),
                manual_review_controls: Vec::new(),
                findings: vec![bad_finding],
                observations: Vec::new(),
                warnings: vec![],
                complete: true,
            },
        };
        let artifacts = vec![artifact];
        let assets = vec!["asset-1".into()];
        let asset_identifier_map = AdapterAssetIdentifierMap::default();
        let input = AdapterInput {
            case_id: "case-1",
            scan_run_id: "run-1",
            engine_run_id: "engine-run-1",
            manifest: &manifest,
            ai_system_applicable: false,
            ai_generated_artifact_applicable: false,
            asset_ids: &assets,
            asset_identifier_map: &asset_identifier_map,
            artifact_root: Path::new("/tmp"),
            raw_artifacts: &artifacts,
        };

        let error = validate_adapter_output(&input, &adapter, &adapter.output)
            .expect_err("cross-run evidence rejected");
        assert!(error.to_string().contains("mismatched finding, scan run"));
    }
}
