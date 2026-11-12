//! Mechanical validation of an explicitly selected, externally reported bundle.
//! No supplied manifest or verifier receipt grants workflow trust or scan authority.
use super::{
    CloudflareDocument, CloudflareValidationReceipt, UPSTREAM_COMMIT, bundle_io::BundleRoot,
    strict_json, validate_bytes,
};
use crate::case_archive_io::validate_path;
use crate::domain::Severity;
use crate::error::{AppError, AppResult};
use crate::provider_report::{
    AgentAuditRecord, ProviderProvenance, ProviderReportProjection, ProviderReportedCounts,
    ProviderSourceLocation, ProviderVerdict,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

const MANIFEST: &str = "provider-manifest.json";
pub(super) const REQUIRED: &[&str] = &[
    "run-metadata.json",
    "architecture.md",
    "coverage-ledger.json",
    "findings.json",
    "REPORT.md",
    "FINDINGS-DETAIL.md",
    "NEEDS-VALIDATION.md",
];
const MIB: u64 = 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuditBinding {
    pub case_id: String,
    pub asset_id: String,
    pub run_id: String,
    pub task_id: String,
    pub session_id: String,
    pub attempt_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleFile {
    pub path: String,
    pub sha256: String,
    pub byte_length: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceView {
    pub canonical_snapshot_id: Option<String>,
    pub canonical_snapshot_sha256: Option<String>,
    pub view_id: String,
    pub view_sha256: String,
    pub source_ref: String,
    pub policy_id: String,
    pub files: Vec<BundleFile>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReportedVerifierAssignment {
    pub assignment_id: String,
    pub binding: AuditBinding,
    pub agent_id: String,
    pub role: String,
    pub fingerprint: String,
    pub view_sha256: String,
    pub record_sha256: String,
    pub output_path: String,
    pub started_at: DateTime<Utc>,
    pub finished_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleManifest {
    pub schema_version: String,
    pub provider_id: String,
    pub upstream_commit: String,
    pub binding: AuditBinding,
    pub source: SourceView,
    pub files: Vec<BundleFile>,
    pub verifier_assignments: Vec<ReportedVerifierAssignment>,
    pub reported_counts: ProviderReportedCounts,
}

#[derive(Debug, Serialize)]
pub struct BundleValidationReceipt {
    pub schema_version: &'static str,
    pub validation_scope: &'static str,
    pub valid: bool,
    pub manifest_sha256: String,
    pub bundle_sha256: String,
    pub binding: AuditBinding,
    pub source_view_sha256: String,
    pub canonical_snapshot_binding_verified: bool,
    pub source_authorization_verified: bool,
    pub provenance: ProviderProvenance,
    pub upstream_validations: Vec<CloudflareValidationReceipt>,
    pub reference_errors: Vec<String>,
    pub projection: Option<ProviderReportProjection>,
    pub audit_performed: bool,
    pub admission_ready: bool,
}

fn invalid(message: &str) -> AppError {
    AppError::InvalidRequest(format!("Cloudflare bundle: {message}"))
}
fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn valid_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
}
fn agent_id(value: &str) -> bool {
    valid_id(value)
        && value.len() <= 64
        && value.bytes().all(|c| !c.is_ascii_uppercase())
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && validate_path(value).is_ok()
}
fn binding_valid(value: &AuditBinding) -> bool {
    [
        &value.case_id,
        &value.asset_id,
        &value.run_id,
        &value.task_id,
        &value.session_id,
        &value.attempt_id,
    ]
    .into_iter()
    .all(|s| valid_id(s))
}

/// Versioned file-index digest: sorted UTF-8 path length (u64 LE), path, raw
/// SHA-256 bytes, file byte length (u64 LE), prefixed by the fixed recipe string.
pub fn file_index_digest(files: &[BundleFile]) -> AppResult<String> {
    let mut sorted = files.iter().collect::<Vec<_>>();
    sorted.sort_by(|a, b| a.path.cmp(&b.path));
    let mut digest = Sha256::new();
    digest.update(b"ai-security-scanner.file-index/v1\0");
    for file in sorted {
        if !valid_hash(&file.sha256) {
            return Err(invalid("invalid file digest"));
        }
        digest.update((file.path.len() as u64).to_le_bytes());
        digest.update(file.path.as_bytes());
        digest.update(hex::decode(&file.sha256).map_err(|_| invalid("invalid file digest"))?);
        digest.update(file.byte_length.to_le_bytes());
    }
    Ok(hex::encode(digest.finalize()))
}

fn check_index(
    files: &[BundleFile],
    max_files: usize,
    total_limit: u64,
    per_file: u64,
) -> AppResult<()> {
    if files.is_empty() || files.len() > max_files {
        return Err(invalid("file index count exceeds its bounds"));
    }
    let mut names = BTreeSet::new();
    let mut components = BTreeMap::new();
    let mut total = 0u64;
    for file in files {
        validate_path(&file.path)?;
        if file.path.split('/').count() > 32
            || !valid_hash(&file.sha256)
            || file.byte_length > per_file
        {
            return Err(invalid("invalid file index entry"));
        }
        if !names.insert(file.path.clone()) {
            return Err(invalid("duplicate file path"));
        }
        let mut prefix = String::new();
        for component in file.path.split('/') {
            if !prefix.is_empty() {
                prefix.push('/');
            }
            prefix.push_str(component);
            if components
                .insert(prefix.to_lowercase(), prefix.clone())
                .is_some_and(|old| old != prefix)
            {
                return Err(invalid("case-colliding file paths"));
            }
        }
        total = total
            .checked_add(file.byte_length)
            .ok_or_else(|| invalid("file size overflow"))?;
    }
    if total > total_limit {
        return Err(invalid("file index exceeds its total byte limit"));
    }
    for name in &names {
        let mut prefix = name.as_str();
        while let Some((parent, _)) = prefix.rsplit_once('/') {
            if names.contains(parent) {
                return Err(invalid("file/directory path collision"));
            }
            prefix = parent;
        }
    }
    Ok(())
}

fn retained_agent(path: &str) -> Option<&str> {
    let parts = path.split('/').collect::<Vec<_>>();
    (parts.len() >= 4 && parts[0] == "agents" && agent_id(parts[1]) && parts[2] == "artifacts")
        .then(|| parts[1])
}

pub(super) fn check_manifest(manifest: &BundleManifest) -> AppResult<()> {
    if manifest.schema_version != "ai-security-scanner.cloudflare-bundle/v1"
        || manifest.provider_id != "cloudflare-security-audit"
        || manifest.upstream_commit != UPSTREAM_COMMIT
        || !binding_valid(&manifest.binding)
    {
        return Err(invalid("unsupported manifest identity or binding"));
    }
    let source = &manifest.source;
    if source
        .canonical_snapshot_id
        .as_ref()
        .is_some_and(|id| !valid_id(id))
        || source
            .canonical_snapshot_sha256
            .as_ref()
            .is_some_and(|hash| !valid_hash(hash))
        || source.canonical_snapshot_id.is_some() != source.canonical_snapshot_sha256.is_some()
        || !valid_id(&source.view_id)
        || !valid_id(&source.policy_id)
        || !valid_hash(&source.view_sha256)
        || source.source_ref.is_empty()
        || source.source_ref.len() > 1024
    {
        return Err(invalid("invalid declared source binding"));
    }
    check_index(&manifest.files, 4096, 64 * MIB, 8 * MIB)?;
    check_index(&source.files, 10_000, 128 * MIB, 8 * MIB)?;
    if file_index_digest(&source.files)? != source.view_sha256 {
        return Err(invalid("source view index digest mismatch"));
    }
    for name in REQUIRED {
        if !manifest.files.iter().any(|file| &file.path == name) {
            return Err(invalid("a required native document is missing"));
        }
    }
    for file in &manifest.files {
        if !REQUIRED.contains(&file.path.as_str()) && retained_agent(&file.path).is_none() {
            return Err(invalid(
                "only native documents and retained agent artifacts may be indexed",
            ));
        }
        if matches!(file.path.as_str(), "findings.json" | "coverage-ledger.json")
            && file.byte_length > 5 * MIB
        {
            return Err(invalid("native JSON exceeds its 5 MiB limit"));
        }
    }
    if manifest.verifier_assignments.len() > 2000 {
        return Err(invalid("too many verifier assignments"));
    }
    Ok(())
}

pub(super) fn verified_read(root: &mut BundleRoot, file: &BundleFile) -> AppResult<Vec<u8>> {
    let bytes = root.read(&file.path, file.byte_length)?;
    if bytes.len() as u64 != file.byte_length || digest(&bytes) != file.sha256 {
        return Err(invalid(
            "indexed file content does not match its size and digest",
        ));
    }
    Ok(bytes)
}

struct SourceFile {
    sha256: String,
    lines: u64,
}
struct References<'a> {
    source: &'a BTreeMap<String, SourceFile>,
    files: &'a BTreeMap<String, Vec<u8>>,
    errors: Vec<String>,
}
impl References<'_> {
    fn error(&mut self, message: &str) {
        if self.errors.len() < 100 {
            self.errors.push(message.into());
        }
    }
    fn source_path(&mut self, path: &str) -> bool {
        let valid = self.source.contains_key(path);
        if !valid {
            self.error("a source reference is absent from the verified view index");
        }
        valid
    }
    fn source_paths(&mut self, paths: &Value) {
        if let Some(paths) = paths.as_array() {
            for path in paths.iter().filter_map(Value::as_str) {
                let prefix = format!("{path}/");
                if !self.source.contains_key(path)
                    && !self
                        .source
                        .range(prefix.clone()..)
                        .next()
                        .is_some_and(|(file, _)| file.starts_with(&prefix))
                {
                    self.error("a reviewed path is absent from the verified view index");
                }
            }
        }
    }
    fn locations(&mut self, record: &Value) -> Vec<ProviderSourceLocation> {
        let mut locations = Vec::new();
        for field in ["trace", "evidence"] {
            for reference in record[field].as_array().into_iter().flatten() {
                let path = reference["file"].as_str().unwrap_or_default();
                if !self.source_path(path) {
                    continue;
                }
                let file = &self.source[path];
                let line = reference["line"].as_u64().unwrap_or_default();
                if line == 0 || line > file.lines {
                    self.error("a source reference line is outside the reviewed file");
                } else {
                    locations.push(ProviderSourceLocation {
                        path: path.into(),
                        line,
                        view_file_sha256: file.sha256.clone(),
                    });
                }
            }
        }
        for change in record["remediation"]["code_changes"]
            .as_array()
            .into_iter()
            .flatten()
        {
            if let Some(path) = change["file_name"].as_str() {
                // A proposed fix may introduce a new file. Never read or write it.
                if validate_path(path).is_err() {
                    self.error("a proposed code-change path is unsafe");
                }
            }
        }
        locations
    }
    fn checks(&mut self, unit: &Value) {
        self.source_paths(&unit["reviewed_paths"]);
        for check in unit["local_checks"].as_array().into_iter().flatten() {
            self.source_paths(&check["reviewed_paths"]);
            if let Some(path) = check["artifact"].as_str()
                && (!self.files.contains_key(path)
                    || retained_agent(path) != check["agent_id"].as_str())
            {
                self.error("local-check artifact is missing or has a different agent owner");
            }
        }
    }
}

/// This entry never persists or admits a finding. All caller-supplied identity,
/// receipt and source-lineage assertions remain explicitly reported-only.
pub async fn validate_bundle(
    bundle_path: &Path,
    view_path: &Path,
) -> AppResult<BundleValidationReceipt> {
    let mut bundle = BundleRoot::open(bundle_path)?;
    let manifest_bytes = bundle.read(MANIFEST, 4 * MIB)?;
    let manifest: BundleManifest = serde_json::from_value(strict_json::parse(&manifest_bytes)?)
        .map_err(|_| invalid("manifest fields do not match the versioned contract"))?;
    check_manifest(&manifest)?;
    let mut files = BTreeMap::new();
    for entry in &manifest.files {
        files.insert(entry.path.clone(), verified_read(&mut bundle, entry)?);
    }
    for name in REQUIRED {
        std::str::from_utf8(&files[*name])
            .map_err(|_| invalid("native documents must be UTF-8"))?;
    }
    let mut view = BundleRoot::open(view_path)?;
    let mut source = BTreeMap::new();
    for entry in &manifest.source.files {
        let bytes = verified_read(&mut view, entry)?;
        std::str::from_utf8(&bytes).map_err(|_| invalid("source view must contain UTF-8 text"))?;
        let lines = bytes.iter().filter(|c| **c == b'\n').count() as u64
            + u64::from(!bytes.is_empty() && !bytes.ends_with(b"\n"));
        source.insert(
            entry.path.clone(),
            SourceFile {
                sha256: entry.sha256.clone(),
                lines,
            },
        );
    }
    let mut receipt = validation_receipt(&manifest, &manifest_bytes)?;
    for (kind, file) in [
        (CloudflareDocument::Findings, "findings.json"),
        (CloudflareDocument::CoverageLedger, "coverage-ledger.json"),
    ] {
        receipt
            .upstream_validations
            .push(validate_bytes(kind, &files[file]).await?);
    }
    if receipt
        .upstream_validations
        .iter()
        .all(|result| result.validation.valid)
    {
        let records = strict_json::parse(&files["findings.json"])?;
        let ledger = strict_json::parse(&files["coverage-ledger.json"])?;
        let metadata = strict_json::parse(&files["run-metadata.json"])?;
        let (projection, errors, candidate_records) =
            check_references(&manifest, &files, &source, &records, &ledger, &metadata)?;
        receipt.reference_errors = errors;
        if !candidate_records.is_empty() {
            let candidate_bytes = serde_json::to_vec(&candidate_records)?;
            receipt
                .upstream_validations
                .push(validate_bytes(CloudflareDocument::Findings, &candidate_bytes).await?);
        }
        receipt.valid = receipt.reference_errors.is_empty()
            && receipt
                .upstream_validations
                .iter()
                .all(|result| result.validation.valid);
        if receipt.valid {
            receipt.projection = Some(projection);
        }
    }
    bundle.verify_unchanged()?;
    view.verify_unchanged()?;
    Ok(receipt)
}

/// Shared binding comparison; terminal status is checked only by the bundle path.
pub(super) fn metadata_binding_matches(metadata: &Value, run_id: &str, source_ref: &str) -> bool {
    metadata.is_object()
        && metadata["run_id"].as_str() == Some(run_id)
        && metadata["source_ref"].as_str() == Some(source_ref)
        && metadata["execution_policy"] == "sandboxed-source-and-local-only"
}

fn check_references(
    manifest: &BundleManifest,
    files: &BTreeMap<String, Vec<u8>>,
    source: &BTreeMap<String, SourceFile>,
    findings: &Value,
    ledger: &Value,
    metadata: &Value,
) -> AppResult<(ProviderReportProjection, Vec<String>, Vec<Value>)> {
    let mut refs = References {
        source,
        files,
        errors: Vec::new(),
    };
    let status = metadata["run_status"].as_str().unwrap_or_default();
    let profile = metadata["profile"].as_str().unwrap_or_default();
    if !metadata.is_object()
        || ["repo", "target"]
            .iter()
            .any(|field| metadata[field].as_str().is_none_or(|s| s.trim().is_empty()))
        || metadata
            .get("budget")
            .is_none_or(|budget| !budget.is_null() && budget.as_u64().is_none())
    {
        refs.error("native run metadata lacks required repository, target or budget fields");
    }
    if metadata["budget"]
        .as_u64()
        .is_some_and(|budget| budget < manifest.verifier_assignments.len() as u64)
    {
        refs.error("reported verifier assignments exceed the declared invocation budget");
    }
    if !matches!(status, "complete" | "incomplete")
        || !matches!(profile, "quick" | "standard" | "deep")
        || !metadata_binding_matches(
            metadata,
            &manifest.binding.run_id,
            &manifest.source.source_ref,
        )
    {
        refs.error("native run metadata does not match the terminal bundle binding");
    }
    if status == "incomplete"
        && metadata["incomplete_reason"]
            .as_str()
            .is_none_or(|s| s.trim().is_empty())
    {
        refs.error("an incomplete run needs a specific reason");
    }
    let scopes = metadata["scope_paths"].as_array();
    if scopes.is_none_or(Vec::is_empty) {
        refs.error("native run metadata has no scope paths");
    } else {
        let mut unique = BTreeSet::new();
        for scope in scopes.into_iter().flatten() {
            let path = scope.as_str().unwrap_or_default();
            if !unique.insert(path) || (path != "." && validate_path(path).is_err()) {
                refs.error("invalid or duplicate scope path");
            }
        }
        for path in source.keys() {
            let mut candidate = Some(path.as_str());
            let mut in_scope = unique.contains(".");
            while let Some(prefix) = candidate {
                in_scope |= unique.contains(prefix);
                candidate = prefix.rsplit_once('/').map(|(parent, _)| parent);
            }
            if !in_scope {
                refs.error("reviewed source falls outside declared scope paths");
            }
        }
    }
    let records = findings
        .as_array()
        .ok_or_else(|| invalid("findings must be an array"))?;
    let units = ledger
        .as_array()
        .ok_or_else(|| invalid("ledger must be an array"))?;
    if status == "complete" && units.is_empty() {
        refs.error("a complete run cannot have an empty coverage ledger");
    }
    let record_map = records
        .iter()
        .map(|r| (r["fingerprint"].as_str().unwrap_or_default(), r))
        .collect::<BTreeMap<_, _>>();
    let mut linked: BTreeMap<&str, Vec<String>> = BTreeMap::new();
    let mut linked_bytes = 0usize;
    let mut hunters: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    let mut unresolved = BTreeSet::new();
    let mut coverage = BTreeMap::new();
    let mut known_agents = manifest
        .verifier_assignments
        .iter()
        .map(|a| a.agent_id.as_str())
        .collect::<BTreeSet<_>>();
    for unit in units {
        let state = unit["status"].as_str().unwrap_or_default();
        *coverage.entry(state.into()).or_insert(0usize) += 1;
        if state == "out_of_scope" {
            for path in unit["starting_paths"].as_array().into_iter().flatten() {
                if path.as_str().is_none_or(|p| validate_path(p).is_err()) {
                    refs.error("an out-of-scope starting path is unsafe");
                }
            }
        } else {
            refs.source_paths(&unit["starting_paths"]);
        }
        refs.checks(unit);
        for attempt in
            std::iter::once(unit).chain(unit["attempts"].as_array().into_iter().flatten())
        {
            if let Some(owner) = attempt["agent_id"].as_str() {
                known_agents.insert(owner);
            }
            for check in attempt["local_checks"].as_array().into_iter().flatten() {
                if let Some(owner) = check["agent_id"].as_str() {
                    known_agents.insert(owner);
                }
            }
        }
        for attempt in unit["attempts"].as_array().into_iter().flatten() {
            refs.checks(attempt);
        }
        if status == "complete" && matches!(state, "planned" | "in_progress") {
            refs.error("a complete run retains unexecuted coverage units");
        }
        for fingerprint in unit["result_fingerprints"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
        {
            // A large coverage ID repeated for many fingerprints must not
            // amplify a bounded native ledger into an unbounded projection.
            linked_bytes += unit["coverage_id"].as_str().unwrap_or_default().len();
            if linked_bytes > 8 * MIB as usize {
                return Err(invalid("coverage reference projection exceeds 8 MiB"));
            }
            linked
                .entry(fingerprint)
                .or_default()
                .push(unit["coverage_id"].as_str().unwrap_or_default().into());
            let owners = hunters.entry(fingerprint).or_default();
            // A carried same-source record is assigned to its current verifier,
            // not to a hunter (the pinned method explicitly permits this).
            if !matches!(
                unit["prior_status"].as_str(),
                Some("prior_confirmed_same_source" | "prior_needs_validation")
            ) {
                owners.insert(unit["agent_id"].as_str().unwrap_or_default());
            }
            for attempt in unit["attempts"].as_array().into_iter().flatten() {
                if attempt["result_fingerprints"]
                    .as_array()
                    .is_some_and(|values| {
                        values
                            .iter()
                            .any(|value| value.as_str() == Some(fingerprint))
                    })
                {
                    owners.insert(attempt["agent_id"].as_str().unwrap_or_default());
                }
            }
            if !record_map.contains_key(fingerprint) {
                unresolved.insert(fingerprint.to_owned());
                if status != "incomplete" || unit["unresolved"].as_array().is_none_or(Vec::is_empty)
                {
                    refs.error("an unvalidated candidate needs an incomplete run and explicit ledger blocker");
                }
            }
        }
    }
    for file in &manifest.files {
        if retained_agent(&file.path).is_some_and(|owner| !known_agents.contains(owner)) {
            refs.error("a retained artifact has no current or historical agent binding");
        }
    }
    let (verifiers, candidates) =
        check_verifiers(manifest, &record_map, &hunters, profile, &mut refs)?;
    let mut counts = ProviderReportedCounts::default();
    let mut normalized = Vec::new();
    for (index, record) in records.iter().enumerate() {
        let fingerprint = record["fingerprint"].as_str().unwrap_or_default();
        let verdict: ProviderVerdict = serde_json::from_value(record["verdict"].clone())
            .map_err(|_| invalid("unknown verdict"))?;
        let severity = if verdict == ProviderVerdict::Confirmed {
            let severity: Severity =
                serde_json::from_value(record["severity"]["overall_severity"].clone())
                    .map_err(|_| invalid("unknown provider severity"))?;
            counts.confirmed += 1;
            *counts
                .reported_confirmed_by_severity
                .entry(severity.clone())
                .or_default() += 1;
            Some(severity)
        } else {
            match verdict {
                ProviderVerdict::NeedsValidation => counts.needs_validation += 1,
                ProviderVerdict::Rejected => counts.rejected += 1,
                _ => {}
            }
            None
        };
        if !linked.contains_key(fingerprint) {
            refs.error("a retained finding has no current ledger fingerprint link");
        }
        let source_locations = refs.locations(record);
        normalized.push(AgentAuditRecord {
            fingerprint: fingerprint.into(),
            verdict,
            severity,
            native_record: record.clone(),
            native_record_index: index,
            native_record_sha256: digest(&serde_json::to_vec(record)?),
            source_locations,
            coverage_ids: linked.get(fingerprint).cloned().unwrap_or_default(),
            reported_verifier_assignments: verifiers.get(fingerprint).cloned().unwrap_or_default(),
        });
    }
    if counts != manifest.reported_counts {
        refs.error("reported counts disagree with the native verdict and severity records");
    }
    let projection = ProviderReportProjection {
        schema_version: "ai-security-scanner.provider-report/v1".into(),
        provider_id: manifest.provider_id.clone(),
        provenance: ProviderProvenance::ReportedOnly,
        reported_run_status: status.into(),
        reported_counts: counts,
        coverage_by_status: coverage,
        unresolved_candidates: unresolved.into_iter().collect(),
        records: normalized,
        native_coverage_ledger: ledger.clone(),
    };
    Ok((projection, refs.errors, candidates))
}

type ReportedVerifierIndex = BTreeMap<String, Vec<String>>;

fn check_verifiers(
    manifest: &BundleManifest,
    records: &BTreeMap<&str, &Value>,
    hunters: &BTreeMap<&str, BTreeSet<&str>>,
    profile: &str,
    refs: &mut References<'_>,
) -> AppResult<(ReportedVerifierIndex, Vec<Value>)> {
    let mut assignments = BTreeSet::new();
    let mut agents = BTreeSet::new();
    let mut outputs = BTreeSet::new();
    let mut roles: BTreeMap<(String, String), &ReportedVerifierAssignment> = BTreeMap::new();
    let mut candidates = BTreeMap::new();
    let mut candidate_bytes = 2u64;
    let mut result: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for assignment in &manifest.verifier_assignments {
        let valid = valid_id(&assignment.assignment_id)
            && agent_id(&assignment.agent_id)
            && assignment.binding == manifest.binding
            && assignment.view_sha256 == manifest.source.view_sha256
            && assignment.started_at <= assignment.finished_at
            && valid_hash(&assignment.record_sha256)
            && matches!(
                assignment.role.as_str(),
                "candidate_verifier" | "final_verifier"
            )
            && assignments.insert(&assignment.assignment_id)
            && agents.insert(&assignment.agent_id)
            && outputs.insert(&assignment.output_path)
            && retained_agent(&assignment.output_path) == Some(assignment.agent_id.as_str());
        if !valid {
            refs.error("verifier assignment has duplicate identity, ownership, time or source/run binding mismatch");
            continue;
        }
        let Some(record) = records.get(assignment.fingerprint.as_str()) else {
            refs.error("verifier assignment refers to an absent native finding");
            continue;
        };
        if hunters
            .get(assignment.fingerprint.as_str())
            .is_some_and(|owners| owners.contains(assignment.agent_id.as_str()))
        {
            refs.error("a verifier is also a linked candidate's assignment owner");
        }
        if roles
            .insert(
                (assignment.fingerprint.clone(), assignment.role.clone()),
                assignment,
            )
            .is_some()
        {
            refs.error("multiple active receipts claim the same verifier role");
        }
        let Some(bytes) = refs.files.get(&assignment.output_path) else {
            refs.error("verifier output is missing from retained artifacts");
            continue;
        };
        let output = strict_json::parse(bytes)?;
        if assignment.role == "candidate_verifier" {
            let encoded_record = serde_json::to_vec(&output["record"])?;
            candidate_bytes += encoded_record.len() as u64 + 1;
            if candidate_bytes > 5 * MIB {
                refs.error("candidate verifier records exceed their 5 MiB validation batch limit");
                continue;
            }
            if !candidate_contract(&output)
                || output["record"]["fingerprint"].as_str() != Some(&assignment.fingerprint)
                || record_digest(&output["record"])? != assignment.record_sha256
            {
                refs.error(
                    "candidate verifier output does not bind its native decision and record",
                );
            } else {
                refs.locations(&output["record"]);
                candidates.insert(assignment.fingerprint.clone(), output["record"].clone());
                if profile == "quick" && output["record"] != **record {
                    refs.error("a quick profile must retain its combined verifier's exact record");
                }
            }
        } else if !final_contract(&output, &assignment.fingerprint)
            || output["decision"] != "verified"
            || record_digest(record)? != assignment.record_sha256
        {
            refs.error("final verifier must verify the exact current record; unresolved replacements cannot be finalized");
        }
        result
            .entry(assignment.fingerprint.clone())
            .or_default()
            .push(assignment.assignment_id.clone());
    }
    for (fingerprint, record) in records {
        let candidate = roles.get(&(fingerprint.to_string(), "candidate_verifier".into()));
        let final_verifier = roles.get(&(fingerprint.to_string(), "final_verifier".into()));
        let needs_final = profile != "quick"
            && matches!(
                record["verdict"].as_str(),
                Some("confirmed" | "needs_validation")
            );
        if candidate.is_none() || (needs_final && final_verifier.is_none()) {
            refs.error("a retained record lacks required independent verifier receipts");
        }
        if let (Some(candidate), Some(final_verifier)) = (candidate, final_verifier)
            && candidate.finished_at > final_verifier.started_at
        {
            refs.error("final verification predates candidate validation completion");
        }
    }
    Ok((result, candidates.into_values().collect()))
}

/// Pinned Phase 3 envelope; schema validation of the returned record is separate.
pub(super) fn candidate_contract(output: &Value) -> bool {
    output
        .as_object()
        .is_some_and(|o| o.len() == 2 && o.contains_key("record"))
        && matches!(
            output["decision"].as_str(),
            Some("confirmed" | "needs_validation" | "rejected")
        )
        && output["decision"] == output["record"]["verdict"]
}
pub(super) fn record_digest(record: &Value) -> AppResult<String> {
    Ok(digest(&serde_json::to_vec(record)?))
}

/// Pinned Phase 5 envelope; replacements still need the findings validator.
pub(super) fn final_contract(output: &Value, fingerprint: &str) -> bool {
    match output["decision"].as_str() {
        Some("verified") => {
            output.as_object().is_some_and(|o| o.len() == 2)
                && output["fingerprint"].as_str() == Some(fingerprint)
        }
        Some("replace") => {
            output
                .as_object()
                .is_some_and(|o| o.len() == 3 && o.contains_key("record"))
                && output["reason"]
                    .as_str()
                    .is_some_and(|s| !s.trim().is_empty())
        }
        _ => false,
    }
}

/// Empty, untrusted receipt also used for an assembled bundle that exceeds limits.
pub(crate) fn validation_receipt(
    manifest: &BundleManifest,
    manifest_bytes: &[u8],
) -> AppResult<BundleValidationReceipt> {
    let mut all_files = manifest.files.clone();
    all_files.push(BundleFile {
        path: MANIFEST.into(),
        sha256: digest(manifest_bytes),
        byte_length: manifest_bytes.len() as u64,
    });
    Ok(BundleValidationReceipt {
        schema_version: "ai-security-scanner.cloudflare-bundle-validation/v1",
        validation_scope: "reported_bundle",
        valid: false,
        manifest_sha256: digest(manifest_bytes),
        bundle_sha256: file_index_digest(&all_files)?,
        binding: manifest.binding.clone(),
        source_view_sha256: manifest.source.view_sha256.clone(),
        canonical_snapshot_binding_verified: false,
        source_authorization_verified: false,
        provenance: ProviderProvenance::ReportedOnly,
        upstream_validations: Vec::new(),
        reference_errors: Vec::new(),
        projection: None,
        audit_performed: false,
        admission_ready: false,
    })
}
