//! Pure planning: no storage mutation, publication, or authority creation.
use super::*;
use crate::cloudflare_provider::{
    audit::sealed::{TerminalState, VerifiedSealedAudit},
    source_view::{domain_digest, valid_hash, valid_id},
};
use crate::domain::*;
use crate::provider_report::ProviderReportProjection;
use crate::workspace_snapshot::{
    WORKSPACE_SNAPSHOT_REFERENCE_METADATA_KEY, WorkspaceSnapshotReference,
};
use sha2::Digest;

#[derive(Debug, Clone, Copy, Serialize, thiserror::Error)]
#[serde(rename_all = "snake_case")]
pub enum PlannerRefusal {
    #[error("binding_not_provable")]
    BindingNotProvable,
    #[error("identity_conflict")]
    IdentityConflict,
    #[error("admission_too_large")]
    AdmissionTooLarge,
}
#[derive(Debug, thiserror::Error)]
pub enum PlanError {
    #[error(transparent)]
    Refused(#[from] PlannerRefusal),
    #[error(transparent)]
    Other(#[from] AppError),
}
impl From<serde_json::Error> for PlanError {
    fn from(error: serde_json::Error) -> Self {
        Self::Other(error.into())
    }
}
type PlanResult<T> = Result<T, PlanError>;

pub const ADAPTER_VERSION: &str = "cloudflare-audit-admission/v1";
#[derive(Debug, Clone)]
pub struct AdmissionRequestFacts {
    pub request_id: String,
    pub request_sha256: String,
}
#[derive(Debug, Clone, Serialize)]
pub struct ArtifactCopy {
    pub member_path: String,
    pub artifact: RawArtifact,
}
#[derive(Debug, Clone, Serialize)]
pub struct AdmissionPlan {
    pub admission: AgentAuditAdmission,
    pub run: ScanRun,
    pub findings: Vec<Finding>,
    pub observations: Vec<FindingObservation>,
    pub artifact_copies: Vec<ArtifactCopy>,
    pub format_requirement: String,
}
impl AdmissionPlan {
    /// Builds the proposed document in memory. The caller owns any later transaction.
    pub fn resulting_case(&self, case: &AssessmentCase) -> PlanResult<AssessmentCase> {
        check_format(case)?;
        check_admission_size(&self.admission)?;
        if case.id != self.run.case_id
            || case.scan_runs.iter().any(|r| r.id == self.run.id)
            || case
                .agent_audit_admissions
                .iter()
                .any(|a| a.identities.session_id == self.admission.identities.session_id)
        {
            return Err(PlannerRefusal::IdentityConflict.into());
        }
        let mut result = case.clone();
        result.scan_runs.push(self.run.clone());
        result.findings.extend(self.findings.clone());
        result
            .finding_observations
            .extend(self.observations.clone());
        result
            .raw_artifacts
            .extend(self.artifact_copies.iter().map(|c| c.artifact.clone()));
        result.agent_audit_admissions.push(self.admission.clone());
        result
            .format_requirements
            .insert(self.format_requirement.clone());
        result.updated_at = self.admission.admitted_at;
        result.status = CaseStatus::NeedsAttention;
        check_write(&result)?;
        bounded_size(&result, MAX_CASE_BYTES, "resulting case exceeds 48 MiB")?;
        Ok(result)
    }
}
fn invalid(message: &str) -> AppError {
    AppError::InvalidRequest(format!("Cloudflare admission: {message}"))
}
fn time(value: &str) -> AppResult<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .map(|t| t.with_timezone(&Utc))
        .map_err(|_| invalid("invalid verified time"))
}

pub fn plan_admission(
    verified: &VerifiedSealedAudit<'_>,
    case: &AssessmentCase,
    request: &AdmissionRequestFacts,
    now: DateTime<Utc>,
    mut id_source: impl FnMut() -> String,
) -> PlanResult<AdmissionPlan> {
    check_format(case)?;
    let b = &verified.identities;
    if case.id != b.case_id
        || !valid_id(&request.request_id)
        || !valid_hash(&request.request_sha256)
        || case
            .scan_runs
            .iter()
            .any(|r| r.id == b.run_id || r.engine_runs.iter().any(|t| t.id == b.task_id))
        || case
            .agent_audit_admissions
            .iter()
            .any(|a| a.identities.session_id == b.session_id || a.request_id == request.request_id)
    {
        return Err(PlannerRefusal::IdentityConflict.into());
    }
    let asset = case
        .assets
        .iter()
        .find(|a| a.id == b.asset_id)
        .ok_or(PlannerRefusal::BindingNotProvable)?;
    let source = case
        .data_sources
        .iter()
        .find(|s| s.id == verified.asset_binding.source_id)
        .ok_or(PlannerRefusal::BindingNotProvable)?;
    let reference: WorkspaceSnapshotReference = serde_json::from_value(
        source
            .metadata
            .get(WORKSPACE_SNAPSHOT_REFERENCE_METADATA_KEY)
            .cloned()
            .ok_or(PlannerRefusal::BindingNotProvable)?,
    )
    .map_err(|_| PlannerRefusal::BindingNotProvable)?;
    if !asset.discovered_from.contains(&source.id)
        || reference.snapshot_id != verified.source.canonical_snapshot_id
        || reference.sha256 != verified.source.canonical_snapshot_sha256
        || asset
            .metadata
            .get("workspace_snapshot_id")
            .and_then(Value::as_str)
            != Some(reference.snapshot_id.as_str())
        || asset
            .metadata
            .get("workspace_snapshot_sha256")
            .and_then(Value::as_str)
            != Some(reference.sha256.as_str())
    {
        return Err(PlannerRefusal::BindingNotProvable.into());
    }
    let mut used = std::collections::BTreeSet::from([b.run_id.clone(), b.task_id.clone()]);
    used.extend(case.findings.iter().map(|f| f.id.clone()));
    used.extend(case.raw_artifacts.iter().map(|a| a.id.clone()));
    used.extend(case.finding_observations.iter().map(|o| o.id.clone()));
    used.extend(
        case.findings
            .iter()
            .flat_map(|f| f.evidence.iter().map(|e| e.id.clone())),
    );
    used.extend(
        case.agent_audit_admissions
            .iter()
            .map(|a| a.admission_id.clone()),
    );
    let mut next_id = || {
        let id = id_source();
        if !valid_id(&id) || !used.insert(id.clone()) {
            return Err(PlanError::Refused(PlannerRefusal::IdentityConflict));
        }
        Ok(id)
    };
    let admission_id = next_id()?;
    let started = time(verified.prepared_at())?;
    let completed = time(verified.sealed_at())?;
    let projection: ProviderReportProjection =
        serde_json::from_value(verified.retained_projection().clone())?;
    let provider = &projection.provider_id;
    let mut copies = Vec::new();
    for member in &verified.package_members {
        if member.path.starts_with("retained/source-view/") {
            continue;
        }
        copies.push(ArtifactCopy {
            member_path: member.path.clone(),
            artifact: RawArtifact {
                id: next_id()?,
                case_id: case.id.clone(),
                run_id: b.run_id.clone(),
                engine_run_id: b.task_id.clone(),
                relative_path: format!("{}/{}/{}/{}", case.id, b.run_id, b.task_id, member.path),
                media_type: match member.path.rsplit('.').next() {
                    Some("json") => "application/json",
                    Some("md") => "text/markdown",
                    Some("txt") => "text/plain",
                    _ => "application/octet-stream",
                }
                .into(),
                sha256: member.sha256.clone(),
                byte_length: member.byte_length,
                created_at: now,
                contains_sensitive_data: true,
            },
        });
    }
    let task = task(
        verified,
        provider,
        &admission_id,
        started,
        completed,
        &copies,
    );
    let run = ScanRun {
        id: b.run_id.clone(),
        case_id: case.id.clone(),
        sequence: case
            .scan_runs
            .iter()
            .map(|r| r.sequence)
            .max()
            .unwrap_or(0)
            .checked_add(1)
            .ok_or_else(|| invalid("run sequence overflow"))?,
        created_at: started,
        completed_at: Some(completed),
        request_outcome: None,
        report_asset_snapshots: vec![ReportAssetSnapshot {
            asset: asset.clone(),
            disposition: ReportAssetDisposition::RequestedForScan,
        }],
        knowledge_cutoff: started,
        ai_system_applicable: false,
        ai_system_applicability: AiSystemApplicabilityAnswer::Unknown,
        ai_generated_artifact: case.ai_generated_artifact,
        verification_baseline_run_id: None,
        scope_grant_ids: vec![],
        scope_grant_snapshots: vec![],
        engine_admission_issues: vec![],
        engine_runs: vec![task],
        campaign_id: None,
    };
    let admission = AgentAuditAdmission {
        admission_id,
        request_id: request.request_id.clone(),
        request_sha256: request.request_sha256.clone(),
        admitted_at: now,
        provider_id: provider.clone(),
        provenance: ProviderProvenance::WorkflowRecorded,
        identities: b.clone(),
        preparation_request_id: verified.preparation_request_id.clone(),
        source_id: source.id.clone(),
        source_view_request_id: verified.source_view_request_id.clone(),
        source: verified.source.clone(),
        digests: verified.digests.clone(),
        method: verified.method.clone(),
        outcome: verified.outcome.clone(),
        verification_scope: verified.verification.scope.into(),
        validators_reexecuted: false,
        counts_by_role: verified.counts_by_role.clone(),
        counts_by_state: verified.counts_by_state.clone(),
        counts: AdmissionCounts {
            confirmed: projection.reported_counts.confirmed,
            needs_validation: projection.reported_counts.needs_validation,
            rejected: projection.reported_counts.rejected,
            unresolved_candidates: projection.unresolved_candidates.len(),
            coverage_by_status: projection.coverage_by_status.clone(),
        },
        artifacts: copies
            .iter()
            .map(|c| ArtifactBinding {
                member_path: c.member_path.clone(),
                artifact_id: c.artifact.id.clone(),
                sha256: c.artifact.sha256.clone(),
                byte_length: c.artifact.byte_length,
            })
            .collect(),
        retained_projection: verified.retained_projection().clone(),
        admission_sha256: String::new(),
    };
    let mut plan = AdmissionPlan {
        admission,
        run,
        findings: vec![],
        observations: vec![],
        artifact_copies: copies,
        format_requirement: FORMAT_REQUIREMENT.into(),
    };
    map_confirmed(&mut plan, case, &projection, &mut next_id)?;
    let mut digest_input = serde_json::to_value(&plan.admission)?;
    digest_input
        .as_object_mut()
        .unwrap()
        .remove("admission_sha256");
    plan.admission.admission_sha256 = domain_digest(FORMAT_REQUIREMENT, &digest_input)?;
    plan.resulting_case(case)?;
    Ok(plan)
}

fn task(
    verified: &VerifiedSealedAudit<'_>,
    provider: &str,
    admission_id: &str,
    started: DateTime<Utc>,
    completed: DateTime<Utc>,
    copies: &[ArtifactCopy],
) -> EngineRun {
    EngineRun {
        id: verified.identities.task_id.clone(),
        scan_run_id: verified.identities.run_id.clone(),
        engine_id: provider.into(),
        task_kind: EngineTaskKind::AgentAudit {
            provider_id: provider.into(),
            admission_id: admission_id.into(),
        },
        localhost_tcp_observation: None,
        asset_ids: vec![verified.identities.asset_id.clone()],
        status: match verified.outcome.state {
            TerminalState::Complete => EngineRunStatus::Completed,
            TerminalState::Incomplete => EngineRunStatus::PartiallyCompleted,
        },
        progress_percent: 100,
        phase: "Source audit sealed".into(),
        started_at: Some(started),
        finished_at: Some(completed),
        resume_token: None,
        last_execution_report_sha256: Some(verified.digests.bundle_sha256.clone()),
        engine_version: Some(verified.method.upstream_commit.clone()),
        reported_version: None,
        image_digest: None,
        rule_version: None,
        adapter_version: ADAPTER_VERSION.into(),
        manifest_schema_version: None,
        source_revision: None,
        repository_url: None,
        distribution_mode: None,
        image_repository: None,
        command_sha256: None,
        execution_timeout_seconds: None,
        knowledge_input: None,
        scope_contract_sha256: None,
        comparison_scope_sha256: None,
        execution_scope_grant_ids: None,
        naabu_work_plan: None,
        naabu_attempt_requests: vec![],
        naabu_attempt_results: vec![],
        mapping_version: None,
        mapping_provenance: None,
        fingerprint_schema_version: Some(ADAPTER_VERSION.into()),
        runtime_provider: None,
        runtime_version: None,
        runtime_security_options: None,
        exit_code: None,
        cleanup_removed: None,
        cleanup_detail: None,
        gateway_refusals: None,
        warnings: vec![],
        unattributed: vec![],
        unevaluated_targets: vec![],
        security_template_executions: vec![],
        manual_review_controls: vec![],
        raw_artifact_ids: copies.iter().map(|c| c.artifact.id.clone()).collect(),
        error_code: matches!(verified.outcome.state, TerminalState::Incomplete)
            .then(|| "source_audit_incomplete".into()),
        error_message: verified.outcome.incomplete_reason.clone(),
    }
}

fn map_confirmed(
    plan: &mut AdmissionPlan,
    case: &AssessmentCase,
    projection: &ProviderReportProjection,
    next_id: &mut impl FnMut() -> PlanResult<String>,
) -> PlanResult<()> {
    use crate::provider_report::ProviderVerdict;
    let admission = &plan.admission;
    let b = &admission.identities;
    let artifact = &plan
        .artifact_copies
        .iter()
        .find(|c| c.member_path == "retained/bundle/findings.json")
        .ok_or_else(|| invalid("verified findings original is missing"))?
        .artifact;
    let observed_at = plan.run.completed_at.unwrap();
    for record in projection
        .records
        .iter()
        .filter(|r| r.verdict == ProviderVerdict::Confirmed)
    {
        let native = &record.native_record;
        let text = |v: &Value| {
            v.as_str()
                .map(str::to_owned)
                .ok_or_else(|| invalid("verified confirmed record has an invalid string"))
        };
        let severity: Severity =
            serde_json::from_value(native["severity"]["overall_severity"].clone())?;
        if severity == Severity::Unknown {
            return Err(invalid("unsupported native severity").into());
        }
        let confidence: Confidence = serde_json::from_value(native["confidence"]["score"].clone())?;
        if !matches!(
            confidence,
            Confidence::Low | Confidence::Medium | Confidence::High
        ) {
            return Err(invalid("unsupported native confidence").into());
        }
        let id = next_id()?;
        let fingerprint = domain_digest(
            ADAPTER_VERSION,
            &serde_json::json!([
                admission.provider_id,
                b.asset_id,
                admission.source.view_id,
                admission.source.view_sha256,
                b.run_id,
                record.fingerprint
            ]),
        )?;
        let mut evidence = Vec::new();
        for (index, item) in native["evidence"]
            .as_array()
            .ok_or_else(|| invalid("missing native evidence"))?
            .iter()
            .enumerate()
        {
            let location = record
                .source_locations
                .iter()
                .find(|l| item["file"] == l.path && item["line"] == l.line)
                .ok_or_else(|| invalid("evidence has no verified source locator"))?;
            let pointer = format!("/{}/evidence/{index}", record.native_record_index);
            evidence.push(Evidence {
                id: next_id()?,
                finding_id: id.clone(),
                run_id: b.run_id.clone(),
                engine_run_id: Some(b.task_id.clone()),
                kind: EvidenceKind::SourceCode,
                engine_id: admission.provider_id.clone(),
                provider_record: Some(ProviderRecordRef {
                    admission_id: admission.admission_id.clone(),
                    native_record_index: record.native_record_index,
                    native_record_sha256: record.native_record_sha256.clone(),
                    native_fingerprint: record.fingerprint.clone(),
                    source_locators: vec![location.clone()],
                }),
                scanner_details: Some(ScannerFindingDetails {
                    description: Some(text(&native["description"])?),
                    remediation: Some(text(&native["remediation"]["strategy"])?),
                    remediation_code_changes: native["remediation"].get("code_changes").cloned(),
                    ..Default::default()
                }),
                source_rule: None,
                result_pointer_sha256: Some(hex::encode(sha2::Sha256::digest(pointer.as_bytes()))),
                observed_at,
                summary: text(&item["description"])?,
                location: Some(format!("{}:{}", location.path, location.line)),
                artifact_id: artifact.id.clone(),
                artifact_sha256: artifact.sha256.clone(),
                pointer: Some(pointer),
                redacted: false,
            });
        }
        let mut finding = Finding {
            id,
            case_id: case.id.clone(),
            first_seen_run_id: b.run_id.clone(),
            last_seen_run_id: b.run_id.clone(),
            fingerprint,
            title: text(&native["title"])?,
            plain_language_summary: text(&native["description"])?,
            possible_impact: text(&native["severity"]["impact"]["reason"])?,
            priority: crate::adapters::priority_for(&severity),
            severity,
            confidence,
            priority_reasons: vec![],
            asset_ids: vec![b.asset_id.clone()],
            evidence,
            control_references: vec![],
            recommendation: text(&native["remediation"]["strategy"])?,
            verification_guidance: String::new(),
            rollback_considerations: None,
            official_references: vec![],
            recommended_expert_type: String::new(),
            status: FindingStatus::Unreviewed,
            tags: vec![],
            family: Some(FindingFamily::SourceCode),
            severity_basis_code: None,
            confidence_basis_code: None,
            context_factors: vec![],
        };
        crate::prioritization::apply_case_context(case, &mut finding);
        plan.observations.push(FindingObservation {
            id: next_id()?,
            run_id: b.run_id.clone(),
            finding_id: finding.id.clone(),
            fingerprint: finding.fingerprint.clone(),
            asset_ids: finding.asset_ids.clone(),
            engine_ids: vec![admission.provider_id.clone()],
            severity: finding.severity.clone(),
            confidence: finding.confidence.clone(),
            evidence_hashes: vec![artifact.sha256.clone()],
            observed_at,
            finding_snapshot: Some(finding.clone()),
        });
        plan.findings.push(finding);
    }
    Ok(())
}

// Retention accepts at most 64 MiB of serialized projection and an 8 MiB inventory.
// Admission's copied history fields fit within twice (4 MiB record + 1 MiB receipt).
// At most 4097 bundle members + 2 documents + retention + 2 workflow files = 4102
// bindings add <=256 bytes each (128-byte IDs plus keys). Allow another 1 MiB for
// fixed metadata: 64 + 8 + 2*(4+1) + ceil(4102*256/2^20) + 1 = 85 MiB.
// Round up to 96 MiB so every accepted retained projection fits this local cap.
// The separate 48 MiB whole-case limit reserves 16 MiB below archive's 64 MiB cap;
// a valid large audit can therefore fail the whole-case check, never be truncated.
pub const MAX_ADMISSION_BYTES: usize = 96 * 1024 * 1024;
pub const MAX_CASE_BYTES: usize = 48 * 1024 * 1024;
fn bounded_size(value: &impl Serialize, limit: usize, _message: &str) -> PlanResult<()> {
    struct Counter {
        bytes: usize,
        limit: usize,
    }
    impl std::io::Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.bytes = self.bytes.saturating_add(bytes.len());
            if self.bytes > self.limit {
                return Err(std::io::Error::other("size limit exceeded"));
            }
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut counter = Counter { bytes: 0, limit };
    serde_json::to_writer(&mut counter, value).map_err(|_| PlannerRefusal::AdmissionTooLarge.into())
}
fn check_admission_size(admission: &AgentAuditAdmission) -> PlanResult<()> {
    bounded_size(
        admission,
        MAX_ADMISSION_BYTES,
        "serialized admission exceeds 96 MiB",
    )
}
