//! Offline custody verification. No authority checks, staging, or validator execution.
use super::{record::Role, *};
use crate::cloudflare_provider::{
    bundle::{AuditBinding, BundleFile, verified_read},
    bundle_io::BundleRoot,
    retained::{self, Loaded},
    source_view::{self, SourceViewPreparationReceipt},
    strict_json,
};
use crate::storage::Storage;
use serde_json::{Value, json};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, Serialize)]
pub struct VerificationError {
    pub error_code: &'static str,
    pub failed_check: &'static str,
}
impl VerificationError {
    fn mismatch(check: &'static str) -> Self {
        Self {
            error_code: "sealed_package_mismatch",
            failed_check: check,
        }
    }
    /// A concurrent case change is retryable contention, never package corruption.
    fn case_changed(check: &'static str) -> Self {
        Self {
            error_code: "case_changed",
            failed_check: check,
        }
    }
    fn at(check: &'static str, error: AppError) -> Self {
        if matches!(error, AppError::UnsafeFilesystemEntry) {
            Self {
                error_code: "unsafe_filesystem_entry",
                failed_check: check,
            }
        } else {
            Self::mismatch(check)
        }
    }
}
type Result<T> = std::result::Result<T, VerificationError>;
fn require(pass: bool, check: &'static str) -> Result<()> {
    if pass {
        Ok(())
    } else {
        Err(VerificationError::mismatch(check))
    }
}
fn equal(actual: &Value, expected: &impl Serialize, check: &'static str) -> Result<()> {
    require(
        *actual
            == serde_json::to_value(expected)
                .map_err(|e| VerificationError::at(check, e.into()))?,
        check,
    )
}
#[derive(Serialize)]
pub struct VerificationScope {
    pub state: &'static str,
    pub scope: &'static str,
    pub committed_files_verified: bool,
    pub full_payload_verified: bool,
    pub workflow_history_verified: bool,
    pub view_lineage_verified: bool,
    pub validators_reexecuted: bool,
}
#[derive(Serialize)]
pub struct AssetBinding {
    pub asset_id: String,
    pub source_id: String,
    pub asset_present: bool,
    pub source_present: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Digests {
    pub preparation_receipt_sha256: String,
    pub source_view_receipt_sha256: String,
    pub view_manifest_sha256: String,
    pub view_sha256: String,
    pub canonical_manifest_sha256: String,
    pub sealed_entry_sha256: String,
    pub bundle_sha256: String,
    pub manifest_sha256: String,
    pub retention_sha256: String,
    pub workflow_sha256: String,
    pub projection_sha256: String,
    pub retained_projection_sha256: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Method {
    pub upstream_commit: String,
    pub validator_resources_sha256: String,
    pub profile: Profile,
    pub budget: record::Budget,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TerminalState {
    Complete,
    Incomplete,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Outcome {
    pub state: TerminalState,
    pub incomplete_reason: Option<String>,
    pub audit_performed: bool,
}
/// Serialization is bounded by the existing record and retained inventory limits.
/// Held roots anchor every indexed read until the caller's final recheck/commit.
#[derive(Serialize)]
pub struct VerifiedSealedAudit<'a> {
    pub verification: VerificationScope,
    pub identities: AuditBinding,
    pub preparation_request_id: String,
    pub source_view_request_id: String,
    pub source: SourceBinding,
    pub sealed_entry_sequence: u64,
    pub digests: Digests,
    pub asset_binding: AssetBinding,
    pub method: Method,
    pub outcome: Outcome,
    pub counts_by_role: BTreeMap<String, usize>,
    pub counts_by_state: BTreeMap<String, usize>,
    pub package_members: Vec<BundleFile>,
    pub package_member_count: usize,
    pub package_bytes: u64,
    pub provenance: &'static str,
    #[serde(skip)]
    root: BundleRoot,
    #[serde(skip)]
    prepared_at: String,
    #[serde(skip)]
    sealed_at: String,
    #[serde(skip)]
    retained: Loaded,
    #[serde(skip)]
    storage: Option<&'a Storage>,
    #[serde(skip)]
    case_revision: i64,
}
impl VerifiedSealedAudit<'_> {
    pub fn retained_projection(&self) -> &Value {
        &self.retained.projection
    }
    pub fn prepared_at(&self) -> &str {
        &self.prepared_at
    }
    pub fn sealed_at(&self) -> &str {
        &self.sealed_at
    }
    /// Reads only a member authenticated by this verifier, with a fresh hash/length check.
    pub fn read_member(&mut self, path: &str) -> crate::error::AppResult<Vec<u8>> {
        let member = self
            .package_members
            .iter()
            .find(|m| m.path == path)
            .ok_or_else(|| AppError::InvalidRequest("unknown verified package member".into()))?;
        verified_read(&mut self.root, member)
    }

    pub fn recheck_unchanged(&self) -> Result<()> {
        let check = "unchanged";
        self.root
            .verify_unchanged()
            .map_err(|e| VerificationError::at(check, e))?;
        self.retained
            .root
            .verify_unchanged()
            .map_err(|e| VerificationError::at(check, e))?;
        let Some(storage) = self.storage else {
            return Ok(());
        };
        let receipt = storage
            .cloudflare_audit_receipt(&self.identities.case_id, &self.identities.session_id, true)
            .map_err(|e| VerificationError::at(check, e))?
            .ok_or_else(|| VerificationError::mismatch(check))?;
        let record = storage
            .cloudflare_audit_record(&receipt)
            .map_err(|e| VerificationError::at(check, e))?;
        let view = storage
            .source_view_receipt(&self.identities.case_id, &self.source_view_request_id)
            .map_err(|e| VerificationError::at(check, e))?
            .ok_or_else(|| VerificationError::mismatch(check))?;
        let case = storage
            .get_case(&self.identities.case_id)
            .map_err(|e| VerificationError::at(check, e))?;
        require(
            receipt.receipt_sha256 == self.digests.preparation_receipt_sha256
                && record.head(&receipt).1 == self.digests.sealed_entry_sha256
                && view.digest == self.digests.source_view_receipt_sha256,
            check,
        )?;
        if case.storage_revision != self.case_revision {
            return Err(VerificationError::case_changed(check));
        }
        Ok(())
    }
}

pub fn verify<'a>(
    data: &Path,
    storage: &'a Storage,
    case_id: &str,
    session_id: &str,
) -> Result<VerifiedSealedAudit<'a>> {
    require(valid_id(case_id) && valid_id(session_id), "identifiers")?;
    let receipt = storage
        .cloudflare_audit_receipt(case_id, session_id, true)
        .map_err(|e| VerificationError::at("record_chain", e))?
        .ok_or(VerificationError {
            error_code: "unknown_preparation",
            failed_check: "preparation",
        })?;
    let record = storage
        .cloudflare_audit_record(&receipt)
        .map_err(|e| VerificationError::at("record_chain", e))?;
    let PreparationResult::Prepared { facts, .. } = &receipt.result else {
        return Err(VerificationError::mismatch("preparation"));
    };
    let view = storage
        .source_view_receipt(case_id, &facts.source.source_view_request_id)
        .map_err(|e| VerificationError::at("view_lineage", e))?
        .ok_or_else(|| VerificationError::mismatch("view_lineage"))?;
    let case = storage
        .get_case(case_id)
        .map_err(|e| VerificationError::at("case_binding", e))?;
    let restored = crate::cloudflare_provider::restored::Context::load(storage, &receipt)
        .map_err(|e| VerificationError::at("restore_history", e))?;
    let mut result = verify_snapshot(
        data,
        &receipt,
        &record,
        &view,
        &case,
        restored.sources_omitted,
    )?;
    result.storage = Some(storage);
    result.recheck_unchanged()?;
    Ok(result)
}

/// Offline verification from immutable snapshot inputs. No database, authority,
/// provider, model or validator is consulted; only recorded members are read.
pub(crate) fn verify_snapshot<'a>(
    data: &Path,
    receipt: &PreparationReceipt,
    record: &record::Record,
    view: &SourceViewPreparationReceipt,
    case: &crate::domain::AssessmentCase,
    omit_source_bodies: bool,
) -> Result<VerifiedSealedAudit<'a>> {
    let (entry, seal) = record.sealed().ok_or(VerificationError {
        error_code: "run_not_sealed",
        failed_check: "terminal_seal",
    })?;
    let PreparationResult::Prepared { facts, .. } = &receipt.result else {
        return Err(VerificationError::mismatch("preparation"));
    };
    seal.verify()
        .map_err(|e| VerificationError::at("seal", e))?;
    let path = seal.path(data, receipt);
    // Only absence of the package directory is absence; absent members are corruption.
    let mut root = BundleRoot::open(&path).map_err(|e| {
        if matches!(e, AppError::UnsafeFilesystemEntry) {
            return VerificationError::at("package_root", e);
        }
        if std::fs::symlink_metadata(&path).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound)
        {
            VerificationError {
                error_code: "sealed_package_missing",
                failed_check: "package_root",
            }
        } else {
            VerificationError::at("package_root", e)
        }
    })?;
    let mut committed = Vec::new();
    for file in &seal.files {
        committed.push(
            verified_read(&mut root, file)
                .map_err(|e| VerificationError::at("committed_files", e))?,
        );
    }
    let mut retained = retained::load_archive_payload(
        &path.join("retained"),
        Some(&seal.files[0].sha256),
        omit_source_bodies,
    )
    .map_err(|e| VerificationError::at("retained_payload", e))?;
    let workflow = strict_json::parse(&committed[1])
        .map_err(|e| VerificationError::at("workflow_history", e))?;
    let expected = json!({"schema_version":"ai-security-scanner.cloudflare-workflow-record/v1",
        "preparation_receipt":receipt, "entries":record.entries[..record.entries.len()-1],
        "record_head":{"sequence":entry.sequence-1,"entry_sha256":entry.predecessor_sha256}});
    require(workflow == expected, "workflow_history")?;
    let projection = strict_json::parse(&committed[2])
        .map_err(|e| VerificationError::at("workflow_projection", e))?;
    require(projection == seal.projection, "workflow_projection")?;
    check_projection(&projection, &retained, receipt, facts, record)?;
    check_captured(&projection, &mut retained, record)?;
    let (manifest_sha256, source_id) = check_lineage(view, receipt, facts, &retained)?;
    let mut members = seal.files.to_vec();
    members.extend(
        retained
            .members
            .iter()
            .filter(|f| f.path != "retention.json")
            .map(|f| BundleFile {
                path: format!("retained/{}", f.path),
                ..f.clone()
            }),
    );
    members.sort_by(|a, b| a.path.cmp(&b.path));
    root.check_inventory(
        &members
            .iter()
            .filter(|f| !omit_source_bodies || !f.path.starts_with("retained/source-view/"))
            .map(|f| f.path.clone())
            .collect(),
    )
    .map_err(|e| VerificationError::at("package_inventory", e))?;
    let reason = projection["incomplete_reason"].as_str().map(String::from);
    let state = serde_json::from_value(projection["run_status"].clone())
        .map_err(|_| VerificationError::mismatch("terminal_outcome"))?;
    require(
        match state {
            // Earlier seals permit a historical reason on complete metadata.
            TerminalState::Complete => true,
            TerminalState::Incomplete => reason.as_ref().is_some_and(|s| !s.trim().is_empty()),
        },
        "terminal_outcome",
    )?;
    let result = VerifiedSealedAudit {
        verification: VerificationScope {
            state: "verified",
            scope: if omit_source_bodies {
                "included_payload"
            } else {
                "full_payload"
            },
            committed_files_verified: true,
            full_payload_verified: !omit_source_bodies,
            workflow_history_verified: true,
            view_lineage_verified: true,
            validators_reexecuted: false,
        },
        identities: retained.manifest.binding.clone(),
        preparation_request_id: receipt.request_id.clone(),
        source_view_request_id: view.request_id.clone(),
        source: facts.source.clone(),
        sealed_entry_sequence: entry.sequence,
        digests: Digests {
            preparation_receipt_sha256: receipt.receipt_sha256.clone(),
            source_view_receipt_sha256: view.digest.clone(),
            view_manifest_sha256: manifest_sha256,
            view_sha256: facts.source.view_sha256.clone(),
            canonical_manifest_sha256: facts.source.canonical_snapshot_sha256.clone(),
            sealed_entry_sha256: entry.entry_sha256.clone(),
            bundle_sha256: seal.bundle_sha256.clone(),
            manifest_sha256: seal.manifest_sha256.clone(),
            retention_sha256: seal.files[0].sha256.clone(),
            workflow_sha256: seal.files[1].sha256.clone(),
            projection_sha256: seal.files[2].sha256.clone(),
            retained_projection_sha256: projection["retained_projection_sha256"]
                .as_str()
                .unwrap()
                .into(),
        },
        asset_binding: AssetBinding {
            asset_id: receipt.asset_id.clone(),
            asset_present: case.assets.iter().any(|a| a.id == receipt.asset_id),
            source_present: case.data_sources.iter().any(|s| s.id == source_id),
            source_id,
        },
        method: Method {
            upstream_commit: facts.upstream_commit.clone(),
            validator_resources_sha256: facts.validator_resources_sha256.clone(),
            profile: facts.profile,
            budget: record.budget(facts.invocation_budget),
        },
        outcome: Outcome {
            state,
            incomplete_reason: reason,
            audit_performed: projection["audit_performed"] == true,
        },
        counts_by_role: record.counts(),
        counts_by_state: record
            .counts_by_state()
            .into_iter()
            .map(|(k, v)| (k.into(), v))
            .collect(),
        package_member_count: members.len(),
        package_bytes: members.iter().map(|f| f.byte_length).sum(),
        package_members: members,
        provenance: "workflow_recorded",
        prepared_at: facts.prepared_at.clone(),
        sealed_at: entry.occurred_at.clone(),
        root,
        retained,
        storage: None,
        case_revision: case.storage_revision,
    };
    result.recheck_unchanged()?;
    Ok(result)
}

fn check_projection(
    p: &Value,
    retained: &Loaded,
    receipt: &PreparationReceipt,
    facts: &Prepared,
    record: &record::Record,
) -> Result<()> {
    let check = "workflow_projection";
    let expected_binding = AuditBinding {
        case_id: receipt.case_id.clone(),
        asset_id: receipt.asset_id.clone(),
        run_id: facts.provider_run_id.clone(),
        task_id: facts.provider_task_id.clone(),
        session_id: facts.session_id.clone(),
        attempt_id: facts.attempt_id.clone(),
    };
    require(retained.manifest.binding == expected_binding, check)?;
    equal(&p["binding"], &expected_binding, check)?;
    equal(&p["source"], &facts.source, check)?;
    equal(&p["profile"], &facts.profile, check)?;
    equal(&p["budget"], &record.budget(facts.invocation_budget), check)?;
    equal(&p["counts_by_role"], &record.counts(), check)?;
    equal(&p["counts_by_state"], &record.counts_by_state(), check)?;
    equal(&p["issued_total"], &record.assignments.len(), check)?;
    let (_, seal) = record.sealed().unwrap();
    let member = |name| retained.members.iter().find(|f| f.path == name).unwrap();
    require(
        p["upstream_commit"] == facts.upstream_commit
            && retained.manifest.upstream_commit == facts.upstream_commit
            && p["validator_resources_sha256"] == facts.validator_resources_sha256
            && p["retained_projection_sha256"] == member("projection.json").sha256
            && seal.manifest_sha256 == member("bundle/provider-manifest.json").sha256
            && seal.bundle_sha256 == retained.inspection.bundle_sha256
            && p["run_status"] == retained.projection["reported_run_status"]
            && p["audit_performed"]
                == record
                    .assignments
                    .iter()
                    .any(|a| a.assignment.spec.role == Role::Hunter && a.state == "closed"),
        check,
    )?;
    for field in [
        "reported_counts",
        "coverage_by_status",
        "unresolved_candidates",
    ] {
        require(p[field] == retained.projection[field], check)?;
    }
    Ok(())
}

fn check_lineage(
    view: &SourceViewPreparationReceipt,
    receipt: &PreparationReceipt,
    facts: &Prepared,
    retained: &Loaded,
) -> Result<(String, String)> {
    let check = "view_lineage";
    let source = &retained.manifest.source;
    let bound = &facts.source;
    let source_view::PreparationResult::Ready {
        view_id,
        manifest_sha256,
        view_sha256,
        ..
    } = &view.result
    else {
        return Err(VerificationError::mismatch(check));
    };
    require(
        view.case_id == receipt.case_id
            && view.asset_id == receipt.asset_id
            && view.request_id == bound.source_view_request_id
            && view.digest == bound.source_view_receipt_sha256
            && view.acknowledgement_sha256 == bound.acknowledgement_sha256
            && view.grant_sha256.as_ref() == Some(&bound.grant_sha256)
            && valid_hash(manifest_sha256)
            && *view_id == bound.view_id
            && source.view_id == *view_id
            && *view_sha256 == bound.view_sha256
            && source.view_sha256 == *view_sha256
            && source.canonical_snapshot_id.as_ref() == Some(&bound.canonical_snapshot_id)
            && source.canonical_snapshot_sha256.as_ref() == Some(&bound.canonical_snapshot_sha256)
            && view.acknowledgement.canonical_snapshot_sha256 == bound.canonical_snapshot_sha256
            && source.policy_id == bound.policy_id
            && view.acknowledgement.policy_id == bound.policy_id
            && view.acknowledgement.scope == bound.scope
            && source.source_ref == bound.source_ref,
        check,
    )?;
    // The receipt's manifest identity is bound transitively by its digest in preparation.
    // Its file-index digest authenticates the exact retained file set; no original view is read.
    let source_id = view
        .source_id
        .as_ref()
        .filter(|s| valid_id(s))
        .ok_or_else(|| VerificationError::mismatch(check))?;
    Ok((manifest_sha256.clone(), source_id.clone()))
}

// Verify captured relationships without rebuilding a projection using today's rules.
fn check_captured(p: &Value, retained: &mut Loaded, record: &record::Record) -> Result<()> {
    let check = "captured_record";
    for file in &retained.manifest.files {
        let expected = record
            .documents
            .get(&file.path)
            .map(|d| (&d.current.sha256, d.current.byte_length))
            .or_else(|| {
                record
                    .assignments
                    .iter()
                    .filter_map(|a| a.output.as_ref())
                    .find(|o| o.path == file.path)
                    .map(|o| (&o.sha256, o.byte_length))
            });
        require(expected == Some((&file.sha256, file.byte_length)), check)?;
    }
    require(
        record.documents.values().all(|d| {
            retained
                .manifest
                .files
                .iter()
                .any(|f| f.path == d.current.name)
        }),
        check,
    )?;
    let file = retained
        .members
        .iter()
        .find(|f| f.path == "bundle/run-metadata.json")
        .ok_or_else(|| VerificationError::mismatch(check))?;
    let bytes =
        verified_read(&mut retained.root, file).map_err(|e| VerificationError::at(check, e))?;
    let metadata = strict_json::parse(&bytes).map_err(|e| VerificationError::at(check, e))?;
    require(
        p["run_status"] == metadata["run_status"]
            && p["incomplete_reason"] == metadata["incomplete_reason"],
        check,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn record_selection_precedes_package_access() {
        let temp = crate::test_temp::tempdir().unwrap();
        let storage = Storage::open(temp.path().join("casework.db")).unwrap();
        // A nonexistent data root cannot mask the missing preparation or bad identifiers.
        let data = temp.path().join("absent");
        let error = verify(&data, &storage, "case", "unknown").err().unwrap();
        assert_eq!(error.error_code, "unknown_preparation");
        let error = verify(&data, &storage, "../case", "unknown").err().unwrap();
        assert_eq!(error.failed_check, "identifiers");
        assert!(!data.exists());
    }
    #[test]
    fn diagnostics_are_bounded_and_do_not_include_input() {
        let error = VerificationError::at(
            "workflow_history",
            AppError::Storage("untrusted document content".into()),
        );
        assert_eq!(
            serde_json::to_value(error).unwrap(),
            json!({"error_code":"sealed_package_mismatch", "failed_check":"workflow_history"})
        );
        assert_eq!(
            VerificationError::at("package_root", AppError::UnsafeFilesystemEntry).error_code,
            "unsafe_filesystem_entry"
        );
    }
}
