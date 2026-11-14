//! Sealing binds product custody to an immutable package; the entry is the commit.
use super::{record::*, validation::*, *};
use crate::case_archive_io::{
    guard_archive_parent, private_tempdir_in, publish_directory_no_replace,
};
use crate::cloudflare_provider::{
    bundle::{BundleFile, verified_read},
    bundle_io::BundleRoot,
    retained,
    source_view::{self, OwnedContext},
};
use crate::provider_report::ProviderProvenance;
use serde_json::{Value, json};
use std::fs;
pub const FINALIZE_SCHEMA: &str = "ai-security-scanner.cloudflare-audit-finalize-request/v1";
const PROJECTION_SCHEMA: &str = "ai-security-scanner.cloudflare-workflow-projection/v1";
const FILES: [&str; 3] = [
    "retained/retention.json",
    "workflow.json",
    "workflow-projection.json",
];
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinalizeRequest {
    pub schema_version: String,
    pub request_id: String,
    pub case_id: String,
    pub session_id: String,
    pub expected_head_sha256: String,
    pub expected_bundle_sha256: String,
}
impl FinalizeRequest {
    pub fn read(path: &Path) -> Result<Self, Refusal> {
        let value = read_request(path).map_err(|e| match e {
            RequestReadError::File => Refusal::RequestFileLimit,
            RequestReadError::Json => Refusal::InvalidRequest,
        })?;
        let request: Self = serde_json::from_value(value).map_err(|_| Refusal::InvalidRequest)?;
        request.check()?;
        Ok(request)
    }
    fn check(&self) -> Result<(), Refusal> {
        if self.schema_version != FINALIZE_SCHEMA
            || [&self.request_id, &self.case_id, &self.session_id]
                .iter()
                .any(|s| !valid_id(s))
            || !valid_hash(&self.expected_head_sha256)
            || !valid_hash(&self.expected_bundle_sha256)
        {
            return Err(Refusal::InvalidRequest);
        }
        Ok(())
    }
    pub(crate) fn content_digest(&self) -> AppResult<String> {
        domain_digest(FINALIZE_SCHEMA, self)
    }
    fn record_request(&self) -> AppResult<RecordRequest<'_>> {
        Ok(RecordRequest {
            request_id: &self.request_id,
            case_id: &self.case_id,
            session_id: &self.session_id,
            expected_head_sha256: &self.expected_head_sha256,
            digest: self.content_digest()?,
            sealing: true,
            terminating: false,
        })
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Seal {
    pub bundle_sha256: String,
    pub manifest_sha256: String,
    pub files: [BundleFile; 3],
    pub projection: Value,
}
impl Seal {
    pub(super) fn verify(&self) -> AppResult<()> {
        let projection = canonical_bytes(&self.projection)?;
        if !valid_hash(&self.bundle_sha256)
            || !valid_hash(&self.manifest_sha256)
            || self.files.iter().zip(FILES).any(|(f, name)| {
                f.path != name
                    || !valid_hash(&f.sha256)
                    || f.byte_length > crate::cloudflare_provider::MAX_SEALED_FILE_BYTES
            })
            || digest(&projection) != self.files[2].sha256
            || projection.len() as u64 != self.files[2].byte_length
            || self.projection["retention_sha256"] != self.files[0].sha256
            || self.projection["workflow_sha256"] != self.files[1].sha256
            || self.projection["schema_version"] != PROJECTION_SCHEMA
            || self.projection["provenance"] != "workflow_recorded"
            || self.projection["canonical_snapshot_binding_verified"] != true
            || self.projection["source_authorization_verified"] != true
            || !self.projection["audit_performed"].is_boolean()
            || self.projection["admission_ready"] != false
            || self.projection["target_execution_allowed"] != false
        {
            return Err(AppError::Storage("invalid sealed record".into()));
        }
        Ok(())
    }
    pub fn path(&self, data: &Path, receipt: &PreparationReceipt) -> PathBuf {
        io::directory(data, receipt)
            .unwrap()
            .join("sealed")
            .join(&self.bundle_sha256)
    }
    /// Only the three committed files are read; this is not full payload inspection.
    pub fn state(&self, data: &Path, receipt: &PreparationReceipt) -> DescriptorState {
        let path = self.path(data, receipt);
        let check = || -> AppResult<()> {
            self.verify()?;
            let mut root = BundleRoot::open(&path)?;
            for file in &self.files {
                verified_read(&mut root, file)?;
            }
            root.verify_unchanged()
        };
        if check().is_ok() {
            return DescriptorState::Verified;
        }
        // Unsafe links (including dangling ones) must not be described as absence.
        for file in &self.files {
            let member = path.join(&file.path);
            for ancestor in member.ancestors() {
                match fs::symlink_metadata(ancestor) {
                    Ok(m) => {
                        if m.file_type().is_symlink() || (ancestor != member && !m.is_dir()) {
                            return DescriptorState::Mismatch;
                        }
                        #[cfg(windows)]
                        {
                            use std::os::windows::fs::MetadataExt;
                            if m.file_attributes() & 0x400 != 0 {
                                return DescriptorState::Mismatch;
                            }
                        }
                    }
                    Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                        return DescriptorState::Mismatch;
                    }
                    _ => {}
                }
            }
        }
        if self
            .files
            .iter()
            .any(|f| fs::symlink_metadata(path.join(&f.path)).is_err())
        {
            DescriptorState::Missing
        } else {
            DescriptorState::Mismatch
        }
    }
}
pub enum FinalizeOutcome {
    Record(CheckpointOutcome),
    Validation(ValidationOutcome),
    NotSealable(Box<Value>),
}
fn refused(code: Refusal) -> FinalizeOutcome {
    FinalizeOutcome::Record(CheckpointOutcome::refused(code))
}

pub fn finalize(
    context: &OwnedContext<'_>,
    request: &FinalizeRequest,
) -> AppResult<FinalizeOutcome> {
    crate::cloudflare_provider::restored::guard(
        context.storage,
        &request.case_id,
        super::RECEIPT_EVENT,
        &request.session_id,
        true,
    )?;
    if let Err(code) = request.check() {
        return Ok(refused(code));
    }
    let loaded =
        context
            .storage
            .cloudflare_audit_receipt(&request.case_id, &request.session_id, true);
    let receipt = match loaded {
        Ok(Some(r)) => r,
        Ok(None) => return Ok(refused(Refusal::UnknownPreparation)),
        Err(AppError::InvalidCloudflareRecord(_)) => return Ok(refused(Refusal::RecordInvalid)),
        Err(error) => return Err(error),
    };
    let record = match context.storage.cloudflare_audit_record(&receipt) {
        Ok(record) => record,
        Err(AppError::InvalidCloudflareRecord(_)) => return Ok(refused(Refusal::RecordInvalid)),
        Err(error) => return Err(error),
    };
    record.ensure_active()?;
    let identity = request.record_request()?;
    // Idempotency precedes authority: replay hands out no new authority or bytes.
    if record.sealed().is_some() {
        let outcome = record.precheck(&receipt, &identity, || Ok(None))?.unwrap();
        if matches!(outcome, CheckpointOutcome::Saved { .. })
            && record.sealed().unwrap().1.state(context.data_dir, &receipt)
                != DescriptorState::Verified
        {
            return Err(AppError::Storage(
                "sealed package missing or mismatched; existing bytes preserved".into(),
            ));
        }
        return Ok(FinalizeOutcome::Record(outcome));
    }
    if record
        .entries
        .iter()
        .any(|e| e.request_id == request.request_id)
    {
        return Ok(refused(Refusal::RequestConflict));
    }
    let staged = match assemble(
        context,
        &ValidateRequest {
            schema_version: VALIDATE_SCHEMA.into(),
            case_id: request.case_id.clone(),
            session_id: request.session_id.clone(),
            expected_head_sha256: Some(request.expected_head_sha256.clone()),
        },
    )? {
        Ok(s) => s,
        Err(outcome) => return Ok(FinalizeOutcome::Validation(outcome)),
    };
    if staged.result["bundle_sha256"] != request.expected_bundle_sha256 {
        return Ok(refused(Refusal::BundleMismatch));
    }
    if let Some(code) = seal_headroom(&staged)? {
        return Ok(refused(code));
    }
    if staged.result["sealable"] != true {
        return Ok(FinalizeOutcome::NotSealable(Box::new(staged.result)));
    }
    let seal = package(context, &staged)?;
    let PreparationResult::Prepared { facts, .. } = &staged.receipt.result else {
        unreachable!()
    };
    let case = context.storage.get_case(&request.case_id)?;
    let outcome = context.storage.append_cloudflare_record(
        &identity,
        staged.revision,
        context.cancelled,
        || {
            checkpoint::current_authority(
                &case,
                &staged.receipt,
                facts,
                &staged.view,
                &chrono::Utc::now,
            )
        },
        |_| {
            Ok(Content::Sealed {
                seal: Box::new(seal),
            })
        },
        || chrono::Utc::now().to_rfc3339(),
    )?;
    Ok(FinalizeOutcome::Record(outcome))
}

fn file(path: &str, bytes: &[u8]) -> BundleFile {
    BundleFile {
        path: path.into(),
        sha256: digest(bytes),
        byte_length: bytes.len() as u64,
    }
}

fn workflow_projection(staged: &Staged, reported: &Value, hashes: &[String; 3]) -> Value {
    let PreparationResult::Prepared { facts, .. } = &staged.receipt.result else {
        unreachable!()
    };
    json!({"schema_version":PROJECTION_SCHEMA,
        "binding":staged.result["bundle_receipt"]["binding"],"source":facts.source,
        "upstream_commit":facts.upstream_commit,"validator_resources_sha256":facts.validator_resources_sha256,
        "profile":facts.profile,"budget":staged.record.budget(facts.invocation_budget),
        "provenance":ProviderProvenance::WorkflowRecorded,"canonical_snapshot_binding_verified":true,
        "source_authorization_verified":true,"audit_performed":staged.record.assignments.iter().any(|a| a.assignment.spec.role == Role::Hunter && a.state == "closed"),
        "admission_ready":false,"target_execution_allowed":false,
        "run_status":reported["reported_run_status"],"incomplete_reason":staged.result["incomplete_reason"],
        "reported_counts":reported["reported_counts"],"coverage_by_status":reported["coverage_by_status"],
        "unresolved_candidates":reported["unresolved_candidates"],
        "counts_by_role":staged.record.counts(),"counts_by_state":staged.record.counts_by_state(),
        "issued_total":staged.record.assignments.len(),
        "retention_sha256":hashes[0],"retained_projection_sha256":hashes[1],
        "workflow_sha256":hashes[2],"record_head_sha256":staged.result["record_head"]["entry_sha256"]})
}

/// Bound the eventual entry before a package exists, including the full reported projection.
pub(super) fn seal_headroom(staged: &Staged) -> AppResult<Option<Refusal>> {
    if let Err(code) = record_limits(staged.record.entries.len(), 0, staged.record.bytes, false) {
        return Ok(Some(code));
    }
    let reported = &staged.result["bundle_receipt"]["projection"];
    if reported.is_null() {
        return Ok(None);
    }
    let hash = "0".repeat(64);
    let projection = workflow_projection(
        staged,
        reported,
        &[hash.clone(), hash.clone(), hash.clone()],
    );
    let seal = Seal {
        bundle_sha256: hash.clone(),
        manifest_sha256: hash.clone(),
        files: FILES.map(|path| BundleFile {
            path: path.into(),
            sha256: hash.clone(),
            byte_length: u64::MAX,
        }),
        projection,
    };
    // Validation does not receive a finalize request. Use the maximum request ID,
    // numeric widths and timestamp precision so every accepted request fits.
    let entry = Entry {
        schema_version: ENTRY_SCHEMA.into(),
        case_id: staged.receipt.case_id.clone(),
        session_id: staged.receipt.session_id().unwrap().into(),
        request_id: "a".repeat(128),
        request_sha256: hash.clone(),
        case_revision: i64::MAX,
        sequence: u64::MAX,
        predecessor_sha256: hash.clone(),
        occurred_at: "9999-12-31T23:59:59.999999999+00:00".into(),
        content: Content::Sealed {
            seal: Box::new(seal),
        },
        entry_sha256: hash,
    };
    Ok(record_limits(
        staged.record.entries.len(),
        canonical_bytes(&entry)?.len(),
        staged.record.bytes,
        false,
    )
    .err())
}
fn package(context: &OwnedContext<'_>, staged: &Staged) -> AppResult<Seal> {
    let receipt = &staged.receipt;
    let directory = io::directory(context.data_dir, receipt)
        .unwrap()
        .join("sealed");
    io::ensure_directory(&directory)?;
    let _guard = guard_archive_parent(&directory)?;
    let temporary = private_tempdir_in(&directory, ".seal-")?;
    // The wrapper restores permissions on every error, including partial freezing.
    let stage = PackageStage(temporary);
    let source_view::PreparationResult::Ready { relative_path, .. } = &staged.view.result else {
        unreachable!()
    };
    let tree = context
        .data_dir
        .join("artifacts")
        .join(relative_path)
        .join("tree");
    let bundle = staged.result["bundle_sha256"].as_str().unwrap();
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(retained::retain_bundle(
            staged.temporary.path(),
            &tree,
            bundle,
            &stage.0.path().join("retained"),
        ))?;
    let workflow = canonical_bytes(
        &json!({"schema_version":"ai-security-scanner.cloudflare-workflow-record/v1",
        "preparation_receipt":receipt,"entries":staged.record.entries,"record_head":staged.result["record_head"]}),
    )?;
    io::publish_bytes(stage.0.path(), "workflow.json", &workflow)?;
    let retention = fs::read(stage.0.path().join(FILES[0]))?;
    let retained_projection = fs::read(stage.0.path().join("retained/projection.json"))?;
    let reported: Value = serde_json::from_slice(&retained_projection)?;
    let projection = workflow_projection(
        staged,
        &reported,
        &[
            digest(&retention),
            digest(&retained_projection),
            digest(&workflow),
        ],
    );
    let projection_bytes = canonical_bytes(&projection)?;
    io::publish_bytes(
        stage.0.path(),
        "workflow-projection.json",
        &projection_bytes,
    )?;
    let seal = Seal {
        bundle_sha256: bundle.into(),
        manifest_sha256: staged.result["manifest_sha256"].as_str().unwrap().into(),
        files: [
            file(FILES[0], &retention),
            file(FILES[1], &workflow),
            file(FILES[2], &projection_bytes),
        ],
        projection,
    };
    seal.verify()?;
    let destination = seal.path(context.data_dir, receipt);
    let _parent = guard_archive_parent(destination.parent().unwrap())?;
    match fs::symlink_metadata(&destination) {
        Ok(_) => {
            if seal.state(context.data_dir, receipt) != DescriptorState::Verified {
                return Err(AppError::Storage(
                    "sealed package differs; existing bytes preserved".into(),
                ));
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            crate::case_archive_io::seal_directory_contents(stage.0.path())?;
            #[cfg(unix)]
            retained::sync_directories(stage.0.path())?;
            publish_directory_no_replace(stage.0.path(), &destination)?;
        }
        Err(e) => return Err(e.into()),
    }
    // An orphan from a stop after rename is byte-checked above and sealed here
    // before the record can commit. Read-only consumers require a committed seal.
    crate::case_archive_io::seal_directory_root(&destination)?;
    #[cfg(unix)]
    fs::File::open(destination.parent().unwrap())?.sync_all()?;
    Ok(seal)
}
struct PackageStage(crate::case_archive_io::PrivateArchiveDirectory);
impl Drop for PackageStage {
    fn drop(&mut self) {
        crate::workspace_snapshot::make_tree_deletable(self.0.path());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cloudflare_provider::MAX_SEALED_FILE_BYTES;

    #[test]
    fn seal_verification_uses_the_shared_file_size_boundary() {
        let hash = "a".repeat(64);
        let projection = json!({"schema_version":PROJECTION_SCHEMA,
            "provenance":"workflow_recorded", "canonical_snapshot_binding_verified":true,
            "source_authorization_verified":true, "audit_performed":true,
            "admission_ready":false, "target_execution_allowed":false,
            "retention_sha256":hash, "workflow_sha256":hash});
        let projection_bytes = canonical_bytes(&projection).unwrap();
        let mut seal = Seal {
            bundle_sha256: hash.clone(),
            manifest_sha256: hash.clone(),
            files: [
                BundleFile {
                    path: FILES[0].into(),
                    sha256: hash.clone(),
                    byte_length: 0,
                },
                BundleFile {
                    path: FILES[1].into(),
                    sha256: hash,
                    byte_length: 0,
                },
                file(FILES[2], &projection_bytes),
            ],
            projection,
        };
        for index in 0..2 {
            seal.files[index].byte_length = MAX_SEALED_FILE_BYTES;
            assert!(seal.verify().is_ok());
            seal.files[index].byte_length = MAX_SEALED_FILE_BYTES + 1;
            assert!(seal.verify().is_err());
            seal.files[index].byte_length = 0;
        }
    }
}
