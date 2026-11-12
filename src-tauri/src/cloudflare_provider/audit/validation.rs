//! Read-only terminal assembly. The writer lease covers currency, custody and validation.
use super::{record::*, *};
use crate::case_archive_io::{guard_archive_parent, make_private, private_tempdir_in};
use crate::cloudflare_provider::{
    bundle,
    bundle_io::BundleRoot,
    source_view::{self, OwnedContext},
    strict_json,
};
use serde_json::{Value, json};
use std::{collections::BTreeMap, fs};
pub const VALIDATE_SCHEMA: &str = "ai-security-scanner.cloudflare-audit-validate-request/v1";
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidateRequest {
    pub schema_version: String,
    pub case_id: String,
    pub session_id: String,
    #[serde(default, deserialize_with = "record::present")]
    pub expected_head_sha256: Option<String>,
}
impl ValidateRequest {
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
        if self.schema_version != VALIDATE_SCHEMA
            || !valid_id(&self.case_id)
            || !valid_id(&self.session_id)
            || self
                .expected_head_sha256
                .as_ref()
                .is_some_and(|h| !valid_hash(h))
        {
            return Err(Refusal::InvalidRequest);
        }
        Ok(())
    }
}
pub enum ValidationOutcome {
    Validated(Box<Value>),
    Rejected {
        error_code: Refusal,
        reason: Option<BlockerCode>,
    },
}
impl ValidationOutcome {
    fn refused(error_code: Refusal) -> Self {
        Self::Rejected {
            error_code,
            reason: None,
        }
    }
    fn stale(reason: BlockerCode) -> Self {
        Self::Rejected {
            error_code: Refusal::SavedReceiptNotCurrent,
            reason: Some(reason),
        }
    }
}
pub(super) struct Staged {
    pub temporary: crate::case_archive_io::PrivateArchiveDirectory,
    pub result: Value,
    pub receipt: PreparationReceipt,
    pub record: Record,
    pub view: source_view::SourceViewPreparationReceipt,
    pub revision: i64,
}
pub fn validate(
    context: &OwnedContext<'_>,
    request: &ValidateRequest,
) -> AppResult<ValidationOutcome> {
    crate::cloudflare_provider::restored::guard(
        context.storage,
        &request.case_id,
        RECEIPT_EVENT,
        &request.session_id,
        true,
    )?;
    Ok(match assemble(context, request)? {
        Ok(staged) => ValidationOutcome::Validated(Box::new(staged.result)),
        Err(outcome) => outcome,
    })
}
pub(super) fn assemble(
    context: &OwnedContext<'_>,
    request: &ValidateRequest,
) -> AppResult<Result<Staged, ValidationOutcome>> {
    if let Err(code) = request.check() {
        return Ok(Err(ValidationOutcome::refused(code)));
    }
    if context
        .lease
        .path()
        .parent()
        .map(fs::canonicalize)
        .transpose()?
        != Some(fs::canonicalize(context.data_dir)?)
        || fs::canonicalize(context.storage.path())?
            != fs::canonicalize(context.data_dir.join("casework.db"))?
    {
        return Err(invalid("ownership context does not match storage"));
    }
    let case = context.storage.get_case(&request.case_id)?;
    let loaded = (|| -> AppResult<_> {
        let receipt = context.storage.cloudflare_audit_receipt(
            &request.case_id,
            &request.session_id,
            true,
        )?;
        receipt
            .map(|r| {
                context
                    .storage
                    .cloudflare_audit_record(&r)
                    .map(|record| (r, record))
            })
            .transpose()
    })();
    let (receipt, record) = match loaded {
        Ok(Some(pair)) => pair,
        Ok(None) => return Ok(Err(ValidationOutcome::refused(Refusal::UnknownPreparation))),
        Err(_) => return Ok(Err(ValidationOutcome::refused(Refusal::RecordInvalid))),
    };
    record.ensure_active()?;
    if record.sealed().is_some() {
        return Ok(Err(ValidationOutcome::refused(Refusal::RunSealed)));
    }
    let (sequence, head) = record.head(&receipt);
    if request
        .expected_head_sha256
        .as_deref()
        .is_some_and(|h| h != head)
    {
        return Ok(Err(ValidationOutcome::refused(Refusal::StaleHead)));
    }
    let PreparationResult::Prepared { facts, .. } = &receipt.result else {
        return Ok(Err(ValidationOutcome::refused(Refusal::BlockedPreparation)));
    };
    let Some(view) = context
        .storage
        .source_view_receipt(&request.case_id, &facts.source.source_view_request_id)?
    else {
        return Ok(Err(ValidationOutcome::stale(
            BlockerCode::SourceBindingMismatch,
        )));
    };
    if let Some(reason) =
        checkpoint::current_authority(&case, &receipt, facts, &view, &chrono::Utc::now)?
    {
        return Ok(Err(ValidationOutcome::stale(reason)));
    }
    let current =
        match source_view::current_view(context.data_dir, &case, &view, chrono::Utc::now())? {
            Ok(current) => current,
            Err(reason) => return Ok(Err(ValidationOutcome::stale(prepare::reason(reason)))),
        };
    if !source_view::effective(&current.grant, &receipt.asset_id, chrono::Utc::now()) {
        return Ok(Err(ValidationOutcome::stale(
            BlockerCode::SourceAuthorizationExpired,
        )));
    }
    if bundle::REQUIRED
        .iter()
        .any(|name| !record.documents.contains_key(*name))
    {
        return Ok(Err(ValidationOutcome::refused(Refusal::DocumentsRequired)));
    }
    if record.assignments.iter().any(|a| a.state == "open") {
        return Ok(Err(ValidationOutcome::refused(Refusal::AssignmentsOpen)));
    }
    let directory = io::directory(context.data_dir, &receipt).unwrap();
    let root = BundleRoot::open(&directory)?;
    let _guard = guard_archive_parent(&directory)?;
    let temporary = private_tempdir_in(&directory, ".validate-")?;
    let mut documents = BTreeMap::new();
    for d in record.documents.values() {
        documents.insert(
            d.current.name.clone(),
            io::read_object(
                context.data_dir,
                &receipt,
                &d.current.sha256,
                d.current.byte_length,
            )?,
        );
    }
    let findings = strict_json::parse(&documents["findings.json"])?;
    let ledger = strict_json::parse(&documents["coverage-ledger.json"])?;
    let metadata = strict_json::parse(&documents["run-metadata.json"])?;
    let manifest =
        manifest::generate(&receipt, facts, &record, current.source, &findings, &ledger)?;
    let bytes = canonical_bytes(&manifest)?;
    let mut validation = bundle::validation_receipt(&manifest, &bytes)?;
    let limits = bundle::check_manifest(&manifest).and_then(|()| {
        if bytes.len() > 4 * 1024 * 1024 {
            Err(invalid("manifest exceeds 4 MiB"))
        } else {
            Ok(())
        }
    });
    if let Err(error) = limits {
        validation.reference_errors.push(error.to_string());
    } else {
        for file in &manifest.files {
            let content = match documents.remove(&file.path) {
                Some(bytes) => bytes,
                None => {
                    io::read_object(context.data_dir, &receipt, &file.sha256, file.byte_length)?
                }
            };
            let path = temporary.path().join(&file.path);
            fs::create_dir_all(path.parent().unwrap())?;
            fs::write(&path, content)?;
            make_private(&path, false)?;
        }
        fs::write(temporary.path().join("provider-manifest.json"), &bytes)?;
        make_private(&temporary.path().join("provider-manifest.json"), false)?;
        let source_view::PreparationResult::Ready { relative_path, .. } = &view.result else {
            unreachable!()
        };
        let tree = context
            .data_dir
            .join("artifacts")
            .join(relative_path)
            .join("tree");
        match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(bundle::validate_bundle(temporary.path(), &tree))
        {
            Ok(receipt) => validation = receipt,
            Err(error @ AppError::InvalidRequest(_)) => {
                validation.reference_errors.push(error.to_string())
            }
            Err(error) => return Err(error),
        }
    }
    let record_errors = record_errors(&record, facts, &ledger, &metadata);
    let result = json!({"sealable":validation.valid && record_errors.is_empty(),
        "record_head":{"sequence":sequence,"entry_sha256":head},
        "manifest_sha256":validation.manifest_sha256,"bundle_sha256":validation.bundle_sha256,
        "bundle_receipt":validation,"record_errors":record_errors,
        "counts_by_role":record.counts(),"counts_by_state":record.counts_by_state(),
        "run_status":metadata["run_status"],"incomplete_reason":metadata["incomplete_reason"]});
    root.verify_unchanged()?;
    Ok(Ok(Staged {
        temporary,
        result,
        receipt,
        record,
        view,
        revision: case.storage_revision,
    }))
}

fn record_errors(
    record: &Record,
    facts: &Prepared,
    ledger: &Value,
    metadata: &Value,
) -> Vec<String> {
    use Role::*;
    let mut errors = Vec::new();
    for (owner, evidence) in manifest::owners(ledger) {
        match record
            .assignments
            .iter()
            .find(|a| a.assignment.agent_id == owner)
        {
            None => errors.push(format!("ledger owner {owner} was not issued in this run")),
            Some(a) => {
                if !matches!(
                    a.assignment.spec.role,
                    Hunter | CandidateVerifier | FinalVerifier
                ) {
                    errors.push(format!(
                        "ledger owner {owner} was not issued an evidence role"
                    ));
                }
                if evidence && a.state != "closed" {
                    errors.push(format!("ledger evidence owner {owner} is not closed"));
                }
            }
        }
    }
    if metadata["run_status"] == "complete" {
        let closed: Vec<_> = record
            .assignments
            .iter()
            .filter(|a| a.state == "closed")
            .map(|a| &a.assignment.spec)
            .collect();
        if closed
            .iter()
            .filter(|a| a.role == ReconnaissanceBaseline)
            .count()
            < 4
        {
            errors.push(
                "a complete run requires four closed baseline reconnaissance assignments".into(),
            );
        }
        let waves: std::collections::BTreeSet<_> = closed
            .iter()
            .filter(|a| a.role == Hunter)
            .filter_map(|a| a.wave)
            .collect();
        for wave in waves {
            if !closed
                .iter()
                .any(|a| a.role == PostWaveCritic && a.wave == Some(wave))
            {
                errors.push(format!(
                    "hunted wave {wave} lacks a closed post-wave critic"
                ));
            }
        }
        if !matches!(facts.profile, Profile::Quick)
            && !closed.iter().any(|a| a.role == FinalCleanCritic)
        {
            errors.push("a complete non-quick run requires a closed final-clean critic".into());
        }
    }
    errors
}
