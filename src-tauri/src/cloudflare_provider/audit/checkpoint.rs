use super::{record::*, *};
use crate::cloudflare_provider::source_view::{self, OwnedContext};
use chrono::{DateTime, Utc};
impl CheckpointRequest {
    pub fn read(path: &Path) -> Result<Self, Refusal> {
        let value = read_request(path).map_err(|e| match e {
            RequestReadError::File => Refusal::RequestFileLimit,
            RequestReadError::Json => Refusal::InvalidRequest,
        })?;
        let request: Self = serde_json::from_value(value).map_err(|_| Refusal::InvalidRequest)?;
        request.validate()?;
        Ok(request)
    }
    pub fn validate(&self) -> Result<(), Refusal> {
        if self.schema_version != CHECKPOINT_SCHEMA
            || !valid_hash(&self.expected_head_sha256)
            || [&self.request_id, &self.case_id, &self.session_id]
                .iter()
                .any(|s| !valid_id(s))
        {
            return Err(Refusal::InvalidRequest);
        }
        Ok(())
    }
}
pub fn checkpoint(
    context: &OwnedContext<'_>,
    request: &CheckpointRequest,
) -> AppResult<CheckpointOutcome> {
    checkpoint_with_clock(context, request, &Utc::now)
}
pub(crate) fn checkpoint_with_clock(
    context: &OwnedContext<'_>,
    request: &CheckpointRequest,
    clock: &dyn Fn() -> DateTime<Utc>,
) -> AppResult<CheckpointOutcome> {
    crate::cloudflare_provider::restored::guard(
        context.storage,
        &request.case_id,
        super::RECEIPT_EVENT,
        &request.session_id,
        true,
    )?;
    if let Err(code) = request.validate() {
        return Ok(CheckpointOutcome::refused(code));
    }
    if context
        .lease
        .path()
        .parent()
        .map(crate::internal_paths::canonicalize)
        .transpose()?
        != Some(crate::internal_paths::canonicalize(context.data_dir)?)
        || crate::internal_paths::canonicalize(context.storage.path())?
            != crate::internal_paths::canonicalize(context.data_dir.join("casework.db"))?
    {
        return Err(invalid("ownership context does not match storage"));
    }
    let case = context.storage.get_case(&request.case_id)?;
    let receipt =
        context
            .storage
            .cloudflare_audit_receipt(&request.case_id, &request.session_id, true)?;
    let record = receipt
        .as_ref()
        .map(|r| context.storage.cloudflare_audit_record(r))
        .transpose()?;
    if let Some(record) = &record {
        record.ensure_active()?;
    }
    if record.as_ref().is_some_and(|r| r.sealed().is_some()) {
        return Ok(CheckpointOutcome::refused(Refusal::RunSealed));
    }
    let facts = receipt.as_ref().and_then(|r| match &r.result {
        PreparationResult::Prepared { facts, .. } => Some(facts),
        _ => None,
    });
    let view = facts
        .map(|f| {
            context
                .storage
                .source_view_receipt(&request.case_id, &f.source.source_view_request_id)
        })
        .transpose()?
        .flatten();
    let current = || {
        let Some((r, f, v)) = receipt
            .as_ref()
            .zip(facts)
            .zip(view.as_ref())
            .map(|((r, f), v)| (r, f, v))
        else {
            return Ok(Some(BlockerCode::SourceBindingMismatch));
        };
        if let Some(reason) = current_authority(&case, r, f, v, clock)? {
            return Ok(Some(reason));
        }
        Ok(super::super::bundle_io::BundleRoot::open(&f.run_directory)
            .err()
            .map(|_| BlockerCode::RunDirectoryUnavailable))
    };
    let mut captured = None;
    let mut submitted = None;
    let mut bindings = std::collections::BTreeMap::new();
    if let Some(receipt) = &receipt {
        let record = record.as_ref().unwrap();
        if let Some(outcome) = record.precheck(receipt, &request.record_request()?, current)? {
            return Ok(outcome);
        }
        if let Action::Issue { assignments } = &request.action {
            bindings = match outputs::final_bindings(
                context.data_dir,
                receipt,
                record,
                assignments,
                facts.unwrap().profile,
            )? {
                Ok(bindings) => bindings,
                Err(code) => return Ok(CheckpointOutcome::refused(code)),
            };
        }
        if let Action::SubmitOutput {
            assignment_id,
            output,
        } = &request.action
        {
            let (content, bytes) =
                match outputs::capture(record, facts.unwrap(), assignment_id, output)? {
                    Ok(value) => value,
                    Err(outcome) => return Ok(outcome),
                };
            if let Some(bytes) = bytes {
                io::publish_object(context.data_dir, receipt, &bytes)?;
            }
            submitted = Some(content);
        }
        if let Action::SubmitDocuments { documents } = &request.action {
            let bytes = match documents::capture(facts.unwrap(), documents)? {
                Ok(bytes) => bytes,
                Err(outcome) => return Ok(outcome),
            };
            if let Err(code) = documents::mint(record, documents, &bytes) {
                return Ok(CheckpointOutcome::refused(code));
            }
            for bytes in &bytes {
                io::publish_object(context.data_dir, receipt, bytes)?;
            }
            captured = Some(bytes);
        }
    }
    if context
        .cancelled
        .is_some_and(|s| s.load(std::sync::atomic::Ordering::Acquire) != 0)
    {
        return Ok(CheckpointOutcome::Interrupted);
    }
    context.storage.append_cloudflare_record(
        &request.record_request()?,
        case.storage_revision,
        context.cancelled,
        current,
        |record| {
            let facts = facts.ok_or(Refusal::UnknownPreparation)?;
            if let Some(Content::SubmitOutput {
                assignment_id,
                requested_output,
                output,
            }) = &submitted
            {
                return outputs::mint(record, assignment_id, requested_output, output);
            }
            if let Action::SubmitDocuments { documents } = &request.action {
                return documents::mint(record, documents, captured.as_ref().unwrap());
            }
            let mut content = mint(
                record,
                &request.action,
                facts.profile,
                facts.invocation_budget,
            )?;
            if let Content::Issue { assignments } = &mut content {
                for a in assignments
                    .iter_mut()
                    .filter(|a| a.spec.role == Role::FinalVerifier)
                {
                    let (revision, digest) = bindings
                        .get(a.spec.fingerprint.as_ref().unwrap())
                        .ok_or(Refusal::FinalRecordIneligible)?;
                    a.findings_revision = Some(*revision);
                    a.bound_record_sha256 = Some(digest.clone());
                }
            }
            Ok(content)
        },
        || clock().to_rfc3339(),
    )
}
fn mint(
    record: &Record,
    action: &Action,
    profile: Profile,
    budget: Option<u64>,
) -> Result<Content, Refusal> {
    match action {
        Action::SubmitOutput { .. } | Action::SubmitDocuments { .. } => {
            unreachable!("documents minted from captured bytes")
        }
        Action::Issue { assignments } => rules::issue(record, assignments, profile, budget),
        Action::Interrupt {
            assignment_id,
            reason,
        } => rules::interrupt(record, assignment_id, reason),
    }
}

pub(super) fn validator_current(facts: &Prepared) -> Option<BlockerCode> {
    (facts.validator_resources_sha256 != super::super::resources_digest())
        .then_some(BlockerCode::ValidatorResourcesChanged)
}

/// Shared authority/resource check; intentionally does not read a host directory.
pub(super) fn current_authority(
    case: &crate::domain::AssessmentCase,
    receipt: &PreparationReceipt,
    facts: &Prepared,
    view: &source_view::SourceViewPreparationReceipt,
    clock: &dyn Fn() -> DateTime<Utc>,
) -> AppResult<Option<BlockerCode>> {
    if let Some(reason) = validator_current(facts) {
        return Ok(Some(reason));
    }
    if view.case_id != receipt.case_id
        || view.asset_id != receipt.asset_id
        || view.digest != facts.source.source_view_receipt_sha256
        || view.grant_sha256.as_deref() != Some(&facts.source.grant_sha256)
    {
        return Ok(Some(BlockerCode::SourceBindingMismatch));
    }
    match source_view::current_authority(case, view, clock())? {
        Err(reason) => Ok(Some(prepare::reason(reason))),
        Ok((_, grant)) => Ok(
            (!source_view::effective(&grant, &receipt.asset_id, clock()))
                .then_some(BlockerCode::SourceAuthorizationExpired),
        ),
    }
}
