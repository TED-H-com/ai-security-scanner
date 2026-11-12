//! Explicit host decision; only the product custody event is written.
use super::{record::*, *};
pub const TERMINATE_SCHEMA: &str = "ai-security-scanner.cloudflare-audit-terminate-request/v1";
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TerminateRequest {
    pub schema_version: String,
    pub request_id: String,
    pub case_id: String,
    pub session_id: String,
    pub expected_head_sha256: String,
    pub reason: TerminationReason,
}
impl TerminateRequest {
    pub(crate) fn content_digest(&self) -> AppResult<String> {
        domain_digest(TERMINATE_SCHEMA, self)
    }
}
impl TerminateRequest {
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
        if self.schema_version != TERMINATE_SCHEMA
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

pub fn terminate(
    context: &crate::cloudflare_provider::source_view::OwnedContext<'_>,
    request: &TerminateRequest,
) -> AppResult<CheckpointOutcome> {
    crate::cloudflare_provider::restored::guard(
        context.storage,
        &request.case_id,
        RECEIPT_EVENT,
        &request.session_id,
        true,
    )?;
    if let Err(code) = request.check() {
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
    let mut outcome = context.storage.append_cloudflare_record(
        &RecordRequest {
            request_id: &request.request_id,
            case_id: &request.case_id,
            session_id: &request.session_id,
            expected_head_sha256: &request.expected_head_sha256,
            digest: request.content_digest()?,
            sealing: false,
            terminating: true,
        },
        case.storage_revision,
        context.cancelled,
        || Ok(None),
        |_| {
            Ok(Content::Terminated {
                reason: request.reason,
            })
        },
        || chrono::Utc::now().to_rfc3339(),
    )?;
    if let CheckpointOutcome::Saved {
        receipt,
        outcome_run,
        ..
    } = &mut outcome
    {
        *outcome_run = crate::agent_audit_failure::retain(context, receipt);
    }
    Ok(outcome)
}
