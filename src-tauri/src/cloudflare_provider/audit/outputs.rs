//! Assignment output capture; accepted bytes are custody, never a product verdict.
use super::{
    documents::{MAX_CAPTURED, capture_file, captured_limit},
    record::*,
    *,
};
use crate::cloudflare_provider::strict_json;
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutputSpec {
    pub path: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "record::present"
    )]
    pub sha256: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "record::present"
    )]
    pub byte_length: Option<u64>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Disposition {
    Accepted,
    Discarded,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssignmentOutput {
    pub disposition: Disposition,
    pub path: String,
    pub sha256: String,
    pub byte_length: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<Refusal>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decision: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub returned_fingerprint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub record_sha256: Option<String>,
}
fn recon(role: Role) -> bool {
    matches!(
        role,
        Role::ReconnaissanceBaseline | Role::ReconnaissanceFocused
    )
}
pub(super) fn bound(role: Role) -> u64 {
    if recon(role) {
        1024 * 1024
    } else {
        5 * 1024 * 1024
    }
}
fn assignment<'a>(
    record: &'a Record,
    id: &str,
    spec: &OutputSpec,
) -> Result<&'a Assignment, Refusal> {
    let a = record
        .assignments
        .iter()
        .find(|a| a.assignment.assignment_id == id)
        .ok_or(Refusal::UnknownAssignment)?;
    if a.state != "open" {
        return Err(Refusal::AssignmentClosed);
    }
    let prefix = format!("agents/{}/artifacts/", a.assignment.agent_id);
    let name = spec
        .path
        .strip_prefix(&prefix)
        .ok_or(Refusal::OutputInvalid)?;
    if name.is_empty()
        || name == "."
        || name == ".."
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        || spec.sha256.as_ref().is_some_and(|h| !valid_hash(h))
    {
        return Err(Refusal::OutputInvalid);
    }
    Ok(&a.assignment)
}
type CapturedOutput = (Content, Option<Vec<u8>>);
pub(super) type FinalBindings = std::collections::BTreeMap<String, (u64, String)>;
pub(super) fn capture(
    record: &Record,
    facts: &Prepared,
    id: &str,
    spec: &OutputSpec,
) -> AppResult<Result<CapturedOutput, CheckpointOutcome>> {
    let fail = |error_code| CheckpointOutcome::DocumentRejected {
        error_code,
        document: spec.path.clone(),
        validation: None,
    };
    let a = match assignment(record, id, spec) {
        Ok(a) => a,
        Err(e) => return Ok(Err(fail(e))),
    };
    let mut root = match documents::capture_root(facts) {
        Ok(root) => root,
        Err(outcome) => return Ok(Err(*outcome)),
    };
    let bytes = match capture_file(
        &mut root,
        &spec.path,
        bound(a.spec.role),
        spec.sha256.as_deref(),
        spec.byte_length,
    ) {
        Ok(bytes) => bytes,
        Err(e) => {
            return Ok(Err(fail(if e == Refusal::DocumentMismatch {
                Refusal::OutputMismatch
            } else {
                Refusal::OutputUnreadable
            })));
        }
    };
    if root.verify_unchanged().is_err() {
        return Ok(Err(fail(Refusal::OutputUnreadable)));
    }
    let mut output = AssignmentOutput {
        disposition: Disposition::Accepted,
        path: spec.path.clone(),
        sha256: digest(&bytes),
        byte_length: bytes.len() as u64,
        reason: None,
        decision: None,
        returned_fingerprint: None,
        record_sha256: None,
    };
    let valid = if recon(a.spec.role) {
        std::str::from_utf8(&bytes).is_ok_and(|s| !s.is_empty())
    } else {
        match strict_json::parse(&bytes) {
            Ok(value) if value.is_object() => check_contract(a, &value, &mut output)?,
            _ => false,
        }
    };
    if !valid {
        if !matches!(a.spec.role, Role::CandidateVerifier | Role::FinalVerifier) {
            return Ok(Err(fail(Refusal::OutputInvalid)));
        }
        output.disposition = Disposition::Discarded;
        output.reason = Some(Refusal::OutputInvalid);
    }
    let bytes = (output.disposition == Disposition::Accepted).then_some(bytes);
    match mint(record, id, spec, &output) {
        Ok(content) => Ok(Ok((content, bytes))),
        Err(code) => Ok(Err(fail(code))),
    }
}
fn check_contract(
    a: &Assignment,
    value: &serde_json::Value,
    output: &mut AssignmentOutput,
) -> AppResult<bool> {
    if !matches!(a.spec.role, Role::CandidateVerifier | Role::FinalVerifier) {
        return Ok(true);
    }
    if a.spec.role == Role::FinalVerifier {
        if !super::super::bundle::final_contract(value, a.spec.fingerprint.as_deref().unwrap()) {
            return Ok(false);
        }
        if value["decision"] == "verified" {
            output.decision = Some("verified".into());
            output.returned_fingerprint = a.spec.fingerprint.clone();
            output.record_sha256 = a.bound_record_sha256.clone();
            return Ok(true);
        }
    } else if !super::super::bundle::candidate_contract(value) {
        return Ok(false);
    }
    let receipt = documents::validate(
        super::super::CloudflareDocument::Findings,
        &serde_json::to_vec(&serde_json::json!([value["record"]]))?,
    )?;
    if !receipt.validation.valid {
        return Ok(false);
    }
    output.decision = value["decision"].as_str().map(Into::into);
    output.returned_fingerprint = value["record"]["fingerprint"].as_str().map(Into::into);
    output.record_sha256 = Some(super::super::bundle::record_digest(&value["record"])?);
    Ok(true)
}
pub(super) fn mint(
    record: &Record,
    id: &str,
    spec: &OutputSpec,
    output: &AssignmentOutput,
) -> Result<Content, Refusal> {
    let a = assignment(record, id, spec)?;
    if output.path != spec.path
        || !valid_hash(&output.sha256)
        || output.byte_length > bound(a.spec.role)
        || spec.sha256.as_ref().is_some_and(|h| h != &output.sha256)
        || spec.byte_length.is_some_and(|n| n != output.byte_length)
    {
        return Err(Refusal::OutputInvalid);
    }
    let verifier = matches!(a.spec.role, Role::CandidateVerifier | Role::FinalVerifier);
    let accepted = output.disposition == Disposition::Accepted;
    if (!accepted && (!verifier || output.reason != Some(Refusal::OutputInvalid)))
        || (accepted && output.reason.is_some())
        || output.decision.is_some() != (accepted && verifier)
        || output.returned_fingerprint.is_some() != (accepted && verifier)
        || output.record_sha256.is_some() != (accepted && verifier)
        || output
            .record_sha256
            .as_ref()
            .is_some_and(|h| !valid_hash(h))
    {
        return Err(Refusal::OutputInvalid);
    }
    captured_limit(record.captured, [output.byte_length], MAX_CAPTURED)?;
    Ok(Content::SubmitOutput {
        assignment_id: id.into(),
        requested_output: spec.clone(),
        output: output.clone(),
    })
}
impl Record {
    pub(super) fn push_output(
        &mut self,
        id: &str,
        spec: &OutputSpec,
        output: &AssignmentOutput,
        time: &str,
    ) -> AppResult<()> {
        mint(self, id, spec, output)
            .map_err(|_| AppError::Storage("audit assignment output invalid".into()))?;
        self.captured += output.byte_length;
        let a = self
            .assignments
            .iter_mut()
            .find(|a| a.assignment.assignment_id == id)
            .unwrap();
        a.state = if output.disposition == Disposition::Accepted {
            "closed"
        } else {
            "discarded"
        };
        a.closed_at = Some(time.into());
        a.output = Some(output.clone());
        Ok(())
    }
}

/// Resolve final review bindings from captured findings, never from the host's live file.
pub(super) fn final_bindings(
    data: &Path,
    receipt: &PreparationReceipt,
    record: &Record,
    requested: &[AssignmentSpec],
    profile: Profile,
) -> AppResult<Result<FinalBindings, Refusal>> {
    let mut bindings = std::collections::BTreeMap::new();
    let finals: Vec<_> = requested
        .iter()
        .filter(|s| s.role == Role::FinalVerifier)
        .collect();
    if finals.is_empty() {
        return Ok(Ok(bindings));
    }
    if matches!(profile, Profile::Quick) {
        return Ok(Err(Refusal::QuickFinalVerifierUnavailable));
    }
    let Some(doc) = record.documents.get("findings.json") else {
        return Ok(Err(Refusal::FinalFindingsRequired));
    };
    let bytes = io::read_object(data, receipt, &doc.current.sha256, doc.current.byte_length)?;
    let findings = strict_json::parse(&bytes).map_err(|e| AppError::Storage(e.to_string()))?;
    for spec in finals {
        let Some(fp) = &spec.fingerprint else {
            return Ok(Err(Refusal::RoleFieldsInvalid));
        };
        let Some(value) = findings
            .as_array()
            .and_then(|v| v.iter().find(|r| r["fingerprint"].as_str() == Some(fp)))
        else {
            return Ok(Err(Refusal::FinalRecordIneligible));
        };
        if !matches!(
            value["verdict"].as_str(),
            Some("confirmed" | "needs_validation")
        ) {
            return Ok(Err(Refusal::FinalRecordIneligible));
        }
        if !record.assignments.iter().any(|a| {
            a.assignment.spec.role == Role::CandidateVerifier
                && a.output.as_ref().is_some_and(|o| {
                    o.disposition == Disposition::Accepted
                        && o.returned_fingerprint.as_ref() == Some(fp)
                })
        }) {
            return Ok(Err(Refusal::FinalCandidateRequired));
        }
        bindings.insert(
            fp.clone(),
            (
                doc.current.revision,
                super::super::bundle::record_digest(value)?,
            ),
        );
    }
    Ok(Ok(bindings))
}
