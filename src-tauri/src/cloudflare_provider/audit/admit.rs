//! Publish verified originals, then atomically admit the immutable audit.
use super::*;
use crate::agent_audit_admission::{
    ADMITTED_EVENT, AdmissionRequestFacts, AgentAuditAdmission, FORMAT_REQUIREMENT, PlanError,
    PlannerRefusal, check_format, plan_admission, publication::OriginalPublicationError,
};
use crate::artifact_store::{ArtifactStore, inspect_raw_artifacts};
use crate::cloudflare_provider::source_view::OwnedContext;
use crate::domain::{AssessmentCase, CaseStatus, new_id};
use chrono::Utc;
use serde_json::{Value, json};

pub const ADMIT_SCHEMA: &str = "ai-security-scanner.cloudflare-audit-admit-request/v1";
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmitRequest {
    pub schema_version: String,
    pub request_id: String,
    pub case_id: String,
    pub session_id: String,
    pub expected_sealed_entry_sha256: String,
    pub expected_bundle_sha256: String,
    pub expected_projection_sha256: String,
}
#[derive(Debug, thiserror::Error)]
pub enum AdmissionError {
    #[error("{code}")]
    Refused {
        code: &'static str,
        exit: u8,
        retryable: bool,
    },
    #[error(transparent)]
    Other(#[from] AppError),
}
type Result<T> = std::result::Result<T, AdmissionError>;
fn refused(code: &'static str, exit: u8, retryable: bool) -> AdmissionError {
    AdmissionError::Refused {
        code,
        exit,
        retryable,
    }
}
impl From<sealed::VerificationError> for AdmissionError {
    fn from(error: sealed::VerificationError) -> Self {
        let changed = error.error_code == "case_changed";
        refused(error.error_code, if changed { 3 } else { 2 }, changed)
    }
}
impl From<PlanError> for AdmissionError {
    fn from(error: PlanError) -> Self {
        match error {
            PlanError::Other(e) => Self::Other(e),
            PlanError::Refused(code) => match code {
                PlannerRefusal::BindingNotProvable => refused("binding_not_provable", 2, false),
                PlannerRefusal::IdentityConflict => refused("identity_conflict", 3, false),
                PlannerRefusal::AdmissionTooLarge => refused("admission_too_large", 2, false),
            },
        }
    }
}
impl AdmitRequest {
    pub fn read(path: &Path) -> Result<Self> {
        let value = read_request(path).map_err(|e| {
            refused(
                match e {
                    RequestReadError::File => "request_file_limit",
                    RequestReadError::Json => "invalid_request",
                },
                2,
                false,
            )
        })?;
        let request: Self =
            serde_json::from_value(value).map_err(|_| refused("invalid_request", 2, false))?;
        request.check()?;
        Ok(request)
    }
    fn check(&self) -> Result<()> {
        if self.schema_version != ADMIT_SCHEMA
            || [&self.request_id, &self.case_id, &self.session_id]
                .iter()
                .any(|s| !valid_id(s))
            || [
                &self.expected_sealed_entry_sha256,
                &self.expected_bundle_sha256,
                &self.expected_projection_sha256,
            ]
            .iter()
            .any(|s| !valid_hash(s))
        {
            return Err(refused("invalid_request", 2, false));
        }
        Ok(())
    }
}
pub struct Admitted {
    pub receipt: Value,
    pub result: Value,
    pub replayed: bool,
}
fn outcome(a: &AgentAuditAdmission, receipt: Value, replayed: bool) -> Admitted {
    Admitted {
        receipt,
        replayed,
        result: json!({
            "admission_id": a.admission_id, "admission_sha256": a.admission_sha256,
            "admission_state": "admitted", "provenance": "workflow_recorded",
            "replayed": replayed, "native_outcome": a.outcome.state, "counts": a.counts,
            "incomplete_reason": a.outcome.incomplete_reason,
            "validators_reexecuted": false
        }),
    }
}
fn replay(
    context: &OwnedContext<'_>,
    case: &AssessmentCase,
    a: &AgentAuditAdmission,
) -> Result<Admitted> {
    let corrupt = || refused("admission_mismatch", 2, false);
    let mut value = serde_json::to_value(a).map_err(AppError::from)?;
    value.as_object_mut().unwrap().remove("admission_sha256");
    if domain_digest(FORMAT_REQUIREMENT, &value)? != a.admission_sha256 {
        return Err(corrupt());
    }
    let artifacts = a
        .artifacts
        .iter()
        .map(|binding| {
            let artifact = case
                .raw_artifacts
                .iter()
                .find(|r| r.id == binding.artifact_id)
                .ok_or_else(corrupt)?;
            if artifact.sha256 != binding.sha256
                || artifact.byte_length != binding.byte_length
                || artifact.case_id != a.identities.case_id
                || artifact.run_id != a.identities.run_id
                || artifact.engine_run_id != a.identities.task_id
                || artifact.relative_path
                    != format!(
                        "{}/{}/{}/{}",
                        a.identities.case_id,
                        a.identities.run_id,
                        a.identities.task_id,
                        binding.member_path
                    )
            {
                return Err(corrupt());
            }
            Ok(artifact.clone())
        })
        .collect::<Result<Vec<_>>>()?;
    inspect_raw_artifacts(&context.data_dir.join("artifacts"), &artifacts)
        .map_err(|_| corrupt())?;
    let events = context.storage.list_case_events(&case.id)?;
    let receipts: Vec<Value> = events
        .iter()
        .filter(|e| e.event_type == ADMITTED_EVENT)
        .map(|e| serde_json::from_str(&e.payload_json).map_err(|_| corrupt()))
        .collect::<Result<_>>()?;
    let matches: Vec<_> = receipts
        .iter()
        .filter(|r| r["request_id"] == a.request_id)
        .collect();
    if matches.len() != 1 {
        return Err(corrupt());
    }
    let receipt = matches[0];
    let revision = receipt["case_revision"].as_i64().ok_or_else(corrupt)?;
    if *receipt != a.receipt(revision) {
        return Err(corrupt());
    }
    Ok(outcome(a, receipt.clone(), true))
}
pub fn admit(context: &OwnedContext<'_>, request: &AdmitRequest) -> Result<Admitted> {
    crate::cloudflare_provider::restored::guard(
        context.storage,
        &request.case_id,
        super::RECEIPT_EVENT,
        &request.session_id,
        true,
    )?;
    request.check()?;
    if let Some(receipt) =
        context
            .storage
            .cloudflare_audit_receipt(&request.case_id, &request.session_id, true)?
    {
        context
            .storage
            .cloudflare_audit_record(&receipt)?
            .ensure_active()?;
    }
    let case = context.storage.get_case(&request.case_id)?;
    check_format(&case)?;
    let digest = domain_digest(ADMIT_SCHEMA, request)?;
    if let Some(a) = case
        .agent_audit_admissions
        .iter()
        .find(|a| a.request_id == request.request_id)
    {
        if a.request_sha256 != digest {
            return Err(refused("request_conflict", 3, false));
        }
        return replay(context, &case, a).map(|o| retain_outcome(context, o));
    }
    if case
        .agent_audit_admissions
        .iter()
        .any(|a| a.identities.session_id == request.session_id)
    {
        return Err(refused("session_already_admitted", 2, false));
    }
    if case.status == CaseStatus::Archived {
        return Err(refused("case_archived", 2, false));
    }
    if case.scan_runs.iter().any(|r| r.completed_at.is_none()) {
        return Err(refused("active_scan", 3, true));
    }
    let mut verified = sealed::verify(
        context.data_dir,
        context.storage,
        &case.id,
        &request.session_id,
    )?;
    if verified.digests.sealed_entry_sha256 != request.expected_sealed_entry_sha256
        || verified.digests.bundle_sha256 != request.expected_bundle_sha256
        || verified.digests.projection_sha256 != request.expected_projection_sha256
    {
        return Err(refused("expected_digest_mismatch", 2, false));
    }
    let plan = plan_admission(
        &verified,
        &case,
        &AdmissionRequestFacts {
            request_id: request.request_id.clone(),
            request_sha256: digest,
        },
        Utc::now(),
        new_id,
    )?;
    let mut resulting = plan.resulting_case(&case)?;
    let store = ArtifactStore::open(context.data_dir.join("artifacts"))?;
    let artifacts: Vec<_> = plan
        .artifact_copies
        .iter()
        .map(|c| c.artifact.clone())
        .collect();
    for copy in &plan.artifact_copies {
        let bytes = verified.read_member(&copy.member_path).map_err(|e| {
            refused(
                if matches!(e, AppError::UnsafeFilesystemEntry) {
                    "unsafe_filesystem_entry"
                } else {
                    "sealed_package_mismatch"
                },
                2,
                false,
            )
        })?;
        store
            .publish_original(&copy.artifact, &bytes, &artifacts)
            .map_err(|e| match e {
                OriginalPublicationError::Conflict => refused("artifact_conflict", 4, false),
                OriginalPublicationError::Other(e) => AdmissionError::Other(e),
            })?;
    }
    inspect_raw_artifacts(store.root(), &artifacts)
        .map_err(|_| refused("artifact_conflict", 4, false))?;
    verified.recheck_unchanged()?;
    context
        .storage
        .save_admitted_case(&mut resulting, &plan.admission)
        .map_err(|e| match e {
            AppError::Conflict(_) => refused("case_changed", 3, true),
            e => AdmissionError::Other(e),
        })?;
    Ok(retain_outcome(
        context,
        outcome(
            &plan.admission,
            plan.admission.receipt(resulting.storage_revision),
            false,
        ),
    ))
}

/// Status uses saved case data; it never re-runs validators or creates a ready flag.
pub fn status(case: &AssessmentCase, session_id: &str, data_dir: &Path, result: &mut Value) {
    let admission = case
        .agent_audit_admissions
        .iter()
        .find(|a| a.identities.session_id == session_id);
    result["admission_state"] = json!(if admission.is_some() {
        "admitted"
    } else {
        "not_admitted"
    });
    if let Some(a) = admission {
        result["admission"] = json!({
            "admission_id": a.admission_id, "admission_sha256": a.admission_sha256,
            "request_id": a.request_id, "run_id": a.identities.run_id,
            "task_id": a.identities.task_id, "admitted_at": a.admitted_at
        });
        let snapshot = crate::report_snapshot::current_run_snapshot(case, &a.identities.run_id)
            .and_then(|r| {
                result["report_snapshot"] = json!(r);
                r.ok_or_else(|| AppError::NotAvailable("Report snapshot is not available.".into()))
            })
            .and_then(|record| {
                record
                    .read(&data_dir.join("artifacts"), &case.id)
                    .map(|_| record)
            });
        let retained = snapshot.is_ok();
        match snapshot {
            Ok(record) => result["report_snapshot"] = json!(record),
            Err(error) => snapshot_failure(result, &error),
        }
        result["report_snapshot_state"] = json!(if retained { "retained" } else { "pending" });
        result["next_operation"] = json!(if retained {
            "retrieve_report"
        } else {
            "admit_replay"
        });
    }
}

/// No runtime, catalog, grant, or provider workspace is needed to save a report.
pub fn retain_report_snapshot(
    storage: &crate::storage::Storage,
    data_dir: &Path,
    case_id: &str,
    run_id: &str,
) -> AppResult<AssessmentCase> {
    let engines = crate::registry::EngineRegistry::empty();
    let adapters = crate::adapter::AdapterRegistry::default();
    crate::case_service::CaseService::new(
        storage,
        &engines,
        &adapters,
        data_dir.join("artifacts"),
        data_dir.join("integrity-signing-key"),
    )
    .retain_terminal_report_snapshot(case_id, run_id)
    .and_then(|case| {
        if crate::report_snapshot::current_run_snapshot(&case, run_id)?.is_none() {
            return Err(AppError::NotAvailable(
                "Report snapshot is not available.".into(),
            ));
        }
        Ok(case)
    })
}
fn retain_outcome(context: &OwnedContext<'_>, mut outcome: Admitted) -> Admitted {
    let case_id = outcome.receipt["case_id"]
        .as_str()
        .expect("committed case id");
    let run_id = outcome.receipt["run_id"]
        .as_str()
        .expect("committed run id");
    // This is deliberately outside the admission transaction. Publication failure
    // leaves the immutable receipt successful and replay retries only this step.
    let record = retain_report_snapshot(context.storage, context.data_dir, case_id, run_id)
        .and_then(|case| {
            crate::report_snapshot::current_run_snapshot(&case, run_id).map(|r| r.cloned())
        });
    match record {
        Ok(Some(record)) => {
            outcome.result["report_snapshot"] = json!(record);
            outcome.result["report_snapshot_state"] = json!("retained");
        }
        Ok(None) => snapshot_failure(
            &mut outcome.result,
            &AppError::NotAvailable("Report snapshot is not available.".into()),
        ),
        Err(error) => snapshot_failure(&mut outcome.result, &error),
    }
    outcome
}

pub fn snapshot_failure(result: &mut Value, error: &AppError) {
    let (_, code, retryable) = crate::error::foreground_error_class(error);
    result["report_snapshot_state"] = json!("pending");
    result["report_snapshot_error_code"] = json!(code);
    result["report_snapshot_retryable"] = json!(retryable);
}
