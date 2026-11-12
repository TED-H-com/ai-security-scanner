//! Assignment custody, independent of host execution or filesystem contents.
use super::documents::{DocumentRevision, DocumentSpec, DocumentState};
use super::outputs::{AssignmentOutput, OutputSpec};
use super::*;
use std::collections::{BTreeMap, BTreeSet};
pub const RECORD_EVENT: &str = "cloudflare_audit.record_entry";
pub const ENTRY_SCHEMA: &str = "ai-security-scanner.cloudflare-audit-record-entry/v1";
pub const CHECKPOINT_SCHEMA: &str = "ai-security-scanner.cloudflare-audit-checkpoint-request/v1";
pub const MAX_ENTRY: usize = 1024 * 1024;
pub const MAX_RECORD: usize = 4 * MAX_ENTRY;
pub const MAX_TERMINAL_ENTRY: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TerminationReason {
    HostCancelled,
    HostInterrupted,
    BudgetExhausted,
    AuthorizationUnavailable,
    RequiredArtifactsUnavailable,
    WorkflowFailed,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    ReconnaissanceBaseline,
    ReconnaissanceFocused,
    Hunter,
    PostWaveCritic,
    FinalCleanCritic,
    CandidateVerifier,
    FinalVerifier,
}
impl Role {
    pub(crate) fn word(self) -> &'static str {
        match self {
            Self::ReconnaissanceBaseline => "recon",
            Self::ReconnaissanceFocused => "focus",
            Self::Hunter => "hunter",
            Self::PostWaveCritic => "critic",
            Self::FinalCleanCritic => "clean",
            Self::CandidateVerifier => "verify",
            Self::FinalVerifier => "final",
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssignmentSpec {
    pub role: Role,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub wave: Option<u64>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub fingerprint: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub replaces: Option<String>,
}
pub(super) fn present<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
    d: D,
) -> Result<Option<T>, D::Error> {
    T::deserialize(d).map(Some)
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Action {
    SubmitOutput {
        assignment_id: String,
        output: OutputSpec,
    },
    SubmitDocuments {
        documents: Vec<DocumentSpec>,
    },
    Issue {
        assignments: Vec<AssignmentSpec>,
    },
    Interrupt {
        assignment_id: String,
        reason: String,
    },
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointRequest {
    pub schema_version: String,
    pub request_id: String,
    pub case_id: String,
    pub session_id: String,
    pub expected_head_sha256: String,
    pub action: Action,
}
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Refusal {
    RunSealed,
    NotSealable,
    BundleMismatch,
    RecordInvalid,
    DocumentsRequired,
    AssignmentsOpen,
    QuickFinalVerifierUnavailable,
    FinalFindingsRequired,
    FinalRecordIneligible,
    FinalCandidateRequired,
    OutputInvalid,
    OutputMismatch,
    OutputUnreadable,
    DocumentBatchLimit,
    DocumentInvalid,
    DocumentMismatch,
    DocumentUnreadable,
    MetadataBindingMismatch,
    CapturedBytesLimit,
    InvalidRequest,
    RequestFileLimit,
    UnknownPreparation,
    BlockedPreparation,
    StaleHead,
    RequestConflict,
    SavedReceiptNotCurrent,
    AssignmentBatchLimit,
    AssignmentRunLimit,
    RecordEntryLimit,
    EntryBytesLimit,
    RecordBytesLimit,
    RoleFieldsInvalid,
    WaveSkipped,
    WaveClosed,
    QuickWaveLimit,
    QuickFinalCleanUnavailable,
    CriticRequiresHunters,
    FingerprintInvalid,
    InvocationBudgetExhausted,
    BudgetCannotReserveCriticsAndValidation,
    InterruptionReasonInvalid,
    UnknownAssignment,
    AssignmentClosed,
    ReplacementNotInterrupted,
    ReplacementMismatch,
    AssignmentAlreadyReplaced,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Assignment {
    pub assignment_id: String,
    pub agent_id: String,
    pub ordinal: u64,
    pub issued_at: String,
    pub spec: AssignmentSpec,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub findings_revision: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bound_record_sha256: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Content {
    Terminated {
        reason: TerminationReason,
    },
    Sealed {
        seal: Box<super::finalize::Seal>,
    },
    SubmitOutput {
        assignment_id: String,
        requested_output: OutputSpec,
        output: AssignmentOutput,
    },
    SubmitDocuments {
        requested_documents: Vec<DocumentSpec>,
        documents: Vec<DocumentRevision>,
    },
    Issue {
        assignments: Vec<Assignment>,
    },
    Interrupt {
        assignment_id: String,
        reason: String,
    },
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub schema_version: String,
    pub case_id: String,
    pub session_id: String,
    pub request_id: String,
    pub request_sha256: String,
    pub case_revision: i64,
    pub sequence: u64,
    pub predecessor_sha256: String,
    pub occurred_at: String,
    pub content: Content,
    pub entry_sha256: String,
}
impl Entry {
    pub fn request_digest(&self) -> AppResult<String> {
        if let Content::Terminated { reason } = self.content {
            return super::terminate::TerminateRequest {
                schema_version: super::terminate::TERMINATE_SCHEMA.into(),
                request_id: self.request_id.clone(),
                case_id: self.case_id.clone(),
                session_id: self.session_id.clone(),
                expected_head_sha256: self.predecessor_sha256.clone(),
                reason,
            }
            .content_digest();
        }
        if let Content::Sealed { seal } = &self.content {
            return super::finalize::FinalizeRequest {
                schema_version: super::finalize::FINALIZE_SCHEMA.into(),
                request_id: self.request_id.clone(),
                case_id: self.case_id.clone(),
                session_id: self.session_id.clone(),
                expected_head_sha256: self.predecessor_sha256.clone(),
                expected_bundle_sha256: seal.bundle_sha256.clone(),
            }
            .content_digest();
        }
        let action = match &self.content {
            Content::Sealed { .. } | Content::Terminated { .. } => unreachable!(),
            Content::SubmitOutput {
                assignment_id,
                requested_output,
                ..
            } => Action::SubmitOutput {
                assignment_id: assignment_id.clone(),
                output: requested_output.clone(),
            },
            Content::SubmitDocuments {
                requested_documents,
                ..
            } => Action::SubmitDocuments {
                documents: requested_documents.clone(),
            },
            Content::Issue { assignments } => Action::Issue {
                assignments: assignments.iter().map(|a| a.spec.clone()).collect(),
            },
            Content::Interrupt {
                assignment_id,
                reason,
            } => Action::Interrupt {
                assignment_id: assignment_id.clone(),
                reason: reason.clone(),
            },
        };
        domain_request(&CheckpointRequest {
            schema_version: CHECKPOINT_SCHEMA.into(),
            request_id: self.request_id.clone(),
            case_id: self.case_id.clone(),
            session_id: self.session_id.clone(),
            expected_head_sha256: self.predecessor_sha256.clone(),
            action,
        })
    }
    pub fn content_digest(&self) -> AppResult<String> {
        let mut v = serde_json::to_value(self)?;
        v.as_object_mut().unwrap().remove("entry_sha256");
        domain_digest(ENTRY_SCHEMA, &v)
    }
}
#[derive(Debug, Clone, Serialize)]
pub struct AssignmentState {
    #[serde(flatten)]
    pub assignment: Assignment,
    pub state: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub closed_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output: Option<AssignmentOutput>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interruption_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replaced_by: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Budget {
    pub limit: Option<u64>,
    pub issued: u64,
    pub remaining: Option<u64>,
}
#[derive(Debug, Default, Serialize)]
pub struct Record {
    pub documents: BTreeMap<String, DocumentState>,
    #[serde(skip)]
    pub captured: u64,
    pub entries: Vec<Entry>,
    pub assignments: Vec<AssignmentState>,
    #[serde(skip)]
    pub bytes: usize,
}
pub(crate) struct RecordRequest<'a> {
    pub request_id: &'a str,
    pub case_id: &'a str,
    pub session_id: &'a str,
    pub expected_head_sha256: &'a str,
    pub digest: String,
    pub sealing: bool,
    pub terminating: bool,
}
impl CheckpointRequest {
    pub(crate) fn record_request(&self) -> AppResult<RecordRequest<'_>> {
        Ok(RecordRequest {
            request_id: &self.request_id,
            case_id: &self.case_id,
            session_id: &self.session_id,
            expected_head_sha256: &self.expected_head_sha256,
            digest: domain_request(self)?,
            sealing: false,
            terminating: false,
        })
    }
}
impl Record {
    pub fn terminated(&self) -> Option<(&Entry, TerminationReason)> {
        self.entries.last().and_then(|entry| match entry.content {
            Content::Terminated { reason } => Some((entry, reason)),
            _ => None,
        })
    }
    pub fn ensure_active(&self) -> AppResult<()> {
        if self.terminated().is_some() {
            return Err(AppError::RunTerminated);
        }
        Ok(())
    }
    pub fn sealed(&self) -> Option<(&Entry, &super::finalize::Seal)> {
        self.entries.last().and_then(|e| match &e.content {
            Content::Sealed { seal } => Some((e, seal.as_ref())),
            _ => None,
        })
    }
    /// Shared preflight and transactional recheck; replay never consumes host documents.
    pub(crate) fn precheck(
        &self,
        receipt: &PreparationReceipt,
        request: &RecordRequest<'_>,
        current: impl FnOnce() -> AppResult<Option<BlockerCode>>,
    ) -> AppResult<Option<CheckpointOutcome>> {
        let saved = self
            .entries
            .iter()
            .find(|e| e.request_id == request.request_id);
        if !request.terminating {
            self.ensure_active()?;
        }
        if request.terminating {
            if let Some(entry) = saved {
                return Ok(Some(if entry.request_sha256 == request.digest {
                    CheckpointOutcome::saved(receipt, entry.clone(), self, true)
                } else {
                    CheckpointOutcome::refused(Refusal::RequestConflict)
                }));
            }
            self.ensure_active()?;
        }
        if self.sealed().is_some() {
            return Ok(Some(
                if request.sealing && saved.is_some_and(|e| e.request_sha256 == request.digest) {
                    CheckpointOutcome::saved(receipt, saved.unwrap().clone(), self, true)
                } else {
                    CheckpointOutcome::refused(Refusal::RunSealed)
                },
            ));
        }
        let digest = &request.digest;
        if saved.is_some_and(|e| *digest != e.request_sha256) {
            return Ok(Some(CheckpointOutcome::refused(Refusal::RequestConflict)));
        }
        if let Some(reason) = current()? {
            return Ok(Some(CheckpointOutcome::Rejected {
                error_code: Refusal::SavedReceiptNotCurrent,
                reason: Some(reason),
            }));
        }
        if let Some(entry) = saved {
            return Ok(Some(CheckpointOutcome::saved(
                receipt,
                entry.clone(),
                self,
                true,
            )));
        }
        if self.head(receipt).1 != request.expected_head_sha256 {
            return Ok(Some(CheckpointOutcome::refused(Refusal::StaleHead)));
        }
        Ok(
            record_limits(self.entries.len(), 0, self.bytes, request.terminating)
                .err()
                .map(CheckpointOutcome::refused),
        )
    }
    pub fn head<'a>(&'a self, receipt: &'a PreparationReceipt) -> (u64, &'a str) {
        self.entries
            .last()
            .map_or((0, &receipt.receipt_sha256), |e| {
                (e.sequence, &e.entry_sha256)
            })
    }
    pub fn budget(&self, limit: Option<u64>) -> Budget {
        let issued = self.assignments.len() as u64;
        Budget {
            limit,
            issued,
            remaining: limit.map(|b| b.saturating_sub(issued)),
        }
    }
    pub fn counts_by_state(&self) -> BTreeMap<&str, usize> {
        ["open", "closed", "interrupted", "discarded"]
            .into_iter()
            .map(|state| {
                (
                    state,
                    self.assignments.iter().filter(|a| a.state == state).count(),
                )
            })
            .collect()
    }
    pub fn counts(&self) -> BTreeMap<String, usize> {
        let mut counts = BTreeMap::new();
        for role in [
            Role::ReconnaissanceBaseline,
            Role::ReconnaissanceFocused,
            Role::Hunter,
            Role::PostWaveCritic,
            Role::FinalCleanCritic,
            Role::CandidateVerifier,
            Role::FinalVerifier,
        ] {
            counts.insert(
                serde_json::to_value(role).unwrap().as_str().unwrap().into(),
                self.assignments
                    .iter()
                    .filter(|a| a.assignment.spec.role == role)
                    .count(),
            );
        }
        counts
    }
    /// One state derivation for all readers and writers; capture can add its closure here.
    pub fn push(
        &mut self,
        receipt: &PreparationReceipt,
        entry: Entry,
        bytes: usize,
    ) -> AppResult<()> {
        let bad = || AppError::Storage("audit record chain invalid".into());
        let (sequence, head) = self.head(receipt);
        if self.sealed().is_some()
            || self.ensure_active().is_err()
            || entry.schema_version != ENTRY_SCHEMA
            || entry.case_id != receipt.case_id
            || Some(entry.session_id.as_str()) != receipt.session_id()
            || entry.sequence != sequence + 1
            || entry.predecessor_sha256 != head
            || entry.case_revision
                <= self
                    .entries
                    .last()
                    .map_or(receipt.case_revision, |e| e.case_revision)
            || !valid_id(&entry.request_id)
            || !valid_hash(&entry.request_sha256)
            || chrono::DateTime::parse_from_rfc3339(&entry.occurred_at).is_err()
            || entry.content_digest()? != entry.entry_sha256
            || entry.request_digest()? != entry.request_sha256
            || self
                .entries
                .iter()
                .any(|e| e.request_id == entry.request_id)
            || record_limits(
                self.entries.len(),
                bytes,
                self.bytes,
                matches!(entry.content, Content::Terminated { .. }),
            )
            .is_err()
        {
            return Err(bad());
        }
        match &entry.content {
            Content::Terminated { .. } => {}
            Content::Sealed { seal } => {
                seal.verify()?;
                if seal.projection["record_head_sha256"] != entry.predecessor_sha256 {
                    return Err(bad());
                }
            }
            Content::SubmitOutput {
                assignment_id,
                requested_output,
                output,
            } => self.push_output(assignment_id, requested_output, output, &entry.occurred_at)?,
            Content::SubmitDocuments {
                requested_documents,
                documents,
            } => self.push_documents(
                requested_documents,
                documents,
                &entry.occurred_at,
                match &receipt.result {
                    PreparationResult::Prepared { facts, .. } => &facts.validator_resources_sha256,
                    _ => return Err(bad()),
                },
            )?,
            Content::Issue { assignments } => {
                if assignments.is_empty()
                    || assignments.len() > 64
                    || self.assignments.len() + assignments.len() > 2000
                {
                    return Err(bad());
                }
                let mut ids: BTreeSet<_> = self
                    .assignments
                    .iter()
                    .map(|a| a.assignment.assignment_id.clone())
                    .collect();
                for a in assignments {
                    let final_role = a.spec.role == Role::FinalVerifier;
                    if final_role != a.findings_revision.is_some()
                        || final_role != a.bound_record_sha256.is_some()
                        || a.bound_record_sha256
                            .as_ref()
                            .is_some_and(|h| !valid_hash(h))
                        || (final_role
                            && self
                                .documents
                                .get("findings.json")
                                .map(|d| d.current.revision)
                                != a.findings_revision)
                        || !valid_id(&a.assignment_id)
                        || !ids.insert(a.assignment_id.clone())
                        || a.ordinal != self.assignments.len() as u64 + 1
                        || a.agent_id != format!("a{:04}-{}", a.ordinal, a.spec.role.word())
                        || a.issued_at != entry.occurred_at
                    {
                        return Err(bad());
                    }
                    if let Some(id) = &a.spec.replaces {
                        let old = self
                            .assignments
                            .iter_mut()
                            .find(|s| s.assignment.assignment_id == *id)
                            .ok_or_else(bad)?;
                        if !matches!(old.state, "interrupted" | "discarded")
                            || old.replaced_by.is_some()
                            || old.assignment.spec.role != a.spec.role
                            || old.assignment.spec.wave != a.spec.wave
                            || old.assignment.spec.fingerprint != a.spec.fingerprint
                        {
                            return Err(bad());
                        }
                        old.replaced_by = Some(a.assignment_id.clone());
                    }
                    self.assignments.push(AssignmentState {
                        assignment: a.clone(),
                        state: "open",
                        closed_at: None,
                        output: None,
                        interruption_reason: None,
                        replaced_by: None,
                    });
                }
            }
            Content::Interrupt {
                assignment_id,
                reason,
            } => {
                let a = self
                    .assignments
                    .iter_mut()
                    .find(|a| a.assignment.assignment_id == *assignment_id)
                    .ok_or_else(bad)?;
                if a.state != "open" {
                    return Err(bad());
                }
                a.state = "interrupted";
                a.closed_at = Some(entry.occurred_at.clone());
                a.interruption_reason = Some(reason.clone());
            }
        }
        self.bytes += bytes;
        self.entries.push(entry);
        Ok(())
    }
}
pub fn domain_request(request: &CheckpointRequest) -> AppResult<String> {
    domain_digest(CHECKPOINT_SCHEMA, request)
}
#[derive(Debug, Serialize)]
pub struct Head {
    pub sequence: u64,
    pub entry_sha256: String,
}
#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum CheckpointOutcome {
    Interrupted,
    DocumentRejected {
        error_code: Refusal,
        document: String,
        validation: Option<super::super::DocumentValidation>,
    },
    Saved {
        entry: Box<Entry>,
        head: Head,
        replayed: bool,
        budget: Budget,
        captured_bytes: serde_json::Value,
        assignment: Option<Box<AssignmentState>>,
        receipt: Box<PreparationReceipt>,
        outcome_run: Option<serde_json::Value>,
    },
    Rejected {
        error_code: Refusal,
        reason: Option<BlockerCode>,
    },
}
impl CheckpointOutcome {
    pub fn refused(error_code: Refusal) -> Self {
        Self::Rejected {
            error_code,
            reason: None,
        }
    }
    pub(crate) fn saved(
        receipt: &PreparationReceipt,
        entry: Entry,
        record: &Record,
        replayed: bool,
    ) -> Self {
        let limit = match &receipt.result {
            PreparationResult::Prepared { facts, .. } => facts.invocation_budget,
            _ => None,
        };
        let (sequence, hash) = record.head(receipt);
        let assignment = match &entry.content {
            Content::SubmitOutput { assignment_id, .. }
            | Content::Interrupt { assignment_id, .. } => record
                .assignments
                .iter()
                .find(|a| a.assignment.assignment_id == *assignment_id)
                .cloned()
                .map(Box::new),
            _ => None,
        };
        Self::Saved {
            assignment,
            head: Head {
                sequence,
                entry_sha256: hash.into(),
            },
            entry: Box::new(entry),
            replayed,
            budget: record.budget(limit),
            captured_bytes: record.captured_bytes(),
            receipt: Box::new(receipt.clone()),
            outcome_run: None,
        }
    }
}
pub(crate) fn entry_limits(count: usize, bytes: usize, total: usize) -> Result<(), Refusal> {
    if count >= 4096 {
        Err(Refusal::RecordEntryLimit)
    } else if bytes > MAX_ENTRY {
        Err(Refusal::EntryBytesLimit)
    } else if bytes.saturating_add(total) > MAX_RECORD {
        Err(Refusal::RecordBytesLimit)
    } else {
        Ok(())
    }
}

pub(crate) fn record_limits(
    count: usize,
    bytes: usize,
    total: usize,
    terminal: bool,
) -> Result<(), Refusal> {
    if terminal {
        if count > 4096 {
            return Err(Refusal::RecordEntryLimit);
        }
        if bytes > MAX_TERMINAL_ENTRY {
            return Err(Refusal::EntryBytesLimit);
        }
        if total > MAX_RECORD {
            return Err(Refusal::RecordBytesLimit);
        }
        Ok(())
    } else {
        entry_limits(count, bytes, total)
    }
}

#[cfg(test)]
mod tests;
