//! Audit preparation commits exclusively to the existing case event log.
use super::*;
use crate::cloudflare_provider::audit::record::*;
use crate::cloudflare_provider::audit::{PreparationReceipt, PreparationResult, RECEIPT_EVENT};
use crate::cloudflare_provider::source_view::canonical_bytes;

// Inspect SQLite's borrowed value before copying or decoding committed JSON.
fn bounded_payload(row: &rusqlite::Row<'_>, index: usize) -> rusqlite::Result<String> {
    let bytes = row.get_ref(index)?.as_str()?;
    if bytes.len() > MAX_ENTRY {
        return Err(rusqlite::Error::FromSqlConversionFailure(
            index,
            rusqlite::types::Type::Text,
            "audit payload exceeds byte bound".into(),
        ));
    }
    Ok(bytes.to_owned())
}

/// Receipt and complete history observed together, with a boundary for publication.
pub struct CapturedSnapshot {
    pub receipt: PreparationReceipt,
    pub record: Record,
    revision: i64,
    data_version: i64,
}
impl CapturedSnapshot {
    pub fn recheck(&self, storage: &Storage) -> AppResult<()> {
        let connection = storage.connection()?;
        let version: i64 = connection.pragma_query_value(None, "data_version", |r| r.get(0))?;
        let revision: Option<i64> = connection
            .query_row(
                "SELECT revision FROM cases WHERE id=?1",
                [&self.receipt.case_id],
                |r| r.get(0),
            )
            .optional()?;
        if version != self.data_version || revision != Some(self.revision) {
            return Err(AppError::Conflict(
                "captured history changed during retrieval".into(),
            ));
        }
        Ok(())
    }
}

fn read(
    connection: &Connection,
    case_id: &str,
    id: &str,
    by_session: bool,
) -> AppResult<Option<PreparationReceipt>> {
    let mut statement = connection.prepare("SELECT occurred_at,payload_json FROM case_events WHERE case_id=?1 AND event_type=?2 ORDER BY sequence")?;
    let rows = statement.query_map(params![case_id, RECEIPT_EVENT], |row| {
        Ok((row.get::<_, String>(0)?, bounded_payload(row, 1)?))
    })?;
    let mut found = None;
    for row in rows {
        let (time, bytes) = row?;
        if bytes.len() > 1024 * 1024 {
            return Err(AppError::Storage("oversized audit receipt".into()));
        }
        let receipt: PreparationReceipt = serde_json::from_str(&bytes)?;
        receipt.verify()?;
        if receipt.case_id != case_id || receipt.occurred_at != time {
            return Err(AppError::Storage("audit event identity mismatch".into()));
        }
        if if by_session {
            receipt.session_id() == Some(id)
        } else {
            receipt.request_id == id
        } {
            if found.is_some() {
                return Err(AppError::Storage("duplicate audit receipt".into()));
            }
            found = Some(receipt);
        }
    }
    Ok(found)
}
fn record(connection: &Connection, receipt: &PreparationReceipt) -> AppResult<Record> {
    let mut runs = std::collections::BTreeMap::<String, (PreparationReceipt, Record)>::new();
    let mut statement = connection.prepare("SELECT occurred_at,payload_json FROM case_events WHERE case_id=?1 AND event_type=?2 ORDER BY sequence")?;
    let rows = statement.query_map(params![receipt.case_id, RECORD_EVENT], |row| {
        Ok((row.get::<_, String>(0)?, bounded_payload(row, 1)?))
    })?;
    for row in rows {
        let (time, bytes) = row?;
        if bytes.len() > MAX_ENTRY {
            return Err(AppError::Storage("oversized audit entry".into()));
        }
        let entry: Entry = serde_json::from_str(&bytes)?;
        if entry.case_id != receipt.case_id
            || entry.occurred_at != time
            || entry.content_digest()? != entry.entry_sha256
        {
            return Err(AppError::Storage(
                "audit entry identity/digest mismatch".into(),
            ));
        }
        if !runs.contains_key(&entry.session_id) {
            let parent = read(connection, &receipt.case_id, &entry.session_id, true)?
                .ok_or_else(|| AppError::Storage("audit entry has no preparation".into()))?;
            runs.insert(entry.session_id.clone(), (parent, Record::default()));
        }
        let (parent, chain) = runs.get_mut(&entry.session_id).unwrap();
        chain.push(parent, entry, bytes.len())?;
    }
    Ok(runs
        .remove(receipt.session_id().unwrap_or_default())
        .map(|(_, r)| r)
        .unwrap_or_default())
}
// The recovery reader bounds the selected history before deserializing each entry.
fn captured_record(connection: &Connection, receipt: &PreparationReceipt) -> AppResult<Record> {
    let mut statement = connection.prepare("SELECT occurred_at,payload_json FROM case_events WHERE case_id=?1 AND event_type=?2 ORDER BY sequence")?;
    let mut rows = statement.query(params![receipt.case_id, RECORD_EVENT])?;
    let mut record = Record::default();
    while let Some(row) = rows.next()? {
        let bytes = row.get_ref(1)?.as_str().map_err(rusqlite::Error::from)?;
        if bytes.len() > MAX_ENTRY {
            return Err(AppError::Storage(
                "captured entry exceeds byte bound".into(),
            ));
        }
        #[derive(serde::Deserialize)]
        struct Binding<'a> {
            session_id: &'a str,
        }
        let binding: Binding<'_> = serde_json::from_str(bytes)?;
        if Some(binding.session_id) != receipt.session_id() {
            continue;
        }
        let entry: Entry = serde_json::from_str(bytes)?;
        if entry.occurred_at != row.get_ref(0)?.as_str().map_err(rusqlite::Error::from)? {
            return Err(AppError::Storage("audit event time mismatch".into()));
        }
        record.push(receipt, entry, bytes.len())?;
    }
    Ok(record)
}

impl Storage {
    pub fn cloudflare_captured_snapshot(
        &self,
        case_id: &str,
        session_id: &str,
    ) -> AppResult<CapturedSnapshot> {
        let mut connection = self.connection()?;
        connection.busy_timeout(std::time::Duration::ZERO)?;
        let transaction = connection.transaction()?;
        let data_version = transaction.pragma_query_value(None, "data_version", |r| r.get(0))?;
        let revision = transaction
            .query_row("SELECT revision FROM cases WHERE id=?1", [case_id], |r| {
                r.get(0)
            })
            .optional()?
            .ok_or_else(|| AppError::CaseNotFound(case_id.into()))?;
        let receipt = read(&transaction, case_id, session_id, true)?
            .ok_or_else(|| AppError::InvalidRequest("unknown audit preparation".into()))?;
        let record = captured_record(&transaction, &receipt)?;
        transaction.commit()?;
        Ok(CapturedSnapshot {
            receipt,
            record,
            revision,
            data_version,
        })
    }
    pub fn cloudflare_audit_receipt(
        &self,
        case_id: &str,
        id: &str,
        by_session: bool,
    ) -> AppResult<Option<PreparationReceipt>> {
        let connection = self.connection()?;
        let receipt = read(&connection, case_id, id, by_session)?;
        if let Some(receipt) = &receipt {
            record(&connection, receipt)?;
        }
        Ok(receipt)
    }
    pub fn cloudflare_audit_record(&self, receipt: &PreparationReceipt) -> AppResult<Record> {
        receipt.verify()?;
        record(&*self.connection()?, receipt)
    }
    pub(crate) fn append_cloudflare_record(
        &self,
        request: &RecordRequest<'_>,
        revision: i64,
        cancelled: Option<&std::sync::atomic::AtomicU8>,
        authorize: impl Fn() -> AppResult<Option<crate::cloudflare_provider::audit::BlockerCode>>,
        mint: impl FnOnce(&Record) -> Result<Content, Refusal>,
        now: impl FnOnce() -> String,
    ) -> AppResult<CheckpointOutcome> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if cancelled.is_some_and(|s| s.load(std::sync::atomic::Ordering::Acquire) != 0) {
            return Ok(CheckpointOutcome::Interrupted);
        }
        let Some(receipt) = read(&transaction, request.case_id, request.session_id, true)? else {
            let code = if read(&transaction, request.case_id, request.session_id, false)?
                .is_some_and(|r| r.session_id().is_none())
            {
                Refusal::BlockedPreparation
            } else {
                Refusal::UnknownPreparation
            };
            return Ok(CheckpointOutcome::refused(code));
        };
        let mut record = record(&transaction, &receipt)?;
        let current: i64 = transaction.query_row(
            "SELECT revision FROM cases WHERE id=?1",
            [request.case_id],
            |r| r.get(0),
        )?;
        if current != revision {
            return Err(AppError::Conflict("case changed during checkpoint".into()));
        }
        if let Some(outcome) = record.precheck(&receipt, request, &authorize)? {
            return Ok(outcome);
        }
        let digest = request.digest.clone();
        let (sequence, head) = record.head(&receipt);
        let content = match mint(&record) {
            Ok(c) => c,
            Err(code) => return Ok(CheckpointOutcome::refused(code)),
        };
        let mut entry = Entry {
            schema_version: ENTRY_SCHEMA.into(),
            case_id: request.case_id.into(),
            session_id: request.session_id.into(),
            request_id: request.request_id.into(),
            request_sha256: digest,
            case_revision: revision
                .checked_add(1)
                .ok_or_else(|| AppError::Storage("case revision overflow".into()))?,
            sequence: sequence + 1,
            predecessor_sha256: head.into(),
            occurred_at: now(),
            content,
            entry_sha256: String::new(),
        };
        if let Content::Issue { assignments } = &mut entry.content {
            for a in assignments {
                a.issued_at = entry.occurred_at.clone();
            }
        }
        entry.entry_sha256 = entry.content_digest()?;
        let bytes = canonical_bytes(&entry)?;
        if let Err(code) = record_limits(
            record.entries.len(),
            bytes.len(),
            record.bytes,
            request.terminating,
        ) {
            return Ok(CheckpointOutcome::refused(code));
        }
        record.push(&receipt, entry.clone(), bytes.len())?;
        if let Some(reason) = authorize()? {
            return Ok(CheckpointOutcome::Rejected {
                error_code: Refusal::SavedReceiptNotCurrent,
                reason: Some(reason),
            });
        }
        transaction.execute(
            "UPDATE cases SET revision=?2 WHERE id=?1 AND revision=?3",
            params![request.case_id, entry.case_revision, revision],
        )?;
        transaction.execute("INSERT INTO case_events(case_id,event_type,occurred_at,payload_json) VALUES (?1,?2,?3,?4)",
            params![request.case_id, RECORD_EVENT, entry.occurred_at, std::str::from_utf8(&bytes).map_err(|e| AppError::Storage(e.to_string()))?])?;
        if request.terminating {
            write_outcome(&transaction, &receipt, &record)?;
        }
        transaction.commit()?;
        Ok(CheckpointOutcome::saved(&receipt, entry, &record, false))
    }
    /// Finalize under the writer transaction: authorization precedes identity minting.
    pub(crate) fn record_cloudflare_audit_receipt(
        &self,
        mut receipt: PreparationReceipt,
        finalize: impl FnOnce() -> AppResult<PreparationResult>,
    ) -> AppResult<PreparationReceipt> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if read(&transaction, &receipt.case_id, &receipt.request_id, false)?.is_some() {
            return Err(AppError::Conflict(
                "audit receipt appeared during evaluation; retry".into(),
            ));
        }
        let revision: i64 = transaction.query_row(
            "SELECT revision FROM cases WHERE id=?1",
            [&receipt.case_id],
            |row| row.get(0),
        )?;
        if revision != receipt.case_revision {
            return Err(AppError::Conflict(
                "case changed during audit preparation".into(),
            ));
        }
        receipt.case_revision = revision
            .checked_add(1)
            .ok_or_else(|| AppError::Storage("case revision overflow".into()))?;
        transaction.execute(
            "UPDATE cases SET revision=?2 WHERE id=?1 AND revision=?3",
            params![receipt.case_id, receipt.case_revision, revision],
        )?;
        receipt.result = finalize()?;
        receipt.receipt_sha256 = receipt.content_digest()?;
        receipt.verify()?;
        let bytes = canonical_bytes(&receipt)?;
        if bytes.len() > 1024 * 1024 {
            return Err(AppError::Storage("audit receipt exceeds 1 MiB".into()));
        }
        let bytes = std::str::from_utf8(&bytes).map_err(|e| AppError::Storage(e.to_string()))?;
        transaction.execute("INSERT INTO case_events(case_id,event_type,occurred_at,payload_json) VALUES (?1,?2,?3,?4)", params![receipt.case_id,RECEIPT_EVENT,receipt.occurred_at,bytes])?;
        if matches!(receipt.result, PreparationResult::Blocked { .. }) {
            write_outcome(&transaction, &receipt, &Record::default())?;
        }
        transaction.commit()?;
        Ok(receipt)
    }
}

fn write_outcome(
    connection: &Connection,
    receipt: &PreparationReceipt,
    record: &Record,
) -> AppResult<()> {
    use crate::agent_audit_failure as failure;
    let document: String = connection.query_row(
        "SELECT document_json FROM cases WHERE id=?1",
        [&receipt.case_id],
        |r| r.get(0),
    )?;
    let mut case: AssessmentCase = serde_json::from_str(&document)?;
    crate::agent_audit_admission::check_format(&case)?;
    let run = failure::plan(&case, receipt, record)?
        .ok_or_else(|| AppError::Storage("missing terminal outcome".into()))?;
    if case
        .scan_runs
        .iter()
        .any(|r| r.id == run.id || r.engine_runs.iter().any(|t| t.id == run.engine_runs[0].id))
    {
        return Err(AppError::Conflict("audit outcome identity conflict".into()));
    }
    let payload = failure::event(&run)?;
    let time = run.completed_at.unwrap().to_rfc3339();
    case.scan_runs.push(run);
    case.format_requirements
        .insert(failure::FORMAT_REQUIREMENT.into());
    crate::agent_audit_admission::check_write(&case)?;
    connection.execute(
        "INSERT INTO case_events(case_id,event_type,occurred_at,payload_json) VALUES (?1,?2,?3,?4)",
        params![
            case.id,
            failure::EVENT,
            time,
            serde_json::to_string(&payload)?
        ],
    )?;
    failure::check_custody(&case, &read_case_events(connection, &case.id)?)?;
    let changed = connection.execute(
        "UPDATE cases SET document_json=?2 WHERE id=?1",
        params![case.id, serde_json::to_string(&case)?],
    )?;
    if changed != 1 {
        return Err(AppError::Conflict(
            "case changed while recording audit outcome".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cloudflare_provider::audit::{Blocker, BlockerCode, RECEIPT_SCHEMA};
    use crate::domain::OrganizationProfile;
    #[test]
    fn cloudflare_audit_commit_conflict_revision_and_digest() {
        let temp = tempfile::tempdir().unwrap();
        let storage = Storage::open(temp.path().join("casework.db")).unwrap();
        let mut case = AssessmentCase::new(
            "Audit".into(),
            OrganizationProfile {
                organization_name: "Example".into(),
                employee_range: "1-10".into(),
                data_classes: vec![],
                notes: None,
            },
        );
        storage.save_case(&mut case, "fixture").unwrap();
        let request = serde_json::from_value::<crate::cloudflare_provider::audit::PrepareRequest>(
            serde_json::json!({
                "schema_version": crate::cloudflare_provider::audit::REQUEST_SCHEMA,
                "request_id": "request", "case_id": case.id, "asset_id": "asset",
                "source_view_request_id": "view", "expected_source_view_receipt_sha256": "a".repeat(64),
                "profile": "quick", "invocation_budget": null,
                "host": {"host_id": "host", "delegation": "available"},
                "run_directory": temp.path()
            }),
        ).unwrap();
        let blocked = || {
            Ok(PreparationResult::Blocked {
                request: Box::new(request.clone()),
                blockers: vec![Blocker::new(
                    BlockerCode::SourceAuthorizationExpired,
                    "commit",
                )],
            })
        };
        let receipt = PreparationReceipt {
            schema_version: RECEIPT_SCHEMA.into(),
            request_id: "request".into(),
            request_sha256: request.content_digest().unwrap(),
            case_id: case.id.clone(),
            asset_id: "asset".into(),
            occurred_at: Utc::now().to_rfc3339(),
            case_revision: case.storage_revision,
            sequence: 0,
            predecessor_sha256: None,
            result: blocked().unwrap(),
            receipt_sha256: String::new(),
        };
        let observer = Connection::open(storage.path()).unwrap();
        observer.busy_timeout(std::time::Duration::ZERO).unwrap();
        let saved = storage
            .record_cloudflare_audit_receipt(receipt.clone(), || {
                assert_eq!(
                    observer
                        .execute_batch("BEGIN IMMEDIATE")
                        .unwrap_err()
                        .sqlite_error_code(),
                    Some(rusqlite::ErrorCode::DatabaseBusy)
                );
                blocked()
            })
            .unwrap();
        assert!(saved.session_id().is_none());
        assert_eq!(saved.case_revision, receipt.case_revision + 1);
        assert_eq!(
            storage
                .cloudflare_audit_receipt(&case.id, "request", false)
                .unwrap()
                .unwrap()
                .receipt_sha256,
            saved.receipt_sha256
        );
        assert!(matches!(
            storage.record_cloudflare_audit_receipt(receipt.clone(), || panic!(
                "no finalization on conflict"
            )),
            Err(AppError::Conflict(_))
        ));
        let mut stale = receipt;
        stale.request_id = "different".into();
        assert!(matches!(
            storage.record_cloudflare_audit_receipt(stale, blocked),
            Err(AppError::Conflict(_))
        ));
        // Even a recomputed receipt digest cannot hide a mismatched embedded request.
        for field in ["request_id", "case_id", "asset_id", "profile"] {
            let mut tampered = serde_json::to_value(&saved).unwrap();
            tampered["result"]["request"][field] = serde_json::json!(if field == "profile" {
                "deep"
            } else {
                "different"
            });
            let mut tampered: PreparationReceipt = serde_json::from_value(tampered).unwrap();
            if field != "profile" {
                let PreparationResult::Blocked { request, .. } = &tampered.result else {
                    unreachable!()
                };
                tampered.request_sha256 = request.content_digest().unwrap();
            }
            tampered.receipt_sha256 = tampered.content_digest().unwrap();
            assert!(tampered.verify().is_err(), "{field}");
        }
        let connection = storage.connection().unwrap();
        connection.execute("UPDATE case_events SET payload_json=replace(payload_json,'source_authorization_expired','grant_changed') WHERE event_type=?1", [RECEIPT_EVENT]).unwrap();
        drop(connection);
        assert!(
            storage
                .cloudflare_audit_receipt(&case.id, "request", false)
                .is_err()
        );
    }
}
