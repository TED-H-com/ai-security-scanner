//! Source preparation uses the existing transactional event log, with no schema migration.
use super::*;
use crate::cloudflare_provider::source_view::{
    Blocker, BlockerCode, PreparationResult, RECEIPT_EVENT, RECEIPT_SCHEMA,
    SourceViewPreparationReceipt,
};

pub(crate) fn validate_receipt(
    receipt: &SourceViewPreparationReceipt,
    case_id: &str,
    sequence: i64,
    time: &str,
) -> AppResult<()> {
    if receipt.schema_version != RECEIPT_SCHEMA
        || receipt.case_id != case_id
        || receipt.event_sequence != sequence
        || receipt.occurred_at != time
        || receipt.case_revision < 1
        || receipt.content_digest()? != receipt.digest
        || crate::cloudflare_provider::source_view::domain_digest(
            "ai-security-scanner.model-processing-acknowledgement/v1",
            &receipt.acknowledgement,
        )? != receipt.acknowledgement_sha256
        || receipt
            .grant
            .as_ref()
            .map(|grant| {
                crate::cloudflare_provider::source_view::domain_digest(
                    "ai-security-scanner.source-view-grant/v1",
                    grant,
                )
            })
            .transpose()?
            != receipt.grant_sha256
        || receipt.acknowledgement.case_id != receipt.case_id
        || receipt.acknowledgement.asset_id != receipt.asset_id
        || receipt.acknowledgement.host_identity_verified
        || !receipt.acknowledgement.acknowledged
        || receipt.analysis_performed
    {
        return Err(AppError::Storage(
            "source-view receipt identity/digest mismatch".into(),
        ));
    }
    Ok(())
}

fn read(
    connection: &Connection,
    case_id: &str,
    request_id: &str,
) -> AppResult<Option<SourceViewPreparationReceipt>> {
    let mut statement = connection.prepare("SELECT sequence, occurred_at, payload_json FROM case_events WHERE case_id=?1 AND event_type=?2 ORDER BY sequence")?;
    let rows = statement.query_map(params![case_id, RECEIPT_EVENT], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
        ))
    })?;
    let mut found = None;
    for row in rows {
        let (sequence, time, bytes) = row?;
        if bytes.len() > 1024 * 1024 {
            return Err(AppError::Storage("oversized source-view receipt".into()));
        }
        let receipt: SourceViewPreparationReceipt = serde_json::from_str(&bytes)?;
        validate_receipt(&receipt, case_id, sequence, &time)?;
        if receipt.request_id == request_id {
            if found.is_some() {
                return Err(AppError::Storage("duplicate source-view receipt".into()));
            }
            found = Some(receipt);
        }
    }
    Ok(found)
}
impl Storage {
    pub fn source_view_receipt(
        &self,
        case_id: &str,
        request_id: &str,
    ) -> AppResult<Option<SourceViewPreparationReceipt>> {
        read(&*self.connection()?, case_id, request_id)
    }
    pub(crate) fn record_source_view_receipt(
        &self,
        mut receipt: SourceViewPreparationReceipt,
        authorized: &dyn Fn() -> bool,
    ) -> AppResult<SourceViewPreparationReceipt> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if read(&transaction, &receipt.case_id, &receipt.request_id)?.is_some() {
            return Err(AppError::Conflict(
                "source-view receipt appeared during evaluation; retry".into(),
            ));
        }
        let revision: i64 = transaction.query_row(
            "SELECT revision FROM cases WHERE id=?1",
            [&receipt.case_id],
            |row| row.get(0),
        )?;
        if revision != receipt.case_revision {
            return Err(AppError::Conflict(
                "case changed during source-view preparation".into(),
            ));
        }
        receipt.case_revision = revision
            .checked_add(1)
            .ok_or_else(|| AppError::Storage("case revision overflow".into()))?;
        transaction.execute(
            "UPDATE cases SET revision=?2 WHERE id=?1 AND revision=?3",
            params![receipt.case_id, receipt.case_revision, revision],
        )?;
        // Last authorization check before encoding and inserting the terminal receipt.
        if matches!(receipt.result, PreparationResult::Ready { .. }) && !authorized() {
            receipt.result = PreparationResult::Blocked {
                blockers: vec![Blocker::new(
                    BlockerCode::SourceAuthorizationExpired,
                    "commit",
                )],
            };
        }
        receipt.digest = receipt.content_digest()?;
        let bytes = serde_json::to_string(&receipt)?;
        if bytes.len() > 1024 * 1024 {
            return Err(AppError::Storage(
                "source-view receipt exceeds 1 MiB".into(),
            ));
        }
        transaction.execute("INSERT INTO case_events(case_id,event_type,occurred_at,payload_json) VALUES (?1,?2,?3,?4)",params![receipt.case_id,RECEIPT_EVENT,receipt.occurred_at,bytes])?;
        receipt.event_sequence = transaction.last_insert_rowid();
        transaction.execute(
            "UPDATE case_events SET payload_json=?2 WHERE sequence=?1",
            params![receipt.event_sequence, serde_json::to_string(&receipt)?],
        )?;
        transaction.commit()?;
        Ok(receipt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cloudflare_provider::source_view::{ModelProcessingAcknowledgement, domain_digest};
    use crate::domain::OrganizationProfile;

    fn fixture() -> (tempfile::TempDir, Storage, SourceViewPreparationReceipt) {
        let temp = tempfile::tempdir().unwrap();
        let storage = Storage::open(temp.path().join("casework.db")).unwrap();
        let mut case = AssessmentCase::new(
            "Source receipt".into(),
            OrganizationProfile {
                organization_name: "Example".into(),
                employee_range: "1-10".into(),
                data_classes: vec![],
                notes: None,
            },
        );
        storage.save_case(&mut case, "fixture.created").unwrap();
        let now = Utc::now().to_rfc3339();
        let acknowledgement = ModelProcessingAcknowledgement {
            schema_version: "ai-security-scanner.model-processing-acknowledgement/v1".into(),
            case_id: case.id.clone(),
            asset_id: "asset".into(),
            canonical_snapshot_sha256: "a".repeat(64),
            scope: vec![".".into()],
            policy_id: "ai-source-view-v1".into(),
            declared_host_id: "test".into(),
            host_identity_verified: false,
            confirmed_by: "owner".into(),
            confirmed_at: now.clone(),
            acknowledged: true,
        };
        let receipt = SourceViewPreparationReceipt {
            schema_version: RECEIPT_SCHEMA.into(),
            case_id: case.id,
            asset_id: "asset".into(),
            source_id: Some("source".into()),
            request_id: "request".into(),
            request_sha256: "b".repeat(64),
            case_revision: case.storage_revision,
            event_sequence: 0,
            occurred_at: now,
            acknowledgement_sha256: domain_digest(
                "ai-security-scanner.model-processing-acknowledgement/v1",
                &acknowledgement,
            )
            .unwrap(),
            acknowledgement,
            grant: None,
            grant_sha256: None,
            analysis_performed: false,
            result: PreparationResult::Ready {
                view_id: "view".into(),
                manifest_sha256: "c".repeat(64),
                manifest_byte_length: 1,
                view_sha256: "d".repeat(64),
                relative_path: "view".into(),
            },
            digest: String::new(),
        };
        (temp, storage, receipt)
    }

    #[test]
    fn receipt_appearing_during_evaluation_conflicts_even_with_identical_inputs() {
        let (_temp, storage, receipt) = fixture();
        let saved = storage
            .record_source_view_receipt(receipt.clone(), &|| true)
            .unwrap();
        let before = storage.list_case_events(&saved.case_id).unwrap().len();
        for changed in [false, true] {
            let mut competing = receipt.clone();
            if changed {
                competing.request_sha256 = "e".repeat(64);
            }
            assert!(matches!(
                storage.record_source_view_receipt(competing, &|| panic!(
                    "conflict must precede authorization"
                )),
                Err(AppError::Conflict(_))
            ));
        }
        assert_eq!(
            storage.list_case_events(&saved.case_id).unwrap().len(),
            before
        );
        assert_eq!(
            storage
                .source_view_receipt(&saved.case_id, &saved.request_id)
                .unwrap()
                .unwrap()
                .digest,
            saved.digest
        );
    }

    #[test]
    fn final_authorization_runs_under_immediate_transaction_and_records_blocked() {
        let (_temp, storage, receipt) = fixture();
        let observer = Connection::open(storage.path()).unwrap();
        observer.busy_timeout(std::time::Duration::ZERO).unwrap();
        let called = std::cell::Cell::new(false);
        let saved = storage
            .record_source_view_receipt(receipt, &|| {
                // The other writer cannot acquire a transaction at this final check.
                let error = observer.execute_batch("BEGIN IMMEDIATE").unwrap_err();
                assert_eq!(
                    error.sqlite_error_code(),
                    Some(rusqlite::ErrorCode::DatabaseBusy)
                );
                called.set(true);
                false
            })
            .unwrap();
        assert!(called.get());
        let PreparationResult::Blocked { blockers } = &saved.result else {
            panic!("ready after expiry")
        };
        assert_eq!(blockers[0].code, BlockerCode::SourceAuthorizationExpired);
        assert_eq!(blockers[0].stage, "commit");
        assert_eq!(
            storage
                .source_view_receipt(&saved.case_id, &saved.request_id)
                .unwrap()
                .unwrap()
                .digest,
            saved.digest
        );
    }
}
