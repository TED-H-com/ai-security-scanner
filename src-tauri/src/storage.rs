mod cloudflare_audit;
pub(crate) mod source_view;
use crate::domain::{AssessmentCase, CaseSummary};
use crate::error::{AppError, AppResult};
use chrono::Utc;
use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct CaseEvent {
    pub sequence: i64,
    pub case_id: String,
    pub event_type: String,
    pub occurred_at: String,
    pub payload_json: String,
}

const SCAN_COMMAND_RECEIPT_EVENT: &str = "scan.foreground_terminal";
const SCAN_COMMAND_RECEIPT_SCHEMA: &str = "ai-security-scanner.scan-command-receipt/v1";
const MAX_SCAN_COMMAND_RECEIPT_BYTES: usize = 1024 * 1024;

/// Durable acknowledgement of one foreground operation. A receipt records
/// command completion independently of scan coverage and cleanup outcomes in
/// `payload`; its existence alone never means the target passed every check.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ScanCommandReceipt {
    pub schema_version: String,
    pub case_id: String,
    pub run_id: String,
    pub request_id: String,
    pub case_revision: i64,
    pub event_sequence: i64,
    pub occurred_at: String,
    pub payload: serde_json::Value,
    pub digest: String,
}

impl ScanCommandReceipt {
    /// Event sequence is a local history index. The digest binds the complete
    /// saved acknowledgement independently of that index, including its
    /// original workspace revision and occurrence time.
    fn content_digest(&self) -> AppResult<String> {
        let body = serde_json::json!({
            "schema_version": self.schema_version,
            "case_id": self.case_id,
            "run_id": self.run_id,
            "request_id": self.request_id,
            "case_revision": self.case_revision,
            "occurred_at": self.occurred_at,
            "payload": self.payload,
        });
        Ok(hex::encode(Sha256::digest(serde_json::to_vec(&body)?)))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactDeletionObligation {
    pub case_id: String,
    pub exact_path: String,
    pub created_at: String,
}

/// Beginner-safe notice for one case row that remains byte-for-byte preserved
/// but cannot be decoded by this application version. The raw document and
/// parser error stay local; callers receive enough stable context to keep the
/// healthy workspace usable and offer a retry/diagnostic path.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct CaseRecoveryDiagnostic {
    pub case_id: String,
    pub title: String,
    pub updated_at: String,
    pub revision: i64,
    pub document_bytes: usize,
    pub code: String,
    pub message: String,
    pub preserved: bool,
}

#[derive(Debug, Clone)]
pub struct ReadableCaseListing {
    pub cases: Vec<CaseSummary>,
    pub recovery_diagnostics: Vec<CaseRecoveryDiagnostic>,
}

/// One SQLite read snapshot for a portable archive. `document_json` preserves
/// the persisted bytes, while `case` is decoded without current triage or
/// compatibility projections. The source revision is not a restore token.
#[derive(Debug, Clone)]
pub struct StoredCaseSnapshot {
    pub case: AssessmentCase,
    pub document_json: String,
    pub events: Vec<CaseEvent>,
    pub revision: i64,
}

pub struct Storage {
    path: PathBuf,
    connection: Mutex<Connection>,
    #[cfg(test)]
    save_case_faults: Mutex<std::collections::VecDeque<SaveCaseFaultInjection>>,
}

const CONTRADICTORY_REQUEST_OUTCOME_WARNING: &str = "Ignored an invalid no-check marker because the saved run was not a completed zero-check run. Any saved checks remain visible.";

#[cfg(test)]
#[derive(Debug, Clone, Copy)]
pub(crate) enum SaveCaseFault {
    Conflict,
    Storage,
}

#[cfg(test)]
#[derive(Debug)]
struct SaveCaseFaultInjection {
    event_type: String,
    fault: SaveCaseFault,
}

impl Storage {
    /// Opens an existing case database without preparing a workspace, migrating
    /// its schema, changing permissions, or recovering interrupted work.
    ///
    /// SQLite still coordinates WAL readers through its own sidecars. On
    /// read-only media, the WAL and SHM must already exist and be readable. Do
    /// not use SQLite's `immutable` option here: a live owner's committed WAL
    /// must remain visible to status readers.
    pub fn open_read_only(path: impl AsRef<Path>) -> AppResult<Self> {
        Self::open_read_only_with_timeout(path, std::time::Duration::from_secs(5))
    }

    /// Read-only recovery must return busy immediately, without automatic retries.
    pub fn open_read_only_no_wait(path: impl AsRef<Path>) -> AppResult<Self> {
        Self::open_read_only_with_timeout(path, std::time::Duration::ZERO)
    }

    fn open_read_only_with_timeout(
        path: impl AsRef<Path>,
        timeout: std::time::Duration,
    ) -> AppResult<Self> {
        let requested_path = path.as_ref();
        let metadata = fs::symlink_metadata(requested_path).map_err(|error| {
            AppError::Storage(format!(
                "read-only inspection requires an existing case database at {}: {error}",
                requested_path.display()
            ))
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(AppError::Storage(
                "case database must be a regular non-symlink file".into(),
            ));
        }
        let parent = requested_path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let parent_metadata = fs::symlink_metadata(parent)?;
        if parent_metadata.file_type().is_symlink() || !parent_metadata.is_dir() {
            return Err(AppError::Storage(
                "case database parent must be a real directory, not a symlink".into(),
            ));
        }
        let filename = requested_path.file_name().ok_or_else(|| {
            AppError::Storage("case database path must include a filename".into())
        })?;
        let path = crate::internal_paths::canonicalize(parent)?.join(filename);
        let connection = Connection::open_with_flags(
            &path,
            OpenFlags::SQLITE_OPEN_READ_ONLY
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        connection.busy_timeout(timeout)?;
        connection.pragma_update(None, "query_only", "ON")?;
        validate_read_only_schema(&connection)?;

        Ok(Self {
            path,
            connection: Mutex::new(connection),
            #[cfg(test)]
            save_case_faults: Mutex::new(std::collections::VecDeque::new()),
        })
    }

    pub fn open(path: impl AsRef<Path>) -> AppResult<Self> {
        let requested_path = path.as_ref();
        let parent = requested_path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let explicit_private_parent = parent != Path::new(".");
        if explicit_private_parent {
            fs::create_dir_all(parent)?;
            let metadata = fs::symlink_metadata(parent)?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(AppError::Storage(
                    "case database parent must be a real directory, not a symlink".into(),
                ));
            }
            restrict_directory(parent)?;
        }
        let parent = fs::canonicalize(parent)?;
        let filename = requested_path.file_name().ok_or_else(|| {
            AppError::Storage("case database path must include a filename".into())
        })?;
        let path = parent.join(filename);
        if let Ok(metadata) = fs::symlink_metadata(&path)
            && (metadata.file_type().is_symlink() || !metadata.is_file())
        {
            return Err(AppError::Storage(
                "case database must be a regular non-symlink file".into(),
            ));
        }

        let connection = Connection::open(&path)?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        connection.pragma_update(None, "secure_delete", "ON")?;
        connection.pragma_update(None, "temp_store", "MEMORY")?;
        connection.busy_timeout(std::time::Duration::from_secs(5))?;

        let storage = Self {
            path,
            connection: Mutex::new(connection),
            #[cfg(test)]
            save_case_faults: Mutex::new(std::collections::VecDeque::new()),
        };
        storage.migrate()?;
        storage.restrict_permissions()?;
        storage.restrict_sidecar_permissions()?;
        Ok(storage)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn connection(&self) -> AppResult<MutexGuard<'_, Connection>> {
        self.connection
            .lock()
            .map_err(|_| AppError::Storage("database lock was poisoned".into()))
    }

    fn migrate(&self) -> AppResult<()> {
        let connection = self.connection()?;
        connection.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version INTEGER PRIMARY KEY,
                applied_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS cases (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                organization_name TEXT NOT NULL,
                status TEXT NOT NULL,
                is_demo INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                document_json TEXT NOT NULL,
                revision INTEGER NOT NULL DEFAULT 1
            );

            CREATE INDEX IF NOT EXISTS idx_cases_updated_at
                ON cases(updated_at DESC);

            CREATE TABLE IF NOT EXISTS case_events (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                occurred_at TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                FOREIGN KEY(case_id) REFERENCES cases(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_case_events_case_sequence
                ON case_events(case_id, sequence);

            CREATE TABLE IF NOT EXISTS app_settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS artifact_deletion_obligations (
                case_id TEXT PRIMARY KEY,
                exact_path TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            INSERT OR IGNORE INTO schema_migrations(version, applied_at)
            VALUES (1, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'));
            "#,
        )?;
        let has_revision = {
            let mut statement = connection.prepare("PRAGMA table_info(cases)")?;
            let columns = statement.query_map([], |row| row.get::<_, String>(1))?;
            let mut found = false;
            for column in columns {
                if column? == "revision" {
                    found = true;
                    break;
                }
            }
            found
        };
        if !has_revision {
            connection.execute(
                "ALTER TABLE cases ADD COLUMN revision INTEGER NOT NULL DEFAULT 1",
                [],
            )?;
        }
        connection.execute(
            r#"
            INSERT OR IGNORE INTO schema_migrations(version, applied_at)
            VALUES (2, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
            "#,
            [],
        )?;
        Ok(())
    }

    #[cfg(unix)]
    fn restrict_permissions(&self) -> AppResult<()> {
        restrict_file(&self.path)
    }

    #[cfg(not(unix))]
    fn restrict_permissions(&self) -> AppResult<()> {
        Ok(())
    }

    fn restrict_sidecar_permissions(&self) -> AppResult<()> {
        for suffix in ["-wal", "-shm"] {
            let mut sidecar = self.path.as_os_str().to_os_string();
            sidecar.push(suffix);
            let sidecar = PathBuf::from(sidecar);
            if fs::symlink_metadata(&sidecar).is_ok() {
                restrict_file(&sidecar)?;
            }
        }
        Ok(())
    }

    /// Persists a case only if the caller still owns the revision it loaded.
    /// New cases carry revision zero; every successful save advances the
    /// in-memory revision after the transaction commits.
    pub fn save_case(&self, case: &mut AssessmentCase, event_type: &str) -> AppResult<()> {
        self.save_case_event(case, event_type, None)
    }

    /// The case document and immutable admission receipt commit together.
    pub(crate) fn save_admitted_case(
        &self,
        case: &mut AssessmentCase,
        admission: &crate::agent_audit_admission::AgentAuditAdmission,
    ) -> AppResult<()> {
        self.save_case_event(
            case,
            crate::agent_audit_admission::ADMITTED_EVENT,
            Some(admission),
        )
    }

    fn save_case_event(
        &self,
        case: &mut AssessmentCase,
        event_type: &str,
        admission: Option<&crate::agent_audit_admission::AgentAuditAdmission>,
    ) -> AppResult<()> {
        #[cfg(test)]
        if let Some(fault) = self.take_save_case_fault(event_type) {
            return Err(match fault {
                SaveCaseFault::Conflict => {
                    AppError::Conflict("injected save-case revision conflict".into())
                }
                SaveCaseFault::Storage => {
                    AppError::Storage("injected save-case storage failure".into())
                }
            });
        }
        crate::agent_audit_admission::check_write(case)?;
        normalize_scan_request_outcome_invariants(case);
        if case.storage_revision < 0 {
            return Err(AppError::Storage(
                "case storage revision cannot be negative".into(),
            ));
        }
        let expected_revision = case.storage_revision;
        let next_revision = expected_revision
            .checked_add(1)
            .ok_or_else(|| AppError::Storage("case storage revision overflowed".into()))?;
        let document = serde_json::to_string(case)?;
        let status = serde_json::to_string(&case.status)?
            .trim_matches('"')
            .to_string();
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;

        // Both keys are omitted when empty, so ordinary cases skip decoding the
        // stored document on every save.
        let previous: Option<(i64, Option<String>)> = transaction
            .query_row(
                r#"SELECT revision,
                   CASE WHEN ?2 OR instr(document_json, '"agent_audit_admissions"') > 0
                        OR instr(document_json, '"format_requirements"') > 0
                   THEN document_json END FROM cases WHERE id = ?1"#,
                params![
                    case.id,
                    admission.is_some() || crate::agent_audit_failure::has_failure(case)
                ],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        if previous.as_ref().map(|(revision, _)| *revision)
            != (expected_revision != 0).then_some(expected_revision)
        {
            return Err(AppError::Conflict(format!(
                "case {} changed or was deleted after it was loaded",
                case.id
            )));
        }
        let previous = previous
            .and_then(|(_, document)| document)
            .map(|document| serde_json::from_str::<AssessmentCase>(&document))
            .transpose()?;
        if let Some(previous) = &previous {
            if admission.is_some_and(|a| {
                previous.agent_audit_admissions.iter().any(|p| {
                    p.identities.session_id == a.identities.session_id
                        || p.request_id == a.request_id
                })
            }) {
                return Err(AppError::Conflict(
                    "audit admission appeared during commit".into(),
                ));
            }
            crate::agent_audit_admission::check_update(previous, case)?;
        }
        crate::agent_audit_failure::check_existing(previous.as_ref(), case)?;
        let affected = if expected_revision == 0 {
            transaction.execute(
                r#"
                INSERT INTO cases (
                    id, title, organization_name, status, is_demo,
                    created_at, updated_at, document_json, revision
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
                ON CONFLICT(id) DO NOTHING
                "#,
                params![
                    case.id,
                    case.title,
                    case.profile.organization_name,
                    status,
                    case.is_demo,
                    case.created_at.to_rfc3339(),
                    case.updated_at.to_rfc3339(),
                    document,
                    next_revision,
                ],
            )?
        } else {
            transaction.execute(
                r#"
                UPDATE cases
                SET title = ?2,
                    organization_name = ?3,
                    status = ?4,
                    is_demo = ?5,
                    created_at = ?6,
                    updated_at = ?7,
                    document_json = ?8,
                    revision = ?9
                WHERE id = ?1 AND revision = ?10
                "#,
                params![
                    case.id,
                    case.title,
                    case.profile.organization_name,
                    status,
                    case.is_demo,
                    case.created_at.to_rfc3339(),
                    case.updated_at.to_rfc3339(),
                    document,
                    next_revision,
                    expected_revision,
                ],
            )?
        };
        if affected != 1 {
            return Err(AppError::Conflict(format!(
                "case {} changed or was deleted after it was loaded",
                case.id
            )));
        }

        transaction.execute(
            r#"
            INSERT INTO case_events(case_id, event_type, occurred_at, payload_json)
            VALUES (?1, ?2, ?3, ?4)
            "#,
            params![
                case.id,
                event_type,
                admission.map_or_else(|| Utc::now().to_rfc3339(), |a| a.admitted_at.to_rfc3339()),
                admission
                    .map_or_else(
                        || serde_json::json!({ "status": case.status }),
                        |a| a.receipt(next_revision),
                    )
                    .to_string(),
            ],
        )?;

        transaction.commit()?;
        case.storage_revision = next_revision;
        Ok(())
    }

    pub fn get_case(&self, id: &str) -> AppResult<AssessmentCase> {
        let connection = self.connection()?;
        let stored: Option<(i64, String)> = connection
            .query_row(
                "SELECT revision, document_json FROM cases WHERE id = ?1",
                [id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;

        let (revision, document) = stored.ok_or_else(|| AppError::CaseNotFound(id.to_owned()))?;
        decode_stored_case(id, revision, &document).map_err(|detail| {
            tracing::error!(
                case_id = id,
                revision,
                detail = %detail,
                "stored case remains preserved because it could not be decoded"
            );
            AppError::Storage(format!(
                "saved project {id} could not be opened; its original data was preserved"
            ))
        })
    }

    /// Freeze the exact persisted document and its historical event rows from
    /// one read transaction. A concurrent writer can continue in WAL mode;
    /// its later commits cannot be mixed into this archive's event history.
    pub fn snapshot_case_for_archive(&self, id: &str) -> AppResult<StoredCaseSnapshot> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
        validate_read_only_schema(&transaction)?;
        let stored: Option<(i64, String)> = transaction
            .query_row(
                "SELECT revision, document_json FROM cases WHERE id = ?1",
                [id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let (revision, document_json) =
            stored.ok_or_else(|| AppError::CaseNotFound(id.to_owned()))?;
        let case = decode_stored_case_document(id, revision, &document_json).map_err(|detail| {
            AppError::Storage(format!(
                "saved project {id} cannot be archived without changing its persisted data: {detail}"
            ))
        })?;
        crate::agent_audit_admission::check_format(&case)?;
        let events = read_case_events(&transaction, id)?;
        validate_archived_events(id, &events)?;
        transaction.commit()?;
        Ok(StoredCaseSnapshot {
            case,
            document_json,
            events,
            revision,
        })
    }

    /// Check the optimistic boundary immediately before archive publication.
    /// Missing, replaced, or changed source rows require a fresh snapshot.
    pub fn assert_case_revision(&self, id: &str, expected: i64) -> AppResult<()> {
        let connection = self.connection()?;
        let actual: Option<i64> = connection
            .query_row("SELECT revision FROM cases WHERE id = ?1", [id], |row| {
                row.get(0)
            })
            .optional()?;
        if expected < 1 || actual != Some(expected) {
            return Err(AppError::Conflict(format!(
                "case {id} changed or was deleted after the archive snapshot was captured"
            )));
        }
        Ok(())
    }

    /// Import a validated archive DTO into a new, empty staging database.
    /// The archive coordinator owns authorization deactivation and reference
    /// validation before calling this method. No current-time case projection,
    /// selected-case setting, worker state, or credential is initialized here.
    pub fn import_archived_case(
        &self,
        case: &mut AssessmentCase,
        events: &[CaseEvent],
        archive_id: &str,
    ) -> AppResult<()> {
        self.import_archived_case_with_provider(case, events, archive_id, None)
    }

    pub(crate) fn import_archived_case_with_provider(
        &self,
        case: &mut AssessmentCase,
        events: &[CaseEvent],
        archive_id: &str,
        provider: Option<&crate::case_archive::VerifiedProviderHistory>,
    ) -> AppResult<()> {
        crate::case_archive::check_restore_case(case, provider)?;
        if case.id.trim().is_empty() || archive_id.trim().is_empty() {
            return Err(AppError::InvalidRequest(
                "archive restore requires a case identity and an archive identity".into(),
            ));
        }
        validate_archived_events(&case.id, events)?;
        let document = serde_json::to_string(case)?;
        let status = serde_json::to_string(&case.status)?
            .trim_matches('"')
            .to_string();
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        validate_read_only_schema(&transaction)?;
        let occupied: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM cases)
                 OR EXISTS(SELECT 1 FROM case_events)
                 OR EXISTS(SELECT 1 FROM app_settings)
                 OR EXISTS(SELECT 1 FROM artifact_deletion_obligations)
                 OR EXISTS(SELECT 1 FROM sqlite_sequence WHERE seq > 0)",
            [],
            |row| row.get(0),
        )?;
        if occupied {
            return Err(AppError::Conflict(
                "archive restore requires a fresh, empty case database".into(),
            ));
        }
        transaction.execute(
            "INSERT INTO cases (id, title, organization_name, status, is_demo,
                 created_at, updated_at, document_json, revision)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 1)",
            params![
                case.id,
                case.title,
                case.profile.organization_name,
                status,
                case.is_demo,
                case.created_at.to_rfc3339(),
                case.updated_at.to_rfc3339(),
                document,
            ],
        )?;
        for event in events {
            transaction.execute(
                "INSERT INTO case_events (sequence, case_id, event_type, occurred_at, payload_json)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    event.sequence,
                    event.case_id,
                    event.event_type,
                    event.occurred_at,
                    event.payload_json,
                ],
            )?;
        }
        let mut payload = serde_json::json!({
            "archive_id": archive_id,
            "source_case_revision": (case.storage_revision > 0).then_some(case.storage_revision),
            "local_storage_revision": 1,
            "historical_event_count": events.len(),
        });
        if let Some(provider) = provider {
            payload["provider_history"] = serde_json::to_value(provider.metadata())?;
        }
        transaction.execute(
            "INSERT INTO case_events (case_id, event_type, occurred_at, payload_json)
             VALUES (?1, 'case.restored', ?2, ?3)",
            params![case.id, Utc::now().to_rfc3339(), payload.to_string(),],
        )?;
        transaction.commit()?;
        case.storage_revision = 1;
        Ok(())
    }

    /// Finish a restored staging database before the coordinator publishes its
    /// directory. Consumption closes the SQLite handle after a complete WAL
    /// truncation; a busy reader or a failed close prevents publication.
    pub fn checkpoint_for_archive_restore(self) -> AppResult<()> {
        let connection = self
            .connection
            .into_inner()
            .map_err(|_| AppError::Storage("database lock was poisoned".into()))?;
        let mode: String = connection.pragma_query_value(None, "journal_mode", |row| row.get(0))?;
        if mode != "wal" {
            return Err(AppError::Storage(
                "archive restore staging requires a WAL database".into(),
            ));
        }
        let (busy, log_frames, checkpointed): (i64, i64, i64) =
            connection.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })?;
        if busy != 0 {
            return Err(AppError::Conflict(
                "archive restore database is still in use; WAL checkpoint could not finish".into(),
            ));
        }
        if log_frames != 0 || checkpointed != 0 {
            return Err(AppError::Storage(
                "archive restore WAL was not completely truncated".into(),
            ));
        }
        connection.close().map_err(|(_, error)| {
            AppError::Storage(format!(
                "archive restore database could not be closed: {error}"
            ))
        })?;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn inject_save_case_faults(
        &self,
        event_type: &str,
        count: usize,
        fault: SaveCaseFault,
    ) {
        let mut faults = self
            .save_case_faults
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        faults.extend((0..count).map(|_| SaveCaseFaultInjection {
            event_type: event_type.to_owned(),
            fault,
        }));
    }

    #[cfg(test)]
    fn take_save_case_fault(&self, event_type: &str) -> Option<SaveCaseFault> {
        let mut faults = self
            .save_case_faults
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if faults
            .front()
            .is_some_and(|injection| injection.event_type == event_type)
        {
            faults.pop_front().map(|injection| injection.fault)
        } else {
            None
        }
    }

    pub fn list_cases(&self) -> AppResult<Vec<CaseSummary>> {
        Ok(self.list_cases_with_recovery_diagnostics()?.cases)
    }

    /// Returns every readable case while isolating only malformed or
    /// structurally unreconcilable rows. No row is rewritten, deleted, or
    /// replaced with demo data. Startup and healthy sibling cases can continue
    /// while the returned diagnostics make the preserved gap observable.
    pub fn list_cases_with_recovery_diagnostics(&self) -> AppResult<ReadableCaseListing> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            r#"
            SELECT id, title, updated_at, revision, document_json
            FROM cases
            ORDER BY updated_at DESC
            "#,
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, String>(4)?,
            ))
        })?;
        let mut cases = Vec::new();
        let mut recovery_diagnostics = Vec::new();

        for row in rows {
            let (case_id, title, updated_at, revision, document) = row?;
            match decode_stored_case(&case_id, revision, &document) {
                Ok(case) => cases.push(CaseSummary::from(&case)),
                Err(detail) => {
                    tracing::error!(
                        case_id = %case_id,
                        revision,
                        detail = %detail,
                        "isolated unreadable case while keeping healthy cases available"
                    );
                    recovery_diagnostics.push(CaseRecoveryDiagnostic {
                        case_id,
                        title,
                        updated_at,
                        revision,
                        document_bytes: document.len(),
                        code: "stored_case_unreadable".into(),
                        message: "This app version cannot open the saved project. Update the app, then try again. Diagnostic code: stored_case_unreadable.".into(),
                        preserved: true,
                    });
                }
            }
        }

        Ok(ReadableCaseListing {
            cases,
            recovery_diagnostics,
        })
    }

    pub fn set_selected_case(&self, id: Option<&str>) -> AppResult<()> {
        let connection = self.connection()?;
        match id {
            Some(id) => {
                connection.execute(
                    r#"
                    INSERT INTO app_settings(key, value) VALUES ('selected_case_id', ?1)
                    ON CONFLICT(key) DO UPDATE SET value = excluded.value
                    "#,
                    [id],
                )?;
            }
            None => {
                connection.execute(
                    "DELETE FROM app_settings WHERE key = 'selected_case_id'",
                    [],
                )?;
            }
        }
        Ok(())
    }

    pub fn selected_case_id(&self) -> AppResult<Option<String>> {
        let connection = self.connection()?;
        Ok(connection
            .query_row(
                "SELECT value FROM app_settings WHERE key = 'selected_case_id'",
                [],
                |row| row.get(0),
            )
            .optional()?)
    }

    /// Read the restore boundary without loading historical event payloads.
    pub fn latest_case_restore_sequence(&self, case_id: &str) -> AppResult<Option<i64>> {
        let connection = self.connection()?;
        Ok(connection.query_row(
            "SELECT MAX(sequence) FROM case_events WHERE case_id = ?1 AND event_type = 'case.restored'",
            [case_id],
            |row| row.get(0),
        )?)
    }

    pub fn list_case_events(&self, case_id: &str) -> AppResult<Vec<CaseEvent>> {
        let connection = self.connection()?;
        read_case_events(&connection, case_id)
    }

    /// Append an acknowledgement and advance the optimistic case boundary in
    /// one transaction. The existing case document and timestamps stay intact.
    /// Call only after the owned worker has stopped and its exact generation
    /// has been reconciled (or a recovery obligation has been recorded).
    pub fn record_scan_command_receipt(
        &self,
        case_id: &str,
        run_id: &str,
        request_id: &str,
        payload: &serde_json::Value,
    ) -> AppResult<ScanCommandReceipt> {
        for identity in [case_id, run_id, request_id] {
            if identity.is_empty() || identity.len() > 256 || identity.chars().any(char::is_control)
            {
                return Err(AppError::InvalidRequest(
                    "scan command receipt requires bounded nonempty identities".into(),
                ));
            }
        }
        if !payload.is_object()
            || serde_json::to_vec(payload)?.len() > MAX_SCAN_COMMAND_RECEIPT_BYTES
        {
            return Err(AppError::InvalidRequest(
                "scan command receipt payload must be an object of at most 1 MiB".into(),
            ));
        }
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let stored: Option<(i64, String)> = transaction
            .query_row(
                "SELECT revision, document_json FROM cases WHERE id = ?1",
                [case_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let (revision, document) =
            stored.ok_or_else(|| AppError::CaseNotFound(case_id.to_owned()))?;
        let case =
            decode_stored_case_document(case_id, revision, &document).map_err(AppError::Storage)?;
        if !case.scan_runs.iter().any(|run| run.id == run_id) {
            return Err(AppError::InvalidRequest(
                "scan command receipt requires an existing exact run".into(),
            ));
        }
        for receipt in read_scan_command_receipts(&transaction, case_id, None)? {
            if receipt.request_id == request_id {
                if receipt.run_id != run_id || receipt.payload != *payload {
                    return Err(AppError::Conflict(
                        "scan command request already has a different saved acknowledgement".into(),
                    ));
                }
                return Ok(receipt);
            }
        }
        let next_revision = revision
            .checked_add(1)
            .ok_or_else(|| AppError::Storage("case storage revision overflowed".into()))?;
        let mut receipt = ScanCommandReceipt {
            schema_version: SCAN_COMMAND_RECEIPT_SCHEMA.into(),
            case_id: case_id.into(),
            run_id: run_id.into(),
            request_id: request_id.into(),
            case_revision: next_revision,
            event_sequence: 0,
            occurred_at: Utc::now().to_rfc3339(),
            payload: payload.clone(),
            digest: String::new(),
        };
        receipt.digest = receipt.content_digest()?;
        transaction.execute(
            "UPDATE cases SET revision = ?2 WHERE id = ?1 AND revision = ?3",
            params![case_id, next_revision, revision],
        )?;
        transaction.execute(
            "INSERT INTO case_events(case_id, event_type, occurred_at, payload_json)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                case_id,
                SCAN_COMMAND_RECEIPT_EVENT,
                receipt.occurred_at,
                serde_json::to_string(&receipt)?,
            ],
        )?;
        receipt.event_sequence = transaction.last_insert_rowid();
        transaction.execute(
            "UPDATE case_events SET payload_json = ?2 WHERE sequence = ?1",
            params![receipt.event_sequence, serde_json::to_string(&receipt)?],
        )?;
        transaction.commit()?;
        Ok(receipt)
    }

    /// Read saved foreground acknowledgements without recovery or mutation.
    /// Original receipts also survive complete case archive/restore as events.
    pub fn scan_command_receipts(
        &self,
        case_id: &str,
        run_id: Option<&str>,
    ) -> AppResult<Vec<ScanCommandReceipt>> {
        let connection = self.connection()?;
        read_scan_command_receipts(&connection, case_id, run_id)
    }

    /// Permanently removes one exact case document and its event history.
    /// Artifact files are handled by the case service so their case-scoped path
    /// can be resolved and reported separately.
    pub fn delete_case(
        &self,
        case_id: &str,
        expected_revision: i64,
        artifact_path: Option<&str>,
    ) -> AppResult<()> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let revision: Option<i64> = transaction
            .query_row(
                "SELECT revision FROM cases WHERE id = ?1",
                [case_id],
                |row| row.get(0),
            )
            .optional()?;
        let revision = revision.ok_or_else(|| AppError::CaseNotFound(case_id.to_owned()))?;
        if revision != expected_revision {
            return Err(AppError::Conflict(format!(
                "case {case_id} changed after deletion was validated"
            )));
        }
        if let Some(exact_path) = artifact_path {
            let existing: Option<String> = transaction
                .query_row(
                    "SELECT exact_path FROM artifact_deletion_obligations WHERE case_id = ?1",
                    [case_id],
                    |row| row.get(0),
                )
                .optional()?;
            if let Some(existing) = existing {
                if existing != exact_path {
                    return Err(AppError::NotAuthorized(
                        "an existing artifact cleanup obligation has a different path".into(),
                    ));
                }
            } else {
                transaction.execute(
                    r#"
                    INSERT INTO artifact_deletion_obligations(case_id, exact_path, created_at)
                    VALUES (?1, ?2, ?3)
                    "#,
                    params![case_id, exact_path, Utc::now().to_rfc3339()],
                )?;
            }
        }
        let deleted = transaction.execute(
            "DELETE FROM cases WHERE id = ?1 AND revision = ?2",
            params![case_id, expected_revision],
        )?;
        if deleted != 1 {
            return Err(AppError::Conflict(format!(
                "case {case_id} changed after deletion was validated"
            )));
        }
        transaction.execute(
            "DELETE FROM app_settings WHERE key = 'selected_case_id' AND value = ?1",
            [case_id],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn list_artifact_deletion_obligations(&self) -> AppResult<Vec<ArtifactDeletionObligation>> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            r#"
            SELECT case_id, exact_path, created_at
            FROM artifact_deletion_obligations
            ORDER BY case_id ASC
            "#,
        )?;
        let rows = statement.query_map([], |row| {
            Ok(ArtifactDeletionObligation {
                case_id: row.get(0)?,
                exact_path: row.get(1)?,
                created_at: row.get(2)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    /// Imports one exact obligation written by the v0.1.0 filesystem ledger.
    /// The immediate transaction prevents the live-case check and durable
    /// insert from being interleaved with another database writer. An exact
    /// existing row is idempotent; a different path is never overwritten.
    pub fn import_artifact_deletion_obligation(
        &self,
        case_id: &str,
        exact_path: &str,
    ) -> AppResult<()> {
        if case_id.is_empty() || exact_path.is_empty() {
            return Err(AppError::InvalidRequest(
                "legacy artifact cleanup obligation is missing its exact identity".into(),
            ));
        }

        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let case_exists: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM cases WHERE id = ?1)",
            [case_id],
            |row| row.get(0),
        )?;
        if case_exists {
            return Err(AppError::NotAuthorized(
                "legacy artifact cleanup obligation cannot be imported while the case database record exists"
                    .into(),
            ));
        }

        let existing: Option<String> = transaction
            .query_row(
                "SELECT exact_path FROM artifact_deletion_obligations WHERE case_id = ?1",
                [case_id],
                |row| row.get(0),
            )
            .optional()?;
        match existing {
            Some(existing) if existing == exact_path => {}
            Some(_) => {
                return Err(AppError::Conflict(
                    "legacy artifact cleanup obligation conflicts with the durable exact path"
                        .into(),
                ));
            }
            None => {
                transaction.execute(
                    r#"
                    INSERT INTO artifact_deletion_obligations(case_id, exact_path, created_at)
                    VALUES (?1, ?2, ?3)
                    "#,
                    params![case_id, exact_path, Utc::now().to_rfc3339()],
                )?;
            }
        }
        transaction.commit()?;
        Ok(())
    }

    /// Claims exactly one durable cleanup obligation while excluding any
    /// concurrent case recreation or second cleanup attempt. The obligation
    /// is consumed only after the filesystem action succeeds.
    pub fn consume_artifact_deletion_obligation<T>(
        &self,
        case_id: &str,
        exact_path: &str,
        action: impl FnOnce() -> AppResult<T>,
    ) -> AppResult<T> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let case_exists: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM cases WHERE id = ?1)",
            [case_id],
            |row| row.get(0),
        )?;
        if case_exists {
            return Err(AppError::NotAuthorized(
                "artifact cleanup is refused while the case database record exists".into(),
            ));
        }
        let obligated_path: Option<String> = transaction
            .query_row(
                "SELECT exact_path FROM artifact_deletion_obligations WHERE case_id = ?1",
                [case_id],
                |row| row.get(0),
            )
            .optional()?;
        let obligated_path = obligated_path.ok_or_else(|| {
            AppError::NotAuthorized(
                "no durable artifact cleanup obligation exists for this deleted case".into(),
            )
        })?;
        if obligated_path != exact_path {
            return Err(AppError::NotAuthorized(
                "artifact cleanup path does not match the durable obligation".into(),
            ));
        }

        let result = action()?;
        let deleted = transaction.execute(
            r#"
            DELETE FROM artifact_deletion_obligations
            WHERE case_id = ?1 AND exact_path = ?2
            "#,
            params![case_id, exact_path],
        )?;
        if deleted != 1 {
            return Err(AppError::Conflict(
                "artifact cleanup obligation changed while it was claimed".into(),
            ));
        }
        transaction.commit()?;
        Ok(result)
    }
}

fn read_scan_command_receipts(
    connection: &Connection,
    case_id: &str,
    run_id: Option<&str>,
) -> AppResult<Vec<ScanCommandReceipt>> {
    let mut statement = connection.prepare(
        "SELECT sequence, occurred_at, payload_json FROM case_events
         WHERE case_id = ?1 AND event_type = ?2 ORDER BY sequence ASC",
    )?;
    let rows = statement.query_map(params![case_id, SCAN_COMMAND_RECEIPT_EVENT], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
        ))
    })?;
    let mut receipts = Vec::new();
    for row in rows {
        let (sequence, occurred_at, document) = row?;
        // Allow the bounded identity/header overhead beyond the payload cap.
        if document.len() > MAX_SCAN_COMMAND_RECEIPT_BYTES + 4096 {
            return Err(AppError::Storage(
                "saved scan command receipt is oversized".into(),
            ));
        }
        let receipt: ScanCommandReceipt = serde_json::from_str(&document)?;
        if receipt.schema_version != SCAN_COMMAND_RECEIPT_SCHEMA
            || receipt.case_id != case_id
            || receipt.event_sequence != sequence
            || receipt.occurred_at != occurred_at
            || receipt.case_revision < 1
            || receipt.content_digest()? != receipt.digest
        {
            return Err(AppError::Storage(
                "saved scan command receipt identity or digest is invalid".into(),
            ));
        }
        if run_id.is_none_or(|run_id| receipt.run_id == run_id) {
            receipts.push(receipt);
        }
    }
    Ok(receipts)
}

fn read_case_events(connection: &Connection, case_id: &str) -> AppResult<Vec<CaseEvent>> {
    let mut statement = connection.prepare(
        "SELECT sequence, case_id, event_type, occurred_at, payload_json
         FROM case_events WHERE case_id = ?1 ORDER BY sequence ASC",
    )?;
    let rows = statement.query_map([case_id], |row| {
        Ok(CaseEvent {
            sequence: row.get(0)?,
            case_id: row.get(1)?,
            event_type: row.get(2)?,
            occurred_at: row.get(3)?,
            payload_json: row.get(4)?,
        })
    })?;
    rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
}

fn validate_archived_events(case_id: &str, events: &[CaseEvent]) -> AppResult<()> {
    let mut previous = 0;
    for event in events {
        if event.case_id != case_id || event.sequence <= previous || event.sequence == i64::MAX {
            return Err(AppError::InvalidRequest(
                "archive events must belong to the case and have increasing positive sequences with room for a restore event".into(),
            ));
        }
        previous = event.sequence;
    }
    Ok(())
}

fn validate_read_only_schema(connection: &Connection) -> AppResult<()> {
    let versions = (|| -> rusqlite::Result<Vec<i64>> {
        let mut statement =
            connection.prepare("SELECT version FROM schema_migrations ORDER BY version")?;
        statement.query_map([], |row| row.get(0))?.collect()
    })()
    .map_err(|error| {
        if matches!(error.sqlite_error_code(), Some(rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked)) {
            return AppError::from(error);
        }
        AppError::Storage(format!(
            "read-only inspection requires an initialized, compatible case database schema; no migration or recovery was attempted: {error}"
        ))
    })?;
    if versions != [1, 2] {
        return Err(AppError::Storage(format!(
            "unsupported case database schema for read-only inspection: migrations {versions:?}, expected [1, 2]; use a compatible application to prepare this database"
        )));
    }
    connection
        .prepare(
            "SELECT id, title, organization_name, status, is_demo, created_at, updated_at, document_json, revision FROM cases LIMIT 0",
        )
        .map_err(|error| {
            if matches!(error.sqlite_error_code(), Some(rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked)) {
                return AppError::from(error);
            }
            AppError::Storage(format!(
                "unsupported case database schema for read-only inspection: {error}"
            ))
        })?;
    Ok(())
}

fn decode_stored_case(
    stored_id: &str,
    revision: i64,
    document: &str,
) -> Result<AssessmentCase, String> {
    let mut case = decode_stored_case_document(stored_id, revision, document)?;
    normalize_scan_request_outcome_invariants(&mut case);
    case.apply_effective_finding_statuses(Utc::now());
    Ok(case)
}

fn decode_stored_case_document(
    stored_id: &str,
    revision: i64,
    document: &str,
) -> Result<AssessmentCase, String> {
    if revision < 1 {
        return Err("stored revision is not positive".into());
    }
    let mut case: AssessmentCase = serde_json::from_str(document).map_err(|error| {
        format!(
            "case document decode category {:?} at line {} column {}",
            error.classify(),
            error.line(),
            error.column()
        )
    })?;
    if case.id != stored_id {
        return Err("document identity does not match database identity".into());
    }
    case.storage_revision = revision;
    Ok(case)
}

/// A request-level no-check outcome and concrete check records cannot both be
/// true. Preserve the concrete records, discard only the contradictory marker,
/// and attach one bounded diagnostic to the first check so old or partially
/// written data cannot make real work disappear from the UI or exports.
fn normalize_scan_request_outcome_invariants(case: &mut AssessmentCase) {
    for run in &mut case.scan_runs {
        if run.request_outcome.is_none()
            || (run.completed_at.is_some() && run.engine_runs.is_empty())
        {
            continue;
        }
        tracing::warn!(
            case_id = %case.id,
            scan_run_id = %run.id,
            completed = run.completed_at.is_some(),
            saved_check_count = run.engine_runs.len(),
            "ignored contradictory request-level no-check marker"
        );
        run.request_outcome = None;
        if let Some(engine_run) = run.engine_runs.first_mut()
            && !engine_run
                .warnings
                .iter()
                .any(|warning| warning == CONTRADICTORY_REQUEST_OUTCOME_WARNING)
        {
            engine_run
                .warnings
                .push(CONTRADICTORY_REQUEST_OUTCOME_WARNING.into());
        }
    }
}

#[cfg(unix)]
fn restrict_directory(path: &Path) -> AppResult<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
fn restrict_directory(_path: &Path) -> AppResult<()> {
    Ok(())
}

#[cfg(unix)]
fn restrict_file(path: &Path) -> AppResult<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn restrict_file(_path: &Path) -> AppResult<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{
        AssessmentCase, DataClass, OrganizationProfile, ScanRequestOutcome, ScanRequestOutcomeCode,
    };
    use std::sync::{Arc, Barrier};

    fn sample_case() -> AssessmentCase {
        AssessmentCase::new(
            "Test case".into(),
            OrganizationProfile {
                organization_name: "Example Co".into(),
                employee_range: "11-50".into(),
                data_classes: vec![DataClass::PersonallyIdentifiableInformation],
                notes: None,
            },
        )
    }

    #[test]
    fn foreground_receipt_is_atomic_idempotent_and_readable_without_a_writer() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("casework.db");
        let storage = Storage::open(&path).unwrap();
        let mut case = crate::demo::build_demo_case();
        storage.save_case(&mut case, "case.created").unwrap();
        let before = storage.snapshot_case_for_archive(&case.id).unwrap();
        let selected_run_id = case.scan_runs[0].id.clone();
        let run_id = selected_run_id.as_str();
        let payload = serde_json::json!({
            "command_outcome": "completed", "run_completeness": "partial",
            "cleanup_pending": true,
        });
        let receipt = storage
            .record_scan_command_receipt(&case.id, run_id, "request-1", &payload)
            .unwrap();
        assert_eq!(receipt.case_revision, before.revision + 1);
        assert_eq!(receipt.digest, receipt.content_digest().unwrap());
        let after = storage.snapshot_case_for_archive(&case.id).unwrap();
        assert_eq!(after.document_json, before.document_json);
        assert_eq!(after.events.len(), before.events.len() + 1);
        assert_eq!(after.case.updated_at, before.case.updated_at);
        assert_eq!(
            storage
                .record_scan_command_receipt(&case.id, run_id, "request-1", &payload)
                .unwrap(),
            receipt
        );
        assert_eq!(
            storage.get_case(&case.id).unwrap().storage_revision,
            receipt.case_revision
        );
        assert!(matches!(
            storage.save_case(&mut case, "stale.writer"),
            Err(AppError::Conflict(_))
        ));
        let reader = Storage::open_read_only(&path).unwrap();
        assert_eq!(
            reader
                .scan_command_receipts(&case.id, Some(run_id))
                .unwrap(),
            vec![receipt.clone()]
        );
        assert!(
            reader
                .scan_command_receipts(&case.id, Some("other-run"))
                .unwrap()
                .is_empty()
        );
        assert!(
            reader
                .record_scan_command_receipt(&case.id, run_id, "reader-write", &payload)
                .is_err()
        );
        drop(reader);
        drop(storage);
        assert_eq!(
            Storage::open_read_only(path)
                .unwrap()
                .scan_command_receipts(&case.id, None)
                .unwrap(),
            vec![receipt]
        );
    }

    #[test]
    fn foreground_receipt_rejects_conflicts_missing_runs_and_corrupt_history() {
        let directory = tempfile::tempdir().unwrap();
        let storage = Storage::open(directory.path().join("casework.db")).unwrap();
        let mut case = crate::demo::build_demo_case();
        storage.save_case(&mut case, "case.created").unwrap();
        let run_id = &case.scan_runs[0].id;
        let payload = serde_json::json!({"command_outcome": "interrupted"});
        let receipt = storage
            .record_scan_command_receipt(&case.id, run_id, "same-request", &payload)
            .unwrap();
        let before = storage.snapshot_case_for_archive(&case.id).unwrap();
        assert!(matches!(
            storage.record_scan_command_receipt(
                &case.id,
                run_id,
                "same-request",
                &serde_json::json!({"command_outcome": "completed"})
            ),
            Err(AppError::Conflict(_))
        ));
        assert!(
            storage
                .record_scan_command_receipt(&case.id, "missing-run", "new-request", &payload)
                .is_err()
        );
        assert!(
            storage
                .record_scan_command_receipt(&case.id, run_id, "", &payload)
                .is_err()
        );
        assert!(
            storage
                .record_scan_command_receipt(
                    &case.id,
                    run_id,
                    "oversized",
                    &serde_json::json!({"data": "x".repeat(MAX_SCAN_COMMAND_RECEIPT_BYTES)})
                )
                .is_err()
        );
        let after = storage.snapshot_case_for_archive(&case.id).unwrap();
        assert_eq!(before.revision, after.revision);
        assert_eq!(before.events, after.events);
        let mut corrupt = receipt.clone();
        corrupt.payload = serde_json::json!({"command_outcome": "completed"});
        storage
            .connection()
            .unwrap()
            .execute(
                "UPDATE case_events SET payload_json = ?1 WHERE sequence = ?2",
                params![
                    serde_json::to_string(&corrupt).unwrap(),
                    receipt.event_sequence
                ],
            )
            .unwrap();
        assert!(storage.scan_command_receipts(&case.id, None).is_err());
        assert!(
            storage
                .record_scan_command_receipt(&case.id, run_id, "same-request", &payload)
                .is_err()
        );
        assert_eq!(
            storage.get_case(&case.id).unwrap().storage_revision,
            receipt.case_revision
        );
    }

    #[test]
    fn foreground_receipts_survive_archive_event_import_with_original_digest() {
        let directory = tempfile::tempdir().unwrap();
        let source = Storage::open(directory.path().join("source.db")).unwrap();
        let mut case = crate::demo::build_demo_case();
        source.save_case(&mut case, "case.created").unwrap();
        let receipt = source
            .record_scan_command_receipt(
                &case.id,
                &case.scan_runs[0].id,
                "saved-request",
                &serde_json::json!({"command_outcome": "completed"}),
            )
            .unwrap();
        let snapshot = source.snapshot_case_for_archive(&case.id).unwrap();
        let destination = Storage::open(directory.path().join("destination.db")).unwrap();
        let mut restored = snapshot.case;
        destination
            .import_archived_case(&mut restored, &snapshot.events, "archive-test")
            .unwrap();
        assert_eq!(restored.storage_revision, 1);
        assert_eq!(
            destination
                .scan_command_receipts(&restored.id, None)
                .unwrap(),
            vec![receipt]
        );
    }

    #[test]
    fn case_round_trip_and_selection() {
        let directory = tempfile::tempdir().expect("temp directory");
        let storage = Storage::open(directory.path().join("casework.db")).expect("storage");
        let mut case = sample_case();

        storage.save_case(&mut case, "case.created").expect("save");
        storage
            .set_selected_case(Some(&case.id))
            .expect("selection");

        let loaded = storage.get_case(&case.id).expect("load");
        assert_eq!(loaded.title, case.title);
        assert_eq!(storage.list_cases().expect("list").len(), 1);
        assert_eq!(
            storage.selected_case_id().expect("selected"),
            Some(case.id.clone())
        );
        assert_eq!(storage.list_case_events(&case.id).expect("events").len(), 1);
    }

    #[test]
    fn unreadable_cases_are_preserved_and_isolated_from_healthy_siblings() {
        let directory = tempfile::tempdir().expect("temp directory");
        let storage = Storage::open(directory.path().join("casework.db")).expect("storage");
        let mut healthy = sample_case();
        healthy.id = "healthy-case".into();
        healthy.title = "Healthy project".into();
        let mut malformed = sample_case();
        malformed.id = "malformed-case".into();
        malformed.title = "Preserved malformed project".into();
        let mut mismatched = sample_case();
        mismatched.id = "mismatched-case".into();
        mismatched.title = "Preserved mismatched project".into();
        storage
            .save_case(&mut healthy, "case.created")
            .expect("save healthy case");
        storage
            .save_case(&mut malformed, "case.created")
            .expect("save malformed fixture case");
        storage
            .save_case(&mut mismatched, "case.created")
            .expect("save mismatched fixture case");

        let malformed_bytes = "{preserve these malformed bytes exactly";
        let mut mismatched_document = mismatched.clone();
        mismatched_document.id = "different-document-identity".into();
        let mismatched_bytes =
            serde_json::to_string(&mismatched_document).expect("mismatched document");
        storage
            .connection()
            .expect("connection")
            .execute(
                "UPDATE cases SET document_json = ?2 WHERE id = ?1",
                params![malformed.id, malformed_bytes],
            )
            .expect("inject malformed case document");
        storage
            .connection()
            .expect("connection")
            .execute(
                "UPDATE cases SET document_json = ?2 WHERE id = ?1",
                params![mismatched.id, mismatched_bytes],
            )
            .expect("inject mismatched case document");

        let listing = storage
            .list_cases_with_recovery_diagnostics()
            .expect("resilient case listing");
        assert_eq!(
            listing
                .cases
                .iter()
                .map(|case| case.id.as_str())
                .collect::<Vec<_>>(),
            vec![healthy.id.as_str()]
        );
        assert_eq!(listing.recovery_diagnostics.len(), 2);
        for diagnostic in &listing.recovery_diagnostics {
            assert_eq!(diagnostic.code, "stored_case_unreadable");
            assert!(diagnostic.preserved);
            assert!(!diagnostic.message.contains(malformed_bytes));
        }
        assert_eq!(storage.list_cases().expect("healthy cases").len(), 1);
        assert!(matches!(
            storage.get_case(&malformed.id),
            Err(AppError::Storage(_))
        ));

        let preserved: String = storage
            .connection()
            .expect("connection")
            .query_row(
                "SELECT document_json FROM cases WHERE id = ?1",
                [&malformed.id],
                |row| row.get(0),
            )
            .expect("preserved malformed bytes");
        assert_eq!(preserved, malformed_bytes);

        let preserved_mismatch: String = storage
            .connection()
            .expect("connection")
            .query_row(
                "SELECT document_json FROM cases WHERE id = ?1",
                [&mismatched.id],
                |row| row.get(0),
            )
            .expect("preserved mismatched document");
        assert_eq!(preserved_mismatch, mismatched_bytes);
    }

    #[test]
    fn contradictory_no_check_marker_never_hides_saved_check_records() {
        let directory = tempfile::tempdir().expect("temp directory");
        let storage = Storage::open(directory.path().join("casework.db")).expect("storage");
        let prepared =
            crate::localhost_quick_scan::prepare_localhost_quick_scan(&storage, &[], 9_001)
                .expect("prepared localhost case");
        let mut contradictory = storage
            .get_case(&prepared.case.id)
            .expect("saved localhost case");
        let asset_id = contradictory.assets[0].id.clone();
        contradictory.scan_runs[0].request_outcome = Some(
            ScanRequestOutcome::no_checks_completed(
                ScanRequestOutcomeCode::NoApplicableChecks,
                vec![asset_id],
                vec!["requested-check".into()],
                "No applicable checks were selected.",
            )
            .expect("valid marker"),
        );

        // Simulate a contradictory legacy/partially written row that predates
        // the write-time invariant.
        let document = serde_json::to_string(&contradictory).expect("document");
        storage
            .connection()
            .expect("connection")
            .execute(
                "UPDATE cases SET document_json = ?2 WHERE id = ?1",
                params![contradictory.id, document],
            )
            .expect("inject legacy contradiction");

        let mut loaded = storage
            .get_case(&contradictory.id)
            .expect("normalized case");
        assert!(loaded.scan_runs[0].request_outcome.is_none());
        assert_eq!(loaded.scan_runs[0].engine_runs.len(), 1);
        assert!(
            loaded.scan_runs[0].engine_runs[0]
                .warnings
                .iter()
                .any(|warning| warning == CONTRADICTORY_REQUEST_OUTCOME_WARNING)
        );

        // The same invariant is enforced before every subsequent write, so a
        // caller cannot reintroduce the marker and hide the concrete check.
        loaded.scan_runs[0].request_outcome = Some(
            ScanRequestOutcome::no_checks_completed(
                ScanRequestOutcomeCode::NoApplicableChecks,
                vec![],
                vec![],
                "No applicable checks were selected.",
            )
            .expect("valid marker"),
        );
        storage
            .save_case(&mut loaded, "test.contradictory_request_outcome")
            .expect("normalized save");
        assert!(loaded.scan_runs[0].request_outcome.is_none());
        assert_eq!(loaded.scan_runs[0].engine_runs.len(), 1);

        loaded.scan_runs[0].engine_runs.clear();
        loaded.scan_runs[0].completed_at = None;
        loaded.scan_runs[0].request_outcome = Some(
            ScanRequestOutcome::no_checks_completed(
                ScanRequestOutcomeCode::NoApplicableChecks,
                vec![],
                vec![],
                "No applicable checks were selected.",
            )
            .expect("valid marker"),
        );
        let incomplete_document = serde_json::to_string(&loaded).expect("incomplete document");
        storage
            .connection()
            .expect("connection")
            .execute(
                "UPDATE cases SET document_json = ?2 WHERE id = ?1",
                params![loaded.id, incomplete_document],
            )
            .expect("inject incomplete legacy marker");
        loaded = storage
            .get_case(&loaded.id)
            .expect("incomplete marker normalized on load");
        assert!(loaded.scan_runs[0].request_outcome.is_none());
        assert!(loaded.scan_runs[0].engine_runs.is_empty());
        storage
            .save_case(&mut loaded, "test.incomplete_request_outcome")
            .expect("incomplete marker normalized");
        assert!(loaded.scan_runs[0].request_outcome.is_none());
        assert!(loaded.scan_runs[0].engine_runs.is_empty());
    }

    #[test]
    fn legacy_case_rows_receive_a_revision_without_data_loss() {
        let directory = tempfile::tempdir().expect("temp directory");
        let database = directory.path().join("casework.db");
        let legacy_case = sample_case();
        let connection = Connection::open(&database).expect("legacy database");
        connection
            .execute_batch(
                r#"
                CREATE TABLE cases (
                    id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    organization_name TEXT NOT NULL,
                    status TEXT NOT NULL,
                    is_demo INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    document_json TEXT NOT NULL
                );
                "#,
            )
            .expect("legacy schema");
        connection
            .execute(
                r#"
                INSERT INTO cases(
                    id, title, organization_name, status, is_demo,
                    created_at, updated_at, document_json
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                "#,
                params![
                    legacy_case.id,
                    legacy_case.title,
                    legacy_case.profile.organization_name,
                    "draft",
                    legacy_case.is_demo,
                    legacy_case.created_at.to_rfc3339(),
                    legacy_case.updated_at.to_rfc3339(),
                    serde_json::to_string(&legacy_case).expect("legacy document"),
                ],
            )
            .expect("legacy case row");
        drop(connection);

        let storage = Storage::open(&database).expect("migrated storage");
        let mut loaded = storage.get_case(&legacy_case.id).expect("migrated case");
        assert_eq!(loaded.title, legacy_case.title);
        assert_eq!(loaded.storage_revision, 1);
        loaded.title = "Updated after migration".into();
        loaded.touch();
        storage
            .save_case(&mut loaded, "case.updated_after_migration")
            .expect("revision-aware update");
        assert_eq!(loaded.storage_revision, 2);
        assert_eq!(
            storage
                .get_case(&legacy_case.id)
                .expect("updated migrated case")
                .title,
            "Updated after migration"
        );
    }

    #[test]
    fn deletion_is_exact_and_cascades_case_events() {
        let directory = tempfile::tempdir().expect("temp directory");
        let storage = Storage::open(directory.path().join("casework.db")).expect("storage");
        let mut first = sample_case();
        let mut second = sample_case();
        second.id = "case-to-keep".into();
        second.title = "Keep me".into();
        storage
            .save_case(&mut first, "case.created")
            .expect("save first");
        storage
            .save_case(&mut second, "case.created")
            .expect("save second");
        storage
            .set_selected_case(Some(&first.id))
            .expect("select first");

        storage
            .delete_case(&first.id, first.storage_revision, None)
            .expect("delete first");

        assert!(matches!(
            storage.get_case(&first.id),
            Err(AppError::CaseNotFound(_))
        ));
        assert_eq!(storage.list_case_events(&first.id).expect("events"), vec![]);
        assert_eq!(
            storage.get_case(&second.id).expect("second").title,
            "Keep me"
        );
        assert_eq!(storage.selected_case_id().expect("selection"), None);
        assert!(matches!(
            storage.delete_case(&first.id, first.storage_revision, None),
            Err(AppError::CaseNotFound(_))
        ));
    }

    #[test]
    fn legacy_artifact_obligation_import_is_exact_idempotent_and_refuses_live_cases() {
        let directory = tempfile::tempdir().expect("temp directory");
        let storage = Storage::open(directory.path().join("casework.db")).expect("storage");
        let mut live_case = sample_case();
        live_case.id = "live-case".into();
        storage
            .save_case(&mut live_case, "case.created")
            .expect("save live case");

        assert!(matches!(
            storage
                .import_artifact_deletion_obligation(&live_case.id, "/private/artifacts/live-case"),
            Err(AppError::NotAuthorized(_))
        ));
        assert!(
            storage
                .list_artifact_deletion_obligations()
                .expect("empty obligations")
                .is_empty()
        );

        storage
            .import_artifact_deletion_obligation("deleted-case", "/private/artifacts/deleted-case")
            .expect("first import");
        storage
            .import_artifact_deletion_obligation("deleted-case", "/private/artifacts/deleted-case")
            .expect("exact import is idempotent");
        assert!(matches!(
            storage.import_artifact_deletion_obligation(
                "deleted-case",
                "/different/artifacts/deleted-case"
            ),
            Err(AppError::Conflict(_))
        ));

        let obligations = storage
            .list_artifact_deletion_obligations()
            .expect("durable obligation");
        assert_eq!(obligations.len(), 1);
        assert_eq!(obligations[0].case_id, "deleted-case");
        assert_eq!(obligations[0].exact_path, "/private/artifacts/deleted-case");
    }

    #[test]
    fn concurrent_stale_updates_cannot_overwrite_each_other() {
        let directory = tempfile::tempdir().expect("temp directory");
        let storage =
            Arc::new(Storage::open(directory.path().join("casework.db")).expect("storage"));
        let mut case = sample_case();
        storage
            .save_case(&mut case, "case.created")
            .expect("initial save");

        let barrier = Arc::new(Barrier::new(3));
        let mut workers = Vec::new();
        for title in ["first concurrent writer", "second concurrent writer"] {
            let storage = Arc::clone(&storage);
            let barrier = Arc::clone(&barrier);
            let case_id = case.id.clone();
            workers.push(std::thread::spawn(move || {
                let mut loaded = storage.get_case(&case_id).expect("load shared revision");
                loaded.title = title.into();
                loaded.touch();
                barrier.wait();
                let result = storage.save_case(&mut loaded, "case.concurrent_update");
                (title, result)
            }));
        }
        barrier.wait();

        let outcomes = workers
            .into_iter()
            .map(|worker| worker.join().expect("writer thread"))
            .collect::<Vec<_>>();
        assert_eq!(
            outcomes.iter().filter(|(_, result)| result.is_ok()).count(),
            1
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|(_, result)| matches!(result, Err(AppError::Conflict(_))))
                .count(),
            1
        );
        let winning_title = outcomes
            .iter()
            .find_map(|(title, result)| result.is_ok().then_some(*title))
            .expect("one winner");
        assert_eq!(
            storage.get_case(&case.id).expect("stored winner").title,
            winning_title
        );
        assert_eq!(
            storage
                .list_case_events(&case.id)
                .expect("committed events")
                .len(),
            2,
            "the rejected writer must not append an event"
        );
    }

    #[test]
    fn stale_save_cannot_resurrect_a_deleted_case() {
        let directory = tempfile::tempdir().expect("temp directory");
        let storage = Storage::open(directory.path().join("casework.db")).expect("storage");
        let mut case = sample_case();
        storage
            .save_case(&mut case, "case.created")
            .expect("initial save");
        let mut stale = storage.get_case(&case.id).expect("stale snapshot");

        storage
            .delete_case(&case.id, case.storage_revision, None)
            .expect("delete");
        stale.title = "must not return".into();
        stale.touch();
        assert!(matches!(
            storage.save_case(&mut stale, "case.stale_update"),
            Err(AppError::Conflict(_))
        ));
        assert!(matches!(
            storage.get_case(&case.id),
            Err(AppError::CaseNotFound(_))
        ));
    }

    #[test]
    fn stale_revision_cannot_delete_a_newer_case() {
        let directory = tempfile::tempdir().expect("temp directory");
        let storage = Storage::open(directory.path().join("casework.db")).expect("storage");
        let mut case = sample_case();
        storage
            .save_case(&mut case, "case.created")
            .expect("initial save");
        let stale_revision = case.storage_revision;
        let mut current = storage.get_case(&case.id).expect("current snapshot");
        current.title = "newer case".into();
        current.touch();
        storage
            .save_case(&mut current, "case.updated")
            .expect("newer save");

        assert!(matches!(
            storage.delete_case(&case.id, stale_revision, None),
            Err(AppError::Conflict(_))
        ));
        assert_eq!(
            storage.get_case(&case.id).expect("case survives").title,
            "newer case"
        );
    }

    #[test]
    fn archive_snapshot_keeps_exact_document_and_unprojected_historical_workflow() {
        use crate::domain::{FindingStatus, FindingWorkflowEvent};

        let directory = tempfile::tempdir().unwrap();
        let storage = Storage::open(directory.path().join("casework.db")).unwrap();
        let mut case = crate::demo::build_demo_case();
        case.findings[0].status = FindingStatus::FalsePositive;
        case.finding_workflow_events.push(FindingWorkflowEvent {
            id: "expired-review".into(),
            case_id: case.id.clone(),
            finding_id: case.findings[0].id.clone(),
            from_status: FindingStatus::Unreviewed,
            to_status: FindingStatus::FalsePositive,
            decided_by: "fixture-reviewer".into(),
            decided_at: Utc::now() - chrono::Duration::days(2),
            reason: "Historical fixture decision".into(),
            expires_at: Some(Utc::now() - chrono::Duration::days(1)),
        });
        storage.save_case(&mut case, "fixture.saved").unwrap();
        let document = format!("\n{}\n", serde_json::to_string_pretty(&case).unwrap());
        storage
            .connection()
            .unwrap()
            .execute(
                "UPDATE cases SET document_json = ?1 WHERE id = ?2",
                params![document, case.id],
            )
            .unwrap();
        let reader = Storage::open_read_only(storage.path()).unwrap();
        let snapshot = reader.snapshot_case_for_archive(&case.id).unwrap();

        assert_eq!(snapshot.document_json, document);
        assert_eq!(snapshot.revision, 1);
        assert_eq!(snapshot.case.storage_revision, 1);
        assert_eq!(
            snapshot.case.findings[0].status,
            FindingStatus::FalsePositive
        );
        assert_eq!(
            serde_json::to_value(&snapshot.case).unwrap(),
            serde_json::to_value(&case).unwrap()
        );
        assert_eq!(snapshot.events, storage.list_case_events(&case.id).unwrap());
        assert_eq!(
            reader.get_case(&case.id).unwrap().findings[0].status,
            FindingStatus::Unreviewed,
            "normal display applies expiry, archive capture must not"
        );
        assert_eq!(
            storage
                .snapshot_case_for_archive(&case.id)
                .unwrap()
                .document_json,
            document
        );
    }

    #[test]
    fn archive_snapshot_reads_case_and_events_from_one_concurrent_commit() {
        let directory = tempfile::tempdir().unwrap();
        let storage = Arc::new(Storage::open(directory.path().join("casework.db")).unwrap());
        let mut case = sample_case();
        storage.save_case(&mut case, "fixture.created").unwrap();
        let case_id = case.id.clone();
        let reader = Storage::open_read_only(storage.path()).unwrap();
        let start = Arc::new(Barrier::new(2));
        let writer = {
            let storage = Arc::clone(&storage);
            let start = Arc::clone(&start);
            std::thread::spawn(move || {
                start.wait();
                for revision in 2..=151 {
                    case.title = format!("Revision {revision}");
                    storage.save_case(&mut case, "fixture.checkpoint").unwrap();
                    std::thread::yield_now();
                }
            })
        };
        start.wait();
        for _ in 0..150 {
            let snapshot = reader.snapshot_case_for_archive(&case_id).unwrap();
            assert_eq!(snapshot.events.len() as i64, snapshot.revision);
            assert_eq!(snapshot.events.last().unwrap().sequence, snapshot.revision);
            if snapshot.revision > 1 {
                assert_eq!(
                    snapshot.case.title,
                    format!("Revision {}", snapshot.revision)
                );
            }
            std::thread::yield_now();
        }
        writer.join().unwrap();
        assert_eq!(
            reader.snapshot_case_for_archive(&case_id).unwrap().revision,
            151
        );
    }

    #[test]
    fn archive_revision_check_rejects_updates_and_deleted_source_rows() {
        let directory = tempfile::tempdir().unwrap();
        let storage = Storage::open(directory.path().join("casework.db")).unwrap();
        let mut case = sample_case();
        storage.save_case(&mut case, "fixture.created").unwrap();
        let reader = Storage::open_read_only(storage.path()).unwrap();
        let snapshot = reader.snapshot_case_for_archive(&case.id).unwrap();
        reader
            .assert_case_revision(&case.id, snapshot.revision)
            .unwrap();
        case.title = "Updated while archive blobs were copied".into();
        storage.save_case(&mut case, "fixture.updated").unwrap();
        assert!(matches!(
            reader.assert_case_revision(&case.id, snapshot.revision),
            Err(AppError::Conflict(_))
        ));
        storage
            .delete_case(&case.id, case.storage_revision, None)
            .unwrap();
        assert!(matches!(
            reader.assert_case_revision(&case.id, case.storage_revision),
            Err(AppError::Conflict(_))
        ));
    }

    fn archive_events(case_id: &str) -> Vec<CaseEvent> {
        [7, 12]
            .into_iter()
            .map(|sequence| CaseEvent {
                sequence,
                case_id: case_id.into(),
                event_type: format!("historical.{sequence}"),
                occurred_at: "2026-09-20T01:02:03.123456+00:00".into(),
                payload_json: "{ \"historical\": true, \"value\": 7 }\n".into(),
            })
            .collect()
    }

    #[test]
    fn archive_import_preserves_dto_and_event_sequences_and_closes_staging_database() {
        let directory = tempfile::tempdir().unwrap();
        let database = directory.path().join("casework.db");
        let storage = Storage::open(&database).unwrap();
        let mut case = crate::demo::build_demo_case();
        case.storage_revision = 42;
        let expected = serde_json::to_value(&case).unwrap();
        let events = archive_events(&case.id);
        storage
            .import_archived_case(&mut case, &events, "archive-identity")
            .unwrap();
        assert_eq!(case.storage_revision, 1);
        assert_eq!(storage.selected_case_id().unwrap(), None);
        let snapshot = storage.snapshot_case_for_archive(&case.id).unwrap();
        assert_eq!(snapshot.revision, 1);
        assert_eq!(serde_json::to_value(&snapshot.case).unwrap(), expected);
        assert_eq!(&snapshot.events[..events.len()], events.as_slice());
        let restore = snapshot.events.last().unwrap();
        assert_eq!(restore.sequence, 13);
        assert_eq!(restore.event_type, "case.restored");
        assert_eq!(restore.case_id, case.id);
        let receipt: serde_json::Value = serde_json::from_str(&restore.payload_json).unwrap();
        assert_eq!(receipt["archive_id"], "archive-identity");
        assert_eq!(receipt["source_case_revision"], 42);
        assert_eq!(receipt["local_storage_revision"], 1);
        storage.checkpoint_for_archive_restore().unwrap();
        assert!(!database.with_file_name("casework.db-wal").exists());
        assert!(!database.with_file_name("casework.db-shm").exists());
        let reopened = Storage::open_read_only(&database).unwrap();
        let after_close = reopened.snapshot_case_for_archive(&case.id).unwrap();
        assert_eq!(serde_json::to_value(after_close.case).unwrap(), expected);
        assert_eq!(after_close.events, snapshot.events);
    }

    #[test]
    fn archive_import_rolls_back_case_and_history_when_restore_event_fails() {
        let directory = tempfile::tempdir().unwrap();
        let storage = Storage::open(directory.path().join("casework.db")).unwrap();
        storage
            .connection()
            .unwrap()
            .execute_batch(
                "CREATE TRIGGER fail_restore_event BEFORE INSERT ON case_events
             WHEN NEW.event_type = 'case.restored'
             BEGIN SELECT RAISE(ABORT, 'injected restore event failure'); END;",
            )
            .unwrap();
        let mut case = sample_case();
        case.storage_revision = 99;
        let events = archive_events(&case.id);
        assert!(
            storage
                .import_archived_case(&mut case, &events, "archive-identity")
                .is_err()
        );
        assert_eq!(case.storage_revision, 99);
        assert!(storage.list_cases().unwrap().is_empty());
        assert!(storage.list_case_events(&case.id).unwrap().is_empty());
        storage
            .connection()
            .unwrap()
            .execute_batch("DROP TRIGGER fail_restore_event")
            .unwrap();
        storage
            .import_archived_case(&mut case, &events, "archive-identity")
            .unwrap();
        assert_eq!(case.storage_revision, 1);
        assert_eq!(
            storage
                .list_case_events(&case.id)
                .unwrap()
                .last()
                .unwrap()
                .sequence,
            13
        );
    }

    #[test]
    fn archive_import_requires_a_fresh_database_without_settings_or_cleanup_obligations() {
        for existing in ["case", "settings", "cleanup", "deleted-history"] {
            let directory = tempfile::tempdir().unwrap();
            let storage = Storage::open(directory.path().join("casework.db")).unwrap();
            let mut existing_case = sample_case();
            match existing {
                "case" | "deleted-history" => {
                    storage
                        .save_case(&mut existing_case, "fixture.created")
                        .unwrap();
                    if existing == "deleted-history" {
                        storage
                            .delete_case(&existing_case.id, existing_case.storage_revision, None)
                            .unwrap();
                    }
                }
                "settings" => storage.set_selected_case(Some("old-selection")).unwrap(),
                "cleanup" => storage
                    .import_artifact_deletion_obligation("old-case", "/fixture-only/old-path")
                    .unwrap(),
                _ => unreachable!(),
            }
            let mut imported = sample_case();
            assert!(
                matches!(
                    storage.import_archived_case(&mut imported, &[], "archive-identity"),
                    Err(AppError::Conflict(_))
                ),
                "must refuse {existing}"
            );
            assert_eq!(imported.storage_revision, 0);
            assert!(matches!(
                storage.get_case(&imported.id),
                Err(AppError::CaseNotFound(_))
            ));
        }
    }

    #[test]
    fn archive_import_rejects_wrong_case_or_invalid_event_sequences_without_partial_writes() {
        let directory = tempfile::tempdir().unwrap();
        let storage = Storage::open(directory.path().join("casework.db")).unwrap();
        let mut case = sample_case();
        for invalid in ["foreign-case", "duplicate", "zero", "exhausted"] {
            let mut events = archive_events(&case.id);
            match invalid {
                "foreign-case" => events[0].case_id = "other-case".into(),
                "duplicate" => events[1].sequence = events[0].sequence,
                "zero" => events[0].sequence = 0,
                "exhausted" => events[1].sequence = i64::MAX,
                _ => unreachable!(),
            }
            assert!(matches!(
                storage.import_archived_case(&mut case, &events, "archive-identity"),
                Err(AppError::InvalidRequest(_))
            ));
            assert!(storage.list_cases().unwrap().is_empty());
            assert!(storage.list_case_events(&case.id).unwrap().is_empty());
            assert_eq!(case.storage_revision, 0);
        }
    }

    #[test]
    fn archive_restore_checkpoint_refuses_an_active_wal_reader() {
        let directory = tempfile::tempdir().unwrap();
        let database = directory.path().join("casework.db");
        let storage = Storage::open(&database).unwrap();
        let mut case = sample_case();
        storage.save_case(&mut case, "fixture.created").unwrap();
        let reader =
            Connection::open_with_flags(&database, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
        reader
            .execute_batch("BEGIN; SELECT document_json FROM cases;")
            .unwrap();
        case.title = "A newer committed row".into();
        storage.save_case(&mut case, "fixture.updated").unwrap();
        storage
            .connection()
            .unwrap()
            .busy_timeout(std::time::Duration::ZERO)
            .unwrap();
        assert!(matches!(
            storage.checkpoint_for_archive_restore(),
            Err(AppError::Conflict(_))
        ));
        reader.execute_batch("ROLLBACK").unwrap();
        drop(reader);
        let reopened = Storage::open(&database).unwrap();
        assert_eq!(reopened.get_case(&case.id).unwrap().title, case.title);
        reopened.checkpoint_for_archive_restore().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn storage_rejects_symlink_database_and_restricts_local_paths() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let directory = tempfile::tempdir().expect("temp directory");
        let private = directory.path().join("private");
        let database = private.join("casework.db");
        let storage = Storage::open(&database).expect("storage");
        assert_eq!(
            fs::metadata(&private).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(storage.path()).unwrap().permissions().mode() & 0o777,
            0o600
        );
        drop(storage);

        let target = directory.path().join("target.db");
        fs::write(&target, []).unwrap();
        let linked = directory.path().join("linked.db");
        symlink(&target, &linked).unwrap();
        assert!(matches!(Storage::open(linked), Err(AppError::Storage(_))));
    }
}
