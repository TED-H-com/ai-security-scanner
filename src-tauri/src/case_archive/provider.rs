//! Shared offline admission and custody verifier for immutable archive snapshots.
use super::{history::*, *};
use crate::cloudflare_provider::{
    audit::{
        self, PreparationReceipt, PreparationResult, captured,
        record::{Entry, RECORD_EVENT, Record},
        sealed,
    },
    source_view::{self, SourceViewPreparationReceipt, canonical_bytes, domain_digest},
};
use crate::domain::EngineTaskKind;

pub(super) fn error(code: &'static str) -> AppError {
    AppError::ArchiveProvider {
        code,
        message: "Source-audit archive data is missing or inconsistent.",
    }
}
fn require(ok: bool, code: &'static str) -> AppResult<()> {
    if ok { Ok(()) } else { Err(error(code)) }
}
const HISTORY: &str = "archive_history_mismatch";
const BINDING: &str = "archive_admission_binding_mismatch";
const CONTENT: &str = "archive_content_mismatch";
const OMISSION: &str = "archive_omission_mismatch";

/// Classify graph errors before the existing export checks, preserving their API/errors.
pub(super) fn graph(case: &AssessmentCase) -> AppResult<()> {
    let mut identities = BTreeSet::new();
    for a in &case.agent_audit_admissions {
        for (kind, id) in [
            ("admission", &a.admission_id),
            ("session", &a.identities.session_id),
            ("run", &a.identities.run_id),
            ("task", &a.identities.task_id),
        ] {
            require(identities.insert((kind, id)), "archive_duplicate_admission")?;
        }
    }
    for a in &case.agent_audit_admissions {
        require(
            a.provider_id == "cloudflare-security-audit"
                && a.retained_projection["schema_version"]
                    == "ai-security-scanner.provider-report/v1"
                && a.retained_projection["provider_id"] == a.provider_id,
            "archive_provider_unsupported",
        )?;
        let run = case
            .scan_runs
            .iter()
            .find(|r| r.id == a.identities.run_id)
            .ok_or_else(|| error(BINDING))?;
        require(
            case.scan_runs.iter().filter(|r| r.id == run.id).count() == 1
                && case
                    .scan_runs
                    .iter()
                    .flat_map(|r| &r.engine_runs)
                    .filter(|t| t.id == a.identities.task_id)
                    .count()
                    <= 1,
            "archive_duplicate_admission",
        )?;
        let task = run
            .engine_runs
            .iter()
            .find(|t| t.id == a.identities.task_id)
            .ok_or_else(|| error(BINDING))?;
        require(
            a.identities.case_id == case.id
                && run.case_id == case.id
                && task.scan_run_id == run.id
                && task.engine_id == a.provider_id
                && task.asset_ids.len() == 1
                && task.asset_ids[0] == a.identities.asset_id
                && run.report_asset_snapshots.iter().any(|s| {
                    s.asset.id == a.identities.asset_id
                        && s.asset.discovered_from.contains(&a.source_id)
                        && s.asset
                            .metadata
                            .get("workspace_snapshot_id")
                            .and_then(serde_json::Value::as_str)
                            == Some(a.source.canonical_snapshot_id.as_str())
                        && s.asset
                            .metadata
                            .get("workspace_snapshot_sha256")
                            .and_then(serde_json::Value::as_str)
                            == Some(a.source.canonical_snapshot_sha256.as_str())
                })
                && crate::source_audit_report::admission(case, task).is_some(),
            BINDING,
        )?;
        let mut members = BTreeSet::new();
        let mut originals = BTreeSet::new();
        for b in &a.artifacts {
            transport::validate_path(&b.member_path).map_err(|_| error(BINDING))?;
            require(
                members.insert(&b.member_path) && originals.insert(&b.artifact_id),
                "archive_original_extra",
            )?;
            require(
                case.raw_artifacts
                    .iter()
                    .filter(|r| r.id == b.artifact_id)
                    .count()
                    <= 1,
                "archive_original_extra",
            )?;
            let raw = case
                .raw_artifacts
                .iter()
                .find(|r| r.id == b.artifact_id)
                .ok_or_else(|| error("archive_original_missing"))?;
            require(
                task.raw_artifact_ids.contains(&b.artifact_id),
                "archive_original_missing",
            )?;
            let expected = format!("{}/{}/{}/{}", case.id, run.id, task.id, b.member_path);
            require(
                raw.case_id == case.id
                    && raw.run_id == run.id
                    && raw.engine_run_id == task.id
                    && raw.relative_path == expected
                    && raw.contains_sensitive_data,
                BINDING,
            )?;
            require(
                raw.sha256 == b.sha256 && raw.byte_length == b.byte_length,
                CONTENT,
            )?;
        }
        require(
            case.raw_artifacts
                .iter()
                .filter(|r| r.engine_run_id == task.id)
                .count()
                == originals.len()
                && task.raw_artifact_ids.len() == originals.len(),
            "archive_original_extra",
        )?;
    }
    for task in case.scan_runs.iter().flat_map(|r| &r.engine_runs) {
        if matches!(task.task_kind, EngineTaskKind::AgentAudit { .. }) {
            require(
                crate::source_audit_report::admission(case, task).is_some(),
                BINDING,
            )?;
        }
    }
    crate::agent_audit_admission::check_bundle(case)
        .map_err(|_| error("archive_evidence_mismatch"))?;
    for a in &case.agent_audit_admissions {
        let mut value = serde_json::to_value(a)?;
        value.as_object_mut().unwrap().remove("admission_sha256");
        require(
            domain_digest(crate::agent_audit_admission::FORMAT_REQUIREMENT, &value)?
                == a.admission_sha256,
            CONTENT,
        )?;
    }
    Ok(())
}

fn member(path: String, sha256: String, byte_length: u64) -> ArchiveEntry {
    ArchiveEntry {
        path,
        sha256,
        byte_length,
    }
}
fn read_member(root: &Path, entry: &ArchiveEntry) -> AppResult<Vec<u8>> {
    transport::validate_path(&entry.path).map_err(|_| error(HISTORY))?;
    let bytes =
        read_private_input(&root.join(&entry.path), MAX_FILE_BYTES).map_err(|_| error(CONTENT))?;
    require(
        digest(&bytes) == entry.sha256 && bytes.len() as u64 == entry.byte_length,
        CONTENT,
    )?;
    Ok(bytes)
}

/// Derive inventories solely from the captured event log and authenticated indexes.
/// Creation reads full sealed packages; archive verification can omit indexed source bodies.
fn inventory(
    root: &Path,
    portable: &PortableCase,
    include_sources: bool,
    omitted: &BTreeSet<String>,
) -> AppResult<History> {
    let case = &portable.case;
    graph(case)?;
    crate::agent_audit_failure::check_custody(case, &portable.historical_events)
        .map_err(|_| error(HISTORY))?;
    let mut receipts = Vec::<(PreparationReceipt, Record)>::new();
    let mut requests = BTreeSet::new();
    let mut sessions = BTreeSet::new();
    let mut views = BTreeMap::<String, SourceViewPreparationReceipt>::new();
    for event in &portable.historical_events {
        if event.event_type == audit::RECEIPT_EVENT {
            require(
                event.payload_json.len() <= audit::record::MAX_ENTRY,
                HISTORY,
            )?;
            let receipt: PreparationReceipt =
                serde_json::from_str(&event.payload_json).map_err(|_| error(HISTORY))?;
            receipt.verify().map_err(|_| error(HISTORY))?;
            require(
                receipt.case_id == case.id
                    && receipt.occurred_at == event.occurred_at
                    && requests.insert(receipt.request_id.clone()),
                HISTORY,
            )?;
            if let PreparationResult::Prepared { facts, .. } = &receipt.result {
                for (kind, id) in [
                    ("session", &facts.session_id),
                    ("run", &facts.provider_run_id),
                    ("task", &facts.provider_task_id),
                ] {
                    require(sessions.insert((kind, id.clone())), HISTORY)?;
                }
            }
            receipts.push((receipt, Record::default()));
        } else if event.event_type == RECORD_EVENT {
            require(
                event.payload_json.len() <= audit::record::MAX_ENTRY,
                HISTORY,
            )?;
            let entry: Entry =
                serde_json::from_str(&event.payload_json).map_err(|_| error(HISTORY))?;
            require(entry.occurred_at == event.occurred_at, HISTORY)?;
            let (receipt, record) = receipts
                .iter_mut()
                .find(|(r, _)| r.session_id() == Some(entry.session_id.as_str()))
                .ok_or_else(|| error(HISTORY))?;
            record
                .push(receipt, entry, event.payload_json.len())
                .map_err(|_| error(HISTORY))?;
        } else if event.event_type == source_view::RECEIPT_EVENT {
            require(
                event.payload_json.len() <= audit::record::MAX_ENTRY,
                HISTORY,
            )?;
            let view: SourceViewPreparationReceipt =
                serde_json::from_str(&event.payload_json).map_err(|_| error(HISTORY))?;
            crate::storage::source_view::validate_receipt(
                &view,
                &case.id,
                event.sequence,
                &event.occurred_at,
            )
            .map_err(|_| error(HISTORY))?;
            require(
                views.insert(view.request_id.clone(), view).is_none(),
                HISTORY,
            )?;
        }
    }
    let mut preparations = Vec::new();
    let mut admitted = BTreeSet::new();
    for (receipt, record) in receipts {
        let (sequence, hash) = record.head(&receipt);
        let mut p = Preparation {
            provider_id: "cloudflare-security-audit".into(),
            preparation_request_id: receipt.request_id.clone(),
            session_id: None,
            provider_run_id: None,
            provider_task_id: None,
            state: State::Blocked,
            recorded_head: Head {
                sequence,
                entry_sha256: hash.into(),
            },
            termination: record.terminated().map(|(entry, reason)| Termination {
                entry_sha256: entry.entry_sha256.clone(),
                occurred_at: entry.occurred_at.clone(),
                reason,
            }),
            outcome_run: case.scan_runs.iter().flat_map(|r| r.engine_runs.iter().map(move |t| (r,t))).find_map(|(r,t)| {
                matches!(&t.task_kind, EngineTaskKind::AgentAuditFailure { outcome, .. } if outcome.preparation_request_id == receipt.request_id)
                    .then(|| OutcomeRun { run_id: r.id.clone(), task_id: t.id.clone() })
            }),
            seal_sha256: None,
            admission_id: None,
            admission_sha256: None,
            descriptor: None,
            package: Vec::new(),
            captured: Vec::new(),
            source_body_omissions: Vec::new(),
            completeness: Completeness {
                recorded_history: true,
                accepted_captures: true,
                sealed_package: false,
                source_bodies: false,
            },
        };
        if let PreparationResult::Prepared {
            facts,
            descriptor_sha256,
        } = &receipt.result
        {
            p.session_id = Some(facts.session_id.clone());
            p.provider_run_id = Some(facts.provider_run_id.clone());
            p.provider_task_id = Some(facts.provider_task_id.clone());
            p.state = State::Unsealed;
            let base = format!(
                "artifacts/{}/cloudflare-sessions/{}",
                case.id, facts.session_id
            );
            let descriptor = member(
                format!("{base}/session.json"),
                descriptor_sha256.clone(),
                canonical_bytes(facts)?.len() as u64,
            );
            require(
                read_member(root, &descriptor)? == canonical_bytes(facts)?,
                HISTORY,
            )?;
            p.descriptor = Some(descriptor);
            p.captured = captured::enumerate(&record)
                .map_err(|_| error(HISTORY))?
                .into_iter()
                .map(|c| Captured {
                    selector: c.selector,
                    role: c.role,
                    sha256: c.sha256,
                    byte_length: c.byte_length,
                    available: c.available,
                    member: c.object_reference.map(|path| format!("{base}/{path}")),
                })
                .collect();
            for c in &p.captured {
                if let Some(path) = &c.member {
                    read_member(root, &member(path.clone(), c.sha256.clone(), c.byte_length))?;
                }
            }
            if let Some((entry, seal)) = record.sealed() {
                p.state = State::Sealed;
                p.seal_sha256 = Some(entry.entry_sha256.clone());
                let view = views
                    .get(&facts.source.source_view_request_id)
                    .ok_or_else(|| error(HISTORY))?;
                let verified = sealed::verify_snapshot(
                    root,
                    &receipt,
                    &record,
                    view,
                    case,
                    omitted.contains(&facts.session_id),
                )
                .map_err(|_| error(HISTORY))?;
                for file in &verified.package_members {
                    let m = member(
                        format!("{base}/sealed/{}/{}", seal.bundle_sha256, file.path),
                        file.sha256.clone(),
                        file.byte_length,
                    );
                    if (!include_sources || omitted.contains(&facts.session_id))
                        && file.path.starts_with("retained/source-view/")
                    {
                        p.source_body_omissions.push(m);
                    } else {
                        p.package.push(m);
                    }
                }
                p.completeness.sealed_package = true;
                p.completeness.source_bodies = p.source_body_omissions.is_empty();
                if let Some(a) = case
                    .agent_audit_admissions
                    .iter()
                    .find(|a| a.identities.session_id == facts.session_id)
                {
                    require(
                        a.preparation_request_id == receipt.request_id
                            && serde_json::to_value(&a.identities)?
                                == serde_json::to_value(&verified.identities)?
                            && serde_json::to_value(&a.digests)?
                                == serde_json::to_value(&verified.digests)?
                            && serde_json::to_value(&a.source)?
                                == serde_json::to_value(&verified.source)?
                            && a.source_view_request_id == verified.source_view_request_id
                            && a.source_id == verified.asset_binding.source_id,
                        BINDING,
                    )?;
                    require(
                        &a.retained_projection == verified.retained_projection(),
                        CONTENT,
                    )?;
                    require(
                        serde_json::to_value(&a.method)? == serde_json::to_value(&verified.method)?
                            && serde_json::to_value(&a.outcome)?
                                == serde_json::to_value(&verified.outcome)?
                            && a.counts_by_role == verified.counts_by_role
                            && a.counts_by_state == verified.counts_by_state
                            && !a.validators_reexecuted
                            && a.verification_scope == "full_payload",
                        BINDING,
                    )?;
                    let expected: BTreeMap<_, _> = verified
                        .package_members
                        .iter()
                        .filter(|m| !m.path.starts_with("retained/source-view/"))
                        .map(|m| (m.path.as_str(), m))
                        .collect();
                    require(
                        a.artifacts.len() >= expected.len(),
                        "archive_original_missing",
                    )?;
                    require(
                        a.artifacts.len() == expected.len(),
                        "archive_original_extra",
                    )?;
                    for b in &a.artifacts {
                        let file = expected
                            .get(b.member_path.as_str())
                            .ok_or_else(|| error("archive_original_extra"))?;
                        require(
                            file.sha256 == b.sha256 && file.byte_length == b.byte_length,
                            CONTENT,
                        )?;
                        read_member(
                            root,
                            &member(
                                format!(
                                    "artifacts/{}/{}/{}/{}",
                                    case.id,
                                    a.identities.run_id,
                                    a.identities.task_id,
                                    b.member_path
                                ),
                                b.sha256.clone(),
                                b.byte_length,
                            ),
                        )?;
                    }
                    p.state = State::Admitted;
                    p.admission_id = Some(a.admission_id.clone());
                    p.admission_sha256 = Some(a.admission_sha256.clone());
                    admitted.insert(a.admission_id.clone());
                }
                verified.recheck_unchanged().map_err(|_| error(HISTORY))?;
            }
        }
        preparations.push(p);
    }
    require(admitted.len() == case.agent_audit_admissions.len(), HISTORY)?;
    // An admission receipt must match the immutable stored admission exactly.
    let mut receipt_ids = BTreeSet::new();
    for event in portable
        .historical_events
        .iter()
        .filter(|e| e.event_type == crate::agent_audit_admission::ADMITTED_EVENT)
    {
        let value: serde_json::Value =
            serde_json::from_str(&event.payload_json).map_err(|_| error(HISTORY))?;
        let a = case
            .agent_audit_admissions
            .iter()
            .find(|a| value["admission_id"] == a.admission_id)
            .ok_or_else(|| error(HISTORY))?;
        require(
            receipt_ids.insert(&a.admission_id)
                && event.occurred_at == a.admitted_at.to_rfc3339()
                && value
                    == a.receipt(
                        value["case_revision"]
                            .as_i64()
                            .ok_or_else(|| error(HISTORY))?,
                    ),
            HISTORY,
        )?;
    }
    require(receipt_ids.len() == admitted.len(), HISTORY)?;
    Ok(History {
        schema_version: SCHEMA.into(),
        preparations,
    })
}

fn members(history: &History) -> impl Iterator<Item = ArchiveEntry> + '_ {
    history.preparations.iter().flat_map(|p| {
        p.descriptor
            .iter()
            .cloned()
            .chain(p.package.iter().cloned())
            .chain(p.captured.iter().filter_map(|c| {
                c.member
                    .as_ref()
                    .map(|path| member(path.clone(), c.sha256.clone(), c.byte_length))
            }))
    })
}

pub(super) fn create(
    root: &Path,
    portable: &PortableCase,
    include_sources: bool,
    builder: &mut Builder,
) -> AppResult<(bool, Vec<String>)> {
    let inherited =
        crate::cloudflare_provider::restored::omitted_sessions(&portable.historical_events)?;
    let history = inventory(root, portable, include_sources, &inherited)?;
    for entry in members(&history) {
        builder.add(&entry.path, &read_member(root, &entry)?)?;
    }
    builder.add(PATH, &serde_json::to_vec(&history)?)?;
    verify(
        builder.directory.path(),
        portable,
        include_sources,
        &builder.entries,
    )?;
    Ok((
        history
            .preparations
            .iter()
            .any(|p| !p.source_body_omissions.is_empty()),
        history.capabilities(),
    ))
}

pub(super) fn verify(
    root: &Path,
    portable: &PortableCase,
    include_sources: bool,
    entries: &BTreeMap<String, ArchiveEntry>,
) -> AppResult<BTreeSet<String>> {
    let bytes = read_private_input(&root.join(PATH), transport::MAX_ARCHIVE_MANIFEST_BYTES)
        .map_err(|_| error(HISTORY))?;
    let history: History = serde_json::from_slice(&bytes).map_err(|_| error(HISTORY))?;
    for p in &history.preparations {
        for omission in &p.source_body_omissions {
            require(!entries.contains_key(&omission.path), OMISSION)?;
        }
    }
    let omitted = history
        .preparations
        .iter()
        .filter(|p| !include_sources || !p.source_body_omissions.is_empty())
        .filter_map(|p| p.session_id.clone())
        .collect();
    let expected = inventory(root, portable, include_sources, &omitted)?;
    require(
        history
            .preparations
            .iter()
            .map(|p| &p.source_body_omissions)
            .eq(expected
                .preparations
                .iter()
                .map(|p| &p.source_body_omissions)),
        OMISSION,
    )?;
    require(history == expected, HISTORY)?;
    let mut referenced = BTreeSet::from([PATH.to_owned()]);
    for entry in members(&history) {
        require(entries.get(&entry.path) == Some(&entry), CONTENT)?;
        referenced.insert(entry.path);
    }
    let prefix = format!("artifacts/{}/cloudflare-sessions/", portable.case.id);
    require(
        entries
            .keys()
            .filter(|p| p.starts_with(&prefix))
            .all(|p| referenced.contains(p)),
        HISTORY,
    )?;
    Ok(referenced)
}
