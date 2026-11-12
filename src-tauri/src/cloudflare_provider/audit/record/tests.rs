use super::*;
fn receipt() -> PreparationReceipt {
    serde_json::from_value(serde_json::json!({
        "schema_version": RECEIPT_SCHEMA, "request_id":"prepare", "request_sha256":"a".repeat(64),
        "case_id":"case", "asset_id":"asset", "occurred_at":"2026-01-01T00:00:00Z",
        "case_revision":1,"sequence":0,"predecessor_sha256":null,"receipt_sha256":"b".repeat(64),
        "result":{"status":"prepared","descriptor_sha256":"c".repeat(64),"facts":{
            "session_id":"run","provider_run_id":"run","provider_task_id":"task","attempt_id":"attempt",
            "prepared_at":"2026-01-01T00:00:00Z","source":{"source_view_request_id":"view", "source_view_receipt_sha256":"a",
            "view_id":"view","view_sha256":"a","canonical_snapshot_id":"snapshot","canonical_snapshot_sha256":"a",
            "policy_id":"policy","scope":["."],"source_ref":"source","grant_sha256":"a","acknowledgement_sha256":"a"},
            "upstream_commit":"a","validator_resources_sha256":"a","profile":"quick","invocation_budget":null,
            "applied_floor":6,"host":{"host_id":"host","delegation":"available"},"run_directory":"/unused","target_execution_allowed":false
        }}
    })).unwrap()
}
fn entry(sequence: u64, predecessor: &str) -> Entry {
    let mut e = Entry {
        schema_version: ENTRY_SCHEMA.into(),
        case_id: "case".into(),
        session_id: "run".into(),
        request_id: format!("request{sequence}"),
        request_sha256: "a".repeat(64),
        case_revision: sequence as i64 + 1,
        sequence,
        predecessor_sha256: predecessor.into(),
        occurred_at: "2026-01-01T00:00:00Z".into(),
        content: Content::Issue {
            assignments: vec![Assignment {
                assignment_id: format!("id{sequence}"),
                agent_id: format!("a{sequence:04}-recon"),
                ordinal: sequence,
                issued_at: "2026-01-01T00:00:00Z".into(),
                findings_revision: None,
                bound_record_sha256: None,
                spec: AssignmentSpec {
                    role: Role::ReconnaissanceBaseline,
                    wave: None,
                    fingerprint: None,
                    replaces: None,
                },
            }],
        },
        entry_sha256: String::new(),
    };
    e.request_sha256 = e.request_digest().unwrap();
    e.entry_sha256 = e.content_digest().unwrap();
    e
}
#[test]
fn chain_checks_digests_order_links_identity_and_deletions() {
    let receipt = receipt();
    let one = entry(1, &receipt.receipt_sha256);
    let two = entry(2, &one.entry_sha256);
    let three = entry(3, &two.entry_sha256);
    let mut good = Record::default();
    for e in [&one, &two, &three] {
        good.push(&receipt, e.clone(), 100).unwrap();
    }
    assert_eq!(good.head(&receipt).0, 3);
    for kind in [
        "digest",
        "identity",
        "predecessor",
        "sequence",
        "ordinal",
        "agent",
    ] {
        let mut e = one.clone();
        match kind {
            "digest" => e.occurred_at = "2026-01-02T00:00:00Z".into(),
            "identity" => e.session_id = "other".into(),
            "predecessor" => e.predecessor_sha256 = "0".repeat(64),
            "sequence" => e.sequence = 2,
            "request" => e.request_sha256 = "d".repeat(64),
            _ => {
                if let Content::Issue { assignments } = &mut e.content {
                    if kind == "ordinal" {
                        assignments[0].ordinal = 2;
                    } else {
                        assignments[0].agent_id = "supplied".into();
                    }
                }
            }
        }
        if kind != "digest" {
            e.entry_sha256 = e.content_digest().unwrap();
        }
        assert!(Record::default().push(&receipt, e, 100).is_err(), "{kind}");
    }
    let mut missing = Record::default();
    missing.push(&receipt, one, 100).unwrap();
    assert!(missing.push(&receipt, three, 100).is_err());
    assert!(Record::default().push(&receipt, two, 100).is_err());
}
#[test]
fn entry_count_and_byte_limits_include_exact_boundaries() {
    assert!(entry_limits(4095, MAX_ENTRY, MAX_RECORD - MAX_ENTRY).is_ok());
    assert_eq!(entry_limits(4096, 0, 0), Err(Refusal::RecordEntryLimit));
    assert_eq!(
        entry_limits(0, MAX_ENTRY + 1, 0),
        Err(Refusal::EntryBytesLimit)
    );
    assert_eq!(
        entry_limits(0, MAX_ENTRY, MAX_RECORD - MAX_ENTRY + 1),
        Err(Refusal::RecordBytesLimit)
    );
    assert_eq!(
        entry_limits(0, 1, usize::MAX),
        Err(Refusal::RecordBytesLimit)
    );
}

#[test]
fn changed_prepared_validator_digest_blocks_new_actions_and_replay() {
    let mut receipt = receipt();
    let mut record = Record::default();
    let saved = entry(1, &receipt.receipt_sha256);
    record.push(&receipt, saved.clone(), 100).unwrap();
    let request: CheckpointRequest = serde_json::from_value(serde_json::json!({
        "schema_version": CHECKPOINT_SCHEMA, "request_id":saved.request_id, "case_id":receipt.case_id,
        "session_id":receipt.session_id(),"expected_head_sha256":receipt.receipt_sha256,
        "action":{"type":"issue","assignments":[{"role":"reconnaissance_baseline"}]}
    })).unwrap();
    let PreparationResult::Prepared { facts, .. } = &mut receipt.result else {
        panic!()
    };
    facts.validator_resources_sha256 = super::super::super::resources_digest();
    assert!(super::super::checkpoint::validator_current(facts).is_none());
    facts.validator_resources_sha256 = "0".repeat(64);
    for action in [
        request.action.clone(),
        Action::Interrupt {
            assignment_id: "id1".into(),
            reason: "stop".into(),
        },
        Action::SubmitDocuments { documents: vec![] },
        Action::SubmitOutput {
            assignment_id: "id1".into(),
            output: OutputSpec {
                path: "unused".into(),
                sha256: None,
                byte_length: None,
            },
        },
    ] {
        let mut r = request.clone();
        if !matches!(action, Action::Issue { .. }) {
            r.request_id = "new".into();
        }
        r.action = action;
        let PreparationResult::Prepared { facts, .. } = &receipt.result else {
            panic!()
        };
        let outcome = record
            .precheck(&receipt, &r.record_request().unwrap(), || {
                Ok(super::super::checkpoint::validator_current(facts))
            })
            .unwrap();
        assert!(matches!(
            outcome,
            Some(CheckpointOutcome::Rejected {
                error_code: Refusal::SavedReceiptNotCurrent,
                reason: Some(BlockerCode::ValidatorResourcesChanged)
            })
        ));
    }
    assert_eq!(record.entries.len(), 1);
}

#[test]
fn output_byte_accounting_shares_document_limit_and_closes_only_once() {
    use super::super::{
        documents::MAX_CAPTURED,
        outputs::{self, Disposition},
    };
    let receipt = receipt();
    let mut record = Record::default();
    record
        .push(&receipt, entry(1, &receipt.receipt_sha256), 100)
        .unwrap();
    let spec = OutputSpec {
        path: "agents/a0001-recon/artifacts/result.txt".into(),
        sha256: None,
        byte_length: None,
    };
    let output = AssignmentOutput {
        disposition: Disposition::Accepted,
        path: spec.path.clone(),
        sha256: digest(b"ok"),
        byte_length: 2,
        reason: None,
        decision: None,
        returned_fingerprint: None,
        record_sha256: None,
    };
    record.captured = MAX_CAPTURED - 1;
    assert_eq!(
        outputs::mint(&record, "id1", &spec, &output).unwrap_err(),
        Refusal::CapturedBytesLimit
    );
    record.captured = MAX_CAPTURED - 2;
    record
        .push_output("id1", &spec, &output, "2026-01-01T00:01:00Z")
        .unwrap();
    assert_eq!(record.captured, MAX_CAPTURED);
    assert_eq!(record.assignments[0].state, "closed");
    assert_eq!(
        outputs::mint(&record, "id1", &spec, &output).unwrap_err(),
        Refusal::AssignmentClosed
    );
}

#[test]
fn terminal_manifest_generation_is_deterministic() {
    let receipt = receipt();
    let PreparationResult::Prepared { facts, .. } = &receipt.result else {
        unreachable!()
    };
    let fixture: serde_json::Value = serde_json::from_slice(
        &std::fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../tests/fixtures/cloudflare/bundle/provider-manifest.json"),
        )
        .unwrap(),
    )
    .unwrap();
    let source: crate::cloudflare_provider::bundle::SourceView =
        serde_json::from_value(fixture["source"].clone()).unwrap();
    let records: serde_json::Value = serde_json::from_slice(
        &std::fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../tests/fixtures/cloudflare/bundle/findings.json"),
        )
        .unwrap(),
    )
    .unwrap();
    let generate = || {
        super::super::manifest::generate(
            &receipt,
            facts,
            &Record::default(),
            source.clone(),
            &records,
            &serde_json::json!([]),
        )
        .unwrap()
    };
    let first = generate();
    assert_eq!(
        canonical_bytes(&first).unwrap(),
        canonical_bytes(&generate()).unwrap()
    );
    assert_eq!(first.reported_counts.confirmed, 1);
    assert_eq!(first.reported_counts.needs_validation, 1);
    assert_eq!(first.reported_counts.rejected, 1);
    assert!(first.verifier_assignments.is_empty());
    assert_eq!(first.binding.run_id, facts.provider_run_id);
}

#[test]
fn captured_history_preserves_revisions_unselected_outputs_and_discarded_metadata() {
    use super::super::captured::{Selector, enumerate};
    use super::super::outputs::Disposition;
    let receipt = receipt();
    let mut record = Record::default();
    let append = |record: &mut Record, content: Content| {
        let (sequence, head) = record.head(&receipt);
        let mut e = entry(sequence + 1, head);
        e.content = content;
        e.request_sha256 = e.request_digest().unwrap();
        e.entry_sha256 = e.content_digest().unwrap();
        let length = serde_json::to_vec(&e).unwrap().len();
        record.push(&receipt, e, length).unwrap();
    };
    for revision in 1..=2 {
        append(
            &mut record,
            Content::SubmitDocuments {
                requested_documents: vec![DocumentSpec {
                    name: "REPORT.md".into(),
                    sha256: None,
                    byte_length: None,
                }],
                documents: vec![DocumentRevision {
                    name: "REPORT.md".into(),
                    revision,
                    sha256: format!("{revision:064x}"),
                    byte_length: revision,
                    validator_resources_sha256: None,
                    valid: None,
                }],
            },
        );
    }
    for (ordinal, role, disposition) in [
        (1, Role::ReconnaissanceBaseline, Disposition::Accepted),
        (2, Role::Hunter, Disposition::Accepted),
        (3, Role::CandidateVerifier, Disposition::Discarded),
    ] {
        let id = format!("assignment{ordinal}");
        let agent_id = format!("a{ordinal:04}-{}", role.word());
        append(
            &mut record,
            Content::Issue {
                assignments: vec![Assignment {
                    assignment_id: id.clone(),
                    agent_id: agent_id.clone(),
                    ordinal,
                    issued_at: "2026-01-01T00:00:00Z".into(),
                    findings_revision: None,
                    bound_record_sha256: None,
                    spec: AssignmentSpec {
                        role,
                        wave: None,
                        fingerprint: None,
                        replaces: None,
                    },
                }],
            },
        );
        let path = format!("agents/{agent_id}/artifacts/output");
        append(
            &mut record,
            Content::SubmitOutput {
                assignment_id: id,
                requested_output: OutputSpec {
                    path: path.clone(),
                    sha256: None,
                    byte_length: None,
                },
                output: AssignmentOutput {
                    path,
                    sha256: format!("{ordinal:064x}"),
                    byte_length: 10,
                    reason: (disposition == Disposition::Discarded)
                        .then_some(Refusal::OutputInvalid),
                    disposition,
                    decision: None,
                    returned_fingerprint: None,
                    record_sha256: None,
                },
            },
        );
    }
    let history = enumerate(&record).unwrap();
    assert_eq!(history.len(), 5);
    for revision in 1..=2 {
        let d = &history[revision as usize - 1];
        assert_eq!(
            d.selector,
            Selector::Document {
                name: "REPORT.md".into(),
                revision
            }
        );
        assert_eq!(d.byte_length, revision);
        assert_eq!(d.object_reference, Some(format!("objects/{revision:064x}")));
    }
    assert!(history[2].available && history[3].available);
    assert_eq!(history[3].role, Some(Role::Hunter));
    assert!(!history[4].available);
    assert!(history[4].object_reference.is_none());
    assert_eq!(history[4].byte_length, 10);
    // Enumeration depends only on events, never even on the derived current maps.
    record.documents.clear();
    record.assignments.clear();
    assert_eq!(
        serde_json::to_value(enumerate(&record).unwrap()).unwrap(),
        serde_json::to_value(history).unwrap()
    );
}

#[test]
fn captured_history_rejects_oversize_lengths_before_any_object_read() {
    use super::super::captured::enumerate;
    let receipt = receipt();
    let mut e = entry(1, &receipt.receipt_sha256);
    e.content = Content::SubmitDocuments {
        requested_documents: vec![DocumentSpec {
            name: "REPORT.md".into(),
            sha256: None,
            byte_length: None,
        }],
        documents: vec![DocumentRevision {
            name: "REPORT.md".into(),
            revision: 1,
            sha256: "a".repeat(64),
            byte_length: u64::MAX,
            validator_resources_sha256: None,
            valid: None,
        }],
    };
    e.request_sha256 = e.request_digest().unwrap();
    e.entry_sha256 = e.content_digest().unwrap();
    assert!(Record::default().push(&receipt, e.clone(), 100).is_err());
    let record = Record {
        entries: vec![e],
        ..Record::default()
    };
    assert!(enumerate(&record).is_err());
}

#[test]
fn termination_reserves_one_bounded_entry_and_preserves_full_chain() {
    for byte_full in [false, true] {
        let receipt = receipt();
        let mut record = Record::default();
        let count = if byte_full { 4 } else { 4096 };
        for revision in 1..=count {
            let mut e = entry(revision, record.head(&receipt).1);
            e.content = Content::SubmitDocuments {
                requested_documents: vec![DocumentSpec {
                    name: "REPORT.md".into(),
                    sha256: None,
                    byte_length: None,
                }],
                documents: vec![DocumentRevision {
                    name: "REPORT.md".into(),
                    revision,
                    sha256: "a".repeat(64),
                    byte_length: 0,
                    validator_resources_sha256: None,
                    valid: None,
                }],
            };
            e.request_sha256 = e.request_digest().unwrap();
            e.entry_sha256 = e.content_digest().unwrap();
            let bytes = if byte_full { MAX_ENTRY } else { 100 };
            record.push(&receipt, e, bytes).unwrap();
        }
        let mut e = entry(count + 1, record.head(&receipt).1);
        e.content = Content::Terminated {
            reason: TerminationReason::WorkflowFailed,
        };
        e.request_sha256 = e.request_digest().unwrap();
        e.entry_sha256 = e.content_digest().unwrap();
        assert!(
            record
                .push(&receipt, e.clone(), MAX_TERMINAL_ENTRY + 1)
                .is_err()
        );
        record
            .push(&receipt, e.clone(), MAX_TERMINAL_ENTRY)
            .unwrap();
        assert!(matches!(
            record.ensure_active(),
            Err(AppError::RunTerminated)
        ));
        assert_eq!(record.documents["REPORT.md"].current.revision, count);
        assert_eq!(
            super::super::captured::enumerate(&record).unwrap().len(),
            count as usize
        );
        assert!(record.push(&receipt, e, 1).is_err());
        assert_eq!(record.entries.len(), count as usize + 1);
    }
    assert!(record_limits(4096, MAX_TERMINAL_ENTRY, MAX_RECORD, true).is_ok());
    assert!(record_limits(4097, 1, 0, true).is_err());
    assert!(record_limits(0, 1, MAX_RECORD + 1, true).is_err());
}
