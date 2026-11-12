//! Deterministic terminal index derived from captured documents and assignment custody.
use super::{outputs::Disposition, record::*, *};
use crate::cloudflare_provider::bundle::{
    self, AuditBinding, BundleFile, BundleManifest, ReportedVerifierAssignment, SourceView,
};
use crate::provider_report::ProviderReportedCounts;
use serde_json::Value;
use std::collections::BTreeMap;

/// Each named owner and whether the ledger attributes evidence to it.
pub(super) fn owners(ledger: &Value) -> BTreeMap<&str, bool> {
    let mut owners = BTreeMap::new();
    for unit in ledger.as_array().into_iter().flatten() {
        for attempt in
            std::iter::once(unit).chain(unit["attempts"].as_array().into_iter().flatten())
        {
            if let Some(id) = attempt["agent_id"].as_str() {
                let evidence = matches!(
                    attempt["status"].as_str(),
                    Some("blocked" | "covered" | "candidate")
                );
                *owners.entry(id).or_default() |= evidence;
            }
            for check in attempt["local_checks"].as_array().into_iter().flatten() {
                if let Some(id) = check["agent_id"].as_str() {
                    owners.insert(id, true);
                }
            }
        }
    }
    owners
}

pub(super) fn generate(
    receipt: &PreparationReceipt,
    facts: &Prepared,
    record: &Record,
    source: SourceView,
    findings: &Value,
    ledger: &Value,
) -> AppResult<BundleManifest> {
    let binding = AuditBinding {
        case_id: receipt.case_id.clone(),
        asset_id: receipt.asset_id.clone(),
        run_id: facts.provider_run_id.clone(),
        task_id: facts.provider_task_id.clone(),
        session_id: facts.session_id.clone(),
        attempt_id: facts.attempt_id.clone(),
    };
    let mut verifiers = Vec::new();
    let mut counts = ProviderReportedCounts::default();
    for finding in findings.as_array().into_iter().flatten() {
        let fingerprint = finding["fingerprint"].as_str().unwrap_or_default();
        let digest = bundle::record_digest(finding)?;
        let verdict = finding["verdict"].as_str().unwrap_or_default();
        match verdict {
            "confirmed" => {
                counts.confirmed += 1;
                let severity =
                    serde_json::from_value(finding["severity"]["overall_severity"].clone())?;
                *counts
                    .reported_confirmed_by_severity
                    .entry(severity)
                    .or_default() += 1;
            }
            "needs_validation" => counts.needs_validation += 1,
            "rejected" => counts.rejected += 1,
            _ => {}
        }
        for role in [Role::CandidateVerifier, Role::FinalVerifier] {
            if role == Role::FinalVerifier
                && (matches!(facts.profile, Profile::Quick)
                    || !matches!(verdict, "confirmed" | "needs_validation"))
            {
                continue;
            }
            let selected = record.assignments.iter().rev().find(|a| {
                a.state == "closed"
                    && a.assignment.spec.role == role
                    && a.assignment.spec.fingerprint.as_deref() == Some(fingerprint)
                    && a.output.as_ref().is_some_and(|o| {
                        o.disposition == Disposition::Accepted
                            && o.returned_fingerprint.as_deref() == Some(fingerprint)
                            && (role != Role::FinalVerifier
                                || (o.decision.as_deref() == Some("verified")
                                    && a.assignment.bound_record_sha256.as_deref()
                                        == Some(&digest)))
                    })
            });
            if let Some(a) = selected {
                let output = a.output.as_ref().unwrap();
                let time = |value: &str| {
                    chrono::DateTime::parse_from_rfc3339(value)
                        .map(|t| t.with_timezone(&chrono::Utc))
                        .map_err(|_| AppError::Storage("invalid assignment time".into()))
                };
                verifiers.push(ReportedVerifierAssignment {
                    assignment_id: a.assignment.assignment_id.clone(),
                    binding: binding.clone(),
                    agent_id: a.assignment.agent_id.clone(),
                    role: serde_json::to_value(role)?.as_str().unwrap().into(),
                    fingerprint: fingerprint.into(),
                    view_sha256: facts.source.view_sha256.clone(),
                    record_sha256: output.record_sha256.clone().unwrap(),
                    output_path: output.path.clone(),
                    started_at: time(&a.assignment.issued_at)?,
                    finished_at: time(a.closed_at.as_deref().unwrap())?,
                });
            }
        }
    }
    let owners = owners(ledger);
    let mut files: Vec<_> = record
        .documents
        .values()
        .map(|d| BundleFile {
            path: d.current.name.clone(),
            sha256: d.current.sha256.clone(),
            byte_length: d.current.byte_length,
        })
        .collect();
    for a in &record.assignments {
        if a.state == "closed"
            && (owners.contains_key(a.assignment.agent_id.as_str())
                || verifiers
                    .iter()
                    .any(|v| v.assignment_id == a.assignment.assignment_id))
        {
            let output = a.output.as_ref().unwrap();
            files.push(BundleFile {
                path: output.path.clone(),
                sha256: output.sha256.clone(),
                byte_length: output.byte_length,
            });
        }
    }
    files.sort_by(|a, b| a.path.cmp(&b.path));
    verifiers.sort_by(|a, b| (&a.fingerprint, &a.role).cmp(&(&b.fingerprint, &b.role)));
    Ok(BundleManifest {
        schema_version: "ai-security-scanner.cloudflare-bundle/v1".into(),
        provider_id: "cloudflare-security-audit".into(),
        upstream_commit: facts.upstream_commit.clone(),
        binding,
        source,
        files,
        verifier_assignments: verifiers,
        reported_counts: counts,
    })
}
