//! Capture only named shared documents; the record owns revision and byte accounting.
use super::{record::*, *};
use crate::cloudflare_provider::{CloudflareDocument, bundle_io::BundleRoot, validate_bytes};
use std::collections::{BTreeMap, BTreeSet};

use crate::cloudflare_provider::bundle::{REQUIRED as NAMES, metadata_binding_matches};
pub const MAX_CAPTURED: u64 = 512 * 1024 * 1024;
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocumentSpec {
    pub name: String,
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
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocumentRevision {
    pub name: String,
    pub revision: u64,
    pub sha256: String,
    pub byte_length: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validator_resources_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid: Option<bool>,
}
#[derive(Debug, Clone, Serialize)]
pub struct DocumentState {
    pub current: DocumentRevision,
    pub accepted_at: String,
    pub revision_count: u64,
}
pub(super) fn bound(name: &str) -> Option<u64> {
    Some(match name {
        "run-metadata.json" => 1024 * 1024,
        "coverage-ledger.json" | "findings.json" => 5 * 1024 * 1024,
        "architecture.md" | "REPORT.md" | "FINDINGS-DETAIL.md" | "NEEDS-VALIDATION.md" => {
            8 * 1024 * 1024
        }
        _ => return None,
    })
}
fn validator(name: &str) -> Option<CloudflareDocument> {
    match name {
        "coverage-ledger.json" => Some(CloudflareDocument::CoverageLedger),
        "findings.json" => Some(CloudflareDocument::Findings),
        _ => None,
    }
}
fn specifications(specs: &[DocumentSpec]) -> Result<(), Refusal> {
    if specs.is_empty() || specs.len() > 7 {
        return Err(Refusal::DocumentBatchLimit);
    }
    let mut seen = BTreeSet::new();
    for s in specs {
        if bound(&s.name).is_none()
            || !seen.insert(&s.name)
            || s.sha256.as_ref().is_some_and(|s| !valid_hash(s))
        {
            return Err(Refusal::DocumentInvalid);
        }
    }
    Ok(())
}
pub(super) fn capture(
    facts: &Prepared,
    specs: &[DocumentSpec],
) -> AppResult<Result<Vec<Vec<u8>>, CheckpointOutcome>> {
    if let Err(code) = specifications(specs) {
        return Ok(Err(if code == Refusal::DocumentInvalid {
            let index = (0..specs.len())
                .find(|i| specifications(&specs[..=*i]).is_err())
                .unwrap();
            CheckpointOutcome::DocumentRejected {
                error_code: code,
                document: specs[index].name.clone(),
                validation: None,
            }
        } else {
            CheckpointOutcome::refused(code)
        }));
    }
    let mut root = match capture_root(facts) {
        Ok(root) => root,
        Err(outcome) => return Ok(Err(*outcome)),
    };
    let mut captured = Vec::new();
    for s in specs {
        let fail = |code| CheckpointOutcome::DocumentRejected {
            error_code: code,
            document: s.name.clone(),
            validation: None,
        };
        let bytes = match capture_file(
            &mut root,
            &s.name,
            bound(&s.name).unwrap(),
            s.sha256.as_deref(),
            s.byte_length,
        ) {
            Ok(bytes) => bytes,
            Err(code) => return Ok(Err(fail(code))),
        };
        if std::str::from_utf8(&bytes).is_err() {
            return Ok(Err(fail(Refusal::DocumentInvalid)));
        }
        if s.name == "run-metadata.json" {
            let metadata = match super::super::strict_json::parse(&bytes) {
                Ok(value) if value.is_object() => value,
                _ => return Ok(Err(fail(Refusal::DocumentInvalid))),
            };
            if !metadata_binding_matches(
                &metadata,
                &facts.provider_run_id,
                &facts.source.source_ref,
            ) || metadata.get("profile") != Some(&serde_json::to_value(facts.profile)?)
                || metadata.get("budget") != Some(&serde_json::to_value(facts.invocation_budget)?)
            {
                return Ok(Err(fail(Refusal::MetadataBindingMismatch)));
            }
        }
        captured.push(bytes);
    }
    if root.verify_unchanged().is_err() {
        return Ok(Err(CheckpointOutcome::DocumentRejected {
            error_code: Refusal::DocumentUnreadable,
            document: specs.last().unwrap().name.clone(),
            validation: None,
        }));
    }
    for (spec, bytes) in specs.iter().zip(&captured) {
        if let Some(kind) = validator(&spec.name) {
            let receipt = validate(kind, bytes)?;
            if !receipt.validation.valid {
                return Ok(Err(CheckpointOutcome::DocumentRejected {
                    error_code: Refusal::DocumentInvalid,
                    document: spec.name.clone(),
                    validation: Some(receipt.validation),
                }));
            }
        }
    }
    Ok(Ok(captured))
}
pub(super) fn mint(
    record: &Record,
    specs: &[DocumentSpec],
    captured: &[Vec<u8>],
) -> Result<Content, Refusal> {
    specifications(specs)?;
    captured_limit(
        record.captured,
        captured.iter().map(|b| b.len() as u64),
        MAX_CAPTURED,
    )?;
    let documents = specs
        .iter()
        .zip(captured)
        .map(|(s, b)| DocumentRevision {
            name: s.name.clone(),
            revision: record
                .documents
                .get(&s.name)
                .map_or(1, |s| s.revision_count + 1),
            sha256: digest(b),
            byte_length: b.len() as u64,
            validator_resources_sha256: validator(&s.name)
                .map(|_| super::super::resources_digest()),
            valid: validator(&s.name).map(|_| true),
        })
        .collect();
    Ok(Content::SubmitDocuments {
        requested_documents: specs.to_vec(),
        documents,
    })
}
impl Record {
    pub fn document_status(&self) -> BTreeMap<&str, Option<&DocumentState>> {
        NAMES
            .iter()
            .map(|name| (*name, self.documents.get(*name)))
            .collect()
    }
    pub fn captured_bytes(&self) -> serde_json::Value {
        serde_json::json!({"limit":MAX_CAPTURED,"used":self.captured})
    }
    pub(super) fn push_documents(
        &mut self,
        specs: &[DocumentSpec],
        documents: &[DocumentRevision],
        time: &str,
        resources: &str,
    ) -> AppResult<()> {
        let bad = || AppError::Storage("audit document revisions invalid".into());
        specifications(specs).map_err(|_| bad())?;
        if specs.len() != documents.len() {
            return Err(bad());
        }
        for (s, d) in specs.iter().zip(documents) {
            if d.valid != validator(&s.name).map(|_| true)
                || d.validator_resources_sha256.as_deref() != validator(&s.name).map(|_| resources)
                || s.name != d.name
                || !valid_hash(&d.sha256)
                || d.byte_length > bound(&d.name).unwrap()
                || d.revision
                    != self
                        .documents
                        .get(&d.name)
                        .map_or(1, |s| s.revision_count + 1)
                || s.sha256.as_ref().is_some_and(|h| *h != d.sha256)
                || s.byte_length.is_some_and(|n| n != d.byte_length)
            {
                return Err(bad());
            }
        }
        let used = captured_limit(
            self.captured,
            documents.iter().map(|d| d.byte_length),
            MAX_CAPTURED,
        )
        .map_err(|_| bad())?;
        for d in documents {
            self.documents.insert(
                d.name.clone(),
                DocumentState {
                    current: d.clone(),
                    accepted_at: time.into(),
                    revision_count: d.revision,
                },
            );
        }
        self.captured = used;
        Ok(())
    }
}

pub(super) fn captured_limit(
    used: u64,
    lengths: impl IntoIterator<Item = u64>,
    limit: u64,
) -> Result<u64, Refusal> {
    lengths.into_iter().try_fold(used, |total, length| {
        total
            .checked_add(length)
            .filter(|n| *n <= limit)
            .ok_or(Refusal::CapturedBytesLimit)
    })
}
pub(super) fn capture_root(facts: &Prepared) -> Result<BundleRoot, Box<CheckpointOutcome>> {
    BundleRoot::open(&facts.run_directory).map_err(|_| {
        Box::new(CheckpointOutcome::Rejected {
            error_code: Refusal::SavedReceiptNotCurrent,
            reason: Some(BlockerCode::RunDirectoryUnavailable),
        })
    })
}
pub(super) fn capture_file(
    root: &mut BundleRoot,
    path: &str,
    limit: u64,
    sha256: Option<&str>,
    length: Option<u64>,
) -> Result<Vec<u8>, Refusal> {
    let bytes = root
        .read(path, limit)
        .map_err(|_| Refusal::DocumentUnreadable)?;
    if sha256.is_some_and(|h| h != digest(&bytes))
        || length.is_some_and(|n| n != bytes.len() as u64)
    {
        return Err(Refusal::DocumentMismatch);
    }
    Ok(bytes)
}

pub(super) fn validate(
    kind: CloudflareDocument,
    bytes: &[u8],
) -> AppResult<super::super::CloudflareValidationReceipt> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(validate_bytes(kind, bytes))
        .map_err(|error| match error {
            AppError::NotAvailable(_) | AppError::UnsafeTemporaryDirectory => error,
            _ => AppError::Runtime(error.to_string()),
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn captured_byte_limit_counts_repeated_revisions_and_rejects_overflow() {
        assert_eq!(captured_limit(0, [4, 4], 8), Ok(8));
        assert_eq!(captured_limit(4, [4], 8), Ok(8));
        assert_eq!(
            captured_limit(4, [4, 1], 8),
            Err(Refusal::CapturedBytesLimit)
        );
        assert_eq!(
            captured_limit(u64::MAX, [1], u64::MAX),
            Err(Refusal::CapturedBytesLimit)
        );
    }
}
