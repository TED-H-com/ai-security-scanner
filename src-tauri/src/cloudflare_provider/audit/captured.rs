//! Pure inventory of validated custody events, independent of storage and live authority.
use super::{documents, outputs, record::*};
use crate::error::{AppError, AppResult};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Selector {
    Document { name: String, revision: u64 },
    Assignment { assignment_id: String },
}

#[derive(Debug, Clone, Serialize)]
pub struct CapturedEntry {
    pub selector: Selector,
    pub role: Option<Role>,
    pub sha256: String,
    pub byte_length: u64,
    /// Relative to the prepared audit directory; absent for discarded output.
    pub object_reference: Option<String>,
    pub available: bool,
}

/// The caller supplies a record validated with `Record::push` and its verified receipt.
/// Superseded documents and all accepted outputs remain custody, even when a seal
/// selects only a subset. Directory contents and derived current-state maps play no part.
pub fn enumerate(record: &Record) -> AppResult<Vec<CapturedEntry>> {
    let mut assignments = BTreeMap::new();
    let mut entries = Vec::new();
    let mut used = 0;
    let bad = || AppError::Storage("invalid captured history bounds or assignment".into());
    for entry in &record.entries {
        match &entry.content {
            Content::Issue {
                assignments: issued,
            } => {
                for assignment in issued {
                    assignments.insert(&assignment.assignment_id, assignment.spec.role);
                }
            }
            Content::SubmitDocuments {
                documents: revisions,
                ..
            } => {
                for revision in revisions {
                    if documents::bound(&revision.name).is_none_or(|n| revision.byte_length > n) {
                        return Err(bad());
                    }
                    entries.push(CapturedEntry {
                        selector: Selector::Document {
                            name: revision.name.clone(),
                            revision: revision.revision,
                        },
                        role: None,
                        sha256: revision.sha256.clone(),
                        byte_length: revision.byte_length,
                        object_reference: Some(format!("objects/{}", revision.sha256)),
                        available: true,
                    });
                    used = documents::captured_limit(
                        used,
                        [revision.byte_length],
                        documents::MAX_CAPTURED,
                    )
                    .map_err(|_| bad())?;
                }
            }
            Content::SubmitOutput {
                assignment_id,
                output,
                ..
            } => {
                let role = *assignments.get(assignment_id).ok_or_else(bad)?;
                if output.byte_length > outputs::bound(role) {
                    return Err(bad());
                }
                let available = output.disposition == outputs::Disposition::Accepted;
                entries.push(CapturedEntry {
                    selector: Selector::Assignment {
                        assignment_id: assignment_id.clone(),
                    },
                    role: Some(role),
                    sha256: output.sha256.clone(),
                    byte_length: output.byte_length,
                    object_reference: available.then(|| format!("objects/{}", output.sha256)),
                    available,
                });
                used =
                    documents::captured_limit(used, [output.byte_length], documents::MAX_CAPTURED)
                        .map_err(|_| bad())?;
            }
            _ => {}
        }
    }
    Ok(entries)
}
