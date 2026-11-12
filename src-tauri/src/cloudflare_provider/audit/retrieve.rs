//! Offline captured-byte recovery: no initialization, lease, event, or authority.
use super::{captured, *};
use crate::storage::Storage;

pub struct Request<'a> {
    pub case_id: &'a str,
    pub session_id: &'a str,
    pub selector: captured::Selector,
    pub destination: &'a Path,
    pub expected_sha256: Option<&'a str>,
    pub expected_head_sha256: Option<&'a str>,
}

/// Filled as facts become known, including when retrieval subsequently fails.
#[derive(Default, Serialize)]
pub struct Observation {
    pub run_id: Option<String>,
    pub task_id: Option<String>,
    pub observed_head_sha256: Option<String>,
    pub sha256: Option<String>,
    pub byte_length: Option<u64>,
}

pub fn retrieve(
    data: &Path,
    product_roots: &[PathBuf],
    request: &Request<'_>,
    observed: &mut Observation,
) -> AppResult<PathBuf> {
    if !valid_id(request.case_id)
        || !valid_id(request.session_id)
        || [request.expected_sha256, request.expected_head_sha256]
            .iter()
            .flatten()
            .any(|h| !valid_hash(h))
    {
        return Err(invalid("invalid retrieval identity or digest"));
    }
    let mut forbidden = product_roots.to_vec();
    forbidden.push(data.to_owned());
    let destination =
        super::super::retained::RetrievalDestination::prepare(request.destination, &forbidden)?;
    let storage = Storage::open_read_only_no_wait(data.join("casework.db"))?;
    let snapshot = storage.cloudflare_captured_snapshot(request.case_id, request.session_id)?;
    let receipt = &snapshot.receipt;
    let PreparationResult::Prepared { facts, .. } = &receipt.result else {
        return Err(invalid("retrieval requires recorded preparation"));
    };
    observed.run_id = Some(facts.provider_run_id.clone());
    observed.task_id = Some(facts.provider_task_id.clone());
    let (_, head) = snapshot.record.head(receipt);
    observed.observed_head_sha256 = Some(head.into());
    if request.expected_head_sha256.is_some_and(|h| h != head) {
        return Err(AppError::Conflict(
            "captured history head differs from expectation".into(),
        ));
    }
    let entry = captured::enumerate(&snapshot.record)?
        .into_iter()
        .find(|e| e.selector == request.selector)
        .ok_or_else(|| invalid("unknown captured selector"))?;
    observed.sha256 = Some(entry.sha256.clone());
    observed.byte_length = Some(entry.byte_length);
    if !entry.available {
        return Err(invalid("discarded output bytes are unavailable"));
    }
    if request.expected_sha256.is_some_and(|h| h != entry.sha256) {
        return Err(invalid("expected digest differs from captured digest"));
    }
    if descriptor_state(data, receipt) != DescriptorState::Verified {
        return Err(AppError::Storage(
            "captured audit descriptor missing or corrupt".into(),
        ));
    }
    let bytes = io::read_object(data, receipt, &entry.sha256, entry.byte_length)?;
    destination.publish(&bytes, || {
        if descriptor_state(data, receipt) != DescriptorState::Verified {
            return Err(AppError::Storage(
                "captured audit descriptor changed".into(),
            ));
        }
        snapshot.recheck(&storage)
    })
}
