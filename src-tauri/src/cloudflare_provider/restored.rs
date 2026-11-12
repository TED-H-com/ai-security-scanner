//! Restore boundaries are event order, never current authorization or filesystem state.
use crate::error::{AppError, AppResult};
use crate::storage::{CaseEvent, Storage};

pub fn is_restored(
    events: &[CaseEvent],
    event_type: &str,
    id: &str,
    session: bool,
) -> AppResult<bool> {
    let boundary = events
        .iter()
        .filter(|e| e.event_type == "case.restored")
        .map(|e| e.sequence)
        .max()
        .unwrap_or(0);
    for event in events
        .iter()
        .filter(|e| e.event_type == event_type && e.sequence < boundary)
    {
        let value: serde_json::Value = serde_json::from_str(&event.payload_json)?;
        let identity = if session {
            &value["result"]["facts"]["session_id"]
        } else {
            &value["request_id"]
        };
        if identity.as_str() == Some(id) {
            return Ok(true);
        }
    }
    Ok(false)
}

pub(crate) fn guard(
    storage: &Storage,
    case_id: &str,
    event_type: &str,
    id: &str,
    session: bool,
) -> AppResult<()> {
    if storage.latest_case_restore_sequence(case_id)?.is_none() {
        return Ok(());
    }
    if is_restored(&storage.list_case_events(case_id)?, event_type, id, session)? {
        return Err(AppError::RestoredSessionInert);
    }
    Ok(())
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProviderHistory {
    pub schema_version: String,
    pub history_sha256: String,
    pub source_bodies_omitted_sessions: Vec<String>,
}
impl ProviderHistory {
    pub(crate) fn validate(&self) -> AppResult<()> {
        if self.schema_version != "ai-security-scanner.restored-provider-history/v1"
            || !super::source_view::valid_hash(&self.history_sha256)
            || self
                .source_bodies_omitted_sessions
                .iter()
                .any(|id| !super::source_view::valid_id(id))
            || self
                .source_bodies_omitted_sessions
                .windows(2)
                .any(|w| w[0] >= w[1])
        {
            return Err(AppError::Storage(
                "invalid restored provider history".into(),
            ));
        }
        Ok(())
    }
}

pub(crate) fn omitted_sessions(
    events: &[CaseEvent],
) -> AppResult<std::collections::BTreeSet<String>> {
    let Some(event) = events
        .iter()
        .filter(|e| e.event_type == "case.restored")
        .max_by_key(|e| e.sequence)
    else {
        return Ok(Default::default());
    };
    let payload: serde_json::Value = serde_json::from_str(&event.payload_json)?;
    let Some(value) = payload.get("provider_history") else {
        return Ok(Default::default());
    };
    let history: ProviderHistory = serde_json::from_value(value.clone())?;
    history.validate()?;
    history
        .source_bodies_omitted_sessions
        .into_iter()
        .filter_map(
            |id| match is_restored(events, super::audit::RECEIPT_EVENT, &id, true) {
                Ok(true) => Some(Ok(id)),
                Ok(false) => None,
                Err(e) => Some(Err(e)),
            },
        )
        .collect()
}

pub const SOURCE_NOTICE: &str = "Source snapshots were not included in the archive this case was restored from; source bytes cannot be rechecked here.";

pub struct Context {
    pub restored: bool,
    pub sources_omitted: bool,
}
impl Context {
    pub fn load(storage: &Storage, receipt: &super::audit::PreparationReceipt) -> AppResult<Self> {
        if storage
            .latest_case_restore_sequence(&receipt.case_id)?
            .is_none()
        {
            return Ok(Self {
                restored: false,
                sources_omitted: false,
            });
        }
        let events = storage.list_case_events(&receipt.case_id)?;
        let omitted = omitted_sessions(&events)?;
        Ok(Self {
            restored: is_restored(
                &events,
                super::audit::RECEIPT_EVENT,
                &receipt.request_id,
                false,
            )?,
            sources_omitted: receipt.session_id().is_some_and(|id| omitted.contains(id)),
        })
    }
    pub fn present(&self, result: &mut serde_json::Value, sealed: bool) {
        use serde_json::json;
        if !self.restored {
            return;
        }
        result["restored"] = json!(true);
        if result.get("outcome_run").is_some() {
            result["next_operation"] = serde_json::Value::Null;
        }
        if sealed {
            result["next_operation"] = if result["report_snapshot_state"] == "retained" {
                json!("retrieve_report")
            } else {
                serde_json::Value::Null
            };
        } else if result["next_operation"].is_object() {
            result["next_operation"]["available"] = json!(false);
            result["next_operation"]["sealing"]["available"] = json!(false);
        }
        for key in ["document_capture", "assignment_output_capture"] {
            if result.get(key).is_some() {
                result[key]["available"] = json!(false);
            }
        }
        if self.sources_omitted {
            result["source_snapshot_notice"] = json!(SOURCE_NOTICE);
        }
    }
}
