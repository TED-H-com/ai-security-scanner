use super::{BlockerCode as B, Ending, Outcome, TerminationReason as T};
use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Description {
    pub summary: String,
    pub reason: String,
    pub next_action: String,
}
// Product-owned bilingual sentences. Indices below are selected only by typed codes.
#[rustfmt::skip]
const TEXT: &[(&str, &str)] = &[
    ("The Cloudflare source audit did not start.", "Cloudflare 原始碼稽核未開始。"),
    ("The Cloudflare source audit ended before completion.", "Cloudflare 原始碼稽核未完成即結束。"),
    ("No source audit was performed for this asset.", "此資產未執行原始碼稽核。"),
    ("The source audit ended before completion; no audit results are available for this asset.", "原始碼稽核未完成即結束，此資產沒有可用的稽核結果。"),
    ("The audit was stopped before completion.", "稽核在完成前已停止。"),
    ("Start a new source audit when ready.", "準備好後開始新的原始碼稽核。"),
    ("The audit was interrupted.", "稽核流程中斷。"),
    ("Start a new source audit.", "開始新的原始碼稽核。"),
    ("The audit used its full invocation budget.", "稽核已用完呼叫預算。"),
    ("Start a new source audit with a larger budget.", "以較高的預算開始新的原始碼稽核。"),
    ("Source authorization was no longer available.", "原始碼授權已失效。"),
    ("Confirm source authorization, then start a new source audit.", "確認原始碼授權後，開始新的原始碼稽核。"),
    ("Files needed to finish the audit were unavailable.", "完成稽核所需的檔案無法取得。"),
    ("The audit workflow could not finish.", "稽核流程無法完成。"),
    ("The approved source snapshot was missing, not ready or changed.", "核准的原始碼快照遺失、尚未就緒或已變更。"),
    ("Prepare a new source snapshot, then start a new source audit.", "重新準備原始碼快照後，開始新的原始碼稽核。"),
    ("The audit was started from a different assistant than the approved one.", "啟動稽核的助理與核准的助理不同。"),
    ("Start a new source audit from the approved assistant.", "從核准的助理開始新的原始碼稽核。"),
    ("Independent review agents were not available.", "無法使用獨立審查代理。"),
    ("Use an assistant that supports independent agents, then start a new source audit.", "改用支援獨立代理的助理，再開始新的原始碼稽核。"),
    ("The invocation budget was too small for this audit.", "呼叫預算不足以進行此稽核。"),
    ("Source authorization was missing, expired or changed.", "原始碼授權缺失、已過期或已變更。"),
    ("The audit working folder was unavailable.", "稽核工作資料夾無法使用。"),
    ("Provide a new empty working folder, then start a new source audit.", "提供新的空白工作資料夾，再開始新的原始碼稽核。"),
    ("The scanner's pinned audit resources did not match.", "掃描工具固定的稽核資源不一致。"),
    ("Repair the scanner installation, then start a new source audit.", "修復掃描工具安裝後，開始新的原始碼稽核。"),
];
impl Outcome {
    pub fn description(&self) -> Description {
        let (reason, action) = match &self.ending {
            Ending::Terminated { reason, .. } => match reason {
                T::HostCancelled => (4, 5),
                T::HostInterrupted => (6, 7),
                T::BudgetExhausted => (8, 9),
                T::AuthorizationUnavailable => (10, 11),
                T::RequiredArtifactsUnavailable => (12, 7),
                T::WorkflowFailed => (13, 7),
            },
            Ending::Blocked { reasons } => match reasons[0] {
                B::SourceViewNotReady
                | B::ViewMissing
                | B::ViewIntegrityFailed
                | B::SnapshotIntegrityFailed
                | B::SourceBindingMismatch => (14, 15),
                B::HostMismatch => (16, 17),
                B::DelegationUnavailable => (18, 19),
                B::BudgetCannotFundReconnaissanceAndReserves => (20, 9),
                B::SourceAuthorizationMissing | B::SourceAuthorizationExpired | B::GrantChanged => {
                    (21, 11)
                }
                B::RunDirectoryUnavailable => (22, 23),
                B::ValidatorResourcesChanged => (24, 25),
            },
        };
        Description {
            summary: TEXT[usize::from(matches!(self.ending, Ending::Terminated { .. }))]
                .0
                .into(),
            reason: TEXT[reason].0.into(),
            next_action: TEXT[action].0.into(),
        }
    }
    pub fn gap(&self) -> &'static str {
        TEXT[2 + usize::from(matches!(self.ending, Ending::Terminated { .. }))].0
    }
}
pub fn translate(english: &str) -> Option<&'static str> {
    TEXT.iter()
        .find(|(en, _)| *en == english)
        .map(|(_, zh)| *zh)
}
