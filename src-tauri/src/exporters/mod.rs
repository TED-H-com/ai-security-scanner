pub mod framework_report;
pub mod ocsf;
pub mod oscal;

use crate::domain::{AssessmentCase, EngineRunStatus, ScanRun};
use crate::error::{AppError, AppResult};

pub use framework_report::{export_master_framework_report, export_master_framework_report_bytes};
pub use ocsf::{export_ocsf_finding_events, export_ocsf_finding_events_bytes};
pub use oscal::{export_oscal_assessment_results, export_oscal_assessment_results_bytes};

fn run_is_terminal(run: &ScanRun) -> bool {
    run.is_terminal_no_checks()
        || (run.engine_runs.is_empty() && run.completed_at.is_some())
        || (!run.engine_runs.is_empty()
            && run.engine_runs.iter().all(|engine_run| {
                matches!(
                    engine_run.status,
                    EngineRunStatus::NotExecuted
                        | EngineRunStatus::Completed
                        | EngineRunStatus::PartiallyCompleted
                        | EngineRunStatus::Failed
                        | EngineRunStatus::Cancelled
                )
            }))
}

fn terminal_run<'a>(case: &'a AssessmentCase, run_id: &str) -> AppResult<&'a ScanRun> {
    let run = case
        .scan_runs
        .iter()
        .find(|run| run.id == run_id)
        .ok_or_else(|| AppError::InvalidRequest(format!("scan run not found: {run_id}")))?;
    if run.case_id != case.id {
        return Err(AppError::InvalidRequest(
            "scan run does not belong to the selected case".into(),
        ));
    }
    if !run_is_terminal(run) {
        return Err(AppError::NotAvailable("scan is in progress".into()));
    }
    Ok(run)
}
