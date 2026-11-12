//! Opaque source/task ZIP downloads for a frozen selected-run report.
use crate::domain::{AssessmentCase, CombinedOriginalFiles};
use crate::error::{AppError, AppResult};
use crate::export::ExportOptions;
use crate::report_renderer::HtmlReportAttachment;
use crate::selected_run_report::{MAX_DOCUMENT_BYTES, SelectedRunReport};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CombinedAttachment {
    pub run_id: String,
    pub attachment: HtmlReportAttachment,
}

pub(crate) fn prepare(
    case: &AssessmentCase,
    ids: &[String],
    options: &ExportOptions,
    root: &Path,
) -> AppResult<(Vec<CombinedAttachment>, CombinedOriginalFiles)> {
    let mut files = 0usize;
    let mut bytes = 0u64;
    let mut excluded = 0usize;
    for id in ids {
        let selected = crate::report_attachments::selected_artifacts_unbounded(case, id, options)?;
        files = files.checked_add(selected.len()).ok_or_else(limit)?;
        for artifact in &selected {
            bytes = bytes.checked_add(artifact.byte_length).ok_or_else(limit)?;
        }
        excluded += case
            .raw_artifacts
            .iter()
            .filter(|artifact| &artifact.run_id == id)
            .count()
            - selected.len();
    }
    let mut summary = CombinedOriginalFiles {
        included_files: files,
        omitted_files: 0,
        sensitive_files_excluded: excluded,
        omission_reason: None,
        archive_file_name: None,
    };
    if bytes > 64 * 1024 * 1024 || files > 10_000 {
        omit(&mut summary, "original_file_limit");
        return Ok((Vec::new(), summary));
    }
    let mut attachments = Vec::new();
    for id in ids {
        for attachment in crate::report_attachments::build_attachments(case, id, options, root)? {
            attachments.push(CombinedAttachment {
                run_id: id.clone(),
                attachment: attachment.into(),
            });
        }
    }
    Ok((attachments, summary))
}

pub(crate) fn omit(summary: &mut CombinedOriginalFiles, reason: &str) {
    summary.omitted_files += summary.included_files;
    summary.included_files = 0;
    summary.omission_reason = Some(reason.into());
}

pub(crate) fn render(
    report: &SelectedRunReport,
    options: &ExportOptions,
    attachments: &[CombinedAttachment],
) -> AppResult<Vec<u8>> {
    let mut html = crate::selected_run_report::render_html(report, options.locale)?;
    if let Some(summary) = &report.original_files {
        let zh = options.locale == crate::export::ReportLocale::ZhHant;
        let mut section = format!(
            "<section><h2>{}</h2><p>{}: {} · {}: {}</p>",
            if zh { "原始檔案" } else { "Original files" },
            if zh { "已附檔案" } else { "Included files" },
            summary.included_files,
            if zh {
                "遮罩設定排除的敏感檔案"
            } else {
                "Sensitive files excluded by redaction"
            },
            summary.sensitive_files_excluded
        );
        if summary.omitted_files > 0 {
            section.push_str(&format!("<p>{} {}. {}</p>", summary.omitted_files,
                if zh { "個原始檔案超出附檔容量，請由私密案件封存取回" } else { "original files exceed the attachment budget; retrieve them from the private case archive" },
                if zh { "案件封存可能包含敏感資料，請勿連同報告分享。" } else { "The case archive may contain sensitive data; keep it private when sharing the report." }));
            if let Some(name) = &summary.archive_file_name {
                section.push_str(&format!("<p><code>{}</code></p>", escape(name)));
            }
        }
        for entry in attachments {
            let a = &entry.attachment;
            // Each download has an independent source/task namespace. Files
            // inside retain upstream relative directories and original bytes.
            let filename = format!("{}-{}.zip", entry.run_id, a.engine_run_id);
            section.push_str(&format!("<details><summary>{} · {} · {}</summary><p>{}</p><a download=\"{}\" href=\"data:application/zip;base64,{}\">{}</a><p>SHA-256: <code>{}</code></p></details>",
                escape(&entry.run_id), escape(crate::report_attachments::audit_label(&a.engine_id, zh).unwrap_or(&a.engine_id)), a.file_names.len(),
                if zh { "下載並解壓縮整個 ZIP，再開啟其中的原始報告。" } else { "Download and extract the entire ZIP before opening an original report." },
                escape(&filename), STANDARD.encode(&a.bytes), if zh { "下載原始檔案" } else { "Download originals" }, escape(&a.sha256)));
        }
        section.push_str("</section>");
        let position = html
            .find("<footer>")
            .ok_or_else(|| AppError::Internal("combined report footer missing".into()))?;
        html.insert_str(position, &section);
    }
    Ok(html.into_bytes())
}

pub(crate) fn exceeds_document_budget(html: &[u8], json: &[u8]) -> bool {
    html.len() > MAX_DOCUMENT_BYTES || json.len() > MAX_DOCUMENT_BYTES
}
fn escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
fn limit() -> AppError {
    AppError::InvalidRequest("combined original file inventory is too large".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn file_budget_is_shared_across_sources_before_any_file_is_read() {
        let mut case = crate::demo::build_demo_case();
        let template = case.raw_artifacts[0].clone();
        let run = case.scan_runs[0].clone();
        case.scan_runs.clear();
        case.raw_artifacts.clear();
        let mut ids = Vec::new();
        for source in 0..2 {
            let mut next = run.clone();
            next.id = format!("source-{source}");
            next.engine_runs.truncate(1);
            let task = &mut next.engine_runs[0];
            task.id = format!("task-{source}");
            task.scan_run_id = next.id.clone();
            task.raw_artifact_ids.clear();
            for file in 0..5001 {
                let mut artifact = template.clone();
                artifact.id = format!("raw-{source}-{file}");
                artifact.case_id = case.id.clone();
                artifact.run_id = next.id.clone();
                artifact.engine_run_id = task.id.clone();
                artifact.relative_path = format!("{}/{}/{}/{file}.txt", case.id, next.id, task.id);
                artifact.byte_length = 1;
                artifact.contains_sensitive_data = false;
                task.raw_artifact_ids.push(artifact.id.clone());
                case.raw_artifacts.push(artifact);
            }
            ids.push(next.id.clone());
            case.scan_runs.push(next);
        }
        let root = tempfile::tempdir().unwrap();
        let options = ExportOptions {
            include_raw_artifacts: true,
            ..Default::default()
        };
        let (entries, summary) = prepare(&case, &ids, &options, root.path()).unwrap();
        assert!(entries.is_empty());
        assert_eq!(summary.omitted_files, 10_002);
        assert_eq!(summary.included_files, 0);
        assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
    }
}
