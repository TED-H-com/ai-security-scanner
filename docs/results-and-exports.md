# Read and share your results

[繁體中文](results-and-exports.zh-TW.md) · [Documentation](README.md)

When a scan finishes or stops, open **Results**. Start with the summary: which systems or files need attention, what matters first and what to do next. While a scan is running, follow it in **Scan progress**.

## Understand each result

| What the report says | What it means |
| --- | --- |
| Problems found | A security check found at least one issue affecting this item. Open it to see the evidence and suggested next step. |
| No problems in completed checks | The checks that finished found no problems within their stated scope. This does not rule out every possible risk. |
| Incomplete or failed | Some requested checks did not finish. Results from completed checks are still available. |
| Not tested | No applicable security check finished for this item. |

The report may also list services, open ports or installed software. These help describe what you have; they are not counted as vulnerabilities.

## Decide what to do first

Read the highest-priority problems first. For each one, the report explains what is affected, why it matters and a practical next step. When available, it also explains how to verify a fix or undo a change.

If someone else will investigate, expand the technical details. They contain the original scanner, rule number, evidence, severity rating and recommendation. “Unknown” means the tool did not provide a severity rating; it does not mean the problem is minor.

The app provides guidance. It does not apply fixes to your systems.

## Check what is still missing

Look at **What was actually tested** and **What was not tested**. A report can contain useful findings even when some work is unfinished. A successful connection or a list of systems does not mean a security check ran.

For unfinished checks, follow the next step shown in the app. Some need a new sign-in or different input before they can run.

## Return later and compare

Open **My scans** to return to a project. Its targets, findings, evidence and report history stay available. Select the scan you want before reading or exporting the report.

When two scans can be compared, the app shows which problems are new, still present or resolved. It marks results that cannot be compared, so missing coverage is not mistaken for a fix.

## Save a report to share

From **Results**, choose **Save or share report**, then **HTML report (recommended)**. Keep sensitive identifiers hidden unless the recipient needs them. Save the file and open it in a browser to check it before sharing.

The report uses the app language, English or Traditional Chinese. It follows the same order as the screen. Technical evidence is available in expandable sections, with formal terms at the end. Saving the report creates a local file; it does not send it to anyone.

To keep the original reports in that same HTML file, turn off **Hide sensitive identifiers** and select **Attach original reports at the end**. The final section offers one ZIP per scanner check. Download and extract the entire ZIP to open its original reports with their images and other supporting files. Tools that did not produce an HTML report may have JSON, XML or logs instead; unfinished checks keep their recorded status. Original files may contain sensitive information.

Keep the HTML when sharing attachments: printing or saving it as a PDF does not include them. The HTML attachment limit is 64 MiB of original files or 10,000 files; use a technical case bundle for larger collections.

<details>
<summary>Formats for technical teams</summary>

- JSON keeps the product's structured report data.
- OCSF provides findings in a common security-data format.
- OSCAL and framework reports include reviewed control references where a mapping exists.
- A case bundle contains the selected project data and evidence allowed by its export options.

All formats use the same finished or stopped scan. SHA-256 hashes identify the exported files. CLI HTML exports use English by default; choose `--locale en` for English or `--locale zh-Hant` for Traditional Chinese. The scan facts remain the same.

</details>
