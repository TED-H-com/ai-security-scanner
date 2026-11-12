//! Bounded single-document validation, not audit execution or finding admission.
pub mod audit;
pub mod bundle;
mod bundle_io;
pub mod restored;
pub mod retained;
pub mod source_view;
mod strict_json;
use crate::case_archive_io::{private_tempdir_in, read_bounded_regular};
use crate::error::{AppError, AppResult};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};

pub const UPSTREAM_COMMIT: &str = "c1c8a8c1471069fb0e188eeaff69b8e8db6564a8";
const MAX_INPUT_BYTES: u64 = 5 * 1024 * 1024;
const MAX_OUTPUT_BYTES: u64 = 256 * 1024;
const TIMEOUT: Duration = Duration::from_secs(15);
const RESOURCES: &[(&str, &[u8])] = &[
    (
        "validate-document.cjs",
        include_bytes!("../../providers/cloudflare/validate-document.cjs"),
    ),
    (
        "upstream/LICENSE",
        include_bytes!("../../providers/cloudflare/upstream/LICENSE"),
    ),
    (
        "upstream/skills/security-audit/report-schema.json",
        include_bytes!(
            "../../providers/cloudflare/upstream/skills/security-audit/report-schema.json"
        ),
    ),
    (
        "upstream/skills/security-audit/validate-findings.cjs",
        include_bytes!(
            "../../providers/cloudflare/upstream/skills/security-audit/validate-findings.cjs"
        ),
    ),
    (
        "upstream/skills/security-audit/validate-coverage-ledger.cjs",
        include_bytes!(
            "../../providers/cloudflare/upstream/skills/security-audit/validate-coverage-ledger.cjs"
        ),
    ),
];

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CloudflareDocument {
    Findings,
    CoverageLedger,
}

impl CloudflareDocument {
    fn as_str(self) -> &'static str {
        match self {
            Self::Findings => "findings",
            Self::CoverageLedger => "coverage-ledger",
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DocumentValidation {
    pub valid: bool,
    pub phase: String,
    pub errors: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct CloudflareValidationReceipt {
    pub schema_version: &'static str,
    pub provider: &'static str,
    pub upstream_commit: &'static str,
    pub document: CloudflareDocument,
    pub validation_scope: &'static str,
    pub input_sha256: String,
    pub input_byte_length: u64,
    pub validator_resources_sha256: String,
    pub validation: DocumentValidation,
    pub audit_performed: bool,
    pub admission_ready: bool,
}

fn invalid(message: impl Into<String>) -> AppError {
    AppError::InvalidRequest(format!(
        "Cloudflare document validation: {}",
        message.into()
    ))
}

fn node_executable() -> AppResult<PathBuf> {
    let name = if cfg!(windows) { "node.exe" } else { "node" };
    let paths = std::env::var_os("PATH").unwrap_or_default();
    for directory in std::env::split_paths(&paths).filter(|path| path.is_absolute()) {
        let candidate = directory.join(name);
        if candidate.is_file() {
            return Ok(crate::internal_paths::canonicalize(candidate)?);
        }
    }
    Err(AppError::NotAvailable(
        "Cloudflare document validation requires Node.js on an absolute PATH entry".into(),
    ))
}

fn resources_digest() -> String {
    let mut hash = Sha256::new();
    for (name, bytes) in RESOURCES {
        hash.update((name.len() as u64).to_le_bytes());
        hash.update(name.as_bytes());
        hash.update((bytes.len() as u64).to_le_bytes());
        hash.update(bytes);
    }
    hex::encode(hash.finalize())
}

pub async fn validate_document(
    document: CloudflareDocument,
    input: &Path,
) -> AppResult<CloudflareValidationReceipt> {
    let bytes = read_bounded_regular(input, MAX_INPUT_BYTES)?;
    validate_bytes(document, &bytes).await
}

async fn validate_bytes(
    document: CloudflareDocument,
    bytes: &[u8],
) -> AppResult<CloudflareValidationReceipt> {
    if bytes.len() as u64 > MAX_INPUT_BYTES {
        return Err(invalid("input exceeds 5 MiB"));
    }
    std::str::from_utf8(bytes).map_err(|_| invalid("input is not valid UTF-8"))?;
    let node = node_executable()?;
    let temporary_parent = crate::internal_paths::canonicalize(std::env::temp_dir())?;
    let staging = private_tempdir_in(&temporary_parent, "scanner-cloudflare-").map_err(
        |error| match error {
            AppError::UnsafeArchiveParent => AppError::UnsafeTemporaryDirectory,
            other => other,
        },
    )?;
    for (relative, contents) in RESOURCES {
        let destination = staging.path().join(relative);
        std::fs::create_dir_all(destination.parent().expect("embedded resource parent"))?;
        std::fs::write(destination, contents)?;
    }
    let validation = execute_validator(&node, staging.path(), document, bytes, TIMEOUT).await?;
    Ok(CloudflareValidationReceipt {
        schema_version: "ai-security-scanner.cloudflare-document-validation/v1",
        provider: "cloudflare-security-audit",
        upstream_commit: UPSTREAM_COMMIT,
        document,
        validation_scope: "single_document",
        input_sha256: hex::encode(Sha256::digest(bytes)),
        input_byte_length: bytes.len() as u64,
        validator_resources_sha256: resources_digest(),
        validation,
        audit_performed: false,
        admission_ready: false,
    })
}

async fn capture(mut reader: impl AsyncRead + Unpin) -> AppResult<Vec<u8>> {
    let mut bytes = Vec::new();
    (&mut reader)
        .take(MAX_OUTPUT_BYTES + 1)
        .read_to_end(&mut bytes)
        .await?;
    if bytes.len() as u64 > MAX_OUTPUT_BYTES {
        return Err(invalid("validator output exceeded its byte limit"));
    }
    Ok(bytes)
}

async fn execute_validator(
    node: &Path,
    staging: &Path,
    document: CloudflareDocument,
    bytes: &[u8],
    timeout: Duration,
) -> AppResult<DocumentValidation> {
    let node = crate::internal_paths::canonicalize(node)?;
    let staging = crate::internal_paths::canonicalize(staging)?;
    let script = crate::internal_paths::canonicalize(staging.join("validate-document.cjs"))?;
    let mut command = tokio::process::Command::new(node);
    command
        .env_clear()
        .current_dir(&staging)
        .args([
            "--max-old-space-size=128",
            "--no-addons",
            "--no-global-search-paths",
        ])
        .arg(script)
        .arg(document.as_str())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    // Node options, module paths and dynamic loader variables never cross this
    // boundary. Windows needs only its OS directory for normal process startup.
    #[cfg(windows)]
    for name in ["SystemRoot", "WINDIR"] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    let mut child = command
        .spawn()
        .map_err(|error| invalid(format!("could not start Node.js: {error}")))?;
    let mut stdin = child.stdin.take().expect("piped stdin");
    let stdout = child.stdout.take().expect("piped stdout");
    let stderr = child.stderr.take().expect("piped stderr");
    let result = tokio::time::timeout(timeout, async {
        let write = async {
            stdin.write_all(bytes).await?;
            stdin.shutdown().await?;
            // shutdown alone does not drop the parent handle on every platform.
            drop(stdin);
            Ok::<(), AppError>(())
        };
        tokio::try_join!(write, capture(stdout), capture(stderr), async {
            child.wait().await.map_err(AppError::from)
        })
    })
    .await;
    let completed = match result {
        Ok(Ok(completed)) => completed,
        failure => {
            let _ = child.start_kill();
            if !matches!(
                tokio::time::timeout(Duration::from_secs(2), child.wait()).await,
                Ok(Ok(_))
            ) {
                return Err(invalid(
                    "validator cleanup did not complete within its time limit",
                ));
            }
            return Err(match failure {
                Ok(Err(error)) => error,
                Err(_) => invalid("validator exceeded its 15-second execution limit"),
                Ok(Ok(_)) => unreachable!(),
            });
        }
    };
    let ((), stdout, stderr, status) = completed;
    if !status.success() || !stderr.is_empty() {
        // Diagnostics from a failed host runtime are not trusted input output.
        return Err(invalid("Node.js validator did not complete successfully"));
    }
    let result: DocumentValidation = serde_json::from_slice(&stdout)
        .map_err(|_| invalid("validator returned an invalid response"))?;
    if !matches!(
        result.phase.as_str(),
        "input" | "preflight" | "parse" | "upstream"
    ) || result.errors.len() > 100
        || result.valid != result.errors.is_empty()
        || (result.valid && result.phase != "upstream")
    {
        return Err(invalid("validator returned an inconsistent response"));
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn stalled_input_and_unbounded_outputs_are_terminated() {
        let node = node_executable().expect("Node.js required for provider tests");
        let temporary = tempfile::tempdir().unwrap();
        let script = temporary.path().join("validate-document.cjs");
        let marker = temporary.path().join("pid");
        for (source, expected) in [
            ("setInterval(() => {}, 1000)", "execution limit"),
            (
                "process.stdout.write('x'.repeat(300000)); setInterval(() => {}, 1000)",
                "output exceeded",
            ),
            (
                "process.stderr.write('x'.repeat(300000)); setInterval(() => {}, 1000)",
                "output exceeded",
            ),
        ] {
            std::fs::write(
                &script,
                format!(
                    "require('node:fs').writeFileSync({}, String(process.pid)); {source}",
                    serde_json::to_string(&marker).unwrap()
                ),
            )
            .unwrap();
            let started = std::time::Instant::now();
            let result = execute_validator(
                &node,
                temporary.path(),
                CloudflareDocument::Findings,
                &vec![b' '; MAX_INPUT_BYTES as usize],
                Duration::from_secs(2),
            )
            .await;
            assert!(result.unwrap_err().to_string().contains(expected));
            assert!(started.elapsed() < Duration::from_secs(6));
            let pid = std::fs::read_to_string(&marker).expect("owned validator actually started");
            #[cfg(unix)]
            {
                // SAFETY: signal zero only inspects the owned child's process ID.
                assert_eq!(unsafe { libc::kill(pid.parse().unwrap(), 0) }, -1);
                assert_eq!(
                    std::io::Error::last_os_error().raw_os_error(),
                    Some(libc::ESRCH)
                );
            }
            #[cfg(not(unix))]
            assert!(pid.parse::<u32>().unwrap() > 0);
            std::fs::remove_file(&marker).unwrap();
        }
    }
}
