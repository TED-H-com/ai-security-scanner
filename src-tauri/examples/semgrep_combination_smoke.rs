//! Local-only normalization check; never starts a scanner or reads live cases.
use ai_security_scanner_lib::adapter::{AdapterAssetIdentifierMap, AdapterInput};
use ai_security_scanner_lib::adapters::builtin_adapter_registry;
use ai_security_scanner_lib::domain::{RawArtifact, Severity};
use ai_security_scanner_lib::registry::EngineRegistry;
use chrono::Utc;
use sha2::{Digest, Sha256};
use std::{env, fs, path::PathBuf};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = PathBuf::from(
        env::args_os()
            .nth(1)
            .ok_or("expected synthetic semgrep.json")?,
    );
    let metadata = fs::symlink_metadata(&path)?;
    if !path.is_absolute()
        || path.file_name().and_then(|v| v.to_str()) != Some("semgrep.json")
        || !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() > 16 * 1024 * 1024
    {
        return Err("expected bounded regular absolute semgrep.json".into());
    }
    let bytes = fs::read(&path)?;
    let native: serde_json::Value = serde_json::from_slice(&bytes)?;
    let rows = native["results"].as_array().ok_or("missing results")?;
    if !native["errors"]
        .as_array()
        .ok_or("missing errors")?
        .is_empty()
    {
        return Err("native scan has errors".into());
    }
    let engines = EngineRegistry::load_builtin()?;
    let mut manifest = engines.get("semgrep").ok_or("missing Semgrep")?.clone();
    // This is direct CE execution with a candidate rule pack, not a new image.
    manifest.image = None;
    manifest.rule_version = Some("legacy-0f5a85c+product-four-local-preview".into());
    let artifact_root = path.parent().ok_or("no parent")?.canonicalize()?;
    let artifacts = vec![RawArtifact {
        id: "synthetic-semgrep-artifact".into(),
        case_id: "synthetic-case".into(),
        run_id: "synthetic-run".into(),
        engine_run_id: "synthetic-semgrep-run".into(),
        relative_path: "semgrep.json".into(),
        media_type: "application/json".into(),
        sha256: hex::encode(Sha256::digest(&bytes)),
        byte_length: bytes.len() as u64,
        created_at: Utc::now(),
        contains_sensitive_data: false,
    }];
    let assets = vec!["synthetic-repository".into()];
    let identifiers = AdapterAssetIdentifierMap::default();
    let input = AdapterInput {
        case_id: "synthetic-case",
        scan_run_id: "synthetic-run",
        engine_run_id: "synthetic-semgrep-run",
        manifest: &manifest,
        ai_system_applicable: false,
        ai_generated_artifact_applicable: false,
        asset_ids: &assets,
        asset_identifier_map: &identifiers,
        artifact_root: &artifact_root,
        raw_artifacts: &artifacts,
    };
    let output = builtin_adapter_registry()?
        .normalize(&input)?
        .ok_or("no adapter")?;
    if !output.warnings.is_empty() || output.findings.len() != rows.len() {
        return Err(format!(
            "normalization differs: {} vs {}, {:?}",
            output.findings.len(),
            rows.len(),
            output.warnings
        )
        .into());
    }
    for row in rows {
        let rule = row["check_id"].as_str().ok_or("missing rule")?;
        let line = row["start"]["line"].as_u64().ok_or("missing line")?;
        let col = row["start"]["col"].as_u64().ok_or("missing column")?;
        let native_path = row["path"].as_str().ok_or("missing path")?;
        let display_path = native_path
            .strip_prefix("/workspace/")
            .ok_or("outside fixture workspace")?;
        let location = format!("{display_path}:line={line}:column={col}");
        let finding = output
            .findings
            .iter()
            .find(|finding| {
                finding.evidence.iter().any(|evidence| {
                    evidence.source_rule.as_deref() == Some(rule)
                        && evidence.location.as_deref() == Some(&location)
                })
            })
            .ok_or_else(|| format!("rule/location not preserved: {rule} / {location}"))?;
        let severity = match row["extra"]["severity"].as_str() {
            Some("ERROR") => Severity::High,
            Some("WARNING") => Severity::Medium,
            Some("INFO") => Severity::Informational,
            _ => return Err("unexpected native severity".into()),
        };
        if finding.severity != severity
            || finding.title
                != row["extra"]["message"]
                    .as_str()
                    .ok_or("missing message")?
                    .chars()
                    .take(512)
                    .collect::<String>()
                    .trim()
            || finding.asset_ids != assets
            || finding
                .evidence
                .iter()
                .any(|evidence| evidence.artifact_sha256 != artifacts[0].sha256)
        {
            return Err("native meaning, asset or evidence hash changed".into());
        }
    }
    println!(
        "{}",
        serde_json::json!({"native_results": rows.len(), "normalized_findings": output.findings.len(), "warnings": output.warnings, "ids_locations_bounded_titles_severity_and_evidence_verified": true, "native_messages_over_title_bound": rows.iter().filter(|r| r["extra"]["message"].as_str().is_some_and(|s| s.chars().count() > 512)).count(), "local_experiment_only": true})
    );
    Ok(())
}
