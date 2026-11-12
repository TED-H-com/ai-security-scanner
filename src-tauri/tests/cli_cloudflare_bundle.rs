#![cfg(feature = "cli")]
use ai_security_scanner_lib::cloudflare_provider::bundle::{BundleFile, file_index_digest};
use ai_security_scanner_lib::process_lease::DataDirectoryExclusiveLease;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

struct Fixture {
    _temporary: tempfile::TempDir,
    bundle: PathBuf,
    view: PathBuf,
    data: PathBuf,
}
fn copy_tree(source: &Path, destination: &Path) {
    fs::create_dir_all(destination).unwrap();
    for entry in fs::read_dir(source).unwrap() {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &destination.join(entry.file_name()));
        } else {
            fs::copy(entry.path(), destination.join(entry.file_name())).unwrap();
        }
    }
}
fn fixture() -> Fixture {
    let builder = tempfile::Builder::new();
    #[cfg(unix)]
    let builder = {
        use std::os::unix::fs::PermissionsExt;
        let mut builder = builder;
        builder.permissions(fs::Permissions::from_mode(0o700));
        builder
    };
    let temporary = builder.tempdir().unwrap();
    let root = paths::canonical(temporary.path());
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("../tests/fixtures/cloudflare");
    copy_tree(&source.join("bundle"), &root.join("bundle"));
    copy_tree(&source.join("source-view"), &root.join("view"));
    Fixture {
        _temporary: temporary,
        bundle: root.join("bundle"),
        view: root.join("view"),
        data: root.join("data"),
    }
}

fn provider_command() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_ai-security-scanner-cli"));
    command.args(["--json", "provider", "cloudflare"]);
    command
}

fn retained(fixture: &Fixture, destination: &Path, expected: &str) -> Output {
    provider_command()
        .arg("retain-bundle")
        .arg("--bundle")
        .arg(&fixture.bundle)
        .arg("--source-view")
        .arg(&fixture.view)
        .arg("--expected-bundle-sha256")
        .arg(expected)
        .arg("--destination")
        .arg(destination)
        .arg("--data-dir")
        .arg(&fixture.data)
        .output()
        .unwrap()
}

fn save(fixture: &Fixture) -> (PathBuf, Value) {
    let preview = fixture.validate(true);
    let directory = fixture.bundle.with_file_name("saved");
    let output = retained(
        fixture,
        &directory,
        preview["bundle_sha256"].as_str().unwrap(),
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    (directory, serde_json::from_slice(&output.stdout).unwrap())
}

fn inspect_saved(directory: &Path, expected: &str) -> Output {
    provider_command()
        .arg("inspect-retained")
        .arg("--input")
        .arg(directory)
        .arg("--expected-retention-sha256")
        .arg(expected)
        .env("PATH", "")
        .output()
        .unwrap()
}

#[test]
fn retained_bundle_moves_and_retrieves_every_original_offline_after_sources_are_removed() {
    let fixture = fixture();
    let (saved, publication) = save(&fixture);
    assert!(!fixture.data.exists());
    let expected = publication["inspection"]["retention_sha256"]
        .as_str()
        .unwrap();
    let index = read(&saved.join("retention.json"));
    let entries = ["bundle_files", "source_files", "documents"]
        .into_iter()
        .flat_map(|field| index[field].as_array().unwrap().iter())
        .map(|file| {
            (
                file["path"].as_str().unwrap().to_owned(),
                fs::read(saved.join(file["path"].as_str().unwrap())).unwrap(),
            )
        })
        .collect::<Vec<_>>();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&saved).unwrap().permissions().mode() & 0o777,
            0o700
        );
        for (name, _) in &entries {
            assert_eq!(
                fs::metadata(saved.join(name)).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }
    fs::remove_dir_all(&fixture.bundle).unwrap();
    fs::remove_dir_all(&fixture.view).unwrap();
    let moved = saved.with_file_name("moved-retained");
    fs::rename(saved, &moved).unwrap();
    let result = inspect_saved(&moved, expected);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let inspection: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(inspection["integrity_verified"], true);
    assert_eq!(inspection["validation_reperformed"], false);
    assert_eq!(inspection["provenance"], "reported_only");
    assert_eq!(inspection["admission_ready"], false);
    assert_eq!(inspection["audit_performed"], false);
    for (i, (member, bytes)) in entries.iter().enumerate() {
        let output = moved.with_file_name(format!("retrieved-{i}"));
        let result = provider_command()
            .arg("retrieve-retained")
            .arg("--input")
            .arg(&moved)
            .arg("--expected-retention-sha256")
            .arg(expected)
            .arg("--member")
            .arg(member)
            .arg("--destination")
            .arg(&output)
            .env("PATH", "")
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert_eq!(&fs::read(output).unwrap(), bytes);
    }
}

#[test]
fn changed_preview_input_failed_validation_and_missing_runtime_publish_nothing() {
    for mutation in ["digest", "file", "references", "node"] {
        let fixture = fixture();
        let preview = fixture.validate(true);
        let mut expected = preview["bundle_sha256"].as_str().unwrap().to_owned();
        match mutation {
            "digest" => expected = "a".repeat(64),
            "file" => fs::write(fixture.bundle.join("architecture.md"), "changed").unwrap(),
            "references" => {
                let mut manifest = fixture.manifest();
                manifest["reported_counts"]["confirmed"] = 2.into();
                fixture.save_manifest(&manifest);
                expected = fixture.validate(false)["bundle_sha256"]
                    .as_str()
                    .unwrap()
                    .into();
            }
            _ => {}
        }
        let destination = fixture.bundle.with_file_name("saved");
        let before = fs::read_dir(destination.parent().unwrap()).unwrap().count();
        let output = if mutation == "node" {
            provider_command()
                .arg("retain-bundle")
                .arg("--bundle")
                .arg(&fixture.bundle)
                .arg("--source-view")
                .arg(&fixture.view)
                .arg("--expected-bundle-sha256")
                .arg(&expected)
                .arg("--destination")
                .arg(&destination)
                .env("PATH", "")
                .output()
                .unwrap()
        } else {
            retained(&fixture, &destination, &expected)
        };
        assert_eq!(output.status.code(), Some(1), "{mutation}");
        assert!(!destination.exists());
        assert_eq!(
            fs::read_dir(destination.parent().unwrap()).unwrap().count(),
            before,
            "{mutation}"
        );
    }
}

#[test]
fn retained_inspection_refuses_tampered_or_missing_payloads_and_wrong_expected_identity() {
    for mutation in [
        "payload",
        "source",
        "projection",
        "validation",
        "index",
        "missing",
        "expected",
    ] {
        let fixture = fixture();
        let (saved, publication) = save(&fixture);
        let mut expected = publication["inspection"]["retention_sha256"]
            .as_str()
            .unwrap()
            .to_owned();
        match mutation {
            "payload" => fs::write(saved.join("bundle/REPORT.md"), "changed").unwrap(),
            "source" => fs::write(saved.join("source-view/src/handler.c"), "changed").unwrap(),
            "projection" => fs::write(saved.join("projection.json"), "{}").unwrap(),
            "validation" => fs::write(saved.join("validation.json"), "{}").unwrap(),
            "index" => {
                let mut index = read(&saved.join("retention.json"));
                index["provenance"] = "workflow_recorded".into();
                write(&saved.join("retention.json"), &index);
                expected = hash(&fs::read(saved.join("retention.json")).unwrap());
            }
            "missing" => fs::remove_file(saved.join("bundle/REPORT.md")).unwrap(),
            _ => expected = "a".repeat(64),
        }
        assert_eq!(
            inspect_saved(&saved, &expected).status.code(),
            Some(1),
            "{mutation}"
        );
    }
}

#[test]
fn publication_and_retrieval_never_overwrite_and_ignore_unindexed_scratch() {
    let fixture = fixture();
    fs::create_dir_all(fixture.bundle.join("agents/hunter-1/scratch")).unwrap();
    fs::write(
        fixture.bundle.join("agents/hunter-1/scratch/secret"),
        "must not copy",
    )
    .unwrap();
    let preview = fixture.validate(true);
    let (saved, publication) = save(&fixture);
    let before = fs::read(saved.join("retention.json")).unwrap();
    assert!(!saved.join("bundle/agents/hunter-1/scratch").exists());
    assert_eq!(
        retained(&fixture, &saved, preview["bundle_sha256"].as_str().unwrap())
            .status
            .code(),
        Some(1)
    );
    assert_eq!(fs::read(saved.join("retention.json")).unwrap(), before);
    let destination = saved.with_file_name("existing.json");
    fs::write(&destination, "keep me").unwrap();
    for member in [
        "projection.json",
        "../escape",
        "bundle/agents/hunter-1/scratch/secret",
    ] {
        let result = provider_command()
            .arg("retrieve-retained")
            .arg("--input")
            .arg(&saved)
            .arg("--expected-retention-sha256")
            .arg(
                publication["inspection"]["retention_sha256"]
                    .as_str()
                    .unwrap(),
            )
            .arg("--member")
            .arg(member)
            .arg("--destination")
            .arg(&destination)
            .env("PATH", "")
            .output()
            .unwrap();
        assert_eq!(result.status.code(), Some(1));
        assert_eq!(fs::read(&destination).unwrap(), b"keep me");
    }
}

#[test]
fn a_saved_receipt_with_a_different_producer_core_remains_retrievable() {
    let fixture = fixture();
    let (saved, _) = save(&fixture);
    let mut index = read(&saved.join("retention.json"));
    index["core_source_sha256"] = "a".repeat(64).into();
    write(&saved.join("retention.json"), &index);
    let expected = hash(&fs::read(saved.join("retention.json")).unwrap());
    let result = inspect_saved(&saved, &expected);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&result.stdout).unwrap()["producer_core_matches"],
        false
    );
}

#[test]
fn concurrent_retention_publishes_one_complete_directory_while_case_writer_is_busy() {
    use std::process::Stdio;
    let fixture = fixture();
    let _lease = DataDirectoryExclusiveLease::acquire(&fixture.data).unwrap();
    let before = fs::read_dir(&fixture.data).unwrap().count();
    let expected = fixture.validate(true)["bundle_sha256"]
        .as_str()
        .unwrap()
        .to_owned();
    let destination = fixture.bundle.with_file_name("concurrent-save");
    let launch = || {
        provider_command()
            .arg("retain-bundle")
            .arg("--bundle")
            .arg(&fixture.bundle)
            .arg("--source-view")
            .arg(&fixture.view)
            .arg("--expected-bundle-sha256")
            .arg(&expected)
            .arg("--destination")
            .arg(&destination)
            .arg("--data-dir")
            .arg(&fixture.data)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap()
    };
    let first = launch();
    let second = launch();
    let results = [
        first.wait_with_output().unwrap(),
        second.wait_with_output().unwrap(),
    ];
    assert_eq!(
        results
            .iter()
            .filter(|result| result.status.success())
            .count(),
        1
    );
    let winner: Value = serde_json::from_slice(
        &results
            .iter()
            .find(|result| result.status.success())
            .unwrap()
            .stdout,
    )
    .unwrap();
    assert!(
        inspect_saved(
            &destination,
            winner["inspection"]["retention_sha256"].as_str().unwrap()
        )
        .status
        .success()
    );
    assert_eq!(fs::read_dir(&fixture.data).unwrap().count(), before);
    assert!(
        fs::read_dir(destination.parent().unwrap())
            .unwrap()
            .all(|entry| !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".scanner-cloudflare-"))
    );
}

#[test]
fn upstream_valid_large_coverage_ids_cannot_amplify_the_saved_projection_without_bound() {
    let fixture = fixture();
    let mut ledger = read(&fixture.bundle.join("coverage-ledger.json"));
    for field in ["surface", "boundary", "subsystem", "attack_class"] {
        ledger[0]["canonical_refs"][field] = "界".repeat(1000).into();
    }
    ledger[0]["coverage_id"] = (0..4)
        .map(|_| "%E7%95%8C".repeat(1000))
        .collect::<Vec<_>>()
        .join("::")
        .into();
    for i in 0..300 {
        ledger[0]["result_fingerprints"]
            .as_array_mut()
            .unwrap()
            .push(format!("pending-{i}").into());
    }
    ledger[0]["unresolved"] = json!(["validation_budget_exhausted"]);
    write(&fixture.bundle.join("coverage-ledger.json"), &ledger);
    let mut metadata = read(&fixture.bundle.join("run-metadata.json"));
    metadata["run_status"] = "incomplete".into();
    metadata["incomplete_reason"] = "validation_budget_exhausted".into();
    write(&fixture.bundle.join("run-metadata.json"), &metadata);
    fixture.reseal();
    let upstream = provider_command()
        .arg("validate-document")
        .args(["--document", "coverage-ledger", "--input"])
        .arg(fixture.bundle.join("coverage-ledger.json"))
        .output()
        .unwrap();
    assert!(
        upstream.status.success(),
        "{} {}",
        String::from_utf8_lossy(&upstream.stdout),
        String::from_utf8_lossy(&upstream.stderr)
    );
    let output = fixture.run();
    assert_eq!(output.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("coverage reference projection exceeds 8 MiB")
    );
}

#[cfg(unix)]
#[test]
fn retained_links_and_redirected_destination_parents_are_refused() {
    use std::os::unix::fs::symlink;
    let fixture = fixture();
    let (saved, publication) = save(&fixture);
    fs::rename(saved.join("source-view"), saved.join("moved")).unwrap();
    symlink("moved", saved.join("source-view")).unwrap();
    assert_eq!(
        inspect_saved(
            &saved,
            publication["inspection"]["retention_sha256"]
                .as_str()
                .unwrap()
        )
        .status
        .code(),
        Some(1)
    );
    let redirect = saved.with_file_name("redirect");
    symlink(&saved, &redirect).unwrap();
    let expected = fixture.validate(true)["bundle_sha256"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(
        retained(&fixture, &redirect.join("saved"), &expected)
            .status
            .code(),
        Some(1)
    );
}
fn read(path: &Path) -> Value {
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}
fn write(path: &Path, value: &Value) {
    fs::write(path, serde_json::to_vec(value).unwrap()).unwrap();
}
fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
impl Fixture {
    fn manifest(&self) -> Value {
        read(&self.bundle.join("provider-manifest.json"))
    }
    fn save_manifest(&self, manifest: &Value) {
        write(&self.bundle.join("provider-manifest.json"), manifest);
    }
    fn reseal(&self) {
        let mut manifest = self.manifest();
        for file in manifest["files"].as_array_mut().unwrap() {
            let bytes = fs::read(self.bundle.join(file["path"].as_str().unwrap())).unwrap();
            file["sha256"] = hash(&bytes).into();
            file["byte_length"] = bytes.len().into();
        }
        self.save_manifest(&manifest);
    }
    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_ai-security-scanner-cli"));
        command
            .args(["--json", "--data-dir"])
            .arg(&self.data)
            .args(["provider", "cloudflare", "validate-bundle", "--bundle"])
            .arg(&self.bundle)
            .arg("--source-view")
            .arg(&self.view);
        command
    }
    fn run(&self) -> Output {
        self.command().output().unwrap()
    }
    fn validate(&self, valid: bool) -> Value {
        let output = self.run();
        assert_eq!(
            output.status.code(),
            Some(if valid { 0 } else { 2 }),
            "{}\n{}",
            String::from_utf8_lossy(&output.stderr),
            String::from_utf8_lossy(&output.stdout)
        );
        let receipt: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(receipt["valid"], valid, "{receipt}");
        assert_eq!(receipt["audit_performed"], false);
        assert_eq!(receipt["admission_ready"], false);
        assert_eq!(receipt["provenance"], "reported_only");
        if !valid {
            assert!(receipt["projection"].is_null());
        }
        receipt
    }
}

#[test]
fn complete_reported_bundle_preserves_verdicts_bytes_and_does_not_write_case_state() {
    let fixture = fixture();
    let before = fs::read(fixture.bundle.join("findings.json")).unwrap();
    let receipt = fixture.validate(true);
    assert!(!fixture.data.exists());
    assert_eq!(receipt["validation_scope"], "reported_bundle");
    assert_eq!(receipt["canonical_snapshot_binding_verified"], false);
    assert_eq!(receipt["source_authorization_verified"], false);
    let projection = &receipt["projection"];
    assert_eq!(
        projection["reported_counts"],
        fixture.manifest()["reported_counts"]
    );
    assert_eq!(
        projection["reported_counts"]["reported_confirmed_by_severity"],
        json!({"medium": 1})
    );
    let native: Value = serde_json::from_slice(&before).unwrap();
    for (index, record) in projection["records"].as_array().unwrap().iter().enumerate() {
        assert_eq!(record["native_record"], native[index]);
        assert_eq!(
            record["native_record_sha256"],
            hash(&serde_json::to_vec(&native[index]).unwrap())
        );
        assert_eq!(
            record["reported_verifier_assignments"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
    }
    assert!(projection["records"][1]["severity"].is_null());
    assert!(projection["records"][2]["severity"].is_null());
    assert_eq!(
        before,
        fs::read(fixture.bundle.join("findings.json")).unwrap()
    );
    let _lease = DataDirectoryExclusiveLease::acquire(&fixture.data).unwrap();
    let count = fs::read_dir(&fixture.data).unwrap().count();
    assert_eq!(
        fixture.validate(true)["bundle_sha256"],
        receipt["bundle_sha256"]
    );
    assert_eq!(fs::read_dir(&fixture.data).unwrap().count(), count);
}

#[test]
fn payload_and_code_whitespace_survive_normalization_and_are_not_executed() {
    let fixture = fixture();
    let mut records = read(&fixture.bundle.join("findings.json"));
    let payload = "\n  $(touch must-not-exist)\n<script>alert('inert')</script>  \n";
    records[0]["execution"]["payloads"] = json!([payload]);
    records[0]["remediation"]["code_changes"] =
        json!([{"file_name":"src/new-file.c","fixed_code":payload}]);
    write(&fixture.bundle.join("findings.json"), &records);
    let mut manifest = fixture.manifest();
    for assignment in manifest["verifier_assignments"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .take(2)
    {
        assignment["record_sha256"] = hash(&serde_json::to_vec(&records[0]).unwrap()).into();
    }
    fixture.save_manifest(&manifest);
    write(
        &fixture
            .bundle
            .join("agents/candidate-1/artifacts/decision.json"),
        &json!({"decision":"confirmed","record":records[0]}),
    );
    fixture.reseal();
    let receipt = fixture.validate(true);
    assert_eq!(
        receipt["projection"]["records"][0]["native_record"]["execution"]["payloads"][0],
        payload
    );
    assert!(!fixture.bundle.join("must-not-exist").exists());
}

#[test]
fn incomplete_candidates_remain_in_ledger_without_fabricated_findings_or_risk() {
    let fixture = fixture();
    let mut ledger = read(&fixture.bundle.join("coverage-ledger.json"));
    ledger[0]["result_fingerprints"]
        .as_array_mut()
        .unwrap()
        .push(json!("unvalidated-candidate"));
    ledger[0]["unresolved"] = json!(["validation_budget_exhausted"]);
    write(&fixture.bundle.join("coverage-ledger.json"), &ledger);
    let mut metadata = read(&fixture.bundle.join("run-metadata.json"));
    metadata["run_status"] = "incomplete".into();
    metadata["incomplete_reason"] = "validation_budget_exhausted".into();
    write(&fixture.bundle.join("run-metadata.json"), &metadata);
    fixture.reseal();
    let receipt = fixture.validate(true);
    assert_eq!(
        receipt["projection"]["unresolved_candidates"],
        json!(["unvalidated-candidate"])
    );
    assert_eq!(
        receipt["projection"]["records"].as_array().unwrap().len(),
        3
    );
    metadata["run_status"] = "complete".into();
    write(&fixture.bundle.join("run-metadata.json"), &metadata);
    fixture.reseal();
    fixture.validate(false);
}

#[test]
fn quick_profile_uses_one_independent_combined_verifier() {
    let fixture = fixture();
    let mut metadata = read(&fixture.bundle.join("run-metadata.json"));
    metadata["profile"] = "quick".into();
    write(&fixture.bundle.join("run-metadata.json"), &metadata);
    let mut manifest = fixture.manifest();
    manifest["verifier_assignments"]
        .as_array_mut()
        .unwrap()
        .retain(|assignment| assignment["role"] == "candidate_verifier");
    manifest["files"]
        .as_array_mut()
        .unwrap()
        .retain(|file| !file["path"].as_str().unwrap().starts_with("agents/final-"));
    fixture.save_manifest(&manifest);
    fixture.reseal();
    fixture.validate(true);
    metadata["profile"] = "standard".into();
    write(&fixture.bundle.join("run-metadata.json"), &metadata);
    fixture.reseal();
    fixture.validate(false);
}

#[test]
fn counts_scope_source_lines_ledger_links_and_run_identity_are_cross_checked() {
    for mutation in [
        "counts",
        "scope",
        "line",
        "ledger",
        "run",
        "budget",
        "historical_check",
    ] {
        let fixture = fixture();
        match mutation {
            "counts" => {
                let mut m = fixture.manifest();
                m["reported_counts"]["confirmed"] = 2.into();
                fixture.save_manifest(&m);
            }
            "scope" | "run" | "budget" => {
                let mut m = read(&fixture.bundle.join("run-metadata.json"));
                if mutation == "scope" {
                    m["scope_paths"] = json!(["other"]);
                } else if mutation == "budget" {
                    m["budget"] = 1.into();
                } else {
                    m["run_id"] = "another-run".into();
                }
                write(&fixture.bundle.join("run-metadata.json"), &m);
            }
            "line" => {
                let mut f = read(&fixture.bundle.join("findings.json"));
                f[0]["trace"][0]["line"] = 999.into();
                write(&fixture.bundle.join("findings.json"), &f);
            }
            "ledger" => {
                let mut l = read(&fixture.bundle.join("coverage-ledger.json"));
                l[0]["result_fingerprints"] = json!(["src-handler-missing-check"]);
                write(&fixture.bundle.join("coverage-ledger.json"), &l);
            }
            _ => {
                let mut l = read(&fixture.bundle.join("coverage-ledger.json"));
                l[0]["local_checks"][0]["artifact"] =
                    "agents/hunter-1/artifacts/missing.txt".into();
                l[0]["local_checks"][0]["method"] = "local".into();
                write(&fixture.bundle.join("coverage-ledger.json"), &l);
            }
        }
        fixture.reseal();
        assert!(
            !fixture.validate(false)["reference_errors"]
                .as_array()
                .unwrap()
                .is_empty(),
            "{mutation}"
        );
    }
}

#[test]
fn missing_duplicate_cross_run_self_verifying_and_stale_receipts_are_refused() {
    for mutation in [
        "missing",
        "duplicate",
        "binding",
        "view",
        "hunter",
        "record",
        "time",
        "replacement",
    ] {
        let fixture = fixture();
        let mut manifest = fixture.manifest();
        let assignments = manifest["verifier_assignments"].as_array_mut().unwrap();
        match mutation {
            "missing" => {
                assignments.remove(0);
            }
            "duplicate" => {
                assignments.push(assignments[0].clone());
            }
            "binding" => assignments[0]["binding"]["task_id"] = "wrong-task".into(),
            "view" => assignments[0]["view_sha256"] = "a".repeat(64).into(),
            "record" => assignments[1]["record_sha256"] = "a".repeat(64).into(),
            "time" => assignments[1]["started_at"] = "2026-11-10T09:00:00Z".into(),
            "hunter" => {
                assignments[0]["agent_id"] = "hunter-1".into();
                assignments[0]["output_path"] = "agents/hunter-1/artifacts/decision.json".into();
                fs::create_dir_all(fixture.bundle.join("agents/hunter-1/artifacts")).unwrap();
                fs::copy(
                    fixture
                        .bundle
                        .join("agents/candidate-1/artifacts/decision.json"),
                    fixture
                        .bundle
                        .join("agents/hunter-1/artifacts/decision.json"),
                )
                .unwrap();
                manifest["files"].as_array_mut().unwrap().push(json!({"path":"agents/hunter-1/artifacts/decision.json","sha256":"a".repeat(64),"byte_length":0}));
            }
            _ => {
                write(
                    &fixture
                        .bundle
                        .join("agents/final-1/artifacts/decision.json"),
                    &json!({"decision":"replace","record":{},"reason":"changed"}),
                );
            }
        }
        fixture.save_manifest(&manifest);
        fixture.reseal();
        fixture.validate(false);
    }
}

#[test]
fn original_file_digests_and_source_view_digest_bind_the_whole_selected_bundle() {
    for mutation in ["report", "source", "view_index", "asset"] {
        let fixture = fixture();
        if mutation == "report" {
            fs::write(fixture.bundle.join("REPORT.md"), "changed").unwrap();
        } else if mutation == "source" {
            fs::write(fixture.view.join("src/handler.c"), "changed\n").unwrap();
        } else if mutation == "view_index" {
            let mut m = fixture.manifest();
            m["source"]["view_sha256"] = "b".repeat(64).into();
            fixture.save_manifest(&m);
        } else {
            let previous = fixture.validate(true)["bundle_sha256"].clone();
            let mut m = fixture.manifest();
            m["binding"]["asset_id"] = "another-asset".into();
            for a in m["verifier_assignments"].as_array_mut().unwrap() {
                a["binding"]["asset_id"] = "another-asset".into();
            }
            fixture.save_manifest(&m);
            assert_ne!(fixture.validate(true)["bundle_sha256"], previous);
            continue;
        }
        assert_eq!(fixture.run().status.code(), Some(1), "{mutation}");
    }
}

#[test]
fn unsafe_ambiguous_and_unknown_manifests_are_rejected_before_node_launch() {
    for mutation in [
        "duplicate_key",
        "version",
        "traversal",
        "duplicate_path",
        "case_alias",
        "oversize",
        "trust",
        "missing",
    ] {
        let fixture = fixture();
        let mut m = fixture.manifest();
        match mutation {
            "duplicate_key" => {
                let bytes = serde_json::to_string(&m).unwrap();
                fs::write(
                    fixture.bundle.join("provider-manifest.json"),
                    bytes.replacen('{', "{\"schema_version\":\"duplicate\",", 1),
                )
                .unwrap();
            }
            "version" => m["schema_version"] = "unsupported/v99".into(),
            "traversal" => m["files"][0]["path"] = "../outside".into(),
            "duplicate_path" => {
                let copy = m["files"][0].clone();
                m["files"].as_array_mut().unwrap().push(copy);
            }
            "case_alias" => {
                let mut copy = m["source"]["files"][0].clone();
                copy["path"] = "SRC/handler.c".into();
                m["source"]["files"].as_array_mut().unwrap().push(copy);
            }
            "oversize" => m["files"][0]["byte_length"] = (9 * 1024 * 1024).into(),
            "trust" => m["provenance"] = "workflow_recorded".into(),
            _ => {
                m["files"].as_array_mut().unwrap().remove(0);
            }
        }
        if mutation != "duplicate_key" {
            fixture.save_manifest(&m);
        }
        let output = fixture.command().env("PATH", "").output().unwrap();
        assert_eq!(output.status.code(), Some(1), "{mutation}");
        assert!(
            !String::from_utf8_lossy(&output.stderr).contains("requires Node.js"),
            "{mutation}"
        );
    }
}

#[test]
fn malformed_verifier_json_is_not_repaired_and_upstream_rejections_have_no_projection() {
    let fixture = fixture();
    fs::write(
        fixture
            .bundle
            .join("agents/final-1/artifacts/decision.json"),
        "Here is the result: {\"decision\":\"verified\"}",
    )
    .unwrap();
    fixture.reseal();
    assert_eq!(fixture.run().status.code(), Some(1));
    write(
        &fixture.bundle.join("findings.json"),
        &json!([{"verdict":"confirmed"}]),
    );
    fixture.reseal();
    let result = fixture.validate(false);
    assert_eq!(
        result["upstream_validations"][0]["validation"]["valid"],
        false
    );
}

#[test]
fn source_index_recipe_matches_fixture_and_listing_order_does_not_change_identity() {
    let fixture = fixture();
    let manifest = fixture.manifest();
    let mut files: Vec<BundleFile> =
        serde_json::from_value(manifest["source"]["files"].clone()).unwrap();
    assert_eq!(
        file_index_digest(&files).unwrap(),
        manifest["source"]["view_sha256"]
    );
    let before = file_index_digest(&files).unwrap();
    files.reverse();
    assert_eq!(file_index_digest(&files).unwrap(), before);
}

#[test]
fn unknown_canonical_lineage_stays_unknown_and_carried_records_use_current_verifiers() {
    let fixture = fixture();
    let mut manifest = fixture.manifest();
    manifest["source"]["canonical_snapshot_id"] = Value::Null;
    manifest["source"]["canonical_snapshot_sha256"] = Value::Null;
    fixture.save_manifest(&manifest);
    let mut ledger = read(&fixture.bundle.join("coverage-ledger.json"));
    ledger[0]["prior_status"] = "prior_confirmed_same_source".into();
    ledger[0]["agent_id"] = "candidate-1".into();
    ledger[0]["local_checks"][0]["agent_id"] = "candidate-1".into();
    write(&fixture.bundle.join("coverage-ledger.json"), &ledger);
    fixture.reseal();
    assert_eq!(
        fixture.validate(true)["canonical_snapshot_binding_verified"],
        false
    );
    ledger[0]["prior_status"] = "new".into();
    write(&fixture.bundle.join("coverage-ledger.json"), &ledger);
    fixture.reseal();
    fixture.validate(false);
}

#[test]
fn archived_checks_and_unowned_retained_artifacts_are_not_ignored() {
    for mutation in ["archived", "unowned"] {
        let fixture = fixture();
        if mutation == "archived" {
            let mut ledger = read(&fixture.bundle.join("coverage-ledger.json"));
            ledger[0]["wave"] = 2.into();
            ledger[0]["attempts"] = json!([{
                "wave":1,"status":"covered","agent_id":"old-hunter","reviewed_paths":["src/handler.c"],
                "local_checks":[{"agent_id":"old-hunter","reviewed_paths":["src/handler.c"],"invariant":"Owner boundary","method":"local","result":"Prior check","artifact":"agents/old-hunter/artifacts/absent.txt"}],
                "result_fingerprints":[],"unresolved":[],"reassignment_reason":"A critic reopened the unit."
            }]);
            write(&fixture.bundle.join("coverage-ledger.json"), &ledger);
        } else {
            let path = "agents/unknown/artifacts/orphan.txt";
            fs::create_dir_all(fixture.bundle.join("agents/unknown/artifacts")).unwrap();
            fs::write(fixture.bundle.join(path), "unowned").unwrap();
            let mut manifest = fixture.manifest();
            manifest["files"]
                .as_array_mut()
                .unwrap()
                .push(json!({"path":path,"sha256":"a".repeat(64),"byte_length":0}));
            fixture.save_manifest(&manifest);
        }
        fixture.reseal();
        assert!(
            !fixture.validate(false)["reference_errors"]
                .as_array()
                .unwrap()
                .is_empty()
        );
    }
}

#[cfg(unix)]
#[test]
fn bundle_and_source_links_cannot_redirect_validation() {
    use std::os::unix::fs::symlink;
    for mutation in ["member", "parent", "root", "source", "hardlink", "pipe"] {
        let fixture = fixture();
        let victim = fixture.bundle.join("architecture.md");
        match mutation {
            "member" => {
                fs::remove_file(&victim).unwrap();
                symlink(fixture.bundle.join("REPORT.md"), &victim).unwrap();
            }
            "parent" => {
                fs::rename(fixture.bundle.join("agents"), fixture.bundle.join("moved")).unwrap();
                symlink("moved", fixture.bundle.join("agents")).unwrap();
            }
            "root" => {
                fs::rename(&fixture.bundle, fixture.bundle.with_file_name("moved")).unwrap();
                symlink("moved", &fixture.bundle).unwrap();
            }
            "source" => {
                fs::rename(fixture.view.join("src"), fixture.view.join("moved")).unwrap();
                symlink("moved", fixture.view.join("src")).unwrap();
            }
            "hardlink" => {
                fs::hard_link(&victim, fixture.bundle.join("alias")).unwrap();
            }
            _ => {
                fs::remove_file(&victim).unwrap();
                let name = std::ffi::CString::new(victim.as_os_str().as_encoded_bytes()).unwrap();
                // SAFETY: name points to an owned test entry and is NUL terminated.
                assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
            }
        }
        assert_eq!(fixture.run().status.code(), Some(1), "{mutation}");
    }
}

#[test]
fn declaring_a_product_generated_view_never_promotes_an_external_bundle() {
    let fixture = fixture();
    let mut manifest = fixture.manifest();
    manifest["source"]["view_id"] = format!("ai-view-{}", "a".repeat(64)).into();
    manifest["source"]["policy_id"] = "ai-source-view-v1".into();
    fixture.save_manifest(&manifest);
    let receipt = fixture.validate(true);
    assert_eq!(receipt["provenance"], "reported_only");
    for flag in [
        "canonical_snapshot_binding_verified",
        "source_authorization_verified",
        "audit_performed",
        "admission_ready",
    ] {
        assert_eq!(receipt[flag], false);
    }
    let (_, retained) = save(&fixture);
    assert_eq!(retained["inspection"]["provenance"], "reported_only");
    assert_eq!(retained["inspection"]["audit_performed"], false);
    assert_eq!(retained["inspection"]["admission_ready"], false);
}

#[test]
fn rejected_records_need_only_candidate_receipts_under_standard() {
    let fixture = fixture();
    let mut manifest = fixture.manifest();
    let removed = manifest["verifier_assignments"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["role"] == "final_verifier" && a["fingerprint"] == "src-router-auth-bypass")
        .unwrap()["output_path"]
        .clone();
    manifest["verifier_assignments"]
        .as_array_mut()
        .unwrap()
        .retain(|a| a["output_path"] != removed);
    manifest["files"]
        .as_array_mut()
        .unwrap()
        .retain(|f| f["path"] != removed);
    fixture.save_manifest(&manifest);
    fixture.validate(true);
}

#[test]
fn out_of_scope_starting_paths_need_not_exist_but_reviewed_paths_must() {
    let fixture = fixture();
    let mut ledger = read(&fixture.bundle.join("coverage-ledger.json"));
    let mut unit = ledger[0].clone();
    unit["canonical_refs"]["surface"] = "zzz-excluded".into();
    unit["surface"] = "Excluded surface".into();
    unit["coverage_id"] = format!(
        "zzz-excluded::{}",
        unit["coverage_id"]
            .as_str()
            .unwrap()
            .split_once("::")
            .unwrap()
            .1
    )
    .into();
    unit["status"] = "out_of_scope".into();
    unit["agent_id"] = Value::Null;
    unit["starting_paths"] = json!(["outside/view.rs"]);
    unit["reviewed_paths"] = json!([]);
    unit["local_checks"] = json!([]);
    unit["result_fingerprints"] = json!([]);
    unit["unresolved"] = json!(["Outside selected scope"]);
    ledger.as_array_mut().unwrap().push(unit);
    write(&fixture.bundle.join("coverage-ledger.json"), &ledger);
    fixture.reseal();
    fixture.validate(true);
    ledger[1]["reviewed_paths"] = json!(["outside/view.rs"]);
    write(&fixture.bundle.join("coverage-ledger.json"), &ledger);
    fixture.reseal();
    fixture.validate(false);
    ledger[1]["reviewed_paths"] = json!([]);
    ledger[1]["starting_paths"] = json!(["../escape"]);
    write(&fixture.bundle.join("coverage-ledger.json"), &ledger);
    fixture.reseal();
    fixture.validate(false);
}

#[path = "support/paths.rs"]
mod paths;
