//! Frozen report inputs for RF-01, generated from the existing all-engine audit.
//! The included harness uses FakeContainerRuntime and never contacts scan targets.
include!("all_engine_report_audit.rs");

#[path = "support/report_version.rs"]
mod report_version;

mod report_fidelity {
    use super::*;
    use ai_security_scanner_lib::export::{create_case_bundle_at, verify_case_bundle};
    use flate2::{Compression, GzBuilder, read::GzDecoder};
    use serde_json::{Value, json};
    use std::io::{Read, Write};
    use std::process::Command;

    const BASELINE_COMMIT: &str = "cc2ef089584594b2908177550da65bb18ae26361";
    const FIXED_TIME: &str = "2026-11-08T12:00:00Z";

    fn root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .to_owned()
    }

    fn baseline_dir() -> PathBuf {
        root().join("tests/fixtures/report-fidelity")
    }

    fn hash(bytes: &[u8]) -> String {
        hex::encode(Sha256::digest(bytes))
    }

    fn write_gzip(path: &Path, bytes: &[u8]) {
        let mut encoder = GzBuilder::new()
            .mtime(0)
            .write(Vec::new(), Compression::best());
        encoder.write_all(bytes).unwrap();
        fs::write(path, encoder.finish().unwrap()).unwrap();
    }

    fn read_gzip(path: &Path) -> Vec<u8> {
        let mut bytes = Vec::new();
        GzDecoder::new(fs::File::open(path).unwrap())
            .read_to_end(&mut bytes)
            .unwrap();
        bytes
    }

    fn write_document_snapshots(output: &Path, destination: &Path) {
        for entry in fs::read_dir(output).unwrap() {
            let path = entry.unwrap().path();
            if path
                .extension()
                .is_some_and(|ext| ext == "html" || ext == "json")
            {
                let name = format!("{}.gz", path.file_name().unwrap().to_str().unwrap());
                write_gzip(&destination.join(name), &fs::read(path).unwrap());
            }
        }
    }

    // This transformation is used only ONCE when capturing a simulated input,
    // never on actual outputs during comparison. References keep their identity.
    fn freeze_input(subject: &AllEngineRun<'_>, scenario: &str) -> AssessmentCase {
        fn freeze_dates(value: &mut Value, key: &str) {
            match value {
                Value::Object(values) => {
                    values.iter_mut().for_each(|(key, v)| freeze_dates(v, key))
                }
                Value::Array(values) => values.iter_mut().for_each(|v| freeze_dates(v, key)),
                Value::String(value) if chrono::DateTime::parse_from_rfc3339(value).is_ok() => {
                    *value = if key == "expires_at" {
                        "2027-11-08T12:00:00Z".into()
                    } else {
                        FIXED_TIME.into()
                    };
                }
                _ => {}
            }
        }
        let mut value = serde_json::to_value(&subject.completed).unwrap();
        freeze_dates(&mut value, "");
        let mut encoded = serde_json::to_string(&value).unwrap();
        // Persist original generated IDs verbatim. In particular evidence IDs
        // cryptographically bind engine-run IDs; replacing those IDs would
        // invalidate upstream provenance. Replays always load this frozen case.
        encoded = encoded.replace(
            subject.database.parent().unwrap().to_str().unwrap(),
            "/report-fidelity-fixture",
        );
        let mut case: AssessmentCase = serde_json::from_str(&encoded).unwrap();
        case.title = format!("ExampleCo — simulated {scenario} report fidelity fixture");
        case.profile.organization_name = "ExampleCo (fictional organization)".into();
        case.profile.notes = Some("Simulated upstream-format adapter inputs; no live target contact. Frozen solely for report compatibility checks.".into());
        case.is_demo = true;
        case.exports.clear();
        case
    }

    fn generate_documents(
        case: &AssessmentCase,
        destination: &Path,
        comparison_version: Option<&str>,
    ) -> Value {
        let comparison_bytes = |name: &str, bytes: Vec<u8>| match comparison_version {
            Some(version) => report_version::normalize(name, &bytes, version),
            None => bytes,
        };
        fs::create_dir_all(destination).unwrap();
        let run_id = &case.scan_runs.last().unwrap().id;
        let engines = EngineRegistry::load_builtin().unwrap();
        let adapters = builtin_adapter_registry().unwrap();
        let mut documents = serde_json::Map::new();
        for (locale_name, locale) in [("en", ReportLocale::En), ("zh-Hant", ReportLocale::ZhHant)] {
            for (disclosure, redaction) in [
                ("standard", RedactionProfile::Standard),
                ("full", RedactionProfile::None),
            ] {
                for (extension, format) in [
                    ("html", CaseExportFormat::Html),
                    ("json", CaseExportFormat::CanonicalJson),
                ] {
                    let name = format!("{locale_name}-{disclosure}.{extension}");
                    // Each format sees the exact same case, before export history
                    // and storage touch timestamps change the live service state.
                    let temp = test_temp::tempdir().unwrap();
                    let storage = Storage::open(temp.path().join("case.db")).unwrap();
                    let mut saved: AssessmentCase =
                        serde_json::from_value(serde_json::to_value(case).unwrap()).unwrap();
                    storage
                        .save_case(&mut saved, "report_fidelity.fixture")
                        .unwrap();
                    let service = CaseService::new(
                        &storage,
                        &engines,
                        &adapters,
                        temp.path().join("artifacts"),
                        temp.path().join("signing-key"),
                    );
                    service
                        .export_case(
                            &case.id,
                            run_id,
                            format,
                            destination.join(&name),
                            ExportOptions {
                                redaction,
                                include_raw_artifacts: false,
                                locale,
                            },
                        )
                        .unwrap();
                    let bytes = comparison_bytes(&name, fs::read(destination.join(&name)).unwrap());
                    if extension == "html" {
                        assert_paragraphs_are_well_formed(
                            std::str::from_utf8(&bytes).unwrap(),
                            &name,
                        );
                    }
                    documents.insert(
                        name,
                        json!({"sha256": hash(&bytes), "byteLength": bytes.len()}),
                    );
                }
            }
        }
        for (name, format) in [
            ("framework.json", CaseExportFormat::FrameworkReport),
            ("ocsf.json", CaseExportFormat::OcsfJson),
            ("oscal.json", CaseExportFormat::OscalJson),
        ] {
            let temp = test_temp::tempdir().unwrap();
            let storage = Storage::open(temp.path().join("case.db")).unwrap();
            let mut saved: AssessmentCase =
                serde_json::from_value(serde_json::to_value(case).unwrap()).unwrap();
            storage
                .save_case(&mut saved, "report_fidelity.fixture")
                .unwrap();
            let service = CaseService::new(
                &storage,
                &engines,
                &adapters,
                temp.path().join("artifacts"),
                temp.path().join("signing-key"),
            );
            let exported = service
                .export_case(
                    &case.id,
                    run_id,
                    format,
                    destination.join(name),
                    ExportOptions::default(),
                )
                .unwrap();
            let produced = fs::read(destination.join(name)).unwrap();
            let bytes = comparison_bytes(name, produced.clone());
            documents.insert(
                name.into(),
                json!({"sha256": hash(&bytes), "byteLength": bytes.len()}),
            );
            if let Some(companion) = exported.coverage_manifest_path {
                let mut companion_bytes = fs::read(&companion).unwrap();
                // The companion binds the real export, including its current
                // product version. Verify that binding before deriving the hash
                // of the version-normalized document for the frozen comparison.
                let value: Value = serde_json::from_slice(&companion_bytes).unwrap();
                assert_eq!(value["companion"]["file_name"], name);
                assert_eq!(value["companion"]["sha256"], hash(&produced));
                if comparison_version.is_some() {
                    let before = format!("\n    \"sha256\": {:?}\n", hash(&produced));
                    let after = format!("\n    \"sha256\": {:?}\n", hash(&bytes));
                    let text = std::str::from_utf8(&companion_bytes).unwrap();
                    assert_eq!(text.matches(&before).count(), 1);
                    companion_bytes = text.replacen(&before, &after, 1).into_bytes();
                }
                let name = Path::new(&companion).file_name().unwrap().to_str().unwrap();
                documents.insert(
                    name.into(),
                    json!({"sha256": hash(&companion_bytes), "byteLength": companion_bytes.len()}),
                );
            }
        }
        let temp = test_temp::tempdir().unwrap();
        let bundle = destination.join("report.case.tar.gz");
        create_case_bundle_at(
            case,
            run_id,
            temp.path().join("artifacts"),
            &bundle,
            temp.path().join("signing-key"),
            ExportOptions::default(),
            FIXED_TIME.parse().unwrap(),
        )
        .unwrap();
        let verification = verify_case_bundle(&bundle).unwrap();
        assert!(verification.valid);
        // Real local integrity signing remains exercised. Its newly generated
        // public identity/signature are not a stable report payload; compare all
        // other entries, including schema documents and coverage, byte for byte.
        let mut entries = serde_json::Map::new();
        let mut archive = tar::Archive::new(GzDecoder::new(fs::File::open(&bundle).unwrap()));
        for entry in archive.entries().unwrap() {
            let mut entry = entry.unwrap();
            let name = entry.path().unwrap().to_str().unwrap().to_owned();
            if name.contains("signing") || name.contains("signature") || name == "manifest.json" {
                continue;
            }
            let mut bytes = Vec::new();
            entry.read_to_end(&mut bytes).unwrap();
            let bytes = comparison_bytes(&name, bytes);
            entries.insert(
                name,
                json!({"sha256": hash(&bytes), "byteLength": bytes.len()}),
            );
        }
        documents.insert("report.case.tar.gz".into(), json!({"comparison": "verified-signature-and-deterministic-payload-entries", "entries": entries}));
        Value::Object(documents)
    }

    #[test]
    #[ignore = "explicit capture from the unchanged baseline core only; see fixture README"]
    fn capture_report_fidelity_baseline() {
        let destination = PathBuf::from(
            std::env::var_os("AI_SCANNER_REPORT_BASELINE_WRITE")
                .expect("set AI_SCANNER_REPORT_BASELINE_WRITE to a new empty directory"),
        );
        assert!(
            !destination.exists() || fs::read_dir(&destination).unwrap().next().is_none(),
            "baseline capture refuses a nonempty destination"
        );
        assert!(
            Command::new("git")
                .current_dir(root())
                .args([
                    "diff",
                    "--quiet",
                    BASELINE_COMMIT,
                    "--",
                    "src-tauri/src",
                    "engines/catalog.json",
                    "src-tauri/Cargo.toml",
                    "Cargo.lock"
                ])
                .status()
                .unwrap()
                .success(),
            "baseline capture requires the unchanged specified production core"
        );
        fs::create_dir_all(&destination).unwrap();
        let mut scenarios = Vec::new();
        for (name, outcomes) in [
            ("all-detectors", EngineOutcomes::EveryDetectorReports),
            ("mixed-terminal", EngineOutcomes::MixedTerminalStates),
        ] {
            all_engines_in_one_report(
                AssessmentIntent::InternalItEnvironment,
                AiGeneratedArtifactAnswer::No,
                outcomes,
                |subject| {
                    let case = freeze_input(subject, name);
                    let directory = destination.join(name);
                    fs::create_dir_all(&directory).unwrap();
                    let input = serde_json::to_vec_pretty(&case).unwrap();
                    write_gzip(&directory.join("case.json.gz"), &input);
                    let output = test_temp::tempdir().unwrap();
                    let documents = generate_documents(&case, output.path(), None);
                    // Freeze exact production output, without normalizing output IDs,
                    // timestamps, ordering, prose, or HTML after rendering.
                    write_document_snapshots(output.path(), &directory);
                    let sources = dispatchable_engine_ids(subject.engines).into_iter().map(|engine_id| {
                    let (bytes, file) = fixture(engine_id, outcomes);
                    json!({"engineId":engine_id,"fixtureFile":file,"fixtureSha256":hash(bytes)})
                }).collect::<Vec<_>>();
                    scenarios.push(json!({"name": name, "caseSha256": hash(&input), "caseId": case.id, "runId": case.scan_runs.last().unwrap().id, "sources": sources, "documents": documents}));
                },
            );
        }
        let mut source_hashes = serde_json::Map::new();
        for path in [
            "src-tauri/src/case_service.rs",
            "src-tauri/src/beginner_report.rs",
            "src-tauri/src/export.rs",
            "src-tauri/src/exporters/framework_report.rs",
            "src-tauri/src/exporters/ocsf.rs",
            "src-tauri/src/exporters/oscal.rs",
            "src-tauri/tests/all_engine_report_audit.rs",
            "src-tauri/tests/support/public_sample_reports.rs",
            "src-tauri/tests/report_fidelity_baseline.rs",
            "engines/catalog.json",
            "Cargo.lock",
        ] {
            source_hashes.insert(
                path.into(),
                json!(hash(&fs::read(root().join(path)).unwrap())),
            );
        }
        let receipt = json!({"schemaVersion":1, "baselineCoreRevision":BASELINE_COMMIT, "productVersion":env!("CARGO_PKG_VERSION"), "capturedAt":Utc::now(), "fixedInputTime":FIXED_TIME, "liveTargetContact":false, "runtime":"FakeContainerRuntime", "inputPreparation":"One-time fixture identity, timestamp and temporary-path freezing; production output bytes are never rewritten", "sourceHashes":source_hashes, "scenarios":scenarios});
        fs::write(
            destination.join("receipt.json"),
            serde_json::to_vec_pretty(&receipt).unwrap(),
        )
        .unwrap();
    }

    fn committed_fixture_file(revision: &str, name: &str) -> Vec<u8> {
        let output = Command::new("git")
            .current_dir(root())
            .arg("show")
            .arg(format!("{revision}:tests/fixtures/report-fidelity/{name}"))
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "cannot read committed fixture {name}"
        );
        output.stdout
    }

    fn replace_outputs(baseline: &Path, destination: &Path, reason: &str) {
        let reason_length = reason.chars().count();
        assert!(
            (10..=200).contains(&reason_length)
                && !reason.trim().is_empty()
                && reason
                    .chars()
                    .all(|ch| !ch.is_control() && ch != '\u{2028}' && ch != '\u{2029}'),
            "replacement reason must be one line of 10 to 200 characters without controls"
        );
        assert!(
            !destination.exists() || fs::read_dir(destination).unwrap().next().is_none(),
            "baseline replacement refuses a nonempty destination"
        );
        let head = Command::new("git")
            .current_dir(root())
            .args(["rev-parse", "HEAD"])
            .output()
            .unwrap();
        assert!(head.status.success(), "cannot identify the production core");
        let revision = std::str::from_utf8(&head.stdout).unwrap().trim().to_owned();
        let receipt_bytes = fs::read(baseline.join("receipt.json")).unwrap();
        assert!(
            receipt_bytes == committed_fixture_file(&revision, "receipt.json"),
            "baseline replacement requires the committed receipt"
        );
        let mut receipt: Value = serde_json::from_slice(&receipt_bytes).unwrap();
        let old_revision = receipt["baselineCoreRevision"].as_str().unwrap().to_owned();
        let old_version = receipt["productVersion"].as_str().unwrap().to_owned();
        assert_ne!(revision, old_revision, "replacement revision must differ");

        // Verify all frozen inputs before creating the destination or rendering.
        let mut inputs = Vec::new();
        for scenario in receipt["scenarios"].as_array().unwrap() {
            let name = scenario["name"].as_str().unwrap();
            let compressed = fs::read(baseline.join(name).join("case.json.gz")).unwrap();
            let mut input = Vec::new();
            GzDecoder::new(compressed.as_slice())
                .read_to_end(&mut input)
                .unwrap();
            assert_eq!(
                hash(&input),
                scenario["caseSha256"],
                "{name} frozen input changed"
            );
            assert!(
                compressed == committed_fixture_file(&revision, &format!("{name}/case.json.gz")),
                "{name} compressed input differs from the committed file"
            );
            let case: AssessmentCase = serde_json::from_slice(&input).unwrap();
            inputs.push((scenario.clone(), compressed, case));
        }
        let mut source_hashes = serde_json::Map::new();
        for path in receipt["sourceHashes"].as_object().unwrap().keys() {
            source_hashes.insert(
                path.clone(),
                json!(hash(&fs::read(root().join(path)).unwrap())),
            );
        }

        // The clean-core guard comes last, so the input checks above also run,
        // and are tested, in a working tree that holds uncommitted product edits.
        assert!(
            Command::new("git")
                .current_dir(root())
                .args([
                    "diff",
                    "--quiet",
                    "HEAD",
                    "--",
                    "src-tauri/src",
                    "engines/catalog.json",
                    "src-tauri/Cargo.toml",
                    "Cargo.lock"
                ])
                .status()
                .unwrap()
                .success(),
            "baseline replacement requires the production core to match HEAD"
        );
        let untracked = Command::new("git")
            .current_dir(root())
            .args([
                "ls-files",
                "--others",
                "--exclude-standard",
                "--",
                "src-tauri/src",
            ])
            .output()
            .unwrap();
        assert!(
            untracked.status.success() && untracked.stdout.is_empty(),
            "baseline replacement requires no untracked production source files"
        );
        fs::create_dir_all(destination).unwrap();
        let mut scenarios = Vec::new();
        let mut changed_documents = Vec::new();
        for (mut scenario, compressed, case) in inputs {
            let name = scenario["name"].as_str().unwrap();
            let directory = destination.join(name);
            fs::create_dir_all(&directory).unwrap();
            fs::write(directory.join("case.json.gz"), compressed).unwrap();
            let output = test_temp::tempdir().unwrap();
            let documents = generate_documents(&case, output.path(), None);
            write_document_snapshots(output.path(), &directory);

            let old_documents = scenario["documents"].as_object().unwrap();
            let new_documents = documents.as_object().unwrap();
            assert!(
                old_documents
                    .keys()
                    .all(|document| new_documents.contains_key(document)),
                "{name} no longer produces a document recorded by the replaced receipt"
            );
            for (document, value) in new_documents {
                if old_documents.get(document) != Some(value) {
                    changed_documents.push(format!("{name}/{document}"));
                }
            }
            scenario["documents"] = documents;
            scenarios.push(scenario);
        }
        changed_documents.sort();
        receipt["baselineCoreRevision"] = json!(revision);
        receipt["productVersion"] = json!(env!("CARGO_PKG_VERSION"));
        receipt["capturedAt"] = json!(Utc::now());
        receipt["sourceHashes"] = Value::Object(source_hashes);
        receipt["scenarios"] = json!(scenarios);
        receipt["replaces"] = json!({
            "baselineCoreRevision": old_revision,
            "productVersion": old_version,
            "receiptSha256": hash(&receipt_bytes),
            "reason": reason,
            "inputs": "carried over byte-identical",
            "changedDocuments": changed_documents,
        });
        fs::write(
            destination.join("receipt.json"),
            serde_json::to_vec_pretty(&receipt).unwrap(),
        )
        .unwrap();
    }

    #[test]
    #[ignore = "explicit replacement of frozen outputs for a reviewed product change; see fixture README"]
    fn replace_report_fidelity_outputs() {
        let destination = PathBuf::from(
            std::env::var_os("AI_SCANNER_REPORT_BASELINE_REPLACE")
                .expect("set AI_SCANNER_REPORT_BASELINE_REPLACE to a new empty directory"),
        );
        let reason = std::env::var("AI_SCANNER_REPORT_BASELINE_REPLACE_REASON")
            .expect("set AI_SCANNER_REPORT_BASELINE_REPLACE_REASON to the replacement reason");
        replace_outputs(&baseline_dir(), &destination, &reason);
    }

    #[test]
    fn replacement_rejects_invalid_inputs_before_writing() {
        let temp = test_temp::tempdir().unwrap();
        for (index, reason) in [
            String::new(),
            "123456789".into(),
            "x".repeat(201),
            " ".repeat(10),
            "invalid\nreason".into(),
            "invalid\u{2028}reason".into(),
        ]
        .iter()
        .enumerate()
        {
            let destination = temp.path().join(index.to_string());
            assert!(
                std::panic::catch_unwind(|| {
                    replace_outputs(&baseline_dir(), &destination, reason)
                })
                .is_err()
            );
            assert!(!destination.exists());
        }

        let destination = temp.path().join("nonempty");
        fs::create_dir(&destination).unwrap();
        fs::write(destination.join("existing"), b"keep").unwrap();
        assert!(
            std::panic::catch_unwind(|| {
                replace_outputs(&baseline_dir(), &destination, "Reviewed report wording")
            })
            .is_err()
        );
        assert_eq!(fs::read(destination.join("existing")).unwrap(), b"keep");
        assert_eq!(fs::read_dir(destination).unwrap().count(), 1);
    }

    #[test]
    fn replacement_checks_every_input_before_writing() {
        let temp = test_temp::tempdir().unwrap();
        let baseline = baseline_dir();
        let copy = temp.path().join("baseline");
        fs::create_dir(&copy).unwrap();
        let receipt_bytes = fs::read(baseline.join("receipt.json")).unwrap();
        let receipt: Value = serde_json::from_slice(&receipt_bytes).unwrap();
        for scenario in receipt["scenarios"].as_array().unwrap() {
            let name = scenario["name"].as_str().unwrap();
            fs::create_dir(copy.join(name)).unwrap();
            fs::copy(
                baseline.join(name).join("case.json.gz"),
                copy.join(name).join("case.json.gz"),
            )
            .unwrap();
        }
        fs::write(copy.join("receipt.json"), &receipt_bytes).unwrap();
        let second_input = copy.join("mixed-terminal/case.json.gz");
        write_gzip(&second_input, b"corrupted input");
        let destination = temp.path().join("replacement");
        let failure = std::panic::catch_unwind(|| {
            replace_outputs(&copy, &destination, "Reviewed report wording")
        })
        .expect_err("a changed second input must be rejected");
        let message = failure
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| failure.downcast_ref::<&str>().copied())
            .unwrap();
        assert!(message.contains("mixed-terminal frozen input changed"));
        assert!(!destination.exists());

        let original = baseline.join("mixed-terminal/case.json.gz");
        let mut compressed = fs::read(&original).unwrap();
        compressed[4] ^= 1; // Change only the gzip timestamp, preserving its input bytes.
        fs::write(&second_input, compressed).unwrap();
        assert_eq!(read_gzip(&second_input), read_gzip(&original));
        let failure = std::panic::catch_unwind(|| {
            replace_outputs(&copy, &destination, "Reviewed report wording")
        })
        .expect_err("a different compressed input must be rejected");
        let message = failure
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| failure.downcast_ref::<&str>().copied())
            .unwrap();
        assert!(
            message.contains("mixed-terminal compressed input differs from the committed file")
        );
        assert!(!destination.exists());

        fs::write(copy.join("receipt.json"), b"{}").unwrap();
        let failure = std::panic::catch_unwind(|| {
            replace_outputs(&copy, &destination, "Reviewed report wording")
        })
        .expect_err("a different receipt must be rejected");
        let message = failure
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| failure.downcast_ref::<&str>().copied())
            .unwrap();
        assert!(message.contains("baseline replacement requires the committed receipt"));
        assert!(!destination.exists());
    }

    #[test]
    #[ignore = "self-check applies only while exporters match the committed corpus"]
    fn replacement_from_an_unchanged_core_changes_only_the_version_token() {
        assert!(
            std::panic::catch_unwind(frozen_report_outputs_match_baseline).is_ok(),
            "the exporters already differ from the committed corpus; this self-check applies to an unchanged core only"
        );
        let baseline = baseline_dir();
        let old_receipt_bytes = fs::read(baseline.join("receipt.json")).unwrap();
        let old_receipt: Value = serde_json::from_slice(&old_receipt_bytes).unwrap();
        let temp = test_temp::tempdir().unwrap();
        let destination = temp.path().join("replacement");
        let reason = "Unchanged core replacement self-check";
        replace_outputs(&baseline, &destination, reason);
        let receipt: Value =
            serde_json::from_slice(&fs::read(destination.join("receipt.json")).unwrap()).unwrap();
        assert_eq!(
            receipt["replaces"]["baselineCoreRevision"],
            old_receipt["baselineCoreRevision"]
        );
        assert_eq!(
            receipt["replaces"]["productVersion"],
            old_receipt["productVersion"]
        );
        assert_eq!(
            receipt["replaces"]["receiptSha256"],
            hash(&old_receipt_bytes)
        );
        assert_eq!(receipt["replaces"]["reason"], reason);
        assert_eq!(receipt["replaces"]["inputs"], "carried over byte-identical");
        assert_eq!(receipt["productVersion"], env!("CARGO_PKG_VERSION"));
        let old_sources = old_receipt["sourceHashes"].as_object().unwrap();
        let sources = receipt["sourceHashes"].as_object().unwrap();
        assert_eq!(sources.len(), old_sources.len());
        for path in old_sources.keys() {
            assert_eq!(sources[path], hash(&fs::read(root().join(path)).unwrap()));
        }
        assert!(!destination.join("visual").exists());

        let old_scenarios = old_receipt["scenarios"].as_array().unwrap();
        let scenarios = receipt["scenarios"].as_array().unwrap();
        assert_eq!(scenarios.len(), old_scenarios.len());
        let mut changed_documents = Vec::new();
        for (old, new) in old_scenarios.iter().zip(scenarios) {
            let name = old["name"].as_str().unwrap();
            for field in ["name", "caseSha256", "caseId", "runId", "sources"] {
                assert_eq!(new[field], old[field], "{name}/{field}");
            }
            assert_eq!(
                fs::read(destination.join(name).join("case.json.gz")).unwrap(),
                fs::read(baseline.join(name).join("case.json.gz")).unwrap()
            );
            let input = read_gzip(&destination.join(name).join("case.json.gz"));
            let case: AssessmentCase = serde_json::from_slice(&input).unwrap();
            let output = test_temp::tempdir().unwrap();
            let normalized = generate_documents(
                &case,
                output.path(),
                Some(&report_version::baseline_version()),
            );
            let old_documents = old["documents"].as_object().unwrap();
            let new_documents = new["documents"].as_object().unwrap();
            assert_eq!(new_documents.len(), old_documents.len());
            assert_eq!(normalized.as_object().unwrap().len(), old_documents.len());
            for (document, expected) in old_documents {
                let actual = new_documents.get(document).expect("replacement document");
                if document == "report.case.tar.gz" {
                    let mut entries = serde_json::Map::new();
                    let bundle = fs::File::open(output.path().join(document)).unwrap();
                    let mut archive = tar::Archive::new(GzDecoder::new(bundle));
                    for entry in archive.entries().unwrap() {
                        let mut entry = entry.unwrap();
                        let entry_name = entry.path().unwrap().to_str().unwrap().to_owned();
                        if entry_name.contains("signing")
                            || entry_name.contains("signature")
                            || entry_name == "manifest.json"
                        {
                            continue;
                        }
                        let mut bytes = Vec::new();
                        entry.read_to_end(&mut bytes).unwrap();
                        entries.insert(
                            entry_name,
                            json!({"sha256": hash(&bytes), "byteLength": bytes.len()}),
                        );
                    }
                    assert_eq!(
                        actual,
                        &json!({"comparison": "verified-signature-and-deterministic-payload-entries", "entries": entries})
                    );
                } else {
                    let bytes = read_gzip(&destination.join(name).join(format!("{document}.gz")));
                    assert_eq!(bytes, fs::read(output.path().join(document)).unwrap());
                    assert_eq!(
                        actual,
                        &json!({"sha256": hash(&bytes), "byteLength": bytes.len()})
                    );
                }
                assert_eq!(&normalized[document], expected, "{name}/{document}");
                if actual != expected {
                    changed_documents.push(format!("{name}/{document}"));
                }
            }
        }
        changed_documents.sort();
        assert_eq!(
            receipt["replaces"]["changedDocuments"],
            json!(changed_documents)
        );
    }

    #[test]
    fn frozen_report_outputs_match_baseline() {
        let baseline = baseline_dir();
        let receipt: Value =
            serde_json::from_slice(&fs::read(baseline.join("receipt.json")).unwrap()).unwrap();
        let output = std::env::var_os("AI_SCANNER_REPORT_BASELINE_OUTPUT").map(PathBuf::from);
        let temp = test_temp::tempdir().unwrap();
        let output = output.as_deref().unwrap_or(temp.path());
        for scenario in receipt["scenarios"].as_array().unwrap() {
            let name = scenario["name"].as_str().unwrap();
            let input = read_gzip(&baseline.join(name).join("case.json.gz"));
            assert_eq!(
                hash(&input),
                scenario["caseSha256"],
                "{name} frozen input changed"
            );
            let case: AssessmentCase = serde_json::from_slice(&input).unwrap();
            let actual = generate_documents(
                &case,
                &output.join(name),
                Some(&report_version::baseline_version()),
            );
            for (document, expected) in scenario["documents"].as_object().unwrap() {
                assert_eq!(
                    &actual[document], expected,
                    "{name}/{document} changed from the reviewed production baseline"
                );
            }
            assert_eq!(
                actual.as_object().unwrap().len(),
                scenario["documents"].as_object().unwrap().len()
            );
        }
    }
}
