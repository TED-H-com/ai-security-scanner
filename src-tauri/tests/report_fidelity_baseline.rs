//! Frozen report inputs for RF-01, generated from the existing all-engine audit.
//! The included harness uses FakeContainerRuntime and never contacts scan targets.
include!("all_engine_report_audit.rs");

mod report_fidelity {
    use super::*;
    use ai_security_scanner_lib::export::{create_case_bundle_at, verify_case_bundle};
    use flate2::{Compression, GzBuilder, read::GzDecoder};
    use serde_json::{Value, json};
    use std::io::{Read, Write};
    use std::process::Command;

    const BASELINE_COMMIT: &str = "6e259b497b87fb8aa2ece1f3b512cc29c9ea5af7";
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

    fn generate_documents(case: &AssessmentCase, destination: &Path) -> Value {
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
                    let temp = tempfile::tempdir().unwrap();
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
                    let bytes = fs::read(destination.join(&name)).unwrap();
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
            let temp = tempfile::tempdir().unwrap();
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
            let bytes = fs::read(destination.join(name)).unwrap();
            documents.insert(
                name.into(),
                json!({"sha256": hash(&bytes), "byteLength": bytes.len()}),
            );
            if let Some(companion) = exported.coverage_manifest_path {
                let bytes = fs::read(&companion).unwrap();
                let name = Path::new(&companion).file_name().unwrap().to_str().unwrap();
                documents.insert(
                    name.into(),
                    json!({"sha256": hash(&bytes), "byteLength": bytes.len()}),
                );
            }
        }
        let temp = tempfile::tempdir().unwrap();
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
                    let output = tempfile::tempdir().unwrap();
                    let documents = generate_documents(&case, output.path());
                    // Freeze exact production output, without normalizing output IDs,
                    // timestamps, ordering, prose, or HTML after rendering.
                    for entry in fs::read_dir(output.path()).unwrap() {
                        let path = entry.unwrap().path();
                        if path
                            .extension()
                            .is_some_and(|ext| ext == "html" || ext == "json")
                        {
                            let name =
                                format!("{}.gz", path.file_name().unwrap().to_str().unwrap());
                            write_gzip(&directory.join(name), &fs::read(path).unwrap());
                        }
                    }
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

    #[test]
    fn frozen_report_outputs_match_baseline() {
        let baseline = baseline_dir();
        let receipt: Value =
            serde_json::from_slice(&fs::read(baseline.join("receipt.json")).unwrap()).unwrap();
        let output = std::env::var_os("AI_SCANNER_REPORT_BASELINE_OUTPUT").map(PathBuf::from);
        let temp = tempfile::tempdir().unwrap();
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
            let actual = generate_documents(&case, &output.join(name));
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
