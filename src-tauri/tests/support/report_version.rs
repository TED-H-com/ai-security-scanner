use serde_json::Value;

pub fn baseline_version() -> String {
    let receipt: Value = serde_json::from_slice(
        &std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../tests/fixtures/report-fidelity/receipt.json"
        ))
        .unwrap(),
    )
    .unwrap();
    receipt["productVersion"].as_str().unwrap().to_owned()
}

// Replace only the product's version token at the known export locations.
// Do not reserialize the document: whitespace, ordering, and every other byte
// remain part of the frozen comparison. Subobject matching is intentionally
// exact, so a formatting change also fails the comparison.
pub fn normalize(name: &str, bytes: &[u8], version: &str) -> Vec<u8> {
    let mut text = std::str::from_utf8(bytes).unwrap().to_owned();
    match name {
        "en-full.json"
        | "en-standard.json"
        | "zh-Hant-full.json"
        | "zh-Hant-standard.json"
        | "framework.json"
        | "exports/beginner-master-report.json"
        | "exports/master-framework-report.json" => {
            let value: Value = serde_json::from_slice(bytes).unwrap();
            assert_eq!(value["product_name"], "ai-security-scanner");
            assert_eq!(value["product_version"], env!("CARGO_PKG_VERSION"));
            let before = format!(
                "\n  \"product_version\": {:?},\n",
                env!("CARGO_PKG_VERSION")
            );
            let after = format!("\n  \"product_version\": {version:?},\n");
            assert_eq!(text.matches(&before).count(), 1);
            text = text.replacen(&before, &after, 1);
        }
        "ocsf.json" | "exports/ocsf-events.json" => {
            let events: Value = serde_json::from_slice(bytes).unwrap();
            for event in events.as_array().unwrap() {
                let product = &event["metadata"]["product"];
                assert_eq!(product["name"], "ai-security-scanner");
                replace_object(&mut text, "product", product, 6, version);
            }
        }
        "oscal.json" | "exports/oscal-assessment-results.json" => {
            let value: Value = serde_json::from_slice(bytes).unwrap();
            replace_object(
                &mut text,
                "metadata",
                &value["assessment-results"]["metadata"],
                4,
                version,
            );
        }
        _ => {}
    }
    text.into_bytes()
}

fn replace_object(text: &mut String, key: &str, object: &Value, indent: usize, version: &str) {
    assert_eq!(object["version"], env!("CARGO_PKG_VERSION"));
    let prefix = format!("\n{}{key:?}: ", " ".repeat(indent));
    let render = |value: &Value| {
        format!(
            "{prefix}{}",
            serde_json::to_string_pretty(value)
                .unwrap()
                .replace('\n', &format!("\n{}", " ".repeat(indent)))
        )
    };
    let before = render(object);
    let mut normalized = object.clone();
    normalized["version"] = version.into();
    assert!(text.contains(&before), "missing product {key} object");
    *text = text.replacen(&before, &render(&normalized), 1);
}
