//! Fixed product policy. Repository text is data and cannot configure these rules.
use super::*;
use crate::workspace_snapshot::{SECRET_NAME_CLASSIFIER_VERSION, likely_secret_config_file_name};

pub const POLICY_ID: &str = "ai-source-view-v1";
pub const MIB: u64 = 1024 * 1024;
pub const MARKERS: [&str; 7] = [
    "-----BEGIN PRIVATE KEY-----",
    "-----BEGIN ENCRYPTED PRIVATE KEY-----",
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN DSA PRIVATE KEY-----",
    "-----BEGIN EC PRIVATE KEY-----",
    "-----BEGIN OPENSSH PRIVATE KEY-----",
    "-----BEGIN PGP PRIVATE KEY BLOCK-----",
];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub id: String,
    pub rules_version: u32,
    pub sensitive_name_classifier_version: u32,
    pub markers: Vec<String>,
    pub text_rules: Vec<String>,
    pub rule_order: Vec<String>,
    pub limits: Limits,
    pub scope: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    pub files: usize,
    pub total_bytes: u64,
    pub file_bytes: u64,
    pub path_components: usize,
    pub scope_selectors: usize,
    pub source_bytes: u64,
    pub manifest_bytes: u64,
    pub canonical_manifest_bytes: u64,
}
impl Policy {
    pub fn new(scope: Vec<String>) -> Self {
        Self {
            id: POLICY_ID.into(),
            rules_version: 1,
            sensitive_name_classifier_version: SECRET_NAME_CLASSIFIER_VERSION,
            markers: MARKERS.iter().map(|s| (*s).into()).collect(),
            text_rules: [
                "utf8",
                "no_nul_or_ascii_controls_except_tab_lf_cr",
                "no_del",
                "identity_bytes",
            ]
            .map(String::from)
            .into(),
            rule_order: [
                "canonical_exclusions",
                "outside_scope",
                "sensitive_name",
                "unsupported_path",
                "oversize_file",
                "non_utf8_text",
                "binary_control_bytes",
                "private_key_marker",
            ]
            .map(String::from)
            .into(),
            limits: Limits {
                files: 10_000,
                total_bytes: 128 * MIB,
                file_bytes: 8 * MIB,
                path_components: 32,
                scope_selectors: 256,
                source_bytes: 2 * MIB,
                manifest_bytes: 128 * MIB,
                canonical_manifest_bytes: 64 * MIB,
            },
            scope,
        }
    }
    pub fn sha256(&self) -> AppResult<String> {
        domain_digest("ai-security-scanner.ai-source-policy/v1", self)
    }
}

pub fn normalize_scope(paths: &[String]) -> AppResult<Vec<String>> {
    if paths.is_empty() || paths.len() > 256 {
        return Err(invalid(
            "provide 1–256 explicit --scope-path selectors (use . for the whole snapshot)",
        ));
    }
    for path in paths {
        if path != "."
            && (path.len() > 4096
                || path
                    .split('/')
                    .any(|part| part.is_empty() || part == "." || part == "..")
                || path
                    .chars()
                    .any(|c| c.is_control() || "\\:*?[]".contains(c)))
        {
            return Err(invalid("malformed scope selector"));
        }
    }
    if paths.iter().any(|p| p == ".") {
        return Ok(vec![".".into()]);
    }
    let mut paths = paths.to_vec();
    paths.sort();
    paths.dedup();
    let mut result: Vec<String> = Vec::new();
    for path in paths {
        if !result.iter().any(|parent| beneath(&path, parent)) {
            result.push(path);
        }
    }
    Ok(result)
}
pub(super) fn beneath(path: &str, parent: &str) -> bool {
    parent == "."
        || path == parent
        || path
            .strip_prefix(parent)
            .is_some_and(|s| s.starts_with('/'))
}
pub(super) fn content_reason(bytes: &[u8]) -> Option<ExclusionReason> {
    if std::str::from_utf8(bytes).is_err() {
        return Some(ExclusionReason::NonUtf8Text);
    }
    if bytes
        .iter()
        .any(|b| (*b < 32 && ![9, 10, 13].contains(b)) || *b == 127)
    {
        return Some(ExclusionReason::BinaryControlBytes);
    }
    if MARKERS
        .iter()
        .any(|m| bytes.windows(m.len()).any(|w| w == m.as_bytes()))
    {
        return Some(ExclusionReason::PrivateKeyMarker);
    }
    None
}
pub(super) fn sensitive(path: &str) -> bool {
    likely_secret_config_file_name(path.rsplit('/').next().unwrap_or(path))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn text_rules_preserve_line_mapping_and_exclude_whole_files() {
        for bytes in [
            b"".as_slice(),
            b"a\r\nb\n",
            "\u{feff}中文".as_bytes(),
            b"a\t b",
        ] {
            assert_eq!(content_reason(bytes), None);
        }
        assert_eq!(content_reason(&[255]), Some(ExclusionReason::NonUtf8Text));
        for b in (0..32).filter(|b| ![9, 10, 13].contains(b)).chain([127]) {
            assert_eq!(
                content_reason(&[b]),
                Some(ExclusionReason::BinaryControlBytes)
            );
        }
        for marker in MARKERS {
            for prefix in [
                "\u{feff}",
                "    ",
                "example\r\n",
                "not at start ",
                &"a".repeat(8190),
            ] {
                assert_eq!(
                    content_reason(format!("{prefix}{marker}\r\nFAKE\r\n").as_bytes()),
                    Some(ExclusionReason::PrivateKeyMarker)
                );
            }
        }
        assert_eq!(content_reason(b"----BEGIN PRIVATE KEY-----"), None);
    }
    #[test]
    fn scope_is_explicit_normalized_and_component_bounded() {
        assert!(normalize_scope(&[]).is_err());
        for path in [
            "../x", "src//x", "src/*", "/src", "src/.", "src\\x", "src/", "",
        ] {
            assert!(normalize_scope(&[path.into()]).is_err());
        }
        assert_eq!(
            normalize_scope(&["src/x".into(), "src".into(), "src2".into()]).unwrap(),
            ["src", "src2"]
        );
        assert!(!beneath("src2/a", "src"));
    }
}

#[cfg(test)]
#[test]
fn policy_index_identity_golden_vectors() {
    let bytes = std::fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../tests/fixtures/cloudflare/source-view-policy/golden.json"),
    )
    .unwrap();
    let golden: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let policy = Policy::new(vec![".".into()]);
    assert_eq!(serde_json::to_value(&policy).unwrap(), golden["policy"]);
    assert_eq!(policy.sha256().unwrap(), golden["policy_sha256"]);
    let files: Vec<BundleFile> = serde_json::from_value(golden["files"].clone()).unwrap();
    assert_eq!(
        file_index_digest(&files).unwrap(),
        golden["file_index_sha256"]
    );
    let payload = &golden["identity_payload"];
    let view = ViewManifest {
        schema_version: VIEW_SCHEMA.into(),
        identity_recipe: "ai-security-scanner.ai-source-view-identity/v1".into(),
        source: SourceView {
            canonical_snapshot_id: Some(
                payload["lineage"]["canonical_snapshot_id"]
                    .as_str()
                    .unwrap()
                    .into(),
            ),
            canonical_snapshot_sha256: Some(
                payload["lineage"]["canonical_manifest_sha256"]
                    .as_str()
                    .unwrap()
                    .into(),
            ),
            view_id: String::new(),
            view_sha256: file_index_digest(&files).unwrap(),
            source_ref: payload["source_ref"].as_str().unwrap().into(),
            policy_id: policy.id.clone(),
            files,
        },
        policy_sha256: policy.sha256().unwrap(),
        policy,
        lineage: serde_json::from_value(payload["lineage"].clone()).unwrap(),
        exclusions: serde_json::from_value(payload["exclusions"].clone()).unwrap(),
        included_file_count: 5,
        omitted_file_count: 1,
        included_bytes: 13,
        line_mapping: "identity".into(),
    };
    assert_eq!(view.identity().unwrap(), golden["view_id"]);
}
