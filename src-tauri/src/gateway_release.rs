use crate::error::{AppError, AppResult};
use crate::managed_network::GatewayContainerSpec;
use serde::Deserialize;

const MANAGED_EGRESS_GATEWAY_MANIFEST: &str =
    include_str!("../../runtime/managed-egress-gateway.json");
const MANIFEST_SCHEMA_VERSION: &str = "1.0.0";
const MANIFEST_MAX_BYTES: usize = 4 * 1024;
#[cfg(test)]
const GATEWAY_IMAGE_REPOSITORY: &str = "ghcr.io/teddashh/ai-security-scanner-egress-gateway";
const GATEWAY_PUBLICATION_TAG: &str = "0.3.0-1";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManagedEgressGatewayManifest {
    schema_version: String,
    product_version: String,
    image: ManagedEgressGatewayImage,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManagedEgressGatewayImage {
    repository: String,
    publication_tag: String,
    digest: String,
    source_revision: String,
}

/// Returns the one immutable gateway image compiled into this product release.
///
/// The publication tag is retained as provenance only. Runtime execution uses
/// the digest-qualified [`GatewayContainerSpec`] returned here and never pulls
/// a mutable tag.
pub fn managed_egress_gateway_spec() -> AppResult<GatewayContainerSpec> {
    parse_managed_egress_gateway_manifest(MANAGED_EGRESS_GATEWAY_MANIFEST.as_bytes())
}

fn parse_managed_egress_gateway_manifest(bytes: &[u8]) -> AppResult<GatewayContainerSpec> {
    if bytes.is_empty() || bytes.len() > MANIFEST_MAX_BYTES {
        return Err(invalid_manifest(
            "manifest must be a non-empty bounded document",
        ));
    }
    let manifest: ManagedEgressGatewayManifest = serde_json::from_slice(bytes)
        .map_err(|_| invalid_manifest("manifest is malformed or contains unknown fields"))?;
    if manifest.schema_version != MANIFEST_SCHEMA_VERSION {
        return Err(invalid_manifest("schema version is unsupported"));
    }
    if manifest.product_version != env!("CARGO_PKG_VERSION") {
        return Err(invalid_manifest(
            "product version does not match the compiled application",
        ));
    }
    if !crate::publication_origins::validate_gateway_repository(&manifest.image.repository) {
        return Err(invalid_manifest("image repository is not release-owned"));
    }
    // A desktop release may reuse an already published gateway image.
    // Keep its provenance pinned independently of the application version.
    if manifest.image.publication_tag != GATEWAY_PUBLICATION_TAG {
        return Err(invalid_manifest("publication tag is not release-fixed"));
    }
    if !is_lower_hex(&manifest.image.source_revision, 40) {
        return Err(invalid_manifest(
            "source revision must be a full lowercase Git object id",
        ));
    }
    if !manifest.image.digest.starts_with("sha256:")
        || !is_lower_hex(&manifest.image.digest["sha256:".len()..], 64)
    {
        return Err(invalid_manifest(
            "image digest must be an immutable lowercase SHA-256",
        ));
    }
    GatewayContainerSpec::new(manifest.image.repository, manifest.image.digest)
        .map_err(|_| invalid_manifest("image identity is not canonical"))
}

fn is_lower_hex(value: &str, expected_len: usize) -> bool {
    value.len() == expected_len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn invalid_manifest(detail: &str) -> AppError {
    AppError::EngineRegistry(format!(
        "managed egress gateway release manifest is invalid: {detail}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest(extra: &str) -> String {
        format!(
            r#"{{
                "schema_version":"1.0.0",
                "product_version":"{}",
                "image":{{
                    "repository":"{}",
                    "publication_tag":"{}",
                    "digest":"sha256:{}",
                    "source_revision":"{}"{}
                }}
            }}"#,
            env!("CARGO_PKG_VERSION"),
            GATEWAY_IMAGE_REPOSITORY,
            GATEWAY_PUBLICATION_TAG,
            "1".repeat(64),
            "2".repeat(40),
            extra,
        )
    }

    #[test]
    fn embedded_manifest_returns_only_a_digest_qualified_image() {
        let spec = managed_egress_gateway_spec().expect("embedded gateway manifest");
        assert_eq!(spec.repository(), GATEWAY_IMAGE_REPOSITORY);
        assert!(
            spec.reference()
                .starts_with(&format!("{GATEWAY_IMAGE_REPOSITORY}@sha256:"))
        );
        assert!(!spec.reference().contains(GATEWAY_PUBLICATION_TAG));
    }

    #[test]
    fn gateway_manifest_accepts_both_publication_origins() {
        for (namespace, _) in crate::publication_origins::PUBLICATION_ORIGINS {
            let repository = format!("{namespace}/ai-security-scanner-egress-gateway");
            let input = manifest("").replace(GATEWAY_IMAGE_REPOSITORY, &repository);
            let spec = parse_managed_egress_gateway_manifest(input.as_bytes()).unwrap();
            assert_eq!(spec.repository(), repository);
        }
    }

    #[test]
    fn strict_manifest_rejects_unknown_fields_and_mutable_or_uppercase_identity() {
        assert!(
            parse_managed_egress_gateway_manifest(manifest(",\"extra\":true").as_bytes()).is_err()
        );
        let mutable = manifest("").replace(&format!("sha256:{}", "1".repeat(64)), "latest");
        assert!(parse_managed_egress_gateway_manifest(mutable.as_bytes()).is_err());
        let uppercase = manifest("").replace(&"2".repeat(40), &"A".repeat(40));
        assert!(parse_managed_egress_gateway_manifest(uppercase.as_bytes()).is_err());
    }

    #[test]
    fn strict_manifest_rejects_version_repository_tag_and_size_drift() {
        let wrong_version = manifest("").replace(env!("CARGO_PKG_VERSION"), "9.9.9");
        assert!(parse_managed_egress_gateway_manifest(wrong_version.as_bytes()).is_err());
        let wrong_repository =
            manifest("").replace(GATEWAY_IMAGE_REPOSITORY, "example.invalid/gateway");
        assert!(parse_managed_egress_gateway_manifest(wrong_repository.as_bytes()).is_err());
        let wrong_tag = manifest("").replace(GATEWAY_PUBLICATION_TAG, "0.2.0-latest");
        assert!(parse_managed_egress_gateway_manifest(wrong_tag.as_bytes()).is_err());
        assert!(
            parse_managed_egress_gateway_manifest(&vec![b' '; MANIFEST_MAX_BYTES + 1]).is_err()
        );
    }
}
