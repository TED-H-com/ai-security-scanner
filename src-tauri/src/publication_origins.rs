use crate::domain::ImageReference;
use crate::error::{AppError, AppResult};

// Keep released pins and new publications in their respective namespaces.
pub const PUBLICATION_ORIGINS: [(&str, &str); 2] = [
    ("ghcr.io/teddashh", "teddashh/ai-security-scanner"),
    ("ghcr.io/ted-h-com", "TED-H-com/ai-security-scanner"),
];

pub fn publication_repository(image: &str) -> Option<&'static str> {
    PUBLICATION_ORIGINS
        .iter()
        .find_map(|(namespace, repository)| {
            image
                .strip_prefix(namespace)
                .filter(|suffix| {
                    suffix.starts_with('/') && suffix.len() > 1 && !suffix[1..].contains('/')
                })
                .map(|_| *repository)
        })
}

pub fn validate_gateway_repository(image: &str) -> bool {
    publication_repository(image).is_some()
        && image.rsplit('/').next() == Some("ai-security-scanner-egress-gateway")
}

pub fn validate_engine_publication(image: &ImageReference) -> AppResult<()> {
    // Upstream packages remain upstream; project-managed packages have a closed origin policy.
    let package = image.repository.rsplit('/').next().unwrap_or_default();
    if !package.starts_with("ai-security-scanner-engine-") && image.signature_identity.is_none() {
        return Ok(());
    }
    let repository = publication_repository(&image.repository).ok_or_else(invalid_origin)?;
    if let Some(identity) = &image.signature_identity {
        let prefix = format!("https://github.com/{repository}/.github/workflows/");
        let workflow = identity.strip_prefix(&prefix).ok_or_else(invalid_origin)?;
        let (file, reference) = workflow.split_once('@').ok_or_else(invalid_origin)?;
        if file.is_empty()
            || file.contains('/')
            || !file.ends_with(".yml")
            || !reference.starts_with("refs/")
            || reference.contains('@')
        {
            return Err(invalid_origin());
        }
    }
    Ok(())
}

fn invalid_origin() -> AppError {
    AppError::EngineRegistry("unrecognized or mixed publication origin".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn publication_pairs_accept_both_origins_and_reject_mixed_and_unknown() {
        for (namespace, repository) in PUBLICATION_ORIGINS {
            let mut image = ImageReference {
                repository: format!("{namespace}/ai-security-scanner-engine-gitleaks"),
                tag: Some("fixture".into()),
                digest: Some(format!("sha256:{}", "1".repeat(64))),
                signature_identity: Some(format!(
                    "https://github.com/{repository}/.github/workflows/engine-image-gitleaks.yml@refs/heads/main"
                )),
            };
            assert!(validate_engine_publication(&image).is_ok());
            let other = PUBLICATION_ORIGINS
                .iter()
                .find(|(_, repo)| *repo != repository)
                .unwrap()
                .1;
            image.signature_identity = image
                .signature_identity
                .map(|value| value.replace(repository, other));
            assert!(validate_engine_publication(&image).is_err());
            image.repository = "ghcr.io/unknown/ai-security-scanner-engine-gitleaks".into();
            assert!(validate_engine_publication(&image).is_err());
            assert!(validate_gateway_repository(&format!(
                "{namespace}/ai-security-scanner-egress-gateway"
            )));
        }
        assert!(!validate_gateway_repository(
            "ghcr.io/unknown/ai-security-scanner-egress-gateway"
        ));
        assert!(!validate_gateway_repository(
            "ghcr.io/teddashh.evil/ai-security-scanner-egress-gateway"
        ));
    }
}
