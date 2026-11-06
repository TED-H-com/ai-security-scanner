//! Typed model input and one-shot in-memory credentials for bounded native inference.
use crate::container_runtime::{CredentialSource, ScannerCredential, ScannerCredentialSet};
use crate::domain::{Asset, AssetKind, ScanPermission, ScopeGrant};
use crate::error::{AppError, AppResult};
use crate::external_scope::{
    CanonicalTarget, ExternalActivity, ExternalScopeGrant, TransportProtocol,
};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::{Arc, Condvar, Mutex};
use url::Url;
use zeroize::Zeroizing;

pub const ENGINE_ID: &str = "garak";
pub const PROFILE_ID: &str = "garak_https_v1";
pub const SOURCE_REVISION: &str = "7aa740fe7412cc9bc33cdc39ca211843223cd3e1";
pub const METADATA_KEY: &str = "model_endpoint";
pub const ENDPOINT_NAMESPACE: &str = "ai-security-scanner:model-endpoint";
pub const MODEL_NAMESPACE: &str = "ai-security-scanner:model-id";
pub const PROBES: [&str; 4] = [
    "dan.Dan_11_0",
    "dan.Dan_10_0",
    "dan.Dan_9_0",
    "ansiescape.AnsiEscaped",
];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ModelEndpointInput {
    pub endpoint: String,
    pub model: String,
}

impl ModelEndpointInput {
    pub fn validated(endpoint: &str, model: &str) -> AppResult<Self> {
        let endpoint = endpoint.trim();
        let model = model.trim();
        let reject = || {
            AppError::InvalidRequest(
                "provide one exact HTTPS chat-completions URL and model identifier".into(),
            )
        };
        if endpoint.len() > 512
            || !endpoint.is_ascii()
            || endpoint.bytes().any(|b| b <= 32 || b == 127)
            || endpoint.contains(['\\', '?', '#', '%'])
            || model.is_empty()
            || model.len() > 128
            || !model
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._:/-".contains(&b))
            || !model.as_bytes()[0].is_ascii_alphanumeric()
        {
            return Err(reject());
        }
        let (_, path) = endpoint
            .strip_prefix("https://")
            .and_then(|s| s.split_once('/'))
            .ok_or_else(reject)?;
        if path.split('/').any(|s| matches!(s, "" | "." | "..")) {
            return Err(reject());
        }
        let uri = Url::parse(endpoint).map_err(|_| reject())?;
        if uri.scheme() != "https"
            || uri.host_str().is_none()
            || !uri.username().is_empty()
            || uri.password().is_some()
            || uri.port_or_known_default().is_none_or(|p| p == 0)
        {
            return Err(reject());
        }
        Ok(Self {
            endpoint: uri.to_string(),
            model: model.into(),
        })
    }

    pub fn target(&self) -> AppResult<CanonicalTarget> {
        let uri = Url::parse(&self.endpoint)
            .map_err(|_| AppError::InvalidRequest("invalid model endpoint".into()))?;
        CanonicalTarget::parse(
            uri.host_str()
                .ok_or_else(|| AppError::InvalidRequest("model endpoint lacks a host".into()))?
                .trim_matches(['[', ']']),
        )
    }

    pub fn matches_scope(&self, scope: &ExternalScopeGrant, now: DateTime<Utc>) -> AppResult<bool> {
        let uri = Url::parse(&self.endpoint)
            .map_err(|_| AppError::InvalidRequest("invalid model endpoint".into()))?;
        let template = &scope.template_policy;
        Ok(scope.target == self.target()?
            && scope.ports
                == std::collections::BTreeSet::from([uri.port_or_known_default().unwrap_or(443)])
            && scope.protocol == TransportProtocol::Https
            && scope.activity == ExternalActivity::ActiveExternal
            && scope.rate_policy.requests_per_second == 1
            && scope.rate_policy.concurrency == 1
            && scope.rate_policy.timeout_seconds == 20
            && scope.expires_at > now
            && scope.expires_at <= now + Duration::hours(1)
            && scope.approved_at <= now
            && template.revision == SOURCE_REVISION
            && template.profile_id.as_deref() == Some(PROFILE_ID)
            && template.allowed_template_ids.is_empty()
            && !template.allow_headless
            && !template.allow_out_of_band
            && !template.allow_fuzzing
            && !template.allow_file_upload
            && !template.allow_denial_of_service
            && !template.allow_credential_attacks)
    }
}

pub fn asset_input(asset: &Asset) -> AppResult<ModelEndpointInput> {
    let invalid = || {
        AppError::NotAuthorized(
            "model input no longer matches its frozen endpoint and model".into(),
        )
    };
    if asset.kind != AssetKind::AiModelEndpoint {
        return Err(invalid());
    }
    let value = asset.metadata.get(METADATA_KEY).ok_or_else(invalid)?;
    let input: ModelEndpointInput = serde_json::from_value(value.clone()).map_err(|_| invalid())?;
    if ModelEndpointInput::validated(&input.endpoint, &input.model)? != input {
        return Err(invalid());
    }
    for (namespace, expected) in [
        (ENDPOINT_NAMESPACE, &input.endpoint),
        (MODEL_NAMESPACE, &input.model),
    ] {
        let ids: Vec<_> = asset
            .identifiers
            .iter()
            .filter(|id| id.namespace == namespace)
            .collect();
        if ids.len() != 1 || ids[0].value != *expected {
            return Err(invalid());
        }
    }
    Ok(input)
}

struct ModelKey {
    input: ModelEndpointInput,
    value: Zeroizing<String>,
    expires_at: DateTime<Utc>,
}

#[derive(Default)]
struct SessionStore {
    entries: Mutex<BTreeMap<(String, String), ModelKey>>,
    changed: Condvar,
}

pub struct ModelEndpointSessions {
    store: Arc<SessionStore>,
}

impl Default for ModelEndpointSessions {
    fn default() -> Self {
        let store = Arc::new(SessionStore::default());
        let weak = Arc::downgrade(&store);
        std::thread::spawn(move || {
            while let Some(store) = weak.upgrade() {
                let Ok(mut entries) = store.entries.lock() else {
                    break;
                };
                let now = Utc::now();
                entries.retain(|_, key| key.expires_at > now);
                let delay = entries
                    .values()
                    .map(|key| key.expires_at - now)
                    .min()
                    .unwrap_or(Duration::seconds(60))
                    .to_std()
                    .unwrap_or_default();
                let Ok((entries, _)) = store.changed.wait_timeout(entries, delay) else {
                    break;
                };
                drop(entries);
            }
        });
        Self { store }
    }
}

impl Drop for ModelEndpointSessions {
    fn drop(&mut self) {
        if let Ok(mut entries) = self.store.entries.lock() {
            entries.clear();
        }
        self.store.changed.notify_one();
    }
}

impl ModelEndpointSessions {
    pub fn put(
        &self,
        case_id: &str,
        asset: &Asset,
        value: Zeroizing<String>,
        now: DateTime<Utc>,
    ) -> AppResult<()> {
        if value.is_empty()
            || value.len() > 4096
            || !value.is_ascii()
            || value.bytes().any(|b| b <= 32 || b == 127)
        {
            return Err(AppError::InvalidRequest(
                "model API key must be a bounded non-empty header value".into(),
            ));
        }
        let input = asset_input(asset)?;
        let mut entries =
            self.store.entries.lock().map_err(|_| {
                AppError::Internal("model credential session is unavailable".into())
            })?;
        entries.retain(|_, e| e.expires_at > now);
        if entries.len() >= 64 && !entries.contains_key(&(case_id.into(), asset.id.clone())) {
            return Err(AppError::NotAvailable(
                "too many pending model keys; start a check or close an unused case".into(),
            ));
        }
        entries.insert(
            (case_id.into(), asset.id.clone()),
            ModelKey {
                input,
                value,
                expires_at: now + Duration::minutes(30),
            },
        );
        self.store.changed.notify_one();
        Ok(())
    }

    /// Consumed before dispatch; failed or interrupted inference cannot silently bill a second run.
    pub fn take(
        &self,
        case_id: &str,
        asset: &Asset,
        grants: &[ScopeGrant],
        now: DateTime<Utc>,
    ) -> AppResult<ScannerCredentialSet> {
        let input = asset_input(asset)?;
        if grants.len() != 1
            || grants[0].asset_id != asset.id
            || grants[0].permission != ScanPermission::ActiveExternalTesting
            || grants[0].confirmed_at > now
            || grants[0].confirmed_by.trim().is_empty()
            || grants[0].expires_at.is_some_and(|expiry| expiry <= now)
            || grants[0]
                .authorization_reference
                .as_deref()
                .is_none_or(|s| s.trim().is_empty())
            || !grants[0].external_scope.as_ref().is_some_and(|scope| {
                scope.case_id == case_id
                    && scope.asset_id == asset.id
                    && scope.validate(now).is_ok()
                    && input.matches_scope(scope, now).unwrap_or(false)
            })
        {
            return Err(AppError::NotAuthorized(
                "model inference requires its exact live profile grant".into(),
            ));
        }
        let mut entries =
            self.store.entries.lock().map_err(|_| {
                AppError::Internal("model credential session is unavailable".into())
            })?;
        entries.retain(|_, e| e.expires_at > now);
        let key = entries
            .remove(&(case_id.into(), asset.id.clone()))
            .ok_or_else(|| {
                AppError::NotAuthorized(
                    "enter a new local model API key before starting this model check".into(),
                )
            })?;
        if key.input != input {
            return Err(AppError::NotAuthorized(
                "model credential was entered for a different endpoint or model".into(),
            ));
        }
        ScannerCredentialSet::new(vec![ScannerCredential::from_vault(
            "REST_API_KEY",
            key.value,
            key.expires_at,
            CredentialSource::LocalModelEndpoint,
        )?])
    }

    pub fn revoke_case(&self, case_id: &str) -> AppResult<()> {
        self.store
            .entries
            .lock()
            .map_err(|_| AppError::Internal("model credential session is unavailable".into()))?
            .retain(|(id, _), _| id != case_id);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::AssetIdentifier;
    use serde_json::json;

    fn fixture(now: DateTime<Utc>) -> (Asset, ScopeGrant) {
        let input = ModelEndpointInput::validated(
            "https://model.example.test/v1/chat/completions",
            "fixture/model",
        )
        .unwrap();
        let asset = Asset {
            id: "model-1".into(),
            kind: AssetKind::AiModelEndpoint,
            name: "fixture".into(),
            provider: None,
            region: None,
            identifiers: vec![
                AssetIdentifier {
                    namespace: ENDPOINT_NAMESPACE.into(),
                    value: input.endpoint.clone(),
                },
                AssetIdentifier {
                    namespace: MODEL_NAMESPACE.into(),
                    value: input.model.clone(),
                },
            ],
            discovered_from: vec![],
            candidate: false,
            owner_confirmed: true,
            internet_exposed: Some(true),
            contains_sensitive_data: None,
            metadata: BTreeMap::from([(METADATA_KEY.into(), json!(input))]),
        };
        let external: ExternalScopeGrant = serde_json::from_value(json!({
            "id": "external-1", "case_id": "case-1", "asset_id": asset.id,
            "target": {"kind": "hostname", "value": "model.example.test"}, "ports": [443], "protocol": "https", "activity": "active_external",
            "rate_policy": {"requests_per_second": 1, "concurrency": 1, "timeout_seconds": 20},
            "template_policy": {"revision": SOURCE_REVISION, "profile_id": PROFILE_ID, "allowed_template_ids": [],
                "allow_headless": false, "allow_out_of_band": false, "allow_fuzzing": false, "allow_file_upload": false,
                "allow_denial_of_service": false, "allow_credential_attacks": false},
            "asserted_authority": "owned fixture model", "approved_by": "fixture owner", "approved_at": now,
            "expires_at": now + Duration::minutes(30), "allow_sensitive_networks": false
        })).unwrap();
        let grant = ScopeGrant {
            id: "grant-1".into(),
            asset_id: asset.id.clone(),
            permission: ScanPermission::ActiveExternalTesting,
            confirmed_by: "fixture owner".into(),
            confirmed_at: now,
            expires_at: Some(now + Duration::minutes(30)),
            authorization_reference: Some("owned fixture model".into()),
            notes: None,
            external_scope: Some(external),
        };
        (asset, grant)
    }

    #[test]
    fn a_key_is_consumed_once_and_never_appears_in_debug_output() {
        let now = Utc::now();
        let (asset, grant) = fixture(now);
        let sessions = ModelEndpointSessions::default();
        sessions
            .put(
                "case-1",
                &asset,
                Zeroizing::new("synthetic-local-key".into()),
                now,
            )
            .unwrap();
        let credentials = sessions
            .take("case-1", &asset, std::slice::from_ref(&grant), now)
            .unwrap();
        assert_eq!(
            credentials.provider_secret("REST_API_KEY"),
            Some("synthetic-local-key")
        );
        assert!(!format!("{credentials:?}").contains("synthetic-local-key"));
        assert!(sessions.take("case-1", &asset, &[grant], now).is_err());
    }

    #[test]
    fn an_idle_expired_key_is_erased_without_another_command() {
        let now = Utc::now();
        let (asset, _) = fixture(now);
        let sessions = ModelEndpointSessions::default();
        sessions
            .put(
                "case-1",
                &asset,
                Zeroizing::new("synthetic-idle-key".into()),
                now - Duration::minutes(30) + Duration::milliseconds(100),
            )
            .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while !sessions.store.entries.lock().unwrap().is_empty()
            && std::time::Instant::now() < deadline
        {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(sessions.store.entries.lock().unwrap().is_empty());
    }

    #[test]
    fn expired_deleted_or_changed_model_keys_cannot_be_reused() {
        let now = Utc::now();
        let (asset, grant) = fixture(now);
        let sessions = ModelEndpointSessions::default();
        sessions
            .put(
                "case-1",
                &asset,
                Zeroizing::new("synthetic".into()),
                now - Duration::minutes(31),
            )
            .unwrap();
        assert!(
            sessions
                .take("case-1", &asset, std::slice::from_ref(&grant), now)
                .is_err()
        );
        sessions
            .put("case-1", &asset, Zeroizing::new("synthetic".into()), now)
            .unwrap();
        sessions.revoke_case("case-1").unwrap();
        assert!(
            sessions
                .take("case-1", &asset, std::slice::from_ref(&grant), now)
                .is_err()
        );
        sessions
            .put("case-1", &asset, Zeroizing::new("synthetic".into()), now)
            .unwrap();
        let mut changed = asset.clone();
        changed.metadata.get_mut(METADATA_KEY).unwrap()["model"] = json!("different/model");
        changed
            .identifiers
            .iter_mut()
            .find(|id| id.namespace == MODEL_NAMESPACE)
            .unwrap()
            .value = "different/model".into();
        assert!(
            sessions
                .take("case-1", &changed, std::slice::from_ref(&grant), now)
                .is_err()
        );
        assert!(sessions.take("case-1", &asset, &[grant], now).is_err());
    }

    #[test]
    fn unrelated_permissions_cases_or_wider_profiles_never_dispatch_the_key() {
        let now = Utc::now();
        let (asset, grant) = fixture(now);
        let sessions = ModelEndpointSessions::default();
        sessions
            .put("case-1", &asset, Zeroizing::new("synthetic".into()), now)
            .unwrap();
        let mutations: [fn(&mut ScopeGrant); 8] = [
            |g| g.permission = ScanPermission::LocalArtifactRead,
            |g| g.authorization_reference = None,
            |g| g.confirmed_by.clear(),
            |g| g.expires_at = Some(Utc::now() - Duration::seconds(1)),
            |g| g.external_scope.as_mut().unwrap().case_id = "other-case".into(),
            |g| g.external_scope.as_mut().unwrap().asset_id = "other-model".into(),
            |g| {
                g.external_scope
                    .as_mut()
                    .unwrap()
                    .rate_policy
                    .requests_per_second = 2
            },
            |g| {
                g.external_scope
                    .as_mut()
                    .unwrap()
                    .template_policy
                    .allow_file_upload = true
            },
        ];
        for mutation in mutations {
            let mut changed = grant.clone();
            mutation(&mut changed);
            assert!(sessions.take("case-1", &asset, &[changed], now).is_err());
        }
        assert!(
            sessions
                .take("case-1", &asset, &[grant.clone(), grant.clone()], now)
                .is_err()
        );
        assert!(
            sessions
                .take("other-case", &asset, std::slice::from_ref(&grant), now)
                .is_err()
        );
        assert!(sessions.take("case-1", &asset, &[grant], now).is_ok());
    }

    #[test]
    fn malformed_saved_model_coordinates_or_header_values_are_not_usable() {
        let now = Utc::now();
        let (asset, _) = fixture(now);
        let sessions = ModelEndpointSessions::default();
        for key in [
            "",
            "key\r\nX-Other: injected",
            "key with spaces",
            "非 ASCII",
        ] {
            assert!(
                sessions
                    .put("case-1", &asset, Zeroizing::new(key.into()), now)
                    .is_err()
            );
        }
        let mut ambiguous = asset.clone();
        ambiguous.identifiers.push(ambiguous.identifiers[0].clone());
        assert!(asset_input(&ambiguous).is_err());
        let mut changed = asset.clone();
        changed.metadata.get_mut(METADATA_KEY).unwrap()["api_key"] = json!("unexpected");
        assert!(asset_input(&changed).is_err());
        changed = asset;
        changed.kind = AssetKind::WebService;
        assert!(asset_input(&changed).is_err());
    }
    #[test]
    fn exact_endpoint_rejects_redirect_credential_and_path_ambiguity() {
        let good = ModelEndpointInput::validated(
            "https://MODEL.example.test:443/v1/chat/completions",
            "fixture/model",
        )
        .unwrap();
        assert_eq!(
            good.endpoint,
            "https://model.example.test/v1/chat/completions"
        );
        for endpoint in [
            "http://model.example.test/a",
            "https://key@model.example.test/a",
            "https://model.example.test/",
            "https://model.example.test/a/../b",
            "https://model.example.test/a%2fb",
            "https://model.example.test/a?key=x",
            "https://model.example.test/a#x",
        ] {
            assert!(
                ModelEndpointInput::validated(endpoint, "fixture").is_err(),
                "{endpoint}"
            );
        }
        for model in ["", "--exec shell", "a\nkey"] {
            assert!(ModelEndpointInput::validated(&good.endpoint, model).is_err());
        }
    }
}
