//! Selected scanner-image preparation without scan admission or target contact.

use crate::adapter::AdapterRegistry;
use crate::container_runtime::{
    ImagePreparationAcquisition, PinnedImage, ProcessContainerRuntime, RuntimePreflight,
};
pub use crate::core_state::{resolve_execution_runtime, resolve_preparation_runtime};
use crate::domain::{DistributionMode, EngineManifest, ScanPermission};
use crate::error::{AppError, AppResult};
use crate::gateway_release::managed_egress_gateway_spec;
use crate::registry::EngineRegistry;
use serde::Serialize;
use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, Ordering};

pub const RUNTIME_PREPARATION_SCHEMA: &str = "ai-security-scanner.runtime-preparation/v1";
const MAX_SELECTED_ENGINES: usize = 25;

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuntimePreparationRole {
    Engine,
    Gateway,
}

#[derive(Debug, Clone, Serialize)]
pub struct RuntimePreparationImage {
    pub role: RuntimePreparationRole,
    pub engine_ids: Vec<String>,
    pub image: String,
    #[serde(skip)]
    pin: PinnedImage,
}

#[derive(Debug, Clone, Serialize)]
pub struct RuntimePreparationPlan {
    pub engine_ids: Vec<String>,
    pub images: Vec<RuntimePreparationImage>,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuntimePreparationStatus {
    Ready,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, Serialize)]
pub struct RuntimePreparationImageOutcome {
    pub role: RuntimePreparationRole,
    pub engine_ids: Vec<String>,
    pub image: String,
    pub status: RuntimePreparationStatus,
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acquisition: Option<ImagePreparationAcquisition>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RuntimePreparationReport {
    pub schema_version: String,
    pub ready: bool,
    pub offline: bool,
    pub engines: Vec<String>,
    pub runtime: Option<RuntimePreflight>,
    pub images: Vec<RuntimePreparationImageOutcome>,
}

impl RuntimePreparationPlan {
    /// Validate the entire selection before any runtime can be resolved. The
    /// catalog and existing adapters decide admissibility; no caller-provided
    /// repository, image tag, command, source path, or target is accepted.
    pub fn new(
        registry: &EngineRegistry,
        adapters: &AdapterRegistry,
        engine_ids: &[String],
    ) -> AppResult<Self> {
        if engine_ids.is_empty() || engine_ids.len() > MAX_SELECTED_ENGINES {
            return Err(AppError::InvalidRequest(
                "select between one and 25 scanner engines".into(),
            ));
        }
        let mut seen = BTreeSet::new();
        let mut selected = Vec::new();
        for id in engine_ids {
            if id.is_empty()
                || id.len() > 128
                || !id
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                || !seen.insert(id.as_str())
            {
                return Err(AppError::InvalidRequest(
                    "scanner engine IDs must be bounded, exact, and unique".into(),
                ));
            }
            let manifest = registry
                .get(id)
                .ok_or_else(|| AppError::InvalidRequest(format!("unknown scanner engine: {id}")))?;
            if let Some(blocker) = manifest.release_blocker() {
                return Err(AppError::NotAvailable(format!(
                    "scanner engine {id} is unavailable: {blocker}"
                )));
            }
            if matches!(
                manifest.distribution_mode,
                DistributionMode::ExternalExecutable
            ) {
                return Err(AppError::NotAvailable(format!(
                    "scanner engine {id} does not use a pinned container image"
                )));
            }
            let adapter = adapters.get(id).ok_or_else(|| {
                AppError::NotAvailable(format!("scanner engine {id} has no loaded adapter"))
            })?;
            if adapter.adapter_version() != manifest.adapter_version {
                return Err(AppError::NotAvailable(format!(
                    "scanner engine {id} adapter version does not match its catalog"
                )));
            }
            selected.push((manifest, PinnedImage::from_manifest(manifest)?));
        }
        let mut images: Vec<RuntimePreparationImage> = Vec::new();
        let mut gateway_engines = Vec::new();
        for (manifest, pin) in selected {
            if let Some(existing) = images.iter_mut().find(|image| image.pin == pin) {
                existing.engine_ids.push(manifest.id.clone());
            } else {
                images.push(RuntimePreparationImage {
                    role: RuntimePreparationRole::Engine,
                    engine_ids: vec![manifest.id.clone()],
                    image: pin.reference(),
                    pin,
                });
            }
            if manifest_needs_managed_network(manifest) {
                gateway_engines.push(manifest.id.clone());
            }
        }
        if !gateway_engines.is_empty() {
            let gateway = managed_egress_gateway_spec()?;
            let pin = PinnedImage::new(gateway.repository(), gateway.digest())?;
            images.push(RuntimePreparationImage {
                role: RuntimePreparationRole::Gateway,
                engine_ids: gateway_engines,
                image: pin.reference(),
                pin,
            });
        }
        Ok(Self {
            engine_ids: engine_ids.to_vec(),
            images,
        })
    }

    pub fn report_for_failure(
        &self,
        offline: bool,
        error: &str,
        cancelled: bool,
    ) -> RuntimePreparationReport {
        let status = if cancelled {
            RuntimePreparationStatus::Cancelled
        } else {
            RuntimePreparationStatus::Failed
        };
        RuntimePreparationReport {
            schema_version: RUNTIME_PREPARATION_SCHEMA.into(),
            ready: false,
            offline,
            engines: self.engine_ids.clone(),
            runtime: None,
            images: self
                .images
                .iter()
                .map(|image| image.outcome(status, Some(error), None))
                .collect(),
        }
    }

    pub fn prepare(
        &self,
        runtime: &ProcessContainerRuntime,
        offline: bool,
        cancellation: &AtomicBool,
    ) -> RuntimePreparationReport {
        if cancellation.load(Ordering::Acquire) {
            return self.report_for_failure(offline, "runtime preparation was cancelled", true);
        }
        let preflight = match runtime.preparation_preflight(cancellation) {
            Ok(preflight) => preflight,
            Err(error) => {
                return self.report_for_failure(
                    offline,
                    &error.to_string(),
                    cancellation.load(Ordering::Acquire),
                );
            }
        };
        let mut images = Vec::with_capacity(self.images.len());
        for image in &self.images {
            if cancellation.load(Ordering::Acquire) {
                images.push(image.outcome(
                    RuntimePreparationStatus::Cancelled,
                    Some("runtime preparation was cancelled"),
                    None,
                ));
                continue;
            }
            let outcome = match runtime.prepare_image(&image.pin, offline, cancellation) {
                Ok(acquisition) => {
                    image.outcome(RuntimePreparationStatus::Ready, None, Some(acquisition))
                }
                Err(error) => image.outcome(
                    if cancellation.load(Ordering::Acquire) {
                        RuntimePreparationStatus::Cancelled
                    } else {
                        RuntimePreparationStatus::Failed
                    },
                    Some(&error.to_string()),
                    None,
                ),
            };
            images.push(outcome);
        }
        RuntimePreparationReport {
            schema_version: RUNTIME_PREPARATION_SCHEMA.into(),
            ready: images
                .iter()
                .all(|image| image.status == RuntimePreparationStatus::Ready),
            offline,
            engines: self.engine_ids.clone(),
            runtime: Some(preflight),
            images,
        }
    }
}

impl RuntimePreparationImage {
    fn outcome(
        &self,
        status: RuntimePreparationStatus,
        error: Option<&str>,
        acquisition: Option<ImagePreparationAcquisition>,
    ) -> RuntimePreparationImageOutcome {
        RuntimePreparationImageOutcome {
            role: self.role,
            engine_ids: self.engine_ids.clone(),
            image: self.pin.reference(),
            status,
            error: error.map(|error| error.chars().take(4096).collect()),
            acquisition,
        }
    }
}

/// Preparation needs the same gateway used by production direct-network or
/// provider-service execution. A per-case scan later resolves and approves the
/// exact destinations; this predicate cannot grant or contact any of them.
fn manifest_needs_managed_network(manifest: &EngineManifest) -> bool {
    !manifest.network_destinations.is_empty()
        || manifest.required_permissions.iter().any(|permission| {
            matches!(
                permission,
                ScanPermission::LowImpactExternalConnection | ScanPermission::ActiveExternalTesting
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::builtin_adapter_registry;

    fn plan(ids: &[&str]) -> RuntimePreparationPlan {
        RuntimePreparationPlan::new(
            &EngineRegistry::load_builtin().unwrap(),
            &builtin_adapter_registry().unwrap(),
            &ids.iter().map(|id| (*id).to_owned()).collect::<Vec<_>>(),
        )
        .unwrap()
    }

    #[test]
    fn cancelled_preparation_resolution_stops_before_provider_detection() {
        let token = std::sync::Arc::new(AtomicBool::new(true));
        for online in [true, false] {
            let error = resolve_preparation_runtime(None, None, online, &token)
                .expect_err("cancelled preparation cannot start a provider command");
            assert!(error.to_string().contains("cancelled"));
            assert!(token.load(Ordering::Acquire));
        }
    }

    #[test]
    fn validates_every_selection_before_runtime_and_keeps_exact_requested_images() {
        let registry = EngineRegistry::load_builtin().unwrap();
        let adapters = builtin_adapter_registry().unwrap();
        for ids in [
            vec![],
            vec!["gitleaks".into(), "gitleaks".into()],
            vec!["gitleaks".into(), "unknown".into()],
            vec!["gitleaks ".into()],
            vec!["gitleaks".into(); 26],
        ] {
            assert!(RuntimePreparationPlan::new(&registry, &adapters, &ids).is_err());
        }
        assert!(
            RuntimePreparationPlan::new(
                &registry,
                &AdapterRegistry::default(),
                &["gitleaks".into()]
            )
            .is_err()
        );
        let selected = plan(&["gitleaks", "semgrep"]);
        assert_eq!(selected.images.len(), 2);
        assert!(
            selected
                .images
                .iter()
                .all(|image| image.role == RuntimePreparationRole::Engine)
        );
        assert_eq!(selected.engine_ids, ["gitleaks", "semgrep"]);
        for image in selected.images {
            let manifest = registry.get(&image.engine_ids[0]).unwrap();
            assert_eq!(
                image.image,
                PinnedImage::from_manifest(manifest).unwrap().reference()
            );
        }
    }

    #[test]
    fn shared_gateway_is_only_requested_for_network_engines() {
        let selected = plan(&["gitleaks", "nuclei", "httpx"]);
        assert_eq!(selected.images.len(), 4);
        let gateways = selected
            .images
            .iter()
            .filter(|image| image.role == RuntimePreparationRole::Gateway)
            .collect::<Vec<_>>();
        assert_eq!(gateways.len(), 1);
        assert_eq!(gateways[0].engine_ids, ["nuclei", "httpx"]);
        assert_eq!(
            gateways[0].image,
            managed_egress_gateway_spec().unwrap().reference()
        );
    }

    #[test]
    fn unavailable_catalog_entry_fails_before_resolving_a_provider() {
        let mut catalog: serde_json::Value =
            serde_json::from_str(include_str!("../../engines/catalog.json")).unwrap();
        let row = catalog
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|row| row["id"] == "gitleaks")
            .unwrap();
        row["compatibility"]["runnable"] = serde_json::json!(false);
        row["compatibility"]["blocked_by"] = serde_json::json!(["fixture_blocker"]);
        let registry =
            EngineRegistry::load_catalog(&serde_json::to_string(&catalog).unwrap()).unwrap();
        assert!(
            RuntimePreparationPlan::new(
                &registry,
                &builtin_adapter_registry().unwrap(),
                &["gitleaks".into()]
            )
            .is_err()
        );
    }

    #[test]
    fn cancellation_and_resolution_failures_keep_every_selected_image_visible() {
        let selected = plan(&["nuclei", "gitleaks"]);
        let missing = selected.report_for_failure(true, "runtime unavailable", false);
        assert!(!missing.ready);
        assert!(missing.runtime.is_none());
        assert_eq!(missing.images.len(), 3);
        assert!(
            missing
                .images
                .iter()
                .all(|image| image.status == RuntimePreparationStatus::Failed)
        );
        let runtime = ProcessContainerRuntime::new(
            crate::container_runtime::RuntimeProvider::Docker,
            "/missing/never-run",
        )
        .unwrap();
        let cancelled = selected.prepare(&runtime, true, &AtomicBool::new(true));
        assert!(
            cancelled
                .images
                .iter()
                .all(|image| image.status == RuntimePreparationStatus::Cancelled)
        );
        assert!(cancelled.runtime.is_none());
    }

    #[cfg(unix)]
    #[test]
    fn a_failed_image_keeps_ready_siblings_and_never_launches_a_container_or_network() {
        use std::io::Write;
        use std::process::{Command, Stdio};
        let temp = tempfile::tempdir().unwrap();
        let binary = temp.path().join("runtime");
        let script = r#"#!/bin/sh
printf '%s\n' "$*" >> "${0%/*}/calls"
if [ "$1" = info ]; then printf '%s\n' '{"serverVersion":"fixture","securityOptions":[]}'; exit 0; fi
if [ "$1" = image ] && [ "$2" = inspect ]; then
  case "$3" in *semgrep@sha256:*) exit 0 ;; *) exit 1 ;; esac
fi
if [ "$1" = pull ]; then exit 11; fi
exit 99
"#;
        let mut installer = Command::new("/bin/sh")
            .args(["-c", r#"cat > "$1" && chmod 700 "$1""#, "sh"])
            .arg(&binary)
            .stdin(Stdio::piped())
            .spawn()
            .unwrap();
        installer
            .stdin
            .take()
            .unwrap()
            .write_all(script.as_bytes())
            .unwrap();
        assert!(installer.wait().unwrap().success());
        let runtime =
            ProcessContainerRuntime::new(crate::container_runtime::RuntimeProvider::Docker, binary)
                .unwrap()
                .with_release_approved_local_image_directory(None);
        let selected = plan(&["gitleaks", "semgrep"]);
        let report = selected.prepare(&runtime, false, &AtomicBool::new(false));
        assert!(!report.ready);
        assert!(report.runtime.is_some());
        assert_eq!(report.images[0].status, RuntimePreparationStatus::Failed);
        assert_eq!(report.images[1].status, RuntimePreparationStatus::Ready);
        assert_eq!(
            report.images[1].acquisition,
            Some(ImagePreparationAcquisition::ExistingLocal)
        );
        let calls = std::fs::read_to_string(temp.path().join("calls")).unwrap();
        let expected = format!(
            "image inspect {}\npull {}\nimage inspect {}\n",
            selected.images[0].image, selected.images[0].image, selected.images[1].image
        );
        assert!(calls.lines().next().unwrap().starts_with("info --format "));
        assert_eq!(calls.split_once('\n').unwrap().1, expected);
        assert!(
            report
                .images
                .iter()
                .all(|image| image.role == RuntimePreparationRole::Engine)
        );
    }
}
