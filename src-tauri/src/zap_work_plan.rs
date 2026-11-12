//! Pure construction of the bounded ZAP passive Automation Framework plan.
//!
//! This module has no runtime, storage, or network side effects. The required
//! SOCKS5 gateway settings keep every request on the product's managed-network
//! path, while the closed job model prevents callers from adding active or
//! otherwise scope-expanding ZAP jobs.
//!
//! The gateway settings are not a convenience. ZAP ignores the `HTTP_PROXY`,
//! `HTTPS_PROXY`, and `ALL_PROXY` variables the product sets for every managed
//! engine, so a plan that omits them reaches the target directly and escapes
//! the egress allowlist entirely. `env.configs` is the route that works, which
//! is why the gateway is a required argument rather than an option.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;
use url::Url;

pub const ZAP_PASSIVE_PROFILE_ID: &str = "zap_passive_v1";
pub const ZAP_ENGINE_ID: &str = "zap";
pub const ZAP_PASSIVE_TEMPLATE_REVISION: &str = "zaproxy@2665d972f6d587ba4773a95053ac39af3fdf8df9";

/// The reviewed origin-wide profile owns its request and job bounds. Neither
/// a generic active grant nor a different engine's profile can authorize it.
pub fn matches_zap_passive_profile(
    activity: crate::external_scope::ExternalActivity,
    protocol: crate::external_scope::TransportProtocol,
    ports: &std::collections::BTreeSet<u16>,
    rate: &crate::external_scope::RatePolicy,
    templates: &crate::external_scope::TemplatePolicy,
) -> bool {
    use crate::external_scope::{ExternalActivity, TransportProtocol};
    activity == ExternalActivity::ActiveExternal
        && matches!(protocol, TransportProtocol::Http | TransportProtocol::Https)
        && ports.len() == 1
        && !ports.contains(&0)
        && rate.requests_per_second == 5
        && rate.concurrency == 5
        && rate.timeout_seconds == 10
        && templates.profile_id.as_deref() == Some(ZAP_PASSIVE_PROFILE_ID)
        && templates.revision == ZAP_PASSIVE_TEMPLATE_REVISION
        && templates.allowed_template_ids.is_empty()
        && !templates.allow_headless
        && !templates.allow_out_of_band
        && !templates.allow_fuzzing
        && !templates.allow_file_upload
        && !templates.allow_denial_of_service
        && !templates.allow_credential_attacks
}
/// The generated plan is a single context with four bounded jobs. The ceiling
/// exists so a control file that grew for any other reason is rejected before
/// it is hashed and mounted, not so the plan can approach it.
pub const MAX_ZAP_PLAN_BYTES: usize = 64 * 1024;

/// Conservative passive-crawl limits. These are validation ceilings, not
/// defaults: every caller must supply an explicit non-zero value.
pub const MAX_ZAP_SPIDER_DEPTH: u16 = 20;
pub const MAX_ZAP_SPIDER_CHILDREN: u16 = 100;
pub const MAX_ZAP_SPIDER_DURATION_MINUTES: u16 = 60;
pub const MAX_ZAP_PASSIVE_WAIT_DURATION_MINUTES: u16 = 60;
/// No scope grant can authorize more concurrency than this: `RatePolicy`
/// caps active external testing at 5 (`external_scope.rs`). Keeping the
/// ceiling here means a plan that outruns its own grant cannot be built.
pub const MAX_ZAP_SPIDER_THREADS: u16 = 5;
pub const MAX_ZAP_ALERTS_PER_RULE: u16 = 100;
pub const MAX_ZAP_REQUESTS_PER_SECOND: u16 = 10;
pub const MAX_ZAP_REQUEST_TIMEOUT_SECONDS: u16 = 60;

const APPROVED_CONTEXT_NAME: &str = "approved";

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ZapWorkPlanError {
    #[error("the approved ZAP origin is invalid: {0}")]
    InvalidApprovedOrigin(String),
    #[error("the ZAP managed-network gateway is invalid: {0}")]
    InvalidGateway(String),
    #[error("ZAP bound {name} must be between 1 and {maximum}; received {value}")]
    InvalidBound {
        name: &'static str,
        value: u16,
        maximum: u16,
    },
    #[error("the ZAP report directory must be an absolute path")]
    InvalidReportDirectory,
    #[error("the ZAP report file stem is invalid")]
    InvalidReportFileStem,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZapGatewayEndpoint {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZapPassiveBounds {
    pub requests_per_second: u16,
    pub request_timeout_seconds: u16,
    pub max_depth: u16,
    pub max_children: u16,
    pub spider_max_duration_minutes: u16,
    pub passive_wait_max_duration_minutes: u16,
    pub thread_count: u16,
    pub max_alerts_per_rule: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ZapPlanDocument {
    env: ZapEnvironment,
    jobs: Vec<ZapJob>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ZapEnvironment {
    contexts: Vec<ZapContext>,
    configs: BTreeMap<String, String>,
    parameters: ZapEnvironmentParameters,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ZapContext {
    name: String,
    urls: Vec<String>,
    #[serde(rename = "includePaths")]
    include_paths: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ZapEnvironmentParameters {
    #[serde(rename = "failOnError")]
    fail_on_error: bool,
    #[serde(rename = "failOnWarning")]
    fail_on_warning: bool,
    #[serde(rename = "continueOnFailure")]
    continue_on_failure: bool,
    #[serde(rename = "progressToStdout")]
    progress_to_stdout: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", deny_unknown_fields)]
enum ZapJob {
    #[serde(rename = "passiveScan-config")]
    PassiveScanConfig {
        parameters: ZapPassiveScanConfigParameters,
    },
    #[serde(rename = "spider")]
    Spider { parameters: ZapSpiderParameters },
    #[serde(rename = "passiveScan-wait")]
    PassiveScanWait {
        parameters: ZapPassiveScanWaitParameters,
    },
    #[serde(rename = "report")]
    Report { parameters: ZapReportParameters },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ZapPassiveScanConfigParameters {
    #[serde(rename = "scanOnlyInScope")]
    scan_only_in_scope: bool,
    #[serde(rename = "maxAlertsPerRule")]
    max_alerts_per_rule: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ZapSpiderParameters {
    context: String,
    url: String,
    #[serde(rename = "maxDuration")]
    max_duration: u16,
    #[serde(rename = "maxDepth")]
    max_depth: u16,
    #[serde(rename = "maxChildren")]
    max_children: u16,
    #[serde(rename = "postForm")]
    post_form: bool,
    #[serde(rename = "processForm")]
    process_form: bool,
    #[serde(rename = "threadCount")]
    thread_count: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ZapPassiveScanWaitParameters {
    #[serde(rename = "maxDuration")]
    max_duration: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ZapReportParameters {
    template: String,
    #[serde(rename = "reportDir")]
    report_dir: String,
    #[serde(rename = "reportFile")]
    report_file: String,
}

/// Builds the JSON-serializable, passive-only plan consumed by ZAP's pinned
/// `-autorun /run/ai-security-scanner/zap-plan.yaml` command.
pub fn build_zap_passive_plan(
    approved_origin: &Url,
    gateway: &ZapGatewayEndpoint,
    bounds: &ZapPassiveBounds,
    report_dir: &str,
    report_file_stem: &str,
) -> Result<ZapPlanDocument, ZapWorkPlanError> {
    validate_approved_origin(approved_origin)?;
    validate_gateway(gateway)?;
    validate_bounds(bounds)?;
    validate_report_destination(report_dir, report_file_stem)?;

    let origin = approved_origin.as_str().to_owned();
    let configs = BTreeMap::from([
        (
            "network.connection.timeoutInSecs".to_owned(),
            bounds.request_timeout_seconds.to_string(),
        ),
        // Network add-on 0.29.0 uses these exact configuration keys. Its
        // limiter applies before each HTTP/HTTPS request, including requests
        // on an existing keep-alive connection. A single RULE group also
        // bounds any attempted off-origin request before the gateway refuses it.
        (
            "network.ratelimit.rules.rule(0).description".to_owned(),
            "approved passive scan".to_owned(),
        ),
        (
            "network.ratelimit.rules.rule(0).enabled".to_owned(),
            "true".to_owned(),
        ),
        (
            "network.ratelimit.rules.rule(0).matchStr".to_owned(),
            ".*".to_owned(),
        ),
        (
            "network.ratelimit.rules.rule(0).regex".to_owned(),
            "true".to_owned(),
        ),
        (
            "network.ratelimit.rules.rule(0).reqsPerSec".to_owned(),
            bounds.requests_per_second.to_string(),
        ),
        (
            "network.ratelimit.rules.rule(0).groupBy".to_owned(),
            "RULE".to_owned(),
        ),
        (
            "network.connection.socksProxy.dns".to_owned(),
            // Java must send literal IP targets as SOCKS address requests.
            // DNS names remain unresolved until the gateway uses frozen IPs.
            matches!(approved_origin.host(), Some(url::Host::Domain(_))).to_string(),
        ),
        (
            "network.connection.socksProxy.enabled".to_owned(),
            "true".to_owned(),
        ),
        (
            "network.connection.socksProxy.host".to_owned(),
            gateway.host.clone(),
        ),
        (
            "network.connection.socksProxy.port".to_owned(),
            gateway.port.to_string(),
        ),
        (
            "network.connection.socksProxy.version".to_owned(),
            "5".to_owned(),
        ),
    ]);

    Ok(ZapPlanDocument {
        env: ZapEnvironment {
            contexts: vec![ZapContext {
                name: APPROVED_CONTEXT_NAME.to_owned(),
                urls: vec![origin.clone()],
                include_paths: vec![format!(r"\Q{origin}\E.*")],
            }],
            configs,
            parameters: ZapEnvironmentParameters {
                fail_on_error: true,
                fail_on_warning: true,
                continue_on_failure: false,
                progress_to_stdout: true,
            },
        },
        jobs: vec![
            ZapJob::PassiveScanConfig {
                parameters: ZapPassiveScanConfigParameters {
                    scan_only_in_scope: true,
                    max_alerts_per_rule: bounds.max_alerts_per_rule,
                },
            },
            ZapJob::Spider {
                parameters: ZapSpiderParameters {
                    context: APPROVED_CONTEXT_NAME.to_owned(),
                    url: origin,
                    max_duration: bounds.spider_max_duration_minutes,
                    max_depth: bounds.max_depth,
                    max_children: bounds.max_children,
                    post_form: false,
                    process_form: false,
                    thread_count: bounds.thread_count,
                },
            },
            ZapJob::PassiveScanWait {
                parameters: ZapPassiveScanWaitParameters {
                    max_duration: bounds.passive_wait_max_duration_minutes,
                },
            },
            ZapJob::Report {
                parameters: ZapReportParameters {
                    template: "traditional-json".to_owned(),
                    report_dir: report_dir.to_owned(),
                    report_file: report_file_stem.to_owned(),
                },
            },
        ],
    })
}

fn validate_approved_origin(approved_origin: &Url) -> Result<(), ZapWorkPlanError> {
    if approved_origin.host().is_none() {
        return Err(ZapWorkPlanError::InvalidApprovedOrigin(
            "a host is required".to_owned(),
        ));
    }
    if !matches!(approved_origin.scheme(), "http" | "https") {
        return Err(ZapWorkPlanError::InvalidApprovedOrigin(
            "the scheme must be http or https".to_owned(),
        ));
    }
    if !approved_origin.username().is_empty() || approved_origin.password().is_some() {
        return Err(ZapWorkPlanError::InvalidApprovedOrigin(
            "userinfo is not allowed".to_owned(),
        ));
    }
    if approved_origin.query().is_some() {
        return Err(ZapWorkPlanError::InvalidApprovedOrigin(
            "a query is not allowed".to_owned(),
        ));
    }
    if approved_origin.fragment().is_some() {
        return Err(ZapWorkPlanError::InvalidApprovedOrigin(
            "a fragment is not allowed".to_owned(),
        ));
    }
    if contains_regex_quote_terminator(approved_origin.as_str()) {
        return Err(ZapWorkPlanError::InvalidApprovedOrigin(
            r"the origin cannot contain the regex quote terminator \E".to_owned(),
        ));
    }
    Ok(())
}

fn contains_regex_quote_terminator(value: &str) -> bool {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%'
            && index + 2 < bytes.len()
            && let (Some(high), Some(low)) =
                (hex_value(bytes[index + 1]), hex_value(bytes[index + 2]))
        {
            decoded.push((high << 4) | low);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    decoded.windows(2).any(|window| window == br"\E")
}

fn hex_value(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn validate_gateway(gateway: &ZapGatewayEndpoint) -> Result<(), ZapWorkPlanError> {
    if gateway.host.is_empty() {
        return Err(ZapWorkPlanError::InvalidGateway(
            "the host is required".to_owned(),
        ));
    }
    if gateway
        .host
        .chars()
        .any(|character| character.is_whitespace() || character.is_control())
    {
        return Err(ZapWorkPlanError::InvalidGateway(
            "the host cannot contain whitespace or control characters".to_owned(),
        ));
    }
    if gateway.port == 0 {
        return Err(ZapWorkPlanError::InvalidGateway(
            "the port must be non-zero".to_owned(),
        ));
    }
    Ok(())
}

fn validate_bounds(bounds: &ZapPassiveBounds) -> Result<(), ZapWorkPlanError> {
    validate_bound(
        "request_timeout_seconds",
        bounds.request_timeout_seconds,
        MAX_ZAP_REQUEST_TIMEOUT_SECONDS,
    )?;
    validate_bound(
        "requests_per_second",
        bounds.requests_per_second,
        MAX_ZAP_REQUESTS_PER_SECOND,
    )?;
    validate_bound("max_depth", bounds.max_depth, MAX_ZAP_SPIDER_DEPTH)?;
    validate_bound("max_children", bounds.max_children, MAX_ZAP_SPIDER_CHILDREN)?;
    validate_bound(
        "spider_max_duration_minutes",
        bounds.spider_max_duration_minutes,
        MAX_ZAP_SPIDER_DURATION_MINUTES,
    )?;
    validate_bound(
        "passive_wait_max_duration_minutes",
        bounds.passive_wait_max_duration_minutes,
        MAX_ZAP_PASSIVE_WAIT_DURATION_MINUTES,
    )?;
    validate_bound("thread_count", bounds.thread_count, MAX_ZAP_SPIDER_THREADS)?;
    validate_bound(
        "max_alerts_per_rule",
        bounds.max_alerts_per_rule,
        MAX_ZAP_ALERTS_PER_RULE,
    )
}

fn validate_bound(name: &'static str, value: u16, maximum: u16) -> Result<(), ZapWorkPlanError> {
    if value == 0 || value > maximum {
        return Err(ZapWorkPlanError::InvalidBound {
            name,
            value,
            maximum,
        });
    }
    Ok(())
}

fn validate_report_destination(
    report_dir: &str,
    report_file_stem: &str,
) -> Result<(), ZapWorkPlanError> {
    if !report_dir.starts_with('/')
        || report_dir.contains('\\')
        || report_dir.chars().any(char::is_control)
    {
        return Err(ZapWorkPlanError::InvalidReportDirectory);
    }
    if report_file_stem.is_empty()
        || report_file_stem.contains('/')
        || report_file_stem.contains('\\')
        || report_file_stem.contains("..")
        || report_file_stem.chars().any(char::is_control)
    {
        return Err(ZapWorkPlanError::InvalidReportFileStem);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    #[test]
    fn report_directory_uses_container_posix_paths_on_every_host() {
        assert!(validate_report_destination("/output", "report").is_ok());
        for path in [
            "output",
            "./output",
            r"C:\output",
            r"\output",
            r"\\server\output",
            r"/output\child",
        ] {
            assert_eq!(
                validate_report_destination(path, "report"),
                Err(ZapWorkPlanError::InvalidReportDirectory)
            );
        }
    }

    fn representative_bounds() -> ZapPassiveBounds {
        ZapPassiveBounds {
            requests_per_second: 5,
            request_timeout_seconds: 10,
            max_depth: 5,
            max_children: 40,
            spider_max_duration_minutes: 3,
            passive_wait_max_duration_minutes: 4,
            thread_count: 2,
            max_alerts_per_rule: 12,
        }
    }

    fn representative_gateway() -> ZapGatewayEndpoint {
        ZapGatewayEndpoint {
            host: "gateway.internal".to_owned(),
            port: 1080,
        }
    }

    fn build(origin: &str) -> Result<ZapPlanDocument, ZapWorkPlanError> {
        build_zap_passive_plan(
            &Url::parse(origin).expect("test URL must parse"),
            &representative_gateway(),
            &representative_bounds(),
            "/output",
            "zap-report",
        )
    }

    #[test]
    fn representative_plan_serializes_to_exact_expected_json() {
        let actual = serde_json::to_value(build("https://example.test/").unwrap()).unwrap();
        let expected = json!({
            "env": {
                "contexts": [{
                    "name": "approved",
                    "urls": ["https://example.test/"],
                    "includePaths": ["\\Qhttps://example.test/\\E.*"]
                }],
                "configs": {
                    "network.connection.timeoutInSecs": "10",
                    "network.ratelimit.rules.rule(0).description": "approved passive scan",
                    "network.ratelimit.rules.rule(0).enabled": "true",
                    "network.ratelimit.rules.rule(0).matchStr": ".*",
                    "network.ratelimit.rules.rule(0).regex": "true",
                    "network.ratelimit.rules.rule(0).reqsPerSec": "5",
                    "network.ratelimit.rules.rule(0).groupBy": "RULE",
                    "network.connection.socksProxy.enabled": "true",
                    "network.connection.socksProxy.host": "gateway.internal",
                    "network.connection.socksProxy.port": "1080",
                    "network.connection.socksProxy.version": "5",
                    "network.connection.socksProxy.dns": "true"
                },
                "parameters": {
                    "failOnError": true,
                    "failOnWarning": true,
                    "continueOnFailure": false,
                    "progressToStdout": true
                }
            },
            "jobs": [
                {
                    "type": "passiveScan-config",
                    "parameters": { "scanOnlyInScope": true, "maxAlertsPerRule": 12 }
                },
                {
                    "type": "spider",
                    "parameters": {
                        "context": "approved",
                        "url": "https://example.test/",
                        "maxDuration": 3,
                        "maxDepth": 5,
                        "maxChildren": 40,
                        "postForm": false,
                        "processForm": false,
                        "threadCount": 2
                    }
                },
                { "type": "passiveScan-wait", "parameters": { "maxDuration": 4 } },
                {
                    "type": "report",
                    "parameters": {
                        "template": "traditional-json",
                        "reportDir": "/output",
                        "reportFile": "zap-report"
                    }
                }
            ]
        });

        assert_eq!(actual, expected);
    }

    #[test]
    fn only_hostnames_are_resolved_by_the_frozen_gateway() {
        for origin in ["http://192.0.2.4:8080/", "https://[2001:db8::4]/"] {
            let value = serde_json::to_value(build(origin).unwrap()).unwrap();
            assert_eq!(
                value["env"]["configs"]["network.connection.socksProxy.dns"],
                "false"
            );
        }
        let value = serde_json::to_value(build("https://example.test/").unwrap()).unwrap();
        assert_eq!(
            value["env"]["configs"]["network.connection.socksProxy.dns"],
            "true"
        );
    }

    #[test]
    fn supplied_gateway_always_populates_all_five_socks_configs() {
        let value = serde_json::to_value(build("https://example.test/").unwrap()).unwrap();
        let configs = value["env"]["configs"].as_object().unwrap();

        assert_eq!(configs.len(), 12);
        assert_eq!(configs["network.connection.socksProxy.enabled"], "true");
        assert_eq!(
            configs["network.connection.socksProxy.host"],
            "gateway.internal"
        );
        assert_eq!(configs["network.connection.socksProxy.port"], "1080");
        assert_eq!(configs["network.connection.socksProxy.version"], "5");
        assert_eq!(configs["network.connection.socksProxy.dns"], "true");
    }

    #[test]
    fn plan_keeps_forms_disabled_and_scope_and_errors_strict() {
        let value = serde_json::to_value(build("https://example.test/").unwrap()).unwrap();
        let jobs = value["jobs"].as_array().unwrap();
        let spider = jobs.iter().find(|job| job["type"] == "spider").unwrap();
        let passive_config = jobs
            .iter()
            .find(|job| job["type"] == "passiveScan-config")
            .unwrap();

        assert_eq!(spider["parameters"]["postForm"], false);
        assert_eq!(spider["parameters"]["processForm"], false);
        assert_eq!(passive_config["parameters"]["scanOnlyInScope"], true);
        assert_eq!(value["env"]["parameters"]["failOnError"], true);
    }

    #[test]
    fn plan_never_emits_forbidden_job_types() {
        const FORBIDDEN_TYPES: &[&str] = &[
            "activeScan",
            "activeScan-config",
            "activeScan-policy",
            "sequence-activeScan",
            "spiderAjax",
            "spiderClient",
            "import",
            "openapi",
            "graphql",
            "postman",
            "soap",
            "requestor",
            "script",
            "replacer",
            "exitStatus",
        ];
        let value = serde_json::to_value(build("https://example.test/").unwrap()).unwrap();
        let emitted_types: Vec<&str> = value["jobs"]
            .as_array()
            .unwrap()
            .iter()
            .map(|job| job["type"].as_str().unwrap())
            .collect();

        assert!(
            FORBIDDEN_TYPES
                .iter()
                .all(|forbidden| !emitted_types.contains(forbidden))
        );
    }

    #[test]
    fn include_path_quotes_exact_approved_origin() {
        let value = serde_json::to_value(build("http://host.test:8080/path/").unwrap()).unwrap();

        assert_eq!(
            value["env"]["contexts"][0]["includePaths"],
            json!(["\\Qhttp://host.test:8080/path/\\E.*"])
        );
    }

    #[test]
    fn rejects_origin_with_regex_quote_terminator() {
        let origin = Url::parse("https://example.test/safe%5CEescaped").unwrap();

        assert!(matches!(
            build_zap_passive_plan(
                &origin,
                &representative_gateway(),
                &representative_bounds(),
                "/output",
                "zap-report"
            ),
            Err(ZapWorkPlanError::InvalidApprovedOrigin(_))
        ));
    }

    #[test]
    fn rejects_non_http_origin() {
        let origin = Url::parse("ftp://example.test/").unwrap();
        assert!(
            build_zap_passive_plan(
                &origin,
                &representative_gateway(),
                &representative_bounds(),
                "/output",
                "zap-report"
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_origin_without_host() {
        let origin = Url::parse("file:///tmp/report").unwrap();
        assert!(
            build_zap_passive_plan(
                &origin,
                &representative_gateway(),
                &representative_bounds(),
                "/output",
                "zap-report"
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_origin_query_fragment_and_userinfo() {
        for origin in [
            "https://example.test/?query=yes",
            "https://example.test/#fragment",
            "https://user@example.test/",
            "https://:password@example.test/",
        ] {
            assert!(build(origin).is_err(), "accepted invalid origin {origin}");
        }
    }

    #[test]
    fn rejects_invalid_gateway_host_and_port() {
        let origin = Url::parse("https://example.test/").unwrap();
        for host in ["", "gateway host", "gateway\n"] {
            let gateway = ZapGatewayEndpoint {
                host: host.to_owned(),
                port: 1080,
            };
            assert!(
                build_zap_passive_plan(
                    &origin,
                    &gateway,
                    &representative_bounds(),
                    "/output",
                    "zap-report"
                )
                .is_err()
            );
        }

        let gateway = ZapGatewayEndpoint {
            host: "gateway.internal".to_owned(),
            port: 0,
        };
        assert!(
            build_zap_passive_plan(
                &origin,
                &gateway,
                &representative_bounds(),
                "/output",
                "zap-report"
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_zero_and_over_maximum_for_every_bound() {
        let origin = Url::parse("https://example.test/").unwrap();
        let cases = [
            ("requests_per_second", 0, MAX_ZAP_REQUESTS_PER_SECOND),
            (
                "requests_per_second",
                MAX_ZAP_REQUESTS_PER_SECOND + 1,
                MAX_ZAP_REQUESTS_PER_SECOND,
            ),
            (
                "request_timeout_seconds",
                0,
                MAX_ZAP_REQUEST_TIMEOUT_SECONDS,
            ),
            (
                "request_timeout_seconds",
                MAX_ZAP_REQUEST_TIMEOUT_SECONDS + 1,
                MAX_ZAP_REQUEST_TIMEOUT_SECONDS,
            ),
            ("max_depth", 0, MAX_ZAP_SPIDER_DEPTH),
            ("max_depth", MAX_ZAP_SPIDER_DEPTH + 1, MAX_ZAP_SPIDER_DEPTH),
            ("max_children", 0, MAX_ZAP_SPIDER_CHILDREN),
            (
                "max_children",
                MAX_ZAP_SPIDER_CHILDREN + 1,
                MAX_ZAP_SPIDER_CHILDREN,
            ),
            (
                "spider_max_duration_minutes",
                0,
                MAX_ZAP_SPIDER_DURATION_MINUTES,
            ),
            (
                "spider_max_duration_minutes",
                MAX_ZAP_SPIDER_DURATION_MINUTES + 1,
                MAX_ZAP_SPIDER_DURATION_MINUTES,
            ),
            (
                "passive_wait_max_duration_minutes",
                0,
                MAX_ZAP_PASSIVE_WAIT_DURATION_MINUTES,
            ),
            (
                "passive_wait_max_duration_minutes",
                MAX_ZAP_PASSIVE_WAIT_DURATION_MINUTES + 1,
                MAX_ZAP_PASSIVE_WAIT_DURATION_MINUTES,
            ),
            ("thread_count", 0, MAX_ZAP_SPIDER_THREADS),
            (
                "thread_count",
                MAX_ZAP_SPIDER_THREADS + 1,
                MAX_ZAP_SPIDER_THREADS,
            ),
            ("max_alerts_per_rule", 0, MAX_ZAP_ALERTS_PER_RULE),
            (
                "max_alerts_per_rule",
                MAX_ZAP_ALERTS_PER_RULE + 1,
                MAX_ZAP_ALERTS_PER_RULE,
            ),
        ];

        for (name, value, maximum) in cases {
            let mut bounds = representative_bounds();
            match name {
                "requests_per_second" => bounds.requests_per_second = value,
                "request_timeout_seconds" => bounds.request_timeout_seconds = value,
                "max_depth" => bounds.max_depth = value,
                "max_children" => bounds.max_children = value,
                "spider_max_duration_minutes" => bounds.spider_max_duration_minutes = value,
                "passive_wait_max_duration_minutes" => {
                    bounds.passive_wait_max_duration_minutes = value;
                }
                "thread_count" => bounds.thread_count = value,
                "max_alerts_per_rule" => bounds.max_alerts_per_rule = value,
                _ => unreachable!(),
            }

            assert_eq!(
                build_zap_passive_plan(
                    &origin,
                    &representative_gateway(),
                    &bounds,
                    "/output",
                    "zap-report"
                ),
                Err(ZapWorkPlanError::InvalidBound {
                    name,
                    value,
                    maximum
                })
            );
        }
    }

    #[test]
    fn rejects_invalid_report_destination() {
        let origin = Url::parse("https://example.test/").unwrap();
        for report_dir in ["relative/output", "/output\nchild"] {
            assert_eq!(
                build_zap_passive_plan(
                    &origin,
                    &representative_gateway(),
                    &representative_bounds(),
                    report_dir,
                    "zap-report"
                ),
                Err(ZapWorkPlanError::InvalidReportDirectory)
            );
        }
        for report_file in [
            "",
            "nested/report",
            r"nested\report",
            "../report",
            "report\n",
        ] {
            assert_eq!(
                build_zap_passive_plan(
                    &origin,
                    &representative_gateway(),
                    &representative_bounds(),
                    "/output",
                    report_file
                ),
                Err(ZapWorkPlanError::InvalidReportFileStem)
            );
        }
    }

    #[test]
    fn supported_http_origins_round_trip_without_changes() {
        for origin in ["https://host.test/", "http://host.test:8080/path/"] {
            let plan = build(origin).unwrap();
            let encoded = serde_json::to_vec(&plan).unwrap();
            let decoded: ZapPlanDocument = serde_json::from_slice(&encoded).unwrap();

            assert_eq!(decoded, plan);
            assert_eq!(
                serde_json::to_value(decoded).unwrap()["jobs"][1]["parameters"]["url"],
                origin
            );
        }
    }

    #[test]
    fn rejects_unknown_fields_when_plan_is_read_back() {
        let mut value = serde_json::to_value(build("https://example.test/").unwrap()).unwrap();
        value["env"]["unexpected"] = Value::Bool(true);

        assert!(serde_json::from_value::<ZapPlanDocument>(value).is_err());
    }
}
