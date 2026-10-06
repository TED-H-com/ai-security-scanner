//! Cross-engine correlation suggestions.
//!
//! Two engines scanning the same asset routinely report the same real-world
//! problem, and today each lands in the finding list as its own row. This
//! module proposes which rows describe one issue so the user can collapse them
//! deliberately.
//!
//! Everything here is a *suggestion*. Nothing in this module mutates a case.
//! Accepting a suggestion goes through the existing reversible, audited
//! `group_findings` path, so the user's decision — not this heuristic — is what
//! ever changes the record. Product spec §9.3 governs:
//!
//! - cross-engine findings are never destructively merged without a stable,
//!   reviewed equivalence rule;
//! - the basis, rule version, and uncertainty of an automatic correlation are
//!   visible;
//! - insufficient coordinates make a comparison unverifiable, and the product
//!   never guesses that two findings are the same;
//! - agreement between two engines is not called corroboration unless the
//!   retained evidence sources are demonstrably independent.
//!
//! The equivalence rule implemented here is deliberately the narrow one we can
//! defend: the *same published vulnerability identifier*, on the *same
//! package*, on the *same asset*. A CVE id is assigned to one specific flaw, so
//! two engines naming the same id about the same package are talking about the
//! same flaw. Configuration rules get no automatic correlation — `CKV_AWS_20`
//! and a KICS query UUID are separate rules with separate semantics, and
//! asserting they are one issue would be a guess.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::domain::{AssessmentCase, Finding};

/// Version of the normalized comparison key. Any change to how the key is
/// derived must bump this, so a suggestion computed under an older rule is
/// never silently treated as equivalent to one computed under a newer rule.
pub const CORRELATION_KEY_SCHEMA_VERSION: &str = "cross-engine-vulnerability-id-1";

/// Upper bound on suggestions returned for one case, so a pathological result
/// set cannot flood the UI. Truncation is reported rather than hidden.
const MAX_SUGGESTIONS: usize = 200;

/// Whether the agreeing engines constitute independent confirmation.
///
/// Spec §9.3 forbids describing similar output from two engines as independent
/// corroboration unless the retained evidence sources are demonstrably
/// independent. We do not retain the vulnerability-database provenance that
/// would establish that, so today this is always `NotEstablished`. The variant
/// exists so the UI has something honest to render and so adding real
/// provenance later is a data change rather than a copy change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CorroborationStatus {
    /// Independence of the underlying evidence sources has not been
    /// established, so agreement between engines must not be presented as
    /// two independent confirmations.
    NotEstablished,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FindingCorrelationSuggestion {
    /// Deterministic identity of this suggestion, derived from the comparison
    /// key. Stable across recomputation so the UI can remember a dismissal.
    pub id: String,
    pub case_id: String,
    /// The normalized comparison key these findings share.
    pub comparison_key: String,
    /// Version of the rule that produced `comparison_key`.
    pub key_version: String,
    /// The published identifier both engines named. Carried separately from
    /// `title` so a caller can compose its own sentence in its own language
    /// instead of parsing one out of English prose.
    pub vulnerability_id: String,
    /// The package both engines named, likewise carried structurally.
    pub package: String,
    /// Proposed group title, suitable as the default when accepting.
    pub title: String,
    /// Plain-language statement of exactly what matched.
    pub basis: String,
    /// What this suggestion does *not* establish.
    pub uncertainty: String,
    pub corroboration: CorroborationStatus,
    /// Member findings, sorted, at least two, from at least two engines.
    pub finding_ids: Vec<String>,
    /// Distinct engines that reported this issue, sorted.
    pub engine_ids: Vec<String>,
}

/// Why a set of findings sharing a vulnerability id was *not* suggested.
///
/// Surfacing this matters: silence would read as "nothing else is related",
/// when the truth is "we could not tell". Spec §9.3 calls this `unverifiable`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnverifiableCorrelation {
    pub case_id: String,
    /// The vulnerability identifier shared by the findings.
    pub vulnerability_id: String,
    pub finding_ids: Vec<String>,
    /// Which coordinate was missing or inconsistent.
    pub reason: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CorrelationReport {
    pub key_version: String,
    pub suggestions: Vec<FindingCorrelationSuggestion>,
    pub unverifiable: Vec<UnverifiableCorrelation>,
    /// Suggestions dropped by `MAX_SUGGESTIONS`. Never silently zero.
    pub truncated_suggestions: usize,
}

/// Coordinates extracted from one finding, or `None` when it carries no
/// published vulnerability identifier and is therefore out of scope.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Coordinates {
    vulnerability_id: String,
    package: Option<String>,
    asset_id: Option<String>,
    engine_id: Option<String>,
}

/// Computes correlation suggestions for a case. Pure: takes a shared reference
/// and returns a fresh report.
pub fn correlation_report(case: &AssessmentCase) -> CorrelationReport {
    // A finding already inside an active group must not be suggested again;
    // accepting such a suggestion would be rejected by `group_findings`.
    let already_grouped = case
        .finding_groups
        .iter()
        .flat_map(|group| group.finding_ids.iter())
        .map(String::as_str)
        .collect::<BTreeSet<_>>();

    let mut by_vulnerability: BTreeMap<String, Vec<(&Finding, Coordinates)>> = BTreeMap::new();
    for finding in &case.findings {
        if finding.case_id != case.id || already_grouped.contains(finding.id.as_str()) {
            continue;
        }
        let Some(coordinates) = coordinates_for(finding) else {
            continue;
        };
        by_vulnerability
            .entry(coordinates.vulnerability_id.clone())
            .or_default()
            .push((finding, coordinates));
    }

    let mut suggestions = Vec::new();
    let mut unverifiable = Vec::new();
    for (vulnerability_id, members) in by_vulnerability {
        if members.len() < 2 {
            continue;
        }
        partition_members(
            &case.id,
            &vulnerability_id,
            &members,
            &mut suggestions,
            &mut unverifiable,
        );
    }

    suggestions.sort_by(|left, right| left.id.cmp(&right.id));
    let truncated_suggestions = suggestions.len().saturating_sub(MAX_SUGGESTIONS);
    suggestions.truncate(MAX_SUGGESTIONS);
    unverifiable.sort_by(|left, right| {
        left.vulnerability_id
            .cmp(&right.vulnerability_id)
            .then_with(|| left.finding_ids.cmp(&right.finding_ids))
    });

    CorrelationReport {
        key_version: CORRELATION_KEY_SCHEMA_VERSION.to_owned(),
        suggestions,
        unverifiable,
        truncated_suggestions,
    }
}

/// Splits findings sharing a vulnerability id into suggestable groups and
/// unverifiable remainders.
fn partition_members(
    case_id: &str,
    vulnerability_id: &str,
    members: &[(&Finding, Coordinates)],
    suggestions: &mut Vec<FindingCorrelationSuggestion>,
    unverifiable: &mut Vec<UnverifiableCorrelation>,
) {
    let mut incomplete: Vec<&Finding> = Vec::new();
    let mut by_key: BTreeMap<(String, String), Vec<(&Finding, &Coordinates)>> = BTreeMap::new();
    for (finding, coordinates) in members {
        // Both coordinates are required. A CVE on the same asset but a
        // different package is a different issue, and a missing package or
        // asset means we cannot tell — spec §9.3 says do not guess.
        match (&coordinates.package, &coordinates.asset_id) {
            (Some(package), Some(asset_id)) => by_key
                .entry((package.clone(), asset_id.clone()))
                .or_default()
                .push((finding, coordinates)),
            _ => incomplete.push(finding),
        }
    }

    if !incomplete.is_empty() {
        let mut finding_ids = incomplete
            .iter()
            .map(|finding| finding.id.clone())
            .collect::<Vec<_>>();
        finding_ids.sort();
        unverifiable.push(UnverifiableCorrelation {
            case_id: case_id.to_owned(),
            vulnerability_id: vulnerability_id.to_owned(),
            finding_ids,
            reason:
                "The findings share this vulnerability identifier, but at least one of them does \
                 not record both the affected package and the affected asset. Without both \
                 coordinates the product cannot confirm they describe the same issue."
                    .into(),
        });
    }

    for ((package, asset_id), grouped) in by_key {
        if grouped.len() < 2 {
            continue;
        }
        let engine_ids = grouped
            .iter()
            .filter_map(|(_, coordinates)| coordinates.engine_id.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        // A single engine reporting the same vulnerability twice is
        // within-engine duplication, already handled by the fingerprint. This
        // module exists to relate *different* engines.
        if engine_ids.len() < 2 {
            continue;
        }
        let mut finding_ids = grouped
            .iter()
            .map(|(finding, _)| finding.id.clone())
            .collect::<Vec<_>>();
        finding_ids.sort();
        finding_ids.dedup();

        let comparison_key = format!(
            "{CORRELATION_KEY_SCHEMA_VERSION}|vuln:{vulnerability_id}|pkg:{package}|asset:{asset_id}"
        );
        suggestions.push(FindingCorrelationSuggestion {
            id: format!("correlation-{}", suggestion_digest(&comparison_key)),
            case_id: case_id.to_owned(),
            comparison_key,
            key_version: CORRELATION_KEY_SCHEMA_VERSION.to_owned(),
            vulnerability_id: vulnerability_id.to_owned(),
            package: package.clone(),
            title: format!("{vulnerability_id} in {package}"),
            basis: format!(
                "{} engines ({}) reported vulnerability {vulnerability_id} against package \
                 {package} on the same asset.",
                engine_ids.len(),
                engine_ids.join(", ")
            ),
            uncertainty:
                "Presentation-only grouping. Each member retains separate evidence and remediation."
                    .into(),
            corroboration: CorroborationStatus::NotEstablished,
            finding_ids,
            engine_ids,
        });
    }
}

fn suggestion_digest(comparison_key: &str) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(comparison_key.as_bytes()))[..32].to_owned()
}

fn coordinates_for(finding: &Finding) -> Option<Coordinates> {
    let vulnerability_id = finding
        .tags
        .iter()
        .filter_map(|tag| tag.strip_prefix("source-rule:"))
        .find_map(normalized_vulnerability_id)?;
    Some(Coordinates {
        vulnerability_id,
        package: finding
            .tags
            .iter()
            .find_map(|tag| tag.strip_prefix("package:"))
            .filter(|package| !package.is_empty())
            .map(str::to_owned),
        asset_id: finding.asset_ids.first().cloned(),
        engine_id: finding
            .tags
            .iter()
            .find_map(|tag| tag.strip_prefix("engine:"))
            .filter(|engine| !engine.is_empty())
            .map(str::to_owned),
    })
}

/// Recognizes a published vulnerability identifier and normalizes its case.
///
/// `safe_tag` lowercases tag values, so the tag carries `cve-2024-1234`. Only
/// the two identifier families with a fixed, globally unique syntax are
/// accepted; a loose pattern would sweep in engine-local rule ids that merely
/// look similar and are not the same flaw across engines.
fn normalized_vulnerability_id(value: &str) -> Option<String> {
    let candidate = value.trim();
    let upper = candidate.to_ascii_uppercase();
    if is_cve_identifier(&upper) || is_ghsa_identifier(&upper) {
        return Some(upper);
    }
    None
}

/// `CVE-<4+ digits>-<4+ digits>`, per the CVE ID syntax.
pub(crate) fn is_cve_identifier(upper: &str) -> bool {
    let Some(rest) = upper.strip_prefix("CVE-") else {
        return false;
    };
    let mut parts = rest.split('-');
    let (Some(year), Some(sequence), None) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    year.len() == 4
        && year.bytes().all(|byte| byte.is_ascii_digit())
        && sequence.len() >= 4
        && sequence.bytes().all(|byte| byte.is_ascii_digit())
}

/// `GHSA-` followed by three base32-ish groups, per the GitHub advisory format.
pub(crate) fn is_ghsa_identifier(upper: &str) -> bool {
    let Some(rest) = upper.strip_prefix("GHSA-") else {
        return false;
    };
    let groups = rest.split('-').collect::<Vec<_>>();
    groups.len() == 3
        && groups
            .iter()
            .all(|group| group.len() == 4 && group.bytes().all(|byte| byte.is_ascii_alphanumeric()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{
        Confidence, DataClass, FindingGroup, FindingStatus, OrganizationProfile, Severity,
    };
    use chrono::Utc;

    fn case() -> AssessmentCase {
        AssessmentCase::new(
            "Correlation".into(),
            OrganizationProfile {
                organization_name: "Example".into(),
                employee_range: "2-49".into(),
                data_classes: vec![DataClass::PersonallyIdentifiableInformation],
                notes: None,
            },
        )
    }

    /// Builds a finding the way `merge_finding` does: the engine, the source
    /// rule and the package all reach the record as lowercased tags.
    fn finding(case: &AssessmentCase, id: &str, engine: &str, rule: &str, asset: &str) -> Finding {
        Finding {
            family: None,
            severity_basis_code: None,
            confidence_basis_code: None,
            context_factors: Vec::new(),
            id: id.into(),
            case_id: case.id.clone(),
            first_seen_run_id: "run".into(),
            last_seen_run_id: "run".into(),
            fingerprint: format!("{engine}:{rule}"),
            title: format!("{engine} reported {rule}"),
            plain_language_summary: "Scanner observation".into(),
            possible_impact: "Possible impact requires review.".into(),
            severity: Severity::High,
            confidence: Confidence::High,
            priority: 80,
            priority_reasons: vec![],
            asset_ids: vec![asset.into()],
            evidence: vec![],
            control_references: vec![],
            recommendation: "Ask a qualified reviewer.".into(),
            verification_guidance: "Rerun after an approved change.".into(),
            rollback_considerations: None,
            official_references: vec![],
            recommended_expert_type: "Security reviewer".into(),
            status: FindingStatus::Unreviewed,
            tags: vec![
                format!("engine:{engine}"),
                format!("source-rule:{}", rule.to_ascii_lowercase()),
            ],
        }
    }

    fn with_package(mut finding: Finding, package: &str) -> Finding {
        finding.tags.push(format!("package:{package}"));
        finding
    }

    #[test]
    fn two_engines_naming_one_cve_on_one_package_become_a_single_suggestion() {
        let mut case = case();
        case.findings = vec![
            with_package(
                finding(&case, "finding-trivy", "trivy", "CVE-2024-3094", "asset-a"),
                "xz-utils",
            ),
            with_package(
                finding(&case, "finding-grype", "grype", "CVE-2024-3094", "asset-a"),
                "xz-utils",
            ),
        ];

        let report = correlation_report(&case);

        assert_eq!(report.suggestions.len(), 1, "{report:?}");
        let suggestion = &report.suggestions[0];
        assert_eq!(suggestion.engine_ids, ["grype", "trivy"]);
        assert_eq!(
            suggestion.finding_ids,
            ["finding-grype", "finding-trivy"],
            "both observations stay addressable as members"
        );
        assert_eq!(suggestion.key_version, CORRELATION_KEY_SCHEMA_VERSION);
        assert_eq!(
            (
                suggestion.vulnerability_id.as_str(),
                suggestion.package.as_str()
            ),
            ("CVE-2024-3094", "xz-utils"),
            "the matched coordinates are carried structurally, so a caller never \
             has to parse them back out of the English title"
        );
        assert!(
            suggestion.comparison_key.contains("CVE-2024-3094")
                && suggestion.comparison_key.contains("xz-utils")
                && suggestion.comparison_key.contains("asset-a"),
            "the comparison key records every coordinate that was matched: {}",
            suggestion.comparison_key
        );
        assert!(
            suggestion.basis.contains("grype") && suggestion.basis.contains("trivy"),
            "the basis names the engines that agreed: {}",
            suggestion.basis
        );
        assert_eq!(
            suggestion.corroboration,
            CorroborationStatus::NotEstablished,
            "spec 9.3 forbids calling this independent confirmation"
        );
        assert!(report.unverifiable.is_empty(), "{report:?}");
        assert_eq!(report.truncated_suggestions, 0);
    }

    #[test]
    fn the_same_cve_on_a_different_package_is_a_different_issue() {
        let mut case = case();
        case.findings = vec![
            with_package(
                finding(&case, "finding-trivy", "trivy", "CVE-2024-3094", "asset-a"),
                "xz-utils",
            ),
            with_package(
                finding(&case, "finding-grype", "grype", "CVE-2024-3094", "asset-a"),
                "liblzma",
            ),
        ];

        let report = correlation_report(&case);

        assert!(
            report.suggestions.is_empty(),
            "a shared CVE id alone must not merge two packages: {report:?}"
        );
    }

    #[test]
    fn the_same_cve_on_a_different_asset_is_a_different_issue() {
        let mut case = case();
        case.findings = vec![
            with_package(
                finding(&case, "finding-trivy", "trivy", "CVE-2024-3094", "asset-a"),
                "xz-utils",
            ),
            with_package(
                finding(&case, "finding-grype", "grype", "CVE-2024-3094", "asset-b"),
                "xz-utils",
            ),
        ];

        let report = correlation_report(&case);

        assert!(
            report.suggestions.is_empty(),
            "the same package on two assets is two issues to fix: {report:?}"
        );
    }

    #[test]
    fn one_engine_reporting_a_cve_twice_is_not_a_cross_engine_suggestion() {
        let mut case = case();
        case.findings = vec![
            with_package(
                finding(&case, "finding-one", "trivy", "CVE-2024-3094", "asset-a"),
                "xz-utils",
            ),
            with_package(
                finding(&case, "finding-two", "trivy", "CVE-2024-3094", "asset-a"),
                "xz-utils",
            ),
        ];

        let report = correlation_report(&case);

        assert!(
            report.suggestions.is_empty(),
            "within-engine duplication is the fingerprint's job: {report:?}"
        );
    }

    #[test]
    fn a_missing_coordinate_is_reported_as_unverifiable_rather_than_as_silence() {
        let mut case = case();
        case.findings = vec![
            with_package(
                finding(&case, "finding-trivy", "trivy", "CVE-2024-3094", "asset-a"),
                "xz-utils",
            ),
            // No package tag: the coordinate needed to compare is absent.
            finding(
                &case,
                "finding-nuclei",
                "nuclei",
                "CVE-2024-3094",
                "asset-a",
            ),
        ];

        let report = correlation_report(&case);

        assert!(
            report.suggestions.is_empty(),
            "an incomplete coordinate set must not be guessed into a group: {report:?}"
        );
        assert_eq!(report.unverifiable.len(), 1, "{report:?}");
        let unverifiable = &report.unverifiable[0];
        assert_eq!(unverifiable.vulnerability_id, "CVE-2024-3094");
        assert_eq!(unverifiable.finding_ids, ["finding-nuclei"]);
        assert!(
            unverifiable.reason.contains("package"),
            "the user is told which coordinate was missing: {}",
            unverifiable.reason
        );
    }

    #[test]
    fn configuration_rule_ids_are_never_correlated_across_engines() {
        let mut case = case();
        // Both engines flag the same S3 bucket, but CKV_AWS_20 and the KICS
        // query id are separate rules; asserting equivalence would be a guess.
        case.findings = vec![
            finding(&case, "finding-checkov", "checkov", "CKV_AWS_20", "asset-a"),
            finding(
                &case,
                "finding-kics",
                "kics",
                "5c0b0a4d-3e6b-4b1d-9c1a-1f2e3d4c5b6a",
                "asset-a",
            ),
        ];

        let report = correlation_report(&case);

        assert!(
            report.suggestions.is_empty(),
            "no reviewed equivalence rule exists for config rules: {report:?}"
        );
        assert!(
            report.unverifiable.is_empty(),
            "these do not even share an identifier, so there is nothing to report: {report:?}"
        );
    }

    #[test]
    fn a_finding_already_in_an_active_group_is_not_suggested_again() {
        let mut case = case();
        case.findings = vec![
            with_package(
                finding(&case, "finding-trivy", "trivy", "CVE-2024-3094", "asset-a"),
                "xz-utils",
            ),
            with_package(
                finding(&case, "finding-grype", "grype", "CVE-2024-3094", "asset-a"),
                "xz-utils",
            ),
        ];
        case.finding_groups = vec![FindingGroup {
            id: "group".into(),
            case_id: case.id.clone(),
            title: "Already reviewed".into(),
            finding_ids: vec!["finding-trivy".into()],
            rationale: "The user grouped this deliberately.".into(),
            grouped_by: "Reviewer".into(),
            created_at: Utc::now(),
        }];

        let report = correlation_report(&case);

        assert!(
            report.suggestions.is_empty(),
            "group_findings rejects an already-grouped member, so suggesting it would be a dead end: {report:?}"
        );
    }

    #[test]
    fn ghsa_identifiers_correlate_but_lookalike_rule_ids_do_not() {
        assert_eq!(
            normalized_vulnerability_id("ghsa-jfh8-c2jp-5v3q").as_deref(),
            Some("GHSA-JFH8-C2JP-5V3Q"),
            "safe_tag lowercases the tag, so recognition must be case-insensitive"
        );
        assert_eq!(
            normalized_vulnerability_id("cve-2024-3094").as_deref(),
            Some("CVE-2024-3094")
        );
        for lookalike in [
            "cve-24-3094",           // year is not four digits
            "cve-2024-309",          // sequence is under four digits
            "cve-2024-3094-extra",   // trailing component
            "ghsa-jfh8-c2jp",        // too few groups
            "ghsa-jfh8-c2jp-5v3q-x", // too many groups
            "cvE_2024_3094",         // wrong separator
            "ckv_aws_20",
            "",
        ] {
            assert_eq!(
                normalized_vulnerability_id(lookalike),
                None,
                "must not treat {lookalike:?} as a published vulnerability identifier"
            );
        }
    }

    #[test]
    fn suggestion_identity_is_stable_across_recomputation() {
        let mut case = case();
        case.findings = vec![
            with_package(
                finding(&case, "finding-trivy", "trivy", "CVE-2024-3094", "asset-a"),
                "xz-utils",
            ),
            with_package(
                finding(&case, "finding-grype", "grype", "CVE-2024-3094", "asset-a"),
                "xz-utils",
            ),
        ];

        let first = correlation_report(&case);
        // Reversing input order must not change the identity the UI remembers.
        case.findings.reverse();
        let second = correlation_report(&case);

        assert_eq!(first, second, "a dismissal must survive recomputation");
    }
}
