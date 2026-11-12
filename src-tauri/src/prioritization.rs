//! Conservative case-context enrichment for canonical findings.
//!
//! Scanner severity remains intact. Case context records why an already-observed
//! issue may deserve earlier human attention in this exact case. A product-owned
//! review order can also place a check lower than its scanner severity suggests
//! when current guidance advises against the benchmark item that check enforces.
//! Questionnaire data never invents a finding and only affects wording when an
//! affected asset independently carries the matching sensitivity or exposure
//! attribute.

use crate::domain::{AssessmentCase, Asset, ContextFactor, DataClass, Finding, SourceKind};
use std::collections::BTreeSet;

const CONTEXT_VERSION_TAG: &str = "context-priority:v1";
const PRIORITY_GUIDANCE_TAG: &str = "priority-guidance:v1";
pub(crate) const INTERNET_REASON: &str = "The affected asset is internet-accessible.";
pub(crate) const SENSITIVE_REASON: &str =
    "The affected asset contains sensitive data, increasing the potential impact.";
const INTERNET_IMPACT: &str =
    " The affected asset is internet-accessible, increasing the reachable attack surface.";
const SENSITIVE_IMPACT: &str =
    " The affected asset contains sensitive data, increasing the potential impact.";

/// Adds bounded, explainable case-context factors, then caps a check whose
/// benchmark item current guidance advises against.
///
/// Case context only raises priority. Afterwards, when every evidence rule
/// maps to the same product order, that order's reason is recorded once, the
/// priority is capped at [`crate::priority_guidance::GUIDED_PRIORITY_CEILING`]
/// (the Low tier of `priority_for`), and the guidance tag is recorded once.
/// Severity, confidence, evidence, title, recommendation, and context factors
/// stay untouched. Questionnaire data never invents a finding.
pub fn apply_case_context(case: &AssessmentCase, finding: &mut Finding) {
    // Reachability inventory is not a weakness to triage. Raising its priority
    // because the target is internet-facing would turn the defining fact of
    // the observation into a vulnerability claim.
    if finding
        .severity_basis_code
        .is_some_and(|code| code.is_exposure_observation())
    {
        deduplicate(&mut finding.priority_reasons);
        deduplicate(&mut finding.tags);
        return;
    }
    let affected = case
        .assets
        .iter()
        .filter(|asset| finding.asset_ids.contains(&asset.id))
        .collect::<Vec<_>>();
    let internet_exposed = affected.iter().any(|asset| {
        asset.internet_exposed == Some(true)
            && has_only_retained_non_questionnaire_sources(case, asset)
    });
    let sensitive_asset = affected.iter().any(|asset| {
        asset.contains_sensitive_data == Some(true)
            && has_only_retained_non_questionnaire_sources(case, asset)
    });
    let sensitive_context = case
        .profile
        .data_classes
        .iter()
        .any(|data_class| !matches!(data_class, DataClass::General));

    let mut adjustment = 0_u8;
    if internet_exposed {
        if push_once(&mut finding.priority_reasons, INTERNET_REASON) {
            adjustment = adjustment.saturating_add(5);
        }
        append_once(&mut finding.possible_impact, INTERNET_IMPACT);
        // Recorded beside the prose, never instead of it. A surface that
        // composes its own impact sentence replaces the string this appendix
        // was appended to, and reads the code to say the same thing.
        push_factor_once(
            &mut finding.context_factors,
            ContextFactor::InternetExposedAsset,
        );
    }
    if sensitive_asset && sensitive_context {
        if push_once(&mut finding.priority_reasons, SENSITIVE_REASON) {
            adjustment = adjustment.saturating_add(5);
        }
        append_once(&mut finding.possible_impact, SENSITIVE_IMPACT);
        push_factor_once(
            &mut finding.context_factors,
            ContextFactor::SensitiveDataAsset,
        );
    }
    if adjustment > 0 {
        finding.priority = finding.priority.saturating_add(adjustment).min(100);
        push_once(&mut finding.tags, CONTEXT_VERSION_TAG);
    }

    if let Some(guidance) = crate::priority_guidance::guidance_for_rules(
        finding
            .evidence
            .iter()
            .map(|evidence| (evidence.engine_id.as_str(), evidence.source_rule.as_deref())),
    ) {
        push_once(&mut finding.priority_reasons, guidance.reason_english());
        finding.priority = finding
            .priority
            .min(crate::priority_guidance::GUIDED_PRIORITY_CEILING);
        push_once(&mut finding.tags, PRIORITY_GUIDANCE_TAG);
    }

    deduplicate(&mut finding.priority_reasons);
    deduplicate(&mut finding.tags);
}

fn has_only_retained_non_questionnaire_sources(case: &AssessmentCase, asset: &Asset) -> bool {
    !asset.discovered_from.is_empty()
        && asset.discovered_from.iter().all(|source_id| {
            case.data_sources
                .iter()
                .find(|source| source.id == *source_id)
                .is_some_and(|source| source.kind != SourceKind::UserDeclared)
        })
}

fn append_once(value: &mut String, suffix: &str) {
    if !value.contains(suffix.trim()) {
        value.push_str(suffix);
    }
}

fn push_factor_once(factors: &mut Vec<ContextFactor>, factor: ContextFactor) {
    if !factors.contains(&factor) {
        factors.push(factor);
    }
}

fn push_once(values: &mut Vec<String>, value: &str) -> bool {
    if !values.iter().any(|candidate| candidate == value) {
        values.push(value.into());
        return true;
    }
    false
}

fn deduplicate(values: &mut Vec<String>) {
    let mut observed = BTreeSet::new();
    values.retain(|value| observed.insert(value.clone()));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{
        Asset, AssetIdentifier, AssetKind, Confidence, DataSource, FindingStatus,
        OrganizationProfile, Severity, SourceConnectionStatus,
    };
    use std::collections::BTreeMap;

    fn finding(case: &AssessmentCase) -> Finding {
        Finding {
            family: None,
            severity_basis_code: None,
            confidence_basis_code: None,
            context_factors: Vec::new(),
            id: "finding".into(),
            case_id: case.id.clone(),
            first_seen_run_id: "run".into(),
            last_seen_run_id: "run".into(),
            fingerprint: "engine:rule:asset".into(),
            title: "Observed issue".into(),
            plain_language_summary: "Scanner observation".into(),
            possible_impact: "Possible impact requires review.".into(),
            severity: Severity::High,
            confidence: Confidence::High,
            priority: 80,
            priority_reasons: vec!["Source severity: high".into()],
            asset_ids: vec!["asset".into()],
            evidence: vec![],
            control_references: vec![],
            recommendation: "Ask a qualified reviewer.".into(),
            verification_guidance: "Rerun after an approved change.".into(),
            rollback_considerations: None,
            official_references: vec![],
            recommended_expert_type: "Security reviewer".into(),
            status: FindingStatus::Unreviewed,
            tags: vec![],
        }
    }

    fn contextual_case() -> AssessmentCase {
        let mut case = AssessmentCase::new(
            "Context".into(),
            OrganizationProfile {
                organization_name: "Example".into(),
                employee_range: "2-49".into(),
                data_classes: vec![DataClass::PersonallyIdentifiableInformation],
                notes: None,
            },
        );
        case.assets.push(Asset {
            id: "asset".into(),
            kind: AssetKind::CloudResource,
            name: "customer data store".into(),
            provider: Some("aws".into()),
            region: Some("us-east-1".into()),
            identifiers: vec![AssetIdentifier {
                namespace: "test".into(),
                value: "asset".into(),
            }],
            discovered_from: vec!["source".into()],
            candidate: false,
            owner_confirmed: true,
            internet_exposed: Some(true),
            contains_sensitive_data: Some(true),
            metadata: BTreeMap::new(),
        });
        case.data_sources.push(DataSource {
            id: "source".into(),
            kind: SourceKind::AwsOrganization,
            label: "Retained AWS inventory".into(),
            status: SourceConnectionStatus::Connected,
            connected_at: None,
            last_discovered_at: None,
            read_only: true,
            metadata: BTreeMap::new(),
        });
        case
    }

    #[test]
    fn evidenced_case_context_changes_priority_and_wording_without_changing_severity() {
        let case = contextual_case();
        let mut finding = finding(&case);
        let original_confidence = finding.confidence.clone();
        let original_evidence = serde_json::to_value(&finding.evidence).unwrap();
        let original_scope = serde_json::to_value(&case.scope_grants).unwrap();
        apply_case_context(&case, &mut finding);

        assert_eq!(finding.priority, 90);
        assert_eq!(finding.severity, Severity::High);
        assert_eq!(finding.confidence, original_confidence);
        assert_eq!(
            serde_json::to_value(&finding.evidence).unwrap(),
            original_evidence
        );
        assert_eq!(
            serde_json::to_value(&case.scope_grants).unwrap(),
            original_scope
        );
        assert!(finding.priority_reasons.contains(&INTERNET_REASON.into()));
        assert!(finding.priority_reasons.contains(&SENSITIVE_REASON.into()));
        assert!(
            finding
                .possible_impact
                .contains("contains sensitive data, increasing the potential impact")
        );
        assert!(finding.tags.contains(&CONTEXT_VERSION_TAG.into()));

        // Every appendix above must have a code beside it. These sentences are
        // appended to `possible_impact`, and a surface that composes its own
        // impact sentence replaces that whole string -- so a factor carrying
        // prose but no code is a ten-point priority rise that only an English
        // reader is ever given a reason for.
        assert_eq!(
            finding.context_factors,
            vec![
                ContextFactor::InternetExposedAsset,
                ContextFactor::SensitiveDataAsset
            ]
        );

        // Both reasons are pushed here rather than by an adapter, so the
        // fixture census over the engines cannot see them. Without this, the
        // reader whose priority just rose ten points gets the two sentences
        // saying why -- and only those two -- in English.
        for reason in [INTERNET_REASON, SENSITIVE_REASON] {
            let translated = crate::finding_narrative::priority_reason_zh_hant(reason);
            assert_ne!(
                translated, reason,
                "case-context reason fell through untranslated: {reason}"
            );
        }

        let once = finding.clone();
        apply_case_context(&case, &mut finding);
        assert_eq!(finding.priority, once.priority);
        assert_eq!(finding.priority_reasons, once.priority_reasons);
        assert_eq!(finding.possible_impact, once.possible_impact);
        assert_eq!(finding.context_factors, once.context_factors);
    }

    #[test]
    fn questionnaire_declared_exposure_alone_never_changes_priority() {
        let mut case = contextual_case();
        case.profile.data_classes = vec![DataClass::General];
        case.assets[0].contains_sensitive_data = None;
        case.data_sources[0].kind = SourceKind::UserDeclared;
        let mut finding = finding(&case);
        let original = finding.clone();

        apply_case_context(&case, &mut finding);

        assert_eq!(finding.priority, original.priority);
        assert_eq!(finding.severity, original.severity);
        assert_eq!(finding.confidence, original.confidence);
        assert_eq!(
            serde_json::to_value(&finding.evidence).unwrap(),
            serde_json::to_value(&original.evidence).unwrap()
        );
        assert_eq!(finding.possible_impact, original.possible_impact);
        assert!(!finding.priority_reasons.contains(&INTERNET_REASON.into()));
        assert!(!finding.tags.contains(&CONTEXT_VERSION_TAG.into()));
    }

    #[test]
    fn reachable_service_inventory_is_never_promoted_as_a_problem() {
        let case = contextual_case();
        let mut observation = finding(&case);
        observation.severity = Severity::Informational;
        observation.priority = 0;
        observation.severity_basis_code = Some(crate::domain::SeverityBasisCode::OpenPort);
        observation.possible_impact = "Reachability alone is not a vulnerability.".into();

        apply_case_context(&case, &mut observation);

        assert_eq!(observation.priority, 0);
        assert_eq!(
            observation.possible_impact,
            "Reachability alone is not a vulnerability."
        );
        assert!(observation.context_factors.is_empty());
        assert!(
            !observation
                .priority_reasons
                .contains(&INTERNET_REASON.into())
        );
        assert!(
            !observation
                .priority_reasons
                .contains(&SENSITIVE_REASON.into())
        );
    }

    #[test]
    fn retained_non_questionnaire_source_can_support_internet_priority() {
        let mut case = contextual_case();
        case.profile.data_classes = vec![DataClass::General];
        case.assets[0].contains_sensitive_data = None;
        let mut finding = finding(&case);
        let original_severity = finding.severity.clone();
        let original_confidence = finding.confidence.clone();

        apply_case_context(&case, &mut finding);

        assert_eq!(finding.priority, 85);
        assert_eq!(finding.severity, original_severity);
        assert_eq!(finding.confidence, original_confidence);
        assert!(finding.priority_reasons.contains(&INTERNET_REASON.into()));
        assert!(
            finding
                .possible_impact
                .contains("internet-accessible, increasing the reachable attack surface")
        );
        assert!(finding.tags.contains(&CONTEXT_VERSION_TAG.into()));
    }

    #[test]
    fn retained_non_questionnaire_source_can_support_sensitive_priority() {
        let mut case = contextual_case();
        case.assets[0].internet_exposed = Some(false);
        let mut finding = finding(&case);
        let original_severity = finding.severity.clone();
        let original_confidence = finding.confidence.clone();

        apply_case_context(&case, &mut finding);

        assert_eq!(finding.priority, 85);
        assert_eq!(finding.severity, original_severity);
        assert_eq!(finding.confidence, original_confidence);
        assert!(finding.priority_reasons.contains(&SENSITIVE_REASON.into()));
        assert!(
            finding
                .possible_impact
                .contains("contains sensitive data, increasing the potential impact")
        );
        assert!(finding.tags.contains(&CONTEXT_VERSION_TAG.into()));
    }

    #[test]
    fn sensitive_context_fails_closed_for_questionnaire_mixed_and_unresolved_provenance() {
        let mut questionnaire_only = contextual_case();
        questionnaire_only.assets[0].internet_exposed = Some(false);
        questionnaire_only.data_sources[0].kind = SourceKind::UserDeclared;

        let mut mixed = contextual_case();
        mixed.assets[0].internet_exposed = Some(false);
        mixed.assets[0]
            .discovered_from
            .push("questionnaire-source".into());
        mixed.data_sources.push(DataSource {
            id: "questionnaire-source".into(),
            kind: SourceKind::UserDeclared,
            label: "Questionnaire entry".into(),
            status: SourceConnectionStatus::Connected,
            connected_at: None,
            last_discovered_at: None,
            read_only: true,
            metadata: BTreeMap::new(),
        });

        let mut unresolved = contextual_case();
        unresolved.assets[0].internet_exposed = Some(false);
        unresolved.assets[0]
            .discovered_from
            .push("missing-source".into());

        for (label, case) in [
            ("questionnaire-only", questionnaire_only),
            ("mixed", mixed),
            ("unresolved", unresolved),
        ] {
            let mut finding = finding(&case);
            let original = finding.clone();

            apply_case_context(&case, &mut finding);

            assert_eq!(finding.priority, original.priority, "{label}");
            assert_eq!(finding.severity, original.severity, "{label}");
            assert_eq!(finding.confidence, original.confidence, "{label}");
            assert_eq!(finding.possible_impact, original.possible_impact, "{label}");
            assert!(
                !finding.priority_reasons.contains(&SENSITIVE_REASON.into()),
                "{label}"
            );
            assert!(
                !finding.tags.contains(&CONTEXT_VERSION_TAG.into()),
                "{label}"
            );
        }
    }

    #[test]
    fn mixed_questionnaire_and_observed_source_provenance_never_changes_priority() {
        let mut case = contextual_case();
        case.profile.data_classes = vec![DataClass::General];
        case.assets[0].contains_sensitive_data = None;
        case.assets[0]
            .discovered_from
            .push("questionnaire-source".into());
        case.data_sources.push(DataSource {
            id: "questionnaire-source".into(),
            kind: SourceKind::UserDeclared,
            label: "Questionnaire entry".into(),
            status: SourceConnectionStatus::Connected,
            connected_at: None,
            last_discovered_at: None,
            read_only: true,
            metadata: BTreeMap::new(),
        });
        let mut finding = finding(&case);
        let original = finding.clone();

        apply_case_context(&case, &mut finding);

        assert_eq!(finding.priority, original.priority);
        assert_eq!(finding.severity, original.severity);
        assert_eq!(finding.confidence, original.confidence);
        assert_eq!(finding.possible_impact, original.possible_impact);
        assert!(!finding.priority_reasons.contains(&INTERNET_REASON.into()));
        assert!(!finding.tags.contains(&CONTEXT_VERSION_TAG.into()));
    }

    #[test]
    fn unresolved_source_provenance_never_changes_priority() {
        let mut case = contextual_case();
        case.profile.data_classes = vec![DataClass::General];
        case.assets[0].contains_sensitive_data = None;
        case.assets[0].discovered_from.push("missing-source".into());
        let mut finding = finding(&case);
        let original = finding.clone();

        apply_case_context(&case, &mut finding);

        assert_eq!(finding.priority, original.priority);
        assert_eq!(finding.possible_impact, original.possible_impact);
        assert!(!finding.priority_reasons.contains(&INTERNET_REASON.into()));
        assert!(!finding.tags.contains(&CONTEXT_VERSION_TAG.into()));
    }

    #[test]
    fn questionnaire_context_alone_never_invents_asset_sensitivity() {
        let mut case = contextual_case();
        case.assets[0].internet_exposed = None;
        case.assets[0].contains_sensitive_data = None;
        let mut finding = finding(&case);
        apply_case_context(&case, &mut finding);

        assert_eq!(finding.priority, 80);
        assert_eq!(finding.possible_impact, "Possible impact requires review.");
        assert!(!finding.tags.contains(&CONTEXT_VERSION_TAG.into()));
    }

    #[test]
    fn unrelated_asset_attributes_cannot_change_a_finding() {
        let mut case = contextual_case();
        case.assets[0].id = "different-asset".into();
        let mut finding = finding(&case);
        apply_case_context(&case, &mut finding);

        assert_eq!(finding.priority, 80);
        assert_eq!(finding.possible_impact, "Possible impact requires review.");
        assert!(!finding.tags.contains(&CONTEXT_VERSION_TAG.into()));
    }

    #[test]
    fn generic_questionnaire_data_does_not_assert_sensitive_impact() {
        let mut case = contextual_case();
        case.profile.data_classes = vec![DataClass::General];
        case.assets[0].internet_exposed = Some(false);
        let mut finding = finding(&case);
        apply_case_context(&case, &mut finding);

        assert_eq!(finding.priority, 80);
        assert!(!finding.possible_impact.contains("sensitive data"));
        assert!(!finding.tags.contains(&CONTEXT_VERSION_TAG.into()));
    }

    use crate::domain::EvidenceKind;
    use crate::finding_narrative::{
        PASSWORD_COMPOSITION_ORDER_REASON, PASSWORD_EXPIRY_ORDER_REASON,
    };
    use chrono::{TimeZone, Utc};

    fn evidence(engine: &str, rule: Option<&str>) -> crate::domain::Evidence {
        crate::domain::Evidence {
            id: "evidence".into(),
            finding_id: "finding".into(),
            run_id: "run".into(),
            engine_run_id: Some("engine-run".into()),
            kind: EvidenceKind::Configuration,
            engine_id: engine.into(),
            scanner_details: None,
            source_rule: rule.map(str::to_owned),
            result_pointer_sha256: None,
            observed_at: Utc.with_ymd_and_hms(2026, 8, 24, 12, 0, 0).unwrap(),
            summary: "summary".into(),
            location: Some("location".into()),
            artifact_id: "artifact".into(),
            artifact_sha256: "hash".into(),
            pointer: None,
            redacted: false,
        }
    }

    fn plain_case() -> AssessmentCase {
        let mut case = contextual_case();
        case.assets[0].internet_exposed = None;
        case.assets[0].contains_sensitive_data = None;
        case
    }

    #[test]
    fn scoutsuite_uppercase_password_rule_is_capped_without_changing_the_scanner_rating() {
        let case = plain_case();
        let mut finding = finding(&case);
        finding.evidence.push(evidence(
            "scoutsuite",
            Some("iam-password-policy-no-uppercase-required"),
        ));
        let severity = finding.severity.clone();
        let confidence = finding.confidence.clone();
        let title = finding.title.clone();
        let recommendation = finding.recommendation.clone();
        let evidence_before = serde_json::to_value(&finding.evidence).unwrap();

        apply_case_context(&case, &mut finding);

        assert_eq!(finding.priority, 35);
        assert_eq!(finding.severity, severity);
        assert_eq!(finding.confidence, confidence);
        assert_eq!(finding.title, title);
        assert_eq!(finding.recommendation, recommendation);
        assert!(finding.context_factors.is_empty());
        assert_eq!(
            serde_json::to_value(&finding.evidence).unwrap(),
            evidence_before
        );
        assert!(
            finding
                .priority_reasons
                .contains(&PASSWORD_COMPOSITION_ORDER_REASON.into())
        );
        assert!(finding.tags.contains(&"priority-guidance:v1".into()));
    }

    #[test]
    fn case_context_cannot_lift_a_guided_password_rule_above_the_low_tier() {
        let case = contextual_case();
        let mut finding = finding(&case);
        finding.evidence.push(evidence(
            "scoutsuite",
            Some("iam-password-policy-no-uppercase-required"),
        ));
        let severity = finding.severity.clone();
        let confidence = finding.confidence.clone();
        let evidence_before = serde_json::to_value(&finding.evidence).unwrap();

        apply_case_context(&case, &mut finding);

        assert_eq!(finding.priority, 35);
        assert_eq!(finding.severity, severity);
        assert_eq!(finding.confidence, confidence);
        assert_eq!(
            serde_json::to_value(&finding.evidence).unwrap(),
            evidence_before
        );
        assert!(finding.priority_reasons.contains(&INTERNET_REASON.into()));
        assert!(finding.priority_reasons.contains(&SENSITIVE_REASON.into()));
        assert!(
            finding
                .priority_reasons
                .contains(&PASSWORD_COMPOSITION_ORDER_REASON.into())
        );
        assert_eq!(
            finding.context_factors,
            vec![
                ContextFactor::InternetExposedAsset,
                ContextFactor::SensitiveDataAsset
            ]
        );
        assert!(finding.tags.contains(&CONTEXT_VERSION_TAG.into()));
        assert!(finding.tags.contains(&"priority-guidance:v1".into()));

        let once = serde_json::to_value(&finding).unwrap();
        apply_case_context(&case, &mut finding);
        assert_eq!(serde_json::to_value(&finding).unwrap(), once);
    }

    #[test]
    fn minimum_password_length_keeps_the_high_priority() {
        let case = plain_case();
        let mut finding = finding(&case);
        finding.evidence.push(evidence(
            "scoutsuite",
            Some("iam-password-policy-minimum-length"),
        ));

        apply_case_context(&case, &mut finding);

        assert_eq!(finding.priority, 80);
        assert_eq!(finding.severity, Severity::High);
        assert!(
            !finding
                .priority_reasons
                .iter()
                .any(|reason| reason == PASSWORD_COMPOSITION_ORDER_REASON
                    || reason == PASSWORD_EXPIRY_ORDER_REASON)
        );
        assert!(!finding.tags.contains(&"priority-guidance:v1".into()));
    }

    #[test]
    fn prowler_scheduled_expiry_records_the_expiry_reason() {
        let case = plain_case();
        let mut finding = finding(&case);
        finding.evidence.push(evidence(
            "prowler",
            Some("iam_password_policy_expires_passwords_within_90_days_or_less"),
        ));
        let severity = finding.severity.clone();
        let confidence = finding.confidence.clone();

        apply_case_context(&case, &mut finding);

        assert_eq!(finding.priority, 35);
        assert_eq!(finding.severity, severity);
        assert_eq!(finding.confidence, confidence);
        assert!(
            finding
                .priority_reasons
                .contains(&PASSWORD_EXPIRY_ORDER_REASON.into())
        );
        assert!(
            !finding
                .priority_reasons
                .contains(&PASSWORD_COMPOSITION_ORDER_REASON.into())
        );
        assert!(finding.tags.contains(&"priority-guidance:v1".into()));
    }
}
