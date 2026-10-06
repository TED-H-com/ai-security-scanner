//! Owner-reviewed presentation groups. Findings and correlation decisions
//! remain unchanged; every member stays in the report.

use crate::beginner_report::{BeginnerFinding, FindingSnapshotSource, severity_rank};
use crate::domain::{AwsIamPolicySource, FindingFamily, Id, ScanRun};
use crate::finding_narrative::{
    EXPOSED_SECRET_NEXT_STEP_ENGLISH, EXPOSED_SECRET_NEXT_STEP_ZH_HANT,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

const RULE_VERSION: &str = "aws-related-checks-1";
const DEPENDENCY_RULE_VERSION: &str = "dependency-advisory-1";
const SECRET_RULE_VERSION: &str = "secret-location-1";

fn rule_version(kind: ReportProblemKind) -> &'static str {
    match kind {
        ReportProblemKind::IamPasswordPolicy
        | ReportProblemKind::RootAccountUsage
        | ReportProblemKind::IamPolicyPermissions => RULE_VERSION,
        ReportProblemKind::VulnerableDependency => DEPENDENCY_RULE_VERSION,
        ReportProblemKind::ExposedSecret => SECRET_RULE_VERSION,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportProblemKind {
    IamPasswordPolicy,
    RootAccountUsage,
    IamPolicyPermissions,
    VulnerableDependency,
    ExposedSecret,
}

/// How many members of a problem group this product ordered lower than their
/// scanner severity suggests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LowerPriorityMembers {
    Partial,
    All,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportProblemGroup {
    pub group_id: Id,
    pub rule_version: String,
    pub kind: ReportProblemKind,
    pub title: String,
    pub target_asset_id: Id,
    pub representative_finding_id: Id,
    pub finding_ids: Vec<Id>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_name: Option<String>,
    /// Present when at least one member carries a product order lower than its
    /// scanner severity. Omitted from the group id: it is presentation only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lower_priority_members: Option<LowerPriorityMembers>,
    /// Package coordinate from the frozen finding's `package:` tag.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package_name: Option<String>,
    /// Installed version the scanners agreed on for [`Self::package_name`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub installed_version: Option<String>,
    /// Members' own advisory ids, not aliases. Uppercase-sorted, first display form kept.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub advisory_ids: Vec<String>,
}

impl ReportProblemGroup {
    pub fn next_step_english(&self) -> Option<&'static str> {
        match self.kind {
            ReportProblemKind::IamPasswordPolicy => match self.lower_priority_members {
                Some(LowerPriorityMembers::Partial) => Some(
                    "Review the account's IAM password policy. Fix the failed length or reuse settings first; change the character-mix or expiry settings only if an audit you must pass still requires them.",
                ),
                Some(LowerPriorityMembers::All) => Some(
                    "Change these IAM password policy settings only if an audit you must pass still requires them; NIST SP 800-63B-4 says not to require character mixes or scheduled expiry.",
                ),
                None => Some(
                    "Review the account's IAM password policy and address each failed setting.",
                ),
            },
            ReportProblemKind::RootAccountUsage => Some(
                "Review each scanner's root-usage window and use an IAM role for routine work.",
            ),
            ReportProblemKind::IamPolicyPermissions | ReportProblemKind::VulnerableDependency => {
                None
            }
            ReportProblemKind::ExposedSecret => Some(EXPOSED_SECRET_NEXT_STEP_ENGLISH),
        }
    }

    pub fn next_step_zh_hant(&self) -> Option<&'static str> {
        match self.kind {
            ReportProblemKind::IamPasswordPolicy => match self.lower_priority_members {
                Some(LowerPriorityMembers::Partial) => Some(
                    "檢查帳號的 IAM 密碼政策：先調整未通過的長度或重複使用設定；字元組成或到期設定，只有在必須通過的稽核仍要求時才需要變更。",
                ),
                Some(LowerPriorityMembers::All) => Some(
                    "只有在必須通過的稽核仍要求時，才需要變更這些 IAM 密碼政策設定；NIST SP 800-63B-4 要求不要強制混合字元類型或定期到期。",
                ),
                None => Some("檢查帳號的 IAM 密碼政策，並調整每項未通過的設定。"),
            },
            ReportProblemKind::RootAccountUsage => {
                Some("檢查各掃描工具記錄的 root 使用時間範圍，日常工作改用 IAM role。")
            }
            ReportProblemKind::IamPolicyPermissions | ReportProblemKind::VulnerableDependency => {
                None
            }
            ReportProblemKind::ExposedSecret => Some(EXPOSED_SECRET_NEXT_STEP_ZH_HANT),
        }
    }

    pub fn impact_english(&self) -> Option<&'static str> {
        match self.kind {
            ReportProblemKind::IamPasswordPolicy => match self.lower_priority_members {
                Some(LowerPriorityMembers::All) => Some(
                    "CIS AWS Foundations Benchmark v1.2.0 lists these settings; current guidance does not treat their absence as a weakness.",
                ),
                Some(LowerPriorityMembers::Partial) | None => Some(
                    "Weak password settings increase the risk of unauthorized access to IAM users.",
                ),
            },
            ReportProblemKind::RootAccountUsage => Some(
                "Root-account activity uses permissions with broad control of this AWS account.",
            ),
            ReportProblemKind::IamPolicyPermissions
            | ReportProblemKind::VulnerableDependency
            | ReportProblemKind::ExposedSecret => None,
        }
    }

    pub fn impact_zh_hant(&self) -> Option<&'static str> {
        match self.kind {
            ReportProblemKind::IamPasswordPolicy => match self.lower_priority_members {
                Some(LowerPriorityMembers::All) => Some(
                    "CIS AWS Foundations Benchmark v1.2.0 列出這些設定；現行指引不把缺少這些設定視為弱點。",
                ),
                Some(LowerPriorityMembers::Partial) | None => {
                    Some("較弱的密碼設定會增加 IAM 使用者遭未授權存取的風險。")
                }
            },
            ReportProblemKind::RootAccountUsage => {
                Some("root 帳號的活動會使用可廣泛控制此 AWS 帳號的權限。")
            }
            ReportProblemKind::IamPolicyPermissions
            | ReportProblemKind::VulnerableDependency
            | ReportProblemKind::ExposedSecret => None,
        }
    }

    pub fn title_english(&self) -> String {
        match self.kind {
            ReportProblemKind::IamPasswordPolicy => "IAM password policy needs attention".into(),
            ReportProblemKind::RootAccountUsage => "Root account used recently".into(),
            ReportProblemKind::IamPolicyPermissions => format!(
                "Review IAM policy permissions: {}",
                self.policy_name.as_deref().unwrap_or("IAM policy")
            ),
            ReportProblemKind::VulnerableDependency => format!(
                "Vulnerable package {} {} ({})",
                self.package_name.as_deref().unwrap_or(""),
                self.installed_version.as_deref().unwrap_or(""),
                self.advisory_ids.join(" / ")
            ),
            ReportProblemKind::ExposedSecret => "Secret found in a file".into(),
        }
    }

    pub fn title_zh_hant(&self) -> String {
        match self.kind {
            ReportProblemKind::IamPasswordPolicy => "IAM 密碼政策需要調整".into(),
            ReportProblemKind::RootAccountUsage => "最近使用過 root 帳號".into(),
            ReportProblemKind::IamPolicyPermissions => format!(
                "檢查 IAM policy 的權限：{}",
                self.policy_name.as_deref().unwrap_or("IAM policy")
            ),
            ReportProblemKind::VulnerableDependency => format!(
                "有已知弱點的套件 {} {}（{}）",
                self.package_name.as_deref().unwrap_or(""),
                self.installed_version.as_deref().unwrap_or(""),
                self.advisory_ids.join(" / ")
            ),
            ReportProblemKind::ExposedSecret => "檔案中發現機密".into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Subject {
    kind: ReportProblemKind,
    asset_id: Id,
    resource: String,
}

const PROWLER_PASSWORD_RULES: &[&str] = &[
    "iam_password_policy_lowercase",
    "iam_password_policy_uppercase",
    "iam_password_policy_number",
    "iam_password_policy_symbol",
    "iam_password_policy_minimum_length_14",
    "iam_password_policy_reuse_24",
    "iam_password_policy_expires_passwords_within_90_days_or_less",
];
const SCOUT_PASSWORD_RULES: &[&str] = &[
    "iam-password-policy-minimum-length",
    "iam-password-policy-reuse-enabled",
    "iam-password-policy-no-expiration",
    "iam-password-policy-expiration-threshold",
];

/// Provenance shared by every problem kind: one approved asset in a completed
/// run, and frozen evidence tied to that asset's task.
fn presentation_asset_id(finding: &BeginnerFinding, run: &ScanRun) -> Option<Id> {
    if run.completed_at.is_none()
        || finding.snapshot_source != FindingSnapshotSource::FrozenSelectedRun
        || finding.target_asset_ids.len() != 1
        || finding.evidence_references.is_empty()
        || finding
            .severity_basis_code
            .is_some_and(|code| code.is_exposure_observation())
    {
        return None;
    }
    let asset_id = &finding.target_asset_ids[0];
    if !run.report_asset_snapshots.iter().any(|snapshot| {
        &snapshot.asset.id == asset_id
            && snapshot.disposition == crate::domain::ReportAssetDisposition::RequestedForScan
    }) {
        return None;
    }
    for evidence in &finding.evidence_references {
        if !evidence.details_frozen {
            return None;
        }
        let task_id = evidence.engine_run_id.as_ref()?;
        let task = run.engine_runs.iter().find(|task| {
            &task.id == task_id
                && task.scan_run_id == run.id
                && task.engine_id == evidence.engine_id
                && task.asset_ids.len() == 1
                && &task.asset_ids[0] == asset_id
        })?;
        let artifact_id = evidence.artifact_id.as_ref()?;
        if !task.raw_artifact_ids.contains(artifact_id) || evidence.artifact_sha256.is_empty() {
            return None;
        }
        evidence.source_rule.as_deref()?;
    }
    Some(asset_id.clone())
}

fn subject(finding: &BeginnerFinding, run: &ScanRun) -> Option<(Subject, Option<String>)> {
    let asset_id = presentation_asset_id(finding, run)?;
    let asset = &run
        .report_asset_snapshots
        .iter()
        .find(|snapshot| {
            snapshot.asset.id == asset_id
                && snapshot.asset.provider.as_deref() == Some("aws")
                && snapshot.asset.kind == crate::domain::AssetKind::CloudAccount
                && snapshot.disposition == crate::domain::ReportAssetDisposition::RequestedForScan
        })?
        .asset;
    let account_ids = asset
        .identifiers
        .iter()
        .filter(|identifier| identifier.namespace == "aws_account_id")
        .map(|identifier| identifier.value.as_str())
        .collect::<BTreeSet<_>>();
    if account_ids.len() != 1 {
        return None;
    }
    let account_id = account_ids.into_iter().next()?;
    if account_id.len() != 12 || !account_id.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let mut subjects = BTreeSet::new();
    let mut policy_name = None;
    for evidence in &finding.evidence_references {
        let rule = evidence.source_rule.as_deref()?;
        if evidence.engine_id == "prowler" {
            if PROWLER_PASSWORD_RULES.contains(&rule)
                && !evidence.location.as_deref().is_some_and(|location| {
                    location.ends_with(&format!(":{account_id}:password-policy"))
                })
            {
                return None;
            }
            if rule == "iam_avoid_root_usage"
                && evidence.location.as_deref()
                    != Some(format!("arn:aws:iam::{account_id}:root").as_str())
            {
                return None;
            }
        }
        let (kind, resource) = match evidence.engine_id.as_str() {
            "prowler" if PROWLER_PASSWORD_RULES.contains(&rule) => (
                ReportProblemKind::IamPasswordPolicy,
                "account-password-policy".into(),
            ),
            "scoutsuite" if SCOUT_PASSWORD_RULES.contains(&rule) => (
                ReportProblemKind::IamPasswordPolicy,
                "account-password-policy".into(),
            ),
            "prowler" if rule == "iam_avoid_root_usage" => {
                (ReportProblemKind::RootAccountUsage, "account-root".into())
            }
            "scoutsuite" if rule == "iam-root-account-used-recently" => {
                (ReportProblemKind::RootAccountUsage, "account-root".into())
            }
            "cloudsplaining"
                if matches!(rule, "ResourceExposure" | "InfrastructureModification") =>
            {
                let policy = evidence.scanner_details.as_ref()?.aws_iam_policy.as_ref()?;
                let location = evidence.location.as_deref()?;
                let (identity, _) = location.split_once(" :: ")?;
                // Only complete ARN/hash coordinates can establish the same
                // policy. Display names and legacy sanitized locations cannot.
                let source = match policy.policy_source {
                    AwsIamPolicySource::AwsManaged
                        if identity.starts_with("arn:aws:iam::aws:policy/")
                            && identity.len() > "arn:aws:iam::aws:policy/".len()
                            && !identity.chars().any(char::is_whitespace) =>
                    {
                        "aws"
                    }
                    AwsIamPolicySource::CustomerManaged
                        if policy_arn(identity)
                            && identity
                                .starts_with(&format!("arn:aws:iam::{account_id}:policy/")) =>
                    {
                        "customer"
                    }
                    AwsIamPolicySource::Inline
                        if identity.len() == 64
                            && identity.bytes().all(|byte| byte.is_ascii_hexdigit()) =>
                    {
                        "inline"
                    }
                    _ => return None,
                };
                policy_name = Some(policy.policy_name.clone());
                (
                    ReportProblemKind::IamPolicyPermissions,
                    format!("{source}:{identity}"),
                )
            }
            _ => return None,
        };
        subjects.insert(Subject {
            kind,
            asset_id: asset_id.clone(),
            resource,
        });
    }
    (subjects.len() == 1).then(|| (subjects.into_iter().next().unwrap(), policy_name))
}

fn policy_arn(identity: &str) -> bool {
    let parts = identity.split(':').collect::<Vec<_>>();
    matches!(parts.as_slice(), ["arn", "aws", "iam", "", account, resource]
        if account.len() == 12 && account.bytes().all(|byte| byte.is_ascii_digit())
        && resource.starts_with("policy/") && resource.len() > 7)
        && !identity.chars().any(char::is_whitespace)
}
const HARD_CODED_CREDENTIAL_CWES: &[&str] = &["CWE-798", "CWE-259", "CWE-321"];

fn is_advisory_id(value: &str) -> bool {
    let upper = value.trim().to_ascii_uppercase();
    crate::correlation::is_cve_identifier(&upper) || crate::correlation::is_ghsa_identifier(&upper)
}

fn agreed_installed_version(finding: &BeginnerFinding) -> Option<String> {
    let mut agreed = None;
    for evidence in &finding.evidence_references {
        let version = evidence
            .scanner_details
            .as_ref()
            .and_then(|details| details.installed_version.as_deref())
            .filter(|version| !version.is_empty())?;
        match &agreed {
            None => agreed = Some(version.to_owned()),
            Some(current) if current == version => {}
            Some(_) => return None,
        }
    }
    agreed
}

fn vulnerability_id_set(finding: &BeginnerFinding) -> BTreeSet<String> {
    let mut ids = BTreeSet::new();
    for evidence in &finding.evidence_references {
        if let Some(rule) = evidence.source_rule.as_deref() {
            let upper = rule.trim().to_ascii_uppercase();
            if !upper.is_empty() {
                ids.insert(upper);
            }
        }
        if let Some(details) = evidence.scanner_details.as_ref() {
            for alias in &details.advisory_aliases {
                let upper = alias.trim().to_ascii_uppercase();
                if !upper.is_empty() {
                    ids.insert(upper);
                }
            }
        }
    }
    ids
}

fn member_advisory_ids(members: &[&BeginnerFinding]) -> Vec<String> {
    let mut display = BTreeMap::<String, String>::new();
    for member in members {
        for evidence in &member.evidence_references {
            let Some(rule) = evidence.source_rule.as_deref() else {
                continue;
            };
            let trimmed = rule.trim();
            if trimmed.is_empty() {
                continue;
            }
            display
                .entry(trimmed.to_ascii_uppercase())
                .or_insert_with(|| trimmed.to_owned());
        }
    }
    display.into_values().collect()
}

fn intersecting_components(sets: &[BTreeSet<String>]) -> Vec<Vec<usize>> {
    let mut parent: Vec<usize> = (0..sets.len()).collect();
    fn find(parent: &mut [usize], mut index: usize) -> usize {
        while parent[index] != index {
            parent[index] = parent[parent[index]];
            index = parent[index];
        }
        index
    }
    for left in 0..sets.len() {
        for right in (left + 1)..sets.len() {
            if sets[left].intersection(&sets[right]).next().is_none() {
                continue;
            }
            let left_root = find(&mut parent, left);
            let right_root = find(&mut parent, right);
            if left_root == right_root {
                continue;
            }
            if left_root < right_root {
                parent[right_root] = left_root;
            } else {
                parent[left_root] = right_root;
            }
        }
    }
    let mut grouped = BTreeMap::<usize, Vec<usize>>::new();
    for index in 0..sets.len() {
        grouped
            .entry(find(&mut parent, index))
            .or_default()
            .push(index);
    }
    grouped.into_values().collect()
}

fn classified_as_hard_coded_credential(finding: &BeginnerFinding) -> bool {
    finding.evidence_references.iter().any(|evidence| {
        evidence.scanner_details.as_ref().is_some_and(|details| {
            details
                .cwe_ids
                .iter()
                .any(|cwe| HARD_CODED_CREDENTIAL_CWES.contains(&cwe.as_str()))
        })
    })
}

fn agreed_secret_place(finding: &BeginnerFinding) -> Option<(String, u32)> {
    let mut agreed = None;
    for evidence in &finding.evidence_references {
        let place =
            crate::finding_narrative::normalized_source_path_line(evidence.location.as_deref()?)?;
        match &agreed {
            None => agreed = Some(place),
            Some(current) if current == &place => {}
            Some(_) => return None,
        }
    }
    agreed
}

struct PresentedFields {
    policy_name: Option<String>,
    package_name: Option<String>,
    installed_version: Option<String>,
    advisory_ids: Vec<String>,
}

fn presented_group(
    kind: ReportProblemKind,
    asset_id: Id,
    resource: &str,
    members: &[&BeginnerFinding],
    run: &ScanRun,
    presented: PresentedFields,
) -> Option<ReportProblemGroup> {
    if members.len() < 2 {
        return None;
    }
    let representative = members.iter().min_by_key(|finding| {
        (
            std::cmp::Reverse(severity_rank(&finding.severity)),
            std::cmp::Reverse(finding.priority.unwrap_or(0)),
            &finding.finding_id,
        )
    })?;
    let mut digest = Sha256::new();
    for component in [
        rule_version(kind),
        run.id.as_str(),
        asset_id.as_str(),
        &format!("{:?}", kind),
        resource,
    ] {
        digest.update(component.as_bytes());
        digest.update([0]);
    }
    let guided = members
        .iter()
        .filter(|finding| {
            crate::priority_guidance::PriorityGuidance::from_priority_reasons(
                &finding.priority_reasons,
            )
            .is_some()
        })
        .count();
    let lower_priority_members = if guided == 0 {
        None
    } else if guided == members.len() {
        Some(LowerPriorityMembers::All)
    } else {
        Some(LowerPriorityMembers::Partial)
    };
    let mut group = ReportProblemGroup {
        group_id: format!("report-problem:{}", hex::encode(digest.finalize())),
        rule_version: rule_version(kind).into(),
        kind,
        title: String::new(),
        target_asset_id: asset_id,
        representative_finding_id: representative.finding_id.clone(),
        finding_ids: members
            .iter()
            .map(|finding| finding.finding_id.clone())
            .collect(),
        policy_name: presented.policy_name,
        lower_priority_members,
        package_name: presented.package_name,
        installed_version: presented.installed_version,
        advisory_ids: presented.advisory_ids,
    };
    group.title = group.title_english();
    Some(group)
}

fn dependency_groups(
    findings: &[BeginnerFinding],
    run: &ScanRun,
    package_by_finding: &BTreeMap<Id, String>,
) -> Vec<ReportProblemGroup> {
    struct Candidate<'a> {
        finding: &'a BeginnerFinding,
        version: String,
        ids: BTreeSet<String>,
    }
    let mut buckets = BTreeMap::<(Id, String, String), Vec<Candidate<'_>>>::new();
    for finding in findings {
        if finding.family != Some(FindingFamily::VulnerableComponent) {
            continue;
        }
        let Some(asset_id) = presentation_asset_id(finding, run) else {
            continue;
        };
        let Some(package) = package_by_finding.get(&finding.finding_id) else {
            continue;
        };
        if finding
            .evidence_references
            .iter()
            .any(|evidence| !evidence.source_rule.as_deref().is_some_and(is_advisory_id))
        {
            continue;
        }
        let Some(version) = agreed_installed_version(finding) else {
            continue;
        };
        buckets
            .entry((asset_id, package.clone(), version.clone()))
            .or_default()
            .push(Candidate {
                finding,
                version,
                ids: vulnerability_id_set(finding),
            });
    }
    let mut groups = Vec::new();
    for ((asset_id, package, _), candidates) in buckets {
        let sets = candidates
            .iter()
            .map(|candidate| candidate.ids.clone())
            .collect::<Vec<_>>();
        for component in intersecting_components(&sets) {
            if component.len() < 2 {
                continue;
            }
            let members = component
                .iter()
                .map(|index| candidates[*index].finding)
                .collect::<Vec<_>>();
            let version = candidates[component[0]].version.clone();
            let advisory_ids = member_advisory_ids(&members);
            let Some(first) = advisory_ids.first() else {
                continue;
            };
            let resource = format!("{package}@{version}#{first}");
            if let Some(group) = presented_group(
                ReportProblemKind::VulnerableDependency,
                asset_id.clone(),
                &resource,
                &members,
                run,
                PresentedFields {
                    policy_name: None,
                    package_name: Some(package.clone()),
                    installed_version: Some(version),
                    advisory_ids,
                },
            ) {
                groups.push(group);
            }
        }
    }
    groups
}

fn secret_groups(findings: &[BeginnerFinding], run: &ScanRun) -> Vec<ReportProblemGroup> {
    let mut buckets = BTreeMap::<Subject, Vec<&BeginnerFinding>>::new();
    for finding in findings {
        if finding.family == Some(FindingFamily::VulnerableComponent) {
            continue;
        }
        let secret = finding.family == Some(FindingFamily::Secret)
            || classified_as_hard_coded_credential(finding);
        if !secret {
            continue;
        }
        let Some(asset_id) = presentation_asset_id(finding, run) else {
            continue;
        };
        let Some((path, line)) = agreed_secret_place(finding) else {
            continue;
        };
        buckets
            .entry(Subject {
                kind: ReportProblemKind::ExposedSecret,
                asset_id,
                resource: format!("{path}:{line}"),
            })
            .or_default()
            .push(finding);
    }
    buckets
        .into_iter()
        .filter_map(|(subject, members)| {
            presented_group(
                subject.kind,
                subject.asset_id,
                &subject.resource,
                &members,
                run,
                PresentedFields {
                    policy_name: None,
                    package_name: None,
                    installed_version: None,
                    advisory_ids: Vec::new(),
                },
            )
        })
        .collect()
}

pub(crate) fn build_problem_groups(
    findings: &[BeginnerFinding],
    run: &ScanRun,
    package_by_finding: &BTreeMap<Id, String>,
) -> Vec<ReportProblemGroup> {
    let mut candidates = BTreeMap::<Subject, (Vec<&BeginnerFinding>, Option<String>)>::new();
    for finding in findings {
        if let Some((subject, name)) = subject(finding, run) {
            let entry = candidates.entry(subject).or_default();
            entry.0.push(finding);
            if entry.1.is_none() {
                entry.1 = name;
            }
        }
    }
    let mut groups = candidates
        .into_iter()
        .filter_map(|(subject, (members, policy_name))| {
            presented_group(
                subject.kind,
                subject.asset_id,
                &subject.resource,
                &members,
                run,
                PresentedFields {
                    policy_name,
                    package_name: None,
                    installed_version: None,
                    advisory_ids: Vec::new(),
                },
            )
        })
        .collect::<Vec<_>>();
    groups.extend(dependency_groups(findings, run, package_by_finding));
    groups.extend(secret_groups(findings, run));
    groups
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::beginner_report::{
        FindingSnapshotSource, build_beginner_master_report,
        tests::{aws_grouping_case, frozen_finding, observation},
    };
    use crate::domain::{AssessmentCase, AssetKind, FindingFamily, Severity};
    use crate::finding_narrative::{
        EXPOSED_SECRET_NEXT_STEP_ENGLISH, EXPOSED_SECRET_NEXT_STEP_ZH_HANT,
        finding_next_action_english,
    };
    use chrono::Utc;
    use std::collections::{BTreeMap, BTreeSet};

    fn add(
        case: &mut AssessmentCase,
        engine: &str,
        rule: &str,
        location: &str,
        policy: Option<(AwsIamPolicySource, &str)>,
        severity: Severity,
    ) {
        let id = format!("finding-{}", case.findings.len());
        let mut finding = frozen_finding(case, &id, 50, severity);
        finding.title = format!("{engine}: {rule} / {id}");
        let evidence = &mut finding.evidence[0];
        evidence.engine_id = engine.into();
        evidence.engine_run_id = Some(engine.into());
        evidence.source_rule = Some(rule.into());
        evidence.location = Some(location.into());
        if let Some((source, name)) = policy {
            evidence.scanner_details = Some(serde_json::from_value(serde_json::json!({
                "aws_iam_policy": {
                    "policy_source": source, "policy_name": name, "finding_identity": rule,
                    "actions": [format!("service:Action{}",case.findings.len())], "actions_complete": true,
                    "attached_to": {"roles":[], "groups":[], "users":[], "complete":true}
                }
            })).unwrap());
        }
        case.scan_runs[0]
            .engine_runs
            .iter_mut()
            .find(|task| task.engine_id == engine)
            .unwrap()
            .raw_artifact_ids
            .push(evidence.artifact_id.clone());
        let mut retained = observation(&finding, "run-1", Utc::now());
        retained.engine_ids = vec![engine.into()];
        case.finding_observations.push(retained);
        case.findings.push(finding);
    }

    pub(crate) fn approved_case() -> AssessmentCase {
        let mut case = aws_grouping_case();
        for rule in PROWLER_PASSWORD_RULES {
            add(
                &mut case,
                "prowler",
                rule,
                "arn:aws:iam::123456789012:password-policy",
                None,
                Severity::Low,
            );
        }
        for rule in SCOUT_PASSWORD_RULES {
            add(
                &mut case,
                "scoutsuite",
                rule,
                "iam.password_policy",
                None,
                Severity::High,
            );
        }
        add(
            &mut case,
            "prowler",
            "iam_avoid_root_usage",
            "arn:aws:iam::123456789012:root",
            None,
            Severity::Medium,
        );
        add(
            &mut case,
            "scoutsuite",
            "iam-root-account-used-recently",
            "iam.credential_report.root",
            None,
            Severity::High,
        );
        for (source, identity, name, total) in [
            (
                AwsIamPolicySource::AwsManaged,
                "arn:aws:iam::aws:policy/SecurityAudit",
                "SecurityAudit",
                6,
            ),
            (
                AwsIamPolicySource::CustomerManaged,
                "arn:aws:iam::123456789012:policy/private-one",
                "PrivatePolicy",
                2,
            ),
            (
                AwsIamPolicySource::CustomerManaged,
                "arn:aws:iam::123456789012:policy/private-two",
                "PrivatePolicy",
                2,
            ),
            (
                AwsIamPolicySource::Inline,
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "InlinePolicy",
                1,
            ),
        ] {
            for index in 0..total {
                add(
                    &mut case,
                    "cloudsplaining",
                    if index % 2 == 0 {
                        "ResourceExposure"
                    } else {
                        "InfrastructureModification"
                    },
                    &format!("{identity} :: service:Action{index}"),
                    Some((source, name)),
                    if index % 2 == 0 {
                        Severity::High
                    } else {
                        Severity::Low
                    },
                );
            }
        }
        for rule in [
            "iam_root_credentials_management",
            "iam_user_mfa_enabled",
            "iam_user_accesskey_unused",
            "iam_role_unused_permissions",
            "other-1",
            "other-2",
            "other-3",
        ] {
            add(
                &mut case,
                "prowler",
                rule,
                "arn:aws:iam::123456789012:role/example",
                None,
                Severity::Medium,
            );
        }
        case
    }

    #[test]
    fn approved_groups_reduce_31_rows_to_13_without_changing_any_original_or_workflow() {
        let case = approved_case();
        let before = serde_json::to_value(&case).unwrap();
        let report = build_beginner_master_report(&case, "run-1").unwrap();
        assert_eq!(report.findings.len(), 31);
        assert_eq!(report.problem_findings().len(), 13);
        let mut sizes = report
            .problem_groups
            .iter()
            .map(|group| group.finding_ids.len())
            .collect::<Vec<_>>();
        sizes.sort();
        assert_eq!(sizes, [2, 2, 2, 6, 11]);
        assert!(
            report
                .problem_groups
                .iter()
                .all(|group| group.rule_version == RULE_VERSION)
        );
        assert!(report.problem_groups.iter().all(|group| {
            report
                .findings
                .iter()
                .find(|finding| finding.finding_id == group.representative_finding_id)
                .unwrap()
                .severity
                == Severity::High
        }));
        assert_eq!(serde_json::to_value(&case).unwrap(), before);
        for original in &case.findings {
            let member = report
                .findings
                .iter()
                .find(|finding| finding.finding_id == original.id)
                .unwrap();
            assert_eq!(member.title, original.title);
            assert_eq!(member.fingerprint, original.fingerprint);
            assert_eq!(member.severity, original.severity);
            assert_eq!(
                member.evidence_references[0].source_rule,
                original.evidence[0].source_rule
            );
            assert_eq!(
                member.evidence_references[0].location,
                original.evidence[0].location
            );
        }
        let serialized = serde_json::to_string(&report).unwrap();
        assert!(!serialized.contains("customer:arn:"));
    }

    #[test]
    fn grouping_requires_frozen_selected_run_asset_task_and_full_resource_identity() {
        let case = approved_case();
        let report = build_beginner_master_report(&case, "run-1").unwrap();
        let run = &case.scan_runs[0];
        for mutate in 0..7 {
            let mut findings = report.findings.clone();
            for finding in &mut findings {
                match mutate {
                    0 => {
                        finding.snapshot_source =
                            FindingSnapshotSource::CurrentCanonicalLegacyFallback
                    }
                    1 => finding.evidence_references[0].details_frozen = false,
                    2 => {
                        finding.evidence_references[0].engine_run_id = Some("other-run-task".into())
                    }
                    3 => finding.target_asset_ids.push("other-asset".into()),
                    4 => finding.evidence_references[0].artifact_id = Some("other-artifact".into()),
                    5 => {
                        finding.evidence_references[0].source_rule = Some("unapproved-rule".into())
                    }
                    _ => finding.evidence_references[0].artifact_sha256.clear(),
                }
            }
            assert!(
                build_problem_groups(&findings, run, &BTreeMap::new()).is_empty(),
                "guard {mutate}"
            );
        }
        let mut wrong_run = run.clone();
        wrong_run.report_asset_snapshots[0].asset.identifiers[0].value = "999999999999".into();
        let groups = build_problem_groups(&report.findings, &wrong_run, &BTreeMap::new());
        assert!(
            groups
                .iter()
                .all(|group| group.finding_ids.iter().all(|id| report
                    .findings
                    .iter()
                    .find(|finding| &finding.finding_id == id)
                    .unwrap()
                    .evidence_references[0]
                    .engine_id
                    != "prowler"))
        );
        wrong_run.report_asset_snapshots.clear();
        assert!(build_problem_groups(&report.findings, &wrong_run, &BTreeMap::new()).is_empty());
        let mut findings = report.findings.clone();
        for finding in &mut findings {
            if finding.evidence_references[0].engine_id == "cloudsplaining" {
                finding.evidence_references[0].location =
                    Some("PrivatePolicy :: service:Action".into());
            }
        }
        assert!(
            build_problem_groups(&findings, run, &BTreeMap::new())
                .iter()
                .all(|group| group.kind != ReportProblemKind::IamPolicyPermissions)
        );
    }

    #[test]
    fn grouping_uses_selected_observations_and_is_backward_compatible() {
        let mut case = approved_case();
        let historical = build_beginner_master_report(&case, "run-1").unwrap();
        for finding in &mut case.findings {
            finding.title = "Changed in a later run".into();
            finding.last_seen_run_id = "run-2".into();
            finding.evidence.clear();
        }
        let retained = build_beginner_master_report(&case, "run-1").unwrap();
        assert_eq!(retained.problem_groups, historical.problem_groups);
        assert_eq!(retained.findings, historical.findings);
        let mut wire = serde_json::to_value(retained).unwrap();
        wire.as_object_mut().unwrap().remove("problem_groups");
        let old: crate::beginner_report::BeginnerMasterReport =
            serde_json::from_value(wire).unwrap();
        assert!(old.problem_groups.is_empty());
        assert_eq!(old.problem_findings().len(), 31);
    }

    #[test]
    fn standard_export_redacts_policy_labels_without_losing_group_membership() {
        let case = approved_case();
        let raw = build_beginner_master_report(&case, "run-1").unwrap();
        let redacted = crate::export::beginner_report_for_export(
            &case,
            "run-1",
            crate::export::RedactionProfile::Standard,
        )
        .unwrap();
        assert_eq!(redacted.findings.len(), 31);
        assert_eq!(redacted.problem_findings().len(), 13);
        for (before, after) in raw.problem_groups.iter().zip(&redacted.problem_groups) {
            assert_eq!(before.group_id, after.group_id);
            assert_eq!(before.finding_ids, after.finding_ids);
            assert_eq!(
                before.representative_finding_id,
                after.representative_finding_id
            );
        }
        let wire = serde_json::to_string(&redacted).unwrap();
        assert!(!wire.contains("PrivatePolicy"));
        assert!(!wire.contains("123456789012"));
        assert!(!wire.contains("private-one"));
        assert!(!wire.contains("private-two"));
    }

    #[test]
    fn password_policy_group_says_when_members_are_ordered_lower() {
        use crate::finding_narrative::{
            PASSWORD_COMPOSITION_ORDER_REASON, PASSWORD_EXPIRY_ORDER_REASON,
        };

        let case = approved_case();
        let report = build_beginner_master_report(&case, "run-1").unwrap();
        let run = &case.scan_runs[0];
        let original = report
            .problem_groups
            .iter()
            .find(|group| group.kind == ReportProblemKind::IamPasswordPolicy)
            .unwrap();
        assert_eq!(original.lower_priority_members, None);
        assert_eq!(
            original.next_step_english(),
            Some("Review the account's IAM password policy and address each failed setting.")
        );
        assert_eq!(
            original.next_step_zh_hant(),
            Some("檢查帳號的 IAM 密碼政策，並調整每項未通過的設定。")
        );
        assert_eq!(
            original.impact_english(),
            Some("Weak password settings increase the risk of unauthorized access to IAM users.")
        );
        assert_eq!(
            original.impact_zh_hant(),
            Some("較弱的密碼設定會增加 IAM 使用者遭未授權存取的風險。")
        );
        let group_id = original.group_id.clone();
        let representative = original.representative_finding_id.clone();
        let password_ids = original
            .finding_ids
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();

        let mut partial_findings = report.findings.clone();
        for finding in &mut partial_findings {
            if !password_ids.contains(&finding.finding_id) {
                continue;
            }
            let evidence = &finding.evidence_references[0];
            let reason = match (evidence.engine_id.as_str(), evidence.source_rule.as_deref()) {
                (
                    "prowler",
                    Some(
                        "iam_password_policy_uppercase"
                        | "iam_password_policy_lowercase"
                        | "iam_password_policy_number"
                        | "iam_password_policy_symbol",
                    ),
                ) => Some(PASSWORD_COMPOSITION_ORDER_REASON),
                (
                    "prowler",
                    Some("iam_password_policy_expires_passwords_within_90_days_or_less"),
                ) => Some(PASSWORD_EXPIRY_ORDER_REASON),
                (
                    "scoutsuite",
                    Some(
                        "iam-password-policy-no-expiration"
                        | "iam-password-policy-expiration-threshold",
                    ),
                ) => Some(PASSWORD_EXPIRY_ORDER_REASON),
                _ => None,
            };
            if let Some(reason) = reason {
                finding.priority_reasons.push(reason.to_owned());
            }
        }
        let partial = build_problem_groups(&partial_findings, run, &BTreeMap::new())
            .into_iter()
            .find(|group| group.kind == ReportProblemKind::IamPasswordPolicy)
            .unwrap();
        assert_eq!(
            partial.lower_priority_members,
            Some(LowerPriorityMembers::Partial)
        );
        assert_eq!(partial.group_id, group_id);
        assert_eq!(partial.representative_finding_id, representative);
        assert_eq!(
            partial.next_step_english(),
            Some(
                "Review the account's IAM password policy. Fix the failed length or reuse settings first; change the character-mix or expiry settings only if an audit you must pass still requires them."
            )
        );
        assert_eq!(
            partial.next_step_zh_hant(),
            Some(
                "檢查帳號的 IAM 密碼政策：先調整未通過的長度或重複使用設定；字元組成或到期設定，只有在必須通過的稽核仍要求時才需要變更。"
            )
        );
        assert_eq!(partial.impact_english(), original.impact_english());
        assert_eq!(partial.impact_zh_hant(), original.impact_zh_hant());
        let partial_wire = serde_json::to_value(&partial).unwrap();
        assert_eq!(partial_wire["lower_priority_members"], "partial");
        let mut without = partial_wire.clone();
        without
            .as_object_mut()
            .unwrap()
            .remove("lower_priority_members");
        let decoded: ReportProblemGroup = serde_json::from_value(without).unwrap();
        assert_eq!(decoded.lower_priority_members, None);

        let mut all_findings = report.findings.clone();
        for finding in &mut all_findings {
            if password_ids.contains(&finding.finding_id) {
                finding
                    .priority_reasons
                    .push(PASSWORD_COMPOSITION_ORDER_REASON.to_owned());
            }
        }
        let groups = build_problem_groups(&all_findings, run, &BTreeMap::new());
        let all = groups
            .iter()
            .find(|group| group.kind == ReportProblemKind::IamPasswordPolicy)
            .unwrap();
        assert_eq!(all.lower_priority_members, Some(LowerPriorityMembers::All));
        assert_eq!(all.group_id, group_id);
        assert_eq!(all.representative_finding_id, representative);
        assert_eq!(
            all.next_step_english(),
            Some(
                "Change these IAM password policy settings only if an audit you must pass still requires them; NIST SP 800-63B-4 says not to require character mixes or scheduled expiry."
            )
        );
        assert_eq!(
            all.next_step_zh_hant(),
            Some(
                "只有在必須通過的稽核仍要求時，才需要變更這些 IAM 密碼政策設定；NIST SP 800-63B-4 要求不要強制混合字元類型或定期到期。"
            )
        );
        assert_eq!(
            all.impact_english(),
            Some(
                "CIS AWS Foundations Benchmark v1.2.0 lists these settings; current guidance does not treat their absence as a weakness."
            )
        );
        assert_eq!(
            all.impact_zh_hant(),
            Some(
                "CIS AWS Foundations Benchmark v1.2.0 列出這些設定；現行指引不把缺少這些設定視為弱點。"
            )
        );
        assert!(groups.iter().all(|group| {
            group.kind == ReportProblemKind::IamPasswordPolicy
                || group.lower_priority_members.is_none()
        }));
        assert!(
            serde_json::to_value(original)
                .unwrap()
                .get("lower_priority_members")
                .is_none()
        );
        assert_eq!(
            serde_json::to_value(all).unwrap()["lower_priority_members"],
            "all"
        );
    }

    fn local_folder_case(engines: &[&str]) -> AssessmentCase {
        let mut case = aws_grouping_case();
        {
            let asset = &mut case.assets[0];
            asset.kind = AssetKind::FileSystem;
            asset.name = "local folder".into();
            asset.provider = None;
            asset.identifiers.clear();
            case.scan_runs[0].report_asset_snapshots[0].asset = asset.clone();
        }
        let template = case.scan_runs[0].engine_runs[0].clone();
        case.scan_runs[0].engine_runs = engines
            .iter()
            .map(|engine| {
                let mut task = template.clone();
                task.id = (*engine).into();
                task.engine_id = (*engine).into();
                task.asset_ids = vec!["localhost-asset".into()];
                task.raw_artifact_ids.clear();
                task
            })
            .collect();
        case
    }

    struct Record<'a> {
        id: &'a str,
        engine: &'a str,
        rule: &'a str,
        family: Option<FindingFamily>,
        severity: Severity,
        location: &'a str,
        version: Option<&'a str>,
        aliases: &'a [&'a str],
        cwes: &'a [&'a str],
        packages: &'a [&'a str],
        asset_id: &'a str,
        task_id: &'a str,
        expert: &'a str,
    }

    fn add_record(case: &mut AssessmentCase, record: Record<'_>) {
        let mut finding = frozen_finding(case, record.id, 50, record.severity);
        finding.family = record.family;
        finding.recommended_expert_type = record.expert.into();
        finding.asset_ids = vec![record.asset_id.into()];
        finding.tags = record
            .packages
            .iter()
            .map(|package| format!("package:{package}"))
            .collect();
        let evidence = &mut finding.evidence[0];
        evidence.engine_id = record.engine.into();
        evidence.engine_run_id = Some(record.task_id.into());
        evidence.source_rule = Some(record.rule.into());
        evidence.location = Some(record.location.into());
        let mut details = serde_json::Map::new();
        if let Some(version) = record.version {
            details.insert(
                "installed_version".into(),
                serde_json::Value::String(version.into()),
            );
        }
        if !record.aliases.is_empty() {
            details.insert("advisory_aliases".into(), serde_json::json!(record.aliases));
        }
        if !record.cwes.is_empty() {
            details.insert("cwe_ids".into(), serde_json::json!(record.cwes));
        }
        if !details.is_empty() {
            evidence.scanner_details =
                Some(serde_json::from_value(serde_json::Value::Object(details)).unwrap());
        }
        case.scan_runs[0]
            .engine_runs
            .iter_mut()
            .find(|task| task.id == record.task_id)
            .unwrap()
            .raw_artifact_ids
            .push(evidence.artifact_id.clone());
        let mut retained = observation(&finding, "run-1", Utc::now());
        retained.engine_ids = vec![record.engine.into()];
        retained.asset_ids = vec![record.asset_id.into()];
        case.finding_observations.push(retained);
        case.findings.push(finding);
    }

    fn add_dependency(
        case: &mut AssessmentCase,
        id: &str,
        engine: &str,
        rule: &str,
        package_at_version: (&str, &str),
        severity: Severity,
        aliases: &[&str],
    ) {
        let (package, version) = package_at_version;
        add_record(
            case,
            Record {
                id,
                engine,
                rule,
                family: Some(FindingFamily::VulnerableComponent),
                severity,
                location: if engine == "grype" {
                    "/requirements.txt"
                } else {
                    "requirements.txt:resource=package"
                },
                version: Some(version),
                aliases,
                cwes: &[],
                packages: &[package],
                asset_id: "localhost-asset",
                task_id: engine,
                expert: "Software supply-chain engineer",
            },
        );
    }

    pub(crate) fn demo_like_case() -> AssessmentCase {
        let mut case = local_folder_case(&["grype", "trivy", "semgrep", "gitleaks", "trufflehog"]);
        let dependencies = [
            (
                "pyyaml-grype",
                "grype",
                "GHSA-8q59-q68h-6hv4",
                "pyyaml",
                "5.3.1",
                Severity::Critical,
                "CVE-2020-14343",
            ),
            (
                "pyyaml-trivy",
                "trivy",
                "CVE-2020-14343",
                "pyyaml",
                "5.3.1",
                Severity::Critical,
                "GHSA-8q59-q68h-6hv4",
            ),
            (
                "requests-a-grype",
                "grype",
                "GHSA-9wx4-h78v-vm56",
                "requests",
                "2.31.0",
                Severity::Medium,
                "CVE-2024-35195",
            ),
            (
                "requests-a-trivy",
                "trivy",
                "CVE-2024-35195",
                "requests",
                "2.31.0",
                Severity::Medium,
                "GHSA-9wx4-h78v-vm56",
            ),
            (
                "requests-b-grype",
                "grype",
                "GHSA-9hjg-9r4m-mvj7",
                "requests",
                "2.31.0",
                Severity::Medium,
                "CVE-2024-47081",
            ),
            (
                "requests-b-trivy",
                "trivy",
                "CVE-2024-47081",
                "requests",
                "2.31.0",
                Severity::Medium,
                "GHSA-9hjg-9r4m-mvj7",
            ),
            (
                "requests-c-grype",
                "grype",
                "GHSA-gc5v-m9x4-r6x2",
                "requests",
                "2.31.0",
                Severity::Medium,
                "CVE-2026-25645",
            ),
            (
                "requests-c-trivy",
                "trivy",
                "CVE-2026-25645",
                "requests",
                "2.31.0",
                Severity::Medium,
                "GHSA-gc5v-m9x4-r6x2",
            ),
            (
                "flask-grype",
                "grype",
                "GHSA-68rp-wp8r-4726",
                "flask",
                "3.0.3",
                Severity::Low,
                "CVE-2026-27205",
            ),
            (
                "flask-trivy",
                "trivy",
                "CVE-2026-27205",
                "flask",
                "3.0.3",
                Severity::Low,
                "GHSA-68rp-wp8r-4726",
            ),
        ];
        for (id, engine, rule, package, version, severity, alias) in dependencies {
            add_dependency(
                &mut case,
                id,
                engine,
                rule,
                (package, version),
                severity,
                &[alias],
            );
        }
        for (id, rule, severity) in [
            (
                "secret-semgrep-1",
                "ai-security-scanner.generic.private-key",
                Severity::High,
            ),
            (
                "secret-semgrep-2",
                "generic.secrets.security.detected-private-key.detected-private-key",
                Severity::High,
            ),
            (
                "secret-semgrep-3",
                "generic.secrets.gitleaks.private-key.private-key",
                Severity::Informational,
            ),
        ] {
            add_record(
                &mut case,
                Record {
                    id,
                    engine: "semgrep",
                    rule,
                    family: Some(FindingFamily::SourceCode),
                    severity,
                    location: "deploy/deploy_key:line=1:column=1",
                    version: None,
                    aliases: &[],
                    cwes: &["CWE-798"],
                    packages: &[],
                    asset_id: "localhost-asset",
                    task_id: "semgrep",
                    expert: "Application security engineer",
                },
            );
        }
        add_record(
            &mut case,
            Record {
                id: "secret-gitleaks",
                engine: "gitleaks",
                rule: "private-key",
                family: Some(FindingFamily::Secret),
                severity: Severity::Unknown,
                location: "deploy/deploy_key:line=1:column=1",
                version: None,
                aliases: &[],
                cwes: &[],
                packages: &[],
                asset_id: "localhost-asset",
                task_id: "gitleaks",
                expert: "Secrets-response specialist",
            },
        );
        add_record(
            &mut case,
            Record {
                id: "secret-trufflehog",
                engine: "trufflehog",
                rule: "trufflehog:PrivateKey",
                family: Some(FindingFamily::Secret),
                severity: Severity::Unknown,
                location: "deploy/deploy_key:line=1",
                version: None,
                aliases: &[],
                cwes: &[],
                packages: &[],
                asset_id: "localhost-asset",
                task_id: "trufflehog",
                expert: "Secrets-response specialist",
            },
        );
        for index in 1..=5 {
            add_record(
                &mut case,
                Record {
                    id: &format!("code-{index}"),
                    engine: "semgrep",
                    rule: &format!("cwe-78-{index}"),
                    family: Some(FindingFamily::SourceCode),
                    severity: Severity::Medium,
                    location: "app.py:line=19",
                    version: None,
                    aliases: &[],
                    cwes: &["CWE-78"],
                    packages: &[],
                    asset_id: "localhost-asset",
                    task_id: "semgrep",
                    expert: "Application security engineer",
                },
            );
        }
        for index in 1..=6 {
            add_record(
                &mut case,
                Record {
                    id: &format!("other-{index}"),
                    engine: "semgrep",
                    rule: &format!("other-{index}"),
                    family: Some(FindingFamily::NetworkExposure),
                    severity: Severity::Low,
                    location: &format!("notes.txt:line={index}"),
                    version: None,
                    aliases: &[],
                    cwes: &[],
                    packages: &[],
                    asset_id: "localhost-asset",
                    task_id: "semgrep",
                    expert: "Network security engineer",
                },
            );
        }
        case
    }

    pub(crate) fn package_name_redaction_case() -> AssessmentCase {
        let mut case = local_folder_case(&["grype", "trivy"]);
        case.profile.organization_name = "AcmeCorp".into();
        add_dependency(
            &mut case,
            "left",
            "grype",
            "GHSA-abcd-efgh-ijkl",
            ("acmecorp-lib", "acmecorp-1.2.3"),
            Severity::Medium,
            &["CVE-2024-1111"],
        );
        add_dependency(
            &mut case,
            "right",
            "trivy",
            "CVE-2024-1111",
            ("acmecorp-lib", "acmecorp-1.2.3"),
            Severity::Low,
            &["GHSA-abcd-efgh-ijkl"],
        );
        case
    }

    fn covered_ids(step: &crate::beginner_report::BeginnerNextStep) -> BTreeSet<String> {
        step.finding_id
            .iter()
            .chain(step.also_resolves.iter())
            .cloned()
            .collect()
    }

    #[test]
    fn aws_password_policy_group_id_matches_the_prechange_digest() {
        let report = build_beginner_master_report(&approved_case(), "run-1").unwrap();
        let group = report
            .problem_groups
            .iter()
            .find(|group| group.kind == ReportProblemKind::IamPasswordPolicy)
            .unwrap();
        assert_eq!(
            group.group_id,
            "report-problem:f9f32d96fa19a8949960adaf32d9c81122a3348464b84f7730db1edf1c6be7a6"
        );
        assert_eq!(group.rule_version, RULE_VERSION);
        assert!(group.package_name.is_none());
        assert!(group.advisory_ids.is_empty());
    }

    #[test]
    fn demo_like_report_collapses_26_findings_to_17_problem_cards() {
        let report = build_beginner_master_report(&demo_like_case(), "run-1").unwrap();
        assert_eq!(report.findings.len(), 26);
        assert_eq!(report.problem_findings().len(), 17);
        let dependencies = report
            .problem_groups
            .iter()
            .filter(|group| group.kind == ReportProblemKind::VulnerableDependency)
            .collect::<Vec<_>>();
        assert_eq!(dependencies.len(), 5);
        assert!(dependencies.iter().all(|group| {
            group.rule_version == DEPENDENCY_RULE_VERSION
                && group.finding_ids.len() == 2
                && group.next_step_english().is_none()
                && group.impact_english().is_none()
        }));
        let pyyaml = dependencies
            .iter()
            .find(|group| group.package_name.as_deref() == Some("pyyaml"))
            .unwrap();
        assert_eq!(
            pyyaml.title_english(),
            "Vulnerable package pyyaml 5.3.1 (CVE-2020-14343 / GHSA-8q59-q68h-6hv4)"
        );
        assert_eq!(
            pyyaml.title_zh_hant(),
            "有已知弱點的套件 pyyaml 5.3.1（CVE-2020-14343 / GHSA-8q59-q68h-6hv4）"
        );
        assert_eq!(
            report
                .findings
                .iter()
                .find(|finding| finding.finding_id == pyyaml.representative_finding_id)
                .unwrap()
                .severity,
            Severity::Critical
        );
        let requests = dependencies
            .iter()
            .filter(|group| group.package_name.as_deref() == Some("requests"))
            .map(|group| group.title_english())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            requests,
            [
                "Vulnerable package requests 2.31.0 (CVE-2024-35195 / GHSA-9wx4-h78v-vm56)",
                "Vulnerable package requests 2.31.0 (CVE-2024-47081 / GHSA-9hjg-9r4m-mvj7)",
                "Vulnerable package requests 2.31.0 (CVE-2026-25645 / GHSA-gc5v-m9x4-r6x2)",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect()
        );
        let flask = dependencies
            .iter()
            .find(|group| group.package_name.as_deref() == Some("flask"))
            .unwrap();
        assert_eq!(
            flask.title_english(),
            "Vulnerable package flask 3.0.3 (CVE-2026-27205 / GHSA-68rp-wp8r-4726)"
        );
        assert_eq!(
            report
                .findings
                .iter()
                .find(|finding| finding.finding_id == flask.representative_finding_id)
                .unwrap()
                .severity,
            Severity::Low
        );
        let secret = report
            .problem_groups
            .iter()
            .find(|group| group.kind == ReportProblemKind::ExposedSecret)
            .unwrap();
        assert_eq!(secret.finding_ids.len(), 5);
        assert_eq!(secret.rule_version, SECRET_RULE_VERSION);
        assert_eq!(secret.title_english(), "Secret found in a file");
        assert_eq!(secret.title_zh_hant(), "檔案中發現機密");
        assert_eq!(
            secret.next_step_english(),
            Some(EXPOSED_SECRET_NEXT_STEP_ENGLISH)
        );
        assert_eq!(
            secret.next_step_zh_hant(),
            Some(EXPOSED_SECRET_NEXT_STEP_ZH_HANT)
        );
        assert!(secret.impact_english().is_none());
        assert!(!secret.title_english().contains("deploy"));
        let secret_ids = secret.finding_ids.iter().cloned().collect::<BTreeSet<_>>();
        assert_eq!(
            secret_ids,
            [
                "secret-gitleaks",
                "secret-semgrep-1",
                "secret-semgrep-2",
                "secret-semgrep-3",
                "secret-trufflehog",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect()
        );
        assert_eq!(
            report
                .findings
                .iter()
                .find(|finding| finding.finding_id == secret.representative_finding_id)
                .unwrap()
                .severity,
            Severity::High
        );
        let secret_step = report
            .next_steps
            .iter()
            .find(|step| step.family == Some(FindingFamily::Secret))
            .unwrap();
        assert_eq!(covered_ids(secret_step), secret_ids);
        assert_eq!(
            secret_step.recommended_expert_type.as_deref(),
            Some("Secrets-response specialist")
        );
        assert_eq!(
            finding_next_action_english(&secret_step.action, secret_step.family, None, false),
            EXPOSED_SECRET_NEXT_STEP_ENGLISH
        );
        let code_step = report
            .next_steps
            .iter()
            .find(|step| step.family == Some(FindingFamily::SourceCode))
            .unwrap();
        assert_eq!(
            covered_ids(code_step),
            (1..=5)
                .map(|index| format!("code-{index}"))
                .collect::<BTreeSet<_>>()
        );
        assert!(covered_ids(code_step).is_disjoint(&secret_ids));
        let rendered_count = |step: &crate::beginner_report::BeginnerNextStep| {
            step.also_resolves
                .iter()
                .chain(step.finding_id.iter())
                .map(|id| {
                    report
                        .problem_group(id)
                        .map(|group| group.group_id.clone())
                        .unwrap_or_else(|| id.clone())
                })
                .collect::<BTreeSet<_>>()
                .len()
        };
        // The five secret findings are one revoke step. The five CWE-78
        // findings stay on the code-change step, each as its own problem.
        assert_eq!(rendered_count(secret_step), 1);
        assert_eq!(rendered_count(code_step), 5);
        assert_eq!(
            finding_next_action_english(&code_step.action, code_step.family, None, false),
            "Change the code to remove the reported unsafe pattern."
        );
        let code_rules = report
            .problem_findings()
            .iter()
            .filter(|finding| finding.finding_id.starts_with("code-"))
            .count();
        assert_eq!(code_rules, 5);
    }

    fn pair_case(left_alias: &[&str], right_alias: &[&str]) -> AssessmentCase {
        let mut case = local_folder_case(&["grype", "trivy"]);
        add_dependency(
            &mut case,
            "left",
            "grype",
            "GHSA-8q59-q68h-6hv4",
            ("pyyaml", "5.3.1"),
            Severity::High,
            left_alias,
        );
        add_dependency(
            &mut case,
            "right",
            "trivy",
            "CVE-2020-14343",
            ("pyyaml", "5.3.1"),
            Severity::Medium,
            right_alias,
        );
        case
    }

    #[test]
    fn one_reported_alias_on_either_side_joins_the_package() {
        let grype_only =
            build_beginner_master_report(&pair_case(&["CVE-2020-14343"], &[]), "run-1").unwrap();
        let trivy_only =
            build_beginner_master_report(&pair_case(&[], &["GHSA-8q59-q68h-6hv4"]), "run-1")
                .unwrap();
        for report in [&grype_only, &trivy_only] {
            assert_eq!(report.problem_groups.len(), 1);
            assert_eq!(
                report.problem_groups[0].kind,
                ReportProblemKind::VulnerableDependency
            );
            assert_eq!(report.problem_groups[0].finding_ids.len(), 2);
        }
    }

    #[test]
    fn advisory_ids_join_transitively_inside_one_package_version() {
        let mut case = local_folder_case(&["grype", "trivy", "semgrep"]);
        add_dependency(
            &mut case,
            "a",
            "grype",
            "GHSA-aaaa-bbbb-ccc1",
            ("pyyaml", "5.3.1"),
            Severity::Low,
            &["CVE-2024-1001"],
        );
        add_dependency(
            &mut case,
            "b",
            "trivy",
            "CVE-2024-1001",
            ("pyyaml", "5.3.1"),
            Severity::Low,
            &["GHSA-aaaa-bbbb-ccc2"],
        );
        add_dependency(
            &mut case,
            "c",
            "semgrep",
            "GHSA-aaaa-bbbb-ccc2",
            ("pyyaml", "5.3.1"),
            Severity::Medium,
            &["CVE-2024-1002"],
        );
        let report = build_beginner_master_report(&case, "run-1").unwrap();
        assert_eq!(report.problem_groups.len(), 1);
        assert_eq!(report.problem_groups[0].finding_ids.len(), 3);
        // CVE-2024-1002 is only an alias on the third finding, so the card
        // lists the members' own advisory ids.
        assert_eq!(
            report.problem_groups[0].advisory_ids,
            vec![
                "CVE-2024-1001".to_owned(),
                "GHSA-aaaa-bbbb-ccc1".to_owned(),
                "GHSA-aaaa-bbbb-ccc2".to_owned(),
            ]
        );
    }

    #[test]
    fn dependency_cards_stay_separate_without_the_same_package_version_and_alias() {
        let mut case = local_folder_case(&["grype", "trivy"]);
        add_dependency(
            &mut case,
            "base",
            "grype",
            "GHSA-8q59-q68h-6hv4",
            ("pyyaml", "5.3.1"),
            Severity::High,
            &["CVE-2020-14343"],
        );
        add_dependency(
            &mut case,
            "other-version",
            "trivy",
            "CVE-2020-14343",
            ("pyyaml", "5.4"),
            Severity::High,
            &["GHSA-8q59-q68h-6hv4"],
        );
        add_dependency(
            &mut case,
            "other-package",
            "trivy",
            "CVE-2020-14343",
            ("yaml", "5.3.1"),
            Severity::High,
            &[],
        );
        add_dependency(
            &mut case,
            "unrelated",
            "grype",
            "GHSA-zzzz-yyyy-xxxx",
            ("pyyaml", "5.3.1"),
            Severity::Low,
            &[],
        );
        add_record(
            &mut case,
            Record {
                id: "no-version",
                engine: "trivy",
                rule: "CVE-2020-14343",
                family: Some(FindingFamily::VulnerableComponent),
                severity: Severity::High,
                location: "requirements.txt",
                version: None,
                aliases: &["GHSA-8q59-q68h-6hv4"],
                cwes: &[],
                packages: &["pyyaml"],
                asset_id: "localhost-asset",
                task_id: "trivy",
                expert: "Software supply-chain engineer",
            },
        );
        add_record(
            &mut case,
            Record {
                id: "no-package",
                engine: "trivy",
                rule: "CVE-2020-14343",
                family: Some(FindingFamily::VulnerableComponent),
                severity: Severity::High,
                location: "requirements.txt",
                version: Some("5.3.1"),
                aliases: &["GHSA-8q59-q68h-6hv4"],
                cwes: &[],
                packages: &[],
                asset_id: "localhost-asset",
                task_id: "trivy",
                expert: "Software supply-chain engineer",
            },
        );
        add_record(
            &mut case,
            Record {
                id: "two-packages",
                engine: "grype",
                rule: "GHSA-8q59-q68h-6hv4",
                family: Some(FindingFamily::VulnerableComponent),
                severity: Severity::High,
                location: "/requirements.txt",
                version: Some("5.3.1"),
                aliases: &["CVE-2020-14343"],
                cwes: &[],
                packages: &["pyyaml", "requests"],
                asset_id: "localhost-asset",
                task_id: "grype",
                expert: "Software supply-chain engineer",
            },
        );
        let report = build_beginner_master_report(&case, "run-1").unwrap();
        assert!(
            report
                .problem_groups
                .iter()
                .all(|group| group.kind != ReportProblemKind::VulnerableDependency)
        );

        let mut other_asset = pair_case(&["CVE-2020-14343"], &[]);
        let mut asset = other_asset.assets[0].clone();
        asset.id = "other-asset".into();
        other_asset.scan_runs[0]
            .report_asset_snapshots
            .push(crate::domain::ReportAssetSnapshot {
                asset: asset.clone(),
                disposition: crate::domain::ReportAssetDisposition::RequestedForScan,
            });
        other_asset.assets.push(asset);
        let mut task = other_asset.scan_runs[0].engine_runs[0].clone();
        task.id = "trivy-other".into();
        task.engine_id = "trivy".into();
        task.asset_ids = vec!["other-asset".into()];
        task.raw_artifact_ids.clear();
        other_asset.scan_runs[0].engine_runs.push(task);
        add_record(
            &mut other_asset,
            Record {
                id: "other-asset-finding",
                engine: "trivy",
                rule: "CVE-2020-14343",
                family: Some(FindingFamily::VulnerableComponent),
                severity: Severity::Critical,
                location: "requirements.txt",
                version: Some("5.3.1"),
                aliases: &["GHSA-8q59-q68h-6hv4"],
                cwes: &[],
                packages: &["pyyaml"],
                asset_id: "other-asset",
                task_id: "trivy-other",
                expert: "Software supply-chain engineer",
            },
        );
        let report = build_beginner_master_report(&other_asset, "run-1").unwrap();
        assert_eq!(report.problem_groups.len(), 1);
        assert_eq!(report.problem_groups[0].target_asset_id, "localhost-asset");
        assert!(
            !report.problem_groups[0]
                .finding_ids
                .iter()
                .any(|id| id == "other-asset-finding")
        );
    }

    #[test]
    fn unfrozen_evidence_and_legacy_snapshots_stay_separate() {
        let mut case = pair_case(&["CVE-2020-14343"], &["GHSA-8q59-q68h-6hv4"]);
        let grouped = build_beginner_master_report(&case, "run-1").unwrap();
        assert_eq!(grouped.problem_groups.len(), 1);
        let mut findings = grouped.findings.clone();
        for finding in &mut findings {
            finding.evidence_references[0].details_frozen = false;
        }
        let map = findings
            .iter()
            .map(|finding| (finding.finding_id.clone(), "pyyaml".into()))
            .collect::<BTreeMap<_, _>>();
        assert!(
            build_problem_groups(&findings, &case.scan_runs[0], &map)
                .iter()
                .all(|group| group.kind != ReportProblemKind::VulnerableDependency)
        );

        for observation in &mut case.finding_observations {
            observation.finding_snapshot = None;
        }
        let legacy = build_beginner_master_report(&case, "run-1").unwrap();
        assert!(legacy.problem_groups.is_empty());
        assert!(legacy.findings.iter().all(|finding| {
            finding.snapshot_source == FindingSnapshotSource::CurrentCanonicalLegacyFallback
        }));
    }

    #[test]
    fn secret_cards_share_one_normalized_file_and_line() {
        let mut case = local_folder_case(&["semgrep", "gitleaks", "trufflehog", "trivy"]);
        for (id, engine, location) in [
            ("slash", "semgrep", "/deploy/deploy_key:line=1"),
            ("dot", "gitleaks", "./deploy/deploy_key:line=1:column=1"),
            ("windows", "trufflehog", "deploy\\deploy_key:line=1"),
        ] {
            add_record(
                &mut case,
                Record {
                    id,
                    engine,
                    rule: id,
                    family: if engine == "semgrep" {
                        Some(FindingFamily::SourceCode)
                    } else {
                        Some(FindingFamily::Secret)
                    },
                    severity: Severity::High,
                    location,
                    version: None,
                    aliases: &[],
                    cwes: if engine == "semgrep" {
                        &["CWE-798"]
                    } else {
                        &[]
                    },
                    packages: &[],
                    asset_id: "localhost-asset",
                    task_id: engine,
                    expert: "Secrets-response specialist",
                },
            );
        }
        add_record(
            &mut case,
            Record {
                id: "other-line",
                engine: "gitleaks",
                rule: "other-line",
                family: Some(FindingFamily::Secret),
                severity: Severity::High,
                location: "deploy/deploy_key:line=2",
                version: None,
                aliases: &[],
                cwes: &[],
                packages: &[],
                asset_id: "localhost-asset",
                task_id: "gitleaks",
                expert: "Secrets-response specialist",
            },
        );
        add_record(
            &mut case,
            Record {
                id: "other-file",
                engine: "gitleaks",
                rule: "other-file",
                family: Some(FindingFamily::Secret),
                severity: Severity::High,
                location: "other/key:line=1",
                version: None,
                aliases: &[],
                cwes: &[],
                packages: &[],
                asset_id: "localhost-asset",
                task_id: "gitleaks",
                expert: "Secrets-response specialist",
            },
        );
        add_record(
            &mut case,
            Record {
                id: "command-injection",
                engine: "semgrep",
                rule: "cwe-78",
                family: Some(FindingFamily::SourceCode),
                severity: Severity::High,
                location: "deploy/deploy_key:line=1",
                version: None,
                aliases: &[],
                cwes: &["CWE-78"],
                packages: &[],
                asset_id: "localhost-asset",
                task_id: "semgrep",
                expert: "Application security engineer",
            },
        );
        add_record(
            &mut case,
            Record {
                id: "package-cwe",
                engine: "trivy",
                rule: "CVE-2020-14343",
                family: Some(FindingFamily::VulnerableComponent),
                severity: Severity::High,
                location: "deploy/deploy_key:line=1",
                version: Some("5.3.1"),
                aliases: &[],
                cwes: &["CWE-798"],
                packages: &["pyyaml"],
                asset_id: "localhost-asset",
                task_id: "trivy",
                expert: "Software supply-chain engineer",
            },
        );
        let report = build_beginner_master_report(&case, "run-1").unwrap();
        let secrets = report
            .problem_groups
            .iter()
            .filter(|group| group.kind == ReportProblemKind::ExposedSecret)
            .collect::<Vec<_>>();
        assert_eq!(secrets.len(), 1);
        assert_eq!(
            secrets[0]
                .finding_ids
                .iter()
                .cloned()
                .collect::<BTreeSet<_>>(),
            ["dot", "slash", "windows"]
                .into_iter()
                .map(str::to_owned)
                .collect()
        );
        assert_eq!(
            secrets[0].next_step_english(),
            Some(EXPOSED_SECRET_NEXT_STEP_ENGLISH)
        );
        assert_eq!(
            secrets[0].next_step_zh_hant(),
            Some(EXPOSED_SECRET_NEXT_STEP_ZH_HANT)
        );
        assert!(report.problem_groups.iter().all(|group| {
            group.kind == ReportProblemKind::ExposedSecret
                && !group.finding_ids.iter().any(|id| {
                    matches!(
                        id.as_str(),
                        "other-line" | "other-file" | "command-injection" | "package-cwe"
                    )
                })
        }));
        assert_eq!(
            report
                .findings
                .iter()
                .find(|finding| finding.finding_id == secrets[0].representative_finding_id)
                .unwrap()
                .severity,
            Severity::High
        );
    }
}
