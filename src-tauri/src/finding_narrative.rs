//! Writes the sentences this product says about a finding, in the reader's
//! language, for the shared HTML report.
//!
//! The findings pane composes these in TypeScript (`src/findingNarrative.ts`).
//! The report is written here because it is produced as a file, not rendered,
//! so the same sentences exist twice. That is deliberate and guarded: the
//! Chinese in the two files is pinned against each other by
//! `tests/frontend/findingNarrativeParity.test.ts`, which reads both and fails
//! on any wording that appears in one and not the other. Two readers being told
//! different things about the same finding is the failure that matters, and
//! only a test that reads both sides can see it.
//!
//! Rules match the TypeScript exactly:
//!
//!  - English and Chinese use the same structured inputs and normalize legacy
//!    stored wording to the current report contract.
//!  - A finding with no code keeps that prose. Untranslated beats blank.
//!  - The engine's own title is never restated in another language.

use crate::domain::{
    AwsIamPolicyFindingDetails, AwsIamPolicySource, BenchmarkReference, ConfidenceBasisCode,
    ContextFactor, FindingFamily, Severity, SeverityBasisCode,
};

/// The direct possible impact for each finding family.
fn consequence(family: FindingFamily) -> &'static str {
    match family {
        FindingFamily::CloudPosture => "雲端資源或資料可能遭到未預期的存取、變更或使用",
        FindingFamily::CloudIdentity => "某個身分可能擁有超出其角色所需的操作權限",
        FindingFamily::Microsoft365 => "Microsoft 365 的身分、郵件、檔案或管理設定的保護可能不足",
        FindingFamily::NetworkExposure => "可從網際網路連線的服務可能暴露非預期的功能或已知弱點",
        FindingFamily::SourceCode | FindingFamily::Secret => {
            "原始碼或憑證可能導致未授權存取或不安全的程式行為"
        }
        FindingFamily::InfrastructureAsCode => "之後部署出來的基礎架構會沿用這個不安全的設定",
        FindingFamily::VulnerableComponent => "容器或軟體元件可能讓工作負載暴露於已知弱點",
        FindingFamily::Kubernetes => "Kubernetes 叢集或工作負載的隔離或管理保護可能不足",
        FindingFamily::ModelBehavior => "這個模型端點可能會產生它原本應該拒絕的輸出",
        FindingFamily::McpSecret => "MCP 設定中的憑證可能被取得設定檔的人用來未授權存取服務",
        FindingFamily::McpConfiguration => "MCP 伺服器程序或工具可能取得超出其用途所需的本機能力",
    }
}

fn consequence_english(family: FindingFamily) -> &'static str {
    match family {
        FindingFamily::CloudPosture => {
            "Cloud resources or data may be exposed, changed, or used beyond the organization's intent"
        }
        FindingFamily::CloudIdentity => {
            "An identity may be able to perform broader actions than its role requires"
        }
        FindingFamily::Microsoft365 => {
            "Microsoft 365 identities, messages, files, or administrative settings may have weaker protection"
        }
        FindingFamily::NetworkExposure => {
            "An internet-reachable service may expose unexpected functionality or a known weakness"
        }
        FindingFamily::SourceCode | FindingFamily::Secret => {
            "Source code or credentials may permit unauthorized access or unsafe application behavior"
        }
        FindingFamily::InfrastructureAsCode => {
            "Deployed infrastructure may inherit the reported insecure configuration"
        }
        FindingFamily::VulnerableComponent => {
            "A container or software component may expose the workload to a known weakness"
        }
        FindingFamily::Kubernetes => {
            "The Kubernetes cluster or workload may have reduced isolation or administrative protection"
        }
        FindingFamily::ModelBehavior => {
            "The model endpoint may produce output it is supposed to refuse"
        }
        FindingFamily::McpSecret => {
            "A credential embedded in MCP configuration may let anyone who obtains that file access the service without authorization"
        }
        FindingFamily::McpConfiguration => {
            "An MCP server process or tool may receive broader local capabilities than its purpose requires"
        }
    }
}

/// The full next-step sentence for an exposed credential, including the period.
pub(crate) const EXPOSED_SECRET_NEXT_STEP_ENGLISH: &str = "Revoke and rotate the exposed credential, then remove it from the source and every retained history entry.";

/// The Traditional Chinese form of [`EXPOSED_SECRET_NEXT_STEP_ENGLISH`].
pub(crate) const EXPOSED_SECRET_NEXT_STEP_ZH_HANT: &str =
    "先撤銷並輪替這組已外洩的憑證，再從原始碼以及仍保留它的歷史紀錄中移除。";

/// The direct recommended action for each finding family.
///
/// `Secret` departs from `SourceCode` even though they share a consequence. A
/// leaked credential stays valid until it is revoked, so sending the reader to
/// a permissions screen first leaves it valid for exactly that long.
fn remedy(family: FindingFamily) -> &'static str {
    match family {
        FindingFamily::CloudPosture => "調整這項檢查所指出的雲端設定或政策",
        FindingFamily::CloudIdentity => "改用只授予該身分角色所需操作的較小範圍政策",
        FindingFamily::Microsoft365 => "調整這項控制項所檢查的 Microsoft 365 租用戶設定",
        // Used by Nuclei and Greenbone vulnerability findings. Reachability
        // inventory from Naabu/httpx takes the exposure-observation path and
        // never reads this clause. A rated finding whose only backing check
        // did not complete takes the confirm-first action and also never
        // reads this clause.
        FindingFamily::NetworkExposure => "調整這項檢查所指出的服務或設定",
        FindingFamily::SourceCode => "修改程式碼以移除回報的不安全寫法",
        FindingFamily::Secret => EXPOSED_SECRET_NEXT_STEP_ZH_HANT
            .strip_suffix('。')
            .expect("exposed-secret next step ends with an ideographic full stop"),
        FindingFamily::InfrastructureAsCode => {
            "修改基礎架構即程式碼的範本，讓重新部署不會再還原這個設定"
        }
        FindingFamily::VulnerableComponent => {
            "將受影響的元件升級到已修正的版本，或記錄目前無法升級的原因"
        }
        FindingFamily::Kubernetes => "調整這項檢查所指出的工作負載或叢集設定",
        FindingFamily::ModelBehavior => {
            "重現這個探測項目，判斷這些回覆是否確實違反該端點的使用政策；若是，請在模型之前或之後加上防護措施"
        }
        FindingFamily::McpSecret => {
            "先撤銷並輪替這組憑證，再從 MCP 設定以及仍保留它的歷史紀錄中移除"
        }
        FindingFamily::McpConfiguration => {
            "移除 MCP 設定中不必要的權限與危險命令旗標，只保留伺服器用途確實需要的能力"
        }
    }
}

fn remedy_english(family: FindingFamily) -> &'static str {
    match family {
        FindingFamily::CloudPosture => "Correct the cloud setting or policy named by this check",
        FindingFamily::CloudIdentity => {
            "Replace the affected policy with a narrower policy that grants only the actions the identity's role requires"
        }
        FindingFamily::Microsoft365 => {
            "Correct the Microsoft 365 tenant setting named by this control"
        }
        FindingFamily::NetworkExposure => {
            "Correct the service or configuration named by this check"
        }
        FindingFamily::SourceCode => "Change the code to remove the reported unsafe pattern",
        FindingFamily::Secret => EXPOSED_SECRET_NEXT_STEP_ENGLISH
            .strip_suffix('.')
            .expect("exposed-secret next step ends with a period"),
        FindingFamily::InfrastructureAsCode => {
            "Correct the infrastructure-as-code template so redeployment does not restore the insecure setting"
        }
        FindingFamily::VulnerableComponent => {
            "Upgrade the affected component to a fixed version; if none is available, record the blocker and track the fix"
        }
        FindingFamily::Kubernetes => "Correct the workload or cluster setting named by this check",
        FindingFamily::ModelBehavior => {
            "Reproduce the probe, decide whether those replies actually breach this endpoint's usage policy, and if so add a guardrail in front of or behind the model"
        }
        FindingFamily::McpSecret => {
            "Revoke and rotate the credential, then remove it from the MCP configuration and every retained history entry"
        }
        FindingFamily::McpConfiguration => {
            "Remove unnecessary permissions and dangerous command flags from the MCP configuration, leaving only the capabilities the server's purpose requires"
        }
    }
}

/// The English clause retained for historical findings whose product-derived
/// severity was frozen before missing scanner ratings began staying Unknown.
///
/// Lives here rather than in the adapter that prints it because two sentences
/// are built from it -- the summary and the priority reason -- and the reader's
/// language is derived by recognising this exact text. A second copy in the
/// adapter would be a second thing to keep in step, and drift would show up as
/// a silently untranslated reason rather than as a failure.
pub fn basis_english(code: SeverityBasisCode) -> &'static str {
    match code {
        SeverityBasisCode::OpenPort => "an open port observation rather than a defect",
        SeverityBasisCode::ReachableHttpService => {
            "a reachable HTTP service observation rather than a defect"
        }
        SeverityBasisCode::SecretPatternMatch => "a secret pattern match in scanned source",
        SeverityBasisCode::UnverifiedCredentialDetector => "a credential detector match",
        SeverityBasisCode::IacPolicyCheck => {
            "a failed infrastructure-as-code policy check, rated flat because \
             Checkov publishes no per-check severity offline"
        }
        SeverityBasisCode::CisKubernetesBenchmark => "a failed CIS Kubernetes Benchmark check",
        SeverityBasisCode::CloudControlQuery => {
            "a failed IAM control from this product's own fixed query"
        }
        SeverityBasisCode::CloudsplainingIamPolicyFinding => {
            "an IAM policy finding Cloudsplaining did not rate"
        }
        SeverityBasisCode::UnratedVulnerabilityTestAlarm => {
            "a Greenbone vulnerability-test alarm whose pinned feed entry carries no parseable severity vector"
        }
        SeverityBasisCode::AdversarialProbeFailureRate => {
            "a count of adversarial probe attempts a garak detector judged as failures, which garak publishes without a severity"
        }
    }
}

/// Every basis code, so a new one cannot be added without being translated.
pub const ALL_SEVERITY_BASIS_CODES: [SeverityBasisCode; 10] = [
    SeverityBasisCode::OpenPort,
    SeverityBasisCode::ReachableHttpService,
    SeverityBasisCode::SecretPatternMatch,
    SeverityBasisCode::UnverifiedCredentialDetector,
    SeverityBasisCode::IacPolicyCheck,
    SeverityBasisCode::CisKubernetesBenchmark,
    SeverityBasisCode::CloudControlQuery,
    SeverityBasisCode::CloudsplainingIamPolicyFinding,
    SeverityBasisCode::UnratedVulnerabilityTestAlarm,
    SeverityBasisCode::AdversarialProbeFailureRate,
];

/// The canonical English clause explaining why this product assigned a
/// confidence when the engine did not provide one.
pub fn confidence_basis_english(code: ConfidenceBasisCode) -> &'static str {
    match code {
        ConfidenceBasisCode::DeterministicPolicyEvaluation => {
            "a deterministic policy or configuration evaluation"
        }
        ConfidenceBasisCode::AdvisoryVersionMatch => {
            "an installed-version match against a published advisory range"
        }
        ConfidenceBasisCode::UnverifiedPatternOrDetectorMatch => "a pattern or detector match",
        ConfidenceBasisCode::ObservedResponse => "a response this product observed directly",
        ConfidenceBasisCode::TemplateMatcher => "a template matcher firing on the assessed target",
        ConfidenceBasisCode::MissingDetectionQualityScore => {
            "the absence of a detection-quality score in the engine result"
        }
    }
}

/// The Traditional Chinese form of [`confidence_basis_english`].
pub fn confidence_basis_zh_hant(code: ConfidenceBasisCode) -> &'static str {
    match code {
        ConfidenceBasisCode::DeterministicPolicyEvaluation => "確定性的政策或設定評估結果",
        ConfidenceBasisCode::AdvisoryVersionMatch => "已安裝版本符合已發布公告的受影響範圍",
        ConfidenceBasisCode::UnverifiedPatternOrDetectorMatch => "樣式或偵測器比對結果",
        ConfidenceBasisCode::ObservedResponse => "本產品直接觀察到的回應",
        ConfidenceBasisCode::TemplateMatcher => "範本比對器在受評估目標上觸發",
        ConfidenceBasisCode::MissingDetectionQualityScore => "引擎結果中未提供偵測品質分數",
    }
}

/// Every confidence basis code, so a new one cannot be added without both
/// reader-facing forms.
pub const ALL_CONFIDENCE_BASIS_CODES: [ConfidenceBasisCode; 6] = [
    ConfidenceBasisCode::DeterministicPolicyEvaluation,
    ConfidenceBasisCode::AdvisoryVersionMatch,
    ConfidenceBasisCode::UnverifiedPatternOrDetectorMatch,
    ConfidenceBasisCode::ObservedResponse,
    ConfidenceBasisCode::TemplateMatcher,
    ConfidenceBasisCode::MissingDetectionQualityScore,
];

fn source_confidence(priority_reasons: &[String]) -> Option<&str> {
    priority_reasons
        .iter()
        .find_map(|reason| reason.trim().strip_prefix("Source confidence: "))
        .filter(|source| !source.is_empty())
}

pub fn confidence_presentation_english(
    confidence_label: &str,
    confidence_basis_code: Option<ConfidenceBasisCode>,
    priority_reasons: &[String],
) -> String {
    if let Some(code) = confidence_basis_code {
        if code == ConfidenceBasisCode::MissingDetectionQualityScore {
            return format!("{confidence_label} — scanner did not report detection quality");
        }
        return format!(
            "{confidence_label} — this product's rating from {}",
            confidence_basis_english(code)
        );
    }
    source_confidence(priority_reasons).map_or_else(
        || confidence_label.to_owned(),
        |source| format!("{confidence_label} — engine rating: {source}"),
    )
}

pub fn confidence_presentation_zh_hant(
    confidence_label: &str,
    confidence_basis_code: Option<ConfidenceBasisCode>,
    priority_reasons: &[String],
) -> String {
    if let Some(code) = confidence_basis_code {
        if code == ConfidenceBasisCode::MissingDetectionQualityScore {
            return format!("{confidence_label} — 掃描工具未提供偵測品質");
        }
        return format!(
            "{confidence_label} — 本產品依據{}評定",
            confidence_basis_zh_hant(code)
        );
    }
    source_confidence(priority_reasons).map_or_else(
        || confidence_label.to_owned(),
        |source| format!("{confidence_label} — 來源工具評定：{source}"),
    )
}

fn basis(code: SeverityBasisCode) -> &'static str {
    match code {
        SeverityBasisCode::OpenPort => "開放連接埠的觀察結果，而非缺陷",
        SeverityBasisCode::ReachableHttpService => "可連線 HTTP 服務的觀察結果，而非缺陷",
        SeverityBasisCode::SecretPatternMatch => "掃描到的原始碼中符合機密資料的樣式",
        SeverityBasisCode::UnverifiedCredentialDetector => "憑證偵測器的比對結果",
        SeverityBasisCode::IacPolicyCheck => {
            "一項未通過的基礎架構即程式碼政策檢查；因為 Checkov 離線執行時不提供各別檢查的嚴重程度，所以一律採用相同等級"
        }
        SeverityBasisCode::CisKubernetesBenchmark => "一項未通過的 CIS Kubernetes Benchmark 檢查",
        SeverityBasisCode::CloudControlQuery => "本產品自有固定查詢中一項未通過的 IAM 控制項",
        SeverityBasisCode::CloudsplainingIamPolicyFinding => {
            "Cloudsplaining 未評定嚴重程度的 IAM 政策問題"
        }
        SeverityBasisCode::UnratedVulnerabilityTestAlarm => {
            "Greenbone 弱點測試發出的警示，但固定版本 feed 條目沒有可解析的嚴重程度向量"
        }
        SeverityBasisCode::AdversarialProbeFailureRate => {
            "garak 偵測器判定為失敗的對抗式探測次數；garak 只提供次數，不提供嚴重程度"
        }
    }
}

/// The specialists the adapters recommend, matched on the whole name.
///
/// Not substring-matched: "security" and "vulnerability" both contain "it", and
/// a rule asking that question sent Kubernetes, container, Microsoft 365 and
/// vulnerability findings all to an IT administrator.
pub fn expert_type_zh_hant(expert: &str) -> &str {
    match expert.trim() {
        "Cloud security engineer" => "雲端安全工程師",
        "Cloud identity specialist" => "雲端身分權限專家",
        "Microsoft 365 security administrator" => "Microsoft 365 安全管理員",
        "Network security engineer" => "網路安全工程師",
        "Application security engineer" => "應用程式安全工程師",
        "Vulnerability manager" => "弱點管理負責人",
        "Secrets-response specialist" => "機密外洩應變專家",
        "Infrastructure-as-code engineer" => "基礎架構即程式碼工程師",
        "Container security engineer" => "容器安全工程師",
        "Software supply-chain engineer" => "軟體供應鏈工程師",
        "Kubernetes security engineer" => "Kubernetes 安全工程師",
        "AI security engineer" => "AI 安全工程師",
        // Not from an adapter. A check that timed out is a network or system
        // problem, and the report says so on purpose; letting it fall through
        // would send the reader to a security specialist for a connectivity
        // fault, which is the same misdirection the substring rule used to
        // cause. The generic name is what a finding with no details gets.
        "Network or system administrator" => "網路或系統管理員",
        "Security professional" => "資安專業人員",
        // A name from a build this one has never seen still has to say
        // something, and a general answer beats a confidently wrong one.
        _ => "資安或 IT 專業人員",
    }
}

/// The engine's display name, read back off the sentence the product wrote, so
/// the translated sentence names it exactly as the English does. `None` for any
/// sentence that is not the shape this product writes.
fn engine_name_from(english_summary: &str) -> Option<&str> {
    // The summary is normalized twice: once into the report's English, then
    // again by the exporter for the reader's locale. `" checked this "` is how
    // the control verdict below opens, so recognizing it here keeps the second
    // pass able to re-render in Chinese what the first pass already rewrote.
    let (name, _) = english_summary
        .split_once(" reported ")
        .or_else(|| english_summary.split_once(" checked this "))?;
    if name.is_empty() || name.contains('.') {
        return None;
    }
    Some(name)
}

/// Drops the trailing confidence-methodology sentence.
///
/// The adapter composes the risk summary as "{what the scanner reported}
/// {how this product rated its confidence}". The second half is already on the
/// same card twice: as the labelled `Confidence` field with its basis, and
/// again in the priority reasons. Keeping a third copy spent the one sentence a
/// beginner reads on the product's own rating method instead of on what the
/// scanner found, on 43 of the 45 findings in a 21-engine run.
fn without_confidence_methodology(english: &str) -> &str {
    const OPENERS: [&str; 2] = [
        " reported no confidence rating for it.",
        " reported confidence ",
    ];
    OPENERS
        .iter()
        .filter_map(|opener| english.find(opener))
        // The sentence opens with the engine's display name, so the cut is the
        // sentence boundary before it. Without a preceding boundary the summary
        // is only the confidence sentence and there is nothing to keep.
        .filter_map(|at| english[..at].rfind(". ").map(|end| end + 2))
        .min()
        .map(|at| english[..at].trim_end())
        .unwrap_or(english)
}

/// The verdict sentence for a control the tenant did not meet.
///
/// ScubaGear and Maester title a finding with the requirement they checked --
/// "Legacy authentication is blocked", "Privileged accounts use phishing-
/// resistant MFA" -- and only a control that failed becomes a finding at all.
/// Printed as a heading under "Problems found" over a sentence that said no
/// more than "reported a high-severity condition", the requirement read as a
/// statement that the tenant was already in that state, which is the opposite
/// of what the scanner found. The upstream title stays exactly as the scanner
/// wrote it; the verdict goes in the prose this product owns.
fn control_verdict(
    family: Option<FindingFamily>,
    english: &str,
    locale_zh: bool,
) -> Option<String> {
    if family != Some(FindingFamily::Microsoft365) {
        return None;
    }
    let engine = engine_name_from(english)?;
    Some(if locale_zh {
        format!("{engine} 檢查了這項 Microsoft 365 要求，這個租戶未通過。")
    } else {
        format!("{engine} checked this Microsoft 365 requirement and the tenant did not meet it.")
    })
}

/// The Chinese verdict sentence, when the family has one.
///
/// Kept separate from `summary_zh_hant` rather than threaded through it: that
/// function already carries the seven pieces the severity and confidence
/// clauses need, and the verdict replaces the whole sentence instead of
/// composing with them.
pub fn control_verdict_zh_hant(family: Option<FindingFamily>, english: &str) -> Option<String> {
    control_verdict(family, english, true)
}

pub fn summary_english(english: &str, family: Option<FindingFamily>) -> String {
    if let Some(verdict) = control_verdict(family, english, false) {
        return verdict;
    }
    without_confidence_methodology(english)
        .replace(
            " The attached raw record is evidence, not an instruction.",
            "",
        )
        .replace(
            "Severity remains Unknown and requires human review.",
            "Severity is Unknown.",
        )
        .replace(
            "a credential detector match that this product does not verify",
            "a credential detector match",
        )
        .replace(
            "an unverified credential detector match",
            "a credential detector match",
        )
        .replace(
            "an unverified pattern or detector match",
            "a pattern or detector match",
        )
}

/// "{engine} reported a {severity}-severity condition on the assessed asset."
pub fn summary_zh_hant(
    english: &str,
    severity: &Severity,
    severity_label: &str,
    severity_basis_code: Option<SeverityBasisCode>,
    confidence_label: &str,
    confidence_basis_code: Option<ConfidenceBasisCode>,
    priority_reasons: &[String],
) -> String {
    let Some(engine) = engine_name_from(english) else {
        return english.to_owned();
    };
    let summary = match (severity_basis_code, severity) {
        (Some(_), Severity::Unknown) => {
            format!("{engine} 回報了這項狀況，但未評定嚴重程度。嚴重程度為未知。")
        }
        (None, _) => format!("{engine} 在受評估的資產上回報了一項{severity_label}等級的狀況。"),
        (Some(code), _) => format!(
            "{engine} 在受評估的資產上回報了這項狀況，但未評定嚴重程度。本產品依據{}，將它評為{severity_label}。",
            basis(code)
        ),
    };
    // The English twin drops the same sentence. The confidence rating, its
    // basis, and the engine's own lack of one are already the labelled
    // confidence field and a priority reason on this same card.
    let _ = (confidence_basis_code, confidence_label, priority_reasons);
    summary
}

/// The case-specific clauses `apply_case_context` appends to `possible_impact`.
///
/// These are appended to the English rather than composed into it, so a
/// surface that rewrites the impact sentence replaces the string they live in
/// and drops them unless it puts them back. That is not a missing translation
/// but a missing fact: the same case raised this finding's priority by up to
/// ten points, and the reasons are the only thing that says why.
fn context_clause(factor: ContextFactor) -> &'static str {
    match factor {
        ContextFactor::InternetExposedAsset => {
            "受影響的資產可從網際網路存取，因此可被觸及的攻擊面較大。"
        }
        ContextFactor::SensitiveDataAsset => {
            "受影響的資產含有敏感資料，因此問題造成的影響可能更高。"
        }
    }
}

fn context_clause_english(factor: ContextFactor) -> &'static str {
    match factor {
        ContextFactor::InternetExposedAsset => {
            " The affected asset is internet-accessible, increasing the reachable attack surface."
        }
        ContextFactor::SensitiveDataAsset => {
            " The affected asset contains sensitive data, increasing the potential impact."
        }
    }
}

fn direct_legacy_impact(english: &str) -> String {
    const PREFIX: &str = "If the scanner result is confirmed, ";
    const UNKNOWN_TAIL: &str =
        " The scanner did not assign a severity; it remains Unknown for human review.";
    const LEGACY_INTERNET: &str = " The affected asset is marked internet-exposed and has only retained non-questionnaire source attribution, which may increase the reachable attack surface; field-level provenance for that attribute is not retained, so it still requires human confirmation.";
    const LEGACY_SENSITIVE: &str = " The affected asset is marked as containing sensitive data and has only retained non-questionnaire source attribution, while the case questionnaire separately records sensitive-data context. This may increase the impact of a confirmed exposure, but field-level data-class provenance is not retained and neither entry is itself proof of data exposure.";
    let mut normalized = english
        .trim()
        .strip_prefix(PREFIX)
        .unwrap_or(english.trim())
        .replace(
            LEGACY_INTERNET,
            context_clause_english(ContextFactor::InternetExposedAsset),
        )
        .replace(
            LEGACY_SENSITIVE,
            context_clause_english(ContextFactor::SensitiveDataAsset),
        );
    if let Some(without_tail) = normalized.strip_suffix(UNKNOWN_TAIL) {
        normalized = without_tail.to_owned();
    }
    for severity in [
        "critical",
        "high",
        "medium",
        "low",
        "informational",
        "unknown",
    ] {
        let tail =
            format!(" The {severity} source severity is not a product-wide compliance score.");
        if let Some(without_tail) = normalized.strip_suffix(&tail) {
            normalized = without_tail.to_owned();
            break;
        }
    }
    if let Some(first) = normalized.get_mut(0..1) {
        first.make_ascii_uppercase();
    }
    normalized
}

pub fn impact_english(
    english: &str,
    family: Option<FindingFamily>,
    context_factors: &[ContextFactor],
) -> String {
    let Some(family) = family else {
        return direct_legacy_impact(english);
    };
    let mut composed = format!("{}.", consequence_english(family));
    for factor in context_factors {
        composed.push_str(context_clause_english(*factor));
    }
    composed
}

/// Direct possible impact and case context.
pub fn impact_zh_hant(
    english: &str,
    _severity: &Severity,
    _severity_label: &str,
    _severity_basis_code: Option<SeverityBasisCode>,
    family: Option<FindingFamily>,
    context_factors: &[ContextFactor],
) -> String {
    let Some(family) = family else {
        return direct_legacy_impact(english);
    };
    let mut composed = format!("{}。", consequence(family));
    for factor in context_factors {
        composed.push_str(context_clause(*factor));
    }
    composed
}

/// The one sentence every adapter finding carries before any change is made.
///
/// Matched exactly rather than inferred from a code. If the adapter's wording
/// ever changes, an exact match falls back to the English -- visible and
/// honest -- where a code would keep confidently printing the old sentence in
/// Chinese. `the_safety_sentence_this_module_translates_is_the_one_adapters_write`
/// in tests/adapter_fixtures.rs pins the two together.
pub const ENGLISH_ROLLBACK: &str =
    "Capture the current configuration and test its restoration path before making the change.";
const LEGACY_ENGLISH_ROLLBACK: &str = "Before any manual change, preserve the current approved configuration and document a tested restoration path.";

pub fn rollback_english(english: &str) -> String {
    if english.trim() == LEGACY_ENGLISH_ROLLBACK {
        ENGLISH_ROLLBACK.to_owned()
    } else {
        english.to_owned()
    }
}

/// "Before any manual change, preserve ... and document a tested restoration path."
pub fn rollback_zh_hant(english: &str) -> String {
    if matches!(english.trim(), ENGLISH_ROLLBACK | LEGACY_ENGLISH_ROLLBACK) {
        return "變更前先保存目前設定，並測試還原路徑。".to_owned();
    }
    english.to_owned()
}

/// The one priority reason every adapter finding carries.
pub const ENGLISH_EVIDENCE_REASON: &str = "Direct scanner evidence is attached.";
pub const ENGLISH_EXPOSURE_OBSERVATION_REASON: &str =
    "Classified as a reachable-service inventory observation, not a vulnerability.";

pub fn is_evidence_only_priority_reason(reason: &str) -> bool {
    matches!(
        reason.trim(),
        ENGLISH_EVIDENCE_REASON
            | "Direct scanner evidence is attached and still requires human review."
    )
}

/// Report-layer wording for Naabu/httpx reachability records. Older cases may
/// contain the vulnerability-oriented impact and remediation prose used before
/// reachability was separated from findings. Export projections replace those
/// stale fields with these inventory semantics while retaining the original
/// evidence and the machine-readable severity basis code.
pub const EXPOSURE_OBSERVATION_RISK: &str = "A service responded within the tested scope. Reachability is inventory evidence, not a vulnerability.";
pub const EXPOSURE_OBSERVATION_IMPACT: &str =
    "Reachability alone does not establish a security weakness or a need to change the service.";
pub const EXPOSURE_OBSERVATION_NEXT_STEP: &str = "Confirm that the service is expected. To look for weaknesses, run an applicable security check against it.";
pub const EXPOSURE_OBSERVATION_VERIFICATION: &str = "Repeat the same bounded discovery if you need to confirm whether the service is still reachable.";
pub const EXPOSURE_OBSERVATION_OWNER: &str = "System or service owner";

/// Next action when every attached check failed to produce observations.
///
/// The finding still appears with its rating, evidence, and stored verification
/// step. This sentence is the recommended action only: finish the incomplete
/// check and confirm the observation before treating the stored verification
/// step — which assumes a change — as something to do.
pub const INCOMPLETE_CHECK_CONFIRM_ACTION: &str = "Finish the check that did not complete, then re-verify this observation, before changing anything.";
pub const INCOMPLETE_CHECK_CONFIRM_ACTION_ZH_HANT: &str =
    "先完成未完成的檢查，再確認這項觀察，之後才變更任何內容。";

/// Why a character-mix password check is ordered lower than its severity.
pub const PASSWORD_COMPOSITION_ORDER_REASON: &str = "Placed lower than its severity suggests. CIS AWS Foundations Benchmark v1.2.0 asks for this character rule, but later CIS versions dropped it and NIST SP 800-63B-4 says not to require character mixes. Check password length and MFA first; change this only if an audit you must pass still requires it.";
/// Traditional Chinese form of [`PASSWORD_COMPOSITION_ORDER_REASON`].
pub const PASSWORD_COMPOSITION_ORDER_REASON_ZH_HANT: &str = "處理順序比嚴重程度所示更後面。CIS AWS Foundations Benchmark v1.2.0 要求這項字元規則，但之後的 CIS 版本已移除，NIST SP 800-63B-4 也要求不要強制混合字元類型。請先確認密碼長度與 MFA；只有在必須通過的稽核仍要求這項規則時，才需要變更。";
/// Why a scheduled-expiry password check is ordered lower than its severity.
pub const PASSWORD_EXPIRY_ORDER_REASON: &str = "Placed lower than its severity suggests. CIS AWS Foundations Benchmark v1.2.0 asks for scheduled password expiry, but later CIS versions dropped it and NIST SP 800-63B-4 says to force a change only when there is evidence a password was compromised. Change this only if an audit you must pass still requires it.";
/// Traditional Chinese form of [`PASSWORD_EXPIRY_ORDER_REASON`].
pub const PASSWORD_EXPIRY_ORDER_REASON_ZH_HANT: &str = "處理順序比嚴重程度所示更後面。CIS AWS Foundations Benchmark v1.2.0 要求密碼定期到期，但之後的 CIS 版本已移除，NIST SP 800-63B-4 也規定只有在有證據顯示密碼已外洩時，才強制更換。只有在必須通過的稽核仍要求這項規則時，才需要變更。";

/// "Why this priority", in the reader's language.
///
/// `priority_reasons` is a bare `Vec<String>` with no per-entry code, so each
/// entry is recognised by its shape rather than looked up. The producers are
/// closed and listed below:
///
///  - the derived-severity reason, built from a basis code and an engine name
///  - `Source severity: {value}`, whose value is the engine's own raw word
///  - the evidence constant above
///  - the reachable-service inventory constant above
///  - the two case-context reasons `apply_case_context` pushes
///  - the two product-order reasons for a password character-mix rule and a
///    scheduled password-expiry rule
///
/// Anything else is returned unchanged. A reason is the product's account of
/// why it ordered a finding where it did, including when it places one lower
/// than the scanner's severity suggests. Printing a confident Chinese sentence
/// for text this build cannot identify would be inventing that account.
/// The two sentences of an unattributed-results coverage gap.
///
/// Composed from the structured payload rather than translated from the
/// English, for the same reason every other pair here is: the identifier and
/// the provider are the engine's own strings and have to read identically in
/// both languages, and the reader has to copy the identifier onto their asset.
pub fn unattributed_gap_zh_hant(
    engine_id: &str,
    unattributed: &crate::domain::UnattributedResults,
) -> (String, String, String) {
    let crate::domain::UnattributedResults {
        provider,
        identifier,
        discarded_results,
    } = unattributed;
    (
        format!("{engine_id}：針對 {provider} {identifier} 的結果"),
        format!(
            "{engine_id} 回報了 {discarded_results} 筆針對 {provider} 識別碼 {identifier} 的結果。你已授權的資產都沒有登記這個識別碼，因此這些結果都沒有被歸屬，也不會出現在這份報告中。"
        ),
        format!("請在你已授權的資產上，新增 {provider} 識別碼 {identifier}，然後重新掃描。"),
    )
}

/// The check a task-level coverage row is about, and whether the row stands
/// for all of it. `append_task_gap` names these rows `"{check}: {state}"`, and
/// the state -- failed, timed out, cancelled, not tested -- is what the row's
/// own label and sentence already say, so the check alone names the row. A
/// partly completed check's row is only the part it did not finish (`false`).
fn task_state_check(dimension: &str) -> Option<(&str, bool)> {
    let (check, state) = dimension.split_once(": ")?;
    let check = check.trim();
    if check.is_empty() {
        return None;
    }
    match state {
        "failed check dimension"
        | "timed-out check dimension"
        | "cancelled check dimension"
        | "not-tested check dimension" => Some((check, true)),
        "remaining requested dimensions" => Some((check, false)),
        _ => None,
    }
}

/// The names a coverage row is speaking about, in English: the backend's own
/// wording, except where it restates the row around it. A row about a whole
/// check is named by the check ("Failed — Nuclei", not "Failed — Nuclei:
/// failed check dimension"), and a control that returned no verdict is not
/// called a manual review, which a redacted export still writes.
///
/// `localizedCoverageDimension` is the twin for the rows the app shows.
pub fn coverage_dimension_english(dimension: &str) -> String {
    match task_state_check(dimension) {
        Some((check, true)) => check.to_owned(),
        Some((check, false)) => format!("{check}: unfinished part"),
        None => dimension.replace(": manual review for ", ": no verdict for "),
    }
}

/// The names a coverage row is speaking about, in Traditional Chinese.
///
/// Most of these are composed at runtime around an identifier -- a check id, an
/// engine id, or the label a person wrote on an exclusion -- and the identifier
/// is the only part telling one row from the next. So the kind is translated
/// and the identifier is carried through untouched, rather than the whole
/// phrase being replaced by a fixed label.
///
/// An unrecognized name keeps its original text behind a marker. Untranslated
/// detail is worth more than fluent erasure: a person can search for
/// "cloudquery" in their scanner's own output, and cannot search for a label
/// this product invented.
pub fn coverage_dimension_zh_hant(dimension: &str) -> String {
    recognized_coverage_dimension_zh_hant(dimension)
        .unwrap_or_else(|| format!("涵蓋範圍細節：{dimension}"))
}

/// `None` for a name this build does not author. `beginner_report.rs` asserts
/// on it in debug builds for every tested dimension it writes, so the whole
/// Rust suite is the census of that vocabulary.
pub(crate) fn recognized_coverage_dimension_zh_hant(dimension: &str) -> Option<String> {
    let lower = dimension.to_lowercase();

    if let Some((check, control)) = dimension
        .split_once(": no verdict for ")
        .or_else(|| dimension.split_once(": manual review for "))
        && !check.is_empty()
        && !control.is_empty()
    {
        return Some(format!("{check}：未回傳判定的控制項 {control}"));
    }

    // Named by the check, as `coverage_dimension_english` explains.
    match task_state_check(dimension) {
        Some((check, true)) => return Some(format!("{check} 檢查")),
        Some((check, false)) => return Some(format!("{check} 未完成的部分")),
        None => {}
    }

    // Fixed names, in the order the more specific one has to be tried first:
    // "completed planned scan batches" is a substring of the partly-completed one.
    for (needle, label) in [
        ("tcp reachability", "TCP 連線狀態"),
        ("bounded connection contract", "受限的連線檢查"),
        (
            "internal-device tls vulnerability checks",
            "內部設備 TLS 弱點檢查",
        ),
        (
            "internal-device scan-profile coverage",
            "內部設備掃描設定檔涵蓋記錄",
        ),
        (
            "greenbone remote vulnerability scan",
            "Greenbone 遠端弱點掃描",
        ),
        ("nuclei upstream website scan", "Nuclei 上游網站掃描"),
        ("ssh service vulnerability checks", "SSH 服務弱點檢查"),
        (
            "ssh endpoint scan-profile coverage",
            "SSH 端點掃描設定檔涵蓋記錄",
        ),
        ("rdp transport security checks", "RDP 傳輸安全性檢查"),
        (
            "rdp transport endpoint scan-profile coverage",
            "RDP 傳輸端點掃描設定檔涵蓋記錄",
        ),
        (
            "rdp implementation, authentication/nla, and endpoint host coverage",
            "RDP 實作、驗證／NLA 與端點主機涵蓋範圍",
        ),
        ("vnc transport security check", "VNC 傳輸安全性檢查"),
        (
            "vnc transport endpoint scan-profile coverage",
            "VNC 傳輸端點掃描設定檔涵蓋記錄",
        ),
        (
            "vnc implementation, authentication, and endpoint host coverage",
            "VNC 實作、驗證與端點主機涵蓋範圍",
        ),
        (
            "smtp cleartext-login and tls security checks",
            "SMTP 明文登入與 TLS 安全性檢查",
        ),
        (
            "smtp fixed security profile attempt",
            "SMTP 固定安全設定檔嘗試",
        ),
        (
            "smtp tls checks with selected-run evidence",
            "具有所選本輪證據的 SMTP TLS 檢查",
        ),
        (
            "smtp tls negotiation-dependent coverage",
            "需成功協商 TLS 的 SMTP 涵蓋範圍",
        ),
        (
            "smtp endpoint scan-profile coverage",
            "SMTP 端點掃描設定檔涵蓋記錄",
        ),
        (
            "smtp server behavior, implementation, and endpoint host coverage",
            "SMTP 伺服器行為、實作與端點主機涵蓋範圍",
        ),
        (
            "telnet cleartext-login security check",
            "Telnet 明文登入安全性檢查",
        ),
        (
            "telnet endpoint scan-profile coverage",
            "Telnet 端點掃描設定檔涵蓋記錄",
        ),
        (
            "telnet authentication, implementation, and endpoint host coverage",
            "Telnet 驗證、實作與端點主機涵蓋範圍",
        ),
        (
            "endpoint operating-system, package, application, and local-configuration coverage",
            "端點作業系統、套件、應用程式與本機設定涵蓋範圍",
        ),
        ("supported vulnerability profile", "可用的弱點掃描設定"),
        (
            "device product and firmware vulnerability coverage",
            "設備產品與韌體弱點涵蓋範圍",
        ),
        ("completed check-to-target coordinate", "完成的目標檢查"),
        ("aws services other than iam", "IAM 以外的 AWS 服務"),
        ("azure services other than iam", "IAM 以外的 Azure 服務"),
        (
            "google cloud settings other than four iam checks",
            "四項 IAM 檢查以外的 Google Cloud 設定",
        ),
        (
            "microsoft 365 products other than entra id",
            "Entra ID 以外的 Microsoft 365 產品",
        ),
        ("requested scan stage", "要求的掃描深度"),
        ("requested limits", "要求的掃描限制"),
        ("scope reduction", "自動縮減的範圍"),
        ("truncation", "自動縮減的範圍"),
        ("target label", "目標的歷史顯示資料"),
        ("target type", "目標的歷史顯示資料"),
        ("finding presentation", "本輪問題顯示資料"),
        ("request outcome", "掃描結果資料一致性"),
        ("recorded finding wording", "記錄的問題說明文字"),
        ("saved run summary", "保存的掃描摘要"),
        (
            "partly completed planned scan batches",
            "部分完成的計畫掃描批次",
        ),
        ("completed planned scan batches", "已完成的計畫掃描批次"),
        ("additional packaged checks", "額外的內建檢查項目"),
        ("requested checks", "要求的檢查項目"),
    ] {
        if lower.contains(needle) {
            return Some(label.to_owned());
        }
    }

    // "{check id} {kind} scan batches ({count})". The count is what makes the row
    // worth reading, so it survives beside the id.
    if let Some((head, count)) = dimension
        .strip_suffix(')')
        .and_then(|rest| rest.rsplit_once(" ("))
        .filter(|(_, count)| !count.is_empty() && count.chars().all(|c| c.is_ascii_digit()))
    {
        for (suffix, label) in [
            (" partly completed scan batches", "部分完成的掃描批次"),
            (" failed scan batches", "失敗的掃描批次"),
            (" timed-out scan batches", "逾時的掃描批次"),
            (" cancelled scan batches", "已取消的掃描批次"),
            (" not-tested scan batches", "未檢測的掃描批次"),
        ] {
            if let Some(check) = head.strip_suffix(suffix) {
                return Some(with_check(check, &format!("{label}（{count}）")));
            }
        }
    }

    // "{check id} {kind}".
    for (suffix, label) in [
        (" completed-check time", "檢查完成時間"),
        (" saved scan-batch coverage", "已儲存的掃描批次涵蓋記錄"),
        (" saved result processing", "已儲存結果的處理"),
        (" final-state reconciliation", "最終狀態核對"),
        (" ended after its time limit", "因逾時而結束"),
        (" stopped before finishing", "未完成就停止"),
        (" was cancelled before finishing", "未完成就被取消"),
    ] {
        if let Some(check) = dimension.strip_suffix(suffix) {
            return Some(with_check(check, label));
        }
    }

    // "{check id}: {kind}".
    if let Some((check, rest)) = dimension.split_once(": ") {
        for (fragment, label) in [
            ("expired detection knowledge", "已過期的偵測知識"),
            ("controls not evaluated", "未評估控制項"),
            ("unfinished check dimension", "未完成的檢查項目"),
            ("vulnerability profile evidence", "弱點掃描設定檔證據"),
            ("website execution evidence", "網站執行證據"),
            ("target response", "目標回應"),
            ("service identification", "服務辨識"),
            ("scanner errors", "掃描工具錯誤"),
            ("unsupported target input", "不支援的目標輸入"),
            (
                "connections refused by the rate limit",
                "遭速率限制拒絕的連線",
            ),
            (
                "destination outside the approved scope",
                "核准範圍外的目的地",
            ),
            ("unrecorded connection refusals", "未記錄的連線拒絕"),
        ] {
            if rest == fragment {
                return Some(with_check(check, label));
            }
        }
    }

    // "requested check {engine id}", singular: the plural rule above is a
    // different row, about the whole requested list rather than one scanner.
    if let Some(engine) = dimension
        .strip_prefix("requested check ")
        .filter(|engine| !engine.is_empty())
    {
        return Some(format!("要求的檢查項目：{engine}"));
    }

    None
}

/// Names the check a composed dimension belongs to, or just the kind when the
/// producer had no id to interpolate.
fn with_check(check: &str, label: &str) -> String {
    let check = check.trim();
    if check.is_empty() {
        return label.to_owned();
    }
    format!("{check} 的{label}")
}

/// Names one limit the run was executed under, in Traditional Chinese.
///
/// The backend composes most of these as "<engine or asset id> <limit kind>",
/// so translating the kind alone erases the only part saying which scanner or
/// which authorized target the limit applied to. A case with three scope
/// grants would otherwise show three rows all reading "approved ports" with no
/// way to attribute them, so the identifier survives in parentheses.
///
/// An unrecognized name keeps its text behind a marker, for the same reason a
/// coverage name does: a limit written by another build still says something.
pub fn requested_limit_name_zh_hant(name: &str) -> String {
    recognized_requested_limit_name_zh_hant(name)
        .unwrap_or_else(|| format!("本輪使用的限制：{name}"))
}

/// `None` for a limit name this build does not author. `beginner_report.rs`
/// asserts on it in debug builds for every limit it writes.
pub(crate) fn recognized_requested_limit_name_zh_hant(name: &str) -> Option<String> {
    // Three names are fixed strings rather than composed ones, so they reach
    // neither the suffix rules nor the fallback.
    match name {
        "endpoint" => return Some("連線端點".to_owned()),
        "connection timeout" => return Some("連線逾時限制".to_owned()),
        "application payload" => return Some("應用資料量".to_owned()),
        _ => {}
    }
    for (suffix, label) in [
        ("approved ports", "允許檢查的連接埠"),
        ("request rate", "請求速率"),
        ("network timeout", "網路逾時限制"),
        ("authorized network target", "已確認的網路目標"),
        ("execution timeout", "檢查逾時限制"),
    ] {
        if let Some(identifier) = name.strip_suffix(suffix) {
            return Some(with_identifier(label, identifier));
        }
    }
    None
}

const REQUESTED_LIMIT_VALUE_UNITS: &[(&str, &str)] =
    &[(" ms", " 毫秒"), (" bytes", " 位元組"), (" seconds", " 秒")];

const REQUEST_RATE_MIDDLE: (&str, &str) = (" per second, concurrency ", " 次，並行 ");

/// One stored requested-limit value in Traditional Chinese.
///
/// Only unit shapes this build authors are changed. Endpoints, targets, port
/// lists, and values written by another build remain byte-for-byte searchable.
pub fn requested_limit_value_zh_hant(name: &str, value: &str) -> String {
    recognized_requested_limit_value_zh_hant(name, value).unwrap_or_else(|| value.to_owned())
}

/// `None` means neither a known unit shape nor a known identifier-bearing
/// limit. The producer assertion uses this distinction to catch a new English
/// unit while the public presentation function safely preserves unknown data.
pub(crate) fn recognized_requested_limit_value_zh_hant(name: &str, value: &str) -> Option<String> {
    for (english_unit, chinese_unit) in REQUESTED_LIMIT_VALUE_UNITS {
        if let Some(number) = value.strip_suffix(english_unit)
            && is_ascii_number(number)
        {
            return Some(format!("{number}{chinese_unit}"));
        }
    }

    if let Some((requests, concurrency)) = value.split_once(REQUEST_RATE_MIDDLE.0)
        && is_ascii_number(requests)
        && is_ascii_number(concurrency)
    {
        return Some(format!(
            "每秒 {requests}{}{concurrency}",
            REQUEST_RATE_MIDDLE.1
        ));
    }

    if name == "endpoint"
        || name.ends_with(" authorized network target")
        || name.ends_with(" approved ports")
    {
        return Some(value.to_owned());
    }
    None
}

fn is_ascii_number(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit())
}

/// Appends the identifier a composed name carries, when it has one.
///
/// `format!("{} approved ports", grant.asset_id)` degrades to a bare suffix if
/// the grant carries no asset id; without this guard the label would end in a
/// pair of empty parentheses.
fn with_identifier(label: &str, identifier: &str) -> String {
    let identifier = identifier.trim();
    if identifier.is_empty() {
        return label.to_owned();
    }
    format!("{label}（{identifier}）")
}

/// The fixed observations attached to tested dimensions, paired with their
/// Traditional Chinese.
///
/// The backend writes these in English before any locale is known and freezes
/// them into the case, so the whole stored observation is the lookup key.
/// `None` means this build did not author the sentence; callers preserve that
/// stored English rather than claiming to understand prose from another build.
const TESTED_OBSERVATION_PROSE: &[(&str, &str)] = &[
    (
        "Nuclei completed the pinned upstream automatic web profile on the displayed origin. Applied checks: templates selected by upstream technology detection. Eligible-template execution completeness: unavailable.",
        "Nuclei 已對畫面所列網站來源範圍完成固定版本的上游自動網站設定。套用的檢查：由上游技術偵測選取的模板。合格模板執行完整度：無法取得。",
    ),
    (
        "The port accepted the bounded TCP connection.",
        "這個連接埠接受了受限的 TCP 連線。",
    ),
    (
        "The port refused the bounded TCP connection.",
        "這個連接埠拒絕了受限的 TCP 連線。",
    ),
    (
        "The bounded TCP connection attempt timed out; reachability was not established.",
        "受限的 TCP 連線嘗試逾時；無法確認連線可達。",
    ),
    (
        "The native task only observed whether the endpoint accepted, refused, or timed out during the bounded connection attempt. It did not perform a vulnerability test.",
        "這項內建工作只觀察端點在受限的連線嘗試期間，是接受連線、拒絕連線，還是逾時。它沒有執行弱點檢測。",
    ),
    (
        "The durable task reached completed state for this target binding. More granular executed dimensions were not frozen in this case record.",
        "這項已保存的工作已針對這個目標完成。這份案件記錄沒有凍結更細部的執行範圍。",
    ),
    (
        "The completed Greenbone task retained a frozen allowlist containing the profile's TLS protocol, cipher, and certificate vulnerability checks.",
        "已完成的 Greenbone 工作保留了凍結的允許清單，其中包含此設定檔的 TLS 協定、加密套件與憑證弱點檢查。",
    ),
    (
        "Greenbone completed the frozen remote-safe profile on the displayed host and ports. Applied checks: feed checks selected by upstream service and product prerequisites. Scheduled-VT execution completeness: unavailable.",
        "Greenbone 已對畫面所列主機與連接埠完成凍結的遠端安全掃描設定。套用的檢查：由上游服務與產品先決條件選取的 feed 檢查。排程 VT 執行完整度：無法取得。",
    ),
    (
        "The completed Greenbone task retained the exact reviewed SSH profile for deprecated protocol, known or static host key, and weak MAC, encryption, host-key, key-size, or key-exchange choices.",
        "已完成的 Greenbone 工作保留了精確且經過檢視的 SSH 設定檔，用來檢查淘汰的協定、已知或固定的 host key，以及較弱的 MAC、加密、host-key、key size 或 key-exchange 選項。",
    ),
    (
        "The completed Greenbone task retained the exact reviewed RDP transport profile: ten TLS protocol, cipher, and certificate checks plus one check for the legacy fixed private key used by RDP 5.2 or earlier.",
        "已完成的 Greenbone 工作保留了精確且經過檢視的 RDP 傳輸設定檔：十項 TLS 協定、加密套件與憑證檢查，加上一項針對 RDP 5.2 或更早版本所使用之舊式固定私密金鑰的檢查。",
    ),
    (
        "The completed Greenbone task retained the exact reviewed VNC transport profile containing one check for an unencrypted VNC connection.",
        "已完成的 Greenbone 工作保留了精確且經過檢視的 VNC 傳輸設定檔，其中包含一項未加密 VNC 連線檢查。",
    ),
    (
        "The completed Greenbone task retained and attempted the exact SMTP profile: one check reads the banner, sends EHLO, tries STARTTLS when offered, and reviews advertised AUTH for cleartext-login risk; ten more checks depend on TLS. TLS-check execution: evidenced by selected-run source OIDs. Credentials and mail: not sent.",
        "已完成的 Greenbone 工作保留並嘗試執行精確的 SMTP 設定檔：其中一項檢查會讀取 banner、送出 EHLO、在服務提供時嘗試 STARTTLS，並檢視服務宣告的 AUTH 是否有明文登入風險；另有十項檢查依賴 TLS。TLS 檢查執行情況：由所選輪次的來源 OID 提供證據。帳密與郵件：未送出。",
    ),
    (
        "Counted coverage: exact TLS source OIDs in selected-run finding evidence. Each OID evidences only its own check.",
        "計入的涵蓋範圍：所選輪次問題證據中的精確 TLS 來源 OID。每個 OID 只證明自己的檢查。",
    ),
    (
        "The completed Greenbone task retained the exact reviewed Telnet profile, which observes whether a login or password prompt is offered without TLS. No username or password was sent and no login was attempted.",
        "已完成的 Greenbone 工作保留了精確且經過檢視的 Telnet 設定檔，用來觀察服務是否在沒有 TLS 的情況下提供登入或密碼提示。本輪未送出帳號或密碼，也沒有嘗試登入。",
    ),
    (
        "These exact frozen scan batches have validated completed outcomes across all saved attempts. A completed network check reports reachability; it is not a security pass.",
        "這些已凍結的特定掃描批次，在所有已儲存的嘗試中都有通過驗證的完成結果。完成的網路檢查只回報連線是否可達；不代表安全性檢查通過。",
    ),
    (
        "Scan-batch status: Partial. Planned operations remain unfinished.",
        "掃描批次狀態：部分完成；仍有計畫中的操作未完成。",
    ),
];

/// A tested-dimension observation in Traditional Chinese, or `None` when this
/// build did not author the stored sentence.
pub fn tested_observation_zh_hant(english: &str) -> Option<String> {
    let trimmed = english.trim();
    TESTED_OBSERVATION_PROSE
        .iter()
        .find(|(candidate, _)| *candidate == trimmed)
        .map(|(_, chinese)| (*chinese).to_owned())
}

/// What a coverage row measured, in Traditional Chinese.
///
/// The third field of a tested row is composed the same way its name is: a
/// fixed phrase this build authors, wrapped around a count, a port, or the
/// identifier of the asset the row is about. So the phrase is translated and
/// every number and identifier is carried through untouched. Dispatch is on
/// the row's name because that vocabulary is already closed and censused;
/// matching the composed value itself would mean guessing at its shape.
///
/// `None` for a row name this build does not author, which
/// [`crate::beginner_report`] asserts on in debug builds.
pub fn tested_value_zh_hant(dimension: &str, value: &str) -> Option<String> {
    /// A slot this build fills with a number. Requiring the digits keeps a
    /// value composed by some other build from being read as this shape and
    /// rearranged into a sentence that says something it does not.
    fn counted(value: &str) -> Option<&str> {
        (!value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit())).then_some(value)
    }

    // Every Greenbone profile row counts its own frozen checks and names the
    // asset. Only the noun differs, so they share one shape.
    let counted_profile = |noun: &str| {
        let (count, asset) = value.split_once(" frozen ")?;
        let count = counted(count)?;
        let asset = asset.strip_prefix(noun)?.strip_prefix(" on asset ")?;
        Some(format!(
            "對資產 {asset} 的 {count} 項已凍結 {}",
            match noun {
                "Greenbone TLS tests" => "Greenbone TLS 檢查",
                "upstream Greenbone SSH tests" => "上游 Greenbone SSH 檢查",
                "upstream Greenbone RDP transport tests" => "上游 Greenbone RDP 傳輸檢查",
                "upstream Greenbone VNC transport test" => "上游 Greenbone VNC 傳輸檢查",
                "upstream Greenbone Telnet check" => "上游 Greenbone Telnet 檢查",
                _ => return None,
            }
        ))
    };

    match dimension {
        // An endpoint and a port carry no words to translate.
        "TCP reachability" => Some(value.to_owned()),
        "bounded connection contract" => {
            // The attempt count is the spelled-out word this build writes, not
            // a number, so it is translated rather than carried through.
            let rest = value.strip_prefix("one connection attempt; ")?;
            let (timeout, payload) = rest.split_once("; ")?;
            Some(format!(
                "一次連線嘗試；逾時 {} 毫秒；應用層酬載 {} 位元組",
                counted(timeout.strip_suffix(" ms timeout")?)?,
                counted(payload.strip_suffix(" application-payload bytes")?)?,
            ))
        }
        "completed check-to-target coordinate" => {
            let (engine, asset) = value.split_once(" on asset ")?;
            Some(format!("{engine} 對資產 {asset}"))
        }
        "completed planned scan batches" | "partly completed planned scan batches" => {
            let (done, total) = value.split_once(" of ")?;
            Some(format!("{} 個中的 {} 個", counted(total)?, counted(done)?))
        }
        "internal-device TLS vulnerability checks" => counted_profile("Greenbone TLS tests"),
        "SSH service vulnerability checks" => counted_profile("upstream Greenbone SSH tests"),
        "RDP transport security checks" => {
            counted_profile("upstream Greenbone RDP transport tests")
        }
        "VNC transport security check" => counted_profile("upstream Greenbone VNC transport test"),
        "Telnet cleartext-login security check" => {
            counted_profile("upstream Greenbone Telnet check")
        }
        "Nuclei upstream website scan" => {
            let asset = value.strip_prefix(
                "technology-aware upstream profile on exact website origin for asset ",
            )?;
            Some(format!(
                "依技術偵測選擇的上游設定檔，套用於資產 {asset} 的確切網站來源"
            ))
        }
        "Greenbone remote vulnerability scan" => {
            let rest = value.strip_prefix("applicability-driven upstream profile on asset ")?;
            let (asset, ports) = rest.split_once(" across ")?;
            let ports = counted(ports.strip_suffix(" approved TCP ports")?)?;
            Some(format!(
                "依適用性選擇的上游設定檔，套用於資產 {asset} 的 {ports} 個已核准 TCP 連接埠"
            ))
        }
        "SMTP fixed security profile attempt" => {
            let rest = value.strip_prefix("exact ")?;
            let (count, asset) =
                rest.split_once("-check upstream Greenbone SMTP profile on asset ")?;
            let count = counted(count)?;
            Some(format!(
                "對資產 {asset} 的確切上游 Greenbone SMTP 設定檔，共 {count} 項檢查"
            ))
        }
        "SMTP TLS checks with selected-run evidence" => {
            let (evidenced, rest) = value.split_once(" of ")?;
            let evidenced = counted(evidenced)?;
            let (total, asset) = rest.split_once(" selected TLS checks on asset ")?;
            let total = counted(total)?;
            Some(format!(
                "對資產 {asset} 已選取的 {total} 項 TLS 檢查中的 {evidenced} 項"
            ))
        }
        _ => None,
    }
}

/// Reviewed catalog rationales presented in Traditional Chinese. The English
/// catalog remains the canonical source, and an unknown sentence from another
/// build deliberately has no translation here.
const CONTROL_MAPPING_RATIONALE_PROSE: &[(&str, &str)] = &[
    (
        "Evidence that an identity has no registered multi-factor device is related to authenticating users and safeguarding authentication information.",
        "某個身分未登記多重要素驗證裝置的證據，與驗證使用者及保護驗證資訊有關。",
    ),
    (
        "Evidence that an attached identity policy grants unrestricted administrative permissions is related to least privilege, entitlement review, and privileged access safeguards.",
        "附加的身分政策授予不受限制之管理權限的證據，與最小權限、權限審查及特權存取保護有關。",
    ),
    (
        "Evidence that an object-storage resource permits public access is related to access policy, authorization review, and cloud service protection.",
        "物件儲存資源允許公開存取的證據，與存取政策、授權審查及雲端服務保護有關。",
    ),
    (
        "Evidence that the account password policy does not require an uppercase character is related to credential lifecycle management and to safeguarding authentication information.",
        "帳戶密碼政策未要求包含大寫字元的證據，與憑證生命週期管理及保護驗證資訊有關。",
    ),
    (
        "Evidence that a role assumable by the EC2 service is attached to no instance is related to least privilege and entitlement review; an unused entitlement stays usable until it is removed.",
        "可由 EC2 服務擔任的角色未附加到任何執行個體的證據，與最小權限及權限審查有關；未使用的權限在移除前仍然可用。",
    ),
    (
        "Evidence of an identity privilege-escalation path is related to least privilege, entitlement review, and privileged access safeguards.",
        "身分權限提升路徑的證據，與最小權限、權限審查及特權存取保護有關。",
    ),
    (
        "Evidence that an identity policy permits actions returning credential material is related to credential lifecycle management, least privilege, authentication information safeguards, and privileged access safeguards.",
        "身分政策允許會回傳憑證資料之操作的證據，與憑證生命週期管理、最小權限、驗證資訊保護及特權存取保護有關。",
    ),
    (
        "Evidence that an identity policy permits actions that can read stored data out of the account is related to least privilege, protection of data at rest, access policy, and entitlement review.",
        "身分政策允許將帳戶內已儲存資料讀出之操作的證據，與最小權限、靜態資料保護、存取政策及權限審查有關。",
    ),
    (
        "Evidence that an identity policy permits actions that change who can reach a resource is related to least privilege, access policy, entitlement review, and cloud service security responsibilities.",
        "身分政策允許變更誰可以存取資源之操作的證據，與最小權限、存取政策、權限審查及雲端服務安全責任有關。",
    ),
    (
        "Evidence that an identity policy permits actions that alter account infrastructure is related to least privilege, entitlement review, and privileged access safeguards.",
        "身分政策允許變更帳戶基礎架構之操作的證據，與最小權限、權限審查及特權存取保護有關。",
    ),
    (
        "Evidence that an identity policy grants every action in a service is related to least privilege, entitlement review, and privileged access safeguards; a wildcard also covers actions the account has never reviewed.",
        "身分政策授予某項服務全部操作的證據，與最小權限、權限審查及特權存取保護有關；萬用字元也會涵蓋該帳戶從未審查過的操作。",
    ),
    (
        "Evidence that legacy authentication is not blocked is related to enforcing appropriate authentication and protecting authentication information.",
        "未封鎖舊式驗證的證據，與強制使用適當的驗證方式及保護驗證資訊有關。",
    ),
    (
        "Evidence that privileged identities lack phishing-resistant authentication is related to authentication enforcement and authentication information safeguards.",
        "特權身分缺少抗網路釣魚驗證的證據，與強制驗證及驗證資訊保護有關。",
    ),
    (
        "Evidence of an exposed database administration interface is related to identifying, validating, recording, and handling technical vulnerabilities.",
        "資料庫管理介面對外暴露的證據，與識別、確認、記錄及處理技術弱點有關。",
    ),
    (
        "Static-analysis evidence of dynamic code execution is related to secure development and pre-execution dangerous-construct checks. AIDEFEND's AI-generated-artifact coordinate applies when the selected code was generated or materially changed by AI.",
        "動態程式碼執行的靜態分析證據，與安全開發及執行前的危險程式結構檢查有關。當所選程式碼由 AI 產生或經 AI 實質修改時，AIDEFEND 的 AI 產生構件條目才適用。",
    ),
    (
        "Static-analysis evidence that Python code invokes an operating-system shell is related to secure development and pre-execution dangerous-construct checks. AIDEFEND's AI-generated-artifact coordinate applies when the selected code was generated or materially changed by AI.",
        "Python 程式碼呼叫作業系統 shell 的靜態分析證據，與安全開發及執行前的危險程式結構檢查有關。當所選程式碼由 AI 產生或經 AI 實質修改時，AIDEFEND 的 AI 產生構件條目才適用。",
    ),
    (
        "Static-analysis evidence that JavaScript or TypeScript code invokes a command through a shell is related to secure development and pre-execution dangerous-construct checks. AIDEFEND's AI-generated-artifact coordinate applies when the selected code was generated or materially changed by AI.",
        "JavaScript 或 TypeScript 程式碼透過 shell 呼叫命令的靜態分析證據，與安全開發及執行前的危險程式結構檢查有關。當所選程式碼由 AI 產生或經 AI 實質修改時，AIDEFEND 的 AI 產生構件條目才適用。",
    ),
    (
        "Static-analysis evidence of private-key material in current project files is related to managing credentials and protecting authentication information. AIDEFEND's static-admission coordinate applies when the selected artifact was generated or materially changed by AI.",
        "目前專案檔案含有私密金鑰資料的靜態分析證據，與管理憑證及保護驗證資訊有關。當所選構件由 AI 產生或經 AI 實質修改時，AIDEFEND 的靜態准入條目才適用。",
    ),
    (
        "Evidence of a credential embedded in current project files is related to managing credentials and protecting authentication information. AIDEFEND's static-admission coordinate applies when the selected artifact was generated or materially changed by AI.",
        "目前專案檔案內嵌憑證的證據，與管理憑證及保護驗證資訊有關。當所選構件由 AI 產生或經 AI 實質修改時，AIDEFEND 的靜態准入條目才適用。",
    ),
    (
        "Every TruffleHog result is a detected credential, so this reference covers the engine's whole detector surface rather than one detector. Evidence of a credential in source material is related to managing credentials and protecting authentication information. AIDEFEND's static-admission coordinate applies when the selected artifact was generated or materially changed by AI.",
        "每一筆 TruffleHog 結果都是偵測到的憑證，因此這項參照涵蓋該掃描工具的完整偵測範圍，而不是單一偵測器。原始資料中含有憑證的證據，與管理憑證及保護驗證資訊有關。當所選構件由 AI 產生或經 AI 實質修改時，AIDEFEND 的靜態准入條目才適用。",
    ),
    (
        "Static evidence that an MCP configuration embeds a credential pattern is related to credential lifecycle management, authentication-information protection, and sensitive-information disclosure.",
        "MCP 設定內嵌憑證樣式的靜態證據，與憑證生命週期管理、驗證資訊保護及敏感資訊外洩有關。",
    ),
    (
        "Static evidence that an MCP server configuration grants a risky tool, permission, command, or command flag is related to least privilege, configuration management, privileged access safeguards, and excessive agency.",
        "MCP 伺服器設定授予高風險工具、權限、命令或命令旗標的靜態證據，與最小權限、組態管理、特權存取保護及過度代理能力有關。",
    ),
    (
        "Infrastructure-as-code evidence that access logging is disabled is related to security-relevant audit records. AIDEFEND's IaC-scanning coordinate applies when the selected configuration provisions an AI system.",
        "基礎架構即程式碼顯示存取記錄已停用的證據，與安全性相關的稽核記錄有關。當所選設定用來佈建 AI 系統時，AIDEFEND 的 IaC 掃描條目才適用。",
    ),
    (
        "Infrastructure-as-code evidence that server-side encryption is absent is related to protecting data at rest and using cryptographic safeguards. AIDEFEND's IaC-scanning coordinate applies when the selected configuration provisions an AI system.",
        "基礎架構即程式碼顯示未使用伺服器端加密的證據，與保護靜態資料及使用密碼學保護措施有關。當所選設定用來佈建 AI 系統時，AIDEFEND 的 IaC 掃描條目才適用。",
    ),
    (
        "Evidence that an installed component is affected by a CVE is related to vulnerability handling. For an AI system, AIDEFEND separates build or deployment admission from the deployed-software remediation lifecycle; this reference does not decide which lifecycle state applies.",
        "已安裝元件受某項 CVE 影響的證據，與弱點處理有關。對 AI 系統而言，AIDEFEND 將建置或部署准入與已部署軟體的修復生命週期分開；這項參照不會判定適用哪一個生命週期階段。",
    ),
    (
        "Evidence that subjects can run commands inside running containers is related to least-privilege authorization, privileged access safeguards, and container isolation. AIDEFEND's container-isolation coordinate applies when the workload is part of an AI system.",
        "主體可以在執行中的容器內執行命令的證據，與最小權限授權、特權存取保護及容器隔離有關。當工作負載屬於 AI 系統的一部分時，AIDEFEND 的容器隔離條目才適用。",
    ),
    (
        "Evidence that a workload declares no CPU or memory limit is related to maintaining resource capacity for availability, capacity management, and platform configuration management.",
        "工作負載未宣告 CPU 或記憶體上限的證據，與維持可用性所需的資源容量、容量管理及平台組態管理有關。",
    ),
    (
        "Evidence that a container can write to its own root filesystem is related to platform configuration management and container isolation. AIDEFEND's container-isolation coordinate applies when the workload is part of an AI system.",
        "容器可以寫入自身根檔案系統的證據，與平台組態管理及容器隔離有關。當工作負載屬於 AI 系統的一部分時，AIDEFEND 的容器隔離條目才適用。",
    ),
    (
        "Evidence that the kubelet service file is writable beyond its owner is related to node configuration management and privileged access safeguards; that file governs a root-level service.",
        "kubelet 服務檔案可由擁有者以外的人寫入的證據，與節點組態管理及特權存取保護有關；該檔案掌管一個以 root 執行的服務。",
    ),
    (
        "Evidence that the kubelet config.yaml file is readable or writable beyond its owner is related to node configuration management and privileged access safeguards; that file holds the kubelet's security settings.",
        "kubelet config.yaml 檔案可由擁有者以外的人讀取或寫入的證據，與節點組態管理及特權存取保護有關；該檔案存放 kubelet 的安全設定。",
    ),
    (
        "Evidence that the kubelet config.yaml file is not owned by root is related to node configuration management and privileged access safeguards; a non-root owner can change the kubelet's security settings.",
        "kubelet config.yaml 檔案的擁有者不是 root 的證據，與節點組態管理及特權存取保護有關；非 root 的擁有者可以變更 kubelet 的安全設定。",
    ),
    (
        "Evidence that the kubelet accepts anonymous authentication is related to authentication enforcement and authentication information safeguards. This is the node check the shipped snapshot benchmark runs; the control-plane equivalent is not in scope for this product.",
        "kubelet 接受匿名驗證的證據，與強制驗證及驗證資訊保護有關。這是隨附的快照基準所執行的節點檢查；對應的控制平面檢查不在本產品範圍內。",
    ),
    (
        "Evidence that kubelet client certificate rotation is turned off is related to credential lifecycle management, authentication information safeguards, and cryptographic safeguards.",
        "kubelet 用戶端憑證輪替已關閉的證據，與憑證生命週期管理、驗證資訊保護及密碼學保護措施有關。",
    ),
    (
        "Evidence that the kube-proxy metrics endpoint is not bound to localhost is related to protecting networks from unauthorized access, node configuration management, and network security.",
        "kube-proxy 指標端點未繫結至 localhost 的證據，與保護網路免於未經授權的存取、節點組態管理及網路安全有關。",
    ),
    (
        "A Greenbone vulnerability-test alarm on an authorized host is evidence related to technical vulnerability handling. For an AI system, AIDEFEND separates build-time dependency admission from the deployed-software remediation lifecycle; this reference points at the deployed lifecycle and does not decide remediation state.",
        "Greenbone 對已授權主機發出的弱點測試警示，是與技術性弱點處理相關的證據。對 AI 系統而言，AIDEFEND 將建置階段的相依套件准入與已部署軟體的修復生命週期分開；這項參照指向已部署的生命週期，並不判定修復狀態。",
    ),
    (
        "garak's dan module holds do-anything-now and other long-form instruction attacks whose stated purpose is to make a target ignore its alignment. A detector judging those attempts as failures is evidence related to prompt injection.",
        "garak 的 dan 模組收錄 do-anything-now 等長篇指令式攻擊，其目的是讓目標忽略自身的對齊限制。偵測器把這些嘗試判定為失敗，是與提示注入相關的證據。",
    ),
    (
        "Every probe in garak's encoding module hides an instruction or payload in an encoding to get it past alignment. A detector judging those attempts as failures is evidence related to prompt injection carried in obfuscated input.",
        "garak encoding 模組中的每個探測項目，都把指令或酬載藏在某種編碼裡，以繞過對齊限制。偵測器把這些嘗試判定為失敗，是與經混淆輸入夾帶提示注入相關的證據。",
    ),
    (
        "garak's latentinjection module buries an instruction inside content the target is asked to process, such as a resume, a report or a passage to translate. A detector judging those attempts as failures is evidence related to indirect prompt injection.",
        "garak 的 latentinjection 模組把指令埋在要求目標處理的內容裡，例如履歷、報告或待翻譯的段落。偵測器把這些嘗試判定為失敗，是與間接提示注入相關的證據。",
    ),
    (
        "garak's sysprompt_extraction module asks the target for its own system prompt through direct requests, encoding tricks and role play. A detector judging those attempts as failures is evidence related to system prompt leakage.",
        "garak 的 sysprompt_extraction 模組透過直接索取、編碼手法與角色扮演，向目標取得它自己的系統提示。偵測器把這些嘗試判定為失敗，是與系統提示外洩相關的證據。",
    ),
    (
        "garak's leakreplay module asks the target to complete or fill in excerpts of documents, to see whether it replays text it was trained on. A detector judging those attempts as failures is evidence related to sensitive information disclosure.",
        "garak 的 leakreplay 模組要求目標補完或填空文件片段，藉此觀察它是否覆述訓練用過的文字。偵測器把這些嘗試判定為失敗，是與敏感資訊外洩相關的證據。",
    ),
    (
        "garak's divergence.Repeat probe asks the target to repeat a word until its output diverges and leaks other material. Its sibling divergence.RepeatedToken measures stability rather than leakage, so this reference is bound to the one probe.",
        "garak 的 divergence.Repeat 探測項目要求目標不斷重複某個詞，直到輸出偏離並洩漏其他內容。同模組的 divergence.RepeatedToken 量測的是穩定性而非外洩，因此這項參照只綁定這一個探測項目。",
    ),
    (
        "garak's packagehallucination module asks the target for code and checks whether the imports it names exist in the language's real package registry. A detector judging those attempts as failures is evidence related to misinformation in generated code.",
        "garak 的 packagehallucination 模組要求目標產生程式碼，並檢查其中列出的匯入項目是否真的存在於該語言的套件登錄中。偵測器把這些嘗試判定為失敗，是與生成程式碼中的錯誤資訊相關的證據。",
    ),
    (
        "garak's snowball module poses reasoning questions whose only correct response is that the task is impossible. A detector judging those attempts as failures is evidence related to misinformation, because the target asserted an answer instead.",
        "garak 的 snowball 模組提出的推理題，唯一正確的回應是指出該任務無法達成。偵測器把這些嘗試判定為失敗，是與錯誤資訊相關的證據，因為目標反而給出了肯定的答案。",
    ),
    (
        "garak's misleading module states false claims and checks whether the target refutes them. A detector judging those attempts as failures is evidence related to misinformation, because the target went along with the claim.",
        "garak 的 misleading 模組提出不實主張，並檢查目標是否加以反駁。偵測器把這些嘗試判定為失敗，是與錯誤資訊相關的證據，因為目標順著該主張作答。",
    ),
    (
        "garak's ansiescape module tries to make the target emit ANSI terminal escape codes, which disrupt whatever renders the reply. A detector judging those attempts as failures is evidence related to improper output handling downstream of the model.",
        "garak 的 ansiescape 模組嘗試讓目標輸出 ANSI 終端跳脫碼，這類字元會干擾負責呈現回覆的元件。偵測器把這些嘗試判定為失敗，是與模型下游輸出處理不當相關的證據。",
    ),
    (
        "garak's web_injection module tries to make the target emit markdown or script that a client will act on, either exfiltrating conversation content through a URI or running as cross-site scripting. A detector judging those attempts as failures is evidence related to improper output handling and to sensitive information disclosure.",
        "garak 的 web_injection 模組嘗試讓目標輸出用戶端會實際處理的 markdown 或指令碼，藉此經由 URI 外傳對話內容，或形成跨站腳本攻擊。偵測器把這些嘗試判定為失敗，是與輸出處理不當及敏感資訊外洩相關的證據。",
    ),
    (
        "OWASP publishes A01:2021 as this set of CWEs, so a scanner-assigned CWE in the set places the result in the category.",
        "OWASP 公布 A01:2021 所對應的一組 CWE；掃描工具標示的 CWE 屬於這組時，結果即歸入此類別。",
    ),
    (
        "OWASP publishes A02:2021 as this set of CWEs, so a scanner-assigned CWE in the set places the result in the category.",
        "OWASP 公布 A02:2021 所對應的一組 CWE；掃描工具標示的 CWE 屬於這組時，結果即歸入此類別。",
    ),
    (
        "OWASP publishes A03:2021 as this set of CWEs, so a scanner-assigned CWE in the set places the result in the category.",
        "OWASP 公布 A03:2021 所對應的一組 CWE；掃描工具標示的 CWE 屬於這組時，結果即歸入此類別。",
    ),
    (
        "OWASP publishes A04:2021 as this set of CWEs, so a scanner-assigned CWE in the set places the result in the category.",
        "OWASP 公布 A04:2021 所對應的一組 CWE；掃描工具標示的 CWE 屬於這組時，結果即歸入此類別。",
    ),
    (
        "OWASP publishes A05:2021 as this set of CWEs, so a scanner-assigned CWE in the set places the result in the category.",
        "OWASP 公布 A05:2021 所對應的一組 CWE；掃描工具標示的 CWE 屬於這組時，結果即歸入此類別。",
    ),
    (
        "OWASP publishes A06:2021 as this set of CWEs, so a scanner-assigned CWE in the set places the result in the category.",
        "OWASP 公布 A06:2021 所對應的一組 CWE；掃描工具標示的 CWE 屬於這組時，結果即歸入此類別。",
    ),
    (
        "OWASP publishes A07:2021 as this set of CWEs, so a scanner-assigned CWE in the set places the result in the category.",
        "OWASP 公布 A07:2021 所對應的一組 CWE；掃描工具標示的 CWE 屬於這組時，結果即歸入此類別。",
    ),
    (
        "OWASP publishes A08:2021 as this set of CWEs, so a scanner-assigned CWE in the set places the result in the category.",
        "OWASP 公布 A08:2021 所對應的一組 CWE；掃描工具標示的 CWE 屬於這組時，結果即歸入此類別。",
    ),
    (
        "OWASP publishes A09:2021 as this set of CWEs, so a scanner-assigned CWE in the set places the result in the category.",
        "OWASP 公布 A09:2021 所對應的一組 CWE；掃描工具標示的 CWE 屬於這組時，結果即歸入此類別。",
    ),
    (
        "OWASP publishes A10:2021 as this set of CWEs, so a scanner-assigned CWE in the set places the result in the category.",
        "OWASP 公布 A10:2021 所對應的一組 CWE；掃描工具標示的 CWE 屬於這組時，結果即歸入此類別。",
    ),
];

pub fn control_mapping_rationale_zh_hant(english: &str) -> Option<String> {
    CONTROL_MAPPING_RATIONALE_PROSE
        .iter()
        .find(|(candidate, _)| *candidate == english)
        .map(|(_, chinese)| (*chinese).to_owned())
}

/// Fixed coverage-ledger explanations shared by the screen and the exported
/// case record. Explanations with retained values are matched by shape below.
const COVERAGE_RECORD_DETAIL_PROSE: &[(&str, &str)] = &[
    (
        "Choose the AI workflow framework for this repository before running its workflow inventory.",
        "請先選擇這個專案的 AI 工作流程框架，再執行工作流程盤點。",
    ),
    (
        "The source is connected, but no attributable discovery has completed and no assets are known. Coverage is not established.",
        "來源已連線，但尚未完成可歸屬的探索，也沒有已知資產。尚未建立涵蓋。",
    ),
    (
        "The discovered candidate has not had ownership and scope explicitly confirmed. Discovery never authorizes a target automatically.",
        "探索到的候選資產尚未明確確認所有權與範圍。探索本身絕不會自動授權目標。",
    ),
    (
        "The asset has no unexpired, valid scope grant. Discovery never authorizes a target automatically.",
        "此資產沒有尚未到期的有效範圍授權。探索本身絕不會自動授權目標。",
    ),
    (
        "The asset is authorized, but no scan plan is tied to its current effective grants.",
        "此資產已獲授權，但沒有任何掃描計畫連結到目前有效的授權。",
    ),
    (
        "The scan predates frozen scope-grant snapshots, so its historical authorization and permission coverage are unknown. Live grants are never substituted for missing run evidence.",
        "這次掃描早於凍結範圍授權快照的機制，因此無法得知當時的授權與權限涵蓋。絕不會用現行授權補上缺少的執行記錄。",
    ),
    (
        "The asset is authorized, but the latest applicable scan plan contains no engine run for it.",
        "此資產已獲授權，但最近適用的掃描計畫沒有包含它的掃描工具工作。",
    ),
];

const COVERAGE_STATE_APPEND: (&str, &str) = (
    " This state is independent of how many findings were reported.",
    " 此狀態與回報了多少個問題無關。",
);
const PROVIDER_DISCOVERY_APPEND: (&str, &str) =
    (" Latest provider discovery: ", " 最近一次供應商探索：");
const STALE_KNOWLEDGE_APPEND: (&str, &str) = (
    " Explicit stale-knowledge warning: ",
    " 明確的過時知識警告：",
);
const STALE_KNOWLEDGE_SUFFIX: (&str, &str) = (
    ". Completion proves execution, not current knowledge.",
    "。完成只證明已執行，不代表知識仍為最新。",
);
const LOCALHOST_ATTEMPT_APPEND: (&str, &str) = (
    " Exact built-in localhost TCP attempt(s): ",
    " 精確的內建 localhost TCP 嘗試：",
);
const LOCALHOST_ATTEMPT_SUFFIX: (&str, &str) = (
    ". This records only those connection attempts; it does not establish that the service or computer is secure, and it does not cover other ports or hosts.",
    "。這只記錄這些連線嘗試；無法證明服務或電腦安全，也不涵蓋其他連接埠或主機。",
);

/// A coverage-ledger explanation in Traditional Chinese, or `None` when this
/// build did not author the stored sentence. Values retained inside a known
/// frame -- including a person's applicability reason -- remain verbatim.
pub fn coverage_record_detail_zh_hant(english: &str) -> Option<String> {
    if let Some((_, chinese)) = COVERAGE_RECORD_DETAIL_PROSE
        .iter()
        .find(|(candidate, _)| *candidate == english)
    {
        return Some((*chinese).to_owned());
    }

    if let Some(translated) =
        translate_trailing_coverage_frame(english, STALE_KNOWLEDGE_APPEND, STALE_KNOWLEDGE_SUFFIX)
    {
        return Some(translated);
    }
    if let Some(translated) = translate_trailing_coverage_frame(
        english,
        LOCALHOST_ATTEMPT_APPEND,
        LOCALHOST_ATTEMPT_SUFFIX,
    ) {
        return Some(translated);
    }
    if let Some(translated) =
        translate_trailing_coverage_frame(english, PROVIDER_DISCOVERY_APPEND, ("", ""))
    {
        return Some(translated);
    }
    if let Some(summary) = english.strip_suffix(COVERAGE_STATE_APPEND.0)
        && let Some(summary) = coverage_record_detail_zh_hant(summary)
    {
        return Some(format!("{summary}{}", COVERAGE_STATE_APPEND.1));
    }

    if let Some(reason) = strip_frame(
        english,
        "The source area is explicitly outside this case: ",
        " This is a scoped applicability statement, not a successful scan result.",
    ) {
        return Some(format!(
            "此來源範圍明確不在本案件內：{reason} 這是範圍適用性的說明，不是掃描成功的結果。"
        ));
    }
    if let Some(count) = strip_frame(
        english,
        "The source is connected and the latest attributable discovery returned no assets. This is not a successful scan result; ",
        " prior asset observation(s) remain retained.",
    ) && is_ascii_number(count)
    {
        return Some(format!(
            "來源已連線，且最近一次可歸屬的探索未傳回任何資產。這不是掃描成功的結果；仍保留 {count} 筆先前的資產觀察結果。"
        ));
    }
    if let Some(rest) = english.strip_prefix("The source is not currently connected (status: ")
        && let Some((status, rest)) = rest.split_once("). Its present coverage is unknown; ")
        && let Some(count) = rest.strip_suffix(
            " previously attributed asset(s) are retained but do not make the source green.",
        )
        && !status.is_empty()
        && is_ascii_number(count)
    {
        return Some(format!(
            "來源目前未連線（狀態：{status}）。目前的涵蓋未知；仍保留 {count} 筆先前歸屬的資產，但這不會讓來源顯示為綠色。"
        ));
    }
    if let Some(detail) = strip_frame(
        english,
        "The scan's frozen authorization evidence is incomplete: ",
        ". Live grants are never used to reconstruct historical scan permission.",
    ) {
        return Some(format!(
            "掃描中凍結的授權證據不完整：{detail}。絕不會用現行授權重建過去的掃描權限。"
        ));
    }
    if let Some(count) = strip_frame(
        english,
        "All ",
        " compatible engine run(s) planned for this asset completed.",
    ) && is_ascii_number(count)
    {
        return Some(format!(
            "為此資產規劃的 {count} 項相容掃描工具工作皆已完成。"
        ));
    }
    if let Some(count) = strip_frame(
        english,
        "All ",
        " planned task(s) for this asset completed their exact declared dimensions.",
    ) && is_ascii_number(count)
    {
        return Some(format!(
            "為此資產規劃的 {count} 項工作，皆已完成各自明確宣告的檢查範圍。"
        ));
    }
    if let Some(reasons) = strip_frame(
        english,
        "The authorized scan is incomplete: ",
        ". Only completed compatible catalog-engine runs or exact completed built-in tasks can produce scanned coverage.",
    ) {
        return Some(format!(
            "已授權的掃描未完成：{reasons}。只有已完成且相容的目錄掃描工具工作，或精確完成的內建工作，才能產生已掃描涵蓋。"
        ));
    }
    None
}

const DATA_QUALITY_WARNING_PROSE: &[(&str, &str)] = &[
    (
        "This run has inconsistent request and check data.",
        "本輪的請求與檢查資料不一致。",
    ),
    (
        "The selected run has an inconsistent project identity. Report data: selected in-project record.",
        "所選掃描輪次的專案識別資料不一致；報告資料：專案內所選記錄。",
    ),
    (
        "One check has incomplete coverage history.",
        "有一項檢查的涵蓋歷程未完成。",
    ),
];

/// A data-quality warning written into the beginner report, in Traditional
/// Chinese. Unknown text is deliberately not translated: case bundles can
/// outlive the build that authored them.
pub fn data_quality_warning_zh_hant(english: &str) -> Option<String> {
    if let Some((_, chinese)) = DATA_QUALITY_WARNING_PROSE
        .iter()
        .find(|(candidate, _)| *candidate == english)
    {
        return Some((*chinese).to_owned());
    }
    if let Some(finding_id) = strip_frame(
        english,
        "Finding ",
        " selected-run presentation snapshot: unavailable. Display wording: current canonical text.",
    ) && !finding_id.is_empty()
    {
        return Some(format!(
            "問題 {finding_id} 所選輪次呈現快照：無法取得；顯示文字：目前正式版本。"
        ));
    }
    if let Some(finding_id) = strip_frame(
        english,
        "Finding ",
        " presentation detail: unavailable. Retained run observation: available.",
    ) && !finding_id.is_empty()
    {
        return Some(format!(
            "問題 {finding_id} 呈現細節：無法取得；保留的輪次觀察：可用。"
        ));
    }
    None
}

fn translate_trailing_coverage_frame(
    english: &str,
    middle: (&str, &str),
    suffix: (&str, &str),
) -> Option<String> {
    let (base, retained_with_suffix) = english.rsplit_once(middle.0)?;
    let retained = retained_with_suffix.strip_suffix(suffix.0)?;
    if retained.is_empty() {
        return None;
    }
    let translated_base = if base.is_empty() {
        String::new()
    } else {
        coverage_record_detail_zh_hant(base)?
    };
    Some(format!(
        "{translated_base}{}{retained}{}",
        middle.1, suffix.1
    ))
}

fn strip_frame<'a>(value: &'a str, prefix: &str, suffix: &str) -> Option<&'a str> {
    value.strip_prefix(prefix)?.strip_suffix(suffix)
}

/// The sentences a coverage row says, paired with their Traditional Chinese.
///
/// The backend writes these in English before any locale is known and freezes
/// them into the case, so the English is canonical and this is a lookup rather
/// than a second source of truth. `None` means the sentence is not one this
/// product authored -- a case exclusion carries the words a person typed -- and
/// the caller prints the stored text rather than inventing a label for it.
///
/// Completeness is not enforced by reading this file. `beginner_report.rs`
/// asserts in debug builds that every gap it writes is found here, so the whole
/// Rust suite is the census, and a new sentence added there fails the test that
/// exercises its path rather than passing silently in English.
const COVERAGE_GAP_PROSE: &[(&str, &str)] = &[
    (
        "This check's packaged scanner cannot read this kind of target, so nothing was tested by it.",
        "這項檢查的內建掃描工具無法讀取這類目標，因此沒有測試任何內容。",
    ),
    // Why the coverage is missing.
    (
        "Maester evaluated this control but did not return a pass or fail verdict.",
        "Maester 已評估這項控制措施，但未回傳通過或失敗的判定。",
    ),
    (
        "Website security-template evidence unavailable. This website cannot be shown as tested.",
        "網站安全模板證據無法取得；無法確認此網站已測試。",
    ),
    (
        "Host response unavailable. Vulnerability checks did not complete.",
        "主機回應無法取得；弱點檢查未完成。",
    ),
    (
        "Greenbone reported errors for this host, so its checks cannot be shown as complete.",
        "Greenbone 回報了這台主機的錯誤，因此其檢查不能顯示為已完成。",
    ),
    (
        "No service identified on the approved ports. Vulnerability checks did not run for this host.",
        "已核准的連接埠上沒有辨識出任何服務，因此這台主機沒有執行弱點檢查。",
    ),
    (
        "The saved summary did not match this run's checks, so the report follows the checks.",
        "保存的摘要與這次掃描的檢查不符，因此報告以檢查為準。",
    ),
    (
        "Some findings are shown without the wording this scan recorded.",
        "部分問題顯示的說明不是這次掃描當時記錄的內容。",
    ),
    (
        "This check's own record of what it scanned is unusable, so it cannot be shown as complete.",
        "這項檢查自己對已掃描內容的記錄無法使用，因此不能顯示為已完成。",
    ),
    (
        "This check ran on detection knowledge whose declared support had already ended, so issues published after that date were not tested.",
        "這項檢查執行時所用的偵測知識，其宣告的支援期限已經結束，因此該日期之後才公布的問題並未受測。",
    ),
    (
        "Treat these results as evidence from expired knowledge, not as current coverage.",
        "請將這些結果視為過期知識留下的證據，而不是目前的涵蓋範圍。",
    ),
    (
        "Usable results were saved for these batches, but the rest of their planned addresses and ports were not tested.",
        "這些掃描批次已儲存可用的結果，但其餘計畫中的位址與連接埠並未受測。",
    ),
    (
        "These planned scan batches stopped before establishing completed coverage.",
        "這些計畫中的掃描批次在建立完整涵蓋之前就停止了。",
    ),
    (
        "These planned scan batches reached their bounded time limit before completed coverage was recorded.",
        "這些計畫中的掃描批次在記錄完整涵蓋之前就達到時間上限。",
    ),
    (
        "These planned scan batches were cancelled before completed coverage was recorded.",
        "這些計畫中的掃描批次在記錄完整涵蓋之前就被取消。",
    ),
    (
        "These frozen scan batches have no validated tested outcome in any saved attempt.",
        "這些已凍結的掃描批次，在任何一次已儲存的嘗試中都沒有通過驗證的檢測結果。",
    ),
    (
        "Some of this check's results could not be read, so findings from it may be missing.",
        "這項檢查的部分結果無法讀取，因此這項檢查的問題可能有所遺漏。",
    ),
    (
        "All of this check's planned work produced evidence, but the check timed out before it finished.",
        "這項檢查所有計畫中的工作都已產生證據，但這項檢查在完成之前就逾時。",
    ),
    (
        "All of this check's planned work produced evidence, but the check ended in failure.",
        "這項檢查所有計畫中的工作都已產生證據，但這項檢查以失敗結束。",
    ),
    (
        "All of this check's planned work produced evidence, but the check was cancelled before it finished.",
        "這項檢查所有計畫中的工作都已產生證據，但這項檢查在完成之前就被取消。",
    ),
    (
        "All of this check's planned work produced evidence, but the check never recorded that it finished.",
        "這項檢查所有計畫中的工作都已產生證據，但這項檢查從未記錄自己已完成。",
    ),
    (
        "The check reached its time limit after saving some usable results.",
        "這項檢查在儲存了一部分可用結果之後達到時間上限。",
    ),
    (
        "The check reached its time limit before saving a tested outcome.",
        "這項檢查在儲存任何檢測結果之前就達到時間上限。",
    ),
    (
        "The check stopped after saving some usable results.",
        "這項檢查在儲存了一部分可用結果之後停止。",
    ),
    (
        "The check stopped before saving a tested outcome.",
        "這項檢查在儲存任何檢測結果之前就停止。",
    ),
    (
        "The check was cancelled after saving some usable results.",
        "這項檢查在儲存了一部分可用結果之後被取消。",
    ),
    (
        "The check was cancelled before saving a tested outcome.",
        "這項檢查在儲存任何檢測結果之前就被取消。",
    ),
    (
        "This check did not reach a confirmed complete result.",
        "這項檢查沒有取得可確認的完整結果。",
    ),
    (
        "The bounded check reached its time limit, so it cannot be treated as tested complete.",
        "這項受限的檢查達到時間上限，因此不能視為已完整檢測。",
    ),
    (
        "This check failed, so it cannot be shown as tested.",
        "這項檢查失敗了，因此不能顯示為已測試。",
    ),
    (
        "This check was cancelled before completed coverage was recorded.",
        "這項檢查在記錄完整涵蓋之前就被取消。",
    ),
    (
        "This check did not start, so it is not a pass.",
        "這項檢查沒有啟動，因此不代表通過。",
    ),
    (
        "The app closed while preparing this check. Retry from the saved plan.",
        "應用程式在準備這項檢查時關閉。請從已儲存的計畫重新執行。",
    ),
    (
        "Packaged check list unavailable. Additional checks: not tested.",
        "內建檢查清單無法取得；額外檢查：未測試。",
    ),
    (
        "Some packaged checks could not be loaded. Additional checks: not tested.",
        "部分內建檢查無法載入；額外檢查：未測試。",
    ),
    (
        "At least one target identifier is frozen with the run, but its displayed label or type comes from current project data or is unavailable. The report labels that provenance and does not call it historical fact.",
        "至少有一個目標的識別資料是與本輪一起凍結的，但畫面上顯示的名稱或類型來自目前的專案資料，或是無法取得。報告會標示這項來源，不會把它當成歷史事實。",
    ),
    (
        "This run did not retain an exact reduction record. An empty list therefore cannot be interpreted as proof that no requested dimension was reduced.",
        "本輪沒有保留精確的縮減記錄。因此清單為空，並不能證明沒有任何要求的項目被縮減。",
    ),
    (
        "No exact per-run limits were retained. Current project settings are not substituted for historical requested limits.",
        "沒有保留本輪的精確限制。目前的專案設定不會拿來代替當時要求的限制。",
    ),
    (
        "Recorded stage selection: unavailable. Current project settings: excluded from this historical record.",
        "已記錄的階段選擇：無法取得。目前專案設定：不納入此歷史記錄。",
    ),
    (
        "At least one readable frozen network plan includes full inventory, but another network check has no valid saved plan. Inventory is the highest known stage, not a complete run-wide record.",
        "至少有一份可讀取的凍結網路計畫包含完整清點，但另一項網路檢查沒有有效的已儲存計畫。清點是目前已知的最高階段，不代表整輪的完整記錄。",
    ),
    (
        "Readable frozen network plans contain quick discovery only, but another network check has no valid saved plan. Quick discovery is the highest known stage, not a complete run-wide record.",
        "可讀取的凍結網路計畫只包含快速探索，但另一項網路檢查沒有有效的已儲存計畫。快速探索是目前已知的最高階段，不代表整輪的完整記錄。",
    ),
    (
        "This HTTPS management-service profile contains no device product or firmware vulnerability checks. TLS protocol, cipher, and certificate checks are reported separately.",
        "此 HTTPS 管理服務設定檔不包含設備產品或韌體弱點檢查；TLS 協定、加密套件與憑證檢查會另行回報。",
    ),
    (
        "This HTTPS management-service profile contains no device product or firmware vulnerability checks.",
        "此 HTTPS 管理服務設定檔不包含設備產品或韌體弱點檢查。",
    ),
    (
        "This run does not retain one exact frozen HTTPS management-service profile for this asset. Current project metadata is not used to claim historical TLS coverage.",
        "本輪沒有為此資產保留一份精確凍結的 HTTPS 管理服務設定檔。目前的專案資料不會用來宣稱當時已涵蓋 TLS。",
    ),
    (
        "This run does not retain the exact fixed SSH profile for this asset. Current project metadata is not used to claim historical SSH vulnerability coverage.",
        "本輪沒有為此資產保留精確固定的 SSH 設定檔。目前的專案資料不會用來宣稱當時已完成 SSH 弱點涵蓋。",
    ),
    (
        "The unauthenticated SSH service profile does not inspect operating-system patch level, installed packages or applications, or local host configuration.",
        "這項不需登入的 SSH 服務設定檔，不會檢查作業系統修補層級、已安裝的套件或應用程式，也不會檢查主機本機設定。",
    ),
    (
        "This run does not retain the exact fixed RDP transport profile for this asset. Current project metadata is not used to claim historical RDP transport security coverage.",
        "本輪沒有為此資產保留精確固定的 RDP 傳輸設定檔。目前的專案資料不會用來宣稱當時已完成 RDP 傳輸安全性涵蓋。",
    ),
    (
        "The unauthenticated RDP transport profile checks one legacy RDP 5.2-or-earlier fixed-private-key issue, but does not inspect broader or current RDP implementation CVEs, authentication or Network Level Authentication (NLA), Windows patch level, installed packages or applications, or local host configuration.",
        "這項不需登入的 RDP 傳輸設定檔會檢查一項 RDP 5.2 或更早版本的舊式固定私密金鑰問題，但不會檢查更廣泛或現行的 RDP 實作 CVE、驗證或網路層級驗證（NLA）、Windows 修補層級、已安裝的套件或應用程式，也不會檢查主機本機設定。",
    ),
    (
        "This run does not retain the exact fixed VNC transport profile for this asset. Current project metadata is not used to claim historical VNC transport security coverage.",
        "本輪沒有為此資產保留精確固定的 VNC 傳輸設定檔。目前的專案資料不會用來宣稱當時已完成 VNC 傳輸安全性涵蓋。",
    ),
    (
        "The unauthenticated VNC transport profile checks whether the VNC connection is encrypted. It does not inspect VNC implementation CVEs, authentication strength, operating-system patch level, installed packages or applications, or local host configuration. No login or desktop session was attempted.",
        "這項不需登入的 VNC 傳輸設定檔會檢查 VNC 連線是否加密，但不會檢查 VNC 實作 CVE、驗證強度、作業系統修補層級、已安裝的套件或應用程式，也不會檢查主機本機設定；本輪未嘗試登入或建立桌面工作階段。",
    ),
    (
        "This run does not retain the exact fixed SMTP profile for this asset. Current project metadata is not used to claim historical SMTP security coverage.",
        "本輪沒有為此資產保留精確固定的 SMTP 設定檔。目前的專案資料不會用來宣稱當時已完成 SMTP 安全性涵蓋。",
    ),
    (
        "The SMTP profile ran, but this scan did not record every one of its TLS checks. Which TLS checks ran is shown only by each finding's source OID.",
        "SMTP 設定檔已執行，但這次掃描沒有記錄它的每一項 TLS 檢查。哪些 TLS 檢查已執行，只由各問題的來源 OID 顯示。",
    ),
    (
        "This check did not complete, so its SMTP TLS checks cannot be shown as run. Which TLS checks ran is shown only by each finding's source OID.",
        "這項檢查沒有完成，因此其 SMTP TLS 檢查不能顯示為已執行。哪些 TLS 檢查已執行，只由各問題的來源 OID 顯示。",
    ),
    (
        "The unauthenticated SMTP profile reads the banner, issues EHLO, negotiates STARTTLS when offered, and checks advertised AUTH for an unencrypted cleartext-login risk. Its TLS checks apply only when TLS can be negotiated. It does not send credentials or mail, test relay or delivery, authentication enforcement or bypass, anti-spam behavior, general mail-server implementation CVEs, operating-system patches, installed software, or local configuration.",
        "這項不需登入的 SMTP 設定檔會讀取 banner、送出 EHLO、在服務提供時協商 STARTTLS，並檢查服務宣告的 AUTH 是否存在未加密的明文登入風險。只有在能協商 TLS 時才會執行 TLS 檢查。它不會送出帳號或密碼、寄信，也不會測試 relay 或投遞、驗證強制或繞過、anti-spam 行為、一般郵件伺服器實作 CVE、作業系統修補、已安裝軟體或本機設定。",
    ),
    (
        "This run does not retain the exact fixed Telnet profile for this asset. Current project metadata is not used to claim historical Telnet security coverage.",
        "本輪沒有為此資產保留精確固定的 Telnet 設定檔。目前的專案資料不會用來宣稱當時已完成 Telnet 安全性涵蓋。",
    ),
    (
        "The unauthenticated Telnet profile observes whether a login or password prompt is offered without TLS. It sends no username or password and does not log in; it does not test default credentials, authentication bypass, Telnet implementation CVEs, operating-system patches, installed software, or local configuration.",
        "這項不需登入的 Telnet 設定檔會觀察服務是否在沒有 TLS 的情況下提供登入或密碼提示。它不會送出帳號或密碼，也不會登入；不會測試預設帳密、驗證繞過、Telnet 實作 CVE、作業系統修補、已安裝軟體或本機設定。",
    ),
    (
        "The Greenbone process completed, but this run does not retain one exact reviewed vulnerability profile for every bound asset. Process completion is not counted as a vulnerability result.",
        "Greenbone 程序雖已完成，但本輪沒有為每個綁定資產保留一份精確且經審查的弱點掃描設定檔。因此程序完成不會被算成弱點掃描結果。",
    ),
    (
        "Supported service-specific vulnerability profile unavailable. Outcome: not tested.",
        "支援的服務專屬弱點掃描設定無法取得；結果：未測試。",
    ),
    (
        "Completed-check time: unavailable. Finish and bounded observation times are absent.",
        "已完成檢查時間：無法取得。缺少結束時間與受限觀察時間。",
    ),
    (
        "Start the expected service, then run this check again.",
        "啟動預定的服務，再重新執行這項檢查。",
    ),
    (
        "The port refused the bounded TCP connection at the recorded time; this is not a security pass or failure.",
        "在記錄的時間點，這個連接埠拒絕了受限的 TCP 連線；這不代表安全性通過或失敗。",
    ),
    (
        "Review what was tested before deciding whether you need a broader scan.",
        "請先檢視已檢測的內容，再決定是否需要更大範圍的掃描。",
    ),
    (
        "Actionable findings in completed checks: 0.",
        "已完成檢查中的可處理問題：0。",
    ),
    // The three explanations this build stores on a request that contacted
    // nothing. The field is durable free text, so an unrecognized one falls
    // back to the stored English rather than failing.
    (
        "No checks ran because this scan has no active permission for a selected target.",
        "沒有執行任何檢查，因為這次掃描對所選目標沒有有效的授權。",
    ),
    (
        "No checks ran because none of the selected targets is confirmed as yours to scan.",
        "沒有執行任何檢查，因為所選目標都尚未確認是你有權掃描的對象。",
    ),
    (
        "No installed check applies to the selected target and permission.",
        "沒有已安裝的檢查同時符合所選目標與授權範圍。",
    ),
    (
        "Review the exact target and permission, then start the scan again.",
        "請確認目標與授權範圍，然後重新開始掃描。",
    ),
    (
        "Choose a target you control, then start the scan again.",
        "請選擇一個你有掌控權的目標，然後重新開始掃描。",
    ),
    (
        "Finish target setup or add a supported input, then start a new scan.",
        "請完成目標設定或加入受支援的輸入，然後重新開始掃描。",
    ),
    // What to do about it.
    (
        "Run this SSH profile again to create a complete coverage record.",
        "重新執行此 SSH 設定檔以建立完整涵蓋記錄。",
    ),
    (
        "Run this RDP profile again to create a complete coverage record.",
        "重新執行此 RDP 設定檔以建立完整涵蓋記錄。",
    ),
    (
        "Run this VNC profile again to create a complete coverage record.",
        "重新執行此 VNC 設定檔以建立完整涵蓋記錄。",
    ),
    (
        "Run this SMTP profile again to create a complete coverage record.",
        "重新執行此 SMTP 設定檔以建立完整涵蓋記錄。",
    ),
    (
        "Run this Telnet profile again to create a complete coverage record.",
        "重新執行此 Telnet 設定檔以建立完整涵蓋記錄。",
    ),
    (
        "Run the HTTPS management-service profile again to create a complete coverage record.",
        "重新執行 HTTPS 管理服務設定檔以建立完整涵蓋記錄。",
    ),
    (
        "Run a separately approved device firmware assessment or use endpoint inventory.",
        "另行執行經核准的裝置韌體評估，或使用端點盤點資料。",
    ),
    (
        "Use an approved endpoint inventory or local snapshot for host-level checks.",
        "使用已核准的端點盤點資料或本機快照進行主機層級檢查。",
    ),
    (
        "Run a separately approved host or RDP-authentication assessment for those checks.",
        "另行執行經核准的主機或 RDP 驗證評估。",
    ),
    (
        "Use an approved endpoint inventory or run a separate authorized VNC assessment.",
        "使用已核准的端點盤點資料，或另行執行已授權的 VNC 評估。",
    ),
    (
        "Run a separately approved mail-server assessment or use endpoint inventory.",
        "另行執行經核准的郵件伺服器評估，或使用端點盤點資料。",
    ),
    (
        "Run a separately approved TLS assessment for complete SMTP TLS coverage.",
        "另行執行經核准的 TLS 評估以取得完整 SMTP TLS 涵蓋。",
    ),
    (
        "Run a separately approved authentication assessment or use endpoint inventory.",
        "另行執行經核准的驗證評估，或使用端點盤點資料。",
    ),
    (
        "Start a new scan and add each exact host under Internal systems.",
        "請開始新的掃描，並在「內部系統」逐一加入要檢查的主機。",
    ),
    (
        "Retry this scan to create a consistent coverage record.",
        "重新執行掃描以建立一致的涵蓋記錄。",
    ),
    (
        "Rerun the scan to create a fully frozen result.",
        "重新執行掃描以建立完全凍結的結果。",
    ),
    (
        "Run this check again to get a usable record.",
        "重新執行這項檢查以取得可用的記錄。",
    ),
    (
        "Retry only the unfinished work.",
        "只重新執行尚未完成的工作。",
    ),
    ("Retry only the failed work.", "只重新執行失敗的工作。"),
    ("Retry only the timed-out work.", "只重新執行逾時的工作。"),
    ("Restart the cancelled work.", "重新啟動已取消的工作。"),
    (
        "Retry the work without a tested outcome.",
        "重試未產生檢測結果的工作。",
    ),
    (
        "Start a new scan for a fresh result.",
        "開始新的掃描以取得新結果。",
    ),
    (
        "Run this check again to confirm the result.",
        "重新執行這項檢查以確認結果。",
    ),
    (
        "Confirm the host is powered on and reachable from this computer on the approved ports, then run this check again.",
        "請確認這台主機已開機，且本機能連到已核准的連接埠，然後再執行一次這項檢查。",
    ),
    (
        "If this host serves a web page, add its full address as a website, then start a new scan.",
        "如果這台主機提供網頁，請把它的完整網址加入為網站，然後開始新的掃描。",
    ),
    (
        "Retry only the unfinished work.",
        "只重新執行尚未完成的工作。",
    ),
    (
        "Retry this check for a confirmed result.",
        "重新執行這項檢查以取得可確認的結果。",
    ),
    ("Retry the timed-out work.", "重新執行逾時的工作。"),
    ("Retry this check.", "重新執行這項檢查。"),
    (
        "Retry this check to complete the missing coverage.",
        "重新執行這項檢查以完成缺少的涵蓋範圍。",
    ),
    (
        "Review the target and try this check again.",
        "請檢視目標設定，然後重新執行這項檢查。",
    ),
    (
        "This project has no MCP configuration to check. Continue with the other checks.",
        "這個專案沒有可檢查的 MCP 設定；請繼續查看其他檢查。",
    ),
    (
        "Return to scan setup and choose which MCP configuration to check.",
        "回到掃描設定，選擇要檢查的 MCP 設定。",
    ),
    (
        "Return to scan setup and choose the AI workflow framework for inventory.",
        "回到掃描設定，選擇要盤點的 AI 工作流程框架。",
    ),
    (
        "MCP configuration discovery did not finish. Continue with the other checks.",
        "MCP 設定探索未完成；請繼續查看其他檢查。",
    ),
    (
        "Update the app, then retry these checks.",
        "請更新應用程式，再重試這些檢查。",
    ),
    (
        "This version of the app does not include this check.",
        "這個版本的應用程式沒有提供這項檢查。",
    ),
    (
        "Retry this check; scan-tool setup is automatic.",
        "重試這項檢查；掃描工具會自動準備。",
    ),
    (
        "Return to scan setup, choose the intended target, and confirm it once.",
        "回到掃描設定，選擇正確目標並確認一次。",
    ),
    (
        "Return to scan setup and reconnect or review the cloud account.",
        "請回到掃描設定，重新連接或檢查雲端帳號。",
    ),
    (
        "Open the skipped check's technical records and match this check to the approved protocol or target form.",
        "請展開未執行檢查的技術紀錄，讓這項檢查符合已核准的通訊協定或目標形式。",
    ),
    (
        "Update the app, then run these checks again.",
        "請更新應用程式，再重新執行這些檢查。",
    ),
    (
        "Review the upstream detail and record a human decision for this control.",
        "請檢視上游詳細資料，並為這項控制措施記錄人工判定。",
    ),
    ("No action for the current scope.", "目前範圍不需處理。"),
    // What a cloud or Microsoft 365 check's fixed profile leaves out.
    (
        "This scan checked identity and access (IAM) settings only. Other AWS services, such as S3, EC2, RDS, CloudTrail and GuardDuty, were not checked.",
        "這次掃描只檢查了身分與存取（IAM）設定。其他 AWS 服務（例如 S3、EC2、RDS、CloudTrail、GuardDuty）沒有檢查。",
    ),
    (
        "This scan checked identity and access (IAM) role settings only. Other Azure services, such as Microsoft Entra ID, Storage, Virtual Machines, networking, Key Vault and Microsoft Defender for Cloud, were not checked.",
        "這次掃描只檢查了身分與存取（IAM）角色設定。其他 Azure 服務（例如 Microsoft Entra ID、儲存體、虛擬機器、網路、Key Vault、適用於雲端的 Microsoft Defender）沒有檢查。",
    ),
    (
        "This scan ran four identity and access (IAM) checks only: audit logging, service-account roles granted at the project level, and separation of duties for KMS and service-account roles. Other IAM settings and other Google Cloud services were not checked.",
        "這次掃描只執行了四項身分與存取（IAM）檢查：稽核記錄、在專案層級授予的服務帳戶角色，以及 KMS 與服務帳戶角色的職責分離。其他 IAM 設定與其他 Google Cloud 服務沒有檢查。",
    ),
    (
        "This scan checked Microsoft Entra ID only. Other Microsoft 365 products, such as Exchange Online, Defender for Office 365, SharePoint and OneDrive, and Teams, were not checked.",
        "這次掃描只檢查了 Microsoft Entra ID。其他 Microsoft 365 產品（例如 Exchange Online、Defender for Office 365、SharePoint 與 OneDrive、Teams）沒有檢查。",
    ),
    (
        "Run a full Prowler scan of this account.",
        "請對這個帳號執行完整的 Prowler 掃描。",
    ),
    (
        "Run a full Prowler scan of this subscription.",
        "請對這個訂用帳戶執行完整的 Prowler 掃描。",
    ),
    (
        "Run a full Prowler scan of this Google Cloud project.",
        "請對這個 Google Cloud 專案執行完整的 Prowler 掃描。",
    ),
    (
        "Run ScubaGear with all products for this tenant.",
        "請對這個租用戶執行包含所有產品的 ScubaGear 掃描。",
    ),
    (
        "Some controls in scope were not evaluated, so their state is unknown.",
        "範圍內有部分控制項未經評估，因此狀態未知。",
    ),
    (
        "Check these controls by hand.",
        "請以人工方式檢查這些控制項。",
    ),
    (
        "The approved rate limit refused some of this check's connections, so part of the check never reached the target.",
        "核准的速率限制拒絕了這項檢查的部分連線，因此部分檢查未能送達目標。",
    ),
    (
        "Connections this check attempted outside the approved scope were refused.",
        "這項檢查嘗試在核准範圍以外建立的連線已被拒絕。",
    ),
    (
        "Whether any of this check's connections were refused was not recorded.",
        "這項檢查是否有連線遭到拒絕，並未留下記錄。",
    ),
];

/// One sentence of a coverage row, in Traditional Chinese, or `None` when this
/// product did not author it.
pub fn coverage_gap_prose_zh_hant(english: &str) -> Option<String> {
    const REVIEW_BASE: &str =
        "Maester evaluated this control but did not return a pass or fail verdict.";
    let trimmed = english.trim();
    if let Some(detail) = trimmed.strip_prefix(&format!("{REVIEW_BASE} Upstream detail: "))
        && !detail.is_empty()
    {
        let base = lookup(REVIEW_BASE)?;
        return Some(format!("{base}上游詳細資料：{detail}"));
    }
    // Six reasons gain a diagnostic code when the task recorded one. It is the
    // scanner's own code and stays verbatim; only the sentence around it moves.
    if let Some((head, code)) = trimmed
        .strip_suffix('.')
        .and_then(|rest| rest.rsplit_once(" Diagnostic code: "))
    {
        // `stable_task_reason` appends to a sentence that already ends in a
        // period, so the head is a complete key on its own.
        let base = lookup(head)?;
        return Some(format!("{base}診斷代碼：{code}。"));
    }
    // The stale-knowledge reason carries the support date the run recorded.
    // Same split as the diagnostic code above: the date is data and stays
    // verbatim, only the sentence around it moves.
    if let Some((head, ended)) = trimmed
        .strip_suffix('.')
        .and_then(|rest| rest.rsplit_once(" Support ended: "))
    {
        let base = lookup(head)?;
        return Some(format!("{base}支援結束日期：{ended}。"));
    }
    // A gateway refusal count is data the cleanup record measured. Same split
    // as the support date: the number stays verbatim, only the sentence moves.
    if let Some((head, count)) = trimmed
        .strip_suffix('.')
        .and_then(|rest| rest.rsplit_once(" Refused connections: "))
        && !count.is_empty()
        && count.bytes().all(|byte| byte.is_ascii_digit())
    {
        let base = lookup(head)?;
        return Some(format!("{base}拒絕的連線：{count}。"));
    }
    // Unevaluated controls are counted by kind. Each count is the engine's and
    // stays verbatim; each kind is this product's wording.
    if let Some((head, items)) = trimmed
        .strip_suffix('.')
        .and_then(|rest| rest.rsplit_once(" Not evaluated: "))
        && !items.is_empty()
    {
        let base = lookup(head)?;
        return Some(format!(
            "{base}未評估：{}。",
            unevaluated_control_items_zh_hant(items)
        ));
    }
    lookup(trimmed)
}

/// The kinds of unevaluated control the Microsoft 365 adapters count, in
/// Traditional Chinese. `UNEVALUATED_CONTROL_KINDS` in `findingNarrative.ts`
/// is the twin.
const UNEVALUATED_CONTROL_KINDS: &[(&str, &str)] = &[
    ("left without an automated verdict", "未回傳自動判定"),
    ("omitted by configuration", "依設定略過"),
    ("could not be evaluated", "無法評估"),
    ("skipped", "已略過"),
    ("not run", "未執行"),
    (
        "reported by the engine but not carried into results",
        "掃描工具已回報，但未帶入結果",
    ),
    (
        "not accounted for by any reported category",
        "未計入任何已回報類別",
    ),
];

/// "20 left without an automated verdict, 5 could not be evaluated", item by
/// item. An item another build wrote keeps its own text.
fn unevaluated_control_items_zh_hant(items: &str) -> String {
    items
        .split(", ")
        .map(|item| {
            UNEVALUATED_CONTROL_KINDS
                .iter()
                .find_map(|(english, chinese)| {
                    let count = item.strip_suffix(english)?.strip_suffix(' ')?;
                    is_ascii_number(count).then(|| format!("{count} {chinese}"))
                })
                .unwrap_or_else(|| item.to_owned())
        })
        .collect::<Vec<_>>()
        .join("、")
}

fn lookup(english: &str) -> Option<String> {
    COVERAGE_GAP_PROSE
        .iter()
        .find(|(candidate, _)| *candidate == english)
        .map(|(_, chinese)| (*chinese).to_owned())
}

pub fn priority_reason_english(english: &str) -> String {
    const LEGACY_INTERNET: &str = "An affected asset is marked internet-exposed, and all retained source attribution for that asset is non-questionnaire.";
    const LEGACY_SENSITIVE: &str = "An affected asset is marked sensitive, all retained source attribution for that asset is non-questionnaire, and the case questionnaire separately records sensitive-data context.";
    const LEGACY_UNRATED_PREFIX: &str = "Severity remains Unknown because ";
    const LEGACY_UNRATED_TAIL: &str = " did not assign one; human review is required.";
    let trimmed = english.trim();
    if trimmed == PASSWORD_COMPOSITION_ORDER_REASON || trimmed == PASSWORD_EXPIRY_ORDER_REASON {
        return english.to_owned();
    }
    if trimmed == LEGACY_INTERNET {
        return crate::prioritization::INTERNET_REASON.to_owned();
    }
    if trimmed == LEGACY_SENSITIVE {
        return crate::prioritization::SENSITIVE_REASON.to_owned();
    }
    if let Some(engine) = trimmed
        .strip_prefix(LEGACY_UNRATED_PREFIX)
        .and_then(|rest| rest.strip_suffix(LEGACY_UNRATED_TAIL))
        .filter(|engine| !engine.is_empty())
    {
        return format!("Severity is Unknown because {engine} did not provide a rating.");
    }
    english
        .replace(
            "a credential detector match that this product does not verify",
            "a credential detector match",
        )
        .replace(
            "an unverified credential detector match",
            "a credential detector match",
        )
        .replace(
            "an unverified pattern or detector match",
            "a pattern or detector match",
        )
}

pub fn priority_reason_zh_hant(english: &str) -> String {
    let normalized = priority_reason_english(english);
    let trimmed = normalized.trim();
    if trimmed == PASSWORD_COMPOSITION_ORDER_REASON {
        return PASSWORD_COMPOSITION_ORDER_REASON_ZH_HANT.to_owned();
    }
    if trimmed == PASSWORD_EXPIRY_ORDER_REASON {
        return PASSWORD_EXPIRY_ORDER_REASON_ZH_HANT.to_owned();
    }
    if trimmed == ENGLISH_EVIDENCE_REASON {
        return "已附上掃描工具的直接證據。".to_owned();
    }
    if trimmed == ENGLISH_EXPOSURE_OBSERVATION_REASON {
        return "這是可連線服務的盤點觀察，不是漏洞。".to_owned();
    }
    if trimmed == crate::prioritization::INTERNET_REASON {
        return "受影響的資產可從網際網路存取。".to_owned();
    }
    if trimmed == crate::prioritization::SENSITIVE_REASON {
        return "受影響的資產含有敏感資料，因此問題造成的影響可能更高。".to_owned();
    }
    const UNRATED_PREFIX: &str = "Severity is Unknown because ";
    const UNRATED_TAIL: &str = " did not provide a rating.";
    if let Some(engine) = trimmed
        .strip_prefix(UNRATED_PREFIX)
        .and_then(|rest| rest.strip_suffix(UNRATED_TAIL))
        .filter(|engine| !engine.is_empty())
    {
        return format!("嚴重程度為未知，因為 {engine} 未提供評級。");
    }
    // The engine's own raw severity word, kept verbatim. Restating "high" as
    // 高 would stop it matching what the reader sees in the engine's own output.
    if let Some(value) = trimmed
        .strip_prefix("Source severity: ")
        .filter(|value| !value.is_empty())
    {
        return format!("來源工具評定的嚴重程度：{value}");
    }
    if let Some(value) = trimmed
        .strip_prefix("Source confidence: ")
        .filter(|value| !value.is_empty())
    {
        return format!("來源工具評定的信心：{value}");
    }
    const CONFIDENCE_DERIVED: &str = "Confidence derived from ";
    const CONFIDENCE_TAIL: &str = " reports no confidence of its own.";
    if let Some(rest) = trimmed
        .strip_prefix(CONFIDENCE_DERIVED)
        .and_then(|rest| rest.strip_suffix(CONFIDENCE_TAIL))
    {
        let Some((basis_text, engine)) = rest.rsplit_once("; ") else {
            return normalized;
        };
        let Some(code) = ALL_CONFIDENCE_BASIS_CODES
            .into_iter()
            .find(|code| confidence_basis_english(*code) == basis_text)
        else {
            return normalized;
        };
        if engine.is_empty() {
            return normalized;
        }
        return format!(
            "信心是由{}推導而來；{engine} 本身不提供信心評定。",
            confidence_basis_zh_hant(code)
        );
    }
    const DERIVED: &str = "Severity derived from ";
    const TAIL: &str = " reports no severity of its own.";
    let Some(rest) = trimmed.strip_prefix(DERIVED) else {
        return normalized;
    };
    let Some(rest) = rest.strip_suffix(TAIL) else {
        return normalized;
    };
    // No basis text contains "; ", so the last one separates basis from engine.
    let Some((basis_text, engine)) = rest.rsplit_once("; ") else {
        return normalized;
    };
    let Some(code) = ALL_SEVERITY_BASIS_CODES
        .into_iter()
        .find(|code| basis_english(*code) == basis_text)
    else {
        return normalized;
    };
    if engine.is_empty() {
        return normalized;
    }
    format!(
        "嚴重程度是由{}推導而來；{engine} 本身不提供嚴重程度。",
        basis(code)
    )
}

/// The benchmark line a card shows for one scanner.
///
/// Entries that name the same benchmark item are one group, in the order the
/// scanner reported them. Versions inside a group stay in that order, without
/// duplicates, joined by `/`. At most three groups are named.
pub fn benchmark_line_english(engine: &str, benchmarks: &[BenchmarkReference]) -> Option<String> {
    benchmark_line(engine, benchmarks, false)
}

/// Traditional Chinese form of [`benchmark_line_english`].
pub fn benchmark_line_zh_hant(engine: &str, benchmarks: &[BenchmarkReference]) -> Option<String> {
    benchmark_line(engine, benchmarks, true)
}

struct BenchmarkGroup {
    name: String,
    reference: String,
    versions: Vec<String>,
}

fn benchmark_groups(benchmarks: &[BenchmarkReference]) -> Vec<BenchmarkGroup> {
    let mut groups: Vec<BenchmarkGroup> = Vec::new();
    for benchmark in benchmarks {
        if let Some(group) = groups
            .iter_mut()
            .find(|group| group.name == benchmark.name && group.reference == benchmark.reference)
        {
            if !group
                .versions
                .iter()
                .any(|version| version == &benchmark.version)
            {
                group.versions.push(benchmark.version.clone());
            }
        } else {
            groups.push(BenchmarkGroup {
                name: benchmark.name.clone(),
                reference: benchmark.reference.clone(),
                versions: vec![benchmark.version.clone()],
            });
        }
    }
    groups
}

fn benchmark_line(
    engine: &str,
    benchmarks: &[BenchmarkReference],
    zh_hant: bool,
) -> Option<String> {
    if benchmarks.is_empty() {
        return None;
    }
    let groups = benchmark_groups(benchmarks);
    let shown = groups.len().min(3);
    let extra = groups.len() - shown;
    let mut parts = Vec::with_capacity(shown);
    for group in groups.iter().take(shown) {
        let versions = group.versions.join("/");
        if zh_hant {
            parts.push(format!(
                "{} {} 第 {} 項",
                group.name, versions, group.reference
            ));
        } else {
            parts.push(format!(
                "{} {} item {}",
                group.name, versions, group.reference
            ));
        }
    }
    let mut line = if zh_hant {
        parts.join("；")
    } else {
        parts.join("; ")
    };
    if extra > 0 {
        if zh_hant {
            line.push_str(&format!("，另有 {extra} 項"));
        } else {
            line.push_str(&format!(" and {extra} more"));
        }
    }
    if zh_hant {
        line.push_str(&format!("（{engine} 回報）"));
    } else {
        line.push_str(&format!(" (reported by {engine})"));
    }
    Some(line)
}

/// "After an approved manual change, rerun {engine} ... source rule {rule}
/// is no longer reported."
///
/// Read back off the sentence for the same reason `engine_name_from` is: the
/// engine's display name and the source rule id are the engine's own strings
/// and have to appear in the Chinese exactly as they do in the English.
/// Returns the English unchanged for any sentence not in this shape.
///
/// When the rule is opaque -- a UUID, as KICS names every query -- and the
/// finding carries a title, the sentence names the title instead: the rule
/// stays in the evidence, and the reader recognises the title.
fn verification_parts(english: &str) -> Option<(&str, &str)> {
    const LEGACY_RERUN: &str = "After an approved manual change, rerun ";
    const LEGACY_SCOPE: &str = " with the same authorized scope and confirm that source rule ";
    const RERUN: &str = "Rerun ";
    const SCOPE: &str = " with the same scope after the change and confirm that source rule ";
    const TAIL: &str = " is no longer reported.";
    let trimmed = english.trim();
    let (prefix, scope) = if trimmed.starts_with(LEGACY_RERUN) {
        (LEGACY_RERUN, LEGACY_SCOPE)
    } else {
        (RERUN, SCOPE)
    };
    let rest = trimmed.strip_prefix(prefix)?.strip_suffix(TAIL)?;
    let (engine, rule) = rest.split_once(scope)?;
    if engine.is_empty() || rule.is_empty() {
        return None;
    }
    Some((engine, rule))
}

/// A source rule is opaque when it is a UUID: exactly five `-`-separated
/// groups of 8, 4, 4, 4 and 12 ASCII hex digits, in either case. KICS names
/// every query this way; the id tells a reader nothing and cannot be
/// compared by eye. No dependency is added for this -- it is a plain split
/// and a length and character check.
fn is_opaque_rule_id(rule: &str) -> bool {
    const GROUP_LENGTHS: [usize; 5] = [8, 4, 4, 4, 12];
    let mut groups = rule.split('-');
    for expected_len in GROUP_LENGTHS {
        let Some(group) = groups.next() else {
            return false;
        };
        if group.len() != expected_len || !group.chars().all(|c| c.is_ascii_hexdigit()) {
            return false;
        }
    }
    groups.next().is_none()
}

/// The title to name instead of the rule: only when the rule is opaque and a
/// non-empty trimmed title is actually available. `None` keeps today's
/// source-rule sentence.
fn opaque_rule_title<'a>(rule: &str, title: Option<&'a str>) -> Option<&'a str> {
    let title = title?.trim();
    (!title.is_empty() && is_opaque_rule_id(rule)).then_some(title)
}

pub fn verification_english(english: &str, title: Option<&str>) -> String {
    verification_parts(english).map_or_else(
        || english.to_owned(),
        |(engine, rule)| match opaque_rule_title(rule, title) {
            Some(title) => format!(
                "Rerun {engine} with the same scope after the change and confirm that \u{201c}{title}\u{201d} is no longer reported."
            ),
            None => format!("Rerun {engine} with the same scope after the change and confirm that source rule {rule} is no longer reported."),
        },
    )
}

pub fn verification_zh_hant(english: &str, title: Option<&str>) -> String {
    verification_parts(english).map_or_else(
        || english.to_owned(),
        |(engine, rule)| match opaque_rule_title(rule, title) {
            Some(title) => {
                format!("變更後以相同範圍重新執行 {engine}，並確認「{title}」不再被回報。")
            }
            None => {
                format!("變更後以相同範圍重新執行 {engine}，並確認來源規則 {rule} 不再被回報。")
            }
        },
    )
}

/// Direct policy-specific action.
const IAM_PRINCIPAL_PREVIEW_LIMIT: usize = 6;

pub fn aws_iam_policy_source_label_english(source: AwsIamPolicySource) -> &'static str {
    match source {
        AwsIamPolicySource::AwsManaged => "AWS-managed",
        AwsIamPolicySource::CustomerManaged => "Customer-managed",
        AwsIamPolicySource::Inline => "Inline",
    }
}

pub fn aws_iam_policy_source_label_zh_hant(source: AwsIamPolicySource) -> &'static str {
    match source {
        AwsIamPolicySource::AwsManaged => "AWS 受管",
        AwsIamPolicySource::CustomerManaged => "客戶受管",
        AwsIamPolicySource::Inline => "內嵌",
    }
}

fn iam_principal_labels(details: &AwsIamPolicyFindingDetails, locale: &str) -> Vec<String> {
    let labels = if locale == "zh-Hant" {
        ("角色", "群組", "使用者")
    } else {
        ("role", "group", "user")
    };
    details
        .attached_to
        .roles
        .iter()
        .map(|name| format!("{} {name}", labels.0))
        .chain(
            details
                .attached_to
                .groups
                .iter()
                .map(|name| format!("{} {name}", labels.1)),
        )
        .chain(
            details
                .attached_to
                .users
                .iter()
                .map(|name| format!("{} {name}", labels.2)),
        )
        .collect()
}

/// The attached principals a reader sees, and how many there are. English
/// prose downstream has to agree in number with a one-principal attachment,
/// which is the common case for an inline or customer-managed policy.
fn iam_principal_summary(
    details: &AwsIamPolicyFindingDetails,
    locale: &str,
) -> Option<(String, usize)> {
    let labels = iam_principal_labels(details, locale);
    if labels.is_empty() {
        return None;
    }
    let count = labels.len();
    let retained = labels
        .iter()
        .take(IAM_PRINCIPAL_PREVIEW_LIMIT)
        .cloned()
        .collect::<Vec<_>>()
        .join(if locale == "zh-Hant" { "、" } else { ", " });
    let omitted = count.saturating_sub(IAM_PRINCIPAL_PREVIEW_LIMIT);
    let summary = if omitted == 0 {
        retained
    } else if locale == "zh-Hant" {
        format!("{retained}，以及另外 {omitted} 個主體")
    } else if omitted == 1 {
        format!("{retained}, and 1 more principal")
    } else {
        format!("{retained}, and {omitted} more principals")
    };
    Some((summary, count))
}

/// Product-owned English next action for bounded Cloudsplaining evidence.
/// The source engine still owns the finding, rating, and attached-principal
/// facts; this function only tells a beginner what kind of manual change fits
/// the policy source.
pub fn aws_iam_policy_action_english(
    _expert_type: &str,
    details: &AwsIamPolicyFindingDetails,
) -> String {
    let principals = iam_principal_summary(details, "en");
    let one_principal = principals.as_ref().is_some_and(|(_, count)| *count == 1);
    let action = match (
        details.policy_source,
        principals.as_ref().map(|(summary, _)| summary.as_str()),
        details.attached_to.complete,
    ) {
        (AwsIamPolicySource::AwsManaged, Some(principals), _) => format!(
            "Replace AWS-managed policy {} with a narrower policy on {principals}, or detach it where it is not needed; AWS-managed policies cannot be edited by this account",
            details.policy_name
        ),
        (AwsIamPolicySource::AwsManaged, None, true) => format!(
            "Keep AWS-managed policy {} detached and choose a narrower policy before attaching it; AWS-managed policies cannot be edited by this account",
            details.policy_name
        ),
        (AwsIamPolicySource::AwsManaged, None, false) => format!(
            "Identify the current roles, groups, and users attached to AWS-managed policy {}, then replace it with a narrower policy or detach it where it is not needed; AWS-managed policies cannot be edited by this account",
            details.policy_name
        ),
        (AwsIamPolicySource::CustomerManaged, Some(principals), _) => format!(
            "Narrow customer-managed policy {} and verify that {principals} {} only the permissions they need",
            details.policy_name,
            if one_principal { "retains" } else { "retain" }
        ),
        (AwsIamPolicySource::CustomerManaged, None, true) => format!(
            "Narrow customer-managed policy {} before it is attached or reused",
            details.policy_name
        ),
        (AwsIamPolicySource::CustomerManaged, None, false) => format!(
            "Identify the current attachments to customer-managed policy {}, then narrow it and verify that each principal retains only the permissions it needs",
            details.policy_name
        ),
        (AwsIamPolicySource::Inline, Some(principals), _) => format!(
            "Narrow inline policy {} directly on {principals}",
            details.policy_name
        ),
        (AwsIamPolicySource::Inline, None, _) => format!(
            "Identify where inline policy {} is owned and narrow it there before reuse",
            details.policy_name
        ),
    };
    let incomplete =
        (!details.attached_to.complete).then_some(" Confirm the current IAM attachments first.");
    format!("{action}.{}", incomplete.unwrap_or_default())
}

fn aws_iam_policy_action_zh_hant(
    _expert_type: &str,
    details: &AwsIamPolicyFindingDetails,
) -> String {
    let principals = iam_principal_summary(details, "zh-Hant");
    let action = match (
        details.policy_source,
        principals.as_ref().map(|(summary, _)| summary.as_str()),
        details.attached_to.complete,
    ) {
        (AwsIamPolicySource::AwsManaged, Some(principals), _) => format!(
            "在{principals}上將 AWS 受管政策 {} 改為權限較小的政策；若不需要則解除附加。AWS 受管政策無法由此帳戶直接編輯",
            details.policy_name
        ),
        (AwsIamPolicySource::AwsManaged, None, true) => format!(
            "確認 AWS 受管政策 {} 維持未附加狀態；之後如有需要，應選用權限較小的政策。AWS 受管政策無法由此帳戶直接編輯",
            details.policy_name
        ),
        (AwsIamPolicySource::AwsManaged, None, false) => format!(
            "先確認目前有哪些角色、群組與使用者附加了 AWS 受管政策 {}，再改用權限較小的政策；若不需要則解除附加。AWS 受管政策無法由此帳戶直接編輯",
            details.policy_name
        ),
        (AwsIamPolicySource::CustomerManaged, Some(principals), _) => format!(
            "縮小客戶受管政策 {} 的權限，並確認{principals}只保留工作所需權限",
            details.policy_name
        ),
        (AwsIamPolicySource::CustomerManaged, None, true) => format!(
            "在客戶受管政策 {} 再次附加或使用前縮小其權限",
            details.policy_name
        ),
        (AwsIamPolicySource::CustomerManaged, None, false) => format!(
            "先確認客戶受管政策 {} 目前附加到哪些 IAM 主體，再縮小政策權限，並確認每個主體只保留工作所需權限",
            details.policy_name
        ),
        (AwsIamPolicySource::Inline, Some(principals), _) => format!(
            "直接在{principals}上縮小內嵌政策 {} 的權限",
            details.policy_name
        ),
        (AwsIamPolicySource::Inline, None, _) => format!(
            "確認內嵌政策 {} 所屬的 IAM 主體，並在再次使用前於該處縮小權限",
            details.policy_name
        ),
    };
    let incomplete = (!details.attached_to.complete).then_some("請先核對目前的 IAM 附加關係。");
    format!("{}。{}", action, incomplete.unwrap_or_default())
}

pub fn action_english(
    english: &str,
    family: Option<FindingFamily>,
    aws_iam_policy: Option<&AwsIamPolicyFindingDetails>,
) -> String {
    if let Some(details) = aws_iam_policy {
        return aws_iam_policy_action_english("", details);
    }
    family.map_or_else(
        || {
            let Some((_, direct)) = english.rsplit_once(", then plan and approve ") else {
                return english.to_owned();
            };
            let mut direct = direct.trim().to_owned();
            if let Some(first) = direct.get_mut(0..1) {
                first.make_ascii_uppercase();
            }
            direct
        },
        |family| format!("{}.", remedy_english(family)),
    )
}

pub fn action_zh_hant(
    english: &str,
    expert_type: &str,
    family: Option<FindingFamily>,
    aws_iam_policy: Option<&AwsIamPolicyFindingDetails>,
) -> String {
    if let Some(details) = aws_iam_policy {
        return aws_iam_policy_action_zh_hant(expert_type, details);
    }
    let Some(family) = family else {
        return action_english(english, None, None);
    };
    format!("{}。", remedy(family))
}

/// Report-layer action: the family's remedy, unless every attached check
/// failed to produce observations, in which case the reader is told to
/// finish that check before changing anything.
pub fn finding_next_action_english(
    english: &str,
    family: Option<FindingFamily>,
    aws_iam_policy: Option<&AwsIamPolicyFindingDetails>,
    unconfirmed_by_coverage: bool,
) -> String {
    if unconfirmed_by_coverage {
        INCOMPLETE_CHECK_CONFIRM_ACTION.to_owned()
    } else {
        action_english(english, family, aws_iam_policy)
    }
}

pub fn finding_next_action_zh_hant(
    english: &str,
    expert_type: &str,
    family: Option<FindingFamily>,
    aws_iam_policy: Option<&AwsIamPolicyFindingDetails>,
    unconfirmed_by_coverage: bool,
) -> String {
    if unconfirmed_by_coverage {
        INCOMPLETE_CHECK_CONFIRM_ACTION_ZH_HANT.to_owned()
    } else {
        action_zh_hant(english, expert_type, family, aws_iam_policy)
    }
}

/// The problem heading a reader sees.
///
/// ScubaGear and Maester name a control for the state it was checking, and
/// only a control the tenant failed becomes a finding. Printed unchanged,
/// that title reads as the opposite of the result. Other families already
/// title a finding with the failure or a neutral rule name, so they stay as
/// the scanner wrote them.
pub fn finding_headline_english(title: &str, family: Option<FindingFamily>) -> String {
    match family {
        Some(FindingFamily::Microsoft365) => format!("Requirement not met: {title}"),
        _ => title.to_owned(),
    }
}

/// The Traditional Chinese form of [`finding_headline_english`].
pub fn finding_headline_zh_hant(title: &str, family: Option<FindingFamily>) -> String {
    match family {
        Some(FindingFamily::Microsoft365) => format!("未符合要求：{title}"),
        _ => title.to_owned(),
    }
}

/// The sentence in front of a next step that covers more than one problem.
///
/// `shared_fix` is true when every problem is fixed by the one change the
/// step names. A family-level instruction is the same kind of change in
/// different places, and the sentence says so instead of calling them one fix.
pub fn step_group_lead_english(count: usize, shared_fix: bool, reason: &str) -> String {
    if shared_fix {
        format!("{count} problems name this same fix. The first is {reason}")
    } else {
        format!(
            "{count} related problems call for this kind of change; each needs its own fix. The first is {reason}"
        )
    }
}

/// The Traditional Chinese form of [`step_group_lead_english`].
pub fn step_group_lead_zh_hant(count: usize, shared_fix: bool, reason: &str) -> String {
    if shared_fix {
        format!("有 {count} 項問題指向同一個修復方式，第一項是 {reason}")
    } else {
        format!("有 {count} 項相關問題需要這類處理，每一項都要分別修正；第一項是 {reason}")
    }
}

/// How a reader confirms a next step.
///
/// One problem keeps that finding's own verification sentence, which names
/// the scanner and the source rule. Several problems do not share one rule,
/// so the sentence asks for the same scan again rather than the lead
/// finding's rule. `title` is the scanner's own title: a verification
/// sentence uses it only when the source rule is an opaque id.
pub fn step_confirmation_english(
    verification: Option<&str>,
    title: &str,
    problems: usize,
) -> String {
    if problems > 1 {
        return "Rerun the same scan after the changes and confirm these problems are no longer reported.".to_owned();
    }
    match verification
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        Some(english) => verification_english(english, Some(title)),
        None => {
            "Rerun the same scan after the change and confirm this problem is no longer reported."
                .to_owned()
        }
    }
}

/// The Traditional Chinese form of [`step_confirmation_english`].
pub fn step_confirmation_zh_hant(
    verification: Option<&str>,
    title: &str,
    problems: usize,
) -> String {
    if problems > 1 {
        return "修正後以相同範圍重新掃描，確認這些問題不再被回報。".to_owned();
    }
    match verification
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        Some(english) => verification_zh_hant(english, Some(title)),
        None => "修正後以相同範圍重新掃描，確認這項問題不再被回報。".to_owned(),
    }
}

/// A [`parse_location_coordinate`] split: the leading path, then the line,
/// column and resource captured from the coordinate tail, each present only
/// when the raw location carried that piece.
type LocationCoordinate<'a> = (&'a str, Option<&'a str>, Option<&'a str>, Option<&'a str>);

/// The coordinate tail `source_coordinate_location` (`src-tauri/src/adapters/mod.rs`)
/// appends to a path: `path[:line=N][:column=N][:resource=R]`, each piece
/// optional and in that order. Splits `trimmed` at the first colon where such
/// a tail runs to the end of the string -- the split the lazy
/// `^(.*?)(?::line=(\d+))?(?::column=(\d+))?(?::resource=(.+))?$` in the
/// TypeScript twin finds. Returns `None` when there is no such colon, or the
/// first one leaves an empty path: a plain path, a URL, a `host:port` pair,
/// `package:name`.
fn parse_location_coordinate(trimmed: &str) -> Option<LocationCoordinate<'_>> {
    fn number<'a>(cursor: &mut &'a str, prefix: &str) -> Option<&'a str> {
        let rest = cursor.strip_prefix(prefix)?;
        let end = rest
            .find(|character: char| !character.is_ascii_digit())
            .unwrap_or(rest.len());
        if end == 0 {
            return None;
        }
        let (digits, rest) = rest.split_at(end);
        *cursor = rest;
        Some(digits)
    }

    let (start, line, column, resource) = trimmed.match_indices(':').find_map(|(start, _)| {
        let mut cursor = &trimmed[start..];
        let line = number(&mut cursor, ":line=");
        let column = number(&mut cursor, ":column=");
        let resource = cursor
            .strip_prefix(":resource=")
            .filter(|rest| !rest.is_empty());
        (resource.is_some() || cursor.is_empty()).then_some((start, line, column, resource))
    })?;
    (start > 0).then(|| (&trimmed[..start], line, column, resource))
}

/// The place `raw` names, with the position worded by `position`; see
/// [`location_english`].
fn location_text(
    raw: &str,
    position: impl Fn(Option<&str>, Option<&str>) -> Option<String>,
) -> String {
    let trimmed = raw.trim();
    let Some((path, line, column, resource)) = parse_location_coordinate(trimmed) else {
        // A root, `./` or `../` in either separator, or a drive letter: the
        // same test `findingLocationText` makes.
        let without_dots = trimmed
            .strip_prefix("..")
            .or_else(|| trimmed.strip_prefix('.'))
            .unwrap_or(trimmed);
        let path_like = without_dots.starts_with(['/', '\\'])
            || matches!(
                trimmed.as_bytes(),
                [drive, b':', b'/' | b'\\', ..] if drive.is_ascii_alphabetic()
            );
        return if path_like {
            report_file_path(trimmed)
        } else {
            raw.to_owned()
        };
    };
    let path = report_file_path(path);
    let mut parts = vec![path.clone()];
    parts.extend(position(line, column));
    if let Some(resource) = resource {
        let mut names = Vec::new();
        for part in resource
            .split(',')
            .map(str::trim)
            .filter(|part| !part.is_empty() && !part.starts_with("similarity:"))
            .map(|part| part.strip_prefix("resource:").unwrap_or(part).trim())
            .filter(|part| !part.is_empty())
            .filter_map(|part| resource_label(part, &path))
        {
            if !names.contains(&part) {
                names.push(part);
            }
        }
        if !names.is_empty() {
            parts.push(names.join(", "));
        }
    }
    parts.join(" · ")
}

/// Normalize only the report-facing spelling of a source path. The original
/// scanner location remains unchanged in the evidence details.
fn report_file_path(raw: &str) -> String {
    let mut path = raw.replace('\\', "/");
    while let Some(relative) = path.strip_prefix("./") {
        path = relative.to_owned();
    }
    if path.starts_with('/') && !path.starts_with("//") {
        path = path.trim_start_matches('/').to_owned();
    }
    if path.is_empty() {
        raw.to_owned()
    } else {
        path
    }
}

/// Path and starting line of a scanner location, normalized the way the report
/// prints a file path. `None` when the location has no line.
pub(crate) fn normalized_source_path_line(raw: &str) -> Option<(String, u32)> {
    let (path, line, _, _) = parse_location_coordinate(raw.trim())?;
    let line = line?.parse().ok()?;
    Some((report_file_path(path), line))
}

/// The resource label worth printing after `path`, if any. KICS writes `n/a`
/// when a result has no resource, and Checkov names a Dockerfile resource
/// after the file (`/Dockerfile.`) or the file and an instruction
/// (`/Dockerfile.EXPOSE`); only the instruction adds anything to the path
/// already printed in front of it.
fn resource_label(part: &str, path: &str) -> Option<String> {
    if part == "n/a" {
        return None;
    }
    match report_file_path(part).strip_prefix(path) {
        Some("") => None,
        Some(rest) => match rest.strip_prefix('.') {
            Some("") => None,
            Some(instruction) => Some(instruction.to_owned()),
            None => Some(part.to_owned()),
        },
        None => Some(part.to_owned()),
    }
}

/// Reads a stored scanner location as a place, not the coordinate string it
/// is kept in. KICS's `R` carries a `resource:<name>` label and/or a
/// `similarity:<64-hex hash>` deduplication key, joined by a comma; that hash
/// is KICS's own deduplication key, not something a reader needs in order to
/// find the spot, so it is dropped here and kept verbatim in the technical
/// details instead, as is a resource label that says `n/a` or only repeats
/// the path (see `resource_label`). A plain path receives the same
/// separator/root cleanup; URLs, endpoints, package coordinates, and other
/// non-path locations remain untouched. A coordinate with an empty leading
/// path is likewise left raw.
///
/// `findingLocationText` in `src/findingNarrative.ts` is the twin of this
/// function and of [`location_zh_hant`]; the two must keep producing
/// byte-identical output for the same locale.
pub fn location_english(raw: &str) -> String {
    location_text(raw, |line, column| match (line, column) {
        (Some(line), Some(column)) => Some(format!("line {line}, column {column}")),
        (Some(line), None) => Some(format!("line {line}")),
        (None, Some(column)) => Some(format!("column {column}")),
        (None, None) => None,
    })
}

/// The Traditional Chinese form of [`location_english`].
pub fn location_zh_hant(raw: &str) -> String {
    location_text(raw, |line, column| match (line, column) {
        (Some(line), Some(column)) => Some(format!("第 {line} 行第 {column} 欄")),
        (Some(line), None) => Some(format!("第 {line} 行")),
        (None, Some(column)) => Some(format!("第 {column} 欄")),
        (None, None) => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_opaque_source_rule_gives_way_to_the_finding_title() {
        // Mirrors "a UUID source rule gives way to the finding's title in
        // the verification sentence" in tests/frontend/findingNarrative.test.ts
        // -- the two must stay identical.
        const UUID: &str = "38c5ee0d-7f22-4260-ab72-5073048df100";
        const TITLE: &str = "S3 Bucket ACL Allows Read Or Write to All Users";
        let current = format!(
            "Rerun KICS with the same scope after the change and confirm that source rule {UUID} is no longer reported."
        );
        let legacy = format!(
            "After an approved manual change, rerun KICS with the same authorized scope and confirm that source rule {UUID} is no longer reported."
        );
        let expected_en = format!(
            "Rerun KICS with the same scope after the change and confirm that \u{201c}{TITLE}\u{201d} is no longer reported."
        );
        let expected_zh = format!("變更後以相同範圍重新執行 KICS，並確認「{TITLE}」不再被回報。");

        for english in [current.as_str(), legacy.as_str()] {
            assert_eq!(verification_english(english, Some(TITLE)), expected_en);
            assert_eq!(verification_zh_hant(english, Some(TITLE)), expected_zh);
        }

        // An uppercase UUID is still opaque.
        let uppercase = format!(
            "Rerun KICS with the same scope after the change and confirm that source rule {} is no longer reported.",
            UUID.to_uppercase()
        );
        assert_eq!(verification_english(&uppercase, Some(TITLE)), expected_en);

        // No title, or a title that is only whitespace, keeps today's
        // source-rule sentence.
        assert_eq!(verification_english(&current, None), current);
        assert_eq!(verification_english(&current, Some("   ")), current);

        // A title is available, but the rule is not opaque -- today's
        // sentence still names the rule.
        for rule in [
            "CKV_AWS_20",
            "GHSA-3pqx-4fqf-j49f",
            "38c5ee0d-7f22-4260-ab72-5073048df10", // 11-digit last group
            "38c5ee0g-7f22-4260-ab72-5073048df100", // non-hex digit
        ] {
            let english = format!(
                "Rerun KICS with the same scope after the change and confirm that source rule {rule} is no longer reported."
            );
            assert_eq!(verification_english(&english, Some(TITLE)), english);
            assert!(
                verification_zh_hant(&english, Some(TITLE)).contains(&format!("來源規則 {rule}"))
            );
        }
    }

    #[test]
    fn a_microsoft_365_heading_says_the_requirement_was_not_met() {
        let title = "Legacy authentication is blocked";
        assert_eq!(
            finding_headline_english(title, Some(FindingFamily::Microsoft365)),
            format!("Requirement not met: {title}")
        );
        assert_eq!(
            finding_headline_zh_hant(title, Some(FindingFamily::Microsoft365)),
            format!("未符合要求：{title}")
        );
        for family in [Some(FindingFamily::CloudPosture), None] {
            assert_eq!(finding_headline_english(title, family), title);
            assert_eq!(finding_headline_zh_hant(title, family), title);
        }
    }

    #[test]
    fn a_grouped_step_says_whether_the_problems_share_one_fix() {
        let reason = "Resource limits — High severity, High confidence";
        assert_eq!(
            step_group_lead_english(9, true, reason),
            format!("9 problems name this same fix. The first is {reason}")
        );
        assert_eq!(
            step_group_lead_english(9, false, reason),
            format!(
                "9 related problems call for this kind of change; each needs its own fix. The first is {reason}"
            )
        );
        assert_eq!(
            step_group_lead_zh_hant(9, true, reason),
            format!("有 9 項問題指向同一個修復方式，第一項是 {reason}")
        );
        assert_eq!(
            step_group_lead_zh_hant(9, false, reason),
            format!("有 9 項相關問題需要這類處理，每一項都要分別修正；第一項是 {reason}")
        );
    }

    #[test]
    fn confirmation_keeps_one_findings_guidance_and_names_the_scan_for_several() {
        const TITLE: &str = "S3 Bucket ACL Allows Read Or Write to All Users";
        let guidance = "Rerun KICS with the same scope after the change and confirm that source rule 38c5ee0d-7f22-4260-ab72-5073048df100 is no longer reported.";
        assert_eq!(
            step_confirmation_english(Some(guidance), TITLE, 1),
            verification_english(guidance, Some(TITLE))
        );
        assert_eq!(
            step_confirmation_zh_hant(Some(guidance), TITLE, 1),
            verification_zh_hant(guidance, Some(TITLE))
        );
        assert_eq!(
            step_confirmation_english(None, TITLE, 1),
            "Rerun the same scan after the change and confirm this problem is no longer reported."
        );
        assert_eq!(
            step_confirmation_english(Some("   "), TITLE, 1),
            "Rerun the same scan after the change and confirm this problem is no longer reported."
        );
        assert_eq!(
            step_confirmation_zh_hant(None, TITLE, 1),
            "修正後以相同範圍重新掃描，確認這項問題不再被回報。"
        );
        assert_eq!(
            step_confirmation_zh_hant(Some("   "), TITLE, 1),
            "修正後以相同範圍重新掃描，確認這項問題不再被回報。"
        );
        assert_eq!(
            step_confirmation_english(Some(guidance), TITLE, 4),
            "Rerun the same scan after the changes and confirm these problems are no longer reported."
        );
        assert_eq!(
            step_confirmation_zh_hant(Some(guidance), TITLE, 4),
            "修正後以相同範圍重新掃描，確認這些問題不再被回報。"
        );
    }

    #[test]
    fn control_mapping_rationale_lookup_translates_only_reviewed_catalog_prose() {
        let known = "Evidence that an identity has no registered multi-factor device is related to authenticating users and safeguarding authentication information.";
        assert_eq!(
            control_mapping_rationale_zh_hant(known),
            Some("某個身分未登記多重要素驗證裝置的證據，與驗證使用者及保護驗證資訊有關。".into())
        );
        assert_eq!(
            control_mapping_rationale_zh_hant("A rationale from another build."),
            None
        );
    }

    #[test]
    fn every_packaged_catalog_rationale_has_a_chinese_form() {
        // The exported report reads this same packaged catalog, so a
        // rationale added there without a Chinese form here would print
        // English in a Chinese report.
        const CATALOG: &str = include_str!("../../mappings/control-mappings.json");
        let catalog: serde_json::Value = serde_json::from_str(CATALOG).expect("packaged catalog");

        let entries = catalog["entries"].as_array().expect("entries");
        assert!(!entries.is_empty());
        let cwe_derived_controls = catalog["cwe_derived_controls"]
            .as_array()
            .expect("cwe_derived_controls");
        assert!(!cwe_derived_controls.is_empty());

        for rationale in entries
            .iter()
            .chain(cwe_derived_controls.iter())
            .map(|entry| entry["rationale"].as_str().expect("rationale"))
        {
            let chinese = control_mapping_rationale_zh_hant(rationale).unwrap_or_else(|| {
                panic!("no Traditional Chinese for catalog rationale: {rationale}")
            });
            assert!(
                chinese
                    .chars()
                    .any(|c| ('\u{4e00}'..='\u{9fff}').contains(&c)),
                "translation has no Han character: {chinese}"
            );
        }
    }

    #[test]
    fn data_quality_warning_lookup_translates_fixed_and_framed_prose_only() {
        assert_eq!(
            data_quality_warning_zh_hant(
                "The selected run has an inconsistent project identity. Report data: selected in-project record."
            ),
            Some("所選掃描輪次的專案識別資料不一致；報告資料：專案內所選記錄。".into())
        );
        assert_eq!(
            data_quality_warning_zh_hant(
                "Finding finding-user-value presentation detail: unavailable. Retained run observation: available."
            ),
            Some("問題 finding-user-value 呈現細節：無法取得；保留的輪次觀察：可用。".into())
        );
        assert_eq!(
            data_quality_warning_zh_hant("[redacted data-quality warning]"),
            None
        );
        assert_eq!(
            data_quality_warning_zh_hant("A warning from a later build."),
            None
        );
    }

    #[test]
    fn requested_limit_values_translate_known_units_and_preserve_identifiers() {
        for (name, value, expected) in [
            ("connection timeout", "250 ms", "250 毫秒"),
            ("application payload", "64 bytes", "64 位元組"),
            ("gitleaks execution timeout", "600 seconds", "600 秒"),
            (
                "asset-primary request rate",
                "5 per second, concurrency 2",
                "每秒 5 次，並行 2",
            ),
            ("endpoint", "127.0.0.1:443", "127.0.0.1:443"),
        ] {
            assert_eq!(requested_limit_value_zh_hant(name, value), expected);
        }
        assert_eq!(
            requested_limit_value_zh_hant("future limit", "value from another build"),
            "value from another build"
        );
    }

    #[test]
    fn coverage_record_detail_shapes_translate_without_changing_retained_values() {
        for (english, expected) in [
            (
                "The source area is explicitly outside this case: Legacy lab stays excluded. This is a scoped applicability statement, not a successful scan result.",
                "此來源範圍明確不在本案件內：Legacy lab stays excluded. 這是範圍適用性的說明，不是掃描成功的結果。",
            ),
            (
                "The source is connected and the latest attributable discovery returned no assets. This is not a successful scan result; 17 prior asset observation(s) remain retained. Latest provider discovery: provider_timeout: Provider response was late.",
                "來源已連線，且最近一次可歸屬的探索未傳回任何資產。這不是掃描成功的結果；仍保留 17 筆先前的資產觀察結果。 最近一次供應商探索：provider_timeout: Provider response was late.",
            ),
            (
                "The source is not currently connected (status: credentials_expired). Its present coverage is unknown; 17 previously attributed asset(s) are retained but do not make the source green.",
                "來源目前未連線（狀態：credentials_expired）。目前的涵蓋未知；仍保留 17 筆先前歸屬的資產，但這不會讓來源顯示為綠色。",
            ),
            (
                "The scan's frozen authorization evidence is incomplete: grant-1=historical_scope_snapshot_missing. Live grants are never used to reconstruct historical scan permission.",
                "掃描中凍結的授權證據不完整：grant-1=historical_scope_snapshot_missing。絕不會用現行授權重建過去的掃描權限。",
            ),
            (
                "All 2 compatible engine run(s) planned for this asset completed. This state is independent of how many findings were reported. Explicit stale-knowledge warning: scanner knowledge 2026-01-01 (support ended 2026-06-01). Completion proves execution, not current knowledge.",
                "為此資產規劃的 2 項相容掃描工具工作皆已完成。 此狀態與回報了多少個問題無關。 明確的過時知識警告：scanner knowledge 2026-01-01 (support ended 2026-06-01)。完成只證明已執行，不代表知識仍為最新。",
            ),
            (
                "All 1 planned task(s) for this asset completed their exact declared dimensions. This state is independent of how many findings were reported. Exact built-in localhost TCP attempt(s): 127.0.0.1:443=reachable. This records only those connection attempts; it does not establish that the service or computer is secure, and it does not cover other ports or hosts.",
                "為此資產規劃的 1 項工作，皆已完成各自明確宣告的檢查範圍。 此狀態與回報了多少個問題無關。 精確的內建 localhost TCP 嘗試：127.0.0.1:443=reachable。這只記錄這些連線嘗試；無法證明服務或電腦安全，也不涵蓋其他連接埠或主機。",
            ),
            (
                "The authorized scan is incomplete: scanner=failed. Only completed compatible catalog-engine runs or exact completed built-in tasks can produce scanned coverage.",
                "已授權的掃描未完成：scanner=failed。只有已完成且相容的目錄掃描工具工作，或精確完成的內建工作，才能產生已掃描涵蓋。",
            ),
        ] {
            assert_eq!(
                coverage_record_detail_zh_hant(english),
                Some(expected.to_owned())
            );
        }
        assert!(
            coverage_record_detail_zh_hant(
                "A later build records a different coverage explanation."
            )
            .is_none()
        );
    }

    #[test]
    fn tested_observation_lookup_translates_only_prose_this_build_authored() {
        assert_eq!(
            tested_observation_zh_hant("The port accepted the bounded TCP connection."),
            Some("這個連接埠接受了受限的 TCP 連線。".to_owned())
        );
        assert_eq!(
            tested_observation_zh_hant(
                "The completed Greenbone task retained the exact reviewed RDP transport profile: ten TLS protocol, cipher, and certificate checks plus one check for the legacy fixed private key used by RDP 5.2 or earlier."
            ),
            Some("已完成的 Greenbone 工作保留了精確且經過檢視的 RDP 傳輸設定檔：十項 TLS 協定、加密套件與憑證檢查，加上一項針對 RDP 5.2 或更早版本所使用之舊式固定私密金鑰的檢查。".to_owned())
        );
        assert_eq!(
            tested_observation_zh_hant(
                "The completed Greenbone task retained the exact reviewed VNC transport profile containing one check for an unencrypted VNC connection."
            ),
            Some("已完成的 Greenbone 工作保留了精確且經過檢視的 VNC 傳輸設定檔，其中包含一項未加密 VNC 連線檢查。".to_owned())
        );
        assert_eq!(
            tested_observation_zh_hant("A later build recorded a different observation."),
            None
        );
    }

    #[test]
    fn a_measured_value_is_translated_around_its_own_counts_and_identifiers() {
        // Every number, port, and asset identifier is the reader's own data
        // and survives the translation byte for byte.
        assert_eq!(
            tested_value_zh_hant("TCP reachability", "127.0.0.1:8443"),
            Some("127.0.0.1:8443".to_owned())
        );
        assert_eq!(
            tested_value_zh_hant(
                "bounded connection contract",
                "one connection attempt; 1500 ms timeout; 0 application-payload bytes"
            ),
            Some("一次連線嘗試；逾時 1500 毫秒；應用層酬載 0 位元組".to_owned())
        );
        assert_eq!(
            tested_value_zh_hant(
                "completed check-to-target coordinate",
                "syft on asset host-10"
            ),
            Some("syft 對資產 host-10".to_owned())
        );
        assert_eq!(
            tested_value_zh_hant("completed planned scan batches", "3 of 12"),
            Some("12 個中的 3 個".to_owned())
        );
        assert_eq!(
            tested_value_zh_hant(
                "SSH service vulnerability checks",
                "9 frozen upstream Greenbone SSH tests on asset host-1"
            ),
            Some("對資產 host-1 的 9 項已凍結 上游 Greenbone SSH 檢查".to_owned())
        );
        assert_eq!(
            tested_value_zh_hant(
                "SMTP fixed security profile attempt",
                "exact 11-check upstream Greenbone SMTP profile on asset host-1"
            ),
            Some("對資產 host-1 的確切上游 Greenbone SMTP 設定檔，共 11 項檢查".to_owned())
        );
        assert_eq!(
            tested_value_zh_hant(
                "SMTP TLS checks with selected-run evidence",
                "2 of 10 selected TLS checks on asset host-1"
            ),
            Some("對資產 host-1 已選取的 10 項 TLS 檢查中的 2 項".to_owned())
        );
        // A row name from another build, and a name this build authors whose
        // value was composed somewhere else.
        assert_eq!(tested_value_zh_hant("a later measurement", "4 of 5"), None);
        assert_eq!(
            tested_value_zh_hant("completed planned scan batches", "all of them"),
            None
        );
    }

    #[test]
    fn a_maester_review_detail_follows_its_sentence_without_a_space() {
        assert_eq!(
            coverage_gap_prose_zh_hant(
                "Maester evaluated this control but did not return a pass or fail verdict. Upstream detail: Confirm the tenant exception."
            ),
            Some("Maester 已評估這項控制措施，但未回傳通過或失敗的判定。上游詳細資料：Confirm the tenant exception.".to_owned())
        );
    }

    #[test]
    fn the_stale_knowledge_reason_keeps_its_date_and_moves_its_sentence() {
        // The date is data the run recorded and stays verbatim in both
        // languages; only the words around it are translated.
        assert_eq!(
            coverage_gap_prose_zh_hant(
                "This check ran on detection knowledge whose declared support had already ended, so issues published after that date were not tested. Support ended: 2023-04-10."
            ),
            Some("這項檢查執行時所用的偵測知識，其宣告的支援期限已經結束，因此該日期之後才公布的問題並未受測。支援結束日期：2023-04-10。".to_owned())
        );
        assert_eq!(
            coverage_gap_prose_zh_hant(
                "Treat these results as evidence from expired knowledge, not as current coverage."
            ),
            Some("請將這些結果視為過期知識留下的證據，而不是目前的涵蓋範圍。".to_owned())
        );
        assert_eq!(
            coverage_dimension_zh_hant("cloudquery: expired detection knowledge"),
            "cloudquery 的已過期的偵測知識"
        );
        // A sentence this build does not write keeps returning None so the
        // producer census in `beginner_report.rs` still has something to fail
        // on.
        assert_eq!(
            coverage_gap_prose_zh_hant("Some other reason. Support ended: 2023-04-10."),
            None
        );
    }

    #[test]
    fn a_gateway_refusal_count_stays_verbatim_and_the_sentence_moves() {
        assert_eq!(
            coverage_gap_prose_zh_hant(
                "The approved rate limit refused some of this check's connections, so part of the check never reached the target. Refused connections: 12."
            ),
            Some(
                "核准的速率限制拒絕了這項檢查的部分連線，因此部分檢查未能送達目標。拒絕的連線：12。"
                    .to_owned()
            )
        );
        assert_eq!(
            coverage_gap_prose_zh_hant(
                "Connections this check attempted outside the approved scope were refused. Refused connections: 3."
            ),
            Some("這項檢查嘗試在核准範圍以外建立的連線已被拒絕。拒絕的連線：3。".to_owned())
        );
        assert_eq!(
            coverage_gap_prose_zh_hant(
                "Whether any of this check's connections were refused was not recorded."
            ),
            Some("這項檢查是否有連線遭到拒絕，並未留下記錄。".to_owned())
        );
        assert_eq!(
            coverage_gap_prose_zh_hant("Some other reason. Refused connections: 12."),
            None
        );
    }

    #[test]
    fn rdp_and_vnc_limit_prose_is_available_in_traditional_chinese() {
        assert_eq!(
            coverage_gap_prose_zh_hant(
                "The unauthenticated RDP transport profile checks one legacy RDP 5.2-or-earlier fixed-private-key issue, but does not inspect broader or current RDP implementation CVEs, authentication or Network Level Authentication (NLA), Windows patch level, installed packages or applications, or local host configuration."
            ),
            Some("這項不需登入的 RDP 傳輸設定檔會檢查一項 RDP 5.2 或更早版本的舊式固定私密金鑰問題，但不會檢查更廣泛或現行的 RDP 實作 CVE、驗證或網路層級驗證（NLA）、Windows 修補層級、已安裝的套件或應用程式，也不會檢查主機本機設定。".to_owned())
        );
        assert_eq!(
            coverage_gap_prose_zh_hant(
                "Run a separately approved host or RDP-authentication assessment for those checks."
            ),
            Some("另行執行經核准的主機或 RDP 驗證評估。".to_owned())
        );
        assert_eq!(
            coverage_gap_prose_zh_hant(
                "The unauthenticated VNC transport profile checks whether the VNC connection is encrypted. It does not inspect VNC implementation CVEs, authentication strength, operating-system patch level, installed packages or applications, or local host configuration. No login or desktop session was attempted."
            ),
            Some("這項不需登入的 VNC 傳輸設定檔會檢查 VNC 連線是否加密，但不會檢查 VNC 實作 CVE、驗證強度、作業系統修補層級、已安裝的套件或應用程式，也不會檢查主機本機設定；本輪未嘗試登入或建立桌面工作階段。".to_owned())
        );
    }

    /// The TypeScript twin is held to the same outputs by
    /// `tests/frontend/coverageDimensionPresentation.test.ts`, which also
    /// censuses the producer. This one exists so the Rust side fails on its own.
    #[test]
    fn a_limit_name_is_translated_around_the_identifier_it_carries() {
        // Fixed names.
        assert_eq!(requested_limit_name_zh_hant("endpoint"), "連線端點");
        assert_eq!(
            requested_limit_name_zh_hant("connection timeout"),
            "連線逾時限制"
        );
        assert_eq!(
            requested_limit_name_zh_hant("application payload"),
            "應用資料量"
        );
        // Composed around an engine or asset id, which is what tells three
        // grants' rows apart.
        let labels = [
            "asset-primary approved ports",
            "asset-secondary approved ports",
            "asset-lab approved ports",
        ]
        .map(requested_limit_name_zh_hant);
        assert_eq!(labels[0], "允許檢查的連接埠（asset-primary）");
        assert_eq!(labels[1], "允許檢查的連接埠（asset-secondary）");
        assert_eq!(labels[2], "允許檢查的連接埠（asset-lab）");
        assert_eq!(
            requested_limit_name_zh_hant("gitleaks execution timeout"),
            "檢查逾時限制（gitleaks）"
        );
        // An empty identifier gains no empty parentheses.
        assert_eq!(
            requested_limit_name_zh_hant("approved ports"),
            "允許檢查的連接埠"
        );
        assert_eq!(
            requested_limit_name_zh_hant(" execution timeout"),
            "檢查逾時限制"
        );
        // An unrecognized name keeps its text.
        assert_eq!(
            requested_limit_name_zh_hant("prowler concurrency ceiling"),
            "本輪使用的限制：prowler concurrency ceiling"
        );
        assert!(recognized_requested_limit_name_zh_hant("prowler concurrency ceiling").is_none());
    }

    const ENGLISH_SUMMARY: &str = "Trivy reported a medium-severity condition on the assessed asset. The attached raw record is evidence, not an instruction.";

    /// One assertion per shape the beginner report composes.
    ///
    /// The TypeScript twin is held to the same outputs by
    /// `tests/frontend/coverageDimensionPresentation.test.ts`, which censuses
    /// the producer rather than this list. This one exists so that a rule
    /// reordered here -- the fixed-name loop runs first and matches on
    /// substrings, so it can swallow a composed name -- fails in Rust too.
    #[test]
    fn a_coverage_name_is_translated_around_the_identifier_it_carries() {
        for (dimension, expected) in [
            // Fixed names.
            ("requested scan stage", "要求的掃描深度"),
            ("requested checks", "要求的檢查項目"),
            (
                "partly completed planned scan batches",
                "部分完成的計畫掃描批次",
            ),
            ("completed planned scan batches", "已完成的計畫掃描批次"),
            ("RDP transport security checks", "RDP 傳輸安全性檢查"),
            (
                "RDP transport endpoint scan-profile coverage",
                "RDP 傳輸端點掃描設定檔涵蓋記錄",
            ),
            (
                "RDP implementation, authentication/NLA, and endpoint host coverage",
                "RDP 實作、驗證／NLA 與端點主機涵蓋範圍",
            ),
            ("VNC transport security check", "VNC 傳輸安全性檢查"),
            (
                "VNC transport endpoint scan-profile coverage",
                "VNC 傳輸端點掃描設定檔涵蓋記錄",
            ),
            (
                "VNC implementation, authentication, and endpoint host coverage",
                "VNC 實作、驗證與端點主機涵蓋範圍",
            ),
            // Composed around a check or engine id.
            (
                "naabu-tcp saved scan-batch coverage",
                "naabu-tcp 的已儲存的掃描批次涵蓋記錄",
            ),
            (
                "naabu-tcp failed scan batches (3)",
                "naabu-tcp 的失敗的掃描批次（3）",
            ),
            (
                "naabu-tcp partly completed scan batches (12)",
                "naabu-tcp 的部分完成的掃描批次（12）",
            ),
            ("trivy: failed check dimension", "trivy 檢查"),
            (
                "trivy: remaining requested dimensions",
                "trivy 未完成的部分",
            ),
            ("requested check prowler", "要求的檢查項目：prowler"),
        ] {
            assert_eq!(
                coverage_dimension_zh_hant(dimension),
                expected,
                "{dimension}"
            );
        }
    }

    /// A row about a whole check says failed, timed out, cancelled or not
    /// tested in its own label and sentence; its name used to say it again
    /// ("Failed — Nuclei: failed check dimension"). The same rows are held in
    /// `tests/frontend/coverageDimensionPresentation.test.ts`.
    #[test]
    fn a_row_about_a_whole_check_is_named_by_the_check() {
        for (dimension, english, chinese) in [
            ("nuclei: failed check dimension", "nuclei", "nuclei 檢查"),
            ("kics: timed-out check dimension", "kics", "kics 檢查"),
            ("naabu: cancelled check dimension", "naabu", "naabu 檢查"),
            (
                "agentic-radar: not-tested check dimension",
                "agentic-radar",
                "agentic-radar 檢查",
            ),
            (
                "Nuclei: remaining requested dimensions",
                "Nuclei: unfinished part",
                "Nuclei 未完成的部分",
            ),
            // With no check to name, the row keeps the words it has.
            (
                ": failed check dimension",
                ": failed check dimension",
                "涵蓋範圍細節：: failed check dimension",
            ),
            (
                "trivy: expired detection knowledge",
                "trivy: expired detection knowledge",
                "trivy 的已過期的偵測知識",
            ),
        ] {
            assert_eq!(
                coverage_dimension_english(dimension),
                english,
                "{dimension}"
            );
            assert_eq!(
                coverage_dimension_zh_hant(dimension),
                chinese,
                "{dimension}"
            );
        }
        // Only a redacted export still writes this wording, and the app never
        // shows one, so it has no row in the TypeScript table.
        assert_eq!(
            coverage_dimension_english("maester: manual review for MT.1003"),
            "maester: no verdict for MT.1003"
        );
    }

    #[test]
    fn an_unsupported_target_input_dimension_is_named_in_traditional_chinese() {
        let localized = coverage_dimension_zh_hant("grype: unsupported target input");
        assert_eq!(localized, "grype 的不支援的目標輸入");
        assert!(
            !localized.contains("unsupported target input"),
            "{localized} still contains the English fragment"
        );
    }

    fn without_test_code(source: &str) -> String {
        let mut production = String::with_capacity(source.len());
        let mut lines = source.lines();
        while let Some(line) = lines.next() {
            if line.trim() == "#[cfg(test)]" {
                let indentation = line.len() - line.trim_start().len();
                let next = lines.next().expect("cfg(test) has an item");
                if next.trim_start().starts_with("use ") {
                    if !next.trim_end().ends_with(';') {
                        for test_line in lines.by_ref() {
                            if test_line.trim_end().ends_with(';') {
                                break;
                            }
                        }
                    }
                } else {
                    let mut body_started = next.contains('{');
                    for test_line in lines.by_ref() {
                        body_started |= test_line.contains('{');
                        let test_indentation = test_line.len() - test_line.trim_start().len();
                        if body_started
                            && test_indentation == indentation
                            && test_line.trim() == "}"
                        {
                            break;
                        }
                    }
                }
                continue;
            }
            production.push_str(line);
            production.push('\n');
        }
        production
    }

    /// The other direction from the producer censuses in `beginner_report.rs`:
    /// those fail when a sentence has no entry, this one fails when an entry
    /// has no production sentence. A key with a typo in it is otherwise
    /// invisible unless the suite happens to exercise the path that writes it.
    #[test]
    fn every_key_is_a_sentence_some_producer_actually_writes() {
        let producers = [
            include_str!("beginner_report.rs"),
            include_str!("case_service.rs"),
        ];
        // Rust continues a long literal with a backslash before the newline and
        // swallows the indentation that follows it.
        let joined = producers
            .iter()
            .map(|source| {
                without_test_code(source)
                    .split('\\')
                    .map(|part| part.trim_start_matches(['\n', ' ']))
                    .collect::<String>()
            })
            .collect::<Vec<_>>();
        // Saved reports can still carry these sentences. Current runs record
        // the scanner version and knowledge date instead of writing them.
        let legacy_expiry_sentences = [
            "This check ran on detection knowledge whose declared support had already ended, so issues published after that date were not tested.",
            "Treat these results as evidence from expired knowledge, not as current coverage.",
        ];
        for legacy in legacy_expiry_sentences {
            assert!(
                COVERAGE_GAP_PROSE
                    .iter()
                    .any(|(english, _)| *english == legacy),
                "a saved report can still contain this sentence, so its translation stays: {legacy}"
            );
            assert!(
                joined.iter().all(|source| !source.contains(legacy)),
                "a current run must not write this expiry sentence: {legacy}"
            );
        }
        let orphans = COVERAGE_GAP_PROSE
            .iter()
            .map(|(english, _)| *english)
            .filter(|english| !legacy_expiry_sentences.contains(english))
            .filter(|english| !joined.iter().any(|source| source.contains(english)))
            .collect::<Vec<_>>();
        assert_eq!(
            orphans,
            Vec::<&str>::new(),
            "no production coverage-gap producer writes these"
        );
        let orphans = DATA_QUALITY_WARNING_PROSE
            .iter()
            .map(|(english, _)| *english)
            .filter(|english| !joined.iter().any(|source| source.contains(english)))
            .collect::<Vec<_>>();
        assert_eq!(
            orphans,
            Vec::<&str>::new(),
            "no production data-quality-warning producer writes these"
        );
        let orphans = TESTED_OBSERVATION_PROSE
            .iter()
            .map(|(english, _)| *english)
            .filter(|english| !joined.iter().any(|source| source.contains(english)))
            .collect::<Vec<_>>();
        assert_eq!(
            orphans,
            Vec::<&str>::new(),
            "no production tested-observation producer writes these"
        );
    }

    #[test]
    fn a_name_this_product_did_not_author_keeps_its_own_text() {
        // A case exclusion's dimension is the label a person typed. There is
        // nothing to translate and no shape to match, so it survives whole
        // rather than being replaced by a label this product invented.
        assert_eq!(
            coverage_dimension_zh_hant("S3 buckets in the archive account"),
            "涵蓋範圍細節：S3 buckets in the archive account"
        );
        // The singular row names one scanner; the plural row is the whole
        // requested list. Collapsing them would lose which is which.
        assert_ne!(
            coverage_dimension_zh_hant("requested check prowler"),
            coverage_dimension_zh_hant("requested checks")
        );
    }

    #[test]
    fn a_finding_with_no_code_keeps_the_english_rather_than_losing_the_sentence() {
        // Legacy runs stored prose and no code. Untranslated beats blank.
        assert_eq!(
            impact_zh_hant("English impact.", &Severity::Unknown, "中", None, None, &[],),
            "English impact."
        );
        assert_eq!(
            action_zh_hant("English action.", "Container security engineer", None, None,),
            "English action."
        );
        // A sentence this product did not write is not taken apart for a name.
        assert_eq!(
            summary_zh_hant(
                "Some other text.",
                &Severity::High,
                "高",
                None,
                "高",
                None,
                &[],
            ),
            "Some other text."
        );
    }

    #[test]
    fn network_exposure_action_is_a_service_fix_not_reachability_inventory() {
        // Nuclei and Greenbone are the findings that compose from this family.
        // Telling the reader to document why the service is reachable is the
        // inventory-observation instruction, and those observations never
        // read this clause.
        assert_eq!(
            action_english("unused", Some(FindingFamily::NetworkExposure), None),
            "Correct the service or configuration named by this check."
        );
        assert_eq!(
            action_zh_hant(
                "unused",
                "Vulnerability manager",
                Some(FindingFamily::NetworkExposure),
                None,
            ),
            "調整這項檢查所指出的服務或設定。"
        );
    }

    #[test]
    fn cloud_posture_action_names_the_checked_setting_not_least_privilege() {
        // Prowler, ScoutSuite, CloudQuery, and Steampipe share this family.
        // A missing MFA device, a password policy, root use, disabled logging,
        // or an unencrypted volume is not a least-privilege change. The
        // scanner's own remediation stays on the finding underneath this step.
        let english = action_english(
            "Apply least privilege to the affected resource's configuration or policy.",
            Some(FindingFamily::CloudPosture),
            None,
        );
        assert_eq!(
            english,
            "Correct the cloud setting or policy named by this check."
        );
        assert!(
            !english.contains("least privilege"),
            "{english} still says least privilege"
        );
        assert_eq!(
            action_zh_hant(
                "Apply least privilege to the affected resource's configuration or policy.",
                "Cloud security engineer",
                Some(FindingFamily::CloudPosture),
                None,
            ),
            "調整這項檢查所指出的雲端設定或政策。"
        );

        // Cloudsplaining stays on the narrower-policy sentence. That family
        // is a least-privilege finding.
        assert_eq!(
            action_english("unused", Some(FindingFamily::CloudIdentity), None),
            "Replace the affected policy with a narrower policy that grants only the actions the identity's role requires."
        );
        assert_eq!(
            action_zh_hant(
                "unused",
                "Cloud identity specialist",
                Some(FindingFamily::CloudIdentity),
                None,
            ),
            "改用只授予該身分角色所需操作的較小範圍政策。"
        );
    }

    #[test]
    fn unconfirmed_coverage_overrides_the_family_remedy_in_both_locales() {
        assert_eq!(
            finding_next_action_english("unused", Some(FindingFamily::NetworkExposure), None, true,),
            INCOMPLETE_CHECK_CONFIRM_ACTION
        );
        assert_eq!(
            finding_next_action_zh_hant(
                "unused",
                "Vulnerability manager",
                Some(FindingFamily::NetworkExposure),
                None,
                true,
            ),
            INCOMPLETE_CHECK_CONFIRM_ACTION_ZH_HANT
        );
        assert_eq!(
            finding_next_action_english(
                "unused",
                Some(FindingFamily::NetworkExposure),
                None,
                false,
            ),
            "Correct the service or configuration named by this check."
        );
        assert_eq!(
            finding_next_action_zh_hant(
                "unused",
                "Vulnerability manager",
                Some(FindingFamily::NetworkExposure),
                None,
                false,
            ),
            "調整這項檢查所指出的服務或設定。"
        );
    }

    #[test]
    fn aws_iam_policy_actions_follow_the_upstream_policy_source_and_attachments() {
        let details = AwsIamPolicyFindingDetails {
            policy_source: AwsIamPolicySource::AwsManaged,
            policy_name: "IAMFullAccess".into(),
            finding_identity: "CreateAccessKey".into(),
            actions: vec!["iam:createaccesskey".into()],
            actions_complete: true,
            attached_to: crate::domain::AwsIamAttachedTo {
                roles: vec!["BuildRole".into()],
                groups: vec![],
                users: vec!["Operator".into()],
                complete: false,
            },
        };

        let english = aws_iam_policy_action_english("Cloud security engineer", &details);
        assert!(english.contains("Replace AWS-managed policy IAMFullAccess"));
        assert!(english.contains("role BuildRole"));
        assert!(english.contains("user Operator"));
        assert!(english.contains("cannot be edited by this account"));
        assert!(english.contains("Confirm the current IAM attachments first"));

        let chinese = action_zh_hant(
            "unused English fallback",
            "Cloud security engineer",
            Some(FindingFamily::CloudIdentity),
            Some(&details),
        );
        assert!(chinese.contains("AWS 受管政策 IAMFullAccess"));
        assert!(chinese.contains("角色 BuildRole"));
        assert!(chinese.contains("使用者 Operator"));
        assert!(chinese.contains("無法由此帳戶直接編輯"));
        assert!(chinese.contains("請先核對目前的 IAM 附加關係"));

        let mut unknown_attachments = details.clone();
        unknown_attachments.attached_to.roles.clear();
        unknown_attachments.attached_to.users.clear();
        let unknown_action =
            aws_iam_policy_action_english("Cloud security engineer", &unknown_attachments);
        assert!(unknown_action.contains("Identify the current roles, groups, and users"));
        assert!(!unknown_action.contains("remains detached"));

        let mut customer_managed = details.clone();
        customer_managed.policy_source = AwsIamPolicySource::CustomerManaged;
        let customer_action =
            aws_iam_policy_action_english("Cloud security engineer", &customer_managed);
        assert!(customer_action.contains("Narrow customer-managed policy IAMFullAccess"));
        assert!(!customer_action.contains("cannot be edited by this account"));
        // Two principals here, one in the common case. The sentence has to
        // agree with whichever it got: "user Operator retain" is not English.
        assert!(customer_action.contains("role BuildRole, user Operator retain only"));
        let mut one_principal = customer_managed.clone();
        one_principal.attached_to.roles.clear();
        assert!(
            aws_iam_policy_action_english("Cloud security engineer", &one_principal)
                .contains("user Operator retains only")
        );

        // Past the preview limit the count itself is a countable noun.
        let mut crowded = customer_managed;
        crowded.attached_to.users = (0..IAM_PRINCIPAL_PREVIEW_LIMIT)
            .map(|index| format!("Operator{index}"))
            .collect();
        let seven = aws_iam_policy_action_english("Cloud security engineer", &crowded);
        assert!(
            seven.contains("and 1 more principal retain only"),
            "{seven}"
        );
        crowded.attached_to.users.push("OperatorLast".into());
        let eight = aws_iam_policy_action_english("Cloud security engineer", &crowded);
        assert!(
            eight.contains("and 2 more principals retain only"),
            "{eight}"
        );

        let mut inline = details;
        inline.policy_source = AwsIamPolicySource::Inline;
        let inline_action = aws_iam_policy_action_english("Cloud security engineer", &inline);
        assert!(inline_action.contains("Narrow inline policy IAMFullAccess directly on"));
    }

    /// The case context this product added must survive being said in Chinese.
    ///
    /// `apply_case_context` appends its sentences to the English
    /// `possible_impact` and raises the priority by up to ten points. Composing
    /// a fresh Chinese sentence replaces the string those appendices live in,
    /// so without this the zh-Hant reader saw a finding promoted above the
    /// scanner's own rating with the explanation removed -- while the English
    /// reader, reading the same finding, was told exactly why.
    #[test]
    fn case_context_that_raised_the_priority_is_not_lost_in_translation() {
        let english = "If the scanner result is confirmed, something may happen.";
        let plain = impact_zh_hant(
            english,
            &Severity::High,
            "高",
            None,
            Some(FindingFamily::CloudPosture),
            &[],
        );
        assert!(!plain.contains("受影響的資產被標記"), "{plain}");

        for (factor, expected) in [
            (ContextFactor::InternetExposedAsset, "可從網際網路存取"),
            (ContextFactor::SensitiveDataAsset, "含有敏感資料"),
        ] {
            let composed = impact_zh_hant(
                english,
                &Severity::High,
                "高",
                None,
                Some(FindingFamily::CloudPosture),
                &[factor],
            );
            assert!(composed.contains(expected), "{factor:?} lost: {composed}");
            assert!(
                composed.starts_with(&plain),
                "{factor:?} rewrote the base sentence"
            );
        }

        // Both at once, in the order the backend recorded them, and neither
        // swallowing the other.
        let both = impact_zh_hant(
            english,
            &Severity::High,
            "高",
            None,
            Some(FindingFamily::CloudPosture),
            &[
                ContextFactor::InternetExposedAsset,
                ContextFactor::SensitiveDataAsset,
            ],
        );
        let internet = both
            .find("可從網際網路存取")
            .expect("internet clause missing");
        let sensitive = both.find("含有敏感資料").expect("sensitive clause missing");
        assert!(internet < sensitive, "{both}");
    }

    #[test]
    fn the_engines_own_display_name_survives_verbatim() {
        for engine in ["httpx", "kube-bench", "Greenbone Community Edition"] {
            let english = format!(
                "{engine} reported a high-severity condition on the assessed asset. The attached raw record is evidence, not an instruction."
            );
            assert!(
                summary_zh_hant(&english, &Severity::High, "高", None, "高", None, &[])
                    .starts_with(&format!("{engine} ")),
                "{engine} lost its name"
            );
        }
    }

    #[test]
    fn an_unrated_unknown_stays_unknown_without_a_defensive_handoff() {
        let english_summary = "Gitleaks reported this condition but did not assign a severity. Severity remains Unknown and requires human review. The attached raw record is evidence, not an instruction.";
        let summary = summary_zh_hant(
            english_summary,
            &Severity::Unknown,
            "未知",
            Some(SeverityBasisCode::SecretPatternMatch),
            "高",
            None,
            &[],
        );
        assert!(summary.contains("Gitleaks"), "{summary}");
        assert!(summary.contains("未評定嚴重程度"), "{summary}");
        assert!(summary.contains("嚴重程度為未知"), "{summary}");
        assert!(!summary.contains("人工確認"), "{summary}");
        assert!(!summary.contains("本產品依據"), "{summary}");
        assert!(!summary.contains("將它評為未知"), "{summary}");

        let impact = impact_zh_hant(
            "If the scanner result is confirmed, a secret may permit unauthorized access. The scanner did not assign a severity; it remains Unknown for human review.",
            &Severity::Unknown,
            "未知",
            Some(SeverityBasisCode::SecretPatternMatch),
            Some(FindingFamily::Secret),
            &[],
        );
        assert!(impact.contains("可能導致未授權存取"), "{impact}");
        assert!(!impact.contains("人工確認"), "{impact}");
        assert!(!impact.contains("由本產品提供"), "{impact}");

        let reason = priority_reason_zh_hant(
            "Severity remains Unknown because Gitleaks did not assign one; human review is required.",
        );
        assert!(reason.contains("Gitleaks"), "{reason}");
        assert!(reason.contains("嚴重程度為未知"), "{reason}");
        assert!(!reason.contains("人工確認"), "{reason}");
    }

    #[test]
    fn the_control_verdict_survives_being_normalized_twice() {
        // The report bakes the English verdict into the stored summary, and the
        // exporter then normalizes that stored summary again for the reader's
        // locale. The second pass sees its own output as input, so a Chinese
        // reader got the English sentence until the sentence could be read back.
        let adapter = "ScubaGear reported this control as failing. \
            ScubaGear reported confidence High for it.";
        let stored = summary_english(adapter, Some(FindingFamily::Microsoft365));
        assert_eq!(
            stored,
            "ScubaGear checked this Microsoft 365 requirement and the tenant did not meet it."
        );

        assert_eq!(
            summary_english(&stored, Some(FindingFamily::Microsoft365)),
            stored,
            "a second English pass must not rewrite the sentence it just wrote"
        );

        let zh = control_verdict_zh_hant(Some(FindingFamily::Microsoft365), &stored)
            .expect("the exporter must recover the engine name from the stored sentence");
        assert_eq!(
            zh,
            "ScubaGear 檢查了這項 Microsoft 365 要求，這個租戶未通過。"
        );
        assert_eq!(
            control_verdict_zh_hant(Some(FindingFamily::Microsoft365), adapter).as_deref(),
            Some(zh.as_str()),
            "both passes must reach the same Chinese sentence"
        );
    }

    #[test]
    fn only_microsoft_365_findings_get_a_control_verdict() {
        let english = "Trivy reported this control as failing.";
        for family in [
            FindingFamily::CloudPosture,
            FindingFamily::CloudIdentity,
            FindingFamily::NetworkExposure,
            FindingFamily::SourceCode,
            FindingFamily::Secret,
            FindingFamily::InfrastructureAsCode,
            FindingFamily::VulnerableComponent,
            FindingFamily::Kubernetes,
        ] {
            assert_eq!(
                control_verdict_zh_hant(Some(family), english),
                None,
                "{family:?} does not check a Microsoft 365 requirement"
            );
        }
        assert_eq!(control_verdict_zh_hant(None, english), None);
    }

    #[test]
    fn every_family_and_basis_composes_a_distinct_chinese_sentence() {
        let families = [
            FindingFamily::CloudPosture,
            FindingFamily::CloudIdentity,
            FindingFamily::Microsoft365,
            FindingFamily::NetworkExposure,
            FindingFamily::SourceCode,
            FindingFamily::Secret,
            FindingFamily::InfrastructureAsCode,
            FindingFamily::VulnerableComponent,
            FindingFamily::Kubernetes,
        ];
        // Every family must resolve to its own action, or two different problems
        // are given the same instruction in the shared report.
        let actions = families
            .iter()
            .map(|family| {
                action_zh_hant(
                    "English.",
                    "Secrets-response specialist",
                    Some(*family),
                    None,
                )
            })
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(actions.len(), families.len());

        let bases = [
            SeverityBasisCode::OpenPort,
            SeverityBasisCode::ReachableHttpService,
            SeverityBasisCode::SecretPatternMatch,
            SeverityBasisCode::UnverifiedCredentialDetector,
            SeverityBasisCode::IacPolicyCheck,
            SeverityBasisCode::CisKubernetesBenchmark,
            SeverityBasisCode::CloudControlQuery,
            SeverityBasisCode::CloudsplainingIamPolicyFinding,
            SeverityBasisCode::UnratedVulnerabilityTestAlarm,
        ];
        let summaries = bases
            .iter()
            .map(|code| {
                summary_zh_hant(
                    ENGLISH_SUMMARY,
                    &Severity::High,
                    "高",
                    Some(*code),
                    "高",
                    None,
                    &[],
                )
            })
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(summaries.len(), bases.len());
        for summary in &summaries {
            assert!(summary.contains("未評定嚴重程度"), "{summary}");
        }
    }

    #[test]
    fn every_confidence_basis_composes_chinese_and_states_who_supplied_the_rating() {
        // The labelled confidence field carries the basis. The risk summary
        // used to repeat it and no longer does, so distinctness is asserted
        // where the reader actually sees it.
        let presentations = ALL_CONFIDENCE_BASIS_CODES
            .into_iter()
            .map(|code| confidence_presentation_zh_hant("高", Some(code), &[]))
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(presentations.len(), ALL_CONFIDENCE_BASIS_CODES.len());
        for presentation in &presentations {
            assert!(presentation.starts_with("高 — "), "{presentation}");
        }
        assert!(presentations.contains("高 — 掃描工具未提供偵測品質"));
        assert_eq!(
            presentations
                .iter()
                .filter(|presentation| presentation.contains("本產品依據"))
                .count(),
            ALL_CONFIDENCE_BASIS_CODES.len() - 1
        );
        // The summary states what the scanner reported and stops there.
        for code in ALL_CONFIDENCE_BASIS_CODES {
            let summary = summary_zh_hant(
                ENGLISH_SUMMARY,
                &Severity::High,
                "高",
                None,
                "高",
                Some(code),
                &[],
            );
            assert!(summary.contains("回報"), "{summary}");
            assert!(!summary.contains("信心"), "{summary}");
        }
        assert_eq!(
            confidence_presentation_zh_hant("高", None, &["Source confidence: HIGH".into()]),
            "高 — 來源工具評定：HIGH"
        );
        assert_eq!(confidence_presentation_zh_hant("高", None, &[]), "高");
        assert_eq!(
            confidence_presentation_english(
                "Unknown confidence",
                Some(ConfidenceBasisCode::MissingDetectionQualityScore),
                &[],
            ),
            "Unknown confidence — scanner did not report detection quality"
        );
    }

    #[test]
    fn each_recommended_specialist_is_named_rather_than_sorted_by_a_substring() {
        let experts = [
            "Cloud security engineer",
            "Cloud identity specialist",
            "Microsoft 365 security administrator",
            "Network security engineer",
            "Application security engineer",
            "Vulnerability manager",
            "Secrets-response specialist",
            "Infrastructure-as-code engineer",
            "Container security engineer",
            "Software supply-chain engineer",
            "Kubernetes security engineer",
            "AI security engineer",
        ];
        let named = experts
            .iter()
            .map(|expert| expert_type_zh_hant(expert))
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(
            named.len(),
            experts.len(),
            "distinct specialists collapsed together: {named:?}"
        );
        assert!(!named.contains(&"資安或 IT 專業人員"));
    }

    #[test]
    fn a_scanner_location_reads_as_a_place() {
        // Mirrors "the scanner location reads as a place, not a coordinate
        // string" in tests/frontend/findingNarrative.test.ts -- the rows and
        // the two edge cases below must stay identical between the two
        // files.
        let rows: [(&str, &str, &str); 18] = [
            (
                "infra/main.tf:line=3:resource=resource:demo-logs-bucket,similarity:6ed736ab0df4cde21ce2716cc0a80470709d43045ca36a0c897af1f7913f1009",
                "infra/main.tf · line 3 · demo-logs-bucket",
                "infra/main.tf · 第 3 行 · demo-logs-bucket",
            ),
            (
                "infra/main.tf:line=7:resource=similarity:ab12",
                "infra/main.tf · line 7",
                "infra/main.tf · 第 7 行",
            ),
            (
                "requirements.txt:resource=PyYAML@5.1",
                "requirements.txt · PyYAML@5.1",
                "requirements.txt · PyYAML@5.1",
            ),
            (
                "app.py:line=12:column=5",
                "app.py · line 12, column 5",
                "app.py · 第 12 行第 5 欄",
            ),
            (
                "config.env:line=4:resource=offset:120",
                "config.env · line 4 · offset:120",
                "config.env · 第 4 行 · offset:120",
            ),
            (
                "https://shop.example.test:8443/login",
                "https://shop.example.test:8443/login",
                "https://shop.example.test:8443/login",
            ),
            ("10.0.0.5:22", "10.0.0.5:22", "10.0.0.5:22"),
            ("/requirements.txt", "requirements.txt", "requirements.txt"),
            (
                "/infra/storage.tf:line=4:resource=aws_s3_bucket.logs",
                "infra/storage.tf · line 4 · aws_s3_bucket.logs",
                "infra/storage.tf · 第 4 行 · aws_s3_bucket.logs",
            ),
            (
                ".\\infra\\storage.tf:line=4:resource=resource:aws_s3_bucket.logs,resource:,similarity:dedup,resource:aws_s3_bucket.logs",
                "infra/storage.tf · line 4 · aws_s3_bucket.logs",
                "infra/storage.tf · 第 4 行 · aws_s3_bucket.logs",
            ),
            (
                ".\\infra\\storage.tf",
                "infra/storage.tf",
                "infra/storage.tf",
            ),
            // KICS's no-resource marker says nothing.
            (
                "infra/main.tf:line=20:resource=resource:n/a,similarity:6ed736ab0df4cde21ce2716cc0a80470709d43045ca36a0c897af1f7913f1009",
                "infra/main.tf · line 20",
                "infra/main.tf · 第 20 行",
            ),
            // Checkov names a Dockerfile resource after the file, and an
            // instruction-level one after the file and the instruction.
            (
                "/Dockerfile:line=1:resource=/Dockerfile.",
                "Dockerfile · line 1",
                "Dockerfile · 第 1 行",
            ),
            (
                "/app/Dockerfile:line=5:resource=/app/Dockerfile.EXPOSE",
                "app/Dockerfile · line 5 · EXPOSE",
                "app/Dockerfile · 第 5 行 · EXPOSE",
            ),
            // A label that is the path itself adds nothing either.
            (
                "/Dockerfile:line=2:resource=Dockerfile",
                "Dockerfile · line 2",
                "Dockerfile · 第 2 行",
            ),
            // A resource that only starts with the path's text is its own name.
            (
                "infra/main.tf:line=3:resource=infra/main.tfx",
                "infra/main.tf · line 3 · infra/main.tfx",
                "infra/main.tf · 第 3 行 · infra/main.tfx",
            ),
            // An empty path is not this form.
            (":line=3", ":line=3", ":line=3"),
            // The smallest valid split, not the first `:line=`.
            ("a:line=3:line=4", "a:line=3 · line 4", "a:line=3 · 第 4 行"),
        ];

        for (raw, en, zh) in rows {
            assert_eq!(location_english(raw), en, "{raw}");
            assert_eq!(location_zh_hant(raw), zh, "{raw}");
        }
    }

    fn benchmark(name: &str, version: &str, reference: &str) -> BenchmarkReference {
        BenchmarkReference {
            name: name.into(),
            version: version.into(),
            reference: reference.into(),
        }
    }

    #[test]
    fn benchmark_lines_follow_the_scanner_and_stop_at_three_groups() {
        let one = [benchmark(
            "CIS Amazon Web Services Foundations",
            "1.2.0",
            "1.5",
        )];
        assert_eq!(
            benchmark_line_english("ScoutSuite", &one).as_deref(),
            Some("CIS Amazon Web Services Foundations 1.2.0 item 1.5 (reported by ScoutSuite)")
        );
        assert_eq!(
            benchmark_line_zh_hant("ScoutSuite", &one).as_deref(),
            Some("CIS Amazon Web Services Foundations 1.2.0 第 1.5 項（ScoutSuite 回報）")
        );
        let versions = [
            benchmark("CIS Amazon Web Services Foundations", "1.0.0", "1.5"),
            benchmark("CIS Amazon Web Services Foundations", "1.1.0", "1.5"),
            benchmark("CIS Amazon Web Services Foundations", "1.2.0", "1.5"),
        ];
        assert_eq!(
            benchmark_line_english("ScoutSuite", &versions).as_deref(),
            Some(
                "CIS Amazon Web Services Foundations 1.0.0/1.1.0/1.2.0 item 1.5 (reported by ScoutSuite)"
            )
        );
        assert_eq!(
            benchmark_line_zh_hant("ScoutSuite", &versions).as_deref(),
            Some(
                "CIS Amazon Web Services Foundations 1.0.0/1.1.0/1.2.0 第 1.5 項（ScoutSuite 回報）"
            )
        );
        let many = [
            benchmark("A", "1", "r1"),
            benchmark("A", "1", "r2"),
            benchmark("B", "2", "r3"),
            benchmark("C", "3", "r4"),
        ];
        assert_eq!(
            benchmark_line_english("X", &many).as_deref(),
            Some("A 1 item r1; A 1 item r2; B 2 item r3 and 1 more (reported by X)")
        );
        assert_eq!(
            benchmark_line_zh_hant("X", &many).as_deref(),
            Some("A 1 第 r1 項；A 1 第 r2 項；B 2 第 r3 項，另有 1 項（X 回報）")
        );
        let duplicated = [benchmark("A", "1", "r1"), benchmark("A", "1", "r1")];
        assert_eq!(
            benchmark_line_english("X", &duplicated).as_deref(),
            Some("A 1 item r1 (reported by X)")
        );
        assert_eq!(benchmark_line_english("X", &[]), None);
        assert_eq!(benchmark_line_zh_hant("ScoutSuite", &[]), None);
    }

    #[test]
    fn password_order_reasons_translate_and_english_stays_verbatim() {
        assert_eq!(
            priority_reason_english(PASSWORD_COMPOSITION_ORDER_REASON),
            PASSWORD_COMPOSITION_ORDER_REASON
        );
        assert_eq!(
            priority_reason_english(&format!("  {PASSWORD_EXPIRY_ORDER_REASON}  ")),
            format!("  {PASSWORD_EXPIRY_ORDER_REASON}  ")
        );
        assert_eq!(
            priority_reason_zh_hant(PASSWORD_COMPOSITION_ORDER_REASON),
            PASSWORD_COMPOSITION_ORDER_REASON_ZH_HANT
        );
        assert_eq!(
            priority_reason_zh_hant(&format!("\n{PASSWORD_EXPIRY_ORDER_REASON}\n")),
            PASSWORD_EXPIRY_ORDER_REASON_ZH_HANT
        );
    }
}
