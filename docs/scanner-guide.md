# Scanner guide

Product v0.4.0 · released and reviewed 2026-10-04.

[Interactive website](https://ted-h-com.github.io/ai-security-scanner/scanner-guide.html) · [Sample reports](samples/v0.4.0/README.md)

SWOT is the project team’s assessment. Enabled features describe this product profile, not the whole upstream platform. Source dates are commit dates, not release dates. Opportunities are possible uses, not promised functionality.

## CloudQuery

Lists selected AWS identities and permission policies. This inventory is kept separate from security findings.

[Upstream](https://github.com/cloudquery/cloudquery) · [README @ e27e4ab](https://github.com/cloudquery/cloudquery/blob/e27e4ab61ad85479a5d53dae9b08440bc63e72b3/README.md) · [Integration and update notes](https://github.com/TED-H-com/ai-security-scanner/blob/335d0666bdc63eb86e6c8c4cddeae110db893397/docs/engines/cloudquery.md)

### About this tool

CloudQuery is a widely used open-source tool that copies data from cloud provider APIs into structured tables you can query and compare later. A source plugin reads the cloud service and a destination plugin writes each row, so every collection comes out in the same shape. We include it in this app because it helps you quickly see which identities and permission policies exist in an approved AWS account, which gives the security checks context. Here it collects one fixed set of identity and access management (IAM) tables: the account, users, groups, roles, policies, password policies, and credential reports. These rows are inventory: they describe what exists, stay separate from security findings, and do not cover every AWS service.

### What the original tool does

CloudQuery moves structured API data into destinations that can be queried and compared. Its CLI, source plugin and destination plugin are independently versioned; recording only the CLI version does not identify the data collection behavior.

### What this app checks

CLI 2.0.31, AWS source 9.2.0 and file destination 1.0.4 run from embedded local binaries. One approved AWS account uses the fixed us-east-1 IAM profile: accounts, credential reports, groups, password policies, policies, roles and users. Child-table output remains evidence. Per-table NDJSON becomes attributed inventory observations.

### What it does not check

This integration does not collect all AWS services, download plugins at scan time, or turn inventory rows into vulnerability findings. The old public plugin closure is deliberately frozen; it is not a claim to ship the newest CloudQuery platform.

### Why we selected it

We selected it for explicit table-level collection and inspectable machine output. It helps establish the IAM inventory that readers can compare with Prowler or policy-analysis evidence in the same asset report.

### When to use it

Use it when an AWS owner wants to enumerate IAM users, roles and policies before reviewing their security posture, or to understand why an identity appears in another scanner result. Select the exact account and read-only inventory access.

### What you see in the report

The sample contributes a cloud-resource observation with a native identifier and table provenance. It adds inventory coverage, not a finding or a successful security verdict.

### Strengths

Named tables and separately pinned plugins make the collection reproducible. Structured rows are easier to attribute and preserve than a screenshot of a cloud console.

### Weaknesses

Inventory describes configuration, not exploitability. The frozen 2023-era plugin has a narrower and older API model than current upstream releases, and a complete table sync cannot establish complete cloud coverage.

### Opportunities

Use the retained inventory to review identity ownership, cross-reference policy findings and compare repeated assessments. A future replacement can preserve this normalized inventory contract while changing the collector.

### Threats

AWS API changes, pagination failures or restricted read permissions can leave missing records. The legacy dependency closure also needs explicit maintenance review; a fresh application release does not refresh that upstream collector automatically.

### Version record

| Item | Included on 2026-10-04 |
| --- | --- |
| Engine version (catalog) | 2.0.31-aws9.2.0-file1.0.4 |
| Image tag | 2.0.31-aws9.2.0-6 |
| Pinned source commit date (UTC) | 2023-01-05T14:16:38Z |
| Source revision | e27e4ab61ad85479a5d53dae9b08440bc63e72b3 |
| Rules / checks | CloudQuery AWS source plugin v9.2.0 and fixed seven-table IAM profile |
| Rules revision | 804be3a90d6f15d3e6c662c0eb7afa88a9596180 |
| Data input | AWS IAM inventory |
| Data revision | None / runtime input |
| Catalog knowledge baseline date | 2023-01-10 |
| Adapter version | 0.2.6 |
| Output format | NDJSON · per-table output |

Image identity: `ghcr.io/teddashh/ai-security-scanner-engine-cloudquery:2.0.31-aws9.2.0-6@sha256:e80bc6914b9a007b2a1e8978a222ff7b0ead657d004ca22f410270d086c3be82`

## Steampipe

Lists AWS users and selected account settings so you can review who has access.

[Upstream](https://github.com/turbot/steampipe) · [README @ 71fa72f](https://github.com/turbot/steampipe/blob/71fa72fc9ce33897bcb0bd0c9ebf09b867b881cf/README.md) · [Integration and update notes](https://github.com/TED-H-com/ai-security-scanner/blob/335d0666bdc63eb86e6c8c4cddeae110db893397/docs/engines/steampipe.md)

### About this tool

Steampipe, maintained by Turbot, is a widely used open-source tool that turns cloud APIs into SQL tables. SQL is the standard database query language, and each provider plugin decides which services and columns you can read. We include it in this app because it helps you quickly list the identity and access management (IAM) users in one approved AWS account, so you can compare that list with what the security checks report. Here it runs one fixed query of the IAM user table. The rows are inventory: they name the users found and do not judge whether any user is a risk. This app does not run Steampipe's ready-made security benchmarks or accept SQL you write.

### What the original tool does

Steampipe exposes APIs through SQL tables using provider plugins. That makes cloud metadata available in a familiar relational model, while the plugin determines which services and columns can be queried.

### What this app checks

Steampipe 2.4.5 uses the preseeded AWS plugin 1.32.0. The product runs its fixed AWS IAM inventory subset for one approved account, through the cloud launcher and managed egress. JSON rows are normalized as cloud-resource observations, with query/source attribution retained.

### What it does not check

There is no arbitrary user-supplied SQL, runtime plugin installation, all-service cloud inventory or bundled security Mod execution in this profile. SQL output alone is not a failed security control.

### Why we selected it

The SQL table model provides a second inspectable IAM inventory representation alongside CloudQuery. We keep that role explicit so a useful inventory is not marketed as a vulnerability scan.

### When to use it

Choose it for an approved AWS IAM review when structured resource rows help explain which users, roles or policies were present. It is useful for comparing inventory with a security scanner result, especially when tracing an identity back to provider data.

### What you see in the report

The sample retains IAM resource observations and their Steampipe provenance. The report keeps the observations in the inventory section; they do not increase the vulnerability count.

### Strengths

SQL gives inventory a consistent, inspectable shape. A pinned local plugin and fixed query scope make the supported collection path reviewable.

### Weaknesses

The selected queries cover only an IAM subset and can only expose data the provider returns. Steampipe infrastructure and plugin management add more moving parts than a single direct API call.

### Opportunities

Compare table-level inventory across assessments, reconcile identities with policy findings, and retain a stable output contract if the plugin is deliberately updated. More SQL tables would require separately reviewed scope and permissions.

### Threats

Provider throttling, column/schema changes and denied API actions can make inventory partial. Automatically adopting a newer plugin could change queries and permissions, so version dates and fixed inputs matter.

### Version record

| Item | Included on 2026-10-04 |
| --- | --- |
| Engine version (catalog) | 2.4.5 |
| Image tag | 2.4.5-6 |
| Pinned source commit date (UTC) | 2026-08-10T13:27:42Z |
| Source revision | 71fa72fc9ce33897bcb0bd0c9ebf09b867b881cf |
| Rules / checks | Steampipe AWS plugin v1.32.0 |
| Rules revision | 6e79b2dece502bc198310b39bd54bc95d2842c99 |
| Data input | AWS IAM inventory |
| Data revision | None / runtime input |
| Catalog knowledge baseline date | 2026-08-24 |
| Adapter version | 0.2.6 |
| Output format | JSON |

Image identity: `ghcr.io/teddashh/ai-security-scanner-engine-steampipe:2.4.5-6@sha256:cd488a85ca1ebfb4c5f17212b9b29c1309a4cf9450d8645a911ffb1bdb6b4e42`

## Prowler

Checks selected identity and permission settings in an approved AWS account, Azure subscription or GCP project.

[Upstream](https://github.com/prowler-cloud/prowler) · [README @ 40ecbd0](https://github.com/prowler-cloud/prowler/blob/40ecbd035e5541bf099917c5033cceb8959c4737/README.md) · [Integration and update notes](https://github.com/TED-H-com/ai-security-scanner/blob/335d0666bdc63eb86e6c8c4cddeae110db893397/docs/engines/prowler.md)

### About this tool

Prowler is a widely used open-source cloud security assessment tool. It calls the cloud provider's APIs, runs its built-in checks, and records each check's name, the affected resource, what failed, and how to fix it. Upstream, it can cover many services and compliance frameworks. We include it in this app because it helps you quickly find identity and permission settings that need attention. Here each run uses a narrow identity and access management (IAM) profile on one approved asset: the IAM service of one AWS account, the IAM service of one Azure subscription, or four specific IAM checks for one GCP project. Other services and accounts are outside the run, and a passed check is not a certification.

### What the original tool does

Prowler is a cloud security assessment project with provider-specific checks and remediation guidance. Its upstream platform is broader than the narrow provider profiles selected by this desktop integration.

### What this app checks

Prowler 5.39.1 evaluates the selected IAM configuration for exactly one AWS account, Azure subscription or GCP project. Native OCSF records retain the check identifier, FAIL/PASS status, resource, severity, failure explanation and remediation. The report leads with the failed condition when the upstream check title is phrased as a desired secure state.

### What it does not check

This is not an all-services or all-accounts Prowler deployment. We do not claim every upstream compliance pack ran, and passing individual checks does not establish certification or an authorization to change cloud resources.

### Why we selected it

We selected Prowler because its native checks provide resource-level evidence and actionable remediation across three major cloud providers. Preserving its check identities allows the report layer to group related work while retaining every upstream result.

### When to use it

Use it during an IAM posture review, after a cloud identity-policy change, or before handing an account/subscription/project to another team. Review the exact provider scope and complete the provider read-only authorization first.

### What you see in the report

The sample includes an AWS managed policy with administrative wildcard permissions. It shows the failed condition, policy ARN, native check and remediation; a PASS row in the same input is not converted into a problem.

### Strengths

Native resource identifiers and OCSF output support precise evidence attribution. Provider-owned check semantics and remediation make findings easier to verify than a product-created risk guess.

### Weaknesses

A configuration finding does not demonstrate that an attacker exercised the permission. The selected profile is intentionally narrow and depends on complete read access, so a clean result covers only evaluated checks in the approved scope.

### Opportunities

Use Prowler evidence with Cloudsplaining policy details and inventory observations to assign a concrete least-privilege remediation. Repeated runs can confirm whether the same native check and resource improved.

### Threats

Cloud API evolution, permission gaps and newly added upstream checks can change coverage. Broad upstream marketing claims can also be misread as this product’s actual scope; the provider profile and version record prevent that ambiguity.

### Version record

| Item | Included on 2026-10-04 |
| --- | --- |
| Engine version (catalog) | 5.39.1 |
| Image tag | 5.39.1-7 |
| Pinned source commit date (UTC) | 2026-08-18T09:32:24Z |
| Source revision | 40ecbd035e5541bf099917c5033cceb8959c4737 |
| Rules / checks | Prowler checks |
| Rules revision | 40ecbd035e5541bf099917c5033cceb8959c4737 |
| Data input | Exact-scope AWS, Azure, or GCP IAM configuration |
| Data revision | None / runtime input |
| Catalog knowledge baseline date | 2026-08-24 |
| Adapter version | 0.2.6 |
| Output format | OCSF-JSON |

Image identity: `ghcr.io/teddashh/ai-security-scanner-engine-prowler:5.39.1-7@sha256:38d9593af214ce164c78b731d1ea29abd06de6babe84b230502972f67a658450`

## ScoutSuite

Checks selected AWS identity and access settings. This app uses a limited part of ScoutSuite.

[Upstream](https://github.com/nccgroup/ScoutSuite) · [README @ 7909f2f](https://github.com/nccgroup/ScoutSuite/blob/7909f2fc6186063e5c9e7ddef8c4d7d1072c8f3d/README.md) · [Integration and update notes](https://github.com/TED-H-com/ai-security-scanner/blob/335d0666bdc63eb86e6c8c4cddeae110db893397/docs/engines/scoutsuite.md)

### About this tool

ScoutSuite, from NCC Group, is a widely used open-source tool that reads cloud configuration through provider APIs and flags settings its rules consider risky. Each result keeps the rule, the affected items, and why they deserve review. Upstream, it supports several cloud providers and produces its own report. We include it in this app because it helps you quickly find AWS identity and access settings worth a closer look, as a second view beside Prowler. Here it runs only the AWS identity and access management (IAM) rules for one approved account; other providers and other AWS services are outside the run. A setting becomes a finding only when a rule flags it, so collected configuration alone is not a vulnerability.

### What the original tool does

ScoutSuite collects cloud configuration through provider APIs and identifies risky configurations for review. Upstream supports a wider multi-cloud assessment workflow and its own presentation.

### What this app checks

ScoutSuite 5.14.0 runs the bounded AWS IAM-only profile for one approved account. A retained JSON-output exception produces machine-readable results without relying on the upstream HTML viewer. The adapter preserves rule identity, affected IAM items and supplied severity/evidence.

### What it does not check

Other ScoutSuite cloud providers and AWS service families are outside this profile. The product does not copy ScoutSuite detection rules into a wrapper or treat every collected configuration item as a vulnerability.

### Why we selected it

It provides a distinct upstream view of AWS IAM configuration that can complement Prowler. Native evidence remains inspectable even when multiple engines lead to one practical action in the shared report.

### When to use it

Use it for a second IAM configuration review or an evidence-rich account handover. It is especially useful when the operator wants the risky configuration itself, not only an inventory of which resources exist.

### What you see in the report

The sample includes several IAM rule findings from the native JSON structure. Each retains ScoutSuite attribution and the affected resource context in the technical evidence.

### Strengths

Resource-oriented configuration evidence supports manual verification. A second upstream rule family can expose differences in interpretation without the product inventing another detector.

### Weaknesses

The pinned release is older and the integration depends on a narrow machine-output patch. Findings overlap with other IAM tools, so raw counts should not be interpreted as independent affected assets.

### Opportunities

Compare ScoutSuite and Prowler evidence on the same IAM resource, retain disagreement for review, and group shared remediation in the product report. A newer source can be considered when the output exception can be revalidated.

### Threats

AWS response changes can outpace the pinned parser. A changed upstream report shape can silently reduce detail unless the adapter fixtures and patch are checked together during an update.

### Version record

| Item | Included on 2026-10-04 |
| --- | --- |
| Engine version (catalog) | 5.14.0 |
| Image tag | 5.14.0-6 |
| Pinned source commit date (UTC) | 2024-05-10T09:24:57Z |
| Source revision | 7909f2fc6186063e5c9e7ddef8c4d7d1072c8f3d |
| Rules / checks | ScoutSuite AWS IAM rules |
| Rules revision | 7909f2fc6186063e5c9e7ddef8c4d7d1072c8f3d |
| Data input | AWS IAM configuration |
| Data revision | None / runtime input |
| Catalog knowledge baseline date | 2026-08-24 |
| Adapter version | 0.2.6 |
| Output format | JSON |

Image identity: `ghcr.io/teddashh/ai-security-scanner-engine-scoutsuite:5.14.0-6@sha256:72eea2aa430852cb92511a5234c99fe6fce6d574c36594fdc15dcf85d3a26394`

## Cloudsplaining

Reviews collected AWS permission policies for access that may be broader than needed.

[Upstream](https://github.com/salesforce/cloudsplaining) · [README @ 75a67ea](https://github.com/salesforce/cloudsplaining/blob/75a67ea9cb6d0fdf35ff185d08dad0d45587e6f7/README.md) · [Integration and update notes](https://github.com/TED-H-com/ai-security-scanner/blob/335d0666bdc63eb86e6c8c4cddeae110db893397/docs/engines/cloudsplaining.md)

### About this tool

Cloudsplaining, from Salesforce, is an open-source tool that checks AWS identity and access management (IAM) policies for permissions broader than the work needs, which breaks the principle of least privilege. It reads an account's authorization details, finds actions allowed without a resource limit, and sorts risky ones into categories such as privilege escalation, data exfiltration, resource exposure, and infrastructure modification, naming the policy and the actions. We include it in this app because it helps you quickly find overly broad permissions and see which actions to review. Here it analyzes one approved AWS account. A flagged action is evidence for review: it does not decide whether the business needs the permission, change the policy, or prove someone can use it now.

### What the original tool does

Cloudsplaining specializes in AWS IAM policy analysis. It examines authorization data and classifies risky permissions such as privilege escalation, data access or infrastructure-changing capabilities.

### What this app checks

Version 0.9.1 downloads authorization details for one approved AWS account and applies the upstream policy analysis. Native actions, policy identities, exclusions and attached-resource context feed the shared report. Related findings may share a remediation while their individual evidence remains available.

### What it does not check

It does not simulate every effective AWS authorization decision, validate business necessity or modify policies. An action classified as risky is evidence for review, not proof that a reachable attacker can use it in the current environment.

### Why we selected it

General posture checks often identify a broad IAM problem; Cloudsplaining adds policy/action detail that helps an owner narrow a wildcard permission. That specialization is useful even when another scanner points to the same policy.

### When to use it

Use it before granting a role to an application, during a least-privilege review, or after an overprivileged policy is reported. Interpret the actions together with trust policies, organization controls and application requirements.

### What you see in the report

The sample shows policy/action findings with native Cloudsplaining categories and provenance. Multiple action records can describe the same policy; the report preserves that relationship rather than implying eighteen unrelated assets.

### Strengths

Focused IAM analysis explains which permissions caused concern. Retained action names make remediation discussions concrete and let a cloud owner verify the evidence in the policy document.

### Weaknesses

Static policy analysis cannot establish actual usage, reachability or the full effect of every external restriction. Some broad permissions are intentional, and the owning team must validate the operational requirement.

### Opportunities

Combine action-level evidence with Prowler, ScoutSuite and inventory to create a focused policy review. Repeat scans can track whether the specific risky actions disappeared without losing the original native finding identities.

### Threats

New AWS services and actions may outpace the pinned policy definitions. Missing authorization details or incomplete permissions can limit the analysis, while duplicate engine reports can overstate urgency if readers count raw records alone.

### Version record

| Item | Included on 2026-10-04 |
| --- | --- |
| Engine version (catalog) | 0.9.1 |
| Image tag | 0.9.1-6 |
| Pinned source commit date (UTC) | 2026-06-14T23:46:19Z |
| Source revision | 75a67ea9cb6d0fdf35ff185d08dad0d45587e6f7 |
| Rules / checks | Cloudsplaining IAM analysis definitions |
| Rules revision | 75a67ea9cb6d0fdf35ff185d08dad0d45587e6f7 |
| Data input | AWS IAM authorization details |
| Data revision | None / runtime input |
| Catalog knowledge baseline date | 2026-08-24 |
| Adapter version | 0.2.6 |
| Output format | JSON |

Image identity: `ghcr.io/teddashh/ai-security-scanner-engine-cloudsplaining:0.9.1-6@sha256:26f629d8bf65dd43aec6e217a4492e7c974ec81d0daf6b07d52efff475968997`

## ScubaGear

Compares supported Microsoft 365 settings with CISA security guidance.

[Upstream](https://github.com/cisagov/ScubaGear) · [README @ 4d34e9a](https://github.com/cisagov/ScubaGear/blob/4d34e9a48e38ce5c2e14c0fdfbaee53e57594ae2/README.md) · [Integration and update notes](https://github.com/TED-H-com/ai-security-scanner/blob/335d0666bdc63eb86e6c8c4cddeae110db893397/docs/engines/scubagear.md)

### About this tool

ScubaGear, from CISA, the U.S. Cybersecurity and Infrastructure Security Agency, is an open-source tool that compares a Microsoft 365 tenant, an organization's Microsoft 365 environment, with CISA's Secure Cloud Business Applications (SCuBA) baselines: written expectations for a secure configuration. Upstream, it also covers other Microsoft 365 products. We include it in this app because it helps you quickly find Microsoft Entra ID settings that fall short of this guidance; Entra ID is the tenant's sign-in and identity directory. Here it checks the Entra ID baseline for one authorized tenant in Microsoft's commercial cloud. Exchange, SharePoint, and other workloads are outside the check. A pass is not a compliance certification, and checks that could not be evaluated stay visible instead of counting as passes.

### What the original tool does

CISA ScubaGear evaluates Microsoft 365 tenant configuration against published SCuBA secure configuration baselines. Upstream has separate product assessments; a baseline result must identify which product was actually assessed.

### What this app checks

ScubaGear 1.8.0 runs the pinned AAD/Entra ID profile through Microsoft Graph for one authorized tenant. The managed image includes the reviewed PowerShell modules and baseline inputs. Native policy/control identities, verdicts and evidence are retained; failed tests become findings and missing evaluation remains visible.

### What it does not check

This profile does not assess every Microsoft 365 workload, run Exchange or SharePoint assessments, or provide a compliance certification. These simulated examples do not establish the outcome of a live tenant assessment.

### Why we selected it

CISA publishes concrete baseline expectations, which makes the reason for a configuration check inspectable. ScubaGear complements Maester by providing a baseline-oriented view of the same authorized Entra environment.

### When to use it

Use it for an Entra configuration review, tenant handover or verification after an identity-policy change. Complete the documented read-only Microsoft consent and review the exact tenant before starting.

### What you see in the report

The sample carries a failed SCuBA control with its native identity and tenant attribution. It demonstrates report presentation using a representative input, not a new scan of a real Microsoft tenant.

### Strengths

Published baseline references explain the policy intent. Native control identifiers allow a reader to follow a result back to the CISA material and retain an audit trail through later rescans.

### Weaknesses

The product enables only the Entra slice of the upstream suite. Licensing, tenant configuration and permissions can affect which checks are evaluable; baseline alignment does not measure every attack path.

### Opportunities

Pair baseline findings with Maester test details, then organize work by the identity setting that needs changing. Repeated authorized runs can show whether the same control changed from failing to passing.

### Threats

Microsoft Graph changes, conditional access restrictions and missing consent can interrupt collection. Baseline revisions can also change the expected behavior, so a newer publication date must not silently replace the pinned baseline.

### Version record

| Item | Included on 2026-10-04 |
| --- | --- |
| Engine version (catalog) | 1.8.0 |
| Image tag | 1.8.0-8 |
| Pinned source commit date (UTC) | 2026-08-20T18:59:38Z |
| Source revision | 4d34e9a48e38ce5c2e14c0fdfbaee53e57594ae2 |
| Rules / checks | CISA ScubaGear baselines |
| Rules revision | 4d34e9a48e38ce5c2e14c0fdfbaee53e57594ae2 |
| Data input | Microsoft Entra ID configuration |
| Data revision | None / runtime input |
| Catalog knowledge baseline date | 2026-08-24 |
| Adapter version | 0.2.6 |
| Output format | JSON · managed envelope of native verdicts |

Image identity: `ghcr.io/teddashh/ai-security-scanner-engine-scubagear:1.8.0-8@sha256:9933c263fee77b187f2b763ffc0b490a0e220effb8b011c8a204abb23d340cc7`

## Maester

Tests supported Microsoft 365 security settings and explains which checks need attention.

[Upstream](https://github.com/maester365/maester) · [README @ 6bf1d98](https://github.com/maester365/maester/blob/6bf1d98f094fc7a68e449d2f40f73ef820b72ee3/README.md) · [Integration and update notes](https://github.com/TED-H-com/ai-security-scanner/blob/335d0666bdc63eb86e6c8c4cddeae110db893397/docs/engines/maester.md)

### About this tool

Maester is an open-source test framework for Microsoft 365 security configuration, written in PowerShell, Microsoft's scripting language. Each test states the setting a secure tenant should have and records whether yours matches. We include it in this app because it helps you quickly find Microsoft Entra ID settings that do not meet those expectations; Entra ID is the tenant's sign-in and identity directory. Here it runs a fixed set of Entra tests for one authorized tenant and skips long-running tests, preview tests, and tests that need other services. Exchange Online and scripts you supply are outside the run. A skipped test is never shown as a pass, and a test that needs human judgment is listed for your review.

### What the original tool does

Maester is a PowerShell-based test framework for Microsoft 365 security configuration. Tests express expected settings and retain a verdict that can be reviewed over time.

### What this app checks

Maester 2.0.0 runs the pinned Graph-only Entra test profile for one authorized tenant. The image freezes required modules and tests, and the adapter preserves native test identifiers, failed-test details and completion information. The M365 setup documents the required read permissions, including selected PIM reads.

### What it does not check

The product does not run every Maester workload, Exchange Online test or arbitrary tenant script. A skipped or unavailable check is not converted into a pass. The sample illustrates output, not a live tenant assessment.

### Why we selected it

Its test-oriented output gives an administrator a concrete item to investigate and recheck. Together with ScubaGear, it provides complementary native evidence while the shared report prevents the reader from juggling two unrelated report formats.

### When to use it

Use it after Entra policy changes, during a tenant security review, or when a team wants repeatable evidence for configuration regression. The selected tenant and Graph permissions must match the approved profile.

### What you see in the report

The sample includes a failed native test with its title and supporting details. The report attributes it to Maester and retains the test identity rather than inventing a new product-owned control.

### Strengths

Explicit tests and stable identifiers support repeatable review. A fixed Graph-only profile reduces the number of independent connection methods an operator must understand.

### Weaknesses

Tests see the configuration exposed by the granted APIs and cannot prove that all tenant attack paths were exercised. Tests requiring unavailable licensing or permissions may remain unevaluated.

### Opportunities

Track native test outcomes before and after a reviewed configuration change, and correlate overlapping ScubaGear results into one practical work item. Broader workload coverage would require separately reviewed profiles.

### Threats

Graph and PowerShell dependency changes can break a previously valid collection path. Tenant-side policy or permission drift can leave partial results even when the local tool version has not changed.

### Version record

| Item | Included on 2026-10-04 |
| --- | --- |
| Engine version (catalog) | 2.0.0 |
| Image tag | 2.0.0-9 |
| Pinned source commit date (UTC) | 2026-08-18T05:20:09Z |
| Source revision | 6bf1d98f094fc7a68e449d2f40f73ef820b72ee3 |
| Rules / checks | Maester Graph-only Entra test profile |
| Rules revision | 6bf1d98f094fc7a68e449d2f40f73ef820b72ee3 |
| Data input | Microsoft Entra ID configuration |
| Data revision | None / runtime input |
| Catalog knowledge baseline date | 2026-08-24 |
| Adapter version | 0.2.6 |
| Output format | JSON · managed envelope of native verdicts |

Image identity: `ghcr.io/teddashh/ai-security-scanner-engine-maester:2.0.0-9@sha256:a41df2693dcb5923a85fb4e75f10d80dca130c6269c5621d82cd4809f176cf81`

## Naabu

Shows which approved ports accept connections. An open port is information to investigate, not proof of a vulnerability.

[Upstream](https://github.com/projectdiscovery/naabu) · [README @ 5a0ca8b](https://github.com/projectdiscovery/naabu/blob/5a0ca8bde91b5bb16213e9e8b5c6871eac954bd8/README.md) · [Integration and update notes](https://github.com/TED-H-com/ai-security-scanner/blob/335d0666bdc63eb86e6c8c4cddeae110db893397/docs/engines/naabu.md)

### About this tool

Naabu is an open-source port-discovery tool from ProjectDiscovery that shows which TCP ports are accepting connections. A TCP port is the number a network service listens on. Its connect scan opens an ordinary TCP connection to each address and port, and a completed connection means the port is open; upstream also offers other discovery methods. We include it in this app because it helps you quickly find out which approved services are listening, so the security checks that follow have a real target. Here it connects only to the exact addresses and ports you approved. It does not add nearby hosts or scan UDP, the other common way services listen, and an open port is inventory, not a vulnerability.

### What the original tool does

Naabu is a network port-discovery tool. Upstream offers several scan methods and discovery options; this product binds its invocation to a frozen work plan instead of exposing an unrestricted port-scanning command.

### What this app checks

Naabu 2.6.1 runs the approved TCP connect discovery profile. Exact targets and ports become bounded work units with an attempt journal. Native JSONL service observations retain host/IP and port context; the journal determines which requested units actually completed.

### What it does not check

An open port is not a vulnerability or a successful security scan by itself. This path does not authorize adjacent hosts, CIDR expansion, UDP coverage or every upstream discovery mode.

### Why we selected it

It gives the report an explicit service inventory that can prepare applicable security checks. Keeping discovery separate prevents ordinary listening services from being mislabeled as exploitable problems.

### When to use it

Use it when an owner needs to identify which approved TCP services answer before selecting protocol-aware checks. For the primary internal-system security path, discovery supports the security assessment; it does not replace Greenbone findings.

### What you see in the report

The sample shows two service observations with Naabu provenance and completed work-unit accounting. They appear in inventory and do not increase the finding count.

### Strengths

Machine-readable service discovery is a useful input to a broader assessment. Exact work units make a cancelled or partial sweep distinguishable from a completed one.

### Weaknesses

A TCP connection says little about service identity, patch state or access control. Firewalls and timing can affect observations, and a closed or silent port does not prove the host is safe.

### Opportunities

Compare expected exposure with observed services and prepare a reviewed security profile for an identified endpoint. Repeated inventories can reveal newly exposed services for investigation.

### Threats

Network middleboxes, rate limits and transient outages can distort discovery. Treating an inventory-only result as a clean vulnerability assessment is a separate interpretation risk the report explicitly avoids.

### Version record

| Item | Included on 2026-10-04 |
| --- | --- |
| Engine version (catalog) | 2.6.1 |
| Image tag | 2.6.1-7 |
| Pinned source commit date (UTC) | 2026-05-05T15:29:23Z |
| Source revision | 5a0ca8bde91b5bb16213e9e8b5c6871eac954bd8 |
| Rules / checks | TCP port discovery has no external rule pack |
| Rules revision | Not applicable |
| Data input | authorized target reachability |
| Data revision | None / runtime input |
| Catalog knowledge baseline date | 2026-08-24 |
| Adapter version | 0.2.6 |
| Output format | JSONL |

Image identity: `ghcr.io/teddashh/ai-security-scanner-engine-naabu:2.6.1-7@sha256:e94240f4f067f39b7db9501a48c60411e6b29a215a11dda63406b9e62c061ab6`

## httpx

Checks whether a selected web service responds and records basic response information. It does not assess vulnerabilities.

[Upstream](https://github.com/projectdiscovery/httpx) · [README @ 13037dd](https://github.com/projectdiscovery/httpx/blob/13037dd08b9715cfbd960a70ae1edfef6686a857/README.md) · [Integration and update notes](https://github.com/TED-H-com/ai-security-scanner/blob/335d0666bdc63eb86e6c8c4cddeae110db893397/docs/engines/httpx.md)

### About this tool

httpx is an open-source web-probing tool from ProjectDiscovery, not the Python HTTPX library of the same name. It sends an ordinary web (HTTP) request to an address and records whether a web service answers, the status code it returns, and other basic response details, which a port check alone cannot tell you. We include it in this app because it helps you quickly confirm that an approved web service is responding before a real security check runs against it. Upstream, it can run many more probes. Here it asks only the exact service you approved and does not crawl, log in, or enable every upstream probe. The result is inventory that describes the service, not a vulnerability finding.

### What the original tool does

ProjectDiscovery httpx is an HTTP probing toolkit, distinct from the Python HTTPX client library. Its probes help characterize responding web services; a response alone does not diagnose a vulnerability.

### What this app checks

httpx 1.10.0 uses the bounded read-only HTTP profile for exact approved services. JSONL response records supply URL/status and retained service metadata to typed inventory, with upstream and asset provenance. The managed network path enforces the approved destination scope.

### What it does not check

This integration does not claim a web vulnerability finding from an HTTP status, crawl every application route, authenticate into an application or enable every upstream probe.

### Why we selected it

It supplies a lightweight, inspectable description of an approved web service before or alongside a security check. Separating metadata from Nuclei or ZAP findings keeps the report’s meaning clear.

### When to use it

Use it to confirm that the selected HTTP service responded and to retain basic response context during exposure inventory. Use a security scanner when the question is whether the service has a security problem.

### What you see in the report

The sample includes HTTP service observations with URL/status metadata and source references. The report preserves them as observations even when an upstream record contains a risk-sounding field.

### Strengths

Line-delimited output is easy to preserve and attribute. Response metadata helps explain which service was reachable without requiring a reader to inspect network logs.

### Weaknesses

Metadata is a point-in-time view and may describe a reverse proxy rather than the application behind it. Reachability says nothing about hidden authenticated routes or exploitability.

### Opportunities

Use the inventory to explain selected website assets, compare exposure changes and attach response context to later Nuclei or ZAP work. It also helps distinguish unavailable targets from completed security checks.

### Threats

CDNs, WAFs, transient errors and changing redirects can alter observations between runs. An operator may otherwise overread a successful HTTP response as security assurance, which is why inventory stays separate.

### Version record

| Item | Included on 2026-10-04 |
| --- | --- |
| Engine version (catalog) | 1.10.0 |
| Image tag | 1.10.0-7 |
| Pinned source commit date (UTC) | 2026-07-09T16:11:51Z |
| Source revision | 13037dd08b9715cfbd960a70ae1edfef6686a857 |
| Rules / checks | HTTP metadata collection has no external rule pack |
| Rules revision | Not applicable |
| Data input | authorized HTTP service observations |
| Data revision | None / runtime input |
| Catalog knowledge baseline date | 2026-08-24 |
| Adapter version | 0.2.6 |
| Output format | JSONL |

Image identity: `ghcr.io/teddashh/ai-security-scanner-engine-httpx:1.10.0-7@sha256:6911039efb20370ebd84ed6e57d7d793d5ae7bdff5813c007ac9b2774aaaed1e`

## Nuclei

Identifies website technologies, then runs suitable read-only checks within the approved address and limits.

[Upstream](https://github.com/projectdiscovery/nuclei) · [README @ a8c88fe](https://github.com/projectdiscovery/nuclei/blob/a8c88feb4a1c8e961b7902534ce3af97e9d524a4/README.md) · [Integration and update notes](https://github.com/TED-H-com/ai-security-scanner/blob/335d0666bdc63eb86e6c8c4cddeae110db893397/docs/engines/nuclei.md)

### About this tool

Nuclei is an open-source vulnerability scanner from ProjectDiscovery, and one of the most widely used and trusted tools of its kind. Each check is a template: a written request plus the response that signals a known exposure or vulnerability. It first recognizes which technologies a site uses, then picks the templates that fit. We include it in this app because it helps you quickly find those known problems; it is the default website check, using the templates bundled here. It stays on one approved site address and sends only read-only requests. It does not log in, submit forms, fuzz, run exploits, drive a browser, or ask an outside server to call back. A path you type does not narrow the check to that path.

### What the original tool does

Nuclei evaluates targets using upstream YAML templates. The template repository supplies detector logic and evolves independently of the engine, so the engine and template revisions must both be identified.

### What this app checks

Nuclei 3.11.1 uses the pinned nuclei-templates snapshot and the reviewed read-only HTTP profile. Native automatic scan performs upstream technology detection and selects applicable eligible templates on one approved scheme://host:port origin. Template identity, severity, evidence and remediation are retained.

### What it does not check

The quick profile excludes authentication, redirects to other origins, form/request bodies, out-of-band callbacks, headless flows, fuzzing and exploit-oriented actions. Entering a URL path does not restrict upstream templates to that path; authorization is origin-wide.

### Why we selected it

The upstream template ecosystem provides technology-specific checks without maintaining a product-owned vendor or CVE decision tree. It is the default quick website security choice because the bounded profile can produce real detector evidence.

### When to use it

Use it for an owned website or API origin, after an application deployment, or while reviewing exposed administration surfaces. Confirm authority for the entire displayed origin before running.

### What you see in the report

The sample includes native template matches, including an exposed administration-panel observation classified by the scanner. Each result retains its template ID and original severity; the report does not upgrade an informational match into a critical exploit.

### Strengths

Independent engine/template pins make the detection basis traceable. Upstream applicability and native evidence provide specific results while thin adapters keep detector behavior recognizable.

### Weaknesses

Coverage depends on templates, detected technology and accessible responses. A zero-match run does not prove every eligible template executed or every page and authenticated workflow was tested.

### Opportunities

Combine template findings with ZAP response-level observations and repository evidence to prioritize a concrete website fix. Deliberate template refreshes can add coverage without rewriting product detector logic.

### Threats

A stale template snapshot misses newer checks; a changed WAF or deployment can alter responses and applicability. Unreviewed template updates may also introduce behavior outside the approved profile, so admission and version records must move together.

### Version record

| Item | Included on 2026-10-04 |
| --- | --- |
| Engine version (catalog) | 3.11.1 |
| Image tag | 3.11.1-7 |
| Pinned source commit date (UTC) | 2026-08-08T12:20:01Z |
| Source revision | a8c88feb4a1c8e961b7902534ce3af97e9d524a4 |
| Rules / checks | projectdiscovery/nuclei-templates |
| Rules revision | 24858b4bfabfa86f0bcfd36aea24fb535152b012 |
| Data input | authorized service responses |
| Data revision | None / runtime input |
| Catalog knowledge baseline date | 2026-08-24 |
| Adapter version | 0.2.6 |
| Output format | JSONL / SARIF |

Image identity: `ghcr.io/teddashh/ai-security-scanner-engine-nuclei:3.11.1-7@sha256:c0d9709528f9d900ccf7e676de3e19456865aaa9788828adb29e19bd55204520`

## Greenbone Community Edition

Identifies services on approved hosts and ports, then runs the security checks that apply.

[Upstream](https://github.com/greenbone/openvas-scanner) · [README @ 26465a1](https://github.com/greenbone/openvas-scanner/blob/26465a11ff0e6a98d60a253265fab5974fc757b6/README.md) · [Integration and update notes](https://github.com/TED-H-com/ai-security-scanner/blob/335d0666bdc63eb86e6c8c4cddeae110db893397/docs/engines/greenbone.md)

### About this tool

Greenbone OpenVAS is an open-source network vulnerability scanner maintained by Greenbone. Its tests come from a fixed copy of the Greenbone Community Feed, a separately maintained library of checks. It first identifies which service is listening on a port, then runs the tests that apply to it. We include it in this app because it helps you find known security problems on internal devices and servers that a simple connection cannot reveal. Here it tests only the exact hosts and ports you approved. It does not log in or inspect the machine from inside, guess passwords, try default accounts, or run disruptive checks. When it cannot identify a service, those tests do not run, and the report lists the host as not tested.

### What the original tool does

Greenbone OpenVAS Scanner executes vulnerability tests from its feed, using service detection and test dependencies to determine applicability. The engine and feed are separate inputs; a current engine with an old feed has different knowledge from a refreshed assessment.

### What this app checks

OpenVAS Scanner 23.50.24 uses the pinned Community Feed snapshot identified by feed202610010558. The remote-safe profile admits non-deprecated, unauthenticated gather_info tests and lets upstream prerequisites select applicable work. Each task binds one exact host/port grant; original OID, family, severity, evidence and solution survive normalization and resume.

### What it does not check

No credentials, local security checks, brute-force/default-account checks, destructive/denial-of-service categories or alternate port scanners are enabled. A scheduled feed profile is not proof every VT executed; the current upstream result API does not provide a complete per-VT execution ledger.

### Why we selected it

It supplies meaningful protocol- and service-aware security checks for internal systems, beyond a successful TCP connection. Upstream owns product detection and vulnerability logic, so the product does not need vendor-specific wrapper branches.

### When to use it

Use it for an authorized server, workstation or network appliance with exact TCP ports selected. The beginner profile proposes common ports; an owner may review a different bounded list for the same host.

### What you see in the report

The sample preserves a native XML vulnerability-test result, including its OID and remote evidence. Host/error/inventory records are not automatically converted into vulnerabilities.

### Strengths

The feed and upstream dependency system support service-aware applicability. Exact OIDs, solutions and scope grants make results traceable to both the detector and the authorized endpoint.

### Weaknesses

The stack and feed are comparatively substantial operational inputs. Unauthenticated remote evidence cannot replace authenticated patch inventory, and zero findings cannot establish complete host or feed coverage.

### Opportunities

Use discovery observations to prepare an applicable security check, then compare native OIDs across a later remediation verification. Feed updates can expand reviewed coverage while the adapter remains thin.

### Threats

Feed age, service fingerprint changes and filtered network responses affect applicability. A broader upstream VT category may have different operational effects, so feed refreshes must preserve the admitted remote-safe profile.

### Version record

| Item | Included on 2026-10-04 |
| --- | --- |
| Engine version (catalog) | 23.50.24 |
| Image tag | 23.50.24-feed202610010558-1 |
| Pinned source commit date (UTC) | 2026-08-31T11:14:24Z |
| Source revision | 26465a11ff0e6a98d60a253265fab5974fc757b6 |
| Rules / checks | Greenbone Community Feed vulnerability tests |
| Rules revision | 816c24126e0375d32c667b78d20342ce7c58ec58 |
| Data input | Greenbone Community Feed and Notus snapshot |
| Data revision | 816c24126e0375d32c667b78d20342ce7c58ec58 |
| Catalog knowledge baseline date | 2026-08-24 |
| Adapter version | 0.2.6 |
| Output format | XML |

Image identity: `ghcr.io/teddashh/ai-security-scanner-engine-greenbone:23.50.24-feed202610010558-1@sha256:d2e95d252272488891d04766e66362aacb234e1e2975dca27e834f0050a695c4`

## ZAP

Visits pages on one approved website and checks the responses. It does not submit forms or send attack payloads.

[Upstream](https://github.com/zaproxy/zaproxy) · [README @ 2665d97](https://github.com/zaproxy/zaproxy/blob/2665d972f6d587ba4773a95053ac39af3fdf8df9/README.md) · [Integration and update notes](https://github.com/TED-H-com/ai-security-scanner/blob/335d0666bdc63eb86e6c8c4cddeae110db893397/docs/engines/zap.md)

### About this tool

ZAP (Zed Attack Proxy, long known as OWASP ZAP) is an open-source web application security scanner, and one of the most widely used and trusted tools of its kind. Upstream, it can sit between a browser and a website, crawl pages, inspect every response, and actively send attack payloads. Its passive rules only read the responses, including headers and cookies, without attacking. We include it in this app because those passive rules help you find problems such as missing security headers or unsafe cookie settings on the pages it reaches, as a complement to Nuclei. Here it is optional: it crawls one approved website within fixed limits and does not log in, submit forms, send attack payloads, or leave the site. Nuclei remains the default.

### What the original tool does

ZAP is a web application security testing project with proxy, crawling, passive and active capabilities. Passive scanning analyzes messages it observes; it is a specific part of the much broader upstream tool.

### What this app checks

The official 2.17.0 image supplies passive rules pscanrules 75.0.0. The optional zap_passive_v1 automation plan crawls one approved origin, uses upstream per-request pacing at 5 requests/second, five spider threads and a 10-second request timeout, with two-minute crawl and passive-processing bounds, depth five and 100 children per page. Alerts retain all native instances.

### What it does not check

The profile does not authenticate, submit forms, send active attack payloads or follow another origin. It is an explicit Advanced choice; Nuclei remains the quick default. The pacing is the upstream rate control, not a guarantee of a strict rolling one-second window.

### Why we selected it

ZAP adds response-level inspection and bounded link discovery that complement template-driven Nuclei checks. Keeping alerts and every instance makes repeated page-level evidence inspectable without rewriting passive rules.

### When to use it

Choose it when you want to review headers, cookies and other passive response indicators across reachable pages of one owned origin. It is useful after a web server or response-policy change.

### What you see in the report

The sample retains native ZAP alert IDs, risk/confidence values and per-URL instances. An alert with several instances remains one upstream alert with inspectable occurrences.

### Strengths

Passive rules provide concrete evidence from actual response messages. Instance-level retention helps a maintainer locate every observed occurrence rather than receiving only an alert count.

### Weaknesses

It sees only responses reached within the crawl bounds. Login-only pages, application state and active exploit behavior remain outside this profile, and crawling still sends real read requests to the website.

### Opportunities

Compare passive findings before and after header/cookie changes, and combine them with code and Nuclei findings by asset. A future additional profile would require its own reviewed behavior and authorization.

### Threats

JavaScript-heavy navigation, WAF behavior and short crawl windows can hide pages. Add-on changes can affect rules or request handling, so the official image and bundled add-on versions are recorded together.

### Version record

| Item | Included on 2026-10-04 |
| --- | --- |
| Engine version (catalog) | 2.17.0 |
| Image tag | 2.17.0 |
| Pinned source commit date (UTC) | 2026-08-06T08:30:53Z |
| Source revision | 2665d972f6d587ba4773a95053ac39af3fdf8df9 |
| Rules / checks | zaproxy/zap-extensions pscanrules |
| Rules revision | pscanrules-75.0.0 |
| Data input | authorized service responses |
| Data revision | None / runtime input |
| Catalog knowledge baseline date | 2026-08-07 |
| Adapter version | 0.2.6 |
| Output format | JSON |

Image identity: `ghcr.io/zaproxy/zaproxy:2.17.0@sha256:781a2bdaea47324e7bab583e2263f21d257b0aee61ed51521a5be45f5f5081ef`

## Semgrep

Finds risky patterns in code, using the rule set included with this version.

[Upstream](https://github.com/semgrep/semgrep) · [README @ a0c13f3](https://github.com/semgrep/semgrep/blob/a0c13f304151e531c7e7c00838076211a07a790c/README.md) · [Integration and update notes](https://github.com/TED-H-com/ai-security-scanner/blob/335d0666bdc63eb86e6c8c4cddeae110db893397/docs/engines/semgrep.md)

### About this tool

Semgrep is a widely used open-source static application security testing (SAST) tool: it looks for security problems in source code without compiling or running the project. A plain text search sees only characters, so a line break, different spacing, or a renamed variable can hide the same code. Semgrep parses code into a syntax tree and matches its structure instead. In the Community Edition this app runs, rules that track untrusted data follow it only within one function. We include it in this app because it helps you quickly find risky patterns, such as unsafe command calls or database queries built from user input, using the security rule pack bundled with this app rather than the complete current registry.

### What the original tool does

Semgrep analyzes source code with declarative rules. Language support, rule selection and Community Edition capabilities determine what can be observed without compiling or executing the target project.

### What this app checks

The pinned CE source is built as 1.174.0-4 with 1,493 selected legacy upstream security rules plus four product rules. The pack has 1,497 unique IDs, is embedded offline and retains rule-source provenance. JSON results preserve rule ID, file/line, upstream severity, message, confidence and available fix/CWE details.

### What it does not check

This is not the current complete Semgrep registry or a Semgrep Pro deployment. Proprietary/unavailable parser dependencies and unselected rule families are excluded. The project snapshot is not executed, and parse errors or unsupported files are coverage gaps rather than clean results.

### Why we selected it

It adds code-level security evidence that dependency and secret scanners cannot replace. The rule message and location can lead directly to a developer action while the detector remains upstream-owned.

### When to use it

Use it for a repository or AI application code snapshot, before review or after a risky implementation change. It is particularly useful for unsafe process invocation, input handling and other patterns represented in the pinned pack.

### What you see in the report

The sample shows a shell-based subprocess call with a native rule ID, file location, CWE and scanner-provided correction. It demonstrates an actual adapter-supported Semgrep JSON result shape with simulated source context.

### Strengths

Source locations and explicit rule messages make results actionable. Offline embedded rules provide a reproducible detection basis and avoid uploading the repository for analysis.

### Weaknesses

Pattern matches depend on supported syntax and available context; some need human review. The deliberately pinned legacy pack has a finite date and does not inherit every new upstream rule or paid analysis capability.

### Opportunities

Combine code evidence with Gitleaks/TruffleHog secrets and package findings to explain an application risk. Rule updates can be reviewed with exact original-source IDs and representative native output.

### Threats

Language changes, generated code and missing dependencies can reduce context. Rule distribution terms and parser availability can also constrain updates, so pack composition and source records must remain explicit.

### Version record

| Item | Included on 2026-10-04 |
| --- | --- |
| Engine version (catalog) | source@a0c13f304151e531c7e7c00838076211a07a790c |
| Image tag | 1.174.0-4 |
| Pinned source commit date (UTC) | 2026-08-20T18:29:37Z |
| Source revision | a0c13f304151e531c7e7c00838076211a07a790c |
| Rules / checks | semgrep/semgrep-rules legacy security selection plus four product rules |
| Rules revision | 0f5a85ceab1b82b193d0eaa418784c932d237d68 |
| Data input | repository or filesystem snapshot |
| Data revision | case_artifact_sha256 |
| Catalog knowledge baseline date | 2026-08-24 |
| Adapter version | 0.2.6 |
| Output format | JSON / SARIF |

Image identity: `ghcr.io/teddashh/ai-security-scanner-engine-semgrep:1.174.0-4@sha256:3f1a10c7bce32eae912479c5744dbb653bdfa9a4cbd3d53afd2e0a435b10fb59`

## Gitleaks

Looks for passwords and keys left in project files. Values are hidden in the report.

[Upstream](https://github.com/gitleaks/gitleaks) · [README @ 83d9cd6](https://github.com/gitleaks/gitleaks/blob/83d9cd684c87d95d656c1458ef04895a7f1cbd8e/README.md) · [Integration and update notes](https://github.com/TED-H-com/ai-security-scanner/blob/335d0666bdc63eb86e6c8c4cddeae110db893397/docs/engines/gitleaks.md)

### About this tool

Gitleaks is an open-source secret scanner, and one of the most popular and trusted tools for finding hardcoded passwords, API keys, tokens, and other credentials in project files. Its rules recognize many known key formats, and some also weigh nearby words or how random a value looks. Upstream Gitleaks can also search a repository's Git history, so a key deleted later can still be found. We include it in this app because it helps you quickly find passwords and keys left in the project you select. Here it reads a read-only copy of the current files only: it does not search deleted Git history or test whether a credential still works, and the report hides the secret values.

### What the original tool does

Gitleaks detects secrets using its scanner-owned rules and pattern context. It supports workflows beyond the file snapshot used here; the scan mode matters when interpreting what was searched.

### What this app checks

Native 8.30.1 is packaged as 8.30.1-2, using the pinned default configuration over a read-only repository snapshot. The adapter keeps the rule, file, line, fingerprint and redacted evidence.

### What it does not check

This path does not search deleted Git history, verify whether a credential is live, revoke a key or upload files. Even the full sample report retains the adapter’s secret-value masking; full disclosure refers to asset and context fields.

### Why we selected it

Secret exposure is a high-value first check that works without running project code. Gitleaks supplies specific file/line evidence and complements TruffleHog’s detector families.

### When to use it

Use it before sharing source code, after adding environment/configuration files, or during an AI project review. A reported secret pattern calls for owner verification and, if real, the organization’s rotation process.

### What you see in the report

The sample contains a synthetic API-key-like value. The finding shows Gitleaks attribution and its location while the value stays hidden in both report variants.

### Strengths

A focused offline scan produces readily locatable evidence and avoids needing cloud access. Stable fingerprints support comparison with a later scan.

### Weaknesses

Patterns can match examples or test tokens and can miss unknown formats or dynamically assembled secrets. Scanning a working-tree snapshot does not recover secrets removed from that snapshot.

### Opportunities

Combine two independent secret detectors, preserve their original rules, and let the shared report organize the remediation. Repeating the same snapshot profile verifies whether the source exposure was removed.

### Threats

New credential formats, ignored or omitted files and obfuscated secrets can reduce coverage. Printing full secret values into a report would create a second exposure, so masking remains a product boundary.

### Version record

| Item | Included on 2026-10-04 |
| --- | --- |
| Engine version (catalog) | 8.30.1 |
| Image tag | 8.30.1-2 |
| Pinned source commit date (UTC) | 2026-03-12T15:40:37Z |
| Source revision | 83d9cd684c87d95d656c1458ef04895a7f1cbd8e |
| Rules / checks | scanner-owned Gitleaks default configuration |
| Rules revision | sha256:e163e53b9e7e8a8511e77271e2b323ed057759542a6d988258afe3a1fa329caf |
| Data input | repository or filesystem snapshot |
| Data revision | case_artifact_sha256 |
| Catalog knowledge baseline date | 2026-08-24 |
| Adapter version | 0.2.6 |
| Output format | JSON |

Image identity: `ghcr.io/teddashh/ai-security-scanner-engine-gitleaks:8.30.1-2@sha256:95313654f9c37115a906629a82113ba6e1c729950be70909da8362e9482b477e`

## TruffleHog

Looks for exposed secrets in local files. It does not try the credentials against a live service.

[Upstream](https://github.com/trufflesecurity/trufflehog) · [README @ 3ab759f](https://github.com/trufflesecurity/trufflehog/blob/3ab759fef4bb5935d4fe9ac68b503d05346b8364/README.md) · [Integration and update notes](https://github.com/TED-H-com/ai-security-scanner/blob/335d0666bdc63eb86e6c8c4cddeae110db893397/docs/engines/trufflehog.md)

### About this tool

TruffleHog is an open-source secret scanner, and one of the most popular and trusted tools for finding exposed credentials such as API keys and tokens. It has dedicated detectors for many kinds of credentials. Upstream, it can also ask the matching live service whether a found key works, and it can search Git history. We include it in this app because it helps you quickly find secrets in the current files, with detectors that complement Gitleaks. Here networking is turned off and the scan reads a read-only copy of those files: it does not search Git history or try any credential on a live service. A match is not proof that the key still works, and the report leaves the secret values out.

### What the original tool does

TruffleHog provides detector families for many credential types and supports multiple source and verification workflows. The available upstream online verification feature is deliberately disabled in this product’s local scan.

### What this app checks

The pinned source is packaged in 3.97.0-3 and runs the filesystem profile on one immutable repository working-tree snapshot with networking disabled. JSONL findings preserve detector identity, location and available verification state, while raw secret material is excluded from normal evidence.

### What it does not check

No online key verification, provider login, Git-history walk, remote source connector or credential remediation is part of this profile. An unverified match is not relabeled as a confirmed live credential.

### Why we selected it

Its detector set provides a complementary view of secret exposure alongside Gitleaks. Keeping verification status explicit gives readers useful evidence without making a stronger claim than the native result supports.

### When to use it

Use it for a repository snapshot containing application configuration, integration code or AI service clients. It is appropriate before code distribution or when reviewing accidental credential inclusion.

### What you see in the report

The sample contains detector matches in filesystem context. Both the native detector name and verification state are retained, while secret content remains protected.

### Strengths

Typed native detectors and line-oriented output provide clear provenance. Running offline avoids transmitting suspected credentials to external verification endpoints.

### Weaknesses

Disabling verification reduces certainty about whether a match is active, and overlapping detectors can report the same underlying exposure. Unsupported formats, generated values and absent history remain coverage limits.

### Opportunities

Cross-reference a match with Gitleaks evidence and application ownership, then verify source removal after the team rotates any real credential. Future source types would need independent scope review.

### Threats

Credential formats and provider validation behavior evolve. A future update must preserve the no-verification boundary and redaction behavior rather than silently activating network checks.

### Version record

| Item | Included on 2026-10-04 |
| --- | --- |
| Engine version (catalog) | source@3ab759fef4bb5935d4fe9ac68b503d05346b8364 |
| Image tag | 3.97.0-3 |
| Pinned source commit date (UTC) | 2026-08-21T14:53:01Z |
| Source revision | 3ab759fef4bb5935d4fe9ac68b503d05346b8364 |
| Rules / checks | TruffleHog detectors |
| Rules revision | 3ab759fef4bb5935d4fe9ac68b503d05346b8364 |
| Data input | repository or filesystem snapshot |
| Data revision | case_artifact_sha256 |
| Catalog knowledge baseline date | 2026-08-24 |
| Adapter version | 0.2.6 |
| Output format | JSONL |

Image identity: `ghcr.io/teddashh/ai-security-scanner-engine-trufflehog:3.97.0-3@sha256:dd0e0879bc4d3ac79194d6c734d2a2636cc83fdacb01f611b6b3284fe86dd55a`

## Checkov

Checks supported deployment and infrastructure files for unsafe settings.

[Upstream](https://github.com/bridgecrewio/checkov) · [README @ 0604e97](https://github.com/bridgecrewio/checkov/blob/0604e97b0f77c89a8c6c1fe2219c3d251cbb9789/README.md) · [Integration and update notes](https://github.com/TED-H-com/ai-security-scanner/blob/335d0666bdc63eb86e6c8c4cddeae110db893397/docs/engines/checkov.md)

### About this tool

Checkov is a widely used open-source scanner for infrastructure as code (IaC): the files that describe how cloud resources and deployments should be set up. It reads those files as resources and the relationships between them, not as plain text, and checks them against a library of security policies. We include it in this app because it helps you quickly find unsafe settings in files such as Terraform, CloudFormation, and Dockerfiles before anything is deployed. Here it reads a read-only copy of the selected project. It does not connect to a cloud account, download platform policy data, or apply the files, so the result describes the files, not the live environment.

### What the original tool does

Checkov provides policy checks for infrastructure as code, container configuration and delivery pipelines. It understands resources and relationships rather than treating every file as plain text.

### What this app checks

The selected repository or IaC working tree is mounted read-only. The bundled Checkov 3.3.13 checks select applicable frameworks automatically, including Terraform, CloudFormation and Dockerfile. The product requests quiet JSON failed-check output with framework detection enabled and metadata downloads disabled.

### What it does not check

This profile does not connect to a cloud account, apply Terraform, download platform policy metadata or provide the upstream commercial platform. Unavailable offline severity stays Unknown. Parse failures and source-level skip comments require particular care: this adapter does not currently translate Checkov summary counters into complete coverage accounting.

### Why we selected it

We selected Checkov for policy evaluation across common deployment formats, with exact upstream check IDs and resource coordinates. It complements code analysis and dependency matching: a vulnerable library and an unsafe storage policy are different problems needing different evidence.

### When to use it

Use it when a selected project contains infrastructure or build configuration, before deployment and again after a configuration change. It is especially useful when the cloud environment is not available for a live posture check.

### What you see in the report

Each failed check retains its check_id, name, file, starting line and resource. The sample includes two failed checks. Native code blocks remain in the underlying evidence; the readable report presents location, next action and upstream links without assigning a severity the scanner did not provide.

### Strengths

Broad infrastructure format support and resource-aware checks make it useful early in delivery. Stable check IDs let teams connect a finding to the exact upstream policy and revisit the same resource after a fix.

### Weaknesses

Static configuration cannot establish deployed state, and unresolved variables or missing modules can reduce context. Offline operation omits most platform-provided ratings and guidelines; successful processing is not proof that every file or rule was evaluated.

### Opportunities

Pair source findings with Prowler or ScoutSuite observations on the deployed account, while retaining separate provenance. KICS provides another policy perspective on the same selected files.

### Threats

Infrastructure syntax and cloud defaults change. A pinned policy bundle can miss newer services, while broad suppression comments can hide relevant checks. Updating the engine should include representative files from the formats the product actually invokes.

### Version record

| Item | Included on 2026-10-04 |
| --- | --- |
| Engine version (catalog) | 3.3.13 |
| Image tag | 3.3.13-1 |
| Pinned source commit date (UTC) | 2026-08-20T09:39:24Z |
| Source revision | 0604e97b0f77c89a8c6c1fe2219c3d251cbb9789 |
| Rules / checks | Checkov checks |
| Rules revision | 0604e97b0f77c89a8c6c1fe2219c3d251cbb9789 |
| Data input | repository working-tree snapshot |
| Data revision | case_artifact_sha256 |
| Catalog knowledge baseline date | 2026-08-24 |
| Adapter version | 0.2.6 |
| Output format | JSON / SARIF / CYCLONEDX |

Image identity: `ghcr.io/teddashh/ai-security-scanner-engine-checkov:3.3.13-1@sha256:0ecc187b17faa9c538c9b1ecc08a4195283290222694d0f87d50016f2bb79b35`

## KICS

Looks for unsafe settings in files that describe how your systems are deployed.

[Upstream](https://github.com/Checkmarx/kics) · [README @ e1f23ca](https://github.com/Checkmarx/kics/blob/e1f23cad9640f55b963f22a116b04906b8c16ac6/README.md) · [Integration and update notes](https://github.com/TED-H-com/ai-security-scanner/blob/335d0666bdc63eb86e6c8c4cddeae110db893397/docs/engines/kics.md)

### About this tool

KICS (Keeping Infrastructure as Code Secure), from Checkmarx, is an open-source scanner for infrastructure as code (IaC): the files that describe how your systems are deployed. It runs a library of security queries over formats such as Terraform, CloudFormation, Kubernetes manifests, and Dockerfiles, and ties each result to a file and line. Its bundled queries also look for passwords and keys left in those files. We include it in this app because it helps you quickly find risky deployment settings, with a query library independent of Checkov's that gives a second view. Here it scans a read-only copy of the selected project with the queries bundled in the tool. It does not connect to a cloud account or download extra queries.

### What the original tool does

KICS evaluates infrastructure definitions with a library of security queries across formats such as Terraform, CloudFormation, Kubernetes and Dockerfile. Its results connect a query to individual file locations.

### What this app checks

The product runs the unchanged, digest-pinned KICS 2.1.20 upstream image against one read-only repository or IaC snapshot. Bundled queries, including secret queries, run without a severity exclusion. JSON output supplies query-level descriptions and file-level evidence.

### What it does not check

No cloud deployment, live account inspection or external query download is included. Optional upstream BOM queries are not enabled. Networking is disabled, so external description or version lookups cannot extend the bundled data.

### Why we selected it

KICS adds a query-based view of infrastructure risk while preserving native query UUIDs, severity and source coordinates. Its file and query failure counters also help distinguish a completed check from incomplete processing.

### When to use it

Use it before applying infrastructure changes or reviewing a repository containing deployment definitions. Running it alongside Checkov is useful when different query libraries cover different configuration mistakes.

### What you see in the report

The sample has one configuration finding. Each result retains the query ID, name, native severity, file and line, description and available CWE or query URL. Failed-file or failed-query counters keep the run incomplete while valid sibling findings remain available.

### Strengths

Precise file coordinates and native descriptions make findings practical to fix in a change review. Running the upstream image unchanged keeps the detector and bundled queries close to their maintained source.

### Weaknesses

A file-level policy result may lack runtime context, and inline skip directives can reduce checked lines. Similar issues can be reported by several tools; shared presentation must preserve the distinct native observations.

### Opportunities

Combine KICS with live cloud posture and dependency results for the same asset. Its query URLs give maintainers a direct path to understand or contribute improvements to a problematic rule.

### Threats

New IaC features, changed provider defaults and query regressions can affect relevance. Updating a pinned image needs checks for output shape and failure counters as well as visible findings.

### Version record

| Item | Included on 2026-10-04 |
| --- | --- |
| Engine version (catalog) | 2.1.20 |
| Image tag | v2.1.20 |
| Pinned source commit date (UTC) | 2026-03-03T17:56:16Z |
| Source revision | e1f23cad9640f55b963f22a116b04906b8c16ac6 |
| Rules / checks | KICS queries |
| Rules revision | e1f23cad9640f55b963f22a116b04906b8c16ac6 |
| Data input | IaC project snapshot |
| Data revision | case_artifact_sha256 |
| Catalog knowledge baseline date | 2026-08-24 |
| Adapter version | 0.2.6 |
| Output format | JSON / SARIF |

Image identity: `checkmarx/kics:v2.1.20@sha256:3e5a268eb8adda2e5a483c9359ddfc4cd520ab856a7076dc0b1d8784a37e2602`

## Trivy

Checks supported project and container packages against the included vulnerability database.

[Upstream](https://github.com/aquasecurity/trivy) · [README @ e1fd17a](https://github.com/aquasecurity/trivy/blob/e1fd17a0ea4a8cf24bc4b4dd7e2cfbf4bb31b994/README.md) · [Integration and update notes](https://github.com/TED-H-com/ai-security-scanner/blob/335d0666bdc63eb86e6c8c4cddeae110db893397/docs/engines/trivy.md)

### About this tool

Trivy, from Aqua Security, is an open-source security scanner, and one of the most popular and trusted tools for finding known vulnerabilities in software packages. It reads the dependency files it recognizes, plus individual packages such as Java JAR files, and matches their versions against public advisories in a vulnerability database, usually CVEs, the standard IDs for known flaws. Upstream Trivy can also check settings and secrets. We include it in this app because it helps you quickly find known vulnerable packages, along with a fixed version when the database lists one. Here only its vulnerability checks run, using the database bundled with this app. In a container image it checks operating-system packages only; Grype covers the image's application libraries.

### What the original tool does

Trivy has capabilities for vulnerability, misconfiguration, secret and other security checks across multiple target types. This integration deliberately selects its vulnerability scanner and fixed offline databases.

### What this app checks

Repository and IaC snapshots receive two upstream passes: filesystem analysis for language manifests and lockfiles, then rootfs analysis for individual packages such as JARs. A selected OCI image layout receives OS-package vulnerability checks. The immutable vulnerability and Java databases are bundled into the managed image. The vulnerability database was updated on 2026-08-24; the separate Java identification index on 2026-09-09. The newer Java index does not make the vulnerability advisory database newer.

### What it does not check

The invocation uses only --scanners vuln. Trivy secret, configuration and license scanning are not enabled. Language packages inside OCI images are covered by the separate Grype profile, not this Trivy OCI invocation. Databases do not refresh during a scan.

### Why we selected it

Trivy supplies advisory IDs, installed and fixed versions, vendor scores and package coordinates that can become useful upgrade guidance. The two-pass repository setup uses upstream analyzers rather than recreating package detection in our adapter.

### When to use it

Use it for a project with dependency metadata, a directory containing supported packaged libraries, or a selected container image. Repeat after dependency changes and after the product receives a refreshed vulnerability database.

### What you see in the report

The sample contains four findings. Native vulnerability IDs, severity, affected package/version, fixed version, advisory references and available CVSS/CWE data remain attributable to Trivy. A fixed version is displayed when upstream supplies one; absence is not replaced with a guessed upgrade.

### Strengths

Useful package-level remediation and broad ecosystem analysis support an actionable dependency report. Bundled databases make results repeatable without sending project files to a remote scanning service.

### Weaknesses

Version matching does not establish whether vulnerable code is reachable or exploitable in the application. Missing metadata can prevent identification, and offline results reflect the bundled database date.

### Opportunities

Compare with Grype and use Syft inventory to understand the package population. Source-code checks can add application context, while the report can show a shared remediation without discarding either upstream observation.

### Threats

New advisories, withdrawn CVEs, distribution backports and package-name ambiguity can change a match. Engine upgrades and database refreshes must be recorded separately so readers know which knowledge snapshot produced a result.

### Version record

| Item | Included on 2026-10-04 |
| --- | --- |
| Engine version (catalog) | 0.74.0 |
| Image tag | 0.74.0-4 |
| Pinned source commit date (UTC) | 2026-08-14T10:24:58Z |
| Source revision | e1fd17a0ea4a8cf24bc4b4dd7e2cfbf4bb31b994 |
| Rules / checks | Trivy OS and library package analyzers |
| Rules revision | e1fd17a0ea4a8cf24bc4b4dd7e2cfbf4bb31b994 |
| Data input | Trivy vulnerability database snapshot |
| Data revision | sha256:a61aa42edc534843230ca24ef72ef322a2da18d717c3de4b6277f4aac43926a1 |
| Catalog knowledge baseline date | 2026-08-24 |
| Adapter version | 0.2.6 |
| Output format | JSON / SARIF / CYCLONEDX / SPDX-JSON |

Image identity: `ghcr.io/teddashh/ai-security-scanner-engine-trivy:0.74.0-4@sha256:9bfcef9a6a9d9a69eefcece06b0670eaed72541656b65155469b41acb3855dc2`

## Grype

Finds known vulnerabilities in supported project and container packages using the included database.

[Upstream](https://github.com/anchore/grype) · [README @ b5fa92b](https://github.com/anchore/grype/blob/b5fa92bbcbef655497e3be840a2f718380e2cdd3/README.md) · [Integration and update notes](https://github.com/TED-H-com/ai-security-scanner/blob/335d0666bdc63eb86e6c8c4cddeae110db893397/docs/engines/grype.md)

### About this tool

Grype, from Anchore, is a widely used open-source tool that matches software packages to known vulnerabilities. It compares package names and versions with a vulnerability database and reports the matching advisory, such as a CVE, the standard ID for a known flaw, or a GitHub security advisory, plus any fixed version the database lists. We include it in this app because it helps you quickly find known vulnerable packages in a selected project or container image; in an image, that includes application libraries as well as operating-system packages. When Trivy reports the same issue, the report still shows which tool found what. Here it uses the database bundled with this app, and it does not pull images from a registry or run the container.

### What the original tool does

Grype matches software components to vulnerability data and reports the affected package, advisory and available fix. It works with package catalogs, directories and container-related inputs.

### What this app checks

The managed profile scans selected repository snapshots and single-image OCI layouts using its pinned offline database. The OCI profile includes both OS and language packages, including supported JAR contents, complementing Trivy’s OS-only OCI profile. Output is native Grype JSON. The bundled database uses schema 6.1.9 and was built on 2026-08-24.

### What it does not check

This profile does not pull arbitrary registries, run the container, update the database during execution or prove exploitability. It does not apply package upgrades. Registry acquisition and selecting an approved OCI snapshot are separate from vulnerability matching.

### Why we selected it

Grype offers an independent advisory-matching perspective and a useful package/fix model. Its overlap with Trivy is intentional: coverage and advisory interpretation differ, and the report keeps original scanner attribution when explaining related results.

### When to use it

Use it for dependency review in a selected project or container image, especially images containing application libraries as well as OS packages. Rerun after upgrades or a new bundled advisory snapshot.

### What you see in the report

The sample includes four findings with vulnerability ID, native severity, package and installed version, fix versions where provided, and advisory evidence. Similar Trivy matches remain separately attributable; a shared finding view must not imply independent matches are extra affected assets.

### Strengths

A focused vulnerability matcher with useful package and remediation metadata. Offline invocation provides repeatable analysis while OCI language-package coverage closes a practical gap in the complementary Trivy profile.

### Weaknesses

Package identification and advisory matching can be ambiguous, especially with vendor backports or incomplete version metadata. A match is evidence of an affected-version relationship, not a successful attack against a running application.

### Opportunities

Use Syft inventory and Trivy results to investigate missing or conflicting matches. Group related remediation in the shared report while keeping both scanners’ advisory details and source coordinates accessible.

### Threats

Advisory database age and changes in package ecosystems can leave emerging issues uncovered. Database schema changes can also break a previously valid engine/data pairing, so upgrades must verify the pair together.

### Version record

| Item | Included on 2026-10-04 |
| --- | --- |
| Engine version (catalog) | 0.117.0 |
| Image tag | 0.117.0-4 |
| Pinned source commit date (UTC) | 2026-08-10T16:05:15Z |
| Source revision | b5fa92bbcbef655497e3be840a2f718380e2cdd3 |
| Rules / checks | Grype matchers |
| Rules revision | b5fa92bbcbef655497e3be840a2f718380e2cdd3 |
| Data input | Grype vulnerability database snapshot |
| Data revision | sha256:db6f590412955f6b58cec12bfa4b712b2626eef9a030bffd8f32b9ebce074ff8 |
| Catalog knowledge baseline date | 2026-08-24 |
| Adapter version | 0.2.6 |
| Output format | JSON / CYCLONEDX / SARIF |

Image identity: `ghcr.io/teddashh/ai-security-scanner-engine-grype:0.117.0-4@sha256:56b0d675e3b8d539890e853699c114493a72a54cca0bbe254eceee7ec2b4c517`

## Syft

Lists the software components in your project or container. The list helps you track what is installed.

[Upstream](https://github.com/anchore/syft) · [README @ 2293641](https://github.com/anchore/syft/blob/2293641e3bd628a01bb37639318d62c0ebe89b39/README.md) · [Integration and update notes](https://github.com/TED-H-com/ai-security-scanner/blob/335d0666bdc63eb86e6c8c4cddeae110db893397/docs/engines/syft.md)

### About this tool

Syft, from Anchore, is a widely used open-source tool that builds a software bill of materials, or SBOM: a list of the software components inside a project or container image, such as libraries and operating-system packages. It records the name, version, and type of each component it recognizes. We include it in this app because it helps you quickly see which software the selected project or image contains, so you know what the vulnerability checks are looking at. The list shows what is there; it is not a vulnerability report. Here it reads a read-only copy with no network connection and does not download images from a registry. Known vulnerabilities are left to Trivy and Grype.

### What the original tool does

Syft generates software bills of materials by identifying packages in directories and container images. Its component inventory can be used by vulnerability tools and supply-chain workflows.

### What this app checks

The product runs Syft 1.51.0 offline against a read-only repository directory or a selected single-image OCI layout. The adapter records component name, version, type and package URL from native syft-json. The upstream binary is unchanged; the managed image sets a non-root runtime and temporary cache.

### What it does not check

Syft does not produce vulnerability findings in this product. Native license, CPE and location detail stays in the raw evidence rather than becoming a license-compliance assessment. Arbitrary remote registries and automatic remediation are not part of this selected-snapshot profile.

### Why we selected it

We need to distinguish “what software is here” from “which software has a known vulnerability.” Syft gives that inventory a dedicated upstream source instead of inventing components from vulnerability findings alone.

### When to use it

Use it with repository or container assessments when the component population matters, including cases where vulnerability tools return no matches. Pair it with Grype or Trivy for actual advisory checks.

### What you see in the report

The sample has two component observations and zero security findings. Components appear in the inventory section with Syft attribution. A component being present, or an inventory task completing, never becomes a vulnerability or a statement that the asset is secure.

### Strengths

A dedicated package inventory provides a clearer basis for explaining dependency coverage. Native package URLs help identify the same component consistently without confusing inventory with risk.

### Weaknesses

A package list does not describe runtime reachability, deployment permissions or exploitability. Unsupported ecosystems and missing metadata can leave components unidentified; an empty list does not prove that no software exists.

### Opportunities

Inventory can support later comparisons between saved assessments and explain why a vulnerability matcher did or did not identify a package. It also provides context for reviewing dependency removal and upgrades.

### Threats

Packaging conventions change, and a scanner that cannot recognize a new format may quietly see less software. Large inventories can also exceed bounded ingestion limits; partial inventory must stay distinguishable from a complete component picture.

### Version record

| Item | Included on 2026-10-04 |
| --- | --- |
| Engine version (catalog) | 1.51.0 |
| Image tag | 1.51.0-1 |
| Pinned source commit date (UTC) | 2026-08-10T14:26:29Z |
| Source revision | 2293641e3bd628a01bb37639318d62c0ebe89b39 |
| Rules / checks | Syft catalogers |
| Rules revision | 2293641e3bd628a01bb37639318d62c0ebe89b39 |
| Data input | repository working-tree snapshot |
| Data revision | case_artifact_sha256 |
| Catalog knowledge baseline date | 2026-08-24 |
| Adapter version | 0.2.6 |
| Output format | SYFT-JSON / CYCLONEDX-JSON / SPDX-JSON |

Image identity: `ghcr.io/teddashh/ai-security-scanner-engine-syft:1.51.0-1@sha256:805c9fe522113319f994f99cd68fcb5c18e322dd933e7d89f82cd91f5a5c8501`

## Kubescape

Checks the Kubernetes configuration files you select, without connecting to a running cluster.

[Upstream](https://github.com/kubescape/kubescape) · [README @ 469969f](https://github.com/kubescape/kubescape/blob/469969f6bebf46bef5e808b91a4bb46fb2bbf4ed/README.md) · [Integration and update notes](https://github.com/TED-H-com/ai-security-scanner/blob/335d0666bdc63eb86e6c8c4cddeae110db893397/docs/engines/kubescape.md)

### About this tool

Kubescape is a widely used open-source tool for checking the configuration of Kubernetes, the system many teams use to run containers. It reads YAML and JSON files as Kubernetes resources and compares them with a fixed hardening checklist, the NSA framework based on U.S. NSA and CISA guidance, so each result names the resource and the control that failed. Upstream Kubescape can also scan live clusters and container images. We include it in this app because it helps you quickly find risky settings in the Kubernetes files you select. Here it checks only that saved snapshot, offline. It does not connect to a running cluster, cannot tell whether the files match what is deployed, and does not scan container packages.

### What the original tool does

Kubescape offers Kubernetes posture and security capabilities spanning configuration assessment and broader cluster workflows. This product selects its offline manifest assessment with a pinned framework and policy library.

### What this app checks

A selected Kubernetes YAML/JSON snapshot is evaluated with the pinned NSA framework and embedded Rego policy data. Networking is disabled. The native JSON resource/control results enter the adapter with their upstream IDs, severity and evidence.

### What it does not check

This profile does not connect to a live cluster, install an operator, inspect runtime traffic or scan container packages. It cannot establish whether the saved manifests match deployed state. Container vulnerability matching belongs to Trivy and Grype.

### Why we selected it

Kubernetes-specific resource and control semantics are better handled by an upstream specialist than by generic wrapper rules. A fixed offline framework makes the selected checks explainable and reproducible for a saved manifest set.

### When to use it

Use it for Kubernetes deployment manifests before deployment or when reviewing an exported configuration snapshot. Pair it with kube-bench node evidence when both workload configuration and node hardening matter.

### What you see in the report

The sample contains three native control findings. Valid failed controls remain visible even if other results are malformed, skipped or errored; incomplete evidence does not become a clean assessment. The report retains the affected resource and original control identity.

### Strengths

Resource-aware Kubernetes checks give precise context for manifest changes. The framework and policy revisions are pinned independently from the engine, so a reader can identify the exact assessment knowledge used.

### Weaknesses

A snapshot lacks admission-time mutations, live permissions and runtime behavior. Framework checks cover selected hardening rules rather than every security property of a cluster or application.

### Opportunities

Combine workload findings with node hardening and image vulnerability results in one asset-oriented report. Comparing saved assessments can show which configuration changes resolved an upstream control.

### Threats

Kubernetes API evolution and policy-library changes can make older checks incomplete or inappropriate. Manifest templating that has not been rendered may also prevent the scanner from seeing the final resources.

### Version record

| Item | Included on 2026-10-04 |
| --- | --- |
| Engine version (catalog) | 4.0.12 |
| Image tag | 4.0.12-3 |
| Pinned source commit date (UTC) | 2026-08-12T08:18:39Z |
| Source revision | 469969f6bebf46bef5e808b91a4bb46fb2bbf4ed |
| Rules / checks | Kubescape NSA framework and control artifacts |
| Rules revision | a12188c49147bb6ec379b42a4159d3d5852634b8 |
| Data input | Kubernetes manifest snapshot |
| Data revision | case_artifact_sha256 |
| Catalog knowledge baseline date | 2026-08-24 |
| Adapter version | 0.2.6 |
| Output format | JSON |

Image identity: `ghcr.io/teddashh/ai-security-scanner-engine-kubescape:4.0.12-3@sha256:87c8e5c29c938aa39e304355b1c037b09bda9f89e130b3ccde6df3eaf7ee537c`

## kube-bench

Checks a saved copy of node settings against CIS guidance. It does not inspect a live host with administrator access.

[Upstream](https://github.com/aquasecurity/kube-bench) · [README @ 9f133cb](https://github.com/aquasecurity/kube-bench/blob/9f133cb7509ce1dbedfc860e94474588000e25ac/README.md) · [Integration and update notes](https://github.com/TED-H-com/ai-security-scanner/blob/335d0666bdc63eb86e6c8c4cddeae110db893397/docs/engines/kube-bench.md)

### About this tool

kube-bench is a widely used open-source tool from Aqua Security that checks Kubernetes nodes, the machines that run workloads, against the CIS Kubernetes Benchmark: the Center for Internet Security's published checklist of secure settings. It compares configuration files and running-process facts with each check and marks it pass, fail, or warn; a warning means the check needs information or judgment that automation cannot supply. Upstream kube-bench runs on a live node and can also check the control plane. We include it in this app because it helps you quickly find node settings that miss this checklist. Here it uses only a saved export of node facts and the node checks. It does not log in to a live host or run the control-plane checks.

### What the original tool does

kube-bench runs benchmark checks against Kubernetes configuration and process facts. Its native outcomes include PASS, FAIL and WARN; some checks require information or judgment that automation cannot supply.

### What this app checks

The product replays an explicitly selected exported node-facts snapshot into the unchanged CIS 1.11 node profile. The current typed snapshot carries five required files and two process-fact records. Bounded adapters supply the saved file metadata and process facts expected by the native checks.

### What it does not check

No privileged host mount, live node connection, cluster-wide collection or control-plane benchmark is included. The binary is built from the pinned source revision with a 0.16.0 version stamp; that stamp is not a claim that an upstream release archive was used.

### Why we selected it

The upstream benchmark already defines node checks and their verdicts. Replaying explicit facts keeps that logic upstream while allowing a bounded snapshot workflow without giving a desktop scanner privileged access to a Kubernetes node.

### When to use it

Use it when an approved node-facts export is available and node configuration matters. Use Kubescape separately for workload manifests; neither result substitutes for the other.

### What you see in the report

The native sample contains 26 checks: 15 PASS, six FAIL and five WARN. Six failures become findings with Unknown severity because upstream does not rate them. The five warnings preserve incomplete coverage instead of being counted as passed checks.

### Strengths

Recognizable benchmark IDs and native remediation connect findings to specific node controls. Snapshot replay keeps the evidence inspectable and avoids rewriting benchmark decisions inside the product.

### Weaknesses

Results are only as current and complete as the exported facts. Manual or unavailable checks remain WARN, and the selected node profile does not assess every cluster component.

### Opportunities

Present node failures alongside workload configuration and image vulnerabilities, with separate sources and coverage. A new snapshot after a change provides concrete evidence that the same benchmark check now passes.

### Threats

Benchmark revisions, Kubernetes distributions and changed process arguments can invalidate assumptions in the snapshot contract. Missing facts must never be silently substituted with a passing value during updates.

### Version record

| Item | Included on 2026-10-04 |
| --- | --- |
| Engine version (catalog) | source@9f133cb7509ce1dbedfc860e94474588000e25ac |
| Image tag | 0.16.0-4 |
| Pinned source commit date (UTC) | 2026-08-18T08:46:22Z |
| Source revision | 9f133cb7509ce1dbedfc860e94474588000e25ac |
| Rules / checks | CIS benchmark configuration |
| Rules revision | 9f133cb7509ce1dbedfc860e94474588000e25ac |
| Data input | Kubernetes node configuration snapshot |
| Data revision | case_artifact_sha256 |
| Catalog knowledge baseline date | 2026-08-24 |
| Adapter version | 0.2.6 |
| Output format | JSON |

Image identity: `ghcr.io/teddashh/ai-security-scanner-engine-kube-bench:0.16.0-4@sha256:77a136e48c6491528a70acabc8380e161d362a63c5bcc9d66312393c3436538c`

## garak

Sends 54 fixed test prompts to one approved model service. Review the request limits and provider charges before starting.

[Upstream](https://github.com/NVIDIA/garak) · [README @ 93aa9cd](https://github.com/NVIDIA/garak/blob/93aa9cdec309ec4170559676f1826ea2a679920c/README.md) · [Integration and update notes](https://github.com/TED-H-com/ai-security-scanner/blob/335d0666bdc63eb86e6c8c4cddeae110db893397/docs/engines/garak.md)

### About this tool

Garak is NVIDIA's widely used open-source vulnerability scanner for large language models (LLMs). It sends crafted prompts, called probes, and detectors judge the replies. The probes used here are “Do Anything Now” instructions that try to talk a model out of its rules, and prompts that try to make it output terminal escape codes. Upstream Garak has many more probes. We include it in this app because it helps you quickly see how one approved model responds to these fixed tests. You start this optional check yourself: it sends 54 prompts to one approved OpenAI-compatible HTTPS chat API and model. A clean result covers only these prompts. The provider may charge, and your API key is used once and never saved with the scan or report.

### What the original tool does

NVIDIA garak is an LLM vulnerability scanner with probe, generator and detector plugins. The full upstream project supports many research workflows; this product exposes one deliberately bounded native probe profile.

### What this app checks

Garak 0.17.0 sends 54 native prompts from dan.Dan_11_0, dan.Dan_10_0, dan.Dan_9_0 and ansiescape.AnsiEscaped to one approved HTTPS chat-completions URL and model. Native DAN and escaped-ANSI detectors evaluate responses. Requests are serial, paced at one per second, with a 64-attempt ceiling including retries and a 600-second run deadline.

### What it does not check

This is not the entire Garak plugin catalog, adaptive red teaming, local-model execution or a guarantee of model safety. The profile has no arbitrary prompt editor or auxiliary model service. Provider usage may incur charges; only the exact selected endpoint and model are approved.

### Why we selected it

We selected Garak to use established upstream probes and detectors rather than invent model-risk verdicts in a wrapper. Its evaluation counts let the report distinguish observed failures, evaluated prompts and unjudged or missing work.

### When to use it

Use this optional check for a model API you are authorized to assess, after confirming the exact URL, model and provider charges. It is useful after model or guardrail changes. A fresh local API key is consumed once and is not stored in saved cases or reports.

### What you see in the report

The sample includes four probe/detector findings from a native-format JSONL evaluation. Each retains failure and evaluation counts and the original pair identity. Severity stays Unknown. Missing evaluations, unjudged attempts or a truncated run leave coverage incomplete; raw model replies are not copied into findings.

### Strengths

Native probes and explicit detector counts make a narrow behavioral test inspectable. Exact endpoint binding, TLS verification and fixed request budgets make its cost and execution scope clearer than an open-ended agent test.

### Weaknesses

A small prompt set cannot characterize all model behaviors. Detector heuristics and response variability can produce ambiguous outcomes; the same endpoint may behave differently after a provider-side change.

### Opportunities

Combine behavioral results with Agentic Radar’s architecture inventory and MCP Armor’s configuration checks. Repeated, separately timestamped assessments can help investigate whether a guardrail change affected the tested behaviors.

### Threats

Model providers can change behavior without changing the model name, and new attack styles may not be represented in the pinned probes. Rate limits, API schema changes and billing policies can also interrupt or alter the practical test.

### Version record

| Item | Included on 2026-10-04 |
| --- | --- |
| Engine version (catalog) | 0.17.0 |
| Image tag | 0.17.0-1 |
| Pinned source commit date (UTC) | 2026-09-09T18:19:05Z |
| Source revision | 93aa9cdec309ec4170559676f1826ea2a679920c |
| Rules / checks | garak packaged probes and detectors |
| Rules revision | Bundled with engine source 93aa9cdec309ec4170559676f1826ea2a679920c |
| Data input | the AI model endpoint named by the case scope grant |
| Data revision | None / runtime input |
| Catalog knowledge baseline date | 2026-09-12 |
| Adapter version | 0.2.6 |
| Output format | JSONL |

Image identity: `ghcr.io/teddashh/ai-security-scanner-engine-garak:0.17.0-1@sha256:8a39b5812a4fd5aa2caecfef089ff85c39709f1bc00afa3328714346baab222f`

## Agentic Radar

Maps agents, tools and connections in supported AI workflows without running them.

[Upstream](https://github.com/splx-ai/agentic-radar) · [README @ 65a7e4b](https://github.com/splx-ai/agentic-radar/blob/65a7e4bd01e2034c7cb52e9620eeed287688cc53/README.md) · [Integration and update notes](https://github.com/TED-H-com/ai-security-scanner/blob/335d0666bdc63eb86e6c8c4cddeae110db893397/docs/engines/agentic-radar.md)

### About this tool

Agentic Radar is an open-source tool that reads AI agent projects and maps how their pieces connect. You choose one of the supported frameworks (LangGraph, CrewAI, n8n, OpenAI Agents, or AutoGen), and its parser lists the agents, tools, and MCP servers and the links between them. An MCP server is an outside tool reached through the Model Context Protocol, a standard way for an AI app to call other tools. Upstream Agentic Radar also offers broader risk analysis. We include it in this app because it helps you quickly understand what an AI agent project contains before you review it. Here it only inventories one saved copy of the project. It does not run the workflow, contact a model, or report security problems.

### What the original tool does

Agentic Radar analyzes agentic workflows and provides architecture and security-oriented analysis capabilities. Our integration selects its framework parsers and graph inventory, not the complete upstream analysis workflow.

### What this app checks

An explicitly selected framework—LangGraph, CrewAI, n8n, OpenAI Agents or AutoGen—is parsed from one immutable repository snapshot. Offline output records workflow components and edges. A narrow machine-readable JSON patch exposes native parser data; the product does not execute the application or load its .env file.

### What it does not check

No live agent invocation, prompt attack, model download or network access is included. Upstream warnings and graph structure are not converted into invented security findings. The broader upstream risk-analysis features are not claimed as enabled.

### Why we selected it

A useful AI assessment first needs to understand the components selected for review. Native framework parsers give us that structure without creating a second parser implementation or calling the application’s tools.

### When to use it

Use it when reviewing a supported agent framework project and you want an inventory of agents, tools and workflow connections before deeper testing. Choose the actual framework explicitly; unsupported or dynamic construction may remain outside the parsed graph.

### What you see in the report

The sample contains 33 inventory observations and zero vulnerabilities from Agentic Radar. Parser diagnostics remain coverage information; known incomplete CrewAI parsing is not shown as a complete architecture. Every observation keeps its upstream source identity.

### Strengths

Specialized framework knowledge produces more useful structure than a generic file listing. Static offline analysis can reveal the application’s declared tools and connections before granting any runtime access.

### Weaknesses

Static parsers cannot fully resolve runtime-generated agents, conditional imports or dynamically selected tools. Inventory describes structure, not whether an agent is safe or whether a tool can actually be exploited.

### Opportunities

Use the graph to decide where a separately authorized Garak or MCP configuration check is relevant. Future upstream machine-readable exports could remove the small maintained output patch.

### Threats

Fast-moving agent frameworks can change APIs faster than pinned parsers follow. A plausible-looking partial graph could mislead readers unless diagnostics and framework scope remain visible.

### Version record

| Item | Included on 2026-10-04 |
| --- | --- |
| Engine version (catalog) | 0.14.1 |
| Image tag | 0.14.1-1 |
| Pinned source commit date (UTC) | 2025-11-27T15:28:30Z |
| Source revision | 65a7e4bd01e2034c7cb52e9620eeed287688cc53 |
| Rules / checks | No vulnerability rules are consumed; only the static workflow graph is normalized |
| Rules revision | Not applicable |
| Data input | repository working-tree snapshot |
| Data revision | case_artifact_sha256 |
| Catalog knowledge baseline date | 2026-09-13 |
| Adapter version | 0.2.6 |
| Output format | JSON · native parser graph via output patch |

Image identity: `ghcr.io/teddashh/ai-security-scanner-engine-agentic-radar:0.14.1-1@sha256:2a8d16b9ff5ac7974b0aea8e6504219e0da295b804d01f51da0b4267d7cdafae`

## MCP Armor

Checks a selected MCP configuration for exposed keys and overly broad tool permissions. It does not start or contact MCP servers.

[Upstream](https://github.com/aira-security/mcp-armor) · [README @ 6af4cee](https://github.com/aira-security/mcp-armor/blob/6af4cee4665ab6242f02a88952f9127b6a04922a/README.md) · [Integration and update notes](https://github.com/TED-H-com/ai-security-scanner/blob/335d0666bdc63eb86e6c8c4cddeae110db893397/docs/engines/mcp-armor.md)

### About this tool

MCP Armor is an open-source tool for checking Model Context Protocol (MCP) configuration, the file that tells an AI app which outside tools to connect to. Two of its checks read that file: one looks for keys and other secrets written into it, the other flags tool commands and permissions broader than needed. The report leaves out the matched secret. Upstream, it can also contact the configured servers and run tests that use a model. We include it in this app because it helps you quickly find exposed keys and overly broad tool permissions in the configuration you select. Here it reads only that file from the saved project; it does not start or contact an MCP server, load a model, or show what a running server enforces.

### What the original tool does

MCP Armor provides security checks for Model Context Protocol configurations and related workflows. The product isolates two existing native static checks in a configuration-only mode.

### What this app checks

MCP Armor 1.0.2 evaluates one explicitly selected JSON/YAML configuration from a read-only repository snapshot. The native hardcoded_secrets and excessive_tool_permissions checks keep their original patterns, severity and decisions. A maintained patch adds a configuration-only entry point and a structured completeness ledger.

### What it does not check

No MCP server is started or contacted. No tools are invoked, no prompt-injection model is loaded, and no runtime permissions are tested. This integration does not claim the complete upstream dynamic-testing feature set.

### Why we selected it

The two native checks address concrete configuration mistakes with useful evidence, while a bounded file-only mode fits the product’s local-project workflow. We preserve upstream detector logic instead of replacing it with product-authored regular expressions.

### When to use it

Use it when the selected repository includes a recognized MCP configuration and you want to review secrets or tool permissions before running its servers. A project without an applicable configuration does not gain an artificial failed check.

### What you see in the report

The sample includes both native finding types. Check ID, severity, configuration path and server or line coordinates remain visible, while matched secret material is excluded. The JSON envelope records whether each of the two checks completed; parse or check failures retain incomplete coverage.

### Strengths

A small, explicit check set is easy to explain and audit. Offline configuration review can find exposed credentials or broad permissions before a server is ever launched.

### Weaknesses

Static configuration does not show what a running server actually enforces. Pattern-based secret detection can miss unusual values or flag examples; permissive configuration also needs application context to assess its real impact.

### Opportunities

Combine these findings with Gitleaks or TruffleHog and Agentic Radar’s tool inventory. An equivalent upstream configuration-only mode could replace the maintained entry-point patch while retaining native results.

### Threats

MCP configuration conventions and permission models evolve quickly. Upstream schema changes could break the strict result contract, while hiding partial checks would create a false impression that both checks completed.

### Version record

| Item | Included on 2026-10-04 |
| --- | --- |
| Engine version (catalog) | 1.0.2 |
| Image tag | 1.0.2-config-only.1 |
| Pinned source commit date (UTC) | 2026-03-27T09:05:47Z |
| Source revision | 6af4cee4665ab6242f02a88952f9127b6a04922a |
| Rules / checks | MCP Armor hardcoded_secrets and excessive_tool_permissions configuration checks |
| Rules revision | 6af4cee4665ab6242f02a88952f9127b6a04922a |
| Data input | one MCP configuration file selected from the repository snapshot |
| Data revision | case_artifact_sha256 |
| Catalog knowledge baseline date | 2026-09-13 |
| Adapter version | 0.2.6 |
| Output format | JSON · configuration-only output patch |

Image identity: `ghcr.io/teddashh/ai-security-scanner-engine-mcp-armor:1.0.2-config-only.1@sha256:f8dcf9b774e0f90cfbe32d81b1dc04c6b1d61538fa9829ca28c674d78440dfdc`
