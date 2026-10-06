# ai-security-scanner product specification

Status: canonical product behavior

This document is the sole source of truth for product behavior. Architecture, implementation, test, and operational documents may explain how, but they do not change the user outcome defined here.

A precedence banner is not enough to preserve alignment: a conflicting subordinate document or implementation is a defect to fix, not an alternative product direction.

## 1. Product direction

`ai-security-scanner` helps an IT generalist or developer find which selected company assets have real security problems and understand what to do next, without first learning a collection of scanner tools, Linux, containers, or security terminology.

Five principles control product decisions:

1. A beginner quickly completes a meaningful scan and understands the result.
2. Scanner integrations stay as close to upstream behavior as practical.
3. All results become one professional, product-owned report instead of disconnected tool reports or framework views.
4. Versioning, publication, certification, and compliance positioning belong to the product owner. Existing work is preserved, but it is not an engineering priority or product prerequisite unless the owner explicitly asks.
5. User-facing choices, progress, and reports are concise first and detailed on demand. The product does not fill the primary path with defensive caveats, implementation defects, test-harness language, or explanations that transfer product responsibility to the user. Required legal terms belong in one report-end or footer destination; technical evidence belongs in collapsed detail.

The product succeeds when a user can say:

> I selected the repositories, internal systems, endpoints, and websites I am responsible for. The product ran applicable security checks and gave me one report showing which assets need attention, what to do, and what was not checked.

### 1.1 Primary user

The primary user is a Windows-based IT generalist, developer, or small-business operator who:

- has little or no security-scanning experience;
- can identify one or more websites, code projects, services, network devices, or endpoints they may assess;
- wants useful next actions rather than scanner output;
- may never have used WSL, Podman, containers, scanner engines, or a CLI.

Experts are secondary users. Their evidence and controls remain available through progressive disclosure and exports, but they do not define the first-run journey.

### 1.2 Core jobs

The product makes these jobs simple:

1. Build one IT scan project from the repositories, internal inventory or endpoints, and websites the user explicitly selects.
2. Check each selected repository for risky code, exposed secrets, vulnerable dependencies, and unsafe configuration.
3. Check each selected internal system, network device, or endpoint with an applicable service-aware or vulnerability scanner; inventory alone is preparation, not success.
4. Check each selected website or API for real security problems with a reviewed web profile.
5. Run those applicable checks in one scan and answer **which assets have vulnerabilities** in one prioritized report, even when an independent check does not finish.
6. Save, share, reopen, compare, and add or remove selected assets without rebuilding the project.
7. Add cloud, infrastructure-code, container, and Kubernetes sources only when needed.

The product is not a security guarantee, an aggressive penetration test by default, an automatic remediation system, a raw-scanner dashboard, or a compliance opinion. It never makes a beginner administer runtime infrastructure merely to use the product.

## 2. First meaningful value

### 2.1 What counts

A first result is meaningful only when at least one security-relevant check actually ran against the selected target or its selected read-only snapshot.

A meaningful result is one of:

- an evidence-backed security problem with an actionable next step;
- an evidence-backed statement that completed checks observed no problem in their exact scope, with important limits and a sensible next step;
- a terminal incomplete result that preserves completed security checks and gives one direct continuation for work that could not finish.

A DNS lookup, ping, socket connection, open/closed port observation, runtime health check, target validation, or scanner download is preparation or inventory. By itself it is not a vulnerability scan, a security finding, or first meaningful value.

### 2.2 Recommended first paths

The home screen leads with three choices:

- **Scan my IT environment**: in one compact setup, add multiple repository folders, complete website URLs, and approved internal systems by exact hostname or IP address, then run the applicable upstream checks together with one Start.
- **Check a website**: enter one complete URL and run a conservative, reviewed web-security profile.
- **Check a project folder**: choose one local folder and run a read-only code profile.

The two single-target choices are shortcuts into the same project model; the user can add more assets later. Cloud accounts and other advanced sources remain secondary. A localhost connection test may remain as a diagnostic labeled exactly as a connection test; it must not be a primary scan action.

### 2.3 Interaction and time

The single-target beginner path has three decisions:

1. Choose what to check.
2. Enter a URL or choose a folder.
3. Review the exact target and press **Start scan**.

The product derives a useful name from the URL or folder. Naming a project, adding an organization, choosing engines, or visiting a project-management screen is not required before the first scan.

The IT-environment path is additive rather than wizard-heavy:

1. Add the exact repository folders, complete website URLs, and approved internal systems to check. Each internal-system row asks only for one exact hostname or IP address. A collapsed Advanced control may replace the visible common TCP-port defaults with up to 64 exact ports; it never accepts a range, CIDR, URL, credential, or neighboring host. The product, not the beginner, chooses an upstream scanner profile. Inventory ranges remain separate and do not silently become active targets. At least one scan-ready asset is enough to begin.
2. Review one concise scan plan grouped by asset type. The product selects the applicable upstream profiles and shows any asset that is inventory-only or still needs a port, protocol, or authorization choice.
3. Confirm the displayed network targets and press one **Start scan** action. Local folders need no network authorization.

Adding ten assets must not create ten copies of the same form. Repeated targets use compact rows, shared safe defaults, and per-target overrides only where the execution boundary differs.

The quick profile uses one concise timing target from Home through Review and active Progress: a useful result within minutes after local tools are ready. Scanner names, scope boundaries, and other technical detail appear only where they change the user's action or in collapsed detail. The unified report opens when the run reaches a terminal outcome.

If tools need preparation, the product explains download size, expected wait, and any operating-system action in ordinary language. Preparation runs in the background, resumes after interruption, and never hides saved reports.
After preparation succeeds in the same uninterrupted UI context, the product
continues the same reviewed scan without asking for a second Start. It does not
reuse that request after the user leaves the page, changes projects, cancels
setup, starts other scan work, or restarts the app. If Windows or the app must
restart, the project returns to Review with its previously prepared eligible
assets selected; the user reviews them and presses **Start scan** again instead of the product
persisting an automatic target-contact instruction across restart.

## 3. Beginner journey

### 3.1 Home and target setup

Without technical detail, Home answers what can be checked, which choice is recommended, what result it provides, and roughly how long it takes. Cards name outcomes rather than engines and have one primary action.

Setup asks only for the selected target or targets:

- an IT environment: repeatable local-folder and complete website inputs plus repeatable exact hostname-or-IP inputs for approved internal systems; each entry stays independently removable and reviewable, and ports remain an optional Advanced override;
- a website: one complete `http://` or `https://` URL;
- a project: one local folder selection;
- a public or internal system: an exact host, domain, or bounded range plus a concise ownership/authorization confirmation;
- an advanced source: only the information required by that source.

Validation is immediate, specific, and non-contacting. The product does not probe an external target merely to validate a form value.

### 3.2 Review and Start

One focused review shows:

- every exact target or snapshot, grouped as repositories, internal systems/endpoints, and websites;
- the applicable included security checks in plain language for each group;
- expected time and important request or resource limits;
- the most important exclusions;
- one **Start scan** action.

Optional depth, rate, template, and engine controls are collapsed. Unchanged authorization is not requested twice.

### 3.3 Progress

Progress leads with what is happening, which asset is being checked, confirmed problem counts, completed/remaining/attention-needed assets and checks, elapsed time and range, and supported controls. **View results** becomes the obvious primary action when the run reaches a terminal outcome.

Scanner logs and runtime details remain collapsed. Durable task outcomes update Progress immediately without exposing a half-finished report.

Tool preparation progress appears in the main content, including on narrow
screens. An expected missing-runtime response becomes this preparation state,
not a contradictory scan-failed message.

### 3.4 Results and export

Results open only for a terminal run and show the unified report. It first answers which repositories, internal systems/endpoints, and websites need attention, then shows the important problems and next actions before technical metrics. A readable HTML report has one primary save action; JSON and specialist formats remain secondary. Export does not create a live or interim report.

## 4. Real scan semantics

### 4.1 Website and API

The recommended quick profile checks one exact URL origin: scheme, host, and port. The path the user entered is retained as context, but upstream templates may request other paths on that same origin. Review states this before Start. A user authorized for only one path must not use the origin-wide profile.

The pinned Nuclei template snapshot owns vulnerability and technology coverage. The launcher mechanically admits its bounded read-only HTTP templates, then Nuclei automatic scan performs Wappalyzer and upstream technology detection before selecting matching vulnerability and exposure templates. The product does not maintain a hand-picked vendor, technology, or CVE list. The selected profile, pinned template revision, rate, concurrency, per-request timeout, and execution ceiling are product defaults rather than beginner inputs.

The profile does not crawl other hosts, follow redirects, authenticate, submit forms or request bodies, use out-of-band callbacks, headless flows, fuzzing, credential attacks, uploads, denial-of-service, or exploit-oriented templates. Positive findings retain the upstream template ID, severity, evidence, and remediation. A zero-match result means only that Nuclei completed its applicability-driven scan and returned no findings; it does not mean every eligible template ran or every page and API workflow was tested.

The advanced website choice may instead crawl links on that same approved origin with ZAP and apply its upstream passive rules to the responses. Nuclei remains the recommended quick default. Review freezes ZAP's own profile, request rate, concurrency, timeout and crawl bounds; it does not reuse another scanner's authorization. ZAP does not sign in, submit forms, send attack payloads or contact another origin. A run without observed responses is incomplete. A zero-alert result covers only the responses examined within the displayed bounds.

### 4.2 Local project

The recommended profile creates a bounded read-only snapshot of the chosen folder and runs applicable upstream checks for:

- exposed secrets, with values masked in presentation;
- risky code patterns;
- vulnerable dependencies when supported manifests exist;
- unsafe application, deployment, and infrastructure configuration.

The product does not modify, build, execute, upload, commit, or push the project. Unsupported languages and missing manifests are visible limits, not clean results.

Repository ignore rules still prune ordinary ignored files and generated directories. Common secret-bearing regular files in source directories, including `.env` variants, private keys, registry/auth configuration, and `*.tfvars`, remain in the bounded snapshot so the upstream secret scanners can inspect them; ignored dependency, build, cache, and VCS directories are not reopened.

**Check fixes** reads each local folder again. The user chooses the folder once more; the product saves a new read-only copy as the same asset and compares it with the copy the earlier scan read. Technical detail names both copies. A problem the same rule still reports in the same file stays **still present** when only its line moved.

### 4.3 Local service

A connection observation answers only whether one address and port accepted a TCP connection, refused it, or did not answer in time. It is labeled **Connection test** and never becomes a vulnerability finding.

A local-service security scan identifies an applicable protocol and runs at least one protocol-aware security check. Otherwise the report says only connectivity was observed and offers a suitable real scan.

### 4.4 Public, internal, AI, and advanced targets

Public and internal scans contact only displayed approved targets and ports. Quick discovery identifies services; meaningful value begins when a service-aware or vulnerability check completes.

The internal-system path accepts any individually approved server, workstation, network appliance, or other TCP-speaking system by exact hostname or IP address. The beginner does not choose a vendor, model, operating system, scanner, or list of product rules. The default profile shows and freezes these common TCP ports before Start: 22, 23, 25, 80, 443, 445, 3389, 5900, 8080, and 8443. Advanced users may replace that list with up to 64 exact ports for the same host. CIDRs and neighboring hosts remain inventory-only unless the user adds and approves each exact system.

The pinned Greenbone Community Feed drives product and vulnerability selection. For this profile, the launcher mechanically selects current, non-deprecated, unauthenticated remote `gather_info` VTs and lets Greenbone's upstream dependency, service-detection, required-key, and required-port logic decide which checks apply. It excludes local security checks, brute-force and default-account checks, credentials, policy/compliance families, Nmap NSE and alternative port scanners. It also excludes every `attack`, `mixed_attack`, `denial`, `destructive_attack`, `kill_host`, and `flood` VT category. The launcher keeps `safe_checks` and upstream optimization enabled, supplies no credentials, and confines traffic to the exact approved host and ports.

Vendor and product names come only from upstream detection evidence. They never select a product-owned branch or vendor-specific wrapper. Updating the pinned feed updates the mechanically derived remote profile without copying detector logic into the application.

A scheduled upstream profile is not proof that every VT executed. Greenbone skips checks whose service, product, key, or port prerequisites are absent, and its current result API does not provide a complete per-VT execution ledger. Positive findings retain their upstream OID, family, severity, evidence, and solution. A zero-finding result says only that Greenbone completed its applicability-driven scan of the displayed ports and returned no findings; it does not claim every feed check ran, whole-host coverage, authenticated patch inventory, or a secure device.

Previously saved exact HTTPS, SSH, RDP, VNC, SMTP, and Telnet profiles keep their original single-service scope and remain runnable. They are compatibility records, not the new beginner setup, and are never silently widened into the generic host profile.

One IT-environment run may contain local repository checks, internal endpoint checks, and website checks at the same time. The execution plan binds each upstream scanner to only its applicable approved assets. An engine selected for one asset never expands to every compatible asset, and a scanner failure for one asset never suppresses completed sibling results.

An AI application scan checks selected code, dependencies, secrets, prompts, configuration, and deployment files the product can inspect. It does not imply model-behavior or jailbreak testing unless those activities ran.

Optional AI workflow inventory reads the same saved repository with one explicitly selected framework. Agentic Radar's native static parser lists agents, tools and workflow connections without executing the project, loading its environment settings or contacting hosted models. Missing or incomplete workflow inventory stays visible as inventory coverage; it cannot create a vulnerability finding or establish a successful security scan.

Optional model behavior testing is a separate explicit run against one exact HTTPS chat-completions URL and model identifier. Garak uses the fixed native DAN/ANSI profile of 54 prompts and preserves detector failure counts without inventing severity. Before starting, the user confirms authority, public/private network scope, inference limits and provider charges. Requests are serial, paced at one per second, with TLS verification, no redirects, a 20-second timeout and a ten-minute deadline. Retries count toward 64 attempts; each requests at most 150 output tokens. The API key remains in local app memory for at most 30 minutes and is consumed once at dispatch; it is never saved with the case. Another attempt requires new consent and a new key. Ordinary rescan actions do not automatically send paid model requests. Failed or unfinished model checks retain partial evidence and completed sibling results, and never imply that the model passed all tests.

Cloud, IaC, container, and Kubernetes paths use exact selected scopes and read-only inputs by default. They remain advanced and never add setup to an unrelated website or project scan.

A cloud or Microsoft 365 scan is something a beginner can finish alone. The most common reader owns or administers the account, so the cloud path leads with numbered provider-console steps for creating read-only access once, then the provider's official sign-in. Handing the setup to an administrator stays available as a secondary choice. When a provider rejects a sign-in for having too much or too little access, the panel names that cause and the fix rather than asking for a retry.

## 5. Scanner integration and execution

### 5.1 Stay close to upstream

The product prefers established upstream scanners over reimplementing detection. An integration:

- uses the scanner's documented interface;
- preserves upstream rule IDs, versions, severity, locations, and evidence;
- normalizes presentation without changing the underlying result;
- limits wrapper logic to scope, isolation, input preparation, parsing, cancellation, and resource bounds;
- pins versions when needed, then updates deliberately;
- tests against representative real upstream output.

Patches and forks are last resorts. Each maintained patch has a narrow reason, an upstream reference when available, and a removal plan. Safety controls belong around the scanner rather than in a long-lived fork whenever possible.

### 5.2 Independent outcomes

Each target/check task ends as queued, running, completed, completed with partial evidence, not applicable, could not run, or cancelled.

One unavailable scanner does not discard another scanner's findings. The task plan is saved before execution so failure still produces a useful explanation. Retry reruns compatible unfinished work unless the user starts a new scan with changed scope.

### 5.3 Runtime

Disposable scanner infrastructure is an implementation detail. The product prepares and repairs its runtime automatically, preserves ambiguous or unrelated system objects, and does not instruct beginners to run generic WSL, container, or cleanup commands.

Runtime availability affects only dependent checks. Existing projects, results, exports, and independent checks remain usable.

## 6. Unified professional report

Every terminal run produces one durable report model used by Results, reopen, preview, and readable export. An active run produces Progress state, not a report. A combined IT-environment run is one report, not separate reports that the user must mentally merge. Every requested repository, website, internal system, legacy service endpoint, or inventory-only item has one asset row derived from its own findings, completed checks, and coverage gaps. It is professional because it is consistent, evidence-based, prioritized, concise, and actionable, not because it mirrors an external framework.

### 6.1 First layer

Without opening technical details, the user can answer:

1. Which assets have vulnerabilities or other security problems?
2. What needs attention first?
3. What could happen if I ignore it?
4. What is the smallest practical next step?
5. How can I verify the fix?
6. What exactly was checked and not checked for each asset?
7. Which requested work completed and which work needs attention?

Each priority item shows severity, confidence, affected target/location, plain-language impact, next action, and verification guidance. Priority is transparent ordering, not a pseudo-precise score.

Severity is the scanner's own rating; this product assigns one only where the scanner did not, and says so. Priority is this product's recommended order. A scanner check that enforces a benchmark item current guidance advises against keeps its scanner severity, shows the benchmark the scanner reported, and is ordered at the Low tier with its reason on the card: the AWS IAM password character-mix and scheduled-expiry checks, which CIS AWS Foundations Benchmark v1.2.0 lists, later CIS versions dropped, and NIST SP 800-63B-4 advises against. Their password-policy problem card tells the reader to fix failed length or reuse settings first.

Product-authored finding narrative states the result, possible impact, next action, rollback, and verification directly. The specialist type is separate routing information; it does not wrap the action in human-review, approval, or responsibility-shifting language. When an upstream scanner supplies no severity, the report says that the scanner did not rate it and keeps the severity **Unknown**.

The asset summary gives every requested asset exactly one beginner-readable state: **problems found**, **no problems in completed checks**, **incomplete or failed**, or **not tested**. A finding linked to multiple assets counts for each affected asset. “No problems” applies only to completed security checks; discovery-only or connection-only work cannot earn that state.

Each completed check names the scanner version that ran and that scanner's last-updated date. Scanner age is disclosure, not a result state: a check is never called expired, and an older scanner never makes a completed check or the report incomplete.

Reachability inventory such as an open port or responding HTTP service appears in a separate **Observed services (not vulnerabilities)** section. It is not counted as a problem, placed in remediation priorities, or given a fix workflow merely because it shares the saved-result pipeline.

That section leads with the number of observed services, affected targets, and
a small representative sample. The complete inventory and evidence remain
available in a collapsed detail rather than displacing actual problems.

### 6.2 No-problem and incomplete results

“No problems observed” is limited to checks and scope that completed. It never means “secure.” Connection failure, missing input, scanner failure, cancellation, and untested scope are not green or passed.

A terminal incomplete report preserves completed findings and places consequential missing coverage beside the relevant result, with one direct product action such as Retry, choose a folder, or narrow the target. The first layer does not repeat caveats; full scope, evidence, and formal terms remain available at the end or in collapsed detail.

The readable report contains one report-end terms and technical-record disclosure after all actionable content. It is collapsed in the product UI and appears as the final section of HTML export. No legal, compliance, automation, or report-status disclaimer interrupts the first layer.

### 6.3 Evidence and one presentation system

The report retains original scanner identity, rule ID, version, severity, location, evidence reference, timestamps, and check outcome. Raw evidence, diagnostics, hashes, runtime detail, and advanced filters are collapsed by default.

HTML export can include original scanner files as downloadable ZIP attachments at the report end, before the terms. Each attachment belongs to one check in the selected terminal run and preserves original file bytes and relative directories, including report images and styles. Original files remain inert inside the consolidated report. Failed checks may have only logs; their attachments do not imply a successful security result. The export preview and saved record identify how many original files are included or omitted. Attachments obey the chosen redaction setting and require an explicit export choice; the default export continues to omit them. Printed or browser-generated PDF copies do not carry the embedded attachments.

Related findings may be grouped for presentation, but original observations remain accessible. Unknown severity or confidence stays unknown. Machine-readable exports derive from the same report model rather than becoming separate interpretations.

Related AWS checks share one first-layer problem card only within the same terminal run and approved account: the reviewed Prowler and ScoutSuite IAM password-policy checks, their recent root-usage checks, and Cloudsplaining resource-exposure or infrastructure-modification actions on the exact same IAM policy. Policy display names alone never establish identity. Root credential management, user MFA, long-lived user credentials, and a role's unused permissions retain separate cards. A group displays the highest member severity and its original-finding count; Results and readable exports use the same problem counts. Every original title, severity, scanner time window, remediation, evidence pointer, and workflow decision remains available individually. Grouping does not raise confidence or change stored findings and correlation decisions. Missing identity or unfrozen legacy evidence stays ungrouped.

Findings from different scanners about the same vulnerable package or the same exposed secret also share one first-layer problem card within the same terminal run and approved asset, under the same display and preservation rules. A package card joins findings that name the same package at the same installed version when one finding's advisory ID equals another's ID or an alias the scanner itself reported, such as the CVE that Grype lists for a GitHub advisory or the GitHub advisory that Trivy lists for a CVE. A secret card joins secret-scanner findings and findings their scanner classifies as hard-coded credentials (CWE-798, CWE-259, or CWE-321) at the same file and starting line; its next step is to revoke and rotate the credential. These cards use only identifiers and locations the scanners report, and the product keeps no table that maps one scanner's rules to another's. A finding without a package, installed version, advisory ID, file, or line stays separate, and configuration or code rules from different scanners are not grouped by rule name or nearby lines.

External framework references, when the product team wants them, are optional context after the actionable report. They do not start, block, rank, or complete a scan and do not define the roadmap.

## 7. Recovery, data, and safety

Errors say what could not happen, what work was preserved, whether the user must act, and one recommended next step. Technical detail is optional.

Structured CLI responses state outcomes as typed fields. Status, planning, discovery, grouping, deletion, engine retrieval, and cleanup commands do not append defensive notice paragraphs that repeat or qualify those fields.

Events are refresh hints, not truth. Startup, focus, resume, and periodic refresh reconcile durable state. Cases, targets, runs, findings, reports, and export history survive restart. One damaged case is isolated; demo data never substitutes for failed native data.

Safety rules are concise:

- Network scans require an exact target and confirmation of ownership or permission.
- Local folders use bounded read-only snapshots; originals are not changed.
- Intrusive, credentialed, or scope-expanding activity requires a separate explicit choice.
- Credentials use official short-lived authorization where possible, never a generic password field.
- Cases and evidence stay local unless the user connects a source or exports them.
- Secrets, credentials, tokens, and personal data are redacted from normal presentation and logs.
- Cancel stops new target contact promptly and preserves completed results.
- The product never applies remediation automatically.
- Deletion identifies exact product-owned data and requires confirmation; unrelated or ambiguously owned data is preserved.

English and Traditional Chinese are first-class. Keyboard, screen-reader, focus, non-color status, and narrow-screen behavior cover the whole primary path.

## 8. Product acceptance and priorities

The strongest evidence is an observed user journey with an actual supported scanner and controlled target or fixture. Automated tests protect parsing, scope, adapter output, persistence, progress, reporting, and export, but do not replace the actual security-check result.

A beginner-path change is complete when the maintained product demonstrates:

1. URL, folder, or mixed IT-environment selection without unnecessary fields;
2. one focused Review and Start step;
3. at least one real security-relevant upstream check;
4. a durable unified report with an actionable result;
5. concise per-asset completion and no-problem states;
6. reopen and readable export without losing findings.

Connectivity-only fixtures prove connectivity handling, not vulnerability scanning. Component counts, build success, runtime health, and documentation do not prove first value.

Unless the product owner directs otherwise, work is ordered by user value:

1. Make the mixed IT-environment, website, and local-project scans short, real, and reliable.
2. Keep the supported repository, website, and generic exact-host paths reliable together; broaden scanner coverage through pinned upstream profiles rather than product-owned vendor detectors.
3. Remove naming, project-management, runtime, and navigation detours before Start.
4. Deliver the unified actionable report when each run reaches its terminal outcome.
5. Improve recovery, speed, scanner coverage, and upstream currency without regressing the beginner paths.

Version labels, publication ceremony, certification, framework mapping, and compliance positioning are outside this priority order unless the product owner explicitly requests them. Existing implementation and evidence in those areas remain intact.
