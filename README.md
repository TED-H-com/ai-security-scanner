# ai-security-scanner

[Project website](https://ted-h-com.github.io/ai-security-scanner/) · [繁體中文](README.zh-TW.md) · [Documentation](docs/README.md) · [Downloads](https://github.com/TED-H-com/ai-security-scanner/releases) · [日本語](README.ja.md)

*A local-first security assessment workbench: choose what to check and get one traceable report you can act on and hand over, without managing a toolchain yourself.*

Find security problems in your code, websites and company systems. Get one report that explains what needs attention, why it matters and what to do next.

Choose what to check in the desktop app. It selects suitable security tools and brings their results together. You can start with one folder or website, or check several parts of your IT environment at once.

## Run your first scan

1. [Download v0.5.1](https://github.com/TED-H-com/ai-security-scanner/releases/tag/v0.5.1) for Windows, macOS or Linux and [follow the install steps](docs/getting-started.md#install). The app prepares its scanning tools; you do not need to install Docker.
2. Open the app and choose **Scan my environment**, **Check a website**, or **Check code or an AI project**. Add the folders, URLs or internal systems you want to check.
3. Review the listed targets and checks. Confirm that you may scan any network targets, then start the scan in the app window.
4. When the scan ends, open **Results**. Choose **Save or share report**, then **Save HTML report** to save a report you can open in a browser.

The first scan may take longer while tools download. Later scans can use those tools again. The [walkthrough](docs/getting-started.md#from-new-scan-to-an-html-report) shows each screen.

## Languages

Japanese UI support is included in v0.5.1. Choose **Settings → 日本語**; the choice is saved across restarts. Untranslated explanations fall back to English; HTML exports from the Japanese UI are in English. See the [Japanese README](README.ja.md) and [Japanese website](https://ted-h-com.github.io/ai-security-scanner/?lang=ja).

## New in v0.5.1

- Japanese UI is included in the desktop installers. Choose **Settings → 日本語**; your choice is saved across restarts.
- Adds a Japanese README and website, with introductions for all 25 scanners.
- Includes [@kieiken](https://github.com/kieiken)'s [#69](https://github.com/TED-H-com/ai-security-scanner/pull/69) and fills translation gaps in onboarding and runtime setup.

[Read the v0.5.1 changes](docs/release/v0.5.1.md).

## New in v0.5.0

- Read related findings as one problem card, with the original evidence available in its details.
- Choose your updated folders again with **Check fixes** and compare problems that no longer appear, remain or are new, including partial fixes.
- Get clearer cloud guidance, progress and scanner version information, plus bilingual guides and a [real before-and-after example](https://ted-h-com.github.io/ai-security-scanner/check-fixes-demo.html).

This release brings together the completed updates since v0.4.1 and includes Linux build and dependency security fixes. [Read the full changes](docs/release/v0.5.0.md).

## What can it check?

| What you choose | What you learn |
| --- | --- |
| Project folders, including AI projects | Whether supported files contain exposed passwords or keys, risky code, vulnerable software packages or unsafe settings. Your project is copied for inspection, not run or changed. |
| Websites and APIs | Whether the approved website has known vulnerabilities or exposed information. Checks stay within the address and limits shown before you start. |
| Internal systems | Which services are available on the approved hosts and ports, and which security problems the applicable checks find. An open port alone is not a vulnerability. |
| Cloud accounts and Microsoft 365 | What the supported account and access checks find. AWS, Azure and GCP currently cover selected identity and permission settings; they do not provide a complete cloud audit. |
| Deployment files, containers and Kubernetes | Whether supported files or container contents have known package vulnerabilities or unsafe settings. Available checks depend on the input you provide. |

Optional AI checks can map supported workflows, inspect MCP configuration, or test one approved model endpoint. The model test sends 54 fixed prompts and may incur provider charges; you review those limits before starting. See [what each scan covers](docs/scanning-scope.md).

## A report you can act on

Start with the problems that need attention first. Each includes the affected system or file, why the problem matters and a practical next step. Technical details retain the scanner's original evidence, rating and recommendation for whoever will investigate or make the fix.

The report also tells you what was checked and what was not. If one check fails, completed results remain available. “No problems found” applies to the completed checks, not every possible risk. The app suggests fixes; it does not make them for you.

You can reopen reports, compare compatible scans and share an English or Traditional Chinese HTML copy. Unredacted exports can include the original scanner reports as ZIP attachments at the end. See [how to read and share results](docs/results-and-exports.md).

### See an example

[Open the example report](https://ted-h-com.github.io/ai-security-scanner/samples/v0.4.0/sample-report-redacted-en.html), or [choose another language or disclosure level](https://ted-h-com.github.io/ai-security-scanner/sample-reports.html).

These examples use simulated data: 62 findings and 42 inventory observations across all 25 tools. They show the report format, not the security of a real company. Inventory is listed separately from security problems. [How the examples were made](docs/samples/v0.4.0/README.md).

For a real scan, see [a project fixed and checked again](https://ted-h-com.github.io/ai-security-scanner/check-fixes-demo.html): 13 problems before the fix, 8 after, and what changed between them.

## Get help from Claude Code or Codex

An assistant running on your computer can help install the app, check setup, explain findings and save the report. You select the targets and start, pause or resume scans in the desktop app.

Open this repository in your assistant and ask:

> Use the ai-security-scanner skill to install the app, guide me through my first scan and save the final HTML report.

Use the [Claude Code skill](.claude/skills/ai-security-scanner/SKILL.md) or the [Codex skill](.codex/skills/ai-security-scanner/SKILL.md). An assistant running elsewhere can provide instructions and download links. It cannot install the app on your computer. [Assistant setup](docs/getting-started.md#use-with-an-agent-skill).

## Your data and access

Projects, findings and evidence are stored on your computer. Local code checks do not upload or execute your project. Website and cloud checks contact the services you approve. Saving an HTML report creates a local file; you decide whether to share it.

Cloud sign-in and cloud permissions are separate. A login can expire while the permissions created during setup remain. Microsoft 365 has an optional [cleanup script](cloud-setup/README.md#english-quick-reference) that waits for a selected scan, saves its report, and removes the recorded setup changes. AWS also has a [temporary-access mode and matching cleanup](cloud-setup/README.md#aws-專用存取與清理). Keep the cleanup window open; an expired administrator sign-in may need renewing. These are optional workflows, not yet the desktop default, and do not remove older, unrecorded AWS or Azure permissions.

## The tools behind the report

The app brings together 25 open-source tools. Each keeps its own detection rules; the app organizes their results and explains what to do next. [Read the tool guide](https://ted-h-com.github.io/ai-security-scanner/scanner-guide.html) for uses, limits and versions.

<details>
<summary>What each of the 25 tools does</summary>

### Repositories, dependencies, and infrastructure as code

**[Semgrep](https://github.com/semgrep/semgrep)** — Semgrep is a widely used open-source static application security testing (SAST) tool: it looks for security problems in source code without compiling or running the project. A plain text search sees only characters, so a line break, different spacing, or a renamed variable can hide the same code. Semgrep parses code into a syntax tree and matches its structure instead. In the Community Edition this app runs, rules that track untrusted data follow it only within one function. We include it in this app because it helps you quickly find risky patterns, such as unsafe command calls or database queries built from user input, using the security rule pack bundled with this app rather than the complete current registry.

**[Gitleaks](https://github.com/gitleaks/gitleaks)** — Gitleaks is an open-source secret scanner, and one of the most popular and trusted tools for finding hardcoded passwords, API keys, tokens, and other credentials in project files. Its rules recognize many known key formats, and some also weigh nearby words or how random a value looks. Upstream Gitleaks can also search a repository's Git history, so a key deleted later can still be found. We include it in this app because it helps you quickly find passwords and keys left in the project you select. Here it reads a read-only copy of the current files only: it does not search deleted Git history or test whether a credential still works, and the report hides the secret values.

**[TruffleHog](https://github.com/trufflesecurity/trufflehog)** — TruffleHog is an open-source secret scanner, and one of the most popular and trusted tools for finding exposed credentials such as API keys and tokens. It has dedicated detectors for many kinds of credentials. Upstream, it can also ask the matching live service whether a found key works, and it can search Git history. We include it in this app because it helps you quickly find secrets in the current files, with detectors that complement Gitleaks. Here networking is turned off and the scan reads a read-only copy of those files: it does not search Git history or try any credential on a live service. A match is not proof that the key still works, and the report leaves the secret values out.

**[Trivy](https://github.com/aquasecurity/trivy)** — Trivy, from Aqua Security, is an open-source security scanner, and one of the most popular and trusted tools for finding known vulnerabilities in software packages. It reads the dependency files it recognizes, plus individual packages such as Java JAR files, and matches their versions against public advisories in a vulnerability database, usually CVEs, the standard IDs for known flaws. Upstream Trivy can also check settings and secrets. We include it in this app because it helps you quickly find known vulnerable packages, along with a fixed version when the database lists one. Here only its vulnerability checks run, using the database bundled with this app. In a container image it checks operating-system packages only; Grype covers the image's application libraries.

**[Grype](https://github.com/anchore/grype)** — Grype, from Anchore, is a widely used open-source tool that matches software packages to known vulnerabilities. It compares package names and versions with a vulnerability database and reports the matching advisory, such as a CVE, the standard ID for a known flaw, or a GitHub security advisory, plus any fixed version the database lists. We include it in this app because it helps you quickly find known vulnerable packages in a selected project or container image; in an image, that includes application libraries as well as operating-system packages. When Trivy reports the same issue, the report still shows which tool found what. Here it uses the database bundled with this app, and it does not pull images from a registry or run the container.

**[Checkov](https://github.com/bridgecrewio/checkov)** — Checkov is a widely used open-source scanner for infrastructure as code (IaC): the files that describe how cloud resources and deployments should be set up. It reads those files as resources and the relationships between them, not as plain text, and checks them against a library of security policies. We include it in this app because it helps you quickly find unsafe settings in files such as Terraform, CloudFormation, and Dockerfiles before anything is deployed. Here it reads a read-only copy of the selected project. It does not connect to a cloud account, download platform policy data, or apply the files, so the result describes the files, not the live environment.

**[KICS](https://github.com/Checkmarx/kics)** — KICS (Keeping Infrastructure as Code Secure), from Checkmarx, is an open-source scanner for infrastructure as code (IaC): the files that describe how your systems are deployed. It runs a library of security queries over formats such as Terraform, CloudFormation, Kubernetes manifests, and Dockerfiles, and ties each result to a file and line. Its bundled queries also look for passwords and keys left in those files. We include it in this app because it helps you quickly find risky deployment settings, with a query library independent of Checkov's that gives a second view. Here it scans a read-only copy of the selected project with the queries bundled in the tool. It does not connect to a cloud account or download extra queries.

**[Syft](https://github.com/anchore/syft)** — Syft, from Anchore, is a widely used open-source tool that builds a software bill of materials, or SBOM: a list of the software components inside a project or container image, such as libraries and operating-system packages. It records the name, version, and type of each component it recognizes. We include it in this app because it helps you quickly see which software the selected project or image contains, so you know what the vulnerability checks are looking at. The list shows what is there; it is not a vulnerability report. Here it reads a read-only copy with no network connection and does not download images from a registry. Known vulnerabilities are left to Trivy and Grype.

The released catalog pins the Grype image to **`0.117.0-4`**, digest `sha256:56b0d675…`. It can scan local repository dependencies for known vulnerabilities; a controlled repository scan recorded **81 Grype findings**. That is a fixture result, not an expected count for every project. See the [exact pin and recorded result](docs/engine-catalog.md#grype-repository-support).

### Websites and internal systems

**[Nuclei](https://github.com/projectdiscovery/nuclei)** · [Nuclei Templates](https://github.com/projectdiscovery/nuclei-templates) — Nuclei is an open-source vulnerability scanner from ProjectDiscovery, and one of the most widely used and trusted tools of its kind. Each check is a template: a written request plus the response that signals a known exposure or vulnerability. It first recognizes which technologies a site uses, then picks the templates that fit. We include it in this app because it helps you quickly find those known problems; it is the default website check, using the templates bundled here. It stays on one approved site address and sends only read-only requests. It does not log in, submit forms, fuzz, run exploits, drive a browser, or ask an outside server to call back. A path you type does not narrow the check to that path.

**[ZAP](https://github.com/zaproxy/zaproxy)** — ZAP (Zed Attack Proxy, long known as OWASP ZAP) is an open-source web application security scanner, and one of the most widely used and trusted tools of its kind. Upstream, it can sit between a browser and a website, crawl pages, inspect every response, and actively send attack payloads. Its passive rules only read the responses, including headers and cookies, without attacking. We include it in this app because those passive rules help you find problems such as missing security headers or unsafe cookie settings on the pages it reaches, as a complement to Nuclei. Here it is optional: it crawls one approved website within fixed limits and does not log in, submit forms, send attack payloads, or leave the site. Nuclei remains the default.

**[Greenbone OpenVAS Scanner](https://github.com/greenbone/openvas-scanner)** — Greenbone OpenVAS is an open-source network vulnerability scanner maintained by Greenbone. Its tests come from a fixed copy of the Greenbone Community Feed, a separately maintained library of checks. It first identifies which service is listening on a port, then runs the tests that apply to it. We include it in this app because it helps you find known security problems on internal devices and servers that a simple connection cannot reveal. Here it tests only the exact hosts and ports you approved. It does not log in or inspect the machine from inside, guess passwords, try default accounts, or run disruptive checks. When it cannot identify a service, those tests do not run, and the report lists the host as not tested.

**[Naabu](https://github.com/projectdiscovery/naabu)** — Naabu is an open-source port-discovery tool from ProjectDiscovery that shows which TCP ports are accepting connections. A TCP port is the number a network service listens on. Its connect scan opens an ordinary TCP connection to each address and port, and a completed connection means the port is open; upstream also offers other discovery methods. We include it in this app because it helps you quickly find out which approved services are listening, so the security checks that follow have a real target. Here it connects only to the exact addresses and ports you approved. It does not add nearby hosts or scan UDP, the other common way services listen, and an open port is inventory, not a vulnerability.

**[httpx](https://github.com/projectdiscovery/httpx)** — httpx is an open-source web-probing tool from ProjectDiscovery, not the Python HTTPX library of the same name. It sends an ordinary web (HTTP) request to an address and records whether a web service answers, the status code it returns, and other basic response details, which a port check alone cannot tell you. We include it in this app because it helps you quickly confirm that an approved web service is responding before a real security check runs against it. Upstream, it can run many more probes. Here it asks only the exact service you approved and does not crawl, log in, or enable every upstream probe. The result is inventory that describes the service, not a vulnerability finding.

### Cloud and Microsoft 365

**[Prowler](https://github.com/prowler-cloud/prowler)** — Prowler is a widely used open-source cloud security assessment tool. It calls the cloud provider's APIs, runs its built-in checks, and records each check's name, the affected resource, what failed, and how to fix it. Upstream, it can cover many services and compliance frameworks. We include it in this app because it helps you quickly find identity and permission settings that need attention. Here each run uses a narrow identity and access management (IAM) profile on one approved asset: the IAM service of one AWS account, the IAM service of one Azure subscription, or four specific IAM checks for one GCP project. Other services and accounts are outside the run, and a passed check is not a certification.

**[ScoutSuite](https://github.com/nccgroup/ScoutSuite)** — ScoutSuite, from NCC Group, is a widely used open-source tool that reads cloud configuration through provider APIs and flags settings its rules consider risky. Each result keeps the rule, the affected items, and why they deserve review. Upstream, it supports several cloud providers and produces its own report. We include it in this app because it helps you quickly find AWS identity and access settings worth a closer look, as a second view beside Prowler. Here it runs only the AWS identity and access management (IAM) rules for one approved account; other providers and other AWS services are outside the run. A setting becomes a finding only when a rule flags it, so collected configuration alone is not a vulnerability.

**[Cloudsplaining](https://github.com/salesforce/cloudsplaining)** — Cloudsplaining, from Salesforce, is an open-source tool that checks AWS identity and access management (IAM) policies for permissions broader than the work needs, which breaks the principle of least privilege. It reads an account's authorization details, finds actions allowed without a resource limit, and sorts risky ones into categories such as privilege escalation, data exfiltration, resource exposure, and infrastructure modification, naming the policy and the actions. We include it in this app because it helps you quickly find overly broad permissions and see which actions to review. Here it analyzes one approved AWS account. A flagged action is evidence for review: it does not decide whether the business needs the permission, change the policy, or prove someone can use it now.

**[CloudQuery](https://github.com/cloudquery/cloudquery)** — CloudQuery is a widely used open-source tool that copies data from cloud provider APIs into structured tables you can query and compare later. A source plugin reads the cloud service and a destination plugin writes each row, so every collection comes out in the same shape. We include it in this app because it helps you quickly see which identities and permission policies exist in an approved AWS account, which gives the security checks context. Here it collects one fixed set of identity and access management (IAM) tables: the account, users, groups, roles, policies, password policies, and credential reports. These rows are inventory: they describe what exists, stay separate from security findings, and do not cover every AWS service.

**[Steampipe](https://github.com/turbot/steampipe)** — Steampipe, maintained by Turbot, is a widely used open-source tool that turns cloud APIs into SQL tables. SQL is the standard database query language, and each provider plugin decides which services and columns you can read. We include it in this app because it helps you quickly list the identity and access management (IAM) users in one approved AWS account, so you can compare that list with what the security checks report. Here it runs one fixed query of the IAM user table. The rows are inventory: they name the users found and do not judge whether any user is a risk. This app does not run Steampipe's ready-made security benchmarks or accept SQL you write.

**[ScubaGear](https://github.com/cisagov/ScubaGear)** — ScubaGear, from CISA, the U.S. Cybersecurity and Infrastructure Security Agency, is an open-source tool that compares a Microsoft 365 tenant, an organization's Microsoft 365 environment, with CISA's Secure Cloud Business Applications (SCuBA) baselines: written expectations for a secure configuration. Upstream, it also covers other Microsoft 365 products. We include it in this app because it helps you quickly find Microsoft Entra ID settings that fall short of this guidance; Entra ID is the tenant's sign-in and identity directory. Here it checks the Entra ID baseline for one authorized tenant in Microsoft's commercial cloud. Exchange, SharePoint, and other workloads are outside the check. A pass is not a compliance certification, and checks that could not be evaluated stay visible instead of counting as passes.

**[Maester](https://github.com/maester365/maester)** — Maester is an open-source test framework for Microsoft 365 security configuration, written in PowerShell, Microsoft's scripting language. Each test states the setting a secure tenant should have and records whether yours matches. We include it in this app because it helps you quickly find Microsoft Entra ID settings that do not meet those expectations; Entra ID is the tenant's sign-in and identity directory. Here it runs a fixed set of Entra tests for one authorized tenant and skips long-running tests, preview tests, and tests that need other services. Exchange Online and scripts you supply are outside the run. A skipped test is never shown as a pass, and a test that needs human judgment is listed for your review.

### Kubernetes

**[Kubescape](https://github.com/kubescape/kubescape)** — Kubescape is a widely used open-source tool for checking the configuration of Kubernetes, the system many teams use to run containers. It reads YAML and JSON files as Kubernetes resources and compares them with a fixed hardening checklist, the NSA framework based on U.S. NSA and CISA guidance, so each result names the resource and the control that failed. Upstream Kubescape can also scan live clusters and container images. We include it in this app because it helps you quickly find risky settings in the Kubernetes files you select. Here it checks only that saved snapshot, offline. It does not connect to a running cluster, cannot tell whether the files match what is deployed, and does not scan container packages.

**[kube-bench](https://github.com/aquasecurity/kube-bench)** — kube-bench is a widely used open-source tool from Aqua Security that checks Kubernetes nodes, the machines that run workloads, against the CIS Kubernetes Benchmark: the Center for Internet Security's published checklist of secure settings. It compares configuration files and running-process facts with each check and marks it pass, fail, or warn; a warning means the check needs information or judgment that automation cannot supply. Upstream kube-bench runs on a live node and can also check the control plane. We include it in this app because it helps you quickly find node settings that miss this checklist. Here it uses only a saved export of node facts and the node checks. It does not log in to a live host or run the control-plane checks.

### AI workflows and MCP configuration

**[Agentic Radar](https://github.com/splx-ai/agentic-radar)** — Agentic Radar is an open-source tool that reads AI agent projects and maps how their pieces connect. You choose one of the supported frameworks (LangGraph, CrewAI, n8n, OpenAI Agents, or AutoGen), and its parser lists the agents, tools, and MCP servers and the links between them. An MCP server is an outside tool reached through the Model Context Protocol, a standard way for an AI app to call other tools. Upstream Agentic Radar also offers broader risk analysis. We include it in this app because it helps you quickly understand what an AI agent project contains before you review it. Here it only inventories one saved copy of the project. It does not run the workflow, contact a model, or report security problems.

**[Garak](https://github.com/NVIDIA/garak)** — Garak is NVIDIA's widely used open-source vulnerability scanner for large language models (LLMs). It sends crafted prompts, called probes, and detectors judge the replies. The probes used here are “Do Anything Now” instructions that try to talk a model out of its rules, and prompts that try to make it output terminal escape codes. Upstream Garak has many more probes. We include it in this app because it helps you quickly see how one approved model responds to these fixed tests. You start this optional check yourself: it sends 54 prompts to one approved OpenAI-compatible HTTPS chat API and model. A clean result covers only these prompts. The provider may charge, and your API key is used once and never saved with the scan or report.

**[MCP Armor](https://github.com/aira-security/mcp-armor)** — MCP Armor is an open-source tool for checking Model Context Protocol (MCP) configuration, the file that tells an AI app which outside tools to connect to. Two of its checks read that file: one looks for keys and other secrets written into it, the other flags tool commands and permissions broader than needed. The report leaves out the matched secret. Upstream, it can also contact the configured servers and run tests that use a model. We include it in this app because it helps you quickly find exposed keys and overly broad tool permissions in the configuration you select. Here it reads only that file from the saved project; it does not start or contact an MCP server, load a model, or show what a running server enforces.

Discovery, inventory, SBOM generation, and the localhost TCP utility remain clearly separated from vulnerability findings. The complete pinned versions, licenses, profiles, and execution boundaries are recorded in the [engine catalog](docs/engine-catalog.md).

Exact scan boundaries and profile behavior are documented in [Scanning scope](docs/scanning-scope.md).

Tools still under evaluation are tracked separately and are not available for scans.


</details>

## More information

- [Getting started](docs/getting-started.md)
- [Scan coverage](docs/scanning-scope.md)
- [Reading and sharing results](docs/results-and-exports.md)
- [Current development status](docs/development-status.md)
- [Changes in v0.5.1](docs/release/v0.5.1.md) · [Changes in v0.5.0](docs/release/v0.5.0.md) · [Earlier changes in v0.3.1](docs/release/v0.3.1.md)
- [Contributing](CONTRIBUTING.md) · [Contributors](CONTRIBUTORS.md) · [Security policy](SECURITY.md)

## Development

Development requires Node.js 24 or newer, Rust 1.98, and the platform dependencies required by Tauri.

```sh
npm ci
npm run typecheck
npm run test:frontend
npm run test:component
npm run build
cargo test --locked --workspace --no-default-features --features cli
npm run tauri dev
```

`npm run dev` opens a browser preview with sample data. Desktop scanning runs through the Tauri application.

`npm run upstream:refresh -- --engine <id>` produces an offline adapter refresh proposal bundle, and `npm run upstream:propose -- --bundle <path>` re-validates it. `mechanical` is the default deterministic path; the optional AI path is selected explicitly with `--provider cli --ai-cli <executable>`. `--open-pr` or `--no-open-pr` records whether the change should be sent back to this repository. These commands print commands for a human to run and never execute them. The full procedure is in [Engine maintenance](docs/engine-maintenance.md).

## License

Project-owned source is licensed under [Apache-2.0](LICENSE). Third-party engines and data retain their own licenses; see [THIRD_PARTY.md](THIRD_PARTY.md).
