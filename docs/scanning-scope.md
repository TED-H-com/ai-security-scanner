# Scanning scope

[繁體中文](scanning-scope.zh-TW.md) · [Documentation](README.md)

The Review screen is the execution boundary. Network scanners receive the exact displayed targets and ports after confirmation. Local scans receive an isolated snapshot of the selected source.

## IT environment

An IT-environment project can contain repositories, websites, and internal systems. The execution plan binds each asset to applicable checks; one engine never expands its scope to every compatible asset.

Each internal system is one exact hostname or IP address. Its default TCP ports are 22, 23, 25, 80, 443, 445, 3389, 5900, 8080, and 8443. Advanced settings can replace the list with up to 64 exact ports for that host. Inventory ranges remain inventory until individual systems are added and confirmed.

## Website or API

The quick website profile runs pinned Nuclei automatic scan against one exact `scheme://host:port` origin. The entered path is retained as context; matching templates can request other paths on the same origin.

Nuclei performs upstream technology detection and selects applicable vulnerability and exposure templates from the pinned read-only snapshot. It does not authenticate, submit forms or request bodies, follow redirects, use out-of-band callbacks, run headless flows, upload files, fuzz without bounds, or select exploit and denial-of-service templates.

A completed no-finding result records the checks Nuclei completed and the exact origin. Upstream technology and template applicability determine which templates run.

The optional ZAP passive profile crawls links within that same approved origin and checks responses with upstream passive rules. It uses five spider threads, native pacing of five requests/second and a ten-second request timeout; crawling is bounded to two minutes, depth five and 100 children per page, followed by at most two minutes of passive processing. It does not authenticate, submit forms or run active attack jobs. No observed responses means incomplete coverage.

## Project folder

The app creates a bounded private snapshot and runs applicable upstream checks for:

- secrets with masked presentation;
- risky code patterns;
- vulnerable dependencies supported by the detected manifests and packages;
- application, deployment, infrastructure, and Kubernetes configuration;
- component inventory used by the report and exports.

The snapshot process follows repository ignore rules for generated, dependency, build, cache, and version-control directories. Common secret-bearing source files (including `.env` variants, private keys, registry or authentication configuration, and `*.tfvars`) remain available to the secret scanners.

The project is not built, executed, uploaded, committed, pushed, or modified.

Optional Agentic Radar inventory uses one selected framework: LangGraph, CrewAI, n8n, OpenAI Agents or AutoGen. It runs offline over the saved repository and reports agents, tools and workflow connections. It does not execute project code or contact models. Parser diagnostics and unsupported input remain incomplete inventory, separate from security findings.

## Model behavior check

The optional Garak run requires one exact OpenAI-compatible HTTPS chat-completions URL, a model identifier and explicit consent for the fixed native DAN/ANSI profile and provider charges. It sends 54 prompts, one request at a time at most once per second. Each request has a 20-second timeout; the run has a ten-minute deadline, at most 64 attempts including retries and 150 requested output tokens per attempt (9,600 maximum requested tokens). TLS verification stays enabled; redirects and other destinations are refused.

Enter the API key only in the dedicated app field. It remains in app memory for up to 30 minutes and is consumed once before dispatch. It is absent from saved cases and reports; another attempt requires a new key and confirmation. Native detector failure counts remain Unknown severity; failed, cancelled or unfinished checks disclose incomplete coverage. Normal rescan actions do not automatically repeat this paid check.

## Internal system

The generic internal-system profile passes the exact confirmed host and ports to Greenbone. The pinned Community Feed supplies current, non-deprecated, unauthenticated remote `gather_info` vulnerability tests. Greenbone owns service and product detection, prerequisites, dependencies, severity, evidence, and remediation.

The profile uses no credentials. It excludes local authenticated checks, default-account and brute-force checks, policy families, alternative port scanners, and attack, denial, destructive, kill-host, and flood categories. It does not add neighboring hosts or undisclosed ports.

Open ports and detected services appear under **Observed services (not vulnerabilities)**. A security finding requires an upstream vulnerability result.

## Infrastructure, containers, Kubernetes, and cloud

Infrastructure files and Kubernetes manifests are scanned as selected artifacts. Exported container images are inspected without running them. Live cluster and cloud paths use their own selected resource and permission scope.

Cloud authorization uses the provider's official browser flow or an isolated administrative bootstrap request. Scan credentials are never entered in a generic app password field.

## Localhost TCP utility

The localhost TCP utility makes one payload-free connection attempt to `127.0.0.1:9001`. It reports accepted, refused, or timed out connectivity. It is not a vulnerability scan.

## Resource profile

Profiles freeze applicable rate, concurrency, timeout, output, runtime, and cancellation limits before execution. Scanner-specific identifiers, severities, evidence, and remediation remain upstream-owned. Product-owned prioritization and cross-engine grouping happen in the shared report.
