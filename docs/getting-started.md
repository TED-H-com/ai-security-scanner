# Getting started

[繁體中文](getting-started.zh-TW.md) · [Documentation](README.md)

## From New scan to an HTML report

In the app, follow this path:

**New scan → Review and start → Scan progress → Results → Share results → HTML report**

1. Select **New scan** in the sidebar. Choose **Scan my environment**, **Check a website**, or **Check code or an AI project** for the targets you want to check.
2. Add the targets in the form, then select **Review scan**. For a local project, select **Choose the source-code folder**, choose your folder, then **Review scan**. You can leave the project name blank.
3. In **Review and start**, check the listed targets and checks and confirm the displayed scope, then select **Start one combined scan** (**Confirm and start scan** for a single website or folder).
4. Follow the work in **Scan progress**. Tool preparation appears here too. Wait until the run finishes or stops; completed checks remain available even when another check could not finish.
5. Select **Results** in the sidebar. If there is more than one saved run, choose the intended scan in **Report run**. Read the affected assets, the highest-priority problems and next actions, and what was not tested.
6. Select **Save or share report** at the top of Results. The breadcrumb changes to **Share results**.
7. Select **HTML report (recommended)**, keep **Hide sensitive identifiers (recommended)** selected, then select **Save HTML report**. Choose a filename and location in the save dialog and save the file. Open the saved `.html` file in a browser to read or share the professional report.

The saved HTML uses the app language, English or Traditional Chinese. A CLI export uses `--locale en` by default, or `--locale zh-Hant` for Traditional Chinese. Scan facts stay the same.

**Review and start**, **Scan progress**, and **Share results** open through these actions; they are not separate sidebar entries. Saving a report writes a local file.

### Return to a scan

Open **My scans** and select your project. For ongoing work, select **View scan progress**. For a finished or stopped run, select **Results** and check **Report run** before saving its report. If checks need another attempt, use **Review scanner status** from Results.

If Scan progress says the plan was saved but no checks started, choose **Continue the original scope** to resume it or **Start a new scan** for a fresh run. **Cancel this run** stops queued or active work when available.

See [Results and exports](results-and-exports.md) for more about the report.

When an AWS or Microsoft 365 read-only connection expires, Results offers **Reconnect and scan again**. Complete the connection in the app and keep the approved scope. Related AWS findings can share an action card; expand technical details to see every original finding.

## Install

Download the **v0.5.1 stable release** for your computer from the [release page](https://github.com/teddashh/ai-security-scanner/releases/tag/v0.5.1):

| Computer | Installer | First launch |
| --- | --- | --- |
| macOS, Apple silicon or Intel | [ai-security-scanner_0.5.1_universal.dmg](https://github.com/teddashh/ai-security-scanner/releases/download/v0.5.1/ai-security-scanner_0.5.1_universal.dmg) | Drag the app into **Applications**. It is not notarized, so run `xattr -dr com.apple.quarantine /Applications/ai-security-scanner.app` once in Terminal before opening it. |
| Windows x86-64 | [ai-security-scanner_0.5.1_x64-setup.exe](https://github.com/teddashh/ai-security-scanner/releases/download/v0.5.1/ai-security-scanner_0.5.1_x64-setup.exe) or the [MSI](https://github.com/teddashh/ai-security-scanner/releases/download/v0.5.1/ai-security-scanner_0.5.1_x64_en-US.msi) | The installer is unsigned. If SmartScreen warns, select **More info → Run anyway**. If Windows asks to install or update WSL, allow it. |
| Debian or Ubuntu x86-64 | [ai-security-scanner_0.5.1_amd64.deb](https://github.com/teddashh/ai-security-scanner/releases/download/v0.5.1/ai-security-scanner_0.5.1_amd64.deb) | Install with `sudo apt install ./ai-security-scanner_0.5.1_amd64.deb`. |

Launch **ai-security-scanner** after installation. The app prepares its own scanning runtime the first time a scan needs it; Docker is not required.

## Use with an Agent Skill

Scans run in the desktop app on your own computer, and **Start** is a button in the app window. An agent on the same computer can install the app, check that the computer is ready to scan, guide you through the app, explain the results, and save the HTML report through the app's CLI. It installs the release above; it does not build this repository.

Open this checkout in **Claude Code** or **Codex** and use the repository's `ai-security-scanner` skill: [Claude Code instructions](../.claude/skills/ai-security-scanner/SKILL.md) · [Codex instructions](../.codex/skills/ai-security-scanner/SKILL.md). Both copies are the same.

Ask the agent:

> Use the ai-security-scanner skill to install the app on this computer, check that it can scan, guide me through a scan, and save the final HTML report.

The agent needs to run on the same computer as the app, with network access. When its sandbox blocks a download or the app, it asks you to allow that one command. A cloud agent cannot install anything on your computer, so it gives you the installer link instead of troubleshooting. You select the folders and confirm any network targets in the app; the skill does not authorize anything for you. Active work stays in **Scan progress**; **Results** and **Share results** use a finished or stopped run.

### Build from source

Building is only needed to change the product. With Node.js 24 or newer, Rust 1.98, and Tauri's Linux development dependencies installed, build and open the app from this checkout:

```sh
npm ci
cargo build --locked --no-default-features --features cli --bin ai-security-scanner-cli
./target/debug/ai-security-scanner-cli doctor
npm run tauri dev
```

These commands have been exercised on Linux.

The current Grype image pin is `0.117.0-4` (`sha256:56b0d675…`), with local repository vulnerability results recorded. See [the exact pin and result](engine-catalog.md#grype-repository-support).

## Choose the first scan

### IT environment

On **New scan**, select **Scan my environment** when repositories, websites, and internal systems belong in one assessment.

1. Add one or more project folders.
2. Add complete `http://` or `https://` website URLs.
3. Add each approved internal system by exact hostname or IP address. The default profile checks ports 22, 23, 25, 80, 443, 445, 3389, 5900, 8080, and 8443. Advanced settings can replace this list with up to 64 exact ports.
4. Select **Review scan** to open **Review and start**, then review every asset and network boundary.
5. Confirm the displayed network targets and select **Start one combined scan**.

Each scanner receives only its assigned assets. All completed outcomes are combined in one report.

### Website

1. Select **Check a website**.
2. Enter one complete URL and select **Review scan**.
3. In **Review and start**, review the exact origin and select **Confirm and start scan**.

This profile covers the displayed `scheme://host:port` origin. See [Scanning scope](scanning-scope.md#website-or-api) for its request behavior.

### Project folder

1. On **New scan**, select **Check code or an AI project**.
2. Select **Choose the source-code folder** and choose the local folder.
3. Select **Review scan**.
4. In **Review and start**, review the snapshot boundary and select **Confirm and start scan**.

The app scans a bounded read-only snapshot. The original folder is not changed.

### Optional checks in v0.5.1

The release provides these explicit choices:

- **ZAP:** in website Advanced settings, choose passive website checks, review the exact origin and confirm the displayed limits. Nuclei remains the quick default.
- **Agentic Radar:** in repository Advanced settings, select LangGraph, CrewAI, n8n, OpenAI Agents or AutoGen for offline workflow inventory. Agent and tool inventory appears separately from security findings.
- **Garak:** in an AI-project or IT-environment Review screen, open **Optional model behavior check**. Enter the complete HTTPS chat-completions URL and model identifier, then the API key in the dedicated password field. Select internal/local networking only when applicable, confirm authorization and provider charges, then select **Start model check**. This starts a separate run with 54 fixed native DAN/ANSI prompts. The key is kept locally for up to 30 minutes and consumed once; another attempt requires a new key and confirmation.

See [Scanning scope](scanning-scope.md#model-behavior-check) for exact request and token limits. Supply model keys only in the app, never in chat or command arguments.

### Cloud account

This checks the identity and access settings of one AWS account, Azure subscription, Google Cloud organization, or Microsoft 365 tenant. If you own or administer the account, you can do every step yourself.

1. On **New scan**, open **More ways to scan** and select **Check a cloud account**.
2. Pick the cloud and select **Create scan project**.
3. In **Scan setup**, select **Open the connection guide** and keep **Sign in with read-only access**.
4. Step 1 lists the console steps that create read-only access once, with the exact permission set, roles, or permissions to choose. If someone else manages the account, open **Someone else manages this account?** to copy a request and import the setup file they send back.
5. In step 2, enter the details step 1 told you to copy. They are public identifiers; never paste a password or secret.
6. Select **Continue to official sign-in**. Sign in on the provider's own page, entering the one-time code the app shows when asked.
7. When the app shows that read-only access is verified, select **Continue: find cloud assets**, review the account, and select **Scan this signed-in account**.

For AWS and Microsoft 365, a script can do step 1 for you. It prints the step 2 values and saves them as a setup file. Running it again adds only what is missing and never removes anything.

- **AWS:** in the AWS console of the account that manages IAM Identity Center, open CloudShell and run:

  ```sh
  curl -fsSLO https://raw.githubusercontent.com/teddashh/ai-security-scanner/main/cloud-setup/aws-read-only.sh
  bash aws-read-only.sh
  ```

  Turning on IAM Identity Center and adding the user who signs in stay console steps; the script says which one is missing.
- **Microsoft 365:** on Windows, run these in PowerShell. Open the Microsoft page the script prints, enter its code, and sign in as a Global Administrator. On macOS or Linux, run the script with `pwsh` (PowerShell 7).

  ```powershell
  Invoke-WebRequest https://raw.githubusercontent.com/teddashh/ai-security-scanner/main/cloud-setup/microsoft365-read-only.ps1 -OutFile microsoft365-read-only.ps1 -UseBasicParsing
  powershell -ExecutionPolicy Bypass -File .\microsoft365-read-only.ps1
  ```

Google Cloud needs an organization (Google Workspace or Cloud Identity); projects under a personal Gmail account cannot be scanned.

If the provider refuses the sign-in because the access can change the account or is missing a permission, the panel names the cause and the fix. Correct the access in the console, then sign in again.

An administrator who prefers not to keep standing read-only access can choose **Let the app create temporary access**. The app creates a separate read-only identity that expires within an hour; after the scan, choose **Remove only what this setup created**. See [Provider authorization](provider-authorization.md) for the exact permissions.

After starting, follow [the steps to an HTML report](#from-new-scan-to-an-html-report).
