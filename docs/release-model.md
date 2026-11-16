# What is published, and what counts as a release?

[繁體中文](release-model.zh-TW.md) · [Documentation](README.md)

Publication status checked: 2026-11-16. Desktop v0.7.0 is published; the complete skill-first entry remains in development.

## Available today

| Delivery | Verified state | What users get |
| --- | --- | --- |
| Desktop | [v0.7.0 stable](https://github.com/TED-H-com/ai-security-scanner/releases/tag/v0.7.0), published November 16, 2026 | Windows, macOS and Linux installers; the existing desktop scan and report path. |
| Repository operator skill | [Instructions are public](https://github.com/TED-H-com/ai-security-scanner/blob/main/.codex/skills/ai-security-scanner/SKILL.md), with a matching Claude Code copy | Helps install and operate the desktop, inspect results and export reports. This is a published repository skill. |
| New skill-first core and bootstrap | Core included in v0.7.0; complete skill-first entry not yet released | Foreground scans, selected-engine preparation, saved reports, case archive/restore and Cloudflare validation/retention. Use a deliberately selected development checkout. |
| Plugin directory listing | Not established by the repository publication | A separate distribution channel; do not describe the repository skill as a listed or reviewed plugin without a listing. |

The [v0.7.0 delivery record](release/v0.7.0.md) identifies the exact released source, files and verification. Source publication and a downloadable core do not by themselves establish a supported skill-first beginner journey.

## Recommended terminology

Use two labels: **what is delivered** and **its maturity**.

| Term | Meaning for this product |
| --- | --- |
| Source / documentation published | Others can retrieve the stated source or pages. It says nothing by itself about a complete supported workflow. |
| Repository skill published | The skill instructions and their required resources are publicly retrievable at an identified revision. State whether they operate the desktop or the new core. |
| Skill preview release | A fixed, retrievable skill/core revision has an exercised entry, clear prerequisites, supported scope and known gaps. Suitable for explicitly selected early use. |
| Skill stable release | The advertised beginner workflow works from setup through a meaningful scan, the shared report and portable archive/restore on its declared hosts and platforms. |
| Desktop release | Installers and their updater delivery are published for the stated version and platforms. Desktop delivery can follow its own schedule. |
| Plugin publication | A separately distributed package or directory listing. Its status must be verified in that channel. |

“Publish” describes making an artifact available. “Release” describes an
identified delivery with a stated maturity and support scope. A release can
contain a skill and pinned source/bootstrap without desktop installers. A GitHub
Release can announce that delivery; a binary attachment is not the definition of
a product release.

OpenAI distinguishes local/repository skill authoring from broader distribution
through plugins. A plugin can package skills, with optional connectors. This
product currently uses repository skills; no plugin packaging is introduced by
this recommendation. See [Build skills](https://learn.chatgpt.com/docs/build-skills)
and [Plugin architecture](https://developers.openai.com/plugins/concepts/plugins).

## Readiness of the new path

The next skill delivery can be a **Skill preview** with an exact verified entry, supported scope and prerequisites. It has not been announced. The [bootstrap evidence](skill-bootstrap.md#november-9-selected-engine-and-real-scan-validation) records a real pinned Gitleaks scan, redacted findings, report delivery and archive/restore on Linux. That does not establish all scanners, asset types or operating systems.

Current source includes foreground execution/recovery, selected scanner image
preparation, shared report snapshots, combined original attachments, and complete
archive/restore for the existing case domain. Cloudflare source audits run
through the host procedure from preparation to sealing, case admission and the
shared report, and admitted audits are kept in complete archives. Details and
verification are in [Development status](development-status.md).

Before calling the complete new skill path stable:

1. Exercise the documented first-run entry on the declared hosts and platforms,
   including automatic managed-runtime acquisition for the promised beginner path.
2. Finish trusted Cloudflare source handling, host orchestration and durable
   case/report integration; preserve its evidence through the complete archive.
3. Exercise the advertised mixed-asset journey, partial failures, shared report,
   offline retrieval and restore into a new workspace, including desktop data
   compatibility.
4. Publish the exact verified source identity, entry instructions, support scope
   and change notes, then synchronize the canonical skill, both host copies,
   documentation and website before changing the default.

These are the accepted product outcomes, not a requirement to maximize test
counts or ship every platform before a deliberately narrower preview. The owner
selects the release scope, version and date. **Desktop v0.7.0 is stable**; **the complete skill-first entry remains in development**. Older release tags and updater files retain their original identities.

## Recording the next delivery

Record the delivery type, channel, exact source revision, core identity,
verified host/platform scope, entry command, changes, limits and data
compatibility in one delivery note. Point README and website status at that
record. Do not reuse an old tag or silently move a pinned source reference.
Version numbering remains an owner decision; this recommendation leaves package
metadata and existing release automation unchanged.

[Desktop release operations](releasing.md) apply when publishing installers.
Historical release records and frozen sample reports keep their original dates,
versions and evidence.
