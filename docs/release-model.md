# What is published, and what counts as a release?

[繁體中文](release-model.zh-TW.md) · [Documentation](README.md)

Skill publication status checked: 2026-11-10; desktop release status updated: 2026-11-12. The terminology below is a recommendation for the
skill-first product. It does not announce a new release or choose a version.

## Available today

| Delivery | Verified state | What users get |
| --- | --- | --- |
| Desktop | [v0.6.1 stable](https://github.com/TED-H-com/ai-security-scanner/releases/tag/v0.6.1), published November 12, 2026 | Windows, macOS and Linux installers; the existing desktop scan and report path. |
| Repository operator skill | [Instructions are public](https://github.com/TED-H-com/ai-security-scanner/blob/6e259b497b87fb8aa2ece1f3b512cc29c9ea5af7/.codex/skills/ai-security-scanner/SKILL.md), with a matching Claude Code copy | Helps install and operate the desktop, inspect results and export reports. This is a published repository skill. |
| New skill-first core and bootstrap | Development implementation; not a published skill release at this check | Foreground scans, selected-engine preparation, saved reports, case archive/restore and Cloudflare validation/retention. Use a deliberately selected development checkout. |
| Plugin directory listing | Not established by the repository publication | A separate distribution channel; do not describe the repository skill as a listed or reviewed plugin without a listing. |

The public default branch was [the November 6 documentation commit](https://github.com/TED-H-com/ai-security-scanner/commit/6e259b497b87fb8aa2ece1f3b512cc29c9ea5af7)
when checked. The newer migration existed as uncommitted working-tree changes.
Local skill synchronization, passing tests and an unchanged package version do
not publish those changes. Recheck the public revision before any announcement.

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

The recommended next delivery is **Skill preview**, after its source is committed
and made retrievable at the exact verified revision. It is not yet published.
Start with the verified Linux path and state its runtime prerequisites. The
[bootstrap evidence](skill-bootstrap.md#november-9-selected-engine-and-real-scan-validation)
records a real pinned Gitleaks scan, redacted findings, report delivery and
archive/restore. That supports a bounded preview; it does not establish all
scanners, all asset types or all operating systems.

Current source includes foreground execution/recovery, selected scanner image
preparation, shared report snapshots, combined original attachments, and complete
archive/restore for the existing case domain. Cloudflare can validate documents
and reported bundles, retain originals privately and retrieve them offline. It
does not yet execute an audit or admit findings to a case/report. Details and
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
selects the release scope, version and date. Keep **Desktop v0.6.1 — stable** as
the current download, and **Skill-first — in development** until an actual
preview is published. Do not relabel v0.6.1 or alter its updater to imply it
contains the new work.

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
