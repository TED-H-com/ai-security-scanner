# Check a fix: a real before-and-after scan · 2026-10-07

[繁體中文](README.zh-TW.md) · [View on the website](https://ted-h-com.github.io/ai-security-scanner/check-fixes-demo.html)

A small demo project was scanned, fixed and checked again with the desktop app. Unlike the [v0.4.0 sample reports](../../samples/v0.4.0/README.md), these are real scans: the eight tools ran on the folder in the app's local scanning runtime.

| Scan | Problems | English | 繁體中文 |
| --- | --- | --- | --- |
| Scan 1, before the fix | 13 (26 findings) | [scan1-before-fix-en.html](scan1-before-fix-en.html) | [scan1-before-fix-zh-TW.html](scan1-before-fix-zh-TW.html) |
| Scan 2, after the fix | 8 (16 findings) | [scan2-after-fix-en.html](scan2-after-fix-en.html) | [scan2-after-fix-zh-TW.html](scan2-after-fix-zh-TW.html) |

The reports show related findings as one problem; for example, five tools' detections of the same private key are one problem. Check fixes compared the two scans: 6 problems no longer observed, 7 still present (one of them only moved from line 19 to line 21), 1 new, 0 verification incomplete.

## How these files were made

- **App:** a development build of the desktop app on Linux, made from commit [`bca90a8`](https://github.com/TED-H-com/ai-security-scanner/commit/bca90a8), after v0.4.1. Its scanner images are the same ones v0.4.1 pins. Both scans were started from the app window.
- **Tools:** Checkov 3.3.13, Gitleaks 8.30.1, Grype 0.117.0, KICS 2.1.20, Semgrep 1.174.0, Syft 1.51.0, Trivy 0.74.0 and TruffleHog 3.97.0. Syft lists software packages and reports no problems. All eight completed in both scans.
- **Scan times:** Scan 1 ran from 01:11:59 to 01:24:36 UTC, Scan 2 from 01:26:25 to 01:38:04 UTC, on October 7, 2026. The screenshots show the test computer's local time (UTC−4), the evening of October 6.
- **Project:** a small Flask service written for this demo, with five planted problems. The fix commit removed the deploy key, switched to `yaml.safe_load`, upgraded PyYAML from 5.3.1 to 6.0.2, ran the container as a non-root user and turned on Flask debug mode on purpose. The project is not published, because it contains the planted private key. That key was created for this demo and never used anywhere.
- **Reports:** saved with the app's HTML exporter and the `standard` redaction profile (**Hide sensitive identifiers**), using commit [`e663b0a`](https://github.com/TED-H-com/ai-security-scanner/commit/e663b0a). The files are unchanged exports; [SHA256SUMS.txt](SHA256SUMS.txt) lists their hashes.
- **Screenshots:** taken from the app window, built from commit `e663b0a` (the comparison screenshot from `dff42c2`), after both scans had finished; then cropped and converted to WebP. Nothing else was edited.

## Not covered

- The deleted key is still in the project's git history. A real key must be revoked or rotated.
- Only the source folder was checked: the service was not run, no container image was built and no website was tested.
- Choosing the fixed folder again before Check fixes is not in v0.4.1. In v0.4.1, Check fixes scans the copy saved when the folder was first chosen.
- v0.4.1 reports do not include the comparison with the earlier scan, and v0.4.1 lists every finding on its own instead of combining related findings into one problem.
