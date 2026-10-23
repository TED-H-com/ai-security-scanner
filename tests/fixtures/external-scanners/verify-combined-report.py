#!/usr/bin/env python3
"""Offline CLI export regression: demo local checks + native Strix fixture.

This executes product import/export only, never a scanner or proof of concept.
All generated artifacts retain the demo marker; no live scan is claimed.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--cli", type=Path, required=True)
args = parser.parse_args()
cli = args.cli.resolve(strict=True)
work = Path(tempfile.mkdtemp(prefix="ai-scanner-combined-report-"))


def run(*command):
    result = subprocess.run(
        [str(cli), "--data-dir", str(work / "data"), "--json", *map(str, command)],
        capture_output=True, text=True, check=False,
    )
    if result.returncode:
        raise RuntimeError(f"{command[0]} failed: {result.stderr}")
    return json.loads(result.stdout)


case = run("case", "seed-demo")
case_id = case["id"]
local_run_id = case["scan_runs"][0]["id"]
fixture = Path(__file__).with_name("strix-vulnerabilities.json").resolve()
preview = run("external-report-preview", "--report", fixture)
binding = {
    "report_path": str(fixture),
    "asset_id": case["assets"][0]["id"],
    "upstream_target": "/workspace/app",
    "source_sha256": preview["source_sha256"],
}
manifest = work / "imports.json"
manifest.write_text(json.dumps([binding, dict(binding, source_sha256="0" * 64)]))
imported = run("external-report-import-batch", "--case-id", case_id, "--manifest", manifest)
imported_run = imported["scan_runs"][-1]
selected = [local_run_id, imported_run["id"]]
assert [task["status"] for task in imported_run["engine_runs"]] == ["partially_completed", "failed"]
assert imported["scope_grants"] == case["scope_grants"]
case_before = run("case", "show", case_id)
receipts = []
for format_, locale in [("html", "en"), ("html", "zh-Hant"), ("json", "en")]:
    destination = work / f"combined-{locale}.{format_}"
    receipt = run("export", "combine", "--case-id", case_id,
                  "--run-id", ",".join(selected), "--format", format_,
                  "--destination", destination, "--locale", locale)
    data = destination.read_bytes()
    assert receipt["selected_run_ids"] == selected
    assert receipt["sha256"] == hashlib.sha256(data).hexdigest()
    assert b"MUST NEVER EXECUTE" not in data
    if format_ == "json":
        report = json.loads(data)
        assert report["is_demo"] is True
        assert report["selected_run_ids"] == selected
        assert [source["origin"] for source in report["sources"]] == ["recorded_checks", "imported_reports"]
        assert {problem["source_run_id"] for problem in report["problems"]} == set(selected)
        assert report["summary"]["sources_with_imports"] == 1
        checks = report["sources"][1]["report"]["actual"]["checks"]
        assert {check["status"] for check in checks} == {"not_tested", "failed"}
        evidence = report["sources"][1]["report"]["findings"][0]["evidence_references"][0]
        assert evidence["observed_at"] == "2026-10-21T12:00:00Z"
        assert evidence["engine_run_id"] == imported_run["engine_runs"][0]["id"]
    else:
        html = data.decode()
        assert "Untrusted command execution" in html
        assert "2026-10-21T12:00:00+00:00" in html
        assert ("Demo project" if locale == "en" else "示範專案") in html
        assert "<script" not in html
    receipts.append(receipt)
assert run("case", "show", case_id) == case_before
summary = {"validation": "offline demo checks plus native upstream report fixture; no scanner executed", "artifacts": str(work), "receipts": receipts}
(work / "result.json").write_text(json.dumps(summary, indent=2))
print(json.dumps(summary, indent=2))
