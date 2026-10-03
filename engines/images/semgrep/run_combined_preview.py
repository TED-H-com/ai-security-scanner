#!/usr/bin/env python3
"""Run three bounded, synthetic, local-only Semgrep comparison passes."""
from __future__ import annotations

import argparse
import collections
import json
import os
from pathlib import Path
import subprocess

from preview_combined_pack import build

IMAGE = "ghcr.io/teddashh/ai-security-scanner-engine-semgrep@sha256:6240c4ce08f9a5d7ead0914d907fae08704a1b783c3a7f8f405f978e9b596498"
HERE = Path(__file__).resolve().parent


def run(archive: Path, output: Path) -> dict:
    if output.exists():
        raise ValueError("experiment output already exists")
    output.mkdir(parents=True)
    metadata = build(archive, HERE / "product-rules.yml", output / "pack")
    anonymous = output / "anonymous-docker"
    anonymous.mkdir()
    (anonymous / "config.json").write_text("{}\n")
    environment = dict(os.environ, DOCKER_CONFIG=str(anonymous))
    # Use a new, empty Docker config; never read the user's registry credentials.
    subprocess.run(["docker", "pull", IMAGE], env=environment, check=True)
    results = output / "results"
    results.mkdir()
    base = ["nice", "-n", "10", "docker", "run", "--rm", "--network", "none", "--read-only", "--user", f"{os.getuid()}:{os.getgid()}", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--cpus", "2", "--memory", "2g", "--pids-limit", "256", "--tmpfs", "/tmp:rw,nosuid,nodev,size=512m"]
    for source, target, readonly in ((output / "pack", "/pack", True), (HERE / "testdata/combination-review", "/workspace", True), (results, "/output", False)):
        base += ["--mount", f"type=bind,source={source},target={target}" + (",readonly" if readonly else "")]
    scans = {}
    for name, config in (("product", "/pack/rules/product"), ("upstream", "/pack/rules/upstream"), ("combined", "/pack/rules")):
        container = f"aiss-semgrep-preview-{os.getpid()}-{name}"
        command = base + ["--name", container, "--entrypoint", "/opt/semgrep/bin/semgrep", IMAGE, "scan", "--json", "--metrics=off", "--disable-version-check", "--no-rewrite-rule-ids", "--oss-only", "--jobs", "2", "--max-memory", "2048", "--timeout", "10", "--timeout-threshold", "3", "--max-target-bytes", "10000000", "--output", f"/output/{name}.json", "--config", config, "/workspace"]
        try:
            with (results / f"{name}.log").open("w") as log:
                subprocess.run(command, env=environment, stdout=log, stderr=log, timeout=600, check=True)
        except subprocess.TimeoutExpired:
            subprocess.run(["docker", "rm", "-f", container], env=environment, check=False)
            raise
        value = json.loads((results / f"{name}.json").read_text())
        if value.get("errors") != [] or not isinstance(value.get("results"), list):
            raise ValueError(f"incomplete {name} scan; inspect preserved native JSON/log")
        scans[name] = value["results"]
    canonical = lambda row: json.dumps(row, sort_keys=True, separators=(",", ":"))
    expected = collections.Counter(canonical(row) for name in ("product", "upstream") for row in scans[name])
    actual = collections.Counter(map(canonical, scans["combined"]))
    if expected != actual:
        raise ValueError("combined native results differ from the separate-pass multiset union")
    summary = {"local_experiment_only": True, "image": IMAGE, "pack": metadata, "native_matches": {name: len(rows) for name, rows in scans.items()}, "errors": [], "exact_full_result_union": True}
    (output / "comparison.json").write_text(json.dumps(summary, indent=2) + "\n")
    adapter = output / "adapter"
    adapter.mkdir()
    (adapter / "semgrep.json").write_bytes((results / "combined.json").read_bytes())
    return summary


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    print(json.dumps(run(arguments.archive.resolve(), arguments.output.resolve()), indent=2))
