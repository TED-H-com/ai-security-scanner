#!/usr/bin/env python3
"""Verify the local candidate launcher on synthetic fixtures; no image pull."""
from __future__ import annotations
import argparse
import collections
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess

from build_rule_pack import build_rule_pack

HERE = Path(__file__).resolve().parent
IMAGE = "aiss-local/semgrep-combined:review"
ARM64_IMAGE = "aiss-local/semgrep-combined-arm64:review"
LAUNCHER = "/usr/local/bin/ai-security-scanner-engine-entrypoint"


def verify(archive: Path, output: Path, image_tag: str = IMAGE) -> dict:
    if image_tag not in (IMAGE, ARM64_IMAGE):
        raise ValueError("only the two local review tags are allowed")
    if output.exists():
        raise ValueError("verification output already exists")
    output.mkdir(parents=True)
    anonymous = output / "anonymous-docker"
    anonymous.mkdir()
    (anonymous / "config.json").write_text("{}\n")
    environment = dict(os.environ, DOCKER_CONFIG=str(anonymous))
    inspected = json.loads(subprocess.check_output(["docker", "image", "inspect", image_tag], env=environment))[0]
    architecture = "arm64" if image_tag == ARM64_IMAGE else "amd64"
    if inspected["Os"] != "linux" or inspected["Architecture"] != architecture:
        raise ValueError("local candidate architecture does not match its review tag")
    host_architecture = {"x86_64": "amd64", "aarch64": "arm64"}.get(platform.machine(), platform.machine())
    if host_architecture != architecture:
        raise ValueError("managed verification requires a native host for the image architecture")
    if inspected["Config"]["Entrypoint"] != [LAUNCHER]:
        raise ValueError("candidate entrypoint differs from the managed launcher")
    labels = inspected["Config"]["Labels"]
    if labels.get("io.ai-security-scanner.local-candidate-only") != "true":
        raise ValueError("image does not declare the local candidate boundary")
    image = inspected["Id"]
    pack = output / "pack"
    metadata = build_rule_pack(archive, HERE / "submodules.lock", pack, 1787250577)
    if labels.get("io.ai-security-scanner.rules-manifest-sha256") != metadata["manifest_sha256"]:
        raise ValueError("candidate image and local pack disagree")
    base = ["nice", "-n", "10", "docker", "run", "--rm", "--pull", "never", "--platform", f"linux/{architecture}", "--network", "none", "--read-only", "--user", f"{os.getuid()}:{os.getgid()}", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--cpus", "2", "--memory", "2g", "--pids-limit", "256", "--ulimit", "fsize=536870912:536870912", "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,mode=1777,size=512m", "--mount", f"type=bind,source={HERE / 'testdata/combination-review'},target=/workspace,readonly"]
    def command(binary, *arguments):
        return ["--entrypoint", binary, image, *arguments]

    def run(name, command, mounts=(), success=True):
        directory = output / name
        directory.mkdir()
        container = f"aiss-semgrep-managed-{os.getpid()}-{name}"
        arguments = base + ["--name", container, "--mount", f"type=bind,source={directory},target=/output"]
        for source, target in mounts:
            arguments += ["--mount", f"type=bind,source={source},target={target},readonly"]
        arguments += command
        try:
            with (output / (name + ".log")).open("w") as log:
                result = subprocess.run(arguments, env=environment, stdout=log, stderr=log, timeout=600)
        except subprocess.TimeoutExpired:
            subprocess.run(["docker", "rm", "-f", container], env=environment, check=False)
            raise
        if success:
            if result.returncode != 0:
                raise ValueError(f"{name} failed; inspect preserved log")
            value = json.loads((directory / "semgrep.json").read_text())
            if value.get("errors") != [] or not isinstance(value.get("results"), list):
                raise ValueError(f"{name} did not complete cleanly")
            return value["results"]
        if result.returncode != 126 or any(directory.iterdir()):
            raise ValueError(f"{name} was not refused before output")
        return result.returncode

    scans = {}
    for name, config in (("product", "/opt/ai-security-scanner/semgrep/rules/product"), ("upstream", "/opt/ai-security-scanner/semgrep/rules/upstream"), ("combined", "/opt/ai-security-scanner/semgrep/rules")):
        scans[name] = run(name, command("/opt/semgrep/bin/semgrep", "scan", "--json", "--output", "/output/semgrep.json", "--config", config, "--metrics=off", "--disable-version-check", "--no-rewrite-rule-ids", "--oss-only", "--jobs", "2", "--max-memory", "2048", "--timeout", "10", "--timeout-threshold", "3", "--max-target-bytes", "10000000", "/workspace"))
    launcher = command(LAUNCHER, "--engine", "semgrep", "--workspace", "/workspace", "--output", "/output")
    scans["managed"] = run("managed", launcher)
    canonical = lambda rows: collections.Counter(json.dumps(row, sort_keys=True, separators=(",", ":")) for row in rows)
    expected = canonical(scans["product"] + scans["upstream"])
    if canonical(scans["combined"]) != expected or canonical(scans["managed"]) != expected:
        raise ValueError("candidate combined/managed output differs from separate-pass union")
    if {name: len(rows) for name, rows in scans.items()} != {"product": 10, "upstream": 12, "combined": 22, "managed": 22}:
        raise ValueError("candidate does not match the reviewed synthetic baseline")
    tampered = output / "tampered"
    tampered.mkdir()
    changed_rule = tampered / "product.yml"
    changed_rule.write_bytes((pack / "rules/product/rules.yml").read_bytes() + b"# tampered\n")
    changed_provenance = tampered / "provenance.json"
    changed_provenance.write_text("{}\n")
    extra = tampered / "extra.yaml"
    extra.write_text("rules: []\n")
    rejections = {}
    for name, source, target in (
        ("changed-rule", changed_rule, "/opt/ai-security-scanner/semgrep/rules/product/rules.yml"),
        ("changed-provenance", changed_provenance, "/opt/ai-security-scanner/semgrep/RULE-PROVENANCE.json"),
        ("extra-rule", extra, "/opt/ai-security-scanner/semgrep/rules/extra.yaml"),
    ):
        rejections[name] = run(name, launcher, [(source, target)], success=False)
    execution = {"mode": "native", "host_architecture": host_architecture, "image_architecture": architecture}
    summary = {"local_candidate_only": True, "image_id": image, "image_tag": image_tag, "execution": execution, "pack": metadata, "native_matches": {name: len(rows) for name, rows in scans.items()}, "exact_full_result_union": True, "rejections_before_output": rejections, "managed_artifact_sha256": hashlib.sha256((output / "managed/semgrep.json").read_bytes()).hexdigest()}
    (output / "verification.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    return summary


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--image", choices=(IMAGE, ARM64_IMAGE), default=IMAGE)
    args = parser.parse_args()
    print(json.dumps(verify(args.archive.resolve(), args.output.resolve(), args.image), indent=2))
