#!/usr/bin/env python3
"""Emulated ARM64 runtime probe: published CE, candidate inputs; no new image build."""
from __future__ import annotations

import argparse
import collections
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess

from build_rule_pack import build_rule_pack

HERE = Path(__file__).resolve().parent
IMAGE = "ghcr.io/teddashh/ai-security-scanner-engine-semgrep@sha256:0e80059911abc48d4aab405cbcc621104c7de0b9a212dede830636940b85d66c"
LAUNCHER = "/usr/local/bin/ai-security-scanner-engine-entrypoint"
HELPER_SHA256 = "bcaf5c26953814a0f3033101140fb342eb049d054d35fb3cb07a49d36a188406"
LAUNCHER_SHA256 = "70d9f2a3d3e55dd59d6c4a111b9a6c0e1919d269f25d53ee191463e929024f16"
STATFS_SHA256 = "87704ad7c1e8402569a07dbd6b840a8f9d3de33d85d53f73fd343a604e7fa3f4"
AMD64_REFERENCE_SHA256 = "861140fd126a1ad251f89198302034e3c945c091896fe2f05b2f8b4f5ed2f5bb"


def pinned_file(path: Path, expected: str) -> None:
    if path.is_symlink() or not path.is_file():
        raise ValueError("probe input must be a regular file")
    if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
        raise ValueError(f"probe input changed: {path.name}")


def verify(archive: Path, output: Path, helper: Path, launcher: Path, statfs: Path, mode: str = "all", reference: Path | None = None) -> dict:
    if platform.machine() != "x86_64" or platform.system() != "Linux":
        raise ValueError("this recorded helper is for a Linux amd64 host")
    pinned_file(helper, HELPER_SHA256)
    pinned_file(launcher, LAUNCHER_SHA256)
    pinned_file(statfs, STATFS_SHA256)
    if mode not in ("all", "boundaries", "managed"):
        raise ValueError("unknown probe mode")
    if mode == "managed":
        if reference is None:
            raise ValueError("managed comparison needs the verified amd64 JSON")
        pinned_file(reference, AMD64_REFERENCE_SHA256)
    if output.exists():
        raise ValueError("verification output already exists")
    output.mkdir(parents=True)
    anonymous = output / "anonymous-docker"
    anonymous.mkdir()
    (anonymous / "config.json").write_text("{}\n")
    environment = dict(os.environ, DOCKER_CONFIG=str(anonymous))
    inspected = json.loads(subprocess.check_output(["docker", "image", "inspect", IMAGE], env=environment))[0]
    if inspected["Os"] != "linux" or inspected["Architecture"] != "arm64" or IMAGE not in inspected["RepoDigests"]:
        raise ValueError("probe requires the exact published ARM64 manifest")
    if inspected["Config"]["Entrypoint"] != [LAUNCHER]:
        raise ValueError("published image entrypoint differs from the recorded launcher path")
    image = inspected["Id"]
    pack = output / "pack"
    metadata = build_rule_pack(archive, HERE / "submodules.lock", pack, 1787250577)
    control = output / "writable-control"
    control.mkdir()
    base = ["nice", "-n", "10", "docker", "run", "--rm", "--pull", "never", "--platform", "linux/arm64", "--network", "none", "--read-only", "--user", f"{os.getuid()}:{os.getgid()}", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--cpus", "2", "--memory", "2g", "--pids-limit", "256", "--ulimit", "fsize=536870912:536870912", "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,mode=1777,size=512m"]
    fixed_mounts = [(helper, "/review-qemu"), (launcher, LAUNCHER), (pack, "/opt/ai-security-scanner/semgrep")]

    def run(name, program, arguments=(), mounts=(), writable=False, refusal=None, probe=False, outer_timeout=600):
        directory = output / name
        directory.mkdir()
        container = f"aiss-semgrep-arm-probe-{os.getpid()}-{name}"
        workspace = control if writable else HERE / "testdata/combination-review"
        command = base + ["--name", container, "--mount", f"type=bind,source={workspace},target=/workspace" + ("" if writable else ",readonly"), "--mount", f"type=bind,source={directory},target=/output"]
        for source, target in fixed_mounts + list(mounts):
            command += ["--mount", f"type=bind,source={source},target={target},readonly"]
        command += ["--entrypoint", "/review-qemu", image, program, *arguments]
        try:
            with (output / (name + ".log")).open("w") as log:
                result = subprocess.run(command, env=environment, stdout=log, stderr=log, timeout=outer_timeout)
        except subprocess.TimeoutExpired:
            subprocess.run(["docker", "rm", "-f", container], env=environment, check=False)
            raise
        log_text = (output / (name + ".log")).read_text()
        if refusal is not None:
            if result.returncode != 126 or any(directory.iterdir()) or refusal not in log_text:
                raise ValueError(f"{name} was not refused for the expected reason before output")
            return result.returncode
        if result.returncode != 0:
            raise ValueError(f"{name} failed; inspect preserved log")
        if probe:
            flags = re.fullmatch(r"architecture=arm64 flags=(\d+) readonly=(true|false)", log_text.strip())
            if flags is None or bool(int(flags[1]) & 1) == writable or (flags[2] == "true") == writable or any(directory.iterdir()):
                raise ValueError(f"{name} did not distinguish the mount flags")
            return log_text.strip()
        value = json.loads((directory / "semgrep.json").read_text())
        if value.get("version") != "1.174.0" or value.get("errors") != [] or not isinstance(value.get("results"), list):
            raise ValueError(f"{name} did not complete on the expected CE version")
        return value["results"]

    mount_flags = {}
    for writable in (False, True):
        name = "statfs-writable" if writable else "statfs-readonly"
        mount_flags[name] = run(name, "/review-statfs", ["/workspace"], [(statfs, "/review-statfs")], writable=writable, probe=True)
    arguments = ["--engine", "semgrep", "--workspace", "/workspace", "--output", "/output"]
    tampered = output / "tampered"
    tampered.mkdir()
    rule = tampered / "rules.yml"
    rule.write_bytes((pack / "rules/product/rules.yml").read_bytes() + b"# tampered\n")
    provenance = tampered / "provenance.json"
    provenance.write_text("{}\n")
    extra = tampered / "rules-with-extra"
    shutil.copytree(pack / "rules", extra)
    (extra / "extra.yaml").write_text("rules: []\n")
    rejections = {}
    for name, source, target, reason in (
        ("changed-rule", rule, "/opt/ai-security-scanner/semgrep/rules/product/rules.yml", "digest"),
        ("changed-provenance", provenance, "/opt/ai-security-scanner/semgrep/RULE-PROVENANCE.json", "digest"),
        ("extra-rule", extra, "/opt/ai-security-scanner/semgrep/rules", "outside its immutable manifest"),
    ):
        rejections[name] = run(name, LAUNCHER, arguments, [(source, target)], refusal=reason)
    rejections["writable-workspace"] = run("writable-workspace", LAUNCHER, arguments, writable=True, refusal="workspace mount is writable")
    sentinel = tampered / "input-boundary-fixture"
    sentinel.write_text("#!/bin/sh\nprintf '%s\\n' local-arm64-input-boundary-probe >&2\nexit 23\n")
    sentinel.chmod(0o555)
    run("valid-inputs", LAUNCHER, arguments, [(sentinel, "/usr/local/bin/semgrep")], refusal="engine failed: exit status 23 (local-arm64-input-boundary-probe)")
    summary = {"local_runtime_probe_only": True, "fresh_candidate_image_build": False, "probe_mode": mode, "published_arm64_manifest": IMAGE, "image_id": image, "execution": {"mode": "qemu-user", "host_architecture": "amd64", "image_architecture": "arm64", "helper_sha256": HELPER_SHA256, "launcher_sha256": LAUNCHER_SHA256}, "mount_flags": mount_flags, "pack": metadata, "rejections_before_output": rejections, "valid_inputs_reach_invocation": True, "valid_input_control_uses_exit_23_fixture": True}
    (output / "boundary-verification.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    canonical = lambda rows: collections.Counter(json.dumps(row, sort_keys=True, separators=(",", ":")) for row in rows)
    if mode == "managed":
        reference_value = json.loads(reference.read_text())
        if reference_value.get("errors") != [] or len(reference_value.get("results", [])) != 22:
            raise ValueError("amd64 reference did not complete cleanly")
        # The actual managed launcher keeps its existing one-hour timeout.
        # This outer allowance handles emulation overhead; engine limits are unchanged.
        managed = run("managed", LAUNCHER, arguments, outer_timeout=3600)
        if canonical(managed) != canonical(reference_value["results"]):
            raise ValueError("managed ARM64 results differ from verified amd64 result objects")
        summary.update({"matches": {"managed": len(managed)}, "matches_verified_amd64_full_results": True, "amd64_reference_sha256": AMD64_REFERENCE_SHA256})
    elif mode == "all":
        scans = {}
        for name, config in (("product", "product"), ("upstream", "upstream"), ("combined", "")):
            config = "/opt/ai-security-scanner/semgrep/rules/" + config
            scans[name] = run(name, "/opt/semgrep/bin/semgrep", ["scan", "--json", "--output", "/output/semgrep.json", "--config", config, "--metrics=off", "--disable-version-check", "--no-rewrite-rule-ids", "--oss-only", "--jobs", "2", "--max-memory", "2048", "--timeout", "10", "--timeout-threshold", "3", "--max-target-bytes", "10000000", "/workspace"])
        scans["managed"] = run("managed", LAUNCHER, arguments)
        expected = canonical(scans["product"] + scans["upstream"])
        if canonical(scans["combined"]) != expected or canonical(scans["managed"]) != expected:
            raise ValueError("combined/managed ARM64 results differ from the complete separate-pass union")
        counts = {name: len(rows) for name, rows in scans.items()}
        if counts != {"product": 10, "upstream": 12, "combined": 22, "managed": 22}:
            raise ValueError("ARM64 runtime differs from the synthetic baseline")
        summary.update({"matches": counts, "exact_full_result_union": True})
    if mode != "boundaries":
        summary["managed_artifact_sha256"] = hashlib.sha256((output / "managed/semgrep.json").read_bytes()).hexdigest()
    (output / "verification.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    return summary


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("archive", "output", "helper", "launcher", "statfs"):
        parser.add_argument("--" + name, required=True, type=Path)
    parser.add_argument("--mode", choices=("all", "boundaries", "managed"), default="all")
    parser.add_argument("--reference", type=Path)
    args = parser.parse_args()
    print(json.dumps(verify(args.archive.absolute(), args.output.absolute(), args.helper.absolute(), args.launcher.absolute(), args.statfs.absolute(), args.mode, args.reference.absolute() if args.reference else None), indent=2))
