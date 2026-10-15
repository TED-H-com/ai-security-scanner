#!/usr/bin/env python3
"""Verify a locally loaded Semgrep build on native synthetic fixtures; no pull."""
from __future__ import annotations
import argparse
import collections
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tarfile

from build_rule_pack import build_rule_pack
from verify_image_payload import verify as verify_image_payload

HERE = Path(__file__).resolve().parent
IMAGE = "aiss-local/semgrep-combined:review"
ARM64_IMAGE = "aiss-local/semgrep-combined-arm64:review"
LAUNCHER = "/usr/local/bin/ai-security-scanner-engine-entrypoint"


def verify_source(image: str, output: Path, pack: Path, environment: dict) -> dict:
    container = f"aiss-semgrep-source-{os.getpid()}"
    source = output / "source-attachment"
    notices = output / "notices"
    subprocess.run(["docker", "create", "--pull", "never", "--name", container, image], env=environment, check=True, stdout=subprocess.DEVNULL)
    try:
        subprocess.run(["docker", "cp", f"{container}:/usr/share/source", str(source)], env=environment, check=True)
        subprocess.run(["docker", "cp", f"{container}:/usr/share/licenses", str(notices)], env=environment, check=True)
    finally:
        subprocess.run(["docker", "rm", container], env=environment, check=True, stdout=subprocess.DEVNULL)
    bundle = source / "semgrep-source.tar.gz"
    if bundle.stat().st_size > 128 * 1024 * 1024:
        raise ValueError("source attachment exceeds its compressed bound")
    provenance = json.loads((pack / "RULE-PROVENANCE.json").read_text())
    originals = {row["path"]: row["source_sha256"] for row in provenance.values() if row["kind"] == "upstream"}
    prefixes = ("semgrep/tests/semgrep-rules/", "semgrep/ai-security-scanner-build/rule-pack/source/")
    required = {prefix + relative: digest for prefix in prefixes for relative, digest in originals.items()}
    for relative in ("Dockerfile", "submodules.lock", "SOURCE-OFFER.md", "build_rule_pack.py", "prepare_source_bundle.py", "product-rules.yml", "product-LICENSE"):
        required["semgrep/ai-security-scanner-build/engines/images/semgrep/" + relative] = hashlib.sha256((HERE / relative).read_bytes()).hexdigest()
    for relative in ("go.mod", "main.go", "main_test.go"):
        required["semgrep/ai-security-scanner-build/engines/images/local-launcher/" + relative] = hashlib.sha256((HERE.parent / "local-launcher" / relative).read_bytes()).hexdigest()
    required["semgrep/tests/semgrep-rules/LICENSE"] = hashlib.sha256((pack / "LICENSE.upstream").read_bytes()).hexdigest()
    required["semgrep/LICENSE"] = hashlib.sha256((notices / "semgrep/LICENSE").read_bytes()).hexdigest()
    profile_name = "semgrep/ai-security-scanner-build/SOURCE-PROFILE.json"
    profile = None
    names, verified = set(), set()
    total = 0
    # One pass avoids repeated seeks/decompression through the 550 MiB tree.
    with tarfile.open(bundle, mode="r|gz") as attached:
        for member in attached:
            total += member.size
            if member.name in names or len(names) >= 100000 or total > 1024 * 1024 * 1024:
                raise ValueError("source attachment inventory exceeds its bound or repeats paths")
            names.add(member.name)
            # The unchanged generated Julia parser is about 70 MiB.
            if member.name.startswith("/") or ".." in Path(member.name).parts or member.size > 128 * 1024 * 1024:
                raise ValueError("unsafe source attachment member")
            if "no-direct-response-writer.yaml" in member.name or ("semgrep-rules" in member.name and member.name.endswith(".tar.gz")):
                raise ValueError("excluded rule or unfiltered rule archive was attached")
            if member.name in required or member.name == profile_name:
                if not member.isfile():
                    raise ValueError("expected regular source attachment member")
                with attached.extractfile(member) as content:
                    if member.name == profile_name:
                        if member.size > 2 * 1024 * 1024:
                            raise ValueError("source profile exceeds its bound")
                        profile = json.load(content)
                    else:
                        digest = hashlib.sha256()
                        while data := content.read(1024 * 1024):
                            digest.update(data)
                        if digest.hexdigest() != required[member.name]:
                            raise ValueError("attached original or rebuild input differs from verified source")
                        verified.add(member.name)
    if verified != set(required):
        raise ValueError("source attachment is missing required originals or rebuild inputs")
    for prefix in prefixes:
        observed = {name[len(prefix):] for name in names if name.startswith(prefix) and name.endswith((".yaml", ".yml"))}
        if observed != set(originals):
            raise ValueError("attached originals differ from the selected rule inventory")
    if not profile or profile["original_upstream_files"] != 1477 or profile["rules_gitlink_override"] != json.loads((pack / "PACK-METADATA.json").read_text())["upstream_revision"] or profile["rules_manifest_sha256"] != hashlib.sha256((pack / "RULES.sha256").read_bytes()).hexdigest():
        raise ValueError("attached source profile differs from the reviewed pack")
    for path, expected in ((notices / "semgrep-rules/LICENSE", pack / "LICENSE"), (notices / "ai-security-scanner-semgrep-rules/LICENSE", pack / "LICENSE.product"), (source / "semgrep-rule-pack.json", pack / "PACK-METADATA.json")):
        if path.read_bytes() != expected.read_bytes():
            raise ValueError("runtime license or pack metadata differs from the verified inputs")
    return {"sha256": hashlib.sha256(bundle.read_bytes()).hexdigest(), "bytes": bundle.stat().st_size, "selected_original_files": len(originals), "excluded_rule_absent": True, "unfiltered_rules_archive_absent": True, "rebuild_inputs_match": True}


def verify(archive: Path, output: Path, image_tag: str = IMAGE, expected_version: str | None = None) -> dict:
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
    if expected_version is None:
        if labels.get("io.ai-security-scanner.local-candidate-only") != "true":
            raise ValueError("local candidate requires its boundary label")
    elif labels.get("org.opencontainers.image.version") != expected_version or labels.get("io.ai-security-scanner.local-candidate-only") == "true":
        raise ValueError("release build does not declare the expected immutable version")
    image = inspected["Id"]
    pack = output / "pack"
    metadata = build_rule_pack(archive, HERE / "submodules.lock", pack, 1787250577)
    if labels.get("io.ai-security-scanner.rules-manifest-sha256") != metadata["manifest_sha256"]:
        raise ValueError("candidate image and local pack disagree")
    source_attachment = verify_source(image, output, pack, environment)
    payload_receipt = verify_image_payload(image, environment)
    base = ["nice", "-n", "10", "docker", "run", "--rm", "--pull", "never", "--platform", f"linux/{architecture}", "--network", "none", "--read-only", "--user", f"{os.getuid()}:{os.getgid()}", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--cpus", "2", "--memory", "2g", "--pids-limit", "256", "--ulimit", "fsize=536870912:536870912", "--mount", f"type=bind,source={HERE / 'testdata/combination-review'},target=/workspace,readonly"]
    def command(binary, *arguments):
        return ["--entrypoint", binary, image, *arguments]

    def run(name, command, mounts=(), success=True, writable_workspace=False):
        directory = output / name
        directory.mkdir()
        scratch = output / (name + "-tmp")
        scratch.mkdir()
        container = f"aiss-semgrep-managed-{os.getpid()}-{name}"
        arguments = base + ["--name", container, "--mount", f"type=bind,source={directory},target=/output", "--mount", f"type=bind,source={scratch},target=/tmp"]
        if writable_workspace:
            index = arguments.index(f"type=bind,source={HERE / 'testdata/combination-review'},target=/workspace,readonly")
            arguments[index] = arguments[index].removesuffix(",readonly")
        for source, target in mounts:
            arguments += ["--mount", f"type=bind,source={source},target={target},readonly"]
        arguments += command
        try:
            with (output / (name + ".log")).open("w") as log:
                result = subprocess.run(arguments, env=environment, stdout=log, stderr=log, timeout=600)
        finally:
            subprocess.run(["docker", "rm", "-f", container], env=environment, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            shutil.rmtree(scratch)
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
    extra = tampered / "extra-rules"
    shutil.copytree(pack / "rules", extra)
    (extra / "extra.yaml").write_text("rules: []\n")
    rejections = {}
    for name, source, target in (
        ("changed-rule", changed_rule, "/opt/ai-security-scanner/semgrep/rules/product/rules.yml"),
        ("changed-provenance", changed_provenance, "/opt/ai-security-scanner/semgrep/RULE-PROVENANCE.json"),
        ("extra-rule", extra, "/opt/ai-security-scanner/semgrep/rules"),
    ):
        rejections[name] = run(name, launcher, [(source, target)], success=False)
    rejections["writable-workspace"] = run("writable-workspace", launcher, success=False, writable_workspace=True)
    execution = {"mode": "native", "host_architecture": host_architecture, "image_architecture": architecture}
    summary = {"published": False, "expected_version": expected_version, "image_id": image, "image_tag": image_tag, "execution": execution, "image_payload": payload_receipt, "source_attachment": source_attachment, "pack": metadata, "native_matches": {name: len(rows) for name, rows in scans.items()}, "exact_full_result_union": True, "rejections_before_output": rejections, "managed_artifact_sha256": hashlib.sha256((output / "managed/semgrep.json").read_bytes()).hexdigest()}
    summary["source_revision"] = os.environ.get("GITHUB_SHA")
    (output / "verification.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    return summary


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--image", choices=(IMAGE, ARM64_IMAGE), default=IMAGE)
    parser.add_argument("--expected-version", help="Require this production version label instead of the private candidate label")
    args = parser.parse_args()
    print(json.dumps(verify(args.archive.resolve(), args.output.resolve(), args.image, args.expected_version), indent=2))
