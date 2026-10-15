#!/usr/bin/env python3
"""Hash an unstarted image filesystem to bind publication to native verification."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import PurePosixPath
import re
import subprocess
import tarfile

# Docker supplies these host/container-specific files at create time.
DOCKER_FILES = {"etc/hostname", "etc/hosts", "etc/resolv.conf", ".dockerenv"}


def payload(archive: tarfile.TarFile) -> dict:
    rows = []
    seen = set()
    total = 0
    for member in archive:
        path = PurePosixPath(member.name)
        name = str(path)
        if path.is_absolute() or ".." in path.parts or name in seen:
            raise ValueError("unsafe or repeated filesystem member")
        seen.add(name)
        total += member.size
        if len(seen) > 100000 or total > 1024 * 1024 * 1024:
            raise ValueError("image filesystem exceeds verification bounds")
        if name in DOCKER_FILES:
            continue
        row = {"path": name, "mode": member.mode, "uid": member.uid, "gid": member.gid}
        if member.isfile():
            digest = hashlib.sha256()
            with archive.extractfile(member) as source:
                while data := source.read(1024 * 1024):
                    digest.update(data)
            row.update(type="file", sha256=digest.hexdigest())
        elif member.issym() or member.islnk():
            row.update(type="symlink" if member.issym() else "hardlink", target=member.linkname)
        elif member.isdir():
            row.update(type="directory")
        else:
            raise ValueError("unexpected image filesystem member type")
        rows.append(row)
    rows.sort(key=lambda row: row["path"])
    if not any(row["path"] == "opt/semgrep/bin/semgrep" for row in rows):
        raise ValueError("Semgrep runtime is absent")
    encoded = json.dumps(rows, sort_keys=True, separators=(",", ":")).encode()
    return {"schema_version": 1, "rootfs_payload_sha256": hashlib.sha256(encoded).hexdigest(), "members": len(rows), "bytes": total, "docker_injected_paths_excluded": sorted(DOCKER_FILES)}


def verify(image: str, environment: dict | None = None) -> dict:
    if not re.fullmatch(r"(?:ghcr\.io/(?:teddashh|ted-h-com)/ai-security-scanner-engine-semgrep@)?sha256:[0-9a-f]{64}", image):
        raise ValueError("filesystem verification requires an exact Semgrep image digest")
    container = f"aiss-semgrep-payload-{os.getpid()}"
    subprocess.run(["docker", "create", "--pull", "never", "--name", container, image], env=environment, check=True, stdout=subprocess.DEVNULL)
    try:
        with subprocess.Popen(["docker", "export", container], env=environment, stdout=subprocess.PIPE) as exported:
            try:
                with tarfile.open(fileobj=exported.stdout, mode="r|") as archive:
                    receipt = payload(archive)
                if exported.wait(timeout=30) != 0:
                    raise ValueError("Docker filesystem export failed")
            except BaseException:
                exported.kill()
                exported.wait()
                raise
    finally:
        subprocess.run(["docker", "rm", container], env=environment, check=True, stdout=subprocess.DEVNULL)
    return receipt


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    parser.add_argument("--expected", required=True)
    args = parser.parse_args()
    receipt = verify(args.image)
    if receipt["rootfs_payload_sha256"] != args.expected:
        raise ValueError("published filesystem differs from the natively verified image")
    print(json.dumps(receipt, indent=2, sort_keys=True))
