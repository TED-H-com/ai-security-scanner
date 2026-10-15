#!/usr/bin/env python3
"""Verify and unpack the pinned Checkov source, then render its hashed runtime lock."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import sys
import tarfile


SOURCE_REVISION = "e40023ab262c7c8b7b0a8f0975072b42d1b601f9"
SOURCE_ARCHIVE_SHA256 = "5f6f20199994878d8af30c85e992339f3d4014fcae831b4537e64ecf209e5b96"
PIPFILE_LOCK_SHA256 = "f51eb3c9693670743a8be18191e44bcacf80f21e68cdfdb86dc00b0017df7995"
SOURCE_DATE_EPOCH = 1_791_891_584
EXPECTED_DEPENDENCIES = 99
NAME_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
VERSION_PATTERN = re.compile(r"^==[^\s;]+$")
HASH_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def safe_relative_path(member_name: str) -> Path:
    archive_path = PurePosixPath(member_name)
    prefix = f"checkov-{SOURCE_REVISION}"
    if archive_path.is_absolute() or not archive_path.parts or archive_path.parts[0] != prefix:
        raise ValueError(f"archive member is outside the pinned source root: {member_name}")
    relative = PurePosixPath(*archive_path.parts[1:])
    if any(part in {"", ".", ".."} for part in relative.parts):
        raise ValueError(f"archive member has an unsafe path: {member_name}")
    return Path(*relative.parts)


def extract_source(archive: Path, destination: Path) -> None:
    if sha256(archive) != SOURCE_ARCHIVE_SHA256:
        raise ValueError("Checkov source archive digest does not match the release contract")
    destination.mkdir(mode=0o755, parents=True, exist_ok=False)
    extracted: list[Path] = [destination]
    with tarfile.open(archive, mode="r:gz") as source:
        members = source.getmembers()
        if not members:
            raise ValueError("Checkov source archive is empty")
        for member in members:
            relative = safe_relative_path(member.name)
            if not relative.parts:
                continue
            target = destination / relative
            if member.isdir():
                target.mkdir(mode=member.mode & 0o755 or 0o755, parents=True, exist_ok=True)
                extracted.append(target)
                continue
            if not member.isreg():
                raise ValueError(f"Checkov source archive contains a non-regular member: {member.name}")
            target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
            payload = source.extractfile(member)
            if payload is None:
                raise ValueError(f"Checkov source archive member could not be read: {member.name}")
            with target.open("xb") as output:
                shutil.copyfileobj(payload, output)
            target.chmod(member.mode & 0o755 or 0o644)
            extracted.append(target)
    for path in sorted(set(extracted), key=lambda value: len(value.parts), reverse=True):
        os.utime(path, (SOURCE_DATE_EPOCH, SOURCE_DATE_EPOCH), follow_symlinks=False)


def render_requirements(source: Path, destination: Path) -> None:
    lock_path = source / "Pipfile.lock"
    if sha256(lock_path) != PIPFILE_LOCK_SHA256:
        raise ValueError("Pipfile.lock digest does not match the pinned Checkov source")
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    packages = lock.get("default")
    if not isinstance(packages, dict) or len(packages) != EXPECTED_DEPENDENCIES:
        raise ValueError("Pipfile.lock runtime dependency set is incomplete")
    lines = [
        "# Generated from Checkov 3.3.29 Pipfile.lock.",
        f"# source-revision: {SOURCE_REVISION}",
        f"# pipfile-lock-sha256: {PIPFILE_LOCK_SHA256}",
    ]
    for name in sorted(packages):
        record = packages[name]
        version = record.get("version")
        hashes = sorted(set(record.get("hashes", [])))
        marker = record.get("markers")
        if not NAME_PATTERN.fullmatch(name) or not isinstance(version, str) or not VERSION_PATTERN.fullmatch(version):
            raise ValueError(f"dependency {name!r} does not have one exact version")
        if not hashes or any(not isinstance(value, str) or not HASH_PATTERN.fullmatch(value) for value in hashes):
            raise ValueError(f"dependency {name!r} does not have an exact sha256 artifact set")
        if marker is not None and (not isinstance(marker, str) or not marker or "\n" in marker or "\r" in marker):
            raise ValueError(f"dependency {name!r} has an unsafe environment marker")
        requirement = f"{name}{version}"
        if marker:
            requirement += f" ; {marker}"
        requirement += " \\\n" + " \\\n".join(f"    --hash={value}" for value in hashes)
        lines.append(requirement)
    destination.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    destination.chmod(0o444)
    os.utime(destination, (SOURCE_DATE_EPOCH, SOURCE_DATE_EPOCH))


def main() -> int:
    if len(sys.argv) != 4:
        raise ValueError("usage: prepare_source.py ARCHIVE SOURCE_DIRECTORY REQUIREMENTS_LOCK")
    archive = Path(sys.argv[1])
    source = Path(sys.argv[2])
    requirements = Path(sys.argv[3])
    if not archive.is_absolute() or not source.is_absolute() or not requirements.is_absolute():
        raise ValueError("all preparation paths must be absolute")
    extract_source(archive, source)
    render_requirements(source, requirements)
    archive.unlink()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
