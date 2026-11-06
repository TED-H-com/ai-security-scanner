#!/usr/bin/env python3
"""Verify and unpack the pinned M365 engine and PowerShell module closure."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import tarfile
import zipfile


CONTRACTS = {
    "scubagear": {
        "source_revision": "6e5a1a421b36c5a1fb3fd983b8c4bcd5b7a6c61d",
        "source_sha256": "b274d46d1a40f5869f4e4d3c94ffd192a212d2c414c1bd6c42b950c4e4fa4569",
        "source_root": "ScubaGear-6e5a1a421b36c5a1fb3fd983b8c4bcd5b7a6c61d",
        "source_date_epoch": 1792695550,
        "selections": {
            "PowerShell/ScubaGear": "engine/ScubaGear",
            "LICENSE": "licenses/ScubaGear-LICENSE",
        },
        "modules": {
            "Microsoft.Graph.Authentication": {
                "version": "2.25.0",
                "sha256": "c9596cd06539ea898d8f0bc3569bdd2fdbab931390fc5747548cfed75b10cc9d",
            },
            "powershell-yaml": {
                "version": "0.4.12",
                "sha256": "d4602bc7a4a093766520422d53ca8b09acde162286fae11e2ee6c8edfea07810",
            },
        },
        "manifest": "engine/ScubaGear/ScubaGear.psd1",
        "module_version": "2.0.0",
    },
    "maester": {
        "source_revision": "7413c42d3fcc724dfea94d2726e690ddd364d914",
        "source_sha256": "5abab2a96dc40ed6088734d1b60665b3c982be7f8f1fe5f8653474b494ef4e41",
        "source_root": "maester-7413c42d3fcc724dfea94d2726e690ddd364d914",
        "source_date_epoch": 1791284189,
        "selections": {
            "powershell": "engine/Maester",
            "build/Build-MaesterModule.ps1": "build/Build-MaesterModule.ps1",
            "build/Update-MaesterConfigVersion.ps1": "build/Update-MaesterConfigVersion.ps1",
            "tests/Maester/Entra": "tests/Maester/Entra",
            "tests/maester-config.json": "tests/maester-config.json",
            "LICENSE": "licenses/Maester-LICENSE",
        },
        "modules": {
            "Microsoft.Graph.Authentication": {
                "version": "2.27.0",
                "sha256": "7ac68868f2e12afb6c35df19542b1dfdd07b848bc69f6b45eca3a618e2143f78",
            },
            "Pester": {
                "version": "5.7.1",
                "sha256": "4a27904c6814a5fbe4758f8e49861f6a1994aee77b71165a5c43c0371ba6c580",
            },
        },
        "manifest": "engine/Maester/Maester.psd1",
        "module_version": "2.0.0",
    },
}

MAX_ARCHIVE_ENTRIES = 100_000
MAX_MEMBER_BYTES = 256 * 1024 * 1024
MAX_TOTAL_BYTES = 2 * 1024 * 1024 * 1024
VERSION_PATTERN = re.compile(r"(?m)^\s*ModuleVersion\s*=\s*['\"]([^'\"]+)['\"]")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def safe_archive_path(name: str, root: str) -> PurePosixPath:
    path = PurePosixPath(name)
    if path.is_absolute() or not path.parts or path.parts[0] != root:
        raise ValueError(f"archive member is outside the pinned source root: {name}")
    if any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError(f"archive member has an unsafe path: {name}")
    return PurePosixPath(*path.parts[1:])


def selected_target(relative: PurePosixPath, selections: dict[str, str]) -> Path | None:
    for source_prefix, destination_prefix in selections.items():
        source = PurePosixPath(source_prefix)
        if relative == source:
            return Path(destination_prefix)
        if len(relative.parts) > len(source.parts) and relative.parts[: len(source.parts)] == source.parts:
            return Path(destination_prefix, *relative.parts[len(source.parts) :])
    return None


def extract_source(archive: Path, output: Path, contract: dict[str, object]) -> None:
    if sha256(archive) != contract["source_sha256"]:
        raise ValueError("source archive digest does not match the managed image contract")
    extracted_files = 0
    extracted_bytes = 0
    seen_files: set[Path] = set()
    with tarfile.open(archive, mode="r:gz") as source:
        members = source.getmembers()
        if not members or len(members) > MAX_ARCHIVE_ENTRIES:
            raise ValueError("source archive entry count is outside the safety limit")
        for member in members:
            relative = safe_archive_path(member.name, str(contract["source_root"]))
            target_relative = selected_target(relative, contract["selections"])
            if target_relative is None:
                continue
            target = output / target_relative
            if member.isdir():
                # Keep the preparation tree writable until extraction is complete.
                # normalize_tree() makes every directory immutable in the final layer.
                target.mkdir(mode=0o755, parents=True, exist_ok=True)
                continue
            if not member.isreg() or member.size < 0 or member.size > MAX_MEMBER_BYTES:
                raise ValueError(f"selected source member is not a bounded regular file: {member.name}")
            if target in seen_files:
                raise ValueError(f"source archive contains a duplicate selected file: {member.name}")
            seen_files.add(target)
            extracted_files += 1
            extracted_bytes += member.size
            if extracted_files > MAX_ARCHIVE_ENTRIES or extracted_bytes > MAX_TOTAL_BYTES:
                raise ValueError("selected source content exceeds the safety limit")
            payload = source.extractfile(member)
            if payload is None:
                raise ValueError(f"selected source member could not be read: {member.name}")
            target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
            with target.open("xb") as destination:
                shutil.copyfileobj(payload, destination)
            target.chmod(0o444)
    for required in contract["selections"].values():
        if not (output / required).exists():
            raise ValueError(f"required selected source path is absent: {required}")


def safe_zip_path(name: str) -> PurePosixPath:
    path = PurePosixPath(name)
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError(f"PowerShell package contains an unsafe path: {name}")
    return path


def extract_module(package: Path, output: Path, name: str, version: str, expected_sha256: str) -> None:
    if sha256(package) != expected_sha256:
        raise ValueError(f"PowerShell package digest does not match for {name} {version}")
    destination_root = output / "modules" / name / version
    destination_root.mkdir(mode=0o755, parents=True, exist_ok=False)
    extracted_bytes = 0
    seen_files: set[Path] = set()
    with zipfile.ZipFile(package) as bundle:
        entries = bundle.infolist()
        if not entries or len(entries) > MAX_ARCHIVE_ENTRIES:
            raise ValueError(f"PowerShell package entry count is outside the limit for {name}")
        for entry in entries:
            relative = safe_zip_path(entry.filename)
            unix_mode = entry.external_attr >> 16
            if unix_mode and stat.S_ISLNK(unix_mode):
                raise ValueError(f"PowerShell package contains a symbolic link: {entry.filename}")
            target = destination_root.joinpath(*relative.parts)
            if entry.is_dir():
                target.mkdir(mode=0o755, parents=True, exist_ok=True)
                continue
            if entry.file_size < 0 or entry.file_size > MAX_MEMBER_BYTES:
                raise ValueError(f"PowerShell package member is outside the size limit: {entry.filename}")
            if target in seen_files:
                raise ValueError(f"PowerShell package contains a duplicate file: {entry.filename}")
            seen_files.add(target)
            extracted_bytes += entry.file_size
            if extracted_bytes > MAX_TOTAL_BYTES:
                raise ValueError(f"PowerShell package exceeds the extracted byte limit: {name}")
            target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
            with bundle.open(entry) as source, target.open("xb") as destination:
                shutil.copyfileobj(source, destination)
            target.chmod(0o444)
    manifest = destination_root / f"{name}.psd1"
    if not manifest.is_file():
        raise ValueError(f"PowerShell package manifest is absent for {name}")
    match = VERSION_PATTERN.search(manifest.read_text(encoding="utf-8-sig"))
    if not match or match.group(1) != version:
        raise ValueError(f"PowerShell package manifest version does not match for {name}")


def validate_lock(lock_path: Path, engine: str, contract: dict[str, object]) -> dict[str, object]:
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    if lock.get("schema_version") != "1.0.0" or lock.get("engine_id") != engine:
        raise ValueError("dependency lock schema or engine does not match")
    source = lock.get("source", {})
    if source.get("revision") != contract["source_revision"] or source.get("archive_sha256") != f"sha256:{contract['source_sha256']}":
        raise ValueError("dependency lock source does not match the compiled preparation contract")
    modules = lock.get("powershell_modules")
    if not isinstance(modules, list) or len(modules) != len(contract["modules"]):
        raise ValueError("dependency lock PowerShell module set is incomplete")
    observed = {
        item.get("name"): (item.get("version"), item.get("package_sha256"))
        for item in modules
        if isinstance(item, dict)
    }
    expected = {
        name: (record["version"], f"sha256:{record['sha256']}")
        for name, record in contract["modules"].items()
    }
    if observed != expected:
        raise ValueError("dependency lock PowerShell module set differs from the compiled contract")
    return lock


def normalize_tree(output: Path, epoch: int) -> None:
    paths = sorted(output.rglob("*"), key=lambda path: len(path.parts), reverse=True)
    for path in paths:
        if path.is_symlink():
            raise ValueError(f"prepared output unexpectedly contains a symbolic link: {path}")
        path.chmod(0o555 if path.is_dir() else 0o444)
        os.utime(path, (epoch, epoch), follow_symlinks=False)
    output.chmod(0o555)
    os.utime(output, (epoch, epoch), follow_symlinks=False)


def parse_packages(values: list[str]) -> dict[str, Path]:
    packages: dict[str, Path] = {}
    for value in values:
        name, separator, path = value.partition("=")
        if not separator or not name or not Path(path).is_absolute() or name in packages:
            raise ValueError("each --package must be a unique NAME=/absolute/path pair")
        packages[name] = Path(path)
    return packages


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--engine", required=True, choices=sorted(CONTRACTS))
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--lock", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--package", action="append", default=[])
    arguments = parser.parse_args()
    if not arguments.source.is_absolute() or not arguments.lock.is_absolute() or not arguments.output.is_absolute():
        raise ValueError("source, lock, and output paths must be absolute")
    if arguments.output.exists():
        raise ValueError("prepared output path must not already exist")

    contract = CONTRACTS[arguments.engine]
    lock = validate_lock(arguments.lock, arguments.engine, contract)
    packages = parse_packages(arguments.package)
    if set(packages) != set(contract["modules"]):
        raise ValueError("provided PowerShell package set is incomplete")

    arguments.output.mkdir(mode=0o755, parents=True, exist_ok=False)
    extract_source(arguments.source, arguments.output, contract)
    for name, record in contract["modules"].items():
        extract_module(packages[name], arguments.output, name, record["version"], record["sha256"])

    engine_manifest = arguments.output / contract["manifest"]
    match = VERSION_PATTERN.search(engine_manifest.read_text(encoding="utf-8-sig"))
    if not match or match.group(1) != contract["module_version"]:
        raise ValueError("engine module manifest version differs from the managed contract")

    canonical_lock = json.dumps(lock, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    lock_destination = arguments.output / "dependencies.lock.json"
    lock_destination.write_text(canonical_lock, encoding="utf-8", newline="\n")
    normalize_tree(arguments.output, int(contract["source_date_epoch"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
