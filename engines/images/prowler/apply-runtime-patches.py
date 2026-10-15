#!/usr/bin/env python3
"""Apply the reviewed Prowler runtime hunks without adding a build dependency.

The pinned upstream image intentionally contains neither git nor patch. This
small strict applier accepts only the reviewed series, exact patch digests,
exact diff file sets, and exact runtime source pre/post images. Test hunks stay
in the review patch but are not copied into the production image.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import os
import re
import stat
from pathlib import Path


SERIES = (
    "0001-azure-static-access-token-iam-only.patch",
    "0002-gcp-exact-project-lookups.patch",
    "0003-gcp-disable-ambient-organization-search.patch",
    "0004-gcp-disable-provider-organization-lookup.patch",
    "0005-azure-disable-tenant-enumeration.patch",
    "0006-azure-require-enabled-subscription.patch",
)
PATCH_SHA256 = {
    SERIES[0]: "053ef441588b6bff99aef8a568f2617d8933a46449d2f9c2804b796c7a39566a",
    SERIES[1]: "7a22e58b3c700813e3b7e814dd04254dd90ddbdbdfbccd917c3b477e487c2fcb",
    SERIES[2]: "136335c3b7defd5a167aa6d07633bcb8f5c99c6f98b398eff01fc15d11a417d1",
    SERIES[3]: "ffef7b02808bbb85f1f7d28ab3c453237b33cde45729daa51feb37633e1fd79a",
    SERIES[4]: "00f40971d80137612b5327a8b7e31de6b05b08dd8239f1bd635339ae6325f80b",
    SERIES[5]: "47b4202cdfe545b699fbe0b0dfc3e5d249d94e9d00cf7d61388405071e5aaeba",
}
EXPECTED_DIFF_FILES = {
    SERIES[0]: {
        "prowler/providers/azure/azure_provider.py",
        "prowler/providers/azure/lib/arguments/arguments.py",
        "prowler/providers/common/provider.py",
        "tests/providers/azure/azure_access_token_auth_test.py",
    },
    SERIES[1]: {
        "prowler/providers/gcp/gcp_provider.py",
        "tests/providers/gcp/gcp_exact_projects_test.py",
    },
    SERIES[2]: {
        "prowler/providers/gcp/services/cloudresourcemanager/cloudresourcemanager_service.py",
        "tests/providers/gcp/services/cloudresourcemanager/cloudresourcemanager_service_test.py",
    },
    SERIES[3]: {
        "prowler/providers/gcp/gcp_provider.py",
        "tests/providers/gcp/gcp_exact_projects_test.py",
    },
    SERIES[4]: {
        "prowler/lib/outputs/finding.py",
        "prowler/providers/azure/azure_provider.py",
        "tests/providers/azure/azure_access_token_auth_test.py",
    },
    SERIES[5]: {
        "prowler/providers/azure/azure_provider.py",
        "tests/providers/azure/azure_access_token_auth_test.py",
    },
}
RUNTIME_FILES = {
    "prowler/providers/azure/azure_provider.py": (
        "8e54390485d31feeb5e114db2c24933f3c73a4f22f2532b5c18583f9520c9cbb",
        "51cef0e3e7ed819144959f62389d3eb169b97aa37baf37aab66d4c290d21bf14",
    ),
    "prowler/providers/azure/lib/arguments/arguments.py": (
        "fc48fdd229d5760f5675f06032e05df8e54ee8777dd04a60aecc093615474068",
        "afb7c9b47f1b9b2354774579121db4f1c26d6b03112a3d0407fb4f14ad8625af",
    ),
    "prowler/providers/common/provider.py": (
        "1080b11456deb6426307167067a3066ec79c87c7af07bb85dd3c507d6c76a1da",
        "bd65d893c106cf47389cd17071f96002e7302706b07ebb17cdca6c10f95f3f27",
    ),
    "prowler/lib/outputs/finding.py": (
        "00ed79bee5e32239d3cce4943c70df33dbfe3f85056deb750ad11f2073613cce",
        "71d5665f11c27a3dc69660ac61b747264066c6791ba65014c50ba80105902749",
    ),
    "prowler/providers/gcp/gcp_provider.py": (
        "9ae2691559660ca902ab3b282fb1a5611bb47ca11f3118d34500dac847770c77",
        "c30756aaaa1ce3739c6bf2a023b4ab633656c767f1e6fa1e84ba4ff9fff1c34f",
    ),
    "prowler/providers/gcp/services/cloudresourcemanager/cloudresourcemanager_service.py": (
        "029725c008bf0ed0d6c8cdb8ba1a378d40e584dc49ee40e021c4955e4e5688f3",
        "379876877311fe2f4aa17bb9d5b132c85baaf2081210aebf6da59472cc11c9fe",
    ),
}
HUNK_HEADER = re.compile(
    r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(?: .*)?\n?$"
)
DIFF_HEADER = re.compile(r"^diff --git a/([^\s]+) b/([^\s]+)\n?$")


def sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def parse_sections(content: bytes) -> dict[str, list[str]]:
    try:
        lines = content.decode("utf-8").splitlines(keepends=True)
    except UnicodeDecodeError as error:
        raise ValueError("patch is not UTF-8") from error
    sections: dict[str, list[str]] = {}
    current_path: str | None = None
    for line in lines:
        match = DIFF_HEADER.match(line)
        if match:
            old_path, new_path = match.groups()
            if old_path != new_path or new_path in sections:
                raise ValueError("patch contains a renamed or duplicate diff path")
            if new_path.startswith("/") or ".." in Path(new_path).parts:
                raise ValueError("patch path escapes the source tree")
            current_path = new_path
            sections[current_path] = []
            continue
        if current_path is not None:
            sections[current_path].append(line)
    if not sections:
        raise ValueError("patch contains no file sections")
    return sections


def apply_section(source: bytes, section: list[str], path: str) -> bytes:
    try:
        source_lines = source.decode("utf-8").splitlines(keepends=True)
    except UnicodeDecodeError as error:
        raise ValueError(f"runtime source is not UTF-8: {path}") from error

    output: list[str] = []
    source_cursor = 0
    index = 0
    hunks = 0
    while index < len(section):
        match = HUNK_HEADER.match(section[index])
        if not match:
            index += 1
            continue
        hunks += 1
        old_start = int(match.group(1))
        old_count = int(match.group(2) or "1")
        new_count = int(match.group(4) or "1")
        target = old_start - 1 if old_count else old_start
        if target < source_cursor or target > len(source_lines):
            raise ValueError(f"out-of-order hunk for {path}")
        output.extend(source_lines[source_cursor:target])
        source_cursor = target
        observed_old = 0
        observed_new = 0
        index += 1
        while index < len(section) and not HUNK_HEADER.match(section[index]):
            line = section[index]
            if line.startswith("\\ No newline at end of file"):
                raise ValueError(f"unsupported no-newline marker for {path}")
            if not line or line[0] not in " +-":
                raise ValueError(f"malformed hunk line for {path}")
            marker, value = line[0], line[1:]
            if marker in " -":
                if source_cursor >= len(source_lines) or source_lines[source_cursor] != value:
                    raise ValueError(f"hunk preimage differs for {path}")
                source_cursor += 1
                observed_old += 1
            if marker in " +":
                output.append(value)
                observed_new += 1
            index += 1
        if observed_old != old_count or observed_new != new_count:
            raise ValueError(f"hunk line count differs for {path}")
    if hunks == 0:
        raise ValueError(f"runtime patch contains no hunks for {path}")
    output.extend(source_lines[source_cursor:])
    return "".join(output).encode("utf-8")


def exact_regular_file(root: Path, relative: str) -> Path:
    path = root / relative
    resolved_root = root.resolve(strict=True)
    resolved_path = path.resolve(strict=True)
    if resolved_path != resolved_root.joinpath(*Path(relative).parts):
        raise ValueError(f"runtime source path contains a symlink: {relative}")
    mode = path.lstat().st_mode
    if not stat.S_ISREG(mode) or stat.S_ISLNK(mode):
        raise ValueError(f"runtime source is not a regular file: {relative}")
    return path


def main() -> None:
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--patch-dir", required=True, type=Path)
    arguments = parser.parse_args()

    series_content = (arguments.patch_dir / "series").read_text(encoding="utf-8")
    series_lines = series_content.splitlines()
    if any(line != line.strip() for line in series_lines) or tuple(
        line for line in series_lines if line
    ) != SERIES:
        raise ValueError("Prowler patch series differs from the reviewed order")

    parsed: dict[str, dict[str, list[str]]] = {}
    for patch_name in SERIES:
        patch_content = (arguments.patch_dir / patch_name).read_bytes()
        if sha256(patch_content) != PATCH_SHA256[patch_name]:
            raise ValueError(f"patch digest differs: {patch_name}")
        sections = parse_sections(patch_content)
        if set(sections) != EXPECTED_DIFF_FILES[patch_name]:
            raise ValueError(f"patch file set differs: {patch_name}")
        parsed[patch_name] = sections

    paths = {
        relative: exact_regular_file(arguments.root, relative)
        for relative in RUNTIME_FILES
    }
    contents = {relative: path.read_bytes() for relative, path in paths.items()}
    for relative, (expected_before, _) in RUNTIME_FILES.items():
        if sha256(contents[relative]) != expected_before:
            raise ValueError(f"pinned image source preimage differs: {relative}")

    for patch_name in SERIES:
        for relative, section in parsed[patch_name].items():
            if relative in contents:
                contents[relative] = apply_section(contents[relative], section, relative)

    for relative, (_, expected_after) in RUNTIME_FILES.items():
        content = contents[relative]
        if sha256(content) != expected_after:
            raise ValueError(f"patched source postimage differs: {relative}")
        ast.parse(content, filename=relative)

    for relative, path in paths.items():
        temporary = path.with_name(path.name + ".ai-security-scanner-patched")
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(descriptor, "wb") as output:
                output.write(contents[relative])
                output.flush()
                os.fsync(output.fileno())
            os.chmod(temporary, stat.S_IMODE(path.stat().st_mode))
            os.replace(temporary, path)
        finally:
            if temporary.exists():
                temporary.unlink()

    print("Prowler runtime patches applied to exact reviewed source postimages")


if __name__ == "__main__":
    main()
