#!/usr/bin/env python3
"""Build the local candidate legacy + product Semgrep rule pack."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tarfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath


RULE_SOURCE_PATH = "tests/semgrep-rules"
RULE_SOURCE_REPOSITORY = "https://github.com/semgrep/semgrep-rules"
EXPECTED_CONFIG_FILE_COUNT = 1478
EXPECTED_RULE_COUNT = 1497
MAX_RULE_FILE_BYTES = 1024 * 1024
MAX_RULE_PACK_BYTES = 16 * 1024 * 1024
TEST_FILE_ENDINGS = (
    ".test.yaml",
    ".test.yml",
    ".fixed.test.yaml",
    ".fixed.test.yml",
)


@dataclass(frozen=True)
class LockedSource:
    repository: str
    revision: str
    digest: str
    size: int
    archive: str


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while block := handle.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def load_locked_source(lock_path: Path) -> LockedSource:
    matches: list[LockedSource] = []
    for raw_line in lock_path.read_text(encoding="utf-8").splitlines():
        if not raw_line or raw_line.startswith("#"):
            continue
        fields = raw_line.split("|")
        if len(fields) != 6:
            raise ValueError(f"invalid Semgrep submodule lock record: {raw_line}")
        path, repository, revision, digest, size_text, archive = fields
        if path != RULE_SOURCE_PATH:
            continue
        if (
            repository != RULE_SOURCE_REPOSITORY
            or not re.fullmatch(r"[0-9a-f]{40}", revision)
            or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest)
            or not re.fullmatch(r"[1-9][0-9]*", size_text)
            or not re.fullmatch(r"[a-z0-9_.-]+\.tar\.gz", archive)
        ):
            raise ValueError("the pinned semgrep-rules lock record is invalid")
        matches.append(LockedSource(repository, revision, digest, int(size_text), archive))
    if len(matches) != 1:
        raise ValueError("the lock must contain exactly one semgrep-rules source record")
    return matches[0]


def is_selected_rule_path(relative_path: PurePosixPath) -> bool:
    if relative_path.suffix not in {".yaml", ".yml"}:
        return False
    if relative_path.name.endswith(TEST_FILE_ENDINGS):
        return False
    parts = relative_path.parts
    # Semgrep CE 1.174.0 advertises Apex but requires an unavailable proprietary
    # parser plugin when these rules are loaded. Keep the offline OSS pack free
    # of rules the embedded engine cannot execute.
    if parts[0] == "apex":
        return False
    return (
        "security" in parts
        or "secrets" in parts
        or parts[:2] == ("ai", "ai-best-practices")
    )


def validate_rule_text(relative_path: PurePosixPath, data: bytes) -> int:
    if not data or len(data) > MAX_RULE_FILE_BYTES or b"\x00" in data:
        raise ValueError(f"invalid rule file size or content: {relative_path}")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError(f"rule file is not UTF-8: {relative_path}") from error
    required_patterns = {
        "rules": r"(?m)^rules:\s*$",
        "rule id": r"(?m)^(?:\s*-\s+|\s+)id:\s*[^\s#]",
        "languages": r"(?m)^\s+languages:\s*",
        "message": r"(?m)^\s+message:\s*",
        "severity": r"(?m)^\s+severity:\s*(?:INFO|WARNING|ERROR)\s*$",
        "metadata": r"(?m)^\s+metadata:\s*$",
    }
    for label, pattern in required_patterns.items():
        if re.search(pattern, text) is None:
            raise ValueError(f"selected YAML lacks {label}: {relative_path}")
    categories = re.findall(r"(?m)^\s+category:\s*([A-Za-z0-9_-]+)\s*$", text)
    if not categories:
        raise ValueError(f"selected YAML lacks an upstream category: {relative_path}")
    severities = re.findall(r"(?m)^\s+severity:\s*(?:INFO|WARNING|ERROR)\s*$", text)
    if len(categories) != len(severities):
        raise ValueError(f"selected YAML has inconsistent rule metadata: {relative_path}")
    if not all(category == "security" for category in categories):
        return 0
    return len(categories)


def safe_relative_member(name: str, expected_root: str) -> PurePosixPath | None:
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts or not path.parts:
        raise ValueError(f"unsafe path in semgrep-rules archive: {name}")
    if path.parts[0] != expected_root:
        raise ValueError(f"unexpected root in semgrep-rules archive: {name}")
    if len(path.parts) == 1:
        return None
    relative = PurePosixPath(*path.parts[1:])
    if any(not part or part in {".", ".."} for part in relative.parts):
        raise ValueError(f"unsafe relative path in semgrep-rules archive: {name}")
    return relative


REVISION = "0f5a85ceab1b82b193d0eaa418784c932d237d68"
ARCHIVE_SHA256 = "a6bb2ee1a261da82a1263c1b32ad6f4535628742192c0bb1f68f13343c31bbcc"
ARCHIVE_BYTES = 1148011
LICENSE_SHA256 = "9600f388f17cb800a7a0ba8b55bc15c5b0ed047de8517f2d5e533becee9d0a18"
EXCLUDED = "java/lang/security/audit/xss/no-direct-response-writer.yaml"
EXCLUDED_SHA256 = "44f00a2b33815116facd15a58b4d360418c7940c2cbdde671856f042d4f5498f"
PRODUCT_SHA256 = "2081a62359682db1ddd15eda7eed1f3931975870cef8f8dab7120ba86fe2e5f3"
PRODUCT_LICENSE_SHA256 = "2c932015241407e23ce7b557b89d284ea7d5f13fa056f480e91184f27e87bdc8"
PRODUCT_IDS = {
    "ai-security-scanner.python.dynamic-code-execution",
    "ai-security-scanner.python.shell-true",
    "ai-security-scanner.javascript.child-process-exec",
    "ai-security-scanner.generic.private-key",
}
ID_LINE = re.compile(r"(?m)^([ \t]*(?:-[ \t]+)?id:[ \t]*)([A-Za-z0-9_.-]+)([ \t]*\r?)$")
NOTICE = (
    "# Modified by ai-security-scanner on 2026-10-02: file-qualified rule IDs\n"
    "# prevent collisions; detector, severity, message and remediation unchanged.\n"
    "# Original bytes and IDs: source/ and RULE-PROVENANCE.json beside rules/.\n"
)



sha = sha256_bytes


def build_combined_rule_pack(archive: Path, product: Path, output: Path) -> dict:
    if output.exists():
        raise ValueError("output already exists")
    if archive.stat().st_size != ARCHIVE_BYTES or sha256_file(archive) != ARCHIVE_SHA256:
        raise ValueError("archive does not match the exact reviewed revision")
    selected, sources, records, ids, excluded = {}, {}, {}, set(), []
    license_bytes = readme_bytes = None
    upstream_rules = 0
    with tarfile.open(archive, "r:gz") as tar:
        for member in tar:
            relative = safe_relative_member(member.name, f"semgrep-rules-{REVISION}")
            if relative is None or member.isdir():
                continue
            if not member.isfile():
                raise ValueError("non-regular archive member")
            path = relative.as_posix()
            if path not in {"LICENSE", "README.md"} and not is_selected_rule_path(relative):
                continue
            if member.size > 1024 * 1024:
                raise ValueError("oversized source member")
            raw = tar.extractfile(member).read()
            if path == "LICENSE":
                license_bytes = raw
                continue
            if path == "README.md":
                readme_bytes = raw
                continue
            count = validate_rule_text(relative, raw)
            if not count:
                continue
            text = raw.decode("utf-8")
            if path == EXCLUDED:
                if sha(raw) != EXCLUDED_SHA256 or "license: proprietary license" not in text:
                    raise ValueError("excluded rule no longer matches the reviewed exception")
                excluded.append({"path": path, "sha256": sha(raw), "reason": "explicit proprietary license", "rules": count})
                continue
            licenses = [value.strip() for value in re.findall(r"(?m)^\s+license:\s*(.+)$", text)]
            if any(value != "Commons Clause License Condition v1.0[LGPL-2.1-only]" for value in licenses):
                raise ValueError(f"unreviewed per-file license: {path}")
            matches = list(ID_LINE.finditer(text))
            if len(matches) != count:
                raise ValueError(f"ID count differs from validated rule count: {path}")
            namespace = relative.with_suffix("").as_posix().replace("/", ".")
            def qualify(match):
                original = match.group(2)
                qualified = f"{namespace}.{original}"
                if qualified in ids or not re.fullmatch(r"[A-Za-z0-9_.-]+", qualified):
                    raise ValueError(f"ambiguous qualified ID: {qualified}")
                ids.add(qualified)
                records[qualified] = {"kind": "upstream", "repository": "https://github.com/semgrep/semgrep-rules", "revision": REVISION, "path": path, "original_id": original, "source_sha256": sha(raw)}
                return match.group(1) + qualified + match.group(3)
            qualified_text = ID_LINE.sub(qualify, text)
            # Round-trip proves all upstream detector and metadata bytes survive.
            restored = ID_LINE.sub(lambda m: m.group(1) + records[m.group(2)]["original_id"] + m.group(3), qualified_text)
            if restored.encode("utf-8") != raw:
                raise ValueError("upstream bytes changed beyond rule IDs")
            selected[f"upstream/{path}"] = (NOTICE + qualified_text).encode("utf-8")
            sources[path] = raw
            upstream_rules += count
    if license_bytes is None or sha(license_bytes) != LICENSE_SHA256 or readme_bytes is None:
        raise ValueError("reviewed license or README missing/changed")
    if len(sources) != 1477 or upstream_rules != 1493 or len(excluded) != 1:
        raise ValueError("legacy selection differs from the reviewed inventory")
    product_bytes = product.read_bytes()
    if sha(product_bytes) != PRODUCT_SHA256:
        raise ValueError("product rules differ from the published four-rule source")
    product_license = (product.parent / "product-LICENSE").read_bytes()
    if sha(product_license) != PRODUCT_LICENSE_SHA256:
        raise ValueError("product license differs from the reviewed Apache license")
    if validate_rule_text(PurePosixPath("product/rules.yml"), product_bytes) != 4:
        raise ValueError("product pack must contain the four existing rules")
    product_matches = list(ID_LINE.finditer(product_bytes.decode("utf-8")))
    if len(product_matches) != 4 or {m.group(2) for m in product_matches} != PRODUCT_IDS:
        raise ValueError("unexpected or duplicated product rule ID")
    for match in product_matches:
        rule_id = match.group(2)
        if rule_id in ids:
            raise ValueError("product/upstream ID collision")
        ids.add(rule_id)
        records[rule_id] = {"kind": "product", "original_id": rule_id, "path": "product/rules.yml", "source_revision": "2641850", "source_sha256": sha(product_bytes), "license": "Apache-2.0"}
    selected["product/rules.yml"] = product_bytes
    if sum(map(len, selected.values())) > 16 * 1024 * 1024:
        raise ValueError("combined pack exceeds resource bound")
    for base, files in ((output / "rules", selected), (output / "source", sources)):
        for path, raw in sorted(files.items()):
            destination = base / path
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(raw)
    manifest = "".join(f"{sha(raw)}  {path}\n" for path, raw in sorted(selected.items())).encode()
    (output / "RULES.sha256").write_bytes(manifest)
    (output / "LICENSE.upstream").write_bytes(license_bytes)
    (output / "LICENSE.product").write_bytes(product_license)
    (output / "UPSTREAM-README.md").write_bytes(readme_bytes)
    (output / "RULE-PROVENANCE.json").write_text(json.dumps(records, indent=2, sort_keys=True) + "\n")
    metadata = {"schema_version": "ai-security-scanner.semgrep-rule-pack/v2", "local_experiment_only": True, "upstream_revision": REVISION, "archive_sha256": ARCHIVE_SHA256, "upstream_files": len(sources), "upstream_rules": upstream_rules, "product_rules": 4, "combined_files": len(selected), "combined_rules": len(ids), "manifest_sha256": sha(manifest), "excluded": excluded, "license_note": "LGPL plus Commons Clause remains applicable to upstream rules; this experiment does not approve publication or commercial use."}
    metadata["upstream"] = {"repository": RULE_SOURCE_REPOSITORY, "revision": REVISION, "archive_sha256": f"sha256:{ARCHIVE_SHA256}"}
    metadata["selection"] = {"rule_files": len(selected), "validated_rules": len(ids), "upstream_rule_files": len(sources), "upstream_rules": upstream_rules, "product_rules": 4, "excluded_path_prefixes": ["apex/"], "required_metadata_category": "security"}
    metadata["provenance_sha256"] = sha((output / "RULE-PROVENANCE.json").read_bytes())
    (output / "PACK-METADATA.json").write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n")
    return metadata



def build_rule_pack(
    archive_path: Path,
    lock_path: Path,
    output_path: Path,
    source_date_epoch: int,
    product_path: Path | None = None,
) -> dict[str, object]:
    if source_date_epoch < 0:
        raise ValueError("source date epoch must be non-negative")
    locked = load_locked_source(lock_path)
    if (locked.revision, locked.digest, locked.size) != (
        REVISION, f"sha256:{ARCHIVE_SHA256}", ARCHIVE_BYTES
    ):
        raise ValueError("lock does not match the reviewed legacy rules source")
    metadata = build_combined_rule_pack(
        archive_path, product_path or Path(__file__).with_name("product-rules.yml"), output_path
    )
    # Retain the existing license location consumed by image-source checks.
    (output_path / "LICENSE").write_bytes((output_path / "LICENSE.upstream").read_bytes())
    for path in sorted(output_path.rglob("*"), reverse=True):
        os.chmod(path, 0o755 if path.is_dir() else 0o644)
        os.utime(path, (source_date_epoch, source_date_epoch), follow_symlinks=False)
    os.chmod(output_path, 0o755)
    os.utime(output_path, (source_date_epoch, source_date_epoch), follow_symlinks=False)
    return metadata


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--lock", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--product", type=Path)
    parser.add_argument("--source-date-epoch", required=True, type=int)
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    try:
        metadata = build_rule_pack(
            args.archive, args.lock, args.output, args.source_date_epoch, args.product
        )
    except (OSError, ValueError, tarfile.TarError) as error:
        print(f"could not build Semgrep rule pack: {error}", file=sys.stderr)
        return 1
    selection = metadata["selection"]
    assert isinstance(selection, dict)
    print(
        f"Built {selection['rule_files']} combined Semgrep configs "
        f"({selection['validated_rules']} rules)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
