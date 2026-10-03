#!/usr/bin/env python3
"""Local experiment only: build a traceable legacy + product Semgrep pack.

This does not change the production Dockerfile, launcher, lock, catalog or tag.
Detection bodies remain upstream bytes; only file-qualified IDs and an explicit
modification notice are added. Original selected files are retained separately.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import tarfile
from pathlib import Path, PurePosixPath

from build_rule_pack import (
    is_selected_rule_path,
    safe_relative_member,
    validate_rule_text,
)

REVISION = "0f5a85ceab1b82b193d0eaa418784c932d237d68"
ARCHIVE_SHA256 = "a6bb2ee1a261da82a1263c1b32ad6f4535628742192c0bb1f68f13343c31bbcc"
ARCHIVE_BYTES = 1148011
LICENSE_SHA256 = "9600f388f17cb800a7a0ba8b55bc15c5b0ed047de8517f2d5e533becee9d0a18"
EXCLUDED = "java/lang/security/audit/xss/no-direct-response-writer.yaml"
EXCLUDED_SHA256 = "44f00a2b33815116facd15a58b4d360418c7940c2cbdde671856f042d4f5498f"
PRODUCT_SHA256 = "2081a62359682db1ddd15eda7eed1f3931975870cef8f8dab7120ba86fe2e5f3"
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


def sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def build(archive: Path, product: Path, output: Path) -> dict:
    if output.exists():
        raise ValueError("output already exists")
    if archive.stat().st_size != ARCHIVE_BYTES or sha(archive.read_bytes()) != ARCHIVE_SHA256:
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
    (output / "LICENSE.product").write_bytes((product.parent / "product-LICENSE").read_bytes())
    (output / "UPSTREAM-README.md").write_bytes(readme_bytes)
    (output / "RULE-PROVENANCE.json").write_text(json.dumps(records, indent=2, sort_keys=True) + "\n")
    metadata = {"local_experiment_only": True, "upstream_revision": REVISION, "archive_sha256": ARCHIVE_SHA256, "upstream_files": len(sources), "upstream_rules": upstream_rules, "product_rules": 4, "combined_files": len(selected), "combined_rules": len(ids), "manifest_sha256": sha(manifest), "excluded": excluded, "license_note": "LGPL plus Commons Clause remains applicable to upstream rules; this experiment does not approve publication or commercial use."}
    (output / "PACK-METADATA.json").write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n")
    return metadata


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--product", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(build(args.archive, args.product, args.output), indent=2))
