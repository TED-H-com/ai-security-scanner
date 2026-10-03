#!/usr/bin/env python3
"""Assemble candidate engine source without redistributing whole rule archives.

Run before compilation. The 35 compiler/parser submodules remain intact. The
rule gitlink is replaced with the selected original bytes and exact notices.
This is a local candidate assembly, not a publication or license clearance.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import shutil
import tarfile
from pathlib import Path

MANIFEST_SHA256 = "63678fc6790ebdeca2961080095611030b8e51f8b19ac228ee7e2c6862083040"
PROVENANCE_SHA256 = "a5f8961abe75a57da4c752f39272baa64ac95ca4181e507c070772c54f5c09bf"
EXCLUDED = "java/lang/security/audit/xss/no-direct-response-writer.yaml"


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def assemble(engine: Path, pack: Path, inputs: Path, output: Path, epoch: int) -> None:
    if epoch < 0 or output.exists() or not engine.is_dir():
        raise ValueError("invalid epoch, existing output or missing engine source")
    if digest(pack / "RULES.sha256") != MANIFEST_SHA256:
        raise ValueError("unreviewed rule-pack manifest")
    provenance = json.loads((pack / "RULE-PROVENANCE.json").read_text())
    metadata = json.loads((pack / "PACK-METADATA.json").read_text())
    if digest(pack / "RULE-PROVENANCE.json") != PROVENANCE_SHA256 or metadata["provenance_sha256"] != PROVENANCE_SHA256:
        raise ValueError("provenance differs from pack metadata")
    sources = {
        entry["path"]: entry["source_sha256"]
        for entry in provenance.values() if entry["kind"] == "upstream"
    }
    if len(provenance) != 1497 or len(sources) != 1477 or EXCLUDED in sources:
        raise ValueError("source inventory differs from reviewed selection")
    for relative, expected in sources.items():
        source = pack / "source" / relative
        if not source.resolve().is_relative_to((pack / "source").resolve()):
            raise ValueError("unsafe selected source path")
        if source.is_symlink() or not source.is_file() or digest(source) != expected:
            raise ValueError("selected original source does not match provenance")
    actual = {path.relative_to(pack / "source").as_posix() for path in (pack / "source").rglob("*") if path.is_file()}
    if actual != set(sources):
        raise ValueError("source directory contains uninventoried files")
    rules = engine / "tests/semgrep-rules"
    if rules.exists() and any(rules.iterdir()):
        raise ValueError("rule gitlink must be empty; do not bundle a full rule archive")
    rules.mkdir(parents=True, exist_ok=True)
    shutil.copytree(pack / "source", rules, dirs_exist_ok=True)
    shutil.copyfile(pack / "LICENSE.upstream", rules / "LICENSE")
    shutil.copyfile(pack / "UPSTREAM-README.md", rules / "README.md")
    build_inputs = engine / "ai-security-scanner-build"
    if build_inputs.exists():
        raise ValueError("candidate source inputs already exist")
    shutil.copytree(inputs, build_inputs)
    shutil.copytree(pack, build_inputs / "rule-pack")
    (build_inputs / "SOURCE-PROFILE.json").write_text(json.dumps({
        "local_candidate_only": True,
        "engine_revision": "a0c13f304151e531c7e7c00838076211a07a790c",
        "rules_gitlink_override": metadata["upstream_revision"],
        "original_upstream_files": len(sources),
        "excluded": metadata["excluded"],
        "rules_manifest_sha256": MANIFEST_SHA256,
        "note": "Compiler/parser sources are retained; only selected original rule files are attached, not the full rules gitlink archive.",
    }, indent=2, sort_keys=True) + "\n")
    # Python's gzip/tar writer avoids reliance on Alpine BusyBox tar --sort.
    # Normalize every header while preserving the upstream file/symlink bytes.
    engine = engine.resolve()
    paths = [engine, *sorted(engine.rglob("*"))]
    total = 0
    for path in paths:
        if path.is_symlink():
            if not path.resolve().is_relative_to(engine):
                raise ValueError("source symlink escapes the attached tree")
        elif path.is_file():
            total += path.stat().st_size
        elif not path.is_dir():
            raise ValueError("non-regular source member")
    if total > 1024 * 1024 * 1024:
        raise ValueError("source attachment exceeds size bound")
    with output.open("xb") as raw, gzip.GzipFile(filename="", fileobj=raw, mode="wb", mtime=epoch) as compressed, tarfile.open(fileobj=compressed, mode="w|", format=tarfile.PAX_FORMAT) as archive:
        for path in paths:
            name = "semgrep" if path == engine else "semgrep/" + path.relative_to(engine).as_posix()
            info = archive.gettarinfo(str(path), arcname=name)
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            info.mtime = epoch
            info.pax_headers = {}
            if info.isreg():
                info.mode = 0o755 if info.mode & 0o111 else 0o644
                with path.open("rb") as handle:
                    archive.addfile(info, handle)
            else:
                info.mode = 0o755 if info.isdir() else 0o777
                archive.addfile(info)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("engine", "pack", "inputs", "output"):
        parser.add_argument("--" + name, required=True, type=Path)
    parser.add_argument("--source-date-epoch", required=True, type=int)
    args = parser.parse_args()
    assemble(args.engine, args.pack, args.inputs, args.output, args.source_date_epoch)
