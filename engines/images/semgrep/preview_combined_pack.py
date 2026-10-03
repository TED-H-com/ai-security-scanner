#!/usr/bin/env python3
"""Compatibility entrypoint for the local-only combination experiment."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
from build_rule_pack import (
    ARCHIVE_BYTES, ARCHIVE_SHA256, EXCLUDED, EXCLUDED_SHA256, ID_LINE,
    LICENSE_SHA256, NOTICE, PRODUCT_IDS, PRODUCT_SHA256, REVISION,
    build_combined_rule_pack as build, sha,
)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--product", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(build(args.archive, args.product, args.output), indent=2))
