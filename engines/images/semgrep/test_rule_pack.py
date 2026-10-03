#!/usr/bin/env python3

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


SEMGREP_DIR = Path(__file__).resolve().parent
ROOT = SEMGREP_DIR.parents[2]
MODULE_SPEC = importlib.util.spec_from_file_location(
    "semgrep_rule_pack", SEMGREP_DIR / "build_rule_pack.py"
)
assert MODULE_SPEC is not None and MODULE_SPEC.loader is not None
RULE_PACK = importlib.util.module_from_spec(MODULE_SPEC)
sys.modules[MODULE_SPEC.name] = RULE_PACK
MODULE_SPEC.loader.exec_module(RULE_PACK)


class RulePackTests(unittest.TestCase):
    def setUp(self) -> None:
        self.archive = (
            ROOT
            / ".engine-cache/offline/semgrep-submodules/tests__semgrep-rules.tar.gz"
        )
        self.lock = SEMGREP_DIR / "submodules.lock"

    def build(self, parent: Path) -> Path:
        output = parent / "pack"
        RULE_PACK.build_rule_pack(self.archive, self.lock, output, 1787250577)
        return output

    def test_pack_is_pinned_broad_and_reproducible(self) -> None:
        with (
            tempfile.TemporaryDirectory() as first_temp,
            tempfile.TemporaryDirectory() as second_temp,
        ):
            first = self.build(Path(first_temp))
            second = self.build(Path(second_temp))
            first_manifest = (first / "RULES.sha256").read_bytes()
            second_manifest = (second / "RULES.sha256").read_bytes()
            self.assertEqual(first_manifest, second_manifest)
            self.assertEqual(len(first_manifest.splitlines()), 1478)
            self.assertEqual(
                hashlib.sha256(first_manifest).hexdigest(),
                "63678fc6790ebdeca2961080095611030b8e51f8b19ac228ee7e2c6862083040",
            )
            metadata = json.loads((first / "PACK-METADATA.json").read_text())
            self.assertEqual(metadata["selection"]["validated_rules"], 1497)
            self.assertEqual(
                metadata["upstream"]["revision"],
                "0f5a85ceab1b82b193d0eaa418784c932d237d68",
            )
            self.assertIn("Commons Clause", (first / "LICENSE").read_text())
            self.assertIn("LGPL 2.1", (first / "LICENSE").read_text())
            self.assertEqual(metadata["upstream_files"], 1477)
            self.assertEqual(metadata["upstream_rules"], 1493)
            self.assertEqual(metadata["product_rules"], 4)
            self.assertEqual((first / "RULES.sha256").stat().st_mtime, 1787250577)
            self.assertIn("# semgrep-rules", (first / "UPSTREAM-README.md").read_text())
            for line in first_manifest.decode("utf-8").splitlines():
                digest, relative = line.split("  ", 1)
                self.assertEqual(
                    hashlib.sha256((first / "rules" / relative).read_bytes()).hexdigest(),
                    digest,
                )

    def test_pack_retains_representative_upstream_security_rules(self) -> None:
        expected = {
            "python/django/security/injection/command/command-injection-os-system.yaml": (
                "python",
                "command-injection-os-system",
            ),
            "javascript/express/security/audit/xss/direct-response-write.yaml": (
                "javascript",
                "direct-response-write",
            ),
            "java/spring/security/audit/spel-injection.yaml": ("java", "spel-injection"),
            "go/lang/security/audit/crypto/math_random.yaml": ("go", "math-random-used"),
            "terraform/aws/security/aws-athena-database-unencrypted.yaml": (
                "hcl",
                "aws-athena-database-unencrypted",
            ),
            "yaml/kubernetes/security/privileged-container.yaml": (
                "yaml",
                "privileged-container",
            ),
            "dockerfile/security/missing-user.yaml": (
                "dockerfile",
                "missing-user",
            ),
        }
        with tempfile.TemporaryDirectory() as temp:
            pack = self.build(Path(temp)) / "rules"
            for relative, (language, rule_id) in expected.items():
                text = (pack / "upstream" / relative).read_text(encoding="utf-8")
                self.assertRegex(text, rf"(?m)^\s*-\s+id:\s*{relative.rsplit('.', 1)[0].replace('/', '.')}.{rule_id}\s*$")
                self.assertIn(language, text)
                self.assertRegex(text, r"(?m)^\s+category:\s*security\s*$")

    def test_pack_excludes_test_and_non_security_yaml(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            rules = self.build(Path(temp)) / "rules"
            relative_paths = [path.relative_to(rules).as_posix() for path in rules.rglob("*")]
            self.assertFalse(any(".test." in path for path in relative_paths))
            self.assertFalse(any(path.startswith(".github/") for path in relative_paths))
            self.assertFalse(any(path.startswith("upstream/apex/") for path in relative_paths))
            self.assertFalse(any(path.startswith("stats/") for path in relative_paths))
            self.assertFalse((rules / "template.yaml").exists())


if __name__ == "__main__":
    unittest.main()
