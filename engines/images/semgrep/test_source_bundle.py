"""Source-attachment checks use only synthetic engine files and pinned rules."""
import hashlib
import json
import tarfile
import tempfile
import unittest
from pathlib import Path

from build_rule_pack import build_rule_pack
from prepare_source_bundle import assemble

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]


class SourceBundleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.pack = self.root / "pack"
        build_rule_pack(ROOT / ".engine-cache/offline/semgrep-submodules/tests__semgrep-rules.tar.gz", HERE / "submodules.lock", self.pack, 1787250577)
        self.inputs = self.root / "inputs"
        self.inputs.mkdir()
        (self.inputs / "build-notes").write_text("synthetic input\n")

    def engine(self, name):
        engine = self.root / name
        (engine / "tests/semgrep-rules").mkdir(parents=True)
        (engine / "compiler-source.c").write_text("/* synthetic compiler sentinel */\n")
        return engine

    def test_reproducible_bundle_retains_compiler_and_only_selected_original_rules(self):
        hashes = []
        for name in ("one", "two"):
            output = self.root / (name + ".tar.gz")
            assemble(self.engine(name), self.pack, self.inputs, output, 1787250577)
            hashes.append(hashlib.sha256(output.read_bytes()).hexdigest())
            with tarfile.open(output) as archive:
                names = archive.getnames()
                self.assertIn("semgrep/compiler-source.c", names)
                originals = [n for n in names if n.startswith("semgrep/tests/semgrep-rules/") and n.endswith((".yaml", ".yml"))]
                self.assertEqual(len(originals), 1477)
                self.assertFalse(any("no-direct-response-writer.yaml" in n for n in names))
                self.assertFalse(any("semgrep-rules" in n and n.endswith(".tar.gz") for n in names))
                self.assertIn(b"Commons Clause", archive.extractfile("semgrep/tests/semgrep-rules/LICENSE").read())
                profile = json.load(archive.extractfile("semgrep/ai-security-scanner-build/SOURCE-PROFILE.json"))
                self.assertEqual(profile["original_upstream_files"], 1477)
                self.assertEqual(archive.getmember("semgrep/compiler-source.c").mtime, 1787250577)
        self.assertEqual(hashes[0], hashes[1])

    def test_changed_original_rule_is_rejected_before_attaching_source(self):
        rule = next((self.pack / "source").rglob("*.yaml"))
        rule.write_bytes(rule.read_bytes() + b"# changed\n")
        with self.assertRaisesRegex(ValueError, "does not match provenance"):
            assemble(self.engine("changed"), self.pack, self.inputs, self.root / "bad.tar.gz", 1787250577)
        self.assertFalse((self.root / "bad.tar.gz").exists())

    def test_full_rule_gitlink_cannot_be_accidentally_attached(self):
        engine = self.engine("full")
        (engine / "tests/semgrep-rules/unselected.yaml").write_text("not selected\n")
        with self.assertRaisesRegex(ValueError, "must be empty"):
            assemble(engine, self.pack, self.inputs, self.root / "bad.tar.gz", 1787250577)
        self.assertFalse((self.root / "bad.tar.gz").exists())


if __name__ == "__main__":
    unittest.main()
