"""Checks for the local combination experiment; no downloads or scanners."""
import os
import tempfile
import unittest
from pathlib import Path

import preview_combined_pack as preview


class CombinedPreviewTests(unittest.TestCase):
    archive = Path(os.environ["SEMGREP_LEGACY_ARCHIVE"])
    product = Path(__file__).with_name("product-rules.yml")

    def test_reproducible_pack_keeps_original_ids_and_detector_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            first, second = Path(tmp) / "first", Path(tmp) / "second"
            metadata = preview.build(self.archive, self.product, first)
            preview.build(self.archive, self.product, second)
            self.assertEqual((first / "RULES.sha256").read_bytes(), (second / "RULES.sha256").read_bytes())
            self.assertEqual(metadata["combined_rules"], 1497)
            self.assertEqual(metadata["combined_files"], 1478)
            self.assertFalse((first / "source" / preview.EXCLUDED).exists())
            self.assertFalse((first / "rules/upstream" / preview.EXCLUDED).exists())
            import json
            provenance = json.loads((first / "RULE-PROVENANCE.json").read_text())
            self.assertEqual(len(provenance), 1497)
            for source in (first / "source").rglob("*"):
                if not source.is_file():
                    continue
                relative = source.relative_to(first / "source")
                qualified = (first / "rules/upstream" / relative).read_bytes()
                self.assertTrue(qualified.startswith(preview.NOTICE.encode()))
                restored = preview.ID_LINE.sub(
                    lambda m: m.group(1) + provenance[m.group(2)]["original_id"] + m.group(3),
                    qualified[len(preview.NOTICE.encode()):].decode(),
                )
                self.assertEqual(restored.encode(), source.read_bytes())
            for line in (first / "RULES.sha256").read_text().splitlines():
                digest, relative = line.split("  ", 1)
                self.assertEqual(preview.sha((first / "rules" / relative).read_bytes()), digest)
            self.assertEqual((first / "rules/product/rules.yml").read_bytes(), self.product.read_bytes())

    def test_unpinned_archive_is_rejected_before_creating_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / "bad.tar.gz"
            bad.write_bytes(b"not the reviewed archive")
            output = Path(tmp) / "pack"
            with self.assertRaisesRegex(ValueError, "archive does not match"):
                preview.build(bad, self.product, output)
            self.assertFalse(output.exists())

    def test_changed_product_detector_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            changed = Path(tmp) / "product-rules.yml"
            changed.write_bytes(self.product.read_bytes().replace(b"severity: ERROR", b"severity: WARNING", 1))
            with self.assertRaisesRegex(ValueError, "product rules differ"):
                preview.build(self.archive, changed, Path(tmp) / "pack")

    def test_existing_output_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "pack"
            output.mkdir()
            sentinel = output / "existing"
            sentinel.write_text("keep")
            with self.assertRaisesRegex(ValueError, "output already exists"):
                preview.build(self.archive, self.product, output)
            self.assertEqual(sentinel.read_text(), "keep")


if __name__ == "__main__":
    unittest.main()
