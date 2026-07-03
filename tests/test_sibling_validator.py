from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ctf_generator.sibling_validator import validate_siblings


class SiblingValidatorTests(unittest.TestCase):
    def test_sibling_validator_generates_distinct_variants(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "siblings"
            report = validate_siblings(output_dir=output, seed="test-seed")

            self.assertEqual(report.errors, [])
            self.assertTrue((output / "sibling-a" / "private" / "variant.json").exists())
            self.assertTrue((output / "sibling-b" / "private" / "variant.json").exists())
            self.assertGreaterEqual(len(report.changed_tokens), 4)

    def test_sibling_validator_refuses_existing_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "siblings"
            output.mkdir()
            report = validate_siblings(output_dir=output, seed="test-seed")

            self.assertNotEqual(report.errors, [])


if __name__ == "__main__":
    unittest.main()
