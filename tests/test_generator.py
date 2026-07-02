from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ctf_generator.generator import create_challenge
from ctf_generator.validator import validate_challenge


class GeneratorTests(unittest.TestCase):
    def test_create_challenge_outputs_required_files(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "invoice-drift"
            create_challenge(
                output_dir=output,
                seed="test-seed",
                title="Invoice Drift",
                difficulty="medium",
                family="web_business_logic_tenant_export",
            )

            report = validate_challenge(output)
            self.assertEqual(report.errors, [])

    def test_create_challenge_refuses_existing_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "existing"
            output.mkdir()

            with self.assertRaises(FileExistsError):
                create_challenge(
                    output_dir=output,
                    seed="test-seed",
                    title="Invoice Drift",
                    difficulty="medium",
                    family="web_business_logic_tenant_export",
                )


if __name__ == "__main__":
    unittest.main()
