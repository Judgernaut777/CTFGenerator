from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ctf_generator.generator import create_challenge
from ctf_generator.score import score_challenge


class ScoreTests(unittest.TestCase):
    def _generate(self, temp_dir: str) -> Path:
        output = Path(temp_dir) / "challenge"
        create_challenge(
            output_dir=output,
            seed="score-seed",
            title="Invoice Drift",
            difficulty="medium",
            family="web_business_logic_tenant_export",
        )
        return output

    def test_generated_challenge_scores_strong(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            report = score_challenge(self._generate(temp_dir))

            self.assertEqual(report.errors, [])
            self.assertEqual(len(report.dimensions), 5)
            self.assertAlmostEqual(
                sum(d.weight for d in report.dimensions), 1.0, places=6
            )
            self.assertGreaterEqual(report.total, 85.0)
            self.assertEqual(report.band, "strong")
            self.assertEqual(report.warnings, [])

    def test_dimensions_are_derived_from_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output = self._generate(temp_dir)
            report = score_challenge(output)
            names = {d.name for d in report.dimensions}
            self.assertEqual(
                names,
                {
                    "variant_uniqueness",
                    "statefulness",
                    "solver_depth",
                    "live_interaction",
                    "scanner_resistance",
                },
            )

    def test_missing_variant_produces_error(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output = self._generate(temp_dir)
            (output / "private/variant.json").unlink()
            report = score_challenge(output)
            self.assertTrue(report.errors)

    def test_statefulness_drops_without_worker(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output = self._generate(temp_dir)
            compose = output / "docker-compose.yml"
            compose.write_text(
                compose.read_text(encoding="utf-8").replace("worker:", "disabled:"),
                encoding="utf-8",
            )
            report = score_challenge(output)
            statefulness = next(d for d in report.dimensions if d.name == "statefulness")
            self.assertLess(statefulness.score, 100.0)
            self.assertTrue(
                any("hidden_sibling_validation" in w for w in report.warnings)
            )


if __name__ == "__main__":
    unittest.main()
