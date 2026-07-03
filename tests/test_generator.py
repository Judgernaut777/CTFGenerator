from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from ctf_generator import __version__
from ctf_generator.generator import create_challenge
from ctf_generator.models import SPEC_VERSION
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

            compose = (output / "docker-compose.yml").read_text(encoding="utf-8")
            self.assertIn("frontend:", compose)
            self.assertIn('"8080:8080"', compose)

            app = (output / "services/api/app.py").read_text(encoding="utf-8")
            self.assertLess(
                app.index('redis_client.hset(f"job:{job_id}"'),
                app.index('redis_client.rpush("export_jobs"'),
            )

            solver = (output / "private/solver.py").read_text(encoding="utf-8")
            self.assertIn("Delayed invoice", solver)
            self.assertIn("may still send", solver)

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


class MetaBlockTests(unittest.TestCase):
    def _create(self, temp_dir: str, seed: str = "meta-seed") -> Path:
        output = Path(temp_dir) / "invoice-drift"
        create_challenge(
            output_dir=output,
            seed=seed,
            title="Invoice Drift",
            difficulty="medium",
            family="web_business_logic_tenant_export",
            force=True,
        )
        return output

    def test_variant_json_carries_meta_block(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output = self._create(temp_dir, seed="meta-seed")
            variant = json.loads(
                (output / "private/variant.json").read_text(encoding="utf-8")
            )
            meta = variant["meta"]
            self.assertEqual(meta["generator_version"], __version__)
            self.assertEqual(meta["spec_version"], SPEC_VERSION)
            self.assertEqual(meta["family"], "web_business_logic_tenant_export")
            self.assertEqual(meta["seed"], "meta-seed")

    def test_challenge_yaml_carries_meta_block(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output = self._create(temp_dir, seed="meta-seed")
            spec = (output / "challenge.yaml").read_text(encoding="utf-8")
            self.assertIn("meta:", spec)
            self.assertIn(f'generator_version: "{__version__}"', spec)
            self.assertIn(f'spec_version: "{SPEC_VERSION}"', spec)
            self.assertIn('seed: "meta-seed"', spec)
            self.assertIn(
                'family: "web_business_logic_tenant_export"', spec
            )

    def test_meta_block_is_seed_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            first = self._create(temp_dir, seed="stable")
            first_yaml = (first / "challenge.yaml").read_text(encoding="utf-8")
            first_variant = (first / "private/variant.json").read_text(
                encoding="utf-8"
            )

            second = self._create(temp_dir, seed="stable")
            second_yaml = (second / "challenge.yaml").read_text(encoding="utf-8")
            second_variant = (second / "private/variant.json").read_text(
                encoding="utf-8"
            )

            self.assertEqual(first_yaml, second_yaml)
            self.assertEqual(first_variant, second_variant)

    def test_meta_survives_static_validation(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output = self._create(temp_dir, seed="valid-seed")
            report = validate_challenge(output)
            self.assertEqual(report.errors, [])


if __name__ == "__main__":
    unittest.main()
