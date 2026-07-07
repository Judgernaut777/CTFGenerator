from __future__ import annotations

import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from ctf_generator import __version__
from ctf_generator.generator import (
    create_challenge,
    create_challenge_from_cve,
    seed_to_int,
)
from ctf_generator.spec_generator import default_spec
from ctf_generator.models import (
    SPEC_VERSION,
    ChallengeSpec,
    ResponseSpec,
    ScenarioSpec,
    TriggerSpec,
)
from ctf_generator.cve_source import SnapshotCveSource
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

            # The solver is a single adaptive script that ships BOTH per-instance
            # techniques (it is byte-identical across classes), so it solves any
            # generated instance and any sibling.
            solver = (output / "private/solver.py").read_text(encoding="utf-8")
            self.assertIn("_try_field_trust", solver)
            self.assertIn("_try_predictable_job_id", solver)

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


class SeedToIntAliasTests(unittest.TestCase):
    def test_seed_to_int_is_deterministic_and_public(self) -> None:
        self.assertEqual(seed_to_int("alpha"), seed_to_int("alpha"))
        self.assertNotEqual(seed_to_int("alpha"), seed_to_int("beta"))
        self.assertIsInstance(seed_to_int("anything"), int)


class CveDrivenChallengeTests(unittest.TestCase):
    def test_create_challenge_from_cve_renders_valid_challenge(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "cve-challenge"
            create_challenge_from_cve(
                output_dir=output,
                cve_id="CVE-2021-44228",
                base_seed="cve-seed",
            )

            report = validate_challenge(output)
            self.assertEqual(report.errors, [])

            spec_text = (output / "challenge.yaml").read_text(encoding="utf-8")
            self.assertIn("cve_refs", spec_text)
            self.assertIn("CVE-2021-44228", spec_text)
            self.assertIn("cve_content_hash", spec_text)

    def test_create_challenge_from_cve_is_seed_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            first = Path(temp_dir) / "first"
            second = Path(temp_dir) / "second"
            create_challenge_from_cve(
                output_dir=first, cve_id="CVE-2021-44228", base_seed="stable-cve"
            )
            create_challenge_from_cve(
                output_dir=second, cve_id="CVE-2021-44228", base_seed="stable-cve"
            )

            self.assertEqual(
                (first / "challenge.yaml").read_text(encoding="utf-8"),
                (second / "challenge.yaml").read_text(encoding="utf-8"),
            )
            self.assertEqual(
                (first / "private/variant.json").read_text(encoding="utf-8"),
                (second / "private/variant.json").read_text(encoding="utf-8"),
            )

    def test_create_challenge_from_cve_unknown_id_raises(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "missing-cve"
            with self.assertRaises(ValueError):
                create_challenge_from_cve(
                    output_dir=output,
                    cve_id="CVE-0000-00000",
                    base_seed="cve-seed",
                )

    def test_create_challenge_from_cve_accepts_injected_source(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "injected-source"
            source = SnapshotCveSource()
            create_challenge_from_cve(
                output_dir=output,
                cve_id="CVE-2017-5638",
                base_seed="cve-seed",
                source=source,
            )
            report = validate_challenge(output)
            self.assertEqual(report.errors, [])


class NonCveOutputUnchangedTests(unittest.TestCase):
    """cve_record must be a passthrough-only param: non-CVE seeding/output is untouched."""

    def test_create_challenge_without_cve_record_unaffected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            plain = Path(temp_dir) / "plain"
            create_challenge(
                output_dir=plain,
                seed="parity-seed",
                title="Invoice Drift",
                difficulty="medium",
                family="web_business_logic_tenant_export",
            )
            explicit_none = Path(temp_dir) / "explicit-none"
            create_challenge(
                output_dir=explicit_none,
                seed="parity-seed",
                title="Invoice Drift",
                difficulty="medium",
                family="web_business_logic_tenant_export",
                cve_record=None,
            )

            self.assertEqual(
                (plain / "challenge.yaml").read_text(encoding="utf-8"),
                (explicit_none / "challenge.yaml").read_text(encoding="utf-8"),
            )
            self.assertEqual(
                (plain / "private/variant.json").read_text(encoding="utf-8"),
                (explicit_none / "private/variant.json").read_text(encoding="utf-8"),
            )


class ScenarioTimelineOutputTests(unittest.TestCase):
    def _scenario_spec(self, seed: str) -> ChallengeSpec:
        return ChallengeSpec(
            title="Live Incident",
            category="web",
            difficulty="medium",
            family="web_business_logic_tenant_export",
            seed=seed,
            learning_objectives=["Respond to a live incident"],
            checkpoints=["contain the breach"],
            mode="scenario",
            scenario=ScenarioSpec(
                enabled=True,
                triggers=[
                    TriggerSpec(
                        trigger_id="t1", description="attacker probes", condition="time:+1s"
                    )
                ],
                responses=[
                    ResponseSpec(
                        response_id="r1", description="rotate creds", action="rotate_credential"
                    )
                ],
            ),
        )

    def test_scenario_enabled_writes_timeline_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "scenario-challenge"
            spec = self._scenario_spec("scenario-seed")
            create_challenge(
                output_dir=output,
                seed=spec.seed,
                title=spec.title,
                difficulty=spec.difficulty,
                family=spec.family,
                spec=spec,
            )

            timeline_path = output / "private/scenario_timeline.json"
            self.assertTrue(timeline_path.exists())
            payload = json.loads(timeline_path.read_text(encoding="utf-8"))
            self.assertEqual(payload, spec.scenario.to_mapping())

    def test_scenario_disabled_does_not_write_timeline_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "no-scenario-challenge"
            # tenant_export ships an enabled default scenario, so disable it
            # explicitly to exercise the scenario-off generation path.
            base = default_spec(
                seed="no-scenario-seed",
                title="Invoice Drift",
                difficulty="medium",
                family="web_business_logic_tenant_export",
            )
            create_challenge(
                output_dir=output,
                seed="no-scenario-seed",
                title="Invoice Drift",
                difficulty="medium",
                family="web_business_logic_tenant_export",
                spec=replace(base, scenario=ScenarioSpec()),
            )

            timeline_path = output / "private/scenario_timeline.json"
            self.assertFalse(timeline_path.exists())

    def test_scenario_timeline_is_seed_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            first = Path(temp_dir) / "first"
            second = Path(temp_dir) / "second"
            create_challenge(
                output_dir=first,
                seed="tl-seed",
                title="Live Incident",
                difficulty="medium",
                family="web_business_logic_tenant_export",
                spec=self._scenario_spec("tl-seed"),
            )
            create_challenge(
                output_dir=second,
                seed="tl-seed",
                title="Live Incident",
                difficulty="medium",
                family="web_business_logic_tenant_export",
                spec=self._scenario_spec("tl-seed"),
            )

            self.assertEqual(
                (first / "private/scenario_timeline.json").read_text(encoding="utf-8"),
                (second / "private/scenario_timeline.json").read_text(encoding="utf-8"),
            )


if __name__ == "__main__":
    unittest.main()
