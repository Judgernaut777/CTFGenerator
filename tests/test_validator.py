from __future__ import annotations

import json
import random
import tempfile
import unittest
from pathlib import Path

from ctf_generator import families
from ctf_generator.families import Family
from ctf_generator.generator import create_challenge
from ctf_generator.models import ChallengeSpec, ResponseSpec, ScenarioSpec, TriggerSpec
from ctf_generator.validator import (
    REQUIRED_FILES,
    ValidationReport,
    _resolve_family,
    _scenario_enabled,
    validate_challenge,
)
from ctf_generator.yaml_writer import dump_yaml


def _spec(**overrides: object) -> ChallengeSpec:
    defaults: dict[str, object] = dict(
        title="Invoice Drift",
        category="web",
        difficulty="medium",
        family="web_business_logic_tenant_export",
        seed="abc123",
        learning_objectives=["obj-1"],
        checkpoints=["step-1", "step-2", "step-3", "step-4", "step-5"],
    )
    defaults.update(overrides)
    return ChallengeSpec(**defaults)  # type: ignore[arg-type]


class RegistrySnapshotMixin:
    """Snapshot/restore the module-global family registry around a test.

    Mirrors the pattern in test_families.py so scratch families registered
    here never leak into other test modules.
    """

    def setUp(self) -> None:  # type: ignore[override]
        self._saved = dict(families._REGISTRY)
        self.addCleanup(self._restore)

    def _restore(self) -> None:
        families._REGISTRY.clear()
        families._REGISTRY.update(self._saved)


def _scratch_render(spec: ChallengeSpec, rng: random.Random, cve_record=None) -> dict[str, str]:
    return {
        "flag.txt": f"FLAG{{{spec.seed}}}",
        "docker-compose.yml": "services:\n  solo:\n    image: busybox\n",
    }


class TenantExportBackCompatTests(unittest.TestCase):
    """The existing, family-registered tenant_export challenge must still
    validate cleanly end to end -- this is the byte-for-byte backwards
    compatibility guarantee for the family-aware validator."""

    def test_generated_tenant_export_challenge_validates_cleanly(self) -> None:
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

    def test_required_files_alias_matches_family(self) -> None:
        fam = families.get("web_business_logic_tenant_export")
        self.assertEqual(fam.required_files, tuple(REQUIRED_FILES))


class ResolveFamilyTests(RegistrySnapshotMixin, unittest.TestCase):
    def test_resolves_registered_family_from_spec_text(self) -> None:
        spec = _spec()
        text = dump_yaml(spec.to_mapping())
        fam = _resolve_family(text)
        self.assertIsNotNone(fam)
        self.assertEqual(fam.name, "web_business_logic_tenant_export")

    def test_returns_none_for_missing_text(self) -> None:
        self.assertIsNone(_resolve_family(None))
        self.assertIsNone(_resolve_family(""))

    def test_returns_none_for_unregistered_family_name(self) -> None:
        spec = _spec(family="totally_unregistered_family")
        text = dump_yaml(spec.to_mapping())
        self.assertIsNone(_resolve_family(text))

    def test_returns_none_for_missing_family_field(self) -> None:
        text = "title: \"No family here\"\n"
        self.assertIsNone(_resolve_family(text))


class FamilyAwareValidationTests(RegistrySnapshotMixin, unittest.TestCase):
    def test_validates_against_resolved_familys_required_files(self) -> None:
        families.register(
            Family(
                name="scratch_minimal",
                category="crypto",
                modes=("red",),
                render=_scratch_render,
                required_files=("challenge.yaml", "flag.txt"),
                compose_service_markers=("solo:",),
            )
        )
        spec = _spec(family="scratch_minimal")
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "scratch"
            output.mkdir()
            (output / "challenge.yaml").write_text(
                dump_yaml(spec.to_mapping()), encoding="utf-8"
            )
            (output / "flag.txt").write_text("FLAG{abc123}", encoding="utf-8")
            (output / "docker-compose.yml").write_text(
                "services:\n  solo:\n    image: busybox\n", encoding="utf-8"
            )

            report = validate_challenge(output)
            self.assertEqual(report.errors, [])

    def test_missing_family_specific_required_file_is_an_error(self) -> None:
        families.register(
            Family(
                name="scratch_minimal",
                category="crypto",
                modes=("red",),
                render=_scratch_render,
                required_files=("challenge.yaml", "flag.txt"),
            )
        )
        spec = _spec(family="scratch_minimal")
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "scratch"
            output.mkdir()
            (output / "challenge.yaml").write_text(
                dump_yaml(spec.to_mapping()), encoding="utf-8"
            )
            # flag.txt deliberately omitted.

            report = validate_challenge(output)
            self.assertIn("missing required file: flag.txt", report.errors)
            # And it must NOT demand tenant_export's unrelated scaffolding
            # (e.g. services/api/app.py) for a family that doesn't declare it.
            self.assertFalse(
                any("services/api/app.py" in err for err in report.errors)
            )

    def test_missing_compose_service_marker_is_an_error(self) -> None:
        families.register(
            Family(
                name="scratch_minimal",
                category="crypto",
                modes=("red",),
                render=_scratch_render,
                required_files=("challenge.yaml",),
                compose_service_markers=("solo:", "sidecar:"),
            )
        )
        spec = _spec(family="scratch_minimal")
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "scratch"
            output.mkdir()
            (output / "challenge.yaml").write_text(
                dump_yaml(spec.to_mapping()), encoding="utf-8"
            )
            (output / "docker-compose.yml").write_text(
                "services:\n  solo:\n    image: busybox\n", encoding="utf-8"
            )

            report = validate_challenge(output)
            self.assertTrue(
                any("sidecar:" in err for err in report.errors), report.errors
            )


class GenericFallbackTests(unittest.TestCase):
    """When the family can't be resolved, validation must fall back to a
    minimal generic check rather than crashing or demanding tenant_export's
    full file layout."""

    def test_unresolvable_family_falls_back_to_minimal_check(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "unknown-family"
            output.mkdir()
            (output / "challenge.yaml").write_text(
                'title: "Mystery"\nfamily: "not_a_registered_family"\n',
                encoding="utf-8",
            )

            report = validate_challenge(output)
            self.assertEqual(report.errors, [])

    def test_missing_challenge_yaml_is_a_hard_error(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "empty"
            output.mkdir()

            report = validate_challenge(output)
            self.assertIn("missing required file: challenge.yaml", report.errors)

    def test_empty_challenge_yaml_is_a_hard_error(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "empty-spec"
            output.mkdir()
            (output / "challenge.yaml").write_text("", encoding="utf-8")

            report = validate_challenge(output)
            self.assertIn("required file is empty: challenge.yaml", report.errors)

    def test_unparseable_challenge_yaml_is_a_hard_error(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "garbage-spec"
            output.mkdir()
            (output / "challenge.yaml").write_text(
                "not yaml at all just words\n", encoding="utf-8"
            )

            report = validate_challenge(output)
            self.assertTrue(
                any("does not look like valid YAML" in err for err in report.errors)
            )

    def test_nonexistent_path_still_reports_error(self) -> None:
        report = validate_challenge(Path("/nonexistent/does-not-exist"))
        self.assertEqual(len(report.errors), 1)
        self.assertIn("does not exist", report.errors[0])

    def test_path_that_is_a_file_reports_error(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "a-file"
            path.write_text("not a directory", encoding="utf-8")
            report = validate_challenge(path)
            self.assertEqual(report.errors, ["%s is not a directory" % path])


class ScenarioSoftCheckTests(unittest.TestCase):
    def test_scenario_enabled_parses_true(self) -> None:
        spec = _spec(
            mode="scenario",
            scenario=ScenarioSpec(
                enabled=True,
                triggers=[TriggerSpec(trigger_id="t1", condition="time:+10s")],
                responses=[ResponseSpec(response_id="r1", action="reveal_hint")],
            ),
        )
        text = dump_yaml(spec.to_mapping())
        self.assertTrue(_scenario_enabled(text))

    def test_scenario_enabled_false_by_default(self) -> None:
        text = dump_yaml(_spec().to_mapping())
        self.assertFalse(_scenario_enabled(text))

    def test_scenario_missing_timeline_is_a_warning_not_an_error(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "scenario-challenge"
            create_challenge(
                output_dir=output,
                seed="scenario-seed",
                title="Timed Heist",
                difficulty="medium",
                family="web_business_logic_tenant_export",
                spec=_spec(
                    seed="scenario-seed",
                    mode="scenario",
                    scenario=ScenarioSpec(
                        enabled=True,
                        triggers=[TriggerSpec(trigger_id="t1", condition="time:+10s")],
                        responses=[ResponseSpec(response_id="r1", action="reveal_hint")],
                    ),
                ),
            )
            # generator.py writes the timeline when scenario.enabled; delete
            # it to exercise the "declared but missing" path.
            timeline = output / "private/scenario_timeline.json"
            self.assertTrue(timeline.exists())
            timeline.unlink()

            report = validate_challenge(output)
            self.assertEqual(report.errors, [])
            self.assertTrue(
                any("scenario_timeline.json" in w and "missing" in w for w in report.warnings)
            )

    def test_scenario_with_valid_timeline_has_no_warning(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "scenario-challenge"
            create_challenge(
                output_dir=output,
                seed="scenario-seed-2",
                title="Timed Heist",
                difficulty="medium",
                family="web_business_logic_tenant_export",
                spec=_spec(
                    seed="scenario-seed-2",
                    mode="scenario",
                    scenario=ScenarioSpec(
                        enabled=True,
                        triggers=[TriggerSpec(trigger_id="t1", condition="time:+10s")],
                        responses=[ResponseSpec(response_id="r1", action="reveal_hint")],
                    ),
                ),
            )

            report = validate_challenge(output)
            self.assertEqual(report.errors, [])
            self.assertFalse(
                any("scenario_timeline.json" in w for w in report.warnings)
            )

    def test_scenario_with_invalid_json_timeline_warns(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "scenario-challenge"
            create_challenge(
                output_dir=output,
                seed="scenario-seed-3",
                title="Timed Heist",
                difficulty="medium",
                family="web_business_logic_tenant_export",
                spec=_spec(
                    seed="scenario-seed-3",
                    mode="scenario",
                    scenario=ScenarioSpec(
                        enabled=True,
                        triggers=[TriggerSpec(trigger_id="t1", condition="time:+10s")],
                        responses=[ResponseSpec(response_id="r1", action="reveal_hint")],
                    ),
                ),
            )
            timeline = output / "private/scenario_timeline.json"
            timeline.write_text("{not valid json", encoding="utf-8")

            report = validate_challenge(output)
            self.assertEqual(report.errors, [])
            self.assertTrue(
                any(
                    "scenario_timeline.json" in w and "not valid JSON" in w
                    for w in report.warnings
                )
            )

    def test_non_scenario_challenge_has_no_scenario_warning(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "invoice-drift"
            create_challenge(
                output_dir=output,
                seed="plain-seed",
                title="Invoice Drift",
                difficulty="medium",
                family="web_business_logic_tenant_export",
            )
            self.assertFalse((output / "private/scenario_timeline.json").exists())

            report = validate_challenge(output)
            self.assertEqual(report.errors, [])
            self.assertEqual(report.warnings, [])


class ValidationReportShapeTests(unittest.TestCase):
    def test_default_report_has_empty_lists(self) -> None:
        report = ValidationReport()
        self.assertEqual(report.errors, [])
        self.assertEqual(report.warnings, [])


if __name__ == "__main__":
    unittest.main()
