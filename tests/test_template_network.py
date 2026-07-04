from __future__ import annotations

import random
import unittest

from ctf_generator.cve_source import CveRecord
from ctf_generator.models import ChallengeSpec
from ctf_generator.templates import network


def _spec(**overrides: object) -> ChallengeSpec:
    defaults = dict(
        title="Edge Diagnostics Pivot",
        category="network",
        difficulty="medium",
        family="network_lateral_pivot",
        seed="net-seed-1",
        learning_objectives=["obj-1", "obj-2"],
        checkpoints=["step-1", "step-2", "step-3", "step-4", "step-5"],
    )
    defaults.update(overrides)
    return ChallengeSpec(**defaults)  # type: ignore[arg-type]


def _cve_record() -> CveRecord:
    return CveRecord(
        cve_id="CVE-2099-00001",
        published="2099-01-01",
        cvss_version="3.1",
        cvss_score=8.8,
        cvss_severity="HIGH",
        cwe_ids=["CWE-798"],
        category="network",
        affected_products=["Example Edge Gateway"],
        description="Example edge gateway ships with unrotated default administrative credentials.",
        references=["https://example.invalid/advisory"],
    )


class ModuleInterfaceTests(unittest.TestCase):
    def test_module_constants(self) -> None:
        self.assertEqual(network.FAMILY_NAME, "network_lateral_pivot")
        self.assertEqual(network.CATEGORY, "network")
        self.assertEqual(network.MODES, ("red", "purple"))
        self.assertEqual(network.DIFFICULTIES, ("easy", "medium", "hard"))
        self.assertTrue(network.CVE_DRIVEN)
        self.assertTrue(network.LLM_BRIEF)
        self.assertIn("edge:", network.COMPOSE_MARKERS)
        self.assertIn("internal:", network.COMPOSE_MARKERS)
        self.assertIn("challenge.yaml", network.REQUIRED_FILES)
        for key in ("has_worker", "has_queue", "live_interaction", "decoy_density"):
            self.assertIn(key, network.SCORING_HINTS)


class RenderShapeTests(unittest.TestCase):
    def _non_challenge_yaml_required_files(self) -> set[str]:
        return {p for p in network.REQUIRED_FILES if p != "challenge.yaml"}

    def test_render_emits_every_required_file_red(self) -> None:
        spec = _spec(mode="red")
        files = network.render(spec, random.Random(spec.seed))
        self.assertEqual(set(files), self._non_challenge_yaml_required_files())
        for path, content in files.items():
            self.assertTrue(content, f"{path} was emitted empty")

    def test_render_emits_every_required_file_purple(self) -> None:
        spec = _spec(mode="purple")
        files = network.render(spec, random.Random(spec.seed))
        self.assertEqual(set(files), self._non_challenge_yaml_required_files())
        for path, content in files.items():
            self.assertTrue(content, f"{path} was emitted empty")

    def test_render_all_supported_modes(self) -> None:
        for mode in network.MODES:
            spec = _spec(mode=mode)
            files = network.render(spec, random.Random(spec.seed))
            self.assertEqual(set(files), self._non_challenge_yaml_required_files())

    def test_compose_markers_present(self) -> None:
        spec = _spec(mode="red")
        files = network.render(spec, random.Random(spec.seed))
        compose = files["docker-compose.yml"]
        for marker in network.COMPOSE_MARKERS:
            self.assertIn(marker, compose)


class DeterminismTests(unittest.TestCase):
    def test_deterministic_same_seed_red(self) -> None:
        spec = _spec(mode="red")
        first = network.render(spec, random.Random("shared-seed"))
        second = network.render(spec, random.Random("shared-seed"))
        self.assertEqual(first, second)

    def test_deterministic_per_mode(self) -> None:
        for mode in network.MODES:
            spec = _spec(mode=mode)
            first = network.render(spec, random.Random("shared-seed-2"))
            second = network.render(spec, random.Random("shared-seed-2"))
            self.assertEqual(first, second)

    def test_deterministic_with_cve_record(self) -> None:
        spec = _spec(mode="red", cve_refs=["CVE-2099-00001"])
        record = _cve_record()
        first = network.render(spec, random.Random("cve-seed"), cve_record=record)
        second = network.render(spec, random.Random("cve-seed"), cve_record=record)
        self.assertEqual(first, second)

    def test_different_seed_changes_output(self) -> None:
        spec = _spec(mode="red")
        a = network.render(spec, random.Random("seed-a"))
        b = network.render(spec, random.Random("seed-b"))
        self.assertNotEqual(a, b)

    def test_cve_record_affects_description_but_not_determinism(self) -> None:
        spec = _spec(mode="red")
        without_cve = network.render(spec, random.Random("seed-x"))
        with_cve = network.render(spec, random.Random("seed-x"), cve_record=_cve_record())
        self.assertNotEqual(
            without_cve["public/description.md"], with_cve["public/description.md"]
        )
        self.assertIn("CVE-2099-00001", with_cve["public/description.md"])


class VariantJsonTests(unittest.TestCase):
    def test_variant_json_contains_flag(self) -> None:
        import json

        spec = _spec(mode="red")
        files = network.render(spec, random.Random(spec.seed))
        variant = json.loads(files["private/variant.json"])
        self.assertIn("flag", variant)
        self.assertTrue(variant["flag"].startswith("ctf{"))
        self.assertEqual(variant["family"], "network_lateral_pivot")
        self.assertIn("routes", variant)
        self.assertIn("creds", variant)
        self.assertIn("network", variant)

    def test_flag_matches_internal_app_and_solver(self) -> None:
        import json

        spec = _spec(mode="red")
        files = network.render(spec, random.Random(spec.seed))
        variant = json.loads(files["private/variant.json"])
        flag = variant["flag"]
        self.assertIn(flag, files["services/internal/app.py"])
        self.assertIn(variant["creds"]["edge_password"], files["services/edge/app.py"])
        self.assertIn(variant["creds"]["internal_token"], files["services/edge/app.py"])
        self.assertIn(variant["creds"]["internal_token"], files["services/internal/app.py"])


class PurpleModeContentTests(unittest.TestCase):
    def test_purple_adds_blue_team_material(self) -> None:
        spec = _spec(mode="purple")
        files = network.render(spec, random.Random(spec.seed))
        self.assertIn("Blue-team", files["public/description.md"])
        self.assertIn("Blue-team detection guidance", files["private/detection_notes.md"])

    def test_red_omits_purple_only_section(self) -> None:
        spec = _spec(mode="red")
        files = network.render(spec, random.Random(spec.seed))
        self.assertNotIn("Blue-team objective", files["public/description.md"])


class ModeDifferentiationTests(unittest.TestCase):
    """Every declared mode must render a materially distinct, valid challenge."""

    def test_every_declared_mode_renders_all_required_files_deterministically(self) -> None:
        required = {p for p in network.REQUIRED_FILES if p != "challenge.yaml"}
        for mode in network.MODES:
            with self.subTest(mode=mode):
                spec = _spec(mode=mode)
                first = network.render(spec, random.Random("mode-loop-seed"))
                second = network.render(spec, random.Random("mode-loop-seed"))
                self.assertEqual(set(first), required)
                for path, content in first.items():
                    self.assertTrue(content, f"{path} was emitted empty for mode={mode}")
                self.assertEqual(first, second, f"non-deterministic render for mode={mode}")

    def test_purple_description_differs_from_red(self) -> None:
        red = network.render(_spec(mode="red"), random.Random(_spec().seed))
        purple = network.render(_spec(mode="purple"), random.Random(_spec().seed))
        self.assertNotEqual(
            red["public/description.md"], purple["public/description.md"]
        )
        self.assertIn("Blue-team deliverable", purple["public/description.md"])
        self.assertIn("detection-writeup-submitted", purple["public/description.md"])
        self.assertNotIn("detection-writeup-submitted", red["public/description.md"])

    def test_purple_private_deliverable_differs_from_red(self) -> None:
        red = network.render(_spec(mode="red"), random.Random(_spec().seed))
        purple = network.render(_spec(mode="purple"), random.Random(_spec().seed))
        # The private solution write-up is a genuinely different deliverable
        # in purple mode: it adds grading notes for the detection narrative.
        self.assertNotEqual(
            red["private/solution.md"], purple["private/solution.md"]
        )
        self.assertIn("Blue-team deliverable (grading notes)", purple["private/solution.md"])
        self.assertNotIn(
            "Blue-team deliverable (grading notes)", red["private/solution.md"]
        )
        # The detection notes deepen into concrete grading guidance in purple.
        self.assertNotEqual(
            red["private/detection_notes.md"], purple["private/detection_notes.md"]
        )
        self.assertIn(
            "Grading this instance's `detection-writeup-submitted` checkpoint",
            purple["private/detection_notes.md"],
        )

    def test_purple_checkpoints_add_detection_writeup_requirement(self) -> None:
        spec = _spec()
        red = network.render(_spec(mode="red"), random.Random(spec.seed))
        purple = network.render(_spec(mode="purple"), random.Random(spec.seed))
        red_yaml = red["private/checkpoints.yaml"]
        purple_yaml = purple["private/checkpoints.yaml"]
        self.assertNotIn("detection-writeup-submitted", red_yaml)
        self.assertIn("detection-writeup-submitted", purple_yaml)
        # Purple keeps every spec-declared checkpoint too; it only adds one.
        for name in spec.checkpoints:
            self.assertIn(name, red_yaml)
            self.assertIn(name, purple_yaml)
        self.assertNotEqual(red_yaml, purple_yaml)
        self.assertEqual(
            network._checkpoint_entries(_spec(mode="red")),
            [{"name": name, "required": True} for name in spec.checkpoints],
        )
        self.assertEqual(
            network._checkpoint_entries(_spec(mode="purple")),
            [{"name": name, "required": True} for name in spec.checkpoints]
            + [{"name": "detection-writeup-submitted", "required": True}],
        )

    def test_red_mode_render_is_byte_identical_to_baseline_solution_and_notes(self) -> None:
        # Regression guard: red mode must not regress now that purple mode
        # has mode-conditional branches added throughout the same helpers.
        spec = _spec(mode="red")
        files = network.render(spec, random.Random(spec.seed))
        self.assertNotIn("Blue-team", files["public/description.md"])
        self.assertNotIn("Blue-team", files["private/solution.md"])
        self.assertNotIn("detection-writeup-submitted", files["private/checkpoints.yaml"])
        self.assertTrue(
            files["private/solution.md"].rstrip("\n").endswith(
                "guessing passwords from scratch."
            )
        )


if __name__ == "__main__":
    unittest.main()
