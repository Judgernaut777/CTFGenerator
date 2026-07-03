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


if __name__ == "__main__":
    unittest.main()
