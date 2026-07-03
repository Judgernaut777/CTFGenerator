from __future__ import annotations

import random
import unittest

from ctf_generator.models import ChallengeSpec
from ctf_generator.templates import cloud


def _spec(**overrides: object) -> ChallengeSpec:
    defaults = dict(
        title="CVE-2021-22986: SSRF in Cloud Asset Pipeline",
        category="cloud",
        difficulty="hard",
        family=cloud.FAMILY_NAME,
        seed="cloud-seed-1",
        learning_objectives=["Understand CWE-918 in a cloud fetch service"],
        checkpoints=[
            "recon identifies the fetch route",
            "discovers the SSRF vulnerability",
            "fetches the metadata role list",
            "steals temporary IAM credentials",
            "extracts the flag from the storage service",
        ],
    )
    defaults.update(overrides)
    return ChallengeSpec(**defaults)  # type: ignore[arg-type]


class ModuleInterfaceTests(unittest.TestCase):
    def test_module_constants(self) -> None:
        self.assertEqual(cloud.FAMILY_NAME, "cloud_metadata_ssrf")
        self.assertEqual(cloud.CATEGORY, "cloud")
        self.assertEqual(cloud.MODES, ("red", "purple"))
        self.assertEqual(cloud.DIFFICULTIES, ("easy", "medium", "hard"))
        self.assertTrue(cloud.CVE_DRIVEN)
        self.assertTrue(cloud.LLM_BRIEF)
        self.assertIn("api:", cloud.COMPOSE_MARKERS)
        self.assertIn("metadata:", cloud.COMPOSE_MARKERS)
        self.assertIn("storage:", cloud.COMPOSE_MARKERS)
        self.assertIsInstance(cloud.SCORING_HINTS, dict)
        for key in ("has_worker", "has_queue", "live_interaction", "decoy_density"):
            self.assertIn(key, cloud.SCORING_HINTS)
        self.assertIn("challenge.yaml", cloud.REQUIRED_FILES)


class RenderRequiredFilesTests(unittest.TestCase):
    def _assert_all_required_files_emitted(self, mode: str) -> None:
        spec = _spec(mode=mode)
        rng = random.Random(spec.seed)
        files = cloud.render(spec, rng)
        for relative in cloud.REQUIRED_FILES:
            if relative == "challenge.yaml":
                continue
            self.assertIn(relative, files, f"missing {relative} for mode={mode}")
            self.assertTrue(files[relative].strip(), f"empty {relative} for mode={mode}")
        # render() must not emit files outside its own REQUIRED_FILES set
        # (aside from challenge.yaml, which the generator writes itself).
        expected = set(cloud.REQUIRED_FILES) - {"challenge.yaml"}
        self.assertEqual(set(files.keys()), expected)

    def test_red_mode_emits_required_files(self) -> None:
        self._assert_all_required_files_emitted("red")

    def test_purple_mode_emits_required_files(self) -> None:
        self._assert_all_required_files_emitted("purple")


class DeterminismTests(unittest.TestCase):
    def _assert_deterministic(self, mode: str) -> None:
        spec = _spec(mode=mode)
        files_a = cloud.render(spec, random.Random(spec.seed))
        files_b = cloud.render(spec, random.Random(spec.seed))
        self.assertEqual(files_a, files_b)

    def test_deterministic_red(self) -> None:
        self._assert_deterministic("red")

    def test_deterministic_purple(self) -> None:
        self._assert_deterministic("purple")

    def test_different_seeds_diverge(self) -> None:
        spec_a = _spec(seed="seed-aaaa")
        spec_b = _spec(seed="seed-bbbb")
        files_a = cloud.render(spec_a, random.Random(spec_a.seed))
        files_b = cloud.render(spec_b, random.Random(spec_b.seed))
        self.assertNotEqual(files_a["private/variant.json"], files_b["private/variant.json"])


class VariantContentTests(unittest.TestCase):
    def test_variant_json_contains_flag(self) -> None:
        spec = _spec(mode="red")
        files = cloud.render(spec, random.Random(spec.seed))
        variant_text = files["private/variant.json"]
        self.assertIn('"flag"', variant_text)
        self.assertIn("ctf{", variant_text)

    def test_variant_json_has_routes_and_tokens(self) -> None:
        spec = _spec(mode="red")
        files = cloud.render(spec, random.Random(spec.seed))
        variant_text = files["private/variant.json"]
        self.assertIn('"routes"', variant_text)
        self.assertIn('"tokens"', variant_text)
        self.assertIn("169.254.169.254", variant_text)

    def test_compose_has_all_markers(self) -> None:
        spec = _spec(mode="red")
        files = cloud.render(spec, random.Random(spec.seed))
        compose = files["docker-compose.yml"]
        for marker in cloud.COMPOSE_MARKERS:
            self.assertIn(marker, compose)

    def test_purple_detection_rule_enabled_red_is_not(self) -> None:
        spec_red = _spec(mode="red")
        spec_purple = _spec(mode="purple")
        files_red = cloud.render(spec_red, random.Random(spec_red.seed))
        files_purple = cloud.render(spec_purple, random.Random(spec_purple.seed))
        self.assertIn("enabled: false", files_red["detection/ssrf_egress_rule.yaml"])
        self.assertIn("enabled: true", files_purple["detection/ssrf_egress_rule.yaml"])

    def test_solver_and_healthcheck_use_stdlib_only(self) -> None:
        spec = _spec(mode="red")
        files = cloud.render(spec, random.Random(spec.seed))
        for path in ("private/solver.py", "tests/healthcheck.py"):
            text = files[path]
            self.assertNotIn("import requests", text)
            self.assertIn("urllib", text)


if __name__ == "__main__":
    unittest.main()
