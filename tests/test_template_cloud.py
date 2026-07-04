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


class PerModeDivergenceTests(unittest.TestCase):
    """Confirm red vs. purple render materially different, valid challenges."""

    def _render(self, mode: str) -> dict[str, str]:
        spec = _spec(mode=mode)
        return cloud.render(spec, random.Random(spec.seed))

    def test_each_mode_renders_and_emits_all_required_files(self) -> None:
        for mode in cloud.MODES:
            files = self._render(mode)
            for relative in cloud.REQUIRED_FILES:
                if relative == "challenge.yaml":
                    continue
                self.assertIn(relative, files, f"missing {relative} for mode={mode}")
                self.assertTrue(files[relative].strip(), f"empty {relative} for mode={mode}")

    def test_each_mode_is_deterministic(self) -> None:
        for mode in cloud.MODES:
            spec = _spec(mode=mode)
            files_a = cloud.render(spec, random.Random(spec.seed))
            files_b = cloud.render(spec, random.Random(spec.seed))
            self.assertEqual(files_a, files_b, f"non-deterministic for mode={mode}")

    def test_purple_description_differs_from_red(self) -> None:
        files_red = self._render("red")
        files_purple = self._render("purple")
        self.assertNotEqual(
            files_red["public/description.md"], files_purple["public/description.md"]
        )
        # Purple must spell out the additional blue/detection objective; red
        # must not (it is a pure-offense challenge).
        self.assertIn("Blue objective", files_purple["public/description.md"])
        self.assertNotIn("Blue objective", files_red["public/description.md"])

    def test_purple_private_deliverable_differs_from_red(self) -> None:
        files_red = self._render("red")
        files_purple = self._render("purple")
        self.assertNotEqual(
            files_red["private/solution.md"], files_purple["private/solution.md"]
        )
        # Purple's solution must additionally require the detection/response
        # write-up; red's solution must remain exploit-only.
        self.assertIn("purple-mode) deliverable", files_purple["private/solution.md"])
        self.assertIn("Remediation", files_purple["private/solution.md"])
        self.assertNotIn("purple-mode) deliverable", files_red["private/solution.md"])

    def test_red_solution_is_byte_identical_to_mode_naive_baseline(self) -> None:
        # Regression guard: red mode's private solution must not have grown
        # a trailing artifact from the purple-only appended section.
        files_red = self._render("red")
        solution = files_red["private/solution.md"]
        self.assertTrue(
            solution.endswith(
                "This teaches SSRF-to-cloud-credential-theft: input validation on the fetch\n"
                "service is necessary but not sufficient without also constraining what the\n"
                "service's own network identity can reach.\n"
            )
        )

    def test_purple_detection_rule_referenced_in_private_deliverable(self) -> None:
        files_purple = self._render("purple")
        rule_yaml = files_purple["detection/ssrf_egress_rule.yaml"]
        solution = files_purple["private/solution.md"]
        description = files_purple["public/description.md"]
        # Extract the generated rule id and confirm it's cross-referenced in
        # both the public description and the private deliverable, tying the
        # exploit, the detection rule, and the response write-up together.
        rule_id_line = next(
            line for line in rule_yaml.splitlines() if line.strip().startswith("id:")
        )
        rule_id = rule_id_line.split(":", 1)[1].strip().strip('"')
        self.assertIn(rule_id, solution)
        self.assertIn(rule_id, description)


if __name__ == "__main__":
    unittest.main()
