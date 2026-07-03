from __future__ import annotations

import json
import random
import unittest

from ctf_generator.cve_source import CveRecord
from ctf_generator.models import ChallengeSpec
from ctf_generator.templates import binary


def _spec(**overrides: object) -> ChallengeSpec:
    defaults = dict(
        title="Legacy Support Daemon",
        category="binary",
        difficulty="medium",
        family=binary.FAMILY_NAME,
        seed="binary-seed-1",
        learning_objectives=["obj-1"],
        checkpoints=["step-1", "step-2", "step-3", "step-4", "step-5"],
    )
    defaults.update(overrides)
    return ChallengeSpec(**defaults)  # type: ignore[arg-type]


_CVE_RECORD = CveRecord(
    cve_id="CVE-2021-3156",
    published="2021-01-26",
    cvss_version="3.1",
    cvss_score=7.8,
    cvss_severity="HIGH",
    cwe_ids=["CWE-193", "CWE-787"],
    category="binary",
    affected_products=["sudo before 1.9.5p2"],
    description="Heap-based buffer overflow in sudoedit argument parsing.",
    references=["https://nvd.nist.gov/vuln/detail/CVE-2021-3156"],
)


class InterfaceShapeTests(unittest.TestCase):
    def test_module_constants(self) -> None:
        self.assertEqual(binary.FAMILY_NAME, "binary_heap_exploit")
        self.assertEqual(binary.CATEGORY, "binary")
        self.assertEqual(binary.MODES, ("red",))
        self.assertEqual(binary.DIFFICULTIES, ("easy", "medium", "hard"))
        self.assertTrue(binary.CVE_DRIVEN)
        self.assertTrue(binary.LLM_BRIEF)
        self.assertIn("vuln", binary.COMPOSE_MARKERS)
        self.assertIsInstance(binary.SCORING_HINTS, dict)
        for key in ("has_worker", "has_queue", "live_interaction", "decoy_density"):
            self.assertIn(key, binary.SCORING_HINTS)
        self.assertIn("challenge.yaml", binary.REQUIRED_FILES)


class RenderRequiredFilesTests(unittest.TestCase):
    def test_render_emits_exactly_required_files_minus_challenge_yaml(self) -> None:
        spec = _spec()
        rendered = binary.render(spec, random.Random(spec.seed))
        expected = set(binary.REQUIRED_FILES) - {"challenge.yaml"}
        self.assertEqual(set(rendered.keys()), expected)

    def test_all_rendered_files_are_nonempty_strings(self) -> None:
        spec = _spec()
        rendered = binary.render(spec, random.Random(spec.seed))
        for path, content in rendered.items():
            self.assertIsInstance(content, str, msg=path)
            self.assertTrue(content.strip(), msg=f"{path} is empty")

    def test_render_works_with_and_without_cve_record(self) -> None:
        spec = _spec()
        without_cve = binary.render(spec, random.Random(spec.seed))
        with_cve = binary.render(spec, random.Random(spec.seed), cve_record=_CVE_RECORD)
        self.assertEqual(set(without_cve.keys()), set(with_cve.keys()))
        # CVE grounding should actually show up in player/solution-facing text.
        self.assertIn("CVE-2021-3156", with_cve["public/description.md"])
        self.assertIn("CVE-2021-3156", with_cve["private/solution.md"])


class DeterminismTests(unittest.TestCase):
    def test_deterministic_same_seed_same_output_red_mode(self) -> None:
        for mode in binary.MODES:
            spec = _spec(mode=mode) if mode != "red" else _spec()
            first = binary.render(spec, random.Random("fixed-seed-42"))
            second = binary.render(spec, random.Random("fixed-seed-42"))
            self.assertEqual(first, second, msg=f"mode={mode!r}")

    def test_deterministic_with_cve_record_too(self) -> None:
        spec = _spec()
        first = binary.render(spec, random.Random("fixed-seed-99"), cve_record=_CVE_RECORD)
        second = binary.render(spec, random.Random("fixed-seed-99"), cve_record=_CVE_RECORD)
        self.assertEqual(first, second)

    def test_different_seeds_vary_output(self) -> None:
        spec = _spec()
        a = binary.render(spec, random.Random("seed-a"))
        b = binary.render(spec, random.Random("seed-b"))
        self.assertNotEqual(a, b)

    def test_unsupported_mode_raises(self) -> None:
        spec = _spec(mode="blue")
        with self.assertRaises(ValueError):
            binary.render(spec, random.Random(spec.seed))


class VariantJsonTests(unittest.TestCase):
    def test_variant_json_contains_flag(self) -> None:
        spec = _spec()
        rendered = binary.render(spec, random.Random(spec.seed))
        payload = json.loads(rendered["private/variant.json"])
        self.assertIn("flag", payload)
        self.assertTrue(payload["flag"].startswith("ctf{"))
        self.assertTrue(payload["flag"].endswith("}"))

    def test_variant_json_is_valid_json_with_expected_shape(self) -> None:
        spec = _spec()
        rendered = binary.render(spec, random.Random(spec.seed))
        payload = json.loads(rendered["private/variant.json"])
        self.assertEqual(payload["family"], "binary_heap_exploit")
        self.assertIn("routes", payload)
        self.assertIn("port", payload["routes"])
        self.assertIsInstance(payload["routes"]["port"], int)
        self.assertIn("tokens", payload)
        for key in (
            "service_name",
            "banner",
            "name_buf_size",
            "admin_field",
            "set_word",
            "dump_word",
            "overflow_len",
            "filler_byte",
        ):
            self.assertIn(key, payload["tokens"])

    def test_flag_appears_in_vuln_source_as_fallback(self) -> None:
        spec = _spec()
        rendered = binary.render(spec, random.Random(spec.seed))
        payload = json.loads(rendered["private/variant.json"])
        self.assertIn(payload["flag"], rendered["services/vuln/vuln.c"])


class ContentConsistencyTests(unittest.TestCase):
    def test_compose_exposes_vuln_service_and_declared_port(self) -> None:
        spec = _spec()
        rendered = binary.render(spec, random.Random(spec.seed))
        payload = json.loads(rendered["private/variant.json"])
        port = payload["routes"]["port"]
        compose = rendered["docker-compose.yml"]
        self.assertIn("vuln:", compose)
        self.assertIn(f'"{port}:{port}"', compose)

    def test_solver_targets_declared_port_and_prints_flag_pattern(self) -> None:
        spec = _spec()
        rendered = binary.render(spec, random.Random(spec.seed))
        payload = json.loads(rendered["private/variant.json"])
        port = payload["routes"]["port"]
        solver = rendered["private/solver.py"]
        self.assertIn(f"default={port}", solver)
        self.assertIn("ctf\\{", solver)

    def test_overflow_len_exceeds_name_buf_size(self) -> None:
        spec = _spec()
        rendered = binary.render(spec, random.Random(spec.seed))
        payload = json.loads(rendered["private/variant.json"])
        tokens = payload["tokens"]
        self.assertGreater(tokens["overflow_len"], tokens["name_buf_size"])

    def test_checkpoints_reflect_spec_checkpoints(self) -> None:
        spec = _spec(checkpoints=["recon", "overflow", "dump"])
        rendered = binary.render(spec, random.Random(spec.seed))
        checkpoints_yaml = rendered["private/checkpoints.yaml"]
        for name in spec.checkpoints:
            self.assertIn(name, checkpoints_yaml)


if __name__ == "__main__":
    unittest.main()
