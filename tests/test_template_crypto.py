from __future__ import annotations

import json
import random
import unittest

from ctf_generator.models import ChallengeSpec
from ctf_generator.templates import crypto


def _spec(**overrides: object) -> ChallengeSpec:
    defaults = dict(
        title="Silent Signature",
        category="crypto",
        difficulty="medium",
        family=crypto.FAMILY_NAME,
        seed="crypto-seed-1",
        learning_objectives=["Understand JWT alg-confusion (CWE-347)"],
        checkpoints=[
            "logs in as the demo user",
            "decodes the issued token",
            "forges an alg=none admin token",
            "reaches the admin endpoint",
            "extracts the flag",
        ],
    )
    defaults.update(overrides)
    return ChallengeSpec(**defaults)  # type: ignore[arg-type]


class ModuleInterfaceTests(unittest.TestCase):
    def test_exports(self) -> None:
        self.assertEqual(crypto.FAMILY_NAME, "crypto_token_forgery")
        self.assertEqual(crypto.CATEGORY, "crypto")
        self.assertEqual(crypto.MODES, ("red",))
        self.assertEqual(crypto.DIFFICULTIES, ("easy", "medium", "hard"))
        self.assertTrue(crypto.CVE_DRIVEN)
        self.assertTrue(crypto.LLM_BRIEF)
        self.assertIn("api:", crypto.COMPOSE_MARKERS)
        self.assertIn("challenge.yaml", crypto.REQUIRED_FILES)
        self.assertIsInstance(crypto.SCORING_HINTS, dict)
        for key in ("has_worker", "has_queue", "live_interaction", "decoy_density"):
            self.assertIn(key, crypto.SCORING_HINTS)


class RenderShapeTests(unittest.TestCase):
    def test_render_emits_every_required_file_except_challenge_yaml(self) -> None:
        spec = _spec()
        files = crypto.render(spec, random.Random(spec.seed))
        expected = set(crypto.REQUIRED_FILES) - {"challenge.yaml"}
        self.assertEqual(set(files), expected)
        for relative, content in files.items():
            self.assertTrue(content, f"{relative} must not be empty")

    def test_render_supports_every_declared_mode(self) -> None:
        for mode in crypto.MODES:
            spec = _spec(mode=mode)
            files = crypto.render(spec, random.Random(spec.seed))
            expected = set(crypto.REQUIRED_FILES) - {"challenge.yaml"}
            self.assertEqual(set(files), expected, msg=f"mode={mode}")


class DeterminismTests(unittest.TestCase):
    def test_same_spec_and_rng_seed_is_byte_identical(self) -> None:
        spec = _spec()
        first = crypto.render(spec, random.Random("shared-seed"))
        second = crypto.render(spec, random.Random("shared-seed"))
        self.assertEqual(first, second)

    def test_same_spec_and_rng_seed_is_byte_identical_per_mode(self) -> None:
        for mode in crypto.MODES:
            spec = _spec(mode=mode)
            first = crypto.render(spec, random.Random("shared-seed"))
            second = crypto.render(spec, random.Random("shared-seed"))
            self.assertEqual(first, second, msg=f"mode={mode}")

    def test_different_rng_seed_changes_output(self) -> None:
        spec = _spec()
        first = crypto.render(spec, random.Random("seed-a"))
        second = crypto.render(spec, random.Random("seed-b"))
        self.assertNotEqual(first, second)

    def test_cve_record_is_accepted_and_stays_deterministic(self) -> None:
        from ctf_generator.cve_source import SnapshotCveSource

        record = SnapshotCveSource().get("CVE-2014-0160")
        self.assertIsNotNone(record)
        spec = _spec()
        first = crypto.render(spec, random.Random("shared-seed"), cve_record=record)
        second = crypto.render(spec, random.Random("shared-seed"), cve_record=record)
        self.assertEqual(first, second)
        self.assertIn(record.cve_id, first["public/description.md"])


class VariantJsonTests(unittest.TestCase):
    def test_variant_json_contains_flag_and_is_valid_json(self) -> None:
        spec = _spec()
        files = crypto.render(spec, random.Random(spec.seed))
        variant = json.loads(files["private/variant.json"])
        self.assertIn("flag", variant)
        self.assertTrue(variant["flag"].startswith("ctf{"))
        self.assertEqual(variant["family"], crypto.FAMILY_NAME)
        self.assertIn("routes", variant)
        self.assertIn("credentials", variant)

    def test_flag_is_consistent_across_files(self) -> None:
        spec = _spec()
        files = crypto.render(spec, random.Random(spec.seed))
        variant = json.loads(files["private/variant.json"])
        flag = variant["flag"]
        self.assertIn(flag, files["services/api/app.py"])
        # The flag itself is not echoed in the public-facing/solution prose --
        # only the app source (served at runtime) and variant.json carry it.
        self.assertNotIn(flag, files["public/description.md"])


class ComposeAndServiceTests(unittest.TestCase):
    def test_compose_has_declared_markers(self) -> None:
        spec = _spec()
        files = crypto.render(spec, random.Random(spec.seed))
        compose = files["docker-compose.yml"]
        for marker in crypto.COMPOSE_MARKERS:
            self.assertIn(marker, compose)

    def test_app_source_implements_its_declared_vuln_class(self) -> None:
        spec = _spec()
        files = crypto.render(spec, random.Random(spec.seed))
        app_source = files["services/api/app.py"]
        vuln_class = json.loads(files["private/variant.json"])["vuln_class"]
        if vuln_class == "alg_none":
            self.assertIn('alg == "none"', app_source)
        else:  # weak_secret: no unsigned-token acceptance path
            self.assertNotIn('if alg == "none"', app_source)
        compile(app_source, "app.py", "exec")

    def test_solver_is_adaptive_covering_both_techniques(self) -> None:
        # The single reference solver ships BOTH techniques regardless of the
        # instance's class, so it solves any instance (and any sibling).
        spec = _spec()
        files = crypto.render(spec, random.Random(spec.seed))
        solver_source = files["private/solver.py"]
        self.assertIn('"alg": "none"', solver_source)  # forge-unsigned technique
        self.assertIn("_crack_secret", solver_source)  # dictionary-attack technique
        compile(solver_source, "solver.py", "exec")


class PerInstanceVulnClassTests(unittest.TestCase):
    """Front C: the vulnerability CLASS varies per instance, so a technique
    tied to one class is not the whole story -- a single-class writeup does not
    generalise to a differently-classed sibling."""

    def _render_class(self, target: str):
        for i in range(200):
            spec = _spec(seed=f"vc-seed-{i}")
            files = crypto.render(spec, random.Random(spec.seed))
            if json.loads(files["private/variant.json"])["vuln_class"] == target:
                return files
        self.fail(f"no seed produced vuln_class={target}")

    def test_both_classes_are_reachable(self) -> None:
        for cls in crypto.VULN_CLASSES:
            with self.subTest(vuln_class=cls):
                self._render_class(cls)

    def test_alg_none_accepts_unsigned_but_weak_secret_does_not(self) -> None:
        alg_none_app = self._render_class("alg_none")["services/api/app.py"]
        weak_app = self._render_class("weak_secret")["services/api/app.py"]
        # The unsigned-token acceptance branch exists ONLY in alg_none: the
        # exact behaviour that makes an alg:none writeup work on one instance
        # and fail on the other.
        self.assertIn('if alg == "none"', alg_none_app)
        self.assertNotIn('if alg == "none"', weak_app)

    def test_weak_secret_uses_a_crackable_secret_and_alg_none_does_not(self) -> None:
        weak_variant = json.loads(self._render_class("weak_secret")["private/variant.json"])
        none_variant = json.loads(self._render_class("alg_none")["private/variant.json"])
        self.assertIn(weak_variant["token"]["secret"], crypto._WEAK_SECRETS)
        self.assertNotIn(none_variant["token"]["secret"], crypto._WEAK_SECRETS)


class CheckpointsTests(unittest.TestCase):
    def test_checkpoints_come_from_spec(self) -> None:
        spec = _spec()
        files = crypto.render(spec, random.Random(spec.seed))
        checkpoints_yaml = files["private/checkpoints.yaml"]
        for name in spec.checkpoints:
            self.assertIn(name, checkpoints_yaml)


if __name__ == "__main__":
    unittest.main()
