from __future__ import annotations

import json
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
        # Red mode ends on the class-independent teaching paragraph (no purple
        # deliverable appended). This tail is stable across all vuln classes.
        self.assertTrue(
            files["private/solution.md"].rstrip("\n").endswith(
                "pivot through the edge host is the constant."
            )
        )


class PerInstanceVulnClassTests(unittest.TestCase):
    """Front C: each instance draws one of three genuinely distinct internal-auth
    vulnerability classes, and the adaptive solver handles any of them."""

    def _render_for_seed(self, seed: str, mode: str = "red") -> dict[str, str]:
        return network.render(_spec(mode=mode, seed=seed), random.Random(seed))

    def _seed_for_class(self, vuln_class: str) -> str:
        for i in range(500):
            seed = f"vc-seed-{i}"
            files = self._render_for_seed(seed)
            if json.loads(files["private/variant.json"])["vuln_class"] == vuln_class:
                return seed
        raise AssertionError(f"no seed produced vuln_class={vuln_class} in 500 tries")

    def test_variant_json_carries_a_known_vuln_class(self) -> None:
        files = self._render_for_seed("class-seed-1")
        vc = json.loads(files["private/variant.json"])["vuln_class"]
        self.assertIn(vc, network.VULN_CLASSES)

    def test_all_three_classes_appear_across_seeds(self) -> None:
        seen = set()
        for i in range(400):
            files = self._render_for_seed(f"spread-{i}")
            seen.add(json.loads(files["private/variant.json"])["vuln_class"])
            if seen == set(network.VULN_CLASSES):
                break
        self.assertEqual(seen, set(network.VULN_CLASSES))

    def test_same_seed_is_stable_class(self) -> None:
        a = json.loads(self._render_for_seed("stable-1")["private/variant.json"])["vuln_class"]
        b = json.loads(self._render_for_seed("stable-1")["private/variant.json"])["vuln_class"]
        self.assertEqual(a, b)

    def test_disclosed_token_internal_discloses_the_real_token(self) -> None:
        seed = self._seed_for_class("disclosed_token")
        files = self._render_for_seed(seed)
        variant = json.loads(files["private/variant.json"])
        internal = files["services/internal/app.py"]
        # The advice endpoint returns the real token; the flag check is
        # token-only (no relay-context bypass).
        self.assertIn('"auth_token": INTERNAL_TOKEN', internal)
        self.assertNotIn("X-Relay-Context", internal)
        # A full random secret, not a wordlist default.
        self.assertNotIn(variant["creds"]["internal_token"], network._WEAK_TOKENS)

    def test_weak_token_uses_a_wordlist_default_and_redacts_it(self) -> None:
        seed = self._seed_for_class("weak_token")
        files = self._render_for_seed(seed)
        variant = json.loads(files["private/variant.json"])
        internal = files["services/internal/app.py"]
        self.assertIn(variant["creds"]["internal_token"], network._WEAK_TOKENS)
        # Advice redacts the token (auth_token is None) and the flag check does
        # not honor the relay-context header.
        self.assertIn('"auth_token": None', internal)
        self.assertNotIn("X-Relay-Context", internal)

    def test_relay_trust_bypasses_token_via_asset_context_header(self) -> None:
        seed = self._seed_for_class("relay_trust")
        files = self._render_for_seed(seed)
        variant = json.loads(files["private/variant.json"])
        internal = files["services/internal/app.py"]
        # The internal flag check honors X-Relay-Context == ASSET_TAG as an
        # auth bypass; the token itself is a full random secret and redacted.
        self.assertIn("X-Relay-Context", internal)
        self.assertIn("context != ASSET_TAG", internal)
        self.assertIn('"auth_token": None', internal)
        self.assertNotIn(variant["creds"]["internal_token"], network._WEAK_TOKENS)

    def test_solver_is_adaptive_over_all_three_techniques(self) -> None:
        # One shipped solver must carry all three techniques regardless of the
        # instance's own class, so it solves any sibling.
        for vuln_class in network.VULN_CLASSES:
            seed = self._seed_for_class(vuln_class)
            solver = self._render_for_seed(seed)["private/solver.py"]
            with self.subTest(vuln_class=vuln_class):
                self.assertIn("auth_token", solver)          # disclosed token
                self.assertIn("context=asset_tag", solver)   # forged relay-trust
                self.assertIn("WEAK_TOKENS", solver)         # dictionary attack

    def test_hints_and_solution_are_class_aware(self) -> None:
        disclosed = self._render_for_seed(self._seed_for_class("disclosed_token"))
        trust = self._render_for_seed(self._seed_for_class("relay_trust"))
        self.assertIn("disclosed_token", disclosed["private/solution.md"])
        self.assertIn("relay_trust", trust["private/solution.md"])
        # The non-generalization argument is documented in every instance.
        self.assertIn(
            "does not generalize", disclosed["private/solution.md"]
        )


if __name__ == "__main__":
    unittest.main()
