from __future__ import annotations

import json
import random
import unittest

from ctf_generator.cve_source import CveRecord
from ctf_generator.models import ChallengeSpec
from ctf_generator.templates import scada_ics


def _spec(**overrides: object) -> ChallengeSpec:
    defaults: dict[str, object] = dict(
        title="Riverbend Modbus Bypass",
        category="scada_ics",
        difficulty="medium",
        family=scada_ics.FAMILY_NAME,
        seed="abc123",
        learning_objectives=["obj-1"],
        checkpoints=["step-1", "step-2", "step-3", "step-4", "step-5"],
        mode="red",
    )
    defaults.update(overrides)
    return ChallengeSpec(**defaults)  # type: ignore[arg-type]


_CVE_RECORD = CveRecord(
    cve_id="CVE-2022-1161",
    published="2022-06-14",
    cvss_version="3.1",
    cvss_score=9.1,
    cvss_severity="CRITICAL",
    cwe_ids=["CWE-693", "CWE-1188"],
    category="scada_ics",
    affected_products=["Schneider Electric Modicon M221 PLC"],
    description=(
        "Schneider Electric Modicon M221 controllers store project passwords "
        "in cleartext in program memory, allowing an attacker with network "
        "access to the PLC to read out engineering credentials and alter "
        "ladder-logic without authorization."
    ),
    references=["https://nvd.nist.gov/vuln/detail/CVE-2022-1161"],
)


class ModuleContractTests(unittest.TestCase):
    def test_module_constants(self) -> None:
        self.assertEqual(scada_ics.FAMILY_NAME, "scada_ics_modbus_takeover")
        self.assertEqual(scada_ics.CATEGORY, "scada_ics")
        self.assertEqual(scada_ics.MODES, ("red", "blue", "purple"))
        self.assertEqual(scada_ics.DIFFICULTIES, ("easy", "medium", "hard"))
        self.assertTrue(scada_ics.CVE_DRIVEN)
        self.assertTrue(scada_ics.LLM_BRIEF)
        self.assertIn("plc:", scada_ics.COMPOSE_MARKERS)
        self.assertIn("hmi:", scada_ics.COMPOSE_MARKERS)
        self.assertIsInstance(scada_ics.SCORING_HINTS, dict)
        for key in ("has_worker", "has_queue", "live_interaction", "decoy_density"):
            self.assertIn(key, scada_ics.SCORING_HINTS)
        self.assertIn("challenge.yaml", scada_ics.REQUIRED_FILES)
        self.assertIn("docker-compose.yml", scada_ics.REQUIRED_FILES)

    def test_required_files_no_duplicates(self) -> None:
        self.assertEqual(len(scada_ics.REQUIRED_FILES), len(set(scada_ics.REQUIRED_FILES)))


class RenderEmitsRequiredFilesTests(unittest.TestCase):
    def test_red_mode_emits_every_required_file(self) -> None:
        files = scada_ics.render(_spec(mode="red"), random.Random("seed-1"))
        for relative in scada_ics.REQUIRED_FILES:
            if relative == "challenge.yaml":
                continue
            self.assertIn(relative, files, f"missing required file: {relative}")
            self.assertTrue(files[relative].strip(), f"required file is empty: {relative}")

    def test_no_extra_files_outside_required_set(self) -> None:
        files = scada_ics.render(_spec(mode="red"), random.Random("seed-1"))
        allowed = set(scada_ics.REQUIRED_FILES) - {"challenge.yaml"}
        self.assertEqual(set(files), allowed)

    def test_each_supported_mode_emits_every_required_file(self) -> None:
        for mode in scada_ics.MODES:
            with self.subTest(mode=mode):
                files = scada_ics.render(_spec(mode=mode), random.Random("seed-per-mode"))
                for relative in scada_ics.REQUIRED_FILES:
                    if relative == "challenge.yaml":
                        continue
                    self.assertIn(relative, files, f"mode {mode} missing {relative}")


class DeterminismTests(unittest.TestCase):
    def test_red_mode_is_deterministic(self) -> None:
        spec = _spec(mode="red")
        first = scada_ics.render(spec, random.Random("fixed-seed"))
        second = scada_ics.render(spec, random.Random("fixed-seed"))
        self.assertEqual(first, second)

    def test_each_mode_is_deterministic(self) -> None:
        for mode in scada_ics.MODES:
            with self.subTest(mode=mode):
                spec = _spec(mode=mode)
                first = scada_ics.render(spec, random.Random("fixed-seed-2"))
                second = scada_ics.render(spec, random.Random("fixed-seed-2"))
                self.assertEqual(first, second)

    def test_different_rng_state_changes_output(self) -> None:
        spec = _spec(mode="red")
        a = scada_ics.render(spec, random.Random("seed-a"))
        b = scada_ics.render(spec, random.Random("seed-b"))
        self.assertNotEqual(a, b)

    def test_cve_record_is_accepted_and_deterministic(self) -> None:
        spec = _spec(mode="red")
        first = scada_ics.render(spec, random.Random("cve-seed"), cve_record=_CVE_RECORD)
        second = scada_ics.render(spec, random.Random("cve-seed"), cve_record=_CVE_RECORD)
        self.assertEqual(first, second)
        self.assertIn(_CVE_RECORD.cve_id, first["public/description.md"])


class VariantJsonTests(unittest.TestCase):
    def test_variant_json_contains_flag(self) -> None:
        files = scada_ics.render(_spec(mode="red"), random.Random("flag-seed"))
        variant = json.loads(files["private/variant.json"])
        self.assertIn("flag", variant)
        self.assertTrue(variant["flag"])
        self.assertTrue(variant["flag"].startswith("ctf{"))
        self.assertTrue(variant["flag"].endswith("}"))

    def test_variant_json_includes_routes_and_creds_and_ids(self) -> None:
        files = scada_ics.render(_spec(mode="purple"), random.Random("flag-seed-2"))
        variant = json.loads(files["private/variant.json"])
        self.assertIn("routes", variant)
        self.assertIn("creds", variant)
        self.assertIn("ids", variant)
        self.assertEqual(variant["family"], scada_ics.FAMILY_NAME)
        self.assertEqual(variant["mode"], "purple")

    def test_flag_varies_by_seed(self) -> None:
        spec = _spec(mode="red")
        flag_a = json.loads(
            scada_ics.render(spec, random.Random("seed-a"))["private/variant.json"]
        )["flag"]
        flag_b = json.loads(
            scada_ics.render(spec, random.Random("seed-b"))["private/variant.json"]
        )["flag"]
        self.assertNotEqual(flag_a, flag_b)


class EmbeddedSourceValidityTests(unittest.TestCase):
    """No Docker/network: statically compile the emitted Python source files."""

    def test_all_emitted_python_files_compile(self) -> None:
        for mode in scada_ics.MODES:
            files = scada_ics.render(_spec(mode=mode), random.Random("compile-check"))
            for relative, content in files.items():
                if relative.endswith(".py"):
                    with self.subTest(mode=mode, path=relative):
                        compile(content, relative, "exec")

    def test_docker_compose_has_expected_service_markers(self) -> None:
        files = scada_ics.render(_spec(mode="red"), random.Random("compose-check"))
        compose = files["docker-compose.yml"]
        for marker in scada_ics.COMPOSE_MARKERS:
            self.assertIn(marker, compose)

    def test_register_write_log_is_valid_jsonl(self) -> None:
        files = scada_ics.render(_spec(mode="blue"), random.Random("log-check"))
        log_text = files["public/evidence/register_write_log.jsonl"]
        lines = [line for line in log_text.splitlines() if line.strip()]
        self.assertGreater(len(lines), 0)
        for line in lines:
            json.loads(line)  # must not raise


class PerModeDifferentiationTests(unittest.TestCase):
    """red = offensive-only, blue = defensive-only, purple = hybrid -- each mode
    must render, emit every required file, be deterministic, and (blue/purple)
    be materially different from red in both the public description and the
    private deliverable, never merely a cosmetic label swap."""

    def test_each_mode_renders_and_emits_every_required_file(self) -> None:
        for mode in scada_ics.MODES:
            with self.subTest(mode=mode):
                files = scada_ics.render(_spec(mode=mode), random.Random("per-mode-render"))
                for relative in scada_ics.REQUIRED_FILES:
                    if relative == "challenge.yaml":
                        continue
                    self.assertIn(relative, files, f"mode {mode} missing {relative}")
                    self.assertTrue(files[relative].strip(), f"mode {mode} has empty {relative}")

    def test_each_mode_is_internally_deterministic(self) -> None:
        for mode in scada_ics.MODES:
            with self.subTest(mode=mode):
                spec = _spec(mode=mode)
                first = scada_ics.render(spec, random.Random("per-mode-determinism"))
                second = scada_ics.render(spec, random.Random("per-mode-determinism"))
                self.assertEqual(first, second)

    def test_red_mode_output_is_unchanged_by_mode_differentiation(self) -> None:
        """Locks in that today's red-mode bytes (already validated in real
        Docker) are not regressed by blue/purple-specific content additions."""
        files = scada_ics.render(_spec(mode="red"), random.Random("red-lock"))
        solution = files["private/solution.md"]
        self.assertIn("## Live exploit path (red / purple)", solution)
        self.assertIn("## Log analysis path (blue / purple)", solution)
        self.assertNotIn("Indicators of compromise", solution)
        self.assertNotIn("Detection & response guidance", solution)
        description = files["public/description.md"]
        self.assertNotIn("## Deliverable", description)
        solver = files["private/solver.py"]
        self.assertIn("class ModbusClient", solver)
        self.assertIn('default="live"', solver)

    def test_blue_description_differs_from_red_and_is_defensive_framing(self) -> None:
        red = scada_ics.render(_spec(mode="red"), random.Random("mode-diff"))
        blue = scada_ics.render(_spec(mode="blue"), random.Random("mode-diff"))
        self.assertNotEqual(red["public/description.md"], blue["public/description.md"])
        blue_desc = blue["public/description.md"]
        self.assertIn("## Deliverable", blue_desc)
        self.assertIn("no live exploitation", blue_desc.lower())

    def test_purple_description_differs_from_red_and_covers_both_paths(self) -> None:
        red = scada_ics.render(_spec(mode="red"), random.Random("mode-diff"))
        purple = scada_ics.render(_spec(mode="purple"), random.Random("mode-diff"))
        self.assertNotEqual(red["public/description.md"], purple["public/description.md"])
        purple_desc = purple["public/description.md"]
        self.assertIn("## Deliverable", purple_desc)
        self.assertIn("either path", purple_desc.lower())

    def test_blue_private_deliverable_differs_from_red_and_has_no_offensive_solver(self) -> None:
        red = scada_ics.render(_spec(mode="red"), random.Random("mode-diff-2"))
        blue = scada_ics.render(_spec(mode="blue"), random.Random("mode-diff-2"))
        self.assertNotEqual(red["private/solution.md"], blue["private/solution.md"])
        self.assertNotEqual(red["private/solver.py"], blue["private/solver.py"])

        blue_solution = blue["private/solution.md"]
        self.assertIn("Indicators of compromise", blue_solution)
        self.assertIn("Recommended remediation", blue_solution)
        self.assertNotIn("## Live exploit path (red / purple)", blue_solution)

        blue_solver = blue["private/solver.py"]
        self.assertNotIn("ModbusClient", blue_solver)
        self.assertNotIn("solve_live", blue_solver)
        self.assertIn("def solve_from_log", blue_solver)
        compile(blue_solver, "private/solver.py", "exec")

    def test_purple_private_deliverable_differs_from_red_and_has_both_paths(self) -> None:
        red = scada_ics.render(_spec(mode="red"), random.Random("mode-diff-3"))
        purple = scada_ics.render(_spec(mode="purple"), random.Random("mode-diff-3"))
        self.assertNotEqual(red["private/solution.md"], purple["private/solution.md"])

        purple_solution = purple["private/solution.md"]
        self.assertIn("## Live exploit path (red / purple)", purple_solution)
        self.assertIn("## Log analysis path (blue / purple)", purple_solution)
        self.assertIn("Detection & response guidance (purple)", purple_solution)

        # Purple's flag is reachable via the same value from either path.
        self.assertEqual(
            json.loads(red["private/variant.json"])["flag"],
            json.loads(purple["private/variant.json"])["flag"],
        )

    def test_blue_solver_solves_from_the_rendered_evidence_log(self) -> None:
        """The blue-only solver is a real, runnable deliverable: given the
        rendered evidence log it must recover the exact flag, offline, with
        no live PLC/network access."""
        files = scada_ics.render(_spec(mode="blue"), random.Random("blue-solver-check"))
        variant = json.loads(files["private/variant.json"])
        namespace: dict[str, object] = {"__name__": "blue_solver_under_test"}
        exec(compile(files["private/solver.py"], "private/solver.py", "exec"), namespace)

        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "log.jsonl"
            log_path.write_text(files["public/evidence/register_write_log.jsonl"], encoding="utf-8")
            solved = namespace["solve_from_log"](log_path)  # type: ignore[operator]

        self.assertEqual(solved, variant["flag"])


if __name__ == "__main__":
    unittest.main()
