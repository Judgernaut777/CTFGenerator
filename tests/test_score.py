from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from ctf_generator.generator import create_challenge
from ctf_generator.models import ChallengeSpec, ResponseSpec, ScenarioSpec, TriggerSpec
from ctf_generator.score import score_challenge, score_with_agent_eval
from ctf_generator.spec_generator import default_spec


class ScoreTests(unittest.TestCase):
    def _generate(self, temp_dir: str) -> Path:
        output = Path(temp_dir) / "challenge"
        create_challenge(
            output_dir=output,
            seed="score-seed",
            title="Invoice Drift",
            difficulty="medium",
            family="web_business_logic_tenant_export",
        )
        return output

    def test_generated_challenge_scores_strong(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            report = score_challenge(self._generate(temp_dir))

            self.assertEqual(report.errors, [])
            self.assertEqual(len(report.dimensions), 5)
            self.assertAlmostEqual(
                sum(d.weight for d in report.dimensions), 1.0, places=6
            )
            self.assertGreaterEqual(report.total, 85.0)
            self.assertEqual(report.band, "strong")
            self.assertEqual(report.warnings, [])

    def test_dimensions_are_derived_from_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output = self._generate(temp_dir)
            report = score_challenge(output)
            names = {d.name for d in report.dimensions}
            self.assertEqual(
                names,
                {
                    "variant_uniqueness",
                    "statefulness",
                    "solver_depth",
                    "live_interaction",
                    "scanner_resistance",
                },
            )

    def test_missing_variant_produces_error(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output = self._generate(temp_dir)
            (output / "private/variant.json").unlink()
            report = score_challenge(output)
            self.assertTrue(report.errors)

    def test_statefulness_drops_without_worker(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output = self._generate(temp_dir)
            compose = output / "docker-compose.yml"
            compose.write_text(
                compose.read_text(encoding="utf-8").replace("worker:", "disabled:"),
                encoding="utf-8",
            )
            report = score_challenge(output)
            statefulness = next(d for d in report.dimensions if d.name == "statefulness")
            self.assertLess(statefulness.score, 100.0)
            self.assertTrue(
                any("hidden_sibling_validation" in w for w in report.warnings)
            )

    # --- Family-aware extensions ---------------------------------------------

    def test_byte_identical_to_pre_family_aware_baseline(self) -> None:
        """A non-scenario, non-CVE, web challenge scores byte-identically.

        Fixture captured from `score_challenge().to_mapping()` for the exact
        same seed/title/difficulty/family *before* the family-aware,
        CVE-provenance, and scenario_resistance changes in this module.
        """
        expected = {
            "total": 97.0,
            "band": "strong",
            "dimensions": [
                {
                    "name": "variant_uniqueness",
                    "weight": 0.25,
                    "score": 88.0,
                    "notes": [
                        "4/5 dynamic-variation dimensions enabled",
                        "11 per-instance route/token values in variant.json",
                    ],
                },
                {
                    "name": "statefulness",
                    "weight": 0.2,
                    "score": 100.0,
                    "notes": [
                        "background worker service: True",
                        "queue/state backend: True",
                        "solver drives async job state: True",
                    ],
                },
                {
                    "name": "solver_depth",
                    "weight": 0.2,
                    "score": 100.0,
                    "notes": [
                        "5 declared checkpoints (target 5)",
                        "9 distinct HTTP interactions in solver",
                    ],
                },
                {
                    "name": "live_interaction",
                    "weight": 0.15,
                    "score": 100.0,
                    "notes": [
                        "spec requires live interaction: True",
                        "solver discovers routes at runtime: True",
                        "solver polls a live endpoint: True",
                    ],
                },
                {
                    "name": "scanner_resistance",
                    "weight": 0.2,
                    "score": 100.0,
                    "notes": [
                        "generic scanner usefulness: low",
                        "decoy density: medium",
                    ],
                },
            ],
            "warnings": [],
            "errors": [],
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            report = score_challenge(self._generate(temp_dir))
            self.assertEqual(report.to_mapping(), expected)

    def test_cve_provenance_note_added_without_changing_score(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            baseline = score_challenge(self._generate(temp_dir))
            baseline_variant_uniqueness = next(
                d for d in baseline.dimensions if d.name == "variant_uniqueness"
            )

            spec = default_spec(
                seed="score-seed",
                title="Invoice Drift",
                difficulty="medium",
                family="web_business_logic_tenant_export",
            )
            spec = ChallengeSpec(
                title=spec.title,
                category=spec.category,
                difficulty=spec.difficulty,
                family=spec.family,
                seed=spec.seed,
                learning_objectives=spec.learning_objectives,
                checkpoints=spec.checkpoints,
                ai_resistance=spec.ai_resistance,
                dynamic_variation=spec.dynamic_variation,
                cve_refs=["CVE-2023-12345"],
            )
            output = Path(temp_dir) / "cve-challenge"
            create_challenge(
                output_dir=output,
                seed="score-seed",
                title="Invoice Drift",
                difficulty="medium",
                family="web_business_logic_tenant_export",
                spec=spec,
            )
            report = score_challenge(output)
            variant_uniqueness = next(
                d for d in report.dimensions if d.name == "variant_uniqueness"
            )

            # Score is unaffected -- this is a non-scoring provenance note.
            self.assertEqual(variant_uniqueness.score, baseline_variant_uniqueness.score)
            self.assertIn("CVE-grounded: CVE-2023-12345", variant_uniqueness.notes)
            self.assertEqual(report.total, baseline.total)
            self.assertEqual(report.band, baseline.band)
            self.assertEqual(len(report.dimensions), 5)

    def test_scenario_resistance_dimension_only_when_enabled(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base_spec = default_spec(
                seed="score-seed",
                title="Invoice Drift",
                difficulty="medium",
                family="web_business_logic_tenant_export",
            )
            scenario_spec = ChallengeSpec(
                title=base_spec.title,
                category=base_spec.category,
                difficulty=base_spec.difficulty,
                family=base_spec.family,
                seed=base_spec.seed,
                learning_objectives=base_spec.learning_objectives,
                checkpoints=base_spec.checkpoints,
                ai_resistance=base_spec.ai_resistance,
                dynamic_variation=base_spec.dynamic_variation,
                scenario=ScenarioSpec(
                    enabled=True,
                    triggers=[
                        TriggerSpec(
                            trigger_id="t1",
                            condition="checkpoint:queues_export_job",
                        ),
                        TriggerSpec(trigger_id="t2", condition="time:+120s"),
                    ],
                    responses=[
                        ResponseSpec(response_id="r1", action="reveal_hint"),
                    ],
                ),
            )
            output = Path(temp_dir) / "scenario-challenge"
            create_challenge(
                output_dir=output,
                seed="score-seed",
                title="Invoice Drift",
                difficulty="medium",
                family="web_business_logic_tenant_export",
                spec=scenario_spec,
            )
            report = score_challenge(output)

            names = {d.name for d in report.dimensions}
            self.assertIn("scenario_resistance", names)
            self.assertEqual(len(report.dimensions), 6)
            self.assertAlmostEqual(
                sum(d.weight for d in report.dimensions), 1.0, places=6
            )

            scenario_dim = next(
                d for d in report.dimensions if d.name == "scenario_resistance"
            )
            self.assertGreater(scenario_dim.score, 0.0)

            # Non-scenario dimensions unchanged (default challenge scores the
            # same generated files), just proportionally reweighted.
            variant_uniqueness = next(
                d for d in report.dimensions if d.name == "variant_uniqueness"
            )
            self.assertAlmostEqual(variant_uniqueness.weight, 0.25 * 0.85, places=6)

    def test_absent_scenario_leaves_dimensions_weights_total_band_unchanged(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            report = score_challenge(self._generate(temp_dir))
            names = {d.name for d in report.dimensions}
            self.assertNotIn("scenario_resistance", names)
            self.assertEqual(len(report.dimensions), 5)
            weights = {d.name: d.weight for d in report.dimensions}
            self.assertEqual(
                weights,
                {
                    "variant_uniqueness": 0.25,
                    "statefulness": 0.20,
                    "solver_depth": 0.20,
                    "live_interaction": 0.15,
                    "scanner_resistance": 0.20,
                },
            )


class ScoreWithAgentEvalTests(unittest.TestCase):
    def _generate(self, temp_dir: str) -> Path:
        output = Path(temp_dir) / "challenge"
        create_challenge(
            output_dir=output,
            seed="agent-eval-score-seed",
            title="Invoice Drift",
            difficulty="medium",
            family="web_business_logic_tenant_export",
        )
        return output

    def test_no_eval_report_path_returns_static_only(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output = self._generate(temp_dir)
            static_report = score_challenge(output)
            blended = score_with_agent_eval(output)
            self.assertEqual(blended["static"], static_report.to_mapping())
            self.assertIsNone(blended["agent_eval"])
            self.assertEqual(blended["blended_score"], static_report.to_mapping()["total"])

    def test_agent_eval_report_shape_blends_score(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output = self._generate(temp_dir)
            eval_report_path = Path(temp_dir) / "eval-report.json"
            eval_report_path.write_text(
                json.dumps(
                    {
                        "result": {
                            "profile": "writeup_replay",
                            "solved": False,
                            "steps": 4,
                            "elapsed_ticks": 4,
                            "notes": [],
                        }
                    }
                ),
                encoding="utf-8",
            )
            blended = score_with_agent_eval(output, eval_report_path)
            self.assertEqual(blended["agent_eval"]["kind"], "agent_eval")
            self.assertFalse(blended["agent_eval"]["solved"])
            static_total = blended["static"]["total"]
            self.assertAlmostEqual(
                blended["blended_score"], round(0.7 * static_total + 0.3 * 100.0, 1)
            )

    def test_adversarial_delta_report_shape_uses_adversarial_leg(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output = self._generate(temp_dir)
            eval_report_path = Path(temp_dir) / "delta-report.json"
            eval_report_path.write_text(
                json.dumps(
                    {
                        "result": {
                            "profile": "writeup_replay",
                            "baseline": {"solved": True, "steps": 2},
                            "adversarial": {"solved": False, "steps": 6},
                            "success_dropped": True,
                            "step_delta": 4,
                        }
                    }
                ),
                encoding="utf-8",
            )
            blended = score_with_agent_eval(output, eval_report_path)
            self.assertEqual(blended["agent_eval"]["kind"], "adversarial_delta")
            self.assertTrue(blended["agent_eval"]["baseline_solved"])
            self.assertFalse(blended["agent_eval"]["adversarial_solved"])
            self.assertTrue(blended["agent_eval"]["success_dropped"])
            static_total = blended["static"]["total"]
            self.assertAlmostEqual(
                blended["blended_score"], round(0.7 * static_total + 0.3 * 100.0, 1)
            )

    def test_missing_eval_report_file_warns_but_does_not_raise(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output = self._generate(temp_dir)
            missing = Path(temp_dir) / "does-not-exist.json"
            blended = score_with_agent_eval(output, missing)
            self.assertIsNone(blended["agent_eval"])
            self.assertTrue(any("could not read" in w for w in blended["warnings"]))

    def test_unrecognized_shape_warns(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output = self._generate(temp_dir)
            eval_report_path = Path(temp_dir) / "weird-report.json"
            eval_report_path.write_text(json.dumps({"result": {"nonsense": True}}), encoding="utf-8")
            blended = score_with_agent_eval(output, eval_report_path)
            self.assertIsNone(blended["agent_eval"])
            self.assertTrue(any("unrecognized shape" in w for w in blended["warnings"]))


if __name__ == "__main__":
    unittest.main()
