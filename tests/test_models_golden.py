from __future__ import annotations

import json
import unittest
from datetime import datetime

from ctf_generator.models import (
    AIResistance,
    ChallengeScoringConfig,
    ChallengeSpec,
    ChallengeValueSnapshot,
    CompetitionConfig,
    DynamicVariation,
    FirstBloodBonusConfig,
    ResponseSpec,
    ScenarioSpec,
    ScoreboardEntry,
    ScoreboardSnapshot,
    SolveEvent,
    Submission,
    TriggerSpec,
    solve_event_from_submission,
)

# The exact shape produced by ChallengeSpec.to_mapping() before this phase,
# plus the one always-emitted addition mandated by the cross-module contract
# (AIResistance.live_adversarial_engine). Any unintended change to default
# serialization -- key added, removed, renamed, or reordered -- should fail
# this test.
_GOLDEN_DEFAULT_MAPPING = {
    "meta": {
        "generator_version": "0.1.0",
        "spec_version": "1.0",
        "family": "web_business_logic_tenant_export",
        "seed": "abc123",
    },
    "title": "Invoice Drift",
    "category": "web",
    "difficulty": "medium",
    "family": "web_business_logic_tenant_export",
    "seed": "abc123",
    "learning_objectives": ["obj1"],
    "ai_resistance": {
        "novelty_target": "high",
        "min_solver_steps": 5,
        "require_live_interaction": True,
        "decoy_density": "medium",
        "generic_scanner_usefulness": "low",
        "hidden_sibling_validation": True,
        "live_adversarial_engine": False,
    },
    "dynamic_variation": {
        "per_user_schema": True,
        "per_user_routes": True,
        "per_user_seed_data": True,
        "per_user_auth_flow": False,
        "per_user_flag_path": True,
    },
    "checkpoints": [{"name": "first"}, {"name": "second"}],
    "validation": {
        "private_solver_required": True,
        "ai_agent_eval_required": False,
        "variant_static_validation_required": True,
    },
}


def _default_spec() -> ChallengeSpec:
    return ChallengeSpec(
        title="Invoice Drift",
        category="web",
        difficulty="medium",
        family="web_business_logic_tenant_export",
        seed="abc123",
        learning_objectives=["obj1"],
        checkpoints=["first", "second"],
    )


class DefaultChallengeSpecGoldenTests(unittest.TestCase):
    """Locks default (red, non-CVE, non-scenario) serialization."""

    def test_to_mapping_matches_golden_structure(self) -> None:
        spec = _default_spec()
        self.assertEqual(spec.to_mapping(), _GOLDEN_DEFAULT_MAPPING)

    def test_to_mapping_key_order_matches_golden_json(self) -> None:
        # dict insertion order is preserved through json.dumps, so this pins
        # byte-for-byte key ordering, not just set-equality of keys.
        spec = _default_spec()
        actual = json.dumps(spec.to_mapping(), indent=2, sort_keys=False)
        expected = json.dumps(_GOLDEN_DEFAULT_MAPPING, indent=2, sort_keys=False)
        self.assertEqual(actual, expected)

    def test_meta_mapping_unchanged_for_default(self) -> None:
        spec = _default_spec()
        self.assertEqual(spec.meta_mapping(), _GOLDEN_DEFAULT_MAPPING["meta"])

    def test_default_spec_has_new_fields_at_documented_defaults(self) -> None:
        spec = _default_spec()
        self.assertEqual(spec.cve_refs, [])
        self.assertIsNone(spec.cve_content_hash)
        self.assertEqual(spec.mode, "red")
        self.assertEqual(spec.scenario, ScenarioSpec())
        self.assertTrue(spec.scenario.is_default())

    def test_grown_fields_do_not_appear_when_default(self) -> None:
        mapping = _default_spec().to_mapping()
        self.assertNotIn("cve_refs", mapping)
        self.assertNotIn("cve_content_hash", mapping)
        self.assertNotIn("mode", mapping)
        self.assertNotIn("scenario", mapping)


class ConditionalGrownFieldEmissionTests(unittest.TestCase):
    def _spec_with(self, **overrides) -> ChallengeSpec:
        base = dict(
            title="Invoice Drift",
            category="web",
            difficulty="medium",
            family="web_business_logic_tenant_export",
            seed="abc123",
            learning_objectives=["obj1"],
            checkpoints=["first", "second"],
        )
        base.update(overrides)
        return ChallengeSpec(**base)

    def test_cve_refs_emitted_when_non_empty(self) -> None:
        spec = self._spec_with(cve_refs=["CVE-2023-12345"])
        mapping = spec.to_mapping()
        self.assertEqual(mapping["cve_refs"], ["CVE-2023-12345"])
        self.assertNotIn("cve_content_hash", mapping)
        self.assertNotIn("mode", mapping)
        self.assertNotIn("scenario", mapping)

    def test_cve_content_hash_emitted_when_set(self) -> None:
        spec = self._spec_with(cve_content_hash="deadbeef")
        mapping = spec.to_mapping()
        self.assertEqual(mapping["cve_content_hash"], "deadbeef")
        self.assertNotIn("cve_refs", mapping)

    def test_mode_emitted_when_non_red(self) -> None:
        spec = self._spec_with(mode="scenario")
        mapping = spec.to_mapping()
        self.assertEqual(mapping["mode"], "scenario")

    def test_scenario_emitted_when_enabled(self) -> None:
        scenario = ScenarioSpec(
            enabled=True,
            triggers=[TriggerSpec(trigger_id="t1", description="d", condition="c")],
            responses=[ResponseSpec(response_id="r1", action="reveal_hint")],
        )
        spec = self._spec_with(scenario=scenario)
        mapping = spec.to_mapping()
        self.assertEqual(
            mapping["scenario"],
            {
                "enabled": True,
                "triggers": [{"trigger_id": "t1", "description": "d", "condition": "c"}],
                "responses": [
                    {
                        "response_id": "r1",
                        "description": "",
                        "action": "reveal_hint",
                        "payload": {},
                    }
                ],
            },
        )

    def test_scenario_with_content_but_disabled_still_emits(self) -> None:
        # is_default() checks enabled OR triggers OR responses, so populated
        # triggers/responses on a disabled scenario still count as non-default.
        scenario = ScenarioSpec(triggers=[TriggerSpec(trigger_id="t1")])
        self.assertFalse(scenario.is_default())
        spec = self._spec_with(scenario=scenario)
        self.assertIn("scenario", spec.to_mapping())

    def test_unset_default_ai_resistance_and_dynamic_variation_untouched(self) -> None:
        spec = self._spec_with(cve_refs=["CVE-2023-12345"])
        self.assertEqual(spec.ai_resistance, AIResistance())
        self.assertEqual(spec.dynamic_variation, DynamicVariation())


class SubmissionAndSolveEventTests(unittest.TestCase):
    def test_solve_event_from_submission_copies_fields(self) -> None:
        ts = datetime(2026, 1, 1, 12, 0, 0)
        submission = Submission(
            submission_id="sub-1",
            team_id="team-a",
            challenge_id="chal-1",
            submitted_at=ts,
            correct=True,
            instance_seed="seed-xyz",
        )
        event = solve_event_from_submission(submission)
        self.assertEqual(
            event,
            SolveEvent(
                team_id="team-a",
                challenge_id="chal-1",
                solved_at=ts,
                submission_id="sub-1",
                instance_seed="seed-xyz",
            ),
        )

    def test_solve_event_from_submission_rejects_incorrect(self) -> None:
        submission = Submission(
            submission_id="sub-2",
            team_id="team-a",
            challenge_id="chal-1",
            submitted_at=datetime(2026, 1, 1),
            correct=False,
        )
        with self.assertRaises(ValueError):
            solve_event_from_submission(submission)

    def test_submission_to_mapping(self) -> None:
        ts = datetime(2026, 1, 1, 12, 0, 0)
        submission = Submission(
            submission_id="sub-1",
            team_id="team-a",
            challenge_id="chal-1",
            submitted_at=ts,
            correct=True,
        )
        self.assertEqual(
            submission.to_mapping(),
            {
                "submission_id": "sub-1",
                "team_id": "team-a",
                "challenge_id": "chal-1",
                "submitted_at": ts.isoformat(),
                "correct": True,
                "instance_seed": None,
            },
        )

    def test_submission_and_solve_event_are_frozen(self) -> None:
        submission = Submission(
            submission_id="sub-1",
            team_id="team-a",
            challenge_id="chal-1",
            submitted_at=datetime(2026, 1, 1),
            correct=True,
        )
        with self.assertRaises(Exception):
            submission.correct = False  # type: ignore[misc]


class ScoringDataclassSerializationTests(unittest.TestCase):
    def test_challenge_scoring_config_to_mapping(self) -> None:
        config = ChallengeScoringConfig(challenge_id="chal-1")
        mapping = config.to_mapping()
        self.assertEqual(mapping["challenge_id"], "chal-1")
        self.assertEqual(
            mapping["first_blood_bonus"], FirstBloodBonusConfig().to_mapping()
        )

    def test_competition_config_to_mapping_handles_optional_datetimes(self) -> None:
        start = datetime(2026, 1, 1)
        end = datetime(2026, 1, 2)
        config = CompetitionConfig(
            competition_id="comp-1", name="Spring CTF", start_time=start, end_time=end
        )
        mapping = config.to_mapping()
        self.assertEqual(mapping["start_time"], start.isoformat())
        self.assertEqual(mapping["end_time"], end.isoformat())
        self.assertIsNone(mapping["scoring_start_time"])
        self.assertIsNone(mapping["freeze_time"])
        self.assertIsNone(mapping["default_scoring"])

    def test_scoreboard_snapshot_to_mapping(self) -> None:
        generated_at = datetime(2026, 1, 1)
        entry = ScoreboardEntry(team_id="team-a", score=500, solve_count=1, rank=1)
        snapshot = ScoreboardSnapshot(
            competition_id="comp-1", generated_at=generated_at, entries=[entry]
        )
        mapping = snapshot.to_mapping()
        self.assertEqual(mapping["entries"], [entry.to_mapping()])
        self.assertFalse(mapping["frozen"])

    def test_challenge_value_snapshot_to_mapping(self) -> None:
        computed_at = datetime(2026, 1, 1)
        snapshot = ChallengeValueSnapshot(
            challenge_id="chal-1", value=450, solve_count=3, computed_at=computed_at
        )
        self.assertEqual(
            snapshot.to_mapping(),
            {
                "challenge_id": "chal-1",
                "value": 450,
                "solve_count": 3,
                "computed_at": computed_at.isoformat(),
            },
        )


if __name__ == "__main__":
    unittest.main()
