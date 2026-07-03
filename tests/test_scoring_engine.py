from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from ctf_generator.events import Event
from ctf_generator.models import (
    ChallengeScoringConfig,
    CompetitionConfig,
    FirstBloodBonusConfig,
)
from ctf_generator.scoring_engine import (
    AIResistanceWeightedEngine,
    DynamicDecayEngine,
    StaticPointsEngine,
    TimeDecayEngine,
    get_scoring_engine,
    list_scoring_engines,
    register_scoring_engine,
    solve_event_from_event,
    validate_competition_config,
)


def _challenge(**overrides: object) -> ChallengeScoringConfig:
    defaults: dict[str, object] = dict(
        challenge_id="chal-1",
        initial_value=500,
        minimum_value=100,
        decay_function="static",
        decay=0,
    )
    defaults.update(overrides)
    return ChallengeScoringConfig(**defaults)  # type: ignore[arg-type]


def _competition(**overrides: object) -> CompetitionConfig:
    defaults: dict[str, object] = dict(
        competition_id="comp-1",
        name="Test Comp",
        start_time=datetime(2026, 1, 1, tzinfo=timezone.utc),
        end_time=datetime(2026, 1, 2, tzinfo=timezone.utc),
    )
    defaults.update(overrides)
    return CompetitionConfig(**defaults)  # type: ignore[arg-type]


class StaticPointsEngineTests(unittest.TestCase):
    def test_name(self) -> None:
        self.assertEqual(StaticPointsEngine.name, "static")

    def test_constant_regardless_of_solve_count_or_time(self) -> None:
        engine = StaticPointsEngine()
        challenge = _challenge(initial_value=500, minimum_value=100)
        competition = _competition()

        for solve_count, now in [
            (0, competition.start_time),
            (1, competition.start_time),
            (500, competition.end_time),
            (500, competition.end_time + timedelta(days=365)),
        ]:
            self.assertEqual(
                engine.challenge_value(challenge, solve_count, competition, now),
                500.0,
            )


class DynamicDecayEngineTests(unittest.TestCase):
    def test_name(self) -> None:
        self.assertEqual(DynamicDecayEngine.name, "dynamic_decay")

    def test_static_decay_function_never_decays(self) -> None:
        engine = DynamicDecayEngine()
        challenge = _challenge(decay_function="static", decay=10)
        competition = _competition()
        now = competition.start_time

        self.assertEqual(engine.challenge_value(challenge, 0, competition, now), 500.0)
        self.assertEqual(engine.challenge_value(challenge, 1000, competition, now), 500.0)

    def test_decay_zero_or_negative_never_decays_even_with_curve_set(self) -> None:
        engine = DynamicDecayEngine()
        competition = _competition()
        now = competition.start_time

        for decay_function in ("linear", "logarithmic"):
            challenge = _challenge(decay_function=decay_function, decay=0)
            self.assertEqual(
                engine.challenge_value(challenge, 50, competition, now), 500.0
            )

    def test_linear_decay_at_zero_solves_is_initial_value(self) -> None:
        engine = DynamicDecayEngine()
        challenge = _challenge(
            initial_value=500, minimum_value=100, decay_function="linear", decay=10
        )
        competition = _competition()
        now = competition.start_time

        self.assertEqual(engine.challenge_value(challenge, 0, competition, now), 500.0)

    def test_linear_decay_midpoint(self) -> None:
        engine = DynamicDecayEngine()
        challenge = _challenge(
            initial_value=500, minimum_value=100, decay_function="linear", decay=10
        )
        competition = _competition()
        now = competition.start_time

        # Halfway through the decay window (5/10 solves): halfway from 500 to 100.
        value = engine.challenge_value(challenge, 5, competition, now)
        self.assertAlmostEqual(value, 300.0)

    def test_linear_decay_floors_at_minimum_beyond_decay_solves(self) -> None:
        engine = DynamicDecayEngine()
        challenge = _challenge(
            initial_value=500, minimum_value=100, decay_function="linear", decay=10
        )
        competition = _competition()
        now = competition.start_time

        self.assertEqual(engine.challenge_value(challenge, 10, competition, now), 100.0)
        self.assertEqual(engine.challenge_value(challenge, 10_000, competition, now), 100.0)

    def test_logarithmic_decay_at_zero_solves_is_initial_value(self) -> None:
        engine = DynamicDecayEngine()
        challenge = _challenge(
            initial_value=500, minimum_value=100, decay_function="logarithmic", decay=10
        )
        competition = _competition()
        now = competition.start_time

        self.assertEqual(engine.challenge_value(challenge, 0, competition, now), 500.0)

    def test_logarithmic_decay_at_decay_solves_hits_minimum(self) -> None:
        engine = DynamicDecayEngine()
        challenge = _challenge(
            initial_value=500, minimum_value=100, decay_function="logarithmic", decay=10
        )
        competition = _competition()
        now = competition.start_time

        # ((100 - 500) / 10**2) * 10**2 + 500 == -400 + 500 == 100
        self.assertAlmostEqual(
            engine.challenge_value(challenge, 10, competition, now), 100.0
        )

    def test_logarithmic_decay_floors_at_minimum_for_many_solves(self) -> None:
        engine = DynamicDecayEngine()
        challenge = _challenge(
            initial_value=500, minimum_value=100, decay_function="logarithmic", decay=10
        )
        competition = _competition()
        now = competition.start_time

        self.assertEqual(
            engine.challenge_value(challenge, 100_000, competition, now), 100.0
        )

    def test_unrecognized_decay_function_behaves_like_static(self) -> None:
        engine = DynamicDecayEngine()
        challenge = _challenge(decay_function="quadratic", decay=10)
        competition = _competition()
        now = competition.start_time

        self.assertEqual(engine.challenge_value(challenge, 5, competition, now), 500.0)


class TimeDecayEngineTests(unittest.TestCase):
    def test_name(self) -> None:
        self.assertEqual(TimeDecayEngine.name, "time_decay")

    def test_default_engine_is_time_decay(self) -> None:
        engine = get_scoring_engine()
        self.assertIsInstance(engine, TimeDecayEngine)
        self.assertEqual(get_scoring_engine("time_decay"), engine)

    def test_at_start_time_value_is_initial(self) -> None:
        engine = TimeDecayEngine()
        challenge = _challenge(initial_value=500, minimum_value=100)
        competition = _competition()

        value = engine.challenge_value(challenge, 0, competition, competition.start_time)
        self.assertEqual(value, 500.0)

    def test_before_start_time_value_is_still_initial(self) -> None:
        engine = TimeDecayEngine()
        challenge = _challenge(initial_value=500, minimum_value=100)
        competition = _competition()
        now = competition.start_time - timedelta(hours=1)

        value = engine.challenge_value(challenge, 0, competition, now)
        self.assertEqual(value, 500.0)

    def test_at_end_time_value_is_minimum(self) -> None:
        engine = TimeDecayEngine()
        challenge = _challenge(initial_value=500, minimum_value=100)
        competition = _competition()

        value = engine.challenge_value(challenge, 0, competition, competition.end_time)
        self.assertEqual(value, 100.0)

    def test_far_past_end_time_value_stays_at_minimum(self) -> None:
        engine = TimeDecayEngine()
        challenge = _challenge(initial_value=500, minimum_value=100)
        competition = _competition()
        now = competition.end_time + timedelta(days=365)

        value = engine.challenge_value(challenge, 0, competition, now)
        self.assertEqual(value, 100.0)

    def test_midpoint_value_is_halfway(self) -> None:
        engine = TimeDecayEngine()
        challenge = _challenge(initial_value=500, minimum_value=100)
        competition = _competition()
        midpoint = competition.start_time + (competition.end_time - competition.start_time) / 2

        value = engine.challenge_value(challenge, 0, competition, midpoint)
        self.assertAlmostEqual(value, 300.0)

    def test_uses_scoring_start_time_when_set(self) -> None:
        engine = TimeDecayEngine()
        challenge = _challenge(initial_value=500, minimum_value=100)
        scoring_start = datetime(2026, 1, 1, 12, tzinfo=timezone.utc)
        competition = _competition(scoring_start_time=scoring_start)

        # Before scoring_start_time (but after start_time): still initial.
        value = engine.challenge_value(
            challenge, 0, competition, scoring_start - timedelta(minutes=1)
        )
        self.assertEqual(value, 500.0)

    def test_freeze_time_caps_effective_clock(self) -> None:
        engine = TimeDecayEngine()
        challenge = _challenge(initial_value=500, minimum_value=100)
        freeze = datetime(2026, 1, 1, 12, tzinfo=timezone.utc)  # exact midpoint
        competition = _competition(freeze_time=freeze)

        at_freeze = engine.challenge_value(challenge, 0, competition, freeze)
        long_after_freeze = engine.challenge_value(
            challenge, 0, competition, competition.end_time + timedelta(days=30)
        )
        self.assertAlmostEqual(at_freeze, 300.0)
        self.assertEqual(at_freeze, long_after_freeze)

    def test_degenerate_zero_length_window_returns_initial_value(self) -> None:
        engine = TimeDecayEngine()
        same = datetime(2026, 1, 1, tzinfo=timezone.utc)
        challenge = _challenge(initial_value=500, minimum_value=100)
        competition = _competition(start_time=same, end_time=same)

        value = engine.challenge_value(challenge, 0, competition, same)
        self.assertEqual(value, 500.0)

    def test_ignores_solve_count(self) -> None:
        engine = TimeDecayEngine()
        challenge = _challenge(initial_value=500, minimum_value=100)
        competition = _competition()

        low = engine.challenge_value(challenge, 0, competition, competition.start_time)
        high = engine.challenge_value(challenge, 999, competition, competition.start_time)
        self.assertEqual(low, high)


class AIResistanceWeightedEngineTests(unittest.TestCase):
    def test_name(self) -> None:
        self.assertEqual(AIResistanceWeightedEngine.name, "ai_resistance")

    def test_default_weight_one_is_passthrough_over_base(self) -> None:
        engine = AIResistanceWeightedEngine(base_engine=StaticPointsEngine())
        challenge = _challenge(initial_value=500)
        competition = _competition()

        value = engine.challenge_value(challenge, 0, competition, competition.start_time)
        self.assertEqual(value, 500.0)

    def test_configured_weight_scales_base_value(self) -> None:
        engine = AIResistanceWeightedEngine(
            weights={"chal-1": 1.5}, base_engine=StaticPointsEngine()
        )
        challenge = _challenge(initial_value=500, challenge_id="chal-1")
        competition = _competition()

        value = engine.challenge_value(challenge, 0, competition, competition.start_time)
        self.assertEqual(value, 750.0)

    def test_unweighted_challenge_falls_back_to_default_weight(self) -> None:
        engine = AIResistanceWeightedEngine(
            weights={"other-chal": 2.0},
            default_weight=0.5,
            base_engine=StaticPointsEngine(),
        )
        challenge = _challenge(initial_value=500, challenge_id="chal-1")
        competition = _competition()

        value = engine.challenge_value(challenge, 0, competition, competition.start_time)
        self.assertEqual(value, 250.0)

    def test_wraps_time_decay_engine_by_default_construction(self) -> None:
        # No base_engine given: default is StaticPointsEngine, and default
        # weight is 1.0, so it should equal the static engine's own value.
        engine = AIResistanceWeightedEngine()
        challenge = _challenge(initial_value=500)
        competition = _competition()

        value = engine.challenge_value(challenge, 0, competition, competition.start_time)
        self.assertEqual(value, 500.0)


class RegistryTests(unittest.TestCase):
    def test_list_scoring_engines_includes_all_four_builtins(self) -> None:
        names = list_scoring_engines()
        for expected in ("static", "dynamic_decay", "time_decay", "ai_resistance"):
            self.assertIn(expected, names)

    def test_list_scoring_engines_is_sorted(self) -> None:
        self.assertEqual(list_scoring_engines(), sorted(list_scoring_engines()))

    def test_get_scoring_engine_default_is_time_decay(self) -> None:
        self.assertEqual(get_scoring_engine().name, "time_decay")

    def test_get_scoring_engine_unknown_name_raises_keyerror(self) -> None:
        with self.assertRaises(KeyError):
            get_scoring_engine("does_not_exist")

    def test_register_scoring_engine_adds_and_replaces(self) -> None:
        class CustomEngine:
            name = "custom_test_engine"

            def challenge_value(self, challenge, solve_count, competition, now):
                return 42.0

        register_scoring_engine(CustomEngine())
        try:
            self.assertIn("custom_test_engine", list_scoring_engines())
            engine = get_scoring_engine("custom_test_engine")
            challenge = _challenge()
            competition = _competition()
            self.assertEqual(
                engine.challenge_value(challenge, 0, competition, competition.start_time),
                42.0,
            )

            # Re-registering under the same name replaces, not appends.
            class ReplacementEngine:
                name = "custom_test_engine"

                def challenge_value(self, challenge, solve_count, competition, now):
                    return 99.0

            register_scoring_engine(ReplacementEngine())
            replaced = get_scoring_engine("custom_test_engine")
            self.assertEqual(
                replaced.challenge_value(
                    challenge, 0, competition, competition.start_time
                ),
                99.0,
            )
            self.assertEqual(
                list_scoring_engines().count("custom_test_engine"), 1
            )
        finally:
            from ctf_generator import scoring_engine as scoring_engine_module

            scoring_engine_module._REGISTRY.pop("custom_test_engine", None)


class ValidateCompetitionConfigTests(unittest.TestCase):
    def test_valid_config_returns_no_errors(self) -> None:
        competition = _competition()
        self.assertEqual(validate_competition_config(competition), [])

    def test_end_before_start_is_an_error(self) -> None:
        competition = _competition(
            start_time=datetime(2026, 1, 2, tzinfo=timezone.utc),
            end_time=datetime(2026, 1, 1, tzinfo=timezone.utc),
        )
        errors = validate_competition_config(competition)
        self.assertTrue(any("end_time" in e for e in errors))

    def test_end_equals_start_is_an_error(self) -> None:
        same = datetime(2026, 1, 1, tzinfo=timezone.utc)
        competition = _competition(start_time=same, end_time=same)
        errors = validate_competition_config(competition)
        self.assertTrue(any("end_time" in e for e in errors))

    def test_scoring_start_time_outside_window_is_an_error(self) -> None:
        competition = _competition(
            scoring_start_time=datetime(2025, 12, 31, tzinfo=timezone.utc)
        )
        errors = validate_competition_config(competition)
        self.assertTrue(any("scoring_start_time" in e for e in errors))

    def test_scoring_start_time_after_end_is_an_error(self) -> None:
        competition = _competition(
            scoring_start_time=datetime(2026, 1, 3, tzinfo=timezone.utc)
        )
        errors = validate_competition_config(competition)
        self.assertTrue(any("scoring_start_time" in e for e in errors))

    def test_scoring_start_time_within_window_is_fine(self) -> None:
        competition = _competition(
            scoring_start_time=datetime(2026, 1, 1, 6, tzinfo=timezone.utc)
        )
        self.assertEqual(validate_competition_config(competition), [])

    def test_freeze_time_outside_window_is_an_error(self) -> None:
        competition = _competition(
            freeze_time=datetime(2025, 12, 31, tzinfo=timezone.utc)
        )
        errors = validate_competition_config(competition)
        self.assertTrue(any("freeze_time" in e for e in errors))

    def test_default_scoring_minimum_exceeds_initial_is_an_error(self) -> None:
        competition = _competition(
            default_scoring=_challenge(initial_value=100, minimum_value=500)
        )
        errors = validate_competition_config(competition)
        self.assertTrue(any("minimum_value" in e for e in errors))

    def test_default_scoring_negative_values_are_errors(self) -> None:
        competition = _competition(
            default_scoring=_challenge(initial_value=-1, minimum_value=-1)
        )
        errors = validate_competition_config(competition)
        self.assertTrue(any("initial_value must not be negative" in e for e in errors))
        self.assertTrue(any("minimum_value must not be negative" in e for e in errors))

    def test_default_scoring_bad_decay_function_is_an_error(self) -> None:
        competition = _competition(
            default_scoring=_challenge(decay_function="exponential")
        )
        errors = validate_competition_config(competition)
        self.assertTrue(any("decay_function" in e for e in errors))

    def test_default_scoring_negative_decay_is_an_error(self) -> None:
        competition = _competition(default_scoring=_challenge(decay=-5))
        errors = validate_competition_config(competition)
        self.assertTrue(any("decay must not be negative" in e for e in errors))

    def test_default_scoring_negative_bonus_points_is_an_error(self) -> None:
        challenge = _challenge(
            first_blood_bonus=FirstBloodBonusConfig(bonus_points=-10)
        )
        competition = _competition(default_scoring=challenge)
        errors = validate_competition_config(competition)
        self.assertTrue(any("bonus_points" in e for e in errors))

    def test_default_scoring_bonus_percent_out_of_range_is_an_error(self) -> None:
        challenge = _challenge(
            first_blood_bonus=FirstBloodBonusConfig(bonus_percent=150.0)
        )
        competition = _competition(default_scoring=challenge)
        errors = validate_competition_config(competition)
        self.assertTrue(any("bonus_percent" in e for e in errors))

    def test_default_scoring_none_skips_challenge_validation(self) -> None:
        competition = _competition(default_scoring=None)
        self.assertEqual(validate_competition_config(competition), [])


class SolveEventFromEventTests(unittest.TestCase):
    def test_non_solve_event_returns_none(self) -> None:
        event = Event(
            seq=1,
            ts="2026-01-01T00:00:00+00:00",
            type="team_join",
            team_id="team-1",
            challenge_id="chal-1",
            payload={},
        )
        self.assertIsNone(solve_event_from_event(event))

    def test_solve_event_maps_all_fields(self) -> None:
        event = Event(
            seq=5,
            ts="2026-01-01T12:34:56+00:00",
            type="solve",
            team_id="team-1",
            challenge_id="chal-1",
            payload={"submission_id": "sub-9", "instance_seed": "seed-abc"},
        )

        solve = solve_event_from_event(event)

        self.assertIsNotNone(solve)
        assert solve is not None
        self.assertEqual(solve.team_id, "team-1")
        self.assertEqual(solve.challenge_id, "chal-1")
        self.assertEqual(solve.solved_at, datetime.fromisoformat(event.ts))
        self.assertEqual(solve.submission_id, "sub-9")
        self.assertEqual(solve.instance_seed, "seed-abc")

    def test_solve_event_missing_submission_id_defaults_to_empty_string(self) -> None:
        event = Event(
            seq=1,
            ts="2026-01-01T00:00:00+00:00",
            type="solve",
            team_id="team-1",
            challenge_id="chal-1",
            payload={},
        )

        solve = solve_event_from_event(event)

        assert solve is not None
        self.assertEqual(solve.submission_id, "")
        self.assertIsNone(solve.instance_seed)

    def test_other_event_types_all_return_none(self) -> None:
        for event_type in ("flag_submit_incorrect", "hint_used", "team_join", ""):
            event = Event(
                seq=1,
                ts="2026-01-01T00:00:00+00:00",
                type=event_type,
                team_id="team-1",
                challenge_id="chal-1",
                payload={},
            )
            self.assertIsNone(solve_event_from_event(event))


if __name__ == "__main__":
    unittest.main()
