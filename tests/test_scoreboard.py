import json
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path

from ctf_generator import scoreboard
from ctf_generator.models import (
    ChallengeScoringConfig,
    CompetitionConfig,
    FirstBloodBonusConfig,
    SolveEvent,
)
from ctf_generator.scoring_engine import (
    DynamicDecayEngine,
    StaticPointsEngine,
    get_scoring_engine,
)

START = datetime(2026, 1, 1, 0, 0, 0)
END = datetime(2026, 1, 1, 10, 0, 0)  # 10-hour window


def make_config(**overrides) -> CompetitionConfig:
    kwargs = dict(
        competition_id="comp-1",
        name="Test Comp",
        start_time=START,
        end_time=END,
    )
    kwargs.update(overrides)
    return CompetitionConfig(**kwargs)


def make_challenge(challenge_id="web-1", **overrides) -> ChallengeScoringConfig:
    kwargs = dict(
        challenge_id=challenge_id,
        initial_value=500,
        minimum_value=100,
    )
    kwargs.update(overrides)
    return ChallengeScoringConfig(**kwargs)


def solve(team_id, challenge_id, when, submission_id="sub", instance_seed=None) -> SolveEvent:
    return SolveEvent(
        team_id=team_id,
        challenge_id=challenge_id,
        solved_at=when,
        submission_id=submission_id,
        instance_seed=instance_seed,
    )


class DeterminismTests(unittest.TestCase):
    def test_same_inputs_produce_identical_snapshot(self):
        config = make_config()
        challenges = {"web-1": make_challenge()}
        events = [
            solve("alpha", "web-1", START + timedelta(minutes=5), submission_id="s1"),
            solve("beta", "web-1", START + timedelta(minutes=10), submission_id="s2"),
        ]

        snap1 = scoreboard.compute_scoreboard(events, challenges, config)
        snap2 = scoreboard.compute_scoreboard(events, challenges, config)

        self.assertEqual(snap1.to_mapping(), snap2.to_mapping())

    def test_input_order_does_not_affect_output(self):
        config = make_config()
        challenges = {"web-1": make_challenge()}
        events = [
            solve("alpha", "web-1", START + timedelta(minutes=5), submission_id="s1"),
            solve("beta", "web-1", START + timedelta(minutes=10), submission_id="s2"),
        ]
        reversed_events = list(reversed(events))

        snap1 = scoreboard.compute_scoreboard(events, challenges, config)
        snap2 = scoreboard.compute_scoreboard(reversed_events, challenges, config)

        self.assertEqual(snap1.to_mapping(), snap2.to_mapping())


class DuplicateSolveTests(unittest.TestCase):
    """A team re-submitting an already-correct flag (double-click, retry,
    replayed event) must not inflate score or a challenge's solve_count."""

    def test_duplicate_solves_do_not_inflate_score(self):
        config = make_config()
        challenges = {"web-1": make_challenge()}
        engine = StaticPointsEngine()
        events = [
            solve("alpha", "web-1", START + timedelta(minutes=5), submission_id="s1"),
            solve("alpha", "web-1", START + timedelta(minutes=6), submission_id="s2"),
            solve("alpha", "web-1", START + timedelta(minutes=7), submission_id="s3"),
        ]

        snap = scoreboard.compute_scoreboard(events, challenges, config, engine)

        self.assertEqual(len(snap.entries), 1)
        self.assertEqual(snap.entries[0].score, 500)  # not 1500
        self.assertEqual(snap.entries[0].solve_count, 1)

    def test_duplicate_solves_do_not_inflate_challenge_value_solve_count(self):
        config = make_config()
        challenges = {"web-1": make_challenge()}
        events = [
            solve("alpha", "web-1", START + timedelta(minutes=5), submission_id="s1"),
            solve("alpha", "web-1", START + timedelta(minutes=6), submission_id="s2"),
        ]

        values = scoreboard.compute_challenge_values(
            events, challenges, config, DynamicDecayEngine()
        )
        by_id = {v.challenge_id: v for v in values}

        # One distinct solver, so decay reflects a single solve, not two.
        self.assertEqual(by_id["web-1"].solve_count, 1)

    def test_canonical_solve_is_the_earliest(self):
        config = make_config()
        challenges = {"web-1": make_challenge()}
        bonus = FirstBloodBonusConfig(enabled=True, bonus_points=50, bonus_percent=0)
        challenges["web-1"] = make_challenge(first_blood_bonus=bonus)
        # beta solves first; alpha's later duplicate must not steal first blood
        # nor add points twice.
        events = [
            solve("beta", "web-1", START + timedelta(minutes=1), submission_id="b1"),
            solve("alpha", "web-1", START + timedelta(minutes=5), submission_id="a1"),
            solve("alpha", "web-1", START + timedelta(minutes=9), submission_id="a2"),
        ]

        snap = scoreboard.compute_scoreboard(events, challenges, config, StaticPointsEngine())
        scores = {e.team_id: e.score for e in snap.entries}

        self.assertEqual(scores["beta"], 550)  # 500 + 50 first blood
        self.assertEqual(scores["alpha"], 500)  # single credit, no bonus


class RetroactiveDecayTests(unittest.TestCase):
    def test_dynamic_decay_value_is_shared_by_all_solvers(self):
        # linear decay: value drops from 500 to 100 over 4 solves.
        config = make_config()
        challenges = {
            "web-1": make_challenge(decay_function="linear", decay=4, minimum_value=100)
        }
        events = [
            solve("alpha", "web-1", START + timedelta(minutes=1), submission_id="s1"),
            solve("beta", "web-1", START + timedelta(minutes=2), submission_id="s2"),
        ]
        engine = DynamicDecayEngine()

        snap = scoreboard.compute_scoreboard(events, challenges, config, engine=engine)
        by_team = {e.team_id: e.score for e in snap.entries}

        # Both solves happened while solve_count was climbing (1 then 2), but
        # the *final* solve_count (2) determines the value applied to both,
        # retroactively -- so alpha and beta score identically.
        expected_value = engine.challenge_value(challenges["web-1"], 2, config, END)
        self.assertEqual(by_team["alpha"], round(expected_value))
        self.assertEqual(by_team["beta"], round(expected_value))
        self.assertEqual(by_team["alpha"], by_team["beta"])

    def test_more_solves_lowers_previously_awarded_value(self):
        config = make_config()
        challenges = {
            "web-1": make_challenge(decay_function="linear", decay=4, minimum_value=100)
        }
        engine = DynamicDecayEngine()
        one_solve = [solve("alpha", "web-1", START + timedelta(minutes=1), submission_id="s1")]
        two_solves = one_solve + [
            solve("beta", "web-1", START + timedelta(minutes=2), submission_id="s2")
        ]

        snap_one = scoreboard.compute_scoreboard(one_solve, challenges, config, engine=engine)
        snap_two = scoreboard.compute_scoreboard(two_solves, challenges, config, engine=engine)

        alpha_score_alone = next(e.score for e in snap_one.entries if e.team_id == "alpha")
        alpha_score_with_beta = next(e.score for e in snap_two.entries if e.team_id == "alpha")
        self.assertGreater(alpha_score_alone, alpha_score_with_beta)

    def test_time_decay_default_engine_used_when_none_passed(self):
        config = make_config()
        challenges = {"web-1": make_challenge(minimum_value=100)}
        # Solve right at the midpoint of the competition window; pin the
        # snapshot to that same moment via as_of so we can compare against
        # a hand-computed expected value instead of the fully-decayed
        # end-of-competition value.
        midpoint = START + timedelta(hours=5)
        events = [solve("alpha", "web-1", midpoint, submission_id="s1")]

        snap = scoreboard.compute_scoreboard(events, challenges, config, as_of=midpoint)
        engine = get_scoring_engine("time_decay")
        expected = engine.challenge_value(challenges["web-1"], 1, config, midpoint)

        self.assertEqual(snap.entries[0].score, round(expected))
        # Sanity: time_decay is genuinely decaying here (not static).
        self.assertLess(expected, 500)
        self.assertGreater(expected, 100)

    def test_as_of_none_uses_competition_end_time_as_the_render_moment(self):
        config = make_config()
        challenges = {"web-1": make_challenge(minimum_value=100)}
        events = [solve("alpha", "web-1", START + timedelta(hours=5), submission_id="s1")]

        snap = scoreboard.compute_scoreboard(events, challenges, config)

        # No as_of => the render moment is the competition's end_time, so a
        # linearly time-decaying challenge has fully bottomed out by then,
        # regardless of when it was actually solved (retroactive decay).
        self.assertEqual(snap.entries[0].score, 100)
        self.assertEqual(snap.generated_at, END)


class TieBreakTests(unittest.TestCase):
    def test_equal_score_orders_by_earliest_last_solve_then_team_id(self):
        config = make_config()
        challenges = {
            "web-1": make_challenge(first_blood_bonus=FirstBloodBonusConfig(enabled=False)),
            "web-2": make_challenge(
                challenge_id="web-2", first_blood_bonus=FirstBloodBonusConfig(enabled=False)
            ),
        }
        engine = StaticPointsEngine()
        # alpha and zulu both solve web-1 at the same timestamp; tie broken
        # deterministically by submission_id ("s1" < "s9" -> alpha is first
        # blood), but first_blood_bonus is disabled here so their scores are
        # equal and the *rank* tie is broken by last_solve_at then team_id.
        events = [
            solve("alpha", "web-1", START + timedelta(minutes=1), submission_id="s1"),
            solve("beta", "web-2", START + timedelta(minutes=2), submission_id="s2"),
            solve("zulu", "web-1", START + timedelta(minutes=1), submission_id="s9"),
        ]

        snap = scoreboard.compute_scoreboard(events, challenges, config, engine=engine)

        # alpha and zulu both score 500 (static) with last_solve_at at
        # minute 1 -- tie broken by team_id ("alpha" < "zulu").
        ranks = {e.team_id: e.rank for e in snap.entries}
        self.assertLess(ranks["alpha"], ranks["zulu"])
        self.assertEqual(snap.entries[0].team_id, "alpha")

    def test_earlier_last_solve_ranks_above_later_at_equal_score(self):
        config = make_config()
        # Two challenges of identical value, each solved by a different
        # (single-solve) team, so totals tie and only last_solve_at differs.
        challenges = {
            "web-1": make_challenge(first_blood_bonus=FirstBloodBonusConfig(enabled=False)),
            "web-2": make_challenge(
                challenge_id="web-2", first_blood_bonus=FirstBloodBonusConfig(enabled=False)
            ),
        }
        engine = StaticPointsEngine()
        events = [
            solve("early", "web-1", START + timedelta(minutes=1), submission_id="s1"),
            solve("late", "web-2", START + timedelta(minutes=50), submission_id="s2"),
        ]

        snap = scoreboard.compute_scoreboard(events, challenges, config, engine=engine)

        self.assertEqual(snap.entries[0].team_id, "early")
        self.assertEqual(snap.entries[1].team_id, "late")
        self.assertEqual(snap.entries[0].score, snap.entries[1].score)


class FirstBloodTests(unittest.TestCase):
    def test_earliest_solver_gets_bonus_points(self):
        config = make_config()
        challenges = {
            "web-1": make_challenge(
                initial_value=500,
                first_blood_bonus=FirstBloodBonusConfig(
                    enabled=True, bonus_points=50, bonus_percent=0.0
                ),
            )
        }
        engine = StaticPointsEngine()
        events = [
            solve("alpha", "web-1", START + timedelta(minutes=1), submission_id="s1"),
            solve("beta", "web-1", START + timedelta(minutes=2), submission_id="s2"),
        ]

        snap = scoreboard.compute_scoreboard(events, challenges, config, engine=engine)
        by_team = {e.team_id: e.score for e in snap.entries}

        self.assertEqual(by_team["alpha"], 550)
        self.assertEqual(by_team["beta"], 500)

    def test_bonus_percent_applies_to_current_challenge_value(self):
        config = make_config()
        challenges = {
            "web-1": make_challenge(
                initial_value=500,
                first_blood_bonus=FirstBloodBonusConfig(
                    enabled=True, bonus_points=0, bonus_percent=10.0
                ),
            )
        }
        engine = StaticPointsEngine()
        events = [solve("alpha", "web-1", START + timedelta(minutes=1), submission_id="s1")]

        snap = scoreboard.compute_scoreboard(events, challenges, config, engine=engine)

        self.assertEqual(snap.entries[0].score, 550)  # 500 + 10% of 500

    def test_disabled_bonus_awards_nothing_extra(self):
        config = make_config()
        challenges = {
            "web-1": make_challenge(
                initial_value=500,
                first_blood_bonus=FirstBloodBonusConfig(
                    enabled=False, bonus_points=999, bonus_percent=99.0
                ),
            )
        }
        engine = StaticPointsEngine()
        events = [solve("alpha", "web-1", START + timedelta(minutes=1), submission_id="s1")]

        snap = scoreboard.compute_scoreboard(events, challenges, config, engine=engine)

        self.assertEqual(snap.entries[0].score, 500)

    def test_only_the_earliest_solver_gets_the_bonus(self):
        config = make_config()
        challenges = {
            "web-1": make_challenge(
                initial_value=500,
                first_blood_bonus=FirstBloodBonusConfig(
                    enabled=True, bonus_points=50, bonus_percent=0.0
                ),
            )
        }
        engine = StaticPointsEngine()
        events = [
            solve("alpha", "web-1", START + timedelta(minutes=1), submission_id="s1"),
            solve("beta", "web-1", START + timedelta(minutes=2), submission_id="s2"),
            solve("gamma", "web-1", START + timedelta(minutes=3), submission_id="s3"),
        ]

        snap = scoreboard.compute_scoreboard(events, challenges, config, engine=engine)
        by_team = {e.team_id: e.score for e in snap.entries}

        self.assertEqual(by_team["alpha"], 550)
        self.assertEqual(by_team["beta"], 500)
        self.assertEqual(by_team["gamma"], 500)


class AsOfFilteringTests(unittest.TestCase):
    def test_solves_after_as_of_are_excluded(self):
        config = make_config()
        challenges = {"web-1": make_challenge()}
        engine = StaticPointsEngine()
        events = [
            solve("alpha", "web-1", START + timedelta(hours=1), submission_id="s1"),
            solve("beta", "web-1", START + timedelta(hours=5), submission_id="s2"),
        ]

        snap = scoreboard.compute_scoreboard(
            events, challenges, config, engine=engine, as_of=START + timedelta(hours=2)
        )

        team_ids = {e.team_id for e in snap.entries}
        self.assertEqual(team_ids, {"alpha"})
        self.assertTrue(snap.frozen)

    def test_as_of_none_includes_everything_and_is_not_frozen(self):
        config = make_config()
        challenges = {"web-1": make_challenge()}
        engine = StaticPointsEngine()
        events = [
            solve("alpha", "web-1", START + timedelta(hours=1), submission_id="s1"),
            solve("beta", "web-1", START + timedelta(hours=5), submission_id="s2"),
        ]

        snap = scoreboard.compute_scoreboard(events, challenges, config, engine=engine)

        team_ids = {e.team_id for e in snap.entries}
        self.assertEqual(team_ids, {"alpha", "beta"})
        self.assertFalse(snap.frozen)

    def test_as_of_affects_retroactive_solve_count_used_for_decay(self):
        config = make_config()
        challenges = {
            "web-1": make_challenge(decay_function="linear", decay=4, minimum_value=100)
        }
        engine = DynamicDecayEngine()
        events = [
            solve("alpha", "web-1", START + timedelta(minutes=1), submission_id="s1"),
            solve("beta", "web-1", START + timedelta(minutes=2), submission_id="s2"),
        ]

        early_snapshot = scoreboard.compute_scoreboard(
            events, challenges, config, engine=engine, as_of=START + timedelta(minutes=1, seconds=30)
        )
        full_snapshot = scoreboard.compute_scoreboard(events, challenges, config, engine=engine)

        alpha_early = next(e.score for e in early_snapshot.entries if e.team_id == "alpha")
        alpha_full = next(e.score for e in full_snapshot.entries if e.team_id == "alpha")
        self.assertGreater(alpha_early, alpha_full)


class ChallengeValueSnapshotTests(unittest.TestCase):
    def test_covers_challenges_with_no_solves_too(self):
        config = make_config()
        challenges = {
            "web-1": make_challenge(),
            "web-2": make_challenge(challenge_id="web-2"),
        }
        events = [solve("alpha", "web-1", START + timedelta(minutes=1), submission_id="s1")]

        snapshots = scoreboard.compute_challenge_values(events, challenges, config)
        by_id = {s.challenge_id: s for s in snapshots}

        self.assertEqual(by_id["web-1"].solve_count, 1)
        self.assertEqual(by_id["web-2"].solve_count, 0)

    def test_missing_challenge_falls_back_to_default_scoring(self):
        default = make_challenge(challenge_id="__default__", initial_value=200, minimum_value=200)
        config = make_config(default_scoring=default)
        challenges: dict = {}
        events = [solve("alpha", "unknown-chal", START + timedelta(minutes=1), submission_id="s1")]

        snap = scoreboard.compute_scoreboard(events, challenges, config, engine=StaticPointsEngine())

        self.assertEqual(snap.entries[0].score, 200)

    def test_missing_challenge_without_default_raises(self):
        config = make_config()
        events = [solve("alpha", "unknown-chal", START + timedelta(minutes=1), submission_id="s1")]

        with self.assertRaises(KeyError):
            scoreboard.compute_scoreboard(events, {}, config, engine=StaticPointsEngine())


class LoaderTests(unittest.TestCase):
    def test_load_events_round_trips_to_mapping(self):
        events = [
            solve("alpha", "web-1", START + timedelta(minutes=1), submission_id="s1"),
            solve("beta", "web-1", START + timedelta(minutes=2), submission_id="s2", instance_seed="seed-x"),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "events.json"
            path.write_text(json.dumps([e.to_mapping() for e in events]), encoding="utf-8")

            loaded = scoreboard.load_events(path)

        self.assertEqual(loaded, events)

    def test_load_challenges_round_trips_to_mapping(self):
        challenges = {
            "web-1": make_challenge(),
            "web-2": make_challenge(
                challenge_id="web-2",
                decay_function="linear",
                decay=10,
                first_blood_bonus=FirstBloodBonusConfig(
                    enabled=True, bonus_points=25, bonus_percent=5.0
                ),
            ),
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "challenges.json"
            path.write_text(
                json.dumps([c.to_mapping() for c in challenges.values()]), encoding="utf-8"
            )

            loaded = scoreboard.load_challenges(path)

        self.assertEqual(loaded, challenges)

    def test_load_competition_config_round_trips_to_mapping(self):
        config = make_config(
            scoring_start_time=START + timedelta(minutes=30),
            freeze_time=END - timedelta(minutes=30),
            default_scoring=make_challenge(challenge_id="__default__"),
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            path.write_text(json.dumps(config.to_mapping()), encoding="utf-8")

            loaded = scoreboard.load_competition_config(path)

        self.assertEqual(loaded, config)

    def test_load_competition_config_with_no_default_scoring(self):
        config = make_config()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            path.write_text(json.dumps(config.to_mapping()), encoding="utf-8")

            loaded = scoreboard.load_competition_config(path)

        self.assertEqual(loaded, config)
        self.assertIsNone(loaded.default_scoring)


if __name__ == "__main__":
    unittest.main()
