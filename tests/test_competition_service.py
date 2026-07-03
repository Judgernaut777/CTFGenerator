from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from ctf_generator.competition_service import (
    ChallengeCatalog,
    ChallengeMeta,
    CompetitionService,
    TeamProgress,
    project_progress,
)
from ctf_generator.events import InMemoryEventStore
from ctf_generator.models import ChallengeScoringConfig, CompetitionConfig
from ctf_generator.scoring_engine import StaticPointsEngine

START = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
END = datetime(2026, 1, 1, 10, 0, 0, tzinfo=timezone.utc)


class ScriptedClock:
    """Fake Clock returning scripted epoch-seconds timestamps in sequence."""

    def __init__(self, timestamps: list[float]) -> None:
        self._timestamps = list(timestamps)
        self._index = 0

    def __call__(self) -> float:
        value = self._timestamps[self._index]
        self._index += 1
        return value


def make_config(**overrides) -> CompetitionConfig:
    kwargs = dict(
        competition_id="comp-1",
        name="Test Comp",
        start_time=START,
        end_time=END,
    )
    kwargs.update(overrides)
    return CompetitionConfig(**kwargs)


def make_catalog() -> ChallengeCatalog:
    return ChallengeCatalog.from_entries(
        {
            "web-1": ChallengeMeta(
                scoring=ChallengeScoringConfig(
                    challenge_id="web-1", initial_value=500, minimum_value=100
                ),
                title="Web One",
                category="web",
            ),
            "pwn-1": ChallengeMeta(
                scoring=ChallengeScoringConfig(
                    challenge_id="pwn-1", initial_value=400, minimum_value=100
                ),
                title="Pwn One",
                category="pwn",
            ),
        }
    )


# 1700000000 -> 2023-11-14T22:13:20+00:00, arbitrary but fixed epoch base
# used purely so ScriptedClock produces distinct, monotonic ISO timestamps.
BASE_EPOCH = 1700000000.0


class ChallengeCatalogTests(unittest.TestCase):
    def test_get_all_ids(self) -> None:
        catalog = make_catalog()

        self.assertEqual(catalog.ids(), ["pwn-1", "web-1"])
        self.assertEqual(catalog.get("web-1").title, "Web One")
        self.assertIsNone(catalog.get("missing"))
        self.assertEqual(set(catalog.all()), {"web-1", "pwn-1"})

    def test_scoring_configs_view(self) -> None:
        catalog = make_catalog()
        configs = catalog.scoring_configs()

        self.assertEqual(configs["web-1"].initial_value, 500)
        self.assertEqual(configs["pwn-1"].initial_value, 400)
        self.assertIsInstance(configs["web-1"], ChallengeScoringConfig)


class ProjectProgressTests(unittest.TestCase):
    def test_folds_solves_and_attempts_per_team(self) -> None:
        store = InMemoryEventStore(clock=ScriptedClock([BASE_EPOCH + i for i in range(5)]))
        store.append("attempt", "alpha", "web-1")
        store.append("solve", "alpha", "web-1", payload={"submission_id": "s1"})
        store.append("attempt", "bravo", "web-1")
        store.append("attempt", "bravo", "pwn-1")
        store.append("solve", "bravo", "pwn-1", payload={"submission_id": "s2"})

        progress = project_progress(store.all())

        self.assertEqual(set(progress), {"alpha", "bravo"})
        alpha = progress["alpha"]
        self.assertEqual(alpha.solved, ["web-1"])
        self.assertEqual(alpha.attempts, 2)  # 1 attempt + 1 solve
        self.assertEqual(alpha.display_name, "alpha")
        self.assertEqual(alpha.last_event_seq, 2)

        bravo = progress["bravo"]
        self.assertEqual(bravo.solved, ["pwn-1"])
        self.assertEqual(bravo.attempts, 3)
        self.assertEqual(bravo.last_event_seq, 5)

    def test_duplicate_solve_of_same_challenge_not_double_counted(self) -> None:
        store = InMemoryEventStore(clock=ScriptedClock([BASE_EPOCH + i for i in range(2)]))
        store.append("solve", "alpha", "web-1", payload={"submission_id": "s1"})
        store.append("solve", "alpha", "web-1", payload={"submission_id": "s2"})

        progress = project_progress(store.all())

        self.assertEqual(progress["alpha"].solved, ["web-1"])
        self.assertEqual(progress["alpha"].attempts, 2)

    def test_hint_events_advance_seq_but_not_attempts_or_solved(self) -> None:
        store = InMemoryEventStore(clock=ScriptedClock([BASE_EPOCH, BASE_EPOCH + 1]))
        store.append("hint", "alpha", "web-1")

        progress = project_progress(store.all())

        self.assertEqual(progress["alpha"].attempts, 0)
        self.assertEqual(progress["alpha"].solved, [])
        self.assertEqual(progress["alpha"].last_event_seq, 1)

    def test_pure_function_of_input_order(self) -> None:
        store = InMemoryEventStore(clock=ScriptedClock([BASE_EPOCH + i for i in range(3)]))
        store.append("attempt", "alpha", "web-1")
        store.append("solve", "alpha", "web-1", payload={"submission_id": "s1"})
        store.append("attempt", "bravo", "pwn-1")
        events_reversed = list(reversed(store.all()))

        forward = project_progress(store.all())
        backward = project_progress(events_reversed)

        self.assertEqual(forward["alpha"], backward["alpha"])
        self.assertEqual(forward["bravo"], backward["bravo"])


class CompetitionServiceTests(unittest.TestCase):
    def _service(self, teams: dict[str, str] | None = None) -> CompetitionService:
        store = InMemoryEventStore(clock=ScriptedClock([BASE_EPOCH + i for i in range(20)]))
        return CompetitionService(
            store=store,
            catalog=make_catalog(),
            config=make_config(),
            scoring_engine=StaticPointsEngine(),
            teams=teams or {},
        )

    def test_record_event_delegates_to_store_append(self) -> None:
        service = self._service()

        event = service.record_event("solve", "alpha", "web-1", payload={"submission_id": "s1"})

        self.assertEqual(event.seq, 1)
        self.assertEqual(event.type, "solve")
        self.assertEqual(event.team_id, "alpha")
        self.assertEqual(event.challenge_id, "web-1")
        self.assertEqual(service.store.latest_seq(), 1)

    def test_feed_since_returns_only_newer_events(self) -> None:
        service = self._service()
        service.record_event("attempt", "alpha", "web-1")
        service.record_event("solve", "alpha", "web-1", payload={"submission_id": "s1"})
        service.record_event("attempt", "bravo", "pwn-1")

        fed = service.feed_since(1)

        self.assertEqual([e.seq for e in fed], [2, 3])
        self.assertEqual(service.feed_since(0)[0].seq, 1)
        self.assertEqual(service.feed_since(3), [])

    def test_recording_solves_updates_progress_and_leaderboard(self) -> None:
        service = self._service(teams={"alpha": "Team Alpha", "bravo": "Team Bravo"})
        service.record_event("attempt", "alpha", "web-1")
        service.record_event("solve", "alpha", "web-1", payload={"submission_id": "s1"})
        service.record_event("solve", "bravo", "pwn-1", payload={"submission_id": "s2"})

        progress = service.progress()
        self.assertEqual(progress["alpha"].solved, ["web-1"])
        self.assertEqual(progress["alpha"].display_name, "Team Alpha")
        self.assertEqual(progress["bravo"].solved, ["pwn-1"])
        self.assertEqual(progress["bravo"].display_name, "Team Bravo")

        board = service.leaderboard()
        entries_by_team = {e.team_id: e for e in board.entries}
        self.assertEqual(entries_by_team["alpha"].score, 500)
        self.assertEqual(entries_by_team["bravo"].score, 400)
        self.assertEqual(entries_by_team["alpha"].solve_count, 1)
        # StaticPointsEngine -> ranked by score descending.
        self.assertEqual(board.entries[0].team_id, "alpha")
        self.assertEqual(board.entries[0].rank, 1)

    def test_public_leaderboard_exposes_only_redacted_fields(self) -> None:
        service = self._service(teams={"alpha": "Team Alpha", "bravo": "Team Bravo"})
        service.record_event("solve", "alpha", "web-1", payload={"submission_id": "s1"})
        service.record_event("solve", "bravo", "pwn-1", payload={"submission_id": "s2"})

        public = service.public_leaderboard()

        self.assertEqual(len(public), 2)
        for row in public:
            self.assertEqual(set(row), {"display_name", "rank", "score", "solve_count"})
            self.assertNotIn("team_id", row)
            self.assertNotIn("last_solve_at", row)
            self.assertNotIn("solved", row)
            self.assertNotIn("attempts", row)
            self.assertNotIn("flag", row)
            self.assertNotIn("payload", row)

        names = {row["display_name"] for row in public}
        self.assertEqual(names, {"Team Alpha", "Team Bravo"})
        top = next(row for row in public if row["rank"] == 1)
        self.assertEqual(top["display_name"], "Team Alpha")
        self.assertEqual(top["score"], 500)
        self.assertEqual(top["solve_count"], 1)

    def test_public_leaderboard_falls_back_to_team_id_when_unnamed(self) -> None:
        service = self._service(teams={})
        service.record_event("solve", "alpha", "web-1", payload={"submission_id": "s1"})

        public = service.public_leaderboard()

        self.assertEqual(public[0]["display_name"], "alpha")

    def test_feed_since_does_not_leak_into_progress_of_unrelated_calls(self) -> None:
        service = self._service()
        service.record_event("solve", "alpha", "web-1", payload={"submission_id": "s1"})

        # progress() always reflects the full log regardless of feed polling.
        service.feed_since(0)
        progress = service.progress()

        self.assertEqual(progress["alpha"].solved, ["web-1"])


class TimeDecayLeaderboardDeterminismTests(unittest.TestCase):
    def test_time_decay_leaderboard_is_deterministic(self) -> None:
        # No explicit scoring_engine -> defaults to time_decay.
        store = InMemoryEventStore(clock=ScriptedClock([BASE_EPOCH + i for i in range(3)]))
        service = CompetitionService(
            store=store,
            catalog=make_catalog(),
            config=make_config(),
        )
        service.record_event(
            "solve",
            "alpha",
            "web-1",
            payload={"submission_id": "s1"},
        )
        # Force a specific, known solved_at by recording a solve then reading
        # the leaderboard "as of" a fixed point mid-competition.
        as_of = START + timedelta(hours=5)

        first = service.leaderboard(as_of=as_of)
        second = service.leaderboard(as_of=as_of)

        self.assertEqual(first.to_mapping(), second.to_mapping())
        self.assertTrue(first.frozen)
        entry = first.entries[0]
        # Half the decay window elapsed -> value should sit strictly between
        # the floor and the initial value (not equal to either).
        self.assertLess(entry.score, 500)
        self.assertGreater(entry.score, 100)


class TeamProgressDataclassTests(unittest.TestCase):
    def test_defaults(self) -> None:
        progress = TeamProgress(team_id="alpha", display_name="Alpha")

        self.assertEqual(progress.solved, [])
        self.assertEqual(progress.attempts, 0)
        self.assertEqual(progress.last_event_seq, 0)


if __name__ == "__main__":
    unittest.main()
