"""Host-pure unit tests for the projection domain value types (M7).

Stdlib only. The projector's end-to-end behavior (never skips a committed
event, poison isolation, rebuild) is proven by the Docker-gated
test_score_projection_integration suite.
"""

from __future__ import annotations

import unittest
from datetime import UTC, datetime

from ctf_generator.domain.ledger.models import (
    VALID_PROJECTION_TASK_STATUSES,
    ProjectionLag,
    ProjectionTask,
    ScoreboardProjectionRecord,
)

_NOW = datetime(2026, 7, 12, 12, 0, tzinfo=UTC)


class ProjectionTaskTests(unittest.TestCase):
    def test_valid_pending_task(self) -> None:
        t = ProjectionTask(
            seq=1, competition_id="cup", status="pending", attempts=0,
            created_at=_NOW,
        )
        self.assertIsNone(t.last_error)

    def test_rejects_bad_seq(self) -> None:
        for bad in (0, -1, "1"):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    ProjectionTask(
                        seq=bad, competition_id="cup", status="pending",
                        attempts=0, created_at=_NOW,
                    )

    def test_rejects_unknown_status(self) -> None:
        with self.assertRaises(ValueError):
            ProjectionTask(
                seq=1, competition_id="cup", status="done", attempts=0,
                created_at=_NOW,
            )
        self.assertEqual(VALID_PROJECTION_TASK_STATUSES, {"pending", "failed"})

    def test_rejects_negative_attempts(self) -> None:
        with self.assertRaises(ValueError):
            ProjectionTask(
                seq=1, competition_id="cup", status="failed", attempts=-1,
                created_at=_NOW,
            )


class ScoreboardProjectionRecordTests(unittest.TestCase):
    def test_valid_record(self) -> None:
        r = ScoreboardProjectionRecord(
            competition_id="cup", as_of_seq=0, entries={"entries": []}
        )
        self.assertEqual(r.as_of_seq, 0)

    def test_rejects_negative_as_of_seq(self) -> None:
        with self.assertRaises(ValueError):
            ScoreboardProjectionRecord(competition_id="cup", as_of_seq=-1)

    def test_entries_excluded_from_equality(self) -> None:
        a = ScoreboardProjectionRecord("cup", 5, entries={"x": 1})
        b = ScoreboardProjectionRecord("cup", 5, entries={"x": 2})
        self.assertEqual(a, b)


class ProjectionLagTests(unittest.TestCase):
    def test_valid_lag(self) -> None:
        lag = ProjectionLag(pending_count=0, latest_seq=10, max_as_of_seq=10)
        self.assertIsNone(lag.oldest_pending_created_at)

    def test_rejects_negatives(self) -> None:
        with self.assertRaises(ValueError):
            ProjectionLag(pending_count=-1, latest_seq=0, max_as_of_seq=0)
        with self.assertRaises(ValueError):
            ProjectionLag(pending_count=0, latest_seq=-1, max_as_of_seq=0)
        with self.assertRaises(ValueError):
            ProjectionLag(pending_count=0, latest_seq=0, max_as_of_seq=-1)


if __name__ == "__main__":
    unittest.main()
