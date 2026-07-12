"""Pure unit tests for the ledger domain value types (host-runnable, stdlib)."""

from __future__ import annotations

import unittest
from datetime import UTC, datetime

from ctf_generator.domain.ledger.models import (
    VALID_SCORE_EVENT_TYPES,
    LedgerSubmission,
    ScoreEvent,
    Solve,
)

_TS = datetime(2026, 6, 1, tzinfo=UTC)


def _submission(**kw):
    base = dict(
        submission_id="s1",
        competition_id="cup",
        team_name="Red",
        definition_slug="sql",
        version_no=1,
        submitted_at=_TS,
        correct=True,
    )
    base.update(kw)
    return LedgerSubmission(**base)


class LedgerSubmissionTests(unittest.TestCase):
    def test_valid(self) -> None:
        self.assertTrue(_submission().correct)

    def test_rejects_empty_and_bad_version(self) -> None:
        with self.assertRaises(ValueError):
            _submission(submission_id="")
        with self.assertRaises(ValueError):
            _submission(team_name=" ")
        with self.assertRaises(ValueError):
            _submission(version_no=0)

    def test_correct_must_be_bool(self) -> None:
        with self.assertRaises(ValueError):
            _submission(correct="yes")


class SolveTests(unittest.TestCase):
    def test_valid(self) -> None:
        Solve(
            solve_id="v1",
            competition_id="cup",
            team_name="Red",
            definition_slug="sql",
            version_no=1,
            submission_id="s1",
            solved_at=_TS,
        )

    def test_rejects_empty_submission(self) -> None:
        with self.assertRaises(ValueError):
            Solve(
                solve_id="v1",
                competition_id="cup",
                team_name="Red",
                definition_slug="sql",
                version_no=1,
                submission_id="",
                solved_at=_TS,
            )


class ScoreEventTests(unittest.TestCase):
    def _event(self, **kw) -> ScoreEvent:
        base = dict(
            competition_id="cup",
            team_name="Red",
            definition_slug="sql",
            version_no=1,
            type="solve",
            ts="2026-06-01T00:00:00Z",
        )
        base.update(kw)
        return ScoreEvent(**base)

    def test_valid_and_seq_optional(self) -> None:
        self.assertIsNone(self._event().seq)
        self.assertEqual(self._event(seq=5).seq, 5)

    def test_all_valid_types(self) -> None:
        for t in VALID_SCORE_EVENT_TYPES:
            self.assertEqual(self._event(type=t).type, t)

    def test_bad_type_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self._event(type="bogus")

    def test_bad_seq_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self._event(seq=0)

    def test_empty_provenance_ids_rejected(self) -> None:
        # None is allowed (absent link); "" is a malformed id, not "absent".
        self.assertIsNone(self._event().submission_id)
        with self.assertRaises(ValueError):
            self._event(submission_id="")
        with self.assertRaises(ValueError):
            self._event(solve_id="  ")

    def test_payload_excluded_from_equality_and_hashable(self) -> None:
        a = self._event(payload={"x": 1})
        b = self._event(payload={"x": 2})
        self.assertEqual(a, b)
        self.assertEqual(len({a, b}), 1)


if __name__ == "__main__":
    unittest.main()
