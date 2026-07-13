"""Host (offline, stdlib-only) tests for the EvalRun domain aggregate + the
service-layer secret-free projection helpers (M15 slice 15a).

Proves, WITHOUT a database:

* the state/timestamp/result invariants of :class:`EvalRun`;
* SECRET-FREE by construction -- the aggregate has NO flag/token/answer field;
* the sanitizer redacts a planted ``ctf{...}`` token from notes/error;
* :data:`VALID_EVAL_PROFILES` does not drift from ``agent_eval.EVAL_PROFILES``.
"""

from __future__ import annotations

import dataclasses
import unittest
from datetime import UTC, datetime

from ctf_generator.domain.evaluation.models import (
    LEGAL_EVAL_TRANSITIONS,
    TERMINAL_EVAL_RUN_STATUSES,
    VALID_EVAL_PROFILES,
    EvalRun,
)

_NOW = datetime(2026, 7, 13, 12, 0, tzinfo=UTC)
_DONE = datetime(2026, 7, 13, 12, 5, tzinfo=UTC)


def _pending(**over) -> EvalRun:
    base = dict(
        eval_run_id="11111111-1111-1111-1111-111111111111",
        definition_slug="sqli",
        version_no=1,
        profile="writeup_replay",
        adversarial=False,
        status="pending",
        requested_at=_NOW,
    )
    base.update(over)
    return EvalRun(**base)


class EvalRunAggregateTests(unittest.TestCase):
    def test_pending_has_no_result_or_completion(self) -> None:
        run = _pending()
        self.assertFalse(run.is_terminal)
        self.assertIsNone(run.completed_at)
        self.assertIsNone(run.solved)
        self.assertIsNone(run.error)

    def test_succeeded_carries_advisory_result(self) -> None:
        run = _pending(
            status="succeeded", completed_at=_DONE, solved=True, steps=3,
            success_dropped=False, step_delta=1, blended_score=71.0,
            notes=("did a thing",),
        )
        self.assertTrue(run.is_terminal)
        self.assertTrue(run.solved)
        self.assertEqual(run.steps, 3)

    def test_failed_carries_sanitized_error_only(self) -> None:
        run = _pending(status="failed", completed_at=_DONE, error="docker boom")
        self.assertTrue(run.is_terminal)
        self.assertEqual(run.error, "docker boom")
        self.assertIsNone(run.solved)

    def test_terminal_requires_completed_at(self) -> None:
        with self.assertRaises(ValueError):
            _pending(status="succeeded", solved=True)  # no completed_at

    def test_pending_must_not_have_completed_at(self) -> None:
        with self.assertRaises(ValueError):
            _pending(completed_at=_DONE)

    def test_result_fields_forbidden_unless_succeeded(self) -> None:
        with self.assertRaises(ValueError):
            _pending(status="failed", completed_at=_DONE, error="x", solved=True)
        with self.assertRaises(ValueError):
            _pending(solved=True)  # pending with a result

    def test_error_only_on_failed(self) -> None:
        with self.assertRaises(ValueError):
            _pending(status="succeeded", completed_at=_DONE, error="nope")
        with self.assertRaises(ValueError):
            _pending(status="failed", completed_at=_DONE)  # failed needs an error

    def test_bad_profile_rejected(self) -> None:
        with self.assertRaises(ValueError):
            _pending(profile="not_a_profile")

    def test_naive_requested_at_rejected(self) -> None:
        with self.assertRaises(ValueError):
            _pending(requested_at=datetime(2026, 7, 13, 12, 0))

    def test_secret_free_by_construction(self) -> None:
        # No field on the aggregate may hold a flag/token/answer/expected value.
        names = {f.name for f in dataclasses.fields(EvalRun)}
        for forbidden in ("flag", "token", "answer", "secret", "expected", "candidate"):
            self.assertNotIn(forbidden, names)

    def test_terminal_states_are_frozen_in_transition_table(self) -> None:
        for terminal in TERMINAL_EVAL_RUN_STATUSES:
            self.assertEqual(LEGAL_EVAL_TRANSITIONS[terminal], frozenset())


try:  # the service module imports sqlalchemy (db extra); the sanitizer is pure.
    from ctf_generator.application.evaluation.service import (
        _sanitize_notes,
        _sanitize_text,
    )

    _SANITIZER_IMPORT_ERROR: str | None = None
except Exception as exc:  # pragma: no cover - host without db extra
    _SANITIZER_IMPORT_ERROR = f"{type(exc).__name__}: {exc}"


@unittest.skipUnless(
    _SANITIZER_IMPORT_ERROR is None,
    f"application.evaluation not importable ({_SANITIZER_IMPORT_ERROR})",
)
class SanitizerTests(unittest.TestCase):
    def test_flag_token_redacted_from_notes_and_error(self) -> None:
        planted = "leak ctf{super_secret_flag_123} more"
        self.assertNotIn("ctf{", _sanitize_text(planted))
        self.assertIn("[redacted]", _sanitize_text(planted))
        # Multi-word flags + provider keys are also redacted (defense in depth).
        self.assertNotIn("ctf{", _sanitize_text("x ctf{multi word flag} y"))
        self.assertNotIn(
            "sk-ant-", _sanitize_text("boom sk-ant-api03-DEADbeef1234567890abcd")
        )
        notes = _sanitize_notes(("clean note", "ctf{another_flag}"))
        for note in notes:
            self.assertNotIn("ctf{", note)


class ProfileDriftTests(unittest.TestCase):
    def test_domain_profiles_match_agent_eval(self) -> None:
        # The domain keeps a stdlib-only frozen copy (it must not import the
        # effectful agent_eval engine). This guards the two from drifting.
        from ctf_generator.agent_eval import EVAL_PROFILES

        self.assertEqual(VALID_EVAL_PROFILES, frozenset(EVAL_PROFILES))


if __name__ == "__main__":
    unittest.main()
