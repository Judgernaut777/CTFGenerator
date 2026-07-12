"""Host-pure unit tests for submission-processing domain types + verifier (M7).

Stdlib only -- no [db] extra required: ``domain.ledger.processing`` and
``application.submissions.verifier`` are deliberately importable without
SQLAlchemy. The transaction script itself is proven by the Docker-gated
integration suite.
"""

from __future__ import annotations

import unittest
from datetime import UTC, datetime

from ctf_generator.application.submissions.verifier import (
    MAX_CANDIDATE_LENGTH,
    SpecFlagVerifier,
    normalize_candidate,
)
from ctf_generator.domain.authoring.models import ChallengeVersion
from ctf_generator.domain.ledger.models import LedgerSubmission, Solve
from ctf_generator.domain.ledger.processing import (
    ChallengeNotAttachedError,
    FlagRejectedError,
    FlagUnavailableError,
    IdempotencyConflictError,
    SubmissionOutcome,
    SubmissionProcessingError,
    SubmissionRequest,
)

_NOW = datetime(2026, 7, 12, 12, 0, tzinfo=UTC)


def _request(**overrides) -> SubmissionRequest:
    base = dict(
        submission_id="7d5f5df1-9556-4d76-8a3d-000000000003",
        competition_id="cup",
        team_name="Red",
        definition_slug="sql",
        version_no=1,
        submitted_at=_NOW,
        candidate_flag="ctf{abc123}",
    )
    base.update(overrides)
    return SubmissionRequest(**base)


def _submission(correct: bool) -> LedgerSubmission:
    return LedgerSubmission(
        submission_id="7d5f5df1-9556-4d76-8a3d-000000000003",
        competition_id="cup",
        team_name="Red",
        definition_slug="sql",
        version_no=1,
        submitted_at=_NOW,
        correct=correct,
    )


def _solve() -> Solve:
    return Solve(
        solve_id="7d5f5df1-9556-4d76-8a3d-000000000004",
        competition_id="cup",
        team_name="Red",
        definition_slug="sql",
        version_no=1,
        submission_id="7d5f5df1-9556-4d76-8a3d-000000000003",
        solved_at=_NOW,
    )


def _version(spec: dict) -> ChallengeVersion:
    return ChallengeVersion(
        definition_slug="sql",
        version_no=1,
        state="published",
        family_version="1.0",
        seed="s",
        spec_sha256="h1",
        spec=spec,
        spec_version="1.0",
        published_at=_NOW,
    )


class SubmissionRequestTests(unittest.TestCase):
    def test_valid_request(self) -> None:
        r = _request()
        self.assertEqual(r.competition_id, "cup")

    def test_rejects_naive_submitted_at(self) -> None:
        with self.assertRaises(ValueError):
            _request(submitted_at=datetime(2026, 7, 12, 12, 0))

    def test_rejects_blank_identity_fields(self) -> None:
        for field in ("submission_id", "competition_id", "team_name", "definition_slug"):
            with self.subTest(field=field):
                with self.assertRaises(ValueError):
                    _request(**{field: "  "})

    def test_rejects_bad_version_no(self) -> None:
        with self.assertRaises(ValueError):
            _request(version_no=0)

    def test_repr_hides_the_candidate_flag(self) -> None:
        r = _request(candidate_flag="ctf{super_secret}")
        self.assertNotIn("ctf{super_secret}", repr(r))


class SubmissionOutcomeTests(unittest.TestCase):
    def test_incorrect_outcome(self) -> None:
        o = SubmissionOutcome(
            submission=_submission(False),
            solve=None,
            score_event=None,
            accepted=False,
            first_solve=False,
        )
        self.assertFalse(o.replay)

    def test_first_solve_requires_solve_and_accept(self) -> None:
        with self.assertRaises(ValueError):
            SubmissionOutcome(
                submission=_submission(True),
                solve=None,
                score_event=None,
                accepted=True,
                first_solve=True,  # but no solve
            )
        with self.assertRaises(ValueError):
            SubmissionOutcome(
                submission=_submission(False),
                solve=_solve(),
                score_event=None,
                accepted=False,  # a solve without acceptance
                first_solve=False,
            )

    def test_accepted_must_match_submission_correct(self) -> None:
        with self.assertRaises(ValueError):
            SubmissionOutcome(
                submission=_submission(False),
                solve=None,
                score_event=None,
                accepted=True,
                first_solve=False,
            )

    def test_error_taxonomy(self) -> None:
        # ChallengeNotAttachedError is LookupError-family per the design.
        self.assertTrue(issubclass(ChallengeNotAttachedError, LookupError))
        for err in (
            ChallengeNotAttachedError,
            IdempotencyConflictError,
            FlagRejectedError,
            FlagUnavailableError,
        ):
            self.assertTrue(issubclass(err, SubmissionProcessingError))


class NormalizationTests(unittest.TestCase):
    def test_strips_whitespace(self) -> None:
        self.assertEqual(normalize_candidate("  ctf{x}  "), "ctf{x}")

    def test_rejects_empty_and_whitespace(self) -> None:
        for bad in ("", "   ", "\t\n"):
            with self.subTest(bad=bad):
                with self.assertRaises(FlagRejectedError):
                    normalize_candidate(bad)

    def test_rejects_control_characters(self) -> None:
        for bad in ("ctf{a\x00b}", "ctf{a}\x1b[0m", "ctf\x7f{}"):
            with self.subTest(bad=bad):
                with self.assertRaises(FlagRejectedError):
                    normalize_candidate(bad)

    def test_rejects_over_long(self) -> None:
        with self.assertRaises(FlagRejectedError):
            normalize_candidate("x" * (MAX_CANDIDATE_LENGTH + 1))
        # Exactly at the cap is fine.
        self.assertEqual(
            len(normalize_candidate("x" * MAX_CANDIDATE_LENGTH)),
            MAX_CANDIDATE_LENGTH,
        )

    def test_rejection_reason_never_echoes_the_candidate(self) -> None:
        try:
            normalize_candidate("ctf{leaky\x00flag}")
        except FlagRejectedError as exc:
            self.assertNotIn("leaky", str(exc))
        else:  # pragma: no cover
            self.fail("expected FlagRejectedError")


class SpecFlagVerifierTests(unittest.TestCase):
    def test_correct_and_incorrect(self) -> None:
        verifier = SpecFlagVerifier()
        version = _version({"flag": "ctf{right}"})
        self.assertTrue(verifier.verify(version, None, "ctf{right}"))
        self.assertFalse(verifier.verify(version, None, "ctf{wrong}"))

    def test_flagless_spec_fails_loud_not_incorrect(self) -> None:
        verifier = SpecFlagVerifier()
        for spec in ({}, {"flag": ""}, {"flag": "   "}, {"flag": 42}):
            with self.subTest(spec=spec):
                with self.assertRaises(FlagUnavailableError):
                    verifier.verify(_version(spec), None, "ctf{x}")

    def test_comparison_is_exact_not_substring(self) -> None:
        verifier = SpecFlagVerifier()
        version = _version({"flag": "ctf{right}"})
        self.assertFalse(verifier.verify(version, None, "ctf{right} "))
        self.assertFalse(verifier.verify(version, None, "ctf{righ}"))


if __name__ == "__main__":
    unittest.main()
