"""Submission-processing request/result value types and domain errors.

Pure stdlib module (the architecture-boundary test keeps it domain-clean).
:class:`SubmissionRequest` is what an interface layer hands the
``SubmissionProcessingService``; :class:`SubmissionOutcome` is what comes back.
The candidate flag is ``repr``-suppressed and is never persisted, never placed
in a ScoreEvent payload, and never logged -- the ledger stores only the
``correct`` boolean.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from .models import LedgerSubmission, ScoreEvent, Solve


class SubmissionProcessingError(Exception):
    """Base class for submission-processing domain errors."""


class ChallengeNotAttachedError(SubmissionProcessingError, LookupError):
    """The (competition, challenge version) pair has no publication -- teams
    may only submit to challenges attached to their competition."""


class IdempotencyConflictError(SubmissionProcessingError):
    """A replayed ``submission_id`` arrived with a different identity tuple
    (competition/team/challenge) than the stored submission."""


class FlagRejectedError(SubmissionProcessingError):
    """The candidate flag failed normalization (empty, control characters,
    over-long). Carries only the *reason* -- never the candidate itself."""


class FlagUnavailableError(SubmissionProcessingError):
    """The published version's spec carries no retrievable expected flag.

    Deliberately an *error*, never a silent ``correct=False``: a flagless spec
    is a configuration defect, and recording an incorrect submission for it
    would penalize the team for the organizer's mistake.
    """


def _require_nonempty(value: str, field_name: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be a non-empty string")


@dataclass(frozen=True)
class SubmissionRequest:
    """One flag submission to process. ``submission_id`` (caller-supplied uuid
    string) doubles as the idempotency key: replays return the original
    outcome without writing. ``submitted_at`` must be timezone-aware -- the
    accepted submission's instant becomes ``Solve.solved_at`` by construction,
    so an ambiguous naive timestamp is rejected at the boundary."""

    submission_id: str
    competition_id: str
    team_name: str
    definition_slug: str
    version_no: int
    submitted_at: datetime
    candidate_flag: str = field(repr=False, default="")
    submitter_email: str | None = None
    instance_seed: str | None = None

    def __post_init__(self) -> None:
        _require_nonempty(self.submission_id, "submission_id")
        _require_nonempty(self.competition_id, "competition_id")
        _require_nonempty(self.team_name, "team_name")
        _require_nonempty(self.definition_slug, "definition_slug")
        if not isinstance(self.version_no, int) or self.version_no < 1:
            raise ValueError(f"version_no must be an int >= 1, got {self.version_no!r}")
        if not isinstance(self.submitted_at, datetime) or self.submitted_at.tzinfo is None:
            raise ValueError("submitted_at must be a timezone-aware datetime")
        if not isinstance(self.candidate_flag, str):
            raise ValueError("candidate_flag must be a string")


@dataclass(frozen=True)
class SubmissionOutcome:
    """The result of processing one submission.

    * ``accepted``   -- the flag was correct (including correct duplicates).
    * ``first_solve``-- this submission produced the team's Solve (and the
      corresponding ``solve`` score event); at most one per (team, challenge).
    * ``replay``     -- the ``submission_id`` had already been processed; the
      stored outcome was returned and nothing was written.
    """

    submission: LedgerSubmission
    solve: Solve | None
    score_event: ScoreEvent | None
    accepted: bool
    first_solve: bool
    replay: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.submission, LedgerSubmission):
            raise ValueError("submission must be a LedgerSubmission")
        if self.first_solve and not self.accepted:
            raise ValueError("first_solve requires accepted")
        if self.first_solve and self.solve is None:
            raise ValueError("first_solve requires a solve")
        if self.solve is not None and not self.accepted:
            raise ValueError("a solve is only produced by an accepted submission")
        if self.score_event is not None and not self.first_solve:
            raise ValueError("a score event is only emitted for the first solve")
        if self.accepted != self.submission.correct:
            raise ValueError("accepted must match submission.correct")
