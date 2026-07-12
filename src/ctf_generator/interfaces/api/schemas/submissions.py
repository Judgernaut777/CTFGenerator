"""Submission DTOs + mappers.

A submission is one team's answer attempt for a ``(competition, challenge
definition, version)``. The candidate answer/flag is inbound only: it is verified
transiently and NEVER persisted, logged, or echoed -- no response or error body
carries the answer, the expected flag, any verifier internal, or a private solver
artifact. Reads expose only public ledger facts (correctness + the derived solve).
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field, field_validator

from ctf_generator.domain.ledger.models import LedgerSubmission, Solve
from ctf_generator.domain.ledger.processing import SubmissionOutcome

_MAX_ANSWER_LENGTH = 4096


class SubmissionCreateRequest(BaseModel):
    team: str = Field(min_length=1, description="Submitting team (name, competition-scoped)")
    definition_slug: str = Field(min_length=1)
    version_no: int = Field(ge=1)
    # The candidate flag: inbound only, never stored/echoed. ``repr=False`` keeps
    # it out of the model's repr so it cannot leak into a log line or traceback.
    answer: str = Field(
        min_length=1, max_length=_MAX_ANSWER_LENGTH, repr=False
    )
    instance_seed: str | None = None

    @field_validator("answer")
    @classmethod
    def _answer_is_printable(cls, value: str) -> str:
        # Reject control characters WITHOUT echoing the value in the error.
        if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value):
            raise ValueError("answer contains control characters")
        return value


class SolveFacts(BaseModel):
    solve_id: str
    solved_at: str


class SubmissionResponse(BaseModel):
    submission_id: str
    competition_id: str
    team: str
    definition_slug: str
    version_no: int
    submitted_at: str
    correct: bool
    first_solve: bool
    replay: bool
    solve: SolveFacts | None = None


class SubmissionListItem(BaseModel):
    submission_id: str
    competition_id: str
    team: str
    definition_slug: str
    version_no: int
    submitted_at: str
    correct: bool


def _solve_facts(solve: Solve | None) -> dict[str, Any] | None:
    if solve is None:
        return None
    return {"solve_id": solve.solve_id, "solved_at": solve.solved_at.isoformat()}


def submission_outcome_to_response(outcome: SubmissionOutcome) -> dict[str, Any]:
    """Map a processing outcome to the public submission response -- correctness
    and the derived solve only; never the answer or any verifier detail."""
    submission = outcome.submission
    return {
        "submission_id": submission.submission_id,
        "competition_id": submission.competition_id,
        "team": submission.team_name,
        "definition_slug": submission.definition_slug,
        "version_no": submission.version_no,
        "submitted_at": submission.submitted_at.isoformat(),
        "correct": outcome.accepted,
        "first_solve": outcome.first_solve,
        "replay": outcome.replay,
        "solve": _solve_facts(outcome.solve),
    }


def submission_to_list_item(submission: LedgerSubmission) -> dict[str, Any]:
    return {
        "submission_id": submission.submission_id,
        "competition_id": submission.competition_id,
        "team": submission.team_name,
        "definition_slug": submission.definition_slug,
        "version_no": submission.version_no,
        "submitted_at": submission.submitted_at.isoformat(),
        "correct": submission.correct,
    }


def submission_detail_to_response(
    submission: LedgerSubmission, solve: Solve | None
) -> dict[str, Any]:
    body = submission_to_list_item(submission)
    body["first_solve"] = solve is not None
    body["replay"] = False
    body["solve"] = _solve_facts(solve)
    return body


def submission_concurrency_payload(submission: LedgerSubmission) -> dict[str, Any]:
    # Submissions are append-only; the ETag is a stable content hash of the
    # immutable public facts (never the answer).
    return {
        "submission_id": submission.submission_id,
        "correct": submission.correct,
        "submitted_at": submission.submitted_at.isoformat(),
    }
