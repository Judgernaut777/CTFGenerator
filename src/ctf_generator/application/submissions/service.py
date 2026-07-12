"""The transactional submission-processing service (M7).

Exactly ONE ``Database.session_scope()`` unit of work per submission
(repositories flush; the UoW commits once). The script:

1.  Resolve the competition and take a competition-scoped
    ``pg_advisory_xact_lock`` (auto-released at commit/rollback) as the first
    write-side statement -- all submission processing for one competition is
    serialized, so the solve-existence re-check below is authoritative and
    the schema's UNIQUE + trigger remain pure backstops.
2.  Idempotency short-circuit: a known ``submission_id`` returns the stored
    outcome (``replay=True``) without writing; an identity-tuple mismatch is
    an :class:`IdempotencyConflictError`.
3.  Load the publication (teams may only submit to attached challenges --
    :class:`ChallengeNotAttachedError` otherwise) and the (non-draft)
    version. Archived-but-still-attached remains submittable per the Epic-2
    publication rule.
4.  Normalize the candidate and verify via the injected ``FlagVerifier``.
5.  Record the submission (incorrect ones are recorded too, accepted=False).
6.  If correct and no solve exists yet for (competition, team, version):
    construct the ``Solve`` from the accepted submission -- ``solved_at =
    submission.submitted_at`` and ``submission_id`` -- IN THE SAME
    TRANSACTION, resolving the design doc's deferred issue #2 *by
    construction*; then append exactly one ``solve`` ScoreEvent. A correct
    duplicate records the submission only.
7.  ``session_scope`` commits once. A crash rolls back everything -- no
    partial state is observable, so client retries are exactly-once in
    effect (they land in the replay or reprocess path).

Isolation: requires READ COMMITTED (the PostgreSQL default) -- the post-lock
re-check sees the previous lock holder's committed solve because READ
COMMITTED takes a fresh snapshot per statement. The integration suite asserts
the isolation level to make the assumption executable.

Security: the candidate flag is never persisted, never placed in an event
payload, and never logged; the submissions table has no flag column by
design.
"""

from __future__ import annotations

import uuid as _uuid

import sqlalchemy as sa
from sqlalchemy.orm import Session

from ctf_generator.domain.ledger.models import LedgerSubmission, ScoreEvent, Solve
from ctf_generator.domain.ledger.processing import (
    ChallengeNotAttachedError,
    IdempotencyConflictError,
    SubmissionOutcome,
    SubmissionProcessingError,
    SubmissionRequest,
)
from ctf_generator.domain.repositories import FlagVerifier
from ctf_generator.infrastructure.database import _resolve
from ctf_generator.infrastructure.database.challenge_publication_repository import (
    SqlAlchemyChallengePublicationRepository,
)
from ctf_generator.infrastructure.database.challenge_version_repository import (
    SqlAlchemyChallengeVersionRepository,
)
from ctf_generator.infrastructure.database.score_ledger_repository import (
    SqlAlchemyScoreLedger,
)
from ctf_generator.infrastructure.database.session import Database
from ctf_generator.infrastructure.database.solve_repository import (
    SqlAlchemySolveRepository,
)
from ctf_generator.infrastructure.database.submission_repository import (
    SqlAlchemyLedgerSubmissionRepository,
)

from .verifier import SpecFlagVerifier, normalize_candidate


def competition_lock(session: Session, competition_uuid: _uuid.UUID) -> None:
    """Take the competition-scoped transaction advisory lock (shared key
    derivation with the scoreboard projector: ``hashtextextended(uuid_text,
    0)``). Auto-released at commit/rollback. Hash collisions across
    competitions only cause spurious serialization, never incorrectness."""
    session.execute(
        sa.text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"),
        {"key": str(competition_uuid)},
    )


class SubmissionProcessingService:
    """Receive -> persist -> verify -> first-correct-solve -> commit once."""

    def __init__(
        self,
        database: Database,
        flag_verifier: FlagVerifier | None = None,
    ) -> None:
        self._database = database
        self._verifier: FlagVerifier = flag_verifier or SpecFlagVerifier()

    def process_submission(self, request: SubmissionRequest) -> SubmissionOutcome:
        with self._database.session_scope() as session:
            competition_uuid = _resolve.competition_uuid(
                session, request.competition_id
            )
            competition_lock(session, competition_uuid)

            submissions = SqlAlchemyLedgerSubmissionRepository(session)
            solves = SqlAlchemySolveRepository(session)

            # (2) Idempotency short-circuit.
            stored = submissions.get(request.submission_id)
            if stored is not None:
                return self._replay(stored, request, solves)

            # (3) Publication + version.
            publication = SqlAlchemyChallengePublicationRepository(session).get(
                request.competition_id,
                request.definition_slug,
                request.version_no,
            )
            if publication is None:
                raise ChallengeNotAttachedError(
                    f"challenge {request.definition_slug!r} v{request.version_no} "
                    f"is not attached to competition {request.competition_id!r}"
                )
            version = SqlAlchemyChallengeVersionRepository(session).get(
                request.definition_slug, request.version_no
            )
            if version is None:  # pragma: no cover - publication FK implies it
                raise SubmissionProcessingError(
                    f"challenge version {request.definition_slug!r} "
                    f"v{request.version_no} not found"
                )
            if version.state == "draft":
                raise SubmissionProcessingError(
                    f"challenge version {request.definition_slug!r} "
                    f"v{request.version_no} is a draft and not submittable"
                )

            # (4) Normalize + verify (constant time; candidate never persisted).
            candidate = normalize_candidate(request.candidate_flag)
            correct = self._verifier.verify(
                version, request.instance_seed, candidate
            )

            # (5) Record the attempt (correct or not).
            submission = LedgerSubmission(
                submission_id=request.submission_id,
                competition_id=request.competition_id,
                team_name=request.team_name,
                definition_slug=request.definition_slug,
                version_no=request.version_no,
                submitted_at=request.submitted_at,
                correct=correct,
                submitter_email=request.submitter_email,
                instance_seed=request.instance_seed,
            )
            submissions.add(submission)

            if not correct:
                return SubmissionOutcome(
                    submission=submission,
                    solve=None,
                    score_event=None,
                    accepted=False,
                    first_solve=False,
                )

            # (6) First-correct-solve check, authoritative under the lock.
            existing = solves.get_for_challenge(
                request.competition_id,
                request.team_name,
                request.definition_slug,
                request.version_no,
            )
            if existing is not None:
                # Correct duplicate: the submission stands, no solve/event.
                return SubmissionOutcome(
                    submission=submission,
                    solve=None,
                    score_event=None,
                    accepted=True,
                    first_solve=False,
                )

            # Deferred issue #2 resolved BY CONSTRUCTION: the Solve is built
            # from the accepted submission in the same transaction, so
            # solved_at == submitted_at and the ids match, always.
            solve = Solve(
                solve_id=str(_uuid.uuid4()),
                competition_id=request.competition_id,
                team_name=request.team_name,
                definition_slug=request.definition_slug,
                version_no=request.version_no,
                submission_id=submission.submission_id,
                solved_at=submission.submitted_at,
                instance_seed=submission.instance_seed,
            )
            solves.add(solve)
            event = SqlAlchemyScoreLedger(session).append(
                ScoreEvent(
                    competition_id=request.competition_id,
                    team_name=request.team_name,
                    definition_slug=request.definition_slug,
                    version_no=request.version_no,
                    type="solve",
                    ts=solve.solved_at.isoformat(),
                    submission_id=submission.submission_id,
                    solve_id=solve.solve_id,
                    payload={},
                )
            )
            return SubmissionOutcome(
                submission=submission,
                solve=solve,
                score_event=event,
                accepted=True,
                first_solve=True,
            )
            # (7) session_scope commits once on scope exit.

    @staticmethod
    def _replay(
        stored: LedgerSubmission,
        request: SubmissionRequest,
        solves: SqlAlchemySolveRepository,
    ) -> SubmissionOutcome:
        """Reconstruct the outcome of an already-processed submission_id
        without writing anything. The stored row must match the request's
        identity tuple -- a mismatch means a submission_id was reused across
        (competition, team, challenge) and is an error, not a leak."""
        identity_matches = (
            stored.competition_id == request.competition_id
            and stored.team_name == request.team_name
            and stored.definition_slug == request.definition_slug
            and stored.version_no == request.version_no
        )
        if not identity_matches:
            raise IdempotencyConflictError(
                f"submission {request.submission_id!r} was already processed "
                "with a different identity tuple"
            )
        solve = solves.get_by_submission(stored.submission_id)
        return SubmissionOutcome(
            submission=stored,
            solve=solve,
            score_event=None,  # events are not rehydrated on replay
            accepted=stored.correct,
            first_solve=solve is not None,
            replay=True,
        )
