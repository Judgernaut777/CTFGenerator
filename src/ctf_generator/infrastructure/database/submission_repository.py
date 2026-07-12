"""Concrete SQLAlchemy repository for the LedgerSubmission aggregate.

Append-only over ``submissions``. Resolves the competition, team, challenge
version and (optional) submitter by business identity via ``_resolve`` and fails
loud on a dangling reference. Reads reconstruct those business identities by
joining the parent tables, so ORM rows never escape. Operates within the
caller's session (flush, never commit/rollback); there is no update/delete (the
``submissions_immutable`` trigger is the DB backstop).
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from ctf_generator.domain.ledger.models import LedgerSubmission

from . import _resolve
from .mappers import _as_uuid, submission_from_orm, submission_to_orm
from .models import (
    ChallengeDefinition as ChallengeDefinitionRow,
)
from .models import (
    ChallengeVersion as ChallengeVersionRow,
)
from .models import (
    Competition,
    Team,
    User,
)
from .models import (
    Submission as SubmissionRow,
)


def _hydrate_query():
    """Select a submission row alongside the parent business keys needed to
    rebuild the domain object (submitter email is an outer join -- may be NULL)."""
    return (
        select(
            SubmissionRow,
            Competition.slug,
            Team.name,
            ChallengeDefinitionRow.slug,
            ChallengeVersionRow.version_no,
            User.email,
        )
        .join(Competition, SubmissionRow.competition_id == Competition.id)
        .join(Team, SubmissionRow.team_id == Team.id)
        .join(
            ChallengeVersionRow,
            SubmissionRow.challenge_version_id == ChallengeVersionRow.id,
        )
        .join(
            ChallengeDefinitionRow,
            ChallengeVersionRow.definition_id == ChallengeDefinitionRow.id,
        )
        .outerjoin(User, SubmissionRow.user_id == User.id)
    )


class SqlAlchemyLedgerSubmissionRepository:
    """Persist and retrieve answer attempts, keyed by ``submission_id``."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def add(self, submission: LedgerSubmission) -> None:
        """Insert an attempt. Raises :class:`LookupError` if the competition,
        team, version or submitter is missing; IntegrityError on a duplicate
        ``submission_id`` at flush time."""
        competition_uuid = _resolve.competition_uuid(
            self._session, submission.competition_id
        )
        team_uuid = _resolve.team_uuid(
            self._session, competition_uuid, submission.team_name
        )
        version_uuid = _resolve.version_uuid(
            self._session, submission.definition_slug, submission.version_no
        )
        user_uuid = _resolve.user_uuid_optional(
            self._session, submission.submitter_email
        )
        row = submission_to_orm(
            submission, competition_uuid, team_uuid, version_uuid, user_uuid
        )
        self._session.add(row)
        self._session.flush()

    @staticmethod
    def _map(row) -> LedgerSubmission:
        sub, comp_slug, team_name, def_slug, version_no, email = row
        return submission_from_orm(
            sub, comp_slug, team_name, def_slug, version_no, email
        )

    def get(self, submission_id: str) -> LedgerSubmission | None:
        try:
            key = _as_uuid(submission_id)
        except (ValueError, AttributeError, TypeError):
            return None  # malformed id is a clean miss, not a persistence error
        row = self._session.execute(
            _hydrate_query().where(SubmissionRow.id == key)
        ).one_or_none()
        return self._map(row) if row is not None else None

    def list_for_team(
        self, competition_id: str, team_name: str
    ) -> list[LedgerSubmission]:
        rows = self._session.execute(
            _hydrate_query()
            .where(Competition.slug == competition_id, Team.name == team_name)
            .order_by(SubmissionRow.submitted_at)
        ).all()
        return [self._map(row) for row in rows]
