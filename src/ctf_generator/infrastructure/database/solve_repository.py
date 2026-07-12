"""Concrete SQLAlchemy repository for the Solve aggregate.

Append-only over ``solves``. ``add`` resolves the competition, team and version
by business identity (fail loud if missing) and inserts the solve; the schema
guarantees at-most-one solve per ``(competition, team, version)`` (UNIQUE), one
solve per submission (UNIQUE), that the referenced submission matches the whole
identity tuple (composite FK), and that it is ``correct`` (trigger). Reads rebuild
business identity via joins; ORM rows never escape. Flush only, never
commit/rollback; no update/delete (trigger-backstopped).
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from ctf_generator.domain.ledger.models import Solve

from . import _resolve
from .mappers import _as_uuid, solve_from_orm, solve_to_orm
from .models import (
    ChallengeDefinition as ChallengeDefinitionRow,
)
from .models import (
    ChallengeVersion as ChallengeVersionRow,
)
from .models import (
    Competition,
    Team,
)
from .models import (
    Solve as SolveRow,
)


def _hydrate_query():
    return (
        select(
            SolveRow,
            Competition.slug,
            Team.name,
            ChallengeDefinitionRow.slug,
            ChallengeVersionRow.version_no,
        )
        .join(Competition, SolveRow.competition_id == Competition.id)
        .join(Team, SolveRow.team_id == Team.id)
        .join(ChallengeVersionRow, SolveRow.challenge_version_id == ChallengeVersionRow.id)
        .join(
            ChallengeDefinitionRow,
            ChallengeVersionRow.definition_id == ChallengeDefinitionRow.id,
        )
    )


class SqlAlchemySolveRepository:
    """Persist and retrieve solves; at most one per (competition, team, version)."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def add(self, solve: Solve) -> None:
        competition_uuid = _resolve.competition_uuid(self._session, solve.competition_id)
        team_uuid = _resolve.team_uuid(self._session, competition_uuid, solve.team_name)
        version_uuid = _resolve.version_uuid(
            self._session, solve.definition_slug, solve.version_no
        )
        row = solve_to_orm(solve, competition_uuid, team_uuid, version_uuid)
        self._session.add(row)
        self._session.flush()

    @staticmethod
    def _map(row) -> Solve:
        solve_row, comp_slug, team_name, def_slug, version_no = row
        return solve_from_orm(solve_row, comp_slug, team_name, def_slug, version_no)

    def get(self, solve_id: str) -> Solve | None:
        try:
            key = _as_uuid(solve_id)
        except (ValueError, AttributeError, TypeError):
            return None  # malformed id is a clean miss, not a persistence error
        row = self._session.execute(
            _hydrate_query().where(SolveRow.id == key)
        ).one_or_none()
        return self._map(row) if row is not None else None

    def get_by_submission(self, submission_id: str) -> Solve | None:
        """The solve derived from ``submission_id`` (unique per the schema's
        ``uq_solves_submission_id``), or ``None``. Malformed ids are a clean
        miss, symmetric with ``get``."""
        try:
            key = _as_uuid(submission_id)
        except (ValueError, AttributeError, TypeError):
            return None
        row = self._session.execute(
            _hydrate_query().where(SolveRow.submission_id == key)
        ).one_or_none()
        return self._map(row) if row is not None else None

    def get_for_challenge(
        self,
        competition_id: str,
        team_name: str,
        definition_slug: str,
        version_no: int,
    ) -> Solve | None:
        row = self._session.execute(
            _hydrate_query().where(
                Competition.slug == competition_id,
                Team.name == team_name,
                ChallengeDefinitionRow.slug == definition_slug,
                ChallengeVersionRow.version_no == version_no,
            )
        ).one_or_none()
        return self._map(row) if row is not None else None

    def list_for_competition(self, competition_id: str) -> list[Solve]:
        rows = self._session.execute(
            _hydrate_query()
            .where(Competition.slug == competition_id)
            .order_by(SolveRow.solved_at)
        ).all()
        return [self._map(row) for row in rows]
