"""Concrete SQLAlchemy repository for the Team aggregate.

Implements the domain :class:`ctf_generator.domain.repositories.TeamRepository`
over the ``teams`` table. Teams are competition-scoped: every operation resolves
the owning competition's surrogate uuid from its business ``slug`` and fails
loudly (:class:`LookupError`) if the competition does not exist -- the domain
never sees a surrogate key. Operates within the caller's session (flush, never
commit/rollback); ORM objects never escape this module.
"""

from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from ctf_generator.domain.identity.models import Team

from .mappers import team_from_orm, team_to_orm
from .models import Competition
from .models import Team as TeamRow


class SqlAlchemyTeamRepository:
    """Persist and retrieve teams, keyed by ``(competition_id, name)``."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def _competition_uuid(self, competition_id: str) -> uuid.UUID:
        """Resolve a competition business ``slug`` to its surrogate uuid, or
        raise :class:`LookupError` (fail loud -- never create a dangling team)."""
        result = self._session.scalars(
            select(Competition.id).where(Competition.slug == competition_id)
        ).one_or_none()
        if result is None:
            raise LookupError(f"competition not found: {competition_id!r}")
        return result

    def add(self, team: Team) -> None:
        """Insert a new team under an existing competition. A duplicate
        ``(competition_id, name)`` raises :class:`~sqlalchemy.exc.IntegrityError`
        at flush time; a missing competition raises :class:`LookupError`."""
        competition_uuid = self._competition_uuid(team.competition_id)
        row = team_to_orm(team, competition_uuid)
        self._session.add(row)
        self._session.flush()

    def get(self, competition_id: str, name: str) -> Team | None:
        """Fetch one team by ``(competition_id, name)``, or ``None``. Returns
        ``None`` (not an error) if the competition itself is unknown."""
        row = self._session.scalars(
            select(TeamRow)
            .join(Competition, TeamRow.competition_id == Competition.id)
            .where(Competition.slug == competition_id, TeamRow.name == name)
        ).one_or_none()
        return team_from_orm(row, competition_id) if row is not None else None

    def list_for_competition(self, competition_id: str) -> list[Team]:
        """Return every team in the given competition as domain objects (empty
        if the competition is unknown or has no teams)."""
        rows = self._session.scalars(
            select(TeamRow)
            .join(Competition, TeamRow.competition_id == Competition.id)
            .where(Competition.slug == competition_id)
        )
        return [team_from_orm(row, competition_id) for row in rows]
