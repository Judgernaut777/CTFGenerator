"""Team catalog service -- unit-of-work-owning facade over
:class:`~ctf_generator.infrastructure.database.team_repository.SqlAlchemyTeamRepository`.

Teams are competition-scoped: ``list`` is always scoped to one competition and
``create`` fails loud (:class:`LookupError`) if the owning competition does not
exist -- the repository resolves the competition's surrogate key and never
creates a dangling team.
"""

from __future__ import annotations

from ctf_generator.domain.identity.models import Team
from ctf_generator.infrastructure.database.session import Database
from ctf_generator.infrastructure.database.team_repository import (
    SqlAlchemyTeamRepository,
)


class TeamService:
    """Create / read / list teams within a competition, owning the transaction."""

    def __init__(self, database: Database) -> None:
        self._database = database

    def create(self, team: Team) -> Team:
        """Persist a new team under an existing competition. A missing
        competition raises :class:`LookupError`; a duplicate
        ``(competition_id, name)`` surfaces the underlying
        :class:`~sqlalchemy.exc.IntegrityError`."""
        with self._database.session_scope() as session:
            repo = SqlAlchemyTeamRepository(session)
            repo.add(team)
            stored = repo.get(team.competition_id, team.name)
        assert stored is not None  # noqa: S101 - just inserted in this UoW
        return stored

    def get(self, competition_id: str, name: str) -> Team | None:
        with self._database.session_scope() as session:
            return SqlAlchemyTeamRepository(session).get(competition_id, name)

    def list_for_competition(self, competition_id: str) -> list[Team]:
        with self._database.session_scope() as session:
            return SqlAlchemyTeamRepository(session).list_for_competition(
                competition_id
            )
