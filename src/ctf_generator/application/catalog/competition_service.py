"""Competition catalog service -- the unit-of-work-owning facade over
:class:`~ctf_generator.infrastructure.database.competition_repository.SqlAlchemyCompetitionRepository`.
"""

from __future__ import annotations

from collections.abc import Callable

from ctf_generator.domain.challenges.models import CompetitionConfig
from ctf_generator.infrastructure.database.competition_repository import (
    SqlAlchemyCompetitionRepository,
)
from ctf_generator.infrastructure.database.session import Database

Guard = Callable[[CompetitionConfig], None]


class CompetitionService:
    """Create / read / list / update competitions, owning the transaction."""

    def __init__(self, database: Database) -> None:
        self._database = database

    def create(self, config: CompetitionConfig) -> CompetitionConfig:
        """Persist a new competition and return the stored aggregate. A duplicate
        ``competition_id`` (slug) surfaces the underlying
        :class:`~sqlalchemy.exc.IntegrityError` at flush time (the caller maps it
        to a 409). Domain/DB validation failures surface as their native
        exceptions."""
        with self._database.session_scope() as session:
            repo = SqlAlchemyCompetitionRepository(session)
            repo.add(config)
            stored = repo.get(config.competition_id)
        assert stored is not None  # noqa: S101 - just inserted in this UoW
        return stored

    def get(self, competition_id: str) -> CompetitionConfig | None:
        with self._database.session_scope() as session:
            return SqlAlchemyCompetitionRepository(session).get(competition_id)

    def list(self) -> list[CompetitionConfig]:
        with self._database.session_scope() as session:
            return SqlAlchemyCompetitionRepository(session).list()

    def update(
        self, config: CompetitionConfig, *, guard: Guard | None = None
    ) -> CompetitionConfig:
        """Update the mutable fields of an existing competition atomically.

        ``guard`` (if given) is invoked with the freshly-read *current* aggregate
        inside the transaction and may raise to abort -- this is the seam the
        interface layer uses for ``If-Match`` optimistic-concurrency checks
        without the service knowing about ETags. Raises :class:`LookupError` if
        the competition does not exist.
        """
        with self._database.session_scope() as session:
            repo = SqlAlchemyCompetitionRepository(session)
            current = repo.get(config.competition_id)
            if current is None:
                raise LookupError(
                    f"competition not found: {config.competition_id!r}"
                )
            if guard is not None:
                guard(current)
            repo.update(config)
            updated = repo.get(config.competition_id)
        assert updated is not None  # noqa: S101 - updated in this UoW
        return updated
