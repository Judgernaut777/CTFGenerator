"""Concrete SQLAlchemy repository for the Competition aggregate.

Implements the domain :class:`ctf_generator.domain.repositories.CompetitionRepository`
protocol over the ``competitions`` table. It operates within the caller's
:class:`~sqlalchemy.orm.Session` -- the unit-of-work boundary -- so it *flushes*
to assign PKs and surface constraint errors eagerly, but never opens, commits,
or rolls back a transaction of its own.

ORM objects never escape this module: every read maps rows back to the frozen
domain :class:`~ctf_generator.domain.challenges.models.CompetitionConfig` via
``competition_from_orm`` before returning.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from ctf_generator.domain.challenges.models import CompetitionConfig

from .mappers import competition_from_orm, competition_to_orm
from .models import Competition


class SqlAlchemyCompetitionRepository:
    """Persist and retrieve competitions, keyed by their business ``slug``.

    Implements the domain ``CompetitionRepository`` protocol. The domain
    ``competition_id`` maps to the ORM ``slug`` (the stable business id); the
    surrogate uuid ``id`` and the ORM-managed ``status`` / ``archived_at`` /
    ``created_at`` columns are never surfaced to the domain.
    """

    def __init__(self, session: Session) -> None:
        self._session = session

    def add(self, competition: CompetitionConfig) -> None:
        """Insert a new competition. A duplicate ``slug`` raises the underlying
        :class:`~sqlalchemy.exc.IntegrityError` at flush time."""
        row = competition_to_orm(competition)
        self._session.add(row)
        self._session.flush()  # assign PK / surface duplicate-slug now

    def get(self, competition_id: str) -> CompetitionConfig | None:
        """Fetch one competition by its business id (``slug``), or ``None``."""
        row = self._session.scalars(
            select(Competition).where(Competition.slug == competition_id)
        ).one_or_none()
        return competition_from_orm(row) if row is not None else None

    def get_for_update(self, competition_id: str) -> CompetitionConfig | None:
        """Fetch one competition by its business id (``slug``) taking a row lock
        (``SELECT ... FOR UPDATE``). Under READ COMMITTED this serializes a
        guarded read-check-write: a second concurrent updater blocks here until
        the first commits, then observes the new state (so a stale ``If-Match``
        reliably yields 412 rather than a lost update)."""
        row = self._session.scalars(
            select(Competition)
            .where(Competition.slug == competition_id)
            .with_for_update()
        ).one_or_none()
        return competition_from_orm(row) if row is not None else None

    def list(self) -> list[CompetitionConfig]:
        """Return every competition as a domain object."""
        return [
            competition_from_orm(row)
            for row in self._session.scalars(select(Competition))
        ]

    def update(self, competition: CompetitionConfig) -> None:
        """Update the mutable fields of an existing competition, keyed by
        ``slug``. Raises :class:`LookupError` if no such row exists."""
        row = self._session.scalars(
            select(Competition).where(Competition.slug == competition.competition_id)
        ).one_or_none()
        if row is None:
            raise LookupError(
                f"competition not found: {competition.competition_id!r}"
            )
        competition_to_orm(competition, existing=row)
        self._session.flush()
