"""Concrete SQLAlchemy repository for the ChallengeDefinition aggregate.

Implements the domain
:class:`ctf_generator.domain.repositories.ChallengeDefinitionRepository` over the
``challenge_definitions`` table, keyed by the business ``slug``. Operates within
the caller's session (flush, never commit/rollback); ORM rows never escape.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from ctf_generator.domain.authoring.models import ChallengeDefinition

from .mappers import challenge_definition_from_orm, challenge_definition_to_orm
from .models import ChallengeDefinition as ChallengeDefinitionRow


class SqlAlchemyChallengeDefinitionRepository:
    """Persist and retrieve challenge definitions, keyed by ``slug``."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def _row(
        self, slug: str, *, for_update: bool = False
    ) -> ChallengeDefinitionRow | None:
        stmt = select(ChallengeDefinitionRow).where(
            ChallengeDefinitionRow.slug == slug
        )
        if for_update:
            stmt = stmt.with_for_update()
        return self._session.scalars(stmt).one_or_none()

    def add(self, definition: ChallengeDefinition) -> None:
        """Insert a new definition. A duplicate ``slug`` raises IntegrityError at
        flush time."""
        row = challenge_definition_to_orm(definition)
        self._session.add(row)
        self._session.flush()

    def get(self, slug: str) -> ChallengeDefinition | None:
        row = self._row(slug)
        return challenge_definition_from_orm(row) if row is not None else None

    def get_for_update(self, slug: str) -> ChallengeDefinition | None:
        """Fetch a definition by ``slug`` taking a row lock (see the competition
        repository's ``get_for_update`` for the serialization rationale)."""
        row = self._row(slug, for_update=True)
        return challenge_definition_from_orm(row) if row is not None else None

    def list(self) -> list[ChallengeDefinition]:
        return [
            challenge_definition_from_orm(row)
            for row in self._session.scalars(select(ChallengeDefinitionRow))
        ]

    def update(self, definition: ChallengeDefinition) -> None:
        """Update the mutable ``title`` of an existing definition, keyed by
        ``slug``. Raises :class:`LookupError` if no such row exists."""
        row = self._row(definition.slug)
        if row is None:
            raise LookupError(f"challenge definition not found: {definition.slug!r}")
        challenge_definition_to_orm(definition, existing=row)
        self._session.flush()
