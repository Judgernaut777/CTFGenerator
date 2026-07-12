"""Concrete SQLAlchemy repository for the ChallengeVersion aggregate.

Implements the domain
:class:`ctf_generator.domain.repositories.ChallengeVersionRepository` over the
``challenge_versions`` table. Versions live under a definition, referenced by the
business ``definition_slug``; the repository resolves it to the surrogate uuid
and fails loudly (:class:`LookupError`) if the definition is missing.

State transitions are explicit and forward-only. ``publish`` moves a ``draft`` to
``published`` (stamping ``published_at``); ``archive`` moves a ``published`` to
``archived`` (retaining the timestamp). There is no generic content ``update`` --
the ``freeze_published_version`` DB trigger is the backstop that rejects any
content change (or illegal state move) once published.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from ctf_generator.domain.authoring.models import ChallengeVersion

from .mappers import (
    challenge_version_from_orm,
    challenge_version_to_orm,
    to_utc,
)
from .models import ChallengeDefinition as ChallengeDefinitionRow
from .models import ChallengeVersion as ChallengeVersionRow


class SqlAlchemyChallengeVersionRepository:
    """Persist and retrieve versions, keyed by ``(definition_slug, version_no)``."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def _definition_uuid(self, definition_slug: str) -> uuid.UUID:
        result = self._session.scalars(
            select(ChallengeDefinitionRow.id).where(
                ChallengeDefinitionRow.slug == definition_slug
            )
        ).one_or_none()
        if result is None:
            raise LookupError(f"challenge definition not found: {definition_slug!r}")
        return result

    def _version_row(
        self, definition_slug: str, version_no: int, *, for_update: bool = False
    ) -> ChallengeVersionRow | None:
        stmt = (
            select(ChallengeVersionRow)
            .join(
                ChallengeDefinitionRow,
                ChallengeVersionRow.definition_id == ChallengeDefinitionRow.id,
            )
            .where(
                ChallengeDefinitionRow.slug == definition_slug,
                ChallengeVersionRow.version_no == version_no,
            )
        )
        if for_update:
            # Lock only the version row (not the joined definition) so a guarded
            # state transition serializes read-check-write under READ COMMITTED.
            stmt = stmt.with_for_update(of=ChallengeVersionRow)
        return self._session.scalars(stmt).one_or_none()

    def add(self, version: ChallengeVersion) -> None:
        """Insert a version under an existing definition. Duplicate
        ``(definition, version_no)`` or ``(definition, spec_sha256)`` raises
        IntegrityError; a missing definition raises :class:`LookupError`."""
        definition_uuid = self._definition_uuid(version.definition_slug)
        row = challenge_version_to_orm(version, definition_uuid)
        self._session.add(row)
        self._session.flush()

    def get(
        self, definition_slug: str, version_no: int
    ) -> ChallengeVersion | None:
        row = self._version_row(definition_slug, version_no)
        return (
            challenge_version_from_orm(row, definition_slug)
            if row is not None
            else None
        )

    def get_by_spec_sha256(
        self, definition_slug: str, spec_sha256: str
    ) -> ChallengeVersion | None:
        row = self._session.scalars(
            select(ChallengeVersionRow)
            .join(
                ChallengeDefinitionRow,
                ChallengeVersionRow.definition_id == ChallengeDefinitionRow.id,
            )
            .where(
                ChallengeDefinitionRow.slug == definition_slug,
                ChallengeVersionRow.spec_sha256 == spec_sha256,
            )
        ).one_or_none()
        return (
            challenge_version_from_orm(row, definition_slug)
            if row is not None
            else None
        )

    def list_for_definition(
        self, definition_slug: str
    ) -> list[ChallengeVersion]:
        rows = self._session.scalars(
            select(ChallengeVersionRow)
            .join(
                ChallengeDefinitionRow,
                ChallengeVersionRow.definition_id == ChallengeDefinitionRow.id,
            )
            .where(ChallengeDefinitionRow.slug == definition_slug)
            .order_by(ChallengeVersionRow.version_no)
        )
        return [challenge_version_from_orm(row, definition_slug) for row in rows]

    def publish(
        self, definition_slug: str, version_no: int, published_at: datetime
    ) -> None:
        """Transition a ``draft`` version to ``published``. Raises
        :class:`LookupError` if missing, :class:`ValueError` if not a draft or if
        ``published_at`` is None (which would violate the state/timestamp CHECK
        with a raw IntegrityError instead of a clean domain error)."""
        if published_at is None:
            raise ValueError("published_at is required to publish a version")
        row = self._version_row(definition_slug, version_no, for_update=True)
        if row is None:
            raise LookupError(
                f"challenge version not found: {definition_slug!r} v{version_no}"
            )
        if row.state != "draft":
            raise ValueError(
                f"only a draft version can be published (state={row.state!r})"
            )
        row.state = "published"
        row.published_at = to_utc(published_at)
        self._session.flush()

    def archive(
        self, definition_slug: str, version_no: int, archived_at: datetime
    ) -> None:
        """Transition a ``published`` version to ``archived``. ``published_at`` is
        retained (provenance) and ``archived_at`` is stamped so the row is
        consistent with the soft-archival convention (design §9). Raises
        :class:`LookupError` if missing, :class:`ValueError` if not published or
        if ``archived_at`` is None."""
        if archived_at is None:
            raise ValueError("archived_at is required to archive a version")
        row = self._version_row(definition_slug, version_no)
        if row is None:
            raise LookupError(
                f"challenge version not found: {definition_slug!r} v{version_no}"
            )
        if row.state != "published":
            raise ValueError(
                f"only a published version can be archived (state={row.state!r})"
            )
        row.state = "archived"
        row.archived_at = to_utc(archived_at)
        self._session.flush()
