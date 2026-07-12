"""Concrete SQLAlchemy repository for the ChallengePublication aggregate.

Implements the domain
:class:`ctf_generator.domain.repositories.ChallengePublicationRepository` over the
``competition_challenges`` join. A publication attaches a *published* challenge
version to a competition with per-competition scoring config, keyed by the
business ``(competition_id, definition_slug, version_no)``. The repository
resolves the competition and version to surrogate uuids, fails loudly if either
is missing, and enforces (app-level, design §5) that only a ``published`` version
may be attached. Scoring fields are mutable via ``update``.
"""

from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from ctf_generator.domain.authoring.models import ChallengePublication

from .mappers import (
    challenge_publication_from_orm,
    challenge_publication_to_orm,
)
from .models import ChallengeDefinition as ChallengeDefinitionRow
from .models import ChallengeVersion as ChallengeVersionRow
from .models import Competition
from .models import CompetitionChallenge as CompetitionChallengeRow


class SqlAlchemyChallengePublicationRepository:
    """Persist and retrieve publications, keyed by ``(competition_id,
    definition_slug, version_no)``."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def _competition_uuid(self, competition_id: str) -> uuid.UUID:
        result = self._session.scalars(
            select(Competition.id).where(Competition.slug == competition_id)
        ).one_or_none()
        if result is None:
            raise LookupError(f"competition not found: {competition_id!r}")
        return result

    def _version_uuid_and_state(
        self, definition_slug: str, version_no: int
    ) -> tuple[uuid.UUID, str]:
        """Resolve a version to ``(uuid, state)``; raise if missing."""
        result = self._session.execute(
            select(ChallengeVersionRow.id, ChallengeVersionRow.state)
            .join(
                ChallengeDefinitionRow,
                ChallengeVersionRow.definition_id == ChallengeDefinitionRow.id,
            )
            .where(
                ChallengeDefinitionRow.slug == definition_slug,
                ChallengeVersionRow.version_no == version_no,
            )
        ).one_or_none()
        if result is None:
            raise LookupError(
                f"challenge version not found: {definition_slug!r} v{version_no}"
            )
        return result.id, result.state

    def add(self, publication: ChallengePublication) -> None:
        """Attach a published version to a competition. Raises
        :class:`LookupError` if the competition or version is missing,
        :class:`ValueError` if the version is not ``published``, and
        IntegrityError on a duplicate ``(competition, version)``."""
        competition_uuid = self._competition_uuid(publication.competition_id)
        version_uuid, state = self._version_uuid_and_state(
            publication.definition_slug, publication.version_no
        )
        if state != "published":
            raise ValueError(
                f"only a published version may be attached (state={state!r})"
            )
        row = challenge_publication_to_orm(publication, competition_uuid, version_uuid)
        self._session.add(row)
        self._session.flush()

    def get(
        self, competition_id: str, definition_slug: str, version_no: int
    ) -> ChallengePublication | None:
        row = self._session.scalars(
            select(CompetitionChallengeRow)
            .join(Competition, CompetitionChallengeRow.competition_id == Competition.id)
            .join(
                ChallengeVersionRow,
                CompetitionChallengeRow.challenge_version_id == ChallengeVersionRow.id,
            )
            .join(
                ChallengeDefinitionRow,
                ChallengeVersionRow.definition_id == ChallengeDefinitionRow.id,
            )
            .where(
                Competition.slug == competition_id,
                ChallengeDefinitionRow.slug == definition_slug,
                ChallengeVersionRow.version_no == version_no,
            )
        ).one_or_none()
        if row is None:
            return None
        return challenge_publication_from_orm(
            row, competition_id, definition_slug, version_no
        )

    def list_for_competition(
        self, competition_id: str
    ) -> list[ChallengePublication]:
        rows = self._session.execute(
            select(
                CompetitionChallengeRow,
                ChallengeDefinitionRow.slug,
                ChallengeVersionRow.version_no,
            )
            .join(Competition, CompetitionChallengeRow.competition_id == Competition.id)
            .join(
                ChallengeVersionRow,
                CompetitionChallengeRow.challenge_version_id == ChallengeVersionRow.id,
            )
            .join(
                ChallengeDefinitionRow,
                ChallengeVersionRow.definition_id == ChallengeDefinitionRow.id,
            )
            .where(Competition.slug == competition_id)
        ).all()
        return [
            challenge_publication_from_orm(
                pub_row, competition_id, definition_slug, version_no
            )
            for pub_row, definition_slug, version_no in rows
        ]

    def remove(
        self, competition_id: str, definition_slug: str, version_no: int
    ) -> bool:
        """Detach a published version from a competition, keyed by the business
        triple. Returns ``True`` when a row was removed, ``False`` when the
        attachment did not exist (so the caller can raise a 404). Fails loud
        (:class:`LookupError`) only when the competition or version themselves are
        unknown."""
        competition_uuid = self._competition_uuid(competition_id)
        version_uuid, _state = self._version_uuid_and_state(
            definition_slug, version_no
        )
        row = self._session.scalars(
            select(CompetitionChallengeRow).where(
                CompetitionChallengeRow.competition_id == competition_uuid,
                CompetitionChallengeRow.challenge_version_id == version_uuid,
            )
        ).one_or_none()
        if row is None:
            return False
        self._session.delete(row)
        self._session.flush()
        return True

    def update(self, publication: ChallengePublication) -> None:
        """Update the mutable scoring fields of an existing publication, keyed by
        ``(competition_id, definition_slug, version_no)``. Raises
        :class:`LookupError` if the publication (or a referent) is missing."""
        competition_uuid = self._competition_uuid(publication.competition_id)
        version_uuid, _state = self._version_uuid_and_state(
            publication.definition_slug, publication.version_no
        )
        row = self._session.scalars(
            select(CompetitionChallengeRow).where(
                CompetitionChallengeRow.competition_id == competition_uuid,
                CompetitionChallengeRow.challenge_version_id == version_uuid,
            )
        ).one_or_none()
        if row is None:
            raise LookupError(
                f"publication not found: {publication.competition_id!r} / "
                f"{publication.definition_slug!r} v{publication.version_no}"
            )
        challenge_publication_to_orm(
            publication, competition_uuid, version_uuid, existing=row
        )
        self._session.flush()
