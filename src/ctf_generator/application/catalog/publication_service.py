"""Publication catalog service -- unit-of-work-owning facade over
:class:`~ctf_generator.infrastructure.database.challenge_publication_repository.SqlAlchemyChallengePublicationRepository`.

A publication attaches a *published* challenge version to a competition with its
per-competition scoring config, keyed by ``(competition_id, definition_slug,
version_no)``. The service owns the transaction (``Database.session_scope``): the
repository flushes, the UoW commits once, and ORM rows never escape -- callers
speak only in the frozen :class:`ChallengePublication` aggregate.

Failure modes surface as the repository's own exceptions so the API's error
mapping stays uniform: a missing competition/version -> :class:`LookupError`
(404), a non-``published`` version -> :class:`ValueError` (422/400), and a
duplicate attach -> the driver ``IntegrityError`` (409).
"""

from __future__ import annotations

from ctf_generator.domain.authoring.models import ChallengePublication
from ctf_generator.infrastructure.database.challenge_publication_repository import (
    SqlAlchemyChallengePublicationRepository,
)
from ctf_generator.infrastructure.database.session import Database


class PublicationService:
    """Attach / detach / list competition<->version publications, owning the UoW."""

    def __init__(self, database: Database) -> None:
        self._database = database

    def attach(self, publication: ChallengePublication) -> ChallengePublication:
        """Attach a published version to a competition. A missing competition or
        version raises :class:`LookupError`; a version that is not ``published``
        raises :class:`ValueError`; a duplicate ``(competition, version)`` surfaces
        the underlying :class:`~sqlalchemy.exc.IntegrityError`."""
        with self._database.session_scope() as session:
            repo = SqlAlchemyChallengePublicationRepository(session)
            repo.add(publication)
            stored = repo.get(
                publication.competition_id,
                publication.definition_slug,
                publication.version_no,
            )
        assert stored is not None  # noqa: S101 - just inserted in this UoW
        return stored

    def get(
        self, competition_id: str, definition_slug: str, version_no: int
    ) -> ChallengePublication | None:
        with self._database.session_scope() as session:
            return SqlAlchemyChallengePublicationRepository(session).get(
                competition_id, definition_slug, version_no
            )

    def list_for_competition(
        self, competition_id: str
    ) -> list[ChallengePublication]:
        with self._database.session_scope() as session:
            return SqlAlchemyChallengePublicationRepository(
                session
            ).list_for_competition(competition_id)

    def detach(
        self, competition_id: str, definition_slug: str, version_no: int
    ) -> None:
        """Detach a version from a competition. A missing competition/version
        raises :class:`LookupError`; an attachment that does not exist also raises
        :class:`LookupError` (404) so a detach of nothing is not a silent 200."""
        with self._database.session_scope() as session:
            removed = SqlAlchemyChallengePublicationRepository(session).remove(
                competition_id, definition_slug, version_no
            )
        if not removed:
            raise LookupError(
                f"publication not found: {competition_id!r} / "
                f"{definition_slug!r} v{version_no}"
            )
