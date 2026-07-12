"""Concrete SQLAlchemy repository for the ChallengeBuild aggregate.

Implements the domain
:class:`ctf_generator.domain.repositories.ChallengeBuildRepository` over the
content-addressed, insert-only ``challenge_builds`` table. A build references the
version it materializes by the business ``(definition_slug, version_no)``; the
repository resolves it to the surrogate uuid, fails loudly if the version is
missing, and verifies the build's ``spec_sha256`` matches the version's (design
§4: "must equal the version's"). Builds are never updated -- the
``challenge_builds_immutable`` DB trigger is the backstop.
"""

from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from ctf_generator.domain.authoring.models import ChallengeBuild

from .mappers import challenge_build_from_orm, challenge_build_to_orm
from .models import ChallengeBuild as ChallengeBuildRow
from .models import ChallengeDefinition as ChallengeDefinitionRow
from .models import ChallengeVersion as ChallengeVersionRow


class SqlAlchemyChallengeBuildRepository:
    """Persist and retrieve builds, keyed by ``build_sha256``."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def _version_uuid_and_sha(
        self, definition_slug: str, version_no: int
    ) -> tuple[uuid.UUID, str]:
        """Resolve ``(definition_slug, version_no)`` to ``(version_uuid,
        spec_sha256)``. Raises :class:`LookupError` if the version is missing."""
        result = self._session.execute(
            select(ChallengeVersionRow.id, ChallengeVersionRow.spec_sha256)
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
        return result.id, result.spec_sha256

    def add(self, build: ChallengeBuild) -> None:
        """Insert a build for an existing version. Raises :class:`LookupError`
        if the version is missing, :class:`ValueError` if the build's
        ``spec_sha256`` disagrees with the version's, and IntegrityError on a
        duplicate ``build_sha256`` (content address) at flush time."""
        version_uuid, version_spec_sha256 = self._version_uuid_and_sha(
            build.definition_slug, build.version_no
        )
        if build.spec_sha256 != version_spec_sha256:
            raise ValueError(
                "build.spec_sha256 does not match the version's "
                f"({build.spec_sha256!r} != {version_spec_sha256!r})"
            )
        row = challenge_build_to_orm(build, version_uuid)
        self._session.add(row)
        self._session.flush()

    def get(self, build_sha256: str) -> ChallengeBuild | None:
        row = self._session.execute(
            select(
                ChallengeBuildRow,
                ChallengeDefinitionRow.slug,
                ChallengeVersionRow.version_no,
            )
            .join(
                ChallengeVersionRow,
                ChallengeBuildRow.challenge_version_id == ChallengeVersionRow.id,
            )
            .join(
                ChallengeDefinitionRow,
                ChallengeVersionRow.definition_id == ChallengeDefinitionRow.id,
            )
            .where(ChallengeBuildRow.build_sha256 == build_sha256)
        ).one_or_none()
        if row is None:
            return None
        build_row, definition_slug, version_no = row
        return challenge_build_from_orm(build_row, definition_slug, version_no)

    def list_for_version(
        self, definition_slug: str, version_no: int
    ) -> list[ChallengeBuild]:
        rows = self._session.scalars(
            select(ChallengeBuildRow)
            .join(
                ChallengeVersionRow,
                ChallengeBuildRow.challenge_version_id == ChallengeVersionRow.id,
            )
            .join(
                ChallengeDefinitionRow,
                ChallengeVersionRow.definition_id == ChallengeDefinitionRow.id,
            )
            .where(
                ChallengeDefinitionRow.slug == definition_slug,
                ChallengeVersionRow.version_no == version_no,
            )
        )
        return [
            challenge_build_from_orm(row, definition_slug, version_no) for row in rows
        ]
