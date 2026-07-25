"""SQLAlchemy repository for the ``challenge_build_stack_images`` registry.

Records one row per SERVICE of a multi-service (compose) build, and resolves the
full stack for a launch from the primary service's ``image_ref`` (the ref the
Instance already carries). All services of one build share a ``bundle_sha256``,
so the launch reader groups by it -- pinning the exact build the instance was
placed on, not a newer rebuild.

Writes are idempotent, append-only INSERTs (ON CONFLICT on the deterministic
``(challenge_version_id, service_name, image_ref)`` unique key). References/hashes
only -- never a flag or secret. The business ``(definition_slug, version_no)``
resolves to the version's surrogate uuid, failing loud on a dangling reference on
the write path; the read path is a non-raising miss.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from ctf_generator.domain.execution.runtime import StackServiceImage

from . import _resolve
from .models import ChallengeBuildStackImage as StackImageRow
from .models import ChallengeDefinition as ChallengeDefinitionRow
from .models import ChallengeVersion as ChallengeVersionRow

__all__ = ["SqlAlchemyChallengeBuildStackImageRepository", "StackServiceImage"]


class SqlAlchemyChallengeBuildStackImageRepository:
    """Persist + read per-service stack images, keyed by challenge version."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def add_service(
        self,
        definition_slug: str,
        version_no: int,
        *,
        service_name: str,
        image_ref: str,
        image_digest: str,
        bundle_sha256: str,
        depends_on: tuple[str, ...],
        expose: tuple[str, ...],
        is_primary: bool,
        now: datetime,
    ) -> None:
        """Record one service image for ``(definition_slug, version_no)``. Raises
        :class:`LookupError` if the version is unknown (callers pass the JOB's own
        version). Idempotent: a repeat of the same ``(version, service, image_ref)``
        collapses via ON CONFLICT DO NOTHING (image_ref is deterministic), so
        re-driving a completed build records nothing new."""
        version_uuid = _resolve.version_uuid(
            self._session, definition_slug, version_no
        )
        stmt = (
            pg_insert(StackImageRow)
            .values(
                challenge_version_id=version_uuid,
                service_name=service_name,
                image_ref=image_ref,
                image_digest=image_digest,
                bundle_sha256=bundle_sha256,
                depends_on=list(depends_on),
                expose=list(expose),
                is_primary=is_primary,
                created_at=now,
            )
            .on_conflict_do_nothing(
                constraint="uq_challenge_build_stack_images_ver_svc_img"
            )
        )
        self._session.execute(stmt)

    def stack_for_primary_image(
        self, definition_slug: str, version_no: int, primary_image_ref: str
    ) -> tuple[StackServiceImage, ...]:
        """The full set of service images for the build whose PRIMARY service is
        ``primary_image_ref``, or ``()`` when there is no stack for it (a
        single-image instance, or an unknown ref). Grouped by the primary row's
        ``bundle_sha256`` so every returned service belongs to the SAME build the
        instance was placed on. Ordered by service name for determinism (the
        launcher topologically re-orders by ``depends_on``)."""
        bundle_sha256 = self._session.execute(
            select(StackImageRow.bundle_sha256)
            .join(
                ChallengeVersionRow,
                StackImageRow.challenge_version_id == ChallengeVersionRow.id,
            )
            .join(
                ChallengeDefinitionRow,
                ChallengeVersionRow.definition_id == ChallengeDefinitionRow.id,
            )
            .where(
                ChallengeDefinitionRow.slug == definition_slug,
                ChallengeVersionRow.version_no == version_no,
                StackImageRow.image_ref == primary_image_ref,
                StackImageRow.is_primary.is_(True),
            )
        ).scalar_one_or_none()
        if bundle_sha256 is None:
            return ()

        rows = self._session.scalars(
            select(StackImageRow)
            .join(
                ChallengeVersionRow,
                StackImageRow.challenge_version_id == ChallengeVersionRow.id,
            )
            .join(
                ChallengeDefinitionRow,
                ChallengeVersionRow.definition_id == ChallengeDefinitionRow.id,
            )
            .where(
                ChallengeDefinitionRow.slug == definition_slug,
                ChallengeVersionRow.version_no == version_no,
                StackImageRow.bundle_sha256 == bundle_sha256,
            )
            .order_by(StackImageRow.service_name.asc())
        )
        return tuple(
            StackServiceImage(
                service_name=r.service_name,
                image_ref=r.image_ref,
                image_digest=r.image_digest,
                depends_on=tuple(r.depends_on or ()),
                expose=tuple(r.expose or ()),
                is_primary=r.is_primary,
            )
            for r in rows
        )
