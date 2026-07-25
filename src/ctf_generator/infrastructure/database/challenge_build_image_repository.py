"""SQLAlchemy repository for the ``challenge_build_images`` registry.

Records the runnable Docker image a worker built for a challenge version
(``image_ref`` + ``image_digest`` + ``bundle_sha256``) and resolves the latest
built image for a ``(definition_slug, version_no)`` at instance-launch time.

The write is an idempotent, append-only INSERT: a deterministic rebuild of the
same version yields the same ``image_digest`` and collapses via ``ON CONFLICT
(challenge_version_id, image_digest) DO NOTHING`` -- so a replayed/duplicated
build completion never errors and never mutates the append-only row (the DB
``reject_mutation`` trigger is the backstop). The business ``(definition_slug,
version_no)`` is resolved to the version's surrogate uuid, failing loud
(:class:`LookupError`) on a dangling reference exactly like the ledger
resolvers. Infrastructure-only; ORM rows never escape (image_ref is a plain
string). References/hashes only -- never a flag or a secret.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from . import _resolve
from .models import ChallengeBuildImage as ChallengeBuildImageRow
from .models import ChallengeDefinition as ChallengeDefinitionRow
from .models import ChallengeVersion as ChallengeVersionRow


class SqlAlchemyChallengeBuildImageRepository:
    """Persist worker-built image references, keyed by challenge version."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def add(
        self,
        definition_slug: str,
        version_no: int,
        image_ref: str,
        image_digest: str,
        bundle_sha256: str,
        now: datetime,
    ) -> None:
        """Record the built image for ``(definition_slug, version_no)``. Raises
        :class:`LookupError` if the version is unknown -- callers pass the JOB's
        own ``(definition_slug, version_no)`` (which always resolve via the job's
        FK), never a worker-supplied payload, so this is a corruption signal, not
        a routine miss. Idempotent: a repeat of the same ``(version, image_ref)``
        collapses via ON CONFLICT DO NOTHING (``image_ref`` is deterministic from
        the bundle hash, so a rebuild of the same frozen version reports the same
        reference), so re-driving a completed build job records nothing new and
        never raises on a duplicate. ``created_at`` is set from the injected
        ``now`` so the launch reader's newest-wins ordering is deterministic."""
        version_uuid = _resolve.version_uuid(
            self._session, definition_slug, version_no
        )
        stmt = (
            pg_insert(ChallengeBuildImageRow)
            .values(
                challenge_version_id=version_uuid,
                image_ref=image_ref,
                image_digest=image_digest,
                bundle_sha256=bundle_sha256,
                created_at=now,
            )
            .on_conflict_do_nothing(
                constraint="uq_challenge_build_images_challenge_version_id_image_ref"
            )
        )
        self._session.execute(stmt)

    def latest_image_ref_for_version(
        self, definition_slug: str, version_no: int
    ) -> str | None:
        """The most recently recorded built ``image_ref`` for the version, or
        ``None`` if no build has been recorded yet. Newest wins (``created_at``
        desc, then a stable ``id`` tiebreak). Returns ``None`` -- never an empty
        string -- so a miss leaves ``Instance.image_ref`` unset rather than
        tripping its non-empty validation. Does NOT raise on an unknown version:
        the inner join simply yields no rows (a legitimate 'no image yet' miss),
        which is distinct from the write path's fail-loud resolution."""
        return self._session.execute(
            select(ChallengeBuildImageRow.image_ref)
            .join(
                ChallengeVersionRow,
                ChallengeBuildImageRow.challenge_version_id == ChallengeVersionRow.id,
            )
            .join(
                ChallengeDefinitionRow,
                ChallengeVersionRow.definition_id == ChallengeDefinitionRow.id,
            )
            .where(
                ChallengeDefinitionRow.slug == definition_slug,
                ChallengeVersionRow.version_no == version_no,
            )
            .order_by(
                ChallengeBuildImageRow.created_at.desc(),
                ChallengeBuildImageRow.id.desc(),
            )
            .limit(1)
        ).scalar_one_or_none()

    def digest_for_version_image(
        self, definition_slug: str, version_no: int, image_ref: str
    ) -> str | None:
        """The recorded ``image_digest`` for the EXACT ``(version, image_ref)``, or
        ``None`` if none is recorded. Keyed on the registry's unique
        ``(challenge_version_id, image_ref)`` so it resolves at most one row --
        launch-time digest-pinning must verify the digest of the image the instance
        ACTUALLY carries (pinned at request time), not merely the newest build,
        which may have appended a different image since. Non-raising on an unknown
        version/image (an inner-join miss), like the reader above."""
        return self._session.execute(
            select(ChallengeBuildImageRow.image_digest)
            .join(
                ChallengeVersionRow,
                ChallengeBuildImageRow.challenge_version_id == ChallengeVersionRow.id,
            )
            .join(
                ChallengeDefinitionRow,
                ChallengeVersionRow.definition_id == ChallengeDefinitionRow.id,
            )
            .where(
                ChallengeDefinitionRow.slug == definition_slug,
                ChallengeVersionRow.version_no == version_no,
                ChallengeBuildImageRow.image_ref == image_ref,
            )
        ).scalar_one_or_none()
