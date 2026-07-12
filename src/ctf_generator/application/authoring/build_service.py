"""Build inspection + build-job triggering (control-plane facade).

``BuildService`` owns the unit of work for the two read paths (list a version's
content-addressed builds; fetch one by ``build_sha256``) and delegates the
*trigger* to :class:`~ctf_generator.application.jobs.service.JobService`, which
enqueues a durable ``build_challenge`` job idempotently. The control plane NEVER
runs the build (ADR-001): this module imports no Docker/subprocess and executes
no generator code -- a worker claims the job with scoped credentials.

The trigger's idempotency key folds in the version's ``spec_sha256`` so a repeat
trigger of the same content collapses to one job, while a re-generated draft
(new content hash) yields a fresh build job. The payload carries references and a
content hash only -- never a flag, seed, or secret.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from ctf_generator.domain.authoring.models import ChallengeBuild
from ctf_generator.domain.work.models import Job
from ctf_generator.infrastructure.database.challenge_build_repository import (
    SqlAlchemyChallengeBuildRepository,
)
from ctf_generator.infrastructure.database.challenge_version_repository import (
    SqlAlchemyChallengeVersionRepository,
)
from ctf_generator.infrastructure.database.session import Database

from ..jobs.service import JobService

_BUILD_JOB_TYPE = "build_challenge"


class BuildService:
    """Read builds + enqueue the build job; the control plane never builds."""

    def __init__(self, database: Database, *, jobs: JobService) -> None:
        self._database = database
        self._jobs = jobs

    # -- reads ---------------------------------------------------------------

    def list_for_version(
        self, definition_slug: str, version_no: int
    ) -> list[ChallengeBuild]:
        with self._database.session_scope() as session:
            return SqlAlchemyChallengeBuildRepository(session).list_for_version(
                definition_slug, version_no
            )

    def get(self, build_sha256: str) -> ChallengeBuild | None:
        with self._database.session_scope() as session:
            return SqlAlchemyChallengeBuildRepository(session).get(build_sha256)

    # -- trigger -------------------------------------------------------------

    def trigger_build(
        self, definition_slug: str, version_no: int, now: datetime
    ) -> tuple[Job, bool]:
        """Enqueue a ``build_challenge`` job for an existing version. Raises
        :class:`LookupError` if the version is unknown (404). Returns
        ``(job, created)`` -- ``created`` is False when a prior identical trigger
        already enqueued the job (idempotent collapse). The build itself runs on a
        worker, never here."""
        with self._database.session_scope() as session:
            version = SqlAlchemyChallengeVersionRepository(session).get(
                definition_slug, version_no
            )
        if version is None:
            raise LookupError(
                f"challenge version not found: {definition_slug!r} v{version_no}"
            )
        job = Job(
            job_id=str(uuid.uuid4()),
            job_type=_BUILD_JOB_TYPE,
            idempotency_key=(
                f"build:{definition_slug}:v{version_no}:{version.spec_sha256}"
            ),
            available_at=now,
            required_capabilities=(_BUILD_JOB_TYPE,),
            # References + a content hash only -- never the seed or a secret.
            payload={
                "definition_slug": definition_slug,
                "version_no": version_no,
                "spec_sha256": version.spec_sha256,
            },
            definition_slug=definition_slug,
            version_no=version_no,
        )
        return self._jobs.enqueue_idempotent(job, now)
