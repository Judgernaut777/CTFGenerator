"""SQLAlchemy writer for the ``worker_image_cache`` scheduler-affinity table.

Records that a given worker has a given ``image_ref`` cached locally, so the
scheduler's ``candidate_workers`` LEFT JOIN can rank a worker that already holds
the image ahead of one that would have to pull it (affinity only -- never a
placement gate; see :mod:`.scheduler_repository`). Populated at build-job
completion time, which is the only point where the worker's authenticated
identity and its reported ``image_ref`` coexist in one transaction (a finished
job's ``claimed_by`` is NULLed by the ``lease_state`` CHECK, so a post-hoc
projector could not attribute the image to its builder).

The write is an idempotent UPSERT: the deterministic build tag means rebuilding
the same version on the same worker yields the same ``image_ref`` and would
collide on ``UNIQUE(worker_id, image_ref)`` -- so a repeat refreshes
``last_used_at`` instead of raising. The worker's business name is resolved to
its surrogate uuid, failing loud on a dangling reference. ``image_ref`` is a
reference only -- never a flag or a secret.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from . import _resolve
from .models import WorkerImageCache as WorkerImageCacheRow


class SqlAlchemyWorkerImageCacheRepository:
    """Record worker->image affinity, keyed by ``(worker_id, image_ref)``."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def record(self, worker_name: str, image_ref: str, now: datetime) -> None:
        """Mark ``image_ref`` as cached on ``worker_name``. Raises
        :class:`LookupError` if the worker is unknown. Idempotent: a repeat
        UPSERTs ``last_used_at = now`` (deterministic build tags collide on the
        unique key), so re-completing the same build never raises. The caller
        must pass a non-empty ``image_ref`` (the DB CHECK rejects blank); the
        completion path guards this via :func:`parse_build_completion`."""
        worker_uuid = _resolve.worker_uuid(self._session, worker_name)
        stmt = pg_insert(WorkerImageCacheRow).values(
            worker_id=worker_uuid,
            image_ref=image_ref,
            last_used_at=now,
        )
        stmt = stmt.on_conflict_do_update(
            constraint="uq_worker_image_cache_worker_id_image_ref",
            set_={"last_used_at": now},
        )
        self._session.execute(stmt)
