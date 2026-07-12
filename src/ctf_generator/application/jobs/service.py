"""Control-plane job-queue service: idempotent enqueue, cancel, inspection,
and the lease-expiry reap loop.

Owns the unit of work (``Database.session_scope()``: repositories flush, the
UoW commits once). Pure SQL over the ``JobQueue`` protocol -- this module
never imports Docker or executes challenge code (ADR-001); the worker-side
claim/heartbeat/complete loop is a separate executable slice that programs
only against the same protocol with scoped credentials, never the
control-plane DSN.

Payload hygiene is guarded here by convention and review: payloads carry
references and hashes only (build hashes, artifact keys, instance ids) --
never flags, tokens, provider keys, or worker credentials.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ctf_generator.domain.work.models import Job
from ctf_generator.infrastructure.database.job_queue_repository import (
    SqlAlchemyJobQueue,
)
from ctf_generator.infrastructure.database.session import Database


class JobService:
    """Enqueue-idempotent control-plane facade over the durable job queue."""

    def __init__(
        self,
        database: Database,
        queue_factory: Callable[[Session], SqlAlchemyJobQueue] = SqlAlchemyJobQueue,
    ) -> None:
        self._database = database
        self._queue_factory = queue_factory

    def enqueue_idempotent(self, job: Job) -> tuple[Job, bool]:
        """Enqueue ``job``, collapsing a duplicate ``idempotency_key`` to the
        existing row. Returns ``(job, created)`` -- ``created`` is False when
        an earlier enqueue won (retries and API double-submits collapse to
        one row)."""
        try:
            with self._database.session_scope() as session:
                persisted = self._queue_factory(session).enqueue(job)
            return persisted, True
        except IntegrityError:
            with self._database.session_scope() as session:
                existing = self._queue_factory(session).get_by_idempotency_key(
                    job.idempotency_key
                )
            if existing is None:  # pragma: no cover - a rolled-back rival
                raise
            return existing, False

    def get(self, job_id: str) -> Job | None:
        with self._database.session_scope() as session:
            return self._queue_factory(session).get(job_id)

    def get_by_idempotency_key(self, key: str) -> Job | None:
        with self._database.session_scope() as session:
            return self._queue_factory(session).get_by_idempotency_key(key)

    def cancel(self, job_id: str, now: datetime) -> Job:
        """Cancel a queued job directly, or request cooperative cancellation
        of a claimed/running one (the worker observes it via heartbeat)."""
        with self._database.session_scope() as session:
            return self._queue_factory(session).request_cancel(job_id, now)

    def reap_expired(self, now: datetime, limit: int = 100) -> list[Job]:
        """One sweep of the lease reaper (requeue-with-backoff or
        dead-letter). Safe to run periodically on the control plane."""
        with self._database.session_scope() as session:
            return self._queue_factory(session).reap_expired(now, limit)

    def list_dead_letter(self) -> list[Job]:
        with self._database.session_scope() as session:
            return self._queue_factory(session).list_dead_letter()

    def retry_dead_letter(self, job_id: str, now: datetime) -> Job:
        with self._database.session_scope() as session:
            return self._queue_factory(session).retry_dead_letter(job_id, now)
