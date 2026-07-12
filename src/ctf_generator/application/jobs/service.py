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

import hashlib
import json
from collections.abc import Callable
from datetime import datetime

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ctf_generator.domain.repositories import JobQueue
from ctf_generator.domain.work.models import Job
from ctf_generator.infrastructure.database.job_queue_repository import (
    SqlAlchemyJobQueue,
)
from ctf_generator.infrastructure.database.session import Database


class JobIdempotencyConflictError(Exception):
    """A reused ``idempotency_key`` arrived with a different request identity
    (job_type / canonical payload / required_capabilities) than the stored
    job. Mirrors the submission service's identity-tuple conflict: a key must
    name exactly one logical request, so silently returning an unrelated job
    would be a correctness hazard, not idempotency."""


def _canonical_payload_hash(payload) -> str:
    """Stable sha256 of a payload mapping (sorted keys, compact separators) so
    two logically-identical payloads hash equal regardless of key order."""
    return hashlib.sha256(
        json.dumps(dict(payload), sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
    ).hexdigest()


class JobService:
    """Enqueue-idempotent control-plane facade over the durable job queue."""

    def __init__(
        self,
        database: Database,
        queue_factory: Callable[[Session], JobQueue] = SqlAlchemyJobQueue,
    ) -> None:
        self._database = database
        self._queue_factory = queue_factory

    def enqueue_idempotent(
        self, job: Job, now: datetime | None = None
    ) -> tuple[Job, bool]:
        """Enqueue ``job``, collapsing a duplicate ``idempotency_key`` to the
        existing row. Returns ``(job, created)`` -- ``created`` is False when
        an earlier enqueue won (retries and API double-submits collapse to
        one row). A duplicate key whose request identity (job_type / canonical
        payload / required_capabilities) differs from the stored job raises
        :class:`JobIdempotencyConflictError`."""
        try:
            with self._database.session_scope() as session:
                persisted = self._queue_factory(session).enqueue(job, now)
            return persisted, True
        except IntegrityError:
            with self._database.session_scope() as session:
                existing = self._queue_factory(session).get_by_idempotency_key(
                    job.idempotency_key
                )
            if existing is None:  # pragma: no cover - a rolled-back rival
                raise
            if not self._same_request(existing, job):
                raise JobIdempotencyConflictError(
                    f"idempotency_key {job.idempotency_key!r} was already used "
                    "for a request with a different identity"
                ) from None
            return existing, False

    @staticmethod
    def _same_request(existing: Job, incoming: Job) -> bool:
        return (
            existing.job_type == incoming.job_type
            and _canonical_payload_hash(existing.payload)
            == _canonical_payload_hash(incoming.payload)
            and sorted(set(existing.required_capabilities))
            == sorted(set(incoming.required_capabilities))
        )

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
