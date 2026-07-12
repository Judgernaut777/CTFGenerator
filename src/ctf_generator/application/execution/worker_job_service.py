"""The one worker-facing surface over the durable job queue (application, M8).

This closes the invariant the M7 ``JobQueue.claim`` docstring records: the raw
queue accepts a ``worker_id`` *string* with no trust / drain / quarantine /
heartbeat check, so it must never be reachable with a request-supplied
``worker_id``. ``WorkerJobService`` is that gate. Before every queue verb it:

1. authenticates the presented bearer credential (constant-time; a bad, expired,
   revoked, non-trusted, or quarantined worker fails identically as
   :class:`WorkerAuthenticationError` -- the caller learns nothing about which);
2. enforces dispatch eligibility -- a *draining* worker may finish its in-flight
   leases but may not ``claim`` new work (this is what finally makes
   ``Worker.drain_requested_at`` live), and a worker whose liveness heartbeat is
   stale is refused until it re-pings;
3. requires the per-verb scope (``jobs:claim`` / ``jobs:heartbeat`` /
   ``jobs:complete``); and
4. derives ``worker_id`` -- and, for ``claim``, the capability set -- EXCLUSIVELY
   from the authenticated credential, so a worker can neither claim as another
   identity nor claim jobs beyond its declared capabilities.

Workers hold exactly one artifact -- the opaque scoped bearer token -- never the
control-plane DSN, never a session key. This service never executes challenge
code and never touches a container runtime; it only mediates queue state.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timedelta

from sqlalchemy.orm import Session

from ctf_generator.application.worker_enrollment import (
    AuthenticatedWorker,
    WorkerEnrollmentService,
    require_scope,
)
from ctf_generator.domain.repositories import JobQueue
from ctf_generator.domain.work.models import Job, JobLease
from ctf_generator.infrastructure.database.job_queue_repository import (
    SqlAlchemyJobQueue,
)
from ctf_generator.infrastructure.database.session import Database
from ctf_generator.infrastructure.database.worker_repository import (
    SqlAlchemyWorkerRegistry,
)

# A worker whose last liveness heartbeat is older than this is not
# dispatch-eligible (the M7 "heartbeat fresh" conjunct). It calls ``ping`` to
# refresh before it may operate again.
DEFAULT_HEARTBEAT_MAX_AGE_SECONDS = 60


class WorkerAuthenticationError(PermissionError):
    """The presented credential is invalid, expired, revoked, or belongs to a
    non-trusted / quarantined worker. Deliberately undifferentiated."""


class WorkerDrainingError(PermissionError):
    """The worker is draining: it may finish in-flight leases but may not claim
    new work."""


class WorkerStaleError(PermissionError):
    """The worker's liveness heartbeat is stale; it must ``ping`` before it may
    operate on the queue again."""


class WorkerJobService:
    """The authenticated, eligibility-gated worker API over the job queue."""

    def __init__(
        self,
        database: Database,
        enrollment: WorkerEnrollmentService,
        *,
        queue_factory: Callable[[Session], JobQueue] = SqlAlchemyJobQueue,
        heartbeat_max_age_seconds: int = DEFAULT_HEARTBEAT_MAX_AGE_SECONDS,
    ) -> None:
        self._database = database
        self._enrollment = enrollment
        self._queue_factory = queue_factory
        self._heartbeat_max_age = heartbeat_max_age_seconds

    # -- gate ------------------------------------------------------------------

    def _authorize(
        self,
        token: str,
        now: datetime,
        *,
        scope: str,
        forbid_drain: bool,
        check_liveness: bool,
    ) -> AuthenticatedWorker:
        """Authenticate + enforce eligibility + require ``scope``. Returns the
        authenticated worker (its ``name`` is the derived ``worker_id``)."""
        auth = self._enrollment.authenticate(token, now)
        if auth is None:
            raise WorkerAuthenticationError("worker authentication failed")
        require_scope(auth, scope)  # ScopeError if the credential lacks it
        if forbid_drain and auth.worker.drain_requested_at is not None:
            raise WorkerDrainingError(
                f"worker {auth.worker.name!r} is draining; cannot claim new work"
            )
        if check_liveness:
            last = auth.worker.last_heartbeat_at
            if last is None or (now - last) > timedelta(
                seconds=self._heartbeat_max_age
            ):
                raise WorkerStaleError(
                    f"worker {auth.worker.name!r} liveness heartbeat is stale"
                )
        return auth

    # -- liveness --------------------------------------------------------------

    def ping(self, token: str, now: datetime) -> None:
        """Refresh the worker's liveness heartbeat. Gated by authentication +
        the heartbeat scope, but NOT by staleness (this is how a stale worker
        recovers). Quarantined / revoked workers still cannot ping."""
        auth = self._authorize(
            token, now, scope="jobs:heartbeat", forbid_drain=False, check_liveness=False
        )
        with self._database.session_scope() as session:
            SqlAlchemyWorkerRegistry(session).heartbeat(auth.worker.name, now)

    # -- queue verbs -----------------------------------------------------------

    def claim(
        self, token: str, lease_seconds: int, now: datetime
    ) -> JobLease | None:
        """Claim the best job this worker may execute. ``worker_id`` and the
        capability set are derived from the credential -- never request-supplied
        -- so a worker cannot spoof another identity nor exceed its
        capabilities. Refused while draining or liveness-stale."""
        auth = self._authorize(
            token, now, scope="jobs:claim", forbid_drain=True, check_liveness=True
        )
        capabilities = frozenset(auth.worker.capabilities)
        with self._database.session_scope() as session:
            return self._queue_factory(session).claim(
                auth.worker.name, capabilities, lease_seconds, now
            )

    def start(
        self, token: str, job_id: str, lease_token: str, now: datetime
    ) -> None:
        """``claimed`` -> ``running``. Permitted while draining (finish leases);
        fenced by ``lease_token`` in the queue."""
        self._authorize(
            token, now, scope="jobs:heartbeat", forbid_drain=False, check_liveness=True
        )
        with self._database.session_scope() as session:
            self._queue_factory(session).start(job_id, lease_token, now)

    def heartbeat(
        self,
        token: str,
        job_id: str,
        lease_token: str,
        lease_seconds: int,
        now: datetime,
    ) -> bool:
        """Extend a lease; returns True iff cancellation was requested. Permitted
        while draining."""
        self._authorize(
            token, now, scope="jobs:heartbeat", forbid_drain=False, check_liveness=True
        )
        with self._database.session_scope() as session:
            return self._queue_factory(session).heartbeat(
                job_id, lease_token, lease_seconds, now
            )

    def complete(
        self,
        token: str,
        job_id: str,
        lease_token: str,
        result_json: dict | None,
        result_ref: str | None,
        log_ref: str | None,
        now: datetime,
    ) -> None:
        """``running`` -> ``succeeded``. Permitted while draining (finish
        leases). Results carry references/hashes only, never secrets."""
        self._authorize(
            token, now, scope="jobs:complete", forbid_drain=False, check_liveness=True
        )
        with self._database.session_scope() as session:
            self._queue_factory(session).complete(
                job_id, lease_token, result_json, result_ref, log_ref, now
            )

    def fail(
        self,
        token: str,
        job_id: str,
        lease_token: str,
        error_class: str,
        error_detail: str | None,
        retryable: bool,
        now: datetime,
    ) -> Job:
        """Report a failure (retry/dead-letter/cancel per the queue). Uses the
        completion scope; permitted while draining."""
        self._authorize(
            token, now, scope="jobs:complete", forbid_drain=False, check_liveness=True
        )
        with self._database.session_scope() as session:
            return self._queue_factory(session).fail(
                job_id, lease_token, error_class, error_detail, retryable, now
            )
