"""The one worker-facing surface over the durable job queue (application, M8).

This closes the invariant the M7 ``JobQueue.claim`` docstring records: the raw
queue accepts a ``worker_id`` *string* with no trust / drain / quarantine /
heartbeat check, so it must never be reachable with a request-supplied
``worker_id``. ``WorkerJobService`` is that gate. Before every queue verb it:

1. authenticates the presented bearer credential (constant-time; a bad, expired,
   revoked, non-trusted, or quarantined worker fails identically as
   :class:`WorkerAuthenticationError` -- the caller learns nothing about which);
2. enforces dispatch eligibility for *new* work -- ``claim`` alone requires a
   fresh, non-draining, live worker (a *draining* worker may finish its in-flight
   leases but may not ``claim``, which is what finally makes
   ``Worker.drain_requested_at`` live; a heartbeat-stale worker is refused until
   it re-pings). ``start`` / ``heartbeat`` / ``complete`` / ``fail`` are NOT
   liveness-gated: they are fenced by the ``lease_token``, so a worker reporting
   a real outcome for a lease it holds is always accepted -- refusing it on
   heartbeat age would reap the lease and double-execute the job;
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

from ctf_generator.application.execution.build_completion import (
    parse_build_completion,
)
from ctf_generator.application.worker_enrollment import (
    AuthenticatedWorker,
    WorkerEnrollmentService,
    require_scope,
)
from ctf_generator.domain.repositories import JobQueue
from ctf_generator.domain.work.models import Job, JobLease
from ctf_generator.infrastructure.database.challenge_build_image_repository import (
    SqlAlchemyChallengeBuildImageRepository,
)
from ctf_generator.infrastructure.database.job_queue_repository import (
    SqlAlchemyJobQueue,
)
from ctf_generator.infrastructure.database.session import Database
from ctf_generator.infrastructure.database.worker_image_cache_repository import (
    SqlAlchemyWorkerImageCacheRepository,
)
from ctf_generator.infrastructure.database.worker_repository import (
    SqlAlchemyWorkerRegistry,
)

# A worker whose last liveness heartbeat is older than this is not
# dispatch-eligible (the M7 "heartbeat fresh" conjunct). It calls ``ping`` to
# refresh before it may operate again.
DEFAULT_HEARTBEAT_MAX_AGE_SECONDS = 60

# The one job type whose completion carries a built image to record. Kept in
# lockstep with ``application.authoring.build_service._BUILD_JOB_TYPE``.
_BUILD_JOB_TYPE = "build_challenge"


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
        fenced by ``lease_token`` in the queue. NOT liveness-gated: a worker that
        holds the lease is reporting real progress on work it owns, so it must be
        accepted regardless of heartbeat age (only ``claim`` requires freshness)."""
        self._authorize(
            token, now, scope="jobs:heartbeat", forbid_drain=False, check_liveness=False
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
        while draining. NOT liveness-gated (lease-fenced; see ``start``)."""
        self._authorize(
            token, now, scope="jobs:heartbeat", forbid_drain=False, check_liveness=False
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
        leases). Results carry references/hashes only, never secrets. NOT
        liveness-gated: refusing a real outcome for a held lease because the
        worker's heartbeat aged would reap the lease and double-execute the job.

        BUILD SIDE EFFECTS (build_challenge slice 2): when a ``build_challenge``
        job's result carries a built ``image_ref``, two idempotent writes ride the
        SAME unit of work as the job terminalization:

        * the worker-affinity cache (``worker_image_cache``), keyed to THIS
          authenticated worker -- the only point where the worker's credential
          identity and its reported image coincide (a terminal job's
          ``claimed_by`` is NULL, so no later projector could attribute it); and
        * the version->image registry (``challenge_build_images``), read at
          launch time to run the freshly-built image -- written only when the
          build reported both a content digest and a bundle hash.

        Two identities are kept strictly separate, because a worker is hostile
        input by construction (ADR-001):

        * the WORKER is ``auth.worker.name`` -- the authenticated credential,
          never a payload field;
        * the TARGET VERSION is the JOB's own recorded ``(definition_slug,
          version_no)`` -- read back from the job row, never the worker-supplied
          ``result_json`` slug/version. Trusting the payload here would let any
          worker holding any build lease poison another challenge's version->image
          mapping. Both writes are also gated on the job actually being a
          ``build_challenge`` job (from the authoritative job row).

        Non-fatal to terminalization: ``parse_build_completion`` never raises, and
        the registry write keys on the job's own version (which always resolves,
        via the job's FK), so a malformed or misreporting worker payload cannot
        roll back an otherwise-successful completion. References/hashes only; the
        payload is never logged."""
        auth = self._authorize(
            token, now, scope="jobs:complete", forbid_drain=False, check_liveness=False
        )
        completion = parse_build_completion(result_json)
        with self._database.session_scope() as session:
            queue = self._queue_factory(session)
            queue.complete(
                job_id, lease_token, result_json, result_ref, log_ref, now
            )
            if completion is not None:
                # Bind the side effects to the AUTHORITATIVE job, not the payload.
                job = queue.get(job_id)
                if job is not None and job.job_type == _BUILD_JOB_TYPE:
                    # Affinity cache: keyed to the authenticated worker.
                    SqlAlchemyWorkerImageCacheRepository(session).record(
                        auth.worker.name, completion.image_ref, now
                    )
                    # Version->image registry: keyed to the JOB's own version
                    # (never the payload), and only when the build carries the
                    # digest + bundle the NOT-NULL registry columns require.
                    if (
                        completion.can_record_image
                        and job.definition_slug is not None
                        and job.version_no is not None
                    ):
                        SqlAlchemyChallengeBuildImageRepository(session).add(
                            job.definition_slug,
                            job.version_no,
                            completion.image_ref,
                            completion.image_digest,
                            completion.bundle_sha256,
                            now,
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
        completion scope; permitted while draining. NOT liveness-gated (a held
        lease reporting its real outcome is always accepted; see ``complete``)."""
        self._authorize(
            token, now, scope="jobs:complete", forbid_drain=False, check_liveness=False
        )
        with self._database.session_scope() as session:
            return self._queue_factory(session).fail(
                job_id, lease_token, error_class, error_detail, retryable, now
            )
