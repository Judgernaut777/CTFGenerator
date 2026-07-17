"""The worker-facing, scope-gated surface over the FULL build bundle
(``docs/architecture/build-challenge-worker-pipeline.md``).

Mirrors :class:`~ctf_generator.application.execution.worker_job_service.WorkerJobService`'s
authenticate-then-act shape: a bad/expired/revoked/non-trusted/quarantined
credential fails identically (reuses THE SAME
:class:`~ctf_generator.application.execution.worker_job_service.WorkerAuthenticationError`
class, so the app-wide ``ctfgen.error`` 401 handler -- already registered for
it -- covers this verb with no additional wiring), and the ``artifacts:pull``
scope (reserved in ``VALID_CREDENTIAL_SCOPES`` since M8, previously unwired) is
required.

LEASE FENCE (the BLOCKER fix). ``artifacts:pull`` is a fleet-wide DEFAULT scope
(``application/worker_enrollment.py`` ``_DEFAULT_SCOPES``) -- credential + scope
alone would let ANY enrolled worker pull ANY challenge's private, flag/solver-
bearing bundle for any ``(definition_slug, version_no)``, with no relationship
to a job it actually holds. Every sibling data-bearing worker verb
(``start``/``heartbeat``/``complete``/``fail`` in ``WorkerJobService``) is
fenced by ``(job_id, lease_token)`` verified against the job queue's lease, so
this verb must be too: the caller must prove it holds a LIVE lease on a
``build_challenge`` job whose payload matches the requested
``(definition_slug, version_no)`` before a single byte is rendered. The lease
check REUSES the queue's own fencing mechanism -- ``JobQueue.heartbeat``, the
exact ``_fenced_row``-backed check ``WorkerJobService.complete``/``.fail``
already rely on -- rather than inventing a new one; a missing job or a stale/
mismatched ``lease_token`` raises the SAME :class:`LookupError` (-> 404) every
other lease-fenced verb raises for a bad lease, so the existing ``ctfgen.error``
envelope handler covers it with no new wiring. As a side effect this also
extends the lease, so a slow bundle transfer cannot lose it mid-flight.

NOT liveness-gated, matching ``WorkerJobService.complete``/``.fail``: a worker
mid-lease fetching the bundle for a ``build_challenge`` job it already holds
must be accepted regardless of heartbeat age -- refusing it here would strand
the job without ever reaching a queue verb that could report the failure.
Permitted while draining (finish in-flight work), for the same reason.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy.orm import Session

from ctf_generator.application.authoring.full_bundle import FullBundleService
from ctf_generator.application.execution.worker_job_service import (
    WorkerAuthenticationError,
)
from ctf_generator.application.worker_enrollment import (
    WorkerEnrollmentService,
    require_scope,
)
from ctf_generator.domain.repositories import JobQueue
from ctf_generator.infrastructure.database.job_queue_repository import (
    SqlAlchemyJobQueue,
)
from ctf_generator.infrastructure.database.session import Database

_ARTIFACTS_PULL_SCOPE = "artifacts:pull"

# The job_type a lease must belong to for a bundle fetch to be honored.
_BUILD_JOB_TYPE = "build_challenge"

# The lease extension applied by the ownership check's ``JobQueue.heartbeat``
# call (a side effect of reusing that verb as the fence) -- matches
# ``WorkerConfig.lease_seconds``'s own default (``workers/worker.py``) and
# ``WorkerJobService.DEFAULT_HEARTBEAT_MAX_AGE_SECONDS``, so a bundle fetch
# grants the same headroom a normal heartbeat would.
_LEASE_VERIFY_EXTENSION_SECONDS = 60


@dataclass(frozen=True)
class BuildBundleView:
    """The wire-agnostic result of a bundle fetch -- carried into both
    ``LocalControlPlaneClient`` (used directly) and the HTTP response (mapped
    onto bytes + headers by the worker-gateway router). May embed the
    flag/solution -- NEVER log ``data``."""

    data: bytes
    bundle_sha256: str
    spec_sha256: str


class WorkerBuildService:
    """Authenticated, ``artifacts:pull``-scoped worker access to a version's
    FULL buildable bundle. Never reachable without a valid worker credential;
    never exposes anything beyond what :class:`FullBundleService` renders."""

    def __init__(
        self,
        database: Database,
        enrollment: WorkerEnrollmentService,
        *,
        full_bundles: FullBundleService | None = None,
        queue_factory: Callable[[Session], JobQueue] = SqlAlchemyJobQueue,
    ) -> None:
        self._database = database
        self._enrollment = enrollment
        self._full_bundles = full_bundles if full_bundles is not None else FullBundleService(database)
        self._queue_factory = queue_factory

    def fetch_build_bundle(
        self,
        token: str,
        definition_slug: str,
        version_no: int,
        job_id: str,
        lease_token: str,
        now: datetime,
    ) -> BuildBundleView:
        """Authenticate ``token``, require ``artifacts:pull``, verify the caller
        holds a LIVE lease on a ``build_challenge`` job for
        ``(definition_slug, version_no)``, and only then render the FULL
        bundle. Raises :class:`WorkerAuthenticationError` (401) for a bad
        credential, :class:`~ctf_generator.application.worker_enrollment.ScopeError`
        (403) for a credential missing the scope, :class:`LookupError` (404)
        for a missing/foreign/mismatched lease OR an unknown version -- the
        same error vocabulary every other worker verb uses."""
        auth = self._enrollment.authenticate(token, now)
        if auth is None:
            raise WorkerAuthenticationError("worker authentication failed")
        require_scope(auth, _ARTIFACTS_PULL_SCOPE)
        self._verify_build_lease(job_id, lease_token, definition_slug, version_no, now)
        bundle = self._full_bundles.render(definition_slug, version_no)
        return BuildBundleView(
            data=bundle.data,
            bundle_sha256=bundle.bundle_sha256,
            spec_sha256=bundle.spec_sha256,
        )

    def _verify_build_lease(
        self,
        job_id: str,
        lease_token: str,
        definition_slug: str,
        version_no: int,
        now: datetime,
    ) -> None:
        """Prove the caller holds a LIVE lease on ``job_id`` -- via
        ``JobQueue.heartbeat``, the SAME lease-fenced check
        ``WorkerJobService.complete``/``.fail`` use (not a new mechanism) --
        and that the leased job is a ``build_challenge`` for exactly this
        ``(definition_slug, version_no)``. A missing job or a stale/mismatched
        ``lease_token`` raises :class:`LookupError` from ``heartbeat`` itself
        (unchanged, un-caught); a live lease on the WRONG job/version raises
        the identical :class:`LookupError` here, so both cases surface as the
        same 404 a bad lease already produces on every other queue verb.
        Changes nothing on refusal (the whole check runs in one transaction
        that is rolled back on any raise)."""
        with self._database.session_scope() as session:
            queue = self._queue_factory(session)
            # Fences on (job_id, lease_token) exactly like complete/fail;
            # raises LookupError for a missing job or a stale/foreign token.
            queue.heartbeat(job_id, lease_token, _LEASE_VERIFY_EXTENSION_SECONDS, now)
            job = queue.get(job_id)
            if (
                job is None
                or job.job_type != _BUILD_JOB_TYPE
                or job.definition_slug != definition_slug
                or job.version_no != version_no
            ):
                raise LookupError(
                    f"job {job_id!r} is not a live build_challenge lease for "
                    f"{definition_slug!r} v{version_no}"
                )
