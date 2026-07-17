"""Worker-gateway dependencies: the SEPARATE worker-auth path + service wiring.

The worker authentication plane is deliberately DISJOINT from the human
Principal/``StubAuthenticator`` plane:

* A worker presents its short-lived scoped credential (``ctfw1.<id>.<secret>``) as
  ``Authorization: Bearer <token>``. :func:`require_worker` extracts the bearer and
  verifies it through :class:`WorkerEnrollmentService` -- the credential hash /
  trust / quarantine / expiry gate. It NEVER resolves a :class:`Principal`, and the
  human :func:`get_principal` / :func:`require_permission` deps are never wired onto
  a worker route. A human dev token cannot satisfy worker auth (it lacks the
  ``ctfw1.`` form and is not in the credential store) and a worker token cannot
  satisfy human auth (it is not in the ``StubAuthenticator`` table) -- the two
  planes are disjoint by construction.
* The edge authentication here yields the authenticated worker so the handler can
  STAMP reports with the credential's worker name (identity from the token, never
  the request). The gated application services independently re-authenticate the
  raw token and enforce every trust/scope/ownership check -- they remain the
  authoritative gate; this dependency is defense-in-depth + a clean early 401.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from fastapi import Depends, Request

from ctf_generator.application.execution.worker_build_service import (
    WorkerBuildService,
)
from ctf_generator.application.execution.worker_instance_service import (
    WorkerAuthenticationError,
    WorkerInstanceService,
)
from ctf_generator.application.execution.worker_job_service import WorkerJobService
from ctf_generator.application.instances.service import InstanceLifecycleService
from ctf_generator.application.jobs.service import JobService
from ctf_generator.application.scheduling.service import SchedulingService
from ctf_generator.application.worker_enrollment import (
    AuthenticatedWorker,
    WorkerEnrollmentService,
)
from ctf_generator.infrastructure.database.session import Database

from ..deps import get_database


@dataclass(frozen=True)
class WorkerAuthContext:
    """The authenticated worker for one request: the raw bearer token (passed
    verbatim to the gated services, which re-authenticate it) plus the verified
    identity (used only to STAMP reports -- never taken from the request body)."""

    token: str
    worker: AuthenticatedWorker

    @property
    def name(self) -> str:
        return self.worker.worker.name


def _worker_bearer(request: Request) -> str | None:
    header = request.headers.get("authorization")
    if not header:
        return None
    scheme, _, value = header.partition(" ")
    if scheme.lower() != "bearer" or not value.strip():
        return None
    return value.strip()


def get_worker_enrollment(
    database: Database = Depends(get_database),
) -> WorkerEnrollmentService:
    return WorkerEnrollmentService(database)


def get_worker_job_service(
    database: Database = Depends(get_database),
) -> WorkerJobService:
    return WorkerJobService(database, WorkerEnrollmentService(database))


def get_worker_build_service(
    database: Database = Depends(get_database),
) -> WorkerBuildService:
    return WorkerBuildService(database, WorkerEnrollmentService(database))


def get_worker_instance_service(
    database: Database = Depends(get_database),
) -> WorkerInstanceService:
    scheduling = SchedulingService(database)
    lifecycle = InstanceLifecycleService(
        database, scheduling=scheduling, jobs=JobService(database)
    )
    return WorkerInstanceService(
        lifecycle, WorkerEnrollmentService(database), scheduling=scheduling
    )


def require_worker(
    request: Request,
    enrollment: WorkerEnrollmentService = Depends(get_worker_enrollment),
) -> WorkerAuthContext:
    """Authenticate the worker credential and return its context.

    Raises :class:`WorkerAuthenticationError` (401) for a missing / malformed /
    invalid / expired / revoked / non-trusted / quarantined credential -- the
    failure is deliberately undifferentiated (the caller learns nothing about
    which check failed). A *draining* worker still authenticates here; the drain
    refusal is enforced per-verb by :class:`WorkerJobService`."""
    token = _worker_bearer(request)
    if not token:
        raise WorkerAuthenticationError("missing worker credential")
    auth = enrollment.authenticate(token, datetime.now(UTC))
    if auth is None:
        raise WorkerAuthenticationError("worker credential rejected")
    # Record only the worker NAME (an operator slug, never the secret) so the
    # access log can attribute the request without echoing the credential.
    request.state.worker_name = auth.worker.name
    return WorkerAuthContext(token=token, worker=auth)
