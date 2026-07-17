"""Worker-facing HTTP gateway router (M9 slice d).

Exposes the ALREADY-GATED worker application services 1:1 over HTTP so a REMOTE
worker can drive the job queue and report instance facts across the network. Each
handler is thin: authenticate the worker credential (the SEPARATE worker-auth
dependency), make ONE gated service call, and map the domain result to a wire DTO.

Security properties enforced here:

* Identity comes ONLY from the credential. No handler reads a ``worker_id`` /
  ``worker_name`` from the path/query/body; the gated services derive it from the
  token, and the health/resource handlers STAMP the authenticated worker name onto
  the domain object (a supplied ``worker`` field is impossible -- the DTOs forbid
  it). This closes the M7/M8 obligation: raw ``JobQueue.claim`` with a
  request-supplied ``worker_id`` is never reachable.
* The human ``get_principal`` / ``require_permission`` dependencies are NEVER wired
  onto these routes; a worker is never resolved into a ``Principal``.
* Errors flow through the app-wide ``ctfgen.error`` handlers (worker-credential
  rejection -> 401, scope -> 403, ownership -> 403, draining/stale -> 409, unknown
  job/instance -> 404). No response ever carries the token, another worker's data,
  or a flag/seed.

Mounting: a production deployment SHOULD serve this router on a SEPARATE
interface/port from the human API (see :func:`create_worker_app`); it is also
included on the main app for the single-host/dev/test path.
"""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Request, Response

from ctf_generator.domain.instances.models import HealthObservation, RuntimeResource

from ..audit import audit
from ..schemas.common import ERROR_RESPONSES
from .deps import (
    WorkerAuthContext,
    get_worker_build_service,
    get_worker_instance_service,
    get_worker_job_service,
    require_worker,
)
from .schemas import (
    ClaimRequest,
    CompleteRequest,
    EndpointReportRequest,
    FailRequest,
    HealthReportRequest,
    HeartbeatRequest,
    HeartbeatResponse,
    JobLeaseResponse,
    ResourceReportRequest,
    StartRequest,
    TransitionRequest,
    WorkerAuthResponse,
    WorkerInstanceView,
    endpoint_from_request,
    instance_to_worker_view,
    job_lease_to_response,
)

router = APIRouter(tags=["worker"])

# The error codes each worker verb can surface (documentation only; the runtime
# bodies come from the exception handlers). 401 (bad credential) and 429 apply
# everywhere; the rest are per-verb.
_AUTH_ERRORS = {k: ERROR_RESPONSES[k] for k in (401, 429)}
_JOB_ERRORS = {k: ERROR_RESPONSES[k] for k in (401, 403, 404, 409, 422, 429)}
_CLAIM_ERRORS = {k: ERROR_RESPONSES[k] for k in (401, 403, 409, 422, 429)}
_INSTANCE_ERRORS = {k: ERROR_RESPONSES[k] for k in (401, 403, 404, 422, 429)}


def _audit(request: Request, worker: str, action: str, target: str) -> None:
    """Record a worker action. ``worker`` is the authenticated worker NAME (an
    operator slug), never the credential token."""
    audit(
        request.app.state.audit_sink,
        actor=f"worker:{worker}",
        action=action,
        target=target,
        outcome="success",
    )


def _now() -> datetime:
    return datetime.now(UTC)


# -- credential ---------------------------------------------------------------


@router.post(
    "/worker/auth",
    response_model=WorkerAuthResponse,
    responses={200: {"model": WorkerAuthResponse, "description": "OK"}, **_AUTH_ERRORS},
)
def authenticate_worker(ctx: WorkerAuthContext = Depends(require_worker)):
    """Validate the presented credential and return the worker identity summary.
    NEVER echoes the token or any secret."""
    auth = ctx.worker
    return WorkerAuthResponse(
        worker_name=auth.worker.name,
        credential_id=auth.credential_id,
        scopes=list(auth.scopes),
        expires_at=auth.expires_at.isoformat(),
    )


# -- job queue ----------------------------------------------------------------


@router.post(
    "/worker/jobs/claim",
    response_model=None,
    responses={
        200: {"model": JobLeaseResponse, "description": "Job claimed"},
        204: {"description": "No job available"},
        **_CLAIM_ERRORS,
    },
)
def claim_job(
    request: Request,
    body: ClaimRequest,
    ctx: WorkerAuthContext = Depends(require_worker),
    service=Depends(get_worker_job_service),
):
    lease = service.claim(ctx.token, body.lease_seconds, _now())
    if lease is None:
        return Response(status_code=204)
    _audit(request, ctx.name, "worker.job.claim", lease.job.job_id)
    return JobLeaseResponse(**job_lease_to_response(lease))


@router.post(
    "/worker/jobs/{job_id}/start",
    status_code=204,
    responses=_JOB_ERRORS,
)
def start_job(
    request: Request,
    job_id: str,
    body: StartRequest,
    ctx: WorkerAuthContext = Depends(require_worker),
    service=Depends(get_worker_job_service),
):
    service.start(ctx.token, job_id, body.lease_token, _now())
    _audit(request, ctx.name, "worker.job.start", job_id)
    return Response(status_code=204)


@router.post(
    "/worker/jobs/{job_id}/heartbeat",
    response_model=HeartbeatResponse,
    responses={200: {"model": HeartbeatResponse, "description": "OK"}, **_JOB_ERRORS},
)
def heartbeat_job(
    job_id: str,
    body: HeartbeatRequest,
    ctx: WorkerAuthContext = Depends(require_worker),
    service=Depends(get_worker_job_service),
):
    cancel = service.heartbeat(
        ctx.token, job_id, body.lease_token, body.lease_seconds, _now()
    )
    return HeartbeatResponse(cancel_requested=cancel)


@router.post(
    "/worker/jobs/{job_id}/complete",
    status_code=204,
    responses=_JOB_ERRORS,
)
def complete_job(
    request: Request,
    job_id: str,
    body: CompleteRequest,
    ctx: WorkerAuthContext = Depends(require_worker),
    service=Depends(get_worker_job_service),
):
    service.complete(ctx.token, job_id, body.lease_token, body.result, None, None, _now())
    _audit(request, ctx.name, "worker.job.complete", job_id)
    return Response(status_code=204)


@router.post(
    "/worker/jobs/{job_id}/fail",
    status_code=204,
    responses=_JOB_ERRORS,
)
def fail_job(
    request: Request,
    job_id: str,
    body: FailRequest,
    ctx: WorkerAuthContext = Depends(require_worker),
    service=Depends(get_worker_job_service),
):
    service.fail(
        ctx.token, job_id, body.lease_token, body.error_class,
        body.error_detail, body.retryable, _now(),
    )
    _audit(request, ctx.name, "worker.job.fail", job_id)
    return Response(status_code=204)


# -- instance read + re-placement ---------------------------------------------


@router.get(
    "/worker/instances/{instance_id}",
    response_model=WorkerInstanceView,
    responses={
        200: {"model": WorkerInstanceView, "description": "OK"},
        **_INSTANCE_ERRORS,
    },
)
def get_instance(
    instance_id: str,
    ctx: WorkerAuthContext = Depends(require_worker),
    service=Depends(get_worker_instance_service),
):
    instance = service.get_owned_instance(ctx.token, instance_id, _now())
    return WorkerInstanceView(**instance_to_worker_view(instance))


@router.post(
    "/worker/instances/{instance_id}/replace",
    response_model=WorkerInstanceView,
    responses={
        200: {"model": WorkerInstanceView, "description": "Re-placed"},
        **{k: ERROR_RESPONSES[k] for k in (401, 403, 404, 409, 422, 429)},
    },
)
def replace_instance(
    request: Request,
    instance_id: str,
    ctx: WorkerAuthContext = Depends(require_worker),
    service=Depends(get_worker_instance_service),
):
    instance = service.replace_instance(ctx.token, instance_id, _now())
    _audit(request, ctx.name, "worker.instance.replace", instance_id)
    return WorkerInstanceView(**instance_to_worker_view(instance))


# -- build bundle (build_challenge, M-buildpipeline) ---------------------------


@router.get(
    "/worker/builds/{definition_slug}/{version_no}/bundle",
    response_model=None,
    responses={
        200: {"description": "The FULL (buildable, private-inclusive) bundle tar"},
        **{k: ERROR_RESPONSES[k] for k in (401, 403, 404, 422, 429)},
    },
)
def fetch_build_bundle(
    request: Request,
    definition_slug: str,
    version_no: int,
    job_id: str,
    lease_token: str,
    ctx: WorkerAuthContext = Depends(require_worker),
    service=Depends(get_worker_build_service),
):
    """Stream a version's FULL bundle to an ``artifacts:pull``-scoped worker
    that also proves -- via ``job_id``/``lease_token`` query params, mirroring
    the ``lease_token`` fence every job verb applies -- it holds a LIVE lease
    on a matching ``build_challenge`` job (see ``WorkerBuildService``). NEVER
    exposed to a contestant -- this is the flag/solution-bearing bundle;
    credential + scope alone is NOT sufficient (``artifacts:pull`` is a
    fleet-wide default scope every enrolled worker carries). ``job_id``/
    ``lease_token`` travel as query params (not path/body) because this is a
    GET serving raw bytes; worker IDENTITY still comes ONLY from the
    credential (``ctx.token``/``ctx.name``), never the request. The content
    hash + the version's current ``spec_sha256`` travel as headers (never
    inside a JSON envelope, which would force attacker-influenced bytes
    through a base64 round-trip) so the worker can verify BEFORE trusting a
    single byte (``docs/architecture/build-challenge-worker-pipeline.md``)."""
    bundle = service.fetch_build_bundle(
        ctx.token, definition_slug, version_no, job_id, lease_token, _now()
    )
    _audit(
        request, ctx.name, "worker.build.fetch_bundle",
        f"{definition_slug}:v{version_no}",
    )
    return Response(
        content=bundle.data,
        media_type="application/x-tar",
        headers={
            "X-Bundle-Sha256": bundle.bundle_sha256,
            "X-Spec-Sha256": bundle.spec_sha256,
            "Content-Length": str(len(bundle.data)),
            "Cache-Control": "no-store",
        },
    )


# -- instance fact reports + transition ---------------------------------------


@router.post(
    "/worker/instances/{instance_id}/health",
    status_code=204,
    responses=_INSTANCE_ERRORS,
)
def report_health(
    request: Request,
    instance_id: str,
    body: HealthReportRequest,
    ctx: WorkerAuthContext = Depends(require_worker),
    service=Depends(get_worker_instance_service),
):
    now = _now()
    observation = HealthObservation(
        instance_id=instance_id,
        observed_state=body.observed_state,
        healthy=body.healthy,
        # Identity from the credential, NEVER the request.
        worker=ctx.name,
        generation=body.generation,
        observed_at=datetime.fromisoformat(body.observed_at),
        detail=body.detail,
    )
    service.report_health(ctx.token, observation, now)
    _audit(request, ctx.name, "worker.instance.health", instance_id)
    return Response(status_code=204)


@router.post(
    "/worker/instances/{instance_id}/resource",
    status_code=204,
    responses=_INSTANCE_ERRORS,
)
def report_resource(
    request: Request,
    instance_id: str,
    body: ResourceReportRequest,
    ctx: WorkerAuthContext = Depends(require_worker),
    service=Depends(get_worker_instance_service),
):
    resource = RuntimeResource(
        instance_id=instance_id,
        kind=body.kind,
        external_ref=body.external_ref,
        # Identity from the credential, NEVER the request.
        worker=ctx.name,
        generation=body.generation,
        state=body.state,
    )
    service.report_runtime_resource(ctx.token, resource, _now())
    _audit(request, ctx.name, "worker.instance.resource", instance_id)
    return Response(status_code=204)


@router.post(
    "/worker/instances/{instance_id}/endpoint",
    status_code=204,
    responses=_INSTANCE_ERRORS,
)
def report_endpoint(
    request: Request,
    instance_id: str,
    body: EndpointReportRequest,
    ctx: WorkerAuthContext = Depends(require_worker),
    service=Depends(get_worker_instance_service),
):
    service.report_endpoint(ctx.token, endpoint_from_request(instance_id, body), _now())
    _audit(request, ctx.name, "worker.instance.endpoint", instance_id)
    return Response(status_code=204)


@router.post(
    "/worker/instances/{instance_id}/transition",
    status_code=204,
    responses=_INSTANCE_ERRORS,
)
def transition_instance(
    request: Request,
    instance_id: str,
    body: TransitionRequest,
    ctx: WorkerAuthContext = Depends(require_worker),
    service=Depends(get_worker_instance_service),
):
    service.transition_instance(
        ctx.token, instance_id, body.to_state, reason=body.reason, now=_now()
    )
    _audit(request, ctx.name, "worker.instance.transition", instance_id)
    return Response(status_code=204)
