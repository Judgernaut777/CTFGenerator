"""Jobs router: ops observability + control (admin / support only).

Read the dead-letter queue, inspect a job, and cancel / retry -- all over
:class:`JobService`. Every response is mapped through the job DTO, which NEVER
surfaces the raw payload / result_json / error_detail (a flag/seed/credential
would live there if the queue's secret-free convention were violated); only the
job type, lifecycle state, attempt accounting, timestamps, and structured
``error_class`` summary are exposed.
"""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Query, Request

from ..concurrency import compute_etag
from ..deps import Permission, Principal, get_job_service, require_permission
from ..envelopes import (
    JOB_LIST_SCHEMA,
    JOB_SCHEMA,
    list_envelope,
    resource_envelope,
)
from ..pagination import clamp_limit, paginate
from ..schemas.common import ERROR_RESPONSES
from ..schemas.jobs import (
    JobResponse,
    job_concurrency_payload,
    job_to_list_item,
    job_to_response,
)
from ._support import record_audit, remember, replay, respond

router = APIRouter(tags=["jobs"])


def _job_sort_key(job) -> str:
    return job.job_id


# Declared BEFORE ``/jobs/{job_id}`` so the literal path wins over the param.
@router.get(
    "/jobs/dead-letter",
    response_model=None,
    responses={k: ERROR_RESPONSES[k] for k in (400, 401, 403, 422, 429)},
)
def list_dead_letter(
    limit: int | None = Query(default=None, ge=1),
    cursor: str | None = Query(default=None),
    principal: Principal = Depends(require_permission(Permission.JOB_READ)),
    service=Depends(get_job_service),
):
    jobs = sorted(service.list_dead_letter(), key=_job_sort_key)
    page = paginate(jobs, key=_job_sort_key, limit=limit, cursor=cursor)
    items = [job_to_list_item(j) for j in page.items]
    envelope = list_envelope(
        JOB_LIST_SCHEMA, items, limit=clamp_limit(limit),
        next_cursor=page.next_cursor,
    )
    return respond(200, envelope)


@router.get(
    "/jobs/{job_id}",
    response_model=None,
    responses={
        200: {"model": JobResponse, "description": "OK"},
        **{k: ERROR_RESPONSES[k] for k in (401, 403, 404, 422, 429)},
    },
)
def get_job(
    job_id: str,
    principal: Principal = Depends(require_permission(Permission.JOB_READ)),
    service=Depends(get_job_service),
):
    job = service.get(job_id)
    if job is None:
        raise LookupError(f"job not found: {job_id!r}")
    envelope = resource_envelope(JOB_SCHEMA, job_to_response(job))
    etag = compute_etag(job_concurrency_payload(job))
    return respond(200, envelope, etag=etag)


def _control_response(request, principal, job, *, action, scope):
    envelope = resource_envelope(JOB_SCHEMA, job_to_response(job))
    etag = compute_etag(job_concurrency_payload(job))
    record_audit(request, principal, action=f"job.{action}", target=job.job_id)
    remember(request, scope, {}, status_code=200, envelope=envelope, etag=etag)
    return respond(200, envelope, etag=etag)


@router.post(
    "/jobs/{job_id}/cancel",
    response_model=None,
    responses={
        200: {"model": JobResponse, "description": "Cancellation requested"},
        **{k: ERROR_RESPONSES[k] for k in (400, 401, 403, 404, 409, 422, 429)},
    },
)
def cancel_job(
    request: Request,
    job_id: str,
    principal: Principal = Depends(require_permission(Permission.JOB_OPERATE)),
    service=Depends(get_job_service),
):
    scope = f"{principal.subject}:job:cancel:{job_id}"
    replayed = replay(request, scope, {})
    if replayed is not None:
        return replayed
    job = service.cancel(job_id, datetime.now(UTC))
    return _control_response(request, principal, job, action="cancel", scope=scope)


@router.post(
    "/jobs/{job_id}/retry",
    response_model=None,
    responses={
        200: {"model": JobResponse, "description": "Requeued from dead-letter"},
        **{k: ERROR_RESPONSES[k] for k in (400, 401, 403, 404, 409, 422, 429)},
    },
)
def retry_job(
    request: Request,
    job_id: str,
    principal: Principal = Depends(require_permission(Permission.JOB_OPERATE)),
    service=Depends(get_job_service),
):
    scope = f"{principal.subject}:job:retry:{job_id}"
    replayed = replay(request, scope, {})
    if replayed is not None:
        return replayed
    job = service.retry_dead_letter(job_id, datetime.now(UTC))
    return _control_response(request, principal, job, action="retry", scope=scope)
