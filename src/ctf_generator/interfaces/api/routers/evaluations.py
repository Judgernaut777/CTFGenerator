"""Evaluations router: request an agent-eval + read its platform record (M15).

A request ENQUEUES a durable ``run_agent_evaluation`` job (idempotent) and
returns the PENDING :class:`EvalRun` record; the control plane NEVER runs the
effectful eval in-process -- a worker (slice 15b) claims the job with scoped
credentials. Reads expose the record's advisory outcome only (never a flag --
the aggregate has none).

AUTHORING-scoped (flat ``require_permission``): an author/organizer evaluates a
version independent of any competition. A plain contestant holds neither
``eval:run`` nor ``eval:read`` -> 403.
"""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Query, Request

from ..concurrency import compute_etag
from ..deps import (
    Permission,
    Principal,
    get_eval_run_service,
    require_permission,
)
from ..envelopes import (
    EVAL_RUN_LIST_SCHEMA,
    EVAL_RUN_SCHEMA,
    list_envelope,
    resource_envelope,
)
from ..pagination import clamp_limit, paginate
from ..schemas.common import ERROR_RESPONSES
from ..schemas.evaluations import (
    EvalRunResponse,
    eval_run_concurrency_payload,
    eval_run_to_list_item,
    eval_run_to_response,
)
from ._support import record_audit, remember, replay, respond

router = APIRouter(tags=["evaluations"])


def _sort_key(run) -> str:
    return run.eval_run_id


@router.get(
    "/challenge-versions/{slug}/{version_no}/evaluations",
    response_model=None,
    responses={k: ERROR_RESPONSES[k] for k in (400, 401, 403, 422, 429)},
)
def list_evaluations(
    slug: str,
    version_no: int,
    limit: int | None = Query(default=None, ge=1),
    cursor: str | None = Query(default=None),
    principal: Principal = Depends(require_permission(Permission.EVAL_READ)),
    service=Depends(get_eval_run_service),
):
    runs = sorted(service.list_for_version(slug, version_no), key=_sort_key)
    page = paginate(runs, key=_sort_key, limit=limit, cursor=cursor)
    items = [eval_run_to_list_item(r) for r in page.items]
    envelope = list_envelope(
        EVAL_RUN_LIST_SCHEMA, items, limit=clamp_limit(limit),
        next_cursor=page.next_cursor,
    )
    return respond(200, envelope)


@router.get(
    "/evaluations/{eval_run_id}",
    response_model=None,
    responses={
        200: {"model": EvalRunResponse, "description": "OK"},
        **{k: ERROR_RESPONSES[k] for k in (401, 403, 404, 422, 429)},
    },
)
def get_evaluation(
    eval_run_id: str,
    principal: Principal = Depends(require_permission(Permission.EVAL_READ)),
    service=Depends(get_eval_run_service),
):
    run = service.get(eval_run_id)
    if run is None:
        raise LookupError(f"eval run not found: {eval_run_id!r}")
    envelope = resource_envelope(EVAL_RUN_SCHEMA, eval_run_to_response(run))
    etag = compute_etag(eval_run_concurrency_payload(run))
    return respond(200, envelope, etag=etag)


@router.post(
    "/challenge-versions/{slug}/{version_no}/evaluations",
    status_code=202,
    response_model=None,
    responses={
        202: {"model": EvalRunResponse, "description": "Eval requested (job enqueued)"},
        200: {"model": EvalRunResponse, "description": "Existing run (idempotent)"},
        **{k: ERROR_RESPONSES[k] for k in (400, 401, 403, 404, 409, 422, 429)},
    },
)
def request_evaluation(
    request: Request,
    slug: str,
    version_no: int,
    profile: str = Query(description="One of the named eval profiles"),
    adversarial: bool = Query(default=False),
    principal: Principal = Depends(require_permission(Permission.EVAL_RUN)),
    service=Depends(get_eval_run_service),
):
    scope = f"{principal.subject}:eval:request:{slug}:{version_no}"
    body_json = {"profile": profile, "adversarial": adversarial}
    replayed = replay(request, scope, body_json)
    if replayed is not None:
        return replayed

    run, created = service.request_eval(
        slug, version_no, profile, adversarial=adversarial, now=datetime.now(UTC)
    )
    status_code = 202 if created else 200
    envelope = resource_envelope(EVAL_RUN_SCHEMA, eval_run_to_response(run))
    record_audit(
        request,
        principal,
        action="eval.request",
        target=f"{slug}/v{version_no}/{profile}"
        + (":adversarial" if adversarial else ""),
    )
    remember(
        request, scope, body_json, status_code=status_code, envelope=envelope,
        etag=None,
    )
    return respond(status_code, envelope)
