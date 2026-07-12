"""Instances router: operator view + desired-state lifecycle actions.

Read paths (``GET``) list/inspect instances through
:meth:`InstanceLifecycleService.list_instances` /
:meth:`~InstanceLifecycleService.get_operator_view`, which expose only public
operational facts -- NEVER an instance credential, runtime handle, worker
credential, or private endpoint token (the secret boundary).

Action paths (``POST``) record DESIRED state and enqueue the corrective job the
M8 lifecycle service owns; the API never launches a container or touches a
runtime backend. Actions are idempotent via ``Idempotency-Key`` and audited (no
payload/secret in the audit record).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel, Field

from ..concurrency import compute_etag
from ..deps import (
    Permission,
    Principal,
    get_instance_lifecycle_service,
    require_permission,
)
from ..envelopes import (
    INSTANCE_LIST_SCHEMA,
    INSTANCE_SCHEMA,
    list_envelope,
    resource_envelope,
)
from ..pagination import clamp_limit, paginate
from ..schemas.common import ERROR_RESPONSES
from ..schemas.instances import (
    InstanceLaunchRequest,
    InstanceResponse,
    instance_concurrency_payload,
    instance_to_list_item,
    instance_to_response,
)
from ._support import record_audit, remember, replay, respond

router = APIRouter(tags=["instances"])

# Deterministic instance_id from a principal-scoped Idempotency-Key so a replayed
# launch resolves to the same instance row (mirrors the submissions router).
_INSTANCE_NS = uuid.UUID("b2c4d6e8-0a1c-4e3f-9b8a-7d6c5e4f3a2b")


class InstanceResetRequest(BaseModel):
    """Optional reset parameters. ``ttl_seconds`` sets the new lifetime the
    capacity hold is renewed for."""

    ttl_seconds: int = Field(default=3600, ge=1)


def _list_sort_key(instance) -> list[str]:
    created = instance.created_at.isoformat() if instance.created_at else ""
    return [created, instance.instance_id]


def _paged(instances, *, limit, cursor):
    instances = sorted(instances, key=_list_sort_key)
    page = paginate(instances, key=_list_sort_key, limit=limit, cursor=cursor)
    items = [instance_to_list_item(i) for i in page.items]
    return list_envelope(
        INSTANCE_LIST_SCHEMA, items, limit=clamp_limit(limit),
        next_cursor=page.next_cursor,
    )


def _detail_or_404(service, instance_id: str):
    view = service.get_operator_view(instance_id)
    if view is None:
        raise LookupError(f"instance not found: {instance_id!r}")
    instance, endpoints, health = view
    envelope = resource_envelope(
        INSTANCE_SCHEMA, instance_to_response(instance, endpoints, health)
    )
    etag = compute_etag(instance_concurrency_payload(instance))
    return respond(200, envelope, etag=etag)


def _action_response(request, principal, instance, *, action, scope, body_json):
    envelope = resource_envelope(
        INSTANCE_SCHEMA, instance_to_response(instance, [], None)
    )
    etag = compute_etag(instance_concurrency_payload(instance))
    record_audit(
        request, principal, action=f"instance.{action}", target=instance.instance_id
    )
    remember(
        request, scope, body_json, status_code=200, envelope=envelope, etag=etag
    )
    return respond(200, envelope, etag=etag)


@router.get(
    "/instances",
    response_model=None,
    responses={k: ERROR_RESPONSES[k] for k in (400, 401, 403, 422, 429)},
)
def list_instances(
    limit: int | None = Query(default=None, ge=1),
    cursor: str | None = Query(default=None),
    principal: Principal = Depends(require_permission(Permission.INSTANCE_READ)),
    service=Depends(get_instance_lifecycle_service),
):
    envelope = _paged(service.list_instances(), limit=limit, cursor=cursor)
    return respond(200, envelope)


@router.get(
    "/competitions/{competition_id}/instances",
    response_model=None,
    responses={k: ERROR_RESPONSES[k] for k in (400, 401, 403, 404, 422, 429)},
)
def list_competition_instances(
    competition_id: str,
    limit: int | None = Query(default=None, ge=1),
    cursor: str | None = Query(default=None),
    principal: Principal = Depends(require_permission(Permission.INSTANCE_READ)),
    service=Depends(get_instance_lifecycle_service),
):
    envelope = _paged(
        service.list_instances(competition_id=competition_id),
        limit=limit,
        cursor=cursor,
    )
    return respond(200, envelope)


@router.get(
    "/instances/{instance_id}",
    response_model=None,
    responses={
        200: {"model": InstanceResponse, "description": "OK"},
        **{k: ERROR_RESPONSES[k] for k in (401, 403, 404, 422, 429)},
    },
)
def get_instance(
    instance_id: str,
    principal: Principal = Depends(require_permission(Permission.INSTANCE_READ)),
    service=Depends(get_instance_lifecycle_service),
):
    return _detail_or_404(service, instance_id)


@router.post(
    "/instances",
    status_code=201,
    response_model=None,
    responses={
        201: {"model": InstanceResponse, "description": "Instance requested"},
        **{k: ERROR_RESPONSES[k] for k in (400, 401, 403, 404, 409, 422, 429)},
    },
)
def request_instance(
    request: Request,
    body: InstanceLaunchRequest,
    principal: Principal = Depends(require_permission(Permission.INSTANCE_OPERATE)),
    service=Depends(get_instance_lifecycle_service),
):
    body_json = body.model_dump(mode="json")
    scope = f"{principal.subject}:instance:request"
    replayed = replay(request, scope, body_json)
    if replayed is not None:
        return replayed

    key = request.headers.get("Idempotency-Key")
    instance_id = (
        str(uuid.uuid5(_INSTANCE_NS, f"{principal.subject}:{key}"))
        if key
        else str(uuid.uuid4())
    )
    now = datetime.now(UTC)
    instance = service.request_instance(
        instance_id=instance_id,
        competition_id=body.competition_id,
        team_name=body.team,
        definition_slug=body.definition_slug,
        version_no=body.version_no,
        requirements=body.requirements(),
        pooled_items=body.pooled_items(),
        expires_at=now + timedelta(seconds=body.ttl_seconds),
        now=now,
        worker_units=body.worker_units,
    )
    envelope = resource_envelope(
        INSTANCE_SCHEMA, instance_to_response(instance, [], None)
    )
    etag = compute_etag(instance_concurrency_payload(instance))
    record_audit(
        request, principal, action="instance.request", target=instance.instance_id
    )
    remember(
        request, scope, body_json, status_code=201, envelope=envelope, etag=etag
    )
    return respond(201, envelope, etag=etag)


@router.post(
    "/instances/{instance_id}/stop",
    response_model=None,
    responses={
        200: {"model": InstanceResponse, "description": "Stop requested"},
        **{k: ERROR_RESPONSES[k] for k in (400, 401, 403, 404, 409, 422, 429)},
    },
)
def stop_instance(
    request: Request,
    instance_id: str,
    principal: Principal = Depends(require_permission(Permission.INSTANCE_OPERATE)),
    service=Depends(get_instance_lifecycle_service),
):
    scope = f"{principal.subject}:instance:stop:{instance_id}"
    replayed = replay(request, scope, {})
    if replayed is not None:
        return replayed
    instance = service.request_stop(instance_id, datetime.now(UTC))
    return _action_response(
        request, principal, instance, action="stop", scope=scope, body_json={}
    )


@router.post(
    "/instances/{instance_id}/reset",
    response_model=None,
    responses={
        200: {"model": InstanceResponse, "description": "Reset requested"},
        **{k: ERROR_RESPONSES[k] for k in (400, 401, 403, 404, 409, 422, 429)},
    },
)
def reset_instance(
    request: Request,
    instance_id: str,
    body: InstanceResetRequest | None = None,
    principal: Principal = Depends(require_permission(Permission.INSTANCE_OPERATE)),
    service=Depends(get_instance_lifecycle_service),
):
    params = body or InstanceResetRequest()
    body_json = params.model_dump(mode="json")
    scope = f"{principal.subject}:instance:reset:{instance_id}"
    replayed = replay(request, scope, body_json)
    if replayed is not None:
        return replayed
    now = datetime.now(UTC)
    instance = service.request_reset(
        instance_id, now + timedelta(seconds=params.ttl_seconds), now
    )
    return _action_response(
        request, principal, instance, action="reset", scope=scope, body_json=body_json
    )


@router.post(
    "/instances/{instance_id}/delete",
    response_model=None,
    responses={
        200: {"model": InstanceResponse, "description": "Delete requested"},
        **{k: ERROR_RESPONSES[k] for k in (400, 401, 403, 404, 409, 422, 429)},
    },
)
def delete_instance(
    request: Request,
    instance_id: str,
    principal: Principal = Depends(require_permission(Permission.INSTANCE_OPERATE)),
    service=Depends(get_instance_lifecycle_service),
):
    scope = f"{principal.subject}:instance:delete:{instance_id}"
    replayed = replay(request, scope, {})
    if replayed is not None:
        return replayed
    instance = service.request_delete(instance_id, datetime.now(UTC))
    return _action_response(
        request, principal, instance, action="delete", scope=scope, body_json={}
    )
