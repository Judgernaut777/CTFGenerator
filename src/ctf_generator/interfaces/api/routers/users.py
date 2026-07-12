"""Users router: register / get / list (paginated).

A user is the global profile record keyed by ``email`` (case-insensitive). This
is the profile only -- no credential is modelled (identity/authN is M10). The
registration request's ``role`` is validated at the boundary but role/team
placement is competition-scoped (a membership) and assigned elsewhere; it is not
stored on the profile (see docs/api/slice-a-limitations.md).
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Request

from ..concurrency import compute_etag
from ..deps import Permission, Principal, get_identity_service, require_permission
from ..envelopes import (
    USER_LIST_SCHEMA,
    USER_SCHEMA,
    list_envelope,
    resource_envelope,
)
from ..pagination import clamp_limit, paginate
from ..schemas.common import ERROR_RESPONSES
from ..schemas.users import (
    UserCreateRequest,
    UserResponse,
    user_concurrency_payload,
    user_to_response,
)
from ._support import record_audit, remember, replay, respond

router = APIRouter(tags=["users"])

_CREATE_SCOPE = "users:create"


@router.post(
    "/users",
    status_code=201,
    response_model=None,
    responses={
        201: {"model": UserResponse, "description": "Created"},
        **{k: ERROR_RESPONSES[k] for k in (400, 401, 403, 404, 409, 422, 429)},
    },
)
def register_user(
    request: Request,
    body: UserCreateRequest,
    principal: Principal = Depends(require_permission(Permission.USER_WRITE)),
    service=Depends(get_identity_service),
):
    body_json = body.model_dump(mode="json")
    scope = f"{principal.subject}:{_CREATE_SCOPE}"
    replayed = replay(request, scope, body_json)
    if replayed is not None:
        return replayed

    user = service.register(body.to_domain())
    envelope = resource_envelope(USER_SCHEMA, user_to_response(user))
    etag = compute_etag(user_concurrency_payload(user))
    record_audit(request, principal, action="user.register", target=user.email)
    remember(
        request, scope, body_json, status_code=201, envelope=envelope, etag=etag
    )
    return respond(201, envelope, etag=etag)


@router.get(
    "/users",
    response_model=None,
    responses={k: ERROR_RESPONSES[k] for k in (400, 401, 403, 422, 429)},
)
def list_users(
    limit: int | None = Query(default=None, ge=1),
    cursor: str | None = Query(default=None),
    principal: Principal = Depends(require_permission(Permission.USER_READ)),
    service=Depends(get_identity_service),
):
    users = sorted(service.list_users(), key=lambda u: u.email)
    page = paginate(users, key=lambda u: u.email, limit=limit, cursor=cursor)
    items = [user_to_response(u) for u in page.items]
    envelope = list_envelope(
        USER_LIST_SCHEMA, items, limit=clamp_limit(limit), next_cursor=page.next_cursor
    )
    return respond(200, envelope)


@router.get(
    "/users/{user_id}",
    response_model=None,
    responses={
        200: {"model": UserResponse, "description": "OK"},
        **{k: ERROR_RESPONSES[k] for k in (401, 403, 404, 422, 429)},
    },
)
def get_user(
    user_id: str,
    principal: Principal = Depends(require_permission(Permission.USER_READ)),
    service=Depends(get_identity_service),
):
    user = service.get(user_id)
    if user is None:
        raise LookupError(f"user not found: {user_id!r}")
    envelope = resource_envelope(USER_SCHEMA, user_to_response(user))
    etag = compute_etag(user_concurrency_payload(user))
    return respond(200, envelope, etag=etag)
