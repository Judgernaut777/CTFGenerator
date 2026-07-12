"""Challenge-definitions router: create / get / list / patch (title; ETag optimistic
concurrency). A definition is the stable logical challenge identity keyed by
``slug``; only ``title`` is mutable."""

from __future__ import annotations

import dataclasses

from fastapi import APIRouter, Depends, Query, Request

from ..concurrency import compute_etag, etags_match
from ..deps import (
    Permission,
    Principal,
    get_challenge_definition_service,
    require_permission,
)
from ..envelopes import (
    CHALLENGE_DEFINITION_LIST_SCHEMA,
    CHALLENGE_DEFINITION_SCHEMA,
    list_envelope,
    resource_envelope,
)
from ..exceptions import PreconditionFailedError, PreconditionRequiredError
from ..pagination import clamp_limit, paginate
from ..schemas.challenges import (
    ChallengeDefinitionCreateRequest,
    ChallengeDefinitionPatchRequest,
    ChallengeDefinitionResponse,
    definition_concurrency_payload,
    definition_to_response,
)
from ..schemas.common import ERROR_RESPONSES
from ._support import record_audit, remember, replay, respond

router = APIRouter(tags=["challenge-definitions"])

_CREATE_SCOPE = "challenge-definitions:create"


@router.post(
    "/challenge-definitions",
    status_code=201,
    response_model=None,
    responses={
        201: {"model": ChallengeDefinitionResponse, "description": "Created"},
        **{k: ERROR_RESPONSES[k] for k in (400, 401, 403, 409, 422, 429)},
    },
)
def create_definition(
    request: Request,
    body: ChallengeDefinitionCreateRequest,
    principal: Principal = Depends(require_permission(Permission.CHALLENGE_WRITE)),
    service=Depends(get_challenge_definition_service),
):
    body_json = body.model_dump(mode="json")
    scope = f"{principal.subject}:{_CREATE_SCOPE}"
    replayed = replay(request, scope, body_json)
    if replayed is not None:
        return replayed

    definition = service.create(body.to_domain())
    envelope = resource_envelope(
        CHALLENGE_DEFINITION_SCHEMA, definition_to_response(definition)
    )
    etag = compute_etag(definition_concurrency_payload(definition))
    record_audit(
        request,
        principal,
        action="challenge_definition.create",
        target=definition.slug,
    )
    remember(
        request, scope, body_json, status_code=201, envelope=envelope, etag=etag
    )
    return respond(201, envelope, etag=etag)


@router.get(
    "/challenge-definitions",
    response_model=None,
    responses={k: ERROR_RESPONSES[k] for k in (400, 401, 403, 422, 429)},
)
def list_definitions(
    limit: int | None = Query(default=None, ge=1),
    cursor: str | None = Query(default=None),
    principal: Principal = Depends(require_permission(Permission.CHALLENGE_READ)),
    service=Depends(get_challenge_definition_service),
):
    definitions = sorted(service.list(), key=lambda d: d.slug)
    page = paginate(definitions, key=lambda d: d.slug, limit=limit, cursor=cursor)
    items = [definition_to_response(d) for d in page.items]
    envelope = list_envelope(
        CHALLENGE_DEFINITION_LIST_SCHEMA,
        items,
        limit=clamp_limit(limit),
        next_cursor=page.next_cursor,
    )
    return respond(200, envelope)


@router.get(
    "/challenge-definitions/{slug}",
    response_model=None,
    responses={
        200: {"model": ChallengeDefinitionResponse, "description": "OK"},
        **{k: ERROR_RESPONSES[k] for k in (401, 403, 404, 422, 429)},
    },
)
def get_definition(
    slug: str,
    principal: Principal = Depends(require_permission(Permission.CHALLENGE_READ)),
    service=Depends(get_challenge_definition_service),
):
    definition = service.get(slug)
    if definition is None:
        raise LookupError(f"challenge definition not found: {slug!r}")
    envelope = resource_envelope(
        CHALLENGE_DEFINITION_SCHEMA, definition_to_response(definition)
    )
    etag = compute_etag(definition_concurrency_payload(definition))
    return respond(200, envelope, etag=etag)


@router.patch(
    "/challenge-definitions/{slug}",
    response_model=None,
    responses={
        200: {"model": ChallengeDefinitionResponse, "description": "Updated"},
        **{k: ERROR_RESPONSES[k] for k in (400, 401, 403, 404, 412, 422, 428, 429)},
    },
)
def patch_definition(
    request: Request,
    slug: str,
    body: ChallengeDefinitionPatchRequest,
    principal: Principal = Depends(require_permission(Permission.CHALLENGE_WRITE)),
    service=Depends(get_challenge_definition_service),
):
    if_match = request.headers.get("If-Match")
    if not if_match:
        raise PreconditionRequiredError("If-Match header is required for updates")

    current = service.get(slug)
    if current is None:
        raise LookupError(f"challenge definition not found: {slug!r}")

    changes = body.model_dump(exclude_unset=True)
    merged = dataclasses.replace(current, **changes)

    def guard(fresh) -> None:
        if not etags_match(
            if_match, compute_etag(definition_concurrency_payload(fresh))
        ):
            raise PreconditionFailedError(
                "If-Match does not match the current resource version"
            )

    updated = service.update(merged, guard=guard)
    envelope = resource_envelope(
        CHALLENGE_DEFINITION_SCHEMA, definition_to_response(updated)
    )
    etag = compute_etag(definition_concurrency_payload(updated))
    record_audit(
        request, principal, action="challenge_definition.update", target=slug
    )
    return respond(200, envelope, etag=etag)
