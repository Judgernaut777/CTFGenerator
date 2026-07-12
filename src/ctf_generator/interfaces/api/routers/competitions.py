"""Competitions router: create / get / list (paginated) / patch (ETag optimistic
concurrency). The reference implementation slice-b/c routers copy.

Pagination note: slice a orders and pages on the stable business id
(``competition_id``); the endpoints draft's per-resource ``sort`` fields are a
later refinement that keeps the same opaque-cursor wire contract.
"""

from __future__ import annotations

import dataclasses

from fastapi import APIRouter, Depends, Query, Request

from ..concurrency import compute_etag, etags_match
from ..deps import (
    Permission,
    Principal,
    get_competition_service,
    require_permission,
)
from ..envelopes import (
    COMPETITION_LIST_SCHEMA,
    COMPETITION_SCHEMA,
    list_envelope,
    resource_envelope,
)
from ..exceptions import (
    PreconditionFailedError,
    PreconditionRequiredError,
    ValidationFailedError,
)
from ..pagination import clamp_limit, paginate
from ..schemas.common import ERROR_RESPONSES
from ..schemas.competitions import (
    CompetitionCreateRequest,
    CompetitionPatchRequest,
    CompetitionResponse,
    competition_concurrency_payload,
    competition_to_response,
    validate_window,
)
from ._support import record_audit, remember, replay, respond

router = APIRouter(tags=["competitions"])

_CREATE_SCOPE = "competitions:create"


@router.post(
    "/competitions",
    status_code=201,
    response_model=None,
    responses={
        201: {"model": CompetitionResponse, "description": "Created"},
        **{k: ERROR_RESPONSES[k] for k in (400, 401, 403, 409, 422, 429)},
    },
)
def create_competition(
    request: Request,
    body: CompetitionCreateRequest,
    principal: Principal = Depends(require_permission(Permission.COMPETITION_WRITE)),
    service=Depends(get_competition_service),
):
    body_json = body.model_dump(mode="json")
    replayed = replay(request, _CREATE_SCOPE, body_json)
    if replayed is not None:
        return replayed

    config = service.create(body.to_domain())
    envelope = resource_envelope(
        COMPETITION_SCHEMA, competition_to_response(config)
    )
    etag = compute_etag(competition_concurrency_payload(config))
    record_audit(
        request, principal, action="competition.create", target=config.competition_id
    )
    remember(
        request, _CREATE_SCOPE, body_json, status_code=201, envelope=envelope, etag=etag
    )
    return respond(201, envelope, etag=etag)


@router.get(
    "/competitions",
    response_model=None,
    responses={k: ERROR_RESPONSES[k] for k in (400, 401, 403, 422, 429)},
)
def list_competitions(
    limit: int | None = Query(default=None, ge=1),
    cursor: str | None = Query(default=None),
    principal: Principal = Depends(require_permission(Permission.COMPETITION_READ)),
    service=Depends(get_competition_service),
):
    configs = sorted(service.list(), key=lambda c: c.competition_id)
    page = paginate(
        configs, key=lambda c: c.competition_id, limit=limit, cursor=cursor
    )
    items = [competition_to_response(c) for c in page.items]
    envelope = list_envelope(
        COMPETITION_LIST_SCHEMA,
        items,
        limit=clamp_limit(limit),
        next_cursor=page.next_cursor,
    )
    return respond(200, envelope)


@router.get(
    "/competitions/{competition_id}",
    response_model=None,
    responses={
        200: {"model": CompetitionResponse, "description": "OK"},
        **{k: ERROR_RESPONSES[k] for k in (401, 403, 404, 422, 429)},
    },
)
def get_competition(
    competition_id: str,
    principal: Principal = Depends(require_permission(Permission.COMPETITION_READ)),
    service=Depends(get_competition_service),
):
    config = service.get(competition_id)
    if config is None:
        raise LookupError(f"competition not found: {competition_id!r}")
    envelope = resource_envelope(
        COMPETITION_SCHEMA, competition_to_response(config)
    )
    etag = compute_etag(competition_concurrency_payload(config))
    return respond(200, envelope, etag=etag)


@router.patch(
    "/competitions/{competition_id}",
    response_model=None,
    responses={
        200: {"model": CompetitionResponse, "description": "Updated"},
        **{k: ERROR_RESPONSES[k] for k in (400, 401, 403, 404, 412, 422, 428, 429)},
    },
)
def patch_competition(
    request: Request,
    competition_id: str,
    body: CompetitionPatchRequest,
    principal: Principal = Depends(require_permission(Permission.COMPETITION_WRITE)),
    service=Depends(get_competition_service),
):
    if_match = request.headers.get("If-Match")
    if not if_match:
        raise PreconditionRequiredError("If-Match header is required for updates")

    current = service.get(competition_id)
    if current is None:
        raise LookupError(f"competition not found: {competition_id!r}")

    changes = body.model_dump(exclude_unset=True)
    merged = dataclasses.replace(current, **changes)

    problems = validate_window(
        merged.start_time,
        merged.end_time,
        merged.scoring_start_time,
        merged.freeze_time,
    )
    if problems:
        raise ValidationFailedError(
            "invalid competition timing window", detail=problems
        )

    def guard(fresh) -> None:
        if not etags_match(
            if_match, compute_etag(competition_concurrency_payload(fresh))
        ):
            raise PreconditionFailedError(
                "If-Match does not match the current resource version"
            )

    updated = service.update(merged, guard=guard)
    envelope = resource_envelope(
        COMPETITION_SCHEMA, competition_to_response(updated)
    )
    etag = compute_etag(competition_concurrency_payload(updated))
    record_audit(
        request, principal, action="competition.update", target=competition_id
    )
    return respond(200, envelope, etag=etag)
