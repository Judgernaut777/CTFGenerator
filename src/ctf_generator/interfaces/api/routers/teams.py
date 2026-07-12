"""Teams router: create / get / list, scoped to a competition. Teams are keyed by
``(competition_id, name)`` (no standalone id in the domain), so the single-resource
path is ``/teams/{competition_id}/{name}`` and list requires a ``competition_id``
filter."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Request

from ..concurrency import compute_etag
from ..deps import Permission, Principal, get_team_service, require_permission
from ..envelopes import (
    TEAM_LIST_SCHEMA,
    TEAM_SCHEMA,
    list_envelope,
    resource_envelope,
)
from ..pagination import clamp_limit, paginate
from ..schemas.common import ERROR_RESPONSES
from ..schemas.teams import (
    TeamCreateRequest,
    TeamResponse,
    team_concurrency_payload,
    team_to_response,
)
from ._support import record_audit, remember, replay, respond

router = APIRouter(tags=["teams"])

_CREATE_SCOPE = "teams:create"


@router.post(
    "/teams",
    status_code=201,
    response_model=None,
    responses={
        201: {"model": TeamResponse, "description": "Created"},
        **{k: ERROR_RESPONSES[k] for k in (400, 401, 403, 404, 409, 422, 429)},
    },
)
def create_team(
    request: Request,
    body: TeamCreateRequest,
    principal: Principal = Depends(require_permission(Permission.TEAM_WRITE)),
    service=Depends(get_team_service),
):
    body_json = body.model_dump(mode="json")
    replayed = replay(request, _CREATE_SCOPE, body_json)
    if replayed is not None:
        return replayed

    team = service.create(body.to_domain())
    envelope = resource_envelope(TEAM_SCHEMA, team_to_response(team))
    etag = compute_etag(team_concurrency_payload(team))
    record_audit(
        request,
        principal,
        action="team.create",
        target=f"{team.competition_id}/{team.name}",
    )
    remember(
        request, _CREATE_SCOPE, body_json, status_code=201, envelope=envelope, etag=etag
    )
    return respond(201, envelope, etag=etag)


@router.get(
    "/teams",
    response_model=None,
    responses={k: ERROR_RESPONSES[k] for k in (400, 401, 403, 422, 429)},
)
def list_teams(
    competition_id: str = Query(
        ..., min_length=1, description="Owning competition (required)"
    ),
    limit: int | None = Query(default=None, ge=1),
    cursor: str | None = Query(default=None),
    principal: Principal = Depends(require_permission(Permission.TEAM_READ)),
    service=Depends(get_team_service),
):
    teams = sorted(
        service.list_for_competition(competition_id), key=lambda t: t.name
    )
    page = paginate(teams, key=lambda t: t.name, limit=limit, cursor=cursor)
    items = [team_to_response(t) for t in page.items]
    envelope = list_envelope(
        TEAM_LIST_SCHEMA,
        items,
        limit=clamp_limit(limit),
        next_cursor=page.next_cursor,
    )
    return respond(200, envelope)


@router.get(
    "/teams/{competition_id}/{name}",
    response_model=None,
    responses={
        200: {"model": TeamResponse, "description": "OK"},
        **{k: ERROR_RESPONSES[k] for k in (401, 403, 404, 422, 429)},
    },
)
def get_team(
    competition_id: str,
    name: str,
    principal: Principal = Depends(require_permission(Permission.TEAM_READ)),
    service=Depends(get_team_service),
):
    team = service.get(competition_id, name)
    if team is None:
        raise LookupError(f"team not found: {competition_id!r}/{name!r}")
    envelope = resource_envelope(TEAM_SCHEMA, team_to_response(team))
    etag = compute_etag(team_concurrency_payload(team))
    return respond(200, envelope, etag=etag)
