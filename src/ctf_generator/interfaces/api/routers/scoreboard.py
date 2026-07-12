"""Scoreboard router: current standings (paginated) + projection lag.

Both are read-only over the scoreboard PROJECTION -- a GET never triggers a
projection run. Standings page by ``(rank, team_id)`` with a stable tiebreak. Lag
is an operator/organizer-only metrics view of the shared projection outbox.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Request

from ..deps import (
    Permission,
    Principal,
    get_scoreboard_service,
    require_competition_permission,
)
from ..envelopes import (
    SCOREBOARD_LAG_SCHEMA,
    SCOREBOARD_SCHEMA,
    list_envelope,
    resource_envelope,
)
from ..pagination import clamp_limit, paginate
from ..schemas.common import ERROR_RESPONSES
from ..schemas.scoreboard import (
    ScoreboardLagResponse,
    entry_sort_key,
    entry_to_response,
    lag_to_response,
)
from ._support import record_audit, respond

router = APIRouter(tags=["scoreboard"])


@router.get(
    "/competitions/{competition_id}/scoreboard",
    response_model=None,
    responses={
        **{k: ERROR_RESPONSES[k] for k in (400, 401, 403, 422, 429)},
    },
)
def get_scoreboard(
    competition_id: str,
    limit: int | None = Query(default=None, ge=1),
    cursor: str | None = Query(default=None),
    principal: Principal = Depends(
        require_competition_permission(Permission.SCOREBOARD_READ)
    ),
    service=Depends(get_scoreboard_service),
):
    entries = sorted(service.standings(competition_id), key=entry_sort_key)
    page = paginate(entries, key=entry_sort_key, limit=limit, cursor=cursor)
    items = [entry_to_response(e) for e in page.items]
    envelope = list_envelope(
        SCOREBOARD_SCHEMA, items, limit=clamp_limit(limit), next_cursor=page.next_cursor
    )
    return respond(200, envelope)


@router.get(
    "/competitions/{competition_id}/scoreboard/lag",
    response_model=None,
    responses={
        200: {"model": ScoreboardLagResponse, "description": "OK"},
        **{k: ERROR_RESPONSES[k] for k in (401, 403, 422, 429)},
    },
)
def get_scoreboard_lag(
    request: Request,
    competition_id: str,
    principal: Principal = Depends(
        require_competition_permission(Permission.SCOREBOARD_LAG_READ)
    ),
    service=Depends(get_scoreboard_service),
):
    lag = service.lag()
    envelope = resource_envelope(SCOREBOARD_LAG_SCHEMA, lag_to_response(lag))
    record_audit(
        request, principal, action="scoreboard.lag.read", target=competition_id
    )
    return respond(200, envelope)
