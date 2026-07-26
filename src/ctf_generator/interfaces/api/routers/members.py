"""Members router: assign a user's role + team placement within a competition.

This is the operator roster surface that turns a registered user into a
competition participant. Without it a user can be created (`POST /users`) but never
granted a competition-scoped permission (e.g. a ``player`` who can submit) -- the
membership was previously only writable from internal code. The write is
COMPETITION-scoped (`membership:write`), so an organizer of A cannot seed
memberships in B; a system admin can seed anywhere.

The single-resource path is ``/competitions/{competition_id}/members/{email}`` and
the verb is an idempotent PUT (upsert): assigning the same (role, team) twice is a
no-op, re-assigning changes the placement.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from ..concurrency import compute_etag
from ..deps import (
    Permission,
    Principal,
    assert_competition_permission,
    get_identity_service,
    get_principal,
)
from ..envelopes import MEMBERSHIP_SCHEMA, resource_envelope
from ..schemas.common import ERROR_RESPONSES
from ..schemas.members import (
    MembershipAssignRequest,
    MembershipResponse,
    membership_concurrency_payload,
    membership_to_response,
)
from ._support import record_audit, respond

router = APIRouter(tags=["members"])


@router.put(
    "/competitions/{competition_id}/members/{email}",
    response_model=None,
    responses={
        200: {"model": MembershipResponse, "description": "Assigned"},
        **{k: ERROR_RESPONSES[k] for k in (400, 401, 403, 404, 409, 422, 429)},
    },
)
def assign_member(
    competition_id: str,
    email: str,
    body: MembershipAssignRequest,
    request: Request,
    principal: Principal = Depends(get_principal),
    service=Depends(get_identity_service),
):
    # membership:write scoped to THIS competition (organizer of A cannot seed B).
    assert_competition_permission(principal, competition_id, Permission.MEMBERSHIP_WRITE)
    membership = service.assign_membership(
        competition_id=competition_id,
        user_email=email,
        role=body.role,
        team_name=body.team_name,
    )
    envelope = resource_envelope(MEMBERSHIP_SCHEMA, membership_to_response(membership))
    etag = compute_etag(membership_concurrency_payload(membership))
    record_audit(
        request,
        principal,
        action="membership.assign",
        target=f"{competition_id}/{membership.user_email}",
    )
    return respond(200, envelope, etag=etag)
