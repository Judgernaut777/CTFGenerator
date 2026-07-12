"""Submissions router: submit an answer / list attempts / fetch one.

* ``POST /competitions/{competition_id}/submissions`` reuses the transactional
  :class:`~ctf_generator.application.submissions.service.SubmissionProcessingService`
  (attempt -> verify -> first-correct-solve -> commit once). The answer is inbound
  only and never echoed. Idempotent via ``Idempotency-Key`` (principal-scoped).
* ``GET /competitions/{competition_id}/submissions`` and
  ``GET /submissions/{submission_id}`` are tenancy-safe: a team-scoped principal
  (player / captain) may read only its own team's attempts; organizer / admin /
  staff may read any (see :func:`submission_team_scope`).

Nothing in any response or audit record carries the answer, the expected flag, or
any verifier internal -- only correctness and the public solve facts.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Query, Request

from ctf_generator.domain.ledger.processing import SubmissionRequest

from ..concurrency import compute_etag
from ..deps import (
    Permission,
    Principal,
    assert_competition_permission,
    get_principal,
    get_submission_processing_service,
    get_submission_query_service,
    require_competition_permission,
    submission_team_scope,
)
from ..envelopes import (
    SUBMISSION_LIST_SCHEMA,
    SUBMISSION_SCHEMA,
    list_envelope,
    resource_envelope,
)
from ..exceptions import AuthorizationError
from ..pagination import clamp_limit, paginate
from ..schemas.common import ERROR_RESPONSES
from ..schemas.submissions import (
    SubmissionCreateRequest,
    SubmissionResponse,
    submission_concurrency_payload,
    submission_detail_to_response,
    submission_outcome_to_response,
    submission_to_list_item,
)
from ._support import record_audit, remember, replay, respond

router = APIRouter(tags=["submissions"])

_CREATE_SCOPE = "submissions:create"
# Fixed namespace: derive a deterministic submission_id from a principal-scoped
# Idempotency-Key so the domain's own submission_id idempotency aligns with the
# HTTP-layer replay (a race past the replay short-circuit still dedupes on the PK).
_SUBMISSION_NS = uuid.UUID("6f8a5c2e-9d41-4b7a-8f2b-2a1c9e0d7b31")


def _submission_id(request: Request, principal: Principal, competition_id: str) -> str:
    key = request.headers.get("Idempotency-Key")
    if key:
        return str(
            uuid.uuid5(_SUBMISSION_NS, f"{principal.subject}:{competition_id}:{key}")
        )
    return str(uuid.uuid4())


def _list_sort_key(item) -> list[str]:
    return [item.submitted_at.isoformat(), item.submission_id]


@router.post(
    "/competitions/{competition_id}/submissions",
    status_code=201,
    response_model=None,
    responses={
        201: {"model": SubmissionResponse, "description": "Attempt recorded"},
        **{k: ERROR_RESPONSES[k] for k in (400, 401, 403, 404, 409, 422, 429)},
    },
)
def submit_answer(
    request: Request,
    competition_id: str,
    body: SubmissionCreateRequest,
    principal: Principal = Depends(
        require_competition_permission(Permission.SUBMISSION_CREATE)
    ),
    service=Depends(get_submission_processing_service),
):
    # Tenancy: submission:create is already scoped to THIS competition by the
    # dependency; now confine a team-scoped principal to its own team in it (a
    # team-scoped principal not placed on a team here is denied, fail closed).
    access = submission_team_scope(principal, competition_id)
    if not access.unrestricted:
        if access.team is None:
            raise AuthorizationError("not placed on a team")
        if body.team != access.team:
            raise AuthorizationError("may only submit for your own team")

    body_json = body.model_dump(mode="json")
    # Scope the HTTP-layer idempotency by competition so it aligns with the
    # domain submission_id (which also folds in competition_id): the same key +
    # body POSTed to two different competitions must NOT replay across them.
    idem_scope = f"{principal.subject}:{_CREATE_SCOPE}:{competition_id}"
    replayed = replay(request, idem_scope, body_json)
    if replayed is not None:
        return replayed

    outcome = service.process_submission(
        SubmissionRequest(
            submission_id=_submission_id(request, principal, competition_id),
            competition_id=competition_id,
            team_name=body.team,
            definition_slug=body.definition_slug,
            version_no=body.version_no,
            submitted_at=datetime.now(UTC),
            candidate_flag=body.answer,
            submitter_email=None,
            instance_seed=body.instance_seed,
        )
    )
    envelope = resource_envelope(
        SUBMISSION_SCHEMA, submission_outcome_to_response(outcome)
    )
    etag = compute_etag(submission_concurrency_payload(outcome.submission))
    record_audit(
        request,
        principal,
        action="submission.create",
        target=(
            f"{competition_id}/{body.team}/{body.definition_slug}/v{body.version_no}"
        ),
    )
    remember(
        request, idem_scope, body_json, status_code=201, envelope=envelope, etag=etag
    )
    return respond(201, envelope, etag=etag)


@router.get(
    "/competitions/{competition_id}/submissions",
    response_model=None,
    responses={
        **{k: ERROR_RESPONSES[k] for k in (400, 401, 403, 404, 422, 429)},
    },
)
def list_submissions(
    competition_id: str,
    team: str | None = Query(
        default=None, description="Filter by team (organizer/admin); ignored scope"
    ),
    limit: int | None = Query(default=None, ge=1),
    cursor: str | None = Query(default=None),
    principal: Principal = Depends(
        require_competition_permission(Permission.SUBMISSION_READ)
    ),
    service=Depends(get_submission_query_service),
):
    access = submission_team_scope(principal, competition_id)
    if access.unrestricted:
        # Tenancy-unrestricted: an optional team filter, else the whole competition.
        submissions = (
            service.list_for_team(competition_id, team)
            if team is not None
            else service.list_for_competition(competition_id)
        )
    else:
        # Team-scoped: confined to the principal's own team; a principal not
        # placed on a team is denied (fail closed).
        if access.team is None:
            raise AuthorizationError("principal is not placed on a team")
        if team is not None and team != access.team:
            raise AuthorizationError("may only list your own team's submissions")
        submissions = service.list_for_team(competition_id, access.team)

    submissions = sorted(submissions, key=_list_sort_key)
    page = paginate(submissions, key=_list_sort_key, limit=limit, cursor=cursor)
    items = [submission_to_list_item(s) for s in page.items]
    envelope = list_envelope(
        SUBMISSION_LIST_SCHEMA,
        items,
        limit=clamp_limit(limit),
        next_cursor=page.next_cursor,
    )
    return respond(200, envelope)


@router.get(
    "/submissions/{submission_id}",
    response_model=None,
    responses={
        200: {"model": SubmissionResponse, "description": "OK"},
        **{k: ERROR_RESPONSES[k] for k in (401, 403, 404, 422, 429)},
    },
)
def get_submission(
    submission_id: str,
    # No {competition_id} in the path; the target competition is resolved from the
    # loaded row, then submission:read is authorized against it (below).
    principal: Principal = Depends(get_principal),
    service=Depends(get_submission_query_service),
):
    detail = service.get_detail(submission_id)
    if detail is None:
        raise LookupError(f"submission not found: {submission_id!r}")
    submission, solve = detail
    # Cross-competition: no submission:read in the row's competition -> 403.
    assert_competition_permission(
        principal, submission.competition_id, Permission.SUBMISSION_READ
    )
    access = submission_team_scope(principal, submission.competition_id)
    if not access.unrestricted and (
        access.team is None or submission.team_name != access.team
    ):
        # Cross-tenant (or teamless): 404 -- never confirm existence to a
        # principal not entitled to see the row.
        raise LookupError(f"submission not found: {submission_id!r}")
    envelope = resource_envelope(
        SUBMISSION_SCHEMA, submission_detail_to_response(submission, solve)
    )
    etag = compute_etag(submission_concurrency_payload(submission))
    return respond(200, envelope, etag=etag)
