"""Challenge-versions router: create draft / get / list / publish.

A version is an immutable-once-published revision under a definition, keyed by
``(definition_slug, version_no)``. ``version_no`` is server-allocated and
``spec_sha256`` server-computed (see :class:`ChallengeVersionService`). Publish is
a forward-only ``draft -> published`` transition. See the service docstring for the
slice-a scope note on deterministic generation.
"""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Query, Request

from ctf_generator.schema import SPEC_SCHEMA, current_version

from ..concurrency import compute_etag
from ..deps import (
    Permission,
    Principal,
    get_challenge_version_service,
    require_permission,
)
from ..envelopes import (
    CHALLENGE_VERSION_LIST_SCHEMA,
    CHALLENGE_VERSION_SCHEMA,
    list_envelope,
    resource_envelope,
)
from ..pagination import clamp_limit, paginate
from ..schemas.challenges import (
    ChallengeVersionCreateRequest,
    ChallengeVersionResponse,
    version_concurrency_payload,
    version_to_list_item,
    version_to_response,
)
from ..schemas.common import ERROR_RESPONSES
from ._support import record_audit, remember, replay, respond

router = APIRouter(tags=["challenge-versions"])

_CREATE_SCOPE = "challenge-versions:create"


@router.post(
    "/challenge-versions",
    status_code=201,
    response_model=None,
    responses={
        201: {"model": ChallengeVersionResponse, "description": "Draft created"},
        **{k: ERROR_RESPONSES[k] for k in (400, 401, 403, 404, 409, 422, 429)},
    },
)
def create_version(
    request: Request,
    body: ChallengeVersionCreateRequest,
    principal: Principal = Depends(require_permission(Permission.CHALLENGE_WRITE)),
    service=Depends(get_challenge_version_service),
):
    body_json = body.model_dump(mode="json")
    replayed = replay(request, _CREATE_SCOPE, body_json)
    if replayed is not None:
        return replayed

    version = service.create_draft(
        definition_slug=body.definition_slug,
        seed=body.seed,
        family_version=body.family_version,
        spec=body.spec,
        spec_version=body.spec_version or current_version(SPEC_SCHEMA),
        mode=body.mode,
        cve_refs=tuple(body.cve_refs),
        cve_content_hash=body.cve_content_hash,
    )
    envelope = resource_envelope(
        CHALLENGE_VERSION_SCHEMA, version_to_response(version)
    )
    etag = compute_etag(version_concurrency_payload(version))
    record_audit(
        request,
        principal,
        action="challenge_version.create_draft",
        target=f"{version.definition_slug}/v{version.version_no}",
    )
    remember(
        request, _CREATE_SCOPE, body_json, status_code=201, envelope=envelope, etag=etag
    )
    return respond(201, envelope, etag=etag)


@router.get(
    "/challenge-versions",
    response_model=None,
    responses={k: ERROR_RESPONSES[k] for k in (400, 401, 403, 422, 429)},
)
def list_versions(
    definition_slug: str = Query(
        ..., min_length=1, description="Parent definition (required)"
    ),
    limit: int | None = Query(default=None, ge=1),
    cursor: str | None = Query(default=None),
    principal: Principal = Depends(require_permission(Permission.CHALLENGE_READ)),
    service=Depends(get_challenge_version_service),
):
    versions = sorted(
        service.list_for_definition(definition_slug), key=lambda v: v.version_no
    )
    page = paginate(versions, key=lambda v: v.version_no, limit=limit, cursor=cursor)
    items = [version_to_list_item(v) for v in page.items]
    envelope = list_envelope(
        CHALLENGE_VERSION_LIST_SCHEMA,
        items,
        limit=clamp_limit(limit),
        next_cursor=page.next_cursor,
    )
    return respond(200, envelope)


@router.get(
    "/challenge-versions/{definition_slug}/{version_no}",
    response_model=None,
    responses={
        200: {"model": ChallengeVersionResponse, "description": "OK"},
        **{k: ERROR_RESPONSES[k] for k in (401, 403, 404, 422, 429)},
    },
)
def get_version(
    definition_slug: str,
    version_no: int,
    principal: Principal = Depends(require_permission(Permission.CHALLENGE_READ)),
    service=Depends(get_challenge_version_service),
):
    version = service.get(definition_slug, version_no)
    if version is None:
        raise LookupError(
            f"challenge version not found: {definition_slug!r} v{version_no}"
        )
    envelope = resource_envelope(
        CHALLENGE_VERSION_SCHEMA, version_to_response(version)
    )
    etag = compute_etag(version_concurrency_payload(version))
    return respond(200, envelope, etag=etag)


@router.post(
    "/challenge-versions/{definition_slug}/{version_no}/publish",
    response_model=None,
    responses={
        200: {"model": ChallengeVersionResponse, "description": "Published"},
        **{k: ERROR_RESPONSES[k] for k in (400, 401, 403, 404, 409, 422, 429)},
    },
)
def publish_version(
    request: Request,
    definition_slug: str,
    version_no: int,
    principal: Principal = Depends(require_permission(Permission.CHALLENGE_PUBLISH)),
    service=Depends(get_challenge_version_service),
):
    version = service.publish(
        definition_slug, version_no, datetime.now(UTC)
    )
    envelope = resource_envelope(
        CHALLENGE_VERSION_SCHEMA, version_to_response(version)
    )
    etag = compute_etag(version_concurrency_payload(version))
    record_audit(
        request,
        principal,
        action="challenge_version.publish",
        target=f"{definition_slug}/v{version_no}",
    )
    return respond(200, envelope, etag=etag)
