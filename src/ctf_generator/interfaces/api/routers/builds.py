"""Builds router: list/inspect content-addressed builds + trigger a build JOB.

The trigger enqueues a durable ``build_challenge`` job (idempotent) and returns
its reference; the control plane NEVER runs the build in-process -- a worker
claims the job with scoped credentials. Reads expose the build's content identity
and provenance only.
"""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel, Field

from ..concurrency import compute_etag
from ..deps import (
    Permission,
    Principal,
    get_build_service,
    require_permission,
)
from ..envelopes import (
    BUILD_LIST_SCHEMA,
    BUILD_SCHEMA,
    JOB_SCHEMA,
    list_envelope,
    resource_envelope,
)
from ..pagination import clamp_limit, paginate
from ..schemas.builds import (
    BuildResponse,
    build_concurrency_payload,
    build_to_list_item,
    build_to_response,
)
from ..schemas.common import ERROR_RESPONSES
from ..schemas.jobs import JobResponse, job_to_response
from ._support import record_audit, remember, replay, respond

router = APIRouter(tags=["builds"])


class BuildTriggerRequest(BaseModel):
    version_no: int = Field(ge=1)


def _build_sort_key(build) -> str:
    return build.build_sha256


@router.get(
    "/challenge-definitions/{slug}/builds",
    response_model=None,
    responses={k: ERROR_RESPONSES[k] for k in (400, 401, 403, 422, 429)},
)
def list_builds(
    slug: str,
    version_no: int = Query(ge=1, description="Version whose builds to list"),
    limit: int | None = Query(default=None, ge=1),
    cursor: str | None = Query(default=None),
    principal: Principal = Depends(require_permission(Permission.BUILD_READ)),
    service=Depends(get_build_service),
):
    builds = sorted(
        service.list_for_version(slug, version_no), key=_build_sort_key
    )
    page = paginate(builds, key=_build_sort_key, limit=limit, cursor=cursor)
    items = [build_to_list_item(b) for b in page.items]
    envelope = list_envelope(
        BUILD_LIST_SCHEMA, items, limit=clamp_limit(limit),
        next_cursor=page.next_cursor,
    )
    return respond(200, envelope)


@router.get(
    "/builds/{build_id}",
    response_model=None,
    responses={
        200: {"model": BuildResponse, "description": "OK"},
        **{k: ERROR_RESPONSES[k] for k in (401, 403, 404, 422, 429)},
    },
)
def get_build(
    build_id: str,
    principal: Principal = Depends(require_permission(Permission.BUILD_READ)),
    service=Depends(get_build_service),
):
    build = service.get(build_id)
    if build is None:
        raise LookupError(f"build not found: {build_id!r}")
    envelope = resource_envelope(BUILD_SCHEMA, build_to_response(build))
    etag = compute_etag(build_concurrency_payload(build))
    return respond(200, envelope, etag=etag)


@router.post(
    "/challenge-definitions/{slug}/builds",
    status_code=202,
    response_model=None,
    responses={
        202: {"model": JobResponse, "description": "Build job enqueued"},
        **{k: ERROR_RESPONSES[k] for k in (400, 401, 403, 404, 409, 422, 429)},
    },
)
def trigger_build(
    request: Request,
    slug: str,
    body: BuildTriggerRequest,
    principal: Principal = Depends(require_permission(Permission.BUILD_CREATE)),
    service=Depends(get_build_service),
):
    body_json = body.model_dump(mode="json")
    scope = f"{principal.subject}:build:trigger:{slug}"
    replayed = replay(request, scope, body_json)
    if replayed is not None:
        return replayed

    job, _created = service.trigger_build(slug, body.version_no, datetime.now(UTC))
    envelope = resource_envelope(JOB_SCHEMA, job_to_response(job))
    record_audit(
        request,
        principal,
        action="build.trigger",
        target=f"{slug}/v{body.version_no}",
    )
    remember(
        request, scope, body_json, status_code=202, envelope=envelope, etag=None
    )
    return respond(202, envelope)
