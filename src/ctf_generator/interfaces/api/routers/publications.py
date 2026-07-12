"""Publications router: attach / list / detach a published version on a
competition.

Thin over :class:`PublicationService` (UoW-owning). Attach is idempotent via
``Idempotency-Key`` and returns the created publication; a duplicate attach
surfaces the store's conflict (409); an unknown competition/version -> 404; a
non-``published`` version -> 422. Detach returns 204 (or 404 if not attached).
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Request, Response

from ..concurrency import compute_etag
from ..deps import (
    Permission,
    Principal,
    get_publication_service,
    require_permission,
)
from ..envelopes import (
    PUBLICATION_LIST_SCHEMA,
    PUBLICATION_SCHEMA,
    list_envelope,
    resource_envelope,
)
from ..pagination import clamp_limit, paginate
from ..schemas.common import ERROR_RESPONSES
from ..schemas.publications import (
    PublicationCreateRequest,
    PublicationResponse,
    publication_concurrency_payload,
    publication_to_response,
)
from ._support import record_audit, remember, replay, respond

router = APIRouter(tags=["publications"])


def _sort_key(publication) -> list:
    return [publication.definition_slug, publication.version_no]


@router.post(
    "/competitions/{competition_id}/publications",
    status_code=201,
    response_model=None,
    responses={
        201: {"model": PublicationResponse, "description": "Attached"},
        **{k: ERROR_RESPONSES[k] for k in (400, 401, 403, 404, 409, 422, 429)},
    },
)
def attach_publication(
    request: Request,
    competition_id: str,
    body: PublicationCreateRequest,
    principal: Principal = Depends(require_permission(Permission.PUBLICATION_WRITE)),
    service=Depends(get_publication_service),
):
    body_json = body.model_dump(mode="json")
    scope = f"{principal.subject}:publication:attach:{competition_id}"
    replayed = replay(request, scope, body_json)
    if replayed is not None:
        return replayed

    publication = service.attach(body.to_domain(competition_id))
    envelope = resource_envelope(
        PUBLICATION_SCHEMA, publication_to_response(publication)
    )
    etag = compute_etag(publication_concurrency_payload(publication))
    record_audit(
        request,
        principal,
        action="publication.attach",
        target=f"{competition_id}/{body.definition_slug}/v{body.version_no}",
    )
    remember(
        request, scope, body_json, status_code=201, envelope=envelope, etag=etag
    )
    return respond(201, envelope, etag=etag)


@router.get(
    "/competitions/{competition_id}/publications",
    response_model=None,
    responses={k: ERROR_RESPONSES[k] for k in (400, 401, 403, 404, 422, 429)},
)
def list_publications(
    competition_id: str,
    limit: int | None = Query(default=None, ge=1),
    cursor: str | None = Query(default=None),
    principal: Principal = Depends(require_permission(Permission.PUBLICATION_READ)),
    service=Depends(get_publication_service),
):
    publications = sorted(
        service.list_for_competition(competition_id), key=_sort_key
    )
    page = paginate(publications, key=_sort_key, limit=limit, cursor=cursor)
    items = [publication_to_response(p) for p in page.items]
    envelope = list_envelope(
        PUBLICATION_LIST_SCHEMA, items, limit=clamp_limit(limit),
        next_cursor=page.next_cursor,
    )
    return respond(200, envelope)


@router.delete(
    "/competitions/{competition_id}/publications/{definition_slug}/{version_no}",
    status_code=204,
    response_model=None,
    responses={k: ERROR_RESPONSES[k] for k in (401, 403, 404, 422, 429)},
)
def detach_publication(
    request: Request,
    competition_id: str,
    definition_slug: str,
    version_no: int,
    principal: Principal = Depends(require_permission(Permission.PUBLICATION_WRITE)),
    service=Depends(get_publication_service),
):
    service.detach(competition_id, definition_slug, version_no)
    record_audit(
        request,
        principal,
        action="publication.detach",
        target=f"{competition_id}/{definition_slug}/v{version_no}",
    )
    return Response(status_code=204)
