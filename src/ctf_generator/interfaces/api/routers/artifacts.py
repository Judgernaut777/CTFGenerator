"""Artifacts router: the contestant PUBLIC-only artifact download (M14 slice 14c-2).

``GET /competitions/{competition_id}/challenges/{definition_slug}/{version_no}/artifact``
streams the version's MATERIALIZED public bundle (the 14c-1 tar, already private-
stripped) to a contestant who may read the competition. It mirrors the contestant
web download and the catalog reads:

* AUTHZ + tenancy: ``assert_competition_permission_or_404`` on ``competition:read``
  -- a caller who cannot read the competition gets an existence-hiding 404 (never a
  403 that would confirm it exists), identical to the contestant catalog surface.
* PUBLISHED-here: the ``(slug, version_no)`` must be published IN THIS competition
  (else 404) -- a contestant may never download an unpublished challenge.
* PUBLIC-ONLY + no traversal: the bytes come ONLY from the DB
  ``ChallengeBuild.storage_uri`` via the :class:`ArtifactStore`; the storage key is
  never caller-controlled and a private file can never be reached.
* Never a 500 on ordinary input: an unmaterialized artifact / missing store bytes /
  an unconfigured store -> a clean 404 ``ctfgen.error`` envelope.

The bytes stream with ``Content-Type: application/x-tar``, a sanitized
``Content-Disposition`` attachment filename, ``Content-Length``, and
``Cache-Control: no-store``.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request, Response

from ..deps import (
    Permission,
    Principal,
    assert_competition_permission_or_404,
    get_artifact_download_service,
    get_principal,
    get_publication_service,
)
from ..schemas.common import ERROR_RESPONSES

router = APIRouter(tags=["artifacts"])

_NOT_FOUND = "challenge artifact not found"
# ``version_no`` is a 32-bit INTEGER column; a client value above this would raise a
# DB DataError (a 500) on the published-here lookup, so reject out-of-range at the
# boundary as a clean existence-hiding 404.
_INT32_MAX = 2147483647


@router.get(
    "/competitions/{competition_id}/challenges/{definition_slug}/{version_no}/artifact",
    response_model=None,
    responses={k: ERROR_RESPONSES[k] for k in (401, 403, 404, 422, 429)},
)
def download_artifact(
    competition_id: str,
    definition_slug: str,
    version_no: int,
    request: Request,
    # Authenticate only; the competition is a PATH param but authorization uses the
    # existence-hiding or_404 form (mirroring the contestant catalog) so a caller
    # who cannot read this competition gets a 404, never a 403 oracle.
    principal: Principal = Depends(get_principal),
    pub_service=Depends(get_publication_service),
    download_service=Depends(get_artifact_download_service),
) -> Response:
    assert_competition_permission_or_404(
        principal, competition_id, Permission.COMPETITION_READ, not_found=_NOT_FOUND
    )
    if version_no < 1 or version_no > _INT32_MAX:
        raise LookupError(_NOT_FOUND)
    if pub_service.get(competition_id, definition_slug, version_no) is None:
        # Not published in THIS competition -> existence-hiding 404.
        raise LookupError(_NOT_FOUND)

    artifact = download_service.resolve_public_artifact(definition_slug, version_no)
    if artifact is None:
        # Published here but no materialized/stored bytes (or store unconfigured):
        # a clean 404 envelope, never a 500.
        raise LookupError(_NOT_FOUND)

    return Response(
        content=artifact.data,
        media_type=artifact.media_type,
        headers={
            "Content-Type": artifact.media_type,
            "Content-Disposition": f'attachment; filename="{artifact.filename}"',
            "Content-Length": str(artifact.content_length),
            "Cache-Control": "no-store",
        },
    )
