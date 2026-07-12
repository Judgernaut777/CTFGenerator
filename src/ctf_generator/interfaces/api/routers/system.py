"""System router: liveness / readiness / version probes (UNAUTHENTICATED).

Load balancers and orchestrators hit these, so none require a credential and none
returns resource content:

* ``/system/health`` -- liveness. Always 200 if the process is up; no DB call.
* ``/system/ready`` -- readiness. A trivial ``SELECT 1`` round-trip; 200 ready,
  503 unavailable (both in the envelope) when the DB is unreachable.
* ``/system/version`` -- the API name + version.
"""

from __future__ import annotations

import sqlalchemy as sa
from fastapi import APIRouter, Request

from ..envelopes import (
    SYSTEM_HEALTH_SCHEMA,
    SYSTEM_READINESS_SCHEMA,
    SYSTEM_VERSION_SCHEMA,
    resource_envelope,
)
from ..schemas.system import (
    HealthResponse,
    ReadinessResponse,
    VersionResponse,
    health_body,
    readiness_body,
    version_body,
)
from ._support import respond

router = APIRouter(tags=["system"])


def database_ready(database) -> bool:
    """True iff a trivial ``SELECT 1`` round-trips. A missing DB handle or any
    connection error reads as not-ready (never raises) -- the probe must always
    answer. Kept as a small, directly unit-testable helper."""
    if database is None:
        return False
    try:
        with database.session_scope() as session:
            session.execute(sa.text("SELECT 1"))
        return True
    except Exception:  # pragma: no cover - exercised via a stub in tests
        return False


@router.get(
    "/system/health",
    response_model=None,
    responses={200: {"model": HealthResponse, "description": "Process is up"}},
)
def health() -> object:
    return respond(200, resource_envelope(SYSTEM_HEALTH_SCHEMA, health_body()))


@router.get(
    "/system/ready",
    response_model=None,
    responses={
        200: {"model": ReadinessResponse, "description": "Ready"},
        503: {"model": ReadinessResponse, "description": "Dependency unavailable"},
    },
)
def ready(request: Request) -> object:
    is_ready = database_ready(getattr(request.app.state, "database", None))
    envelope = resource_envelope(
        SYSTEM_READINESS_SCHEMA, readiness_body(ready=is_ready)
    )
    return respond(200 if is_ready else 503, envelope)


@router.get(
    "/system/version",
    response_model=None,
    responses={200: {"model": VersionResponse, "description": "OK"}},
)
def version(request: Request) -> object:
    return respond(
        200,
        resource_envelope(
            SYSTEM_VERSION_SCHEMA,
            version_body(request.app.title, request.app.version),
        ),
    )
