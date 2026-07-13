"""System router: liveness / readiness / version / metrics probes.

Load balancers and orchestrators hit the probes, so the liveness/readiness/
version probes require no credential and none returns resource content:

* ``/system/health`` (and its alias ``/system/live``) -- liveness. Always 200 if
  the process is up; no DB call.
* ``/system/ready`` -- readiness DEPTH (M16b): a structured multi-check body over
  the DB (hard), migration head (hard), dead-letter depth (soft), and projection
  lag (soft). 503 only when a HARD dependency is unmet (DB down / migrations
  behind); a soft signal returns 200 with ``degraded: true`` (serving, but
  attention-needed). Every check is guarded -- a probe never 500s.
* ``/system/version`` -- the API name + version.
* ``/system/metrics`` -- Prometheus text-format operational gauges (M16b).
  ADMIN / SUPPORT ONLY (``metrics:read``); never public. Never 500s: a failed
  read-model becomes an omitted gauge, not an error.

All probes are SECRET-FREE: readiness carries statuses + aggregate counts/ages,
metrics carries aggregate gauges + the version label -- never a flag, token,
credential, or DSN.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime

import sqlalchemy as sa
from fastapi import APIRouter, Depends, Request, Response

from ctf_generator.infrastructure.database.migrations import (
    CODE_MIGRATION_HEAD,
    current_db_revision,
)

from ..deps import Permission, require_permission
from ..envelopes import (
    SYSTEM_HEALTH_SCHEMA,
    SYSTEM_READINESS_SCHEMA,
    SYSTEM_VERSION_SCHEMA,
    resource_envelope,
)
from ..schemas.system import (
    PROMETHEUS_CONTENT_TYPE,
    HealthResponse,
    ReadinessResponse,
    VersionResponse,
    health_body,
    readiness_body,
    render_metrics,
    version_body,
)
from ._support import respond

router = APIRouter(tags=["system"])

_logger = logging.getLogger("ctfgen.api")

# Soft-signal thresholds (degraded, NOT down). Any dead-lettered job or failed
# projection row is attention-needed; a pending projection row that has aged past
# the window signals the projector is lagging.
_DEAD_LETTER_DEGRADED_AT = 1
_PROJECTION_FAILED_DEGRADED_AT = 1
_PROJECTION_PENDING_AGE_DEGRADED_SECONDS = 300


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


def _database(request: Request):
    return getattr(request.app.state, "database", None)


def _check_migrations(database, *, db_up: bool) -> dict[str, object]:
    """HARD check: the applied Alembic revision equals the code head. When the DB
    is down we cannot know -> 'unknown' (the DB check already forces 503)."""
    if not db_up:
        return {"status": "unknown"}
    try:
        applied = current_db_revision(database)
    except Exception:  # pragma: no cover - current_db_revision already guards
        return {"status": "unknown"}
    at_head = applied == CODE_MIGRATION_HEAD
    return {"status": "ok" if at_head else "behind", "at_head": at_head}


def _check_dead_letter(database) -> dict[str, object]:
    """SOFT check: dead-letter queue depth. Guarded -> 'unknown' on any error."""
    try:
        from ctf_generator.application.jobs.service import JobService

        count = len(JobService(database).list_dead_letter())
    except Exception:
        return {"status": "unknown"}
    degraded = count >= _DEAD_LETTER_DEGRADED_AT
    return {"status": "degraded" if degraded else "ok", "count": count}


def _check_projection_lag(database) -> dict[str, object]:
    """SOFT check: projection failed rows / oldest-pending age. Guarded."""
    try:
        from ctf_generator.application.scoring.scoreboard_service import (
            ScoreboardService,
        )

        lag = ScoreboardService(database).lag()
    except Exception:
        return {"status": "unknown"}
    age_seconds: int | None = None
    oldest = lag.oldest_pending_created_at
    if oldest is not None:
        try:
            ref = oldest if oldest.tzinfo is not None else oldest.replace(tzinfo=UTC)
            age_seconds = max(0, int((datetime.now(UTC) - ref).total_seconds()))
        except Exception:  # pragma: no cover - defensive datetime guard
            age_seconds = None
    degraded = lag.failed_count >= _PROJECTION_FAILED_DEGRADED_AT or (
        age_seconds is not None
        and age_seconds >= _PROJECTION_PENDING_AGE_DEGRADED_SECONDS
    )
    return {
        "status": "degraded" if degraded else "ok",
        "pending": lag.pending_count,
        "failed": lag.failed_count,
        "oldest_pending_age_seconds": age_seconds,
    }


@router.get(
    "/system/health",
    response_model=None,
    responses={200: {"model": HealthResponse, "description": "Process is up"}},
)
def health() -> object:
    return respond(200, resource_envelope(SYSTEM_HEALTH_SCHEMA, health_body()))


@router.get(
    "/system/live",
    response_model=None,
    responses={200: {"model": HealthResponse, "description": "Process is up"}},
)
def live() -> object:
    """Liveness alias of ``/system/health`` (Kubernetes livenessProbe naming)."""
    return respond(200, resource_envelope(SYSTEM_HEALTH_SCHEMA, health_body()))


@router.get(
    "/system/ready",
    response_model=None,
    responses={
        200: {"model": ReadinessResponse, "description": "Ready or degraded"},
        503: {"model": ReadinessResponse, "description": "Hard dependency unavailable"},
    },
)
def ready(request: Request) -> object:
    """Readiness DEPTH. Hard: DB + migration head (unmet -> 503). Soft:
    dead-letter depth + projection lag (degraded -> 200 with the flag)."""
    database = _database(request)
    db_up = database_ready(database)
    migrations = _check_migrations(database, db_up=db_up)
    dead_letter = _check_dead_letter(database) if db_up else {"status": "unknown"}
    projection = _check_projection_lag(database) if db_up else {"status": "unknown"}

    hard_ok = db_up and migrations.get("status") == "ok"
    degraded = (
        dead_letter.get("status") == "degraded"
        or projection.get("status") == "degraded"
    )
    checks = {
        "database": {"status": "up" if db_up else "down"},
        "migrations": migrations,
        "dead_letter": dead_letter,
        "projection_lag": projection,
    }
    body = readiness_body(hard_ok=hard_ok, degraded=degraded, checks=checks)
    envelope = resource_envelope(SYSTEM_READINESS_SCHEMA, body)
    return respond(200 if hard_ok else 503, envelope)


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


def _metric_count(fn) -> int | None:
    """Evaluate one read-model count, returning ``None`` (omit the gauge) on any
    failure so the metrics endpoint never 500s."""
    try:
        return int(fn())
    except Exception:
        return None


@router.get("/system/metrics", response_model=None)
def metrics(
    request: Request,
    _principal=Depends(require_permission(Permission.METRICS_READ)),
) -> Response:
    """Prometheus text-format operational gauges (ADMIN / SUPPORT only).

    Surfaces the EXISTING read models -- projection pending/failed, dead-letter
    depth, non-terminal eval runs -- plus ``build_info``. Never 500s: each read is
    guarded and a failure omits that gauge. SECRET-FREE (aggregate counts only)."""
    database = _database(request)

    if database is None:
        pending = failed = dead_letter = eval_non_terminal = None
    else:
        from ctf_generator.application.evaluation import EvalRunService
        from ctf_generator.application.jobs.service import JobService
        from ctf_generator.application.scoring.scoreboard_service import (
            ScoreboardService,
        )

        lag_holder: dict[str, object] = {}

        def _lag():
            if "lag" not in lag_holder:
                lag_holder["lag"] = ScoreboardService(database).lag()
            return lag_holder["lag"]

        pending = _metric_count(lambda: _lag().pending_count)
        failed = _metric_count(lambda: _lag().failed_count)
        dead_letter = _metric_count(
            lambda: len(JobService(database).list_dead_letter())
        )
        eval_non_terminal = _metric_count(
            lambda: len(
                EvalRunService(
                    database, jobs=JobService(database)
                ).list_non_terminal()
            )
        )

    text = render_metrics(
        version=request.app.version,
        projection_pending=pending,
        projection_failed=failed,
        jobs_dead_letter=dead_letter,
        eval_runs_non_terminal=eval_non_terminal,
    )
    return Response(content=text, media_type=PROMETHEUS_CONTENT_TYPE)
