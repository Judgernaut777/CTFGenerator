"""System DTOs: health / readiness / version + operational metrics rendering.

These power the operational probes. Health/version/readiness are unauthenticated
(load balancers hit them); the metrics endpoint is admin/support-gated. NO secret
is ever involved -- readiness carries only per-check statuses + aggregate
counts/ages, and the metrics text carries only aggregate gauges.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class HealthResponse(BaseModel):
    status: str = "ok"


class ReadinessResponse(BaseModel):
    # "ready" | "degraded" | "unavailable"
    status: str
    degraded: bool = False
    # Per-dependency check statuses (secret-free: statuses + counts only).
    checks: dict[str, Any] = {}


class VersionResponse(BaseModel):
    name: str
    version: str


def health_body() -> dict[str, Any]:
    return {"status": "ok"}


def version_body(name: str, version: str) -> dict[str, Any]:
    return {"name": name, "version": version}


# -- readiness (depth) --------------------------------------------------------

READY = "ready"
DEGRADED = "degraded"
UNAVAILABLE = "unavailable"


def readiness_body(
    *, hard_ok: bool, degraded: bool, checks: dict[str, Any]
) -> dict[str, Any]:
    """Structured multi-check readiness body.

    ``hard_ok`` is False when a HARD dependency (DB down / migrations behind) is
    unmet -> overall ``unavailable`` (the caller returns 503). Otherwise the
    service is serving: ``degraded`` (a soft signal -- dead-letter depth /
    projection lag) still returns 200 with the flag set, else ``ready``.
    """
    if not hard_ok:
        status = UNAVAILABLE
    elif degraded:
        status = DEGRADED
    else:
        status = READY
    return {"status": status, "degraded": bool(degraded and hard_ok), "checks": checks}


# -- metrics (Prometheus text exposition format v0.0.4) -----------------------

PROMETHEUS_CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"


def _escape_label_value(value: str) -> str:
    """Escape a Prometheus label value (backslash, double-quote, newline)."""
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def render_metrics(
    *,
    version: str,
    projection_pending: int | None,
    projection_failed: int | None,
    jobs_dead_letter: int | None,
    eval_runs_non_terminal: int | None,
) -> str:
    """Render the platform gauges as Prometheus v0.0.4 text.

    A ``None`` value means the underlying read failed: the sample is OMITTED and a
    comment records that it is unavailable (a scrape sees a gap, never a 500 and
    never a misleading 0). Only aggregate counts + the version label are emitted
    -- no secret can appear.
    """
    lines: list[str] = []

    lines.append("# HELP ctfgen_build_info Build information (constant 1; version in label).")
    lines.append("# TYPE ctfgen_build_info gauge")
    lines.append(f'ctfgen_build_info{{version="{_escape_label_value(version)}"}} 1')

    gauges = (
        (
            "ctfgen_projection_pending",
            "Pending rows in the scoreboard projection outbox.",
            projection_pending,
        ),
        (
            "ctfgen_projection_failed",
            "Failed rows in the scoreboard projection outbox.",
            projection_failed,
        ),
        (
            "ctfgen_jobs_dead_letter",
            "Jobs currently in the dead-letter queue.",
            jobs_dead_letter,
        ),
        (
            "ctfgen_eval_runs_non_terminal",
            "Evaluation runs still awaiting a result (pending/running).",
            eval_runs_non_terminal,
        ),
    )
    for name, help_text, value in gauges:
        lines.append(f"# HELP {name} {help_text}")
        lines.append(f"# TYPE {name} gauge")
        if value is None:
            lines.append(f"# {name} unavailable (read-model error)")
        else:
            lines.append(f"{name} {int(value)}")

    return "\n".join(lines) + "\n"
