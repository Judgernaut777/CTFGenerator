"""System DTOs: health / readiness / version.

These power the unauthenticated operational probes (load balancers hit them). No
resource content and no secret is ever involved.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class HealthResponse(BaseModel):
    status: str = "ok"


class ReadinessResponse(BaseModel):
    status: str  # "ready" | "unavailable"


class VersionResponse(BaseModel):
    name: str
    version: str


def health_body() -> dict[str, Any]:
    return {"status": "ok"}


def readiness_body(*, ready: bool) -> dict[str, Any]:
    return {"status": "ready" if ready else "unavailable"}


def version_body(name: str, version: str) -> dict[str, Any]:
    return {"name": name, "version": version}
