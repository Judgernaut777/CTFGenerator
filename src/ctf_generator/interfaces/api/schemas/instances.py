"""Instance DTOs + mappers (operator view over the M8 lifecycle).

CRITICAL SECRET BOUNDARY. An instance carries, in the store, access credentials
(``InstanceCredential.secret_ref``), runtime-resource handles
(``RuntimeResource.external_ref``), worker credentials, and internal endpoint
addresses. NONE of those may appear in an API response. These DTOs are built ONLY
from the public operational facts: the lifecycle ``state`` / ``desired_state``,
the competition / team / challenge business refs, the assigned-worker *name*, the
PUBLIC (non-internal) endpoint addresses, the latest health verdict, and the
timestamps. Credentials and runtime resources are never read on this path (see
``InstanceLifecycleService.get_operator_view``), so they cannot leak.

The launch request maps to ``InstanceLifecycleService.request_instance``: it
records desired state and enqueues a launch job a worker claims -- the API never
starts a container.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from ctf_generator.domain.instances.models import (
    HealthObservation,
    Instance,
    InstanceEndpoint,
)
from ctf_generator.domain.scheduling.models import (
    PLATFORM_SCOPE_KEY,
    ReservationItem,
    WorkerRequirements,
)

_DEFAULT_CAPABILITY = "launch_instance"


class InstanceLaunchRequest(BaseModel):
    """Request a new instance for a team. The scheduling inputs (architecture,
    required capabilities, TTL, platform capacity to hold) are explicit so the
    handler stays a thin DTO->domain mapping -- no scheduling policy is invented
    in the interface layer."""

    competition_id: str = Field(min_length=1)
    team: str = Field(min_length=1)
    definition_slug: str = Field(min_length=1)
    version_no: int = Field(ge=1)
    architecture: str = Field(default="x86_64", min_length=1)
    required_capabilities: list[str] = Field(
        default_factory=lambda: [_DEFAULT_CAPABILITY]
    )
    ttl_seconds: int = Field(default=3600, ge=1)
    worker_units: int = Field(default=1, ge=1)
    platform_capacity: int = Field(
        default=1, ge=1, description="Platform active-instance units to reserve"
    )

    def requirements(self) -> WorkerRequirements:
        caps = frozenset(self.required_capabilities) or frozenset(
            {_DEFAULT_CAPABILITY}
        )
        return WorkerRequirements(
            architecture=self.architecture, required_capabilities=caps
        )

    def pooled_items(self) -> tuple[ReservationItem, ...]:
        return (
            ReservationItem(
                "platform",
                PLATFORM_SCOPE_KEY,
                "active_instances",
                self.platform_capacity,
            ),
        )


class InstanceEndpointResponse(BaseModel):
    name: str
    host: str
    port: int
    protocol: str
    url: str


class InstanceHealthResponse(BaseModel):
    observed_state: str
    healthy: bool
    observed_at: str
    generation: int


class InstanceListItem(BaseModel):
    instance_id: str
    competition_id: str
    team: str
    definition_slug: str
    version_no: int
    state: str
    desired_state: str
    assigned_worker: str | None = None
    generation: int
    image_ref: str | None = None
    expires_at: str | None = None
    created_at: str | None = None
    updated_at: str | None = None


class InstanceResponse(InstanceListItem):
    endpoints: list[InstanceEndpointResponse] = Field(default_factory=list)
    health: InstanceHealthResponse | None = None


def _iso(value) -> str | None:
    return value.isoformat() if value is not None else None


def instance_to_list_item(instance: Instance) -> dict[str, Any]:
    """Map an instance to its public list projection. Deliberately omits
    ``instance_seed`` (a generation input that can influence flags) and every
    credential / runtime handle."""
    return {
        "instance_id": instance.instance_id,
        "competition_id": instance.competition_id,
        "team": instance.team_name,
        "definition_slug": instance.definition_slug,
        "version_no": instance.version_no,
        "state": instance.state,
        "desired_state": instance.desired_state,
        "assigned_worker": instance.assigned_worker,
        "generation": instance.generation,
        "image_ref": instance.image_ref,
        "expires_at": _iso(instance.expires_at),
        "created_at": _iso(instance.created_at),
        "updated_at": _iso(instance.updated_at),
    }


def _endpoint_to_response(endpoint: InstanceEndpoint) -> dict[str, Any]:
    return {
        "name": endpoint.name,
        "host": endpoint.host,
        "port": endpoint.port,
        "protocol": endpoint.protocol,
        "url": endpoint.url,
    }


def _health_to_response(health: HealthObservation | None) -> dict[str, Any] | None:
    if health is None:
        return None
    return {
        "observed_state": health.observed_state,
        "healthy": health.healthy,
        "observed_at": health.observed_at.isoformat(),
        "generation": health.generation,
    }


def instance_to_response(
    instance: Instance,
    endpoints: list[InstanceEndpoint],
    health: HealthObservation | None,
) -> dict[str, Any]:
    """Map an instance + its PUBLIC endpoints + latest health to the detail DTO.
    ``endpoints`` must already be filtered to non-internal (the service does this);
    no credential / runtime-resource / secret_ref is ever read here."""
    body = instance_to_list_item(instance)
    body["endpoints"] = [_endpoint_to_response(e) for e in endpoints]
    body["health"] = _health_to_response(health)
    return body


def instance_concurrency_payload(instance: Instance) -> dict[str, Any]:
    return {
        "instance_id": instance.instance_id,
        "state": instance.state,
        "desired_state": instance.desired_state,
        "generation": instance.generation,
        "updated_at": _iso(instance.updated_at),
    }
