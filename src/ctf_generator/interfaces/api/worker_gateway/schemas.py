"""Wire DTOs for the worker-facing HTTP gateway (M9 slice d).

These are the machine-to-machine contract between a REMOTE worker process and the
control plane. Two invariants shape every DTO here:

* Identity is NEVER carried in a request. No DTO accepts a ``worker`` /
  ``worker_id`` / ``worker_name`` field; the gated services derive the worker
  EXCLUSIVELY from the presented credential. The health / resource reports omit
  ``worker`` entirely -- the gateway stamps it from the authenticated token.
* No secret ever crosses this boundary in the response direction beyond what the
  worker legitimately needs to do its job. The instance view omits
  ``instance_seed`` (a flag-influencing input); job payloads carry references only
  (the queue's secret-free-by-construction convention); the credential token is
  never echoed.

The paired :class:`~ctf_generator.workers.http_client.HttpControlPlaneClient`
serializes/deserializes these exact shapes so the worker run loop behaves
identically on the in-process (Local) and networked (HTTP) transports.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from ctf_generator.domain.instances.models import Instance, InstanceEndpoint
from ctf_generator.domain.work.models import JobLease

# NOTE ON IDENTITY: no request DTO carries a ``worker`` / ``worker_id`` /
# ``worker_name`` field, and Pydantic's default ``extra="ignore"`` means an
# unknown field a client tries to smuggle (e.g. ``worker_name`` in a claim body)
# is DROPPED, never read. Identity is derived solely from the credential inside the
# gated services -- a spoofed identity field is silently ignored, and the action is
# always attributed to the authenticated worker.


def _iso(value) -> str | None:
    return value.isoformat() if value is not None else None


# -- credential ---------------------------------------------------------------


class WorkerAuthResponse(BaseModel):
    """Identity summary returned by ``POST /worker/auth``. Mirrors
    ``LocalControlPlaneClient.authenticate``'s contract: it confirms the
    credential is live and reports WHO the caller is + the grant, but NEVER echoes
    the token or any secret."""

    worker_name: str
    credential_id: str
    scopes: list[str]
    expires_at: str


# -- job queue ----------------------------------------------------------------


class ClaimRequest(BaseModel):
    lease_seconds: int = Field(default=60, ge=1)


class StartRequest(BaseModel):
    lease_token: str = Field(min_length=1)


class HeartbeatRequest(BaseModel):
    lease_token: str = Field(min_length=1)
    lease_seconds: int = Field(default=60, ge=1)


class HeartbeatResponse(BaseModel):
    cancel_requested: bool


class CompleteRequest(BaseModel):
    lease_token: str = Field(min_length=1)
    result: dict[str, Any] | None = None


class FailRequest(BaseModel):
    lease_token: str = Field(min_length=1)
    error_class: str = Field(min_length=1)
    error_detail: str | None = None
    retryable: bool = True


class JobLeaseResponse(BaseModel):
    """A won claim rendered for the wire. Carries the job fields the worker needs
    to dispatch (type + payload references) plus the fencing ``lease_token`` and
    the lease expiry. ``payload`` holds references/ids only (never a flag/seed)."""

    job_id: str
    job_type: str
    idempotency_key: str
    available_at: str
    status: str
    priority: int
    payload: dict[str, Any]
    required_capabilities: list[str]
    attempt_count: int
    max_attempts: int
    claimed_by: str | None = None
    competition_id: str | None = None
    definition_slug: str | None = None
    version_no: int | None = None
    lease_token: str
    lease_expires_at: str


def job_lease_to_response(lease: JobLease) -> dict[str, Any]:
    job = lease.job
    return {
        "job_id": job.job_id,
        "job_type": job.job_type,
        "idempotency_key": job.idempotency_key,
        "available_at": job.available_at.isoformat(),
        "status": job.status,
        "priority": job.priority,
        "payload": dict(job.payload),
        "required_capabilities": list(job.required_capabilities),
        "attempt_count": job.attempt_count,
        "max_attempts": job.max_attempts,
        "claimed_by": job.claimed_by,
        "competition_id": job.competition_id,
        "definition_slug": job.definition_slug,
        "version_no": job.version_no,
        "lease_token": lease.lease_token,
        "lease_expires_at": lease.lease_expires_at.isoformat(),
    }


# -- instance facts + transitions ---------------------------------------------


class WorkerInstanceView(BaseModel):
    """The worker's view of an instance: exactly the operational facts a worker
    needs to launch/observe it. Deliberately OMITS ``instance_seed`` (a
    generation input that can influence flags) and every credential / runtime
    handle -- those never reach the worker over this read."""

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


def instance_to_worker_view(instance: Instance) -> dict[str, Any]:
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
    }


class HealthReportRequest(BaseModel):
    """A health observation. Note the ABSENT ``worker`` field -- the gateway
    stamps the authenticated worker; a client cannot report as another."""

    observed_state: str = Field(min_length=1)
    healthy: bool
    generation: int = Field(ge=1)
    observed_at: str = Field(min_length=1)
    detail: dict[str, Any] = Field(default_factory=dict)


class ResourceReportRequest(BaseModel):
    """A runtime resource. ``worker`` is ABSENT -- stamped from the credential."""

    kind: str = Field(min_length=1)
    external_ref: str = Field(min_length=1)
    generation: int = Field(ge=1)
    state: str = "active"


class EndpointReportRequest(BaseModel):
    name: str = Field(min_length=1)
    host: str = Field(min_length=1)
    port: int = Field(ge=1, le=65535)
    protocol: str = Field(min_length=1)
    url: str = Field(min_length=1)
    internal: bool = False


class TransitionRequest(BaseModel):
    to_state: str = Field(min_length=1)
    reason: str = Field(min_length=1)


def endpoint_from_request(
    instance_id: str, body: EndpointReportRequest
) -> InstanceEndpoint:
    return InstanceEndpoint(
        instance_id=instance_id,
        name=body.name,
        host=body.host,
        port=body.port,
        protocol=body.protocol,
        url=body.url,
        internal=body.internal,
    )
