"""Corrective-action primitives shared by the lifecycle service and reconciler.

The one idempotency contract for every instance-lifecycle job: the key is
``(instance_id, generation, action)``. Because ``JobService.enqueue_idempotent``
collapses a duplicate key to the existing row, a re-run of any lifecycle step or
reconciler pass enqueues at most one job per ``(instance, generation, action)``
-- which is exactly what makes the whole plane crash-safe and non-thrashing.

Payloads carry references only (instance id, generation, action) -- never a
flag, token, or credential.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime

from ctf_generator.domain.instances.models import Instance
from ctf_generator.domain.work.models import Job

# The lifecycle "action" -> durable job type. Each action's corrective job is a
# real M7 job type a worker claims with scoped credentials in slice 2.
INSTANCE_ACTION_JOB_TYPES: dict[str, str] = {
    "launch": "launch_instance",
    "stop": "stop_instance",
    "reset": "reset_instance",
    "expire": "expire_instance",
    "delete": "delete_runtime_resources",
}


def corrective_idempotency_key(
    instance_id: str, generation: int, action: str
) -> str:
    """The single stable idempotency key for an instance corrective job:
    ``instance:<id>:gen<n>:<action>``. Two enqueues with this key collapse to one
    job (a second pass / retry is a no-op)."""
    if action not in INSTANCE_ACTION_JOB_TYPES:
        raise ValueError(
            f"action must be one of {sorted(INSTANCE_ACTION_JOB_TYPES)}, "
            f"got {action!r}"
        )
    return f"instance:{instance_id}:gen{generation}:{action}"


def build_corrective_job(
    instance: Instance, generation: int, action: str, now: datetime
) -> Job:
    """Build the (idempotency-keyed) corrective job for ``action`` against
    ``instance`` at ``generation``. Carries the instance's competition /
    challenge-version audit linkage and a reference-only payload; requires the
    worker to advertise the matching job-type capability."""
    job_type = INSTANCE_ACTION_JOB_TYPES[action]
    return Job(
        job_id=str(uuid.uuid4()),
        job_type=job_type,
        idempotency_key=corrective_idempotency_key(
            instance.instance_id, generation, action
        ),
        available_at=now,
        required_capabilities=(job_type,),
        payload={
            "instance_id": instance.instance_id,
            "generation": generation,
            "action": action,
        },
        competition_id=instance.competition_id,
        definition_slug=instance.definition_slug,
        version_no=instance.version_no,
    )


@dataclass(frozen=True)
class ReconcileAction:
    """One corrective decision a reconciler pass took, for observability and
    test assertions. ``job_created`` is ``True`` when an enqueue minted a new
    job, ``False`` when it collapsed onto an existing one (the idempotency
    proof), and ``None`` for a non-enqueue action (a transition / cleanup)."""

    instance_id: str
    case: str
    action: str
    detail: str = ""
    job_type: str | None = None
    idempotency_key: str | None = None
    job_created: bool | None = None
