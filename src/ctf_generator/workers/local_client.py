"""In-process control-plane client for the single-host / test path (M8 slice 2).

:class:`LocalControlPlaneClient` implements
:class:`~ctf_generator.workers.worker.WorkerControlPlaneClient` by calling the
control-plane application services in-process over a local DB session. It is the
DOCUMENTED single-host exception to the rule that a worker holds no control-plane
DB credential -- appropriate only when the worker and control plane share a host
and a database. The NETWORKED worker (M9) swaps this for an HTTP client that
carries only the scoped bearer token; the run loop is unchanged because both
implement the same Protocol.

This module lives under ``workers`` (execution-plane), not ``application``, so the
dependency direction is honest: the worker depends on the control-plane services,
never the reverse.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from ctf_generator.application.execution.worker_instance_service import (
    WorkerInstanceService,
)
from ctf_generator.application.execution.worker_job_service import WorkerJobService
from ctf_generator.application.instances.service import InstanceLifecycleService
from ctf_generator.application.scheduling.service import SchedulingService
from ctf_generator.domain.instances.models import (
    HealthObservation,
    Instance,
    InstanceEndpoint,
    RuntimeResource,
)
from ctf_generator.domain.scheduling.models import (
    PLATFORM_SCOPE_KEY,
    ReservationItem,
    WorkerRequirements,
)
from ctf_generator.domain.work.models import JobLease


class LocalControlPlaneClient:
    """In-process ``WorkerControlPlaneClient`` over local application services.

    Fact reports and observed-lifecycle transitions are routed through the
    authenticated, ownership-checked :class:`WorkerInstanceService` (never the
    ungated :class:`InstanceLifecycleService` methods directly), so the single-host
    path enforces the same worker-owns-instance trust boundary the networked M9
    HTTP transport will.
    """

    def __init__(
        self,
        *,
        jobs: WorkerJobService,
        instances: WorkerInstanceService,
        lifecycle: InstanceLifecycleService,
        scheduling: SchedulingService,
        token: str,
        architecture: str,
        reservation_ttl_hours: int = 2,
    ) -> None:
        self._jobs = jobs
        self._instances = instances
        self._lifecycle = lifecycle
        self._scheduling = scheduling
        self._token = token
        self._architecture = architecture
        self._reservation_ttl_hours = reservation_ttl_hours

    # -- credential ------------------------------------------------------------

    def authenticate(self, now: datetime) -> str:
        """Return the pre-issued scoped bearer token. (A local worker is handed a
        credential at start; rotation is an operator action via
        ``WorkerEnrollmentService``.)"""
        return self._token

    # -- queue verbs -----------------------------------------------------------

    def claim(self, token: str, lease_seconds: int, now: datetime) -> JobLease | None:
        return self._jobs.claim(token, lease_seconds, now)

    def start(self, token: str, job_id: str, lease_token: str, now: datetime) -> None:
        self._jobs.start(token, job_id, lease_token, now)

    def heartbeat(
        self, token: str, job_id: str, lease_token: str, lease_seconds: int, now: datetime
    ) -> bool:
        return self._jobs.heartbeat(token, job_id, lease_token, lease_seconds, now)

    def complete(
        self, token: str, job_id: str, lease_token: str, result: dict | None, now: datetime
    ) -> None:
        self._jobs.complete(token, job_id, lease_token, result, None, None, now)

    def fail(
        self,
        token: str,
        job_id: str,
        lease_token: str,
        error_class: str,
        error_detail: str | None,
        retryable: bool,
        now: datetime,
    ) -> None:
        self._jobs.fail(
            token, job_id, lease_token, error_class, error_detail, retryable, now
        )

    # -- instance facts --------------------------------------------------------

    def get_instance(self, instance_id: str) -> Instance | None:
        return self._lifecycle.get(instance_id)

    def replace_instance(self, instance_id: str, now: datetime) -> Instance:
        """Re-place + re-reserve an unassigned instance (the slice-2 launch
        contract). Reuses ``SchedulingService`` keyed on ``instance_id`` (so the
        hold is idempotent) and records the fresh assignment before the worker
        starts a container. ``architecture`` is derived from THIS worker's own
        runtime probe (never hardcoded), so an arm64 fleet places on arm64."""
        instance = self._lifecycle.get(instance_id)
        if instance is None:
            raise LookupError(f"instance not found: {instance_id!r}")
        requirements = WorkerRequirements(
            architecture=self._architecture,
            required_capabilities=frozenset({"launch_instance"}),
        )
        expires_at = now + timedelta(hours=self._reservation_ttl_hours)
        _reservation, worker_name = self._scheduling.select_and_reserve(
            requirements=requirements,
            reservation_id=instance_id,
            pooled_items=(
                ReservationItem("platform", PLATFORM_SCOPE_KEY, "active_instances", 1),
            ),
            expires_at=expires_at,
            now=now,
        )
        return self._lifecycle.set_assignment(instance_id, worker_name, now)

    def report_health(self, observation: HealthObservation, now: datetime) -> None:
        self._instances.report_health(self._token, observation, now)

    def report_runtime_resource(self, resource: RuntimeResource, now: datetime) -> None:
        self._instances.report_runtime_resource(self._token, resource, now)

    def report_endpoint(self, endpoint: InstanceEndpoint, now: datetime) -> None:
        self._instances.report_endpoint(self._token, endpoint, now)

    def transition_instance(
        self, instance_id: str, to_state: str, *, reason: str, now: datetime
    ) -> None:
        self._instances.transition_instance(
            self._token, instance_id, to_state, reason=reason, now=now
        )
