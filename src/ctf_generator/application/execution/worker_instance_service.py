"""The authenticated worker-facing surface over instance FACTS + transitions (M8).

This closes the same trust gap for instance reports that :class:`WorkerJobService`
closes for the job queue: the raw :class:`InstanceLifecycleService` fact/transition
methods (``record_observation`` / ``record_runtime_resource`` / ``record_endpoint``
/ ``apply_transition``) take no credential and no ownership check, so a worker --
or anything holding a DB session -- could report health, resources, endpoints, or
drive a lifecycle transition for ANY instance, including one assigned to a
different worker. ``WorkerInstanceService`` is that gate. Before every verb it:

1. authenticates the presented bearer credential (delegated to
   :class:`WorkerEnrollmentService`; a bad / expired / revoked / non-trusted /
   quarantined worker fails identically as :class:`WorkerAuthenticationError`);
2. requires the per-verb scope (``instances:report`` for facts,
   ``instances:transition`` for a driven transition);
3. enforces OWNERSHIP -- the target instance's ``assigned_worker`` must equal the
   authenticated worker's name, so a worker can never report or transition an
   instance it is not assigned; and
4. derives ``worker`` EXCLUSIVELY from the credential -- a worker cannot stamp a
   report with another worker's name.

The reconciler remains the eventual authority that folds observations against
desired state (generation-fenced); this service only lets an ASSIGNED worker
report what it observes and drive the observed lifecycle it is responsible for --
through an authenticated, ownership-checked path, never the ungated one.
"""

from __future__ import annotations

from datetime import datetime

from ctf_generator.application.instances.service import InstanceLifecycleService
from ctf_generator.application.worker_enrollment import (
    WorkerEnrollmentService,
    require_scope,
)
from ctf_generator.domain.instances.models import (
    HealthObservation,
    InstanceEndpoint,
    RuntimeResource,
)

REPORT_SCOPE = "instances:report"
TRANSITION_SCOPE = "instances:transition"


class WorkerAuthenticationError(PermissionError):
    """The presented credential is invalid, expired, revoked, or belongs to a
    non-trusted / quarantined worker. Deliberately undifferentiated."""


class InstanceOwnershipError(PermissionError):
    """The authenticated worker is not the instance's ``assigned_worker`` -- it
    may not report facts for it or drive its lifecycle."""


class WorkerInstanceService:
    """Authenticated, scope-gated, ownership-checked worker API over instance
    facts and observed-lifecycle transitions."""

    def __init__(
        self,
        lifecycle: InstanceLifecycleService,
        enrollment: WorkerEnrollmentService,
    ) -> None:
        self._lifecycle = lifecycle
        self._enrollment = enrollment

    # -- gate ------------------------------------------------------------------

    def _authorize_owner(
        self, token: str, instance_id: str, now: datetime, *, scope: str
    ) -> str:
        """Authenticate + require ``scope`` + verify the credential's worker owns
        ``instance_id``. Returns the authenticated worker name (the ONLY name a
        report may be stamped with)."""
        auth = self._enrollment.authenticate(token, now)
        if auth is None:
            raise WorkerAuthenticationError("worker authentication failed")
        require_scope(auth, scope)
        instance = self._lifecycle.get(instance_id)
        if instance is None:
            raise LookupError(f"instance not found: {instance_id!r}")
        if instance.assigned_worker != auth.worker.name:
            raise InstanceOwnershipError(
                f"worker {auth.worker.name!r} is not assigned instance "
                f"{instance_id!r}; refusing report/transition"
            )
        return auth.worker.name

    # -- fact reports (instances:report) ---------------------------------------

    def report_health(self, token: str, observation: HealthObservation, now: datetime) -> None:
        """Append a health observation for an OWNED instance. ``observation.worker``
        must be the authenticated worker (a worker cannot report as another)."""
        worker = self._authorize_owner(
            token, observation.instance_id, now, scope=REPORT_SCOPE
        )
        if observation.worker != worker:
            raise InstanceOwnershipError(
                "health observation.worker does not match the authenticated worker"
            )
        self._lifecycle.record_observation(observation)

    def report_runtime_resource(
        self, token: str, resource: RuntimeResource, now: datetime
    ) -> None:
        worker = self._authorize_owner(
            token, resource.instance_id, now, scope=REPORT_SCOPE
        )
        if resource.worker != worker:
            raise InstanceOwnershipError(
                "runtime resource.worker does not match the authenticated worker"
            )
        self._lifecycle.record_runtime_resource(resource)

    def report_endpoint(self, token: str, endpoint: InstanceEndpoint, now: datetime) -> None:
        self._authorize_owner(
            token, endpoint.instance_id, now, scope=REPORT_SCOPE
        )
        self._lifecycle.record_endpoint(endpoint)

    # -- observed-lifecycle transition (instances:transition) ------------------

    def transition_instance(
        self, token: str, instance_id: str, to_state: str, *, reason: str, now: datetime
    ) -> None:
        """Drive an OWNED instance's observed lifecycle. The reconciler remains
        the eventual authority; this is the authenticated, ownership-checked path
        for a worker's synchronous observed transition."""
        # Ownership is already checked; the audit ``actor`` uses the validated
        # 'worker' vocabulary token (the specific worker name is carried by the
        # ownership check + the reason, not smuggled into the actor enum).
        self._authorize_owner(token, instance_id, now, scope=TRANSITION_SCOPE)
        self._lifecycle.apply_transition(
            instance_id, to_state, reason=reason, actor="worker", now=now
        )
