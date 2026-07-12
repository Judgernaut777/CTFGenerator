"""Instance reconciler (M8 slice 1b): converge observed onto desired state.

A durable, crash-safe, re-entrant pass that compares DESIRED (each instance's
``desired_state`` + its expected/leaked runtime resources and endpoints) against
OBSERVED (the latest generation-matched :class:`HealthObservation` supplied by a
pluggable :class:`ObservedStateSource` -- the DB in prod, a fake in tests) and
issues the corrective action for each of ten drift cases.

Two invariants make repeated passes converge without thrash:

* GENERATION-GATE. An observation whose ``generation`` does not equal the
  instance's current generation is ignored for every decision (a stale worker's
  view can never drive a transition), so a reset (which bumps the generation) is
  fenced cleanly.
* IDEMPOTENT ENQUEUE. Every corrective job is keyed ``(instance_id, generation,
  action)`` via :func:`..corrective.build_corrective_job`, and
  ``JobService.enqueue_idempotent`` collapses a duplicate key -- so re-running a
  pass (or two passes racing) enqueues at most one job per
  ``(instance, generation, action)``. A second pass over a converged instance is
  a no-op.

The control plane never runs a container: this module imports no Docker/
subprocess and executes no challenge code. Corrective work is expressed as
``JobQueue`` jobs a worker claims with scoped credentials in slice 2.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from typing import Protocol

from sqlalchemy.orm import Session

from ctf_generator.domain.instances.models import (
    HealthObservation,
    Instance,
)
from ctf_generator.domain.repositories import InstanceRepository, WorkerRegistry
from ctf_generator.infrastructure.database.instance_repository import (
    SqlAlchemyInstanceRepository,
)
from ctf_generator.infrastructure.database.session import Database
from ctf_generator.infrastructure.database.worker_repository import (
    SqlAlchemyWorkerRegistry,
)

from ..jobs.service import JobService
from ..scheduling.service import SchedulingService
from .corrective import (
    INSTANCE_ACTION_JOB_TYPES,
    ReconcileAction,
    build_corrective_job,
)

# States from which a stopped/deleted instance may converge toward stopping.
_RUNNING_STATES = frozenset(
    {"active", "healthy", "degraded", "ready", "starting"}
)
# States from which archival is legal (deleted-desired end game).
_ARCHIVABLE_STATES = frozenset({"stopped", "expired", "failed", "quarantined"})


class ObservedStateSource(Protocol):
    """The reconciler's window onto the observed world: the latest health
    observation for an instance. The DB-backed source reads the newest
    ``health_observations`` row; a fake supplies canned observations in tests.
    The reconciler applies generation-gating itself, so this returns the raw
    latest observation (or ``None`` when the worker has never reported)."""

    def latest_observation(self, instance_id: str) -> HealthObservation | None:
        ...


class WorkerLivenessSource(Protocol):
    """Whether a worker is still dispatch-eligible (trusted, not quarantined,
    not draining, heartbeat fresh). Backs the stale-worker drift case; faked in
    tests."""

    def is_dispatchable(self, worker_name: str, now: datetime) -> bool:
        ...


class InstanceReconciler:
    """Desired-vs-observed convergence with generation-fenced, idempotent
    corrective work."""

    def __init__(
        self,
        database: Database,
        *,
        observed_source: ObservedStateSource,
        worker_liveness: WorkerLivenessSource,
        jobs: JobService,
        scheduling: SchedulingService,
        repository_factory: Callable[
            [Session], InstanceRepository
        ] = SqlAlchemyInstanceRepository,
    ) -> None:
        self._database = database
        self._observed = observed_source
        self._liveness = worker_liveness
        self._jobs = jobs
        self._scheduling = scheduling
        self._repo = repository_factory

    # -- public entry --------------------------------------------------------

    def reconcile_once(
        self, now: datetime, *, stuck_after_seconds: int = 300, limit: int = 500
    ) -> list[ReconcileAction]:
        """One convergence pass over every non-archived instance plus a global
        leak sweep. Returns the corrective actions taken (empty when the world is
        already converged)."""
        with self._database.session_scope() as session:
            instances = self._repo(session).list_reconcilable(limit)

        actions: list[ReconcileAction] = []
        for instance in instances:
            actions.extend(
                self._reconcile_instance(instance, now, stuck_after_seconds)
            )
        actions.extend(self._reconcile_leaks(now, limit))
        return actions

    # -- helpers -------------------------------------------------------------

    def _effective_observation(
        self, instance: Instance
    ) -> HealthObservation | None:
        """The latest observation, generation-gated: an observation carrying a
        different generation than the instance is stale and ignored."""
        obs = self._observed.latest_observation(instance.instance_id)
        if obs is None or obs.generation != instance.generation:
            return None
        return obs

    def _enqueue(
        self,
        instance: Instance,
        generation: int,
        action: str,
        now: datetime,
        *,
        case: str,
    ) -> ReconcileAction:
        job = build_corrective_job(instance, generation, action, now)
        _persisted, created = self._jobs.enqueue_idempotent(job, now)
        return ReconcileAction(
            instance_id=instance.instance_id,
            case=case,
            action=action,
            detail=f"enqueue {action} gen{generation}",
            job_type=INSTANCE_ACTION_JOB_TYPES[action],
            idempotency_key=job.idempotency_key,
            job_created=created,
        )

    def _transition(
        self,
        instance_id: str,
        to_state: str,
        *,
        reason: str,
        now: datetime,
        case: str,
    ) -> tuple[Instance, ReconcileAction]:
        with self._database.session_scope() as session:
            updated = self._repo(session).transition(
                instance_id, to_state, reason=reason, actor="system", now=now
            )
        return updated, ReconcileAction(
            instance_id=instance_id,
            case=case,
            action="transition",
            detail=f"-> {to_state}",
        )

    def _mark_releasing(
        self, instance_id: str, resources, now: datetime, *, case: str
    ) -> list[ReconcileAction]:
        out: list[ReconcileAction] = []
        with self._database.session_scope() as session:
            repo = self._repo(session)
            for res in resources:
                if res.state == "active":
                    repo.set_resource_state(
                        instance_id, res.kind, res.external_ref, "releasing", now
                    )
                    out.append(
                        ReconcileAction(
                            instance_id=instance_id,
                            case=case,
                            action="mark_releasing",
                            detail=f"{res.kind}:{res.external_ref}",
                        )
                    )
        return out

    def _delete_endpoints(
        self, instance_id: str, endpoints, now: datetime, *, case: str
    ) -> list[ReconcileAction]:
        out: list[ReconcileAction] = []
        with self._database.session_scope() as session:
            repo = self._repo(session)
            for endpoint in endpoints:
                if repo.delete_endpoint(instance_id, endpoint.name):
                    out.append(
                        ReconcileAction(
                            instance_id=instance_id,
                            case=case,
                            action="delete_endpoint",
                            detail=endpoint.name,
                        )
                    )
        return out

    def _load_facts(self, instance_id: str):
        with self._database.session_scope() as session:
            repo = self._repo(session)
            return (
                repo.list_runtime_resources(instance_id),
                repo.list_endpoints(instance_id),
            )

    # -- per-instance decision -----------------------------------------------

    def _reconcile_instance(
        self, instance: Instance, now: datetime, stuck_after_seconds: int
    ) -> list[ReconcileAction]:
        obs = self._effective_observation(instance)
        observed_absent = obs is None or obs.observed_absent
        observed_present = obs is not None and not obs.observed_absent
        observed_healthy = observed_present and obs.healthy

        if instance.desired_state == "active":
            return self._reconcile_active(
                instance,
                obs,
                observed_absent,
                observed_present,
                observed_healthy,
                now,
                stuck_after_seconds,
            )
        if instance.desired_state == "stopped":
            return self._reconcile_stopped(
                instance, observed_present, observed_absent, now
            )
        # desired_state == "deleted"
        return self._reconcile_deleted(
            instance, observed_present, observed_absent, now
        )

    def _reconcile_active(
        self,
        instance: Instance,
        obs: HealthObservation | None,
        observed_absent: bool,
        observed_present: bool,
        observed_healthy: bool,
        now: datetime,
        stuck_after_seconds: int,
    ) -> list[ReconcileAction]:
        actions: list[ReconcileAction] = []

        # (3) STALE WORKER: the placed worker is no longer dispatch-eligible.
        # Release the dead hold, CLEAR the assignment (this is what stops the
        # case re-firing next pass -> no thrash), bump the generation to fence
        # stale observations, and enqueue a fresh-generation launch (re-placement
        # onto a live worker is finalized by the launch job in slice 2).
        if instance.assigned_worker is not None and not self._liveness.is_dispatchable(
            instance.assigned_worker, now
        ):
            self._scheduling.release(instance.instance_id, now)
            with self._database.session_scope() as session:
                repo = self._repo(session)
                repo.set_assignment(instance.instance_id, None, now)
                bumped = repo.bump_generation(instance.instance_id, now)
            actions.append(
                ReconcileAction(
                    instance_id=instance.instance_id,
                    case="3-stale-worker",
                    action="clear_assignment_bump_generation",
                    detail=f"gen{instance.generation}->gen{bumped.generation}",
                )
            )
            actions.append(
                self._enqueue(
                    bumped, bumped.generation, "launch", now, case="3-stale-worker"
                )
            )
            return actions

        # (8) PARTIAL RESET: resources created under an older generation still
        # linger. Clean them up (mark releasing + enqueue delete) and let the
        # (1) path below ensure the new-generation launch. Old-generation
        # observations are already ignored by the generation-gate above.
        resources, _endpoints = self._load_facts(instance.instance_id)
        stale_resources = [
            r for r in resources if r.state == "active" and r.generation < instance.generation
        ]
        if stale_resources:
            actions.extend(
                self._mark_releasing(
                    instance.instance_id, stale_resources, now, case="8-partial-reset"
                )
            )
            actions.append(
                self._enqueue(
                    instance,
                    instance.generation,
                    "delete",
                    now,
                    case="8-partial-reset",
                )
            )

        # (6) FAILED ACKNOWLEDGEMENT: stuck in building/starting past a threshold
        # while a healthy observation says it is up -> advance per the
        # observation (age is measured off updated_at; the caller passes now).
        if (
            instance.state in ("building", "starting")
            and observed_healthy
            and self._age_seconds(instance, now) >= stuck_after_seconds
        ):
            target = "ready" if instance.state == "building" else "healthy"
            _updated, action = self._transition(
                instance.instance_id,
                target,
                reason="advance on healthy observation (stuck)",
                now=now,
                case="6-failed-ack",
            )
            actions.append(action)
            return actions

        # (1)/(4) MISSING CONTAINER / EXPIRED LEASE: desired active but nothing is
        # observed (or the observation is stale). Signal degradation from a
        # healthy point, then ensure the launch job is enqueued (idempotent -- a
        # requeued-by-reaper launch collapses, so no double).
        if observed_absent and instance.state in (
            "active",
            "healthy",
            "degraded",
            "ready",
            "starting",
            "building",
            "queued",
            "failed",
            "stopped",
        ):
            if instance.state in ("active", "healthy"):
                _updated, action = self._transition(
                    instance.instance_id,
                    "degraded",
                    reason="observed absent while desired active",
                    now=now,
                    case="1-missing-container",
                )
                actions.append(action)
            actions.append(
                self._enqueue(
                    instance,
                    instance.generation,
                    "launch",
                    now,
                    case="1-missing-container",
                )
            )
            return actions

        return actions

    def _reconcile_stopped(
        self,
        instance: Instance,
        observed_present: bool,
        observed_absent: bool,
        now: datetime,
    ) -> list[ReconcileAction]:
        actions: list[ReconcileAction] = []

        # (2) UNEXPECTED CONTAINER: still running though desired stopped -> stop.
        if observed_present:
            actions.append(
                self._enqueue(
                    instance, instance.generation, "stop", now, case="2-unexpected"
                )
            )

        # Drive the observed state toward stopped once the container is gone.
        if observed_absent:
            if instance.state in _RUNNING_STATES:
                _updated, action = self._transition(
                    instance.instance_id,
                    "stopping",
                    reason="desired stopped; draining",
                    now=now,
                    case="2-unexpected",
                )
                actions.append(action)
                return actions
            if instance.state == "stopping":
                instance, action = self._transition(
                    instance.instance_id,
                    "stopped",
                    reason="observed absent; stopped",
                    now=now,
                    case="2-unexpected",
                )
                actions.append(action)

        # (9) STOPPED STILL EXPOSED: endpoints/active resources linger -> clean.
        if instance.state == "stopped":
            actions.extend(self._cleanup_exposed(instance, now, case="9-exposed"))
        return actions

    def _reconcile_deleted(
        self,
        instance: Instance,
        observed_present: bool,
        observed_absent: bool,
        now: datetime,
    ) -> list[ReconcileAction]:
        actions: list[ReconcileAction] = []

        # (2) UNEXPECTED CONTAINER for a delete: stop AND schedule resource
        # deletion.
        if observed_present:
            actions.append(
                self._enqueue(
                    instance, instance.generation, "stop", now, case="2-unexpected"
                )
            )
            actions.append(
                self._enqueue(
                    instance, instance.generation, "delete", now, case="2-unexpected"
                )
            )
            return actions

        # Container gone: clean endpoints + resources, then converge to archived.
        cleanup = self._cleanup_exposed(instance, now, case="9-exposed")
        actions.extend(cleanup)

        if instance.state in _RUNNING_STATES:
            _updated, action = self._transition(
                instance.instance_id,
                "stopping",
                reason="desired deleted; draining",
                now=now,
                case="9-exposed",
            )
            actions.append(action)
            return actions
        if instance.state == "stopping":
            _updated, action = self._transition(
                instance.instance_id,
                "stopped",
                reason="observed absent; stopped",
                now=now,
                case="9-exposed",
            )
            actions.append(action)
            return actions
        if instance.state in _ARCHIVABLE_STATES:
            resources, endpoints = self._load_facts(instance.instance_id)
            active_left = [r for r in resources if r.state == "active"]
            if not active_left and not endpoints:
                _updated, action = self._transition(
                    instance.instance_id,
                    "archived",
                    reason="deleted; fully cleaned up",
                    now=now,
                    case="9-exposed",
                )
                actions.append(action)
                self._scheduling.release(instance.instance_id, now)
        return actions

    def _cleanup_exposed(
        self, instance: Instance, now: datetime, *, case: str
    ) -> list[ReconcileAction]:
        """Delete an instance's endpoints and schedule deletion of its still-
        active runtime resources (marking them releasing). Idempotent: once the
        endpoints are gone and the resources releasing, a re-run is a no-op."""
        resources, endpoints = self._load_facts(instance.instance_id)
        actions: list[ReconcileAction] = []
        actions.extend(
            self._delete_endpoints(instance.instance_id, endpoints, now, case=case)
        )
        active_resources = [r for r in resources if r.state == "active"]
        if active_resources:
            actions.append(
                self._enqueue(
                    instance, instance.generation, "delete", now, case=case
                )
            )
            actions.extend(
                self._mark_releasing(
                    instance.instance_id, active_resources, now, case=case
                )
            )
        return actions

    # -- global leak sweep ---------------------------------------------------

    def _reconcile_leaks(self, now: datetime, limit: int) -> list[ReconcileAction]:
        actions: list[ReconcileAction] = []
        with self._database.session_scope() as session:
            repo = self._repo(session)
            leaked = repo.list_leaked_resources(limit)
            orphan_endpoints = repo.list_orphan_endpoints(limit)

        # (5) LEAKED RESOURCE: an active runtime resource whose owning instance
        # is archived (terminal) -> schedule deletion + mark releasing.
        seen_instances: set[str] = set()
        for res in leaked:
            instance = self.get_instance(res.instance_id)
            if instance is None:  # pragma: no cover - FK guarantees presence
                continue
            if res.instance_id not in seen_instances:
                actions.append(
                    self._enqueue(
                        instance,
                        instance.generation,
                        "delete",
                        now,
                        case="5-leaked-resource",
                    )
                )
                seen_instances.add(res.instance_id)
            actions.extend(
                self._mark_releasing(
                    res.instance_id, [res], now, case="5-leaked-resource"
                )
            )

        # (10) ORPHANED ENDPOINT: an endpoint whose owning instance is terminal.
        for endpoint in orphan_endpoints:
            actions.extend(
                self._delete_endpoints(
                    endpoint.instance_id, [endpoint], now, case="10-orphan-endpoint"
                )
            )
        return actions

    def get_instance(self, instance_id: str) -> Instance | None:
        with self._database.session_scope() as session:
            return self._repo(session).get(instance_id)

    @staticmethod
    def _age_seconds(instance: Instance, now: datetime) -> float:
        if instance.updated_at is None:
            return float("inf")
        return (now - instance.updated_at).total_seconds()


# --- DB-backed seams --------------------------------------------------------


class RepositoryObservedStateSource:
    """The production :class:`ObservedStateSource`: the newest
    ``health_observations`` row for an instance, read in its own short
    transaction."""

    def __init__(
        self,
        database: Database,
        repository_factory: Callable[
            [Session], InstanceRepository
        ] = SqlAlchemyInstanceRepository,
    ) -> None:
        self._database = database
        self._repo = repository_factory

    def latest_observation(self, instance_id: str) -> HealthObservation | None:
        with self._database.session_scope() as session:
            return self._repo(session).latest_observation(instance_id)


class RepositoryWorkerLivenessSource:
    """The production :class:`WorkerLivenessSource`: a worker is dispatchable iff
    it is ``trusted``, not quarantined, not draining, and its heartbeat is within
    ``max_age_seconds``."""

    def __init__(
        self,
        database: Database,
        *,
        max_age_seconds: int = 60,
        registry_factory: Callable[
            [Session], WorkerRegistry
        ] = SqlAlchemyWorkerRegistry,
    ) -> None:
        self._database = database
        self._max_age_seconds = max_age_seconds
        self._registry = registry_factory

    def is_dispatchable(self, worker_name: str, now: datetime) -> bool:
        with self._database.session_scope() as session:
            worker = self._registry(session).get(worker_name)
        if worker is None:
            return False
        if worker.trust_state != "trusted":
            return False
        if worker.quarantined_at is not None or worker.drain_requested_at is not None:
            return False
        if worker.last_heartbeat_at is None:
            return False
        return (now - worker.last_heartbeat_at).total_seconds() <= self._max_age_seconds
