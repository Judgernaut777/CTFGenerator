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
from ctf_generator.domain.work.models import TERMINAL_JOB_STATUSES
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
    corrective_idempotency_key,
)

# Entering one of these releases the capacity hold (mirrors
# InstanceLifecycleService._RELEASE_STATES so the service and reconciler paths
# cannot diverge on the release semantics).
_RELEASE_STATES = frozenset({"stopped", "expired", "archived"})
# Every LIVE (non-terminal, still-drainable) state a stopped/deleted instance
# may converge toward ``stopping`` from -- NOT just the running ones, so an
# early-state (requested/queued/building) instance still drains.
_LIVE_DRAINABLE_STATES = frozenset(
    {
        "requested",
        "queued",
        "building",
        "ready",
        "starting",
        "healthy",
        "active",
        "degraded",
    }
)
# States a desired-active instance may be relaunched from when its container is
# observed absent.
_RECOVERY_STATES = _LIVE_DRAINABLE_STATES | frozenset({"failed", "stopped"})
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
    """The reconciler's window onto a worker's dispatch health. Two distinct
    signals back the stale-worker drift case (faked in tests):

    * :meth:`is_dispatchable` -- the full eligibility check (trusted, not
      quarantined, not draining, heartbeat fresh).
    * :meth:`is_adverse` -- a GENUINE adverse condition (gone / untrusted /
      quarantined / draining), DELIBERATELY excluding mere heartbeat staleness.
      A worker still serving a healthy, generation-matched instance whose only
      fault is a stale heartbeat is NOT adverse, so a heartbeat blip never tears
      a healthy instance down."""

    def is_dispatchable(self, worker_name: str, now: datetime) -> bool:
        ...

    def is_adverse(self, worker_name: str, now: datetime) -> bool:
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
            # Per-instance fault isolation: one instance's guard rejection (e.g. a
            # concurrent operator transition making this pass's drain edge illegal
            # -> ProgrammingError) or any other error must not abort the whole
            # batch. Record a structured, secret-free per-instance error and move
            # on so every other instance still converges this pass.
            try:
                actions.extend(
                    self._reconcile_instance(instance, now, stuck_after_seconds)
                )
            except Exception as exc:  # noqa: BLE001 - isolate, never abort the batch
                actions.append(
                    ReconcileAction(
                        instance_id=instance.instance_id,
                        case="error",
                        action="reconcile_error",
                        detail=f"{type(exc).__name__}: {exc}",
                    )
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

    def _drive_transition(
        self,
        instance_id: str,
        to_state: str,
        *,
        reason: str,
        now: datetime,
        case: str,
    ) -> tuple[Instance | None, list[ReconcileAction]]:
        """The SINGLE reconciler state-change primitive. Applies a guarded
        transition (idempotent no-op when already at ``to_state``) and, after any
        move that ENTERS :data:`_RELEASE_STATES`, releases the capacity hold --
        mirroring :meth:`InstanceLifecycleService.apply_transition` so the service
        and reconciler can never diverge on release semantics. Returns the updated
        instance (or ``None`` if it vanished) and the emitted actions."""
        with self._database.session_scope() as session:
            repo = self._repo(session)
            current = repo.get(instance_id)
            if current is None:  # pragma: no cover - FK guarantees presence
                return None, []
            if current.state == to_state:
                return current, []
            updated = repo.transition(
                instance_id, to_state, reason=reason, actor="system", now=now
            )
        actions = [
            ReconcileAction(
                instance_id=instance_id,
                case=case,
                action="transition",
                detail=f"-> {to_state}",
            )
        ]
        if to_state in _RELEASE_STATES:
            # Idempotent: a second release (or a service-driven one) is a no-op.
            self._scheduling.release(instance_id, now)
        return updated, actions

    def _fence_stale_worker(
        self, instance_id: str, expected_worker: str, expected_generation: int, now: datetime
    ) -> Instance | None:
        with self._database.session_scope() as session:
            return self._repo(session).fence_stale_worker(
                instance_id,
                expected_worker=expected_worker,
                expected_generation=expected_generation,
                now=now,
            )

    def _fence_missing_container(
        self, instance_id: str, expected_generation: int, now: datetime
    ) -> Instance | None:
        with self._database.session_scope() as session:
            return self._repo(session).fence_missing_container(
                instance_id, expected_generation=expected_generation, now=now
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

        # (3) STALE / ADVERSE WORKER: evacuate off a worker that is genuinely
        # adverse (gone / untrusted / quarantined / draining) OR is merely
        # heartbeat-stale WHILE the instance is itself observed absent/unhealthy.
        # A pure heartbeat blip on a worker still serving a healthy,
        # generation-matched instance is NOT a reason to tear it down. The clear
        # + bump is a locked, precondition-checked re-check (still the same
        # worker at the same generation), so two concurrent passes -- or a pass
        # racing an operator -- produce at most one bump and one launch.
        if instance.assigned_worker is not None:
            adverse = self._liveness.is_adverse(instance.assigned_worker, now)
            heartbeat_stale = not adverse and not self._liveness.is_dispatchable(
                instance.assigned_worker, now
            )
            if adverse or (heartbeat_stale and not observed_healthy):
                fenced = self._fence_stale_worker(
                    instance.instance_id,
                    instance.assigned_worker,
                    instance.generation,
                    now,
                )
                if fenced is not None:
                    self._scheduling.release(instance.instance_id, now)
                    actions.append(
                        ReconcileAction(
                            instance_id=instance.instance_id,
                            case="3-stale-worker",
                            action="clear_assignment_bump_generation",
                            detail=f"gen{instance.generation}->gen{fenced.generation}",
                        )
                    )
                    actions.append(
                        self._enqueue(
                            fenced,
                            fenced.generation,
                            "launch",
                            now,
                            case="3-stale-worker",
                        )
                    )
                # Converged (or a rival did): this instance is done this pass.
                return actions

        # (8) PARTIAL RESET: resources created under an older generation still
        # linger. Clean them up (mark releasing + enqueue delete); the recovery
        # below reuses the current-generation launch. Old-generation observations
        # are already ignored by the generation-gate.
        resources, _endpoints = self._load_facts(instance.instance_id)
        stale_resources = [
            r
            for r in resources
            if r.state == "active" and r.generation < instance.generation
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

        # (6) FAILED ACKNOWLEDGEMENT: stuck in an early state past a threshold
        # while a healthy observation says it is up -> advance ONE rung toward
        # healthy each pass (building->ready->starting->healthy) instead of
        # stalling at 'ready'.
        if observed_healthy and self._age_seconds(instance, now) >= stuck_after_seconds:
            ladder = {"building": "ready", "ready": "starting", "starting": "healthy"}
            target = ladder.get(instance.state)
            if target is not None:
                _updated, acts = self._drive_transition(
                    instance.instance_id,
                    target,
                    reason="advance on healthy observation (stuck)",
                    now=now,
                    case="6-failed-ack",
                )
                actions.extend(acts)
                return actions

        # (1)/(4) MISSING CONTAINER: desired active but nothing current-generation
        # is observed. Signal degradation, then EITHER reuse an in-flight launch
        # (crash-between-scopes -- the launch never completed) OR fence the old
        # generation and relaunch on a FRESH one (the container launched then
        # died, so re-using the consumed gen-N launch key would collapse to the
        # completed job and never relaunch). Every generation mutation is a
        # locked, precondition-checked re-check, so concurrent passes mint exactly
        # one new generation; and reusing the SAME launch key the reset path uses
        # collapses a reset-vs-recovery race onto one job.
        if observed_absent and instance.state in _RECOVERY_STATES:
            if instance.state in ("active", "healthy"):
                updated, acts = self._drive_transition(
                    instance.instance_id,
                    "degraded",
                    reason="observed absent while desired active",
                    now=now,
                    case="1-missing-container",
                )
                actions.extend(acts)
                instance = updated or instance
            launch_key = corrective_idempotency_key(
                instance.instance_id, instance.generation, "launch"
            )
            existing = self._jobs.get_by_idempotency_key(launch_key)
            if existing is not None and existing.status not in TERMINAL_JOB_STATUSES:
                # In-flight (never completed): ensure it is present -- the
                # idempotent enqueue collapses onto it. No generation bump.
                actions.append(
                    self._enqueue(
                        instance,
                        instance.generation,
                        "launch",
                        now,
                        case="1-missing-container",
                    )
                )
            elif existing is None or existing.status == "succeeded":
                # Never enqueued, or a completed launch whose container died ->
                # fence the old generation and relaunch on the new one.
                fenced = self._fence_missing_container(
                    instance.instance_id, instance.generation, now
                )
                if fenced is not None:
                    actions.append(
                        ReconcileAction(
                            instance_id=instance.instance_id,
                            case="1-missing-container",
                            action="bump_generation",
                            detail=f"gen{instance.generation}->gen{fenced.generation}",
                        )
                    )
                    actions.append(
                        self._enqueue(
                            fenced,
                            fenced.generation,
                            "launch",
                            now,
                            case="1-missing-container",
                        )
                    )
                # else: a rival pass already fenced + relaunched -> nothing.
            # else: the current-generation launch failed permanently
            # (failed / cancelled / dead_letter) -> surface to operators; do NOT
            # thrash-relaunch by inflating the generation.
            return actions

        return actions

    def _drain_to_stopped(
        self, instance: Instance, now: datetime, *, case: str
    ) -> tuple[Instance, list[ReconcileAction]]:
        """Drive ``instance`` from ANY live state all the way to ``stopped`` once
        its container is observed gone: any drainable state -> ``stopping`` ->
        ``stopped`` (each move via :meth:`_drive_transition`, so reaching stopped
        releases the hold). Returns the (possibly-advanced) instance and actions."""
        actions: list[ReconcileAction] = []
        if instance.state in _LIVE_DRAINABLE_STATES:
            updated, acts = self._drive_transition(
                instance.instance_id,
                "stopping",
                reason=f"desired {instance.desired_state}; draining",
                now=now,
                case=case,
            )
            actions.extend(acts)
            instance = updated or instance
        if instance.state == "stopping":
            updated, acts = self._drive_transition(
                instance.instance_id,
                "stopped",
                reason="observed absent; stopped",
                now=now,
                case=case,
            )
            actions.extend(acts)
            instance = updated or instance
        return instance, actions

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

        # Drive toward stopped (from ANY live state, not just the running ones)
        # once the container is gone; reaching stopped releases the hold.
        if observed_absent:
            instance, acts = self._drain_to_stopped(
                instance, now, case="2-unexpected"
            )
            actions.extend(acts)

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

        # Container gone: clean endpoints + resources, drain to stopped from ANY
        # live state (releasing the hold), then archive -- but ONLY once every
        # runtime resource is worker-confirmed ``released``. Archiving while a
        # resource is still ``active``/``releasing`` would strand it under a
        # terminal instance, invisible to the case-5 leak sweep forever.
        actions.extend(self._cleanup_exposed(instance, now, case="9-exposed"))
        instance, acts = self._drain_to_stopped(instance, now, case="9-exposed")
        actions.extend(acts)

        if instance.state in _ARCHIVABLE_STATES:
            resources, endpoints = self._load_facts(instance.instance_id)
            unreleased = [r for r in resources if r.state != "released"]
            if not unreleased and not endpoints:
                _updated, acts = self._drive_transition(
                    instance.instance_id,
                    "archived",
                    reason="deleted; fully cleaned up",
                    now=now,
                    case="9-exposed",
                )
                actions.extend(acts)
        return actions

    def _cleanup_exposed(
        self, instance: Instance, now: datetime, *, case: str
    ) -> list[ReconcileAction]:
        """Delete an instance's endpoints and schedule deletion of every runtime
        resource that is not yet worker-confirmed ``released`` (``active`` OR
        ``releasing``), marking the still-``active`` ones ``releasing``.

        The delete job is (re-)enqueued for a resource stuck in ``releasing`` --
        not only for a fresh ``active`` one -- so a delete job that dead-lettered
        (or was reaped away) is re-driven on the next pass instead of stranding
        the resource, and its owning deleted instance, non-archived forever. The
        idempotency key collapses duplicate enqueues while a delete job is still
        live; once no live/blocking job holds the key a fresh enqueue is minted.
        Idempotent: once the endpoints are gone and every resource is ``released``,
        a re-run is a no-op."""
        resources, endpoints = self._load_facts(instance.instance_id)
        actions: list[ReconcileAction] = []
        actions.extend(
            self._delete_endpoints(instance.instance_id, endpoints, now, case=case)
        )
        active_resources = [r for r in resources if r.state == "active"]
        # Anything not yet 'released' still needs a delete driven; 'releasing'
        # resources are included so a dead-lettered delete gets retried.
        unreleased_resources = [
            r for r in resources if r.state in ("active", "releasing")
        ]
        if unreleased_resources:
            actions.append(
                self._enqueue(
                    instance, instance.generation, "delete", now, case=case
                )
            )
        if active_resources:
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

    def is_adverse(self, worker_name: str, now: datetime) -> bool:
        """A GENUINE adverse condition -- the worker is gone, untrusted,
        quarantined, or draining -- DELIBERATELY excluding mere heartbeat
        staleness (a fresh-but-lapsed heartbeat on a worker still serving a
        healthy instance must not, on its own, trigger a teardown)."""
        with self._database.session_scope() as session:
            worker = self._registry(session).get(worker_name)
        if worker is None:
            return True
        if worker.trust_state != "trusted":
            return True
        return (
            worker.quarantined_at is not None
            or worker.drain_requested_at is not None
        )
