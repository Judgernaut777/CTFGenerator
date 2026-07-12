"""Instance-lifecycle application service (M8 slice 1b).

``InstanceLifecycleService`` orchestrates the instance's life across three
collaborators, each owning its own unit of work:

* the :class:`~...infrastructure.database.instance_repository.SqlAlchemyInstanceRepository`
  (the guarded state machine + append-only audit),
* the :class:`~..scheduling.service.SchedulingService` (capacity reservation,
  keyed ``reservation_id == instance_id`` so a relaunch reuses the hold), and
* the :class:`~..jobs.service.JobService` (idempotent corrective enqueue).

The reservation lifecycle rides the instance lifecycle: ``request_instance``
reserves; a live instance's hold is kept alive with :meth:`renew_lease`; and the
hold is released the moment the instance reaches ``stopped`` / ``expired`` /
``archived``. Every corrective enqueue is keyed ``(instance_id, generation,
action)`` so duplicates collapse.

The control plane never runs a container: this module imports no Docker/
subprocess and executes no challenge code; it persists desired state and
enqueues jobs a worker claims with scoped credentials in slice 2. Payloads,
image refs, and instance seeds are references only -- never a flag or a secret.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime

from sqlalchemy.orm import Session

from ctf_generator.domain.instances.models import (
    HealthObservation,
    Instance,
    InstanceCredential,
    InstanceEndpoint,
    RuntimeResource,
)
from ctf_generator.domain.repositories import InstanceRepository
from ctf_generator.domain.scheduling.models import (
    CeilingRequirement,
    ReservationItem,
    WorkerRequirements,
)
from ctf_generator.infrastructure.database.instance_repository import (
    SqlAlchemyInstanceRepository,
)
from ctf_generator.infrastructure.database.session import Database

from ..jobs.service import JobService
from ..scheduling.service import SchedulingService
from .corrective import build_corrective_job

# States at which a live instance no longer needs its capacity hold -- the hold
# is released the instant the instance reaches one of these.
_RELEASE_STATES = frozenset({"stopped", "expired", "archived"})


class InstanceLifecycleService:
    """Desired-state-driven instance lifecycle with generation-fenced,
    idempotent corrective work and reservation-coupled capacity."""

    def __init__(
        self,
        database: Database,
        *,
        scheduling: SchedulingService,
        jobs: JobService,
        repository_factory: Callable[
            [Session], InstanceRepository
        ] = SqlAlchemyInstanceRepository,
    ) -> None:
        self._database = database
        self._scheduling = scheduling
        self._jobs = jobs
        self._repo = repository_factory

    # -- creation + placement ------------------------------------------------

    def request_instance(
        self,
        *,
        instance_id: str,
        competition_id: str,
        team_name: str,
        definition_slug: str,
        version_no: int,
        requirements: WorkerRequirements,
        pooled_items: tuple[ReservationItem, ...],
        expires_at: datetime,
        now: datetime,
        image_ref: str | None = None,
        instance_seed: str | None = None,
        worker_units: int = 1,
        ceilings: tuple[CeilingRequirement, ...] = (),
        competition_key: str | None = None,
        team_key: str | None = None,
        challenge_key: str | None = None,
        scheduling_image_ref: str | None = None,
    ) -> Instance:
        """Create the instance in ``requested``, reserve capacity (keyed by
        ``instance_id``), place it on a worker, move it to ``queued``, and
        enqueue the launch job idempotently keyed ``(instance_id, 1, 'launch')``.

        A reservation failure (:class:`NoEligibleWorkerError` /
        :class:`QuotaExceededError`) propagates with the instance left in
        ``requested`` (an operator/retry can act on it later); the launch job is
        enqueued only after a successful placement.
        """
        instance = Instance(
            instance_id=instance_id,
            competition_id=competition_id,
            team_name=team_name,
            definition_slug=definition_slug,
            version_no=version_no,
            state="requested",
            desired_state="active",
            image_ref=image_ref,
            instance_seed=instance_seed,
            expires_at=expires_at,
        )
        with self._database.session_scope() as session:
            self._repo(session).add(instance, now)

        # Reserve + place. Any failure leaves the instance in 'requested'.
        _reservation, worker_name = self._scheduling.select_and_reserve(
            requirements=requirements,
            reservation_id=instance_id,
            pooled_items=pooled_items,
            expires_at=expires_at,
            now=now,
            worker_units=worker_units,
            ceilings=ceilings,
            competition_key=competition_key,
            team_key=team_key,
            challenge_key=challenge_key,
            image_ref=scheduling_image_ref,
        )

        with self._database.session_scope() as session:
            repo = self._repo(session)
            repo.set_assignment(instance_id, worker_name, now)
            placed = repo.transition(
                instance_id,
                "queued",
                reason="placed and enqueued for launch",
                actor="system",
                now=now,
            )

        self._jobs.enqueue_idempotent(
            build_corrective_job(placed, placed.generation, "launch", now), now
        )
        return placed

    # -- transitions ---------------------------------------------------------

    def apply_transition(
        self,
        instance_id: str,
        to_state: str,
        *,
        reason: str,
        actor: str,
        now: datetime,
    ) -> Instance:
        """Apply a guarded state transition. A transition to the CURRENT state is
        an idempotent no-op (re-applying the same transition never errors). On
        reaching ``stopped`` / ``expired`` / ``archived`` the capacity hold is
        released."""
        with self._database.session_scope() as session:
            repo = self._repo(session)
            current = repo.get(instance_id)
            if current is None:
                raise LookupError(f"instance not found: {instance_id!r}")
            if current.state == to_state:
                return current
            updated = repo.transition(
                instance_id, to_state, reason=reason, actor=actor, now=now
            )
        if to_state in _RELEASE_STATES:
            self._scheduling.release(instance_id, now)
        return updated

    # -- desired-state intents -----------------------------------------------

    def request_stop(self, instance_id: str, now: datetime) -> Instance:
        """Mark the instance ``desired_state = stopped`` and enqueue the stop job
        (idempotent). The observed transition to ``stopped`` is driven by the
        worker's report + the reconciler."""
        with self._database.session_scope() as session:
            instance = self._repo(session).set_desired_state(
                instance_id, "stopped", now
            )
        self._jobs.enqueue_idempotent(
            build_corrective_job(instance, instance.generation, "stop", now), now
        )
        return instance

    def request_reset(
        self,
        instance_id: str,
        new_expires_at: datetime,
        now: datetime,
        *,
        requirements: WorkerRequirements | None = None,
        pooled_items: tuple[ReservationItem, ...] = (),
    ) -> Instance:
        """Bump the fencing generation (so stale observations are ignored),
        re-establish the capacity hold for the new lifetime, and enqueue the
        relaunch keyed on the NEW generation.

        The corrective action is the SAME ``launch`` the reconciler's
        missing-container path would enqueue (keyed ``(instance, new_generation)``)
        so a reset and a concurrent reconciler pass collapse idempotently onto one
        job instead of racing a ``reset`` job against a ``launch`` job.
        """
        with self._database.session_scope() as session:
            instance = self._repo(session).bump_generation(instance_id, now)
        # Keep or re-establish the hold BEFORE the relaunch, so a reset of a
        # stopped / expiry-swept instance never relaunches with no quota
        # accounting. renew keeps a still-*held* reservation; a *released* header
        # is re-held in place; the LookupError is handled, never swallowed.
        try:
            self._scheduling.renew(instance_id, new_expires_at, now)
        except LookupError:
            reservation = self._scheduling.get_reservation(instance_id)
            if reservation is not None:
                # A released header exists -> re-hold it on the original placement.
                self._scheduling.reactivate(instance_id, new_expires_at, now)
            elif requirements is not None:
                # No reservation ever existed -> place + reserve afresh.
                self._scheduling.select_and_reserve(
                    requirements=requirements,
                    reservation_id=instance_id,
                    pooled_items=pooled_items,
                    expires_at=new_expires_at,
                    now=now,
                )
            # else: the instance was never reserved and the caller supplied no
            # placement inputs -> there is no hold to account for.
        self._jobs.enqueue_idempotent(
            build_corrective_job(instance, instance.generation, "launch", now), now
        )
        return instance

    def request_delete(self, instance_id: str, now: datetime) -> Instance:
        """Mark the instance ``desired_state = deleted``. The reconciler drives
        stop + resource/endpoint cleanup + archival (and releases the hold on
        archival).

        An already-``archived`` (terminal) instance is a clean idempotent no-op:
        the delete goal is already met, and the row is frozen -- writing
        ``desired_state`` to it would trip the archived-freeze guard and raise a
        raw ``ProgrammingError``. Mirrors :meth:`expire`'s already-``expired``
        no-op so a repeated / racing delete never errors."""
        with self._database.session_scope() as session:
            repo = self._repo(session)
            current = repo.get(instance_id)
            if current is None:
                raise LookupError(f"instance not found: {instance_id!r}")
            if current.is_terminal:
                return current
            return repo.set_desired_state(instance_id, "deleted", now)

    def expire(self, instance_id: str, now: datetime) -> Instance:
        """TTL expiry: move the instance to ``expired`` and, ONLY when that
        transition actually happens, release the capacity hold and enqueue the
        expire job (idempotent). Already-``expired`` is an idempotent no-op (the
        hold was released on the first expiry). A state from which ``expired`` is
        illegal is surfaced (``ValueError``) rather than silently releasing the
        hold and enqueuing a corrective for a transition that never occurred."""
        with self._database.session_scope() as session:
            repo = self._repo(session)
            current = repo.get(instance_id)
            if current is None:
                raise LookupError(f"instance not found: {instance_id!r}")
            if current.state == "expired":
                return current
            if not current.can_transition_to("expired"):
                raise ValueError(
                    f"cannot expire instance {instance_id!r} in state "
                    f"{current.state!r} ('expired' is not a legal transition)"
                )
            current = repo.transition(
                instance_id,
                "expired",
                reason="ttl expired",
                actor="system",
                now=now,
            )
        self._scheduling.release(instance_id, now)
        self._jobs.enqueue_idempotent(
            build_corrective_job(current, current.generation, "expire", now), now
        )
        return current

    def renew_lease(
        self, instance_id: str, new_expires_at: datetime, now: datetime
    ) -> Instance:
        """Extend a live instance's capacity hold (so the leaked-hold sweep never
        reclaims it) and record the new TTL on the instance."""
        self._scheduling.renew(instance_id, new_expires_at, now)
        with self._database.session_scope() as session:
            return self._repo(session).set_runtime_facts(
                instance_id, now, expires_at=new_expires_at
            )

    # -- worker-reported facts -----------------------------------------------

    def record_observation(
        self, observation: HealthObservation
    ) -> HealthObservation:
        """Append a worker health observation (append-only). Generation-gating is
        applied by the reconciler, not here."""
        with self._database.session_scope() as session:
            return self._repo(session).append_observation(observation)

    def record_endpoint(self, endpoint: InstanceEndpoint) -> None:
        with self._database.session_scope() as session:
            self._repo(session).record_endpoint(endpoint)

    def record_runtime_resource(self, resource: RuntimeResource) -> None:
        with self._database.session_scope() as session:
            self._repo(session).record_runtime_resource(resource)

    def record_credential(self, credential: InstanceCredential) -> None:
        with self._database.session_scope() as session:
            self._repo(session).record_credential(credential)

    def set_assignment(
        self, instance_id: str, assigned_worker: str | None, now: datetime
    ) -> Instance:
        """Record (or clear) an instance's placement on a worker. Used by the
        slice-2 launch-contract re-placement: after a worker re-reserves an
        unassigned instance it records the fresh assignment before starting."""
        with self._database.session_scope() as session:
            return self._repo(session).set_assignment(instance_id, assigned_worker, now)

    # -- reads ---------------------------------------------------------------

    def get(self, instance_id: str) -> Instance | None:
        with self._database.session_scope() as session:
            return self._repo(session).get(instance_id)
