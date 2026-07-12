"""Placement + capacity reservation service (application layer, M8).

``SchedulingService`` owns the multi-aggregate transactions via
``Database.session_scope()`` (repositories flush; the UoW commits once). It ties
the capability-aware scheduler to the atomic quota ledger:

* ``select_and_reserve`` -- pick a dispatch-eligible worker and, in one
  transaction, reserve the shared pools (platform/competition/team/challenge)
  *and* one unit of the worker's ``active_instances`` counter. Worker
  concurrency is modeled as a ``(worker, active_instances)`` quota row (limit =
  worker capacity, upserted lazily), so overcommit protection and capacity
  scheduling ride the one race-safe primitive. A *full worker* (its counter is
  saturated) makes the loop retry the next candidate; a *shared-pool overrun*
  propagates (no worker will help); no eligible candidate raises
  ``NoEligibleWorkerError``. A duplicate ``reservation_id`` (a re-launch of the
  same instance) collapses idempotently to the existing reservation.
* ``ensure_worker_capacity_quota`` -- lazily seed a worker's capacity quota so
  ``worker_enrollment`` stays untouched.
* ``release`` / ``release_expired`` -- return capacity; sweep leaked holds.
* ``reconcile_counters`` -- self-heal counter drift.

Because the shared pools sort before the ``worker`` scope, the ledger checks
them first: a shared overrun is raised before the worker counter is even
touched, which is what lets the service distinguish the two failure modes by the
exception's ``scope_type``.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ctf_generator.domain.repositories import (
    QuotaLedger,
    QuotaPolicyRepository,
    SchedulerRepository,
)
from ctf_generator.domain.scheduling.models import (
    CeilingRequirement,
    NoEligibleWorkerError,
    QuotaExceededError,
    QuotaReservation,
    ReservationItem,
    ResourceDemand,
    ResourceQuota,
    WorkerCandidate,
    WorkerRequirements,
)
from ctf_generator.infrastructure.database.quota_repository import (
    SqlAlchemyQuotaLedger,
    SqlAlchemyQuotaPolicyRepository,
)
from ctf_generator.infrastructure.database.scheduler_repository import (
    SqlAlchemyScheduler,
)
from ctf_generator.infrastructure.database.session import Database

_WORKER_SCOPE = "worker"
_ACTIVE_INSTANCES = "active_instances"

# Default liveness window: a worker whose last heartbeat is older than this is
# not dispatch-eligible (the M7 "heartbeat fresh" conjunct, now enforced).
DEFAULT_HEARTBEAT_MAX_AGE_SECONDS = 60


class SchedulingService:
    """Capability-aware placement with atomic, race-safe capacity reservation."""

    def __init__(
        self,
        database: Database,
        *,
        scheduler_factory: Callable[[Session], SchedulerRepository] = SqlAlchemyScheduler,
        ledger_factory: Callable[[Session], QuotaLedger] = SqlAlchemyQuotaLedger,
        policy_factory: Callable[
            [Session], QuotaPolicyRepository
        ] = SqlAlchemyQuotaPolicyRepository,
    ) -> None:
        self._database = database
        self._scheduler_factory = scheduler_factory
        self._ledger_factory = ledger_factory
        self._policy_factory = policy_factory

    # -- capacity seeding -----------------------------------------------------

    def ensure_worker_capacity_quota(self, worker_name: str, capacity: int) -> None:
        """Lazily seed the ``(worker, active_instances)`` quota with
        ``limit = capacity`` (idempotent; never overwrites the live counter)."""
        with self._database.session_scope() as session:
            self._policy_factory(session).upsert_limit(
                ResourceQuota(
                    scope_type=_WORKER_SCOPE,
                    scope_key=worker_name,
                    dimension=_ACTIVE_INSTANCES,
                    limit_value=capacity,
                )
            )

    # -- placement + reservation ---------------------------------------------

    def list_candidates(
        self,
        requirements: WorkerRequirements,
        now: datetime,
        *,
        heartbeat_max_age_seconds: int = DEFAULT_HEARTBEAT_MAX_AGE_SECONDS,
        image_ref: str | None = None,
        limit: int = 20,
    ) -> list[WorkerCandidate]:
        with self._database.session_scope() as session:
            return self._scheduler_factory(session).candidate_workers(
                requirements, now, heartbeat_max_age_seconds, image_ref, limit
            )

    def select_and_reserve(
        self,
        *,
        requirements: WorkerRequirements,
        reservation_id: str,
        pooled_items: tuple[ReservationItem, ...],
        expires_at: datetime,
        now: datetime,
        worker_units: int = 1,
        ceilings: tuple[CeilingRequirement, ...] = (),
        competition_key: str | None = None,
        team_key: str | None = None,
        challenge_key: str | None = None,
        image_ref: str | None = None,
        heartbeat_max_age_seconds: int = DEFAULT_HEARTBEAT_MAX_AGE_SECONDS,
        candidate_limit: int = 20,
    ) -> tuple[QuotaReservation, str]:
        """Place and reserve one instance. Returns ``(reservation, worker_name)``.

        Raises :class:`NoEligibleWorkerError` when no dispatch-eligible worker
        has both a capability match and free capacity, and
        :class:`~ctf_generator.domain.scheduling.models.QuotaExceededError` when
        a *shared* pool is saturated (no worker choice can help).
        """
        # A prior successful reserve for this instance id -> idempotent replay.
        existing = self.get_reservation(reservation_id)
        if existing is not None:
            return existing, existing.worker_key

        candidates = self.list_candidates(
            requirements,
            now,
            heartbeat_max_age_seconds=heartbeat_max_age_seconds,
            image_ref=image_ref,
            limit=candidate_limit,
        )
        if not candidates:
            raise NoEligibleWorkerError(
                "no dispatch-eligible worker matches "
                f"architecture={requirements.architecture!r}, "
                f"capabilities={sorted(requirements.required_capabilities)!r}"
            )

        for candidate in candidates:
            worker_item = ReservationItem(
                scope_type=_WORKER_SCOPE,
                scope_key=candidate.worker_name,
                dimension=_ACTIVE_INSTANCES,
                amount=worker_units,
            )
            demand = ResourceDemand(
                reservation_id=reservation_id,
                worker_key=candidate.worker_name,
                expires_at=expires_at,
                items=(*pooled_items, worker_item),
                ceilings=ceilings,
                competition_key=competition_key,
                team_key=team_key,
                challenge_key=challenge_key,
            )
            try:
                with self._database.session_scope() as session:
                    # Seed the worker capacity quota in the same tx so the
                    # reserve below has a counter to lock.
                    self._policy_factory(session).upsert_limit(
                        ResourceQuota(
                            scope_type=_WORKER_SCOPE,
                            scope_key=candidate.worker_name,
                            dimension=_ACTIVE_INSTANCES,
                            limit_value=candidate.capacity,
                        )
                    )
                    reservation = self._ledger_factory(session).reserve(demand, now)
                return reservation, candidate.worker_name
            except QuotaExceededError as exc:
                # A saturated *worker* -> try the next candidate. Any other scope
                # is a shared-pool overrun that no candidate can resolve.
                if exc.scope_type == _WORKER_SCOPE:
                    continue
                raise
            except IntegrityError:
                # A racing re-launch won the reservation_id first -> idempotent.
                collapsed = self.get_reservation(reservation_id)
                if collapsed is None:  # pragma: no cover - the rival rolled back
                    raise
                return collapsed, collapsed.worker_key

        raise NoEligibleWorkerError(
            "every dispatch-eligible worker is at capacity for "
            f"architecture={requirements.architecture!r}"
        )

    # -- release / maintenance ------------------------------------------------

    def release(self, reservation_id: str, now: datetime) -> bool:
        with self._database.session_scope() as session:
            return self._ledger_factory(session).release(reservation_id, now)

    def release_expired(self, now: datetime, limit: int = 100) -> list[str]:
        """Release every held reservation whose TTL has elapsed. Returns the
        released reservation ids. Each release is its own transaction, so a
        large sweep never holds one giant lock."""
        with self._database.session_scope() as session:
            expired = self._ledger_factory(session).list_expired(now, limit)
        released: list[str] = []
        for reservation in expired:
            if self.release(reservation.reservation_id, now):
                released.append(reservation.reservation_id)
        return released

    def get_reservation(self, reservation_id: str) -> QuotaReservation | None:
        with self._database.session_scope() as session:
            return self._ledger_factory(session).get(reservation_id)

    def reconcile_counters(self) -> int:
        with self._database.session_scope() as session:
            return self._ledger_factory(session).reconcile_counters()
