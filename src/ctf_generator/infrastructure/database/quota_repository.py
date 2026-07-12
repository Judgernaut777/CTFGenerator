"""Concrete SQLAlchemy quota policy + reservation ledger (M8).

``SqlAlchemyQuotaPolicyRepository`` sets and reads quota *limits*.
``SqlAlchemyQuotaLedger`` performs the atomic reserve/release over the
``resource_quotas`` counters + ``quota_reservations`` headers +
``quota_reservation_items`` append-only detail.

The race-safety primitive is a per-*pooled-counter* ``SELECT ... FOR UPDATE``
taken in a deterministic ``(scope_type, scope_key, dimension)`` order (so
concurrent reserves serialize on a shared pool row and never deadlock). Ceilings
are read with a *plain* ``SELECT`` -- they are static caps that are never
counted, so they need no lock; locking them would add an out-of-order lock and a
deadlock hazard for nothing. If any counter would exceed its limit -- or any
ceiling exceeds its cap -- the method raises ``QuotaExceededError`` and touches
nothing further; the caller's ``Database.session_scope()`` rolls the whole
reservation back, so there is never a partial increment. A brand-new reservation
inserts its header first, so a duplicate ``reservation_id`` surfaces as
``IntegrityError`` at that insert (the idempotent re-launch guard). A
``reservation_id`` whose prior reservation was *released* is re-holdable via
``reactivate`` (a relaunch of the same instance transparently re-reserves its
original placement).

Both take the caller's Session; FLUSH only, never commit/rollback. Domain
objects only ever cross the boundary.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from ctf_generator.domain.scheduling.models import (
    CEILING_DIMENSIONS,
    QuotaExceededError,
    QuotaReservation,
    ReservationItem,
    ResourceDemand,
    ResourceQuota,
)

from .mappers import (
    _as_uuid,
    quota_reservation_from_orm,
    quota_reservation_to_orm,
    reservation_item_from_orm,
    reservation_item_to_orm,
    resource_quota_from_orm,
    to_utc,
)
from .models import QuotaReservation as QuotaReservationRow
from .models import QuotaReservationItem as QuotaReservationItemRow
from .models import ResourceQuota as ResourceQuotaRow


class SqlAlchemyQuotaPolicyRepository:
    """Quota *limits*, keyed by ``(scope_type, scope_key, dimension)``. Never
    writes the live ``reserved_value`` counter (that is the ledger's)."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def _row(
        self, scope_type: str, scope_key: str, dimension: str
    ) -> ResourceQuotaRow | None:
        return self._session.scalars(
            select(ResourceQuotaRow).where(
                ResourceQuotaRow.scope_type == scope_type,
                ResourceQuotaRow.scope_key == scope_key,
                ResourceQuotaRow.dimension == dimension,
            )
        ).one_or_none()

    def upsert_limit(self, quota: ResourceQuota) -> None:
        """Seed the quota row *if absent*; never overwrite an existing limit.

        Race-safe and idempotent via ``INSERT ... ON CONFLICT DO NOTHING`` on the
        ``(scope_type, scope_key, dimension)`` unique key: two concurrent
        first-time seeds both no-op rather than one raising a unique violation
        (the cold-start seed race). An existing row is left untouched -- so a
        seed derived from a *stale* candidate snapshot can never clobber an
        operator-set limit, and the live ``reserved_value`` counter (owned by the
        ledger) is never written here."""
        stmt = (
            pg_insert(ResourceQuotaRow)
            .values(
                id=uuid.uuid4(),
                scope_type=quota.scope_type,
                scope_key=quota.scope_key,
                dimension=quota.dimension,
                limit_value=quota.limit_value,
                reserved_value=quota.reserved_value,
            )
            .on_conflict_do_nothing(
                index_elements=["scope_type", "scope_key", "dimension"]
            )
        )
        self._session.execute(stmt)
        self._session.flush()

    def get(
        self, scope_type: str, scope_key: str, dimension: str
    ) -> ResourceQuota | None:
        row = self._row(scope_type, scope_key, dimension)
        return resource_quota_from_orm(row) if row is not None else None

    def list_for_scope(
        self, scope_type: str, scope_key: str
    ) -> list[ResourceQuota]:
        rows = self._session.scalars(
            select(ResourceQuotaRow)
            .where(
                ResourceQuotaRow.scope_type == scope_type,
                ResourceQuotaRow.scope_key == scope_key,
            )
            .order_by(ResourceQuotaRow.dimension)
        ).all()
        return [resource_quota_from_orm(row) for row in rows]


class SqlAlchemyQuotaLedger:
    """Atomic reserve/release over the quota counters + reservation ledger."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def _locked_quota(
        self, scope_type: str, scope_key: str, dimension: str
    ) -> ResourceQuotaRow | None:
        return self._session.scalars(
            select(ResourceQuotaRow)
            .where(
                ResourceQuotaRow.scope_type == scope_type,
                ResourceQuotaRow.scope_key == scope_key,
                ResourceQuotaRow.dimension == dimension,
            )
            .with_for_update()
        ).one_or_none()

    def _plain_quota(
        self, scope_type: str, scope_key: str, dimension: str
    ) -> ResourceQuotaRow | None:
        """A read-only lookup (NO ``FOR UPDATE``). Used for ceilings, which are
        static caps that are never counted, so they need no row lock -- taking
        one would introduce an out-of-order lock and a deadlock hazard."""
        return self._session.scalars(
            select(ResourceQuotaRow).where(
                ResourceQuotaRow.scope_type == scope_type,
                ResourceQuotaRow.scope_key == scope_key,
                ResourceQuotaRow.dimension == dimension,
            )
        ).one_or_none()

    def _items_for(self, reservation_uuid) -> list[QuotaReservationItemRow]:
        return list(
            self._session.scalars(
                select(QuotaReservationItemRow)
                .where(QuotaReservationItemRow.reservation_id == reservation_uuid)
                .order_by(
                    QuotaReservationItemRow.scope_type,
                    QuotaReservationItemRow.scope_key,
                    QuotaReservationItemRow.dimension,
                )
            ).all()
        )

    def _check_ceilings(self, demand: ResourceDemand) -> None:
        """Validate every scalar ceiling with a plain read (never counted)."""
        for ceiling in demand.ceilings:
            quota = self._plain_quota(
                ceiling.scope_type, ceiling.scope_key, ceiling.dimension
            )
            if quota is None:
                raise LookupError(
                    "no quota configured for ceiling "
                    f"({ceiling.scope_type!r}, {ceiling.scope_key!r}, "
                    f"{ceiling.dimension!r})"
                )
            if ceiling.required_value > quota.limit_value:
                raise QuotaExceededError(
                    f"ceiling {ceiling.dimension!r} for "
                    f"({ceiling.scope_type}, {ceiling.scope_key}): required "
                    f"{ceiling.required_value} exceeds cap {quota.limit_value}",
                    scope_type=ceiling.scope_type,
                    scope_key=ceiling.scope_key,
                    dimension=ceiling.dimension,
                )

    def _hold_items(
        self,
        items: tuple[ReservationItem, ...],
        reservation_uuid: uuid.UUID,
        *,
        insert_items: bool,
    ) -> None:
        """Lock each pooled counter ``FOR UPDATE`` in the caller-provided (already
        sorted) order and increment it, aborting the whole unit of work with
        ``QuotaExceededError`` if any would exceed its limit. When
        ``insert_items`` is True the append-only reservation item is written too
        (a brand-new reserve); a reactivation re-increments the *existing*
        immutable items and writes none."""
        for item in items:
            quota = self._locked_quota(
                item.scope_type, item.scope_key, item.dimension
            )
            if quota is None:
                raise LookupError(
                    "no quota configured for "
                    f"({item.scope_type!r}, {item.scope_key!r}, {item.dimension!r})"
                )
            if quota.reserved_value + item.amount > quota.limit_value:
                raise QuotaExceededError(
                    f"pool {item.dimension!r} for ({item.scope_type}, "
                    f"{item.scope_key}): reserving {item.amount} over "
                    f"{quota.reserved_value}/{quota.limit_value} would exceed the limit",
                    scope_type=item.scope_type,
                    scope_key=item.scope_key,
                    dimension=item.dimension,
                )
            quota.reserved_value = quota.reserved_value + item.amount
            if insert_items:
                self._session.add(reservation_item_to_orm(item, reservation_uuid))

    def reserve(self, demand: ResourceDemand, now: datetime) -> QuotaReservation:
        # Insert the header first so a duplicate reservation_id fails fast at
        # flush (the idempotent re-launch guard) before any counter is touched.
        # A *released* header being reused is re-held via ``reactivate`` (the
        # caller detects that case); here we only ever create a fresh hold.
        header = QuotaReservation(
            reservation_id=demand.reservation_id,
            worker_key=demand.worker_key,
            expires_at=demand.expires_at,
            state="held",
            competition_key=demand.competition_key,
            team_key=demand.team_key,
            challenge_key=demand.challenge_key,
        )
        header_row = quota_reservation_to_orm(header)
        self._session.add(header_row)
        self._session.flush()  # duplicate reservation_id -> IntegrityError here

        # Ceilings are static caps: read (never locked), compared, never counted.
        self._check_ceilings(demand)
        # Pooled counters: locked FOR UPDATE and incremented in deterministic
        # order, writing one append-only item per counter.
        self._hold_items(
            demand.sorted_items(), header_row.reservation_id, insert_items=True
        )
        self._session.flush()
        self._session.refresh(header_row, ["created_at"])
        return quota_reservation_from_orm(header_row, items=demand.items)

    def reactivate(
        self, reservation_id: str, new_expires_at: datetime, now: datetime
    ) -> QuotaReservation:
        """Re-hold a *released* reservation in place (a relaunch of the same
        instance id transparently re-reserves its original placement).

        Flips ``released -> held`` under a ``FOR UPDATE`` lock on the header,
        clears ``released_at``, extends the TTL to ``new_expires_at``, and
        re-increments the counters for the reservation's *original* append-only
        items (which are never rewritten). Idempotent: an already-``held``
        reservation is returned unchanged (a racing reactivation collapsed
        first). ``LookupError`` if the reservation does not exist;
        ``QuotaExceededError`` if a counter (e.g. the original worker, now at
        capacity) cannot re-admit the hold."""
        key = _as_uuid(reservation_id)
        header = self._session.scalars(
            select(QuotaReservationRow)
            .where(QuotaReservationRow.reservation_id == key)
            .with_for_update()
        ).one_or_none()
        if header is None:
            raise LookupError(f"no reservation {reservation_id!r} to reactivate")
        items = tuple(
            reservation_item_from_orm(row) for row in self._items_for(key)
        )
        if header.state == "held":
            return quota_reservation_from_orm(header, items=items)
        header.state = "held"
        header.released_at = None
        header.expires_at = to_utc(new_expires_at)
        self._session.flush()
        # Re-increment the original (already-sorted) items; write no new items.
        self._hold_items(items, key, insert_items=False)
        self._session.flush()
        return quota_reservation_from_orm(header, items=items)

    def renew(
        self, reservation_id: str, new_expires_at: datetime, now: datetime
    ) -> None:
        """Extend a *held* reservation's TTL to ``new_expires_at`` under a
        ``FOR UPDATE`` lock. The instance-lifecycle owner calls this to keep a
        still-running instance's hold alive so ``release_expired`` (a safety
        sweep for abandoned holds) never reclaims capacity out from under it.
        ``LookupError`` if the reservation is missing or already released."""
        try:
            key = _as_uuid(reservation_id)
        except (ValueError, AttributeError, TypeError) as exc:
            raise LookupError(
                f"malformed reservation id {reservation_id!r}"
            ) from exc
        header = self._session.scalars(
            select(QuotaReservationRow)
            .where(QuotaReservationRow.reservation_id == key)
            .with_for_update()
        ).one_or_none()
        if header is None or header.state != "held":
            raise LookupError(
                f"no held reservation {reservation_id!r} to renew"
            )
        header.expires_at = to_utc(new_expires_at)
        self._session.flush()

    def release(self, reservation_id: str, now: datetime) -> bool:
        try:
            key = _as_uuid(reservation_id)
        except (ValueError, AttributeError, TypeError):
            return False  # malformed id is a clean no-op release
        header = self._session.scalars(
            select(QuotaReservationRow)
            .where(QuotaReservationRow.reservation_id == key)
            .with_for_update()
        ).one_or_none()
        if header is None or header.state != "held":
            return False  # absent or already released -> idempotent no-op
        for item in self._items_for(key):
            quota = self._locked_quota(item.scope_type, item.scope_key, item.dimension)
            if quota is None:  # pragma: no cover - composite FK guarantees it exists
                continue
            quota.reserved_value = max(quota.reserved_value - item.amount, 0)
        header.state = "released"
        header.released_at = to_utc(now)
        self._session.flush()
        return True

    def get(self, reservation_id: str) -> QuotaReservation | None:
        try:
            key = _as_uuid(reservation_id)
        except (ValueError, AttributeError, TypeError):
            return None
        header = self._session.scalars(
            select(QuotaReservationRow).where(
                QuotaReservationRow.reservation_id == key
            )
        ).one_or_none()
        if header is None:
            return None
        items = tuple(reservation_item_from_orm(row) for row in self._items_for(key))
        return quota_reservation_from_orm(header, items=items)

    def list_expired(
        self, now: datetime, limit: int = 100
    ) -> list[QuotaReservation]:
        rows = self._session.scalars(
            select(QuotaReservationRow)
            .where(
                QuotaReservationRow.state == "held",
                QuotaReservationRow.expires_at < to_utc(now),
            )
            .order_by(QuotaReservationRow.expires_at.asc())
            .limit(limit)
        ).all()
        return [quota_reservation_from_orm(row) for row in rows]

    def reconcile_counters(self) -> int:
        """Recompute every quota's ``reserved_value`` from the held items
        (self-healing drift repair). Takes the quota-row ``FOR UPDATE`` locks
        FIRST (in the deterministic ``(scope_type, scope_key, dimension)`` order
        every reserve uses), THEN sums the held items under those locks -- so a
        reserve committing during the sweep is either already counted or blocked
        behind the lock, never overwritten (a lock-then-compute ordering would
        re-introduce the drift it is meant to heal)."""
        rows = self._session.scalars(
            select(ResourceQuotaRow)
            .order_by(
                ResourceQuotaRow.scope_type,
                ResourceQuotaRow.scope_key,
                ResourceQuotaRow.dimension,
            )
            .with_for_update()
        ).all()
        held_sums = {
            (scope_type, scope_key, dimension): total
            for scope_type, scope_key, dimension, total in self._session.execute(
                select(
                    QuotaReservationItemRow.scope_type,
                    QuotaReservationItemRow.scope_key,
                    QuotaReservationItemRow.dimension,
                    func.sum(QuotaReservationItemRow.amount),
                )
                .join(
                    QuotaReservationRow,
                    QuotaReservationRow.reservation_id
                    == QuotaReservationItemRow.reservation_id,
                )
                .where(QuotaReservationRow.state == "held")
                .group_by(
                    QuotaReservationItemRow.scope_type,
                    QuotaReservationItemRow.scope_key,
                    QuotaReservationItemRow.dimension,
                )
            ).all()
        }
        changed = 0
        for row in rows:
            if row.dimension in CEILING_DIMENSIONS:
                expected = 0
            else:
                expected = int(
                    held_sums.get((row.scope_type, row.scope_key, row.dimension), 0)
                )
            if row.reserved_value != expected:
                row.reserved_value = expected
                changed += 1
        self._session.flush()
        return changed
