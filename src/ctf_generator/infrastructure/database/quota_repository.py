"""Concrete SQLAlchemy quota policy + reservation ledger (M8).

``SqlAlchemyQuotaPolicyRepository`` sets and reads quota *limits*.
``SqlAlchemyQuotaLedger`` performs the atomic reserve/release over the
``resource_quotas`` counters + ``quota_reservations`` headers +
``quota_reservation_items`` append-only detail.

The race-safety primitive is a per-counter ``SELECT ... FOR UPDATE`` taken in a
deterministic ``(scope_type, scope_key, dimension)`` order (so concurrent
reserves serialize on a shared pool row and never deadlock). If any counter
would exceed its limit -- or any ceiling exceeds its cap -- the method raises
``QuotaExceededError`` and touches nothing further; the caller's
``Database.session_scope()`` rolls the whole reservation back, so there is never
a partial increment. A duplicate ``reservation_id`` surfaces as ``IntegrityError``
at the header insert (the idempotent re-launch guard).

Both take the caller's Session; FLUSH only, never commit/rollback. Domain
objects only ever cross the boundary.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ctf_generator.domain.scheduling.models import (
    CEILING_DIMENSIONS,
    QuotaExceededError,
    QuotaReservation,
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
    resource_quota_to_orm,
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
        """Create the quota row or update only its ``limit_value``. A limit
        reduction leaves ``reserved_value`` untouched (holds grandfathered)."""
        existing = self._row(quota.scope_type, quota.scope_key, quota.dimension)
        if existing is None:
            self._session.add(resource_quota_to_orm(quota))
        else:
            resource_quota_to_orm(quota, existing=existing)
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

    def reserve(self, demand: ResourceDemand, now: datetime) -> QuotaReservation:
        # Insert the header first so a duplicate reservation_id fails fast at
        # flush (the idempotent re-launch guard) before any counter is touched.
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

        # Ceiling checks: a static cap, compared but never counted.
        for ceiling in demand.ceilings:
            quota = self._locked_quota(
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

        # Pooled counters, locked and incremented in deterministic order.
        for item in demand.sorted_items():
            quota = self._locked_quota(item.scope_type, item.scope_key, item.dimension)
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
            self._session.add(
                reservation_item_to_orm(item, header_row.reservation_id)
            )
        self._session.flush()
        self._session.refresh(header_row, ["created_at"])
        return quota_reservation_from_orm(header_row, items=demand.items)

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
        (self-healing drift repair). Locks every quota row, so it never races a
        concurrent reserve/release on the same counter."""
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
        rows = self._session.scalars(
            select(ResourceQuotaRow).with_for_update()
        ).all()
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
