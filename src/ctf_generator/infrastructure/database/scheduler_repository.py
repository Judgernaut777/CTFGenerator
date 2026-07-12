"""Concrete SQLAlchemy scheduler read-side (M8).

``SqlAlchemyScheduler`` implements the domain ``SchedulerRepository``: it returns
dispatch-eligible workers that satisfy an instance's requirements, ranked for
placement. Dispatch eligibility is the conjunction the M7 partial index encodes
plus liveness -- ``trusted`` AND not quarantined AND ``drain_requested_at`` null
(finally enforcing that dead M7 state) AND a fresh heartbeat. Capacity comes
from the worker's ``(worker, active_instances)`` quota row (limit = capacity,
reserved = live in-flight count), so scheduling and quota accounting share one
race-safe counter. Image-cache affinity is a LEFT JOIN (ranking only, never a
gate), so its emptiness in slice 1 never changes correctness.

Takes the caller's Session; read-only; returns domain objects only.
"""

from __future__ import annotations

from datetime import datetime, timedelta

import sqlalchemy as sa
from sqlalchemy import and_, func, select
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import Session, aliased

from ctf_generator.domain.scheduling.models import WorkerCandidate, WorkerRequirements

from . import _resolve
from .mappers import to_utc
from .models import ResourceQuota as ResourceQuotaRow
from .models import Worker as WorkerRow
from .models import WorkerImageCache as WorkerImageCacheRow

# Worker concurrency is tracked as this quota dimension under scope_type
# 'worker', scope_key = worker.name.
_WORKER_SCOPE = "worker"
_ACTIVE_INSTANCES = "active_instances"


def _text_array(values) -> sa.ColumnElement:
    """A CAST literal ``text[]`` -- required because psycopg cannot infer the
    element type of an empty Python list (the empty-capabilities caveat from
    ``job_queue_repository.claim``)."""
    return sa.cast(
        sa.literal(sorted(values), type_=postgresql.ARRAY(sa.Text)),
        postgresql.ARRAY(sa.Text),
    )


class SqlAlchemyScheduler:
    """Capability-aware, capacity-aware worker selection (read-only)."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def candidate_workers(
        self,
        requirements: WorkerRequirements,
        now: datetime,
        heartbeat_max_age_seconds: int,
        image_ref: str | None = None,
        limit: int = 20,
    ) -> list[WorkerCandidate]:
        rq = aliased(ResourceQuotaRow)
        cutoff = to_utc(now) - timedelta(seconds=heartbeat_max_age_seconds)

        effective_limit = func.coalesce(rq.limit_value, WorkerRow.capacity)
        reserved = func.coalesce(rq.reserved_value, 0)
        free = effective_limit - reserved

        if image_ref is not None:
            wic = aliased(WorkerImageCacheRow)
            image_cached = wic.id.isnot(None)
            image_join = (
                wic,
                and_(
                    wic.worker_id == WorkerRow.id,
                    wic.image_ref == image_ref,
                ),
            )
        else:
            image_cached = sa.literal(False)
            image_join = None

        stmt = select(
            WorkerRow.name,
            effective_limit.label("effective_limit"),
            reserved.label("reserved"),
            image_cached.label("image_cached"),
        ).outerjoin(
            rq,
            and_(
                rq.scope_type == _WORKER_SCOPE,
                rq.scope_key == WorkerRow.name,
                rq.dimension == _ACTIVE_INSTANCES,
            ),
        )
        if image_join is not None:
            stmt = stmt.outerjoin(*image_join)

        stmt = stmt.where(
            WorkerRow.trust_state == "trusted",
            WorkerRow.quarantined_at.is_(None),
            WorkerRow.drain_requested_at.is_(None),
            WorkerRow.last_heartbeat_at.isnot(None),
            WorkerRow.last_heartbeat_at >= cutoff,
            # architecture membership: architectures @> ARRAY[arch]
            WorkerRow.architectures.contains(_text_array([requirements.architecture])),
            # capability superset: capabilities @> required_capabilities
            WorkerRow.capabilities.contains(
                _text_array(requirements.required_capabilities)
            ),
            free > 0,
        )
        if requirements.runtime_type is not None:
            stmt = stmt.where(WorkerRow.runtime_type == requirements.runtime_type)

        # Rank: image-cache hit first (affinity), then most free capacity, then
        # oldest heartbeat (spread load off the busiest worker).
        stmt = stmt.order_by(
            image_cached.desc(),
            free.desc(),
            WorkerRow.last_heartbeat_at.asc(),
        ).limit(limit)

        rows = self._session.execute(stmt).all()
        return [
            WorkerCandidate(
                worker_name=name,
                capacity=int(eff_limit),
                reserved=int(res),
                image_cached=bool(cached),
            )
            for name, eff_limit, res, cached in rows
        ]

    def free_capacity(self, worker_name: str) -> int:
        # Fail loud on an unknown worker (mirrors the resolver contract).
        _resolve.worker_uuid(self._session, worker_name)
        row = self._session.scalars(
            select(ResourceQuotaRow).where(
                ResourceQuotaRow.scope_type == _WORKER_SCOPE,
                ResourceQuotaRow.scope_key == worker_name,
                ResourceQuotaRow.dimension == _ACTIVE_INSTANCES,
            )
        ).one_or_none()
        if row is None:
            capacity = self._session.scalars(
                select(WorkerRow.capacity).where(WorkerRow.name == worker_name)
            ).one()
            return int(capacity)
        return max(int(row.limit_value) - int(row.reserved_value), 0)
