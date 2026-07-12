"""Concrete SQLAlchemy repositories for the gap-safe scoreboard projection (M7).

``SqlAlchemyScoreProjectionQueue`` drains the trigger-populated transactional
outbox (``score_projection_outbox``): rows are inserted by the DB trigger
``score_events_enqueue_projection`` in the same transaction as every
``score_events`` INSERT, so a committed event always has an unprocessed outbox
row and can never be skipped -- no seq cursor appears anywhere in the
correctness path. ``complete`` deletes rows (the ledger is the permanent
history; a processed row carries no information); ``fail`` keeps the row with
a sanitized error so a poison event is diagnosable and blocks only itself.

``SqlAlchemyScoreboardProjectionRepository`` upserts the rebuildable cache with
a monotonic ``as_of_seq`` guard: an older-snapshot fold can never overwrite a
newer one (valid because the committed event set only grows).

Both take the caller's Session; FLUSH only, never commit/rollback.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from ctf_generator.domain.ledger.models import (
    ProjectionLag,
    ProjectionTask,
    ScoreboardProjectionRecord,
)

from . import _resolve
from .mappers import projection_task_from_orm, scoreboard_projection_from_orm
from .models import Competition
from .models import ScoreboardProjection as ScoreboardProjectionRow
from .models import ScoreEvent as ScoreEventRow
from .models import ScoreProjectionOutbox as OutboxRow

# Keep stored errors bounded and obviously sanitized (class + message only).
_MAX_ERROR_LEN = 1000


class SqlAlchemyScoreProjectionQueue:
    """Work-queue view over the trigger-populated projection outbox."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def pending_competitions(self, limit: int = 100) -> list[str]:
        rows = self._session.execute(
            select(Competition.slug)
            .select_from(OutboxRow)
            .join(Competition, OutboxRow.competition_id == Competition.id)
            .where(OutboxRow.status == "pending")
            .group_by(Competition.slug)
            .order_by(func.min(OutboxRow.seq))
            .limit(limit)
        ).all()
        return [slug for (slug,) in rows]

    def claim_pending(
        self, limit: int, competition_id: str | None = None
    ) -> list[ProjectionTask]:
        """Lock (FOR UPDATE SKIP LOCKED, outbox rows only) and return pending
        rows in seq order. Locks die with the transaction, so a crashed
        projector's claims simply reappear."""
        query = (
            select(OutboxRow)
            .where(OutboxRow.status == "pending")
            .order_by(OutboxRow.seq.asc())
            .limit(limit)
            .with_for_update(skip_locked=True, of=OutboxRow)
        )
        if competition_id is not None:
            comp_uuid = _resolve.competition_uuid(self._session, competition_id)
            query = query.where(OutboxRow.competition_id == comp_uuid)
        rows = self._session.scalars(query).all()
        tasks: list[ProjectionTask] = []
        for row in rows:
            slug = self._session.scalars(
                select(Competition.slug).where(Competition.id == row.competition_id)
            ).one()
            tasks.append(projection_task_from_orm(row, slug))
        return tasks

    def complete(self, seqs: Sequence[int]) -> None:
        """Delete processed rows -- only ever called in the same transaction
        that folded their events into the projection."""
        if not seqs:
            return
        self._session.execute(
            sa.delete(OutboxRow).where(OutboxRow.seq.in_(list(seqs)))
        )
        self._session.flush()

    def fail(self, seqs: Sequence[int], error: str) -> int:
        """Mark still-pending rows failed with a sanitized error. Returns the
        number of rows marked."""
        if not seqs:
            return 0
        result = self._session.execute(
            sa.update(OutboxRow)
            .where(OutboxRow.seq.in_(list(seqs)), OutboxRow.status == "pending")
            .values(
                status="failed",
                attempts=OutboxRow.attempts + 1,
                last_error=error[:_MAX_ERROR_LEN],
            )
        )
        self._session.flush()
        return int(result.rowcount or 0)

    def list_failed(self) -> list[ProjectionTask]:
        rows = self._session.execute(
            select(OutboxRow, Competition.slug)
            .select_from(OutboxRow)
            .join(Competition, OutboxRow.competition_id == Competition.id)
            .where(OutboxRow.status == "failed")
            .order_by(OutboxRow.seq.asc())
        ).all()
        return [projection_task_from_orm(row, slug) for row, slug in rows]

    def requeue_all(self) -> int:
        """Rebuild support: re-enqueue an outbox row for every ledger event
        (idempotent via ON CONFLICT DO NOTHING) and flip failed rows back to
        pending. Returns the number of rows (re)enqueued or reset."""
        insert_stmt = (
            pg_insert(OutboxRow)
            .from_select(
                ["seq", "competition_id"],
                select(ScoreEventRow.seq, ScoreEventRow.competition_id),
            )
            .on_conflict_do_nothing(index_elements=["seq"])
            # RETURNING gives an exact count -- the driver's rowcount is
            # unreliable (-1) for INSERT ... FROM SELECT ON CONFLICT.
            .returning(OutboxRow.seq)
        )
        inserted = len(self._session.execute(insert_stmt).fetchall())
        reset = len(
            self._session.execute(
                sa.update(OutboxRow)
                .where(OutboxRow.status == "failed")
                .values(status="pending", last_error=None)
                .returning(OutboxRow.seq)
            ).fetchall()
        )
        self._session.flush()
        return inserted + reset

    def pending_stats(self) -> ProjectionLag:
        pending_count, oldest = self._session.execute(
            select(func.count(), func.min(OutboxRow.created_at)).where(
                OutboxRow.status == "pending"
            )
        ).one()
        latest_seq = self._session.execute(
            select(func.coalesce(func.max(ScoreEventRow.seq), 0))
        ).scalar_one()
        max_as_of = self._session.execute(
            select(func.coalesce(func.max(ScoreboardProjectionRow.as_of_seq), 0))
        ).scalar_one()
        return ProjectionLag(
            pending_count=int(pending_count),
            latest_seq=int(latest_seq),
            max_as_of_seq=int(max_as_of),
            oldest_pending_created_at=oldest,
        )


class SqlAlchemyScoreboardProjectionRepository:
    """The rebuildable per-competition scoreboard cache with a monotonic
    ``as_of_seq`` upsert guard."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def upsert(self, projection: ScoreboardProjectionRecord) -> None:
        comp_uuid = _resolve.competition_uuid(
            self._session, projection.competition_id
        )
        stmt = pg_insert(ScoreboardProjectionRow).values(
            competition_id=comp_uuid,
            as_of_seq=projection.as_of_seq,
            entries=dict(projection.entries),
        )
        stmt = stmt.on_conflict_do_update(
            index_elements=["competition_id"],
            set_={
                "as_of_seq": stmt.excluded.as_of_seq,
                "entries": stmt.excluded.entries,
                "computed_at": sa.func.now(),
            },
            where=stmt.excluded.as_of_seq >= ScoreboardProjectionRow.as_of_seq,
        )
        self._session.execute(stmt)
        self._session.flush()

    def get(self, competition_id: str) -> ScoreboardProjectionRecord | None:
        comp_uuid = _resolve.competition_uuid(self._session, competition_id)
        row = self._session.scalars(
            select(ScoreboardProjectionRow).where(
                ScoreboardProjectionRow.competition_id == comp_uuid
            )
        ).one_or_none()
        if row is None:
            return None
        return scoreboard_projection_from_orm(row, competition_id)
