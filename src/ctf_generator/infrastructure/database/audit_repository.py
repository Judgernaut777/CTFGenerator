"""Concrete SQLAlchemy repository for the append-only audit trail (M16).

Implements the domain :class:`ctf_generator.domain.repositories.AuditRepository`
over the ``audit_events`` table. ``add`` is insert-only (a persisted row is frozen
by the ``audit_events_immutable`` BEFORE UPDATE OR DELETE trigger -- the store
never offers an update/delete). ``list`` is the privileged operator read: a
filtered, ``occurred_at``-DESC, keyset-cursor-paginated query. ORM rows never
escape -- every method returns domain objects.
"""

from __future__ import annotations

import uuid

from sqlalchemy import select, tuple_
from sqlalchemy.orm import Session

from ctf_generator.domain.audit.models import (
    AuditCursor,
    AuditEvent,
    AuditEventPage,
)

from .mappers import audit_event_from_orm, audit_event_to_orm
from .models import AuditEvent as AuditEventRow


class SqlAlchemyAuditRepository:
    """Persist and query audit records, keyed by ``audit_event_id``."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def add(self, event: AuditEvent) -> None:
        """Append one audit event (flush, not commit -- the unit of work owns the
        transaction). Insert-only: the row can never be updated or deleted."""
        self._session.add(audit_event_to_orm(event))
        self._session.flush()

    def list(
        self,
        *,
        actor: str | None = None,
        action: str | None = None,
        outcome: str | None = None,
        since=None,
        until=None,
        limit: int,
        cursor: AuditCursor | None = None,
    ) -> AuditEventPage:
        """One ``occurred_at``-DESC page (newest first), ``audit_event_id`` DESC as
        the deterministic tiebreak. Exact-match ``actor``/``action``/``outcome``
        filters + inclusive ``since``/``until`` window. ``cursor`` resumes strictly
        after the previous page's last row via a keyset row-value comparison (no
        OFFSET). Fetches ``limit + 1`` internally to know whether more rows follow;
        the page carries ``next_cursor`` iff they do."""
        stmt = select(AuditEventRow)
        if actor is not None:
            stmt = stmt.where(AuditEventRow.actor == actor)
        if action is not None:
            stmt = stmt.where(AuditEventRow.action == action)
        if outcome is not None:
            stmt = stmt.where(AuditEventRow.outcome == outcome)
        if since is not None:
            stmt = stmt.where(AuditEventRow.occurred_at >= since)
        if until is not None:
            stmt = stmt.where(AuditEventRow.occurred_at <= until)
        if cursor is not None:
            # DESC keyset: the next page is the rows sorting AFTER the cursor in
            # the DESC order -- i.e. the (occurred_at, id) tuple strictly LESS THAN
            # the cursor's. A row-value comparison keeps the tiebreak correct.
            stmt = stmt.where(
                tuple_(AuditEventRow.occurred_at, AuditEventRow.id)
                < tuple_(cursor.occurred_at, uuid.UUID(cursor.audit_event_id))
            )
        stmt = stmt.order_by(
            AuditEventRow.occurred_at.desc(), AuditEventRow.id.desc()
        ).limit(limit + 1)

        rows = list(self._session.scalars(stmt))
        has_more = len(rows) > limit
        page_rows = rows[:limit]
        events = tuple(audit_event_from_orm(row) for row in page_rows)
        next_cursor: AuditCursor | None = None
        if has_more and events:
            last = events[-1]
            next_cursor = AuditCursor(
                occurred_at=last.occurred_at,
                audit_event_id=last.audit_event_id,
            )
        return AuditEventPage(items=events, next_cursor=next_cursor)
