"""Read-only audit-trail query service (unit-of-work-owning).

The audit trail is WRITTEN best-effort by the API's audit sink (see
``interfaces/api/audit.py``); this service is the privileged READ path. It exposes
the durable, append-only ``audit_events`` log as a filtered, ``occurred_at``-DESC,
cursor-paginated page. Every field it can surface is a short identifier -- there
is no secret column to leak.

Authorization (admin/support-only, SYSTEM scope) is decided in the interface layer
via ``require_permission(Permission.AUDIT_READ)``; this service just serves the
requested query.
"""

from __future__ import annotations

from datetime import datetime

from ctf_generator.domain.audit.models import AuditCursor, AuditEventPage
from ctf_generator.infrastructure.database.audit_repository import (
    SqlAlchemyAuditRepository,
)
from ctf_generator.infrastructure.database.session import Database


class AuditQueryService:
    """Query the audit trail read-only, owning the transaction."""

    def __init__(self, database: Database) -> None:
        self._database = database

    def list(
        self,
        *,
        actor: str | None = None,
        action: str | None = None,
        outcome: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int,
        cursor: AuditCursor | None = None,
    ) -> AuditEventPage:
        with self._database.session_scope() as session:
            return SqlAlchemyAuditRepository(session).list(
                actor=actor,
                action=action,
                outcome=outcome,
                since=since,
                until=until,
                limit=limit,
                cursor=cursor,
            )
