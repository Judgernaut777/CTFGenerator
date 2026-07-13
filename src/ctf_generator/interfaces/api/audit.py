"""Audit hook for privileged mutations + the durable audit trail (M16).

Emits one structured audit record per privileged action -- ``actor`` / ``action``
/ ``target`` / ``outcome`` / ``request_id`` (+ an optional ``reason`` for an admin
override, REQ-INV-009). It records WHO did WHAT to WHICH resource and whether it
succeeded; it NEVER records request bodies, flags, tokens, session keys, or any
other secret -- only short identifiers.

Sinks are pluggable:

* :class:`LoggingAuditSink` -- one JSON line per event (the historical behavior).
* :class:`DbAuditSink` -- persists each event as an immutable
  :class:`~ctf_generator.domain.audit.models.AuditEvent` row (M16 durable,
  operator-queryable, tamper-evident trail). BEST-EFFORT / NON-FATAL: it runs in
  its OWN transaction and a persistence failure is caught + logged, NEVER
  propagated -- an audit write must never turn an audited success into a 500 or
  roll back the user's operation.
* :class:`CompositeAuditSink` -- fans one event out to several sinks, each guarded
  independently so one failing sink never blocks the others or the request.

``create_app`` wires the default to ``CompositeAuditSink(DbAuditSink(db),
LoggingAuditSink())`` when a database is configured (durable trail + log line),
falling back to the log-only sink otherwise.
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Protocol

from .context import current_request_id

if TYPE_CHECKING:  # pragma: no cover - import only for typing (no runtime coupling)
    from ctf_generator.infrastructure.database.session import Database

_audit_logger = logging.getLogger("ctfgen.api.audit")


class AuditSink(Protocol):
    def record(self, event: dict[str, str]) -> None: ...


class LoggingAuditSink:
    """Writes each audit record as a single JSON line at INFO."""

    def __init__(self, logger: logging.Logger | None = None) -> None:
        self._logger = logger or _audit_logger

    def record(self, event: dict[str, str]) -> None:
        self._logger.info("audit %s", json.dumps(event, sort_keys=True))


class DbAuditSink:
    """Persists each audit event as an immutable ``audit_events`` row (M16).

    NON-FATAL BY DESIGN: ``record`` opens its OWN unit of work (a transaction
    separate from the request's -- the user's operation has already committed by
    the time the audit fires) and swallows + logs any failure. A DB outage, a
    constraint violation, or a malformed event NEVER propagates out of ``record``,
    so an audit write can never turn an audited success into a 500 or roll back
    the user's operation. This mirrors the M10b denied-audit guard.
    """

    def __init__(self, database: Database) -> None:
        self._database = database

    def record(self, event: dict[str, str]) -> None:
        try:
            from ctf_generator.infrastructure.database.audit_repository import (
                SqlAlchemyAuditRepository,
            )

            audit_event = self._to_domain(event)
            with self._database.session_scope() as session:
                SqlAlchemyAuditRepository(session).add(audit_event)
        except Exception:  # noqa: BLE001 - audit must never mask the real operation
            _audit_logger.warning(
                "failed to persist audit event action=%s outcome=%s request_id=%s",
                event.get("action"),
                event.get("outcome"),
                event.get("request_id"),
                exc_info=True,
            )

    @staticmethod
    def _to_domain(event: dict[str, str]):
        from ctf_generator.domain.audit.models import AuditEvent

        return AuditEvent(
            audit_event_id=str(uuid.uuid4()),
            actor=event["actor"],
            action=event["action"],
            target=event.get("target", ""),
            outcome=event["outcome"],
            request_id=event.get("request_id", ""),
            reason=event.get("reason"),
            occurred_at=datetime.now(UTC),
        )


class CompositeAuditSink:
    """Fan one audit event out to several sinks. Each sink is invoked under its own
    guard so a failure in one (e.g. the log line) never blocks another (the
    durable trail) and never propagates to the caller -- the whole audit path stays
    best-effort / non-fatal."""

    def __init__(self, *sinks: AuditSink) -> None:
        self._sinks = tuple(sinks)

    def record(self, event: dict[str, str]) -> None:
        for sink in self._sinks:
            try:
                sink.record(event)
            except Exception:  # noqa: BLE001 - one sink must not break the others
                _audit_logger.warning(
                    "audit sink %s failed action=%s request_id=%s",
                    type(sink).__name__,
                    event.get("action"),
                    event.get("request_id"),
                    exc_info=True,
                )


def audit(
    sink: AuditSink,
    *,
    actor: str,
    action: str,
    target: str,
    outcome: str,
    reason: str | None = None,
) -> None:
    """Emit a privileged-action audit record. ``actor`` is the principal subject,
    ``action`` a stable verb (e.g. ``competition.create``) or HTTP method,
    ``target`` the business id / request path of the affected resource, ``outcome``
    ``"success"`` / ``"denied"`` / ``"error"``. ``reason`` is an OPTIONAL operator
    justification recorded for an admin override (REQ-INV-009); it is threaded into
    the event only when provided. No secrets are ever passed here."""
    event: dict[str, str] = {
        "actor": actor,
        "action": action,
        "target": target,
        "outcome": outcome,
        "request_id": current_request_id(),
    }
    if reason is not None:
        event["reason"] = reason
    sink.record(event)
