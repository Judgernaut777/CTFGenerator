"""Audit-event read DTOs (M16 audit trail).

The audit-read API exposes ONLY the allowlisted, secret-free fields of an
:class:`~ctf_generator.domain.audit.models.AuditEvent`: ``audit_event_id`` /
``actor`` / ``action`` / ``target`` / ``outcome`` / ``request_id`` / ``reason`` /
``occurred_at``. There is no flag/token/body field to surface -- the aggregate has
none -- so this DTO cannot leak a secret.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel

from ctf_generator.domain.audit.models import AuditEvent


class AuditEventResponse(BaseModel):
    audit_event_id: str
    actor: str
    action: str
    target: str
    outcome: str
    request_id: str
    reason: str | None = None
    occurred_at: str


def audit_event_to_response(event: AuditEvent) -> dict[str, Any]:
    return {
        "audit_event_id": event.audit_event_id,
        "actor": event.actor,
        "action": event.action,
        "target": event.target,
        "outcome": event.outcome,
        "request_id": event.request_id,
        "reason": event.reason,
        "occurred_at": event.occurred_at.isoformat(),
    }
