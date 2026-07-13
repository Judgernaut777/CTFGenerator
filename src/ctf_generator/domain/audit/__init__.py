"""Audit-trail domain: the durable, append-only privileged-action record.

Exposes the :class:`AuditEvent` aggregate (secret-free by construction), the
opaque-keyset :class:`AuditCursor`, and the :class:`AuditEventPage` returned by a
filtered/paginated read. Domain-pure: stdlib only, no framework or I/O.
"""

from __future__ import annotations

from .models import (
    VALID_AUDIT_OUTCOMES,
    AuditCursor,
    AuditEvent,
    AuditEventPage,
)

__all__ = [
    "VALID_AUDIT_OUTCOMES",
    "AuditCursor",
    "AuditEvent",
    "AuditEventPage",
]
