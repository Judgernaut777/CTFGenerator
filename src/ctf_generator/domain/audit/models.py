"""Audit value types: ``AuditEvent`` -- the durable, APPEND-ONLY record of one
privileged state change (M16 slice 16a; REQ-COMP-013 / REQ-INV-014).

Today an audit event goes only to a logger (``LoggingAuditSink``): there is no
durable trail and nothing an organizer/admin can query. This aggregate turns the
audit stream into a first-class, tamper-evident record: it says WHO
(``actor``) did WHAT (``action``) to WHICH resource (``target``), with what
``outcome``, under which ``request_id``, and -- for an admin override that
requires a recorded justification (REQ-INV-009) -- an optional ``reason``.

SECRET-FREE BY CONSTRUCTION. This aggregate has ONLY short-identifier fields --
``actor`` (a subject or ``"anonymous"``), ``action`` (a stable verb / HTTP
method), ``target`` (a business id or request PATH), ``outcome``, ``request_id``,
and an optional free-text ``reason``. There is NO flag / token / password /
provider-key / DSN / request-body / candidate-answer field: none exists to be
populated, so a secret cannot be persisted here even if a caller tried to pass
one -- the value would simply be recorded as opaque data in a short-id column.
The audit trail records THAT something happened and to which id, never the
secret material itself. The persisted row and the read API expose exactly this
allowlist and nothing else.

APPEND-ONLY / TAMPER-EVIDENT. An ``AuditEvent`` is never updated or deleted --
the store enforces this with the shared ``reject_mutation`` BEFORE UPDATE OR
DELETE trigger (see migration 0014). Immutability is the whole point of an audit
trail: a persisted record cannot be silently altered or removed.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

# The outcomes an audit record may carry. Deliberately small + closed: a success
# path records ``"success"``; a denied authN/authZ attempt records ``"denied"``
# (the M10b denied-audit path); an errored privileged operation records
# ``"error"``. An unknown outcome is a ValueError (fail loud) so the vocabulary
# cannot silently drift.
VALID_AUDIT_OUTCOMES = frozenset({"success", "denied", "error"})


def _require_nonempty(value: str, field_name: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be a non-empty string")


def _require_tz_aware(value: datetime, field_name: str) -> None:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ValueError(f"{field_name} must be a timezone-aware datetime")


@dataclass(frozen=True)
class AuditEvent:
    """One privileged-action audit record, keyed by ``audit_event_id``.

    Every field is a short identifier or sanitized free text -- there is
    deliberately NO column that could hold a flag/token/secret. ``target`` is a
    business id or request path (never a secret); ``reason`` is an optional
    operator-supplied justification for an admin override (REQ-INV-009).
    """

    audit_event_id: str
    actor: str
    action: str
    target: str
    outcome: str
    request_id: str
    occurred_at: datetime
    reason: str | None = None

    def __post_init__(self) -> None:
        _require_nonempty(self.audit_event_id, "audit_event_id")
        _require_nonempty(self.actor, "actor")
        _require_nonempty(self.action, "action")
        _require_nonempty(self.outcome, "outcome")
        if self.outcome not in VALID_AUDIT_OUTCOMES:
            raise ValueError(
                f"outcome must be one of {sorted(VALID_AUDIT_OUTCOMES)}, "
                f"got {self.outcome!r}"
            )
        # target / request_id are short identifiers; they may be empty (e.g. no
        # request context) but must be strings -- never None, so the row is total.
        if not isinstance(self.target, str):
            raise ValueError("target must be a string")
        if not isinstance(self.request_id, str):
            raise ValueError("request_id must be a string")
        if self.reason is not None and not isinstance(self.reason, str):
            raise ValueError("reason must be a string or None")
        _require_tz_aware(self.occurred_at, "occurred_at")


@dataclass(frozen=True)
class AuditCursor:
    """The keyset boundary of an audit read page.

    The trail is ordered ``occurred_at`` DESC (newest first), with
    ``audit_event_id`` as the deterministic tiebreak. A cursor names the last row
    of the previous page; the next page is the rows sorting strictly after it
    (i.e. ``(occurred_at, audit_event_id)`` strictly LESS THAN the cursor's, in
    the DESC ordering). Framework-free: the interface layer wraps/unwraps this in
    the opaque base64 token clients see."""

    occurred_at: datetime
    audit_event_id: str


@dataclass(frozen=True)
class AuditEventPage:
    """One page of an audit read: the (already ordered) events plus the cursor to
    resume after the last one, or ``None`` when the page is the tail."""

    items: tuple[AuditEvent, ...]
    next_cursor: AuditCursor | None = None
