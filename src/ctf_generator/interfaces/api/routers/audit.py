"""Audit router: read the durable, tamper-evident privileged-action trail (M16).

``GET /audit`` is the privileged, admin/support-only (``AUDIT_READ``, SYSTEM
scope) read over the append-only ``audit_events`` log. It is filterable by
``actor`` / ``action`` / ``outcome`` and an inclusive ``since`` / ``until`` time
window, and cursor-paginated newest-first. The response exposes ONLY the
allowlisted, secret-free fields -- there is no flag/token/body to surface.

A malformed filter (bad ``outcome`` / unparsable time / bad cursor) is a clean
400 envelope, never a 500: each parse raises a ``ValueError`` (the cursor a
``CursorError`` subclass), which the error handler maps to 400 ``invalid_request``.
"""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Query

from ctf_generator.domain.audit.models import (
    VALID_AUDIT_OUTCOMES,
    AuditCursor,
)

from ..deps import (
    Permission,
    Principal,
    get_audit_query_service,
    require_permission,
)
from ..envelopes import AUDIT_EVENT_LIST_SCHEMA, list_envelope
from ..pagination import CursorError, clamp_limit, decode_cursor, encode_cursor
from ..schemas.audit import audit_event_to_response
from ..schemas.common import ERROR_RESPONSES
from ._support import respond

router = APIRouter(tags=["audit"])


def _parse_time(value: str | None, field: str) -> datetime | None:
    """Parse an ISO-8601 instant filter, coercing a naive value to UTC. A
    malformed value is a clean 400 (``ValueError``), never a 500."""
    if value is None:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ValueError(f"invalid {field}: not an ISO-8601 datetime") from exc
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


def _decode_audit_cursor(cursor: str | None) -> AuditCursor | None:
    """Decode the opaque page token into the keyset boundary. Anything not issued
    by this endpoint is a ``CursorError`` (400), never a 500."""
    if cursor is None:
        return None
    payload = decode_cursor(cursor)  # CursorError on a malformed token
    if (
        not isinstance(payload, list)
        or len(payload) != 2
        or not all(isinstance(part, str) for part in payload)
    ):
        raise CursorError(f"invalid cursor: {cursor!r}")
    occurred_raw, audit_event_id = payload
    try:
        occurred_at = datetime.fromisoformat(occurred_raw)
    except ValueError as exc:
        raise CursorError(f"invalid cursor: {cursor!r}") from exc
    if occurred_at.tzinfo is None:
        occurred_at = occurred_at.replace(tzinfo=UTC)
    return AuditCursor(occurred_at=occurred_at, audit_event_id=audit_event_id)


def _encode_audit_cursor(cursor: AuditCursor | None) -> str | None:
    if cursor is None:
        return None
    return encode_cursor([cursor.occurred_at.isoformat(), cursor.audit_event_id])


@router.get(
    "/audit",
    response_model=None,
    responses={k: ERROR_RESPONSES[k] for k in (400, 401, 403, 422, 429)},
)
def list_audit_events(
    actor: str | None = Query(default=None),
    action: str | None = Query(default=None),
    outcome: str | None = Query(default=None),
    since: str | None = Query(default=None, description="ISO-8601 lower bound"),
    until: str | None = Query(default=None, description="ISO-8601 upper bound"),
    limit: int | None = Query(default=None, ge=1),
    cursor: str | None = Query(default=None),
    principal: Principal = Depends(require_permission(Permission.AUDIT_READ)),
    service=Depends(get_audit_query_service),
):
    if outcome is not None and outcome not in VALID_AUDIT_OUTCOMES:
        raise ValueError(
            f"invalid outcome filter: {outcome!r} "
            f"(one of {sorted(VALID_AUDIT_OUTCOMES)})"
        )
    since_dt = _parse_time(since, "since")
    until_dt = _parse_time(until, "until")
    boundary = _decode_audit_cursor(cursor)

    page = service.list(
        actor=actor,
        action=action,
        outcome=outcome,
        since=since_dt,
        until=until_dt,
        limit=clamp_limit(limit),
        cursor=boundary,
    )
    items = [audit_event_to_response(event) for event in page.items]
    envelope = list_envelope(
        AUDIT_EVENT_LIST_SCHEMA,
        items,
        limit=clamp_limit(limit),
        next_cursor=_encode_audit_cursor(page.next_cursor),
    )
    return respond(200, envelope)
