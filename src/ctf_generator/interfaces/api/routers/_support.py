"""Shared router helpers: response construction, idempotent-POST plumbing, and
the audit-sink accessor. Keeps the resource routers free of repeated wiring while
holding no business logic."""

from __future__ import annotations

from typing import Any

from fastapi import Request
from fastapi.responses import JSONResponse

from ..audit import AuditSink, audit
from ..deps import Principal
from ..idempotency import (
    IdempotencyStore,
    StoredResponse,
    fingerprint,
    replay_or_conflict,
)


def respond(
    status_code: int, envelope: dict[str, Any], *, etag: str | None = None
) -> JSONResponse:
    """Build a JSON response, attaching a strong ``ETag`` when given. The
    ``X-Request-ID`` header is added by :class:`RequestIDMiddleware`."""
    headers = {"ETag": etag} if etag else None
    return JSONResponse(status_code=status_code, content=envelope, headers=headers)


def _idempotency_store(request: Request) -> IdempotencyStore:
    return request.app.state.idempotency_store


def audit_sink(request: Request) -> AuditSink:
    return request.app.state.audit_sink


def replay(
    request: Request, scope: str, body_json: Any
) -> JSONResponse | None:
    """If this POST carries an ``Idempotency-Key`` that was already used with the
    same body, return the stored response to replay; if the same key was used with
    a different body, raise ``409``; otherwise return ``None`` (proceed)."""
    key = request.headers.get("Idempotency-Key")
    if not key:
        return None
    stored = replay_or_conflict(
        _idempotency_store(request), scope, key, fingerprint(body_json)
    )
    if stored is None:
        return None
    return respond(stored.status_code, stored.body, etag=stored.etag)


def remember(
    request: Request,
    scope: str,
    body_json: Any,
    *,
    status_code: int,
    envelope: dict[str, Any],
    etag: str | None,
) -> None:
    """Store a successful mutating response against its ``Idempotency-Key`` (a
    no-op when the header is absent) so a later retry replays it verbatim."""
    key = request.headers.get("Idempotency-Key")
    if not key:
        return
    _idempotency_store(request).save(
        scope,
        key,
        StoredResponse(
            request_hash=fingerprint(body_json),
            status_code=status_code,
            body=envelope,
            etag=etag,
        ),
    )


def record_audit(
    request: Request,
    principal: Principal,
    *,
    action: str,
    target: str,
    outcome: str = "success",
) -> None:
    audit(
        audit_sink(request),
        actor=principal.subject,
        action=action,
        target=target,
        outcome=outcome,
    )
