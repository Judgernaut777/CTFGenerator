"""Request-scoped correlation context.

A single :class:`contextvars.ContextVar` holds the current request id so any
layer (error handler, access log, audit hook) can stamp it without threading it
through every call. The :class:`RequestIDMiddleware` sets it per request; readers
fall back to ``"-"`` when there is no active request (e.g. a unit test calling a
helper directly).
"""

from __future__ import annotations

import contextvars

_REQUEST_ID: contextvars.ContextVar[str] = contextvars.ContextVar(
    "ctfgen_request_id", default="-"
)


def set_request_id(request_id: str) -> contextvars.Token:
    return _REQUEST_ID.set(request_id)


def reset_request_id(token: contextvars.Token) -> None:
    _REQUEST_ID.reset(token)


def current_request_id() -> str:
    return _REQUEST_ID.get()
