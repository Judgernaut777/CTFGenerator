"""Signed, session-bound CSRF protection (M11 slice a).

Cookie authentication is CSRF-able, so every state-changing POST carries a CSRF
token that a cross-site attacker cannot forge. The token is an HMAC-SHA256 over
the caller's opaque session token keyed by a server-side secret -- a *signed
double-submit* bound to the session: the server recomputes the expected value
from the httpOnly session cookie (which JS/other origins cannot read) and never
stores per-request CSRF state. A forged cross-site POST arrives WITHOUT a matching
token (the attacker knows neither the secret nor the victim's session token), so
it is rejected with 403.

``issue_csrf_token`` mints the token for a template; ``require_csrf`` is the
FastAPI dependency future write slices (11b/c) attach to their POST handlers.
"""

from __future__ import annotations

import hashlib
import hmac

from fastapi import Request

from .formdata import read_form
from .settings import CSRF_FIELD_NAME, WebSettings


class WebCsrfError(Exception):
    """A state-changing request presented a missing / mismatched CSRF token.

    Surfaced as a friendly 403 HTML page by the web app's handler. Carries no
    detail (never the expected token) so it leaks nothing."""


def issue_csrf_token(session_token: str, secret: bytes) -> str:
    """The CSRF token for a session: ``HMAC-SHA256(secret, session_token)`` hex.

    Deterministic for a given (session, secret), so the value rendered into a form
    matches the value :func:`require_csrf` recomputes from the same session cookie.
    Never returns anything derived from a URL/query so it cannot leak via logs."""
    return hmac.new(
        secret, session_token.encode("utf-8"), hashlib.sha256
    ).hexdigest()


def csrf_token_for_request(request: Request, settings: WebSettings) -> str | None:
    """The CSRF token to render for the current request, or ``None`` when there is
    no session cookie yet (e.g. the login page -- which is CSRF-exempt by nature).
    """
    session_token = request.cookies.get(settings.cookie_name)
    if not session_token:
        return None
    return issue_csrf_token(session_token, settings.csrf_secret)


async def require_csrf(request: Request) -> None:
    """FastAPI dependency: verify the submitted CSRF token against the one derived
    from the caller's session cookie. Raises :class:`WebCsrfError` (403) on a
    missing session, a missing field, or a mismatch (constant-time compare)."""
    settings: WebSettings = request.app.state.web_settings
    session_token = request.cookies.get(settings.cookie_name)
    if not session_token:
        raise WebCsrfError("no session for CSRF verification")
    form = await read_form(request)
    submitted = form.get(CSRF_FIELD_NAME)
    if not submitted:
        raise WebCsrfError("missing CSRF token")
    expected = issue_csrf_token(session_token, settings.csrf_secret)
    if not hmac.compare_digest(submitted, expected):
        raise WebCsrfError("CSRF token mismatch")
