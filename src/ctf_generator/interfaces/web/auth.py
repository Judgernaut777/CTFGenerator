"""The cookie-session auth bridge (M11 slice a).

The browser authenticates with the EXACT M10 server-side session, carried by an
httpOnly + Secure + SameSite=Lax cookie instead of an ``Authorization: Bearer``
header. This module:

* sets / clears that cookie (``set_session_cookie`` / ``clear_session_cookie``),
  NEVER placing the token in a URL, body, or log;
* resolves it to the API :class:`~interfaces.api.deps.Principal` via the EXISTING
  M10 :class:`~interfaces.api.db_authenticator.DbAuthenticator` -- so the web
  surface reuses the identical ResolvedPrincipal -> Principal mapping and the same
  M10b system-roles/memberships context, never forking the session model; and
* exposes :func:`get_web_principal`, the UI auth dependency: an unauthenticated
  page raises :class:`WebAuthRequired` (mapped to a 302 redirect to the login
  form), NOT a JSON 401.

The session is stable until logout/expiry -- there is NO per-request rotation (the
prototype dashboard rotated the token on every GET and bounced concurrent polls
back to /login; that self-DoS is deliberately not repeated).
"""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import Depends, Request
from starlette.responses import Response

from ctf_generator.application.auth import AuthService
from ctf_generator.interfaces.api.db_authenticator import DbAuthenticator
from ctf_generator.interfaces.api.deps import Principal
from ctf_generator.interfaces.api.exceptions import AuthenticationError

from .deps import get_web_auth_service, get_web_settings
from .settings import WebSettings


class WebAuthRequired(Exception):
    """The current UI page requires a signed-in session and none was resolved.

    Mapped by the web app to a 302 redirect to the login form (never a JSON 401).
    Carries nothing about why (missing / invalid / expired) so it leaks nothing.
    """


def set_session_cookie(
    response: Response,
    token: str,
    settings: WebSettings,
    *,
    now: datetime,
    expires_at: datetime,
) -> None:
    """Attach the opaque session token as the hardened session cookie. ``max_age``
    tracks the session's own TTL so the cookie expires with the session. The token
    is written ONLY here (Set-Cookie), never to a URL/body/log."""
    max_age = max(0, int((expires_at - now).total_seconds()))
    response.set_cookie(
        key=settings.cookie_name,
        value=token,
        max_age=max_age,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="lax",
        path=settings.mount_path or "/",
    )


def clear_session_cookie(response: Response, settings: WebSettings) -> None:
    """Delete the session cookie (logout / a resolved-but-revoked session)."""
    response.delete_cookie(
        key=settings.cookie_name,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="lax",
        path=settings.mount_path or "/",
    )


def _session_token(request: Request, settings: WebSettings) -> str | None:
    return request.cookies.get(settings.cookie_name)


def get_web_principal(
    request: Request,
    settings: WebSettings = Depends(get_web_settings),
    auth_service: AuthService = Depends(get_web_auth_service),
) -> Principal:
    """Resolve the cookie session to a :class:`Principal`, reusing the M10
    :class:`DbAuthenticator` mapping verbatim. Raises :class:`WebAuthRequired`
    (-> 302 to /app/login) for a missing / invalid / expired / revoked session --
    the browser is redirected to sign in, not handed a JSON 401. Stashes the
    subject on ``request.state`` for the access log (never the token)."""
    token = _session_token(request, settings)
    try:
        principal = DbAuthenticator(auth_service).authenticate(token)
    except AuthenticationError as exc:
        raise WebAuthRequired() from exc
    request.state.principal = principal
    return principal


def logout_session(request: Request, settings: WebSettings) -> None:
    """Revoke the current cookie session server-side (best-effort: an
    already-invalid session is a no-op, never an error). The cookie itself is
    cleared by the caller via :func:`clear_session_cookie`."""
    from ctf_generator.application.auth import InvalidCredentialsError

    token = _session_token(request, settings)
    service = get_web_auth_service(request)
    try:
        service.logout(token, datetime.now(UTC))
    except InvalidCredentialsError:
        pass
