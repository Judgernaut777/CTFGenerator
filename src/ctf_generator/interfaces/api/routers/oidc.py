"""OIDC federated-login router: login redirect + callback (M10 slice c).

Thin handlers over the application
:class:`~ctf_generator.application.auth.oidc.service.OidcService` (which owns the
login-transaction unit of work, the token exchange, and all ID-token validation).
No business logic or crypto here. OIDC is a LOGIN method: the callback issues a
normal M10a local session and returns the SAME ``{token, expires_at}`` shape as
``/auth/login`` -- no OIDC/ID token ever becomes an API bearer.

* ``GET /auth/oidc/login``    -- 302 redirect to the IdP authorization endpoint
  (with response_type=code, scope, redirect_uri, state, nonce, PKCE S256). The
  URL carries only the anti-forgery state; nothing secret is returned.
* ``GET /auth/oidc/callback`` -- ``?code=&state=`` -> validate + issue the local
  session -> ``{token, expires_at}``. A bad/expired/replayed state, a
  token-exchange failure, an invalid ID token, or a disallowed email surfaces as a
  generic ``401`` (:class:`OidcAuthError`); a missing ``code``/``state`` is a
  ``400`` (``ValueError``). The id-token / client_secret / code are NEVER echoed.

This router is mounted ONLY when an ``OidcProviderConfig`` is present (see
``create_app``); when OIDC is not configured the routes do not exist and the API
returns a clean ``404 not_found`` envelope (feature-disabled), never a 500.

Secrets discipline (REQ-INV-011): the raw session token is returned exactly once
(callback) and is NEVER logged; the audit records only the issuer and the
resolved subject, never a token, code, or secret.
"""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import RedirectResponse

from ..audit import audit
from ..schemas.auth import TokenResponse, token_response
from ..schemas.common import ERROR_RESPONSES
from ._support import audit_sink, respond

router = APIRouter(tags=["auth"])


def get_oidc_service(request: Request):
    """The app-scoped :class:`OidcService`. The router is only mounted when OIDC
    is configured, so this is normally always present; a defensive miss surfaces
    as a 404 (feature-disabled), never a 500."""
    service = getattr(request.app.state, "oidc_service", None)
    if service is None:  # pragma: no cover - router is mounted only when set
        raise LookupError("oidc login is not enabled")
    return service


@router.get(
    "/auth/oidc/login",
    response_model=None,
    responses={
        302: {"description": "Redirect to the IdP authorization endpoint"},
        **{k: ERROR_RESPONSES[k] for k in (404, 429)},
    },
)
def oidc_login(request: Request, service=Depends(get_oidc_service)):
    redirect = service.build_authorization_url(datetime.now(UTC))
    audit(
        audit_sink(request),
        actor="anonymous",
        action="auth.oidc.login_start",
        target=service.config.issuer,
        outcome="redirect",
    )
    # 302 + Location: the standard authorization-request redirect. The URL carries
    # only the anti-forgery state (already public in the redirect), no secret.
    return RedirectResponse(url=redirect.url, status_code=302)


@router.get(
    "/auth/oidc/callback",
    response_model=None,
    responses={
        200: {"model": TokenResponse, "description": "Federated login succeeded"},
        **{k: ERROR_RESPONSES[k] for k in (400, 401, 404, 429)},
    },
)
def oidc_callback(
    request: Request,
    code: str | None = Query(default=None),
    state: str | None = Query(default=None),
    service=Depends(get_oidc_service),
):
    issued = service.handle_callback(code, state, datetime.now(UTC))
    audit(
        audit_sink(request),
        actor=issued.user_email,
        action="auth.oidc.login",
        target=issued.user_email,
        outcome="success",
    )
    return respond(200, token_response(issued))
