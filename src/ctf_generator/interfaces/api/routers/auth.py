"""Auth router: login / refresh / logout / me (M10 slice a).

Thin handlers over the application :class:`~ctf_generator.application.auth.AuthService`
(which owns the unit of work, the KDF, and session issuance). No business logic
or session management here. Secrets discipline (REQ-INV-011): the raw token is
returned exactly once (login / refresh) and is NEVER logged; the password is
accepted and never echoed; ``/auth/me`` returns only the resolved principal.

* ``POST /auth/login``   -- ``{email, password}`` -> ``{token, expires_at}``.
  Wrong credentials -> 401 (generic, constant-time -- unknown email and wrong
  password are indistinguishable). Unauthenticated; rate-limited by the shared
  middleware.
* ``POST /auth/refresh`` -- Bearer current token -> a new ``{token, expires_at}``;
  the presented token is revoked (rotation happens ONLY here).
* ``POST /auth/logout``  -- Bearer -> 204; revokes the session.
* ``GET  /auth/me``      -- Bearer -> the current principal summary (subject,
  system roles, competition roles) -- proves the real seam resolves a Principal.
"""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Request, Response

from ..audit import audit
from ..deps import Principal, get_auth_service, get_principal
from ..deps import _bearer_token as bearer_token
from ..schemas.auth import (
    LoginRequest,
    MeResponse,
    TokenResponse,
    me_response,
    token_response,
)
from ..schemas.common import ERROR_RESPONSES
from ._support import audit_sink, respond

router = APIRouter(tags=["auth"])


@router.post(
    "/auth/login",
    response_model=None,
    responses={
        200: {"model": TokenResponse, "description": "Authenticated"},
        **{k: ERROR_RESPONSES[k] for k in (400, 401, 422, 429)},
    },
)
def login(request: Request, body: LoginRequest, service=Depends(get_auth_service)):
    issued = service.authenticate(body.email, body.password, datetime.now(UTC))
    audit(
        audit_sink(request),
        actor=issued.user_email,
        action="auth.login",
        target=issued.user_email,
        outcome="success",
    )
    return respond(200, token_response(issued))


@router.post(
    "/auth/refresh",
    response_model=None,
    responses={
        200: {"model": TokenResponse, "description": "Rotated"},
        **{k: ERROR_RESPONSES[k] for k in (401, 429)},
    },
)
def refresh(request: Request, service=Depends(get_auth_service)):
    issued = service.refresh(bearer_token(request), datetime.now(UTC))
    audit(
        audit_sink(request),
        actor=issued.user_email,
        action="auth.refresh",
        target=issued.user_email,
        outcome="success",
    )
    return respond(200, token_response(issued))


@router.post(
    "/auth/logout",
    status_code=204,
    responses={k: ERROR_RESPONSES[k] for k in (401, 429)},
)
def logout(request: Request, service=Depends(get_auth_service)):
    service.logout(bearer_token(request), datetime.now(UTC))
    return Response(status_code=204)


@router.get(
    "/auth/me",
    response_model=None,
    responses={
        200: {"model": MeResponse, "description": "Current principal"},
        **{k: ERROR_RESPONSES[k] for k in (401, 429)},
    },
)
def me(principal: Principal = Depends(get_principal)):
    return respond(200, me_response(principal))
