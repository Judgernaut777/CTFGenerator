"""Security response headers + a per-response CSP nonce (M11 slice a).

Every HTML response from the web sub-app carries a strict Content-Security-Policy,
plus the standard hardening headers. Because ALL assets are inlined (no CDN, no
external origins), the policy is ``default-src 'self'`` with inline ``<style>`` /
``<script>`` allowed ONLY via a per-response cryptographic nonce -- never
``'unsafe-inline'`` for scripts. The middleware mints the nonce BEFORE the route
runs (stashing it on ``request.state`` so the template can stamp it on its inline
tags) and emits the matching ``Content-Security-Policy`` header on the way out, so
the header and the rendered nonce always agree.
"""

from __future__ import annotations

import secrets

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.types import ASGIApp


def _csp(nonce: str) -> str:
    """The Content-Security-Policy for an inlined-asset HTML page.

    ``script-src`` / ``style-src`` admit ONLY this response's nonce (no
    ``'unsafe-inline'``), so an injected ``<script>`` without the nonce cannot
    execute even if autoescape were somehow bypassed. ``default-src 'self'`` with
    no external origins forbids any CDN; ``object-src 'none'`` + ``base-uri
    'none'`` + ``frame-ancestors 'none'`` + ``form-action 'self'`` close the
    common bypasses. ``img-src`` permits inline ``data:`` images only."""
    return "; ".join(
        (
            "default-src 'self'",
            f"script-src 'nonce-{nonce}'",
            f"style-src 'nonce-{nonce}'",
            "img-src 'self' data:",
            "font-src 'self'",
            "connect-src 'self'",
            "object-src 'none'",
            "base-uri 'none'",
            "frame-ancestors 'none'",
            "form-action 'self'",
        )
    )


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Mint a CSP nonce per request and stamp the security headers on every
    response (including redirects + error pages -- they flow back through here)."""

    def __init__(self, app: ASGIApp) -> None:
        super().__init__(app)

    async def dispatch(self, request: Request, call_next):
        nonce = secrets.token_urlsafe(16)
        request.state.csp_nonce = nonce
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = _csp(nonce)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        # No web response here is a cacheable public asset: every page carries
        # per-user competition data and/or the session-bound CSRF token. Forbid
        # ALL caching (shared caches AND the bfcache/back button) so nothing is
        # readable after logout or via the back button.
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
        response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        response.headers.setdefault("Cross-Origin-Resource-Policy", "same-origin")
        return response
