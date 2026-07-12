"""Rate limiting middleware with a pluggable limiter.

Slice a ships an in-memory token-bucket limiter keyed by the caller's network
identity (client IP). The middleware runs BEFORE authentication, so it cannot
key on the (unverified) Authorization header: a pre-auth attacker could rotate a
caller-supplied header per request and mint a fresh bucket every time, defeating
the login brute-force limit. The client IP is the only identity the caller
cannot rotate pre-auth. On exhaustion it returns a ``429`` in the
``ctfgen.error`` envelope with a ``Retry-After`` header -- it builds the response
directly rather than raising, so the limit is enforced even before routing/auth
run. (Principal-accurate, distributed limiting refines later; the ``RateLimiter``
seam lets a Redis/token-bucket backend drop in. Per-authenticated-principal
limiting, if ever wanted, is a separate POST-auth concern -- not this middleware.)
"""

from __future__ import annotations

import math
import threading
import time
from typing import Protocol

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from ..context import current_request_id
from ..envelopes import error_envelope


class RateLimiter(Protocol):
    def check(self, key: str) -> tuple[bool, int]:
        """Return ``(allowed, retry_after_seconds)`` for one request from
        ``key``. ``retry_after_seconds`` is meaningful only when denied."""
        ...


class TokenBucketLimiter:
    """Process-local token bucket: ``burst`` capacity refilling at ``rate`` tokens
    per second, one bucket per key. Thread-safe."""

    def __init__(self, rate: float, burst: int) -> None:
        if rate <= 0 or burst <= 0:
            raise ValueError("rate and burst must be positive")
        self._rate = float(rate)
        self._burst = float(burst)
        self._buckets: dict[str, tuple[float, float]] = {}
        self._lock = threading.Lock()

    def check(self, key: str) -> tuple[bool, int]:
        now = time.monotonic()
        with self._lock:
            tokens, last = self._buckets.get(key, (self._burst, now))
            tokens = min(self._burst, tokens + (now - last) * self._rate)
            if tokens >= 1.0:
                self._buckets[key] = (tokens - 1.0, now)
                return True, 0
            self._buckets[key] = (tokens, now)
            retry_after = max(1, math.ceil((1.0 - tokens) / self._rate))
            return False, retry_after


def _client_key(request: Request, *, trust_forwarded_for: bool = False) -> str:
    """Return a rate-limit bucket key from the caller's network identity.

    Keys on the client's peer address (``request.client.host``) -- a stable
    identity the caller cannot rotate pre-auth. The Authorization header is
    NEVER used: the middleware runs before auth and cannot validate a token, so
    keying on it would let an attacker mint a fresh bucket per request.

    ``trust_forwarded_for`` (OFF by default) opts into reading the LEFTMOST
    ``X-Forwarded-For`` address for reverse-proxy deployments. Only enable it
    when a trusted proxy sets that header -- otherwise a caller could spoof it to
    rotate keys, re-introducing the bypass. Caveat: behind a trusted proxy with
    the toggle OFF, every client shares the proxy's IP bucket (over-throttle);
    flip it ON only once a trusted proxy owns X-Forwarded-For (an M18 deployment
    concern)."""
    if trust_forwarded_for:
        forwarded = request.headers.get("x-forwarded-for", "")
        if forwarded:
            first = forwarded.split(",", 1)[0].strip()
            if first:
                return f"ip:{first}"
    client = request.client
    return f"ip:{client.host}" if client else "ip:unknown"


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(
        self, app, limiter: RateLimiter | None, *, trust_forwarded_for: bool = False
    ) -> None:
        super().__init__(app)
        self._limiter = limiter
        self._trust_forwarded_for = trust_forwarded_for

    async def dispatch(self, request: Request, call_next) -> Response:
        if self._limiter is None:
            return await call_next(request)
        key = _client_key(request, trust_forwarded_for=self._trust_forwarded_for)
        allowed, retry_after = self._limiter.check(key)
        if allowed:
            return await call_next(request)
        request_id = current_request_id()
        body = error_envelope(
            code="rate_limited",
            message="rate limit exceeded",
            request_id=request_id,
        )
        return JSONResponse(
            status_code=429,
            content=body,
            headers={"Retry-After": str(retry_after), "X-Request-ID": request_id},
        )
