"""Rate limiting middleware with a pluggable limiter.

Slice a ships an in-memory token-bucket limiter keyed by the caller's bearer
token (a cheap principal proxy) or, absent one, the client IP. On exhaustion it
returns a ``429`` in the ``ctfgen.error`` envelope with a ``Retry-After`` header --
it builds the response directly rather than raising, so the limit is enforced
even before routing/auth run. (Principal-accurate, distributed limiting refines in
M10; the ``RateLimiter`` seam lets a Redis/token-bucket backend drop in.)
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


def _client_key(request: Request) -> str:
    auth = request.headers.get("authorization", "")
    if auth:
        # Key on the token WITHOUT storing/logging it: a short opaque hash bucket
        # keeps callers separated without persisting the credential.
        return f"tok:{hash(auth) & 0xFFFFFFFF:08x}"
    client = request.client
    return f"ip:{client.host}" if client else "ip:unknown"


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, limiter: RateLimiter | None) -> None:
        super().__init__(app)
        self._limiter = limiter

    async def dispatch(self, request: Request, call_next) -> Response:
        if self._limiter is None:
            return await call_next(request)
        allowed, retry_after = self._limiter.check(_client_key(request))
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
