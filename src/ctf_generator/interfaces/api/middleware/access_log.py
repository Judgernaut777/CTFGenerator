"""Structured JSON access log.

Emits one line per request: method, path, status, latency-ms, request_id, and the
authenticated principal's subject (``-`` when unauthenticated). It deliberately
records NONE of: request/response bodies, query strings with potential secrets,
headers, flags, tokens, or credentials -- only the request line's shape and
outcome.
"""

from __future__ import annotations

import json
import logging
import time

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

_logger = logging.getLogger("ctfgen.api.access")


class AccessLogMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        started = time.perf_counter()
        status = 500
        try:
            response = await call_next(request)
            status = response.status_code
            return response
        finally:
            latency_ms = round((time.perf_counter() - started) * 1000, 2)
            principal = getattr(request.state, "principal", None)
            subject = getattr(principal, "subject", "-") if principal else "-"
            _logger.info(
                "access %s",
                json.dumps(
                    {
                        "method": request.method,
                        "path": request.url.path,
                        "status": status,
                        "latency_ms": latency_ms,
                        "request_id": getattr(request.state, "request_id", "-"),
                        "principal": subject,
                    },
                    sort_keys=True,
                ),
            )
