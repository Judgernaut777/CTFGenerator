"""Request-id correlation middleware.

Accepts an inbound ``X-Request-ID`` (so a caller/proxy can supply its own
correlation id) or generates one, publishes it to the request-scoped context for
every downstream layer (error envelope, access log, audit hook), and echoes it on
the response ``X-Request-ID`` header. The generated id is opaque and carries no
caller data.
"""

from __future__ import annotations

import uuid

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from ..context import reset_request_id, set_request_id

_HEADER = "X-Request-ID"
_MAX_LEN = 200


def _sanitize(value: str) -> str:
    """Keep only a bounded, printable subset of a client-supplied id so it is
    safe to log and echo (never trust an inbound header verbatim)."""
    cleaned = "".join(c for c in value if c.isalnum() or c in "-_.").strip()
    return cleaned[:_MAX_LEN]


class RequestIDMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        inbound = request.headers.get(_HEADER, "")
        request_id = _sanitize(inbound) if inbound else ""
        if not request_id:
            request_id = f"req_{uuid.uuid4().hex}"
        request.state.request_id = request_id
        token = set_request_id(request_id)
        try:
            response = await call_next(request)
        finally:
            reset_request_id(token)
        response.headers[_HEADER] = request_id
        return response
