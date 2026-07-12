"""The ``ctfgen.error`` envelope + exception handlers.

Registers handlers that translate every failure into the single error envelope
(``docs/api/endpoints.md`` §1.2) with a stable machine-readable ``code`` and the
correlation ``request_id``. The catch-all logs the exception with the request id
but the response body NEVER leaks internals, a stack trace, or a secret.

Mapping (authoritative for slice a):

===========================================  =======  ====================
exception                                    status   code
===========================================  =======  ====================
``AuthenticationError``                      401      unauthorized
``AuthorizationError`` / ``PermissionError`` 403      forbidden
``LookupError``                              404      not_found
``IntegrityError`` / ``QuotaExceededError``  409      conflict
domain ``IdempotencyConflictError``          409      conflict
``PreconditionFailedError``                  412      precondition_failed
non-JSON body (``json_invalid``)             415      unsupported_media_type
``CompetitionWindowError``                   422      validation_failed
``RequestValidationError``                   422      validation_failed
``PreconditionRequiredError``                428      precondition_failed
``RateLimitedError``                         429      rate_limited (+Retry-After)
``ValueError``                               400      invalid_request
framework ``HTTPException`` (404/405/415/…)  =status  not_found/method_not_allowed/…
anything else                                500      internal (logged, no leak)
===========================================  =======  ====================

The request id is sourced from ``request.state.request_id`` (stamped by
:class:`RequestIDMiddleware` *before* the route runs, so it survives even the 500
path where the middleware's contextvar has already been reset) with the contextvar
as a fallback.

Worker-credential / unsupported-runtime mappings (401/409/501) land with the
slice-c worker HTTP transport; those exceptions cannot arise on slice-a routes.
"""

from __future__ import annotations

import logging

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy.exc import IntegrityError
from starlette.exceptions import HTTPException as StarletteHTTPException

from ctf_generator.application.catalog.competition_service import (
    CompetitionWindowError,
)
from ctf_generator.domain.ledger.processing import (
    IdempotencyConflictError as DomainIdempotencyConflictError,
)
from ctf_generator.domain.scheduling.models import QuotaExceededError

from .context import current_request_id
from .envelopes import error_envelope
from .exceptions import ApiError, AuthorizationError, RateLimitedError

_logger = logging.getLogger("ctfgen.api")

# Framework HTTPException status -> canonical error.code. Anything unlisted maps
# to the generic ``invalid_request``.
_HTTP_STATUS_CODES: dict[int, str] = {
    404: "not_found",
    405: "method_not_allowed",
    415: "unsupported_media_type",
}


def _request_id(request: Request) -> str:
    """The correlation id for this request. Prefer the value stamped on
    ``request.state`` (survives the 500 path, where the RequestID middleware's
    contextvar has already been reset), falling back to the contextvar."""
    return getattr(request.state, "request_id", None) or current_request_id()


def _response(
    request: Request,
    status_code: int,
    code: str,
    message: str,
    *,
    detail: list[dict[str, str]] | None = None,
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    request_id = _request_id(request)
    body = error_envelope(
        code=code, message=message, request_id=request_id, detail=detail
    )
    response_headers = {"X-Request-ID": request_id}
    if headers:
        response_headers.update(headers)
    return JSONResponse(
        status_code=status_code, content=body, headers=response_headers
    )


async def _handle_api_error(request: Request, exc: ApiError) -> JSONResponse:
    headers: dict[str, str] | None = None
    if isinstance(exc, RateLimitedError):
        headers = {"Retry-After": str(exc.retry_after)}
    return _response(
        request, exc.status_code, exc.code, exc.message, detail=exc.detail,
        headers=headers,
    )


async def _handle_permission_error(
    request: Request, exc: PermissionError
) -> JSONResponse:
    # Generic PermissionError (incl. domain ScopeError) -> 403. Typed API authz
    # failures are handled by _handle_api_error above.
    return _response(request, 403, AuthorizationError.code, "permission denied")


async def _handle_validation_error(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    errors = exc.errors()
    # A body that is not valid JSON at all (wrong content-type / malformed) is an
    # unsupported media type, not a field-level validation failure.
    if any(
        err.get("type") == "json_invalid"
        or "JSON decode" in str(err.get("msg", ""))
        for err in errors
    ):
        return _response(
            request,
            415,
            "unsupported_media_type",
            "request body is not valid JSON",
        )
    detail: list[dict[str, str]] = []
    for err in errors:
        location = [str(p) for p in err.get("loc", []) if p != "body"]
        detail.append(
            {"field": ".".join(location) or "body", "issue": err.get("msg", "invalid")}
        )
    return _response(
        request, 422, "validation_failed", "request body failed validation",
        detail=detail,
    )


async def _handle_competition_window_error(
    request: Request, exc: CompetitionWindowError
) -> JSONResponse:
    # Service-enforced timing-window invariant (end>start; scoring/freeze within
    # the window) -> 422 validation_failed on both create and patch paths.
    return _response(
        request,
        422,
        "validation_failed",
        "invalid competition timing window",
        detail=getattr(exc, "problems", None),
    )


async def _handle_lookup_error(request: Request, exc: LookupError) -> JSONResponse:
    return _response(request, 404, "not_found", str(exc) or "resource not found")


async def _handle_integrity_error(
    request: Request, exc: IntegrityError
) -> JSONResponse:
    # A uniqueness / FK / CHECK violation -> 409. The DB driver message can
    # embed connection/constraint internals, so it is NOT surfaced to the client.
    _logger.info("integrity conflict request_id=%s", _request_id(request))
    return _response(
        request, 409, "conflict", "the request conflicts with existing state"
    )


async def _handle_quota_exceeded(
    request: Request, exc: QuotaExceededError
) -> JSONResponse:
    return _response(request, 409, "conflict", "resource quota exceeded")


async def _handle_domain_idempotency_conflict(
    request: Request, exc: DomainIdempotencyConflictError
) -> JSONResponse:
    return _response(request, 409, "conflict", str(exc) or "idempotency conflict")


async def _handle_value_error(request: Request, exc: ValueError) -> JSONResponse:
    return _response(request, 400, "invalid_request", str(exc) or "invalid request")


async def _handle_http_exception(
    request: Request, exc: StarletteHTTPException
) -> JSONResponse:
    # Framework-raised HTTPExceptions (unknown-route 404, wrong-method 405,
    # unsupported-media 415, ...) must still be the ctfgen.error envelope. The
    # status code is preserved; the detail text is framework-generated (never a
    # secret) so it is safe to surface.
    code = _HTTP_STATUS_CODES.get(exc.status_code, "invalid_request")
    message = exc.detail if isinstance(exc.detail, str) else "request failed"
    headers = dict(exc.headers) if exc.headers else None
    return _response(request, exc.status_code, code, message, headers=headers)


async def _handle_unexpected(request: Request, exc: Exception) -> JSONResponse:
    # Log the full exception WITH the request id for correlation; return an
    # opaque body. No stack/detail/secret ever reaches the client.
    _logger.exception(
        "unhandled API exception request_id=%s", _request_id(request)
    )
    return _response(request, 500, "internal", "an internal error occurred")


def register_exception_handlers(app: FastAPI) -> None:
    """Wire every mapping onto ``app``. Order does not matter -- Starlette
    dispatches by the most specific registered class in the exception's MRO
    (so ``CompetitionWindowError`` beats the generic ``ValueError``)."""
    app.add_exception_handler(ApiError, _handle_api_error)
    app.add_exception_handler(RequestValidationError, _handle_validation_error)
    app.add_exception_handler(CompetitionWindowError, _handle_competition_window_error)
    app.add_exception_handler(IntegrityError, _handle_integrity_error)
    app.add_exception_handler(QuotaExceededError, _handle_quota_exceeded)
    app.add_exception_handler(
        DomainIdempotencyConflictError, _handle_domain_idempotency_conflict
    )
    app.add_exception_handler(LookupError, _handle_lookup_error)
    app.add_exception_handler(PermissionError, _handle_permission_error)
    app.add_exception_handler(StarletteHTTPException, _handle_http_exception)
    app.add_exception_handler(ValueError, _handle_value_error)
    app.add_exception_handler(Exception, _handle_unexpected)
