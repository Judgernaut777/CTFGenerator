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
``RequestValidationError``                   422      validation_error
``PreconditionRequiredError``                428      precondition_failed
``RateLimitedError``                         429      rate_limited (+Retry-After)
``ValueError``                               400      invalid_request
anything else                                500      internal (logged, no leak)
===========================================  =======  ====================

Worker-credential / unsupported-runtime mappings (401/409/501) land with the
slice-c worker HTTP transport; those exceptions cannot arise on slice-a routes.
"""

from __future__ import annotations

import logging

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy.exc import IntegrityError

from ctf_generator.domain.ledger.processing import (
    IdempotencyConflictError as DomainIdempotencyConflictError,
)
from ctf_generator.domain.scheduling.models import QuotaExceededError

from .context import current_request_id
from .envelopes import error_envelope
from .exceptions import ApiError, AuthorizationError, RateLimitedError

_logger = logging.getLogger("ctfgen.api")


def _response(
    status_code: int,
    code: str,
    message: str,
    *,
    detail: list[dict[str, str]] | None = None,
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    request_id = current_request_id()
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
        exc.status_code, exc.code, exc.message, detail=exc.detail, headers=headers
    )


async def _handle_permission_error(
    request: Request, exc: PermissionError
) -> JSONResponse:
    # Generic PermissionError (incl. domain ScopeError) -> 403. Typed API authz
    # failures are handled by _handle_api_error above.
    return _response(403, AuthorizationError.code, "permission denied")


async def _handle_validation_error(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    detail: list[dict[str, str]] = []
    for err in exc.errors():
        location = [str(p) for p in err.get("loc", []) if p != "body"]
        detail.append(
            {"field": ".".join(location) or "body", "issue": err.get("msg", "invalid")}
        )
    return _response(
        422, "validation_error", "request body failed validation", detail=detail
    )


async def _handle_lookup_error(request: Request, exc: LookupError) -> JSONResponse:
    return _response(404, "not_found", str(exc) or "resource not found")


async def _handle_integrity_error(
    request: Request, exc: IntegrityError
) -> JSONResponse:
    # A uniqueness / FK / CHECK violation -> 409. The DB driver message can
    # embed connection/constraint internals, so it is NOT surfaced to the client.
    _logger.info("integrity conflict request_id=%s", current_request_id())
    return _response(409, "conflict", "the request conflicts with existing state")


async def _handle_quota_exceeded(
    request: Request, exc: QuotaExceededError
) -> JSONResponse:
    return _response(409, "conflict", "resource quota exceeded")


async def _handle_domain_idempotency_conflict(
    request: Request, exc: DomainIdempotencyConflictError
) -> JSONResponse:
    return _response(409, "conflict", str(exc) or "idempotency conflict")


async def _handle_value_error(request: Request, exc: ValueError) -> JSONResponse:
    return _response(400, "invalid_request", str(exc) or "invalid request")


async def _handle_unexpected(request: Request, exc: Exception) -> JSONResponse:
    # Log the full exception WITH the request id for correlation; return an
    # opaque body. No stack/detail/secret ever reaches the client.
    _logger.exception(
        "unhandled API exception request_id=%s", current_request_id()
    )
    return _response(500, "internal", "an internal error occurred")


def register_exception_handlers(app: FastAPI) -> None:
    """Wire every mapping onto ``app``. Order does not matter -- Starlette
    dispatches by the most specific registered class in the exception's MRO."""
    app.add_exception_handler(ApiError, _handle_api_error)
    app.add_exception_handler(RequestValidationError, _handle_validation_error)
    app.add_exception_handler(IntegrityError, _handle_integrity_error)
    app.add_exception_handler(QuotaExceededError, _handle_quota_exceeded)
    app.add_exception_handler(
        DomainIdempotencyConflictError, _handle_domain_idempotency_conflict
    )
    app.add_exception_handler(LookupError, _handle_lookup_error)
    app.add_exception_handler(PermissionError, _handle_permission_error)
    app.add_exception_handler(ValueError, _handle_value_error)
    app.add_exception_handler(Exception, _handle_unexpected)
