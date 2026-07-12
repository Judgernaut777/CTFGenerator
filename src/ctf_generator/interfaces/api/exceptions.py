"""API-layer typed exceptions (framework-free).

These carry the *HTTP intent* of a failure that the domain/application layers do
not model -- authentication, authorization, and the precondition/idempotency
semantics of the HTTP contract. They deliberately do NOT import FastAPI so that
an optimistic-concurrency ``guard`` passed into an application service can raise
one without coupling the application layer to the web framework; the exception
handlers in :mod:`errors` translate each to the ``ctfgen.error`` envelope with the
right status code and stable error ``code``.

Domain/application exceptions (``LookupError``, ``ValueError``,
``IntegrityError``, ``QuotaExceededError``, ...) are mapped directly by
:mod:`errors` and are NOT re-wrapped here.
"""

from __future__ import annotations


class ApiError(Exception):
    """Base for API-layer errors carrying an HTTP status + stable code.

    ``detail`` optionally carries a list of per-field problems ``[{"field",
    "issue"}]`` for validation-style errors; it must NEVER contain secrets.
    """

    status_code: int = 500
    code: str = "internal"

    def __init__(
        self,
        message: str,
        *,
        detail: list[dict[str, str]] | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.detail = detail


class AuthenticationError(ApiError):
    """Missing or invalid credentials -> 401."""

    status_code = 401
    code = "unauthorized"


class AuthorizationError(ApiError):
    """Authenticated but lacking the required permission -> 403."""

    status_code = 403
    code = "forbidden"


class ValidationFailedError(ApiError):
    """A well-formed request that is semantically invalid -> 422. Used for
    cross-field checks (e.g. a PATCH whose merged times violate start<end) that
    Pydantic's per-request validation cannot express on a partial body."""

    status_code = 422
    code = "validation_failed"


class PreconditionRequiredError(ApiError):
    """A required ``If-Match`` precondition was not supplied -> 428."""

    status_code = 428
    code = "precondition_failed"


class PreconditionFailedError(ApiError):
    """A supplied ``If-Match`` no longer matches the resource -> 412."""

    status_code = 412
    code = "precondition_failed"


class IdempotencyConflictError(ApiError):
    """An ``Idempotency-Key`` was reused with a different request body -> 409."""

    status_code = 409
    code = "idempotency_key_reused"


class RateLimitedError(ApiError):
    """The caller exceeded its request budget -> 429. ``retry_after`` seconds is
    surfaced in the ``Retry-After`` header by the handler."""

    status_code = 429
    code = "rate_limited"

    def __init__(self, message: str, *, retry_after: int) -> None:
        super().__init__(message)
        self.retry_after = retry_after
