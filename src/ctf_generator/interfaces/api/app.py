"""Application factory + module-level ASGI app.

``create_app`` wires the routers, middleware, and exception handlers over injected
collaborators (database, authenticator, idempotency store, audit sink, rate
limiter) so tests can supply fakes/fixtures. The module-level ``app`` builds those
collaborators from the environment for ``uvicorn ctf_generator.interfaces.api.app:app``.

Layering: handlers are thin over the application services (which own the unit of
work). This factory owns NO business logic -- only composition.
"""

from __future__ import annotations

import logging
import os

from fastapi import FastAPI
from starlette.middleware.cors import CORSMiddleware

from ctf_generator.infrastructure.database.config import (
    DatabaseConfig,
    DatabaseConfigError,
)
from ctf_generator.infrastructure.database.session import Database

from .audit import AuditSink, LoggingAuditSink
from .deps import Authenticator, StubAuthenticator, principal_for
from .errors import register_exception_handlers
from .idempotency import IdempotencyStore, InMemoryIdempotencyStore
from .middleware import (
    AccessLogMiddleware,
    RateLimitMiddleware,
    RequestIDMiddleware,
    TokenBucketLimiter,
)
from .routers import (
    builds,
    challenge_definitions,
    challenge_versions,
    competitions,
    instances,
    jobs,
    publications,
    scoreboard,
    submissions,
    system,
    teams,
    users,
)
from .settings import ApiSettings

API_V1_PREFIX = "/api/v1"


def create_app(
    settings: ApiSettings | None = None,
    *,
    database: Database | None = None,
    authenticator: Authenticator | None = None,
    idempotency_store: IdempotencyStore | None = None,
    audit_sink: AuditSink | None = None,
    rate_limiter=None,
) -> FastAPI:
    settings = settings or ApiSettings()

    app = FastAPI(
        title=settings.title,
        version=settings.version,
        root_path=settings.root_path,
        openapi_url=f"{API_V1_PREFIX}/openapi.json",
        docs_url=f"{API_V1_PREFIX}/docs",
        redoc_url=f"{API_V1_PREFIX}/redoc",
    )

    # Injected collaborators live on app.state; the dependencies read them.
    app.state.database = database
    app.state.authenticator = authenticator or StubAuthenticator()
    app.state.idempotency_store = idempotency_store or InMemoryIdempotencyStore()
    app.state.audit_sink = audit_sink or LoggingAuditSink()

    register_exception_handlers(app)

    # Middleware. add_middleware installs OUTERMOST-last, so the request flows
    # RequestID -> AccessLog -> RateLimit -> route, and every response (including
    # error envelopes and 429s) carries X-Request-ID.
    if rate_limiter is None and settings.rate_limit_enabled:
        rate_limiter = TokenBucketLimiter(
            rate=settings.rate_limit_rate, burst=settings.rate_limit_burst
        )
    app.add_middleware(RateLimitMiddleware, limiter=rate_limiter)
    app.add_middleware(AccessLogMiddleware)
    app.add_middleware(RequestIDMiddleware)
    if settings.cors_allow_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=list(settings.cors_allow_origins),
            allow_methods=["*"],
            allow_headers=["*"],
        )

    for module in (
        competitions,
        teams,
        challenge_definitions,
        challenge_versions,
        users,
        submissions,
        scoreboard,
        instances,
        builds,
        publications,
        jobs,
        system,
    ):
        app.include_router(module.router, prefix=API_V1_PREFIX)

    return app


def _authenticator_from_env() -> Authenticator:
    """Build the stub authenticator for the module-level app.

    The insecure dev bearer token from ``CTFGEN_API_DEV_TOKEN`` is registered
    ONLY when ``CTFGEN_API_INSECURE_STUB_AUTH=1`` is explicitly set -- so the stub
    can never be a silent production default. With the flag set and a token
    present it registers an admin principal and emits a prominent warning; without
    the flag no token authenticates (every request is 401 until M10 wires real
    auth). The token value is never logged or echoed."""
    stub = StubAuthenticator()
    if os.environ.get("CTFGEN_API_INSECURE_STUB_AUTH") == "1":
        token = os.environ.get("CTFGEN_API_DEV_TOKEN")
        if token:
            logging.getLogger("ctfgen.api").warning(
                "INSECURE: stub bearer auth enabled -- never use in production"
            )
            stub.register(token, principal_for("dev-admin", {"admin"}))
    return stub


def _database_from_env() -> Database | None:
    try:
        return Database(DatabaseConfig.from_env())
    except DatabaseConfigError:
        # No DSN configured: build the app so OpenAPI/import work; data routes
        # raise a clear 500 until a database is configured.
        return None


# Module-level ASGI app for `uvicorn ...:app`. Rate limiting defaults ON here
# (opt-OUT via CTFGEN_API_RATE_LIMIT=0) so the shipped production app is never
# unthrottled; the create_app/test injection path keeps ApiSettings' False
# default so the unit/OpenAPI suites stay unthrottled.
app = create_app(
    ApiSettings(
        rate_limit_enabled=os.environ.get("CTFGEN_API_RATE_LIMIT", "1") != "0",
    ),
    database=_database_from_env(),
    authenticator=_authenticator_from_env(),
)
