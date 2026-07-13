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

from ctf_generator.application.auth import AuthService
from ctf_generator.domain.repositories import ArtifactStore
from ctf_generator.infrastructure.database.config import (
    DatabaseConfig,
    DatabaseConfigError,
)
from ctf_generator.infrastructure.database.session import Database
from ctf_generator.observability import configure_logging

from .audit import AuditSink, CompositeAuditSink, DbAuditSink, LoggingAuditSink
from .db_authenticator import DbAuthenticator
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
    artifacts,
    audit,
    auth,
    builds,
    challenge_definitions,
    challenge_versions,
    competitions,
    evaluations,
    instances,
    jobs,
    oidc,
    publications,
    scoreboard,
    submissions,
    system,
    teams,
    users,
)
from .settings import ApiSettings
from .worker_gateway import router as worker_router

API_V1_PREFIX = "/api/v1"


def _artifact_store_from_env_or_none() -> ArtifactStore | None:
    """Build the artifact store from ``CTFGEN_ARTIFACT_ROOT``, or ``None`` when it is
    unset. A missing store is NOT an error -- the contestant download then resolves
    to a clean "not available" (404) rather than a 500."""
    from ctf_generator.infrastructure.artifacts.config import (
        ArtifactStoreConfigError,
        artifact_store_from_env,
    )

    try:
        return artifact_store_from_env()
    except ArtifactStoreConfigError:
        return None


def create_app(
    settings: ApiSettings | None = None,
    *,
    database: Database | None = None,
    authenticator: Authenticator | None = None,
    auth_service: AuthService | None = None,
    oidc_service=None,
    idempotency_store: IdempotencyStore | None = None,
    audit_sink: AuditSink | None = None,
    rate_limiter=None,
    artifact_store: ArtifactStore | None = None,
) -> FastAPI:
    settings = settings or ApiSettings()

    # Structured, redacted JSON logging for the API process (REQ-PLAT-009 /
    # REQ-INV-011). Idempotent, so building fixtures/apps repeatedly is a no-op
    # after the first call; it configures the ctfgen/ctf_generator logger trees
    # only (never third-party/root loggers).
    configure_logging()

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
    # The shared, app-scoped auth service (owns the password hasher + session
    # TTL). Built over the database when not injected; the /auth routes read it
    # via get_auth_service, and the module-level app shares this instance with
    # its DbAuthenticator so both agree on hashing/session policy.
    app.state.auth_service = auth_service or (
        AuthService(database) if database is not None else None
    )
    app.state.authenticator = authenticator or StubAuthenticator()
    # OIDC federated login is OPTIONAL: its router is mounted only when an
    # OidcService is provided (i.e. an OidcProviderConfig is configured). When
    # absent, the /auth/oidc/* routes simply do not exist -- a clean 404
    # (feature-disabled) envelope, and local auth is entirely unaffected.
    app.state.oidc_service = oidc_service
    app.state.idempotency_store = idempotency_store or InMemoryIdempotencyStore()
    # The default audit sink is BOTH the durable, tamper-evident DB trail (M16)
    # AND the historical log line, when a database is configured; otherwise the
    # log-only sink. The DB sink is non-fatal (its own txn, failures swallowed), so
    # co-mounting it can never turn an audited success into a 500.
    app.state.audit_sink = audit_sink or (
        CompositeAuditSink(DbAuditSink(database), LoggingAuditSink())
        if database is not None
        else LoggingAuditSink()
    )
    # The artifact store backs the contestant public-artifact download (14c-2). Built
    # from CTFGEN_ARTIFACT_ROOT when not injected, or left None (download then cleanly
    # 404s -- never a 500) when that env is unset.
    app.state.artifact_store = artifact_store or _artifact_store_from_env_or_none()

    register_exception_handlers(app)

    # Middleware. add_middleware installs OUTERMOST-last, so the request flows
    # RequestID -> AccessLog -> RateLimit -> route, and every response (including
    # error envelopes and 429s) carries X-Request-ID.
    if rate_limiter is None and settings.rate_limit_enabled:
        rate_limiter = TokenBucketLimiter(
            rate=settings.rate_limit_rate, burst=settings.rate_limit_burst
        )
    app.add_middleware(
        RateLimitMiddleware,
        limiter=rate_limiter,
        trust_forwarded_for=settings.trust_forwarded_for,
    )
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
        auth,
        competitions,
        teams,
        challenge_definitions,
        challenge_versions,
        users,
        submissions,
        scoreboard,
        instances,
        builds,
        evaluations,
        publications,
        artifacts,
        jobs,
        audit,
        system,
    ):
        app.include_router(module.router, prefix=API_V1_PREFIX)

    # OIDC federated-login routes are mounted ONLY when configured (else the
    # endpoints do not exist -> clean 404, not a broken half-wired feature).
    if oidc_service is not None:
        app.include_router(oidc.router, prefix=API_V1_PREFIX)

    # The worker-facing gateway. Included here for the single-host / dev / test
    # path; a PRODUCTION deployment SHOULD bind it to a separate interface/port via
    # ``create_worker_app`` (control-plane / worker listener separation, M18). Worker
    # auth is a plane disjoint from the human Principal auth (see worker_gateway.deps)
    # so co-mounting never weakens the boundary.
    app.include_router(worker_router, prefix=API_V1_PREFIX)

    return app


def create_worker_app(
    settings: ApiSettings | None = None,
    *,
    database: Database | None = None,
    audit_sink: AuditSink | None = None,
    rate_limiter=None,
) -> FastAPI:
    """Build a FastAPI app exposing ONLY the worker gateway.

    This is the production-recommended shape: serve the worker gateway on a
    SEPARATE listener from the human control-plane API so the two trust planes are
    also network-isolated. It shares the ``ctfgen.error`` envelope, the request-id
    middleware, and the rate limiter, but wires NO human authenticator and NO
    resource routers -- a human Principal token has nothing to reach here. Worker
    identity is resolved solely from the scoped credential inside the gated
    services."""
    settings = settings or ApiSettings()

    configure_logging()

    app = FastAPI(
        title=f"{settings.title} (Worker Gateway)",
        version=settings.version,
        root_path=settings.root_path,
        openapi_url=f"{API_V1_PREFIX}/openapi.json",
        docs_url=f"{API_V1_PREFIX}/docs",
        redoc_url=f"{API_V1_PREFIX}/redoc",
    )
    app.state.database = database
    # Durable + log audit trail on the worker gateway too (its denied-worker-auth
    # events then persist), non-fatal when the DB is unreachable.
    app.state.audit_sink = audit_sink or (
        CompositeAuditSink(DbAuditSink(database), LoggingAuditSink())
        if database is not None
        else LoggingAuditSink()
    )

    register_exception_handlers(app)

    if rate_limiter is None and settings.rate_limit_enabled:
        rate_limiter = TokenBucketLimiter(
            rate=settings.rate_limit_rate, burst=settings.rate_limit_burst
        )
    app.add_middleware(
        RateLimitMiddleware,
        limiter=rate_limiter,
        trust_forwarded_for=settings.trust_forwarded_for,
    )
    app.add_middleware(AccessLogMiddleware)
    app.add_middleware(RequestIDMiddleware)

    app.include_router(worker_router, prefix=API_V1_PREFIX)
    return app


def _authenticator_from_env(auth_service: AuthService | None) -> Authenticator:
    """Build the authenticator for the module-level (production) app.

    The PRODUCTION default is the real :class:`DbAuthenticator` over the shared
    :class:`AuthService` -- it resolves a Bearer session token to a Principal from
    real data (M10a). The insecure ``StubAuthenticator`` is used ONLY when
    ``CTFGEN_API_INSECURE_STUB_AUTH=1`` is explicitly set (dev/test escape hatch):
    with the flag set and ``CTFGEN_API_DEV_TOKEN`` present it registers an admin
    principal and emits a prominent warning. Without a configured database (no
    auth service) and without the flag, an empty stub authenticates nothing (every
    request is 401) rather than silently trusting anyone. No token is ever
    logged/echoed."""
    if os.environ.get("CTFGEN_API_INSECURE_STUB_AUTH") == "1":
        stub = StubAuthenticator()
        token = os.environ.get("CTFGEN_API_DEV_TOKEN")
        if token:
            logging.getLogger("ctfgen.api").warning(
                "INSECURE: stub bearer auth enabled -- never use in production"
            )
            stub.register(token, principal_for("dev-admin", {"admin"}))
        return stub
    if auth_service is not None:
        return DbAuthenticator(auth_service)
    # No database configured: nothing can authenticate (fail closed).
    return StubAuthenticator()


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
def _oidc_service_from_env(database: Database | None, auth_service: AuthService | None):
    """Build the OIDC federated-login service for the module-level (production)
    app, or ``None`` when OIDC is not configured (no ``CTFGEN_OIDC_*`` env) or the
    prerequisites (a database + auth service) are absent. A present-but-invalid
    OIDC config fails fast (``OidcConfigurationError``) rather than silently
    disabling the feature. NEVER logs the client_secret."""
    if database is None or auth_service is None:
        return None
    from ctf_generator.application.auth.oidc import OidcProviderConfig, OidcService

    config = OidcProviderConfig.from_env()
    if config is None:
        return None
    return OidcService(config, database, auth_service)


def _maybe_mount_web_app(
    api_app: FastAPI,
    database: Database | None,
    auth_service: AuthService | None,
) -> None:
    """Mount the M11 organizer web UI on the module-level (production) app under
    ``/app`` when it is enabled and its prerequisites (a database + auth service +
    the ``[web]`` extra) are present.

    The import is LAZY + guarded so a deployment WITHOUT jinja2 (the ``[web]``
    extra) still imports this module and serves the JSON API unaffected -- the UI
    simply does not exist. Disabled explicitly via ``CTFGEN_WEB_ENABLED=0``. The
    mounted sub-app owns its own middleware/handlers and is absent from
    ``/api/v1/openapi.json`` (the JSON API surface is unchanged)."""
    if database is None or auth_service is None:
        return
    if os.environ.get("CTFGEN_WEB_ENABLED", "1") == "0":
        return
    try:
        from ..web import mount_web_app
        from ..web.settings import WebSettings
    except ImportError:
        logging.getLogger("ctfgen.web").info(
            "organizer web UI disabled: the [web] extra (jinja2) is not installed"
        )
        return
    mount_web_app(
        api_app,
        database=database,
        auth_service=auth_service,
        settings=WebSettings.from_env(),
        # Share the parent app's artifact store so the contestant download works on
        # the mounted UI (both otherwise build the same store from the same env).
        artifact_store=getattr(api_app.state, "artifact_store", None),
    )


_module_database = _database_from_env()
_module_auth_service = (
    AuthService(_module_database) if _module_database is not None else None
)
app = create_app(
    ApiSettings(
        rate_limit_enabled=os.environ.get("CTFGEN_API_RATE_LIMIT", "1") != "0",
        trust_forwarded_for=os.environ.get("CTFGEN_API_TRUSTED_PROXY", "0") == "1",
    ),
    database=_module_database,
    auth_service=_module_auth_service,
    authenticator=_authenticator_from_env(_module_auth_service),
    oidc_service=_oidc_service_from_env(_module_database, _module_auth_service),
)
_maybe_mount_web_app(app, _module_database, _module_auth_service)
