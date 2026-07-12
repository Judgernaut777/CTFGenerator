"""The web sub-application factory + mount helper (M11 slice a).

``create_web_app`` builds a self-contained FastAPI app for the organizer HTML UI:
its own security-headers middleware, its own HTML error handlers (a friendly page,
never the JSON ``ctfgen.error`` envelope), and its own ``app.state`` collaborators
(database + shared M10 ``AuthService`` + renderer + web settings). It can be served
on its own listener OR mounted on the main API app under ``/app`` via
``mount_web_app`` -- a mounted sub-app does NOT appear in the parent's
``/api/v1/openapi.json`` (the two surfaces stay cleanly separated).

The API app imports this module LAZILY + guarded, so a deployment without the
``[web]`` extra (jinja2) simply runs the JSON API with no UI and no import error.
"""

from __future__ import annotations

import logging

from fastapi import FastAPI, Request
from starlette.responses import RedirectResponse, Response

from ctf_generator.application.auth import AuthService
from ctf_generator.infrastructure.database.session import Database
from ctf_generator.interfaces.api.exceptions import (
    AuthenticationError,
    AuthorizationError,
)

from .auth import WebAuthRequired
from .csrf import WebCsrfError
from .rendering import TemplateRenderer
from .router import router
from .security import SecurityHeadersMiddleware
from .settings import WebSettings

_logger = logging.getLogger("ctfgen.web")


def _error_page(
    request: Request, status_code: int, title: str, message: str
) -> Response:
    """Render the generic HTML error page (leaking nothing). Falls back to a bare
    text response if the renderer is somehow unavailable."""
    renderer: TemplateRenderer | None = getattr(
        request.app.state, "web_renderer", None
    )
    if renderer is None:  # pragma: no cover - misconfiguration guard
        return Response(message, status_code=status_code, media_type="text/plain")
    return renderer.render(
        request,
        "error.html",
        {"title": title, "message": message, "status_code": status_code},
        status_code=status_code,
    )


def _register_handlers(app: FastAPI) -> None:
    async def _auth_required(request: Request, exc: WebAuthRequired) -> Response:
        # Unauthenticated UI page -> redirect the browser to the login form
        # (a 302, NOT a JSON 401). No token is read into the URL.
        settings: WebSettings = request.app.state.web_settings
        try:
            login = str(request.url_for("web_login"))
        except Exception:  # pragma: no cover
            login = f"{settings.mount_path}/login"
        return RedirectResponse(url=login, status_code=302)

    async def _csrf_failed(request: Request, exc: WebCsrfError) -> Response:
        return _error_page(
            request, 403, "Request blocked",
            "This request could not be verified. Please reload the page and try again.",
        )

    async def _forbidden(request: Request, exc: Exception) -> Response:
        return _error_page(
            request, 403, "Forbidden",
            "You do not have access to this resource.",
        )

    async def _not_found(request: Request, exc: LookupError) -> Response:
        return _error_page(
            request, 404, "Not found",
            str(exc) or "The requested resource was not found.",
        )

    async def _unexpected(request: Request, exc: Exception) -> Response:
        # Log with no body leak; the page carries a generic message only.
        _logger.exception("unhandled web exception path=%s", request.url.path)
        return _error_page(
            request, 500, "Something went wrong",
            "An internal error occurred. Please try again later.",
        )

    app.add_exception_handler(WebAuthRequired, _auth_required)
    app.add_exception_handler(WebCsrfError, _csrf_failed)
    app.add_exception_handler(AuthorizationError, _forbidden)
    app.add_exception_handler(AuthenticationError, _forbidden)
    app.add_exception_handler(PermissionError, _forbidden)
    app.add_exception_handler(LookupError, _not_found)
    app.add_exception_handler(Exception, _unexpected)


def create_web_app(
    *,
    database: Database,
    auth_service: AuthService,
    settings: WebSettings | None = None,
    renderer: TemplateRenderer | None = None,
) -> FastAPI:
    """Build the organizer web sub-app over the SAME database + M10 auth service."""
    settings = settings or WebSettings()
    app = FastAPI(
        title="CTFGenerator Organizer",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.database = database
    app.state.auth_service = auth_service
    app.state.web_settings = settings
    app.state.web_renderer = renderer or TemplateRenderer()

    app.add_middleware(SecurityHeadersMiddleware)
    _register_handlers(app)
    app.include_router(router)
    return app


def mount_web_app(
    api_app: FastAPI,
    *,
    database: Database,
    auth_service: AuthService,
    settings: WebSettings | None = None,
    mount_path: str = "/app",
) -> FastAPI:
    """Mount the web sub-app on ``api_app`` at ``mount_path`` (default ``/app``).

    The mounted sub-app carries its OWN middleware + error handlers + state and is
    absent from the parent's OpenAPI schema, so the JSON API surface is unchanged.
    Returns the created web app (for tests)."""
    settings = settings or WebSettings(mount_path=mount_path)
    web_app = create_web_app(
        database=database, auth_service=auth_service, settings=settings
    )
    api_app.mount(mount_path, web_app)
    return web_app
