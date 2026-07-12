"""The organizer web routes (M11 slice a).

Thin handlers: resolve the cookie session to a :class:`Principal`, call ONE
application service, map the result to a view dict, and render a template. No
business logic, no session lifecycle, no ORM leakage. Authorization is the SAME
M10b scoping as the JSON API -- an organizer sees only its own competitions
(``authorized_competitions``), and an unauthorized competition detail is an
existence-hiding 404 (``assert_competition_permission_or_404``), never a 403 that
would confirm the competition exists.

Routes (paths are relative to the sub-app; mounted at ``/app`` they become
``/app/login`` etc.):

* ``GET  /login``   -- the login form.
* ``POST /login``   -- authenticate; set the session cookie; redirect to ``/app``.
* ``POST /logout``  -- CSRF-protected; revoke the session + clear the cookie.
* ``GET  /``        -- the dashboard (the caller's competitions + quick counts).
* ``GET  /competitions``               -- the caller's competitions (list).
* ``GET  /competitions/{competition_id}`` -- one competition's config (detail).
"""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Request
from starlette.responses import RedirectResponse, Response

from ctf_generator.application.auth import AuthService, InvalidCredentialsError
from ctf_generator.application.catalog import CompetitionService
from ctf_generator.interfaces.api.deps import (
    Permission,
    Principal,
    assert_competition_permission_or_404,
    authorized_competitions,
)

from .auth import (
    clear_session_cookie,
    get_web_principal,
    logout_session,
    set_session_cookie,
)
from .csrf import require_csrf
from .deps import (
    get_web_auth_service,
    get_web_competition_service,
    get_web_settings,
)
from .formdata import read_form
from .rendering import TemplateRenderer, get_renderer
from .settings import WebSettings
from .views import competition_detail, competition_row

router = APIRouter()

_NOT_FOUND = "Competition not found"


def _login_url(request: Request, settings: WebSettings) -> str:
    """The absolute path to the login form, mount-aware."""
    try:
        return str(request.url_for("web_login"))
    except Exception:  # pragma: no cover - url_for needs the router in scope
        return f"{settings.mount_path}/login"


def _visible_competitions(principal: Principal, service: CompetitionService):
    """The competitions the caller may read, applying the EXACT M10b filter the
    API's ``GET /competitions`` uses: a system role sees all; anyone else sees only
    the competitions whose membership grants ``competition:read``."""
    configs = service.list()
    allowed = authorized_competitions(principal, Permission.COMPETITION_READ)
    if allowed is not None:
        configs = [c for c in configs if c.competition_id in allowed]
    return sorted(configs, key=lambda c: c.competition_id)


# -- authentication ---------------------------------------------------------


@router.get("/login", name="web_login")
def login_form(
    request: Request,
    renderer: TemplateRenderer = Depends(get_renderer),
) -> Response:
    return renderer.render(request, "login.html", {"error": None})


@router.post("/login", name="web_login_submit")
async def login_submit(
    request: Request,
    renderer: TemplateRenderer = Depends(get_renderer),
    settings: WebSettings = Depends(get_web_settings),
    auth_service: AuthService = Depends(get_web_auth_service),
) -> Response:
    form = await read_form(request)
    email = form.get("email", "")
    password = form.get("password", "")
    now = datetime.now(UTC)
    try:
        issued = auth_service.authenticate(email, password, now)
    except InvalidCredentialsError:
        # Generic error, NO cookie set, no disclosure of which field was wrong.
        return renderer.render(
            request,
            "login.html",
            {"error": "Invalid email or password."},
            status_code=401,
        )
    response = RedirectResponse(
        url=str(request.url_for("web_dashboard")), status_code=303
    )
    set_session_cookie(
        response, issued.token, settings, now=now, expires_at=issued.expires_at
    )
    return response


@router.post("/logout", name="web_logout")
async def logout(
    request: Request,
    settings: WebSettings = Depends(get_web_settings),
    _principal: Principal = Depends(get_web_principal),
    _csrf: None = Depends(require_csrf),
) -> Response:
    logout_session(request, settings)
    response = RedirectResponse(url=_login_url(request, settings), status_code=303)
    clear_session_cookie(response, settings)
    return response


# -- read views -------------------------------------------------------------


@router.get("/", name="web_dashboard")
def dashboard(
    request: Request,
    principal: Principal = Depends(get_web_principal),
    renderer: TemplateRenderer = Depends(get_renderer),
    service: CompetitionService = Depends(get_web_competition_service),
) -> Response:
    configs = _visible_competitions(principal, service)
    context = {
        "competitions": [competition_row(c) for c in configs],
        "competition_count": len(configs),
    }
    return renderer.render(request, "dashboard.html", context, principal=principal)


@router.get("/competitions", name="web_competitions")
def competitions_list(
    request: Request,
    principal: Principal = Depends(get_web_principal),
    renderer: TemplateRenderer = Depends(get_renderer),
    service: CompetitionService = Depends(get_web_competition_service),
) -> Response:
    configs = _visible_competitions(principal, service)
    context = {"competitions": [competition_row(c) for c in configs]}
    return renderer.render(
        request, "competitions_list.html", context, principal=principal
    )


@router.get("/competitions/{competition_id}", name="web_competition_detail")
def competition_detail_view(
    competition_id: str,
    request: Request,
    principal: Principal = Depends(get_web_principal),
    renderer: TemplateRenderer = Depends(get_renderer),
    service: CompetitionService = Depends(get_web_competition_service),
) -> Response:
    # Authorize FIRST, surfacing a denial as the same generic 404 as a nonexistent
    # id -- so "exists but you can't see it" is indistinguishable from "does not
    # exist" (no existence oracle, no config/flag leak).
    assert_competition_permission_or_404(
        principal, competition_id, Permission.COMPETITION_READ, not_found=_NOT_FOUND
    )
    config = service.get(competition_id)
    if config is None:
        raise LookupError(_NOT_FOUND)
    context = {"competition": competition_detail(config)}
    return renderer.render(
        request, "competition_detail.html", context, principal=principal
    )
