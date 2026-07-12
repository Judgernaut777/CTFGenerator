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

import dataclasses
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Request
from sqlalchemy.exc import IntegrityError
from starlette.responses import RedirectResponse, Response

from ctf_generator.application.auth import AuthService, InvalidCredentialsError
from ctf_generator.application.catalog import (
    ChallengeDefinitionService,
    ChallengeVersionService,
    CompetitionService,
    TeamService,
)
from ctf_generator.application.catalog.competition_service import (
    CompetitionWindowError,
)
from ctf_generator.application.catalog.publication_service import PublicationService
from ctf_generator.domain.authoring.models import ChallengePublication
from ctf_generator.domain.challenges.models import CompetitionConfig
from ctf_generator.domain.identity.models import Team
from ctf_generator.interfaces.api.deps import (
    Permission,
    Principal,
    assert_competition_permission_or_404,
    authorized_competitions,
    competition_permissions,
)
from ctf_generator.interfaces.api.exceptions import AuthorizationError

from .auth import (
    clear_session_cookie,
    get_web_principal,
    logout_session,
    set_session_cookie,
)
from .csrf import (
    clear_login_csrf_cookie,
    current_login_csrf_token,
    issue_login_csrf_token,
    require_csrf,
    require_login_csrf,
    set_login_csrf_cookie,
)
from .deps import (
    get_web_auth_service,
    get_web_challenge_definition_service,
    get_web_challenge_version_service,
    get_web_competition_service,
    get_web_publication_service,
    get_web_settings,
    get_web_team_service,
)
from .formdata import read_form
from .rendering import TemplateRenderer, get_renderer
from .settings import WebSettings
from .views import (
    competition_detail,
    competition_form_values,
    competition_row,
    publication_row,
    team_row,
)

router = APIRouter()

_NOT_FOUND = "Competition not found"
_PUBLICATION_NOT_FOUND = "Publication not found"

_COMPETITION_FIELDS = (
    "competition_id",
    "name",
    "start_time",
    "end_time",
    "scoring_start_time",
    "freeze_time",
)


# -- write-handler helpers --------------------------------------------------
#
# These keep every POST handler thin (auth + CSRF + one service call + a render or
# a 303 redirect). They never touch a secret; the ONLY values they read from a form
# are the public timing/name/slug fields, and a domain/validation failure is turned
# into a per-field message that is re-rendered (autoescaped) with the user's input
# preserved -- never a 500.


def _require_flat(principal: Principal, permission: Permission) -> None:
    """Enforce a FLAT (non-competition-scoped) permission, mirroring the API's
    ``require_permission``. Used for competition CREATE, which cannot be scoped to a
    pre-existing membership. Raises :class:`AuthorizationError` (-> 403 page)."""
    if not principal.has(permission):
        raise AuthorizationError(
            f"principal lacks required permission {permission.value!r}"
        )


def _redirect(request: Request, name: str, **params: str) -> RedirectResponse:
    """A POST-redirect-GET 303 to a named route (mount-aware via ``url_for``)."""
    try:
        url = str(request.url_for(name, **params))
    except Exception:  # pragma: no cover - url_for needs the router in scope
        url = request.url.path
    return RedirectResponse(url=url, status_code=303)


def _parse_dt(
    raw: str | None, field: str, errors: dict[str, str], *, required: bool
) -> datetime | None:
    """Parse an ``<input type=datetime-local>`` value into a tz-aware UTC datetime.
    Records a per-field message (and returns ``None``) on a missing-but-required or
    unparseable value, so the caller re-renders rather than 500-ing."""
    raw = (raw or "").strip()
    if not raw:
        if required:
            errors[field] = "Required."
        return None
    try:
        value = datetime.fromisoformat(raw)
    except ValueError:
        errors[field] = "Enter a valid date and time."
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value


def _competition_form_input(form: dict[str, str]) -> dict[str, str]:
    """The raw (stripped) competition form fields, preserved verbatim for re-render."""
    return {field: form.get(field, "").strip() for field in _COMPETITION_FIELDS}


def _competition_from_input(
    values: dict[str, str],
    *,
    competition_id: str,
    errors: dict[str, str],
    base: CompetitionConfig | None = None,
) -> CompetitionConfig | None:
    """Build a :class:`CompetitionConfig` from form input, collecting per-field
    errors. On edit (``base`` given) the immutable id + any unmodelled fields
    (e.g. ``default_scoring``) are carried over via ``dataclasses.replace``. Returns
    ``None`` (leaving ``errors`` populated) if any field is missing/invalid. The
    timing-window invariant itself is enforced by the SERVICE, not here."""
    name = values.get("name", "").strip()
    if base is None and not (competition_id or "").strip():
        errors["competition_id"] = "Required."
    if not name:
        errors["name"] = "Required."
    start = _parse_dt(values.get("start_time"), "start_time", errors, required=True)
    end = _parse_dt(values.get("end_time"), "end_time", errors, required=True)
    scoring = _parse_dt(
        values.get("scoring_start_time"), "scoring_start_time", errors, required=False
    )
    freeze = _parse_dt(
        values.get("freeze_time"), "freeze_time", errors, required=False
    )
    if errors:
        return None
    assert start is not None and end is not None  # noqa: S101 - guarded above
    if base is not None:
        return dataclasses.replace(
            base,
            name=name,
            start_time=start,
            end_time=end,
            scoring_start_time=scoring,
            freeze_time=freeze,
        )
    return CompetitionConfig(
        competition_id=competition_id.strip(),
        name=name,
        start_time=start,
        end_time=end,
        scoring_start_time=scoring,
        freeze_time=freeze,
    )


def _apply_window_problems(
    exc: CompetitionWindowError, errors: dict[str, str]
) -> None:
    """Fold the service's ``{field, issue}`` timing-window problems into per-field
    form errors (the messages are autoescaped when rendered)."""
    for problem in exc.problems:
        errors.setdefault(problem["field"], problem["issue"])


def _render_competition_form(
    request: Request,
    renderer: TemplateRenderer,
    principal: Principal,
    *,
    values: dict[str, str],
    errors: dict[str, str],
    mode: str,
    competition_id: str | None = None,
    status_code: int = 200,
) -> Response:
    if mode == "create":
        context = {
            "heading": "New competition",
            "form_action": str(request.url_for("web_competition_create")),
            "submit_label": "Create competition",
            "cancel_url": str(request.url_for("web_competitions")),
            "id_editable": True,
        }
    else:
        context = {
            "heading": "Edit competition",
            "form_action": str(
                request.url_for("web_competition_update", competition_id=competition_id)
            ),
            "submit_label": "Save changes",
            "cancel_url": str(
                request.url_for("web_competition_detail", competition_id=competition_id)
            ),
            "id_editable": False,
        }
    context.update({"values": values, "errors": errors})
    return renderer.render(
        request, "competition_form.html", context,
        principal=principal, status_code=status_code,
    )


def _render_teams(
    request: Request,
    renderer: TemplateRenderer,
    principal: Principal,
    service: TeamService,
    competition_id: str,
    *,
    values: dict[str, str],
    errors: dict[str, str],
    status_code: int = 200,
) -> Response:
    teams = sorted(
        service.list_for_competition(competition_id), key=lambda t: t.name
    )
    context = {
        "competition_id": competition_id,
        "teams": [team_row(t) for t in teams],
        "values": values,
        "errors": errors,
    }
    return renderer.render(
        request, "teams.html", context,
        principal=principal, status_code=status_code,
    )


def _version_choices(
    def_service: ChallengeDefinitionService,
    ver_service: ChallengeVersionService,
) -> list[dict[str, str]]:
    """The published (definition, version) pairs an organizer may attach, as
    ``{value, label}`` option dicts. Only ``published`` versions are offered."""
    titles = {d.slug: d.title for d in def_service.list()}
    choices: list[dict[str, str]] = []
    for slug in sorted(titles):
        for version in ver_service.list_for_definition(slug):
            if version.state != "published":
                continue
            choices.append(
                {
                    "value": f"{slug}:{version.version_no}",
                    "label": f"{titles[slug]} — {slug} v{version.version_no}",
                }
            )
    choices.sort(key=lambda c: c["value"])
    return choices


def _parse_publication_target(
    target: str, errors: dict[str, str]
) -> tuple[str, int] | None:
    """Parse the ``slug:version_no`` select value. A malformed value is a field
    error (re-render), never a 500."""
    slug, sep, raw_version = target.rpartition(":")
    if not sep or not slug:
        errors["publication_target"] = "Choose a challenge version."
        return None
    try:
        version_no = int(raw_version)
    except ValueError:
        errors["publication_target"] = "Choose a challenge version."
        return None
    if version_no < 1:
        errors["publication_target"] = "Choose a challenge version."
        return None
    return slug, version_no


def _render_publications(
    request: Request,
    renderer: TemplateRenderer,
    principal: Principal,
    competition_id: str,
    pub_service: PublicationService,
    def_service: ChallengeDefinitionService,
    ver_service: ChallengeVersionService,
    *,
    values: dict[str, str],
    errors: dict[str, str],
    status_code: int = 200,
) -> Response:
    publications = sorted(
        pub_service.list_for_competition(competition_id),
        key=lambda p: (p.definition_slug, p.version_no),
    )
    context = {
        "competition_id": competition_id,
        "publications": [publication_row(p) for p in publications],
        "version_choices": _version_choices(def_service, ver_service),
        "values": values,
        "errors": errors,
    }
    return renderer.render(
        request, "publications.html", context,
        principal=principal, status_code=status_code,
    )


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
    settings: WebSettings = Depends(get_web_settings),
) -> Response:
    # Mint the login-CSRF token: echo it into BOTH the (httpOnly) cookie and the
    # hidden field so POST /login can verify the double-submit pair.
    token = issue_login_csrf_token()
    response = renderer.render(
        request, "login.html", {"error": None, "login_csrf_token": token}
    )
    set_login_csrf_cookie(response, token, settings)
    return response


@router.post("/login", name="web_login_submit")
async def login_submit(
    request: Request,
    renderer: TemplateRenderer = Depends(get_renderer),
    settings: WebSettings = Depends(get_web_settings),
    auth_service: AuthService = Depends(get_web_auth_service),
    _login_csrf: None = Depends(require_login_csrf),
) -> Response:
    # ``require_login_csrf`` has already rejected a missing/forged login-CSRF token
    # (403) BEFORE we reach here, so login-CSRF / session fixation is closed.
    form = await read_form(request)
    email = form.get("email", "")
    password = form.get("password", "")
    now = datetime.now(UTC)
    try:
        issued = auth_service.authenticate(email, password, now)
    except InvalidCredentialsError:
        # Generic error, NO cookie touched (the failure response stays byte-for-byte
        # the same shape it always had -- no Set-Cookie), no disclosure of which
        # field was wrong. The existing login-CSRF cookie (verified present by the
        # dependency) is re-rendered into the form so it stays submittable.
        return renderer.render(
            request,
            "login.html",
            {
                "error": "Invalid email or password.",
                "login_csrf_token": current_login_csrf_token(request),
            },
            status_code=401,
        )
    response = RedirectResponse(
        url=str(request.url_for("web_dashboard")), status_code=303
    )
    set_session_cookie(
        response, issued.token, settings, now=now, expires_at=issued.expires_at
    )
    # The login-CSRF token is single-use: drop it once the session is established.
    clear_login_csrf_cookie(response, settings)
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
        "can_create": principal.has(Permission.COMPETITION_WRITE),
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
    context = {
        "competitions": [competition_row(c) for c in configs],
        "can_create": principal.has(Permission.COMPETITION_WRITE),
    }
    return renderer.render(
        request, "competitions_list.html", context, principal=principal
    )


# -- competition create (write) --------------------------------------------
#
# NOTE ON ROUTE ORDER: ``/competitions/new`` is registered BEFORE
# ``/competitions/{competition_id}`` (Starlette matches in registration order), so
# ``new`` is not swallowed as a competition id. The deeper write routes
# (``/competitions/{competition_id}/edit`` etc.) live below the detail route --
# they are one segment longer and never collide with it.


@router.get("/competitions/new", name="web_competition_new")
def competition_new_form(
    request: Request,
    principal: Principal = Depends(get_web_principal),
    renderer: TemplateRenderer = Depends(get_renderer),
) -> Response:
    # Creating a NEW competition is NOT competition-scoped (no pre-existing
    # membership to scope to), so -- exactly like the API's flat
    # ``require_permission`` on ``POST /competitions`` -- it is gated on the FLAT
    # competition:write, not the per-competition check. An organizer holds it via
    # its role; a contestant does not (403).
    _require_flat(principal, Permission.COMPETITION_WRITE)
    return _render_competition_form(
        request, renderer, principal, values={}, errors={}, mode="create"
    )


@router.post("/competitions/new", name="web_competition_create")
async def competition_create(
    request: Request,
    principal: Principal = Depends(get_web_principal),
    renderer: TemplateRenderer = Depends(get_renderer),
    service: CompetitionService = Depends(get_web_competition_service),
    _csrf: None = Depends(require_csrf),
) -> Response:
    _require_flat(principal, Permission.COMPETITION_WRITE)
    form = await read_form(request)
    values = _competition_form_input(form)
    errors: dict[str, str] = {}
    config = _competition_from_input(values, competition_id=values["competition_id"], errors=errors)
    if errors or config is None:
        return _render_competition_form(
            request, renderer, principal, values=values, errors=errors,
            mode="create", status_code=400,
        )
    try:
        stored = service.create(config)
    except CompetitionWindowError as exc:
        _apply_window_problems(exc, errors)
        return _render_competition_form(
            request, renderer, principal, values=values, errors=errors,
            mode="create", status_code=400,
        )
    except IntegrityError:
        errors["competition_id"] = "A competition with this ID already exists."
        return _render_competition_form(
            request, renderer, principal, values=values, errors=errors,
            mode="create", status_code=409,
        )
    return _redirect(request, "web_competition_detail", competition_id=stored.competition_id)


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
    can_manage = Permission.COMPETITION_WRITE in competition_permissions(
        principal, competition_id
    )
    context = {"competition": competition_detail(config), "can_manage": can_manage}
    return renderer.render(
        request, "competition_detail.html", context, principal=principal
    )


# -- competition edit + team + publication write handlers -------------------


@router.get("/competitions/{competition_id}/edit", name="web_competition_edit")
def competition_edit_form(
    competition_id: str,
    request: Request,
    principal: Principal = Depends(get_web_principal),
    renderer: TemplateRenderer = Depends(get_renderer),
    service: CompetitionService = Depends(get_web_competition_service),
) -> Response:
    # Existence-hiding 404 on a denial (matching the detail view): a competition
    # the caller cannot write is indistinguishable from one that does not exist.
    assert_competition_permission_or_404(
        principal, competition_id, Permission.COMPETITION_WRITE, not_found=_NOT_FOUND
    )
    config = service.get(competition_id)
    if config is None:
        raise LookupError(_NOT_FOUND)
    return _render_competition_form(
        request, renderer, principal,
        values=competition_form_values(config), errors={},
        mode="edit", competition_id=competition_id,
    )


@router.post("/competitions/{competition_id}/edit", name="web_competition_update")
async def competition_update(
    competition_id: str,
    request: Request,
    principal: Principal = Depends(get_web_principal),
    renderer: TemplateRenderer = Depends(get_renderer),
    service: CompetitionService = Depends(get_web_competition_service),
    _csrf: None = Depends(require_csrf),
) -> Response:
    assert_competition_permission_or_404(
        principal, competition_id, Permission.COMPETITION_WRITE, not_found=_NOT_FOUND
    )
    current = service.get(competition_id)
    if current is None:
        raise LookupError(_NOT_FOUND)
    form = await read_form(request)
    values = _competition_form_input(form)
    values["competition_id"] = competition_id  # immutable; ignore any submitted id
    errors: dict[str, str] = {}
    merged = _competition_from_input(
        values, competition_id=competition_id, errors=errors, base=current
    )
    if errors or merged is None:
        return _render_competition_form(
            request, renderer, principal, values=values, errors=errors,
            mode="edit", competition_id=competition_id, status_code=400,
        )
    try:
        service.update(merged)
    except CompetitionWindowError as exc:
        _apply_window_problems(exc, errors)
        return _render_competition_form(
            request, renderer, principal, values=values, errors=errors,
            mode="edit", competition_id=competition_id, status_code=400,
        )
    return _redirect(request, "web_competition_detail", competition_id=competition_id)


@router.get("/competitions/{competition_id}/teams", name="web_teams")
def teams_view(
    competition_id: str,
    request: Request,
    principal: Principal = Depends(get_web_principal),
    renderer: TemplateRenderer = Depends(get_renderer),
    service: TeamService = Depends(get_web_team_service),
) -> Response:
    assert_competition_permission_or_404(
        principal, competition_id, Permission.TEAM_READ, not_found=_NOT_FOUND
    )
    return _render_teams(
        request, renderer, principal, service, competition_id, values={}, errors={}
    )


@router.post("/competitions/{competition_id}/teams", name="web_team_create")
async def team_create(
    competition_id: str,
    request: Request,
    principal: Principal = Depends(get_web_principal),
    renderer: TemplateRenderer = Depends(get_renderer),
    service: TeamService = Depends(get_web_team_service),
    _csrf: None = Depends(require_csrf),
) -> Response:
    assert_competition_permission_or_404(
        principal, competition_id, Permission.TEAM_WRITE, not_found=_NOT_FOUND
    )
    form = await read_form(request)
    name = form.get("name", "").strip()
    values = {"name": name}
    errors: dict[str, str] = {}
    if not name:
        errors["name"] = "Required."
        return _render_teams(
            request, renderer, principal, service, competition_id,
            values=values, errors=errors, status_code=400,
        )
    try:
        service.create(Team(competition_id=competition_id, name=name))
    except IntegrityError:
        errors["name"] = "A team with this name already exists."
        return _render_teams(
            request, renderer, principal, service, competition_id,
            values=values, errors=errors, status_code=409,
        )
    return _redirect(request, "web_teams", competition_id=competition_id)


@router.get("/competitions/{competition_id}/publications", name="web_publications")
def publications_view(
    competition_id: str,
    request: Request,
    principal: Principal = Depends(get_web_principal),
    renderer: TemplateRenderer = Depends(get_renderer),
    pub_service: PublicationService = Depends(get_web_publication_service),
    def_service: ChallengeDefinitionService = Depends(
        get_web_challenge_definition_service
    ),
    ver_service: ChallengeVersionService = Depends(
        get_web_challenge_version_service
    ),
) -> Response:
    assert_competition_permission_or_404(
        principal, competition_id, Permission.PUBLICATION_READ, not_found=_NOT_FOUND
    )
    return _render_publications(
        request, renderer, principal, competition_id,
        pub_service, def_service, ver_service, values={}, errors={},
    )


@router.post("/competitions/{competition_id}/publications", name="web_publication_attach")
async def publication_attach(
    competition_id: str,
    request: Request,
    principal: Principal = Depends(get_web_principal),
    renderer: TemplateRenderer = Depends(get_renderer),
    pub_service: PublicationService = Depends(get_web_publication_service),
    def_service: ChallengeDefinitionService = Depends(
        get_web_challenge_definition_service
    ),
    ver_service: ChallengeVersionService = Depends(
        get_web_challenge_version_service
    ),
    _csrf: None = Depends(require_csrf),
) -> Response:
    assert_competition_permission_or_404(
        principal, competition_id, Permission.PUBLICATION_WRITE, not_found=_NOT_FOUND
    )
    form = await read_form(request)
    target = form.get("publication_target", "").strip()
    values = {"publication_target": target}
    errors: dict[str, str] = {}
    parsed = _parse_publication_target(target, errors)
    if parsed is None:
        return _render_publications(
            request, renderer, principal, competition_id,
            pub_service, def_service, ver_service,
            values=values, errors=errors, status_code=400,
        )
    slug, version_no = parsed
    try:
        pub_service.attach(
            ChallengePublication(
                competition_id=competition_id,
                definition_slug=slug,
                version_no=version_no,
            )
        )
    except LookupError:
        errors["publication_target"] = "That challenge version was not found."
    except ValueError:
        errors["publication_target"] = "That version is not published."
    except IntegrityError:
        errors["publication_target"] = "That version is already attached."
    if errors:
        return _render_publications(
            request, renderer, principal, competition_id,
            pub_service, def_service, ver_service,
            values=values, errors=errors, status_code=409,
        )
    return _redirect(request, "web_publications", competition_id=competition_id)


@router.post(
    "/competitions/{competition_id}/publications/detach",
    name="web_publication_detach",
)
async def publication_detach(
    competition_id: str,
    request: Request,
    principal: Principal = Depends(get_web_principal),
    pub_service: PublicationService = Depends(get_web_publication_service),
    _csrf: None = Depends(require_csrf),
) -> Response:
    assert_competition_permission_or_404(
        principal, competition_id, Permission.PUBLICATION_WRITE, not_found=_NOT_FOUND
    )
    form = await read_form(request)
    slug = form.get("definition_slug", "").strip()
    raw_version = form.get("version_no", "").strip()
    try:
        version_no = int(raw_version)
    except ValueError:
        raise LookupError(_PUBLICATION_NOT_FOUND) from None
    if not slug:
        raise LookupError(_PUBLICATION_NOT_FOUND)
    pub_service.detach(competition_id, slug, version_no)
    return _redirect(request, "web_publications", competition_id=competition_id)
