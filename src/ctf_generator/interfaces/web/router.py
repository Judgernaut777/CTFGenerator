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
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, Request
from sqlalchemy.exc import IntegrityError
from starlette.responses import RedirectResponse, Response

from ctf_generator.application.auth import AuthService, InvalidCredentialsError
from ctf_generator.application.authoring.build_service import BuildService
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
from ctf_generator.application.instances.service import InstanceLifecycleService
from ctf_generator.application.jobs.service import JobService
from ctf_generator.application.scoring.scoreboard_service import ScoreboardService
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
    get_web_build_service,
    get_web_challenge_definition_service,
    get_web_challenge_version_service,
    get_web_competition_service,
    get_web_instance_lifecycle_service,
    get_web_job_service,
    get_web_publication_service,
    get_web_scoreboard_service,
    get_web_settings,
    get_web_team_service,
)
from .formdata import read_form
from .rendering import TemplateRenderer, get_renderer
from .settings import WebSettings
from .views import (
    build_row,
    competition_detail,
    competition_form_values,
    competition_row,
    instance_detail,
    instance_row,
    job_row,
    publication_row,
    scoreboard_entry,
    scoreboard_entry_key,
    team_row,
)

router = APIRouter()

_NOT_FOUND = "Competition not found"
_PUBLICATION_NOT_FOUND = "Publication not found"
_INSTANCE_NOT_FOUND = "Instance not found"
# The ``version_no`` column is a 32-bit INTEGER; a client-tampered select value
# above this would raise a DB DataError (a 500). Reject out-of-range at parse
# time so an out-of-range selection is a field error, never a 500.
_INT32_MAX = 2147483647

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
    if version_no < 1 or version_no > _INT32_MAX:
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
        # The job-queue ops surface is admin/support only (flat JOB_READ), so the
        # nav link only shows for a caller who could actually open the page.
        "can_view_jobs": principal.has(Permission.JOB_READ),
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
    perms = competition_permissions(principal, competition_id)
    context = {
        "competition": competition_detail(config),
        "can_manage": Permission.COMPETITION_WRITE in perms,
        "can_view_instances": Permission.INSTANCE_READ in perms,
        "can_view_scoreboard": Permission.SCOREBOARD_READ in perms,
    }
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
    status_code = 200
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
        status_code = 404
    except ValueError:
        errors["publication_target"] = "That version is not published."
        status_code = 422
    except IntegrityError:
        errors["publication_target"] = "That version is already attached."
        status_code = 409
    if errors:
        return _render_publications(
            request, renderer, principal, competition_id,
            pub_service, def_service, ver_service,
            values=values, errors=errors, status_code=status_code,
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
    # Out-of-range (INT32) or missing slug is a clean not-found, never a DB
    # DataError 500.
    if not slug or version_no < 1 or version_no > _INT32_MAX:
        raise LookupError(_PUBLICATION_NOT_FOUND)
    pub_service.detach(competition_id, slug, version_no)
    return _redirect(request, "web_publications", competition_id=competition_id)


# ===========================================================================
# M11c -- organizer OPS views (monitor + operate). Every route is authz-scoped
# IDENTICALLY to its JSON-API sibling; every POST is CSRF-protected; the control
# plane NEVER launches a container from a handler (operate actions record desired
# state / enqueue jobs via the services, exactly like the API). No secret
# (credential / runtime token / instance_seed / job payload / flag) is ever placed
# in a rendered context -- the view mappers delegate to the API DTO mappers, whose
# redaction is the single source of truth.
# ===========================================================================


# -- instances (monitor + operate) ------------------------------------------
#
# The competition-scoped LIST is existence-hiding on a denial (the M11 web
# convention): a competition the caller cannot read is a 404, indistinguishable
# from a nonexistent one -- never weaker than the API's 403. The by-id routes
# resolve the target competition from the LOADED instance row (no {competition_id}
# in the path) and surface a cross-tenant denial as the SAME generic 404 as a
# nonexistent id, mirroring the API's ``_load_for_action`` / ``_detail_or_404`` so
# no cross-tenant existence oracle / competition-id disclosure is possible.


def _instance_sort_key(instance) -> tuple[str, str]:
    created = instance.created_at.isoformat() if instance.created_at else ""
    return (created, instance.instance_id)


def _load_instance_or_404(
    service: InstanceLifecycleService,
    principal: Principal,
    instance_id: str,
    permission: Permission,
):
    """Load an instance by id (generic 404 if absent) and authorize ``permission``
    against ITS competition, surfacing a denial as the SAME generic 404 (no
    existence/competition leak)."""
    instance = service.get(instance_id)
    if instance is None:
        raise LookupError(_INSTANCE_NOT_FOUND)
    assert_competition_permission_or_404(
        principal, instance.competition_id, permission, not_found=_INSTANCE_NOT_FOUND
    )
    return instance


@router.get("/competitions/{competition_id}/instances", name="web_instances")
def instances_view(
    competition_id: str,
    request: Request,
    principal: Principal = Depends(get_web_principal),
    renderer: TemplateRenderer = Depends(get_renderer),
    service: InstanceLifecycleService = Depends(get_web_instance_lifecycle_service),
) -> Response:
    assert_competition_permission_or_404(
        principal, competition_id, Permission.INSTANCE_READ, not_found=_NOT_FOUND
    )
    instances = sorted(
        service.list_instances(competition_id=competition_id),
        key=_instance_sort_key,
    )
    context = {
        "competition_id": competition_id,
        "instances": [instance_row(i) for i in instances],
    }
    return renderer.render(
        request, "instances_list.html", context, principal=principal
    )


@router.get("/instances/{instance_id}", name="web_instance_detail")
def instance_detail_view(
    instance_id: str,
    request: Request,
    principal: Principal = Depends(get_web_principal),
    renderer: TemplateRenderer = Depends(get_renderer),
    service: InstanceLifecycleService = Depends(get_web_instance_lifecycle_service),
) -> Response:
    view = service.get_operator_view(instance_id)
    if view is None:
        raise LookupError(_INSTANCE_NOT_FOUND)
    instance, endpoints, health = view
    assert_competition_permission_or_404(
        principal, instance.competition_id, Permission.INSTANCE_READ,
        not_found=_INSTANCE_NOT_FOUND,
    )
    can_operate = Permission.INSTANCE_OPERATE in competition_permissions(
        principal, instance.competition_id
    )
    context = {
        "instance": instance_detail(instance, endpoints, health),
        "competition_id": instance.competition_id,
        "can_operate": can_operate,
    }
    return renderer.render(
        request, "instance_detail.html", context, principal=principal
    )


@router.post("/instances/{instance_id}/stop", name="web_instance_stop")
async def instance_stop(
    instance_id: str,
    request: Request,
    principal: Principal = Depends(get_web_principal),
    service: InstanceLifecycleService = Depends(get_web_instance_lifecycle_service),
    _csrf: None = Depends(require_csrf),
) -> Response:
    _load_instance_or_404(
        service, principal, instance_id, Permission.INSTANCE_OPERATE
    )
    service.request_stop(instance_id, datetime.now(UTC))
    return _redirect(request, "web_instance_detail", instance_id=instance_id)


@router.post("/instances/{instance_id}/reset", name="web_instance_reset")
async def instance_reset(
    instance_id: str,
    request: Request,
    principal: Principal = Depends(get_web_principal),
    service: InstanceLifecycleService = Depends(get_web_instance_lifecycle_service),
    _csrf: None = Depends(require_csrf),
) -> Response:
    _load_instance_or_404(
        service, principal, instance_id, Permission.INSTANCE_OPERATE
    )
    now = datetime.now(UTC)
    service.request_reset(instance_id, now + timedelta(hours=1), now)
    return _redirect(request, "web_instance_detail", instance_id=instance_id)


@router.post("/instances/{instance_id}/delete", name="web_instance_delete")
async def instance_delete(
    instance_id: str,
    request: Request,
    principal: Principal = Depends(get_web_principal),
    service: InstanceLifecycleService = Depends(get_web_instance_lifecycle_service),
    _csrf: None = Depends(require_csrf),
) -> Response:
    instance = _load_instance_or_404(
        service, principal, instance_id, Permission.INSTANCE_OPERATE
    )
    service.request_delete(instance_id, datetime.now(UTC))
    # After a delete the instance list is the useful destination.
    return _redirect(request, "web_instances", competition_id=instance.competition_id)


# -- jobs (ops read + control; admin / support only) ------------------------
#
# Jobs are a SYSTEM surface: the API gates them with the FLAT ``require_permission``
# (JOB_READ / JOB_OPERATE), which only ``admin`` / ``support`` hold. The web uses
# the SAME flat check (``_require_flat``) -> a contestant or an
# organizer-without-a-system-role gets a 403 page, nothing performed.


def _render_ops_jobs(
    request: Request,
    renderer: TemplateRenderer,
    principal: Principal,
    service: JobService,
    *,
    lookup_id: str = "",
    lookup=None,
    lookup_not_found: bool = False,
    error: str | None = None,
    status_code: int = 200,
) -> Response:
    dead = sorted(service.list_dead_letter(), key=lambda j: j.job_id)
    context = {
        "dead_letter": [job_row(j) for j in dead],
        "lookup_id": lookup_id,
        "lookup": job_row(lookup) if lookup is not None else None,
        "lookup_not_found": lookup_not_found,
        "error": error,
    }
    return renderer.render(
        request, "jobs.html", context, principal=principal, status_code=status_code
    )


@router.get("/ops/jobs", name="web_ops_jobs")
def ops_jobs_view(
    request: Request,
    principal: Principal = Depends(get_web_principal),
    renderer: TemplateRenderer = Depends(get_renderer),
    service: JobService = Depends(get_web_job_service),
    job_id: str | None = None,
) -> Response:
    _require_flat(principal, Permission.JOB_READ)
    jid = (job_id or "").strip()
    lookup = service.get(jid) if jid else None
    return _render_ops_jobs(
        request, renderer, principal, service,
        lookup_id=jid, lookup=lookup, lookup_not_found=bool(jid) and lookup is None,
    )


@router.post("/ops/jobs/{job_id}/cancel", name="web_ops_job_cancel")
async def ops_job_cancel(
    job_id: str,
    request: Request,
    principal: Principal = Depends(get_web_principal),
    renderer: TemplateRenderer = Depends(get_renderer),
    service: JobService = Depends(get_web_job_service),
    _csrf: None = Depends(require_csrf),
) -> Response:
    _require_flat(principal, Permission.JOB_OPERATE)
    try:
        service.cancel(job_id, datetime.now(UTC))
    except LookupError as exc:
        # An invalid target/state is a friendly re-render, NEVER a 500.
        return _render_ops_jobs(
            request, renderer, principal, service,
            error=str(exc) or "That job could not be cancelled.", status_code=409,
        )
    return _redirect(request, "web_ops_jobs")


@router.post("/ops/jobs/{job_id}/retry", name="web_ops_job_retry")
async def ops_job_retry(
    job_id: str,
    request: Request,
    principal: Principal = Depends(get_web_principal),
    renderer: TemplateRenderer = Depends(get_renderer),
    service: JobService = Depends(get_web_job_service),
    _csrf: None = Depends(require_csrf),
) -> Response:
    _require_flat(principal, Permission.JOB_OPERATE)
    try:
        service.retry_dead_letter(job_id, datetime.now(UTC))
    except LookupError as exc:
        return _render_ops_jobs(
            request, renderer, principal, service,
            error=str(exc) or "That job could not be retried.", status_code=409,
        )
    return _redirect(request, "web_ops_jobs")


# -- builds (list + trigger a build JOB) ------------------------------------
#
# Builds are an AUTHORING surface: the API gates them with the FLAT
# ``require_permission`` (BUILD_READ / BUILD_CREATE). The trigger ENQUEUES a durable
# ``build_challenge`` job (idempotent) -- the control plane never runs the build.


def _render_builds(
    request: Request,
    renderer: TemplateRenderer,
    principal: Principal,
    service: BuildService,
    slug: str,
    version_no: int,
    *,
    can_trigger: bool,
    values: dict[str, str],
    errors: dict[str, str],
    notice: str | None = None,
    status_code: int = 200,
) -> Response:
    builds = sorted(
        service.list_for_version(slug, version_no), key=lambda b: b.build_sha256
    )
    context = {
        "slug": slug,
        "version_no": version_no,
        "builds": [build_row(b) for b in builds],
        "can_trigger": can_trigger,
        "values": values,
        "errors": errors,
        "notice": notice,
    }
    return renderer.render(
        request, "builds.html", context, principal=principal, status_code=status_code
    )


def _parse_version_no(raw: str | None, errors: dict[str, str]) -> int | None:
    """Parse a ``version_no`` form/query value; an out-of-range or malformed value
    is a field error (re-render), never a DB DataError 500."""
    raw = (raw or "").strip()
    try:
        version_no = int(raw)
    except (TypeError, ValueError):
        errors["version_no"] = "Enter a version number."
        return None
    if version_no < 1 or version_no > _INT32_MAX:
        errors["version_no"] = "Enter a valid version number."
        return None
    return version_no


@router.get("/challenge-definitions/{slug}/builds", name="web_builds")
def builds_view(
    slug: str,
    request: Request,
    principal: Principal = Depends(get_web_principal),
    renderer: TemplateRenderer = Depends(get_renderer),
    service: BuildService = Depends(get_web_build_service),
    version_no: str | None = None,
) -> Response:
    _require_flat(principal, Permission.BUILD_READ)
    errors: dict[str, str] = {}
    parsed = _parse_version_no(version_no, errors)
    can_trigger = principal.has(Permission.BUILD_CREATE)
    if parsed is None:
        # No (or bad) version selected: render the empty picker, no list yet.
        return _render_builds(
            request, renderer, principal, service, slug, 0,
            can_trigger=can_trigger, values={"version_no": (version_no or "").strip()},
            errors=errors,
        )
    return _render_builds(
        request, renderer, principal, service, slug, parsed,
        can_trigger=can_trigger,
        values={"version_no": str(parsed)}, errors={},
    )


@router.post("/challenge-definitions/{slug}/builds", name="web_build_trigger")
async def build_trigger(
    slug: str,
    request: Request,
    principal: Principal = Depends(get_web_principal),
    renderer: TemplateRenderer = Depends(get_renderer),
    service: BuildService = Depends(get_web_build_service),
    _csrf: None = Depends(require_csrf),
) -> Response:
    _require_flat(principal, Permission.BUILD_CREATE)
    form = await read_form(request)
    errors: dict[str, str] = {}
    parsed = _parse_version_no(form.get("version_no"), errors)
    if parsed is None:
        return _render_builds(
            request, renderer, principal, service, slug, 0,
            can_trigger=True, values={"version_no": form.get("version_no", "").strip()},
            errors=errors, status_code=400,
        )
    try:
        _job, created = service.trigger_build(slug, parsed, datetime.now(UTC))
    except LookupError:
        errors["version_no"] = "That challenge version was not found."
        return _render_builds(
            request, renderer, principal, service, slug, parsed,
            can_trigger=True, values={"version_no": str(parsed)}, errors=errors,
            status_code=404,
        )
    notice = (
        "Build job enqueued." if created else "A build for this version is already queued."
    )
    return _render_builds(
        request, renderer, principal, service, slug, parsed,
        can_trigger=True, values={"version_no": str(parsed)}, errors={},
        notice=notice,
    )


# -- scoreboard (admin / organizer read of the projection) ------------------
#
# Read-only over the scoreboard PROJECTION (a GET never folds the ledger),
# competition-scoped SCOREBOARD_READ. A cross-competition caller is an
# existence-hiding 404 (never weaker than the API's scoped check). The optional lag
# indicator is shown ONLY to a caller holding SCOREBOARD_LAG in this competition.


@router.get("/competitions/{competition_id}/scoreboard", name="web_scoreboard")
def scoreboard_view(
    competition_id: str,
    request: Request,
    principal: Principal = Depends(get_web_principal),
    renderer: TemplateRenderer = Depends(get_renderer),
    service: ScoreboardService = Depends(get_web_scoreboard_service),
) -> Response:
    assert_competition_permission_or_404(
        principal, competition_id, Permission.SCOREBOARD_READ, not_found=_NOT_FOUND
    )
    entries = sorted(
        (scoreboard_entry(e) for e in service.standings(competition_id)),
        key=scoreboard_entry_key,
    )
    lag = None
    if Permission.SCOREBOARD_LAG_READ in competition_permissions(
        principal, competition_id
    ):
        snapshot = service.lag()
        lag = {
            "pending_count": snapshot.pending_count,
            "failed_count": snapshot.failed_count,
            "latest_seq": snapshot.latest_seq,
            "max_as_of_seq": snapshot.max_as_of_seq,
        }
    context = {
        "competition_id": competition_id,
        "entries": entries,
        "lag": lag,
    }
    return renderer.render(
        request, "scoreboard.html", context, principal=principal
    )
