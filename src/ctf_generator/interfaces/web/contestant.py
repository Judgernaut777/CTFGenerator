"""The contestant web read surface (M12 slice a -- READS ONLY).

The player/captain counterpart to the organizer ``router``. Thin handlers, the
identical M11 pattern: resolve the cookie :class:`Principal`, authorize with the
SAME M10b competition-scoped checks as the JSON API, call ONE (or a few read-only)
application service(s), map the aggregates to pure view dicts, render. No writes
land in this slice (submit arrives in 12b).

Authorization + tenancy invariants (mirroring the API):

* Every route is gated by ``assert_competition_permission_or_404`` on a permission
  a contestant actually holds (``competition:read``), so a competition the caller
  cannot read is an existence-hiding 404 -- never a 403 that would confirm it
  exists (no cross-competition oracle).
* The roster is TENANCY fail-closed: a team-scoped contestant sees ONLY their own
  team's members (derived from ``submission_team_scope``); a teamless contestant
  sees a friendly "not on a team" page, never another team's data; only a
  tenancy-unrestricted caller (organizer / admin / staff) sees every team.
* The published catalog exposes PUBLIC challenge metadata only (slug / title /
  version / mode / category). The private version ``spec`` -- where a flag or
  private scenario content lives -- is never read, so no secret can reach a page.
  A publication whose version/definition cannot be resolved degrades to the slug,
  never a 500.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from starlette.responses import Response

from ctf_generator.application.catalog import (
    ChallengeDefinitionService,
    ChallengeVersionService,
    CompetitionService,
)
from ctf_generator.application.catalog.publication_service import PublicationService
from ctf_generator.application.identity import IdentityService
from ctf_generator.domain.authoring.models import ChallengePublication
from ctf_generator.interfaces.api.deps import (
    Permission,
    Principal,
    assert_competition_permission_or_404,
    authorized_competitions,
    submission_team_scope,
)

from .auth import get_web_principal
from .deps import (
    get_web_challenge_definition_service,
    get_web_challenge_version_service,
    get_web_competition_service,
    get_web_identity_service,
    get_web_publication_service,
)
from .rendering import TemplateRenderer, get_renderer
from .views import catalog_entry, competition_row, roster_member

contestant_router = APIRouter()

_NOT_FOUND = "Competition not found"


def _catalog_entries(
    publications: list[ChallengePublication],
    ver_service: ChallengeVersionService,
    def_service: ChallengeDefinitionService,
) -> list[dict[str, object]]:
    """Resolve each published attachment to its PUBLIC catalog view. The version's
    ``spec`` is never read; a missing version/definition degrades gracefully (the
    entry is marked unavailable and shows the slug), never a 500."""
    entries: list[dict[str, object]] = []
    for pub in publications:
        version = ver_service.get(pub.definition_slug, pub.version_no)
        definition = def_service.get(pub.definition_slug)
        entries.append(catalog_entry(pub, version, definition))
    entries.sort(key=lambda e: (str(e["title"]), e["version_no"]))
    return entries


@contestant_router.get("/play", name="web_play")
def play_landing(
    request: Request,
    principal: Principal = Depends(get_web_principal),
    renderer: TemplateRenderer = Depends(get_renderer),
    service: CompetitionService = Depends(get_web_competition_service),
) -> Response:
    """The contestant landing: the competitions the caller may read.

    Applies the EXACT M10b filter the organizer dashboard uses -- a system role
    sees all (``authorized_competitions`` returns ``None``); everyone else sees
    only competitions whose membership grants ``competition:read``. A caller with
    no readable competition simply gets an empty list (never another's rows)."""
    configs = service.list()
    allowed = authorized_competitions(principal, Permission.COMPETITION_READ)
    if allowed is not None:
        configs = [c for c in configs if c.competition_id in allowed]
    configs = sorted(configs, key=lambda c: c.competition_id)
    context = {"competitions": [competition_row(c) for c in configs]}
    return renderer.render(request, "play_landing.html", context, principal=principal)


@contestant_router.get(
    "/competitions/{competition_id}/play", name="web_competition_play"
)
def competition_play_view(
    competition_id: str,
    request: Request,
    principal: Principal = Depends(get_web_principal),
    renderer: TemplateRenderer = Depends(get_renderer),
    service: CompetitionService = Depends(get_web_competition_service),
    pub_service: PublicationService = Depends(get_web_publication_service),
    def_service: ChallengeDefinitionService = Depends(
        get_web_challenge_definition_service
    ),
    ver_service: ChallengeVersionService = Depends(
        get_web_challenge_version_service
    ),
) -> Response:
    """The per-competition contestant landing: window + published catalog + the
    caller's own-team context + links to roster / scoreboard. Existence-hiding 404
    for a competition the caller cannot read."""
    assert_competition_permission_or_404(
        principal, competition_id, Permission.COMPETITION_READ, not_found=_NOT_FOUND
    )
    config = service.get(competition_id)
    if config is None:
        raise LookupError(_NOT_FOUND)
    scope = submission_team_scope(principal, competition_id)
    catalog = _catalog_entries(
        pub_service.list_for_competition(competition_id), ver_service, def_service
    )
    context = {
        "competition": competition_row(config),
        "catalog": catalog,
        # ``team_name`` is the caller's OWN team (None => not on a team). An
        # unrestricted (organizer/staff) caller has no single team -- flagged so
        # the page says "staff access" rather than "not on a team".
        "unrestricted": scope.unrestricted,
        "team_name": None if scope.unrestricted else scope.team,
    }
    return renderer.render(
        request, "competition_play.html", context, principal=principal
    )


@contestant_router.get(
    "/competitions/{competition_id}/challenges", name="web_competition_challenges"
)
def challenges_view(
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
    """The published challenge catalog as a standalone page (same public metadata
    as the play view). Existence-hiding 404 for an unreadable competition."""
    assert_competition_permission_or_404(
        principal, competition_id, Permission.COMPETITION_READ, not_found=_NOT_FOUND
    )
    catalog = _catalog_entries(
        pub_service.list_for_competition(competition_id), ver_service, def_service
    )
    context = {"competition_id": competition_id, "catalog": catalog}
    return renderer.render(request, "challenges.html", context, principal=principal)


@contestant_router.get(
    "/competitions/{competition_id}/roster", name="web_competition_roster"
)
def roster_view(
    competition_id: str,
    request: Request,
    principal: Principal = Depends(get_web_principal),
    renderer: TemplateRenderer = Depends(get_renderer),
    identity_service: IdentityService = Depends(get_web_identity_service),
) -> Response:
    """The caller's OWN team roster.

    Fail-closed tenancy, derived from ``submission_team_scope`` (the SAME per-
    competition scoping the API's submission reads use):

    * unrestricted role (organizer / admin / staff / judge / observer / author):
      may see every team's members;
    * team-scoped role (player / captain): confined to the team of their
      membership IN THIS competition -- the roster is filtered to
      ``m.team_name == scope.team`` so no other team's members are ever rendered;
    * team-scoped but not placed on a team: a friendly "not on a team" page with
      NO members (never another team's data, never a 500).
    """
    # A contestant holds competition:read; gating on it keeps the denial an
    # existence-hiding 404 identical to a nonexistent competition.
    assert_competition_permission_or_404(
        principal, competition_id, Permission.COMPETITION_READ, not_found=_NOT_FOUND
    )
    scope = submission_team_scope(principal, competition_id)
    teamless = not scope.unrestricted and scope.team is None
    if teamless:
        # Fail closed: do not even read the roster; render the friendly page.
        confined: list = []
    else:
        memberships = identity_service.list_memberships_for_competition(
            competition_id
        )
        if scope.unrestricted:
            confined = list(memberships)
        else:
            # Team-scoped: ONLY the caller's own team's members.
            confined = [m for m in memberships if m.team_name == scope.team]
    members = [
        roster_member(m) for m in sorted(confined, key=lambda m: m.user_email)
    ]
    context = {
        "competition_id": competition_id,
        "unrestricted": scope.unrestricted,
        "teamless": teamless,
        "team_name": None if scope.unrestricted else scope.team,
        "members": members,
    }
    return renderer.render(request, "roster.html", context, principal=principal)
