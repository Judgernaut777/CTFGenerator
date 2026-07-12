"""The contestant web surface (M12 slices a READS + b WRITES).

The player/captain counterpart to the organizer ``router``. Thin handlers, the
identical M11 pattern: resolve the cookie :class:`Principal`, authorize with the
SAME M10b competition-scoped checks as the JSON API, call ONE (or a few)
application service(s), map the aggregates to pure view dicts, render. Slice a is
read-only (play / catalog / roster); slice b adds the WRITE surface -- flag
submission and the caller's own-team submission history.

Authorization + tenancy invariants (mirroring the API):

* Every route is gated by ``assert_competition_permission_or_404`` on a permission
  a contestant actually holds (``competition:read`` for reads; ``submission:create``
  / ``submission:read`` for the write surface), so a competition the caller cannot
  act in is an existence-hiding 404 -- never a 403 that would confirm it exists (no
  cross-competition oracle).
* The roster is TENANCY fail-closed: a team-scoped contestant sees ONLY their own
  team's members (derived from ``submission_team_scope``); a teamless contestant
  sees a friendly "not on a team" page, never another team's data; only a
  tenancy-unrestricted caller (organizer / admin / staff) sees every team.
* The published catalog exposes PUBLIC challenge metadata only (slug / title /
  version / mode / category). The private version ``spec`` -- where a flag or
  private scenario content lives -- is never read, so no secret can reach a page.
  A publication whose version/definition cannot be resolved degrades to the slug,
  never a 500.

Slice-b write invariants (mirroring ``interfaces.api.routers.submissions``):

* The team a submission is recorded for -- and the team whose history is shown --
  is ALWAYS derived SERVER-SIDE from the caller's per-competition membership
  (``submission_team_scope``); it is NEVER read from a form field or path. A
  team-scoped caller confined to team Red can only ever submit for / read Red.
* A team-scoped caller not placed on a team (and, on this contestant-only surface,
  a tenancy-unrestricted staff caller who has no single team) fails CLOSED: a
  friendly "not on a team" page with no form / an empty history -- never a 500,
  never another team's data.
* Every POST is CSRF-protected (``require_csrf``). Idempotency mirrors the API's
  ``Idempotency-Key``: a per-render hidden nonce is folded (with the same
  ``_SUBMISSION_NS``) into a deterministic ``submission_id`` via ``uuid5``, so a
  double-POST of the same rendered form replays onto the same submission (no double
  solve). The submitted answer is inbound-only: never echoed back, never rendered,
  never stored (the ledger has no answer column) and never logged.
* Every ``SubmissionProcessingError`` subclass (and ``LookupError``) is mapped to a
  friendly response, NEVER a 500.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Request
from starlette.responses import Response

from ctf_generator.application.catalog import (
    ChallengeDefinitionService,
    ChallengeVersionService,
    CompetitionService,
)
from ctf_generator.application.catalog.publication_service import PublicationService
from ctf_generator.application.identity import IdentityService
from ctf_generator.application.submissions.query_service import SubmissionQueryService
from ctf_generator.application.submissions.service import (
    SubmissionProcessingService,
)
from ctf_generator.domain.authoring.models import ChallengePublication
from ctf_generator.domain.ledger.processing import (
    ChallengeNotAttachedError,
    FlagRejectedError,
    FlagUnavailableError,
    IdempotencyConflictError,
    SubmissionProcessingError,
    SubmissionRequest,
)
from ctf_generator.interfaces.api.deps import (
    Permission,
    Principal,
    assert_competition_permission_or_404,
    authorized_competitions,
    submission_team_scope,
)

# Single source of truth for the idempotency namespace: reuse the JSON API's value
# so a nonce/Idempotency-Key computed on either surface derives the identical
# deterministic submission_id (the domain PK idempotency then aligns across both).
from ctf_generator.interfaces.api.routers.submissions import _SUBMISSION_NS

from .auth import get_web_principal
from .csrf import require_csrf
from .deps import (
    get_web_challenge_definition_service,
    get_web_challenge_version_service,
    get_web_competition_service,
    get_web_identity_service,
    get_web_publication_service,
    get_web_submission_processing_service,
    get_web_submission_query_service,
)
from .formdata import read_form
from .rendering import TemplateRenderer, get_renderer
from .views import (
    catalog_entry,
    competition_row,
    roster_member,
    submission_history_row,
)

contestant_router = APIRouter()

_NOT_FOUND = "Competition not found"
_CHALLENGE_NOT_FOUND = "Challenge not available"
# The ``version_no`` column is a 32-bit INTEGER; a client-tampered value above this
# would raise a DB DataError (a 500). Reject out-of-range at the boundary so it is a
# clean existence-hiding 404, never a 500.
_INT32_MAX = 2147483647


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


# ===========================================================================
# M12b -- contestant WRITE surface: flag submission + own-team history.
#
# The team is derived SERVER-SIDE from ``submission_team_scope`` and is NEVER read
# from a form field or path. A team-scoped caller with no team -- and a
# tenancy-unrestricted staff caller (who has no single team on this contestant-only
# surface) -- fails closed to a friendly no-team page (option (b): this surface is
# for contestants; unrestricted staff submit via the JSON API / organizer tools).
# ===========================================================================

_SUBMIT_ROUTE = (
    "/competitions/{competition_id}/challenges/{definition_slug}/{version_no}/submit"
)


def _contestant_team(principal: Principal, competition_id: str) -> str | None:
    """The single team this contestant may act as in the competition, or ``None``.

    ``None`` means the caller has no submitting identity here -- a team-scoped
    caller not placed on a team, OR a tenancy-unrestricted staff caller (no single
    team on the contestant surface). Both fail closed. The team is taken ONLY from
    the caller's membership; nothing in the request can influence it."""
    scope = submission_team_scope(principal, competition_id)
    if scope.unrestricted:
        return None
    return scope.team


def _resolve_title(
    definition_slug: str, def_service: ChallengeDefinitionService
) -> str:
    """The public display title for a slug (falls back to the slug; never a 500)."""
    definition = def_service.get(definition_slug)
    return definition.title if definition is not None else definition_slug


def _fresh_nonce() -> str:
    """A per-render idempotency nonce (folded into the deterministic submission_id
    so a double-POST of the SAME rendered form replays, but a fresh render starts a
    new attempt)."""
    return uuid.uuid4().hex


def _render_submit(
    request: Request,
    renderer: TemplateRenderer,
    principal: Principal,
    *,
    competition_id: str,
    definition_slug: str,
    version_no: int,
    title: str,
    team_name: str | None,
    idempotency_nonce: str,
    result: str | None = None,
    result_correct: bool = False,
    error: str | None = None,
    status_code: int = 200,
) -> Response:
    """Render the submit form (or the friendly no-team page when ``team_name`` is
    ``None``). The answer is NEVER echoed -- the input renders empty every time."""
    context = {
        "competition_id": competition_id,
        "definition_slug": definition_slug,
        "version_no": version_no,
        "title": title,
        "team_name": team_name,
        "has_team": team_name is not None,
        "idempotency_nonce": idempotency_nonce,
        "form_action": str(
            request.url_for(
                "web_challenge_submit",
                competition_id=competition_id,
                definition_slug=definition_slug,
                version_no=version_no,
            )
        ),
        "result": result,
        "result_correct": result_correct,
        "error": error,
    }
    return renderer.render(
        request, "challenge_submit.html", context,
        principal=principal, status_code=status_code,
    )


def _require_published_or_404(
    pub_service: PublicationService,
    competition_id: str,
    definition_slug: str,
    version_no: int,
) -> None:
    """404 unless the ``(slug, version_no)`` is actually PUBLISHED in THIS
    competition -- a contestant may never submit against an unpublished challenge.
    An out-of-range version is a clean 404 (never a DB DataError 500)."""
    if version_no < 1 or version_no > _INT32_MAX:
        raise LookupError(_CHALLENGE_NOT_FOUND)
    if pub_service.get(competition_id, definition_slug, version_no) is None:
        raise LookupError(_CHALLENGE_NOT_FOUND)


@contestant_router.get(_SUBMIT_ROUTE, name="web_challenge_submit_form")
def challenge_submit_form(
    competition_id: str,
    definition_slug: str,
    version_no: int,
    request: Request,
    principal: Principal = Depends(get_web_principal),
    renderer: TemplateRenderer = Depends(get_renderer),
    pub_service: PublicationService = Depends(get_web_publication_service),
    def_service: ChallengeDefinitionService = Depends(
        get_web_challenge_definition_service
    ),
) -> Response:
    """The flag submit form for one PUBLISHED challenge. Existence-hiding 404 for a
    competition the caller cannot submit in, or a challenge not published here. A
    caller with no team gets a friendly no-form page (200)."""
    assert_competition_permission_or_404(
        principal, competition_id, Permission.SUBMISSION_CREATE, not_found=_NOT_FOUND
    )
    _require_published_or_404(
        pub_service, competition_id, definition_slug, version_no
    )
    return _render_submit(
        request, renderer, principal,
        competition_id=competition_id,
        definition_slug=definition_slug,
        version_no=version_no,
        title=_resolve_title(definition_slug, def_service),
        team_name=_contestant_team(principal, competition_id),
        idempotency_nonce=_fresh_nonce(),
    )


# NOTE (M12b, documented in docs/web/contestant-portal.md): this POST is
# CSRF-protected and tenancy-confined, and flag values are high-entropy, so a
# flooded session cannot brute-force a flag. It carries NO app-level per-principal
# submit throttle -- this is at PARITY with the JSON API, whose RateLimitMiddleware
# is IP-keyed (pre-auth) only, and abuse throttling is a deployment-edge concern
# (reverse proxy / M18). A per-team submit rate limit is a documented future
# enhancement, not a silent gap.
@contestant_router.post(_SUBMIT_ROUTE, name="web_challenge_submit")
async def challenge_submit(
    competition_id: str,
    definition_slug: str,
    version_no: int,
    request: Request,
    principal: Principal = Depends(get_web_principal),
    renderer: TemplateRenderer = Depends(get_renderer),
    pub_service: PublicationService = Depends(get_web_publication_service),
    def_service: ChallengeDefinitionService = Depends(
        get_web_challenge_definition_service
    ),
    proc_service: SubmissionProcessingService = Depends(
        get_web_submission_processing_service
    ),
    _csrf: None = Depends(require_csrf),
) -> Response:
    """Record one flag attempt. Existence-hiding 404 for an unreadable competition
    or an unpublished challenge; a friendly no-form page for a caller with no team;
    a friendly banner (never a 500) for any bad input or domain error."""
    assert_competition_permission_or_404(
        principal, competition_id, Permission.SUBMISSION_CREATE, not_found=_NOT_FOUND
    )
    _require_published_or_404(
        pub_service, competition_id, definition_slug, version_no
    )
    title = _resolve_title(definition_slug, def_service)
    # The team is derived from MEMBERSHIP only -- never from the form / path.
    team = _contestant_team(principal, competition_id)
    if team is None:
        # Fail closed: no submitting identity here. Never a 500, never another team.
        return _render_submit(
            request, renderer, principal,
            competition_id=competition_id, definition_slug=definition_slug,
            version_no=version_no, title=title, team_name=None,
            idempotency_nonce=_fresh_nonce(),
        )

    form = await read_form(request)
    answer = form.get("answer", "").strip()
    nonce = form.get("idempotency_nonce", "").strip()
    if not answer:
        return _render_submit(
            request, renderer, principal,
            competition_id=competition_id, definition_slug=definition_slug,
            version_no=version_no, title=title, team_name=team,
            idempotency_nonce=nonce or _fresh_nonce(),
            error="Enter an answer to submit.", status_code=400,
        )

    # Deterministic (principal + competition + nonce)-scoped submission_id: a
    # double-POST of the SAME rendered form (same nonce) replays onto the same id.
    # A missing nonce falls back to a fresh uuid4, exactly as the API does when no
    # Idempotency-Key is supplied.
    submission_id = (
        str(uuid.uuid5(_SUBMISSION_NS, f"{principal.subject}:{competition_id}:{nonce}"))
        if nonce
        else str(uuid.uuid4())
    )

    def _fail(message: str, status_code: int) -> Response:
        # Re-render with a friendly banner, a FRESH nonce (a retry is a new attempt),
        # and the answer NEVER echoed back.
        return _render_submit(
            request, renderer, principal,
            competition_id=competition_id, definition_slug=definition_slug,
            version_no=version_no, title=title, team_name=team,
            idempotency_nonce=_fresh_nonce(), error=message, status_code=status_code,
        )

    try:
        outcome = proc_service.process_submission(
            SubmissionRequest(
                submission_id=submission_id,
                competition_id=competition_id,
                team_name=team,
                definition_slug=definition_slug,
                version_no=version_no,
                submitted_at=datetime.now(UTC),
                candidate_flag=answer,
                submitter_email=None,
                # Contestants have no per-instance surface in M12; per-instance
                # seeded verification is a future slice.
                instance_seed=None,
            )
        )
    except FlagRejectedError:
        return _fail("That answer's format is invalid.", 400)
    except FlagUnavailableError:
        return _fail(
            "This challenge is misconfigured. Please contact an organizer.", 400
        )
    except IdempotencyConflictError:
        return _fail("That looks like a duplicate request. Please try again.", 409)
    except (ChallengeNotAttachedError, LookupError):
        # ChallengeNotAttachedError is also a LookupError; a challenge detached in a
        # race -> the same existence-hiding 404 as an unpublished one.
        raise LookupError(_CHALLENGE_NOT_FOUND) from None
    except SubmissionProcessingError:
        # A draft / missing version (the plain base error) -> not available (404-ish).
        raise LookupError(_CHALLENGE_NOT_FOUND) from None

    if outcome.accepted and outcome.first_solve:
        result, correct = "Correct! First solve for your team.", True
    elif outcome.accepted:
        result, correct = "Correct -- your team already solved this.", True
    else:
        result, correct = "Incorrect. Try again.", False
    return _render_submit(
        request, renderer, principal,
        competition_id=competition_id, definition_slug=definition_slug,
        version_no=version_no, title=title, team_name=team,
        idempotency_nonce=_fresh_nonce(), result=result, result_correct=correct,
    )


@contestant_router.get(
    "/competitions/{competition_id}/submissions", name="web_my_submissions"
)
def my_submissions_view(
    competition_id: str,
    request: Request,
    principal: Principal = Depends(get_web_principal),
    renderer: TemplateRenderer = Depends(get_renderer),
    query_service: SubmissionQueryService = Depends(
        get_web_submission_query_service
    ),
    def_service: ChallengeDefinitionService = Depends(
        get_web_challenge_definition_service
    ),
) -> Response:
    """The caller's OWN-team submission history (newest first).

    Fail-closed tenancy identical to the API's team-scoped read: a team-scoped
    caller sees ONLY ``list_for_team(cid, own_team)``; a caller with no submitting
    identity here (teamless, or a tenancy-unrestricted staff caller who has no
    single team on this contestant surface -- who reads via the organizer surface)
    gets a friendly empty page, never another team's rows. Existence-hiding 404 for
    an unreadable competition. The ledger stores no answer, so none can leak."""
    assert_competition_permission_or_404(
        principal, competition_id, Permission.SUBMISSION_READ, not_found=_NOT_FOUND
    )
    team = _contestant_team(principal, competition_id)
    if team is None:
        rows: list = []
    else:
        submissions = query_service.list_for_team(competition_id, team)
        submissions = sorted(
            submissions,
            key=lambda s: (s.submitted_at, s.submission_id),
            reverse=True,
        )
        titles = {
            s.definition_slug: _resolve_title(s.definition_slug, def_service)
            for s in submissions
        }
        rows = [
            submission_history_row(s, titles[s.definition_slug]) for s in submissions
        ]
    context = {
        "competition_id": competition_id,
        "team_name": team,
        "teamless": team is None,
        "submissions": rows,
    }
    return renderer.render(
        request, "my_submissions.html", context, principal=principal
    )
