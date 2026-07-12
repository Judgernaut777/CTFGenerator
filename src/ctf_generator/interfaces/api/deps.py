"""The authentication / authorization seam + shared request dependencies.

This is the seam M10 replaces with real local-auth + OIDC. Slice a ships:

* :class:`Principal` -- the authenticated caller (subject, roles, resolved
  permissions, optional org/team context). Framework-free.
* :class:`Permission` -- the fine-grained permission enum, and ``ROLE_PERMISSIONS``
  mapping the identity roles (``VALID_ROLES``) to permission sets.
* :class:`Authenticator` -- a ``Protocol`` the API programs against. The
  production implementation is :class:`~.db_authenticator.DbAuthenticator`
  (M10a: resolves a Bearer *session* token to a Principal from real local-auth
  data). :class:`StubAuthenticator` (a static ``token -> Principal`` table)
  survives only for dev/test behind the explicit ``CTFGEN_API_INSECURE_STUB_AUTH=1``
  flag, so it is never a silent production default; it never logs/echoes a token.
  (Federated OIDC/SSO is the next slice's implementation of the same protocol.)
* dependencies: :func:`get_principal` (delegates to the app's authenticator),
  :func:`require_permission` (403 if the principal lacks the permission),
  :func:`get_database` (the request-scoped DB handle), and the per-resource
  service getters. Handlers call the application services returned here; they do
  NOT open sessions or embed business rules.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Protocol

from fastapi import Depends, Request

from ctf_generator.application.auth import AuthService
from ctf_generator.application.authoring.build_service import BuildService
from ctf_generator.application.catalog import (
    ChallengeDefinitionService,
    ChallengeVersionService,
    CompetitionService,
    TeamService,
)
from ctf_generator.application.catalog.publication_service import PublicationService
from ctf_generator.application.identity import IdentityService
from ctf_generator.application.instances.service import InstanceLifecycleService
from ctf_generator.application.jobs.service import JobService
from ctf_generator.application.scheduling.service import SchedulingService
from ctf_generator.application.scoring.scoreboard_service import ScoreboardService
from ctf_generator.application.submissions.query_service import SubmissionQueryService
from ctf_generator.application.submissions.service import (
    SubmissionProcessingService,
)
from ctf_generator.infrastructure.database.session import Database

from .exceptions import AuthenticationError, AuthorizationError


class Permission(StrEnum):
    """Fine-grained permissions gating the control-plane operations."""

    COMPETITION_READ = "competition:read"
    COMPETITION_WRITE = "competition:write"
    TEAM_READ = "team:read"
    TEAM_WRITE = "team:write"
    CHALLENGE_READ = "challenge:read"
    CHALLENGE_WRITE = "challenge:write"
    CHALLENGE_PUBLISH = "challenge:publish"
    # slice-b contestant competition-loop surface.
    USER_READ = "user:read"
    USER_WRITE = "user:write"
    SUBMISSION_CREATE = "submission:create"
    SUBMISSION_READ = "submission:read"
    SCOREBOARD_READ = "scoreboard:read"
    SCOREBOARD_LAG_READ = "scoreboard:lag"
    # slice-c organizer / ops control-plane surface.
    INSTANCE_READ = "instance:read"
    INSTANCE_OPERATE = "instance:operate"
    BUILD_READ = "build:read"
    BUILD_CREATE = "build:create"
    PUBLICATION_READ = "publication:read"
    PUBLICATION_WRITE = "publication:write"
    JOB_READ = "job:read"
    JOB_OPERATE = "job:operate"


class PermissionScope(StrEnum):
    """The authorization TIER a :class:`Permission` is evaluated in (M10b).

    * ``SYSTEM`` -- deployment-global, satisfied by a system role (``admin`` /
      ``support``). Evaluated by the flat :func:`require_permission`.
    * ``AUTHORING`` -- platform-global challenge authoring, independent of any
      competition. Also evaluated by the flat :func:`require_permission`.
    * ``COMPETITION`` -- scoped to a TARGET competition: satisfied only by the
      caller's effective role IN that competition (its membership there ∪ its
      system roles). Evaluated by :func:`require_competition_permission` /
      :func:`assert_competition_permission`.
    """

    SYSTEM = "system"
    AUTHORING = "authoring"
    COMPETITION = "competition"


# Every Permission's authorization tier. MUST stay total: an unclassified
# permission is a fail-closed error (guarded at import + by a completeness test)
# so a newly added permission can never silently default to a weaker check.
PERMISSION_SCOPE: dict[Permission, PermissionScope] = {
    # SYSTEM (deployment-global; a system role).
    Permission.USER_READ: PermissionScope.SYSTEM,
    Permission.USER_WRITE: PermissionScope.SYSTEM,
    Permission.JOB_READ: PermissionScope.SYSTEM,
    Permission.JOB_OPERATE: PermissionScope.SYSTEM,
    # AUTHORING (platform-global challenge authoring; independent of a competition).
    Permission.CHALLENGE_READ: PermissionScope.AUTHORING,
    Permission.CHALLENGE_WRITE: PermissionScope.AUTHORING,
    Permission.CHALLENGE_PUBLISH: PermissionScope.AUTHORING,
    Permission.BUILD_READ: PermissionScope.AUTHORING,
    Permission.BUILD_CREATE: PermissionScope.AUTHORING,
    # COMPETITION (scoped to the target competition via the caller's membership).
    Permission.COMPETITION_READ: PermissionScope.COMPETITION,
    Permission.COMPETITION_WRITE: PermissionScope.COMPETITION,
    Permission.TEAM_READ: PermissionScope.COMPETITION,
    Permission.TEAM_WRITE: PermissionScope.COMPETITION,
    Permission.SUBMISSION_CREATE: PermissionScope.COMPETITION,
    Permission.SUBMISSION_READ: PermissionScope.COMPETITION,
    Permission.SCOREBOARD_READ: PermissionScope.COMPETITION,
    Permission.SCOREBOARD_LAG_READ: PermissionScope.COMPETITION,
    Permission.PUBLICATION_READ: PermissionScope.COMPETITION,
    Permission.PUBLICATION_WRITE: PermissionScope.COMPETITION,
    Permission.INSTANCE_READ: PermissionScope.COMPETITION,
    Permission.INSTANCE_OPERATE: PermissionScope.COMPETITION,
}

_UNCLASSIFIED = frozenset(Permission) - frozenset(PERMISSION_SCOPE)
if _UNCLASSIFIED:  # pragma: no cover - guards a future unclassified permission
    raise RuntimeError(
        "PERMISSION_SCOPE is not total; unclassified permissions: "
        f"{sorted(p.value for p in _UNCLASSIFIED)}"
    )


_ALL = frozenset(Permission)
_CATALOG_READ = frozenset(
    {Permission.COMPETITION_READ, Permission.TEAM_READ, Permission.CHALLENGE_READ}
)
# A contestant (player / captain): read the catalog + scoreboard, submit
# answers, and read submissions (confined to their own team by the tenancy
# check in :func:`submission_team_scope`, not by this coarse grant).
_CONTESTANT = _CATALOG_READ | frozenset(
    {
        Permission.SCOREBOARD_READ,
        Permission.SUBMISSION_CREATE,
        Permission.SUBMISSION_READ,
    }
)

# Role -> permission set. Roles are the identity domain's ``VALID_ROLES``. Only
# the roles relevant to a resource carry write grants; unknown roles contribute
# nothing (fail closed).
ROLE_PERMISSIONS: dict[str, frozenset[Permission]] = {
    "admin": _ALL,
    "organizer": frozenset(
        {
            Permission.COMPETITION_READ,
            Permission.COMPETITION_WRITE,
            Permission.TEAM_READ,
            Permission.TEAM_WRITE,
            Permission.CHALLENGE_READ,
            Permission.USER_READ,
            Permission.USER_WRITE,
            Permission.SUBMISSION_READ,
            Permission.SCOREBOARD_READ,
            Permission.SCOREBOARD_LAG_READ,
            # Organizer operator surface: drive instance lifecycle, trigger
            # builds, and attach/detach published versions to competitions.
            # NOT the job-queue ops surface (admin / support only).
            Permission.INSTANCE_READ,
            Permission.INSTANCE_OPERATE,
            Permission.BUILD_READ,
            Permission.BUILD_CREATE,
            Permission.PUBLICATION_READ,
            Permission.PUBLICATION_WRITE,
        }
    ),
    "author": frozenset(
        {
            Permission.COMPETITION_READ,
            Permission.CHALLENGE_READ,
            Permission.CHALLENGE_WRITE,
            Permission.CHALLENGE_PUBLISH,
            Permission.SCOREBOARD_READ,
            # An author materializes their own challenge builds.
            Permission.BUILD_READ,
            Permission.BUILD_CREATE,
        }
    ),
    "captain": _CONTESTANT,
    "player": _CONTESTANT,
    "judge": _CATALOG_READ
    | frozenset({Permission.SUBMISSION_READ, Permission.SCOREBOARD_READ}),
    "observer": _CATALOG_READ | frozenset({Permission.SCOREBOARD_READ}),
    # Support is the ops-staff role: read-only instance/build visibility plus the
    # job-queue observability + control surface (dead-letter, cancel, retry).
    "support": _CATALOG_READ
    | frozenset(
        {
            Permission.SCOREBOARD_READ,
            Permission.SCOREBOARD_LAG_READ,
            Permission.INSTANCE_READ,
            Permission.BUILD_READ,
            Permission.JOB_READ,
            Permission.JOB_OPERATE,
        }
    ),
}


# Roles whose submission reads are NOT confined to a single team. Everyone else
# (``player`` / ``captain``) may only see the team of their membership IN THE
# TARGET COMPETITION (M10b: ``submission_team_scope`` derives the team from
# ``memberships[competition_id]``, per-competition, not a flat ``Principal.team``).
TENANCY_UNRESTRICTED_ROLES = frozenset(
    {"admin", "organizer", "judge", "support", "observer", "author"}
)


@dataclass(frozen=True)
class Principal:
    """An authenticated caller. Carries only identity + authorization context --
    never a credential/secret.

    ``roles`` is the FLAT union of the caller's deployment-global system roles
    (``system_roles``) and every competition role it holds across its
    memberships; ``permissions`` resolves from that flat set via
    ``ROLE_PERMISSIONS`` (unchanged from slice a, so ``require_permission`` is
    identical). The M10a additions are populated best-effort for forward
    compatibility -- M10b tightens authorization to per-competition scoping using
    ``memberships``:

    * ``system_roles`` -- the deployment-global roles (``admin`` / ``support``)
      granted on the auth account.
    * ``memberships`` -- ``competition_id -> (role, team_name)`` for every
      competition the caller has a membership in.
    """

    subject: str
    roles: frozenset[str] = field(default_factory=frozenset)
    permissions: frozenset[Permission] = field(default_factory=frozenset)
    org: str | None = None
    team: str | None = None
    system_roles: frozenset[str] = field(default_factory=frozenset)
    memberships: Mapping[str, tuple[str, str | None]] = field(default_factory=dict)

    def has(self, permission: Permission) -> bool:
        return permission in self.permissions


def resolve_permissions(
    roles: frozenset[str] | set[str] | list[str],
) -> frozenset[Permission]:
    """Union the permission grants of every role (fail-closed on unknown roles).

    The single source of truth for role → permission resolution, used by both the
    flat ``principal_for`` and the competition-scoped ``competition_permissions``.
    """
    perms: set[Permission] = set()
    for role in roles:
        perms |= ROLE_PERMISSIONS.get(role, frozenset())
    return frozenset(perms)


def principal_for(
    subject: str,
    roles: frozenset[str] | set[str] | list[str],
    *,
    org: str | None = None,
    team: str | None = None,
    system_roles: frozenset[str] | set[str] | list[str] | None = None,
    memberships: Mapping[str, tuple[str, str | None]] | None = None,
) -> Principal:
    """Build a principal, resolving its permission set from its (flat) roles.

    ``system_roles`` / ``memberships`` are optional context: they do NOT change
    the flat ``permissions`` set (which stays over ``roles`` so
    ``require_permission`` -- SYSTEM/AUTHORING -- is unchanged), but they ARE the
    inputs the COMPETITION-scoped checks consume (``require_competition_permission``
    / ``submission_team_scope``). Existing callers that pass only ``roles`` are
    unaffected."""
    role_set = frozenset(roles)
    return Principal(
        subject=subject,
        roles=role_set,
        permissions=resolve_permissions(role_set),
        org=org,
        team=team,
        system_roles=frozenset(system_roles or frozenset()),
        memberships=dict(memberships or {}),
    )


def competition_effective_roles(
    principal: Principal, competition_id: str
) -> frozenset[str]:
    """The caller's EFFECTIVE role set for one competition: its deployment-global
    ``system_roles`` ∪ the single role of its membership in that competition (if
    any). This -- NOT the flat ``Principal.roles`` -- is what a COMPETITION-scoped
    authorization decision is resolved over, so a role held only in competition A
    grants nothing in competition B."""
    roles = set(principal.system_roles)
    membership = principal.memberships.get(competition_id)
    if membership is not None:
        roles.add(membership[0])
    return frozenset(roles)


def competition_permissions(
    principal: Principal, competition_id: str
) -> frozenset[Permission]:
    """The permissions the caller effectively holds IN one competition."""
    return resolve_permissions(competition_effective_roles(principal, competition_id))


def assert_competition_permission(
    principal: Principal, competition_id: str | None, permission: Permission
) -> None:
    """Raise :class:`AuthorizationError` unless the caller holds ``permission`` in
    ``competition_id`` (via its membership there or a system role). Fail closed on
    a missing competition id. Shared by :func:`require_competition_permission` and
    by handlers whose target competition is not a path parameter (resolved from
    the loaded resource -- e.g. an instance / submission by id)."""
    if not competition_id:
        raise AuthorizationError("no competition context for authorization")
    if permission not in competition_permissions(principal, competition_id):
        raise AuthorizationError(
            f"principal lacks {permission.value!r} in competition "
            f"{competition_id!r}"
        )


def authorized_competitions(
    principal: Principal, permission: Permission
) -> frozenset[str] | None:
    """The competitions in which the caller holds ``permission``.

    Returns ``None`` when a system role grants it deployment-wide (an unrestricted
    cross-competition view); otherwise the (possibly empty) set of competition ids
    where a membership grants it. Used to SAFELY filter cross-competition operator
    lists (e.g. ``GET /instances``) so a caller never sees another competition's
    rows."""
    if permission in resolve_permissions(principal.system_roles):
        return None
    return frozenset(
        competition_id
        for competition_id, (role, _team) in principal.memberships.items()
        if permission in ROLE_PERMISSIONS.get(role, frozenset())
    )


@dataclass(frozen=True)
class SubmissionAccess:
    """A principal's submission tenancy scope.

    ``unrestricted`` distinguishes a tenancy-unrestricted role (organizer / admin
    / staff -- may act on any team) from a team-scoped role. For a team-scoped
    principal, ``team`` is the single team it is confined to; ``team is None``
    means the principal is not placed on a team and can see NOTHING (fail closed).
    ``team`` is meaningful only when ``unrestricted`` is False.
    """

    unrestricted: bool
    team: str | None


def submission_team_scope(
    principal: Principal, competition_id: str
) -> SubmissionAccess:
    """Resolve a principal's submission tenancy scope WITHIN one competition.

    The team is derived from the caller's per-competition membership
    (``memberships[competition_id]``), NOT a flat single team -- so a player of
    team Red in competition X is confined to Red in X and has no standing in
    competition Y (a same-named team in a different competition no longer leaks).

    * A caller whose EFFECTIVE role in this competition is tenancy-unrestricted
      (organizer of this competition / admin / staff / observer / judge / author)
      may act on any team in it.
    * A team-scoped role (``player`` / ``captain``) is confined to the team of its
      membership in THIS competition.
    * A team-scoped caller not placed on a team in this competition (no membership,
      or a membership with no team) is denied entirely (fail closed)."""
    if competition_effective_roles(principal, competition_id) & (
        TENANCY_UNRESTRICTED_ROLES
    ):
        return SubmissionAccess(unrestricted=True, team=None)
    membership = principal.memberships.get(competition_id)
    team = membership[1] if membership is not None else None
    return SubmissionAccess(unrestricted=False, team=team)


class Authenticator(Protocol):
    """Resolves a bearer token to a :class:`Principal`.

    Implementations MUST raise :class:`AuthenticationError` for a missing or
    invalid token and MUST NOT log or echo the token.
    """

    def authenticate(self, token: str | None) -> Principal: ...


class StubAuthenticator:
    """Dev-only static bearer-token authenticator for slice a.

    Constructed with a ``token -> Principal`` table. **Not for production** --
    M10 replaces it. It performs no cryptography and stores no secret beyond the
    opaque dev tokens the operator seeds; it never logs them.
    """

    def __init__(self, tokens: dict[str, Principal] | None = None) -> None:
        self._tokens = dict(tokens or {})

    def register(self, token: str, principal: Principal) -> None:
        self._tokens[token] = principal

    def authenticate(self, token: str | None) -> Principal:
        if not token:
            raise AuthenticationError("missing bearer token")
        principal = self._tokens.get(token)
        if principal is None:
            raise AuthenticationError("invalid bearer token")
        return principal


def _bearer_token(request: Request) -> str | None:
    header = request.headers.get("authorization")
    if not header:
        return None
    scheme, _, value = header.partition(" ")
    if scheme.lower() != "bearer" or not value.strip():
        return None
    return value.strip()


def get_authenticator(request: Request) -> Authenticator:
    authenticator = getattr(request.app.state, "authenticator", None)
    if authenticator is None:  # pragma: no cover - misconfiguration guard
        raise AuthenticationError("no authenticator configured")
    return authenticator


def get_principal(request: Request) -> Principal:
    """Authenticate the caller. Raises 401 on a missing/invalid token. Stashes
    the principal on ``request.state`` so the access log can record its subject
    (never a secret)."""
    authenticator = get_authenticator(request)
    principal = authenticator.authenticate(_bearer_token(request))
    request.state.principal = principal
    return principal


def require_permission(permission: Permission):
    """Return a dependency that authenticates then enforces ``permission`` (403
    if absent)."""

    def _dependency(principal: Principal = Depends(get_principal)) -> Principal:
        if not principal.has(permission):
            raise AuthorizationError(
                f"principal lacks required permission {permission.value!r}"
            )
        return principal

    return _dependency


def require_competition_permission(permission: Permission):
    """Return a dependency that authenticates then enforces ``permission`` IN the
    ``{competition_id}`` from the request path (403 if the caller has no effective
    role granting it there). This is the COMPETITION-scoped counterpart to the flat
    :func:`require_permission`: an organizer of competition A is denied in B because
    its membership -- not its flat role union -- is what the check consults. A
    system role (``admin`` / ``support``) is granted in every competition."""

    def _dependency(
        request: Request, principal: Principal = Depends(get_principal)
    ) -> Principal:
        competition_id = request.path_params.get("competition_id")
        assert_competition_permission(principal, competition_id, permission)
        return principal

    return _dependency


def require_any_competition_permission(permission: Permission):
    """Return a dependency for a cross-competition operator LIST view: authenticate
    then require the caller holds ``permission`` in at least ONE competition (or
    deployment-wide via a system role). The handler still filters its result set to
    :func:`authorized_competitions` so no other competition's rows leak; this
    dependency only fail-closes a caller (e.g. a contestant) with the permission
    NOWHERE, so it gets a 403 rather than an empty 200."""

    def _dependency(principal: Principal = Depends(get_principal)) -> Principal:
        allowed = authorized_competitions(principal, permission)
        if allowed is not None and not allowed:
            raise AuthorizationError(
                f"principal lacks {permission.value!r} in any competition"
            )
        return principal

    return _dependency


def get_database(request: Request) -> Database:
    database = getattr(request.app.state, "database", None)
    if database is None:  # pragma: no cover - misconfiguration guard
        raise RuntimeError("no database configured on the API app")
    return database


def get_auth_service(request: Request) -> AuthService:
    """The shared, app-scoped :class:`AuthService`.

    Unlike the per-resource services (constructed per request over the database
    handle), the auth service is a single stateless instance stashed on
    ``app.state`` at startup -- so its password hasher / session TTL / lazily
    computed dummy-hash are shared with the app's ``DbAuthenticator`` (the seam
    that resolves bearer sessions to a ``Principal``). Every method still opens
    its own unit of work; nothing request-scoped is held."""
    service = getattr(request.app.state, "auth_service", None)
    if service is None:
        raise RuntimeError("no auth service configured on the API app")
    return service


def get_competition_service(
    database: Database = Depends(get_database),
) -> CompetitionService:
    return CompetitionService(database)


def get_team_service(database: Database = Depends(get_database)) -> TeamService:
    return TeamService(database)


def get_challenge_definition_service(
    database: Database = Depends(get_database),
) -> ChallengeDefinitionService:
    return ChallengeDefinitionService(database)


def get_challenge_version_service(
    database: Database = Depends(get_database),
) -> ChallengeVersionService:
    return ChallengeVersionService(database)


def get_identity_service(database: Database = Depends(get_database)) -> IdentityService:
    return IdentityService(database)


def get_submission_processing_service(
    database: Database = Depends(get_database),
) -> SubmissionProcessingService:
    return SubmissionProcessingService(database)


def get_submission_query_service(
    database: Database = Depends(get_database),
) -> SubmissionQueryService:
    return SubmissionQueryService(database)


def get_scoreboard_service(
    database: Database = Depends(get_database),
) -> ScoreboardService:
    return ScoreboardService(database)


def get_job_service(database: Database = Depends(get_database)) -> JobService:
    return JobService(database)


def get_build_service(database: Database = Depends(get_database)) -> BuildService:
    return BuildService(database, jobs=JobService(database))


def get_publication_service(
    database: Database = Depends(get_database),
) -> PublicationService:
    return PublicationService(database)


def get_instance_lifecycle_service(
    database: Database = Depends(get_database),
) -> InstanceLifecycleService:
    # The lifecycle service composes the scheduling + job collaborators exactly as
    # the M8 workers do; the API only ever calls its desired-state / read methods
    # (it never launches a container -- the corrective jobs it enqueues are claimed
    # by workers with scoped credentials).
    return InstanceLifecycleService(
        database,
        scheduling=SchedulingService(database),
        jobs=JobService(database),
    )
