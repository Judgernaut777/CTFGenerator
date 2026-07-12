"""The authentication / authorization seam + shared request dependencies.

This is the seam M10 replaces with real local-auth + OIDC. Slice a ships:

* :class:`Principal` -- the authenticated caller (subject, roles, resolved
  permissions, optional org/team context). Framework-free.
* :class:`Permission` -- the fine-grained permission enum, and ``ROLE_PERMISSIONS``
  mapping the identity roles (``VALID_ROLES``) to permission sets.
* :class:`Authenticator` -- a ``Protocol`` the API programs against, and
  :class:`StubAuthenticator`, a dev-only bearer-token implementation for slice a
  (a static ``token -> Principal`` table). **TODO(M10): replace StubAuthenticator
  with real credential verification (local password/session + OIDC).** The stub
  never logs or echoes a token. The module-level app registers a dev token ONLY
  when ``CTFGEN_API_INSECURE_STUB_AUTH=1`` is explicitly set (see
  ``app._authenticator_from_env``), so it is never a silent production default.
* dependencies: :func:`get_principal` (delegates to the app's authenticator),
  :func:`require_permission` (403 if the principal lacks the permission),
  :func:`get_database` (the request-scoped DB handle), and the per-resource
  service getters. Handlers call the application services returned here; they do
  NOT open sessions or embed business rules.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Protocol

from fastapi import Depends, Request

from ctf_generator.application.catalog import (
    ChallengeDefinitionService,
    ChallengeVersionService,
    CompetitionService,
    TeamService,
)
from ctf_generator.application.identity import IdentityService
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
        }
    ),
    "author": frozenset(
        {
            Permission.COMPETITION_READ,
            Permission.CHALLENGE_READ,
            Permission.CHALLENGE_WRITE,
            Permission.CHALLENGE_PUBLISH,
            Permission.SCOREBOARD_READ,
        }
    ),
    "captain": _CONTESTANT,
    "player": _CONTESTANT,
    "judge": _CATALOG_READ
    | frozenset({Permission.SUBMISSION_READ, Permission.SCOREBOARD_READ}),
    "observer": _CATALOG_READ | frozenset({Permission.SCOREBOARD_READ}),
    "support": _CATALOG_READ
    | frozenset({Permission.SCOREBOARD_READ, Permission.SCOREBOARD_LAG_READ}),
}


# Roles whose submission reads are NOT confined to a single team. Everyone else
# (``player`` / ``captain``) may only see their own ``Principal.team``. This is
# the coarse team-scope tenancy slice-b can enforce from what the Principal
# already carries; full per-org/per-team resource ownership is deferred to M10
# (see docs/api/slice-a-limitations.md).
TENANCY_UNRESTRICTED_ROLES = frozenset(
    {"admin", "organizer", "judge", "support", "observer", "author"}
)


@dataclass(frozen=True)
class Principal:
    """An authenticated caller. Carries only identity + authorization context --
    never a credential/secret."""

    subject: str
    roles: frozenset[str] = field(default_factory=frozenset)
    permissions: frozenset[Permission] = field(default_factory=frozenset)
    org: str | None = None
    team: str | None = None

    def has(self, permission: Permission) -> bool:
        return permission in self.permissions


def principal_for(
    subject: str,
    roles: frozenset[str] | set[str] | list[str],
    *,
    org: str | None = None,
    team: str | None = None,
) -> Principal:
    """Build a principal, resolving its permission set from its roles."""
    role_set = frozenset(roles)
    perms: set[Permission] = set()
    for role in role_set:
        perms |= ROLE_PERMISSIONS.get(role, frozenset())
    return Principal(
        subject=subject,
        roles=role_set,
        permissions=frozenset(perms),
        org=org,
        team=team,
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


def submission_team_scope(principal: Principal) -> SubmissionAccess:
    """Resolve a principal's submission tenancy scope.

    A tenancy-unrestricted principal (organizer / admin / staff) may act on any
    team. A team-scoped principal (``player`` / ``captain``) is confined to its own
    :attr:`Principal.team`; a principal with no team is denied entirely until
    placed on a team (fail closed)."""
    if principal.roles & TENANCY_UNRESTRICTED_ROLES:
        return SubmissionAccess(unrestricted=True, team=None)
    return SubmissionAccess(unrestricted=False, team=principal.team)


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


def get_database(request: Request) -> Database:
    database = getattr(request.app.state, "database", None)
    if database is None:  # pragma: no cover - misconfiguration guard
        raise RuntimeError("no database configured on the API app")
    return database


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
