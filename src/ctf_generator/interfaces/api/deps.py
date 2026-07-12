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
from ctf_generator.infrastructure.database.session import Database

from .exceptions import AuthenticationError, AuthorizationError


class Permission(StrEnum):
    """Fine-grained permissions gating slice-a operations."""

    COMPETITION_READ = "competition:read"
    COMPETITION_WRITE = "competition:write"
    TEAM_READ = "team:read"
    TEAM_WRITE = "team:write"
    CHALLENGE_READ = "challenge:read"
    CHALLENGE_WRITE = "challenge:write"
    CHALLENGE_PUBLISH = "challenge:publish"


_ALL = frozenset(Permission)
_READ_ONLY = frozenset(
    {Permission.COMPETITION_READ, Permission.TEAM_READ, Permission.CHALLENGE_READ}
)

# Role -> permission set. Roles are the identity domain's ``VALID_ROLES``; only
# the roles relevant to slice-a resources carry write grants. Unknown roles
# contribute nothing (fail closed).
ROLE_PERMISSIONS: dict[str, frozenset[Permission]] = {
    "admin": _ALL,
    "organizer": frozenset(
        {
            Permission.COMPETITION_READ,
            Permission.COMPETITION_WRITE,
            Permission.TEAM_READ,
            Permission.TEAM_WRITE,
            Permission.CHALLENGE_READ,
        }
    ),
    "author": frozenset(
        {
            Permission.COMPETITION_READ,
            Permission.CHALLENGE_READ,
            Permission.CHALLENGE_WRITE,
            Permission.CHALLENGE_PUBLISH,
        }
    ),
    "captain": _READ_ONLY,
    "judge": _READ_ONLY,
    "observer": _READ_ONLY,
    "support": _READ_ONLY,
    "player": _READ_ONLY,
}


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
