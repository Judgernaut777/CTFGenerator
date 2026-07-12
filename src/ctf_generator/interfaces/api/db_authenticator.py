"""The real local-auth :class:`~.deps.Authenticator` (M10 slice a).

``DbAuthenticator`` replaces the M9 ``StubAuthenticator`` seam: it resolves a
presented Bearer *session* token to a :class:`~.deps.Principal` backed by real
data. It delegates the cryptographic + persistence work to the application
:class:`~ctf_generator.application.auth.AuthService` (hash the token, look up the
live session, load the user's system roles + competition memberships) and maps
the layer-neutral ``ResolvedPrincipal`` onto the API ``Principal`` via the
EXISTING ``ROLE_PERMISSIONS`` resolution -- so every ``require_permission`` check
and every existing authorization test behaves identically; only the *source* of
the principal changed (a real session instead of a static dev table).

Authorization stays the flat permission model this slice: the principal's flat
``roles`` is the union of the caller's system roles and every competition role it
holds; ``system_roles`` / ``memberships`` are populated best-effort for M10b
(per-competition scoping) to tighten later. Any failure (missing / invalid /
expired / revoked token) surfaces as a single :class:`AuthenticationError` -- the
caller never learns which check failed, and the token is never logged or echoed.
"""

from __future__ import annotations

from datetime import UTC, datetime

from ctf_generator.application.auth import AuthService, InvalidCredentialsError

from .deps import Principal, principal_for
from .exceptions import AuthenticationError


class DbAuthenticator:
    """Resolve a Bearer session token to a :class:`Principal` from real data."""

    def __init__(self, auth_service: AuthService) -> None:
        self._auth = auth_service

    def authenticate(self, token: str | None) -> Principal:
        now = datetime.now(UTC)
        try:
            resolved = self._auth.resolve(token, now)
        except InvalidCredentialsError as exc:
            # Deliberately undifferentiated: missing / invalid / expired /
            # revoked all map to the same 401 with no token echoed.
            raise AuthenticationError("invalid or expired credentials") from exc

        memberships: dict[str, tuple[str, str | None]] = {
            competition_id: (role, team_name)
            for competition_id, role, team_name in resolved.memberships
        }
        # Flat role set = system roles ∪ every competition role held. Permission
        # resolution (in principal_for) is unchanged from slice a.
        flat_roles = set(resolved.system_roles) | {
            role for _cid, role, _team in resolved.memberships
        }
        return principal_for(
            resolved.subject,
            flat_roles,
            team=_best_effort_team(resolved.memberships),
            system_roles=resolved.system_roles,
            memberships=memberships,
        )


def _best_effort_team(
    memberships: tuple[tuple[str, str, str | None], ...],
) -> str | None:
    """A forward-compat single-team hint for the still-coarse submission tenancy
    check (``submission_team_scope`` reads ``Principal.team``). Deterministically
    the team of the caller's first team-placed membership (sorted by competition
    id); ``None`` if the caller is unteamed everywhere. M10b replaces this with
    per-competition scoping."""
    for _competition_id, _role, team_name in sorted(memberships):
        if team_name is not None:
            return team_name
    return None
