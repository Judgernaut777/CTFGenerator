"""Auth DTOs + mappers (login / refresh / me).

Request/response models for the ``/auth`` surface. Secrets discipline: the login
request carries a ``password`` (accepted, never echoed / logged); the token
responses carry the raw session token EXACTLY ONCE (at login / refresh) and
nothing else sensitive; ``/auth/me`` NEVER returns a token, password, or hash --
only the resolved principal summary.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from ctf_generator.domain.auth.models import IssuedSession

from ..deps import Principal


class LoginRequest(BaseModel):
    email: str = Field(min_length=1, description="Case-insensitive account email")
    password: str = Field(
        min_length=1, description="Local account password (never logged/echoed)"
    )


class TokenResponse(BaseModel):
    token: str = Field(description="Opaque bearer session token (shown once)")
    expires_at: datetime


class MembershipSummary(BaseModel):
    competition_id: str
    role: str
    team: str | None = None


class MeResponse(BaseModel):
    subject: str
    system_roles: list[str]
    roles: list[str]
    memberships: list[MembershipSummary]


def token_response(issued: IssuedSession) -> dict[str, Any]:
    """The one-time token payload. Carries the raw token (returned once) and its
    expiry -- nothing else."""
    return {
        "token": issued.token,
        "expires_at": issued.expires_at.isoformat(),
    }


def me_response(principal: Principal) -> dict[str, Any]:
    """The current-principal summary -- identity + roles only, NEVER a token or
    secret."""
    return {
        "subject": principal.subject,
        "system_roles": sorted(principal.system_roles),
        "roles": sorted(principal.roles),
        "memberships": [
            {"competition_id": competition_id, "role": role, "team": team}
            for competition_id, (role, team) in sorted(principal.memberships.items())
        ],
    }
