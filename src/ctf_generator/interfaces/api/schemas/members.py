"""Membership DTOs + mappers (a user's role + team placement in one competition)."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from ctf_generator.domain.identity.models import Membership


class MembershipAssignRequest(BaseModel):
    """PUT body for assigning/re-assigning a membership. The user + competition are
    path parameters; only the mutable placement (role, optional team) is in the
    body."""

    role: str = Field(min_length=1)
    team_name: str | None = Field(default=None, min_length=1)


class MembershipResponse(BaseModel):
    competition_id: str
    user_email: str
    role: str
    team_name: str | None = None


def membership_concurrency_payload(m: Membership) -> dict[str, Any]:
    return {
        "competition_id": m.competition_id,
        "user_email": m.user_email,
        "role": m.role,
        "team_name": m.team_name,
    }


def membership_to_response(m: Membership) -> dict[str, Any]:
    return {
        "competition_id": m.competition_id,
        "user_email": m.user_email,
        "role": m.role,
        "team_name": m.team_name,
    }
