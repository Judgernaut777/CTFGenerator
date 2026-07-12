"""Team DTOs + mappers (maps the domain ``Team``, keyed by ``(competition_id,
name)``)."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from ctf_generator.domain.identity.models import Team


class TeamCreateRequest(BaseModel):
    competition_id: str = Field(min_length=1)
    name: str = Field(min_length=1)

    def to_domain(self) -> Team:
        return Team(competition_id=self.competition_id, name=self.name)


class TeamResponse(BaseModel):
    competition_id: str
    name: str


def team_concurrency_payload(team: Team) -> dict[str, Any]:
    return {"competition_id": team.competition_id, "name": team.name}


def team_to_response(team: Team) -> dict[str, Any]:
    return {"competition_id": team.competition_id, "name": team.name}
