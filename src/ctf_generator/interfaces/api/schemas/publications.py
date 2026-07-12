"""Publication DTOs + mappers (organizer attaches a version to a competition).

A publication is a published challenge version attached to a competition with its
per-competition scoring config, keyed by ``(competition_id, definition_slug,
version_no)``. All fields are public configuration -- no secret is involved.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from ctf_generator.domain.authoring.models import ChallengePublication


class PublicationCreateRequest(BaseModel):
    """Attach a published version to the competition named in the path. The
    scoring fields default to the domain defaults."""

    definition_slug: str = Field(min_length=1)
    version_no: int = Field(ge=1)
    initial_value: int = Field(default=500, ge=0)
    minimum_value: int = Field(default=100, ge=0)
    decay_function: str = Field(default="static")
    decay: int = Field(default=0, ge=0)
    first_blood_enabled: bool = True
    first_blood_bonus_points: int = Field(default=0, ge=0)
    first_blood_bonus_percent: float = Field(default=0.0, ge=0.0)

    def to_domain(self, competition_id: str) -> ChallengePublication:
        return ChallengePublication(
            competition_id=competition_id,
            definition_slug=self.definition_slug,
            version_no=self.version_no,
            initial_value=self.initial_value,
            minimum_value=self.minimum_value,
            decay_function=self.decay_function,
            decay=self.decay,
            first_blood_enabled=self.first_blood_enabled,
            first_blood_bonus_points=self.first_blood_bonus_points,
            first_blood_bonus_percent=self.first_blood_bonus_percent,
        )


class PublicationResponse(BaseModel):
    competition_id: str
    definition_slug: str
    version_no: int
    initial_value: int
    minimum_value: int
    decay_function: str
    decay: int
    first_blood_enabled: bool
    first_blood_bonus_points: int
    first_blood_bonus_percent: float


def publication_to_response(publication: ChallengePublication) -> dict[str, Any]:
    return {
        "competition_id": publication.competition_id,
        "definition_slug": publication.definition_slug,
        "version_no": publication.version_no,
        "initial_value": publication.initial_value,
        "minimum_value": publication.minimum_value,
        "decay_function": publication.decay_function,
        "decay": publication.decay,
        "first_blood_enabled": publication.first_blood_enabled,
        "first_blood_bonus_points": publication.first_blood_bonus_points,
        "first_blood_bonus_percent": publication.first_blood_bonus_percent,
    }


def publication_concurrency_payload(
    publication: ChallengePublication,
) -> dict[str, Any]:
    return publication_to_response(publication)
