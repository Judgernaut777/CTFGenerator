"""Competition DTOs + mappers (maps the domain ``CompetitionConfig``).

``default_scoring`` is intentionally absent from the write DTOs: its persistence
raises ``NotImplementedError`` today (it normalizes into ``competition_challenges``
in a later step), so slice a neither accepts nor stores it. The response DTO
surfaces it as ``null`` to keep the wire shape forward-compatible.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, model_validator

from ctf_generator.domain.challenges.models import CompetitionConfig


def validate_window(
    start: datetime,
    end: datetime,
    scoring_start: datetime | None,
    freeze: datetime | None,
) -> list[dict[str, str]]:
    """Return a list of ``{field, issue}`` problems for an invalid timing window
    (empty when valid). Shared by the create validator and the PATCH handler so
    both paths reject the same states."""
    problems: list[dict[str, str]] = []
    if end <= start:
        problems.append({"field": "end_time", "issue": "must be after start_time"})
    if scoring_start is not None and not (start <= scoring_start <= end):
        problems.append(
            {"field": "scoring_start_time", "issue": "must be within [start_time, end_time]"}
        )
    if freeze is not None and not (start <= freeze <= end):
        problems.append(
            {"field": "freeze_time", "issue": "must be within [start_time, end_time]"}
        )
    return problems


class CompetitionCreateRequest(BaseModel):
    competition_id: str = Field(min_length=1, description="Stable business slug")
    name: str = Field(min_length=1)
    start_time: datetime
    end_time: datetime
    scoring_start_time: datetime | None = None
    freeze_time: datetime | None = None

    @model_validator(mode="after")
    def _check_window(self) -> CompetitionCreateRequest:
        problems = validate_window(
            self.start_time, self.end_time, self.scoring_start_time, self.freeze_time
        )
        if problems:
            raise ValueError("; ".join(p["issue"] for p in problems))
        return self

    def to_domain(self) -> CompetitionConfig:
        return CompetitionConfig(
            competition_id=self.competition_id,
            name=self.name,
            start_time=self.start_time,
            end_time=self.end_time,
            scoring_start_time=self.scoring_start_time,
            freeze_time=self.freeze_time,
        )


class CompetitionPatchRequest(BaseModel):
    """Partial update. Every field optional; the handler merges onto the current
    aggregate and re-validates the timing window."""

    name: str | None = Field(default=None, min_length=1)
    start_time: datetime | None = None
    end_time: datetime | None = None
    scoring_start_time: datetime | None = None
    freeze_time: datetime | None = None


class CompetitionResponse(BaseModel):
    competition_id: str
    name: str
    start_time: datetime
    end_time: datetime
    scoring_start_time: datetime | None = None
    freeze_time: datetime | None = None
    default_scoring: dict[str, Any] | None = None


def competition_concurrency_payload(config: CompetitionConfig) -> dict[str, Any]:
    """The concurrency-relevant projection an ETag is computed from."""
    return config.to_mapping()


def competition_to_response(config: CompetitionConfig) -> dict[str, Any]:
    return {
        "competition_id": config.competition_id,
        "name": config.name,
        "start_time": config.start_time.isoformat(),
        "end_time": config.end_time.isoformat(),
        "scoring_start_time": (
            config.scoring_start_time.isoformat()
            if config.scoring_start_time
            else None
        ),
        "freeze_time": config.freeze_time.isoformat() if config.freeze_time else None,
        "default_scoring": (
            config.default_scoring.to_mapping() if config.default_scoring else None
        ),
    }
