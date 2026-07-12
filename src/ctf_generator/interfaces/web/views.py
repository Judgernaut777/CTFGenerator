"""Domain -> view-dict mapping (M11 slice a).

Handlers map the ORM-free application aggregates onto plain dicts BEFORE handing
them to a template, so an ORM object / lazy relationship never escapes into the
rendering layer, and the exact set of rendered fields is explicit and auditable.
A :class:`CompetitionConfig` carries NO secret (no flags, tokens, or credentials),
and this mapping renders only its timing/scoring configuration.
"""

from __future__ import annotations

from typing import Any

from ctf_generator.domain.challenges.models import CompetitionConfig


def _iso(value: Any) -> str | None:
    return value.isoformat() if value is not None else None


def competition_row(config: CompetitionConfig) -> dict[str, Any]:
    """A compact list-row view (id + name + window bounds)."""
    return {
        "competition_id": config.competition_id,
        "name": config.name,
        "start_time": _iso(config.start_time),
        "end_time": _iso(config.end_time),
    }


def competition_detail(config: CompetitionConfig) -> dict[str, Any]:
    """The full read view of a competition's configuration (no secrets)."""
    scoring = config.default_scoring
    scoring_view: dict[str, Any] | None = None
    if scoring is not None:
        scoring_view = {
            "challenge_id": scoring.challenge_id,
            "initial_value": scoring.initial_value,
            "minimum_value": scoring.minimum_value,
            "decay_function": scoring.decay_function,
            "decay": scoring.decay,
            "first_blood_enabled": scoring.first_blood_bonus.enabled,
            "first_blood_bonus_points": scoring.first_blood_bonus.bonus_points,
            "first_blood_bonus_percent": scoring.first_blood_bonus.bonus_percent,
        }
    return {
        "competition_id": config.competition_id,
        "name": config.name,
        "start_time": _iso(config.start_time),
        "end_time": _iso(config.end_time),
        "scoring_start_time": _iso(config.scoring_start_time),
        "freeze_time": _iso(config.freeze_time),
        "scoring": scoring_view,
    }
