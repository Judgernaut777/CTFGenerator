"""Compatibility shim (M5 refactor).

The challenge/competition/scoring/submission value types moved to
``ctf_generator.domain.challenges.models`` as the domain layer was established.
This module re-exports them so the ~40 existing ``from .models import ...`` /
``from ..models import ...`` call sites keep working unchanged. New code should
import from ``ctf_generator.domain.challenges.models`` (or a future
``ctf_generator.domain`` facade) directly.
"""

from __future__ import annotations

from .domain.challenges.models import (
    SPEC_VERSION,
    AIResistance,
    ChallengeScoringConfig,
    ChallengeSpec,
    ChallengeValueSnapshot,
    CompetitionConfig,
    DynamicVariation,
    FirstBloodBonusConfig,
    ResponseSpec,
    ScenarioSpec,
    ScoreboardEntry,
    ScoreboardSnapshot,
    SolveEvent,
    Submission,
    TriggerSpec,
    solve_event_from_submission,
)

__all__ = [
    "SPEC_VERSION",
    "AIResistance",
    "ChallengeScoringConfig",
    "ChallengeSpec",
    "ChallengeValueSnapshot",
    "CompetitionConfig",
    "DynamicVariation",
    "FirstBloodBonusConfig",
    "ResponseSpec",
    "ScenarioSpec",
    "ScoreboardEntry",
    "ScoreboardSnapshot",
    "SolveEvent",
    "Submission",
    "TriggerSpec",
    "solve_event_from_submission",
]
