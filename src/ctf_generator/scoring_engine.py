"""Compatibility shim for pluggable competition scoring.

The scoring engines, registry, config validation, and event bridge now live in
``ctf_generator.domain.scoring.scoring_engine`` (domain-pure: it depends only
on the event contract in ``domain.competitions.events`` and the value types in
``domain.challenges.models``). This module re-exports their public names -- and
the process-wide ``_REGISTRY`` -- so existing
``from ctf_generator.scoring_engine import ...`` call sites keep working
unchanged.
"""

from __future__ import annotations

from .domain.scoring.scoring_engine import (
    _DEFAULT_ENGINE_NAME,
    _REGISTRY,
    _VALID_DECAY_FUNCTIONS,
    AIResistanceWeightedEngine,
    DynamicDecayEngine,
    ScoringEngine,
    StaticPointsEngine,
    TimeDecayEngine,
    get_scoring_engine,
    list_scoring_engines,
    register_scoring_engine,
    solve_event_from_event,
    validate_competition_config,
)

__all__ = [
    "AIResistanceWeightedEngine",
    "DynamicDecayEngine",
    "ScoringEngine",
    "StaticPointsEngine",
    "TimeDecayEngine",
    "get_scoring_engine",
    "list_scoring_engines",
    "register_scoring_engine",
    "solve_event_from_event",
    "validate_competition_config",
]
