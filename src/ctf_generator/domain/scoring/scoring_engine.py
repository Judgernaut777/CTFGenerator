"""Pluggable competition scoring.

Stdlib-only. Every ``ScoringEngine`` implementation is a pure function of its
inputs -- wall-clock time is never read internally; callers always pass
``now`` explicitly, which keeps engines deterministic and trivially testable.

Four engines are registered by default:

* :class:`StaticPointsEngine` (``"static"``) -- constant per-challenge value.
* :class:`DynamicDecayEngine` (``"dynamic_decay"``) -- CTFd-style value decay
  as ``solve_count`` rises, honoring ``ChallengeScoringConfig.decay_function``
  and ``.decay``.
* :class:`TimeDecayEngine` (``"time_decay"``) -- value decays with elapsed
  competition time rather than solve count. **This is the default engine**
  returned by :func:`get_scoring_engine` when no name is given.
* :class:`AIResistanceWeightedEngine` (``"ai_resistance"``) -- wraps another
  engine and applies an advisory per-challenge weight multiplier. Weights are
  injected explicitly (no hidden data source), so by default -- with no
  weights configured -- it is a no-op passthrough.

All four are registered into the process-wide registry at import time, mirroring
the ``register``/``get``/... registry pattern in ``families.py``.
"""

from __future__ import annotations

from datetime import datetime
from typing import Protocol

from ..competitions.events import Event
from ..challenges.models import ChallengeScoringConfig, CompetitionConfig, SolveEvent

# --- Engine protocol ---------------------------------------------------------


class ScoringEngine(Protocol):
    name: str

    def challenge_value(
        self,
        challenge: ChallengeScoringConfig,
        solve_count: int,
        competition: CompetitionConfig,
        now: datetime,
    ) -> float: ...


# --- Static engine -----------------------------------------------------------


class StaticPointsEngine:
    """Constant value: always ``challenge.initial_value``, regardless of
    solve count or time."""

    name = "static"

    def challenge_value(
        self,
        challenge: ChallengeScoringConfig,
        solve_count: int,
        competition: CompetitionConfig,
        now: datetime,
    ) -> float:
        return float(challenge.initial_value)


# --- Dynamic (solve-count) decay engine ---------------------------------------


class DynamicDecayEngine:
    """CTFd-style value decay as ``solve_count`` rises.

    Honors ``ChallengeScoringConfig.decay_function`` / ``.decay``:

    * ``"static"`` (or ``decay <= 0``) -- no decay; always ``initial_value``.
    * ``"linear"`` -- value drops linearly from ``initial_value`` to
      ``minimum_value`` over ``decay`` solves, then stays at the floor.
    * ``"logarithmic"`` -- CTFd's classic quadratic-in-solves curve:
      ``((minimum - initial) / decay**2) * solve_count**2 + initial``, which
      falls off faster near ``decay`` solves and is clamped at the floor.

    The result is always clamped to ``[minimum_value, initial_value]``, so an
    unrecognized ``decay_function`` behaves like ``"static"``.
    """

    name = "dynamic_decay"

    def challenge_value(
        self,
        challenge: ChallengeScoringConfig,
        solve_count: int,
        competition: CompetitionConfig,
        now: datetime,
    ) -> float:
        initial = float(challenge.initial_value)
        minimum = float(challenge.minimum_value)
        decay = challenge.decay
        solves = max(0, solve_count)

        if challenge.decay_function == "linear" and decay > 0:
            value = initial - (initial - minimum) * (solves / decay)
        elif challenge.decay_function == "logarithmic" and decay > 0:
            value = ((minimum - initial) / (decay**2)) * (solves**2) + initial
        else:
            value = initial

        lo, hi = (minimum, initial) if minimum <= initial else (initial, minimum)
        return max(lo, min(hi, value))


# --- Time decay engine (default) ----------------------------------------------


class TimeDecayEngine:
    """Value decays linearly with elapsed competition time, not solve count.

    Rewards early solves. The decay window runs from
    ``competition.scoring_start_time`` (falling back to ``.start_time`` when
    unset) to ``competition.end_time``. ``competition.freeze_time`` -- if
    set -- caps the effective clock, so value stops dropping once the
    scoreboard would be frozen.

    Floors at ``challenge.minimum_value`` and never exceeds
    ``challenge.initial_value``, including in degenerate configs (e.g. a
    zero-length or inverted window).
    """

    name = "time_decay"

    def challenge_value(
        self,
        challenge: ChallengeScoringConfig,
        solve_count: int,
        competition: CompetitionConfig,
        now: datetime,
    ) -> float:
        initial = float(challenge.initial_value)
        minimum = float(challenge.minimum_value)
        lo, hi = (minimum, initial) if minimum <= initial else (initial, minimum)

        start = competition.scoring_start_time or competition.start_time
        end = competition.end_time
        effective_now = now
        if competition.freeze_time is not None and effective_now > competition.freeze_time:
            effective_now = competition.freeze_time

        window = (end - start).total_seconds()
        if window <= 0:
            # Degenerate/inverted window: no meaningful decay curve, so
            # behave like the static engine.
            return hi

        elapsed = (effective_now - start).total_seconds()
        if elapsed <= 0:
            return hi
        if elapsed >= window:
            return lo

        fraction = elapsed / window
        value = initial - (initial - minimum) * fraction
        return max(lo, min(hi, value))


# --- AI-resistance weighted engine ---------------------------------------------


class AIResistanceWeightedEngine:
    """Wraps another engine and applies an advisory per-challenge weight.

    There is no AI-resistance factor on ``ChallengeScoringConfig`` itself (it
    lives on ``ChallengeSpec.ai_resistance`` in a different layer), so weights
    are supplied explicitly via ``weights`` (``challenge_id -> multiplier``),
    keeping this engine pure/deterministic and this module free of any
    dependency on generation-time models. Advisory by design: with no weights
    configured, every challenge gets ``default_weight`` (1.0), so this engine
    is a transparent passthrough over its wrapped ``base_engine`` unless the
    caller opts in.
    """

    name = "ai_resistance"

    def __init__(
        self,
        weights: dict[str, float] | None = None,
        default_weight: float = 1.0,
        base_engine: ScoringEngine | None = None,
    ) -> None:
        self._weights: dict[str, float] = dict(weights) if weights else {}
        self._default_weight = default_weight
        self._base_engine: ScoringEngine = base_engine or StaticPointsEngine()

    def challenge_value(
        self,
        challenge: ChallengeScoringConfig,
        solve_count: int,
        competition: CompetitionConfig,
        now: datetime,
    ) -> float:
        base = self._base_engine.challenge_value(challenge, solve_count, competition, now)
        weight = self._weights.get(challenge.challenge_id, self._default_weight)
        return base * weight


# --- Registry --------------------------------------------------------------------

_DEFAULT_ENGINE_NAME = "time_decay"
_REGISTRY: dict[str, ScoringEngine] = {}


def register_scoring_engine(engine: ScoringEngine) -> None:
    """Register (or replace) an engine in the process-wide registry, keyed by
    ``engine.name``."""
    _REGISTRY[engine.name] = engine


def get_scoring_engine(name: str = _DEFAULT_ENGINE_NAME) -> ScoringEngine:
    """Look up a registered engine by name.

    Defaults to ``"time_decay"``, the competition-wide default engine.
    Raises ``KeyError`` for an unregistered name.
    """
    try:
        return _REGISTRY[name]
    except KeyError:
        raise KeyError(f"unknown scoring engine: {name}") from None


def list_scoring_engines() -> list[str]:
    return sorted(_REGISTRY)


register_scoring_engine(StaticPointsEngine())
register_scoring_engine(DynamicDecayEngine())
register_scoring_engine(TimeDecayEngine())
register_scoring_engine(AIResistanceWeightedEngine())


# --- Competition config validation ----------------------------------------------

_VALID_DECAY_FUNCTIONS = ("static", "linear", "logarithmic")


def validate_competition_config(config: CompetitionConfig) -> list[str]:
    """Sanity-check a ``CompetitionConfig`` (and its ``default_scoring``, if
    set). Returns a list of human-readable problem descriptions; an empty
    list means the config is valid."""
    errors: list[str] = []

    if config.end_time <= config.start_time:
        errors.append("end_time must be after start_time")

    if config.scoring_start_time is not None:
        if config.scoring_start_time < config.start_time:
            errors.append("scoring_start_time must not be before start_time")
        if config.scoring_start_time > config.end_time:
            errors.append("scoring_start_time must not be after end_time")

    if config.freeze_time is not None:
        if config.freeze_time < config.start_time:
            errors.append("freeze_time must not be before start_time")
        if config.freeze_time > config.end_time:
            errors.append("freeze_time must not be after end_time")

    if config.default_scoring is not None:
        errors.extend(_validate_challenge_scoring(config.default_scoring))

    return errors


def _validate_challenge_scoring(challenge: ChallengeScoringConfig) -> list[str]:
    errors: list[str] = []
    prefix = f"default_scoring ({challenge.challenge_id})"

    if challenge.minimum_value > challenge.initial_value:
        errors.append(f"{prefix}: minimum_value must not exceed initial_value")
    if challenge.initial_value < 0:
        errors.append(f"{prefix}: initial_value must not be negative")
    if challenge.minimum_value < 0:
        errors.append(f"{prefix}: minimum_value must not be negative")
    if challenge.decay_function not in _VALID_DECAY_FUNCTIONS:
        errors.append(
            f"{prefix}: decay_function must be one of {_VALID_DECAY_FUNCTIONS}, "
            f"got {challenge.decay_function!r}"
        )
    if challenge.decay < 0:
        errors.append(f"{prefix}: decay must not be negative")

    bonus = challenge.first_blood_bonus
    if bonus.bonus_points < 0:
        errors.append(f"{prefix}: first_blood_bonus.bonus_points must not be negative")
    if not (0.0 <= bonus.bonus_percent <= 100.0):
        errors.append(f"{prefix}: first_blood_bonus.bonus_percent must be within [0, 100]")

    return errors


# --- Event bridge --------------------------------------------------------------


def solve_event_from_event(event: Event) -> SolveEvent | None:
    """Build a ``SolveEvent`` from an ``events.Event``, or ``None`` if the
    event is not a ``"solve"``.

    Maps ``event.ts`` (an ISO-8601 string) to ``SolveEvent.solved_at`` via
    ``datetime.fromisoformat``, and reads ``submission_id`` / ``instance_seed``
    out of ``event.payload`` (missing ``submission_id`` becomes ``""``;
    missing ``instance_seed`` becomes ``None``, matching its default on
    ``SolveEvent``).
    """
    if event.type != "solve":
        return None
    return SolveEvent(
        team_id=event.team_id,
        challenge_id=event.challenge_id,
        solved_at=datetime.fromisoformat(event.ts),
        submission_id=str(event.payload.get("submission_id", "")),
        instance_seed=event.payload.get("instance_seed"),
    )
