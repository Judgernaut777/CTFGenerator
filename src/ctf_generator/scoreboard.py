"""Pure scoreboard computation on top of ``scoring_engine.py``.

Stdlib-only. The only I/O in this module lives in the three ``load_*``
functions at the bottom; everything else is a pure fold over already-loaded
data, so ``compute_scoreboard`` (and its helper ``compute_challenge_values``)
are trivially deterministic and testable: same ``events`` / ``challenges`` /
``config`` / ``engine`` / ``as_of`` in, byte-identical ``ScoreboardSnapshot``
out.

Retroactive decay
------------------
A challenge's point value is *not* locked in at solve time. Instead, at
render time (``as_of``, or the competition's ``end_time`` when ``as_of`` is
``None``) each challenge's value is recomputed from its solve_count *as of
that same moment*, and every recorded solve of that challenge -- no matter
when it happened -- is worth that freshly-computed value. This mirrors how
CTFd-style dynamic scoring actually behaves: as more teams solve a challenge,
everyone's already-awarded points for it drift down (or, for the default
time-decay engine, drift down purely with elapsed competition time).

First blood
-----------
``ChallengeScoringConfig.first_blood_bonus`` describes a single bonus (a flat
``bonus_points`` plus a ``bonus_percent`` of the challenge's current value),
not a list of per-rank bonuses, so it is awarded to exactly one solver per
challenge: whichever included solve sorts earliest under the deterministic
``(solved_at, submission_id, team_id)`` tie-break.

Missing per-challenge config
-----------------------------
If a challenge_id appears in ``events`` (or is otherwise looked up) but has
no entry in the ``challenges`` mapping, ``CompetitionConfig.default_scoring``
is used as a fallback (with its ``challenge_id`` swapped in) -- this is
exactly what that field exists for. If neither is available, resolution
raises ``KeyError``.
"""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import replace
from datetime import datetime
from pathlib import Path
from typing import Mapping, Sequence

from .models import (
    ChallengeScoringConfig,
    ChallengeValueSnapshot,
    CompetitionConfig,
    FirstBloodBonusConfig,
    ScoreboardEntry,
    ScoreboardSnapshot,
    SolveEvent,
)
from .scoring_engine import ScoringEngine, get_scoring_engine

# --- Internal helpers --------------------------------------------------------


def _effective_now(config: CompetitionConfig, as_of: datetime | None) -> datetime:
    """The point in time scoring is computed "as of".

    ``as_of`` when given; otherwise the competition's ``end_time``, which
    keeps this module free of any wall-clock read (determinism) while still
    giving a sensible "final" snapshot when the caller doesn't care about a
    specific moment.
    """
    return as_of if as_of is not None else config.end_time


def _filter_solves(events: Sequence[SolveEvent], as_of: datetime | None) -> list[SolveEvent]:
    if as_of is None:
        return list(events)
    return [event for event in events if event.solved_at <= as_of]


def _resolve_challenge_config(
    challenge_id: str,
    challenges: Mapping[str, ChallengeScoringConfig],
    config: CompetitionConfig,
) -> ChallengeScoringConfig:
    cfg = challenges.get(challenge_id)
    if cfg is not None:
        return cfg
    if config.default_scoring is not None:
        return replace(config.default_scoring, challenge_id=challenge_id)
    raise KeyError(
        f"no ChallengeScoringConfig for challenge_id={challenge_id!r} and "
        "CompetitionConfig.default_scoring is unset"
    )


def _solve_sort_key(solve: SolveEvent) -> tuple[datetime, str, str]:
    """Deterministic ordering for solves of the same challenge: earliest
    ``solved_at`` first, then ``submission_id``, then ``team_id`` to break
    any remaining tie (e.g. simultaneous timestamps in a fake clock)."""
    return (solve.solved_at, solve.submission_id, solve.team_id)


# --- Public pure computation --------------------------------------------------


def compute_challenge_values(
    events: Sequence[SolveEvent],
    challenges: Mapping[str, ChallengeScoringConfig],
    config: CompetitionConfig,
    engine: ScoringEngine | None = None,
    as_of: datetime | None = None,
) -> list[ChallengeValueSnapshot]:
    """Compute each challenge's current point value as of ``as_of``.

    Covers every challenge_id that appears in ``challenges`` and/or has at
    least one solve in the (``as_of``-filtered) ``events``, sorted by
    challenge_id for determinism. ``solve_count`` fed to the engine is the
    number of included solves for that challenge as of the same moment used
    for ``now`` -- see module docstring re: retroactive decay.
    """
    engine = engine or get_scoring_engine("time_decay")
    now = _effective_now(config, as_of)
    solves = _filter_solves(events, as_of)

    solve_counts: dict[str, int] = defaultdict(int)
    for solve in solves:
        solve_counts[solve.challenge_id] += 1

    challenge_ids = set(challenges) | set(solve_counts)
    snapshots: list[ChallengeValueSnapshot] = []
    for challenge_id in sorted(challenge_ids):
        cfg = _resolve_challenge_config(challenge_id, challenges, config)
        count = solve_counts.get(challenge_id, 0)
        value = engine.challenge_value(cfg, count, config, now)
        snapshots.append(
            ChallengeValueSnapshot(
                challenge_id=challenge_id,
                value=round(value),
                solve_count=count,
                computed_at=now,
            )
        )
    return snapshots


def compute_scoreboard(
    events: Sequence[SolveEvent],
    challenges: Mapping[str, ChallengeScoringConfig],
    config: CompetitionConfig,
    engine: ScoringEngine | None = None,
    as_of: datetime | None = None,
) -> ScoreboardSnapshot:
    """Fold solve events into a deterministic scoreboard snapshot.

    * ``engine`` defaults to ``get_scoring_engine("time_decay")``.
    * Solves with ``solved_at > as_of`` are excluded when ``as_of`` is given;
      all events are included when it is ``None``.
    * Each challenge's value is computed once (via
      :func:`compute_challenge_values`) and applied to every included solve
      of that challenge -- retroactive decay, not value-at-solve-time.
    * The single earliest solver of each challenge (per the deterministic
      tie-break in :func:`_solve_sort_key`) receives that challenge's
      ``first_blood_bonus``, if enabled.
    * Entries are ordered by score (descending), then earliest last-solve
      time (ascending), then ``team_id`` (ascending) -- a total order, so
      ranking is stable across repeated calls with identical inputs.
    * ``frozen`` is ``True`` iff ``as_of`` was given (a snapshot pinned to a
      specific moment rather than "as of the end of the competition").
    """
    engine = engine or get_scoring_engine("time_decay")
    now = _effective_now(config, as_of)
    solves = _filter_solves(events, as_of)

    values_by_challenge = {
        snapshot.challenge_id: snapshot
        for snapshot in compute_challenge_values(events, challenges, config, engine, as_of)
    }

    solves_by_challenge: dict[str, list[SolveEvent]] = defaultdict(list)
    for solve in solves:
        solves_by_challenge[solve.challenge_id].append(solve)

    team_score: dict[str, int] = defaultdict(int)
    team_solved: dict[str, set[str]] = defaultdict(set)
    team_last_solve: dict[str, datetime] = {}

    for challenge_id, challenge_solves in solves_by_challenge.items():
        cfg = _resolve_challenge_config(challenge_id, challenges, config)
        snapshot = values_by_challenge[challenge_id]
        ordered = sorted(challenge_solves, key=_solve_sort_key)
        for index, solve in enumerate(ordered):
            points = snapshot.value
            if index == 0 and cfg.first_blood_bonus.enabled:
                points += _first_blood_bonus_amount(cfg.first_blood_bonus, snapshot.value)
            team_score[solve.team_id] += points
            team_solved[solve.team_id].add(challenge_id)
            prev = team_last_solve.get(solve.team_id)
            if prev is None or solve.solved_at > prev:
                team_last_solve[solve.team_id] = solve.solved_at

    entries = [
        ScoreboardEntry(
            team_id=team_id,
            score=team_score[team_id],
            solve_count=len(team_solved[team_id]),
            last_solve_at=team_last_solve.get(team_id),
        )
        for team_id in team_score
    ]
    entries.sort(key=_entry_rank_key)
    ranked_entries = [replace(entry, rank=index + 1) for index, entry in enumerate(entries)]

    return ScoreboardSnapshot(
        competition_id=config.competition_id,
        generated_at=now,
        entries=ranked_entries,
        frozen=as_of is not None,
    )


def _first_blood_bonus_amount(bonus: FirstBloodBonusConfig, challenge_value: int) -> int:
    return round(bonus.bonus_points + challenge_value * bonus.bonus_percent / 100.0)


def _entry_rank_key(entry: ScoreboardEntry) -> tuple[int, bool, datetime | None, str]:
    # ``has_last`` lets entries with no last-solve timestamp sort after ones
    # that do without ever comparing a ``None`` against a ``datetime`` --
    # ``last_solve_at`` is only compared when both entries share the same
    # ``has_last`` value, so it is either "both None" (skipped) or "both
    # real datetimes" (comparable) by the time Python looks at it.
    has_last = entry.last_solve_at is None
    return (-entry.score, has_last, entry.last_solve_at, entry.team_id)


# --- I/O: JSON loaders (the only I/O in this module) --------------------------


def _parse_first_blood_bonus(data: Mapping[str, object] | None) -> FirstBloodBonusConfig:
    data = data or {}
    return FirstBloodBonusConfig(
        enabled=bool(data.get("enabled", True)),
        bonus_points=int(data.get("bonus_points", 0)),  # type: ignore[arg-type]
        bonus_percent=float(data.get("bonus_percent", 0.0)),  # type: ignore[arg-type]
    )


def _parse_challenge_scoring(
    fallback_challenge_id: str, data: Mapping[str, object]
) -> ChallengeScoringConfig:
    bonus_data = data.get("first_blood_bonus")
    return ChallengeScoringConfig(
        challenge_id=str(data.get("challenge_id", fallback_challenge_id)),
        initial_value=int(data.get("initial_value", 500)),  # type: ignore[arg-type]
        minimum_value=int(data.get("minimum_value", 100)),  # type: ignore[arg-type]
        decay_function=str(data.get("decay_function", "static")),
        decay=int(data.get("decay", 0)),  # type: ignore[arg-type]
        first_blood_bonus=_parse_first_blood_bonus(
            bonus_data if isinstance(bonus_data, dict) else None
        ),
    )


def _parse_solve_event(data: Mapping[str, object]) -> SolveEvent:
    return SolveEvent(
        team_id=str(data.get("team_id", "")),
        challenge_id=str(data.get("challenge_id", "")),
        solved_at=datetime.fromisoformat(str(data["solved_at"])),
        submission_id=str(data.get("submission_id", "")),
        instance_seed=(
            str(data["instance_seed"]) if data.get("instance_seed") is not None else None
        ),
    )


def load_events(path: Path | str) -> list[SolveEvent]:
    """Load a JSON array of ``SolveEvent.to_mapping()``-shaped objects."""
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    return [_parse_solve_event(item) for item in raw]


def load_challenges(path: Path | str) -> dict[str, ChallengeScoringConfig]:
    """Load a JSON array of ``ChallengeScoringConfig.to_mapping()``-shaped
    objects into a ``challenge_id -> ChallengeScoringConfig`` dict."""
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    result: dict[str, ChallengeScoringConfig] = {}
    for item in raw:
        cfg = _parse_challenge_scoring("", item)
        result[cfg.challenge_id] = cfg
    return result


def load_competition_config(path: Path | str) -> CompetitionConfig:
    """Load a single JSON object shaped like ``CompetitionConfig.to_mapping()``."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    default_scoring_data = data.get("default_scoring")
    return CompetitionConfig(
        competition_id=str(data.get("competition_id", "")),
        name=str(data.get("name", "")),
        start_time=datetime.fromisoformat(str(data["start_time"])),
        end_time=datetime.fromisoformat(str(data["end_time"])),
        scoring_start_time=(
            datetime.fromisoformat(str(data["scoring_start_time"]))
            if data.get("scoring_start_time") is not None
            else None
        ),
        freeze_time=(
            datetime.fromisoformat(str(data["freeze_time"]))
            if data.get("freeze_time") is not None
            else None
        ),
        default_scoring=(
            _parse_challenge_scoring(
                str(default_scoring_data.get("challenge_id", "")), default_scoring_data
            )
            if isinstance(default_scoring_data, dict)
            else None
        ),
    )
