"""Ledger value types: ``LedgerSubmission``, ``Solve``, ``ScoreEvent``.

Pure, frozen domain aggregates. Each references the competition, team and
challenge version by *business* identity (competition slug, team name,
``(definition_slug, version_no)``) -- never a surrogate uuid. All three are
append-only: history is never rewritten; a correction is a new compensating
row/event (the store enforces this with immutability triggers).

Identity:

* ``LedgerSubmission`` -- keyed by ``submission_id`` (a caller-supplied uuid
  string that becomes the row PK).
* ``Solve`` -- keyed by ``solve_id`` (uuid string PK); at most one per
  ``(competition_id, team_name, definition_slug, version_no)`` (the core product
  rule, enforced by a UNIQUE constraint).
* ``ScoreEvent`` -- the store assigns a strictly monotonic ``seq`` on append;
  in-memory (pre-append) instances carry ``seq is None``.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime

# Event types carried in the score ledger (mirrors events.py usage). Stored as
# text + CHECK so new types can be added by migration.
VALID_SCORE_EVENT_TYPES = frozenset(
    {"submission", "solve", "first_blood", "freeze", "revalue"}
)


def _require_nonempty(value: str, field_name: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be a non-empty string")


def _require_positive_version(version_no: int) -> None:
    if not isinstance(version_no, int) or version_no < 1:
        raise ValueError(f"version_no must be an int >= 1, got {version_no!r}")


@dataclass(frozen=True)
class LedgerSubmission:
    """A single team's answer attempt for a challenge version (append-only).

    ``correct`` is decided at insert and never edited. ``submitter_email`` is the
    submitting member if tracked (optional). Keyed by ``submission_id``.
    """

    submission_id: str
    competition_id: str
    team_name: str
    definition_slug: str
    version_no: int
    submitted_at: datetime
    correct: bool
    submitter_email: str | None = None
    instance_seed: str | None = None

    def __post_init__(self) -> None:
        _require_nonempty(self.submission_id, "submission_id")
        _require_nonempty(self.competition_id, "competition_id")
        _require_nonempty(self.team_name, "team_name")
        _require_nonempty(self.definition_slug, "definition_slug")
        _require_positive_version(self.version_no)
        if not isinstance(self.correct, bool):
            raise ValueError("correct must be a bool")


@dataclass(frozen=True)
class Solve:
    """The at-most-once accepted result for a (competition, team, challenge).

    Derived from a *correct* submission (``submission_id``). At most one Solve
    exists per ``(competition_id, team_name, definition_slug, version_no)``.
    """

    solve_id: str
    competition_id: str
    team_name: str
    definition_slug: str
    version_no: int
    submission_id: str
    solved_at: datetime
    instance_seed: str | None = None

    def __post_init__(self) -> None:
        _require_nonempty(self.solve_id, "solve_id")
        _require_nonempty(self.competition_id, "competition_id")
        _require_nonempty(self.team_name, "team_name")
        _require_nonempty(self.definition_slug, "definition_slug")
        _require_positive_version(self.version_no)
        _require_nonempty(self.submission_id, "submission_id")


@dataclass(frozen=True)
class ScoreEvent:
    """An append-only entry in the durable score ledger.

    The store assigns ``seq`` (strictly monotonic from 1); pre-append instances
    carry ``seq is None``. ``ts`` is an ISO-8601 UTC string (byte-compatible with
    ``events.Event.ts``). ``payload`` is an opaque jsonb document, excluded from
    equality/hash (it round-trips at the dict level, not byte-for-byte).
    ``submission_id`` / ``solve_id`` are optional provenance links.
    """

    competition_id: str
    team_name: str
    definition_slug: str
    version_no: int
    type: str
    ts: str
    payload: Mapping[str, object] = field(default_factory=dict, compare=False)
    submission_id: str | None = None
    solve_id: str | None = None
    seq: int | None = None

    def __post_init__(self) -> None:
        _require_nonempty(self.competition_id, "competition_id")
        _require_nonempty(self.team_name, "team_name")
        _require_nonempty(self.definition_slug, "definition_slug")
        _require_positive_version(self.version_no)
        if self.type not in VALID_SCORE_EVENT_TYPES:
            raise ValueError(
                f"type must be one of {sorted(VALID_SCORE_EVENT_TYPES)}, "
                f"got {self.type!r}"
            )
        _require_nonempty(self.ts, "ts")
        if not isinstance(self.payload, Mapping):
            raise ValueError("payload must be a mapping")
        if self.seq is not None and (not isinstance(self.seq, int) or self.seq < 1):
            raise ValueError(f"seq must be a positive int or None, got {self.seq!r}")
        # Optional provenance links: absent (None) or a non-empty id -- never "".
        if self.submission_id is not None:
            _require_nonempty(self.submission_id, "submission_id")
        if self.solve_id is not None:
            _require_nonempty(self.solve_id, "solve_id")
