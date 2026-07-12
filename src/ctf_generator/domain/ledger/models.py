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


# --- Gap-safe projection (M7) ------------------------------------------------
#
# The transactional outbox row for score event ``seq`` is inserted by a DB
# trigger in the same transaction as the event itself, so it becomes visible at
# exactly the instant the event commits -- regardless of how many higher seqs
# committed first. A committed event can therefore never be skipped by the
# projector (deleting an outbox row happens only in the transaction that folded
# its event into the projection). No seq cursor appears anywhere in the
# correctness path.

VALID_PROJECTION_TASK_STATUSES = frozenset({"pending", "failed"})


@dataclass(frozen=True)
class ProjectionTask:
    """One pending/failed outbox row: score event ``seq`` awaiting projection.
    ``last_error`` is sanitized (exception class + message only -- never
    payloads, never flags)."""

    seq: int
    competition_id: str
    status: str
    attempts: int
    created_at: datetime
    last_error: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.seq, int) or self.seq < 1:
            raise ValueError(f"seq must be an int >= 1, got {self.seq!r}")
        _require_nonempty(self.competition_id, "competition_id")
        if self.status not in VALID_PROJECTION_TASK_STATUSES:
            raise ValueError(
                f"status must be one of {sorted(VALID_PROJECTION_TASK_STATUSES)}, "
                f"got {self.status!r}"
            )
        if not isinstance(self.attempts, int) or self.attempts < 0:
            raise ValueError(f"attempts must be an int >= 0, got {self.attempts!r}")


@dataclass(frozen=True)
class ScoreboardProjectionRecord:
    """The rebuildable, discardable scoreboard cache for one competition,
    stamped with ``as_of_seq`` (the max ``score_events.seq`` folded in). Never
    a source of truth -- deleting it and replaying the ledger reproduces it."""

    competition_id: str
    as_of_seq: int
    entries: Mapping[str, object] = field(default_factory=dict, compare=False)
    computed_at: datetime | None = None

    def __post_init__(self) -> None:
        _require_nonempty(self.competition_id, "competition_id")
        if not isinstance(self.as_of_seq, int) or self.as_of_seq < 0:
            raise ValueError(f"as_of_seq must be an int >= 0, got {self.as_of_seq!r}")
        if not isinstance(self.entries, Mapping):
            raise ValueError("entries must be a mapping")


@dataclass(frozen=True)
class ProjectionLag:
    """Observability snapshot of projection lag. These are *metrics only* --
    never an incremental cursor (a naive committed low-water mark is
    non-monotonic under the allocation-vs-commit-order race)."""

    pending_count: int
    latest_seq: int
    max_as_of_seq: int
    oldest_pending_created_at: datetime | None = None
    failed_count: int = 0

    def __post_init__(self) -> None:
        if not isinstance(self.pending_count, int) or self.pending_count < 0:
            raise ValueError("pending_count must be an int >= 0")
        if not isinstance(self.latest_seq, int) or self.latest_seq < 0:
            raise ValueError("latest_seq must be an int >= 0")
        if not isinstance(self.max_as_of_seq, int) or self.max_as_of_seq < 0:
            raise ValueError("max_as_of_seq must be an int >= 0")
        if not isinstance(self.failed_count, int) or self.failed_count < 0:
            raise ValueError("failed_count must be an int >= 0")
