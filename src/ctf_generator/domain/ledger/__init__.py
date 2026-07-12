"""Ledger domain: the append-only competition ledger aggregates.

* ``LedgerSubmission`` -- every answer attempt (correct or not), append-only.
* ``Solve`` -- the at-most-once accepted result per (competition, team,
  challenge version); derived from a correct submission.
* ``ScoreEvent`` -- the durable, event-sourced ledger entry (the relational form
  of the in-memory ``events.Event``); scoreboards are folds over these.
* ``ProjectionTask`` / ``ScoreboardProjectionRecord`` / ``ProjectionLag`` --
  the gap-safe projection outbox/cache value types (M7): the outbox row commits
  atomically with its event, so the projector can never skip a committed event.
* ``processing`` module -- submission-processing request/outcome types and
  domain errors.

These bridge the flat scoring domain (``Submission``/``SolveEvent`` in
``challenges.models``, which use opaque ``team_id``/``challenge_id`` strings) to
the normalized persistence schema by carrying full *business* identity:
competition slug, team name, and challenge ``(definition_slug, version_no)``.
Surrogate uuid keys, ``jsonb`` payloads and the monotonic ``seq`` live only in
``ctf_generator.infrastructure``. See ``models`` for invariants.
"""

from .models import (
    VALID_PROJECTION_TASK_STATUSES,
    VALID_SCORE_EVENT_TYPES,
    LedgerSubmission,
    ProjectionLag,
    ProjectionTask,
    ScoreboardProjectionRecord,
    ScoreEvent,
    Solve,
)

__all__ = [
    "VALID_PROJECTION_TASK_STATUSES",
    "VALID_SCORE_EVENT_TYPES",
    "LedgerSubmission",
    "ProjectionLag",
    "ProjectionTask",
    "ScoreboardProjectionRecord",
    "ScoreEvent",
    "Solve",
]
