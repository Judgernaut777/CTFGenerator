"""Live competition state/service layer over the event log + scoring.

Stdlib-only, pure and offline-testable: every external effect (the wall
clock, event persistence) is already pushed behind ``events.Clock`` /
``events.EventStore`` by ``events.py``, so this module never touches either
directly -- it is handed an already-constructed store and a ``now``/``as_of``
whenever it needs "the current moment".

Layering
--------
``events.py`` is the append-only source of truth (raw ``Event`` records).
``scoring_engine.py`` / ``scoreboard.py`` turn *solve* events into points.
This module sits between them for a *live* competition:

* :class:`ChallengeCatalog` -- static challenge display metadata + the
  ``ChallengeScoringConfig`` each challenge scores under (the ``challenges``
  mapping ``scoreboard.compute_scoreboard`` expects).
* :func:`project_progress` -- a pure fold of the event log into per-team
  progress (solved challenges, attempt counts), independent of scoring.
* :class:`CompetitionService` -- the façade a dashboard/CLI/MCP tool talks
  to: record events, poll the live feed, read progress, and read the
  (possibly redacted) leaderboard.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Mapping, Sequence

from . import events
from .models import ChallengeScoringConfig, CompetitionConfig, ScoreboardSnapshot
from .scoreboard import compute_scoreboard
from .scoring_engine import ScoringEngine, get_scoring_engine, solve_event_from_event

# --- Challenge catalog ---------------------------------------------------------


@dataclass(frozen=True)
class ChallengeMeta:
    """Display metadata + scoring config for a single challenge."""

    scoring: ChallengeScoringConfig
    title: str = ""
    category: str = ""
    # "red" (static/generated challenge) vs. e.g. "scenario" (live, timed
    # storyline challenge) -- mirrors ``ChallengeSpec.mode`` in models.py,
    # duplicated here since a scoring config alone carries no display info.
    mode: str = "red"


@dataclass
class ChallengeCatalog:
    """A small ``challenge_id -> ChallengeMeta`` wrapper.

    Exists so ``CompetitionService`` has one place to resolve both a
    challenge's ``ChallengeScoringConfig`` (for scoring) and its display
    metadata (title/category/mode), without either concern leaking into the
    event log or the scoring engines.
    """

    _entries: dict[str, ChallengeMeta] = field(default_factory=dict)

    def get(self, challenge_id: str) -> ChallengeMeta | None:
        return self._entries.get(challenge_id)

    def all(self) -> dict[str, ChallengeMeta]:
        return dict(self._entries)

    def ids(self) -> list[str]:
        return sorted(self._entries)

    def scoring_configs(self) -> dict[str, ChallengeScoringConfig]:
        """The ``challenge_id -> ChallengeScoringConfig`` view that
        ``scoreboard.compute_scoreboard`` expects as its ``challenges``
        argument."""
        return {challenge_id: meta.scoring for challenge_id, meta in self._entries.items()}

    @classmethod
    def from_entries(cls, entries: Mapping[str, ChallengeMeta]) -> "ChallengeCatalog":
        return cls(dict(entries))


# --- Team progress ---------------------------------------------------------------


@dataclass
class TeamProgress:
    """A single team's standing in the raw event log (pre-scoring)."""

    team_id: str
    display_name: str
    solved: list[str] = field(default_factory=list)
    attempts: int = 0
    last_event_seq: int = 0


def project_progress(events_seq: Sequence[events.Event]) -> dict[str, TeamProgress]:
    """Fold an event log into per-team progress.

    Pure function of ``events_seq``; processes events in ``seq`` order
    regardless of input order, so re-folding the same log (or a superset of
    it that includes the same events) is deterministic.

    Semantics:

    * A team's ``TeamProgress`` is created lazily on its first event, with
      ``display_name`` defaulting to ``team_id`` (this module has no notion
      of a team roster -- ``CompetitionService`` overlays real display names
      from its own ``teams`` mapping).
    * ``"attempt"`` and ``"solve"`` events each count as one submission
      attempt.
    * ``"solve"`` events additionally append ``challenge_id`` to ``solved``
      (first-seen order, deduplicated -- a repeated solve of an
      already-solved challenge does not add a duplicate entry).
    * Every event (including e.g. ``"hint"``) advances ``last_event_seq``.
    """
    progress: dict[str, TeamProgress] = {}
    for event in sorted(events_seq, key=lambda e: e.seq):
        team = progress.get(event.team_id)
        if team is None:
            team = TeamProgress(team_id=event.team_id, display_name=event.team_id)
            progress[event.team_id] = team

        if event.seq > team.last_event_seq:
            team.last_event_seq = event.seq

        if event.type in ("attempt", "solve"):
            team.attempts += 1

        if event.type == "solve" and event.challenge_id not in team.solved:
            team.solved.append(event.challenge_id)

    return progress


# --- Competition service -----------------------------------------------------------


@dataclass
class CompetitionService:
    """Live competition state/service layer over an ``events.EventStore``.

    Pure/deterministic given its inputs: no wall-clock reads, no randomness
    -- ``leaderboard``/``public_leaderboard`` take an explicit ``as_of`` and
    delegate to ``scoreboard.compute_scoreboard`` (which itself never reads
    the clock).
    """

    store: events.EventStore
    catalog: ChallengeCatalog
    config: CompetitionConfig
    scoring_engine: ScoringEngine | None = None
    # team_id -> display_name, e.g. for anonymizing/friendlifying the public
    # leaderboard. Teams with no entry here fall back to their team_id.
    teams: dict[str, str] = field(default_factory=dict)

    def _engine(self) -> ScoringEngine:
        return self.scoring_engine or get_scoring_engine("time_decay")

    def _display_name(self, team_id: str) -> str:
        return self.teams.get(team_id, team_id)

    def record_event(
        self,
        type: str,
        team_id: str,
        challenge_id: str,
        payload: dict | None = None,
    ) -> events.Event:
        """Append a competition event (``"solve"``, ``"attempt"``,
        ``"hint"``, or any other caller-defined ``type``) to the log."""
        return self.store.append(type, team_id, challenge_id, payload=payload)

    def feed_since(self, seq: int) -> list[events.Event]:
        """The raw live feed: every event with ``seq > seq``."""
        return self.store.since(seq)

    def progress(self) -> dict[str, TeamProgress]:
        """Per-team progress folded from the full event log, with display
        names overlaid from ``self.teams`` where known."""
        progress = project_progress(self.store.all())
        for team_id, team in progress.items():
            if team_id in self.teams:
                team.display_name = self.teams[team_id]
        return progress

    def leaderboard(self, as_of: datetime | None = None) -> ScoreboardSnapshot:
        """The full (internal) scoreboard snapshot as of ``as_of`` (or the
        competition's ``end_time`` when ``None``), via
        ``scoreboard.compute_scoreboard``."""
        solve_events = [
            solve_event
            for solve_event in (solve_event_from_event(event) for event in self.store.all())
            if solve_event is not None
        ]
        return compute_scoreboard(
            solve_events,
            self.catalog.scoring_configs(),
            self.config,
            self._engine(),
            as_of,
        )

    def public_leaderboard(self, as_of: datetime | None = None) -> list[dict]:
        """The public-facing leaderboard: a structurally redacted subset of
        ``leaderboard()`` -- ONLY ``display_name``, ``rank``, ``score``, and
        ``solve_count`` per entry.

        Deliberately excludes team ids, per-challenge detail, progress
        internals (attempts, solved challenge ids), and anything
        flag/payload-shaped -- this is what is safe to expose to
        contestants/spectators without leaking other teams' internals.
        """
        snapshot = self.leaderboard(as_of)
        return [
            {
                "display_name": self._display_name(entry.team_id),
                "rank": entry.rank,
                "score": entry.score,
                "solve_count": entry.solve_count,
            }
            for entry in snapshot.entries
        ]
