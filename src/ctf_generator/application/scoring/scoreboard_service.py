"""Read-only scoreboard query service (unit-of-work-owning).

The scoreboard is a PROJECTION maintained by
:class:`~ctf_generator.application.scoring.projector.ScoreProjector` (which folds
the append-only score ledger into the ``scoreboard_projections`` cache). This
service exposes that cache read-only: a GET NEVER triggers a projection run --
standings are served from whatever the projector has already folded, so a read is
cheap and side-effect-free.

* :meth:`standings` reads the cached per-competition projection and returns the
  public team entries (team, score, solve count, last-solve time, rank). Nothing
  secret is present -- the projection stores only public standings.
* :meth:`lag` reports projection lag for operators (pending/failed outbox counts
  and the folded-vs-latest sequence gap) via
  :meth:`ScoreProjector.lag`. Lag is a property of the shared projection outbox,
  so it is global, not per-competition.
"""

from __future__ import annotations

from ctf_generator.domain.ledger.models import ProjectionLag
from ctf_generator.infrastructure.database.score_projection_repository import (
    SqlAlchemyScoreboardProjectionRepository,
)
from ctf_generator.infrastructure.database.session import Database

from .projector import ScoreProjector


class ScoreboardService:
    """Serve current standings + projection lag, read-only."""

    def __init__(self, database: Database) -> None:
        self._database = database

    def standings(self, competition_id: str) -> list[dict[str, object]]:
        """The current cached standings for a competition, one entry per team.

        Returns an empty list when no projection has been computed yet (an
        unstarted or unknown competition) -- a read never folds the ledger. Each
        entry is a plain public mapping (``team_id``, ``score``, ``solve_count``,
        ``last_solve_at``, ``rank``); no ORM row or private data escapes.
        """
        with self._database.session_scope() as session:
            record = SqlAlchemyScoreboardProjectionRepository(session).get(
                competition_id
            )
        if record is None:
            return []
        raw_entries = record.entries.get("entries", [])
        if not isinstance(raw_entries, list):  # pragma: no cover - defensive
            return []
        return [dict(entry) for entry in raw_entries]

    def lag(self) -> ProjectionLag:
        """Projection lag metrics (operators only). Never a cursor -- a metrics
        snapshot of the shared projection outbox."""
        return ScoreProjector(self._database).lag()
