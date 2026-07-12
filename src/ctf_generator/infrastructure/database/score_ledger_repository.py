"""Concrete SQLAlchemy repository for the ScoreEvent ledger (ScoreLedger).

Append-only over ``score_events``. ``append`` resolves the competition/team/
version by business identity, inserts the event (the DB assigns the monotonic
``seq``), and returns the persisted domain event carrying that ``seq``.
``since``/``latest_seq`` mirror the pure EventStore cursor contract over the
DB sequence. Reads rebuild business identity via joins; ORM rows never escape.
Flush only; no update/delete (the ``score_events_immutable`` trigger backstops).
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ctf_generator.domain.ledger.models import ScoreEvent

from . import _resolve
from .mappers import score_event_from_orm, score_event_to_orm
from .models import (
    ChallengeDefinition as ChallengeDefinitionRow,
)
from .models import (
    ChallengeVersion as ChallengeVersionRow,
)
from .models import (
    Competition,
    Team,
)
from .models import (
    ScoreEvent as ScoreEventRow,
)


def _hydrate_query():
    return (
        select(
            ScoreEventRow,
            Competition.slug,
            Team.name,
            ChallengeDefinitionRow.slug,
            ChallengeVersionRow.version_no,
        )
        .join(Competition, ScoreEventRow.competition_id == Competition.id)
        .join(Team, ScoreEventRow.team_id == Team.id)
        .join(
            ChallengeVersionRow,
            ScoreEventRow.challenge_version_id == ChallengeVersionRow.id,
        )
        .join(
            ChallengeDefinitionRow,
            ChallengeVersionRow.definition_id == ChallengeDefinitionRow.id,
        )
    )


class SqlAlchemyScoreLedger:
    """Append-only score ledger with a DB-assigned monotonic ``seq``."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def append(self, event: ScoreEvent) -> ScoreEvent:
        """Append an event, assigning ``seq``. Returns the persisted event
        carrying its ``seq``. Raises :class:`LookupError` if a parent is missing,
        and :class:`ValueError` (failing the appending transaction) if ``ts`` is
        not an ISO-8601 timestamp carrying a timezone offset -- a naive instant
        is ambiguous and the projector's fold contract requires tz-aware
        timestamps."""
        try:
            parsed_ts = datetime.fromisoformat(event.ts)
        except (ValueError, TypeError) as exc:
            raise ValueError(
                "ScoreEvent.ts must be an ISO-8601 timestamp"
            ) from exc
        if parsed_ts.tzinfo is None:
            raise ValueError(
                "ScoreEvent.ts must carry a timezone offset (got a naive "
                "instant); the fold requires an unambiguous UTC instant"
            )
        competition_uuid = _resolve.competition_uuid(self._session, event.competition_id)
        team_uuid = _resolve.team_uuid(self._session, competition_uuid, event.team_name)
        version_uuid = _resolve.version_uuid(
            self._session, event.definition_slug, event.version_no
        )
        row = score_event_to_orm(event, competition_uuid, team_uuid, version_uuid)
        self._session.add(row)
        self._session.flush()  # assigns seq
        return score_event_from_orm(
            row,
            event.competition_id,
            event.team_name,
            event.definition_slug,
            event.version_no,
        )

    @staticmethod
    def _map(row) -> ScoreEvent:
        ev_row, comp_slug, team_name, def_slug, version_no = row
        return score_event_from_orm(ev_row, comp_slug, team_name, def_slug, version_no)

    def since(self, seq: int) -> list[ScoreEvent]:
        rows = self._session.execute(
            _hydrate_query().where(ScoreEventRow.seq > seq).order_by(ScoreEventRow.seq)
        ).all()
        return [self._map(row) for row in rows]

    def latest_seq(self) -> int:
        return int(
            self._session.execute(
                select(func.coalesce(func.max(ScoreEventRow.seq), 0))
            ).scalar_one()
        )

    def list_for_competition(self, competition_id: str) -> list[ScoreEvent]:
        rows = self._session.execute(
            _hydrate_query()
            .where(Competition.slug == competition_id)
            .order_by(ScoreEventRow.seq)
        ).all()
        return [self._map(row) for row in rows]
