"""The idempotent, gap-safe scoreboard projector (M7).

Drains the trigger-populated transactional outbox
(``score_projection_outbox``) by *refolding the full committed per-competition
event set* through the existing pure ``compute_scoreboard`` and UPSERTing the
``scoreboard_projections`` cache with a monotonic ``as_of_seq`` guard.

Why this can never skip a committed event: the outbox row for seq N is
written by a DB trigger in the same transaction as event N, so it becomes
visible at exactly the instant event N commits -- regardless of how many
higher seqs committed first -- and its presence forces a later refold that
includes it. Rows are deleted only in the same transaction that folded them.
No seq cursor appears anywhere in the correctness path; aborted appends burn
a seq but roll back their outbox row too, so permanent identity gaps are
inert. Duplicate delivery is safe because apply is a deterministic refold +
monotone-guarded UPSERT; restart-safe because all state is in the DB (SKIP
LOCKED claims die with a crashed session).

Each competition is processed in its OWN unit of work, so a poison event
diverts only its competition to ``failed`` (sanitized error: exception class
+ message only) and every other competition still projects.

Control plane only -- pure PostgreSQL, no Docker, no challenge code, nothing
secret in ``entries`` (public team names/points/solve times) or errors.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy.exc import DBAPIError, OperationalError

from ctf_generator.domain.challenges.models import (
    ChallengeScoringConfig,
    FirstBloodBonusConfig,
    SolveEvent,
)
from ctf_generator.domain.ledger.models import (
    ProjectionLag,
    ScoreboardProjectionRecord,
    ScoreEvent,
)
from ctf_generator.domain.scoring.scoring_engine import get_scoring_engine
from ctf_generator.infrastructure.database.challenge_publication_repository import (
    SqlAlchemyChallengePublicationRepository,
)
from ctf_generator.infrastructure.database.competition_repository import (
    SqlAlchemyCompetitionRepository,
)
from ctf_generator.infrastructure.database.locks import acquire_competition_lock
from ctf_generator.infrastructure.database.score_ledger_repository import (
    SqlAlchemyScoreLedger,
)
from ctf_generator.infrastructure.database.score_projection_repository import (
    SqlAlchemyScoreboardProjectionRepository,
    SqlAlchemyScoreProjectionQueue,
)
from ctf_generator.infrastructure.database.session import Database
from ctf_generator.scoreboard import compute_scoreboard

# The transient-retry budget: a non-deterministic failure keeps its outbox rows
# ``pending`` (re-claimable) and only diverts to ``failed`` once a row has been
# attempted this many times, so a wedged competition eventually surfaces.
_MAX_TRANSIENT_ATTEMPTS = 5


class ProjectionUnsupportedEventError(RuntimeError):
    """A scoring-affecting event type the fold cannot represent yet reached
    the projector. Fails loud (mapper doctrine): silently dropping a
    ``revalue``/``freeze``/``first_blood`` event would corrupt the projection
    without any error."""


class ProjectionMalformedEventError(RuntimeError):
    """A ledger event carried data the fold cannot parse (e.g. an unparseable
    ``ts``). Deterministic poison: isolate the competition to ``failed`` rather
    than retrying forever."""


# Deterministic ("poison") failures: refolding the same committed event set
# will fail identically, so isolate the competition to ``failed`` immediately.
# Everything else (DB connectivity, deadlock, timeout, ...) is treated as
# transient and left re-claimable.
_DETERMINISTIC_POISON = (
    ProjectionUnsupportedEventError,
    ProjectionMalformedEventError,
    LookupError,
)


# Event types that are pure provenance (recorded but score-neutral to the
# fold: solves alone drive the scoreboard, and first-blood bonuses are derived
# from solve ORDER + publication config, not from events).
_NON_SCORING_EVENT_TYPES = frozenset({"submission"})


def _challenge_key(definition_slug: str, version_no: int) -> str:
    return f"{definition_slug}:v{version_no}"


def _solve_event(event: ScoreEvent) -> SolveEvent:
    try:
        solved_at = datetime.fromisoformat(event.ts)
    except (ValueError, TypeError) as exc:
        raise ProjectionMalformedEventError(
            f"score event seq={event.seq} has an unparseable ts"
        ) from exc
    # Degrade gracefully on a legacy/naive stored ts: treat it as UTC so one
    # bad row cannot brick the whole competition's fold. The write path
    # (SqlAlchemyScoreLedger.append) rejects naive ts going forward.
    if solved_at.tzinfo is None:
        solved_at = solved_at.replace(tzinfo=UTC)
    return SolveEvent(
        team_id=event.team_name,
        challenge_id=_challenge_key(event.definition_slug, event.version_no),
        solved_at=solved_at,
        submission_id=event.submission_id
        or event.solve_id
        or f"seq:{event.seq}",
    )


class ScoreProjector:
    """Claims outbox rows, refolds per competition, upserts the cache."""

    def __init__(self, database: Database, engine_name: str = "dynamic_decay") -> None:
        self._database = database
        self._engine_name = engine_name

    # -- the drain loop --------------------------------------------------------

    def run_once(self, batch_size: int = 100) -> int:
        """One pass: for each competition with pending work, claim its rows,
        refold, upsert, and complete -- one transaction per competition (a
        failure diverts that competition's claimed rows to ``failed`` in a
        separate small transaction and moves on). Returns the number of
        outbox rows completed."""
        with self._database.session_scope() as session:
            competitions = SqlAlchemyScoreProjectionQueue(session).pending_competitions()
        processed = 0
        for slug in competitions:
            processed += self._project_competition(slug, batch_size)
        return processed

    def run_until_drained(self, batch_size: int = 100) -> int:
        """Drain to empty. Returns total rows completed. Failed rows do not
        count as pending, so a poison event cannot spin this loop."""
        total = 0
        while True:
            processed = self.run_once(batch_size)
            total += processed
            if processed == 0:
                return total

    def _project_competition(self, slug: str, batch_size: int) -> int:
        claimed_seqs: list[int] = []
        try:
            with self._database.session_scope() as session:
                queue = SqlAlchemyScoreProjectionQueue(session)
                tasks = queue.claim_pending(batch_size, competition_id=slug)
                if not tasks:
                    return 0
                claimed_seqs = [task.seq for task in tasks]
                # Serialize refolds per competition (the as_of_seq UPSERT
                # guard alone is sufficient for correctness; the lock avoids
                # wasted rival refolds). Shared key derivation with the
                # submission service (public locks seam).
                acquire_competition_lock(session, slug)
                record = self._refold(session, slug)
                SqlAlchemyScoreboardProjectionRepository(session).upsert(record)
                queue.complete(claimed_seqs)
                return len(claimed_seqs)
        except Exception as exc:  # noqa: BLE001 - poison isolation by design
            # Deterministic poison isolates the competition to ``failed``;
            # a transient error (DB connectivity, deadlock, timeout, ...) leaves
            # the claimed rows re-claimable (the claim lock died with the
            # rolled-back txn) and only diverts after the retry budget.
            if isinstance(exc, _DETERMINISTIC_POISON) and not isinstance(
                exc, (OperationalError, DBAPIError)
            ):
                self._mark_failed(claimed_seqs, exc)
            else:
                self._mark_transient(claimed_seqs, exc)
            return 0

    def _refold(self, session, slug: str) -> ScoreboardProjectionRecord:
        """Fold the full committed event set for one competition (MVCC: the
        SELECT sees only committed rows) into a projection record."""
        config = SqlAlchemyCompetitionRepository(session).get(slug)
        if config is None:  # pragma: no cover - outbox rows FK a competition
            raise LookupError(f"competition not found: {slug!r}")
        events = SqlAlchemyScoreLedger(session).list_for_competition(slug)

        solves: list[SolveEvent] = []
        max_seq = 0
        for event in events:
            if event.seq is not None:
                max_seq = max(max_seq, event.seq)
            if event.type == "solve":
                solves.append(_solve_event(event))
            elif event.type in _NON_SCORING_EVENT_TYPES:
                continue  # provenance-only; deliberately score-neutral
            else:
                raise ProjectionUnsupportedEventError(
                    f"score event type {event.type!r} (seq={event.seq}) is not "
                    "supported by the scoreboard fold yet"
                )

        challenges: dict[str, ChallengeScoringConfig] = {}
        publications = SqlAlchemyChallengePublicationRepository(
            session
        ).list_for_competition(slug)
        for pub in publications:
            key = _challenge_key(pub.definition_slug, pub.version_no)
            challenges[key] = ChallengeScoringConfig(
                challenge_id=key,
                initial_value=pub.initial_value,
                minimum_value=pub.minimum_value,
                decay_function=pub.decay_function,
                decay=pub.decay,
                first_blood_bonus=FirstBloodBonusConfig(
                    enabled=pub.first_blood_enabled,
                    bonus_points=pub.first_blood_bonus_points,
                    bonus_percent=pub.first_blood_bonus_percent,
                ),
            )

        snapshot = compute_scoreboard(
            solves, challenges, config, engine=get_scoring_engine(self._engine_name)
        )
        return ScoreboardProjectionRecord(
            competition_id=slug,
            as_of_seq=max_seq,
            entries=snapshot.to_mapping(),
        )

    @staticmethod
    def _sanitize_error(exc: Exception) -> str:
        """Bound and sanitize a stored error: exception class + message only,
        never payloads or flags. For a SQLAlchemy DBAPI/statement error, use the
        driver's ``orig`` (its class + message) and strip SQLAlchemy's
        ``[SQL: ...]`` / ``[parameters: ...]`` echo, which can quote row values.
        Length-capped by the repository."""
        base = getattr(exc, "orig", None) or exc
        message = f"{type(base).__name__}: {base}"
        marker = message.find("[SQL")
        if marker != -1:
            message = message[:marker].rstrip()
        return message

    def _mark_failed(self, seqs: list[int], exc: Exception) -> None:
        """Divert deterministically-poisoned rows to ``failed`` in a separate
        small transaction (sanitized error)."""
        if not seqs:
            return
        with self._database.session_scope() as session:
            SqlAlchemyScoreProjectionQueue(session).fail(
                seqs, self._sanitize_error(exc)
            )

    def _mark_transient(self, seqs: list[int], exc: Exception) -> None:
        """Bump the attempts counter for a transient failure, leaving the rows
        ``pending`` (re-claimable) until the retry budget is exhausted."""
        if not seqs:
            return
        with self._database.session_scope() as session:
            SqlAlchemyScoreProjectionQueue(session).mark_transient(
                seqs, self._sanitize_error(exc), _MAX_TRANSIENT_ATTEMPTS
            )

    # -- operations ------------------------------------------------------------

    def rebuild(self, batch_size: int = 100) -> int:
        """Delete every projection row, re-enqueue an outbox row per ledger
        event, and drain -- the ledger stays the sole source of truth."""
        with self._database.session_scope() as session:
            SqlAlchemyScoreboardProjectionRepository(session).delete_all()
            SqlAlchemyScoreProjectionQueue(session).requeue_all()
        return self.run_until_drained(batch_size)

    def lag(self) -> ProjectionLag:
        with self._database.session_scope() as session:
            return SqlAlchemyScoreProjectionQueue(session).pending_stats()
